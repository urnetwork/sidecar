// config/<env>/dns.yml (§12.6): what the dns engine serves and how it answers. Roots are config, so
// changing the root needs no code (D-DNS-1): no code here names one, and recurd.dev is not one
// (X17). Both roles of server/cli/dns read this one file.
//
// §12.6 leaves three numbers open until real hosts give them (HANDOFF 9.10): signatures_per_second,
// tcp.connections_per_source and RRL's rate. Each is zero in DefaultDnsSettings, and Validate refuses
// a zero, because a silent default on a public NS is worse than refusing to start.

package dnsservice

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// R-DNS-7's bound on a negative TTL, in seconds: a requirement, so not a setting.
const dnsNegativeTtlMaxSeconds = 60

// The least a DNS message may be held to, by RFC 1035 and RFC 6891 §6.2.3.
const dnsMinimumMessageByteCount = 512

// The longest DNS label, by RFC 1035 §2.3.4.
const dnsLabelMaxByteCount = 63

// The value `any` holds: RFC 8482's minimal answer, the only mode §12.6 names.
const DnsAnyMinimal = "minimal"

// The value `client_subnet` holds: RFC 7871's option is never echoed or stored (dns-2).
const DnsClientSubnetIgnore = "ignore"

// The classes RRL counts apart (§12.6), which metrics.go's labels share.
const (
	DnsRrlClassAnswer = "answer"
	DnsRrlClassDenial = "denial"
	DnsRrlClassError  = "error"
)

// A dns.yml that cannot be served from. The wrapping error names the field.
var ErrDnsSettingsRefused = errors.New("dns.yml refused")

// §12.6's sketch, field for field. Safe to read concurrently once loaded, and never changed after.
type DnsSettings struct {
	// Every root served, canonical once loaded: lowercase, fully qualified. A list, so changing the
	// root needs no code (D-DNS-1). None may sit inside another, since each is one zone with no cut.
	Roots []string `yaml:"roots"`
	// Where the reverse zones of the sending addresses come from (M9). Nothing reads it before
	// DNS-M9-02 gives it a form. Empty means none.
	Reverse string `yaml:"reverse"`
	// Which delegated _domainkey.<domain> zones are served (v1, §14.6). Nothing reads it before
	// DNS-M9-02 gives it a form. Empty means none.
	Delegated string `yaml:"delegated"`
	// The NS host labels under each root, one for each dns edge host.
	Ns []string `yaml:"ns"`
	// §12.6's TTLs (D-DNS-4).
	Ttl DnsTtlSettings `yaml:"ttl"`
	// Response-rate limiting, as DNS-M5-05 keys it.
	Rrl DnsRrlSettings `yaml:"rrl"`
	// The fresh signatures one edge makes in a second, cached answers aside. Left unset by §12.6.
	// A file that does not set it above zero is refused.
	SignaturesPerSecond int `yaml:"signatures_per_second"`
	// The largest UDP answer in bytes, and what the OPT record offers: 1232 fits a 1280-byte IPv6 MTU
	// with no fragment. At least 512.
	EdnsUdpSize int `yaml:"edns_udp_size"`
	// How ANY is answered: DnsAnyMinimal, the only value.
	Any string `yaml:"any"`
	// What becomes of a client subnet option: DnsClientSubnetIgnore, the only value.
	ClientSubnet string `yaml:"client_subnet"`
	// TCP 53, as DNS-M5-05 bounds it.
	Tcp DnsTcpSettings `yaml:"tcp"`
	// The most CNAME records one answer follows inside the root before it stops and leaves the rest
	// to the resolver, which bounds a loop and the answer's size. Not in the sketch, which names no
	// bound. At least 1.
	CnameChainMaxCount int `yaml:"cname_chain_max_count"`
}

// Seconds, each as §12.6 gives it: short enough for ACME, failover and takedown (D-DNS-4). None may
// be zero.
type DnsTtlSettings struct {
	// _acme-challenge TXT, inside R-DNS-7's 60 s.
	Challenge uint32 `yaml:"challenge"`
	// A and AAAA at *, @ and each copy: the longest a health drop stays cached.
	Edge uint32 `yaml:"edge"`
	// MX at @, *, b and each copy.
	Mx uint32 `yaml:"mx"`
	// A and AAAA at mx.
	MxHost uint32 `yaml:"mx_host"`
	// TLSA at _25._tcp.mx.
	Tlsa uint32 `yaml:"tlsa"`
	// _mta-sts, _smtp._tls and _dmarc TXT.
	MailPolicy uint32 `yaml:"mail_policy"`
	// CAA at <root>.
	Caa uint32 `yaml:"caa"`
	// A user record that names no TTL of its own.
	User uint32 `yaml:"user"`
	// The least and most a user record may name, in that order.
	UserRange [2]uint32 `yaml:"user_range"`
	// The SOA's MINIMUM, which bounds a denial's TTL. R-DNS-7 holds it to at most 60.
	SoaMinimum uint32 `yaml:"soa_minimum"`
	// NS at <root>.
	Ns uint32 `yaml:"ns"`
	// PTR in the reverse zones.
	Ptr uint32 `yaml:"ptr"`
}

// §12.6's rrl block. RRL buckets resolvers, so these key by prefix and never by address.
type DnsRrlSettings struct {
	// IPv4 addresses sharing a bucket, as a prefix length from 1 to 32.
	Ipv4Prefix int `yaml:"ipv4_prefix"`
	// IPv6 addresses sharing a bucket, as a prefix length from 1 to 128.
	Ipv6Prefix int `yaml:"ipv6_prefix"`
	// Every Nth dropped answer goes out as TC=1, so a real resolver retries on TCP. 2 by §12.6. Zero
	// sends none.
	Slip int `yaml:"slip"`
	// What is limited, of DnsRrlClassAnswer, DnsRrlClassDenial and DnsRrlClassError.
	Classes []string `yaml:"classes"`
	// Responses a bucket sends per second in one class. Left unset by §12.6, whose sketch names no
	// rate. A file that does not set it above zero is refused.
	ResponsesPerSecond int `yaml:"responses_per_second"`
}

// §12.6's tcp block.
type DnsTcpSettings struct {
	// Open connections one source may hold. Left unset by §12.6. A file that does not set it above
	// zero is refused.
	ConnectionsPerSource int `yaml:"connections_per_source"`
	// Seconds a connection may sit silent before the edge closes it. Must be above zero.
	IdleTimeoutSeconds int `yaml:"idle_timeout_s"`
}

// §12.6's values. Roots has no default, since that is a deployment's to say, and the three numbers
// §12.6 leaves open stay zero, so this alone does not pass Validate.
func DefaultDnsSettings() *DnsSettings {
	return &DnsSettings{
		Ns: []string{"ns1", "ns2"},
		Ttl: DnsTtlSettings{
			Challenge:  60,
			Edge:       60,
			Mx:         300,
			MxHost:     300,
			Tlsa:       300,
			MailPolicy: 3600,
			Caa:        3600,
			User:       300,
			UserRange:  [2]uint32{60, 3600},
			SoaMinimum: 60,
			Ns:         86400,
			Ptr:        3600,
		},
		Rrl: DnsRrlSettings{
			Ipv4Prefix: 24,
			Ipv6Prefix: 56,
			Slip:       2,
			Classes:    []string{DnsRrlClassAnswer, DnsRrlClassDenial, DnsRrlClassError},
		},
		EdnsUdpSize:  1232,
		Any:          DnsAnyMinimal,
		ClientSubnet: DnsClientSubnetIgnore,
		Tcp: DnsTcpSettings{
			IdleTimeoutSeconds: 10,
		},
		CnameChainMaxCount: 8,
	}
}

// Reads one dns.yml over DefaultDnsSettings, so a key the file leaves out keeps its default. A key
// this release does not know is refused rather than ignored, since it is a typo more often than not,
// and a mistyped limit that took its default would be silent on a public NS.
func LoadDnsSettings(data []byte) (*DnsSettings, error) {
	settings := DefaultDnsSettings()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(settings); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsSettingsRefused, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one document", ErrDnsSettingsRefused)
	}
	for index, root := range settings.Roots {
		settings.Roots[index] = dns.CanonicalName(root)
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return settings, nil
}

// Whether these settings can be served from, and what is wrong when not.
func (self *DnsSettings) Validate() error {
	refuse := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: %s", ErrDnsSettingsRefused, fmt.Sprintf(format, arguments...))
	}
	if self.SignaturesPerSecond <= 0 {
		return refuse("signatures_per_second is unset")
	}
	if self.Tcp.ConnectionsPerSource <= 0 {
		return refuse("tcp.connections_per_source is unset")
	}
	if self.Rrl.ResponsesPerSecond <= 0 {
		return refuse("rrl.responses_per_second is unset")
	}
	if len(self.Roots) == 0 {
		return refuse("roots is empty")
	}
	for index, root := range self.Roots {
		if err := validateDnsRoot(root); err != nil {
			return refuse("roots: %v", err)
		}
		for _, other := range self.Roots[:index] {
			if dns.IsSubDomain(root, other) || dns.IsSubDomain(other, root) {
				return refuse("roots: %s and %s overlap", other, root)
			}
		}
	}
	if len(self.Ns) == 0 {
		return refuse("ns is empty")
	}
	for index, label := range self.Ns {
		if !isDnsHostLabel(label) {
			return refuse("ns: %q is not one host label", label)
		}
		if slices.Contains(self.Ns[:index], label) {
			return refuse("ns: %s is listed twice", label)
		}
	}
	if err := self.Ttl.validate(); err != nil {
		return refuse("ttl: %v", err)
	}
	if self.Rrl.Ipv4Prefix < 1 || 32 < self.Rrl.Ipv4Prefix {
		return refuse("rrl.ipv4_prefix %d is not a prefix length", self.Rrl.Ipv4Prefix)
	}
	if self.Rrl.Ipv6Prefix < 1 || 128 < self.Rrl.Ipv6Prefix {
		return refuse("rrl.ipv6_prefix %d is not a prefix length", self.Rrl.Ipv6Prefix)
	}
	if self.Rrl.Slip < 0 {
		return refuse("rrl.slip is negative")
	}
	if len(self.Rrl.Classes) == 0 {
		return refuse("rrl.classes is empty")
	}
	for _, class := range self.Rrl.Classes {
		if !slices.Contains([]string{DnsRrlClassAnswer, DnsRrlClassDenial, DnsRrlClassError}, class) {
			return refuse("rrl.classes: %q is not a class", class)
		}
	}
	if self.EdnsUdpSize < dnsMinimumMessageByteCount || dns.MaxMsgSize < self.EdnsUdpSize {
		return refuse("edns_udp_size %d is out of range", self.EdnsUdpSize)
	}
	if self.Any != DnsAnyMinimal {
		return refuse("any %q: only %s is served", self.Any, DnsAnyMinimal)
	}
	if self.ClientSubnet != DnsClientSubnetIgnore {
		return refuse("client_subnet %q: only %s is served", self.ClientSubnet, DnsClientSubnetIgnore)
	}
	if self.Tcp.IdleTimeoutSeconds <= 0 {
		return refuse("tcp.idle_timeout_s is not positive")
	}
	if self.CnameChainMaxCount < 1 {
		return refuse("cname_chain_max_count is below 1")
	}
	return nil
}

// Whether every TTL is set and §12.6's relations hold.
func (self *DnsTtlSettings) validate() error {
	namedTtls := []struct {
		name string
		ttl  uint32
	}{
		{name: "challenge", ttl: self.Challenge},
		{name: "edge", ttl: self.Edge},
		{name: "mx", ttl: self.Mx},
		{name: "mx_host", ttl: self.MxHost},
		{name: "tlsa", ttl: self.Tlsa},
		{name: "mail_policy", ttl: self.MailPolicy},
		{name: "caa", ttl: self.Caa},
		{name: "user", ttl: self.User},
		{name: "soa_minimum", ttl: self.SoaMinimum},
		{name: "ns", ttl: self.Ns},
		{name: "ptr", ttl: self.Ptr},
	}
	for _, namedTtl := range namedTtls {
		if namedTtl.ttl == 0 || dnsTtlMaxSeconds < namedTtl.ttl {
			return fmt.Errorf("%s %d is out of range", namedTtl.name, namedTtl.ttl)
		}
	}
	if dnsNegativeTtlMaxSeconds < self.SoaMinimum {
		return fmt.Errorf("soa_minimum %d is above R-DNS-7's %d", self.SoaMinimum, dnsNegativeTtlMaxSeconds)
	}
	if self.UserRange[0] == 0 || self.UserRange[1] < self.UserRange[0] || dnsTtlMaxSeconds < self.UserRange[1] {
		return fmt.Errorf("user_range %v is not a range", self.UserRange)
	}
	if self.User < self.UserRange[0] || self.UserRange[1] < self.User {
		return fmt.Errorf("user %d is outside user_range %v", self.User, self.UserRange)
	}
	return nil
}

// Whether root names a zone this engine can serve: canonical, LDH and below a TLD.
func validateDnsRoot(root string) error {
	labelCount, ok := dns.IsDomainName(root)
	if !ok || !dns.IsFqdn(root) || root != strings.ToLower(root) {
		return fmt.Errorf("%q is not a canonical name", root)
	}
	if labelCount < 2 {
		return fmt.Errorf("%q is not below a top-level domain", root)
	}
	for _, label := range dns.SplitDomainName(root) {
		if !isDnsHostLabel(label) {
			return fmt.Errorf("%q has a label that is not a host label", root)
		}
	}
	return nil
}

// Letters, digits and inner hyphens: RFC 1123's host label, in either case.
func isDnsHostLabel(label string) bool {
	if label == "" || dnsLabelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := range len(label) {
		character := label[index]
		isLetter := 'a' <= character && character <= 'z' || 'A' <= character && character <= 'Z'
		isDigit := '0' <= character && character <= '9'
		if !isLetter && !isDigit && character != '-' {
			return false
		}
	}
	return true
}
