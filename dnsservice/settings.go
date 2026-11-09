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
	"time"

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
	// How online signatures are timed and cached (DNS-M5-04). Not in the sketch, which says only that
	// RRSIG lifetimes are settings.
	Signing DnsSigningSettings `yaml:"signing"`
	// How dnsedge reads its sockets and drains (DNS-M5-05). Not in the sketch.
	Edge DnsEdgeSettings `yaml:"edge"`
	// How dnsedge probes the lb interfaces (DNS-M5-07). Not in the sketch, whose prose gives the
	// interval, the ports and the failures these default to.
	Probe DnsProbeSettings `yaml:"probe"`
	// How dnsedge follows the feed and keeps its local snapshot (DNS-M5-06). Not in the sketch.
	Feed DnsFeedSettings `yaml:"feed"`
	// How the API block holds, reads and bounds its routes (DNS-M5-08). Not in the sketch.
	Api DnsApiSettings `yaml:"api"`
}

// How the API block holds, reads and bounds its routes (DNS-M5-08, §12.8).
type DnsApiSettings struct {
	// Seconds GET journal holds a poll with nothing new: §12.6's 25. Must be positive and below the
	// lb's 30 s proxy_read_timeout.
	JournalHoldSeconds int `yaml:"journal_hold_s"`
	// Seconds GET ready holds while a running NS is behind: §12.8's 25, under the same bound.
	ReadyHoldSeconds int `yaml:"ready_hold_s"`
	// The most journal rows one answer carries; an edge asks again for the rest. Must be positive.
	RowLimit int `yaml:"row_limit"`
	// Seconds at least between two rounds of SOA reads of one root's NS, however many requests wait.
	// Must be positive.
	SoaReadIntervalSeconds int `yaml:"soa_read_interval_s"`
	// Seconds one SOA read may take before its NS reads as not answering. Must be positive.
	SoaReadTimeoutSeconds int `yaml:"soa_read_timeout_s"`
	// Seconds a canary verdict counts: plan-DNS-canary-route-state's 180. Must be positive.
	CanaryFreshSeconds int `yaml:"canary_fresh_s"`
	// The most bytes a POST reload-diff body may hold: an (owner, type) a changed RRset, for a whole
	// zone after a restore. Must be positive.
	DiffMaxByteCount int `yaml:"diff_max_bytes"`
	// The most bytes an edge reads of one journal answer. Must hold row_limit rows of the largest
	// RRset: at least 64 KiB, and the default is far above.
	AnswerMaxByteCount int `yaml:"answer_max_bytes"`
	// Seconds between the block's reads of every root's dns_root row, which Ready reports. Must be
	// positive.
	StoreProbeSeconds int `yaml:"store_probe_s"`
	// Seconds one probe read may take. Must be positive.
	StoreTimeoutSeconds int `yaml:"store_timeout_s"`
	// Seconds Drain waits for holds it ended to answer. Zero waits for none.
	DrainSeconds int `yaml:"drain_s"`
}

// How dnsedge follows the feed and keeps its local snapshot (DNS-M5-06).
type DnsFeedSettings struct {
	// Seconds the first wait after a failed poll, reload or apply takes, doubling to retry_max_s. Must
	// be positive.
	RetryMinSeconds int `yaml:"retry_min_s"`
	// The longest that wait grows to. At least retry_min_s.
	RetryMaxSeconds int `yaml:"retry_max_s"`
	// Seconds at least between the starts of two polls that both came back with nothing, so a block
	// that answers at once cannot make the loop spin. A block holds each poll up to 25 s first. Must
	// be positive.
	EmptyPollSeconds int `yaml:"empty_poll_s"`
	// Seconds the local snapshot's writer waits after a change before it writes, so a burst of rows
	// costs one write of the zone; a restart within it serves a view that much older until the feed
	// catches it up. A reload's view is written at once. Must be positive.
	SnapshotWriteSeconds int `yaml:"snapshot_write_s"`
	// Seconds a replaced snapshot older than restore_serial is kept for its diff: dns-1's 24 h. Must be
	// positive.
	ReplacedKeepSeconds int `yaml:"replaced_keep_s"`
}

// When an RRSIG made online is valid, and how long one is cached (§12.6's Signing). Seconds. A cached
// signature serves while it has refresh_s left, and none outlives the released DNSKEY window, so a
// leaked ZSK's forgeries end with its windows (§12.6's runbook).
type DnsSigningSettings struct {
	// How long a fresh RRSIG stays valid, before jitter and the window's end cut it. Four days keeps
	// a signature valid past ns's one-day TTL, the longest here, with a day to spare. Must exceed
	// refresh_s plus jitter_s, so a fresh signature never needs refreshing at once.
	LifetimeSeconds int `yaml:"lifetime_s"`
	// How far before now an inception sits, so a validator whose clock runs slow still accepts a
	// fresh signature. Zero puts the inception at now.
	InceptionOffsetSeconds int `yaml:"inception_offset_s"`
	// The most a lifetime is cut at random, so signatures cached together expire apart and their
	// refreshes do not land in one second of the cap. Zero cuts none.
	JitterSeconds int `yaml:"jitter_s"`
	// A cached signature with less than this left is made again. Above the longest TTL, so a
	// resolver can keep an answer and its signature for the whole TTL. Must be positive.
	RefreshSeconds int `yaml:"refresh_s"`
	// The most signatures the cache holds, the least recently used going first. About 400 bytes an
	// entry. Must be positive.
	CacheEntryCount int `yaml:"cache_entries"`
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
	// Seconds' worth of responses a bucket may owe, so a prefix that floods stays limited this long
	// after it stops, and how long an idle bucket is kept. BIND's default. Not in the sketch. Zero owes
	// nothing, so a flood is limited only while it lasts.
	WindowSeconds int `yaml:"window_s"`
	// The most buckets held, the least recently used dropped first, so a spoofed spread of prefixes
	// costs bounded memory: about 150 bytes a bucket. Not in the sketch. Must be positive.
	BucketCount int `yaml:"buckets"`
}

// §12.6's tcp block.
type DnsTcpSettings struct {
	// Open connections one source may hold. Left unset by §12.6. A file that does not set it above
	// zero is refused.
	ConnectionsPerSource int `yaml:"connections_per_source"`
	// Seconds a connection may sit silent before the edge closes it. Must be above zero.
	IdleTimeoutSeconds int `yaml:"idle_timeout_s"`
	// The most connections an edge holds at once from every source together, so many sources cannot
	// hold every descriptor. Not in the sketch. Must be positive.
	ConnectionCount int `yaml:"connections"`
}

// How dnsedge probes the lb interfaces (DNS-M5-07, §12.6, §13.4).
type DnsProbeSettings struct {
	// Seconds between rounds: owner decision 34's 10. Must be positive.
	IntervalSeconds int `yaml:"interval_s"`
	// Seconds one probe may take, dial to tlsedge's alert, before it fails. Must be positive and
	// below interval_s, so a round ends before the next is due.
	TimeoutSeconds int `yaml:"timeout_s"`
	// Consecutive failures on any one port that drop an address: reading 7's 3. At least 1.
	FailureCount int `yaml:"failures"`
	// The ports tlsedge answers on: 443, and 8443, 8883 and 5671 unsplit (§13.4; owner decision 121).
	// Each once, from 1 to 65535.
	Ports []int `yaml:"ports"`
	// Probes in flight at once in a round, across interfaces, families, ports and route probes. Must be
	// positive.
	ConcurrencyCount int `yaml:"concurrency"`
	// The port route probes reach the split on: 443, where §13.4's map runs. From 1 to 65535.
	RoutePort int `yaml:"route_port"`
	// The most added hosts of one reported map version an edge route-probes: §13.4's 16. At least 1.
	RouteHostCount int `yaml:"route_hosts"`
	// Seconds the post of a round's route-probe report may take before the round gives it up, its
	// passes to be probed again. Must be positive and below interval_s.
	ReportTimeoutSeconds int `yaml:"report_timeout_s"`
}

// How dnsedge reads its sockets and drains (DNS-M5-05).
type DnsEdgeSettings struct {
	// Goroutines reading each UDP socket, each answering what it reads. Zero or less takes one for each
	// processor Go schedules on.
	UdpReaderCount int `yaml:"udp_readers"`
	// Milliseconds an accept or a read waits after a fault other than its socket closing, so a fault
	// that persists cannot spin. Must be positive.
	RetryMilliseconds int `yaml:"retry_ms"`
	// Seconds Drain waits for TCP connections to finish their queries before Close cuts them. Zero
	// waits for none.
	DrainSeconds int `yaml:"drain_s"`
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
			Ipv4Prefix:    24,
			Ipv6Prefix:    56,
			Slip:          2,
			Classes:       []string{DnsRrlClassAnswer, DnsRrlClassDenial, DnsRrlClassError},
			WindowSeconds: 15,
			BucketCount:   256 * 1024,
		},
		EdnsUdpSize:  1232,
		Any:          DnsAnyMinimal,
		ClientSubnet: DnsClientSubnetIgnore,
		Tcp: DnsTcpSettings{
			IdleTimeoutSeconds: 10,
			ConnectionCount:    16 * 1024,
		},
		CnameChainMaxCount: 8,
		Signing: DnsSigningSettings{
			LifetimeSeconds:        4 * 24 * 3600,
			InceptionOffsetSeconds: 3600,
			JitterSeconds:          6 * 3600,
			RefreshSeconds:         2 * 24 * 3600,
			CacheEntryCount:        128 * 1024,
		},
		Edge: DnsEdgeSettings{
			UdpReaderCount:    0,
			RetryMilliseconds: 100,
			DrainSeconds:      5,
		},
		Probe: DnsProbeSettings{
			IntervalSeconds:      10,
			TimeoutSeconds:       3,
			FailureCount:         3,
			Ports:                []int{443, 8443, 8883, 5671},
			ConcurrencyCount:     64,
			RoutePort:            443,
			RouteHostCount:       16,
			ReportTimeoutSeconds: 3,
		},
		Feed: DnsFeedSettings{
			RetryMinSeconds:      1,
			RetryMaxSeconds:      30,
			EmptyPollSeconds:     1,
			SnapshotWriteSeconds: 5,
			ReplacedKeepSeconds:  24 * 3600,
		},
		Api: DnsApiSettings{
			JournalHoldSeconds:     25,
			ReadyHoldSeconds:       25,
			RowLimit:               1024,
			SoaReadIntervalSeconds: 1,
			SoaReadTimeoutSeconds:  2,
			CanaryFreshSeconds:     180,
			DiffMaxByteCount:       64 * 1024 * 1024,
			AnswerMaxByteCount:     256 * 1024 * 1024,
			StoreProbeSeconds:      10,
			StoreTimeoutSeconds:    5,
			DrainSeconds:           5,
		},
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
	if self.Tcp.ConnectionCount <= 0 {
		return refuse("tcp.connections is not positive")
	}
	if self.Rrl.WindowSeconds < 0 {
		return refuse("rrl.window_s is negative")
	}
	if self.Rrl.BucketCount <= 0 {
		return refuse("rrl.buckets is not positive")
	}
	if self.Edge.RetryMilliseconds <= 0 {
		return refuse("edge.retry_ms is not positive")
	}
	if self.Edge.DrainSeconds < 0 {
		return refuse("edge.drain_s is negative")
	}
	if err := self.Probe.validate(); err != nil {
		return refuse("probe: %v", err)
	}
	if err := self.Feed.validate(); err != nil {
		return refuse("feed: %v", err)
	}
	if err := self.Api.validate(); err != nil {
		return refuse("api: %v", err)
	}
	if self.CnameChainMaxCount < 1 {
		return refuse("cname_chain_max_count is below 1")
	}
	if err := self.Signing.validate(); err != nil {
		return refuse("signing: %v", err)
	}
	return nil
}

// Whether a fresh signature outlives its own refresh, and every value is in range.
func (self *DnsSigningSettings) validate() error {
	switch {
	case self.RefreshSeconds <= 0:
		return errors.New("refresh_s is not positive")
	case self.InceptionOffsetSeconds < 0:
		return errors.New("inception_offset_s is negative")
	case self.JitterSeconds < 0:
		return errors.New("jitter_s is negative")
	case self.LifetimeSeconds <= self.RefreshSeconds+self.JitterSeconds:
		return errors.New("lifetime_s does not exceed refresh_s plus jitter_s")
	case self.CacheEntryCount <= 0:
		return errors.New("cache_entries is not positive")
	}
	return nil
}

// Whether a round can finish before the next, and every port is one.
func (self *DnsProbeSettings) validate() error {
	switch {
	case self.IntervalSeconds <= 0:
		return errors.New("interval_s is not positive")
	case self.TimeoutSeconds <= 0 || self.IntervalSeconds <= self.TimeoutSeconds:
		return errors.New("timeout_s is not positive and below interval_s")
	case self.FailureCount < 1:
		return errors.New("failures is below 1")
	case len(self.Ports) == 0:
		return errors.New("ports is empty")
	case self.ConcurrencyCount <= 0:
		return errors.New("concurrency is not positive")
	case self.RoutePort < 1 || 65535 < self.RoutePort:
		return fmt.Errorf("route_port %d is no port", self.RoutePort)
	case self.RouteHostCount < 1:
		return errors.New("route_hosts is below 1")
	case self.ReportTimeoutSeconds <= 0 || self.IntervalSeconds <= self.ReportTimeoutSeconds:
		return errors.New("report_timeout_s is not positive and below interval_s")
	}
	for index, port := range self.Ports {
		if port < 1 || 65535 < port {
			return fmt.Errorf("port %d is no port", port)
		}
		if slices.Contains(self.Ports[:index], port) {
			return fmt.Errorf("port %d is listed twice", port)
		}
	}
	return nil
}

// Whether every wait is positive and the backoff grows.
func (self *DnsFeedSettings) validate() error {
	switch {
	case self.RetryMinSeconds <= 0:
		return errors.New("retry_min_s is not positive")
	case self.RetryMaxSeconds < self.RetryMinSeconds:
		return errors.New("retry_max_s is below retry_min_s")
	case self.EmptyPollSeconds <= 0:
		return errors.New("empty_poll_s is not positive")
	case self.SnapshotWriteSeconds <= 0:
		return errors.New("snapshot_write_s is not positive")
	case self.ReplacedKeepSeconds <= 0:
		return errors.New("replaced_keep_s is not positive")
	}
	return nil
}

// Whether every hold stays under the lb's read timeout and every bound is positive.
func (self *DnsApiSettings) validate() error {
	switch {
	case self.JournalHoldSeconds <= 0 || dnsLbProxyReadTimeoutSeconds <= self.JournalHoldSeconds:
		return fmt.Errorf("journal_hold_s is not positive and under the lb's %d s", dnsLbProxyReadTimeoutSeconds)
	case self.ReadyHoldSeconds <= 0 || dnsLbProxyReadTimeoutSeconds <= self.ReadyHoldSeconds:
		return fmt.Errorf("ready_hold_s is not positive and under the lb's %d s", dnsLbProxyReadTimeoutSeconds)
	case self.RowLimit <= 0:
		return errors.New("row_limit is not positive")
	case self.SoaReadIntervalSeconds <= 0:
		return errors.New("soa_read_interval_s is not positive")
	case self.SoaReadTimeoutSeconds <= 0:
		return errors.New("soa_read_timeout_s is not positive")
	case self.CanaryFreshSeconds <= 0:
		return errors.New("canary_fresh_s is not positive")
	case self.DiffMaxByteCount <= 0:
		return errors.New("diff_max_bytes is not positive")
	case self.AnswerMaxByteCount < 64*1024:
		return errors.New("answer_max_bytes is below 64 KiB")
	case self.StoreProbeSeconds <= 0:
		return errors.New("store_probe_s is not positive")
	case self.StoreTimeoutSeconds <= 0:
		return errors.New("store_timeout_s is not positive")
	case self.DrainSeconds < 0:
		return errors.New("drain_s is negative")
	}
	return nil
}

// A setting's seconds as a duration.
func dnsSeconds(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
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
