//go:build !sidecar_http && !js && !ios_extension

// The zone watch's two public resolvers over connect's DoH (DNS-M5-22; D-TRUST-9, §2.8 ext-3): one connect.DohCache a
// resolver, each with remote DoH alone and one url, so no lookup falls back to the host's resolver or reaches a
// URnetwork proxy, and each answer is that resolver's own. Off sidecar_http and js, since it links connect.
//
// DnsWatchDohSettings' ForwarderFactory stands in for the urls: it builds the resolvers' forwarders, which the resolver
// owns and releases at its Close, so a test or the e2e world asks a DNS of its own through the same parsing. A nil
// ForwarderFactory, the default and every host's, builds a cache over each url, the public ones by default, as
// production asks. A test sends nothing off the machine, so in a test binary that default is refused with
// ErrDnsWatchPublicResolver before any cache is built: testing.Testing reads true only in a binary go test linked.
//
// An answer is parsed with dnsmessage into DnsWatchAnswer's canonical form: addresses as netip writes them, TXT
// strings joined, MX names lowercase with their final dot, TLSA and CAA from their RDATA's bytes. Safe for concurrent
// use.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/connect"
)

// connect's cache is what each resolver forwards through by default.
var _ DnsWatchForwarder = (*connect.DohCache)(nil)

// One resolver's raw RFC 8484 answers, as connect's DohCache.Forward gives them: the response to qType for a domain
// given without its final dot, and whether a usable one came. Safe for concurrent use.
type DnsWatchForwarder interface {
	Forward(ctx context.Context, qType dnsmessage.Type, domain string) (response []byte, usable bool)
}

// A zone watch's resolver in a test binary over urls, the public ones by default: refused, so no test sends a query
// off the machine.
var ErrDnsWatchPublicResolver = errors.New("dns watch: a zone watch in a test asks no DoH resolver by url; set DnsWatchDohSettings.ForwarderFactory to the test's own DNS")

// The resolvers' forwarders as a ForwarderFactory gives them, which one DnsWatchDohResolver alone asks.
type DnsWatchForwarders struct {
	// One a resolver, in the order Lookup numbers them: the settings' ResolverCount, none nil.
	Forwarders []DnsWatchForwarder
	// Releases the forwarders once the resolver has closed; nil releases nothing.
	Close func()
}

// Tunables of the DoH resolvers.
type DnsWatchDohSettings struct {
	// How many resolvers the watch asks, each a different operator's: D-TRUST-9's two, the pair whose answers
	// DnsWatch.Pass compares for a split, which compares no third. Must be positive.
	ResolverCount int
	// The resolvers' RFC 8484 urls, ResolverCount of them: by default the first ResolverCount of connect's default
	// remote DoH servers, each a different operator. Unread where ForwarderFactory is set.
	ResolverUrls []string
	// Builds the resolvers' forwarders, which the resolver owns and releases at its Close. Nil, the default and every
	// host's: a DohCache of the resolver's own over each url. A resolver in a test binary refuses that default, so a
	// test names a DNS of its own here. An error, or forwarders other than ResolverCount or one nil, leaves the
	// resolver unbuilt.
	ForwarderFactory func() (*DnsWatchForwarders, error)
}

// Two of connect's default remote DoH servers, each a different operator.
func DefaultDnsWatchDohSettings() *DnsWatchDohSettings {
	resolverCount := 2
	urls := connect.DefaultDnsResolverSettings().RemoteDohUrlsIpv4
	return &DnsWatchDohSettings{
		ResolverCount: resolverCount,
		ResolverUrls:  slices.Clone(urls[:min(resolverCount, len(urls))]),
	}
}

// The watch's resolvers over DoH. Close releases them.
type DnsWatchDohResolver struct {
	forwarders []DnsWatchForwarder
	caches     []*connect.DohCache
	// a ForwarderFactory's release, nil for none
	release   func()
	closeOnce sync.Once
}

// The resolvers settings name, nil taking the defaults: its ForwarderFactory's forwarders, else a DohCache of the
// resolver's own over each url, which in a test binary are refused with ErrDnsWatchPublicResolver before any cache is
// built. A factory's error comes back as it was given, and forwarders other than ResolverCount, or one nil, are
// refused, released first.
func NewDnsWatchDohResolver(settings *DnsWatchDohSettings) (*DnsWatchDohResolver, error) {
	return newDnsWatchDohResolver(settings, testing.Testing())
}

// NewDnsWatchDohResolver, inTest, a test binary's, refusing the urls.
func newDnsWatchDohResolver(settings *DnsWatchDohSettings, inTest bool) (*DnsWatchDohResolver, error) {
	if settings == nil {
		settings = DefaultDnsWatchDohSettings()
	}
	if settings.ResolverCount <= 0 {
		return nil, fmt.Errorf("%w: the zone watch asks at least one resolver", errInvalidSettings)
	}
	if settings.ForwarderFactory != nil {
		forwarders, err := settings.ForwarderFactory()
		if err != nil {
			return nil, err
		}
		if forwarders == nil || len(forwarders.Forwarders) != settings.ResolverCount || slices.Contains(forwarders.Forwarders, nil) {
			if forwarders != nil && forwarders.Close != nil {
				forwarders.Close()
			}
			return nil, fmt.Errorf("%w: the zone watch asks %d resolvers", errInvalidSettings, settings.ResolverCount)
		}
		return &DnsWatchDohResolver{forwarders: slices.Clone(forwarders.Forwarders), release: forwarders.Close}, nil
	}
	if inTest {
		return nil, ErrDnsWatchPublicResolver
	}
	if len(settings.ResolverUrls) != settings.ResolverCount {
		return nil, fmt.Errorf("%w: the zone watch asks %d resolvers", errInvalidSettings, settings.ResolverCount)
	}
	self := &DnsWatchDohResolver{}
	for _, resolverUrl := range settings.ResolverUrls {
		dohSettings := connect.DefaultDohSettings()
		// the url alone, listed once, and no fallback to local DoH or plain DNS
		dohSettings.DnsResolverSettings = &connect.DnsResolverSettings{
			EnableRemoteDoh:   true,
			RemoteDohUrlsIpv4: []string{resolverUrl},
		}
		cache := connect.NewDohCache(dohSettings)
		self.caches = append(self.caches, cache)
		self.forwarders = append(self.forwarders, cache)
	}
	return self, nil
}

// A resolver over forwarders, for a test's fake forwarders.
func newDnsWatchForwarderResolver(forwarders ...DnsWatchForwarder) *DnsWatchDohResolver {
	return &DnsWatchDohResolver{forwarders: forwarders}
}

// Releases the caches' connections, or the factory's forwarders, once.
func (self *DnsWatchDohResolver) Close() {
	self.closeOnce.Do(func() {
		for _, cache := range self.caches {
			cache.Close()
		}
		if self.release != nil {
			self.release()
		}
	})
}

// The resolvers' count: one a url or a factory's forwarder.
func (self *DnsWatchDohResolver) ResolverCount() int {
	return len(self.forwarders)
}

// A resolver that gave no usable answer.
var errDnsWatchResolverFailed = errors.New("dns watch: the resolver gave no answer")

// resolver's own answer for name and qType, through its cache's raw forward alone, in the watch's form.
func (self *DnsWatchDohResolver) Lookup(ctx context.Context, resolver int, name string, qType uint16) (*DnsWatchAnswer, error) {
	if resolver < 0 || len(self.forwarders) <= resolver {
		return nil, errDnsWatchResolverFailed
	}
	response, usable := self.forwarders[resolver].Forward(ctx, dnsmessage.Type(qType), strings.TrimSuffix(name, "."))
	if !usable {
		return nil, errDnsWatchResolverFailed
	}
	return parseDnsWatchAnswer(response, CanonicalDnsRecordName(name), qType)
}

// response's answer for name and qType in the watch's canonical form.
func parseDnsWatchAnswer(response []byte, name string, qType uint16) (*DnsWatchAnswer, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil {
		return nil, errDnsWatchResolverFailed
	}
	answer := &DnsWatchAnswer{Values: []string{}}
	switch header.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		answer.NameError = true
		return answer, nil
	default:
		// SERVFAIL and the rest say nothing of the zone
		return nil, errDnsWatchResolverFailed
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, errDnsWatchResolverFailed
	}
	for {
		resourceHeader, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, errDnsWatchResolverFailed
		}
		owner := CanonicalDnsRecordName(resourceHeader.Name.String())
		value := ""
		switch resourceHeader.Type {
		case dnsmessage.TypeCNAME:
			resource, err := parser.CNAMEResource()
			if err != nil {
				return nil, errDnsWatchResolverFailed
			}
			if owner == name {
				answer.Cname = CanonicalDnsRecordName(resource.CNAME.String())
			}
			continue
		case dnsmessage.TypeA:
			resource, err := parser.AResource()
			if err != nil {
				return nil, errDnsWatchResolverFailed
			}
			value = netip.AddrFrom4(resource.A).String()
		case dnsmessage.TypeAAAA:
			resource, err := parser.AAAAResource()
			if err != nil {
				return nil, errDnsWatchResolverFailed
			}
			value = netip.AddrFrom16(resource.AAAA).Unmap().String()
		case dnsmessage.TypeTXT:
			resource, err := parser.TXTResource()
			if err != nil {
				return nil, errDnsWatchResolverFailed
			}
			value = strings.Join(resource.TXT, "")
		case dnsmessage.TypeMX:
			resource, err := parser.MXResource()
			if err != nil {
				return nil, errDnsWatchResolverFailed
			}
			value = strconv.Itoa(int(resource.Pref)) + " " + CanonicalDnsRecordName(resource.MX.String())
		default:
			resource, err := parser.UnknownResource()
			if err != nil {
				return nil, errDnsWatchResolverFailed
			}
			value, err = dnsWatchRdataValue(uint16(resourceHeader.Type), resource.Data)
			if err != nil {
				return nil, err
			}
		}
		if uint16(resourceHeader.Type) == qType {
			answer.Values = append(answer.Values, value)
		}
	}
	slices.Sort(answer.Values)
	return answer, nil
}

// A CAA's or TLSA's RDATA in the watch's form, from its bytes (RFC 8659 §4.1, RFC 6698 §2.1). Another type is its
// bytes in hex, which compare as themselves.
func dnsWatchRdataValue(qType uint16, data []byte) (string, error) {
	switch qType {
	case DnsWatchTypeCaa:
		if len(data) < 2 || len(data) < 2+int(data[1]) {
			return "", errDnsWatchResolverFailed
		}
		tag := strings.ToLower(string(data[2 : 2+int(data[1])]))
		return strconv.Itoa(int(data[0])) + " " + tag + " " + string(data[2+int(data[1]):]), nil
	case DnsWatchTypeTlsa:
		if len(data) < 3 {
			return "", errDnsWatchResolverFailed
		}
		return fmt.Sprintf("%d %d %d %s", data[0], data[1], data[2], strings.ToUpper(hex.EncodeToString(data[3:]))), nil
	}
	return strings.ToUpper(hex.EncodeToString(data)), nil
}
