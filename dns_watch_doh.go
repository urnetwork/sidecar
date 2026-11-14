//go:build !sidecar_http && !js && !ios_extension

// The zone watch's two public resolvers over connect's DoH (DNS-M5-22; D-TRUST-9, §2.8 ext-3): one connect.DohCache a
// resolver, each with remote DoH alone and one url, so no lookup falls back to the host's resolver or reaches a
// URnetwork proxy, and each answer is that resolver's own. Off sidecar_http and js, since it links connect.
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

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/connect"
)

// connect's cache is what each resolver forwards through.
var _ dnsWatchForwarder = (*connect.DohCache)(nil)

// One resolver's raw RFC 8484 answers.
type dnsWatchForwarder interface {
	Forward(ctx context.Context, qType dnsmessage.Type, domain string) (response []byte, usable bool)
}

// Tunables of the DoH resolvers.
type DnsWatchDohSettings struct {
	// The two resolvers' RFC 8484 urls. Empty takes the first two of connect's default remote DoH servers, each a
	// different operator.
	ResolverUrls []string
}

// Two of connect's default remote DoH servers, each a different operator.
func DefaultDnsWatchDohSettings() *DnsWatchDohSettings {
	urls := connect.DefaultDnsResolverSettings().RemoteDohUrlsIpv4
	return &DnsWatchDohSettings{ResolverUrls: slices.Clone(urls[:min(2, len(urls))])}
}

// The watch's resolvers over DoH. Close releases their connections.
type DnsWatchDohResolver struct {
	forwarders []dnsWatchForwarder
	caches     []*connect.DohCache
}

// Two resolvers, one a url of settings. nil takes the defaults.
func NewDnsWatchDohResolver(settings *DnsWatchDohSettings) (*DnsWatchDohResolver, error) {
	if settings == nil {
		settings = DefaultDnsWatchDohSettings()
	}
	if len(settings.ResolverUrls) != 2 {
		return nil, fmt.Errorf("%w: the zone watch asks two resolvers", errInvalidSettings)
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
func newDnsWatchForwarderResolver(forwarders ...dnsWatchForwarder) *DnsWatchDohResolver {
	return &DnsWatchDohResolver{forwarders: forwarders}
}

// Releases the caches' connections.
func (self *DnsWatchDohResolver) Close() {
	for _, cache := range self.caches {
		cache.Close()
	}
}

// The resolvers' count: one a url.
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
