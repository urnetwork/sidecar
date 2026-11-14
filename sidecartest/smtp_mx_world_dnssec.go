//go:build !sidecar_http

// MxWorld as a DNSSEC-OK resolver (DNS-M7-04): the stand-in for C20's DohCache.ForwardDnssec (QD-145), which the zone
// watch's StrictChain fetches its chains over (sidecar.DnsWatchDnssecForwarder) until connect has it. Each question
// gets the message a recursive resolver with DO and checking disabled would give: the RRset with its RRSIG in the
// answer, a denial's NSEC3 records with theirs in the authority section, every zone signed as its options say, broken
// ones included, so the device's own validation decides. MX is answered as LookupMx finds it (exact, wildcard or the
// name existing without one), TLSA at _25._tcp.<host>, DNSKEY at a zone's apex, and DS from the parent, or the
// parent's proof that there is none.

package sidecartest

import (
	"context"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.DnsWatchDnssecForwarder = (*MxWorld)(nil)

// See sidecar.DnsWatchDnssecForwarder: the world's answer to qType at domain as packed DNS, the root asked as ".".
func (self *MxWorld) ForwardDnssec(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	name := mxWorldName(domain)
	message := &dns.Msg{}
	message.SetQuestion(name, uint16(qType))
	message.Response = true
	message.RecursionAvailable = true
	message.CheckingDisabled = true
	// as a resolver packs it: owners and the names an MX or CNAME holds compressed, RRSIGs' and NSECs' never
	message.Compress = true
	message.SetEdns0(4096, true)
	zone := self.zoneOfWithLock(name)
	if zone == nil {
		message.Rcode = dns.RcodeNameError
	} else {
		wire, nameError := self.dnssecAnswerWithLock(zone, name, uint16(qType))
		if nameError {
			message.Rcode = dns.RcodeNameError
		}
		for offset := 0; offset < len(wire); {
			rr, next, err := dns.UnpackRR(wire, offset)
			if err != nil {
				return nil, false
			}
			offset = next
			if mxWorldDenialRr(rr) {
				message.Ns = append(message.Ns, rr)
			} else {
				message.Answer = append(message.Answer, rr)
			}
		}
	}
	packed, err := message.Pack()
	return packed, err == nil
}

// Whether rr belongs to a denial: an NSEC3, or an RRSIG over one.
func mxWorldDenialRr(rr dns.RR) bool {
	if signature, ok := rr.(*dns.RRSIG); ok {
		return signature.TypeCovered == dns.TypeNSEC3
	}
	return rr.Header().Rrtype == dns.TypeNSEC3
}

// The answer to rrtype at name in zone, as wire, and whether name does not exist.
func (self *MxWorld) dnssecAnswerWithLock(zone *mxWorldZone, name string, rrtype uint16) ([]byte, bool) {
	exists := func() bool {
		for owner := range zone.records {
			if dns.IsSubDomain(name, owner) {
				return true
			}
		}
		return name == zone.name
	}()
	denial := func() ([]byte, bool) {
		if zone.key == nil {
			return nil, !exists
		}
		return self.denialWithLock(zone, name), !exists
	}
	switch rrtype {
	case dns.TypeMX:
		wire, _, _, found := self.mxAnswerWithLock(zone, name)
		if !found {
			return denial()
		}
		return wire, false
	case dns.TypeTLSA:
		host, ok := strings.CutPrefix(name, "_25._tcp.")
		if !ok || zone.records[name][dns.TypeTLSA] == nil {
			return denial()
		}
		wire, _ := self.tlsaAnswerWithLock(zone, host)
		return wire, false
	case dns.TypeDNSKEY:
		apex, ok := self.zones[name]
		if !ok || apex.key == nil {
			return denial()
		}
		return self.signedWithLock(apex, []dns.RR{apex.key}), false
	case dns.TypeDS:
		child, ok := self.zones[name]
		if !ok || name == "." {
			return denial()
		}
		parent := self.parentOfWithLock(child)
		if ds := parent.records[name][dns.TypeDS]; 0 < len(ds) {
			return self.signedWithLock(parent, ds), false
		}
		if parent.key == nil {
			return nil, false
		}
		// an insecure delegation: the parent proves the DS absent
		return self.denialWithLock(parent, name), false
	}
	return denial()
}
