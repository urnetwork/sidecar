// §12.6's self-check: a zone build or key set serves only once this passes, else the previous one
// stays. It holds the released window to the configured KSK, finds the ZSK in it, holds the window to
// the clock, then signs a probe of every answer shape and verifies each as a validator would, with
// miekg's RRSIG.Verify. The probes run on the view itself for the apex, a denial and the DNSKEY RRset,
// and on a small view of the same root built here for the shapes a zone may not hold yet: a wildcard,
// a copy, an edge row, a CNAME chain and an empty non-terminal. So the check costs the same whatever
// the zone's size, and runs at every applied row.

package dnsservice

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// What SelfCheck refuses. The wrapping error says what failed, and never a key's bytes.
var ErrDnsSelfCheck = errors.New("dns self-check failed")

// The labels the built probe view's names hang under, and the one its NXDOMAIN probe asks, at the
// root. A built view holds only these, so they collide with nothing; a real view is asked only for
// names it does not hold.
const (
	dnsProbeLabel     = "p"
	dnsProbeNameError = "_dns-self-check"
)

// One probe: a question and whether it asks for DNSSEC and compact answers.
type dnsProbe struct {
	name           string
	qtype          uint16
	signed         bool
	compactAnswers bool
}

// The query a probe sends, over TCP so nothing is truncated.
func (self *dnsProbe) query() *DnsQuery {
	message := &dns.Msg{}
	message.SetQuestion(self.name, self.qtype)
	message.SetEdns0(dns.DefaultMsgSize, self.signed)
	if self.compactAnswers {
		message.IsEdns0().SetCo()
	}
	return &DnsQuery{Message: message, Tcp: true}
}

// Checks keySet against view and anchors at now, and returns the keys an edge may then publish beside
// view. anchors are the root's KSK DNSKEYs as configured (ParseDnsTrustAnchors). Every failure wraps
// ErrDnsSelfCheck, and one for a set that does not parse wraps ErrDnsKeyRefused too; an edge then keeps
// what it served.
func SelfCheck(view *ZoneView, keySet *DnsKeySet, anchors []*dns.DNSKEY, now time.Time) (*DnsSigningKeys, error) {
	fail := func(format string, arguments ...any) error {
		return fmt.Errorf("%w: %s", ErrDnsSelfCheck, fmt.Sprintf(format, arguments...))
	}
	if view == nil {
		return nil, fail("no view")
	}
	if view.soa == nil {
		return nil, fail("the view has no SOA at its apex")
	}
	keys, err := newDnsSigningKeys(view.root, keySet)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsSelfCheck, err)
	}
	if err := keys.checkWindow(anchors, now); err != nil {
		return nil, fail("%v", err)
	}
	probeView, probeHealthy, err := newDnsProbeView(view)
	if err != nil {
		return nil, fail("the probe view: %v", err)
	}
	// probes sign fresh, uncached and outside the cap
	signer := &Signer{settings: view.settings}
	run := func(probeView *ZoneView, healthy *HealthySet, probes []dnsProbe) error {
		for index := range probes {
			probe := &probes[index]
			query := probe.query()
			reply := signer.answerAt(query, probeView, keys, healthy, now)
			if err := verifyDnsSignedReply(reply, query.Message.Question[0], probe.signed, probe.compactAnswers, keys, anchors, now); err != nil {
				return fmt.Errorf("%s %s: %w", probe.name, dnsTypeText(probe.qtype), err)
			}
		}
		return nil
	}
	if err := run(view, nil, view.probes()); err != nil {
		return nil, fail("%v", err)
	}
	if err := run(probeView, probeHealthy, dnsProbeViewProbes(view.root)); err != nil {
		return nil, fail("%v", err)
	}
	return keys, nil
}

// Whether the window is current at now and a configured KSK signed it, that KSK being in it.
func (self *DnsSigningKeys) checkWindow(anchors []*dns.DNSKEY, now time.Time) error {
	if now.Before(self.notBefore) || !now.Before(self.notAfter) {
		return errors.New("the key window is not current")
	}
	rrset := make([]dns.RR, 0, len(self.dnskeys))
	for _, key := range self.dnskeys {
		rrset = append(rrset, key)
	}
	for _, rrsig := range self.dnskeyRrsigs {
		for _, anchor := range anchors {
			if dns.CanonicalName(anchor.Hdr.Name) != self.root || !dnsUsableZoneKey(anchor) || anchor.Flags&dns.SEP == 0 {
				continue
			}
			published := slices.ContainsFunc(self.dnskeys, func(key *dns.DNSKEY) bool {
				return dnsSameKey(key, anchor) && key.Flags == anchor.Flags
			})
			if published && rrsig.Verify(anchor, rrset) == nil && rrsig.ValidityPeriod(now) {
				return nil
			}
		}
	}
	return errors.New("no signature over the key window verifies by a configured KSK it publishes")
}

// The probes asked of a real view: its apex signed and unsigned, its DNSKEY RRset, an empty answer
// at the apex, and a name it does not hold, with and without CO. Names are found, never assumed: a
// view that holds every candidate name or type is asked one shape fewer, and the built view still
// asks that shape.
func (self *ZoneView) probes() []dnsProbe {
	probes := []dnsProbe{
		{name: self.root, qtype: dns.TypeSOA, signed: true},
		{name: self.root, qtype: dns.TypeSOA},
		{name: self.root, qtype: dns.TypeDNSKEY, signed: true},
	}
	for _, rrType := range []uint16{dns.TypeReserved, dns.TypeNULL} {
		if !self.names.get(self.root).holds(DnsRecordKey{Owner: self.root, Type: rrType}) {
			probes = append(probes, dnsProbe{name: self.root, qtype: rrType, signed: true})
			break
		}
	}
	for index := range 4 {
		name := fmt.Sprintf("%s-%d.%s", dnsProbeNameError, index, self.root)
		if self.match(name).node == nil {
			probes = append(probes,
				dnsProbe{name: name, qtype: dns.TypeA, signed: true},
				dnsProbe{name: name, qtype: dns.TypeA, signed: true, compactAnswers: true},
			)
			break
		}
	}
	return probes
}

// A view of view's root holding one of each shape a zone can answer, beside view's SOA, and a healthy
// set with one interface for its edge rows. Addresses are documentation ones: the view answers no one.
func newDnsProbeView(view *ZoneView) (*ZoneView, *HealthySet, error) {
	root := view.root
	probe := dnsProbeLabel + "." + root
	soaText := strings.TrimPrefix(view.soa.String(), view.soa.Hdr.String())
	rows := []DnsRecordSet{
		{Owner: root, Type: dns.TypeSOA, Ttl: view.soa.Hdr.Ttl, Kind: DnsRecordKindSystem, Rdata: []string{soaText}},
		{Owner: "*." + probe, Type: dns.TypeA, Ttl: view.settings.Ttl.Edge, Kind: DnsRecordKindEdge},
		{Owner: "*." + probe, Type: dns.TypeAAAA, Ttl: view.settings.Ttl.Edge, Kind: DnsRecordKindEdge},
		{Owner: "*." + probe, Type: dns.TypeTXT, Ttl: view.settings.Ttl.User, Kind: DnsRecordKindSystem, Rdata: []string{`"probe"`}},
		{Owner: "c." + probe, Type: DnsCopyType, Kind: DnsRecordKindCopy},
		{Owner: "x.c." + probe, Type: dns.TypeTXT, Ttl: view.settings.Ttl.User, Kind: DnsRecordKindSystem, Rdata: []string{`"probe"`}},
		{Owner: "n." + probe, Type: dns.TypeCNAME, Ttl: view.settings.Ttl.User, Kind: DnsRecordKindSystem, Rdata: []string{"t." + probe}},
		{Owner: "t." + probe, Type: dns.TypeTXT, Ttl: view.settings.Ttl.User, Kind: DnsRecordKindSystem, Rdata: []string{`"probe"`}},
	}
	probeView, err := NewZoneView(view.settings, NewDnsSnapshotRows(DnsSnapshot{Format: DnsFormat, Root: root, Serial: view.serial}, rows))
	if err != nil {
		return nil, nil, err
	}
	healthy := NewHealthySet([]DnsLbInterface{{
		Name: "probe",
		Ipv4: netip.MustParseAddr("192.0.2.1"),
		Ipv6: netip.MustParseAddr("2001:db8::1"),
	}}, nil)
	return probeView, healthy, nil
}

// The probes asked of the built view: a wildcard's synthesized addresses, its own record, its empty
// answer and ANY; a copy's addresses and records; a CNAME chain; an empty non-terminal; a name under
// one that exists, which no wildcard covers.
func dnsProbeViewProbes(root string) []dnsProbe {
	probe := dnsProbeLabel + "." + root
	return []dnsProbe{
		{name: "w." + probe, qtype: dns.TypeA, signed: true},
		{name: "w." + probe, qtype: dns.TypeAAAA, signed: true},
		{name: "w." + probe, qtype: dns.TypeTXT, signed: true},
		{name: "w." + probe, qtype: dns.TypeMX, signed: true},
		{name: "w." + probe, qtype: dns.TypeANY, signed: true},
		{name: "c." + probe, qtype: dns.TypeA, signed: true},
		{name: "c." + probe, qtype: dns.TypeTXT, signed: true},
		{name: "c." + probe, qtype: dns.TypeMX, signed: true},
		{name: "n." + probe, qtype: dns.TypeTXT, signed: true},
		{name: probe, qtype: dns.TypeA, signed: true},
		{name: "z.x.c." + probe, qtype: dns.TypeA, signed: true},
	}
}

// Whether reply is what a validator holding anchors accepts for question at now: under DO, an RRSIG on
// every RRset in the answer and authority sections by the ZSK, the DNSKEY RRset's by a configured
// KSK, each verifying and current with labels counting the name as answered, no signature over
// nothing, and a denial that is RFC 9824's, its NSEC denying the last name searched and no other.
// Without DO, nothing DNSSEC adds. Tests read replies with this too.
func verifyDnsSignedReply(reply *dns.Msg, question dns.Question, signed bool, compactAnswers bool, keys *DnsSigningKeys, anchors []*dns.DNSKEY, now time.Time) error {
	if reply == nil {
		return errors.New("no reply")
	}
	if reply.Truncated {
		return errors.New("truncated")
	}
	if reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError {
		return fmt.Errorf("rcode %s", dnsRcodeLabel(reply.Rcode))
	}
	if !reply.Authoritative {
		return errors.New("not authoritative")
	}
	sections := [][]dns.RR{reply.Answer, reply.Ns}
	if !signed {
		for _, section := range sections {
			for _, record := range section {
				if rrType := record.Header().Rrtype; rrType == dns.TypeRRSIG || rrType == dns.TypeNSEC {
					return fmt.Errorf("a %s without DO", dnsTypeText(rrType))
				}
			}
		}
		return nil
	}
	for _, section := range sections {
		if err := verifyDnsSignedSection(section, keys, anchors, now); err != nil {
			return err
		}
	}
	return verifyDnsCompactDenial(reply, question, compactAnswers)
}

// Every RRset in section signed and verifying, and every signature in it over an RRset beside it.
func verifyDnsSignedSection(section []dns.RR, keys *DnsSigningKeys, anchors []*dns.DNSKEY, now time.Time) error {
	type rrsetKey struct {
		owner  string
		rrType uint16
	}
	rrsigs := map[rrsetKey][]*dns.RRSIG{}
	data := []dns.RR{}
	for _, record := range section {
		if rrsig, ok := record.(*dns.RRSIG); ok {
			key := rrsetKey{owner: dns.CanonicalName(rrsig.Hdr.Name), rrType: rrsig.TypeCovered}
			rrsigs[key] = append(rrsigs[key], rrsig)
			continue
		}
		data = append(data, record)
	}
	for _, rrset := range dnsRrsets(data) {
		header := rrset[0].Header()
		key := rrsetKey{owner: dns.CanonicalName(header.Name), rrType: header.Rrtype}
		covering := rrsigs[key]
		if len(covering) == 0 {
			return fmt.Errorf("%s %s is unsigned", header.Name, dnsTypeText(header.Rrtype))
		}
		delete(rrsigs, key)
		labelCount := uint8(dns.CountLabel(header.Name))
		if strings.HasPrefix(header.Name, "*.") {
			labelCount -= 1
		}
		for _, rrsig := range covering {
			if rrsig.Labels != labelCount {
				return fmt.Errorf("%s %s: labels %d where the name has %d", header.Name, dnsTypeText(header.Rrtype), rrsig.Labels, labelCount)
			}
			if !rrsig.ValidityPeriod(now) {
				return fmt.Errorf("%s %s: a signature not current", header.Name, dnsTypeText(header.Rrtype))
			}
			verified := false
			if header.Rrtype == dns.TypeDNSKEY {
				for _, anchor := range anchors {
					if rrsig.Verify(anchor, rrset) == nil {
						verified = true
						break
					}
				}
			} else {
				verified = rrsig.Verify(keys.zskRecord, rrset) == nil
			}
			if !verified {
				return fmt.Errorf("%s %s: a signature does not verify", header.Name, dnsTypeText(header.Rrtype))
			}
		}
	}
	for key := range rrsigs {
		return fmt.Errorf("a signature over %s %s, which is not there", key.owner, dnsTypeText(key.rrType))
	}
	return nil
}

// Whether a denial in reply is RFC 9824's: one NSEC, at the last name searched, whose next name is its
// immediate successor; NXNAME, RRSIG and NSEC alone for a name that does not exist, under NOERROR
// unless CO was asked; for an empty answer, the real types without the one asked or a CNAME. A reply
// that denies nothing passes.
func verifyDnsCompactDenial(reply *dns.Msg, question dns.Question, compactAnswers bool) error {
	nsecs := []*dns.NSEC{}
	soaCount := 0
	for _, record := range reply.Ns {
		switch typed := record.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, typed)
		case *dns.SOA:
			soaCount += 1
		}
	}
	if reply.Rcode == dns.RcodeSuccess && soaCount == 0 && len(nsecs) == 0 {
		return nil
	}
	if soaCount != 1 || len(nsecs) != 1 {
		return fmt.Errorf("a denial with %d SOA and %d NSEC", soaCount, len(nsecs))
	}
	nsec := nsecs[0]
	denied := dns.CanonicalName(dnsDeniedName(reply, question.Name))
	if dns.CanonicalName(nsec.Hdr.Name) != denied {
		return fmt.Errorf("an NSEC at %s denying %s", nsec.Hdr.Name, denied)
	}
	successor, ok := dnsImmediateSuccessor(denied)
	if !ok || dns.CanonicalName(nsec.NextDomain) != dns.CanonicalName(successor) {
		return fmt.Errorf("an NSEC whose next name %s is not %s's successor", nsec.NextDomain, denied)
	}
	if slices.Contains(nsec.TypeBitMap, dns.TypeNXNAME) {
		if !slices.Equal(nsec.TypeBitMap, []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME}) {
			return fmt.Errorf("an NXNAME denial naming %v", nsec.TypeBitMap)
		}
		wantRcode := dns.RcodeSuccess
		if compactAnswers {
			wantRcode = dns.RcodeNameError
		}
		if reply.Rcode != wantRcode {
			return fmt.Errorf("an NXNAME denial under %s", dnsRcodeLabel(reply.Rcode))
		}
		return nil
	}
	if reply.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("an empty answer under %s", dnsRcodeLabel(reply.Rcode))
	}
	for _, rrType := range []uint16{question.Qtype, dns.TypeCNAME} {
		if slices.Contains(nsec.TypeBitMap, rrType) {
			return fmt.Errorf("an empty answer whose NSEC names %s", dnsTypeText(rrType))
		}
	}
	for _, rrType := range dnsSignedNameTypes {
		if !slices.Contains(nsec.TypeBitMap, rrType) {
			return fmt.Errorf("an NSEC that does not name %s", dnsTypeText(rrType))
		}
	}
	return nil
}
