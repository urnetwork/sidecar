// Compact denial of existence (RFC 9824; §12.6's Denial, D-DNS-5). Under DO a name that does not
// exist answers NOERROR with one NSEC at that very name, whose next name is the name's immediate
// successor and whose types are RRSIG, NSEC and NXNAME; a name with no data of the type asked answers
// the same NSEC with the name's real types. No NSEC chain exists, so nothing can be walked, and a
// denial under a wildcard or a copy names only the queried name, so it shows neither which names
// exist nor which a wildcard covers. Without DO, NXDOMAIN stays (reading 14 restores it under DO for a
// client that sets the CO flag).

package dnsservice

import (
	"slices"

	"github.com/miekg/dns"
)

// RFC 1035 §3.1: the most octets a name takes on the wire.
const dnsNameMaxWireByteCount = 255

// The types every name has once signed: the RRSIG over its NSEC, and the NSEC itself.
var dnsSignedNameTypes = []uint16{dns.TypeRRSIG, dns.TypeNSEC}

// The name that sorts right after name in canonical order among names that can exist (RFC 4034 §6.1,
// RFC 4471 §3.1): "\000." in front, or for a name too long for that, a zero octet after its first
// label, which a name of that length has no child to sort between. name is canonical. False for a
// name too long for either, which only an attack sends, and which then answers SERVFAIL rather than a
// denial that would cover names beside it.
func dnsImmediateSuccessor(name string) (string, bool) {
	wire := make([]byte, dnsNameMaxWireByteCount+2)
	length, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil {
		return "", false
	}
	wire = wire[:length]
	var successor []byte
	switch {
	case length+2 <= dnsNameMaxWireByteCount:
		successor = append([]byte{1, 0}, wire...)
	case length+1 <= dnsNameMaxWireByteCount && 0 < wire[0] && int(wire[0]) < dnsLabelMaxByteCount:
		labelLength := int(wire[0])
		successor = make([]byte, 0, length+1)
		successor = append(successor, byte(labelLength+1))
		successor = append(successor, wire[1:1+labelLength]...)
		successor = append(successor, 0)
		successor = append(successor, wire[1+labelLength:]...)
	default:
		return "", false
	}
	text, _, err := dns.UnpackDomainName(successor, 0)
	if err != nil {
		return "", false
	}
	return text, true
}

// RFC 9824's NSEC at owner, which denies owner and nothing else: types sorted, each once.
func dnsCompactNsec(owner string, ttl uint32, types []uint16) (*dns.NSEC, bool) {
	next, ok := dnsImmediateSuccessor(dns.CanonicalName(owner))
	if !ok {
		return nil, false
	}
	bitmap := slices.Clone(types)
	slices.Sort(bitmap)
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
		NextDomain: next,
		TypeBitMap: slices.Compact(bitmap),
	}, true
}

// Whether a row answers any record at this moment: an edge or router row only while the healthy set
// holds an address of its family, and any other while it holds records.
func (self *zoneRrset) answersData(healthy *HealthySet) bool {
	switch self.set.Kind {
	case DnsRecordKindEdge, DnsRecordKindRouter:
		return len(healthy.addresses(self.set.Kind, self.set.Type)) != 0
	}
	return self.set.Type == dns.TypeSOA || len(self.records) != 0
}

// The types name answers with data now, as typedRecords would answer them: its own RRsets, then its
// copy row's wildcard's for the types it lacks, each only while it answers a record. nil when the name
// does not exist; empty for an empty non-terminal. name is canonical and at or below the root.
func (self *ZoneView) dataTypes(name string, healthy *HealthySet) []uint16 {
	match := self.match(name)
	if match.node == nil {
		return nil
	}
	types := []uint16{}
	add := func(node *zoneNode) {
		for _, held := range node.rrsets {
			if rrset := node.rrset(held.set.Type); rrset != nil && rrset.answersData(healthy) {
				types = append(types, held.set.Type)
			}
		}
	}
	add(match.node)
	if match.node.copyRow != nil {
		if source := self.copySource(match.name); source != nil {
			add(source)
		}
	}
	slices.Sort(types)
	return slices.Compact(types)
}

// The name a reply's search ended at, which its rcode and denial speak for (RFC 6604 §3): the question's
// name, or the target of the last CNAME the answer followed from it.
func dnsDeniedName(reply *dns.Msg, questionName string) string {
	name := questionName
	for _, record := range reply.Answer {
		if cname, ok := record.(*dns.CNAME); ok && dns.CanonicalName(cname.Hdr.Name) == dns.CanonicalName(name) {
			name = cname.Target
		}
	}
	return name
}

// Whether a NOERROR reply denies data: an empty answer for the last name searched, which Answer marks
// with the zone's SOA in authority. A chain that stopped short holds no SOA, and denies nothing.
func dnsReplyDeniesData(reply *dns.Msg) bool {
	if reply.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, record := range reply.Ns {
		if record.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}
