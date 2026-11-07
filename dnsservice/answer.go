// Unsigned answers (§12.6, §12.7), a pure function of a query, a view and the healthy set, so one
// query at one serial gives the same bytes on both NS, and DNS-M5-04's Signer can wrap it. Denials are
// plain here, and the signer makes them compact under DO.
//
// This is the one place records are synthesized. An edge or router row takes its addresses from the
// healthy set here, and a copy row answers its wildcard's current records and TTLs here, so a write to
// * or a health drop reaches every copy with no further write (D-DNS-11).
//
// What a resolver can learn stays small (R-DNS-4): no additional section, no NS in authority, and a
// wildcard answer names the queried name, so nothing shows that a wildcard covered it.

package dnsservice

import (
	"net"
	"slices"

	"github.com/miekg/dns"
)

// What RFC 8482 §4.2 puts in a synthesized HINFO's CPU field.
const dnsMinimalAnyCpu = "RFC8482"

// One query as it reached an edge.
type DnsQuery struct {
	// As parsed. Answer reads it and does not change it.
	Message *dns.Msg
	// Over TCP, where the answer's bound is the message size and not EDNS's.
	Tcp bool
}

// The answer to query from view at this moment's healthy set. Pure: no clock, no randomness, nothing
// kept, and the reply shares nothing with the view. view may be nil, when REFUSED is all there is to
// say. A message that is itself a response gets nil, so two servers can never answer each other.
func Answer(query *DnsQuery, view *ZoneView, healthy *HealthySet) *dns.Msg {
	request := query.Message
	if request == nil || request.Response {
		return nil
	}
	reply := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               request.Id,
			Response:         true,
			Opcode:           request.Opcode,
			RecursionDesired: request.RecursionDesired,
			CheckingDisabled: request.CheckingDisabled,
		},
		Compress: true,
	}

	if len(request.Question) == 1 {
		reply.Question = []dns.Question{request.Question[0]}
	}

	// RFC 6891 §6.1.1 refuses a second OPT, and §6.1.3 answers an unknown version before anything else
	var opt *dns.OPT
	for _, extra := range request.Extra {
		if record, ok := extra.(*dns.OPT); ok {
			if opt != nil || record.Hdr.Name != "." {
				reply.Rcode = dns.RcodeFormatError
				return reply
			}
			opt = record
		}
	}
	if opt != nil {
		udpSize := uint16(dnsMinimumMessageByteCount)
		if view != nil {
			udpSize = uint16(view.settings.EdnsUdpSize)
		}
		// nothing else of the query's OPT comes back: a client subnet option is never echoed (dns-2)
		reply.SetEdns0(udpSize, opt.Do())
		if 0 < opt.Version() {
			reply.Rcode = dns.RcodeBadVers
			return reply
		}
	}
	if request.Opcode != dns.OpcodeQuery {
		reply.Rcode = dns.RcodeNotImplemented
		return reply
	}
	if len(request.Question) != 1 {
		reply.Rcode = dns.RcodeFormatError
		return reply
	}
	question := request.Question[0]
	name := dns.CanonicalName(question.Name)
	refused := question.Qclass != dns.ClassINET || question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR ||
		view == nil || !dns.IsSubDomain(view.root, name)
	if refused {
		reply.Rcode = dns.RcodeRefused
		return reply
	}
	if view.soa == nil {
		reply.Rcode = dns.RcodeServerFailure
		return reply
	}

	reply.Authoritative = true
	view.answerQuestion(reply, question, healthy)
	fitDnsAnswer(reply, dnsAnswerLimit(query, opt, view.settings))
	return reply
}

// The most bytes this answer may hold: the message limit on TCP, and on UDP the smaller of what the
// client offers, 512 with no EDNS, and what this server offers.
func dnsAnswerLimit(query *DnsQuery, opt *dns.OPT, settings *DnsSettings) int {
	if query.Tcp {
		return dns.MaxMsgSize
	}
	limit := dnsMinimumMessageByteCount
	if opt != nil {
		limit = max(limit, int(opt.UDPSize()))
	}
	return min(limit, settings.EdnsUdpSize)
}

// Holds reply to limit. An answer that does not fit goes whole and TC tells the client to come back
// over TCP: a partial RRset would be no use under DNSSEC, and the client must not use it anyway (RFC
// 2181 §9).
func fitDnsAnswer(reply *dns.Msg, limit int) {
	if reply.Len() <= limit {
		return
	}
	reply.Truncated = true
	reply.Answer = nil
	reply.Ns = nil
}

// One search's result: the node that answers a name, and that node's own name, which is the wildcard's
// when a wildcard answers. A nil node means the name does not exist.
type zoneMatch struct {
	node *zoneNode
	name string
}

// RFC 4592's search: the exact owner, then the closest encloser, whose wildcard answers if there is
// one. name is canonical and at or below the root. An existing name always stops the search, an empty
// non-terminal included, which is the block that copy rows exist to undo.
func (self *ZoneView) match(name string) zoneMatch {
	if node := self.names.get(name); node != nil {
		return zoneMatch{node: node, name: name}
	}
	for ancestor := name; ancestor != self.root && ancestor != ""; {
		ancestor = zoneParent(ancestor)
		if self.names.get(ancestor) != nil {
			wildcard := "*." + ancestor
			return zoneMatch{node: self.names.get(wildcard), name: wildcard}
		}
	}
	return zoneMatch{}
}

// The wildcard a copy row at name answers from: the one name would have matched were its children not
// there. So the walk goes up past names that exist only because of what is below them, and an ancestor
// with rows of its own ends it, since such a name would have blocked any wildcard above it. nil when
// nothing covers name.
func (self *ZoneView) copySource(name string) *zoneNode {
	for ancestor := name; ancestor != self.root && ancestor != ""; {
		ancestor = zoneParent(ancestor)
		wildcard := "*." + ancestor
		if wildcard != name {
			if node := self.names.get(wildcard); node != nil && node.holdsOwnRows() {
				return node
			}
		}
		if node := self.names.get(ancestor); node != nil && node.holdsOwnRows() {
			return nil
		}
	}
	return nil
}

// A fresh record at owner for address.
func dnsAddressRecord(owner string, rrType uint16, ttl uint32, ip net.IP) dns.RR {
	header := dns.RR_Header{Name: owner, Rrtype: rrType, Class: dns.ClassINET, Ttl: ttl}
	if rrType == dns.TypeA {
		return &dns.A{Hdr: header, A: ip}
	}
	return &dns.AAAA{Hdr: header, AAAA: ip}
}

// The SOA as it goes out: the view's serial, and a MINIMUM no higher than R-DNS-7's setting.
func (self *ZoneView) soaRecord() *dns.SOA {
	soa := dns.Copy(self.soa).(*dns.SOA)
	soa.Serial = uint32(self.serial)
	soa.Minttl = min(soa.Minttl, self.settings.Ttl.SoaMinimum)
	return soa
}

// The SOA a denial carries, whose TTL is its negative TTL (RFC 2308 §5).
func (self *ZoneView) denialSoa() *dns.SOA {
	soa := self.soaRecord()
	soa.Hdr.Ttl = min(soa.Hdr.Ttl, soa.Minttl)
	return soa
}

// An RRset's records as owner's, shared with nothing. An edge or router row with no healthy address
// gives none, so its name answers as having no data of that type.
func (self *ZoneView) rrsetRecords(rrset *zoneRrset, owner string, healthy *HealthySet) []dns.RR {
	set := &rrset.set
	switch {
	case set.Kind == DnsRecordKindEdge || set.Kind == DnsRecordKindRouter:
		addresses := healthy.addresses(set.Kind, set.Type)
		records := make([]dns.RR, 0, len(addresses))
		for _, address := range addresses {
			records = append(records, dnsAddressRecord(owner, set.Type, set.Ttl, address.AsSlice()))
		}
		return records
	case set.Type == dns.TypeSOA:
		soa := self.soaRecord()
		soa.Hdr.Name = owner
		return []dns.RR{soa}
	}
	records := make([]dns.RR, 0, len(rrset.records))
	for _, record := range rrset.records {
		copied := dns.Copy(record)
		copied.Header().Name = owner
		records = append(records, copied)
	}
	return records
}

// The records a matched name answers rrType with: its own RRset, or the copy row's wildcard's.
func (self *ZoneView) typedRecords(match zoneMatch, rrType uint16, owner string, healthy *HealthySet) []dns.RR {
	if rrset := match.node.rrset(rrType); rrset != nil {
		return self.rrsetRecords(rrset, owner, healthy)
	}
	if match.node.copyRow != nil {
		if source := self.copySource(match.name); source != nil {
			if rrset := source.rrset(rrType); rrset != nil {
				return self.rrsetRecords(rrset, owner, healthy)
			}
		}
	}
	return nil
}

// RFC 8482's answer to ANY (plan reading 21): the first RRset of the name's in type order, or a
// synthesized HINFO where it has none to give.
func (self *ZoneView) anyRecords(match zoneMatch, owner string, healthy *HealthySet) []dns.RR {
	first := func(node *zoneNode) []dns.RR {
		for _, held := range node.rrsets {
			if rrset := node.rrset(held.set.Type); rrset != nil {
				if records := self.rrsetRecords(rrset, owner, healthy); len(records) != 0 {
					return records
				}
			}
		}
		return nil
	}
	if records := first(match.node); records != nil {
		return records
	}
	if match.node.copyRow != nil {
		if source := self.copySource(match.name); source != nil {
			if records := first(source); records != nil {
				return records
			}
		}
	}
	header := dns.RR_Header{Name: owner, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: self.denialSoa().Hdr.Ttl}
	return []dns.RR{&dns.HINFO{Hdr: header, Cpu: dnsMinimalAnyCpu}}
}

// Fills reply for question, restarting at a CNAME's target while it stays in this root, as RFC 1034
// §3.6.2 asks. The rcode and authority follow the last name searched (RFC 6604 §3). A chain that leaves
// the root, loops or passes the setting's bound stops there, for the resolver to go on with.
func (self *ZoneView) answerQuestion(reply *dns.Msg, question dns.Question, healthy *HealthySet) {
	owner := dns.Fqdn(question.Name)
	for chainCount := 0; ; {
		match := self.match(dns.CanonicalName(owner))
		if match.node == nil {
			reply.Rcode = dns.RcodeNameError
			reply.Ns = append(reply.Ns, self.denialSoa())
			return
		}
		if question.Qtype == dns.TypeANY {
			reply.Answer = append(reply.Answer, self.anyRecords(match, owner, healthy)...)
			return
		}
		if records := self.typedRecords(match, question.Qtype, owner, healthy); len(records) != 0 {
			reply.Answer = append(reply.Answer, records...)
			return
		}
		cname := match.node.rrset(dns.TypeCNAME)
		if cname == nil {
			reply.Ns = append(reply.Ns, self.denialSoa())
			return
		}
		records := self.rrsetRecords(cname, owner, healthy)
		reply.Answer = append(reply.Answer, records...)
		chainCount += 1
		target := records[0].(*dns.CNAME).Target
		if self.settings.CnameChainMaxCount <= chainCount || !dns.IsSubDomain(self.root, dns.CanonicalName(target)) {
			return
		}
		if slices.ContainsFunc(reply.Answer, func(record dns.RR) bool {
			return dns.CanonicalName(record.Header().Name) == dns.CanonicalName(target)
		}) {
			return
		}
		owner = target
	}
}
