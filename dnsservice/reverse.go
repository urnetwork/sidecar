// The reverse zones of the sending addresses (§12.7, §14.6, R-DNS-9; owner decision 124; DNS-M9-02): each
// zone HE delegates for the shared lb addresses smtpedge sends from answers each covered address's PTR with
// its HELO name under bringyour.com, TTL ptr, so a receiver's forward-confirmed reverse DNS finds the name
// HELO gave, whose A record (W11's) names the address. _spf.<root> lists the same addresses (DnsSpfRdata),
// so b.<net>.<root>'s include passes SPF from them and from nothing else.
//
// These zones are not roots. They are answered unsigned, since HE's parent zone holds no DS for them and a
// signature would prove nothing: no RRSIG, NSEC or DNSKEY is given, DO or not. Each holds its apex's SOA
// and NS and one PTR a covered address, fixed at the edge's start from dns.yml and the host's sending
// addresses, and takes no journal row: a PTR leaves when smtpedge.yml drops its address, at the next start
// (dns-1's ttl). A sending address no zone covers has no PTR, so it fails FCrDNS and smtpedge sends nothing
// from it (§14.6).
//
// RFC 2317's classless delegation names a zone for a prefix longer than /24 by a label the parent picks
// (0/26, 0-26 or another) below the /24's in-addr.arpa name, and an address's PTR sits at its last octet
// below that zone. A /8, /16 or /24 prefix is a whole zone at its own in-addr.arpa name, and an address's
// PTR sits at its full reverse name.

package dnsservice

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// The name below which every IPv4 reverse zone sits (RFC 1035 §3.5).
const dnsIpv4ReverseSuffix = "in-addr.arpa."

// One reverse zone dns.yml lists: the name the parent delegates and the IPv4 prefix it covers.
type DnsReverseZoneSettings struct {
	// The zone's name, canonical once loaded: below in-addr.arpa, and for a prefix longer than /24 one
	// label below the /24's name (RFC 2317).
	Zone string `yaml:"zone"`
	// The IPv4 prefix the zone covers, as 192.0.2.0/26: /8, /16, /24, or /25 to /32.
	Prefix string `yaml:"prefix"`
}

// dns.yml's reverse: the zones the edges answer the sending addresses' PTRs in.
type DnsReverseSettings struct {
	// None by default: HE's delegation names them (M9's entry).
	Zones []DnsReverseZoneSettings `yaml:"zones"`
}

// One sending address and its PTR name (§14.6): smtpedge.yml's address and helo.
type DnsSendingAddress struct {
	// A shared lb IPv4 address.
	Address netip.Addr
	// Its HELO name, o<k>.out.bringyour.com in production: canonical and fully qualified.
	Name string
}

// The standard reverse name of the prefix's first address at its octet boundary: 2.0.192.in-addr.arpa.
// for 192.0.2.0/24. bits is 8, 16 or 24.
func dnsIpv4ReverseZoneName(prefix netip.Prefix, bits int) string {
	octets := prefix.Addr().As4()
	labels := []string{}
	for index := bits/8 - 1; 0 <= index; index -= 1 {
		labels = append(labels, strconv.Itoa(int(octets[index])))
	}
	return strings.Join(labels, ".") + "." + dnsIpv4ReverseSuffix
}

// The prefix a zone covers, and whether its name fits it (see the file header).
func (self *DnsReverseZoneSettings) parse() (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(self.Prefix)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("zone %s: prefix %q is no IPv4 prefix", self.Zone, self.Prefix)
	}
	if prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("zone %s: prefix %s has host bits", self.Zone, self.Prefix)
	}
	if !isCanonicalDnsName(self.Zone) || !dns.IsSubDomain(dnsIpv4ReverseSuffix, self.Zone) {
		return netip.Prefix{}, fmt.Errorf("zone %q is not a canonical name below %s", self.Zone, dnsIpv4ReverseSuffix)
	}
	bits := prefix.Bits()
	switch {
	case bits == 8 || bits == 16 || bits == 24:
		if want := dnsIpv4ReverseZoneName(prefix, bits); self.Zone != want {
			return netip.Prefix{}, fmt.Errorf("zone %s for %s is not %s", self.Zone, prefix, want)
		}
	case 24 < bits:
		parent := dnsIpv4ReverseZoneName(netip.PrefixFrom(prefix.Addr(), 24).Masked(), 24)
		label, rest, _ := strings.Cut(self.Zone, ".")
		if rest != parent || label == "" {
			return netip.Prefix{}, fmt.Errorf("zone %s for %s is not one label below %s (RFC 2317)", self.Zone, prefix, parent)
		}
	default:
		return netip.Prefix{}, fmt.Errorf("zone %s: prefix %s is neither an octet boundary nor longer than /24", self.Zone, prefix)
	}
	return prefix, nil
}

// Whether each zone parses, and none overlaps another zone or a root.
func (self *DnsReverseSettings) validate(roots []string) error {
	prefixes := []netip.Prefix{}
	for index := range self.Zones {
		zone := &self.Zones[index]
		prefix, err := zone.parse()
		if err != nil {
			return err
		}
		for otherIndex, other := range prefixes {
			if prefix.Overlaps(other) {
				return fmt.Errorf("zones %s and %s overlap", self.Zones[otherIndex].Zone, zone.Zone)
			}
		}
		for _, root := range roots {
			if dns.IsSubDomain(root, zone.Zone) || dns.IsSubDomain(zone.Zone, root) {
				return fmt.Errorf("zone %s overlaps the root %s", zone.Zone, root)
			}
		}
		prefixes = append(prefixes, prefix)
	}
	return nil
}

// Whether each sending address is IPv4, once, with a canonical host name: what the edge's PTRs and
// _spf.<root> can carry.
func validateDnsSendingAddresses(addresses []DnsSendingAddress) error {
	for index, address := range addresses {
		if !address.Address.IsValid() || !address.Address.Is4() {
			return fmt.Errorf("%s is no IPv4 address", address.Address)
		}
		if slices.ContainsFunc(addresses[:index], func(other DnsSendingAddress) bool { return other.Address == address.Address }) {
			return fmt.Errorf("%s twice", address.Address)
		}
		if err := validateDnsRoot(address.Name); err != nil {
			return fmt.Errorf("%s's name: %v", address.Address, err)
		}
	}
	return nil
}

// Sets SendingAddresses from smtpedge.yml's (address, helo) pairs, each address unmapped and each name
// canonical, refusing what Validate refuses. The host calls it once at start, before anything reads
// these settings.
func (self *DnsSettings) SetSendingAddresses(addresses []DnsSendingAddress) error {
	canonical := make([]DnsSendingAddress, 0, len(addresses))
	for _, address := range addresses {
		canonical = append(canonical, DnsSendingAddress{Address: address.Address.Unmap(), Name: dns.CanonicalName(address.Name)})
	}
	if err := validateDnsSendingAddresses(canonical); err != nil {
		return fmt.Errorf("%w: sending addresses: %v", ErrDnsSettingsRefused, err)
	}
	self.SendingAddresses = canonical
	return nil
}

// _spf.<root>'s TXT (§14.6; plan reading 16) as presentation-form RDATA: v=spf1, every one of settings'
// sending addresses as ip4: in address order, then -all, or v=spf1 -all with none, so b.<net>.<root>'s
// include passes nothing until smtpedge.yml lists an address. Split into character-strings of at most
// settings' TXT string bound, which a receiver joins with nothing between them (RFC 7208 §3.3).
func DnsSpfRdata(settings *DnsSettings) string {
	sorted := slices.Clone(settings.SendingAddresses)
	slices.SortFunc(sorted, func(a DnsSendingAddress, b DnsSendingAddress) int { return a.Address.Compare(b.Address) })
	text := "v=spf1"
	for _, address := range sorted {
		text += " ip4:" + address.Address.String()
	}
	text += " -all"
	quoted := []string{}
	for 0 < len(text) {
		part := text[:min(len(text), settings.TxtStringMaxByteCount)]
		text = text[len(part):]
		quoted = append(quoted, `"`+part+`"`)
	}
	return strings.Join(quoted, " ")
}

// The SOA an unsigned zone here answers (reverse and delegated zones alike): MNAME the first NS under the
// first root, RNAME that root's soa_rname or hostmaster.<root>, serial given, soa's timers, MINIMUM the
// negative TTL. Its TTL is ttl.ns, as the root's SOA's is.
func dnsUnsignedSoa(settings *DnsSettings, apex string, serial uint32) *dns.SOA {
	root := settings.Roots[0]
	rname := "hostmaster." + root
	if records := settings.RootRecords[root]; records != nil && records.SoaRname != "" {
		rname = dns.CanonicalName(records.SoaRname)
	}
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: settings.Ttl.Ns},
		Ns:      settings.Ns[0] + "." + root,
		Mbox:    rname,
		Serial:  serial,
		Refresh: settings.Soa.RefreshSeconds,
		Retry:   settings.Soa.RetrySeconds,
		Expire:  settings.Soa.ExpireSeconds,
		Minttl:  settings.Ttl.SoaMinimum,
	}
}

// The NS an unsigned zone's apex answers: each dns.yml NS under the first root, TTL ttl.ns.
func dnsUnsignedNs(settings *DnsSettings, apex string) []dns.RR {
	records := []dns.RR{}
	for _, ns := range settings.Ns {
		records = append(records, &dns.NS{
			Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: settings.Ttl.Ns},
			Ns:  ns + "." + settings.Roots[0],
		})
	}
	return records
}

// A zone answered unsigned (reverse and delegated zones): its apex's SOA and NS, and what each name below
// the apex holds.
type dnsUnsignedZone struct {
	apex string
	soa  *dns.SOA
	ns   []dns.RR
	// What a name below the apex holds by type, and whether it exists. name is canonical.
	lookup func(name string) (rrsets map[uint16][]dns.RR, exists bool)
}

// records as owner's, shared with nothing.
func dnsRecordsAs(records []dns.RR, owner string) []dns.RR {
	copies := make([]dns.RR, 0, len(records))
	for _, record := range records {
		copied := dns.Copy(record)
		copied.Header().Name = owner
		copies = append(copies, copied)
	}
	return copies
}

// The answer to query from zone, unsigned: no RRSIG, NSEC or DNSKEY whatever the query's DO, RFC 2308's
// denials under the zone's SOA with its MINIMUM as their TTL, and RFC 8482's minimal ANY. As Answer does,
// a response gets nil, and the header's faults their rcodes.
func answerUnsignedZone(query *DnsQuery, settings *DnsSettings, zone *dnsUnsignedZone) *dns.Msg {
	reply, opt, done := dnsAnswerStart(query, settings.EdnsUdpSize)
	if reply == nil || done {
		return reply
	}
	question := reply.Question[0]
	if question.Qclass != dns.ClassINET || question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR {
		reply.Rcode = dns.RcodeRefused
		return reply
	}
	if question.Qtype == dns.TypeNXNAME {
		// RFC 9824: NXNAME is a meta-type, never asked for
		reply.Rcode = dns.RcodeFormatError
		return reply
	}
	reply.Authoritative = true
	owner := dns.Fqdn(question.Name)
	name := dns.CanonicalName(owner)
	denialSoa := dns.Copy(zone.soa).(*dns.SOA)
	denialSoa.Hdr.Ttl = min(denialSoa.Hdr.Ttl, denialSoa.Minttl)
	rrsets := map[uint16][]dns.RR{}
	if name == zone.apex {
		rrsets[dns.TypeSOA] = []dns.RR{zone.soa}
		rrsets[dns.TypeNS] = zone.ns
	} else {
		var exists bool
		if dns.IsSubDomain(zone.apex, name) {
			rrsets, exists = zone.lookup(name)
		}
		if !exists {
			reply.Rcode = dns.RcodeNameError
			reply.Ns = []dns.RR{denialSoa}
			return reply
		}
	}
	switch records, held := rrsets[question.Qtype]; {
	case held && len(records) != 0:
		reply.Answer = dnsRecordsAs(records, owner)
	case question.Qtype == dns.TypeANY:
		// the first RRset in type order, or RFC 8482's HINFO where there is none
		types := []uint16{}
		for rrType, records := range rrsets {
			if len(records) != 0 {
				types = append(types, rrType)
			}
		}
		slices.Sort(types)
		if 0 < len(types) {
			reply.Answer = dnsRecordsAs(rrsets[types[0]], owner)
		} else {
			header := dns.RR_Header{Name: owner, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: denialSoa.Hdr.Ttl}
			reply.Answer = []dns.RR{&dns.HINFO{Hdr: header, Cpu: dnsMinimalAnyCpu}}
		}
	default:
		reply.Ns = []dns.RR{denialSoa}
	}
	fitDnsAnswer(reply, dnsAnswerLimit(query, opt, settings))
	return reply
}

// One reverse zone as served.
type dnsReverseZone struct {
	apex   string
	prefix netip.Prefix
	// Each covered sending address's PTR, by its owner.
	pointers map[string]*dns.PTR
	zone     *dnsUnsignedZone
}

// The owner of address's PTR in a zone at apex covering prefix (see the file header).
func dnsReversePointerOwner(apex string, prefix netip.Prefix, address netip.Addr) string {
	if 24 < prefix.Bits() {
		return strconv.Itoa(int(address.As4()[3])) + "." + apex
	}
	name, _ := dns.ReverseAddr(address.String())
	return name
}

// Every reverse zone one edge answers, fixed at its start (see the file header). Immutable, so safe for
// concurrent use.
type ReverseZones struct {
	settings *DnsSettings
	// By apex, sorted.
	zones []*dnsReverseZone
}

// The reverse zones settings list, each with the PTRs of the sending addresses it covers. settings must
// be valid.
func NewReverseZones(settings *DnsSettings) (*ReverseZones, error) {
	self := &ReverseZones{settings: settings}
	for index := range settings.Reverse.Zones {
		zoneSettings := &settings.Reverse.Zones[index]
		prefix, err := zoneSettings.parse()
		if err != nil {
			return nil, fmt.Errorf("%w: reverse: %v", ErrDnsSettingsRefused, err)
		}
		zone := &dnsReverseZone{apex: zoneSettings.Zone, prefix: prefix, pointers: map[string]*dns.PTR{}}
		for _, sending := range settings.SendingAddresses {
			if !prefix.Contains(sending.Address) {
				continue
			}
			owner := dnsReversePointerOwner(zone.apex, prefix, sending.Address)
			zone.pointers[owner] = &dns.PTR{
				Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: settings.Ttl.Ptr},
				Ptr: sending.Name,
			}
		}
		zone.zone = &dnsUnsignedZone{
			apex: zone.apex,
			// no zone here is transferred, so its serial says nothing to anyone, and one fixed value
			// lets both NS answer alike
			soa: dnsUnsignedSoa(settings, zone.apex, 1),
			ns:  dnsUnsignedNs(settings, zone.apex),
			lookup: func(name string) (map[uint16][]dns.RR, bool) {
				pointer, ok := zone.pointers[name]
				if !ok {
					return nil, false
				}
				return map[uint16][]dns.RR{dns.TypePTR: {pointer}}, true
			},
		}
		self.zones = append(self.zones, zone)
	}
	slices.SortFunc(self.zones, func(a *dnsReverseZone, b *dnsReverseZone) int { return strings.Compare(a.apex, b.apex) })
	return self, nil
}

// Every zone's apex, sorted.
func (self *ReverseZones) Zones() []string {
	apexes := []string{}
	for _, zone := range self.zones {
		apexes = append(apexes, zone.apex)
	}
	return apexes
}

// The PTR owner and name address has here, and whether a zone covers it as a sending address.
func (self *ReverseZones) Pointer(address netip.Addr) (owner string, name string, ok bool) {
	address = address.Unmap()
	for _, zone := range self.zones {
		if !zone.prefix.Contains(address) {
			continue
		}
		owner := dnsReversePointerOwner(zone.apex, zone.prefix, address)
		if pointer, held := zone.pointers[owner]; held {
			return owner, pointer.Ptr, true
		}
	}
	return "", "", false
}

// The zone name is at or below, or nil. name is canonical.
func (self *ReverseZones) zoneFor(name string) *dnsReverseZone {
	if self == nil {
		return nil
	}
	for _, zone := range self.zones {
		if dns.IsSubDomain(zone.apex, name) {
			return zone
		}
	}
	return nil
}

// Whether query's one question names a name in these zones.
func (self *ReverseZones) holds(query *DnsQuery) bool {
	request := query.Message
	if request == nil || len(request.Question) != 1 {
		return false
	}
	return self.zoneFor(dns.CanonicalName(request.Question[0].Name)) != nil
}

// The answer to query from these zones, unsigned (see the file header): REFUSED for a name in none of
// them, as Answer gives a name in no root; nil for a response.
func (self *ReverseZones) Answer(query *DnsQuery) *dns.Msg {
	request := query.Message
	if request != nil && len(request.Question) == 1 {
		if zone := self.zoneFor(dns.CanonicalName(request.Question[0].Name)); zone != nil {
			return answerUnsignedZone(query, self.settings, zone.zone)
		}
	}
	reply, _, done := dnsAnswerStart(query, self.settings.EdnsUdpSize)
	if reply != nil && !done {
		reply.Rcode = dns.RcodeRefused
	}
	return reply
}
