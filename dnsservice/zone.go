// One root at one serial (§12.6), which is all an edge answers from. A ZoneView never changes: Apply
// builds the next one beside it, so a reader holding a view sees a whole serial, never half a diff,
// and an edge can self-check a new view before anything serves it, then publish it with one atomic
// swap. dns edges hold no lock on the answer path (zone_trie.go).
//
// A view takes what the feed gives it in two ways. What breaks wire.go's rules is refused whole, and
// the edge keeps the view it had. What only breaks §12.7's rules for a user is kept and never
// answered (a withheld row): those rules move between releases and stop at the write, so a row that
// slipped past them, or that a later release's stricter rule catches, costs its own name and not
// every write behind it in the journal, as refusing would. The row stays in Rows, since a local
// snapshot and a reload's diff have to agree with the server's.
//
// A name inside a suspended zone or host has no rows here, because the feed withheld them (§12.9).

package dnsservice

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"
	"github.com/urnetwork/connect"
)

// Ranges §12.7 refuses in a user's A and AAAA, and those a public address cannot be in at all, so an
// IPv4-mapped address reads as its IPv4 address. Format values: the registries' and not a setting.
var dnsNonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
}

// The one global unicast block IANA allocates from. Everything else in IPv6 is not public: ULA,
// link-local, multicast, the loopback and the mapped and compatible forms.
var dnsGlobalUnicastPrefix = netip.MustParsePrefix("2000::/3")

// connect's DNS stand-ins, which reach no host (connect/net_http_doh.go).
var dnsStandInAddresses = []netip.Addr{
	netip.MustParseAddr(connect.DefaultDnsUpgradeMaskAddress),
	netip.MustParseAddr(connect.DefaultDnsUpgradeMaskAddressIpv6),
}

// Whether §12.7 lets a user publish this address.
func isPublicDnsAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || slices.Contains(dnsStandInAddresses, address) {
		return false
	}
	if address.Is6() && !dnsGlobalUnicastPrefix.Contains(address) {
		return false
	}
	for _, prefix := range dnsNonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// §12.7's refused types, which only a system writer may hold.
func isRefusedUserType(rrType uint16) bool {
	switch rrType {
	case dns.TypeNS, dns.TypeSOA, dns.TypeDS, dns.TypeDNAME, dns.TypePTR, dns.TypeCAA, dns.TypeHTTPS, dns.TypeSVCB:
		return true
	}
	return false
}

// Whether a view holds this row and never answers it. See the file header.
func isWithheldRow(root string, set *DnsRecordSet, records []dns.RR) bool {
	// * is never a CNAME (D-DNS-6), and only the root's apex holds an SOA or NS (plan reading 2)
	if set.Type == dns.TypeCNAME && strings.HasPrefix(set.Owner, "*.") {
		return true
	}
	if (set.Type == dns.TypeSOA || set.Type == dns.TypeNS) && set.Owner != root {
		return true
	}
	if set.Kind != DnsRecordKindUser {
		return false
	}
	if isRefusedUserType(set.Type) {
		return true
	}
	for _, record := range records {
		var ip net.IP
		switch typed := record.(type) {
		case *dns.A:
			ip = typed.A
		case *dns.AAAA:
			ip = typed.AAAA
		default:
			continue
		}
		address, ok := netip.AddrFromSlice(ip)
		if !ok || !isPublicDnsAddress(address) {
			return true
		}
	}
	return false
}

// One row of a view, parsed once. Immutable.
type zoneRrset struct {
	set DnsRecordSet
	// The rdata as records, with the row's owner and TTL. Empty on edge, router and copy rows.
	records []dns.RR
	// Held and not answered. See the file header.
	withheld bool
}

// What one name holds. Immutable: a change makes a new node. A name exists while this holds a row or a
// child, and one holding only children is an empty non-terminal.
type zoneNode struct {
	// By type, ascending, so ANY answers the same RRset each time.
	rrsets []*zoneRrset
	// The copy row, which stands for every type the wildcard holds and this name does not.
	copyRow *zoneRrset
	// Names one label below this one that exist.
	childCount int
}

// Whether this name holds nothing and has no child, and so does not exist.
func (self *zoneNode) empty() bool {
	return len(self.rrsets) == 0 && self.copyRow == nil && self.childCount == 0
}

// A copy of this node, or an empty one for a name not there yet, ready to change.
func (self *zoneNode) clone() *zoneNode {
	if self == nil {
		return &zoneNode{}
	}
	clone := *self
	clone.rrsets = slices.Clone(self.rrsets)
	return &clone
}

// Where rrType sits in rrsets, and whether it is there.
func (self *zoneNode) rrsetIndex(rrType uint16) (int, bool) {
	return slices.BinarySearchFunc(self.rrsets, rrType, func(rrset *zoneRrset, rrType uint16) int {
		return int(rrset.set.Type) - int(rrType)
	})
}

// The RRset of rrType this name will answer, or nil. A CNAME beside other data is not answered: the
// lint refuses it at the write (RFC 2181 §10.1), so this is only what a view does should one arrive.
func (self *zoneNode) rrset(rrType uint16) *zoneRrset {
	index, found := self.rrsetIndex(rrType)
	if !found || self.rrsets[index].withheld {
		return nil
	}
	if rrType == dns.TypeCNAME && (1 < len(self.rrsets) || self.copyRow != nil) {
		return nil
	}
	return self.rrsets[index]
}

// Whether this name holds the row at key. A nil node is a name not there.
func (self *zoneNode) holds(key DnsRecordKey) bool {
	if self == nil {
		return false
	}
	if key.Type == DnsCopyType {
		return self.copyRow != nil
	}
	_, found := self.rrsetIndex(key.Type)
	return found
}

// Whether this name holds a row of its own, a copy row aside, withheld or not.
func (self *zoneNode) holdsOwnRows() bool {
	return len(self.rrsets) != 0
}

// The name one label up. name is below the root, so there is one.
func zoneParent(name string) string {
	next, _ := dns.NextLabel(name, 0)
	return name[next:]
}

// One root at one serial. See the file header. Safe for concurrent use, as it never changes.
type ZoneView struct {
	settings *DnsSettings
	root     string
	serial   uint64
	// Above every branch this view reaches, so its next build may write only its own.
	generation uint64
	names      zoneNames
	// The apex's SOA record, as served but for its serial. nil until a row gives one, and a view with
	// none answers SERVFAIL rather than deny with nothing to deny by.
	soa *dns.SOA
	// Rows held and not answered.
	withheldCount int
}

// Reads a snapshot into a view at its serial, or refuses it whole. settings must be valid, and the
// caller still closes rows. A row given twice is refused, since a snapshot holds each key once.
func NewZoneView(settings *DnsSettings, rows DnsSnapshotRows) (*ZoneView, error) {
	snapshot := rows.Snapshot()
	if err := checkDnsFormat(snapshot.Format); err != nil {
		return nil, err
	}
	if err := validateDnsRoot(snapshot.Root); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDnsRowMalformed, err)
	}
	self := &ZoneView{
		settings:   settings,
		root:       snapshot.Root,
		serial:     snapshot.Serial,
		generation: 1,
		names:      newZoneNames(),
	}
	for {
		set, err := rows.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if self.names.get(set.Owner).holds(set.Key()) {
			return nil, fmt.Errorf("%w: %s %s twice in a snapshot", ErrDnsRowMalformed, set.Owner, dnsTypeText(set.Type))
		}
		if err := self.upsert(self.generation, set); err != nil {
			return nil, err
		}
	}
	self.refreshSoa()
	return self, nil
}

// The zone this view holds, canonical.
func (self *ZoneView) Root() string {
	return self.root
}

// The serial this view holds whole, which the SOA carries the low 32 bits of (plan reading 4).
func (self *ZoneView) Serial() uint64 {
	return self.serial
}

// Rows held and never answered: zero unless a write path has a fault, so an edge reports it.
func (self *ZoneView) WithheldCount() int {
	return self.withheldCount
}

// Every row of this serial, withheld ones too, in no order a caller may rely on. The rows are the
// view's, so a caller reads them and does not keep or change them.
func (self *ZoneView) Rows() iter.Seq[*DnsRecordSet] {
	return func(yield func(set *DnsRecordSet) bool) {
		for _, node := range self.names.all() {
			for _, rrset := range node.rrsets {
				if !yield(&rrset.set) {
					return
				}
			}
			if node.copyRow != nil && !yield(&node.copyRow.set) {
				return
			}
		}
	}
}

// The view rows make of this one, whole or not at all: each must be the serial after the last, and a
// fault in any leaves this view as the one to answer from. rows may be empty, for this view.
//
// A row past the next serial fails with ErrDnsSerialGap, and one at or below this view's with
// ErrDnsSerialLower, since a view never lowers: only a reload's NewZoneView replaces one.
func (self *ZoneView) Apply(rows []DnsJournalRow) (*ZoneView, error) {
	if len(rows) == 0 {
		return self, nil
	}
	testHookBarrier("dnsservice.zone_apply.before", "")
	next := *self
	next.generation = self.generation + 1
	for index := range rows {
		row := &rows[index]
		if err := row.validateHead(); err != nil {
			return nil, err
		}
		if row.Root != self.root {
			return nil, fmt.Errorf("%w: a row of %s for %s", ErrDnsRowMalformed, row.Root, self.root)
		}
		if row.Serial <= next.serial {
			return nil, fmt.Errorf("%w: row %d at serial %d", ErrDnsSerialLower, row.Serial, next.serial)
		}
		if next.serial+1 < row.Serial {
			return nil, fmt.Errorf("%w: row %d at serial %d", ErrDnsSerialGap, row.Serial, next.serial)
		}
		for setIndex := range row.Upserts {
			if err := next.upsert(next.generation, &row.Upserts[setIndex]); err != nil {
				return nil, err
			}
		}
		for _, key := range row.Deletes {
			next.remove(next.generation, key)
		}
		next.serial = row.Serial
	}
	next.refreshSoa()
	testHookBarrier("dnsservice.zone_apply", "")
	testHookBarrier("dnsservice.zone_apply.after", "")
	return &next, nil
}

// Sets the row at set's key, adding its name if it is new. A build's write: the view is not yet
// published.
func (self *ZoneView) upsert(generation uint64, set *DnsRecordSet) error {
	records, err := set.parse(self.root)
	if err != nil {
		return err
	}
	rrset := &zoneRrset{set: set.Clone(), records: records, withheld: isWithheldRow(self.root, set, records)}
	before := self.names.get(set.Owner)
	node := before.clone()
	if set.Kind == DnsRecordKindCopy {
		self.countOut(node.copyRow)
		node.copyRow = rrset
	} else if index, found := node.rrsetIndex(set.Type); found {
		self.countOut(node.rrsets[index])
		node.rrsets[index] = rrset
	} else {
		node.rrsets = slices.Insert(node.rrsets, index, rrset)
	}
	if rrset.withheld {
		self.withheldCount += 1
	}
	self.names.set(generation, set.Owner, node)
	if before == nil {
		self.link(generation, set.Owner)
	}
	return nil
}

// Takes the count of a row leaving the view. nil is no row.
func (self *ZoneView) countOut(rrset *zoneRrset) {
	if rrset != nil && rrset.withheld {
		self.withheldCount -= 1
	}
}

// Deletes the row at key, and its name once nothing holds it. A key not there is no fault, since a
// delete means the same either way.
func (self *ZoneView) remove(generation uint64, key DnsRecordKey) {
	before := self.names.get(key.Owner)
	if before == nil {
		return
	}
	node := before.clone()
	if key.Type == DnsCopyType {
		if node.copyRow == nil {
			return
		}
		self.countOut(node.copyRow)
		node.copyRow = nil
	} else {
		index, found := node.rrsetIndex(key.Type)
		if !found {
			return
		}
		self.countOut(node.rrsets[index])
		node.rrsets = slices.Delete(node.rrsets, index, index+1)
	}
	self.setOrDrop(generation, key.Owner, node)
}

// Stores node, or takes out its name when nothing holds it any more.
func (self *ZoneView) setOrDrop(generation uint64, name string, node *zoneNode) {
	if !node.empty() {
		self.names.set(generation, name, node)
		return
	}
	self.names.remove(generation, name)
	if name != self.root {
		parent := zoneParent(name)
		parentNode := self.names.get(parent).clone()
		parentNode.childCount -= 1
		self.setOrDrop(generation, parent, parentNode)
	}
}

// Counts a new name in its parent, which makes empty non-terminals of the names above it that held
// nothing yet.
func (self *ZoneView) link(generation uint64, name string) {
	for name != self.root {
		parent := zoneParent(name)
		before := self.names.get(parent)
		node := before.clone()
		node.childCount += 1
		self.names.set(generation, parent, node)
		if before != nil {
			return
		}
		name = parent
	}
}

// Reads the apex's SOA, once a build's rows are in.
func (self *ZoneView) refreshSoa() {
	self.soa = nil
	if apex := self.names.get(self.root); apex != nil {
		if rrset := apex.rrset(dns.TypeSOA); rrset != nil {
			self.soa = rrset.records[0].(*dns.SOA)
		}
	}
}

// The addresses edge and router rows answer now. Immutable, so DNS-M5-07's prober builds a new set and
// swaps it in through an atomic pointer, an answer takes no lock, and a health drop reaches every name
// answered from it with no journal write. A nil set holds no address.
type HealthySet struct {
	edgeIpv4   []netip.Addr
	edgeIpv6   []netip.Addr
	routerIpv4 []netip.Addr
	routerIpv6 []netip.Addr
}

// Each list's addresses of one family, sorted, so one set answers the same bytes each time.
func healthyAddresses(interfaces []DnsLbInterface) (ipv4s []netip.Addr, ipv6s []netip.Addr) {
	for index := range interfaces {
		if address := interfaces[index].Ipv4.Unmap(); address.Is4() {
			ipv4s = append(ipv4s, address)
		}
		if address := interfaces[index].Ipv6; address.Is6() {
			ipv6s = append(ipv6s, address)
		}
	}
	slices.SortFunc(ipv4s, netip.Addr.Compare)
	slices.SortFunc(ipv6s, netip.Addr.Compare)
	return slices.Compact(ipv4s), slices.Compact(ipv6s)
}

// A set from the interfaces healthy for user names and those healthy for mail. The two are apart since
// a failed 25 banner drops an interface from mx hosts alone (DNS-M7-01).
func NewHealthySet(edge []DnsLbInterface, router []DnsLbInterface) *HealthySet {
	self := &HealthySet{}
	self.edgeIpv4, self.edgeIpv6 = healthyAddresses(edge)
	self.routerIpv4, self.routerIpv6 = healthyAddresses(router)
	return self
}

// What a row of this kind and type answers.
func (self *HealthySet) addresses(kind DnsRecordKind, rrType uint16) []netip.Addr {
	if self == nil {
		return nil
	}
	switch {
	case kind == DnsRecordKindEdge && rrType == dns.TypeA:
		return self.edgeIpv4
	case kind == DnsRecordKindEdge && rrType == dns.TypeAAAA:
		return self.edgeIpv6
	case kind == DnsRecordKindRouter && rrType == dns.TypeA:
		return self.routerIpv4
	case kind == DnsRecordKindRouter && rrType == dns.TypeAAAA:
		return self.routerIpv6
	}
	return nil
}
