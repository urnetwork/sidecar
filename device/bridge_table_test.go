// §22.5's "Classify = linear scan": the flattened table against a linear longest-prefix scan over random prefix sets
// with nesting, /32s and carves, at every range edge, and §17.5's and §17.7's cases one at a time.

package device_test

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	bridgeTableLink       = bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK
	bridgeTableUnassigned = bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNASSIGNED
	bridgeTableCarved     = bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_CARVED
	bridgeTableService    = bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE
)

// An IPv4 header of 20 bytes to destination, and a payload byte, as a tun hands one over.
func bridgeTestPacket(destination netip.Addr) []byte {
	packet := make([]byte, 21)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], []byte{192, 0, 2, 1})
	octets := destination.As4()
	copy(packet[16:20], octets[:])
	return packet
}

// An address as Lookup takes one.
func bridgeTestAddress(address netip.Addr) uint32 {
	octets := address.As4()
	return uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
}

// The address Lookup's form names.
func bridgeTestAddr(address uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)})
}

// The reference: every entry scanned, the longest prefix holding the address kept, a carve winning its prefix and
// standing for the default route. Shares no code with the table.
func bridgeTestLinearScan(entries []device.BridgeEntry, address netip.Addr) (netip.Prefix, bool) {
	best := -1
	for i, entry := range entries {
		if !entry.Prefix.Contains(address) {
			continue
		}
		if best < 0 || entries[best].Prefix.Bits() < entry.Prefix.Bits() ||
			(entries[best].Prefix.Bits() == entry.Prefix.Bits() && entry.Kind == bridgeTableCarved) {
			best = i
		}
	}
	if best < 0 || entries[best].Kind == bridgeTableCarved {
		return netip.Prefix{}, false
	}
	return entries[best].Prefix, true
}

// A random set of prefixes as a sender's table holds them: a block with nested overlay /32s, subnets nested in each
// other, carves inside both, each kind at random, and no two non-carves of one prefix.
func bridgeTestRandomEntries(random *rand.Rand, count int) []device.BridgeEntry {
	entries := []device.BridgeEntry{}
	held := map[netip.Prefix]bool{}
	add := func(prefix netip.Prefix, kind bridge.BridgeRuleEntryKind) {
		prefix = prefix.Masked()
		if kind != bridgeTableCarved && held[prefix] {
			return
		}
		if kind != bridgeTableCarved {
			held[prefix] = true
		}
		entries = append(entries, device.BridgeEntry{Prefix: prefix, Kind: kind, RuleIndex: len(entries)})
	}
	randomAddr := func() netip.Addr {
		return bridgeTestAddr(random.Uint32())
	}
	within := func(prefix netip.Prefix) netip.Addr {
		first := bridgeTestAddress(prefix.Addr())
		span := uint64(1) << (32 - prefix.Bits())
		return bridgeTestAddr(first + uint32(random.Uint64N(span)))
	}
	kinds := []bridge.BridgeRuleEntryKind{bridgeTableLink, bridgeTableUnassigned, bridgeTableService, bridgeTableLink}
	for len(entries) < count {
		switch random.IntN(4) {
		case 0:
			// a fresh prefix anywhere, of any length
			add(netip.PrefixFrom(randomAddr(), 1+random.IntN(32)), kinds[random.IntN(len(kinds))])
		case 1, 2:
			// nested inside one already held
			if len(entries) == 0 {
				continue
			}
			outer := entries[random.IntN(len(entries))].Prefix
			if outer.Bits() == 32 {
				continue
			}
			length := outer.Bits() + 1 + random.IntN(32-outer.Bits())
			add(netip.PrefixFrom(within(outer), length), kinds[random.IntN(len(kinds))])
		case 3:
			// a carve, inside a held prefix or alone, sometimes on a held /32
			if len(entries) == 0 {
				add(netip.PrefixFrom(randomAddr(), 32), bridgeTableCarved)
				continue
			}
			outer := entries[random.IntN(len(entries))].Prefix
			add(netip.PrefixFrom(within(outer), 32), bridgeTableCarved)
		}
	}
	return entries
}

// Every edge of every range, each address on either side of one, and random addresses besides.
func bridgeTestProbes(random *rand.Rand, entries []device.BridgeEntry) []netip.Addr {
	probes := []netip.Addr{bridgeTestAddr(0), bridgeTestAddr(0xFFFFFFFF)}
	for _, entry := range entries {
		first := bridgeTestAddress(entry.Prefix.Addr())
		last := first | uint32(uint64(1)<<(32-entry.Prefix.Bits())-1)
		for _, address := range []uint32{first - 1, first, first + 1, last - 1, last, last + 1} {
			probes = append(probes, bridgeTestAddr(address))
		}
	}
	for range 256 {
		probes = append(probes, bridgeTestAddr(random.Uint32()))
	}
	return probes
}

func TestBridgeTableClassifyEqualsLinearScan(t *testing.T) {
	for seed := range uint64(300) {
		random := rand.New(rand.NewPCG(seed, 0x6272696467652d74))
		entries := bridgeTestRandomEntries(random, 1+random.IntN(64))
		table, err := device.NewBridgeTable(entries)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, address := range bridgeTestProbes(random, entries) {
			wantPrefix, wantEntry := bridgeTestLinearScan(entries, address)
			got := table.Classify(bridgeTestPacket(address))
			switch {
			case !wantEntry && got != nil:
				t.Fatalf("seed %d, %v: %v, want the default route", seed, address, got.Prefix)
			case wantEntry && got == nil:
				t.Fatalf("seed %d, %v: the default route, want %v", seed, address, wantPrefix)
			case wantEntry && got.Prefix != wantPrefix:
				t.Fatalf("seed %d, %v: %v, want %v", seed, address, got.Prefix, wantPrefix)
			}
			if lookedUp := table.Lookup(bridgeTestAddress(address)); lookedUp != got {
				t.Fatalf("seed %d, %v: Lookup and Classify differ", seed, address)
			}
		}
		if bound := 2*len(entries) + 1; bound < table.RangeCount() {
			t.Fatalf("seed %d: %d ranges for %d entries", seed, table.RangeCount(), len(entries))
		}
	}
}

// One table for the cases below: a block with services and an overlay host, a subnet holding a nested subnet holding
// a host route, and a link entry left with no advertiser.
func bridgeTestTable(t *testing.T, extra ...device.BridgeEntry) *device.BridgeTable {
	t.Helper()
	entries := append([]device.BridgeEntry{
		{Prefix: netip.MustParsePrefix("100.80.0.0/16"), Kind: bridgeTableUnassigned, RuleIndex: 0},
		{Prefix: netip.MustParsePrefix("100.80.0.0/24"), Kind: bridgeTableService, RuleIndex: 1},
		{Prefix: netip.MustParsePrefix("100.80.1.3/32"), Kind: bridgeTableLink, RuleIndex: 2},
		{Prefix: netip.MustParsePrefix("198.51.0.0/16"), Kind: bridgeTableLink, RuleIndex: 3},
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Kind: bridgeTableLink, RuleIndex: 4},
		{Prefix: netip.MustParsePrefix("198.51.100.77/32"), Kind: bridgeTableLink, RuleIndex: 5},
		{Prefix: netip.MustParsePrefix("100.80.9.0/24"), Kind: bridgeTableLink, RuleIndex: 6},
	}, extra...)
	table, err := device.NewBridgeTable(entries)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// The rule index of what an address classifies to, -1 for the default route.
func bridgeTestClassify(table *device.BridgeTable, address string) int {
	entry := table.Classify(bridgeTestPacket(netip.MustParseAddr(address)))
	if entry == nil {
		return -1
	}
	return entry.RuleIndex
}

func TestBridgeTableNestedPrefixWins(t *testing.T) {
	table := bridgeTestTable(t)
	cases := []struct {
		address string
		want    int
	}{
		{"198.51.7.7", 3},
		{"198.51.100.1", 4},
		{"198.51.100.77", 5},
		{"198.51.100.78", 4},
		{"198.51.101.0", 3},
		{"100.80.1.3", 2},
		{"100.80.1.4", 0},
		{"100.80.0.53", 1},
		{"203.0.113.9", -1},
	}
	for _, c := range cases {
		if got := bridgeTestClassify(table, c.address); got != c.want {
			t.Errorf("%s: %d, want %d", c.address, got, c.want)
		}
	}
}

// §17.7's trap: an entry owns its range whatever its links do. One left with no advertiser still classifies to itself,
// which answers with rejects, and never to the block around it or the default route.
func TestBridgeTableEntryWithNoAdvertiserDoesNotFallThrough(t *testing.T) {
	table := bridgeTestTable(t)
	for _, address := range []string{"100.80.9.0", "100.80.9.1", "100.80.9.255"} {
		if got := bridgeTestClassify(table, address); got != 6 {
			t.Errorf("%s: %d, want the entry with no advertiser", address, got)
		}
	}
	// and the block resumes past it
	if got := bridgeTestClassify(table, "100.80.10.0"); got != 0 {
		t.Errorf("past the entry: %d", got)
	}
}

// §17.4's carve: a local /32 inside an entry, or on one, takes the default route, and only that /32.
func TestBridgeTableCarveTakesTheDefaultRoute(t *testing.T) {
	table := bridgeTestTable(t,
		device.BridgeEntry{Prefix: netip.MustParsePrefix("100.80.4.4/32"), Kind: bridgeTableCarved, RuleIndex: -1},
		device.BridgeEntry{Prefix: netip.MustParsePrefix("198.51.100.1/32"), Kind: bridgeTableCarved, RuleIndex: -1},
		device.BridgeEntry{Prefix: netip.MustParsePrefix("100.80.1.3/32"), Kind: bridgeTableCarved, RuleIndex: -1},
	)
	cases := []struct {
		address string
		want    int
	}{
		{"100.80.4.4", -1},
		{"100.80.4.3", 0},
		{"100.80.4.5", 0},
		{"198.51.100.1", -1},
		{"198.51.100.2", 4},
		{"100.80.1.3", -1},
	}
	for _, c := range cases {
		if got := bridgeTestClassify(table, c.address); got != c.want {
			t.Errorf("%s: %d, want %d", c.address, got, c.want)
		}
	}
}

// What is not an IPv4 header takes the default route; every fragment of a datagram classifies as the datagram does,
// since each carries the destination at its fixed offset.
func TestBridgeTableShortV6AndFragmentPackets(t *testing.T) {
	table := bridgeTestTable(t)
	packet := bridgeTestPacket(netip.MustParseAddr("198.51.100.77"))
	if table.Classify(packet[:19]) != nil || table.Classify(nil) != nil {
		t.Fatal("a short packet classified")
	}
	v6 := make([]byte, 60)
	v6[0] = 0x60
	if table.Classify(v6) != nil {
		t.Fatal("an IPv6 packet classified")
	}
	whole := table.Classify(packet)
	first := append([]byte{}, packet...)
	// more fragments, offset 0
	first[6] = 0x20
	later := append([]byte{}, packet...)
	// the last fragment, at offset 185 eight-byte units
	later[6], later[7] = 0x00, 0xB9
	if whole == nil || table.Classify(first) != whole || table.Classify(later) != whole {
		t.Fatal("a fragment classified apart from its datagram")
	}
	// options lengthen the header, and the destination stays at its offset
	withOptions := append([]byte{}, packet...)
	withOptions[0] = 0x46
	if table.Classify(withOptions) != whole {
		t.Fatal("a header with options classified apart")
	}
}

// The edges of the space: an entry from 0.0.0.0 and one ending at 255.255.255.255.
func TestBridgeTableEdgesOfTheSpace(t *testing.T) {
	table, err := device.NewBridgeTable([]device.BridgeEntry{
		{Prefix: netip.MustParsePrefix("0.0.0.0/8"), Kind: bridgeTableLink, RuleIndex: 0},
		{Prefix: netip.MustParsePrefix("255.255.255.255/32"), Kind: bridgeTableLink, RuleIndex: 1},
		{Prefix: netip.MustParsePrefix("128.0.0.0/1"), Kind: bridgeTableUnassigned, RuleIndex: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		address string
		want    int
	}{
		{"0.0.0.0", 0},
		{"0.255.255.255", 0},
		{"1.0.0.0", -1},
		{"127.255.255.255", -1},
		{"128.0.0.0", 2},
		{"255.255.255.254", 2},
		{"255.255.255.255", 1},
	}
	for _, c := range cases {
		if got := bridgeTestClassify(table, c.address); got != c.want {
			t.Errorf("%s: %d, want %d", c.address, got, c.want)
		}
	}
	empty, err := device.NewBridgeTable(nil)
	if err != nil || empty.Classify(bridgeTestPacket(netip.MustParseAddr("192.0.2.1"))) != nil || empty.RangeCount() != 1 {
		t.Fatal("an empty table routed something")
	}
}

func TestBridgeTableRefusesWhatItCannotBuild(t *testing.T) {
	cases := []struct {
		name    string
		entries []device.BridgeEntry
	}{
		{name: "IPv6", entries: []device.BridgeEntry{{Prefix: netip.MustParsePrefix("2001:db8::/32"), Kind: bridgeTableLink}}},
		{name: "host bits", entries: []device.BridgeEntry{{Prefix: netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 24), Kind: bridgeTableLink}}},
		{name: "no prefix", entries: []device.BridgeEntry{{Kind: bridgeTableLink}}},
		{name: "no kind", entries: []device.BridgeEntry{{Prefix: netip.MustParsePrefix("192.0.2.0/24")}}},
		{name: "two of one prefix", entries: []device.BridgeEntry{
			{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Kind: bridgeTableLink},
			{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Kind: bridgeTableUnassigned},
		}},
	}
	for _, c := range cases {
		if _, err := device.NewBridgeTable(c.entries); !errors.Is(err, device.ErrBridgeTableInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// The fixture's rules as a table, through BridgeRulesEntries: each entry where its rules put it.
func TestBridgeTableFromRules(t *testing.T) {
	rules, err := device.ParseBridgeRules(bridgeRulesTestFixture().Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := device.BridgeRulesEntries(rules)
	if err != nil {
		t.Fatal(err)
	}
	table, err := device.NewBridgeTable(entries)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		address string
		want    int
	}{
		{"100.80.200.1", 0},
		{"100.80.0.53", 1},
		{"100.80.7.7", -1},
		{"100.80.1.3", 3},
		{"192.0.2.9", 4},
		{"100.80.9.9", 5},
		{"203.0.113.1", -1},
	}
	for _, c := range cases {
		if got := bridgeTestClassify(table, c.address); got != c.want {
			t.Errorf("%s: %d, want %d", c.address, got, c.want)
		}
	}
}

// R-BRIDGE-9: a lookup allocates nothing, whatever it finds.
func TestBridgeTableClassifyAllocatesNothing(t *testing.T) {
	table := bridgeTestTable(t)
	packets := [][]byte{
		bridgeTestPacket(netip.MustParseAddr("198.51.100.77")),
		bridgeTestPacket(netip.MustParseAddr("203.0.113.9")),
		bridgeTestPacket(netip.MustParseAddr("100.80.9.1")),
		{0x60},
	}
	allocations := testing.AllocsPerRun(1000, func() {
		for _, packet := range packets {
			table.Classify(packet)
		}
	})
	if allocations != 0 {
		t.Fatalf("%v allocations a run", allocations)
	}
}
