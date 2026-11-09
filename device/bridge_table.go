// §17.5's classify: which entry of the sender's table a packet's destination falls in, by longest prefix (R-BRIDGE-1).
// In-repo rather than bart, since device/ imports nothing third-party (plan-BRIDGE-small-readings #1): NewBridgeTable
// flattens the prefixes into sorted, disjoint ranges of the IPv4 space, each naming the entry that owns it, so the
// longest prefix is decided once, at build, and a lookup is a binary search over about twice as many ranges as there
// are prefixes, with no allocation and no lock.
//
// An entry owns its range outright (§17.7): whatever its links' health, a destination in it classifies to it, never
// to a broader prefix or the default route, which could reach another network that reuses the addresses. A carve, a
// local /32 the physical path needs (§17.4), is the one way back to the default route, and wins over every entry,
// one of the same prefix included.
//
// A table is immutable once built and safe for concurrent use; a bridge swaps a new one in by pointer.

package device

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One prefix of the sender's table.
type BridgeEntry struct {
	Prefix netip.Prefix
	Kind   bridge.BridgeRuleEntryKind
	// Which of BridgeRules.entries this is, for whatever routes over it; the table never reads it. -1 for an entry the
	// device adds itself, as a carve.
	RuleIndex int
}

// Entries a table cannot be built from.
var ErrBridgeTableInvalid = errors.New("bridge table invalid")

// The sender's table. See the file's comment.
type BridgeTable struct {
	entries []BridgeEntry
	// starts[i] is the first address of range i, and starts[0] is 0, so every address has a range. Each range runs to
	// the next one's start.
	starts []uint32
	// The entry owning each range, -1 for the default route.
	entryIndexes []int32
}

// The offsets of the IPv4 header fields Classify reads.
const (
	bridgeIpv4HeaderByteCount   = 20
	bridgeIpv4DestinationOffset = 16
)

// Builds the table of entries, which it copies. Each prefix must be IPv4 with no host bits, each kind known, and no
// two entries may share a prefix, unless one of them is a carve, which wins.
func NewBridgeTable(entries []BridgeEntry) (*BridgeTable, error) {
	self := &BridgeTable{}
	byPrefix := map[netip.Prefix]int{}
	for _, entry := range entries {
		if !entry.Prefix.Addr().Is4() || entry.Prefix.Masked() != entry.Prefix {
			return nil, fmt.Errorf("%w: a prefix that is not IPv4 with no host bits", ErrBridgeTableInvalid)
		}
		switch entry.Kind {
		case bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK,
			bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNASSIGNED,
			bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_CARVED,
			bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE:
		default:
			return nil, fmt.Errorf("%w: kind %d", ErrBridgeTableInvalid, entry.Kind)
		}
		carved := entry.Kind == bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_CARVED
		if at, held := byPrefix[entry.Prefix]; held {
			heldCarved := self.entries[at].Kind == bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_CARVED
			if !carved && !heldCarved {
				return nil, fmt.Errorf("%w: two entries of one prefix", ErrBridgeTableInvalid)
			}
			// a carve wins its prefix
			if carved {
				self.entries[at] = entry
			}
			continue
		}
		byPrefix[entry.Prefix] = len(self.entries)
		self.entries = append(self.entries, entry)
	}
	self.flatten()
	return self, nil
}

// An entry's range of addresses, both ends included.
type bridgeTableSpan struct {
	first uint32
	last  uint32
	// the entry, or -1 for the default route
	entryIndex int32
}

// The first and last addresses of an IPv4 prefix.
func bridgePrefixSpan(prefix netip.Prefix) (uint32, uint32) {
	octets := prefix.Addr().As4()
	first := uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
	hostBits := 32 - prefix.Bits()
	if hostBits == 32 {
		return 0, 0xFFFFFFFF
	}
	return first, first | (uint32(1)<<hostBits - 1)
}

// Lays the entries' spans out as disjoint ranges, each owned by the innermost span covering it. Prefixes nest or are
// disjoint, so a sweep in order of first address, broader first, with a stack of the spans open at the cursor, gives
// each range its innermost span.
func (self *BridgeTable) flatten() {
	spans := make([]bridgeTableSpan, 0, len(self.entries))
	for i, entry := range self.entries {
		first, last := bridgePrefixSpan(entry.Prefix)
		entryIndex := int32(i)
		if entry.Kind == bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_CARVED {
			entryIndex = -1
		}
		spans = append(spans, bridgeTableSpan{first: first, last: last, entryIndex: entryIndex})
	}
	slices.SortFunc(spans, func(a bridgeTableSpan, b bridgeTableSpan) int {
		if order := cmp.Compare(a.first, b.first); order != 0 {
			return order
		}
		// the broader first, so it is open when the narrower one starts
		return cmp.Compare(b.last, a.last)
	})
	self.starts = make([]uint32, 0, 2*len(spans)+1)
	self.entryIndexes = make([]int32, 0, 2*len(spans)+1)
	emit := func(start uint32, entryIndex int32) {
		if last := len(self.entryIndexes) - 1; 0 <= last && self.entryIndexes[last] == entryIndex {
			return
		}
		self.starts = append(self.starts, start)
		self.entryIndexes = append(self.entryIndexes, entryIndex)
	}
	// the next address no range covers yet; past the space once it reaches 1 << 32
	cursor := uint64(0)
	open := []bridgeTableSpan{}
	closeSpan := func(span bridgeTableSpan) {
		if cursor <= uint64(span.last) {
			emit(uint32(cursor), span.entryIndex)
			cursor = uint64(span.last) + 1
		}
	}
	for _, span := range spans {
		for 0 < len(open) && open[len(open)-1].last < span.first {
			closeSpan(open[len(open)-1])
			open = open[:len(open)-1]
		}
		if cursor < uint64(span.first) {
			entryIndex := int32(-1)
			if 0 < len(open) {
				entryIndex = open[len(open)-1].entryIndex
			}
			emit(uint32(cursor), entryIndex)
			cursor = uint64(span.first)
		}
		open = append(open, span)
	}
	for 0 < len(open) {
		closeSpan(open[len(open)-1])
		open = open[:len(open)-1]
	}
	if cursor <= 0xFFFFFFFF {
		emit(uint32(cursor), -1)
	}
}

// The entry a packet's destination falls in, by longest prefix, or nil for the default route: no entry, a carve, or a
// packet that is not IPv4 or too short for its header. Reads the destination at its fixed offset, which every fragment
// carries, so a datagram's fragments classify alike. Allocates nothing.
func (self *BridgeTable) Classify(packet []byte) *BridgeEntry {
	if len(packet) < bridgeIpv4HeaderByteCount || packet[0]>>4 != 4 {
		return nil
	}
	destination := uint32(packet[bridgeIpv4DestinationOffset])<<24 | uint32(packet[bridgeIpv4DestinationOffset+1])<<16 |
		uint32(packet[bridgeIpv4DestinationOffset+2])<<8 | uint32(packet[bridgeIpv4DestinationOffset+3])
	return self.Lookup(destination)
}

// The entry an IPv4 address, as four bytes most significant first, falls in, or nil for the default route.
func (self *BridgeTable) Lookup(destination uint32) *BridgeEntry {
	// the last range starting at or before destination; starts[0] is 0, so there is one. Each step halves what is
	// left with a conditional move rather than a branch, which a destination's bits would mispredict half the time.
	starts := self.starts
	base := 0
	for remaining := len(starts); 1 < remaining; {
		half := remaining >> 1
		if starts[base+half] <= destination {
			base += half
		}
		remaining -= half
	}
	entryIndex := self.entryIndexes[base]
	if entryIndex < 0 {
		return nil
	}
	return &self.entries[entryIndex]
}

// The entries the table holds, after carves won their prefixes. Callers must not change them.
func (self *BridgeTable) Entries() []BridgeEntry {
	return self.entries
}

// How many disjoint ranges the table holds, which bounds a lookup's probes by its logarithm.
func (self *BridgeTable) RangeCount() int {
	return len(self.starts)
}

// The entries of rules ParseBridgeRules returned, for NewBridgeTable, each with its place in BridgeRules.entries. A
// prefix it cannot read fails the whole, as the parse would have.
func BridgeRulesEntries(rules *bridge.BridgeRules) ([]BridgeEntry, error) {
	entries := make([]BridgeEntry, 0, len(rules.GetEntries()))
	for i, entry := range rules.GetEntries() {
		prefix, ok := bridgeRulePrefix(entry.GetPrefix())
		if !ok {
			return nil, fmt.Errorf("%w: entries[%d]'s prefix", ErrBridgeRulesMalformed, i)
		}
		entries = append(entries, BridgeEntry{Prefix: prefix, Kind: entry.GetKind(), RuleIndex: i})
	}
	return entries, nil
}
