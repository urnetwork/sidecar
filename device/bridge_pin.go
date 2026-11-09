// §17.5's pins (D-BRIDGE-7, D-BRIDGE-9): which of an entry's links a packet takes, so a live pair stays on its link
// across edits, since TCP cannot change its exit mid-flow. A pin keys on the pair, (source, destination, protocol),
// which every fragment's header carries, so a pair's flows and fragments share one link; only a TCP connection under a
// 5-tuple pin (the syn row) leaves its pair's link. Pick follows the rows in order:
//
//	no choice  an entry with one link routes over it and records nothing
//	lookup     a TCP segment's 5-tuple pin, then its pair's pin, while that link still serves the entry
//	syn        a SYN of a pair the window would pin, or pinned to a draining link, takes the hash over the entry's
//	           undrained links under a 5-tuple pin, so new connections take the new rule at once; with no such link
//	           or no free slot it follows its pair
//	window     a pinless pair at first sight goes to the link the entry had before it offered a choice, pinned
//	hash       else weighted rendezvous over the advertisers that are up (D-BRIDGE-9), or over every live one when
//	           none is up, or over the draining ones when nothing else remains, pinned where a slot is free
//	full       no free slot: the pair routes by the hash unpinned, and nothing is refused (owner decision 66)
//	idle       a pin ends 600 s after its pair's last packet for TCP, 5 min otherwise
//	record     a pin's last-seen time is written at most once a second
//
// The table is a fixed array of slots of atomics, with no lock and no allocation on the packet path. A key hashes to a
// run of bridgePinProbeCount slots, and a hit compares the whole key, so a collision never routes one pair onto
// another's link. Each slot is a seqlock: a writer takes it from an even sequence to odd with a compare-and-swap from
// the sequence it read, writes, and makes it even again; a reader takes its words between two equal even reads, so a
// slot is read whole. A writer that loses the race writes nothing, and the pair is pinned at a later packet. Pure
// logic on the injected clock: links are integers here.
//
// A BridgePinTable is safe for concurrent use.

package device

import (
	"encoding/binary"
	"math"
	"math/bits"
	"sync/atomic"
	"time"
)

// The slots a key may sit in, from the one it hashes to: the table's associativity.
const bridgePinProbeCount = 4

// How many times a read of a slot a writer holds is tried before the slot counts as unreadable this time.
const bridgePinReadAttemptCount = 64

// The bits of a slot's second key word.
const (
	bridgePinOccupiedBit   = uint64(1) << 63
	bridgePinFiveTupleBit  = uint64(1) << 62
	bridgePinEntryIdShift  = 40
	bridgePinEntryIdMask   = 0xFFFFF
	bridgePinProtocolShift = 32
)

// One slot. sequence is odd while a writer holds it.
type bridgePinSlot struct {
	sequence atomic.Uint64
	// source << 32 | destination
	key0 atomic.Uint64
	// occupied, five-tuple, entry id, protocol, source port << 16 | destination port; 0 for an empty slot
	key1 atomic.Uint64
	// link << 32 | the last second a packet of the pin was seen, counted from the table's epoch
	value atomic.Uint64
}

// Reads the slot whole: its sequence and words, or false when a writer held it through every attempt.
func (self *bridgePinSlot) read() (sequence uint64, key0 uint64, key1 uint64, value uint64, ok bool) {
	for range bridgePinReadAttemptCount {
		sequence = self.sequence.Load()
		if sequence&1 != 0 {
			continue
		}
		key0 = self.key0.Load()
		key1 = self.key1.Load()
		value = self.value.Load()
		if self.sequence.Load() == sequence {
			return sequence, key0, key1, value, true
		}
	}
	return 0, 0, 0, 0, false
}

// Writes the slot if it is still as read at sequence: false when another writer came first.
func (self *bridgePinSlot) write(sequence uint64, key0 uint64, key1 uint64, value uint64) bool {
	if !self.sequence.CompareAndSwap(sequence, sequence+1) {
		return false
	}
	self.key0.Store(key0)
	self.key1.Store(key1)
	self.value.Store(value)
	self.sequence.Store(sequence + 2)
	return true
}

// A packet's pin keys and what Pick reads of its TCP header.
type bridgePinPacket struct {
	key0 uint64
	// the pair's second word, with no ports and no five-tuple bit, and the entry id still to add
	pairKey1 uint64
	// the 5-tuple's, the same and its ports
	fiveTupleKey1 uint64
	tcp           bool
	// a TCP segment whose ports were read: a first fragment or a whole one
	hasPorts bool
	// a SYN without ACK: a new connection
	syn bool
	// the pair's hash, which rendezvous mixes each link into
	pairHash uint64
}

// Reads a packet's keys at their fixed offsets: false for anything shorter than its IPv4 header.
func bridgePinPacketOf(packet []byte) (bridgePinPacket, bool) {
	if len(packet) < bridgeIpv4HeaderByteCount || packet[0]>>4 != 4 {
		return bridgePinPacket{}, false
	}
	headerByteCount := int(packet[0]&0x0F) * 4
	if headerByteCount < bridgeIpv4HeaderByteCount || len(packet) < headerByteCount {
		return bridgePinPacket{}, false
	}
	protocol := uint64(packet[9])
	parsed := bridgePinPacket{
		key0:     uint64(binary.BigEndian.Uint32(packet[12:16]))<<32 | uint64(binary.BigEndian.Uint32(packet[16:20])),
		pairKey1: bridgePinOccupiedBit | protocol<<bridgePinProtocolShift,
		tcp:      protocol == bridgeProtocolTcp,
	}
	parsed.pairHash = bridgePinMix(parsed.key0 ^ bridgePinMix(parsed.pairKey1))
	fragmentOffset := binary.BigEndian.Uint16(packet[6:8]) & 0x1FFF
	if parsed.tcp && fragmentOffset == 0 && headerByteCount+14 <= len(packet) {
		tcpHeader := packet[headerByteCount:]
		parsed.hasPorts = true
		ports := uint64(binary.BigEndian.Uint32(tcpHeader[0:4]))
		parsed.fiveTupleKey1 = parsed.pairKey1 | bridgePinFiveTupleBit | ports
		flags := tcpHeader[13]
		parsed.syn = flags&0x02 != 0 && flags&0x10 == 0
	}
	return parsed, true
}

// A 64-bit finalizer (splitmix64's), so each bit of the key moves every bit of the hash.
func bridgePinMix(value uint64) uint64 {
	value ^= value >> 30
	value *= 0xBF58476D1CE4E5B9
	value ^= value >> 27
	value *= 0x94D049BB133111EB
	value ^= value >> 31
	return value
}

// The sender's pins. See the file's comment.
type BridgePinTable struct {
	settings *BridgeSettings
	clock    Clock
	// what last-seen seconds count from
	epoch time.Time
	slots []bridgePinSlot
	mask  uint64
	// seconds between two writes of a pin's last-seen time, at least 1
	touchSeconds uint32
	// picks that found no free slot for the pin they wanted
	unpinnedPickCount atomic.Uint64
}

// A table of PinSlotCount slots, rounded up to a power of two and to at least bridgePinProbeCount. Nil settings are
// DefaultBridgeSettings.
func NewBridgePinTable(settings *BridgeSettings) *BridgePinTable {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	slotCount := max(settings.PinSlotCount, bridgePinProbeCount)
	if slotCount&(slotCount-1) != 0 {
		slotCount = 1 << bits.Len(uint(slotCount))
	}
	clock := settings.clock()
	return &BridgePinTable{
		settings:     settings,
		clock:        clock,
		epoch:        clock.Now(),
		slots:        make([]bridgePinSlot, slotCount),
		mask:         uint64(slotCount - 1),
		touchSeconds: uint32(max(1, (settings.PinTouchInterval+time.Second-1)/time.Second)),
	}
}

// Seconds since the table's epoch.
func (self *BridgePinTable) seconds(now time.Time) uint32 {
	elapsed := now.Sub(self.epoch)
	if elapsed < 0 {
		return 0
	}
	return uint32(elapsed / time.Second)
}

// How long a pin of the protocol idles before it ends.
func (self *BridgePinTable) idleSeconds(tcp bool) uint32 {
	if tcp {
		return uint32(self.settings.PinTcpIdleTimeout / time.Second)
	}
	return uint32(self.settings.PinIdleTimeout / time.Second)
}

// Whether a pin last seen at lastSeen has idled out at nowSeconds, by its key's protocol.
func (self *BridgePinTable) expired(key1 uint64, lastSeen uint32, nowSeconds uint32) bool {
	tcp := (key1>>bridgePinProtocolShift)&0xFF == bridgeProtocolTcp
	return lastSeen <= nowSeconds && self.idleSeconds(tcp) <= nowSeconds-lastSeen
}

// The first slot of a key's run.
func (self *BridgePinTable) home(key0 uint64, key1 uint64) uint64 {
	return bridgePinMix(key0^bridgePinMix(key1)) & self.mask
}

// The live pin of a key: its link, the slot holding it and the sequence it was read at, or link 0 for none.
func (self *BridgePinTable) lookup(key0 uint64, key1 uint64, nowSeconds uint32) (BridgeLinkId, uint64, uint64) {
	home := self.home(key0, key1)
	for probe := range uint64(bridgePinProbeCount) {
		index := (home + probe) & self.mask
		sequence, slotKey0, slotKey1, value, ok := self.slots[index].read()
		if !ok || slotKey0 != key0 || slotKey1 != key1 {
			continue
		}
		if self.expired(slotKey1, uint32(value), nowSeconds) {
			return 0, 0, 0
		}
		return BridgeLinkId(value >> 32), index, sequence
	}
	return 0, 0, 0
}

// Writes a pin's last-seen time when it is touchSeconds old, if the slot still holds what was read.
func (self *BridgePinTable) touch(index uint64, sequence uint64, link BridgeLinkId, nowSeconds uint32) {
	slot := &self.slots[index]
	value := slot.value.Load()
	if BridgeLinkId(value>>32) != link || nowSeconds < uint32(value)+self.touchSeconds {
		return
	}
	slot.write(sequence, slot.key0.Load(), slot.key1.Load(), uint64(link)<<32|uint64(nowSeconds))
}

// Pins a key to link in the slot holding the key, else in an empty or idled-out slot of its run: false when every
// slot holds another live pin, or a writer came first.
func (self *BridgePinTable) insert(key0 uint64, key1 uint64, link BridgeLinkId, nowSeconds uint32) bool {
	home := self.home(key0, key1)
	value := uint64(link)<<32 | uint64(nowSeconds)
	free := -1
	var freeSequence uint64
	for probe := range uint64(bridgePinProbeCount) {
		index := (home + probe) & self.mask
		sequence, slotKey0, slotKey1, slotValue, ok := self.slots[index].read()
		if !ok {
			continue
		}
		if slotKey0 == key0 && slotKey1 == key1 {
			return self.slots[index].write(sequence, key0, key1, value)
		}
		if free < 0 && (slotKey1 == 0 || self.expired(slotKey1, uint32(slotValue), nowSeconds)) {
			free = int(index)
			freeSequence = sequence
		}
	}
	if free < 0 {
		return false
	}
	return self.slots[free].write(freeSequence, key0, key1, value)
}

// Pins a pair, counting a pick that found no slot (owner decision 66: it routes unpinned, refused nothing).
func (self *BridgePinTable) pinOrCount(key0 uint64, key1 uint64, link BridgeLinkId, nowSeconds uint32) {
	if !self.insert(key0, key1, link, nowSeconds) {
		self.unpinnedPickCount.Add(1)
	}
}

// The link a packet to entry takes, by the file's rows; 0 when no link serves the entry, which the router answers
// with a reject. Lock- and allocation-free.
func (self *BridgePinTable) Pick(entry *BridgeEntryState, packet []byte) BridgeLinkId {
	parsed, ok := bridgePinPacketOf(packet)
	if !ok {
		return 0
	}
	snapshot := entry.snapshot.Load()
	switch len(snapshot.links) {
	case 0:
		return 0
	case 1:
		// no choice, so no pin: a draining link serves every pair while nothing else remains
		link := &snapshot.links[0]
		if link.drainingSince.IsZero() || link.serves(parsed.tcp, self.clock.Now()) {
			return link.link
		}
		return 0
	}
	now := self.clock.Now()
	nowSeconds := self.seconds(now)
	entryKey1 := uint64(entry.entryId) << bridgePinEntryIdShift
	pairKey1 := parsed.pairKey1 | entryKey1

	// lookup: the connection's pin, then the pair's, while its link serves the entry
	if parsed.hasPorts {
		fiveTupleKey1 := parsed.fiveTupleKey1 | entryKey1
		link, index, sequence := self.lookup(parsed.key0, fiveTupleKey1, nowSeconds)
		if state := snapshot.find(link); link != 0 && state != nil && state.serves(true, now) {
			self.touch(index, sequence, link, nowSeconds)
			return link
		}
	}
	pairLink, pairIndex, pairSequence := self.lookup(parsed.key0, pairKey1, nowSeconds)
	pairState := snapshot.find(pairLink)
	if pairLink == 0 || pairState == nil || !pairState.serves(parsed.tcp, now) {
		pairState = nil
	}
	if pairState != nil && !(parsed.syn && !pairState.drainingSince.IsZero()) {
		self.touch(pairIndex, pairSequence, pairLink, nowSeconds)
		return pairLink
	}

	// the window, for a pinless pair
	var windowState *bridgeEntryLinkState
	if pairState == nil && !snapshot.windowSince.IsZero() &&
		now.Before(snapshot.windowSince.Add(self.idleOf(parsed.tcp))) {
		if state := snapshot.find(snapshot.windowLink); state != nil && state.serves(parsed.tcp, now) {
			windowState = state
		}
	}

	// syn: a new connection takes the new rule at once, under its own pin
	if parsed.syn && (windowState != nil || pairState != nil) {
		link := self.rendezvous(snapshot, parsed.pairHash, now, false, true)
		if link != 0 && self.insert(parsed.key0, parsed.fiveTupleKey1|entryKey1, link, nowSeconds) {
			return link
		}
		if pairState != nil {
			self.touch(pairIndex, pairSequence, pairLink, nowSeconds)
			return pairLink
		}
	}
	if windowState != nil {
		self.pinOrCount(parsed.key0, pairKey1, windowState.link, nowSeconds)
		return windowState.link
	}

	// the hash
	link := self.rendezvous(snapshot, parsed.pairHash, now, true, parsed.tcp)
	if link == 0 {
		return 0
	}
	self.pinOrCount(parsed.key0, pairKey1, link, nowSeconds)
	return link
}

// How long a protocol's pin idles, and its window holds.
func (self *BridgePinTable) idleOf(tcp bool) time.Duration {
	if tcp {
		return self.settings.PinTcpIdleTimeout
	}
	return self.settings.PinIdleTimeout
}

// Weighted rendezvous (D-BRIDGE-9) over the advertisers that are up; with none up, over every live one, so a down
// mark moves nothing when no other advertiser is up; with none live and withDraining, over the draining links that
// still serve the pair's protocol, since a draining link serves every pair while nothing else remains. 0 for no link.
// Each link scores weight / -ln(u), u its uniform hash with the pair, and the highest wins, ties to the lower link.
func (self *BridgePinTable) rendezvous(snapshot *bridgeEntrySnapshot, pairHash uint64, now time.Time, withDraining bool, tcp bool) BridgeLinkId {
	nowNano := now.UnixNano()
	pick := func(eligible func(link *bridgeEntryLinkState) bool) BridgeLinkId {
		best := BridgeLinkId(0)
		bestScore := 0.0
		for i := range snapshot.links {
			link := &snapshot.links[i]
			if !eligible(link) {
				continue
			}
			hash := bridgePinMix(pairHash ^ bridgePinMix(uint64(link.link)))
			// a uniform value in (0, 1), never 0 or 1, from the top 53 bits
			uniform := (float64(hash>>11) + 0.5) / (1 << 53)
			score := link.weight / -math.Log(uniform)
			if best == 0 || bestScore < score {
				best = link.link
				bestScore = score
			}
		}
		return best
	}
	if link := pick(func(link *bridgeEntryLinkState) bool { return link.up(nowNano) }); link != 0 {
		return link
	}
	if link := pick(func(link *bridgeEntryLinkState) bool { return link.drainingSince.IsZero() }); link != 0 {
		return link
	}
	if !withDraining {
		return 0
	}
	return pick(func(link *bridgeEntryLinkState) bool {
		return link.serves(tcp, now)
	})
}

// Drops every pin of entry to link at once: a revoked advertiser (§17.8's revocation row). Scans the table, so call it
// off the packet path, after BridgeEntryState.Reset.
func (self *BridgePinTable) Reset(entry *BridgeEntryState, link BridgeLinkId) int {
	droppedCount := 0
	for index := range self.slots {
		slot := &self.slots[index]
		sequence, _, key1, value, ok := slot.read()
		if !ok || key1 == 0 || BridgeLinkId(value>>32) != link ||
			uint32(key1>>bridgePinEntryIdShift)&bridgePinEntryIdMask != entry.entryId {
			continue
		}
		if slot.write(sequence, 0, 0, 0) {
			droppedCount += 1
		}
	}
	return droppedCount
}

// The live pins the table holds now, by a scan, for a status.
func (self *BridgePinTable) PinnedCount() int {
	nowSeconds := self.seconds(self.clock.Now())
	pinnedCount := 0
	for index := range self.slots {
		_, _, key1, value, ok := self.slots[index].read()
		if ok && key1 != 0 && !self.expired(key1, uint32(value), nowSeconds) {
			pinnedCount += 1
		}
	}
	return pinnedCount
}

// Picks since the table was built that found no free slot for their pin and routed by the hash, unpinned.
func (self *BridgePinTable) UnpinnedPickCount() uint64 {
	return self.unpinnedPickCount.Load()
}

// The slots the table holds, PinSlotCount rounded up.
func (self *BridgePinTable) SlotCount() int {
	return len(self.slots)
}
