// §17.5's rejects row: what Route hands a packet the sender refuses, so the source hears at once rather than waiting
// out a timeout. A TCP reset, or an ICMP destination unreachable, administratively prohibited (v4 3/13, v6 1/1), built
// by connect.AdministrativeRejectPacket, enters the tun through receive. Connect writes policy resets unthrottled, so
// each source gets a token bucket, RejectPerSecond with a burst of RejectBurst (20 a second, 40): a reject past it is
// not sent, and is counted. The bucket is taken before anything is built, so a flood costs no allocation past it.
//
// Buckets live in a fixed table of slots of atomics, a source hashing to a run of bridgeRejectProbeCount of them. A
// slot holds one source's key, and its bucket packed in one word, tokens and the time of its last refill, so a take is
// a compare-and-swap with no lock. A slot whose source's bucket has refilled whole is as good as empty, and a new
// source takes it. A source finding every slot of its run held by another source short of a full bucket sends no
// reject, counted with the rest.
//
// A BridgeRejectClient is safe for concurrent use.

package device

import (
	"encoding/binary"
	"math/bits"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// The packing of a bucket's word, and the slots a source may sit in.
const (
	bridgeRejectProbeCount = 4
	// tokens are kept in units of 1/1024 token, so a refill keeps its fractions
	bridgeRejectTokenScale = 1024
	// the low bits hold the ms since the client's epoch of the last refill, 34 years of them
	bridgeRejectTimeBits = 40
	bridgeRejectTimeMask = uint64(1)<<bridgeRejectTimeBits - 1
	// the most tokens a bucket holds: what the 24 high bits hold at bridgeRejectTokenScale
	bridgeRejectTokensMax = (1<<(64-bridgeRejectTimeBits) - 1) / bridgeRejectTokenScale
)

// One source's bucket. key is 0 for none.
type bridgeRejectSlot struct {
	key   atomic.Uint64
	state atomic.Uint64
}

// The reject client. See the file's comment.
type BridgeRejectClient struct {
	settings *BridgeSettings
	clock    Clock
	epoch    time.Time
	// where a reject enters the tun, which borrows it; nil sends none
	receive atomic.Pointer[connect.ReceivePacketFunction]

	slots []bridgeRejectSlot
	mask  uint64

	sentCount   atomic.Uint64
	unsentCount atomic.Uint64
}

var _ connect.UserNatClient = (*BridgeRejectClient)(nil)

// A client writing its rejects through receive, which borrows each; nil receive sends none, counting each as unsent.
// Nil settings are DefaultBridgeSettings.
func NewBridgeRejectClient(receive connect.ReceivePacketFunction, settings *BridgeSettings) *BridgeRejectClient {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	slotCount := max(settings.RejectSourceSlotCount, bridgeRejectProbeCount)
	if slotCount&(slotCount-1) != 0 {
		slotCount = 1 << bits.Len(uint(slotCount))
	}
	clock := settings.clock()
	self := &BridgeRejectClient{
		settings: settings,
		clock:    clock,
		epoch:    clock.Now(),
		slots:    make([]bridgeRejectSlot, slotCount),
		mask:     uint64(slotCount - 1),
	}
	self.SetReceive(receive)
	return self
}

// Where rejects enter the tun from now on, which borrows each; nil sends none, counting each as unsent.
func (self *BridgeRejectClient) SetReceive(receive connect.ReceivePacketFunction) {
	if receive == nil {
		self.receive.Store(nil)
		return
	}
	self.receive.Store(&receive)
}

// connect.UserNatClient. Takes the packet, whatever it returns: a reject goes back into the tun if the source's bucket
// holds a token and the packet is one an answer may go to, else nothing does and the reject counts as unsent. Always
// true, since the packet is disposed of here either way.
func (self *BridgeRejectClient) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	key, ok := bridgeRejectSourceKey(packet)
	if !ok || !self.take(key) {
		self.unsentCount.Add(1)
		connect.MessagePoolReturn(packet)
		return true
	}
	receive := self.receive.Load()
	reject := connect.AdministrativeRejectPacket(packet)
	if reject == nil || receive == nil {
		if reject != nil {
			connect.MessagePoolReturn(reject)
		}
		self.unsentCount.Add(1)
		connect.MessagePoolReturn(packet)
		return true
	}
	// the outbound flow the reject answers, as a receive callback names it
	ipPath, err := connect.ParseIpPath(packet)
	if err != nil {
		connect.MessagePoolReturn(reject)
		self.unsentCount.Add(1)
		connect.MessagePoolReturn(packet)
		return true
	}
	(*receive)(connect.TransferPath{}, provideMode, ipPath, reject)
	self.sentCount.Add(1)
	connect.MessagePoolReturn(reject)
	connect.MessagePoolReturn(packet)
	return true
}

func (self *BridgeRejectClient) Close() {}

func (self *BridgeRejectClient) Shuffle() {}

func (self *BridgeRejectClient) SecurityPolicyStats(reset bool) connect.SecurityPolicyStats {
	return connect.SecurityPolicyStats{}
}

func (self *BridgeRejectClient) SetLocalSecurityBypass(localSecurityBypass bool) {}

// The rejects sent, and those the buckets, an unanswerable packet or a missing receive kept back.
func (self *BridgeRejectClient) Counts() (sentCount uint64, unsentCount uint64) {
	return self.sentCount.Load(), self.unsentCount.Load()
}

// A packet's source as a bucket's key, never 0: an IPv4 address as itself above bit 32, an IPv6 one hashed with its
// top bit set. False for anything shorter than its header.
func bridgeRejectSourceKey(packet []byte) (uint64, bool) {
	if len(packet) == 0 {
		return 0, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < bridgeIpv4HeaderByteCount {
			return 0, false
		}
		return uint64(1)<<32 | uint64(binary.BigEndian.Uint32(packet[12:16])), true
	case 6:
		if len(packet) < 40 {
			return 0, false
		}
		high := binary.BigEndian.Uint64(packet[8:16])
		low := binary.BigEndian.Uint64(packet[16:24])
		return bridgePinMix(high^bridgePinMix(low)) | uint64(1)<<63, true
	default:
		return 0, false
	}
}

// Milliseconds since the client's epoch, as a bucket's word keeps them.
func (self *BridgeRejectClient) nowMs() uint64 {
	elapsed := self.clock.Now().Sub(self.epoch)
	if elapsed < 0 {
		return 0
	}
	return uint64(elapsed/time.Millisecond) & bridgeRejectTimeMask
}

// A bucket's tokens, scaled, refilled to nowMs.
func (self *BridgeRejectClient) refilled(state uint64, nowMs uint64) uint64 {
	tokens := state >> bridgeRejectTimeBits
	lastMs := state & bridgeRejectTimeMask
	if lastMs < nowMs {
		tokens += (nowMs - lastMs) * uint64(self.settings.RejectPerSecond) * bridgeRejectTokenScale / 1000
	}
	return min(tokens, uint64(self.settings.RejectBurst)*bridgeRejectTokenScale)
}

// Takes one of the source's tokens: false when its bucket is empty, or when it finds no slot.
func (self *BridgeRejectClient) take(key uint64) bool {
	nowMs := self.nowMs()
	home := bridgePinMix(key) & self.mask
	for probe := range uint64(bridgeRejectProbeCount) {
		slot := &self.slots[(home+probe)&self.mask]
		if slot.key.Load() == key {
			return self.takeFrom(slot, nowMs)
		}
	}
	full := uint64(self.settings.RejectBurst) * bridgeRejectTokenScale
	for probe := range uint64(bridgeRejectProbeCount) {
		slot := &self.slots[(home+probe)&self.mask]
		held := slot.key.Load()
		if held != 0 && self.refilled(slot.state.Load(), nowMs) < full {
			continue
		}
		if slot.key.CompareAndSwap(held, key) {
			slot.state.Store(full<<bridgeRejectTimeBits | nowMs)
			return self.takeFrom(slot, nowMs)
		}
	}
	return false
}

// Takes a token from slot's bucket at nowMs, writing the refill either way.
func (self *BridgeRejectClient) takeFrom(slot *bridgeRejectSlot, nowMs uint64) bool {
	for {
		state := slot.state.Load()
		tokens := self.refilled(state, nowMs)
		taken := bridgeRejectTokenScale <= tokens
		if taken {
			tokens -= bridgeRejectTokenScale
		}
		if slot.state.CompareAndSwap(state, tokens<<bridgeRejectTimeBits|nowMs) {
			return taken
		}
	}
}
