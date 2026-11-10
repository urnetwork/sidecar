//go:build !ios_extension

// §15.7's hybrid logical clock for f/'s flag ops (MAIL-M7-06), as MAIL-FORMAT.md's f/ section states it: one
// number, wall ms since the epoch in the top 48 bits and a counter in the low 16, so it compares as one and a
// counter past 65,535 carries into the wall. A device ticks once per op it writes and raises its clock past every op
// it reads, so of two ops on one key the one written later by any device's knowledge carries the higher clock, and
// last writer wins (MailFlagOpCompare) needs no clock to agree across devices.
//
// The clock is per mailbox and needs no storage: a restart rebuilds it from f/ as the view reads, and an op that
// never reached f/ has nothing to order against. On every leg.

package sidecar

import (
	"math"
	"sync"
)

// The counter's bits below the wall (MAIL-FORMAT.md). A format value.
const mailHlcCounterBitCount = 16

// The latest wall the clock's 48 bits hold, ms since the epoch: the year 10889. A format value.
const mailHlcWallMax = uint64(1)<<(64-mailHlcCounterBitCount) - 1

// MAIL-FORMAT.md's tick: max(now << 16, last + 1), last + 1 stopping at the top of the clock rather than wrapping
// below every op, and a wall past 48 bits held to them.
func MailHlcTick(last uint64, nowMillis uint64) uint64 {
	next := last
	if last != math.MaxUint64 {
		next = last + 1
	}
	return max(min(nowMillis, mailHlcWallMax)<<mailHlcCounterBitCount, next)
}

// The wall ms of a clock value: what dates a trash for the 30-day shred.
func MailHlcWallMillis(hlc uint64) uint64 {
	return hlc >> mailHlcCounterBitCount
}

// One mailbox's clock on this device. Safe for concurrent use.
type MailHlc struct {
	clock Clock

	stateLock sync.Mutex
	last      uint64
}

// A clock reading wall time from clock, real time when nil, that has seen no op.
func NewMailHlc(clock Clock) *MailHlc {
	return &MailHlc{clock: clockOrReal(clock)}
}

// The clock value of an op this device writes now, past every value it has ticked or observed.
func (self *MailHlc) Tick() uint64 {
	nowMillis := uint64(max(0, self.clock.Now().UnixMilli()))
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.last = MailHlcTick(self.last, nowMillis)
	return self.last
}

// Raises the clock to an op's value read from f/, so this device's next op orders after it.
func (self *MailHlc) Observe(hlc uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.last = max(self.last, hlc)
}

// The highest value ticked or observed.
func (self *MailHlc) Last() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.last
}
