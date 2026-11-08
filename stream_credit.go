// §6.7's credit (R-PROTO-9, D-PROTO-4): what a receiver commits to the windows it grants a peer's
// streams. A receiver commits a window's bytes, from its peer's credit and the process's, before it
// sends the window, and holds them until its reader takes the bytes or the stream ends, so every byte a
// peer may send has room waiting (stream_buffer.go). The process's share is SubprotocolBudget's, inside
// §5's MemoryBudgetByteCount; each peer's is one streamCredit, which the wire layer (PROTO-M5-02) keeps
// per peer beside its queue.
//
// An edge's budget grows with its streams (§6.7's credit row): each stream it opens adds a minimum
// window to its cap, so one slow visitor holding its window cannot stall the rest, and only the
// process's credit bounds an edge. Above half of GOMEMLIMIT, a new window commits
// StreamPressureMinWindowByteCount instead of StreamMinWindowByteCount (§13.6).
//
// No connect type appears here, so the file builds on every leg. Safe for concurrent use.

package sidecar

import (
	"errors"
	"math"
	"runtime/debug"
	"runtime/metrics"
	"sync"
)

// A window a receiver could not commit: the acceptor answers StreamReject{BUSY} and the opener fails
// locally with RESOURCE_EXHAUSTED (§6.7's window row).
var errStreamCreditExhausted = errors.New("stream credit exhausted")

// One peer's credit, as this side grants it.
type streamCredit struct {
	settings *SidecarProtocolSettings
	budget   *SubprotocolBudget
	// the peer is an edge, whose cap grows with its streams
	edge bool
	// whether the process is above half of GOMEMLIMIT now
	pressure func() bool

	stateLock          sync.Mutex
	committedByteCount int64
	streamCount        int
}

// A peer's credit inside budget. pressure nil reads the process's own memory (streamMemoryPressure).
func newStreamCredit(settings *SidecarProtocolSettings, budget *SubprotocolBudget, edge bool, pressure func() bool) *streamCredit {
	if pressure == nil {
		pressure = streamMemoryPressure
	}
	return &streamCredit{settings: settings, budget: budget, edge: edge, pressure: pressure}
}

// Whether the process is above half of GOMEMLIMIT, as the runtime counts toward it: the memory it has
// mapped less what it has returned. With no limit set, never.
func streamMemoryPressure() bool {
	limit := debug.SetMemoryLimit(-1)
	if limit <= 0 || limit == math.MaxInt64 {
		return false
	}
	samples := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindUint64 || samples[1].Value.Kind() != metrics.KindUint64 {
		return false
	}
	return uint64(limit)/2 < samples[0].Value.Uint64()-samples[1].Value.Uint64()
}

// The most this peer's windows may hold now: StreamPeerCreditByteCount, and for an edge as much again
// as a minimum window for each of its streams.
func (self *streamCredit) capByteCountWithLock() int64 {
	capByteCount := self.settings.StreamPeerCreditByteCount
	if self.edge {
		capByteCount += int64(self.streamCount) * self.settings.StreamMinWindowByteCount
	}
	return capByteCount
}

// What a new window commits before it is sent: StreamMinWindowByteCount, or above half of GOMEMLIMIT
// StreamPressureMinWindowByteCount if that is less.
func (self *streamCredit) minWindowByteCount() int64 {
	minWindowByteCount := self.settings.StreamMinWindowByteCount
	if self.pressure() {
		minWindowByteCount = min(minWindowByteCount, self.settings.StreamPressureMinWindowByteCount)
	}
	return minWindowByteCount
}

// The most one stream's window grows to: min(StreamMaxWindowByteCount, StreamMaxPeerCreditFraction of
// the peer's credit), and never below the minimum window.
func (self *streamCredit) maxWindowByteCount() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fractionByteCount := int64(float64(self.capByteCountWithLock()) * self.settings.StreamMaxPeerCreditFraction)
	return max(min(self.settings.StreamMaxWindowByteCount, fractionByteCount), self.settings.StreamMinWindowByteCount)
}

// Counts a stream opened with this peer, before its window commits, so an edge's cap has grown for it.
func (self *streamCredit) openStream() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.streamCount += 1
}

// Counts a stream ended, once its window is released.
func (self *streamCredit) closeStream() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.streamCount = max(self.streamCount-1, 0)
}

// Commits byteCount from the peer's cap and the process's budget, both or neither. The peer's part is
// taken first and handed back if the process refuses, with no lock held across the budget's call.
func (self *streamCredit) commit(byteCount int64) bool {
	if byteCount <= 0 {
		return true
	}
	taken := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.capByteCountWithLock()-self.committedByteCount < byteCount {
			return false
		}
		self.committedByteCount += byteCount
		return true
	}()
	if !taken {
		return false
	}
	if !self.budget.reserveCredit(byteCount) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.committedByteCount -= byteCount
		return false
	}
	return true
}

// Gives back what commit took. Every commitment has one owner that releases it once, so this never
// goes below zero, and stops there if a bug makes it try.
func (self *streamCredit) release(byteCount int64) {
	if byteCount <= 0 {
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		byteCount = min(byteCount, self.committedByteCount)
		self.committedByteCount -= byteCount
	}()
	self.budget.releaseCredit(byteCount)
}

// What the peer's windows hold now.
func (self *streamCredit) committed() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.committedByteCount
}
