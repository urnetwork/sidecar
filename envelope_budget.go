// The process's share of §5's memory budget that §6 spends, on every leg (§6.6, R-PROTO-9).

package sidecar

import (
	"sync"
)

// What one process holds for §6: the reassembly, idempotency and credit counters. Each stops at its
// process cap in SidecarProtocolSettings, and the three together at the budget the caller passes, the
// part of MemoryBudgetByteCount §6 may spend. A refused reservation answers RESOURCE_EXHAUSTED.
//
// The daemon or host creates one and passes it to every Subprotocol it runs, which is what makes these
// counters process-wide: it is never a package global, so two hosts in one process never contend
// (connect/CODESTYLE.md, budgets). Safe for concurrent use.
type SubprotocolBudget struct {
	settings              *SidecarProtocolSettings
	memoryBudgetByteCount int64

	stateLock sync.Mutex
	usage     subprotocolBudgetUsage
}

// What a budget holds at one moment.
type subprotocolBudgetUsage struct {
	reassemblyByteCount  int64
	idempotencyByteCount int64
	creditByteCount      int64
}

// Holds nothing yet. memoryBudgetByteCount comes from the caller, since one process may run several
// Sidecars and only it knows what else shares the budget (§5.4).
func NewSubprotocolBudget(settings *SidecarProtocolSettings, memoryBudgetByteCount int64) *SubprotocolBudget {
	return &SubprotocolBudget{
		settings:              settings,
		memoryBudgetByteCount: memoryBudgetByteCount,
	}
}

// Takes byteCount from count, one of usage's fields, unless that would pass capByteCount or the budget
// as a whole.
func (self *SubprotocolBudget) reserve(count *int64, capByteCount int64, byteCount int64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	heldByteCount := self.usage.reassemblyByteCount + self.usage.idempotencyByteCount + self.usage.creditByteCount
	if capByteCount-*count < byteCount || self.memoryBudgetByteCount-heldByteCount < byteCount {
		return false
	}
	*count += byteCount
	return true
}

// Returns byteCount to count. Every reservation has one owner who returns it once, so this never goes
// below zero, and it stops there if a bug makes it try, since a negative count would hand out memory
// nobody has.
func (self *SubprotocolBudget) release(count *int64, byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	*count = max(*count-byteCount, 0)
}

// For a body's declared length, at its first chunk.
func (self *SubprotocolBudget) reserveReassembly(byteCount int64) bool {
	return self.reserve(&self.usage.reassemblyByteCount, self.settings.ReassemblyProcessByteCount, byteCount)
}

// Gives back what reserveReassembly took, once the body completes or is dropped.
func (self *SubprotocolBudget) releaseReassembly(byteCount int64) {
	self.release(&self.usage.reassemblyByteCount, byteCount)
}

// For a cached response.
func (self *SubprotocolBudget) reserveIdempotency(byteCount int64) bool {
	return self.reserve(&self.usage.idempotencyByteCount, self.settings.IdempotencyProcessByteCount, byteCount)
}

// Gives back what reserveIdempotency took, once the response is evicted.
func (self *SubprotocolBudget) releaseIdempotency(byteCount int64) {
	self.release(&self.usage.idempotencyByteCount, byteCount)
}

// For a stream's window.
func (self *SubprotocolBudget) reserveCredit(byteCount int64) bool {
	return self.reserve(&self.usage.creditByteCount, self.settings.StreamProcessCreditByteCount, byteCount)
}

// Gives back what reserveCredit took, once the reader consumes it or the stream ends.
func (self *SubprotocolBudget) releaseCredit(byteCount int64) {
	self.release(&self.usage.creditByteCount, byteCount)
}

// What the budget holds now.
func (self *SubprotocolBudget) currentUsage() subprotocolBudgetUsage {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.usage
}
