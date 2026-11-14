// The push sender's held entries (§19.4's input row): every entry a sender read and has not settled, in a
// heap by when it is next due, and by its stream and id, so a claim of an entry already held is not held
// twice. Not safe for concurrent use: the sender holds it under its stateLock.

package pushservice

import (
	"container/heap"
)

// One entry a sender holds.
type wakeHeldEntry struct {
	// the stream it was read from, and its id there
	streamKey string
	entryId   string
	entry     *WakeEntry
	// when it is next due, in unix milliseconds: due_millis, or a window's end it was put off to
	dueMs int64
	// it was put off to a window's end once already
	windowDeferred bool
	// its index in the heap's slice, -1 once out of it
	index int
}

// The key held entries are found by.
type wakeHeldKey struct {
	streamKey string
	entryId   string
}

// Held entries by due time. Its heap.Interface methods are container/heap's to call.
type wakeHeap struct {
	entries []*wakeHeldEntry
	keys    map[wakeHeldKey]*wakeHeldEntry
}

func newWakeHeap() *wakeHeap {
	return &wakeHeap{keys: map[wakeHeldKey]*wakeHeldEntry{}}
}

// See heap.Interface.
func (self *wakeHeap) Len() int {
	return len(self.entries)
}

// See heap.Interface: due first, then by stream and id, so equal dues settle in a fixed order.
func (self *wakeHeap) Less(i int, j int) bool {
	a, b := self.entries[i], self.entries[j]
	if a.dueMs != b.dueMs {
		return a.dueMs < b.dueMs
	}
	if a.streamKey != b.streamKey {
		return a.streamKey < b.streamKey
	}
	return compareWakeEntryIds(a.entryId, b.entryId) < 0
}

// See heap.Interface.
func (self *wakeHeap) Swap(i int, j int) {
	self.entries[i], self.entries[j] = self.entries[j], self.entries[i]
	self.entries[i].index = i
	self.entries[j].index = j
}

// See heap.Interface.
func (self *wakeHeap) Push(value any) {
	held := value.(*wakeHeldEntry)
	held.index = len(self.entries)
	self.entries = append(self.entries, held)
}

// See heap.Interface.
func (self *wakeHeap) Pop() any {
	last := len(self.entries) - 1
	held := self.entries[last]
	self.entries[last] = nil
	self.entries = self.entries[:last]
	held.index = -1
	return held
}

// Whether an entry of streamKey and entryId is held, in the heap or settling.
func (self *wakeHeap) holds(streamKey string, entryId string) bool {
	_, ok := self.keys[wakeHeldKey{streamKey: streamKey, entryId: entryId}]
	return ok
}

// Holds held until it is next due. An entry already held is not held again: false.
func (self *wakeHeap) add(held *wakeHeldEntry) bool {
	key := wakeHeldKey{streamKey: held.streamKey, entryId: held.entryId}
	if _, ok := self.keys[key]; ok {
		return false
	}
	self.keys[key] = held
	heap.Push(self, held)
	return true
}

// Puts a held entry that settled to wait again, due at dueMs.
func (self *wakeHeap) requeue(held *wakeHeldEntry, dueMs int64) {
	held.dueMs = dueMs
	heap.Push(self, held)
}

// The earliest entry due at or before nowMs, taken out of the heap and still held, or nil.
func (self *wakeHeap) popDue(nowMs int64) *wakeHeldEntry {
	if len(self.entries) == 0 || nowMs < self.entries[0].dueMs {
		return nil
	}
	return heap.Pop(self).(*wakeHeldEntry)
}

// When the earliest entry is due, and false for none waiting.
func (self *wakeHeap) nextDueMs() (int64, bool) {
	if len(self.entries) == 0 {
		return 0, false
	}
	return self.entries[0].dueMs, true
}

// Lets go of an entry that settled for good.
func (self *wakeHeap) release(held *wakeHeldEntry) {
	delete(self.keys, wakeHeldKey{streamKey: held.streamKey, entryId: held.entryId})
}

// Entries held, waiting or settling.
func (self *wakeHeap) heldCount() int {
	return len(self.keys)
}

// Two stream ids compared as their two integer parts; a malformed one sorts first.
func compareWakeEntryIds(a string, b string) int {
	order, err := CompareStreamId(a, b)
	if err != nil {
		switch {
		case a < b:
			return -1
		case b < a:
			return 1
		}
		return 0
	}
	return order
}
