// The root's copies of connect's MonitorValue and CallbackList (connect/util.go:74, :220), on every
// leg because naming connect's links gVisor into the page Worker (§4.4). They behave as connect's
// do; this one locks with stateLock, as CODESTYLE names it, where connect's list says mutex.

package sidecar

import (
	"slices"
	"sync"
)

// A value paired with its change notification, so the two halves of the monitor contract cannot be
// separated. The value is read only together with a channel armed at the instant of the read (Get)
// and written only through Set or Update, which notify inside the same critical section. A
// forgotten notify and a subscribe across a wait, both silent, are so not representable.
//
// Set notifies only when the value changes, which lets a loop that both reads and writes the value
// converge instead of waking itself forever.
//
// Safe for concurrent use. Update's function runs under the lock, so it must not call back into
// this value.
type MonitorValue[T comparable] struct {
	stateLock sync.Mutex
	value     T
	notify    chan struct{}
}

// Starts at value, with nothing notified.
func NewMonitorValue[T comparable](value T) *MonitorValue[T] {
	return &MonitorValue[T]{
		value:  value,
		notify: make(chan struct{}),
	}
}

// The current value and a channel that closes on the next change, taken atomically so no change
// slips between the read and the subscribe. Act on the value, then wait on the channel, never the
// reverse. A closed channel stays closed: call again to re-arm.
func (self *MonitorValue[T]) Get() (T, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.value, self.notify
}

// The current value with no subscription. Only for a read no wait follows; anything that waits for
// a change uses Get.
func (self *MonitorValue[T]) Value() T {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.value
}

// Stores the value and reports whether it changed, notifying waiters only then.
func (self *MonitorValue[T]) Set(value T) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.setWithLock(value)
}

// Stores f of the current value and reports whether it changed, notifying waiters only then.
func (self *MonitorValue[T]) Update(f func(T) T) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.setWithLock(f(self.value))
}

// Notifies in the same critical section as the write, and only on a change.
func (self *MonitorValue[T]) setWithLock(value T) bool {
	if self.value == value {
		return false
	}
	self.value = value
	close(self.notify)
	self.notify = make(chan struct{})
	return true
}

// Callbacks that come and go while others iterate them. Each change copies the list, so a slice
// from Get is a stable snapshot, read without a lock. Safe for concurrent use.
type CallbackList[T any] struct {
	stateLock sync.Mutex
	// parallel arrays. callbackIds stays sorted ascending, since Add appends a rising id, which is
	// what lets Remove search it
	callbacks      []T
	callbackIds    []int
	nextCallbackId int
}

// Empty.
func NewCallbackList[T any]() *CallbackList[T] {
	return &CallbackList[T]{
		callbacks:      []T{},
		callbackIds:    []int{},
		nextCallbackId: 0,
	}
}

// The callbacks in the order they were added. The slice is shared: read it, never write it.
func (self *CallbackList[T]) Get() []T {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.callbacks
}

// Returns the id that Remove takes.
func (self *CallbackList[T]) Add(callback T) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	callbackId := self.nextCallbackId
	self.nextCallbackId += 1

	self.callbacks = append(slices.Clone(self.callbacks), callback)
	self.callbackIds = append(slices.Clone(self.callbackIds), callbackId)

	return callbackId
}

// Does nothing for an id already removed or never added.
func (self *CallbackList[T]) Remove(callbackId int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()

	i, found := slices.BinarySearch(self.callbackIds, callbackId)
	if !found {
		return
	}

	self.callbacks = slices.Delete(slices.Clone(self.callbacks), i, i+1)
	self.callbackIds = slices.Delete(slices.Clone(self.callbackIds), i, i+1)
}
