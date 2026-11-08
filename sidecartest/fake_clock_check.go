// ServiceHost.ClockCheck in memory (host_clock.go): a schedule says what chronyd's replies would have
// measured, and this keeps the interface's promises about it, the sure edge and its channel included.
// It starts sure at offset zero, unlike a real check, so a test that is not about clocks need not set
// one; a test of the real starting state calls SetUnknown first. Each engine that needs a clock of its
// own, as FS-1's evs2 does, takes its own instance in its ServiceHost. server's check is held to the
// same promises by its own tests, against a fake chronyd on a fake clock.

package sidecartest

import (
	"sync"
	"time"
)

type FakeClockCheckSettings struct {
	// The largest offset Sure allows, as the real check's settings hold it.
	SureOffset time.Duration
}

func DefaultFakeClockCheckSettings() *FakeClockCheckSettings {
	return &FakeClockCheckSettings{
		SureOffset: 50 * time.Millisecond,
	}
}

// Safe for concurrent use.
type FakeClockCheck struct {
	settings *FakeClockCheckSettings

	stateLock sync.Mutex
	offset    time.Duration
	known     bool
	sure      bool
	// open through one sure stretch, closed at its end, and closed for as long as the clock is unsure
	unsureChannel chan struct{}
}

func NewFakeClockCheck(settings *FakeClockCheckSettings) *FakeClockCheck {
	if settings == nil {
		settings = DefaultFakeClockCheckSettings()
	}
	return &FakeClockCheck{
		settings:      settings,
		known:         true,
		sure:          true,
		unsureChannel: make(chan struct{}),
	}
}

// As the real check's: zero and false while unknown.
func (self *FakeClockCheck) Offset() (time.Duration, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.offset, self.known
}

// Whether the offset is known and within SureOffset.
func (self *FakeClockCheck) Sure() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sure
}

// The current sure stretch's channel, or a closed one while unsure.
func (self *FakeClockCheck) UnsureChannel() <-chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.unsureChannel
}

func (self *FakeClockCheck) setWithLock(offset time.Duration, known bool) {
	self.offset = offset
	self.known = known
	sure := known && offset <= self.settings.SureOffset
	if sure == self.sure {
		return
	}
	self.sure = sure
	if sure {
		self.unsureChannel = make(chan struct{})
	} else {
		close(self.unsureChannel)
	}
}

// What the next reply measures. Offset returns a magnitude, so a clock running fast, given here as a
// negative offset, is as far off as one running slow by as much.
func (self *FakeClockCheck) SetOffset(offset time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.setWithLock(offset.Abs(), true)
}

// chronyd stops answering, or answers unsynchronised.
func (self *FakeClockCheck) SetUnknown() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.setWithLock(0, false)
}
