// The admission world's row bound (AdmissionSuiteSettings.RowTimeout): the world's context ends once RowTimeout passes
// on the row's clock with no progress, so a wait that stalls fails the row that long after the row's last progress,
// while a row that keeps applying entries runs as long as its work takes, however loaded the host. The world notes
// progress at each page it reads, each entry its readers apply and each catch-up of the writer's follower; the watchdog
// reads the newest note only when its bound comes due, so a note costs a clock read and a store, never a wakeup.
//
// A deadline fixed at the row's start bounded the row's whole run instead, and so failed a healthy row whose CPU a
// loaded host lent slowly: TestTeamAdmissionsMeetNoMemberDeviceCap on tip-check at 7215073e, "the writer's follower at
// 1033: config client closed", a row of some 25 s of CPU whose follower waits were each well under a second.
//
// On a FakeClock the bound's check runs inside the Advance that reaches it, on the advancing goroutine, so a test of the
// bound holds no race (admission_watchdog_test.go).

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar"
)

// Why the world's context ended when its row made no progress for RowTimeout: the context's cause.
var ErrAdmissionRowStalled = errors.New("the row made no progress")

// The no-progress bound of one world's row. Safe for concurrent use: the row notes progress on its goroutine, and a
// real clock runs the check on one of its own.
type admissionWatchdog struct {
	clock   Clock
	timeout time.Duration
	cancel  context.CancelCauseFunc
	// the clock's time at the start; progress is an offset from it, so a real clock's monotonic reading measures it
	start time.Time
	// the newest progress's offset, which only moves forward
	progress atomic.Int64

	stateLock sync.Mutex
	// stops the pending check, nil for none
	stopCheck func() bool
	ended     bool
}

// A context of parent that ends with ErrAdmissionRowStalled once timeout passes on clock after the newest progress,
// the start counting as progress, and its watchdog, which ends it at end.
func newAdmissionWatchdog(parent context.Context, clock Clock, timeout time.Duration) (context.Context, *admissionWatchdog) {
	ctx, cancel := context.WithCancelCause(parent)
	self := &admissionWatchdog{clock: clock, timeout: timeout, cancel: cancel, start: clock.Now()}
	self.arm(self.start.Add(timeout))
	return ctx, self
}

// Notes progress at the clock's time now.
func (self *admissionWatchdog) progressed() {
	offset := int64(self.clock.Now().Sub(self.start))
	for {
		previous := self.progress.Load()
		if offset <= previous || self.progress.CompareAndSwap(previous, offset) {
			return
		}
	}
}

// Sets the next check for at on the clock, a wait for that time itself (QD-1425), unless the watchdog has ended.
func (self *admissionWatchdog) arm(at time.Time) {
	ended := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.ended
	}()
	if ended {
		return
	}
	// outside the lock: a FakeClock calls a check that is due at once before the wait is set
	stopCheck := sidecar.ClockAfterFuncAt(self.clock, at, self.check)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.ended {
		stopCheck()
		return
	}
	self.stopCheck = stopCheck
}

// The bound's check, on the clock's call: the context ends once timeout has passed since the newest progress, and
// otherwise the next check waits for the rest of it.
func (self *admissionWatchdog) check() {
	// now before the newest progress, so a note made after now is never read as older than it
	now := int64(self.clock.Now().Sub(self.start))
	due := self.progress.Load() + int64(self.timeout)
	if due <= now {
		self.cancel(fmt.Errorf("%w for %s", ErrAdmissionRowStalled, self.timeout))
		return
	}
	self.arm(self.start.Add(time.Duration(due)))
}

// Stops the checks and ends the context, as the world's Close does. Safe to call again.
func (self *admissionWatchdog) end() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.ended = true
		if self.stopCheck != nil {
			self.stopCheck()
			self.stopCheck = nil
		}
	}()
	self.cancel(nil)
}
