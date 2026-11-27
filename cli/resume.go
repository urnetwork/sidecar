// The host's wake for the daemon's bridges and the core's own wall-clock ends (§17.8's after sleep or a clock step,
// owner decision 789; QD-1422): a bridge's waits, and the core's waits for a stream's grant end or a forward's expiry
// (sidecar's core_clock_check.go), are runtime timers, which stop while the host sleeps, so the daemon has every bridge
// it holds, and every core check its composition added (addClockCheck: each hosted Sidecar's, the forwards'), read the
// clock again when the host resumes (device.Bridge.CheckClock, Sidecar.CheckClock, DaemonBridges.CheckClock), where the
// platform tells a process so cheaply: logind's PrepareForSleep(false) on Linux, over the system bus ur already talks to
// for systemd-resolved (resume_linux.go), and the power-resume notification on Windows (resume_windows.go). macOS tells
// no process without cgo, and elsewhere nothing watches; no platform tells of a step of the clock. There, and wherever
// a watch cannot start or ends, the desktop's cap covers the host, late by at most the cap after it wakes: the bridges
// cap their own waits at device.BridgeSettings.ClockCheckInterval, on in the daemon's bridge settings, and the daemon
// runs the core's checks at that same interval (runClockCap), so one interval caps both.

package main

import (
	"context"
	"time"

	"github.com/urnetwork/sidecar"
)

// Watches for the host's resume until ctx ends, calling resumed at each; resumed never blocks. Returns at once where
// the platform's notice is not to be had.
type urResumeWatchFunction func(ctx context.Context, resumed func(), log sidecar.Logger)

// The platform's watch, which resume_linux.go and resume_windows.go set. Nil elsewhere, where none runs.
var urResumeWatch urResumeWatchFunction

// Has every bridge the daemon holds, and every core check added, read the clock again at once: the host woke, or its
// clock changed. Never blocks, since each check hands its work on or arms timers.
func (self *urBridgeDaemon) checkClock() {
	checks := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		checks := []func(){}
		for _, network := range self.networks {
			if network.checkClock != nil {
				checks = append(checks, network.checkClock)
			}
		}
		return checks
	}()
	for _, check := range checks {
		check()
	}
	self.checkCoreClocks()
}

// Has every core check added read the clock again at once, not the bridges', which cap their own waits.
func (self *urBridgeDaemon) checkCoreClocks() {
	checks := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		checks := make([]func(), 0, len(self.coreClockChecks))
		for _, check := range self.coreClockChecks {
			checks = append(checks, check)
		}
		return checks
	}()
	for _, check := range checks {
		check()
	}
}

// Adds a check of the core's wall-clock ends the daemon calls at each resume and at its cap, beside the bridges';
// check must never block. The returned function removes it.
func (self *urBridgeDaemon) addClockCheck(check func()) func() {
	id := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.coreClockCheckSeq += 1
		self.coreClockChecks[self.coreClockCheckSeq] = check
		return self.coreClockCheckSeq
	}()
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.coreClockChecks, id)
	}
}

// Runs the platform's watch for the daemon's life, each resume a check of every bridge's clock and the core's, and
// closes resumeDone once it returns.
func (self *urBridgeDaemon) runResumeWatch(watch urResumeWatchFunction) {
	defer close(self.resumeDone)
	watch(self.ctx, self.checkClock, self.log)
}

// The desktop's cap on the core's waits (the file's comment): every interval of the daemon's clock, the core's checks,
// for the daemon's life, closing clockCapDone once it ends. No check runs once the daemon has ended, a timer taken as
// it ended included.
func (self *urBridgeDaemon) runClockCap(interval time.Duration) {
	defer close(self.clockCapDone)
	// select takes either of its ready cases at random: a timer taken as the daemon ended reads as the end
	for self.ctx.Err() == nil {
		select {
		case <-self.ctx.Done():
		case <-self.clock.After(interval):
		}
		if self.ctx.Err() != nil {
			return
		}
		self.checkCoreClocks()
	}
}
