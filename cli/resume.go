// The host's wake for the daemon's bridges (§17.8's after sleep or a clock step, owner decision 789): a bridge's waits
// are runtime timers, which stop while the host sleeps, so the daemon has every bridge it holds read the clock again
// when the host resumes (device.Bridge.CheckClock), where the platform tells a process so cheaply: logind's
// PrepareForSleep(false) on Linux, over the system bus ur already talks to for systemd-resolved (resume_linux.go), and
// the power-resume notification on Windows (resume_windows.go). macOS tells no process without cgo, and elsewhere
// nothing watches: there, and wherever a watch cannot start or ends, the desktop's capped wait
// (device.BridgeSettings.ClockCheckInterval, on in the daemon's bridge settings) covers the host, late by at most the
// cap after it wakes.

package main

import (
	"context"

	"github.com/urnetwork/sidecar"
)

// Watches for the host's resume until ctx ends, calling resumed at each; resumed never blocks. Returns at once where
// the platform's notice is not to be had.
type urResumeWatchFunction func(ctx context.Context, resumed func(), log sidecar.Logger)

// The platform's watch, which resume_linux.go and resume_windows.go set. Nil elsewhere, where none runs.
var urResumeWatch urResumeWatchFunction

// Has every bridge the daemon holds read the clock again at once: the host woke, or its clock changed. Never blocks,
// since each check is handed to its bridge's run.
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
}

// Runs the platform's watch for the daemon's life, each resume a check of every bridge's clock, and closes resumeDone
// once it returns.
func (self *urBridgeDaemon) runResumeWatch(watch urResumeWatchFunction) {
	defer close(self.resumeDone)
	watch(self.ctx, self.checkClock, self.log)
}
