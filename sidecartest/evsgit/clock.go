//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// A git world's moving clock (FS-73; EVS2-M10-29): a fake clock kept at real time plus an offset. Between jumps it
// runs at real time, so the queue's delays, the receive path's waits and stock git, which reads the host's clock for
// everything but the dates Commit stamps, go on as on a real clock; Jump moves it, and the offset with it, forward at
// once, so stored state ages by days the way a schedule's Advance ages it, and evs, every device and the next commit
// read the same time.
//
// Safe for concurrent use. Timers fire on the follower's goroutine, or on Jump's caller's.

package evsgit

import (
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// A fake clock that follows real time plus what Jump moved it.
type FollowingClock struct {
	fake *sidecartest.FakeClock

	stateLock sync.Mutex
	// how far Jump has moved the clock past real time
	offset time.Duration
}

// Keeps fake at real time plus the offset Jump moves until t ends, stepping it every interval. fake starts at or
// behind real time, so the first step brings it level.
func FollowRealTime(t testing.TB, fake *sidecartest.FakeClock, interval time.Duration) *FollowingClock {
	clock := &FollowingClock{fake: fake}
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				clock.follow()
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-stopped
	})
	clock.follow()
	return clock
}

// The fake clock every reader holds.
func (self *FollowingClock) Fake() *sidecartest.FakeClock {
	return self.fake
}

// One step: the clock to real time plus the offset, never back.
func (self *FollowingClock) follow() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.fake.AdvanceTo(time.Now().Add(self.offset))
}

// Moves the clock forward by d at once, firing every timer it passes, and keeps it that much further ahead of real
// time from then on.
func (self *FollowingClock) Jump(d time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.offset += d
	self.fake.AdvanceTo(time.Now().Add(self.offset))
}
