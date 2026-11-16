//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FS-73's clauses (evsgit/fs73.go) on T2: the engine in this process, a world a clause, each with the network in the
// format2 gate, this host's stock git-lfs on PATH in every clone, its transfer agent and git-remote-ur this test
// binary relaying to the device's daemon, and a clock that follows real time until a clause moves it by days. Server's
// evshost TestFs73OnT3 runs the same clauses on T3's stores, across §22.9's matrix rows the host holds. FS-73 is a T3
// row; these are the same schedules on the fakes, so a divergence shows. The race clause and the twin hold or switch
// the real code, so they need the sidecar_testhooks build and skip without it.

package sidecartest_test

import (
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// Not a test: git-lfs's transfer agent a world's clones exec, relaying to its device's daemon (evsgit.LfsAgentHelper).
func TestEvsGitLfsAgentHelperProcess(t *testing.T) {
	evsgit.LfsAgentHelper()
}

// Not a test: git-remote-ur as a world's git execs it for a ur:// remote, dialing its device's daemon in git mode
// (evsgit.RemoteHelper).
func TestEvsGitRemoteHelperProcess(t *testing.T) {
	evsgit.RemoteHelper()
}

// A world for FS-73: format 2, git-lfs, git-remote-ur, and a clock that follows real time.
func newEvsGitFs73World(t *testing.T) *evsgit.World {
	t.Helper()
	gitLfs, err := exec.LookPath("git-lfs")
	if err != nil {
		t.Skip("no git-lfs on this host")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	settings := evsgit.DefaultWorldSettings()
	settings.HookCommand, settings.ClientSettings = evsGitHookCommand(t), evsgit.Fs73ClientSettings()
	settings.Clock = evsgit.FollowRealTime(t, sidecartest.NewFakeClock(time.Now()), 10*time.Millisecond)
	settings.Format2 = true
	settings.Lfs = &evsgit.WorldLfs{AgentCommand: []string{binary, "-test.run=^TestEvsGitLfsAgentHelperProcess$"}, GitLfs: gitLfs}
	settings.RemoteHelperCommand = []string{binary, "-test.run=^TestEvsGitRemoteHelperProcess$", "--"}
	return evsgit.NewWorld(t, settings)
}

func TestEvsGitFs73StoreAndSmudge(t *testing.T) {
	evsgit.Fs73StoreAndSmudge(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73PrunedHistory(t *testing.T) {
	evsgit.Fs73PrunedHistory(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73PruneLosesToATouch(t *testing.T) {
	evsgit.Fs73PruneLosesToATouch(t, newEvsGitFs73World(t), newEvsGitFs73Barrier(t).hold)
}

func TestEvsGitFs73OverEachTransport(t *testing.T) {
	evsgit.Fs73OverEachTransport(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73OwnedRefHoldsWhenPrunedMeanwhile(t *testing.T) {
	evsgit.Fs73OwnedRefHoldsWhenPrunedMeanwhile(t, newEvsGitFs73World(t), newEvsGitFs73Barrier(t).hold)
}

func TestEvsGitFs73SkipOptionsRefusedAlike(t *testing.T) {
	evsgit.Fs73SkipOptionsRefusedAlike(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73AttributesChangeChecksTheObject(t *testing.T) {
	evsgit.Fs73AttributesChangeChecksTheObject(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73ImportUploadsFirst(t *testing.T) {
	evsgit.Fs73ImportUploadsFirst(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73PruneRefusesWithARefMissing(t *testing.T) {
	evsgit.Fs73PruneRefusesWithARefMissing(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73WindowBelowSevenReadsAsSeven(t *testing.T) {
	evsgit.Fs73WindowBelowSevenReadsAsSeven(t, newEvsGitFs73World(t))
}

// The holds FS-73's race and owned clauses take on T2: a barrier hook of the test's own, where a site's next arrival,
// <name> or <name>@<key> as sidecartest.BarrierSite writes it, holds until release.
type evsGitFs73Barrier struct {
	stateLock sync.Mutex
	armed     map[string]*evsGitFs73Hold
}

// One armed site: arrived closes when an arrival holds, release lets it go.
type evsGitFs73Hold struct {
	arrived chan struct{}
	release chan struct{}
}

func newEvsGitFs73Barrier(t *testing.T) *evsGitFs73Barrier {
	t.Helper()
	if !sidecartest.HooksLinked {
		t.Skip("needs the sidecar_testhooks build")
	}
	barrier := &evsGitFs73Barrier{armed: map[string]*evsGitFs73Hold{}}
	remove, err := sidecartest.InstallTestHooks(nil, barrier.hit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	return barrier
}

// An evsgit.Fs73Hold: site's next arrival holds until the answer is called, and arrived closes when it comes.
func (self *evsGitFs73Barrier) hold(t testing.TB, site string) (<-chan struct{}, func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hold := &evsGitFs73Hold{arrived: make(chan struct{}), release: make(chan struct{})}
	self.armed[site] = hold
	var once sync.Once
	return hold.arrived, func() {
		once.Do(func() {
			self.stateLock.Lock()
			// an arm nothing reached goes with its release
			if self.armed[site] == hold {
				delete(self.armed, site)
			}
			self.stateLock.Unlock()
			close(hold.release)
		})
	}
}

func (self *evsGitFs73Barrier) hit(name string, key string) {
	hold := func() *evsGitFs73Hold {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, site := range []string{sidecartest.BarrierSite(name, key), name} {
			if hold, ok := self.armed[site]; ok {
				delete(self.armed, site)
				return hold
			}
		}
		return nil
	}()
	if hold == nil {
		return
	}
	close(hold.arrived)
	<-hold.release
}
