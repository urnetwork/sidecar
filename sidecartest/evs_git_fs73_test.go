//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FS-73's clauses (evsgit/fs73.go) on T2: the engine in this process, a world a clause, each with the network in the
// format2 gate, this host's stock git-lfs on PATH in every clone, its transfer agent this test binary relaying to the
// device's daemon, and a clock that follows real time until a clause moves it by days. Server's evshost TestFs73OnT3
// runs the same clauses on T3's stores, across §22.9's matrix rows the host holds. FS-73 is a T3 row; these are the
// same schedules on the fakes, so a divergence shows. The race clause and the twin hold or switch the real code, so they
// need the sidecar_testhooks build and skip without it.

package sidecartest_test

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// Not a test: git-lfs's transfer agent a world's clones exec, relaying to its device's daemon (evsgit.LfsAgentHelper).
func TestEvsGitLfsAgentHelperProcess(t *testing.T) {
	evsgit.LfsAgentHelper()
}

// A world for FS-73: format 2, git-lfs, and a clock that follows real time.
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
	return evsgit.NewWorld(t, settings)
}

func TestEvsGitFs73StoreAndSmudge(t *testing.T) {
	evsgit.Fs73StoreAndSmudge(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73PrunedHistory(t *testing.T) {
	evsgit.Fs73PrunedHistory(t, newEvsGitFs73World(t))
}

func TestEvsGitFs73PruneLosesToATouch(t *testing.T) {
	barrier := newEvsGitTwinBarrier(t)
	evsgit.Fs73PruneLosesToATouch(t, newEvsGitFs73World(t), func(t testing.TB, name string) (<-chan struct{}, func()) {
		return barrier.arm(name)
	})
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
