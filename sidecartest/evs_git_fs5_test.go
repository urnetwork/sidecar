//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FS-5's clauses (evsgit/fs5.go) on T2: the engine in this process and a world a clause, so every go test runs each
// schedule server's evshost TestFs5OnT3 runs on T3's stores with the same steps.

package sidecartest_test

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// The files of the push in parts: past PartMaxEntryWriteCount, 1,024 entry writes.
const evsGitFs5PartsFileCount = 1100

// A world whose devices take FS-5's client settings.
func newEvsGitFs5World(t *testing.T) *evsgit.World {
	t.Helper()
	settings := evsgit.DefaultWorldSettings()
	settings.HookCommand, settings.ClientSettings = evsGitHookCommand(t), evsgit.Fs5ClientSettings()
	return evsgit.NewWorld(t, settings)
}

func TestEvsGitFs5Siblings(t *testing.T) {
	evsgit.Fs5Siblings(t, newEvsGitFs5World(t))
}

func TestEvsGitFs5RefusalsAreNoNonFastForward(t *testing.T) {
	evsgit.Fs5RefusalsAreNoNonFastForward(t, newEvsGitFs5World(t))
}

func TestEvsGitFs5PushInParts(t *testing.T) {
	evsgit.Fs5PushInParts(t, newEvsGitFs5World(t), evsGitFs5PartsFileCount)
}

func TestEvsGitFs5AtomicSecondRefConflicts(t *testing.T) {
	evsgit.Fs5AtomicSecondRefConflicts(t, newEvsGitFs5World(t))
}

func TestEvsGitFs5LostAnswerReconciles(t *testing.T) {
	evsgit.Fs5LostAnswerReconciles(t, newEvsGitFs5World(t))
}
