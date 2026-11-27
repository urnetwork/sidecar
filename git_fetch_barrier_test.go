//go:build sidecar_testhooks && !ios_extension && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// GIT-M13-02's barrier proof (§13.6's trap: the taint is fsynced before the worktree's first byte, never after): on
// the sidecar_testhooks leg, a clone of another member's push passes git.fetch_taint, which follows the run's taint,
// before git.worktree_write, which precedes the checkout's first byte.

package sidecar_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// The taint's barrier comes before the worktree's, and the taint before both.
func TestFetchTaintBarrierPrecedesWorktree(t *testing.T) {
	world, writer, bundled := newGitWorld(t)
	other := world.Device("other-member", &evsgit.DeviceSettings{OtherMember: true})
	dir := writer.Clone()
	writer.Commit(dir, "base", map[string]*string{"README": evsgit.Text("base\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the base: %s", out)
	}
	if err := other.Replay("main"); err != nil {
		t.Fatal(err)
	}
	otherDir := other.Clone()
	other.MustGit(otherDir, "checkout", "-q", "-B", "theirs", "origin/main")
	other.Commit(otherDir, "theirs", map[string]*string{"theirs.txt": evsgit.Text("theirs\n")})
	if out, ok := other.Push(otherDir, "origin", "HEAD:refs/heads/theirs"); !ok {
		t.Fatalf("the other member's push: %s", out)
	}
	stateLock := sync.Mutex{}
	order := []string{}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if strings.HasPrefix(name, "git.") {
			stateLock.Lock()
			defer stateLock.Unlock()
			order = append(order, name)
		}
	}})
	defer sidecar.SetTestHooks(nil)
	_, _, _, recorder := gitWorldClone(t, world, bundled, "theirs", "")
	stateLock.Lock()
	defer stateLock.Unlock()
	if recorder.calls != 1 || strings.Join(order, " ") != "git.fetch_taint git.worktree_write" {
		t.Fatalf("taints %d, barriers %v", recorder.calls, order)
	}
}
