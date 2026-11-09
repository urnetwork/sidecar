//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// EVS1-M2-33's tests: a mount created and reopened from the sealed store, its bare repository's settings and its
// clone's committer; a ref lock held by sync blocking receive until released; a git below 2.34 refused by name.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A clock whose waits never end, so a lock's timeout never fires in a test.
type evsTestStillClock struct{}

// The test's fixed now.
func (self evsTestStillClock) Now() time.Time {
	return time.Date(2026, time.November, 8, 0, 0, 0, 0, time.UTC)
}

// Never fires.
func (self evsTestStillClock) After(timeout time.Duration) <-chan time.Time { return nil }

// Never fires.
func (self evsTestStillClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return true }
}

// The system git's runner, skipping where none is installed.
func evsTestGitRunner(t *testing.T) *EvsGitRunner {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no system git")
	}
	gitPath, err = filepath.Abs(gitPath)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewEvsGitRunner(context.Background(), gitPath, t.TempDir(), DefaultEvsSettings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

// A mount creates its bare repository with the receive settings and hooks path, sets the clone's committer, and a new
// registry on the same store reopens it.
func TestEvsMountCreatesAndReopens(t *testing.T) {
	git := evsTestGitRunner(t)
	store := newEvsTestStore(t)
	test := newEvsTestClient(t, http.NotFoundHandler(), store)
	stateDir := t.TempDir()
	if _, err := NewEvsMounts(test.client, stateDir, git); err != nil {
		t.Fatal(err)
	}
	clone := t.TempDir()
	if _, err := git.Run(context.Background(), "", "init", "--quiet", clone); err != nil {
		t.Fatal(err)
	}
	repoId := evsTestId("mounted repo")
	info, err := test.client.Repo(repoId).Mount(context.Background(), &EvsMountArgs{Dir: clone, AgentLabel: "agent one"})
	if err != nil {
		t.Fatal(err)
	}
	if info.BareDir == "" || !strings.HasPrefix(info.BareDir, stateDir) {
		t.Fatalf("bare dir %s", info.BareDir)
	}
	config := func(dir string, key string, all bool) string {
		args := []string{"config"}
		if all {
			args = append(args, "--get-all")
		} else {
			args = append(args, "--get")
		}
		out, err := git.Run(context.Background(), dir, append(args, key)...)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		return strings.TrimSpace(string(out))
	}
	if got := config(info.BareDir, "receive.procReceiveRefs", true); got != "refs/heads\nrefs/tags" {
		t.Errorf("procReceiveRefs %q", got)
	}
	if got := config(info.BareDir, "receive.advertiseAtomic", false); got != "false" {
		t.Errorf("advertiseAtomic %q", got)
	}
	if got := config(info.BareDir, "core.hooksPath", false); !strings.HasSuffix(got, ".hooks") {
		t.Errorf("hooksPath %q", got)
	}
	// absent is sha1, git's default; only a sha256 repository names the extension
	if out, err := git.Run(context.Background(), info.BareDir, "rev-parse", "--show-object-format"); err != nil || strings.TrimSpace(string(out)) != "sha1" {
		t.Errorf("object format %q %v", out, err)
	}
	if got := config(clone, "committer.name", false); got != "agent one" {
		t.Errorf("committer.name %q", got)
	}
	if got := config(clone, "committer.email", false); got != evsTestId("client").String()+"@ur.invalid" {
		t.Errorf("committer.email %q", got)
	}
	// a second add is the same mount, its settings not doubled
	if _, err := test.client.Repo(repoId).Mount(context.Background(), &EvsMountArgs{Dir: clone, AgentLabel: "agent one"}); err != nil {
		t.Fatal(err)
	}
	if got := config(info.BareDir, "receive.procReceiveRefs", true); got != "refs/heads\nrefs/tags" {
		t.Errorf("procReceiveRefs after a second add %q", got)
	}

	reopened := newEvsTestClient(t, http.NotFoundHandler(), store)
	again, err := NewEvsMounts(reopened.client, stateDir, git)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	mount, ok := again.Get(repoId)
	if !ok || mount.BareDir != info.BareDir || mount.Dir != clone || mount.AgentLabel != "agent one" {
		t.Errorf("reopened %+v", mount)
	}
}

// A ref lock held by the sync engine keeps receive-pack's update waiting: a receive whose ctx ends first never takes
// it, and one after the release does.
func TestEvsRefLockHeldBySyncBlocksReceive(t *testing.T) {
	locks := NewEvsRefLocks(DefaultEvsSettings(), evsTestStillClock{})
	releaseSync, err := locks.Lock(context.Background(), "refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		_, err := locks.Lock(ctx, "refs/heads/main")
		waiting <- err
	}()
	cancel()
	if err := <-waiting; !errors.Is(err, context.Canceled) {
		t.Fatalf("receive took a held lock: %v", err)
	}
	if other, err := locks.Lock(context.Background(), "refs/heads/other"); err != nil {
		t.Fatalf("another ref: %v", err)
	} else {
		other()
	}
	got := make(chan func(), 1)
	go func() {
		release, err := locks.Lock(context.Background(), "refs/heads/main")
		if err != nil {
			t.Error(err)
		}
		got <- release
	}()
	releaseSync()
	releaseReceive := <-got
	if !locks.Held("refs/heads/main") {
		t.Errorf("receive does not hold the lock")
	}
	releaseReceive()
	releaseReceive()
	if locks.Held("refs/heads/main") {
		t.Errorf("released twice, still held")
	}
}

// A git below 2.34 is refused with a message naming both versions; one at the floor passes.
func TestEvsOldGitRefused(t *testing.T) {
	for _, c := range []struct {
		output string
		ok     bool
	}{
		{output: "git version 2.33.8", ok: false},
		{output: "git version 2.34.0", ok: true},
		{output: "git version 2.47.1.windows.2", ok: true},
		{output: "git version 1.9.5", ok: false},
	} {
		dir := t.TempDir()
		fake := filepath.Join(dir, "git")
		if err := os.WriteFile(fake, []byte("#!/bin/sh\necho '"+c.output+"'\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := NewEvsGitRunner(context.Background(), fake, dir, DefaultEvsSettings(), nil)
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.output, err)
		}
		if !c.ok && (!errors.Is(err, ErrEvsGitTooOld) || !strings.Contains(err.Error(), "2.34")) {
			t.Errorf("%s: the refusal %v", c.output, err)
		}
	}
	if _, err := NewEvsGitRunner(context.Background(), "git", t.TempDir(), DefaultEvsSettings(), nil); err == nil {
		t.Errorf("a git by a relative path")
	}
}
