//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// EVS1-M2-33's tests: a mount created and reopened from the sealed store, its bare repository's settings and its
// clone's committer; the bare repository beside its sealed mirror, in <state>'s modes, gone with the network; a stored
// record naming no path; a ref lock held by sync blocking receive until released; a git below 2.34 refused by name.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	// 8.2.11's upkeep, and the daemon's namespace
	for key, want := range map[string]string{
		"transfer.hideRefs": "refs/ur", "gc.auto": "0", "receive.autogc": "false", "transfer.fsckObjects": "false",
		"receive.denyNonFastForwards": "false", "receive.denyDeletes": "false", "core.logAllRefUpdates": "false",
	} {
		if got := config(info.BareDir, key, false); got != want {
			t.Errorf("%s %q", key, got)
		}
	}
	if stat, err := os.Stat(filepath.Join(info.BareDir, "refs", "ur")); err != nil || !stat.IsDir() {
		t.Errorf("refs/ur/: %v", err)
	}
	if got := config(info.BareDir, "core.sharedRepository", false); got != "0600" {
		t.Errorf("sharedRepository %q", got)
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

// The sealed mirror layout on a desktop: a mount's bare repository and hooks sit in the network's plaintext git tree
// under <state>, beside the evs component's sealed directory that holds the repo's mirror and never inside it, with
// <state>'s 0700 and 0600 modes on what git writes later too; and leaving the network takes the plaintext with the
// sealed state.
func TestEvsMountSitsBesideItsSealedMirror(t *testing.T) {
	git := evsTestGitRunner(t)
	state := t.TempDir()
	backend, err := NewSidecarOsBackend(state)
	if err != nil {
		t.Fatal(err)
	}
	instance := newInstanceOn(t, backend, newFakeKeyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	store := storeOf(t, instance, testNetworkId, evsComponentName)
	test := newEvsTestClient(t, http.NotFoundHandler(), store)
	mounts, err := NewEvsMounts(test.client, state, git)
	if err != nil {
		t.Fatal(err)
	}
	networkDir := filepath.Join(state, "net", testNetworkId.String())
	if mounts.GitTree() != filepath.Join(networkDir, "git") {
		t.Errorf("git tree %s", mounts.GitTree())
	}
	repoId := evsTestId("mounted repo")
	if _, err := test.client.Repo(repoId).Mount(context.Background(), &EvsMountArgs{}); err != nil {
		t.Fatal(err)
	}
	mount, ok := mounts.Get(repoId)
	if !ok {
		t.Fatal("no mount")
	}
	if mount.BareDir != filepath.Join(networkDir, "git", evsUrlId(repoId)+".git") ||
		mount.HooksDir != filepath.Join(networkDir, "git", evsUrlId(repoId)+".hooks") {
		t.Errorf("bare %s hooks %s", mount.BareDir, mount.HooksDir)
	}
	mirror, err := test.client.Mirror(repoId)
	if err != nil || mount.Mirror != mirror {
		t.Fatalf("the mount's mirror is not the client's: %v", err)
	}
	refId := evsTestId("ref")
	if err := mirror.Put(EvsMirrorStatementKey(refId, 1), bytes.NewReader([]byte("a statement"))); err != nil {
		t.Fatal(err)
	}
	statementFile := filepath.Join(networkDir, "evs", "mirror", evsUrlId(repoId), "stmt", evsUrlId(refId), "00000000000000000001")
	if _, err := os.Stat(statementFile); err != nil {
		t.Errorf("the mirror's statement: %v", err)
	}
	// the sealed directory holds no file of git's, and the registry lists its one record
	entries, err := store.List("")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name, "mirror/") && !strings.HasPrefix(entry.Name, "mounts/") {
			t.Errorf("the sealed directory holds %s", entry.Name)
		}
	}
	if records, err := store.List(evsMountDirectory); err != nil || len(records) != 1 {
		t.Errorf("mount records %d %v", len(records), err)
	}

	if runtime.GOOS != "windows" {
		blob := filepath.Join(t.TempDir(), "blob")
		if err := os.WriteFile(blob, []byte("plaintext like the working tree\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := mount.Git(context.Background(), "hash-object", "-w", blob)
		if err != nil {
			t.Fatal(err)
		}
		oid := strings.TrimSpace(string(out))
		// the user's alone: no group or other bit, on the tree and on an object git wrote after init (read-only)
		for _, path := range []string{
			filepath.Join(networkDir, "git"),
			mount.BareDir,
			mount.HooksDir,
			filepath.Join(mount.BareDir, "config"),
			filepath.Join(mount.BareDir, "objects", oid[:2]),
			filepath.Join(mount.BareDir, "objects", oid[:2], oid[2:]),
		} {
			info, err := os.Stat(path)
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s: mode %o", path, info.Mode().Perm())
			}
		}
	}

	if err := instance.forgetNetwork(testNetworkId); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(mount.BareDir, "HEAD"), filepath.Join(mount.BareDir, "config"), statementFile} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s outlives the network: %v", path, err)
		}
	}
}

// A mount's paths come from the layout alone: a stored record naming a bare repository elsewhere, as an older record
// or a tampered one might, does not send git there.
func TestEvsMountRecordNamesNoPath(t *testing.T) {
	git := evsTestGitRunner(t)
	store := newEvsTestStore(t)
	test := newEvsTestClient(t, http.NotFoundHandler(), store)
	state := t.TempDir()
	mounts, err := NewEvsMounts(test.client, state, git)
	if err != nil {
		t.Fatal(err)
	}
	repoId := evsTestId("mounted repo")
	elsewhere := t.TempDir()
	record := `{"dir":"","bare_dir":"` + elsewhere + `","hooks_dir":"` + elsewhere + `","agent_label":"agent one"}`
	writeStoreFile(t, store, evsMountDirectory+repoId.String(), []byte(record))
	if err := mounts.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	mount, ok := mounts.Get(repoId)
	if !ok {
		t.Fatal("no mount")
	}
	if mount.BareDir != filepath.Join(mounts.GitTree(), evsUrlId(repoId)+".git") || strings.HasPrefix(mount.BareDir, elsewhere) ||
		strings.HasPrefix(mount.HooksDir, elsewhere) || mount.AgentLabel != "agent one" {
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
