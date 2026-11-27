//go:build !ios_extension && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// GIT-M13-02's clone tests on evsgit's world (DESIGN-COMPUTE §13.4's clone row, D-GIT-1, D-GIT-2): the bundled git
// clones what stock git pushed through the local tier, with oids equal to a stock git device's clone and a worktree
// stock git's fsck passes; a sparse clone writes and fetches only its prefix; a remote that is not ur:// is refused
// before anything is written.

package sidecar_test

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// Not a test: the hook a world's mounts exec relays to its device's daemon (evsgit.HookHelper).
func TestGitHookHelperProcess(t *testing.T) {
	evsgit.HookHelper()
}

// A world with a writer device on stock git and the bundled git's device, whose evs client the bundled git uses.
func newGitWorld(t *testing.T) (*evsgit.World, *evsgit.Device, *evsgit.Device) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	settings := evsgit.DefaultWorldSettings()
	settings.HookCommand = []string{binary, "-test.run=^TestGitHookHelperProcess$", "--"}
	world := evsgit.NewWorld(t, settings)
	return world, world.Device("writer", nil), world.Device("bundled", nil)
}

// The world's repo as the bundled git's remote.
func gitWorldUrl(world *evsgit.World) string {
	return "ur://world/id:" + world.RepoId().String()
}

// A fresh worktree directory and its file system.
func gitWorldWorktree(t *testing.T) (string, sidecar.GitFileSystem) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "worktree")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fileSystem, closeFileSystem, err := sidecar.NewGitOsFileSystem(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeFileSystem() })
	return dir, fileSystem
}

// A taint that records each call and what the worktree held when it came.
type gitTaintRecorder struct {
	dir string

	stateLock sync.Mutex
	calls     int
	// the worktree's entries beside .git at the first call
	heldAtTaint []string
}

func (self *gitTaintRecorder) taint(ctx context.Context) error {
	entries, err := os.ReadDir(self.dir)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.calls == 0 {
		for _, entry := range entries {
			if entry.Name() != ".git" {
				self.heldAtTaint = append(self.heldAtTaint, entry.Name())
			}
		}
	}
	self.calls += 1
	return nil
}

// Clones the world's branch with device's evs client into a fresh worktree.
func gitWorldClone(t *testing.T, world *evsgit.World, device *evsgit.Device, branch string, sparse string) (*sidecar.GitRepository, *sidecar.GitCloneResult, string, *gitTaintRecorder) {
	t.Helper()
	dir, fileSystem := gitWorldWorktree(t)
	recorder := &gitTaintRecorder{dir: dir}
	repository, result, err := sidecar.GitClone(t.Context(), &sidecar.GitCloneArgs{
		Url: gitWorldUrl(world), FileSystem: fileSystem, Branch: branch, Sparse: sparse,
		Evs: &sidecar.GitEvsArgs{Evs: device.Client, Taint: recorder.taint},
	})
	if err != nil {
		t.Fatalf("the bundled git's clone: %v", err)
	}
	return repository, result, dir, recorder
}

// Runs stock git in dir with no system or global config.
func gitStock(t *testing.T, dir string, args ...string) string {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on this host")
	}
	command := exec.Command(gitPath, args...)
	command.Dir = dir
	command.Env = []string{"HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "LC_ALL=C", "PATH=" + os.Getenv("PATH")}
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// The writer pushes a history of three pushes, the last carrying two commits so a blob rides only in its history
// records; the bundled git clones it with every oid equal to a stock git device's clone, its worktree passes stock
// git's fsck and status, and nothing a member's own untainted pushes brought taints the run.
func TestCloneMatchesStockGit(t *testing.T) {
	world, writer, bundled := newGitWorld(t)
	dir := writer.Clone()
	writer.Commit(dir, "first", map[string]*string{"README.md": evsgit.Text("# readme\n"), "docs/plan.md": evsgit.Text("plan\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the first push: %s", out)
	}
	writer.Commit(dir, "second", map[string]*string{"src/main.go": evsgit.Text("package main\n"), "docs/plan.md": evsgit.Text("plan, revised\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the second push: %s", out)
	}
	writer.Commit(dir, "third", map[string]*string{"notes/draft.txt": evsgit.Text("a draft only history holds\n")})
	writer.Commit(dir, "fourth", map[string]*string{"notes/draft.txt": evsgit.Text("the draft, final\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the third push: %s", out)
	}
	repository, result, worktree, recorder := gitWorldClone(t, world, bundled, "main", "")
	want := strings.TrimSpace(writer.MustGit(dir, "rev-parse", "HEAD"))
	if result.Tip == nil || result.Tip.String() != want {
		t.Fatalf("the clone's tip %v, the writer pushed %s", result.Tip, want)
	}
	if recorder.calls != 0 {
		t.Fatal("a member's own untainted pushes tainted the run")
	}
	// a stock git device's clone of the same ref holds the same commits
	if err := bundled.Replay("main"); err != nil {
		t.Fatal(err)
	}
	stockDir := bundled.Clone()
	if bundled.Shape(stockDir, "origin/main") != bundled.Shape(worktree, "HEAD") {
		t.Fatalf("stock git's clone holds %s, the bundled git's %s", bundled.Shape(stockDir, "origin/main"), bundled.Shape(worktree, "HEAD"))
	}
	if gitStock(t, stockDir, "log", "--format=%H %T", "origin/main") != gitStock(t, worktree, "log", "--format=%H %T", "HEAD") {
		t.Fatal("the histories differ")
	}
	gitStock(t, worktree, "fsck", "--strict", "--no-dangling")
	if status := gitStock(t, worktree, "status", "--porcelain"); status != "" {
		t.Fatalf("stock git's status of the clone: %q", status)
	}
	if upstream := strings.TrimSpace(gitStock(t, worktree, "rev-parse", "--abbrev-ref", "main@{upstream}")); upstream != "origin/main" {
		t.Fatalf("main's upstream reads %q", upstream)
	}
	content, err := os.ReadFile(filepath.Join(worktree, "notes", "draft.txt"))
	if err != nil || string(content) != "the draft, final\n" {
		t.Fatalf("the worktree holds %q, %v", content, err)
	}
	if repository.Lazy() {
		t.Fatal("a full clone reads as lazy")
	}
}

// A sparse clone writes and fetches only its prefix: the other paths sit in the index marked unwritten, their blobs
// promised, never fetched; status reads every entry unchanged.
func TestSparseCloneFetchesPrefixOnly(t *testing.T) {
	world, writer, bundled := newGitWorld(t)
	dir := writer.Clone()
	writer.Commit(dir, "tree", map[string]*string{
		"docs/a.md": evsgit.Text("a\n"), "docs/b.md": evsgit.Text("b\n"), "src/main.go": evsgit.Text("package main\n"),
		"src/util/u.go": evsgit.Text("package util\n"), "README": evsgit.Text("readme\n"),
	})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	repository, result, worktree, _ := gitWorldClone(t, world, bundled, "main", "docs")
	if result.Checkout.SparseCount != 3 {
		t.Fatalf("%d paths left out, want 3", result.Checkout.SparseCount)
	}
	if !repository.Lazy() || repository.SparseCheckout().Prefix != "docs/" {
		t.Fatalf("the clone reads lazy %v, prefix %q", repository.Lazy(), repository.SparseCheckout().Prefix)
	}
	written := []string{}
	filepath.WalkDir(worktree, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			if entry != nil && entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		relative, _ := filepath.Rel(worktree, path)
		written = append(written, filepath.ToSlash(relative))
		return nil
	})
	slices.Sort(written)
	if !slices.Equal(written, []string{"docs/a.md", "docs/b.md"}) {
		t.Fatalf("the sparse clone wrote %v", written)
	}
	index, err := repository.Worktree().ReadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Entries) != 5 {
		t.Fatalf("the index holds %d entries, want every path", len(index.Entries))
	}
	objects := repository.Objects()
	for _, entry := range index.Entries {
		inside := strings.HasPrefix(entry.Path, "docs/")
		if entry.Unwritten == inside || objects.Local(entry.Oid) != inside || objects.Promised(entry.Oid) == inside {
			t.Fatalf("%q: unwritten %v, held %v, promised %v", entry.Path, entry.Unwritten, objects.Local(entry.Oid), objects.Promised(entry.Oid))
		}
		if state, err := repository.Worktree().EntryState(t.Context(), entry, nil); err != nil || state != sidecar.GitEntryUnchanged {
			t.Fatalf("%q reads %d, %v", entry.Path, state, err)
		}
	}
}

// A blob outside the sparse prefix is fetched the first time a read asks for it, an entry's and a history record's
// alike, held to its oid; a second read fetches nothing.
func TestLazyBlobOnFirstRead(t *testing.T) {
	world, writer, bundled := newGitWorld(t)
	dir := writer.Clone()
	writer.Commit(dir, "tree", map[string]*string{"docs/a.md": evsgit.Text("a\n"), "src/main.go": evsgit.Text("package main\n")})
	writer.Commit(dir, "draft", map[string]*string{"src/draft.go": evsgit.Text("package draft // only history holds this\n")})
	writer.Commit(dir, "final", map[string]*string{"src/draft.go": evsgit.Text("package draft\n")})
	if out, ok := writer.Push(dir, "origin", "HEAD:refs/heads/main"); !ok {
		t.Fatalf("the push: %s", out)
	}
	repository, _, _, _ := gitWorldClone(t, world, bundled, "main", "docs")
	requests := 0
	world.SetIntercept(func(request *http.Request) (*http.Response, error) {
		requests += 1
		return nil, nil
	}, nil)
	defer world.SetIntercept(nil, nil)
	objects := repository.Objects()
	for _, content := range []string{"package main\n", "package draft // only history holds this\n"} {
		oid := gitWorldBlobOid(t, writer, dir, content)
		if !objects.Promised(oid) {
			t.Fatalf("%q is not promised after the sparse clone", content)
		}
		before := requests
		kind, read, err := objects.ReadGitObject(t.Context(), oid)
		if err != nil || kind != "blob" || string(read) != content {
			t.Fatalf("the lazy read of %q: %s %q, %v", content, kind, read, err)
		}
		if requests == before {
			t.Fatalf("%q read with no request to evs", content)
		}
		if !objects.Local(oid) || objects.Promised(oid) {
			t.Fatalf("%q is not held after its fetch", content)
		}
		after := requests
		if _, _, err := objects.ReadGitObject(t.Context(), oid); err != nil || requests != after {
			t.Fatalf("a second read of %q asked evs again: %v", content, err)
		}
	}
}

// The oid stock git gives content.
func gitWorldBlobOid(t *testing.T, device *evsgit.Device, dir string, content string) sidecar.EvsGitOid {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	hexOid := strings.TrimSpace(device.MustGit(dir, "hash-object", path))
	decoded, err := hex.DecodeString(hexOid)
	if err != nil || len(decoded) != len(sidecar.EvsGitOid{}) {
		t.Fatalf("git hash-object gave %q", hexOid)
	}
	oid := sidecar.EvsGitOid(decoded)
	return oid
}

// Every remote but ur:// is refused before anything is read or written (Q-GIT-2).
func TestNonUrRemotesRefused(t *testing.T) {
	for _, url := range []string{
		"https://github.example/owner/repo.git", "http://git.example/repo", "ssh://git@git.example/repo.git",
		"git@git.example:owner/repo.git", "git://git.example/repo", "file:///tmp/repo", "/tmp/repo", "../repo",
	} {
		dir, fileSystem := gitWorldWorktree(t)
		_, _, err := sidecar.GitClone(t.Context(), &sidecar.GitCloneArgs{Url: url, FileSystem: fileSystem, Evs: &sidecar.GitEvsArgs{}})
		if !errors.Is(err, sidecar.ErrGitRemoteUnsupported) || !strings.Contains(err.Error(), "not supported by ur git") {
			t.Fatalf("%q: %v", url, err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("%q: a refused clone wrote %d entries", url, len(entries))
		}
	}
	for _, url := range []string{"ur://network.example/project-notes", "ur://network.example/", "ur:///id:00000000000000000000000000", "ur://network.example/id:nothex"} {
		if _, err := sidecar.ParseGitRemoteUrl(url); !errors.Is(err, sidecar.ErrGitRemoteInvalid) {
			t.Fatalf("%q: %v", url, err)
		}
	}
	remote, err := sidecar.ParseGitRemoteUrl("ur://network.example/id:" + strings.Repeat("ab", 16))
	if err != nil || remote.Network != "network.example" {
		t.Fatalf("a 32-hex repo id: %+v, %v", remote, err)
	}
}
