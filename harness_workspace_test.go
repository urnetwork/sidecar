//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A workspace in a test's temp directory with cap, removed at the test's end.
func newHarnessTestWorkspace(t *testing.T, capByteCount int64) *harnessWorkspace {
	t.Helper()
	workspace, err := newHarnessWorkspace(&harnessWorkspaceArgs{Parent: t.TempDir(), CapByteCount: capByteCount})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { workspace.Remove() })
	return workspace
}

// `..` is refused wherever it stands, and a path's . components and repeated separators fold away.
func TestHarnessWorkspaceRefusesTraversal(t *testing.T) {
	workspace := newHarnessTestWorkspace(t, 1024*1024)
	for _, name := range []string{"..", "../outside.txt", "a/../../outside.txt", "a/..", `a\..\..\outside.txt`, "./a/../b"} {
		if _, err := workspace.WriteFile(name, []byte("x")); !errors.Is(err, ErrHarnessWorkspacePath) {
			t.Errorf("%q: %v", name, err)
		}
		if _, _, err := workspace.ReadFile(name, 1024); !errors.Is(err, ErrHarnessWorkspacePath) {
			t.Errorf("read %q: %v", name, err)
		}
	}
	held, err := workspace.WriteFile("./notes//today.md", []byte("x"))
	if err != nil || held != "notes/today.md" {
		t.Fatalf("a folded path: %q, %v", held, err)
	}
	if _, err := os.Stat(filepath.Join(workspace.HostPath(), "notes", "today.md")); err != nil {
		t.Fatal(err)
	}
	// a refusal names its rule, never a host path
	_, err = workspace.WriteFile("../x", []byte("x"))
	if strings.Contains(err.Error(), workspace.HostPath()) || strings.Contains(err.Error(), os.TempDir()) {
		t.Fatalf("a refusal names a host path: %v", err)
	}
}

// A symbolic link resolving outside the workspace is refused for reads and writes; one that stays inside is followed.
func TestHarnessWorkspaceRefusesSymlinkOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on windows")
	}
	workspace := newHarnessTestWorkspace(t, 1024*1024)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace.HostPath(), "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(workspace.HostPath(), "secret-link")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"escape/secret.txt", "secret-link"} {
		if data, _, err := workspace.ReadFile(name, 1024); err == nil {
			t.Errorf("read %q through a link out: %q", name, data)
		}
	}
	if _, err := workspace.WriteFile("escape/planted.txt", []byte("x")); err == nil {
		t.Fatal("a write through a link out landed")
	}
	if _, err := os.Stat(filepath.Join(outside, "planted.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a file appeared outside the workspace: %v", err)
	}
	// a link that stays inside is followed
	if _, err := workspace.WriteFile("inner/real.txt", []byte("inside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.txt", filepath.Join(workspace.HostPath(), "inner", "alias.txt")); err != nil {
		t.Fatal(err)
	}
	if data, _, err := workspace.ReadFile("inner/alias.txt", 1024); err != nil || string(data) != "inside" {
		t.Fatalf("a link inside: %q, %v", data, err)
	}
}

// Absolute host paths, drive letters, UNC paths, alternate data streams and a home directory are refused.
func TestHarnessWorkspaceRefusesAbsoluteAndWindowsPaths(t *testing.T) {
	workspace := newHarnessTestWorkspace(t, 1024*1024)
	for _, name := range []string{"/etc/hosts", `\Windows\win.ini`, `C:\Users\x.txt`, `C:x.txt`, "c:/x.txt", `\\server\share\x.txt`,
		"//server/share/x.txt", "notes.txt:hidden", "notes.txt::$DATA", "~/x.txt", "a/b:c/d"} {
		if _, err := workspace.WriteFile(name, []byte("x")); !errors.Is(err, ErrHarnessWorkspacePath) {
			t.Errorf("%q: %v", name, err)
		}
	}
}

// The cap counts every file beneath the root, a git worktree's among them, and is checked before a write lands; an
// overwrite counts the file it replaces as freed.
func TestHarnessWorkspaceCapCountsWorktrees(t *testing.T) {
	workspace := newHarnessTestWorkspace(t, 1000)
	// what the bundled git checked out beneath the workspace, written beside the file tools
	worktree := filepath.Join(workspace.HostPath(), "repo")
	if err := os.MkdirAll(filepath.Join(worktree, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, "src", "main.go"), []byte(strings.Repeat("g", 600)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, "README"), []byte(strings.Repeat("r", 300)), 0o600); err != nil {
		t.Fatal(err)
	}
	if usage, err := workspace.Usage(); err != nil || usage != 900 {
		t.Fatalf("usage %d, %v", usage, err)
	}
	if _, err := workspace.WriteFile("notes.txt", []byte(strings.Repeat("n", 200))); !errors.Is(err, ErrHarnessWorkspaceFull) {
		t.Fatalf("a write past the cap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace.HostPath(), "notes.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused write landed")
	}
	if _, err := workspace.WriteFile("notes.txt", []byte(strings.Repeat("n", 100))); err != nil {
		t.Fatalf("a write within the cap: %v", err)
	}
	// replacing the README's 300 bytes with 300 fits; with 301 it does not
	if _, err := workspace.WriteFile("repo/README", []byte(strings.Repeat("R", 300))); err != nil {
		t.Fatalf("an overwrite of the same size: %v", err)
	}
	if _, err := workspace.WriteFile("repo/README", []byte(strings.Repeat("R", 301))); !errors.Is(err, ErrHarnessWorkspaceFull) {
		t.Fatalf("an overwrite past the cap: %v", err)
	}
}

// Removing the workspace, as its run ends, deletes it whole, and every later use is refused.
func TestHarnessWorkspaceRemovedAtRunEnd(t *testing.T) {
	workspace := newHarnessTestWorkspace(t, 1024*1024)
	if _, err := workspace.WriteFile("work/draft.md", []byte("draft")); err != nil {
		t.Fatal(err)
	}
	hostPath := workspace.HostPath()
	if err := workspace.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(hostPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the workspace stands after its run: %v", err)
	}
	if _, err := workspace.WriteFile("again.md", []byte("x")); !errors.Is(err, ErrHarnessWorkspaceRemoved) {
		t.Fatalf("a write after removal: %v", err)
	}
	if _, _, err := workspace.ReadFile("work/draft.md", 1024); !errors.Is(err, ErrHarnessWorkspaceRemoved) {
		t.Fatalf("a read after removal: %v", err)
	}
	if err := workspace.Remove(); err != nil {
		t.Fatalf("a second removal: %v", err)
	}
}
