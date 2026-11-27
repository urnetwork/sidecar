//go:build !ios_extension && !sidecar_http && !js

// GIT-M13-01's workspace cap test (DESIGN-COMPUTE §7.5, §13.7): a worktree in an agent's workspace counts against the
// workspace's cap, and a checkout that would pass it is refused before the file lands, never truncating what stood.

package sidecar

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A checkout of a file past what the workspace has left is refused with ErrGitWorkspaceFull, the file absent and the
// staging copy gone; a small file within the cap lands.
func TestWorktreeCountsAgainstWorkspaceCap(t *testing.T) {
	workspace, err := newHarnessWorkspace(&harnessWorkspaceArgs{Parent: t.TempDir(), CapByteCount: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Remove()
	fileSystem, closeFileSystem, err := newGitWorkspaceFileSystem(workspace, "repo")
	if err != nil {
		t.Fatal(err)
	}
	defer closeFileSystem()
	repository := gitTestInit(t, fileSystem)
	small := gitTestTree(t, repository.Objects(), []gitTestFile{{path: "small.txt", mode: EvsGitModeFile, content: "small\n"}})
	gitTestCheckout(t, repository, &GitCheckoutArgs{Tree: small})
	if content, err := os.ReadFile(filepath.Join(workspace.HostPath(), "repo", "small.txt")); err != nil || string(content) != "small\n" {
		t.Fatalf("the small file: %q, %v", content, err)
	}
	// the large blob is written by a store outside the workspace's budget, as a fetch's would be counted, then checked out
	large := strings.Repeat("x", 80*1024)
	unbounded, closeUnbounded, err := NewGitOsFileSystem(filepath.Join(workspace.HostPath(), "repo"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeUnbounded()
	tree := gitTestTree(t, newGitObjectStore(unbounded, DefaultGitSettings()), []gitTestFile{
		{path: "small.txt", mode: EvsGitModeFile, content: "small\n"}, {path: "large.txt", mode: EvsGitModeFile, content: large},
	})
	lock, err := repository.Worktree().LockIndex()
	if err != nil {
		t.Fatal(err)
	}
	held, err := repository.Worktree().ReadIndex()
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.Worktree().Checkout(context.Background(), &GitCheckoutArgs{Tree: tree}, held)
	lock.Abandon()
	if !errors.Is(err, ErrGitWorkspaceFull) {
		t.Fatalf("a checkout past the cap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workspace.HostPath(), "repo", "large.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the file past the cap landed")
	}
	staged, _ := os.ReadDir(filepath.Join(workspace.HostPath(), "repo", ".git", "ur", "tmp"))
	if len(staged) != 0 {
		t.Fatalf("the refused write left %d staged files", len(staged))
	}
	if content, err := os.ReadFile(filepath.Join(workspace.HostPath(), "repo", "small.txt")); err != nil || string(content) != "small\n" {
		t.Fatalf("the refused checkout changed small.txt: %q, %v", content, err)
	}
}
