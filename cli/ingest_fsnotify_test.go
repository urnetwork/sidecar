package main

// The daemon's fsnotify watch (MCP-M6-03): a write in the worktree and in a directory made after the watch began are
// reported relative to the root, git's own directory never is, and a worktree past the directory cap is refused.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar/mcp"
)

func TestFsnotifyWatchReportsWorktreeChanges(t *testing.T) {
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	changes := make(chan *mcp.IngestFileChange, 64)
	stop, err := urFsnotifyWatch(root, 16, &mcp.IngestFileWatchSink{
		Change: func(change *mcp.IngestFileChange) { changes <- change },
		Lost:   func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	// the OS reports asynchronously: each wait ends at the change it waits for, bounded only to fail
	await := func(path string) {
		t.Helper()
		for {
			select {
			case change := <-changes:
				if change.Path == ".git" || filepath.Dir(filepath.FromSlash(change.Path)) == ".git" {
					t.Errorf("git's own directory reported: %+v", change)
				}
				if change.Path == path {
					return
				}
			case <-t.Context().Done():
				t.Fatalf("no change of %s reported", path)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "index"), []byte("git's\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	await("a.txt")
	if err := os.MkdirAll(filepath.Join(root, "made"), 0o755); err != nil {
		t.Fatal(err)
	}
	await("made")
	if err := os.WriteFile(filepath.Join(root, "made", "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	await("made/b.txt")

	crowded := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.MkdirAll(filepath.Join(crowded, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := urFsnotifyWatch(crowded, 2, &mcp.IngestFileWatchSink{Change: func(*mcp.IngestFileChange) {}, Lost: func() {}}); err == nil {
		t.Error("a worktree past the directory cap was watched")
	}
}
