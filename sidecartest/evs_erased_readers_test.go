//go:build !sidecar_http && !ios_extension

// Export, index settings and replacement writes after authenticated slot destruction on a record repo.

package sidecartest

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A file export keeps the path, its signed mode and the exact entry hash. A later independent commit still exports.
func TestEvsFileExportRendersCommittedErasures(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git required to verify the exported repository")
	}
	for _, format2 := range []bool{false, true} {
		var world *epochWorld
		var writer, reader *epochDevice
		versioning := ""
		if format2 {
			world = newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
			writer, reader = world.format2Device("w"), world.format2Device("r")
			versioning = sidecar.EvsVersioningOff
		} else {
			world = newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
			writer, reader = world.device("w", nil), world.device("r", nil)
		}
		ctx := world.ctx
		path := "notes/draft"
		content := []byte("the executable draft")
		if _, err := writer.repo.Write(ctx, &sidecar.EvsWriteArgs{Path: path, Content: bytes.NewReader(content), Size: int64(len(content)), Mode: sidecar.EvsGitModeExecutable, Versioning: versioning}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.write("survivor", []byte("another entry")); err != nil {
			t.Fatal(err)
		}
		history, err := reader.repo.History(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
		if err != nil || len(history.Versions) != 1 {
			t.Fatalf("history: %+v, %v", history, err)
		}
		entry := history.Versions[0]
		backupRoot := t.TempDir()
		before := filepath.Join(backupRoot, "before.git")
		if _, err := reader.repo.Export(ctx, &sidecar.EvsExportArgs{Dir: before}); err != nil {
			t.Fatalf("initial backup: %v", err)
		}
		gitAt := func(dir string, args ...string) string {
			t.Helper()
			out, err := exec.CommandContext(ctx, git, append([]string{"--git-dir", dir}, args...)...).CombinedOutput()
			if err != nil {
				t.Fatalf("git %v: %s, %v", args, out, err)
			}
			return string(out)
		}
		originalHead := gitAt(before, "rev-parse", "main")
		keys, err := writer.repo.SlotKeysOf(ctx, nil, []string{path})
		if err != nil || len(keys) != 1 {
			t.Fatalf("slot keys: %+v, %v", keys, err)
		}
		if erased, err := writer.repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true}); err != nil || erased.Version != 1 || world.slotKeyCount(keys[0].SlotId) != 0 {
			t.Fatalf("erasure: %+v, %v", erased, err)
		}
		dir := filepath.Join(backupRoot, "after.git")
		result, err := reader.repo.Export(ctx, &sidecar.EvsExportArgs{Dir: dir})
		if err != nil || len(result.Refs) != 1 || result.Refs[0].Versions != 2 {
			t.Fatalf("format2 %t export: %+v, %v", format2, result, err)
		}
		gitAt(dir, "fsck", "--strict", "--no-dangling")
		stub := fmt.Sprintf("ur-erased %x %s\n", writer.tokenPath(path, max(1, entry.Epoch)).Bytes(), hex.EncodeToString(entry.EntrySha256))
		if got := gitAt(dir, "show", "main~1:"+path); got != stub {
			t.Fatalf("format2 %t, stub %q, want %q", format2, got, stub)
		}
		if got := gitAt(dir, "ls-tree", "--format=%(objectmode)", "main", path); got != "100755\n" {
			t.Fatalf("mode %q", got)
		}
		if got := gitAt(dir, "show", "main:survivor"); got != "another entry" {
			t.Fatalf("later commit: %q", got)
		}
		if _, err := reader.repo.Export(ctx, &sidecar.EvsExportArgs{Dir: before}); !errors.Is(err, sidecar.ErrEvsExport) {
			t.Fatalf("existing backup: %v", err)
		}
		if got := gitAt(before, "rev-parse", "main"); got != originalHead {
			t.Fatalf("pre-erasure backup head moved: %q", got)
		}
	}
}
