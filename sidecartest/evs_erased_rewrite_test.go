//go:build !sidecar_http && !ios_extension

// A path written again over a version whose key a committed ERASE destroyed, on a record repo (§11.7's checkpoint rule
// (3), §11.12's retention, versionless and export rows; evs_plan_erased.go, evs_export_file.go,
// evs_export_format2.go): sidecar.EvsClient devices against an evsservice.EvsEngine over FakeHost's stores, on the
// path-epoch world (evs_epoch_world_test.go). The write is a checkpoint under a fresh key in a new slot, keeping the
// erased version's sealed mode; an export renders the erased version and goes on to the new one.

package sidecartest

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A versionless path's versions share one key in one slot until a checkpoint draws another (§11.7's keys row). Once a
// committed ERASE destroys it, the next write draws a fresh key in a new slot, never the destroyed one the path's
// versions shared; the new version reads, and each earlier one reads erased.
func TestEvsVersionlessWriteOverAnErasedVersionDrawsANewSlot(t *testing.T) {
	world := newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
	ctx := world.ctx
	w := world.format2Device("w")
	path := "notes/draft.bin"
	if _, err := w.writeSetting(path, versionlessContent("draft 0", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	if _, err := w.writeSetting(path, versionlessContent("draft 1", 2*1024), ""); err != nil {
		t.Fatalf("the overwrite: %v", err)
	}
	before := world.slotKeys()
	keys, err := w.repo.SlotKeysOf(ctx, nil, []string{path})
	if err != nil || len(keys) != 1 {
		t.Fatalf("the path's slot keys: %v, %v", keys, err)
	}
	erasedSlotId := keys[0].SlotId
	if erased, err := w.repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true}); err != nil || erased.Version != 1 {
		t.Fatalf("the ERASE: %+v, %v", erased, err)
	}
	next := versionlessContent("draft 2", 44*1024)
	if _, err := w.writeSetting(path, next, ""); err != nil {
		t.Fatalf("the write over the erased version: %v", err)
	}
	slotIds := epochNewSlots(before, world.slotKeys())
	if len(slotIds) != 1 || slotIds[0] == erasedSlotId {
		t.Fatalf("the write's new slots %v, the erased one %v", slotIds, erasedSlotId)
	}
	if count := world.slotKeyCount(slotIds[0]); count != 1 {
		t.Fatalf("the new slot holds %d keys", count)
	}
	if count := world.slotKeyCount(erasedSlotId); count != 0 {
		t.Fatalf("the erased slot holds %d keys again", count)
	}
	world.requireReads("after the write", path, next)
	reader := world.format2Device("r")
	history, err := reader.repo.History(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
	if err != nil || len(history.Versions) != 3 {
		t.Fatalf("the history: %+v, %v", history, err)
	}
	if newest := history.Versions[0]; len(newest.SlotIds) != 1 || newest.SlotIds[0] != slotIds[0] {
		t.Fatalf("the newest version's slots %v, the new slot %v", newest.SlotIds, slotIds[0])
	}
	for _, version := range history.Versions[1:] {
		if len(version.SlotIds) != 1 || version.SlotIds[0] != erasedSlotId {
			t.Fatalf("version %d's slots %v, the erased one %v", version.Version, version.SlotIds, erasedSlotId)
		}
		if _, err := reader.repo.ReadVersion(ctx, &sidecar.EvsReadArgs{Path: path, Version: version.Version, Fresh: true}, io.Discard); !errors.Is(err, sidecar.ErrEvsErased) {
			t.Fatalf("version %d after the write: %v", version.Version, err)
		}
	}
}

// A path written again over a version a committed ERASE destroyed, its mode left to the erased version's sealed fields,
// exports both versions, git fsck clean: the erased one as its stub in format 1 and as a kept version in format 2, a
// replaced versionless one as its git-lfs pointer, noted, which reads no content whatever its key
// (evs_export_format2.go's erased row), and the newest as its content, each under the erased version's mode.
func TestEvsFileExportOfAPathWrittenAgainOverAnErasure(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git required to verify the exported repository")
	}
	for _, form := range []string{"format 1", "format 2 kept", "format 2 versionless"} {
		var world *epochWorld
		var writer, reader *epochDevice
		versioning := ""
		switch form {
		case "format 1":
			world = newEpochWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
			writer, reader = world.device("w", nil), world.device("r", nil)
		case "format 2 kept":
			world = newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
			writer, reader = world.format2Device("w"), world.format2Device("r")
			versioning = sidecar.EvsVersioningOn
		default:
			world = newVersionlessWorldOf(t, protocol.RepoKind_REPO_KIND_RECORD)
			writer, reader = world.format2Device("w"), world.format2Device("r")
			versioning = sidecar.EvsVersioningOff
		}
		ctx := world.ctx
		path := "notes/draft"
		first := []byte("the first draft")
		second := []byte("the second draft, over the erased first")
		if _, err := writer.repo.Write(ctx, &sidecar.EvsWriteArgs{Path: path, Content: bytes.NewReader(first), Size: int64(len(first)), Mode: sidecar.EvsGitModeExecutable, Versioning: versioning}); err != nil {
			t.Fatalf("%s: the first write: %v", form, err)
		}
		history, err := reader.repo.History(ctx, &sidecar.EvsReadArgs{Path: path, Fresh: true})
		if err != nil || len(history.Versions) != 1 {
			t.Fatalf("%s: history: %+v, %v", form, history, err)
		}
		entry := history.Versions[0]
		keys, err := writer.repo.SlotKeysOf(ctx, nil, []string{path})
		if err != nil || len(keys) != 1 {
			t.Fatalf("%s: slot keys: %+v, %v", form, keys, err)
		}
		if erased, err := writer.repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true}); err != nil || erased.Version != 1 || world.slotKeyCount(keys[0].SlotId) != 0 {
			t.Fatalf("%s: erasure: %+v, %v", form, erased, err)
		}
		// no mode and no versioning: both come from the erased version, its sealed fields and its entry
		if _, err := writer.repo.Write(ctx, &sidecar.EvsWriteArgs{Path: path, Content: bytes.NewReader(second), Size: int64(len(second))}); err != nil {
			t.Fatalf("%s: the write over the erased version: %v", form, err)
		}
		dir := filepath.Join(t.TempDir(), "export.git")
		result, err := reader.repo.Export(ctx, &sidecar.EvsExportArgs{Dir: dir})
		if err != nil || len(result.Refs) != 1 || result.Refs[0].Versions != 2 || len(result.Refs[0].Refused) != 0 {
			t.Fatalf("%s: export: %+v, %v", form, result, err)
		}
		gitAt := func(args ...string) string {
			t.Helper()
			out, err := exec.CommandContext(ctx, git, append([]string{"--git-dir", dir}, args...)...).CombinedOutput()
			if err != nil {
				t.Fatalf("%s: git %v: %s, %v", form, args, out, err)
			}
			return string(out)
		}
		gitAt("fsck", "--strict", "--no-dangling")
		want := fmt.Sprintf("ur-erased %x %x\n", writer.tokenPath(path, max(1, entry.Epoch)).Bytes(), entry.EntrySha256)
		if form == "format 2 versionless" {
			sum := sha256.Sum256(first)
			want = string(sidecar.EvsLfsPointerText(sum[:], uint64(len(first))))
			if note := gitAt("notes", "--ref=ur", "show", "main~1"); !strings.Contains(note, "lfs-pointer ") {
				t.Fatalf("%s: the erased version's commit's note: %q", form, note)
			}
		}
		if got := gitAt("show", "main~1:"+path); got != want {
			t.Fatalf("%s: the erased version %q, want %q", form, got, want)
		}
		if got := gitAt("show", "main:"+path); got != string(second) {
			t.Fatalf("%s: the version over it %q", form, got)
		}
		for _, commit := range []string{"main~1", "main"} {
			if got := gitAt("ls-tree", "--format=%(objectmode)", commit, path); got != "100755\n" {
				t.Fatalf("%s: %s's mode %q", form, commit, got)
			}
		}
	}
}
