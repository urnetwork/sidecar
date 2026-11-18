//go:build !js

// Export in format 2 (EVS2-M10-19; FS-89's export clause, plan-EVS2-small-readings#7, against the stand-in evs at
// format 2): a replaced versionless version exports as the git-lfs pointer to its content, byte-exact by git-lfs's
// spec, and the path's newest version its content; each version an executed drop lists exports as its stub, byte-exact,
// and the kept head its content; a pending drop's versions export their content; refs/notes/ur names each pointer and
// stub; git fsck takes the export; and two exporters give equal oids.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// One path's entry hash at each of its versions, as the stand-in committed them.
func evsTestEntryHashes(world *evsTestWorld, path string) map[uint64][]byte {
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	hashes := map[uint64][]byte{}
	for version, held := range world.paths[path].versions {
		if held.entryBytes != nil {
			sum := sha256.Sum256(held.entryBytes)
			hashes[version] = sum[:]
		}
	}
	return hashes
}

// A versionless file written twice, a file dropped with now, and a file whose drop is pending, exported twice.
func TestEvsExportFormat2PointersAndStubs(t *testing.T) {
	writer, server, _ := newEvsTestDropPusher(t)
	ctx := context.Background()
	versionless := [][]byte{}
	for i := 0; i < 2; i += 1 {
		content := evsTestEdited("big.txt", 2000, i)
		versionless = append(versionless, content)
		writer.server.know("big.txt")
		if _, err := writer.repo.Write(ctx, &EvsWriteArgs{
			Path: "big.txt", Content: bytes.NewReader(content), Size: int64(len(content)), Versioning: EvsVersioningOff,
		}); err != nil {
			t.Fatal(err)
		}
	}
	notesHead := evsTestDropHistory(t, writer, server, "notes.md", 1000, 3)
	preview, err := writer.repo.DropHistoryPreview(ctx, &EvsDropPreviewArgs{Paths: []string{"notes.md"}})
	if err != nil {
		t.Fatal(err)
	}
	dropped, err := writer.repo.DropHistory(ctx, &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "notes.md", Now: true, ConfirmNow: EvsDropConfirmNow})
	if err != nil {
		t.Fatal(err)
	}
	pendingHead := evsTestDropHistory(t, writer, server, "pending.md", 1000, 2)
	preview, err = writer.repo.DropHistoryPreview(ctx, &EvsDropPreviewArgs{Paths: []string{"pending.md"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.repo.DropHistory(ctx, &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "pending.md"}); err != nil {
		t.Fatal(err)
	}
	notesHashes := evsTestEntryHashes(writer.world, "notes.md")
	// a creation takes the ref's base + 1, so the file's first version is 3, and the kept head 6
	notesVersions := []uint64{}
	for version := range notesHashes {
		notesVersions = append(notesVersions, version)
	}
	slices.Sort(notesVersions)
	tips := []EvsGitOid{}
	for _, label := range []string{"one", "two"} {
		reader := writer.world.reader(t, evsTestId("exporter "+label))
		reader.client.args.Gkm = writer.gkm
		reader.client.args.Transport = &evsTestTransport{handler: writer.server}
		reader.client.http.transport = wrapSidecarApiTransport(reader.client.args.Transport)
		reader.client.EnableFormat2Reader()
		dir := filepath.Join(t.TempDir(), "format2.git")
		result, err := reader.client.Repo(writer.world.repoId).Export(ctx, &EvsExportArgs{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Refs) != 1 || result.Refs[0].Versions != 9 {
			t.Fatalf("exported %+v", result.Refs)
		}
		tips = append(tips, result.Refs[0].Tip)
		evsTestGit(t, dir, "fsck", "--strict", "--no-dangling")
		show := func(rev string, path string) string {
			return evsTestGit(t, dir, "show", rev+":"+path)
		}
		first := sha256.Sum256(versionless[0])
		if pointer := show("main~8", "big.txt"); pointer != string(EvsLfsPointerText(first[:], uint64(len(versionless[0])))) {
			t.Fatalf("a replaced versionless version exported %q", pointer)
		}
		// git-lfs's spec v1: a version line naming the spec, then the oid and size lines, each ended by a newline
		pointerLines := strings.Split(show("main~8", "big.txt"), "\n")
		if len(pointerLines) != 4 || !strings.HasPrefix(pointerLines[0], "version https://") || !strings.HasSuffix(pointerLines[0], "/spec/v1") ||
			pointerLines[1] != "oid sha256:"+hex.EncodeToString(first[:]) || pointerLines[2] != fmt.Sprintf("size %d", len(versionless[0])) || pointerLines[3] != "" {
			t.Fatalf("not git-lfs's pointer: %q", pointerLines)
		}
		if content := show("main~7", "big.txt"); content != string(versionless[1]) {
			t.Fatalf("the newest versionless version exported other content")
		}
		for i, rev := range []string{"main~6", "main~5", "main~4"} {
			if stub := show(rev, "notes.md"); stub != string(EvsExportDroppedStub(dropped.Pushes[0].DropId, notesHashes[notesVersions[i]])) {
				t.Fatalf("dropped version %d exported %q", notesVersions[i], stub)
			}
		}
		if content := show("main~3", "notes.md"); content != string(notesHead) {
			t.Fatalf("the kept head exported other content")
		}
		if content := show("main~1", "pending.md"); content != string(pendingHead) {
			t.Fatalf("a pending drop's version exported other content")
		}
		note := evsTestGit(t, dir, "notes", "--ref=ur", "show", "main~8")
		if !strings.Contains(note, "lfs-pointer ") {
			t.Fatalf("the pointer's note %q", note)
		}
		if note := evsTestGit(t, dir, "notes", "--ref=ur", "show", "main~6"); !strings.Contains(note, "dropped ") {
			t.Fatalf("the stub's note %q", note)
		}
	}
	if tips[0] != tips[1] {
		t.Fatalf("two exporters: %s, %s", tips[0], tips[1])
	}
}
