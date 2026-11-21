//go:build !js

// QD-1156's export of a git-mode ref one of whose blobs a committed ERASE destroyed (evs_export_erased.go), on the
// stand-in evs (evs_world_test.go): a record repo's main, its secret keyed in a slot of its own as a record-class repo
// keys every chain. The ERASE stands as evs leaves it once committed, the slot rewritten without the key
// (EvsSlotWithoutKeys), and the reader's judge names that key as it does once it reads the committed ERASE
// (evs_read_erased.go), which the stand-in does not serve.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// For the test's length, the judge a read makes once it reads a committed ERASE of keys: the erasure ref's read, which
// the stand-in evs does not serve, stood in for.
func evsTestEraseJudged(t *testing.T, keys ...EvsErasedKey) {
	t.Helper()
	saved := newEvsErasureJudge
	newEvsErasureJudge = func() evsErasureJudge {
		erased := &evsErasedKeys{read: true, keys: map[EvsErasedKey]bool{}, slots: map[Id]bool{}}
		for _, key := range keys {
			erased.keys[key] = true
			erased.slots[key.SlotId] = true
		}
		return erased
	}
	t.Cleanup(func() { newEvsErasureJudge = saved })
}

// The slot as evs leaves it once an ERASE of its key at index 0 commits (§11.12's push row): rewritten without it.
func (self *evsTestWorld) eraseSlotKey(t *testing.T, slotId Id) {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rewritten, removedCount, err := EvsSlotWithoutKeys(self.slots[string(slotId.Bytes())], []uint32{0})
	if err != nil || removedCount != 1 {
		t.Fatalf("the slot's rewrite: %d keys removed, %v", removedCount, err)
	}
	self.slots[string(slotId.Bytes())] = rewritten
}

// The entry hash the push at version gave path's change.
func (self *evsTestWorld) entrySha256Of(t *testing.T, version uint64, path string) []byte {
	t.Helper()
	self.stateLock.Lock()
	built := self.commits[version-1].built
	self.stateLock.Unlock()
	checked, err := EvsCheckPayload(built.Statement, built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range checked.Changes {
		if bytes.Equal(change.TokenPath.Bytes(), self.tokens(path).Bytes()) {
			return change.Change.GetEntrySha256()
		}
	}
	t.Fatalf("no change of %s at version %d", path, version)
	return nil
}

// A record repo's main: c0 holds README; c1 adds secret.txt, keyed in a slot of its own; c2 adds notes.txt with the
// secret standing; refs/tags/v1 is an annotated tag of c2; c3 removes the secret. Before any ERASE every oid exports as
// the original's. Once a committed ERASE destroys the secret's key, export writes it as its erased stub in each commit
// holding it, rewrites c1 and c2 over it, c3 over its rewritten parent though its own tree keeps its oid, and the tag
// over c2, git fsck clean: c0 keeps its oid, every other byte of a rewritten object is its own, each rewritten commit's
// note names its original and c1's push's note the stub, no originals are left beside the export, and two exporters
// write one history.
func TestEvsExportStubsAGitModeBlobAnEraseDestroyedAndRewritesWhatHoldsIt(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no system git")
	}
	world := newEvsTestWorld(t)
	world.config.repo.Kind = protocol.RepoKind_REPO_KIND_RECORD
	email := evsTestId("world client").String() + evsCommitterDomain
	history := &evsTestGitHistory{t: t, store: newEvsTestGitStore(), email: email}
	readme := history.blob("hello\n")
	c0, sealed0 := history.commit(history.tree(map[string]EvsGitOid{"README": readme}, nil), email)
	world.pushGitUpdate(&evsTestGitUpdate{
		refName: EvsMainRefName, newTip: &c0, commits: []*protocol.EvsSealedCommit{sealed0},
		changes: []*evsTestChange{{path: "README", content: []byte("hello\n")}},
	})
	secretSlot := NewEvsSlotId()
	secret := history.blob("a secret\n")
	c1, sealed1 := history.commit(history.tree(map[string]EvsGitOid{"README": readme, "secret.txt": secret}, nil), email, c0)
	secretVersion := world.pushGitUpdate(&evsTestGitUpdate{
		oldTip: &c0, newTip: &c1, commits: []*protocol.EvsSealedCommit{sealed1},
		changes: []*evsTestChange{{path: "secret.txt", content: []byte("a secret\n"), slotId: &secretSlot}},
	})
	c2, sealed2 := history.commit(history.tree(map[string]EvsGitOid{"README": readme, "secret.txt": secret, "notes.txt": history.blob("notes\n")}, nil), email, c1)
	mainAtC2 := world.pushGitUpdate(&evsTestGitUpdate{
		oldTip: &c1, newTip: &c2, commits: []*protocol.EvsSealedCommit{sealed2},
		changes: []*evsTestChange{{path: "notes.txt", content: []byte("notes\n")}},
	})
	tagRef := world.otherRef([]byte("refs/tags/v1"))
	tag := evsTestTag(c2, evsGitCommitKind, "v1")
	tagOid, _ := history.store.WriteGitObject(evsGitTagKind, tag)
	tagRef.pushGitUpdate(&evsTestGitUpdate{
		refName: []byte("refs/tags/v1"), flags: uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE), newTip: &tagOid,
		tags: [][]byte{tag}, sources: []*protocol.EvsOverlay{{RefId: world.refId.Bytes(), Version: mainAtC2}},
	})
	c3Tree := history.tree(map[string]EvsGitOid{"README": readme, "notes.txt": history.blob("notes\n")}, nil)
	c3, sealed3 := history.commit(c3Tree, email, c2)
	world.pushGitUpdate(&evsTestGitUpdate{
		oldTip: &c2, newTip: &c3, commits: []*protocol.EvsSealedCommit{sealed3},
		changes: []*evsTestChange{{path: "secret.txt"}},
	})

	export := func(label string) (string, *EvsExportResult) {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "export.git")
		reader := world.reader(t, evsTestId("exporter "+label))
		result, err := reader.client.Repo(world.repoId).Export(context.Background(), &EvsExportArgs{Dir: dir, RefNames: [][]byte{EvsMainRefName, []byte("refs/tags/v1")}})
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
			t.Fatalf("%s: alarms %v", label, alarms)
		}
		if len(result.Refs) != 2 || len(result.Refs[0].Refused) != 0 || len(result.Refs[1].Refused) != 0 {
			t.Fatalf("%s: exported %+v", label, result.Refs)
		}
		evsTestGit(t, dir, "fsck", "--strict", "--no-dangling")
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(dir), ".ur-export-originals-*")); len(left) != 0 {
			t.Fatalf("%s: originals left beside the export: %v", label, left)
		}
		return dir, result
	}
	if _, before := export("before"); before.Refs[0].Tip != c3 || before.Refs[0].Rewritten != 0 || before.Refs[1].Tip != tagOid {
		t.Fatalf("before the ERASE: %+v, %+v", before.Refs[0], before.Refs[1])
	}

	world.eraseSlotKey(t, secretSlot)
	evsTestEraseJudged(t, EvsErasedKey{SlotId: secretSlot, KeyIndex: 0})
	dir, result := export("one")
	_, again := export("two")
	mainTip, tagTip := result.Refs[0].Tip, result.Refs[1].Tip
	if mainTip == c3 || tagTip == tagOid || result.Refs[0].Rewritten != 3 || again.Refs[0].Tip != mainTip || again.Refs[1].Tip != tagTip {
		t.Fatalf("after the ERASE: %+v, %+v; again %+v, %+v", result.Refs[0], result.Refs[1], again.Refs[0], again.Refs[1])
	}
	oidHex := func(oid EvsGitOid) string { return hex.EncodeToString(oid[:]) }
	// c3 rewritten over its parent alone, its tree its own; c0, before the secret, its own oid
	if got := strings.TrimSpace(evsTestGit(t, dir, "rev-parse", "main", "main^{tree}", "main~3")); got != oidHex(mainTip)+"\n"+oidHex(c3Tree)+"\n"+oidHex(c0) {
		t.Fatalf("main, its tree and the commit before the secret: %q", got)
	}
	if got := evsTestGit(t, dir, "ls-tree", "--name-only", "main"); got != "README\nnotes.txt\n" {
		t.Fatalf("c3's files %q", got)
	}
	tokenHex := hex.EncodeToString(world.tokens("secret.txt").Bytes())
	entryHex := hex.EncodeToString(world.entrySha256Of(t, secretVersion, "secret.txt"))
	stub := fmt.Sprintf("ur-erased %s %s\n", tokenHex, entryHex)
	for _, commit := range []string{"main~1", "main~2"} {
		if got := evsTestGit(t, dir, "show", commit+":secret.txt"); got != stub {
			t.Fatalf("%s's secret.txt %q, want %q", commit, got, stub)
		}
		if got := evsTestGit(t, dir, "show", commit+":README"); got != "hello\n" {
			t.Fatalf("%s's README %q", commit, got)
		}
	}
	if got := evsTestGit(t, dir, "show", "main~1:notes.txt"); got != "notes\n" {
		t.Fatalf("notes.txt %q", got)
	}
	// every byte of c2 but its tree and parent lines, and of the tag but its object line
	afterHeaders := func(object string, from string) string {
		at := strings.Index(object, from)
		if at < 0 {
			t.Fatalf("%q in %q", from, object)
		}
		return object[at:]
	}
	if got := evsTestGit(t, dir, "cat-file", "commit", "main~1"); afterHeaders(got, "\nauthor ") != afterHeaders(string(sealed2.GetObject()), "\nauthor ") ||
		!strings.Contains(got, "parent "+strings.TrimSpace(evsTestGit(t, dir, "rev-parse", "main~2"))+"\n") {
		t.Fatalf("the rewritten c2:\n%s", got)
	}
	if got := evsTestGit(t, dir, "cat-file", "tag", "refs/tags/v1"); got != "object "+strings.TrimSpace(evsTestGit(t, dir, "rev-parse", "main~1"))+"\n"+afterHeaders(string(tag), "type ") {
		t.Fatalf("the rewritten tag:\n%s", got)
	}
	for commit, lines := range map[string][]string{
		"main":   {"rewritten " + oidHex(c3)},
		"main~1": {"rewritten " + oidHex(c2)},
		"main~2": {"rewritten " + oidHex(c1), "erased " + tokenHex + " " + entryHex},
	} {
		note := evsTestGit(t, dir, "notes", "--ref=ur", "show", commit)
		for _, line := range lines {
			if !strings.Contains(note, "\n"+line+"\n") {
				t.Fatalf("%s's note lacks %q:\n%s", commit, line, note)
			}
		}
	}
	if note := evsTestGit(t, dir, "notes", "--ref=ur", "show", "main~3"); strings.Contains(note, "rewritten ") || strings.Contains(note, "erased ") {
		t.Fatalf("c0's note:\n%s", note)
	}
}
