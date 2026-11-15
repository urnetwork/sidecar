//go:build !ios_extension

package sidecar

// SEARCH-M10-13: the in-ref writer on the real push builder. Its hook adds the writer's head to a content write's plan,
// versioning 2 and staged, naming the head's index_epoch and the push's one signed time, so one head CAS commits content
// and index (§22.5's "entries ride the content push on file-mode refs"); it writes nothing outside the format2 gate, in
// a config repo or with the index off; a replaced version with fewer chunks leaves tombstones for the dropped ones; the
// sender plans a push again on an index 409 or INDEX_EPOCH and gives a content 409 back; and the store over EvsRepo
// maps evs's refusals to the index's.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// An in-ref writer on the test writer's client, its view read from fake, admins counted by admins.
func testIndexWriterOn(t *testing.T, writer *evsTestWriter, fake *testIndexRef, admins ...Id) *IndexWriter {
	t.Helper()
	indexWriter, err := newIndexWriter(&indexWriterArgs{
		client: writer.test.client,
		store: func(repo *EvsRepo, refName []byte) indexRefStore {
			return &testIndexHeadStore{indexRefStore: fake.store(evsTestId("reader"))}
		},
		isAdmin: func(repoId Id) func(file *indexFileVersion) bool {
			return func(file *indexFileVersion) bool {
				for _, admin := range admins {
					if file.signerSidecarId == admin {
						return true
					}
				}
				return false
			}
		},
		settings: DefaultIndexFormatSettings(),
		clock:    writer.test.clock,
		log:      NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(indexWriter.Install())
	return indexWriter
}

// A fake index read at its head whatever ref version is asked: the content ref's versions, which the test writer's
// world numbers, are not the fake's.
type testIndexHeadStore struct {
	indexRefStore
}

func (self *testIndexHeadStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	return self.indexRefStore.List(ctx, 0)
}

func (self *testIndexHeadStore) History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error) {
	return self.indexRefStore.History(ctx, path, 0)
}

// The planned paths under .ur-index/, by path.
func testIndexPlanned(plan *EvsWritePlan) map[string]*EvsPlannedPath {
	planned := map[string]*EvsPlannedPath{}
	for _, path := range plan.Paths {
		if strings.HasPrefix(path.Path, indexFileModePrefix) && path.Kind == protocol.EvsEntryKind_EVS_ENTRY_FILE {
			planned[path.Path] = path
		}
	}
	return planned
}

// The slot an index write of plan carries, decoded from its content.
func testIndexWrittenSlot(t *testing.T, plan *EvsWritePlan, path string) *indexSlot {
	t.Helper()
	write := plan.writeOf(path)
	if write == nil || write.Content == nil {
		t.Fatalf("no index write at the slot")
	}
	content := make([]byte, write.Content.Size())
	if _, err := write.Content.ReadAt(content, 0); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	slot, err := indexDecodeSlot(content, sum[:], false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	return slot
}

// §22.5's in-ref row at the plan: a text file's write plans the writer's head beside it, versioning 2, staged, held
// to a creation, its one full entry the file's document at the version the plan writes; the plan names the head's
// index_epoch and the push's signed time, which the entry's time is.
func TestIndexWriterAddsItsHeadToTheContentPlan(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.test.client.SetFormat2Source(func() bool { return true })
	testIndexWriterOn(t, writer, testNewIndexRef())
	content := []byte("a note about the harbor lights and the evening ferry schedule\n")
	plan := writer.plan(t, false, &EvsPathWrite{Path: "notes/harbor.txt", Content: bytes.NewReader(content)})
	if !plan.indexHooked || plan.SignedTimeMs == 0 || plan.IndexEpoch != 0 {
		t.Fatalf("hooked %v, time %d, epoch %d", plan.indexHooked, plan.SignedTimeMs, plan.IndexEpoch)
	}
	planned := testIndexPlanned(plan)
	if len(planned) != 1 {
		t.Fatalf("%d index files planned", len(planned))
	}
	var contentPath *EvsPlannedPath
	for _, path := range plan.Paths {
		if path.Path == "notes/harbor.txt" {
			contentPath = path
		}
	}
	for path, indexPlanned := range planned {
		if indexPlanned.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX) || len(indexPlanned.Chain) != 1 || !indexPlanned.Chain[0].Staged {
			t.Fatalf("the head is not a staged versioning-2 file: %+v", indexPlanned)
		}
		slot := testIndexWrittenSlot(t, plan, path)
		if len(slot.entries) != 1 {
			t.Fatalf("%d entries in the head", len(slot.entries))
		}
		entry := slot.entries[0]
		repoKey, _ := writer.gkm.EnsureWritable(context.Background(), writer.world.repoId)
		refKey, _ := indexRefKey(repoKey)
		key, _ := indexDocKey(refKey, plan.RefId, []byte("notes/harbor.txt"), 0)
		if entry.kind != indexEntryFull || entry.key != key || entry.version != contentPath.Version ||
			entry.timeSeconds != indexEntrySeconds(plan.SignedTimeMs) {
			t.Fatalf("the head's entry: %+v", entry)
		}
	}
}

// What the writer leaves out: outside the format2 gate, with the index off by an admin's settings, and a binary
// creation, the plan carries no index file, and the write is planned as it would be.
func TestIndexWriterWritesNothingWhereTheIndexDoesNot(t *testing.T) {
	ungated := newEvsTestWriter(t)
	testIndexWriterOn(t, ungated, testNewIndexRef())
	plan := ungated.plan(t, false, &EvsPathWrite{Path: "notes/a.txt", Content: bytes.NewReader([]byte("plain words here\n"))})
	if plan.indexHooked || len(testIndexPlanned(plan)) != 0 {
		t.Fatal("a write outside the format2 gate carried the index")
	}

	off := newEvsTestWriter(t)
	off.test.client.SetFormat2Source(func() bool { return true })
	fake := testNewIndexRef()
	admin := evsTestId("admin")
	settingsFile, err := indexEncodeSettings(&protocol.IndexSettings{Off: true})
	if err != nil {
		t.Fatal(err)
	}
	fake.store(admin).testCommit(t, testDayTime(20341, 0), &indexPushFile{path: indexNewPaths(false, indexRootNumber).settings(), plaintext: settingsFile})
	testIndexWriterOn(t, off, fake, admin)
	plan = off.plan(t, false, &EvsPathWrite{Path: "notes/a.txt", Content: bytes.NewReader([]byte("plain words here\n"))})
	if len(testIndexPlanned(plan)) != 0 {
		t.Fatal("a write into an index an admin turned off carried the index")
	}

	binary := newEvsTestWriter(t)
	binary.test.client.SetFormat2Source(func() bool { return true })
	testIndexWriterOn(t, binary, testNewIndexRef())
	plan = binary.plan(t, false, &EvsPathWrite{Path: "image.bin", Content: bytes.NewReader([]byte{0, 1, 2, 0, 0, 0, 3})})
	if len(testIndexPlanned(plan)) != 0 {
		t.Fatal("a binary creation carried an index entry")
	}
}

// 1.2.3's choose on a replaced version: a removal of an indexed text writes its document's tombstone at the removal's
// version, read from the replaced version's text.
func TestIndexWriterRemovalWritesItsTombstone(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "notes/gone.txt", []byte("words that will be removed soon\n")); err != nil {
		t.Fatal(err)
	}
	writer.test.client.SetFormat2Source(func() bool { return true })
	testIndexWriterOn(t, writer, testNewIndexRef())
	plan := writer.plan(t, false, &EvsPathWrite{Path: "notes/gone.txt", Remove: true})
	planned := testIndexPlanned(plan)
	if len(planned) != 1 {
		t.Fatalf("%d index files for a removal", len(planned))
	}
	var removal *EvsPlannedPath
	for _, path := range plan.Paths {
		if path.Path == "notes/gone.txt" {
			removal = path
		}
	}
	for path := range planned {
		slot := testIndexWrittenSlot(t, plan, path)
		if len(slot.entries) != 1 || slot.entries[0].kind != indexEntryTombstone || slot.entries[0].version != removal.BaseEntryVersion+1 {
			t.Fatalf("the removal's entries: %+v", slot.entries)
		}
	}
}

// §11.14's conflict and epoch rows at the sender: a push the hook added files to is planned again on 409
// INDEX_EPOCH, on a 409 naming only its index files and on an index file that moved before the plan read it; a 409
// naming a content path, and any 409 of a push with no hooked file, goes back to the caller.
func TestIndexConflictPlansAgainOnlyForTheIndex(t *testing.T) {
	indexPath := indexFileModePrefix + "i1/b/20340/w/aa/" + strings.Repeat("aa", 16) + "/0"
	indexToken := EvsTokenPath{EvsToken{1}}
	contentToken := EvsTokenPath{EvsToken{2}}
	plan := &EvsWritePlan{
		indexHooked: true,
		writes: map[string]*EvsPathWrite{
			"notes/a.txt": {Path: "notes/a.txt"},
			indexPath:     {Path: indexPath, Options: &EvsWriteOptions{Reserved: EvsReservedIndex}},
		},
		Paths: []*EvsPlannedPath{{Path: "notes/a.txt", TokenPath: contentToken}, {Path: indexPath, TokenPath: indexToken}},
	}
	conflict := func(paths ...EvsTokenPath) error {
		return &EvsError{Status: http.StatusConflict, Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, Paths: paths}
	}
	epoch := &EvsError{Status: http.StatusConflict, Code: protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH}
	cases := []struct {
		name    string
		err     error
		plan    *EvsWritePlan
		rebuild bool
	}{
		{name: "index epoch", err: epoch, plan: plan, rebuild: true},
		{name: "the head alone", err: conflict(indexToken), plan: plan, rebuild: true},
		{name: "a content path", err: conflict(contentToken), plan: plan, rebuild: false},
		{name: "both", err: conflict(indexToken, contentToken), plan: plan, rebuild: false},
		{name: "a parent's delta alone", err: conflict(), plan: plan, rebuild: false},
		{name: "moved before the plan read it", err: errEvsIndexMoved, plan: nil, rebuild: true},
		{name: "no hooked file", err: epoch, plan: &EvsWritePlan{}, rebuild: false},
	}
	for _, c := range cases {
		if got := evsIndexRebuilds(c.err, c.plan); got != c.rebuild {
			t.Errorf("%s: rebuild %v", c.name, got)
		}
	}
}

// The store over EvsRepo's refusals: a path conflict names its paths, INDEX_EPOCH, a 429 waits, a quota, and
// anything else as it is.
func TestIndexRefusalOfEvs(t *testing.T) {
	cases := []struct {
		err  error
		kind indexRefusalKind
	}{
		{err: &EvsPathConflictError{Refusal: &EvsError{Status: http.StatusConflict}, Paths: []string{"x"}}, kind: indexRefusalConflict},
		{err: &EvsError{Status: http.StatusConflict, Code: protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH}, kind: indexRefusalIndexEpoch},
		{err: &EvsError{Status: http.StatusTooManyRequests}, kind: indexRefusalRetry},
		{err: &EvsError{Status: http.StatusPaymentRequired, Code: protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT}, kind: indexRefusalQuota},
		{err: errEvsIndexMoved, kind: indexRefusalConflict},
	}
	for _, c := range cases {
		refusal, ok := indexRefusalOf(indexRefusalOfEvs(c.err))
		if !ok || refusal.kind != c.kind {
			t.Errorf("%v: %v", c.err, refusal)
		}
	}
	other := errors.New("other")
	if indexRefusalOfEvs(other) != other {
		t.Error("an error evs did not answer was changed")
	}
}

// A CLOSURE's content push carries no in-ref entry: its flags reach the hook from the plan's arguments, before the
// sender sets them on the plan (1.2.3: a CLOSURE rewrites no head it has no other reason to touch).
func TestIndexWriterLeavesAClosureAlone(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.test.client.SetFormat2Source(func() bool { return true })
	testIndexWriterOn(t, writer, testNewIndexRef())
	ctx := context.Background()
	writer.server.know("notes/a.txt")
	refId, err := writer.repo.resolveRefId(ctx, EvsMainRefName, nil)
	if err != nil {
		t.Fatal(err)
	}
	repoKey, err := writer.gkm.EnsureWritable(ctx, writer.world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := writer.repo.PlanWrite(ctx, &EvsPlanArgs{
		RefName: EvsMainRefName, RefId: refId, Generation: repoKey.Generation(),
		Flags:  uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE),
		Writes: []*EvsPathWrite{{Path: "notes/a.txt", Content: bytes.NewReader([]byte("rewritten words\n"))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.indexHooked || len(testIndexPlanned(plan)) != 0 {
		t.Fatal("a CLOSURE carried the writer's head")
	}
}
