//go:build !sidecar_http && !ios_extension

// RECORD-M10-01's record erasure on format 2 (§16.8's Erasure; §11.12's closure, cut and reconcile rows; RECORD.md
// section 8; DESIGN-DETAILS 15.2.10, 15.6's RECORD-M10-01 rows; R-MCP-8, D-EVS-26, FI-19, FS-80, FS-111), on
// sidecartest's record streams and authorization state, the log's ur/index on the index's fake with its real eraser
// (record_erase_index_export_test.go): the ERASEs of steps 2 and 3 committing before the CUT is built, a copy found at
// the second read among them; the CUT listing each copy's document and each stream's card through its epoch; an erased
// entry leaving its run card when the card is folded again; the team record's case of FS-111, a stream writer's card
// push built before the CUT refused 409 INDEX_EPOCH and rebuilt without the entry; a restart going on from evs's state
// after a kill before the CUT and another at the rewrite; a late copy erased, listed and its card folded again; an
// erasure with nothing to list completing as in format 1; the context line `ur record erase` shows; and a CUT past its
// bound refused before anything is erased.
//
// Not here: the same on evsservice's engines through NewRecordEvsEraseIndex (RECORD-M10-06's and SEARCH-M10-37's
// schedules, T2 and T3), and FS-80's search-side checks, a reader's results and masks (SEARCH-M10-38's world).

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A kill at a step, as a test injects one.
var errTestEraseIndexKilled = errors.New("the eraser was killed here")

// The eraser's streams as these tests watch them: each committed ERASE told to the index's fake in the order the
// record's evs took it, kept by push id, and a hook after each; and, where a test asks, the next commit's answer lost
// and a retry of its push id answered as evs answers one past its memory of the push id, the keys gone.
type testEraseIndexTap struct {
	sidecar.RecordStreams
	index *sidecar.RecordEraseTestIndex

	stateLock     sync.Mutex
	erases        []*sidecar.RecordStreamErase
	afterErase    func(count int)
	loseAndForget bool
	forgotten     map[sidecar.Id]bool
}

func (self *testEraseIndexTap) Erase(ctx context.Context, repoId sidecar.Id, erase *sidecar.RecordStreamErase) (*sidecar.RecordStreamCommit, error) {
	forgotten := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.forgotten[erase.PushId]
	}()
	if forgotten {
		return nil, &sidecar.RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE, Recorded: true}
	}
	commit, err := self.RecordStreams.Erase(ctx, repoId, erase)
	if err != nil {
		return commit, err
	}
	count, hook, lost := func() (int, func(count int), bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if slices.ContainsFunc(self.erases, func(held *sidecar.RecordStreamErase) bool { return held.PushId == erase.PushId }) {
			// a retry evs answered as the commit it made
			return len(self.erases), nil, false
		}
		self.erases = append(self.erases, erase)
		self.index.NoteStreamErase(erase.ErasureId, erase.Complete)
		lost := self.loseAndForget
		if lost {
			self.loseAndForget = false
			if self.forgotten == nil {
				self.forgotten = map[sidecar.Id]bool{}
			}
			self.forgotten[erase.PushId] = true
		}
		return len(self.erases), self.afterErase, lost
	}()
	if hook != nil {
		hook(count)
	}
	if lost {
		return nil, errTestEraseIndexKilled
	}
	return commit, nil
}

// Loses the next committed ERASE's answer, a retry of it then answered as evs past its memory of the push id.
func (self *testEraseIndexTap) setLoseAndForget() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.loseAndForget = true
}

// The committed ERASEs, by push id, in order.
func (self *testEraseIndexTap) committed() []*sidecar.RecordStreamErase {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.erases)
}

func (self *testEraseIndexTap) setAfterErase(hook func(count int)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.afterErase = hook
}

// Taps device's streams for index, before its record is opened.
func testEraseIndexTapOn(device *testRecordDevice, index *sidecar.RecordEraseTestIndex) *testEraseIndexTap {
	tap := &testEraseIndexTap{RecordStreams: device.tap.RecordStreams, index: index}
	device.tap.RecordStreams = tap
	return tap
}

// device's record, opened, its erasures' index side index's ur/index signing as device.
func testEraseIndexOpen(device *testRecordDevice, index *sidecar.RecordEraseTestIndex) *sidecar.SidecarRecord {
	record := device.open()
	record.SetEraseIndex(index.Open(device.sidecarId))
	return record
}

// A log admin's device of the team record that erases there.
func (self *testTeamWorld) teamEraser() *testRecordDevice {
	self.t.Helper()
	device := self.adminDevice()
	repo := self.fixture.Repos[self.teamRecordId]
	repo.Admins = append(repo.Admins, device.sidecarId)
	self.publish()
	return device
}

// Whether two lists name the same keys in order.
func testEraseIndexSameKeys(a []*sidecar.RecordSlotKey, b []*sidecar.RecordSlotKey) bool {
	return slices.EqualFunc(a, b, func(x *sidecar.RecordSlotKey, y *sidecar.RecordSlotKey) bool { return *x == *y })
}

// Whether every key of a word is among keys: whether a search finds the word there.
func testEraseIndexHolds(keys []uint32, word []uint32) bool {
	for _, key := range word {
		if !slices.Contains(keys, key) {
			return false
		}
	}
	return true
}

// The entries of key above version, failing unless exactly one stands there.
func testEraseIndexOneAbove(t *testing.T, index *sidecar.RecordEraseTestIndex, key [16]byte, version uint64) *sidecar.RecordEraseTestEntry {
	t.Helper()
	above := []*sidecar.RecordEraseTestEntry{}
	for _, entry := range index.Entries(key) {
		if version < entry.Version {
			above = append(above, entry)
		}
	}
	if len(above) != 1 {
		t.Fatalf("%d entries of a card above version %d", len(above), version)
	}
	return above[0]
}

// The entry ref of refs in logId.
func testEraseIndexRefIn(t *testing.T, refs []*sidecar.RecordEntryRef, logId sidecar.Id) *sidecar.RecordEntryRef {
	t.Helper()
	for _, ref := range refs {
		if ref.LogId == logId {
			return ref
		}
	}
	t.Fatalf("no entry in %s", logId)
	return nil
}

// A vault run's entries, as a consented device files them: a context naming its project, and a change touching path.
func testEraseVaultRunDrafts(runId *sidecar.Id, path string) []*sidecar.RecordDraft {
	repoId := sidecar.NewId()
	sha := bytes.Repeat([]byte{0x5a}, 32)
	return []*sidecar.RecordDraft{
		{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceHook, RunId: runId, Body: &protocol.ContextBody{
			Stage: 1, Harness: "claude-code", HarnessVersion: "2.0.1", AgentLabel: "builder", RepoId: repoId.Bytes(),
			Project: "acme-frobnicator", Branch: "rotate-keys", Title: "Rotate the keys",
		}},
		{Kind: sidecar.RecordKindChange, Source: sidecar.RecordSourceObserved, RunId: runId, Body: &protocol.ChangeBody{
			RepoId: repoId.Bytes(), Project: "acme-frobnicator", PathCount: 1, EditCount: 1, Capture: 1,
			Paths: []*protocol.ChangedPath{{Path: path, BeforeSha256: sha, AfterSha256: sha, Attribution: 1}},
		}},
	}
}

// A team run's entries, as a member's device files them: a context, and a change naming commit.
func testEraseTeamRunDrafts(runId *sidecar.Id, commit string) []*sidecar.RecordDraft {
	repoId := sidecar.NewId()
	return []*sidecar.RecordDraft{
		{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceHook, RunId: runId, Body: &protocol.ContextBody{
			Stage: 1, Harness: "claude-code", HarnessVersion: "2.0.1", AgentLabel: "builder", RepoId: repoId.Bytes(),
		}},
		{Kind: sidecar.RecordKindChange, Source: sidecar.RecordSourceObserved, RunId: runId, Body: &protocol.ChangeBody{
			RepoId: repoId.Bytes(), Commits: []string{commit}, Capture: 1,
		}},
	}
}

// Ingests the log once and lands what it wrote.
func testEraseIngest(t *testing.T, record *sidecar.SidecarRecord, logId sidecar.Id, flush bool) {
	t.Helper()
	if err := record.Ingester().Ingest(t.Context(), logId); err != nil {
		t.Fatal(err)
	}
	if flush {
		if err := record.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

// DESIGN-DETAILS 15.6's TestRecordEraseOrder: a vault entry and its run's context, each with a copy in two ingesters'
// streams, the second stream's copies landing only after the first ERASE: the ERASE of step 2 and the ERASE of step 3,
// which takes the copies found at the second read, both commit before the CUT is built and neither says complete; the
// CUT lists the note's document in each stream at its path's entry version and the run's card in each stream through
// the epoch it names, and steps 5 and 6 follow it; the index holding none of them, a completion ERASE naming the first
// ERASE's keys ends the erasure (QD-1132).
func TestRecordEraseOrder(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, _ := world.eraserDevice()
	other := world.device(true)
	depositor := world.device(false)
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_VAULT, eraser.sidecarId)
	tap := testEraseIndexTapOn(eraser, index)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	depositorRecord := depositor.open()
	contextRef := testRecordAppend(t, depositorRecord, testEraseVaultRunDrafts(&runId, "internal/widget.go")[0])
	note := testRecordAppend(t, depositorRecord, testRecordNote(&runId, "the rotation plan"))
	if err := depositorRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	eraserRecord := testEraseIndexOpen(eraser, index)
	otherRecord := other.open()
	// the other ingester's copies wait in its writer until the eraser's first ERASE commits
	testEraseIngest(t, otherRecord, world.vaultId, false)
	testEraseIngest(t, eraserRecord, world.vaultId, true)
	testEraseIngest(t, eraserRecord, world.vaultId, false)
	tap.setAfterErase(func(count int) {
		if count == 1 {
			if err := otherRecord.Flush(ctx); err != nil {
				t.Error(err)
			}
		}
	})
	erasesAtCut := -1
	index.OnCall(func(method string) {
		if method == "cut" && erasesAtCut < 0 {
			erasesAtCut = len(tap.committed())
		}
	})
	result, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: []sidecar.Id{contextRef.EntryId, note.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	erases := tap.committed()
	if len(erases) != 3 || erasesAtCut != 2 {
		t.Fatalf("%d ERASEs, %d of them before the CUT", len(erases), erasesAtCut)
	}
	for _, erase := range erases[:2] {
		if erase.Complete || erase.ErasureId != result.ErasureId {
			t.Fatalf("an ERASE before the CUT said complete, or named another erasure: %+v", erase)
		}
	}
	if completion := erases[2]; !completion.Complete || completion.ErasureId != result.ErasureId || !testEraseIndexSameKeys(completion.Keys, erases[0].Keys) {
		t.Fatalf("the completion ERASE: %+v", completion)
	}
	if _, complete := index.Erases(result.ErasureId); !complete || !result.Index.Completed {
		t.Fatal("the erasure did not end")
	}
	if calls := index.Calls(); !slices.Equal(calls, []string{"cut", "reenter", "rewrite"}) {
		t.Fatalf("the index was called %v", calls)
	}
	if result.Index == nil || !result.Index.Fenced || result.Index.DocumentCount != 4 || result.Index.CardCount != 2 {
		t.Fatalf("the index's part: %+v", result.Index)
	}
	entry, ok := eraserRecord.Reader().Entry(world.vaultId, note.EntryId)
	if !ok || len(entry.Copies) != 2 {
		t.Fatal("the note does not stand in two streams")
	}
	streamIds := []sidecar.Id{}
	for _, entryCopy := range entry.Copies {
		streamIds = append(streamIds, entryCopy.StreamSidecarId)
	}
	if !slices.Contains(streamIds, other.sidecarId) || !slices.Contains(streamIds, eraser.sidecarId) {
		t.Fatalf("the note's copies stand in %v", streamIds)
	}
	listed := index.ErasureDocs(result.ErasureId)
	if len(listed) != 4 {
		t.Fatalf("the CUT lists %d documents", len(listed))
	}
	for _, entryCopy := range entry.Copies {
		refId := sidecartest.FakeRecordStreamRefId(world.vaultId, entryCopy.StreamSidecarId)
		if version, ok := listed[index.DocKey(refId, []byte(entryCopy.Path))]; !ok || version != entryCopy.Version {
			t.Errorf("the note's copy in %s is listed at %d, its entry version %d", entryCopy.StreamSidecarId, version, entryCopy.Version)
		}
		// the first CUT on the ref names epoch 0: every version of it
		if version, ok := listed[index.CardKey(refId, runId)]; !ok || version != 1<<32-1 {
			t.Errorf("the card of %s is listed through %d", entryCopy.StreamSidecarId, version)
		}
	}
	if len(result.Erased) != 2 || len(result.Missing) != 0 || result.Entry == nil {
		t.Fatalf("erased %v, missing %v, the entry %v", result.Erased, result.Missing, result.Entry)
	}
	index.Sweep()
}

// "An erased entry leaving its run card at the next re-projection" (RECORD-M10-01's Tests; FS-80's card clause): a
// vault run's card, indexed with a change's path, is listed by the change's erasure through the CUT's epoch; the eraser
// folds the card again at its stream's head without the change and enters it in its own head above the list, where the
// path no longer finds it and the context's project still does; no openable stored version holds a listed version,
// and the erasure entry lands.
func TestRecordEraseFoldsTheCardAgainWithoutTheEntry(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, _ := world.eraserDevice()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_VAULT, eraser.sidecarId)
	testEraseIndexTapOn(eraser, index)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	record := testEraseIndexOpen(eraser, index)
	drafts := testEraseVaultRunDrafts(&runId, "internal/quokkazebra.go")
	testRecordAppend(t, record, drafts[0])
	change := testRecordAppend(t, record, drafts[1])
	if err := record.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := record.Reader().Sync(ctx, world.vaultId); err != nil {
		t.Fatal(err)
	}
	refId := sidecartest.FakeRecordStreamRefId(world.vaultId, eraser.sidecarId)
	cardKey := index.CardKey(refId, runId)
	erasedWord, keptWord := index.TextKeys("quokkazebra"), index.TextKeys("frobnicator")
	indexed := index.PrepareCard(record.Reader(), world.vaultId, eraser.sidecarId, refId, runId, eraser.sidecarId, nil)
	if indexed == nil || !testEraseIndexHolds(indexed.Keys, erasedWord) || !testEraseIndexHolds(indexed.Keys, keptWord) {
		t.Fatal("the card before the erasure does not hold the path and the project")
	}
	if err := indexed.Send(); err != nil {
		t.Fatal(err)
	}
	result, err := record.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: []sidecar.Id{change.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Index == nil || result.Index.DocumentCount != 1 || result.Index.CardCount != 1 || result.Index.EnteredCount != 1 {
		t.Fatalf("the index's part: %+v", result.Index)
	}
	listed, ok := index.Listed()[cardKey]
	if !ok || listed < indexed.Version {
		t.Fatalf("the card's indexed version %d is not listed (%d)", indexed.Version, listed)
	}
	card := testEraseIndexOneAbove(t, index, cardKey, listed)
	if card.Writer != eraser.sidecarId || !card.Head {
		t.Fatalf("the card folded again stands in %s's files, head %t", card.Writer, card.Head)
	}
	if testEraseIndexHolds(card.Keys, erasedWord) || !testEraseIndexHolds(card.Keys, keptWord) {
		t.Fatal("the card folded again holds the erased change, or lost the context")
	}
	index.Sweep()
	// the re-entry rewrote the one file holding the card in place, so a completion ERASE ended the erasure
	if _, complete := index.Erases(result.ErasureId); !complete || !result.Index.Completed {
		t.Fatal("the erasure did not end")
	}
	if err := record.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if bodies := testEraseBodies(t, testEraseStored(world, eraser.sidecarId)); len(bodies) != 1 || sidecar.Id(bodies[0].GetErasureId()) != result.ErasureId {
		t.Fatalf("the erasure entries: %v", bodies)
	}
}

// FS-111's team record case (RECORD-M10-01's Tests: a CUT before any index push built earlier commits, at the later of
// M10-out and M6-out): two log admins ingest a member's run into their streams of the team record, and the second
// indexes its stream's card; once a later entry of the run lands it builds its next card push, the change still folded
// in, and holds it. The first admin erases the change: its CUT lists both streams' cards through its epoch, a CLOSURE
// rewrites the second admin's head holding the listed card under a fresh key, and the last ERASE says complete. The
// held push is then refused 409 INDEX_EPOCH, and built again from the erasure ref and the set it commits without the
// change, above the list. FI-19's sweep finds nothing.
func TestRecordEraseTeamCutFencesACardPushBuiltBeforeIt(t *testing.T) {
	ctx := t.Context()
	world := newTestTeamWorld(t)
	member := world.memberDevice(true)
	eraser, other := world.teamEraser(), world.teamEraser()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_TEAM_RECORD, eraser.sidecarId, other.sidecarId)
	tap := testEraseIndexTapOn(eraser, index)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	memberRecord := member.open()
	drafts := testEraseTeamRunDrafts(&runId, "c0ffeequokka")
	testRecordAppendAll(t, memberRecord, drafts[0])
	change := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[1]), world.teamRecordId)
	eraserRecord := testEraseIndexOpen(eraser, index)
	otherRecord := other.open()
	ingestBoth := func() {
		if err := memberRecord.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		for _, record := range []*sidecar.SidecarRecord{eraserRecord, otherRecord} {
			testEraseIngest(t, record, world.teamRecordId, true)
		}
		for _, record := range []*sidecar.SidecarRecord{eraserRecord, otherRecord} {
			testEraseIngest(t, record, world.teamRecordId, false)
		}
		if err := otherRecord.Reader().Sync(ctx, world.teamRecordId); err != nil {
			t.Fatal(err)
		}
	}
	ingestBoth()
	otherRef := sidecartest.FakeRecordStreamRefId(world.teamRecordId, other.sidecarId)
	cardKey := index.CardKey(otherRef, runId)
	erasedWord, keptWord := index.TextKeys("c0ffeequokka"), index.TextKeys("acmeforecast")
	prepare := func() *sidecar.RecordEraseTestCardPush {
		erasures, err := world.streams.For(other.sidecarId).ReadErasures(ctx, world.teamRecordId, 0)
		if err != nil {
			t.Fatal(err)
		}
		return index.PrepareCard(otherRecord.Reader(), world.teamRecordId, other.sidecarId, otherRef, runId, other.sidecarId, erasures)
	}
	indexed := prepare()
	if indexed == nil || !testEraseIndexHolds(indexed.Keys, erasedWord) {
		t.Fatal("the indexed card does not hold the change's commit")
	}
	if err := indexed.Send(); err != nil {
		t.Fatal(err)
	}
	testRecordAppendAll(t, memberRecord, testEraseTeamRunDrafts(&runId, "acmeforecast")[1])
	ingestBoth()
	held := prepare()
	if held == nil || held.Version <= indexed.Version || !testEraseIndexHolds(held.Keys, erasedWord) || !testEraseIndexHolds(held.Keys, keptWord) {
		t.Fatal("the held card push does not fold both changes")
	}
	result, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.teamRecordId, EntryIds: []sidecar.Id{change.EntryId}, Reason: sidecar.RecordErasureReasonModeration, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Index == nil || !result.Index.Fenced || result.Index.CardCount != 2 || result.Index.DocumentCount != 2 || !result.Index.Completed {
		t.Fatalf("the index's part: %+v", result.Index)
	}
	if count, complete := index.Erases(result.ErasureId); !complete || index.Closures(result.ErasureId) == 0 || count < 2 {
		t.Fatalf("%d ERASEs, the newest complete %t, after %d CLOSUREs", count, complete, index.Closures(result.ErasureId))
	}
	for _, erase := range tap.committed() {
		if erase.Complete {
			t.Fatal("a body's ERASE said complete before the CUT")
		}
	}
	if err := held.Send(); !sidecar.RecordEraseTestIndexEpochRefused(err) {
		t.Fatalf("the card push built before the CUT: %v", err)
	}
	if err := otherRecord.Reader().Sync(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	rebuilt := prepare()
	if rebuilt == nil || testEraseIndexHolds(rebuilt.Keys, erasedWord) || !testEraseIndexHolds(rebuilt.Keys, keptWord) {
		t.Fatal("the card push built again holds the erased change, or lost the later one")
	}
	if err := rebuilt.Send(); err != nil {
		t.Fatal(err)
	}
	listed := index.Listed()[cardKey]
	if held.Version > listed || rebuilt.Version <= listed {
		t.Fatalf("the held card at %d and the rebuilt one at %d against the list's %d", held.Version, rebuilt.Version, listed)
	}
	index.Sweep()
}

// A restart going on from evs's state (RECORD-M10-01's Tests; §11.12's reconcile row): the eraser is killed after its
// ERASE and before its CUT, then again at its rewrite after its CUT and re-entry; each restart's Resume takes up the
// journal's step, so the bodies' ERASE commits once, the CUT lists the erasure, each card is entered once, the CLOSURE
// and the complete ERASE follow, and the erasure entry lands once; a third Resume does nothing.
func TestRecordEraseResumesFromEvsState(t *testing.T) {
	ctx := t.Context()
	world := newTestTeamWorld(t)
	member := world.memberDevice(true)
	eraser, other := world.teamEraser(), world.teamEraser()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_TEAM_RECORD, eraser.sidecarId, other.sidecarId)
	tap := testEraseIndexTapOn(eraser, index)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	memberRecord := member.open()
	drafts := testEraseTeamRunDrafts(&runId, "c0ffeequokka")
	testRecordAppendAll(t, memberRecord, drafts[0])
	change := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[1]), world.teamRecordId)
	if err := memberRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	eraserRecord := testEraseIndexOpen(eraser, index)
	otherRecord := other.open()
	for _, flush := range []bool{true, false} {
		for _, record := range []*sidecar.SidecarRecord{eraserRecord, otherRecord} {
			testEraseIngest(t, record, world.teamRecordId, flush)
		}
	}
	if err := otherRecord.Reader().Sync(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	otherRef := sidecartest.FakeRecordStreamRefId(world.teamRecordId, other.sidecarId)
	eraserRef := sidecartest.FakeRecordStreamRefId(world.teamRecordId, eraser.sidecarId)
	indexed := index.PrepareCard(otherRecord.Reader(), world.teamRecordId, other.sidecarId, otherRef, runId, other.sidecarId, nil)
	if indexed == nil {
		t.Fatal("no card to index")
	}
	if err := indexed.Send(); err != nil {
		t.Fatal(err)
	}
	args := &sidecar.RecordEraseArgs{LogId: world.teamRecordId, EntryIds: []sidecar.Id{change.EntryId}, Reason: sidecar.RecordErasureReasonModeration, Confirmed: true}
	index.FailNext("cut", errTestEraseIndexKilled)
	if _, err := eraserRecord.Eraser().Erase(ctx, args); !errors.Is(err, errTestEraseIndexKilled) {
		t.Fatalf("the erasure killed before its CUT: %v", err)
	}
	erases := tap.committed()
	if len(erases) != 1 || erases[0].Complete || len(erases[0].Keys) != 2 {
		t.Fatalf("before the CUT: %d ERASEs", len(erases))
	}
	erasureId := erases[0].ErasureId
	if index.ErasureDocs(erasureId) != nil {
		t.Fatal("a CUT was listed though it was killed")
	}
	restarted := testEraseIndexOpen(eraser, index)
	index.FailNext("rewrite", errTestEraseIndexKilled)
	if err := restarted.Eraser().Resume(ctx); !errors.Is(err, errTestEraseIndexKilled) {
		t.Fatalf("the resume killed at its rewrite: %v", err)
	}
	listed := index.ErasureDocs(erasureId)
	if len(listed) != 2 {
		t.Fatalf("the CUT lists %d documents", len(listed))
	}
	for _, refId := range []sidecar.Id{eraserRef, otherRef} {
		key := index.CardKey(refId, runId)
		if card := testEraseIndexOneAbove(t, index, key, listed[key]); card.Writer != eraser.sidecarId {
			t.Fatal("a card was folded again by another")
		}
	}
	again := testEraseIndexOpen(eraser, index)
	if err := again.Eraser().Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if _, complete := index.Erases(erasureId); !complete || index.Closures(erasureId) == 0 {
		t.Fatal("the rewrite did not end the erasure")
	}
	for _, refId := range []sidecar.Id{eraserRef, otherRef} {
		key := index.CardKey(refId, runId)
		testEraseIndexOneAbove(t, index, key, listed[key])
	}
	if calls := index.Calls(); !slices.Equal(calls, []string{"cut", "cut", "reenter", "rewrite", "reenter", "rewrite"}) {
		t.Fatalf("the index was called %v", calls)
	}
	if erases := tap.committed(); len(erases) != 1 {
		t.Fatalf("%d bodies' ERASEs committed", len(erases))
	}
	if err := again.Eraser().Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if calls := index.Calls(); len(calls) != 6 {
		t.Fatalf("a third Resume called the index: %v", calls)
	}
	if err := again.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := again.Reader().Sync(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	if entries, _ := again.Reader().EntriesOfKinds(world.teamRecordId, 0, sidecar.RecordKindErasure); len(entries) != 1 {
		t.Fatalf("%d erasure entries", len(entries))
	}
	index.Sweep()
}

// DESIGN-DETAILS 15.6's TestRecordEraseLateCopy: a copy of the erased change that a second ingester lands after the
// erasure's second read is a late copy. The erasure had ended, a third ingester's indexed card rewritten and its last
// ERASE saying complete; the next look of a log admin's daemon ERASEs the late copy's key row under the same erasure,
// saying nothing complete, which opens the erasure again, so its rewrite runs rather than reading it done; CUTs again
// so the erasure's set entry lists the copy's stream's card through the new epoch; folds that card again without the
// change into its own head above the list; and, no file holding a listed version of the copy's, ends the erasure again
// with a completion ERASE (QD-1132), writing no second erasure entry. The copy no longer opens, a look after that finds
// nothing, and a later erasure's CUT drops the erasure, complete again.
func TestRecordEraseLateCopy(t *testing.T) {
	ctx := t.Context()
	world := newTestTeamWorld(t)
	member := world.memberDevice(true)
	eraser, other, third := world.teamEraser(), world.teamEraser(), world.teamEraser()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_TEAM_RECORD, eraser.sidecarId, other.sidecarId, third.sidecarId)
	tap := testEraseIndexTapOn(eraser, index)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	memberRecord := member.open()
	drafts := testEraseTeamRunDrafts(&runId, "c0ffeequokka")
	contextRef := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[0]), world.teamRecordId)
	change := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[1]), world.teamRecordId)
	if err := memberRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	eraserRecord := testEraseIndexOpen(eraser, index)
	otherRecord := other.open()
	thirdRecord := third.open()
	// the second ingester's copies wait in its writer; the third's land, and it indexes its stream's card
	testEraseIngest(t, otherRecord, world.teamRecordId, false)
	for _, flush := range []bool{true, false} {
		for _, record := range []*sidecar.SidecarRecord{eraserRecord, thirdRecord} {
			testEraseIngest(t, record, world.teamRecordId, flush)
		}
	}
	if err := thirdRecord.Reader().Sync(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	thirdRef := sidecartest.FakeRecordStreamRefId(world.teamRecordId, third.sidecarId)
	indexed := index.PrepareCard(thirdRecord.Reader(), world.teamRecordId, third.sidecarId, thirdRef, runId, third.sidecarId, nil)
	if indexed == nil {
		t.Fatal("no card to index")
	}
	if err := indexed.Send(); err != nil {
		t.Fatal(err)
	}
	result, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.teamRecordId, EntryIds: []sidecar.Id{change.EntryId}, Reason: sidecar.RecordErasureReasonModeration, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if listed := index.ErasureDocs(result.ErasureId); len(listed) != 2 || result.Index == nil || !result.Index.Completed {
		t.Fatalf("the erasure lists %d documents before the late copy, its part %+v", len(listed), result.Index)
	}
	otherRef := sidecartest.FakeRecordStreamRefId(world.teamRecordId, other.sidecarId)
	otherCardKey := index.CardKey(otherRef, runId)
	// the late copy lands
	if err := otherRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	epoch := index.Epoch()
	lates, err := eraserRecord.Eraser().EraseLateCopies(ctx, world.teamRecordId)
	if err != nil {
		t.Fatal(err)
	}
	if len(lates) != 1 || lates[0].ErasureId != result.ErasureId || lates[0].Entry != nil || lates[0].Index == nil || !lates[0].Index.Fenced {
		t.Fatalf("the late copies' erasures: %+v", lates)
	}
	erases := tap.committed()
	if len(erases) != 3 || erases[1].ErasureId != result.ErasureId || erases[1].Complete || len(erases[1].Keys) != 1 {
		t.Fatalf("the late copy's ERASE: %d ERASEs", len(erases))
	}
	if completion := erases[2]; !completion.Complete || !testEraseIndexSameKeys(completion.Keys, erases[1].Keys) || !lates[0].Index.Completed {
		t.Fatal("no completion ERASE ended the erasure after its late copy's rewrite")
	}
	if state := lates[0].Index.Erasure; state == nil || state.State == sidecar.SidecarErasureDone {
		t.Fatal("the late copy's rewrite read the erasure done from its earlier complete ERASE")
	}
	if _, complete := index.Erases(result.ErasureId); !complete {
		t.Fatal("the erasure does not read complete after its late copy")
	}
	listed := index.ErasureDocs(result.ErasureId)
	if version, ok := listed[otherCardKey]; len(listed) != 3 || !ok || version != epoch<<32|(1<<32-1) {
		t.Fatalf("the erasure lists %d documents, the late stream's card through %d", len(listed), version)
	}
	card := testEraseIndexOneAbove(t, index, otherCardKey, listed[otherCardKey])
	if card.Writer != eraser.sidecarId || testEraseIndexHolds(card.Keys, index.TextKeys("c0ffeequokka")) {
		t.Fatal("the late stream's card was not folded again without the change")
	}
	again, err := eraserRecord.Eraser().EraseLateCopies(ctx, world.teamRecordId)
	if err != nil || len(again) != 0 {
		t.Fatalf("a second look took up %d erasures: %v", len(again), err)
	}
	if err := eraserRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	reader := world.newReader(nil, nil)
	if err := reader.reader.Sync(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	if entries, _ := reader.reader.EntriesOfKinds(world.teamRecordId, 0, sidecar.RecordKindErasure); len(entries) != 1 {
		t.Fatalf("%d erasure entries", len(entries))
	}
	entry, ok := reader.reader.Entry(world.teamRecordId, change.EntryId)
	if !ok || len(entry.Copies) != 3 || entry.Body != nil || !entry.State.KeyGone() {
		t.Fatal("the late copy still opens")
	}
	slot, err := world.streams.For(eraser.sidecarId).ReadSlot(ctx, world.teamRecordId, erases[1].Keys[0].SlotId)
	if err == nil {
		for _, row := range slot.Rows {
			if row.KeyIndex == erases[1].Keys[0].KeyIndex {
				t.Fatal("the late copy's key row stands")
			}
		}
	}
	index.Sweep()
	// a later erasure's CUT drops the erasure, complete again
	later, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.teamRecordId, EntryIds: []sidecar.Id{contextRef.EntryId}, Reason: sidecar.RecordErasureReasonModeration, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if index.ErasureDocs(later.ErasureId) == nil || index.ErasureDocs(result.ErasureId) != nil {
		t.Fatal("a later CUT kept the completed erasure, or listed nothing of its own")
	}
	index.Sweep()
}

// An erasure none of whose entries is a document or a card's source (a vault's permission entry): no CUT, nothing
// asked of the index, and its last ERASE says complete, as in format 1.
func TestRecordEraseWithNothingToListCompletes(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, _ := world.eraserDevice()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_VAULT, eraser.sidecarId)
	tap := testEraseIndexTapOn(eraser, index)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	record := testEraseIndexOpen(eraser, index)
	permission := testRecordAppend(t, record, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindPermission, Source: sidecar.RecordSourceHook, RunId: &runId, Body: &protocol.PermissionBody{
			Decision: 2, DecidedBy: 1, ToolClass: 1, ToolName: "Bash", ArgumentsSha256: bytes.Repeat([]byte{0x5a}, 32),
		},
	})
	if err := record.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := record.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: []sidecar.Id{permission.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Index != nil || len(index.Calls()) != 0 {
		t.Fatalf("an erasure with nothing to list called the index %v", index.Calls())
	}
	if erases := tap.committed(); len(erases) != 1 || !erases[0].Complete {
		t.Fatal("its ERASE did not say complete")
	}
}

// `ur record erase`'s listing of a context entry in a format-2 log (DESIGN-DETAILS 15.2.8; QD-782): the documents of
// its run's other entries that keep its agent label and session ids, the run's note in its stream, and none in a
// format-1 log.
func TestRecordErasePlanNamesTheContextFieldsKept(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, _ := world.eraserDevice()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_VAULT, eraser.sidecarId)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	record := eraser.open()
	contextRef := testRecordAppend(t, record, testEraseVaultRunDrafts(&runId, "internal/widget.go")[0])
	testRecordAppend(t, record, testRecordNote(&runId, "the rotation plan"))
	testRecordAppend(t, record, testRecordNote(nil, "a note of no run"))
	if err := record.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	args := &sidecar.RecordEraseArgs{LogId: world.vaultId, EntryIds: []sidecar.Id{contextRef.EntryId}, Reason: sidecar.RecordErasureReasonPerson}
	plan, err := record.Eraser().Plan(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 1 || plan.Items[0].KeptContextCount != 0 {
		t.Fatalf("a format-1 plan: %+v", plan.Items)
	}
	record.SetEraseIndex(index.Open(eraser.sidecarId))
	if plan, err = record.Eraser().Plan(ctx, args); err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 1 || plan.Items[0].KeptContextCount != 1 {
		t.Fatalf("a format-2 plan: %+v", plan.Items)
	}
}

// An erasure whose CUT would list more documents than its bound is refused before anything is erased: no ERASE, no
// CUT, every body still opening, and no journal for a restart to take up.
func TestRecordEraseRefusesACutPastItsBound(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, _ := world.eraserDevice()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_VAULT, eraser.sidecarId)
	tap := testEraseIndexTapOn(eraser, index)
	record := testEraseIndexOpen(eraser, index)
	entryIds := []sidecar.Id{}
	for _, text := range []string{"first", "second", "third"} {
		entryIds = append(entryIds, testRecordAppend(t, record, testRecordNote(nil, text)).EntryId)
	}
	if err := record.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	eraserOfRecord := record.Eraser()
	settings := sidecar.DefaultRecordEraserSettings()
	settings.CutDocumentCount = 2
	eraserOfRecord.SetSettingsForTest(settings)
	if _, err := eraserOfRecord.Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: entryIds, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	}); !errors.Is(err, sidecar.ErrRecordEraseTooLarge) {
		t.Fatalf("an erasure past the CUT's bound: %v", err)
	}
	if err := record.Eraser().Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if len(tap.committed()) != 0 || len(index.Calls()) != 0 {
		t.Fatal("a refused erasure erased or cut")
	}
	stored := testEraseStored(world, eraser.sidecarId)
	for _, entryId := range entryIds {
		if item := stored[entryId]; item == nil || item.body == nil {
			t.Fatal("a refused erasure took a body")
		}
	}
}

// An erasure that took no key, every ERASE of it finding the keys gone already, as when two admins' passes race and the
// first commit wins (RECORD.md section 8's expiry row), committed nothing and never began (§11.12's reconcile row): it
// lists nothing and asks nothing of the index, the first erasure's CUT listing the documents.
func TestRecordEraseThatTookNoKeyListsNothing(t *testing.T) {
	ctx := t.Context()
	world := newTestTeamWorld(t)
	member := world.memberDevice(true)
	eraser, other := world.teamEraser(), world.teamEraser()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_TEAM_RECORD, eraser.sidecarId, other.sidecarId)
	testEraseIndexTapOn(eraser, index)
	otherTap := testEraseIndexTapOn(other, index)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	memberRecord := member.open()
	drafts := testEraseTeamRunDrafts(&runId, "c0ffeequokka")
	testRecordAppendAll(t, memberRecord, drafts[0])
	change := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[1]), world.teamRecordId)
	if err := memberRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	eraserRecord := testEraseIndexOpen(eraser, index)
	otherRecord := testEraseIndexOpen(other, index)
	for _, flush := range []bool{true, false} {
		for _, record := range []*sidecar.SidecarRecord{eraserRecord, otherRecord} {
			testEraseIngest(t, record, world.teamRecordId, flush)
		}
	}
	// the other admin's reader holds both copies' keys before the first erasure takes them
	if err := otherRecord.Reader().Sync(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	args := &sidecar.RecordEraseArgs{LogId: world.teamRecordId, EntryIds: []sidecar.Id{change.EntryId}, Reason: sidecar.RecordErasureReasonRetention}
	first, err := eraserRecord.Eraser().Erase(ctx, args)
	if err != nil || first.Index == nil || !first.Index.Fenced {
		t.Fatalf("the first erasure: %+v, %v", first, err)
	}
	calls := len(index.Calls())
	second, err := otherRecord.Eraser().Erase(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	if second.Index != nil || len(index.Calls()) != calls || len(otherTap.committed()) != 0 || index.ErasureDocs(second.ErasureId) != nil {
		t.Fatalf("an erasure that took no key listed %+v, called the index %v", second.Index, index.Calls()[calls:])
	}
}

// §16.8's Erasure and §11.12's reconcile row: an eraser killed between its ERASE and its CUT, never to start again,
// has its erasure taken up by another device: not by an admin of another member while the eraser still erases, and by
// another device of the eraser's member only 25 h after its last ERASE, which then commits the CUT, rewrites the index
// file holding a listed card, its last ERASE saying complete, and folds the listed cards again; once the eraser no
// longer erases in the log, an admin of another member takes up its next such erasure at once. (In this world the
// index side's ERASEs are not on the record streams' erasure ref, as they are on evs's, so a later look runs the
// index's Resume again, which finds the erasure complete and does nothing.)
func TestRecordEraseResumedByAnotherDevice(t *testing.T) {
	ctx := t.Context()
	world := newTestTeamWorld(t)
	member := world.memberDevice(true)
	eraser, sibling, stranger := world.teamEraser(), world.teamEraser(), world.teamEraser()
	// the sibling is another device of the eraser's member
	world.fixture.Members[sibling.sidecarId] = world.fixture.Members[eraser.sidecarId]
	world.publish()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_TEAM_RECORD, eraser.sidecarId, sibling.sidecarId, stranger.sidecarId)
	tap := testEraseIndexTapOn(eraser, index)
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	memberRecord := member.open()
	drafts := testEraseTeamRunDrafts(&runId, "c0ffeequokka")
	contextRef := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[0]), world.teamRecordId)
	change := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[1]), world.teamRecordId)
	if err := memberRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	eraserRecord := testEraseIndexOpen(eraser, index)
	siblingRecord := testEraseIndexOpen(sibling, index)
	strangerRecord := testEraseIndexOpen(stranger, index)
	records := []*sidecar.SidecarRecord{eraserRecord, siblingRecord, strangerRecord}
	for _, flush := range []bool{true, false} {
		for _, record := range records {
			testEraseIngest(t, record, world.teamRecordId, flush)
		}
	}
	if err := strangerRecord.Reader().Sync(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	strangerRef := sidecartest.FakeRecordStreamRefId(world.teamRecordId, stranger.sidecarId)
	indexed := index.PrepareCard(strangerRecord.Reader(), world.teamRecordId, stranger.sidecarId, strangerRef, runId, stranger.sidecarId, nil)
	if indexed == nil {
		t.Fatal("no card to index")
	}
	if err := indexed.Send(); err != nil {
		t.Fatal(err)
	}
	index.FailNext("cut", errTestEraseIndexKilled)
	if _, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.teamRecordId, EntryIds: []sidecar.Id{change.EntryId}, Reason: sidecar.RecordErasureReasonModeration, Confirmed: true,
	}); !errors.Is(err, errTestEraseIndexKilled) {
		t.Fatalf("the erasure killed before its CUT: %v", err)
	}
	erasureId := tap.committed()[0].ErasureId
	if results, err := strangerRecord.Eraser().ResumeOthers(ctx, world.teamRecordId); err != nil || len(results) != 0 {
		t.Fatalf("an admin of another member took up a live eraser's erasure: %d, %v", len(results), err)
	}
	results, err := siblingRecord.Eraser().ResumeOthers(ctx, world.teamRecordId)
	if err != nil || len(results) != 1 || results[0].Index == nil || !results[0].Index.Waiting || results[0].Index.Fenced {
		t.Fatalf("the sibling before 25 h: %+v, %v", results, err)
	}
	if index.ErasureDocs(erasureId) != nil {
		t.Fatal("a CUT was committed before 25 h")
	}
	index.Advance(25*time.Hour + time.Minute)
	if results, err = siblingRecord.Eraser().ResumeOthers(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ErasureId != erasureId || results[0].Index == nil || !results[0].Index.Fenced ||
		!results[0].Index.Completed || results[0].Index.CardCount != 3 || results[0].Index.EnteredCount != 3 {
		t.Fatalf("the sibling after 25 h: %+v", results)
	}
	listed := index.ErasureDocs(erasureId)
	if len(listed) != 3 {
		t.Fatalf("the CUT lists %d documents", len(listed))
	}
	for key, version := range listed {
		if card := testEraseIndexOneAbove(t, index, key, version); card.Writer != sibling.sidecarId {
			t.Fatal("a card was folded again by another device")
		}
	}
	if _, complete := index.Erases(erasureId); !complete || index.Closures(erasureId) == 0 {
		t.Fatal("the taken-up erasure did not end")
	}
	index.Sweep()

	// the eraser no longer erases in the log: its next erasure killed before the CUT is any admin's at once
	index.FailNext("cut", errTestEraseIndexKilled)
	if _, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.teamRecordId, EntryIds: []sidecar.Id{contextRef.EntryId}, Reason: sidecar.RecordErasureReasonModeration, Confirmed: true,
	}); !errors.Is(err, errTestEraseIndexKilled) {
		t.Fatalf("the second erasure killed before its CUT: %v", err)
	}
	later := tap.committed()[1].ErasureId
	repo := world.fixture.Repos[world.teamRecordId]
	repo.Admins = removeTestId(repo.Admins, eraser.sidecarId)
	world.publish()
	if results, err = strangerRecord.Eraser().ResumeOthers(ctx, world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	taken := slices.ContainsFunc(results, func(result *sidecar.RecordEraseResult) bool {
		return result.ErasureId == later && result.Index != nil && result.Index.Fenced
	})
	if !taken || index.ErasureDocs(later) == nil {
		t.Fatalf("an admin did not take up a revoked eraser's erasure: %+v", results)
	}
	index.Sweep()
}

// An erasure whose ERASE committed though its answer was lost, resumed after evs has forgotten the push id, so the
// retry answers NOTHING_TO_ERASE: evs's erasure ref shows the ERASE of this erasure, so it began, and it CUTs and lists
// its documents rather than reading as one another erasure took the keys of.
func TestRecordEraseResumedPastEvsMemoryStillCuts(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, _ := world.eraserDevice()
	index := sidecar.NewRecordEraseTestIndex(t, protocol.RepoKind_REPO_KIND_VAULT, eraser.sidecarId)
	tap := testEraseIndexTapOn(eraser, index)
	record := testEraseIndexOpen(eraser, index)
	note := testRecordAppend(t, record, testRecordNote(nil, "the rotation plan"))
	if err := record.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	tap.setLoseAndForget()
	if _, err := record.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: []sidecar.Id{note.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	}); !errors.Is(err, errTestEraseIndexKilled) {
		t.Fatalf("the erasure whose answer was lost: %v", err)
	}
	erasureId := tap.committed()[0].ErasureId
	if index.ErasureDocs(erasureId) != nil {
		t.Fatal("a CUT before the ERASE's answer")
	}
	restarted := testEraseIndexOpen(eraser, index)
	if err := restarted.Eraser().Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if index.ErasureDocs(erasureId) == nil || !slices.Contains(index.Calls(), "cut") {
		t.Fatal("the resumed erasure read as one that never began, and listed nothing")
	}
}
