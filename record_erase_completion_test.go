//go:build !sidecar_http && !ios_extension

// QD-1132's completion ERASE for a record erasure (record_erase.go's rewrite row; evs_erase_completion.go), on
// RECORD-M10-01's worlds (record_erase_index_test.go): which key a completion names after a late copy reopened an
// erasure a completion had ended.

package sidecar_test

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// An erasure whose index held nothing ends by a completion ERASE naming its first ERASE's first key. A late copy's
// ERASE then reopens it, its rewrite again finds nothing, and the next completion names a key no completion took, the
// late copy's: one naming the first key again meets a completion as the newest ERASE naming that key, which evs
// refuses (question erasure-completion-erase-evs-cannot-read-complete's option 1, as the record streams' fake takes
// it). The erasure reads complete again, writes no second erasure entry, and a later erasure's CUT drops it.
func TestRecordEraseLateCopyAfterACompletionNamesAnotherKey(t *testing.T) {
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
	contextRef := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[0]), world.teamRecordId)
	change := testEraseIndexRefIn(t, testRecordAppendAll(t, memberRecord, drafts[1]), world.teamRecordId)
	if err := memberRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	eraserRecord := testEraseIndexOpen(eraser, index)
	otherRecord := other.open()
	// the second ingester's copies wait in its writer; no index file holds anything
	testEraseIngest(t, otherRecord, world.teamRecordId, false)
	for _, flush := range []bool{true, false} {
		testEraseIngest(t, eraserRecord, world.teamRecordId, flush)
	}
	result, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.teamRecordId, EntryIds: []sidecar.Id{change.EntryId}, Reason: sidecar.RecordErasureReasonModeration, Confirmed: true,
	})
	if err != nil || result.Index == nil || !result.Index.Completed {
		t.Fatalf("the erasure: %+v, %v", result, err)
	}
	erases := tap.committed()
	if len(erases) != 2 || erases[0].Complete || !erases[1].Complete || !testEraseIndexSameKeys(erases[1].Keys, erases[0].Keys[:1]) {
		t.Fatalf("the first completion: %d ERASEs", len(erases))
	}
	// the late copy lands, and a log admin's daemon's next look ERASEs it
	if err := otherRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	lates, err := eraserRecord.Eraser().EraseLateCopies(ctx, world.teamRecordId)
	if err != nil || len(lates) != 1 || lates[0].ErasureId != result.ErasureId || lates[0].Index == nil || !lates[0].Index.Completed {
		t.Fatalf("the late copy's erasure: %+v, %v", lates, err)
	}
	erases = tap.committed()
	if len(erases) != 4 || erases[2].Complete || len(erases[2].Keys) != 1 {
		t.Fatalf("the late copy's ERASE: %d ERASEs", len(erases))
	}
	if completion := erases[3]; !completion.Complete || completion.ErasureId != result.ErasureId || !testEraseIndexSameKeys(completion.Keys, erases[2].Keys) {
		t.Fatalf("the second completion named %v, the late copy's ERASE %v", completion.Keys, erases[2].Keys)
	}
	if _, complete := index.Erases(result.ErasureId); !complete {
		t.Fatal("the erasure does not read complete after its late copy")
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
