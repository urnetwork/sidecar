//go:build !ios_extension && !sidecar_http && !js

// CTXH-M11-06's prune (DESIGN-COMPUTE §24.10's prune row, §24.16's Erasure row; RECORD.md section 8) on sidecartest's
// streams: `ur record erase --run` erases every entry of the run, with --context its session entries and blobs alone,
// with --blobs-only its blobs alone; erasing a session entry by id erases its parts' blobs, and the plan lists, before
// anything is erased, the run's same_as nodes and the calls whose context it cuts and the runs that continue it; a
// person's erasure unconfirmed erases nothing. External, on session_storage_test.go's admin world.

package sidecar_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A run with a context entry, a tool result kept in blobs, a model call and a coverage entry: every kind a run holds.
func testRecordEraseRun(t *testing.T, world *testSessionJournalWorld) *testSessionRecorder {
	t.Helper()
	recorder, _ := testSessionCapRun(t, world, 200*1024)
	testRecordAppend(t, world.record, &sidecar.RecordDraft{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceObserved, RunId: &recorder.run.RunId,
		Body: &protocol.ContextBody{Stage: 1, Harness: sidecar.HarnessRunHarnessName, Title: "read the logs"}})
	testRecordAppend(t, world.record, &sidecar.RecordDraft{Kind: sidecar.RecordKindCoverage, Source: sidecar.RecordSourceObserved, RunId: &recorder.run.RunId,
		Body: &protocol.Coverage{RunId: recorder.run.RunId.Bytes(), Sources: []string{sidecar.RecordCoverageSourceHarness}}})
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return recorder
}

// The kinds of runId's entries whose keys are gone, and of those that stand, as another device reads them.
func testRecordEraseKinds(t *testing.T, world *testSessionJournalWorld, runId sidecar.Id) (gone []sidecar.RecordKind, stand []sidecar.RecordKind) {
	t.Helper()
	for _, entry := range testSessionCapRead(t, world, runId) {
		if entry.State.KeyGone() {
			gone = append(gone, entry.Kind())
		} else {
			stand = append(stand, entry.Kind())
		}
	}
	return gone, stand
}

// --run erases every entry of the run, every kind, and no other run's; unconfirmed it erases nothing.
func TestRecordEraseRunLeavesNoEntry(t *testing.T) {
	world := newTestSessionAdminWorld(t)
	recorder := testRecordEraseRun(t, world)
	other, _ := testSessionCapRun(t, world, 1024)
	spec := &sidecar.SessionPruneSpec{RunId: &recorder.run.RunId}
	if _, err := world.record.SessionPrune(t.Context(), spec, false, false); !errors.Is(err, sidecar.ErrRecordEraseUnconfirmed) {
		t.Fatalf("an unconfirmed prune: %v", err)
	}
	if gone, _ := testRecordEraseKinds(t, world, recorder.run.RunId); len(gone) != 0 {
		t.Fatalf("an unconfirmed prune erased %v", gone)
	}
	if _, err := world.record.SessionPrune(t.Context(), spec, true, true); !errors.Is(err, sidecar.ErrRecordEraseUnconfirmed) {
		t.Fatalf("a prune under a harness: %v", err)
	}
	if _, err := world.record.SessionPrune(t.Context(), spec, true, false); err != nil {
		t.Fatal(err)
	}
	gone, stand := testRecordEraseKinds(t, world, recorder.run.RunId)
	if len(stand) != 0 {
		t.Fatalf("entries of the run stand: %v", stand)
	}
	for _, kind := range []sidecar.RecordKind{sidecar.RecordKindSessionEntry, sidecar.RecordKindSessionBlob, sidecar.RecordKindModelCall,
		sidecar.RecordKindContext, sidecar.RecordKindCoverage} {
		if !slices.Contains(gone, kind) {
			t.Errorf("no %s was erased", kind)
		}
	}
	if gone, _ := testRecordEraseKinds(t, world, other.run.RunId); len(gone) != 0 {
		t.Fatalf("another run lost %v", gone)
	}
}

// --context erases the run's session entries and blobs, its context, model call and coverage entries standing.
func TestRecordEraseContextOnly(t *testing.T) {
	world := newTestSessionAdminWorld(t)
	recorder := testRecordEraseRun(t, world)
	if _, err := world.record.SessionPrune(t.Context(), &sidecar.SessionPruneSpec{RunId: &recorder.run.RunId, Scope: sidecar.RecordEraseRunContext}, true, false); err != nil {
		t.Fatal(err)
	}
	gone, stand := testRecordEraseKinds(t, world, recorder.run.RunId)
	for _, kind := range gone {
		if kind != sidecar.RecordKindSessionEntry && kind != sidecar.RecordKindSessionBlob {
			t.Errorf("--context erased a %s", kind)
		}
	}
	for _, kind := range []sidecar.RecordKind{sidecar.RecordKindModelCall, sidecar.RecordKindContext, sidecar.RecordKindCoverage} {
		if !slices.Contains(stand, kind) {
			t.Errorf("the run's %s did not stand", kind)
		}
	}
	if slices.Contains(stand, sidecar.RecordKindSessionEntry) || slices.Contains(stand, sidecar.RecordKindSessionBlob) {
		t.Fatalf("session history stands: %v", stand)
	}
}

// --blobs-only erases the run's blobs alone, every node standing.
func TestRecordEraseBlobsOnly(t *testing.T) {
	world := newTestSessionAdminWorld(t)
	recorder := testRecordEraseRun(t, world)
	if _, err := world.record.SessionPrune(t.Context(), &sidecar.SessionPruneSpec{RunId: &recorder.run.RunId, Scope: sidecar.RecordEraseRunBlobs}, true, false); err != nil {
		t.Fatal(err)
	}
	gone, stand := testRecordEraseKinds(t, world, recorder.run.RunId)
	if len(gone) == 0 || slices.ContainsFunc(gone, func(kind sidecar.RecordKind) bool { return kind != sidecar.RecordKindSessionBlob }) {
		t.Fatalf("--blobs-only erased %v", gone)
	}
	if slices.Contains(stand, sidecar.RecordKindSessionBlob) || !slices.Contains(stand, sidecar.RecordKindSessionEntry) {
		t.Fatalf("after --blobs-only: %v", stand)
	}
}

// Erasing a session entry by id erases its parts' blobs; the plan, before anything is erased, lists them, the run's
// nodes left without their item, a same_as node and one sharing the part's blobs, the call whose context it cuts, and
// a run that continues it.
func TestRecordEraseNodeErasesItsBlobsAndListsSameAs(t *testing.T) {
	world := newTestSessionAdminWorld(t)
	run := testSessionRun()
	system := testSessionMessage("system", "", "system", "Read files.")
	big := strings.Repeat("the same large file ", 2048)
	first := testSessionToolResult("first", "system", "evs_read", big, "", &sidecar.SessionToolResult{Name: "evs_read", BuiltIn: true})
	// the same file read again: its part names the first's blobs
	second := testSessionToolResult("second", "first", "evs_read", big, "", &sidecar.SessionToolResult{Name: "evs_read", BuiltIn: true})
	// an item the run holds already: a same_as node
	repeated := &sidecar.SessionNode{Key: "repeated", ParentKey: "second", Type: sidecar.SessionNodeMessage, Item: []byte(`{"message":{"content":"again","role":"user"},"type":"message"}`)}
	again := &sidecar.SessionNode{Key: "again", ParentKey: "repeated", Type: sidecar.SessionNodeMessage, Item: []byte(`{"message":{"content":"again","role":"user"},"type":"message"}`)}
	journaled := world.journalNodes(run, system, first, second, repeated, again)
	if journaled[4].SameAs == nil {
		t.Fatal("the repeated item is no same_as node")
	}
	call := &protocol.CallContext{InputNodeId: journaled[4].NodeId.Bytes(), SystemNodeId: journaled[0].NodeId.Bytes(), RequestSha256: make([]byte, 32),
		Renderer: sidecar.SessionRendererHarness1}
	callRef := testRecordAppend(t, world.record, &sidecar.RecordDraft{Kind: sidecar.RecordKindModelCall, Source: sidecar.RecordSourceObserved, RunId: &run.RunId,
		Body: &protocol.ModelCallBody{Model: "local-test-model-high", Provider: "local", Route: sidecar.RecordModelCallRouteLocal, Context: call}})
	continuer := sidecar.NewId()
	testRecordAppend(t, world.record, &sidecar.RecordDraft{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceObserved, RunId: &continuer,
		Body: &protocol.ContextBody{Stage: 2, Harness: sidecar.HarnessRunHarnessName, ContinuesRunId: run.RunId.Bytes(), ContinuesEntryId: journaled[4].Entry.EntryId.Bytes()}})
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	firstEntry := journaled[1].Entry.EntryId
	repeatedEntry := journaled[3].Entry.EntryId
	spec := &sidecar.SessionPruneSpec{EntryIds: []sidecar.Id{firstEntry, repeatedEntry}}
	plan, err := world.record.SessionPrunePlan(t.Context(), spec, false)
	if err != nil {
		t.Fatal(err)
	}
	blobs := 0
	for _, item := range plan.Items {
		if item.Kind == sidecar.RecordKindSessionBlob.String() {
			blobs += 1
		}
	}
	if blobs == 0 || len(plan.Items) != 2+blobs {
		t.Fatalf("the plan's items: %+v", plan.Items)
	}
	secondEntry, againEntry := journaled[2].Entry.EntryId, journaled[4].Entry.EntryId
	if !slices.Contains(plan.Impact.SameAs, secondEntry) || !slices.Contains(plan.Impact.SameAs, againEntry) {
		t.Fatalf("the plan's same_as: %v, not %s and %s", plan.Impact.SameAs, secondEntry, againEntry)
	}
	if !slices.Equal(plan.Impact.Calls, []sidecar.Id{callRef.EntryId}) || !slices.Equal(plan.Impact.Runs, []sidecar.Id{continuer}) {
		t.Fatalf("the plan's calls %v and runs %v", plan.Impact.Calls, plan.Impact.Runs)
	}
	if gone, _ := testRecordEraseKinds(t, world, run.RunId); len(gone) != 0 {
		t.Fatal("a plan erased something")
	}
	if _, err := world.record.SessionPrune(t.Context(), spec, true, false); err != nil {
		t.Fatal(err)
	}
	gone, _ := testRecordEraseKinds(t, world, run.RunId)
	if len(gone) != 2+blobs {
		t.Fatalf("erased %v", gone)
	}
	for _, entry := range testSessionCapRead(t, world, run.RunId) {
		if bytes.Equal(entry.EntryId.Bytes(), secondEntry.Bytes()) && entry.State.KeyGone() {
			t.Fatal("the node sharing the blobs was erased itself")
		}
	}
}
