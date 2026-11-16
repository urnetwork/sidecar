//go:build sidecar_testhooks

// Evacuation over the reseed records the reseed route's own attempts leave at its barriers (the owner's answer
// QD-872; evacuate_resolve.go, resolve.go): a re-seeded push whose rerun a live push's commit refused leaves a record
// its ref's history never commits, which is fenced and dropped at 25 h with its minute's batches, the committed
// records of those batches kept; and a re-seeded push a retry commits while its first attempt waits at its head CAS
// leaves two records, of which the one its version's entry names is kept and the other dropped as a second copy.

package evsservice

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// TestReseedRerunPastAConflictingLivePushIsRefused's schedule, then 25 h and an evacuation run, then 26 h more and
// another. The walk's re-seeded push appended its reseed record before its head CAS, lost the CAS to the writer's
// push and was refused 409 PATH_CONFLICT on the rerun, so the record names a push its ref's history never commits.
// The first run fences the ref, one head CAS that changes no version, drops that record as dead and deletes every
// batch of the minute, within §11.13's 26 h, and the four re-seeded versions' records and the writer's push record
// that shared those batches read from their parcel as their batches held them. The second run finds nothing.
func TestEvacuationDropsTheReseedRecordOfARerunALivePushRefused(t *testing.T) {
	evacuate := newEvacuateFixture(t, nil)
	fixture, device, history := reseedLivePushRaceOn(reseedFixtureOf(evacuate.pushFixture))
	check := fixture.check
	ref, status, reached := fixture.walkPastALivePush(device, func(plan *sidecar.EvsPushPlan) {
		plan.Changes = append(plan.Changes, check.change(plan, checkTestPath("a"), 1, 2))
	})
	evsError, ok := sidecar.EvsErrorOf(ref.Stopped)
	if status != http.StatusOK || reached != 1 || !ok || evsError.Code != protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT || ref.Version != 4 {
		t.Fatalf("the writer's push answered %d, and the walk ended at %d after %d head CASes, stopped by %v", status, ref.Version, reached, ref.Stopped)
	}
	before := fixture.head()
	if before.Version() != 5 || before.Head.GetFenceMs() != 0 {
		t.Fatalf("head at %d with fence_ms %d", before.Version(), before.Head.GetFenceMs())
	}
	committed := []*sidecar.EvsBatchRecord{}
	for version := uint64(1); version <= 5; version += 1 {
		committed = append(committed, fixture.recordAt(check.refId, version))
	}
	batchKeys := evacuate.keys("meta-1", batchKeyPrefix)
	if len(batchKeys) == 0 {
		t.Fatal("no batch to evacuate")
	}

	evacuate.age()
	result := evacuate.mustRun()
	if result.FenceCount != 1 || result.DeadCount != 1 || result.KeptCount != 5 || result.DuplicateCount != 0 || result.WaitingCount != 0 ||
		result.MinuteWaitingCount != 0 || result.BatchDeletedCount != len(batchKeys) || result.SlotKeptCount != 0 || result.HasBatches {
		t.Fatalf("result at 25 h %+v", result)
	}
	if keys := evacuate.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("batches left at 25 h: %v", keys)
	}
	after := fixture.head()
	if after.Version() != 5 || after.Head.GetFence() != before.Head.GetFence()+1 || after.Head.GetFenceMs() != fixture.clock.Now().UnixMilli() ||
		!bytes.Equal(after.Head.GetPushId(), before.Head.GetPushId()) || len(after.Head.GetRefused()) != 0 {
		t.Fatalf("the fence left version %d fence %d fence_ms %d", after.Version(), after.Head.GetFence(), after.Head.GetFenceMs())
	}
	for i, want := range committed {
		got := fixture.recordAt(check.refId, uint64(i+1))
		if got.Type != want.Type || got.PushId != want.PushId || !bytes.Equal(got.Body, want.Body) {
			t.Fatalf("version %d's record reads other bytes from its parcel", i+1)
		}
	}
	if committed[3].Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || committed[4].Type != protocol.EvsBatchRecordType_EVS_BATCH_PUSH {
		t.Fatalf("versions 4 and 5 are %s and %s records", committed[3].Type, committed[4].Type)
	}

	fixture.clock.Advance(26 * time.Hour)
	again := evacuate.mustRun()
	if again.MinuteCount != 0 || again.BatchCount != 0 || again.FenceCount != 0 || again.WaitingCount != 0 || again.MinuteWaitingCount != 0 || again.HasBatches {
		t.Fatalf("result 26 h on %+v", again)
	}
	if head := fixture.head(); head.Etag != after.Etag {
		t.Fatal("the second run wrote the head")
	}
	// the re-seeded push, sent again, is still refused at 5g, before step 6, so it leaves no record
	requireRefusal(t, fixture.reseed(history.bodies[4]), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	if keys := evacuate.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("the refused push wrote batches: %v", keys)
	}
}

// A re-seeded push committed through a retry: its first attempt appended its reseed record and waits at its head
// CAS, the device's retry of the call runs whole, appending a record of its own and committing version 2 at that
// record's place, and the first attempt's CAS then fails, finds the push committed and answers its version. Past
// 25 h the record the version's entry names leaves for a parcel as its batch held it, and the first attempt's, a
// second copy at a place the history does not name, is dropped as a push's is, with no fence raised. The call sent
// again answers the version from the parcel.
func TestEvacuationKeepsTheRecordAReseedRetryCommitted(t *testing.T) {
	evacuate := newEvacuateFixture(t, nil)
	fixture := reseedFixtureOf(evacuate.pushFixture)
	check := fixture.check
	first := fixture.kept()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(first)), 1)
	next := fixture.kept()
	fixture.create(next, "b")
	body := fixture.reseedBody(next)
	retried := 0
	reached := atBarrierOnce(t, BarrierHeadCasBefore, barrierRefKey(check.repoId, check.refId), func() {
		retried = fixture.reseed(body).Code
	})
	recorder := fixture.reseed(body)
	sidecar.SetTestHooks(nil)
	if retried != http.StatusOK || *reached != 1 {
		t.Fatalf("the retry answered %d, and the first attempt reached %d head CASes", retried, *reached)
	}
	fixture.requireCommitted(recorder, 2)
	fixture.awaitStepEights()
	head := fixture.head()
	if head.Version() != 2 {
		t.Fatalf("head at %d", head.Version())
	}
	committed := fixture.recordAt(check.refId, 2)

	evacuate.age()
	result := evacuate.mustRun()
	if result.KeptCount != 2 || result.DuplicateCount != 1 || result.DeadCount != 0 || result.FenceCount != 0 || result.WaitingCount != 0 ||
		result.MinuteWaitingCount != 0 || result.HasBatches {
		t.Fatalf("result %+v", result)
	}
	if keys := evacuate.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("batches left: %v", keys)
	}
	if after := fixture.head(); after.Etag != head.Etag {
		t.Fatal("the run wrote the head")
	}
	kept := fixture.recordAt(check.refId, 2)
	if kept.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || kept.PushId != committed.PushId || !bytes.Equal(kept.Body, committed.Body) {
		t.Fatalf("version 2's record from its parcel is type %s", kept.Type)
	}
	fixture.requireCommitted(fixture.reseed(body), 2)
	if keys := evacuate.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("the call sent again wrote batches: %v", keys)
	}
}
