//go:build sidecar_testhooks

package evsservice

import (
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// DESIGN-DETAILS 2.2.3's three rules at their barriers (EVSB-M2-24): the fence of a ref with no head against a
// creating push, in both orders, and the record before the head write. Each hook runs once, at the barrier it
// names, with the hooks off while it runs.

// Runs act the first time the barrier name is reached on key, and returns how many times it was reached.
func atBarrierOnce(t *testing.T, name string, key string, act func()) *int {
	t.Helper()
	reached := new(int)
	var hooks *sidecar.TestHooks
	hooks = &sidecar.TestHooks{Barrier: func(barrierName string, barrierKey string) {
		if barrierName != name || barrierKey != key {
			return
		}
		*reached += 1
		if *reached == 1 {
			sidecar.SetTestHooks(nil)
			act()
			sidecar.SetTestHooks(hooks)
		}
	}}
	sidecar.SetTestHooks(hooks)
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	return reached
}

// A creating attempt that held the absent head when evacuation fenced the ref: its If-None-Match fails on the
// placeholder, it reads the placeholder, finds fence_ms past its own arrival and ends 503 unknown. Nothing commits,
// and the placeholder stands.
func TestCreatingPushThatHeldTheAbsentHeadEndsUnknownAtTheFence(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	token := fixture.token(fixture.check.signerId)
	refKey := barrierRefKey(fixture.check.repoId, fixture.check.refId)
	paid := fixture.paidContext()
	var fenceErr error
	atBarrierOnce(t, BarrierHeadCasBefore, refKey, func() {
		_, fenceErr = fixture.engine.heads.RaiseFence(paid, fixture.cluster, fixture.check.repoId, fixture.check.refId)
	})
	recorder := fixture.post(token, body)
	if fenceErr != nil {
		t.Fatalf("the fence: %v", fenceErr)
	}
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if refusalOf(t, recorder).GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
		t.Fatal("a creating attempt ended at the fence with an outcome other than unknown")
	}
	head := fixture.head()
	if head.Absent() || head.Version() != 0 || head.Head.GetFence() != 1 || head.Head.GetFenceMs() == 0 {
		t.Fatalf("the head after the fenced create: %v", head.Head)
	}
}

// The other order: a first commit lands between the fence's read of the absent head and its creation. The creation
// answers 412, and the fence rereads and fences the head it finds by If-Match, moving no version.
func TestRaiseFenceOnARefCreatedMeanwhileFencesTheHeadItFinds(t *testing.T) {
	fixture := newHeadFixture(t)
	refKey := barrierRefKey(fixture.repoId, fixture.refId)
	var commitErr error
	reached := atBarrierOnce(t, BarrierHeadCasBefore, refKey, func() {
		_, commitErr = fixture.heads.Commit(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId, &EvsStoredHead{}, testHead(1, 1))
	})
	fenced, err := fixture.heads.RaiseFence(fixture.ctx, fixture.cluster, fixture.repoId, fixture.refId)
	if commitErr != nil || err != nil {
		t.Fatalf("the first commit and the fence: %v, %v", commitErr, err)
	}
	if fenced.Version() != 1 || fenced.Head.GetFence() != testHead(1, 1).GetFence()+1 || fenced.Head.GetFenceMs() != fixture.clock.Now().UnixMilli() {
		t.Fatalf("fenced %v", fenced.Head)
	}
	// the creation that lost, and the If-Match that fenced
	if *reached != 2 {
		t.Fatalf("%d head writes by the fence, want the create that lost and one If-Match", *reached)
	}
}

// FS-59's paused push on a ref with no head: a creating push writes its record and pauses before its head write.
// More than 25 h later evacuation finds the record pending on a ref with no head, fences the ref by a placeholder
// head, resolves the record dead and drops it with its batch. The push then issues its create: it fails on the
// placeholder, and the attempt ends 503 unknown at the fence. No head ever names what the push carried.
func TestEvacuationFenceEndsACreatingPushPausedBeforeItsHeadWrite(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	refKey := barrierRefKey(fixture.check.repoId, fixture.check.refId)
	var result *EvacuationResult
	var runErr error
	atBarrierOnce(t, BarrierHeadCasBefore, refKey, func() {
		if keys := fixture.keys("meta-1", batchKeyPrefix); len(keys) != 1 {
			t.Errorf("the paused push's record is in %d batches", len(keys))
		}
		fixture.age()
		result, runErr = fixture.run()
	})
	recorder := fixture.post(fixture.token(fixture.check.signerId), body)
	if runErr != nil || result == nil {
		t.Fatalf("the evacuation run: %v", runErr)
	}
	if result.FenceCount != 1 || result.DeadCount != 1 || result.KeptCount != 0 || result.BatchDeletedCount != 1 {
		t.Fatalf("result %+v", result)
	}
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if refusalOf(t, recorder).GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
		t.Fatal("the paused push ended at the fence with an outcome other than unknown")
	}
	head := fixture.head()
	if head.Absent() || head.Version() != 0 || head.Head.GetFence() != 1 {
		t.Fatalf("the head after the paused push woke: %v", head.Head)
	}
	if keys := fixture.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("batches %v", keys)
	}
	if keys := append(fixture.keys("meta-1", parcelKeyPrefix), fixture.keys("meta-1", pidxKeyPrefix)...); len(keys) != 0 {
		t.Fatalf("a dead push's record was kept: %v", keys)
	}
}

// The record rule's order: step 7's window is checked after the record's write. A batch write that lands only as
// the window from step 4's reads passes sends the attempt back to steps 4 and 5 with no head write issued on the old
// reads, and it then commits.
func TestStepSevenWindowIsCheckedAfterTheRecordsWrite(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	refKey := barrierRefKey(fixture.check.repoId, fixture.check.refId)
	stepSixes, headWrites, headWritesAtSlowBatch := 0, 0, -1
	advanced := false
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		switch {
		case name == BarrierPushStep6Before && key == refKey:
			stepSixes += 1
		case name == BarrierHeadCasBefore && key == refKey:
			headWrites += 1
		case name == BarrierBatchPutAfter && !advanced:
			// the record's write took the whole of step 7's window
			advanced = true
			headWritesAtSlowBatch = headWrites
			fixture.clock.Advance(fixture.settings.PushStepSevenWindow)
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), body), 1)
	if !advanced || headWritesAtSlowBatch != 0 {
		t.Fatalf("a head write was issued before the record's write: %d", headWritesAtSlowBatch)
	}
	if stepSixes != 2 || headWrites != 1 {
		t.Fatalf("%d step 6s and %d head writes, want a rerun of steps 4 and 5 and one head write", stepSixes, headWrites)
	}
}

// An attempt past step 4 when its process's clock turned unsure opens no batch: it writes no record, issues no head
// write and ends 503.
func TestPushPastStepFourOpensNoBatchOnceTheClockTurnsUnsure(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	refKey := barrierRefKey(fixture.check.repoId, fixture.check.refId)
	headWrites := 0
	turned := false
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		switch {
		case name == BarrierPushStep6Before && key == refKey && !turned:
			turned = true
			fixture.host.ClockCheck.SetUnknown()
		case name == BarrierHeadCasBefore && key == refKey:
			headWrites += 1
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	recorder := fixture.post(fixture.token(fixture.check.signerId), body)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if !turned || headWrites != 0 {
		t.Fatalf("turned %t, %d head writes", turned, headWrites)
	}
	if !fixture.head().Absent() {
		t.Fatal("a head was written")
	}
	if keys, _, err := fixture.cluster.List(fixture.ctx, batchKeyPrefix, "", 10); err != nil || len(keys) != 0 {
		t.Fatalf("batches opened on an unsure clock: %v, %v", keys, err)
	}
}
