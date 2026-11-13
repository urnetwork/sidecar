//go:build sidecar_testhooks

// DESIGN-DETAILS 14.6's schedules at the push route's barriers, with evacuation's delete of a dead record's own
// slots on, each ending 26 h on with the evacuation run and the committed version's slot read back
// (evacuate_slot_test.go's helpers):
//
//	A      a PATH_EPOCH commits between an honest push's step 6 and its step 7: its record is written and its slot
//	       created under its origin, its step 7 fails and its recheck refuses it 412 PATH_EPOCH; its retoken takes
//	       the slot over after the settle age and commits, and evacuation keeps the slot, the retoken's
//	B      another writer lists a committed version's young slot with its bytes and is refused 409 SLOT_STALE at its
//	       own step 6, while a push of its own commits at the barrier after it; evacuation keeps the slot
//	late   an attempt held between its record and its slot PUT past 26 h: evacuation drops its record and finds no
//	       slot, the PUT then stores one that nothing deletes, and its step 7 ends on the fence; held instead just
//	       after its PUT, its slot is unsettled when evacuation HEADs it, and stays

package evsservice

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A at the barriers: an honest push passes step 6, its record and new slot written under its origin, and a PATH_EPOCH
// commits before its step 7, whose condition then fails; its recheck on the new head refuses it 412 PATH_EPOCH. Its
// retoken, a new push id carrying the same slot id and bytes in epoch 2, waits out the settle age, takes the slot
// over and commits. 26 h on, evacuation drops the refused statement's record and keeps the slot, the retoken's.
func TestEvacuationKeepsTheSlotOfARetokenWhoseRefusedAttemptPassedStepSix(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	commitment := fixture.crossRemove(false)
	fixture.awaitStepEights()
	source := fixture.head()
	parts, mapSha256 := fixture.mapPartsAt(2, source.Version(), source.Head.GetChain(), []*protocol.EvsPathMove{pathEpochTestMoveAt(2, []uint64{1}, "a")})
	fixture.uploadParts(parts, mapSha256)
	cutOver := fixture.pathEpochPlanAt(2, 2, commitment, mapSha256, source.Version(), source.Head.GetChain())
	slotId, _, slotBody := checkTestSlot(t, "retoken at the barrier")
	refused := fixture.planAtTwo(commitment)
	fixture.createWithSlot(refused, checkTestPath("s"), slotId, slotBody)
	refusedBody, refusedOrigin := fixture.bodyAndOrigin(refused)
	token := fixture.token(fixture.check.signerId)

	var cutOverRecorder *httptest.ResponseRecorder
	reached := atBarrierOnce(t, BarrierPushStep6After, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		cutOverRecorder = fixture.push(cutOver)
	})
	requireRefusal(t, fixture.post(token, refusedBody), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)
	if *reached != 1 || cutOverRecorder == nil {
		t.Fatalf("the refused push passed step 6 %d times", *reached)
	}
	fixture.requireCommitted(cutOverRecorder, 3)
	sidecar.SetTestHooks(nil)
	// the refused attempt's step 6 created the slot under its origin
	fixture.requireSlotOrigin(slotId, slotBody, refusedOrigin)
	_, _, storedAt, _ := fixture.slotObject(slotId)

	retoken := fixture.planOnHead(2, commitment)
	fixture.createWithSlot(retoken, epochPath(2, "s"), slotId, slotBody)
	retoken.Changes[0].SourcePaths = [][]byte{epochSourcePath(t, 1, "s")}
	retokenBody, retokenOrigin := fixture.bodyAndOrigin(retoken)
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- fixture.post(token, retokenBody)
	}()
	settledAt := storedAt.Add(fixture.settings2().SlotSettleAge)
	fixture.awaitTimerAt(settledAt)
	fixture.clock.AdvanceTo(settledAt)
	fixture.requireCommitted(<-answered, 4)
	fixture.awaitStepEights()

	// the refused statement's record is dead, and the four committed ones are kept
	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 1 && result.KeptCount == 4 && result.SlotForeignCount == 1 && result.SlotDeletedCount == 0
	})
	fixture.requireSlotOrigin(slotId, slotBody, retokenOrigin)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "s"), 1: checkTestPath("s")}, epochPath(2, "s"), slotId, slotBody)
}

// B's race at the barriers: another writer lists a committed version's young slot as new with its bytes. Its slot
// round finds the committed statement's origin and refuses it 409 SLOT_STALE, recorded, before any step 7, while a
// push of its own creating the same path commits at the barrier after its step 6. 26 h on, evacuation drops its
// record and keeps the slot, another statement's.
func TestEvacuationKeepsACommittedVersionsSlotARefusedRelistingListed(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	slotId, _, slotBody := checkTestSlot(t, "committed at the barrier")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 1)
	fixture.awaitStepEights()

	relisting := fixture.plan()
	fixture.createWithSlot(relisting, checkTestPath("b"), slotId, slotBody)
	race := fixture.plan()
	fixture.create(race, "b")
	var raceRecorder *httptest.ResponseRecorder
	reached := atBarrierOnce(t, BarrierPushStep6After, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		raceRecorder = fixture.pushAsOther(race)
	})
	requireRefusal(t, fixture.pushAsOther(relisting), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	if *reached != 1 || raceRecorder == nil {
		t.Fatalf("the re-listing passed step 6 %d times", *reached)
	}
	fixture.requireCommitted(raceRecorder, 2)
	sidecar.SetTestHooks(nil)
	fixture.awaitStepEights()
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)

	// the re-listing's record is dead, and the two committed ones are kept
	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 1 && result.KeptCount == 2 && result.SlotForeignCount == 1 && result.SlotDeletedCount == 0
	})
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{1: checkTestPath("a")}, checkTestPath("a"), slotId, slotBody)
}

// The late slot PUT, stored after its record (14.5's first leak): an attempt passes step 6's record and is held
// before its slot PUT while 26 h pass and evacuation fences the ref, finds the record dead and its slot absent, and
// drops the record with its batch. The PUT then stores the slot under the attempt's origin, its step 7 ends 503
// unknown on the fence, and nothing deletes the slot: a later run finds no batch.
func TestEvacuationLeavesASlotStoredAfterItsDeadRecordLeft(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	fixture.commitCached("x")
	slotId, _, slotBody := checkTestSlot(t, "late put")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("late"), slotId, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	before := fixture.head()

	// the hook runs on the attempt's slot goroutine, so it only records what the run did
	var evacuated *EvacuationResult
	var evacuatedErr error
	evacuator := fixture.evacuator()
	reached := atBarrierOnce(t, BarrierPushSlotPutBefore, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		fixture.age()
		evacuated, evacuatedErr = evacuator.Run(fixture.ctx, "meta-1")
	})
	recorder := fixture.post(fixture.token(fixture.check.signerId), body)
	sidecar.SetTestHooks(nil)
	if *reached != 1 || evacuated == nil || evacuatedErr != nil {
		t.Fatalf("the attempt reached its slot PUT %d times: %v", *reached, evacuatedErr)
	}
	if evacuated.DeadCount != 1 || evacuated.KeptCount != 1 || evacuated.FenceCount != 1 || evacuated.SlotAbsentCount != 1 || evacuated.HasBatches {
		t.Fatalf("result %+v", evacuated)
	}
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if refusalOf(t, recorder).GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
		t.Fatal("the late attempt's outcome is not unknown")
	}
	if head := fixture.head(); head.Version() != before.Version() {
		t.Fatalf("the late attempt committed at %d", head.Version())
	}
	fixture.requireSlotOrigin(slotId, slotBody, origin)
	fixture.clock.Advance(time.Hour)
	if result := fixture.mustRun(); result.BatchCount != 0 || result.SlotDeletedCount != 0 {
		t.Fatalf("a later run %+v", result)
	}
	fixture.requireSlotOrigin(slotId, slotBody, origin)
}

// The late slot PUT, unsettled: the attempt is held before its PUT while 25 h pass, and again just after it, when
// evacuation fences the ref and HEADs the dead record's slot: its own origin, stored within the settle age, so it
// stays, counted unsettled. The attempt's step 7 ends 503 unknown on the fence.
func TestEvacuationKeepsTheUnsettledSlotOfAnAttemptThatSlept(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	fixture.commitCached("x")
	slotId, _, slotBody := checkTestSlot(t, "unsettled put")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("unsettled"), slotId, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	refKey := barrierRefKey(fixture.check.repoId, fixture.check.refId)

	// the hooks run on the attempt's slot goroutine, so they only record what the run did
	var evacuated *EvacuationResult
	var evacuatedErr error
	evacuator := fixture.evacuator()
	var hooks *sidecar.TestHooks
	hooks = &sidecar.TestHooks{Barrier: func(name string, key string) {
		if key != refKey {
			return
		}
		switch name {
		case BarrierPushSlotPutBefore:
			fixture.age()
		case BarrierPushSlotPutAfter:
			sidecar.SetTestHooks(nil)
			evacuated, evacuatedErr = evacuator.Run(fixture.ctx, "meta-1")
			sidecar.SetTestHooks(hooks)
		}
	}}
	sidecar.SetTestHooks(hooks)
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	recorder := fixture.post(fixture.token(fixture.check.signerId), body)
	sidecar.SetTestHooks(nil)
	if evacuated == nil || evacuatedErr != nil || evacuated.DeadCount != 1 || evacuated.SlotUnsettledCount != 1 || evacuated.SlotDeletedCount != 0 || evacuated.HasBatches {
		t.Fatalf("result %+v %v", evacuated, evacuatedErr)
	}
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.requireSlotOrigin(slotId, slotBody, origin)
}
