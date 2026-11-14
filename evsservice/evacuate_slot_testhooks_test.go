//go:build sidecar_testhooks

// DESIGN-DETAILS 14.6's schedules at the push route's barriers, with evacuation's delete of a dead record's own
// slots on, each ending 26 h on with the evacuation run and the committed version's slot read back
// (evacuate_slot_test.go's helpers):
//
//	A      a PATH_EPOCH commits between an honest push's step 6 and its step 7: its record is written and its slot
//	       created under its origin, its step 7 fails and its recheck refuses it 412 PATH_EPOCH; its retoken takes
//	       the slot over after the settle age and commits, and evacuation keeps the slot, the retoken's
//	B      another writer lists a committed version's young slot with its bytes and is refused 409 SLOT_STALE at its
//	       own step 6's slot round, before any record of its own (QD-806's order), while a push of its own commits
//	       at the barrier after it; evacuation finds nothing of it and keeps the slot
//	slept  an attempt held between its slots and its record past 25 h (QD-806's order): evacuation finds no record of
//	       it and leaves its slot, one no record names; released, it appends its record, which its step 7 cannot
//	       commit, and 26 h on evacuation deletes the dead record's own settled slot with it
//
// In QD-806's order an attempt's record never comes before its slots, so 14.5's late slot PUT, stored after its record
// left, and an attempt's own slot found unsettled at its record's evacuation no longer arise from one attempt; the
// unsettled row stays held by evacuate_slot_test.go's row test and the NoSettle twin (slot_twins_testhooks_test.go).

package evsservice

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
// round finds the committed statement's origin and refuses it 409 SLOT_STALE, recorded, before any step 7 and before
// any record of its own (QD-806's order), while a push of its own creating the same path commits at the barrier after
// its step 6. 26 h on, evacuation finds the two committed records alone and the slot stands, another statement's.
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

	// the re-listing left no record, and the two committed ones are kept
	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 0 && result.KeptCount == 2 && result.SlotForeignCount == 0 && result.SlotDeletedCount == 0
	})
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{1: checkTestPath("a")}, checkTestPath("a"), slotId, slotBody)
}

// The slept attempt, in QD-806's order: an attempt passes its slot round and is held before its record's append
// while 25 h pass, its slot standing under its origin with no record naming it; evacuation, run then, finds no record
// of it, keeps the other commit's and deletes nothing. Released, the attempt appends its record, a day younger than
// its slot, and its step 7, past 5 s of its step 4, reruns step 5, which refuses a statement past its time bound, so
// it never commits. 26 h on, its record is dead and evacuation deletes its own settled slot with it: where the order
// 14.5 was written on left a slot stored after its record had left, nothing is left here.
func TestEvacuationDeletesTheSlotOfAnAttemptThatSleptBeforeItsRecord(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	fixture.commitCached("x")
	slotId, _, slotBody := checkTestSlot(t, "slept")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("slept"), slotId, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	before := fixture.head()

	// the hook runs on the attempt's goroutine, so it only records what the run did
	var evacuated *EvacuationResult
	var evacuatedErr error
	slotStanding := false
	evacuator := fixture.evacuator()
	reached := atBarrierOnce(t, BarrierPushRecordBefore, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		fixture.age()
		evacuated, evacuatedErr = evacuator.Run(fixture.ctx, "meta-1")
		_, held, _, found := fixture.slotObject(slotId)
		slotStanding = found && held == origin
	})
	recorder := fixture.post(fixture.token(fixture.check.signerId), body)
	sidecar.SetTestHooks(nil)
	if *reached != 1 || evacuated == nil || evacuatedErr != nil {
		t.Fatalf("the attempt reached its record's append %d times: %v", *reached, evacuatedErr)
	}
	if evacuated.DeadCount != 0 || evacuated.KeptCount != 1 || evacuated.SlotAbsentCount != 0 || evacuated.SlotDeletedCount != 0 || !slotStanding {
		t.Fatalf("result %+v, the slot standing %t", evacuated, slotStanding)
	}
	if recorder.Code == http.StatusOK {
		t.Fatal("the slept attempt committed")
	}
	if head := fixture.head(); head.Version() != before.Version() {
		t.Fatalf("the slept attempt committed at %d", head.Version())
	}
	fixture.requireSlotOrigin(slotId, slotBody, origin)
	if records := fixture.batchRecords(); len(records) != 1 {
		t.Fatalf("%d records after the release, its own alone wanted", len(records))
	}

	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 1 && result.SlotDeletedCount == 1
	})
	if _, _, _, found := fixture.slotObject(slotId); found {
		t.Fatal("the dead record's own settled slot stands")
	}
}
