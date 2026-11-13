//go:build sidecar_testhooks

// DESIGN-DETAILS 14.6's step 6 rows and schedules that hold an attempt between two of its steps, at the push route's
// barriers (push_slot_test.go's helpers):
//
//	two retokens  two retokens of one refused statement, the first held at its takeover's DELETE while the second
//	              takes the slot over and commits: the first's DELETE names the refused statement's LastModified and
//	              answers 412, its create answers 412 on the second's object, and it is refused 409 SLOT_STALE; the
//	              committed retoken's slot stands at 26 h
//	5a first      an attempt that passed step 5 before its own statement committed finds at its slot round its own
//	              object rewritten by an ERASE, or another statement's object created after its version's removal,
//	              and is answered its 200 by the cluster read and 5a, never a refusal (I-EVS-3)

package evsservice

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Two retokens of one refused statement, its object settled: the first reaches its takeover's DELETE and is held
// there while the second takes the object over, creates its own and commits. The first's DELETE names the refused
// statement's LastModified and the store answers 412, the second's object being a second or more younger; its create
// again answers 412 and its GET finds the second's origin, in its own epoch and so not takeable: 409 SLOT_STALE. At
// 26 h evacuation drops the refused first's record and keeps the committed second's slot.
func TestPushSlotTwoRetokensOfOneStatementOneTakesOverTheOtherIsRefused(t *testing.T) {
	takeover := newTakeoverCase(t, "two retokens", true, nil)
	fixture := takeover.fixture
	evacuation := &evacuateFixture{pushFixture: fixture, settings: DefaultEvacuatorSettings()}
	evacuation.settings.SpoolDirectory = t.TempDir()
	evacuation.settings.DeleteDeadSlots = true
	firstBody, _ := fixture.bodyAndOrigin(takeover.retoken("s"))
	secondBody, secondOrigin := fixture.bodyAndOrigin(takeover.retoken("t"))
	token := fixture.token(fixture.check.signerId)

	// the refused statement's object is settled, so the second's whole push runs inside the hook, on the first's
	// slot goroutine, which is held at its DELETE meanwhile
	var secondRecorder *httptest.ResponseRecorder
	reached := atBarrierOnce(t, BarrierPushSlotTakeBefore, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		secondRecorder = fixture.post(token, secondBody)
	})
	firstRecorder := fixture.post(token, firstBody)
	sidecar.SetTestHooks(nil)
	if *reached < 1 || secondRecorder == nil {
		t.Fatalf("the takeover's DELETE was reached %d times", *reached)
	}
	fixture.requireCommitted(secondRecorder, 4)
	requireRefusal(t, firstRecorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	fixture.awaitStepEights()
	fixture.requireSlotOrigin(takeover.slotId, takeover.slotBody, secondOrigin)

	evacuation.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 1 && result.SlotForeignCount == 1 && result.SlotDeletedCount == 0
	})
	fixture.requireSlotOrigin(takeover.slotId, takeover.slotBody, secondOrigin)
}

// 14.2.3's own-origin row answered by 5a: an attempt of a push passes step 5 on a head that does not show the push
// committed and is held before step 6, while another attempt of the same statement commits, its slot created under
// the statement's origin, and an ERASE rewrites the slot without one of its keys, keeping the origin. The held
// attempt's create answers 412 and its GET finds its own origin with other bytes; the cluster read and 5a find the
// push committed, so it is answered 200 at the commit's version, and nothing alarms.
func TestPushSlotOwnObjectAnErasureRewroteIsAnsweredByFiveA(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	slotId, object, slotBody := eraseTestSlot(t, "own rewritten", 2)
	plan := fixture.plan()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"), EntryVersion: fixture.check.fileEntry(plan, 1, nil, slotId),
	})
	plan.NewObjects = append(plan.NewObjects, object)
	plan.SlotBodies = append(plan.SlotBodies, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	token := fixture.token(fixture.check.signerId)

	var otherRecorder, eraseRecorder *httptest.ResponseRecorder
	reached := atBarrierOnce(t, BarrierPushStep6Before, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		otherRecorder = fixture.post(token, body)
		eraseRecorder = fixture.slotsDelete(fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0}), "admin")
	})
	recorder := fixture.post(token, body)
	sidecar.SetTestHooks(nil)
	if *reached != 1 || otherRecorder == nil || eraseRecorder == nil {
		t.Fatalf("step 6 was reached %d times", *reached)
	}
	fixture.requireCommitted(otherRecorder, 1)
	fixture.requireCommitted(eraseRecorder, 1)
	fixture.requireCommitted(recorder, 1)
	stored, held, _, found := fixture.slotObject(slotId)
	if !found || held != origin || len(stored) == len(slotBody) {
		t.Fatalf("the rewritten slot: found %t, origin %+v, %d bytes", found, held, len(stored))
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v after erasing key 0", indexes)
	}
	if foreign, mismatch := fixture.slotCounts(); foreign != 0 || mismatch != 0 {
		t.Fatalf("counted %v foreign and %v mismatched", foreign, mismatch)
	}
}

// 14.2.3's anything-else row answered by 5a first: an attempt of a push passes step 5 before the push's other attempt
// commits, and is held before step 6 while the commit lands and its slot is deleted and created again under another
// writer's statement, as after the version's removal. The held attempt's GET finds that statement's origin, which it
// may not take over, and the cluster read and 5a find the push committed: 200, never SLOT_STALE.
func TestPushSlotAnotherStatementsObjectIsAnsweredTheCommitByFiveAFirst(t *testing.T) {
	fixture := newPushFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "recreated")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("a"), slotId, slotBody)
	body, origin := fixture.bodyAndOrigin(plan)
	token := fixture.token(fixture.check.signerId)
	another := origin
	another.PushId = testId("another statement")
	another.SignerSidecarId = fixture.check.otherId

	var otherRecorder *httptest.ResponseRecorder
	reached := atBarrierOnce(t, BarrierPushStep6Before, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		otherRecorder = fixture.post(token, body)
		if err := fixture.cluster.Delete(fixture.ctx, SlotKey(fixture.check.repoId, slotId)); err != nil {
			t.Fatal(err)
		}
		fixture.plantSlot(slotId, slotBody, another)
	})
	recorder := fixture.post(token, body)
	sidecar.SetTestHooks(nil)
	if *reached != 1 || otherRecorder == nil {
		t.Fatalf("step 6 was reached %d times", *reached)
	}
	fixture.requireCommitted(otherRecorder, 1)
	fixture.requireCommitted(recorder, 1)
	fixture.requireSlotOrigin(slotId, slotBody, another)
	if foreign, mismatch := fixture.slotCounts(); foreign != 0 || mismatch != 0 {
		t.Fatalf("counted %v foreign and %v mismatched", foreign, mismatch)
	}
}
