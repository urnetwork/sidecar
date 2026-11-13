//go:build sidecar_testhooks

// DESIGN-DETAILS 14.6's schedules A and B for 14.2.8's interim (QD-766) at the push route's barriers, where a
// commit lands between a push's step 6 and its step 7: the push's own attempt has written its record and taken its
// slot, and its step 7 then fails and its recheck refuses it. Each ends, 26 h on, with the evacuation run and the
// committed version's slot read back (evacuate_slot_test.go's helpers).

package evsservice

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A at the barriers: an honest push passes step 6, its record and new slot written, and a PATH_EPOCH commits before
// its step 7, whose condition then fails; its recheck on the new head refuses it 412 PATH_EPOCH. Its retoken, a new
// push id carrying the same slot id and bytes in epoch 2, finds the slot at its step 6, equal bytes under 23 h, and
// commits. 26 h on, evacuation drops the refused statement's record, which lists the slot, and the slot stands for
// the version the retoken committed.
func TestEvacuationKeepsTheSlotOfARetokenWhoseRefusedAttemptPassedStepSix(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	commitment := fixture.crossRemove(false)
	fixture.awaitStepEights()
	source := fixture.head()
	parts, mapSha256 := fixture.mapPartsAt(2, source.Version(), source.Head.GetChain(), []*protocol.EvsPathMove{pathEpochTestMoveAt(2, []uint64{1}, "a")})
	fixture.uploadParts(parts, mapSha256)
	cutOver := fixture.pathEpochPlanAt(2, 2, commitment, mapSha256, source.Version(), source.Head.GetChain())
	slotId, _, slotBody := checkTestSlot(t, "retoken at the barrier")
	refused := fixture.planAtTwo(commitment)
	fixture.createWithSlot(refused, checkTestPath("s"), slotId, slotBody)

	var cutOverRecorder *httptest.ResponseRecorder
	reached := atBarrierOnce(t, BarrierPushStep6After, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		cutOverRecorder = fixture.push(cutOver)
	})
	requireRefusal(t, fixture.push(refused), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)
	if *reached != 1 || cutOverRecorder == nil {
		t.Fatalf("the refused push passed step 6 %d times", *reached)
	}
	fixture.requireCommitted(cutOverRecorder, 3)
	// the refused attempt's step 6 wrote the slot
	fixture.requireSlot(slotId, slotBody)

	retoken := fixture.planOnHead(2, commitment)
	fixture.createWithSlot(retoken, epochPath(2, "s"), slotId, slotBody)
	retoken.Changes[0].SourcePaths = [][]byte{epochSourcePath(t, 1, "s")}
	fixture.requireCommitted(fixture.push(retoken), 4)
	fixture.awaitStepEights()

	// the refused statement's record is dead, and the four committed ones are kept
	fixture.requireEvacuatedKeepingSlots(1, 4)
	fixture.requireSlot(slotId, slotBody)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "s"), 1: checkTestPath("s")}, epochPath(2, "s"), slotId, slotBody)
}

// B's race at the barriers: another writer lists a committed version's young slot as new with its bytes, and its
// slot round takes the object; before its step 7 a push of its own creates the same path and commits, so its step 7's
// condition fails and its recheck refuses it 409 PATH_CONFLICT. 26 h on, evacuation drops its record, which lists the
// slot, and the slot stands with the committed version's bytes.
func TestEvacuationKeepsACommittedVersionsSlotARefusedRelistingTookAtStepSix(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "committed at the barrier")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), slotId, slotBody)
	fixture.requireCommitted(fixture.push(committed), 1)
	fixture.awaitStepEights()

	relisting := fixture.plan()
	fixture.createWithSlot(relisting, checkTestPath("b"), slotId, slotBody)
	race := fixture.plan()
	fixture.create(race, "b")
	var raceRecorder *httptest.ResponseRecorder
	reached := atBarrierOnce(t, BarrierPushStep6After, barrierRefKey(fixture.check.repoId, fixture.check.refId), func() {
		raceRecorder = fixture.pushAsOther(race)
	})
	requireRefusal(t, fixture.pushAsOther(relisting), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
	if *reached != 1 || raceRecorder == nil {
		t.Fatalf("the re-listing passed step 6 %d times", *reached)
	}
	fixture.requireCommitted(raceRecorder, 2)
	fixture.awaitStepEights()
	fixture.requireSlot(slotId, slotBody)

	// the re-listing's record is dead, and the two committed ones are kept
	fixture.requireEvacuatedKeepingSlots(1, 2)
	fixture.requireSlot(slotId, slotBody)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{1: checkTestPath("a")}, checkTestPath("a"), slotId, slotBody)
}
