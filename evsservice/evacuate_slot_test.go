// DESIGN-DETAILS 14.6's schedules for 14.2.8's interim (QD-766), on T2's fakes through the push route and the
// hourly evacuation, each ending with every committed version's slot read back as a reader reads it:
//
//	A  an honest push passes step 6 and is refused 412 PATH_EPOCH once a PATH_EPOCH commits; its retoken, a new
//	   push id carrying the same slot id and bytes, takes the slot at its own step 6 and commits; 26 h on,
//	   evacuation drops the refused statement's record, which lists the slot, and the slot stands
//	B  another writer lists a committed version's slot as new, with other bytes and with its bytes, young and past
//	   23 h, in pushes that are refused or never let commit; 26 h on, evacuation drops each record, every one of
//	   which lists the slot, and the slot stands with the committed version's bytes
//
// The dead records go with their batches, as every dead record does: the interim keeps only their slots. Here A's
// first attempt is cut short after its step 6 and its retry is refused; evacuate_slot_testhooks_test.go refuses the
// attempt that passed step 6 itself, at the push route's barriers, and runs B's race. C and D, a second introduction
// and a citing deposit that a CONSUME then removes, stay open until 14.7's track 2, so they have no schedule here.

package evsservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The slot stands on the repo's cluster holding body.
func (self *pushFixture) requireSlot(slotId sidecar.Id, body []byte) {
	self.t.Helper()
	object, err := self.cluster.Get(self.ctx, SlotKey(self.check.repoId, slotId))
	if err != nil {
		self.t.Fatalf("slot %s: %v", slotId, err)
	}
	stored, err := readAllLimited(object, self.settings.SlotMaxByteCount)
	object.Body.Close()
	if err != nil || !bytes.Equal(stored, body) {
		self.t.Fatalf("slot %s holds other bytes: %v", slotId, err)
	}
}

// A creation of path at the plan's next version, its file naming slotId, which the push lists as new with body.
func (self *pushFixture) createWithSlot(plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath, slotId sidecar.Id, body []byte) {
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: path, EntryVersion: self.check.fileEntry(plan, plan.BaseVersion+1, nil, slotId),
	})
	plan.NewObjects = append(plan.NewObjects, &sidecar.EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()})
	plan.SlotBodies = append(plan.SlotBodies, body)
}

// plan pushed by the fixture's other writer, which signs it and names itself its signer.
func (self *pushFixture) pushAsOther(plan *sidecar.EvsPushPlan) *httptest.ResponseRecorder {
	self.t.Helper()
	plan.SignerSidecarId = self.check.otherId
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(self.check.otherKey, self.check.otherId)).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.post(self.token(self.check.otherId), &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload})
}

// A slot body other than checkTestSlot's: its one key's wrapped bytes all fill.
func otherSlotBody(t *testing.T, fill byte) []byte {
	t.Helper()
	body, err := sidecar.EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{
		{KeyIndex: 0, Generation: 1, Wrapped: bytes.Repeat([]byte{fill}, sidecar.EvsWrappedKeyByteCount)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A reader's read of the path named in each epoch of named, at the head: its newest version, proven against its
// statement as path, names slotId alone, and the slot reads whole as body.
func (self *pushFixture) requireSlotReadBack(named map[uint64]sidecar.EvsTokenPath, path sidecar.EvsTokenPath, slotId sidecar.Id, body []byte) {
	self.t.Helper()
	token := self.token(self.check.signerId)
	reply := self.readNamed(token, 0, named)
	if len(reply.paths) != 1 {
		self.t.Fatalf("%d paths read", len(reply.paths))
	}
	pathReply := reply.paths[0]
	requireVersionProven(self.t, reply, pathReply, path)
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(pathReply.GetVersion().GetEntryVersion(), entry); err != nil {
		self.t.Fatal(err)
	}
	if slotIds := entry.GetSlotIds(); len(slotIds) != 1 || !bytes.Equal(slotIds[0], slotId.Bytes()) {
		self.t.Fatalf("the committed version names slots %x", slotIds)
	}
	objects := self.read(token, &protocol.EvsReadRequest{RefId: self.check.refId.Bytes(), SlotIds: [][]byte{slotId.Bytes()}}).objects
	if len(objects) != 1 || objects[0].GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_SLOT || objects[0].GetMissing() ||
		!bytes.Equal(objects[0].GetBody(), body) {
		self.t.Fatalf("the committed version's slot reads as %v", objects)
	}
}

// The evacuation run of 14.6's schedules, 25 h 2 min past the last write: every batch goes, with dead records
// counted, each listing the slot, and no slot deleted.
func (self *evacuateFixture) requireEvacuatedKeepingSlots(deadCount int, keptCount int) {
	self.t.Helper()
	if len(self.keys("meta-1", batchKeyPrefix)) == 0 {
		self.t.Fatal("no batch to evacuate")
	}
	self.age()
	result := self.mustRun()
	if result.DeadCount != deadCount || result.SlotKeptCount != deadCount || result.SlotDeletedCount != 0 || result.KeptCount != keptCount ||
		result.WaitingCount != 0 || result.HasBatches {
		self.t.Fatalf("result %+v", result)
	}
	if keys := self.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		self.t.Fatalf("batches left: %v", keys)
	}
}

// A, its first attempt cut short: an honest push passes step 6, its record and new slot written, and its attempt
// ends 503 unknown with step 7's answer and every reread lost; a PATH_EPOCH commits; the push's retry is refused
// 412 PATH_EPOCH, for good; its retoken, a new push id carrying the same slot id and bytes in epoch 2, finds the
// slot at its step 6, equal bytes under 23 h, and commits. 26 h on, evacuation drops the refused statement's record,
// which lists the slot, and the slot stands for the version the retoken committed.
func TestEvacuationKeepsTheSlotARetokenCommittedOverItsRefusedStatementsRecord(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	commitment := fixture.crossRemove(false)
	fixture.awaitStepEights()
	slotId, _, slotBody := checkTestSlot(t, "retoken")
	refused := fixture.planAtTwo(commitment)
	fixture.createWithSlot(refused, checkTestPath("s"), slotId, slotBody)
	refusedBody := fixture.body(refused)
	token := fixture.token(fixture.check.signerId)

	faults := fixture.host.Blobs.Faults()
	for _, op := range []string{sidecartest.FaultOpPut, sidecartest.FaultOpGet} {
		if _, err := faults.Add(&sidecartest.FaultPlan{
			Op: op, KeyPrefix: HeadKey(fixture.check.repoId, fixture.check.refId), Result: sidecartest.FailBeforeApply, Repeat: -1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	recorder := fixture.post(token, refusedBody)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if refusalOf(t, recorder).GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
		t.Fatal("the cut-short attempt's outcome is not unknown")
	}
	faults.Clear()
	// its step 6 wrote the slot
	fixture.requireSlot(slotId, slotBody)

	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	requireRefusal(t, fixture.post(token, refusedBody), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)

	retoken := fixture.planOnHead(2, commitment)
	fixture.createWithSlot(retoken, epochPath(2, "s"), slotId, slotBody)
	retoken.Changes[0].SourcePaths = [][]byte{epochSourcePath(t, 1, "s")}
	fixture.requireCommitted(fixture.push(retoken), 4)
	fixture.awaitStepEights()
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "s"), 1: checkTestPath("s")}, epochPath(2, "s"), slotId, slotBody)

	// the refused statement's record is dead, and the four committed ones are kept
	fixture.requireEvacuatedKeepingSlots(1, 4)
	fixture.requireSlot(slotId, slotBody)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "s"), 1: checkTestPath("s")}, epochPath(2, "s"), slotId, slotBody)
}

// B: another writer lists a committed version's slot as new four times. Young with other bytes, its slot round
// alarms and it is refused 409 SLOT_STALE, recorded; young with the slot's bytes, its slot round takes the object
// and every step 7 then fails its condition, as a race its writer arranged would, so it ends 429 BUSY and is never
// sent again; past 23 h, with the slot's bytes and with other bytes, each is refused 409 SLOT_STALE, recorded. 26 h
// on, evacuation drops the four records, every one listing the slot, and the slot stands with the committed
// version's bytes.
func TestEvacuationKeepsACommittedVersionsSlotThatRefusedPushesListAgain(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	slotId, _, slotBody := checkTestSlot(t, "committed")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), slotId, slotBody)
	fixture.requireCommitted(fixture.push(committed), 1)
	fixture.awaitStepEights()
	window, err := EvsHeadWindow(fixture.head().Head)
	if err != nil || len(window) != 1 {
		t.Fatalf("window %v", err)
	}
	place := window[0].Place
	recordBytes, err := fixture.readRecord(fixture.check.refId, place)
	if err != nil {
		t.Fatal(err)
	}
	relist := func(label string, body []byte) *httptest.ResponseRecorder {
		plan := fixture.plan()
		fixture.createWithSlot(plan, checkTestPath(label), slotId, body)
		return fixture.pushAsOther(plan)
	}
	evsSettings := fixture.settings2()

	requireRefusal(t, relist("young other", otherSlotBody(t, 1)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	fixture.clock.Advance(evsSettings.RefusalFenceInterval)
	faults := fixture.host.Blobs.Faults()
	if _, err := faults.Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: HeadKey(fixture.check.repoId, fixture.check.refId), Result: sidecartest.Precondition,
		Repeat: evsSettings.PushConflictRetryCount,
	}); err != nil {
		t.Fatal(err)
	}
	requireRefusal(t, relist("young equal", slotBody), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_BUSY)
	if unfired := faults.Unfired(); len(unfired) != 0 {
		t.Fatalf("step 7 failed fewer times than planned: %v", unfired)
	}
	fixture.clock.Advance(evsSettings.SlotExistingMaxAge)
	requireRefusal(t, relist("old equal", slotBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	fixture.clock.Advance(evsSettings.RefusalFenceInterval)
	requireRefusal(t, relist("old other", otherSlotBody(t, 2)), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	if head := fixture.head(); head.Version() != 1 {
		t.Fatalf("a re-listing committed: the head is at %d", head.Version())
	}
	fixture.requireSlot(slotId, slotBody)

	fixture.requireEvacuatedKeepingSlots(4, 1)
	fixture.requireSlot(slotId, slotBody)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{1: checkTestPath("a")}, checkTestPath("a"), slotId, slotBody)
	fixture.requireRecord(place, recordBytes)
}
