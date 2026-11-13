// DESIGN-DETAILS 14.6's evacuation tests and schedules for the slot origin (QD-765, 14.7's track 2), on T2's fakes
// through the push route and the hourly evacuation, each schedule ending with every committed version's slot read
// back as a reader reads it:
//
//	rows   one dead record per row of 14.2.5, with the delete switched on: a slot absent at the HEAD, one of another
//	       statement's origin, one of none, a re-seeded one, the record's own settled, which goes, and its own
//	       unsettled, which stays; with the switch off, as it is in this release, every slot stays, counted. A hold
//	       keeps the record's own slot, an object stored between the HEAD and the DELETE answers 412 and stays, and
//	       a HEAD the store does not answer leaves the minute waiting. FS-8's clause as 14.8 amends it: the dead
//	       records' own slots are gone at 26 h, and a slot a dead record listed and did not create stands
//	types  a push in parts whose seal wrote its slot and ended 429: its parts and seal die, and the part listing the
//	       slot has it deleted by the statement it shares with the seal
//	A      an honest push passes step 6 and is refused 412 PATH_EPOCH once a PATH_EPOCH commits; its retoken, a new
//	       push id carrying the same slot id and bytes, waits out the settle age, takes the slot over and commits;
//	       26 h on, evacuation drops the refused statement's record, finds the retoken's origin and keeps the slot;
//	       again with a CLOSURE, whose retoken commits on its one closure upload's receipt
//	B      another writer lists a committed version's slot as new, with its bytes and with others, young and past
//	       23 h: each is 409 SLOT_STALE at step 6; 26 h on, evacuation drops each record and keeps the slot, another
//	       statement's
//	stall  a run held between its HEAD and its DELETE while a second run deletes the dead statement's slot and a later
//	       push creates the id again and commits: the first run's DELETE answers 412, and the new slot stands
//
// push_slot_test.go holds C and D, and evacuate_slot_testhooks_test.go the schedules that hold an attempt at the push
// route's barriers.

package evsservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	body, _ := self.bodyAndOriginBy(plan, self.check.otherKey, self.check.otherId)
	return self.post(self.token(self.check.otherId), body)
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

// An evacuation fixture with the delete of a dead record's own slots on, as the release after the origin's runs it.
func newSlotEvacuateFixture(t *testing.T) *evacuateFixture {
	return newEvacuateFixture(t, func(settings *EvacuatorSettings) { settings.DeleteDeadSlots = true })
}

// A new evacuator whose run calls atStep at each step, nil calling nothing, with no kill of the fixture's.
func (self *evacuateFixture) evacuatorWith(atStep func(name string, key string) error) *Evacuator {
	self.t.Helper()
	evacuator, err := NewEvacuator(self.host.ServiceHost(), &EvacuatorDeps{Settings: self.settings, EvsSettings: self.settings2(), atStep: atStep})
	if err != nil {
		self.t.Fatal(err)
	}
	return evacuator
}

// The run of 14.6's schedules, 25 h 2 min past the last write: every batch goes, and its result passes check.
func (self *evacuateFixture) requireEvacuated(check func(result *EvacuationResult) bool) *EvacuationResult {
	self.t.Helper()
	if len(self.keys("meta-1", batchKeyPrefix)) == 0 {
		self.t.Fatal("no batch to evacuate")
	}
	self.age()
	result := self.mustRun()
	if !check(result) || result.WaitingCount != 0 || result.HasBatches {
		self.t.Fatalf("result %+v", result)
	}
	if keys := self.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		self.t.Fatalf("batches left: %v", keys)
	}
	return result
}

// One dead record per row of 14.2.5: an unposted push of the writer's listing its own new slot, and what that
// slot's object is when the run comes. late's object is stored once the clock has aged.
type evacuateSlotRow struct {
	label   string
	slotId  sidecar.Id
	body    []byte
	origin  EvsSlotOrigin
	planted bool
	late    bool
}

// The rows' records in one batch beside a committed record, each row's object planted as its row says, but late's.
func (self *evacuateFixture) putSlotRows(t *testing.T) []*evacuateSlotRow {
	self.commit("committed")
	records := []*sidecar.EvsBatchRecord{}
	rows := []*evacuateSlotRow{}
	for _, label := range []string{"absent", "another", "no origin", "reseeded", "own settled", "own unsettled"} {
		slotId, _, body := checkTestSlot(t, label)
		plan := self.plan()
		self.createWithSlot(plan, checkTestPath(label), slotId, body)
		_, own := self.bodyAndOrigin(plan)
		records = append(records, self.unposted(plan))
		row := &evacuateSlotRow{label: label, slotId: slotId, body: body, origin: own, planted: label != "absent", late: label == "own unsettled"}
		switch label {
		case "another":
			row.origin = slotOriginTestPush()
		case "no origin":
			row.origin = EvsSlotOrigin{}
		case "reseeded":
			row.origin = EvsSlotOriginReseeded()
		}
		if row.planted && !row.late {
			self.plantSlot(slotId, body, row.origin)
		}
		rows = append(rows, row)
	}
	self.putBatch(1, records...)
	return rows
}

// 14.2.5, one case per row: of the slots six dead records list, the one absent is counted absent; those of another
// statement's origin, of none and of a re-seed stay as not the record's; the record's own, settled, goes by a
// DELETE naming its LastModified; its own stored within the settle age of the run stays, unsettled. Every dead record
// goes with its batch, and the committed one is kept.
func TestEvacuationDecidesEachDeadRecordsSlotOnItsObject(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	rows := fixture.putSlotRows(t)
	fixture.age()
	for _, row := range rows {
		if row.late {
			fixture.plantSlot(row.slotId, row.body, row.origin)
		}
	}
	result := fixture.mustRun()
	if result.DeadCount != len(rows) || result.KeptCount != 1 || result.SlotAbsentCount != 1 || result.SlotForeignCount != 3 ||
		result.SlotDeletedCount != 1 || result.SlotUnsettledCount != 1 || result.SlotHeldCount != 0 || result.SlotChangedCount != 0 ||
		result.SlotKeptCount != 0 || result.WaitingCount != 0 || result.HasBatches {
		t.Fatalf("result %+v", result)
	}
	for _, row := range rows {
		_, origin, _, found := fixture.slotObject(row.slotId)
		switch {
		case row.label == "own settled" && found:
			t.Fatalf("%s: the dead record's own slot stands", row.label)
		case row.planted && row.label != "own settled" && (!found || origin != row.origin):
			t.Fatalf("%s: found %t under %+v", row.label, found, origin)
		}
	}
}

// With the delete off, as the release that brings origins runs it (14.2.8, 14.7), no slot a dead record lists is
// judged: each stays, counted kept, and none is HEADed.
func TestEvacuationKeepsEveryDeadRecordsSlotWhileTheDeleteIsOff(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	if fixture.settings.DeleteDeadSlots {
		t.Fatal("the delete is on by default")
	}
	rows := fixture.putSlotRows(t)
	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == len(rows) && result.SlotKeptCount == len(rows) && result.SlotDeletedCount == 0 &&
			result.SlotAbsentCount == 0 && result.SlotForeignCount == 0 && result.SlotUnsettledCount == 0
	})
	for _, row := range rows {
		if _, origin, _, found := fixture.slotObject(row.slotId); row.planted && !row.late && (!found || origin != row.origin) {
			t.Fatalf("%s: found %t under %+v", row.label, found, origin)
		}
	}
	for _, step := range fixture.steps {
		if step == BarrierEvacuateSlotHeadBefore {
			t.Fatal("a slot was HEADed with the delete off")
		}
	}
}

// A dead record's own slot, settled, under a hold covering its repo: kept held, as a dead push's slot was before the
// origin, and the record goes with its batch.
func TestEvacuationKeepsADeadRecordsOwnSlotUnderAHold(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	fixture.commit("committed")
	slotId, _, body := checkTestSlot(t, "held")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("held"), slotId, body)
	_, own := fixture.bodyAndOrigin(plan)
	fixture.putBatch(1, fixture.unposted(plan))
	fixture.plantSlot(slotId, body, own)
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.check.networkId, CaseId: testId("evacuation hold"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 1 && result.SlotHeldCount == 1 && result.SlotDeletedCount == 0
	})
	fixture.requireSlotOrigin(slotId, body, own)
}

// An object stored between the run's HEAD and its DELETE: the record's own slot, settled at the HEAD, is deleted and
// created again by the same statement's late attempt before the DELETE goes. The DELETE names the LastModified the
// HEAD read, so the store answers 412 and the new object stays, counted changed.
func TestEvacuationDeletesNothingStoredSinceItsHead(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	fixture.commit("committed")
	slotId, _, body := checkTestSlot(t, "changed")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("changed"), slotId, body)
	_, own := fixture.bodyAndOrigin(plan)
	fixture.putBatch(1, fixture.unposted(plan))
	fixture.plantSlot(slotId, body, own)
	fixture.age()
	replaced := false
	evacuator := fixture.evacuatorWith(func(name string, key string) error {
		if name == BarrierEvacuateSlotHeadAfter && !replaced {
			replaced = true
			if err := fixture.cluster.Delete(fixture.ctx, SlotKey(fixture.check.repoId, slotId)); err != nil {
				return err
			}
			fixture.clock.Advance(5 * time.Second)
			fixture.plantSlot(slotId, body, own)
		}
		return nil
	})
	result, err := evacuator.Run(fixture.ctx, "meta-1")
	if err != nil || !replaced || result.DeadCount != 1 || result.SlotChangedCount != 1 || result.SlotDeletedCount != 0 || result.HasBatches {
		t.Fatalf("result %+v %v (replaced %t)", result, err, replaced)
	}
	if _, _, lastModified, found := fixture.slotObject(slotId); !found || !lastModified.Equal(fixture.clock.Now()) {
		t.Fatal("the object stored since the HEAD is gone")
	}
}

// A HEAD the store does not answer leaves the minute waiting with its batches and deletes nothing; the next run, the
// store answering, decides the slot.
func TestEvacuationWaitsOnASlotItCannotRead(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	fixture.commit("committed")
	slotId, _, body := checkTestSlot(t, "unread")
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("unread"), slotId, body)
	_, own := fixture.bodyAndOrigin(plan)
	fixture.putBatch(1, fixture.unposted(plan))
	fixture.plantSlot(slotId, body, own)
	fixture.age()
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpGet, KeyPrefix: SlotKey(fixture.check.repoId, slotId), Result: sidecartest.FailBeforeApply, Repeat: -1,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.run()
	if err == nil || result.MinuteWaitingCount != 1 || result.SlotDeletedCount != 0 || !result.HasBatches {
		t.Fatalf("result %+v %v", result, err)
	}
	fixture.host.Blobs.Faults().Clear()
	fixture.requireSlotOrigin(slotId, body, own)
	result = fixture.mustRun()
	if result.SlotDeletedCount != 1 || result.HasBatches {
		t.Fatalf("the run once the store answers %+v", result)
	}
	if _, _, _, found := fixture.slotObject(slotId); found {
		t.Fatal("the dead record's own slot stands")
	}
}

// A record of each type: a push in parts whose seal's step 6 wrote its slot under the push's statement, and whose
// step 7 then lost every race, ending 429 BUSY. Its parts and its seal are pending, fenced and dead at 26 h; the seal
// lists no slot, and the part that lists it has the slot deleted, its origin being the statement the part shares
// with the seal.
func TestEvacuationDeletesTheSlotOfADeadPushInPartsByItsStatement(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	token := fixture.token(fixture.check.signerId)
	slotId, slotObject, slotBody := checkTestSlot(t, "parted")
	plan := fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100)
	plan.Changes[0].EntryVersion = fixture.check.fileEntry(plan, 1, nil, slotId)
	plan.NewObjects = append(plan.NewObjects, slotObject)
	plan.SlotBodies = append(plan.SlotBodies, slotBody)
	built := fixture.built(plan)
	own, err := EvsSlotOriginOf(built.Statement)
	if err != nil {
		t.Fatal(err)
	}
	places := fixture.postParts(token, built)
	fixture.clock.Advance(time.Minute)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: HeadKey(fixture.check.repoId, fixture.check.refId), Result: sidecartest.Precondition, Repeat: -1,
	}); err != nil {
		t.Fatal(err)
	}
	requireRefusal(t, fixture.seal(token, built, places), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_BUSY)
	fixture.host.Blobs.Faults().Clear()
	fixture.requireSlotOrigin(slotId, slotBody, own)

	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == len(places)+1 && result.SlotDeletedCount == 1 && result.SlotForeignCount == 0
	})
	if _, _, _, found := fixture.slotObject(slotId); found {
		t.Fatal("the dead push's own slot stands")
	}
}

// A, its first attempt cut short: an honest push passes step 6, its record and new slot written under its origin, and
// its attempt ends 503 unknown with step 7's answer and every reread lost; a PATH_EPOCH commits; the push's retry is
// refused 412 PATH_EPOCH, for good. Its retoken, a new push id carrying the same slot id and bytes in epoch 2, finds
// the refused statement's object, waits out the settle age on evs's clock, deletes it by a DELETE naming its
// LastModified, creates its own and commits. 26 h on, evacuation drops the refused statement's record and keeps the
// slot, whose origin is the retoken's.
func TestEvacuationKeepsTheSlotARetokenTookOverFromItsRefusedStatement(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	commitment := fixture.crossRemove(false)
	fixture.awaitStepEights()
	slotId, _, slotBody := checkTestSlot(t, "retoken")
	refused := fixture.planAtTwo(commitment)
	fixture.createWithSlot(refused, checkTestPath("s"), slotId, slotBody)
	refusedBody, refusedOrigin := fixture.bodyAndOrigin(refused)
	token := fixture.token(fixture.check.signerId)

	fixture.failHeadWrites()
	recorder := fixture.post(token, refusedBody)
	requireRefusal(t, recorder, http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	if refusalOf(t, recorder).GetOutcome() != protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN {
		t.Fatal("the cut-short attempt's outcome is not unknown")
	}
	fixture.host.Blobs.Faults().Clear()
	fixture.requireSlotOrigin(slotId, slotBody, refusedOrigin)
	_, _, storedAt, _ := fixture.slotObject(slotId)

	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	requireRefusal(t, fixture.post(token, refusedBody), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)

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
	fixture.requireSlotOrigin(slotId, slotBody, retokenOrigin)
	named := map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "s"), 1: checkTestPath("s")}
	fixture.requireSlotReadBack(named, epochPath(2, "s"), slotId, slotBody)

	// the refused statement's record is dead, and the four committed ones are kept
	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 1 && result.KeptCount == 4 && result.SlotForeignCount == 1 && result.SlotDeletedCount == 0
	})
	fixture.requireSlotOrigin(slotId, slotBody, retokenOrigin)
	fixture.requireSlotReadBack(named, epochPath(2, "s"), slotId, slotBody)
}

// A again with a CLOSURE (14.6): an admin's CLOSURE re-checkpoints c, its new chain in one closure upload and its fresh
// key in a new slot; it passes step 6, its attempt is cut short, a PATH_EPOCH commits, and its retry is refused 412
// PATH_EPOCH. Its retoken keeps the upload's receipt, the slot id and the slot's bytes, so nothing is uploaded or
// charged again: it waits out the settle age, takes the slot over and commits on that one receipt. 26 h on,
// evacuation drops the refused CLOSURE's record and keeps the slot, the retoken's.
func TestEvacuationKeepsTheSlotAClosureRetokenTookOver(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	commitment := fixture.crossRemove(false)
	// c's version: one record of an upload, its key in a slot
	keptId, keptObject, keptReceipt := fixture.check.upload("closure kept", fixture.clock.Now(), fixture.check.signerId)
	oldSlotId, oldSlotObject, oldSlotBody := checkTestSlot(t, "old key")
	committed := fixture.planAtTwo(commitment)
	committed.Changes = append(committed.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("c"), EntryVersion: fixture.check.fileEntry(committed, 3, []*protocol.EvsLocator{checkTestSegmentLocator(keptId)}, oldSlotId),
	})
	committed.NewObjects = append(committed.NewObjects, keptObject, oldSlotObject)
	committed.SlotBodies = append(committed.SlotBodies, oldSlotBody)
	committedBody, _ := fixture.bodyAndOrigin(committed)
	committedBody.Receipts = []*protocol.EvsUploadReceipt{keptReceipt}
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 3)
	fixture.awaitStepEights()

	// the CLOSURE's one upload, and its new key's slot
	uploadId, uploadObject, uploadReceipt := fixture.check.upload("closure upload", fixture.clock.Now(), fixture.check.signerId)
	slotId, slotObject, slotBody := checkTestSlot(t, "new key")
	closure := func(plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath) *sidecar.EvsPushPlan {
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
		plan.Erased = []*sidecar.EvsErasedKey{{SlotId: oldSlotId, KeyIndex: 0}}
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
			TokenPath: path, BaseEntryVersion: 3,
			EntryVersion: fixture.check.fileEntry(plan, 4, []*protocol.EvsLocator{checkTestSegmentLocator(uploadId)}, slotId),
		})
		plan.NewObjects = append(plan.NewObjects, uploadObject, slotObject)
		plan.SlotBodies = append(plan.SlotBodies, slotBody)
		return plan
	}
	admin := fixture.token(fixture.check.signerId, "admin")
	refusedBody, refusedOrigin := fixture.bodyAndOrigin(closure(fixture.planAtTwo(commitment), checkTestPath("c")))
	refusedBody.Receipts = []*protocol.EvsUploadReceipt{uploadReceipt}
	fixture.failHeadWrites()
	requireRefusal(t, fixture.post(admin, refusedBody), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	fixture.host.Blobs.Faults().Clear()
	fixture.requireSlotOrigin(slotId, slotBody, refusedOrigin)
	_, _, storedAt, _ := fixture.slotObject(slotId)

	fixture.cutOverToEpochTwo(commitment, pathEpochTestMoveAt(2, []uint64{1}, "a"))
	requireRefusal(t, fixture.post(admin, refusedBody), http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)

	retoken := closure(fixture.planOnHead(2, commitment), epochPath(2, "c"))
	retoken.Changes[0].SourcePaths = [][]byte{epochSourcePath(t, 1, "c")}
	retokenBody, retokenOrigin := fixture.bodyAndOrigin(retoken)
	retokenBody.Receipts = []*protocol.EvsUploadReceipt{uploadReceipt}
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		answered <- fixture.post(admin, retokenBody)
	}()
	settledAt := storedAt.Add(fixture.settings2().SlotSettleAge)
	fixture.awaitTimerAt(settledAt)
	fixture.clock.AdvanceTo(settledAt)
	fixture.requireCommitted(<-answered, 5)
	fixture.awaitStepEights()
	fixture.requireSlotOrigin(slotId, slotBody, retokenOrigin)

	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 1 && result.SlotForeignCount == 1 && result.SlotDeletedCount == 0
	})
	fixture.requireSlotOrigin(slotId, slotBody, retokenOrigin)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{2: epochPath(2, "c"), 1: checkTestPath("c")}, epochPath(2, "c"), slotId, slotBody)
}

// B: another writer lists a committed version's slot as new four times, young and past 23 h, with its bytes and with
// others. Each is refused 409 SLOT_STALE at step 6, recorded, the object being another statement's: no alarm, no
// step 7, nothing taken. 26 h on, evacuation drops the four records, every one listing the slot, finds the committed
// statement's origin at each HEAD, and keeps the slot.
func TestEvacuationKeepsACommittedVersionsSlotThatRefusedPushesListAgain(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	slotId, _, slotBody := checkTestSlot(t, "committed")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), slotId, slotBody)
	committedBody, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedBody), 1)
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
	relist := func(label string, body []byte) {
		t.Helper()
		plan := fixture.plan()
		fixture.createWithSlot(plan, checkTestPath(label), slotId, body)
		requireRefusal(t, fixture.pushAsOther(plan), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
	}
	evsSettings := fixture.settings2()
	relist("young equal", slotBody)
	fixture.clock.Advance(evsSettings.RefusalFenceInterval)
	relist("young other", otherSlotBody(t, 1))
	fixture.clock.Advance(evsSettings.SlotExistingMaxAge)
	relist("old equal", slotBody)
	fixture.clock.Advance(evsSettings.RefusalFenceInterval)
	relist("old other", otherSlotBody(t, 2))
	if head := fixture.head(); head.Version() != 1 {
		t.Fatalf("a re-listing committed: the head is at %d", head.Version())
	}
	if foreign, mismatch := fixture.slotCounts(); foreign != 4 || mismatch != 0 {
		t.Fatalf("counted %v foreign and %v mismatched", foreign, mismatch)
	}

	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 4 && result.KeptCount == 1 && result.SlotForeignCount == 4 && result.SlotDeletedCount == 0
	})
	fixture.requireSlotOrigin(slotId, slotBody, committedOrigin)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{1: checkTestPath("a")}, checkTestPath("a"), slotId, slotBody)
	fixture.requireRecord(place, recordBytes)
}

// A stalled run: run 1 HEADs a dead record's own settled slot and stalls before its DELETE; run 2 deletes the slot
// and the record's batch; a later push of the writer's creates the slot id again under its own origin and commits.
// Run 1 wakes and sends its DELETE, which names the LastModified its HEAD read: the store answers 412, the new
// object stands, and the committed version reads it back.
func TestEvacuationStalledBetweenItsHeadAndItsDeleteDeletesNothingNewer(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	fixture.commit("committed")
	slotId, _, body := checkTestSlot(t, "stalled")
	dead := fixture.plan()
	fixture.createWithSlot(dead, checkTestPath("dead"), slotId, body)
	_, deadOrigin := fixture.bodyAndOrigin(dead)
	fixture.putBatch(1, fixture.unposted(dead))
	fixture.plantSlot(slotId, body, deadOrigin)
	fixture.age()

	stalled := make(chan struct{})
	wake := make(chan struct{})
	first := fixture.evacuatorWith(func(name string, key string) error {
		if name == BarrierEvacuateSlotHeadAfter {
			close(stalled)
			<-wake
		}
		return nil
	})
	type runResult struct {
		result *EvacuationResult
		err    error
	}
	firstDone := make(chan runResult, 1)
	go func() {
		result, err := first.Run(fixture.ctx, "meta-1")
		firstDone <- runResult{result: result, err: err}
	}()
	<-stalled

	second, err := fixture.evacuatorWith(nil).Run(fixture.ctx, "meta-1")
	if err != nil || second.DeadCount != 1 || second.SlotDeletedCount != 1 || second.HasBatches {
		t.Fatalf("the second run %+v %v", second, err)
	}
	if _, _, _, found := fixture.slotObject(slotId); found {
		t.Fatal("the second run left the dead record's own slot")
	}
	fixture.clock.Advance(5 * time.Second)
	later := fixture.plan()
	fixture.createWithSlot(later, checkTestPath("later"), slotId, body)
	laterBody, laterOrigin := fixture.bodyAndOrigin(later)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), laterBody), 2)
	fixture.awaitStepEights()

	close(wake)
	done := <-firstDone
	if done.err != nil || done.result.SlotChangedCount != 1 || done.result.SlotDeletedCount != 0 {
		t.Fatalf("the stalled run %+v %v", done.result, done.err)
	}
	fixture.requireSlotOrigin(slotId, body, laterOrigin)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{1: checkTestPath("later")}, checkTestPath("later"), slotId, body)
}

// FS-8's slot clause under the origin (14.8): a dead record's own slot is gone at 26 h, and a slot it listed and did
// not create, the committed version's, stands.
func TestFs8DeadRecordsOwnSlotsGoAndTheSlotsTheyListedStand(t *testing.T) {
	fixture := newSlotEvacuateFixture(t)
	committedId, _, committedBody := checkTestSlot(t, "fs8 committed")
	committed := fixture.plan()
	fixture.createWithSlot(committed, checkTestPath("a"), committedId, committedBody)
	committedRequest, committedOrigin := fixture.bodyAndOrigin(committed)
	fixture.requireCommitted(fixture.post(fixture.token(fixture.check.signerId), committedRequest), 1)
	fixture.awaitStepEights()

	ownId, _, ownBody := checkTestSlot(t, "fs8 own")
	dead := fixture.plan()
	fixture.createWithSlot(dead, checkTestPath("dead"), ownId, ownBody)
	fixture.createWithSlot(dead, checkTestPath("dead listed"), committedId, committedBody)
	_, deadOrigin := fixture.bodyAndOrigin(dead)
	fixture.putBatch(1, fixture.unposted(dead))
	fixture.plantSlot(ownId, ownBody, deadOrigin)

	fixture.requireEvacuated(func(result *EvacuationResult) bool {
		return result.DeadCount == 1 && result.KeptCount == 1 && result.SlotDeletedCount == 1 && result.SlotForeignCount == 1
	})
	if _, _, _, found := fixture.slotObject(ownId); found {
		t.Fatal("the dead record's own slot stands at 26 h")
	}
	fixture.requireSlotOrigin(committedId, committedBody, committedOrigin)
	fixture.requireSlotReadBack(map[uint64]sidecar.EvsTokenPath{1: checkTestPath("a")}, checkTestPath("a"), committedId, committedBody)
}
