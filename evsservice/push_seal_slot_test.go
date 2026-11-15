// QD-819's seal on T2's fakes through the push route (question push-record-no-slot-bodies-part-slot-bodies): a push
// in parts carries its slot bodies whole in its seal request and in none of its parts. A slot-keyed push past 1,024
// entry writes goes in parts, step 6 of its seal writes its slots from the request under the statement's origin, and
// no record evs keeps, the seal's or a part's, holds a body or a key of one; a part holding section 7 is refused at
// the part route; a seal whose bodies do not match its new slots, or pass their bound, is refused writing nothing; a
// seal's retry carrying its bodies again is answered its version, and one whose first attempt wrote its slots but not
// its record finds them its own and commits; a re-seeded part holding section 7 is refused; a one-part push carrying
// bodies beside its payload is refused; and after an ERASE no batch, parcel or pack holds the erased key, and neither
// does any record or part the read route serves.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A new slot of keyCount keys introduced by a push: its id, body, and each key's wrapped bytes, drawn from its label
// so no other stored bytes hold them by chance.
type sealTestSlot struct {
	slotId  sidecar.Id
	body    []byte
	wrapped [][]byte
}

func newSealTestSlot(t *testing.T, label string, keyCount int) *sealTestSlot {
	t.Helper()
	slot := &protocol.EvsSlotObject{}
	// testId keeps a label's first 16 bytes, which labels here share
	testSlot := &sealTestSlot{slotId: testIdFrom("seal slot " + label)}
	for index := range keyCount {
		wrapped := []byte{}
		for block := 0; len(wrapped) < sidecar.EvsWrappedKeyByteCount; block += 1 {
			digest := sha256.Sum256([]byte(fmt.Sprintf("seal slot %s key %d block %d", label, index, block)))
			wrapped = append(wrapped, digest[:]...)
		}
		wrapped = wrapped[:sidecar.EvsWrappedKeyByteCount]
		slot.Keys = append(slot.Keys, &protocol.EvsSlotKey{KeyIndex: uint32(index), Generation: 1, Wrapped: wrapped})
		testSlot.wrapped = append(testSlot.wrapped, wrapped)
	}
	body, err := sidecar.EvsEncodeSlotObject(slot)
	if err != nil {
		t.Fatal(err)
	}
	testSlot.body = body
	return testSlot
}

// A plan creating count files on the fixture's file-mode ref, in parts past 1,024 entry writes, and a file naming each
// slot, which the push introduces.
func (self *pushFixture) slottedPartsPlan(count int, slots ...*sealTestSlot) *sidecar.EvsPushPlan {
	plan := self.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, count)
	for i, slot := range slots {
		self.createWithSlot(plan, checkTestPath("slotted", strconv.Itoa(i)), slot.slotId, slot.body)
	}
	return plan
}

// The stored objects, on the metadata cluster and the segment cluster, whose bytes hold any of secrets.
func (self *pushFixture) storedHolding(secrets ...[]byte) []string {
	self.t.Helper()
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	holding := []string{}
	for _, cluster := range []sidecar.BlobCluster{self.cluster, segmentCluster} {
		for startAfter, more := "", true; more; {
			var infos []*sidecar.BlobInfo
			infos, more, err = cluster.List(self.ctx, "", startAfter, 1000)
			if err != nil {
				self.t.Fatal(err)
			}
			for _, info := range infos {
				startAfter = info.Key
				object, err := cluster.Get(self.ctx, info.Key)
				if err != nil {
					self.t.Fatal(err)
				}
				content, err := io.ReadAll(object.Body)
				object.Body.Close()
				if err != nil {
					self.t.Fatal(err)
				}
				for _, secret := range secrets {
					if bytes.Contains(content, secret) {
						holding = append(holding, cluster.ClusterId()+":"+info.Key)
						break
					}
				}
			}
		}
	}
	return holding
}

// Whether any of held holds a slot's body or any of its wrapped keys.
func sealTestHolds(slots []*sealTestSlot, held ...[]byte) bool {
	for _, slot := range slots {
		for _, heldBytes := range held {
			if bytes.Contains(heldBytes, slot.body) {
				return true
			}
			for _, wrapped := range slot.wrapped {
				if bytes.Contains(heldBytes, wrapped) {
					return true
				}
			}
		}
	}
	return false
}

// A slot-keyed push in parts carries its bodies in its seal alone, whether past 1,024 entry writes or past 1 MiB by its
// sealed metadata: before the seal no slot exists, the seal commits, step 6 wrote each slot from the request under the
// statement's origin, the record at the window's place is the seal's and each part record it names checks as a stored
// part, and no batch record holds a body or a key of one.
func TestSealWritesTheSlotsFromItsRequestAndNoRecordKeepsABody(t *testing.T) {
	for _, shape := range []struct {
		label string
		plan  func(fixture *pushFixture, slots []*sealTestSlot) *sidecar.EvsPushPlan
	}{
		{"past 1,024 entry writes", func(fixture *pushFixture, slots []*sealTestSlot) *sidecar.EvsPushPlan {
			return fixture.slottedPartsPlan(1100, slots...)
		}},
		{"past 1 MiB", func(fixture *pushFixture, slots []*sealTestSlot) *sidecar.EvsPushPlan {
			plan := fixture.plan()
			plan.SealedMetadata = bytes.Repeat([]byte{0x5a}, 1536*1024)
			for i, slot := range slots {
				fixture.createWithSlot(plan, checkTestPath("slotted", strconv.Itoa(i)), slot.slotId, slot.body)
			}
			return plan
		}},
	} {
		slots := []*sealTestSlot{newSealTestSlot(t, shape.label+" written a", 2), newSealTestSlot(t, shape.label+" written b", 1)}
		requireSealWritesItsSlots(t, shape.label, slots, shape.plan)
	}
}

// One shape of TestSealWritesTheSlotsFromItsRequestAndNoRecordKeepsABody, on a fixture of its own.
func requireSealWritesItsSlots(t *testing.T, label string, slots []*sealTestSlot, planOf func(fixture *pushFixture, slots []*sealTestSlot) *sidecar.EvsPushPlan) {
	t.Helper()
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(planOf(fixture, slots))
	if len(built.Parts) < 2 || len(built.SlotBodies) == 0 {
		t.Fatalf("%s: %d parts, %d bytes of slot bodies", label, len(built.Parts), len(built.SlotBodies))
	}
	if sealTestHolds(slots, built.Parts...) {
		t.Fatalf("%s: a part as built holds a slot body or key", label)
	}
	places := fixture.postParts(token, built)
	for _, slot := range slots {
		if _, _, _, found := fixture.slotObject(slot.slotId); found {
			t.Fatalf("%s: a slot was written before its seal", label)
		}
	}
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
	fixture.awaitStepEights()
	origin, err := EvsSlotOriginOf(built.Statement)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range slots {
		fixture.requireSlotOrigin(slot.slotId, slot.body, origin)
	}

	window, err := EvsHeadWindow(fixture.head().Head)
	if err != nil || len(window) != 1 {
		t.Fatalf("%s: window %v", label, err)
	}
	seal, err := fixture.engine.readRecordAt(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, window[0].Place)
	if err != nil || seal.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
		t.Fatalf("%s: the window's record: %v", label, err)
	}
	_, sealParts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
	if err != nil || len(sealParts) != len(built.Parts) {
		t.Fatalf("%s: the seal names %d parts: %v", label, len(sealParts), err)
	}
	for i, sealPart := range sealParts {
		record, err := fixture.engine.readRecordAt(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, sealPart.Place)
		if err != nil || record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART {
			t.Fatalf("%s: part %d's record: %v", label, i+1, err)
		}
		_, partBytes, _, _, err := sidecar.ParseEvsSealPartRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sidecar.EvsCheckStoredPart(built.Statement, partBytes); err != nil {
			t.Fatalf("%s: part %d as stored: %v", label, i+1, err)
		}
	}
	records := fixture.batchRecords()
	if len(records) != len(built.Parts)+1 {
		t.Fatalf("%s: %d records, want %d parts and a seal", label, len(records), len(built.Parts))
	}
	if sealTestHolds(slots, records...) {
		t.Fatalf("%s: a batch record holds a slot body or key", label)
	}
	if foreign, mismatch := fixture.slotCounts(); foreign != 0 || mismatch != 0 {
		t.Fatalf("%s: counted %v foreign and %v mismatched", label, foreign, mismatch)
	}
}

// A part whose sections hold section 7 is refused 400 INVALID at the part route and writes nothing, its statement
// otherwise its own (QD-819); the part as built is taken.
func TestPartHoldingSlotBodiesIsRefusedAtThePartRoute(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.slottedPartsPlan(1100, newSealTestSlot(t, "held in a part", 1)))
	last := len(built.Parts) - 1
	message := &protocol.EvsPushPart{}
	if err := proto.Unmarshal(built.Parts[last], message); err != nil {
		t.Fatal(err)
	}
	sections, err := sidecar.ParseEvsPayload(message.GetSections())
	if err != nil {
		t.Fatal(err)
	}
	sections.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES, built.SlotBodies)
	message.Sections = sections.Encode()
	holding, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	recorder := fixture.call(token, http.MethodPost, "/push/"+sidecar.EvsKeyId(pushId)+"/"+strconv.Itoa(last+1),
		&protocol.EvsPartRequest{Statement: built.Statement.Bytes, Part: holding})
	requireRefusal(t, recorder, http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if records := fixture.batchRecords(); len(records) != 0 {
		t.Fatalf("the refused part wrote %d records", len(records))
	}
	fixture.requirePlace(fixture.postPart(token, built, last))
}

// A seal whose slot bodies do not match the statement's new slots is refused 400 INVALID, as a one-part push's are,
// writing no slot, record or head: none, one of two, a body that is no slot object, an item cut short, and bodies past
// the format's bound. The seal with its own bodies then commits.
func TestSealWhoseSlotBodiesDoNotMatchItsNewSlotsIsRefused(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	slots := []*sealTestSlot{newSealTestSlot(t, "unmatched a", 1), newSealTestSlot(t, "unmatched b", 1)}
	built := fixture.built(fixture.slottedPartsPlan(1100, slots...))
	places := fixture.postParts(token, built)
	firstItem := binary.BigEndian.AppendUint32(nil, uint32(len(slots[0].body)))
	firstItem = append(firstItem, slots[0].body...)
	notASlot := append(bytes.Clone(firstItem), binary.BigEndian.AppendUint32(nil, 10)...)
	notASlot = append(notASlot, []byte("not a slot")...)
	for _, refused := range []struct {
		label      string
		slotBodies []byte
	}{
		{"none", nil},
		{"one of two", firstItem},
		{"a body that is no slot object", notASlot},
		{"an item cut short", built.SlotBodies[:len(built.SlotBodies)-1]},
		{"past the bound", make([]byte, sidecar.DefaultEvsFormatSettings().SealSlotBodiesMaxByteCount+1)},
	} {
		recorder := fixture.post(token, &protocol.EvsPushRequest{Statement: built.Statement.Bytes, PartPlaces: places, SlotBodies: refused.slotBodies})
		if recorder.Code != http.StatusBadRequest || refusalOf(t, recorder).GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_INVALID {
			t.Fatalf("slot bodies %s: status %d (%s), want 400 INVALID", refused.label, recorder.Code, refusalOf(t, recorder).GetCode())
		}
	}
	for _, slot := range slots {
		if _, _, _, found := fixture.slotObject(slot.slotId); found {
			t.Fatal("a refused seal wrote a slot")
		}
	}
	if records := fixture.batchRecords(); len(records) != len(built.Parts) || !fixture.head().Absent() {
		t.Fatalf("refused seals wrote %d records or the head", len(records)-len(built.Parts))
	}
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
}

// A seal's retry carries its bodies again and is answered its version (I-EVS-3): a minute after the commit, 5a finds
// the push, so the slots are not written again, the head stays at 1 and no record is added.
func TestSealRetryCarryingItsBodiesAgainIsIdempotent(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	slot := newSealTestSlot(t, "retried", 2)
	built := fixture.built(fixture.slottedPartsPlan(1100, slot))
	places := fixture.postParts(token, built)
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
	fixture.awaitStepEights()
	stored, origin, lastModified, found := fixture.slotObject(slot.slotId)
	if !found || !bytes.Equal(stored, slot.body) {
		t.Fatal("the seal's slot")
	}
	records := len(fixture.batchRecords())
	fixture.clock.Advance(time.Minute)
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
	fixture.awaitStepEights()
	againStored, againOrigin, againModified, found := fixture.slotObject(slot.slotId)
	if !found || !bytes.Equal(againStored, stored) || againOrigin != origin || !againModified.Equal(lastModified) {
		t.Fatal("the retry wrote the slot again")
	}
	if again := len(fixture.batchRecords()); again != records || fixture.head().Version() != 1 {
		t.Fatalf("the retry wrote %d records, head at %d", again-records, fixture.head().Version())
	}
}

// QD-806's order at a seal: an attempt whose slots are written and whose record is not answers 503, its slots
// standing under the statement's origin with no record naming them; the seal's retry, carrying its bodies again, finds
// each slot its own with equal bytes, appends its record, which keeps no body, and commits.
func TestSealSlotsStandForTheRetryOfASealWhoseRecordWasNotWritten(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	slot := newSealTestSlot(t, "no seal record", 1)
	built := fixture.built(fixture.slottedPartsPlan(1100, slot))
	places := fixture.postParts(token, built)
	partRecords := len(fixture.batchRecords())
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: batchKeyPrefix, Result: sidecartest.FailBeforeApply, Repeat: -1,
	}); err != nil {
		t.Fatal(err)
	}
	requireRefusal(t, fixture.seal(token, built, places), http.StatusServiceUnavailable, protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE)
	origin, err := EvsSlotOriginOf(built.Statement)
	if err != nil {
		t.Fatal(err)
	}
	fixture.requireSlotOrigin(slot.slotId, slot.body, origin)
	if records := len(fixture.batchRecords()); records != partRecords || !fixture.head().Absent() {
		t.Fatalf("the failed seal wrote %d records or the head", records-partRecords)
	}

	fixture.host.Blobs.Faults().Clear()
	fixture.requireCommitted(fixture.seal(token, built, places), 1)
	fixture.requireSlotOrigin(slot.slotId, slot.body, origin)
	records := fixture.batchRecords()
	if len(records) != partRecords+1 || sealTestHolds([]*sealTestSlot{slot}, records...) {
		t.Fatalf("%d records after the retry, or one holding the slot's body", len(records))
	}
	if foreign, mismatch := fixture.slotCounts(); foreign != 0 || mismatch != 0 {
		t.Fatalf("counted %v foreign and %v mismatched", foreign, mismatch)
	}
}

// A re-seeded part that holds section 7 is refused at its call 400 INVALID writing nothing, its statement signed again
// over the changed part so only section 7 refuses it; the push's parts as built, which carry no body, re-seed a part a
// call and then their seal (QD-819, QD-836).
func TestReseedOfAPartHoldingSlotBodiesIsRefused(t *testing.T) {
	fixture := newReseedFixture(t)
	slot := newSealTestSlot(t, "reseeded part", 1)
	plan := fixture.keptParts(1100)
	fixture.createWithSlot(plan, checkTestPath("slotted"), slot.slotId, slot.body)
	built := fixture.built(plan)
	last := len(built.Parts) - 1
	message := &protocol.EvsPushPart{}
	if err := proto.Unmarshal(built.Parts[last], message); err != nil {
		t.Fatal(err)
	}
	sections, err := sidecar.ParseEvsPayload(message.GetSections())
	if err != nil {
		t.Fatal(err)
	}
	sections.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES, built.SlotBodies)
	message.Sections = sections.Encode()
	holding, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	// the statement signed again over parts, as the builder signs one
	resign := func(parts [][]byte) []byte {
		t.Helper()
		partHashes := []byte{}
		for _, partBytes := range parts {
			digest := sha256.Sum256(partBytes)
			partHashes = append(partHashes, digest[:]...)
		}
		push := proto.Clone(built.Statement.Push).(*protocol.EvsPush)
		partsDigest := sha256.Sum256(partHashes)
		push.PartsSha256 = partsDigest[:]
		pushBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(push)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := checkTestSign(fixture.check.signingKey, fixture.check.signerId)("evs-push", bridge.SignedType_SIGNED_EVS_PUSH, pushBytes, nil)
		if err != nil {
			t.Fatal(err)
		}
		statementBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return statementBytes
	}
	if !bytes.Equal(resign(built.Parts), built.Statement.Bytes) {
		t.Fatal("the statement signed again over the parts as built is not the builder's")
	}
	parts := append(slices.Clone(built.Parts[:last]), holding)
	holdingCall := &protocol.EvsReseedRequest{Statement: resign(parts), Parts: [][]byte{holding}, PartNumber: uint32(last + 1)}
	requireRefusal(t, fixture.reseed(holdingCall), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if records := fixture.batchRecords(); len(records) != 0 || !fixture.head().Absent() {
		t.Fatalf("the refused re-seed wrote %d records or the head", len(records))
	}
	fixture.requireCommitted(fixture.reseedInParts(built), 1)
	fixture.awaitStepEights()
	if sealTestHolds([]*sealTestSlot{slot}, fixture.batchRecords()...) {
		t.Fatal("a re-seeded record holds the slot's body or key")
	}
	if _, _, _, found := fixture.slotObject(slot.slotId); found {
		t.Fatal("a re-seed of a push in parts wrote its slot, which comes by its own call")
	}
}

// A one-part push carries its slot bodies in its payload's section 7 (QD-806): one that sets the seal's field beside
// its payload is refused 400 INVALID writing nothing, and commits without it.
func TestOnePartPushCarryingSlotBodiesBesideItsPayloadIsRefused(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	slot := newSealTestSlot(t, "beside", 1)
	plan := fixture.plan()
	fixture.createWithSlot(plan, checkTestPath("a"), slot.slotId, slot.body)
	body := fixture.body(plan)
	beside := proto.Clone(body).(*protocol.EvsPushRequest)
	beside.SlotBodies = binary.BigEndian.AppendUint32(nil, uint32(len(slot.body)))
	beside.SlotBodies = append(beside.SlotBodies, slot.body...)
	requireRefusal(t, fixture.post(token, beside), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	if _, _, _, found := fixture.slotObject(slot.slotId); found || !fixture.head().Absent() {
		t.Fatal("the refused push wrote its slot or the head")
	}
	fixture.requireCommitted(fixture.post(token, body), 1)
}

// After an ERASE of a key a push in parts introduced, no stored object holds it: before the ERASE the slot alone does,
// and after it no batch holds it, then no parcel once evacuation moved the records and no pack once the nightly pass
// packed the idle repo's parcels a week on; and at each stage neither the seal record nor any part the read route
// serves holds it, every one of them served and none missing.
func TestEraseLeavesNoCopyOfItsKeyInAPushInPartsRecords(t *testing.T) {
	nightly := newNightlyFixture(t)
	// the push's records pass the default 256 KiB, which would pack them at once: a parcel first, then its pack
	nightly.evacuateFixture.settings.PackByteCount = 64 * 1024 * 1024
	fixture := nightly.pushFixture
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	token := fixture.token(fixture.check.signerId)
	slot := newSealTestSlot(t, "erased", 2)
	built := fixture.built(fixture.slottedPartsPlan(1100, slot))
	fixture.requireCommitted(fixture.seal(token, built, fixture.postParts(token, built)), 1)
	fixture.awaitStepEights()
	slotKey := fixture.cluster.ClusterId() + ":" + SlotKey(fixture.check.repoId, slot.slotId)
	if holding := fixture.storedHolding(slot.wrapped[0]); len(holding) != 1 || holding[0] != slotKey {
		t.Fatalf("the key stored in %v, its slot alone wanted", holding)
	}
	fixture.clock.Advance(time.Minute)
	fixture.requireCommitted(fixture.slotsDelete(fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slot.slotId, KeyIndex: 0}), "admin"), 1)
	fixture.awaitStepEights()
	if indexes := fixture.slotIndexes(slot.slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v after erasing key 0", indexes)
	}

	pushId := sidecar.Id(built.Statement.Push.GetPushId())
	requireErased := func(stage string) {
		t.Helper()
		// a token of the clock's now, since each stage moves it past the last one's 15 min
		readToken := fixture.token(fixture.check.signerId, "r")
		if holding := fixture.storedHolding(slot.wrapped[0]); len(holding) != 0 {
			t.Fatalf("%s: the erased key is stored in %v", stage, holding)
		}
		pushes := []*protocol.EvsReadPush{}
		for part := range uint32(len(built.Parts) + 1) {
			pushes = append(pushes, &protocol.EvsReadPush{PushId: pushId.Bytes(), Version: 1, Part: part})
		}
		recorder := fixture.call(readToken, http.MethodPost, "/read", &protocol.EvsReadRequest{RefId: fixture.check.refId.Bytes(), Pushes: pushes})
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: the read: status %d", stage, recorder.Code)
		}
		if bytes.Contains(recorder.Body.Bytes(), slot.wrapped[0]) {
			t.Fatalf("%s: a served record holds the erased key", stage)
		}
		reply := decodeReadFrames(t, recorder.Body.Bytes())
		served := 0
		for _, object := range reply.objects {
			if object.GetKind() == protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD && !object.GetMissing() {
				served += 1
			}
		}
		if served != len(built.Parts)+1 {
			t.Fatalf("%s: %d records served, want the seal's and %d parts'", stage, served, len(built.Parts))
		}
	}
	requireErased("in the batches")
	nightly.age()
	nightly.mustRun()
	if parcels := nightly.keys("meta-1", "hp/"); len(parcels) == 0 {
		t.Fatal("evacuation wrote no parcel")
	}
	requireErased("in a parcel")
	nightly.clock.Advance(6 * 24 * time.Hour)
	deps := nightly.deps()
	deps.Evacuator = nightly.evacuateFixture.settings
	pass, err := NewNightlyPass(fixture.host.ServiceHost(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := pass.Run(fixture.ctx, "meta-1", "", ""); err != nil {
		t.Fatalf("the nightly pass: %v (%+v)", err, result)
	}
	if packs := nightly.keys(nightly.segmentCluster().ClusterId(), "pack/"); len(packs) == 0 {
		t.Fatal("the nightly pass wrote no pack")
	}
	requireErased("in a pack")
}
