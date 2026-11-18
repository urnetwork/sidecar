// Resolve and evacuation over a one-part re-seeded push's record (§11.8's Resolve row and §11.13's resolve row as the
// owner's answer QD-872 amends them; resolve.go, evacuate_resolve.go), on T2's fakes through the reseed route and the
// hourly evacuation: the record resolves by its statement as a push's does, with the fence in place of the time
// clause. Committed at its place it is kept; a second copy is dropped as a push's is; one its ref's history never
// commits is pending whatever its statement's age and whatever fence the head held before the run held the record,
// and dead once the ref is fenced since, dropped with nothing else. The owner's answer QD-974 extends the rule to a
// re-seeded push's parts and its seal, and this build to every seal, which
// TestResolveJudgesReseededPartsAndEverySealByTheFence holds.
//
// evacuate_reseed_testhooks_test.go holds the schedules that leave such records through the reseed route's own
// attempts: a rerun a live push's commit refused, and a retry that commits while the first attempt waits.
// evacuate_reseed_seal_testhooks_test.go holds a re-seed's seal attempt stalled at its head CAS past a run.

package evsservice

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The EVS_BATCH_RESEED record the reseed mode's step 6 writes for body, a one-part push's call: its statement, and its
// payload with no slot body.
func (self *reseedFixture) reseedRecord(body *protocol.EvsReseedRequest) *sidecar.EvsBatchRecord {
	self.t.Helper()
	statement, err := sidecar.ParseEvsStatement(body.GetStatement())
	if err != nil {
		self.t.Fatal(err)
	}
	recordPayload, err := sidecar.EvsRecordPayload(body.GetPayload())
	if err != nil {
		self.t.Fatal(err)
	}
	push := statement.Push
	return &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_RESEED, RepoId: self.check.repoId, RefId: sidecar.Id(push.GetRefId()),
		PushId: sidecar.Id(push.GetPushId()), SignerSidecarId: sidecar.Id(push.GetSignerSidecarId()), TimeMs: push.GetTimeMs(),
		Body: sidecar.EvsPushRecordBody(body.GetStatement(), recordPayload),
	}
}

// Resolve's rule for a reseed record. Its statement is a month old, so the time clause would call it dead on any
// fence: it is pending on a head with no fence, on one whose fence is older than the time its resolver held it by,
// and for a resolver that holds no such time; dead on a fence at or past that time, and once the head stands 64 past
// its base; committed where its ref's history names it, with its version and place. The same statement in a push's
// record is dead on the older fence, by its time.
func TestResolveJudgesAReseedRecordByTheFenceInPlaceOfItsStatementsTime(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	first := fixture.kept()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(first)), 1)
	head := fixture.head()
	window, err := EvsHeadWindow(head.Head)
	if err != nil || len(window) != 1 {
		t.Fatalf("window of %d: %v", len(window), err)
	}
	heldTime := fixture.clock.Now()
	resolve := func(record *sidecar.EvsBatchRecord, head *protocol.EvsHead, heldTime time.Time) *EvsResolution {
		t.Helper()
		resolution, err := fixture.engine.ResolvePush(fixture.ctx, fixture.cluster, record, head, heldTime)
		if err != nil {
			t.Fatal(err)
		}
		return resolution
	}
	if resolution := resolve(fixture.recordAt(check.refId, 1), head.Head, heldTime); resolution.State != EvsResolveCommitted ||
		resolution.Version != 1 || !placesEqual(resolution.Place, window[0].Place) {
		t.Fatalf("the committed reseed record resolves %+v", resolution)
	}

	never := fixture.kept()
	fixture.create(never, "b")
	record := fixture.reseedRecord(fixture.reseedBody(never))
	fencedAt := func(fenceTime time.Time) *protocol.EvsHead {
		fenced := CloneEvsHead(head.Head)
		fenced.Fence += 1
		fenced.FenceMs = fenceTime.UnixMilli()
		return fenced
	}
	older := fencedAt(heldTime.Add(-time.Millisecond))
	for label, pending := range map[string]*EvsResolution{
		"no head":                  resolve(record, nil, heldTime),
		"no fence":                 resolve(record, head.Head, heldTime),
		"an older fence":           resolve(record, older, heldTime),
		"a resolver with no time":  resolve(record, fencedAt(heldTime.Add(time.Hour)), time.Time{}),
		"a fence long before held": resolve(record, fencedAt(heldTime.Add(-24*time.Hour)), heldTime),
	} {
		if pending.State != EvsResolvePending {
			t.Fatalf("%s: resolved %+v, want pending", label, pending)
		}
	}
	for label, dead := range map[string]*EvsResolution{
		"a fence at the time held": resolve(record, fencedAt(heldTime), heldTime),
		"a later fence":            resolve(record, fencedAt(heldTime.Add(time.Hour)), heldTime),
	} {
		if dead.State != EvsResolveDead {
			t.Fatalf("%s: resolved %+v, want dead", label, dead)
		}
	}
	// the statement in a push's record is past its time checks, so the older fence ends it
	pushed := *record
	pushed.Type = protocol.EvsBatchRecordType_EVS_BATCH_PUSH
	if resolution := resolve(&pushed, older, heldTime); resolution.State != EvsResolveDead {
		t.Fatalf("the statement as a push's record resolves %+v on the older fence", resolution)
	}

	// 64 commits past its base: it can no longer land within (b, b+64], fence or none
	for i := 0; i < evsFileModeBaseWindow+1; i += 1 {
		next := fixture.plan()
		fixture.create(next, fmt.Sprintf("after %d", i))
		fixture.requireCommitted(fixture.push(next), uint64(2+i))
	}
	if resolution := resolve(record, fixture.head().Head, time.Time{}); resolution.State != EvsResolveDead {
		t.Fatalf("resolved %+v past its base's window", resolution)
	}
}

// The EVS_BATCH_SEAL record step 6 writes for built's parts at places, a re-seed's or the push route's alike.
func (self *reseedFixture) sealRecord(built *sidecar.EvsBuiltPush, places []*protocol.EvsPlace) *sidecar.EvsBatchRecord {
	self.t.Helper()
	parts := make([]*sidecar.EvsSealPart, len(places))
	for i, place := range places {
		checked, err := sidecar.EvsCheckPart(built.Statement, built.Parts[i])
		if err != nil {
			self.t.Fatal(err)
		}
		parts[i] = &sidecar.EvsSealPart{Place: place, ChangesRoot: checked.Root, FirstTokenPath: checked.FirstTokenPath()}
	}
	push := built.Statement.Push
	return &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_SEAL, RepoId: self.check.repoId, RefId: sidecar.Id(push.GetRefId()),
		PushId: sidecar.Id(push.GetPushId()), SignerSidecarId: sidecar.Id(push.GetSignerSidecarId()), TimeMs: push.GetTimeMs(),
		Body: sidecar.EvsSealRecordBody(built.Statement.Bytes, parts),
	}
}

// Resolve's rule for a re-seed's other records and for every seal (QD-974): a re-seeded push's part, its seal as the
// reseed mode writes it, and a seal of the push route's, none committed, are pending on no head, on a head with no
// fence, on one whose fence is older than the time their resolver held them by, however far past their statements'
// time, and for a resolver that holds no such time; dead on a fence at or past that time, and once the head stands 64
// past their base. A part of the push route's keeps the time clause, its seal held to 30 min of its time_ms: pending
// with no fence, dead on the older fence.
func TestResolveJudgesReseededPartsAndEverySealByTheFence(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	first := fixture.kept()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(first)), 1)
	head := fixture.head()
	recordAt := func(place *protocol.EvsPlace) *sidecar.EvsBatchRecord {
		t.Helper()
		record, err := fixture.engine.readRecordAt(fixture.ctx, fixture.cluster, check.repoId, check.refId, place)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	// a re-seed's push in parts and one of the push route's, each sealed by nobody yet
	reseeded := fixture.built(fixture.keptParts(1100))
	reseededPlaces := fixture.reseedParts(reseeded)
	pushedPlan := fixture.plan()
	for i := 0; i < 1100; i += 1 {
		fixture.create(pushedPlan, fmt.Sprintf("p-%05d", i))
	}
	pushed := fixture.built(pushedPlan)
	pushedPlaces := fixture.postParts(fixture.token(check.signerId), pushed)
	pushedPart := recordAt(pushedPlaces[0])
	fenced := []struct {
		label  string
		record *sidecar.EvsBatchRecord
	}{
		{label: "a re-seeded part", record: recordAt(reseededPlaces[0])},
		{label: "a re-seeded seal", record: fixture.sealRecord(reseeded, reseededPlaces)},
		{label: "a seal of the push route's", record: fixture.sealRecord(pushed, pushedPlaces)},
	}
	if !sidecar.EvsReseedRecordHoldsPart(fenced[0].record) || pushedPart.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART {
		t.Fatalf("the parts' records are of types %s and %s", fenced[0].record.Type, pushedPart.Type)
	}
	resolve := func(record *sidecar.EvsBatchRecord, head *protocol.EvsHead, heldTime time.Time) EvsResolveState {
		t.Helper()
		resolution, err := fixture.engine.ResolvePush(fixture.ctx, fixture.cluster, record, head, heldTime)
		if err != nil {
			t.Fatal(err)
		}
		return resolution.State
	}
	fencedAt := func(fenceTime time.Time) *protocol.EvsHead {
		fencedHead := CloneEvsHead(head.Head)
		fencedHead.Fence += 1
		fencedHead.FenceMs = fenceTime.UnixMilli()
		return fencedHead
	}
	// as a run holds them 25 h on; the older fence an hour on, past every statement's time clause
	heldTime := fixture.clock.Now().Add(25*time.Hour + 2*time.Minute)
	older := fencedAt(fixture.clock.Now().Add(time.Hour))
	for _, each := range fenced {
		for _, c := range []struct {
			on       string
			head     *protocol.EvsHead
			heldTime time.Time
			state    EvsResolveState
		}{
			{on: "no head", head: nil, heldTime: heldTime, state: EvsResolvePending},
			{on: "no fence", head: head.Head, heldTime: heldTime, state: EvsResolvePending},
			{on: "an older fence", head: older, heldTime: heldTime, state: EvsResolvePending},
			{on: "a resolver with no time", head: fencedAt(heldTime.Add(time.Hour)), heldTime: time.Time{}, state: EvsResolvePending},
			{on: "a fence at the time held", head: fencedAt(heldTime), heldTime: heldTime, state: EvsResolveDead},
			{on: "a later fence", head: fencedAt(heldTime.Add(time.Hour)), heldTime: heldTime, state: EvsResolveDead},
		} {
			if state := resolve(each.record, c.head, c.heldTime); state != c.state {
				t.Errorf("%s on %s resolves %d, want %d", each.label, c.on, state, c.state)
			}
		}
	}
	if state := resolve(pushedPart, head.Head, heldTime); state != EvsResolvePending {
		t.Errorf("a part of the push route's resolves %d with no fence", state)
	}
	if state := resolve(pushedPart, older, heldTime); state != EvsResolveDead {
		t.Errorf("a part of the push route's resolves %d on the older fence, past its statement's time", state)
	}

	// 64 commits past their base: none can land within (b, b+64], fence or none
	for i := 0; i < evsFileModeBaseWindow+1; i += 1 {
		next := fixture.plan()
		fixture.create(next, fmt.Sprintf("after %d", i))
		fixture.requireCommitted(fixture.push(next), uint64(2+i))
	}
	for _, each := range fenced {
		if state := resolve(each.record, fixture.head().Head, time.Time{}); state != EvsResolveDead {
			t.Errorf("%s resolves %d past its base's window", each.label, state)
		}
	}
}

// A second copy of a committed re-seeded push, at a place its ref's history does not name, as an attempt that lost
// the head CAS to another attempt of its push leaves one: dropped with its batch and nothing else, as a push's copy
// is, and the committed record leaves for a parcel as its batch held it. No fence is raised for it.
func TestEvacuationDropsASecondCopyOfACommittedReseedRecord(t *testing.T) {
	evacuate := newEvacuateFixture(t, nil)
	fixture := reseedFixtureOf(evacuate.pushFixture)
	check := fixture.check
	plan := fixture.kept()
	fixture.create(plan, "a")
	body := fixture.reseedBody(plan)
	fixture.requireCommitted(fixture.reseed(body), 1)
	fixture.awaitStepEights()
	before := fixture.recordAt(check.refId, 1)
	_, copies := evacuate.putBatch(1, fixture.reseedRecord(body))
	head := fixture.head()

	evacuate.age()
	result := evacuate.mustRun()
	if result.KeptCount != 1 || result.DuplicateCount != 1 || result.DeadCount != 0 || result.FenceCount != 0 ||
		result.BatchDeletedCount != 2 || result.ParcelCount != 1 || result.WaitingCount != 0 || result.HasBatches {
		t.Fatalf("result %+v", result)
	}
	if after := fixture.head(); after.Etag != head.Etag {
		t.Fatal("a duplicate's evacuation wrote the head")
	}
	if _, err := evacuate.readRecord(check.refId, copies[0]); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("the second copy still reads: %v", err)
	}
	after := fixture.recordAt(check.refId, 1)
	if after.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || after.PushId != before.PushId || !bytes.Equal(after.Body, before.Body) {
		t.Fatalf("version 1's record from its parcel is type %s", after.Type)
	}
	// the re-seed's retry finds the push committed where its record moved
	fixture.requireCommitted(fixture.reseed(body), 1)
}

// A reseed record its ref's history never commits, on a ref whose head already held an evacuation fence from before
// the record was written, and listing a new slot that stands under its own statement's origin, with the delete of a
// dead record's own slots on. While this process's clock is unsure no fence is raised and the record's minute waits.
// Once it is sure, the older fence ends nothing of this record, so the run raises the ref's fence again, one head CAS
// that changes no version, and the record, still not committed, is dead: its batch goes within the run, and nothing
// else does, the slot it lists neither deleted nor counted, since the reseed mode writes none.
func TestEvacuationFencesThenDropsAReseedRecordItsRefNeverCommits(t *testing.T) {
	evacuate := newSlotEvacuateFixture(t)
	fixture := reseedFixtureOf(evacuate.pushFixture)
	check := fixture.check
	first := fixture.kept()
	fixture.create(first, "a")
	firstBody := fixture.reseedBody(first)
	fixture.requireCommitted(fixture.reseed(firstBody), 1)
	fixture.awaitStepEights()
	committed := fixture.recordAt(check.refId, 1)
	// an evacuation fence from before the re-seeded push's attempt arrived
	if _, err := fixture.engine.heads.RaiseFence(fixture.paidContext(), fixture.cluster, check.repoId, check.refId); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(2 * time.Minute)

	slotId, slotObject, slotBody := checkTestSlot(t, "reseed never committed")
	body := fixture.keptWithSlot(slotId, slotObject, slotBody, "b")
	statement, err := sidecar.ParseEvsStatement(body.GetStatement())
	if err != nil {
		t.Fatal(err)
	}
	own, err := EvsSlotOriginOf(statement)
	if err != nil {
		t.Fatal(err)
	}
	fixture.plantSlot(slotId, slotBody, own)
	neverKey, neverPlaces := evacuate.putBatch(1, fixture.reseedRecord(body))
	before := fixture.head()
	if before.Head.GetFenceMs() == 0 || fixture.clock.Now().UnixMilli() <= before.Head.GetFenceMs() {
		t.Fatalf("the older fence's fence_ms is %d", before.Head.GetFenceMs())
	}
	evacuate.age()

	fixture.host.ClockCheck.SetUnknown()
	result := evacuate.mustRun()
	if result.FenceCount != 0 || result.DeadCount != 0 || result.WaitingCount != 1 || result.MinuteWaitingCount != 1 || result.KeptCount != 1 ||
		result.BatchDeletedCount != 1 {
		t.Fatalf("result on an unsure clock %+v", result)
	}
	if head := fixture.head(); head.Etag != before.Etag {
		t.Fatal("an unsure clock wrote the head")
	}
	if keys := evacuate.keys("meta-1", batchKeyPrefix); !slices.Equal(keys, []string{neverKey}) {
		t.Fatalf("batches %v", keys)
	}

	fixture.host.ClockCheck.SetOffset(0)
	result = evacuate.mustRun()
	if result.FenceCount != 1 || result.DeadCount != 1 || result.KeptCount != 0 || result.DuplicateCount != 0 || result.WaitingCount != 0 ||
		result.MinuteWaitingCount != 0 || result.BatchDeletedCount != 1 || result.HasBatches {
		t.Fatalf("result once sure %+v", result)
	}
	if result.SlotDeletedCount != 0 || result.SlotKeptCount != 0 || result.SlotForeignCount != 0 || result.SlotAbsentCount != 0 ||
		result.SlotUnsettledCount != 0 || result.SlotHeldCount != 0 || result.SlotChangedCount != 0 {
		t.Fatalf("a dead reseed record's slot was judged: %+v", result)
	}
	if slices.Contains(evacuate.steps, BarrierEvacuateSlotHeadBefore) {
		t.Fatal("a slot a dead reseed record lists was HEADed")
	}
	after := fixture.head()
	if after.Version() != before.Version() || after.Head.GetFence() != before.Head.GetFence()+1 || after.Head.GetFenceMs() != fixture.clock.Now().UnixMilli() {
		t.Fatalf("the fence wrote version %d fence %d fence_ms %d", after.Version(), after.Head.GetFence(), after.Head.GetFenceMs())
	}
	if stored, origin, _, found := fixture.slotObject(slotId); !found || origin != own || !bytes.Equal(stored, slotBody) {
		t.Fatalf("the slot the dead reseed record lists: found %t under %+v", found, origin)
	}
	if _, err := evacuate.readRecord(check.refId, neverPlaces[0]); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("the dead reseed record still reads: %v", err)
	}
	if kept := fixture.recordAt(check.refId, 1); kept.Type != committed.Type || !bytes.Equal(kept.Body, committed.Body) {
		t.Fatal("version 1's record reads other bytes from its parcel")
	}
	// the push its record named was never committed, and its statement commits when the device sends it again, in an
	// attempt that arrives after the fence
	fixture.clock.Advance(time.Second)
	fixture.requireCommitted(fixture.reseed(body), 2)
}
