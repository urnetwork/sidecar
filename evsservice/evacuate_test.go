// EVSB-M2-11's tests: the hourly evacuation on T2's fakes, over records the push route really wrote, on one fake
// clock. Resolve's four answers and what each deletes, the fence and its two refusals (an unsure clock, a ref with
// no head), the skip row's repo states and holds, parcels, packs at their size and at 7 d, the resume row with a
// stop at every barrier, a seal evacuated a run after its parts, an unknown batch format, the job's chain, and
// HoldCache. A reader here is a fresh RecordLocator, so nothing a process cached answers for the store.

package evsservice

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The push fixture with an evacuator's settings and a stop at one barrier.
type evacuateFixture struct {
	*pushFixture
	settings *EvacuatorSettings
	// barriers a run passed, in order
	steps []string
	// the barrier the next run stops at, once
	stopAt string
}

func newEvacuateFixture(t *testing.T, adjust func(settings *EvacuatorSettings)) *evacuateFixture {
	settings := DefaultEvacuatorSettings()
	settings.SpoolDirectory = t.TempDir()
	if adjust != nil {
		adjust(settings)
	}
	return &evacuateFixture{pushFixture: newPushFixture(t, nil), settings: settings}
}

// A new evacuator, as a new taskworker run builds one: no cache of an earlier run.
func (self *evacuateFixture) evacuator() *Evacuator {
	self.t.Helper()
	evacuator, err := NewEvacuator(self.host.ServiceHost(), &EvacuatorDeps{
		Settings:    self.settings,
		EvsSettings: self.settings2(),
		atStep: func(name string, key string) error {
			self.steps = append(self.steps, name)
			if name == self.stopAt {
				self.stopAt = ""
				return errors.New("killed here")
			}
			return nil
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return evacuator
}

// The engine's settings, which the evacuator reads repo/'s cache age and the fence's retries from.
func (self *evacuateFixture) settings2() *EvsSettings {
	return self.pushFixture.settings
}

// One run on meta-1.
func (self *evacuateFixture) run() (*EvacuationResult, error) {
	self.t.Helper()
	return self.evacuator().Run(self.ctx, "meta-1")
}

// One run that must end clean.
func (self *evacuateFixture) mustRun() *EvacuationResult {
	self.t.Helper()
	result, err := self.run()
	if err != nil {
		self.t.Fatalf("run: %v (%+v)", err, result)
	}
	return result
}

// The keys under prefix on a cluster.
func (self *evacuateFixture) keys(clusterId string, prefix string) []string {
	self.t.Helper()
	cluster, err := self.host.Blobs.Cluster(clusterId)
	if err != nil {
		self.t.Fatal(err)
	}
	keys := []string{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(self.ctx, prefix, startAfter, 1000)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, object := range objects {
			keys = append(keys, object.Key)
			startAfter = object.Key
		}
		if !more {
			return keys
		}
	}
}

// The record at place as a reader with no cache finds it: in its batch, or through pidx/.
func (self *evacuateFixture) readRecord(refId sidecar.Id, place *protocol.EvsPlace) ([]byte, error) {
	return NewRecordLocator(self.host.Blobs, nil).ReadRecord(self.ctx, self.cluster, self.check.repoId, refId, place)
}

// The record must read as want.
func (self *evacuateFixture) requireRecord(place *protocol.EvsPlace, want []byte) {
	self.t.Helper()
	got, err := self.readRecord(self.check.refId, place)
	if err != nil {
		self.t.Fatalf("the record at %s: %v", placeKey(place), err)
	}
	if !bytes.Equal(got, want) {
		self.t.Fatalf("the record at %s reads other bytes", placeKey(place))
	}
}

// A one-part push committed, creating label: its place in the head's window and its record's bytes.
func (self *evacuateFixture) commit(label string) (*protocol.EvsPlace, []byte) {
	self.t.Helper()
	plan := self.plan()
	self.create(plan, label)
	self.requireCommitted(self.push(plan), plan.BaseVersion+1)
	self.awaitStepEights()
	window, err := EvsHeadWindow(self.head().Head)
	if err != nil || len(window) == 0 {
		self.t.Fatalf("window %v", err)
	}
	place := window[len(window)-1].Place
	recordBytes, err := self.readRecord(self.check.refId, place)
	if err != nil {
		self.t.Fatal(err)
	}
	return place, recordBytes
}

// A push record of plan, built and signed but never posted.
func (self *evacuateFixture) unposted(plan *sidecar.EvsPushPlan) *sidecar.EvsBatchRecord {
	body := self.body(plan)
	return &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: plan.RepoId, RefId: plan.RefId,
		PushId: plan.PushId, SignerSidecarId: self.check.signerId, TimeMs: plan.TimeMs,
		Body: sidecar.EvsPushRecordBody(body.Statement, body.Payload),
	}
}

// A batch of records written by hand in the clock's minute, as another evs process would have: its key and places.
func (self *evacuateFixture) putBatch(seq uint32, records ...*sidecar.EvsBatchRecord) (string, []*protocol.EvsPlace) {
	self.t.Helper()
	now := self.clock.Now()
	writer := sidecar.NewEvsBatchWriter(0x7e57, BatchMinute(now), seq, now.UnixMilli())
	places := []*protocol.EvsPlace{}
	for _, record := range records {
		place, err := writer.Add(record)
		if err != nil {
			self.t.Fatal(err)
		}
		places = append(places, place)
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		self.t.Fatal(err)
	}
	key := BatchKey(BatchMinute(now), 0x7e57, seq)
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, key, batchBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	return key, places
}

// Past the 25 h mark of everything written so far.
func (self *evacuateFixture) age() {
	self.clock.Advance(25*time.Hour + 2*time.Minute)
}

// A committed record leaves its batch for a parcel with its pidx/ entry, the batch is deleted whole, and a reader
// finds the record's bytes as its batch held them.
func TestEvacuationMovesACommittedRecordToAParcel(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	place, recordBytes := fixture.commit("a")

	// under 25 h: nothing is due
	fixture.clock.Advance(24*time.Hour + 58*time.Minute)
	early := fixture.mustRun()
	if early.MinuteCount != 0 || len(fixture.keys("meta-1", batchKeyPrefix)) != 1 {
		t.Fatalf("a batch under 25 h old was taken: %+v", early)
	}
	if !early.HasBatches || early.OldestBatchAge < 24*time.Hour {
		t.Fatalf("oldest batch %s %t", early.OldestBatchAge, early.HasBatches)
	}

	fixture.clock.Advance(4 * time.Minute)
	result := fixture.mustRun()
	if result.KeptCount != 1 || result.ParcelCount != 1 || result.PackCount != 0 || result.BatchDeletedCount != 1 || result.MinuteDeletedCount != 1 || result.MinuteWaitingCount != 0 {
		t.Fatalf("result %+v", result)
	}
	if result.HasBatches {
		t.Fatal("a batch is still listed")
	}
	if keys := fixture.keys("meta-1", batchKeyPrefix); len(keys) != 0 {
		t.Fatalf("batches left: %v", keys)
	}
	parcels := fixture.keys("meta-1", parcelKeyPrefix)
	entries := fixture.keys("meta-1", pidxKeyPrefix)
	if len(parcels) != 1 || len(entries) != 1 {
		t.Fatalf("parcels %v entries %v", parcels, entries)
	}
	if !strings.HasPrefix(entries[0], PidxRefPrefix(fixture.check.repoId, fixture.check.refId)+keyNumber(1)+"-") {
		t.Fatalf("the entry's key %s does not name version 1", entries[0])
	}
	fixture.requireRecord(place, recordBytes)
	// the order a kill may land in: container, entry, then the batch
	want := []string{
		BarrierEvacuateContainerPutBefore, BarrierEvacuateContainerPutAfter,
		BarrierEvacuatePidxPutBefore, BarrierEvacuatePidxPutAfter,
		BarrierEvacuateBatchDeleteBefore, BarrierEvacuateBatchDeleteAfter,
	}
	if !slices.Equal(fixture.steps, want) {
		t.Fatalf("steps %v", fixture.steps)
	}
	// every write was P2 funded work, and none went unpriced
	if fixture.host.Budget.P2ByteCount("meta-1", true) == 0 || len(fixture.host.Budget.Violations()) != 0 {
		t.Fatalf("funded P2 %d, violations %v", fixture.host.Budget.P2ByteCount("meta-1", true), fixture.host.Budget.Violations())
	}
	if got := fixture.host.Metrics.Value(evacuateRecordsMetricName, "meta-1", evacuateOutcomeKept); got != 1 {
		t.Fatalf("kept counter %v", got)
	}
	// a run with nothing due does nothing
	if again := fixture.mustRun(); again.MinuteCount != 0 {
		t.Fatalf("a second run took %+v", again)
	}
}

// A second copy of a committed push, at a place its ref's history does not name, is dropped with its batch and
// nothing else: the committed copy is the one a container holds.
func TestEvacuationDropsACopyCommittedAtAnotherPlace(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	place, recordBytes := fixture.commit("a")
	committed, err := sidecar.ParseEvsBatchRecord(recordBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, copies := fixture.putBatch(1, committed)
	fixture.age()
	result := fixture.mustRun()
	if result.KeptCount != 1 || result.DuplicateCount != 1 || result.BatchDeletedCount != 2 || result.FenceCount != 0 {
		t.Fatalf("result %+v", result)
	}
	fixture.requireRecord(place, recordBytes)
	if _, err := fixture.readRecord(fixture.check.refId, copies[0]); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("the uncommitted copy still reads: %v", err)
	}
}

// A pending record on an idle ref: the ref is fenced by one head CAS that sets fence_ms and changes no version, the
// record then resolves dead, its new slot is deleted and its batch goes. The committed record beside it is kept.
func TestEvacuationFencesThenDropsAPendingRecord(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	place, recordBytes := fixture.commit("a")
	slotId, slotObject, slotBody := checkTestSlot(t, "dead push")
	pending := fixture.plan()
	pending.Changes = append(pending.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("b"), EntryVersion: fixture.check.fileEntry(pending, 2, nil, slotId),
	})
	pending.NewObjects = append(pending.NewObjects, slotObject)
	pending.SlotBodies = append(pending.SlotBodies, slotBody)
	fixture.putBatch(1, fixture.unposted(pending))
	// step 6 wrote its slot before the attempt died
	if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, SlotKey(fixture.check.repoId, slotId), slotBody, nil); err != nil {
		t.Fatal(err)
	}
	before := fixture.head()
	fixture.age()
	result := fixture.mustRun()
	if result.FenceCount != 1 || result.DeadCount != 1 || result.KeptCount != 1 || result.SlotDeletedCount != 1 || result.BatchDeletedCount != 2 {
		t.Fatalf("result %+v", result)
	}
	after := fixture.head()
	if after.Version() != before.Version() || after.Head.GetFence() != before.Head.GetFence()+1 || after.Head.GetFenceMs() != fixture.clock.Now().UnixMilli() {
		t.Fatalf("the fence wrote version %d fence %d fence_ms %d", after.Version(), after.Head.GetFence(), after.Head.GetFenceMs())
	}
	if _, err := fixture.cluster.Head(fixture.ctx, SlotKey(fixture.check.repoId, slotId)); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("the dead push's slot stands: %v", err)
	}
	fixture.requireRecord(place, recordBytes)
	if !slices.Contains(fixture.steps, BarrierEvacuateFenceBefore) || !slices.Contains(fixture.steps, BarrierEvacuateFenceAfter) {
		t.Fatalf("steps %v", fixture.steps)
	}
}

// While this process's clock is unsure no fence is raised: the pending record stays, and its minute waits with every
// batch of it, while an older minute with nothing pending is evacuated. Once the clock is sure the next run fences.
func TestEvacuationRaisesNoFenceOnAnUnsureClock(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	place, recordBytes := fixture.commit("a")
	fixture.clock.Advance(2 * time.Minute)
	pending := fixture.plan()
	fixture.create(pending, "b")
	pendingKey, _ := fixture.putBatch(1, fixture.unposted(pending))
	before := fixture.head()
	fixture.age()

	fixture.host.ClockCheck.SetUnknown()
	result := fixture.mustRun()
	if result.FenceCount != 0 || result.WaitingCount != 1 || result.MinuteWaitingCount != 1 || result.KeptCount != 1 || result.BatchDeletedCount != 1 {
		t.Fatalf("result %+v", result)
	}
	if head := fixture.head(); head.Etag != before.Etag {
		t.Fatal("an unsure clock wrote the head")
	}
	if keys := fixture.keys("meta-1", batchKeyPrefix); !slices.Equal(keys, []string{pendingKey}) {
		t.Fatalf("batches %v", keys)
	}
	fixture.requireRecord(place, recordBytes)

	fixture.host.ClockCheck.SetOffset(0)
	result = fixture.mustRun()
	if result.FenceCount != 1 || result.DeadCount != 1 || result.BatchDeletedCount != 1 || result.HasBatches {
		t.Fatalf("result once sure %+v", result)
	}
}

// A pending record on a ref with no head has nothing to fence, and no rule here says how such a ref is fenced
// (DESIGN-DETAILS.md's problem 2): it stays, its minute waits, and no head is written.
func TestEvacuationLeavesAPendingRecordOnARefWithNoHead(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	pending := fixture.plan()
	fixture.create(pending, "a")
	key, _ := fixture.putBatch(1, fixture.unposted(pending))
	fixture.age()
	result := fixture.mustRun()
	if result.WaitingCount != 1 || result.FenceCount != 0 || result.BatchDeletedCount != 0 || result.MinuteWaitingCount != 1 {
		t.Fatalf("result %+v", result)
	}
	if !fixture.head().Absent() {
		t.Fatal("a head was written for a ref that had none")
	}
	if keys := fixture.keys("meta-1", batchKeyPrefix); !slices.Equal(keys, []string{key}) {
		t.Fatalf("batches %v", keys)
	}
}

// The skip row: an unheld repo in shredding loses its batched records with nothing written for it; a deleted,
// restorable repo keeps them.
func TestEvacuationDropsAnUnheldShreddingReposRecordsAndKeepsADeletedRepos(t *testing.T) {
	shredding := newEvacuateFixture(t, nil)
	shredding.commit("a")
	shredding.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_SHREDDING)
	shredding.age()
	result := shredding.mustRun()
	if result.ShreddedCount != 1 || result.KeptCount != 0 || result.BatchDeletedCount != 1 {
		t.Fatalf("shredding: %+v", result)
	}
	if keys := append(shredding.keys("meta-1", parcelKeyPrefix), shredding.keys("meta-1", pidxKeyPrefix)...); len(keys) != 0 {
		t.Fatalf("a shredding repo had objects written: %v", keys)
	}

	deleted := newEvacuateFixture(t, nil)
	place, recordBytes := deleted.commit("a")
	deleted.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_DELETED)
	deleted.age()
	result = deleted.mustRun()
	if result.KeptCount != 1 || result.ParcelCount != 1 || result.BatchDeletedCount != 1 {
		t.Fatalf("deleted: %+v", result)
	}
	deleted.requireRecord(place, recordBytes)
}

// A held network's records, a shredding repo's included, are moved as usual and nothing of the repo is deleted
// while the hold stands: a dead push's slot stays, and a parcel a pack replaced stays with its entries.
func TestEvacuationMovesAHeldReposRecordsAndDeletesNothingOfIt(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	first, firstBytes := fixture.commit("a")
	fixture.age()
	if result := fixture.mustRun(); result.ParcelCount != 1 {
		t.Fatalf("first run %+v", result)
	}
	parcels := fixture.keys("meta-1", parcelKeyPrefix)

	second, secondBytes := fixture.commit("b")
	slotId, slotObject, slotBody := checkTestSlot(t, "held dead push")
	pending := fixture.plan()
	pending.Changes = append(pending.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("c"), EntryVersion: fixture.check.fileEntry(pending, 3, nil, slotId),
	})
	pending.NewObjects = append(pending.NewObjects, slotObject)
	pending.SlotBodies = append(pending.SlotBodies, slotBody)
	fixture.putBatch(1, fixture.unposted(pending))
	if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, SlotKey(fixture.check.repoId, slotId), slotBody, nil); err != nil {
		t.Fatal(err)
	}
	// the fence a pending record needs is raised while the repo is still active
	fixture.age()
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.check.networkId, CaseId: testId("hold case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_SHREDDING)
	// a pack is due by size, so the first run's parcel would be replaced
	fixture.settings.PackByteCount = 1
	result := fixture.mustRun()
	if result.KeptCount != 1 || result.PackCount != 1 || result.DeadCount != 1 || result.SlotDeletedCount != 0 || result.ReplacedParcelCount != 0 || result.BatchDeletedCount != 2 {
		t.Fatalf("held run %+v", result)
	}
	if _, err := fixture.cluster.Head(fixture.ctx, SlotKey(fixture.check.repoId, slotId)); err != nil {
		t.Fatalf("a held repo's slot was deleted: %v", err)
	}
	if kept := fixture.keys("meta-1", parcelKeyPrefix); !slices.Equal(kept, parcels) {
		t.Fatalf("a held repo's parcel was deleted: %v", kept)
	}
	if packs := fixture.keys("seg-1", packKeyPrefix); len(packs) != 1 {
		t.Fatalf("packs %v", packs)
	}
	fixture.requireRecord(first, firstBytes)
	fixture.requireRecord(second, secondBytes)
	// the next run finds the pack holding everything and writes nothing more
	fixture.clock.Advance(time.Hour)
	if again := fixture.mustRun(); again.PackCount != 0 || again.ParcelCount != 0 {
		t.Fatalf("a second held run wrote %+v", again)
	}
}

// A repo/ with no network reads as held with unknown terms: its records are moved and its dead push's slot stays.
func TestEvacuationKeepsEverythingOfARepoWithNoNetwork(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	fixture.commit("a")
	slotId, slotObject, slotBody := checkTestSlot(t, "no network dead push")
	pending := fixture.plan()
	pending.Changes = append(pending.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("b"), EntryVersion: fixture.check.fileEntry(pending, 2, nil, slotId),
	})
	pending.NewObjects = append(pending.NewObjects, slotObject)
	pending.SlotBodies = append(pending.SlotBodies, slotBody)
	fixture.putBatch(1, fixture.unposted(pending))
	if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, SlotKey(fixture.check.repoId, slotId), slotBody, nil); err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: fixture.check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := fixture.cluster.Head(fixture.ctx, RepoKey(fixture.check.repoId))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.cluster.PutIfMatch(fixture.ctx, RepoKey(fixture.check.repoId), info.Etag, repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	fixture.age()
	result := fixture.mustRun()
	if result.KeptCount != 1 || result.DeadCount != 1 || result.SlotDeletedCount != 0 || result.BatchDeletedCount != 2 {
		t.Fatalf("result %+v", result)
	}
	if _, err := fixture.cluster.Head(fixture.ctx, SlotKey(fixture.check.repoId, slotId)); err != nil {
		t.Fatalf("the slot of a repo with no network was deleted: %v", err)
	}
}

// Aged material at the pack's size goes to one pack on the segment cluster, with the parcel an earlier run wrote and
// the log page that has turned 24 h old; then the parcel, its entry and the log page are deleted, and a reader finds
// every record and the page through the pack.
func TestEvacuationPacksAtItsSizeAndDeletesWhatThePackReplaced(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	first, firstBytes := fixture.commit("first")
	fixture.age()
	if result := fixture.mustRun(); result.ParcelCount != 1 {
		t.Fatalf("first run %+v", result)
	}
	parcelEntries := fixture.keys("meta-1", pidxKeyPrefix)

	// enough commits to page the window's oldest 64 out to log/
	places := []*protocol.EvsPlace{}
	recordBytes := [][]byte{}
	for i := 0; len(fixture.keys("meta-1", logKeyPrefix)) == 0; i += 1 {
		if 200 < i {
			t.Fatal("no log page after 200 commits")
		}
		place, record := fixture.commit(fmt.Sprintf("more-%03d", i))
		places = append(places, place)
		recordBytes = append(recordBytes, record)
	}
	logKeys := fixture.keys("meta-1", logKeyPrefix)
	fixture.settings.PackByteCount = 1
	fixture.age()
	result := fixture.mustRun()
	if result.PackCount != 1 || result.ParcelCount != 0 || result.ReplacedParcelCount != 1 || result.PackedLogPageCount != len(logKeys) || result.KeptCount != len(places) {
		t.Fatalf("pack run %+v", result)
	}
	if left := append(fixture.keys("meta-1", parcelKeyPrefix), fixture.keys("meta-1", logKeyPrefix)...); len(left) != 0 {
		t.Fatalf("replaced objects left: %v", left)
	}
	for _, key := range parcelEntries {
		if slices.Contains(fixture.keys("meta-1", pidxKeyPrefix), key) {
			t.Fatalf("the replaced parcel's entry %s stands", key)
		}
	}
	if packs := fixture.keys("seg-1", packKeyPrefix); len(packs) != 1 {
		t.Fatalf("packs %v", packs)
	}
	fixture.requireRecord(first, firstBytes)
	for i, place := range places {
		fixture.requireRecord(place, recordBytes[i])
	}
	page, err := NewRecordLocator(fixture.host.Blobs, nil).ReadLogPage(fixture.ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, 0)
	if err != nil {
		t.Fatalf("the packed log page: %v", err)
	}
	if _, err := ParseLogPage(fixture.check.repoId, fixture.check.refId, 0, page); err != nil {
		t.Fatalf("the packed log page does not parse: %v", err)
	}
	if !slices.Contains(fixture.steps, BarrierEvacuateParcelDeleteBefore) || !slices.Contains(fixture.steps, BarrierEvacuateParcelDeleteAfter) {
		t.Fatalf("steps %v", fixture.steps)
	}
}

// A small repo's parcel packs once its oldest record would pass 7 d before the next run, in the run that evacuates
// the repo, however little it holds.
func TestEvacuationPacksASmallReposParcelAtSevenDays(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	first, firstBytes := fixture.commit("a")
	fixture.age()
	if result := fixture.mustRun(); result.ParcelCount != 1 {
		t.Fatalf("first run %+v", result)
	}
	// a second record four days on: both stay parcels
	fixture.clock.Advance(3 * 24 * time.Hour)
	second, secondBytes := fixture.commit("b")
	fixture.age()
	if result := fixture.mustRun(); result.ParcelCount != 1 || result.PackCount != 0 {
		t.Fatalf("second run %+v", result)
	}
	// a third as the first nears 7 d
	fixture.clock.Advance(7*24*time.Hour - fixture.clock.Now().Sub(batchMinuteTime(first.GetMinute())) - 26*time.Hour)
	third, thirdBytes := fixture.commit("c")
	fixture.age()
	result := fixture.mustRun()
	if result.PackCount != 1 || result.ReplacedParcelCount != 2 || result.ParcelCount != 0 {
		t.Fatalf("7 d run %+v", result)
	}
	if left := fixture.keys("meta-1", parcelKeyPrefix); len(left) != 0 {
		t.Fatalf("parcels left: %v", left)
	}
	fixture.requireRecord(first, firstBytes)
	fixture.requireRecord(second, secondBytes)
	fixture.requireRecord(third, thirdBytes)
}

// A run stopped at each barrier, as a kill there would leave it: a reader finds the record at every stop, and the
// next run finishes with one container holding it and no batch left.
func TestEvacuationResumesAfterAStopAtEachBarrier(t *testing.T) {
	stops := []string{
		BarrierEvacuateContainerPutBefore, BarrierEvacuateContainerPutAfter,
		BarrierEvacuatePidxPutBefore, BarrierEvacuatePidxPutAfter,
		BarrierEvacuateBatchDeleteBefore, BarrierEvacuateBatchDeleteAfter,
	}
	for _, stop := range stops {
		fixture := newEvacuateFixture(t, nil)
		place, recordBytes := fixture.commit("a")
		fixture.age()
		fixture.stopAt = stop
		if _, err := fixture.run(); !errors.Is(err, errEvacuateStopped) {
			t.Fatalf("%s: the stopped run ended %v", stop, err)
		}
		fixture.requireRecord(place, recordBytes)
		result := fixture.mustRun()
		fixture.requireRecord(place, recordBytes)
		if result.HasBatches || len(fixture.keys("meta-1", batchKeyPrefix)) != 0 {
			t.Errorf("%s: a batch is left after the rerun: %+v", stop, result)
		}
		if parcels := fixture.keys("meta-1", parcelKeyPrefix); len(parcels) != 1 {
			t.Errorf("%s: %d parcels after the rerun", stop, len(parcels))
		}
		if entries := fixture.keys("meta-1", pidxKeyPrefix); len(entries) != 1 {
			t.Errorf("%s: %d entries after the rerun", stop, len(entries))
		}
	}
}

// A run stopped around the fence and around a replaced parcel's delete resumes clean too: the fence already raised is
// read, not raised twice by the same record's dead answer, and the pack's deletes are made by the next run.
func TestEvacuationResumesAfterAStopAtTheFenceAndTheParcelDelete(t *testing.T) {
	for _, stop := range []string{BarrierEvacuateFenceBefore, BarrierEvacuateFenceAfter} {
		fixture := newEvacuateFixture(t, nil)
		place, recordBytes := fixture.commit("a")
		pending := fixture.plan()
		fixture.create(pending, "b")
		fixture.putBatch(1, fixture.unposted(pending))
		fixture.age()
		fixture.stopAt = stop
		if _, err := fixture.run(); !errors.Is(err, errEvacuateStopped) {
			t.Fatalf("%s: the stopped run ended %v", stop, err)
		}
		fixture.requireRecord(place, recordBytes)
		result := fixture.mustRun()
		wantFences := 1
		if stop == BarrierEvacuateFenceAfter {
			// the fence landed before the stop, so the record now resolves dead with no second fence
			wantFences = 0
		}
		if result.FenceCount != wantFences || result.DeadCount != 1 || result.KeptCount != 1 || result.HasBatches {
			t.Errorf("%s: rerun %+v", stop, result)
		}
		fixture.requireRecord(place, recordBytes)
	}

	for _, stop := range []string{BarrierEvacuateParcelDeleteBefore, BarrierEvacuateParcelDeleteAfter} {
		fixture := newEvacuateFixture(t, nil)
		first, firstBytes := fixture.commit("a")
		fixture.age()
		fixture.mustRun()
		second, secondBytes := fixture.commit("b")
		fixture.settings.PackByteCount = 1
		fixture.age()
		fixture.stopAt = stop
		if _, err := fixture.run(); !errors.Is(err, errEvacuateStopped) {
			t.Fatalf("%s: the stopped run ended %v", stop, err)
		}
		// readers take the pack's entry over the parcel's, whichever still stands
		fixture.requireRecord(first, firstBytes)
		fixture.requireRecord(second, secondBytes)
		result := fixture.mustRun()
		if result.PackCount != 0 || result.HasBatches {
			t.Errorf("%s: the rerun packed again or left a batch: %+v", stop, result)
		}
		if left := fixture.keys("meta-1", parcelKeyPrefix); len(left) != 0 {
			t.Errorf("%s: parcels left after the rerun: %v", stop, left)
		}
		if packs := fixture.keys("seg-1", packKeyPrefix); len(packs) != 1 {
			t.Errorf("%s: %d packs", stop, len(packs))
		}
		fixture.requireRecord(first, firstBytes)
		fixture.requireRecord(second, secondBytes)
	}
}

// The resume row: a run killed after its container and entries, restarted once more minutes are due, moves only what
// no container holds.
func TestEvacuationMovesOnlyWhatNoContainerHolds(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	first, firstBytes := fixture.commit("a")
	fixture.clock.Advance(30 * time.Minute)
	second, secondBytes := fixture.commit("b")
	// the first run takes only the first record's minute, and dies before its batch delete
	fixture.clock.Advance(24*time.Hour + 32*time.Minute)
	fixture.stopAt = BarrierEvacuateBatchDeleteBefore
	if _, err := fixture.run(); !errors.Is(err, errEvacuateStopped) {
		t.Fatalf("the stopped run ended %v", err)
	}
	firstParcels := fixture.keys("meta-1", parcelKeyPrefix)
	if len(firstParcels) != 1 {
		t.Fatalf("parcels %v", firstParcels)
	}
	// the restart takes both minutes: the first record is held, so its parcel holds the second alone
	fixture.clock.Advance(time.Hour)
	result := fixture.mustRun()
	if result.KeptCount != 2 || result.ParcelCount != 1 || result.BatchDeletedCount != 2 {
		t.Fatalf("restart %+v", result)
	}
	parcels := fixture.keys("meta-1", parcelKeyPrefix)
	if len(parcels) != 2 || !slices.Contains(parcels, firstParcels[0]) {
		t.Fatalf("parcels after the restart %v", parcels)
	}
	for _, key := range parcels {
		object, err := fixture.cluster.Get(fixture.ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		parcelBytes, _ := readAllLimited(object, 1024*1024)
		object.Body.Close()
		_, items, err := ParseContainer(parcelBytes)
		if err != nil || len(items) != 1 {
			t.Fatalf("parcel %s holds %d records: %v", key, len(items), err)
		}
	}
	fixture.requireRecord(first, firstBytes)
	fixture.requireRecord(second, secondBytes)
}

// A push in parts: its parts follow their seal, each kept at the seal's version when the seal's record names its
// place, a part posted twice leaving one copy dropped. The seal is evacuated a run after its parts, each container
// holding its own entry, and a reader finds the seal and every part.
func TestEvacuationOfPartsFollowsTheirSeal(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	places := fixture.postParts(token, built)
	// part 1 again, as a re-sent POST leaves it: a second copy the seal does not name
	extra := fixture.requirePlace(fixture.postPart(token, built, 0))
	if placesEqual(extra, places[0]) {
		t.Fatal("the second copy of a part took the first's place")
	}
	fixture.clock.Advance(10 * time.Minute)
	fixture.requireCommitted(fixture.seal(fixture.token(fixture.check.signerId), built, places), 1)
	fixture.awaitStepEights()
	window, err := EvsHeadWindow(fixture.head().Head)
	if err != nil || len(window) != 1 {
		t.Fatalf("window %v", err)
	}
	sealPlace := window[0].Place
	partBytes := make([][]byte, len(places))
	for i, place := range places {
		if partBytes[i], err = fixture.readRecord(fixture.check.refId, place); err != nil {
			t.Fatal(err)
		}
	}
	sealBytes, err := fixture.readRecord(fixture.check.refId, sealPlace)
	if err != nil {
		t.Fatal(err)
	}

	// the parts' minute is due and the seal's is not
	fixture.clock.Advance(24*time.Hour + 52*time.Minute)
	result := fixture.mustRun()
	if result.KeptCount != len(places) || result.DuplicateCount != 1 || result.MinuteDeletedCount != 1 || !result.HasBatches {
		t.Fatalf("the parts' run %+v", result)
	}
	firstEntries := fixture.keys("meta-1", pidxKeyPrefix)
	if len(firstEntries) != 1 {
		t.Fatalf("entries after the parts' run %v", firstEntries)
	}
	entryBytes, err := fixture.cluster.Get(fixture.ctx, firstEntries[0])
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := readAllLimited(entryBytes, EvsPidxEntryMaxByteCount)
	entryBytes.Body.Close()
	entry, err := DecodeEvsPidxEntry(stored)
	if err != nil || len(entry.GetRecords()) != len(places) {
		t.Fatalf("the parts' entry: %v", err)
	}
	for _, record := range entry.GetRecords() {
		if record.GetVersion() != 1 || record.GetType() != protocol.EvsBatchRecordType_EVS_BATCH_PART {
			t.Fatalf("a part indexed at version %d as type %d", record.GetVersion(), record.GetType())
		}
	}

	fixture.clock.Advance(time.Hour)
	result = fixture.mustRun()
	if result.KeptCount != 1 || result.HasBatches {
		t.Fatalf("the seal's run %+v", result)
	}
	if entries := fixture.keys("meta-1", pidxKeyPrefix); len(entries) != 2 {
		t.Fatalf("entries after the seal's run %v", entries)
	}
	fixture.requireRecord(sealPlace, sealBytes)
	for i, place := range places {
		fixture.requireRecord(place, partBytes[i])
	}
	if _, err := fixture.readRecord(fixture.check.refId, extra); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("the part's second copy still reads: %v", err)
	}
}

// A batch of a format this evacuator does not know stays, alarmed, with every batch of its minute; so does one whose
// bytes fail their trailer. Other minutes are evacuated.
func TestEvacuationLeavesABatchItCannotRead(t *testing.T) {
	for _, damage := range []string{"format", "trailer"} {
		fixture := newEvacuateFixture(t, nil)
		place, recordBytes := fixture.commit("a")
		fixture.clock.Advance(2 * time.Minute)
		plan := fixture.plan()
		fixture.create(plan, "b")
		now := fixture.clock.Now()
		writer := sidecar.NewEvsBatchWriter(0x7e57, BatchMinute(now), 9, now.UnixMilli())
		if _, err := writer.Add(fixture.unposted(plan)); err != nil {
			t.Fatal(err)
		}
		batchBytes, err := writer.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if damage == "format" {
			batchBytes[4] = 2
		} else {
			batchBytes[len(batchBytes)-1] ^= 1
		}
		key := BatchKey(BatchMinute(now), 0x7e57, 9)
		if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, key, batchBytes, nil); err != nil {
			t.Fatal(err)
		}
		fixture.age()
		result := fixture.mustRun()
		if result.MinuteWaitingCount != 1 || result.MinuteDeletedCount != 1 || result.KeptCount != 1 {
			t.Fatalf("%s: %+v", damage, result)
		}
		if keys := fixture.keys("meta-1", batchKeyPrefix); !slices.Equal(keys, []string{key}) {
			t.Fatalf("%s: batches %v", damage, keys)
		}
		fixture.requireRecord(place, recordBytes)
	}
}

// A store that does not answer a batch's DELETE leaves the batch for the next run, which finds its record held and
// deletes it: nothing is moved twice.
func TestEvacuationRetriesABatchDeleteThatFailed(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	place, recordBytes := fixture.commit("a")
	fixture.age()
	fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpDelete, KeyPrefix: batchKeyPrefix, Result: sidecartest.FailBeforeApply})
	result, err := fixture.run()
	if err == nil || result.BatchDeletedCount != 0 || result.MinuteWaitingCount != 1 {
		t.Fatalf("the failed delete: %v %+v", err, result)
	}
	fixture.requireRecord(place, recordBytes)
	result = fixture.mustRun()
	if result.BatchDeletedCount != 1 || result.ParcelCount != 0 || result.HasBatches {
		t.Fatalf("the rerun %+v", result)
	}
	if parcels := fixture.keys("meta-1", parcelKeyPrefix); len(parcels) != 1 {
		t.Fatalf("parcels %v", parcels)
	}
	fixture.requireRecord(place, recordBytes)
}

// A run past its minute bound settles the oldest minutes and says more wait, and the job queues its next run at
// once; the hourly start queues itself an interval on and each metadata cluster's run.
func TestEvacuationJobChainsHourlyAndAtOnceWhileMinutesWait(t *testing.T) {
	fixture := newEvacuateFixture(t, func(settings *EvacuatorSettings) { settings.RunMinuteCount = 1 })
	first, firstBytes := fixture.commit("a")
	fixture.clock.Advance(2 * time.Minute)
	second, secondBytes := fixture.commit("b")
	fixture.age()
	host := fixture.host.ServiceHost()
	deps := &EvacuatorDeps{Settings: fixture.settings, EvsSettings: fixture.settings2()}

	if result, err := RunEvacuation(fixture.ctx, host, deps, nil); err != nil || result != nil {
		t.Fatalf("the start: %+v %v", result, err)
	}
	pending := fixture.host.Tasks.Pending()
	if len(pending) != 2 {
		t.Fatalf("%d requests after the start", len(pending))
	}
	var start, cluster *sidecar.TaskRequest
	for _, request := range pending {
		if len(request.Args) == 0 {
			start = request
		} else {
			cluster = request
		}
	}
	if start == nil || cluster == nil || start.Name != EvsEvacuateTaskName || cluster.Name != EvsEvacuateTaskName {
		t.Fatalf("requests %+v %+v", start, cluster)
	}
	if !start.RunAt.Equal(fixture.clock.Now().Add(time.Hour)) || start.OnceKey == cluster.OnceKey || string(cluster.Args) != "meta-1" || cluster.RunAt.After(fixture.clock.Now()) {
		t.Fatalf("start at %s key %s; cluster args %s at %s key %s", start.RunAt, start.OnceKey, cluster.Args, cluster.RunAt, cluster.OnceKey)
	}

	result, err := RunEvacuation(fixture.ctx, host, deps, cluster.Args)
	if err != nil || !result.More || result.MinuteDeletedCount != 1 || !result.HasBatches {
		t.Fatalf("the bounded run: %v %+v", err, result)
	}
	fixture.requireRecord(first, firstBytes)
	result, err = RunEvacuation(fixture.ctx, host, deps, cluster.Args)
	if err != nil || result.More || result.MinuteDeletedCount != 1 || result.HasBatches {
		t.Fatalf("the next run: %v %+v", err, result)
	}
	fixture.requireRecord(second, secondBytes)

	if _, err := RunEvacuation(fixture.ctx, host, deps, []byte("meta-9")); !errors.Is(err, sidecar.ErrBlobClusterUnknown) {
		t.Fatalf("a cluster this process does not hold: %v", err)
	}
}

// §11.13's floors: a minute under 25 h, a log page under 24 h and a pack age past 7 d are refused.
func TestEvacuatorSettingsHoldTheFloors(t *testing.T) {
	cases := []func(settings *EvacuatorSettings){
		func(settings *EvacuatorSettings) { settings.MinuteAge = 25*time.Hour - time.Second },
		func(settings *EvacuatorSettings) { settings.LogPageAge = 24*time.Hour - time.Second },
		func(settings *EvacuatorSettings) { settings.PackAge = 7*24*time.Hour + time.Second },
		func(settings *EvacuatorSettings) { settings.RunMinuteCount = 0 },
		func(settings *EvacuatorSettings) { settings.PackPutTimeout = 0 },
	}
	for i, change := range cases {
		settings := DefaultEvacuatorSettings()
		change(settings)
		if err := settings.Validate(); !errors.Is(err, ErrEvacuatorSettings) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if err := DefaultEvacuatorSettings().Validate(); err != nil {
		t.Fatal(err)
	}
}

// HoldCache: a repo's cover by the network its repo/ carries, read at most 5 s old; a repo/ with no network and a
// hold/ that cannot be read both cover with unknown terms.
func TestHoldCacheCoversByTheReposNetwork(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	// a reread interval past §11.13's 5 s is held to it
	cache := NewHoldCache(blobs, clock, &sidecar.HoldSetSettings{RereadInterval: time.Minute, ListPageCount: 10, CacheNetworkCount: 10})
	networkId, repoId, otherRepoId := testId("hold network"), testId("hold repo"), testId("hold other repo")
	object := &protocol.EvsRepoObject{RepoId: repoId.Bytes(), NetworkId: networkId.Bytes()}

	cover, err := cache.CoveringRepo(ctx, repoId, object)
	if err != nil || cover.Covered() {
		t.Fatalf("no hold: %+v %v", cover, err)
	}
	if err := sidecartest.PlaceHold(ctx, blobs, &sidecar.HoldRecord{
		NetworkId: networkId, CaseId: testId("hold case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeRepos(repoId), PlaceTime: clock.Now(), ExpireTime: clock.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// within 5 s the cached read still answers
	clock.Advance(4 * time.Second)
	if cover, _ := cache.CoveringRepo(ctx, repoId, object); cover.Covered() {
		t.Fatal("a hold seen before the cached read aged")
	}
	clock.Advance(2 * time.Second)
	cover, err = cache.CoveringRepo(ctx, repoId, object)
	if err != nil || !cover.Covered() || cover.Unknown || len(cover.Holds) != 1 {
		t.Fatalf("5 s on: %+v %v", cover, err)
	}
	if other, _ := cache.Covering(ctx, networkId, otherRepoId); other.Covered() {
		t.Fatal("a repo outside the hold's scope is covered")
	}
	// a repo/ with no network keeps everything
	if cover, _ := cache.CoveringRepo(ctx, repoId, &protocol.EvsRepoObject{RepoId: repoId.Bytes()}); !cover.Unknown {
		t.Fatal("a repo with no network is not covered")
	}
	// a hold/ that cannot be listed covers, with the error
	clock.Advance(6 * time.Second)
	blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpList, KeyPrefix: "hold/", Result: sidecartest.FailBeforeApply})
	cover, err = cache.CoveringRepo(ctx, repoId, object)
	if err == nil || !cover.Unknown {
		t.Fatalf("an unread hold/: %+v %v", cover, err)
	}
}
