package evsservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The push fixture's repo on meta-1 and seg-1, with a nightly pass over it.
type nightlyFixture struct {
	*evacuateFixture
	passSettings *NightlyPassSettings
	gcSettings   *OrphanGcSettings
	// barriers the pass and its GC reached, in order
	gcSteps []string
	// runs at each barrier, when set
	onStep func(name string, key string)
	// the segment cluster's drives past half their measured capacity; unmeasured reads {nvb_<cluster>} instead
	busy       bool
	unmeasured bool
}

func newNightlyFixture(t *testing.T) *nightlyFixture {
	return &nightlyFixture{
		evacuateFixture: newEvacuateFixture(t, nil),
		passSettings:    DefaultNightlyPassSettings(),
		gcSettings:      DefaultOrphanGcSettings(),
	}
}

func (self *nightlyFixture) deps() *NightlyPassDeps {
	deps := &NightlyPassDeps{
		Settings:    self.passSettings,
		OrphanGc:    self.gcSettings,
		EvsSettings: self.settings2(),
		atStep: func(name string, key string) error {
			self.gcSteps = append(self.gcSteps, name)
			if self.onStep != nil {
				self.onStep(name, key)
			}
			return nil
		},
		// a pace on a fake clock passes as the clock is moved
		wait: func(wait time.Duration) { self.clock.Advance(wait) },
	}
	if !self.unmeasured {
		deps.SegmentClusterBusy = func(ctx context.Context, clusterId string) bool { return self.busy }
	}
	return deps
}

// A new pass, as a new taskworker run builds one: no cache of an earlier run.
func (self *nightlyFixture) pass() *NightlyPass {
	self.t.Helper()
	pass, err := NewNightlyPass(self.host.ServiceHost(), self.deps())
	if err != nil {
		self.t.Fatal(err)
	}
	return pass
}

// One run of meta-1's one shard, which must end clean.
func (self *nightlyFixture) runPass() *NightlyResult {
	self.t.Helper()
	result, err := self.pass().Run(self.ctx, "meta-1", "", "")
	if err != nil {
		self.t.Fatalf("run: %v (%+v)", err, result)
	}
	return result
}

func (self *nightlyFixture) segmentCluster() sidecar.BlobCluster {
	self.t.Helper()
	cluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	return cluster
}

// Stores a segment of the repo as an upload would: its key, its id and its bytes.
func (self *nightlyFixture) putSegment(label string) (string, [32]byte, []byte) {
	self.t.Helper()
	body := []byte("segment " + label)
	segmentId := sha256.Sum256(body)
	key := SegmentKey(self.check.repoId, segmentId)
	if _, err := self.segmentCluster().PutIfNoneMatch(self.ctx, key, body, nil); err != nil {
		self.t.Fatal(err)
	}
	return key, segmentId, body
}

// Writes a pidx/ entry of a parcel whose one record introduces segmentIds: its key.
func (self *nightlyFixture) putPidx(label string, firstVersion uint64, segmentIds ...[32]byte) string {
	self.t.Helper()
	containerId := testId("container " + label)
	entry := &protocol.EvsPidxEntry{
		ContainerKind: protocol.EvsContainerKind_EVS_CONTAINER_PARCEL,
		ContainerId:   containerId.Bytes(),
		FirstVersion:  firstVersion,
		LastVersion:   firstVersion,
		Records: []*protocol.EvsPidxRecord{{
			Version: firstVersion, Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, Offset: 0, Length: 200,
			Place: &protocol.EvsPlace{Minute: 1, Instance: 2, Seq: 3, Offset: sidecar.EvsBatchHeaderByteCount, Length: 200},
		}},
	}
	for _, segmentId := range segmentIds {
		entry.SegmentIds = append(entry.SegmentIds, segmentId[:])
	}
	entryBytes, err := encodeEvsPidxEntry(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	key := PidxKey(self.check.repoId, self.check.refId, firstVersion, containerId)
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, key, entryBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	return key
}

func (self *nightlyFixture) stands(cluster sidecar.BlobCluster, key string) bool {
	self.t.Helper()
	_, err := cluster.Head(sidecartest.InspectContext(self.ctx), key)
	if err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
		self.t.Fatal(err)
	}
	return err == nil
}

// Past the horizon of everything stored so far, with no batch left: 49 h and more.
func (self *nightlyFixture) pastTheHorizon() {
	self.clock.Advance(49*time.Hour + 5*time.Minute)
}

// The horizon is evacuation's floor, 25 h before the LIST, when no batch is left.
func TestOrphanHorizonFromAnEmptyBatchPrefix(t *testing.T) {
	fixture := newNightlyFixture(t)
	horizon, err := fixture.pass().OrphanHorizon(fixture.ctx, fixture.cluster)
	if err != nil || !horizon.Equal(fixture.clock.Now().Add(-25*time.Hour)) {
		t.Fatalf("horizon %v, %v", horizon, err)
	}
}

// With a batch older than the floor still on the cluster, as when evacuation waits, the horizon is the start of the
// minute its key names: nothing whose record could be in it is past the horizon.
func TestOrphanHorizonFromItsOldestBatch(t *testing.T) {
	fixture := newNightlyFixture(t)
	opened := fixture.clock.Now()
	pending := fixture.plan()
	fixture.create(pending, "a")
	fixture.putBatch(1, fixture.unposted(pending))
	fixture.clock.Advance(30 * time.Hour)
	fixture.putBatch(2, fixture.unposted(pending))
	horizon, err := fixture.pass().OrphanHorizon(fixture.ctx, fixture.cluster)
	if err != nil || !horizon.Equal(opened.Truncate(time.Minute)) {
		t.Fatalf("horizon %v, want the minute of %v: %v", horizon, opened, err)
	}
}

// A batch younger than the floor leaves the horizon at the floor.
func TestOrphanHorizonFromABatchYoungerThanTheFloor(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.clock.Advance(30 * time.Hour)
	pending := fixture.plan()
	fixture.create(pending, "a")
	fixture.putBatch(1, fixture.unposted(pending))
	fixture.clock.Advance(30 * time.Second)
	horizon, err := fixture.pass().OrphanHorizon(fixture.ctx, fixture.cluster)
	if err != nil || !horizon.Equal(fixture.clock.Now().Add(-25*time.Hour)) {
		t.Fatalf("horizon %v, %v", horizon, err)
	}
}

// An unsure clock gives no horizon, and a key under pb/ that is no batch's gives none either.
func TestOrphanHorizonFailsClosed(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.host.ClockCheck.SetUnknown()
	if _, err := fixture.pass().OrphanHorizon(fixture.ctx, fixture.cluster); !errors.Is(err, ErrNightlyClockUnsure) {
		t.Fatalf("an unsure clock: %v", err)
	}
	fixture.host.ClockCheck.SetOffset(0)
	if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, batchKeyPrefix+"0000/not-a-batch", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pass().OrphanHorizon(fixture.ctx, fixture.cluster); !errors.Is(err, ErrNightlyBatchKey) {
		t.Fatalf("a key that is no batch's: %v", err)
	}
}

// §11.13's orphans row by the horizon: an unadopted segment stays at 25 h and at 49 h, and goes once the horizon
// has passed its LastModified + 24 h + 2 min, by a DELETE naming its LastModified.
func TestOrphanGcDeletesAnUnadoptedSegmentOnlyPastTheHorizon(t *testing.T) {
	fixture := newNightlyFixture(t)
	key, _, _ := fixture.putSegment("orphan")
	seg := fixture.segmentCluster()

	fixture.clock.Advance(25*time.Hour + time.Minute)
	result := fixture.runPass()
	if result.Orphans.CandidateCount != 0 || result.Orphans.DeletedCount != 0 || !fixture.stands(seg, key) {
		t.Fatalf("at 25 h: %+v", result.Orphans)
	}
	// 49 h 1 min after the upload: the horizon is a minute short of the segment's bound
	fixture.clock.Advance(24 * time.Hour)
	result = fixture.runPass()
	if result.Orphans.DeletedCount != 0 || !fixture.stands(seg, key) {
		t.Fatalf("a minute before its bound: %+v", result.Orphans)
	}
	fixture.clock.Advance(2 * time.Minute)
	result = fixture.runPass()
	if !result.HasHorizon || result.Orphans.CandidateCount != 1 || result.Orphans.DeletedCount != 1 || fixture.stands(seg, key) {
		t.Fatalf("past its bound: %+v", result)
	}
	if !slices.Contains(fixture.gcSteps, BarrierGcDeleteBefore) || !slices.Contains(fixture.gcSteps, BarrierGcDeleteAfter) {
		t.Fatalf("steps %v", fixture.gcSteps)
	}
}

// While a batch that could adopt the segment is still on the cluster, as when evacuation waits behind a record it
// cannot settle, the horizon stays behind the segment's bound and nothing is deleted, however old the segment.
func TestOrphanGcDeletesNothingWhileAnOlderBatchStands(t *testing.T) {
	fixture := newNightlyFixture(t)
	key, _, _ := fixture.putSegment("orphan")
	fixture.clock.Advance(23 * time.Hour)
	pending := fixture.plan()
	fixture.create(pending, "a")
	batchKey, _ := fixture.putBatch(1, fixture.unposted(pending))
	fixture.clock.Advance(3 * 24 * time.Hour)
	result := fixture.runPass()
	if result.Orphans.CandidateCount != 0 || result.Orphans.DeletedCount != 0 || !fixture.stands(fixture.segmentCluster(), key) {
		t.Fatalf("with a batch standing: %+v", result.Orphans)
	}

	// evacuation settles the batch, and the next pass deletes
	if err := fixture.cluster.Delete(fixture.ctx, batchKey); err != nil {
		t.Fatal(err)
	}
	result = fixture.runPass()
	if result.Orphans.DeletedCount != 1 || fixture.stands(fixture.segmentCluster(), key) {
		t.Fatalf("once the batch is gone: %+v", result.Orphans)
	}
}

// A segment a pidx/ entry lists as introduced was adopted by a committed push: it is kept, and the one beside it
// that no entry lists goes.
func TestOrphanGcKeepsASegmentAPidxEntryIntroduces(t *testing.T) {
	fixture := newNightlyFixture(t)
	adopted, adoptedId, _ := fixture.putSegment("adopted")
	orphan, _, _ := fixture.putSegment("orphan")
	fixture.clock.Advance(26 * time.Hour)
	fixture.putPidx("a", 1, adoptedId)
	fixture.pastTheHorizon()
	result := fixture.runPass()
	seg := fixture.segmentCluster()
	if result.Orphans.CandidateCount != 2 || result.Orphans.PidxReadCount != 1 || result.Orphans.DeletedCount != 1 {
		t.Fatalf("result %+v", result.Orphans)
	}
	if !fixture.stands(seg, adopted) || fixture.stands(seg, orphan) {
		t.Fatal("the adopted segment went, or the orphan stayed")
	}
}

// The one order orphan GC rests on (twin GcReadsIndexFirst): the horizon is read before pidx/ is listed.
func TestOrphanGcReadsTheHorizonBeforeTheIndex(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.putSegment("orphan")
	fixture.pastTheHorizon()
	// LISTs counted at each barrier: the engine's own loops may LIST the cluster beside the run, so only the
	// counts' order is held, never their exact values
	listsAt := map[string]int{}
	fixture.onStep = func(name string, key string) {
		if _, seen := listsAt[name]; !seen {
			listsAt[name] = fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpList)
		}
	}
	fixture.runPass()
	want := []string{BarrierGcHorizonBefore, BarrierGcHorizonAfter, BarrierGcIndexBefore, BarrierGcIndexAfter, BarrierGcDeleteBefore, BarrierGcDeleteAfter}
	if !slices.Equal(fixture.gcSteps, want) {
		t.Fatalf("steps %v, want %v", fixture.gcSteps, want)
	}
	// the horizon's LIST of pb/ issues between its barriers, and the pidx/ LIST only after evs.gc.index.before
	if listsAt[BarrierGcHorizonAfter] < listsAt[BarrierGcHorizonBefore]+1 || listsAt[BarrierGcIndexBefore] < listsAt[BarrierGcHorizonAfter] ||
		listsAt[BarrierGcIndexAfter] < listsAt[BarrierGcIndexBefore]+1 {
		t.Fatalf("LISTs at each barrier %v", listsAt)
	}
}

// Finding D: the segment is deleted by another run and its bytes are uploaded again between this run's LIST and
// its DELETE. The DELETE names the object it listed, answers 412, and the new object stays.
func TestOrphanGcLeavesASegmentUploadedAgainSinceItsList(t *testing.T) {
	fixture := newNightlyFixture(t)
	key, segmentId, body := fixture.putSegment("orphan")
	seg := fixture.segmentCluster()
	fixture.pastTheHorizon()
	fixture.onStep = func(name string, stepKey string) {
		if name != BarrierGcDeleteBefore || stepKey != barrierSegmentKey(fixture.check.repoId, segmentId[:]) {
			return
		}
		if err := seg.Delete(fixture.ctx, key); err != nil {
			t.Error(err)
		}
		fixture.clock.Advance(2 * time.Second)
		if _, err := seg.PutIfNoneMatch(fixture.ctx, key, body, nil); err != nil {
			t.Error(err)
		}
	}
	result := fixture.runPass()
	if result.Orphans.ReplacedCount != 1 || result.Orphans.DeletedCount != 0 || !fixture.stands(seg, key) {
		t.Fatalf("result %+v", result.Orphans)
	}
	// the new object is judged on a later night, by its own LastModified
	fixture.onStep = nil
	result = fixture.runPass()
	if result.Orphans.CandidateCount != 0 || !fixture.stands(seg, key) {
		t.Fatalf("the night after: %+v", result.Orphans)
	}
}

// A held key and an unknown outcome leave the segment for a later night, and are never counted as deleted.
func TestOrphanGcLeavesAHeldKeyAndAnUnknownOutcome(t *testing.T) {
	for _, faultResult := range []sidecartest.FaultResult{sidecartest.Held, sidecartest.FailBeforeApply} {
		fixture := newNightlyFixture(t)
		key, _, _ := fixture.putSegment("orphan")
		fixture.pastTheHorizon()
		if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpDelete, KeyPrefix: segmentKeyPrefix, Result: faultResult}); err != nil {
			t.Fatal(err)
		}
		result := fixture.runPass()
		if result.Orphans.DeletedCount != 0 || result.Orphans.HeldCount+result.Orphans.FailedCount != 1 || !fixture.stands(fixture.segmentCluster(), key) {
			t.Fatalf("%v: %+v", faultResult, result.Orphans)
		}
		result = fixture.runPass()
		if result.Orphans.DeletedCount != 1 {
			t.Fatalf("the night after %v: %+v", faultResult, result.Orphans)
		}
	}
}

// A hold covering the repo, a repo that is neither active nor deleted, a build that has not passed the settle
// cases and an unsure clock each stop the repo's GC: nothing is deleted.
func TestOrphanGcGatesDeleteNothing(t *testing.T) {
	gates := map[string]func(fixture *nightlyFixture){
		"a hold": func(fixture *nightlyFixture) {
			err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
				NetworkId: fixture.check.networkId, CaseId: testId("hold case"), Kind: sidecar.HoldKindPreserve2703f,
				Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(90 * 24 * time.Hour),
			})
			if err != nil {
				fixture.t.Fatal(err)
			}
		},
		"a shredding repo": func(fixture *nightlyFixture) {
			fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_SHREDDING)
		},
		"the segment cluster's settle gate": func(fixture *nightlyFixture) {
			fixture.host.Blobs.SetSettlePassed(fixture.segmentCluster().ClusterId(), false)
		},
		"the metadata cluster's settle gate": func(fixture *nightlyFixture) {
			fixture.host.Blobs.SetSettlePassed("meta-1", false)
		},
		"an unsure clock": func(fixture *nightlyFixture) {
			fixture.host.ClockCheck.SetUnknown()
		},
	}
	for name, close := range gates {
		fixture := newNightlyFixture(t)
		key, _, _ := fixture.putSegment("orphan")
		fixture.pastTheHorizon()
		close(fixture)
		result := fixture.runPass()
		if result.Orphans.DeletedCount != 0 || result.OrphanSkippedRepoCount != 1 || !fixture.stands(fixture.segmentCluster(), key) {
			t.Fatalf("%s: %+v", name, result)
		}
		if deletes := fixture.host.Blobs.RequestCount(fixture.segmentCluster().ClusterId(), sidecartest.FaultOpDelete); deletes != 0 {
			t.Fatalf("%s: %d DELETEs issued", name, deletes)
		}
	}
}

// A hold placed while GC runs stops the repo at its next DELETE: step 5 reads hold/ again before each.
func TestOrphanGcStopsAtAHoldPlacedWhileItRuns(t *testing.T) {
	fixture := newNightlyFixture(t)
	first, firstId, _ := fixture.putSegment("first")
	fixture.clock.Advance(time.Minute)
	second, _, _ := fixture.putSegment("second")
	fixture.pastTheHorizon()
	fixture.onStep = func(name string, key string) {
		if name != BarrierGcDeleteAfter || key != barrierSegmentKey(fixture.check.repoId, firstId[:]) {
			return
		}
		err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
			NetworkId: fixture.check.networkId, CaseId: testId("hold case"), Kind: sidecar.HoldKindPreserve2703f,
			Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(90 * 24 * time.Hour),
		})
		if err != nil {
			t.Error(err)
		}
		// past the 5 s a hold/ read is cached
		fixture.clock.Advance(6 * time.Second)
	}
	result := fixture.runPass()
	seg := fixture.segmentCluster()
	if result.Orphans.DeletedCount != 1 || fixture.stands(seg, first) || !fixture.stands(seg, second) {
		t.Fatalf("result %+v", result.Orphans)
	}
}

// Over PidxReadCount entries to read: nothing of the repo is deleted in that run.
func TestOrphanGcDeletesNothingPastItsIndexBound(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.gcSettings.PidxReadCount = 2
	key, _, _ := fixture.putSegment("orphan")
	fixture.clock.Advance(26 * time.Hour)
	for version := uint64(1); version <= 3; version += 1 {
		fixture.putPidx("entry", version)
	}
	fixture.pastTheHorizon()
	result := fixture.runPass()
	if result.Orphans.DeletedCount != 0 || result.OrphanSkippedRepoCount != 1 || !fixture.stands(fixture.segmentCluster(), key) {
		t.Fatalf("result %+v", result)
	}
}

// An entry older than the oldest candidate less an hour cannot introduce it, and is not read.
func TestOrphanGcReadsOnlyEntriesWrittenSinceItsOldestCandidate(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.putPidx("old", 1)
	fixture.clock.Advance(2 * time.Hour)
	key, _, _ := fixture.putSegment("orphan")
	fixture.clock.Advance(26 * time.Hour)
	fixture.putPidx("new", 2)
	fixture.pastTheHorizon()
	result := fixture.runPass()
	if result.Orphans.PidxReadCount != 1 || result.Orphans.DeletedCount != 1 || fixture.stands(fixture.segmentCluster(), key) {
		t.Fatalf("result %+v", result.Orphans)
	}
}

// A pidx/ entry the pass listed is gone when GC reads it, a pack having replaced its parcel: GC lists that ref's
// entries again, once, reads the pack's, and keeps the segment it introduces. With nothing in the gone entry's
// place, nothing of the repo is deleted.
func TestOrphanGcListsAReplacedEntrysRefAgain(t *testing.T) {
	fixture := newNightlyFixture(t)
	adopted, adoptedId, _ := fixture.putSegment("adopted")
	fixture.clock.Advance(26 * time.Hour)
	parcelEntry := fixture.putPidx("parcel", 1, adoptedId)
	fixture.pastTheHorizon()
	horizon := fixture.clock.Now().Add(-25 * time.Hour)
	seg := fixture.segmentCluster()
	listed := func(cluster sidecar.BlobCluster, prefix string) []*sidecar.BlobInfo {
		objects, _, err := cluster.List(fixture.ctx, prefix, "", 1000)
		if err != nil {
			t.Fatal(err)
		}
		return objects
	}
	repo := &OrphanGcRepo{
		RepoId: fixture.check.repoId, MetadataCluster: fixture.cluster, Horizon: horizon,
		Segments:    listed(seg, segmentKeyPrefix),
		PidxEntries: listed(fixture.cluster, pidxKeyPrefix),
	}
	// after the LIST: the pack's entry is written, then the parcel's is deleted
	fixture.putPidx("pack", 1, adoptedId)
	if err := fixture.cluster.Delete(fixture.ctx, parcelEntry); err != nil {
		t.Fatal(err)
	}
	gc, err := NewOrphanGc(fixture.host.ServiceHost(), &OrphanGcDeps{EvsSettings: fixture.settings2()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := gc.RunRepo(fixture.ctx, repo)
	if err != nil || result.Skipped != "" || result.DeletedCount != 0 || result.PidxReadCount != 2 || !fixture.stands(seg, adopted) {
		t.Fatalf("result %+v, %v", result, err)
	}

	// the entry gone with nothing in its place: no deletion on a doubt
	missing := &OrphanGcRepo{
		RepoId: fixture.check.repoId, MetadataCluster: fixture.cluster, Horizon: horizon,
		Segments:    repo.Segments,
		PidxEntries: []*sidecar.BlobInfo{{Key: PidxKey(fixture.check.repoId, testId("another ref"), 1, testId("gone")), LastModified: fixture.clock.Now()}},
	}
	result, err = gc.RunRepo(fixture.ctx, missing)
	if err != nil || result.Skipped == "" || result.DeletedCount != 0 || !fixture.stands(seg, adopted) {
		t.Fatalf("a listed entry gone with nothing in its place: %+v, %v", result, err)
	}
}

// DESIGN-DETAILS 2.2.5: an uncommitted path map above its ref's current epoch goes once the horizon has passed its
// oldest part's bound, each part by a DELETE naming its LastModified; a map at or below the head's epoch is left.
func TestOrphanGcDeletesAnUncommittedPathMapAboveTheHeadsEpoch(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.commit("a")
	current := fixture.head().Head.GetPathEpoch().GetCurrent()
	above, below := sha256.Sum256([]byte("map above")), sha256.Sum256([]byte("map at the head's epoch"))
	aboveKeys := []string{}
	for part := uint32(0); part < 2; part += 1 {
		key := PathMapKey(fixture.check.repoId, fixture.check.refId, current+1, above[:], part)
		if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, key, []byte("part"), nil); err != nil {
			t.Fatal(err)
		}
		aboveKeys = append(aboveKeys, key)
	}
	belowKey := PathMapKey(fixture.check.repoId, fixture.check.refId, current, below[:], 0)
	if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, belowKey, []byte("part"), nil); err != nil {
		t.Fatal(err)
	}

	fixture.age()
	if result := fixture.runPass(); result.Orphans.MapPartDeletedCount != 0 {
		t.Fatalf("before the maps' bound: %+v", result.Orphans)
	}
	// the committed push's batch is evacuated, and the horizon passes the maps' bound
	fixture.mustRun()
	fixture.clock.Advance(25 * time.Hour)
	result := fixture.runPass()
	if result.Orphans.MapPartDeletedCount != 2 {
		t.Fatalf("past the maps' bound: %+v", result.Orphans)
	}
	for _, key := range aboveKeys {
		if fixture.stands(fixture.cluster, key) {
			t.Fatalf("a part of the uncommitted map stands: %s", key)
		}
	}
	if !fixture.stands(fixture.cluster, belowKey) {
		t.Fatal("a map at the head's epoch was deleted")
	}
}

func TestOrphanGcSettingsHoldTheAdoptionBound(t *testing.T) {
	settings := DefaultOrphanGcSettings()
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	if settings.AdoptionBound != 24*time.Hour+2*time.Minute || settings.Window != 7*24*time.Hour || settings.DeleteCount != 1024 || settings.DeleteRate != 10 || settings.PidxReadCount != 4096 {
		t.Fatalf("defaults %+v", settings)
	}
	settings.AdoptionBound -= time.Second
	if err := settings.Validate(); !errors.Is(err, ErrOrphanGcSettings) {
		t.Fatalf("an adoption bound under its floor: %v", err)
	}
}

// The pass keeps no cursor: each night judges what the horizon passed within Window, and DeleteCount bounds a run.
func TestOrphanGcBoundsARunAndItsWindow(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.gcSettings.DeleteCount = 2
	keys := []string{}
	for _, label := range []string{"a", "b", "c"} {
		key, _, _ := fixture.putSegment(label)
		keys = append(keys, key)
		fixture.clock.Advance(time.Minute)
	}
	fixture.pastTheHorizon()
	result := fixture.runPass()
	seg := fixture.segmentCluster()
	if result.Orphans.DeletedCount != 2 || !result.Orphans.More || fixture.stands(seg, keys[0]) || fixture.stands(seg, keys[1]) || !fixture.stands(seg, keys[2]) {
		t.Fatalf("a bounded run, oldest first: %+v", result.Orphans)
	}
	// past the window the last one is no longer judged, until a run's window is widened to the gap
	fixture.clock.Advance(8 * 24 * time.Hour)
	if result = fixture.runPass(); result.Orphans.CandidateCount != 0 {
		t.Fatalf("past the window: %+v", result.Orphans)
	}
	fixture.gcSettings.Window = 10 * 24 * time.Hour
	if result = fixture.runPass(); result.Orphans.DeletedCount != 1 || fixture.stands(seg, keys[2]) {
		t.Fatalf("with the window widened: %+v", result.Orphans)
	}
}

// A segment cluster past half its measured capacity, or with none measured, takes no orphan DELETE that night, as a
// drop job stays paused (plan-EVSB-settle-gate): the orphan stays, and goes on a night the cluster is quiet.
func TestOrphanGcDeletesNothingOnABusyOrUnmeasuredSegmentCluster(t *testing.T) {
	fixture := newNightlyFixture(t)
	key, _, _ := fixture.putSegment("busy")
	fixture.pastTheHorizon()

	fixture.busy = true
	if result := fixture.runPass(); result.Orphans.DeletedCount != 0 || !fixture.stands(fixture.segmentCluster(), key) {
		t.Fatalf("a busy cluster: %+v", result.Orphans)
	}
	fixture.busy = false
	fixture.unmeasured = true
	if result := fixture.runPass(); result.Orphans.DeletedCount != 0 || !fixture.stands(fixture.segmentCluster(), key) {
		t.Fatalf("an unmeasured cluster: %+v", result.Orphans)
	}
	fixture.unmeasured = false
	if result := fixture.runPass(); result.Orphans.DeletedCount != 1 || fixture.stands(fixture.segmentCluster(), key) {
		t.Fatalf("a quiet cluster: %+v", result.Orphans)
	}
}
