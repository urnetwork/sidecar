package evsservice

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// §11.13's bytes row: a repo's stored bytes are its seg/, pack/ and hp/ objects' sizes as LIST gives them, plus the
// record lengths its head windows give for versions still in batches, by the network its repo/ names. Once the
// batch is evacuated the record counts from its parcel and no longer from the window.
func TestNightlyPassCountsStoredBytesByNetwork(t *testing.T) {
	fixture := newNightlyFixture(t)
	place, _ := fixture.commit("a")
	_, _, first := fixture.putSegment("first")
	_, _, second := fixture.putSegment("second")

	result := fixture.runPass()
	if !result.Complete || result.More || result.RepoCount != 1 || result.UnknownNetworkRepoCount != 0 || len(result.NetworkBytes) != 1 {
		t.Fatalf("result %+v", result)
	}
	stored := result.NetworkBytes[fixture.check.networkId]
	if stored == nil || stored.RepoCount != 1 || stored.SegmentByteCount != int64(len(first)+len(second)) || stored.PackByteCount != 0 || stored.ParcelByteCount != 0 {
		t.Fatalf("stored %+v", stored)
	}
	if stored.BatchRecordByteCount != int64(place.GetLength()) {
		t.Fatalf("%d bytes of batch records, want the committed record's %d", stored.BatchRecordByteCount, place.GetLength())
	}
	if stored.StoredByteCount() != stored.SegmentByteCount+stored.BatchRecordByteCount {
		t.Fatalf("stored count %d", stored.StoredByteCount())
	}

	// evacuated: the record counts from its parcel
	fixture.age()
	fixture.mustRun()
	parcels := fixture.keys("meta-1", parcelKeyPrefix)
	if len(parcels) != 1 {
		t.Fatalf("parcels %v", parcels)
	}
	parcel, err := fixture.cluster.Head(fixture.ctx, parcels[0])
	if err != nil {
		t.Fatal(err)
	}
	stored = fixture.runPass().NetworkBytes[fixture.check.networkId]
	if stored == nil || stored.ParcelByteCount != parcel.ByteCount || stored.BatchRecordByteCount != 0 || stored.SegmentByteCount != int64(len(first)+len(second)) {
		t.Fatalf("stored after evacuation %+v", stored)
	}
}

// The count is read whatever stops deletion: on an unsure clock, and on a build that has not passed the settle
// cases, the pass still counts and deletes nothing.
func TestNightlyPassCountsWhileItMayNotDelete(t *testing.T) {
	fixture := newNightlyFixture(t)
	key, _, body := fixture.putSegment("orphan")
	fixture.pastTheHorizon()
	fixture.host.ClockCheck.SetUnknown()
	result := fixture.runPass()
	if result.HasHorizon || !result.Complete || result.Orphans.DeletedCount != 0 || !fixture.stands(fixture.segmentCluster(), key) {
		t.Fatalf("result %+v", result)
	}
	if stored := result.NetworkBytes[fixture.check.networkId]; stored == nil || stored.SegmentByteCount != int64(len(body)) {
		t.Fatalf("stored %+v", stored)
	}
}

// A run that reaches its bound stops, gives the key it reached and is not complete; the job queues itself there.
func TestNightlyPassStopsAtItsBoundAndIsNotComplete(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.commit("a")
	whole := fixture.runPass()
	if !whole.Complete || whole.More || whole.NextStartAfter != "" {
		t.Fatalf("a whole run: %+v", whole)
	}
	// from the repo's own key on, nothing is left, and a resumed run never stands for the shard
	resumed, err := fixture.pass().Run(fixture.ctx, "meta-1", "", RepoKey(fixture.check.repoId))
	if err != nil || resumed.RepoCount != 0 || resumed.Complete {
		t.Fatalf("a resumed run: %+v, %v", resumed, err)
	}
	if _, err := fixture.pass().Run(fixture.ctx, "meta-1", "zz", ""); !errors.Is(err, ErrNightlyPassSettings) {
		t.Fatalf("a shard the settings do not make: %v", err)
	}
	if _, err := fixture.pass().Run(fixture.ctx, "meta-9", "", ""); !errors.Is(err, sidecar.ErrBlobClusterUnknown) {
		t.Fatalf("a cluster the host does not hold: %v", err)
	}
}

// Shards are the hex prefixes of a repo's id, and a shard's run lists only its own repos.
func TestNightlyPassShardsByRepoIdPrefix(t *testing.T) {
	settings := DefaultNightlyPassSettings()
	if shards := settings.Shards(); !slices.Equal(shards, []string{""}) {
		t.Fatalf("one job a cluster: %v", shards)
	}
	settings.ShardHexDigitCount = 1
	if shards := settings.Shards(); len(shards) != 16 || shards[0] != "0" || shards[15] != "f" {
		t.Fatalf("16 shards: %v", shards)
	}
	settings.ShardHexDigitCount = 2
	if shards := settings.Shards(); len(shards) != 256 || shards[0] != "00" || shards[255] != "ff" || !slices.IsSorted(shards) {
		t.Fatalf("256 shards: %d", len(shards))
	}
	settings.ShardHexDigitCount = 3
	if err := settings.Validate(); !errors.Is(err, ErrNightlyPassSettings) {
		t.Fatalf("three shard digits: %v", err)
	}

	fixture := newNightlyFixture(t)
	fixture.passSettings.ShardHexDigitCount = 1
	fixture.commit("a")
	own := sidecar.EvsKeyId(fixture.check.repoId)[:1]
	repoCount := 0
	for _, shard := range fixture.passSettings.Shards() {
		result, err := fixture.pass().Run(fixture.ctx, "meta-1", shard, "")
		if err != nil {
			t.Fatal(err)
		}
		if (result.RepoCount == 1) != (shard == own) {
			t.Fatalf("shard %q listed %d repos, the repo's is %q", shard, result.RepoCount, own)
		}
		repoCount += result.RepoCount
	}
	if repoCount != 1 {
		t.Fatalf("%d repos over the shards", repoCount)
	}
}

func TestEvsNightlyArgsRoundTrip(t *testing.T) {
	args := EvsNightlyArgs("meta-1", "a7", "repo/a7ff")
	clusterId, shard, startAfter, ok := ParseEvsNightlyArgs(args)
	if !ok || clusterId != "meta-1" || shard != "a7" || startAfter != "repo/a7ff" {
		t.Fatalf("%q %q %q %t", clusterId, shard, startAfter, ok)
	}
	if _, _, _, ok := ParseEvsNightlyArgs(nil); ok {
		t.Fatal("the start's empty args read as a shard's")
	}
	if _, _, _, ok := ParseEvsNightlyArgs([]byte("meta-1")); ok {
		t.Fatal("args of another shape read as a shard's")
	}
	request := EvsNightlyTaskRequest("meta-1", "a7", "", time.Unix(1700000000, 0), nil)
	other := EvsNightlyTaskRequest("meta-1", "a8", "", time.Unix(1700000000, 0), nil)
	if request.Name != EvsNightlyTaskName || request.OnceKey == other.OnceKey || request.OnceKey == EvsNightlyStartTaskRequest(time.Unix(1700000000, 0)).OnceKey {
		t.Fatalf("once keys %q %q", request.OnceKey, other.OnceKey)
	}
}

// Stores a container no entry names, as a run killed between its container and its entries leaves one: its key.
func (self *nightlyFixture) putUnnamed(label string, pack bool) (sidecar.BlobCluster, string) {
	self.t.Helper()
	containerId := testId("unnamed " + label)
	cluster, key := self.cluster, ParcelKey(self.check.repoId, containerId)
	if pack {
		cluster, key = self.segmentCluster(), PackKey(self.check.repoId, containerId)
	}
	if _, err := cluster.PutIfNoneMatch(self.ctx, key, []byte("container "+label), nil); err != nil {
		self.t.Fatal(err)
	}
	return cluster, key
}

// §11.13's resume row: a parcel no pidx/ entry names goes once it is 25 h old, by a DELETE naming its LastModified,
// and not before; a named one stays.
func TestNightlyPassDeletesAContainerNoEntryNamesAfter25Hours(t *testing.T) {
	fixture := newNightlyFixture(t)
	parcelCluster, parcel := fixture.putUnnamed("parcel", false)
	named := fixture.putPidx("named", 1)
	namedId := testId("container named")
	if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, ParcelKey(fixture.check.repoId, namedId), []byte("named parcel"), nil); err != nil {
		t.Fatal(err)
	}

	fixture.clock.Advance(24 * time.Hour)
	if result := fixture.runPass(); result.UnnamedDeletedCount != 0 || !fixture.stands(parcelCluster, parcel) {
		t.Fatalf("under 25 h: %+v", result)
	}
	fixture.clock.Advance(1*time.Hour + time.Minute)
	result := fixture.runPass()
	if result.UnnamedDeletedCount != 1 || fixture.stands(parcelCluster, parcel) {
		t.Fatalf("past 25 h: %+v", result)
	}
	if !fixture.stands(fixture.cluster, named) || !fixture.stands(fixture.cluster, ParcelKey(fixture.check.repoId, namedId)) {
		t.Fatal("a named parcel or its entry went")
	}
}

// An unnamed container stays while a batch from before its minutes stands: an evacuation that resumes such a
// minute may build the same bytes again and reuse it, so it goes only once the horizon has passed every minute it
// could hold records of.
func TestNightlyPassKeepsAnUnnamedContainerTheHorizonHasNotPassed(t *testing.T) {
	fixture := newNightlyFixture(t)
	batch, _ := fixture.putBatch(1, fixture.unposted(fixture.plan()))
	fixture.clock.Advance(25*time.Hour + time.Minute)
	parcelCluster, parcel := fixture.putUnnamed("parcel", false)
	fixture.clock.Advance(25*time.Hour + time.Minute)
	if result := fixture.runPass(); result.UnnamedDeletedCount != 0 || !fixture.stands(parcelCluster, parcel) {
		t.Fatalf("behind an older batch: %+v", result)
	}
	if err := fixture.cluster.Delete(fixture.ctx, batch); err != nil {
		t.Fatal(err)
	}
	if result := fixture.runPass(); result.UnnamedDeletedCount != 1 || fixture.stands(parcelCluster, parcel) {
		t.Fatalf("once the batch is gone: %+v", result)
	}
}

// A hold covering the repo keeps an unnamed container, and one stored again since the LIST answers 412 and stays,
// counted as replaced.
func TestNightlyPassKeepsAHeldOrReplacedUnnamedContainer(t *testing.T) {
	fixture := newNightlyFixture(t)
	parcelCluster, parcel := fixture.putUnnamed("parcel", false)
	fixture.clock.Advance(25*time.Hour + time.Minute)
	err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.check.networkId, CaseId: testId("hold case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := fixture.runPass(); result.UnnamedDeletedCount != 0 || !fixture.stands(parcelCluster, parcel) {
		t.Fatalf("held: %+v", result)
	}

	fixture.clock.Advance(25 * time.Hour)
	fixture.onStep = func(name string, key string) {
		if name != BarrierGcDeleteBefore || key != barrierRepoKey(fixture.check.repoId) {
			return
		}
		fixture.onStep = nil
		if err := parcelCluster.Delete(fixture.ctx, parcel); err != nil {
			t.Error(err)
		}
		fixture.clock.Advance(2 * time.Second)
		if _, err := parcelCluster.PutIfNoneMatch(fixture.ctx, parcel, []byte("container parcel"), nil); err != nil {
			t.Error(err)
		}
	}
	result := fixture.runPass()
	if result.UnnamedReplacedCount != 1 || result.UnnamedDeletedCount != 0 || !fixture.stands(parcelCluster, parcel) {
		t.Fatalf("stored again: %+v", result)
	}
}

// FS-53's idle repo: a parcel no push brings back to evacuation is packed by the nightly pass once its oldest record
// would pass 7 d before the next pass, the pack and its entries first, then the parcel and its entries, and the
// record still reads.
func TestNightlyPassPacksAnIdleRepoBeforeItsParcelPasses7Days(t *testing.T) {
	fixture := newNightlyFixture(t)
	place, recordBytes := fixture.commit("a")
	fixture.age()
	fixture.mustRun()
	if parcels := fixture.keys("meta-1", parcelKeyPrefix); len(parcels) != 1 {
		t.Fatalf("parcels %v", parcels)
	}

	fixture.clock.Advance(4 * 24 * time.Hour)
	if result := fixture.runPass(); result.IdlePackCount != 0 || len(fixture.keys("meta-1", parcelKeyPrefix)) != 1 {
		t.Fatalf("at 5 d: %+v", result)
	}
	fixture.clock.Advance(24 * time.Hour)
	result := fixture.runPass()
	if result.IdlePackCount != 1 || result.ReplacedParcelCount != 1 {
		t.Fatalf("at 6 d: %+v", result)
	}
	if parcels, packs := fixture.keys("meta-1", parcelKeyPrefix), fixture.keys("seg-1", packKeyPrefix); len(parcels) != 0 || len(packs) != 1 {
		t.Fatalf("parcels %v packs %v", parcels, packs)
	}
	fixture.requireRecord(place, recordBytes)
}

// An unnamed pack stays while the repo has a parcel or a log page a move could build the same bytes from again: a
// move killed after its pack, run again beside the pass, would reuse the pack on its 412 and name it.
func TestNightlyPassKeepsAnUnnamedPackAMoveCouldRebuild(t *testing.T) {
	fixture := newNightlyFixture(t)
	packCluster, pack := fixture.putUnnamed("pack", true)
	_, parcel := fixture.putUnnamed("parcel", false)
	fixture.clock.Advance(25*time.Hour + time.Minute)
	// the unnamed parcel goes this night, and with it what a move could rebuild the pack from
	if result := fixture.runPass(); result.UnnamedDeletedCount != 1 || !fixture.stands(packCluster, pack) || fixture.stands(fixture.cluster, parcel) {
		t.Fatalf("beside a parcel: %+v", result)
	}
	if result := fixture.runPass(); result.UnnamedDeletedCount != 1 || fixture.stands(packCluster, pack) {
		t.Fatalf("the next night: %+v", result)
	}
}
