package evsservice

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
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

// A shard's args go back whole, its start key last whatever bytes it holds; the start's empty args and any other
// shape read as no shard's; and every run of one shard, of any night or part, shares the shard's once key.
func TestEvsNightlyArgsRoundTrip(t *testing.T) {
	args := &EvsNightlyShardArgs{ClusterId: "meta-1", Shard: "a7", StartAfter: "repo/a7ff\nwith a break", Night: 1762819200123, Part: 2, Whole: true}
	parsed, ok := ParseEvsNightlyArgs(EvsNightlyArgs(args))
	if !ok || *parsed != *args {
		t.Fatalf("%+v %t", parsed, ok)
	}
	for _, bad := range []string{
		"",
		"meta-1",
		"meta-1\na7\nrepo/a7ff",
		"\na7\n1762819200123\n0\n1\n",
		"meta-1\na7\n0\n0\n1\n",
		"meta-1\na7\nnight\n0\n1\n",
		"meta-1\na7\n1762819200123\n-1\n1\n",
		"meta-1\na7\n1762819200123\n0\nyes\n",
	} {
		if _, ok := ParseEvsNightlyArgs([]byte(bad)); ok {
			t.Errorf("%q read as a shard's args", bad)
		}
	}
	at := time.Unix(1700000000, 0)
	request := EvsNightlyTaskRequest(args, at, nil)
	other := EvsNightlyTaskRequest(&EvsNightlyShardArgs{ClusterId: "meta-1", Shard: "a8", Night: args.Night, Whole: true}, at, nil)
	if request.Name != EvsNightlyTaskName || request.OnceKey == other.OnceKey || request.OnceKey == EvsNightlyStartTaskRequest(at).OnceKey {
		t.Fatalf("once keys %q %q", request.OnceKey, other.OnceKey)
	}
	if next := EvsNightlyTaskRequest(&EvsNightlyShardArgs{ClusterId: "meta-1", Shard: "a7", Night: args.Night + 1, Whole: true}, at, nil); next.OnceKey != request.OnceKey {
		t.Fatalf("another night's run of the shard under %q", next.OnceKey)
	}
}

// Another repo of networkId on meta-1, holding one segment of body: its id.
func (self *nightlyFixture) putOtherRepo(label string, networkId sidecar.Id, body []byte) sidecar.Id {
	self.t.Helper()
	repoId := testId("repo " + label)
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: self.check.signerId}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 1, NetworkId: networkId.Bytes(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, RepoKey(repoId), repoBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	segmentId := sha256.Sum256(body)
	if _, err := self.segmentCluster().PutIfNoneMatch(self.ctx, SegmentKey(repoId, segmentId), body, nil); err != nil {
		self.t.Fatal(err)
	}
	return repoId
}

// The night's sums on the fixture's Redis.
func (self *nightlyFixture) sums() *NightlySums {
	self.t.Helper()
	sums, err := NewNightlySums(self.host.Redis, self.passSettings)
	if err != nil {
		self.t.Fatal(err)
	}
	return sums
}

// The nightly start queues each shard of each metadata cluster with the night, its own time, and the night's closing
// job naming every shard; the run that lists its shard whole replaces the shard's sums for the night, which read
// back as each network's stored bytes; and a run with a read that failed counts on and reports nothing.
func TestNightlyPassReportsAWholeShardForItsNight(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.commit("a")
	fixture.putSegment("first")
	host := fixture.host.ServiceHost()
	if result, err := RunNightlyPass(fixture.ctx, host, fixture.deps(), nil); err != nil || result != nil {
		t.Fatalf("the start: %+v %v", result, err)
	}
	night := fixture.clock.Now().UnixMilli()
	var shardArgs *EvsNightlyShardArgs
	var closeArgs *EvsNightlyCloseArgs
	for _, request := range fixture.host.Tasks.Pending() {
		switch {
		case request.Name == EvsNightlyCloseTaskName:
			closeArgs, _ = ParseEvsNightlyCloseArgs(request.Args)
			if !request.RunAt.Equal(fixture.clock.Now().Add(fixture.passSettings.NightlyCloseRetryInterval)) {
				t.Fatalf("the closing job first asks at %v", request.RunAt)
			}
		case request.Name == EvsNightlyTaskName && 0 < len(request.Args):
			shardArgs, _ = ParseEvsNightlyArgs(request.Args)
		}
	}
	if shardArgs == nil || shardArgs.ClusterId != "meta-1" || shardArgs.Night != night || shardArgs.Part != 0 || !shardArgs.Whole {
		t.Fatalf("the shard's run: %+v", shardArgs)
	}
	if closeArgs == nil || closeArgs.Night != night || !slices.Equal(closeArgs.ShardFields, []string{"meta-1:"}) {
		t.Fatalf("the closing job: %+v", closeArgs)
	}

	result, err := RunNightlyPass(fixture.ctx, host, fixture.deps(), EvsNightlyArgs(shardArgs))
	if err != nil || !result.Complete || !result.Reported || result.Night != night {
		t.Fatalf("the shard's run: %+v %v", result, err)
	}
	counts, found, err := fixture.sums().Read(fixture.ctx, night, "meta-1", "")
	stored := result.NetworkBytes[fixture.check.networkId]
	if err != nil || !found || len(counts) != 1 || stored == nil || counts[fixture.check.networkId] != stored.StoredByteCount() {
		t.Fatalf("the shard's sums %v %t %v, the run's %+v", counts, found, err, stored)
	}

	// another night's run, with a LIST that fails
	later := *shardArgs
	later.Night = night + 1
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpList, KeyPrefix: segmentKeyPrefix, Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	result, err = RunNightlyPass(fixture.ctx, host, fixture.deps(), EvsNightlyArgs(&later))
	if err == nil || result == nil || result.Reported || result.RepoCount != 1 {
		t.Fatalf("a run with a read that failed: %+v %v", result, err)
	}
	if _, found, err := fixture.sums().Read(fixture.ctx, later.Night, "meta-1", ""); err != nil || found {
		t.Fatalf("a run with a read that failed reported: %t %v", found, err)
	}
}

// A shard listed over several runs carries its sums from run to run in the night's key and never in its args, and
// the run that reaches the shard's end reports every repo's; a chain whose carried sums are gone reports nothing.
func TestNightlyPassCarriesAShardsSumsAcrossItsRuns(t *testing.T) {
	fixture := newNightlyFixture(t)
	fixture.passSettings.RunRepoCount = 1
	fixture.putSegment("first")
	otherNetworkId := testId("network other")
	otherBody := []byte("the other repo's segment")
	fixture.putOtherRepo("other", otherNetworkId, otherBody)
	host := fixture.host.ServiceHost()
	night := fixture.clock.Now().UnixMilli()

	first, err := RunNightlyPass(fixture.ctx, host, fixture.deps(), EvsNightlyArgs(&EvsNightlyShardArgs{ClusterId: "meta-1", Night: night, Whole: true}))
	if err != nil || !first.More || first.Reported || first.RepoCount != 1 {
		t.Fatalf("the first run: %+v %v", first, err)
	}
	var next *EvsNightlyShardArgs
	for _, request := range fixture.host.Tasks.Pending() {
		if request.Name == EvsNightlyTaskName {
			next, _ = ParseEvsNightlyArgs(request.Args)
		}
	}
	if next == nil || next.Part != 1 || !next.Whole || next.StartAfter != first.NextStartAfter || next.Night != night {
		t.Fatalf("the next run: %+v", next)
	}
	for _, request := range fixture.host.Tasks.AllRequests() {
		for _, networkId := range []sidecar.Id{fixture.check.networkId, otherNetworkId} {
			if bytes.Contains(request.Args, networkId[:]) || bytes.Contains(request.Args, []byte(sidecar.EvsKeyId(networkId))) {
				t.Fatalf("a run's args name a network: %q", request.Args)
			}
		}
	}

	last, err := RunNightlyPass(fixture.ctx, host, fixture.deps(), EvsNightlyArgs(next))
	if err != nil || last.More || !last.Reported || last.Complete {
		t.Fatalf("the last run: %+v %v", last, err)
	}
	want := nightlyStoredByteCounts(first.NetworkBytes)
	if err := addNightlySums(want, nightlyStoredByteCounts(last.NetworkBytes)); err != nil {
		t.Fatal(err)
	}
	counts, found, err := fixture.sums().Read(fixture.ctx, night, "meta-1", "")
	if err != nil || !found || !maps.Equal(counts, want) || len(counts) != 2 || counts[otherNetworkId] != int64(len(otherBody)) {
		t.Fatalf("the shard's sums %v %t %v, want %v", counts, found, err, want)
	}

	// the chain's carried sums lost: the last run, run again, reports nothing
	fixture.host.Redis.LoseKeys(NightlySumsKey(night))
	again, err := RunNightlyPass(fixture.ctx, host, fixture.deps(), EvsNightlyArgs(next))
	if err != nil || again.Reported {
		t.Fatalf("the last run again: %+v %v", again, err)
	}
	if _, found, err := fixture.sums().Read(fixture.ctx, night, "meta-1", ""); err != nil || found {
		t.Fatalf("a chain with its sums gone reported: %t %v", found, err)
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
