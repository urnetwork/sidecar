package fault

// FS-60's nightly clauses (§22.8, FI-1, FI-13 (c); EVSB-M2-12), on T2: the nightly pass over the evacuation world of
// fs60_test.go. A small repo no push brings back to evacuation has its parcels packed by the pass as they near 7 d,
// the replacement killed between the pack's entries and the parcel's delete and finished by the next night, a
// reader finding every record at each step and taking the pack's entry over the parcel's; and the pass's count is
// the LIST sizes plus the batch-resident record lengths, less the containers it deleted, which with shards the
// closing job writes once every shard has reported (EVSB-M2-26; owner decision 198). T3's run on the real store is
// EVSB-M2-17's suite.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One nightly run of meta-1's one shard, the segment cluster quiet.
func (self *evacuationWorld) nightly() (*evsservice.NightlyResult, error) {
	self.t.Helper()
	pass, err := evsservice.NewNightlyPass(self.host.ServiceHost(), &evsservice.NightlyPassDeps{
		Evacuator:          self.settings,
		SegmentClusterBusy: func(ctx context.Context, clusterId string) bool { return false },
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return pass.Run(self.ctx, "meta-1", "", "")
}

// FS-60: a small repo's parcels pack at 7 d in the nightly pass when no push brings the repo back to evacuation,
// the replacement killed between the pack's entries and the parcel's delete; a reader finds every record
// throughout, and the next night deletes the parcel the pack holds.
func TestFs60NightlyPacksAnIdleRepoWithTheReplacementKilled(t *testing.T) {
	world := newEvacuationWorld(t)
	world.commit()
	world.age()
	if result := world.mustRun(); result.ParcelCount != 1 {
		t.Fatalf("evacuation %+v", result)
	}
	parcels := world.keys("meta-1", "hp/")

	// the night its parcel's oldest record would pass 7 d before the next night
	world.clock.Advance(5*24*time.Hour + time.Hour)
	world.killAt(sidecartest.FaultOpDelete, "pidx/", 1)
	if result, err := world.nightly(); err == nil {
		t.Fatalf("the pass was not killed: %+v", result)
	}
	if unfired := world.host.Blobs.Faults().Unfired(); len(unfired) != 0 {
		t.Fatalf("the kill never fired: %v", unfired)
	}
	if packs := world.keys("seg-1", "pack/"); len(packs) != 1 {
		t.Fatalf("packs after the kill: %v", packs)
	}
	if kept := world.keys("meta-1", "hp/"); len(kept) != 1 || kept[0] != parcels[0] {
		t.Fatalf("the parcel went past the kill: %v", kept)
	}
	world.requireEveryRecord("the pack and the parcel both standing")

	world.clock.Advance(24 * time.Hour)
	result, err := world.nightly()
	if err != nil {
		t.Fatalf("the next night: %v (%+v)", err, result)
	}
	if result.IdlePackCount != 0 || result.ReplacedParcelCount != 1 {
		t.Fatalf("the next night %+v", result)
	}
	if left := world.keys("meta-1", "hp/"); len(left) != 0 {
		t.Fatalf("parcels left: %v", left)
	}
	world.requireEveryRecord("after the parcel went")
}

// FI-13 (c) after a pass: the network's count is what the LISTs show of seg/, pack/ and hp/ plus the lengths the
// head window gives for records still in batches, and a container the pass deleted counts no more.
func TestFs60NightlyCountIsListSizesPlusBatchRecords(t *testing.T) {
	world := newEvacuationWorld(t)
	first := world.commit()
	world.age()
	world.mustRun()
	second := world.commit()

	result, err := world.nightly()
	if err != nil {
		t.Fatal(err)
	}
	stored := result.NetworkBytes[world.networkId]
	if stored == nil {
		t.Fatalf("no count for the network: %+v", result)
	}
	listed := int64(0)
	for _, family := range []struct{ clusterId, prefix string }{{"seg-1", "seg/"}, {"seg-1", "pack/"}, {"meta-1", "hp/"}} {
		cluster, err := world.host.Blobs.Cluster(family.clusterId)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range world.keys(family.clusterId, family.prefix) {
			info, err := cluster.Head(sidecartest.InspectContext(world.ctx), key)
			if err != nil {
				t.Fatal(err)
			}
			listed += info.ByteCount
		}
	}
	if want := listed + int64(second.place.GetLength()); stored.StoredByteCount() != want {
		t.Fatalf("count %d (%+v), want %d: listed %d and the batch-resident record's %d", stored.StoredByteCount(), stored, want, listed, second.place.GetLength())
	}
	if stored.BatchRecordByteCount != int64(second.place.GetLength()) || first.place.GetLength() == 0 {
		t.Fatalf("batch-resident %d", stored.BatchRecordByteCount)
	}
}

// T2's count store for the closing job: each network's count, as network_quota_state holds it. Safe for concurrent
// use.
type fs60Counts struct {
	stateLock sync.Mutex
	counts    map[sidecar.Id]int64
}

func (self *fs60Counts) SetStoredByteCount(ctx context.Context, networkId sidecar.Id, storedByteCount int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.counts[networkId] = storedByteCount
	return nil
}

func (self *fs60Counts) NetworkIdsWithStoredByteCount(ctx context.Context, after *sidecar.Id, limit int) ([]sidecar.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := []sidecar.Id{}
	for _, networkId := range slices.SortedFunc(maps.Keys(self.counts), func(a sidecar.Id, b sidecar.Id) int { return bytes.Compare(a[:], b[:]) }) {
		if self.counts[networkId] <= 0 || (after != nil && bytes.Compare(networkId[:], after[:]) <= 0) {
			continue
		}
		if len(networkIds) == limit {
			break
		}
		networkIds = append(networkIds, networkId)
	}
	return networkIds, nil
}

func (self *fs60Counts) count(networkId sidecar.Id) (int64, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count, ok := self.counts[networkId]
	return count, ok
}

// Another repo of the world's network on meta-1, in another shard of 16 than the world's repo, holding one segment.
func (self *evacuationWorld) putOtherRepo() sidecar.Id {
	self.t.Helper()
	shard := sidecar.EvsKeyId(self.repoId)[:1]
	var repoId sidecar.Id
	for index := 0; ; index += 1 {
		repoId = evacuationId(fmt.Sprintf("other repo %d", index))
		if sidecar.EvsKeyId(repoId)[:1] != shard {
			break
		}
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: self.signerId}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: self.repoKind, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 1, NetworkId: self.networkId.Bytes(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, evsservice.RepoKey(repoId), repoBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	body := []byte("the other repo's one segment")
	if _, err := segmentCluster.PutIfNoneMatch(self.ctx, evsservice.SegmentKey(repoId, sha256.Sum256(body)), body, nil); err != nil {
		self.t.Fatal(err)
	}
	return repoId
}

// FS-60's nightly count with shards (FI-13 (c); owner decision 198): the pass run as its jobs, sixteen shards of the
// one metadata cluster, the network's two repos in two of them. No shard's run writes the count; the closing job,
// once every shard has reported, writes it once, the LIST sizes of seg/, pack/ and hp/ over both repos plus the
// batch-resident record's length.
func TestFs60NightlyCountCombinesTheShards(t *testing.T) {
	world := newEvacuationWorld(t)
	world.commit()
	world.age()
	world.mustRun()
	second := world.commit()
	world.putOtherRepo()

	settings := evsservice.DefaultNightlyPassSettings()
	settings.ShardHexDigitCount = 1
	counts := &fs60Counts{counts: map[sidecar.Id]int64{}}
	host := world.host.ServiceHost()
	passDeps := &evsservice.NightlyPassDeps{
		Settings:           settings,
		Evacuator:          world.settings,
		SegmentClusterBusy: func(ctx context.Context, clusterId string) bool { return false },
	}
	world.host.Tasks.Register(evsservice.EvsNightlyTaskName, func(ctx context.Context, args []byte) error {
		_, err := evsservice.RunNightlyPass(ctx, host, passDeps, args)
		return err
	})
	world.host.Tasks.Register(evsservice.EvsNightlyCloseTaskName, func(ctx context.Context, args []byte) error {
		_, err := evsservice.RunNightlyClose(ctx, host, &evsservice.NightlyCloseDeps{Counts: counts, Settings: settings}, args)
		return err
	})
	if err := world.host.Tasks.Schedule(world.ctx, evsservice.EvsNightlyStartTaskRequest(world.clock.Now())); err != nil {
		t.Fatal(err)
	}
	// the start, then each shard's run
	ran, err := world.host.Tasks.RunDue(world.ctx)
	if err != nil || ran != 1+16 {
		t.Fatalf("ran %d: %v", ran, err)
	}
	if _, written := counts.count(world.networkId); written {
		t.Fatal("a shard's run wrote the count")
	}
	world.clock.Advance(settings.NightlyCloseRetryInterval)
	if ran, err := world.host.Tasks.RunDue(world.ctx); err != nil || ran != 1 {
		t.Fatalf("the closing job: ran %d: %v", ran, err)
	}

	listed := int64(0)
	for _, family := range []struct{ clusterId, prefix string }{{"seg-1", "seg/"}, {"seg-1", "pack/"}, {"meta-1", "hp/"}} {
		cluster, err := world.host.Blobs.Cluster(family.clusterId)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range world.keys(family.clusterId, family.prefix) {
			info, err := cluster.Head(sidecartest.InspectContext(world.ctx), key)
			if err != nil {
				t.Fatal(err)
			}
			listed += info.ByteCount
		}
	}
	want := listed + int64(second.place.GetLength())
	if count, written := counts.count(world.networkId); !written || count != want {
		t.Fatalf("count %d (written %t), want %d: listed %d and the batch-resident record's %d", count, written, want, listed, second.place.GetLength())
	}
	if world.host.Tasks.RunCount(evsservice.EvsNightlyCloseTaskName) != 1 {
		t.Fatalf("closing runs %d", world.host.Tasks.RunCount(evsservice.EvsNightlyCloseTaskName))
	}
}
