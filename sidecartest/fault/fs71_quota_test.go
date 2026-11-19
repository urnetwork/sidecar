package fault

// FS-71's api half on T2 (QUOTA-M10-01; §20.6's adds and purge rows, §20.7's stored and count rows; R-QUOTA-7,
// D-QUOTA-3; FI-13 (a) and (c)): the stored count as format 2's jobs move it, over the real committing purge, the real
// evacuation with its staged decision and its sweep, the turn-on pass and the nightly pass, each producer's real
// batcher (evs's, and taskworker's as server/taskworker/evs_evacuate.go makes it) and FakeQuota, on one fake clock.
// The history is committed by hand as evs commits it, on the drop rows' world (fs_drop_world_test.go): versionless
// versions on uploaded kind-5 segments and on staged segments riding in their push's record, and the removals that
// replace them, each with its purge list in its record's tail and bit 4 in its window entry. Adds are reported as evs
// reports them: a segment's stored size at its upload and a record's length at its commit.
//
//	count     FakeQuota keeps no nightly count: a network's stored bytes there are the deltas applied, once each. So
//	          the count is held to the adds less the frees reported, and, while every record is still in its batch,
//	          to the sum the real nightly pass lists (FI-13 (c)): what LISTs show and what the batches moved agree
//	kind-5    the committing process's purge deletes a replaced kind-5 segment at seg/ and reports it once; a
//	          process handed the same commit again, and evacuation's sweep of the record, find it gone and report
//	          nothing
//	staged    a staged record counts while its batch lives, at its record's length; replaced 24 h after its push,
//	          its purge finds nothing at seg/ and reports nothing, and at 25 h evacuation drops it with its batch and
//	          taskworker reports it once, a resent batch and a second run moving nothing
//	observe   under purge: observe nothing is deleted or reported and the replaced content counts; the turn-on pass
//	          deletes it and reports nothing, so the count keeps it until the night, whose listing has let it go
//
// The refusal at the exact limit is evs's gate's (evsservice's push_purge_test.go) and follows the count on T3
// (server/quotahost's format2_usage_t3_test.go), since FakeQuota derives no refusal from its count. After evacuation
// the count and a listing differ by the container's framing until the night's write, which only T3 has.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// §19.11's format2 gate with a purge mode a test turns.
type fs71Format2 struct {
	stateLock sync.Mutex
	purge     sidecar.Format2Mode
}

func (self *fs71Format2) Admits(networkId sidecar.Id) bool { return true }

func (self *fs71Format2) PurgeMode() sidecar.Format2Mode {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.purge
}

func (self *fs71Format2) DropMode() sidecar.Format2Mode { return sidecar.Format2Observe }

func (self *fs71Format2) set(mode sidecar.Format2Mode) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.purge = mode
}

// Each path's newest committed version as the world committed it, for the committing purge's reread. Evacuation and
// the passes read theirs from the cluster.
type fs71Newest struct {
	stateLock  sync.Mutex
	pathNewest map[string]*evsservice.PurgeNewest
}

func (self *fs71Newest) NewestNames(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, pathEpoch uint64, tokenPath sidecar.EvsTokenPath) (*evsservice.PurgeNewest, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	newest, ok := self.pathNewest[tokenPath.KeyString()]
	if !ok {
		return &evsservice.PurgeNewest{Names: map[string]bool{}}, nil
	}
	names := map[string]bool{}
	for id := range newest.Names {
		names[id] = true
	}
	return &evsservice.PurgeNewest{Names: names, CommitVersion: newest.CommitVersion, CommitMinuteEnd: newest.CommitMinuteEnd}, nil
}

func (self *fs71Newest) set(tokenPath sidecar.EvsTokenPath, newest *evsservice.PurgeNewest) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pathNewest[tokenPath.KeyString()] = newest
}

// One change of a push: a versionless version of its path, or its removal.
type fs71Change struct {
	path sidecar.EvsTokenPath
	// the path's entry version the change is based on, 0 for a create
	base uint64
	// the version written, nil for a removal; the commit fills its push, base and time
	entry *protocol.EvsEntryVersion
}

// One push as the world commits it.
type fs71Push struct {
	changes    []*fs71Change
	newObjects []*sidecar.EvsNewObject
	// staged segments riding in the record's tail
	staged [][]byte
	// what the push's versions replace, as step 5 lists it
	list *protocol.EvsPurgeList
}

// A committed push.
type fs71Committed struct {
	pushId  sidecar.Id
	version uint64
	// its record's length in its batch, which evs adds to the stored count at the commit
	recordByteCount int64
}

// The drop rows' world with format 2's versionless writes, both usage producers and the count they must hold.
type fs71QuotaWorld struct {
	*fsDropWorld
	gate   *fs71Format2
	newest *fs71Newest
	refId  sidecar.Id
	// evs's producer, and taskworker's as its evacuation run makes one
	evsUsage  *evsservice.UsageBatcher
	taskUsage *sidecar.QuotaUsageBatcher
	oracle    *sidecartest.QuotaOracle
	// the adds less the frees reported so far
	count int64
}

func newFs71QuotaWorld(t *testing.T, purge sidecar.Format2Mode) *fs71QuotaWorld {
	t.Helper()
	base := newFsDropWorld(t)
	// placed, as evacuation and the nightly pass find a repo
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: base.cluster.ClusterId(), CreatorSidecarId: base.signerId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	first, err := base.serviceHost.Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.PutIfNoneMatch(base.paidCtx, sidecar.EvsPlaceKey(base.repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	evsUsage, err := evsservice.NewUsageBatcher(base.ctx, base.serviceHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(evsUsage.Close)
	taskUsage, err := sidecar.NewQuotaUsageBatcher(base.ctx, base.serviceHost, sidecar.QuotaProducerTaskworker, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(taskUsage.Close)
	return &fs71QuotaWorld{
		fsDropWorld: base,
		gate:        &fs71Format2{purge: purge},
		newest:      &fs71Newest{pathNewest: map[string]*evsservice.PurgeNewest{}},
		refId:       fsDropId16("ref v"),
		evsUsage:    evsUsage,
		taskUsage:   taskUsage,
		oracle:      sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(base.host.Quota)),
	}
}

// A versionless version at entry version version, on one kind-5 segment: uploaded, or staged in its push's record.
func fs71Entry(version uint64, segmentId [32]byte, staged bool) *protocol.EvsEntryVersion {
	return &protocol.EvsEntryVersion{
		Version: version, Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
		Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS),
		Chain: []*protocol.EvsLocator{{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: bytes.Clone(segmentId[:]),
			Offset: sidecar.EvsKind5SegmentHeaderByteCount, Length: uint32(sidecar.EvsRecordByteCount(100)), Staged: staged,
		}},
	}
}

// A staged segment from a label: its bytes, padded as a small file's, and its id.
func fs71Staged(label string) ([]byte, [32]byte) {
	size := int(sidecar.EvsPadme(1000))
	segment := bytes.Repeat([]byte(label), size/len(label)+1)[:size]
	return segment, sha256.Sum256(segment)
}

// An upload of a kind-5 segment of byteCount to seg/, counted as evs's upload route counts it.
func (self *fs71QuotaWorld) upload(id [32]byte, byteCount int) {
	self.t.Helper()
	self.storeSegment(id, byteCount)
	if err := self.evsUsage.AddStored(connect.Id(self.networkId), int64(byteCount)); err != nil {
		self.t.Fatal(err)
	}
	self.count += int64(byteCount)
}

// Commits push on the world's ref at its next version, as steps 6 and 7 do: its record in a batch with its tail, then
// the head, its window entry carrying bit 4 when the record lists candidates; and counts its record as the commit does.
func (self *fs71QuotaWorld) push(push *fs71Push) *fs71Committed {
	self.t.Helper()
	ref, ok := self.refs[self.refId]
	if !ok {
		ref = &fsDropRef{head: &evsservice.EvsStoredHead{}, mode: protocol.EvsRefMode_EVS_REF_FILE, epoch: 1}
		self.refs[self.refId] = ref
	}
	self.pushSeq += 1
	pushId := fsDropId16(fmt.Sprintf("fs71 push %d", self.pushSeq))
	baseVersion := ref.head.Version()
	baseChain := sidecar.EvsChainStart(self.repoId, self.refId)
	if !ref.head.Absent() && 0 < baseVersion {
		baseChain = [32]byte(ref.head.Head.GetChain())
	}
	now := self.clock.Now()
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain, Generation: 1, GroupId: fsDropId16("group"),
		GenerationCommitment: make([]byte, 32), PathEpoch: ref.epoch, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		SignerSidecarId: self.signerId, ClientId: fsDropId16("client"), TimeMs: now.UnixMilli(),
		SealedMetadata: []byte("sealed metadata"), NewObjects: push.newObjects,
	}
	changes := slices.Clone(push.changes)
	slices.SortStableFunc(changes, func(a *fs71Change, b *fs71Change) int { return a.path.Compare(b.path) })
	changedPaths := []sidecar.EvsTokenPath{}
	createsPath := false
	for _, change := range changes {
		var entryBytes []byte
		if change.entry != nil {
			change.entry.PushId = pushId.Bytes()
			change.entry.BaseVersion = baseVersion
			change.entry.TimeMs = now.UnixMilli()
			var err error
			entryBytes, err = proto.MarshalOptions{Deterministic: true}.Marshal(change.entry)
			if err != nil {
				self.t.Fatal(err)
			}
		}
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: change.path, BaseEntryVersion: change.base, EntryVersion: entryBytes})
		changedPaths = append(changedPaths, change.path)
		createsPath = createsPath || (change.base == 0 && change.entry != nil)
	}
	built, err := self.builder.BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: self.repoId, RefId: self.refId, PushId: pushId,
		SignerSidecarId: self.signerId, TimeMs: plan.TimeMs, Body: sidecar.EvsPushRecordBody(built.Statement.Bytes, built.Payload),
	}
	tail := &sidecar.EvsBatchRecordTail{Staged: sidecar.EvsEncodeStaged(push.staged)}
	if push.list != nil {
		listBytes, err := sidecar.EncodeEvsPurgeList(push.list)
		if err != nil {
			self.t.Fatal(err)
		}
		tail.PurgeList = listBytes
	}
	place, err := self.batches.AppendFormat2(self.paidCtx, "meta-1", record, tail)
	if err != nil {
		self.t.Fatal(err)
	}
	var coveringPrefixes []sidecar.EvsTokenPath
	if len(built.Statement.Push.GetChangesRoot()) != 0 {
		coveringPrefixes = built.Statement.ChangedPrefixes
	}
	windowEntry := sidecar.NewEvsWindowEntry(built.Statement.Sha256, built.Statement.Push, changedPaths, coveringPrefixes, createsPath, place)
	if push.list != nil {
		windowEntry.SetReplacesVersionless()
	}
	next := evsservice.CloneEvsHead(ref.head.Head)
	if ref.head.Absent() {
		next = &protocol.EvsHead{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED), RefMode: uint32(protocol.EvsRefMode_EVS_REF_FILE),
			PathEpoch: &protocol.EvsPathEpoch{Current: 1}, WindowBaseChain: baseChain[:],
		}
	}
	chain := sidecar.EvsChainNext(baseChain, pushId, built.Statement.Sha256)
	next.Version = baseVersion + 1
	next.Chain = chain[:]
	next.PushId = pushId.Bytes()
	next.Window = append(bytes.Clone(next.GetWindow()), windowEntry.Encode()...)
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, ref.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	ref.head = written

	// each changed path's newest version, as the purge's reread would find it at the head
	minuteEnd := now.Truncate(time.Minute).Add(time.Minute)
	for _, change := range changes {
		newest := &evsservice.PurgeNewest{Names: map[string]bool{}, CommitVersion: next.Version, CommitMinuteEnd: minuteEnd}
		for _, locator := range change.entry.GetChain() {
			newest.Names[string(locator.GetId())] = true
		}
		self.newest.set(change.path, newest)
	}
	// step 7's count of the record (push_commit.go)
	recordByteCount := int64(place.GetLength())
	if err := self.evsUsage.AddStored(connect.Id(self.networkId), recordByteCount); err != nil {
		self.t.Fatal(err)
	}
	self.count += recordByteCount
	return &fs71Committed{pushId: pushId, version: next.Version, recordByteCount: recordByteCount}
}

// A push removing path, whose versionless version replaced it lists in list.
func (self *fs71QuotaWorld) remove(path sidecar.EvsTokenPath, replaced *protocol.EvsEntryVersion, candidate *protocol.EvsPurgeCandidate) (*fs71Committed, *evsservice.PurgeCommit) {
	self.t.Helper()
	candidate.TokenPath = path.Components()
	candidate.ReplacedVersion = replaced.GetVersion()
	list := &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{candidate}}
	committed := self.push(&fs71Push{changes: []*fs71Change{{path: path, base: replaced.GetVersion()}}, list: list})
	return committed, &evsservice.PurgeCommit{
		ClusterId: "meta-1", RepoId: self.repoId, RefId: self.refId, NetworkId: self.networkId,
		PushId: committed.pushId, Version: committed.version, PathEpoch: 1, List: list,
		Replaced: []*evsservice.PurgeReplaced{{TokenPath: path, Version: replaced}},
	}
}

// One evs process handed commit as certain: its purge waits out the readers' allowance, deletes what falls due and
// ends, as a stopping process drains. What it did.
func (self *fs71QuotaWorld) purge(commit *evsservice.PurgeCommit) evsservice.PurgeStats {
	self.t.Helper()
	purger, err := evsservice.NewPurger(self.ctx, self.serviceHost, &evsservice.PurgerDeps{Format2: self.gate, Newest: self.newest, Usage: self.evsUsage})
	if err != nil {
		self.t.Fatal(err)
	}
	defer purger.Close()
	purger.Certain(commit)
	self.clock.Advance(evsservice.DefaultPurgerSettings().Allowance)
	// ends once its queue is empty: the clock stands still, so the drain's own timeout never fires
	purger.Drain()
	if queued := purger.QueuedIdCount(); queued != 0 {
		self.t.Fatalf("the purge ended with %d ids queued", queued)
	}
	return purger.Stats()
}

// One hourly evacuation of meta-1 at format 2, as taskworker's job runs it: its sweep and its staged decisions reading
// the cluster, its frees to taskworker's producer, whose window is sent as the run ends.
func (self *fs71QuotaWorld) evacuate() *evsservice.EvacuationResult {
	self.t.Helper()
	evsSettings := evsservice.DefaultEvsSettings()
	evsSettings.InstanceFormat = sidecar.EvsRepoFormat2
	settings := evsservice.DefaultEvacuatorSettings()
	settings.SpoolDirectory = self.t.TempDir()
	evacuator, err := evsservice.NewEvacuator(self.serviceHost, &evsservice.EvacuatorDeps{
		Settings: settings, EvsSettings: evsSettings, Format2: self.gate, Usage: self.taskUsage,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	result, err := evacuator.Run(self.ctx, "meta-1")
	if err != nil {
		self.t.Fatalf("evacuation: %v (%+v)", err, result)
	}
	return result
}

// The nightly pass's sums for the network, from the real pass over meta-1's one shard.
func (self *fs71QuotaWorld) nightly(what string) *evsservice.NightlyBytes {
	self.t.Helper()
	pass, err := evsservice.NewNightlyPass(self.serviceHost, &evsservice.NightlyPassDeps{
		SegmentClusterBusy: func(ctx context.Context, clusterId string) bool { return false },
	})
	if err != nil {
		self.t.Fatal(err)
	}
	result, err := pass.Run(self.ctx, "meta-1", "", "")
	if err != nil || !result.Complete {
		self.t.Fatalf("%s: the nightly pass: %v (%+v)", what, err, result)
	}
	stored, ok := result.NetworkBytes[self.networkId]
	if !ok {
		return &evsservice.NightlyBytes{}
	}
	return stored
}

// Both producers' open windows sent, and what FakeQuota applied since: each batch once.
func (self *fs71QuotaWorld) drain(what string) {
	self.t.Helper()
	if err := self.evsUsage.Drain(self.ctx); err != nil {
		self.t.Fatalf("%s: evs's batches: %v", what, err)
	}
	if err := self.taskUsage.Drain(self.ctx); err != nil {
		self.t.Fatalf("%s: taskworker's batches: %v", what, err)
	}
}

// FI-13 (a) over the network, and its count: the adds less the frees reported, each once.
func (self *fs71QuotaWorld) requireCount(what string) {
	self.t.Helper()
	self.drain(what)
	if err := self.oracle.Check(self.ctx); err != nil {
		self.t.Fatalf("%s: %v", what, err)
	}
	if stored := self.host.Quota.StoredDelta(connect.Id(self.networkId)); stored != self.count {
		self.t.Fatalf("%s: the network counts %d stored, want %d", what, stored, self.count)
	}
}

// requireCount, and FI-13 (c) against the listing the real nightly pass makes: the count is what LISTs and head windows
// show. Only while every record is in its batch or nothing moved since a container was built.
func (self *fs71QuotaWorld) requireNight(what string) *evsservice.NightlyBytes {
	self.t.Helper()
	self.requireCount(what)
	stored := self.nightly(what)
	listing := &sidecartest.QuotaStoredListing{
		SegmentByteCount: stored.SegmentByteCount, PackByteCount: stored.PackByteCount,
		ParcelByteCount: stored.ParcelByteCount, BatchRecordByteCount: stored.BatchRecordByteCount,
	}
	if err := self.oracle.CheckStored(self.ctx, connect.Id(self.networkId), listing); err != nil {
		self.t.Fatalf("%s: %v", what, err)
	}
	return stored
}

// The batches FakeQuota applied from producer.
func (self *fs71QuotaWorld) batchesOf(producer string) []*sidecar.UsageBatch {
	batches := []*sidecar.UsageBatch{}
	for _, batch := range self.host.Quota.Batches() {
		if batch.Producer == producer {
			batches = append(batches, batch)
		}
	}
	return batches
}

// FS-71's api half: a replaced kind-5 segment counts until the committing process purges it, which reports it once,
// a second hand of the same commit and evacuation's sweep counting nothing twice; a staged record counts while its
// batch lives, and a staged candidate replaced 24 h after its push is subtracted once, by evacuation at 25 h, its
// purge having found nothing at seg/. The count is the nightly pass's listing at every step before a container is
// built.
func TestFs71QuotaFreesMoveTheStoredCountOnce(t *testing.T) {
	world := newFs71QuotaWorld(t, sidecar.Format2On)
	x, small := fsDropPath("x"), fsDropPath("small")
	s1 := fsDropSegment("fs71 s1")
	t1, t1Id := fs71Staged("t1")

	// x's version 1 on its uploaded kind-5 segment s1, 3,000 B stored, and push u1's small file, staged in its record
	world.upload(s1, 3000)
	xEntry := fs71Entry(1, s1, false)
	world.push(&fs71Push{
		changes:    []*fs71Change{{path: x, entry: xEntry}},
		newObjects: []*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: s1[:], PaddedSize: 4096, UploadDay: 1}},
	})
	smallEntry := fs71Entry(1, t1Id, true)
	u1 := world.push(&fs71Push{
		changes:    []*fs71Change{{path: small, entry: smallEntry}},
		newObjects: []*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: t1Id[:], PaddedSize: uint64(len(t1))}},
		staged:     [][]byte{t1},
	})
	if u1.recordByteCount < int64(len(t1)) {
		t.Fatalf("u1's record of %d B does not hold its %d staged bytes", u1.recordByteCount, len(t1))
	}
	night := world.requireNight("the night before")
	if night.SegmentByteCount != 3000 || night.BatchRecordByteCount == 0 {
		t.Fatalf("the night before lists %+v", night)
	}

	// a minute later u2 removes x: its record counts, and s1 counts until its purge
	world.clock.Advance(time.Minute)
	_, u2Commit := world.remove(x, xEntry, &protocol.EvsPurgeCandidate{SegmentIds: [][]byte{s1[:]}})
	world.requireNight("u2 committed, s1 not yet purged")
	if !world.stored(s1) {
		t.Fatal("s1 went before its purge")
	}

	// u2's process purges s1 at seg/ after the readers' allowance and reports it
	stats := world.purge(u2Commit)
	if stats.DeletedCount != 1 || stats.FreedByteCount != 3000 || world.stored(s1) {
		t.Fatalf("the purge of s1: %+v, stored %t", stats, world.stored(s1))
	}
	world.count -= 3000
	if night := world.requireNight("s1 purged"); night.SegmentByteCount != 0 {
		t.Fatalf("after the purge the night lists %+v", night)
	}

	// a process handed the same commit again, as a reread after a lost answer hands it, finds s1 gone and reports nothing
	evsBatchCount := len(world.batchesOf(sidecar.QuotaProducerEvs))
	stats = world.purge(u2Commit)
	if stats.DeletedCount != 0 || stats.AbsentCount != 1 || stats.FreedByteCount != 0 {
		t.Fatalf("the second purge of s1: %+v", stats)
	}
	world.requireCount("s1 purged twice")
	if got := len(world.batchesOf(sidecar.QuotaProducerEvs)); got != evsBatchCount {
		t.Fatalf("a purge that found nothing sent %d batches", got-evsBatchCount)
	}

	// 24 h after u1, u3 removes the small file: its record counts, and its purge, the staged version being over 23 h
	// old, DELETEs at seg/, where t1 never was, and reports nothing; u1's record still counts t1 in its batch
	world.clock.Advance(24*time.Hour - 3*time.Minute)
	_, u3Commit := world.remove(small, smallEntry, &protocol.EvsPurgeCandidate{StagedSegmentIds: [][]byte{t1Id[:]}})
	stats = world.purge(u3Commit)
	if stats.DeletedCount != 0 || stats.AbsentCount != 1 || stats.EvacuationCount != 0 || stats.FreedByteCount != 0 {
		t.Fatalf("u3's purge of the staged candidate: %+v", stats)
	}
	world.requireNight("t1 replaced, its batch alive")

	// 25 h after u1, evacuation empties its minute: t1, replaced an hour ago, goes with its batch and taskworker reports
	// it; the sweep of u2's record HEADs s1, gone, and reports nothing
	world.clock.Advance(time.Hour + 5*time.Minute)
	result := world.evacuate()
	if result.StagedDroppedCount != 1 || result.StagedWrittenCount != 0 || world.stored(t1Id) {
		t.Fatalf("evacuation's staged decision: %+v, t1 at seg/ %t", result, world.stored(t1Id))
	}
	if result.Swept.CandidateCount != 1 || result.Swept.AbsentCount != 1 || result.Swept.DeletedCount != 0 || result.Swept.FreedByteCount != 0 {
		t.Fatalf("evacuation's sweep of u2's record: %+v", result.Swept)
	}
	world.count -= int64(len(t1))
	world.requireCount("t1 dropped at evacuation")
	taskBatches := world.batchesOf(sidecar.QuotaProducerTaskworker)
	if len(taskBatches) != 1 || len(taskBatches[0].Events) != 1 {
		t.Fatalf("taskworker's batches: %d", len(taskBatches))
	}
	if event := taskBatches[0].Events[0]; event.NetworkId != connect.Id(world.networkId) || event.Meter != sidecar.QuotaMeterEvs ||
		event.StoredByteDelta != -int64(len(t1)) || event.TransferByteCount != 0 {
		t.Fatalf("taskworker's event: %+v", event)
	}
	if got := len(world.batchesOf(sidecar.QuotaProducerEvs)); got != evsBatchCount+1 {
		t.Fatalf("evs sent %d batches since the purge, want u3's record alone", got-evsBatchCount)
	}

	// the batch resent after a lost answer applies nothing, and a second run finds no batch of that minute to report
	if err := world.host.Quota.ReportUsage(world.ctx, taskBatches[0]); err != nil {
		t.Fatal(err)
	}
	world.requireCount("taskworker's batch resent")
	if again := world.evacuate(); again.StagedDroppedCount != 0 || again.Swept.DeletedCount != 0 {
		t.Fatalf("a second evacuation: %+v", again)
	}
	world.requireCount("a second evacuation")
	if got := len(world.batchesOf(sidecar.QuotaProducerTaskworker)); got != 1 {
		t.Fatalf("taskworker applied %d batches", got)
	}

	// the night after: only u3's record is in a batch, nothing is at seg/, and t1's bytes are listed nowhere
	after := world.nightly("the night after")
	if after.SegmentByteCount != 0 || after.BatchRecordByteCount == 0 || u1.recordByteCount <= after.BatchRecordByteCount {
		t.Fatalf("the night after lists %+v", after)
	}
}

// FS-71's observe clause (D-TEST-12): under purge: observe the committing purge and evacuation's sweep delete nothing
// and report nothing, so the replaced content counts; once deletes turn on, the turn-on pass deletes what observe kept
// and reports nothing either, and the night's listing lets it go: the nightly pass catches what only it freed.
func TestFs71QuotaObserveCountsReplacedContentUntilDeletesTurnOn(t *testing.T) {
	world := newFs71QuotaWorld(t, sidecar.Format2Observe)
	x := fsDropPath("x")
	s1 := fsDropSegment("fs71 s1")
	world.upload(s1, 3000)
	xEntry := fs71Entry(1, s1, false)
	world.push(&fs71Push{
		changes:    []*fs71Change{{path: x, entry: xEntry}},
		newObjects: []*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: s1[:], PaddedSize: 4096, UploadDay: 1}},
	})
	world.clock.Advance(time.Minute)
	_, u2Commit := world.remove(x, xEntry, &protocol.EvsPurgeCandidate{SegmentIds: [][]byte{s1[:]}})

	// observe: the purge logs its candidate and deletes nothing
	stats := world.purge(u2Commit)
	if stats.ObservedCount != 1 || stats.DeletedCount != 0 || stats.FreedByteCount != 0 || !world.stored(s1) {
		t.Fatalf("the purge under observe: %+v, s1 stored %t", stats, world.stored(s1))
	}
	if night := world.requireNight("a night under observe"); night.SegmentByteCount != 3000 {
		t.Fatalf("under observe the night lists %+v", night)
	}

	// deletes turn on: the turn-on pass rereads the repo's flagged versions and deletes what observe kept
	world.gate.set(sidecar.Format2On)
	sweep, err := evsservice.NewSweep(world.serviceHost, &evsservice.SweepDeps{Format2: world.gate})
	if err != nil {
		t.Fatal(err)
	}
	batchCount := len(world.host.Quota.Batches())
	swept, err := sweep.TurnOnPass(world.ctx, "meta-1", world.repoId, time.Time{})
	if err != nil || swept.DeletedCount != 1 || swept.FreedByteCount != 3000 || world.stored(s1) {
		t.Fatalf("the turn-on pass: %+v, %v, s1 stored %t", swept, err, world.stored(s1))
	}
	// it reports nothing: the count keeps s1's bytes
	world.requireCount("after the turn-on pass, before the night")
	if got := len(world.host.Quota.Batches()); got != batchCount {
		t.Fatalf("the turn-on pass sent %d batches", got-batchCount)
	}
	// and the night's listing is 3,000 B under it, which the night's write takes off
	night := world.nightly("the night after the turn-on")
	if night.SegmentByteCount != 0 || night.StoredByteCount() != world.count-3000 {
		t.Fatalf("the night after the turn-on lists %+v, the count %d", night, world.count)
	}
}
