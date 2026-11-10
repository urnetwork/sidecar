package fault

// FS-60 (§22.8, FI-1; EVSB-M2-11), every clause but the nightly ones, on T2: the hourly evacuation over one repo's
// history on the fake file clusters and one fake clock. The history is written as evs writes it, through the
// formats' own codecs: signed statements, batch records in pb/ batches, heads committed If-Match through HeadStore
// with each push's window entry, and a log page built from the head's oldest versions. A kill is a store request
// that never applies, at the request a schedule names: the run dies there with nothing more written, and the next
// run resumes from the store.
//
// A reader is a fresh RecordLocator at every check, so it finds each record where the store holds it at that
// moment: in its batch, in a parcel or in a pack (FI-1's closure, for the records and log pages evacuation moves).
//
// Here: a run killed after its pack, after its pidx/ entry and before the batch delete, a reader finding every
// record at each step; a pending record on an idle ref fenced, then dropped; a shredded repo's records dropped and
// a deleted repo's kept; a held network's records, a shredding repo's included, packed and nothing deleted; a small
// repo's parcels packed at 7 d with the replacement killed between the pack's entries and the parcel's delete; a
// seal evacuated a run after its parts, each container holding its entry; and a run killed after a container and its
// entries, restarted once a log page has turned 24 h old, moving only what no container holds. The nightly clauses
// are EVSB-M2-12's (fs60_nightly_test.go), and T3's run on the real store is EVSB-M2-17's suite.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One committed or uncommitted push as the world wrote it.
type evacuationPush struct {
	record      *sidecar.EvsBatchRecord
	recordBytes []byte
	place       *protocol.EvsPlace
	statement   *sidecar.EvsStatement
	version     uint64
}

// One repo on meta-1 with one ref, written by hand through evs's codecs.
type evacuationWorld struct {
	t          *testing.T
	ctx        context.Context
	clock      *sidecartest.FakeClock
	host       *sidecartest.FakeHost
	cluster    sidecar.BlobCluster
	heads      *evsservice.HeadStore
	settings   *evsservice.EvacuatorSettings
	networkId  sidecar.Id
	repoKind   protocol.RepoKind
	repoId     sidecar.Id
	refId      sidecar.Id
	signerId   sidecar.Id
	signingKey ed25519.PrivateKey
	pushCount  int
	batchSeq   uint32
	// the chain at each committed version, C_0 first
	chains [][sha256.Size]byte
	// each committed push, by version from 1
	committed []*evacuationPush
}

// An id from a label, the same every run.
func evacuationId(label string) sidecar.Id {
	sum := sha256.Sum256([]byte("fs60 " + label))
	return sidecar.Id(sum[:16])
}

func newEvacuationWorld(t *testing.T) *evacuationWorld {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostSettings := sidecartest.DefaultFakeHostSettings()
	hostSettings.Blobs.MetadataClusterIds = []string{"meta-1"}
	hostSettings.Blobs.Report = func(violation string) { t.Errorf("blobs: %s", violation) }
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, hostSettings)
	sidecartest.RegisterEvsTwins(host.Redis)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("fs60 signer"))
	settings := evsservice.DefaultEvacuatorSettings()
	settings.SpoolDirectory = t.TempDir()
	world := &evacuationWorld{
		t:          t,
		ctx:        ctx,
		clock:      clock,
		host:       host,
		cluster:    cluster,
		heads:      evsservice.NewHeadStore(clock, host.ClockCheck, nil, evsservice.DefaultEvsSettings(), nil),
		settings:   settings,
		networkId:  evacuationId("network"),
		repoKind:   protocol.RepoKind_REPO_KIND_GENERAL,
		repoId:     evacuationId("repo"),
		refId:      evacuationId("ref"),
		signerId:   evacuationId("signer"),
		signingKey: ed25519.NewKeyFromSeed(seed[:]),
	}
	world.chains = [][sha256.Size]byte{sidecar.EvsChainStart(world.repoId, world.refId)}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: world.signerId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(world.repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	world.putRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE)
	return world
}

// repo/ in state, created or replaced.
func (self *evacuationWorld) putRepo(state protocol.EvsRepoState) {
	self.t.Helper()
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: self.repoId.Bytes(), Kind: self.repoKind, State: state, Format: 1, NetworkId: self.networkId.Bytes(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	key := evsservice.RepoKey(self.repoId)
	info, err := self.cluster.Head(self.ctx, key)
	if err == nil {
		_, err = self.cluster.PutIfMatch(self.ctx, key, info.Etag, repoBytes, nil)
	} else {
		_, err = self.cluster.PutIfNoneMatch(self.ctx, key, repoBytes, nil)
	}
	if err != nil {
		self.t.Fatal(err)
	}
}

// The writer's signature over a statement.
func (self *evacuationWorld) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body: bytes.Clone(body), SignerId: self.signerId.Bytes(), Type: uint32(signedType),
		Signature: ed25519.Sign(self.signingKey, bridge.SignedBytes(purpose, signedType, body)),
	}, nil
}

// A one-part push creating one path on the head as it stands, built and signed: its record, not yet written.
func (self *evacuationWorld) build() *evacuationPush {
	self.t.Helper()
	self.pushCount += 1
	baseVersion := uint64(len(self.committed))
	pushId := evacuationId(fmt.Sprintf("push %d", self.pushCount))
	timeMs := self.clock.Now().UnixMilli()
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
		Version: baseVersion + 1, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: timeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
		Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: self.chains[baseVersion],
		Generation: 1, GroupId: evacuationId("group"), GenerationCommitment: bytes.Repeat([]byte{7}, 32), PathEpoch: 1,
		Auth:            &bridge.AuthPin{Version: 1, Chain: bytes.Repeat([]byte{5}, 32)},
		SignerSidecarId: self.signerId, ClientId: evacuationId("client"), TimeMs: timeMs,
		SealedMetadata: []byte("sealed metadata"),
		Changes: []*sidecar.EvsPlannedChange{{
			TokenPath: sidecar.EvsTokenPath{sidecar.EvsToken(evacuationId(fmt.Sprintf("path %d", self.pushCount)))}, EntryVersion: entryBytes,
		}},
	}
	built, err := sidecar.NewEvsStatementBuilder(self.sign).Build(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	return &evacuationPush{
		statement: built.Statement,
		record: &sidecar.EvsBatchRecord{
			Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: self.repoId, RefId: self.refId, PushId: pushId,
			SignerSidecarId: self.signerId, TimeMs: timeMs, Body: sidecar.EvsPushRecordBody(built.Statement.Bytes, built.Payload),
		},
	}
}

// Writes records as one batch in the clock's minute, as an evs process's flush does, and gives their places and
// bytes.
func (self *evacuationWorld) putBatch(records ...*sidecar.EvsBatchRecord) ([]*protocol.EvsPlace, [][]byte) {
	self.t.Helper()
	now := self.clock.Now()
	minute := evsservice.BatchMinute(now)
	self.batchSeq += 1
	writer := sidecar.NewEvsBatchWriter(0xf560, minute, self.batchSeq, now.UnixMilli())
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
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, evsservice.BatchKey(minute, 0xf560, self.batchSeq), batchBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	recordBytes := [][]byte{}
	for _, place := range places {
		recordBytes = append(recordBytes, bytes.Clone(batchBytes[place.GetOffset():place.GetOffset()+place.GetLength()]))
	}
	return places, recordBytes
}

// Step 6 without step 7: the push's record in a batch, and no head naming it.
func (self *evacuationWorld) writeRecord(push *evacuationPush) {
	places, recordBytes := self.putBatch(push.record)
	push.place, push.recordBytes = places[0], recordBytes[0]
}

// The ref's head from the cluster.
func (self *evacuationWorld) head() *evsservice.EvsStoredHead {
	self.t.Helper()
	head, err := self.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		self.t.Fatal(err)
	}
	return head
}

// Step 7: the head's next version, naming the push's statement and the place of its record.
func (self *evacuationWorld) commitHead(push *evacuationPush) {
	self.t.Helper()
	prior := self.head()
	version := prior.Version() + 1
	chain := sidecar.EvsChainNext(self.chains[version-1], push.record.PushId, push.statement.Sha256)
	next := evsservice.CloneEvsHead(prior.Head)
	next.Version = version
	next.Chain = chain[:]
	next.PushId = push.record.PushId.Bytes()
	if len(next.GetWindow()) == 0 {
		next.WindowBaseChain = self.chains[version-1][:]
	}
	entry := sidecar.NewEvsWindowEntry(push.statement.Sha256, push.statement.Push, nil, nil, true, push.place)
	next.Window = append(bytes.Clone(next.GetWindow()), entry.Encode()...)
	if _, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, prior, next); err != nil {
		self.t.Fatal(err)
	}
	push.version = version
	self.chains = append(self.chains, chain)
	self.committed = append(self.committed, push)
}

// One push committed: its record in a batch of its own, then the head.
func (self *evacuationWorld) commit() *evacuationPush {
	self.t.Helper()
	push := self.build()
	self.writeRecord(push)
	self.commitHead(push)
	return push
}

// Pages the head's versions 1 to 63 out to log/0, as step 6's page-out does: the page first, then the head without
// them.
func (self *evacuationWorld) pageOut() {
	self.t.Helper()
	prior := self.head()
	const pageVersionCount = 63
	if prior.Version() < pageVersionCount || evsservice.EvsHeadWindowFirstVersion(prior.Head) != 1 {
		self.t.Fatalf("a head at %d cannot page out page 0", prior.Version())
	}
	window := prior.Head.GetWindow()
	pageWindow := window[:pageVersionCount*sidecar.EvsWindowEntryByteCount]
	statements := [][]byte{}
	for _, push := range self.committed[:pageVersionCount] {
		statements = append(statements, push.statement.Bytes)
	}
	page, err := evsservice.BuildLogPage(self.repoId, self.refId, 0, self.chains[0], pageWindow, statements)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.ctx, evsservice.LogPageKey(self.repoId, self.refId, 0), page.Bytes, nil); err != nil {
		self.t.Fatal(err)
	}
	next := evsservice.CloneEvsHead(prior.Head)
	next.Window = bytes.Clone(window[pageVersionCount*sidecar.EvsWindowEntryByteCount:])
	next.WindowBaseChain = self.chains[pageVersionCount][:]
	next.Fence = prior.Head.GetFence() + 1
	if _, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, prior, next); err != nil {
		self.t.Fatal(err)
	}
}

// One evacuation run on meta-1 by a new evacuator, as a new taskworker run builds one.
func (self *evacuationWorld) run() (*evsservice.EvacuationResult, error) {
	self.t.Helper()
	evacuator, err := evsservice.NewEvacuator(self.host.ServiceHost(), &evsservice.EvacuatorDeps{Settings: self.settings})
	if err != nil {
		self.t.Fatal(err)
	}
	return evacuator.Run(self.ctx, "meta-1")
}

// A run that must end clean.
func (self *evacuationWorld) mustRun() *evsservice.EvacuationResult {
	self.t.Helper()
	result, err := self.run()
	if err != nil {
		self.t.Fatalf("run: %v (%+v)", err, result)
	}
	return result
}

// Kills the next run at its nth request of op under keyPrefix: the request never applies and the run ends there. A
// create is sent once more after a read shows it never landed (sidecar.PutImmutable), so a kill at a PUT fails that
// one too.
func (self *evacuationWorld) killAt(op string, keyPrefix string, nth int) {
	self.t.Helper()
	plan := &sidecartest.FaultPlan{Op: op, KeyPrefix: keyPrefix, Nth: nth, Result: sidecartest.FailBeforeApply}
	if op == sidecartest.FaultOpPut {
		plan.Repeat = 1
	}
	if _, err := self.host.Blobs.Faults().Add(plan); err != nil {
		self.t.Fatal(err)
	}
}

// A run that must die at the armed kill.
func (self *evacuationWorld) killedRun() {
	self.t.Helper()
	if result, err := self.run(); err == nil {
		self.t.Fatalf("the run was not killed: %+v", result)
	}
	if unfired := self.host.Blobs.Faults().Unfired(); len(unfired) != 0 {
		self.t.Fatalf("the kill never fired: %v", unfired)
	}
}

// FI-1 for what evacuation moves: a reader with no cache finds every committed record's bytes as its batch held
// them, wherever the store holds them now.
func (self *evacuationWorld) requireEveryRecord(when string) {
	self.t.Helper()
	locator := evsservice.NewRecordLocator(self.host.Blobs, nil)
	for _, push := range self.committed {
		recordBytes, err := locator.ReadRecord(self.ctx, self.cluster, self.repoId, self.refId, push.place)
		if err != nil {
			self.t.Fatalf("%s: version %d's record: %v", when, push.version, err)
		}
		if !bytes.Equal(recordBytes, push.recordBytes) {
			self.t.Fatalf("%s: version %d's record reads other bytes", when, push.version)
		}
	}
}

// The keys under prefix on a cluster.
func (self *evacuationWorld) keys(clusterId string, prefix string) []string {
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

// Past the 25 h mark of everything written so far.
func (self *evacuationWorld) age() {
	self.clock.Advance(25*time.Hour + 2*time.Minute)
}

// A network-wide hold placed now.
func (self *evacuationWorld) placeHold() {
	self.t.Helper()
	if err := sidecartest.PlaceHold(self.ctx, self.host.Blobs, &sidecar.HoldRecord{
		NetworkId: self.networkId, CaseId: evacuationId("case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: self.clock.Now(), ExpireTime: self.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		self.t.Fatal(err)
	}
}

// Evacuation killed after a pack, then after its pidx/ entry and before the batch delete: a reader at each step
// finds every record, and the run after them leaves one pack, one entry and no batch.
func TestFs60KilledAfterThePackAndBeforeTheBatchDelete(t *testing.T) {
	world := newEvacuationWorld(t)
	world.settings.PackByteCount = 1
	for i := 0; i < 3; i += 1 {
		world.commit()
	}
	world.age()
	world.requireEveryRecord("before any run")

	// the pack lands and the run dies before its pidx/ entry
	world.killAt(sidecartest.FaultOpPut, "pidx/", 1)
	world.killedRun()
	if packs := world.keys("seg-1", "pack/"); len(packs) != 1 {
		t.Fatalf("packs after the first kill: %v", packs)
	}
	if entries := world.keys("meta-1", "pidx/"); len(entries) != 0 {
		t.Fatalf("an entry was written past the kill: %v", entries)
	}
	world.requireEveryRecord("killed after the pack")

	// the entry lands and the run dies before the first batch delete
	world.killAt(sidecartest.FaultOpDelete, "pb/", 1)
	world.killedRun()
	if entries := world.keys("meta-1", "pidx/"); len(entries) != 1 {
		t.Fatalf("entries after the second kill: %v", entries)
	}
	if batches := world.keys("meta-1", "pb/"); len(batches) != 3 {
		t.Fatalf("a batch went past the kill: %v", batches)
	}
	world.requireEveryRecord("killed after the pidx/ entry")

	result := world.mustRun()
	if result.PackCount != 0 || result.BatchDeletedCount != 3 || result.HasBatches {
		t.Fatalf("the run after the kills: %+v", result)
	}
	if packs, entries := world.keys("seg-1", "pack/"), world.keys("meta-1", "pidx/"); len(packs) != 1 || len(entries) != 1 {
		t.Fatalf("packs %v entries %v", packs, entries)
	}
	world.requireEveryRecord("after the batches went")
}

// A pending record on an idle ref is fenced, then dropped: the head's fence rises with fence_ms set and no version
// changes, and the record's batch goes while the committed records beside it are kept.
func TestFs60PendingRecordOnAnIdleRefIsFencedThenDropped(t *testing.T) {
	world := newEvacuationWorld(t)
	world.commit()
	pending := world.build()
	world.writeRecord(pending)
	before := world.head()
	world.age()
	result := world.mustRun()
	if result.FenceCount != 1 || result.DeadCount != 1 || result.KeptCount != 1 || result.HasBatches {
		t.Fatalf("result %+v", result)
	}
	after := world.head()
	if after.Version() != before.Version() || after.Head.GetFence() != before.Head.GetFence()+1 || after.Head.GetFenceMs() != world.clock.Now().UnixMilli() {
		t.Fatalf("the fence wrote version %d, fence %d, fence_ms %d", after.Version(), after.Head.GetFence(), after.Head.GetFenceMs())
	}
	if _, err := evsservice.NewRecordLocator(world.host.Blobs, nil).ReadRecord(world.ctx, world.cluster, world.repoId, world.refId, pending.place); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("the dead record still reads: %v", err)
	}
	world.requireEveryRecord("after the fence")
}

// A shredded repo's records are dropped with nothing written for it, and a deleted, restorable repo's are kept.
func TestFs60ShreddedReposRecordsDroppedAndDeletedReposKept(t *testing.T) {
	for _, state := range []protocol.EvsRepoState{protocol.EvsRepoState_EVS_REPO_SHREDDING, protocol.EvsRepoState_EVS_REPO_SHREDDED} {
		world := newEvacuationWorld(t)
		world.commit()
		world.putRepo(state)
		world.age()
		result := world.mustRun()
		if result.ShreddedCount != 1 || result.KeptCount != 0 || result.HasBatches {
			t.Fatalf("%s: %+v", state, result)
		}
		if written := append(world.keys("meta-1", "hp/"), world.keys("meta-1", "pidx/")...); len(written) != 0 {
			t.Fatalf("%s: objects written for it: %v", state, written)
		}
	}
	world := newEvacuationWorld(t)
	world.commit()
	world.putRepo(protocol.EvsRepoState_EVS_REPO_DELETED)
	world.age()
	if result := world.mustRun(); result.KeptCount != 1 || result.HasBatches {
		t.Fatalf("deleted: %+v", result)
	}
	world.requireEveryRecord("a deleted repo")
}

// A held network's records, a shredding repo's included, are packed and nothing of the repo is deleted: the parcel
// the pack replaced stays with its entry while the hold stands.
func TestFs60HeldNetworksRecordsArePackedAndNotDeleted(t *testing.T) {
	world := newEvacuationWorld(t)
	world.commit()
	world.age()
	if result := world.mustRun(); result.ParcelCount != 1 {
		t.Fatalf("first run %+v", result)
	}
	parcels, parcelEntries := world.keys("meta-1", "hp/"), world.keys("meta-1", "pidx/")
	world.commit()
	world.age()
	world.placeHold()
	world.putRepo(protocol.EvsRepoState_EVS_REPO_SHREDDING)
	world.settings.PackByteCount = 1
	result := world.mustRun()
	if result.KeptCount != 1 || result.PackCount != 1 || result.ReplacedParcelCount != 0 || result.HasBatches {
		t.Fatalf("held run %+v", result)
	}
	if kept := world.keys("meta-1", "hp/"); !slices.Equal(kept, parcels) {
		t.Fatalf("a held repo's parcel was deleted: %v", kept)
	}
	for _, key := range parcelEntries {
		if !slices.Contains(world.keys("meta-1", "pidx/"), key) {
			t.Fatalf("a held repo's entry %s was deleted", key)
		}
	}
	world.requireEveryRecord("under the hold")
}

// A small repo's parcels pack at 7 d. The replacement is killed between the pack's entries and the parcel's delete:
// both stand, readers find every record, taking the pack's entry over the parcel's, and the next run deletes the
// parcel and its entry without packing again.
func TestFs60ParcelsPackAtSevenDaysWithTheReplacementKilled(t *testing.T) {
	world := newEvacuationWorld(t)
	first := world.commit()
	world.age()
	if result := world.mustRun(); result.ParcelCount != 1 || result.PackCount != 0 {
		t.Fatalf("first run %+v", result)
	}
	parcels := world.keys("meta-1", "hp/")
	// a second push late enough that its evacuation comes as the first record nears 7 d
	firstTime := time.Unix(int64(first.place.GetMinute())*60, 0)
	world.clock.AdvanceTo(firstTime.Add(7*24*time.Hour - 26*time.Hour))
	world.commit()
	world.age()

	// the pack and its entry land, and the run dies at the parcel's delete: its entry's DELETE is the first
	world.killAt(sidecartest.FaultOpDelete, "pidx/", 1)
	world.killedRun()
	if packs := world.keys("seg-1", "pack/"); len(packs) != 1 {
		t.Fatalf("packs after the kill: %v", packs)
	}
	if kept := world.keys("meta-1", "hp/"); !slices.Equal(kept, parcels) {
		t.Fatalf("the parcel went past the kill: %v", kept)
	}
	world.requireEveryRecord("the pack and the parcel both standing")

	result := world.mustRun()
	if result.PackCount != 0 || result.ReplacedParcelCount != 1 || result.HasBatches {
		t.Fatalf("the run after the kill: %+v", result)
	}
	if left := world.keys("meta-1", "hp/"); len(left) != 0 {
		t.Fatalf("parcels left: %v", left)
	}
	if entries := world.keys("meta-1", "pidx/"); len(entries) != 1 {
		t.Fatalf("entries left: %v", entries)
	}
	world.requireEveryRecord("after the parcel went")
}

// A seal evacuated a run after its parts: each part is kept at the seal's version in the first run's container, the
// seal in the second's, each container holding its own entry, and a reader finds them all.
func TestFs60SealEvacuatedARunAfterItsParts(t *testing.T) {
	world := newEvacuationWorld(t)
	pushId := evacuationId("parts push")
	timeMs := world.clock.Now().UnixMilli()
	changes := []*sidecar.EvsPlannedChange{}
	// past 1,024 entry writes, so the builder splits the push into parts
	for i := 0; i < 1100; i += 1 {
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
			Version: 1, PushId: pushId.Bytes(), TimeMs: timeMs,
			Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
			Chain: []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")}},
		})
		if err != nil {
			t.Fatal(err)
		}
		changes = append(changes, &sidecar.EvsPlannedChange{
			TokenPath: sidecar.EvsTokenPath{sidecar.EvsToken(evacuationId(fmt.Sprintf("part path %05d", i)))}, EntryVersion: entryBytes,
		})
	}
	built, err := sidecar.NewEvsStatementBuilder(world.sign).Build(&sidecar.EvsPushPlan{
		RepoId: world.repoId, RefId: world.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseChain: world.chains[0],
		Generation: 1, GroupId: evacuationId("group"), GenerationCommitment: bytes.Repeat([]byte{7}, 32), PathEpoch: 1,
		Auth:            &bridge.AuthPin{Version: 1, Chain: bytes.Repeat([]byte{5}, 32)},
		SignerSidecarId: world.signerId, ClientId: evacuationId("client"), TimeMs: timeMs,
		SealedMetadata: []byte("sealed metadata"), Changes: changes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Parts) < 2 {
		t.Fatalf("%d parts, want at least 2", len(built.Parts))
	}
	header := func(recordType protocol.EvsBatchRecordType, body []byte) *sidecar.EvsBatchRecord {
		return &sidecar.EvsBatchRecord{
			Type: recordType, RepoId: world.repoId, RefId: world.refId, PushId: pushId, SignerSidecarId: world.signerId, TimeMs: timeMs, Body: body,
		}
	}
	parts := []*evacuationPush{}
	sealParts := []*sidecar.EvsSealPart{}
	for _, partBytes := range built.Parts {
		part := &protocol.EvsPushPart{}
		if err := proto.Unmarshal(partBytes, part); err != nil {
			t.Fatal(err)
		}
		firstPath, err := sidecar.ParseEvsChangedTokenPath(part.GetChanges()[0].GetTokenPath())
		if err != nil {
			t.Fatal(err)
		}
		places, recordBytes := world.putBatch(header(protocol.EvsBatchRecordType_EVS_BATCH_PART, sidecar.EvsPartRecordBody(built.Statement.Bytes, partBytes, nil, 0)))
		parts = append(parts, &evacuationPush{place: places[0], recordBytes: recordBytes[0], version: 1})
		sealParts = append(sealParts, &sidecar.EvsSealPart{Place: places[0], ChangesRoot: [sha256.Size]byte(part.GetChangesRoot()), FirstTokenPath: firstPath})
	}
	// the seal ten minutes on, in a later minute directory
	world.clock.Advance(10 * time.Minute)
	seal := &evacuationPush{statement: built.Statement, record: header(protocol.EvsBatchRecordType_EVS_BATCH_SEAL, sidecar.EvsSealRecordBody(built.Statement.Bytes, sealParts))}
	world.writeRecord(seal)
	world.commitHead(seal)
	world.committed = append(world.committed, parts...)
	world.requireEveryRecord("before any run")

	// the parts' minute is due and the seal's is not
	world.clock.Advance(24*time.Hour + 52*time.Minute)
	result := world.mustRun()
	if result.KeptCount != len(parts) || !result.HasBatches {
		t.Fatalf("the parts' run %+v", result)
	}
	firstEntries := world.keys("meta-1", "pidx/")
	if len(firstEntries) != 1 {
		t.Fatalf("entries after the parts' run: %v", firstEntries)
	}
	world.requireEveryRecord("parts evacuated, the seal in its batch")

	world.clock.Advance(time.Hour)
	result = world.mustRun()
	if result.KeptCount != 1 || result.HasBatches {
		t.Fatalf("the seal's run %+v", result)
	}
	entries := world.keys("meta-1", "pidx/")
	containers := append(world.keys("meta-1", "hp/"), world.keys("seg-1", "pack/")...)
	if len(entries) != 2 || !slices.Contains(entries, firstEntries[0]) || len(containers) != 2 {
		t.Fatalf("after the seal's run: entries %v, containers %v", entries, containers)
	}
	world.requireEveryRecord("the seal evacuated a run after its parts")
}

// A run killed after a container and its pidx/ entries, restarted once a log page has turned 24 h old, moves only
// what no container holds: the restart's pack holds the log page and the records the first container does not, and
// the first container's records are not written again.
func TestFs60RestartMovesOnlyWhatNoContainerHolds(t *testing.T) {
	world := newEvacuationWorld(t)
	for i := 0; i < 70; i += 1 {
		world.commit()
	}
	// the first run, an hour's minutes later, takes these 70 and dies before its first batch delete
	world.age()
	world.pageOut()
	later := world.commit()
	world.killAt(sidecartest.FaultOpDelete, "pb/", 1)
	world.killedRun()
	firstContainers := world.keys("meta-1", "hp/")
	if len(firstContainers) != 1 || len(world.keys("meta-1", "pidx/")) != 1 {
		t.Fatalf("the killed run left parcels %v", firstContainers)
	}
	world.requireEveryRecord("killed after the container and its entries")

	// a day on the log page has aged and the later push is due: one pack takes them and the parcel's records
	world.age()
	world.settings.PackByteCount = 1
	result := world.mustRun()
	if result.KeptCount != 71 || result.PackCount != 1 || result.PackedLogPageCount != 1 || result.ReplacedParcelCount != 1 || result.HasBatches {
		t.Fatalf("the restart: %+v", result)
	}
	packs := world.keys("seg-1", "pack/")
	if len(packs) != 1 {
		t.Fatalf("packs %v", packs)
	}
	segments, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	object, err := segments.Get(world.ctx, packs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	packBytes := &bytes.Buffer{}
	if _, err := packBytes.ReadFrom(object.Body); err != nil {
		t.Fatal(err)
	}
	_, items, err := evsservice.ParseContainer(packBytes.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	recordCount, pageCount := 0, 0
	for _, item := range items {
		if item.LogPage {
			pageCount += 1
		} else {
			recordCount += 1
		}
	}
	// every record once: the 70 the parcel held and the one no container did
	if recordCount != 71 || pageCount != 1 {
		t.Fatalf("the pack holds %d records and %d log pages", recordCount, pageCount)
	}
	if left := append(world.keys("meta-1", "hp/"), world.keys("meta-1", "log/")...); len(left) != 0 {
		t.Fatalf("replaced objects left: %v", left)
	}
	world.requireEveryRecord("after the restart")
	// the page-out's versions resolve through the packed page: a second copy of an old push is seen as committed
	// elsewhere, with no fence
	world.clock.Advance(time.Minute)
	world.putBatch(world.committed[0].record)
	world.age()
	result = world.mustRun()
	if result.DuplicateCount != 1 || result.FenceCount != 0 || result.HasBatches {
		t.Fatalf("a copy of a paged-out version: %+v", result)
	}
	_ = later
}
