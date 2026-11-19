package fault

// The drop rows' T2 world (FS-90, FS-92, FS-93, FS-96; EVSB-M10-04, EVSB-M10-06): a repo's committed history across
// refs on fake clusters, written as evs writes it, each kind-1 segment and slot its versions name stored, and a drop
// job over the real resolve, mark, verify (dropverify, injected as taskworker injects it) and deletes. DROP pushes are
// committed by hand and reach the table through DropSink as step 8 appends them, since the DROP push route is
// EVS2-M10-09's. newFsDropWorldOn builds the same world on a Net's stores, so the FI oracles read it (TEST-M10-01):
// every request through the Net's blob recorder, the repo placed, the Net's gates admitting its network to format 2
// with both modes on, and the job's horizon the nightly pass's own, read from the store.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/evsservice/dropverify"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One ref: its head, mode and current epoch.
type fsDropRef struct {
	head  *evsservice.EvsStoredHead
	mode  protocol.EvsRefMode
	epoch uint64
}

// What an entry version names; a nil spec in a change removes its path.
type fsDropEntry struct {
	version  uint64
	segments [][32]byte
	slots    []sidecar.Id
	inline   bool
}

// One change of a push.
type fsDropChange struct {
	path sidecar.EvsTokenPath
	base uint64
	spec *fsDropEntry
	// the entry version's bytes as committed
	entry []byte
}

// One push.
type fsDropPush struct {
	changes          []*fsDropChange
	newObjects       []*sidecar.EvsNewObject
	flags            uint32
	dropBody         []byte
	dropLists        []byte
	pathEpoch        uint64
	pathMapSha256    []byte
	mapSourceVersion uint64
	mapSourceChain   []byte
	tailMoves        [][]byte
}

// The horizon a schedule sets.
type fsDropHorizon struct {
	horizon time.Time
}

func (self *fsDropHorizon) OrphanHorizon(ctx context.Context, cluster sidecar.BlobCluster) (time.Time, error) {
	return self.horizon, nil
}

// The drop mode a schedule sets.
type fsDropFormat2 struct {
	mode sidecar.Format2Mode
}

func (self *fsDropFormat2) Admits(networkId sidecar.Id) bool { return true }
func (self *fsDropFormat2) PurgeMode() sidecar.Format2Mode   { return sidecar.Format2Observe }
func (self *fsDropFormat2) DropMode() sidecar.Format2Mode    { return self.mode }

// No lock stands.
type fsDropNoLock struct{}

func (self fsDropNoLock) LockStanding(networkId sidecar.Id, repoId sidecar.Id) (bool, evsservice.EvsAuthAnswer) {
	return false, evsservice.EvsAuthAllowed
}

// dropverify.Verify behind evsservice.DropVerifier, as taskworker injects it.
type fsDropVerifier struct{}

func (self fsDropVerifier) Verify(ctx context.Context, request *evsservice.DropVerifyRequest) (*evsservice.DropVerifyResult, error) {
	drops := make([]*dropverify.Drop, 0, len(request.Drops))
	for _, drop := range request.Drops {
		drops = append(drops, &dropverify.Drop{DropId: drop.DropId, RefId: drop.RefId, Version: drop.Version})
	}
	result, err := dropverify.Verify(ctx, &dropverify.Request{
		Cluster: request.Cluster, SegmentCluster: request.SegmentCluster, RepoId: request.RepoId, JobId: request.JobId,
		Round: request.Round, Marked: request.Marked, Since: request.Since, Drops: drops,
		Executed: request.Liveness.Executed, LockStanding: request.LockStanding, Pace: request.Pace,
	})
	if err != nil {
		return nil, err
	}
	lateMarks := make([]evsservice.DropScanId, 0, len(result.LateMarks))
	for _, id := range result.LateMarks {
		lateMarks = append(lateMarks, evsservice.DropScanId{Id: id.Id, Kind: evsservice.DropIdKind(id.Kind)})
	}
	return &evsservice.DropVerifyResult{
		Snapshot: result.Snapshot, Disagree: result.Disagree, Detail: result.Detail, LateMarks: lateMarks,
		Cancelled: result.Cancelled, Locked: result.Locked, ScanByteCount: result.ScanByteCount,
	}, nil
}

// The world.
type fsDropWorld struct {
	t            *testing.T
	ctx          context.Context
	clock        *sidecartest.FakeClock
	host         *sidecartest.FakeHost
	cluster      sidecar.BlobCluster
	segment      sidecar.BlobCluster
	settings     *evsservice.EvsSettings
	dropSettings *evsservice.DropSettings
	heads        *evsservice.HeadStore
	batches      *evsservice.BatchWriter
	builder      *sidecar.EvsStatementBuilder
	paidCtx      context.Context
	repoId       sidecar.Id
	networkId    sidecar.Id
	signerId     sidecar.Id
	refs         map[sidecar.Id]*fsDropRef
	horizon      *fsDropHorizon
	format2      *fsDropFormat2
	pushSeq      int
	entrySeq     int
	// what engines run on: the fake host's own, or a Net's, whose Blobs record every request
	serviceHost *sidecar.ServiceHost
	// the Net it was built on, nil for its own fakes
	net *Net
	// the job's horizon read from the store, nil for the schedule's own (horizon)
	storeHorizon evsservice.DropHorizonSource
}

func newFsDropWorld(t *testing.T) *fsDropWorld {
	return newFsDropWorldOn(t, nil)
}

// See the file header: on net's stores, or on fakes of its own when net is nil.
func newFsDropWorldOn(t *testing.T, net *Net) *fsDropWorld {
	ctx := t.Context()
	var clock *sidecartest.FakeClock
	var host *sidecartest.FakeHost
	var serviceHost *sidecar.ServiceHost
	if net == nil {
		clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
		host = sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
		serviceHost = host.ServiceHost()
	} else {
		clock, host, serviceHost = net.Clock(), net.Fakes(), net.Host()
	}
	sidecartest.RegisterEvsTwins(host.Redis)
	settings := evsservice.DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	cluster, err := serviceHost.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	segment, err := serviceHost.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := host.Budget.AdmitP1(ctx, "meta-1", [16]byte{0x9d}, sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(grant.Close)
	dropSettings := evsservice.DefaultDropSettings()
	// the schedules move the clock themselves: no read pace or DELETE rate waits on it
	dropSettings.ReadBytesPerSecond = 1000 * 1000 * 1000 * 1000 * 1000
	dropSettings.DeletesPerSecond = 1000 * 1000
	signerId := fsDropId16("signer")
	world := &fsDropWorld{
		t: t, ctx: ctx, clock: clock, host: host, cluster: cluster, segment: segment, settings: settings, dropSettings: dropSettings,
		heads:   evsservice.NewHeadStore(clock, host.ClockCheck, host.Redis, settings, sidecar.NewNoopLogger()),
		batches: evsservice.NewBatchWriter(ctx, clock, host.ClockCheck, serviceHost.Blobs, nil, settings, sidecar.NewNoopLogger()),
		builder: sidecar.NewEvsStatementBuilder(func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
			return &bridge.Signed{Body: bytes.Clone(body), SignerId: signerId.Bytes(), Signature: make([]byte, 64), Type: uint32(signedType)}, nil
		}),
		paidCtx: grant.Context(), repoId: fsDropId16("repo"), networkId: fsDropId16("network"), signerId: signerId,
		refs: map[sidecar.Id]*fsDropRef{}, horizon: &fsDropHorizon{}, format2: &fsDropFormat2{mode: sidecar.Format2On},
		serviceHost: serviceHost, net: net,
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 2,
		NetworkId: world.networkId.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(world.paidCtx, evsservice.RepoKey(world.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	if net != nil {
		// placed, as the oracle's walk finds a repo, and admitted to format 2 with both modes on, as the oracle reads
		// the modes from the Net's gates
		placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: cluster.ClusterId(), CreatorSidecarId: signerId}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		first, err := serviceHost.Blobs.FirstCluster()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.PutIfNoneMatch(world.paidCtx, sidecar.EvsPlaceKey(world.repoId), placeBytes, nil); err != nil {
			t.Fatal(err)
		}
		network := connect.Id(world.networkId).String()
		gates := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: {enabled: true, networks: [%q], percent: 0, purge: \"on\", drop: \"on\"}\n", network, network)
		if err := host.Gates.Set(gates); err != nil {
			t.Fatal(err)
		}
		nightly, err := evsservice.NewNightlyPass(serviceHost, &evsservice.NightlyPassDeps{})
		if err != nil {
			t.Fatal(err)
		}
		world.storeHorizon = nightly
	}
	return world
}

// A 16 B id from a label.
func fsDropId16(label string) sidecar.Id {
	digest := sha256.Sum256([]byte("fs drop id " + label))
	return sidecar.Id(digest[:16])
}

// A 32 B segment id from a label.
func fsDropSegment(label string) [32]byte {
	return sha256.Sum256([]byte("fs drop segment " + label))
}

// A token path from labels.
func fsDropPath(labels ...string) sidecar.EvsTokenPath {
	tokenPath := sidecar.EvsTokenPath{}
	for _, label := range labels {
		tokenPath = append(tokenPath, sidecar.EvsToken(fsDropId16("token "+label)))
	}
	return tokenPath
}

// A source path.
func fsDropSource(epoch uint64, path sidecar.EvsTokenPath) *protocol.EvsSourcePath {
	return &protocol.EvsSourcePath{Epoch: epoch, TokenPath: path.Components()}
}

// A move to newPath from sources.
func fsDropMove(newPath sidecar.EvsTokenPath, sources ...*protocol.EvsSourcePath) *protocol.EvsPathMove {
	return &protocol.EvsPathMove{NewTokenPath: newPath.Components(), Sources: sources, SealedName: []byte("sealed name")}
}

// Stores segment id, of byteCount bytes, unless it is stored.
func (self *fsDropWorld) storeSegment(id [32]byte, byteCount int) {
	_, err := self.segment.PutIfNoneMatch(self.paidCtx, evsservice.SegmentKey(self.repoId, id), make([]byte, byteCount), nil)
	if err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
		self.t.Fatal(err)
	}
}

// Whether segment id is stored.
func (self *fsDropWorld) stored(id [32]byte) bool {
	_, err := self.segment.Head(self.ctx, evsservice.SegmentKey(self.repoId, id))
	if err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
		self.t.Fatal(err)
	}
	return err == nil
}

// Whether slot id is stored.
func (self *fsDropWorld) slotStored(slotId sidecar.Id) bool {
	_, err := self.cluster.Head(self.ctx, evsservice.SlotKey(self.repoId, slotId))
	if err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
		self.t.Fatal(err)
	}
	return err == nil
}

// The entry version bytes pushId writes on baseVersion, each kind-1 segment and slot it names stored (segments of
// 1,000 B).
func (self *fsDropWorld) entryOf(pushId sidecar.Id, baseVersion uint64, spec *fsDropEntry) []byte {
	self.entrySeq += 1
	entry := &protocol.EvsEntryVersion{
		Version: spec.version, PushId: pushId.Bytes(), BaseVersion: baseVersion, Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE),
		PaddedSize: 4096, SealedFields: []byte(fmt.Sprintf("sealed %d", self.entrySeq)), TimeMs: self.clock.Now().UnixMilli(),
	}
	for _, segment := range spec.segments {
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: bytes.Clone(segment[:]), Length: 4096})
		self.storeSegment(segment, 1000)
	}
	if spec.inline {
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")})
	}
	for _, slot := range spec.slots {
		entry.SlotIds = append(entry.SlotIds, slot.Bytes())
		_, err := self.cluster.PutIfNoneMatch(self.paidCtx, evsservice.SlotKey(self.repoId, slot), []byte("slot"), nil)
		if err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
			self.t.Fatal(err)
		}
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// Commits push on refId at its next version.
func (self *fsDropWorld) commit(refId sidecar.Id, mode protocol.EvsRefMode, push *fsDropPush) uint64 {
	self.t.Helper()
	ref, ok := self.refs[refId]
	if !ok {
		ref = &fsDropRef{head: &evsservice.EvsStoredHead{}, mode: mode, epoch: 1}
		self.refs[refId] = ref
	}
	self.pushSeq += 1
	pushId := fsDropId16(fmt.Sprintf("push %d", self.pushSeq))
	baseVersion := ref.head.Version()
	baseChain := sidecar.EvsChainStart(self.repoId, refId)
	if !ref.head.Absent() && 0 < baseVersion {
		baseChain = [32]byte(ref.head.Head.GetChain())
	}
	epoch := ref.epoch
	if push.pathEpoch != 0 {
		epoch = push.pathEpoch
	}
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: mode,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain, Generation: 1, GroupId: fsDropId16("group"),
		GenerationCommitment: make([]byte, 32), PathEpoch: epoch, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		SignerSidecarId: self.signerId, ClientId: fsDropId16("client"), TimeMs: self.clock.Now().UnixMilli(),
		SealedMetadata: []byte("sealed metadata"), Flags: push.flags, NewObjects: push.newObjects, DropBody: push.dropBody,
		DropLists: push.dropLists, PathMapSha256: push.pathMapSha256, MapSourceVersion: push.mapSourceVersion,
		MapSourceChain: push.mapSourceChain, TailMoves: push.tailMoves,
	}
	changes := slices.Clone(push.changes)
	slices.SortStableFunc(changes, func(a *fsDropChange, b *fsDropChange) int { return a.path.Compare(b.path) })
	changedPaths := []sidecar.EvsTokenPath{}
	createsPath := false
	for _, change := range changes {
		if change.spec != nil {
			change.entry = self.entryOf(pushId, baseVersion, change.spec)
		}
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: change.path, BaseEntryVersion: change.base, EntryVersion: change.entry})
		changedPaths = append(changedPaths, change.path)
		createsPath = createsPath || (change.base == 0 && change.entry != nil)
	}
	built, err := self.builder.BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: self.repoId, RefId: refId, PushId: pushId,
		SignerSidecarId: self.signerId, TimeMs: plan.TimeMs, Body: sidecar.EvsPushRecordBody(built.Statement.Bytes, built.Payload),
	}
	place, err := self.batches.Append(self.paidCtx, "meta-1", record)
	if err != nil {
		self.t.Fatal(err)
	}
	var coveringPrefixes []sidecar.EvsTokenPath
	if len(built.Statement.Push.GetChangesRoot()) != 0 {
		coveringPrefixes = built.Statement.ChangedPrefixes
	}
	windowEntry := sidecar.NewEvsWindowEntry(built.Statement.Sha256, built.Statement.Push, changedPaths, coveringPrefixes, createsPath, place)
	next := evsservice.CloneEvsHead(ref.head.Head)
	if ref.head.Absent() {
		next = &protocol.EvsHead{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED), RefMode: uint32(mode),
			PathEpoch: &protocol.EvsPathEpoch{Current: 1}, WindowBaseChain: baseChain[:],
		}
	}
	chain := sidecar.EvsChainNext(baseChain, pushId, built.Statement.Sha256)
	next.Version = baseVersion + 1
	next.Chain = chain[:]
	next.PushId = pushId.Bytes()
	next.Window = append(bytes.Clone(next.GetWindow()), windowEntry.Encode()...)
	if push.flags&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		next.PathEpoch = &protocol.EvsPathEpoch{Current: push.pathEpoch, Sources: []*protocol.EvsEpochSource{{Epoch: ref.epoch, MapSha256: push.pathMapSha256}}}
		ref.epoch = push.pathEpoch
	}
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, refId, ref.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	ref.head = written
	return next.Version
}

// One file write on a file-mode ref: the entry version's bytes.
func (self *fsDropWorld) write(refId sidecar.Id, path sidecar.EvsTokenPath, base uint64, spec *fsDropEntry) []byte {
	self.t.Helper()
	spec.version = base + 1
	change := &fsDropChange{path: path, base: base, spec: spec}
	self.commit(refId, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{changes: []*fsDropChange{change}})
	return change.entry
}

// Commits a PATH_EPOCH to epoch on refId over a map of partMoves' parts and tail.
func (self *fsDropWorld) pathEpoch(refId sidecar.Id, epoch uint64, partMoves [][]*protocol.EvsPathMove, tail []*protocol.EvsPathMove) {
	self.t.Helper()
	ref := self.refs[refId]
	sourceVersion, sourceChain := ref.head.Version(), bytes.Clone(ref.head.Head.GetChain())
	moveOrder := func(a *protocol.EvsPathMove, b *protocol.EvsPathMove) int {
		pathA, _ := sidecar.ParseEvsTokenPath(a.GetNewTokenPath())
		pathB, _ := sidecar.ParseEvsTokenPath(b.GetNewTokenPath())
		return pathA.Compare(pathB)
	}
	// runs ascending by new token path within and across parts (DESIGN-DETAILS 9.2.2)
	sortedParts := [][]*protocol.EvsPathMove{}
	for _, moves := range partMoves {
		moves = slices.Clone(moves)
		slices.SortFunc(moves, moveOrder)
		sortedParts = append(sortedParts, moves)
	}
	slices.SortStableFunc(sortedParts, func(a []*protocol.EvsPathMove, b []*protocol.EvsPathMove) int { return moveOrder(a[0], b[0]) })
	parts := [][]byte{}
	for i, moves := range sortedParts {
		body, err := proto.Marshal(&protocol.EvsPathMap{
			RepoId: self.repoId.Bytes(), RefId: refId.Bytes(), PathEpoch: epoch, Part: uint32(i + 1), Parts: uint32(len(partMoves)),
			Moves: moves, SourceVersion: sourceVersion, SourceChain: sourceChain,
		})
		if err != nil {
			self.t.Fatal(err)
		}
		partBytes, err := proto.Marshal(&bridge.Signed{Body: body, SignerId: self.signerId.Bytes(), Signature: make([]byte, 64), Type: uint32(bridge.SignedType_SIGNED_EVS_PATH_MAP)})
		if err != nil {
			self.t.Fatal(err)
		}
		parts = append(parts, partBytes)
	}
	mapSha256 := sidecar.EvsPathMapSha256(parts)
	for i, partBytes := range parts {
		if _, err := self.cluster.PutIfNoneMatch(self.paidCtx, evsservice.PathMapKey(self.repoId, refId, epoch, mapSha256, uint32(i+1)), partBytes, nil); err != nil {
			self.t.Fatal(err)
		}
	}
	tailItems := [][]byte{}
	for _, move := range tail {
		item, err := proto.Marshal(move)
		if err != nil {
			self.t.Fatal(err)
		}
		tailItems = append(tailItems, item)
	}
	self.commit(refId, protocol.EvsRefMode_EVS_REF_FILE, &fsDropPush{
		flags: uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH), pathEpoch: epoch, pathMapSha256: mapSha256,
		mapSourceVersion: sourceVersion, mapSourceChain: sourceChain, tailMoves: tailItems,
	})
}

// A drop path of lineage (newest first) through through at boundary, its map parts mapParts.
func fsDropPathOf(through uint64, boundary uint32, mapParts []uint32, lineage ...*protocol.EvsSourcePath) *protocol.EvsDropPath {
	return &protocol.EvsDropPath{Lineage: lineage, MapParts: mapParts, ThroughVersion: through, Boundary: boundary}
}

// Commits a DROP of paths, each listing listed's entry versions, now (not_before_ms its time_ms), and appends it to the
// table as step 8 would, seen_ms the clock after its commit.
func (self *fsDropWorld) drop(refId sidecar.Id, dropId sidecar.Id, paths []*protocol.EvsDropPath, listed [][][]byte) {
	self.t.Helper()
	newest := func(path *protocol.EvsDropPath) sidecar.EvsTokenPath {
		tokenPath, _ := sidecar.ParseEvsTokenPath(path.GetLineage()[0].GetTokenPath())
		return tokenPath
	}
	order := make([]int, len(paths))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a int, b int) int { return newest(paths[a]).Compare(newest(paths[b])) })
	sortedPaths, hashes := []*protocol.EvsDropPath{}, [][][]byte{}
	for _, i := range order {
		sortedPaths = append(sortedPaths, paths[i])
		pathHashes := [][]byte{}
		for _, entryBytes := range listed[i] {
			digest := sha256.Sum256(entryBytes)
			pathHashes = append(pathHashes, digest[:])
		}
		hashes = append(hashes, pathHashes)
	}
	lists, err := sidecar.EvsBuildDropLists(sortedPaths, hashes)
	if err != nil {
		self.t.Fatal(err)
	}
	history := &protocol.EvsDropHistory{DropId: dropId.Bytes(), Action: 1, NotBeforeMs: self.clock.Now().UnixMilli(), Paths: sortedPaths}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(history)
	if err != nil {
		self.t.Fatal(err)
	}
	push := &fsDropPush{flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), dropBody: body, dropLists: lists}
	for _, path := range sortedPaths {
		if path.GetBoundary() == 1 {
			push.changes = append(push.changes, &fsDropChange{path: newest(path), base: path.GetThroughVersion() - 1, spec: &fsDropEntry{version: path.GetThroughVersion(), inline: true}})
		}
	}
	version := self.commit(refId, protocol.EvsRefMode_EVS_REF_FILE, push)
	window, err := evsservice.EvsHeadWindow(self.refs[refId].head.Head)
	if err != nil {
		self.t.Fatal(err)
	}
	entry := window[len(window)-1]
	table, err := evsservice.NewDropTable(self.serviceHost, evsservice.NewBudgetedBlobs(self.serviceHost.Blobs), self.dropSettings, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := table.Append(self.paidCtx, &evsservice.DropCommit{
		ClusterId: "meta-1", RepoId: self.repoId, RefId: refId, PushId: entry.PushId, Version: version, Place: entry.Place, Body: history,
	}, self.clock.Now().UnixMilli()); err != nil {
		self.t.Fatal(err)
	}
}

// A drop job instance over the real seams.
func (self *fsDropWorld) job(instance string) *evsservice.DropJob {
	self.t.Helper()
	host := self.serviceHost
	resolver, err := evsservice.NewDropResolve(host, &evsservice.DropResolveDeps{Settings: self.dropSettings, EvsSettings: self.settings})
	if err != nil {
		self.t.Fatal(err)
	}
	marker, err := evsservice.NewDropMark(host, &evsservice.DropMarkDeps{Settings: self.dropSettings, EvsSettings: self.settings})
	if err != nil {
		self.t.Fatal(err)
	}
	deleter, err := evsservice.NewDropDelete(host, &evsservice.DropDeleteDeps{Format2: self.format2, Settings: self.dropSettings, EvsSettings: self.settings})
	if err != nil {
		self.t.Fatal(err)
	}
	return self.jobWith(instance, resolver, marker, fsDropVerifier{}, deleter)
}

// A drop job instance over the seams given.
func (self *fsDropWorld) jobWith(instance string, resolver evsservice.DropResolver, marker evsservice.DropMarker, verifier evsservice.DropVerifier, deleter evsservice.DropDeleter) *evsservice.DropJob {
	self.t.Helper()
	var horizon evsservice.DropHorizonSource = self.horizon
	if self.storeHorizon != nil {
		horizon = self.storeHorizon
	}
	job, err := evsservice.NewDropJob(self.serviceHost, &evsservice.DropJobDeps{
		Resolver: resolver, Marker: marker, Verifier: verifier, Deleter: deleter, Locks: fsDropNoLock{}, Horizon: horizon,
		Format2: self.format2, Settings: self.dropSettings, EvsSettings: self.settings, Instance: fsDropId16("instance " + instance),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return job
}

// The segment cluster's capacity known and well under the pause line, as §19.6's hdd loop publishes it.
func (self *fsDropWorld) hddKnown() {
	figures, err := json.Marshal(&evsservice.HddFigures{ClusterId: "seg-1", TimeMs: self.clock.Now().UnixMilli(), DriveOpsPerSecond: 10, CapacityOps: 1000})
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.host.Redis.HashSet(self.ctx, "{nvb_seg-1}", map[string][]byte{"hdd": figures}); err != nil {
		self.t.Fatal(err)
	}
}

// One run of job.
func (self *fsDropWorld) run(job *evsservice.DropJob) (*evsservice.DropJobResult, error) {
	self.hddKnown()
	return job.Run(self.ctx, "meta-1", self.repoId)
}

// Moves the clock past every drop's start and the horizon to the clock, so a job runs through.
func (self *fsDropWorld) ripen(by time.Duration) {
	self.clock.Advance(by)
	self.horizon.horizon = self.clock.Now()
}

// Runs job until it ends or asks for nothing, moving the clock to each wake it asks for, at most runCount runs.
func (self *fsDropWorld) runToEnd(job *evsservice.DropJob, runCount int) *evsservice.DropJobResult {
	self.t.Helper()
	var result *evsservice.DropJobResult
	for range runCount {
		var err error
		result, err = self.run(job)
		if err != nil {
			self.t.Fatal(err)
		}
		if result.Ended || result.Next.IsZero() {
			return result
		}
		if wait := result.Next.Sub(self.clock.Now()); 0 < wait {
			self.ripen(wait)
		}
	}
	return result
}

// The table's state of dropId.
func (self *fsDropWorld) dropState(dropId sidecar.Id) evsservice.DropState {
	self.t.Helper()
	table, err := evsservice.NewDropTable(self.serviceHost, evsservice.NewBudgetedBlobs(self.serviceHost.Blobs), self.dropSettings, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	read, err := table.Read(self.ctx, self.cluster, self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	if entry := read.State.Drop(dropId); entry != nil {
		return entry.State
	}
	if void := read.State.Void(dropId); void != nil {
		return void.State
	}
	return 0
}
