package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A repo's committed history across refs on fake clusters, for the drop job's own passes: statements through the
// root's builder, records through the batch writer, heads through HeadStore, committed maps at pmap/ and log pages at
// log/ as a page-out leaves them. Every ref and mode a test names.
type dropWorld struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	cluster  sidecar.BlobCluster
	segment  sidecar.BlobCluster
	settings *EvsSettings
	heads    *HeadStore
	batches  *BatchWriter
	builder  *sidecar.EvsStatementBuilder
	paidCtx  context.Context
	repoId   sidecar.Id
	signerId sidecar.Id
	jobId    sidecar.Id
	refs     map[sidecar.Id]*dropWorldRef
	pushSeq  int
	entrySeq int
}

// One ref of the world: its head, mode, current epoch and each version's statement.
type dropWorldRef struct {
	head       *EvsStoredHead
	mode       protocol.EvsRefMode
	epoch      uint64
	statements [][]byte
}

// One change: a path's write of an entry version spec names, built for its push, or with spec nil its removal.
type dropChange struct {
	path sidecar.EvsTokenPath
	base uint64
	spec *dropEntry
	// the entry version's bytes as committed
	entry []byte
}

// One push the world commits.
type dropPush struct {
	changes    []*dropChange
	newObjects []*sidecar.EvsNewObject
	flags      uint32
	dropBody   []byte
	dropLists  []byte
	// a PATH_EPOCH's
	pathEpoch        uint64
	pathMapSha256    []byte
	mapSourceVersion uint64
	mapSourceChain   []byte
	tailMoves        [][]byte
}

// What an entry version names.
type dropEntry struct {
	version  uint64
	segments [][32]byte
	kind5    [][32]byte
	slots    []sidecar.Id
	inline   bool
}

func newDropWorld(t *testing.T) *dropWorld {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	settings := DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	segment, err := host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := host.Budget.AdmitP1(ctx, "meta-1", connectNetworkId(), sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(grant.Close)
	signerId := testId("drop-signer")
	world := &dropWorld{
		t: t, ctx: ctx, clock: clock, host: host, cluster: cluster, segment: segment, settings: settings,
		heads:   NewHeadStore(clock, host.ClockCheck, host.Redis, settings, sidecar.NewNoopLogger()),
		batches: NewBatchWriter(ctx, clock, host.ClockCheck, host.Blobs, nil, settings, sidecar.NewNoopLogger()),
		builder: sidecar.NewEvsStatementBuilder(func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
			return &bridge.Signed{Body: bytes.Clone(body), SignerId: signerId.Bytes(), Signature: make([]byte, 64), Type: uint32(signedType)}, nil
		}),
		paidCtx: grant.Context(), repoId: testId("drop-repo"), signerId: signerId, jobId: testId("drop-job"),
		refs: map[sidecar.Id]*dropWorldRef{},
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 2,
		NetworkId: testId("network-a").Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(world.paidCtx, RepoKey(world.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	return world
}

// A 32 B id from a label.
func dropTestId(label string) [32]byte {
	return sha256.Sum256([]byte("drop test " + label))
}

// The ref, made in mode on its first use.
func (self *dropWorld) ref(refId sidecar.Id, mode protocol.EvsRefMode) *dropWorldRef {
	ref, ok := self.refs[refId]
	if !ok {
		ref = &dropWorldRef{head: &EvsStoredHead{}, mode: mode, epoch: 1}
		self.refs[refId] = ref
	}
	return ref
}

// An entry version's bytes no push wrote, unique by a push id of its own: what a list may add.
func (self *dropWorld) entry(spec *dropEntry) []byte {
	self.entrySeq += 1
	return self.entryOf(testId(fmt.Sprintf("entry-%d", self.entrySeq)), 0, spec)
}

// The entry version bytes pushId writes on base baseVersion.
func (self *dropWorld) entryOf(pushId sidecar.Id, baseVersion uint64, spec *dropEntry) []byte {
	self.entrySeq += 1
	entry := &protocol.EvsEntryVersion{
		Version: spec.version, PushId: pushId.Bytes(), BaseVersion: baseVersion, Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE),
		PaddedSize: 4096, SealedFields: []byte(fmt.Sprintf("sealed %d", self.entrySeq)), TimeMs: self.clock.Now().UnixMilli(),
	}
	for _, segment := range spec.segments {
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: bytes.Clone(segment[:]), Length: 4096})
	}
	for _, segment := range spec.kind5 {
		entry.Versioning = uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: bytes.Clone(segment[:]),
			Offset: sidecar.EvsKind5SegmentHeaderByteCount, Length: uint32(sidecar.EvsRecordByteCount(4096)),
		})
	}
	if spec.inline {
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline record")})
	}
	for _, slot := range spec.slots {
		entry.SlotIds = append(entry.SlotIds, slot.Bytes())
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// Commits push on the ref at its next version and returns that version.
func (self *dropWorld) commit(refId sidecar.Id, mode protocol.EvsRefMode, push *dropPush) uint64 {
	self.t.Helper()
	ref := self.ref(refId, mode)
	self.pushSeq += 1
	pushId := testId(fmt.Sprintf("drop-push-%d", self.pushSeq))
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
		PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain, Generation: 1, GroupId: testId("group"),
		GenerationCommitment: make([]byte, 32), PathEpoch: epoch, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		SignerSidecarId: self.signerId, ClientId: testId("client"), TimeMs: self.clock.Now().UnixMilli(),
		SealedMetadata: []byte("sealed metadata"), Flags: push.flags, NewObjects: push.newObjects,
		DropBody: push.dropBody, DropLists: push.dropLists, PathMapSha256: push.pathMapSha256,
		MapSourceVersion: push.mapSourceVersion, MapSourceChain: push.mapSourceChain, TailMoves: push.tailMoves,
	}
	changes := slices.Clone(push.changes)
	slices.SortStableFunc(changes, func(a *dropChange, b *dropChange) int { return a.path.Compare(b.path) })
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
	if len(built.Parts) != 0 {
		self.t.Fatal("a test push built in parts")
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
	next := CloneEvsHead(ref.head.Head)
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
	ref.statements = append(ref.statements, built.Statement.Bytes)
	return next.Version
}

// A file write of a file-mode ref: path's version entry, on base.
func (self *dropWorld) write(refId sidecar.Id, path sidecar.EvsTokenPath, base uint64, spec *dropEntry) ([]byte, uint64) {
	self.t.Helper()
	spec.version = base + 1
	change := &dropChange{path: path, base: base, spec: spec}
	version := self.commit(refId, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{changes: []*dropChange{change}})
	return change.entry, version
}

// A move to newPath in epoch from each (epoch, path) source.
func dropMove(newPath sidecar.EvsTokenPath, sources ...*protocol.EvsSourcePath) *protocol.EvsPathMove {
	return &protocol.EvsPathMove{NewTokenPath: newPath.Components(), Sources: sources, SealedName: []byte("sealed name")}
}

// A source path.
func dropSource(epoch uint64, path sidecar.EvsTokenPath) *protocol.EvsSourcePath {
	return &protocol.EvsSourcePath{Epoch: epoch, TokenPath: path.Components()}
}

// Commits a PATH_EPOCH to epoch on refId over a map whose parts hold partMoves (each part's moves sorted), stored at
// pmap/ as the commit leaves them, and tail: the version it commits at.
func (self *dropWorld) pathEpoch(refId sidecar.Id, epoch uint64, partMoves [][]*protocol.EvsPathMove, tail []*protocol.EvsPathMove) uint64 {
	self.t.Helper()
	ref := self.ref(refId, protocol.EvsRefMode_EVS_REF_FILE)
	sourceVersion, sourceChain := ref.head.Version(), bytes.Clone(ref.head.Head.GetChain())
	parts := [][]byte{}
	for i, moves := range partMoves {
		moves = slices.Clone(moves)
		slices.SortFunc(moves, func(a *protocol.EvsPathMove, b *protocol.EvsPathMove) int {
			pathA, _ := sidecar.ParseEvsTokenPath(a.GetNewTokenPath())
			pathB, _ := sidecar.ParseEvsTokenPath(b.GetNewTokenPath())
			return pathA.Compare(pathB)
		})
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
		if _, err := self.cluster.PutIfNoneMatch(self.paidCtx, PathMapKey(self.repoId, refId, epoch, mapSha256, uint32(i+1)), partBytes, nil); err != nil {
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
	return self.commit(refId, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		flags: uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH), pathEpoch: epoch, pathMapSha256: mapSha256,
		mapSourceVersion: sourceVersion, mapSourceChain: sourceChain, tailMoves: tailItems,
	})
}

// A drop path of lineage (newest first) through through at boundary, its map parts mapParts.
func dropPathOf(through uint64, boundary uint32, mapParts []uint32, lineage ...*protocol.EvsSourcePath) *protocol.EvsDropPath {
	return &protocol.EvsDropPath{Lineage: lineage, MapParts: mapParts, ThroughVersion: through, Boundary: boundary}
}

// Commits a DROP of paths, each listing listed's entry versions by hash, on refId; a written path's change writes its
// lineage's newest token path at through_version with a kept head. The drop's covered record, as the table holds it.
func (self *dropWorld) drop(refId sidecar.Id, dropId sidecar.Id, paths []*protocol.EvsDropPath, listed [][][]byte) *DropCovered {
	self.t.Helper()
	hashes := make([][][]byte, len(listed))
	for i, entries := range listed {
		for _, entryBytes := range entries {
			digest := sha256.Sum256(entryBytes)
			hashes[i] = append(hashes[i], digest[:])
		}
	}
	order := make([]int, len(paths))
	for i := range order {
		order[i] = i
	}
	newest := func(path *protocol.EvsDropPath) sidecar.EvsTokenPath {
		tokenPath, _ := sidecar.ParseEvsTokenPath(path.GetLineage()[0].GetTokenPath())
		return tokenPath
	}
	slices.SortStableFunc(order, func(a int, b int) int { return newest(paths[a]).Compare(newest(paths[b])) })
	sortedPaths, sortedHashes := []*protocol.EvsDropPath{}, [][][]byte{}
	for _, i := range order {
		sortedPaths, sortedHashes = append(sortedPaths, paths[i]), append(sortedHashes, hashes[i])
	}
	lists, err := sidecar.EvsBuildDropLists(sortedPaths, sortedHashes)
	if err != nil {
		self.t.Fatal(err)
	}
	history := &protocol.EvsDropHistory{DropId: dropId.Bytes(), Action: 1, NotBeforeMs: self.clock.Now().UnixMilli(), Paths: sortedPaths}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(history)
	if err != nil {
		self.t.Fatal(err)
	}
	push := &dropPush{flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), dropBody: body, dropLists: lists}
	for _, path := range sortedPaths {
		if path.GetBoundary() != evsDropBoundaryWritten {
			continue
		}
		push.changes = append(push.changes, &dropChange{
			path: newest(path), base: path.GetThroughVersion() - 1, spec: &dropEntry{version: path.GetThroughVersion(), inline: true},
		})
	}
	version := self.commit(refId, protocol.EvsRefMode_EVS_REF_FILE, push)
	window, err := EvsHeadWindow(self.refs[refId].head.Head)
	if err != nil {
		self.t.Fatal(err)
	}
	entry := window[len(window)-1]
	return &DropCovered{DropId: dropId, RefId: refId, Version: version, PushId: entry.PushId, Place: entry.Place, SeenMs: self.clock.Now().UnixMilli()}
}

// Pages versions 1 to 63 of refId out of its head into log page 0, as a page-out leaves them.
func (self *dropWorld) pageOutFirstPage(refId sidecar.Id) {
	self.t.Helper()
	ref := self.refs[refId]
	head := ref.head.Head
	if EvsHeadWindowFirstVersion(head) != 1 || head.GetVersion() < EvsLogPageVersionCount {
		self.t.Fatalf("a window from %d to %d", EvsHeadWindowFirstVersion(head), head.GetVersion())
	}
	count := int(EvsLogPageVersionCount - 1)
	page, err := BuildLogPage(self.repoId, refId, 0, sidecar.EvsChainStart(self.repoId, refId), head.GetWindow()[:count*sidecar.EvsWindowEntryByteCount], ref.statements[:count])
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.paidCtx, LogPageKey(self.repoId, refId, 0), page.Bytes, nil); err != nil {
		self.t.Fatal(err)
	}
	next := CloneEvsHead(head)
	next.Window = bytes.Clone(head.GetWindow()[count*sidecar.EvsWindowEntryByteCount:])
	next.WindowBaseChain = page.LastChain[:]
	next.Fence += 1
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, refId, ref.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	ref.head = written
}

// Drop settings whose read pace never waits on the fake clock.
func dropTestSettings() *DropSettings {
	settings := DefaultDropSettings()
	settings.ReadBytesPerSecond = 1000 * 1000 * 1000 * 1000 * 1000
	return settings
}

// A resolve on the world.
func (self *dropWorld) resolver() *DropResolve {
	resolver, err := NewDropResolve(self.host.ServiceHost(), &DropResolveDeps{Settings: dropTestSettings(), EvsSettings: self.settings})
	if err != nil {
		self.t.Fatal(err)
	}
	return resolver
}

// Resolves drops under the world's job.
func (self *dropWorld) resolve(drops ...*DropCovered) *DropResolveResult {
	self.t.Helper()
	result, err := self.resolver().Resolve(self.ctx, &DropResolveRequest{
		Cluster: self.cluster, SegmentCluster: self.segment, RepoId: self.repoId, JobId: self.jobId, Drops: drops,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

// The job's files.
func (self *dropWorld) files(jobId sidecar.Id) *DropFiles {
	return NewDropFiles(self.segment, self.repoId, jobId, dropTestSettings())
}

// The ids of the job's cand files, in cand order.
func (self *dropWorld) candidates(jobId sidecar.Id) []DropScanId {
	self.t.Helper()
	candidates, err := self.files(jobId).Candidates(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	scanIds := []DropScanId{}
	for _, candidate := range candidates {
		scanIds = append(scanIds, candidate.DropScanId)
	}
	return scanIds
}

// The repo's list files.
func (self *dropWorld) listFiles() []*DropListFile {
	self.t.Helper()
	files, _, err := ReadDropListFiles(self.ctx, self.segment, self.repoId, dropTestSettings())
	if err != nil {
		self.t.Fatal(err)
	}
	return files
}

// Sorted scan ids, for comparing sets.
func sortedDropScanIds(scanIds ...DropScanId) []DropScanId {
	sorted := slices.Clone(scanIds)
	slices.SortFunc(sorted, CompareDropScanIds)
	return sorted
}

// The history the resolve tests share: on ref A, x written three times, its first version naming segment s1 and slot
// k1, its second s2 and a kind-5 v5 beside it in another path's versionless version, its third an inline record;
// another ref B's y naming s9. A drop of x through version 4 lists x's three versions.
type dropResolveHistory struct {
	world      *dropWorld
	refA, refB sidecar.Id
	x          sidecar.EvsTokenPath
	xVersions  [][]byte
	s1, s2, s9 [32]byte
	k1         sidecar.Id
}

func newDropResolveHistory(t *testing.T) *dropResolveHistory {
	world := newDropWorld(t)
	history := &dropResolveHistory{
		world: world, refA: testId("ref-a"), refB: testId("ref-b"), x: worldPath("x"),
		s1: dropTestId("s1"), s2: dropTestId("s2"), s9: dropTestId("s9"), k1: testId("slot-k1"),
	}
	first, _ := world.write(history.refA, history.x, 0, &dropEntry{segments: [][32]byte{history.s1}, slots: []sidecar.Id{history.k1}})
	second, _ := world.write(history.refA, history.x, 1, &dropEntry{segments: [][32]byte{history.s2}})
	third, _ := world.write(history.refA, history.x, 2, &dropEntry{inline: true})
	history.xVersions = [][]byte{first, second, third}
	world.write(history.refB, worldPath("y"), 0, &dropEntry{segments: [][32]byte{history.s9}})
	return history
}

// The drop of x's three versions, through 4.
func (self *dropResolveHistory) dropX(dropId sidecar.Id, listed [][]byte) *DropCovered {
	return self.world.drop(self.refA, dropId, []*protocol.EvsDropPath{dropPathOf(4, evsDropBoundaryWritten, nil, dropSource(1, self.x))}, [][][]byte{listed})
}

// §11.13's resolve row: an exact list resolves, and its candidates are every segment id its listed versions' kind-1
// locators name and every slot id, nothing of an inline record and nothing of another ref; the list file holds the
// three listed entry hashes, the inline one flagged, written before the cand file.
func TestDropResolveWritesTheListAndCandFilesOfAnExactList(t *testing.T) {
	history := newDropResolveHistory(t)
	world := history.world
	covered := history.dropX(testId("drop-x"), history.xVersions)
	result := world.resolve(covered)
	if len(result.Mismatch) != 0 {
		t.Fatalf("an exact list refused: %v", result.Mismatch)
	}
	if result.ScanByteCount == 0 {
		t.Fatal("resolve counted no bytes read")
	}
	want := sortedDropScanIds(DropSegmentId(history.s1), DropSegmentId(history.s2), DropSlotId(history.k1))
	if got := world.candidates(world.jobId); !slices.Equal(got, want) {
		t.Fatalf("candidates %x, want %x", got, want)
	}
	files := world.listFiles()
	if len(files) != 1 || len(files[0].Drops) != 1 || files[0].Drops[0].DropId != testId("drop-x") || files[0].Drops[0].Version != covered.Version {
		t.Fatalf("list files %+v", files)
	}
	inline := sha256.Sum256(history.xVersions[2])
	if len(files[0].Rows) != 3 {
		t.Fatalf("%d rows", len(files[0].Rows))
	}
	for _, row := range files[0].Rows {
		if row.Inline != (row.EntrySha256 == inline) {
			t.Fatalf("row %x flagged inline %t", row.EntrySha256[:8], row.Inline)
		}
		if !files[0].MayHold(row.EntrySha256) {
			t.Fatal("the bloom misses a row")
		}
	}
	listObject, err := world.segment.Head(world.ctx, DropFileKey(world.repoId, world.jobId, DropFileList, 0))
	if err != nil {
		t.Fatal(err)
	}
	candObject, err := world.segment.Head(world.ctx, DropFileKey(world.repoId, world.jobId, DropFileCand, 0))
	if err != nil {
		t.Fatal(err)
	}
	if candObject.LastModified.Before(listObject.LastModified) {
		t.Fatal("the cand file went before the list file")
	}
}

// DESIGN-DETAILS 10.5's kill row: resolve run again whole writes byte-equal files, each a 412 on equal bytes.
func TestDropResolveRunAgainWritesEqualBytes(t *testing.T) {
	history := newDropResolveHistory(t)
	world := history.world
	covered := history.dropX(testId("drop-x"), history.xVersions)
	world.resolve(covered)
	before := world.host.Blobs.Dump()
	if result := world.resolve(covered); len(result.Mismatch) != 0 {
		t.Fatalf("the second resolve: %v", result.Mismatch)
	}
	after := world.host.Blobs.Dump()
	for key, value := range before {
		if strings.Contains(key, "dropscan/") && !bytes.Equal(after[key], value) {
			t.Fatalf("%s changed on a second resolve", key)
		}
	}
	if violations := world.host.Blobs.Violations(); len(violations) != 0 {
		t.Fatalf("violations %v", violations)
	}
}

// FS-95's list clause on the job's side: a list missing one version, and one holding a version no history wrote in place
// of one it did, each refused {mismatch} with nothing written for it, its page counting what the list lacks and adds,
// while a covered drop of another ref resolves alone.
func TestDropResolveRefusesAListMissingOrAddingAVersionAlone(t *testing.T) {
	history := newDropResolveHistory(t)
	world := history.world
	lines := []string{}
	missing := history.dropX(testId("drop-missing"), history.xVersions[:2])
	// a list of the right count holding a version no history wrote in place of one it did
	added := history.dropX(testId("drop-added"), append(slices.Clone(history.xVersions[:2]), world.entry(&dropEntry{version: 3})))
	resolver, err := NewDropResolve(world.host.ServiceHost(), &DropResolveDeps{Settings: dropTestSettings(), Log: &capturingLogger{lines: &lines}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(world.ctx, &DropResolveRequest{
		Cluster: world.cluster, SegmentCluster: world.segment, RepoId: world.repoId, JobId: world.jobId, Drops: []*DropCovered{missing, added},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Mismatch) != 2 {
		t.Fatalf("mismatches %v", result.Mismatch)
	}
	if len(world.listFiles()) != 0 || len(world.candidates(world.jobId)) != 0 {
		t.Fatal("a refused drop wrote files")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "lacks 1 versions") || !strings.Contains(joined, "adds 1") {
		t.Fatalf("the page names no count of what the list lacks and adds:\n%s", joined)
	}

	// a drop of y on ref B resolves beside one refused on ref A
	world.jobId = testId("drop-job-2")
	y2, _ := world.write(history.refB, worldPath("y"), 1, &dropEntry{segments: [][32]byte{dropTestId("s10")}})
	good := world.drop(history.refB, testId("drop-y"), []*protocol.EvsDropPath{dropPathOf(3, evsDropBoundaryWritten, nil, dropSource(1, worldPath("y")))},
		[][][]byte{{world.refEntry(history.refB, worldPath("y"), 1), y2}})
	result = world.resolve(missing, good)
	if !slices.Equal(result.Mismatch, []sidecar.Id{missing.DropId}) {
		t.Fatalf("mismatches %v", result.Mismatch)
	}
	if want := sortedDropScanIds(DropSegmentId(history.s9), DropSegmentId(dropTestId("s10"))); !slices.Equal(world.candidates(world.jobId), want) {
		t.Fatalf("candidates %x", world.candidates(world.jobId))
	}
}

// The entry version bytes the ref's history wrote for path at version, read from its record.
func (self *dropWorld) refEntry(refId sidecar.Id, path sidecar.EvsTokenPath, version uint64) []byte {
	self.t.Helper()
	ref := self.refs[refId]
	reader, err := newDropRefReader(self.ctx, self.cluster, self.repoId, refId, ref.head.Head, NewRecordCache(self.settings), NewRecordLocator(self.host.Blobs, nil), NewLogPageCache(self.settings), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	for at := uint64(1); at <= ref.head.Version(); at += 1 {
		entry, _, err := reader.entryAt(at)
		if err != nil {
			self.t.Fatal(err)
		}
		_, payload, err := reader.pushAt(at, entry)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, change := range payload.Changes {
			if !change.TokenPath.Equal(path) || len(change.EntryVersion) == 0 {
				continue
			}
			parsed := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, parsed); err != nil {
				self.t.Fatal(err)
			}
			if parsed.GetVersion() == version {
				return change.EntryVersion
			}
		}
	}
	self.t.Fatalf("no version %d of the path", version)
	return nil
}

// FS-93's link clauses (DESIGN-DETAILS 10.6's drop_resolve_test.go row): x live across a path epoch, its link in the
// committed map's part and, for a path created after the map's source, in the PATH_EPOCH's tail; a link named in the
// wrong part, the tail where the map holds it, a part past the map's, and a lineage entry no map or tail links, each
// refused {mismatch}.
func TestDropResolveChecksEachLinkInItsMapPartOrTail(t *testing.T) {
	x1, w1, late1 := worldPath("x"), worldPath("w"), worldPath("late")
	x2, w2, late2 := worldPath("e2", "x"), worldPath("e2", "w"), worldPath("e2", "late")
	linkedPart := sortedPartOf(w2, x2)
	cases := []struct {
		mapParts []uint32
		older    *protocol.EvsSourcePath
		linked   bool
	}{
		{mapParts: []uint32{linkedPart}, older: dropSource(1, x1), linked: true},
		{mapParts: []uint32{3 - linkedPart}, older: dropSource(1, x1)},
		{mapParts: []uint32{0}, older: dropSource(1, x1)},
		{mapParts: []uint32{7}, older: dropSource(1, x1)},
		{mapParts: []uint32{linkedPart}, older: dropSource(1, late1)},
	}
	for i, c := range cases {
		world := newDropWorld(t)
		refA := testId("ref-a")
		xFirst, _ := world.write(refA, x1, 0, &dropEntry{segments: [][32]byte{dropTestId("x1")}})
		world.write(refA, w1, 0, &dropEntry{segments: [][32]byte{dropTestId("w1")}})
		world.pathEpoch(refA, 2, [][]*protocol.EvsPathMove{{dropMove(w2, dropSource(1, w1))}, {dropMove(x2, dropSource(1, x1))}}, []*protocol.EvsPathMove{dropMove(late2, dropSource(1, late1))})
		xSecond, _ := world.write(refA, x2, 1, &dropEntry{segments: [][32]byte{dropTestId("x2")}})
		covered := world.drop(refA, testId(fmt.Sprintf("drop-%d", i)), []*protocol.EvsDropPath{dropPathOf(3, evsDropBoundaryWritten, c.mapParts, dropSource(2, x2), c.older)},
			[][][]byte{{xFirst, xSecond}})
		result := world.resolve(covered)
		if c.linked != (len(result.Mismatch) == 0) {
			t.Fatalf("case %d, map parts %v: mismatches %v", i, c.mapParts, result.Mismatch)
		}
		if !c.linked {
			continue
		}
		if want := sortedDropScanIds(DropSegmentId(dropTestId("x1")), DropSegmentId(dropTestId("x2"))); !slices.Equal(world.candidates(world.jobId), want) {
			t.Fatalf("candidates %x", world.candidates(world.jobId))
		}
	}
}

// The part, 1 or 2, a two-part map holds b's move in when its parts are a's and b's moves, sorted.
func sortedPartOf(a sidecar.EvsTokenPath, b sidecar.EvsTokenPath) uint32 {
	if a.Compare(b) < 0 {
		return 2
	}
	return 1
}

// §11.13's removed boundary: x removed with the directory holding it, its standing removal one past its last version,
// resolves; a through_version off that removal is refused {mismatch}.
func TestDropResolveTakesADirectorysRemovalAsTheRemovedBoundary(t *testing.T) {
	world := newDropWorld(t)
	refA := testId("ref-a")
	x := worldPath("d", "x")
	first, _ := world.write(refA, x, 0, &dropEntry{segments: [][32]byte{dropTestId("x1")}})
	second, _ := world.write(refA, x, 1, &dropEntry{segments: [][32]byte{dropTestId("x2")}})
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{changes: []*dropChange{{path: worldPath("d"), base: 1}}})
	covered := world.drop(refA, testId("drop-removed"), []*protocol.EvsDropPath{dropPathOf(3, evsDropBoundaryRemoved, nil, dropSource(1, x))}, [][][]byte{{first, second}})
	if result := world.resolve(covered); len(result.Mismatch) != 0 {
		t.Fatalf("a directory's removal refused: %v", result.Mismatch)
	}
	world.jobId = testId("drop-job-off")
	off := world.drop(refA, testId("drop-off"), []*protocol.EvsDropPath{dropPathOf(4, evsDropBoundaryRemoved, nil, dropSource(1, x))}, [][][]byte{{first, second}})
	if result := world.resolve(off); !slices.Equal(result.Mismatch, []sidecar.Id{off.DropId}) {
		t.Fatalf("a removal off through_version: %v", result.Mismatch)
	}
}

// G11 (DESIGN-DETAILS 8.3): candidates come from the listed versions' kind-1 locators and slot ids alone: a listed
// version's kind-5 locator is the purge's, and a repo full of segments no listed version names stays out of them.
func TestDropResolveCandidatesAreTheListedVersionsKind1AndSlotIdsAlone(t *testing.T) {
	world := newDropWorld(t)
	refA := testId("ref-a")
	x := worldPath("x")
	first, _ := world.write(refA, x, 0, &dropEntry{segments: [][32]byte{dropTestId("x1")}, kind5: [][32]byte{dropTestId("v1")}})
	second, _ := world.write(refA, x, 1, &dropEntry{segments: [][32]byte{dropTestId("x2")}})
	for i := range 20 {
		if _, err := world.segment.PutIfNoneMatch(world.paidCtx, SegmentKey(world.repoId, dropTestId(fmt.Sprintf("loose %d", i))), []byte("loose"), nil); err != nil {
			t.Fatal(err)
		}
	}
	covered := world.drop(refA, testId("drop-x"), []*protocol.EvsDropPath{dropPathOf(3, evsDropBoundaryWritten, nil, dropSource(1, x))}, [][][]byte{{first, second}})
	if result := world.resolve(covered); len(result.Mismatch) != 0 {
		t.Fatalf("refused: %v", result.Mismatch)
	}
	if want := sortedDropScanIds(DropSegmentId(dropTestId("x1")), DropSegmentId(dropTestId("x2"))); !slices.Equal(world.candidates(world.jobId), want) {
		t.Fatalf("candidates %x", world.candidates(world.jobId))
	}
}

// G11's trap, held in the source: no drop pass lists seg/, so nothing outside the listed versions' chains is ever a
// candidate (DESIGN-DETAILS 10.7's EVSB-M10-04 note). Each names a segment only by its full key.
func TestDropPassesNeverListSegments(t *testing.T) {
	for _, name := range []string{"drop_resolve.go", "drop_mark.go", "drop_delete.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "segmentKeyPrefix") || strings.Contains(string(source), `"seg/`) {
			t.Fatalf("%s names seg/'s prefix", name)
		}
	}
}

// DESIGN-DETAILS 10.4's preview: a dry run finds each link by searching the committed map's parts and then the tail,
// answers map_parts, linked, the resolved count and list_match, writes its candidates under its own id, writes no list
// file, and hands back the entry hashes it would list.
func TestDropResolvePreviewFindsLinksAndCounts(t *testing.T) {
	world := newDropWorld(t)
	refA := testId("ref-a")
	x1, w1, late1 := worldPath("x"), worldPath("w"), worldPath("late")
	xFirst, _ := world.write(refA, x1, 0, &dropEntry{segments: [][32]byte{dropTestId("x1")}, inline: true})
	world.write(refA, w1, 0, &dropEntry{segments: [][32]byte{dropTestId("w1")}})
	lateFirst, _ := world.write(refA, late1, 0, &dropEntry{segments: [][32]byte{dropTestId("late1")}})
	x2, w2, late2 := worldPath("e2", "x"), worldPath("e2", "w"), worldPath("e2", "late")
	world.pathEpoch(refA, 2, [][]*protocol.EvsPathMove{{dropMove(w2, dropSource(1, w1))}, {dropMove(x2, dropSource(1, x1))}}, []*protocol.EvsPathMove{dropMove(late2, dropSource(1, late1))})
	xSecond, _ := world.write(refA, x2, 1, &dropEntry{segments: [][32]byte{dropTestId("x2")}})
	listed := func(entries ...[]byte) *protocol.EvsDropPath {
		path := dropPathOf(0, evsDropBoundaryWritten, nil)
		hashes := [][]byte{}
		for _, entryBytes := range entries {
			digest := sha256.Sum256(entryBytes)
			hashes = append(hashes, digest[:])
		}
		if _, err := sidecar.EvsBuildDropLists([]*protocol.EvsDropPath{path}, [][][]byte{hashes}); err != nil {
			t.Fatal(err)
		}
		return path
	}
	xPath := listed(xFirst, xSecond)
	xPath.Lineage, xPath.ThroughVersion = []*protocol.EvsSourcePath{dropSource(2, x2), dropSource(1, x1)}, 3
	latePath := listed(lateFirst, world.entry(&dropEntry{version: 1}))
	latePath.Lineage, latePath.ThroughVersion = []*protocol.EvsSourcePath{dropSource(2, late2), dropSource(1, late1)}, 2
	unlinked := listed(xFirst)
	unlinked.Lineage, unlinked.ThroughVersion = []*protocol.EvsSourcePath{dropSource(2, worldPath("e2", "nowhere")), dropSource(1, x1)}, 2
	previewId := testId("preview")
	result, err := world.resolver().Preview(world.ctx, &DropPreviewResolveRequest{
		Cluster: world.cluster, SegmentCluster: world.segment, RepoId: world.repoId, PreviewId: previewId,
		Request: &protocol.EvsDropPreviewRequest{RefId: refA.Bytes(), Paths: []*protocol.EvsDropPath{xPath, latePath, unlinked}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SnapshotVersion != world.refs[refA].head.Version() || len(result.Paths) != 3 {
		t.Fatalf("snapshot %d, %d paths", result.SnapshotVersion, len(result.Paths))
	}
	if got := result.Paths[0]; !got.GetListMatch() || got.GetCount() != 2 || !got.GetLinked() || !slices.Equal(got.GetMapParts(), []uint32{sortedPartOf(w2, x2)}) {
		t.Fatalf("x's answer %v", got)
	}
	if got := result.Paths[1]; got.GetListMatch() || got.GetCount() != 1 || !got.GetLinked() || !slices.Equal(got.GetMapParts(), []uint32{0}) {
		t.Fatalf("late's answer %v", got)
	}
	if got := result.Paths[2]; got.GetLinked() || len(got.GetMapParts()) != 0 {
		t.Fatalf("an unlinked lineage's answer %v", got)
	}
	if result.InlineByteCount == 0 {
		t.Fatal("no inline bytes counted for x's first version")
	}
	if !result.Listed[sha256.Sum256(xFirst)] || !result.Listed[sha256.Sum256(lateFirst)] {
		t.Fatal("the listed entry hashes are not handed back")
	}
	if want := sortedDropScanIds(DropSegmentId(dropTestId("x1")), DropSegmentId(dropTestId("x2")), DropSegmentId(dropTestId("late1"))); !slices.Equal(world.candidates(previewId), want) {
		t.Fatalf("candidates %x", world.candidates(previewId))
	}
	if len(world.listFiles()) != 0 {
		t.Fatal("a dry run wrote a list file")
	}
}

// Resolve reads a ref's history from its log pages as well as its window: the drop of a path written past a page-out.
func TestDropResolveReadsVersionsPagedOutOfTheWindow(t *testing.T) {
	world := newDropWorld(t)
	refA := testId("ref-a")
	x := worldPath("x")
	listed := [][]byte{}
	for base := uint64(0); base < 64; base += 1 {
		entryBytes, _ := world.write(refA, x, base, &dropEntry{segments: [][32]byte{dropTestId(fmt.Sprintf("x%d", base+1))}})
		listed = append(listed, entryBytes)
	}
	world.pageOutFirstPage(refA)
	covered := world.drop(refA, testId("drop-x"), []*protocol.EvsDropPath{dropPathOf(65, evsDropBoundaryWritten, nil, dropSource(1, x))}, [][][]byte{listed})
	if result := world.resolve(covered); len(result.Mismatch) != 0 {
		t.Fatalf("a paged-out history refused: %v", result.Mismatch)
	}
	if got := world.candidates(world.jobId); len(got) != 64 {
		t.Fatalf("%d candidates", len(got))
	}
}

// DESIGN-DETAILS 10.2.9's list file, byte for byte: three drops and 300 rows lay out as the vector pins (the header,
// rows, index of every 128th row, a 10-bit-a-row bloom and the tail), and read back whole.
func TestDropListFileBytesMatchTheVector(t *testing.T) {
	repoId, jobId := testId("vector-repo"), testId("vector-job")
	drops := []*DropListDrop{}
	for i := range 3 {
		drops = append(drops, &DropListDrop{DropId: testId(fmt.Sprintf("vector-drop-%d", i)), RefId: testId("vector-ref"), Version: uint64(10 + i), PushId: testId(fmt.Sprintf("vector-push-%d", i))})
	}
	rows := []DropListRow{}
	for i := range 300 {
		rows = append(rows, DropListRow{EntrySha256: sha256.Sum256([]byte("vector row " + strconv.Itoa(i))), Drop: uint16(i % 3), Inline: i%7 == 0})
	}
	slices.SortFunc(rows, compareDropListRows)
	encoded := EncodeDropListFile(repoId, jobId, 0, drops, rows)
	if want := 48 + 4 + 3*56 + 300*35 + 3*32 + 375 + 8 + 32; len(encoded) != want {
		t.Fatalf("%d bytes, want %d", len(encoded), want)
	}
	digest := sha256.Sum256(encoded)
	if got := hex.EncodeToString(digest[:]); got != dropListFileVector {
		t.Fatalf("the list file's SHA-256 %s, the vector %s", got, dropListFileVector)
	}
	file, err := DecodeDropListFile(encoded, repoId, jobId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(file.Rows, rows) || len(file.Drops) != 3 || len(file.Index) != 3 || file.Index[2] != rows[256].EntrySha256 {
		t.Fatal("the file reads back otherwise")
	}
	for _, row := range rows {
		if !file.MayHold(row.EntrySha256) {
			t.Fatal("the bloom misses a row")
		}
	}
	// a flipped byte breaks the trailer; rows out of order break the layout
	tampered := bytes.Clone(encoded)
	tampered[100] ^= 1
	if _, err := DecodeDropListFile(tampered, repoId, jobId, 0); !errors.Is(err, ErrDropFileInvalid) {
		t.Fatalf("a flipped byte: %v", err)
	}
	swapped := slices.Clone(rows)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if _, err := DecodeDropListFile(EncodeDropListFile(repoId, jobId, 0, drops, swapped), repoId, jobId, 0); !errors.Is(err, ErrDropFileInvalid) {
		t.Fatalf("rows out of order: %v", err)
	}
	if _, err := DecodeDropListFile(encoded, repoId, jobId, 1); !errors.Is(err, ErrDropFileInvalid) {
		t.Fatalf("another sequence's key: %v", err)
	}
}

// The SHA-256 of TestDropListFileBytesMatchTheVector's file.
const dropListFileVector = "86f4d39e3e9def24ac94faf4d570c07c31fdb309cdf88fd106caaef91c82daf4"

// A dropscan/ file of the most rows a job writes reads back: DropFiles.Read is bounded by the settings, not by a
// pidx/ entry's 4 MiB.
func TestDropFilesReadAWholeFileOfTheMostRows(t *testing.T) {
	world := newDropWorld(t)
	settings := dropTestSettings()
	scanIds := make([]DropScanId, settings.FileRowCount)
	for i := range scanIds {
		scanIds[i] = DropSegmentId(dropTestId("bulk " + strconv.Itoa(i)))
	}
	encoded, err := EncodeDropIdFile(DropFileCand, world.repoId, world.jobId, 0, scanIds)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= EvsPidxEntryMaxByteCount {
		t.Fatalf("a file of %d bytes tests nothing", len(encoded))
	}
	files := world.files(world.jobId)
	if err := files.Put(world.ctx, DropFileCand, 0, encoded); err != nil {
		t.Fatal(err)
	}
	file, err := files.Read(world.ctx, DropFileCand, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Ids) != settings.FileRowCount {
		t.Fatalf("%d ids", len(file.Ids))
	}
}
