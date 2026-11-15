package dropverify_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"slices"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/evsservice/dropverify"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A synthetic id from a label, so tests read the same every run.
func testId(label string) sidecar.Id {
	var id sidecar.Id
	copy(id[:], fmt.Sprintf("%-16s", label))
	return id
}

// A repo's committed history on fake clusters, written as evs writes it: statements through the root's builder,
// records through evsservice's batch writer, heads through its head store. The test builds with evsservice; verify
// reads with nothing of it.
type verifyWorld struct {
	t        *testing.T
	ctx      context.Context
	host     *sidecartest.FakeHost
	cluster  sidecar.BlobCluster
	segment  sidecar.BlobCluster
	paidCtx  context.Context
	heads    *evsservice.HeadStore
	batches  *evsservice.BatchWriter
	builder  *sidecar.EvsStatementBuilder
	repoId   sidecar.Id
	jobId    sidecar.Id
	signerId sidecar.Id
	refHeads map[sidecar.Id]*evsservice.EvsStoredHead
	pushSeq  int
	entrySeq int
}

func newVerifyWorld(t *testing.T) *verifyWorld {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	settings := evsservice.DefaultEvsSettings()
	settings.BatchFlushDelay = 0
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	segment, err := host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := host.Budget.AdmitP1(ctx, "meta-1", [16]byte(testId("network")), sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(grant.Close)
	signerId := testId("signer")
	return &verifyWorld{
		t: t, ctx: ctx, host: host, cluster: cluster, segment: segment, paidCtx: grant.Context(),
		heads:   evsservice.NewHeadStore(clock, host.ClockCheck, host.Redis, settings, sidecar.NewNoopLogger()),
		batches: evsservice.NewBatchWriter(ctx, clock, host.ClockCheck, host.Blobs, nil, settings, sidecar.NewNoopLogger()),
		builder: sidecar.NewEvsStatementBuilder(func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
			return &bridge.Signed{Body: bytes.Clone(body), SignerId: signerId.Bytes(), Signature: make([]byte, 64), Type: uint32(signedType)}, nil
		}),
		repoId: testId("verify-repo"), jobId: testId("verify-job"), signerId: signerId,
		refHeads: map[sidecar.Id]*evsservice.EvsStoredHead{},
	}
}

// A file version naming segments by kind-1 locators and slots, its bytes its own as a push id makes each version's.
func (self *verifyWorld) entryVersion(version uint64, segments [][32]byte, slots []sidecar.Id) []byte {
	self.entrySeq += 1
	entry := &protocol.EvsEntryVersion{
		Version: version, PushId: testId(fmt.Sprintf("entry-%d", self.entrySeq)).Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE),
		PaddedSize: 4096, SealedFields: []byte(fmt.Sprintf("sealed %d", version)),
	}
	for _, segment := range segments {
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: bytes.Clone(segment[:]), Length: 4096})
	}
	for _, slot := range slots {
		entry.SlotIds = append(entry.SlotIds, slot.Bytes())
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// One change of a push: a path and its entry version's bytes, or a DROP body for a cancel.
type verifyChange struct {
	path         string
	base         uint64
	entryVersion []byte
}

// Commits a push on refId: its changes, its git-mode new objects and its flags and DROP body.
func (self *verifyWorld) commit(refId sidecar.Id, mode protocol.EvsRefMode, changes []*verifyChange, newObjects []*sidecar.EvsNewObject, flags uint32, dropBody []byte) uint64 {
	self.pushSeq += 1
	pushId := testId(fmt.Sprintf("push-%d", self.pushSeq))
	head := self.refHeads[refId]
	if head == nil {
		head = &evsservice.EvsStoredHead{}
	}
	baseVersion := head.Version()
	baseChain := sidecar.EvsChainStart(self.repoId, refId)
	if !head.Absent() {
		baseChain = [32]byte(head.Head.GetChain())
	}
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: mode,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain, Generation: 1, GroupId: testId("group"),
		GenerationCommitment: make([]byte, 32), PathEpoch: 1, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		SignerSidecarId: self.signerId, ClientId: testId("client"), TimeMs: sidecartest.DefaultClockStart().UnixMilli(),
		SealedMetadata: []byte("sealed metadata"), NewObjects: newObjects, Flags: flags, DropBody: dropBody,
	}
	changedPaths := []sidecar.EvsTokenPath{}
	for _, change := range changes {
		path := sidecar.EvsTokenPath{sidecar.EvsToken(testId("token-" + change.path))}
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: path, BaseEntryVersion: change.base, EntryVersion: change.entryVersion})
		changedPaths = append(changedPaths, path)
	}
	build := self.builder.Build
	if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) != 0 {
		build = self.builder.BuildFormat2
	}
	built, err := build(plan)
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
	windowEntry := sidecar.NewEvsWindowEntry(built.Statement.Sha256, built.Statement.Push, changedPaths, nil, false, place)
	next := evsservice.CloneEvsHead(head.Head)
	if head.Absent() {
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
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, refId, head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	self.refHeads[refId] = written
	return next.Version
}

// The job's cand file and its mark file, as resolve and mark write them.
func (self *verifyWorld) writeCandidates(candidates []evsservice.DropScanId, marks []evsservice.DropScanId) {
	files := evsservice.NewDropFiles(self.segment, self.repoId, self.jobId, evsservice.DefaultDropSettings())
	cand, err := evsservice.EncodeDropIdFile(evsservice.DropFileCand, self.repoId, self.jobId, 0, candidates)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := files.Put(self.ctx, evsservice.DropFileCand, 0, cand); err != nil {
		self.t.Fatal(err)
	}
	if err := files.Put(self.ctx, evsservice.DropFileMark, 0, evsservice.EncodeDropMarkFile(self.repoId, self.jobId, 0, sidecar.Id{}, 0, marks)); err != nil {
		self.t.Fatal(err)
	}
}

// A list file as DESIGN-DETAILS 10.2.9 lays it out, written as resolve (EVSB-M10-04) will: its drops, its rows by entry
// hash, an index of every 128th row, a bloom of 10 bits a row and its tail.
func (self *verifyWorld) writeListFile(dropIds []sidecar.Id, listed map[int][][]byte) {
	type row struct {
		entrySha256 [32]byte
		drop        uint16
	}
	rows := []row{}
	for dropIndex, entryVersions := range listed {
		for _, entryBytes := range entryVersions {
			rows = append(rows, row{entrySha256: sha256.Sum256(entryBytes), drop: uint16(dropIndex)})
		}
	}
	slices.SortFunc(rows, func(a row, b row) int {
		if c := bytes.Compare(a.entrySha256[:], b.entrySha256[:]); c != 0 {
			return c
		}
		return int(a.drop) - int(b.drop)
	})
	encoded := []byte("URds")
	encoded = append(encoded, 1, 3, 0, 0)
	encoded = append(encoded, self.repoId[:]...)
	encoded = append(encoded, self.jobId[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, 0)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(rows)))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(dropIds)))
	encoded = append(encoded, 0, 0)
	for _, dropId := range dropIds {
		encoded = append(encoded, dropId[:]...)
		encoded = append(encoded, testId("ref").Bytes()...)
		encoded = binary.BigEndian.AppendUint64(encoded, 9)
		encoded = append(encoded, testId("drop push").Bytes()...)
	}
	for _, row := range rows {
		encoded = append(encoded, row.entrySha256[:]...)
		encoded = binary.BigEndian.AppendUint16(encoded, row.drop)
		encoded = append(encoded, 0)
	}
	indexOffset := len(encoded)
	for i := 0; i < len(rows); i += 128 {
		encoded = append(encoded, rows[i].entrySha256[:]...)
	}
	bloomOffset := len(encoded)
	bloom := make([]byte, (len(rows)*10+7)/8)
	bitCount := uint64(len(bloom) * 8)
	for _, row := range rows {
		a, b := binary.BigEndian.Uint64(row.entrySha256[0:8]), binary.BigEndian.Uint64(row.entrySha256[8:16])
		for i := range uint64(7) {
			bit := (a + i*b) % max(1, bitCount)
			bloom[bit/8] |= 1 << (bit % 8)
		}
	}
	encoded = append(encoded, bloom...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(indexOffset))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(bloomOffset))
	trailer := sha256.Sum256(encoded)
	encoded = append(encoded, trailer[:]...)
	key := evsservice.DropFileKey(self.repoId, self.jobId, evsservice.DropFileList, 0)
	if _, err := self.segment.PutIfNoneMatch(self.ctx, key, encoded, nil); err != nil {
		self.t.Fatal(err)
	}
}

// A verify of round 1 over the world's job, the covered drop executed.
func (self *verifyWorld) verify(marked map[sidecar.Id]uint64, since map[sidecar.Id]uint64, drops []*dropverify.Drop, executed map[sidecar.Id]bool, locked bool) *dropverify.Result {
	result, err := dropverify.Verify(self.ctx, &dropverify.Request{
		Cluster: self.cluster, SegmentCluster: self.segment, RepoId: self.repoId, JobId: self.jobId, Round: 1,
		Marked: marked, Since: since, Drops: drops,
		Executed:     func(dropId sidecar.Id) bool { return executed[dropId] },
		LockStanding: func(ctx context.Context) (bool, error) { return locked, nil },
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

// The history most cases share: on ref A, X written naming s1 and slot k1, then replaced naming s2; on ref B, Y naming
// s3. The drop lists X's first version, so its candidates are s1 and k1.
type verifyHistory struct {
	world     *verifyWorld
	refA      sidecar.Id
	refB      sidecar.Id
	s1, s2    [32]byte
	s3        [32]byte
	k1        sidecar.Id
	listedX   []byte
	candidate []evsservice.DropScanId
	dropId    sidecar.Id
}

func newVerifyHistory(t *testing.T) *verifyHistory {
	world := newVerifyWorld(t)
	history := &verifyHistory{
		world: world, refA: testId("ref-a"), refB: testId("ref-b"),
		s1: [32]byte{1}, s2: [32]byte{2}, s3: [32]byte{3}, k1: testId("slot-k1"), dropId: testId("drop-1"),
	}
	history.listedX = world.entryVersion(1, [][32]byte{history.s1}, []sidecar.Id{history.k1})
	world.commit(history.refA, protocol.EvsRefMode_EVS_REF_FILE, []*verifyChange{{path: "x", entryVersion: history.listedX}}, nil, 0, nil)
	world.commit(history.refA, protocol.EvsRefMode_EVS_REF_FILE, []*verifyChange{{path: "x", base: 1, entryVersion: world.entryVersion(2, [][32]byte{history.s2}, nil)}}, nil, 0, nil)
	world.commit(history.refB, protocol.EvsRefMode_EVS_REF_FILE, []*verifyChange{{path: "y", entryVersion: world.entryVersion(1, [][32]byte{history.s3}, nil)}}, nil, 0, nil)
	history.candidate = []evsservice.DropScanId{evsservice.DropSegmentId(history.s1), evsservice.DropSlotId(history.k1)}
	world.writeListFile([]sidecar.Id{history.dropId}, map[int][][]byte{0: {history.listedX}})
	return history
}

// FS-96's clause: an honest mark and the oracle agree, the listed version marking nothing, and observe records the same
// D; V_r is each head's version.
func TestVerifyAgreesWithAnHonestMark(t *testing.T) {
	history := newVerifyHistory(t)
	history.world.writeCandidates(history.candidate, nil)
	drops := []*dropverify.Drop{{DropId: history.dropId, RefId: history.refA, Version: 2}}
	result := history.world.verify(map[sidecar.Id]uint64{history.refA: 2, history.refB: 1}, nil, drops, map[sidecar.Id]bool{history.dropId: true}, false)
	if result.Disagree || len(result.LateMarks) != 0 || result.Locked || len(result.Cancelled) != 0 {
		t.Fatalf("an honest mark disagreed: %+v", result)
	}
	if result.Snapshot[history.refA] != 2 || result.Snapshot[history.refB] != 1 || result.ScanByteCount == 0 {
		t.Fatalf("the snapshot: %+v", result)
	}
	// the listed version is live while its drop has not executed: then it names its own candidates
	result = history.world.verify(map[sidecar.Id]uint64{history.refA: 2, history.refB: 1}, nil, drops, map[sidecar.Id]bool{}, false)
	if !result.Disagree {
		t.Fatal("a version of a drop not executed marked nothing")
	}
}

// A seeded mark bug: a live version on another ref names a candidate below M, which mark left unmarked; verify refuses
// {verify}.
func TestVerifyRefusesASeededMarkBug(t *testing.T) {
	history := newVerifyHistory(t)
	world := history.world
	world.commit(history.refB, protocol.EvsRefMode_EVS_REF_FILE, []*verifyChange{{path: "z", entryVersion: world.entryVersion(1, [][32]byte{history.s1}, nil)}}, nil, 0, nil)
	world.writeCandidates(history.candidate, nil)
	drops := []*dropverify.Drop{{DropId: history.dropId, RefId: history.refA, Version: 2}}
	result := world.verify(map[sidecar.Id]uint64{history.refA: 2, history.refB: 2}, nil, drops, map[sidecar.Id]bool{history.dropId: true}, false)
	if !result.Disagree || result.Detail == "" {
		t.Fatalf("a seeded mark bug passed: %+v", result)
	}
	// the honest mark, which marked s1, agrees
	world.jobId = testId("verify-job-2")
	world.writeListFile([]sidecar.Id{history.dropId}, map[int][][]byte{0: {history.listedX}})
	world.writeCandidates(history.candidate, []evsservice.DropScanId{evsservice.DropSegmentId(history.s1)})
	if result := world.verify(map[sidecar.Id]uint64{history.refA: 2, history.refB: 2}, nil, drops, map[sidecar.Id]bool{history.dropId: true}, false); result.Disagree {
		t.Fatalf("the honest mark disagreed: %s", result.Detail)
	}
}

// FS-91 (e): a version that came to name a candidate after mark's snapshot, a re-upload adopted, is marked and kept, a
// late mark, and the slot a live version names is found as a slot.
func TestVerifyMarksAHitAboveMark(t *testing.T) {
	history := newVerifyHistory(t)
	world := history.world
	world.commit(history.refB, protocol.EvsRefMode_EVS_REF_FILE, []*verifyChange{{path: "w", entryVersion: world.entryVersion(1, [][32]byte{history.s1}, []sidecar.Id{history.k1})}}, nil, 0, nil)
	world.writeCandidates(history.candidate, nil)
	drops := []*dropverify.Drop{{DropId: history.dropId, RefId: history.refA, Version: 2}}
	result := world.verify(map[sidecar.Id]uint64{history.refA: 2, history.refB: 1}, nil, drops, map[sidecar.Id]bool{history.dropId: true}, false)
	if result.Disagree || len(result.LateMarks) != 2 {
		t.Fatalf("a hit above mark: %+v", result)
	}
	kinds := []uint8{result.LateMarks[0].Kind, result.LateMarks[1].Kind}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []uint8{dropverify.IdKindSegment, dropverify.IdKindSlot}) {
		t.Fatalf("late marks of kinds %v", kinds)
	}
	// a later round reads only versions after the earlier round's V
	result = world.verify(map[sidecar.Id]uint64{history.refA: 2, history.refB: 1}, map[sidecar.Id]uint64{history.refA: 2, history.refB: 2}, drops, map[sidecar.Id]bool{history.dropId: true}, false)
	if len(result.LateMarks) != 0 || result.Disagree {
		t.Fatalf("round 2 read below its V_1: %+v", result)
	}
}

// G11 (DESIGN-DETAILS 8.3): a git-mode push's history segments are named by its new-objects list and nothing else, so
// verify counts them; a mark that skipped them (DropJobTwin-MarkSkipsHistory) is refused.
func TestVerifyCountsAGitPushsHistorySegments(t *testing.T) {
	history := newVerifyHistory(t)
	world := history.world
	refG := testId("ref-git")
	world.commit(refG, protocol.EvsRefMode_EVS_REF_GIT, []*verifyChange{{path: "g", entryVersion: world.entryVersion(1, [][32]byte{{9}}, nil)}},
		[]*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: bytes.Clone(history.s1[:]), PaddedSize: 4096, UploadDay: 20000}}, 0, nil)
	world.writeCandidates(history.candidate, nil)
	drops := []*dropverify.Drop{{DropId: history.dropId, RefId: history.refA, Version: 2}}
	result := world.verify(map[sidecar.Id]uint64{history.refA: 2, history.refB: 1, refG: 1}, nil, drops, map[sidecar.Id]bool{history.dropId: true}, false)
	if !result.Disagree {
		t.Fatal("a git-mode push's history segment went uncounted")
	}
}

// Verify rereads each covered drop's ref for a cancel and the repo for a lock (§11.13's verify row).
func TestVerifyFindsACancelAndALock(t *testing.T) {
	history := newVerifyHistory(t)
	world := history.world
	body, err := proto.Marshal(&protocol.EvsDropHistory{
		DropId: testId("cancel").Bytes(), Action: 2, CancelsDropId: history.dropId.Bytes(), CancelsVersion: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	world.commit(history.refA, protocol.EvsRefMode_EVS_REF_FILE, nil, nil, uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), body)
	world.writeCandidates(history.candidate, nil)
	drops := []*dropverify.Drop{{DropId: history.dropId, RefId: history.refA, Version: 2}}
	result := world.verify(map[sidecar.Id]uint64{history.refA: 3, history.refB: 1}, nil, drops, map[sidecar.Id]bool{history.dropId: true}, true)
	if len(result.Cancelled) != 1 || result.Cancelled[0] != history.dropId || !result.Locked {
		t.Fatalf("the cancel and the lock: %+v", result)
	}
}

// Records evacuated to a container are read through pidx/, and versions paged out of the head through log pages: a ref
// of 65 versions whose page 0 left the window and whose records went to a parcel, version 2 naming the candidate.
func TestVerifyReadsEvacuatedRecordsAndLogPages(t *testing.T) {
	world := newVerifyWorld(t)
	refC := testId("ref-c")
	s1 := [32]byte{1}
	for version := uint64(1); version <= 65; version += 1 {
		segments := [][32]byte{{byte(100 + version%100), byte(version)}}
		if version == 2 {
			segments = [][32]byte{s1}
		}
		base := version - 1
		world.commit(refC, protocol.EvsRefMode_EVS_REF_FILE, []*verifyChange{{path: "c", base: base, entryVersion: world.entryVersion(version, segments, nil)}}, nil, 0, nil)
	}
	world.writeCandidates([]evsservice.DropScanId{evsservice.DropSegmentId(s1)}, nil)
	head := world.refHeads[refC].Head
	window, err := sidecar.DecodeEvsWindow(head.GetWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(window) != 65 {
		t.Fatalf("a window of %d", len(window))
	}
	// versions 1 to 63 go to log page 0 and out of the window, their batches' records into a parcel
	pageEntries := window[:63]
	statements := [][]byte{}
	records := []*evsservice.ContainerRecord{}
	batchKeys := map[string]bool{}
	for i, entry := range pageEntries {
		recordBytes := world.recordBytesAt(entry.Place)
		record, err := sidecar.ParseEvsBatchRecord(recordBytes)
		if err != nil {
			t.Fatal(err)
		}
		statement, _, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			t.Fatal(err)
		}
		statements = append(statements, statement)
		records = append(records, &evsservice.ContainerRecord{RefId: refC, Version: uint64(i + 1), Place: entry.Place, Bytes: recordBytes})
		batchKeys[evsservice.PlaceBatchKey(entry.Place)] = true
	}
	for _, entry := range window[63:] {
		if batchKeys[evsservice.PlaceBatchKey(entry.Place)] {
			t.Skip("the batch writer put a kept version beside paged ones; this case needs one batch each")
		}
	}
	pageWindow := head.GetWindow()[:63*sidecar.EvsWindowEntryByteCount]
	page, err := evsservice.BuildLogPage(world.repoId, refC, 0, sidecar.EvsChainStart(world.repoId, refC), pageWindow, statements)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cluster.PutIfNoneMatch(world.paidCtx, evsservice.LogPageKey(world.repoId, refC, 0), page.Bytes, nil); err != nil {
		t.Fatal(err)
	}
	container, err := evsservice.BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PARCEL, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := evsservice.WriteContainer(world.paidCtx, world.host.Blobs, world.cluster, world.repoId, container); err != nil {
		t.Fatal(err)
	}
	for batchKey := range batchKeys {
		if err := world.cluster.Delete(world.paidCtx, batchKey); err != nil {
			t.Fatal(err)
		}
	}
	next := evsservice.CloneEvsHead(head)
	next.Window = bytes.Clone(head.GetWindow()[63*sidecar.EvsWindowEntryByteCount:])
	next.WindowBaseChain = page.LastChain[:]
	next.Fence += 1
	written, err := world.heads.Commit(world.ctx, world.cluster, world.repoId, refC, world.refHeads[refC], next)
	if err != nil {
		t.Fatal(err)
	}
	world.refHeads[refC] = written
	result := world.verify(map[sidecar.Id]uint64{refC: 65}, nil, nil, map[sidecar.Id]bool{}, false)
	if !result.Disagree {
		t.Fatalf("a hit in an evacuated record behind a log page went unfound: %+v", result)
	}
	// with the candidate marked, the same scan agrees: every version read
	world.jobId = testId("verify-job-2")
	world.writeCandidates([]evsservice.DropScanId{evsservice.DropSegmentId(s1)}, []evsservice.DropScanId{evsservice.DropSegmentId(s1)})
	if result := world.verify(map[sidecar.Id]uint64{refC: 65}, nil, nil, map[sidecar.Id]bool{}, false); result.Disagree || result.Snapshot[refC] != 65 {
		t.Fatalf("the marked scan: %+v", result)
	}
}

// The record bytes at place, from its batch, as the batch writer left them.
func (self *verifyWorld) recordBytesAt(place *protocol.EvsPlace) []byte {
	object, err := self.cluster.GetRange(self.ctx, evsservice.PlaceBatchKey(place), int64(place.GetOffset()), int64(place.GetLength()))
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	recordBytes := make([]byte, place.GetLength())
	if _, err := io.ReadFull(object.Body, recordBytes); err != nil {
		self.t.Fatal(err)
	}
	return recordBytes
}

// DESIGN-DETAILS 10.6's dropverify row: verify shares no scan code with mark, an import check. Its non-test files import
// nothing of evsservice, only std, the root, protocol and protobuf.
func TestVerifySharesNoScanCodeWithMark(t *testing.T) {
	allowed := map[string]bool{
		"github.com/urnetwork/sidecar":          true,
		"github.com/urnetwork/sidecar/protocol": true,
		"google.golang.org/protobuf/proto":      true,
	}
	fileSet := token.NewFileSet()
	packages, err := parser.ParseDir(fileSet, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for name, pkg := range packages {
		if name != "dropverify" {
			continue
		}
		for fileName, file := range pkg.Files {
			for _, spec := range file.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.ContainsRune([]byte(path), '.') && !allowed[path] {
					t.Errorf("%s imports %s", fileName, path)
				}
				checked += 1
			}
		}
	}
	if checked == 0 {
		t.Fatal("no import was checked")
	}
}
