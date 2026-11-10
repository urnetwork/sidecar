package evsservice

// EVSB-M10-02's recompute of a marked purge list on T2, over hand-built format-2 history, since no format-2 push
// commits before EVS2-M10-06: the replaced versions found by a write's prev_commit_version, by the path's folded
// entry and by the walk back; every id a version of u's push names kept, a rename's target in another part included;
// a path whose version is not found keeping its content; evacuation recomputing a marked list at the record's version.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A ref of format-2 pushes built by hand on the evacuate fixture's repo, committed in the order added: each record in
// a batch of its own and its window entry in a head written by hand, as step 7 would leave them.
type recomputeRef struct {
	fixture *evacuateFixture
	seq     uint32
	entries []*sidecar.EvsWindowEntry
	// by version, from 1
	records []*sidecar.EvsBatchRecord
	tails   []*sidecar.EvsBatchRecordTail
	places  []*protocol.EvsPlace
	pushIds []sidecar.Id
	etag    string
}

func newRecomputeRef(fixture *evacuateFixture) *recomputeRef {
	return &recomputeRef{fixture: fixture, seq: 0x5e00}
}

// One record in a batch of its own at the clock's minute, its tail carried: its place.
func (self *recomputeRef) putRecord(record *sidecar.EvsBatchRecord, tail *sidecar.EvsBatchRecordTail) *protocol.EvsPlace {
	fixture := self.fixture
	fixture.t.Helper()
	now := fixture.clock.Now()
	self.seq += 1
	writer := sidecar.NewEvsBatchWriter(0x7e57, BatchMinute(now), self.seq, now.UnixMilli())
	place, err := writer.AddFormat2(record, tail)
	if err != nil {
		fixture.t.Fatal(err)
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		fixture.t.Fatal(err)
	}
	if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, BatchKey(BatchMinute(now), 0x7e57, self.seq), batchBytes, nil); err != nil {
		fixture.t.Fatal(err)
	}
	return place
}

// The tail of a record listing list, nil for none.
func recomputeTestTail(t *testing.T, list *protocol.EvsPurgeList) *sidecar.EvsBatchRecordTail {
	if list == nil {
		return nil
	}
	listBytes, err := sidecar.EncodeEvsPurgeList(list)
	if err != nil {
		t.Fatal(err)
	}
	return &sidecar.EvsBatchRecordTail{PurgeList: listBytes}
}

// The head over every push added, written over the last.
func (self *recomputeRef) writeHead() {
	fixture := self.fixture
	fixture.t.Helper()
	window := []byte{}
	for _, entry := range self.entries {
		window = append(window, entry.Encode()...)
	}
	chain := sha256.Sum256([]byte(fmt.Sprintf("recompute chain %d", len(self.entries))))
	head := &protocol.EvsHead{
		Version: uint64(len(self.entries)), Chain: chain[:], PushId: self.pushIds[len(self.pushIds)-1].Bytes(),
		RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED), RefMode: uint32(protocol.EvsRefMode_EVS_REF_FILE),
		Window: window, WindowBaseChain: make([]byte, 32),
	}
	headBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(head)
	if err != nil {
		fixture.t.Fatal(err)
	}
	key := HeadKey(fixture.check.repoId, fixture.check.refId)
	if self.etag == "" {
		self.etag, err = fixture.cluster.PutIfNoneMatch(fixture.ctx, key, headBytes, nil)
	} else {
		self.etag, err = fixture.cluster.PutIfMatch(fixture.ctx, key, self.etag, headBytes, nil)
	}
	if err != nil {
		fixture.t.Fatal(err)
	}
}

// A one-part format-2 push at the next version, its changes from changes given its plan, its record listing list:
// its version.
func (self *recomputeRef) push(changes func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange, list *protocol.EvsPurgeList) uint64 {
	fixture := self.fixture
	fixture.t.Helper()
	plan := fixture.check.plan()
	plan.TimeMs = fixture.clock.Now().UnixMilli()
	plan.BaseVersion = uint64(len(self.entries))
	plan.Changes = changes(plan)
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.signingKey, fixture.check.signerId)).BuildFormat2(plan)
	if err != nil {
		fixture.t.Fatal(err)
	}
	if len(built.Parts) != 0 {
		fixture.t.Fatal("a one-part push built in parts")
	}
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: plan.RepoId, RefId: plan.RefId, PushId: plan.PushId,
		SignerSidecarId: fixture.check.signerId, TimeMs: plan.TimeMs,
		Body: sidecar.EvsPushRecordBody(built.Statement.Bytes, built.Payload),
	}
	tail := recomputeTestTail(fixture.t, list)
	place := self.putRecord(record, tail)
	self.add(built, plan, record, tail, place, list != nil)
	return uint64(len(self.entries))
}

// A sealed format-2 push at the next version: its parts' records, each listing partLists[i] (nil for none), and its
// seal's: its version and the parts' records.
func (self *recomputeRef) sealed(plan *sidecar.EvsPushPlan, partLists func(part int, changes []*sidecar.EvsCheckedChange) *protocol.EvsPurgeList) (uint64, []*sidecar.EvsBatchRecord, []*sidecar.EvsBatchRecordTail) {
	fixture := self.fixture
	fixture.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.signingKey, fixture.check.signerId)).BuildFormat2(plan)
	if err != nil {
		fixture.t.Fatal(err)
	}
	if len(built.Parts) < 2 {
		fixture.t.Fatalf("a push of %d changes built in %d parts", len(plan.Changes), len(built.Parts))
	}
	sealParts := []*sidecar.EvsSealPart{}
	partRecords := []*sidecar.EvsBatchRecord{}
	partTails := []*sidecar.EvsBatchRecordTail{}
	anyListed := false
	for i, partBytes := range built.Parts {
		checked, err := sidecar.EvsCheckStoredPart(built.Statement, partBytes)
		if err != nil {
			fixture.t.Fatal(err)
		}
		record := &sidecar.EvsBatchRecord{
			Type: protocol.EvsBatchRecordType_EVS_BATCH_PART, RepoId: plan.RepoId, RefId: plan.RefId, PushId: plan.PushId,
			SignerSidecarId: fixture.check.signerId, TimeMs: plan.TimeMs,
			Body: sidecar.EvsPartRecordBody(built.Statement.Bytes, partBytes, nil, plan.BaseVersion),
		}
		list := partLists(i, checked.Changes)
		anyListed = anyListed || list != nil
		tail := recomputeTestTail(fixture.t, list)
		place := self.putRecord(record, tail)
		partRecords = append(partRecords, record)
		partTails = append(partTails, tail)
		sealParts = append(sealParts, &sidecar.EvsSealPart{Place: place, ChangesRoot: checked.Root, FirstTokenPath: checked.Changes[0].TokenPath})
	}
	seal := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_SEAL, RepoId: plan.RepoId, RefId: plan.RefId, PushId: plan.PushId,
		SignerSidecarId: fixture.check.signerId, TimeMs: plan.TimeMs,
		Body: sidecar.EvsSealRecordBody(built.Statement.Bytes, sealParts),
	}
	place := self.putRecord(seal, nil)
	self.add(built, plan, seal, nil, place, anyListed)
	return uint64(len(self.entries)), partRecords, partTails
}

func (self *recomputeRef) add(built *sidecar.EvsBuiltPush, plan *sidecar.EvsPushPlan, record *sidecar.EvsBatchRecord, tail *sidecar.EvsBatchRecordTail, place *protocol.EvsPlace, replaces bool) {
	paths := []sidecar.EvsTokenPath{}
	for _, change := range plan.Changes {
		paths = append(paths, change.TokenPath)
	}
	entry := sidecar.NewEvsWindowEntry(built.Statement.Sha256, built.Statement.Push, paths, nil, true, place)
	if replaces {
		entry.SetReplacesVersionless()
	}
	self.entries = append(self.entries, entry)
	self.records = append(self.records, record)
	self.tails = append(self.tails, tail)
	self.places = append(self.places, place)
	self.pushIds = append(self.pushIds, plan.PushId)
	self.writeHead()
}

// The sweep's target for the record at version.
func (self *recomputeRef) target(version uint64, record *sidecar.EvsBatchRecord, list *protocol.EvsPurgeList) *SweepTarget {
	fixture := self.fixture
	return &SweepTarget{
		RepoId: fixture.check.repoId, RefId: fixture.check.refId,
		Repo:      &protocol.EvsRepoObject{RepoId: fixture.check.repoId.Bytes(), NetworkId: fixture.check.networkId.Bytes(), Format: 2},
		PathEpoch: 1, Record: record, CommitVersion: version, List: list,
	}
}

// An entry version of plan's push at version, versionless or kept, replacing prev's push at prevVersion when named.
func recomputeTestEntry(t *testing.T, plan *sidecar.EvsPushPlan, version uint64, versionless bool, prevPushId *sidecar.Id, prevVersion uint64, locators ...*protocol.EvsLocator) []byte {
	entry := &protocol.EvsEntryVersion{
		Version: version, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
		Chain: locators,
	}
	if versionless {
		entry.Versioning = uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	}
	if prevPushId != nil {
		entry.PrevPushId = prevPushId.Bytes()
		entry.PrevCommitVersion = prevVersion
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return entryBytes
}

// A kind-5 locator naming id, uploaded.
func recomputeTestKind5(id []byte) *protocol.EvsLocator {
	return &protocol.EvsLocator{
		Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: id,
		Offset: sidecar.EvsKind5SegmentHeaderByteCount, Length: uint32(sidecar.EvsRecordByteCount(100)),
	}
}

// A kind-1 locator naming id.
func recomputeTestKind1(id []byte) *protocol.EvsLocator {
	return &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: id, Offset: 0, Length: uint32(sidecar.EvsRecordByteCount(100))}
}

// A segment id for label, stored at seg/ with byteCount bytes.
func (self *evacuateFixture) recomputeSegment(label string, byteCount int) []byte {
	self.t.Helper()
	id := sha256.Sum256([]byte("recompute segment " + label))
	cluster, err := self.host.Blobs.Cluster("seg-1")
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(self.ctx, SegmentKey(self.check.repoId, id), make([]byte, byteCount), nil); err != nil {
		self.t.Fatal(err)
	}
	return id[:]
}

func (self *evacuateFixture) recomputeStored(id []byte) bool {
	return self.segmentAt([32]byte(id)) != nil
}

// A sweep over the fixture's host with the purge on, X's newest version read from newest.
func (self *evacuateFixture) recomputeSweep(newest PurgeNewestReader, settings *SweepSettings) *Sweep {
	self.t.Helper()
	sweep, err := NewSweep(self.host.ServiceHost(), &SweepDeps{
		Format2: &testFormat2Gate{purge: sidecar.Format2On}, Newest: newest, EvsSettings: self.settings2(), Settings: settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return sweep
}

// V writes x and y versionless and z kept; u writes x over V's, citing one of its segments, and removes y and z.
type recomputeHistory struct {
	ref                *recomputeRef
	x, y, z            sidecar.EvsTokenPath
	s1, s2, s3, y1, z1 []byte
	u                  uint64
}

// V at version 1, between pushes after it, then u marking its list.
func newRecomputeHistory(fixture *evacuateFixture, between int) *recomputeHistory {
	history := &recomputeHistory{
		ref: newRecomputeRef(fixture),
		x:   checkTestPath("x"), y: checkTestPath("y"), z: checkTestPath("z"),
		s1: fixture.recomputeSegment("s1", 300), s2: fixture.recomputeSegment("s2", 300), s3: fixture.recomputeSegment("s3", 300),
		y1: fixture.recomputeSegment("y1", 500), z1: fixture.recomputeSegment("z1", 700),
	}
	t := fixture.t
	history.ref.push(func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{
			{TokenPath: history.x, EntryVersion: recomputeTestEntry(t, plan, 1, true, nil, 0, recomputeTestKind5(history.s1), recomputeTestKind5(history.s2))},
			{TokenPath: history.y, EntryVersion: recomputeTestEntry(t, plan, 1, true, nil, 0, recomputeTestKind5(history.y1))},
			{TokenPath: history.z, EntryVersion: recomputeTestEntry(t, plan, 1, false, nil, 0, recomputeTestKind1(history.z1))},
		}
	}, nil)
	vPushId := history.ref.pushIds[0]
	for i := 0; i < between; i += 1 {
		label := fmt.Sprintf("between %d", i)
		history.ref.push(func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
			return []*sidecar.EvsPlannedChange{{TokenPath: checkTestPath(label), EntryVersion: recomputeTestEntry(t, plan, 1, false, nil, 0, recomputeTestKind1(history.z1))}}
		}, nil)
	}
	history.u = history.ref.push(func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{
			{TokenPath: history.x, BaseEntryVersion: 1, EntryVersion: recomputeTestEntry(t, plan, 2, true, &vPushId, 1, recomputeTestKind5(history.s2), recomputeTestKind5(history.s3))},
			{TokenPath: history.y, BaseEntryVersion: 1},
			{TokenPath: history.z, BaseEntryVersion: 1},
		}
	}, &protocol.EvsPurgeList{Marked: true})
	return history
}

// X's newest version, u's, names s2 and s3; y and z stand removed.
func (self *recomputeHistory) newest() *fakePurgeNewest {
	newest := &fakePurgeNewest{}
	newest.name(self.x, self.s2, self.s3)
	return newest
}

// §11.13's sweep row: a marked list is recomputed from what u replaced, x's version found by its prev_commit_version
// and y's by the walk back to its newest write, each less what a version of u's push names; z's kept version leaves
// nothing; the candidates are swept as a listed one's are.
func TestSweepRecomputesAMarkedListFromTheReplacedVersions(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	history := newRecomputeHistory(fixture, 0)
	sweep := fixture.recomputeSweep(history.newest(), nil)
	list := &protocol.EvsPurgeList{Marked: true}
	result, err := sweep.SweepList(fixture.ctx, fixture.cluster, history.ref.target(history.u, history.ref.records[history.u-1], list),
		sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.RecomputedCount != 1 || result.CandidateCount != 2 || result.DeletedCount != 2 || result.KeptCount != 0 || result.FreedByteCount != 800 {
		t.Fatalf("result %+v", result)
	}
	if fixture.recomputeStored(history.s1) || fixture.recomputeStored(history.y1) {
		t.Fatal("a replaced version's content no version of u names stayed")
	}
	if !fixture.recomputeStored(history.s2) || !fixture.recomputeStored(history.s3) || !fixture.recomputeStored(history.z1) {
		t.Fatal("the recompute took what u names or what a kept version holds")
	}
	// swept again, as a rerun after a kill: nothing left to delete
	again, err := sweep.SweepList(fixture.ctx, fixture.cluster, history.ref.target(history.u, history.ref.records[history.u-1], list),
		sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil || again.DeletedCount != 0 || again.AbsentCount != 2 {
		t.Fatalf("a rerun: %+v %v", again, err)
	}
}

// A removal's replaced version past the walk's bound is read from the path's folded entry; with no entry either, the
// path keeps its content, counted kept, while a write's is still found by its own prev_commit_version.
func TestSweepRecomputeReadsTheFoldedEntryAndKeepsWhatItCannotFind(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	history := newRecomputeHistory(fixture, 2)
	sweep := fixture.recomputeSweep(history.newest(), &SweepSettings{ListLimit: 1000, RecomputeVersionCount: 2})
	list := &protocol.EvsPurgeList{Marked: true}
	target := history.ref.target(history.u, history.ref.records[history.u-1], list)

	// the walk reaches two versions back, the pushes between, so neither y nor z is found
	result, err := sweep.SweepList(fixture.ctx, fixture.cluster, target, sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.RecomputedCount != 1 || result.KeptCount != 2 || result.DeletedCount != 1 || !fixture.recomputeStored(history.y1) || fixture.recomputeStored(history.s1) {
		t.Fatalf("past the bound: %+v", result)
	}

	// y's entry folded V's version beside u's removal marker: found there
	vVersion := history.ref.records[0]
	_, payloadBytes, err := sidecar.ParseEvsPushRecordBody(vVersion.Body)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := EvsBatchRecordStatement(vVersion)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	var yEntryVersion []byte
	for _, change := range payload.Changes {
		if change.TokenPath.Equal(history.y) {
			yEntryVersion = change.EntryVersion
		}
	}
	entry := &protocol.EvsIndexEntry{
		Versions: []*protocol.EvsIndexVersion{{PushId: history.ref.pushIds[0].Bytes(), CommitVersion: 1, EntryVersion: yEntryVersion}},
		Marker:   &protocol.EvsRemovalMarker{PushId: history.ref.pushIds[history.u-1].Bytes(), RemovalVersion: history.u, PathVersion: 2},
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, IndexEntryKey(fixture.check.repoId, fixture.check.refId, 1, history.y), entryBytes, nil); err != nil {
		t.Fatal(err)
	}
	result, err = sweep.SweepList(fixture.ctx, fixture.cluster, target, sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.KeptCount != 1 || result.DeletedCount != 1 || fixture.recomputeStored(history.y1) || !fixture.recomputeStored(history.z1) {
		t.Fatalf("from the folded entry: %+v", result)
	}
}

// Observe mode, an unpassed build and a list with no record to recompute from keep a marked list whole, and read
// nothing of its history.
func TestSweepRecomputeKeepsAMarkedListUnderItsGates(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	history := newRecomputeHistory(fixture, 0)
	list := &protocol.EvsPurgeList{Marked: true}
	newest := history.newest()
	observe, err := NewSweep(fixture.host.ServiceHost(), &SweepDeps{Format2: &testFormat2Gate{purge: sidecar.Format2Observe}, Newest: newest, EvsSettings: fixture.settings2()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := observe.SweepList(fixture.ctx, fixture.cluster, history.ref.target(history.u, history.ref.records[history.u-1], list), sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil || result.KeptCount != 1 || result.RecomputedCount != 0 || !fixture.recomputeStored(history.s1) {
		t.Fatalf("observe: %+v %v", result, err)
	}
	sweep := fixture.recomputeSweep(newest, nil)
	fixture.host.Blobs.SetSettlePassed("seg-1", false)
	result, err = sweep.SweepList(fixture.ctx, fixture.cluster, history.ref.target(history.u, history.ref.records[history.u-1], list), sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil || result.KeptCount != 1 || result.RecomputedCount != 0 || !fixture.recomputeStored(history.s1) {
		t.Fatalf("an unpassed build: %+v %v", result, err)
	}
	fixture.host.Blobs.SetSettlePassed("seg-1", true)
	result, err = sweep.SweepList(fixture.ctx, fixture.cluster, history.ref.target(history.u, nil, list), sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil || result.KeptCount != 1 || result.RecomputedCount != 0 || !fixture.recomputeStored(history.s1) {
		t.Fatalf("no record: %+v %v", result, err)
	}
}

// A sealed push whose rename crosses parts: part 1 removes x, part 2 creates w citing one of x's segments. Part 1's
// marked list, recomputed, takes only what no part's version names, and so does the seal's.
func TestSweepRecomputeOfAPartSubtractsEveryPartsVersions(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	ref := newRecomputeRef(fixture)
	x := checkTestPath("x")
	s1, s2 := fixture.recomputeSegment("s1", 300), fixture.recomputeSegment("s2", 300)
	ref.push(func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{
			{TokenPath: x, EntryVersion: recomputeTestEntry(t, plan, 1, true, nil, 0, recomputeTestKind5(s1), recomputeTestKind5(s2))},
		}
	}, nil)

	// past 1,024 entry writes, so the builder cuts parts; w's label is the first that sorts into another part than x
	plan := fixture.check.plan()
	plan.TimeMs = fixture.clock.Now().UnixMilli()
	plan.BaseVersion = 1
	filler := recomputeTestKind1(bytes.Repeat([]byte{0xf1}, 32))
	for i := 0; i < 1100; i += 1 {
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
			TokenPath: checkTestPath(fmt.Sprintf("file-%05d", i)), EntryVersion: recomputeTestEntry(t, plan, 1, false, nil, 0, filler),
		})
	}
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: x, BaseEntryVersion: 1})
	partOf := func(changes []*sidecar.EvsCheckedChange, tokenPath sidecar.EvsTokenPath) bool {
		for _, change := range changes {
			if change.TokenPath.Equal(tokenPath) {
				return true
			}
		}
		return false
	}
	var w sidecar.EvsTokenPath
	for i := 0; w == nil; i += 1 {
		if 64 < i {
			t.Fatal("no label sorts into another part than x")
		}
		candidate := checkTestPath(fmt.Sprintf("a-%d", i))
		trial := *plan
		trial.Changes = append(append([]*sidecar.EvsPlannedChange{}, plan.Changes...), &sidecar.EvsPlannedChange{
			TokenPath: candidate, EntryVersion: recomputeTestEntry(t, plan, 1, true, nil, 0, recomputeTestKind5(s1)),
		})
		built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.signingKey, fixture.check.signerId)).BuildFormat2(&trial)
		if err != nil {
			t.Fatal(err)
		}
		xPart, wPart := -1, -1
		for part, partBytes := range built.Parts {
			checked, err := sidecar.EvsCheckStoredPart(built.Statement, partBytes)
			if err != nil {
				t.Fatal(err)
			}
			if partOf(checked.Changes, x) {
				xPart = part
			}
			if partOf(checked.Changes, candidate) {
				wPart = part
			}
		}
		if xPart != wPart {
			w = candidate
			plan.Changes = trial.Changes
		}
	}
	xPart := -1
	u, partRecords, _ := ref.sealed(plan, func(part int, changes []*sidecar.EvsCheckedChange) *protocol.EvsPurgeList {
		if partOf(changes, x) {
			xPart = part
			return &protocol.EvsPurgeList{Marked: true}
		}
		return nil
	})
	newest := &fakePurgeNewest{}
	newest.name(w, s1)
	sweep := fixture.recomputeSweep(newest, nil)
	list := &protocol.EvsPurgeList{Marked: true}
	result, err := sweep.SweepList(fixture.ctx, fixture.cluster, ref.target(u, partRecords[xPart], list), sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.RecomputedCount != 1 || result.CandidateCount != 1 || result.DeletedCount != 1 || result.KeptCount != 0 {
		t.Fatalf("part: %+v", result)
	}
	if !fixture.recomputeStored(s1) || fixture.recomputeStored(s2) {
		t.Fatal("a rename's target in another part lost its content, or x's other segment stayed")
	}
	// the seal's own list, recomputed over every part, comes to the same
	sealResult, err := sweep.SweepList(fixture.ctx, fixture.cluster, ref.target(u, ref.records[u-1], list), sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil || sealResult.CandidateCount != 1 || sealResult.AbsentCount != 1 || !fixture.recomputeStored(s1) {
		t.Fatalf("seal: %+v %v", sealResult, err)
	}
}

// Evacuation's settle of a kept format-2 record recomputes its marked list at the version its push committed at.
func TestEvacuationRecomputesAMarkedListAtItsRecordsVersion(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	history := newRecomputeHistory(fixture, 0)
	run := fixture.format2Run(history.newest(), &testFormat2Gate{purge: sidecar.Format2On}, &fakeStoredDeltas{})
	place := history.ref.places[history.u-1]
	minute := &evacuateMinute{minute: place.GetMinute()}
	if why, err := run.settleFormat2(minute, place, history.ref.records[history.u-1], history.ref.tails[history.u-1], history.u); why != "" {
		t.Fatalf("waits: %s %v", why, err)
	}
	swept := run.result.Swept
	if swept.RecomputedCount != 1 || swept.DeletedCount != 2 || fixture.recomputeStored(history.s1) || fixture.recomputeStored(history.y1) || !fixture.recomputeStored(history.s2) {
		t.Fatalf("swept %+v", swept)
	}
	if !bytes.Equal(fixture.segmentAt([32]byte(history.z1)), make([]byte, 700)) {
		t.Fatal("a kept version's segment moved")
	}
}
