package evsservice

// EVSB-M10-02's staged decisions on T2: a kept format-2 record's staged segment written to seg/ while its version is
// newest, replaced under 60 s ago, of unknown replacement time, kept by a hold or in observe mode, and dropped
// otherwise; a rerun after a kill between the seg/ PUT and the batch's DELETE storing one object; usage deltas for
// what is dropped or kept only for a hold; a store that does not answer leaving the minute waiting; the record kept
// in its container without its staged bytes; pidx/ listing the staged segments a record introduced.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// taskworker's stored deltas as a test reads them.
type fakeStoredDeltas struct {
	stateLock     sync.Mutex
	networkDeltas map[connect.Id]int64
}

func (self *fakeStoredDeltas) AddStoredDelta(networkId connect.Id, byteDelta int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.networkDeltas == nil {
		self.networkDeltas = map[connect.Id]int64{}
	}
	self.networkDeltas[networkId] += byteDelta
	return nil
}

func (self *fakeStoredDeltas) of(networkId sidecar.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkDeltas[connect.Id(networkId)]
}

// A format-2 push record of the fixture's repo writing path versionless from one staged segment, and its tail with
// list: the record, the tail, the segment and its id.
func (self *evacuateFixture) stagedRecord(label string, list *protocol.EvsPurgeList) (*sidecar.EvsBatchRecord, *sidecar.EvsBatchRecordTail, []byte, [32]byte) {
	self.t.Helper()
	size := int(sidecar.EvsPadme(1000))
	segment := bytes.Repeat([]byte(label), size/len(label)+1)[:size]
	id := sha256.Sum256(segment)
	plan := self.plan()
	entry := &protocol.EvsEntryVersion{
		Version: 1, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: uint64(size), SealedFields: []byte("sealed fields"),
		Versioning: uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS),
		Chain: []*protocol.EvsLocator{{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: id[:],
			Offset: sidecar.EvsKind5SegmentHeaderByteCount, Length: uint32(sidecar.EvsRecordByteCount(100)), Staged: true,
		}},
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: checkTestPath(label), EntryVersion: entryBytes}}
	plan.NewObjects = []*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: id[:], PaddedSize: uint64(size)}}
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(self.check.signingKey, self.check.signerId)).BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: plan.RepoId, RefId: plan.RefId, PushId: plan.PushId,
		SignerSidecarId: self.check.signerId, TimeMs: plan.TimeMs,
		Body: sidecar.EvsPushRecordBody(built.Statement.Bytes, built.Payload),
	}
	tail := &sidecar.EvsBatchRecordTail{Staged: sidecar.EvsEncodeStaged([][]byte{segment})}
	if list != nil {
		listBytes, err := sidecar.EncodeEvsPurgeList(list)
		if err != nil {
			self.t.Fatal(err)
		}
		tail.PurgeList = listBytes
	}
	return record, tail, segment, id
}

// An evacuator over the fixture's host with format 2's deps, and one run of it on meta-1 as Run starts one.
func (self *evacuateFixture) format2Run(newest PurgeNewestReader, format2 Format2Gate, usage StoredDeltaSink) *evacuateRun {
	self.t.Helper()
	evacuator, err := NewEvacuator(self.host.ServiceHost(), &EvacuatorDeps{
		Settings: self.settings, EvsSettings: self.settings2(), Newest: newest, Format2: format2, Usage: usage,
		atStep: func(name string, key string) error {
			self.steps = append(self.steps, name)
			if name == self.stopAt {
				self.stopAt = ""
				return errors.New("killed here")
			}
			return nil
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return &evacuateRun{
		evacuator: evacuator, ctx: self.ctx, cluster: self.cluster, clusterId: "meta-1", now: self.clock.Now(),
		repos: map[sidecar.Id]*evacuateRepo{}, refHeads: map[string]*EvsStoredHead{}, sealParts: map[string]map[string]bool{},
		alarmed: map[string]bool{}, result: &EvacuationResult{ClusterId: "meta-1"},
		rank: sidecar.WriteP2RankEvacuation, funded: true, nextRunInterval: self.settings.RunInterval,
	}
}

func (self *evacuateFixture) segmentAt(id [32]byte) []byte {
	return self.object("seg-1", SegmentKey(self.check.repoId, id))
}

// What the fake host holds at key, nil for nothing.
func (self *evacuateFixture) object(clusterId string, key string) []byte {
	self.t.Helper()
	cluster, err := self.host.Blobs.Cluster(clusterId)
	if err != nil {
		self.t.Fatal(err)
	}
	object, err := cluster.Get(self.ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil
	}
	if err != nil {
		self.t.Fatal(err)
	}
	defer object.Body.Close()
	body, _ := readAllLimited(object, 1024*1024)
	return body
}

// §11.13's staged row: still newest, written to seg/ with its id as checksum and counted in place of its batch; a
// rerun after a kill between that PUT and the batch's DELETE finds equal bytes, one object.
func TestEvacuationWritesAStagedSegmentStillNewest(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	newest := &fakePurgeNewest{}
	deltas := &fakeStoredDeltas{}
	record, tail, segment, id := fixture.stagedRecord("newest", nil)
	newest.name(checkTestPath("newest"), id[:])
	run := fixture.format2Run(newest, &testFormat2Gate{purge: sidecar.Format2On}, deltas)
	minute := &evacuateMinute{minute: BatchMinute(fixture.clock.Now())}
	place := &protocol.EvsPlace{Minute: minute.minute}
	if why, err := run.decideStaged(minute, place, record, tail); why != "" {
		t.Fatalf("waits: %s %v", why, err)
	}
	if !bytes.Equal(fixture.segmentAt(id), segment) || run.result.StagedWrittenCount != 1 {
		t.Fatal("a staged segment still newest did not reach seg/")
	}
	if deltas.of(fixture.check.networkId) != 0 {
		t.Fatal("a staged segment moved to seg/ left the stored count")
	}
	// killed before the batch's DELETE: the rerun's PUT meets equal bytes
	again := fixture.format2Run(newest, &testFormat2Gate{purge: sidecar.Format2On}, deltas)
	if why, err := again.decideStaged(minute, place, record, tail); why != "" {
		t.Fatalf("a rerun waits: %s %v", why, err)
	}
	if len(fixture.keys("seg-1", segmentKeyPrefix+sidecar.EvsKeyId(fixture.check.repoId)+"/")) != 1 {
		t.Fatal("a rerun stored a second object")
	}
	if got := fixture.host.Metrics.Value(versionlessStagedMetricName, versionlessStagedWritten); got != 2 {
		t.Fatalf("staged written %v", got)
	}
}

// Replaced more than 60 s before the decision: dropped, never reaching seg/, and out of the stored count; replaced
// under 60 s ago, or at a time the head no longer shows: written, as readers may be inside the allowance; observe
// mode keeps replaced content: written.
func TestEvacuationDropsAStagedSegmentReplacedEarlier(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	deltas := &fakeStoredDeltas{}
	cases := []struct {
		label     string
		replaced  time.Duration
		mode      sidecar.Format2Mode
		unknown   bool
		written   bool
		deltaSign int64
	}{
		{label: "dropped", replaced: -10 * time.Minute, mode: sidecar.Format2On, written: false, deltaSign: -1},
		{label: "recent", replaced: -30 * time.Second, mode: sidecar.Format2On, written: true},
		{label: "unknown", unknown: true, mode: sidecar.Format2On, written: true},
		{label: "observed", replaced: -10 * time.Minute, mode: sidecar.Format2Observe, written: true},
	}
	for _, c := range cases {
		newest := &fakePurgeNewest{}
		record, tail, segment, id := fixture.stagedRecord(c.label, nil)
		path := checkTestPath(c.label)
		newest.name(path)
		if !c.unknown {
			// the replacing version's minute ended this long ago
			newest.committed(path, fixture.clock.Now().Add(c.replaced))
		}
		run := fixture.format2Run(newest, &testFormat2Gate{purge: c.mode}, deltas)
		minute := &evacuateMinute{minute: BatchMinute(fixture.clock.Now().Add(-25 * time.Hour))}
		before := deltas.of(fixture.check.networkId)
		if why, err := run.decideStaged(minute, &protocol.EvsPlace{Minute: minute.minute}, record, tail); why != "" {
			t.Fatalf("%s waits: %s %v", c.label, why, err)
		}
		if written := fixture.segmentAt(id) != nil; written != c.written {
			t.Errorf("%s: written %v, want %v", c.label, written, c.written)
		}
		if delta := deltas.of(fixture.check.networkId) - before; delta != c.deltaSign*int64(len(segment)) {
			t.Errorf("%s: stored delta %d", c.label, delta)
		}
	}
}

// Under a hold, a staged segment of a batch from before its placement is written, and leaves the stored count as
// content only a hold keeps; one written after the placement is purged as usual.
func TestEvacuationWritesStagedContentAHoldKeeps(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	deltas := &fakeStoredDeltas{}
	newest := &fakePurgeNewest{}
	batchTime := fixture.clock.Now()
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.check.networkId, CaseId: testId("staged case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeRepos(fixture.check.repoId), PlaceTime: batchTime.Add(time.Hour), ExpireTime: batchTime.Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(25 * time.Hour)
	for _, c := range []struct {
		label   string
		minute  time.Time
		written bool
	}{
		{label: "held", minute: batchTime, written: true},
		{label: "after", minute: batchTime.Add(2 * time.Hour), written: false},
	} {
		record, tail, segment, id := fixture.stagedRecord(c.label, nil)
		newest.name(checkTestPath(c.label))
		newest.committed(checkTestPath(c.label), c.minute.Add(time.Minute))
		run := fixture.format2Run(newest, &testFormat2Gate{purge: sidecar.Format2On}, deltas)
		minute := &evacuateMinute{minute: BatchMinute(c.minute)}
		before := deltas.of(fixture.check.networkId)
		if why, err := run.decideStaged(minute, &protocol.EvsPlace{Minute: minute.minute}, record, tail); why != "" {
			t.Fatalf("%s waits: %s %v", c.label, why, err)
		}
		if written := fixture.segmentAt(id) != nil; written != c.written {
			t.Errorf("%s: written %v, want %v", c.label, written, c.written)
		}
		if delta := deltas.of(fixture.check.networkId) - before; delta != -int64(len(segment)) {
			t.Errorf("%s: stored delta %d, want the segment out of the count", c.label, delta)
		}
	}
}

// A newest version the store did not answer for leaves the minute waiting; a staged segment no version cites is
// dropped with an alarm.
func TestEvacuationStagedDecisionWaitsOnTheStore(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	newest := &fakePurgeNewest{err: sidecar.ErrBlobHeld}
	record, tail, _, id := fixture.stagedRecord("held head", nil)
	run := fixture.format2Run(newest, &testFormat2Gate{purge: sidecar.Format2On}, &fakeStoredDeltas{})
	minute := &evacuateMinute{minute: BatchMinute(fixture.clock.Now())}
	if why, _ := run.decideStaged(minute, &protocol.EvsPlace{Minute: minute.minute}, record, tail); why == "" {
		t.Fatal("a held head let the decision go on")
	}
	if fixture.segmentAt(id) != nil {
		t.Fatal("a staged segment was written on a guess")
	}
	// another segment rides in the tail: no version of the record cites it
	stray := bytes.Repeat([]byte("s"), int(sidecar.EvsPadme(800)))
	strayId := sha256.Sum256(stray)
	tail.Staged = sidecar.EvsEncodeStaged([][]byte{stray})
	newest.err = nil
	run = fixture.format2Run(newest, &testFormat2Gate{purge: sidecar.Format2On}, &fakeStoredDeltas{})
	if why, err := run.decideStaged(minute, &protocol.EvsPlace{Minute: minute.minute}, record, tail); why != "" {
		t.Fatalf("waits: %s %v", why, err)
	}
	if fixture.segmentAt(strayId) != nil || run.result.StagedDroppedCount != 1 {
		t.Fatal("a staged segment no version cites reached seg/")
	}
}

// A kept record goes to its container without its staged bytes, its purge list kept, and in format 1's form when it
// has none; its hashes and changes read the same.
func TestEvacuationKeepsARecordWithoutItsStagedBytes(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	list := &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{{
		TokenPath: checkTestPath("old").Components(), ReplacedVersion: 1, SegmentIds: [][]byte{bytes.Repeat([]byte{9}, 32)},
	}}}
	record, tail, segment, _ := fixture.stagedRecord("kept", list)
	stripped := sidecar.EvsBatchRecordBytesWithoutStaged(record, tail)
	if bytes.Contains(stripped, segment) {
		t.Fatal("the container's record holds staged bytes")
	}
	parsed, parsedTail, err := sidecar.ParseEvsBatchRecordFormat2(stripped)
	if err != nil || !bytes.Equal(parsed.Body, record.Body) || parsedTail.Empty() || len(parsedTail.Staged) != 0 {
		t.Fatalf("the stripped record: %v", err)
	}
	if got, err := parsedTail.PurgeListValue(); err != nil || len(got.GetCandidates()) != 1 {
		t.Fatalf("the purge list was not kept: %v", err)
	}
	formatOne := sidecar.EvsBatchRecordBytesWithoutStaged(record, &sidecar.EvsBatchRecordTail{Staged: tail.Staged})
	if _, err := sidecar.ParseEvsBatchRecord(formatOne); err != nil {
		t.Fatalf("a record with no list left is not format 1's form: %v", err)
	}
	// the staged item is listed among what the record introduced, for pidx/
	ids, _, err := evacuateRecordObjects(record)
	if err != nil || len(ids) != 1 {
		t.Fatalf("introduced %v %v", ids, err)
	}
}
