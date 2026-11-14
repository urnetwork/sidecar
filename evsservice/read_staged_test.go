// Staged content on the read route (EVS2-M10-08; FS-66's reader, R-EVS-8's round count): a staged range resolved in
// its push's batch record, at seg/ once the batch is gone, never for a collected version, and not at all without the
// version that stages it.

package evsservice

import (
	"bytes"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The segment objects of reply, by whether each is missing.
func readTestSegments(reply *readTestReply) (served [][]byte, missing int) {
	for _, object := range reply.objects {
		if object.GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT {
			continue
		}
		if object.GetMissing() {
			missing += 1
			continue
		}
		served = append(served, object.GetBody())
	}
	return served, missing
}

// A range over the whole of a staged segment.
func readTestStagedRange(id [32]byte, segment []byte) *protocol.EvsReadRange {
	return &protocol.EvsReadRange{SegmentId: id[:], Offset: 0, Length: uint32(len(segment))}
}

// A second engine over the fixture's host, as another evs process is: none of the first one's caches.
func (self *pushFixture) otherEngine() *EvsEngine {
	self.t.Helper()
	engine, err := NewEvsEngine(self.ctx, self.host.ServiceHost(), self.settings, &EvsEngineDeps{
		AuthState: self.auth,
		Uploads:   self.engine.deps.Uploads,
		GateViews: &pushTestGateViews{check: self.check},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	return engine
}

// A staged segment has no object of its own while its push's record is batch-resident: a read naming the version
// that stages it beside the range is served the segment's bytes from that record, in the request's two store rounds;
// a range of the same id with no such path beside it finds nothing at seg/ and answers missing.
func TestReadServesAStagedSegmentFromItsPushRecord(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	token := fixture.token(fixture.check.signerId)
	path := checkTestPath("small")
	segment, id := fixture.commitStaged(path, 0, 1, "one", 1)

	reply := fixture.readVersion(path, 0, readTestStagedRange(id, segment))
	served, missing := readTestSegments(reply)
	if len(served) != 1 || missing != 0 || !bytes.Equal(served[0], segment) {
		t.Fatalf("the staged range beside its path: %d served, %d missing", len(served), missing)
	}
	if reply.paths[0].GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED || !reply.ended {
		t.Fatalf("the path's reply: state %s ended %t", reply.paths[0].GetState(), reply.ended)
	}

	// another process, nothing cached: the head, the entry round and the record's batch range, no read more for the
	// staged bytes, which ride in the record the path's reply already read (R-EVS-8)
	other := fixture.otherEngine()
	first := fixture.engine
	fixture.engine = other
	reply = fixture.readVersion(path, 0, readTestStagedRange(id, segment))
	fixture.engine = first
	served, missing = readTestSegments(reply)
	if len(served) != 1 || missing != 0 || !bytes.Equal(served[0], segment) {
		t.Fatalf("another process: %d served, %d missing", len(served), missing)
	}
	if _, readCount, _ := other.records.Counts(); readCount != 1 {
		t.Fatalf("another process read %d batch ranges for one staged version, want 1", readCount)
	}

	// the range alone names no version
	alone := fixture.read(token, &protocol.EvsReadRequest{
		RefId: fixture.check.refId.Bytes(), PinVersion: 1, Ranges: []*protocol.EvsReadRange{readTestStagedRange(id, segment)},
	})
	if served, missing := readTestSegments(alone); len(served) != 0 || missing != 1 {
		t.Fatalf("a staged range with no path: %d served, %d missing", len(served), missing)
	}
	// and a path that stages another segment does not lend its push to this one
	otherPath := checkTestPath("other")
	fixture.commitStaged(otherPath, 0, 2, "two", 2)
	crossed := fixture.readVersion(otherPath, 0, readTestStagedRange(id, segment))
	if served, missing := readTestSegments(crossed); len(served) != 0 || missing != 1 {
		t.Fatalf("a staged range beside another path: %d served, %d missing", len(served), missing)
	}
}

// FS-66's reader in observe mode: a replaced staged version's bytes still sit in their batch, and from T its path
// answers `collected` and its range missing, as with the purge on; before T both are served.
func TestReadServesNoStagedContentOfACollectedVersion(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	path := checkTestPath("small")
	segment, id := fixture.commitStaged(path, 0, 1, "one", 1)
	newer, newerId := fixture.commitStaged(path, 1, 2, "two", 2)
	from := fixture.collectedFrom(2)

	fixture.clockTo(from.Add(-time.Second))
	reply := fixture.readVersion(path, 1, readTestStagedRange(id, segment))
	if served, missing := readTestSegments(reply); len(served) != 1 || missing != 0 || !bytes.Equal(served[0], segment) ||
		reply.paths[0].GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("inside the allowance: %d served, %d missing, state %s", len(served), missing, reply.paths[0].GetState())
	}

	fixture.clockTo(from)
	reply = fixture.readVersion(path, 1, readTestStagedRange(id, segment))
	if served, missing := readTestSegments(reply); len(served) != 0 || missing != 1 ||
		reply.paths[0].GetState() != protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED {
		t.Fatalf("from T: %d served, %d missing, state %s", len(served), missing, reply.paths[0].GetState())
	}
	// the batch still holds the bytes: the purge is in observe mode and evacuation has not run
	place := windowEntryAt(fixture.head().Head, 1).Place
	recordBytes, err := fixture.engine.readBatchRecordBytes(&readAttempt{ctx: fixture.ctx, cluster: fixture.cluster}, place)
	if err != nil || !bytes.Contains(recordBytes, segment) {
		t.Fatalf("the replaced version's batch record: %v", err)
	}
	// the newest version reads on
	reply = fixture.readVersion(path, 0, readTestStagedRange(newerId, newer))
	if served, missing := readTestSegments(reply); len(served) != 1 || missing != 0 || !bytes.Equal(served[0], newer) {
		t.Fatalf("the newest version: %d served, %d missing", len(served), missing)
	}
}

// Evacuation's two steps for a retained staged segment, as evacuate_staged.go and evacuate_resolve.go take them: the
// segment written to seg/ when write is set, then the batch deleted. The engine it returns is another process, which
// holds the push's record as a container gives it, without its staged bytes.
func (self *evacuateFixture) evacuateStaged(place *protocol.EvsPlace, id [32]byte, write bool) *EvsEngine {
	self.t.Helper()
	recordBytes, err := self.engine.readBatchRecordBytes(&readAttempt{ctx: self.ctx, cluster: self.cluster}, place)
	if err != nil {
		self.t.Fatal(err)
	}
	record, tail, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		self.t.Fatal(err)
	}
	if write {
		newest := &fakePurgeNewest{}
		newest.name(checkTestPath("small"), id[:])
		run := self.format2Run(newest, &testFormat2Gate{purge: sidecar.Format2On}, &fakeStoredDeltas{})
		if why, err := run.decideStaged(&evacuateMinute{minute: place.GetMinute()}, place, record, tail); why != "" {
			self.t.Fatalf("the staged decision waits: %s %v", why, err)
		}
	}
	if err := self.cluster.Delete(self.ctx, PlaceBatchKey(place)); err != nil {
		self.t.Fatal(err)
	}
	other := self.otherEngine()
	other.records.Put(self.cluster.ClusterId(), place, sidecar.EvsBatchRecordBytesWithoutStaged(record, tail))
	return other
}

// FS-66's reader across evacuation: evacuation writes a retained staged segment to seg/ before it deletes the batch,
// and its record goes on without its staged bytes. A read after it, by a process that never saw the batch, finds no
// staged bytes in the record and is served the segment at seg/; the committing process, whose cache still holds the
// batch's record, serves the same bytes.
func TestReadFindsAStagedSegmentAtSegAfterEvacuation(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	fixture.openFormat2Checked()
	path := checkTestPath("small")
	segment, id := fixture.commitStaged(path, 0, 1, "one", 1)
	place := windowEntryAt(fixture.head().Head, 1).Place
	other := fixture.evacuateStaged(place, id, true)
	if !bytes.Equal(fixture.segmentAt(id), segment) {
		t.Fatal("the staged decision did not write the newest version's segment to seg/")
	}

	first := fixture.engine
	fixture.engine = other
	reply := fixture.readVersion(path, 0, readTestStagedRange(id, segment))
	fixture.engine = first
	if served, missing := readTestSegments(reply); len(served) != 1 || missing != 0 || !bytes.Equal(served[0], segment) {
		t.Fatalf("after evacuation, from seg/: %d served, %d missing", len(served), missing)
	}

	reply = fixture.readVersion(path, 0, readTestStagedRange(id, segment))
	if served, missing := readTestSegments(reply); len(served) != 1 || missing != 0 || !bytes.Equal(served[0], segment) {
		t.Fatalf("after evacuation, the committing process: %d served, %d missing", len(served), missing)
	}
}

// A staged segment neither its batch nor seg/ holds answers missing, for the reader to decide: the newest version's
// reader alarms as for a missing segment (§11.9's collected row).
func TestReadAnswersAStagedSegmentNothingHoldsMissing(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	fixture.openFormat2Checked()
	path := checkTestPath("small")
	segment, id := fixture.commitStaged(path, 0, 1, "one", 1)
	place := windowEntryAt(fixture.head().Head, 1).Place
	fixture.engine = fixture.evacuateStaged(place, id, false)
	reply := fixture.readVersion(path, 0, readTestStagedRange(id, segment))
	if served, missing := readTestSegments(reply); len(served) != 0 || missing != 1 {
		t.Fatalf("a staged segment nothing holds: %d served, %d missing", len(served), missing)
	}
	if reply.paths[0].GetVersion().GetCommitVersion() != 1 || reply.paths[0].GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("the newest version's reply: %v state %s", reply.paths[0].GetVersion(), reply.paths[0].GetState())
	}
}
