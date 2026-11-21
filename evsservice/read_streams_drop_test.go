// Record and object withholding across EVS read modes on private in-memory stores.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A held job and its immutable inventory, published on the fixture's stores.
func (self *pushFixture) publishReadHold(heldIds ...DropScanId) sidecar.Id {
	self.t.Helper()
	jobId := testId("stream read held inventory")
	if _, err := self.engine.drops.Update(self.paidContext(), self.cluster, self.check.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		state.HeldJobs = append(state.HeldJobs, &DropJobRecord{JobId: jobId, StartedMs: now.UnixMilli(), Phase: protocol.EvsDropPhase_EVS_DROP_DELETE, Held: true})
		return true, nil
	}); err != nil {
		self.t.Fatal(err)
	}
	segments, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	encoded, err := EncodeDropIdFile(DropFileHeld, self.check.repoId, jobId, 0, heldIds)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := NewDropFiles(segments, self.check.repoId, jobId, self.settings.Drop).Put(self.ctx, DropFileHeld, 0, encoded); err != nil {
		self.t.Fatal(err)
	}
	return jobId
}

// An unsigned staged tail is all-or-none. The stored payload and its purge list still verify when a held id
// removes the tail from a public record. Path-qualified ranges can still serve its other staged object.
func TestReadRecordWithholdsAStagedTailContainingAHeldSegment(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	availablePath, heldPath := checkTestPath("available"), checkTestPath("held")
	fixture.commitStaged(availablePath, 0, 1, "previous", 1)
	plan := fixture.plan()
	staged := [][]byte{}
	ids := [][32]byte{}
	for i, path := range []sidecar.EvsTokenPath{availablePath, heldPath} {
		segment, object := checkTestStaged(t, plan, []string{"available", "held"}[i])
		staged = append(staged, segment)
		ids = append(ids, object.Id)
		plan.NewObjects = append(plan.NewObjects, object.NewObject())
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
			TokenPath: path, BaseEntryVersion: uint64(1 - i),
			EntryVersion: fixture.check.versionedEntry(plan, 2, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(object.Id, true)),
		})
	}
	token := fixture.token(fixture.check.signerId)
	fixture.requireCommitted(fixture.post(token, fixture.bodyStaged(plan, staged)), 2)
	fixture.awaitStepEights()
	request := &protocol.EvsReadRequest{RefId: plan.RefId.Bytes(), PinVersion: 2, Pushes: []*protocol.EvsReadPush{{PushId: plan.PushId.Bytes(), Version: 2}}}
	readRecord := func() []byte {
		t.Helper()
		reply := fixture.read(token, request)
		if len(reply.objects) != 1 || reply.objects[0].GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD {
			t.Fatal("expected the committed staged record")
		}
		return reply.objects[0].GetBody()
	}
	record, tail, err := sidecar.ParseEvsBatchRecordFormat2(readRecord())
	if err != nil || tail == nil || !bytes.Equal(tail.Staged, sidecar.EvsEncodeStaged(staged)) || len(tail.PurgeList) == 0 {
		t.Fatalf("expected both staged segments and the replaced version's purge list: %v", err)
	}
	fixture.publishReadHold(DropSegmentId(ids[1]))
	if got, want := readRecord(), sidecar.EvsBatchRecordBytesWithoutStaged(record, tail); !bytes.Equal(got, want) {
		t.Fatal("record differs from the verified stored form with only the staged item removed")
	}
	if served, missing := readTestSegments(fixture.readVersion(heldPath, 2, readTestStagedRange(ids[1], staged[1]))); len(served) != 0 || missing != 1 {
		t.Fatal("a path-qualified held range must be missing")
	}
	if served, missing := readTestSegments(fixture.readVersion(availablePath, 2, readTestStagedRange(ids[0], staged[0]))); len(served) != 1 || missing != 0 || !bytes.Equal(served[0], staged[0]) {
		t.Fatal("the other path's staged range must remain readable")
	}
	// This request also names a replaced staged version and its record. Its collected verdict covers
	// the publicly framed record even though the fixture still holds the stored tail.
	fixture.clockTo(fixture.collectedFrom(2))
	old := fixture.windowEntryAt(1)
	collected := fixture.read(fixture.token(fixture.check.signerId), &protocol.EvsReadRequest{
		RefId: plan.RefId.Bytes(), PinVersion: 2,
		Paths:  []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: availablePath.Components()}}, Version: 1}},
		Pushes: []*protocol.EvsReadPush{{PushId: old.PushId.Bytes(), Version: 1}},
	})
	if len(collected.paths) != 1 || collected.paths[0].GetState() != protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED || len(collected.objects) != 1 {
		t.Fatal("expected the replaced version's collected verdict and its record")
	}
	_, tail, err = sidecar.ParseEvsBatchRecordFormat2(collected.objects[0].GetBody())
	if err != nil || (tail != nil && len(tail.Staged) != 0) {
		t.Fatalf("the collected version's record retained a staged tail or failed to parse: %v", err)
	}
}

// The same encoded entry can occur under two paths. A real drop on a shared ref selects the second one.
// Both framers must keep the signed statement, first entry, part framing and record cache intact, including
// when the original push or part is carried in a reseed envelope.
func TestReadStreamRecordsElideOnlyTheListedEntry(t *testing.T) {
	for _, parted := range []bool{false, true} {
		fixture := newDropTestFixture(t, 0)
		kept := checkTestPath("kept")
		if kept.Compare(fixture.x) > 0 {
			fixture.x, kept = kept, fixture.x
		}
		plan := fixture.plan()
		entry := fixture.check.fileEntry(plan, 1, nil)
		for _, path := range []sidecar.EvsTokenPath{kept, fixture.x} {
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: path, EntryVersion: entry})
		}
		if parted {
			plan.SealedMetadata = bytes.Repeat([]byte{0x5a}, 1536*1024)
		}
		built := fixture.built(plan)
		token := fixture.token(fixture.check.signerId)
		if parted {
			if len(built.Parts) < 2 {
				t.Fatal("expected a push in parts")
			}
			fixture.requireCommitted(fixture.seal(token, built, fixture.postParts(token, built)), 1)
		} else {
			fixture.requireCommitted(fixture.push(plan), 1)
		}
		fixture.awaitStepEights()
		digest := sha256.Sum256(entry)
		fixture.newest, fixture.hashes[1] = 1, digest[:]
		drop, history := fixture.dropPlan(false, fixture.listedBelow(2))
		fixture.commitDrop(drop, 2)
		fixture.clockTo(time.UnixMilli(history.GetNotBeforeMs()))
		read := &readAttempt{ctx: t.Context(), engine: fixture.engine, settings: fixture.settings, cluster: fixture.cluster, repoId: plan.RepoId, refId: plan.RefId, head: fixture.head()}
		read.pushes = newReadPushes(read.engine, read.ctx, read.cluster, read.repoId, read.refId, read.head.Head)
		objects, err := read.streamVersionObjects(1)
		if err != nil {
			t.Fatal(err)
		}
		if parted {
			// A stored format-2 part can retain its unsigned purge list after evacuation. Read the same
			// signed seal through a cold instance with that container form at its first part's place.
			push, err := read.pushes.at(1)
			if err != nil {
				t.Fatal(err)
			}
			part, _, err := sidecar.ParseEvsBatchRecordFormat2(objects.records[1])
			if err != nil {
				t.Fatal(err)
			}
			tail := recomputeTestTail(t, &protocol.EvsPurgeList{Marked: true})
			archived := sidecar.EvsBatchRecordBytesWithoutStaged(part, tail)
			other := fixture.otherEngine()
			other.records.Put(read.cluster.ClusterId(), push.sealParts[0].Place, archived)
			cold := *read
			cold.engine = other
			cold.pushes = newReadPushes(other, read.ctx, read.cluster, read.repoId, read.refId, read.head.Head)
			parsed, err := cold.streamVersionObjects(1)
			if err != nil || !bytes.Equal(parsed.records[1], archived) {
				t.Fatalf("format-2 sealed part failed its original statement check: %v", err)
			}
		}
		request := &protocol.EvsReadRequest{RefId: plan.RefId.Bytes(), PinVersion: 2}
		for number := range objects.records {
			request.Pushes = append(request.Pushes, &protocol.EvsReadPush{PushId: plan.PushId.Bytes(), Version: 1, Part: uint32(number)})
		}
		ordinary := fixture.read(fixture.token(fixture.check.signerId), request)
		for _, reseed := range []bool{false, true} {
			served := *objects
			served.records = make([][]byte, len(objects.records))
			want := make([][]byte, len(objects.records))
			matched := 0
			for i, original := range objects.records {
				record := bytes.Clone(original)
				if reseed && (!parted || i > 0) {
					record[0] = byte(protocol.EvsBatchRecordType_EVS_BATCH_RESEED)
				}
				served.records[i], want[i] = record, bytes.Clone(record)
				if at := bytes.Index(record, entry); at >= 0 {
					if bytes.Count(record, entry) != 2 {
						t.Fatal("expected the two identical checked entries in one record")
					}
					end := bytes.LastIndex(record, entry) + len(entry)
					clear(want[i][end-len(entry) : end])
					matched++
				}
			}
			if matched != 1 {
				t.Fatal("expected one record containing both entries")
			}
			reply := httptest.NewRecorder()
			stream := &readStream{request: &EvsRequest{engine: fixture.engine, Writer: reply, RepoId: plan.RepoId}}
			if !read.streamVersion(stream, &served) || !stream.frame(&protocol.EvsReadFrame{End: true}) {
				t.Fatal("stream record framing failed")
			}
			framed := decodeReadFrames(t, reply.Body.Bytes())
			if len(framed.statements) != 1 || !bytes.Equal(framed.statements[0].GetStatement(), built.Statement.Bytes) {
				t.Fatal("the original signed statement changed")
			}
			check := func(answer *readTestReply) {
				t.Helper()
				records := make([][]byte, len(want))
				for _, frame := range answer.objects {
					records[frame.GetNumber()] = append(records[frame.GetNumber()], frame.GetBody()...)
				}
				for i, record := range records {
					if !bytes.Equal(record, want[i]) {
						t.Fatalf("unexpected bytes in part %d, multipart %t, reseed %t", i, parted, reseed)
					}
				}
			}
			check(framed)
			if !reseed {
				check(ordinary)
			}
		}
	}
}

// A guarded streams read keeps its framing and exact ranges across a held inventory, an unreadable inventory,
// and a retry. The objects remain in the fake store throughout.
func TestReadStreamsWithholdsStoredSegmentsAndSlots(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.putRepo(protocol.RepoKind_REPO_KIND_RECORD, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.openFormat2Checked()
	segments, err := fixture.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	plan := fixture.plan()
	plan.RefKind, plan.OwnerSidecarId = protocol.EvsRefKind_EVS_REF_OWNED, &fixture.check.signerId
	var receipts []*protocol.EvsUploadReceipt
	var heldIds []DropScanId
	held := map[string]bool{}
	for index, label := range []string{"held", "available"} {
		segment := bytes.Repeat([]byte{byte(index + 1)}, 4096)
		segmentId := sha256.Sum256(segment)
		if _, err := segments.PutIfNoneMatch(t.Context(), SegmentKey(plan.RepoId, segmentId), segment, nil); err != nil {
			t.Fatal(err)
		}
		now := fixture.clock.Now()
		receipt, err := IssueUploadReceipt(fixture.check.receiptKeys, plan.RepoId, segmentId, uint64(len(segment)), now, fixture.check.signerId, false, now)
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
		slotId, slot, slotBytes := checkTestSlot(t, label)
		plan.NewObjects = append(plan.NewObjects, &sidecar.EvsNewObject{
			Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segmentId[:],
			PaddedSize: uint64(len(segment)), UploadDay: uint32(now.UnixMilli() / evsUploadDayMs),
		}, slot)
		plan.SlotBodies = append(plan.SlotBodies, slotBytes)
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
			TokenPath: checkTestPath(label), EntryVersion: fixture.check.fileEntry(plan, 1, []*protocol.EvsLocator{checkTestSegmentLocator(segmentId)}, slotId),
		})
		if index == 0 {
			heldIds = []DropScanId{DropSegmentId(segmentId), DropSlotId(slotId)}
			held[string(segmentId[:])], held[string(slotId[:])] = true, true
		}
	}
	token := fixture.token(fixture.check.signerId)
	body := fixture.body(plan)
	body.Receipts = receipts
	fixture.requireCommitted(fixture.post(token, body), 1)
	fixture.awaitStepEights()
	read := &protocol.EvsReadRequest{Refs: []*protocol.EvsReadRef{{RefId: plan.RefId.Bytes()}}}
	baseline := fixture.read(token, read)
	if len(baseline.statements) != 1 || !bytes.Equal(baseline.statements[0].GetStatement(), body.GetStatement()) || len(baseline.objects) != 5 {
		t.Fatal("expected the original statement, its record, two ranges and two slots")
	}
	for _, object := range baseline.objects {
		if object.GetMissing() || len(object.GetBody()) == 0 {
			t.Fatal("expected readable fixture objects before the hold")
		}
		if object.GetKind() == protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT {
			locator := checkTestSegmentLocator([32]byte(object.GetId()))
			end := int(locator.GetOffset() + locator.GetLength())
			if object.GetOffset() != 0 || len(object.GetBody()) != end {
				t.Fatalf("streamed segment range starts at %d and has %d bytes, want [0,%d)", object.GetOffset(), len(object.GetBody()), end)
			}
		}
	}

	jobId := fixture.publishReadHold(heldIds...)
	requireHeld := func() {
		t.Helper()
		reply := fixture.read(token, read)
		if !reply.ended || len(reply.objects) != len(baseline.objects) || len(reply.statements) != 1 || !proto.Equal(reply.statements[0], baseline.statements[0]) {
			t.Fatal("the hold changed the stream's statement, object count or end")
		}
		missing := 0
		for i, object := range reply.objects {
			want := baseline.objects[i]
			if held[string(want.GetId())] {
				missing++
				want = &protocol.EvsReadObject{Kind: want.GetKind(), Id: want.GetId(), Missing: true}
			}
			if !proto.Equal(object, want) {
				t.Fatalf("unexpected %s frame at %d, missing %t, body length %d", object.GetKind(), i, object.GetMissing(), len(object.GetBody()))
			}
		}
		if missing != len(heldIds) {
			t.Fatalf("marked %d objects missing, want %d", missing, len(heldIds))
		}
	}
	requireHeld()
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpList, KeyPrefix: dropFileKindPrefix(plan.RepoId, jobId, DropFileHeld), Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	failed := fixture.call(token, http.MethodPost, "/read", read)
	if failed.Code != http.StatusOK {
		t.Fatalf("expected an in-stream refusal, status %d", failed.Code)
	}
	frames := sidecar.NewEvsReadFrames(bytes.NewReader(failed.Body.Bytes()))
	for {
		frame, err := frames.Next()
		if err != nil {
			var refusal *sidecar.EvsError
			if !errors.As(err, &refusal) || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE || refusal.RetryAfter <= 0 {
				t.Fatalf("unreadable held inventory ended with %v", err)
			}
			break
		}
		if object := frame.GetObject(); object != nil && object.GetKind() != protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD {
			t.Fatal("an object was framed before its inventory was available")
		}
	}
	requireHeld()
	fixture.engine = fixture.otherEngine()
	// Older one-part records retained the push's unsigned slot bodies. A new instance reading that archive
	// must emit the same canonical record and fetch each visible slot under its own current inventory.
	record, err := sidecar.ParseEvsBatchRecord(baseline.objects[0].GetBody())
	if err != nil {
		t.Fatal(err)
	}
	record.Body = sidecar.EvsPushRecordBody(body.GetStatement(), body.GetPayload())
	legacy := record.Bytes(nil)
	if bytes.Equal(legacy, baseline.objects[0].GetBody()) {
		t.Fatal("fixture lacks the legacy slot section")
	}
	fixture.engine.records.Put(fixture.cluster.ClusterId(), fixture.windowEntryAt(1).Place, legacy)
	requireHeld()
}
