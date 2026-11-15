// POST /evs/v1/repos/<id>/read {refs} (§11.9's streams row; D-EVS-61, FI-25; EVS1-M6-01): one request reads up to
// ReadStreamRefMaxCount of a record-class repo's owned streams after their pins, which the team directory's daemons
// do for the streams a sync finds moved, 64 at a time (§16.11), instead of one read a stream.
//
//	request  refs alone, each (ref_id, pin_version), each once: any other field, a ref past the bound, a repo that is
//	         not record-class or a ref that stands and is not an owned file-mode stream answers 400 INVALID before
//	         anything is read past the heads
//	heads    each ref's head from {evsh_} where §11.9's cache row allows, at least its pin, else the cluster's, all
//	         read before the first frame, so a failure there answers 503
//	per ref  its head summary first; nothing more when it stands at or below its pin; `behind` with the first
//	         missing version when its pin is older than the window, the client paging GET .../log; else each version
//	         after the pin in order: its Signed EvsPush as received, its push record (a sealed push's seal record and
//	         each part's), and the objects the entries it creates name, each chain's segment ranges and each slot,
//	         with the slots the push introduces
//	budget   the reply's frames stay within ReadStreamMaxByteCount, 4 MiB: a version that would pass it is not
//	         started, and its ref answers `more` with that version, as does every ref after it with a version past
//	         its pin; a request serves at least one version whatever its size, so a large push never wedges a stream
//	failed   a store read that fails once the 200 is written ends the reply with an error frame in the end frame's
//	         place, UNAVAILABLE, as every read does (QD-662); a record that is not its statement's also alarms
//
// evs sees no path: a stream's writer rules stay reader checks (§16.11), and a team directory's ERASE, CLOSURE,
// closure uploads and slots/delete stay admin-only on their own routes (I-EVS-16). Streams are format 1's; cards,
// repo files and the index are M10's (D-PHASE-11).
//
// Barriers: evs.read.streams.before and .after around the heads' reads, keyed by the repo, with no lock held.

package evsservice

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One stream of a streams read.
type readStreamRef struct {
	refId      sidecar.Id
	pinVersion uint64
	head       *EvsStoredHead
}

// See the file header.
func (self *EvsEngine) serveReadStreams(request *EvsRequest, body *protocol.EvsReadRequest) {
	settings := self.settings
	request.Note("streams")
	if len(body.GetRefId()) != 0 || body.GetPinVersion() != 0 || body.GetFresh() || 0 < len(body.GetPaths()) ||
		0 < len(body.GetRanges()) || 0 < len(body.GetSlotIds()) || 0 < len(body.GetMaps()) || 0 < len(body.GetLogPages()) ||
		0 < len(body.GetPushes()) || 0 < len(body.GetHeldDrops()) || settings.ReadStreamRefMaxCount < len(body.GetRefs()) {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	ctx := request.Ctx
	refs := []*readStreamRef{}
	seen := map[sidecar.Id]bool{}
	for _, readRef := range body.GetRefs() {
		refId, err := sidecar.IdFromBytes(readRef.GetRefId())
		if err != nil || seen[refId] {
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
			return
		}
		seen[refId] = true
		refs = append(refs, &readStreamRef{refId: refId, pinVersion: readRef.GetPinVersion()})
		request.NoteRefIds(refId)
	}
	repo, err := self.repos.Read(ctx, request.Cluster, request.RepoId)
	if !self.answerTransition(request, err) {
		return
	}
	if !sidecar.EvsRepoKindRecordClass(protocol.RepoKind(repo.Object.GetKind())) {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	barrierKey := sidecar.EvsKeyId(request.RepoId)
	testHookBarrier(BarrierReadStreamsBefore, barrierKey)
	errs := make([]error, len(refs))
	var waitGroup sync.WaitGroup
	for i, ref := range refs {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			ref.head, errs[i] = self.heads.ReadCached(ctx, request.Cluster, request.RepoId, ref.refId, ref.pinVersion, false)
		}()
	}
	waitGroup.Wait()
	testHookBarrier(BarrierReadStreamsAfter, barrierKey)
	for i, ref := range refs {
		if errs[i] != nil {
			request.Unavailable(nil)
			return
		}
		head := ref.head.Head
		if !ref.head.Absent() && evsHeadExists(head) &&
			(head.GetRefKind() != uint32(protocol.EvsRefKind_EVS_REF_OWNED) || head.GetRefMode() != uint32(protocol.EvsRefMode_EVS_REF_FILE)) {
			// only a writer's own stream is read so
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
			return
		}
	}
	if request.answered {
		return
	}
	request.answered = true
	request.status = http.StatusOK
	request.Writer.Header().Set("Content-Type", evsContentType)
	request.Writer.WriteHeader(http.StatusOK)
	stream := &readStream{request: request}
	stream.flusher, _ = request.Writer.(http.Flusher)
	served := false
	spent := false
	for _, ref := range refs {
		read := &readAttempt{
			engine: self, request: request, settings: settings, ctx: ctx, cluster: request.Cluster, repoId: request.RepoId,
			refId: ref.refId, body: body, head: ref.head,
		}
		if !stream.frame(&protocol.EvsReadFrame{Head: read.headSummary()}) {
			return
		}
		head := ref.head.Head
		if ref.head.Absent() || !evsHeadExists(head) || head.GetVersion() <= ref.pinVersion {
			continue
		}
		if spent {
			if !stream.frame(&protocol.EvsReadFrame{More: ref.pinVersion + 1}) {
				return
			}
			continue
		}
		if ref.pinVersion+1 < EvsHeadWindowFirstVersion(head) {
			if !stream.frame(&protocol.EvsReadFrame{Behind: ref.pinVersion + 1}) {
				return
			}
			continue
		}
		read.pushes = newReadPushes(self, ctx, request.Cluster, request.RepoId, ref.refId, head)
		for version := ref.pinVersion + 1; version <= head.GetVersion(); version += 1 {
			version := version
			objects, err := read.streamVersionObjects(version)
			if err != nil {
				if errors.Is(err, ErrEvsStatementMismatch) {
					self.log.Errorf("[evs] alarm read streams: repo %s ref %s: %v", sidecar.EvsKeyId(request.RepoId), sidecar.EvsKeyId(ref.refId), err)
					self.metrics.alarms.Add(1, "read")
				}
				// the 200 is written: the error frame ends the reply in its end frame's place (QD-662)
				stream.fail("stream_version_failed", err)
				return
			}
			if served && settings.ReadStreamMaxByteCount < request.replyByteCount+objects.byteCount() {
				spent = true
				if !stream.frame(&protocol.EvsReadFrame{More: version}) {
					return
				}
				break
			}
			if !read.streamVersion(stream, objects) {
				return
			}
			served = true
		}
	}
	stream.frame(&protocol.EvsReadFrame{End: true})
}

// What one version of a stream sends beyond its head: its statement, its records, and what its entries name.
type readStreamVersion struct {
	version   uint64
	statement []byte
	pushId    []byte
	// the push record, then a sealed push's part records by part number
	records [][]byte
	// the segment ranges its entries' chains name, the keyed header of each segment once, and the slots they and the
	// push name, each once
	ranges  []*protocol.EvsReadRange
	slotIds [][]byte
	// what the budget counts a slot as before it is read (ReadStreamSlotEstimateByteCount)
	slotEstimateByteCount int64
}

// What the version will cost the reply, its segment ranges and slots by their sizes, before any of it is read.
func (self *readStreamVersion) byteCount() int64 {
	count := int64(len(self.statement))
	for _, record := range self.records {
		count += int64(len(record))
	}
	for _, readRange := range self.ranges {
		count += int64(readRange.GetLength())
	}
	// a slot object holds a few wrapped keys
	count += int64(len(self.slotIds)) * self.slotEstimateByteCount
	return count
}

// The version's statement, records and the objects its entries name.
func (self *readAttempt) streamVersionObjects(version uint64) (*readStreamVersion, error) {
	push, err := self.pushes.at(version)
	if err != nil {
		return nil, err
	}
	if err := self.pushes.readRecord(push); err != nil {
		return nil, err
	}
	recordBytes, err := self.engine.readRecordBytesAt(self.ctx, self.cluster, self.repoId, self.refId, push.entry.Place)
	if err != nil {
		return nil, err
	}
	objects := &readStreamVersion{
		version: version, statement: push.statement.Bytes, pushId: push.statement.Push.GetPushId(), records: [][]byte{recordBytes},
		slotEstimateByteCount: self.settings.ReadStreamSlotEstimateByteCount,
	}
	changes := []*sidecar.EvsCheckedChange{}
	newObjects := []*sidecar.EvsNewObject{}
	if push.sealParts == nil {
		changes, newObjects = push.payload.Changes, push.payload.NewObjects
	} else {
		// a sealed push's parts, read and checked whole as the seal took them, for its new objects
		parts := [][]byte{}
		for part := range push.sealParts {
			partRecord, err := self.engine.readRecordBytesAt(self.ctx, self.cluster, self.repoId, self.refId, push.sealParts[part].Place)
			if err != nil {
				return nil, err
			}
			objects.records = append(objects.records, partRecord)
			record, err := sidecar.ParseEvsBatchRecord(partRecord)
			if err != nil {
				return nil, fmt.Errorf("%w: a seal's part place holds another record", ErrEvsStatementMismatch)
			}
			// a part record, or a re-seeded push's part, a reseed record holding a part's body (QD-818)
			_, partBytes, _, _, err := sidecar.ParseEvsSealPartRecord(record)
			if err != nil {
				return nil, fmt.Errorf("%w: a seal's part place holds another record: %w", ErrEvsStatementMismatch, err)
			}
			parts = append(parts, partBytes)
		}
		payload, _, err := sidecar.EvsCheckStoredSeal(push.statement, parts)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		changes, newObjects = payload.Changes, payload.NewObjects
	}
	keyedHeader := uint32(sidecar.EvsSegmentHeaderByteCount + sidecar.EvsWrappedKeyByteCount)
	// a segment's ranges: from its start through the furthest record named while that stays within
	// ReadSegmentWholeByteCount, which covers its header; past it, the keyed header and each record exactly
	segmentEnds := map[string]uint32{}
	segmentOrder := [][]byte{}
	segmentHeaders := map[string]bool{}
	slots := map[string]bool{}
	addSlot := func(slotId []byte) {
		if len(slotId) == 16 && !slots[string(slotId)] {
			slots[string(slotId)] = true
			objects.slotIds = append(objects.slotIds, slotId)
		}
	}
	for _, change := range changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
		}
		for _, locator := range entry.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT {
				continue
			}
			id := string(locator.GetId())
			end := locator.GetOffset() + locator.GetLength()
			if int64(end) <= self.settings.ReadSegmentWholeByteCount {
				if _, ok := segmentEnds[id]; !ok {
					segmentOrder = append(segmentOrder, locator.GetId())
				}
				segmentEnds[id] = max(segmentEnds[id], end, keyedHeader)
				continue
			}
			if !segmentHeaders[id] {
				segmentHeaders[id] = true
				objects.ranges = append(objects.ranges, &protocol.EvsReadRange{SegmentId: locator.GetId(), Length: keyedHeader})
			}
			objects.ranges = append(objects.ranges, &protocol.EvsReadRange{SegmentId: locator.GetId(), Offset: locator.GetOffset(), Length: locator.GetLength()})
		}
		for _, slotId := range entry.GetSlotIds() {
			addSlot(slotId)
		}
	}
	for _, segmentId := range segmentOrder {
		objects.ranges = append(objects.ranges, &protocol.EvsReadRange{SegmentId: segmentId, Length: segmentEnds[string(segmentId)]})
	}
	for _, object := range newObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			addSlot(object.Id)
		}
	}
	return objects, nil
}

// One version's frames: the statement, its records, then each range and slot. false once the stream failed.
func (self *readAttempt) streamVersion(stream *readStream, objects *readStreamVersion) bool {
	if !stream.frame(&protocol.EvsReadFrame{Statement: &protocol.EvsReadStatement{Version: objects.version, Statement: objects.statement}}) {
		return false
	}
	for number, record := range objects.records {
		if !stream.object(self.settings, protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD, objects.pushId, uint64(number), 0, bytes.NewReader(record)) {
			return false
		}
	}
	for _, readRange := range objects.ranges {
		if !self.streamExactRange(stream, readRange) {
			return false
		}
	}
	for _, slotId := range objects.slotIds {
		object, err := self.cluster.Get(self.ctx, SlotKey(self.repoId, sidecar.Id(slotId)))
		if !self.streamObject(stream, protocol.EvsReadObjectKind_EVS_READ_OBJECT_SLOT, slotId, 0, object, err) {
			return false
		}
	}
	return true
}

// One segment range exactly as named: the streams read sends what each record needs and no more of a segment.
func (self *readAttempt) streamExactRange(stream *readStream, readRange *protocol.EvsReadRange) bool {
	kind := protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT
	segmentId := [32]byte(readRange.GetSegmentId())
	object, err := self.engine.segments.OpenSegment(self.ctx, self.cluster, self.repoId, segmentId, int64(readRange.GetOffset()), int64(readRange.GetLength()))
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound), errors.Is(err, sidecar.ErrBlobRange):
		return stream.missing(kind, segmentId[:], 0)
	case err != nil:
		stream.fail("segment_read_failed", err)
		return false
	}
	defer object.Body.Close()
	return stream.object(self.settings, kind, segmentId[:], 0, readRange.GetOffset(), io.LimitReader(object.Body, int64(readRange.GetLength())))
}
