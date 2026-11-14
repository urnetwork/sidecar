// Staged content on the read route (§11.7's kind 5, staged and reads rows; D-EVS-36, FI-6, FS-66; EVS2-M10-08). A
// staged segment is a one-record versionless version of at most 16 KiB that rode in its push's batch record, outside
// every hash (evs_staged.go). It has no object of its own until evacuation writes it to seg/<repo>/<id>, which it does
// before it deletes the batch, and only while its version is retained (evacuate_staged.go). Packs and parcels never
// hold staged bytes.
//
// A segment id alone names no push, so evs resolves a staged range through a version the same request names: a read
// that asks for a range of a staged segment names the path of the version that stages it, at that version, beside the
// range (the owner's rule that client reads stay version-addressed, plan-EVS2-small-readings#5). For each path reply
// that serves a version, evs notes the staged locators its entry version names with the push that committed it, and a
// range naming one of those ids is read
//
//	1. from that push's record, or for a push in parts the part's that holds the version's change, at the place
//	   its window entry, log page or seal names: this process's cache, else one range GET of its batch;
//	2. else, the batch gone or the record now a container's copy with no staged bytes, from seg/<repo>/<id>.
//
// The order is the retry the design asks for: a batch range that 404s is answered at seg/, never the other way, since
// evacuation writes seg/ first. One neither holds answers missing, and the reader decides: a replaced version's
// reader rereads the head, a newest version's alarms as for a missing segment (§11.9's collected row).
//
// A version the reply answers `collected` has none of its staged content served, whether or not its batch still
// holds it (read_collected.go's T): its ranges answer missing. A range of a staged id that no path of the request
// stages is read at seg/ alone, as any segment's is.
//
// Not safe for concurrent use: the notes live on one request.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One staged segment a path reply's version names.
type readStagedSegment struct {
	path *readPath
	// the version as served: its push's commit version and its change's leaf place
	served *protocol.EvsIndexVersion
	// the reply answered `collected` for the version
	collected bool
}

// Notes the staged segments the reply's version names, for the ranges that follow the path frames.
func (self *readAttempt) noteStaged(path *readPath, reply *protocol.EvsReadPathReply) {
	for _, id := range readReplyStagedIds(reply) {
		if self.staged == nil {
			self.staged = map[[sha256.Size]byte]*readStagedSegment{}
		}
		self.staged[id] = &readStagedSegment{path: path, served: reply.GetVersion(), collected: readReplyCollected(reply)}
	}
}

// The place of the record that carries staged's bytes: its push's record, or for a push in parts the part's that
// holds the version's change. nil when the push does not hold the version as served.
func (self *readAttempt) stagedRecordPlace(staged *readStagedSegment) (*protocol.EvsPlace, sidecar.Id, error) {
	push, err := self.pushes.at(staged.served.GetCommitVersion())
	if err != nil {
		return nil, sidecar.Id{}, err
	}
	if push.entry.PushId != sidecar.Id(staged.served.GetPushId()) {
		return nil, sidecar.Id{}, nil
	}
	if err := self.pushes.readRecord(push); err != nil {
		return nil, sidecar.Id{}, err
	}
	if push.sealParts == nil {
		return push.entry.Place, push.entry.PushId, nil
	}
	change, part, _, err := self.locate(push, staged.path, evsLeafPlaceOfVersion(staged.served), false)
	if err != nil || change == nil || part < 0 || len(push.sealParts) <= part {
		return nil, sidecar.Id{}, err
	}
	return push.sealParts[part].Place, push.entry.PushId, nil
}

// A record's bytes as its batch holds them, staged tail included: this process's cache, else one range GET of the
// batch. ErrEvsRecordEvacuated once the batch is gone. A cached copy that came from a container holds no staged bytes,
// which its caller finds by looking.
func (self *EvsEngine) readBatchRecordBytes(attempt *readAttempt, place *protocol.EvsPlace) ([]byte, error) {
	clusterId := attempt.cluster.ClusterId()
	if recordBytes, ok := self.records.Get(clusterId, place); ok {
		return recordBytes, nil
	}
	if _, err := ReadRecord(attempt.ctx, self.records, attempt.cluster, place); err != nil {
		return nil, err
	}
	if recordBytes, ok := self.records.Get(clusterId, place); ok {
		return recordBytes, nil
	}
	// a cache that keeps nothing: the batch's range once more
	object, err := attempt.cluster.GetRange(attempt.ctx, PlaceBatchKey(place), int64(place.GetOffset()), int64(place.GetLength()))
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return nil, ErrEvsRecordEvacuated
	case err != nil:
		return nil, err
	}
	defer object.Body.Close()
	recordBytes := &bytes.Buffer{}
	if _, err := recordBytes.ReadFrom(object.Body); err != nil {
		return nil, err
	}
	return recordBytes.Bytes(), nil
}

// The staged segment's bytes from its record while that record is batch-resident: nil, and no error, when the batch
// is gone or the record there holds no such staged segment, which sends the read to seg/.
func (self *readAttempt) stagedBytes(segmentId [sha256.Size]byte, staged *readStagedSegment) ([]byte, error) {
	place, pushId, err := self.stagedRecordPlace(staged)
	if errors.Is(err, ErrEvsRecordEvacuated) || errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil || place == nil {
		return nil, err
	}
	recordBytes, err := self.engine.readBatchRecordBytes(self, place)
	if errors.Is(err, ErrEvsRecordEvacuated) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	record, tail, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		return nil, err
	}
	if record.PushId != pushId || record.RepoId != self.repoId || record.RefId != self.refId || tail.Empty() {
		return nil, nil
	}
	segments, err := tail.StagedSegments()
	if err != nil {
		return nil, err
	}
	for _, segment := range segments {
		if sha256.Sum256(segment) == segmentId {
			return segment, nil
		}
	}
	return nil, nil
}

// A range of a staged segment one of the request's paths stages: see the file header. handled is false for a range
// that names none, which the caller reads as any segment's; ok is false once the stream has failed.
func (self *readAttempt) streamStagedRange(stream *readStream, readRange *protocol.EvsReadRange) (handled bool, ok bool) {
	if len(readRange.GetSegmentId()) != sha256.Size {
		return false, true
	}
	segmentId := [sha256.Size]byte(readRange.GetSegmentId())
	staged := self.staged[segmentId]
	if staged == nil {
		return false, true
	}
	kind := protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT
	if staged.collected {
		return true, stream.missing(kind, segmentId[:], 0)
	}
	segment, err := self.stagedBytes(segmentId, staged)
	if err != nil {
		stream.fail("staged_read_failed", err)
		return true, false
	}
	if segment == nil {
		// the batch's range is gone, or its record moved without its staged bytes: seg/, which evacuation wrote first
		return false, true
	}
	// a staged segment is at most 16 KiB, under the whole-read bound: served whole from offset 0, as a small segment is
	return true, stream.object(self.settings, kind, segmentId[:], 0, 0, bytes.NewReader(segment))
}
