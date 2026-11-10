// A read reply's frames (§11.9's reply row; EVS1-M2-14): u32be(length) | EvsReadFrame, the head summary first, then
// each statement after the pin, `behind`, each path, then the objects the request names, the last frame with end
// set (sidecar.EncodeEvsReadFrame). Objects are streamed as they are read, in round 2:
//
//	slots     slot/<repo>/<id>, whole; a 404 answers missing
//	maps      pmap/<repo>/<ref>/<p>/<map>/<part>/_, whole, over frames past 1 MiB
//	pages     log/<repo>/<ref>/<n>, this process's cache, the object, or its container through pidx/
//	records   a push's record at the place its version's entry names, or a part's at the place its seal names
//	ranges    a segment through SegmentLocator: up to 256 KiB read whole from offset 0, larger ones in 64 KiB-aligned
//	          ranges covering what was asked, each range over frames past 1 MiB, offset naming each frame's first byte
//
// The status is 200 once the first frame is written, so a read that fails afterwards ends the stream short of its
// last frame, which the client reads as ErrEvsReplyInvalid and retries; the service log keeps the failure's note.

package evsservice

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The reply's frames on their way out.
type readStream struct {
	request *EvsRequest
	flusher http.Flusher
	failed  bool
}

// Starts the 200 and streams reply, then the objects, then the end frame.
func (self *readAttempt) stream(reply *readReply) {
	request := self.request
	if request.answered {
		return
	}
	request.answered = true
	request.status = http.StatusOK
	header := request.Writer.Header()
	header.Set("Content-Type", evsContentType)
	request.Writer.WriteHeader(http.StatusOK)
	stream := &readStream{request: request}
	stream.flusher, _ = request.Writer.(http.Flusher)
	if !stream.frame(&protocol.EvsReadFrame{Head: reply.head}) {
		return
	}
	for _, statement := range reply.statements {
		if !stream.frame(&protocol.EvsReadFrame{Statement: statement}) {
			return
		}
	}
	if reply.behind != 0 && !stream.frame(&protocol.EvsReadFrame{Behind: reply.behind}) {
		return
	}
	for _, path := range reply.paths {
		if !stream.frame(&protocol.EvsReadFrame{Path: path}) {
			return
		}
	}
	if !self.streamObjects(stream) {
		return
	}
	stream.frame(&protocol.EvsReadFrame{End: true})
}

// One frame, flushed. false once the stream has failed, after which nothing more is written.
func (self *readStream) frame(frame *protocol.EvsReadFrame) bool {
	if self.failed {
		return false
	}
	frameBytes, err := sidecar.EncodeEvsReadFrame(frame)
	if err == nil {
		_, err = self.request.Writer.Write(frameBytes)
	}
	if err != nil {
		self.failed = true
		self.request.Note("stream_failed")
		return false
	}
	self.request.replyByteCount += int64(len(frameBytes))
	if self.flusher != nil {
		self.flusher.Flush()
	}
	return true
}

// An object's bytes, over frames of at most ReadFrameByteCount, from offset.
func (self *readStream) object(settings *EvsSettings, kind protocol.EvsReadObjectKind, id []byte, number uint64, offset uint32, body io.Reader) bool {
	buffer := make([]byte, settings.ReadFrameByteCount)
	at := offset
	sent := false
	for {
		n, err := io.ReadFull(body, buffer)
		if 0 < n {
			if !self.frame(&protocol.EvsReadFrame{Object: &protocol.EvsReadObject{Kind: kind, Id: id, Number: number, Offset: at, Body: buffer[:n]}}) {
				return false
			}
			at += uint32(n)
			sent = true
		}
		switch {
		case err == nil:
			continue
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			if !sent {
				// an empty object still answers one frame, so the client knows it was found
				return self.frame(&protocol.EvsReadFrame{Object: &protocol.EvsReadObject{Kind: kind, Id: id, Number: number, Offset: at}})
			}
			return true
		default:
			self.failed = true
			self.request.Note("object_read_failed")
			return false
		}
	}
}

// An object evs found no copy of.
func (self *readStream) missing(kind protocol.EvsReadObjectKind, id []byte, number uint64) bool {
	return self.frame(&protocol.EvsReadFrame{Object: &protocol.EvsReadObject{Kind: kind, Id: id, Number: number, Missing: true}})
}

// Round 2's objects, in the request's order: slots, maps, log pages, push records, then segment ranges.
func (self *readAttempt) streamObjects(stream *readStream) bool {
	engine := self.engine
	body := self.body
	for _, slotId := range body.GetSlotIds() {
		object, err := self.cluster.Get(self.ctx, SlotKey(self.repoId, sidecar.Id(slotId)))
		if !self.streamObject(stream, protocol.EvsReadObjectKind_EVS_READ_OBJECT_SLOT, slotId, 0, object, err) {
			return false
		}
	}
	for _, readMap := range body.GetMaps() {
		object, err := self.cluster.Get(self.ctx, PathMapKey(self.repoId, self.refId, readMap.GetPathEpoch(), readMap.GetMapSha256(), readMap.GetPart()))
		if !self.streamObject(stream, protocol.EvsReadObjectKind_EVS_READ_OBJECT_MAP_PART, readMap.GetMapSha256(), uint64(readMap.GetPart()), object, err) {
			return false
		}
	}
	for _, page := range body.GetLogPages() {
		logPage, err := engine.readLogPage(self.ctx, self.cluster, self.repoId, self.refId, page)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound), errors.Is(err, ErrEvsRecordEvacuated):
			if !stream.missing(protocol.EvsReadObjectKind_EVS_READ_OBJECT_LOG_PAGE, nil, page) {
				return false
			}
		case err != nil:
			stream.failed = true
			self.request.Note("log_page_read_failed")
			return false
		default:
			if !stream.object(self.settings, protocol.EvsReadObjectKind_EVS_READ_OBJECT_LOG_PAGE, nil, page, 0, bytes.NewReader(logPage.Bytes)) {
				return false
			}
		}
	}
	for _, readPush := range body.GetPushes() {
		if !self.streamPushRecord(stream, readPush) {
			return false
		}
	}
	for _, readRange := range body.GetRanges() {
		if !self.streamRange(stream, readRange) {
			return false
		}
	}
	return true
}

// One whole object, or missing on a 404.
func (self *readAttempt) streamObject(stream *readStream, kind protocol.EvsReadObjectKind, id []byte, number uint64, object *sidecar.BlobObject, err error) bool {
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return stream.missing(kind, id, number)
	case err != nil:
		stream.failed = true
		self.request.Note("object_read_failed")
		return false
	}
	defer object.Body.Close()
	return stream.object(self.settings, kind, id, number, 0, object.Body)
}

// A push's record, or one of its parts' (§11.9's request row: push records and parts by push id), at the place the
// version's entry or its seal names; one the head does not name as asked answers missing.
func (self *readAttempt) streamPushRecord(stream *readStream, readPush *protocol.EvsReadPush) bool {
	kind := protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD
	pushId := readPush.GetPushId()
	number := uint64(readPush.GetPart())
	push, err := self.pushes.at(readPush.GetVersion())
	if err != nil || push.entry.PushId != sidecar.Id(pushId) {
		return stream.missing(kind, pushId, number)
	}
	place := push.entry.Place
	if 0 < readPush.GetPart() {
		if err := self.pushes.readRecord(push); err != nil || push.sealParts == nil || len(push.sealParts) < int(readPush.GetPart()) {
			return stream.missing(kind, pushId, number)
		}
		place = push.sealParts[readPush.GetPart()-1].Place
	}
	recordBytes, err := self.engine.readRecordBytesAt(self.ctx, self.cluster, self.repoId, self.refId, place)
	switch {
	case errors.Is(err, ErrEvsRecordEvacuated), errors.Is(err, sidecar.ErrBlobNotFound):
		return stream.missing(kind, pushId, number)
	case err != nil:
		stream.failed = true
		self.request.Note("record_read_failed")
		return false
	}
	return stream.object(self.settings, kind, pushId, number, 0, bytes.NewReader(recordBytes))
}

// One segment range: whole up to ReadSegmentWholeByteCount, else the aligned range covering it (§11.9's rounds
// row). A segment evs holds no copy of answers missing.
func (self *readAttempt) streamRange(stream *readStream, readRange *protocol.EvsReadRange) bool {
	kind := protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT
	segmentId := [32]byte(readRange.GetSegmentId())
	offset := int64(readRange.GetOffset())
	end := offset + int64(readRange.GetLength())
	from, byteCount := int64(0), int64(0)
	if self.settings.ReadSegmentWholeByteCount < end {
		align := self.settings.ReadSegmentRangeAlign
		from = offset - offset%align
		byteCount = (end - from + align - 1) / align * align
	}
	object, err := self.engine.segments.OpenSegment(self.ctx, self.cluster, self.repoId, segmentId, from, byteCount)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound), errors.Is(err, sidecar.ErrBlobRange):
		return stream.missing(kind, segmentId[:], 0)
	case err != nil:
		stream.failed = true
		self.request.Note("segment_read_failed")
		return false
	}
	defer object.Body.Close()
	return stream.object(self.settings, kind, segmentId[:], 0, uint32(from), object.Body)
}
