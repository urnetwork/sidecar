package evsservice

// EVS2-M10-06's versionless uploads (§11.13's receipt row, §11.7's kind 5 row; FS-64's evs clauses): a kind-5 header
// naming the upload's push takes a receipt marked versionless, the mark inside the MAC, and an equal re-upload the
// same mark with no extra read; one naming another push, or from a network outside the format2 gate, gets 409
// VERSIONING and writes nothing; a versioned segment's equal bytes get an unmarked receipt; and a format-1 instance
// still refuses a kind-5 header FORMAT_UNSUPPORTED {needs_format: 2}.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A kind-5 segment of byteCount bytes for repoId at generation 1 naming pushId, then filler.
func testKind5Segment(repoId sidecar.Id, pushId sidecar.Id, byteCount int, fill byte) []byte {
	segment := testSegment(repoId, byteCount, fill)
	segment[4] = 2
	copy(segment[32:48], pushId[:])
	return segment
}

// The format2 gate open, or closed, to the fixture's network, beside evs's.
func (self *uploadFixture) setFormat2(open bool) {
	self.t.Helper()
	format2 := "{enabled: false}"
	if open {
		format2 = fmt.Sprintf("{enabled: true, networks: [%q]}", self.networkId.String())
	}
	text := fmt.Sprintf("sidecar:\n  evs: {enabled: true, networks: [%q]}\n  format2: %s\n", self.networkId.String(), format2)
	if err := self.host.Gates.Set(text); err != nil {
		self.t.Fatal(err)
	}
}

func TestUploadVersionlessMarksAKind5SegmentOfItsPush(t *testing.T) {
	fixture := newUploadFixture(t)
	fixture.setFormat2(true)
	pushId := testId("push")
	segment := testKind5Segment(fixture.repoId, pushId, 4096, 7)
	segmentId := sha256.Sum256(segment)
	receipt := fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	if !receipt.GetVersionless() {
		t.Fatal("a kind-5 segment of its push took an unmarked receipt")
	}
	if err := CheckUploadReceipt(fixture.keys, receipt, fixture.repoId, fixture.writer, fixture.clock.Now()); err != nil {
		t.Fatalf("the marked receipt does not verify: %v", err)
	}
	// the mark is inside the MAC: the receipt with the mark taken off does not verify
	unmarked := proto.Clone(receipt).(*protocol.EvsUploadReceipt)
	unmarked.Versionless = false
	if err := CheckUploadReceipt(fixture.keys, unmarked, fixture.repoId, fixture.writer, fixture.clock.Now()); err == nil {
		t.Fatal("a versionless receipt verified with its mark taken off")
	}
	// an equal re-upload carries an equal header, so it takes the same mark
	fixture.clock.Advance(time.Hour)
	again := fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	if !again.GetVersionless() || again.GetUploadMs() != receipt.GetUploadMs() {
		t.Fatalf("a re-upload's receipt: versionless %v, upload_ms %d", again.GetVersionless(), again.GetUploadMs())
	}
	// a versioned segment's equal bytes, as a format-1 header holds them, take an unmarked receipt
	versioned := testSegment(fixture.repoId, 4096, 7)
	versionedId := sha256.Sum256(versioned)
	if fixture.receipt(fixture.upload(fixture.writer, "rw", versioned, versionedId, false)).GetVersionless() {
		t.Fatal("a format-1 segment took a versionless receipt")
	}
}

func TestUploadVersionlessRefusesAnotherPushAndANetworkOutsideTheGate(t *testing.T) {
	fixture := newUploadFixture(t)
	fixture.setFormat2(true)
	other := testKind5Segment(fixture.repoId, testId("another push"), 4096, 8)
	otherId := sha256.Sum256(other)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", other, otherId, false), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)
	if fixture.object("seg-1", SegmentKey(fixture.repoId, otherId)) != nil {
		t.Fatal("another push's segment was stored")
	}
	fixture.setFormat2(false)
	own := testKind5Segment(fixture.repoId, testId("push"), 4096, 9)
	ownId := sha256.Sum256(own)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", own, ownId, false), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)
	if fixture.object("seg-1", SegmentKey(fixture.repoId, ownId)) != nil {
		t.Fatal("a segment from outside the gate was stored")
	}
	// a kind-5 header of another repo, or cut short, is malformed
	foreign := testKind5Segment(testId("other repo"), testId("push"), 4096, 10)
	fixture.setFormat2(true)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", foreign, sha256.Sum256(foreign), false), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	noGeneration := testKind5Segment(fixture.repoId, testId("push"), 4096, 11)
	binary.BigEndian.PutUint64(noGeneration[24:32], 0)
	requireRefusal(t, fixture.upload(fixture.writer, "rw", noGeneration, sha256.Sum256(noGeneration), false), http.StatusBadRequest, protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
}

func TestUploadVersionlessAtAFormat1InstanceNeedsFormat2(t *testing.T) {
	settings := DefaultEvsSettings()
	settings.InstanceFormat = sidecar.EvsRepoFormat1
	fixture := newUploadFixtureWith(t, settings)
	segment := testKind5Segment(fixture.repoId, testId("push"), 4096, 12)
	recorder := fixture.upload(fixture.writer, "rw", segment, sha256.Sum256(segment), false)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED)
	if refusalOf(t, recorder).GetNeedsFormat() != 2 {
		t.Fatal("a kind-5 header's refusal names no format")
	}
}
