// QD-1402: the routes mark exactly the store requests whose bodies move at a client's own pace
// (sidecar.WithBlobClientPaced), which the file clusters send outside their cap on a host's connections: a segment
// upload's PutStream, and the slots, map parts and segment ranges a read streams to its client; never a push's reads,
// a read's rounds or the pages and records it reads whole.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A segment upload streams its client's body to seg/ at the client's pace, its one marked request.
func TestSegmentUploadGoesAtItsClientsPace(t *testing.T) {
	fixture := newUploadFixture(t)
	segment := testSegment(fixture.repoId, 64*1024, 0x5a)
	segmentId := sha256.Sum256(segment)
	fixture.receipt(fixture.upload(fixture.writer, "rw", segment, segmentId, false))
	want := []string{sidecartest.FaultOpPut + " " + SegmentKey(fixture.repoId, segmentId)}
	if got := fixture.host.Blobs.ClientPacedRequests("seg-1"); !slices.Equal(got, want) {
		t.Fatalf("client-paced requests on seg-1: %v, want %v", got, want)
	}
	if got := fixture.host.Blobs.ClientPacedRequests("meta-1"); len(got) != 0 {
		t.Fatalf("client-paced requests on meta-1: %v", got)
	}
}

// A push marks none of its requests. A read marks the GETs of the slot, the map part and the segment range it
// streams, found or missing, and nothing it reads whole: its statements, the push record it names, its pages.
func TestReadStreamsItsObjectsAtItsClientsPace(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	slotId, slotObject, slotBody := checkTestSlot(t, "slot a")
	plan := fixture.plan()
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: checkTestPath("a"), EntryVersion: fixture.check.fileEntry(plan, 1, nil, slotId),
	})
	plan.NewObjects = append(plan.NewObjects, slotObject)
	plan.SlotBodies = append(plan.SlotBodies, slotBody)
	fixture.requireCommitted(fixture.push(plan), 1)
	fixture.awaitStepEights()
	for _, clusterId := range []string{"meta-1", "seg-1"} {
		if got := fixture.host.Blobs.ClientPacedRequests(clusterId); len(got) != 0 {
			t.Fatalf("a push's client-paced requests on %s: %v", clusterId, got)
		}
	}

	readMap := &protocol.EvsReadMap{PathEpoch: 1, MapSha256: bytes.Repeat([]byte{7}, 32), Part: 1}
	segmentId := [32]byte(bytes.Repeat([]byte{9}, 32))
	reply := fixture.read(token, &protocol.EvsReadRequest{
		RefId:   fixture.check.refId.Bytes(),
		SlotIds: [][]byte{slotId.Bytes()},
		Maps:    []*protocol.EvsReadMap{readMap},
		Pushes:  []*protocol.EvsReadPush{{PushId: plan.PushId.Bytes(), Version: 1}},
		Ranges:  []*protocol.EvsReadRange{{SegmentId: segmentId[:], Offset: 0, Length: 16}},
	})
	if len(reply.objects) != 4 || !bytes.Equal(reply.objects[0].GetBody(), slotBody) || reply.objects[2].GetMissing() {
		t.Fatalf("objects %v", reply.objects)
	}
	wantMetadata := []string{
		sidecartest.FaultOpGet + " " + SlotKey(fixture.check.repoId, slotId),
		sidecartest.FaultOpGet + " " + PathMapKey(fixture.check.repoId, fixture.check.refId, readMap.GetPathEpoch(), readMap.GetMapSha256(), readMap.GetPart()),
	}
	if got := fixture.host.Blobs.ClientPacedRequests("meta-1"); !slices.Equal(got, wantMetadata) {
		t.Fatalf("client-paced requests on meta-1: %v, want %v", got, wantMetadata)
	}
	wantSegment := []string{sidecartest.FaultOpGet + " " + SegmentKey(fixture.check.repoId, segmentId)}
	if got := fixture.host.Blobs.ClientPacedRequests("seg-1"); !slices.Equal(got, wantSegment) {
		t.Fatalf("client-paced requests on seg-1: %v, want %v", got, wantSegment)
	}
}
