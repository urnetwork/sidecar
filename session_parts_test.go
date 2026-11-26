//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.16's caps and settings row for the journal's parts (CTXH-M11-03; D-CTXH-3, Q-CTXH-8): a 9 MiB
// result is two blobs, its node within 16 KiB and the part rebuilt whole from them; a 65 MiB part is kept by hash and
// size, omitted, the run's coverage counting oversize; the run-hour budget holds, the next hour's parts whole again;
// and a part the run holds already names its blobs again. External, as session_journal_test.go.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A 9 MiB tool result is one part in two session_blob pieces, 8 MiB and 1 MiB, its node's item within its cap, its
// reference at the part's pointer, and the part's bytes the pieces in order.
func TestSessionNineMiBResultIsTwoBlobs(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	text := strings.Repeat("0123456789abcdef", 9*1024*1024/16)
	journaled := journalWorld.journalNodes(run, testSessionToolResult("result", "", "bash", text, "", nil))
	if len(journaled[0].Parts) != 1 || len(journaled[0].Parts[0].GetBlobEntryIds()) != 2 || journaled[0].Parts[0].GetOmitted() {
		t.Fatalf("a 9 MiB result: %d parts", len(journaled[0].Parts))
	}
	nodes, blobs, _ := journalWorld.stored()
	node := nodes[journaled[0].NodeId]
	settings := sidecar.DefaultRecordBodySettings()
	if settings.SessionItemByteCount < len(node.GetItem()) || bytes.Contains(node.GetItem(), []byte("0123456789abcdef0123")) {
		t.Errorf("the node's item holds %d bytes", len(node.GetItem()))
	}
	part := node.GetParts()[0]
	if part.GetPointer() != "/message/content/0/text" || part.GetSize() != uint64(len(text)) {
		t.Errorf("the part at %s of %d bytes", part.GetPointer(), part.GetSize())
	}
	pieces := []*protocol.SessionBlobBody{}
	for _, blobId := range part.GetBlobEntryIds() {
		pieces = append(pieces, blobs[sidecar.Id(blobId)])
	}
	if len(pieces[0].GetContent()) != settings.BlobByteCount || len(pieces[1].GetContent()) != 1024*1024 {
		t.Errorf("pieces of %d and %d bytes", len(pieces[0].GetContent()), len(pieces[1].GetContent()))
	}
	assembled, err := sidecar.SessionPartAssemble(part, pieces)
	if err != nil || string(assembled) != text {
		t.Fatalf("the part rebuilt: %v", err)
	}
	restored, err := sidecar.SessionItemRestore(node.GetItem(), node.GetParts(), map[string][]byte{part.GetPointer(): assembled})
	if err != nil || !bytes.Contains(restored, []byte(text[:64])) {
		t.Errorf("the item restored: %v", err)
	}
	if err := sidecar.SessionNodeCheck(node, nil); err != nil {
		t.Errorf("the node fails its check: %v", err)
	}
}

// A part past 64 MiB is kept by hash and size alone, omitted, with no blobs, and the run's coverage counts oversize.
func TestSessionSixtyFiveMiBPartOmittedOversize(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	text := strings.Repeat("x", 65*1024*1024)
	journaled := journalWorld.journalNodes(run, testSessionToolResult("huge", "", "bash", text, "", nil))
	part := journaled[0].Parts[0]
	digest := sha256.Sum256([]byte(text))
	if !part.GetOmitted() || len(part.GetBlobEntryIds()) != 0 || part.GetSize() != uint64(len(text)) || !bytes.Equal(part.GetSha256(), digest[:]) {
		t.Fatalf("a 65 MiB part: omitted %v, %d blobs, %d bytes", part.GetOmitted(), len(part.GetBlobEntryIds()), part.GetSize())
	}
	if gaps := journalWorld.device.takeGaps(); !slices.Contains(gaps, run.RunId.String()+" "+sidecar.RecordCoverageGapOversize) {
		t.Errorf("gaps %v", gaps)
	}
	_, blobs, _ := journalWorld.stored()
	if len(blobs) != 0 {
		t.Errorf("%d blobs for an omitted part", len(blobs))
	}
}

// Past the run-hour budget a part goes by hash and size, oversize counted; the next run-hour keeps parts whole again.
func TestSessionRunHourBudgetHolds(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	ingest.RunHourByteCount = 1024 * 1024
	journalWorld := newTestSessionJournalWorld(t, nil, ingest)
	run := testSessionRun()
	text := strings.Repeat("y", 600*1024)
	first := journalWorld.journalNodes(run, testSessionToolResult("first", "", "bash", text, "", nil))
	second := journalWorld.journalNodes(run, testSessionToolResult("second", "first", "bash", text+"z", "", nil))
	if first[0].Parts[0].GetOmitted() || !second[0].Parts[0].GetOmitted() {
		t.Fatalf("within the budget: omitted %v, past it: omitted %v", first[0].Parts[0].GetOmitted(), second[0].Parts[0].GetOmitted())
	}
	if gaps := journalWorld.device.takeGaps(); !slices.Equal(gaps, []string{run.RunId.String() + " " + sidecar.RecordCoverageGapOversize}) {
		t.Errorf("gaps %v", gaps)
	}
	journalWorld.world.clock.Advance(ingest.RunHourInterval + time.Second)
	third := journalWorld.journalNodes(run, testSessionToolResult("third", "second", "bash", text+"w", "", nil))
	if third[0].Parts[0].GetOmitted() {
		t.Error("the next run-hour omitted a part within its budget")
	}
}

// A part the run already holds names the blobs it was written to before, writing no bytes again.
func TestSessionPartTheRunHoldsNamesItsBlobsAgain(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	text := strings.Repeat("a long synthetic result\n", 2048)
	first := journalWorld.journalNodes(run, testSessionToolResult("first", "", "read", text, "", nil))
	second := journalWorld.journalNodes(run, testSessionToolResult("second", "first", "read", text, "", nil))
	if second[0].SameAs != nil {
		t.Fatal("two results with other call ids are one item")
	}
	if !slices.EqualFunc(first[0].Parts[0].GetBlobEntryIds(), second[0].Parts[0].GetBlobEntryIds(), bytes.Equal) {
		t.Error("the second result's part wrote its bytes again")
	}
	_, blobs, _ := journalWorld.stored()
	if len(blobs) != 1 {
		t.Errorf("%d blobs for one part read twice", len(blobs))
	}
}
