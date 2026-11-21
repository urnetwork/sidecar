//go:build !ios_extension

// MAIL-M10-02's CUT through the search index's own eraser (IndexEraser), as NewMailEraser builds it over the mailbox's
// EvsRepo, on MAIL-M10-01's evs stand-in with the index on: the documents mail lists are the ones the index's writer
// keyed, so the CUT it commits masks them and the next ingest's push leaves them out. The stand-in's erasure ref
// stays at version zero. The ERASEs and index files' rewrite run on mail's seam in mail_erase_index_test.go.

package sidecar

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// An authority under which every device erases.
type mailEraseEvsTestAuthority struct{}

func (self *mailEraseEvsTestAuthority) Erases(repoId Id, sidecarId Id) bool {
	return true
}

// A format-2 mailbox's eraser reaches the index's eraser on the mailbox's main ref: the doc_key it lists for a message
// is the one the ingest's index delta holds it under, at the m/ file's version and one chunk; its CUT lands in the
// ref's erasure set under the erasure's id and moves the ref's index epoch; a CUT committed again pushes nothing; and
// the next ingest's head holds the kept and the new message and not the erased one.
func TestMailEraseFormat2CutListsTheDocumentsTheIndexHolds(t *testing.T) {
	world := newMailIndexTestWorld(t, protocol.RepoKind_REPO_KIND_MAILBOX)
	ctx := context.Background()
	_, erasedPath := world.deposit(testMailIngestMessage("Tide tables", "high water at six"))
	_, keptPath := world.deposit(testMailIngestMessage("Ferry times", "the late boat sails at ten"))
	if pass := world.ingest(); pass.Ingested != 2 {
		t.Fatalf("the pass %+v", pass)
	}
	entries := testMailIndexHeadEntries(world.view())
	if testMailIndexEntryOf(entries, world.docKey(erasedPath)) == nil || testMailIndexEntryOf(entries, world.docKey(keptPath)) == nil {
		t.Fatal("the head lacks a message before the erasure")
	}
	eraser, err := NewMailEraser(&MailEraserArgs{
		Repo: world.writer.repo, SidecarId: world.writer.world.signer.sidecarId, Authority: &mailEraseEvsTestAuthority{}, Clock: world.writer.test.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	index, err := eraser.indexOf(ctx)
	if err != nil || index == nil {
		t.Fatalf("the index's side of a format-2 mailbox: %v", err)
	}
	month, messageId, ok := searchJoinMailPath(erasedPath)
	if !ok {
		t.Fatalf("the path %s", erasedPath)
	}
	key, err := index.docKey(erasedPath, 0)
	if err != nil || key != world.docKey(erasedPath) {
		t.Fatalf("mail's doc_key is not the index's: %v", err)
	}
	fileVersion := world.writer.entry(t, erasedPath).GetVersion()
	version, chunkCount, err := eraser.documentOf(ctx, index, erasedPath, fileVersion, 0)
	if err != nil || version != fileVersion || chunkCount != 1 {
		t.Fatalf("the message's documents: version %d, %d chunks, %v", version, chunkCount, err)
	}
	erasureId := NewId()
	messages := []mailErasedMessage{{Month: month, MessageId: messageId, Version: version, ChunkCount: chunkCount}}
	epochBefore := world.view().head.indexEpoch
	before, _ := world.writer.server.sentCounts()
	if listed, err := eraser.cut(ctx, index, erasureId, messages); err != nil || !listed {
		t.Fatalf("the CUT: %t, %v", listed, err)
	}
	if after, _ := world.writer.server.sentCounts(); after != before+1 {
		t.Fatalf("%d pushes for one CUT", after-before)
	}
	view := world.view()
	if view.erasureSet == nil || len(view.erasureSet.GetErasures()) != 1 {
		t.Fatalf("the erasure set after the CUT: %+v", view.erasureSet)
	}
	listedErasure := view.erasureSet.GetErasures()[0]
	if Id(listedErasure.GetErasureId()) != erasureId || len(listedErasure.GetDocs()) != 1 ||
		[indexIdByteCount]byte(listedErasure.GetDocs()[0].GetDocKey()) != key || listedErasure.GetDocs()[0].GetVersion() != fileVersion {
		t.Fatalf("the erasure the set lists: %d docs", len(listedErasure.GetDocs()))
	}
	if view.head.indexEpoch <= epochBefore {
		t.Fatalf("the index epoch %d after the CUT, %d before", view.head.indexEpoch, epochBefore)
	}
	// the same CUT again pushes nothing
	before, _ = world.writer.server.sentCounts()
	if listed, err := eraser.cut(ctx, index, erasureId, messages); err != nil || !listed {
		t.Fatalf("the CUT again: %t, %v", listed, err)
	}
	if after, _ := world.writer.server.sentCounts(); after != before {
		t.Fatalf("a CUT already listed pushed %d times", after-before)
	}
	_, laterPath := world.deposit(testMailIngestMessage("Harbor notice", "the quay is closed on sunday"))
	if pass := world.ingest(); pass.Ingested != 1 {
		t.Fatalf("the later pass %+v", pass)
	}
	entries = testMailIndexHeadEntries(world.view())
	if testMailIndexEntryOf(entries, key) != nil {
		t.Fatal("the head still holds the erased message's document after the CUT")
	}
	if testMailIndexEntryOf(entries, world.docKey(keptPath)) == nil || testMailIndexEntryOf(entries, world.docKey(laterPath)) == nil {
		t.Fatal("the head lost a message the CUT did not list")
	}
}
