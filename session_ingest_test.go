//go:build !sidecar_http

// DESIGN-COMPUTE §24.5's session entries through a depositor and a team network (CTXH-M11-02): a device the vault does
// not consent deposits a session entry whole, and its ingester files it as its writer would, header at e/<n> and body
// at s/<n> of its own stream, which a reader verifies deferred and fetches; and in a team network a session entry
// goes to its author's vault alone, never to the team record (I-20). External, as record_ingest_test.go.

package sidecar_test

import (
	"bytes"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A deposited session entry is ingested apart: the ingester's stream holds its header at e/1, body_apart set, and its
// body at s/1; a reader reads it deferred, its writer and chain the depositor's, and fetches the node written.
func TestSessionIngestedEntryFiledApart(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	depositorRecord := depositor.open()
	runId := sidecar.NewId()
	draft := testSessionDraft(&runId, "deposited history")
	testRecordAppend(t, depositorRecord, draft)
	if err := depositorRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	record := ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, record, world)
	versions, err := world.streams.For(world.readerId).ReadStream(t.Context(), world.vaultId, ingester.sidecarId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 || len(versions[0].Entries) != 1 || len(versions[0].Bodies) != 1 ||
		versions[0].Entries[0].Path != "e/0/0/1" || versions[0].Bodies[0].Path != "s/0/0/1" {
		t.Fatalf("the ingester's stream: %d versions", len(versions))
	}
	entry := &protocol.RecordEntry{}
	if err := proto.Unmarshal(versions[0].Entries[0].Entry, entry); err != nil {
		t.Fatal(err)
	}
	if !entry.GetBodyApart() || len(entry.GetSealedBody()) != 0 {
		t.Errorf("the ingested entry at e/1: body apart %v, %d body bytes", entry.GetBodyApart(), len(entry.GetSealedBody()))
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 1 || entries[0].State != sidecar.RecordEntryDeferred ||
		!bytes.Equal(entries[0].Header.Header.GetWriterSidecarId(), depositor.sidecarId[:]) || entries[0].Header.Header.GetSeq() != 1 {
		t.Fatalf("the reader holds %v", testSessionStates(entries))
	}
	if fetched, err := reader.reader.FetchBodies(t.Context(), world.vaultId, nil); err != nil || fetched != 1 {
		t.Fatalf("fetched %d: %v", fetched, err)
	}
	fetched := reader.reader.Entries(world.vaultId)[0]
	body := &protocol.SessionEntryBody{}
	if proto.Unmarshal(fetched.Body, body) != nil || !proto.Equal(body, draft.Body) {
		t.Error("the fetched body is not the node deposited")
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 0 {
		t.Errorf("%d deposits left", len(deposits))
	}
}

// In a team network a session entry and a blob go to the author's vault alone: the team record takes none.
func TestSessionKindsRoutedToTheVaultAlone(t *testing.T) {
	world := newTestTeamWorld(t)
	device := world.memberDevice(true)
	admin := world.adminDevice()
	record := device.open()
	runId := sidecar.NewId()
	world.runs.StartRun(runId)
	refs := testRecordAppendAll(t, record, testSessionDraft(&runId, "the vault's alone"))
	part := bytes.Repeat([]byte{0x42}, 64)
	refs = append(refs, testRecordAppendAll(t, record, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindSessionBlob, Source: sidecar.RecordSourceObserved, RunId: &runId,
		Body: &protocol.SessionBlobBody{PartSha256: bytes.Repeat([]byte{0x01}, 32), Index: 0, Count: 1, Content: part},
	})...)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if ref.LogId != world.vaultId {
			t.Errorf("an entry went to %s", ref.LogId)
		}
	}
	if count := len(world.teamDeposits(device.sidecarId, admin.sidecarId)); count != 0 {
		t.Errorf("the team record took %d entries", count)
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world.testRecordWorld)
	kinds := []sidecar.RecordKind{}
	for _, entry := range entries {
		kinds = append(kinds, entry.Kind())
	}
	if !slices.Equal(kinds, []sidecar.RecordKind{sidecar.RecordKindSessionEntry, sidecar.RecordKindSessionBlob}) {
		t.Errorf("the vault holds %v", kinds)
	}
}
