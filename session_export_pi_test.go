//go:build !ios_extension && !sidecar_http && !js

// CTXH-M11-05's export and the addresses a run keeps (DESIGN-COMPUTE §24.6, §24.9, §24.16's Erasure and export row;
// D-CTXH-11, Q-CTXH-15) on sidecartest's streams: `ur harness export` refuses before it reads anything unconfirmed, and
// confirmed lands its disclosure entry, format pi, before it answers a line, answering none where the entry cannot
// land; its lines are Pi's v3 session JSONL, the header then every node with its parts put back from their blobs; every
// email address and phone number in them is hashed under record.redact.pii, as in `ur record export --bodies`, while
// the vault keeps them as typed, so a run read back after its daemon is killed, and continued on a phone after the app
// closed, still has the address the person typed and the attendees a calendar read returned. External, on
// session_journal_test.go's and session_continue_test.go's worlds.

package sidecar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The address the person types and the attendees a calendar read returns, which the vault keeps as written.
const (
	testSessionTypedAddress  = "bob@example.com"
	testSessionAttendee      = "carol@example.org"
	testSessionAttendeePhone = "+14155550123"
)

// A run whose prompt names an address and whose calendar read returns attendees, as the Harness journals it.
func testSessionAddressRun(t *testing.T, world *testSessionJournalWorld) *testSessionRecorder {
	t.Helper()
	recorder := newTestSessionRecorder(t, world)
	recorder.model = testSessionContinueModel
	system := recorder.message("", testSessionRebuildSystem("Keep the calendar."), "")
	user := recorder.message(system, testSessionRebuildUser("Invite "+testSessionTypedAddress+" to the launch."), "")
	callId := "call-calendar"
	asked := recorder.message(user, testSessionRebuildAssistant("", "", &sidecar.HarnessPiToolCall{Id: callId, Name: "calendar_read",
		Arguments: json.RawMessage(`{"day":"2027-01-15"}`)}), "")
	result := sidecar.NewHarnessPiEntryId()
	recorder.journal(sidecar.NewHarnessPiMessageEntry(result, asked, recorder.now(), testSessionRebuildResult(callId, "calendar_read",
		"Launch review, attendees "+testSessionAttendee+" and "+testSessionAttendeePhone+"; "+strings.Repeat("agenda notes ", 2000))),
		"", &sidecar.SessionToolResult{Name: "calendar_read", BuiltIn: true})
	recorder.call(result, system)
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return recorder
}

// The redactor the export hashes under, record.redact.pii's default, hash.
func testSessionExportRedactor(t *testing.T) *sidecar.Redactor {
	t.Helper()
	redactor, err := sidecar.NewRedactor(bytes.NewReader(bytes.Repeat([]byte{0x45}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return redactor
}

// The disclosure entries a device reads in the vault.
func testSessionDisclosures(t *testing.T, world *testSessionJournalWorld) []*protocol.DisclosureBody {
	t.Helper()
	record := world.world.device(true).open()
	if err := record.Reader().Sync(t.Context(), world.world.vaultId); err != nil {
		t.Fatal(err)
	}
	bodies := []*protocol.DisclosureBody{}
	entries, _ := record.Reader().EntriesOfKinds(world.world.vaultId, 0, sidecar.RecordKindDisclosure)
	for _, entry := range entries {
		body := &protocol.DisclosureBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// An export unconfirmed is refused before anything is read or written; one whose disclosure entry cannot land answers
// no line; confirmed, its disclosure entry, act export, format pi, naming the run with bodies, has landed in the vault
// when the lines come back.
func TestHarnessExportNeedsConfirmationAndWritesDisclosureFirst(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := testSessionAddressRun(t, world)
	exporter := world.record.SessionPiExport()
	if _, err := exporter.Export(t.Context(), &sidecar.SessionPiExportArgs{RunId: recorder.run.RunId}); !errors.Is(err, sidecar.ErrRecordExportUnconfirmed) {
		t.Fatalf("an unconfirmed export: %v", err)
	}
	if disclosures := testSessionDisclosures(t, world); len(disclosures) != 0 {
		t.Fatalf("an unconfirmed export filed %d disclosures", len(disclosures))
	}
	world.device.tap.setDown(true)
	exported, err := exporter.Export(t.Context(), &sidecar.SessionPiExportArgs{RunId: recorder.run.RunId, Confirmed: true, Redactor: testSessionExportRedactor(t)})
	if err == nil || exported != nil {
		t.Fatalf("an export whose record could not land answered %v, %v", exported, err)
	}
	world.device.tap.setDown(false)
	exported, err = exporter.Export(t.Context(), &sidecar.SessionPiExportArgs{RunId: recorder.run.RunId, Confirmed: true, Redactor: testSessionExportRedactor(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.Lines) == 0 || exported.ReceiptsOnly {
		t.Fatalf("the export: %+v", exported)
	}
	landed := false
	for _, body := range testSessionDisclosures(t, world) {
		if body.GetAct() == sidecar.RecordDisclosureActExport && body.GetFormat() == uint32(sidecar.RecordExportFormatPi) && body.GetBodies() &&
			bytes.Equal(body.GetRunId(), recorder.run.RunId.Bytes()) {
			landed = true
		}
	}
	if !landed {
		t.Fatal("the export's disclosure entry is not in the vault once its lines came back")
	}
}

// The export hashes the address the person typed and the attendees a calendar read returned, as `ur record export
// --bodies` does in kinds 54 and 55's lines, which then carry their hashed fields and no body or salt.
func TestHarnessExportHashesTypedAddress(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := testSessionAddressRun(t, world)
	redactor := testSessionExportRedactor(t)
	exported, err := world.record.SessionPiExport().Export(t.Context(), &sidecar.SessionPiExportArgs{RunId: recorder.run.RunId, Confirmed: true, Redactor: redactor})
	if err != nil {
		t.Fatal(err)
	}
	text := string(bytes.Join(exported.Lines, []byte("\n")))
	for _, value := range []string{testSessionTypedAddress, testSessionAttendee, testSessionAttendeePhone} {
		if strings.Contains(text, value) {
			t.Errorf("the pi export holds %q", value)
		}
	}
	if exported.PiiCount != 3 || !strings.Contains(text, "[REDACTED:pii-email:") || !strings.Contains(text, "[REDACTED:pii-phone:") {
		t.Fatalf("%d hashed, the markers: %v", exported.PiiCount, strings.Contains(text, "[REDACTED:"))
	}
	runId := recorder.run.RunId
	lines, err := world.record.Export().Export(t.Context(), &sidecar.RecordExportArgs{LogId: world.world.vaultId, RunId: &runId,
		Kinds: []sidecar.RecordKind{sidecar.RecordKindSessionEntry, sidecar.RecordKindSessionBlob}, Bodies: true,
		Format: sidecar.RecordExportFormatJsonl, Confirmed: true, Redactor: redactor})
	if err != nil {
		t.Fatal(err)
	}
	hashed := 0
	for _, line := range lines.Lines {
		decoded := map[string]any{}
		if err := json.Unmarshal(line, &decoded); err != nil {
			t.Fatal(err)
		}
		if _, ok := decoded["pii_hashed"]; ok {
			hashed += 1
			if _, ok := decoded["body"]; ok {
				t.Error("a hashed line carries its body as written")
			}
		}
		for _, value := range []string{testSessionTypedAddress, testSessionAttendee, testSessionAttendeePhone} {
			if bytes.Contains(line, []byte(value)) {
				t.Errorf("a record export line holds %q", value)
			}
		}
	}
	if hashed == 0 {
		t.Fatal("no record export line was hashed")
	}
}

// A run read back after its daemon is killed keeps the address the person typed and the attendees a calendar read
// returned, unhashed, and so does its continuation on a phone after the app closed: the vault spares kinds 54 and 55
// record.redact.pii's hashing (Q-CTXH-15), while the secret rules still applied.
func TestSessionResumedAfterKillKeepsTypedAddressAndAttendees(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := testSessionAddressRun(t, world)
	// the daemon is killed and comes back over what its stores hold
	world.open(nil)
	view, err := world.record.SessionReader().Open(t.Context(), world.world.vaultId, recorder.run.RunId)
	if err != nil {
		t.Fatal(err)
	}
	restored := []string{}
	for _, node := range view.Nodes {
		if node.Body == nil || node.Invalid != nil {
			t.Fatalf("a node not read back: %s %v", node.State, node.Invalid)
		}
		item, err := sidecar.SessionItemRestore(node.Body.GetItem(), node.Body.GetParts(), node.PartBytes)
		if err != nil {
			t.Fatal(err)
		}
		restored = append(restored, string(item))
	}
	text := strings.Join(restored, "\n")
	for _, value := range []string{testSessionTypedAddress, testSessionAttendee, testSessionAttendeePhone} {
		if !strings.Contains(text, value) {
			t.Errorf("the run read back lost %q", value)
		}
	}
	// the app closed; on its next start the phone continues the run from the vault
	phone := newTestSessionHarnessHost(t, world.world, true)
	phone.live.set(sidecar.AgentStateIdle, nil)
	continued, err := phone.continues.Continue(context.Background(), &sidecar.SessionContinueSpec{RunId: recorder.run.RunId})
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := phone.harness.Agent(continued.AgentId)
	phone.prompt(agent, "Send the invites.")
	sent := ""
	for _, message := range phone.router.made()[0].Messages {
		sent += message.Text() + "\n"
	}
	for _, value := range []string{testSessionTypedAddress, testSessionAttendee, testSessionAttendeePhone} {
		if !strings.Contains(sent, value) {
			t.Errorf("the continued run's request lost %q", value)
		}
	}
}

// The export is Pi's v3 session JSONL: its first line the session header, version 3, the run's id; each other line one
// node's entry, type, id and timestamp, its parent an entry of the file or none at its root; the calendar result's
// part, past the item cap and kept in blobs, put back whole.
func TestHarnessExportIsPiV3Jsonl(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := testSessionAddressRun(t, world)
	exported, err := world.record.SessionPiExport().Export(t.Context(), &sidecar.SessionPiExportArgs{RunId: recorder.run.RunId, Confirmed: true,
		Redactor: testSessionExportRedactor(t)})
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.Lines) != 1+len(recorder.nodes) || exported.NodeCount != len(recorder.nodes) || exported.UnheldCount != 0 {
		t.Fatalf("%d lines for %d nodes: %+v", len(exported.Lines), len(recorder.nodes), exported)
	}
	header := struct {
		Type    string `json:"type"`
		Version int    `json:"version"`
		Id      string `json:"id"`
	}{}
	if err := json.Unmarshal(exported.Lines[0], &header); err != nil || header.Type != "session" || header.Version != sidecar.HarnessPiSessionVersion ||
		header.Id != recorder.run.RunId.String() {
		t.Fatalf("the header: %s, %v", exported.Lines[0], err)
	}
	ids := map[string]bool{}
	type piEntry struct {
		Type      string          `json:"type"`
		Id        string          `json:"id"`
		ParentId  *string         `json:"parentId"`
		Timestamp string          `json:"timestamp"`
		Message   json.RawMessage `json:"message"`
	}
	entries := []*piEntry{}
	for _, line := range exported.Lines[1:] {
		entry := &piEntry{}
		if err := json.Unmarshal(line, entry); err != nil || entry.Type == "" || len(entry.Id) != 8 || entry.Timestamp == "" {
			t.Fatalf("a line that is no Pi entry: %s, %v", line, err)
		}
		ids[entry.Id] = true
		entries = append(entries, entry)
	}
	roots := 0
	for _, entry := range entries {
		switch {
		case entry.ParentId == nil:
			roots += 1
		case !ids[*entry.ParentId]:
			t.Errorf("entry %s names a parent the file does not hold", entry.Id)
		}
	}
	if roots != 1 {
		t.Fatalf("%d roots", roots)
	}
	if text := string(bytes.Join(exported.Lines, nil)); strings.Count(text, "agenda notes ") != 2000 || strings.Contains(text, `"sha256"`) {
		t.Fatal("the calendar result's part is not whole in the export")
	}
}
