//go:build !sidecar_http

// RECORD-M6-07's exports on sidecartest's streams and authorization state: RECORD.md section 20's export cases. A
// line verifies given its writer's key; an erased entry is a stub; a plain line holds no body field; a fixture's
// relay, route and action addresses appear in neither ocsf, otel nor a plain jsonl; a receipt that cannot land stops
// the export; a receipt-only reader's export files only receipts; the export's disclosure entry lands before any line
// is returned; the OCSF class and activity tables; and a follow job resuming from its cursor.

package sidecar_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The addresses the export fixture's bodies hold: a relay's, a route's, a published host's and an action's.
var testExportAddresses = []string{"203.0.113.9", "192.0.2.0/24", "203.0.113.20", "198.51.100.7"}

// The disclosure world, with entries a log admin's device writes straight to the team record whose bodies hold
// addresses: a reach receipt naming its relay, a route with its cidrs, a publish of a host that is an address, and a
// membership event.
func newTestExportWorld(t *testing.T) *testDiscloseWorld {
	t.Helper()
	world := newTestDiscloseWorld(t)
	subject := sidecar.NewId()
	grantId := bytes.Repeat([]byte{0x31}, 32)
	drafts := []*sidecar.RecordDraft{
		{Kind: sidecar.RecordKindReach, Source: sidecar.RecordSourceObserved, NoSession: true, GrantId: grantId, Body: &protocol.ReachReceipt{
			GrantId: grantId, PolicyVersion: 3, Kind: uint32(sidecar.RecordReachKindForward), Peers: [][]byte{subject.Bytes()},
			StreamCount: 2, ByteCount: 4096, Relays: []string{"relay.example 203.0.113.9 example-operator"},
		}},
		{Kind: sidecar.RecordKindRoute, Source: sidecar.RecordSourceObserved, NoSession: true, Body: &protocol.RouteBody{
			Event: 1, Kind: 2, TargetSidecarId: subject.Bytes(), TargetPort: 8443, Cidrs: []string{"192.0.2.0/24"},
		}},
		{Kind: sidecar.RecordKindPublish, Source: sidecar.RecordSourceObserved, NoSession: true, Body: &protocol.PublishBody{
			Event: 1, Host: "203.0.113.20", Port: 443, Audience: 1,
		}},
		{Kind: sidecar.RecordKindPublish, Source: sidecar.RecordSourceObserved, NoSession: true, Body: &protocol.PublishBody{
			Event: 2, Host: "app.example", Port: 443, Audience: 1, Reason: 1,
		}},
		{Kind: sidecar.RecordKindInventory, Source: sidecar.RecordSourceObserved, NoSession: true, Body: &protocol.InventoryBody{
			Agents: []*protocol.InventoryAgent{{AgentId: subject.Bytes()}},
		}},
	}
	for _, draft := range drafts {
		testRecordAppend(t, world.adminRecord, draft)
	}
	if err := world.adminRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return world
}

// An export that must succeed, its lines parsed.
func testExport(t *testing.T, record *sidecar.SidecarRecord, args *sidecar.RecordExportArgs) ([]map[string]any, [][]byte) {
	t.Helper()
	exported, err := record.Export().Export(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	lines := []map[string]any{}
	for _, line := range exported.Lines {
		parsed := map[string]any{}
		if err := json.Unmarshal(line, &parsed); err != nil {
			t.Fatalf("a line that is no JSON object: %s", line)
		}
		lines = append(lines, parsed)
	}
	return lines, exported.Lines
}

// The line of the first entry of kind.
func testExportLineOf(t *testing.T, lines []map[string]any, kind string) map[string]any {
	t.Helper()
	for _, line := range lines {
		if line["kind"] == kind {
			return line
		}
	}
	t.Fatalf("no %s line", kind)
	return nil
}

// RECORD.md section 20: a line verifies given its writer's key, a plain line holds no body field, and a line with
// bodies opens its header's commitment. Lines are canonical: keys sorted, nothing between tokens, ids in lowercase
// hex and times in RFC 3339 UTC with milliseconds.
func TestRecordExportLineVerifiesFromItself(t *testing.T) {
	world := newTestExportWorld(t)
	plain, plainBytes := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl})
	if len(plain) < 10 {
		t.Fatalf("%d lines", len(plain))
	}
	keys := map[sidecar.Id]ed25519.PublicKey{
		world.admin.sidecarId:  world.admin.key.Public().(ed25519.PublicKey),
		world.member.sidecarId: world.member.key.Public().(ed25519.PublicKey),
	}
	for i, line := range plain {
		for _, field := range []string{"salt", "body", "fields", "agent_label"} {
			if _, ok := line[field]; ok {
				t.Fatalf("a plain line holds %s", field)
			}
		}
		// canonical: re-encoding the parsed object with sorted keys and no whitespace gives the same bytes
		encoded := &bytes.Buffer{}
		encoder := json.NewEncoder(encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(line); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bytes.TrimSuffix(encoded.Bytes(), []byte("\n")), plainBytes[i]) || bytes.ContainsAny(plainBytes[i], "\n\t ") {
			t.Fatalf("a line is not canonical: %s", plainBytes[i])
		}
		signedBytes, err := base64.StdEncoding.DecodeString(line["header"].(string))
		if err != nil {
			t.Fatal(err)
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(signedBytes, signed); err != nil {
			t.Fatal(err)
		}
		writerId := sidecar.Id(signed.GetSignerId())
		if err := bridge.VerifySigned(signed, sidecar.RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, keys[writerId]); err != nil {
			t.Fatalf("a line's header does not verify under its writer's key: %v", err)
		}
		header, err := sidecar.ParseStoredRecordHeader(signed.GetBody())
		if err != nil {
			t.Fatal(err)
		}
		leaf := header.LeafHash()
		if line["entry"] != strings.ToLower(line["entry"].(string)) || line["leaf"] != bytesHex(leaf[:]) || line["writer"] != bytesHex(writerId[:]) ||
			line["v"] != float64(1) || line["state"] != "live" || !strings.HasSuffix(line["time"].(string), "Z") || len(line["time"].(string)) != len("2026-11-05T07:12:09.123Z") {
			t.Fatalf("a line's fields do not match its header: %v", line)
		}
	}
	change := testExportLineOf(t, plain, "change")
	if content, ok := change["content"].([]any); !ok || len(content) != 1 {
		t.Fatalf("T's change line names no vault entry: %v", change["content"])
	}

	// bodies take a confirmed command, and then each line opens its commitment
	if _, err := world.adminRecord.Export().Export(t.Context(), &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl, Bodies: true}); !errors.Is(err, sidecar.ErrRecordExportUnconfirmed) {
		t.Fatalf("bodies from an unconfirmed command: %v", err)
	}
	full, _ := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl, Bodies: true, Confirmed: true})
	for _, line := range full {
		header, _ := base64.StdEncoding.DecodeString(line["header"].(string))
		salt, _ := base64.StdEncoding.DecodeString(line["salt"].(string))
		body, _ := base64.StdEncoding.DecodeString(line["body"].(string))
		if _, err := sidecar.VerifyRecordOpening(&protocol.Opening{Header: header, Salt: salt, Body: body}); err != nil || len(salt) == 0 {
			t.Fatalf("a %s line's body does not open its header's commitment: %v", line["kind"], err)
		}
	}
	context := testExportLineOf(t, full, "context")
	if fields, ok := context["fields"].(map[string]any); !ok || fields["harness"] != "claude-code" || fields["model"] != "example-model" {
		t.Fatalf("the context line's fields: %v", context["fields"])
	}
	// fields is a convenience by proto field name: bytes as lowercase hex, repeated fields as arrays
	reach := testExportLineOf(t, full, "reach")
	fields := reach["fields"].(map[string]any)
	if peers, ok := fields["peers"].([]any); !ok || len(peers) != 1 || len(peers[0].(string)) != 32 || fields["byte_count"] != float64(4096) {
		t.Fatalf("the reach line's fields: %v", fields)
	}
}

// Lowercase hex of bytes.
func bytesHex(value []byte) string {
	const digits = "0123456789abcdef"
	text := make([]byte, 0, 2*len(value))
	for _, b := range value {
		text = append(text, digits[b>>4], digits[b&15])
	}
	return string(text)
}

// RECORD.md section 20 and I-13: the fixture's relay, route and action addresses appear in neither ocsf, otel nor a
// plain jsonl. A jsonl with bodies does carry them, in fields and body, which its confirmation says.
func TestRecordExportCarriesNoAddressOutsideBodies(t *testing.T) {
	world := newTestExportWorld(t)
	for _, format := range []sidecar.RecordExportFormat{sidecar.RecordExportFormatJsonl, sidecar.RecordExportFormatOcsf, sidecar.RecordExportFormatOtel} {
		args := &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: format, Confirmed: format != sidecar.RecordExportFormatJsonl}
		_, lines := testExport(t, world.adminRecord, args)
		if len(lines) < 10 {
			t.Fatalf("format %d: %d lines", format, len(lines))
		}
		for _, line := range lines {
			for _, address := range testExportAddresses {
				if bytes.Contains(line, []byte(address)) {
					t.Errorf("format %d carries the address %s: %s", format, address, line)
				}
			}
			for _, prose := range []string{"set the app's address", "relay.example", "example-operator"} {
				if bytes.Contains(line, []byte(prose)) {
					t.Errorf("format %d carries the prose %q", format, prose)
				}
			}
		}
	}
	_, full := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl, Bodies: true, Confirmed: true})
	joined := bytes.Join(full, []byte("\n"))
	for _, address := range []string{"203.0.113.9", "192.0.2.0/24", "203.0.113.20"} {
		if !bytes.Contains(joined, []byte(address)) {
			t.Errorf("a jsonl export with bodies does not hold %s, which its body does", address)
		}
	}
	// ocsf and otel carry body data, so each takes a confirmed command
	for _, format := range []sidecar.RecordExportFormat{sidecar.RecordExportFormatOcsf, sidecar.RecordExportFormatOtel} {
		if _, err := world.adminRecord.Export().Export(t.Context(), &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: format}); !errors.Is(err, sidecar.ErrRecordExportUnconfirmed) {
			t.Errorf("format %d from an unconfirmed command: %v", format, err)
		}
	}
}

// Section 9's OCSF table: each kind's class, category and activity, with type_uid class_uid × 100 + activity_id, and
// what every event sets.
func TestRecordExportOcsfClassAndActivityTables(t *testing.T) {
	world := newTestExportWorld(t)
	events, _ := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatOcsf, Confirmed: true})
	cases := []struct {
		kind     string
		event    float64
		class    float64
		category float64
		activity float64
	}{
		{kind: "route", class: 4001, category: 4, activity: 1},
		{kind: "publish", event: 1, class: 4001, category: 4, activity: 7},
		{kind: "publish", event: 2, class: 4001, category: 4, activity: 2},
		{kind: "reach", class: 4001, category: 4, activity: 6},
		{kind: "context", class: 6003, category: 6, activity: 1},
		{kind: "coverage", class: 6003, category: 6, activity: 3},
		{kind: "approval", class: 6003, category: 6, activity: 1},
		{kind: "log_settings", class: 6003, category: 6, activity: 1},
		{kind: "disclosure", class: 6003, category: 6, activity: 2},
	}
	seen := map[string]bool{}
	for _, event := range events {
		unmapped := event["unmapped"].(map[string]any)
		metadata := event["metadata"].(map[string]any)
		if metadata["version"] != "1.3.0" || len(metadata["uid"].(string)) != 32 || metadata["product"].(map[string]any)["name"] != "recURd" ||
			event["cloud"].(map[string]any)["provider"] != "urnetwork" || event["type_uid"] != event["class_uid"].(float64)*100+event["activity_id"].(float64) ||
			len(event["src_endpoint"].(map[string]any)["uid"].(string)) != 32 || len(event["osint"].([]any)) != 0 {
			t.Fatalf("an event lacks what every event sets: %v", event)
		}
		for _, c := range cases {
			if unmapped["kind"] != c.kind || (c.event != 0 && unmapped["event"] != c.event) {
				continue
			}
			seen[c.kind] = true
			if event["class_uid"] != c.class || event["category_uid"] != c.category || event["activity_id"] != c.activity {
				t.Errorf("%s (event %v): class %v, category %v, activity %v", c.kind, c.event, event["class_uid"], event["category_uid"], event["activity_id"])
			}
		}
		switch unmapped["kind"] {
		case "route":
			if len(event["dst_endpoint"].(map[string]any)["uid"].(string)) != 32 {
				t.Errorf("a route's dst_endpoint: %v", event["dst_endpoint"])
			}
		case "publish":
			// a host that is an address is left out; a name is the endpoint
			endpoint, has := event["dst_endpoint"].(map[string]any)
			if unmapped["event"] == float64(2) && (!has || endpoint["uid"] != "app.example") {
				t.Errorf("a publish's dst_endpoint: %v", event["dst_endpoint"])
			}
			if unmapped["event"] == float64(1) && has {
				t.Errorf("a publish of an address names it: %v", endpoint)
			}
		case "context":
			if event["api"].(map[string]any)["operation"] != "recurd.context" || event["actor"].(map[string]any)["session"] == nil {
				t.Errorf("a context's api and actor: %v %v", event["api"], event["actor"])
			}
		}
	}
	// a disclosure entry exists only once an export recorded itself: this export's own
	for _, c := range cases {
		if !seen[c.kind] && c.kind != "disclosure" {
			t.Errorf("no %s event", c.kind)
		}
	}
	// otel: one ResourceLogs object a line, the run as the conversation and a context's model as the request's
	records, _ := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatOtel, Confirmed: true})
	found := false
	for _, record := range records {
		logRecord := record["resourceLogs"].([]any)[0].(map[string]any)["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)[0].(map[string]any)
		attributes := map[string]any{}
		for _, attribute := range logRecord["attributes"].([]any) {
			typed := attribute.(map[string]any)
			attributes[typed["key"].(string)] = typed["value"]
		}
		if logRecord["eventName"] != "recurd.context" {
			continue
		}
		found = true
		if attributes["gen_ai.request.model"].(map[string]any)["stringValue"] != "example-model" ||
			attributes["gen_ai.conversation.id"].(map[string]any)["stringValue"] != bytesHex(world.runId[:]) ||
			attributes["recurd.seq"].(map[string]any)["intValue"] == nil || len(logRecord["timeUnixNano"].(string)) < 19 {
			t.Errorf("a context's log record: %v", logRecord)
		}
	}
	if !found {
		t.Error("no context log record")
	}
}

// RECORD.md section 20: an erased entry is a stub. Its line keeps the header's fields and its state, and holds no
// salt, body or fields, whatever the export asked.
func TestRecordExportErasedEntryIsAStub(t *testing.T) {
	world := newTestExportWorld(t)
	approvals := world.entriesOf(sidecar.RecordKindApproval)
	place := approvals[0].Copies[0]
	if _, err := world.streams.For(world.admin.sidecarId).Erase(t.Context(), world.teamRecordId, &sidecar.RecordStreamErase{
		PushId: sidecar.NewId(), Keys: []*sidecar.RecordSlotKey{{SlotId: place.SlotId, KeyIndex: place.KeyIndex}}, SealedNote: []byte("a sealed note"),
	}); err != nil {
		t.Fatal(err)
	}
	for _, format := range []sidecar.RecordExportFormat{sidecar.RecordExportFormatJsonl, sidecar.RecordExportFormatOcsf, sidecar.RecordExportFormatOtel} {
		lines, raw := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{
			LogId: world.teamRecordId, Format: format, Bodies: true, Confirmed: true, Kinds: []sidecar.RecordKind{sidecar.RecordKindApproval},
		})
		if len(lines) != 1 || bytes.Contains(raw[0], []byte("summary")) || bytes.Contains(raw[0], []byte("set the app")) {
			t.Fatalf("format %d: an erased entry's line: %s", format, raw)
		}
		if format == sidecar.RecordExportFormatJsonl {
			line := lines[0]
			if line["state"] != "erased" || line["salt"] != nil || line["body"] != nil || line["fields"] != nil || line["header"] == nil || line["kind"] != "approval" {
				t.Fatalf("an erased entry's stub: %v", line)
			}
		}
	}
}

// The export's record is written ahead: its disclosure entry, with act 3 and what was asked, is in the log before any
// line is returned, source approver for a confirmed command and observed for a plain one, and an export whose record
// cannot land returns no line. An evs export's lines are format 4, with bodies.
func TestRecordExportRecordsItselfBeforeItsFirstLine(t *testing.T) {
	world := newTestExportWorld(t)
	since := world.clock.Now().Add(-60 * 60 * 1000 * 1000 * 1000).UnixMilli()
	lines, _ := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{
		LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl, RunId: &world.runId, SinceMillis: since,
		Kinds: []sidecar.RecordKind{sidecar.RecordKindContext, sidecar.RecordKindChange},
	})
	if len(lines) != 2 {
		t.Fatalf("%d lines for the run's context and change", len(lines))
	}
	disclosures := world.entriesOf(sidecar.RecordKindDisclosure)
	if len(disclosures) != 1 {
		t.Fatalf("%d disclosure entries", len(disclosures))
	}
	body := &protocol.DisclosureBody{}
	if err := proto.Unmarshal(disclosures[0].Body, body); err != nil {
		t.Fatal(err)
	}
	if body.GetAct() != sidecar.RecordDisclosureActExport || body.GetFormat() != 1 || body.GetBodies() || body.GetSinceMillis() != since ||
		!bytes.Equal(body.GetRunId(), world.runId[:]) || !slices.Equal(body.GetKinds(), []uint32{16, 17}) || len(body.GetPacketSha256()) != 0 ||
		sidecar.RecordSource(disclosures[0].Header.Header.GetSource()) != sidecar.RecordSourceObserved {
		t.Fatalf("a plain export's disclosure entry: %+v", body)
	}
	// an evs export's lines: format 4, bodies, a confirmed command
	if _, err := world.adminRecord.Export().Export(t.Context(), &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatGit, Confirmed: true}); !errors.Is(err, sidecar.ErrRecordExportArgs) {
		t.Fatalf("an evs export without bodies: %v", err)
	}
	git, _ := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatGit, Bodies: true, Confirmed: true})
	if git[0]["body"] == nil || git[0]["header"] == nil {
		t.Fatalf("an evs export's line: %v", git[0])
	}
	disclosures = world.entriesOf(sidecar.RecordKindDisclosure)
	if err := proto.Unmarshal(disclosures[len(disclosures)-1].Body, body); err != nil {
		t.Fatal(err)
	}
	if body.GetFormat() != 4 || !body.GetBodies() || sidecar.RecordSource(disclosures[len(disclosures)-1].Header.Header.GetSource()) != sidecar.RecordSourceApprover {
		t.Fatalf("an evs export's disclosure entry: %+v", body)
	}
	// a record that cannot land stops the export
	world.streams.SetGateClosed(world.teamRecordId, true)
	exported, err := world.adminRecord.Export().Export(t.Context(), &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl})
	if !errors.Is(err, sidecar.ErrRecordNotLanded) || exported != nil {
		t.Fatalf("an export whose record did not land: %v", err)
	}
	world.streams.SetGateClosed(world.teamRecordId, false)
	// a sidecar that does not read the log exports nothing
	if _, err := world.memberRecord.Export().Export(t.Context(), &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl}); !errors.Is(err, sidecar.ErrRecordNotReader) {
		t.Fatalf("an export by a sidecar that does not read the log: %v", err)
	}
}

// RECORD.md section 20: a receipt-only reader's export files only receipts, purpose 3, and a receipt that cannot land
// stops the export.
func TestRecordExportReceiptOnlyReaderFilesOnlyReceipts(t *testing.T) {
	world := newTestExportWorld(t)
	reader := world.device(false)
	repo := world.fixture.Repos[world.teamRecordId]
	repo.Readers = append(repo.Readers, reader.sidecarId)
	repo.Depositors = append(repo.Depositors, reader.sidecarId)
	repo.ReceiptOnly = append(repo.ReceiptOnly, reader.sidecarId)
	if err := world.streams.Grant(world.teamRecordId, reader.sidecarId, sidecartest.RecordStreamsScope{Read: true, Deposit: true, ReceiptOnly: true}); err != nil {
		t.Fatal(err)
	}
	world.publish()
	record := reader.openWith(testLogNoWitness{t: t})
	args := &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl, Kinds: []sidecar.RecordKind{sidecar.RecordKindRoute, sidecar.RecordKindReach}}
	world.streams.SetGateClosed(world.teamRecordId, true)
	if exported, err := record.Export().Export(t.Context(), args); err == nil || exported != nil {
		t.Fatalf("an export whose receipt did not land returned lines")
	}
	world.streams.SetGateClosed(world.teamRecordId, false)
	exported, err := record.Export().Export(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	if !exported.ReceiptsOnly || len(exported.Lines) != 2 {
		t.Fatalf("receipts only: %t, %d lines", exported.ReceiptsOnly, len(exported.Lines))
	}
	deposits, err := world.streams.For(world.admin.sidecarId).ReadDeposits(t.Context(), world.teamRecordId, reader.sidecarId)
	if err != nil || len(deposits) == 0 {
		t.Fatalf("%d deposits from the reader: %v", len(deposits), err)
	}
	receipted := 0
	for _, deposit := range deposits {
		entries, err := sidecar.RecordDepositBatchParse(deposit.Batch, reader.settings.DepositByteCount)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			header, err := sidecar.ParseStoredRecordHeader(testSignedBody(t, entry.Signed))
			if err != nil {
				t.Fatal(err)
			}
			opened, err := sidecar.RecordOpen(header, entry.SealedBody, entry.Key, entry.Salt)
			if err != nil {
				t.Fatal(err)
			}
			read := &protocol.ReadBody{}
			if err := proto.Unmarshal(opened, read); err != nil {
				t.Fatal(err)
			}
			if header.Kind() != sidecar.RecordKindRead || read.GetPurpose() != uint32(sidecar.RecordReadPurposeExport) {
				t.Fatalf("the reader deposited a %s of purpose %d", header.Kind(), read.GetPurpose())
			}
			receipted += len(read.GetObjectIds())
		}
	}
	if receipted != 2 {
		t.Fatalf("receipts name %d entries, and 2 were exported", receipted)
	}
	if got := len(world.entriesOf(sidecar.RecordKindDisclosure)); got != 0 {
		t.Fatalf("a receipt-only reader's export filed %d disclosure entries", got)
	}
}

// A file a follow job appends to, in memory.
type testExportSink struct {
	stateLock sync.Mutex
	pathLines map[string][]string
}

type testExportSinkWriter struct {
	sink   *testExportSink
	path   string
	buffer bytes.Buffer
}

func (self *testExportSinkWriter) Write(p []byte) (int, error) {
	return self.buffer.Write(p)
}

func (self *testExportSinkWriter) Close() error {
	self.sink.stateLock.Lock()
	defer self.sink.stateLock.Unlock()
	for _, line := range strings.Split(strings.TrimSuffix(self.buffer.String(), "\n"), "\n") {
		self.sink.pathLines[self.path] = append(self.sink.pathLines[self.path], line)
	}
	return nil
}

func (self *testExportSink) open(path string) (io.WriteCloser, error) {
	return &testExportSinkWriter{sink: self, path: path}, nil
}

func (self *testExportSink) lines(path string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.pathLines[path])
}

// RECORD.md section 20: a follow job resumes from its cursor. It writes a line an entry as each verifies, a new
// process of the daemon goes on from the cursor in the record's state and writes no line twice, and the job ends
// with the sidecar's read of the log.
func TestRecordExportFollowResumesFromItsCursor(t *testing.T) {
	world := newTestLogWorld(t)
	admin := world.admin()
	record := admin.openWith(testLogNoWitness{t: t})
	sink := &testExportSink{pathLines: map[string][]string{}}
	record.SetExportSink(sink.open)
	first := testLogEntry(t, record)
	args := &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl, Kinds: []sidecar.RecordKind{sidecar.RecordKindInventory}}
	if _, err := record.Export().Follow(t.Context(), args, "/exports/team.jsonl"); !errors.Is(err, sidecar.ErrRecordExportUnconfirmed) {
		t.Fatalf("a follow job from an unconfirmed command: %v", err)
	}
	args.Confirmed = true
	noSink := admin.openWith(testLogNoWitness{t: t})
	if _, err := noSink.Export().Follow(t.Context(), args, "/exports/team.jsonl"); !errors.Is(err, sidecar.ErrRecordExportNoSink) {
		t.Fatalf("a follow job on a host with no file sink: %v", err)
	}
	if _, err := record.Export().Follow(t.Context(), args, "/exports/team.jsonl"); err != nil {
		t.Fatal(err)
	}
	// its disclosure entry is in the log before any line is written
	if len(sink.lines("/exports/team.jsonl")) != 0 {
		t.Fatal("a line was written before the record's next pass")
	}
	disclosures, _ := record.Reader().EntriesOfKinds(world.teamRecordId, 0, sidecar.RecordKindDisclosure)
	if err := record.Reader().Sync(t.Context(), world.teamRecordId); err != nil {
		t.Fatal(err)
	}
	disclosures, _ = record.Reader().EntriesOfKinds(world.teamRecordId, 0, sidecar.RecordKindDisclosure)
	if len(disclosures) != 1 {
		t.Fatalf("%d disclosure entries for the job", len(disclosures))
	}
	record.Export().Tick(t.Context())
	lines := sink.lines("/exports/team.jsonl")
	if len(lines) != 1 || !strings.Contains(lines[0], bytesHex(first.EntryId[:])) {
		t.Fatalf("the job's first pass wrote %v", lines)
	}
	// nothing moved: nothing more is written
	record.Export().Tick(t.Context())
	second := testLogEntry(t, record)
	record.Export().Tick(t.Context())
	if lines := sink.lines("/exports/team.jsonl"); len(lines) != 2 || !strings.Contains(lines[1], bytesHex(second.EntryId[:])) {
		t.Fatalf("after a second entry the file holds %v", lines)
	}

	// the daemon's next life goes on from the cursor
	next := admin.openWith(testLogNoWitness{t: t})
	next.SetExportSink(sink.open)
	next.Export().Tick(t.Context())
	if lines := sink.lines("/exports/team.jsonl"); len(lines) != 2 {
		t.Fatalf("a resumed job wrote lines again: %d", len(lines))
	}
	third := testLogEntry(t, next)
	next.Export().Tick(t.Context())
	if lines := sink.lines("/exports/team.jsonl"); len(lines) != 3 || !strings.Contains(lines[2], bytesHex(third.EntryId[:])) {
		t.Fatalf("a resumed job after a third entry: %d lines", len(lines))
	}

	// the job ends with the sidecar's read of the log
	repo := world.fixture.Repos[world.teamRecordId]
	repo.Readers = removeTestId(repo.Readers, admin.sidecarId)
	world.publish()
	testRecordAppend(t, next, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindInventory, Source: sidecar.RecordSourceObserved, NoSession: true, Body: &protocol.InventoryBody{},
	})
	if err := next.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	next.Export().Tick(t.Context())
	if lines := sink.lines("/exports/team.jsonl"); len(lines) != 3 {
		t.Fatalf("a job went on past its sidecar's read of the log: %d lines", len(lines))
	}
	for _, path := range admin.files.Paths() {
		if strings.Contains(path, "/export/") {
			t.Fatalf("an ended job's state stays: %s", path)
		}
	}
}
