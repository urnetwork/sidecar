//go:build !sidecar_http

// RECORD-M6-06's packets on sidecartest's streams and authorization state: RECORD.md section 20's packet cases. A good
// packet passes the offline verifier and fails on each altered byte class; a packet spanning a key rotation verifies
// under both log keys and fails under one; a disclosure that cannot land returns no packet; a receipt-only reader's
// packet files only receipts; a caller under a harness process is refused; an erased entry goes as a header alone;
// and the author's openings ride a packet as content. The good packet is also a committed vector,
// testdata/record/packets/approval.json, which record_verify_packet_test.go verifies with nothing else in hand.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var updateRecordPackets = flag.Bool("update-record-packets", false, "rewrite testdata/record/packets/")

// A team network with its verifiable log on, a member whose daemon records a run with one approved action, and a log
// admin's device that ingests it.
type testDiscloseWorld struct {
	*testLogWorld
	admin        *testRecordDevice
	adminRecord  *sidecar.SidecarRecord
	member       *testRecordDevice
	memberRecord *sidecar.SidecarRecord
	runId        sidecar.Id
	approvalId   sidecar.Id
	// the member's vault entry of the run's context, which T's projection references
	vaultContextId sidecar.Id
	logKey         string
}

func newTestDiscloseWorld(t *testing.T, witnesses ...*testLogWitness) *testDiscloseWorld {
	t.Helper()
	world := &testDiscloseWorld{testLogWorld: newTestLogWorld(t)}
	world.admin = world.testLogWorld.admin()
	var witness sidecar.RecordLogWitness = testLogNoWitness{t: t}
	if 0 < len(witnesses) {
		witness = witnesses[0]
	}
	world.adminRecord = world.admin.openWith(witness)
	testLogOn(t, world.testLogWorld, world.adminRecord, witnesses...)
	world.member = world.memberDevice(true)
	world.memberRecord = world.member.open()
	world.runId = sidecar.NewId()
	world.runs.StartRun(world.runId)

	request := testRecordParsedRequest(t, world.approvalRequest(world.member, testRecordDnsSet(t, "198.51.100.7").Bytes, "set the app's address", nil))
	world.approvalId = request.ApprovalId()
	payload := request.Action.PayloadSha256()
	effectKey := sidecar.ApprovalEffectKey(request.ApprovalId(), request.Action.ActionId(request.ApprovalId()))
	sha := bytes.Repeat([]byte{0x42}, sha256.Size)
	drafts := []*sidecar.RecordDraft{
		{Kind: sidecar.RecordKindContext, Source: sidecar.RecordSourceHook, RunId: &world.runId, Body: &protocol.ContextBody{
			Stage: 1, Harness: "claude-code", Model: "example-model", AgentLabel: "limiter-fix", Title: "tune the limiter",
		}},
		{Kind: sidecar.RecordKindChange, Source: sidecar.RecordSourceObserved, RunId: &world.runId, Body: &protocol.ChangeBody{
			PathCount: 1, EditCount: 1, Capture: 1,
			Paths: []*protocol.ChangedPath{{Path: "internal/limiter.go", BeforeSha256: sha, AfterSha256: sha, Attribution: 1}},
		}},
		{Kind: sidecar.RecordKindApproval, Source: sidecar.RecordSourceObserved, RunId: &world.runId, StoredBody: request.Bytes},
		{Kind: sidecar.RecordKindApprovalDecision, Source: sidecar.RecordSourceApprover, NoSession: true, StoredBody: world.member.decide(request)},
		{Kind: sidecar.RecordKindApprovalUse, Source: sidecar.RecordSourceObserved, RunId: &world.runId, Body: &protocol.ApprovalUseBody{
			ApprovalId: request.Request.GetApprovalId(), PayloadSha256: payload[:], EffectKey: effectKey[:], State: 1,
		}},
		{Kind: sidecar.RecordKindCoverage, Source: sidecar.RecordSourceObserved, RunId: &world.runId, Body: &protocol.Coverage{
			RunId: world.runId.Bytes(), Harness: "claude-code", Sources: []string{sidecar.RecordCoverageSourceHooks}, FirstSeq: 1, LastSeq: 5,
		}},
	}
	for i, draft := range drafts {
		refs, err := world.memberRecord.Writer().Append(draft)
		if err != nil {
			t.Fatalf("draft %d, a %s: %v", i, draft.Kind, err)
		}
		if i == 0 {
			world.vaultContextId = refs[0].EntryId
		}
	}
	if err := world.memberRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	world.ingest()
	world.logKey = testLogStatus(t, world.testLogWorld, world.adminRecord).LogKey
	return world
}

// The admin's device ingests what waits for the team record, and pushes it.
func (self *testDiscloseWorld) ingest() {
	self.t.Helper()
	if err := self.adminRecord.Ingester().Ingest(self.t.Context(), self.teamRecordId); err != nil {
		self.t.Fatal(err)
	}
	if err := self.adminRecord.Flush(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
}

// The approval profile's request, confirmed.
func (self *testDiscloseWorld) approvalArgs() *sidecar.RecordDiscloseArgs {
	return &sidecar.RecordDiscloseArgs{
		LogId: self.teamRecordId, ApprovalId: &self.approvalId, Recipient: "client.example", Purpose: "proof of one approved action", Confirmed: true,
	}
}

// The team record's entries of kind, as the admin reads them.
func (self *testDiscloseWorld) entriesOf(kind sidecar.RecordKind) []*sidecar.RecordReadEntry {
	self.t.Helper()
	if err := self.adminRecord.Reader().Sync(self.t.Context(), self.teamRecordId); err != nil {
		self.t.Fatal(err)
	}
	entries, _ := self.adminRecord.Reader().EntriesOfKinds(self.teamRecordId, 0, kind)
	return entries
}

// Verifies a packet under keys, which must be readable.
func testVerifyPacket(t *testing.T, packet []byte, args *sidecar.RecordVerifyArgs) *sidecar.RecordVerifyReport {
	t.Helper()
	report, err := sidecar.VerifyRecordDisclosurePacket(packet, args)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// A verify report's failures, flat.
func testVerifyFailures(report *sidecar.RecordVerifyReport) []string {
	failures := slices.Clone(report.Failures)
	for _, checkpoint := range report.Checkpoints {
		failures = append(failures, checkpoint.Failures...)
	}
	for _, entry := range report.Entries {
		failures = append(failures, entry.Failures...)
	}
	return failures
}

// The committed vector's shape.
type testPacketVector struct {
	Comment string `json:"comment"`
	LogKey  string `json:"log_key"`
	Packet  string `json:"packet"`
}

const testPacketVectorPath = "testdata/record/packets/approval.json"

// RECORD.md section 20: `ur record verify` passes a good packet offline. The approval profile opens the approval, its
// decision and its use, carries the header of the run's coverage entry, and its disclosure entry is in the log before
// the packet is returned.
func TestRecordDiscloseApprovalPacketVerifiesOffline(t *testing.T) {
	world := newTestDiscloseWorld(t)
	plan, err := world.adminRecord.Disclosure().Plan(t.Context(), world.approvalArgs())
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[sidecar.RecordKind]*sidecar.RecordDisclosureItem{}
	for _, item := range plan.Items {
		kinds[item.Kind] = item
	}
	if len(plan.Items) != 4 || !kinds[sidecar.RecordKindApproval].Opened || !kinds[sidecar.RecordKindApprovalDecision].Opened ||
		!kinds[sidecar.RecordKindApprovalUse].Opened || kinds[sidecar.RecordKindCoverage] == nil || kinds[sidecar.RecordKindCoverage].Opened {
		t.Fatalf("the approval profile's plan: %+v", plan.Items)
	}
	// the confirmation lists what an approval opens: its summary and its action's fields among them
	for _, field := range []string{"summary", "canonical_action", "canonical_action.dns_value", "approvers"} {
		if !slices.Contains(kinds[sidecar.RecordKindApproval].Fields, field) {
			t.Errorf("the plan does not list %s among %v", field, kinds[sidecar.RecordKindApproval].Fields)
		}
	}
	if got := len(world.entriesOf(sidecar.RecordKindDisclosure)); got != 0 {
		t.Fatalf("a plan filed %d disclosure entries", got)
	}

	args := world.approvalArgs()
	for _, item := range plan.Items {
		args.ExpectEntryIds = append(args.ExpectEntryIds, item.EntryId)
	}
	disclosed, err := world.adminRecord.Disclosure().Disclose(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	if disclosed.ReceiptsOnly || disclosed.PacketSha256 != sha256.Sum256(disclosed.Packet) {
		t.Fatalf("the packet's record or hash")
	}
	// the log's own record of the act names the packet and its entries
	disclosures := world.entriesOf(sidecar.RecordKindDisclosure)
	if len(disclosures) != 1 {
		t.Fatalf("%d disclosure entries", len(disclosures))
	}
	body := &protocol.DisclosureBody{}
	if err := proto.Unmarshal(disclosures[0].Body, body); err != nil {
		t.Fatal(err)
	}
	if body.GetAct() != sidecar.RecordDisclosureActPacket || !bytes.Equal(body.GetPacketSha256(), disclosed.PacketSha256[:]) || len(body.GetEntryIds()) != 4 ||
		body.GetRecipient() != "client.example" || sidecar.RecordSource(disclosures[0].Header.Header.GetSource()) != sidecar.RecordSourceApprover {
		t.Fatalf("the disclosure entry: %+v", body)
	}

	report := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}})
	if !report.Ok || len(report.Entries) != 4 || len(report.Checkpoints) != 1 || report.LogId != world.teamRecordId {
		t.Fatalf("a good packet: %v", testVerifyFailures(report))
	}
	for _, key := range report.Keys {
		if !key.TeamStated || key.Label == "" {
			t.Errorf("a key's label is not marked the team's statement: %+v", key)
		}
	}
	// no key but public ones: nothing a reader's slot rows or the log's state holds is in the file
	if logKey := testLogKey(t, world.testLogWorld, world.admin); bytes.Contains(disclosed.Packet, logKey.Seed()) {
		t.Fatal("the packet holds the log key")
	}
	// under no log key, or another's, a note fails
	other, err := sidecar.NewRecordLogVerifierKey(sidecar.RecordLogOrigin(world.teamRecordId), sidecar.RecordLogKeyTypeEd25519, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{}).Ok || testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{other.String()}}).Ok {
		t.Fatal("a packet verified without its log key")
	}
	if _, err := sidecar.VerifyRecordDisclosurePacket(disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}, SshKeys: true}); !errors.Is(err, sidecar.ErrRecordVerifySshUnbuilt) {
		t.Fatalf("an ssh check that is not built: %v", err)
	}
	if _, err := sidecar.VerifyRecordDisclosurePacket([]byte("not a packet"), &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}}); !errors.Is(err, sidecar.ErrRecordPacketUnreadable) {
		t.Fatalf("a file that is no packet: %v", err)
	}

	if *updateRecordPackets {
		vector, err := json.MarshalIndent(&testPacketVector{
			Comment: "A good approval-profile packet with the log key a recipient pins: `ur record verify` passes it offline, and fails it with any byte of a note, a path, a header, a salt, a body or a decision changed (RECORD.md section 20). Made by TestRecordDiscloseApprovalPacketVerifiesOffline with -update-record-packets; every id and key is random test data.",
			LogKey:  world.logKey,
			Packet:  base64.StdEncoding.EncodeToString(disclosed.Packet),
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata/record/packets", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testPacketVectorPath, append(vector, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The decision profile opens the decision and sends its approval as a header alone: a person decided on a hash, and
// no more, so the request's summary and action stay in the log.
func TestRecordDiscloseDecisionProfileKeepsTheRequestClosed(t *testing.T) {
	world := newTestDiscloseWorld(t)
	args := world.approvalArgs()
	args.Profile = sidecar.RecordDisclosureProfileDecision
	disclosed, err := world.adminRecord.Disclosure().Disclose(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disclosed.Packet, []byte("set the app's address")) || bytes.Contains(disclosed.Packet, []byte("198.51.100.7")) {
		t.Fatal("the decision profile opened the request's summary or action")
	}
	report := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}})
	if !report.Ok || len(report.Entries) != 2 {
		t.Fatalf("the decision profile's packet: %d entries, %v", len(report.Entries), testVerifyFailures(report))
	}
	for _, entry := range report.Entries {
		if entry.Opened != (entry.Kind == sidecar.RecordKindApprovalDecision) {
			t.Errorf("a %s entry opened: %t", entry.Kind, entry.Opened)
		}
	}
}

// Only a person's confirmed command discloses, of one thing, and of what was shown: a caller under a harness process
// is refused before anything is read, a dry run included.
func TestRecordDiscloseRefusals(t *testing.T) {
	world := newTestDiscloseWorld(t)
	disclosure := world.adminRecord.Disclosure()
	change := func(change func(args *sidecar.RecordDiscloseArgs)) *sidecar.RecordDiscloseArgs {
		args := world.approvalArgs()
		change(args)
		return args
	}
	harness := change(func(args *sidecar.RecordDiscloseArgs) { args.HarnessAncestor = true })
	if _, err := disclosure.Plan(t.Context(), harness); !errors.Is(err, sidecar.ErrRecordDisclosureHarness) {
		t.Fatalf("a dry run under a harness: %v", err)
	}
	if _, err := disclosure.Disclose(t.Context(), harness); !errors.Is(err, sidecar.ErrRecordDisclosureHarness) {
		t.Fatalf("a packet under a harness: %v", err)
	}
	if _, err := disclosure.Open(t.Context(), &sidecar.RecordOpenArgs{EntryIds: []sidecar.Id{world.vaultContextId}, Confirmed: true, HarnessAncestor: true}); !errors.Is(err, sidecar.ErrRecordDisclosureHarness) {
		t.Fatalf("an opening under a harness: %v", err)
	}
	if _, err := disclosure.Disclose(t.Context(), change(func(args *sidecar.RecordDiscloseArgs) { args.Confirmed = false })); !errors.Is(err, sidecar.ErrRecordDisclosureUnconfirmed) {
		t.Fatalf("an unconfirmed packet: %v", err)
	}
	if _, err := disclosure.Disclose(t.Context(), change(func(args *sidecar.RecordDiscloseArgs) { args.RunId = &world.runId })); !errors.Is(err, sidecar.ErrRecordDisclosureArgs) {
		t.Fatalf("two selectors: %v", err)
	}
	if _, err := disclosure.Disclose(t.Context(), change(func(args *sidecar.RecordDiscloseArgs) { args.Profile = sidecar.RecordDisclosureProfileRun })); !errors.Is(err, sidecar.ErrRecordDisclosureArgs) {
		t.Fatalf("a run profile of an approval: %v", err)
	}
	if _, err := disclosure.Disclose(t.Context(), change(func(args *sidecar.RecordDiscloseArgs) { args.Purpose = string(bytes.Repeat([]byte{'p'}, 513)) })); !errors.Is(err, sidecar.ErrRecordDisclosureArgs) {
		t.Fatalf("a purpose past its cap: %v", err)
	}
	unknown := sidecar.NewId()
	if _, err := disclosure.Disclose(t.Context(), change(func(args *sidecar.RecordDiscloseArgs) { args.ApprovalId = &unknown })); !errors.Is(err, sidecar.ErrRecordDisclosureNotFound) {
		t.Fatalf("an approval the log does not hold: %v", err)
	}
	if _, err := disclosure.Disclose(t.Context(), change(func(args *sidecar.RecordDiscloseArgs) { args.ExpectEntryIds = []sidecar.Id{unknown} })); !errors.Is(err, sidecar.ErrRecordDisclosureChanged) {
		t.Fatalf("a selection that is not what was shown: %v", err)
	}
	if _, err := disclosure.Disclose(t.Context(), change(func(args *sidecar.RecordDiscloseArgs) { args.LogId = world.vaultId })); err == nil {
		t.Fatalf("a packet of a vault, which has no checkpoint")
	}
	if got := len(world.entriesOf(sidecar.RecordKindDisclosure)); got != 0 {
		t.Fatalf("a refused packet filed %d disclosure entries", got)
	}
	// with the verifiable log off, nothing covers an entry and no packet is built
	offWorld := newTestLogWorld(t)
	admin := offWorld.admin()
	record := admin.openWith(testLogNoWitness{t: t})
	ref := testLogEntry(t, record)
	if _, err := record.Disclosure().Disclose(t.Context(), &sidecar.RecordDiscloseArgs{LogId: offWorld.teamRecordId, EntryIds: []sidecar.Id{ref.EntryId}, Confirmed: true}); !errors.Is(err, sidecar.ErrRecordLogOff) {
		t.Fatalf("a packet with the verifiable log off: %v", err)
	}
}

// RECORD.md section 20: a disclosure that cannot land refuses the file. With the team record's gate closed the
// disclosure entry does not commit, and no packet is returned.
func TestRecordDiscloseRefusesTheFileWhenItsRecordCannotLand(t *testing.T) {
	world := newTestDiscloseWorld(t)
	// the entries are under a checkpoint already, so only the record is left to land
	testLogCheckpoint(t, world.testLogWorld, world.adminRecord)
	world.streams.SetGateClosed(world.teamRecordId, true)
	disclosed, err := world.adminRecord.Disclosure().Disclose(t.Context(), world.approvalArgs())
	if !errors.Is(err, sidecar.ErrRecordNotLanded) || disclosed != nil {
		t.Fatalf("a packet whose record did not land: %v", err)
	}
	world.streams.SetGateClosed(world.teamRecordId, false)
	if _, err := world.adminRecord.Disclosure().Disclose(t.Context(), world.approvalArgs()); err != nil {
		t.Fatalf("a packet once the gate opened: %v", err)
	}
}

// RECORD.md section 20: a receipt-only reader's packet files only receipts. It deposits a read entry of purpose 4
// naming the entries, files no disclosure entry, and its packet verifies all the same.
func TestRecordDiscloseReceiptOnlyReaderFilesOnlyReceipts(t *testing.T) {
	world := newTestDiscloseWorld(t)
	testLogCheckpoint(t, world.testLogWorld, world.adminRecord)
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
	disclosed, err := record.Disclosure().Disclose(t.Context(), world.approvalArgs())
	if err != nil {
		t.Fatal(err)
	}
	if !disclosed.ReceiptsOnly {
		t.Fatal("a receipt-only reader's record is not its receipts")
	}
	deposits, err := world.streams.For(world.admin.sidecarId).ReadDeposits(t.Context(), world.teamRecordId, reader.sidecarId)
	if err != nil || len(deposits) != 1 {
		t.Fatalf("%d deposits from the reader: %v", len(deposits), err)
	}
	entries, err := sidecar.RecordDepositBatchParse(deposits[0].Batch, reader.settings.DepositByteCount)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the reader's deposit: %v", err)
	}
	header, err := sidecar.ParseStoredRecordHeader(testSignedBody(t, entries[0].Signed))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sidecar.RecordOpen(header, entries[0].SealedBody, entries[0].Key, entries[0].Salt)
	if err != nil {
		t.Fatal(err)
	}
	read := &protocol.ReadBody{}
	if err := proto.Unmarshal(opened, read); err != nil {
		t.Fatal(err)
	}
	if header.Kind() != sidecar.RecordKindRead || read.GetPurpose() != uint32(sidecar.RecordReadPurposeDisclosure) || len(read.GetObjectIds()) != 4 {
		t.Fatalf("the reader's receipt: a %s of purpose %d naming %d", header.Kind(), read.GetPurpose(), len(read.GetObjectIds()))
	}
	if got := len(world.entriesOf(sidecar.RecordKindDisclosure)); got != 0 {
		t.Fatalf("a receipt-only reader filed %d disclosure entries", got)
	}
	if report := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}}); !report.Ok {
		t.Fatalf("the reader's packet: %v", testVerifyFailures(report))
	}
	// a receipt that cannot land refuses the file
	world.streams.SetGateClosed(world.teamRecordId, true)
	args := world.approvalArgs()
	args.Profile = sidecar.RecordDisclosureProfileDecision
	world.clock.Advance(25 * 60 * 60 * 1000 * 1000 * 1000)
	if _, err := record.Disclosure().Disclose(t.Context(), args); err == nil {
		t.Fatal("a packet whose receipts did not land")
	}
}

// The body a stored Signed holds.
func testSignedBody(t *testing.T, storedSigned []byte) []byte {
	t.Helper()
	header, err := sidecar.VerifyRecordOpening(&protocol.Opening{Header: storedSigned})
	if err != nil {
		t.Fatal(err)
	}
	return header.Header.Bytes
}

// An erased entry goes as a header alone, showing it existed and is gone: the packet verifies, and holds no body of
// it whatever the profile asked.
func TestRecordDiscloseErasedEntryGoesAsAHeaderAlone(t *testing.T) {
	world := newTestDiscloseWorld(t)
	approvals := world.entriesOf(sidecar.RecordKindApproval)
	if len(approvals) != 1 || len(approvals[0].Copies) == 0 {
		t.Fatalf("%d approval entries", len(approvals))
	}
	place := approvals[0].Copies[0]
	if _, err := world.streams.For(world.admin.sidecarId).Erase(t.Context(), world.teamRecordId, &sidecar.RecordStreamErase{
		PushId: sidecar.NewId(), Keys: []*sidecar.RecordSlotKey{{SlotId: place.SlotId, KeyIndex: place.KeyIndex}}, SealedNote: []byte("a sealed note"),
	}); err != nil {
		t.Fatal(err)
	}
	disclosed, err := world.adminRecord.Disclosure().Disclose(t.Context(), &sidecar.RecordDiscloseArgs{
		LogId: world.teamRecordId, EntryIds: []sidecar.Id{approvals[0].EntryId}, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !disclosed.Plan.Items[0].Erased || disclosed.Plan.Items[0].Opened || bytes.Contains(disclosed.Packet, []byte("set the app's address")) {
		t.Fatalf("an erased entry's item: %+v", disclosed.Plan.Items[0])
	}
	report := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}})
	if !report.Ok || report.Entries[0].Opened {
		t.Fatalf("an erased entry's packet: %v", testVerifyFailures(report))
	}
}

// Section 11's content row: a T entry's ContentRef opens only with the author's Opening, made on the author's
// consented device, which files its own disclosure entry in the vault. The run profile's packet carries it, the
// verifier checks it against the ContentRef, and an admin's device cannot make one.
func TestRecordDiscloseRunPacketCarriesTheAuthorsOpenings(t *testing.T) {
	world := newTestDiscloseWorld(t)
	if _, err := world.adminRecord.Disclosure().Open(t.Context(), &sidecar.RecordOpenArgs{EntryIds: []sidecar.Id{world.vaultContextId}, Confirmed: true}); !errors.Is(err, sidecar.ErrRecordNotReader) {
		t.Fatalf("an admin opening a member's vault entry: %v", err)
	}
	if _, err := world.memberRecord.Disclosure().Open(t.Context(), &sidecar.RecordOpenArgs{EntryIds: []sidecar.Id{world.vaultContextId}}); !errors.Is(err, sidecar.ErrRecordDisclosureUnconfirmed) {
		t.Fatalf("an unconfirmed opening: %v", err)
	}
	opening, err := world.memberRecord.Disclosure().Open(t.Context(), &sidecar.RecordOpenArgs{
		EntryIds: []sidecar.Id{world.vaultContextId}, Recipient: "client.example", Purpose: "the run's context", Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(opening.Packet, []byte("tune the limiter")) {
		t.Fatal("the author's opening does not hold the vault entry's body")
	}
	// the vault holds the author's own record of the act
	vaultReader := world.newReader(nil, nil)
	disclosures := 0
	for _, entry := range vaultReader.sync(t, world.testRecordWorld) {
		if entry.Kind() != sidecar.RecordKindDisclosure {
			continue
		}
		disclosures += 1
		body := &protocol.DisclosureBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil {
			t.Fatal(err)
		}
		if body.GetAct() != sidecar.RecordDisclosureActOpening || !bytes.Equal(body.GetPacketSha256(), opening.PacketSha256[:]) {
			t.Fatalf("the vault's disclosure entry: %+v", body)
		}
	}
	if disclosures != 1 {
		t.Fatalf("%d disclosure entries in the vault", disclosures)
	}

	args := &sidecar.RecordDiscloseArgs{LogId: world.teamRecordId, RunId: &world.runId, Content: [][]byte{opening.Packet}, Confirmed: true}
	disclosed, err := world.adminRecord.Disclosure().Disclose(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	kinds := []sidecar.RecordKind{}
	contentCount := 0
	for _, item := range disclosed.Plan.Items {
		kinds = append(kinds, item.Kind)
		contentCount += item.ContentCount
		if !item.Opened {
			t.Errorf("the run profile left a %s closed", item.Kind)
		}
	}
	slices.Sort(kinds)
	want := []sidecar.RecordKind{sidecar.RecordKindContext, sidecar.RecordKindChange, sidecar.RecordKindApproval, sidecar.RecordKindApprovalDecision, sidecar.RecordKindApprovalUse, sidecar.RecordKindCoverage}
	slices.Sort(want)
	if !slices.Equal(kinds, want) || contentCount != 1 {
		t.Fatalf("the run profile took %v with %d content openings", kinds, contentCount)
	}
	report := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}})
	if !report.Ok {
		t.Fatalf("the run's packet: %v", testVerifyFailures(report))
	}
	// T's projection holds no title; the packet does, by the author's opening alone
	if !bytes.Contains(disclosed.Packet, []byte("tune the limiter")) {
		t.Fatal("the packet does not carry the author's opening")
	}
	// a content opening with its body changed fails step 5
	packet := &protocol.DisclosurePacket{}
	if err := proto.Unmarshal(disclosed.Packet, packet); err != nil {
		t.Fatal(err)
	}
	for _, entry := range packet.GetEntries() {
		for _, content := range entry.GetContent() {
			content.Body[len(content.Body)-1] ^= 1
		}
	}
	altered, err := proto.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	if report := testVerifyPacket(t, altered, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}}); report.Ok {
		t.Fatal("a packet with a content body changed verified")
	}
	// an opening no entry of the packet references is refused, never packed
	approvalArgs := world.approvalArgs()
	approvalArgs.Profile = sidecar.RecordDisclosureProfileDecision
	approvalArgs.Content = [][]byte{opening.Packet}
	if _, err := world.adminRecord.Disclosure().Disclose(t.Context(), approvalArgs); !errors.Is(err, sidecar.ErrRecordDisclosureArgs) {
		t.Fatalf("an opening nothing references: %v", err)
	}
}

// RECORD.md section 20: a packet spanning a key rotation verifies under both log keys and fails under one. An entry
// of the old checkpointer's cosigned batch keeps that batch's note, and one filed after the successor took over has
// the successor's.
func TestRecordDisclosePacketSpansAKeyRotation(t *testing.T) {
	witness := newTestLogWitness(t, "auditor")
	world := newTestDiscloseWorld(t, witness)
	oldEntry := testLogEntry(t, world.adminRecord)
	testLogCheckpoint(t, world.testLogWorld, world.adminRecord)
	// the old checkpointer's next entry files the witness's cosignature of that batch
	testLogEntry(t, world.adminRecord)
	testLogCheckpoint(t, world.testLogWorld, world.adminRecord)

	successor := world.testLogWorld.admin()
	successorRecord := successor.openWith(witness)
	if err := successorRecord.Log().On(t.Context(), &sidecar.RecordLogOnArgs{LogId: world.teamRecordId, Confirmed: true, Witnesses: []*sidecar.RecordLogWitnessArgs{witness.args()}}); err != nil {
		t.Fatal(err)
	}
	newEntry := testLogEntry(t, successorRecord)
	// the witness does not trust the successor's key yet, so its note has no cosignature
	testLogCheckpoint(t, world.testLogWorld, successorRecord)
	newKey := testLogStatus(t, world.testLogWorld, successorRecord).LogKey
	if newKey == world.logKey {
		t.Fatal("the successor signs with the old log key")
	}
	disclosed, err := successorRecord.Disclosure().Disclose(t.Context(), &sidecar.RecordDiscloseArgs{
		LogId: world.teamRecordId, EntryIds: []sidecar.Id{oldEntry.EntryId, newEntry.EntryId}, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	both := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey, newKey}})
	if !both.Ok || len(both.Checkpoints) != 2 {
		t.Fatalf("under both keys, %d notes: %v", len(both.Checkpoints), testVerifyFailures(both))
	}
	for _, keys := range [][]string{{world.logKey}, {newKey}} {
		if report := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: keys}); report.Ok {
			t.Fatalf("a packet spanning the rotation verified under one key")
		}
	}
	// the old note carries the witness's cosignature, with its time; the successor's has none yet, so asking for
	// the witness on every note fails and says which
	witnessKey := witness.args().Vkey
	cosigned := 0
	quorum := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey, newKey}, WitnessKeys: []string{witnessKey}})
	for _, checkpoint := range quorum.Checkpoints {
		if len(checkpoint.Cosigned) == 1 && checkpoint.Cosigned[0].Name == "auditor" && 0 < checkpoint.Cosigned[0].TimeSeconds {
			cosigned += 1
		}
	}
	if quorum.Ok || cosigned != 1 {
		t.Fatalf("with the witness asked for on every note: ok %t, %d notes cosigned", quorum.Ok, cosigned)
	}
}
