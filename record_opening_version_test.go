//go:build !sidecar_http && !ios_extension

// Opening.version (QD-864, question record-m6-03-opening-entry-version) at every opener and every consumer that
// reads an opening's body, on sidecartest's streams and authorization state: an Opening of a version-2 entry states
// 2 and its reader shows the kind's message from inside the AgentSignedBody, the agent verified; a version-1 Opening
// is written without the field, as it always was, and bytes from before the field read as 1; a wrong version fails
// to read and passes nothing; a later version stands on its commitment alone. For a copy in the author's vault, a
// disclosure packet and its verifier's reading of an approval request and decision, an author's opening carried as
// content, and an export line with bodies, whose entry_version key is the same answer. External, as
// record_agent_body_test.go, whose subkeys these use.

package sidecar_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A read entry's Opening as an opener writes it: the version only above 1.
func testOpeningOf(entry *sidecar.RecordReadEntry) *protocol.Opening {
	opening := &protocol.Opening{Header: entry.SignedBytes, Salt: entry.Salt, Body: entry.CommittedBody()}
	if 1 < entry.Version {
		opening.Version = entry.Version
	}
	return opening
}

// The packet's entry of kind, and its header.
func testPacketEntryOf(t *testing.T, packet *protocol.DisclosurePacket, kind sidecar.RecordKind) *protocol.DisclosedEntry {
	t.Helper()
	for _, entry := range packet.GetEntries() {
		opened, err := sidecar.VerifyRecordOpening(&protocol.Opening{Header: entry.GetOpening().GetHeader()})
		if err == nil && opened.Header.Kind() == kind {
			return entry
		}
	}
	t.Fatalf("the packet has no %s entry", kind)
	return nil
}

// The report's entry of kind.
func testReportEntryOf(t *testing.T, report *sidecar.RecordVerifyReport, kind sidecar.RecordKind) *sidecar.RecordVerifyEntry {
	t.Helper()
	for _, entry := range report.Entries {
		if entry.Kind == kind {
			return entry
		}
	}
	t.Fatalf("the report has no %s entry", kind)
	return nil
}

// A packet's bytes with one change made to it, verified under the world's log key.
func testVerifyChangedPacket(t *testing.T, world *testDiscloseWorld, packetBytes []byte, change func(packet *protocol.DisclosurePacket)) *sidecar.RecordVerifyReport {
	t.Helper()
	packet := &protocol.DisclosurePacket{}
	if err := proto.Unmarshal(packetBytes, packet); err != nil {
		t.Fatal(err)
	}
	change(packet)
	changed, err := proto.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	return testVerifyPacket(t, changed, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}})
}

// An opening reads by the version it states, and by nothing else: a version-2 entry's as the AgentSignedBody
// holding its kind's message, a version-1 entry's as the message, bytes from before the field as version 1, a wrong
// version as nothing, and a later version as its commitment alone.
func TestRecordOpeningVersionReadsTheBodyItStates(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	newTestAgentSubkeys(t, device)
	record := device.open()
	agentId := sidecar.NewId()
	ref := testRecordAppend(t, record, testAgentNote(agentId, "from the agent"))
	testRecordAppend(t, record, testRecordNote(nil, "from the daemon"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	entries := world.newReader(nil, nil).sync(t, world)
	if len(entries) != 2 {
		t.Fatalf("%d entries read", len(entries))
	}
	agentEntry, daemonEntry := entries[0], entries[1]
	if agentEntry.EntryId != ref.EntryId {
		agentEntry, daemonEntry = entries[1], entries[0]
	}
	if agentEntry.Version != 2 || daemonEntry.Version != 1 {
		t.Fatalf("versions %d and %d", agentEntry.Version, daemonEntry.Version)
	}
	identityKey := device.key.Public().(ed25519.PublicKey)

	// version 2: the opening states it, and its reader shows the note from inside the AgentSignedBody, verified
	opened, err := sidecar.VerifyRecordOpening(testOpeningOf(agentEntry))
	if err != nil || opened.Version != 2 {
		t.Fatalf("the agent entry's opening reads version %d: %v", opened.Version, err)
	}
	message, provenance, err := opened.KindBody(identityKey, nil)
	if err != nil || provenance != sidecar.RecordAgentProvenanceVerified || testAgentNoteText(t, message) != "from the agent" {
		t.Fatalf("the agent entry's opening shows %q, %q: %v", message, provenance, err)
	}
	if !bytes.Equal(message, agentEntry.Body) || bytes.Equal(message, opened.Body) {
		t.Error("the message is not the kind's own, apart from the committed bytes")
	}
	// under another key than the writer's the agent is not attributed, and the caller is told
	otherKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, provenance, err := opened.KindBody(otherKey, nil); err != nil || provenance != sidecar.RecordAgentProvenanceInvalid {
		t.Errorf("under another identity key: %q, %v", provenance, err)
	}

	// version 1: written without the field, the bytes an opening always was, and read as the kind's message
	daemonOpening := testOpeningOf(daemonEntry)
	written, err := proto.MarshalOptions{Deterministic: true}.Marshal(daemonOpening)
	if err != nil {
		t.Fatal(err)
	}
	old := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), daemonEntry.SignedBytes)
	old = protowire.AppendBytes(protowire.AppendTag(old, 2, protowire.BytesType), daemonEntry.Salt)
	old = protowire.AppendBytes(protowire.AppendTag(old, 3, protowire.BytesType), daemonEntry.Body)
	if !bytes.Equal(written, old) {
		t.Fatal("a version-1 opening is not the bytes it was before the field")
	}
	// an opening from before the field: three fields, no version, read as 1
	parsed := &protocol.Opening{}
	if err := proto.Unmarshal(old, parsed); err != nil {
		t.Fatal(err)
	}
	opened, err = sidecar.VerifyRecordOpening(parsed)
	if err != nil || opened.Version != 1 {
		t.Fatalf("an opening without the field reads version %d: %v", opened.Version, err)
	}
	message, provenance, err = opened.KindBody(identityKey, nil)
	if err != nil || provenance != "" || testAgentNoteText(t, message) != "from the daemon" {
		t.Fatalf("a version-1 opening shows %q, %q: %v", message, provenance, err)
	}
	// stated outright, version 1 reads the same
	parsed.Version = 1
	if opened, err := sidecar.VerifyRecordOpening(parsed); err != nil || opened.Version != 1 {
		t.Errorf("an opening stating version 1: %v", err)
	}

	// a copy states what its entries were sealed as: nothing for version 1, however it was handed in
	copyBody, err := sidecar.NewRecordCopyBody([]*sidecar.RecordOpened{
		{SignedBytes: agentEntry.SignedBytes, Salt: agentEntry.Salt, Body: agentEntry.CommittedBody(), Version: agentEntry.Version},
		{SignedBytes: daemonEntry.SignedBytes, Salt: daemonEntry.Salt, Body: daemonEntry.Body, Version: 1},
		{SignedBytes: daemonEntry.SignedBytes, Salt: daemonEntry.Salt, Body: daemonEntry.Body},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := copyBody.GetEntries(); got[0].GetVersion() != 2 || got[1].GetVersion() != 0 || got[2].GetVersion() != 0 {
		t.Errorf("a copy's openings state versions %d, %d and %d", got[0].GetVersion(), got[1].GetVersion(), got[2].GetVersion())
	}

	// a wrong version: the commitment still opens, since it binds the bytes, and the body reads as nothing
	wrongDown := testOpeningOf(agentEntry)
	wrongDown.Version = 0
	opened, err = sidecar.VerifyRecordOpening(wrongDown)
	if err != nil {
		t.Fatalf("a version-2 entry's opening stating 1 no longer opens its commitment: %v", err)
	}
	if message, _, err := opened.KindBody(identityKey, nil); !errors.Is(err, sidecar.ErrRecordBodyInvalid) || message != nil {
		t.Errorf("an AgentSignedBody read as its kind's message: %q, %v", message, err)
	}
	wrongUp := testOpeningOf(daemonEntry)
	wrongUp.Version = 2
	opened, err = sidecar.VerifyRecordOpening(wrongUp)
	if err != nil {
		t.Fatalf("a version-1 entry's opening stating 2 no longer opens its commitment: %v", err)
	}
	if message, provenance, err := opened.KindBody(identityKey, nil); err == nil && provenance != sidecar.RecordAgentProvenanceInvalid {
		t.Errorf("a kind's message read as an AgentSignedBody: %q, %q", message, provenance)
	}

	// a version this build does not read: the commitment, and nothing parsed
	later := testOpeningOf(agentEntry)
	later.Version = 3
	opened, err = sidecar.VerifyRecordOpening(later)
	if err != nil || opened.Version != 3 {
		t.Fatalf("a later version's opening: %v", err)
	}
	if message, _, err := opened.KindBody(identityKey, nil); !errors.Is(err, sidecar.ErrRecordOpeningVersion) || message != nil {
		t.Errorf("a later version's body: %q, %v", message, err)
	}
	// a header alone holds no body, whatever version it states
	opened, err = sidecar.VerifyRecordOpening(&protocol.Opening{Header: agentEntry.SignedBytes, Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := opened.KindBody(identityKey, nil); !errors.Is(err, sidecar.ErrRecordBodyInvalid) {
		t.Errorf("a header alone: %v", err)
	}
}

// The copies a member's vault keeps of what it deposited to T state each entry's version: 2 where an agent's subkey
// signed inside the body, and then the copy's reader shows T's projection from inside it; and nothing where the
// writer signs no agent's entries, each copy's opening being the three fields it was.
func TestRecordOpeningVersionOfATeamCopy(t *testing.T) {
	for _, signing := range []bool{true, false} {
		world := newTestTeamWorld(t)
		device := world.memberDevice(true)
		if signing {
			newTestAgentSubkeys(t, device)
		}
		record := device.open()
		runId := sidecar.NewId()
		world.runs.StartRun(runId)
		agentId := sidecar.NewId()
		for _, draft := range testTeamRunDrafts(&runId) {
			draft.AgentId = &agentId
			if _, err := record.Writer().Append(draft); err != nil {
				t.Fatal(err)
			}
		}
		if err := record.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
		identityKey := device.key.Public().(ed25519.PublicKey)
		copies := 0
		for _, entry := range world.newReader(nil, nil).sync(t, world.testRecordWorld) {
			if entry.Kind() != sidecar.RecordKindCopy {
				continue
			}
			body := &protocol.CopyBody{}
			if err := proto.Unmarshal(entry.Body, body); err != nil || len(body.GetEntries()) != 1 {
				t.Fatalf("signing %t: a copy: %v", signing, err)
			}
			opening := body.GetEntries()[0]
			opened, err := sidecar.VerifyRecordOpening(opening)
			if err != nil {
				t.Fatalf("signing %t: a copy's opening: %v", signing, err)
			}
			message, provenance, err := opened.KindBody(identityKey, nil)
			if err != nil {
				t.Fatalf("signing %t: a copy of T's %s entry does not read: %v", signing, opened.Header.Kind(), err)
			}
			if err := sidecar.RecordBodyValidateStored(opened.Header.Kind(), message); err != nil {
				t.Errorf("signing %t: a copy shows no %s: %v", signing, opened.Header.Kind(), err)
			}
			if signing {
				if opening.GetVersion() != 2 || opened.Version != 2 || provenance != sidecar.RecordAgentProvenanceVerified {
					t.Errorf("a copy of a version-2 entry states version %d, its agent %q", opening.GetVersion(), provenance)
				}
				signedBody := &protocol.AgentSignedBody{}
				if err := proto.Unmarshal(opening.GetBody(), signedBody); err != nil || !bytes.Equal(signedBody.GetBody(), message) {
					t.Errorf("the message is not the body the AgentSignedBody holds: %v", err)
				}
			} else if opening.GetVersion() != 0 || opened.Version != 1 || provenance != "" || !bytes.Equal(message, opening.GetBody()) {
				t.Errorf("a copy of a version-1 entry states version %d, its agent %q", opening.GetVersion(), provenance)
			}
			copies += 1
		}
		if copies != 3 {
			t.Errorf("signing %t: %d copies", signing, copies)
		}
	}
}

// A packet of a run an agent's subkey signed: each opened entry states its version, the verifier reads the approval
// request and its decision from the kind's message each version gives, the decision still bound to the request, and
// reports each agent signature. A version changed in the file fails the entry it is on and passes nothing: a
// version-2 request stated as 1, a version-1 decision stated as 2, and either stated as a version no build reads.
func TestRecordOpeningVersionInAPacket(t *testing.T) {
	agentId := sidecar.NewId()
	world := newTestDiscloseWorldWith(t, &testDiscloseOptions{
		agentId:       &agentId,
		prepareMember: func(member *testRecordDevice) { newTestAgentSubkeys(t, member) },
	})
	disclosed, err := world.adminRecord.Disclosure().Disclose(t.Context(), world.approvalArgs())
	if err != nil {
		t.Fatal(err)
	}
	packet := &protocol.DisclosurePacket{}
	if err := proto.Unmarshal(disclosed.Packet, packet); err != nil {
		t.Fatal(err)
	}
	wantVersions := map[sidecar.RecordKind]uint32{
		sidecar.RecordKindApproval:         2,
		sidecar.RecordKindApprovalUse:      2,
		sidecar.RecordKindApprovalDecision: 0,
		// a header alone states none
		sidecar.RecordKindCoverage: 0,
	}
	for kind, version := range wantVersions {
		if got := testPacketEntryOf(t, packet, kind).GetOpening().GetVersion(); got != version {
			t.Errorf("the packet's %s opening states version %d, not %d", kind, got, version)
		}
	}
	// the request's opening holds an AgentSignedBody, and the request inside it
	requestOpening := testPacketEntryOf(t, packet, sidecar.RecordKindApproval).GetOpening()
	signedBody := &protocol.AgentSignedBody{}
	if err := proto.Unmarshal(requestOpening.GetBody(), signedBody); err != nil || !bytes.Equal(signedBody.GetAgentId(), agentId.Bytes()) {
		t.Fatalf("the request's opening: %v", err)
	}
	if request, err := sidecar.ParseStoredApprovalRequest(signedBody.GetBody()); err != nil || request.ApprovalId() != world.approvalId {
		t.Fatalf("the request inside the AgentSignedBody: %v", err)
	}

	report := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}})
	if !report.Ok || len(report.Entries) != 4 {
		t.Fatalf("a good packet of version-2 entries: %v", testVerifyFailures(report))
	}
	for _, entry := range report.Entries {
		if !entry.Inclusion || !entry.Header || !entry.Body || !entry.Message || !entry.Content || !entry.Approval || entry.BodyGeneric {
			t.Errorf("a step did not pass for the %s entry: %+v", entry.Kind, entry)
		}
		switch entry.Kind {
		case sidecar.RecordKindApproval, sidecar.RecordKindApprovalUse:
			if entry.Version != 2 || entry.AgentProvenance != sidecar.RecordAgentProvenanceVerified {
				t.Errorf("the %s entry reports version %d, its agent %q", entry.Kind, entry.Version, entry.AgentProvenance)
			}
		default:
			if entry.Version != 1 || entry.AgentProvenance != "" {
				t.Errorf("the %s entry reports version %d, its agent %q", entry.Kind, entry.Version, entry.AgentProvenance)
			}
		}
	}

	cases := []struct {
		name    string
		kind    sidecar.RecordKind
		version uint32
		check   func(entry *sidecar.RecordVerifyEntry) bool
	}{
		// the AgentSignedBody is no ApprovalRequest's Signed: the request is not read
		{name: "a version-2 request stated as 1", kind: sidecar.RecordKindApproval, version: 0, check: func(entry *sidecar.RecordVerifyEntry) bool {
			return entry.Body && !entry.Approval
		}},
		// the decision's Signed is no AgentSignedBody naming the header's agent: never read on
		{name: "a version-1 decision stated as 2", kind: sidecar.RecordKindApprovalDecision, version: 2, check: func(entry *sidecar.RecordVerifyEntry) bool {
			return entry.Body && !entry.Message && !entry.Approval
		}},
		{name: "a request stated as a later version", kind: sidecar.RecordKindApproval, version: 3, check: func(entry *sidecar.RecordVerifyEntry) bool {
			return entry.Body && entry.BodyGeneric && !entry.Approval && entry.AgentProvenance == ""
		}},
		{name: "a decision stated as a later version", kind: sidecar.RecordKindApprovalDecision, version: 3, check: func(entry *sidecar.RecordVerifyEntry) bool {
			return entry.Body && entry.BodyGeneric && !entry.Approval
		}},
		// the use's body is read by no step, and its agent's signature is: an AgentSignedBody is no ApprovalUseBody
		{name: "a version-2 use stated as 1", kind: sidecar.RecordKindApprovalUse, version: 0, check: func(entry *sidecar.RecordVerifyEntry) bool {
			return entry.Body && !entry.Message && entry.AgentProvenance == ""
		}},
	}
	for _, c := range cases {
		report := testVerifyChangedPacket(t, world, disclosed.Packet, func(packet *protocol.DisclosurePacket) {
			testPacketEntryOf(t, packet, c.kind).Opening.Version = c.version
		})
		entry := testReportEntryOf(t, report, c.kind)
		if report.Ok || len(entry.Failures) == 0 || !c.check(entry) {
			t.Errorf("%s: ok %t, its entry %+v", c.name, report.Ok, entry)
		}
		// the commitment binds the bytes whatever the version says, and every other entry reads as it did
		for _, otherEntry := range report.Entries {
			if otherEntry.Kind != c.kind && (0 < len(otherEntry.Failures) || !otherEntry.Body) {
				t.Errorf("%s: the %s entry fails too: %v", c.name, otherEntry.Kind, otherEntry.Failures)
			}
		}
	}
}

// An author's opening of a version-2 vault entry states 2, rides a run's packet as content with its version, and
// the verifier reads it by that: the same opening stated as version 1 fails step 5.
func TestRecordOpeningVersionOfAnAuthorsOpening(t *testing.T) {
	agentId := sidecar.NewId()
	world := newTestDiscloseWorldWith(t, &testDiscloseOptions{
		agentId:       &agentId,
		prepareMember: func(member *testRecordDevice) { newTestAgentSubkeys(t, member) },
	})
	opening, err := world.memberRecord.Disclosure().Open(t.Context(), &sidecar.RecordOpenArgs{
		EntryIds: []sidecar.Id{world.vaultContextId}, Recipient: "client.example", Purpose: "the run's context", Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	authored := &protocol.DisclosurePacket{}
	if err := proto.Unmarshal(opening.Packet, authored); err != nil || len(authored.GetEntries()) != 1 {
		t.Fatalf("the author's opening: %v", err)
	}
	vaultOpening := authored.GetEntries()[0].GetOpening()
	opened, err := sidecar.VerifyRecordOpening(vaultOpening)
	if err != nil || vaultOpening.GetVersion() != 2 || opened.Version != 2 {
		t.Fatalf("the author's opening states version %d: %v", vaultOpening.GetVersion(), err)
	}
	message, provenance, err := opened.KindBody(world.member.key.Public().(ed25519.PublicKey), nil)
	if err != nil || provenance != sidecar.RecordAgentProvenanceVerified {
		t.Fatalf("the author's opening reads %q: %v", provenance, err)
	}
	context := &protocol.ContextBody{}
	if err := proto.Unmarshal(message, context); err != nil || context.GetTitle() != "tune the limiter" {
		t.Fatalf("the author's opening shows the context %+v: %v", context, err)
	}

	disclosed, err := world.adminRecord.Disclosure().Disclose(t.Context(), &sidecar.RecordDiscloseArgs{
		LogId: world.teamRecordId, RunId: &world.runId, Content: [][]byte{opening.Packet}, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	packet := &protocol.DisclosurePacket{}
	if err := proto.Unmarshal(disclosed.Packet, packet); err != nil {
		t.Fatal(err)
	}
	contentCount := 0
	for _, entry := range packet.GetEntries() {
		for _, content := range entry.GetContent() {
			contentCount += 1
			if content.GetVersion() != 2 {
				t.Errorf("a content opening rides the packet stating version %d", content.GetVersion())
			}
		}
	}
	if contentCount != 1 {
		t.Fatalf("%d content openings", contentCount)
	}
	if report := testVerifyPacket(t, disclosed.Packet, &sidecar.RecordVerifyArgs{LogKeys: []string{world.logKey}}); !report.Ok {
		t.Fatalf("the run's packet: %v", testVerifyFailures(report))
	}
	report := testVerifyChangedPacket(t, world, disclosed.Packet, func(packet *protocol.DisclosurePacket) {
		for _, entry := range packet.GetEntries() {
			for _, content := range entry.GetContent() {
				content.Version = 0
			}
		}
	})
	contentFailed := false
	for _, entry := range report.Entries {
		contentFailed = contentFailed || (!entry.Content && entry.Body)
	}
	if report.Ok || !contentFailed {
		t.Fatalf("a version-2 content opening stated as 1 verified: %v", testVerifyFailures(report))
	}
}

// An export line with bodies is the same answer in jsonl: entry_version is on a line whose entry is above version 1
// and on no other, and the Opening made of a line's header, salt, body and entry_version reads as the kind's
// message.
func TestRecordOpeningVersionOfAnExportLine(t *testing.T) {
	agentId := sidecar.NewId()
	world := newTestDiscloseWorldWith(t, &testDiscloseOptions{
		agentId:       &agentId,
		prepareMember: func(member *testRecordDevice) { newTestAgentSubkeys(t, member) },
	})
	keys := map[sidecar.Id]ed25519.PublicKey{
		world.admin.sidecarId:  world.admin.key.Public().(ed25519.PublicKey),
		world.member.sidecarId: world.member.key.Public().(ed25519.PublicKey),
	}
	lines, _ := testExport(t, world.adminRecord, &sidecar.RecordExportArgs{LogId: world.teamRecordId, Format: sidecar.RecordExportFormatJsonl, Bodies: true, Confirmed: true})
	versions := map[string]uint32{}
	for _, line := range lines {
		header, _ := base64.StdEncoding.DecodeString(line["header"].(string))
		salt, _ := base64.StdEncoding.DecodeString(line["salt"].(string))
		body, _ := base64.StdEncoding.DecodeString(line["body"].(string))
		opening := &protocol.Opening{Header: header, Salt: salt, Body: body}
		if entryVersion, ok := line["entry_version"]; ok {
			opening.Version = uint32(entryVersion.(float64))
			if opening.Version <= 1 {
				t.Errorf("a %s line states entry_version %d", line["kind"], opening.Version)
			}
		}
		opened, err := sidecar.VerifyRecordOpening(opening)
		if err != nil {
			t.Fatalf("a %s line's body does not open its header's commitment: %v", line["kind"], err)
		}
		message, provenance, err := opened.KindBody(keys[sidecar.Id(opened.Header.Header.GetWriterSidecarId())], nil)
		if err != nil {
			t.Fatalf("a %s line of version %d does not read: %v", line["kind"], opened.Version, err)
		}
		if (opened.Version == 2) != (provenance == sidecar.RecordAgentProvenanceVerified) {
			t.Errorf("a %s line of version %d reads its agent %q", line["kind"], opened.Version, provenance)
		}
		if opened.Header.Kind() == sidecar.RecordKindApproval {
			if request, err := sidecar.ParseStoredApprovalRequest(message); err != nil || request.ApprovalId() != world.approvalId {
				t.Errorf("the approval line's message is not the request: %v", err)
			}
		}
		versions[line["kind"].(string)] = opened.Version
	}
	if versions["approval"] != 2 || versions["approval_use"] != 2 || versions["approval_decision"] != 1 {
		t.Fatalf("the lines' versions: %v", versions)
	}
}
