// RECORD.md section 11's offline verifier, on every leg: `ur record verify` over one DisclosurePacket. It needs no
// daemon, network or keychain, and nothing here reads anything but the packet's bytes and the keys the caller pins:
// the log and witness keys come from the command line, never from the packet.
//
//	1 note       each checkpoint parses; a signature by a given log key verifies, and a note under no given key
//	             fails; at least quorum cosignatures by given witness keys verify, every one given by default; each
//	             cosignature's time is reported
//	2 inclusion  leaf(opening.header) reaches the note's root at its size by the path (RFC 9162 section 2.1.3.2)
//	3 header     VerifySigned(record-entry) under a key in keys; log_id equals the packet's
//	4 body       where opened, body_commitment recomputes
//	  message    an opened body is read as its Opening's version says, an absent one reading 1 (QD-864): the kind's
//	             message at 1; at 2 an AgentSignedBody holding it, whose agent signature is checked under the
//	             writer's key in keys and reported verified or agent_asserted, a failed one failing the entry; a
//	             later version is kept on its commitment alone and shown generically. The version is the opener's
//	             word, so a wrong one fails here or at step 6 and nothing is read by how bytes happen to parse
//	5 content    each content Opening's own header verifies, its entry_id and body_commitment equal a ContentRef's,
//	             and its body reads as its version says
//	6 approval   approval: its request parses. approval_decision: VerifySigned(approval, SIGNED_APPROVAL_DECISION)
//	             under a key in keys; beside its approval entry, request_sha256 is SHA-256 of that body and
//	             payload_sha256 of its canonical_action. Both from the kind's message as its version gives it, and
//	             an opened one that is not read fails
//	7 ssh        not checked: the owner dropped SSHSIGs from v0 (plan-MCP-risk-classifier#1), so an sshsig field is
//	             ignored and never trusted, and asking for the check is refused rather than passed
//	8 report     for each entry what passed, and each key's label marked as the team's statement
//
// A packet shows that an entry was in the team's log under the notes it carries, that its writer's key signed its
// header, and a body by its commitment. It does not show that the log holds every action, that a writer told the
// truth, or that a key is a named person: a key's owner is the team's statement, since the config repo stays sealed
// (section 11's table). The report says so for every key.
//
// A packet of an author's vault openings (`ur record open`) carries no checkpoint and is not a packet this verifies:
// its openings are checked as another packet's content, at step 5.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The packet's format values (RECORD.md section 11's messages).
const (
	RecordDisclosurePacketVersion      = 1
	recordDisclosureEntryCount         = 1024
	recordDisclosureRecipientByteCount = 128
	recordDisclosurePurposeByteCount   = 512
)

var (
	// The file is no DisclosurePacket this build reads: `ur record verify` exits 2.
	ErrRecordPacketUnreadable = errors.New("record disclosure packet unreadable")
	// SSH signatures are not checked in this version, and a check that was asked for is not passed over.
	ErrRecordVerifySshUnbuilt = errors.New("record verify checks no ssh signature in this version")
)

// What the verifier pins: nothing of it comes from the packet.
type RecordVerifyArgs struct {
	// The log's verifier keys, a successor's among them: a note must verify under one.
	LogKeys []string
	// The witnesses' verifier keys.
	WitnessKeys []string
	// How many of them must have cosigned each note: 0 for every one given.
	Quorum int
	// --ssh-key was given: refused, since nothing here checks an sshsig.
	SshKeys bool
	// The certificate bounds a version-2 entry's agent signature is held to: nil for the defaults, the format's.
	AgentSubkeys *SidecarAgentSubkeySettings
}

// One cosignature a note carries under a pinned witness key.
type RecordVerifyCosignature struct {
	Name        string
	TimeSeconds uint64
}

// One checkpoint of the packet.
type RecordVerifyCheckpoint struct {
	Size uint64
	Root []byte
	// The pinned log key it verified under, empty for none.
	LogKey   string
	Cosigned []*RecordVerifyCosignature
	Failures []string
}

// One entry of the packet, with what passed.
type RecordVerifyEntry struct {
	EntryId         Id
	Kind            RecordKind
	TimeMillis      int64
	WriterSidecarId Id
	LeafIndex       uint64
	// The body is in the packet: false for a header alone, an erased entry's among them.
	Opened bool
	// Steps 2 to 6: true where the step passed, and where it did not apply.
	Inclusion bool
	Header    bool
	Body      bool
	// The opened body reads as its version says, its agent signature not failing: true for a header alone, and for
	// a version this build does not read, which BodyGeneric marks.
	Message  bool
	Content  bool
	Approval bool
	// The opening's version, an absent one reading 1: the opener's word for what the body is.
	Version uint32
	// A version this build does not read: the body stands on its commitment alone and nothing in it was checked.
	BodyGeneric bool
	// What a version-2 body's agent signature came to: verified or agent_asserted, or invalid beside its failure.
	// Empty for version 1, whose agent is the writer's word.
	AgentProvenance RecordAgentProvenance
	// How many content openings the entry carries.
	ContentCount int
	Failures     []string
}

// One key the packet states.
type RecordVerifyKey struct {
	SidecarId Id
	KeyId     []byte
	Label     string
	// The label is the team's statement: always, since no ssh signature is checked.
	TeamStated bool
}

// What `ur record verify` reports.
type RecordVerifyReport struct {
	// Every check passed: exit 0, else 1.
	Ok          bool
	LogId       Id
	Origin      string
	Purpose     string
	Checkpoints []*RecordVerifyCheckpoint
	Entries     []*RecordVerifyEntry
	Keys        []*RecordVerifyKey
	// Failures of the packet as a whole.
	Failures []string
}

// Parses a packet's bytes, holding it to section 11's shape: ErrRecordPacketUnreadable otherwise.
func ParseRecordDisclosurePacket(packetBytes []byte) (*protocol.DisclosurePacket, error) {
	packet := &protocol.DisclosurePacket{}
	if err := proto.Unmarshal(packetBytes, packet); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordPacketUnreadable, err)
	}
	if packet.GetVersion() != RecordDisclosurePacketVersion {
		return nil, fmt.Errorf("%w: version %d", ErrRecordPacketUnreadable, packet.GetVersion())
	}
	if len(packet.GetLogId()) != recordIdByteCount || len(packet.GetEntries()) == 0 || recordDisclosureEntryCount < len(packet.GetEntries()) {
		return nil, fmt.Errorf("%w: a log id of %d bytes and %d entries", ErrRecordPacketUnreadable, len(packet.GetLogId()), len(packet.GetEntries()))
	}
	for _, entry := range packet.GetEntries() {
		if entry.GetOpening() == nil || len(entry.GetOpening().GetHeader()) == 0 || recordLogPathHashCount < len(entry.GetInclusionPath()) {
			return nil, fmt.Errorf("%w: an entry with no header, or a path past %d hashes", ErrRecordPacketUnreadable, recordLogPathHashCount)
		}
	}
	return packet, nil
}

// The key of keys that signed, by its key id when the Signed names one, else by its signer.
func recordDisclosedKeyFor(keys []*protocol.DisclosedKey, signed *bridge.Signed) *protocol.DisclosedKey {
	for _, key := range keys {
		if len(signed.GetKeyId()) != 0 {
			if bytes.Equal(key.GetKeyId(), signed.GetKeyId()) {
				return key
			}
			continue
		}
		if len(key.GetKeyId()) == 0 && bytes.Equal(key.GetSidecarId(), signed.GetSignerId()) {
			return key
		}
	}
	return nil
}

// What the verifier reads of one opening's body.
type recordVerifyBody struct {
	version uint32
	// salt and body recompute the header's commitment: true for a header alone
	committed bool
	// the kind's message as the version gives it: nil for a header alone, a body that did not commit, one that does
	// not read as its version says, and a version this build does not read
	message    []byte
	provenance RecordAgentProvenance
	generic    bool
	// why the body does not read as its version says, empty where it does
	failure string
}

// Step 4 and the reading after it for one opening: the commitment, then the body as the opening's version says,
// a version-2 entry's agent signature under the key keys states for the header's writer.
func recordVerifyOpeningBody(keys []*protocol.DisclosedKey, opening *protocol.Opening, settings *SidecarAgentSubkeySettings) *recordVerifyBody {
	body := &recordVerifyBody{version: max(opening.GetVersion(), recordEntryVersion)}
	opened, err := VerifyRecordOpening(opening)
	if err != nil {
		return body
	}
	body.committed = true
	if len(opened.Salt) == 0 {
		return body
	}
	var identityPublicKey []byte
	if _, signed, err := recordSignedHeader(opening.GetHeader()); err == nil && bytes.Equal(signed.GetSignerId(), opened.Header.Header.GetWriterSidecarId()) {
		if key := recordDisclosedKeyFor(keys, signed); key != nil && bridge.SignedKeyAlg(key.GetAlg()) == bridge.SignedKeyAlgEd25519 {
			identityPublicKey = key.GetPublicKey()
		}
	}
	message, provenance, err := opened.KindBody(identityPublicKey, settings)
	switch {
	case errors.Is(err, ErrRecordOpeningVersion):
		body.generic = true
	case err != nil:
		body.failure = fmt.Sprintf("its body does not read as version %d of its kind", body.version)
	case provenance == RecordAgentProvenanceInvalid:
		// never attributed, and never read on: a wrong version lands here as often as a bad signature
		body.provenance = provenance
		body.failure = "its agent's signature does not verify"
	default:
		body.message = message
		body.provenance = provenance
	}
	return body
}

// Step 3 for one stored header: its Signed verifies as a record entry's under a key in keys, as signed by its
// writer. The parsed header, or why not.
func recordVerifyOpeningHeader(keys []*protocol.DisclosedKey, storedSigned []byte) (*StoredRecordHeader, string) {
	header, signed, err := recordSignedHeader(storedSigned)
	if err != nil {
		return nil, "its header does not parse"
	}
	if !bytes.Equal(signed.GetSignerId(), header.Header.GetWriterSidecarId()) {
		return header, "its header is signed by another than its writer"
	}
	key := recordDisclosedKeyFor(keys, signed)
	if key == nil || bridge.SignedKeyAlg(key.GetAlg()) != bridge.SignedKeyAlgEd25519 {
		return header, "the packet states no identity key for its writer"
	}
	if err := bridge.VerifySigned(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, key.GetPublicKey()); err != nil {
		return header, "its header's signature does not verify under the key the packet states"
	}
	return header, ""
}

// Verifies packetBytes by section 11's steps. An error is a file that cannot be read, or a check asked for that is
// not built; every failed check is in the report, whose Ok is then false.
func VerifyRecordDisclosurePacket(packetBytes []byte, args *RecordVerifyArgs) (*RecordVerifyReport, error) {
	if args == nil {
		args = &RecordVerifyArgs{}
	}
	if args.SshKeys {
		return nil, ErrRecordVerifySshUnbuilt
	}
	packet, err := ParseRecordDisclosurePacket(packetBytes)
	if err != nil {
		return nil, err
	}
	logKeys := []*RecordLogVerifierKey{}
	for _, vkey := range args.LogKeys {
		key, err := ParseRecordLogVerifierKey(vkey)
		if err != nil || key.Type != RecordLogKeyTypeEd25519 {
			return nil, fmt.Errorf("%w: --log-key %q", ErrRecordLogNote, vkey)
		}
		logKeys = append(logKeys, key)
	}
	witnessKeys := []*RecordLogVerifierKey{}
	for _, vkey := range args.WitnessKeys {
		key, err := ParseRecordLogVerifierKey(vkey)
		if err != nil || key.Type == RecordLogKeyTypeEd25519 {
			return nil, fmt.Errorf("%w: --witness %q", ErrRecordLogNote, vkey)
		}
		witnessKeys = append(witnessKeys, key)
	}
	quorum := args.Quorum
	if quorum <= 0 {
		quorum = len(witnessKeys)
	}
	if len(witnessKeys) < quorum {
		return nil, fmt.Errorf("%w: a quorum of %d with %d witness keys", ErrRecordLogNote, quorum, len(witnessKeys))
	}
	logId := Id(packet.GetLogId())
	report := &RecordVerifyReport{LogId: logId, Origin: packet.GetOrigin(), Purpose: packet.GetPurpose()}
	fail := func(format string, a ...any) {
		report.Failures = append(report.Failures, fmt.Sprintf(format, a...))
	}
	if len(logKeys) == 0 {
		fail("no --log-key was given, so no note verifies")
	}
	if packet.GetOrigin() != RecordLogOrigin(logId) {
		fail("the packet's origin is not its log's")
	}
	for _, key := range packet.GetKeys() {
		reportKey := &RecordVerifyKey{KeyId: bytes.Clone(key.GetKeyId()), Label: key.GetLabel(), TeamStated: true}
		if len(key.GetSidecarId()) == recordIdByteCount {
			reportKey.SidecarId = Id(key.GetSidecarId())
		}
		report.Keys = append(report.Keys, reportKey)
	}

	// 1 note
	notes := []*RecordLogNote{}
	for i, checkpointBytes := range packet.GetCheckpoints() {
		checkpoint := &RecordVerifyCheckpoint{}
		report.Checkpoints = append(report.Checkpoints, checkpoint)
		note, err := ParseRecordLogNote(checkpointBytes)
		notes = append(notes, note)
		if err != nil {
			checkpoint.Failures = append(checkpoint.Failures, fmt.Sprintf("checkpoint %d does not parse", i))
			continue
		}
		checkpoint.Size = note.Size
		checkpoint.Root = bytes.Clone(note.Root[:])
		if note.Origin != packet.GetOrigin() {
			checkpoint.Failures = append(checkpoint.Failures, fmt.Sprintf("checkpoint %d is of another origin", i))
		}
		for _, key := range logKeys {
			_, err := note.SignedBy(key)
			if err == nil {
				checkpoint.LogKey = key.String()
				break
			}
			if !errors.Is(err, ErrRecordLogNoteUnsigned) {
				checkpoint.Failures = append(checkpoint.Failures, fmt.Sprintf("checkpoint %d carries a signature of %s that does not verify", i, key.Name))
			}
		}
		if checkpoint.LogKey == "" {
			checkpoint.Failures = append(checkpoint.Failures, fmt.Sprintf("checkpoint %d is under no log key given", i))
		}
		for _, key := range witnessKeys {
			timeSeconds, err := note.SignedBy(key)
			if err == nil {
				checkpoint.Cosigned = append(checkpoint.Cosigned, &RecordVerifyCosignature{Name: key.Name, TimeSeconds: timeSeconds})
			} else if !errors.Is(err, ErrRecordLogNoteUnsigned) {
				checkpoint.Failures = append(checkpoint.Failures, fmt.Sprintf("checkpoint %d carries a cosignature of %s that does not verify", i, key.Name))
			}
		}
		if len(checkpoint.Cosigned) < quorum {
			checkpoint.Failures = append(checkpoint.Failures, fmt.Sprintf("checkpoint %d has %d of the %d cosignatures asked for", i, len(checkpoint.Cosigned), quorum))
		}
	}

	// each entry's body as its opening's version gives it, and the approval requests the packet opens, by approval
	// id, for step 6
	bodies := make([]*recordVerifyBody, len(packet.GetEntries()))
	approvalRequests := map[Id]*StoredApprovalRequest{}
	for i, entry := range packet.GetEntries() {
		bodies[i] = recordVerifyOpeningBody(packet.GetKeys(), entry.GetOpening(), args.AgentSubkeys)
		header, _, err := recordSignedHeader(entry.GetOpening().GetHeader())
		if err != nil || header.Kind() != RecordKindApproval || bodies[i].message == nil {
			continue
		}
		if request, err := ParseStoredApprovalRequest(bodies[i].message); err == nil {
			approvalRequests[request.ApprovalId()] = request
		}
	}

	for i, entry := range packet.GetEntries() {
		opening := entry.GetOpening()
		reportEntry := &RecordVerifyEntry{LeafIndex: entry.GetLeafIndex(), ContentCount: len(entry.GetContent())}
		report.Entries = append(report.Entries, reportEntry)
		failEntry := func(format string, a ...any) {
			reportEntry.Failures = append(reportEntry.Failures, fmt.Sprintf(format, a...))
		}
		reportEntry.Opened = len(opening.GetSalt()) != 0 || len(opening.GetBody()) != 0

		// 3 header
		header, reason := recordVerifyOpeningHeader(packet.GetKeys(), opening.GetHeader())
		if header == nil {
			failEntry("entry %d: %s", i, reason)
			continue
		}
		reportEntry.EntryId = recordIdOf(header.Header.GetEntryId())
		reportEntry.Kind = header.Kind()
		reportEntry.TimeMillis = header.Header.GetTimeMillis()
		reportEntry.WriterSidecarId = recordIdOf(header.Header.GetWriterSidecarId())
		switch {
		case reason != "":
			failEntry("entry %s: %s", reportEntry.EntryId, reason)
		case !bytes.Equal(header.Header.GetLogId(), packet.GetLogId()):
			failEntry("entry %s is of another log", reportEntry.EntryId)
		default:
			reportEntry.Header = true
		}

		// 2 inclusion
		if int(entry.GetCheckpoint()) < len(notes) && notes[entry.GetCheckpoint()] != nil {
			note := notes[entry.GetCheckpoint()]
			if RecordLogVerifyInclusion(header.LeafHash(), entry.GetLeafIndex(), note.Size, entry.GetInclusionPath(), note.Root) {
				reportEntry.Inclusion = true
			} else {
				failEntry("entry %s does not reach its checkpoint's root", reportEntry.EntryId)
			}
		} else {
			failEntry("entry %s names no checkpoint the packet holds", reportEntry.EntryId)
		}

		// 4 body, and the message its version says it holds
		body := bodies[i]
		reportEntry.Version = body.version
		reportEntry.BodyGeneric = body.generic
		reportEntry.AgentProvenance = body.provenance
		if body.committed {
			reportEntry.Body = true
		} else {
			failEntry("entry %s: its body does not open its commitment", reportEntry.EntryId)
		}
		if body.failure == "" {
			reportEntry.Message = true
		} else {
			failEntry("entry %s: %s", reportEntry.EntryId, body.failure)
		}

		// 5 content
		reportEntry.Content = true
		for _, content := range entry.GetContent() {
			contentHeader, reason := recordVerifyOpeningHeader(packet.GetKeys(), content.GetHeader())
			if contentHeader == nil || reason != "" {
				reportEntry.Content = false
				failEntry("entry %s: a content opening: %s", reportEntry.EntryId, reason)
				continue
			}
			named := slices.ContainsFunc(header.Header.GetContent(), func(ref *protocol.ContentRef) bool {
				return bytes.Equal(ref.GetRepoId(), contentHeader.Header.GetLogId()) &&
					bytes.Equal(ref.GetObjectId(), contentHeader.Header.GetEntryId()) &&
					bytes.Equal(ref.GetCommitment(), contentHeader.Header.GetBodyCommitment())
			})
			if !named {
				reportEntry.Content = false
				failEntry("entry %s: a content opening that none of its ContentRefs names", reportEntry.EntryId)
				continue
			}
			contentBody := recordVerifyOpeningBody(packet.GetKeys(), content, args.AgentSubkeys)
			if !contentBody.committed {
				reportEntry.Content = false
				failEntry("entry %s: a content opening whose body does not open its commitment", reportEntry.EntryId)
			} else if contentBody.failure != "" {
				reportEntry.Content = false
				failEntry("entry %s: a content opening: %s", reportEntry.EntryId, contentBody.failure)
			}
		}

		// 6 approval
		reportEntry.Approval = true
		if (header.Kind() == RecordKindApproval || header.Kind() == RecordKindApprovalDecision) && reportEntry.Opened {
			reportEntry.Approval = false
			if body.message == nil {
				// not committed, not what its version says, or a version this build does not read: nothing of it is
				// parsed, and nothing passes on it
				failEntry("entry %s: its %s is not read, so nothing of it is checked", reportEntry.EntryId, header.Kind())
				continue
			}
		}
		if header.Kind() == RecordKindApproval && reportEntry.Opened {
			if _, err := ParseStoredApprovalRequest(body.message); err != nil {
				failEntry("entry %s: its request does not parse", reportEntry.EntryId)
				continue
			}
			reportEntry.Approval = true
		}
		if header.Kind() == RecordKindApprovalDecision && reportEntry.Opened {
			decision, err := ParseStoredApprovalDecision(body.message)
			if err != nil {
				failEntry("entry %s: its decision does not parse", reportEntry.EntryId)
				continue
			}
			key := recordDisclosedKeyFor(packet.GetKeys(), decision.Signed)
			if key == nil {
				failEntry("entry %s: the packet states no key for its decision's signer", reportEntry.EntryId)
				continue
			}
			if err := decision.Verify(bridge.SignedKeyAlg(key.GetAlg()), key.GetPublicKey()); err != nil {
				failEntry("entry %s: its decision's signature does not verify", reportEntry.EntryId)
				continue
			}
			if request, ok := approvalRequests[recordIdOf(decision.Decision.GetApprovalId())]; ok && !decision.Binds(request) {
				failEntry("entry %s: its decision does not name the approval request the packet opens", reportEntry.EntryId)
				continue
			}
			reportEntry.Approval = true
		}
	}

	report.Ok = len(report.Failures) == 0
	for _, checkpoint := range report.Checkpoints {
		report.Ok = report.Ok && len(checkpoint.Failures) == 0
	}
	for _, entry := range report.Entries {
		report.Ok = report.Ok && len(entry.Failures) == 0
	}
	return report, nil
}

// SHA-256 of a packet file: DisclosureBody.packet_sha256.
func RecordDisclosurePacketSha256(packetBytes []byte) [sha256.Size]byte {
	return sha256.Sum256(packetBytes)
}
