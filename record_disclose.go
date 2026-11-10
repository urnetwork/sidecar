// RECORD.md section 11's disclosure, on every leg: a person gives someone outside a log proof of some of its entries,
// as one file the offline verifier checks alone (record_verify_packet.go).
//
//	who         a person, by a command confirmed on /dev/tty or in an app's UI, on a device that reads the log; no
//	            MCP tool; a caller with a harness process among its ancestors is refused, a dry run included, so a
//	            prompt-injected agent's shell builds no packet
//	profiles    entries: exactly the ids named, opened
//	            approval: its approval, approval_decision and approval_use entries opened, and the header of the
//	            run's newest coverage entry
//	            decision: its approval_decision entries opened, its approval as a header alone
//	            run: its context, coverage and change entries opened, and its approvals as the approval profile
//	show        Plan lists every field the packet opens, for the confirmation and for --dry-run; an approval opens
//	            its ApprovalRequest whole, summary and the action's preview included, since the hashes cover them
//	checkpoint  every entry needs a verified checkpoint covering it: a checkpointer cuts one first, another device
//	            is told the entry is under none yet, and a log whose verifiable log is off is refused
//	content     a T entry's ContentRef opens only with the author's Opening, made by Open on the author's consented
//	            device, which files its own disclosure entry in the vault; an admin cannot make one (§8.5)
//	record      write-ahead: a device that writes or deposits to the log files a disclosure entry and holds its
//	            commit in evs before the packet is returned; a receipt-only reader deposits read receipts, purpose 4,
//	            instead; a reader that can do neither discloses nothing; an act whose record cannot land is refused
//	erased      an erased entry goes as a header alone, showing it existed and is gone
//	no keys     a packet holds salts and bodies of what it opens, never an entry key, slot row or log key
//
// A packet states each signer's key with a label, which is the team's statement and never a person's proof. A
// decision signed by a presence key is not packed yet: RecordAuthView resolves identity keys alone, so such a packet
// is refused rather than built to fail its verification.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A packet's profile (section 11's profiles row).
type RecordDisclosureProfile string

const (
	RecordDisclosureProfileEntries  RecordDisclosureProfile = "entries"
	RecordDisclosureProfileApproval RecordDisclosureProfile = "approval"
	RecordDisclosureProfileDecision RecordDisclosureProfile = "decision"
	RecordDisclosureProfileRun      RecordDisclosureProfile = "run"
)

// DisclosureBody.act.
const (
	RecordDisclosureActPacket  = 1
	RecordDisclosureActOpening = 2
	RecordDisclosureActExport  = 3
)

var (
	// The request names nothing, more than one thing, a profile its selector does not take, or text past its caps.
	ErrRecordDisclosureArgs = errors.New("record disclosure request invalid")
	// The caller has a harness process among its ancestors, or its ancestry cannot be read.
	ErrRecordDisclosureHarness = errors.New("record disclosure refused under a harness process")
	// The act is a person's: it takes a command confirmed on /dev/tty or in an app's UI.
	ErrRecordDisclosureUnconfirmed = errors.New("record disclosure takes a confirmed command")
	// An entry named, or an approval or run, is not in the log as this device reads it.
	ErrRecordDisclosureNotFound = errors.New("record disclosure names nothing this log holds")
	// The entries chosen now are not the ones the person was shown.
	ErrRecordDisclosureChanged = errors.New("record disclosure differs from what was confirmed")
	// This device can neither file a disclosure entry in the log nor deposit a receipt there.
	ErrRecordDisclosureNoRecord = errors.New("record disclosure leaves no record from this device")
	// A signer's key is not one this state resolves, so the packet would not verify.
	ErrRecordDisclosureKey = errors.New("record disclosure cannot state a signer's key")
)

// What a person asks to disclose.
type RecordDiscloseArgs struct {
	LogId Id
	// Exactly one of the three.
	EntryIds   []Id
	ApprovalId *Id
	RunId      *Id
	// Empty takes the selector's own: entries, approval or run. decision goes with ApprovalId.
	Profile   RecordDisclosureProfile
	Recipient string
	Purpose   string
	// Files `ur record open` wrote on the author's device: openings of vault entries T's entries reference.
	Content [][]byte
	// The entries the person was shown, in the plan's order: a selection that differs now is refused.
	ExpectEntryIds []Id
	// The person confirmed the command on /dev/tty or in an app's UI.
	Confirmed bool
	// The calling process has a harness process among its ancestors, or its ancestry could not be read.
	HarnessAncestor bool
}

// One entry of a plan: what the confirmation and --dry-run show for it.
type RecordDisclosureItem struct {
	EntryId    Id
	Kind       RecordKind
	TimeMillis int64
	// The packet carries its salt and body.
	Opened bool
	// Erased in the log: a header alone, whatever the profile.
	Erased bool
	// Every body field the packet opens, by name: nested ones dotted.
	Fields []string
	// The author's openings of its ContentRefs the packet carries.
	ContentCount int
}

// What a packet would open.
type RecordDisclosurePlan struct {
	LogId   Id
	Profile RecordDisclosureProfile
	Items   []*RecordDisclosureItem
}

// A packet as built, its record landed.
type RecordDisclosed struct {
	Plan *RecordDisclosurePlan
	// The file's bytes, to write as they are.
	Packet       []byte
	PacketSha256 [sha256.Size]byte
	// The record is read receipts alone: this device files no disclosure entry in the log.
	ReceiptsOnly bool
}

// What an author asks to open of its own vault (`ur record open`).
type RecordOpenArgs struct {
	EntryIds        []Id
	Recipient       string
	Purpose         string
	Confirmed       bool
	HarnessAncestor bool
}

// Builds packets from what this device reads.
type RecordDisclosure struct {
	record *SidecarRecord
}

// The record's disclosure (RECORD-M6-06).
func (self *SidecarRecord) Disclosure() *RecordDisclosure {
	return &RecordDisclosure{record: self}
}

// Holds a disclosure body to section 11's caps.
func recordDisclosureValidate(body *protocol.DisclosureBody) error {
	packetAct := body.GetAct() == RecordDisclosureActPacket || body.GetAct() == RecordDisclosureActOpening
	checks := []error{
		recordBodyRule(RecordDisclosureActPacket <= body.GetAct() && body.GetAct() <= RecordDisclosureActExport, "disclosure act %d", body.GetAct()),
		recordBodyRule(recordBodyLength(body.GetPacketSha256(), recordHashByteCount, !packetAct) && (packetAct || len(body.GetPacketSha256()) == 0), "packet_sha256 of %d bytes for act %d", len(body.GetPacketSha256()), body.GetAct()),
		recordBodyRule(len(body.GetEntryIds()) <= recordDisclosureEntryCount && (packetAct || len(body.GetEntryIds()) == 0), "%d entry ids for act %d", len(body.GetEntryIds()), body.GetAct()),
		recordBodyRule(len(body.GetRecipient()) <= recordDisclosureRecipientByteCount, "recipient of %d bytes", len(body.GetRecipient())),
		recordBodyRule(len(body.GetPurpose()) <= recordDisclosurePurposeByteCount, "purpose of %d bytes", len(body.GetPurpose())),
		recordBodyRule((body.GetAct() == RecordDisclosureActExport) == (1 <= body.GetFormat() && body.GetFormat() <= 4), "format %d for act %d", body.GetFormat(), body.GetAct()),
		recordBodyRule(recordBodyLength(body.GetRunId(), recordIdByteCount, true), "run_id of %d bytes", len(body.GetRunId())),
	}
	for _, entryId := range body.GetEntryIds() {
		checks = append(checks, recordBodyRule(len(entryId) == recordIdByteCount, "an entry id of %d bytes", len(entryId)))
	}
	return errors.Join(checks...)
}

// The names of every field message sets, nested messages' dotted under prefix: what a body opens.
func recordMessageFieldNames(message protoreflect.Message, prefix string) []string {
	names := []string{}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		name := prefix + string(field.Name())
		if field.Kind() == protoreflect.MessageKind && !field.IsList() && !field.IsMap() {
			names = append(names, recordMessageFieldNames(value.Message(), name+".")...)
			return true
		}
		if field.Kind() == protoreflect.MessageKind && field.IsList() {
			nested := map[string]bool{}
			for i := 0; i < value.List().Len(); i += 1 {
				for _, nestedName := range recordMessageFieldNames(value.List().Get(i).Message(), name+".") {
					nested[nestedName] = true
				}
			}
			for nestedName := range nested {
				names = append(names, nestedName)
			}
			return true
		}
		names = append(names, name)
		return true
	})
	slices.Sort(names)
	return names
}

// Every field an entry's stored body opens, by name. An approval names its action's fields too, and a kind whose
// stored body is a Signed names what it signs. A body this build cannot name is said to be opened whole.
func recordDisclosureFields(kind RecordKind, body []byte) []string {
	whole := []string{fmt.Sprintf("the whole body, %d bytes of a kind this build does not name", len(body))}
	if signedBody, _, ok := kind.NewSignedBody(); ok {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(body, signed); err != nil || proto.Unmarshal(signed.GetBody(), signedBody) != nil {
			return whole
		}
		return append(recordMessageFieldNames(signedBody.ProtoReflect(), ""), "signature")
	}
	message, ok := kind.NewBody()
	if !ok || proto.Unmarshal(body, message) != nil {
		return whole
	}
	names := recordMessageFieldNames(message.ProtoReflect(), "")
	if request, ok := message.(*protocol.ApprovalRequest); ok {
		action := &protocol.CanonicalAction{}
		if err := proto.Unmarshal(request.GetCanonicalAction(), action); err == nil {
			names = append(names, recordMessageFieldNames(action.ProtoReflect(), "canonical_action.")...)
		}
	}
	return names
}

// One entry a packet takes.
type recordDisclosureChoice struct {
	entry  *RecordReadEntry
	opened bool
}

// The checks before anything is read: who asks, and that the request is one request.
func (self *RecordDiscloseArgs) check() (RecordDisclosureProfile, error) {
	if self == nil {
		return "", fmt.Errorf("%w: no request", ErrRecordDisclosureArgs)
	}
	selectors := 0
	profile := self.Profile
	want := RecordDisclosureProfileEntries
	if 0 < len(self.EntryIds) {
		selectors += 1
	}
	if self.ApprovalId != nil {
		selectors += 1
		want = RecordDisclosureProfileApproval
	}
	if self.RunId != nil {
		selectors += 1
		want = RecordDisclosureProfileRun
	}
	if selectors != 1 {
		return "", fmt.Errorf("%w: exactly one of entries, an approval or a run", ErrRecordDisclosureArgs)
	}
	if profile == "" {
		profile = want
	}
	if profile != want && !(profile == RecordDisclosureProfileDecision && self.ApprovalId != nil) {
		return "", fmt.Errorf("%w: profile %s does not go with that selector", ErrRecordDisclosureArgs, profile)
	}
	if recordDisclosureRecipientByteCount < len(self.Recipient) || recordDisclosurePurposeByteCount < len(self.Purpose) {
		return "", fmt.Errorf("%w: a recipient past %d bytes or a purpose past %d", ErrRecordDisclosureArgs, recordDisclosureRecipientByteCount, recordDisclosurePurposeByteCount)
	}
	if recordDisclosureEntryCount < len(self.EntryIds) {
		return "", fmt.Errorf("%w: more than %d entries", ErrRecordDisclosureArgs, recordDisclosureEntryCount)
	}
	return profile, nil
}

// The approval id a held approval-family entry is about, false for any other entry or a body that does not parse.
func recordApprovalIdOf(entry *RecordReadEntry) (Id, bool) {
	if entry.Body == nil {
		return Id{}, false
	}
	switch entry.Kind() {
	case RecordKindApproval:
		request := &protocol.ApprovalRequest{}
		if err := proto.Unmarshal(entry.Body, request); err == nil && len(request.GetApprovalId()) == recordIdByteCount {
			return Id(request.GetApprovalId()), true
		}
	case RecordKindApprovalDecision:
		if decision, err := ParseStoredApprovalDecision(entry.Body); err == nil {
			return Id(decision.Decision.GetApprovalId()), true
		}
	case RecordKindApprovalUse:
		use := &protocol.ApprovalUseBody{}
		if err := proto.Unmarshal(entry.Body, use); err == nil && len(use.GetApprovalId()) == recordIdByteCount {
			return Id(use.GetApprovalId()), true
		}
	}
	return Id{}, false
}

// Reads the log and chooses the entries the request's profile takes, in the log's read order.
func (self *RecordDisclosure) choose(ctx context.Context, args *RecordDiscloseArgs) (RecordDisclosureProfile, []*recordDisclosureChoice, error) {
	profile, err := args.check()
	if err != nil {
		return "", nil, err
	}
	if args.HarnessAncestor {
		return "", nil, ErrRecordDisclosureHarness
	}
	record := self.record
	auth := record.writer.auth()
	if !auth.Reads(args.LogId, record.writer.sidecarId) {
		return "", nil, fmt.Errorf("%w: %s", ErrRecordNotReader, args.LogId)
	}
	if !recordLogVerifiable(auth, args.LogId) {
		return "", nil, fmt.Errorf("%w: a packet needs a checkpoint, and %s takes no verifiable log", ErrRecordLogUnsupported, args.LogId)
	}
	if err := record.reader.Sync(ctx, args.LogId); err != nil {
		return "", nil, err
	}
	entries := record.reader.Entries(args.LogId)
	choices := []*recordDisclosureChoice{}
	take := func(entry *RecordReadEntry, opened bool) {
		choices = append(choices, &recordDisclosureChoice{entry: entry, opened: opened && entry.Body != nil && entry.State != RecordEntryErased})
	}
	approvalEntries := func(approvalIds map[Id]bool, request bool, uses bool) {
		for _, entry := range entries {
			approvalId, ok := recordApprovalIdOf(entry)
			if !ok || !approvalIds[approvalId] {
				continue
			}
			switch entry.Kind() {
			case RecordKindApproval:
				take(entry, request)
			case RecordKindApprovalDecision:
				take(entry, true)
			case RecordKindApprovalUse:
				if uses {
					take(entry, true)
				}
			}
		}
	}
	switch profile {
	case RecordDisclosureProfileEntries:
		for _, entryId := range args.EntryIds {
			index := slices.IndexFunc(entries, func(entry *RecordReadEntry) bool { return entry.EntryId == entryId })
			if index < 0 {
				return "", nil, fmt.Errorf("%w: entry %s", ErrRecordDisclosureNotFound, entryId)
			}
			take(entries[index], true)
		}
	case RecordDisclosureProfileApproval, RecordDisclosureProfileDecision:
		approvalEntries(map[Id]bool{*args.ApprovalId: true}, profile == RecordDisclosureProfileApproval, profile == RecordDisclosureProfileApproval)
		if profile == RecordDisclosureProfileApproval {
			// the header of the run's newest coverage entry, which says how much of the run the record holds
			var coverage *RecordReadEntry
			for _, choice := range choices {
				runId := choice.entry.Header.Header.GetRunId()
				if choice.entry.Kind() != RecordKindApproval || len(runId) == 0 {
					continue
				}
				for _, entry := range entries {
					if entry.Kind() == RecordKindCoverage && bytes.Equal(entry.Header.Header.GetRunId(), runId) {
						coverage = entry
					}
				}
			}
			if coverage != nil {
				take(coverage, false)
			}
		}
	case RecordDisclosureProfileRun:
		approvalIds := map[Id]bool{}
		for _, entry := range entries {
			if !bytes.Equal(entry.Header.Header.GetRunId(), args.RunId[:]) {
				continue
			}
			switch entry.Kind() {
			case RecordKindContext, RecordKindCoverage, RecordKindChange:
				take(entry, true)
			case RecordKindApproval:
				if approvalId, ok := recordApprovalIdOf(entry); ok {
					approvalIds[approvalId] = true
				}
			}
		}
		approvalEntries(approvalIds, true, true)
	}
	if len(choices) == 0 {
		return "", nil, fmt.Errorf("%w: nothing matches", ErrRecordDisclosureNotFound)
	}
	if recordDisclosureEntryCount < len(choices) {
		return "", nil, fmt.Errorf("%w: %d entries, and a packet holds %d", ErrRecordDisclosureArgs, len(choices), recordDisclosureEntryCount)
	}
	return profile, choices, nil
}

// The author's openings a request carries, each verified to open its own header: by the entry id they open.
func recordDisclosureContent(files [][]byte) (map[Id]*protocol.Opening, []*protocol.DisclosedKey, error) {
	openings := map[Id]*protocol.Opening{}
	keys := []*protocol.DisclosedKey{}
	for _, file := range files {
		packet, err := ParseRecordDisclosurePacket(file)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: a content file: %v", ErrRecordDisclosureArgs, err)
		}
		for _, entry := range packet.GetEntries() {
			opened, err := VerifyRecordOpening(entry.GetOpening())
			if err != nil {
				return nil, nil, fmt.Errorf("%w: a content file's opening: %v", ErrRecordDisclosureArgs, err)
			}
			openings[recordIdOf(opened.Header.Header.GetEntryId())] = entry.GetOpening()
		}
		keys = append(keys, packet.GetKeys()...)
	}
	return openings, keys, nil
}

// The plan of what a packet opens, entry by entry.
func recordDisclosurePlanOf(logId Id, profile RecordDisclosureProfile, choices []*recordDisclosureChoice, content map[Id]*protocol.Opening) *RecordDisclosurePlan {
	plan := &RecordDisclosurePlan{LogId: logId, Profile: profile}
	for _, choice := range choices {
		item := &RecordDisclosureItem{
			EntryId: choice.entry.EntryId, Kind: choice.entry.Kind(), TimeMillis: choice.entry.Header.Header.GetTimeMillis(),
			Opened: choice.opened, Erased: choice.entry.State == RecordEntryErased,
		}
		if choice.opened {
			item.Fields = recordDisclosureFields(choice.entry.Kind(), choice.entry.Body)
		}
		for _, ref := range choice.entry.Header.Header.GetContent() {
			if _, ok := content[recordIdOf(ref.GetObjectId())]; ok {
				item.ContentCount += 1
			}
		}
		plan.Items = append(plan.Items, item)
	}
	return plan
}

// What a packet for args would open, read from the log now: for the confirmation and for --dry-run. It builds no
// packet and files nothing.
func (self *RecordDisclosure) Plan(ctx context.Context, args *RecordDiscloseArgs) (*RecordDisclosurePlan, error) {
	profile, choices, err := self.choose(ctx, args)
	if err != nil {
		return nil, err
	}
	content, _, err := recordDisclosureContent(args.Content)
	if err != nil {
		return nil, err
	}
	return recordDisclosurePlanOf(args.LogId, profile, choices, content), nil
}

// The key a packet states for a sidecar's identity key, with the team's label for it.
func recordDisclosedIdentityKey(auth RecordAuthView, sidecarId Id) (*protocol.DisclosedKey, error) {
	publicKey := auth.IdentityKey(sidecarId)
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("%w: sidecar %s", ErrRecordDisclosureKey, sidecarId)
	}
	label := "sidecar " + sidecarId.String()
	if memberId, ok := auth.Member(sidecarId); ok {
		label += " of member " + memberId.String()
	} else if sponsorId, ok := auth.Sponsor(sidecarId); ok {
		label += " sponsored by member " + sponsorId.String()
	}
	return &protocol.DisclosedKey{SidecarId: sidecarId.Bytes(), Alg: uint32(bridge.SignedKeyAlgEd25519), PublicKey: bytes.Clone(publicKey), Label: label}, nil
}

// Files section 11's record of an act in logId and waits for it to land: a disclosure entry from a device that
// writes or deposits there, read receipts from a receipt-only reader. True when receipts alone stand as the record.
func (self *RecordDisclosure) recordAct(ctx context.Context, logId Id, body *protocol.DisclosureBody, purpose RecordReadPurpose, objectIds [][]byte, confirmed bool) (bool, error) {
	record := self.record
	auth := record.writer.auth()
	sidecarId := record.writer.sidecarId
	if auth.Deposits(logId, sidecarId) && auth.ReceiptOnly(logId, sidecarId) {
		// ingest takes only read from it (section 5.4's step 5), so its receipts stand as the record
		if len(objectIds) == 0 {
			return false, fmt.Errorf("%w: a receipt names what was read", ErrRecordDisclosureNoRecord)
		}
		if err := record.receipts.Deposit(ctx, &RecordReceiptRequest{RepoId: logId, Purpose: purpose, ObjectIds: objectIds, NoSession: true}); err != nil {
			return false, err
		}
		return true, nil
	}
	source := RecordSourceObserved
	if confirmed {
		source = RecordSourceApprover
	}
	refs, err := record.writer.Append(&RecordDraft{Kind: RecordKindDisclosure, Source: source, NoSession: true, Body: body, LogId: &logId})
	if errors.Is(err, ErrRecordRouteNoLog) {
		return false, fmt.Errorf("%w: %v", ErrRecordDisclosureNoRecord, err)
	}
	if err != nil {
		return false, err
	}
	return false, record.Land(ctx, refs)
}

// Builds the packet for args and files its record first: when this returns nil the log holds the act, and the caller
// writes Packet to the person's file. A confirmed command only.
func (self *RecordDisclosure) Disclose(ctx context.Context, args *RecordDiscloseArgs) (*RecordDisclosed, error) {
	profile, choices, err := self.choose(ctx, args)
	if err != nil {
		return nil, err
	}
	if !args.Confirmed {
		return nil, ErrRecordDisclosureUnconfirmed
	}
	if args.ExpectEntryIds != nil {
		chosen := []Id{}
		for _, choice := range choices {
			chosen = append(chosen, choice.entry.EntryId)
		}
		if !slices.Equal(chosen, args.ExpectEntryIds) {
			return nil, ErrRecordDisclosureChanged
		}
	}
	content, contentKeys, err := recordDisclosureContent(args.Content)
	if err != nil {
		return nil, err
	}
	record := self.record
	auth := record.writer.auth()
	log := record.log

	// checkpoint: every entry under a verified one, a checkpointer cutting it first
	covered := func() error {
		for _, choice := range choices {
			if _, err := log.Proof(args.LogId, choice.entry.Leaf); err != nil {
				return err
			}
		}
		return nil
	}
	if err := covered(); errors.Is(err, ErrRecordLogUncovered) {
		if _, checkpointErr := log.Checkpoint(ctx, args.LogId, true); checkpointErr != nil {
			if errors.Is(checkpointErr, ErrRecordLogOff) {
				return nil, checkpointErr
			}
			return nil, fmt.Errorf("%w: its checkpointer has not covered it yet (%v)", ErrRecordLogUncovered, checkpointErr)
		}
		if err := covered(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	packet := &protocol.DisclosurePacket{
		Version: RecordDisclosurePacketVersion, LogId: args.LogId.Bytes(), Origin: RecordLogOrigin(args.LogId),
		CreatedMillis: record.writer.clock.Now().UnixMilli(), Purpose: args.Purpose,
	}
	checkpointIndexs := map[string]uint32{}
	keyed := map[Id]bool{}
	stateKey := func(sidecarId Id) error {
		if keyed[sidecarId] {
			return nil
		}
		key, err := recordDisclosedIdentityKey(auth, sidecarId)
		if err != nil {
			return err
		}
		keyed[sidecarId] = true
		packet.Keys = append(packet.Keys, key)
		return nil
	}
	body := &protocol.DisclosureBody{Act: RecordDisclosureActPacket, Recipient: args.Recipient, Purpose: args.Purpose}
	objectIds := [][]byte{}
	contentUsed := map[Id]bool{}
	for _, choice := range choices {
		entry := choice.entry
		proof, err := log.Proof(args.LogId, entry.Leaf)
		if err != nil {
			return nil, err
		}
		index, ok := checkpointIndexs[string(proof.Checkpoint)]
		if !ok {
			index = uint32(len(packet.Checkpoints))
			checkpointIndexs[string(proof.Checkpoint)] = index
			packet.Checkpoints = append(packet.Checkpoints, proof.Checkpoint)
		}
		opening := &protocol.Opening{Header: bytes.Clone(entry.SignedBytes)}
		if choice.opened {
			opening.Salt = bytes.Clone(entry.Salt)
			opening.Body = bytes.Clone(entry.Body)
			if _, err := VerifyRecordOpening(opening); err != nil {
				return nil, err
			}
		}
		disclosed := &protocol.DisclosedEntry{Opening: opening, LeafIndex: proof.LeafIndex, Checkpoint: index, InclusionPath: proof.InclusionPath}
		for _, ref := range entry.Header.Header.GetContent() {
			contentId := recordIdOf(ref.GetObjectId())
			contentOpening, ok := content[contentId]
			if !ok {
				continue
			}
			opened, err := VerifyRecordOpening(contentOpening)
			if err != nil || !bytes.Equal(opened.Header.Header.GetLogId(), ref.GetRepoId()) || !bytes.Equal(opened.Header.Header.GetBodyCommitment(), ref.GetCommitment()) {
				return nil, fmt.Errorf("%w: a content opening is not the entry %s references", ErrRecordDisclosureArgs, entry.EntryId)
			}
			disclosed.Content = append(disclosed.Content, contentOpening)
			contentUsed[contentId] = true
		}
		if err := stateKey(recordIdOf(entry.Header.Header.GetWriterSidecarId())); err != nil {
			return nil, err
		}
		if choice.opened && entry.Kind() == RecordKindApprovalDecision {
			decision, err := ParseStoredApprovalDecision(entry.Body)
			if err != nil {
				return nil, err
			}
			if len(decision.Signed.GetKeyId()) != 0 || len(decision.Signed.GetSignerId()) != recordIdByteCount {
				return nil, fmt.Errorf("%w: the decision in entry %s is signed by a key that is no sidecar's identity key", ErrRecordDisclosureKey, entry.EntryId)
			}
			if err := stateKey(Id(decision.Signed.GetSignerId())); err != nil {
				return nil, err
			}
		}
		packet.Entries = append(packet.Entries, disclosed)
		body.EntryIds = append(body.EntryIds, entry.EntryId.Bytes())
		objectIds = append(objectIds, entry.EntryId.Bytes())
	}
	for contentId := range content {
		if !contentUsed[contentId] {
			return nil, fmt.Errorf("%w: a content opening of %s, which no entry of the packet references", ErrRecordDisclosureArgs, contentId)
		}
	}
	// the keys the author's openings were stated under, for the entries taken
	for _, key := range contentKeys {
		if len(key.GetSidecarId()) == recordIdByteCount && !keyed[Id(key.GetSidecarId())] {
			keyed[Id(key.GetSidecarId())] = true
			packet.Keys = append(packet.Keys, key)
		}
	}
	packetBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(packet)
	if err != nil {
		return nil, err
	}
	packetSha256 := RecordDisclosurePacketSha256(packetBytes)
	body.PacketSha256 = packetSha256[:]

	receiptsOnly, err := self.recordAct(ctx, args.LogId, body, RecordReadPurposeDisclosure, objectIds, true)
	if err != nil {
		return nil, err
	}
	return &RecordDisclosed{
		Plan: recordDisclosurePlanOf(args.LogId, profile, choices, content), Packet: packetBytes, PacketSha256: packetSha256, ReceiptsOnly: receiptsOnly,
	}, nil
}

// The author's openings of its own vault entries, as one file for a discloser's --content: each entry's header with
// the salt and body that open it, an erased one's header alone, and the writers' keys. Only on a consented device of
// the vault, by a confirmed command with no harness ancestor, and only after the vault holds this act's own
// disclosure entry.
func (self *RecordDisclosure) Open(ctx context.Context, args *RecordOpenArgs) (*RecordDisclosed, error) {
	if args == nil || len(args.EntryIds) == 0 || recordDisclosureEntryCount < len(args.EntryIds) ||
		recordDisclosureRecipientByteCount < len(args.Recipient) || recordDisclosurePurposeByteCount < len(args.Purpose) {
		return nil, fmt.Errorf("%w: 1 to %d entries, a recipient and a purpose within their caps", ErrRecordDisclosureArgs, recordDisclosureEntryCount)
	}
	if args.HarnessAncestor {
		return nil, ErrRecordDisclosureHarness
	}
	if !args.Confirmed {
		return nil, ErrRecordDisclosureUnconfirmed
	}
	record := self.record
	auth := record.writer.auth()
	vault, err := recordVaultRoute(auth, record.writer.sidecarId)
	if err != nil || vault.deposit || !auth.Reads(vault.logId, record.writer.sidecarId) {
		return nil, fmt.Errorf("%w: only a consented device of the author's vault opens its entries", ErrRecordNotReader)
	}
	if err := record.reader.Sync(ctx, vault.logId); err != nil {
		return nil, err
	}
	packet := &protocol.DisclosurePacket{
		Version: RecordDisclosurePacketVersion, LogId: vault.logId.Bytes(), CreatedMillis: record.writer.clock.Now().UnixMilli(), Purpose: args.Purpose,
	}
	body := &protocol.DisclosureBody{Act: RecordDisclosureActOpening, Recipient: args.Recipient, Purpose: args.Purpose}
	plan := &RecordDisclosurePlan{LogId: vault.logId, Profile: RecordDisclosureProfileEntries}
	keyed := map[Id]bool{}
	for _, entryId := range args.EntryIds {
		entry, ok := record.reader.Entry(vault.logId, entryId)
		if !ok {
			return nil, fmt.Errorf("%w: entry %s", ErrRecordDisclosureNotFound, entryId)
		}
		opening := &protocol.Opening{Header: bytes.Clone(entry.SignedBytes)}
		item := &RecordDisclosureItem{EntryId: entry.EntryId, Kind: entry.Kind(), TimeMillis: entry.Header.Header.GetTimeMillis(), Erased: entry.State == RecordEntryErased}
		if entry.Body != nil && entry.State != RecordEntryErased {
			opening.Salt = bytes.Clone(entry.Salt)
			opening.Body = bytes.Clone(entry.Body)
			if _, err := VerifyRecordOpening(opening); err != nil {
				return nil, err
			}
			item.Opened = true
			item.Fields = recordDisclosureFields(entry.Kind(), entry.Body)
		}
		writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
		if !keyed[writerId] {
			key, err := recordDisclosedIdentityKey(auth, writerId)
			if err != nil {
				return nil, err
			}
			keyed[writerId] = true
			packet.Keys = append(packet.Keys, key)
		}
		packet.Entries = append(packet.Entries, &protocol.DisclosedEntry{Opening: opening})
		body.EntryIds = append(body.EntryIds, entry.EntryId.Bytes())
		plan.Items = append(plan.Items, item)
	}
	packetBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(packet)
	if err != nil {
		return nil, err
	}
	packetSha256 := RecordDisclosurePacketSha256(packetBytes)
	body.PacketSha256 = packetSha256[:]
	if _, err := self.recordAct(ctx, vault.logId, body, RecordReadPurposeDisclosure, nil, true); err != nil {
		return nil, err
	}
	return &RecordDisclosed{Plan: plan, Packet: packetBytes, PacketSha256: packetSha256}, nil
}
