// A push's statement (§11.6, §11.8): a Signed EvsPush, purpose evs-push, by the §5 identity key, at most 1 KiB as
// signed, so log pages hold statements and the head's window names each one's hash. Its changes ride inline while the
// signed statement stays within 1 KiB; past that it states changes_root, change_count and changed_prefixes (token
// paths of at most 512 B in all, covering every change) and the change list moves to the payload, sorted strictly by
// token path, each part of a push in parts a contiguous run and the root over the parts' roots (D-EVS-20). A statement
// over 1 KiB is refused, never trimmed.
//
// Everything that hashes a statement or checks its signature reads its bytes as received, never a re-marshal (§22.6):
// EvsStatement keeps them, and C_v, the window's prefix and statement_sha256 come from them.
//
// EvsStatementBuilder is the client's half: from what a push carries it builds the statement and its payload, or its
// parts when the push passes 1 MiB or 1,024 entry writes, and signs through the caller's identity key. The sections no
// change carries spill into the parts' room beside the changes, and what still does not fit goes in changeless parts
// after them (DESIGN-DETAILS 8.2.2's parts row), which carry no changes_root and are no leaf of the statement's root;
// a push with no change past 1 MiB is every part changeless, under the root of zero parts with changes, a count of 0
// and no prefix (QD-658). ParseEvsStatement is evs's and readers' half, holding a statement to format 1's shape before any check that needs the
// head.
//
// Format 2 (EVS-FORMAT.md's format 2 chapter) parses through ParseEvsStatementFormat2 and builds through BuildFormat2,
// which take flags 256 DROP and 512 CUT and fields 33 and 34: a DROP sets flag 256 alone, drop_sha256 over its body
// and index_epoch 0, and its body and lists ride as payload sections 9 and 10 (evs_drop_payload.go).
//
// On every leg. Package-level functions are safe for concurrent use, and so is an EvsStatementBuilder whose sign
// function is.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose an EvsPush is signed under (§6.11).
const evsPushPurpose = "evs-push"

// What a one-part push's payload passing 1 MiB tells the builder: build parts instead.
var errEvsPayloadTooLarge = errors.New("evs payload past 1 MiB")

// The flag bits format 1 writes, and format 2's, which it refuses as needing that format.
const (
	evsFormat1PushFlags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE) | uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) |
		uint32(protocol.EvsPushFlag_EVS_PUSH_BASE) | uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE) |
		uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME) | uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) |
		uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) | uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
	evsFormat2PushFlags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) | uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
)

// A Signed EvsPush as received, held to format 1's shape: its bytes and their hash, the Signed wrapper, the push, its
// inline changes checked in order, and its covering prefixes.
type EvsStatement struct {
	Bytes           []byte
	Sha256          [sha256.Size]byte
	Signed          *bridge.Signed
	Push            *protocol.EvsPush
	Changes         []*EvsCheckedChange
	ChangedPrefixes []EvsTokenPath
}

// A field that must be 16 bytes.
func checkEvsId(name string, value []byte) error {
	if len(value) != 16 {
		return fmt.Errorf("%w: %s of %d bytes", ErrEvsPushInvalid, name, len(value))
	}
	return nil
}

// A hash field: 32 bytes, or none when allowed.
func checkEvsHash(name string, value []byte, optional bool) error {
	if (optional && len(value) == 0) || len(value) == sha256.Size {
		return nil
	}
	return fmt.Errorf("%w: %s of %d bytes", ErrEvsPushInvalid, name, len(value))
}

// A statement's bytes as received, held to format 1's shape: at most 1 KiB; a Signed EvsPush by an identity key,
// signer_id its signer_sidecar_id; its ids, chains and pins of their widths; a ref kind and mode format 1 has; only
// format 1's flags, format 2's and its fields being ErrEvsFormatUnsupported; each hash present only where its flag or
// list is; changes inline and strictly sorted, or under changes_root with a count and covering prefixes of at most
// 512 B; a part count of 0 or 2 to 1,024 with parts_sha256 beside it. The signature is Verify's.
func ParseEvsStatement(statementBytes []byte) (*EvsStatement, error) {
	return parseEvsStatement(statementBytes, false)
}

// A statement's bytes held to format 2's shape: format 1's, with flag 256 DROP, alone, and drop_sha256 present
// exactly when it is, and flag 512 CUT and index_epoch taken. A DROP's index_epoch is 0. What a CUT and an index
// push's index_epoch must equal is 5d's, which needs the head.
func ParseEvsStatementFormat2(statementBytes []byte) (*EvsStatement, error) {
	return parseEvsStatement(statementBytes, true)
}

// A statement's bytes held to its format's shape.
func parseEvsStatement(statementBytes []byte, format2 bool) (*EvsStatement, error) {
	if DefaultEvsFormatSettings().StatementMaxByteCount < len(statementBytes) {
		return nil, fmt.Errorf("%w: a statement of %d bytes, past 1 KiB", ErrEvsPushInvalid, len(statementBytes))
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(statementBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: a statement that does not parse", ErrEvsPushInvalid)
	}
	if signed.GetType() != uint32(bridge.SignedType_SIGNED_EVS_PUSH) || len(signed.GetSignature()) == 0 ||
		len(signed.GetKeyId()) != 0 || signed.GetWebauthn() != nil {
		return nil, fmt.Errorf("%w: not an identity key's EvsPush", ErrEvsPushInvalid)
	}
	push := &protocol.EvsPush{}
	if err := proto.Unmarshal(signed.GetBody(), push); err != nil {
		return nil, fmt.Errorf("%w: a push that does not parse", ErrEvsPushInvalid)
	}
	statement := &EvsStatement{Bytes: statementBytes, Sha256: sha256.Sum256(statementBytes), Signed: signed, Push: push}
	if err := statement.checkShape(format2); err != nil {
		return nil, err
	}
	return statement, nil
}

// The push's shape: format 1's, or with format2 format 2's.
func (self *EvsStatement) checkShape(format2 bool) error {
	push := self.Push
	for name, value := range map[string][]byte{
		"repo_id": push.GetRepoId(), "ref_id": push.GetRefId(), "push_id": push.GetPushId(),
		"signer_sidecar_id": push.GetSignerSidecarId(), "client_id": push.GetClientId(), "group_id": push.GetGroupId(),
	} {
		if err := checkEvsId(name, value); err != nil {
			return err
		}
	}
	if len(push.GetOwnerSidecarId()) != 0 {
		if err := checkEvsId("owner_sidecar_id", push.GetOwnerSidecarId()); err != nil {
			return err
		}
	}
	if !bytes.Equal(self.Signed.GetSignerId(), push.GetSignerSidecarId()) {
		return fmt.Errorf("%w: signed by another than its signer_sidecar_id", ErrEvsPushInvalid)
	}
	for name, value := range map[string][]byte{
		"base_chain": push.GetBaseChain(), "generation_commitment": push.GetGenerationCommitment(),
		"auth chain": push.GetAuth().GetChain(),
	} {
		if err := checkEvsHash(name, value, false); err != nil {
			return err
		}
	}
	if push.GetAuth().GetVersion() == 0 || push.GetGeneration() == 0 || push.GetPathEpoch() == 0 || push.GetTimeMs() <= 0 {
		return fmt.Errorf("%w: a pin, generation, path epoch or time missing", ErrEvsPushInvalid)
	}
	if push.GetRefKind() == 0 || uint32(protocol.EvsRefKind_EVS_REF_ERASURE) < push.GetRefKind() ||
		push.GetRefMode() == 0 || uint32(protocol.EvsRefMode_EVS_REF_FILE) < push.GetRefMode() {
		return fmt.Errorf("%w: ref kind %d or mode %d", ErrEvsPushInvalid, push.GetRefKind(), push.GetRefMode())
	}
	flags := push.GetFlags()
	knownFlags := evsFormat1PushFlags
	if !format2 && (flags&evsFormat2PushFlags != 0 || len(push.GetDropSha256()) != 0 || push.GetIndexEpoch() != 0) {
		return fmt.Errorf("%w: DROP, CUT or their fields", ErrEvsFormatUnsupported)
	}
	if format2 {
		knownFlags |= evsFormat2PushFlags
		drop := flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) != 0
		if err := checkEvsHash("drop_sha256", push.GetDropSha256(), true); err != nil {
			return err
		}
		if drop != (len(push.GetDropSha256()) != 0) {
			return fmt.Errorf("%w: drop_sha256 without flag 256, or flag 256 without it", ErrEvsPushInvalid)
		}
		if drop && (flags != uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) || push.GetIndexEpoch() != 0) {
			return fmt.Errorf("%w: a DROP with other flags or an index_epoch", ErrEvsPushInvalid)
		}
	}
	if flags&^knownFlags != 0 {
		return fmt.Errorf("%w: flags %#x", ErrEvsPushInvalid, flags)
	}
	hasFlag := func(flag protocol.EvsPushFlag) bool {
		return flags&uint32(flag) != 0
	}
	for name, value := range map[string][]byte{
		"sealed_metadata_sha256": push.GetSealedMetadataSha256(), "new_objects_sha256": push.GetNewObjectsSha256(),
		"erased_sha256": push.GetErasedSha256(), "path_tail_sha256": push.GetPathTailSha256(),
		"source_paths_sha256": push.GetSourcePathsSha256(), "changes_root": push.GetChangesRoot(),
		"parts_sha256": push.GetPartsSha256(), "path_map_sha256": push.GetPathMapSha256(),
		"map_source_chain": push.GetMapSourceChain(),
	} {
		if err := checkEvsHash(name, value, true); err != nil {
			return err
		}
	}
	pathEpoch := hasFlag(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)
	if pathEpoch != (len(push.GetPathMapSha256()) != 0) || pathEpoch != (len(push.GetMapSourceChain()) != 0) ||
		(!pathEpoch && (push.GetMapSourceVersion() != 0 || len(push.GetPathTailSha256()) != 0)) {
		return fmt.Errorf("%w: a path map's fields without PATH_EPOCH, or PATH_EPOCH without them", ErrEvsPushInvalid)
	}
	if len(push.GetErasedSha256()) != 0 && !hasFlag(protocol.EvsPushFlag_EVS_PUSH_ERASE) && !hasFlag(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) {
		return fmt.Errorf("%w: an erased list without ERASE or CLOSURE", ErrEvsPushInvalid)
	}
	if push.GetConsumedThrough() != 0 && !hasFlag(protocol.EvsPushFlag_EVS_PUSH_CONSUME) {
		return fmt.Errorf("%w: consumed_through without CONSUME", ErrEvsPushInvalid)
	}
	partCount := push.GetPartCount()
	if partCount != 0 && (partCount < evsMinPartCount || EvsMaxPartCount < partCount) {
		return fmt.Errorf("%w: a part count of %d", ErrEvsPushInvalid, partCount)
	}
	if (partCount != 0) != (len(push.GetPartsSha256()) != 0) || (partCount != 0 && len(push.GetChangesRoot()) == 0) {
		return fmt.Errorf("%w: parts without parts_sha256 or changes_root", ErrEvsPushInvalid)
	}
	prefixByteCount := 0
	for _, prefix := range push.GetChangedPrefixes() {
		tokenPath, err := ParseEvsTokenPath(prefix.GetToken())
		if err != nil {
			return err
		}
		prefixByteCount += len(tokenPath) * EvsTokenByteCount
		self.ChangedPrefixes = append(self.ChangedPrefixes, tokenPath)
	}
	if DefaultEvsFormatSettings().ChangedPrefixesMaxByteCount < prefixByteCount {
		return fmt.Errorf("%w: changed_prefixes of %d bytes", ErrEvsPushInvalid, prefixByteCount)
	}
	if len(push.GetChangesRoot()) != 0 {
		emptyRoot := sha256.Sum256(nil)
		switch {
		case len(push.GetChanges()) != 0:
			return fmt.Errorf("%w: changes_root beside inline changes", ErrEvsPushInvalid)
		case push.GetChangeCount() == 0 && len(push.GetChangedPrefixes()) == 0 && partCount != 0 &&
			bytes.Equal(push.GetChangesRoot(), emptyRoot[:]):
			// a push in parts with no change, every part changeless: the root of zero parts with changes and no
			// prefix (QD-658)
		case push.GetChangeCount() == 0 || len(push.GetChangedPrefixes()) == 0:
			return fmt.Errorf("%w: changes_root without a count or prefixes", ErrEvsPushInvalid)
		}
		return nil
	}
	if push.GetChangeCount() != 0 || len(push.GetChangedPrefixes()) != 0 {
		return fmt.Errorf("%w: a count or prefixes beside inline changes", ErrEvsPushInvalid)
	}
	var previous EvsTokenPath
	for _, change := range push.GetChanges() {
		tokenPath, err := checkEvsChange(change)
		if err != nil {
			return err
		}
		if previous != nil && 0 <= previous.Compare(tokenPath) {
			return fmt.Errorf("%w: inline changes not in strictly ascending token path order", ErrEvsPushInvalid)
		}
		previous = tokenPath
		self.Changes = append(self.Changes, &EvsCheckedChange{Change: change, TokenPath: tokenPath})
	}
	return nil
}

// Checks the signature over the statement's received bytes by identityPublicKey, the Ed25519 key §5's binding gives
// its signer (§11.8's 5b).
func (self *EvsStatement) Verify(identityPublicKey []byte) error {
	return bridge.VerifySigned(self.Signed, evsPushPurpose, bridge.SignedType_SIGNED_EVS_PUSH, bridge.SignedKeyAlgEd25519, identityPublicKey)
}

// Signs as this sidecar's identity key, in Sidecar.Sign's shape, as GkmSignFunction does.
type EvsSignFunction func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)

// One change a push carries: its path, the version it is based on (0 creates), its new entry version's bytes (nil
// removes the path), and the EvsSourcePath encodings 11.6's read rule names for it while sources stand.
type EvsPlannedChange struct {
	TokenPath        EvsTokenPath
	BaseEntryVersion uint64
	EntryVersion     []byte
	SourcePaths      [][]byte
}

// What a push states and carries before it is built and signed. Every field the statement names comes from here;
// the builder computes the changes' hashes and order, the change list's place, the parts, and every section hash.
type EvsPushPlan struct {
	RepoId               Id
	RefId                Id
	RefKind              protocol.EvsRefKind
	RefMode              protocol.EvsRefMode
	OwnerSidecarId       *Id
	PushId               Id
	BaseVersion          uint64
	BaseChain            [sha256.Size]byte
	Generation           uint64
	GroupId              Id
	GenerationCommitment []byte
	PathEpoch            uint64
	Auth                 *bridge.AuthPin
	SignerSidecarId      Id
	ClientId             Id
	TimeMs               int64
	Flags                uint32
	PathMapSha256        []byte
	MapSourceVersion     uint64
	MapSourceChain       []byte
	ConsumedThrough      uint64
	Changes              []*EvsPlannedChange
	// whether the head lists sources, so the payload carries a source-paths item per change
	SourcesStand   bool
	SealedMetadata []byte
	NewObjects     []*EvsNewObject
	// one per new slot, in its new-objects item's order: its EvsSlotObject bytes
	SlotBodies [][]byte
	Erased     []*EvsErasedKey
	// a PATH_EPOCH push's tail: each EvsPathMove's bytes
	TailMoves [][]byte
	ReuseList []*EvsReuse
	// a creating push's payload sections 15 and 16 (DESIGN-DETAILS 8.2.2): its sealed ref name (EvsSealRefName) and an
	// overlay's base, which the sealed metadata repeats under the signature
	RefName []byte
	Base    *protocol.EvsOverlay
	// format 2, a DROP's: its EvsDropHistory bytes, section 9, which drop_sha256 is set over, and its lists, section 10
	// (EvsBuildDropLists)
	DropBody  []byte
	DropLists []byte
}

// A push built and signed: its statement as signed, and its payload for one part or its parts for several, with the
// trees its change list makes, nil while the list is inline.
type EvsBuiltPush struct {
	Statement  *EvsStatement
	Payload    []byte
	Parts      [][]byte
	ChangeTree *EvsChangeTree
}

// Builds pushes' statements and payloads and signs them through sign, within format's bounds.
type EvsStatementBuilder struct {
	sign   EvsSignFunction
	format *EvsFormatSettings
}

// A builder signing through sign, which signs as the sidecar's identity key, within the protocol's bounds.
func NewEvsStatementBuilder(sign EvsSignFunction) *EvsStatementBuilder {
	return &EvsStatementBuilder{sign: sign, format: DefaultEvsFormatSettings()}
}

// A planned change as the push carries it: its message and its leaf bytes.
type evsBuildChange struct {
	planned *EvsPlannedChange
	message *protocol.EvsChange
	leaf    []byte
	// its source paths as one item
	sourceItem []byte
}

// The statement's fields that do not depend on where the change list goes.
func (self *EvsPushPlan) basePush() *protocol.EvsPush {
	push := &protocol.EvsPush{
		RepoId: self.RepoId.Bytes(), RefId: self.RefId.Bytes(), RefKind: uint32(self.RefKind),
		PushId: self.PushId.Bytes(), BaseVersion: self.BaseVersion, BaseChain: bytes.Clone(self.BaseChain[:]),
		Generation: self.Generation, PathEpoch: self.PathEpoch, Auth: self.Auth,
		SignerSidecarId: self.SignerSidecarId.Bytes(), ClientId: self.ClientId.Bytes(), TimeMs: self.TimeMs,
		Flags: self.Flags, PathMapSha256: self.PathMapSha256, RefMode: uint32(self.RefMode),
		GroupId: self.GroupId.Bytes(), GenerationCommitment: self.GenerationCommitment,
		MapSourceVersion: self.MapSourceVersion, MapSourceChain: self.MapSourceChain,
		ConsumedThrough: self.ConsumedThrough,
	}
	if self.OwnerSidecarId != nil {
		push.OwnerSidecarId = self.OwnerSidecarId.Bytes()
	}
	return push
}

// The size the statement will have once signed by an identity key: its body, a 16-byte signer and a 64-byte
// signature.
func evsSignedStatementSize(push *protocol.EvsPush) int {
	return proto.Size(&bridge.Signed{
		Body: make([]byte, proto.Size(push)), SignerId: make([]byte, 16), Signature: make([]byte, 64),
		Type: uint32(bridge.SignedType_SIGNED_EVS_PUSH),
	})
}

// Covering prefixes of paths cut to depth components, with any a shorter one holds dropped, and their token bytes.
func evsCoveringPrefixes(paths []EvsTokenPath, depth int) ([]EvsTokenPath, int) {
	cut := make([]EvsTokenPath, 0, len(paths))
	for _, tokenPath := range paths {
		cut = append(cut, tokenPath[:min(depth, len(tokenPath))])
	}
	slices.SortFunc(cut, EvsTokenPath.Compare)
	cover := []EvsTokenPath{}
	byteCount := 0
	for _, prefix := range cut {
		if 0 < len(cover) && prefix.HasPrefix(cover[len(cover)-1]) {
			continue
		}
		cover = append(cover, prefix)
		byteCount += len(prefix) * EvsTokenByteCount
	}
	return cover, byteCount
}

// Puts the change list under changes_root with count, choosing the deepest covering prefixes within 512 B that keep
// the signed statement within 1 KiB.
func evsStateChangeRoot(push *protocol.EvsPush, root [sha256.Size]byte, changeCount int, paths []EvsTokenPath) error {
	push.Changes = nil
	push.ChangesRoot = bytes.Clone(root[:])
	push.ChangeCount = uint32(changeCount)
	for depth := EvsTokenPathMaxLength; 0 <= depth; depth -= 1 {
		cover, byteCount := evsCoveringPrefixes(paths, depth)
		if DefaultEvsFormatSettings().ChangedPrefixesMaxByteCount < byteCount {
			continue
		}
		push.ChangedPrefixes = make([]*protocol.EvsTokenPath, len(cover))
		for i, prefix := range cover {
			push.ChangedPrefixes[i] = prefix.Proto()
		}
		if evsSignedStatementSize(push) <= DefaultEvsFormatSettings().StatementMaxByteCount {
			return nil
		}
	}
	return fmt.Errorf("%w: no statement within 1 KiB", ErrEvsPushInvalid)
}

// Builds the push plan describes and signs its statement: its changes inline if the signed statement stays within
// 1 KiB, else under changes_root; one payload while it stays within 1 MiB and 1,024 entry writes, else parts.
func (self *EvsStatementBuilder) Build(plan *EvsPushPlan) (*EvsBuiltPush, error) {
	if plan.Flags&evsFormat2PushFlags != 0 || len(plan.DropBody) != 0 || len(plan.DropLists) != 0 {
		return nil, fmt.Errorf("%w: DROP or CUT", ErrEvsFormatUnsupported)
	}
	return self.build(plan, false)
}

// Builds a format-2 push as Build builds a format-1 one, a DROP's body and lists among its sections, drop_sha256 set
// over its body, and its statement parsed back as format 2. Its staged bytes are the caller's (EvsEncodeStaged), which
// a part's bound must count beside the part (plan-EVS2-small-readings#13). A DROP in parts is laid out as DESIGN-DETAILS
// 10.2.5 has it (buildParts); a DROP whose body or lists pass one DROP push's bounds is ErrEvsDropTooLarge before
// anything is signed, which the client's drop engine cuts at lineage boundaries.
func (self *EvsStatementBuilder) BuildFormat2(plan *EvsPushPlan) (*EvsBuiltPush, error) {
	if len(plan.DropBody) != 0 {
		if self.format.DropMaxBodyByteCount < len(plan.DropBody) {
			return nil, fmt.Errorf("%w: a body of %d bytes", ErrEvsDropTooLarge, len(plan.DropBody))
		}
		if self.format.DropMaxListedCount*sha256.Size < len(plan.DropLists) {
			return nil, fmt.Errorf("%w: lists of %d bytes", ErrEvsDropTooLarge, len(plan.DropLists))
		}
	}
	return self.build(plan, true)
}

// Builds a push of either format.
func (self *EvsStatementBuilder) build(plan *EvsPushPlan, format2 bool) (*EvsBuiltPush, error) {
	changes := make([]*evsBuildChange, 0, len(plan.Changes))
	entryWriteCount := 0
	for _, planned := range plan.Changes {
		// the empty path is the root, which the payload's checks hold to a directory's delta
		if EvsTokenPathMaxLength < len(planned.TokenPath) {
			return nil, fmt.Errorf("%w: a change of %d components", ErrEvsTokenInvalid, len(planned.TokenPath))
		}
		if planned.EntryVersion == nil && planned.BaseEntryVersion == 0 {
			return nil, fmt.Errorf("%w: a removal of a path it names absent", ErrEvsPushInvalid)
		}
		message := &protocol.EvsChange{TokenPath: planned.TokenPath.Components(), BaseEntryVersion: planned.BaseEntryVersion}
		if planned.EntryVersion != nil {
			digest := sha256.Sum256(planned.EntryVersion)
			message.EntrySha256 = digest[:]
			entryWriteCount += 1
		}
		leaf, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("evs: change: %w", err)
		}
		changes = append(changes, &evsBuildChange{planned: planned, message: message, leaf: leaf, sourceItem: evsJoinItems(planned.SourcePaths)})
	}
	slices.SortFunc(changes, func(a *evsBuildChange, b *evsBuildChange) int {
		return a.planned.TokenPath.Compare(b.planned.TokenPath)
	})
	for i := 1; i < len(changes); i++ {
		if changes[i-1].planned.TokenPath.Equal(changes[i].planned.TokenPath) {
			return nil, fmt.Errorf("%w: a path changed twice", ErrEvsPushInvalid)
		}
	}

	// the sections no change carries, as a one-part payload holds them
	common := &EvsPayload{}
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA, plan.SealedMetadata)
	newObjectItems := [][]byte{}
	for _, object := range plan.NewObjects {
		newObjectItems = append(newObjectItems, object.encode())
	}
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_NEW_OBJECTS, evsJoinItems(newObjectItems))
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES, evsJoinItems(plan.SlotBodies))
	erasedItems := [][]byte{}
	for _, erased := range plan.Erased {
		erasedItems = append(erasedItems, binary.BigEndian.AppendUint16(erased.SlotId.Bytes(), erased.KeyIndex))
	}
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_ERASED_LIST, evsJoinItems(erasedItems))
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY, plan.DropBody)
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS, plan.DropLists)
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_TAIL_MOVES, evsJoinItems(plan.TailMoves))
	reuseItems := [][]byte{}
	for _, reuse := range plan.ReuseList {
		reuseItems = append(reuseItems, reuse.encode())
	}
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_REUSE_LIST, evsJoinItems(reuseItems))
	common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_REF_NAME, plan.RefName)
	if plan.Base != nil {
		baseBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(plan.Base)
		if err != nil {
			return nil, fmt.Errorf("evs: overlay base: %w", err)
		}
		common.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_OVERLAY_BASE, baseBytes)
	}

	push := plan.basePush()
	statePayloadHashes := func(sources []byte) {
		hashOf := func(sectionBytes []byte) []byte {
			if len(sectionBytes) == 0 {
				return nil
			}
			digest := sha256.Sum256(sectionBytes)
			return digest[:]
		}
		push.SealedMetadataSha256 = hashOf(common.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA))
		push.NewObjectsSha256 = hashOf(common.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_NEW_OBJECTS))
		push.ErasedSha256 = hashOf(common.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_ERASED_LIST))
		push.PathTailSha256 = hashOf(common.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_TAIL_MOVES))
		push.SourcePathsSha256 = hashOf(sources)
		push.DropSha256 = hashOf(common.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY))
	}
	sourcesSection := []byte{}
	if plan.SourcesStand {
		sourceItems := make([][]byte, len(changes))
		for i, change := range changes {
			sourceItems[i] = change.sourceItem
		}
		sourcesSection = evsJoinItems(sourceItems)
	}
	statePayloadHashes(sourcesSection)

	if entryWriteCount <= self.format.PartMaxEntryWriteCount {
		built, err := self.buildOnePart(push, changes, common, sourcesSection, format2)
		if err == nil || !errors.Is(err, errEvsPayloadTooLarge) {
			return built, err
		}
	}
	return self.buildParts(push, changes, common, sourcesSection, format2)
}

// A one-part push: its payload with the change list and proofs, refused as errEvsPayloadTooLarge past 1 MiB, so the
// caller goes to parts; then inline instead if the signed statement stays within 1 KiB.
func (self *EvsStatementBuilder) buildOnePart(push *protocol.EvsPush, changes []*evsBuildChange, common *EvsPayload, sourcesSection []byte, format2 bool) (*EvsBuiltPush, error) {
	payload := &EvsPayload{sections: common.sections}
	entryVersions := [][]byte{}
	leaves := make([][]byte, len(changes))
	paths := make([]EvsTokenPath, len(changes))
	for i, change := range changes {
		leaves[i] = change.leaf
		paths[i] = change.planned.TokenPath
		if change.planned.EntryVersion != nil {
			entryVersions = append(entryVersions, change.planned.EntryVersion)
		}
	}
	payload.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_ENTRY_VERSIONS, evsJoinItems(entryVersions))
	payload.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_SOURCE_PATHS, sourcesSection)
	tree, err := NewEvsChangeTree(leaves)
	if err != nil {
		return nil, err
	}
	proofs, err := evsEntryProofs(tree, 0, changes)
	if err != nil {
		return nil, err
	}
	listed := &EvsPayload{sections: payload.sections}
	listed.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST, evsJoinItems(leaves))
	listed.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_MERKLE_PROOFS, evsJoinItems(proofs))
	listedBytes := listed.Encode()
	if self.format.PayloadMaxByteCount < len(listedBytes) {
		return nil, errEvsPayloadTooLarge
	}

	push.Changes = make([]*protocol.EvsChange, len(changes))
	for i, change := range changes {
		push.Changes[i] = change.message
	}
	built := &EvsBuiltPush{Payload: payload.Encode()}
	if self.format.StatementMaxByteCount < evsSignedStatementSize(push) {
		if err := evsStateChangeRoot(push, tree.Root(), len(changes), paths); err != nil {
			return nil, err
		}
		built.Payload = listedBytes
		built.ChangeTree = tree
	}
	statement, err := self.signStatementOf(push, format2)
	if err != nil {
		return nil, err
	}
	built.Statement = statement
	return built, nil
}

// Each entry-writing change's Merkle proof to its tree's root, in change order, as section 14 holds them: changes are
// the part's, part its index in tree.
func evsEntryProofs(tree *EvsChangeTree, part int, changes []*evsBuildChange) ([][]byte, error) {
	proofs := [][]byte{}
	for index, change := range changes {
		if change.planned.EntryVersion == nil {
			continue
		}
		proof, err := tree.InclusionProof(part, index)
		if err != nil {
			return nil, err
		}
		proofBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(proof[0])
		if err != nil {
			return nil, fmt.Errorf("evs: proof: %w", err)
		}
		proofs = append(proofs, proofBytes)
	}
	return proofs, nil
}

// A bound on what one change adds to a part: its leaf twice, as a change and in its proof, its entry version, its
// source paths, and a path of pathLength hashes, with framing.
func evsChangePartByteCount(change *evsBuildChange, pathLength int) int {
	return 2*len(change.leaf) + len(change.planned.EntryVersion) + len(change.sourceItem) + pathLength*(sha256.Size+2) + 32
}

// What one part of a push in parts carries before it is encoded.
type evsBuildPart struct {
	changes   []*evsBuildChange
	byteCount int
	metadata  []byte
	sections  *EvsPayload
}

// The sections no change carries, in the order they spill into the parts' room.
var evsSpilledSections = []protocol.EvsPayloadSection{
	protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA, protocol.EvsPayloadSection_EVS_PAYLOAD_NEW_OBJECTS,
	protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES, protocol.EvsPayloadSection_EVS_PAYLOAD_ERASED_LIST,
	protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY, protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS,
	protocol.EvsPayloadSection_EVS_PAYLOAD_TAIL_MOVES, protocol.EvsPayloadSection_EVS_PAYLOAD_REUSE_LIST,
	protocol.EvsPayloadSection_EVS_PAYLOAD_REF_NAME, protocol.EvsPayloadSection_EVS_PAYLOAD_OVERLAY_BASE,
}

// A push in parts: changes split into contiguous runs within 1,024 entry writes and 1 MiB, each with its entry
// versions, source paths and proofs to its own root; then the sealed metadata and the other sections spread over the
// parts' room in order, each slice anywhere, and what is left over in changeless parts after them (DESIGN-DETAILS
// 8.2.2's parts row). A push with no change past 1 MiB, a tag over a long unheld history or an update whose tip tree
// stands, is every part changeless, its statement the root of zero parts with changes, a count of 0 and no prefix
// (QD-658).
//
// A DROP lays out as DESIGN-DETAILS 10.2.5 has it: part 1 takes section 9, its body, whole, its run of changes cut to
// leave it room (a first part with no change when the DROP has none); section 10's values fill each part's room
// left in part order from part 1 on, a value never split; then parts with no change take at most
// DropListPartValueCount values each until the lists end.
func (self *EvsStatementBuilder) buildParts(push *protocol.EvsPush, changes []*evsBuildChange, common *EvsPayload, sourcesSection []byte, format2 bool) (*EvsBuiltPush, error) {
	format := self.format
	dropBody := common.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY)
	// the room part 1 keeps for the body, whole (10.2.5's step 2)
	dropReserve := 0
	if len(dropBody) != 0 {
		dropReserve = len(dropBody) + evsPayloadSectionHeaderByteCount
	}
	partRoom := func(index int) int {
		room := format.PartMaxByteCount - format.PartFieldsByteCount
		if index == 0 {
			room -= dropReserve
		}
		return room
	}
	pathLength := bits.Len(uint(len(changes)))
	parts := []*evsBuildPart{}
	if 0 < len(changes) {
		parts = append(parts, &evsBuildPart{sections: &EvsPayload{}})
	}
	entryWrites := 0
	for _, change := range changes {
		changeByteCount := evsChangePartByteCount(change, pathLength)
		current := parts[len(parts)-1]
		writes := 0
		if change.planned.EntryVersion != nil {
			writes = 1
		}
		if 0 < len(current.changes) && (format.PartMaxEntryWriteCount < entryWrites+writes || partRoom(len(parts)-1) < current.byteCount+changeByteCount) {
			current = &evsBuildPart{sections: &EvsPayload{}}
			parts = append(parts, current)
			entryWrites = 0
		}
		current.changes = append(current.changes, change)
		current.byteCount += changeByteCount
		entryWrites += writes
	}
	if EvsMaxPartCount < len(parts) {
		return nil, fmt.Errorf("%w: %d parts", ErrEvsPushInvalid, len(parts))
	}
	changefulCount := len(parts)
	partLeaves := make([][][]byte, changefulCount)
	for i, part := range parts {
		for _, change := range part.changes {
			partLeaves[i] = append(partLeaves[i], change.leaf)
		}
	}
	tree, err := NewEvsPartedChangeTree(partLeaves)
	if err != nil {
		return nil, err
	}

	// spill the sections no change carries into the parts' room, in section order, then into changeless parts
	type evsSpilledSection struct {
		sectionType protocol.EvsPayloadSection
		remaining   []byte
	}
	spill := []*evsSpilledSection{}
	for _, sectionType := range evsSpilledSections {
		if sectionType == protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY {
			// part 1's, whole, below
			continue
		}
		if sectionBytes := common.Section(sectionType); len(sectionBytes) != 0 {
			spill = append(spill, &evsSpilledSection{sectionType: sectionType, remaining: sectionBytes})
		}
	}
	setSlice := func(part *evsBuildPart, sectionType protocol.EvsPayloadSection, slice []byte) {
		if sectionType == protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA {
			part.metadata = slice
		} else {
			part.sections.SetSection(sectionType, slice)
		}
	}
	fill := func(part *evsBuildPart, room int) {
		for _, pending := range spill {
			if room <= evsPayloadSectionHeaderByteCount || len(pending.remaining) == 0 {
				continue
			}
			take := min(len(pending.remaining), room-evsPayloadSectionHeaderByteCount)
			if pending.sectionType == protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS {
				// whole values, and at most DropListPartValueCount in a part with no change (10.2.5's step 3)
				if len(part.changes) == 0 {
					take = min(take, format.DropListPartValueCount*sha256.Size)
				}
				take -= take % sha256.Size
				if take == 0 {
					continue
				}
			}
			setSlice(part, pending.sectionType, pending.remaining[:take])
			pending.remaining = pending.remaining[take:]
			room -= take + evsPayloadSectionHeaderByteCount
		}
	}
	left := func() bool {
		return slices.ContainsFunc(spill, func(pending *evsSpilledSection) bool { return 0 < len(pending.remaining) })
	}
	if len(dropBody) != 0 {
		// section 9 rides whole in part 1, which a DROP with no change makes changeless (10.2.5's steps 2 and 4)
		if len(parts) == 0 {
			parts = append(parts, &evsBuildPart{sections: &EvsPayload{}})
		}
		parts[0].sections.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY, dropBody)
	}
	for i, part := range parts {
		fill(part, partRoom(i)-part.byteCount)
	}
	for left() {
		if EvsMaxPartCount <= len(parts) {
			return nil, fmt.Errorf("%w: more than %d parts", ErrEvsPushInvalid, EvsMaxPartCount)
		}
		changeless := &evsBuildPart{sections: &EvsPayload{}}
		fill(changeless, partRoom(len(parts)))
		parts = append(parts, changeless)
	}
	if len(parts) < evsMinPartCount {
		// one change, or none, and every section fitting in one part in a push past 1 MiB, by the proofs' room: the
		// last slice's tail goes to a changeless part, which a slice may split anywhere to do
		first := parts[0]
		var last protocol.EvsPayloadSection
		for _, sectionType := range evsSpilledSections {
			if sectionType == protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA && 0 < len(first.metadata) ||
				0 < len(first.sections.Section(sectionType)) {
				last = sectionType
			}
		}
		if last == protocol.EvsPayloadSection_EVS_PAYLOAD_SECTION_UNSPECIFIED || last == protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY {
			// a DROP's body never splits (10.2.5), and a DROP with lists has them after it
			return nil, fmt.Errorf("%w: a push in parts with one change and nothing to put beside it", ErrEvsPushInvalid)
		}
		slice := first.metadata
		if last != protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA {
			slice = first.sections.Section(last)
		}
		half := len(slice) / 2
		if last == protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS {
			// a value never split
			half -= half % sha256.Size
		}
		changeless := &evsBuildPart{sections: &EvsPayload{}}
		setSlice(changeless, last, slice[half:])
		if half == 0 {
			setSlice(first, last, nil)
		} else {
			setSlice(first, last, slice[:half])
		}
		parts = append(parts, changeless)
	}

	built := &EvsBuiltPush{ChangeTree: tree}
	partHashes := []byte{}
	paths := make([]EvsTokenPath, 0, len(changes))
	for i, part := range parts {
		message := &protocol.EvsPushPart{PushId: push.GetPushId(), Part: uint32(i + 1), SealedMetadata: part.metadata}
		if i < changefulCount {
			partRoot, _ := tree.PartRoot(i)
			message.ChangesRoot = partRoot[:]
		}
		sourceItems := [][]byte{}
		for _, change := range part.changes {
			message.Changes = append(message.Changes, change.message)
			paths = append(paths, change.planned.TokenPath)
			sourceItems = append(sourceItems, change.sourceItem)
			if change.planned.EntryVersion != nil {
				message.EntryVersions = append(message.EntryVersions, change.planned.EntryVersion)
			}
		}
		if i < changefulCount {
			proofs, err := evsEntryProofs(tree, i, part.changes)
			if err != nil {
				return nil, err
			}
			if 0 < len(sourcesSection) {
				part.sections.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_SOURCE_PATHS, evsJoinItems(sourceItems))
			}
			part.sections.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_MERKLE_PROOFS, evsJoinItems(proofs))
		}
		message.Sections = part.sections.Encode()
		partBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("evs: part: %w", err)
		}
		if format.PartMaxByteCount < len(partBytes) {
			return nil, fmt.Errorf("%w: part %d of %d bytes", ErrEvsPushInvalid, i+1, len(partBytes))
		}
		digest := sha256.Sum256(partBytes)
		partHashes = append(partHashes, digest[:]...)
		built.Parts = append(built.Parts, partBytes)
	}
	push.PartCount = uint32(len(parts))
	partsDigest := sha256.Sum256(partHashes)
	push.PartsSha256 = partsDigest[:]
	if len(changes) == 0 {
		root := tree.Root()
		push.Changes, push.ChangesRoot, push.ChangeCount, push.ChangedPrefixes = nil, bytes.Clone(root[:]), 0, nil
	} else if err := evsStateChangeRoot(push, tree.Root(), len(changes), paths); err != nil {
		return nil, err
	}
	statement, err := self.signStatementOf(push, format2)
	if err != nil {
		return nil, err
	}
	built.Statement = statement
	return built, nil
}

// Signs push as an EvsPush and parses the result back as evs will, refusing one past 1 KiB.
func (self *EvsStatementBuilder) signStatement(push *protocol.EvsPush) (*EvsStatement, error) {
	return self.signStatementOf(push, false)
}

// Signs push as signStatement does, parsing it back as its format.
func (self *EvsStatementBuilder) signStatementOf(push *protocol.EvsPush, format2 bool) (*EvsStatement, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(push)
	if err != nil {
		return nil, fmt.Errorf("evs: push: %w", err)
	}
	signed, err := self.sign(evsPushPurpose, bridge.SignedType_SIGNED_EVS_PUSH, body, nil)
	if err != nil {
		return nil, err
	}
	statementBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("evs: statement: %w", err)
	}
	return parseEvsStatement(statementBytes, format2)
}
