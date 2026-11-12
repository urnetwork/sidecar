// §22.5's push vectors and §11.6's checks row: statements inline within 1 KiB and under changes_root past it, parts
// past 1 MiB or 1,024 entry writes, each checked over the bytes as received, tampering refused before adoption, an
// unsorted change list refused (FS-10's case), and a one-change statement at depth 32 still within 1 KiB.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/evs/push_vectors.json
var evsPushVectorsJson []byte

// A test sidecar's identity key, signing EvsPush as Sidecar.Sign would.
type evsTestSigner struct {
	sidecarId  Id
	privateKey ed25519.PrivateKey
}

func newEvsTestSigner(label string) *evsTestSigner {
	return &evsTestSigner{
		sidecarId:  evsTestId("sidecar " + label),
		privateKey: ed25519.NewKeyFromSeed(evsTestBytes("identity "+label, ed25519.SeedSize)),
	}
}

// The EvsSignFunction.
func (self *evsTestSigner) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func (self *evsTestSigner) publicKey() []byte {
	return self.privateKey.Public().(ed25519.PublicKey)
}

// An entry version of a file at path k, written by plan's push.
func evsTestEntryVersion(t testing.TB, plan *EvsPushPlan, k int, version uint64) []byte {
	t.Helper()
	entry := &protocol.EvsEntryVersion{
		Version: version, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096,
		SealedFields: evsTestBytes(fmt.Sprint("sealed fields ", k), 32),
		Chain: []*protocol.EvsLocator{{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: evsTestBytes(fmt.Sprint("segment ", k), 32),
			Offset: 104, Length: 300,
		}},
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return entryBytes
}

// A push of changeCount files, k/<j> under directories of 50, each written on base version j (a creation at 0),
// with sealed metadata and a new segment, as signer writes it.
func evsTestPlan(t testing.TB, signer *evsTestSigner, label string, changeCount int) *EvsPushPlan {
	t.Helper()
	repoId := evsTestId("repo")
	pathKey := evsTestPathKey(t, repoId, 2)
	plan := &EvsPushPlan{
		RepoId: repoId, RefId: evsTestId("ref main"), RefKind: protocol.EvsRefKind_EVS_REF_SHARED,
		RefMode: protocol.EvsRefMode_EVS_REF_FILE, PushId: evsTestId("push " + label), BaseVersion: 7,
		BaseChain: EvsChainStart(repoId, evsTestId("ref main")), Generation: 2, GroupId: evsTestId("group"),
		GenerationCommitment: evsTestBytes("commitment", 32), PathEpoch: 2,
		Auth:            &bridge.AuthPin{Version: 41, Chain: evsTestBytes("auth chain", 32)},
		SignerSidecarId: signer.sidecarId, ClientId: evsTestId("client"), TimeMs: 1767225600000,
		SealedMetadata: evsTestBytes("sealed metadata", 32),
		NewObjects: []*EvsNewObject{{
			Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: evsTestBytes("segment 0", 32),
			PaddedSize: 4096, UploadDay: 20454,
		}},
	}
	for k := range changeCount {
		tokenPath, err := EvsPathTokens(pathKey, [][]byte{[]byte(fmt.Sprint("d", k/50)), []byte(fmt.Sprint("f", k))})
		if err != nil {
			t.Fatal(err)
		}
		baseEntryVersion := uint64(k % 3)
		plan.Changes = append(plan.Changes, &EvsPlannedChange{
			TokenPath: tokenPath, BaseEntryVersion: baseEntryVersion,
			EntryVersion: evsTestEntryVersion(t, plan, k, baseEntryVersion+1),
		})
	}
	return plan
}

// Builds a plan and checks the result as evs would: the statement parses and verifies, and its payload or parts
// pass the checks row.
func evsTestBuildAndCheck(t testing.TB, signer *evsTestSigner, plan *EvsPushPlan) (*EvsBuiltPush, *EvsCheckedPayload) {
	t.Helper()
	built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := ParseEvsStatement(built.Statement.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := statement.Verify(signer.publicKey()); err != nil {
		t.Fatal(err)
	}
	if len(statement.Bytes) > DefaultEvsFormatSettings().StatementMaxByteCount {
		t.Fatalf("a statement of %d bytes", len(statement.Bytes))
	}
	if statement.Push.GetPartCount() == 0 {
		checked, err := EvsCheckPayload(statement, built.Payload)
		if err != nil {
			t.Fatal(err)
		}
		return built, checked
	}
	checked, _, err := EvsCheckSeal(statement, built.Parts)
	if err != nil {
		t.Fatal(err)
	}
	return built, checked
}

// What testdata/evs/push_vectors.json holds.
type evsPushVectors struct {
	SignerPublicKey hexBytes         `json:"signer_public_key"`
	Pushes          []*evsPushVector `json:"pushes"`
}

type evsPushVector struct {
	Name          string     `json:"name"`
	ChangeCount   int        `json:"change_count"`
	Statement     hexBytes   `json:"statement"`
	ChangesRoot   hexBytes   `json:"changes_root,omitempty"`
	PartCount     uint32     `json:"part_count"`
	PayloadSha256 hexBytes   `json:"payload_sha256,omitempty"`
	Payload       hexBytes   `json:"payload,omitempty"`
	PartSha256s   []hexBytes `json:"part_sha256s,omitempty"`
}

var evsPushVectorCases = []struct {
	name        string
	changeCount int
	// what the case adds to evsTestPlan's push
	edit func(plan *EvsPushPlan)
}{
	{name: "inline", changeCount: 2},
	{name: "under changes_root", changeCount: 60},
	{name: "in parts", changeCount: 1100},
	// DESIGN-DETAILS 8.2.2's parts row: sealed metadata past the room beside 30 changes, its rest in a changeless part
	{name: "a changeless part", changeCount: 30, edit: func(plan *EvsPushPlan) {
		plan.SealedMetadata = bytes.Repeat(evsTestBytes("long sealed metadata", 32), 48*1024)
	}},
	// QD-658: a push with no change past 1 MiB, every part changeless, under the root of zero parts with changes
	{name: "no change in parts", changeCount: 0, edit: func(plan *EvsPushPlan) {
		plan.SealedMetadata = bytes.Repeat(evsTestBytes("long sealed metadata", 32), 48*1024)
	}},
	// 8.2.2's sections row: a creating git-mode push's sealed ref name and overlay base, sections 15 and 16
	{name: "a creating push", changeCount: 2, edit: func(plan *EvsPushPlan) {
		plan.RefMode = protocol.EvsRefMode_EVS_REF_GIT
		plan.RefName = append(evsTestBytes("sealed ref name", 32), evsTestBytes("sealed ref name tail", 30)...)
		plan.Base = &protocol.EvsOverlay{RefId: evsTestId("ref base").Bytes(), Version: 3}
	}},
}

func computeEvsPushVectors(t *testing.T) *evsPushVectors {
	signer := newEvsTestSigner("writer")
	vectors := &evsPushVectors{SignerPublicKey: signer.publicKey()}
	for _, pushCase := range evsPushVectorCases {
		plan := evsTestPlan(t, signer, pushCase.name, pushCase.changeCount)
		if pushCase.edit != nil {
			pushCase.edit(plan)
		}
		built, _ := evsTestBuildAndCheck(t, signer, plan)
		vector := &evsPushVector{
			Name: pushCase.name, ChangeCount: pushCase.changeCount, Statement: built.Statement.Bytes,
			ChangesRoot: built.Statement.Push.GetChangesRoot(), PartCount: built.Statement.Push.GetPartCount(),
		}
		if built.Payload != nil {
			digest := sha256.Sum256(built.Payload)
			vector.PayloadSha256 = digest[:]
			if len(built.Payload) <= 4096 {
				vector.Payload = built.Payload
			}
		}
		for _, part := range built.Parts {
			digest := sha256.Sum256(part)
			vector.PartSha256s = append(vector.PartSha256s, digest[:])
		}
		vectors.Pushes = append(vectors.Pushes, vector)
	}
	return vectors
}

// Each stored statement is what this build signs, parses as format 1 and verifies over its own bytes, and its case
// has the shape its name says.
func TestEvsPushVectors(t *testing.T) {
	stored := &evsPushVectors{}
	if !compareEvsVectors(t, "testdata/evs/push_vectors.json", evsPushVectorsJson, computeEvsPushVectors(t), stored) {
		return
	}
	for _, vector := range stored.Pushes {
		statement, err := ParseEvsStatement(vector.Statement)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if err := statement.Verify(stored.SignerPublicKey); err != nil {
			t.Errorf("%s: %v", vector.Name, err)
		}
		if statement.Sha256 != sha256.Sum256(vector.Statement) {
			t.Errorf("%s: the statement's hash is not over its bytes", vector.Name)
		}
		switch vector.Name {
		case "inline":
			if len(statement.Push.GetChanges()) != vector.ChangeCount || len(statement.Push.GetChangesRoot()) != 0 {
				t.Errorf("inline: %d changes inline", len(statement.Push.GetChanges()))
			}
			if vector.Payload != nil {
				if _, err := EvsCheckPayload(statement, vector.Payload); err != nil {
					t.Errorf("inline: the stored payload: %v", err)
				}
			}
		case "under changes_root":
			if statement.Push.GetChangeCount() != uint32(vector.ChangeCount) || vector.PartCount != 0 {
				t.Errorf("under changes_root: count %d, %d parts", statement.Push.GetChangeCount(), vector.PartCount)
			}
		case "in parts":
			if vector.PartCount < 2 || uint32(len(vector.PartSha256s)) != vector.PartCount {
				t.Errorf("in parts: %d parts", vector.PartCount)
			}
			partHashes := slices.Concat(func() [][]byte {
				hashes := [][]byte{}
				for _, partSha256 := range vector.PartSha256s {
					hashes = append(hashes, partSha256)
				}
				return hashes
			}()...)
			if digest := sha256.Sum256(partHashes); !bytes.Equal(digest[:], statement.Push.GetPartsSha256()) {
				t.Error("in parts: parts_sha256 is not over the parts' hashes")
			}
		case "a changeless part":
			if vector.PartCount != 2 || statement.Push.GetChangeCount() != uint32(vector.ChangeCount) {
				t.Errorf("a changeless part: %d parts, count %d", vector.PartCount, statement.Push.GetChangeCount())
			}
		case "no change in parts":
			emptyRoot := sha256.Sum256(nil)
			if vector.PartCount < 2 || statement.Push.GetChangeCount() != 0 || !bytes.Equal(vector.ChangesRoot, emptyRoot[:]) {
				t.Errorf("no change in parts: %d parts, count %d", vector.PartCount, statement.Push.GetChangeCount())
			}
		case "a creating push":
			if vector.Payload == nil || statement.Push.GetRefMode() != uint32(protocol.EvsRefMode_EVS_REF_GIT) {
				t.Fatal("a creating push: no payload stored, or not git mode")
			}
			checked, err := EvsCheckPayload(statement, vector.Payload)
			if err != nil || len(checked.RefName) == 0 || checked.Base.GetVersion() != 3 {
				t.Errorf("a creating push: the stored payload's sections: %v", err)
			}
		}
	}
}

// A push whose changes fit stays inline and carries no list or proofs in its payload.
func TestEvsSmallPushStaysInline(t *testing.T) {
	signer := newEvsTestSigner("writer")
	built, checked := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "small", 2))
	if built.ChangeTree != nil || len(built.Statement.Push.GetChanges()) != 2 {
		t.Fatalf("%d changes inline", len(built.Statement.Push.GetChanges()))
	}
	payload, _ := ParseEvsPayload(built.Payload)
	if payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST) != nil || payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_MERKLE_PROOFS) != nil {
		t.Error("an inline push lists its changes again")
	}
	if !checked.CreatesPath || len(checked.Changes) != 2 || checked.Changes[0].EntryVersion == nil {
		t.Error("the checks lost the changes or their entry versions")
	}
}

// Past 1 KiB the changes move under changes_root, their covering prefixes within 512 B covering every change, and
// every entry version's proof reaches the root.
func TestEvsLargePushFallsBackToChangesRoot(t *testing.T) {
	signer := newEvsTestSigner("writer")
	built, checked := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "large", 300))
	push := built.Statement.Push
	if len(push.GetChanges()) != 0 || push.GetChangeCount() != 300 || built.ChangeTree == nil {
		t.Fatalf("count %d, %d inline", push.GetChangeCount(), len(push.GetChanges()))
	}
	prefixBytes := 0
	for _, prefix := range built.Statement.ChangedPrefixes {
		prefixBytes += len(prefix) * EvsTokenByteCount
	}
	if DefaultEvsFormatSettings().ChangedPrefixesMaxByteCount < prefixBytes || !evsPrefixesCover(built.Statement.ChangedPrefixes, checked.Changes) {
		t.Errorf("covering prefixes of %d bytes", prefixBytes)
	}
	root := built.ChangeTree.Root()
	if !bytes.Equal(root[:], push.GetChangesRoot()) {
		t.Error("changes_root is not the tree's")
	}
}

// §22.5: at depth 32, a one-change statement still fits inline, or falls back to changes_root with a cover that keeps
// it within 1 KiB.
func TestEvsDepthThirtyTwoOneChangeStatementFits(t *testing.T) {
	signer := newEvsTestSigner("writer")
	plan := evsTestPlan(t, signer, "deep", 0)
	names := [][]byte{}
	for i := range EvsTokenPathMaxLength {
		names = append(names, []byte(fmt.Sprint("level", i)))
	}
	tokenPath, err := EvsPathTokens(evsTestPathKey(t, plan.RepoId, 2), names)
	if err != nil {
		t.Fatal(err)
	}
	plan.Changes = []*EvsPlannedChange{{TokenPath: tokenPath, EntryVersion: evsTestEntryVersion(t, plan, 0, 1)}}
	built, checked := evsTestBuildAndCheck(t, signer, plan)
	if len(built.Statement.Bytes) > DefaultEvsFormatSettings().StatementMaxByteCount || len(checked.Changes) != 1 || !checked.Changes[0].TokenPath.Equal(tokenPath) {
		t.Fatalf("a statement of %d bytes", len(built.Statement.Bytes))
	}
	t.Logf("depth 32: %d-byte statement, changes inline: %v", len(built.Statement.Bytes), len(built.Statement.Push.GetChanges()) == 1)

	// a statement with more of its own fields set has no room for the change inline, so it falls back to a root,
	// with covering prefixes cut short enough that it still fits
	owner := evsTestId("owner")
	plan.OwnerSidecarId = &owner
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)
	plan.PathMapSha256 = evsTestBytes("map", 32)
	plan.MapSourceVersion = 6
	plan.MapSourceChain = evsTestBytes("map source", 32)
	built, checked = evsTestBuildAndCheck(t, signer, plan)
	push := built.Statement.Push
	if len(built.Statement.Bytes) > DefaultEvsFormatSettings().StatementMaxByteCount || len(push.GetChanges()) != 0 || push.GetChangeCount() != 1 ||
		len(built.Statement.ChangedPrefixes) != 1 || !tokenPath.HasPrefix(built.Statement.ChangedPrefixes[0]) {
		t.Fatalf("the fallback: a %d-byte statement, %d inline", len(built.Statement.Bytes), len(push.GetChanges()))
	}
	t.Logf("depth 32 with a full statement: %d bytes under changes_root, a covering prefix of %d components", len(built.Statement.Bytes), len(built.Statement.ChangedPrefixes[0]))
}

// FS-10's case: a change list out of order is refused, whether inline in the statement or under a root a writer
// signed over the unsorted list.
func TestEvsUnsortedChangeListRefused(t *testing.T) {
	signer := newEvsTestSigner("writer")
	plan := evsTestPlan(t, signer, "unsorted", 60)
	built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ParseEvsPayload(built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	leaves, _ := EvsPayloadItems(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST))
	leaves[0], leaves[1] = leaves[1], leaves[0]
	unsortedRoot := NewEvsMerkleTree(leaves).Root()
	push := proto.Clone(built.Statement.Push).(*protocol.EvsPush)
	push.ChangesRoot = unsortedRoot[:]
	payload.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST, evsJoinItems(leaves))
	statement, err := NewEvsStatementBuilder(signer.sign).signStatement(push)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvsCheckPayload(statement, payload.Encode()); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a signed root over an unsorted list: %v", err)
	}

	inline := proto.Clone(evsTestBuiltInline(t, signer).Statement.Push).(*protocol.EvsPush)
	inline.Changes[0], inline.Changes[1] = inline.Changes[1], inline.Changes[0]
	body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(inline)
	signed, _ := signer.sign(evsPushPurpose, bridge.SignedType_SIGNED_EVS_PUSH, body, nil)
	statementBytes, _ := proto.Marshal(signed)
	if _, err := ParseEvsStatement(statementBytes); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("unsorted inline changes: %v", err)
	}
	inline.Changes[1] = inline.Changes[0]
	body, _ = proto.MarshalOptions{Deterministic: true}.Marshal(inline)
	signed, _ = signer.sign(evsPushPurpose, bridge.SignedType_SIGNED_EVS_PUSH, body, nil)
	statementBytes, _ = proto.Marshal(signed)
	if _, err := ParseEvsStatement(statementBytes); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a path changed twice: %v", err)
	}
}

func evsTestBuiltInline(t testing.TB, signer *evsTestSigner) *EvsBuiltPush {
	built, _ := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "inline", 3))
	return built
}

// A statement past 1 KiB is refused, never trimmed; and every shape rule refuses with its code: format 2's flags and
// fields as needing format 2, the rest as INVALID.
func TestEvsStatementShapeRefusals(t *testing.T) {
	signer := newEvsTestSigner("writer")
	base := evsTestBuiltInline(t, signer).Statement.Push
	resign := func(push *protocol.EvsPush) []byte {
		body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(push)
		signed, _ := signer.sign(evsPushPurpose, bridge.SignedType_SIGNED_EVS_PUSH, body, nil)
		statementBytes, _ := proto.Marshal(signed)
		return statementBytes
	}
	cases := []struct {
		name   string
		mutate func(*protocol.EvsPush)
		want   error
	}{
		{name: "DROP", mutate: func(push *protocol.EvsPush) { push.Flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) }, want: ErrEvsFormatUnsupported},
		{name: "CUT", mutate: func(push *protocol.EvsPush) { push.Flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_CUT) }, want: ErrEvsFormatUnsupported},
		{name: "drop_sha256", mutate: func(push *protocol.EvsPush) { push.DropSha256 = evsTestBytes("drop", 32) }, want: ErrEvsFormatUnsupported},
		{name: "index_epoch", mutate: func(push *protocol.EvsPush) { push.IndexEpoch = 3 }, want: ErrEvsFormatUnsupported},
		{name: "an unknown flag", mutate: func(push *protocol.EvsPush) { push.Flags |= 1024 }, want: ErrEvsPushInvalid},
		{name: "consumed_through alone", mutate: func(push *protocol.EvsPush) { push.ConsumedThrough = 5 }, want: ErrEvsPushInvalid},
		{name: "an erased list alone", mutate: func(push *protocol.EvsPush) { push.ErasedSha256 = evsTestBytes("erased", 32) }, want: ErrEvsPushInvalid},
		{name: "one part", mutate: func(push *protocol.EvsPush) { push.PartCount = 1 }, want: ErrEvsPushInvalid},
		{name: "a short push id", mutate: func(push *protocol.EvsPush) { push.PushId = push.PushId[:15] }, want: ErrEvsPushInvalid},
		{name: "ref kind 5", mutate: func(push *protocol.EvsPush) { push.RefKind = 5 }, want: ErrEvsPushInvalid},
		{name: "another signer", mutate: func(push *protocol.EvsPush) { push.SignerSidecarId = evsTestId("other").Bytes() }, want: ErrEvsPushInvalid},
		{name: "a path map without PATH_EPOCH", mutate: func(push *protocol.EvsPush) { push.PathMapSha256 = evsTestBytes("map", 32) }, want: ErrEvsPushInvalid},
		{name: "a count beside inline changes", mutate: func(push *protocol.EvsPush) { push.ChangeCount = 3 }, want: ErrEvsPushInvalid},
	}
	for _, refusal := range cases {
		push := proto.Clone(base).(*protocol.EvsPush)
		refusal.mutate(push)
		if _, err := ParseEvsStatement(resign(push)); !errors.Is(err, refusal.want) {
			t.Errorf("%s: %v", refusal.name, err)
		}
	}
	long := proto.Clone(base).(*protocol.EvsPush)
	long.SealedMetadataSha256 = nil
	statementBytes := resign(long)
	padded := append(bytes.Clone(statementBytes), make([]byte, DefaultEvsFormatSettings().StatementMaxByteCount+1-len(statementBytes))...)
	if _, err := ParseEvsStatement(padded); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a statement past 1 KiB: %v", err)
	}
	otherType, _ := proto.Marshal(&bridge.Signed{Body: []byte{}, SignerId: signer.sidecarId.Bytes(), Signature: make([]byte, 64), Type: uint32(bridge.SignedType_SIGNED_EVS_RESEED)})
	if _, err := ParseEvsStatement(otherType); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("another signed type: %v", err)
	}
}

// §22.6: a statement's hash and signature are over the bytes as received. A signed statement whose fields arrive in
// another order hashes to its own bytes, not a re-marshal's, and its body's signature still verifies; a flipped byte
// does not.
func TestEvsStatementHashesItsReceivedBytes(t *testing.T) {
	signer := newEvsTestSigner("writer")
	built := evsTestBuiltInline(t, signer)
	signed := built.Statement.Signed
	reordered := []byte{}
	reordered = append(reordered, protoBytesField(6, nil, uint64(signed.GetType()))...)
	reordered = append(reordered, protoBytesField(4, signed.GetSignature(), 0)...)
	reordered = append(reordered, protoBytesField(2, signed.GetSignerId(), 0)...)
	reordered = append(reordered, protoBytesField(1, signed.GetBody(), 0)...)
	statement, err := ParseEvsStatement(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if statement.Sha256 != sha256.Sum256(reordered) || statement.Sha256 == built.Statement.Sha256 {
		t.Error("the hash is not over the received bytes")
	}
	if err := statement.Verify(signer.publicKey()); err != nil {
		t.Errorf("the reordered statement's signature: %v", err)
	}
	flipped := bytes.Clone(built.Statement.Bytes)
	flipped[len(flipped)/2] ^= 1
	if parsed, err := ParseEvsStatement(flipped); err == nil && parsed.Verify(signer.publicKey()) == nil {
		t.Error("a flipped statement verified")
	}
}

// A protobuf field: bytes for wire type 2, else value as a varint.
func protoBytesField(number int, value []byte, varint uint64) []byte {
	if value == nil {
		return append([]byte{byte(number<<3 | 0)}, appendVarint(nil, varint)...)
	}
	field := append([]byte{byte(number<<3 | 2)}, appendVarint(nil, uint64(len(value)))...)
	return append(field, value...)
}

func appendVarint(dst []byte, value uint64) []byte {
	for 0x80 <= value {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

// §22.6: tampering with any hashed section of a payload fails the checks before anything is adopted, as does a
// section the statement does not state.
func TestEvsPayloadTamperingFailsBeforeAdoption(t *testing.T) {
	signer := newEvsTestSigner("writer")
	plan := evsTestPlan(t, signer, "tamper", 60)
	plan.Erased = []*EvsErasedKey{{SlotId: evsTestId("slot"), KeyIndex: 3}}
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE)
	built, _ := evsTestBuildAndCheck(t, signer, plan)
	payload, err := ParseEvsPayload(built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, sectionType := range []protocol.EvsPayloadSection{
		protocol.EvsPayloadSection_EVS_PAYLOAD_ENTRY_VERSIONS, protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA,
		protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST, protocol.EvsPayloadSection_EVS_PAYLOAD_NEW_OBJECTS,
		protocol.EvsPayloadSection_EVS_PAYLOAD_ERASED_LIST, protocol.EvsPayloadSection_EVS_PAYLOAD_MERKLE_PROOFS,
	} {
		sectionBytes := payload.Section(sectionType)
		if len(sectionBytes) == 0 {
			t.Fatalf("section %d absent", sectionType)
		}
		for _, at := range []int{0, len(sectionBytes) / 2, len(sectionBytes) - 1} {
			tampered := &EvsPayload{sections: payload.sections}
			flipped := bytes.Clone(sectionBytes)
			flipped[at] ^= 0x01
			tampered.SetSection(sectionType, flipped)
			if _, err := EvsCheckPayload(built.Statement, tampered.Encode()); err == nil {
				t.Errorf("section %d flipped at %d passed", sectionType, at)
			}
		}
		dropped := &EvsPayload{sections: payload.sections}
		dropped.SetSection(sectionType, nil)
		if _, err := EvsCheckPayload(built.Statement, dropped.Encode()); err == nil {
			t.Errorf("section %d dropped passed", sectionType)
		}
	}
	extra := &EvsPayload{sections: payload.sections}
	extra.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_TAIL_MOVES, []byte{0, 0, 0, 0})
	if _, err := EvsCheckPayload(built.Statement, extra.Encode()); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a section with no statement hash: %v", err)
	}
	if _, err := EvsCheckPayload(built.Statement, append(bytes.Clone(built.Payload), 1)); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a byte past the last section: %v", err)
	}
}

// What questions/evs1-m2-01-inline-record-home leaves open fails closed: inline records in section 3 or in a part
// are refused. Format 2's sections, staged segments, versioning and locators are refused as needing format 2;
// reserved locator kinds and layouts as INVALID.
func TestEvsPayloadRefusesWhatFormatOneDoesNotCarry(t *testing.T) {
	signer := newEvsTestSigner("writer")
	built, _ := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "refusals", 2))
	payload, _ := ParseEvsPayload(built.Payload)
	withInline := &EvsPayload{sections: payload.sections}
	withInline.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_INLINE_RECORDS, evsJoinItems([][]byte{{1, 2, 3}}))
	if _, err := EvsCheckPayload(built.Statement, withInline.Encode()); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("inline records: %v", err)
	}
	withDrop := &EvsPayload{sections: payload.sections}
	withDrop.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY, []byte{1})
	if _, err := ParseEvsPayload(withDrop.Encode()); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("a DROP section: %v", err)
	}
	staged := (&EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, Id: make([]byte, 32)}).encode()
	if _, err := decodeEvsNewObject(staged); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("a staged segment: %v", err)
	}
	plan := evsTestPlan(t, signer, "entry refusals", 1)
	entries := map[string]func(*protocol.EvsEntryVersion){
		"versioning 1": func(entry *protocol.EvsEntryVersion) { entry.Versioning = 1 },
		"a kind-5 locator": func(entry *protocol.EvsEntryVersion) {
			entry.Chain[0].Kind = uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT)
		},
		"a staged locator":      func(entry *protocol.EvsEntryVersion) { entry.Chain[0].Staged = true },
		"a kind-3 locator":      func(entry *protocol.EvsEntryVersion) { entry.Chain[0].Kind = 3 },
		"layout 1":              func(entry *protocol.EvsEntryVersion) { entry.Layout = 1 },
		"another push's":        func(entry *protocol.EvsEntryVersion) { entry.PushId = evsTestId("other push").Bytes() },
		"a file with no fields": func(entry *protocol.EvsEntryVersion) { entry.SealedFields = nil },
	}
	for label, mutate := range entries {
		entry := &protocol.EvsEntryVersion{}
		proto.Unmarshal(plan.Changes[0].EntryVersion, entry)
		mutate(entry)
		entryBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		_, err := checkEvsEntryVersion(entryBytes, &protocol.EvsPush{PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion})
		want := ErrEvsPushInvalid
		if label == "versioning 1" || label == "a kind-5 locator" || label == "a staged locator" {
			want = ErrEvsFormatUnsupported
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// A push past 1,024 entry writes goes in parts: each part checks alone as it arrives, the seal checks them together,
// and a seal over parts missing, swapped, from another push or tampered is refused.
func TestEvsPartsCheckAloneAndAtTheSeal(t *testing.T) {
	signer := newEvsTestSigner("writer")
	built, checked := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "parts", 1100))
	push := built.Statement.Push
	if push.GetPartCount() < 2 || len(built.Parts) != int(push.GetPartCount()) || len(checked.Changes) != 1100 {
		t.Fatalf("%d parts, %d changes", push.GetPartCount(), len(checked.Changes))
	}
	for i, part := range built.Parts {
		checkedPart, err := EvsCheckPart(built.Statement, part)
		if err != nil || checkedPart.Part != uint32(i+1) {
			t.Fatalf("part %d: %v", i+1, err)
		}
		root, _ := built.ChangeTree.PartRoot(i)
		if checkedPart.Root != root || len(checkedPart.Changes) == 0 {
			t.Errorf("part %d's root or changes", i+1)
		}
	}
	if _, _, err := EvsCheckSeal(built.Statement, built.Parts[:len(built.Parts)-1]); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a part missing: %v", err)
	}
	swapped := slices.Clone(built.Parts)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if _, _, err := EvsCheckSeal(built.Statement, swapped); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("parts swapped: %v", err)
	}
	other, _ := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "other parts", 1100))
	if _, err := EvsCheckPart(built.Statement, other.Parts[0]); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("another push's part: %v", err)
	}
	tampered := slices.Clone(built.Parts)
	part := &protocol.EvsPushPart{}
	proto.Unmarshal(tampered[0], part)
	part.EntryVersions[0] = append(bytes.Clone(part.EntryVersions[0]), 0)
	tampered[0], _ = proto.MarshalOptions{Deterministic: true}.Marshal(part)
	if _, err := EvsCheckPart(built.Statement, tampered[0]); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a tampered entry version: %v", err)
	}
	if _, _, err := EvsCheckSeal(built.Statement, tampered); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a seal over a tampered part: %v", err)
	}
	inlineRecords := &protocol.EvsPushPart{}
	proto.Unmarshal(built.Parts[0], inlineRecords)
	inlineRecords.InlineRecords = [][]byte{{1}}
	withInline, _ := proto.MarshalOptions{Deterministic: true}.Marshal(inlineRecords)
	if _, err := EvsCheckPart(built.Statement, withInline); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("inline records in a part: %v", err)
	}
}

// Receipts and path maps hold their shapes; a versionless receipt is format 2's.
func TestEvsReceiptAndPathMapShapes(t *testing.T) {
	receipt := &protocol.EvsUploadReceipt{
		RepoId: evsTestId("repo").Bytes(), SegmentId: evsTestBytes("segment", 32), PaddedSize: 4096, UploadMs: 1767225600000,
		UploaderSidecarId: evsTestId("uploader").Bytes(), KeyId: 1, Mac: evsTestBytes("mac", 16),
	}
	receiptBytes, _ := proto.Marshal(receipt)
	if _, err := DecodeEvsUploadReceipt(receiptBytes); err != nil {
		t.Errorf("a receipt: %v", err)
	}
	versionless := proto.Clone(receipt).(*protocol.EvsUploadReceipt)
	versionless.Versionless = true
	versionlessBytes, _ := proto.Marshal(versionless)
	if _, err := DecodeEvsUploadReceipt(versionlessBytes); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Errorf("a versionless receipt: %v", err)
	}
	notPadme := proto.Clone(receipt).(*protocol.EvsUploadReceipt)
	notPadme.PaddedSize = 4097
	notPadmeBytes, _ := proto.Marshal(notPadme)
	if _, err := DecodeEvsUploadReceipt(notPadmeBytes); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a size no Padmé gives: %v", err)
	}
	signedMap := evsTestPathMap(t)
	if _, _, err := ParseEvsPathMap(signedMap); err != nil {
		t.Errorf("a path map: %v", err)
	}
	if _, _, err := ParseEvsPathMap(signedMap[:len(signedMap)/2]); err == nil {
		t.Error("half a path map parsed")
	}
}

// A signed path map part with one move from epoch 1 into 2.
func evsTestPathMap(t testing.TB) []byte {
	t.Helper()
	signer := newEvsTestSigner("mapper")
	move := &protocol.EvsPathMove{
		NewTokenPath: EvsTokenPath{evsTestToken("new")}.Components(),
		Sources:      []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: EvsTokenPath{evsTestToken("old")}.Components()}},
		SealedName:   evsTestBytes("sealed name", 32),
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsPathMap{
		RepoId: evsTestId("repo").Bytes(), RefId: evsTestId("ref main").Bytes(), PathEpoch: 2, Part: 1, Parts: 1,
		Moves: []*protocol.EvsPathMove{move}, SourceVersion: 9, SourceChain: evsTestBytes("source chain", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := signer.sign("evs-path-epoch", bridge.SignedType_SIGNED_EVS_PATH_MAP, body, nil)
	signedBytes, _ := proto.Marshal(signed)
	return signedBytes
}

// The push the push target tampers with: a statement under changes_root with its payload.
type evsFuzzPushFixture struct {
	statement []byte
	payload   []byte
	checked   *EvsCheckedPayload
	publicKey []byte
}

func newEvsFuzzPushFixture(t testing.TB) *evsFuzzPushFixture {
	signer := newEvsTestSigner("fuzz writer")
	built, checked := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "fuzz", 40))
	return &evsFuzzPushFixture{statement: built.Statement.Bytes, payload: built.Payload, checked: checked, publicKey: signer.publicKey()}
}

// §22.6's push target: whatever is done to the statement or the payload, a push that still parses, verifies and
// passes the checks adopts exactly the changes, entry versions and hashed sections the original carried.
func checkEvsPushTampering(t *testing.T, fixture *evsFuzzPushFixture, input []byte) {
	statementBytes, payloadBytes := fixture.statement, fixture.payload
	if 0 < len(input) {
		if input[0]%2 == 0 {
			statementBytes = evsFuzzTamper(fixture.statement, input[1:], func([]byte) {})
		} else {
			payloadBytes = evsFuzzTamper(fixture.payload, input[1:], func([]byte) {})
		}
	}
	statement, err := ParseEvsStatement(statementBytes)
	if err != nil || statement.Verify(fixture.publicKey) != nil {
		return
	}
	checked, err := EvsCheckPayload(statement, payloadBytes)
	if err != nil {
		return
	}
	if len(checked.Changes) != len(fixture.checked.Changes) || !bytes.Equal(checked.SealedMetadata, fixture.checked.SealedMetadata) {
		t.Fatal("a tampered push was adopted with other changes or metadata")
	}
	for i, change := range checked.Changes {
		original := fixture.checked.Changes[i]
		if !bytes.Equal(change.Leaf, original.Leaf) || !bytes.Equal(change.EntryVersion, original.EntryVersion) {
			t.Fatalf("change %d was adopted otherwise", i)
		}
	}
}

func TestEvsPushFuzzSeeds(t *testing.T) {
	fixture := newEvsFuzzPushFixture(t)
	for _, seed := range evsFuzzSeedFiles(t, "testdata/fuzz/evs_push") {
		checkEvsPushTampering(t, fixture, seed)
	}
}

// QD-658 (question evs1-m2-48-changeless-push-in-parts): a push with no change past 1 MiB goes in parts, every part
// changeless, its statement stating change_count 0, no prefix and the root of zero parts with changes, SHA-256 of no
// bytes, which the seal check takes; changes_root with a count of 0 is refused on a statement not in parts, under
// another root, or beside a prefix.
func TestEvsPushWithNoChangeGoesInParts(t *testing.T) {
	signer := newEvsTestSigner("writer")
	plan := evsTestPlan(t, signer, "no change", 0)
	plan.SealedMetadata = evsTestContent("long sealed metadata", 1536*1024)
	built, checked := evsTestBuildAndCheck(t, signer, plan)
	push := built.Statement.Push
	emptyRoot := sha256.Sum256(nil)
	if push.GetPartCount() < 2 || push.GetChangeCount() != 0 || len(push.GetChangedPrefixes()) != 0 || !bytes.Equal(push.GetChangesRoot(), emptyRoot[:]) {
		t.Fatalf("the statement: %d parts, count %d, %d prefixes", push.GetPartCount(), push.GetChangeCount(), len(push.GetChangedPrefixes()))
	}
	if len(checked.Changes) != 0 || !bytes.Equal(checked.SealedMetadata, plan.SealedMetadata) {
		t.Fatalf("the joined payload: %d changes, %d bytes of metadata", len(checked.Changes), len(checked.SealedMetadata))
	}
	resign := func(push *protocol.EvsPush) []byte {
		body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(push)
		signed, _ := signer.sign(evsPushPurpose, bridge.SignedType_SIGNED_EVS_PUSH, body, nil)
		statementBytes, _ := proto.Marshal(signed)
		return statementBytes
	}
	for name, mutate := range map[string]func(push *protocol.EvsPush){
		"not in parts": func(push *protocol.EvsPush) { push.PartCount, push.PartsSha256 = 0, nil },
		"another root": func(push *protocol.EvsPush) { push.ChangesRoot = evsTestBytes("another root", 32) },
		"a prefix": func(push *protocol.EvsPush) {
			push.ChangedPrefixes = []*protocol.EvsTokenPath{{Token: [][]byte{evsTestBytes("a token", EvsTokenByteCount)}}}
		},
	} {
		mutated := proto.Clone(push).(*protocol.EvsPush)
		mutate(mutated)
		if _, err := ParseEvsStatement(resign(mutated)); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("count 0 under changes_root %s: %v", name, err)
		}
	}
}

// DESIGN-DETAILS 10.2.5's layout, three ways: a DROP of one change and 100,000 listed values is 4 parts, the last 3
// changeless; of no change and 40,000 values 2 changeless parts under the empty change list; of 1,024 changes with
// 16 KiB kept heads and 2^20 values within 51 parts. Each time section 9 rides whole in part 1, no value is split,
// a changeless part holds at most DropListPartValueCount values, and the slices joined in part order are the one-part
// sections; the seal check takes each.
func TestEvsStatementLaysOutADropInParts(t *testing.T) {
	format := DefaultEvsFormatSettings()
	signer := newEvsTestSigner("drop layout")
	dropOf := func(t *testing.T, plan *EvsPushPlan, label string, count int) {
		listed := evsTestDropListed(label, count)
		paths := []*protocol.EvsDropPath{evsTestDropPath(label, uint64(count)+1, evsDropBoundaryWritten)}
		if len(plan.Changes) == 0 {
			paths[0].Boundary = evsDropBoundaryRemoved
		}
		lists, err := EvsBuildDropLists(paths, [][][]byte{listed})
		if err != nil {
			t.Fatal(err)
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsDropHistory{
			DropId: evsTestId("drop " + label).Bytes(), Action: evsDropActionDrop, NotBeforeMs: plan.TimeMs, Paths: paths,
		})
		if err != nil {
			t.Fatal(err)
		}
		plan.PathEpoch = evsTestDropPathEpoch
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
		plan.DropBody = body
		plan.DropLists = lists
		plan.NewObjects = nil
	}
	layOut := func(t *testing.T, plan *EvsPushPlan, check bool) (built *EvsBuiltPush, changeless int) {
		t.Helper()
		built, err := NewEvsStatementBuilder(signer.sign).BuildFormat2(plan)
		if err != nil {
			t.Fatal(err)
		}
		bodySlices, listSlices := [][]byte{}, [][]byte{}
		for i, partBytes := range built.Parts {
			part, _, err := parseEvsPushPart(partBytes)
			if err != nil {
				t.Fatal(err)
			}
			sections, err := parseEvsPayload(part.GetSections(), true)
			if err != nil {
				t.Fatal(err)
			}
			body := sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY)
			if (i == 0) != (len(body) != 0) {
				t.Fatalf("part %d holds %d bytes of the body", i+1, len(body))
			}
			bodySlices = append(bodySlices, body)
			list := sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS)
			if len(list)%sha256.Size != 0 {
				t.Fatalf("part %d cuts a value: %d bytes", i+1, len(list))
			}
			if len(part.GetChanges()) == 0 {
				changeless += 1
				if format.DropListPartValueCount < len(list)/sha256.Size {
					t.Fatalf("changeless part %d holds %d values", i+1, len(list)/sha256.Size)
				}
			}
			listSlices = append(listSlices, list)
		}
		if !bytes.Equal(bytes.Join(bodySlices, nil), plan.DropBody) || !bytes.Equal(bytes.Join(listSlices, nil), plan.DropLists) {
			t.Fatal("the joined slices are not the one-part sections")
		}
		if check {
			checked, _, err := EvsCheckSealFormat2(built.Statement, built.Parts, make([][]byte, len(built.Parts)))
			if err != nil {
				t.Fatal(err)
			}
			if checked.Drop == nil || !bytes.Equal(checked.Drop.Body, plan.DropBody) {
				t.Fatal("the seal did not adopt the DROP")
			}
		}
		return built, changeless
	}

	one := evsTestPlan(t, signer, "drop one change", 1)
	dropOf(t, one, "one", 100000)
	built, changeless := layOut(t, one, true)
	if len(built.Parts) != 4 || changeless != 3 {
		t.Errorf("one change and 100,000 values: %d parts, %d changeless", len(built.Parts), changeless)
	}

	none := evsTestPlan(t, signer, "drop no change", 0)
	dropOf(t, none, "none", 40000)
	built, changeless = layOut(t, none, true)
	push := built.Statement.Push
	if len(built.Parts) != 2 || changeless != 2 || push.GetChangeCount() != 0 || len(push.GetChangedPrefixes()) != 0 {
		t.Errorf("no change and 40,000 values: %d parts, %d changeless, count %d", len(built.Parts), changeless, push.GetChangeCount())
	}
	if empty := sha256.Sum256(nil); !bytes.Equal(push.GetChangesRoot(), empty[:]) {
		t.Error("a changeless DROP's root is not the empty change list's")
	}

	// 1,024 written boundaries, each with a kept head of 16 KiB inline in its entry version
	big := evsTestPlan(t, signer, "drop big", 0)
	pathKey := evsTestPathKey(t, big.RepoId, 2)
	for k := range format.DropMaxPathCount {
		tokenPath, err := EvsPathTokens(pathKey, [][]byte{[]byte(fmt.Sprint("d", k/50)), []byte(fmt.Sprint("f", k))})
		if err != nil {
			t.Fatal(err)
		}
		big.Changes = append(big.Changes, &EvsPlannedChange{TokenPath: tokenPath, BaseEntryVersion: 1, EntryVersion: bytes.Repeat(evsTestBytes(fmt.Sprint("kept head ", k), 32), 16*1024/32)})
	}
	dropOf(t, big, "big", format.DropMaxListedCount)
	built, _ = layOut(t, big, false)
	if 51 < len(built.Parts) {
		t.Errorf("1,024 changes and 2^20 values in %d parts", len(built.Parts))
	}
}

// A DROP whose body rides in a part past part 1 is INVALID at the seal (DESIGN-DETAILS 10.2.5), whatever its hash.
func TestEvsSealRefusesADropBodyOutsidePartOne(t *testing.T) {
	signer := newEvsTestSigner("drop body moved")
	plan := evsTestPlan(t, signer, "drop body moved", 0)
	listed := evsTestDropListed("moved", 40000)
	paths := []*protocol.EvsDropPath{evsTestDropPath("moved", 40001, evsDropBoundaryRemoved)}
	lists, err := EvsBuildDropLists(paths, [][][]byte{listed})
	if err != nil {
		t.Fatal(err)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsDropHistory{
		DropId: evsTestId("drop moved").Bytes(), Action: evsDropActionDrop, NotBeforeMs: plan.TimeMs, Paths: paths,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.PathEpoch = evsTestDropPathEpoch
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
	plan.DropBody, plan.DropLists, plan.NewObjects = body, lists, nil
	built, err := NewEvsStatementBuilder(signer.sign).BuildFormat2(plan)
	if err != nil {
		t.Fatal(err)
	}
	// move the body from part 1 to part 2, re-signing parts_sha256 over the moved parts, as a modified client would
	parts := make([]*protocol.EvsPushPart, len(built.Parts))
	for i, partBytes := range built.Parts {
		if parts[i], _, err = parseEvsPushPart(partBytes); err != nil {
			t.Fatal(err)
		}
	}
	first, err := parseEvsPayload(parts[0].GetSections(), true)
	if err != nil {
		t.Fatal(err)
	}
	secondSections, err := parseEvsPayload(parts[1].GetSections(), true)
	if err != nil {
		t.Fatal(err)
	}
	secondSections.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY, first.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY))
	first.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY, nil)
	parts[0].Sections, parts[1].Sections = first.Encode(), secondSections.Encode()
	partHashes := []byte{}
	partBytes := make([][]byte, len(parts))
	for i, part := range parts {
		marshal := proto.MarshalOptions{Deterministic: true}
		if partBytes[i], err = marshal.Marshal(part); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(partBytes[i])
		partHashes = append(partHashes, digest[:]...)
	}
	push := proto.Clone(built.Statement.Push).(*protocol.EvsPush)
	partsDigest := sha256.Sum256(partHashes)
	push.PartsSha256 = partsDigest[:]
	statement, err := NewEvsStatementBuilder(signer.sign).signStatementOf(push, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := EvsCheckSealFormat2(statement, partBytes, make([][]byte, len(partBytes))); !errors.Is(err, ErrEvsPushInvalid) || !strings.Contains(err.Error(), "part 1") {
		t.Errorf("a DROP's body in part 2: %v", err)
	}
	if _, _, err := EvsCheckSealFormat2(built.Statement, built.Parts, make([][]byte, len(built.Parts))); err != nil {
		t.Errorf("its twin with the body in part 1: %v", err)
	}
}

// DESIGN-DETAILS 10.2.2's replaced row: a purge list with replaced set rides only in a part's record, as AddFormat2
// writes it and ParseEvsBatchRecordFormat2 reads it; in a push's or a seal's record it is INVALID either way.
func TestEvsRecordTailTakesReplacedOnlyInAPart(t *testing.T) {
	list := &protocol.EvsPurgeList{Replaced: true, Candidates: []*protocol.EvsPurgeCandidate{{
		TokenPath: EvsTokenPath{evsTestToken("x")}.Components(), ReplacedVersion: 3, SegmentIds: [][]byte{evsTestBytes("segment", 32)},
	}}}
	listBytes, err := EncodeEvsPurgeList(list)
	if err != nil {
		t.Fatal(err)
	}
	record := func(recordType protocol.EvsBatchRecordType) *EvsBatchRecord {
		return &EvsBatchRecord{
			Type: recordType, RepoId: evsTestId("repo"), RefId: evsTestId("ref"), PushId: evsTestId("push"),
			SignerSidecarId: evsTestId("signer"), TimeMs: 1767225600000, Body: evsJoinItems([][]byte{evsTestBytes("statement", 32)}),
		}
	}
	tail := &EvsBatchRecordTail{PurgeList: listBytes}
	writer := NewEvsBatchWriter(0, 0, 0, 0)
	if _, err := writer.AddFormat2(record(protocol.EvsBatchRecordType_EVS_BATCH_PART), tail); err != nil {
		t.Errorf("a part's replaced list: %v", err)
	}
	for _, recordType := range []protocol.EvsBatchRecordType{protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_SEAL} {
		if _, err := writer.AddFormat2(record(recordType), tail); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("a %s record's replaced list was written: %v", recordType, err)
		}
		encoded := record(recordType).encodeFormat2(tail)
		if _, _, err := ParseEvsBatchRecordFormat2(encoded); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("a %s record's replaced list was read: %v", recordType, err)
		}
	}
	encoded := record(protocol.EvsBatchRecordType_EVS_BATCH_PART).encodeFormat2(tail)
	if _, read, err := ParseEvsBatchRecordFormat2(encoded); err != nil || !bytes.Equal(read.PurgeList, listBytes) {
		t.Errorf("a part's replaced list as read: %v", err)
	}
}
