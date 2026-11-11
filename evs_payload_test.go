// EVS1-M2-48's payload rows (DESIGN-DETAILS 8.2.2): changeless parts after the parts with changes, under a root
// over those alone; a creating push's sections 15 and 16 held to their shape; a gitlink's empty chain taken by the
// checks and read back by its oid, and an empty chain under any other mode refused by the reader; and the ref name's
// seal under its own AAD.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A plan of changeCount changes whose sealed metadata passes what the parts' room beside them holds.
func evsTestChangelessPlan(t testing.TB, signer *evsTestSigner, changeCount int, metadataByteCount int) *EvsPushPlan {
	plan := evsTestPlan(t, signer, "changeless", changeCount)
	plan.SealedMetadata = bytes.Repeat([]byte{0x5a}, metadataByteCount)
	return plan
}

// DESIGN-DETAILS 8.4's 2,000 commits on 30 files: sealed metadata past one part beside the changes goes in changeless
// parts after them, which carry no changes_root and are no leaf of the root; the seal takes them, and each change's
// proof reaches the statement's root through a tree of the parts with changes.
func TestEvsChangelessPartsFollowTheChanges(t *testing.T) {
	signer := newEvsTestSigner("writer")
	built, checked := evsTestBuildAndCheck(t, signer, evsTestChangelessPlan(t, signer, 30, 1536*1024))
	push := built.Statement.Push
	if push.GetPartCount() != 2 || len(built.Parts) != 2 || len(checked.Changes) != 30 {
		t.Fatalf("%d parts, %d changes", push.GetPartCount(), len(checked.Changes))
	}
	if len(checked.SealedMetadata) != 1536*1024 {
		t.Errorf("sealed metadata of %d bytes joined", len(checked.SealedMetadata))
	}
	first, err := EvsCheckPart(built.Statement, built.Parts[0])
	if err != nil {
		t.Fatal(err)
	}
	last, err := EvsCheckPart(built.Statement, built.Parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if !first.HoldsChanges() || last.HoldsChanges() || last.FirstTokenPath() != nil || last.Root != ([sha256.Size]byte{}) {
		t.Fatalf("the parts: first holds changes %t, last %t", first.HoldsChanges(), last.HoldsChanges())
	}
	if built.ChangeTree.PartCount() != 1 {
		t.Errorf("a root over %d parts", built.ChangeTree.PartCount())
	}
	for index := range checked.Changes {
		proofs, err := built.ChangeTree.InclusionProof(0, index)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := EvsVerifyChangeInclusion(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), proofs); err != nil {
			t.Errorf("change %d: %v", index, err)
		}
	}
	// a path past every change, whose absence the last change's all-right path proves
	beyond := EvsTokenPath{EvsToken(bytes.Repeat([]byte{0xff}, EvsTokenByteCount))}
	absence, err := built.ChangeTree.AbsenceProof(beyond)
	if err != nil {
		t.Fatal(err)
	}
	if err := EvsVerifyChangeAbsence(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), beyond, absence); err != nil {
		t.Errorf("the absence past the last change: %v", err)
	}
	// a part-level size past the signed part count is refused
	tooMany := proto.Clone(absence).(*protocol.EvsAbsenceProof)
	tooMany.Below[1].Size = uint64(push.GetPartCount()) + 1
	if EvsVerifyChangeAbsence(push.GetChangesRoot(), push.GetPartCount(), uint64(push.GetChangeCount()), beyond, tooMany) == nil {
		t.Error("a part tree claimed past part_count verified")
	}
}

// One change beside sections past 1 MiB still goes in parts: its part, and changeless ones after it.
func TestEvsOneChangeWithLargeSectionsGoesInParts(t *testing.T) {
	signer := newEvsTestSigner("writer")
	built, checked := evsTestBuildAndCheck(t, signer, evsTestChangelessPlan(t, signer, 1, 2500*1024))
	if built.Statement.Push.GetPartCount() != 3 || len(checked.Changes) != 1 {
		t.Fatalf("%d parts, %d changes", built.Statement.Push.GetPartCount(), len(checked.Changes))
	}
}

// A push with no change has no root a statement can state, so one past 1 MiB has no shape and is refused before
// anything is signed.
func TestEvsPushPastOneMiBWithNoChangeIsRefused(t *testing.T) {
	signer := newEvsTestSigner("writer")
	plan := evsTestChangelessPlan(t, signer, 0, 1536*1024)
	if _, err := NewEvsStatementBuilder(signer.sign).Build(plan); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a push past 1 MiB with no change: %v", err)
	}
}

// Signs push's statement again after a test changed it, as the builder would.
func evsTestResign(t testing.TB, signer *evsTestSigner, push *protocol.EvsPush) *EvsStatement {
	t.Helper()
	statement, err := NewEvsStatementBuilder(signer.sign).signStatement(push)
	if err != nil {
		t.Fatal(err)
	}
	return statement
}

// A part with no change that holds no slice, one naming a root or an entry, and a seal whose changeless part comes
// before a part with a change are each refused.
func TestEvsChangelessPartsAreHeldToTheirPlace(t *testing.T) {
	signer := newEvsTestSigner("writer")
	built, _ := evsTestBuildAndCheck(t, signer, evsTestChangelessPlan(t, signer, 30, 1536*1024))
	part := func(index int) *protocol.EvsPushPart {
		message := &protocol.EvsPushPart{}
		if err := proto.Unmarshal(built.Parts[index], message); err != nil {
			t.Fatal(err)
		}
		return message
	}
	encode := func(message *protocol.EvsPushPart) []byte {
		partBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		return partBytes
	}
	empty := part(1)
	empty.SealedMetadata = nil
	empty.Sections = nil
	if _, err := EvsCheckPart(built.Statement, encode(empty)); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a part with neither a change nor a slice: %v", err)
	}
	rooted := part(1)
	rooted.ChangesRoot = bytes.Repeat([]byte{1}, sha256.Size)
	if _, err := EvsCheckPart(built.Statement, encode(rooted)); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a changeless part naming a root: %v", err)
	}

	// the changeless part first, the changes second, under a statement signed over that order
	swappedFirst, swappedSecond := part(1), part(0)
	swappedFirst.Part, swappedSecond.Part = 1, 2
	parts := [][]byte{encode(swappedFirst), encode(swappedSecond)}
	partHashes := []byte{}
	for _, partBytes := range parts {
		digest := sha256.Sum256(partBytes)
		partHashes = append(partHashes, digest[:]...)
	}
	push := proto.Clone(built.Statement.Push).(*protocol.EvsPush)
	partsDigest := sha256.Sum256(partHashes)
	push.PartsSha256 = partsDigest[:]
	statement := evsTestResign(t, signer, push)
	if _, _, err := EvsCheckSeal(statement, parts); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a changeless part before a part with a change: %v", err)
	}
}

// A seal record names a changeless part by its place alone, and a part whose first change is the root by an empty
// token path; both parse back.
func TestEvsSealRecordNamesChangelessPartsAndTheRoot(t *testing.T) {
	parts := []*EvsSealPart{
		{Place: &protocol.EvsPlace{Minute: 1, Seq: 2, Length: 30}, ChangesRoot: [sha256.Size]byte{7}, FirstTokenPath: EvsTokenPath{}},
		{Place: &protocol.EvsPlace{Minute: 1, Seq: 3, Length: 40}, ChangesRoot: [sha256.Size]byte{8}, FirstTokenPath: EvsTokenPath{evsTestToken("a")}},
		{Place: &protocol.EvsPlace{Minute: 1, Seq: 4, Length: 50}, Changeless: true},
	}
	statement, parsed, err := ParseEvsSealRecordBody(EvsSealRecordBody([]byte("statement"), parts))
	if err != nil {
		t.Fatal(err)
	}
	if string(statement) != "statement" || len(parsed) != 3 || parsed[0].Changeless || len(parsed[0].FirstTokenPath) != 0 ||
		!parsed[1].FirstTokenPath.Equal(parts[1].FirstTokenPath) || !parsed[2].Changeless || parsed[2].Place.GetSeq() != 4 {
		t.Errorf("parsed %+v", parsed)
	}
	// a part with a change after a changeless one has no place in a record
	if _, _, err := ParseEvsSealRecordBody(EvsSealRecordBody([]byte("statement"), []*EvsSealPart{parts[2], parts[1]})); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a changeless part first: %v", err)
	}
}

// Sections 15 and 16 ride whole in a one-part push and as slices in parts, and come back from the checks as the
// sealed ref name's bytes and the base; a base naming the ref itself or no version, and a sealed name too short to be
// sealed, are refused.
func TestEvsCreatingSectionsKeepTheirShape(t *testing.T) {
	signer := newEvsTestSigner("writer")
	base := &protocol.EvsOverlay{RefId: evsTestId("ref base").Bytes(), Version: 4}
	sealedName := evsTestBytes("sealed ref name", 32)
	sealedName = append(sealedName, evsTestBytes("sealed ref name tail", 24)...)
	for _, changeCount := range []int{2, 1100} {
		plan := evsTestPlan(t, signer, "creating", changeCount)
		plan.RefMode = protocol.EvsRefMode_EVS_REF_GIT
		plan.RefName = sealedName
		plan.Base = base
		_, checked := evsTestBuildAndCheck(t, signer, plan)
		if !bytes.Equal(checked.RefName, sealedName) || !proto.Equal(checked.Base, base) {
			t.Errorf("%d changes: the sections came back as %x and %v", changeCount, checked.RefName, checked.Base)
		}
	}
	refused := map[string]func(plan *EvsPushPlan){
		"a base of the ref itself":  func(plan *EvsPushPlan) { plan.Base = &protocol.EvsOverlay{RefId: plan.RefId.Bytes(), Version: 4} },
		"a base at version 0":       func(plan *EvsPushPlan) { plan.Base = &protocol.EvsOverlay{RefId: base.GetRefId()} },
		"a base of a short ref id":  func(plan *EvsPushPlan) { plan.Base = &protocol.EvsOverlay{RefId: []byte("short"), Version: 4} },
		"a sealed name of 10 bytes": func(plan *EvsPushPlan) { plan.RefName = []byte("ten bytes!") },
	}
	for label, mutate := range refused {
		plan := evsTestPlan(t, signer, "creating", 2)
		plan.RefMode = protocol.EvsRefMode_EVS_REF_GIT
		mutate(plan)
		built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EvsCheckPayload(built.Statement, built.Payload); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// A ref name seals under "UR evs 1.0 ref name" || repo_id || ref_id, opens only under that ref's AAD, and is held
// to git's bound.
func TestEvsRefNameSealsUnderItsRef(t *testing.T) {
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	refId := evsTestId("ref feature")
	sealed, err := EvsSealRefName(keys.manifest, refId, []byte("feature/x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != len("feature/x")+evsSealOverhead {
		t.Errorf("a sealed name of %d bytes", len(sealed))
	}
	name, err := EvsOpenRefName(keys.manifest, refId, sealed)
	if err != nil || string(name) != "feature/x" {
		t.Errorf("opened %q: %v", name, err)
	}
	if _, err := EvsOpenRefName(keys.manifest, evsTestId("ref other"), sealed); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("opened under another ref: %v", err)
	}
	if _, err := EvsSealRefName(keys.manifest, refId, bytes.Repeat([]byte("n"), EvsRefNameMaxByteCount+1)); !errors.Is(err, ErrEvsRefNameInvalid) {
		t.Errorf("a name past the bound: %v", err)
	}
}

// DESIGN-DETAILS 8.2.2's gitlink row: a file entry with an empty chain passes the checks, which cannot see its mode,
// and reads back as a gitlink, its oid the linked commit's and no content; under any other mode a reader refuses it
// and alarms tamper.
func TestEvsGitlinkEntryReadsBackAndAnEmptyChainOtherwiseIsRefused(t *testing.T) {
	world := newEvsTestWorld(t)
	linked := EvsGitOid(evsTestBytes("linked commit", 20))
	gitlinkEntry := func(mode uint32, size uint64) func(pushId Id, baseVersion uint64, version uint64) []byte {
		return func(pushId Id, baseVersion uint64, version uint64) []byte {
			keys := evsTestKeys(t, world.repoId, world.generation)
			sealedFields, err := EvsSealFields(keys.manifest, &protocol.EvsSealedFields{
				FileId: evsTestId("gitlink file").Bytes(), Mode: mode, GitOid: linked[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: size,
			})
			if err != nil {
				t.Fatal(err)
			}
			entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsEntryVersion{
				Version: version, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: 1767225600000,
				Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedFields: sealedFields,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := checkEvsEntryVersion(entryBytes, &protocol.EvsPush{PushId: pushId.Bytes(), BaseVersion: baseVersion}); err != nil {
				t.Fatalf("the checks refused an empty chain: %v", err)
			}
			return entryBytes
		}
	}
	world.pushEntry("vendor/lib", gitlinkEntry(EvsGitModeGitlink, 0))
	reader := world.reader(t, evsTestId("reader"))
	content, info, err := evsTestRead(t, reader, world, "vendor/lib")
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 || info.Mode != EvsGitModeGitlink || info.GitOid != linked || info.Size != 0 {
		t.Errorf("the gitlink read as %d bytes, mode %o, oid %s", len(content), info.Mode, info.GitOid)
	}

	tampered := newEvsTestWorld(t)
	world = tampered
	tampered.pushEntry("file", gitlinkEntry(EvsGitModeFile, 0))
	reader = tampered.reader(t, evsTestId("reader"))
	if _, _, err := evsTestRead(t, reader, tampered, "file"); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("an empty chain under mode 100644: %v", err)
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 1 || alarms[0].EvsAlarm != SidecarEvsAlarmTamper {
		t.Errorf("alarms %v", alarms)
	}
}
