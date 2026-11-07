// §22.5's ladder and missing-key rows, and the fixed bytes of §10.5's key hierarchy on every leg, wasm's included.
// A format change regenerates the vectors:
//
//	go test -run '^TestGkm.*Vectors$' . -args -update-gkm-vectors
//
// which is a format change, and is read as one in review. The Worker has no file system, so they are embedded.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/gkm/ladder.json
var gkmLadderVectorsJson []byte

var updateGkmVectors = flag.Bool("update-gkm-vectors", false, "rewrite testdata/gkm's ladder, wrap_aad and wrap_paths vectors")

// Writes a vector file from the host's source tree.
func writeGkmVectors(t *testing.T, path string, vectors any) {
	t.Helper()
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// 32 bytes no other vector shares.
func gkmTestBytes(label string, length int) []byte {
	digest := sha256.Sum256([]byte("gkm vector " + label))
	return bytes.Clone(digest[:length])
}

// An id no other vector shares.
func gkmTestId(label string) Id {
	return Id(gkmTestBytes(label, gkmIdByteCount))
}

// The auth pin every generation of the vectors states.
func gkmTestAuth(version uint64) *bridge.AuthPin {
	return &bridge.AuthPin{Version: version, Chain: gkmTestBytes("chain", gkmAuthChainByteCount)}
}

// The time every generation of the vectors states.
var gkmTestTime = time.UnixMilli(1767225600000)

// A test sidecar's identity key, signing as Sidecar.Sign would: signer_id the sidecar_id (CORE-M1-05).
type gkmTestSigner struct {
	sidecarId  Id
	privateKey ed25519.PrivateKey
}

// A signer whose keys come from label.
func newGkmTestSigner(label string) *gkmTestSigner {
	return &gkmTestSigner{
		sidecarId:  gkmTestId("sidecar " + label),
		privateKey: ed25519.NewKeyFromSeed(gkmTestBytes("identity "+label, ed25519.SeedSize)),
	}
}

// The GkmSignFunction.
func (self *gkmTestSigner) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// The public identity key.
func (self *gkmTestSigner) publicKey() ed25519.PublicKey {
	return self.privateKey.Public().(ed25519.PublicKey)
}

// A GkmIdentityKeyFunction that knows only this signer.
func (self *gkmTestSigner) identityKey(signerId Id) ([]byte, error) {
	if signerId != self.sidecarId {
		return nil, errors.New("not admitted")
	}
	return self.publicKey(), nil
}

// Arguments every test generation shares, with its cause.
func gkmTestArgs(cause GkmCause) *GkmGenerationArgs {
	return &GkmGenerationArgs{
		Cause:         cause,
		Auth:          gkmTestAuth(41),
		Time:          gkmTestTime,
		HoldersSha256: gkmTestBytes("holders", gkmDigestByteCount),
		WrapCount:     3,
	}
}

// gen/<g>'s object, signed and parsed back, as a reader gets it.
func gkmTestGeneration(t *testing.T, signer *gkmTestSigner, rotate *protocol.GenRotate) *GkmGeneration {
	t.Helper()
	signed, err := SignGenRotate(rotate, signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	objectBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := ParseGenRotate(objectBytes, Id(rotate.GetGroupId()), rotate.GetGeneration(), signer.identityKey)
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

// A three-generation ladder as a rotator builds it: the keys it drew and each gen/<g> as a reader parses it.
func gkmTestLadder(t *testing.T, signer *gkmTestSigner) ([]*EvsRepoKey, []*GkmGeneration) {
	t.Helper()
	repoId := gkmTestId("repo")
	groupId := gkmTestId("group")
	first, rotate, err := NewGkmFirstGeneration(repoId, groupId, gkmTestArgs(GkmCauseRequest))
	if err != nil {
		t.Fatal(err)
	}
	keys := []*EvsRepoKey{first}
	generations := []*GkmGeneration{gkmTestGeneration(t, signer, rotate)}
	for _, cause := range []GkmCause{GkmCauseRemove, GkmCauseSchedule} {
		next, rotate, err := keys[len(keys)-1].NextGeneration(gkmTestArgs(cause))
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, next)
		generations = append(generations, gkmTestGeneration(t, signer, rotate))
	}
	return keys, generations
}

// Each purpose's key of a generation, ref from RK_1, which the vectors list.
var gkmTestPurposes = []string{
	EvsKeyPurposeLink, EvsKeyPurposeFek, EvsKeyPurposeManifest, EvsKeyPurposePath, EvsKeyPurposeRef,
	EvsKeyPurposeDrop, EvsKeyPurposeIndex,
}

func TestGkmLadderOpensEveryGeneration(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)

	// A reader that got RK_3 alone, by a delivery or a GenWrap, walks down to RK_1.
	top, err := OpenEvsRepoKey(generations[2], keys[2].repoKey)
	if err != nil {
		t.Fatal(err)
	}
	if top.HoldsFirst() {
		t.Fatal("RK_3 alone holds RK_1")
	}
	walked, err := OpenGkmLadder(top, generations[:2])
	if err != nil {
		t.Fatal(err)
	}
	if len(walked) != 3 {
		t.Fatalf("%d keys", len(walked))
	}
	for index, key := range walked {
		if key.Generation() != uint64(index+1) || !key.HoldsFirst() {
			t.Fatalf("key %d: generation %d, holds RK_1 %v", index, key.Generation(), key.HoldsFirst())
		}
		if !bytes.Equal(key.repoKey, keys[index].repoKey) || !bytes.Equal(key.Commitment(), keys[index].Commitment()) {
			t.Errorf("generation %d opened another key", index+1)
		}
		if key.Cause() != keys[index].Cause() || key.Time() != keys[index].Time() || !proto.Equal(key.Auth(), keys[index].Auth()) {
			t.Errorf("generation %d lost what gen/<g> states", index+1)
		}
		for _, purpose := range gkmTestPurposes {
			derived, err := key.DeriveKey(purpose, nil)
			if err != nil {
				t.Fatal(err)
			}
			want, err := keys[index].DeriveKey(purpose, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(derived, want) {
				t.Errorf("generation %d's %s differs from its rotator's", index+1, purpose)
			}
		}
	}

	// ref is RK_1's at every generation (D-KEYS-22), and nothing else is.
	firstRef, _ := walked[0].DeriveKey(EvsKeyPurposeRef, nil)
	for _, key := range walked[1:] {
		ref, _ := key.DeriveKey(EvsKeyPurposeRef, nil)
		if !bytes.Equal(ref, firstRef) {
			t.Errorf("generation %d's ref is not RK_1's", key.Generation())
		}
		fek, _ := key.DeriveKey(EvsKeyPurposeFek, nil)
		firstFek, _ := walked[0].DeriveKey(EvsKeyPurposeFek, nil)
		if bytes.Equal(fek, firstFek) {
			t.Errorf("generation %d's fek is RK_1's", key.Generation())
		}
	}
}

// §22.5's "missing key refused": the walk never skips a generation, and nothing defaults.
func TestGkmLadderRefusesAMissingKey(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	top, err := OpenEvsRepoKey(generations[2], keys[2].repoKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenGkmLadder(top, []*GkmGeneration{generations[0], nil}); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("gen/2 missing: %v", err)
	}
	if _, err := OpenGkmLadder(top, generations[1:2]); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("one statement for two generations: %v", err)
	}
	if _, err := OpenGkmLadder(top, []*GkmGeneration{generations[1], generations[0]}); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("statements out of order: %v", err)
	}
	if _, err := OpenGkmLadder(nil, nil); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("no key: %v", err)
	}
	if _, err := top.OpenParent(nil); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("no parent statement: %v", err)
	}
	first, err := OpenEvsRepoKey(generations[0], keys[0].repoKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.OpenParent(generations[0]); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("generation 1's parent: %v", err)
	}

	// ref before the walk reaches RK_1 is refused, never derived from RK_g.
	if _, err := top.DeriveKey(EvsKeyPurposeRef, nil); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("ref without RK_1: %v", err)
	}
	if _, err := OpenEvsRepoKey(nil, keys[2].repoKey); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("a key with no statement: %v", err)
	}
	withFirst, err := top.WithFirst(first)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := withFirst.DeriveKey(EvsKeyPurposeRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := first.DeriveKey(EvsKeyPurposeRef, nil)
	if !bytes.Equal(ref, want) {
		t.Error("ref with RK_1 is not RK_1's")
	}
	if _, err := top.WithFirst(top); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("RK_3 as RK_1: %v", err)
	}
	// another ladder's RK_1 of the same repo never replaces the one a key holds, or every ref id would move
	otherKeys, _ := gkmTestLadder(t, signer)
	if _, err := withFirst.WithFirst(otherKeys[0]); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another RK_1 of the repo: %v", err)
	}
}

// An EvsRepoKey any caller can declare, or a nil one, holds no RK_g, and every use of the secret refuses it as
// missing, rather than derive public keys from an empty secret or seal nothing (§10.5's missing key; ePrint
// 2024/546).
func TestGkmKeyHoldingNoRepoKeyRefusesEveryUse(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	groupId := keys[2].GroupId()
	recipientKey := gkmTestRecipientKey(t, "reader")
	recoveryKey := gkmTestRecipientKey(t, "recovery")
	kek := gkmTestBytes("kek", gkmKekByteCount)
	var declared EvsRepoKey
	var none *EvsRepoKey
	// a generation-3 key with its parent's commitment but no RK_3, which only OpenParent's own check refuses
	keyless := &EvsRepoKey{repoId: keys[2].repoId, groupId: groupId, generation: 3, parentCommitment: keys[1].Commitment(), cause: keys[2].cause}
	if _, err := keyless.OpenParent(generations[1]); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("a generation-3 key holding no RK_3 opened its parent: %v", err)
	}

	for name, key := range map[string]*EvsRepoKey{"declared": &declared, "nil": none} {
		calls := map[string]func() error{
			"DropKeyPair": func() error { _, err := key.DropKeyPair(); return err },
			"WithFirst":   func() error { _, err := key.WithFirst(keys[0]); return err },
			"NextGeneration": func() error {
				_, _, err := key.NextGeneration(gkmTestArgs(GkmCauseRequest))
				return err
			},
			"OpenParent":    func() error { _, err := key.OpenParent(generations[0]); return err },
			"OpenGkmLadder": func() error { _, err := OpenGkmLadder(key, nil); return err },
			"SealGkmGenWrap": func() error {
				_, err := SealGkmGenWrap(key, groupId, 1, kek)
				return err
			},
			"SealGkmGroupInfo": func() error {
				_, err := SealGkmGroupInfo(key, groupId, 1, []byte("group info"))
				return err
			},
			"OpenGkmGroupInfo": func() error {
				_, err := OpenGkmGroupInfo(key, groupId, 1, make([]byte, gkmSealedKeyByteCount))
				return err
			},
			"SealGkmDelivery": func() error {
				_, err := SealGkmDelivery(key, &GkmDeliveryArgs{
					GroupId:            groupId,
					Type:               GkmWrapTypeReader,
					Recipient:          gkmTestId("reader sidecar").Bytes(),
					RecipientPublicKey: recipientKey.PublicKey().Bytes(),
					Kind:               GkmDeliveryStaged,
				})
				return err
			},
			"SealGkmRecoveryWrap": func() error {
				_, err := SealGkmRecoveryWrap(key, &GkmRecoveryArgs{
					MemberId:          gkmTestId("member"),
					GroupId:           groupId,
					RecoveryPublicKey: recoveryKey.PublicKey().Bytes(),
					BindingKeySha256:  gkmTestBytes("binding", gkmDigestByteCount),
				})
				return err
			},
		}
		for _, purpose := range gkmTestPurposes {
			calls["DeriveKey "+purpose] = func() error { _, err := key.DeriveKey(purpose, nil); return err }
		}
		calls["DeriveKey groupinfo"] = func() error {
			_, err := key.DeriveKey(EvsKeyPurposeGroupInfo, GkmGroupInfoContext(groupId, 1))
			return err
		}
		for call, run := range calls {
			if err := run(); !errors.Is(err, ErrGkmKeyMissing) {
				t.Errorf("%s key, %s: %v", name, call, err)
			}
		}
	}
}

// A key is accepted only where gen/<g>'s C_g names it, and a link only toward the parent gen/<g> names.
func TestGkmLadderRefusesAnotherCommitment(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)

	if _, err := OpenEvsRepoKey(generations[2], keys[1].repoKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("RK_2 against gen/3: %v", err)
	}
	top, err := OpenEvsRepoKey(generations[2], keys[2].repoKey)
	if err != nil {
		t.Fatal(err)
	}
	// a parent statement whose commitment is not the one gen/3 names
	otherParent := &GkmGeneration{Rotate: proto.Clone(generations[1].Rotate).(*protocol.GenRotate)}
	otherParent.Rotate.Commitment = gkmTestBytes("another commitment", gkmCommitmentByteCount)
	if _, err := top.OpenParent(otherParent); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another parent: %v", err)
	}
	// gen/1 offered as gen/2
	if _, err := top.OpenParent(generations[0]); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("gen/1 as the parent of gen/3: %v", err)
	}
	// A gen/3 whose GenLink opens the true RK_2 but whose signed parent_commitment names another parent: the
	// opened key matches gen/2's C_2, so only OpenParent's parent check keeps each generation to the one parent it
	// states (FI-4).
	forged := &GkmGeneration{Rotate: proto.Clone(generations[2].Rotate).(*protocol.GenRotate)}
	forged.Rotate.ParentCommitment = gkmTestBytes("a parent no one signed", gkmCommitmentByteCount)
	forgedTop, err := OpenEvsRepoKey(forged, keys[2].repoKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forgedTop.OpenParent(generations[1]); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("a gen/3 naming another parent walked to gen/2: %v", err)
	}
	if _, err := OpenGkmLadder(forgedTop, generations[:2]); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("the ladder walked past a gen/3 naming another parent: %v", err)
	}
}

// GenLink's AAD carries the cause §11's rewrap rule reads: a statement relabeling its cause opens no link,
// whoever signed it.
func TestGkmLadderRefusesAChangedCause(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	for _, cause := range []GkmCause{GkmCauseRequest, GkmCauseSchedule} {
		relabeled := &GkmGeneration{Rotate: proto.Clone(generations[1].Rotate).(*protocol.GenRotate)}
		relabeled.Rotate.Cause = uint32(cause)
		key, err := OpenEvsRepoKey(relabeled, keys[1].repoKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := key.OpenParent(generations[0]); !errors.Is(err, ErrGkmAuthentication) {
			t.Errorf("gen/2 relabeled %d opened its link: %v", cause, err)
		}
	}
}

// Each field of GenLink's, GenWrap's and GroupInfo's AAD, changed alone, opens nothing.
func TestGkmSealAadFieldsEachBind(t *testing.T) {
	repoId := gkmTestId("repo")
	groupId := gkmTestId("group")
	key := gkmTestBytes("seal key", gkmRepoKeyByteCount)
	plaintext := gkmTestBytes("sealed key", gkmRepoKeyByteCount)
	cases := []struct {
		name     string
		aad      []byte
		tampered []byte
	}{
		{name: "GenLink repo_id", aad: gkmGenLinkAad(repoId, 2, GkmCauseRemove), tampered: gkmGenLinkAad(gkmTestId("other repo"), 2, GkmCauseRemove)},
		{name: "GenLink g", aad: gkmGenLinkAad(repoId, 2, GkmCauseRemove), tampered: gkmGenLinkAad(repoId, 3, GkmCauseRemove)},
		{name: "GenLink cause", aad: gkmGenLinkAad(repoId, 2, GkmCauseRemove), tampered: gkmGenLinkAad(repoId, 2, GkmCauseRequest)},
		{name: "GenWrap group_id", aad: gkmKeyWrapAad(groupId, 7, 3), tampered: gkmKeyWrapAad(gkmTestId("other group"), 7, 3)},
		{name: "GenWrap e", aad: gkmKeyWrapAad(groupId, 7, 3), tampered: gkmKeyWrapAad(groupId, 8, 3)},
		{name: "GenWrap g", aad: gkmKeyWrapAad(groupId, 7, 3), tampered: gkmKeyWrapAad(groupId, 7, 2)},
		{name: "GroupInfo group_id", aad: gkmGroupInfoAad(groupId, 5), tampered: gkmGroupInfoAad(gkmTestId("other group"), 5)},
		{name: "GroupInfo e", aad: gkmGroupInfoAad(groupId, 5), tampered: gkmGroupInfoAad(groupId, 6)},
	}
	for _, c := range cases {
		sealed, err := gkmSeal(key, plaintext, c.aad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gkmOpen(key, sealed, c.aad); err != nil {
			t.Fatalf("%s: does not open as sealed: %v", c.name, err)
		}
		if _, err := gkmOpen(key, sealed, c.tampered); !errors.Is(err, ErrGkmAuthentication) {
			t.Errorf("%s changed: %v", c.name, err)
		}
	}
}

// The layouts the vectors pin, built by hand from §10.5's text.
func TestGkmLayoutsAreSection105s(t *testing.T) {
	repoId := gkmTestId("repo")
	groupId := gkmTestId("group")
	repoKey := gkmTestBytes("rk", gkmRepoKeyByteCount)

	commitment := sha256.Sum256(append(append(append([]byte("UR evs 1.0 commit"), repoId[:]...),
		0, 0, 0, 0, 0, 0, 0, 9), repoKey...))
	if !bytes.Equal(gkmCommitment(repoId, 9, repoKey), commitment[:]) {
		t.Error("C_g")
	}
	for _, purpose := range gkmTestPurposes {
		info := append([]byte("UR evs 1.0 "+purpose), 0, 0, 0, 0, 0, 0, 0, 9)
		want, err := hkdf.Key(sha256.New, repoKey, repoId[:], string(info), 32)
		if err != nil {
			t.Fatal(err)
		}
		derived, err := gkmDeriveKey(repoKey, repoId, purpose, 9, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(derived, want) {
			t.Errorf("K_%s", purpose)
		}
	}
	info := append(append([]byte("UR evs 1.0 groupinfo"), 0, 0, 0, 0, 0, 0, 0, 9), append(groupId[:], 0, 0, 0, 0, 0, 0, 0, 5)...)
	want, _ := hkdf.Key(sha256.New, repoKey, repoId[:], string(info), 32)
	derived, _ := gkmDeriveKey(repoKey, repoId, EvsKeyPurposeGroupInfo, 9, GkmGroupInfoContext(groupId, 5))
	if !bytes.Equal(derived, want) {
		t.Error("K_groupinfo")
	}

	if want := append(append(repoId[:], 0, 0, 0, 0, 0, 0, 0, 2), 1); !bytes.Equal(gkmGenLinkAad(repoId, 2, GkmCauseRemove), want) {
		t.Error("GenLink's AAD")
	}
	if want := append(append(groupId[:], 0, 0, 0, 0, 0, 0, 0, 7), 0, 0, 0, 0, 0, 0, 0, 3); !bytes.Equal(gkmKeyWrapAad(groupId, 7, 3), want) {
		t.Error("GenWrap's AAD")
	}
	if want := append(groupId[:], 0, 0, 0, 0, 0, 0, 0, 5); !bytes.Equal(gkmGroupInfoAad(groupId, 5), want) {
		t.Error("GroupInfo's AAD")
	}
	sealed, err := gkmSeal(repoKey, repoKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 72 {
		t.Errorf("a sealed key of %d bytes, §10.6 says 72", len(sealed))
	}
}

func TestGkmDeriveKeyRefusesWhatNoPurposeTakes(t *testing.T) {
	keys, _ := gkmTestLadder(t, newGkmTestSigner("rotator"))
	key := keys[1]
	if _, err := key.DeriveKey("kek", nil); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("an unknown purpose: %v", err)
	}
	if _, err := key.DeriveKey("", nil); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("no purpose: %v", err)
	}
	if _, err := key.DeriveKey(EvsKeyPurposeFek, []byte{1}); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("fek with a context: %v", err)
	}
	if _, err := key.DeriveKey(EvsKeyPurposeGroupInfo, nil); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("groupinfo without a context: %v", err)
	}
	if _, err := key.DeriveKey(EvsKeyPurposeGroupInfo, make([]byte, gkmGroupInfoContextByteCount+1)); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("groupinfo with a long context: %v", err)
	}
	first, _ := key.DeriveKey(EvsKeyPurposeGroupInfo, GkmGroupInfoContext(gkmTestId("group"), 5))
	second, _ := key.DeriveKey(EvsKeyPurposeGroupInfo, GkmGroupInfoContext(gkmTestId("group"), 6))
	if bytes.Equal(first, second) {
		t.Error("two epochs share K_groupinfo")
	}
}

func TestGkmGenWrapOpensOnlyAtItsEpoch(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	groupId := keys[2].GroupId()
	kek := gkmTestBytes("kek", gkmKekByteCount)

	genWrap, err := SealGkmGenWrap(keys[2], groupId, 7, kek)
	if err != nil {
		t.Fatal(err)
	}
	if len(genWrap) != 72 {
		t.Errorf("GenWrap of %d bytes", len(genWrap))
	}
	opened, err := OpenGkmGenWrap(generations[2], groupId, 7, kek, genWrap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.repoKey, keys[2].repoKey) {
		t.Error("another key")
	}
	if _, err := OpenGkmGenWrap(generations[2], groupId, 8, kek, genWrap); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another epoch: %v", err)
	}
	if _, err := OpenGkmGenWrap(generations[1], groupId, 7, kek, genWrap); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("against gen/2: %v", err)
	}
	if _, err := OpenGkmGenWrap(generations[2], groupId, 7, gkmTestBytes("other kek", gkmKekByteCount), genWrap); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another epoch's KEK: %v", err)
	}
	if _, err := OpenGkmGenWrap(generations[2], groupId, 7, kek[:16], genWrap); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a short KEK: %v", err)
	}
	if _, err := SealGkmGenWrap(keys[2], groupId, 7, kek[:31]); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("sealing under a short KEK: %v", err)
	}
}

func TestGkmLeafWrapOpensForItsEpochsLeaves(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	repoId := gkmTestId("repo")
	groupId := gkmTestId("group")
	kek := gkmTestBytes("kek", gkmKekByteCount)
	first, rotate, err := NewGkmFirstGeneration(repoId, groupId, gkmTestArgs(GkmCauseRequest))
	if err != nil {
		t.Fatal(err)
	}
	args := gkmTestArgs(GkmCauseRemove)
	args.LeafWrapKek = kek
	args.LeafWrapEpoch = 11
	second, rotate, err := first.NextGeneration(args)
	if err != nil {
		t.Fatal(err)
	}
	if rotate.GetLeafWrap().GetEpoch() != 11 || len(rotate.GetLeafWrap().GetCiphertext()) != 72 {
		t.Fatalf("leaf wrap %v", rotate.GetLeafWrap())
	}
	generation := gkmTestGeneration(t, signer, rotate)
	opened, err := OpenGkmLeafWrap(generation, kek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.repoKey, second.repoKey) {
		t.Error("another key")
	}
	if _, err := OpenGkmLeafWrap(generation, gkmTestBytes("another epoch's kek", gkmKekByteCount)); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another epoch's KEK: %v", err)
	}
	_, noLeafWrap, _ := second.NextGeneration(gkmTestArgs(GkmCauseRequest))
	if _, err := OpenGkmLeafWrap(gkmTestGeneration(t, signer, noLeafWrap), kek); !errors.Is(err, ErrGkmKeyMissing) {
		t.Errorf("no leaf wrap: %v", err)
	}
}

func TestGkmGroupInfoOpensOnlyForItsGroupAndEpoch(t *testing.T) {
	keys, _ := gkmTestLadder(t, newGkmTestSigner("rotator"))
	groupId := keys[1].GroupId()
	groupInfo := []byte("a GroupInfo with its ratchet_tree")
	sealed, err := SealGkmGroupInfo(keys[1], groupId, 5, groupInfo)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenGkmGroupInfo(keys[1], groupId, 5, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, groupInfo) {
		t.Error("another GroupInfo")
	}
	if _, err := OpenGkmGroupInfo(keys[1], groupId, 6, sealed); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another epoch: %v", err)
	}
	if _, err := OpenGkmGroupInfo(keys[1], gkmTestId("other group"), 5, sealed); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another group: %v", err)
	}
	if _, err := OpenGkmGroupInfo(keys[2], groupId, 5, sealed); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another generation: %v", err)
	}
}

func TestGkmDropKeyIsTheGenerationsOwn(t *testing.T) {
	repoId := gkmTestId("repo")
	args := gkmTestArgs(GkmCauseRequest)
	args.DropNotAfter = gkmTestTime.Add(90 * 24 * time.Hour)
	key, rotate, err := NewGkmFirstGeneration(repoId, gkmTestId("group"), args)
	if err != nil {
		t.Fatal(err)
	}
	dropKey, err := key.DropKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rotate.GetDropPublicKey(), dropKey.PublicKey().Bytes()) || len(rotate.GetDropPublicKey()) != 1216 {
		t.Error("the GenRotate publishes another drop key")
	}
	if rotate.GetDropNotAfterMs() != args.DropNotAfter.UnixMilli() {
		t.Errorf("drop_not_after_ms %d", rotate.GetDropNotAfterMs())
	}
	next, nextRotate, err := key.NextGeneration(gkmTestArgs(GkmCauseRequest))
	if err != nil {
		t.Fatal(err)
	}
	if len(nextRotate.GetDropPublicKey()) != 0 || nextRotate.GetDropNotAfterMs() != 0 {
		t.Error("a drop key nobody asked for")
	}
	nextDropKey, _ := next.DropKeyPair()
	if bytes.Equal(nextDropKey.PublicKey().Bytes(), dropKey.PublicKey().Bytes()) {
		t.Error("two generations share a drop key")
	}
}

func TestGkmGenerationRefusesMissingArguments(t *testing.T) {
	repoId := gkmTestId("repo")
	groupId := gkmTestId("group")
	mutations := map[string]func(args *GkmGenerationArgs){
		"no cause":       func(args *GkmGenerationArgs) { args.Cause = 0 },
		"cause 4":        func(args *GkmGenerationArgs) { args.Cause = 4 },
		"no auth":        func(args *GkmGenerationArgs) { args.Auth = nil },
		"auth at 0":      func(args *GkmGenerationArgs) { args.Auth.Version = 0 },
		"a short chain":  func(args *GkmGenerationArgs) { args.Auth.Chain = args.Auth.Chain[:31] },
		"no time":        func(args *GkmGenerationArgs) { args.Time = time.Time{} },
		"no holders":     func(args *GkmGenerationArgs) { args.HoldersSha256 = nil },
		"a short KEK":    func(args *GkmGenerationArgs) { args.LeafWrapKek = make([]byte, 16) },
		"a nil argument": nil,
	}
	for name, mutate := range mutations {
		var args *GkmGenerationArgs
		if mutate != nil {
			args = gkmTestArgs(GkmCauseRequest)
			mutate(args)
		}
		if _, _, err := NewGkmFirstGeneration(repoId, groupId, args); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Each of GenRotate's format rules, alone, refuses, and the statement it was cut from passes.
func TestGkmGenRotateFormat(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	_, generations := gkmTestLadder(t, signer)
	second := generations[1].Rotate
	first := generations[0].Rotate
	if err := checkGkmGenRotate(second); err != nil {
		t.Fatal(err)
	}
	if err := checkGkmGenRotate(first); err != nil {
		t.Fatal(err)
	}
	dropKey := gkmTestDropPublicKey(t)
	mutations := map[string]struct {
		from   *protocol.GenRotate
		mutate func(rotate *protocol.GenRotate)
	}{
		"a short group_id":   {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.GroupId = rotate.GroupId[:15] }},
		"a long repo_id":     {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.RepoId = append(rotate.RepoId, 0) }},
		"generation 0":       {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Generation = 0 }},
		"a short commitment": {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Commitment = rotate.Commitment[:8] }},
		"no parent at 2":     {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.ParentCommitment = nil }},
		"no GenLink at 2":    {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Genlink = nil }},
		"a short GenLink":    {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Genlink = rotate.Genlink[:71] }},
		"a parent at 1":      {from: first, mutate: func(rotate *protocol.GenRotate) { rotate.ParentCommitment = second.GetCommitment() }},
		"a GenLink at 1":     {from: first, mutate: func(rotate *protocol.GenRotate) { rotate.Genlink = second.GetGenlink() }},
		"cause 0":            {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Cause = 0 }},
		"cause 4":            {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Cause = 4 }},
		"no auth":            {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Auth = nil }},
		"auth at 0":          {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Auth.Version = 0 }},
		"a short chain":      {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.Auth.Chain = rotate.Auth.Chain[:31] }},
		"no time":            {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.TimeMs = 0 }},
		"no holders hash":    {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.HoldersSha256 = nil }},
		"a short leaf wrap": {from: second, mutate: func(rotate *protocol.GenRotate) {
			rotate.LeafWrap = &protocol.LeafWrap{Epoch: 1, Ciphertext: make([]byte, 71)}
		}},
		"a drop expiry with no drop key": {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.DropNotAfterMs = 1 }},
		"a drop key with no expiry":      {from: second, mutate: func(rotate *protocol.GenRotate) { rotate.DropPublicKey = dropKey }},
		"a short drop key": {from: second, mutate: func(rotate *protocol.GenRotate) {
			rotate.DropPublicKey = dropKey[:1215]
			rotate.DropNotAfterMs = 1
		}},
	}
	for name, mutation := range mutations {
		rotate := proto.Clone(mutation.from).(*protocol.GenRotate)
		mutation.mutate(rotate)
		if err := checkGkmGenRotate(rotate); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := SignGenRotate(rotate, signer.sign); !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("%s signed: %v", name, err)
		}
	}
	withDrop := proto.Clone(second).(*protocol.GenRotate)
	withDrop.DropPublicKey = dropKey
	withDrop.DropNotAfterMs = 1
	if err := checkGkmGenRotate(withDrop); err != nil {
		t.Errorf("a drop key with its expiry: %v", err)
	}
}

// A drop public key, as a GenRotate carries one.
func gkmTestDropPublicKey(t *testing.T) []byte {
	t.Helper()
	args := gkmTestArgs(GkmCauseRequest)
	args.DropNotAfter = gkmTestTime.Add(time.Hour)
	_, rotate, err := NewGkmFirstGeneration(gkmTestId("drop repo"), gkmTestId("drop group"), args)
	if err != nil {
		t.Fatal(err)
	}
	return rotate.GetDropPublicKey()
}

func TestParseGenRotateRefusesWhatItCannotVerify(t *testing.T) {
	signer := newGkmTestSigner("rotator")
	keys, generations := gkmTestLadder(t, signer)
	groupId := keys[0].GroupId()
	objectBytes, err := proto.Marshal(generations[1].Signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGenRotate(objectBytes, groupId, 2, signer.identityKey); err != nil {
		t.Fatal(err)
	}

	other := newGkmTestSigner("someone else")
	otherKey := func(signerId Id) ([]byte, error) { return other.publicKey(), nil }
	if _, err := ParseGenRotate(objectBytes, groupId, 2, otherKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another key: %v", err)
	}
	if _, err := ParseGenRotate(objectBytes, groupId, 2, other.identityKey); err == nil {
		t.Error("a signer the state does not admit")
	}
	if _, err := ParseGenRotate(objectBytes, gkmTestId("other group"), 2, signer.identityKey); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("another group's key: %v", err)
	}
	if _, err := ParseGenRotate(objectBytes, groupId, 3, signer.identityKey); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("another generation's key: %v", err)
	}
	if _, err := ParseGenRotate([]byte{0xff}, groupId, 2, signer.identityKey); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("not a Signed: %v", err)
	}

	mutate := func(change func(signed *bridge.Signed)) []byte {
		signed := proto.Clone(generations[1].Signed).(*bridge.Signed)
		change(signed)
		encoded, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	refusals := map[string][]byte{
		"a changed body":      mutate(func(signed *bridge.Signed) { signed.Body[len(signed.Body)-1] ^= 1 }),
		"another type":        mutate(func(signed *bridge.Signed) { signed.Type = uint32(bridge.SignedType_SIGNED_GROUP_FORM) }),
		"no signer":           mutate(func(signed *bridge.Signed) { signed.SignerId = nil }),
		"a changed signature": mutate(func(signed *bridge.Signed) { signed.Signature[0] ^= 1 }),
	}
	for name, encoded := range refusals {
		if _, err := ParseGenRotate(encoded, groupId, 2, signer.identityKey); err == nil {
			t.Errorf("%s passed", name)
		}
	}

	// signed under another purpose, the type gen-rotate's
	body := generations[1].Signed.GetBody()
	misPurposed := &bridge.Signed{
		Body:      body,
		SignerId:  signer.sidecarId.Bytes(),
		Signature: ed25519.Sign(signer.privateKey, bridge.SignedBytes("reader-wrap", bridge.SignedType_SIGNED_GEN_ROTATE, body)),
		Type:      uint32(bridge.SignedType_SIGNED_GEN_ROTATE),
	}
	encoded, _ := proto.Marshal(misPurposed)
	if _, err := ParseGenRotate(encoded, groupId, 2, signer.identityKey); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("another purpose: %v", err)
	}
}

// What testdata/gkm/ladder.json holds.
type gkmLadderVectors struct {
	RepoId      hexBytes                    `json:"repo_id"`
	GroupId     hexBytes                    `json:"group_id"`
	Generations []gkmLadderGenerationVector `json:"generations"`
	GenWrap     gkmKeyWrapVector            `json:"gen_wrap"`
	LeafWrap    gkmKeyWrapVector            `json:"leaf_wrap"`
	GroupInfo   gkmGroupInfoVector          `json:"group_info"`
}

// One generation: its key, commitment, every purpose's key and, from generation 2, its GenLink.
type gkmLadderGenerationVector struct {
	Generation       uint64              `json:"generation"`
	Cause            GkmCause            `json:"cause"`
	RepoKey          hexBytes            `json:"repo_key"`
	Commitment       hexBytes            `json:"commitment"`
	Keys             map[string]hexBytes `json:"keys"`
	DropPublicSha256 hexBytes            `json:"drop_public_key_sha256"`
	GenLinkNonce     hexBytes            `json:"genlink_nonce,omitempty"`
	GenLinkAad       hexBytes            `json:"genlink_aad,omitempty"`
	GenLink          hexBytes            `json:"genlink,omitempty"`
}

// A GenWrap or LeafWrap: one generation's key under an epoch's KEK.
type gkmKeyWrapVector struct {
	Kek        hexBytes `json:"kek"`
	Epoch      uint64   `json:"epoch"`
	Generation uint64   `json:"generation"`
	Nonce      hexBytes `json:"nonce"`
	Aad        hexBytes `json:"aad"`
	Sealed     hexBytes `json:"sealed"`
}

// A sealed GroupInfo.
type gkmGroupInfoVector struct {
	Generation uint64   `json:"generation"`
	Epoch      uint64   `json:"epoch"`
	Key        hexBytes `json:"key"`
	Nonce      hexBytes `json:"nonce"`
	Aad        hexBytes `json:"aad"`
	Plaintext  hexBytes `json:"plaintext"`
	Sealed     hexBytes `json:"sealed"`
}

// A gen/<g> statement for vectors, unsigned: what OpenEvsRepoKey and OpenParent read of one.
func gkmVectorRotate(repoId Id, groupId Id, generation uint64, cause GkmCause, repoKey []byte, parentCommitment []byte, genLink []byte) *GkmGeneration {
	return &GkmGeneration{Rotate: &protocol.GenRotate{
		GroupId:          groupId.Bytes(),
		RepoId:           repoId.Bytes(),
		Generation:       generation,
		ParentCommitment: parentCommitment,
		Commitment:       gkmCommitment(repoId, generation, repoKey),
		Cause:            uint32(cause),
		Auth:             gkmTestAuth(41),
		TimeMs:           gkmTestTime.UnixMilli(),
		HoldersSha256:    gkmTestBytes("holders", gkmDigestByteCount),
		Genlink:          genLink,
	}}
}

// The ladder vectors, computed from their fixed inputs by this build.
func computeGkmLadderVectors(t *testing.T) *gkmLadderVectors {
	t.Helper()
	repoId := gkmTestId("repo")
	groupId := gkmTestId("group")
	vectors := &gkmLadderVectors{RepoId: repoId.Bytes(), GroupId: groupId.Bytes()}
	causes := []GkmCause{GkmCauseRequest, GkmCauseRemove, GkmCauseSchedule}
	var repoKeys [][]byte
	for index, cause := range causes {
		generation := uint64(index + 1)
		repoKey := gkmTestBytes("RK_"+strconv.FormatUint(generation, 10), gkmRepoKeyByteCount)
		repoKeys = append(repoKeys, repoKey)
		vector := gkmLadderGenerationVector{
			Generation: generation,
			Cause:      cause,
			RepoKey:    repoKey,
			Commitment: gkmCommitment(repoId, generation, repoKey),
			Keys:       map[string]hexBytes{},
		}
		for _, purpose := range gkmTestPurposes {
			secret, keyGeneration := repoKey, generation
			if purpose == EvsKeyPurposeRef {
				secret, keyGeneration = repoKeys[0], 1
			}
			derived, err := gkmDeriveKey(secret, repoId, purpose, keyGeneration, nil)
			if err != nil {
				t.Fatal(err)
			}
			vector.Keys[purpose] = derived
		}
		key := &EvsRepoKey{repoId: repoId, generation: generation, repoKey: repoKey}
		dropKey, err := key.DropKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		dropPublicSha256 := sha256.Sum256(dropKey.PublicKey().Bytes())
		vector.DropPublicSha256 = dropPublicSha256[:]
		if 1 < generation {
			vector.GenLinkNonce = gkmTestBytes("genlink nonce "+strconv.FormatUint(generation, 10), 24)
			vector.GenLinkAad = gkmGenLinkAad(repoId, generation, cause)
			genLink, err := gkmSealWithNonce(vector.Keys[EvsKeyPurposeLink], vector.GenLinkNonce, repoKeys[index-1], vector.GenLinkAad)
			if err != nil {
				t.Fatal(err)
			}
			vector.GenLink = genLink
		}
		vectors.Generations = append(vectors.Generations, vector)
	}

	keyWrap := func(label string, epoch uint64, generation uint64) gkmKeyWrapVector {
		vector := gkmKeyWrapVector{
			Kek:        gkmTestBytes(label+" kek", gkmKekByteCount),
			Epoch:      epoch,
			Generation: generation,
			Nonce:      gkmTestBytes(label+" nonce", 24),
			Aad:        gkmKeyWrapAad(groupId, epoch, generation),
		}
		sealed, err := gkmSealWithNonce(vector.Kek, vector.Nonce, repoKeys[generation-1], vector.Aad)
		if err != nil {
			t.Fatal(err)
		}
		vector.Sealed = sealed
		return vector
	}
	vectors.GenWrap = keyWrap("genwrap", 7, 3)
	vectors.LeafWrap = keyWrap("leafwrap", 8, 2)

	groupInfoKey, err := gkmDeriveKey(repoKeys[1], repoId, EvsKeyPurposeGroupInfo, 2, GkmGroupInfoContext(groupId, 5))
	if err != nil {
		t.Fatal(err)
	}
	vectors.GroupInfo = gkmGroupInfoVector{
		Generation: 2,
		Epoch:      5,
		Key:        groupInfoKey,
		Nonce:      gkmTestBytes("groupinfo nonce", 24),
		Aad:        gkmGroupInfoAad(groupId, 5),
		Plaintext:  []byte("a GroupInfo with its ratchet_tree, as MLS encodes one"),
	}
	sealed, err := gkmSealWithNonce(groupInfoKey, vectors.GroupInfo.Nonce, vectors.GroupInfo.Plaintext, vectors.GroupInfo.Aad)
	if err != nil {
		t.Fatal(err)
	}
	vectors.GroupInfo.Sealed = sealed
	return vectors
}

// The ladder's bytes, equal on this leg to the file, and every sealed value opening through the exported calls.
func TestGkmLadderVectors(t *testing.T) {
	computed := computeGkmLadderVectors(t)
	if *updateGkmVectors {
		writeGkmVectors(t, "testdata/gkm/ladder.json", computed)
		return
	}
	stored := &gkmLadderVectors{}
	if err := json.Unmarshal(gkmLadderVectorsJson, stored); err != nil {
		t.Fatal(err)
	}
	computedJson, _ := json.Marshal(computed)
	storedJson, _ := json.Marshal(stored)
	if !bytes.Equal(computedJson, storedJson) {
		t.Fatalf("this build's ladder differs from testdata/gkm/ladder.json:\n%s\n%s", computedJson, storedJson)
	}

	repoId := Id(stored.RepoId)
	groupId := Id(stored.GroupId)
	var generations []*GkmGeneration
	for _, vector := range stored.Generations {
		var parentCommitment []byte
		if 1 < vector.Generation {
			parentCommitment = stored.Generations[vector.Generation-2].Commitment
		}
		generations = append(generations, gkmVectorRotate(repoId, groupId, vector.Generation, vector.Cause, vector.RepoKey, parentCommitment, vector.GenLink))
	}
	top, err := OpenEvsRepoKey(generations[2], stored.Generations[2].RepoKey)
	if err != nil {
		t.Fatal(err)
	}
	walked, err := OpenGkmLadder(top, generations[:2])
	if err != nil {
		t.Fatal(err)
	}
	for index, key := range walked {
		if !bytes.Equal(key.repoKey, stored.Generations[index].RepoKey) {
			t.Errorf("the walk opened another RK_%d", index+1)
		}
		for purpose, want := range stored.Generations[index].Keys {
			derived, err := key.DeriveKey(purpose, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(derived, want) {
				t.Errorf("generation %d's %s", index+1, purpose)
			}
		}
	}
	genWrap := stored.GenWrap
	opened, err := OpenGkmGenWrap(generations[genWrap.Generation-1], groupId, genWrap.Epoch, genWrap.Kek, genWrap.Sealed)
	if err != nil || !bytes.Equal(opened.repoKey, stored.Generations[genWrap.Generation-1].RepoKey) {
		t.Errorf("GenWrap: %v", err)
	}
	leafWrap := stored.LeafWrap
	generations[leafWrap.Generation-1].Rotate.LeafWrap = &protocol.LeafWrap{Epoch: leafWrap.Epoch, Ciphertext: leafWrap.Sealed}
	opened, err = OpenGkmLeafWrap(generations[leafWrap.Generation-1], leafWrap.Kek)
	if err != nil || !bytes.Equal(opened.repoKey, stored.Generations[leafWrap.Generation-1].RepoKey) {
		t.Errorf("LeafWrap: %v", err)
	}
	groupInfo, err := OpenGkmGroupInfo(walked[stored.GroupInfo.Generation-1], groupId, stored.GroupInfo.Epoch, stored.GroupInfo.Sealed)
	if err != nil || !bytes.Equal(groupInfo, stored.GroupInfo.Plaintext) {
		t.Errorf("GroupInfo: %v", err)
	}
}

// The vector inputs' u64be fields, as the file writes them: a reader of the JSON need not know Go.
func TestGkmLadderVectorsSpellTheirIntegers(t *testing.T) {
	stored := &gkmLadderVectors{}
	if err := json.Unmarshal(gkmLadderVectorsJson, stored); err != nil {
		t.Fatal(err)
	}
	for _, vector := range stored.Generations[1:] {
		aad := vector.GenLinkAad
		if len(aad) != 25 || binary.BigEndian.Uint64(aad[16:24]) != vector.Generation || GkmCause(aad[24]) != vector.Cause {
			t.Errorf("generation %d's GenLink AAD %x", vector.Generation, aad)
		}
	}
}
