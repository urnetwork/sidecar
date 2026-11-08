// Welcome, GroupInfo and the two-phase join (KEYS-M2-07): the mlswg's welcome and messages vectors under 0x0001,
// a join through gkm's GenWrap and sealed GroupInfo, and a forged GroupInfo over a valid Welcome refused before
// RK_g is trusted.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// What a vector's Welcome joins under: its KeyPackage and private keys.
func mlsTestVectorHeld(t *testing.T, suite *mlsCipherSuite, encodedKeyPackage []byte, initPriv []byte, encryptionPriv []byte, signaturePriv []byte) *mlsHeldKeyPackage {
	t.Helper()
	keyPackage := &mlsKeyPackage{}
	if err := mlsUnmarshalMessageOf(encodedKeyPackage, mlsWireFormatKeyPackage, keyPackage); err != nil {
		t.Fatal(err)
	}
	ref, err := keyPackage.ref(suite)
	if err != nil {
		t.Fatal(err)
	}
	held := &mlsHeldKeyPackage{keyPackage: keyPackage, encoded: encodedKeyPackage, ref: ref}
	if held.initKey, err = suite.loadKemKey("test", initPriv); err != nil {
		t.Fatal(err)
	}
	if encryptionPriv != nil {
		if held.leafKey, err = suite.loadKemKey("test", encryptionPriv); err != nil {
			t.Fatal(err)
		}
	}
	if signaturePriv != nil {
		if held.signatureKey, err = suite.loadSignatureKey("test", signaturePriv); err != nil {
			t.Fatal(err)
		}
	}
	return held
}

// welcome.json under 0x0001: the group secrets open under the init key, the GroupInfo under welcome_secret, its
// confirmation tag holds against the epoch joiner_secret derives, and its signature against the signer's key.
func TestMlsWelcomeVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite uint16      `json:"cipher_suite"`
		InitPriv    mlsHexBytes `json:"init_priv"`
		SignerPub   mlsHexBytes `json:"signer_pub"`
		KeyPackage  mlsHexBytes `json:"key_package"`
		Welcome     mlsHexBytes `json:"welcome"`
	}
	mlsLoadVectors(t, "welcome", &vectors)
	suite := mlsTestSuiteX25519
	ran := 0
	for index, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		ran += 1
		held := mlsTestVectorHeld(t, suite, vector.KeyPackage, vector.InitPriv, nil, nil)
		welcome := &mlsWelcome{}
		if err := mlsUnmarshalMessageOf(vector.Welcome, mlsWireFormatWelcome, welcome); err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		opened, err := openMlsWelcome(suite, welcome, held)
		if err != nil {
			t.Fatalf("vector %d: %v", index, err)
		}
		if err := opened.groupInfo.verify(suite, vector.SignerPub); err != nil {
			t.Errorf("vector %d: %v", index, err)
		}
		reencoded, err := mlsMarshalMessageOf(mlsWireFormatWelcome, welcome)
		if err != nil || !bytes.Equal(reencoded, vector.Welcome) {
			t.Errorf("vector %d: the Welcome re-encoded differently: %v", index, err)
		}

		// another init key opens nothing, and a Welcome to no KeyPackage of this sidecar names none
		other, err := suite.generateKemKey("test")
		if err != nil {
			t.Fatal(err)
		}
		wrongKey := *held
		wrongKey.initKey = other
		if _, err := openMlsWelcome(suite, welcome, &wrongKey); !errors.Is(err, errMlsAuthentication) {
			t.Errorf("vector %d: another init key: %v", index, err)
		}
		wrongRef := *held
		wrongRef.ref = bytes.Repeat([]byte{1}, len(held.ref))
		if _, err := openMlsWelcome(suite, welcome, &wrongRef); !errors.Is(err, errMlsWelcomeNotOurs) {
			t.Errorf("vector %d: another ref: %v", index, err)
		}
	}
	if ran == 0 {
		t.Fatal("no 0x0001 vector")
	}
}

// messages.json's Welcomes, GroupInfos and GroupSecrets re-encode byte for byte, or, for group secrets naming a
// PSK, are refused when parsed (§10.4).
func TestMlsMessagesWelcomeVectors(t *testing.T) {
	var vectors []struct {
		Welcome      mlsHexBytes `json:"mls_welcome"`
		GroupInfo    mlsHexBytes `json:"mls_group_info"`
		GroupSecrets mlsHexBytes `json:"group_secrets"`
	}
	mlsLoadVectors(t, "messages", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	roundTrips, pskRefusals := 0, 0
	for index, vector := range vectors {
		welcome := &mlsWelcome{}
		if err := mlsUnmarshalMessageOf(vector.Welcome, mlsWireFormatWelcome, welcome); err != nil {
			t.Errorf("vector %d: Welcome: %v", index, err)
		} else if reencoded, err := mlsMarshalMessageOf(mlsWireFormatWelcome, welcome); err != nil || !bytes.Equal(reencoded, vector.Welcome) {
			t.Errorf("vector %d: the Welcome re-encoded differently: %v", index, err)
		}

		groupInfo := &mlsGroupInfo{}
		if err := mlsUnmarshalMessageOf(vector.GroupInfo, mlsWireFormatGroupInfo, groupInfo); err != nil {
			t.Errorf("vector %d: GroupInfo: %v", index, err)
		} else if reencoded, err := mlsMarshalMessageOf(mlsWireFormatGroupInfo, groupInfo); err != nil || !bytes.Equal(reencoded, vector.GroupInfo) {
			t.Errorf("vector %d: the GroupInfo re-encoded differently: %v", index, err)
		}

		// the syntax through a reader that keeps the PSK list raw, then the production parse, which refuses one
		permissive := &mlsTestGroupSecrets{}
		if err := mlsUnmarshal(vector.GroupSecrets, permissive); err != nil {
			t.Errorf("vector %d: GroupSecrets: %v", index, err)
		} else if reencoded, err := mlsMarshal(permissive); err != nil || !bytes.Equal(reencoded, vector.GroupSecrets) {
			t.Errorf("vector %d: the GroupSecrets re-encoded differently: %v", index, err)
		} else {
			roundTrips += 1
		}
		groupSecrets := &mlsGroupSecrets{}
		err := mlsUnmarshal(vector.GroupSecrets, groupSecrets)
		switch {
		case len(permissive.psks) != 0 && errors.Is(err, errMlsRefused):
			pskRefusals += 1
		case len(permissive.psks) != 0:
			t.Errorf("vector %d: group secrets naming a PSK: %v", index, err)
		case err != nil:
			t.Errorf("vector %d: GroupSecrets: %v", index, err)
		}

		// none of them reads as a commit
		for _, encoded := range [][]byte{vector.Welcome, vector.GroupInfo} {
			if _, err := ParseMlsHeader(encoded); err == nil {
				t.Errorf("vector %d: gkm read a Welcome or GroupInfo as a commit", index)
			}
		}
	}
	t.Logf("group secrets: %d round trips, %d refused for a PSK", roundTrips, pskRefusals)
	if roundTrips == 0 {
		t.Error("no GroupSecrets round-tripped")
	}
}

// GroupSecrets as RFC 9420 writes them, its PSK list kept as bytes, for checking the vectors' syntax: production
// refuses what this reads.
type mlsTestGroupSecrets struct {
	joinerSecret []byte
	pathSecret   []byte
	psks         []byte
}

func (self *mlsTestGroupSecrets) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.joinerSecret)
	encoder.writeOptional(self.pathSecret != nil)
	if self.pathSecret != nil {
		encoder.writeVector(self.pathSecret)
	}
	encoder.writeVector(self.psks)
}

func (self *mlsTestGroupSecrets) decode(decoder *mlsDecoder) {
	self.joinerSecret = decoder.readVector()
	if decoder.readOptional() {
		self.pathSecret = decoder.readVector()
	}
	self.psks = decoder.readVector()
}

// A join's first phase opens nothing a forged GroupInfo can then complete, the second binds the tree, and gkm's
// ladder runs between them: KEK_e from the Welcome opens GenWrap_e, accepted against gen/<g>'s C_g, which gives
// K_groupinfo, which opens the sealed GroupInfo that completes the join (§10.6; KEYS-M2-04's seam). RK_g stays
// provisional until Complete passes: a forged GroupInfo sealed under the same K_groupinfo, as a member could make
// one, completes nothing and leaves no group.
func TestMlsTwoPhaseJoinThroughTheLadder(t *testing.T) {
	world := newMlsTestWorld(t)
	creator, joiner := world.sidecar(nil), world.sidecar(nil)
	repoId := mlsTestUrGroup().RepoId
	group, err := creator.engine.CreateGroup(NewId(), mlsTestUrGroup())
	if err != nil {
		t.Fatal(err)
	}
	groupId := group.GroupId()
	keyPackage, err := joiner.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := group.Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}

	// the committer seals GenWrap_1 and GroupInfo_1 under the generation, as KF2 does
	rotator := newGkmTestSigner("rotator")
	repoKey, rotate, err := NewGkmFirstGeneration(repoId, groupId, gkmTestArgs(GkmCauseRequest))
	if err != nil {
		t.Fatal(err)
	}
	generation := gkmTestGeneration(t, rotator, rotate)
	kek, err := MlsKek(staged, repoId)
	if err != nil {
		t.Fatal(err)
	}
	genWrap, err := SealGkmGenWrap(repoKey, groupId, 1, kek)
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	sealedGroupInfo, err := SealGkmGroupInfo(repoKey, groupId, 1, groupInfo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.Adopt(); err != nil {
		t.Fatal(err)
	}

	// phase one: KEK_1, before any tree
	pending, err := joiner.engine.JoinWelcome(staged.Welcome())
	if err != nil {
		t.Fatal(err)
	}
	joinerKek, err := MlsKek(pending, repoId)
	if err != nil || !bytes.Equal(joinerKek, kek) {
		t.Fatalf("phase one's KEK: %v", err)
	}
	provisional, err := OpenGkmGenWrap(generation, groupId, 1, joinerKek, genWrap)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenGkmGroupInfo(provisional, groupId, 1, sealedGroupInfo)
	if err != nil || !bytes.Equal(opened, groupInfo) {
		t.Fatalf("the sealed GroupInfo: %v", err)
	}

	// forgeries under the same K_groupinfo, each refused, none leaving a group
	forgeries := mlsTestForgedGroupInfos(t, opened)
	for name, forged := range forgeries {
		sealed, err := SealGkmGroupInfo(provisional, groupId, 1, forged)
		if err != nil {
			t.Fatal(err)
		}
		unsealed, err := OpenGkmGroupInfo(provisional, groupId, 1, sealed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pending.Complete(unsealed); err == nil {
			t.Fatalf("%s completed the join", name)
		}
		if _, err := joiner.engine.LoadGroup(groupId); !errors.Is(err, ErrMlsGroupUnknown) {
			t.Fatalf("%s left a group: %v", name, err)
		}
	}

	joined, err := pending.Complete(opened)
	if err != nil {
		t.Fatalf("the true GroupInfo after the forgeries: %v", err)
	}
	creatorGroup, err := creator.engine.LoadGroup(groupId)
	if err != nil {
		t.Fatal(err)
	}
	mlsTestAgree(t, []MlsGroup{creatorGroup, joined})
	if _, err := pending.Complete(opened); err == nil {
		t.Error("a pending join completed twice")
	}
}

// GroupInfos a member or server could put in front of a joiner in place of the true one, each carrying the
// Welcome's GroupContext and tag where it can.
func mlsTestForgedGroupInfos(t *testing.T, encoded []byte) map[string][]byte {
	t.Helper()
	decode := func() *mlsGroupInfo {
		groupInfo := &mlsGroupInfo{}
		if err := mlsUnmarshalMessageOf(encoded, mlsWireFormatGroupInfo, groupInfo); err != nil {
			t.Fatal(err)
		}
		return groupInfo
	}
	marshal := func(groupInfo *mlsGroupInfo) []byte {
		forged, err := mlsMarshalMessageOf(mlsWireFormatGroupInfo, groupInfo)
		if err != nil {
			t.Fatal(err)
		}
		return forged
	}
	attackerKey, err := mlsSuite.generateSignatureKey("test")
	if err != nil {
		t.Fatal(err)
	}
	forgeries := map[string][]byte{}

	flipped := bytes.Clone(encoded)
	flipped[len(flipped)-1] ^= 1
	forgeries["a flipped signature"] = flipped

	resigned := decode()
	if err := resigned.sign(mlsSuite, attackerKey); err != nil {
		t.Fatal(err)
	}
	forgeries["a signature by another key"] = marshal(resigned)

	// the signer's leaf swapped for the attacker's key, re-signed: the tree no longer hashes to the context
	swapped := decode()
	tree, err := swapped.ratchetTree(mlsSuite, defaultMlsTreeSettings())
	if err != nil {
		t.Fatal(err)
	}
	signerLeaf := *tree.leafNode(swapped.signer)
	signerLeaf.signatureKey = []byte(attackerKey.Public().(ed25519.PublicKey))
	tree.setNode(swapped.signer.node(), mlsTreeNode{leaf: &signerLeaf})
	treeExtension, err := mlsRatchetTreeExtension(tree)
	if err != nil {
		t.Fatal(err)
	}
	for index := range swapped.extensions {
		if swapped.extensions[index].extensionType == mlsExtensionTypeRatchetTree {
			swapped.extensions[index] = treeExtension
		}
	}
	if err := swapped.sign(mlsSuite, attackerKey); err != nil {
		t.Fatal(err)
	}
	forgeries["a tree with the signer's key swapped"] = marshal(swapped)

	// no tree at all
	treeless := decode()
	treeless.extensions = []mlsExtension{}
	forgeries["no ratchet tree"] = marshal(treeless)

	// another epoch's context
	otherEpoch := decode()
	otherEpoch.groupContext.epoch += 1
	forgeries["another epoch's context"] = marshal(otherEpoch)

	// another external key, signed by nobody it could be
	return forgeries
}

// A GroupInfo's signature covers its extensions, its tag and its signer, and verifies only under its signer's key.
func TestMlsGroupInfoSignatureBindsEveryField(t *testing.T) {
	world := newMlsTestWorld(t)
	groups := mlsTestGroupOf(t, world.sidecar(nil), world.sidecar(nil))
	state := groups[0].(*mlsRealGroup).state
	groupInfo, err := state.groupInfo(true)
	if err != nil {
		t.Fatal(err)
	}
	key := state.tree.leafNode(state.ownLeaf()).signatureKey
	if err := groupInfo.verify(mlsSuite, key); err != nil {
		t.Fatal(err)
	}
	tampers := map[string]func(groupInfo *mlsGroupInfo){
		"extensions":       func(groupInfo *mlsGroupInfo) { groupInfo.extensions = groupInfo.extensions[:1] },
		"confirmation tag": func(groupInfo *mlsGroupInfo) { groupInfo.confirmationTag = bytes.Repeat([]byte{1}, 32) },
		"signer":           func(groupInfo *mlsGroupInfo) { groupInfo.signer += 1 },
		"epoch":            func(groupInfo *mlsGroupInfo) { groupInfo.groupContext.epoch += 1 },
	}
	for name, tamper := range tampers {
		tampered := *groupInfo
		tampered.groupContext = groupInfo.groupContext
		tampered.extensions = append([]mlsExtension{}, groupInfo.extensions...)
		tamper(&tampered)
		if err := tampered.verify(mlsSuite, key); !errors.Is(err, errMlsAuthentication) {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := groups[1].(*mlsRealGroup).state
	if err := groupInfo.verify(mlsSuite, other.tree.leafNode(other.ownLeaf()).signatureKey); err == nil {
		t.Error("verified under another leaf's key")
	}
	// the Welcome's copy carries neither the tree nor external_pub
	welcomeCopy, err := state.groupInfo(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(welcomeCopy.extensions) != 0 {
		t.Errorf("the Welcome's GroupInfo carries %d extensions", len(welcomeCopy.extensions))
	}
}

// A full GroupInfo naming an external key not its epoch's is refused at the join, though its signature is good.
func TestMlsJoinRefusesAnotherExternalKey(t *testing.T) {
	world := newMlsTestWorld(t)
	creator, joiner := world.sidecar(nil), world.sidecar(nil)
	group, err := creator.engine.CreateGroup(NewId(), mlsTestUrGroup())
	if err != nil {
		t.Fatal(err)
	}
	keyPackage, err := joiner.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := group.Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	next := staged.(*mlsRealStagedCommit).staged.next
	groupInfo, err := next.groupInfo(true)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := mlsSuite.generateKemKey("test")
	if err != nil {
		t.Fatal(err)
	}
	externalPub, err := mlsExternalPubExtension(otherKey.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	groupInfo.extensions[1] = externalPub
	if err := groupInfo.sign(mlsSuite, next.signatureKey); err != nil {
		t.Fatal(err)
	}
	encoded, err := mlsMarshalMessageOf(mlsWireFormatGroupInfo, groupInfo)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := joiner.engine.JoinWelcome(staged.Welcome())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pending.Complete(encoded); !errors.Is(err, errMlsInvalid) {
		t.Errorf("another external key: %v", err)
	}
}

// A Welcome's group secrets naming a PSK are refused when parsed, before any key opens with them.
func TestMlsGroupSecretsRefuseAPsk(t *testing.T) {
	encoded, err := mlsMarshal(&mlsGroupSecrets{joinerSecret: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	withPsk := append(bytes.Clone(encoded[:len(encoded)-1]), 3, 1, 2, 3)
	if err := mlsUnmarshal(withPsk, &mlsGroupSecrets{}); !errors.Is(err, errMlsRefused) {
		t.Errorf("a PSK: %v", err)
	}
	decoded := &mlsGroupSecrets{}
	if err := mlsUnmarshal(encoded, decoded); err != nil || decoded.pathSecret != nil {
		t.Errorf("no path secret: %v", err)
	}
}

// A KeyPackage used past its lifetime still joins a Welcome a committer sent inside it: the lifetime binds the
// sender (RFC 9420 §7.3), and a Welcome may arrive late.
func TestMlsWelcomeJoinsAfterTheKeyPackagesLifetime(t *testing.T) {
	world := newMlsTestWorld(t)
	creator, joiner := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, creator)
	keyPackage, err := joiner.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := groups[0].Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: []byte("add")})
	if err != nil {
		t.Fatal(err)
	}
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	world.clock.advance(100 * 24 * time.Hour)
	pending, err := joiner.engine.JoinWelcome(staged.Welcome())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pending.Complete(groupInfo); err != nil {
		t.Errorf("a late Welcome: %v", err)
	}
}
