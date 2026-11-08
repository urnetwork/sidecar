// What a member refuses of a received commit (KEYS-M2-08): every feature §10.4 refuses fails when parsed, inside
// a PrivateMessage sealed under a real sender's keys as well as in the clear, and every rule of RFC 9420 §12.2's
// list and the subset's refuses a commit whose signature and sealing are good, before its confirmation tag is
// read; a commit whose tag is wrong is refused after.

package sidecar

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// A group of three real members at epoch 1.
func mlsTestThree(t *testing.T) (*mlsTestWorld, []*mlsTestSidecar, []MlsGroup) {
	t.Helper()
	world := newMlsTestWorld(t)
	sidecars := []*mlsTestSidecar{world.sidecar(nil), world.sidecar(nil), world.sidecar(nil)}
	return world, sidecars, mlsTestGroupOf(t, sidecars[0], sidecars[1], sidecars[2])
}

// plaintext sealed as sender's PrivateMessage commit at its epoch, under its next handshake generation, so only
// what the plaintext holds can be refused.
func mlsTestSealedPlaintext(t *testing.T, sender *mlsTestSidecar, group MlsGroup, contentType uint8, plaintext []byte) []byte {
	t.Helper()
	state := group.(*mlsRealGroup).state
	generation, err := sender.engine.reserveGeneration(state)
	if err != nil {
		t.Fatal(err)
	}
	protection, err := state.messageProtection()
	if err != nil {
		t.Fatal(err)
	}
	ratchets, err := protection.secretTree.ratchets(state.ownLeaf())
	if err != nil {
		t.Fatal(err)
	}
	if err := ratchets.handshake.skipTo(generation); err != nil {
		t.Fatal(err)
	}
	message := &mlsPrivateMessage{groupId: state.groupId(), epoch: state.epoch(), contentType: contentType, authenticatedData: []byte("raw")}
	if err := protection.sealPlaintext(message, state.ownLeaf(), plaintext); err != nil {
		t.Fatal(err)
	}
	encoder := &mlsEncoder{}
	encoder.writeUint16(mlsProtocolVersion10)
	encoder.writeUint16(mlsWireFormatPrivateMessage)
	message.encode(encoder)
	encoded, err := encoder.finish()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// commit, whatever it holds, signed by sender and sealed as its PrivateMessage, with tag as its confirmation tag.
func mlsTestRawCommit(t *testing.T, sender *mlsTestSidecar, group MlsGroup, commit *mlsCommit, tag []byte) []byte {
	t.Helper()
	state := group.(*mlsRealGroup).state
	authenticated := &mlsAuthenticatedContent{
		wireFormat: mlsWireFormatPrivateMessage,
		content: mlsFramedContent{
			groupId:           state.groupId(),
			epoch:             state.epoch(),
			sender:            mlsSender{senderType: mlsSenderTypeMember, leafIndex: state.ownLeaf()},
			authenticatedData: []byte("raw"),
			contentType:       mlsContentTypeCommit,
			body:              commit,
		},
	}
	if err := authenticated.sign(mlsSuite, state.signatureKey, state.encodedGroupContext); err != nil {
		t.Fatal(err)
	}
	authenticated.auth.confirmationTag = tag
	generation, err := sender.engine.reserveGeneration(state)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := state.sealCommit(authenticated, generation)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// One proposal's bytes as a commit holds it: the inline tag, the type, then body.
func mlsTestProposalBytes(proposalType uint16, body []byte) []byte {
	encoder := &mlsEncoder{}
	encoder.writeUint8(mlsProposalOrRefTypeProposal)
	encoder.writeUint16(proposalType)
	encoder.writeFixed(body)
	return encoder.encoded
}

// A PrivateMessage plaintext: a commit of these proposal bytes and no path, then a signature and a tag that no
// one reaches, since the parse refuses first.
func mlsTestCommitPlaintext(proposals ...[]byte) []byte {
	encoder := &mlsEncoder{}
	encoder.writeVector(bytes.Join(proposals, nil))
	encoder.writeOptional(false)
	encoder.writeVector(bytes.Repeat([]byte{1}, 64))
	encoder.writeVector(bytes.Repeat([]byte{2}, 32))
	return encoder.encoded
}

// Each feature §10.4 refuses fails when parsed, though the message carrying it is sealed under the sender's real
// keys: Update, PreSharedKey and ReInit proposals, a proposal by reference, an unknown proposal type, application
// data and standalone proposals; and in the clear, a member's PublicMessage, an external sender's proposal and a
// new member's proposal (§10.4's refused row).
func TestMlsRefusedFeaturesFailAtParse(t *testing.T) {
	_, sidecars, groups := mlsTestThree(t)
	sender, receiver := sidecars[1], groups[2]
	reference := func() []byte {
		encoder := &mlsEncoder{}
		encoder.writeUint8(mlsProposalOrRefTypeReference)
		encoder.writeVector(bytes.Repeat([]byte{3}, 32))
		return encoder.encoded
	}()
	sealed := map[string][]byte{
		"an Update proposal":       mlsTestSealedPlaintext(t, sender, groups[1], mlsContentTypeCommit, mlsTestCommitPlaintext(mlsTestProposalBytes(mlsProposalTypeUpdate, nil))),
		"a PreSharedKey proposal":  mlsTestSealedPlaintext(t, sender, groups[1], mlsContentTypeCommit, mlsTestCommitPlaintext(mlsTestProposalBytes(mlsProposalTypePsk, nil))),
		"a ReInit proposal":        mlsTestSealedPlaintext(t, sender, groups[1], mlsContentTypeCommit, mlsTestCommitPlaintext(mlsTestProposalBytes(mlsProposalTypeReInit, nil))),
		"an unknown proposal type": mlsTestSealedPlaintext(t, sender, groups[1], mlsContentTypeCommit, mlsTestCommitPlaintext(mlsTestProposalBytes(0x0a0a, nil))),
		"a proposal by reference":  mlsTestSealedPlaintext(t, sender, groups[1], mlsContentTypeCommit, mlsTestCommitPlaintext(reference)),
		"application data":         mlsTestSealedPlaintext(t, sender, groups[1], mlsContentTypeApplication, []byte("data")),
		"a standalone proposal":    mlsTestSealedPlaintext(t, sender, groups[1], mlsContentTypeProposal, mlsTestProposalBytes(mlsProposalTypeRemove, []byte{0, 0, 0, 0})[1:]),
	}
	for name, message := range sealed {
		if _, err := receiver.Process(message); !errors.Is(err, errMlsRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	clear := map[string][]byte{
		"a member's PublicMessage":      mlsTestPublicFrame(mlsSenderTypeMember, mlsContentTypeCommit, mlsTestCommitOf(nil)),
		"an external sender's proposal": mlsTestPublicFrame(mlsSenderTypeExternal, mlsContentTypeProposal, nil),
		"a new member's proposal":       mlsTestPublicFrame(mlsSenderTypeNewMemberProposal, mlsContentTypeProposal, nil),
	}
	for name, message := range clear {
		if _, err := receiver.Process(message); !errors.Is(err, errMlsRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if receiver.Epoch() != 1 {
		t.Error("a refused message moved the group")
	}
}

// RFC 9420 §12.2's list rules and the subset's, each on a commit whose signature and sealing are good: a
// committer removing itself, a leaf removed twice, a blank leaf removed, an ExternalInit in a member's commit, two
// GroupContextExtensions, one changing ur_group or dropping the subset's requirements, a Remove without a path, an
// empty commit without one, and an Add of a sidecar already a leaf.
func TestMlsReceivedCommitListRulesRefuse(t *testing.T) {
	_, sidecars, groups := mlsTestThree(t)
	sender, receiver := sidecars[1], groups[2]
	state := groups[1].(*mlsRealGroup).state
	own := state.ownLeaf()
	other := mlsLeafIndex(groups[2].Self().LeafIndex)
	// a path that encodes, which the receiver never reaches: the list is refused first
	path := &mlsUpdatePath{leafNode: *state.tree.leafNode(own)}
	extensions := state.groupContext.extensions
	otherUrGroup := mlsTestUrGroup()
	otherUrGroup.RepoId = gkmTestId("another repo")
	changed, err := mlsSubsetGroupExtensions(otherUrGroup)
	if err != nil {
		t.Fatal(err)
	}
	dropped := []mlsExtension{extensions[0]}
	keyPackage, err := sidecars[2].engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &mlsKeyPackage{}
	if err := mlsUnmarshalMessageOf(keyPackage.Encoded, mlsWireFormatKeyPackage, decoded); err != nil {
		t.Fatal(err)
	}
	remove := func(leaf mlsLeafIndex) mlsProposal {
		return mlsProposal{proposalType: mlsProposalTypeRemove, removed: leaf}
	}
	cases := []struct {
		name   string
		commit *mlsCommit
		want   error
	}{
		{name: "its committer removed", commit: &mlsCommit{proposals: []mlsProposal{remove(own)}, path: path}, want: errMlsInvalid},
		{name: "a leaf removed twice", commit: &mlsCommit{proposals: []mlsProposal{remove(other), remove(other)}, path: path}, want: errMlsInvalid},
		{name: "a blank leaf removed", commit: &mlsCommit{proposals: []mlsProposal{remove(7)}, path: path}, want: errMlsInvalid},
		{name: "an ExternalInit", commit: &mlsCommit{proposals: []mlsProposal{{proposalType: mlsProposalTypeExternalInit, kemOutput: []byte("kem")}}, path: path}, want: errMlsInvalid},
		{name: "two GroupContextExtensions", commit: &mlsCommit{proposals: []mlsProposal{
			{proposalType: mlsProposalTypeGroupContextExtensions, extensions: extensions},
			{proposalType: mlsProposalTypeGroupContextExtensions, extensions: extensions},
		}, path: path}, want: errMlsInvalid},
		{name: "ur_group changed", commit: &mlsCommit{proposals: []mlsProposal{{proposalType: mlsProposalTypeGroupContextExtensions, extensions: changed}}, path: path}, want: errMlsInvalid},
		{name: "the requirements dropped", commit: &mlsCommit{proposals: []mlsProposal{{proposalType: mlsProposalTypeGroupContextExtensions, extensions: dropped}}, path: path}, want: errMlsInvalid},
		{name: "a Remove without a path", commit: &mlsCommit{proposals: []mlsProposal{remove(other)}}, want: errMlsInvalid},
		{name: "an empty commit without a path", commit: &mlsCommit{}, want: errMlsInvalid},
		{name: "an Add of a sidecar already a leaf", commit: &mlsCommit{proposals: []mlsProposal{{proposalType: mlsProposalTypeAdd, keyPackage: decoded}}}, want: errMlsInvalid},
	}
	for _, c := range cases {
		message := mlsTestRawCommit(t, sender, groups[1], c.commit, bytes.Repeat([]byte{0}, 32))
		if _, err := receiver.Process(message); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A commit whose every check holds but its confirmation tag is refused, so a member never adopts an epoch its
// committer did not reach (RFC 9420 §12.4.2).
func TestMlsReceivedCommitWithAWrongTagIsRefused(t *testing.T) {
	_, sidecars, groups := mlsTestThree(t)
	state := groups[1].(*mlsRealGroup).state
	// a real self-update, its tag replaced once the receiver has opened it
	generation, err := sidecars[1].engine.reserveGeneration(state)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := state.stageCommit(&mlsCommitInput{path: true, pathIdentity: mlsTestLeafIdentity(t, sidecars[1].signer), authenticatedData: []byte("update"), generation: generation, now: mlsTestTime})
	if err != nil {
		t.Fatal(err)
	}
	opened := &mlsMessage{}
	if err := mlsUnmarshal(staged.message, opened); err != nil {
		t.Fatal(err)
	}
	receiverState := groups[2].(*mlsRealGroup).state
	protection, err := receiverState.messageProtection()
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := protection.open(opened)
	if err != nil {
		t.Fatal(err)
	}
	authenticated.auth.confirmationTag = bytes.Repeat([]byte{9}, 32)
	if _, err := receiverState.processMemberCommit(authenticated, authenticated.content.commit()); !errors.Is(err, errMlsAuthentication) {
		t.Errorf("a wrong tag: %v", err)
	}
}

// A committer's own refusals before anything seals: an Add of a KeyPackage past its lifetime, or of a sidecar the
// check does not admit.
func TestMlsCommitRefusesKeyPackagesItCannotSend(t *testing.T) {
	world := newMlsTestWorld(t)
	creator, joiner := world.sidecar(nil), world.sidecar(nil)
	groups := mlsTestGroupOf(t, creator)
	keyPackage, err := joiner.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	world.clock.advance(91 * 24 * time.Hour)
	if _, err := groups[0].Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: []byte("late")}); !errors.Is(err, errMlsInvalid) {
		t.Errorf("a lapsed KeyPackage: %v", err)
	}

	outsider := &mlsTestSidecar{signer: newGkmTestSigner("outsider"), store: newMlsTestStore(), clock: world.clock, admissions: &mlsTestAdmissions{}, suite: mlsSuite}
	outsider.signer.sidecarId = NewId()
	outsider.admissions.admit(outsider.signer)
	outsider.restart(t)
	unadmitted, err := outsider.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups[0].Commit(&MlsCommitArgs{Adds: [][]byte{unadmitted.Encoded}, AuthenticatedData: []byte("outsider")}); err == nil {
		t.Error("a sidecar no check admits was added")
	}
	if groups[0].Epoch() != 0 {
		t.Error("a refused commit moved the group")
	}
}

// An engine with no admission check creates a group and updates its own leaf, and adds no one (KEYS-M2-19 fails
// closed until it lands).
func TestMlsEngineWithNoCheckAddsNoOne(t *testing.T) {
	world := newMlsTestWorld(t)
	joiner := world.sidecar(nil)
	signer := newGkmTestSigner("unchecked")
	engine, err := newMlsEngine(&MlsEngineArgs{
		SidecarId:         signer.sidecarId,
		IdentityPublicKey: signer.publicKey(),
		AdmissionSha256:   gkmTestBytes("admission", gkmDigestByteCount),
		Sign:              signer.sign,
		Store:             newMlsTestStore(),
		Clock:             world.clock,
	}, mlsSuite, defaultMlsGroupSettings())
	if err != nil {
		t.Fatal(err)
	}
	group, err := engine.CreateGroup(NewId(), mlsTestUrGroup())
	if err != nil {
		t.Fatal(err)
	}
	staged, err := group.Commit(&MlsCommitArgs{Path: true, AuthenticatedData: []byte("self-update")})
	if err != nil {
		t.Fatal(err)
	}
	if group, err = staged.Adopt(); err != nil {
		t.Fatal(err)
	}
	keyPackage, err := joiner.engine.CreateKeyPackage(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := group.Commit(&MlsCommitArgs{Adds: [][]byte{keyPackage.Encoded}, AuthenticatedData: []byte("add")}); !errors.Is(err, errMlsRefused) {
		t.Errorf("an unchecked engine added a leaf: %v", err)
	}
}
