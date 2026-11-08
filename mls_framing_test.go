// Framing against the mlswg's message-protection and messages vectors under 0x0001, and its behavior
// under both suites.
//
// The vectors frame what §10.4 refuses: application data, proposals, a member's PublicMessage, and
// commits holding a PSK or a reference. So every vector message is asserted refused through the
// production parse first, and then run through the production crypto with mlsTestReadContent in place
// of mlsReadCommit, which is how the keys, nonces, AADs and signatures meet known answers anyway.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A content's exact bytes, for the vectors' contents that production refuses.
type mlsTestContent []byte

// Writes the bytes it holds.
func (self mlsTestContent) encode(encoder *mlsEncoder) {
	encoder.writeFixed(self)
}

// Reads any content the vectors hold, keeping its bytes and judging none of them.
func mlsTestReadContent(decoder *mlsDecoder, contentType uint8) mlsEncodable {
	start := decoder.remaining
	switch contentType {
	case mlsContentTypeApplication:
		decoder.readVector()
	case mlsContentTypeProposal:
		var proposal mlsProposal
		proposal.decode(decoder)
	case mlsContentTypeCommit:
		decoder.take(decoder.readLength())
		if decoder.readOptional() {
			var path mlsUpdatePath
			path.decode(decoder)
		}
	default:
		decoder.fail(fmt.Errorf("%w: content type %d", errMlsMalformed, contentType))
	}
	if decoder.err != nil {
		return nil
	}
	return mlsTestContent(bytes.Clone(start[:len(start)-len(decoder.remaining)]))
}

// A PublicMessage as RFC §6.2 has it from a member, which only the vectors send.
type mlsTestMemberPublicMessage struct {
	content       mlsFramedContent
	auth          mlsFramedContentAuthData
	membershipTag []byte
}

// MLSMessage around a member's PublicMessage.
func (self *mlsTestMemberPublicMessage) encode(encoder *mlsEncoder) {
	encoder.writeUint16(mlsProtocolVersion10)
	encoder.writeUint16(mlsWireFormatPublicMessage)
	self.content.encode(encoder)
	self.auth.encode(encoder, self.content.contentType)
	encoder.writeVector(self.membershipTag)
}

// MLSMessage around a member's PublicMessage.
func (self *mlsTestMemberPublicMessage) decode(decoder *mlsDecoder) {
	decoder.readUint16()
	if wireFormat := decoder.readUint16(); decoder.err == nil && wireFormat != mlsWireFormatPublicMessage {
		decoder.fail(fmt.Errorf("wire format %#x", wireFormat))
		return
	}
	self.content.decode(decoder, mlsTestReadContent)
	if decoder.err != nil {
		return
	}
	self.auth.decode(decoder, self.content.contentType)
	self.membershipTag = decoder.readVector()
}

// membership_tag (RFC §6.2) over AuthenticatedContentTBM.
func (self *mlsTestMemberPublicMessage) verifyMembershipTag(t *testing.T, suite *mlsCipherSuite, membershipKey []byte, groupContext []byte) bool {
	t.Helper()
	authenticated := &mlsAuthenticatedContent{wireFormat: mlsWireFormatPublicMessage, content: self.content, auth: self.auth}
	toBeSigned, err := authenticated.toBeSigned(groupContext)
	if err != nil {
		t.Fatal(err)
	}
	encoder := &mlsEncoder{}
	encoder.writeFixed(toBeSigned)
	self.auth.encode(encoder, self.content.contentType)
	encoded, err := encoder.finish()
	if err != nil {
		t.Fatal(err)
	}
	return suite.verifyMac(membershipKey, encoded, self.membershipTag)
}

// A PrivateMessage of any content type, which production stops at its clear header.
func mlsTestDecodePrivateMessage(t *testing.T, encoded []byte) *mlsPrivateMessage {
	t.Helper()
	decoder := &mlsDecoder{remaining: encoded}
	decoder.readUint16()
	if wireFormat := decoder.readUint16(); wireFormat != mlsWireFormatPrivateMessage {
		t.Fatalf("wire format %#x", wireFormat)
	}
	message := &mlsPrivateMessage{}
	message.groupId = decoder.readVector()
	message.epoch = decoder.readUint64()
	message.contentType = decoder.readUint8()
	message.authenticatedData = decoder.readVector()
	message.encryptedSenderData = decoder.readVector()
	message.ciphertext = decoder.readVector()
	if err := decoder.finish(); err != nil {
		t.Fatal(err)
	}
	return message
}

// The message on the wire and back, as a receiver gets it.
func mlsTestOnTheWire(t *testing.T, message *mlsMessage) *mlsMessage {
	t.Helper()
	encoded, err := mlsMarshal(message)
	if err != nil {
		t.Fatal(err)
	}
	received := &mlsMessage{}
	if err := mlsUnmarshal(encoded, received); err != nil {
		t.Fatal(err)
	}
	return received
}

// A PrivateMessage on the wire and back.
func mlsTestPrivateOnTheWire(t *testing.T, message *mlsPrivateMessage) *mlsMessage {
	t.Helper()
	return mlsTestOnTheWire(t, &mlsMessage{wireFormat: mlsWireFormatPrivateMessage, privateMessage: message})
}

// message-protection.json, as test-vectors.md has it, within what §10.4 lets run: each message opens
// and verifies, and each commit is protected afresh and opens again.
func TestMlsMessageProtectionVectors(t *testing.T) {
	var vectors []struct {
		CipherSuite             uint16      `json:"cipher_suite"`
		GroupId                 mlsHexBytes `json:"group_id"`
		Epoch                   uint64      `json:"epoch"`
		TreeHash                mlsHexBytes `json:"tree_hash"`
		ConfirmedTranscriptHash mlsHexBytes `json:"confirmed_transcript_hash"`
		SignaturePriv           mlsHexBytes `json:"signature_priv"`
		SignaturePub            mlsHexBytes `json:"signature_pub"`
		EncryptionSecret        mlsHexBytes `json:"encryption_secret"`
		SenderDataSecret        mlsHexBytes `json:"sender_data_secret"`
		MembershipKey           mlsHexBytes `json:"membership_key"`
		Proposal                mlsHexBytes `json:"proposal"`
		ProposalPriv            mlsHexBytes `json:"proposal_priv"`
		ProposalPub             mlsHexBytes `json:"proposal_pub"`
		Commit                  mlsHexBytes `json:"commit"`
		CommitPriv              mlsHexBytes `json:"commit_priv"`
		CommitPub               mlsHexBytes `json:"commit_pub"`
		Application             mlsHexBytes `json:"application"`
		ApplicationPriv         mlsHexBytes `json:"application_priv"`
	}
	mlsLoadVectors(t, "message-protection", &vectors)

	suite := mlsTestSuiteX25519
	ran := 0
	for _, vector := range vectors {
		if vector.CipherSuite != suite.value {
			continue
		}
		ran++
		groupContext := &mlsGroupContext{
			cipherSuite:             suite.value,
			groupId:                 vector.GroupId,
			epoch:                   vector.Epoch,
			treeHash:                vector.TreeHash,
			confirmedTranscriptHash: vector.ConfirmedTranscriptHash,
		}
		encodedGroupContext, err := mlsMarshal(groupContext)
		if err != nil {
			t.Fatal(err)
		}
		// two members, the sender at leaf 1, as test-vectors.md has it
		tree := mlsShapedTree(
			mlsShapeLeaf("receiver"),
			mlsTreeNode{},
			mlsTreeNode{leaf: &mlsLeafNode{signatureKey: vector.SignaturePub}},
		)
		newProtection := func() *mlsMessageProtection {
			protection, err := newMlsMessageProtection(
				suite, defaultMlsMessageSettings(), groupContext, tree, vector.EncryptionSecret, vector.SenderDataSecret,
			)
			if err != nil {
				t.Fatal(err)
			}
			return protection
		}
		signatureKey, err := suite.loadSignatureKey("test", vector.SignaturePriv)
		if err != nil {
			t.Fatal(err)
		}

		// the production parse refuses every one of these
		for name, encoded := range map[string][]byte{
			"proposal_pub": vector.ProposalPub, "commit_pub": vector.CommitPub,
			"proposal_priv": vector.ProposalPriv, "application_priv": vector.ApplicationPriv,
		} {
			if err := mlsUnmarshal(encoded, &mlsMessage{}); !errors.Is(err, errMlsRefused) {
				t.Errorf("%s: %v", name, err)
			}
			if _, err := ParseMlsHeader(encoded); !errors.Is(err, errMlsRefused) {
				t.Errorf("%s header: %v", name, err)
			}
		}

		// commit_priv is a commit in its clear header, and its PSK is refused once it decrypts
		message := &mlsMessage{}
		if err := mlsUnmarshal(vector.CommitPriv, message); err != nil {
			t.Fatal(err)
		}
		protection := newProtection()
		if _, err := protection.open(message); !errors.Is(err, errMlsRefused) {
			t.Errorf("commit_priv through the production parse: %v", err)
		}

		// a refusal is not a forgery either: the sender's generation is still there to open
		if opened, err := protection.openPrivate(message.privateMessage, mlsTestReadContent); err != nil {
			t.Errorf("commit_priv: %v", err)
		} else if !bytes.Equal(opened.content.body.(mlsTestContent), vector.Commit) {
			t.Errorf("commit_priv opened to %x", opened.content.body)
		}

		privateCases := []struct {
			name        string
			encoded     []byte
			contentType uint8
			want        []byte
			// RFC §6.3.1: application content comes off the leaf's other ratchet, which production
			// never draws on, so the test puts it where production looks
			applicationRatchet bool
		}{
			{name: "proposal_priv", encoded: vector.ProposalPriv, contentType: mlsContentTypeProposal, want: vector.Proposal},
			{name: "commit_priv", encoded: vector.CommitPriv, contentType: mlsContentTypeCommit, want: vector.Commit},
			{
				name: "application_priv", encoded: vector.ApplicationPriv, contentType: mlsContentTypeApplication,
				want: mlsTestVector(t, vector.Application), applicationRatchet: true,
			},
		}
		for _, c := range privateCases {
			private := mlsTestDecodePrivateMessage(t, c.encoded)
			if private.contentType != c.contentType {
				t.Fatalf("%s: content type %d", c.name, private.contentType)
			}
			protection := newProtection()
			ratchets, err := protection.secretTree.ratchets(1)
			if err != nil {
				t.Fatal(err)
			}
			if c.applicationRatchet {
				ratchets.handshake, ratchets.application = ratchets.application, ratchets.handshake
			}
			opened, err := protection.openPrivate(private, mlsTestReadContent)
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
				continue
			}
			if !bytes.Equal(opened.content.body.(mlsTestContent), c.want) {
				t.Errorf("%s opened to %x, want %x", c.name, opened.content.body, c.want)
			}
			if opened.content.sender.leafIndex != 1 {
				t.Errorf("%s: sender %d", c.name, opened.content.sender.leafIndex)
			}
			reencoded, err := mlsMarshal(private)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reencoded, c.encoded[4:]) {
				t.Errorf("%s re-encoded differently", c.name)
			}
		}

		publicCases := []struct {
			name    string
			encoded []byte
			want    []byte
		}{
			{name: "proposal_pub", encoded: vector.ProposalPub, want: vector.Proposal},
			{name: "commit_pub", encoded: vector.CommitPub, want: vector.Commit},
		}
		for _, c := range publicCases {
			public := &mlsTestMemberPublicMessage{}
			if err := mlsUnmarshal(c.encoded, public); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if !bytes.Equal(public.content.body.(mlsTestContent), c.want) {
				t.Errorf("%s holds %x, want %x", c.name, public.content.body, c.want)
			}
			if !public.verifyMembershipTag(t, suite, vector.MembershipKey, encodedGroupContext) {
				t.Errorf("%s: membership tag", c.name)
			}
			authenticated := &mlsAuthenticatedContent{wireFormat: mlsWireFormatPublicMessage, content: public.content, auth: public.auth}
			if err := authenticated.verifySignature(suite, vector.SignaturePub, encodedGroupContext); err != nil {
				t.Errorf("%s: %v", c.name, err)
			}

			// protected afresh by this code, it verifies under the vector's keys
			resigned := &mlsAuthenticatedContent{wireFormat: mlsWireFormatPublicMessage, content: public.content, auth: public.auth}
			if err := resigned.sign(suite, signatureKey, encodedGroupContext); err != nil {
				t.Fatal(err)
			}
			if err := resigned.verifySignature(suite, vector.SignaturePub, encodedGroupContext); err != nil {
				t.Errorf("%s resigned: %v", c.name, err)
			}
		}

		// protected afresh by this code, the commit opens under the vector's keys
		commitPrivate := mlsTestDecodePrivateMessage(t, vector.CommitPriv)
		reference, err := newProtection().openPrivate(commitPrivate, mlsTestReadContent)
		if err != nil {
			t.Fatal(err)
		}
		authenticated := &mlsAuthenticatedContent{
			wireFormat: mlsWireFormatPrivateMessage,
			content: mlsFramedContent{
				groupId:           vector.GroupId,
				epoch:             vector.Epoch,
				sender:            mlsSender{senderType: mlsSenderTypeMember, leafIndex: 1},
				authenticatedData: []byte("authenticated data"),
				contentType:       mlsContentTypeCommit,
				body:              mlsTestContent(vector.Commit),
			},
		}
		if err := authenticated.sign(suite, signatureKey, encodedGroupContext); err != nil {
			t.Fatal(err)
		}
		authenticated.auth.confirmationTag = reference.auth.confirmationTag
		sealed, err := newProtection().seal(authenticated)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := newProtection().openPrivate(mlsTestPrivateOnTheWire(t, sealed).privateMessage, mlsTestReadContent)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(opened.content.body.(mlsTestContent), vector.Commit) {
			t.Errorf("the sealed commit opened to %x", opened.content.body)
		}
		if !bytes.Equal(opened.auth.confirmationTag, reference.auth.confirmationTag) {
			t.Errorf("confirmation tag %x", opened.auth.confirmationTag)
		}

		// test-vectors.md's other half: an application message has no PublicMessage, and here no
		// PrivateMessage either
		application := *authenticated
		application.content.contentType = mlsContentTypeApplication
		if _, err := newProtection().seal(&application); !errors.Is(err, errMlsRefused) {
			t.Errorf("sealing application content: %v", err)
		}
	}
	if ran == 0 {
		t.Fatal("no vector for suite 0x0001")
	}
}

// application_data<V>'s bytes, as mlsTestReadContent keeps them.
func mlsTestVector(t *testing.T, data []byte) []byte {
	t.Helper()
	encoder := &mlsEncoder{}
	encoder.writeVector(data)
	encoded, err := encoder.finish()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// messages.json's framed messages, which check syntax alone. Each re-encodes byte for byte through the
// permissive reader, and each is refused by the production parse unless it is a PrivateMessage commit.
func TestMlsMessagesFramingVectors(t *testing.T) {
	var vectors []struct {
		PublicMessageApplication mlsHexBytes `json:"public_message_application"`
		PublicMessageProposal    mlsHexBytes `json:"public_message_proposal"`
		PublicMessageCommit      mlsHexBytes `json:"public_message_commit"`
		PrivateMessage           mlsHexBytes `json:"private_message"`
		Commit                   mlsHexBytes `json:"commit"`
	}
	mlsLoadVectors(t, "messages", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}

	sawCommit := false
	for index, vector := range vectors {
		publicCases := []struct {
			name    string
			encoded []byte
		}{
			{name: "application", encoded: vector.PublicMessageApplication},
			{name: "proposal", encoded: vector.PublicMessageProposal},
			{name: "commit", encoded: vector.PublicMessageCommit},
		}
		for _, c := range publicCases {
			public := &mlsTestMemberPublicMessage{}
			if err := mlsUnmarshal(c.encoded, public); err != nil {
				t.Errorf("vector %d: public %s: %v", index, c.name, err)
				continue
			}
			reencoded, err := mlsMarshal(public)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reencoded, c.encoded) {
				t.Errorf("vector %d: public %s re-encoded differently", index, c.name)
			}
			if err := mlsUnmarshal(c.encoded, &mlsMessage{}); !errors.Is(err, errMlsRefused) {
				t.Errorf("vector %d: public %s through the production parse: %v", index, c.name, err)
			}
		}

		private := mlsTestDecodePrivateMessage(t, vector.PrivateMessage)
		reencoded, err := mlsMarshal(private)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reencoded, vector.PrivateMessage[4:]) {
			t.Errorf("vector %d: private message re-encoded differently", index)
		}
		err = mlsUnmarshal(vector.PrivateMessage, &mlsMessage{})
		if private.contentType == mlsContentTypeCommit {
			sawCommit = true
			if err != nil {
				t.Errorf("vector %d: private commit: %v", index, err)
			}
		} else if !errors.Is(err, errMlsRefused) {
			t.Errorf("vector %d: private content type %d: %v", index, private.contentType, err)
		}

		// every commit in the file proposes by reference
		if err := mlsUnmarshal(vector.Commit, &mlsCommit{}); !errors.Is(err, errMlsRefused) {
			t.Errorf("vector %d: commit: %v", index, err)
		}
	}
	if !sawCommit {
		t.Error("no private message was a commit")
	}
}

// One epoch of a real group, for sealing and opening.
type mlsTestEpoch struct {
	t                *testing.T
	suite            *mlsCipherSuite
	group            *mlsTestGroup
	groupContext     *mlsGroupContext
	encryptionSecret []byte
	senderDataSecret []byte
}

// A group of this many members, merged, with fresh epoch secrets.
func mlsNewTestEpoch(t *testing.T, suite *mlsCipherSuite, memberCount int) *mlsTestEpoch {
	t.Helper()
	group := mlsNewMergedTestGroup(t, suite, memberCount)
	treeHash, err := group.members[0].tree.treeHash()
	if err != nil {
		t.Fatal(err)
	}
	return &mlsTestEpoch{
		t:     t,
		suite: suite,
		group: group,
		groupContext: &mlsGroupContext{
			cipherSuite:             suite.value,
			groupId:                 group.groupId,
			epoch:                   group.epoch,
			treeHash:                treeHash,
			confirmedTranscriptHash: []byte("transcript"),
		},
		encryptionSecret: suite.generateSecret("test"),
		senderDataSecret: suite.generateSecret("test"),
	}
}

// One member's own protection of the epoch: each derives it apart from the same secrets, and shares
// no ratchet with another.
func (self *mlsTestEpoch) protection(leaf mlsLeafIndex) *mlsMessageProtection {
	self.t.Helper()
	protection, err := newMlsMessageProtection(
		self.suite, defaultMlsMessageSettings(), self.groupContext, self.group.members[leaf].tree, self.encryptionSecret, self.senderDataSecret,
	)
	if err != nil {
		self.t.Fatal(err)
	}
	return protection
}

// The epoch's encoded GroupContext.
func (self *mlsTestEpoch) encodedGroupContext() []byte {
	self.t.Helper()
	encoded, err := mlsMarshal(self.groupContext)
	if err != nil {
		self.t.Fatal(err)
	}
	return encoded
}

// A member's commit, signed and tagged, with this authenticated_data.
func (self *mlsTestEpoch) signedCommit(sender mlsLeafIndex, authenticatedData []byte, commit mlsEncodable) *mlsAuthenticatedContent {
	self.t.Helper()
	authenticated := &mlsAuthenticatedContent{
		wireFormat: mlsWireFormatPrivateMessage,
		content: mlsFramedContent{
			groupId:           self.groupContext.groupId,
			epoch:             self.groupContext.epoch,
			sender:            mlsSender{senderType: mlsSenderTypeMember, leafIndex: sender},
			authenticatedData: authenticatedData,
			contentType:       mlsContentTypeCommit,
			body:              commit,
		},
	}
	if err := authenticated.sign(self.suite, self.group.members[sender].signatureKey, self.encodedGroupContext()); err != nil {
		self.t.Fatal(err)
	}
	authenticated.auth.confirmationTag = self.suite.confirmationTag(make([]byte, self.suite.hashLength), []byte("confirmed"))
	return authenticated
}

// The smallest commit worth framing: one Remove and no path.
func mlsTestRemoveCommit(removed mlsLeafIndex) *mlsCommit {
	return &mlsCommit{proposals: []mlsProposal{{proposalType: mlsProposalTypeRemove, removed: removed}}}
}

// A member's sealed commit, in the clear header's own terms.
func (self *mlsTestEpoch) sealed(protection *mlsMessageProtection, sender mlsLeafIndex) *mlsPrivateMessage {
	self.t.Helper()
	message, err := protection.seal(self.signedCommit(sender, []byte("header"), mlsTestRemoveCommit(1)))
	if err != nil {
		self.t.Fatal(err)
	}
	return message
}

func TestMlsPrivateMessageRoundTripUnderBothSuites(t *testing.T) {
	for _, suite := range mlsTestSuites {
		epoch := mlsNewTestEpoch(t, suite, 3)
		updatePath, _, _ := mlsPreparedCommit(t, epoch.group, 0)
		commit := &mlsCommit{proposals: mlsTestRemoveCommit(1).proposals, path: updatePath}
		authenticated := epoch.signedCommit(0, []byte("header"), commit)
		message, err := epoch.protection(0).seal(authenticated)
		if err != nil {
			t.Fatal(err)
		}

		// every other member opens it, each from its own view of the epoch
		for _, leaf := range []mlsLeafIndex{1, 2} {
			opened, err := epoch.protection(leaf).open(mlsTestPrivateOnTheWire(t, message))
			if err != nil {
				t.Fatalf("suite %#x, leaf %d: %v", suite.value, leaf, err)
			}
			if opened.wireFormat != mlsWireFormatPrivateMessage {
				t.Errorf("wire format %#x", opened.wireFormat)
			}
			if sender := opened.content.sender; sender.senderType != mlsSenderTypeMember || sender.leafIndex != 0 {
				t.Errorf("sender %+v", sender)
			}
			if !bytes.Equal(opened.content.authenticatedData, []byte("header")) {
				t.Errorf("authenticated data %q", opened.content.authenticatedData)
			}
			if !bytes.Equal(opened.auth.signature, authenticated.auth.signature) {
				t.Error("the signature changed on the way")
			}
			if !bytes.Equal(opened.auth.confirmationTag, authenticated.auth.confirmationTag) {
				t.Error("the confirmation tag changed on the way")
			}
			got, err := mlsMarshal(opened.content.commit())
			if err != nil {
				t.Fatal(err)
			}
			want, err := mlsMarshal(commit)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Error("the commit changed on the way")
			}
		}
	}
}

// The whole of what a commit's framing feeds, from the committer's signature to the epoch both sides
// reach, so the steps mls_framing.go's header names are proved to compose.
func TestMlsCommitFramingThroughTheKeySchedule(t *testing.T) {
	for _, suite := range mlsTestSuites {
		epoch := mlsNewTestEpoch(t, suite, 3)
		group := epoch.group
		initSecret := suite.generateSecret("test")
		interimBefore := suite.hash([]byte("interim transcript hash"))

		// RFC §12.4.1: the path is sealed to the provisional GroupContext, the commit signed in the
		// current one, and the tag comes from the epoch the signature keys
		updatePath, prepared, receiverTree := mlsPreparedCommit(t, group, 0)
		authenticated := epoch.signedCommit(0, []byte("header"), &mlsCommit{path: updatePath})
		authenticated.auth.confirmationTag = nil
		nextEpoch := func(content *mlsAuthenticatedContent, tree *mlsRatchetTree, commitSecret []byte) (*mlsEpochSecrets, []byte) {
			input, err := content.confirmedTranscriptHashInput()
			if err != nil {
				t.Fatal(err)
			}
			confirmed := suite.nextConfirmedTranscriptHash(interimBefore, input)
			treeHash, err := tree.treeHash()
			if err != nil {
				t.Fatal(err)
			}
			groupContext, err := mlsMarshal(&mlsGroupContext{
				cipherSuite:             suite.value,
				groupId:                 group.groupId,
				epoch:                   group.epoch + 1,
				treeHash:                treeHash,
				confirmedTranscriptHash: confirmed,
			})
			if err != nil {
				t.Fatal(err)
			}
			joinerSecret, err := suite.deriveJoinerSecret(initSecret, commitSecret, groupContext)
			if err != nil {
				t.Fatal(err)
			}
			secrets, err := suite.deriveEpochSecrets(joinerSecret, nil, groupContext)
			if err != nil {
				t.Fatal(err)
			}
			return secrets, confirmed
		}
		committerSecrets, committerConfirmed := nextEpoch(authenticated, prepared.tree, prepared.commitSecret)
		authenticated.auth.confirmationTag = suite.confirmationTag(committerSecrets.confirmationKey, committerConfirmed)
		sealed, err := epoch.protection(0).seal(authenticated)
		if err != nil {
			t.Fatal(err)
		}

		member := group.members[1]
		opened, err := epoch.protection(1).open(mlsTestPrivateOnTheWire(t, sealed))
		if err != nil {
			t.Fatal(err)
		}
		received := opened.content.commit()
		if err := receiverTree.mergeUpdatePath(0, received.path, nil, group.validation); err != nil {
			t.Fatal(err)
		}
		receivedPath, err := member.secrets.receiveUpdatePath(receiverTree, 0, received.path, group.provisionalContext(receiverTree), nil)
		if err != nil {
			t.Fatal(err)
		}
		memberSecrets, memberConfirmed := nextEpoch(opened, receiverTree, receivedPath.commitSecret)
		if !suite.verifyConfirmationTag(memberSecrets.confirmationKey, memberConfirmed, opened.auth.confirmationTag) {
			t.Fatalf("suite %#x: the confirmation tag does not verify", suite.value)
		}
		if suite.verifyConfirmationTag(memberSecrets.membershipKey, memberConfirmed, opened.auth.confirmationTag) {
			t.Error("the tag verifies under another key")
		}
		if !bytes.Equal(memberSecrets.epochAuthenticator, committerSecrets.epochAuthenticator) {
			t.Error("the two sides reached different epochs")
		}
		committerInterim, err := suite.nextInterimTranscriptHash(committerConfirmed, authenticated.auth.confirmationTag)
		if err != nil {
			t.Fatal(err)
		}
		memberInterim, err := suite.nextInterimTranscriptHash(memberConfirmed, opened.auth.confirmationTag)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(committerInterim, memberInterim) {
			t.Error("the two sides hold different interim hashes")
		}
	}
}

// A joiner's external commit, built as a resync would: its ExternalInit, the Remove of its old leaf and
// a path from a leaf it reserved.
func (self *mlsTestEpoch) externalCommit(removed mlsLeafIndex) (*mlsTestClient, *mlsPublicMessage) {
	self.t.Helper()
	t := self.t
	suite := self.suite
	joiner := mlsNewTestClient(t, suite, "external joiner")

	tree := self.group.members[0].tree.clone()
	if err := tree.removeLeaf(removed); err != nil {
		t.Fatal(err)
	}
	sender, err := tree.reserveLeaf()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := tree.prepareUpdatePath(sender, &joiner.keyPackage.leafNode, joiner.signatureKey, self.group.groupId)
	if err != nil {
		t.Fatal(err)
	}
	updatePath, err := prepared.encrypt(self.group.provisionalContext(tree), nil)
	if err != nil {
		t.Fatal(err)
	}

	authenticated := &mlsAuthenticatedContent{
		wireFormat: mlsWireFormatPublicMessage,
		content: mlsFramedContent{
			groupId:           self.groupContext.groupId,
			epoch:             self.groupContext.epoch,
			sender:            mlsSender{senderType: mlsSenderTypeNewMemberCommit},
			authenticatedData: []byte("header"),
			contentType:       mlsContentTypeCommit,
			body: &mlsCommit{
				proposals: []mlsProposal{
					{proposalType: mlsProposalTypeExternalInit, kemOutput: []byte("kem output")},
					{proposalType: mlsProposalTypeRemove, removed: removed},
				},
				path: updatePath,
			},
		},
	}
	if err := authenticated.sign(suite, joiner.signatureKey, self.encodedGroupContext()); err != nil {
		t.Fatal(err)
	}
	authenticated.auth.confirmationTag = suite.confirmationTag(make([]byte, suite.hashLength), []byte("confirmed"))
	return joiner, &mlsPublicMessage{content: authenticated.content, auth: authenticated.auth}
}

func TestMlsPublicMessageRoundTripUnderBothSuites(t *testing.T) {
	for _, suite := range mlsTestSuites {
		epoch := mlsNewTestEpoch(t, suite, 3)
		_, message := epoch.externalCommit(1)
		received := mlsTestOnTheWire(t, &mlsMessage{wireFormat: mlsWireFormatPublicMessage, publicMessage: message})
		opened, err := epoch.protection(0).open(received)
		if err != nil {
			t.Fatalf("suite %#x: %v", suite.value, err)
		}
		if opened.wireFormat != mlsWireFormatPublicMessage {
			t.Errorf("wire format %#x", opened.wireFormat)
		}
		if opened.content.sender.senderType != mlsSenderTypeNewMemberCommit {
			t.Errorf("sender type %d", opened.content.sender.senderType)
		}
		if len(opened.content.commit().proposals) != 2 {
			t.Errorf("%d proposals", len(opened.content.commit().proposals))
		}
		if len(opened.auth.confirmationTag) != suite.hashLength {
			t.Errorf("confirmation tag of %d bytes", len(opened.auth.confirmationTag))
		}
	}
}

// An external commit's signature names no member: the key is the commit's own, so the check proves
// the commit is whole and that nobody re-signed part of it.
func TestMlsPublicMessageTamperIsCaught(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	cases := []struct {
		name   string
		change func(message *mlsPublicMessage)
	}{
		{name: "authenticated_data", change: func(message *mlsPublicMessage) { message.content.authenticatedData = []byte("other") }},
		{name: "a proposal", change: func(message *mlsPublicMessage) { message.content.commit().proposals[1].removed = 2 }},
		{name: "the signature", change: func(message *mlsPublicMessage) { message.auth.signature[0] ^= 1 }},
		{name: "the proposals' order", change: func(message *mlsPublicMessage) { slices.Reverse(message.content.commit().proposals) }},
		{name: "a path ciphertext", change: func(message *mlsPublicMessage) {
			message.content.commit().path.nodes[0].encryptedPathSecrets[0].ciphertext[0] ^= 1
		}},
	}
	for _, c := range cases {
		_, message := epoch.externalCommit(1)
		received := mlsTestOnTheWire(t, &mlsMessage{wireFormat: mlsWireFormatPublicMessage, publicMessage: message})
		c.change(received.publicMessage)
		if _, err := epoch.protection(0).open(received); !errors.Is(err, errMlsAuthentication) {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	_, message := epoch.externalCommit(1)
	message.content.commit().path = nil
	if _, err := epoch.protection(0).openPublic(message); !errors.Is(err, errMlsInvalid) {
		t.Errorf("no path: %v", err)
	}
}

// The joiner signs the epoch it read, so a commit signed under another GroupContext does not verify.
func TestMlsPublicMessageBindsTheGroupContext(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	_, message := epoch.externalCommit(1)
	epoch.groupContext.treeHash = []byte("another tree")
	if _, err := epoch.protection(0).openPublic(message); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

func TestMlsOtherEpochsAreNotJudged(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	cases := []struct {
		name   string
		change func(groupId *[]byte, number *uint64)
	}{
		{name: "next epoch", change: func(groupId *[]byte, number *uint64) { *number += 1 }},
		{name: "last epoch", change: func(groupId *[]byte, number *uint64) { *number -= 1 }},
		{name: "another group", change: func(groupId *[]byte, number *uint64) { *groupId = []byte("another group") }},
	}
	for _, c := range cases {
		private := epoch.sealed(epoch.protection(0), 0)
		c.change(&private.groupId, &private.epoch)
		receiver := epoch.protection(1)
		_, err := receiver.open(&mlsMessage{wireFormat: mlsWireFormatPrivateMessage, privateMessage: private})
		if !errors.Is(err, errMlsOtherEpoch) {
			t.Errorf("private, %s: %v", c.name, err)
		}

		_, public := epoch.externalCommit(1)
		c.change(&public.content.groupId, &public.content.epoch)
		_, err = receiver.open(&mlsMessage{wireFormat: mlsWireFormatPublicMessage, publicMessage: public})
		if !errors.Is(err, errMlsOtherEpoch) {
			t.Errorf("public, %s: %v", c.name, err)
		}
	}
}

// Every clear field is bound to the ciphertext, so changing one fails the AEAD and not only the equality
// check in front of it. The receiver here agrees with the tampered value, as a forger would want.
func TestMlsClearHeaderIsBoundIntoTheAead(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	cases := []struct {
		name   string
		change func(message *mlsPrivateMessage, groupContext *mlsGroupContext)
	}{
		{name: "group_id", change: func(message *mlsPrivateMessage, groupContext *mlsGroupContext) {
			message.groupId = []byte("another group")
			groupContext.groupId = message.groupId
		}},
		{name: "epoch", change: func(message *mlsPrivateMessage, groupContext *mlsGroupContext) {
			message.epoch += 1
			groupContext.epoch = message.epoch
		}},
		{name: "content_type", change: func(message *mlsPrivateMessage, groupContext *mlsGroupContext) {
			message.contentType = mlsContentTypeProposal
		}},
		{name: "authenticated_data", change: func(message *mlsPrivateMessage, groupContext *mlsGroupContext) {
			message.authenticatedData = []byte("other")
		}},
		{name: "encrypted_sender_data", change: func(message *mlsPrivateMessage, groupContext *mlsGroupContext) {
			message.encryptedSenderData[0] ^= 1
		}},
		{name: "ciphertext", change: func(message *mlsPrivateMessage, groupContext *mlsGroupContext) {
			message.ciphertext[len(message.ciphertext)-1] ^= 1
		}},
		{name: "the sender data's sample", change: func(message *mlsPrivateMessage, groupContext *mlsGroupContext) {
			message.ciphertext[0] ^= 1
		}},
	}
	for _, c := range cases {
		message := epoch.sealed(epoch.protection(0), 0)
		groupContext := *epoch.groupContext
		c.change(message, &groupContext)
		receiver, err := newMlsMessageProtection(
			mlsSuite, defaultMlsMessageSettings(), &groupContext, epoch.group.members[1].tree, epoch.encryptionSecret, epoch.senderDataSecret,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.openPrivate(message, mlsReadCommit); !errors.Is(err, errMlsAuthentication) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A server changing the header a member's commit carries, which only ParseMlsHeader would believe.
func TestMlsTamperedAuthenticatedDataFailsTheAead(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	message := epoch.sealed(epoch.protection(0), 0)
	message.authenticatedData = []byte("generation 9")
	received := mlsTestPrivateOnTheWire(t, message)

	encoded, err := mlsMarshal(received)
	if err != nil {
		t.Fatal(err)
	}
	header, err := ParseMlsHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header.AuthenticatedData, []byte("generation 9")) {
		t.Fatalf("header %q", header.AuthenticatedData)
	}
	if _, err := epoch.protection(1).open(received); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

// A member holds every ratchet of the epoch, so it can encrypt whatever it likes under another sender's
// name. The signature, which also covers authenticated_data, is what stops it, and the real sender's
// generation survives the attempt.
func TestMlsMemberForgingAuthenticatedDataFailsTheSignature(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	authenticated := epoch.signedCommit(0, []byte("generation 1"), mlsTestRemoveCommit(1))

	forged := *authenticated
	forged.content.authenticatedData = []byte("generation 9")
	message, err := epoch.protection(2).seal(&forged)
	if err != nil {
		t.Fatal(err)
	}

	receiver := epoch.protection(1)
	_, err = receiver.open(mlsTestPrivateOnTheWire(t, message))
	if !errors.Is(err, errMlsAuthentication) {
		t.Fatalf("forgery: %v", err)
	}

	// the sender's own message, at the very generation the forgery claimed, still opens
	honest, err := epoch.protection(0).seal(authenticated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.open(mlsTestPrivateOnTheWire(t, honest)); err != nil {
		t.Fatalf("the honest message after a forgery: %v", err)
	}
}

// A commit signed by another member's key under this sender's name, encrypted with keys every member
// holds.
func TestMlsSignatureMustBeTheSendersKey(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	authenticated := epoch.signedCommit(0, []byte("header"), mlsTestRemoveCommit(1))
	if err := authenticated.sign(mlsSuite, epoch.group.members[2].signatureKey, epoch.encodedGroupContext()); err != nil {
		t.Fatal(err)
	}
	message, err := epoch.protection(0).seal(authenticated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := epoch.protection(1).open(mlsTestPrivateOnTheWire(t, message)); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

// The signature covers the wire format, so a PublicMessage's signature means nothing inside a
// PrivateMessage, and the GroupContext, so one epoch's signature means nothing in another.
func TestMlsSignatureBindsTheWireFormatAndTheEpoch(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	wrongFormat := epoch.signedCommit(0, []byte("header"), mlsTestRemoveCommit(1))
	wrongFormat.wireFormat = mlsWireFormatPublicMessage
	if err := wrongFormat.sign(mlsSuite, epoch.group.members[0].signatureKey, epoch.encodedGroupContext()); err != nil {
		t.Fatal(err)
	}
	wrongFormat.wireFormat = mlsWireFormatPrivateMessage
	message, err := epoch.protection(0).seal(wrongFormat)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := epoch.protection(1).open(mlsTestPrivateOnTheWire(t, message)); !errors.Is(err, errMlsAuthentication) {
		t.Errorf("signed as a PublicMessage: %v", err)
	}

	wrongContext := epoch.signedCommit(0, []byte("header"), mlsTestRemoveCommit(1))
	if err := wrongContext.sign(mlsSuite, epoch.group.members[0].signatureKey, []byte("another group context")); err != nil {
		t.Fatal(err)
	}
	message, err = epoch.protection(0).seal(wrongContext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := epoch.protection(1).open(mlsTestPrivateOnTheWire(t, message)); !errors.Is(err, errMlsAuthentication) {
		t.Errorf("signed under another GroupContext: %v", err)
	}
}

func TestMlsReplayedCommitIsRefused(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	message := epoch.sealed(epoch.protection(0), 0)
	receiver := epoch.protection(1)
	if _, err := receiver.open(mlsTestPrivateOnTheWire(t, message)); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.open(mlsTestPrivateOnTheWire(t, message)); !errors.Is(err, errMlsGeneration) {
		t.Fatal(err)
	}
}

// RFC §9.2: the ratchet moved on and kept nothing of what it used, so a generation cannot be reached
// again, even by a receiver asked to.
func TestMlsOpenDeletesConsumedKeysAtOnce(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	sender := epoch.protection(0)
	first := epoch.sealed(sender, 0)
	second := epoch.sealed(sender, 0)

	receiver := epoch.protection(1)
	ratchets, err := receiver.secretTree.ratchets(0)
	if err != nil {
		t.Fatal(err)
	}
	secretBefore := bytes.Clone(ratchets.handshake.secret)
	if _, err := receiver.open(mlsTestPrivateOnTheWire(t, second)); err != nil {
		t.Fatal(err)
	}
	if ratchets.handshake.generation != 2 {
		t.Errorf("next generation %d", ratchets.handshake.generation)
	}
	if bytes.Equal(ratchets.handshake.secret, secretBefore) {
		t.Error("the ratchet still holds its old secret")
	}
	// skipped keys are not kept: the first message, now behind the ratchet, cannot open
	if _, err := receiver.open(mlsTestPrivateOnTheWire(t, first)); !errors.Is(err, errMlsGeneration) {
		t.Fatal(err)
	}
}

// A step left open by a failure must leave no key behind.
func TestMlsFailedOpenLeavesNoKeyInTheStep(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	message := epoch.sealed(epoch.protection(0), 0)
	message.ciphertext[len(message.ciphertext)-1] ^= 1
	receiver := epoch.protection(1)
	if _, err := receiver.open(mlsTestPrivateOnTheWire(t, message)); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
	ratchets, err := receiver.secretTree.ratchets(0)
	if err != nil {
		t.Fatal(err)
	}
	if ratchets.handshake.generation != 0 {
		t.Fatalf("next generation %d after a failed open", ratchets.handshake.generation)
	}
}

func TestMlsSealNeverReusesAGeneration(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	sender := epoch.protection(0)
	opener := epoch.protection(1)
	var generations []uint32
	for range 3 {
		message := epoch.sealed(sender, 0)
		senderData, err := opener.openSenderData(message)
		if err != nil {
			t.Fatal(err)
		}
		generations = append(generations, senderData.generation)
	}
	if !slices.Equal(generations, []uint32{0, 1, 2}) {
		t.Fatalf("generations %v", generations)
	}
}

// Generations a sender skipped, as when gkm dropped an attempt: the ratchet jumps them, and only past
// the settings' bound is a message too far ahead.
func TestMlsOpenJumpsToALaterGeneration(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	sender := epoch.protection(0)
	var last *mlsPrivateMessage
	for range 4 {
		last = epoch.sealed(sender, 0)
	}
	if _, err := epoch.protection(1).open(mlsTestPrivateOnTheWire(t, last)); err != nil {
		t.Fatal(err)
	}

	settings := defaultMlsMessageSettings()
	settings.SecretTree = &mlsSecretTreeSettings{MaximumForwardDistance: 2}
	receiver, err := newMlsMessageProtection(
		mlsSuite, settings, epoch.groupContext, epoch.group.members[1].tree, epoch.encryptionSecret, epoch.senderDataSecret,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.open(mlsTestPrivateOnTheWire(t, last)); !errors.Is(err, errMlsGeneration) {
		t.Fatal(err)
	}
}

// RFC §6.3.2: a sender at a blank leaf is refused before any ratchet is touched, however good its
// keys. The sealer here is a member removed since, who still holds the epoch's secrets.
func TestMlsBlankSenderIsRefused(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 4)
	removedSender := epoch.protection(1)
	message := epoch.sealed(removedSender, 1)

	tree := epoch.group.members[0].tree.clone()
	if err := tree.removeLeaf(1); err != nil {
		t.Fatal(err)
	}
	receiver, err := newMlsMessageProtection(
		mlsSuite, defaultMlsMessageSettings(), epoch.groupContext, tree, epoch.encryptionSecret, epoch.senderDataSecret,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.open(mlsTestPrivateOnTheWire(t, message)); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
	if count := len(receiver.secretTree.leafIndexRatchets); count != 0 {
		t.Errorf("%d ratchets derived for a refused sender", count)
	}
}

// A sender index past the tree is blank too, and must not wrap into it.
func TestMlsSenderOutsideTheTreeIsRefused(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 2)
	for _, leaf := range []mlsLeafIndex{2, 0x80000000, 0xffffffff} {
		senderData := &mlsSenderData{leafIndex: leaf}
		receiver := epoch.protection(0)
		message := &mlsPrivateMessage{
			groupId:     epoch.groupContext.groupId,
			epoch:       epoch.groupContext.epoch,
			contentType: mlsContentTypeCommit,
			ciphertext:  []byte("ciphertext"),
		}
		key, nonce, err := mlsSuite.deriveSenderDataKey(epoch.senderDataSecret, message.ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		additionalData, err := message.senderDataAad()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := mlsMarshal(senderData)
		if err != nil {
			t.Fatal(err)
		}
		if message.encryptedSenderData, err = mlsSuite.aeadSeal(key, nonce, additionalData, encoded); err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.openPrivate(message, mlsReadCommit); !errors.Is(err, errMlsInvalid) {
			t.Errorf("leaf %#x: %v", leaf, err)
		}
	}
}

func TestMlsSenderDataRefusesAnotherLength(t *testing.T) {
	for _, length := range []int{11, 13} {
		if err := mlsUnmarshal(make([]byte, length), &mlsSenderData{}); !errors.Is(err, errMlsMalformed) {
			t.Errorf("%d bytes: %v", length, err)
		}
	}
	senderData := &mlsSenderData{leafIndex: 7, generation: 9, reuseGuard: [4]byte{1, 2, 3, 4}}
	encoded, err := mlsMarshal(senderData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, []byte{0, 0, 0, 7, 0, 0, 0, 9, 1, 2, 3, 4}) {
		t.Fatalf("%x", encoded)
	}
	decoded := &mlsSenderData{}
	if err := mlsUnmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if *decoded != *senderData {
		t.Fatalf("%+v", decoded)
	}
}

// RFC §6.3.1 has the guard change the nonce, so the key schedule's nonce alone must not open a
// message.
func TestMlsReuseGuardEntersTheNonce(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	message := epoch.sealed(epoch.protection(0), 0)
	reader := epoch.protection(1)
	senderData, err := reader.openSenderData(message)
	if err != nil {
		t.Fatal(err)
	}
	if senderData.reuseGuard == [mlsReuseGuardLength]byte{} {
		t.Fatal("no guard")
	}
	ratchets, err := reader.secretTree.ratchets(0)
	if err != nil {
		t.Fatal(err)
	}
	step, err := ratchets.handshake.stepTo(senderData.generation)
	if err != nil {
		t.Fatal(err)
	}
	additionalData, err := message.contentAad()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mlsSuite.aeadOpen(step.key, step.nonce, additionalData, message.ciphertext); !errors.Is(err, errMlsAuthentication) {
		t.Errorf("the unguarded nonce: %v", err)
	}
	senderData.guardNonce(step.nonce)
	if _, err := mlsSuite.aeadOpen(step.key, step.nonce, additionalData, message.ciphertext); err != nil {
		t.Errorf("the guarded nonce: %v", err)
	}
}

// Two seals with a lost ratchet, the failure the guard exists for: both draw generation 0, and still
// use different nonces.
func TestMlsReuseGuardsDifferBetweenTwoLostRatchets(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	first := epoch.sealed(epoch.protection(0), 0)
	second := epoch.sealed(epoch.protection(0), 0)
	reader := epoch.protection(1)
	firstData, err := reader.openSenderData(first)
	if err != nil {
		t.Fatal(err)
	}
	secondData, err := reader.openSenderData(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstData.generation != secondData.generation {
		t.Fatalf("generations %d and %d", firstData.generation, secondData.generation)
	}
	if firstData.reuseGuard == secondData.reuseGuard {
		t.Fatal("one guard twice")
	}
	if bytes.Equal(first.ciphertext, second.ciphertext) {
		t.Fatal("one ciphertext twice")
	}
}

func TestMlsPaddingOfZerosIsTaken(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	settings := defaultMlsMessageSettings()
	settings.PaddingLength = 100
	sender, err := newMlsMessageProtection(
		mlsSuite, settings, epoch.groupContext, epoch.group.members[0].tree, epoch.encryptionSecret, epoch.senderDataSecret,
	)
	if err != nil {
		t.Fatal(err)
	}
	padded := epoch.sealed(sender, 0)
	unpadded := epoch.sealed(epoch.protection(0), 0)
	if len(padded.ciphertext) != len(unpadded.ciphertext)+100 {
		t.Errorf("ciphertext of %d bytes, %d without padding", len(padded.ciphertext), len(unpadded.ciphertext))
	}
	if _, err := epoch.protection(1).open(mlsTestPrivateOnTheWire(t, padded)); err != nil {
		t.Fatal(err)
	}

	settings.PaddingLength = -1
	if _, err := sender.seal(epoch.signedCommit(0, nil, mlsTestRemoveCommit(1))); err != nil {
		t.Fatalf("negative padding: %v", err)
	}
}

// The plaintext of a commit from this sender, signed, with these bytes after it.
func (self *mlsTestEpoch) plaintextWith(sender mlsLeafIndex, padding []byte) (*mlsPrivateMessage, []byte) {
	self.t.Helper()
	authenticated := self.signedCommit(sender, []byte("header"), mlsTestRemoveCommit(1))
	encoder := &mlsEncoder{}
	authenticated.content.body.encode(encoder)
	authenticated.auth.encode(encoder, mlsContentTypeCommit)
	encoder.writeFixed(padding)
	plaintext, err := encoder.finish()
	if err != nil {
		self.t.Fatal(err)
	}
	return &mlsPrivateMessage{
		groupId:           self.groupContext.groupId,
		epoch:             self.groupContext.epoch,
		contentType:       mlsContentTypeCommit,
		authenticatedData: []byte("header"),
	}, plaintext
}

// RFC §6.3.1: padding that is not zero rejects the message as malformed, signature or no signature, so
// padding cannot be a covert channel.
func TestMlsPaddingOfAnythingElseIsRefused(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	for _, padding := range [][]byte{{1}, {0, 0, 0, 1}, {1, 0, 0, 0}, {0xff}} {
		message, plaintext := epoch.plaintextWith(0, padding)
		if err := epoch.protection(0).sealPlaintext(message, 0, plaintext); err != nil {
			t.Fatal(err)
		}
		receiver := epoch.protection(1)
		if _, err := receiver.open(mlsTestPrivateOnTheWire(t, message)); !errors.Is(err, errMlsMalformed) {
			t.Errorf("padding %x: %v", padding, err)
		}
		ratchets, err := receiver.secretTree.ratchets(0)
		if err != nil {
			t.Fatal(err)
		}
		if ratchets.handshake.generation != 0 {
			t.Errorf("padding %x cost the sender its generation", padding)
		}
	}

	// the same plaintext with zeros opens, so it is the padding that was refused
	message, plaintext := epoch.plaintextWith(0, make([]byte, 4))
	if err := epoch.protection(0).sealPlaintext(message, 0, plaintext); err != nil {
		t.Fatal(err)
	}
	if _, err := epoch.protection(1).open(mlsTestPrivateOnTheWire(t, message)); err != nil {
		t.Fatal(err)
	}
}

func TestMlsSealRefusals(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	cases := []struct {
		name   string
		change func(authenticated *mlsAuthenticatedContent)
		want   error
	}{
		{name: "application", change: func(authenticated *mlsAuthenticatedContent) {
			authenticated.content.contentType = mlsContentTypeApplication
		}, want: errMlsRefused},
		{name: "proposal", change: func(authenticated *mlsAuthenticatedContent) {
			authenticated.content.contentType = mlsContentTypeProposal
		}, want: errMlsRefused},
		{name: "unknown content", change: func(authenticated *mlsAuthenticatedContent) {
			authenticated.content.contentType = 9
		}, want: errMlsMalformed},
		{name: "a public wire format", change: func(authenticated *mlsAuthenticatedContent) {
			authenticated.wireFormat = mlsWireFormatPublicMessage
		}, want: errMlsRefused},
		{name: "a new member", change: func(authenticated *mlsAuthenticatedContent) {
			authenticated.content.sender = mlsSender{senderType: mlsSenderTypeNewMemberCommit}
		}, want: errMlsRefused},
		{name: "another epoch", change: func(authenticated *mlsAuthenticatedContent) {
			authenticated.content.epoch += 1
		}, want: errMlsOtherEpoch},
	}
	for _, c := range cases {
		sender := epoch.protection(0)
		authenticated := epoch.signedCommit(0, nil, mlsTestRemoveCommit(1))
		c.change(authenticated)
		if _, err := sender.seal(authenticated); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		// nothing was drawn for a message that was never sealed
		ratchets, err := sender.secretTree.ratchets(0)
		if err != nil {
			t.Fatal(err)
		}
		if ratchets.handshake.generation != 0 {
			t.Errorf("%s spent a generation", c.name)
		}
	}

	noBody := epoch.signedCommit(0, nil, mlsTestRemoveCommit(1))
	noBody.content.body = nil
	if _, err := epoch.protection(0).seal(noBody); err == nil {
		t.Error("no body was sealed")
	}
	if _, err := mlsMarshal(&noBody.content); err == nil {
		t.Error("no body was encoded")
	}
}

func TestMlsOpenRefusesOtherWireFormats(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 2)
	if _, err := epoch.protection(0).open(&mlsMessage{wireFormat: 3}); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
}

func TestMlsProtectionEraseOverwritesItsSecrets(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	protection := epoch.protection(0)
	message := epoch.sealed(protection, 0)
	senderDataSecret := protection.senderDataSecret
	protection.erase()
	if !bytes.Equal(senderDataSecret, make([]byte, mlsSuite.hashLength)) {
		t.Error("sender_data_secret survived")
	}
	if 0 < len(protection.secretTree.nodeIndexSecrets) || 0 < len(protection.secretTree.leafIndexRatchets) {
		t.Error("the secret tree survived")
	}
	if _, err := protection.open(mlsTestPrivateOnTheWire(t, message)); err == nil {
		t.Error("an erased epoch opened a message")
	}
}

// The caller keeps its own copies, and the epoch's end must not reach them.
func TestMlsProtectionCopiesItsSecrets(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	want := bytes.Clone(epoch.senderDataSecret)
	protection := epoch.protection(0)
	protection.erase()
	if !bytes.Equal(epoch.senderDataSecret, want) {
		t.Fatal("erasing reached the caller's secret")
	}
}

// A GroupContext no signature could cover builds no protection. external_senders is refused in every
// list written (§10.4), which fails the encoding as cheaply on wasm as anywhere, where a vector past
// the codec's maximum would take a gigabyte to build.
func TestMlsProtectionRefusesAnUnencodableContext(t *testing.T) {
	tree := mlsShapedTree(mlsShapeLeaf("a"))
	groupContext := &mlsGroupContext{extensions: []mlsExtension{{extensionType: mlsExtensionTypeExternalSenders}}}
	if _, err := newMlsMessageProtection(mlsSuite, defaultMlsMessageSettings(), groupContext, tree, nil, nil); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
}

func TestMlsHeaderReadsAPrivateMessageWithNoKey(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	message, err := epoch.protection(0).seal(epoch.signedCommit(0, []byte("header"), mlsTestRemoveCommit(1)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mlsMarshal(&mlsMessage{wireFormat: mlsWireFormatPrivateMessage, privateMessage: message})
	if err != nil {
		t.Fatal(err)
	}
	header, err := ParseMlsHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header.GroupId, epoch.groupContext.groupId) {
		t.Errorf("group %q", header.GroupId)
	}
	if header.Epoch != epoch.groupContext.epoch {
		t.Errorf("epoch %d", header.Epoch)
	}
	if header.ContentType != mlsContentTypeCommit {
		t.Errorf("content type %d", header.ContentType)
	}
	if !bytes.Equal(header.AuthenticatedData, []byte("header")) {
		t.Errorf("authenticated data %q", header.AuthenticatedData)
	}
	// owner decision 59: a member commit shows no proposal, credential or tree
	if header.External != nil {
		t.Errorf("a PrivateMessage showed %+v", header.External)
	}
}

func TestMlsHeaderReadsAnExternalCommitWithNoKey(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	_, message := epoch.externalCommit(1)
	encoded, err := mlsMarshal(&mlsMessage{wireFormat: mlsWireFormatPublicMessage, publicMessage: message})
	if err != nil {
		t.Fatal(err)
	}
	header, err := ParseMlsHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if header.Epoch != epoch.groupContext.epoch || !bytes.Equal(header.AuthenticatedData, []byte("header")) {
		t.Errorf("header %+v", header)
	}
	external := header.External
	if external == nil {
		t.Fatal("no external commit")
	}
	if !bytes.Equal(external.Credential, []byte("external joiner")) {
		t.Errorf("credential %q", external.Credential)
	}
	if external.RemovedLeaf == nil || *external.RemovedLeaf != 1 {
		t.Errorf("removed leaf %v", external.RemovedLeaf)
	}
}

// A recovery self-join removes no leaf (§10.9's External row), so gkm reads none from it; and RFC
// §12.4.3.2 fixes no order between an ExternalInit and a Remove.
func TestMlsHeaderReadsARecoverySelfJoinAndEitherOrder(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	_, message := epoch.externalCommit(2)
	commit := message.content.commit()
	externalInit, remove := commit.proposals[0], commit.proposals[1]
	removedLeaf := uint32(2)
	cases := []struct {
		name      string
		proposals []mlsProposal
		removed   *uint32
	}{
		{name: "a self-join", proposals: []mlsProposal{externalInit}, removed: nil},
		{name: "a Remove first", proposals: []mlsProposal{remove, externalInit}, removed: &removedLeaf},
	}
	for _, c := range cases {
		commit.proposals = c.proposals
		encoded, err := mlsMarshal(&mlsMessage{wireFormat: mlsWireFormatPublicMessage, publicMessage: message})
		if err != nil {
			t.Fatal(err)
		}
		header, err := ParseMlsHeader(encoded)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := header.External.RemovedLeaf; (got == nil) != (c.removed == nil) || (got != nil && *got != *c.removed) {
			t.Errorf("%s: removed leaf %v", c.name, got)
		}
		if !bytes.Equal(header.External.Credential, []byte("external joiner")) {
			t.Errorf("%s: credential %q", c.name, header.External.Credential)
		}
	}
}

// RFC §12.4.3.2, less §10.4's PSKs: an external commit holds one ExternalInit and at most one Remove,
// and anything else is refused when parsed, before gkm reads its header or a member checks it.
func TestMlsExternalCommitHoldsOneExternalInitAndAtMostOneRemove(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	added := mlsNewTestClient(t, mlsSuite, "added")
	externalInit := mlsProposal{proposalType: mlsProposalTypeExternalInit, kemOutput: []byte("kem output")}
	remove := func(leaf mlsLeafIndex) mlsProposal {
		return mlsProposal{proposalType: mlsProposalTypeRemove, removed: leaf}
	}
	cases := []struct {
		name      string
		proposals []mlsProposal
	}{
		{name: "no proposal", proposals: nil},
		{name: "a Remove alone", proposals: []mlsProposal{remove(1)}},
		{name: "two ExternalInits", proposals: []mlsProposal{externalInit, externalInit}},
		{name: "two Removes", proposals: []mlsProposal{externalInit, remove(1), remove(2)}},
		{name: "an Add", proposals: []mlsProposal{externalInit, {proposalType: mlsProposalTypeAdd, keyPackage: added.keyPackage}}},
		{name: "a GroupContextExtensions", proposals: []mlsProposal{externalInit, {proposalType: mlsProposalTypeGroupContextExtensions}}},
	}
	for _, c := range cases {
		_, message := epoch.externalCommit(1)
		message.content.commit().proposals = c.proposals
		encoded, err := mlsMarshal(&mlsMessage{wireFormat: mlsWireFormatPublicMessage, publicMessage: message})
		if err != nil {
			t.Fatal(err)
		}
		if err := mlsUnmarshal(encoded, &mlsMessage{}); !errors.Is(err, errMlsInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, err := ParseMlsHeader(encoded); !errors.Is(err, errMlsInvalid) {
			t.Errorf("header of %s: %v", c.name, err)
		}
	}
}

// The header owns what it returns, so gkm may reuse the buffer a request arrived in.
func TestMlsHeaderCopiesWhatItReturns(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	_, public := epoch.externalCommit(1)
	for _, value := range []*mlsMessage{
		{wireFormat: mlsWireFormatPrivateMessage, privateMessage: epoch.sealed(epoch.protection(0), 0)},
		{wireFormat: mlsWireFormatPublicMessage, publicMessage: public},
	} {
		encoded, err := mlsMarshal(value)
		if err != nil {
			t.Fatal(err)
		}
		header, err := ParseMlsHeader(encoded)
		if err != nil {
			t.Fatal(err)
		}
		groupId, authenticatedData := bytes.Clone(header.GroupId), bytes.Clone(header.AuthenticatedData)
		var credential []byte
		if header.External != nil {
			credential = bytes.Clone(header.External.Credential)
		}
		clear(encoded)
		if !bytes.Equal(header.GroupId, groupId) || !bytes.Equal(header.AuthenticatedData, authenticatedData) {
			t.Errorf("wire format %#x: the header changed with its buffer", value.wireFormat)
		}
		if header.External != nil && !bytes.Equal(header.External.Credential, credential) {
			t.Error("the credential changed with its buffer")
		}
	}
}

// D-KEYS-3: what gkm reads out of authenticated_data is the real GkmCommitHeader, generation and auth
// pin, however the commit is framed.
func TestMlsHeaderCarriesGkmCommitHeader(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	want := &protocol.GkmCommitHeader{Generation: 7, Auth: &bridge.AuthPin{Version: 41, Chain: bytes.Repeat([]byte{9}, 32)}}
	authenticatedData, err := proto.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	message, err := epoch.protection(0).seal(epoch.signedCommit(0, authenticatedData, mlsTestRemoveCommit(1)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mlsMarshal(&mlsMessage{wireFormat: mlsWireFormatPrivateMessage, privateMessage: message})
	if err != nil {
		t.Fatal(err)
	}
	header, err := ParseMlsHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got := &protocol.GkmCommitHeader{}
	if err := proto.Unmarshal(header.AuthenticatedData, got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("header %v", got)
	}
}

// The clear header of a commit, ready to take what a case puts after it.
func mlsTestFramingPrefix(encoder *mlsEncoder, wireFormat uint16) {
	encoder.writeUint16(mlsProtocolVersion10)
	encoder.writeUint16(wireFormat)
	encoder.writeVector([]byte("group"))
	encoder.writeUint64(1)
}

// A commit's proposals vector holding one element, and no path.
func mlsTestCommitOf(element []byte) []byte {
	encoder := &mlsEncoder{}
	encoder.writeVector(element)
	encoder.writeOptional(false)
	return encoder.encoded
}

// A member or new sender's PublicMessage around these bytes.
func mlsTestPublicFrame(senderType uint8, contentType uint8, body []byte) []byte {
	encoder := &mlsEncoder{}
	mlsTestFramingPrefix(encoder, mlsWireFormatPublicMessage)
	encoder.writeUint8(senderType)
	if senderType == mlsSenderTypeMember || senderType == mlsSenderTypeExternal {
		encoder.writeUint32(1)
	}
	encoder.writeVector(nil)
	encoder.writeUint8(contentType)
	encoder.writeFixed(body)
	return encoder.encoded
}

// A PrivateMessage with this clear content type and empty ciphertexts.
func mlsTestPrivateFrame(contentType uint8) []byte {
	encoder := &mlsEncoder{}
	mlsTestFramingPrefix(encoder, mlsWireFormatPrivateMessage)
	encoder.writeUint8(contentType)
	encoder.writeVector(nil)
	encoder.writeVector([]byte("sender data"))
	encoder.writeVector([]byte("ciphertext"))
	return encoder.encoded
}

// One inline proposal of this type, whatever follows it.
func mlsTestInlineProposal(proposalType uint16, body ...byte) []byte {
	encoder := &mlsEncoder{}
	encoder.writeUint8(mlsProposalOrRefTypeProposal)
	encoder.writeUint16(proposalType)
	encoder.writeFixed(body)
	return encoder.encoded
}

// §10.4's refused list, at each path a peer's bytes can take into a parser: an MLSMessage, the header
// gkm reads, a bare Commit, and a commit decrypted out of a PrivateMessage. A refusal is
// errMlsRefused, so nothing outside the subset reads as merely broken, and each case names the row
// of §10.4 it stands for.
func TestMlsRefusedFeaturesAtEveryParsePath(t *testing.T) {
	reference := append([]byte{mlsProposalOrRefTypeReference, 32}, make([]byte, 32)...)
	commitElements := []struct {
		name    string
		element []byte
	}{
		{name: "a proposal by reference, so a standalone one", element: reference},
		{name: "an Update proposal", element: mlsTestInlineProposal(mlsProposalTypeUpdate)},
		{name: "a PSK", element: mlsTestInlineProposal(mlsProposalTypePsk)},
		{name: "a ReInit", element: mlsTestInlineProposal(mlsProposalTypeReInit)},
		{name: "an unknown proposal type", element: mlsTestInlineProposal(0x0a0a)},
	}
	// the path a peer's bytes take through a decrypting member
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	for _, c := range commitElements {
		commit := mlsTestCommitOf(c.element)
		if err := mlsUnmarshal(commit, &mlsCommit{}); !errors.Is(err, errMlsRefused) {
			t.Errorf("commit with %s: %v", c.name, err)
		}

		// a PublicMessage shows it in the clear
		encoded := mlsTestPublicFrame(mlsSenderTypeNewMemberCommit, mlsContentTypeCommit, commit)
		if err := mlsUnmarshal(encoded, &mlsMessage{}); !errors.Is(err, errMlsRefused) {
			t.Errorf("public commit with %s: %v", c.name, err)
		}
		if _, err := ParseMlsHeader(encoded); !errors.Is(err, errMlsRefused) {
			t.Errorf("header of a public commit with %s: %v", c.name, err)
		}

		// a PrivateMessage hides it until it decrypts, and the opener is the one to refuse it
		authenticated := epoch.signedCommit(0, []byte("header"), mlsTestContent(commit))
		sealed, err := epoch.protection(0).seal(authenticated)
		if err != nil {
			t.Fatal(err)
		}
		receiver := epoch.protection(1)
		if _, err := receiver.open(mlsTestPrivateOnTheWire(t, sealed)); !errors.Is(err, errMlsRefused) {
			t.Errorf("sealed commit with %s: %v", c.name, err)
		}
		ratchets, err := receiver.secretTree.ratchets(0)
		if err != nil {
			t.Fatal(err)
		}
		if ratchets.handshake.generation != 0 {
			t.Errorf("sealed commit with %s spent a generation", c.name)
		}
	}

	messages := []struct {
		name    string
		encoded []byte
		want    error
	}{
		{name: "application content, private", encoded: mlsTestPrivateFrame(mlsContentTypeApplication), want: errMlsRefused},
		{name: "a standalone proposal, private", encoded: mlsTestPrivateFrame(mlsContentTypeProposal), want: errMlsRefused},
		{name: "an unknown content type, private", encoded: mlsTestPrivateFrame(0), want: errMlsMalformed},
		{name: "a content type past commit, private", encoded: mlsTestPrivateFrame(4), want: errMlsMalformed},

		{
			name:    "application content, public",
			encoded: mlsTestPublicFrame(mlsSenderTypeNewMemberCommit, mlsContentTypeApplication, []byte{0}),
			want:    errMlsRefused,
		},
		{
			name:    "a standalone proposal, public",
			encoded: mlsTestPublicFrame(mlsSenderTypeNewMemberCommit, mlsContentTypeProposal, []byte{0, 3, 0, 0, 0, 0}),
			want:    errMlsRefused,
		},
		{
			name:    "an unknown content type, public",
			encoded: mlsTestPublicFrame(mlsSenderTypeNewMemberCommit, 0, nil),
			want:    errMlsMalformed,
		},
		{
			name:    "a member's PublicMessage",
			encoded: mlsTestPublicFrame(mlsSenderTypeMember, mlsContentTypeCommit, []byte{0, 0}),
			want:    errMlsRefused,
		},
		{
			name:    "an external sender",
			encoded: mlsTestPublicFrame(mlsSenderTypeExternal, mlsContentTypeCommit, []byte{0, 0}),
			want:    errMlsRefused,
		},
		{
			name:    "a new member's proposal",
			encoded: mlsTestPublicFrame(mlsSenderTypeNewMemberProposal, mlsContentTypeProposal, []byte{0, 3, 0, 0, 0, 0}),
			want:    errMlsRefused,
		},
		{
			name:    "an unknown sender type",
			encoded: mlsTestPublicFrame(9, mlsContentTypeCommit, []byte{0, 0}),
			want:    errMlsMalformed,
		},
		{
			name:    "an external commit with no path",
			encoded: mlsTestPublicFrame(mlsSenderTypeNewMemberCommit, mlsContentTypeCommit, []byte{0, 0}),
			want:    errMlsInvalid,
		},

		{name: "a Welcome", encoded: []byte{0, 1, 0, 3, 0}, want: errMlsRefused},
		{name: "a GroupInfo", encoded: []byte{0, 1, 0, 4, 0}, want: errMlsRefused},
		{name: "a KeyPackage", encoded: []byte{0, 1, 0, 5, 0}, want: errMlsRefused},
		{name: "an unknown wire format", encoded: []byte{0, 1, 0xff, 0xff}, want: errMlsRefused},
		{name: "another version", encoded: []byte{0, 2, 0, 2}, want: errMlsRefused},
		{name: "the reserved version", encoded: []byte{0, 0, 0, 2}, want: errMlsRefused},
		{name: "nothing", encoded: nil, want: errMlsMalformed},
		{name: "half a version", encoded: []byte{0}, want: errMlsMalformed},
		{name: "a version alone", encoded: []byte{0, 1}, want: errMlsMalformed},
	}
	for _, c := range messages {
		if err := mlsUnmarshal(c.encoded, &mlsMessage{}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, err := ParseMlsHeader(c.encoded); !errors.Is(err, c.want) {
			t.Errorf("header of %s: %v", c.name, err)
		}
	}

	// senders are refused alone, too
	for _, senderType := range []uint8{mlsSenderTypeExternal, mlsSenderTypeNewMemberProposal} {
		decoder := &mlsDecoder{remaining: []byte{senderType, 0, 0, 0, 0}}
		var sender mlsSender
		sender.decode(decoder)
		if !errors.Is(decoder.err, errMlsRefused) {
			t.Errorf("sender type %d: %v", senderType, decoder.err)
		}
		encoder := &mlsEncoder{}
		(&mlsSender{senderType: senderType}).encode(encoder)
		if !errors.Is(encoder.err, errMlsRefused) {
			t.Errorf("encoding sender type %d: %v", senderType, encoder.err)
		}
	}
}

// RFC §12.4's ProposalOrRef admits only its two types, and neither reference nor junk reads as a
// proposal.
func TestMlsCommitRefusesAnUnknownProposalOrRef(t *testing.T) {
	if err := mlsUnmarshal(mlsTestCommitOf([]byte{9, 0, 3, 0, 0, 0, 1}), &mlsCommit{}); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

func TestMlsCommitRoundTrip(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsSuite, 3)
	updatePath, _, _ := mlsPreparedCommit(t, group, 0)
	cases := []struct {
		name   string
		commit *mlsCommit
	}{
		{name: "empty", commit: &mlsCommit{}},
		{name: "path only", commit: &mlsCommit{path: updatePath}},
		{name: "proposals only", commit: mlsTestRemoveCommit(1)},
		{name: "both", commit: &mlsCommit{proposals: mlsTestRemoveCommit(2).proposals, path: updatePath}},
	}
	for _, c := range cases {
		encoded, err := mlsMarshal(c.commit)
		if err != nil {
			t.Fatal(err)
		}
		decoded := &mlsCommit{}
		if err := mlsUnmarshal(encoded, decoded); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		reencoded, err := mlsMarshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Errorf("%s re-encoded differently", c.name)
		}
	}
	if err := mlsUnmarshal([]byte{0, 2}, &mlsCommit{}); !errors.Is(err, errMlsMalformed) {
		t.Errorf("a presence octet of 2: %v", err)
	}
}

// Nothing a canonical encoder would not write gets through, on either framing.
func TestMlsMessageRefusesWhatIsLeftOver(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	message := epoch.sealed(epoch.protection(0), 0)
	_, public := epoch.externalCommit(1)
	for _, value := range []*mlsMessage{
		{wireFormat: mlsWireFormatPrivateMessage, privateMessage: message},
		{wireFormat: mlsWireFormatPublicMessage, publicMessage: public},
	} {
		encoded, err := mlsMarshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseMlsHeader(append(bytes.Clone(encoded), 0)); !errors.Is(err, errMlsMalformed) {
			t.Errorf("wire format %#x: %v", value.wireFormat, err)
		}
		if _, err := ParseMlsHeader(encoded[:len(encoded)-1]); !errors.Is(err, errMlsMalformed) {
			t.Errorf("wire format %#x, cut short: %v", value.wireFormat, err)
		}
	}
}

// §10.4's signature is Ed25519's, so an external commit whose leaf carries another key size verifies
// nothing rather than failing some other way.
func TestMlsExternalCommitWithABadKeyVerifiesNothing(t *testing.T) {
	epoch := mlsNewTestEpoch(t, mlsSuite, 3)
	_, message := epoch.externalCommit(1)
	message.content.commit().path.leafNode.signatureKey = make([]byte, ed25519.PublicKeySize-1)
	if _, err := epoch.protection(0).openPublic(message); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}
