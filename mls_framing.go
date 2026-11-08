// Message framing (RFC 9420 §6): how a commit travels, and what it proves on arrival.
//
// §10.4 frames one content, a commit, in two ways (D-KEYS-3). A member's commit is a PrivateMessage,
// whose clear header shows group_id, epoch, content type and authenticated_data. An external commit
// comes from a sender holding no key of the epoch, so it is a PublicMessage, which RFC §6.2 gives no
// membership tag when its sender is new. Everything else RFC §6 frames is refused when parsed:
// application data, standalone proposals, external senders and a member's PublicMessage. The
// refusals sit in the decoders of the two messages, so nothing reaches a key or a signature check
// without passing them.
//
// authenticated_data is clear, which lets gkm read a commit's GkmCommitHeader with no key
// (ParseMlsHeader; I-1), and bound into the AEAD and the signature, which lets every member catch a
// server that changed it.
//
// A commit is signed before its tag can exist, because the signature enters the transcript hash that
// keys the epoch the tag comes from (mls_transcript.go). So a committer fills in one
// mlsAuthenticatedContent in steps: sign, derive the new epoch from its transcript hash, set the
// confirmation tag, then seal. A receiver gets the same value back from open, signature checked, and
// checks the tag once it has derived that epoch.
//
// A sender draws its generation before it encrypts and a receiver gives one up only after the
// signature holds: every member can derive every sender's ratchet, so a valid AEAD proves only
// membership, and a forgery must not cost the real sender its key (mls_secrettree.go).
//
// mlsMessageProtection is not safe for concurrent use; one group state owns it.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
)

// WireFormat (RFC §17.2): the two that carry a commit.
const (
	mlsWireFormatPublicMessage  uint16 = 0x0001
	mlsWireFormatPrivateMessage uint16 = 0x0002
)

// ContentType (RFC §6).
const (
	mlsContentTypeApplication uint8 = 1
	mlsContentTypeProposal    uint8 = 2
	mlsContentTypeCommit      uint8 = 3
)

// SenderType (RFC §6).
const (
	mlsSenderTypeMember            uint8 = 1
	mlsSenderTypeExternal          uint8 = 2
	mlsSenderTypeNewMemberProposal uint8 = 3
	mlsSenderTypeNewMemberCommit   uint8 = 4
)

const (
	// What MlsHeader.ContentType holds, the one content §10.4 frames.
	MlsContentTypeCommit = mlsContentTypeCommit

	// Signature labels (RFC §17.6).
	mlsSignatureLabelFramedContent = "FramedContentTBS"

	// SenderData's reuse_guard (RFC §6.3.2).
	mlsReuseGuardLength = 4
)

// A message of another group or epoch, which says nothing about this one, so a caller routes it and
// does not judge it.
var errMlsOtherEpoch = errors.New("mls: message of another group or epoch")

// Tunes message protection.
type mlsMessageSettings struct {
	// Zero bytes a sealed commit carries past its content, which RFC §6.3.1 leaves to the application.
	// §10.6 prices commits unpadded and gkm sees their sizes anyway (gkm-2), so the default is none.
	// Non-positive adds none.
	PaddingLength int
	// The secret tree each epoch's protection runs.
	SecretTree *mlsSecretTreeSettings
}

// The defaults every group runs on outside tests.
func defaultMlsMessageSettings() *mlsMessageSettings {
	return &mlsMessageSettings{
		PaddingLength: 0,
		SecretTree:    defaultMlsSecretTreeSettings(),
	}
}

// Sender (RFC §6). No group has external senders (I-4) and none takes a standalone proposal, so a
// member and an external committer are all there is here.
type mlsSender struct {
	senderType uint8
	// When a member.
	leafIndex mlsLeafIndex
}

// Sender, refusing what decode refuses.
func (self *mlsSender) encode(encoder *mlsEncoder) {
	encoder.writeUint8(self.senderType)
	switch self.senderType {
	case mlsSenderTypeMember:
		encoder.writeUint32(uint32(self.leafIndex))
	case mlsSenderTypeNewMemberCommit:
	default:
		encoder.fail(fmt.Errorf("%w: sender type %d", errMlsRefused, self.senderType))
	}
}

// Sender: its type, then a member's leaf.
func (self *mlsSender) decode(decoder *mlsDecoder) {
	self.senderType = decoder.readUint8()
	if decoder.err != nil {
		return
	}
	switch self.senderType {
	case mlsSenderTypeMember:
		self.leafIndex = mlsLeafIndex(decoder.readUint32())
	case mlsSenderTypeNewMemberCommit:
	case mlsSenderTypeExternal, mlsSenderTypeNewMemberProposal:
		decoder.fail(fmt.Errorf("%w: sender type %d", errMlsRefused, self.senderType))
	default:
		decoder.fail(fmt.Errorf("%w: sender type %d", errMlsMalformed, self.senderType))
	}
}

// Whether §10.4 frames this content.
func mlsCheckContentType(contentType uint8) error {
	switch contentType {
	case mlsContentTypeCommit:
		return nil
	case mlsContentTypeApplication, mlsContentTypeProposal:
		return fmt.Errorf("%w: content type %d", errMlsRefused, contentType)
	default:
		return fmt.Errorf("%w: content type %d", errMlsMalformed, contentType)
	}
}

// Reads a content of this type, or fails the decoder. A content has no length header, so only a reader
// that understands it can say where the signature after it starts.
type mlsContentReader func(decoder *mlsDecoder, contentType uint8) mlsEncodable

// The subset's reader: a Commit and nothing else.
func mlsReadCommit(decoder *mlsDecoder, contentType uint8) mlsEncodable {
	if err := mlsCheckContentType(contentType); err != nil {
		decoder.fail(err)
		return nil
	}
	commit := &mlsCommit{}
	commit.decode(decoder)
	return commit
}

// FramedContent (RFC §6).
type mlsFramedContent struct {
	groupId           []byte
	epoch             uint64
	sender            mlsSender
	authenticatedData []byte
	contentType       uint8
	// What contentType selects, in production always an *mlsCommit.
	body mlsEncodable
}

// FramedContent, in RFC §6's field order.
func (self *mlsFramedContent) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.groupId)
	encoder.writeUint64(self.epoch)
	self.sender.encode(encoder)
	encoder.writeVector(self.authenticatedData)
	encoder.writeUint8(self.contentType)
	if self.body == nil {
		encoder.fail(fmt.Errorf("mls: framed content with no body"))
		return
	}
	self.body.encode(encoder)
}

// FramedContent, its body by readContent.
func (self *mlsFramedContent) decode(decoder *mlsDecoder, readContent mlsContentReader) {
	self.groupId = decoder.readVector()
	self.epoch = decoder.readUint64()
	self.sender.decode(decoder)
	self.authenticatedData = decoder.readVector()
	self.contentType = decoder.readUint8()
	if decoder.err != nil {
		return
	}
	self.body = readContent(decoder, self.contentType)
}

// The body as a commit, nil when it is anything else.
func (self *mlsFramedContent) commit() *mlsCommit {
	commit, _ := self.body.(*mlsCommit)
	return commit
}

// FramedContentAuthData (RFC §6.1), whose shape depends on the content it follows.
type mlsFramedContentAuthData struct {
	signature []byte
	// When the content is a commit.
	confirmationTag []byte
}

// FramedContentAuthData.
func (self *mlsFramedContentAuthData) encode(encoder *mlsEncoder, contentType uint8) {
	encoder.writeVector(self.signature)
	if contentType == mlsContentTypeCommit {
		encoder.writeVector(self.confirmationTag)
	}
}

// FramedContentAuthData.
func (self *mlsFramedContentAuthData) decode(decoder *mlsDecoder, contentType uint8) {
	self.signature = decoder.readVector()
	if contentType == mlsContentTypeCommit {
		self.confirmationTag = decoder.readVector()
	}
}

// AuthenticatedContent (RFC §6.1): what a sender signed and how it was framed, the same value on both
// sides whichever message carried it.
type mlsAuthenticatedContent struct {
	wireFormat uint16
	content    mlsFramedContent
	auth       mlsFramedContentAuthData
}

// FramedContentTBS's bytes. Both senders here sign the epoch's encoded GroupContext with their content.
func (self *mlsAuthenticatedContent) toBeSigned(groupContext []byte) ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeUint16(mlsProtocolVersion10)
	encoder.writeUint16(self.wireFormat)
	self.content.encode(encoder)
	encoder.writeFixed(groupContext)
	return encoder.finish()
}

// Fills in the signature, over the fields as they stand (RFC §6.1).
func (self *mlsAuthenticatedContent) sign(suite *mlsCipherSuite, signatureKey ed25519.PrivateKey, groupContext []byte) error {
	content, err := self.toBeSigned(groupContext)
	if err != nil {
		return err
	}
	signature, err := suite.signWithLabel(signatureKey, mlsSignatureLabelFramedContent, content)
	if err != nil {
		return err
	}
	self.auth.signature = signature
	return nil
}

// Against the sender's signature key (RFC §6.1).
func (self *mlsAuthenticatedContent) verifySignature(suite *mlsCipherSuite, verificationKey []byte, groupContext []byte) error {
	content, err := self.toBeSigned(groupContext)
	if err != nil {
		return err
	}
	if !suite.verifyWithLabel(verificationKey, mlsSignatureLabelFramedContent, content, self.auth.signature) {
		return fmt.Errorf("%w: framed content signature", errMlsAuthentication)
	}
	return nil
}

// PublicMessage (RFC §6.2), only ever an external commit (D-KEYS-3), so its sender is new and it has
// no membership tag.
type mlsPublicMessage struct {
	content mlsFramedContent
	auth    mlsFramedContentAuthData
}

// PublicMessage: the content, then what authenticates it.
func (self *mlsPublicMessage) encode(encoder *mlsEncoder) {
	self.content.encode(encoder)
	self.auth.encode(encoder, self.content.contentType)
}

// Refuses all but an external commit with a path: a member's PublicMessage is a content §10.4 sends
// only as a PrivateMessage, and without a path nothing names the key that signed the commit.
func (self *mlsPublicMessage) decode(decoder *mlsDecoder) {
	self.content.decode(decoder, mlsReadCommit)
	if decoder.err != nil {
		return
	}
	if self.content.sender.senderType != mlsSenderTypeNewMemberCommit {
		decoder.fail(fmt.Errorf("%w: a PublicMessage from a member", errMlsRefused))
		return
	}
	if self.content.commit().path == nil {
		decoder.fail(fmt.Errorf("%w: an external commit with no path", errMlsInvalid))
		return
	}
	self.auth.decode(decoder, self.content.contentType)
}

// PrivateMessage (RFC §6.3).
type mlsPrivateMessage struct {
	groupId             []byte
	epoch               uint64
	contentType         uint8
	authenticatedData   []byte
	encryptedSenderData []byte
	ciphertext          []byte
}

// PrivateMessage, in RFC §6.3's field order.
func (self *mlsPrivateMessage) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.groupId)
	encoder.writeUint64(self.epoch)
	encoder.writeUint8(self.contentType)
	encoder.writeVector(self.authenticatedData)
	encoder.writeVector(self.encryptedSenderData)
	encoder.writeVector(self.ciphertext)
}

// Refuses anything but a commit from its clear content type, before any key is touched.
func (self *mlsPrivateMessage) decode(decoder *mlsDecoder) {
	self.groupId = decoder.readVector()
	self.epoch = decoder.readUint64()
	self.contentType = decoder.readUint8()
	if decoder.err != nil {
		return
	}
	if err := mlsCheckContentType(self.contentType); err != nil {
		decoder.fail(err)
		return
	}
	self.authenticatedData = decoder.readVector()
	self.encryptedSenderData = decoder.readVector()
	self.ciphertext = decoder.readVector()
}

// PrivateContentAAD (RFC §6.3.1).
func (self *mlsPrivateMessage) contentAad() ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeVector(self.groupId)
	encoder.writeUint64(self.epoch)
	encoder.writeUint8(self.contentType)
	encoder.writeVector(self.authenticatedData)
	return encoder.finish()
}

// SenderDataAAD (RFC §6.3.2).
func (self *mlsPrivateMessage) senderDataAad() ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeVector(self.groupId)
	encoder.writeUint64(self.epoch)
	encoder.writeUint8(self.contentType)
	return encoder.finish()
}

// PrivateMessageContent (RFC §6.3.1) as what its sender signed. Whatever follows the auth data is
// padding, which must be zero so that it can carry nothing. Everything kept is a copy, so the caller
// still owns and erases plaintext.
func (self *mlsPrivateMessage) parseContent(plaintext []byte, sender mlsLeafIndex, readContent mlsContentReader) (*mlsAuthenticatedContent, error) {
	authenticated := &mlsAuthenticatedContent{
		wireFormat: mlsWireFormatPrivateMessage,
		content: mlsFramedContent{
			groupId:           self.groupId,
			epoch:             self.epoch,
			sender:            mlsSender{senderType: mlsSenderTypeMember, leafIndex: sender},
			authenticatedData: self.authenticatedData,
			contentType:       self.contentType,
		},
	}
	decoder := &mlsDecoder{remaining: plaintext}
	authenticated.content.body = readContent(decoder, self.contentType)
	authenticated.auth.decode(decoder, self.contentType)
	if decoder.err != nil {
		return nil, decoder.err
	}
	if slices.ContainsFunc(decoder.remaining, func(value byte) bool { return value != 0 }) {
		return nil, fmt.Errorf("%w: padding is not zero", errMlsMalformed)
	}
	return authenticated, nil
}

// SenderData (RFC §6.3.2).
type mlsSenderData struct {
	leafIndex  mlsLeafIndex
	generation uint32
	reuseGuard [mlsReuseGuardLength]byte
}

// SenderData, in RFC §6.3.2's field order.
func (self *mlsSenderData) encode(encoder *mlsEncoder) {
	encoder.writeUint32(uint32(self.leafIndex))
	encoder.writeUint32(self.generation)
	encoder.writeFixed(self.reuseGuard[:])
}

// SenderData, in RFC §6.3.2's field order.
func (self *mlsSenderData) decode(decoder *mlsDecoder) {
	self.leafIndex = mlsLeafIndex(decoder.readUint32())
	self.generation = decoder.readUint32()
	copy(self.reuseGuard[:], decoder.readFixed(mlsReuseGuardLength))
}

// Mixes the guard into the key schedule's nonce, in place (RFC §6.3.1), so that a client that lost its
// place in the schedule still does not repeat a nonce.
func (self *mlsSenderData) guardNonce(nonce []byte) {
	for index, value := range self.reuseGuard {
		nonce[index] ^= value
	}
}

// MLSMessage (RFC §6) for the two wire formats that carry a commit. A Welcome, a GroupInfo and a
// KeyPackage reach a client by their own gkm routes, and are refused here.
type mlsMessage struct {
	wireFormat     uint16
	publicMessage  *mlsPublicMessage
	privateMessage *mlsPrivateMessage
}

// MLSMessage, refusing what decode refuses.
func (self *mlsMessage) encode(encoder *mlsEncoder) {
	encoder.writeUint16(mlsProtocolVersion10)
	encoder.writeUint16(self.wireFormat)
	switch self.wireFormat {
	case mlsWireFormatPublicMessage:
		self.publicMessage.encode(encoder)
	case mlsWireFormatPrivateMessage:
		self.privateMessage.encode(encoder)
	default:
		encoder.fail(fmt.Errorf("%w: wire format %#x", errMlsRefused, self.wireFormat))
	}
}

// Refuses any version but mls10 (§10.4) and any other wire format.
func (self *mlsMessage) decode(decoder *mlsDecoder) {
	if version := decoder.readUint16(); decoder.err == nil && version != mlsProtocolVersion10 {
		decoder.fail(fmt.Errorf("%w: protocol version %d", errMlsRefused, version))
		return
	}
	self.wireFormat = decoder.readUint16()
	if decoder.err != nil {
		return
	}
	switch self.wireFormat {
	case mlsWireFormatPublicMessage:
		self.publicMessage = &mlsPublicMessage{}
		self.publicMessage.decode(decoder)
	case mlsWireFormatPrivateMessage:
		self.privateMessage = &mlsPrivateMessage{}
		self.privateMessage.decode(decoder)
	default:
		decoder.fail(fmt.Errorf("%w: wire format %#x", errMlsRefused, self.wireFormat))
	}
}

// What one epoch seals and opens commits with. Its secrets go at the epoch's end, and the group state
// builds one for the next.
type mlsMessageProtection struct {
	suite    *mlsCipherSuite
	settings *mlsMessageSettings

	groupContext *mlsGroupContext
	// groupContext's encoding, which every signature of the epoch covers.
	encodedGroupContext []byte
	// Who may send in this epoch, and with which key. Only read here.
	tree *mlsRatchetTree

	senderDataSecret []byte
	secretTree       *mlsSecretTree
}

// One epoch's protection over its tree. The secrets are copied, so the caller still owns and erases
// them.
func newMlsMessageProtection(suite *mlsCipherSuite, settings *mlsMessageSettings, groupContext *mlsGroupContext, tree *mlsRatchetTree, encryptionSecret []byte, senderDataSecret []byte) (*mlsMessageProtection, error) {
	encodedGroupContext, err := mlsMarshal(groupContext)
	if err != nil {
		return nil, err
	}
	secretTree, err := newMlsSecretTree(suite, settings.SecretTree, encryptionSecret, tree.leafCount())
	if err != nil {
		return nil, err
	}
	return &mlsMessageProtection{
		suite:               suite,
		settings:            settings,
		groupContext:        groupContext,
		encodedGroupContext: encodedGroupContext,
		tree:                tree,
		senderDataSecret:    bytes.Clone(senderDataSecret),
		secretTree:          secretTree,
	}, nil
}

// Overwrites every key this holds, at the end of its epoch (RFC §9.2).
func (self *mlsMessageProtection) erase() {
	clear(self.senderDataSecret)
	self.secretTree.erase()
}

// Whether a message names this epoch.
func (self *mlsMessageProtection) checkEpoch(groupId []byte, epoch uint64) error {
	if !bytes.Equal(groupId, self.groupContext.groupId) || epoch != self.groupContext.epoch {
		return fmt.Errorf("%w: epoch %d", errMlsOtherEpoch, epoch)
	}
	return nil
}

// Encrypts a member's signed commit as a PrivateMessage (RFC §6.3). The caller has signed it and set
// its confirmation tag.
func (self *mlsMessageProtection) seal(authenticated *mlsAuthenticatedContent) (*mlsPrivateMessage, error) {
	content := &authenticated.content
	if authenticated.wireFormat != mlsWireFormatPrivateMessage || content.sender.senderType != mlsSenderTypeMember {
		return nil, fmt.Errorf("%w: sealing wire format %#x from sender type %d", errMlsRefused, authenticated.wireFormat, content.sender.senderType)
	}
	if err := mlsCheckContentType(content.contentType); err != nil {
		return nil, err
	}
	if err := self.checkEpoch(content.groupId, content.epoch); err != nil {
		return nil, err
	}
	if content.body == nil {
		return nil, fmt.Errorf("mls: sealing a framed content with no body")
	}

	encoder := &mlsEncoder{}
	content.body.encode(encoder)
	authenticated.auth.encode(encoder, content.contentType)
	encoder.writeFixed(make([]byte, max(self.settings.PaddingLength, 0)))
	plaintext, err := encoder.finish()
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)

	message := &mlsPrivateMessage{
		groupId:           content.groupId,
		epoch:             content.epoch,
		contentType:       content.contentType,
		authenticatedData: content.authenticatedData,
	}
	if err := self.sealPlaintext(message, content.sender.leafIndex, plaintext); err != nil {
		return nil, err
	}
	return message, nil
}

// Fills in a message's two ciphertexts under the sender's next handshake generation (RFC §6.3.1, RFC
// §6.3.2).
func (self *mlsMessageProtection) sealPlaintext(message *mlsPrivateMessage, sender mlsLeafIndex, plaintext []byte) error {
	suite := self.suite
	ratchets, err := self.secretTree.ratchets(sender)
	if err != nil {
		return err
	}
	generation, key, nonce, err := ratchets.handshake.next()
	if err != nil {
		return err
	}
	defer clear(key)
	defer clear(nonce)

	senderData := &mlsSenderData{leafIndex: sender, generation: generation}
	// drawn through the suite's one hooked source of randomness, which is wider than a guard
	reuseGuard := suite.generateSecret("reuse_guard")
	defer clear(reuseGuard)
	copy(senderData.reuseGuard[:], reuseGuard)
	senderData.guardNonce(nonce)

	additionalData, err := message.contentAad()
	if err != nil {
		return err
	}
	if message.ciphertext, err = suite.aeadSeal(key, nonce, additionalData, plaintext); err != nil {
		return err
	}

	senderDataKey, senderDataNonce, err := suite.deriveSenderDataKey(self.senderDataSecret, message.ciphertext)
	if err != nil {
		return err
	}
	defer clear(senderDataKey)
	defer clear(senderDataNonce)
	encodedSenderData, err := mlsMarshal(senderData)
	if err != nil {
		return err
	}
	if additionalData, err = message.senderDataAad(); err != nil {
		return err
	}
	message.encryptedSenderData, err = suite.aeadSeal(senderDataKey, senderDataNonce, additionalData, encodedSenderData)
	return err
}

// Unprotects a message of this epoch into what its sender signed, with the signature checked (RFC
// §6.1). The confirmation tag stays the caller's to check, against the epoch the commit starts.
func (self *mlsMessageProtection) open(message *mlsMessage) (*mlsAuthenticatedContent, error) {
	switch message.wireFormat {
	case mlsWireFormatPublicMessage:
		return self.openPublic(message.publicMessage)
	case mlsWireFormatPrivateMessage:
		return self.openPrivate(message.privateMessage, mlsReadCommit)
	default:
		return nil, fmt.Errorf("%w: wire format %#x", errMlsRefused, message.wireFormat)
	}
}

// An external commit: its own UpdatePath names the key that signed it, so the signature proves only
// that this sender wrote it. Whether such a sender may join is the group state's to judge.
func (self *mlsMessageProtection) openPublic(message *mlsPublicMessage) (*mlsAuthenticatedContent, error) {
	if err := self.checkEpoch(message.content.groupId, message.content.epoch); err != nil {
		return nil, err
	}
	commit := message.content.commit()
	if commit == nil || commit.path == nil {
		return nil, fmt.Errorf("%w: an external commit with no path", errMlsInvalid)
	}
	authenticated := &mlsAuthenticatedContent{
		wireFormat: mlsWireFormatPublicMessage,
		content:    message.content,
		auth:       message.auth,
	}
	if err := authenticated.verifySignature(self.suite, commit.path.leafNode.signatureKey, self.encodedGroupContext); err != nil {
		return nil, err
	}
	return authenticated, nil
}

// A member's commit, its content read by readContent (RFC §6.3.1, RFC §6.3.2). The sender's generation
// is given up only once the signature holds, whatever fails before that.
func (self *mlsMessageProtection) openPrivate(message *mlsPrivateMessage, readContent mlsContentReader) (*mlsAuthenticatedContent, error) {
	if err := self.checkEpoch(message.groupId, message.epoch); err != nil {
		return nil, err
	}
	suite := self.suite
	senderData, err := self.openSenderData(message)
	if err != nil {
		return nil, err
	}
	leafNode := self.tree.leafNode(senderData.leafIndex)
	if leafNode == nil {
		return nil, fmt.Errorf("%w: sender data names leaf %d, which is blank", errMlsInvalid, senderData.leafIndex)
	}
	ratchets, err := self.secretTree.ratchets(senderData.leafIndex)
	if err != nil {
		return nil, err
	}
	step, err := ratchets.handshake.stepTo(senderData.generation)
	if err != nil {
		return nil, err
	}
	defer step.discard()
	senderData.guardNonce(step.nonce)

	additionalData, err := message.contentAad()
	if err != nil {
		return nil, err
	}
	plaintext, err := suite.aeadOpen(step.key, step.nonce, additionalData, message.ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	authenticated, err := message.parseContent(plaintext, senderData.leafIndex, readContent)
	if err != nil {
		return nil, err
	}
	if err := authenticated.verifySignature(suite, leafNode.signatureKey, self.encodedGroupContext); err != nil {
		return nil, err
	}
	step.consume()
	return authenticated, nil
}

// Who sent a message and under which generation (RFC §6.3.2). Every member can forge this, so it only
// says which key to try.
func (self *mlsMessageProtection) openSenderData(message *mlsPrivateMessage) (*mlsSenderData, error) {
	suite := self.suite
	key, nonce, err := suite.deriveSenderDataKey(self.senderDataSecret, message.ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	defer clear(nonce)
	additionalData, err := message.senderDataAad()
	if err != nil {
		return nil, err
	}
	encoded, err := suite.aeadOpen(key, nonce, additionalData, message.encryptedSenderData)
	if err != nil {
		return nil, err
	}
	senderData := &mlsSenderData{}
	if err := mlsUnmarshal(encoded, senderData); err != nil {
		return nil, err
	}
	return senderData, nil
}

// What an MLS message shows with no key, which is all gkm reads of one (§10.6, I-1). Nothing here is
// authenticated, because a server has no key to authenticate it with: members check the same values
// when they open the message.
type MlsHeader struct {
	GroupId []byte
	Epoch   uint64
	// MlsContentTypeCommit, since anything else is refused.
	ContentType uint8
	// A commit's GkmCommitHeader, left encoded (D-KEYS-3).
	AuthenticatedData []byte
	// Set for an external commit, nil for a PrivateMessage, whose proposals nobody but a member reads.
	ExternalCommit *MlsExternalCommit
}

// What an external commit shows in the clear (gkm-6).
type MlsExternalCommit struct {
	// Of the joiner's credential, which gkm holds to the uploader.
	Identity []byte
	// In the commit's order.
	Proposals []MlsExternalProposal
}

// One proposal of an external commit.
type MlsExternalProposal struct {
	// As RFC §17.4 numbers them.
	ProposalType uint16
	// The leaf a Remove names, nil for any other proposal. Without the tree this is only a position, so
	// gkm can count these but not check whose leaf one is.
	RemovedLeaf *uint32
}

// The clear header of an encoded MLSMessage, with no key. Refuses what the subset refuses, so
// a message that gets through here is a commit in one of its two framings.
func ParseMlsHeader(encoded []byte) (*MlsHeader, error) {
	message := &mlsMessage{}
	if err := mlsUnmarshal(encoded, message); err != nil {
		return nil, err
	}
	if private := message.privateMessage; private != nil {
		return &MlsHeader{
			GroupId:           private.groupId,
			Epoch:             private.epoch,
			ContentType:       private.contentType,
			AuthenticatedData: private.authenticatedData,
		}, nil
	}

	content := &message.publicMessage.content
	commit := content.commit()
	external := &MlsExternalCommit{Identity: commit.path.leafNode.credential.identity}
	for index := range commit.proposals {
		proposal := MlsExternalProposal{ProposalType: commit.proposals[index].proposalType}
		if proposal.ProposalType == mlsProposalTypeRemove {
			removedLeaf := uint32(commit.proposals[index].removed)
			proposal.RemovedLeaf = &removedLeaf
		}
		external.Proposals = append(external.Proposals, proposal)
	}
	return &MlsHeader{
		GroupId:           content.groupId,
		Epoch:             content.epoch,
		ContentType:       content.contentType,
		AuthenticatedData: content.authenticatedData,
		ExternalCommit:    external,
	}, nil
}
