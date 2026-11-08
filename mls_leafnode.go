// A member's appearance in a group: LeafNode (RFC 9420 §7.2) and what it carries, credentials (RFC
// §5.3), capabilities and a lifetime. A leaf is the same bytes in a KeyPackage and in the ratchet
// tree, and everything in it is signed, so what is decoded is kept exactly as it arrived.
//
// §10.4's subset takes one credential type on the wire, 0xF552, whose encoding M2's entry review
// specifies (D-KEYS-10). Until then the decoder refuses it like any type it cannot read. Basic, which
// the mlswg's vectors and the test groups use, reads only in the test binary, the way suite 0x0001 is
// built only there, so production refuses it when parsed (D-KEYS-12) and no leaf decodes outside
// tests yet. Reading is not acceptance either: that is the mlsCredentialValidator's call, and the only
// production validator there is refuses everything until §7.9's admission check exists.

package sidecar

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Credential types (RFC §17.5; §10.4).
const (
	mlsCredentialTypeBasic     uint16 = 0x0001
	mlsCredentialTypeUrSidecar uint16 = 0xf552
)

// LeafNodeSource (RFC §7.2).
const (
	mlsLeafNodeSourceKeyPackage uint8 = 1
	mlsLeafNodeSourceUpdate     uint8 = 2
	mlsLeafNodeSourceCommit     uint8 = 3
)

// Signature labels (RFC §17.6).
const mlsSignatureLabelLeafNode = "LeafNodeTBS"

// A structure that decodes but breaks a rule of the protocol.
var errMlsInvalid = errors.New("mls: invalid")

// Whether a credential is acceptable for a signature key (RFC §5.3.1). The application decides: for
// §10.4, a verified SidecarAdmit naming the credential's sidecar and identity key, checked against
// §7.9's authorization log.
type mlsCredentialValidator func(credential *mlsCredential, signatureKey []byte) error

// The validator production has until §7.9's admission check lands, so every credential fails closed.
func mlsRefuseEveryCredential(credential *mlsCredential, signatureKey []byte) error {
	return fmt.Errorf("%w: no admission check exists yet for credential type %#x", errMlsRefused, credential.credentialType)
}

// Whether basic credentials encode and decode. Production leaves this false. The test binary sets it,
// and TestMlsProductionCodeReadsNoBasicCredential holds every other file to leaving it alone.
var mlsTestReadsBasicCredentials bool

// A member's claimed identity (RFC §5.3).
type mlsCredential struct {
	credentialType uint16
	// A basic credential's identity.
	identity []byte
}

// Credential, refusing what decode refuses.
func (self *mlsCredential) encode(encoder *mlsEncoder) {
	encoder.writeUint16(self.credentialType)
	if self.credentialType == mlsCredentialTypeBasic && mlsTestReadsBasicCredentials {
		encoder.writeVector(self.identity)
		return
	}
	encoder.fail(fmt.Errorf("%w: credential type %#x", errMlsRefused, self.credentialType))
}

// Every type is refused outside tests: x509 is outside the subset, 0xF552 is not specified yet, basic
// is the tests' alone, and an unknown type's length cannot be known.
func (self *mlsCredential) decode(decoder *mlsDecoder) {
	self.credentialType = decoder.readUint16()
	if decoder.err != nil {
		return
	}
	if self.credentialType == mlsCredentialTypeBasic && mlsTestReadsBasicCredentials {
		self.identity = decoder.readVector()
		return
	}
	decoder.fail(fmt.Errorf("%w: credential type %#x", errMlsRefused, self.credentialType))
}

// What a leaf says it supports (RFC §7.2). Unknown values stay, because the list is signed, and mean
// nothing.
type mlsCapabilities struct {
	versions     []uint16
	cipherSuites []uint16
	extensions   []uint16
	proposals    []uint16
	credentials  []uint16
}

// Capabilities, in RFC §7.2's field order.
func (self *mlsCapabilities) encode(encoder *mlsEncoder) {
	encoder.writeUint16Vector(self.versions)
	encoder.writeUint16Vector(self.cipherSuites)
	encoder.writeUint16Vector(self.extensions)
	encoder.writeUint16Vector(self.proposals)
	encoder.writeUint16Vector(self.credentials)
}

// Capabilities, in RFC §7.2's field order.
func (self *mlsCapabilities) decode(decoder *mlsDecoder) {
	self.versions = decoder.readUint16Vector()
	self.cipherSuites = decoder.readUint16Vector()
	self.extensions = decoder.readUint16Vector()
	self.proposals = decoder.readUint16Vector()
	self.credentials = decoder.readUint16Vector()
}

// Default extension types are implicit (RFC §7.2), but for external_senders: §10.4 refuses it, so no
// leaf here supports it, listed or not, and a group that carries or requires it fails every leaf.
func (self *mlsCapabilities) supportsExtension(extensionType uint16) bool {
	if extensionType == mlsExtensionTypeExternalSenders {
		return false
	}
	return (mlsExtensionTypeApplicationId <= extensionType && extensionType <= mlsExtensionTypeExternalPub) ||
		slices.Contains(self.extensions, extensionType)
}

// Default proposal types are implicit (RFC §7.2).
func (self *mlsCapabilities) supportsProposal(proposalType uint16) bool {
	return (mlsProposalTypeAdd <= proposalType && proposalType <= mlsProposalTypeGroupContextExtensions) ||
		slices.Contains(self.proposals, proposalType)
}

// Unlike the other two, nothing is implicit here (RFC §11.1).
func (self *mlsCapabilities) supportsCredential(credentialType uint16) bool {
	return slices.Contains(self.credentials, credentialType)
}

// What every member of a group must support (RFC §11.1), a GroupContext extension's data.
type mlsRequiredCapabilities struct {
	extensionTypes  []uint16
	proposalTypes   []uint16
	credentialTypes []uint16
}

// RequiredCapabilities, in RFC §11.1's field order.
func (self *mlsRequiredCapabilities) encode(encoder *mlsEncoder) {
	encoder.writeUint16Vector(self.extensionTypes)
	encoder.writeUint16Vector(self.proposalTypes)
	encoder.writeUint16Vector(self.credentialTypes)
}

// RequiredCapabilities, in RFC §11.1's field order.
func (self *mlsRequiredCapabilities) decode(decoder *mlsDecoder) {
	self.extensionTypes = decoder.readUint16Vector()
	self.proposalTypes = decoder.readUint16Vector()
	self.credentialTypes = decoder.readUint16Vector()
}

// Whether these capabilities meet the requirement.
func (self *mlsCapabilities) satisfies(required *mlsRequiredCapabilities) bool {
	for _, extensionType := range required.extensionTypes {
		if !self.supportsExtension(extensionType) {
			return false
		}
	}
	for _, proposalType := range required.proposalTypes {
		if !self.supportsProposal(proposalType) {
			return false
		}
	}
	for _, credentialType := range required.credentialTypes {
		if !self.supportsCredential(credentialType) {
			return false
		}
	}
	return true
}

// The window a KeyPackage's leaf is valid in (RFC §7.2), in seconds since the Unix epoch.
type mlsLifetime struct {
	notBefore uint64
	notAfter  uint64
}

// At least the second must not precede the first, and a positive maximum bounds the span (RFC §7.2 has
// the application set one).
func (self *mlsLifetime) validSpan(maximum time.Duration) bool {
	if self.notAfter < self.notBefore {
		return false
	}
	if maximum <= 0 {
		return true
	}
	return self.notAfter-self.notBefore <= uint64(maximum/time.Second)
}

// Whether this moment is inside the lifetime, both ends included.
func (self *mlsLifetime) contains(at time.Time) bool {
	seconds := at.Unix()
	return 0 <= seconds && self.notBefore <= uint64(seconds) && uint64(seconds) <= self.notAfter
}

// A member's leaf of the ratchet tree (RFC §7.2).
type mlsLeafNode struct {
	encryptionKey  []byte
	signatureKey   []byte
	credential     mlsCredential
	capabilities   mlsCapabilities
	leafNodeSource uint8
	// When leafNodeSource is key_package.
	lifetime mlsLifetime
	// When leafNodeSource is commit.
	parentHash []byte
	extensions []mlsExtension
	signature  []byte
}

// Every field the signature covers but the group context.
func (self *mlsLeafNode) encodeContent(encoder *mlsEncoder) {
	encoder.writeVector(self.encryptionKey)
	encoder.writeVector(self.signatureKey)
	self.credential.encode(encoder)
	self.capabilities.encode(encoder)
	encoder.writeUint8(self.leafNodeSource)
	switch self.leafNodeSource {
	case mlsLeafNodeSourceKeyPackage:
		encoder.writeUint64(self.lifetime.notBefore)
		encoder.writeUint64(self.lifetime.notAfter)
	case mlsLeafNodeSourceUpdate:
	case mlsLeafNodeSourceCommit:
		encoder.writeVector(self.parentHash)
	default:
		encoder.fail(fmt.Errorf("%w: leaf node source %d", errMlsInvalid, self.leafNodeSource))
	}
	encoder.writeExtensions(self.extensions)
}

// LeafNode: the content, then the signature.
func (self *mlsLeafNode) encode(encoder *mlsEncoder) {
	self.encodeContent(encoder)
	encoder.writeVector(self.signature)
}

// LeafNode, refusing a source RFC §7.2 does not define.
func (self *mlsLeafNode) decode(decoder *mlsDecoder) {
	self.encryptionKey = decoder.readVector()
	self.signatureKey = decoder.readVector()
	self.credential.decode(decoder)
	self.capabilities.decode(decoder)
	self.leafNodeSource = decoder.readUint8()
	if decoder.err != nil {
		return
	}
	switch self.leafNodeSource {
	case mlsLeafNodeSourceKeyPackage:
		self.lifetime.notBefore = decoder.readUint64()
		self.lifetime.notAfter = decoder.readUint64()
	case mlsLeafNodeSourceUpdate:
	case mlsLeafNodeSourceCommit:
		self.parentHash = decoder.readVector()
	default:
		decoder.fail(fmt.Errorf("%w: leaf node source %d", errMlsMalformed, self.leafNodeSource))
		return
	}
	self.extensions = decoder.readExtensions()
	self.signature = decoder.readVector()
}

// LeafNodeTBS. A leaf from a KeyPackage is not yet in any group, so only the other two sources bind
// the group and the position.
func (self *mlsLeafNode) toBeSigned(groupId []byte, leafIndex mlsLeafIndex) ([]byte, error) {
	encoder := &mlsEncoder{}
	self.encodeContent(encoder)
	if self.leafNodeSource != mlsLeafNodeSourceKeyPackage {
		encoder.writeVector(groupId)
		encoder.writeUint32(uint32(leafIndex))
	}
	return encoder.finish()
}

// Fills in the signature, over the fields as they stand.
func (self *mlsLeafNode) sign(suite *mlsCipherSuite, signatureKey ed25519.PrivateKey, groupId []byte, leafIndex mlsLeafIndex) error {
	content, err := self.toBeSigned(groupId, leafIndex)
	if err != nil {
		return err
	}
	signature, err := suite.signWithLabel(signatureKey, mlsSignatureLabelLeafNode, content)
	if err != nil {
		return err
	}
	self.signature = signature
	return nil
}

// Against the leaf's own signature key, which validateAlone ties to its credential.
func (self *mlsLeafNode) verifySignature(suite *mlsCipherSuite, groupId []byte, leafIndex mlsLeafIndex) bool {
	content, err := self.toBeSigned(groupId, leafIndex)
	if err != nil {
		return false
	}
	return suite.verifyWithLabel(self.signatureKey, mlsSignatureLabelLeafNode, content, self.signature)
}

// RFC §7.3's checks on the leaf alone: its credential, its signature, and a capabilities list
// consistent with what it carries. The checks against the rest of the group are the tree's.
func (self *mlsLeafNode) validateAlone(suite *mlsCipherSuite, settings *mlsTreeSettings, credentialValidator mlsCredentialValidator, groupId []byte, leafIndex mlsLeafIndex) error {
	if !self.capabilities.supportsCredential(self.credential.credentialType) {
		return fmt.Errorf("%w: capabilities do not list the leaf's own credential type %#x", errMlsInvalid, self.credential.credentialType)
	}
	for index := range self.extensions {
		if extensionType := self.extensions[index].extensionType; !self.capabilities.supportsExtension(extensionType) {
			return fmt.Errorf("%w: capabilities do not list leaf extension %#x", errMlsInvalid, extensionType)
		}
	}
	if self.leafNodeSource == mlsLeafNodeSourceKeyPackage && !self.lifetime.validSpan(settings.MaximumLeafLifetime) {
		return fmt.Errorf("%w: lifetime %d to %d", errMlsInvalid, self.lifetime.notBefore, self.lifetime.notAfter)
	}
	// a key nobody can encrypt to would stall every later commit that reaches it
	if _, err := suite.kem.NewPublicKey(self.encryptionKey); err != nil {
		return fmt.Errorf("%w: leaf encryption key: %w", errMlsInvalid, err)
	}
	if err := credentialValidator(&self.credential, self.signatureKey); err != nil {
		return err
	}
	if !self.verifySignature(suite, groupId, leafIndex) {
		return fmt.Errorf("%w: leaf node signature", errMlsAuthentication)
	}
	return nil
}
