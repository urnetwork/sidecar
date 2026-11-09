// KeyPackage (RFC 9420 §10): a client's published offer to join a group, one leaf and one init key
// under one suite. KeyPackages are public, and their leaves enter trees unchanged.
//
// A sidecar makes its own (§10.6's KeyPackages): fresh init, leaf and signature keys, a leaf carrying
// credential 0xF552 for that signature key, the subset's capabilities, and a lifetime of 90 days, which
// starts a little before now so a peer whose clock runs behind can still add it. Being public, its
// credential names no member, tag or client (§10.4). The last-resort one says so in its own extensions
// (mls_extension.go) and is kept; a one-time one is dropped once a Welcome under it joins.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"fmt"
	"time"
)

// A leaf's signature key and the credential naming it, which the identity key signed.
type mlsLeafIdentity struct {
	signatureKey ed25519.PrivateKey
	credential   mlsCredential
	// What its leaves advertise. Nil, as every engine leaves it, is the subset's (mlsSubsetCapabilities). Only the
	// root's tests set it, for basic-credential leaves under 0x0001 that a peer without 0xF552 can read.
	capabilities *mlsCapabilities
}

// The capabilities a new leaf of this identity carries under suite.
func (self *mlsLeafIdentity) leafCapabilities(suite *mlsCipherSuite) mlsCapabilities {
	if self.capabilities != nil {
		return *self.capabilities
	}
	return mlsSubsetCapabilities(suite)
}

// A KeyPackage this sidecar made, with the private keys only it holds.
type mlsHeldKeyPackage struct {
	keyPackage *mlsKeyPackage
	// Its MLSMessage, which gkm stores at kp/<sidecar_id>/<ref>.
	encoded    []byte
	ref        []byte
	lastResort bool

	initKey      hpke.PrivateKey
	leafKey      hpke.PrivateKey
	signatureKey ed25519.PrivateKey
}

// A fresh KeyPackage for identity's leaf, valid over lifetime. The init and leaf keys are new and hooked,
// and the signature key is identity's.
func newMlsHeldKeyPackage(suite *mlsCipherSuite, identity *mlsLeafIdentity, lifetime mlsLifetime, lastResort bool) (*mlsHeldKeyPackage, error) {
	initKey, err := suite.generateKemKey("init_priv")
	if err != nil {
		return nil, err
	}
	leafKey, err := suite.generateKemKey("leaf_priv")
	if err != nil {
		return nil, err
	}
	leafNode := mlsLeafNode{
		encryptionKey:  leafKey.PublicKey().Bytes(),
		signatureKey:   []byte(identity.signatureKey.Public().(ed25519.PublicKey)),
		credential:     identity.credential,
		capabilities:   identity.leafCapabilities(suite),
		leafNodeSource: mlsLeafNodeSourceKeyPackage,
		lifetime:       lifetime,
	}
	if err := leafNode.sign(suite, identity.signatureKey, nil, 0); err != nil {
		return nil, err
	}
	keyPackage := &mlsKeyPackage{
		cipherSuite: suite.value,
		initKey:     initKey.PublicKey().Bytes(),
		leafNode:    leafNode,
	}
	if lastResort {
		keyPackage.extensions = []mlsExtension{{extensionType: mlsExtensionTypeLastResort}}
	}
	if err := keyPackage.sign(suite, identity.signatureKey); err != nil {
		return nil, err
	}
	encoded, err := mlsMarshalMessageOf(mlsWireFormatKeyPackage, keyPackage)
	if err != nil {
		return nil, err
	}
	ref, err := keyPackage.ref(suite)
	if err != nil {
		return nil, err
	}
	return &mlsHeldKeyPackage{
		keyPackage:   keyPackage,
		encoded:      encoded,
		ref:          ref,
		lastResort:   lastResort,
		initKey:      initKey,
		leafKey:      leafKey,
		signatureKey: identity.signatureKey,
	}, nil
}

// A KeyPackage's MLSMessage, as an Add names it, decoded and checked against suite (RFC §10.1) with
// sendingAt as validate takes it.
func mlsDecodeKeyPackage(suite *mlsCipherSuite, settings *mlsTreeSettings, credentialValidator mlsCredentialValidator, encoded []byte, sendingAt *time.Time) (*mlsKeyPackage, error) {
	keyPackage := &mlsKeyPackage{}
	if err := mlsUnmarshalMessageOf(encoded, mlsWireFormatKeyPackage, keyPackage); err != nil {
		return nil, err
	}
	if err := keyPackage.validate(suite, settings, credentialValidator, sendingAt); err != nil {
		return nil, err
	}
	return keyPackage, nil
}

// The window a new leaf is valid in: from skew before now for maximum, and never past the tree's bound.
func newMlsLifetime(now time.Time, skew time.Duration, maximum time.Duration) mlsLifetime {
	notBefore := now.Add(-skew).Unix()
	if notBefore < 0 {
		notBefore = 0
	}
	return mlsLifetime{notBefore: uint64(notBefore), notAfter: uint64(notBefore) + uint64(maximum/time.Second)}
}

// Signature labels (RFC §17.6).
const mlsSignatureLabelKeyPackage = "KeyPackageTBS"

// What a client publishes so that others can add it to a group (RFC §10).
type mlsKeyPackage struct {
	cipherSuite uint16
	initKey     []byte
	leafNode    mlsLeafNode
	extensions  []mlsExtension
	signature   []byte
}

// KeyPackageTBS.
func (self *mlsKeyPackage) encodeContent(encoder *mlsEncoder) {
	encoder.writeUint16(mlsProtocolVersion10)
	encoder.writeUint16(self.cipherSuite)
	encoder.writeVector(self.initKey)
	self.leafNode.encode(encoder)
	encoder.writeExtensions(self.extensions)
}

// KeyPackage: KeyPackageTBS, then the signature.
func (self *mlsKeyPackage) encode(encoder *mlsEncoder) {
	self.encodeContent(encoder)
	encoder.writeVector(self.signature)
}

// Refuses any version but mls10 (§10.4).
func (self *mlsKeyPackage) decode(decoder *mlsDecoder) {
	if version := decoder.readUint16(); decoder.err == nil && version != mlsProtocolVersion10 {
		decoder.fail(fmt.Errorf("%w: protocol version %d", errMlsRefused, version))
		return
	}
	self.cipherSuite = decoder.readUint16()
	self.initKey = decoder.readVector()
	self.leafNode.decode(decoder)
	self.extensions = decoder.readExtensions()
	self.signature = decoder.readVector()
}

// KeyPackageTBS's bytes.
func (self *mlsKeyPackage) toBeSigned() ([]byte, error) {
	encoder := &mlsEncoder{}
	self.encodeContent(encoder)
	return encoder.finish()
}

// Fills in the signature, over the fields as they stand.
func (self *mlsKeyPackage) sign(suite *mlsCipherSuite, signatureKey ed25519.PrivateKey) error {
	content, err := self.toBeSigned()
	if err != nil {
		return err
	}
	signature, err := suite.signWithLabel(signatureKey, mlsSignatureLabelKeyPackage, content)
	if err != nil {
		return err
	}
	self.signature = signature
	return nil
}

// KeyPackageRef (RFC §5.2).
func (self *mlsKeyPackage) ref(suite *mlsCipherSuite) ([]byte, error) {
	encoded, err := mlsMarshal(self)
	if err != nil {
		return nil, err
	}
	return suite.makeKeyPackageRef(encoded)
}

// RFC §10.1's checks, against the group's suite. The checks against the group's members are the tree's,
// at the leaf's position.
//
// sendingAt is the current time when this client is about to send the KeyPackage in an Add, which
// must then be inside its lifetime (RFC §7.3). A receiver passes nil, since a message may outlive the
// lifetime on its way.
func (self *mlsKeyPackage) validate(suite *mlsCipherSuite, settings *mlsTreeSettings, credentialValidator mlsCredentialValidator, sendingAt *time.Time) error {
	if self.cipherSuite != suite.value {
		return fmt.Errorf("%w: key package suite %#x", errMlsInvalid, self.cipherSuite)
	}
	if self.leafNode.leafNodeSource != mlsLeafNodeSourceKeyPackage {
		return fmt.Errorf("%w: leaf node source %d in a key package", errMlsInvalid, self.leafNode.leafNodeSource)
	}
	if bytes.Equal(self.leafNode.encryptionKey, self.initKey) {
		return fmt.Errorf("%w: init key equals the leaf's encryption key", errMlsInvalid)
	}
	if _, err := suite.kem.NewPublicKey(self.initKey); err != nil {
		return fmt.Errorf("%w: init key: %w", errMlsInvalid, err)
	}
	if sendingAt != nil && !self.leafNode.lifetime.contains(*sendingAt) {
		return fmt.Errorf("%w: key package outside its lifetime", errMlsInvalid)
	}
	if err := self.leafNode.validateAlone(suite, settings, credentialValidator, nil, 0); err != nil {
		return err
	}
	content, err := self.toBeSigned()
	if err != nil {
		return err
	}
	if !suite.verifyWithLabel(self.leafNode.signatureKey, mlsSignatureLabelKeyPackage, content, self.signature) {
		return fmt.Errorf("%w: key package signature", errMlsAuthentication)
	}
	return nil
}
