// KeyPackage (RFC 9420 §10): a client's published offer to join a group, one leaf and one init key
// under one suite. KeyPackages are public, and their leaves enter trees unchanged.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"
)

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
