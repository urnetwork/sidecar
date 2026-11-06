// The cipher suite layer: the primitives a suite names and the labeled forms MLS reaches them
// through (RFC 9420 §5, and ExpandWithLabel and its relatives from RFC §8 and RFC §9).
//
// Production has one suite, mlsSuite, 0x0010: X-Wing with HKDF-SHA256, AES-128-GCM, SHA-256 and
// Ed25519 (owner decision 44; draft-ietf-mls-pq-ciphersuites-07). A suite is always passed in, never
// looked up from a value on the wire, so nothing a peer sends can select another one. The only other
// suite is 0x0001, which tests build for the mlswg's vectors (§10.4) and which differs in its KEM
// alone.
//
// Every secret this layer creates, derives or unwraps goes through testHookSecret before its first
// use. So each method that makes one takes a kind, the literal naming the value as its section does,
// and the call site supplies it.
//
// KEM 0x647a's key derivation is draft-ietf-hpke-pq's LabeledDerive, which the suite's draft cites and
// crypto/hpke implements. It is not the unlabeled SHAKE256 of the X-Wing draft's own §5.6.
//
// Everything here is safe for concurrent use: a suite holds no state.
//
// Across the mls_ files, RFC § cites RFC 9420 and a bare § cites DESIGN.md, as elsewhere in this
// repository, since the two number their sections alike: §7.9 is parent hashes in one and the
// authorization log in the other.

package sidecar

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
)

const (
	// ProtocolVersion mls10, the only version (§10.4).
	mlsProtocolVersion10 uint16 = 1

	// MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519.
	mlsCipherSuiteXWing uint16 = 0x0010

	// Prepended to every label of the labeled functions (RFC §5.1.2, RFC §5.1.3, RFC §8).
	mlsLabelPrefix = "MLS 1.0 "

	// RefHash labels (RFC §5.2).
	mlsRefHashLabelKeyPackage = "MLS 1.0 KeyPackage Reference"
	mlsRefHashLabelProposal   = "MLS 1.0 Proposal Reference"
)

// A failed MAC, signature or AEAD check.
var errMlsAuthentication = errors.New("mls: authentication failed")

// The suite every group, KeyPackage and credential uses.
var mlsSuite = newMlsCipherSuite(mlsCipherSuiteXWing, hpke.MLKEM768X25519())

// One suite's primitives. Immutable.
type mlsCipherSuite struct {
	value uint16
	kem   hpke.KEM
	kdf   hpke.KDF
	aead  hpke.AEAD

	newHash func() hash.Hash

	// KDF.Nh
	hashLength int
	// AEAD.Nk
	aeadKeyLength int
	// AEAD.Nn
	aeadNonceLength int
}

// Pairs a KEM with the primitives both suites share.
func newMlsCipherSuite(value uint16, kem hpke.KEM) *mlsCipherSuite {
	return &mlsCipherSuite{
		value:           value,
		kem:             kem,
		kdf:             hpke.HKDFSHA256(),
		aead:            hpke.AES128GCM(),
		newHash:         sha256.New,
		hashLength:      sha256.Size,
		aeadKeyLength:   16,
		aeadNonceLength: 12,
	}
}

// Hash.
func (self *mlsCipherSuite) hash(data []byte) []byte {
	hasher := self.newHash()
	hasher.Write(data)
	return hasher.Sum(nil)
}

// MAC, the suite's HMAC.
func (self *mlsCipherSuite) mac(key []byte, data []byte) []byte {
	hasher := hmac.New(self.newHash, key)
	hasher.Write(data)
	return hasher.Sum(nil)
}

// In constant time.
func (self *mlsCipherSuite) verifyMac(key []byte, data []byte, tag []byte) bool {
	return hmac.Equal(self.mac(key, data), tag)
}

// KDF.Extract. A nil salt means the all-zero salt, as RFC 5869 and RFC 9420 §8 both do.
func (self *mlsCipherSuite) extract(kind string, salt []byte, inputKey []byte) ([]byte, error) {
	extracted, err := hkdf.Extract(self.newHash, inputKey, salt)
	if err != nil {
		return nil, fmt.Errorf("mls: extract: %w", err)
	}
	testHookSecret(kind, extracted)
	return extracted, nil
}

// ExpandWithLabel (RFC §8).
func (self *mlsCipherSuite) expandWithLabel(kind string, secret []byte, label string, context []byte, length int) ([]byte, error) {
	if length < 0 || 0xffff < length {
		return nil, fmt.Errorf("mls: expand length %d", length)
	}
	encoder := &mlsEncoder{}
	encoder.writeUint16(uint16(length))
	encoder.writeVector([]byte(mlsLabelPrefix + label))
	encoder.writeVector(context)
	kdfLabel, err := encoder.finish()
	if err != nil {
		return nil, err
	}
	expanded, err := hkdf.Expand(self.newHash, secret, string(kdfLabel), length)
	if err != nil {
		return nil, fmt.Errorf("mls: expand: %w", err)
	}
	testHookSecret(kind, expanded)
	return expanded, nil
}

// DeriveSecret (RFC §8).
func (self *mlsCipherSuite) deriveSecret(kind string, secret []byte, label string) ([]byte, error) {
	return self.expandWithLabel(kind, secret, label, nil, self.hashLength)
}

// DeriveTreeSecret (RFC §9.1): the generation is the context, as a big-endian uint32.
func (self *mlsCipherSuite) deriveTreeSecret(kind string, secret []byte, label string, generation uint32, length int) ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeUint32(generation)
	return self.expandWithLabel(kind, secret, label, encoder.encoded, length)
}

// RefHash (RFC §5.2).
func (self *mlsCipherSuite) refHash(label string, value []byte) ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeVector([]byte(label))
	encoder.writeVector(value)
	refHashInput, err := encoder.finish()
	if err != nil {
		return nil, err
	}
	return self.hash(refHashInput), nil
}

// MakeKeyPackageRef, over the encoded KeyPackage.
func (self *mlsCipherSuite) makeKeyPackageRef(encodedKeyPackage []byte) ([]byte, error) {
	return self.refHash(mlsRefHashLabelKeyPackage, encodedKeyPackage)
}

// MakeProposalRef, over the encoded AuthenticatedContent carrying the proposal.
func (self *mlsCipherSuite) makeProposalRef(encodedAuthenticatedContent []byte) ([]byte, error) {
	return self.refHash(mlsRefHashLabelProposal, encodedAuthenticatedContent)
}

// SignContent and EncryptContext (RFC §5.1.2, RFC §5.1.3), which share a form: the prefixed label,
// then the content.
func mlsLabeledContent(label string, content []byte) ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeVector([]byte(mlsLabelPrefix + label))
	encoder.writeVector(content)
	return encoder.finish()
}

// SignWithLabel (RFC §5.1.2).
func (self *mlsCipherSuite) signWithLabel(signatureKey ed25519.PrivateKey, label string, content []byte) ([]byte, error) {
	if len(signatureKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("mls: signature private key of %d bytes", len(signatureKey))
	}
	signContent, err := mlsLabeledContent(label, content)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(signatureKey, signContent), nil
}

// VerifyWithLabel (RFC §5.1.2). A key of the wrong size verifies nothing.
func (self *mlsCipherSuite) verifyWithLabel(verificationKey []byte, label string, content []byte, signature []byte) bool {
	if len(verificationKey) != ed25519.PublicKeySize {
		return false
	}
	signContent, err := mlsLabeledContent(label, content)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(verificationKey), signContent, signature)
}

// EncryptWithLabel (RFC §5.1.3): SealBase with an empty AAD. publicKey is an HPKEPublicKey's bytes,
// so a key that does not parse under the suite's KEM is an error here.
func (self *mlsCipherSuite) encryptWithLabel(publicKey []byte, label string, context []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error) {
	recipientKey, err := self.kem.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("mls: hpke public key: %w", err)
	}
	encryptContext, err := mlsLabeledContent(label, context)
	if err != nil {
		return nil, nil, err
	}
	kemOutput, sender, err := hpke.NewSender(recipientKey, self.kdf, self.aead, encryptContext)
	if err != nil {
		return nil, nil, fmt.Errorf("mls: hpke setup: %w", err)
	}
	ciphertext, err = sender.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("mls: hpke seal: %w", err)
	}
	return kemOutput, ciphertext, nil
}

// DecryptWithLabel (RFC §5.1.3): OpenBase with an empty AAD. The plaintext is an unwrapped secret,
// so kind names it.
func (self *mlsCipherSuite) decryptWithLabel(kind string, privateKey hpke.PrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error) {
	encryptContext, err := mlsLabeledContent(label, context)
	if err != nil {
		return nil, err
	}
	recipient, err := hpke.NewRecipient(kemOutput, privateKey, self.kdf, self.aead, encryptContext)
	if err != nil {
		return nil, fmt.Errorf("%w: hpke setup: %w", errMlsAuthentication, err)
	}
	plaintext, err := recipient.Open(nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: hpke open: %w", errMlsAuthentication, err)
	}
	testHookSecret(kind, plaintext)
	return plaintext, nil
}

// A fresh random value of size KDF.Nh.
func (self *mlsCipherSuite) generateSecret(kind string) []byte {
	secret := make([]byte, self.hashLength)
	rand.Read(secret)
	testHookSecret(kind, secret)
	return secret
}

// Hooks an HPKE private key's serialized form.
func (self *mlsCipherSuite) hookKemKey(kind string, privateKey hpke.PrivateKey) error {
	encoded, err := privateKey.Bytes()
	if err != nil {
		return fmt.Errorf("mls: hpke private key: %w", err)
	}
	testHookSecret(kind, encoded)
	return nil
}

// A fresh HPKE key pair.
func (self *mlsCipherSuite) generateKemKey(kind string) (hpke.PrivateKey, error) {
	privateKey, err := self.kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("mls: hpke key generation: %w", err)
	}
	if err := self.hookKemKey(kind, privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// KEM.DeriveKeyPair.
func (self *mlsCipherSuite) deriveKemKey(kind string, secret []byte) (hpke.PrivateKey, error) {
	privateKey, err := self.kem.DeriveKeyPair(secret)
	if err != nil {
		return nil, fmt.Errorf("mls: hpke key derivation: %w", err)
	}
	if err := self.hookKemKey(kind, privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// An HPKE private key from its serialized form, as a state load unwraps it.
func (self *mlsCipherSuite) loadKemKey(kind string, encoded []byte) (hpke.PrivateKey, error) {
	privateKey, err := self.kem.NewPrivateKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("mls: hpke private key: %w", err)
	}
	if err := self.hookKemKey(kind, privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// A fresh signature key. The hook gets its seed, the part the rest of the key is computed from.
func (self *mlsCipherSuite) generateSignatureKey(kind string) (ed25519.PrivateKey, error) {
	_, signatureKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mls: signature key generation: %w", err)
	}
	testHookSecret(kind, signatureKey.Seed())
	return signatureKey, nil
}

// A signature key from its seed, as a state load unwraps it.
func (self *mlsCipherSuite) loadSignatureKey(kind string, seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("mls: signature seed of %d bytes", len(seed))
	}
	testHookSecret(kind, seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// The suite's AEAD under one key, refusing a key or nonce of the wrong size, which cipher.AEAD would
// panic on.
func (self *mlsCipherSuite) newAead(key []byte, nonce []byte) (cipher.AEAD, error) {
	if len(key) != self.aeadKeyLength || len(nonce) != self.aeadNonceLength {
		return nil, fmt.Errorf("mls: aead key of %d bytes, nonce of %d", len(key), len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("mls: aead key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mls: aead: %w", err)
	}
	return aead, nil
}

// AEAD.Seal.
func (self *mlsCipherSuite) aeadSeal(key []byte, nonce []byte, additionalData []byte, plaintext []byte) ([]byte, error) {
	aead, err := self.newAead(key, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// AEAD.Open.
func (self *mlsCipherSuite) aeadOpen(key []byte, nonce []byte, additionalData []byte, ciphertext []byte) ([]byte, error) {
	aead, err := self.newAead(key, nonce)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: aead open: %w", errMlsAuthentication, err)
	}
	return plaintext, nil
}
