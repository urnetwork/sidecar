// The key schedule (RFC 9420 §8): the GroupContext it binds, one epoch's secrets, the exporter and
// external initialization.
//
// Hook kinds name the values as RFC §8's table 4 and diagram do. The two extractions the diagram leaves
// unnamed are "joiner_extract" and "member_extract".
//
// PSKs are refused (§10.4), so production passes a nil psk_secret, which is RFC §8's all-zero vector.
// The parameter exists because the secret enters the schedule either way and the mlswg's vectors
// set it.

package sidecar

import (
	"bytes"
	"crypto/hpke"
	"fmt"
)

// The HPKE exporter context of RFC §8.3.
const mlsExternalInitLabel = "MLS 1.0 external init secret"

// RFC §8.1's summary of a group's state, which binds the key schedule to it.
type mlsGroupContext struct {
	cipherSuite             uint16
	groupId                 []byte
	epoch                   uint64
	treeHash                []byte
	confirmedTranscriptHash []byte
	extensions              []mlsExtension
}

// GroupContext, version included, which only mls10 fills.
func (self *mlsGroupContext) encode(encoder *mlsEncoder) {
	encoder.writeUint16(mlsProtocolVersion10)
	encoder.writeUint16(self.cipherSuite)
	encoder.writeVector(self.groupId)
	encoder.writeUint64(self.epoch)
	encoder.writeVector(self.treeHash)
	encoder.writeVector(self.confirmedTranscriptHash)
	encoder.writeExtensions(self.extensions)
}

// Refuses any version but mls10 (§10.4).
func (self *mlsGroupContext) decode(decoder *mlsDecoder) {
	if version := decoder.readUint16(); decoder.err == nil && version != mlsProtocolVersion10 {
		decoder.fail(fmt.Errorf("%w: protocol version %d", errMlsRefused, version))
		return
	}
	self.cipherSuite = decoder.readUint16()
	self.groupId = decoder.readVector()
	self.epoch = decoder.readUint64()
	self.treeHash = decoder.readVector()
	self.confirmedTranscriptHash = decoder.readVector()
	self.extensions = decoder.readExtensions()
}

// RFC §7.8's tree_hash and §8.2's confirmed_transcript_hash are the suite's hash outputs, the latter the empty
// string at epoch 0 alone. Decoding cannot check this, since it reads the suite from the same bytes, so a received
// GroupContext is held to it once its suite is known, before anything derives from it: nothing else would refuse a
// confirmed_transcript_hash of another length, which only feeds the confirmation tag's MAC.
func (self *mlsGroupContext) checkHashLengths(suite *mlsCipherSuite) error {
	if len(self.treeHash) != suite.hashLength {
		return fmt.Errorf("%w: a tree_hash of %d bytes", errMlsInvalid, len(self.treeHash))
	}
	if len(self.confirmedTranscriptHash) != suite.hashLength && (self.epoch != 0 || len(self.confirmedTranscriptHash) != 0) {
		return fmt.Errorf("%w: a confirmed_transcript_hash of %d bytes at epoch %d", errMlsInvalid, len(self.confirmedTranscriptHash), self.epoch)
	}
	return nil
}

// What one epoch keeps of the schedule, as RFC §8's table 4 names it, with the two secrets a commit
// also produces. epoch_secret itself is consumed here (RFC §9.2). The caller retains what its role
// needs and erases the rest.
type mlsEpochSecrets struct {
	// Set only when the epoch came from a commit or a Welcome. A committer needs it for the Welcome.
	joinerSecret []byte
	// Set only when the epoch came from a commit or a Welcome.
	welcomeSecret []byte

	// The next epoch's input.
	initSecret []byte

	senderDataSecret   []byte
	encryptionSecret   []byte
	exporterSecret     []byte
	externalSecret     []byte
	confirmationKey    []byte
	membershipKey      []byte
	resumptionPsk      []byte
	epochAuthenticator []byte
}

// Overwrites every secret, for an epoch left behind (RFC §9.2).
func (self *mlsEpochSecrets) erase() {
	clear(self.joinerSecret)
	clear(self.welcomeSecret)
	clear(self.initSecret)
	clear(self.senderDataSecret)
	clear(self.encryptionSecret)
	clear(self.exporterSecret)
	clear(self.externalSecret)
	clear(self.confirmationKey)
	clear(self.membershipKey)
	clear(self.resumptionPsk)
	clear(self.epochAuthenticator)
}

// The schedule's first half: init_secret_[n-1] and commit_secret to joiner_secret. A nil commit_secret
// is the all-zero vector of a commit without a path (RFC §12.4.1). The caller still owns and erases its
// inputs.
func (self *mlsCipherSuite) deriveJoinerSecret(initSecret []byte, commitSecret []byte, groupContext []byte) ([]byte, error) {
	if commitSecret == nil {
		commitSecret = make([]byte, self.hashLength)
	}
	extracted, err := self.extract("joiner_extract", initSecret, commitSecret)
	if err != nil {
		return nil, err
	}
	defer clear(extracted)
	return self.expandWithLabel("joiner_secret", true, extracted, "joiner", groupContext, self.hashLength)
}

// The schedule's second half, from joiner_secret on, for a committer and for a Welcome's recipient.
// The result keeps its own copy of joiner_secret, and the caller still owns and erases its inputs.
func (self *mlsCipherSuite) deriveEpochSecrets(joinerSecret []byte, pskSecret []byte, groupContext []byte) (*mlsEpochSecrets, error) {
	if pskSecret == nil {
		pskSecret = make([]byte, self.hashLength)
	}
	extracted, err := self.extract("member_extract", joinerSecret, pskSecret)
	if err != nil {
		return nil, err
	}
	defer clear(extracted)
	welcomeSecret, err := self.deriveSecret("welcome_secret", extracted, "welcome")
	if err != nil {
		return nil, err
	}
	epochSecret, err := self.expandWithLabel("epoch_secret", true, extracted, "epoch", groupContext, self.hashLength)
	if err != nil {
		return nil, err
	}
	defer clear(epochSecret)
	secrets, err := self.deriveFromEpochSecret(epochSecret)
	if err != nil {
		return nil, err
	}
	secrets.joinerSecret = bytes.Clone(joinerSecret)
	secrets.welcomeSecret = welcomeSecret
	return secrets, nil
}

// welcome_secret alone, from joiner_secret and the zero psk_secret, for a Welcome's recipient, which needs it to
// read the GroupContext the rest of the schedule binds (RFC §12.4.3.1). The caller owns and erases both.
func (self *mlsCipherSuite) deriveWelcomeSecret(joinerSecret []byte) ([]byte, error) {
	extracted, err := self.extract("member_extract", joinerSecret, make([]byte, self.hashLength))
	if err != nil {
		return nil, err
	}
	defer clear(extracted)
	return self.deriveSecret("welcome_secret", extracted, "welcome")
}

// welcome_key and welcome_nonce (RFC §12.4.3.1), which seal a Welcome's GroupInfo.
func (self *mlsCipherSuite) deriveWelcomeKey(welcomeSecret []byte) (key []byte, nonce []byte, err error) {
	key, err = self.expandWithLabel("welcome_key", true, welcomeSecret, "key", nil, self.aeadKeyLength)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = self.expandWithLabel("welcome_nonce", false, welcomeSecret, "nonce", nil, self.aeadNonceLength)
	if err != nil {
		clear(key)
		return nil, nil, err
	}
	return key, nonce, nil
}

// Epoch 0 of a new group (RFC §11): epoch_secret is fresh, so there is no joiner or welcome secret, and
// the GroupContext enters only through what later epochs derive.
func (self *mlsCipherSuite) newGroupEpochSecrets() (*mlsEpochSecrets, error) {
	epochSecret := self.generateSecret("epoch_secret")
	defer clear(epochSecret)
	return self.deriveFromEpochSecret(epochSecret)
}

// Table 4 and init_secret_[n] from epoch_secret.
func (self *mlsCipherSuite) deriveFromEpochSecret(epochSecret []byte) (*mlsEpochSecrets, error) {
	secrets := &mlsEpochSecrets{}
	derivations := []struct {
		kind   string
		label  string
		target *[]byte
	}{
		{kind: "sender_data_secret", label: "sender data", target: &secrets.senderDataSecret},
		{kind: "encryption_secret", label: "encryption", target: &secrets.encryptionSecret},
		{kind: "exporter_secret", label: "exporter", target: &secrets.exporterSecret},
		{kind: "external_secret", label: "external", target: &secrets.externalSecret},
		{kind: "confirmation_key", label: "confirm", target: &secrets.confirmationKey},
		{kind: "membership_key", label: "membership", target: &secrets.membershipKey},
		{kind: "resumption_psk", label: "resumption", target: &secrets.resumptionPsk},
		{kind: "epoch_authenticator", label: "authentication", target: &secrets.epochAuthenticator},
		{kind: "init_secret", label: "init", target: &secrets.initSecret},
	}
	for _, derivation := range derivations {
		derived, err := self.deriveSecret(derivation.kind, epochSecret, derivation.label)
		if err != nil {
			return nil, err
		}
		*derivation.target = derived
	}
	return secrets, nil
}

// external_priv and, through its public half, external_pub (RFC §8).
func (self *mlsCipherSuite) deriveExternalKey(externalSecret []byte) (hpke.PrivateKey, error) {
	return self.deriveKemKey("external_priv", externalSecret)
}

// MLS-Exporter (RFC §8.5). kind names what the caller exports.
func (self *mlsCipherSuite) exporter(kind string, exporterSecret []byte, label string, context []byte, length int) ([]byte, error) {
	labelSecret, err := self.deriveSecret("exporter_label_secret", exporterSecret, label)
	if err != nil {
		return nil, err
	}
	defer clear(labelSecret)
	return self.expandWithLabel(kind, true, labelSecret, "exported", self.hash(context), length)
}

// A joiner's half of RFC §8.3: encapsulates to external_pub and exports the new init_secret, which
// the ExternalInit proposal's kem_output carries to the group.
func (self *mlsCipherSuite) externalInitSeal(externalPublicKey []byte) (kemOutput []byte, initSecret []byte, err error) {
	publicKey, err := self.kem.NewPublicKey(externalPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("mls: external public key: %w", err)
	}
	kemOutput, sender, err := hpke.NewSender(publicKey, self.kdf, self.aead, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("mls: hpke setup: %w", err)
	}
	initSecret, err = sender.Export(mlsExternalInitLabel, self.hashLength)
	if err != nil {
		return nil, nil, fmt.Errorf("mls: hpke export: %w", err)
	}
	testHookSecret("init_secret", initSecret)
	return kemOutput, initSecret, nil
}

// A member's half of RFC §8.3: the same init_secret from kem_output and external_priv.
func (self *mlsCipherSuite) externalInitOpen(externalPrivateKey hpke.PrivateKey, kemOutput []byte) ([]byte, error) {
	recipient, err := hpke.NewRecipient(kemOutput, externalPrivateKey, self.kdf, self.aead, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: hpke setup: %w", errMlsAuthentication, err)
	}
	initSecret, err := recipient.Export(mlsExternalInitLabel, self.hashLength)
	if err != nil {
		return nil, fmt.Errorf("mls: hpke export: %w", err)
	}
	testHookSecret("init_secret", initSecret)
	return initSecret, nil
}
