// Welcome (RFC 9420 §12.4.3.1): how a commit's Adds join. Each joiner gets the epoch's joiner_secret, and the
// path secret of the lowest node it shares with the committer, sealed to its KeyPackage's init key, and every
// joiner gets the epoch's GroupInfo under welcome_secret.
//
// gkm stores a Welcome without the ratchet tree (§10.6), so a join takes two phases. openMlsWelcome is the
// first: it decrypts the group secrets and the GroupInfo, derives the epoch from joiner_secret and the
// GroupContext, and checks the confirmation tag, which only a holder of joiner_secret can make. That gives the
// epoch's exporter, KEK_e with it, which opens GenWrap_e and so K_groupinfo. The GroupInfo's signature cannot be
// checked yet, since the signer's key is in the tree it lacks, so nothing the Welcome says is trusted: RK_g stays
// provisional (KEYS-M2-04's seam). complete is the second phase, once the sealed GroupInfo is open: its tree
// must validate, hash to the GroupContext's tree_hash, hold the joiner's own KeyPackage leaf and the leaves whose
// keys verify both GroupInfos, and the path secret must give the keys the tree shows above the joiner.
//
// PSKs are refused (§10.4), so group secrets naming one are refused when parsed.
//
// On every leg, with no connect import. Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
)

// Public key encryption labels (RFC §17.7).
const mlsEncryptLabelWelcome = "Welcome"

// A Welcome names none of this sidecar's KeyPackages.
var errMlsWelcomeNotOurs = errors.New("mls: a Welcome to none of this sidecar's KeyPackages")

// GroupSecrets (RFC §12.4.3.1).
type mlsGroupSecrets struct {
	joinerSecret []byte
	// Nil when the commit carried no path.
	pathSecret []byte
}

// GroupSecrets, with no PSK.
func (self *mlsGroupSecrets) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.joinerSecret)
	encoder.writeOptional(self.pathSecret != nil)
	if self.pathSecret != nil {
		encoder.writeVector(self.pathSecret)
	}
	encoder.writeVector(nil)
}

// GroupSecrets, refusing any PSK (§10.4).
func (self *mlsGroupSecrets) decode(decoder *mlsDecoder) {
	self.joinerSecret = decoder.readVector()
	if decoder.readOptional() {
		self.pathSecret = decoder.readVector()
	}
	if psks := decoder.readVector(); decoder.err == nil && len(psks) != 0 {
		decoder.fail(fmt.Errorf("%w: group secrets naming a PSK", errMlsRefused))
	}
}

// Overwrites both secrets.
func (self *mlsGroupSecrets) erase() {
	clear(self.joinerSecret)
	clear(self.pathSecret)
}

// EncryptedGroupSecrets (RFC §12.4.3.1).
type mlsEncryptedGroupSecrets struct {
	// KeyPackageRef of the joiner's KeyPackage, which gkm's welcome pointers name in the clear (gkm-5).
	newMember             []byte
	encryptedGroupSecrets mlsHpkeCiphertext
}

// EncryptedGroupSecrets, in RFC §12.4.3.1's field order.
func (self *mlsEncryptedGroupSecrets) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.newMember)
	self.encryptedGroupSecrets.encode(encoder)
}

// EncryptedGroupSecrets, in RFC §12.4.3.1's field order.
func (self *mlsEncryptedGroupSecrets) decode(decoder *mlsDecoder) {
	self.newMember = decoder.readVector()
	self.encryptedGroupSecrets.decode(decoder)
}

// Welcome (RFC §12.4.3.1).
type mlsWelcome struct {
	cipherSuite        uint16
	secrets            []mlsEncryptedGroupSecrets
	encryptedGroupInfo []byte
}

// Welcome, in RFC §12.4.3.1's field order.
func (self *mlsWelcome) encode(encoder *mlsEncoder) {
	encoder.writeUint16(self.cipherSuite)
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for index := range self.secrets {
			self.secrets[index].encode(elements)
		}
	})
	encoder.writeVector(self.encryptedGroupInfo)
}

// Welcome, in RFC §12.4.3.1's field order.
func (self *mlsWelcome) decode(decoder *mlsDecoder) {
	self.cipherSuite = decoder.readUint16()
	decoder.readVectorOf(func(element *mlsDecoder) {
		var secrets mlsEncryptedGroupSecrets
		secrets.decode(element)
		self.secrets = append(self.secrets, secrets)
	})
	self.encryptedGroupInfo = decoder.readVector()
}

// The KeyPackageRefs a Welcome names, in order.
func (self *mlsWelcome) newMembers() [][]byte {
	refs := [][]byte{}
	for index := range self.secrets {
		refs = append(refs, self.secrets[index].newMember)
	}
	return refs
}

// One joiner of a commit's Welcome.
type mlsWelcomeJoiner struct {
	keyPackage *mlsKeyPackage
	// The path secret of the lowest node the joiner shares with the committer, nil without a path. Borrowed.
	pathSecret []byte
}

// A commit's Welcome as an MLSMessage: groupInfo, the new epoch's without its tree, sealed under welcomeSecret,
// and each joiner's group secrets sealed to its init key. The caller owns and erases both secrets.
func sealMlsWelcome(suite *mlsCipherSuite, joinerSecret []byte, welcomeSecret []byte, groupInfo *mlsGroupInfo, joiners []mlsWelcomeJoiner) ([]byte, error) {
	key, nonce, err := suite.deriveWelcomeKey(welcomeSecret)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	defer clear(nonce)
	encodedGroupInfo, err := mlsMarshal(groupInfo)
	if err != nil {
		return nil, err
	}
	welcome := &mlsWelcome{cipherSuite: suite.value}
	if welcome.encryptedGroupInfo, err = suite.aeadSeal(key, nonce, nil, encodedGroupInfo); err != nil {
		return nil, err
	}
	for _, joiner := range joiners {
		ref, err := joiner.keyPackage.ref(suite)
		if err != nil {
			return nil, err
		}
		encodedSecrets, err := mlsMarshal(&mlsGroupSecrets{joinerSecret: joinerSecret, pathSecret: joiner.pathSecret})
		if err != nil {
			return nil, err
		}
		kemOutput, ciphertext, err := suite.encryptWithLabel(joiner.keyPackage.initKey, mlsEncryptLabelWelcome, welcome.encryptedGroupInfo, encodedSecrets)
		clear(encodedSecrets)
		if err != nil {
			return nil, err
		}
		welcome.secrets = append(welcome.secrets, mlsEncryptedGroupSecrets{
			newMember:             ref,
			encryptedGroupSecrets: mlsHpkeCiphertext{kemOutput: kemOutput, ciphertext: ciphertext},
		})
	}
	return mlsMarshalMessageOf(mlsWireFormatWelcome, welcome)
}

// A Welcome after its first phase: its epoch derived, its confirmation tag checked, its GroupInfo's signature
// and tree not yet.
type mlsOpenedWelcome struct {
	suite *mlsCipherSuite
	held  *mlsHeldKeyPackage
	// The Welcome's own GroupInfo, without the tree.
	groupInfo           *mlsGroupInfo
	encodedGroupContext []byte
	epochSecrets        *mlsEpochSecrets
	// Nil when the commit carried no path.
	pathSecret []byte
}

// The first phase of a Welcome join under held, whose ref the Welcome must name: errMlsWelcomeNotOurs when it
// names none.
func openMlsWelcome(suite *mlsCipherSuite, welcome *mlsWelcome, held *mlsHeldKeyPackage) (*mlsOpenedWelcome, error) {
	if welcome.cipherSuite != suite.value || held.keyPackage.cipherSuite != suite.value {
		return nil, fmt.Errorf("%w: a Welcome of suite %#x", errMlsInvalid, welcome.cipherSuite)
	}
	var encrypted *mlsEncryptedGroupSecrets
	for index := range welcome.secrets {
		if bytes.Equal(welcome.secrets[index].newMember, held.ref) {
			encrypted = &welcome.secrets[index]
			break
		}
	}
	if encrypted == nil {
		return nil, errMlsWelcomeNotOurs
	}
	encodedSecrets, err := suite.decryptWithLabel(
		"group_secrets", held.initKey, mlsEncryptLabelWelcome, welcome.encryptedGroupInfo,
		encrypted.encryptedGroupSecrets.kemOutput, encrypted.encryptedGroupSecrets.ciphertext,
	)
	if err != nil {
		return nil, err
	}
	defer clear(encodedSecrets)
	groupSecrets := &mlsGroupSecrets{}
	if err := mlsUnmarshal(encodedSecrets, groupSecrets); err != nil {
		return nil, err
	}
	defer groupSecrets.erase()
	testHookSecret("joiner_secret", groupSecrets.joinerSecret)
	if groupSecrets.pathSecret != nil {
		testHookSecret("path_secret", groupSecrets.pathSecret)
	}
	if len(groupSecrets.joinerSecret) != suite.hashLength || (groupSecrets.pathSecret != nil && len(groupSecrets.pathSecret) != suite.hashLength) {
		return nil, fmt.Errorf("%w: group secrets of the wrong length", errMlsInvalid)
	}

	welcomeSecret, err := suite.deriveWelcomeSecret(groupSecrets.joinerSecret)
	if err != nil {
		return nil, err
	}
	defer clear(welcomeSecret)
	key, nonce, err := suite.deriveWelcomeKey(welcomeSecret)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	defer clear(nonce)
	encodedGroupInfo, err := suite.aeadOpen(key, nonce, nil, welcome.encryptedGroupInfo)
	if err != nil {
		return nil, err
	}
	groupInfo := &mlsGroupInfo{}
	if err := mlsUnmarshal(encodedGroupInfo, groupInfo); err != nil {
		return nil, err
	}
	if groupInfo.groupContext.cipherSuite != suite.value {
		return nil, fmt.Errorf("%w: a group info of suite %#x", errMlsInvalid, groupInfo.groupContext.cipherSuite)
	}
	encodedGroupContext, err := mlsMarshal(&groupInfo.groupContext)
	if err != nil {
		return nil, err
	}
	epochSecrets, err := suite.deriveEpochSecrets(groupSecrets.joinerSecret, nil, encodedGroupContext)
	if err != nil {
		return nil, err
	}
	if !suite.verifyConfirmationTag(epochSecrets.confirmationKey, groupInfo.groupContext.confirmedTranscriptHash, groupInfo.confirmationTag) {
		epochSecrets.erase()
		return nil, fmt.Errorf("%w: the Welcome's confirmation tag", errMlsAuthentication)
	}
	opened := &mlsOpenedWelcome{
		suite:               suite,
		held:                held,
		groupInfo:           groupInfo,
		encodedGroupContext: encodedGroupContext,
		epochSecrets:        epochSecrets,
	}
	if groupSecrets.pathSecret != nil {
		opened.pathSecret = bytes.Clone(groupSecrets.pathSecret)
	}
	return opened, nil
}

// The joined epoch's exporter, before anything the Welcome says is trusted.
func (self *mlsOpenedWelcome) exportSecret(label string, context []byte, length int) ([]byte, error) {
	return self.suite.exporter("exported_secret", self.epochSecrets.exporterSecret, label, context, length)
}

// Overwrites the phase's secrets, for a join that will not complete.
func (self *mlsOpenedWelcome) erase() {
	self.epochSecrets.erase()
	clear(self.pathSecret)
}

// The second phase: tree, from fullGroupInfo or for the mlswg's Welcomes from the Welcome's own GroupInfo or
// beside it, against the Welcome. fullGroupInfo, nil when the tree came another way, must carry the Welcome's
// GroupContext and confirmation tag and verify under its signer's leaf. tree must validate under validator and
// the GroupContext, hash to its tree_hash, hold this sidecar's KeyPackage leaf and the leaf whose key verifies
// the Welcome's GroupInfo, and agree with the path secret. Nothing of this sidecar's changes on a refusal, and
// the opened Welcome stays usable, so a forged GroupInfo leaves the true one to complete it.
func (self *mlsOpenedWelcome) complete(tree *mlsRatchetTree, fullGroupInfo *mlsGroupInfo, settings *mlsGroupSettings, credentialValidator mlsCredentialValidator) (*mlsGroupState, error) {
	suite := self.suite
	context := &self.groupInfo.groupContext
	if fullGroupInfo != nil {
		fullContext, err := mlsMarshal(&fullGroupInfo.groupContext)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(fullContext, self.encodedGroupContext) || !bytes.Equal(fullGroupInfo.confirmationTag, self.groupInfo.confirmationTag) {
			return nil, fmt.Errorf("%w: a group info of another epoch than the Welcome's", errMlsInvalid)
		}
	}
	validation := &mlsLeafValidation{
		groupId:             context.groupId,
		groupExtensions:     context.extensions,
		credentialValidator: credentialValidator,
	}
	if err := tree.validate(validation); err != nil {
		return nil, err
	}
	treeHash, err := tree.treeHash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(treeHash, context.treeHash) {
		return nil, fmt.Errorf("%w: the tree does not hash to the Welcome's group context", errMlsInvalid)
	}
	if err := self.groupInfo.verifyIn(suite, tree); err != nil {
		return nil, err
	}
	if fullGroupInfo != nil {
		if err := fullGroupInfo.verifyIn(suite, tree); err != nil {
			return nil, err
		}
	}

	ownLeafNode, err := mlsMarshal(&self.held.keyPackage.leafNode)
	if err != nil {
		return nil, err
	}
	ownLeaf := mlsLeafIndex(0)
	found := false
	for index := range tree.leafCount() {
		leaf := tree.leafNode(mlsLeafIndex(index))
		if leaf == nil {
			continue
		}
		encoded, err := mlsMarshal(leaf)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(encoded, ownLeafNode) {
			ownLeaf, found = mlsLeafIndex(index), true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: the tree holds no leaf of this sidecar's KeyPackage", errMlsInvalid)
	}
	signer := self.groupInfo.signer
	if signer == ownLeaf {
		return nil, fmt.Errorf("%w: a Welcome signed by its own joiner", errMlsInvalid)
	}

	treeSecrets := newMlsTreeSecrets(suite, ownLeaf, self.held.leafKey)
	if self.pathSecret != nil {
		if err := treeSecrets.implantWelcomePath(tree, signer, self.pathSecret); err != nil {
			return nil, err
		}
	}
	interimTranscriptHash, err := suite.nextInterimTranscriptHash(context.confirmedTranscriptHash, self.groupInfo.confirmationTag)
	if err != nil {
		return nil, err
	}
	state, err := newMlsGroupState(&mlsGroupStateArgs{
		suite:                 suite,
		settings:              settings,
		credentialValidator:   credentialValidator,
		groupContext:          context,
		tree:                  tree,
		treeSecrets:           treeSecrets,
		signatureKey:          self.held.signatureKey,
		interimTranscriptHash: interimTranscriptHash,
		confirmationTag:       self.groupInfo.confirmationTag,
		epochSecrets:          self.epochSecrets,
	})
	if err != nil {
		return nil, err
	}
	if fullGroupInfo != nil {
		// external_pub, where the full one carries it, must be the epoch's own
		externalPub, err := fullGroupInfo.externalPub()
		if err != nil {
			return nil, err
		}
		if externalPub != nil {
			own, err := state.externalPub()
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(externalPub, own) {
				return nil, fmt.Errorf("%w: a group info naming another external key", errMlsInvalid)
			}
		}
	}
	return state, nil
}
