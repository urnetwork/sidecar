// GroupInfo (RFC 9420 §12.4.3): one epoch's GroupContext, its confirmation tag and extensions, signed by a
// leaf of that epoch. A joiner reads it twice over in §10.6: a Welcome carries one without the ratchet tree,
// and the full one, ratchet_tree and external_pub included, arrives sealed under K_groupinfo (§10.5), from the
// epoch object at 16 leaves or fewer and from group-info above. An external committer reads only the full one.
//
// Its signature covers its extensions, so the Welcome's copy and the full one are two signatures, each by the
// leaf that wrote it, over one GroupContext and one confirmation tag: a Welcome's is its committer's, and a full
// one above 16 leaves may be any leaf's (§10.6's group-info row). Neither is trusted until the tree the full one
// carries validates, hashes to the GroupContext's tree_hash, and holds the leaf whose key verifies it.
//
// On every leg, with no connect import. Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

// Signature labels (RFC §17.6).
const mlsSignatureLabelGroupInfo = "GroupInfoTBS"

// GroupInfo (RFC §12.4.3).
type mlsGroupInfo struct {
	groupContext    mlsGroupContext
	extensions      []mlsExtension
	confirmationTag []byte
	signer          mlsLeafIndex
	signature       []byte
}

// GroupInfoTBS.
func (self *mlsGroupInfo) encodeContent(encoder *mlsEncoder) {
	self.groupContext.encode(encoder)
	encoder.writeExtensions(self.extensions)
	encoder.writeVector(self.confirmationTag)
	encoder.writeUint32(uint32(self.signer))
}

// GroupInfo: GroupInfoTBS, then the signature.
func (self *mlsGroupInfo) encode(encoder *mlsEncoder) {
	self.encodeContent(encoder)
	encoder.writeVector(self.signature)
}

// GroupInfo, refusing what GroupContext and the extension lists refuse.
func (self *mlsGroupInfo) decode(decoder *mlsDecoder) {
	self.groupContext.decode(decoder)
	self.extensions = decoder.readExtensions()
	self.confirmationTag = decoder.readVector()
	self.signer = mlsLeafIndex(decoder.readUint32())
	self.signature = decoder.readVector()
}

// GroupInfoTBS's bytes.
func (self *mlsGroupInfo) toBeSigned() ([]byte, error) {
	encoder := &mlsEncoder{}
	self.encodeContent(encoder)
	return encoder.finish()
}

// Fills in the signature, over the fields as they stand.
func (self *mlsGroupInfo) sign(suite *mlsCipherSuite, signatureKey ed25519.PrivateKey) error {
	content, err := self.toBeSigned()
	if err != nil {
		return err
	}
	signature, err := suite.signWithLabel(signatureKey, mlsSignatureLabelGroupInfo, content)
	if err != nil {
		return err
	}
	self.signature = signature
	return nil
}

// Against verificationKey, the signer leaf's in a tree the caller already trusts.
func (self *mlsGroupInfo) verify(suite *mlsCipherSuite, verificationKey []byte) error {
	content, err := self.toBeSigned()
	if err != nil {
		return err
	}
	if !suite.verifyWithLabel(verificationKey, mlsSignatureLabelGroupInfo, content, self.signature) {
		return fmt.Errorf("%w: group info signature", errMlsAuthentication)
	}
	return nil
}

// Against the signer's leaf in tree, which must hold one there.
func (self *mlsGroupInfo) verifyIn(suite *mlsCipherSuite, tree *mlsRatchetTree) error {
	signer := tree.leafNode(self.signer)
	if signer == nil {
		return fmt.Errorf("%w: group info signed by leaf %d, which is blank", errMlsInvalid, self.signer)
	}
	return self.verify(suite, signer.signatureKey)
}

// The ratchet_tree extension's data: the tree as RFC §12.4.3.3 encodes it.
func mlsRatchetTreeExtension(tree *mlsRatchetTree) (mlsExtension, error) {
	encoded, err := mlsMarshal(tree)
	if err != nil {
		return mlsExtension{}, err
	}
	return mlsExtension{extensionType: mlsExtensionTypeRatchetTree, extensionData: encoded}, nil
}

// The external_pub extension's data: struct { HPKEPublicKey external_pub; } (RFC §12.4.3.2).
func mlsExternalPubExtension(externalPub []byte) (mlsExtension, error) {
	encoder := &mlsEncoder{}
	encoder.writeVector(externalPub)
	encoded, err := encoder.finish()
	if err != nil {
		return mlsExtension{}, err
	}
	return mlsExtension{extensionType: mlsExtensionTypeExternalPub, extensionData: encoded}, nil
}

// The tree a full GroupInfo carries, decoded under suite and settings. Refuses one with none: §10.6 sends the
// tree no other way.
func (self *mlsGroupInfo) ratchetTree(suite *mlsCipherSuite, settings *mlsTreeSettings) (*mlsRatchetTree, error) {
	extension := mlsFindExtension(self.extensions, mlsExtensionTypeRatchetTree)
	if extension == nil {
		return nil, fmt.Errorf("%w: a group info without its ratchet tree", errMlsInvalid)
	}
	return decodeMlsRatchetTree(suite, settings, extension.extensionData)
}

// external_pub, nil when the GroupInfo carries none.
func (self *mlsGroupInfo) externalPub() ([]byte, error) {
	extension := mlsFindExtension(self.extensions, mlsExtensionTypeExternalPub)
	if extension == nil {
		return nil, nil
	}
	decoder := &mlsDecoder{remaining: extension.extensionData}
	externalPub := decoder.readVector()
	if err := decoder.finish(); err != nil {
		return nil, err
	}
	return externalPub, nil
}

// A full GroupInfo's checks short of its signature, which needs the tree they return: the suite, the subset's
// GroupContext extensions, a tree that validates under them and hashes to tree_hash, and a signer leaf in it.
// validation's group id and extensions are taken from the GroupContext here.
func (self *mlsGroupInfo) checkTree(suite *mlsCipherSuite, settings *mlsTreeSettings, credentialValidator mlsCredentialValidator) (*mlsRatchetTree, error) {
	context := &self.groupContext
	if context.cipherSuite != suite.value {
		return nil, fmt.Errorf("%w: group info of suite %#x", errMlsInvalid, context.cipherSuite)
	}
	if err := context.checkHashLengths(suite); err != nil {
		return nil, err
	}
	if _, err := mlsCheckSubsetGroupExtensions(context.extensions); err != nil {
		return nil, err
	}
	tree, err := self.ratchetTree(suite, settings)
	if err != nil {
		return nil, err
	}
	validation := &mlsLeafValidation{
		groupId:             context.groupId,
		groupExtensions:     context.extensions,
		credentialValidator: credentialValidator,
	}
	if err := tree.validate(validation); err != nil {
		return nil, err
	}
	if err := mlsCheckUniqueSidecars(tree); err != nil {
		return nil, err
	}
	treeHash, err := tree.treeHash()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(treeHash, context.treeHash) {
		return nil, fmt.Errorf("%w: the tree does not hash to the group context's", errMlsInvalid)
	}
	if err := self.verifyIn(suite, tree); err != nil {
		return nil, err
	}
	return tree, nil
}

// One leaf per sidecar: every leaf's credential names another sidecar_id, so a resync's old leaf and a
// member's own leaf are each one leaf (§10.4: a leaf is a member device). Every leaf must already have
// passed mlsUrCredentialValidator.
func mlsCheckUniqueSidecars(tree *mlsRatchetTree) error {
	sidecarIds := map[Id]bool{}
	for index := range tree.leafCount() {
		leaf := tree.leafNode(mlsLeafIndex(index))
		if leaf == nil {
			continue
		}
		sidecarId, err := mlsLeafSidecarId(leaf)
		if err != nil {
			return err
		}
		if sidecarIds[sidecarId] {
			return fmt.Errorf("%w: two leaves of one sidecar", errMlsInvalid)
		}
		sidecarIds[sidecarId] = true
	}
	return nil
}

// The sidecar a leaf's credential names.
func mlsLeafSidecarId(leaf *mlsLeafNode) (Id, error) {
	if leaf.credential.credentialType != mlsCredentialTypeUrSidecar {
		if leaf.credential.credentialType == mlsCredentialTypeBasic && mlsTestReadsBasicCredentials {
			// the test groups' identities stand in for sidecar ids
			return mlsTestBasicSidecarId(leaf.credential.identity), nil
		}
		return Id{}, fmt.Errorf("%w: credential type %#x", errMlsRefused, leaf.credential.credentialType)
	}
	credential, err := mlsReadUrMlsCredential(leaf.credential.urMlsCredential)
	if err != nil {
		return Id{}, err
	}
	return Id(credential.GetSidecarId()), nil
}

// A basic identity as a sidecar id, for the test groups alone: its first 16 bytes, zero-padded.
func mlsTestBasicSidecarId(identity []byte) Id {
	var sidecarId Id
	copy(sidecarId[:], identity)
	return sidecarId
}
