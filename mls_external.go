// External commits (RFC 9420 §12.4.3.2), which §10.4 takes only to resync or recover (KF5, §10.8): a sidecar
// outside the epoch joins from its full GroupInfo, by an ExternalInit that exports the new epoch's init_secret
// to the group's external_pub, at most a Remove of its own old leaf, and a path that installs its new leaf in
// the leftmost blank one. It is a PublicMessage, signed by that new leaf (D-KEYS-3).
//
// The old leaf a resync removes is found by sidecar_id and identity key, never by signature key, because
// self-updates rotate mls_signature_public_key (§10.9's External row). A Remove of anyone else's leaf is refused
// on both sides, and so is a join that would leave two leaves of one sidecar.
//
// Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
)

// Stages an external commit from groupInfo, already checked with its tree by checkTree: identity's new leaf, a
// Remove of removes, which may name only identity's own old leaf, and authenticatedData in the clear. Returns the
// commit staged with its next epoch, this sidecar's.
func mlsStageExternalCommit(suite *mlsCipherSuite, settings *mlsGroupSettings, credentialValidator mlsCredentialValidator, groupInfo *mlsGroupInfo, tree *mlsRatchetTree, identity *mlsLeafIdentity, removes []mlsLeafIndex, authenticatedData []byte) (*mlsStagedState, error) {
	externalPub, err := groupInfo.externalPub()
	if err != nil {
		return nil, err
	}
	if externalPub == nil {
		return nil, fmt.Errorf("%w: a group info with no external_pub", errMlsInvalid)
	}
	if 1 < len(removes) {
		return nil, fmt.Errorf("%w: an external commit removing %d leaves", errMlsInvalid, len(removes))
	}
	context := &groupInfo.groupContext
	encodedContext, err := mlsMarshal(context)
	if err != nil {
		return nil, err
	}
	template := &mlsLeafNode{
		signatureKey:   []byte(identity.signatureKey.Public().(ed25519.PublicKey)),
		credential:     identity.credential,
		capabilities:   identity.leafCapabilities(suite),
		leafNodeSource: mlsLeafNodeSourceCommit,
	}

	next := tree.clone()
	commit := &mlsCommit{}
	removed := []mlsRemovedLeaf{}
	for _, index := range removes {
		old := tree.leafNode(index)
		if old == nil || !mlsSameIdentity(old, template) {
			return nil, fmt.Errorf("%w: an external commit removes only its sender's old leaf", errMlsInvalid)
		}
		removed = append(removed, mlsRemovedLeaf{index: index, leaf: old})
		if err := next.removeLeaf(index); err != nil {
			return nil, err
		}
	}
	sender, err := next.reserveLeaf()
	if err != nil {
		return nil, err
	}
	prepared, err := next.prepareUpdatePath(sender, template, identity.signatureKey, context.groupId)
	if err != nil {
		return nil, err
	}
	defer prepared.erase()
	defer clear(prepared.commitSecret)
	if err := next.validateNewLeaf(prepared.leafNode, sender, mlsLeafNodeSourceCommit, &mlsLeafValidation{
		groupId:             context.groupId,
		groupExtensions:     context.extensions,
		credentialValidator: credentialValidator,
	}); err != nil {
		return nil, err
	}
	if err := mlsCheckUniqueSidecars(next); err != nil {
		return nil, fmt.Errorf("%w: a resync that keeps its old leaf", err)
	}

	// a group state at the GroupInfo's epoch, as far as an outsider holds one, to derive the next from
	base := &mlsGroupState{suite: suite, settings: settings, credentialValidator: credentialValidator, groupContext: context, encodedGroupContext: encodedContext, tree: tree}
	_, provisional, err := base.nextGroupContext(next, context.extensions, context.confirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	kemOutput, initSecret, err := suite.externalInitSeal(externalPub)
	if err != nil {
		return nil, err
	}
	defer clear(initSecret)
	commit.proposals = append(commit.proposals, mlsProposal{proposalType: mlsProposalTypeExternalInit, kemOutput: kemOutput})
	for _, index := range removes {
		commit.proposals = append(commit.proposals, mlsProposal{proposalType: mlsProposalTypeRemove, removed: index})
	}
	if commit.path, err = prepared.encrypt(provisional, nil); err != nil {
		return nil, err
	}

	authenticated := &mlsAuthenticatedContent{
		wireFormat: mlsWireFormatPublicMessage,
		content: mlsFramedContent{
			groupId:           context.groupId,
			epoch:             context.epoch,
			sender:            mlsSender{senderType: mlsSenderTypeNewMemberCommit},
			authenticatedData: bytes.Clone(authenticatedData),
			contentType:       mlsContentTypeCommit,
			body:              commit,
		},
	}
	if err := authenticated.sign(suite, identity.signatureKey, encodedContext); err != nil {
		return nil, err
	}
	interimTranscriptHash, err := suite.nextInterimTranscriptHash(context.confirmedTranscriptHash, groupInfo.confirmationTag)
	if err != nil {
		return nil, err
	}
	nextEpoch, err := base.deriveNextEpoch(authenticated, interimTranscriptHash, next, context.extensions, initSecret, prepared.commitSecret)
	if err != nil {
		return nil, err
	}
	defer nextEpoch.epochSecrets.erase()
	authenticated.auth.confirmationTag = nextEpoch.confirmationTag
	message, err := mlsMarshal(&mlsMessage{
		wireFormat:    mlsWireFormatPublicMessage,
		publicMessage: &mlsPublicMessage{content: authenticated.content, auth: authenticated.auth},
	})
	if err != nil {
		return nil, err
	}

	treeSecrets := newMlsTreeSecrets(suite, sender, prepared.leafKey)
	prepared.adopt(treeSecrets)
	nextState, err := newMlsGroupState(&mlsGroupStateArgs{
		suite:                 suite,
		settings:              settings,
		credentialValidator:   credentialValidator,
		groupContext:          nextEpoch.groupContext,
		tree:                  next,
		treeSecrets:           treeSecrets,
		signatureKey:          identity.signatureKey,
		interimTranscriptHash: nextEpoch.interimTranscriptHash,
		confirmationTag:       nextEpoch.confirmationTag,
		epochSecrets:          nextEpoch.epochSecrets,
	})
	if err != nil {
		return nil, err
	}
	return &mlsStagedState{
		baseEpoch:         context.epoch,
		message:           message,
		external:          true,
		committer:         sender,
		committerLeaf:     prepared.leafNode,
		removed:           removed,
		authenticatedData: bytes.Clone(authenticatedData),
		next:              nextState,
	}, nil
}

// An external commit received by a member, its signature already checked against its path's leaf: its
// ExternalInit opened under this epoch's external_priv, its Remove holding only the joiner's old leaf, its leaf
// in the leftmost blank one, and its path and confirmation tag checked as a member commit's are.
func (self *mlsGroupState) processExternalCommit(authenticated *mlsAuthenticatedContent, commit *mlsCommit) (*mlsStagedState, error) {
	suite := self.suite
	own := self.ownLeaf()
	removedIndex, err := mlsExternalCommitRemoval(commit)
	if err != nil {
		return nil, err
	}
	var kemOutput []byte
	for index := range commit.proposals {
		if commit.proposals[index].proposalType == mlsProposalTypeExternalInit {
			kemOutput = commit.proposals[index].kemOutput
		}
	}
	pathLeaf := &commit.path.leafNode
	tree := self.tree.clone()
	removed := []mlsRemovedLeaf{}
	removesSelf := false
	if removedIndex != nil {
		old := self.tree.leafNode(*removedIndex)
		if old == nil || !mlsSameIdentity(old, pathLeaf) {
			return nil, fmt.Errorf("%w: an external commit removing a leaf not its sender's", errMlsInvalid)
		}
		removed = append(removed, mlsRemovedLeaf{index: *removedIndex, leaf: old})
		removesSelf = *removedIndex == own
		if err := tree.removeLeaf(*removedIndex); err != nil {
			return nil, err
		}
	}
	sender, err := tree.reserveLeaf()
	if err != nil {
		return nil, err
	}
	extensions := self.groupContext.extensions
	if err := tree.mergeUpdatePath(sender, commit.path, nil, self.leafValidation(extensions)); err != nil {
		return nil, err
	}
	if err := mlsCheckUniqueSidecars(tree); err != nil {
		return nil, err
	}
	staged := &mlsStagedState{
		external:      true,
		committer:     sender,
		committerLeaf: pathLeaf,
		removed:       removed,
		removesSelf:   removesSelf,
	}
	if removesSelf {
		return staged, nil
	}

	externalKey, err := suite.deriveExternalKey(self.externalSecret)
	if err != nil {
		return nil, err
	}
	initSecret, err := suite.externalInitOpen(externalKey, kemOutput)
	if err != nil {
		return nil, err
	}
	defer clear(initSecret)
	_, provisional, err := self.nextGroupContext(tree, extensions, self.groupContext.confirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	received, err := self.treeSecrets.receiveUpdatePath(tree, sender, commit.path, provisional, nil)
	if err != nil {
		return nil, err
	}
	defer clear(received.commitSecret)
	next, err := self.deriveNextEpoch(authenticated, self.interimTranscriptHash, tree, extensions, initSecret, received.commitSecret)
	if err != nil {
		return nil, err
	}
	defer next.epochSecrets.erase()
	if !suite.verifyMac(next.epochSecrets.confirmationKey, next.groupContext.confirmedTranscriptHash, authenticated.auth.confirmationTag) {
		return nil, fmt.Errorf("%w: confirmation tag", errMlsAuthentication)
	}
	treeSecrets := self.treeSecrets.clone()
	received.adopt(treeSecrets)
	staged.next, err = newMlsGroupState(&mlsGroupStateArgs{
		suite:                 suite,
		settings:              self.settings,
		credentialValidator:   self.credentialValidator,
		groupContext:          next.groupContext,
		tree:                  tree,
		treeSecrets:           treeSecrets,
		signatureKey:          self.signatureKey,
		interimTranscriptHash: next.interimTranscriptHash,
		confirmationTag:       next.confirmationTag,
		epochSecrets:          next.epochSecrets,
	})
	if err != nil {
		return nil, err
	}
	return staged, nil
}
