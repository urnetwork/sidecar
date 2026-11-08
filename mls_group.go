// One group's state at one epoch, as one member holds it, and the commits that move it (RFC 9420 §11, §12.2 to
// §12.4): §10.4's subset, Add, Remove and GroupContextExtensions inline, path-only commits for self-update, and
// external commits (mls_external.go). Everything else the RFC frames is refused when parsed (mls_framing.go,
// mls_proposal.go, mls_commit.go), and here a member's commit holding an ExternalInit, a Remove of its own
// committer or a Remove without a path is refused too (RFC §12.2, §10.4).
//
// A commit, made here or received, is staged: its next epoch is computed in full on clones, the member's keys
// and the tree included, and nothing of the current epoch changes until the engine adopts it (D-KEYS-5; RFC
// §14). A received commit is staged once its signature, its proposals, its path and its confirmation tag hold;
// whether its committer may make it is §10.9's, judged by the caller at its auth pin before it adopts. A commit
// that removes this member stages with no next epoch, since a removed leaf derives none.
//
// The subset's structural rules are held here, never left to the caller: every GroupContext carries ur_group
// unchanged from creation and requires 0xF552 and ur_group of every leaf (mls_extension.go), every leaf is a
// different sidecar, and a path's new leaf keeps its sidecar_id and identity key, since a self-update rotates the
// signature key and nothing else (§10.9's Self-update row).
//
// A member's commits are PrivateMessages under the epoch's secret tree. Its own handshake generation never
// repeats within an epoch, even across a restart, because the engine reserves each before it seals (§10.4: each
// AEAD key is used once).
//
// Every secret here is hooked where it is made: the key schedule, TreeKEM and the suite do it.
//
// Not safe for concurrent use; one owner drives a state and what it stages.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"fmt"
	"maps"
	"slices"
	"time"
)

// Tunes a group: its tree and its messages.
type mlsGroupSettings struct {
	Tree    *mlsTreeSettings
	Message *mlsMessageSettings
}

// The defaults every group runs on outside tests.
func defaultMlsGroupSettings() *mlsGroupSettings {
	return &mlsGroupSettings{
		Tree:    defaultMlsTreeSettings(),
		Message: defaultMlsMessageSettings(),
	}
}

// One epoch of one group as this member holds it.
type mlsGroupState struct {
	suite               *mlsCipherSuite
	settings            *mlsGroupSettings
	credentialValidator mlsCredentialValidator

	groupContext        *mlsGroupContext
	encodedGroupContext []byte
	tree                *mlsRatchetTree
	// This member's private keys, its leaf index among them.
	treeSecrets  *mlsTreeSecrets
	signatureKey ed25519.PrivateKey

	interimTranscriptHash []byte
	// The tag of the commit that made this epoch, which every GroupInfo of it carries.
	confirmationTag []byte

	// What this epoch keeps of RFC §8's table 4: the next epoch's input, the exporter, external_priv's
	// secret, the secret tree's two roots and the authenticator. The rest is erased as it is derived.
	initSecret         []byte
	exporterSecret     []byte
	externalSecret     []byte
	encryptionSecret   []byte
	senderDataSecret   []byte
	epochAuthenticator []byte

	// The next handshake generation this member may seal at.
	handshakeGeneration uint32
	// Built on first use.
	protection *mlsMessageProtection
}

// What newMlsGroupState builds a state from.
type mlsGroupStateArgs struct {
	suite                 *mlsCipherSuite
	settings              *mlsGroupSettings
	credentialValidator   mlsCredentialValidator
	groupContext          *mlsGroupContext
	tree                  *mlsRatchetTree
	treeSecrets           *mlsTreeSecrets
	signatureKey          ed25519.PrivateKey
	interimTranscriptHash []byte
	confirmationTag       []byte
	// Copied: the caller still owns and erases these.
	epochSecrets        *mlsEpochSecrets
	handshakeGeneration uint32
}

// A state over args, holding copies of the epoch secrets it keeps.
func newMlsGroupState(args *mlsGroupStateArgs) (*mlsGroupState, error) {
	encodedGroupContext, err := mlsMarshal(args.groupContext)
	if err != nil {
		return nil, err
	}
	return &mlsGroupState{
		suite:                 args.suite,
		settings:              args.settings,
		credentialValidator:   args.credentialValidator,
		groupContext:          args.groupContext,
		encodedGroupContext:   encodedGroupContext,
		tree:                  args.tree,
		treeSecrets:           args.treeSecrets,
		signatureKey:          ed25519.PrivateKey(bytes.Clone(args.signatureKey)),
		interimTranscriptHash: bytes.Clone(args.interimTranscriptHash),
		confirmationTag:       bytes.Clone(args.confirmationTag),
		initSecret:            bytes.Clone(args.epochSecrets.initSecret),
		exporterSecret:        bytes.Clone(args.epochSecrets.exporterSecret),
		externalSecret:        bytes.Clone(args.epochSecrets.externalSecret),
		encryptionSecret:      bytes.Clone(args.epochSecrets.encryptionSecret),
		senderDataSecret:      bytes.Clone(args.epochSecrets.senderDataSecret),
		epochAuthenticator:    bytes.Clone(args.epochSecrets.epochAuthenticator),
		handshakeGeneration:   args.handshakeGeneration,
	}, nil
}

// Overwrites every secret this epoch keeps, at its end (RFC §9.2). The node keys are hpke's and cannot be
// overwritten, so they are dropped; the leaf index stays, so the public state still reads.
func (self *mlsGroupState) erase() {
	clear(self.initSecret)
	clear(self.exporterSecret)
	clear(self.externalSecret)
	clear(self.encryptionSecret)
	clear(self.senderDataSecret)
	clear(self.signatureKey)
	if self.protection != nil {
		self.protection.erase()
		self.protection = nil
	}
	clear(self.treeSecrets.nodeIndexKeys)
}

// This member's leaf.
func (self *mlsGroupState) ownLeaf() mlsLeafIndex {
	return self.treeSecrets.leaf
}

// The group's id.
func (self *mlsGroupState) groupId() []byte {
	return self.groupContext.groupId
}

// The epoch this state is at.
func (self *mlsGroupState) epoch() uint64 {
	return self.groupContext.epoch
}

// MLS-Exporter (RFC §8.5) of this epoch.
func (self *mlsGroupState) exportSecret(label string, context []byte, length int) ([]byte, error) {
	return self.suite.exporter("exported_secret", self.exporterSecret, label, context, length)
}

// external_pub, which a full GroupInfo carries for external commits (RFC §12.4.3.2).
func (self *mlsGroupState) externalPub() ([]byte, error) {
	externalKey, err := self.suite.deriveExternalKey(self.externalSecret)
	if err != nil {
		return nil, err
	}
	return externalKey.PublicKey().Bytes(), nil
}

// The epoch's GroupInfo signed by this member's leaf: the full one, ratchet_tree and external_pub included, or
// a Welcome's, with neither (§10.6).
func (self *mlsGroupState) groupInfo(full bool) (*mlsGroupInfo, error) {
	groupInfo := &mlsGroupInfo{
		groupContext:    *self.groupContext,
		confirmationTag: self.confirmationTag,
		signer:          self.ownLeaf(),
	}
	if full {
		treeExtension, err := mlsRatchetTreeExtension(self.tree)
		if err != nil {
			return nil, err
		}
		externalPub, err := self.externalPub()
		if err != nil {
			return nil, err
		}
		externalPubExtension, err := mlsExternalPubExtension(externalPub)
		if err != nil {
			return nil, err
		}
		groupInfo.extensions = []mlsExtension{treeExtension, externalPubExtension}
	}
	if err := groupInfo.sign(self.suite, self.signatureKey); err != nil {
		return nil, err
	}
	return groupInfo, nil
}

// The full GroupInfo as an MLSMessage.
func (self *mlsGroupState) encodedGroupInfo() ([]byte, error) {
	groupInfo, err := self.groupInfo(true)
	if err != nil {
		return nil, err
	}
	return mlsMarshalMessageOf(mlsWireFormatGroupInfo, groupInfo)
}

// The epoch's message protection, built on first use.
func (self *mlsGroupState) messageProtection() (*mlsMessageProtection, error) {
	if self.protection == nil {
		protection, err := newMlsMessageProtection(self.suite, self.settings.Message, self.groupContext, self.tree, self.encryptionSecret, self.senderDataSecret)
		if err != nil {
			return nil, err
		}
		self.protection = protection
	}
	return self.protection, nil
}

// The leaf validation every leaf entering this group runs, under extensions.
func (self *mlsGroupState) leafValidation(extensions []mlsExtension) *mlsLeafValidation {
	return &mlsLeafValidation{
		groupId:             self.groupContext.groupId,
		groupExtensions:     extensions,
		credentialValidator: self.credentialValidator,
	}
}

// One leaf as the seam shows it.
func mlsMemberOf(leafIndex mlsLeafIndex, leaf *mlsLeafNode) (MlsMember, error) {
	sidecarId, err := mlsLeafSidecarId(leaf)
	if err != nil {
		return MlsMember{}, err
	}
	return MlsMember{LeafIndex: uint32(leafIndex), SidecarId: sidecarId, Credential: bytes.Clone(leaf.credential.body())}, nil
}

// Every leaf of the epoch, by index.
func (self *mlsGroupState) roster() ([]MlsMember, error) {
	members := []MlsMember{}
	for index := range self.tree.leafCount() {
		leaf := self.tree.leafNode(mlsLeafIndex(index))
		if leaf == nil {
			continue
		}
		member, err := mlsMemberOf(mlsLeafIndex(index), leaf)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, nil
}

// Whether two leaves are one sidecar under one identity key: the same sidecar_id and identity_public_key in
// their credentials, read as they entered the tree. A self-update's new leaf must be, and so must a resync's
// old leaf and new one.
func mlsSameIdentity(first *mlsLeafNode, second *mlsLeafNode) bool {
	if first.credential.credentialType != second.credential.credentialType {
		return false
	}
	if first.credential.credentialType != mlsCredentialTypeUrSidecar {
		return bytes.Equal(first.credential.identity, second.credential.identity)
	}
	firstCredential, err := mlsReadUrMlsCredential(first.credential.urMlsCredential)
	if err != nil {
		return false
	}
	secondCredential, err := mlsReadUrMlsCredential(second.credential.urMlsCredential)
	if err != nil {
		return false
	}
	return bytes.Equal(firstCredential.GetSidecarId(), secondCredential.GetSidecarId()) &&
		bytes.Equal(firstCredential.GetIdentityPublicKey(), secondCredential.GetIdentityPublicKey())
}

// A new group at epoch 0 whose only leaf is identity's (RFC §11), with extensions as its GroupContext's, which
// must be the subset's.
func newMlsGroup(suite *mlsCipherSuite, settings *mlsGroupSettings, credentialValidator mlsCredentialValidator, groupId []byte, extensions []mlsExtension, identity *mlsLeafIdentity, lifetime mlsLifetime) (*mlsGroupState, error) {
	if _, err := mlsCheckSubsetGroupExtensions(extensions); err != nil {
		return nil, err
	}
	leafKey, err := suite.generateKemKey("leaf_priv")
	if err != nil {
		return nil, err
	}
	leaf := &mlsLeafNode{
		encryptionKey:  leafKey.PublicKey().Bytes(),
		signatureKey:   []byte(identity.signatureKey.Public().(ed25519.PublicKey)),
		credential:     identity.credential,
		capabilities:   mlsSubsetCapabilities(suite),
		leafNodeSource: mlsLeafNodeSourceKeyPackage,
		lifetime:       lifetime,
	}
	if err := leaf.sign(suite, identity.signatureKey, nil, 0); err != nil {
		return nil, err
	}
	tree := newMlsRatchetTree(suite, settings.Tree, leaf)
	if err := tree.validateGroupCompatibility(leaf, extensions); err != nil {
		return nil, err
	}
	treeHash, err := tree.treeHash()
	if err != nil {
		return nil, err
	}
	groupContext := &mlsGroupContext{
		cipherSuite:             suite.value,
		groupId:                 bytes.Clone(groupId),
		epoch:                   0,
		treeHash:                treeHash,
		confirmedTranscriptHash: []byte{},
		extensions:              extensions,
	}
	epochSecrets, err := suite.newGroupEpochSecrets()
	if err != nil {
		return nil, err
	}
	defer epochSecrets.erase()
	confirmationTag := suite.confirmationTag(epochSecrets.confirmationKey, groupContext.confirmedTranscriptHash)
	interimTranscriptHash, err := suite.nextInterimTranscriptHash(groupContext.confirmedTranscriptHash, confirmationTag)
	if err != nil {
		return nil, err
	}
	return newMlsGroupState(&mlsGroupStateArgs{
		suite:                 suite,
		settings:              settings,
		credentialValidator:   credentialValidator,
		groupContext:          groupContext,
		tree:                  tree,
		treeSecrets:           newMlsTreeSecrets(suite, 0, leafKey),
		signatureKey:          identity.signatureKey,
		interimTranscriptHash: interimTranscriptHash,
		confirmationTag:       confirmationTag,
		epochSecrets:          epochSecrets,
	})
}

// A leaf of the epoch a commit removes, as it stood there.
type mlsRemovedLeaf struct {
	index mlsLeafIndex
	leaf  *mlsLeafNode
}

// A commit staged on a state: its message, what it changes, and the next epoch, nil when it removes this
// member.
type mlsStagedState struct {
	// The epoch it is staged on, which adoption requires to be still held.
	baseEpoch              uint64
	baseEpochAuthenticator []byte

	message []byte
	// external: an external commit, whose committer is its new leaf
	external bool
	// in the old epoch, or for an external commit in the new one
	committer     mlsLeafIndex
	committerLeaf *mlsLeafNode
	// in the new epoch
	added   []mlsLeafIndex
	removed []mlsRemovedLeaf
	// GkmCommitHeader's encoding, as the commit authenticated it
	authenticatedData []byte
	// This member's own commit's Welcome, nil without Adds or for a received commit.
	welcome []byte

	removesSelf bool
	next        *mlsGroupState
}

// The leaves a commit adds, in the new epoch.
func (self *mlsStagedState) addedMembers() ([]MlsMember, error) {
	members := []MlsMember{}
	for _, index := range self.added {
		member, err := mlsMemberOf(index, self.next.tree.leafNode(index))
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, nil
}

// The leaves a commit removes, as they were in the old epoch.
func (self *mlsStagedState) removedMembers() ([]MlsMember, error) {
	members := []MlsMember{}
	for _, removed := range self.removed {
		member, err := mlsMemberOf(removed.index, removed.leaf)
		if err != nil {
			return nil, err
		}
		members = append(members, member)
	}
	return members, nil
}

// What a member commit made here changes.
type mlsCommitInput struct {
	// Decoded KeyPackages of the devices it adds, checked against the group here.
	adds    []*mlsKeyPackage
	removes []mlsLeafIndex
	path    bool
	// A GroupContextExtensions proposal's list, nil for none.
	groupContextExtensions []mlsExtension
	authenticatedData      []byte
	// The leaf a path installs: a new signature key and its credential. Required with a path.
	pathIdentity *mlsLeafIdentity
	// The handshake generation to seal at, which the engine reserved.
	generation uint32
	// When the KeyPackages must be inside their lifetimes (RFC §7.3).
	now time.Time
}

// The proposals a member commit holds, sorted by type, once RFC §12.2's list rules and the subset's hold.
type mlsCommitProposals struct {
	adds                   []*mlsKeyPackage
	removes                []mlsLeafIndex
	groupContextExtensions []mlsExtension
	hasGroupContextExtensions bool
}

// RFC §12.2's list rules for a member's commit, and §10.4's: Add, Remove and GroupContextExtensions alone, no
// leaf removed twice, never the committer, at most one GroupContextExtensions, and a path whenever there is a
// Remove, a GroupContextExtensions or no proposal at all (RFC §17.4's path column; §10.4).
func (self *mlsGroupState) checkMemberProposals(committer mlsLeafIndex, proposalList []mlsProposal, hasPath bool, sendingAt *time.Time) (*mlsCommitProposals, error) {
	proposals := &mlsCommitProposals{}
	for index := range proposalList {
		proposal := &proposalList[index]
		switch proposal.proposalType {
		case mlsProposalTypeAdd:
			if err := proposal.keyPackage.validate(self.suite, self.settings.Tree, self.credentialValidator, sendingAt); err != nil {
				return nil, err
			}
			proposals.adds = append(proposals.adds, proposal.keyPackage)
		case mlsProposalTypeRemove:
			if proposal.removed == committer {
				return nil, fmt.Errorf("%w: a committer removing itself (RFC 9420 §12.2)", errMlsInvalid)
			}
			if slices.Contains(proposals.removes, proposal.removed) {
				return nil, fmt.Errorf("%w: leaf %d removed twice", errMlsInvalid, proposal.removed)
			}
			if self.tree.leafNode(proposal.removed) == nil {
				return nil, fmt.Errorf("%w: a Remove of leaf %d, which is blank", errMlsInvalid, proposal.removed)
			}
			proposals.removes = append(proposals.removes, proposal.removed)
		case mlsProposalTypeGroupContextExtensions:
			if proposals.hasGroupContextExtensions {
				return nil, fmt.Errorf("%w: two GroupContextExtensions proposals", errMlsInvalid)
			}
			if err := mlsCheckGroupExtensionsChange(self.groupContext.extensions, proposal.extensions); err != nil {
				return nil, err
			}
			proposals.groupContextExtensions = proposal.extensions
			proposals.hasGroupContextExtensions = true
		default:
			return nil, fmt.Errorf("%w: a member's commit with proposal type %#x", errMlsInvalid, proposal.proposalType)
		}
	}
	pathRequired := len(proposals.removes) != 0 || proposals.hasGroupContextExtensions || len(proposalList) == 0
	if pathRequired && !hasPath {
		return nil, fmt.Errorf("%w: a commit with no path that needs one (§10.4)", errMlsInvalid)
	}
	return proposals, nil
}

// The tree after a member commit's proposals, in RFC §12.3's order: GroupContextExtensions, Removes, then Adds,
// each Add's leaf checked as it enters, then every leaf against the new extensions. Returns the tree, the new
// extensions, the leaves removed as they stood, and the leaves added.
func (self *mlsGroupState) applyMemberProposals(proposals *mlsCommitProposals) (*mlsRatchetTree, []mlsExtension, []mlsRemovedLeaf, []mlsLeafIndex, error) {
	extensions := self.groupContext.extensions
	if proposals.hasGroupContextExtensions {
		extensions = proposals.groupContextExtensions
	}
	validation := self.leafValidation(extensions)
	tree := self.tree.clone()
	removed := []mlsRemovedLeaf{}
	for _, index := range proposals.removes {
		removed = append(removed, mlsRemovedLeaf{index: index, leaf: self.tree.leafNode(index)})
		if err := tree.removeLeaf(index); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	added := []mlsLeafIndex{}
	for _, keyPackage := range proposals.adds {
		index, err := tree.addLeaf(&keyPackage.leafNode)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if err := tree.validateNewLeaf(&keyPackage.leafNode, index, mlsLeafNodeSourceKeyPackage, validation); err != nil {
			return nil, nil, nil, nil, err
		}
		added = append(added, index)
	}
	if proposals.hasGroupContextExtensions {
		for index := range tree.leafCount() {
			if leaf := tree.leafNode(mlsLeafIndex(index)); leaf != nil {
				if err := tree.validateGroupCompatibility(leaf, extensions); err != nil {
					return nil, nil, nil, nil, fmt.Errorf("leaf %d: %w", index, err)
				}
			}
		}
	}
	if err := mlsCheckUniqueSidecars(tree); err != nil {
		return nil, nil, nil, nil, err
	}
	return tree, extensions, removed, added, nil
}

// The GroupContext of the next epoch over tree, with confirmedTranscriptHash: the old one for the provisional
// context a path encrypts under, the new one once the commit is signed.
func (self *mlsGroupState) nextGroupContext(tree *mlsRatchetTree, extensions []mlsExtension, confirmedTranscriptHash []byte) (*mlsGroupContext, []byte, error) {
	treeHash, err := tree.treeHash()
	if err != nil {
		return nil, nil, err
	}
	context := &mlsGroupContext{
		cipherSuite:             self.groupContext.cipherSuite,
		groupId:                 self.groupContext.groupId,
		epoch:                   self.groupContext.epoch + 1,
		treeHash:                treeHash,
		confirmedTranscriptHash: confirmedTranscriptHash,
		extensions:              extensions,
	}
	encoded, err := mlsMarshal(context)
	if err != nil {
		return nil, nil, err
	}
	return context, encoded, nil
}

// The next epoch's schedule from a signed commit: its confirmed transcript hash, GroupContext, secrets and
// confirmation tag. initSecret is the old epoch's, or an external commit's from its ExternalInit; a nil
// commitSecret is a commit without a path. The caller erases the secrets.
type mlsNextEpoch struct {
	groupContext          *mlsGroupContext
	encodedGroupContext   []byte
	epochSecrets          *mlsEpochSecrets
	confirmationTag       []byte
	interimTranscriptHash []byte
}

// Derives the next epoch from authenticated, whose signature is set and whose tag is not yet, over tree.
func (self *mlsGroupState) deriveNextEpoch(authenticated *mlsAuthenticatedContent, interimTranscriptHash []byte, tree *mlsRatchetTree, extensions []mlsExtension, initSecret []byte, commitSecret []byte) (*mlsNextEpoch, error) {
	suite := self.suite
	input, err := authenticated.confirmedTranscriptHashInput()
	if err != nil {
		return nil, err
	}
	confirmedTranscriptHash := suite.nextConfirmedTranscriptHash(interimTranscriptHash, input)
	context, encoded, err := self.nextGroupContext(tree, extensions, confirmedTranscriptHash)
	if err != nil {
		return nil, err
	}
	joinerSecret, err := suite.deriveJoinerSecret(initSecret, commitSecret, encoded)
	if err != nil {
		return nil, err
	}
	defer clear(joinerSecret)
	epochSecrets, err := suite.deriveEpochSecrets(joinerSecret, nil, encoded)
	if err != nil {
		return nil, err
	}
	confirmationTag := suite.confirmationTag(epochSecrets.confirmationKey, confirmedTranscriptHash)
	nextInterim, err := suite.nextInterimTranscriptHash(confirmedTranscriptHash, confirmationTag)
	if err != nil {
		epochSecrets.erase()
		return nil, err
	}
	return &mlsNextEpoch{
		groupContext:          context,
		encodedGroupContext:   encoded,
		epochSecrets:          epochSecrets,
		confirmationTag:       confirmationTag,
		interimTranscriptHash: nextInterim,
	}, nil
}

// A copy of this member's keys, which a staged epoch changes without touching the current one. Keys are
// immutable, so the copy shares them.
func (self *mlsTreeSecrets) clone() *mlsTreeSecrets {
	return &mlsTreeSecrets{suite: self.suite, leaf: self.leaf, nodeIndexKeys: maps.Clone(self.nodeIndexKeys)}
}

// Stages this member's commit (RFC §12.4.2): proposals in the order RFC §12.3 applies them, a path when asked
// or needed, the content signed under the current epoch's key, the next epoch derived, the tag set, and the
// commit sealed as a PrivateMessage at input.generation. A commit with Adds also builds their Welcome.
func (self *mlsGroupState) stageCommit(input *mlsCommitInput) (*mlsStagedState, error) {
	suite := self.suite
	own := self.ownLeaf()
	commit := &mlsCommit{}
	if input.groupContextExtensions != nil {
		commit.proposals = append(commit.proposals, mlsProposal{proposalType: mlsProposalTypeGroupContextExtensions, extensions: input.groupContextExtensions})
	}
	for _, removed := range input.removes {
		commit.proposals = append(commit.proposals, mlsProposal{proposalType: mlsProposalTypeRemove, removed: removed})
	}
	for _, keyPackage := range input.adds {
		commit.proposals = append(commit.proposals, mlsProposal{proposalType: mlsProposalTypeAdd, keyPackage: keyPackage})
	}
	if len(commit.proposals) == 0 && !input.path {
		return nil, fmt.Errorf("%w: an empty commit", errMlsInvalid)
	}
	if !input.path && (len(input.removes) != 0 || input.groupContextExtensions != nil) {
		return nil, fmt.Errorf("%w: a Remove or GroupContextExtensions with no path (§10.4)", errMlsInvalid)
	}
	sendingAt := input.now
	proposals, err := self.checkMemberProposals(own, commit.proposals, input.path, &sendingAt)
	if err != nil {
		return nil, err
	}
	tree, extensions, removed, added, err := self.applyMemberProposals(proposals)
	if err != nil {
		return nil, err
	}

	var prepared *mlsPreparedPath
	var commitSecret []byte
	signatureKey := self.signatureKey
	if input.path {
		if input.pathIdentity == nil {
			return nil, fmt.Errorf("mls: a path commit without its new leaf identity")
		}
		template := *tree.leafNode(own)
		template.signatureKey = []byte(input.pathIdentity.signatureKey.Public().(ed25519.PublicKey))
		template.credential = input.pathIdentity.credential
		if prepared, err = tree.prepareUpdatePath(own, &template, input.pathIdentity.signatureKey, self.groupId()); err != nil {
			return nil, err
		}
		defer prepared.erase()
		_, provisional, err := self.nextGroupContext(tree, extensions, self.groupContext.confirmedTranscriptHash)
		if err != nil {
			return nil, err
		}
		if commit.path, err = prepared.encrypt(provisional, added); err != nil {
			return nil, err
		}
		commitSecret = prepared.commitSecret
		defer clear(commitSecret)
		signatureKey = input.pathIdentity.signatureKey
	}

	authenticated := &mlsAuthenticatedContent{
		wireFormat: mlsWireFormatPrivateMessage,
		content: mlsFramedContent{
			groupId:           self.groupId(),
			epoch:             self.epoch(),
			sender:            mlsSender{senderType: mlsSenderTypeMember, leafIndex: own},
			authenticatedData: bytes.Clone(input.authenticatedData),
			contentType:       mlsContentTypeCommit,
			body:              commit,
		},
	}
	if err := authenticated.sign(suite, self.signatureKey, self.encodedGroupContext); err != nil {
		return nil, err
	}
	next, err := self.deriveNextEpoch(authenticated, self.interimTranscriptHash, tree, extensions, self.initSecret, commitSecret)
	if err != nil {
		return nil, err
	}
	defer next.epochSecrets.erase()
	authenticated.auth.confirmationTag = next.confirmationTag
	message, err := self.sealCommit(authenticated, input.generation)
	if err != nil {
		return nil, err
	}

	treeSecrets := self.treeSecrets.clone()
	if prepared != nil {
		prepared.adopt(treeSecrets)
	} else {
		treeSecrets.forgetStaleKeys(tree)
	}
	nextState, err := newMlsGroupState(&mlsGroupStateArgs{
		suite:                 suite,
		settings:              self.settings,
		credentialValidator:   self.credentialValidator,
		groupContext:          next.groupContext,
		tree:                  tree,
		treeSecrets:           treeSecrets,
		signatureKey:          signatureKey,
		interimTranscriptHash: next.interimTranscriptHash,
		confirmationTag:       next.confirmationTag,
		epochSecrets:          next.epochSecrets,
	})
	if err != nil {
		return nil, err
	}
	staged := &mlsStagedState{
		baseEpoch:              self.epoch(),
		baseEpochAuthenticator: bytes.Clone(self.epochAuthenticator),
		message:                message,
		committer:              own,
		committerLeaf:          self.tree.leafNode(own),
		added:                  added,
		removed:                removed,
		authenticatedData:      bytes.Clone(input.authenticatedData),
		next:                   nextState,
	}
	if 0 < len(added) {
		welcomeGroupInfo, err := nextState.groupInfo(false)
		if err != nil {
			return nil, err
		}
		joiners := []mlsWelcomeJoiner{}
		for position, index := range added {
			joiner := mlsWelcomeJoiner{keyPackage: proposals.adds[position]}
			if prepared != nil {
				joiner.pathSecret = prepared.pathSecretAt(mlsCommonAncestor(index.node(), own.node()))
			}
			joiners = append(joiners, joiner)
		}
		if staged.welcome, err = sealMlsWelcome(suite, next.epochSecrets.joinerSecret, next.epochSecrets.welcomeSecret, welcomeGroupInfo, joiners); err != nil {
			return nil, err
		}
	}
	return staged, nil
}

// Seals this member's signed commit as a PrivateMessage at generation, which must be at or past every
// generation this state has sealed at, and returns its MLSMessage.
func (self *mlsGroupState) sealCommit(authenticated *mlsAuthenticatedContent, generation uint32) ([]byte, error) {
	protection, err := self.messageProtection()
	if err != nil {
		return nil, err
	}
	ratchets, err := protection.secretTree.ratchets(self.ownLeaf())
	if err != nil {
		return nil, err
	}
	if generation < ratchets.handshake.generation {
		return nil, fmt.Errorf("%w: handshake generation %d is used", errMlsGeneration, generation)
	}
	if err := ratchets.handshake.skipTo(generation); err != nil {
		return nil, err
	}
	private, err := protection.seal(authenticated)
	if err != nil {
		return nil, err
	}
	self.handshakeGeneration = ratchets.handshake.generation
	return mlsMarshal(&mlsMessage{wireFormat: mlsWireFormatPrivateMessage, privateMessage: private})
}

// Opens another's commit in this epoch, a member's or an external one, and stages it once its signature,
// proposals, path and confirmation tag hold. errMlsOtherEpoch for a commit of another group or epoch, which
// says nothing about this one.
func (self *mlsGroupState) processCommit(encoded []byte) (*mlsStagedState, error) {
	message := &mlsMessage{}
	if err := mlsUnmarshal(encoded, message); err != nil {
		return nil, err
	}
	protection, err := self.messageProtection()
	if err != nil {
		return nil, err
	}
	authenticated, err := protection.open(message)
	if err != nil {
		return nil, err
	}
	commit := authenticated.content.commit()
	if commit == nil {
		return nil, fmt.Errorf("%w: no commit", errMlsRefused)
	}
	var staged *mlsStagedState
	switch authenticated.content.sender.senderType {
	case mlsSenderTypeMember:
		staged, err = self.processMemberCommit(authenticated, commit)
	case mlsSenderTypeNewMemberCommit:
		staged, err = self.processExternalCommit(authenticated, commit)
	default:
		err = fmt.Errorf("%w: sender type %d", errMlsRefused, authenticated.content.sender.senderType)
	}
	if err != nil {
		return nil, err
	}
	staged.message = bytes.Clone(encoded)
	staged.baseEpoch = self.epoch()
	staged.baseEpochAuthenticator = bytes.Clone(self.epochAuthenticator)
	staged.authenticatedData = bytes.Clone(authenticated.content.authenticatedData)
	return staged, nil
}

// A member's commit (RFC §12.4.2's processing), its signature already checked against its sender's leaf.
func (self *mlsGroupState) processMemberCommit(authenticated *mlsAuthenticatedContent, commit *mlsCommit) (*mlsStagedState, error) {
	suite := self.suite
	own := self.ownLeaf()
	sender := authenticated.content.sender.leafIndex
	if sender == own {
		return nil, fmt.Errorf("%w: this member's own commit, which it adopts or discards as staged", errMlsInvalid)
	}
	proposals, err := self.checkMemberProposals(sender, commit.proposals, commit.path != nil, nil)
	if err != nil {
		return nil, err
	}
	tree, extensions, removed, added, err := self.applyMemberProposals(proposals)
	if err != nil {
		return nil, err
	}
	removesSelf := slices.ContainsFunc(removed, func(leaf mlsRemovedLeaf) bool { return leaf.index == own })
	staged := &mlsStagedState{
		committer:     sender,
		committerLeaf: self.tree.leafNode(sender),
		added:         added,
		removed:       removed,
		removesSelf:   removesSelf,
	}

	var received *mlsReceivedPath
	var commitSecret []byte
	if commit.path != nil {
		if err := tree.mergeUpdatePath(sender, commit.path, added, self.leafValidation(extensions)); err != nil {
			return nil, err
		}
		if !mlsSameIdentity(self.tree.leafNode(sender), &commit.path.leafNode) {
			return nil, fmt.Errorf("%w: a path changing its committer's sidecar or identity key", errMlsInvalid)
		}
		if err := mlsCheckUniqueSidecars(tree); err != nil {
			return nil, err
		}
		if removesSelf {
			return staged, nil
		}
		_, provisional, err := self.nextGroupContext(tree, extensions, self.groupContext.confirmedTranscriptHash)
		if err != nil {
			return nil, err
		}
		if received, err = self.treeSecrets.receiveUpdatePath(tree, sender, commit.path, provisional, added); err != nil {
			return nil, err
		}
		commitSecret = received.commitSecret
		defer clear(commitSecret)
	}
	next, err := self.deriveNextEpoch(authenticated, self.interimTranscriptHash, tree, extensions, self.initSecret, commitSecret)
	if err != nil {
		return nil, err
	}
	defer next.epochSecrets.erase()
	if !suite.verifyMac(next.epochSecrets.confirmationKey, next.groupContext.confirmedTranscriptHash, authenticated.auth.confirmationTag) {
		return nil, fmt.Errorf("%w: confirmation tag", errMlsAuthentication)
	}
	treeSecrets := self.treeSecrets.clone()
	if received != nil {
		received.adopt(treeSecrets)
	} else {
		treeSecrets.forgetStaleKeys(tree)
	}
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

// A copy of an HPKE private key's serialized form, for a state written to disk, which the caller erases.
// crypto/hpke answers its own slice, so erasing that would erase the key.
func mlsKemKeyBytes(privateKey hpke.PrivateKey) ([]byte, error) {
	encoded, err := privateKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("mls: hpke private key: %w", err)
	}
	return bytes.Clone(encoded), nil
}
