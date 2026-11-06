// TreeKEM and the ratchet tree under both suites, on groups built here: no vectors exist for 0x0010,
// so a seeded random lifecycle has to reach the shapes the mlswg's trees show, blanks, unmerged leaves
// and skipped links in the parent hash chain among them, and check every invariant after every commit.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"testing/cryptotest"
	"time"
)

// A fixed moment for KeyPackage lifetimes.
var mlsTestTime = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

// What one test client holds to appear in a group.
type mlsTestClient struct {
	signatureKey ed25519.PrivateKey
	leafKey      hpke.PrivateKey
	initKey      hpke.PrivateKey
	keyPackage   *mlsKeyPackage
}

// A basic-credential client with a KeyPackage valid for 90 days from mlsTestTime.
func mlsNewTestClient(t *testing.T, suite *mlsCipherSuite, identity string) *mlsTestClient {
	t.Helper()
	signatureKey, err := suite.generateSignatureKey("test")
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := suite.generateKemKey("test")
	if err != nil {
		t.Fatal(err)
	}
	initKey, err := suite.generateKemKey("test")
	if err != nil {
		t.Fatal(err)
	}
	notBefore := uint64(mlsTestTime.Unix())
	leafNode := mlsLeafNode{
		encryptionKey:  leafKey.PublicKey().Bytes(),
		signatureKey:   []byte(signatureKey.Public().(ed25519.PublicKey)),
		credential:     mlsCredential{credentialType: mlsCredentialTypeBasic, identity: []byte(identity)},
		capabilities:   mlsTestCapabilities(suite),
		leafNodeSource: mlsLeafNodeSourceKeyPackage,
		lifetime:       mlsLifetime{notBefore: notBefore, notAfter: notBefore + 90*24*60*60},
	}
	if err := leafNode.sign(suite, signatureKey, nil, 0); err != nil {
		t.Fatal(err)
	}
	keyPackage := &mlsKeyPackage{
		cipherSuite: suite.value,
		initKey:     initKey.PublicKey().Bytes(),
		leafNode:    leafNode,
	}
	if err := keyPackage.sign(suite, signatureKey); err != nil {
		t.Fatal(err)
	}
	return &mlsTestClient{signatureKey: signatureKey, leafKey: leafKey, initKey: initKey, keyPackage: keyPackage}
}

// What a test leaf advertises.
func mlsTestCapabilities(suite *mlsCipherSuite) mlsCapabilities {
	return mlsCapabilities{
		versions:     []uint16{mlsProtocolVersion10},
		cipherSuites: []uint16{suite.value},
		credentials:  []uint16{mlsCredentialTypeBasic},
	}
}

// One member's whole view of a group.
type mlsTestMember struct {
	identity     string
	signatureKey ed25519.PrivateKey
	tree         *mlsRatchetTree
	secrets      *mlsTreeSecrets
}

// A group of members that each process every commit themselves, sharing nothing but what a commit
// and a Welcome would carry.
type mlsTestGroup struct {
	t          *testing.T
	suite      *mlsCipherSuite
	groupId    []byte
	epoch      uint64
	validation *mlsLeafValidation
	members    map[mlsLeafIndex]*mlsTestMember
	nextClient int
}

// A group of one, at epoch 0.
func mlsNewTestGroup(t *testing.T, suite *mlsCipherSuite) *mlsTestGroup {
	t.Helper()
	groupId := []byte("mls-base test group")
	creator := mlsNewTestClient(t, suite, "client-0")
	tree := newMlsRatchetTree(suite, defaultMlsTreeSettings(), &creator.keyPackage.leafNode)
	return &mlsTestGroup{
		t:          t,
		suite:      suite,
		groupId:    groupId,
		validation: mlsTestLeafValidation(groupId),
		members: map[mlsLeafIndex]*mlsTestMember{0: {
			identity:     "client-0",
			signatureKey: creator.signatureKey,
			tree:         tree,
			secrets:      newMlsTreeSecrets(suite, 0, creator.leafKey),
		}},
		nextClient: 1,
	}
}

// The provisional GroupContext of the next epoch over this tree.
func (self *mlsTestGroup) provisionalContext(tree *mlsRatchetTree) []byte {
	self.t.Helper()
	treeHash, err := tree.treeHash()
	if err != nil {
		self.t.Fatal(err)
	}
	encoded, err := mlsMarshal(&mlsGroupContext{
		cipherSuite:             self.suite.value,
		groupId:                 self.groupId,
		epoch:                   self.epoch + 1,
		treeHash:                treeHash,
		confirmedTranscriptHash: []byte("transcript"),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return encoded
}

// One commit, with this many Adds and these Removes, with or without a path, processed by every
// member. Fails the test on any disagreement or broken invariant.
func (self *mlsTestGroup) commit(committer mlsLeafIndex, removed []mlsLeafIndex, addCount int, withPath bool) {
	self.t.Helper()
	t := self.t

	clients := make([]*mlsTestClient, addCount)
	identities := make([]string, addCount)
	for index := range clients {
		identities[index] = fmt.Sprintf("client-%d", self.nextClient)
		self.nextClient++
		clients[index] = mlsNewTestClient(t, self.suite, identities[index])
		if err := clients[index].keyPackage.validate(self.suite, defaultMlsTreeSettings(), mlsAcceptBasicCredential, &mlsTestTime); err != nil {
			t.Fatal(err)
		}
	}
	applyProposals := func(tree *mlsRatchetTree) []mlsLeafIndex {
		for _, leaf := range removed {
			if err := tree.removeLeaf(leaf); err != nil {
				t.Fatal(err)
			}
		}
		var newLeaves []mlsLeafIndex
		for _, client := range clients {
			leaf, err := tree.addLeaf(&client.keyPackage.leafNode)
			if err != nil {
				t.Fatal(err)
			}
			newLeaves = append(newLeaves, leaf)
		}
		return newLeaves
	}

	committerMember := self.members[committer]
	committerTree := committerMember.tree.clone()
	newLeaves := applyProposals(committerTree)

	var prepared *mlsPreparedPath
	var updatePath *mlsUpdatePath
	if withPath {
		var err error
		prepared, err = committerTree.prepareUpdatePath(
			committer, committerTree.leafNode(committer), committerMember.signatureKey, self.groupId,
		)
		if err != nil {
			t.Fatal(err)
		}
		if updatePath, err = prepared.encrypt(self.provisionalContext(committerTree), newLeaves); err != nil {
			t.Fatal(err)
		}
		// on the wire and back, as a receiver gets it
		encoded, err := mlsMarshal(updatePath)
		if err != nil {
			t.Fatal(err)
		}
		updatePath = &mlsUpdatePath{}
		if err := mlsUnmarshal(encoded, updatePath); err != nil {
			t.Fatal(err)
		}
	}

	for leaf, member := range self.members {
		if leaf == committer || slices.Contains(removed, leaf) {
			continue
		}
		tree := member.tree.clone()
		applyProposals(tree)
		if withPath {
			if err := tree.mergeUpdatePath(committer, updatePath, newLeaves, self.validation); err != nil {
				t.Fatalf("leaf %d merging leaf %d's path: %v", leaf, committer, err)
			}
			commitSecret, err := member.secrets.receiveUpdatePath(tree, committer, updatePath, self.provisionalContext(tree), newLeaves)
			if err != nil {
				t.Fatalf("leaf %d receiving leaf %d's path: %v", leaf, committer, err)
			}
			if !bytes.Equal(commitSecret, prepared.commitSecret) {
				t.Fatalf("leaf %d: commit secret differs from leaf %d's", leaf, committer)
			}
		}
		member.secrets.forgetStaleKeys(tree)
		member.tree = tree
	}
	for _, leaf := range removed {
		delete(self.members, leaf)
	}

	if withPath {
		prepared.adopt(committerMember.secrets)
	}
	committerMember.secrets.forgetStaleKeys(committerTree)
	committerMember.tree = committerTree

	// Welcome: the tree on the wire, then the path secret at the lowest node shared with the committer
	for index, client := range clients {
		encodedTree, err := mlsMarshal(committerTree)
		if err != nil {
			t.Fatal(err)
		}
		joinerTree, err := decodeMlsRatchetTree(self.suite, defaultMlsTreeSettings(), encodedTree)
		if err != nil {
			t.Fatal(err)
		}
		secrets := newMlsTreeSecrets(self.suite, newLeaves[index], client.leafKey)
		if withPath {
			ancestor := mlsCommonAncestor(newLeaves[index].node(), committer.node())
			if err := secrets.implantWelcomePath(joinerTree, committer, prepared.pathSecretAt(ancestor)); err != nil {
				t.Fatal(err)
			}
		}
		self.members[newLeaves[index]] = &mlsTestMember{
			identity:     identities[index],
			signatureKey: client.signatureKey,
			tree:         joinerTree,
			secrets:      secrets,
		}
	}
	if withPath {
		prepared.erase()
	}
	self.epoch++
	self.checkInvariants()
}

// Everything a group must hold after any commit.
func (self *mlsTestGroup) checkInvariants() {
	self.t.Helper()
	t := self.t

	var firstHash []byte
	for leaf, member := range self.members {
		hash, err := member.tree.treeHash()
		if err != nil {
			t.Fatal(err)
		}
		if firstHash == nil {
			firstHash = hash
		}
		if !bytes.Equal(hash, firstHash) {
			t.Fatalf("epoch %d: leaf %d's tree hash differs", self.epoch, leaf)
		}
		if member.tree.leafNode(leaf) == nil {
			t.Fatalf("epoch %d: leaf %d is blank in its own tree", self.epoch, leaf)
		}
		if !member.secrets.consistentWith(member.tree) {
			t.Fatalf("epoch %d: leaf %d holds a key its tree does not show", self.epoch, leaf)
		}

		// §4.2's tree invariant, both ways
		ownNode := leaf.node()
		for node := range member.secrets.nodeIndexKeys {
			if !node.subtreeContains(ownNode) {
				t.Fatalf("epoch %d: leaf %d holds node %d, not above it", self.epoch, leaf, node)
			}
		}
		for _, ancestor := range ownNode.directPath(member.tree.leafCount()) {
			parent := member.tree.nodes[ancestor].parent
			if parent == nil {
				continue
			}
			_, held := member.secrets.nodeIndexKeys[ancestor]
			unmerged := slices.Contains(parent.unmergedLeaves, leaf)
			if held == unmerged {
				t.Fatalf("epoch %d: leaf %d at node %d: holds %v, unmerged %v", self.epoch, leaf, ancestor, held, unmerged)
			}
		}
	}

	var anyMember *mlsTestMember
	for _, member := range self.members {
		anyMember = member
		break
	}
	tree := anyMember.tree
	if err := tree.validate(self.validation); err != nil {
		t.Fatalf("epoch %d: %v", self.epoch, err)
	}

	// the cached hashes must equal a tree that never had a cache
	encoded, err := mlsMarshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := decodeMlsRatchetTree(self.suite, tree.settings, encoded)
	if err != nil {
		t.Fatal(err)
	}
	freshHash, err := fresh.treeHash()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(freshHash, firstHash) {
		t.Fatalf("epoch %d: a stale tree hash cache", self.epoch)
	}
}

// The members' leaves, in order, so a seeded run is repeatable.
func (self *mlsTestGroup) leaves() []mlsLeafIndex {
	leaves := make([]mlsLeafIndex, 0, len(self.members))
	for leaf := range self.members {
		leaves = append(leaves, leaf)
	}
	slices.Sort(leaves)
	return leaves
}

func TestMlsTreeKemLifecycleUnderBothSuites(t *testing.T) {
	for _, suite := range mlsTestSuites {
		cryptotest.SetGlobalRandom(t, 1)
		choices := rand.New(rand.NewPCG(2026, 11))
		group := mlsNewTestGroup(t, suite)
		sawBlankParent := false
		sawUnmerged := false
		sawBlankLeaf := false
		for step := 0; step < 120; step++ {
			leaves := group.leaves()
			committer := leaves[choices.IntN(len(leaves))]
			switch choice := choices.IntN(10); {
			case len(leaves) < 3 || choice < 3:
				// grow, sometimes leaving the new leaves unmerged
				group.commit(committer, nil, 1+choices.IntN(3), choices.IntN(2) == 0)
			case choice < 6 && 4 < len(leaves):
				others := slices.DeleteFunc(slices.Clone(leaves), func(leaf mlsLeafIndex) bool { return leaf == committer })
				removed := others[choices.IntN(len(others))]
				group.commit(committer, []mlsLeafIndex{removed}, 0, true)
			case choice < 7 && 4 < len(leaves):
				others := slices.DeleteFunc(slices.Clone(leaves), func(leaf mlsLeafIndex) bool { return leaf == committer })
				removed := others[choices.IntN(len(others))]
				group.commit(committer, []mlsLeafIndex{removed}, 1, true)
			default:
				group.commit(committer, nil, 0, true)
			}

			tree := group.members[committer].tree
			for index := range tree.nodes {
				node := &tree.nodes[index]
				if node.parent != nil && 0 < len(node.parent.unmergedLeaves) {
					sawUnmerged = true
				}
				if node.blank() && !mlsNodeIndex(index).isLeaf() {
					sawBlankParent = true
				}
				if node.blank() && mlsNodeIndex(index).isLeaf() {
					sawBlankLeaf = true
				}
			}
		}
		if !sawBlankParent || !sawUnmerged || !sawBlankLeaf {
			t.Errorf("suite %#x: the run missed a shape: blank parent %v, unmerged %v, blank leaf %v",
				suite.value, sawBlankParent, sawUnmerged, sawBlankLeaf)
		}
	}
}

// A tree the size of §10.4's cap, built and validated once, so width is not only a claim.
func TestMlsTreeKemAtFullGroupWidth(t *testing.T) {
	suite := mlsTestSuiteX25519
	cryptotest.SetGlobalRandom(t, 2)
	group := mlsNewTestGroup(t, suite)
	creator := group.members[0]
	for count := 1; count < 1000; count++ {
		client := mlsNewTestClient(t, suite, fmt.Sprintf("client-%d", count))
		if _, err := creator.tree.addLeaf(&client.keyPackage.leafNode); err != nil {
			t.Fatal(err)
		}
	}
	if creator.tree.leafCount() != 1024 {
		t.Fatalf("%d leaves", creator.tree.leafCount())
	}
	prepared, err := creator.tree.prepareUpdatePath(0, creator.tree.leafNode(0), creator.signatureKey, group.groupId)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.path) != 10 {
		t.Errorf("path of %d nodes, want 10", len(prepared.path))
	}
	if _, err := prepared.encrypt(group.provisionalContext(creator.tree), nil); err != nil {
		t.Fatal(err)
	}
	if err := creator.tree.validate(group.validation); err != nil {
		t.Fatal(err)
	}
}

// A built group of this many members, everyone merged by a commit from each in turn.
func mlsNewMergedTestGroup(t *testing.T, suite *mlsCipherSuite, memberCount int) *mlsTestGroup {
	t.Helper()
	group := mlsNewTestGroup(t, suite)
	group.commit(0, nil, memberCount-1, true)
	for _, leaf := range group.leaves() {
		group.commit(leaf, nil, 0, true)
	}
	return group
}

// A commit's path, built by the group's committer against its own tree, and a fresh tree to merge it
// into.
func mlsPreparedCommit(t *testing.T, group *mlsTestGroup, committer mlsLeafIndex) (*mlsUpdatePath, *mlsPreparedPath, *mlsRatchetTree) {
	t.Helper()
	member := group.members[committer]
	committerTree := member.tree.clone()
	prepared, err := committerTree.prepareUpdatePath(committer, committerTree.leafNode(committer), member.signatureKey, group.groupId)
	if err != nil {
		t.Fatal(err)
	}
	updatePath, err := prepared.encrypt(group.provisionalContext(committerTree), nil)
	if err != nil {
		t.Fatal(err)
	}
	return updatePath, prepared, member.tree.clone()
}

func TestMlsMergeRefusesAWrongNodeCount(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	updatePath.nodes = updatePath.nodes[:len(updatePath.nodes)-1]
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsMergeRefusesAWrongCiphertextCount(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	updatePath.nodes[0].encryptedPathSecrets = nil
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsMergeRefusesAPathKeyAlreadyInTheTree(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	updatePath.nodes[0].encryptionKey = tree.leafNode(2).encryptionKey
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsMergeRefusesTheSameKeyTwiceInAPath(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	updatePath.nodes[1].encryptionKey = updatePath.nodes[0].encryptionKey
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// Re-signed by the real committer, so only the hash check can catch it.
func TestMlsMergeRefusesAWrongParentHash(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	member := group.members[0]
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	updatePath.leafNode.parentHash = bytes.Repeat([]byte{7}, 32)
	if err := updatePath.leafNode.sign(group.suite, member.signatureKey, group.groupId, 0); err != nil {
		t.Fatal(err)
	}
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// Keeping the leaf's old key is a commit that heals nothing (§12.4.2).
func TestMlsMergeRefusesAnUnchangedLeafKey(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	member := group.members[0]
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	updatePath.leafNode.encryptionKey = tree.leafNode(0).encryptionKey
	if err := updatePath.leafNode.sign(group.suite, member.signatureKey, group.groupId, 0); err != nil {
		t.Fatal(err)
	}
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsMergeRefusesATamperedLeaf(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	updatePath.leafNode.credential.identity = []byte("someone else")
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

// The leaf's signature binds its position, so a path cannot be replayed from another leaf.
func TestMlsMergeRefusesAPathFromAnotherPosition(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	if err := tree.mergeUpdatePath(1, updatePath, nil, group.validation); !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

func TestMlsMergeRefusesASourceOtherThanCommit(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	updatePath.leafNode.leafNodeSource = mlsLeafNodeSourceUpdate
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsMergeRefusesASenderOutsideTheTree(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	if err := tree.mergeUpdatePath(4, updatePath, nil, group.validation); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// The validator is the application's say. A refusal there must stop the merge.
func TestMlsMergeRefusesACredentialTheValidatorRefuses(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsTestSuiteX25519, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	validation := &mlsLeafValidation{groupId: group.groupId, credentialValidator: mlsRefuseEveryCredential}
	if err := tree.mergeUpdatePath(0, updatePath, nil, validation); !errors.Is(err, errMlsRefused) {
		t.Fatal(err)
	}
}

// A committer who encrypts a path secret that does not derive the public key it published must not
// move anyone's private state.
func TestMlsReceiveRefusesAPathSecretThatMissesThePublicKey(t *testing.T) {
	for _, suite := range mlsTestSuites {
		group := mlsNewMergedTestGroup(t, suite, 4)
		member := group.members[0]
		committerTree := member.tree.clone()
		prepared, err := committerTree.prepareUpdatePath(0, committerTree.leafNode(0), member.signatureKey, group.groupId)
		if err != nil {
			t.Fatal(err)
		}
		// the wrong secret goes out, and the public keys stay what the path signed
		for _, pathSecret := range prepared.pathSecrets {
			clear(pathSecret)
		}
		updatePath, err := prepared.encrypt(group.provisionalContext(committerTree), nil)
		if err != nil {
			t.Fatal(err)
		}

		receiver := group.members[3]
		tree := receiver.tree.clone()
		if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); err != nil {
			t.Fatal(err)
		}
		before := receiver.secrets.cloneForTest()
		_, err = receiver.secrets.receiveUpdatePath(tree, 0, updatePath, group.provisionalContext(tree), nil)
		if !errors.Is(err, errMlsInvalid) {
			t.Fatalf("suite %#x: %v", suite.value, err)
		}
		if len(receiver.secrets.nodeIndexKeys) != len(before.nodeIndexKeys) {
			t.Fatalf("suite %#x: a refused path changed the private state", suite.value)
		}
		for node, key := range before.nodeIndexKeys {
			if receiver.secrets.nodeIndexKeys[node] != key {
				t.Fatalf("suite %#x: node %d's key changed", suite.value, node)
			}
		}
	}
}

func TestMlsReceiveRefusesTamperedCiphertext(t *testing.T) {
	for _, suite := range mlsTestSuites {
		group := mlsNewMergedTestGroup(t, suite, 4)
		updatePath, _, tree := mlsPreparedCommit(t, group, 0)
		if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); err != nil {
			t.Fatal(err)
		}
		last := len(updatePath.nodes) - 1
		updatePath.nodes[last].encryptedPathSecrets[0].ciphertext[0] ^= 1
		_, err := group.members[3].secrets.receiveUpdatePath(tree, 0, updatePath, group.provisionalContext(tree), nil)
		if !errors.Is(err, errMlsAuthentication) {
			t.Fatalf("suite %#x: %v", suite.value, err)
		}
	}
}

// The GroupContext is the HPKE context, so a member on a fork cannot open the path.
func TestMlsReceiveRefusesAnotherGroupContext(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsSuite, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); err != nil {
		t.Fatal(err)
	}
	_, err := group.members[3].secrets.receiveUpdatePath(tree, 0, updatePath, []byte("another context"), nil)
	if !errors.Is(err, errMlsAuthentication) {
		t.Fatal(err)
	}
}

func TestMlsReceiveRefusesTheSendersOwnPath(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsSuite, 4)
	updatePath, _, tree := mlsPreparedCommit(t, group, 0)
	if err := tree.mergeUpdatePath(0, updatePath, nil, group.validation); err != nil {
		t.Fatal(err)
	}
	_, err := group.members[0].secrets.receiveUpdatePath(tree, 0, updatePath, group.provisionalContext(tree), nil)
	if !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

// A new leaf's key must not appear among the path's recipients: it gets the secret by Welcome (§7.5).
func TestMlsNewLeavesAreLeftOutOfThePath(t *testing.T) {
	suite := mlsSuite
	group := mlsNewMergedTestGroup(t, suite, 3)
	member := group.members[0]
	tree := member.tree.clone()
	client := mlsNewTestClient(t, suite, "newcomer")
	newLeaf, err := tree.addLeaf(&client.keyPackage.leafNode)
	if err != nil {
		t.Fatal(err)
	}
	if newLeaf != 3 {
		t.Fatalf("new leaf %d", newLeaf)
	}
	prepared, err := tree.prepareUpdatePath(0, tree.leafNode(0), member.signatureKey, group.groupId)
	if err != nil {
		t.Fatal(err)
	}
	updatePath, err := prepared.encrypt(group.provisionalContext(tree), []mlsLeafIndex{newLeaf})
	if err != nil {
		t.Fatal(err)
	}
	// the copath child above leaf 2 and leaf 3 resolves to both, or to its own key and the new leaf
	last := len(prepared.path) - 1
	copathChild := prepared.path[last].copathChild
	all := tree.resolution(copathChild)
	if !slices.Contains(all, newLeaf.node()) {
		t.Fatalf("the new leaf is not in the resolution %v", all)
	}
	if count := len(updatePath.nodes[last].encryptedPathSecrets); count != len(all)-1 {
		t.Fatalf("%d ciphertexts for a resolution of %d", count, len(all))
	}
}

// Filtered direct path keeps a node whose copath child has only new leaves, with no ciphertexts.
func TestMlsNodeOverOnlyNewLeavesTakesNoCiphertexts(t *testing.T) {
	suite := mlsSuite
	group := mlsNewTestGroup(t, suite)
	member := group.members[0]
	tree := member.tree.clone()
	client := mlsNewTestClient(t, suite, "newcomer")
	newLeaf, err := tree.addLeaf(&client.keyPackage.leafNode)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := tree.prepareUpdatePath(0, tree.leafNode(0), member.signatureKey, group.groupId)
	if err != nil {
		t.Fatal(err)
	}
	updatePath, err := prepared.encrypt(group.provisionalContext(tree), []mlsLeafIndex{newLeaf})
	if err != nil {
		t.Fatal(err)
	}
	if len(updatePath.nodes) != 1 || len(updatePath.nodes[0].encryptedPathSecrets) != 0 {
		t.Fatalf("path %+v", updatePath.nodes)
	}
}

// A removed member's keys open nothing in the commit that removes it: that is what the path is for.
func TestMlsRemovedMemberOpensNoPathSecret(t *testing.T) {
	for _, suite := range mlsTestSuites {
		group := mlsNewMergedTestGroup(t, suite, 8)
		removed := group.members[5]
		removedKeys := removed.secrets.nodeIndexKeys

		committer := group.members[0]
		tree := committer.tree.clone()
		if err := tree.removeLeaf(5); err != nil {
			t.Fatal(err)
		}
		prepared, err := tree.prepareUpdatePath(0, tree.leafNode(0), committer.signatureKey, group.groupId)
		if err != nil {
			t.Fatal(err)
		}
		groupContext := group.provisionalContext(tree)
		updatePath, err := prepared.encrypt(groupContext, nil)
		if err != nil {
			t.Fatal(err)
		}
		opened := 0
		for _, node := range updatePath.nodes {
			for _, ciphertext := range node.encryptedPathSecrets {
				for _, key := range removedKeys {
					_, err := suite.decryptWithLabel(
						"test", key, mlsEncryptLabelUpdatePathNode, groupContext, ciphertext.kemOutput, ciphertext.ciphertext,
					)
					if err == nil {
						opened++
					}
				}
			}
		}
		if opened != 0 {
			t.Fatalf("suite %#x: the removed member opened %d ciphertexts", suite.value, opened)
		}
	}
}

// A commit heals the tree: everything the committer held on its path is gone from the others' views
// once replaced, so an old key opens nothing new.
func TestMlsOutdatedKeysAreForgotten(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsSuite, 4)
	member := group.members[3]
	oldRootKey := member.secrets.nodeIndexKeys[mlsTreeRoot(4)]
	if oldRootKey == nil {
		t.Fatal("no root key before the commit")
	}
	group.commit(0, nil, 0, true)
	newRootKey := member.secrets.nodeIndexKeys[mlsTreeRoot(4)]
	if newRootKey == nil || newRootKey == oldRootKey {
		t.Fatal("the root key did not change")
	}
	for node, key := range member.secrets.nodeIndexKeys {
		if key == oldRootKey {
			t.Fatalf("the old root key survives at node %d", node)
		}
	}
}

func TestMlsErasedPreparedPathKeepsNoPathSecrets(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsSuite, 4)
	_, prepared, _ := mlsPreparedCommit(t, group, 0)
	pathSecrets := slices.Clone(prepared.pathSecrets)
	prepared.erase()
	zero := make([]byte, mlsSuite.hashLength)
	for index, pathSecret := range pathSecrets {
		if !bytes.Equal(pathSecret, zero) {
			t.Errorf("path secret %d survived", index)
		}
	}
	if prepared.pathSecretAt(prepared.path[0].node) != nil {
		t.Error("an erased path still answers")
	}
	if _, err := prepared.encrypt([]byte("context"), nil); err == nil {
		t.Error("an erased path encrypted")
	}
}

// A group of one has no path, and commit_secret must still be fresh each time.
func TestMlsCommitInAGroupOfOne(t *testing.T) {
	group := mlsNewTestGroup(t, mlsSuite)
	member := group.members[0]
	first := member.tree.clone()
	prepared, err := first.prepareUpdatePath(0, first.leafNode(0), member.signatureKey, group.groupId)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.path) != 0 {
		t.Fatalf("path of %d nodes", len(prepared.path))
	}
	if len(prepared.leafNode.parentHash) != 0 {
		t.Errorf("parent hash %x", prepared.leafNode.parentHash)
	}
	second := member.tree.clone()
	again, err := second.prepareUpdatePath(0, second.leafNode(0), member.signatureKey, group.groupId)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.commitSecret) != mlsSuite.hashLength || bytes.Equal(prepared.commitSecret, again.commitSecret) {
		t.Fatal("commit_secret is not fresh")
	}
}

// External commit's tree half: the joiner takes the leftmost blank leaf, and every member follows.
func TestMlsExternalCommitPath(t *testing.T) {
	for _, suite := range mlsTestSuites {
		group := mlsNewMergedTestGroup(t, suite, 4)
		group.commit(0, []mlsLeafIndex{1}, 0, true)

		joiner := mlsNewTestClient(t, suite, "external joiner")
		joinerTree := group.members[0].tree.clone()
		leaf, err := joinerTree.reserveLeaf()
		if err != nil {
			t.Fatal(err)
		}
		if leaf != 1 {
			t.Fatalf("reserved leaf %d", leaf)
		}
		prepared, err := joinerTree.prepareUpdatePath(leaf, &joiner.keyPackage.leafNode, joiner.signatureKey, group.groupId)
		if err != nil {
			t.Fatal(err)
		}
		updatePath, err := prepared.encrypt(group.provisionalContext(joinerTree), nil)
		if err != nil {
			t.Fatal(err)
		}

		member := group.members[3]
		tree := member.tree.clone()
		reserved, err := tree.reserveLeaf()
		if err != nil {
			t.Fatal(err)
		}
		if reserved != leaf {
			t.Fatalf("member reserved leaf %d", reserved)
		}
		if err := tree.mergeUpdatePath(leaf, updatePath, nil, group.validation); err != nil {
			t.Fatal(err)
		}
		commitSecret, err := member.secrets.receiveUpdatePath(tree, leaf, updatePath, group.provisionalContext(tree), nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(commitSecret, prepared.commitSecret) {
			t.Fatalf("suite %#x: commit secrets differ", suite.value)
		}
		if err := tree.validate(group.validation); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMlsImplantRefusesAPathSecretForAnotherKey(t *testing.T) {
	group := mlsNewMergedTestGroup(t, mlsSuite, 4)
	secrets := group.members[0].secrets
	root := mlsTreeRoot(4)
	if err := secrets.implantPathSecret(group.members[0].tree, root, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
	if err := secrets.implantPathSecret(group.members[0].tree, 99, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}

func TestMlsWelcomePathRefusesASenderWithoutAPath(t *testing.T) {
	group := mlsNewTestGroup(t, mlsSuite)
	secrets := group.members[0].secrets
	if err := secrets.implantWelcomePath(group.members[0].tree, 0, make([]byte, 32)); !errors.Is(err, errMlsInvalid) {
		t.Fatal(err)
	}
}
