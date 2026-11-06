// TreeKEM (RFC 9420 §7.4-§7.6): how a commit's UpdatePath refreshes the keys along one member's path
// and delivers them to everyone else.
//
// A committer runs prepareUpdatePath on its clone of the tree, which leaves the tree in its new shape,
// then builds the provisional GroupContext from that tree's hash and calls encrypt. A receiver runs
// mergeUpdatePath on its clone and then, with the same provisional GroupContext, receiveUpdatePath.
// Both sides leave the transcript and the key schedule to their caller, which takes commit_secret
// from here.
//
// Private keys live apart from the tree, in mlsTreeSecrets, one per member's view (§4.2). A secret
// that drives the path is erased as soon as what it derives exists, and any held key the tree no
// longer shows is forgotten (§7.5).
//
// Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"fmt"
	"maps"
	"slices"
)

// Public key encryption labels (§17.7).
const mlsEncryptLabelUpdatePathNode = "UpdatePathNode"

// HPKECiphertext (§7.6).
type mlsHpkeCiphertext struct {
	kemOutput  []byte
	ciphertext []byte
}

func (self *mlsHpkeCiphertext) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.kemOutput)
	encoder.writeVector(self.ciphertext)
}

func (self *mlsHpkeCiphertext) decode(decoder *mlsDecoder) {
	self.kemOutput = decoder.readVector()
	self.ciphertext = decoder.readVector()
}

// UpdatePathNode (§7.6): one public key of the path, and its path secret encrypted to each node of
// the copath child's resolution.
type mlsUpdatePathNode struct {
	encryptionKey        []byte
	encryptedPathSecrets []mlsHpkeCiphertext
}

func (self *mlsUpdatePathNode) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.encryptionKey)
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for index := range self.encryptedPathSecrets {
			self.encryptedPathSecrets[index].encode(elements)
		}
	})
}

func (self *mlsUpdatePathNode) decode(decoder *mlsDecoder) {
	self.encryptionKey = decoder.readVector()
	decoder.readVectorOf(func(element *mlsDecoder) {
		var ciphertext mlsHpkeCiphertext
		ciphertext.decode(element)
		self.encryptedPathSecrets = append(self.encryptedPathSecrets, ciphertext)
	})
}

// UpdatePath (§7.6): the committer's new leaf and the nodes of its filtered direct path, in order.
type mlsUpdatePath struct {
	leafNode mlsLeafNode
	nodes    []mlsUpdatePathNode
}

func (self *mlsUpdatePath) encode(encoder *mlsEncoder) {
	self.leafNode.encode(encoder)
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for index := range self.nodes {
			self.nodes[index].encode(elements)
		}
	})
}

func (self *mlsUpdatePath) decode(decoder *mlsDecoder) {
	self.leafNode.decode(decoder)
	decoder.readVectorOf(func(element *mlsDecoder) {
		var node mlsUpdatePathNode
		node.decode(element)
		self.nodes = append(self.nodes, node)
	})
}

// path_secret[n+1] (§7.4). The value after the last node's is commit_secret.
func (self *mlsCipherSuite) nextPathSecret(pathSecret []byte) ([]byte, error) {
	return self.deriveSecret("path_secret", pathSecret, "path")
}

// A node's key pair from its path secret (§7.4), by way of a node secret that lives only here.
func (self *mlsCipherSuite) derivePathKey(pathSecret []byte) (hpke.PrivateKey, error) {
	nodeSecret, err := self.deriveSecret("node_secret", pathSecret, "node")
	if err != nil {
		return nil, err
	}
	defer clear(nodeSecret)
	return self.deriveKemKey("node_priv", nodeSecret)
}

// Who a path secret is encrypted to at one copath child: its resolution, without leaves new in this
// commit, which get the secret by Welcome instead (§7.5).
func (self *mlsRatchetTree) pathSecretRecipients(copathChild mlsNodeIndex, newLeaves []mlsLeafIndex) []mlsNodeIndex {
	return slices.DeleteFunc(self.resolution(copathChild), func(node mlsNodeIndex) bool {
		return node.isLeaf() && slices.Contains(newLeaves, node.leaf())
	})
}

// Installs a path's public keys on the filtered path, then fills in parent_hash from the root down
// (§7.9.1). Returns the hash the leaf must carry. A path node starts with no unmerged leaves, so its
// original sibling tree hash is the sibling's tree hash as it stands (§7.9).
func (self *mlsRatchetTree) installPathKeys(path []mlsFilteredPathNode, encryptionKeys [][]byte) ([]byte, error) {
	parentHash := []byte{}
	for index := len(path) - 1; 0 <= index; index-- {
		siblingHash, err := self.nodeTreeHash(path[index].copathChild)
		if err != nil {
			return nil, err
		}
		self.setNode(path[index].node, mlsTreeNode{parent: &mlsParentNode{
			encryptionKey: encryptionKeys[index],
			parentHash:    parentHash,
		}})
		parentHash, err = self.hashParentHashInput(encryptionKeys[index], parentHash, siblingHash)
		if err != nil {
			return nil, err
		}
	}
	return parentHash, nil
}

// What a committer holds between building its path and encrypting it.
type mlsPreparedPath struct {
	tree   *mlsRatchetTree
	sender mlsLeafIndex
	path   []mlsFilteredPathNode

	// By position on the path: path_secret[n].
	pathSecrets [][]byte
	// By position on the path.
	pathKeys []hpke.PrivateKey
	leafKey  hpke.PrivateKey
	// The signed leaf, now in the tree.
	leafNode *mlsLeafNode

	commitSecret []byte
}

// Refreshes the sender's path (§7.4, §7.5) on this tree, which must be the commit's clone with its
// proposals applied. The new leaf takes everything but its keys and hash from leafTemplate; signatureKey
// must be the private half of leafTemplate's. An external committer reserves its leaf first.
func (self *mlsRatchetTree) prepareUpdatePath(sender mlsLeafIndex, leafTemplate *mlsLeafNode, signatureKey ed25519.PrivateKey, groupId []byte) (*mlsPreparedPath, error) {
	suite := self.suite
	path := self.filteredDirectPath(sender)
	self.blankPath(sender)

	prepared := &mlsPreparedPath{tree: self, sender: sender, path: path}
	encryptionKeys := make([][]byte, len(path))
	pathSecret := suite.generateSecret("path_secret")
	for index := range path {
		pathKey, err := suite.derivePathKey(pathSecret)
		if err != nil {
			return nil, err
		}
		prepared.pathSecrets = append(prepared.pathSecrets, pathSecret)
		prepared.pathKeys = append(prepared.pathKeys, pathKey)
		encryptionKeys[index] = pathKey.PublicKey().Bytes()
		if pathSecret, err = suite.nextPathSecret(pathSecret); err != nil {
			return nil, err
		}
	}
	// the value past the last node, or the fresh one in a tree with no path, is commit_secret
	prepared.commitSecret = pathSecret
	testHookSecret("commit_secret", prepared.commitSecret)

	parentHash, err := self.installPathKeys(path, encryptionKeys)
	if err != nil {
		return nil, err
	}

	leafKey, err := suite.generateKemKey("leaf_priv")
	if err != nil {
		return nil, err
	}
	prepared.leafKey = leafKey
	leafNode := *leafTemplate
	leafNode.encryptionKey = leafKey.PublicKey().Bytes()
	leafNode.leafNodeSource = mlsLeafNodeSourceCommit
	leafNode.parentHash = parentHash
	leafNode.lifetime = mlsLifetime{}
	if err := leafNode.sign(suite, signatureKey, groupId, sender); err != nil {
		return nil, err
	}
	prepared.leafNode = &leafNode
	self.setNode(sender.node(), mlsTreeNode{leaf: &leafNode})
	return prepared, nil
}

// Encrypts each path secret to the copath child's resolution under the provisional GroupContext
// (§7.5), which needs this tree's hash, so it comes only now. newLeaves are the commit's Adds.
func (self *mlsPreparedPath) encrypt(groupContext []byte, newLeaves []mlsLeafIndex) (*mlsUpdatePath, error) {
	if len(self.pathSecrets) != len(self.path) {
		return nil, fmt.Errorf("mls: encrypting a path already erased")
	}
	tree := self.tree
	suite := tree.suite
	updatePath := &mlsUpdatePath{leafNode: *self.leafNode}
	for index, entry := range self.path {
		node := mlsUpdatePathNode{encryptionKey: tree.nodes[entry.node].encryptionKey()}
		for _, recipient := range tree.pathSecretRecipients(entry.copathChild, newLeaves) {
			kemOutput, ciphertext, err := suite.encryptWithLabel(
				tree.nodes[recipient].encryptionKey(), mlsEncryptLabelUpdatePathNode, groupContext, self.pathSecrets[index],
			)
			if err != nil {
				return nil, err
			}
			node.encryptedPathSecrets = append(node.encryptedPathSecrets, mlsHpkeCiphertext{kemOutput: kemOutput, ciphertext: ciphertext})
		}
		updatePath.nodes = append(updatePath.nodes, node)
	}
	return updatePath, nil
}

// The path secret of one node of the path, for a new member's Welcome (§12.4.1), or nil if the node is
// not on the path or the path is erased.
func (self *mlsPreparedPath) pathSecretAt(node mlsNodeIndex) []byte {
	if len(self.pathSecrets) != len(self.path) {
		return nil
	}
	for index, entry := range self.path {
		if entry.node == node {
			return self.pathSecrets[index]
		}
	}
	return nil
}

// Hands the path's private keys to the committer's secrets, which then match the tree.
func (self *mlsPreparedPath) adopt(secrets *mlsTreeSecrets) {
	secrets.leaf = self.sender
	secrets.nodeIndexKeys[self.sender.node()] = self.leafKey
	for index, entry := range self.path {
		secrets.nodeIndexKeys[entry.node] = self.pathKeys[index]
	}
	secrets.forgetStaleKeys(self.tree)
}

// Overwrites the path secrets, once any Welcome is built (§7.5). commit_secret is the caller's.
func (self *mlsPreparedPath) erase() {
	for _, pathSecret := range self.pathSecrets {
		clear(pathSecret)
	}
	self.pathSecrets = nil
}

// Validates a received UpdatePath and merges it (§7.5, §12.4.2) into this tree, which must be the
// commit's clone with its proposals applied. A sender joining by external commit reserves its leaf
// first. newLeaves are the commit's Adds.
func (self *mlsRatchetTree) mergeUpdatePath(sender mlsLeafIndex, updatePath *mlsUpdatePath, newLeaves []mlsLeafIndex, validation *mlsLeafValidation) error {
	if self.leafCount() <= uint32(sender) {
		return fmt.Errorf("%w: sender %d outside the tree", errMlsInvalid, sender)
	}
	leaf := &updatePath.leafNode
	if err := self.validateNewLeaf(leaf, sender, mlsLeafNodeSourceCommit, validation); err != nil {
		return err
	}

	path := self.filteredDirectPath(sender)
	if len(updatePath.nodes) != len(path) {
		return fmt.Errorf("%w: update path of %d nodes for a filtered path of %d", errMlsInvalid, len(updatePath.nodes), len(path))
	}
	treeKeys := map[string]bool{}
	for index := range self.nodes {
		if !self.nodes[index].blank() {
			treeKeys[string(self.nodes[index].encryptionKey())] = true
		}
	}
	if treeKeys[string(leaf.encryptionKey)] {
		return fmt.Errorf("%w: the path's leaf repeats a key of the tree", errMlsInvalid)
	}
	treeKeys[string(leaf.encryptionKey)] = true
	encryptionKeys := make([][]byte, len(path))
	for index, entry := range path {
		node := &updatePath.nodes[index]
		if treeKeys[string(node.encryptionKey)] {
			return fmt.Errorf("%w: path node %d repeats a key of the tree", errMlsInvalid, index)
		}
		treeKeys[string(node.encryptionKey)] = true
		if _, err := self.suite.kem.NewPublicKey(node.encryptionKey); err != nil {
			return fmt.Errorf("%w: path node %d: %w", errMlsInvalid, index, err)
		}
		recipients := self.pathSecretRecipients(entry.copathChild, newLeaves)
		if len(node.encryptedPathSecrets) != len(recipients) {
			return fmt.Errorf("%w: path node %d has %d ciphertexts for %d recipients", errMlsInvalid, index, len(node.encryptedPathSecrets), len(recipients))
		}
		encryptionKeys[index] = node.encryptionKey
	}

	self.blankPath(sender)
	parentHash, err := self.installPathKeys(path, encryptionKeys)
	if err != nil {
		return err
	}
	if !bytes.Equal(leaf.parentHash, parentHash) {
		return fmt.Errorf("%w: the path's leaf carries the wrong parent hash", errMlsInvalid)
	}
	self.setNode(sender.node(), mlsTreeNode{leaf: leaf})
	return nil
}

// What one member holds of the tree (§4.2): the private keys of its leaf and of the nodes above it
// that it knows. Everything here must match the public tree, which forgetStaleKeys restores after a
// change.
type mlsTreeSecrets struct {
	suite *mlsCipherSuite
	leaf  mlsLeafIndex
	// The member's leaf key sits at its leaf node, like any other.
	nodeIndexKeys map[mlsNodeIndex]hpke.PrivateKey
}

func newMlsTreeSecrets(suite *mlsCipherSuite, leaf mlsLeafIndex, leafKey hpke.PrivateKey) *mlsTreeSecrets {
	return &mlsTreeSecrets{
		suite:         suite,
		leaf:          leaf,
		nodeIndexKeys: map[mlsNodeIndex]hpke.PrivateKey{leaf.node(): leafKey},
	}
}

// Sets one node's key from its path secret, refusing a key that is not the tree's (§12.4.3.1).
func (self *mlsTreeSecrets) implantPathSecret(tree *mlsRatchetTree, node mlsNodeIndex, pathSecret []byte) error {
	if len(tree.nodes) <= int(node) {
		return fmt.Errorf("%w: node %d outside the tree", errMlsInvalid, node)
	}
	key, err := self.suite.derivePathKey(pathSecret)
	if err != nil {
		return err
	}
	if !bytes.Equal(key.PublicKey().Bytes(), tree.nodes[node].encryptionKey()) {
		return fmt.Errorf("%w: path secret does not match node %d", errMlsInvalid, node)
	}
	self.nodeIndexKeys[node] = key
	return nil
}

// A new member's keys above its leaf (§12.4.3.1): a Welcome's path_secret is the path secret of the
// lowest node shared with the committer, and each node above that on the committer's filtered path
// follows from it. tree is the tree the Welcome carries, already validated. The caller still owns
// and erases pathSecret.
func (self *mlsTreeSecrets) implantWelcomePath(tree *mlsRatchetTree, sender mlsLeafIndex, pathSecret []byte) error {
	suite := self.suite
	ancestor := mlsCommonAncestor(self.leaf.node(), sender.node())
	path := tree.filteredDirectPath(sender)
	position := slices.IndexFunc(path, func(entry mlsFilteredPathNode) bool {
		return entry.node == ancestor
	})
	if position < 0 {
		return fmt.Errorf("%w: node %d is not on sender %d's path", errMlsInvalid, ancestor, sender)
	}
	current := bytes.Clone(pathSecret)
	defer func() { clear(current) }()
	for _, entry := range path[position:] {
		if err := self.implantPathSecret(tree, entry.node, current); err != nil {
			return err
		}
		next, err := suite.nextPathSecret(current)
		if err != nil {
			return err
		}
		clear(current)
		current = next
	}
	return nil
}

// Whether every key held is the tree's (treekem's consistency check, and a cheap one to keep).
func (self *mlsTreeSecrets) consistentWith(tree *mlsRatchetTree) bool {
	for node, key := range self.nodeIndexKeys {
		if len(tree.nodes) <= int(node) || !bytes.Equal(key.PublicKey().Bytes(), tree.nodes[node].encryptionKey()) {
			return false
		}
	}
	return true
}

// Drops every key the tree no longer shows: a blanked node's, a truncated one's, one a path replaced
// (§7.5's outdated key pairs).
func (self *mlsTreeSecrets) forgetStaleKeys(tree *mlsRatchetTree) {
	maps.DeleteFunc(self.nodeIndexKeys, func(node mlsNodeIndex, key hpke.PrivateKey) bool {
		return len(tree.nodes) <= int(node) || !bytes.Equal(key.PublicKey().Bytes(), tree.nodes[node].encryptionKey())
	})
}

// Finds the path node this member's secret arrives at and decrypts it (§7.5's "decrypts the path
// secrets"). tree is the merged tree: copath resolutions are untouched by the merge. Returns the
// node's position on the path and the path secret.
func (self *mlsTreeSecrets) decryptPathSecret(tree *mlsRatchetTree, sender mlsLeafIndex, updatePath *mlsUpdatePath, groupContext []byte, newLeaves []mlsLeafIndex) (int, []byte, error) {
	path := tree.filteredDirectPath(sender)
	if len(updatePath.nodes) != len(path) {
		return 0, nil, fmt.Errorf("%w: update path of %d nodes for a filtered path of %d", errMlsInvalid, len(updatePath.nodes), len(path))
	}
	for index, entry := range path {
		if !entry.copathChild.subtreeContains(self.leaf.node()) {
			continue
		}
		ciphertexts := updatePath.nodes[index].encryptedPathSecrets
		recipients := tree.pathSecretRecipients(entry.copathChild, newLeaves)
		if len(ciphertexts) != len(recipients) {
			return 0, nil, fmt.Errorf("%w: path node %d has %d ciphertexts for %d recipients", errMlsInvalid, index, len(ciphertexts), len(recipients))
		}
		for position, recipient := range recipients {
			key, ok := self.nodeIndexKeys[recipient]
			if !ok {
				continue
			}
			pathSecret, err := self.suite.decryptWithLabel(
				"path_secret", key, mlsEncryptLabelUpdatePathNode, groupContext, ciphertexts[position].kemOutput, ciphertexts[position].ciphertext,
			)
			if err != nil {
				return 0, nil, err
			}
			return index, pathSecret, nil
		}
		return 0, nil, fmt.Errorf("%w: no key for path node %d", errMlsInvalid, index)
	}
	return 0, nil, fmt.Errorf("%w: leaf %d is below no copath node of sender %d", errMlsInvalid, self.leaf, sender)
}

// Derives the path from one node up, checks each public key against the UpdatePath (§7.5), and
// returns commit_secret. Keys are adopted only if the whole path checks. Erases pathSecret.
func (self *mlsTreeSecrets) adoptPathSecret(tree *mlsRatchetTree, sender mlsLeafIndex, updatePath *mlsUpdatePath, position int, pathSecret []byte) ([]byte, error) {
	suite := self.suite
	path := tree.filteredDirectPath(sender)
	derivedKeys := map[mlsNodeIndex]hpke.PrivateKey{}
	current := pathSecret
	defer func() { clear(current) }()
	for index := position; index < len(path); index++ {
		key, err := suite.derivePathKey(current)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(key.PublicKey().Bytes(), updatePath.nodes[index].encryptionKey) {
			return nil, fmt.Errorf("%w: path secret does not match path node %d", errMlsInvalid, index)
		}
		derivedKeys[path[index].node] = key
		next, err := suite.nextPathSecret(current)
		if err != nil {
			return nil, err
		}
		clear(current)
		current = next
	}
	commitSecret := bytes.Clone(current)
	testHookSecret("commit_secret", commitSecret)
	maps.Copy(self.nodeIndexKeys, derivedKeys)
	self.forgetStaleKeys(tree)
	return commitSecret, nil
}

// A receiver's whole step: decrypts, verifies and adopts the path, returning commit_secret. tree must
// already be merged.
func (self *mlsTreeSecrets) receiveUpdatePath(tree *mlsRatchetTree, sender mlsLeafIndex, updatePath *mlsUpdatePath, groupContext []byte, newLeaves []mlsLeafIndex) ([]byte, error) {
	position, pathSecret, err := self.decryptPathSecret(tree, sender, updatePath, groupContext, newLeaves)
	if err != nil {
		return nil, err
	}
	return self.adoptPathSecret(tree, sender, updatePath, position, pathSecret)
}
