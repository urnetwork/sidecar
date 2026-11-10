// TreeKEM (RFC 9420 §7.4 to §7.6): how a commit's UpdatePath refreshes the keys along one member's
// path and delivers them to everyone else.
//
// A committer runs prepareUpdatePath on its clone of the tree, which leaves the tree in its new shape,
// then builds the provisional GroupContext from that tree's hash and calls encrypt. A receiver runs
// mergeUpdatePath on its clone and then, with the same provisional GroupContext, receiveUpdatePath.
// Both sides leave the transcript and the key schedule to their caller, which takes commit_secret
// from here.
//
// Neither side changes the member's private keys until the whole commit validates: like the tree,
// they are adopted only then, by mlsPreparedPath.adopt or mlsReceivedPath.adopt, so a commit refused
// after its path checks, by its confirmation tag say, leaves the member as it was (RFC §12.4.2).
//
// Private keys live apart from the tree, in mlsTreeSecrets, one per member's view (RFC §4.2). A path
// secret is erased once nothing still needs it, and any held key the tree no longer shows is
// forgotten (RFC §7.5).
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

// Public key encryption labels (RFC §17.7).
const mlsEncryptLabelUpdatePathNode = "UpdatePathNode"

// A value sealed to one node's key: the KEM output and the AEAD ciphertext (RFC §7.6).
type mlsHpkeCiphertext struct {
	kemOutput  []byte
	ciphertext []byte
}

// HPKECiphertext, in RFC §7.6's field order.
func (self *mlsHpkeCiphertext) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.kemOutput)
	encoder.writeVector(self.ciphertext)
}

// HPKECiphertext, in RFC §7.6's field order.
func (self *mlsHpkeCiphertext) decode(decoder *mlsDecoder) {
	self.kemOutput = decoder.readVector()
	self.ciphertext = decoder.readVector()
}

// One node of a commit's path (RFC §7.6): its public key, and its path secret encrypted to each node of
// the copath child's resolution.
type mlsUpdatePathNode struct {
	encryptionKey        []byte
	encryptedPathSecrets []mlsHpkeCiphertext
}

// UpdatePathNode, in RFC §7.6's field order.
func (self *mlsUpdatePathNode) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.encryptionKey)
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for index := range self.encryptedPathSecrets {
			self.encryptedPathSecrets[index].encode(elements)
		}
	})
}

// UpdatePathNode, in RFC §7.6's field order.
func (self *mlsUpdatePathNode) decode(decoder *mlsDecoder) {
	self.encryptionKey = decoder.readVector()
	decoder.readVectorOf(func(element *mlsDecoder) {
		var ciphertext mlsHpkeCiphertext
		ciphertext.decode(element)
		self.encryptedPathSecrets = append(self.encryptedPathSecrets, ciphertext)
	})
}

// What a commit carries to refresh its committer's path (RFC §7.6): the new leaf and the nodes of its
// filtered direct path, in order.
type mlsUpdatePath struct {
	leafNode mlsLeafNode
	nodes    []mlsUpdatePathNode
}

// UpdatePath, in RFC §7.6's field order.
func (self *mlsUpdatePath) encode(encoder *mlsEncoder) {
	self.leafNode.encode(encoder)
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for index := range self.nodes {
			self.nodes[index].encode(elements)
		}
	})
}

// UpdatePath, in RFC §7.6's field order.
func (self *mlsUpdatePath) decode(decoder *mlsDecoder) {
	self.leafNode.decode(decoder)
	decoder.readVectorOf(func(element *mlsDecoder) {
		var node mlsUpdatePathNode
		node.decode(element)
		self.nodes = append(self.nodes, node)
	})
}

// path_secret[n+1] (RFC §7.4). The value after the last node's is commit_secret.
func (self *mlsCipherSuite) nextPathSecret(pathSecret []byte) ([]byte, error) {
	return self.deriveSecret("path_secret", pathSecret, "path")
}

// A node's key pair from its path secret (RFC §7.4), by way of a node secret that lives only here.
func (self *mlsCipherSuite) derivePathKey(pathSecret []byte) (hpke.PrivateKey, error) {
	nodeSecret, err := self.deriveSecret("node_secret", pathSecret, "node")
	if err != nil {
		return nil, err
	}
	defer clear(nodeSecret)
	return self.deriveKemKey("node_priv", nodeSecret)
}

// Who a path secret is encrypted to at one copath child: its resolution, without leaves new in this
// commit, which get the secret by Welcome instead (RFC §7.5).
func (self *mlsRatchetTree) pathSecretRecipients(copathChild mlsNodeIndex, newLeaves []mlsLeafIndex) []mlsNodeIndex {
	return slices.DeleteFunc(self.resolution(copathChild), func(node mlsNodeIndex) bool {
		return node.isLeaf() && slices.Contains(newLeaves, node.leaf())
	})
}

// Installs a path's public keys on the filtered path, then fills in parent_hash from the root down
// (RFC §7.9.1). Returns the hash the leaf must carry. A path node starts with no unmerged leaves,
// so its original sibling tree hash is the sibling's tree hash as it stands (RFC §7.9).
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

// Refreshes the sender's path (RFC §7.4, RFC §7.5) on this tree, which must be the commit's clone
// with its proposals applied. The new leaf takes everything but its keys and hash from
// leafTemplate; signatureKey must be the private half of leafTemplate's. An external committer
// reserves its leaf first.
func (self *mlsRatchetTree) prepareUpdatePath(sender mlsLeafIndex, leafTemplate *mlsLeafNode, signatureKey ed25519.PrivateKey, groupId []byte) (*mlsPreparedPath, error) {
	if self.leafCount() <= uint32(sender) {
		return nil, fmt.Errorf("%w: sender %d outside the tree", errMlsInvalid, sender)
	}
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
// (RFC §7.5), which needs this tree's hash, so it comes only now. newLeaves are the commit's Adds.
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
			tree.settings.yield()
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

// The path secret of one node of the path, for a new member's Welcome (RFC §12.4.1), or nil if the
// node is not on the path or the path is erased.
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

// Overwrites the path secrets, once any Welcome is built (RFC §7.5). commit_secret is the caller's.
func (self *mlsPreparedPath) erase() {
	for _, pathSecret := range self.pathSecrets {
		clear(pathSecret)
	}
	self.pathSecrets = nil
}

// Validates a received UpdatePath and merges it (RFC §7.5, RFC §12.4.2) into this tree, which must
// be the commit's clone with its proposals applied. A sender joining by external commit reserves
// its leaf first. newLeaves are the commit's Adds.
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

// What one member holds of the tree (RFC §4.2): the private keys of its leaf and of the nodes above it
// that it knows. Everything here must match the public tree, which forgetStaleKeys restores after a
// change.
type mlsTreeSecrets struct {
	suite *mlsCipherSuite
	leaf  mlsLeafIndex
	// The member's leaf key sits at its leaf node, like any other.
	nodeIndexKeys map[mlsNodeIndex]hpke.PrivateKey
}

// A member that holds only its leaf key, as it has before any path reaches it.
func newMlsTreeSecrets(suite *mlsCipherSuite, leaf mlsLeafIndex, leafKey hpke.PrivateKey) *mlsTreeSecrets {
	return &mlsTreeSecrets{
		suite:         suite,
		leaf:          leaf,
		nodeIndexKeys: map[mlsNodeIndex]hpke.PrivateKey{leaf.node(): leafKey},
	}
}

// One node's key from its path secret, refusing a key that is not the tree's (RFC §12.4.3.1).
func (self *mlsTreeSecrets) pathKeyAt(tree *mlsRatchetTree, node mlsNodeIndex, pathSecret []byte) (hpke.PrivateKey, error) {
	if !tree.holds(node) {
		return nil, fmt.Errorf("%w: node %d outside the tree", errMlsInvalid, node)
	}
	key, err := self.suite.derivePathKey(pathSecret)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(key.PublicKey().Bytes(), tree.nodes[node].encryptionKey()) {
		return nil, fmt.Errorf("%w: path secret does not match node %d", errMlsInvalid, node)
	}
	return key, nil
}

// Sets one node's key from its path secret, refusing a key that is not the tree's (RFC §12.4.3.1).
func (self *mlsTreeSecrets) implantPathSecret(tree *mlsRatchetTree, node mlsNodeIndex, pathSecret []byte) error {
	key, err := self.pathKeyAt(tree, node, pathSecret)
	if err != nil {
		return err
	}
	self.nodeIndexKeys[node] = key
	return nil
}

// A new member's keys above its leaf (RFC §12.4.3.1): a Welcome's path_secret is the path secret of the
// lowest node shared with the committer, and each node above that on the committer's filtered path
// follows from it. tree is the tree the Welcome carries, already validated. Keys are set only if every
// node checks, and the secrets are the join's own, so a Welcome refused later goes with them. The
// caller still owns and erases pathSecret.
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
	nodeIndexKeys := map[mlsNodeIndex]hpke.PrivateKey{}
	current := bytes.Clone(pathSecret)
	defer func() { clear(current) }()
	for _, entry := range path[position:] {
		key, err := self.pathKeyAt(tree, entry.node, current)
		if err != nil {
			return err
		}
		nodeIndexKeys[entry.node] = key
		next, err := suite.nextPathSecret(current)
		if err != nil {
			return err
		}
		clear(current)
		current = next
	}
	maps.Copy(self.nodeIndexKeys, nodeIndexKeys)
	return nil
}

// Whether every key held is the tree's (treekem's consistency check, and a cheap one to keep).
func (self *mlsTreeSecrets) consistentWith(tree *mlsRatchetTree) bool {
	for node, key := range self.nodeIndexKeys {
		if !tree.holds(node) || !bytes.Equal(key.PublicKey().Bytes(), tree.nodes[node].encryptionKey()) {
			return false
		}
	}
	return true
}

// Drops every key the tree no longer shows: a blanked node's, a truncated one's, one a path replaced
// (RFC §7.5's outdated key pairs).
func (self *mlsTreeSecrets) forgetStaleKeys(tree *mlsRatchetTree) {
	maps.DeleteFunc(self.nodeIndexKeys, func(node mlsNodeIndex, key hpke.PrivateKey) bool {
		return !tree.holds(node) || !bytes.Equal(key.PublicKey().Bytes(), tree.nodes[node].encryptionKey())
	})
}

// Finds the path node this member's secret arrives at and decrypts it (RFC §7.5's "decrypts the path
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

// What a receiver learns from a commit's path, held apart from its secrets: the commit can still be
// refused after the path checks, by its confirmation tag, which needs commit_secret from here, and a
// refused commit leaves the member as it was (RFC §12.4.2).
type mlsReceivedPath struct {
	// The merged tree, which these keys match.
	tree *mlsRatchetTree
	// The path's private keys, from the node the member's secret arrived at up.
	nodeIndexKeys map[mlsNodeIndex]hpke.PrivateKey
	// The caller's to use and erase.
	commitSecret []byte
}

// Hands the path's keys to the member's secrets once the whole commit validates, and drops every key
// the merged tree no longer shows (RFC §7.5's outdated key pairs), so the secrets match it.
func (self *mlsReceivedPath) adopt(secrets *mlsTreeSecrets) {
	maps.Copy(secrets.nodeIndexKeys, self.nodeIndexKeys)
	secrets.forgetStaleKeys(self.tree)
}

// Derives the path from one node up and checks each public key against the UpdatePath (RFC §7.5).
// The member's secrets are not touched. Erases pathSecret.
func (self *mlsTreeSecrets) derivePathFrom(tree *mlsRatchetTree, sender mlsLeafIndex, updatePath *mlsUpdatePath, position int, pathSecret []byte) (*mlsReceivedPath, error) {
	suite := self.suite
	path := tree.filteredDirectPath(sender)
	received := &mlsReceivedPath{tree: tree, nodeIndexKeys: map[mlsNodeIndex]hpke.PrivateKey{}}
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
		received.nodeIndexKeys[path[index].node] = key
		next, err := suite.nextPathSecret(current)
		if err != nil {
			return nil, err
		}
		clear(current)
		current = next
	}
	received.commitSecret = bytes.Clone(current)
	testHookSecret("commit_secret", received.commitSecret)
	return received, nil
}

// A receiver's step up to the commit's own checks: decrypts and verifies the path, and returns its
// keys and commit_secret for adopt once the whole commit validates. tree must already be merged. The
// member's secrets are not touched.
func (self *mlsTreeSecrets) receiveUpdatePath(tree *mlsRatchetTree, sender mlsLeafIndex, updatePath *mlsUpdatePath, groupContext []byte, newLeaves []mlsLeafIndex) (*mlsReceivedPath, error) {
	position, pathSecret, err := self.decryptPathSecret(tree, sender, updatePath, groupContext, newLeaves)
	if err != nil {
		return nil, err
	}
	return self.derivePathFrom(tree, sender, updatePath, position, pathSecret)
}
