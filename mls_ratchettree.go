// The ratchet tree's public state (RFC 9420 §7): the array of nodes, resolutions and filtered
// direct paths (RFC §4.1), tree and parent hashes (RFC §7.8, RFC §7.9), leaf changes (RFC §7.7, RFC
// §12.1), the ratchet_tree encoding (RFC §12.4.3.3) and the validation a joiner runs (RFC
// §12.4.3.1). TreeKEM's encryption over this is mls_treekem.go.
//
// Nodes are immutable once in the tree: a change installs a new node, so clone is a shallow copy and
// a commit runs on one, adopted only if the whole commit validates. A method that returns an error
// may leave a half-changed tree behind for the same reason.
//
// Tree hashes are cached per node and dropped along the path of any change, since a commit touches
// only one path of what may be a 1,000-leaf tree (D-KEYS-14).
//
// Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"fmt"
	"slices"
	"time"
)

// NodeType (RFC §7.8).
const (
	mlsNodeTypeLeaf   uint8 = 1
	mlsNodeTypeParent uint8 = 2
)

// Tunes a ratchet tree.
type mlsTreeSettings struct {
	// Widest tree taken, in leaves, a power of two. A group holds at most 1,000 leaves (D-KEYS-2),
	// which 1,024 fits, and Adds fill the leftmost blank leaf, so no honest tree is wider. This bounds
	// what a decoded tree can make a client allocate and hash.
	MaximumLeafCount uint32
	// Longest span a leaf's lifetime may cover, which RFC §7.2 has the application set: KeyPackages are
	// valid 90 days (§10.6). Non-positive disables the bound, which only tests do, because the mlswg's
	// leaves never expire.
	MaximumLeafLifetime time.Duration
}

// The defaults every tree runs on outside tests.
func defaultMlsTreeSettings() *mlsTreeSettings {
	return &mlsTreeSettings{
		MaximumLeafCount:    1024,
		MaximumLeafLifetime: 90 * 24 * time.Hour,
	}
}

// The group-side inputs of leaf validation.
type mlsLeafValidation struct {
	groupId []byte
	// The GroupContext's, whose required_capabilities leaves must meet.
	groupExtensions     []mlsExtension
	credentialValidator mlsCredentialValidator
}

// An interior node of the ratchet tree (RFC §7.1).
type mlsParentNode struct {
	encryptionKey []byte
	parentHash    []byte
	// In increasing order.
	unmergedLeaves []mlsLeafIndex
}

// ParentNode, in RFC §7.1's field order.
func (self *mlsParentNode) encode(encoder *mlsEncoder) {
	encoder.writeVector(self.encryptionKey)
	encoder.writeVector(self.parentHash)
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for _, leaf := range self.unmergedLeaves {
			elements.writeUint32(uint32(leaf))
		}
	})
}

// Refuses an unmerged list out of order (RFC §7.1), which also means no leaf appears twice.
func (self *mlsParentNode) decode(decoder *mlsDecoder) {
	self.encryptionKey = decoder.readVector()
	self.parentHash = decoder.readVector()
	decoder.readVectorOf(func(element *mlsDecoder) {
		leaf := mlsLeafIndex(element.readUint32())
		if count := len(self.unmergedLeaves); 0 < count && leaf <= self.unmergedLeaves[count-1] {
			element.fail(fmt.Errorf("%w: unmerged leaves out of order", errMlsMalformed))
			return
		}
		self.unmergedLeaves = append(self.unmergedLeaves, leaf)
	})
}

// One position in the tree: a leaf, a parent or, with both nil, blank.
type mlsTreeNode struct {
	leaf   *mlsLeafNode
	parent *mlsParentNode
}

// Whether the position holds no value.
func (self *mlsTreeNode) blank() bool {
	return self.leaf == nil && self.parent == nil
}

// The node's HPKE public key, nil when blank.
func (self *mlsTreeNode) encryptionKey() []byte {
	if self.leaf != nil {
		return self.leaf.encryptionKey
	}
	if self.parent != nil {
		return self.parent.encryptionKey
	}
	return nil
}

// One group's tree.
type mlsRatchetTree struct {
	suite    *mlsCipherSuite
	settings *mlsTreeSettings

	// The array, always 2^(d+1)-1 long.
	nodes []mlsTreeNode
	// Tree hashes by node index, nil where not computed since the last change below.
	nodeHashes [][]byte
}

// A tree of one leaf, a new group's (RFC §11).
func newMlsRatchetTree(suite *mlsCipherSuite, settings *mlsTreeSettings, creator *mlsLeafNode) *mlsRatchetTree {
	return &mlsRatchetTree{
		suite:      suite,
		settings:   settings,
		nodes:      []mlsTreeNode{{leaf: creator}},
		nodeHashes: make([][]byte, 1),
	}
}

// Reads optional<Node> ratchet_tree<V> (RFC §12.4.3.3): the last entry must be non-blank, the array is
// extended to a full tree with blanks, and each position must hold its own kind of node.
func decodeMlsRatchetTree(suite *mlsCipherSuite, settings *mlsTreeSettings, encoded []byte) (*mlsRatchetTree, error) {
	if !mlsTreeLeafCountValid(settings.MaximumLeafCount) {
		return nil, fmt.Errorf("mls: maximum of %d leaves is not a tree", settings.MaximumLeafCount)
	}
	maximumWidth := int(mlsTreeWidth(settings.MaximumLeafCount))
	var nodes []mlsTreeNode
	decoder := &mlsDecoder{remaining: encoded}
	decoder.readVectorOf(func(element *mlsDecoder) {
		if len(nodes) == maximumWidth {
			element.fail(fmt.Errorf("%w: tree wider than %d leaves", errMlsRefused, settings.MaximumLeafCount))
			return
		}
		var node mlsTreeNode
		if element.readOptional() {
			switch nodeType := element.readUint8(); nodeType {
			case mlsNodeTypeLeaf:
				node.leaf = &mlsLeafNode{}
				node.leaf.decode(element)
			case mlsNodeTypeParent:
				node.parent = &mlsParentNode{}
				node.parent.decode(element)
			default:
				element.fail(fmt.Errorf("%w: node type %d", errMlsMalformed, nodeType))
				return
			}
		}
		nodes = append(nodes, node)
	})
	if err := decoder.finish(); err != nil {
		return nil, err
	}

	if len(nodes) == 0 || nodes[len(nodes)-1].blank() {
		return nil, fmt.Errorf("%w: tree ends in a blank node or is empty", errMlsMalformed)
	}
	for index := range nodes {
		node := &nodes[index]
		if (node.leaf != nil && !mlsNodeIndex(index).isLeaf()) || (node.parent != nil && mlsNodeIndex(index).isLeaf()) {
			return nil, fmt.Errorf("%w: node %d holds the wrong kind of node", errMlsMalformed, index)
		}
	}

	leafCount := uint32(1)
	for int(mlsTreeWidth(leafCount)) < len(nodes) {
		leafCount *= 2
	}
	width := int(mlsTreeWidth(leafCount))
	nodes = append(nodes, make([]mlsTreeNode, width-len(nodes))...)
	return &mlsRatchetTree{
		suite:      suite,
		settings:   settings,
		nodes:      nodes,
		nodeHashes: make([][]byte, width),
	}, nil
}

// optional<Node> ratchet_tree<V>, without trailing blanks (RFC §12.4.3.3).
func (self *mlsRatchetTree) encode(encoder *mlsEncoder) {
	last := len(self.nodes) - 1
	for 0 <= last && self.nodes[last].blank() {
		last--
	}
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for index := 0; index <= last; index++ {
			node := &self.nodes[index]
			elements.writeOptional(!node.blank())
			switch {
			case node.leaf != nil:
				elements.writeUint8(mlsNodeTypeLeaf)
				node.leaf.encode(elements)
			case node.parent != nil:
				elements.writeUint8(mlsNodeTypeParent)
				node.parent.encode(elements)
			}
		}
	})
}

// A copy to change without touching this tree: nodes are immutable, so it shares them.
func (self *mlsRatchetTree) clone() *mlsRatchetTree {
	return &mlsRatchetTree{
		suite:      self.suite,
		settings:   self.settings,
		nodes:      slices.Clone(self.nodes),
		nodeHashes: slices.Clone(self.nodeHashes),
	}
}

// The leaves the array holds, blank ones included.
func (self *mlsRatchetTree) leafCount() uint32 {
	return (uint32(len(self.nodes)) + 1) / 2
}

// Whether this index is inside the tree. Indices are uint32 on every leg, so this compares in that
// width, not in int.
func (self *mlsRatchetTree) holds(index mlsNodeIndex) bool {
	return uint32(index) < uint32(len(self.nodes))
}

// The leaf at this index, nil when blank or outside the tree.
func (self *mlsRatchetTree) leafNode(leaf mlsLeafIndex) *mlsLeafNode {
	if self.leafCount() <= uint32(leaf) {
		return nil
	}
	return self.nodes[leaf.node()].leaf
}

// Installs a node and drops the cached hashes it changes.
func (self *mlsRatchetTree) setNode(index mlsNodeIndex, node mlsTreeNode) {
	self.nodes[index] = node
	self.nodeHashes[index] = nil
	for _, ancestor := range index.directPath(self.leafCount()) {
		self.nodeHashes[ancestor] = nil
	}
}

// RFC §4.1.1's resolution of a node, as node indices, unmerged leaves as their leaf nodes.
func (self *mlsRatchetTree) resolution(index mlsNodeIndex) []mlsNodeIndex {
	node := &self.nodes[index]
	if !node.blank() {
		resolved := []mlsNodeIndex{index}
		if node.parent != nil {
			for _, leaf := range node.parent.unmergedLeaves {
				resolved = append(resolved, leaf.node())
			}
		}
		return resolved
	}
	if index.isLeaf() {
		return nil
	}
	left, _ := index.left()
	right, _ := index.right()
	return append(self.resolution(left), self.resolution(right)...)
}

// A node of a filtered direct path, with the child on the copath that keeps it there.
type mlsFilteredPathNode struct {
	node        mlsNodeIndex
	copathChild mlsNodeIndex
}

// RFC §4.1.2's filtered direct path of a leaf, leaf to root: the direct path without any node whose
// copath child has an empty resolution. Empty for a leaf outside the tree, which a peer can name and
// whose node index could wrap back inside it.
func (self *mlsRatchetTree) filteredDirectPath(leaf mlsLeafIndex) []mlsFilteredPathNode {
	leafCount := self.leafCount()
	if leafCount <= uint32(leaf) {
		return nil
	}
	var path []mlsFilteredPathNode
	node := leaf.node()
	for {
		parent, ok := node.parent(leafCount)
		if !ok {
			return path
		}
		sibling, _ := node.sibling(leafCount)
		if 0 < len(self.resolution(sibling)) {
			path = append(path, mlsFilteredPathNode{node: parent, copathChild: sibling})
		}
		node = parent
	}
}

// The tree hash of the whole tree (RFC §7.8).
func (self *mlsRatchetTree) treeHash() ([]byte, error) {
	return self.nodeTreeHash(mlsTreeRoot(self.leafCount()))
}

// A node's tree hash, cached.
func (self *mlsRatchetTree) nodeTreeHash(index mlsNodeIndex) ([]byte, error) {
	if cached := self.nodeHashes[index]; cached != nil {
		return cached, nil
	}
	var hash []byte
	var err error
	if index.isLeaf() {
		hash, err = self.hashLeaf(index.leaf(), self.nodes[index].leaf)
	} else {
		left, _ := index.left()
		right, _ := index.right()
		var leftHash []byte
		var rightHash []byte
		if leftHash, err = self.nodeTreeHash(left); err != nil {
			return nil, err
		}
		if rightHash, err = self.nodeTreeHash(right); err != nil {
			return nil, err
		}
		hash, err = self.hashParent(self.nodes[index].parent, leftHash, rightHash)
	}
	if err != nil {
		return nil, err
	}
	self.nodeHashes[index] = hash
	return hash, nil
}

// A leaf's TreeHashInput, a nil leaf being a blank one.
func (self *mlsRatchetTree) hashLeaf(index mlsLeafIndex, leaf *mlsLeafNode) ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeUint8(mlsNodeTypeLeaf)
	encoder.writeUint32(uint32(index))
	encoder.writeOptional(leaf != nil)
	if leaf != nil {
		leaf.encode(encoder)
	}
	encoded, err := encoder.finish()
	if err != nil {
		return nil, err
	}
	return self.suite.hash(encoded), nil
}

// A parent's TreeHashInput, a nil parent being a blank one.
func (self *mlsRatchetTree) hashParent(parent *mlsParentNode, leftHash []byte, rightHash []byte) ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeUint8(mlsNodeTypeParent)
	encoder.writeOptional(parent != nil)
	if parent != nil {
		parent.encode(encoder)
	}
	encoder.writeVector(leftHash)
	encoder.writeVector(rightHash)
	encoded, err := encoder.finish()
	if err != nil {
		return nil, err
	}
	return self.suite.hash(encoded), nil
}

// The tree hash of a subtree as it stood before these leaves joined (RFC §7.9's original sibling tree
// hash): each blanked, and dropped from every parent's unmerged list. A subtree without any of them
// hashes as it is, cached, which is the common case.
func (self *mlsRatchetTree) originalTreeHash(index mlsNodeIndex, excludedLeaves []mlsLeafIndex) ([]byte, error) {
	var within []mlsLeafIndex
	for _, leaf := range excludedLeaves {
		if index.subtreeContains(leaf.node()) {
			within = append(within, leaf)
		}
	}
	if len(within) == 0 {
		return self.nodeTreeHash(index)
	}
	if index.isLeaf() {
		return self.hashLeaf(index.leaf(), nil)
	}
	left, _ := index.left()
	right, _ := index.right()
	leftHash, err := self.originalTreeHash(left, within)
	if err != nil {
		return nil, err
	}
	rightHash, err := self.originalTreeHash(right, within)
	if err != nil {
		return nil, err
	}
	parent := self.nodes[index].parent
	if parent != nil {
		parent = &mlsParentNode{
			encryptionKey: parent.encryptionKey,
			parentHash:    parent.parentHash,
			unmergedLeaves: slices.DeleteFunc(slices.Clone(parent.unmergedLeaves), func(leaf mlsLeafIndex) bool {
				return slices.Contains(within, leaf)
			}),
		}
	}
	return self.hashParent(parent, leftHash, rightHash)
}

// Hash of ParentHashInput (RFC §7.9).
func (self *mlsRatchetTree) hashParentHashInput(encryptionKey []byte, parentHash []byte, originalSiblingTreeHash []byte) ([]byte, error) {
	encoder := &mlsEncoder{}
	encoder.writeVector(encryptionKey)
	encoder.writeVector(parentHash)
	encoder.writeVector(originalSiblingTreeHash)
	encoded, err := encoder.finish()
	if err != nil {
		return nil, err
	}
	return self.suite.hash(encoded), nil
}

// Whether a non-blank parent node P is parent-hash valid (RFC §7.9.2): exactly one node D below it, in
// the resolution of one child C, carries P's parent hash with the other child as copath child, and
// everything else in C's resolution is P's unmerged leaves under C.
func (self *mlsRatchetTree) verifyParentHash(index mlsNodeIndex) error {
	// the parent_hash a node carries: a leaf from anything but a commit has none to link with, and a
	// node outside the tree, which an unmerged list validate has yet to refuse can name, has none either
	carriedHash := func(candidate mlsNodeIndex) []byte {
		if !self.holds(candidate) {
			return nil
		}
		node := &self.nodes[candidate]
		if node.parent != nil {
			return node.parent.parentHash
		}
		if node.leaf != nil && node.leaf.leafNodeSource == mlsLeafNodeSourceCommit {
			return node.leaf.parentHash
		}
		return nil
	}

	parent := self.nodes[index].parent
	left, _ := index.left()
	right, _ := index.right()
	matches := 0
	for _, children := range [][2]mlsNodeIndex{{left, right}, {right, left}} {
		child, sibling := children[0], children[1]
		originalHash, err := self.originalTreeHash(sibling, parent.unmergedLeaves)
		if err != nil {
			return err
		}
		parentHash, err := self.hashParentHashInput(parent.encryptionKey, parent.parentHash, originalHash)
		if err != nil {
			return err
		}

		var unmergedNodes []mlsNodeIndex
		for _, leaf := range parent.unmergedLeaves {
			if child.subtreeContains(leaf.node()) {
				unmergedNodes = append(unmergedNodes, leaf.node())
			}
		}
		resolved := self.resolution(child)
		for _, candidate := range resolved {
			if !bytes.Equal(carriedHash(candidate), parentHash) {
				continue
			}
			others := slices.DeleteFunc(slices.Clone(resolved), func(node mlsNodeIndex) bool {
				return node == candidate
			})
			slices.Sort(others)
			if slices.Equal(others, unmergedNodes) {
				matches++
			}
		}
	}
	if matches != 1 {
		return fmt.Errorf("%w: parent node %d has %d parent hash links", errMlsInvalid, index, matches)
	}
	return nil
}

// Every non-blank parent is parent-hash valid (RFC §7.9.2).
func (self *mlsRatchetTree) verifyParentHashes() error {
	for index := range self.nodes {
		if self.nodes[index].parent == nil {
			continue
		}
		if err := self.verifyParentHash(mlsNodeIndex(index)); err != nil {
			return err
		}
	}
	return nil
}

// RFC §7.3's checks of one leaf's capabilities against the group's parameters:
// required_capabilities, and every extension of the GroupContext (RFC §13.4).
func (self *mlsRatchetTree) validateGroupCompatibility(leaf *mlsLeafNode, groupExtensions []mlsExtension) error {
	if extension := mlsFindExtension(groupExtensions, mlsExtensionTypeRequiredCapabilities); extension != nil {
		required := &mlsRequiredCapabilities{}
		if err := mlsUnmarshal(extension.extensionData, required); err != nil {
			return err
		}
		if !leaf.capabilities.satisfies(required) {
			return fmt.Errorf("%w: leaf lacks the group's required capabilities", errMlsInvalid)
		}
	}
	for index := range groupExtensions {
		if extensionType := groupExtensions[index].extensionType; !leaf.capabilities.supportsExtension(extensionType) {
			return fmt.Errorf("%w: leaf lacks group extension %#x", errMlsInvalid, extensionType)
		}
	}
	return nil
}

// RFC §7.3 for a leaf entering this tree at a position, or replacing what is there: everything
// validateAlone checks, its source, the group's parameters, mutual credential support, and unique
// signature and encryption keys among the other members.
func (self *mlsRatchetTree) validateNewLeaf(leaf *mlsLeafNode, position mlsLeafIndex, expectedSource uint8, validation *mlsLeafValidation) error {
	if leaf.leafNodeSource != expectedSource {
		return fmt.Errorf("%w: leaf node source %d, want %d", errMlsInvalid, leaf.leafNodeSource, expectedSource)
	}
	if err := leaf.validateAlone(self.suite, self.settings, validation.credentialValidator, validation.groupId, position); err != nil {
		return err
	}
	if err := self.validateGroupCompatibility(leaf, validation.groupExtensions); err != nil {
		return err
	}
	for index := range self.leafCount() {
		other := self.nodes[mlsLeafIndex(index).node()].leaf
		if other == nil || mlsLeafIndex(index) == position {
			continue
		}
		if bytes.Equal(other.signatureKey, leaf.signatureKey) {
			return fmt.Errorf("%w: signature key already at leaf %d", errMlsInvalid, index)
		}
		if bytes.Equal(other.encryptionKey, leaf.encryptionKey) {
			return fmt.Errorf("%w: encryption key already at leaf %d", errMlsInvalid, index)
		}
		if !other.capabilities.supportsCredential(leaf.credential.credentialType) {
			return fmt.Errorf("%w: leaf %d does not support credential type %#x", errMlsInvalid, index, leaf.credential.credentialType)
		}
		if !leaf.capabilities.supportsCredential(other.credential.credentialType) {
			return fmt.Errorf("%w: leaf does not support credential type %#x, in use at leaf %d", errMlsInvalid, other.credential.credentialType, index)
		}
	}
	return nil
}

// A joiner's check of a whole tree (RFC §12.4.3.1), other than comparing its hash to the GroupInfo's:
// every leaf is valid, every key appears once, every unmerged list is honest, and every parent is
// parent-hash valid. Lifetimes are not held against a tree: a member may hold a long-expired
// KeyPackage leaf and be no less a member (RFC §7.3 makes this check only recommended).
func (self *mlsRatchetTree) validate(validation *mlsLeafValidation) error {
	if !mlsTreeLeafCountValid(self.leafCount()) || self.settings.MaximumLeafCount < self.leafCount() {
		return fmt.Errorf("%w: tree of %d leaves", errMlsRefused, self.leafCount())
	}

	credentialTypes := map[uint16]bool{}
	signatureKeys := map[string]bool{}
	encryptionKeys := map[string]bool{}
	hasMember := false
	for index := range self.nodes {
		node := &self.nodes[index]
		if node.blank() {
			continue
		}
		key := string(node.encryptionKey())
		if encryptionKeys[key] {
			return fmt.Errorf("%w: node %d repeats an encryption key", errMlsInvalid, index)
		}
		encryptionKeys[key] = true
		if node.leaf == nil {
			continue
		}
		hasMember = true
		leafIndex := mlsNodeIndex(index).leaf()
		if err := node.leaf.validateAlone(self.suite, self.settings, validation.credentialValidator, validation.groupId, leafIndex); err != nil {
			return fmt.Errorf("leaf %d: %w", leafIndex, err)
		}
		if err := self.validateGroupCompatibility(node.leaf, validation.groupExtensions); err != nil {
			return fmt.Errorf("leaf %d: %w", leafIndex, err)
		}
		if signatureKeys[string(node.leaf.signatureKey)] {
			return fmt.Errorf("%w: leaf %d repeats a signature key", errMlsInvalid, leafIndex)
		}
		signatureKeys[string(node.leaf.signatureKey)] = true
		credentialTypes[node.leaf.credential.credentialType] = true
	}
	if !hasMember {
		return fmt.Errorf("%w: a tree with no members", errMlsInvalid)
	}

	for index := range self.nodes {
		node := &self.nodes[index]
		if node.leaf != nil {
			for credentialType := range credentialTypes {
				if !node.leaf.capabilities.supportsCredential(credentialType) {
					return fmt.Errorf("%w: leaf %d does not support credential type %#x", errMlsInvalid, index/2, credentialType)
				}
			}
		}
		if node.parent != nil {
			if _, err := self.suite.kem.NewPublicKey(node.parent.encryptionKey); err != nil {
				return fmt.Errorf("%w: parent %d: %w", errMlsInvalid, index, err)
			}
			if err := self.validateUnmergedLeaves(mlsNodeIndex(index)); err != nil {
				return err
			}
		}
	}
	return self.verifyParentHashes()
}

// RFC §12.4.3.1's rules for one parent's unmerged list: each entry a non-blank leaf below it, listed by
// every non-blank node between that leaf and it.
func (self *mlsRatchetTree) validateUnmergedLeaves(index mlsNodeIndex) error {
	parent := self.nodes[index].parent
	leafCount := self.leafCount()
	for position, leaf := range parent.unmergedLeaves {
		if 0 < position && leaf <= parent.unmergedLeaves[position-1] {
			return fmt.Errorf("%w: parent %d's unmerged leaves are out of order", errMlsInvalid, index)
		}
		if self.leafNode(leaf) == nil || !index.subtreeContains(leaf.node()) {
			return fmt.Errorf("%w: parent %d lists leaf %d, which is not a member below it", errMlsInvalid, index, leaf)
		}
		for _, between := range leaf.node().directPath(leafCount) {
			if between == index {
				break
			}
			intermediate := self.nodes[between].parent
			if intermediate != nil && !slices.Contains(intermediate.unmergedLeaves, leaf) {
				return fmt.Errorf("%w: node %d omits unmerged leaf %d", errMlsInvalid, between, leaf)
			}
		}
	}
	return nil
}

// The leftmost blank leaf, extending the tree when there is none (RFC §7.7, RFC §12.1.1). Refuses
// to pass the widest tree the settings allow.
func (self *mlsRatchetTree) reserveLeaf() (mlsLeafIndex, error) {
	leafCount := self.leafCount()
	for index := range leafCount {
		if self.nodes[mlsLeafIndex(index).node()].leaf == nil {
			return mlsLeafIndex(index), nil
		}
	}
	if self.settings.MaximumLeafCount <= leafCount {
		return 0, fmt.Errorf("%w: tree of %d leaves is full", errMlsRefused, leafCount)
	}
	self.nodes = append(self.nodes, make([]mlsTreeNode, len(self.nodes)+1)...)
	self.nodeHashes = append(self.nodeHashes, make([][]byte, len(self.nodeHashes)+1)...)
	return mlsLeafIndex(leafCount), nil
}

// Applies an Add (RFC §12.1.1), returning the new member's leaf. The leaf must already be validated.
func (self *mlsRatchetTree) addLeaf(leaf *mlsLeafNode) (mlsLeafIndex, error) {
	index, err := self.reserveLeaf()
	if err != nil {
		return 0, err
	}
	self.setNode(index.node(), mlsTreeNode{leaf: leaf})
	for _, ancestor := range index.node().directPath(self.leafCount()) {
		parent := self.nodes[ancestor].parent
		if parent == nil {
			continue
		}
		position, _ := slices.BinarySearch(parent.unmergedLeaves, index)
		self.setNode(ancestor, mlsTreeNode{parent: &mlsParentNode{
			encryptionKey:  parent.encryptionKey,
			parentHash:     parent.parentHash,
			unmergedLeaves: slices.Insert(slices.Clone(parent.unmergedLeaves), position, index),
		}})
	}
	return index, nil
}

// Applies a Remove (RFC §12.1.3): blanks the leaf and its direct path, then halves the tree until
// its right subtree holds a member (RFC §7.7). The root and right subtree go, blank or not, and the
// left child becomes the root, so hashes below it stay valid. Refuses a leaf that is not a member.
func (self *mlsRatchetTree) removeLeaf(leaf mlsLeafIndex) error {
	if self.leafNode(leaf) == nil {
		return fmt.Errorf("%w: removing leaf %d, which is blank", errMlsInvalid, leaf)
	}
	self.blankPath(leaf)
	self.setNode(leaf.node(), mlsTreeNode{})

	rightHalfHasMember := func() bool {
		leafCount := self.leafCount()
		for index := leafCount / 2; index < leafCount; index++ {
			if self.nodes[mlsLeafIndex(index).node()].leaf != nil {
				return true
			}
		}
		return false
	}
	for 1 < self.leafCount() && !rightHalfHasMember() {
		width := (len(self.nodes) - 1) / 2
		self.nodes = self.nodes[:width]
		self.nodeHashes = self.nodeHashes[:width]
	}
	return nil
}

// Blanks the nodes on a leaf's direct path, leaving the leaf.
func (self *mlsRatchetTree) blankPath(leaf mlsLeafIndex) {
	for _, ancestor := range leaf.node().directPath(self.leafCount()) {
		self.setNode(ancestor, mlsTreeNode{})
	}
}
