// Tree math for the array layout of RFC 9420 Appendix C, which the ratchet tree and the secret tree
// share: leaf n sits at node 2n, parents at odd indices, and a tree is always full, with 2^d leaves
// and 2^(d+1)-1 nodes (§7.7). So relationships between nodes are bit operations on their indices.
//
// A leaf count here is always such a power of two, at most mlsTreeLeafCountMaximum, which callers
// establish once: mlsTreeLeafCountValid says whether a count qualifies. A node index, by contrast, can
// come from a peer, so anything that walks a path stops at a node outside the tree instead of
// trusting it.

package sidecar

import (
	"math/bits"
)

// The largest tree whose node indices fit in 32 bits.
const mlsTreeLeafCountMaximum uint32 = 1024 * 1024 * 1024 * 2

// A leaf's position, 0 at the left. This is what the wire carries.
type mlsLeafIndex uint32

// A node's position in the array.
type mlsNodeIndex uint32

// A positive power of two within the limit.
func mlsTreeLeafCountValid(leafCount uint32) bool {
	return bits.OnesCount32(leafCount) == 1 && leafCount <= mlsTreeLeafCountMaximum
}

// The nodes of a tree with this many leaves (node_width).
func mlsTreeWidth(leafCount uint32) uint32 {
	if leafCount == 0 {
		return 0
	}
	return 2*(leafCount-1) + 1
}

// The root of a tree with this many leaves.
func mlsTreeRoot(leafCount uint32) mlsNodeIndex {
	width := mlsTreeWidth(leafCount)
	if width == 0 {
		return 0
	}
	return mlsNodeIndex(uint32(1)<<(bits.Len32(width)-1) - 1)
}

func (self mlsLeafIndex) node() mlsNodeIndex {
	return mlsNodeIndex(self) * 2
}

func (self mlsNodeIndex) isLeaf() bool {
	return self%2 == 0
}

// The leaf at this node, which must be a leaf node.
func (self mlsNodeIndex) leaf() mlsLeafIndex {
	return mlsLeafIndex(self / 2)
}

// 0 for leaves, 1 for their parents, and so on up.
func (self mlsNodeIndex) level() int {
	return bits.TrailingZeros32(^uint32(self))
}

// False for a leaf.
func (self mlsNodeIndex) left() (mlsNodeIndex, bool) {
	level := self.level()
	if level == 0 {
		return 0, false
	}
	return self ^ (1 << (level - 1)), true
}

// False for a leaf.
func (self mlsNodeIndex) right() (mlsNodeIndex, bool) {
	level := self.level()
	if level == 0 {
		return 0, false
	}
	return self ^ (3 << (level - 1)), true
}

// False for the root and for a node outside the tree.
func (self mlsNodeIndex) parent(leafCount uint32) (mlsNodeIndex, bool) {
	if self == mlsTreeRoot(leafCount) || mlsTreeWidth(leafCount) <= uint32(self) {
		return 0, false
	}
	level := self.level()
	high := (self >> (level + 1)) & 1
	return (self | (1 << level)) ^ (high << (level + 1)), true
}

// The other child of this node's parent. False for the root and for a node outside the tree.
func (self mlsNodeIndex) sibling(leafCount uint32) (mlsNodeIndex, bool) {
	parent, ok := self.parent(leafCount)
	if !ok {
		return 0, false
	}
	if self < parent {
		return parent.right()
	}
	return parent.left()
}

// Ordered from this node's parent to the root (§4.1.2). Empty for the root and for a node outside
// the tree.
func (self mlsNodeIndex) directPath(leafCount uint32) []mlsNodeIndex {
	var path []mlsNodeIndex
	node := self
	for {
		parent, ok := node.parent(leafCount)
		if !ok {
			return path
		}
		path = append(path, parent)
		node = parent
	}
}

// The sibling of this node and of each node on its direct path but the root, leaf to root (§4.1.2).
func (self mlsNodeIndex) copath(leafCount uint32) []mlsNodeIndex {
	var copath []mlsNodeIndex
	node := self
	for {
		sibling, ok := node.sibling(leafCount)
		if !ok {
			return copath
		}
		copath = append(copath, sibling)
		node, _ = node.parent(leafCount)
	}
}

// Whether node is this node or a descendant. A node of level k spans the 2^k - 1 indices to each side
// of it.
func (self mlsNodeIndex) subtreeContains(node mlsNodeIndex) bool {
	reach := uint64(1)<<self.level() - 1
	return uint64(self)-reach <= uint64(node) && uint64(node) <= uint64(self)+reach
}

// The lowest node on both nodes' paths, either node included (common_ancestor_direct).
func mlsCommonAncestor(first mlsNodeIndex, second mlsNodeIndex) mlsNodeIndex {
	firstReach := first.level() + 1
	secondReach := second.level() + 1
	if firstReach <= secondReach && uint64(first)>>secondReach == uint64(second)>>secondReach {
		return second
	}
	if secondReach <= firstReach && uint64(first)>>firstReach == uint64(second)>>firstReach {
		return first
	}
	shift := 0
	for first != second {
		first >>= 1
		second >>= 1
		shift++
	}
	return first<<shift + 1<<(shift-1) - 1
}
