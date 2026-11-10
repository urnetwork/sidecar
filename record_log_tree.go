// RECORD.md section 10.1's tree, on every leg: RFC 9162's Merkle tree over §16.8's leaves, leaf(E) = SHA-256(0x00 ||
// E.header.body) (record_hash.go's RecordLeafHash) and node = SHA-256(0x01 || left || right), with its inclusion and
// consistency proofs and their verifiers (RFC 9162 sections 2.1.1, 2.1.3 and 2.1.4). A leaf here is already a hash:
// the tree never sees an entry.
//
// The verifiers are pure and take proofs as they travel, a list of 32-byte hashes, so the offline verifier
// (record_verify_packet.go) and a witness check alike. recordLogTree is the tree a reader rebuilds from checkpoint
// entries: it only grows, and it remembers each whole power-of-two subtree it hashed, so a root or a proof at any
// earlier size costs a logarithm of hashes once the tree was walked. Its methods are not safe for concurrent use:
// RecordLog holds its lock around them.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

// RFC 9162's node prefix, a format value; the leaf prefix is record_hash.go's.
const recordLogNodePrefix = 0x01

// The most hashes an inclusion path holds (DisclosedEntry.inclusion_path): a tree of 2^63 leaves.
const recordLogPathHashCount = 63

// A size, an index or a proof that is no part of the tree it names.
var ErrRecordLogProof = errors.New("record log proof invalid")

// SHA-256(0x01 || left || right).
func recordLogNode(left [sha256.Size]byte, right [sha256.Size]byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte{recordLogNodePrefix})
	hash.Write(left[:])
	hash.Write(right[:])
	var node [sha256.Size]byte
	hash.Sum(node[:0])
	return node
}

// The largest power of two below n, for n of at least 2: where RFC 9162 splits a tree.
func recordLogSplit(n uint64) uint64 {
	return uint64(1) << (bits.Len64(n-1) - 1)
}

// RFC 9162's MTH over leaves: SHA-256 of nothing for none.
func RecordLogRoot(leaves [][sha256.Size]byte) [sha256.Size]byte {
	tree := newRecordLogTree()
	tree.append(leaves...)
	return tree.root()
}

// A tree of leaves that only grows.
type recordLogTree struct {
	leaves [][sha256.Size]byte
	// hashes of whole subtrees by (first leaf, size), size a power of two above 1 and first a multiple of it
	nodes map[[2]uint64][sha256.Size]byte
}

// An empty tree.
func newRecordLogTree() *recordLogTree {
	return &recordLogTree{nodes: map[[2]uint64][sha256.Size]byte{}}
}

// The number of leaves.
func (self *recordLogTree) size() uint64 {
	return uint64(len(self.leaves))
}

// Adds leaves at the end.
func (self *recordLogTree) append(leaves ...[sha256.Size]byte) {
	self.leaves = append(self.leaves, leaves...)
}

// MTH(D[first:first+size]).
func (self *recordLogTree) hash(first uint64, size uint64) [sha256.Size]byte {
	if size == 0 {
		return sha256.Sum256(nil)
	}
	if size == 1 {
		return self.leaves[first]
	}
	whole := size&(size-1) == 0 && first%size == 0
	if whole {
		if node, ok := self.nodes[[2]uint64{first, size}]; ok {
			return node
		}
	}
	split := recordLogSplit(size)
	node := recordLogNode(self.hash(first, split), self.hash(first+split, size-split))
	if whole {
		self.nodes[[2]uint64{first, size}] = node
	}
	return node
}

// The root over every leaf.
func (self *recordLogTree) root() [sha256.Size]byte {
	return self.hash(0, self.size())
}

// The root the tree had at size leaves.
func (self *recordLogTree) rootAt(size uint64) ([sha256.Size]byte, error) {
	if self.size() < size {
		return [sha256.Size]byte{}, fmt.Errorf("%w: size %d past the tree's %d", ErrRecordLogProof, size, self.size())
	}
	return self.hash(0, size), nil
}

// RFC 9162 section 2.1.3.1's PATH(index, D[0:size]): the leaf's audit path in the tree of size leaves, lowest first.
func (self *recordLogTree) inclusionPath(index uint64, size uint64) ([][sha256.Size]byte, error) {
	if self.size() < size || size <= index {
		return nil, fmt.Errorf("%w: index %d of size %d in a tree of %d", ErrRecordLogProof, index, size, self.size())
	}
	path := [][sha256.Size]byte{}
	var walk func(index uint64, first uint64, size uint64)
	walk = func(index uint64, first uint64, size uint64) {
		if size == 1 {
			return
		}
		split := recordLogSplit(size)
		if index < split {
			walk(index, first, split)
			path = append(path, self.hash(first+split, size-split))
		} else {
			walk(index-split, first+split, size-split)
			path = append(path, self.hash(first, split))
		}
	}
	walk(index, 0, size)
	return path, nil
}

// RFC 9162 section 2.1.4.1's PROOF(first, D[0:second]): that the tree of first leaves is a prefix of the tree of
// second. Empty when the sizes are equal or first is 0, which need no proof.
func (self *recordLogTree) consistencyPath(first uint64, second uint64) ([][sha256.Size]byte, error) {
	if self.size() < second || second < first {
		return nil, fmt.Errorf("%w: sizes %d to %d in a tree of %d", ErrRecordLogProof, first, second, self.size())
	}
	path := [][sha256.Size]byte{}
	if first == 0 || first == second {
		return path, nil
	}
	var walk func(m uint64, start uint64, n uint64, whole bool)
	walk = func(m uint64, start uint64, n uint64, whole bool) {
		if m == n {
			if !whole {
				path = append(path, self.hash(start, n))
			}
			return
		}
		split := recordLogSplit(n)
		if m <= split {
			walk(m, start, split, whole)
			path = append(path, self.hash(start+split, n-split))
		} else {
			walk(m-split, start+split, n-split, false)
			path = append(path, self.hash(start, split))
		}
	}
	walk(first, 0, second, true)
	return path, nil
}

// A proof's hashes as fixed arrays: false for one that is not 32 bytes.
func recordLogPathOf(path [][]byte) ([][sha256.Size]byte, bool) {
	hashes := make([][sha256.Size]byte, 0, len(path))
	for _, hash := range path {
		if len(hash) != sha256.Size {
			return nil, false
		}
		hashes = append(hashes, [sha256.Size]byte(hash))
	}
	return hashes, true
}

// RFC 9162 section 2.1.3.2: whether leaf sits at index in the tree of size leaves whose root is root, by path. A path
// of another length than the tree's shape gives, or past 63 hashes, is false.
func RecordLogVerifyInclusion(leaf [sha256.Size]byte, index uint64, size uint64, path [][]byte, root [sha256.Size]byte) bool {
	hashes, ok := recordLogPathOf(path)
	if !ok || size <= index || recordLogPathHashCount < len(hashes) {
		return false
	}
	fn := index
	sn := size - 1
	node := leaf
	for _, hash := range hashes {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			node = recordLogNode(hash, node)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			node = recordLogNode(node, hash)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && node == root
}

// RFC 9162 section 2.1.4.2: whether the tree of first leaves under firstRoot is a prefix of the tree of second leaves
// under secondRoot, by path. Equal sizes need equal roots and an empty path; a first size of 0 is a prefix of
// anything, with an empty path.
func RecordLogVerifyConsistency(first uint64, second uint64, firstRoot [sha256.Size]byte, secondRoot [sha256.Size]byte, path [][]byte) bool {
	hashes, ok := recordLogPathOf(path)
	if !ok || second < first {
		return false
	}
	if first == second {
		return len(hashes) == 0 && firstRoot == secondRoot
	}
	if first == 0 {
		return len(hashes) == 0
	}
	if len(hashes) == 0 {
		return false
	}
	if first&(first-1) == 0 {
		// a whole tree is its own first node
		hashes = append([][sha256.Size]byte{firstRoot}, hashes...)
	}
	fn := first - 1
	sn := second - 1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr := hashes[0]
	sr := hashes[0]
	for _, hash := range hashes[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = recordLogNode(hash, fr)
			sr = recordLogNode(hash, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = recordLogNode(sr, hash)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && fr == firstRoot && sr == secondRoot
}

// The inclusion path of the leaf at index among leaves, as it travels: what a test or a tool with every leaf in hand
// asks for.
func RecordLogInclusionPath(index uint64, leaves [][sha256.Size]byte) ([][]byte, error) {
	tree := newRecordLogTree()
	tree.append(leaves...)
	path, err := tree.inclusionPath(index, tree.size())
	if err != nil {
		return nil, err
	}
	return recordLogPathBytes(path), nil
}

// The consistency path from the first leaves of leaves to all of them, as it travels.
func RecordLogConsistencyPath(first uint64, leaves [][sha256.Size]byte) ([][]byte, error) {
	tree := newRecordLogTree()
	tree.append(leaves...)
	path, err := tree.consistencyPath(first, tree.size())
	if err != nil {
		return nil, err
	}
	return recordLogPathBytes(path), nil
}

// A proof's hashes as byte slices.
func recordLogPathBytes(path [][sha256.Size]byte) [][]byte {
	hashes := make([][]byte, 0, len(path))
	for _, hash := range path {
		hashes = append(hashes, append([]byte{}, hash[:]...))
	}
	return hashes
}
