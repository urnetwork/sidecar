// RFC 9162 §2.1's Merkle trees over a push's change list (§11.6's merkle row): leaf SHA-256(0x00 || bytes), node
// SHA-256(0x01 || left || right), the empty tree SHA-256 of nothing. A change's leaf is its EvsChange bytes as listed,
// never a re-marshal. Changes sort by their token paths' bytes, strictly, so no path is listed twice. A one-part push
// whose change list is not inline states changes_root over its changes; a push in parts states it over its parts'
// roots, each part's root over that part's changes, which are a contiguous run in part order. So an inclusion proof
// is one RFC 9162 path, or two, part level last, and two adjacent leaves' proofs show that no path between them
// changed (§11.9), which is how a reader learns that a push it cannot read whole left a path alone.
//
// Every size a proof claims is checked against what the statement signs where it signs one: change_count for a
// one-part push and part_count for the parts. A part's own size is signed nowhere, so leaves of one part are held to
// one claimed size, and a part's first and last leaves to the spines no other leaf can stand on, since RFC 9162
// separates leaves from nodes.
//
// On every leg. Package-level functions are safe for concurrent use; an EvsMerkleTree or EvsChangeTree is not, since
// it remembers the subtrees it hashed.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// RFC 9162 §2.1.1's prefixes, which keep a leaf from passing as a node.
const (
	evsMerkleLeafPrefix byte = 0x00
	evsMerkleNodePrefix byte = 0x01
)

// A path's bound: 64 hashes reach the root of any tree a 64-bit size names.
const evsMerklePathMaxLength = 64

// The parts a push in parts has: part_count is 0 for one part, else 2 to 1,024 (§11.8).
const (
	evsMinPartCount = 2
	EvsMaxPartCount = 1024
)

// A Merkle proof that does not reach its root, claims a position its tree cannot have, or proves something other
// than it says; or a change list out of §11.6's order.
var ErrEvsMerkleInvalid = errors.New("evs merkle proof invalid")

// RFC 9162's MTH({d}) = SHA-256(0x00 || d).
func EvsMerkleLeafHash(leaf []byte) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte{evsMerkleLeafPrefix})
	digest.Write(leaf)
	return [sha256.Size]byte(digest.Sum(nil))
}

// SHA-256(0x01 || left || right).
func evsMerkleNodeHash(left []byte, right []byte) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte{evsMerkleNodePrefix})
	digest.Write(left)
	digest.Write(right)
	return [sha256.Size]byte(digest.Sum(nil))
}

// RFC 9162 §2.1.1's k: the largest power of two smaller than a size of at least 2.
func evsMerkleSplit(size int) int {
	return 1 << (bits.Len(uint(size-1)) - 1)
}

// One RFC 9162 tree over its leaves, remembering the subtrees it hashed, so every leaf's path costs about one
// tree's hashing in all.
type EvsMerkleTree struct {
	leafHashes [][sha256.Size]byte
	// MTH of leaves [start, end), for subtrees of two or more
	nodeHashes map[[2]int][sha256.Size]byte
}

// The tree over leaves, each hashed as given.
func NewEvsMerkleTree(leaves [][]byte) *EvsMerkleTree {
	leafHashes := make([][sha256.Size]byte, len(leaves))
	for i, leaf := range leaves {
		leafHashes[i] = EvsMerkleLeafHash(leaf)
	}
	return &EvsMerkleTree{leafHashes: leafHashes, nodeHashes: map[[2]int][sha256.Size]byte{}}
}

// The number of leaves.
func (self *EvsMerkleTree) Size() int {
	return len(self.leafHashes)
}

// MTH over every leaf; SHA-256 of nothing for no leaf.
func (self *EvsMerkleTree) Root() [sha256.Size]byte {
	if len(self.leafHashes) == 0 {
		return sha256.Sum256(nil)
	}
	return self.subtreeHash(0, len(self.leafHashes))
}

// MTH of leaves [start, end), end past start.
func (self *EvsMerkleTree) subtreeHash(start int, end int) [sha256.Size]byte {
	if end-start == 1 {
		return self.leafHashes[start]
	}
	key := [2]int{start, end}
	if nodeHash, ok := self.nodeHashes[key]; ok {
		return nodeHash
	}
	split := start + evsMerkleSplit(end-start)
	left := self.subtreeHash(start, split)
	right := self.subtreeHash(split, end)
	nodeHash := evsMerkleNodeHash(left[:], right[:])
	self.nodeHashes[key] = nodeHash
	return nodeHash
}

// RFC 9162 §2.1.3.1's PATH(index, leaves), nearest the leaf first: empty for a tree of one.
func (self *EvsMerkleTree) InclusionPath(index int) ([][]byte, error) {
	if index < 0 || len(self.leafHashes) <= index {
		return nil, fmt.Errorf("%w: leaf %d of %d", ErrEvsMerkleInvalid, index, len(self.leafHashes))
	}
	return self.path(index, 0, len(self.leafHashes), [][]byte{}), nil
}

// PATH within leaves [start, end), appended to path.
func (self *EvsMerkleTree) path(index int, start int, end int, path [][]byte) [][]byte {
	if end-start == 1 {
		return path
	}
	split := start + evsMerkleSplit(end-start)
	if index < split {
		path = self.path(index, start, split, path)
		sibling := self.subtreeHash(split, end)
		return append(path, sibling[:])
	}
	path = self.path(index, split, end, path)
	sibling := self.subtreeHash(start, split)
	return append(path, sibling[:])
}

// The proof message of a leaf: its bytes, index, the tree's size and its path.
func (self *EvsMerkleTree) proof(leaf []byte, index int) (*protocol.EvsMerkleProof, error) {
	path, err := self.InclusionPath(index)
	if err != nil {
		return nil, err
	}
	return &protocol.EvsMerkleProof{
		Leaf:  bytes.Clone(leaf),
		Index: uint64(index),
		Size:  uint64(len(self.leafHashes)),
		Path:  path,
	}, nil
}

// RFC 9162 §2.1.3.2: the root a leaf hash's path proves for index in a tree of size, the bounds first. The caller
// compares the root with the one it trusts.
func EvsMerklePathRoot(leafHash [sha256.Size]byte, index uint64, size uint64, path [][]byte) ([sha256.Size]byte, error) {
	noRoot := [sha256.Size]byte{}
	if size <= index {
		return noRoot, fmt.Errorf("%w: index %d of %d", ErrEvsMerkleInvalid, index, size)
	}
	if evsMerklePathMaxLength < len(path) {
		return noRoot, fmt.Errorf("%w: a path of %d hashes", ErrEvsMerkleInvalid, len(path))
	}
	// §2.1.3.2's fn, sn and r
	node := index
	lastNode := size - 1
	root := leafHash
	for _, sibling := range path {
		if len(sibling) != sha256.Size {
			return noRoot, fmt.Errorf("%w: a path hash of %d bytes", ErrEvsMerkleInvalid, len(sibling))
		}
		if lastNode == 0 {
			return noRoot, fmt.Errorf("%w: a path too long for index %d of %d", ErrEvsMerkleInvalid, index, size)
		}
		if node&1 == 1 || node == lastNode {
			root = evsMerkleNodeHash(sibling, root[:])
			for node&1 == 0 && node != 0 {
				node >>= 1
				lastNode >>= 1
			}
		} else {
			root = evsMerkleNodeHash(root[:], sibling)
		}
		node >>= 1
		lastNode >>= 1
	}
	if lastNode != 0 {
		return noRoot, fmt.Errorf("%w: a path too short for index %d of %d", ErrEvsMerkleInvalid, index, size)
	}
	return root, nil
}

// Whether proof's leaf reaches root.
func EvsVerifyMerkleProof(root []byte, proof *protocol.EvsMerkleProof) error {
	computed, err := EvsMerklePathRoot(EvsMerkleLeafHash(proof.GetLeaf()), proof.GetIndex(), proof.GetSize(), proof.GetPath())
	if err != nil {
		return err
	}
	if !bytes.Equal(computed[:], root) {
		return fmt.Errorf("%w: the proof reaches another root", ErrEvsMerkleInvalid)
	}
	return nil
}

// A change as a leaf: its message and the token path it names.
func parseEvsChangeLeaf(leaf []byte) (*protocol.EvsChange, EvsTokenPath, error) {
	change := &protocol.EvsChange{}
	if err := proto.Unmarshal(leaf, change); err != nil {
		return nil, nil, fmt.Errorf("%w: a change that does not parse", ErrEvsMerkleInvalid)
	}
	tokenPath, err := ParseEvsChangedTokenPath(change.GetTokenPath())
	if err != nil {
		return nil, nil, err
	}
	return change, tokenPath, nil
}

// One run of a change list: its tree and each leaf's token path.
type evsChangeRun struct {
	leaves     [][]byte
	tokenPaths []EvsTokenPath
	tree       *EvsMerkleTree
}

// A push's change list as its trees: one over its changes, or one per part and one over the parts' roots.
type EvsChangeTree struct {
	runs []*evsChangeRun
	// nil for one part
	partTree *EvsMerkleTree
}

// The tree of a one-part push's change list, each change's EvsChange bytes as listed, which must be in strictly
// ascending token path order.
func NewEvsChangeTree(changes [][]byte) (*EvsChangeTree, error) {
	runs, err := newEvsChangeRuns([][][]byte{changes})
	if err != nil {
		return nil, err
	}
	return &EvsChangeTree{runs: runs}, nil
}

// The trees of a push in parts: 2 to 1,024 parts, none empty, their changes ascending across all of them.
func NewEvsPartedChangeTree(parts [][][]byte) (*EvsChangeTree, error) {
	if len(parts) < evsMinPartCount || EvsMaxPartCount < len(parts) {
		return nil, fmt.Errorf("%w: %d parts", ErrEvsMerkleInvalid, len(parts))
	}
	runs, err := newEvsChangeRuns(parts)
	if err != nil {
		return nil, err
	}
	partRoots := make([][]byte, len(runs))
	for i, run := range runs {
		if run.tree.Size() == 0 {
			return nil, fmt.Errorf("%w: part %d holds no change", ErrEvsMerkleInvalid, i+1)
		}
		root := run.tree.Root()
		partRoots[i] = root[:]
	}
	return &EvsChangeTree{runs: runs, partTree: NewEvsMerkleTree(partRoots)}, nil
}

// Each run's tree, refusing a change that does not parse or breaks the strict order across all runs.
func newEvsChangeRuns(parts [][][]byte) ([]*evsChangeRun, error) {
	runs := make([]*evsChangeRun, len(parts))
	var previous EvsTokenPath
	for i, changes := range parts {
		run := &evsChangeRun{leaves: changes, tokenPaths: make([]EvsTokenPath, len(changes))}
		for j, leaf := range changes {
			_, tokenPath, err := parseEvsChangeLeaf(leaf)
			if err != nil {
				return nil, err
			}
			if previous != nil && 0 <= previous.Compare(tokenPath) {
				return nil, fmt.Errorf("%w: changes not in strictly ascending token path order", ErrEvsMerkleInvalid)
			}
			run.tokenPaths[j] = tokenPath
			previous = tokenPath
		}
		run.tree = NewEvsMerkleTree(changes)
		runs[i] = run
	}
	return runs, nil
}

// changes_root: over the changes for one part, over the parts' roots for several.
func (self *EvsChangeTree) Root() [sha256.Size]byte {
	if self.partTree == nil {
		return self.runs[0].tree.Root()
	}
	return self.partTree.Root()
}

// The number of parts: 0 for a one-part push, as part_count says.
func (self *EvsChangeTree) PartCount() uint32 {
	if self.partTree == nil {
		return 0
	}
	return uint32(len(self.runs))
}

// Every change, across its parts: change_count.
func (self *EvsChangeTree) ChangeCount() int {
	changeCount := 0
	for _, run := range self.runs {
		changeCount += len(run.leaves)
	}
	return changeCount
}

// A part's root, part counted from 0, which EvsPushPart.changes_root states and a seal record keeps.
func (self *EvsChangeTree) PartRoot(part int) ([sha256.Size]byte, error) {
	if part < 0 || len(self.runs) <= part {
		return [sha256.Size]byte{}, fmt.Errorf("%w: part %d of %d", ErrEvsMerkleInvalid, part, len(self.runs))
	}
	return self.runs[part].tree.Root(), nil
}

// The proofs of change index of part (both from 0) to changes_root, part level last: what §11.9's reply and the
// payload's proofs carry.
func (self *EvsChangeTree) InclusionProof(part int, index int) ([]*protocol.EvsMerkleProof, error) {
	if part < 0 || len(self.runs) <= part {
		return nil, fmt.Errorf("%w: part %d of %d", ErrEvsMerkleInvalid, part, len(self.runs))
	}
	run := self.runs[part]
	if index < 0 || len(run.leaves) <= index {
		return nil, fmt.Errorf("%w: change %d of %d", ErrEvsMerkleInvalid, index, len(run.leaves))
	}
	leafProof, err := run.tree.proof(run.leaves[index], index)
	if err != nil {
		return nil, err
	}
	if self.partTree == nil {
		return []*protocol.EvsMerkleProof{leafProof}, nil
	}
	partRoot := run.tree.Root()
	partProof, err := self.partTree.proof(partRoot[:], part)
	if err != nil {
		return nil, err
	}
	return []*protocol.EvsMerkleProof{leafProof, partProof}, nil
}

// Where a token path would sit: the first change at or after it, as a part and an index, and whether that change is
// the path itself. A position past the last change is (len(runs), 0).
func (self *EvsChangeTree) position(tokenPath EvsTokenPath) (int, int, bool) {
	for part, run := range self.runs {
		index := sort.Search(len(run.tokenPaths), func(i int) bool {
			return 0 <= run.tokenPaths[i].Compare(tokenPath)
		})
		if index < len(run.tokenPaths) {
			return part, index, run.tokenPaths[index].Equal(tokenPath)
		}
	}
	return len(self.runs), 0, false
}

// The adjacent leaves around tokenPath with their proofs, refused when the push changed tokenPath itself. One
// absence proof speaks for one path: a reader asks it for the path and for each prefix EvsAbsencePaths names.
func (self *EvsChangeTree) AbsenceProof(tokenPath EvsTokenPath) (*protocol.EvsAbsenceProof, error) {
	part, index, present := self.position(tokenPath)
	if present {
		return nil, fmt.Errorf("%w: the push changed the path", ErrEvsMerkleInvalid)
	}
	absence := &protocol.EvsAbsenceProof{TokenPath: tokenPath.Components()}
	// the leaf below: the one before (part, index), in this part or at the end of an earlier one
	belowPart, belowIndex := part, index-1
	for belowIndex < 0 && 0 < belowPart {
		belowPart -= 1
		belowIndex = len(self.runs[belowPart].leaves) - 1
	}
	if 0 <= belowIndex {
		below, err := self.InclusionProof(belowPart, belowIndex)
		if err != nil {
			return nil, err
		}
		absence.Below = below
	}
	if part < len(self.runs) {
		above, err := self.InclusionProof(part, index)
		if err != nil {
			return nil, err
		}
		absence.Above = above
	}
	return absence, nil
}

// A change a proof chain names, verified to changes_root, with its place.
type evsProvenChange struct {
	change    *protocol.EvsChange
	tokenPath EvsTokenPath
	part      uint64
	index     uint64
	// the claimed size of its part, or of the list for one part
	size uint64
}

// Walks proofs, part level last, to changesRoot: one proof for one part, whose size is changeCount, and two for
// partCount parts.
func verifyEvsChangeProofs(changesRoot []byte, partCount uint32, changeCount uint64, proofs []*protocol.EvsMerkleProof) (*evsProvenChange, error) {
	if partCount != 0 && (partCount < evsMinPartCount || EvsMaxPartCount < partCount) {
		return nil, fmt.Errorf("%w: a part count of %d", ErrEvsMerkleInvalid, partCount)
	}
	levelCount := 1
	if partCount != 0 {
		levelCount = 2
	}
	if len(proofs) != levelCount {
		return nil, fmt.Errorf("%w: %d proofs for %d levels", ErrEvsMerkleInvalid, len(proofs), levelCount)
	}
	leafProof := proofs[0]
	change, tokenPath, err := parseEvsChangeLeaf(leafProof.GetLeaf())
	if err != nil {
		return nil, err
	}
	proven := &evsProvenChange{change: change, tokenPath: tokenPath, index: leafProof.GetIndex(), size: leafProof.GetSize()}
	leafRoot, err := EvsMerklePathRoot(EvsMerkleLeafHash(leafProof.GetLeaf()), leafProof.GetIndex(), leafProof.GetSize(), leafProof.GetPath())
	if err != nil {
		return nil, err
	}
	if levelCount == 1 {
		if leafProof.GetSize() != changeCount {
			return nil, fmt.Errorf("%w: a list of %d changes, not the %d signed", ErrEvsMerkleInvalid, leafProof.GetSize(), changeCount)
		}
		if !bytes.Equal(leafRoot[:], changesRoot) {
			return nil, fmt.Errorf("%w: the proof reaches another root", ErrEvsMerkleInvalid)
		}
		return proven, nil
	}
	partProof := proofs[1]
	if !bytes.Equal(partProof.GetLeaf(), leafRoot[:]) {
		return nil, fmt.Errorf("%w: the part proof is of another part root", ErrEvsMerkleInvalid)
	}
	if partProof.GetSize() != uint64(partCount) {
		return nil, fmt.Errorf("%w: %d parts, not the %d signed", ErrEvsMerkleInvalid, partProof.GetSize(), partCount)
	}
	if err := EvsVerifyMerkleProof(changesRoot, partProof); err != nil {
		return nil, err
	}
	proven.part = partProof.GetIndex()
	return proven, nil
}

// Verifies proofs, part level last, from a change to the changesRoot a statement signs with its partCount and
// changeCount, and gives back the change and its token path.
func EvsVerifyChangeInclusion(changesRoot []byte, partCount uint32, changeCount uint64, proofs []*protocol.EvsMerkleProof) (*protocol.EvsChange, EvsTokenPath, error) {
	proven, err := verifyEvsChangeProofs(changesRoot, partCount, changeCount, proofs)
	if err != nil {
		return nil, nil, err
	}
	return proven.change, proven.tokenPath, nil
}

// Verifies that the push whose change list has changesRoot, partCount and changeCount did not change tokenPath:
// the proof's path is tokenPath, its leaves sort around it, and they are adjacent, or the one present is the
// list's first (nothing below) or last (nothing above).
func EvsVerifyChangeAbsence(changesRoot []byte, partCount uint32, changeCount uint64, tokenPath EvsTokenPath, absence *protocol.EvsAbsenceProof) error {
	stated, err := ParseEvsChangedTokenPath(absence.GetTokenPath())
	if err != nil {
		return err
	}
	if !stated.Equal(tokenPath) {
		return fmt.Errorf("%w: the proof speaks for another path", ErrEvsMerkleInvalid)
	}
	var below, above *evsProvenChange
	if len(absence.GetBelow()) != 0 {
		if below, err = verifyEvsChangeProofs(changesRoot, partCount, changeCount, absence.GetBelow()); err != nil {
			return err
		}
		if 0 <= below.tokenPath.Compare(tokenPath) {
			return fmt.Errorf("%w: the leaf below does not sort below the path", ErrEvsMerkleInvalid)
		}
	}
	if len(absence.GetAbove()) != 0 {
		if above, err = verifyEvsChangeProofs(changesRoot, partCount, changeCount, absence.GetAbove()); err != nil {
			return err
		}
		if above.tokenPath.Compare(tokenPath) <= 0 {
			return fmt.Errorf("%w: the leaf above does not sort above the path", ErrEvsMerkleInvalid)
		}
	}
	lastPart := uint64(0)
	if partCount != 0 {
		lastPart = uint64(partCount) - 1
	}
	isFirst := func(proven *evsProvenChange) bool {
		return proven.part == 0 && proven.index == 0
	}
	isLast := func(proven *evsProvenChange) bool {
		return proven.part == lastPart && proven.index == proven.size-1
	}
	switch {
	case below == nil && above == nil:
		return fmt.Errorf("%w: no leaf on either side", ErrEvsMerkleInvalid)
	case below == nil:
		if !isFirst(above) {
			return fmt.Errorf("%w: nothing below, but the leaf above is not the first", ErrEvsMerkleInvalid)
		}
	case above == nil:
		if !isLast(below) {
			return fmt.Errorf("%w: nothing above, but the leaf below is not the last", ErrEvsMerkleInvalid)
		}
	case below.part == above.part:
		if below.size != above.size || below.index+1 != above.index {
			return fmt.Errorf("%w: the leaves are not adjacent", ErrEvsMerkleInvalid)
		}
	case below.part+1 == above.part:
		if below.index != below.size-1 || above.index != 0 {
			return fmt.Errorf("%w: the leaves are not the ends of adjacent parts", ErrEvsMerkleInvalid)
		}
	default:
		return fmt.Errorf("%w: the leaves are in parts that are not adjacent", ErrEvsMerkleInvalid)
	}
	return nil
}

// What a reader needs absence proofs for, when a statement whose change list it does not hold may have changed
// tokenPath (§11.9): the path itself and each prefix holding it that a covering prefix covers, since every change
// lies under a covering prefix, so no other prefix can be among the changes. Longest first.
func EvsAbsencePaths(changedPrefixes []EvsTokenPath, tokenPath EvsTokenPath) []EvsTokenPath {
	paths := []EvsTokenPath{}
	if len(tokenPath) == 0 {
		// the root, which only the empty covering prefix reaches, and which nothing removes, so it is no prefix
		// another path's absence needs (DESIGN-DETAILS 9.2.8)
		if slices.ContainsFunc(changedPrefixes, func(covering EvsTokenPath) bool { return len(covering) == 0 }) {
			paths = append(paths, tokenPath)
		}
		return paths
	}
	for length := len(tokenPath); 0 < length; length -= 1 {
		prefix := tokenPath[:length]
		for _, covering := range changedPrefixes {
			if prefix.HasPrefix(covering) {
				paths = append(paths, prefix)
				break
			}
		}
	}
	return paths
}
