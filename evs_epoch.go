//go:build !ios_extension

// Path epochs as evs and its clients both judge them (§11.6's due, map and commit rows; D-EVS-12; DESIGN-DETAILS
// 9.2.2, 9.2.3 and 9.2.6): one function for each rule both sides apply, so the two never differ.
//
//	classify  a push whose generation pin crosses a REMOVE generation records an immediate due unless the newest
//	          verified state shows the repo's holders last shrank at or below the auth pin of the generation it
//	          crosses from: then only expiries passed, and the due is batched. A compromise retirement shrinks though
//	          no holder leaves (§7.9), so every shrink reads as immediate (question evs1-m2-16-due-classification,
//	          option 1). A party that cannot read one of the two, the state's shrink or the generation's pin, reads
//	          the crossing as immediate.
//	blocks    an immediate due blocks creation only on shared and owned refs of general, config and mailcfg repos,
//	          whose names carry meaning; deposit and erasure refs hold random ids under no path key and stay at
//	          epoch 1, and the other kinds name entries by id or sequence (plan-EVS1-epoch-kinds #1 and #2)
//	map hash  path_map_sha256 is SHA-256 over a map's parts' signed bytes in part order (9.2.2's map row), which
//	          the copy checks as it reads the parts (9.2.6) and a mapper computes as it builds them
//
// On every leg. Package-level functions are safe for concurrent use; an EvsPathMapHasher is not.

package sidecar

import (
	"crypto/sha256"
	"hash"

	"github.com/urnetwork/sidecar/protocol"
)

// DESIGN-DETAILS 9.2.2's EvsReadPath: a read names a path in at most 8 epochs, one token path an epoch, which evs
// matches by the epoch field.
const EvsReadPathMaxEpochCount = 8

// Whether a crossing of a REMOVE generation is immediate: a shrink of the repo's holders, at holdersShrunkAt in
// the newest verified state, after fromAuthVersion, the auth pin of the generation the crossing starts from. Batched
// otherwise. See the file header.
func EvsClassifyPathEpochDue(holdersShrunkAt uint64, fromAuthVersion uint64) bool {
	return fromAuthVersion < holdersShrunkAt
}

// Whether an immediate due blocks creation on a ref of refKind in a repo of repoKind: a shared or owned ref of a
// general, config or mailcfg repo. See the file header.
func EvsRefBlocksCreation(repoKind protocol.RepoKind, refKind protocol.EvsRefKind) bool {
	switch repoKind {
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG:
		return refKind == protocol.EvsRefKind_EVS_REF_SHARED || refKind == protocol.EvsRefKind_EVS_REF_OWNED
	}
	return false
}

// path_map_sha256 over a map's parts as they are read or built, one part at a time in part order, so neither the copy
// nor a mapper holds more than one part to hash a map.
type EvsPathMapHasher struct {
	hash      hash.Hash
	partCount int
}

// A hasher before its first part.
func NewEvsPathMapHasher() *EvsPathMapHasher {
	return &EvsPathMapHasher{hash: sha256.New()}
}

// Adds the next part's signed bytes, as stored or sent.
func (self *EvsPathMapHasher) Add(partBytes []byte) {
	self.hash.Write(partBytes)
	self.partCount += 1
}

// How many parts it holds.
func (self *EvsPathMapHasher) PartCount() int {
	return self.partCount
}

// The map's path_map_sha256 over the parts added so far.
func (self *EvsPathMapHasher) Sum() []byte {
	return self.hash.Sum(nil)
}

// path_map_sha256 of a map whose parts' signed bytes are parts, in part order.
func EvsPathMapSha256(parts [][]byte) []byte {
	hasher := NewEvsPathMapHasher()
	for _, partBytes := range parts {
		hasher.Add(partBytes)
	}
	return hasher.Sum()
}
