// A push's paths digest (§11.8's digest row): a 64-bit Bloom filter with k = 2 in each window entry, over every
// token path the push changes and, when its change list is not inline, each covering prefix in changed_prefixes. A
// path's indexes are u32(h[0:4]) mod 64 and u32(h[4:8]) mod 64, h = SHA-256("UR evs digest" || token path), and the
// digest is the u64 whose bit i is index i (plan-EVS1-format-bytes#7).
//
// The digest only ever sends evs to a statement's change list: a match is a maybe, which the change list settles,
// and a miss on a path and on every prefix holding it proves the push changed neither, since each changed path set
// its own two bits. A wrong digest from evs can only cost a reader a statement it then checks (§11.8's trust row).
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
)

// What every digest input starts with.
const evsDigestLabel = "UR evs digest"

// The filter, bit i set for index i.
type EvsPathsDigest uint64

// The digest of a push: each changed path's two bits, and each covering prefix's when coveringPrefixes is not nil,
// that is when the change list is not inline.
func NewEvsPathsDigest(changedPaths []EvsTokenPath, coveringPrefixes []EvsTokenPath) EvsPathsDigest {
	digest := EvsPathsDigest(0)
	for _, tokenPath := range changedPaths {
		digest = digest.With(tokenPath)
	}
	for _, tokenPath := range coveringPrefixes {
		digest = digest.With(tokenPath)
	}
	return digest
}

// tokenPath's two indexes, 0 to 63.
func evsDigestIndexes(tokenPath EvsTokenPath) (uint32, uint32) {
	digest := sha256.New()
	digest.Write([]byte(evsDigestLabel))
	digest.Write(tokenPath.Bytes())
	sum := digest.Sum(nil)
	return binary.BigEndian.Uint32(sum[0:4]) % 64, binary.BigEndian.Uint32(sum[4:8]) % 64
}

// The digest with tokenPath's bits set.
func (self EvsPathsDigest) With(tokenPath EvsTokenPath) EvsPathsDigest {
	first, second := evsDigestIndexes(tokenPath)
	return self | EvsPathsDigest(1)<<first | EvsPathsDigest(1)<<second
}

// Whether both of tokenPath's bits are set: maybe changed, never surely.
func (self EvsPathsDigest) Matches(tokenPath EvsTokenPath) bool {
	first, second := evsDigestIndexes(tokenPath)
	want := EvsPathsDigest(1)<<first | EvsPathsDigest(1)<<second
	return self&want == want
}

// What evs and readers query (§11.8): whether tokenPath or any prefix holding it, down to its first component,
// matches. False proves the push changed neither tokenPath nor a directory holding it.
func (self EvsPathsDigest) MayChange(tokenPath EvsTokenPath) bool {
	for length := len(tokenPath); 0 < length; length -= 1 {
		if self.Matches(tokenPath[:length]) {
			return true
		}
	}
	return false
}
