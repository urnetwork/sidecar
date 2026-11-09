// A shard's pad (§11.14's pad row; protocol/INDEX-FORMAT.md's Shards). A shard's dictionary and lists are the only
// structures shared across documents, so its length would show which trigrams a probe document shares with others;
// the pad hides that, even at a padding boundary, by a count of zero bytes drawn from K_index_g and the shard's own
// hash, below Padmé's step at its length. It is the only thing hiding shared trigrams, so a shard is never written
// without it. A rewrite in place (a CLOSURE, a DROP's rewrite, a roll-up's step 4) pads with zeros to the replaced
// length instead, keeping the replaced header's pad_generation, and no reader recomputes either pad.

package sidecar

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

// What the pad's HMAC reads first, its three ASCII bytes.
const indexPadLabel = "pad"

// K_index_g, which draws the pads of shards whose header names g. Immutable once made, so safe for concurrent use.
type indexPadKey struct {
	generation uint64
	key        []byte
}

// K_index_g of repoKey's generation: HKDF-SHA256(RK_g, salt repo_id, info "UR evs 1.0 index" || u64be(g)), no further
// context (plan-SEARCH-index-format-bytes#7). DeriveKey hooks it as K_index, and refuses a key that holds no RK_g.
func indexNewPadKey(repoKey *EvsRepoKey) (*indexPadKey, error) {
	key, err := repoKey.DeriveKey(EvsKeyPurposeIndex, nil)
	if err != nil {
		return nil, err
	}
	return &indexPadKey{generation: repoKey.Generation(), key: key}, nil
}

// Padmé's step at length: 2^(E - S), with E = ⌊log2 L⌋ and S = ⌊log2 E⌋ + 1, the granularity EvsPadme rounds to
// there, 16 KiB near a shard's cap. Lengths below 4 are their own.
func indexPadStep(length int) int {
	if length < 4 {
		return 1
	}
	exponent := bits.Len64(uint64(length)) - 1
	return 1 << (exponent - bits.Len64(uint64(exponent)))
}

// The zero bytes after a shard of these bytes: u32be(HMAC-SHA256(K_index_g, "pad" || SHA-256(unpadded))[0:4]) mod
// step(len(unpadded)). Below a step, so a shard within its 1,032,192 B stays within 1 MiB padded.
func (self *indexPadKey) padByteCount(unpadded []byte) int {
	digest := sha256.Sum256(unpadded)
	mac := hmac.New(sha256.New, self.key)
	mac.Write([]byte(indexPadLabel))
	mac.Write(digest[:])
	return int(binary.BigEndian.Uint32(mac.Sum(nil)[:4]) % uint32(indexPadStep(len(unpadded))))
}

// unpadded with zero bytes to exactly byteCount, the replaced version's length, for a rewrite in place. Longer than
// that, it is refused, so a rewrite that cannot fit fails closed rather than change the file's size.
func indexPadToExactly(unpadded []byte, byteCount int) ([]byte, error) {
	if byteCount < len(unpadded) {
		return nil, indexMalformed("a rewrite longer than what it replaces")
	}
	if indexShardPaddedMaxByteCount < byteCount {
		return nil, indexMalformed("a rewrite past an index file's cap")
	}
	return append(unpadded, make([]byte, byteCount-len(unpadded))...), nil
}
