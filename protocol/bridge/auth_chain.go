// The authorization log's chain (§7.9, D-TEAM-19), which everything that reads the log walks, so it lives here, where
// the keyless device role reaches it without linking the root or protocol (§4.4).
//
// These hash bytes as received, never a re-marshal: an entry's body is kept verbatim (§7.9's retain row), and another
// encoding of it is another chain.
//
// No key is created, derived or unwrapped here, so nothing calls testHookSecret. Package-level functions are safe for
// concurrent use.

package bridge

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Starts every chain digest's input (§7.9).
const authChainPrefix = "urnetwork-sidecar-v1/auth-log"

// AuthEntry.kind (§7.9).
const (
	// body: a Signed ProjectionHeader
	AuthEntryKindBase uint32 = 1
	// body: one Signed statement
	AuthEntryKindStatement uint32 = 2
	// body: an ApiTick, unsigned
	AuthEntryKindTick uint32 = 3
)

// A previous digest was not 32 bytes.
var ErrAuthChainSize = errors.New("auth chain digest size refused")

// A_n = SHA-256("urnetwork-sidecar-v1/auth-log" || u64be(n) || A_{n-1} || u32be(kind) || i64be(time_ms) ||
// SHA-256(body)), with no separators (§7.9). body is the entry's as received.
//
// Only the fields' fixed widths keep them apart, so a prevChain of any other size, which a received prev_chain can be,
// refuses rather than hashing into its neighbors. The rest is the formula alone: an entry's kind and position are
// §7.9's apply row's to judge, and a kind it refuses still has a digest, since a refused statement keeps its position.
func AuthChainDigest(n uint64, prevChain []byte, kind uint32, timeMs int64, body []byte) ([sha256.Size]byte, error) {
	if len(prevChain) != sha256.Size {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %d bytes", ErrAuthChainSize, len(prevChain))
	}
	bodySha256 := sha256.Sum256(body)
	chainBytes := make([]byte, 0, len(authChainPrefix)+8+sha256.Size+4+8+sha256.Size)
	chainBytes = append(chainBytes, authChainPrefix...)
	chainBytes = binary.BigEndian.AppendUint64(chainBytes, n)
	chainBytes = append(chainBytes, prevChain...)
	chainBytes = binary.BigEndian.AppendUint32(chainBytes, kind)
	chainBytes = binary.BigEndian.AppendUint64(chainBytes, uint64(timeMs))
	chainBytes = append(chainBytes, bodySha256[:]...)
	return sha256.Sum256(chainBytes), nil
}

// A_0 = SHA-256(Signed Genesis), the bytes as received (§7.9), which invites and pre-approved keys carry as the anchor.
//
// This hashes the Signed, wrapper included, and is no statement id: a genesis is pinned and chained, never checked for
// a repeat, so another wrapper around it misses the anchor and fails closed.
func GenesisChain(signedGenesisBytes []byte) [sha256.Size]byte {
	return sha256.Sum256(signedGenesisBytes)
}
