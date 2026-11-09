// A ref's hash chain (§11.8): C_0 = SHA-256("UR evs 1.0 ref" || repo_id || ref_id), and C_v = SHA-256(C_(v-1) ||
// push_id_v || statement_sha256_v), where statement_sha256_v is the SHA-256 of version v's Signed EvsPush bytes as
// received, never a re-marshal (§22.6). A reader pins (ref, v, C_v) and refuses any head that does not extend its
// pin, so a server that drops, reorders or swaps a statement breaks the chain.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// C_0's prefix.
const evsChainLabel = "UR evs 1.0 ref"

// A chain value or statement hash of the wrong width.
var ErrEvsChainInvalid = errors.New("evs chain invalid")

// C_0 of refId in repoId, before its first version.
func EvsChainStart(repoId Id, refId Id) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte(evsChainLabel))
	digest.Write(repoId.Bytes())
	digest.Write(refId.Bytes())
	return [sha256.Size]byte(digest.Sum(nil))
}

// SHA-256 of a Signed EvsPush's bytes as received: what C_v, the window entry's prefix and a refusal record's prefix
// hash.
func EvsStatementSha256(statementBytes []byte) [sha256.Size]byte {
	return sha256.Sum256(statementBytes)
}

// C_v from C_(v-1), the push id committed at v and its statement's hash.
func EvsChainNext(previous [sha256.Size]byte, pushId Id, statementSha256 [sha256.Size]byte) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write(previous[:])
	digest.Write(pushId.Bytes())
	digest.Write(statementSha256[:])
	return [sha256.Size]byte(digest.Sum(nil))
}

// A chain value or statement hash as a protobuf field holds it: exactly 32 bytes.
func EvsChainFromBytes(chainBytes []byte) ([sha256.Size]byte, error) {
	if len(chainBytes) != sha256.Size {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %d bytes", ErrEvsChainInvalid, len(chainBytes))
	}
	return [sha256.Size]byte(chainBytes), nil
}
