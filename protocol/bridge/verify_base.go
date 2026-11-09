// The keyless device role's check of a base entry (§7.9's base row: "keyless device roles check only the signature,
// prev_chain, rows_sha256 and the two versions"). It holds no config key, so it reads no config head; which sidecar
// signs bases, a config writer at S(n-1), is its caller's to know from the rows it holds, and so is the key passed
// here. A full reader runs this too, before its own head check (the root's config_base.go).
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. Package-level functions are safe
// for concurrent use.

package bridge

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// A base's rows are at most this many bytes (§8.8).
const baseRowsMaxByteCount = 4 * 1024 * 1024

// The base does not pass, wrapped with which check failed.
var ErrBaseRefused = errors.New("base refused")

// Checks a base entry and returns its header: entry's kind; its Signed, of type SIGNED_PROJECTION_HEADER under purpose
// authority, verifying under signerPublicKey, the Ed25519 identity key of the config writer that signed it; the
// header's network, version and prev_chain equal to the entry's; rows hashing to rows_sha256 at rows_byte_count bytes,
// at most 4 MiB; folded_through below the entry's position; and, after a previous base, config_version and
// folded_through each at least its own, so no base rolls back policy or the fold. previous is nil for base 1.
//
// rows and the entry's body are read as received, never re-marshaled.
func VerifyBaseKeyless(entry *AuthEntry, signerPublicKey []byte, rows []byte, previous *ProjectionHeader) (*ProjectionHeader, error) {
	rowsSha256 := sha256.Sum256(rows)
	return VerifyBaseKeylessDigest(entry, signerPublicKey, rowsSha256[:], int64(len(rows)), previous)
}

// VerifyBaseKeyless's checks with the rows already hashed: their SHA-256 and their length in bytes. A keyless device
// role streams rows of up to 4 MiB to its store, hashing as they pass, so it never holds them whole (§18.4, §18.6),
// and then checks the base here, by the same rule as every other reader.
func VerifyBaseKeylessDigest(entry *AuthEntry, signerPublicKey []byte, rowsSha256 []byte, rowsByteCount int64, previous *ProjectionHeader) (*ProjectionHeader, error) {
	if entry == nil {
		return nil, fmt.Errorf("%w: no entry", ErrBaseRefused)
	}
	if entry.GetKind() != AuthEntryKindBase {
		return nil, fmt.Errorf("%w: kind %d", ErrBaseRefused, entry.GetKind())
	}
	signed := &Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBaseRefused, err)
	}
	if err := VerifySigned(signed, SignedPurposeAuthority, SignedType_SIGNED_PROJECTION_HEADER, SignedKeyAlgEd25519, signerPublicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBaseRefused, err)
	}
	header := &ProjectionHeader{}
	if err := proto.Unmarshal(signed.GetBody(), header); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBaseRefused, err)
	}
	switch {
	case !bytes.Equal(header.GetNetworkId(), entry.GetNetworkId()):
		return nil, fmt.Errorf("%w: another network's header", ErrBaseRefused)
	case header.GetVersion() != entry.GetN():
		return nil, fmt.Errorf("%w: version %d at position %d", ErrBaseRefused, header.GetVersion(), entry.GetN())
	case !bytes.Equal(header.GetPrevChain(), entry.GetPrevChain()):
		return nil, fmt.Errorf("%w: prev_chain is not the entry's", ErrBaseRefused)
	case entry.GetN() <= header.GetFoldedThrough():
		return nil, fmt.Errorf("%w: folded_through %d at position %d", ErrBaseRefused, header.GetFoldedThrough(), entry.GetN())
	case !bytes.Equal(header.GetRowsSha256(), rowsSha256):
		return nil, fmt.Errorf("%w: rows do not hash to rows_sha256", ErrBaseRefused)
	case rowsByteCount != int64(header.GetRowsByteCount()) || baseRowsMaxByteCount < rowsByteCount:
		return nil, fmt.Errorf("%w: rows of %d bytes", ErrBaseRefused, rowsByteCount)
	}
	if previous != nil {
		switch {
		case header.GetConfigVersion() < previous.GetConfigVersion():
			return nil, fmt.Errorf("%w: config_version %d below the previous base's %d", ErrBaseRefused, header.GetConfigVersion(), previous.GetConfigVersion())
		case header.GetFoldedThrough() < previous.GetFoldedThrough():
			return nil, fmt.Errorf("%w: folded_through %d below the previous base's %d", ErrBaseRefused, header.GetFoldedThrough(), previous.GetFoldedThrough())
		}
	}
	return header, nil
}
