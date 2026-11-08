// The sealed values of §11.6: an entry version's sealed_fields, which open to EvsSealedFields (file_id, mode, git oid,
// size), and a push's sealed metadata, which opens to EvsSealedMetadata (the writer's group head, provenance, its git
// commits and an import). Each is 24 B nonce | ciphertext | 16 B tag, XChaCha20-Poly1305 under manifest_g, g the
// push's generation, AAD "UR evs 1.0 fields" or "UR evs 1.0 metadata" || repo_id || u64be(g) (plan-EVS1-format-bytes#9);
// on a deposit ref under the deposit's K_dep, which takes manifest's place (#5). evs stores them and never opens one.
//
// Also the AEAD every evs seal shares: XChaCha20-Poly1305 with a random 24-byte nonce drawn per seal, so writers share
// no counter and nothing is encrypted deterministically (§11.6's nonces row).
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The labels the sealed values' AADs start with.
const (
	evsFieldsAadLabel   = "UR evs 1.0 fields"
	evsMetadataAadLabel = "UR evs 1.0 metadata"
)

// What a seal adds to its plaintext: the nonce in front and the tag behind.
const evsSealOverhead = chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead

var (
	// A seal that does not open, or bytes that break a sealed layout. Tampering lands here, before any plaintext is
	// returned.
	ErrEvsSealInvalid = errors.New("evs seal invalid")
	// A format-2 construct, which format-1 code refuses as FORMAT_UNSUPPORTED {needs_format: 2}, never as tampering,
	// a fork or a missing segment (§11.6's kinds row, owner decision 163).
	ErrEvsFormatUnsupported = errors.New("evs format 2 construct")
)

// label || repo_id || u64be(g), the AAD of every sealed value, header and key block.
func evsLabeledAad(label string, repoId Id, generation uint64) []byte {
	aad := make([]byte, 0, len(label)+16+8)
	aad = append(aad, label...)
	aad = append(aad, repoId.Bytes()...)
	return binary.BigEndian.AppendUint64(aad, generation)
}

// nonce || XChaCha20-Poly1305(key, nonce, plaintext, aad) || tag under a fresh random nonce.
func evsSeal(key []byte, plaintext []byte, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%w: a key of %d bytes", ErrEvsKeyMissing, len(key))
	}
	sealed := make([]byte, chacha20poly1305.NonceSizeX, evsSealOverhead+len(plaintext))
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(sealed)
	return aead.Seal(sealed, sealed[:chacha20poly1305.NonceSizeX], plaintext, aad), nil
}

// The plaintext of nonce || ciphertext || tag, or ErrEvsSealInvalid.
func evsOpen(key []byte, sealed []byte, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%w: a key of %d bytes", ErrEvsKeyMissing, len(key))
	}
	if len(sealed) < evsSealOverhead {
		return nil, fmt.Errorf("%w: a seal of %d bytes", ErrEvsSealInvalid, len(sealed))
	}
	plaintext, err := aead.Open(nil, sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: the seal does not open", ErrEvsSealInvalid)
	}
	return plaintext, nil
}

// The git modes a file's sealed fields may carry: the git codec's, but a directory, which is an entry of its own kind.
func evsFileModeValid(mode uint32) bool {
	switch mode {
	case EvsGitModeFile, EvsGitModeFileGroupWritable, EvsGitModeExecutable, EvsGitModeSymlink, EvsGitModeGitlink:
		return true
	}
	return false
}

// What format 1 holds a file's sealed fields to: a 16-byte file_id, a file's git mode, a SHA-1 oid (v0 is SHA-1 only,
// plan-EVS1-format-bytes#4), and no content_sha256, which only format 2's versionless files carry.
func checkEvsSealedFields(fields *protocol.EvsSealedFields) error {
	if len(fields.GetContentSha256()) != 0 {
		return fmt.Errorf("%w: content_sha256 in a file's sealed fields", ErrEvsFormatUnsupported)
	}
	if len(fields.GetFileId()) != 16 {
		return fmt.Errorf("%w: a file_id of %d bytes", ErrEvsSealInvalid, len(fields.GetFileId()))
	}
	if !evsFileModeValid(fields.GetMode()) {
		return fmt.Errorf("%w: mode %o is no file's", ErrEvsSealInvalid, fields.GetMode())
	}
	if fields.GetOidKind() != protocol.EvsOidKind_EVS_OID_SHA1 || len(fields.GetGitOid()) != len(EvsGitOid{}) {
		return fmt.Errorf("%w: an oid that is not SHA-1", ErrEvsSealInvalid)
	}
	return nil
}

// A file's sealed_fields under manifestKey, which is manifest_g of the push's generation or a deposit's K_dep.
func EvsSealFields(manifestKey *EvsManifestKey, fields *protocol.EvsSealedFields) ([]byte, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if err := checkEvsSealedFields(fields); err != nil {
		return nil, err
	}
	plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("evs: sealed fields: %w", err)
	}
	return evsSeal(manifestKey.key, plaintext, evsLabeledAad(evsFieldsAadLabel, manifestKey.repoId, manifestKey.generation))
}

// A file's sealed fields opened and held to format 1: ErrEvsSealInvalid for a seal that does not open or a value no
// file has, ErrEvsFormatUnsupported for format 2's content_sha256.
func EvsOpenFields(manifestKey *EvsManifestKey, sealed []byte) (*protocol.EvsSealedFields, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	plaintext, err := evsOpen(manifestKey.key, sealed, evsLabeledAad(evsFieldsAadLabel, manifestKey.repoId, manifestKey.generation))
	if err != nil {
		return nil, err
	}
	fields := &protocol.EvsSealedFields{}
	if err := proto.Unmarshal(plaintext, fields); err != nil {
		return nil, fmt.Errorf("%w: sealed fields that do not parse", ErrEvsSealInvalid)
	}
	if err := checkEvsSealedFields(fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// A push's sealed metadata under manifestKey: manifest_g of its generation, or the K_dep of a deposit push's first
// entry.
func EvsSealMetadata(manifestKey *EvsManifestKey, metadata *protocol.EvsSealedMetadata) ([]byte, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("evs: sealed metadata: %w", err)
	}
	return evsSeal(manifestKey.key, plaintext, evsLabeledAad(evsMetadataAadLabel, manifestKey.repoId, manifestKey.generation))
}

// A push's sealed metadata opened. Format 2's tainted bit is kept as read, for format 1 ignores it rather than refuse.
func EvsOpenMetadata(manifestKey *EvsManifestKey, sealed []byte) (*protocol.EvsSealedMetadata, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	plaintext, err := evsOpen(manifestKey.key, sealed, evsLabeledAad(evsMetadataAadLabel, manifestKey.repoId, manifestKey.generation))
	if err != nil {
		return nil, err
	}
	metadata := &protocol.EvsSealedMetadata{}
	if err := proto.Unmarshal(plaintext, metadata); err != nil {
		return nil, fmt.Errorf("%w: sealed metadata that does not parse", ErrEvsSealInvalid)
	}
	return metadata, nil
}
