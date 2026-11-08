// Sealed names (§11.7's name row): a directory's row for each child holds the child's token, its kind and its name
// sealed alone: the name's raw bytes, then 0x80, then zeros to the next multiple of 64 B, under a random 24 B nonce
// with a 16 B tag. The seal is XChaCha20-Poly1305 under manifest_p, AAD repo_id || u64be(p) || parent token || child
// token, p the path epoch whose tokens the row uses (EVS-FORMAT.md), so a row moved under another directory, to
// another child or into another epoch fails to open. Padding to 64 B steps hides a name's length to its step.
//
// A reader opens each row and checks the name against its token, recomputing the token from the parent's, since
// evs folds directory deltas itself and only the token ties a row to a path. A carried row (EvsName.epoch, a source
// epoch's row a path-epoch copy has not translated yet, §11.6) opens under that epoch's keys and its parent's token in
// that epoch.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.7's name padding.
const (
	evsNamePadByteCount      = 64
	evsNamePadMarker    byte = 0x80
	// a directory's bounds (§11.7's directory row), which 5g checks
	EvsDirectoryMaxChildCount     = 4096
	EvsNameTableMaxBoundByteCount = 448 * 1024
)

// repo_id || u64be(p) || parent || child.
func evsNameAad(repoId Id, epoch uint64, parent EvsToken, child EvsToken) []byte {
	aad := make([]byte, 0, 16+8+2*EvsTokenByteCount)
	aad = append(aad, repoId[:]...)
	aad = binary.BigEndian.AppendUint64(aad, epoch)
	aad = append(aad, parent[:]...)
	return append(aad, child[:]...)
}

// name sealed as child's row under parent, in the epoch manifestKey is of, which must be the epoch of both tokens.
func EvsNameSeal(manifestKey *EvsManifestKey, parent EvsToken, child EvsToken, name []byte) ([]byte, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if manifestKey.deposit {
		return nil, fmt.Errorf("%w: a deposit names no path", ErrEvsKeyMissing)
	}
	if err := checkEvsPathName(name); err != nil {
		return nil, err
	}
	paddedLength := (len(name)/evsNamePadByteCount + 1) * evsNamePadByteCount
	padded := make([]byte, paddedLength)
	copy(padded, name)
	padded[len(name)] = evsNamePadMarker
	return evsSeal(manifestKey.key, padded, evsNameAad(manifestKey.repoId, manifestKey.generation, parent, child))
}

// The name a row's sealed_name holds, checked against child's token under parent: manifestKey and pathKey are the
// epoch's own. ErrEvsSealInvalid for a seal that does not open or a padding §11.7 does not write, ErrEvsTokenInvalid
// for a name whose token is not child's.
func EvsNameOpen(manifestKey *EvsManifestKey, pathKey *EvsPathKey, parent EvsToken, child EvsToken, sealed []byte) ([]byte, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if err := pathKey.checkHeld(); err != nil {
		return nil, err
	}
	if pathKey.epoch != manifestKey.generation || pathKey.repoId != manifestKey.repoId {
		return nil, fmt.Errorf("%w: path and manifest keys of two epochs or repos", ErrEvsKeyMissing)
	}
	paddedLength := len(sealed) - chacha20poly1305.NonceSizeX - chacha20poly1305.Overhead
	if paddedLength <= 0 || paddedLength%evsNamePadByteCount != 0 {
		return nil, fmt.Errorf("%w: a sealed name of %d bytes", ErrEvsSealInvalid, len(sealed))
	}
	padded, err := evsOpen(manifestKey.key, sealed, evsNameAad(manifestKey.repoId, manifestKey.generation, parent, child))
	if err != nil {
		return nil, err
	}
	marker := bytes.LastIndexByte(padded, evsNamePadMarker)
	if marker < 0 || paddedLength-evsNamePadByteCount > marker {
		return nil, fmt.Errorf("%w: no padding marker in the last step", ErrEvsSealInvalid)
	}
	for _, b := range padded[marker+1:] {
		if b != 0 {
			return nil, fmt.Errorf("%w: padding past the marker", ErrEvsSealInvalid)
		}
	}
	name := padded[:marker]
	token, err := EvsPathToken(pathKey, parent, name)
	if err != nil {
		return nil, err
	}
	if token != child {
		return nil, fmt.Errorf("%w: a name whose token is not its row's", ErrEvsTokenInvalid)
	}
	return name, nil
}

// One row of a name table, opened.
type EvsOpenedName struct {
	Token EvsToken
	Kind  protocol.EvsEntryKind
	Name  []byte
	// 0, or the source epoch a carried row keeps
	Epoch uint64
}

// The keys a row of epoch opens under, and the directory's own token in that epoch: its parent in the rows. epoch is
// the table's own path epoch for a row that is not carried.
type EvsNameEpochFunction func(epoch uint64) (*EvsManifestKey, *EvsPathKey, EvsToken, error)

// Every row of a directory's name table opened and checked, a push's delta or a fold's table: each token 16 bytes and
// listed once, each kind a file or a directory, each name opening under its own epoch's keys (tableEpoch's, or a
// carried row's source epoch, which must be older) to the row's token; and each removed token 16 bytes. Any failure
// refuses the whole table, before a name is returned.
func EvsOpenNameTable(table *protocol.EvsNameTable, tableEpoch uint64, epochKeys EvsNameEpochFunction) ([]*EvsOpenedName, error) {
	opened := make([]*EvsOpenedName, 0, len(table.GetNames()))
	seen := map[EvsToken]bool{}
	for _, row := range table.GetNames() {
		token, err := EvsTokenFromBytes(row.GetToken())
		if err != nil {
			return nil, err
		}
		if seen[token] {
			return nil, fmt.Errorf("%w: a token listed twice", ErrEvsSealInvalid)
		}
		seen[token] = true
		kind := protocol.EvsEntryKind(row.GetKind())
		if kind != protocol.EvsEntryKind_EVS_ENTRY_FILE && kind != protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			return nil, fmt.Errorf("%w: entry kind %d", ErrEvsSealInvalid, row.GetKind())
		}
		epoch := tableEpoch
		if row.GetEpoch() != 0 {
			if tableEpoch <= row.GetEpoch() {
				return nil, fmt.Errorf("%w: a carried row of epoch %d in a table of %d", ErrEvsSealInvalid, row.GetEpoch(), tableEpoch)
			}
			epoch = row.GetEpoch()
		}
		manifestKey, pathKey, parent, err := epochKeys(epoch)
		if err != nil {
			return nil, err
		}
		name, err := EvsNameOpen(manifestKey, pathKey, parent, token, row.GetSealedName())
		if err != nil {
			return nil, err
		}
		opened = append(opened, &EvsOpenedName{Token: token, Kind: kind, Name: name, Epoch: row.GetEpoch()})
	}
	for _, removed := range table.GetRemovedTokens() {
		if _, err := EvsTokenFromBytes(removed); err != nil {
			return nil, err
		}
	}
	return opened, nil
}

// What a name table counts against §11.7's 448 KiB: each row as the table encodes it, a carried row at its untagged
// size, so a path-epoch copy never takes a directory past its bound.
func EvsNameTableBoundByteCount(table *protocol.EvsNameTable) int {
	byteCount := 0
	for _, row := range table.GetNames() {
		untagged := &protocol.EvsName{Token: row.GetToken(), Kind: row.GetKind(), SealedName: row.GetSealedName()}
		rowByteCount := proto.Size(untagged)
		byteCount += 1 + evsVarintByteCount(uint64(rowByteCount)) + rowByteCount
	}
	return byteCount
}

// The bytes a protobuf varint of value takes.
func evsVarintByteCount(value uint64) int {
	byteCount := 1
	for 0x80 <= value {
		value >>= 7
		byteCount += 1
	}
	return byteCount
}
