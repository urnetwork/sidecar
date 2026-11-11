//go:build !sidecar_http && !ios_extension

// §9.9's share header (D-SOCK-16; SOCK-M5-15): the fixed-width bytes at the head of a share/ stream, the only framing
// a share's stream has. Integers are big endian:
//
//	get     getter -> sharer   version[1] = 1 || secret[32] || get_id[16] || u64be offset           57 B
//	status  sharer -> getter   status[1]: 0 ok, 1 spent, 2 changed; ok adds u64be size || sha256[32], then the
//	                           file's bytes [offset, size)
//	done    getter -> sharer   done[1] = 1, once SHA-256 over [0, size) matched and <out> is in place
//
// A refusal that says nothing, a wrong secret, a Remove or the expiry, is a stream reset with no status, so a getter
// holding a wrong link learns only that the stream reset (§9.9's first match). The widths are the format's layout and
// the secret's 256 bits, not limits, so they stay constants beside it; the format is unfrozen until M5's exit.
//
// On every connect leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

// The header's format values (§9.9).
const (
	socketShareVersion = 1
	// The share's secret, 256 bits.
	socketShareSecretByteCount = 32
	// A get's id, random, as an Id.
	socketShareGetIdByteCount = 16
	// version, secret, get_id and offset.
	socketShareGetByteCount = 1 + socketShareSecretByteCount + socketShareGetIdByteCount + 8
	// The statuses.
	socketShareStatusOk      = 0
	socketShareStatusSpent   = 1
	socketShareStatusChanged = 2
	// ok's status, size and SHA-256.
	socketShareOkByteCount = 1 + 8 + sha256.Size
	// done's one byte.
	socketShareDone = 1
)

var (
	// A get header that is not one: another length, another version, or an offset past what a file can hold.
	errSocketShareHeader = errors.New("not a share get header")
	// A sharer's answer that is not one.
	errSocketShareAnswer = errors.New("not a share answer")
)

// What a getter sends first.
type socketShareGet struct {
	// The share's secret, from the link's fragment. Never logged.
	secret []byte
	getId  Id
	// Where the getter's <out>.part ends.
	offset uint64
}

// The header's 57 bytes.
func (self *socketShareGet) encode() []byte {
	encoded := make([]byte, 0, socketShareGetByteCount)
	encoded = append(encoded, socketShareVersion)
	encoded = append(encoded, self.secret...)
	encoded = append(encoded, self.getId.Bytes()...)
	return binary.BigEndian.AppendUint64(encoded, self.offset)
}

// A getter's header, refusing anything but exactly 57 bytes of version 1 whose offset an int64 holds.
func decodeSocketShareGet(header []byte) (*socketShareGet, error) {
	if len(header) != socketShareGetByteCount || header[0] != socketShareVersion {
		return nil, errSocketShareHeader
	}
	secretEnd := 1 + socketShareSecretByteCount
	getIdEnd := secretEnd + socketShareGetIdByteCount
	getId, err := IdFromBytes(header[secretEnd:getIdEnd])
	if err != nil {
		return nil, errSocketShareHeader
	}
	offset := binary.BigEndian.Uint64(header[getIdEnd:])
	if math.MaxInt64 < offset {
		return nil, errSocketShareHeader
	}
	return &socketShareGet{
		secret: append([]byte(nil), header[1:secretEnd]...),
		getId:  getId,
		offset: offset,
	}, nil
}

// The sharer's ok: what the getter checks the whole file against.
type socketShareOk struct {
	size   uint64
	sha256 []byte
}

// ok's 41 bytes.
func (self *socketShareOk) encode() []byte {
	encoded := make([]byte, 0, socketShareOkByteCount)
	encoded = append(encoded, socketShareStatusOk)
	encoded = binary.BigEndian.AppendUint64(encoded, self.size)
	return append(encoded, self.sha256...)
}

// ok's size and hash, after its status byte.
func decodeSocketShareOk(rest []byte) (*socketShareOk, error) {
	if len(rest) != socketShareOkByteCount-1 {
		return nil, errSocketShareAnswer
	}
	size := binary.BigEndian.Uint64(rest)
	if math.MaxInt64 < size {
		return nil, errSocketShareAnswer
	}
	return &socketShareOk{size: size, sha256: append([]byte(nil), rest[8:]...)}, nil
}
