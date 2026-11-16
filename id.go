//go:build !sidecar_http

// The root's identifier on every leg but the page Worker's: operator-core's Id (owner decision 251), which
// is server.Id moved, connect.Id's [16]byte layout with its parsing, formatting and comparison delegating
// to connect. sidecar keeps its own generator, NewId on crypto/rand, and its own strict ParseId and
// IdFromBytes, which answer the alias. connect-facing files still convert at their boundary,
// connect.Id(id) and Id(connectId), plain conversions between two [16]byte types.
//
// The alias brings connect into every leg that links this file, the iOS extension's included (§4.4). The
// sidecar_http leg, the page Worker's sdk.wasm, links neither connect nor operator-core (QD-856): there
// id_http.go declares Id as its own [16]byte type with the same methods and the same encodings, and with
// this file's generator and parsing, which TestIdTwinKeepsTheSharedSource holds equal to these, function
// by function.

package sidecar

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// connect.Id's layout, a ULID: a 48-bit big-endian millisecond timestamp, then 80 bits of entropy,
// so ids sort by creation time. The timestamp is the clock of whatever minted the id: a dependable
// order within one source, and no global clock across sources. Comparable, so it keys maps. Its
// methods are operator-core's: Bytes, Less and LessThan, Cmp, String, the JSON and database/sql codecs
// and Hash.
type Id = operator.Id

// The bytes one id draws: 2 and 8 for a new millisecond's entropy, 4 for an increment within it.
const idDrawByteCount = 14

// operator-core's, so a refusal here and one of Id's JSON decode match the same errors.Is.
var errInvalidId = operator.ErrInvalidId

// Strictly increasing ids: the timestamp never falls, and an id minted in the same millisecond, or
// after the wall clock stepped back, adds a random increment to the one before it. Safe for
// concurrent use.
type idGenerator struct {
	stateLock sync.Mutex
	ms        uint64
	// the current millisecond's entropy, as hi:lo (16:64 bits)
	entropyHi uint16
	entropyLo uint64
}

// One per process, so the strict order holds across everything that process mints.
var processIdGenerator idGenerator

// A new id above every earlier one from this process. Unlike connect.NewId, which runs per packet,
// this one is off the hot path and draws from crypto/rand, since ids here name repos and sidecars
// and may be seen by others.
func NewId() Id {
	var draw [idDrawByteCount]byte
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(draw[:])
	return processIdGenerator.next(uint64(time.Now().UnixMilli()), draw)
}

// The id after the last one, with wallMs as the clock and draw as its entropy.
func (self *idGenerator) next(wallMs uint64, draw [idDrawByteCount]byte) Id {
	var id Id
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.ms < wallMs {
			self.ms = wallMs
			self.entropyHi = binary.BigEndian.Uint16(draw[0:2])
			self.entropyLo = binary.BigEndian.Uint64(draw[2:10])
		} else {
			entropyLo := self.entropyLo + 1 + uint64(binary.BigEndian.Uint32(draw[10:14]))
			if entropyLo < self.entropyLo {
				self.entropyHi += 1
				if self.entropyHi == 0 {
					// the entropy wrapped: carry into the timestamp, as in one 128-bit integer
					self.ms += 1
				}
			}
			self.entropyLo = entropyLo
		}
		id[0] = byte(self.ms >> 40)
		id[1] = byte(self.ms >> 32)
		id[2] = byte(self.ms >> 24)
		id[3] = byte(self.ms >> 16)
		id[4] = byte(self.ms >> 8)
		id[5] = byte(self.ms)
		binary.BigEndian.PutUint16(id[6:8], self.entropyHi)
		binary.BigEndian.PutUint64(id[8:16], self.entropyLo)
	}()
	return id
}

// Exactly 16 bytes, copied, or an error.
func IdFromBytes(idBytes []byte) (Id, error) {
	if len(idBytes) != len(Id{}) {
		return Id{}, errInvalidId
	}
	return Id(idBytes), nil
}

// Takes connect.ParseId's two forms, with dashes (36 characters) or without (32). A separator other
// than a dash is refused, where connect drops it unread. The error never repeats the input, which
// may not be an id at all (I-13).
func ParseId(idStr string) (Id, error) {
	switch len(idStr) {
	case 36:
		if idStr[8] != '-' || idStr[13] != '-' || idStr[18] != '-' || idStr[23] != '-' {
			return Id{}, errInvalidId
		}
		idStr = idStr[0:8] + idStr[9:13] + idStr[14:18] + idStr[19:23] + idStr[24:]
	case 32:
	default:
		return Id{}, errInvalidId
	}
	var id Id
	if _, err := hex.Decode(id[:], []byte(idStr)); err != nil {
		return Id{}, errInvalidId
	}
	return id, nil
}
