// The root's own identifier, on every leg. connect.Id has the same [16]byte layout, but naming it
// links gVisor into the importer (§4.4), so every-leg files use this type and connect-facing files
// convert at their boundary: connect.Id(id) and Id(connectId), plain conversions between two
// [16]byte types. The methods read, sort and encode as connect/id.go's do, so an id means the same
// on both sides of that boundary.

package sidecar

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// connect.Id's layout, a ULID: a 48-bit big-endian millisecond timestamp, then 80 bits of entropy,
// so ids sort by creation time. The timestamp is the clock of whatever minted the id: a dependable
// order within one source, and no global clock across sources. Comparable, so it keys maps.
type Id [16]byte

// The bytes one id draws: 2 and 8 for a new millisecond's entropy, 4 for an increment within it.
const idDrawByteCount = 14

var errInvalidId = errors.New("invalid id")

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

// A copy, since the receiver is one, so a write to it leaves the id alone.
func (self Id) Bytes() []byte {
	return self[0:16]
}

// Whether this id sorts before b, by creation time within one source.
func (self Id) LessThan(b Id) bool {
	return self.Cmp(b) < 0
}

// -1, 0 or 1, by byte, as bytes.Compare gives.
func (self Id) Cmp(b Id) int {
	return bytes.Compare(self[:], b[:])
}

// Lowercase hex in the 8-4-4-4-12 form, connect's and the database's uuid.
func (self Id) String() string {
	var encoded [36]byte
	hex.Encode(encoded[0:8], self[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], self[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], self[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], self[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], self[10:16])
	return string(encoded[:])
}

// A value receiver, so an Id field has one encoding whether its struct is marshaled by value or by
// pointer: a pointer receiver leaves a non-addressable Id to encoding/json's byte array form.
func (self Id) MarshalJSON() ([]byte, error) {
	return []byte(`"` + self.String() + `"`), nil
}

// Takes a quoted id and refuses everything else, JSON null included, as connect does. That covers
// what is sent, not what is left out: a field absent from the JSON never reaches this, so it keeps its
// value, the zero id in a fresh struct, with no error. A reader of a required id compares it to Id{}.
func (self *Id) UnmarshalJSON(src []byte) error {
	if len(src) != 38 || src[0] != '"' || src[37] != '"' {
		return errInvalidId
	}
	id, err := ParseId(string(src[1:37]))
	if err != nil {
		return err
	}
	*self = id
	return nil
}
