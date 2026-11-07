// VByte and the reader every index decoder shares (protocol/INDEX-FORMAT.md). Index files are read by devices that did
// not write them, so a decoder here refuses everything but the one canonical encoding, which is what makes
// re-encoding reproduce a file's bytes (FI-22). Nothing is compressed, so no decoder needs more memory than its input.

package sidecar

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// A 64-bit value's longest encoding.
const indexVByteMaxByteCount = 10

// Every refusal wraps this, and a reader answers each by dropping the file and raising index_malformed.
var errIndexMalformed = errors.New("index file malformed")

// A refusal, saying what broke the format.
func indexMalformed(reason string) error {
	return fmt.Errorf("%w: %s", errIndexMalformed, reason)
}

// Appends value, least significant group first, the format's LEB128.
func indexAppendVByte(dst []byte, value uint64) []byte {
	return binary.AppendUvarint(dst, value)
}

// The bytes value encodes to.
func indexVByteLength(value uint64) int {
	return len(indexAppendVByte(make([]byte, 0, indexVByteMaxByteCount), value))
}

// Reads one value from src's start, taking only the minimal encoding of a value that fits 64 bits, where
// binary.Uvarint also takes non-minimal ones.
func indexReadVByte(src []byte) (value uint64, byteCount int, ok bool) {
	for index := 0; index < len(src) && index < indexVByteMaxByteCount; index += 1 {
		b := src[index]
		// The tenth byte holds the 64th bit and nothing else.
		if index == indexVByteMaxByteCount-1 && 1 < b {
			return 0, 0, false
		}
		value |= uint64(b&0x7F) << (7 * index)
		if b&0x80 == 0 {
			if b == 0 && 0 < index {
				return 0, 0, false
			}
			return value, index + 1, true
		}
	}
	return 0, 0, false
}

// Reads one encoded value front to back. The first refusal sticks and every later read returns zero values, so a
// decoder reads straight through and asks once, and nothing past a refusal can index out of range. Not safe for
// concurrent use.
type indexDecoder struct {
	src []byte
	err error
}

// Records why src is not canonical, keeping the first reason.
func (self *indexDecoder) refuse(reason string) {
	if self.err == nil {
		self.err = indexMalformed(reason)
	}
}

// Bytes not yet read.
func (self *indexDecoder) remaining() int {
	return len(self.src)
}

// One minimal VByte.
func (self *indexDecoder) vbyte() uint64 {
	if self.err != nil {
		return 0
	}
	value, byteCount, ok := indexReadVByte(self.src)
	if !ok {
		self.refuse("not a minimal vbyte")
		return 0
	}
	self.src = self.src[byteCount:]
	return value
}

// The next byteCount bytes, a view of src, checked against what is left before anything is sized by it.
func (self *indexDecoder) take(byteCount uint64) []byte {
	if self.err != nil {
		return nil
	}
	if uint64(len(self.src)) < byteCount {
		self.refuse("past the end of its input")
		return nil
	}
	taken := self.src[:byteCount]
	self.src = self.src[byteCount:]
	return taken
}

// One fixed-width byte.
func (self *indexDecoder) oneByte() byte {
	taken := self.take(1)
	if taken == nil {
		return 0
	}
	return taken[0]
}
