// The TLS presentation language as RFC 9420 uses it (RFC §2.1): big-endian integers, fixed opaque
// fields, optional<T> behind a presence octet, and vectors behind a variable-size length header.
//
// Both directions take only canonical encodings: a length header in its shortest form, a presence
// octet of 0 or 1, and no byte past the value. A value therefore has exactly one encoding, which is
// what lets hashes and signatures run over a structure encoded again from its fields.
//
// Everything decoded comes from an untrusted peer. A decoder allocates no more than the input it
// holds, and bad input is an error, never a panic. Decoded byte fields are copies, so a value
// outlives the buffer it came from.
//
// An encoder or decoder keeps its first failure and turns every later call into a no-op, so a
// structure's fields read straight through and the failure surfaces once, at the end.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// The largest length a variable-size vector header carries (RFC §2.1.2).
const mlsVectorLengthMaximum = 1024*1024*1024 - 1

var (
	// Input that is not a canonical encoding of the expected structure.
	errMlsMalformed = errors.New("mls: malformed encoding")
	// A well-formed value this subset does not take (§10.4: refused when parsed).
	errMlsRefused = errors.New("mls: outside the subset")
)

// A structure with a TLS encoding.
type mlsEncodable interface {
	encode(encoder *mlsEncoder)
}

// A structure read from a TLS encoding.
type mlsDecodable interface {
	decode(decoder *mlsDecoder)
}

// Returns the value's encoding.
func mlsMarshal(value mlsEncodable) ([]byte, error) {
	encoder := &mlsEncoder{}
	value.encode(encoder)
	return encoder.finish()
}

// Fills the value from exactly the encoded bytes: anything left over is malformed.
func mlsUnmarshal(encoded []byte, value mlsDecodable) error {
	decoder := &mlsDecoder{remaining: encoded}
	value.decode(decoder)
	return decoder.finish()
}

// Appends values to one encoding.
type mlsEncoder struct {
	encoded []byte
	err     error
}

// Keeps the first failure.
func (self *mlsEncoder) fail(err error) {
	if self.err == nil {
		self.err = err
	}
}

// Returns the encoding, or the first failure.
func (self *mlsEncoder) finish() ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	return self.encoded, nil
}

// One octet.
func (self *mlsEncoder) writeUint8(value uint8) {
	self.encoded = append(self.encoded, value)
}

// Big-endian, as every integer here.
func (self *mlsEncoder) writeUint16(value uint16) {
	self.encoded = binary.BigEndian.AppendUint16(self.encoded, value)
}

// Big-endian.
func (self *mlsEncoder) writeUint32(value uint32) {
	self.encoded = binary.BigEndian.AppendUint32(self.encoded, value)
}

// Big-endian.
func (self *mlsEncoder) writeUint64(value uint64) {
	self.encoded = binary.BigEndian.AppendUint64(self.encoded, value)
}

// A fixed-size field, with no length header.
func (self *mlsEncoder) writeFixed(value []byte) {
	self.encoded = append(self.encoded, value...)
}

// A length header in its shortest form (RFC §2.1.2).
func (self *mlsEncoder) writeLength(length int) {
	switch {
	case length < 0 || mlsVectorLengthMaximum < length:
		self.fail(fmt.Errorf("mls: vector length %d does not fit a header", length))
	case length < 64:
		self.writeUint8(uint8(length))
	case length < 16384:
		self.writeUint16(0x4000 | uint16(length))
	default:
		self.writeUint32(0x80000000 | uint32(length))
	}
}

// opaque value<V>.
func (self *mlsEncoder) writeVector(value []byte) {
	self.writeLength(len(value))
	self.writeFixed(value)
}

// A vector of structures: writeElements appends them to a fresh encoder, and their total size
// becomes the header.
func (self *mlsEncoder) writeVectorOf(writeElements func(elements *mlsEncoder)) {
	elements := &mlsEncoder{}
	writeElements(elements)
	if elements.err != nil {
		self.fail(elements.err)
		return
	}
	self.writeVector(elements.encoded)
}

// uint16 values<V>.
func (self *mlsEncoder) writeUint16Vector(values []uint16) {
	self.writeVectorOf(func(elements *mlsEncoder) {
		for _, value := range values {
			elements.writeUint16(value)
		}
	})
}

// optional<T>'s presence octet. The caller writes the value after it when present.
func (self *mlsEncoder) writeOptional(present bool) {
	if present {
		self.writeUint8(1)
	} else {
		self.writeUint8(0)
	}
}

// Reads values from one encoding.
type mlsDecoder struct {
	remaining []byte
	err       error
}

// Keeps the first failure and drops the rest of the input, so later reads return zero values.
func (self *mlsDecoder) fail(err error) {
	if self.err == nil {
		self.err = err
	}
	self.remaining = nil
}

// Returns the first failure, or a failure when input is left over.
func (self *mlsDecoder) finish() error {
	if self.err != nil {
		return self.err
	}
	if 0 < len(self.remaining) {
		return fmt.Errorf("%w: %d bytes past the value", errMlsMalformed, len(self.remaining))
	}
	return nil
}

// The next length bytes, not copied, or nil on a failure.
func (self *mlsDecoder) take(length int) []byte {
	if self.err != nil {
		return nil
	}
	if length < 0 || len(self.remaining) < length {
		self.fail(fmt.Errorf("%w: input ends inside a value", errMlsMalformed))
		return nil
	}
	taken := self.remaining[:length]
	self.remaining = self.remaining[length:]
	return taken
}

// One octet, 0 on a failure, as for every read here.
func (self *mlsDecoder) readUint8() uint8 {
	taken := self.take(1)
	if taken == nil {
		return 0
	}
	return taken[0]
}

// Big-endian, as every integer here.
func (self *mlsDecoder) readUint16() uint16 {
	taken := self.take(2)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint16(taken)
}

// Big-endian.
func (self *mlsDecoder) readUint32() uint32 {
	taken := self.take(4)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint32(taken)
}

// Big-endian.
func (self *mlsDecoder) readUint64() uint64 {
	taken := self.take(8)
	if taken == nil {
		return 0
	}
	return binary.BigEndian.Uint64(taken)
}

// A fixed-size field: a copy of the next length bytes.
func (self *mlsDecoder) readFixed(length int) []byte {
	taken := self.take(length)
	if taken == nil {
		return nil
	}
	return bytes.Clone(taken)
}

// A length header: refuses the 0b11 prefix and any value a shorter form could carry (RFC §2.1.2).
func (self *mlsDecoder) readLength() int {
	if self.err != nil {
		return 0
	}
	if len(self.remaining) == 0 {
		self.fail(fmt.Errorf("%w: input ends before a vector header", errMlsMalformed))
		return 0
	}
	first := self.remaining[0]
	var length int
	switch first >> 6 {
	case 0:
		length = int(self.readUint8())
	case 1:
		length = int(self.readUint16() & 0x3fff)
		if self.err == nil && length < 64 {
			self.fail(fmt.Errorf("%w: length %d in a two-byte header", errMlsMalformed, length))
		}
	case 2:
		length = int(self.readUint32() & 0x3fffffff)
		if self.err == nil && length < 16384 {
			self.fail(fmt.Errorf("%w: length %d in a four-byte header", errMlsMalformed, length))
		}
	default:
		self.fail(fmt.Errorf("%w: vector header prefix 0b11", errMlsMalformed))
	}
	if self.err != nil {
		return 0
	}
	return length
}

// opaque value<V>, as a copy.
func (self *mlsDecoder) readVector() []byte {
	return self.readFixed(self.readLength())
}

// A vector of structures: readElement runs until the vector's bytes are used. An element that
// reads past the vector's end is malformed, and so is one that reads nothing, which would never
// finish.
func (self *mlsDecoder) readVectorOf(readElement func(element *mlsDecoder)) {
	taken := self.take(self.readLength())
	if taken == nil {
		return
	}
	element := &mlsDecoder{remaining: taken}
	for 0 < len(element.remaining) {
		before := len(element.remaining)
		readElement(element)
		if element.err != nil {
			self.fail(element.err)
			return
		}
		if len(element.remaining) == before {
			self.fail(fmt.Errorf("%w: empty vector element", errMlsMalformed))
			return
		}
	}
}

// uint16 values<V>.
func (self *mlsDecoder) readUint16Vector() []uint16 {
	var values []uint16
	self.readVectorOf(func(element *mlsDecoder) {
		values = append(values, element.readUint16())
	})
	return values
}

// optional<T>'s presence octet: anything but 0 or 1 is malformed (RFC §2.1.1). The caller reads the
// value after it when present.
func (self *mlsDecoder) readOptional() bool {
	presence := self.readUint8()
	if 1 < presence {
		self.fail(fmt.Errorf("%w: presence octet %d", errMlsMalformed, presence))
		return false
	}
	return presence == 1
}
