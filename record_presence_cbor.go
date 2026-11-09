// A small reader of CTAP2's canonical CBOR (CTAP 2.1 §8's "CTAP2 canonical CBOR encoding form"), for what §16.6's
// registration reads: a WebAuthn attestation object, its attestation statement, and its authenticator data's credential
// public key (COSE_Key) and extensions. The root links no CBOR module (MCP-M3-08), so this holds only what those need.
//
// It refuses what is not canonical rather than reading it some way: an integer or a length not in its shortest form,
// an indefinite length, a tag, a float, a simple value other than false, true and null, text that is not UTF-8, and map
// keys out of CTAP2's order (major type, then encoded length, then the encoded bytes), which a repeated key also is. A
// reader that took two encodings of one value would let a relay rewrite an attestation it stores.
//
// Work and memory are bounded by the input: a declared count is checked against the bytes left before anything is
// allocated for it, nesting stops at presenceCborMaxDepth, and every item holds slices of the input rather than copies.
//
// Package-level functions are safe for concurrent use, and so are the items they return, which nothing changes.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// The deepest nesting a WebAuthn attestation object has is the object, its statement, the x5c array and a
// certificate, and the authenticator data's extensions under their own map; anything near this is no attestation.
const presenceCborMaxDepth = 16

// The input does not decode as canonical CBOR: malformed, not in canonical form, nested too deep or longer than its
// item.
var ErrPresenceCbor = errors.New("presence cbor refused")

// An item's major type, and for major type 7 which simple value.
type presenceCborKind int

const (
	presenceCborUnsigned presenceCborKind = iota + 1
	presenceCborNegative
	presenceCborBytes
	presenceCborText
	presenceCborArray
	presenceCborMap
	presenceCborBool
	presenceCborNull
)

// One decoded item. Slices point into the input.
type presenceCborItem struct {
	kind presenceCborKind
	// An unsigned item's value; a negative item's n, its value being -1 - n; a bool's 0 or 1.
	argument uint64
	// A byte or text string's content.
	content []byte
	// An array's items.
	items []*presenceCborItem
	// A map's keys and values, in order, keys strictly ascending.
	keys   []*presenceCborItem
	values []*presenceCborItem
	// The item's whole encoding, which a map's key order compares.
	encoded []byte
}

// Decodes data as exactly one item, nothing after it.
func presenceCborDecodeAll(data []byte) (*presenceCborItem, error) {
	item, rest, err := presenceCborDecode(data)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after the item", ErrPresenceCbor, len(rest))
	}
	return item, nil
}

// Decodes the first item of data, returning it and the bytes after it.
func presenceCborDecode(data []byte) (*presenceCborItem, []byte, error) {
	item, size, err := presenceCborDecodeAt(data, 0)
	if err != nil {
		return nil, nil, err
	}
	return item, data[size:], nil
}

// The item at the start of data, nested depth deep, and its encoded size.
func presenceCborDecodeAt(data []byte, depth int) (*presenceCborItem, int, error) {
	if presenceCborMaxDepth <= depth {
		return nil, 0, fmt.Errorf("%w: nested deeper than %d", ErrPresenceCbor, presenceCborMaxDepth)
	}
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("%w: truncated", ErrPresenceCbor)
	}
	majorType := data[0] >> 5
	additional := data[0] & 0x1f

	if majorType == 7 {
		item := &presenceCborItem{encoded: data[:1]}
		switch additional {
		case 20, 21:
			item.kind = presenceCborBool
			item.argument = uint64(additional - 20)
		case 22:
			item.kind = presenceCborNull
		default:
			return nil, 0, fmt.Errorf("%w: simple value or float 0x%02x", ErrPresenceCbor, data[0])
		}
		return item, 1, nil
	}
	if majorType == 6 {
		return nil, 0, fmt.Errorf("%w: a tag", ErrPresenceCbor)
	}

	argument, headerSize, err := presenceCborArgument(data)
	if err != nil {
		return nil, 0, err
	}
	rest := data[headerSize:]
	item := &presenceCborItem{argument: argument}

	switch majorType {
	case 0:
		item.kind = presenceCborUnsigned
		item.encoded = data[:headerSize]
		return item, headerSize, nil

	case 1:
		item.kind = presenceCborNegative
		item.encoded = data[:headerSize]
		return item, headerSize, nil

	case 2, 3:
		if uint64(len(rest)) < argument {
			return nil, 0, fmt.Errorf("%w: a string of %d bytes with %d left", ErrPresenceCbor, argument, len(rest))
		}
		item.content = rest[:argument]
		item.kind = presenceCborBytes
		if majorType == 3 {
			item.kind = presenceCborText
			if !utf8.Valid(item.content) {
				return nil, 0, fmt.Errorf("%w: text that is not UTF-8", ErrPresenceCbor)
			}
		}
		size := headerSize + int(argument)
		item.encoded = data[:size]
		return item, size, nil

	case 4:
		// every item takes at least a byte, so a count past what is left cannot be met and allocates nothing
		if uint64(len(rest)) < argument {
			return nil, 0, fmt.Errorf("%w: an array of %d with %d bytes left", ErrPresenceCbor, argument, len(rest))
		}
		item.kind = presenceCborArray
		item.items = make([]*presenceCborItem, 0, argument)
		size := headerSize
		for range argument {
			element, elementSize, err := presenceCborDecodeAt(data[size:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			item.items = append(item.items, element)
			size += elementSize
		}
		item.encoded = data[:size]
		return item, size, nil

	default:
		// major type 5: each entry takes at least two bytes
		if uint64(len(rest))/2 < argument {
			return nil, 0, fmt.Errorf("%w: a map of %d with %d bytes left", ErrPresenceCbor, argument, len(rest))
		}
		item.kind = presenceCborMap
		item.keys = make([]*presenceCborItem, 0, argument)
		item.values = make([]*presenceCborItem, 0, argument)
		size := headerSize
		for i := range argument {
			key, keySize, err := presenceCborDecodeAt(data[size:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			if 0 < i && !presenceCborKeyBefore(item.keys[i-1].encoded, key.encoded) {
				return nil, 0, fmt.Errorf("%w: map keys out of canonical order", ErrPresenceCbor)
			}
			size += keySize
			value, valueSize, err := presenceCborDecodeAt(data[size:], depth+1)
			if err != nil {
				return nil, 0, err
			}
			size += valueSize
			item.keys = append(item.keys, key)
			item.values = append(item.values, value)
		}
		item.encoded = data[:size]
		return item, size, nil
	}
}

// An item's argument, the value or length its initial byte and the bytes after it give, in its shortest form, and the
// header's size.
func presenceCborArgument(data []byte) (uint64, int, error) {
	additional := data[0] & 0x1f
	switch {
	case additional < 24:
		return uint64(additional), 1, nil
	case 27 < additional:
		// 28 to 30 are reserved and 31 is an indefinite length, which canonical form never has
		return 0, 0, fmt.Errorf("%w: additional information %d", ErrPresenceCbor, additional)
	}
	followSize := 1 << (additional - 24)
	if len(data) < 1+followSize {
		return 0, 0, fmt.Errorf("%w: truncated", ErrPresenceCbor)
	}
	var argument uint64
	var shortestFloor uint64
	switch followSize {
	case 1:
		argument = uint64(data[1])
		shortestFloor = 24
	case 2:
		argument = uint64(binary.BigEndian.Uint16(data[1:3]))
		shortestFloor = 0x100
	case 4:
		argument = uint64(binary.BigEndian.Uint32(data[1:5]))
		shortestFloor = 0x10000
	default:
		argument = binary.BigEndian.Uint64(data[1:9])
		shortestFloor = 0x100000000
	}
	if argument < shortestFloor {
		return 0, 0, fmt.Errorf("%w: %d not in its shortest form", ErrPresenceCbor, argument)
	}
	return argument, 1 + followSize, nil
}

// CTAP2's canonical key order: the lower major type first, then the shorter encoding, then the lower bytes. Strict, so a
// repeated key is out of order.
func presenceCborKeyBefore(before []byte, after []byte) bool {
	if beforeType, afterType := before[0]>>5, after[0]>>5; beforeType != afterType {
		return beforeType < afterType
	}
	if len(before) != len(after) {
		return len(before) < len(after)
	}
	return bytes.Compare(before, after) < 0
}

// The item as an int64, and false for anything but an integer in range.
func (self *presenceCborItem) int64Value() (int64, bool) {
	switch self.kind {
	case presenceCborUnsigned:
		if self.argument <= 1<<63-1 {
			return int64(self.argument), true
		}
	case presenceCborNegative:
		if self.argument <= 1<<63-1 {
			return -1 - int64(self.argument), true
		}
	}
	return 0, false
}

// The value of a map's text key, and false when the item is no map or has no such key.
func (self *presenceCborItem) textKey(key string) (*presenceCborItem, bool) {
	if self.kind != presenceCborMap {
		return nil, false
	}
	for i, mapKey := range self.keys {
		if mapKey.kind == presenceCborText && string(mapKey.content) == key {
			return self.values[i], true
		}
	}
	return nil, false
}

// The value of a map's integer key, and false when the item is no map or has no such key.
func (self *presenceCborItem) intKey(key int64) (*presenceCborItem, bool) {
	if self.kind != presenceCborMap {
		return nil, false
	}
	for i, mapKey := range self.keys {
		if value, ok := mapKey.int64Value(); ok && value == key {
			return self.values[i], true
		}
	}
	return nil, false
}

// Whether the item is a map whose keys are all text and are exactly keys, in any order the decoder has already held to
// canonical form.
func (self *presenceCborItem) hasTextKeysExactly(keys ...string) bool {
	if self.kind != presenceCborMap || len(self.keys) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := self.textKey(key); !ok {
			return false
		}
	}
	return true
}

// The number of items the tree holds, itself included, which the fuzz target holds to the input's length.
func (self *presenceCborItem) count() int {
	count := 1
	for _, element := range self.items {
		count += element.count()
	}
	for i := range self.keys {
		count += self.keys[i].count() + self.values[i].count()
	}
	return count
}
