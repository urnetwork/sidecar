// The codec's canonical-encoding rules (RFC 9420 §2.1), against the mlswg's deserialization vectors
// and hand-built bad input.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"runtime"
	"testing"
)

func TestMlsVectorHeaderVectors(t *testing.T) {
	var vectors []struct {
		VlbytesHeader mlsHexBytes `json:"vlbytes_header"`
		Length        int         `json:"length"`
	}
	mlsLoadVectors(t, "deserialization", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vector := range vectors {
		decoder := &mlsDecoder{remaining: vector.VlbytesHeader}
		length := decoder.readLength()
		if err := decoder.finish(); err != nil {
			t.Errorf("%x: %v", vector.VlbytesHeader, err)
			continue
		}
		if length != vector.Length {
			t.Errorf("%x: length %d, want %d", vector.VlbytesHeader, length, vector.Length)
		}
		encoder := &mlsEncoder{}
		encoder.writeLength(vector.Length)
		if !bytes.Equal(encoder.encoded, vector.VlbytesHeader) {
			t.Errorf("length %d: header %x, want %x", vector.Length, encoder.encoded, vector.VlbytesHeader)
		}
	}
}

// The worked examples in RFC §2.1.2.
func TestMlsVectorHeaderSpecExamples(t *testing.T) {
	cases := []struct {
		header string
		length int
	}{
		{header: "9d7f3e7d", length: 494878333},
		{header: "7bbd", length: 15293},
		{header: "25", length: 37},
	}
	for _, c := range cases {
		header, err := hex.DecodeString(c.header)
		if err != nil {
			t.Fatal(err)
		}
		decoder := &mlsDecoder{remaining: header}
		if length := decoder.readLength(); length != c.length {
			t.Errorf("%s: length %d, want %d", c.header, length, c.length)
		}
		if err := decoder.finish(); err != nil {
			t.Errorf("%s: %v", c.header, err)
		}
	}
}

func TestMlsVectorHeaderBoundaries(t *testing.T) {
	cases := []struct {
		length     int
		headerSize int
	}{
		{length: 0, headerSize: 1},
		{length: 63, headerSize: 1},
		{length: 64, headerSize: 2},
		{length: 16383, headerSize: 2},
		{length: 16384, headerSize: 4},
		{length: mlsVectorLengthMaximum, headerSize: 4},
	}
	for _, c := range cases {
		encoder := &mlsEncoder{}
		encoder.writeLength(c.length)
		encoded, err := encoder.finish()
		if err != nil {
			t.Errorf("length %d: %v", c.length, err)
			continue
		}
		if len(encoded) != c.headerSize {
			t.Errorf("length %d: %d header bytes, want %d", c.length, len(encoded), c.headerSize)
		}
		decoder := &mlsDecoder{remaining: encoded}
		if length := decoder.readLength(); length != c.length {
			t.Errorf("length %d decoded as %d", c.length, length)
		}
		if err := decoder.finish(); err != nil {
			t.Errorf("length %d: %v", c.length, err)
		}
	}
}

func TestMlsVectorHeaderRefusesNonCanonicalForms(t *testing.T) {
	cases := []string{
		"4000",     // 0 in two bytes
		"403f",     // 63 in two bytes
		"80000000", // 0 in four bytes
		"80003fff", // 16383 in four bytes
		"c0",       // the prefix with no meaning
		"ff00000000000000",
		"",   // nothing at all
		"40", // two-byte header cut short
		"80ff",
	}
	for _, c := range cases {
		encoded, err := hex.DecodeString(c)
		if err != nil {
			t.Fatal(err)
		}
		decoder := &mlsDecoder{remaining: encoded}
		decoder.readLength()
		if err := decoder.finish(); !errors.Is(err, errMlsMalformed) {
			t.Errorf("%q: %v", c, err)
		}
	}
}

func TestMlsEncoderRefusesLengthPastTheHeader(t *testing.T) {
	for _, length := range []int{-1, mlsVectorLengthMaximum + 1} {
		encoder := &mlsEncoder{}
		encoder.writeLength(length)
		if _, err := encoder.finish(); err == nil {
			t.Errorf("length %d encoded", length)
		}
	}
}

func TestMlsEncoderFailureSurvivesNestedVectors(t *testing.T) {
	encoder := &mlsEncoder{}
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		elements.writeVectorOf(func(inner *mlsEncoder) {
			inner.writeLength(-1)
		})
	})
	encoder.writeUint8(1)
	if _, err := encoder.finish(); err == nil {
		t.Fatal("a nested failure was lost")
	}
}

func TestMlsIntegersAreBigEndian(t *testing.T) {
	encoder := &mlsEncoder{}
	encoder.writeUint8(0x01)
	encoder.writeUint16(0x0203)
	encoder.writeUint32(0x04050607)
	encoder.writeUint64(0x08090a0b0c0d0e0f)
	want, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoder.encoded, want) {
		t.Fatalf("encoded %x", encoder.encoded)
	}

	decoder := &mlsDecoder{remaining: encoder.encoded}
	if value := decoder.readUint8(); value != 0x01 {
		t.Errorf("uint8 %x", value)
	}
	if value := decoder.readUint16(); value != 0x0203 {
		t.Errorf("uint16 %x", value)
	}
	if value := decoder.readUint32(); value != 0x04050607 {
		t.Errorf("uint32 %x", value)
	}
	if value := decoder.readUint64(); value != 0x08090a0b0c0d0e0f {
		t.Errorf("uint64 %x", value)
	}
	if err := decoder.finish(); err != nil {
		t.Error(err)
	}
}

func TestMlsDecoderRefusesTruncatedIntegers(t *testing.T) {
	reads := []func(decoder *mlsDecoder){
		func(decoder *mlsDecoder) { decoder.readUint16() },
		func(decoder *mlsDecoder) { decoder.readUint32() },
		func(decoder *mlsDecoder) { decoder.readUint64() },
		func(decoder *mlsDecoder) { decoder.readFixed(2) },
	}
	for _, read := range reads {
		decoder := &mlsDecoder{remaining: []byte{0x01}}
		read(decoder)
		if err := decoder.finish(); !errors.Is(err, errMlsMalformed) {
			t.Errorf("%v", err)
		}
	}
	empty := &mlsDecoder{}
	empty.readUint8()
	if err := empty.finish(); !errors.Is(err, errMlsMalformed) {
		t.Errorf("%v", err)
	}
}

// After a failure every read gives its zero value and input is no longer consumed.
func TestMlsDecoderStopsAtTheFirstFailure(t *testing.T) {
	decoder := &mlsDecoder{remaining: []byte{0xc0, 0x05, 0x05}}
	decoder.readVector()
	firstErr := decoder.err
	if firstErr == nil {
		t.Fatal("no failure")
	}
	if value := decoder.readUint8(); value != 0 {
		t.Errorf("uint8 %d after a failure", value)
	}
	if value := decoder.readVector(); value != nil {
		t.Errorf("vector %x after a failure", value)
	}
	if decoder.err != firstErr {
		t.Errorf("failure replaced by %v", decoder.err)
	}
}

func TestMlsOptionalRefusesOtherPresenceOctets(t *testing.T) {
	cases := []struct {
		octet   byte
		present bool
		refused bool
	}{
		{octet: 0, present: false},
		{octet: 1, present: true},
		{octet: 2, refused: true},
		{octet: 0xff, refused: true},
	}
	for _, c := range cases {
		decoder := &mlsDecoder{remaining: []byte{c.octet}}
		present := decoder.readOptional()
		err := decoder.finish()
		if c.refused {
			if !errors.Is(err, errMlsMalformed) {
				t.Errorf("octet %d: %v", c.octet, err)
			}
			continue
		}
		if err != nil || present != c.present {
			t.Errorf("octet %d: present %v, %v", c.octet, present, err)
		}
	}
}

func TestMlsVectorRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 63, 64, 16383, 16384, 70000} {
		value := bytes.Repeat([]byte{0xab}, size)
		encoder := &mlsEncoder{}
		encoder.writeVector(value)
		encoded, err := encoder.finish()
		if err != nil {
			t.Fatal(err)
		}
		decoder := &mlsDecoder{remaining: encoded}
		decoded := decoder.readVector()
		if err := decoder.finish(); err != nil {
			t.Errorf("size %d: %v", size, err)
		}
		if !bytes.Equal(decoded, value) {
			t.Errorf("size %d: value changed", size)
		}
	}
}

func TestMlsDecodedBytesDoNotAliasTheInput(t *testing.T) {
	input := []byte{0x02, 0xaa, 0xbb, 0xcc}
	decoder := &mlsDecoder{remaining: input}
	vector := decoder.readVector()
	fixed := decoder.readFixed(1)
	if err := decoder.finish(); err != nil {
		t.Fatal(err)
	}
	clear(input)
	if !bytes.Equal(vector, []byte{0xaa, 0xbb}) || !bytes.Equal(fixed, []byte{0xcc}) {
		t.Fatalf("vector %x, fixed %x", vector, fixed)
	}
}

// A header claiming a gigabyte over a few bytes of input fails without reserving anything for it.
func TestMlsDecoderDoesNotAllocateForAClaimedLength(t *testing.T) {
	input := []byte{0xbf, 0xff, 0xff, 0xff, 0x00}
	var before runtime.MemStats
	var after runtime.MemStats
	runtime.ReadMemStats(&before)
	decoder := &mlsDecoder{remaining: input}
	value := decoder.readVector()
	runtime.ReadMemStats(&after)

	if value != nil {
		t.Errorf("vector of %d bytes", len(value))
	}
	if err := decoder.finish(); !errors.Is(err, errMlsMalformed) {
		t.Error(err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; 1024*1024 < allocated {
		t.Errorf("allocated %d bytes", allocated)
	}
}

func TestMlsVectorOfElements(t *testing.T) {
	encoder := &mlsEncoder{}
	encoder.writeVectorOf(func(elements *mlsEncoder) {
		for _, value := range []uint16{1, 2, 3} {
			elements.writeUint16(value)
		}
	})
	encoded, err := encoder.finish()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, []byte{6, 0, 1, 0, 2, 0, 3}) {
		t.Fatalf("encoded %x", encoded)
	}

	var values []uint16
	decoder := &mlsDecoder{remaining: encoded}
	decoder.readVectorOf(func(element *mlsDecoder) {
		values = append(values, element.readUint16())
	})
	if err := decoder.finish(); err != nil {
		t.Fatal(err)
	}
	if len(values) != 3 || values[0] != 1 || values[1] != 2 || values[2] != 3 {
		t.Fatalf("values %v", values)
	}
}

func TestMlsVectorOfRefusesAnElementCrossingTheVectorEnd(t *testing.T) {
	// a three-byte vector of uint16 elements: the second element ends past it
	decoder := &mlsDecoder{remaining: []byte{3, 0, 1, 0, 2}}
	decoder.readVectorOf(func(element *mlsDecoder) {
		element.readUint16()
	})
	if err := decoder.finish(); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

func TestMlsVectorOfRefusesAnElementReadingNothing(t *testing.T) {
	decoder := &mlsDecoder{remaining: []byte{1, 0}}
	decoder.readVectorOf(func(element *mlsDecoder) {})
	if err := decoder.finish(); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}

// One fixed struct through mlsMarshal and mlsUnmarshal.
type mlsCodecTestValue struct {
	number uint16
	body   []byte
}

// A fixed field, then a vector.
func (self *mlsCodecTestValue) encode(encoder *mlsEncoder) {
	encoder.writeUint16(self.number)
	encoder.writeVector(self.body)
}

// A fixed field, then a vector.
func (self *mlsCodecTestValue) decode(decoder *mlsDecoder) {
	self.number = decoder.readUint16()
	self.body = decoder.readVector()
}

func TestMlsUnmarshalRefusesTrailingBytes(t *testing.T) {
	encoded, err := mlsMarshal(&mlsCodecTestValue{number: 7, body: []byte{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if err := mlsUnmarshal(encoded, &mlsCodecTestValue{}); err != nil {
		t.Fatal(err)
	}
	if err := mlsUnmarshal(append(encoded, 0), &mlsCodecTestValue{}); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
	if err := mlsUnmarshal(encoded[:len(encoded)-1], &mlsCodecTestValue{}); !errors.Is(err, errMlsMalformed) {
		t.Fatal(err)
	}
}
