// Holds the root's Id to one reading on every leg (QD-856). Id is operator-core's on every leg but
// sidecar_http, and that leg's own type in id_http.go. These tests name neither: they hold whichever Id
// the leg compiles to one list of vectors and one digest, whose values were read off operator-core's Id,
// so the two agree on the same bytes wherever both pass: the host's legs run them on the alias, and the
// page Worker's run on the twin (TestHttpLegPassesInAWorker names them).

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	mathrand "math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The methods operator-core's Id gives a caller on every leg. The database/sql Scanner and Valuer are
// the alias's alone: the page Worker holds no database.
var (
	_ interface {
		Bytes() []byte
		Less(b Id) bool
		LessThan(b Id) bool
		Cmp(b Id) int
		String() string
		MarshalJSON() ([]byte, error)
		Hash() uint64
	} = Id{}
	_ interface {
		UnmarshalJSON(src []byte) error
	} = (*Id)(nil)
)

// One id as operator-core's Id reads it: its text, its JSON and its hash.
type idTwinVector struct {
	idHex string
	text  string
	json  string
	hash  uint64
}

// Read off operator-core's Id, which is the alias on the host's legs.
var idTwinVectors = []idTwinVector{
	{
		idHex: "00000000000000000000000000000000",
		text:  "00000000-0000-0000-0000-000000000000",
		json:  `"00000000-0000-0000-0000-000000000000"`,
		hash:  0x88201fb960ff6465,
	},
	{
		idHex: "ffffffffffffffffffffffffffffffff",
		text:  "ffffffff-ffff-ffff-ffff-ffffffffffff",
		json:  `"ffffffff-ffff-ffff-ffff-ffffffffffff"`,
		hash:  0x873c67d692e7acb5,
	},
	{
		idHex: "0123456789abcdeffedcba9876543210",
		text:  "01234567-89ab-cdef-fedc-ba9876543210",
		json:  `"01234567-89ab-cdef-fedc-ba9876543210"`,
		hash:  0x25604f5d7c663fc5,
	},
	{
		// a ULID's shape: a millisecond timestamp, then entropy with leading zero bytes
		idHex: "019a8b2f4c7d000000000000000000a1",
		text:  "019a8b2f-4c7d-0000-0000-0000000000a1",
		json:  `"019a8b2f-4c7d-0000-0000-0000000000a1"`,
		hash:  0x97cfd5a5a046b536,
	},
	{
		idHex: "000102030405060708090a0b0c0d0e0f",
		text:  "00010203-0405-0607-0809-0a0b0c0d0e0f",
		json:  `"00010203-0405-0607-0809-0a0b0c0d0e0f"`,
		hash:  0xeebb60c961cea7a5,
	},
}

func TestIdTwinReadsAsOperatorIdDoes(t *testing.T) {
	for _, vector := range idTwinVectors {
		idBytes, err := hex.DecodeString(vector.idHex)
		if err != nil {
			t.Fatal(err)
		}
		id, err := IdFromBytes(idBytes)
		if err != nil {
			t.Fatalf("%s: %v", vector.idHex, err)
		}
		if !bytes.Equal(id.Bytes(), idBytes) {
			t.Errorf("%s: bytes %x", vector.idHex, id.Bytes())
		}
		if id.String() != vector.text {
			t.Errorf("%s: string %q, want %q", vector.idHex, id.String(), vector.text)
		}
		direct, err := id.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		byValue, err := json.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		byPointer, err := json.Marshal(&id)
		if err != nil {
			t.Fatal(err)
		}
		if string(direct) != vector.json || string(byValue) != vector.json || string(byPointer) != vector.json {
			t.Errorf("%s: json %s, %s by value and %s by pointer, want %s", vector.idHex, direct, byValue, byPointer, vector.json)
		}
		if id.Hash() != vector.hash {
			t.Errorf("%s: hash %#x, want %#x", vector.idHex, id.Hash(), vector.hash)
		}

		for _, form := range []string{vector.text, vector.idHex, strings.ToUpper(vector.text), strings.ToUpper(vector.idHex)} {
			parsed, err := ParseId(form)
			if err != nil {
				t.Errorf("%q: %v", form, err)
				continue
			}
			if parsed != id {
				t.Errorf("%q parsed to %v", form, parsed)
			}
		}
		for _, src := range []string{vector.json, strings.ToUpper(vector.json)} {
			decoded := Id{7}
			if err := json.Unmarshal([]byte(src), &decoded); err != nil {
				t.Errorf("%s: %v", src, err)
				continue
			}
			if decoded != id {
				t.Errorf("%s decoded to %v", src, decoded)
			}
		}
	}
}

// Ids for the digest, the same on every run and every leg: random ones, and beside each some that share
// its prefix or all of it, so the order is read where one late byte decides it.
func idTwinSweep() []Id {
	generator := mathrand.NewChaCha8([32]byte{'i', 'd', ' ', 't', 'w', 'i', 'n'})
	ids := []Id{}
	for len(ids) < 4096 {
		var id Id
		generator.Read(id[:])
		ids = append(ids, id)

		near := id
		near[int(generator.Uint64()%16)] ^= byte(1 + generator.Uint64()%255)
		ids = append(ids, near)

		last := id
		last[15] += 1
		ids = append(ids, last, id)
	}
	return ids
}

// SHA-256 over what each of idTwinSweep's ids reads as, in order: its bytes, text, JSON and hash, and
// its order against the id before it under Cmp, Less and LessThan, both ways.
func idTwinSweepDigest(t *testing.T) string {
	t.Helper()
	digest := sha256.New()
	orderByte := func(order bool) byte {
		if order {
			return 1
		}
		return 0
	}
	previous := Id{}
	for _, id := range idTwinSweep() {
		digest.Write(id.Bytes())
		digest.Write([]byte(id.String()))
		encoded, err := json.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		digest.Write(encoded)
		digest.Write(binary.BigEndian.AppendUint64(nil, id.Hash()))
		digest.Write([]byte{
			byte(id.Cmp(previous) + 1), byte(previous.Cmp(id) + 1),
			orderByte(id.Less(previous)), orderByte(previous.Less(id)),
			orderByte(id.LessThan(previous)), orderByte(previous.LessThan(id)),
		})

		var decoded Id
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != id {
			t.Fatalf("%s decoded to %v: %v", encoded, decoded, err)
		}
		parsed, err := ParseId(id.String())
		if err != nil || parsed != id {
			t.Fatalf("%s parsed to %v: %v", id, parsed, err)
		}
		previous = id
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// What idTwinSweepDigest gives over operator-core's Id.
const idTwinSweepDigestHex = "ebc8656cede15881e0ea0f127cc345acbb56658ddebd3686e5a48aa635a36ff0"

func TestIdTwinReadsASweepAsOperatorIdDoes(t *testing.T) {
	if digestHex := idTwinSweepDigest(t); digestHex != idTwinSweepDigestHex {
		t.Errorf("the sweep's digest is %s, and over operator-core's Id it is %s", digestHex, idTwinSweepDigestHex)
	}
}

// The order agrees with the bytes', which is what makes ids sort by creation time.
func TestIdTwinOrdersByByte(t *testing.T) {
	previous := Id{}
	for _, id := range idTwinSweep() {
		want := bytes.Compare(id[:], previous[:])
		if id.Cmp(previous) != want || previous.Cmp(id) != -want {
			t.Fatalf("Cmp of %v and %v: %d and %d, want %d", id, previous, id.Cmp(previous), previous.Cmp(id), want)
		}
		if id.Less(previous) != (want < 0) || id.LessThan(previous) != (want < 0) {
			t.Fatalf("Less of %v and %v: %t and %t", id, previous, id.Less(previous), id.LessThan(previous))
		}
		if previous.Less(id) != (want > 0) || previous.LessThan(id) != (want > 0) {
			t.Fatalf("Less of %v and %v: %t and %t", previous, id, previous.Less(id), previous.LessThan(id))
		}
		previous = id
	}
}

// operator-core's refusals, word for word: server.Id's words for a null and a wrong length, and
// "invalid id" for the rest. Each matches errInvalidId and leaves the id alone, and none repeats its
// input (I-13).
func TestIdTwinRefusesInOperatorIdsWords(t *testing.T) {
	for _, c := range []struct {
		src  string
		want string
	}{
		{src: `null`, want: "Unmarshal with nil source not supported by Id (use *Id)"},
		{src: `""`, want: "invalid length for UUID: 2"},
		{src: `"not-an-id"`, want: "invalid length for UUID: 11"},
		{src: `1234`, want: "invalid length for UUID: 4"},
		{src: `"0123456789abcdeffedcba9876543210"`, want: "invalid length for UUID: 34"},
		{src: `x01234567-89ab-cdef-fedc-ba9876543210x`, want: "invalid id"},
		{src: `"01234567-89ab-cdef-fedc-ba9876543210x`, want: "invalid id"},
		{src: `x01234567-89ab-cdef-fedc-ba9876543210"`, want: "invalid id"},
		{src: `"01234567x89ab-cdef-fedc-ba9876543210"`, want: "invalid id"},
		{src: `"01234567-89abxcdef-fedc-ba9876543210"`, want: "invalid id"},
		{src: `"01234567-89ab-cdefxfedc-ba9876543210"`, want: "invalid id"},
		{src: `"01234567-89ab-cdef-fedcxba9876543210"`, want: "invalid id"},
		{src: `"g1234567-89ab-cdef-fedc-ba9876543210"`, want: "invalid id"},
		{src: `"0123456-789ab-cdef-fedc-ba9876543210"`, want: "invalid id"},
		// 38 digits: valid JSON, a number
		{src: `12345678901234567890123456789012345678`, want: "invalid id"},
	} {
		id := Id{7}
		err := id.UnmarshalJSON([]byte(c.src))
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.src, err, c.want)
		}
		if !errors.Is(err, errInvalidId) {
			t.Errorf("%s: %v does not match the invalid id error", c.src, err)
		}
		if id != (Id{7}) {
			t.Errorf("%s wrote %v", c.src, id)
		}
	}

	for _, malformed := range []string{
		"",
		"not-an-id",
		"01234567-89ab-cdef-fedc-ba987654321",
		"01234567x89ab-cdef-fedc-ba9876543210",
		"g123456789abcdeffedcba9876543210",
	} {
		if _, err := ParseId(malformed); err != errInvalidId || err.Error() != "invalid id" {
			t.Errorf("ParseId %q: %v", malformed, err)
		}
	}
	for _, byteCount := range []int{0, 15, 17, 32} {
		if _, err := IdFromBytes(make([]byte, byteCount)); err != errInvalidId {
			t.Errorf("IdFromBytes of %d bytes: %v", byteCount, err)
		}
	}
}

// Every exported method of Id, so one operator-core's Id gains reaches the twin, or fails here on the
// alias's legs first. Scan and Value come as a pair, on the alias alone.
func TestIdTwinHoldsOperatorIdsMethods(t *testing.T) {
	methodNames := func(methodType reflect.Type) []string {
		names := []string{}
		for index := 0; index < methodType.NumMethod(); index += 1 {
			names = append(names, methodType.Method(index).Name)
		}
		return names
	}
	valueNames := []string{"Bytes", "Cmp", "Hash", "Less", "LessThan", "MarshalJSON", "String"}
	pointerNames := []string{"Bytes", "Cmp", "Hash", "Less", "LessThan", "MarshalJSON", "String", "UnmarshalJSON"}
	databaseValueNames := []string{"Bytes", "Cmp", "Hash", "Less", "LessThan", "MarshalJSON", "String", "Value"}
	databasePointerNames := []string{"Bytes", "Cmp", "Hash", "Less", "LessThan", "MarshalJSON", "Scan", "String", "UnmarshalJSON", "Value"}

	gotValueNames := methodNames(reflect.TypeFor[Id]())
	gotPointerNames := methodNames(reflect.TypeFor[*Id]())
	plain := slices.Equal(gotValueNames, valueNames) && slices.Equal(gotPointerNames, pointerNames)
	database := slices.Equal(gotValueNames, databaseValueNames) && slices.Equal(gotPointerNames, databasePointerNames)
	if !plain && !database {
		t.Errorf("Id has %v and *Id %v, want %v and %v, with or without Scan and Value", gotValueNames, gotPointerNames, valueNames, pointerNames)
	}
}
