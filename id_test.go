package sidecar

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIdStringIsDashedLowercaseHex(t *testing.T) {
	id := Id{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	if s := id.String(); s != "01234567-89ab-cdef-fedc-ba9876543210" {
		t.Errorf("string %q", s)
	}
}

func TestParseIdTakesBothForms(t *testing.T) {
	id := NewId()
	for _, form := range []string{
		id.String(),
		strings.ReplaceAll(id.String(), "-", ""),
		strings.ToUpper(id.String()),
	} {
		parsed, err := ParseId(form)
		if err != nil {
			t.Fatalf("%q: %v", form, err)
		}
		if parsed != id {
			t.Errorf("%q parsed to %v", form, parsed)
		}
	}
}

func TestParseIdRefusesMalformedWithoutEchoingThem(t *testing.T) {
	for _, malformed := range []string{
		"",
		"not-an-id",
		"01234567-89ab-cdef-fedc-ba987654321",
		"01234567-89ab-cdef-fedc-ba98765432100",
		// the right length, with a separator connect would drop unread
		"01234567x89ab-cdef-fedc-ba9876543210",
		"01234567-89abxcdef-fedc-ba9876543210",
		"01234567-89ab-cdefxfedc-ba9876543210",
		"01234567-89ab-cdef-fedcxba9876543210",
		// the right length, with a character hex refuses
		"g1234567-89ab-cdef-fedc-ba9876543210",
		"g123456789abcdeffedcba9876543210",
	} {
		_, err := ParseId(malformed)
		if err == nil {
			t.Errorf("%q parsed", malformed)
			continue
		}
		if malformed != "" && strings.Contains(err.Error(), malformed) {
			t.Errorf("error %q repeats its input", err)
		}
	}
}

func TestIdFromBytesTakesSixteen(t *testing.T) {
	id := NewId()
	fromBytes, err := IdFromBytes(id.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if fromBytes != id {
		t.Errorf("round trip gave %v, want %v", fromBytes, id)
	}
	for _, byteCount := range []int{0, 15, 17} {
		if _, err := IdFromBytes(make([]byte, byteCount)); err == nil {
			t.Errorf("%d bytes accepted", byteCount)
		}
	}
}

func TestIdBytesIsACopy(t *testing.T) {
	id := Id{1}
	id.Bytes()[0] = 2
	if id != (Id{1}) {
		t.Errorf("writing through Bytes changed the id: %v", id)
	}
}

func TestIdCmpOrdersByByte(t *testing.T) {
	low := Id{0x00, 0xff}
	high := Id{0x01, 0x00}
	if !low.LessThan(high) || high.LessThan(low) || low.LessThan(low) {
		t.Errorf("LessThan misordered %v and %v", low, high)
	}
	if low.Cmp(high) != -1 || high.Cmp(low) != 1 || low.Cmp(low) != 0 {
		t.Errorf("Cmp misordered %v and %v", low, high)
	}
}

func TestIdJsonIsOneEncodingByValueAndPointer(t *testing.T) {
	type holder struct {
		Id    Id  `json:"id"`
		IdPtr *Id `json:"id_ptr"`
	}
	id := NewId()
	want := `{"id":"` + id.String() + `","id_ptr":"` + id.String() + `"}`
	// by value the Id field is not addressable, which is what a pointer receiver would get wrong
	byValue, err := json.Marshal(holder{Id: id, IdPtr: &id})
	if err != nil {
		t.Fatal(err)
	}
	byPointer, err := json.Marshal(&holder{Id: id, IdPtr: &id})
	if err != nil {
		t.Fatal(err)
	}
	if string(byValue) != want || string(byPointer) != want {
		t.Errorf("by value %s, by pointer %s, want %s", byValue, byPointer, want)
	}

	var decoded holder
	if err := json.Unmarshal(byValue, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Id != id || decoded.IdPtr == nil || *decoded.IdPtr != id {
		t.Errorf("decoded %+v", decoded)
	}
}

func TestIdJsonRefusesAnythingButAnId(t *testing.T) {
	for _, src := range []string{
		`null`,
		`""`,
		`1234`,
		`"not-an-id"`,
		// 38 bytes, not quoted
		`x01234567-89ab-cdef-fedc-ba9876543210x`,
	} {
		var id Id
		if err := json.Unmarshal([]byte(src), &id); err == nil {
			t.Errorf("%s decoded to %v", src, id)
		}
	}
}

func TestNewIdIsStrictlyIncreasingAcrossGoroutines(t *testing.T) {
	const goroutineCount = 8
	const idCount = 2000
	idLists := make([][]Id, goroutineCount)
	var wg sync.WaitGroup
	for i := range idLists {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids := make([]Id, idCount)
			for j := range ids {
				ids[j] = NewId()
			}
			idLists[i] = ids
		}()
	}
	wg.Wait()

	seen := map[Id]bool{}
	for _, ids := range idLists {
		for j, id := range ids {
			if seen[id] {
				t.Fatalf("id %v minted twice", id)
			}
			seen[id] = true
			if 0 < j && !ids[j-1].LessThan(id) {
				t.Fatalf("id %v does not follow %v", id, ids[j-1])
			}
		}
	}
}

func TestNewIdTakesTheWallClock(t *testing.T) {
	before := uint64(time.Now().UnixMilli())
	id := NewId()

	var ms uint64
	for _, b := range id[0:6] {
		ms = ms<<8 | uint64(b)
	}
	if ms < before {
		t.Errorf("timestamp %d is before the wall clock's %d", ms, before)
	}
}

func TestIdGeneratorLaysOutAUlid(t *testing.T) {
	var generator idGenerator
	draw := [idDrawByteCount]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa}
	id := generator.next(0x010203040506, draw)
	want := Id{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa}
	if id != want {
		t.Errorf("id %x, want %x", id, want)
	}
}

func TestIdGeneratorKeepsOrderWhenTheClockStepsBack(t *testing.T) {
	var generator idGenerator
	draw := [idDrawByteCount]byte{}
	first := generator.next(5000, draw)
	second := generator.next(4000, draw)
	third := generator.next(5000, draw)

	if !first.LessThan(second) || !second.LessThan(third) {
		t.Errorf("order broke: %v %v %v", first, second, third)
	}
	if string(second[0:6]) != string(first[0:6]) {
		t.Errorf("timestamp fell: %x then %x", first[0:6], second[0:6])
	}
}

func TestIdGeneratorIncrementsByTheDraw(t *testing.T) {
	var generator idGenerator
	first := generator.next(5000, [idDrawByteCount]byte{})
	second := generator.next(5000, [idDrawByteCount]byte{13: 9})
	// one, so a zero draw still moves, plus the draw
	if first[15] != 0 || second[15] != 10 {
		t.Errorf("low bytes %d then %d", first[15], second[15])
	}
}

func TestIdGeneratorFreshEntropyEachMillisecond(t *testing.T) {
	var generator idGenerator
	first := generator.next(5000, [idDrawByteCount]byte{0: 0xaa})
	second := generator.next(5001, [idDrawByteCount]byte{0: 0xbb})
	if first[6] != 0xaa || second[6] != 0xbb {
		t.Errorf("entropy bytes %x and %x", first[6], second[6])
	}
	if !first.LessThan(second) {
		t.Errorf("%v does not precede %v", first, second)
	}
}

func TestIdGeneratorCarriesIntoHighEntropy(t *testing.T) {
	generator := idGenerator{ms: 5000, entropyHi: 1, entropyLo: ^uint64(0)}
	id := generator.next(5000, [idDrawByteCount]byte{})

	// 0x0001ffffffffffffffff plus one
	if id[6] != 0 || id[7] != 2 {
		t.Errorf("high entropy %x", id[6:8])
	}
	for _, b := range id[8:16] {
		if b != 0 {
			t.Fatalf("low entropy %x", id[8:16])
		}
	}
}

func TestIdGeneratorCarriesIntoTheTimestampWhenEntropyWraps(t *testing.T) {
	generator := idGenerator{ms: 5000, entropyHi: ^uint16(0), entropyLo: ^uint64(0)}
	last := Id{4: byte(5000 >> 8), 5: byte(5000 & 0xff)}
	for i := 6; i < 16; i += 1 {
		last[i] = 0xff
	}

	wrapped := generator.next(5000, [idDrawByteCount]byte{})
	if !last.LessThan(wrapped) {
		t.Errorf("%v does not follow the last id of its millisecond, %v", wrapped, last)
	}
	if generator.ms != 5001 {
		t.Errorf("timestamp %d", generator.ms)
	}
}

func TestParseIdErrorsAreOneValue(t *testing.T) {
	_, err := ParseId("short")
	if !errors.Is(err, errInvalidId) {
		t.Errorf("err %v", err)
	}
}
