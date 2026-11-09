//go:build !js

// §22.6's Index files target, for entries, rows, key sets, slots and large entries: decoding is total and bounded,
// and whatever decodes re-encodes to the bytes it came from. Non-minimal VByte and unsorted or repeated keys sit in the
// seeds in testdata/fuzz/, which run in every go test. Shards join this target with their own task.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

// Seeds this target must hold: each a way a file is close to canonical and is not, beside good ones.
func testSlotSeeds(t testing.TB) map[string][]byte {
	seeds := map[string][]byte{}
	for _, c := range testSlotCases(t) {
		file, err := indexEncodeSlot(c.slot, c.companion)
		if err != nil {
			t.Fatal(err)
		}
		seeds["good-"+c.name] = file
	}
	body := testTombstones("a", "b")
	header := testFilledHeader(indexFileSlot, 2, body)
	seeds["bad-unsorted-entries"] = testRawFile(t, header, append(append([]byte{}, body[19:]...), body[:19]...), nil)
	seeds["bad-repeated-entry"] = testRawFile(t, header, append(append([]byte{}, body[:19]...), body[:19]...), nil)
	seeds["bad-pad"] = testRawFile(t, header, body, []byte{0, 1})
	nonMinimal := append(append([]byte{}, body[:17]...), 0x81, 0x00, 0x01)
	nonMinimal = append(nonMinimal, body[19:]...)
	seeds["bad-non-minimal-version"] = testRawFile(t, testFilledHeader(indexFileSlot, 2, nonMinimal), nonMinimal, nil)
	for name, keys := range map[string][]byte{
		"bad-repeated-key":    {2, 1, 0},
		"bad-non-minimal-gap": {1, 0x81, 0x00},
		"bad-key-past-range":  {1, 0x81, 0x80, 0x80, 0x08},
	} {
		row, err := (&indexRow{docKind: indexDocFile, trigramCount: 2, locator: "f"}).appendEncoded(nil, false)
		if err != nil {
			t.Fatal(err)
		}
		entry := testRawEntry(1, 1, row, keys)
		seeds[name] = testRawFile(t, testFilledHeader(indexFileSlot, 1, entry), entry, nil)
	}
	return seeds
}

// Seeds for one entry alone, of each kind.
func testEntrySeeds(t testing.TB) map[string][]byte {
	seeds := map[string][]byte{}
	for _, c := range testEntryCases() {
		encoded, err := c.entry.appendEncoded(nil, c.companion)
		if err != nil {
			t.Fatal(err)
		}
		seeds[c.name] = encoded
	}
	return seeds
}

func TestCodecSeedFilesAreCurrent(t *testing.T) {
	for _, companion := range []bool{false, true} {
		for name, file := range testSlotSeeds(t) {
			testCheckCorpusFile(t, "FuzzIndexSlot", fmt.Sprintf("%s-%t", name, companion), fmt.Sprintf("[]byte(%q)", file), fmt.Sprintf("bool(%t)", companion))
		}
		for name, encoded := range testEntrySeeds(t) {
			testCheckCorpusFile(t, "FuzzIndexEntry", fmt.Sprintf("%s-%t", name, companion), fmt.Sprintf("[]byte(%q)", encoded), fmt.Sprintf("bool(%t)", companion))
		}
	}
}

func FuzzIndexSlot(f *testing.F) {
	f.Fuzz(func(t *testing.T, file []byte, companion bool) {
		sum := sha256.Sum256(file)
		slot, err := indexDecodeSlot(file, sum[:], companion)
		if err != nil {
			return
		}
		again, err := indexEncodeSlot(slot, companion)
		if err != nil {
			t.Fatalf("what decoded does not encode: %v", err)
		}
		if !bytes.Equal(again, file) {
			t.Fatalf("re-encoding changed the bytes:\n got %x\nwant %x", again, file)
		}
	})
}

func FuzzIndexEntry(f *testing.F) {
	f.Fuzz(func(t *testing.T, encoded []byte, companion bool) {
		decoder := indexDecoder{src: encoded}
		entry := decoder.entry(companion)
		if decoder.err != nil {
			return
		}
		used := encoded[:len(encoded)-decoder.remaining()]
		again, err := entry.appendEncoded(nil, companion)
		if err != nil {
			t.Fatalf("what decoded does not encode: %v", err)
		}
		if !bytes.Equal(again, used) {
			t.Fatalf("re-encoding changed the bytes:\n got %x\nwant %x", again, used)
		}
	})
}
