//go:build !js

// §22.6's decoders: on any bytes each ends, spends only what its input holds, and answers a fixed error
// that repeats none of it. What decodes must also encode back to the same bytes, or a parser and a
// writer disagree on what a file means. Off the js leg, where a fuzz target cannot read its corpus in a
// Worker with no file system, and the decoders are the same code.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// One fuzz seed per decoder's real shape.
func keychainFuzzSeeds(t testing.TB) (records []byte, unlock []byte, keychain []byte) {
	wrapped := wrappedKey{}
	wrapped.nonce[3] = 9
	records = encodeKeychainRecords(map[string][]byte{"a/b": []byte("value"), "c": {}})
	unlock = (&unlockWrap{
		generation:   3,
		store:        &unlockStoreWrap{generation: 2, wrapped: wrapped},
		pass:         &unlockPassWrap{memoryKibiCount: 8, iterationCount: 1, threadCount: 1, wrapped: wrapped},
		previousKeys: []unlockPreviousKey{{generation: 2, wrapped: wrapped}},
	}).encode()
	keychain = (&keychainWrap{
		networkId: Id{1},
		roots: []keychainRoot{
			{generation: 2, unlockGeneration: 3, wrapped: wrapped},
			{generation: 1, unlockGeneration: 3, wrapped: wrapped},
		},
	}).encode()
	return records, unlock, keychain
}

// The error a decoder gave, held to the rule: a Failed, and the same few words for any input.
func requireFixedDecodeError(t *testing.T, err error, want error) {
	t.Helper()
	if !errors.Is(err, ErrSidecarStoreFailed) {
		t.Fatalf("err %v", err)
	}
	if err.Error() != want.Error() {
		t.Fatalf("err %q varies with its input", err)
	}
}

func FuzzDecodeKeychainRecords(f *testing.F) {
	records, _, _ := keychainFuzzSeeds(f)
	f.Add(records)
	f.Add([]byte{})
	f.Add([]byte("URKR\x01\xff\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		nameValues, err := decodeKeychainRecords(encoded)
		if err != nil {
			requireFixedDecodeError(t, err, errKeychainRecordsFormat)
			return
		}
		if !bytes.Equal(encodeKeychainRecords(nameValues), encoded) {
			t.Error("two encodings of one keychain")
		}
	})
}

func FuzzDecodeUnlockWrap(f *testing.F) {
	_, unlock, _ := keychainFuzzSeeds(f)
	f.Add(unlock)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		wrap, err := decodeUnlockWrap(encoded)
		if err != nil {
			requireFixedDecodeError(t, err, errUnlockWrapFormat)
			return
		}
		if !bytes.Equal(wrap.encode(), encoded) {
			t.Error("two encodings of one wrap")
		}
		if wrap.pass != nil && !wrap.pass.costFits() {
			t.Error("a cost past the bounds decoded")
		}
		if wrap.store == nil && wrap.pass == nil {
			t.Error("a wrap nothing can open decoded")
		}
	})
}

func FuzzDecodeKeychainWrap(f *testing.F) {
	_, _, keychain := keychainFuzzSeeds(f)
	f.Add(keychain)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		wrap, err := decodeKeychainWrap(encoded)
		if err != nil {
			requireFixedDecodeError(t, err, errKeychainWrapFormat)
			return
		}
		if !bytes.Equal(wrap.encode(), encoded) {
			t.Error("two encodings of one wrap")
		}
		if len(wrap.roots) == 0 {
			t.Error("a wrap with no root decoded")
		}
	})
}

func FuzzDecodeStateDocument(f *testing.F) {
	id := Id{1}
	seed, err := (&sidecarStateDocument{
		Version:        stateJsonVersion,
		InstanceId:     id,
		NetworkRecords: []SidecarNetworkRecord{{NetworkId: id, ClientId: id, SidecarId: id, ConnectInstanceId: id}},
	}).encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		document, err := decodeStateDocument(encoded)
		if err != nil {
			requireFixedDecodeError(t, err, errStateJsonFormat)
			return
		}
		again, err := document.encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeStateDocument(again); err != nil {
			t.Errorf("what decoded does not decode again: %v", err)
		}
	})
}

// A sealed file under a key nobody fuzzing holds: no bytes get past it, and none make it panic.
func FuzzOpenSealedFile(f *testing.F) {
	good := sealTestFile(&testing.T{}, sealTestHeader(), sealTestKey, "evs/a", []byte("synthetic"))
	f.Add(good)
	f.Add(good[:len(good)-1])
	f.Add([]byte{})
	f.Add([]byte("URSF\x01"))
	f.Fuzz(func(t *testing.T, sealed []byte) {
		in := bytes.NewReader(sealed)
		header, err := readSealHeader(in)
		if err != nil {
			if !errors.Is(err, ErrSidecarStoreFailed) {
				t.Fatalf("err %v", err)
			}
			return
		}
		plaintext, err := io.ReadAll(newSealReader(in, header, "evs/a", sealTestAead(sealTestKey)))
		if err != nil {
			if !errors.Is(err, ErrSidecarStoreFailed) {
				t.Fatalf("err %v", err)
			}
			return
		}
		if !bytes.Equal(sealed, good) {
			t.Errorf("%d forged bytes opened to %q", len(sealed), plaintext)
		}
	})
}
