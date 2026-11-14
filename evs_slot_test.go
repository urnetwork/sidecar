// QD-739's record slot rows in evs's slot format (EVS-FORMAT.md's record slot rows), on every leg: a 64 B row, an
// entry's key || salt, goes through its 104 B block and a slot object and back; the block opens only under its own
// label, repo and generation, as EVS-FORMAT.md spells it, written apart here; a slot never holds keys of two widths;
// 64 rows fit a slot within 8 KiB as RECORD.md section 5.7 counts; and an erasure takes a row's whole block.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A 64 B row no other test shares: its key's 32 B, then its salt's.
func evsTestRecordSlotRow(label string) []byte {
	row := evsTestBytes("record slot row key "+label, RecordKeyByteCount)
	return append(row, evsTestBytes("record slot row salt "+label, RecordSaltByteCount)...)
}

// The 104 B block of row under fek, failing the test on an error.
func evsTestWrapRecordSlotRow(t *testing.T, fek *EvsFekKey, row []byte) []byte {
	t.Helper()
	wrapped, err := EvsWrapRecordSlotRow(fek, row)
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

// A row wraps to 104 B under a fresh nonce, holds neither half in the clear, rides a slot object through its codec,
// and opens back under fek of its generation, the record's split giving the key and the salt.
func TestEvsRecordSlotRowRoundTrip(t *testing.T) {
	if RecordSlotRowByteCount != evsRecordSlotRowByteCount || EvsRecordSlotRowWrappedByteCount != 104 {
		t.Fatalf("a row is %d B to the record and %d B to evs, its block %d B", RecordSlotRowByteCount, evsRecordSlotRowByteCount, EvsRecordSlotRowWrappedByteCount)
	}
	keys := evsTestKeys(t, evsTestId("repo"), 3)
	row := evsTestRecordSlotRow("round trip")
	wrapped := evsTestWrapRecordSlotRow(t, keys.fek, row)
	if len(wrapped) != EvsRecordSlotRowWrappedByteCount {
		t.Fatalf("a block of %d B", len(wrapped))
	}
	if bytes.Contains(wrapped, row[:RecordKeyByteCount]) || bytes.Contains(wrapped, row[RecordKeyByteCount:]) {
		t.Fatal("the block holds the key or the salt in the clear")
	}
	if again := evsTestWrapRecordSlotRow(t, keys.fek, row); bytes.Equal(again, wrapped) {
		t.Fatal("two wraps of one row are one block: the nonce is not fresh")
	}
	slot := &protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 7, Generation: 3, Wrapped: wrapped}}}
	encoded, err := EvsEncodeSlotObject(slot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := EvsDecodeSlotObject(encoded)
	if err != nil || !proto.Equal(decoded, slot) {
		t.Fatalf("the slot back: %v", err)
	}
	slotKey, ok := EvsSlotKeyAt(decoded, 7)
	if !ok {
		t.Fatal("the row's key index is gone")
	}
	opened, err := EvsOpenRecordSlotRow(keys.fek, slotKey)
	if err != nil || !bytes.Equal(opened, row) {
		t.Fatalf("the row back: %v", err)
	}
	key, salt, err := RecordSlotRowSplit(opened)
	if err != nil || !bytes.Equal(key, row[:RecordKeyByteCount]) || !bytes.Equal(salt, row[RecordKeyByteCount:]) {
		t.Fatalf("the row's key and salt: %v", err)
	}
	if _, err := EvsOpenRecordSlotRow(evsTestKeys(t, evsTestId("repo"), 4).fek, slotKey); !errors.Is(err, ErrEvsKeyMissing) {
		t.Errorf("a row opened under fek of another generation: %v", err)
	}
}

// EVS-FORMAT.md's spelling, written apart from evs_slot.go: 24 B nonce | XChaCha20-Poly1305 of the row | 16 B tag,
// AAD "UR evs 1.0 record slot row" || repo_id || u64be(g). A block opens only there: not under another repo's or
// generation's fek, not under the object key's label, not at another width, and not with any byte changed; and an
// object key's 72 B block never opens as a row, nor a row's block as an object key.
func TestEvsRecordSlotRowOpensUnderItsOwnLabelOnly(t *testing.T) {
	repoId := evsTestId("repo")
	keys := evsTestKeys(t, repoId, 2)
	row := evsTestRecordSlotRow("label")
	spelledAad := func(label string, repoId Id, generation uint64) []byte {
		aad := append([]byte(label), repoId.Bytes()...)
		return binary.BigEndian.AppendUint64(aad, generation)
	}
	aead, err := chacha20poly1305.NewX(keys.fek.key)
	if err != nil {
		t.Fatal(err)
	}

	wrapped := evsTestWrapRecordSlotRow(t, keys.fek, row)
	opened, err := aead.Open(nil, wrapped[:24], wrapped[24:], spelledAad("UR evs 1.0 record slot row", repoId, 2))
	if err != nil || !bytes.Equal(opened, row) {
		t.Fatalf("the block does not open as EVS-FORMAT.md spells it: %v", err)
	}
	nonce := evsTestBytes("record slot row nonce", 24)
	spelled := aead.Seal(bytes.Clone(nonce), nonce, row, spelledAad("UR evs 1.0 record slot row", repoId, 2))
	if back, err := EvsUnwrapRecordSlotRow(keys.fek, spelled); err != nil || !bytes.Equal(back, row) {
		t.Fatalf("a block sealed as EVS-FORMAT.md spells it does not unwrap: %v", err)
	}

	refused := map[string]func() error{
		"another repo's fek": func() error {
			_, err := EvsUnwrapRecordSlotRow(evsTestKeys(t, evsTestId("another repo"), 2).fek, wrapped)
			return err
		},
		"another generation's fek": func() error {
			_, err := EvsUnwrapRecordSlotRow(evsTestKeys(t, repoId, 5).fek, wrapped)
			return err
		},
		"the object key's label": func() error {
			_, err := EvsUnwrapRecordSlotRow(keys.fek, aead.Seal(bytes.Clone(nonce), nonce, row, spelledAad("UR evs 1.0 object key", repoId, 2)))
			return err
		},
		"another generation in the aad": func() error {
			_, err := EvsUnwrapRecordSlotRow(keys.fek, aead.Seal(bytes.Clone(nonce), nonce, row, spelledAad("UR evs 1.0 record slot row", repoId, 3)))
			return err
		},
		"an object key's block as a row": func() error {
			objectKeyBlock, err := EvsWrapObjectKey(keys.fek, NewEvsObjectKey())
			if err != nil {
				return err
			}
			_, err = EvsUnwrapRecordSlotRow(keys.fek, objectKeyBlock)
			return err
		},
		"a row's block as an object key": func() error {
			_, err := EvsUnwrapObjectKey(keys.fek, wrapped)
			return err
		},
		"a block a byte short": func() error {
			_, err := EvsUnwrapRecordSlotRow(keys.fek, wrapped[:len(wrapped)-1])
			return err
		},
	}
	for _, place := range []int{0, 23, 24, 87, 88, 103} {
		tampered := bytes.Clone(wrapped)
		tampered[place] ^= 0x01
		refused[fmt.Sprintf("byte %d changed", place)] = func() error {
			_, err := EvsUnwrapRecordSlotRow(keys.fek, tampered)
			return err
		}
	}
	for _, length := range []int{0, 32, 63, 65, 104} {
		refused[fmt.Sprintf("a row of %d B", length)] = func() error {
			_, err := EvsWrapRecordSlotRow(keys.fek, make([]byte, length))
			return err
		}
	}
	for label, refuse := range refused {
		if err := refuse(); !errors.Is(err, ErrEvsSealInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
	if _, err := EvsWrapRecordSlotRow(nil, row); !errors.Is(err, ErrEvsKeyMissing) {
		t.Errorf("a wrap with no fek: %v", err)
	}
	if _, err := EvsUnwrapRecordSlotRow(nil, wrapped); !errors.Is(err, ErrEvsKeyMissing) {
		t.Errorf("an unwrap with no fek: %v", err)
	}
}

// One width a slot: 72 B object keys, 104 B record slot rows or a deposit's HPKE bytes, each alone; a slot mixing two
// of them, in either order, is refused on encode and on decode, and so is any other width.
func TestEvsSlotRefusesKeysOfTwoWidths(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	objectKeyBlock, err := EvsWrapObjectKey(keys.fek, NewEvsObjectKey())
	if err != nil {
		t.Fatal(err)
	}
	widths := map[string][]byte{
		"an object key":     objectKeyBlock,
		"a record slot row": evsTestWrapRecordSlotRow(t, keys.fek, evsTestRecordSlotRow("widths")),
		"a deposit's key":   make([]byte, EvsDepositWrappedKeyByteCount),
	}
	slotOf := func(first []byte, second []byte) *protocol.EvsSlotObject {
		return &protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{
			{KeyIndex: 0, Generation: 2, Wrapped: first},
			{KeyIndex: 1, Generation: 2, Wrapped: second},
		}}
	}
	for label, wrapped := range widths {
		if _, err := EvsEncodeSlotObject(slotOf(wrapped, wrapped)); err != nil {
			t.Errorf("a slot of %s twice: %v", label, err)
		}
	}
	refuse := func(label string, slot *protocol.EvsSlotObject) {
		if _, err := EvsEncodeSlotObject(slot); !errors.Is(err, ErrEvsSealInvalid) {
			t.Errorf("%s encoded: %v", label, err)
		}
		// as evs reads it from a push or the cluster, encoded by anyone
		slotBytes, err := proto.Marshal(slot)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EvsDecodeSlotObject(slotBytes); !errors.Is(err, ErrEvsSealInvalid) {
			t.Errorf("%s decoded: %v", label, err)
		}
	}
	for firstLabel, first := range widths {
		for secondLabel, second := range widths {
			if firstLabel != secondLabel {
				refuse(firstLabel+" then "+secondLabel, slotOf(first, second))
			}
		}
	}
	for _, length := range []int{0, 32, 64, 71, 73, 103, 105, EvsDepositWrappedKeyByteCount - 1} {
		refuse(fmt.Sprintf("a key of %d B", length), slotOf(make([]byte, length), make([]byte, length)))
	}
}

// RECORD.md section 5.7's check against the codec itself: 64 rows of 104 B are 6,656 B of blocks, and the encoded
// slot, its framing and the largest generation included, stays within SlotMaxByteCount; every row opens back; a 65th
// row, or a row at index 64, is refused.
func TestEvsSlotHoldsSixtyFourRecordRowsWithin8KiB(t *testing.T) {
	format := DefaultEvsFormatSettings()
	if blocks := format.SlotMaxKeyCount * EvsRecordSlotRowWrappedByteCount; blocks != 6656 || format.SlotMaxByteCount < blocks {
		t.Fatalf("64 blocks are %d B of a %d B slot", blocks, format.SlotMaxByteCount)
	}
	generation := uint64(math.MaxUint64)
	keys := evsTestKeys(t, evsTestId("repo"), generation)
	slot := &protocol.EvsSlotObject{}
	rows := [][]byte{}
	for keyIndex := range uint32(format.SlotMaxKeyCount) {
		row := evsTestRecordSlotRow(fmt.Sprint("full ", keyIndex))
		rows = append(rows, row)
		slot.Keys = append(slot.Keys, &protocol.EvsSlotKey{KeyIndex: keyIndex, Generation: generation, Wrapped: evsTestWrapRecordSlotRow(t, keys.fek, row)})
	}
	encoded, err := EvsEncodeSlotObject(slot)
	if err != nil {
		t.Fatalf("a full slot of rows: %v", err)
	}
	if format.SlotMaxByteCount < len(encoded) {
		t.Fatalf("a full slot of rows is %d B", len(encoded))
	}
	decoded, err := EvsDecodeSlotObject(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for i, slotKey := range decoded.GetKeys() {
		opened, err := EvsOpenRecordSlotRow(keys.fek, slotKey)
		if err != nil || !bytes.Equal(opened, rows[i]) {
			t.Fatalf("row %d back: %v", i, err)
		}
	}
	past := proto.Clone(slot).(*protocol.EvsSlotObject)
	past.Keys = append(past.Keys, &protocol.EvsSlotKey{KeyIndex: 64, Generation: generation, Wrapped: evsTestWrapRecordSlotRow(t, keys.fek, evsTestRecordSlotRow("past"))})
	if _, err := EvsEncodeSlotObject(past); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("a 65th row: %v", err)
	}
	high := &protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 64, Generation: generation, Wrapped: evsTestWrapRecordSlotRow(t, keys.fek, evsTestRecordSlotRow("high"))}}}
	if _, err := EvsEncodeSlotObject(high); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("a row at index 64: %v", err)
	}
}

// What evs rewrites a record slot to after an ERASE: the erased row's whole block gone, its nonce and tag with it,
// so its key and salt go together; the other rows' blocks byte for byte at their indexes, still opening; and an
// erasure of the gone row again changing nothing.
func TestEvsSlotErasureTakesARecordRowsWholeBlock(t *testing.T) {
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	slot := &protocol.EvsSlotObject{}
	rows := [][]byte{}
	for keyIndex := range uint32(3) {
		row := evsTestRecordSlotRow(fmt.Sprint("erase ", keyIndex))
		rows = append(rows, row)
		slot.Keys = append(slot.Keys, &protocol.EvsSlotKey{KeyIndex: keyIndex, Generation: 2, Wrapped: evsTestWrapRecordSlotRow(t, keys.fek, row)})
	}
	encoded, err := EvsEncodeSlotObject(slot)
	if err != nil {
		t.Fatal(err)
	}
	erasedBlock := slot.Keys[1].GetWrapped()
	rewritten, removedCount, err := EvsSlotWithoutKeys(encoded, []uint32{1})
	if err != nil || removedCount != 1 {
		t.Fatalf("the erasure: %d, %v", removedCount, err)
	}
	for label, part := range map[string][]byte{"block": erasedBlock, "nonce": erasedBlock[:24], "tag": erasedBlock[len(erasedBlock)-16:]} {
		if bytes.Contains(rewritten, part) {
			t.Errorf("the erased row's %s is still in its slot", label)
		}
	}
	after, err := EvsDecodeSlotObject(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := EvsSlotKeyAt(after, 1); ok || len(after.GetKeys()) != 2 {
		t.Fatal("the erased row survives")
	}
	for _, keyIndex := range []uint32{0, 2} {
		slotKey, ok := EvsSlotKeyAt(after, keyIndex)
		if !ok || !bytes.Equal(slotKey.GetWrapped(), slot.Keys[keyIndex].GetWrapped()) {
			t.Fatalf("row %d moved or changed", keyIndex)
		}
		if opened, err := EvsOpenRecordSlotRow(keys.fek, slotKey); err != nil || !bytes.Equal(opened, rows[keyIndex]) {
			t.Fatalf("row %d no longer opens: %v", keyIndex, err)
		}
	}
	if same, removedCount, err := EvsSlotWithoutKeys(rewritten, []uint32{1}); err != nil || removedCount != 0 || !bytes.Equal(same, rewritten) {
		t.Errorf("erasing the gone row again changed the slot: %d, %v", removedCount, err)
	}
}
