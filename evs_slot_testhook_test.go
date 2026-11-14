//go:build sidecar_testhooks

// Under the tag, a record slot row's unwrap reaches the privacy harness's hook with the row it opened, so §22.7's
// capture scan looks for an entry's key || salt wherever a reader opens one; the wrap hooks nothing, since RecordSeal
// hooked the key and the salt where it drew them, and a block that does not open hooks nothing.

package sidecar

import (
	"testing"
)

func TestEvsHookSeesEveryRecordSlotRowUnwrap(t *testing.T) {
	recorder := mlsRecordHooks(t)
	keys := evsTestKeys(t, evsTestId("repo"), 2)
	rowCount := func() int {
		return len(recorder.kindSecrets["record_slot_row"])
	}
	row := evsTestRecordSlotRow("hook")
	wrapped := evsTestWrapRecordSlotRow(t, keys.fek, row)
	if rowCount() != 0 {
		t.Fatalf("%d rows hooked by the wrap", rowCount())
	}
	opened, err := EvsUnwrapRecordSlotRow(keys.fek, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	recorder.require(t, "record_slot_row", opened)
	if rowCount() != 1 {
		t.Fatalf("%d rows hooked by one unwrap", rowCount())
	}
	tampered := append([]byte{}, wrapped...)
	tampered[40] ^= 0x01
	if _, err := EvsUnwrapRecordSlotRow(keys.fek, tampered); err == nil {
		t.Fatal("a tampered block opened")
	}
	if rowCount() != 1 {
		t.Errorf("%d rows hooked after a block that does not open", rowCount())
	}
}
