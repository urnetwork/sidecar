//go:build !sidecar_http

// record_batch.go's push loop: a batch cut at 64 entries and the rest sent after PushCoalesce on the fake clock, a
// push's slot object holding each of its entries' key and salt at the entry's key_index, and a push refused 412
// GATE_CLOSED built again under new push and slot ids around the same signed bytes. External, as
// record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Waits for a commit's notice, failing the test when the test's context ends first.
func testRecordAwaitCommit(t *testing.T, commits chan struct{}) {
	t.Helper()
	select {
	case <-commits:
	case <-t.Context().Done():
		t.Fatal("no commit came")
	}
}

// §16.8's batch row on the loop itself: 64 entries go in one push as soon as they wait, and a 65th waits for
// PushCoalesce, a timer on the fake clock, then goes alone.
func TestRecordBatchCutsAt64EntriesAndAfterTheCoalesceWait(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	commits := make(chan struct{}, 64)
	unsubscribe := world.streams.For(world.readerId).Subscribe(world.vaultId, func(repoId sidecar.Id) {
		select {
		case commits <- struct{}{}:
		default:
		}
	})
	defer unsubscribe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		record.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	for index := range 65 {
		testRecordAppend(t, record, testRecordNote(nil, fmt.Sprintf("note %d", index)))
	}
	testRecordAwaitCommit(t, commits)
	stored := world.storedEntries(device.sidecarId)
	if len(stored) != 64 || stored[63].version != 1 {
		t.Fatalf("the first push holds %d entries", len(stored))
	}
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(device.settings.PushCoalesce)
	testRecordAwaitCommit(t, commits)
	stored = world.storedEntries(device.sidecarId)
	if len(stored) != 65 || stored[64].version != 2 || stored[64].header.GetSeq() != 65 {
		t.Fatalf("after the wait the stream holds %d entries", len(stored))
	}
}

// A push's one slot object holds 64 rows, each its entry's key || salt at the key_index the entry names, which opens
// that entry's body; wrapped at 104 B a row, the object stays inside 8 KiB.
func TestRecordBatchSlotObjectHoldsEachEntrysKey(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	for index := range 64 {
		testRecordAppend(t, record, testRecordNote(nil, fmt.Sprintf("note %d", index)))
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	stored := world.storedEntries(device.sidecarId)
	if len(stored) != 64 {
		t.Fatalf("%d entries", len(stored))
	}
	seen := map[uint32]bool{}
	for index, item := range stored {
		if item.version != 1 || item.slotId != stored[0].slotId || seen[item.keyIndex] || item.body == nil {
			t.Fatalf("entry %d: version %d, slot %s, key_index %d", index, item.version, item.slotId, item.keyIndex)
		}
		seen[item.keyIndex] = true
	}
	slot, err := world.streams.For(world.readerId).ReadSlot(t.Context(), world.vaultId, stored[0].slotId)
	if err != nil {
		t.Fatal(err)
	}
	if len(slot.Rows) != 64 {
		t.Fatalf("the slot object holds %d rows", len(slot.Rows))
	}
	for _, row := range slot.Rows {
		if len(row.Row) != sidecar.RecordSlotRowByteCount {
			t.Fatalf("a row of %d bytes", len(row.Row))
		}
	}
	// a row wrapped under fek_g: its nonce and tag besides
	if wrapped := len(slot.Rows) * (sidecar.RecordSlotRowByteCount + 24 + 16); 8*1024 < wrapped {
		t.Errorf("a full slot object wraps to %d bytes", wrapped)
	}
}

// A push refused 412 GATE_CLOSED spends its push id: the next attempt is a new push id and slot id, with new rows, and
// the very same signed headers and sealed bodies, since key_slot_id and key_index lie outside the signed header.
func TestRecordBatchRebuildAfterGateClosedDrawsNewIdsAndSignsNothing(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	testRecordAppend(t, record, testRecordNote(nil, "one"))
	testRecordAppend(t, record, testRecordNote(nil, "two"))
	world.streams.SetGateClosed(world.vaultId, true)
	err := record.Flush(t.Context())
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED {
		t.Fatalf("a closed gate: %v", err)
	}
	world.streams.SetGateClosed(world.vaultId, false)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if count := device.tap.pushCount(); count != 2 {
		t.Fatalf("%d pushes", count)
	}
	refused, rebuilt := device.tap.pushes[0], device.tap.pushes[1]
	if refused.PushId == rebuilt.PushId || refused.SlotId == rebuilt.SlotId {
		t.Fatal("the rebuilt push kept a spent id")
	}
	for index := range refused.Entries {
		before := &protocol.RecordEntry{}
		after := &protocol.RecordEntry{}
		if err := proto.Unmarshal(refused.Entries[index].Entry, before); err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(rebuilt.Entries[index].Entry, after); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(before.GetHeader(), after.GetHeader()) || !bytes.Equal(before.GetSealedBody(), after.GetSealedBody()) {
			t.Errorf("entry %d was sealed or signed again", index)
		}
		if !bytes.Equal(after.GetKeySlotId(), rebuilt.SlotId[:]) {
			t.Errorf("entry %d names slot %x, not the rebuilt push's", index, after.GetKeySlotId())
		}
	}
	if got := testRecordTexts(t, world.storedEntries(device.sidecarId)); len(got) != 2 {
		t.Fatalf("the stream holds %v", got)
	}
}
