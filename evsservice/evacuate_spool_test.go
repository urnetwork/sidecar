// A kept format-2 record on its way to a container, without its staged bytes (§11.13's staged row): the move's spool
// read and the container's length rule, both found by FS-72's rollback case (EVS2-M10-30).

package evsservice

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A run over a committed staged push and a commit after it in the same minute: the staged record reaches its parcel
// without its staged bytes and the one after it whole, each read back through pidx/ as its own bytes, and the batches
// go. The move once read each kept record back from its spool at its place's length, which for a format-2 record
// counts the staged bytes the spool no longer holds, so the parcel held the record with the next one's head after
// it, which no reader could parse.
func TestEvacuationMovesAStagedRecordAtItsSpooledLength(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	fixture.openFormat2Checked()
	fixture.commitStaged(checkTestPath("small"), 0, 1, "one", 1)
	stagedPlace := windowEntryAt(fixture.head().Head, 1).Place
	batchRecordBytes, err := fixture.readRecord(fixture.check.refId, stagedPlace)
	if err != nil {
		t.Fatal(err)
	}
	record, tail, err := sidecar.ParseEvsBatchRecordFormat2(batchRecordBytes)
	if err != nil || tail.Empty() {
		t.Fatalf("the staged push's record: %v", err)
	}
	stripped := sidecar.EvsBatchRecordBytesWithoutStaged(record, tail)
	if len(stripped) == len(batchRecordBytes) {
		t.Fatal("the staged record keeps its length without its staged bytes")
	}
	nextPlace, nextBytes := fixture.commit("after")
	fixture.age()
	result := fixture.mustRun()
	if result.KeptCount != 2 || result.StagedWrittenCount != 1 || result.MinuteWaitingCount != 0 || result.BatchDeletedCount == 0 {
		t.Fatalf("the run: %+v", result)
	}
	if keys := fixture.keys("meta-1", "pb/"); len(keys) != 0 {
		t.Fatalf("batches left: %v", keys)
	}
	fixture.requireRecord(stagedPlace, stripped)
	fixture.requireRecord(nextPlace, nextBytes)
}

// A container holds a format-2 record without its staged bytes at the record's own length, its pidx/ entry giving
// that length beside its place's; a record cut short of its place is still refused, as is one past it.
func TestContainerHoldsARecordWithoutItsStagedBytes(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	fixture.openFormat2Checked()
	fixture.commitStaged(checkTestPath("small"), 0, 1, "one", 1)
	place := windowEntryAt(fixture.head().Head, 1).Place
	batchRecordBytes, err := fixture.readRecord(fixture.check.refId, place)
	if err != nil {
		t.Fatal(err)
	}
	record, tail, err := sidecar.ParseEvsBatchRecordFormat2(batchRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	stripped := sidecar.EvsBatchRecordBytesWithoutStaged(record, tail)
	held := &ContainerRecord{RefId: fixture.check.refId, Version: 1, Place: place, Bytes: stripped}
	container, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, []*ContainerRecord{held}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys, entries, err := container.EntryKeys(fixture.check.repoId)
	if err != nil || len(keys) != 1 {
		t.Fatalf("entries %v %v", keys, err)
	}
	entry, err := DecodeEvsPidxEntry(entries[0])
	if err != nil || len(entry.GetRecords()) != 1 {
		t.Fatalf("the entry: %v", err)
	}
	if held := entry.GetRecords()[0]; held.GetLength() != uint32(len(stripped)) || held.GetPlace().GetLength() != place.GetLength() {
		t.Fatalf("the entry holds a record of %d bytes at a place of %d", held.GetLength(), held.GetPlace().GetLength())
	}
	for name, recordBytes := range map[string][]byte{"cut short": stripped[:len(stripped)-1], "past its place": append(bytes.Clone(batchRecordBytes), 0)} {
		bad := &ContainerRecord{RefId: fixture.check.refId, Version: 1, Place: place, Bytes: recordBytes}
		if _, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PACK, []*ContainerRecord{bad}, nil); !errors.Is(err, ErrEvsContainerInvalid) {
			t.Errorf("a record %s: %v", name, err)
		}
	}
}
