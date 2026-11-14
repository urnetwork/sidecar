// record_mirror.go's keys on §16.7's own spool (RECORD-M3-10): a kept deposit's life and version survive the spool's
// names, a prune below a life's first key takes every earlier life and nothing of it, and a spool at its cap drops its
// oldest kept deposit and counts the drop, the gap a run's coverage names (spool_drop).

package sidecar

import (
	"bytes"
	"errors"
	"testing"
)

var _ RecordDepositSpool = (*Spool)(nil)

// The keys spool keeps for logId, in the order kept.
func testSpoolKeptKeys(t *testing.T, spool *Spool, logId Id) []uint64 {
	t.Helper()
	keys := []uint64{}
	err := spool.Kept(logId, func(key uint64, deposit []byte) error {
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestRecordMirrorKeysSurviveTheSpoolsNames(t *testing.T) {
	_, _, spool := newTestSpool(t, testSpoolSettings())
	logId := Id{0x4c}
	earlier, err := recordMirrorKeptKey(0, 7)
	if err != nil {
		t.Fatal(err)
	}
	later, err := recordMirrorKeptKey(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []uint64{earlier, later} {
		if err := spool.Keep(logId, key, []byte("a deposit")); err != nil {
			t.Fatal(err)
		}
	}
	keys := testSpoolKeptKeys(t, spool, logId)
	if len(keys) != 2 || keys[0] != earlier || keys[1] != later {
		t.Fatalf("kept keys %v", keys)
	}
	if recordMirrorKeptLife(keys[0]) != 0 || recordMirrorKeptLife(keys[1]) != 1 {
		t.Fatalf("lives %d and %d", recordMirrorKeptLife(keys[0]), recordMirrorKeptLife(keys[1]))
	}
	floor, err := recordMirrorKeptKey(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if removed, err := spool.PruneKept(logId, floor-1); err != nil || removed != 1 {
		t.Fatalf("pruned %d below the life's first key: %v", removed, err)
	}
	if keys := testSpoolKeptKeys(t, spool, logId); len(keys) != 1 || keys[0] != later {
		t.Fatalf("kept keys %v after the prune", keys)
	}
	if _, err := recordMirrorKeptKey(0, 1<<recordMirrorLifeShift); !errors.Is(err, ErrRecordMirrorVersion) {
		t.Fatalf("a version past the key's bits: %v", err)
	}
}

func TestSpoolAtItsCapDropsTheOldestKeptDepositAndCountsIt(t *testing.T) {
	settings := testSpoolSettings()
	settings.SpoolByteCount = 1024
	_, _, spool := newTestSpool(t, settings)
	logId := Id{0x4c}
	deposit := bytes.Repeat([]byte{0x5a}, 300)
	for version := uint64(1); version <= 5; version += 1 {
		if err := spool.Keep(logId, version, deposit); err != nil {
			t.Fatalf("deposit %d: %v", version, err)
		}
	}
	keys := testSpoolKeptKeys(t, spool, logId)
	if len(keys) == 0 || 5 <= len(keys) || keys[len(keys)-1] != 5 {
		t.Fatalf("kept keys %v at the cap", keys)
	}
	for i, key := range keys {
		if want := uint64(5 - len(keys) + 1 + i); key != want {
			t.Fatalf("kept keys %v: the oldest did not go first", keys)
		}
	}
	if dropped := spool.TakeDropCount(); dropped != 5-len(keys) {
		t.Fatalf("%d drops counted for %d deposits gone", dropped, 5-len(keys))
	}
	if err := spool.Keep(logId, 6, bytes.Repeat([]byte{0x5a}, 2048)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("a deposit past the whole cap: %v", err)
	}
	if dropped := spool.TakeDropCount(); dropped == 0 {
		t.Fatal("a deposit that was not kept counted no drop")
	}
}
