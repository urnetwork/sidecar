// §16.7's spool (record_spool.go, record_spool_locked.go): capture while locked drained at unlock in order, taint
// first; keys turning at each unlock with an old epoch still draining; the cap dropping and counting; a drain killed
// midway resuming; a locked start with no key counting a gap; and no plaintext or key on the medium.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Spool settings a test can fill: small segments, a cursor every two records.
func testSpoolSettings() *SidecarIngestSettings {
	settings := defaultSidecarIngestSettings()
	settings.SpoolSegmentByteCount = 512
	settings.SpoolCursorRecordCount = 2
	return settings
}

// An unlocked, enrolled instance on a memory medium, and a spool on it.
func newTestSpool(t *testing.T, settings *SidecarIngestSettings) (*SidecarInstance, SidecarStoreBackend, *Spool) {
	t.Helper()
	instance, backend, _ := enrolledInstance(t)
	spool, err := NewSpool(instance.Store(&testNetworkId), settings)
	if err != nil {
		t.Fatal(err)
	}
	return instance, backend, spool
}

// A capture record of text.
func testSpoolCapture(text string) *SpoolRecord {
	return &SpoolRecord{Kind: SpoolRecordCapture, RunId: Id{0x0a}, Bytes: []byte(text)}
}

// Spools each text as a capture record, which must take.
func spoolTestTexts(t *testing.T, spool *Spool, texts ...string) {
	t.Helper()
	for _, text := range texts {
		if err := spool.Append(testSpoolCapture(text)); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
	}
}

// Drains spool, answering what came out, in order, as kind:text.
func drainTestSpool(t *testing.T, spool *Spool) []string {
	t.Helper()
	drained := []string{}
	err := spool.Drain(context.Background(), func(id SpoolRecordId, record *SpoolRecord) error {
		drained = append(drained, fmt.Sprintf("%d:%s", record.Kind, record.Bytes))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return drained
}

// Fails unless got is want.
func requireDrained(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("drained %v, want %v", got, want)
	}
}

// Relocks and unlocks instance, as an auto-lock and the person's unlock do.
func lockTestInstance(t *testing.T, instance *SidecarInstance) {
	t.Helper()
	instance.Lock()
}

// Unlocks instance, which must take.
func unlockTestInstance(t *testing.T, instance *SidecarInstance) {
	t.Helper()
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolWhileLockedThenDrain(t *testing.T) {
	// room for both locked records in one segment, whose header alone holds X-Wing's 1,120-byte enc
	settings := testSpoolSettings()
	settings.SpoolSegmentByteCount = 64 * 1024
	instance, backend, spool := newTestSpool(t, settings)
	spoolTestTexts(t, spool, "before the lock")
	lockTestInstance(t, instance)
	spoolTestTexts(t, spool, "locked one", "locked two")
	if err := spool.Drain(context.Background(), func(SpoolRecordId, *SpoolRecord) error { return nil }); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a locked drain answered %v", err)
	}
	locked, err := backend.List(networkFilePath(testNetworkId, "ingest/spool/"))
	if err != nil {
		t.Fatal(err)
	}
	if len(locked) != 2 || !strings.HasSuffix(locked[1].Name, spoolLockedSuffix) {
		t.Fatalf("segments %+v", locked)
	}
	unlockTestInstance(t, instance)
	requireDrained(t, drainTestSpool(t, spool), "1:before the lock", "1:locked one", "1:locked two")
	if remaining, _ := backend.List(networkFilePath(testNetworkId, "ingest/spool/")); len(remaining) != 0 {
		t.Errorf("drained segments stayed: %+v", remaining)
	}
	if spool.ByteCount() != 0 {
		t.Errorf("%d bytes counted after the drain", spool.ByteCount())
	}
	requireDrained(t, drainTestSpool(t, spool))
}

// Each unlock turns the key pair, and a locked segment of an old epoch still drains; the drain takes old epochs'
// keys with their segments.
func TestKeyRotatesAtUnlock(t *testing.T) {
	instance, backend, spool := newTestSpool(t, testSpoolSettings())
	spoolTestTexts(t, spool, "epoch one")
	lockTestInstance(t, instance)
	spoolTestTexts(t, spool, "sealed to one")
	unlockTestInstance(t, instance)
	spoolTestTexts(t, spool, "epoch two")
	lockTestInstance(t, instance)
	spoolTestTexts(t, spool, "sealed to two")
	epochs, err := backend.List(networkFilePath(testNetworkId, "ingest/"+spoolEpochDirectoryName+"/"))
	if err != nil {
		t.Fatal(err)
	}
	if len(epochs) != 2 {
		t.Fatalf("%d epochs", len(epochs))
	}
	first := readBackend(t, backend, epochs[0].Name)
	second := readBackend(t, backend, epochs[1].Name)
	if bytes.Equal(first[spoolEpochFixedByteCount:], second[spoolEpochFixedByteCount:]) {
		t.Error("an unlock kept the key pair")
	}
	unlockTestInstance(t, instance)
	requireDrained(t, drainTestSpool(t, spool), "1:epoch one", "1:sealed to one", "1:epoch two", "1:sealed to two")
	remaining, err := backend.List(networkFilePath(testNetworkId, "ingest/"+spoolEpochDirectoryName+"/"))
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Errorf("%d epochs after the drain, want the current one", len(remaining))
	}
	names, err := instance.secrets(testNetworkId, spoolSecretsNamespace).List(spoolEpochDirectoryName + "/")
	if err != nil || len(names) != 1 {
		t.Errorf("keychain holds %v, err %v", names, err)
	}
}

// Past the cap a record is dropped at once and counted, locked or not.
func TestCapDropsAndCountsGap(t *testing.T) {
	settings := testSpoolSettings()
	settings.SpoolByteCount = 300
	instance, _, spool := newTestSpool(t, settings)
	taken := 0
	dropped := 0
	for i := 0; i < 10; i += 1 {
		err := spool.Append(testSpoolCapture(strings.Repeat("x", 40)))
		switch {
		case err == nil:
			taken += 1
		case errors.Is(err, ErrSpoolFull):
			dropped += 1
		default:
			t.Fatal(err)
		}
	}
	if taken == 0 || dropped == 0 || spool.TakeDropCount() != dropped || spool.TakeDropCount() != 0 {
		t.Errorf("taken %d, dropped %d", taken, dropped)
	}
	lockTestInstance(t, instance)
	if err := spool.Append(testSpoolCapture(strings.Repeat("y", 40))); !errors.Is(err, ErrSpoolFull) {
		t.Errorf("a locked append past the cap answered %v", err)
	}
	if spool.TakeDropCount() != 1 {
		t.Error("the locked drop was not counted")
	}
	unlockTestInstance(t, instance)
	if drained := drainTestSpool(t, spool); len(drained) != taken {
		t.Errorf("drained %d, took %d", len(drained), taken)
	}
	spoolTestTexts(t, spool, "room again")
}

// Taint records come first, each in capture order, then every other record in capture order, across segments and
// epochs.
func TestDrainOrder(t *testing.T) {
	instance, _, spool := newTestSpool(t, testSpoolSettings())
	appendRecord := func(kind SpoolRecordKind, text string) {
		if err := spool.Append(&SpoolRecord{Kind: kind, Bytes: []byte(text)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 12; i += 1 {
		appendRecord(SpoolRecordCapture, fmt.Sprintf("c%02d %s", i, strings.Repeat("p", 60)))
		if i%5 == 2 {
			appendRecord(SpoolRecordTaint, fmt.Sprintf("t%02d", i))
		}
		if i == 6 {
			lockTestInstance(t, instance)
		}
	}
	unlockTestInstance(t, instance)
	drained := drainTestSpool(t, spool)
	want := []string{"2:t02", "2:t07"}
	for i := 0; i < 12; i += 1 {
		want = append(want, fmt.Sprintf("1:c%02d %s", i, strings.Repeat("p", 60)))
	}
	requireDrained(t, drained, want...)
}

// A drain stopped midway, as a kill would, starts again at its cursor; a consumer that keeps the last id it took
// skips what comes again, and every record is taken once.
func TestKillMidDrainResumes(t *testing.T) {
	_, _, spool := newTestSpool(t, testSpoolSettings())
	texts := []string{}
	for i := 0; i < 9; i += 1 {
		texts = append(texts, fmt.Sprintf("record %d %s", i, strings.Repeat("q", 50)))
	}
	spoolTestTexts(t, spool, texts...)
	killed := errors.New("synthetic kill")
	var lastTaken *SpoolRecordId
	taken := []string{}
	deliveredCount := 0
	consume := func(stopAfter int) func(id SpoolRecordId, record *SpoolRecord) error {
		return func(id SpoolRecordId, record *SpoolRecord) error {
			if 0 < stopAfter && deliveredCount == stopAfter {
				return killed
			}
			deliveredCount += 1
			if lastTaken != nil && id.Compare(*lastTaken) <= 0 {
				return nil
			}
			taken = append(taken, string(record.Bytes))
			lastTaken = &id
			return nil
		}
	}
	if err := spool.Drain(context.Background(), consume(5)); !errors.Is(err, killed) {
		t.Fatalf("the first drain answered %v", err)
	}
	if err := spool.Drain(context.Background(), consume(0)); err != nil {
		t.Fatal(err)
	}
	if strings.Join(taken, ",") != strings.Join(texts, ",") {
		t.Errorf("took %v", taken)
	}
	if deliveredCount <= len(texts) {
		t.Logf("%d deliveries for %d records", deliveredCount, len(texts))
	}
}

// A daemon that starts locked with no key pair on disk counts each record a gap; one that starts locked after an
// unlock seals to the epoch on disk.
func TestStartLockedWithNoKeyIsGap(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	lockTestInstance(t, instance)
	spool, err := NewSpool(instance.Store(&testNetworkId), testSpoolSettings())
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Append(testSpoolCapture("no key")); !errors.Is(err, ErrSpoolNoKey) {
		t.Errorf("answered %v", err)
	}
	if spool.TakeDropCount() != 1 {
		t.Error("the gap was not counted")
	}

	unlockTestInstance(t, instance)
	spoolTestTexts(t, spool, "unlocked")
	lockTestInstance(t, instance)
	restarted, err := NewSpool(instance.Store(&testNetworkId), testSpoolSettings())
	if err != nil {
		t.Fatal(err)
	}
	spoolTestTexts(t, restarted, "after a locked restart")
	unlockTestInstance(t, instance)
	requireDrained(t, drainTestSpool(t, restarted), "1:unlocked", "1:after a locked restart")
}

// A locked segment whose epoch's key is gone is unreadable for good: counted as dropped and removed, never read.
func TestSegmentWithLostKeyIsDropped(t *testing.T) {
	instance, _, spool := newTestSpool(t, testSpoolSettings())
	spoolTestTexts(t, spool, "kept")
	lockTestInstance(t, instance)
	spoolTestTexts(t, spool, "lost")
	unlockTestInstance(t, instance)
	names, err := instance.secrets(testNetworkId, spoolSecretsNamespace).List(spoolEpochDirectoryName + "/")
	if err != nil || len(names) == 0 {
		t.Fatalf("names %v, err %v", names, err)
	}
	if err := instance.secrets(testNetworkId, spoolSecretsNamespace).Delete(names[0]); err != nil {
		t.Fatal(err)
	}
	requireDrained(t, drainTestSpool(t, spool), "1:kept")
	if spool.TakeDropCount() != 1 {
		t.Error("the unreadable segment was not counted")
	}
}

// No record's bytes reach the medium in the clear, locked or unlocked.
func TestSpoolCanary(t *testing.T) {
	instance, backend, spool := newTestSpool(t, testSpoolSettings())
	canary := "synthetic-canary-0b7c1e"
	spoolTestTexts(t, spool, canary+" unlocked")
	lockTestInstance(t, instance)
	spoolTestTexts(t, spool, canary+" locked")
	for path, content := range backendSnapshot(t, backend) {
		if bytes.Contains(content, []byte(canary)) {
			t.Errorf("%s holds the canary", path)
		}
	}
}

// A depositor keeps its deposits until the ingester's mark passes them.
func TestKeptDepositsPruneAtTheMark(t *testing.T) {
	_, _, spool := newTestSpool(t, testSpoolSettings())
	logId := Id{0x0b}
	for version := uint64(1); version <= 4; version += 1 {
		if err := spool.Keep(logId, version, []byte(fmt.Sprintf("deposit %d", version))); err != nil {
			t.Fatal(err)
		}
	}
	if removed, err := spool.PruneKept(logId, 2); err != nil || removed != 2 {
		t.Fatalf("pruned %d, err %v", removed, err)
	}
	kept := []string{}
	err := spool.Kept(logId, func(version uint64, deposit []byte) error {
		kept = append(kept, fmt.Sprintf("%d:%s", version, deposit))
		return nil
	})
	if err != nil || strings.Join(kept, ",") != "3:deposit 3,4:deposit 4" {
		t.Errorf("kept %v, err %v", kept, err)
	}
}

// A keychain rotation moves the sealed segments to the new root and leaves the locked ones and the epoch files, which
// no root seals, where they are; the drain reads all of them after it.
func TestSpoolSurvivesRotation(t *testing.T) {
	instance, _, spool := newTestSpool(t, testSpoolSettings())
	spoolTestTexts(t, spool, "sealed")
	lockTestInstance(t, instance)
	spoolTestTexts(t, spool, "locked")
	unlockTestInstance(t, instance)
	if err := instance.RotateKeychain(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	requireDrained(t, drainTestSpool(t, spool), "1:sealed", "1:locked")
}

// A clock stepped back across a restart still draws segment ids above every one on disk, so capture order and a
// consumer's last id hold.
func TestSegmentIdsKeepGrowing(t *testing.T) {
	instance, _, spool := newTestSpool(t, testSpoolSettings())
	spoolTestTexts(t, spool, "first")
	restarted, err := NewSpool(instance.Store(&testNetworkId), testSpoolSettings())
	if err != nil {
		t.Fatal(err)
	}
	// as a step back of the clock would leave it: the last id far ahead of any NewId
	restarted.lastSegmentId = Id{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}
	spoolTestTexts(t, restarted, "second")
	ids := []SpoolRecordId{}
	err = restarted.Drain(context.Background(), func(id SpoolRecordId, record *SpoolRecord) error {
		ids = append(ids, id)
		return nil
	})
	if err != nil || len(ids) != 2 || 0 <= ids[0].Compare(ids[1]) {
		t.Errorf("ids %+v, err %v", ids, err)
	}
	if ids[1].SegmentId.Cmp(Id{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}) <= 0 {
		t.Errorf("segment %s is not past the last", ids[1].SegmentId)
	}
}
