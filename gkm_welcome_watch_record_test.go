// The pending record's bytes with its Welcome watches (gkm_group.go's encode, QD-747), on every leg: a record with a
// draft, an owed Welcome and watches reads back as written; one with no watch ends after its owed Welcomes, as
// records did before the watches, and reads back with none; and no shorter or longer run of the bytes reads as a
// record, but the one that ends where the watches begin.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// A record with every part: KF1's draft, one owed Welcome, and two watches, one answered 404.
func testGkmPendingRecordWithWatches() *gkmPendingRecord {
	return &gkmPendingRecord{
		create: &gkmCreateDraft{
			groupId: NewId(),
			repoKey: gkmTestBytes("a pending record's repo key", gkmRepoKeyByteCount),
			request: []byte("a create request"),
		},
		owedWelcomes: []*gkmOwedWelcome{
			{epoch: 7, commitSha256: gkmTestBytes("a pending record's commit", gkmDigestByteCount), request: []byte("a welcome request")},
		},
		watchGroupId: NewId(),
		watchEpoch:   9,
		welcomeWatches: []*gkmWelcomeWatch{
			{epoch: 8, timeMs: 1_700_000_000_123, unwelcomed: true, sidecarIds: []Id{NewId(), NewId()}},
			{epoch: 9, timeMs: 1_700_000_600_456, sidecarIds: []Id{NewId()}},
		},
	}
}

// Whether two records hold the same fields.
func testGkmPendingRecordsEqual(a *gkmPendingRecord, b *gkmPendingRecord) bool {
	if (a.create == nil) != (b.create == nil) {
		return false
	}
	if a.create != nil && (a.create.groupId != b.create.groupId || !bytes.Equal(a.create.repoKey, b.create.repoKey) || !bytes.Equal(a.create.request, b.create.request)) {
		return false
	}
	owedEqual := slices.EqualFunc(a.owedWelcomes, b.owedWelcomes, func(a *gkmOwedWelcome, b *gkmOwedWelcome) bool {
		return a.epoch == b.epoch && bytes.Equal(a.commitSha256, b.commitSha256) && bytes.Equal(a.request, b.request)
	})
	watchesEqual := slices.EqualFunc(a.welcomeWatches, b.welcomeWatches, func(a *gkmWelcomeWatch, b *gkmWelcomeWatch) bool {
		return a.epoch == b.epoch && a.timeMs == b.timeMs && a.unwelcomed == b.unwelcomed && slices.Equal(a.sidecarIds, b.sidecarIds)
	})
	return owedEqual && watchesEqual && a.watchGroupId == b.watchGroupId && a.watchEpoch == b.watchEpoch
}

func TestAPendingRecordWithWelcomeWatchesReadsBackAsWritten(t *testing.T) {
	record := testGkmPendingRecordWithWatches()
	encoded := record.encode()
	decoded, err := decodeGkmPendingRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !testGkmPendingRecordsEqual(record, decoded) {
		t.Errorf("the record read back differs: %+v", decoded)
	}
	if !bytes.Equal(decoded.encode(), encoded) {
		t.Errorf("the record read back encodes to other bytes")
	}
	// watches alone, as a leaf that owes nothing keeps them
	watchesOnly := &gkmPendingRecord{watchGroupId: record.watchGroupId, watchEpoch: record.watchEpoch, welcomeWatches: record.welcomeWatches}
	decoded, err = decodeGkmPendingRecord(watchesOnly.encode())
	if err != nil {
		t.Fatal(err)
	}
	if !testGkmPendingRecordsEqual(watchesOnly, decoded) {
		t.Errorf("a record of watches alone read back differs: %+v", decoded)
	}
}

// A record with no watch is the bytes a record was before QD-747, and names no group or epoch for them.
func TestAPendingRecordWithNoWatchEndsAfterItsOwedWelcomes(t *testing.T) {
	record := testGkmPendingRecordWithWatches()
	withWatches := record.encode()
	record.welcomeWatches = nil
	encoded := record.encode()
	if len(withWatches) <= len(encoded) || !bytes.Equal(withWatches[:len(encoded)], encoded) {
		t.Fatalf("a record with no watch is not the start of the same record with watches")
	}
	decoded, err := decodeGkmPendingRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.welcomeWatches) != 0 || decoded.watchGroupId != (Id{}) || decoded.watchEpoch != 0 {
		t.Errorf("a record with no watch read back with %d, at epoch %d", len(decoded.welcomeWatches), decoded.watchEpoch)
	}
	if len(decoded.watchesAt(record.watchGroupId, record.watchEpoch)) != 0 {
		t.Errorf("a record with no watch holds one at a group")
	}
	record.watchGroupId, record.watchEpoch = Id{}, 0
	if !testGkmPendingRecordsEqual(record, decoded) {
		t.Errorf("the record read back differs: %+v", decoded)
	}
}

// Every run of the record's bytes that is cut short or carries more is refused as malformed, never read as fewer
// watches; the one cut that reads is where the watches begin, which is the record with none.
func TestAPendingRecordCutShortOrLongerIsRefused(t *testing.T) {
	record := testGkmPendingRecordWithWatches()
	encoded := record.encode()
	watchless := *record
	watchless.welcomeWatches = nil
	watchesStart := len(watchless.encode())
	for byteCount := 0; byteCount < len(encoded); byteCount += 1 {
		decoded, err := decodeGkmPendingRecord(encoded[:byteCount])
		if byteCount == watchesStart {
			if err != nil || len(decoded.welcomeWatches) != 0 {
				t.Errorf("the record cut where its watches begin: %v", err)
			}
			continue
		}
		if !errors.Is(err, ErrGkmMalformed) {
			t.Errorf("the record cut to %d of %d bytes was read: %v", byteCount, len(encoded), err)
		}
	}
	if _, err := decodeGkmPendingRecord(append(bytes.Clone(encoded), 0)); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a record with a byte after its watches was read: %v", err)
	}
	// a version this build does not write
	other := bytes.Clone(encoded)
	other[0] += 1
	if _, err := decodeGkmPendingRecord(other); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a record of another version was read: %v", err)
	}
}
