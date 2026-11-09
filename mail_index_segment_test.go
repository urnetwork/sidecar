// MAIL-M7-06's i/ writer on the in-memory store: a segment closes at each bound, an append keeps what it read byte
// for byte, a racing write's conflict reads again, an entry already there is not appended twice, and every refusal
// the store gives that a retry cannot pass comes back at once. Every name is synthetic.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// 00:00 UTC on day of month, in ms.
func testMailDayMillis(month MailYearMonth, day int) uint64 {
	return uint64(time.Date(month.Year(), month.Month(), day, 0, 0, 0, 0, time.UTC).UnixMilli())
}

// A synthetic message id: n in its last 8 bytes.
func testMailId(n uint64) Id {
	var id Id
	id[0] = 0x4d
	binary.BigEndian.PutUint64(id[8:], n)
	return id
}

// A small entry for message n at timeMillis.
func testMailIndexEntry(n uint64, timeMillis uint64) *protocol.IndexEntry {
	return &protocol.IndexEntry{
		Id:      testMailId(n).Bytes(),
		Address: "id@k3j4h5g6f7.root.example",
		Time:    timeMillis,
		From:    "Sender <sender@sender.example>",
		Subject: fmt.Sprintf("message %d", n),
		Size:    1000 + n,
	}
}

// An entry's record, as a writer encodes it.
func testMailRecord(t testing.TB, entry *protocol.IndexEntry) []byte {
	t.Helper()
	record, err := mailIndexEntryRecord(entry)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// The ids of a segment's records, in order.
func testMailSegmentIds(t testing.TB, segment []byte) []Id {
	t.Helper()
	ids := []Id{}
	if err := mailSegmentRecords(segment, func(index int, record []byte) error {
		id, _, ok := mailIndexRecordKey(record)
		if !ok {
			t.Fatalf("record %d has no key", index)
		}
		ids = append(ids, id)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ids
}

// A segment holding count entries numbered from first.
func testMailSegment(t testing.TB, first uint64, count int, timeMillis uint64) []byte {
	t.Helper()
	segment := []byte{}
	for index := range count {
		segment = mailSegmentAppend(segment, testMailRecord(t, testMailIndexEntry(first+uint64(index), timeMillis)))
	}
	return segment
}

// 4,096 entries close a segment: the 4,096th goes into it, the next starts segment 1.
func TestMailIndexWriterClosesASegmentAtTheEntryBound(t *testing.T) {
	ctx := context.Background()
	store := newMailTestStore()
	month := MailYearMonth(202611)
	at := testMailDayMillis(month, 3)
	store.put(MailIndexPath(month, 0), testMailSegment(t, 0, MailIndexSegmentMaxEntryCount-1, at))
	writer := NewMailIndexWriter(store, DefaultMailStoreSettings())

	appended, err := writer.Append(ctx, testMailIndexEntry(10000, at))
	if err != nil || appended.Path != MailIndexPath(month, 0) || appended.Present {
		t.Fatalf("the 4,096th: %+v, %v", appended, err)
	}
	if ids := testMailSegmentIds(t, store.file(MailIndexPath(month, 0)).content); len(ids) != MailIndexSegmentMaxEntryCount || ids[len(ids)-1] != testMailId(10000) {
		t.Fatalf("segment 0 holds %d", len(ids))
	}
	appended, err = writer.Append(ctx, testMailIndexEntry(10001, at))
	if err != nil || appended.Path != MailIndexPath(month, 1) || appended.Version != 1 {
		t.Fatalf("the 4,097th: %+v, %v", appended, err)
	}
	if ids := testMailSegmentIds(t, store.file(MailIndexPath(month, 1)).content); len(ids) != 1 || ids[0] != testMailId(10001) {
		t.Errorf("segment 1 holds %v", ids)
	}
	if ids := testMailSegmentIds(t, store.file(MailIndexPath(month, 0)).content); len(ids) != MailIndexSegmentMaxEntryCount {
		t.Errorf("a closed segment changed: %d", len(ids))
	}
}

// 1 MiB closes a segment: an entry that ends exactly at 1,048,576 bytes goes into it, one a byte longer starts the
// next, and every segment stays under the 1,088 KiB a re-checkpoint may rewrite.
func TestMailIndexWriterClosesASegmentAtTheByteBound(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202612)
	at := testMailDayMillis(month, 9)
	// fill with large entries, then size the last so the segment lands exactly on the bound
	filler := func(n uint64, subjectByteCount int) *protocol.IndexEntry {
		entry := testMailIndexEntry(n, at)
		entry.Subject = strings.Repeat("s", subjectByteCount)
		return entry
	}
	base := []byte{}
	n := uint64(0)
	for {
		next := mailSegmentAppend(base, testMailRecord(t, filler(n, 2*1024)))
		if MailIndexSegmentMaxByteCount-8*1024 < len(next) {
			break
		}
		base, n = next, n+1
	}
	// the subject length that ends the segment at exactly the bound
	exact := 0
	for subjectByteCount := 0; subjectByteCount < 12*1024; subjectByteCount += 1 {
		if len(base)+mailSegmentRecordByteCount(testMailRecord(t, filler(900, subjectByteCount))) == MailIndexSegmentMaxByteCount {
			exact = subjectByteCount
			break
		}
	}
	if exact == 0 || MailIndexEntryMaxByteCount < len(testMailRecord(t, filler(900, exact))) {
		t.Fatalf("no subject length lands on the bound (%d)", exact)
	}
	for _, c := range []struct {
		subjectByteCount int
		wantSegment      uint64
	}{
		{subjectByteCount: exact, wantSegment: 0},
		{subjectByteCount: exact + 1, wantSegment: 1},
	} {
		store := newMailTestStore()
		store.put(MailIndexPath(month, 0), base)
		appended, err := NewMailIndexWriter(store, DefaultMailStoreSettings()).Append(ctx, filler(900, c.subjectByteCount))
		if err != nil || appended.Path != MailIndexPath(month, c.wantSegment) {
			t.Errorf("subject of %d: %+v, %v", c.subjectByteCount, appended, err)
			continue
		}
		for _, path := range store.paths() {
			if size := len(store.file(path).content); MailIndexSegmentMaxByteCount < size {
				t.Errorf("%d bytes in a segment", size)
			}
		}
	}
}

// An append adds its record to the bytes it read and re-encodes nothing, so a field a newer writer added, in the
// segment or inside an entry, stays as it was.
func TestMailIndexWriterKeepsWhatItRead(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	at := testMailDayMillis(month, 4)
	newer := testMailRecord(t, testMailIndexEntry(1, at))
	newer = protowire.AppendTag(newer, 99, protowire.BytesType)
	newer = protowire.AppendBytes(newer, []byte("a newer writer's field"))
	segment := mailSegmentAppend(nil, newer)
	segment = protowire.AppendTag(segment, 2, protowire.VarintType)
	segment = protowire.AppendVarint(segment, 7)
	store := newMailTestStore()
	store.put(MailIndexPath(month, 0), segment)
	if _, err := NewMailIndexWriter(store, DefaultMailStoreSettings()).Append(ctx, testMailIndexEntry(2, at)); err != nil {
		t.Fatal(err)
	}
	written := store.file(MailIndexPath(month, 0)).content
	if !bytes.HasPrefix(written, segment) {
		t.Fatal("the bytes read were rewritten")
	}
	decoded := &protocol.MailIndexSegment{}
	if err := proto.Unmarshal(written, decoded); err != nil || len(decoded.GetEntries()) != 2 {
		t.Fatalf("%d entries, %v", len(decoded.GetEntries()), err)
	}
	if !bytes.Equal(decoded.GetEntries()[1].GetId(), testMailId(2).Bytes()) {
		t.Error("the appended entry is not last")
	}
}

// A racing writer that lands between this writer's read and its write: the write conflicts, the writer reads again
// and appends after it, so both entries stand and neither is lost.
func TestMailIndexWriterReadsAgainAfterARacingWrite(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	at := testMailDayMillis(month, 5)
	store := newMailTestStore()
	writer := NewMailIndexWriter(store, DefaultMailStoreSettings())
	if _, err := writer.Append(ctx, testMailIndexEntry(1, at)); err != nil {
		t.Fatal(err)
	}
	racer := NewMailIndexWriter(store, DefaultMailStoreSettings())
	store.beforeWrite = func() {
		if _, err := racer.Append(ctx, testMailIndexEntry(2, at)); err != nil {
			t.Error(err)
		}
	}
	writesBefore := store.writeCount
	appended, err := writer.Append(ctx, testMailIndexEntry(3, at))
	if err != nil {
		t.Fatal(err)
	}
	ids := testMailSegmentIds(t, store.file(MailIndexPath(month, 0)).content)
	if len(ids) != 3 || ids[0] != testMailId(1) || ids[1] != testMailId(2) || ids[2] != testMailId(3) {
		t.Fatalf("segment holds %v", ids)
	}
	// the racer's write, the refused one and the retry
	if store.writeCount-writesBefore != 3 || appended.Version != 3 {
		t.Errorf("%d writes, version %d", store.writeCount-writesBefore, appended.Version)
	}
}

// A conflict on every attempt gives up after WriteRetryCount reads, giving the conflict back.
func TestMailIndexWriterGivesUpAfterItsRetries(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	at := testMailDayMillis(month, 6)
	store := newMailTestStore()
	settings := DefaultMailStoreSettings()
	settings.WriteRetryCount = 3
	n := uint64(100)
	var race func()
	race = func() {
		n += 1
		store.put(MailIndexPath(month, 0), testMailSegment(t, n, 1, at))
		store.beforeWrite = race
	}
	store.beforeWrite = race
	_, err := NewMailIndexWriter(store, settings).Append(ctx, testMailIndexEntry(1, at))
	if !errors.Is(err, ErrMailStoreConflict) || store.writeCount != settings.WriteRetryCount+1 {
		t.Errorf("%d writes: %v", store.writeCount, err)
	}
}

// An entry already in the newest segment, as after a lost answer, is not appended again.
func TestMailIndexWriterFindsItsOwnEntry(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	entry := testMailIndexEntry(1, testMailDayMillis(month, 7))
	store := newMailTestStore()
	writer := NewMailIndexWriter(store, DefaultMailStoreSettings())
	if _, err := writer.Append(ctx, entry); err != nil {
		t.Fatal(err)
	}
	again, err := writer.Append(ctx, entry)
	if err != nil || !again.Present || again.Path != MailIndexPath(month, 0) || again.Version != 1 {
		t.Fatalf("%+v, %v", again, err)
	}
	if ids := testMailSegmentIds(t, store.file(MailIndexPath(month, 0)).content); len(ids) != 1 || store.writeCount != 1 {
		t.Errorf("%d entries after %d writes", len(ids), store.writeCount)
	}
}

// Ingest's m/ creation rides the same push. A conflict on it comes back at once with nothing written, since only the
// caller knows another reader won; the segment's own conflict is the only one the writer reads again for.
func TestMailIndexWriterGivesBackAConflictOnItsOtherWrites(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	at := testMailDayMillis(month, 8)
	store := newMailTestStore()
	writer := NewMailIndexWriter(store, DefaultMailStoreSettings())
	message := &mailStoreWrite{Path: MailMessagePath(month, testMailId(1)), Content: []byte("From: a\r\n\r\nbody\r\n")}
	appended, err := writer.Append(ctx, testMailIndexEntry(1, at), message)
	if err != nil || len(appended.WithVersions) != 1 || appended.WithVersions[0] != 1 || store.writeCount != 1 {
		t.Fatalf("%+v, %v after %d writes", appended, err, store.writeCount)
	}
	// a second reader racing the same deposit: its m/ creation conflicts and comes back
	other := &mailStoreWrite{Path: MailMessagePath(month, testMailId(1)), Content: []byte("From: a\r\n\r\nbody\r\n")}
	_, err = writer.Append(ctx, testMailIndexEntry(4, at), other)
	if !mailStoreConflictOn(err, other.Path) || store.writeCount != 2 {
		t.Fatalf("%v after %d writes", err, store.writeCount)
	}
	if ids := testMailSegmentIds(t, store.file(MailIndexPath(month, 0)).content); len(ids) != 1 {
		t.Errorf("the refused push appended: %v", ids)
	}
	// an entry already there still lets its other writes go
	third := &mailStoreWrite{Path: MailMessagePath(month, testMailId(9)), Content: []byte("x")}
	appended, err = writer.Append(ctx, testMailIndexEntry(1, at), third)
	if err != nil || !appended.Present || len(appended.WithVersions) != 1 || store.file(third.Path) == nil {
		t.Errorf("%+v, %v", appended, err)
	}
}

// A store refusal no retry passes comes back as it was given, after one write: evs's DIRECTORY_FULL among them.
func TestMailIndexWriterGivesBackDirectoryFull(t *testing.T) {
	ctx := context.Background()
	store := newMailTestStore()
	store.failWrite = &EvsError{Status: 409, Code: protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL}
	_, err := NewMailIndexWriter(store, DefaultMailStoreSettings()).Append(ctx, testMailIndexEntry(1, testMailDayMillis(202611, 9)))
	if !IsMailDirectoryFull(err) || store.writeCount != 1 {
		t.Errorf("%v after %d writes", err, store.writeCount)
	}
}

// An entry no segment holds is refused before anything is read: no 16-byte id, no time, or past 16 KiB.
func TestMailIndexWriterRefusesAnUnfitEntry(t *testing.T) {
	ctx := context.Background()
	at := testMailDayMillis(202611, 10)
	shortId := testMailIndexEntry(1, at)
	shortId.Id = shortId.Id[:15]
	noTime := testMailIndexEntry(1, 0)
	huge := testMailIndexEntry(1, at)
	huge.Subject = strings.Repeat("s", MailIndexEntryMaxByteCount)
	for _, entry := range []*protocol.IndexEntry{shortId, noTime, huge} {
		store := newMailTestStore()
		if _, err := NewMailIndexWriter(store, DefaultMailStoreSettings()).Append(ctx, entry); !errors.Is(err, ErrMailIndexEntryUnfit) || store.readCount != 0 {
			t.Errorf("%v after %d reads", err, store.readCount)
		}
	}
}

// A newest segment that does not parse is closed: the entry starts the next segment, and the bytes stay.
func TestMailIndexWriterClosesASegmentThatDoesNotParse(t *testing.T) {
	ctx := context.Background()
	month := MailYearMonth(202611)
	store := newMailTestStore()
	broken := []byte{0x0a, 0x7f, 0x01}
	store.put(MailIndexPath(month, 0), broken)
	appended, err := NewMailIndexWriter(store, DefaultMailStoreSettings()).Append(ctx, testMailIndexEntry(1, testMailDayMillis(month, 11)))
	if err != nil || appended.Path != MailIndexPath(month, 1) {
		t.Fatalf("%+v, %v", appended, err)
	}
	if !bytes.Equal(store.file(MailIndexPath(month, 0)).content, broken) {
		t.Error("the broken segment was rewritten")
	}
}
