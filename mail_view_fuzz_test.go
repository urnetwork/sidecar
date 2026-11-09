// FuzzMailIndexSegment (MAIL-M7-06, §22.6's segment target): any bytes as an i/ segment, and as an f/ segment, are
// read totally, never a panic or an error from the view, and within a fixed multiple of their size; the writer's
// append onto them either closes them or leaves bytes that read with exactly one more record, the bytes read kept as
// they were. The seeds in testdata/fuzz/FuzzMailIndexSegment/ hold writer-made segments, a newer writer's field, a
// record cut short and a lone tag.

package sidecar

import (
	"bytes"
	"context"
	"runtime"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// The bytes a fuzz run may allocate for one input: a fixed allowance for the view, the writer and the store's
// copies, and a multiple of the input for the keys, entries and ops it decodes.
func mailFuzzAllocationBound(inputByteCount int) uint64 {
	return 4*1024*1024 + 64*uint64(inputByteCount)
}

func FuzzMailIndexSegment(f *testing.F) {
	month := MailYearMonth(202611)
	at := testMailDayMillis(month, 12)
	two := testMailSegment(f, 1, 2, at)
	f.Add(two)
	f.Add(protowire.AppendVarint(protowire.AppendTag(bytes.Clone(two), 2, protowire.VarintType), 9))
	f.Add([]byte{0x0a, 0x05, 0x01})
	f.Add([]byte{0x0a})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, segment []byte) {
		if mailIndexSegmentReadMaxByteCount < len(segment) {
			return
		}
		ctx := context.Background()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		store := newMailTestStore()
		store.put(MailIndexPath(month, 0), segment)
		store.put(MailFlagPath(month, 0), segment)
		view := testMailView(store, nil, nil)
		page, err := view.List(ctx, &MailListArgs{Folder: MailFolderAll, Limit: MailIndexSegmentMaxEntryCount})
		if err != nil {
			t.Fatalf("the view failed: %v", err)
		}
		// every entry listed is a record of the segment, so no more than its bytes allow
		if len(segment)/20+1 < len(page.Entries) {
			t.Fatalf("%d entries from %d bytes", len(page.Entries), len(segment))
		}
		for _, entry := range page.Entries {
			if len(entry.Entry.GetId()) != 16 || MailYearMonthOf(entry.Entry.GetTime()) != month {
				t.Fatalf("an entry broke its month or id: %v", entry.Entry)
			}
		}

		recordCount := 0
		parses := mailSegmentRecords(segment, func(index int, record []byte) error {
			recordCount += 1
			return nil
		}) == nil
		appended, err := NewMailIndexWriter(store, DefaultMailStoreSettings()).Append(ctx, testMailIndexEntry(1<<40, at))
		if err != nil {
			t.Fatalf("the append failed: %v", err)
		}
		written := store.file(appended.Path).content
		switch {
		case appended.Present:
		case appended.Path == MailIndexPath(month, 0):
			// appended in place: only to a segment that parses and had room, keeping its bytes
			if !parses || MailIndexSegmentMaxEntryCount <= recordCount || !bytes.HasPrefix(written, segment) {
				t.Fatalf("appended to a segment it should have closed (parses %t, %d records)", parses, recordCount)
			}
			after := 0
			if err := mailSegmentRecords(written, func(index int, record []byte) error { after += 1; return nil }); err != nil || after != recordCount+1 {
				t.Fatalf("%d records after the append, %v", after, err)
			}
		case appended.Path == MailIndexPath(month, 1):
			if MailIndexSegmentMaxByteCount < len(written) {
				t.Fatal("a new segment past its bound")
			}
		default:
			t.Fatalf("appended to %d bytes elsewhere", len(written))
		}
		if !bytes.Equal(store.file(MailFlagPath(month, 0)).content, segment) {
			t.Fatal("a read changed the f/ segment")
		}

		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		if allocated := after.TotalAlloc - before.TotalAlloc; mailFuzzAllocationBound(len(segment)) < allocated {
			t.Fatalf("%d bytes allocated for %d bytes of input", allocated, len(segment))
		}
	})
}
