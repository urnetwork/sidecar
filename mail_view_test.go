// MAIL-M7-06's view on the in-memory store: newest first across months, pages that never repeat or skip, folders by
// flags, spam_score and verdicts, group messages through r/ references with both repos' flags, the first of a
// duplicate id kept, whatever breaks MAIL-FORMAT.md passed over and counted, and a 100,000-message mailbox paged
// within §18.4's budget by a working-set test. Every name is synthetic.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The repo ids a view test names.
var (
	testMailMailboxId = testMailId(0xb0)
	testMailGroupId   = testMailId(0xc0)
)

// A view over store and the given group stores, with settings.
func testMailView(store mailStore, groups map[Id]mailStore, settings *MailStoreSettings) *MailView {
	if settings == nil {
		settings = DefaultMailStoreSettings()
	}
	return NewMailView(&MailViewArgs{
		MailboxId: testMailMailboxId,
		Mailbox:   store,
		Groups: func(ctx context.Context, repoId Id) (mailStore, error) {
			if group, ok := groups[repoId]; ok {
				return group, nil
			}
			return nil, ErrEvsPathAbsent
		},
		Settings: settings,
	})
}

// Every page of a folder with limit, joined, and the unreadable count of the first page.
func testMailListAll(t *testing.T, view *MailView, folder MailFolder, label string, limit int) ([]*MailViewEntry, int) {
	t.Helper()
	all := []*MailViewEntry{}
	unreadable := -1
	var after *MailListCursor
	for range 100000 {
		page, err := view.List(context.Background(), &MailListArgs{Folder: folder, Label: label, After: after, Limit: limit})
		if err != nil {
			t.Fatal(err)
		}
		if unreadable < 0 {
			unreadable = page.Unreadable
		}
		all = append(all, page.Entries...)
		if page.Next == nil {
			return all, unreadable
		}
		after = page.Next
	}
	t.Fatal("the pages never end")
	return nil, 0
}

// The numbers of entries' ids, as testMailId made them.
func testMailEntryNumbers(entries []*MailViewEntry) []uint64 {
	numbers := []uint64{}
	for _, entry := range entries {
		id := Id(entry.Entry.GetId())
		numbers = append(numbers, uint64(id[8])<<56|uint64(id[9])<<48|uint64(id[10])<<40|uint64(id[11])<<32|uint64(id[12])<<24|uint64(id[13])<<16|uint64(id[14])<<8|uint64(id[15]))
	}
	return numbers
}

// Appends entries through the writer, so the segments are the writer's.
func testMailAppend(t *testing.T, store mailStore, entries ...*protocol.IndexEntry) {
	t.Helper()
	writer := NewMailIndexWriter(store, DefaultMailStoreSettings())
	for _, entry := range entries {
		if _, err := writer.Append(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
	}
}

// Writes flag changes as a device.
func testMailFlag(t *testing.T, store mailStore, writerNumber uint64, changes ...*MailFlagChange) {
	t.Helper()
	clock := &mailTestClock{now: time.UnixMilli(1793923200000)}
	if _, err := NewMailFlagWriter(store, NewMailHlc(clock), testMailId(writerNumber), DefaultMailStoreSettings()).Apply(context.Background(), changes); err != nil {
		t.Fatal(err)
	}
}

// Newest first across months, then by id where times are equal, whatever order the entries were appended in.
func TestMailViewListsNewestFirstAcrossMonths(t *testing.T) {
	store := newMailTestStore()
	october, november, december := MailYearMonth(202610), MailYearMonth(202611), MailYearMonth(202612)
	testMailAppend(t, store,
		testMailIndexEntry(1, testMailDayMillis(november, 2)),
		testMailIndexEntry(2, testMailDayMillis(october, 30)),
		testMailIndexEntry(3, testMailDayMillis(december, 1)),
		testMailIndexEntry(4, testMailDayMillis(november, 20)),
		testMailIndexEntry(6, testMailDayMillis(november, 2)),
		testMailIndexEntry(5, testMailDayMillis(november, 2)),
	)
	entries, unreadable := testMailListAll(t, testMailView(store, nil, nil), MailFolderAll, "", 100)
	if got := testMailEntryNumbers(entries); !slices.Equal(got, []uint64{3, 4, 6, 5, 1, 2}) || unreadable != 0 {
		t.Errorf("listed %v, %d unreadable", got, unreadable)
	}
	for _, entry := range entries {
		if entry.RepoId != testMailMailboxId || entry.Flags == nil {
			t.Errorf("entry %x: repo %v", entry.Entry.GetId(), entry.RepoId)
		}
	}
}

// Pages of any size join to the full list with nothing repeated or skipped, across months and runs of equal times; a
// later page holds to what the first read, though an entry landed between them, and a first page reads afresh.
func TestMailViewPagesWithoutRepeatOrSkip(t *testing.T) {
	store := newMailTestStore()
	entries := []*protocol.IndexEntry{}
	for n := range uint64(997) {
		month := MailYearMonth(202608 + n%4)
		// runs of equal times inside each month
		entries = append(entries, testMailIndexEntry(n, testMailDayMillis(month, 1+int(n%9))))
	}
	testMailAppend(t, store, entries...)
	want, _ := testMailListAll(t, testMailView(store, nil, nil), MailFolderAll, "", 2000)
	if len(want) != len(entries) {
		t.Fatalf("%d of %d", len(want), len(entries))
	}
	for index := 1; index < len(want); index += 1 {
		previous, current := want[index-1].Entry, want[index].Entry
		if cmp.Or(cmp.Compare(previous.GetTime(), current.GetTime()), mailIdCompare(Id(previous.GetId()), Id(current.GetId()))) <= 0 {
			t.Fatalf("out of order at %d", index)
		}
	}
	for _, limit := range []int{1, 7, 50, 333} {
		got, _ := testMailListAll(t, testMailView(store, nil, nil), MailFolderAll, "", limit)
		if !slices.Equal(testMailEntryNumbers(got), testMailEntryNumbers(want)) {
			t.Errorf("limit %d pages differently", limit)
		}
	}
	// an entry lands newest of all between pages: the snapshot holds, and a first page sees it
	view := testMailView(store, nil, nil)
	first, err := view.List(context.Background(), &MailListArgs{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	testMailAppend(t, store, testMailIndexEntry(5000, testMailDayMillis(202611, 28)))
	rest := first.Entries
	for after := first.Next; after != nil; {
		page, err := view.List(context.Background(), &MailListArgs{Limit: 10, After: after})
		if err != nil {
			t.Fatal(err)
		}
		rest, after = append(rest, page.Entries...), page.Next
	}
	if !slices.Equal(testMailEntryNumbers(rest), testMailEntryNumbers(want)) {
		t.Error("a later page changed after a write")
	}
	fresh, err := view.List(context.Background(), &MailListArgs{Limit: 1})
	if err != nil || testMailEntryNumbers(fresh.Entries)[0] != 5000 {
		t.Errorf("a first page did not read afresh: %v", err)
	}
}

// Folders: trash only in trash; sent apart from the inbox; spam by a person's verdict, which outranks spam_score,
// else by spam_score at the threshold; a label's own folder.
func TestMailViewFolders(t *testing.T) {
	store := newMailTestStore()
	month := MailYearMonth(202611)
	at := func(day int) uint64 { return testMailDayMillis(month, day) }
	scored := func(n uint64, day int, score uint32) *protocol.IndexEntry {
		entry := testMailIndexEntry(n, at(day))
		entry.SpamScore = score
		return entry
	}
	testMailAppend(t, store,
		scored(1, 1, 0),    // inbox
		scored(2, 2, 0),    // sent
		scored(3, 3, 500),  // spam by score, at the threshold
		scored(4, 4, 499),  // inbox, just under
		scored(5, 5, 900),  // not-spam verdict: inbox
		scored(6, 6, 0),    // spam verdict
		scored(7, 7, 0),    // trash
		scored(8, 8, 1200), // past 1,000 reads as 1,000: spam
		scored(9, 9, 0),    // label work
	)
	label := func(n uint64, name string) *MailFlagChange {
		return &MailFlagChange{Month: month, MessageId: testMailId(n), Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: name}
	}
	testMailFlag(t, store, 1,
		label(2, MailLabelSent), label(5, MailLabelNotSpam), label(6, MailLabelSpam), label(9, "work"),
		&MailFlagChange{Month: month, MessageId: testMailId(7), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true},
	)
	view := testMailView(store, nil, nil)
	for _, c := range []struct {
		folder MailFolder
		label  string
		want   []uint64
	}{
		{folder: MailFolderAll, want: []uint64{9, 8, 6, 5, 4, 3, 2, 1}},
		{folder: MailFolderInbox, want: []uint64{9, 5, 4, 1}},
		{folder: MailFolderSent, want: []uint64{2}},
		{folder: MailFolderSpam, want: []uint64{8, 6, 3}},
		{folder: MailFolderTrash, want: []uint64{7}},
		{folder: MailFolderLabel, label: "work", want: []uint64{9}},
	} {
		got, _ := testMailListAll(t, view, c.folder, c.label, 2)
		if !slices.Equal(testMailEntryNumbers(got), c.want) {
			t.Errorf("folder %d: %v", c.folder, testMailEntryNumbers(got))
		}
	}
	for _, args := range []*MailListArgs{{Folder: MailFolderLabel}, {Folder: MailFolderInbox, Label: "x"}, {Folder: MailFolder(99)}} {
		if _, err := view.List(context.Background(), args); !errors.Is(err, ErrMailViewArgsInvalid) {
			t.Errorf("%+v: %v", args, err)
		}
	}
}

// Group messages a mailbox's r/ references name join its list from the group repo, with the member's flags and the
// group's (an admin's trash); an unreferenced group message, a reference whose bytes do not match its path, and a
// group this device cannot read stay out, the mailbox's own messages listing all the same.
func TestMailViewMergesGroupReferences(t *testing.T) {
	mailbox := newMailTestStore()
	group := newMailTestStore()
	month := MailYearMonth(202611)
	testMailAppend(t, mailbox, testMailIndexEntry(1, testMailDayMillis(month, 1)))
	testMailAppend(t, group,
		testMailIndexEntry(10, testMailDayMillis(month, 2)),
		testMailIndexEntry(11, testMailDayMillis(month, 3)),
		testMailIndexEntry(12, testMailDayMillis(month, 4)),
		testMailIndexEntry(13, testMailDayMillis(month, 5)),
	)
	reference := func(messageNumber uint64, repoId Id) {
		content, err := proto.Marshal(&protocol.MailGroupRef{RepoId: repoId.Bytes(), MessageId: testMailId(messageNumber).Bytes()})
		if err != nil {
			t.Fatal(err)
		}
		mailbox.put(MailGroupRefPath(month, testMailId(messageNumber)), content)
	}
	reference(10, testMailGroupId)
	reference(11, testMailGroupId)
	reference(13, testMailGroupId)
	// a reference whose message is not its path's
	mismatched, _ := proto.Marshal(&protocol.MailGroupRef{RepoId: testMailGroupId.Bytes(), MessageId: testMailId(99).Bytes()})
	mailbox.put(MailGroupRefPath(month, testMailId(12)), mismatched)
	// a reference to a group this device cannot read
	reference(20, testMailId(0xdd))
	// the member saw 10; an admin trashed 11 in the group's own f/; the group's ops on the mailbox's message count for nothing
	testMailFlag(t, mailbox, 1, &MailFlagChange{Month: month, MessageId: testMailId(10), Kind: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true})
	testMailFlag(t, group, 2,
		&MailFlagChange{Month: month, MessageId: testMailId(11), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true},
		&MailFlagChange{Month: month, MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true},
	)
	view := testMailView(mailbox, map[Id]mailStore{testMailGroupId: group}, nil)
	all, unreadable := testMailListAll(t, view, MailFolderAll, "", 10)
	if got := testMailEntryNumbers(all); !slices.Equal(got, []uint64{13, 10, 1}) || unreadable != 2 {
		t.Fatalf("listed %v, %d unreadable", got, unreadable)
	}
	if all[0].RepoId != testMailGroupId || all[2].RepoId != testMailMailboxId || !all[1].Flags.Seen {
		t.Errorf("repos %v %v, seen %t", all[0].RepoId, all[2].RepoId, all[1].Flags.Seen)
	}
	trash, _ := testMailListAll(t, view, MailFolderTrash, "", 10)
	if got := testMailEntryNumbers(trash); !slices.Equal(got, []uint64{11}) {
		t.Errorf("trash %v", got)
	}
	// with no group stores at all the mailbox still lists
	alone, _ := testMailListAll(t, NewMailView(&MailViewArgs{MailboxId: testMailMailboxId, Mailbox: mailbox, Settings: DefaultMailStoreSettings()}), MailFolderAll, "", 10)
	if got := testMailEntryNumbers(alone); !slices.Equal(got, []uint64{1}) {
		t.Errorf("with no groups: %v", got)
	}
}

// One entry an id: the first in segment order of two the mailbox holds, and the mailbox's over a group's.
func TestMailViewKeepsTheFirstOfADuplicateId(t *testing.T) {
	mailbox := newMailTestStore()
	group := newMailTestStore()
	month := MailYearMonth(202611)
	first := testMailIndexEntry(1, testMailDayMillis(month, 1))
	first.Subject = "first"
	second := testMailIndexEntry(1, testMailDayMillis(month, 9))
	second.Subject = "second"
	mailbox.put(MailIndexPath(month, 0), mailSegmentAppend(nil, testMailRecord(t, first)))
	mailbox.put(MailIndexPath(month, 1), mailSegmentAppend(nil, testMailRecord(t, second)))
	shadow := testMailIndexEntry(1, testMailDayMillis(month, 20))
	shadow.Subject = "a group's"
	testMailAppend(t, group, shadow)
	content, _ := proto.Marshal(&protocol.MailGroupRef{RepoId: testMailGroupId.Bytes(), MessageId: testMailId(1).Bytes()})
	mailbox.put(MailGroupRefPath(month, testMailId(1)), content)
	all, _ := testMailListAll(t, testMailView(mailbox, map[Id]mailStore{testMailGroupId: group}, nil), MailFolderAll, "", 10)
	if len(all) != 1 || all[0].Entry.GetSubject() != "first" || all[0].RepoId != testMailMailboxId {
		t.Errorf("%d entries, the first %q", len(all), all[0].Entry.GetSubject())
	}
}

// Whatever breaks MAIL-FORMAT.md is passed over and counted, never shown and never an error: an entry dated in
// another month, a record that does not parse, a segment that does not, one past its bound, and a malformed op.
func TestMailViewPassesOverWhatBreaksTheFormat(t *testing.T) {
	store := newMailTestStore()
	month := MailYearMonth(202611)
	good := testMailIndexEntry(1, testMailDayMillis(month, 1))
	elsewhere := testMailIndexEntry(2, testMailDayMillis(202612, 1))
	segment := mailSegmentAppend(nil, testMailRecord(t, good))
	segment = mailSegmentAppend(segment, testMailRecord(t, elsewhere))
	segment = mailSegmentAppend(segment, []byte{0x0a, 0x05, 0x01})
	store.put(MailIndexPath(month, 0), segment)
	store.put(MailIndexPath(month, 1), []byte{0x0a, 0x7f})
	store.put(MailIndexPath(month, 2), make([]byte, mailIndexSegmentReadMaxByteCount+1))
	store.put(MailIndexPath(month, 3), mailSegmentAppend(nil, testMailRecord(t, testMailIndexEntry(3, testMailDayMillis(month, 2)))))
	badOp, _ := proto.Marshal(&protocol.MailFlagOp{MessageId: testMailId(1).Bytes(), Op: protocol.MailFlagKind_MAIL_FLAG_SEEN, Label: "x", SidecarId: testMailId(1).Bytes()})
	store.put(MailFlagPath(month, 0), mailSegmentAppend(nil, badOp))
	all, unreadable := testMailListAll(t, testMailView(store, nil, nil), MailFolderAll, "", 10)
	if got := testMailEntryNumbers(all); !slices.Equal(got, []uint64{3, 1}) || unreadable != 5 {
		t.Errorf("listed %v, %d unreadable", got, unreadable)
	}
}

// Entry and Flags by month and id; one appended after its month was kept is read again once; an absent one is
// ErrMailViewEntryAbsent.
func TestMailViewEntryAndFlags(t *testing.T) {
	store := newMailTestStore()
	month := MailYearMonth(202611)
	testMailAppend(t, store, testMailIndexEntry(1, testMailDayMillis(month, 1)))
	testMailFlag(t, store, 1, &MailFlagChange{Month: month, MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_FLAGGED, Set: true})
	view := testMailView(store, nil, nil)
	entry, err := view.Entry(context.Background(), month, testMailId(1))
	if err != nil || entry.Entry.GetSubject() != "message 1" || !entry.Flags.Flagged {
		t.Fatalf("%+v, %v", entry, err)
	}
	testMailAppend(t, store, testMailIndexEntry(2, testMailDayMillis(month, 2)))
	if entry, err := view.Entry(context.Background(), month, testMailId(2)); err != nil || entry.Entry.GetSubject() != "message 2" {
		t.Errorf("an entry written after its month was kept: %v", err)
	}
	if flags, err := view.Flags(context.Background(), month, testMailId(1)); err != nil || !flags.Flagged {
		t.Errorf("flags %+v, %v", flags, err)
	}
	if _, err := view.Entry(context.Background(), month, testMailId(3)); !errors.Is(err, ErrMailViewEntryAbsent) {
		t.Errorf("an absent entry: %v", err)
	}
	if _, err := view.Flags(context.Background(), 202501, testMailId(1)); !errors.Is(err, ErrMailViewEntryAbsent) {
		t.Errorf("another month: %v", err)
	}
}

// The view raises the mailbox's clock past every op it reads, so this device's next op orders after them.
func TestMailViewObservesTheClock(t *testing.T) {
	store := newMailTestStore()
	month := MailYearMonth(202611)
	testMailAppend(t, store, testMailIndexEntry(1, testMailDayMillis(month, 1)))
	ahead := MailHlcTick(0, 1793923200000+86_400_000)
	record, _ := proto.Marshal(&protocol.MailFlagOp{MessageId: testMailId(1).Bytes(), Op: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true, Hlc: ahead, SidecarId: testMailId(2).Bytes()})
	store.put(MailFlagPath(month, 0), mailSegmentAppend(nil, record))
	hlc := NewMailHlc(&mailTestClock{now: time.UnixMilli(1793923200000)})
	view := NewMailView(&MailViewArgs{MailboxId: testMailMailboxId, Mailbox: store, Hlc: hlc, Settings: DefaultMailStoreSettings()})
	if _, err := view.List(context.Background(), &MailListArgs{}); err != nil {
		t.Fatal(err)
	}
	if hlc.Tick() <= ahead {
		t.Error("the view did not raise the clock")
	}
}

// The live heap after a collection, in bytes.
func testMailLiveHeap() uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// §18.4's budget on a phone (16 MiB on Android, the tightest) holds a 100,000-message mailbox paged from newest to
// oldest: the view's working set, measured as the live heap above the store's own, stays under half of it, both when
// the messages spread over 25 months and when 25,000 sit in one month. Every message has a seen op and every tenth
// a label, so flags are part of what is kept. Nothing the test keeps grows with the mailbox: it checks order, count
// and a sum of ids as it goes.
func TestMailViewWorkingSetWith100000Entries(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 125,000 entries")
	}
	const budget = 8 * 1024 * 1024
	for _, c := range []struct {
		name          string
		monthCount    int
		perMonthCount int
	}{
		{name: "spread", monthCount: 25, perMonthCount: 4000},
		{name: "one heavy month", monthCount: 1, perMonthCount: 25000},
	} {
		store := newMailTestStore()
		n := uint64(0)
		for monthIndex := range c.monthCount {
			month := MailYearMonth(202401 + (monthIndex/12)*100 + monthIndex%12)
			segmentNumber := uint64(0)
			segment := []byte{}
			ops := []byte{}
			opCount := 0
			opSegment := uint64(0)
			for index := range c.perMonthCount {
				entry := testMailIndexEntry(n, testMailDayMillis(month, 1+index%28)+uint64(index))
				entry.Snippet = fmt.Sprintf("a snippet for message %d of a synthetic mailbox", n)
				record := testMailRecord(t, entry)
				if len(segment)+mailSegmentRecordByteCount(record) > MailIndexSegmentMaxByteCount || index%MailIndexSegmentMaxEntryCount == 0 && 0 < index {
					store.put(MailIndexPath(month, segmentNumber), segment)
					segment, segmentNumber = []byte{}, segmentNumber+1
				}
				segment = mailSegmentAppend(segment, record)
				changes := []*protocol.MailFlagOp{{MessageId: testMailId(n).Bytes(), Op: protocol.MailFlagKind_MAIL_FLAG_SEEN, Set: true, Hlc: uint64(index + 1), SidecarId: testMailId(1).Bytes()}}
				if n%10 == 0 {
					changes = append(changes, &protocol.MailFlagOp{MessageId: testMailId(n).Bytes(), Op: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: "work", Hlc: uint64(index + 1), SidecarId: testMailId(1).Bytes()})
				}
				for _, op := range changes {
					if opCount == MailFlagSegmentMaxOpCount {
						store.put(MailFlagPath(month, opSegment), ops)
						ops, opCount, opSegment = []byte{}, 0, opSegment+1
					}
					opRecord, _ := proto.Marshal(op)
					ops = mailSegmentAppend(ops, opRecord)
					opCount += 1
				}
				n += 1
			}
			store.put(MailIndexPath(month, segmentNumber), segment)
			store.put(MailFlagPath(month, opSegment), ops)
		}
		wantSum := uint64(0)
		for number := range n {
			wantSum += number
		}
		view := testMailView(store, nil, nil)
		baseline := testMailLiveHeap()
		peak := uint64(0)
		count := uint64(0)
		sum := uint64(0)
		var after *MailListCursor
		var previous *protocol.IndexEntry
		for page := 0; ; page += 1 {
			listed, err := view.List(context.Background(), &MailListArgs{Folder: MailFolderAll, After: after, Limit: 50})
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range listed.Entries {
				if previous != nil && cmp.Or(cmp.Compare(previous.GetTime(), entry.Entry.GetTime()), mailIdCompare(Id(previous.GetId()), Id(entry.Entry.GetId()))) <= 0 {
					t.Fatalf("%s: out of order at %d", c.name, count)
				}
				if !entry.Flags.Seen {
					t.Fatalf("%s: a message lost its flags", c.name)
				}
				previous = entry.Entry
				count += 1
				sum += testMailEntryNumbers([]*MailViewEntry{entry})[0]
			}
			if page%25 == 0 || listed.Next == nil {
				if live := testMailLiveHeap(); baseline < live {
					peak = max(peak, live-baseline)
				}
			}
			if listed.Next == nil {
				break
			}
			after = listed.Next
		}
		if count != n || sum != wantSum {
			t.Errorf("%s: %d of %d listed", c.name, count, n)
		}
		if budget < peak {
			t.Errorf("%s: the view held %d bytes", c.name, peak)
		}
		t.Logf("%s: %d messages paged, working set at most %d KiB", c.name, n, peak/1024)
	}
}
