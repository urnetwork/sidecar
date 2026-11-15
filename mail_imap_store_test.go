//go:build !sidecar_http && !js && !ios_extension

package sidecar

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The device an IMAP store test writes flags as.
var testMailImapSidecarId = testMailId(0xd1)

// A store over mailbox, on state, clocked at now.
func testMailImapStore(t *testing.T, mailbox mailStore, state SidecarStore, clock *mailTestClock) *MailImapStore {
	t.Helper()
	store, err := NewMailImapStore(&MailImapStoreArgs{
		MailboxId: testMailMailboxId,
		Mailbox:   mailbox,
		Hlc:       NewMailHlc(clock),
		SidecarId: testMailImapSidecarId,
		State:     state,
		Clock:     clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// The numbers and UIDs of a snapshot's messages, in UID order.
func testMailImapUids(snapshot *MailImapSnapshot) ([]uint64, []uint32) {
	numbers := []uint64{}
	uids := []uint32{}
	for _, message := range snapshot.Messages {
		id := message.Key.Id
		numbers = append(numbers, uint64(id[14])<<8|uint64(id[15]))
		uids = append(uids, message.Uid)
	}
	return numbers, uids
}

// Appends a message's entry and its m/ file, as ingest leaves them.
func testMailImapDeliver(t *testing.T, mailbox *mailTestStore, n uint64, timeMillis uint64) {
	t.Helper()
	entry := testMailIndexEntry(n, timeMillis)
	testMailAppend(t, mailbox, entry)
	mailbox.put(MailMessagePath(MailYearMonthOf(timeMillis), testMailId(n)), []byte("Subject: message\r\n\r\nbody\r\n"))
}

// UIDs are local, strictly rising in arrival order, and stable across a restart: a store made again over the same
// sealed state gives each message the UID it had and a new message the next.
func TestMailImapUidsRiseAndSurviveARestart(t *testing.T) {
	ctx := context.Background()
	mailbox := newMailTestStore()
	state := newTestMemoryStore()
	clock := &mailTestClock{now: time.UnixMilli(1793923200000)}
	base := uint64(1793923200000)
	testMailImapDeliver(t, mailbox, 2, base+2000)
	testMailImapDeliver(t, mailbox, 1, base+1000)
	store := testMailImapStore(t, mailbox, state, clock)
	snapshot, err := store.Select(ctx, "inbox")
	if err != nil {
		t.Fatal(err)
	}
	numbers, uids := testMailImapUids(snapshot)
	if !slices.Equal(numbers, []uint64{1, 2}) || !slices.Equal(uids, []uint32{1, 2}) || snapshot.Next != 3 || snapshot.Folder != MailImapFolderInbox {
		t.Fatalf("first select: %v %v next %d", numbers, uids, snapshot.Next)
	}
	validity := snapshot.Validity

	testMailImapDeliver(t, mailbox, 3, base+3000)
	restarted := testMailImapStore(t, mailbox, state, clock)
	snapshot, err = restarted.Select(ctx, MailImapFolderInbox)
	if err != nil {
		t.Fatal(err)
	}
	numbers, uids = testMailImapUids(snapshot)
	if !slices.Equal(numbers, []uint64{1, 2, 3}) || !slices.Equal(uids, []uint32{1, 2, 3}) || snapshot.Validity != validity {
		t.Fatalf("after a restart: %v %v validity %d, was %d", numbers, uids, snapshot.Validity, validity)
	}

	// a message that leaves the folder gives its UID up, and comes back under a new one
	testMailFlag(t, mailbox, 9, &MailFlagChange{Month: MailYearMonthOf(base + 1000), MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true})
	snapshot, _ = restarted.Select(ctx, MailImapFolderInbox)
	if numbers, uids = testMailImapUids(snapshot); !slices.Equal(numbers, []uint64{2, 3}) || !slices.Equal(uids, []uint32{2, 3}) {
		t.Fatalf("after a trash: %v %v", numbers, uids)
	}
	testMailFlag(t, mailbox, 9, &MailFlagChange{Month: MailYearMonthOf(base + 1000), MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: false})
	snapshot, _ = restarted.Select(ctx, MailImapFolderInbox)
	if numbers, uids = testMailImapUids(snapshot); !slices.Equal(numbers, []uint64{2, 3, 1}) || !slices.Equal(uids, []uint32{2, 3, 4}) {
		t.Fatalf("after a restore: %v %v", numbers, uids)
	}
}

// A lost UID store raises UIDVALIDITY: a folder's file gone, or the whole store gone with the clock moved on.
func TestMailImapLostUidsRaiseValidity(t *testing.T) {
	ctx := context.Background()
	mailbox := newMailTestStore()
	testMailImapDeliver(t, mailbox, 1, 1793923200000)
	state := newTestMemoryStore()
	clock := &mailTestClock{now: time.UnixMilli(1793923200000)}
	first, err := testMailImapStore(t, mailbox, state, clock).Select(ctx, MailImapFolderInbox)
	if err != nil {
		t.Fatal(err)
	}
	// the folder's file alone is lost: the issued validity still stands, so the new one is past it
	state.Remove("imap/" + mailImapUidFileName(MailImapFolderInbox))
	second, err := testMailImapStore(t, mailbox, state, clock).Select(ctx, MailImapFolderInbox)
	if err != nil {
		t.Fatal(err)
	}
	if second.Validity <= first.Validity {
		t.Errorf("a lost folder file kept validity %d, was %d", second.Validity, first.Validity)
	}
	// a file that does not decode is a lost one
	writer, _ := state.Create("imap/" + mailImapUidFileName(MailImapFolderInbox))
	writer.Write([]byte("{not json"))
	writer.Commit()
	third, err := testMailImapStore(t, mailbox, state, clock).Select(ctx, MailImapFolderInbox)
	if err != nil || third.Validity <= second.Validity {
		t.Errorf("a corrupt file: validity %d after %d, %v", third.Validity, second.Validity, err)
	}
	// the whole store lost, a minute on
	clock.now = clock.now.Add(time.Minute)
	fourth, err := testMailImapStore(t, mailbox, newTestMemoryStore(), clock).Select(ctx, MailImapFolderInbox)
	if err != nil || fourth.Validity <= third.Validity {
		t.Errorf("a lost store: validity %d after %d, %v", fourth.Validity, third.Validity, err)
	}
	// and a store that keeps its state keeps its validity
	fifth, _ := testMailImapStore(t, mailbox, state, clock).Select(ctx, MailImapFolderInbox)
	if fifth.Validity != third.Validity {
		t.Errorf("a kept store's validity moved: %d, was %d", fifth.Validity, third.Validity)
	}
}

// Flags round-trip through f/: a client's \Seen and \Flagged reach the mailbox's f/ as ops another device's view
// reads, \Deleted moves a message to Trash and clearing it there restores it, and a flag the store does not keep
// refuses, writing nothing.
func TestMailImapFlagsRoundTripThroughFlagOps(t *testing.T) {
	ctx := context.Background()
	mailbox := newMailTestStore()
	base := uint64(1793923200000)
	testMailImapDeliver(t, mailbox, 1, base+1000)
	testMailImapDeliver(t, mailbox, 2, base+2000)
	clock := &mailTestClock{now: time.UnixMilli(int64(base) + 5000)}
	store := testMailImapStore(t, mailbox, newTestMemoryStore(), clock)
	snapshot, err := store.Select(ctx, MailImapFolderInbox)
	if err != nil {
		t.Fatal(err)
	}
	revision, changed := store.Revision()
	if err := store.SetFlags(ctx, MailImapFolderInbox, snapshot.Messages[:1], []*MailImapFlagChange{{Flag: MailImapFlagSeen, Set: true}, {Flag: MailImapFlagFlagged, Set: true}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Error("a flag write woke no session")
	}
	if next, _ := store.Revision(); next != revision+1 {
		t.Errorf("revision %d after %d", next, revision)
	}
	// another device's view of the same mailbox
	other := testMailView(mailbox, nil, nil)
	flags, err := other.Flags(ctx, MailYearMonthOf(base+1000), testMailId(1))
	if err != nil || !flags.Seen || !flags.Flagged {
		t.Fatalf("another view read %+v, %v", flags, err)
	}
	snapshot, _ = store.Select(ctx, MailImapFolderInbox)
	if got := snapshot.Messages[0].ImapFlags(); !slices.Equal(got, []string{`\Flagged`, `\Seen`}) {
		t.Errorf("flags %v", got)
	}

	if err := store.SetFlags(ctx, MailImapFolderInbox, snapshot.Messages[1:], []*MailImapFlagChange{{Flag: MailImapFlagDeleted, Set: true}}); err != nil {
		t.Fatal(err)
	}
	trash, _ := store.Select(ctx, MailImapFolderTrash)
	if numbers, _ := testMailImapUids(trash); !slices.Equal(numbers, []uint64{2}) || !slices.Equal(trash.Messages[0].ImapFlags(), []string{`\Deleted`}) {
		t.Fatalf("trash %v", numbers)
	}
	if err := store.SetFlags(ctx, MailImapFolderTrash, trash.Messages, []*MailImapFlagChange{{Flag: MailImapFlagDeleted, Set: true}}); !errors.Is(err, ErrMailImapFlagRefused) {
		t.Errorf("\\Deleted in Trash: %v", err)
	}
	if err := store.SetFlags(ctx, MailImapFolderTrash, trash.Messages, []*MailImapFlagChange{{Flag: MailImapFlagDeleted, Set: false}}); err != nil {
		t.Fatal(err)
	}
	inbox, _ := store.Select(ctx, MailImapFolderInbox)
	if numbers, _ := testMailImapUids(inbox); !slices.Equal(numbers, []uint64{1, 2}) {
		t.Errorf("restored inbox %v", numbers)
	}
	before := len(mailbox.paths())
	if err := store.SetFlags(ctx, MailImapFolderInbox, inbox.Messages, []*MailImapFlagChange{{Flag: `\Answered`, Set: true}}); !errors.Is(err, ErrMailImapFlagRefused) {
		t.Errorf("\\Answered: %v", err)
	}
	if len(mailbox.paths()) != before {
		t.Error("a refused flag wrote")
	}
}

// An erasure expunges from a selected folder: PurgeMail wakes the session, the next select no longer lists the
// message, its UID is never given again, its bytes refuse, and a stale list that still shows it does not bring it
// back.
func TestMailImapErasureExpungesFromASelectedFolder(t *testing.T) {
	ctx := context.Background()
	mailbox := newMailTestStore()
	base := uint64(1793923200000)
	testMailImapDeliver(t, mailbox, 1, base+1000)
	testMailImapDeliver(t, mailbox, 2, base+2000)
	clock := &mailTestClock{now: time.UnixMilli(int64(base) + 5000)}
	store := testMailImapStore(t, mailbox, newTestMemoryStore(), clock)
	snapshot, err := store.Select(ctx, MailImapFolderInbox)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := store.Body(ctx, snapshot.Messages[0]); err != nil || len(body) == 0 {
		t.Fatalf("body %q %v", body, err)
	}
	_, changed := store.Revision()
	// the erasure's hint, while i/ still lists the message, as it does until the erasure's rewrite lands
	if err := store.PurgeMail(ctx, testMailMailboxId, []Id{testMailId(1)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Error("a purge woke no selected session")
	}
	after, err := store.Select(ctx, MailImapFolderInbox)
	if err != nil {
		t.Fatal(err)
	}
	if numbers, uids := testMailImapUids(after); !slices.Equal(numbers, []uint64{2}) || !slices.Equal(uids, []uint32{2}) {
		t.Fatalf("after the purge %v %v", numbers, uids)
	}
	if _, err := store.Body(ctx, snapshot.Messages[0]); !errors.Is(err, ErrMailImapMessagePurged) {
		t.Errorf("a purged message's bytes: %v", err)
	}
	// purging again is nothing new, and a store made again remembers the purge
	if err := store.PurgeMail(ctx, testMailMailboxId, []Id{testMailId(1)}); err != nil {
		t.Fatal(err)
	}
	testMailImapDeliver(t, mailbox, 3, base+3000)
	again, _ := store.Select(ctx, MailImapFolderInbox)
	if numbers, uids := testMailImapUids(again); !slices.Equal(numbers, []uint64{2, 3}) || !slices.Equal(uids, []uint32{2, 3}) {
		t.Errorf("a purged message's UID came back: %v %v", numbers, uids)
	}
}

// Every label a message carries is a folder beside the four, and one that would read as one of them is not.
func TestMailImapFoldersListTheLabels(t *testing.T) {
	ctx := context.Background()
	mailbox := newMailTestStore()
	base := uint64(1793923200000)
	testMailImapDeliver(t, mailbox, 1, base+1000)
	month := MailYearMonthOf(base + 1000)
	for _, label := range []string{"receipts", "inbox", "a/b"} {
		testMailFlag(t, mailbox, 9, &MailFlagChange{Month: month, MessageId: testMailId(1), Kind: protocol.MailFlagKind_MAIL_FLAG_LABEL, Set: true, Label: label})
	}
	store := testMailImapStore(t, mailbox, newTestMemoryStore(), &mailTestClock{now: time.UnixMilli(int64(base))})
	folders, err := store.Folders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, folder := range folders {
		names = append(names, folder.Name)
	}
	if !slices.Equal(names, []string{"INBOX", "Sent", "Trash", "Spam", "receipts"}) {
		t.Errorf("folders %v", names)
	}
	snapshot, err := store.Select(ctx, "receipts")
	if err != nil || len(snapshot.Messages) != 1 {
		t.Errorf("the label folder %v %v", snapshot, err)
	}
	if _, err := store.Select(ctx, "a/b"); !errors.Is(err, ErrMailImapFolderAbsent) {
		t.Errorf("a label with the delimiter: %v", err)
	}
}
