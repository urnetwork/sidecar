//go:build !ios_extension

// Reconciliation of a member's existing group references across a rewrite and a retry.

package sidecar

import (
	"context"
	"errors"
	"testing"
)

// A CLOSURE and an append between syncs can leave the same number of rows with a different last message.
func TestMailGroupRefsCatchAnAppendAfterAClosure(t *testing.T) {
	ctx := t.Context()
	group := newMailTestStore()
	mailbox := &mailTestRemoveStore{mailTestStore: newMailTestStore()}
	erased := newMailIngestTestRepo()
	refs := newMailGroupRefs(NewId(), group, mailbox, erased.Erasures, nil)
	month := MailYearMonth(202611)
	first := testMailIndexEntry(1, testMailDayMillis(month, 1))
	kept := testMailIndexEntry(2, testMailDayMillis(month, 2))
	added := testMailIndexEntry(3, testMailDayMillis(month, 3))
	testMailAppend(t, group, first, kept)
	if result, err := refs.Sync(ctx); err != nil || result.Added != 2 {
		t.Fatalf("initial references: %+v, %v", result, err)
	}
	erased.erase(NewId(), mailErasureNote([]mailErasedMessage{{Month: month, MessageId: mailEntryId(first)}}, nil))
	group.put(MailIndexPath(month, 0), mailSegmentAppend(nil, testMailRecord(t, kept)))
	testMailAppend(t, group, added)
	if result, err := refs.Sync(ctx); err != nil || result.Dropped != 1 || result.Added != 1 {
		t.Fatalf("references after rewrite and append: %+v, %v", result, err)
	}
	if mailbox.file(MailGroupRefPath(month, mailEntryId(added))) == nil || mailbox.file(MailGroupRefPath(month, mailEntryId(first))) != nil {
		t.Fatal("the member's references do not match the rewritten group index")
	}
}

// A mailbox that temporarily cannot commit one reference removal.
type mailGroupRefRemoveTestStore struct {
	*mailTestRemoveStore
	fail error
}

// Consumes the one injected failure, then uses the mailbox's version-checked removal.
func (self *mailGroupRefRemoveTestStore) Remove(ctx context.Context, path string, ifVersion uint64) error {
	if err := self.fail; err != nil {
		self.fail = nil
		return err
	}
	return self.mailTestRemoveStore.Remove(ctx, path, ifVersion)
}

// The erasure cursor advances only after the member's reference removal commits.
func TestMailGroupRefsRetryAFailedRemoval(t *testing.T) {
	ctx := t.Context()
	group := newMailTestStore()
	mailbox := &mailGroupRefRemoveTestStore{mailTestRemoveStore: &mailTestRemoveStore{mailTestStore: newMailTestStore()}}
	erased := newMailIngestTestRepo()
	refs := newMailGroupRefs(NewId(), group, mailbox, erased.Erasures, nil)
	month := MailYearMonth(202611)
	entry := testMailIndexEntry(1, testMailDayMillis(month, 1))
	id := mailEntryId(entry)
	testMailAppend(t, group, entry)
	if _, err := refs.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	erased.erase(NewId(), mailErasureNote([]mailErasedMessage{{Month: month, MessageId: id}}, nil))
	fail := errors.New("mailbox temporarily unavailable")
	mailbox.fail = fail
	if _, err := refs.Sync(ctx); !errors.Is(err, fail) {
		t.Fatalf("first removal: %v", err)
	}
	if result, err := refs.Sync(ctx); err != nil || result.Dropped != 1 || mailbox.file(MailGroupRefPath(month, id)) != nil {
		t.Fatalf("retried removal: %+v, %v", result, err)
	}
}
