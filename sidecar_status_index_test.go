//go:build !ios_extension

package sidecar

// QUOTA-M10-01's index share (D-QUOTA-10): ReadIndexShare sums every root of every repo it reads, leaves out the kinds
// that hold no index, counts what it cannot read as unread rather than guessing, and Status shows the last read until
// the next one replaces it.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// EvsRepo is what a host hands ReadIndexShare.
var _ SidecarIndexStatusReader = (*EvsRepo)(nil)

// One repo's index status as a test sets it.
type testIndexStatusReader struct {
	status    *EvsIndexStatus
	err       error
	readCount int
}

func (self *testIndexStatusReader) IndexStatus(ctx context.Context, args *EvsIndexStatusArgs) (*EvsIndexStatus, error) {
	self.readCount += 1
	if self.err != nil {
		return self.status, self.err
	}
	return self.status, nil
}

func newIndexShareTestSidecar(t *testing.T) (*Sidecar, *identityTestClock) {
	t.Helper()
	sidecar := newSidecarBase(nil, cheapKeychainSettings())
	clock := newIdentityTestClock()
	sidecar.clock = clock
	return sidecar, clock
}

// Every root of a read repo adds its files and bytes; an excluded kind is left out; an error, and a root in a newer
// format, count the repo unread and add nothing of it, even the roots it did read.
func TestReadIndexShareSumsEveryRootItCanRead(t *testing.T) {
	sidecar, clock := newIndexShareTestSidecar(t)
	if share := sidecar.Status().IndexShare; share != nil {
		t.Fatalf("a share before any read: %+v", share)
	}
	mailbox := &testIndexStatusReader{status: &EvsIndexStatus{Roots: []*EvsIndexRootStatus{
		{RootNumber: 1, State: EvsIndexStateOn, FileCount: 3, ByteCount: 3000},
		{RootNumber: 1, Companion: true, State: EvsIndexStateOff, FileCount: 1, ByteCount: 200},
	}}}
	record := &testIndexStatusReader{status: &EvsIndexStatus{Roots: []*EvsIndexRootStatus{
		{RootNumber: 1, State: EvsIndexStateNone},
		{RootNumber: 1, Companion: true, State: EvsIndexStateOn, FileCount: 2, ByteCount: 500},
	}}}
	config := &testIndexStatusReader{err: ErrEvsIndexExcluded}
	unreadable := &testIndexStatusReader{
		status: &EvsIndexStatus{Roots: []*EvsIndexRootStatus{{RootNumber: 1, State: EvsIndexStateOn, FileCount: 9, ByteCount: 9000}}},
		err:    errors.New("a head the read could not verify"),
	}
	newer := &testIndexStatusReader{status: &EvsIndexStatus{Roots: []*EvsIndexRootStatus{
		{RootNumber: 1, State: EvsIndexStateOn, FileCount: 4, ByteCount: 4000},
		{RootNumber: 1, Companion: true, State: EvsIndexStateUpdate},
	}}}
	share := sidecar.ReadIndexShare(t.Context(), []SidecarIndexStatusReader{mailbox, record, config, unreadable, newer, nil})
	want := SidecarIndexShare{RepoCount: 4, UnreadRepoCount: 2, FileCount: 6, ByteCount: 3700, ReadAt: clock.Now()}
	if *share != want {
		t.Fatalf("share %+v, want %+v", *share, want)
	}
	shown := sidecar.Status().IndexShare
	if shown == nil || *shown != want {
		t.Fatalf("Status shows %+v, want %+v", shown, want)
	}
	// what a read answered and what Status shows share nothing with what the Sidecar keeps
	share.ByteCount = 1
	shown.FileCount = 1
	if again := sidecar.Status().IndexShare; *again != want {
		t.Fatalf("Status shows %+v after its copies changed", *again)
	}
	for _, reader := range []*testIndexStatusReader{mailbox, record, config, unreadable, newer} {
		if reader.readCount != 1 {
			t.Fatalf("a repo read %d times", reader.readCount)
		}
	}
}

// The next read replaces the last whole, so a repo no longer asked, or one shrunk, shows as it is now.
func TestReadIndexShareReplacesTheLastRead(t *testing.T) {
	sidecar, clock := newIndexShareTestSidecar(t)
	first := &testIndexStatusReader{status: &EvsIndexStatus{Roots: []*EvsIndexRootStatus{{State: EvsIndexStateOn, FileCount: 5, ByteCount: 5000}}}}
	second := &testIndexStatusReader{status: &EvsIndexStatus{Roots: []*EvsIndexRootStatus{{State: EvsIndexStateOn, FileCount: 2, ByteCount: 800}}}}
	sidecar.ReadIndexShare(t.Context(), []SidecarIndexStatusReader{first, second})
	clock.advance(time.Hour)
	// the first repo's index turned off and its files removed (§11.14's off row), the second gone from the list
	first.status = &EvsIndexStatus{Roots: []*EvsIndexRootStatus{{State: EvsIndexStateOff, FileCount: 1, ByteCount: 100}}}
	sidecar.ReadIndexShare(t.Context(), []SidecarIndexStatusReader{first})
	want := SidecarIndexShare{RepoCount: 1, FileCount: 1, ByteCount: 100, ReadAt: clock.Now()}
	if shown := sidecar.Status().IndexShare; shown == nil || *shown != want {
		t.Fatalf("Status shows %+v, want %+v", shown, want)
	}
}

// A read whose ctx has ended asks no repo and counts each unread, so the share it leaves says it covered nothing.
func TestReadIndexShareCountsTheRestUnreadOnceItsContextEnds(t *testing.T) {
	sidecar, clock := newIndexShareTestSidecar(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	repo := &testIndexStatusReader{status: &EvsIndexStatus{Roots: []*EvsIndexRootStatus{{State: EvsIndexStateOn, FileCount: 5, ByteCount: 5000}}}}
	share := sidecar.ReadIndexShare(ctx, []SidecarIndexStatusReader{repo, repo})
	want := SidecarIndexShare{RepoCount: 2, UnreadRepoCount: 2, ReadAt: clock.Now()}
	if *share != want || repo.readCount != 0 {
		t.Fatalf("share %+v after %d reads, want %+v and none", *share, repo.readCount, want)
	}
}
