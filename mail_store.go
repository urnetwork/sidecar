//go:build !ios_extension

// mailStore (MAIL-M7-06): what MAIL's writers and readers need of one mail repo's file-mode ref, by path, so the
// message list (i/), the flags (f/), the spam model (s/model) and the view over them are written against it and tested
// with no evs. It reads a file's newest version with that version, lists a directory, and writes paths in one push,
// each only while its path still stands at the version its writer read: a path CAS, which is how §15.7's racing
// writers meet ("a racing i/ write gets a path 409 and re-reads", §11.8's 5g).
//
// mailEvsStore is the store over EvsRepo. Its reads are EvsRepo's verified ReadHead and List. Its writes refuse,
// closed, with ErrMailStoreWriteHeld: EvsRepo.Write plans each path from a read of its own, made inside the call, so
// a writer that built its bytes from an earlier read would replace whatever another writer committed in between, and
// no error would say so. Until evs takes the writer's version as the push's base_entry_version (question
// mail-m7-06-evs-path-precondition), nothing here writes through evs, so no append is lost.
//
// Paths are a mail repo's own, as mail_paths.go spells them, and are never logged (I-13). On every leg, sidecar_http
// included: a page Worker reads mail through the same store.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

var (
	// A conditional write found a path moved since its writer read it: another version stands there, or the path the
	// writer read as absent now stands (evs's PATH_CONFLICT). Nothing was written, and the writer reads again.
	// errors.As finds the *MailStoreConflictError naming the paths.
	ErrMailStoreConflict = errors.New("mail store: a path moved since it was read")
	// A file larger than its reader bounds the read to: a segment no writer that follows MAIL-FORMAT.md makes.
	ErrMailStoreTooLarge = errors.New("mail store: a file past its bound")
	// Conditional writes through evs wait on its path precondition (question mail-m7-06-evs-path-precondition).
	ErrMailStoreWriteHeld = errors.New("mail store: a conditional write waits on evs's path precondition")
)

// The paths of a write that moved, a subset of what the write named, in its order.
type MailStoreConflictError struct {
	Paths []string
}

// The count only: a path is never logged (I-13).
func (self *MailStoreConflictError) Error() string {
	return fmt.Sprintf("%s: %d paths", ErrMailStoreConflict, len(self.Paths))
}

// ErrMailStoreConflict, which every conflict is.
func (self *MailStoreConflictError) Unwrap() error {
	return ErrMailStoreConflict
}

// Whether err is a conflict that names path.
func mailStoreConflictOn(err error, path string) bool {
	var conflict *MailStoreConflictError
	if !errors.As(err, &conflict) {
		return false
	}
	for _, conflicted := range conflict.Paths {
		if conflicted == path {
			return true
		}
	}
	return false
}

// What the mailbox's writers and its view are tuned by (MAIL-M7-06).
type MailStoreSettings struct {
	// How many times a writer reads again after a conflict on its own path before it gives the conflict back. Racing
	// ingests and flag writes of one mailbox meet a few times at most; non-positive tries once.
	WriteRetryCount int
	// The entries a view's page holds when its caller names no limit. Non-positive takes 1.
	PageEntryCount int
	// The months whose order a view keeps between pages, about 112 bytes a message: a phone pages a month at a
	// time, and two keep a page that crosses a month's end from reading either again. Non-positive keeps the one
	// being read.
	CachedMonthCount int
	// The i/ segments a view keeps decoded between pages, each at most 1 MiB. Non-positive keeps none, and each
	// page reads its segments again.
	CachedSegmentCount int
	// spam_score, parts per thousand, from which a message with no person's verdict counts as spam (§15.9). 0 counts
	// everything as spam; past 1,000 counts nothing.
	SpamScoreThreshold uint32
}

// The one default.
func DefaultMailStoreSettings() *MailStoreSettings {
	return &MailStoreSettings{
		WriteRetryCount:    8,
		PageEntryCount:     50,
		CachedMonthCount:   2,
		CachedSegmentCount: 2,
		SpamScoreThreshold: DefaultMailSpamSettings().ScoreThreshold,
	}
}

// One path of a conditional write.
type mailStoreWrite struct {
	Path    string
	Content []byte
	// The path's version its writer read, 0 for a path it read as absent.
	IfVersion uint64
}

// One mail repo's file-mode ref, by path. Implementations are safe for concurrent use.
type mailStore interface {
	// The newest committed content of path and its version, refusing with ErrMailStoreTooLarge past maxByteCount
	// bytes and with ErrEvsPathAbsent where no file stands. The bytes are the caller's to keep.
	Read(ctx context.Context, path string, maxByteCount int) ([]byte, uint64, error)
	// The names of directory's children, in no order: ErrEvsPathAbsent where no directory stands.
	List(ctx context.Context, directory string) ([]string, error)
	// Writes every path in one push, all or none, each only while it stands at its IfVersion; else a
	// *MailStoreConflictError naming those that moved, and nothing is written. Each path's new version, in order.
	Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error)
}

// A writer that keeps what it is given up to a bound, and refuses past it.
type mailBoundedBuffer struct {
	buffer       bytes.Buffer
	maxByteCount int
}

// Keeps data, or refuses all of it with ErrMailStoreTooLarge where it would pass the bound.
func (self *mailBoundedBuffer) Write(data []byte) (int, error) {
	if self.maxByteCount < self.buffer.Len()+len(data) {
		return 0, ErrMailStoreTooLarge
	}
	return self.buffer.Write(data)
}

// mailStore over one repo's ref, by EvsRepo's verified reads. Safe for concurrent use.
type mailEvsStore struct {
	repo *EvsRepo
	// The ref's name bytes: nil names main, a mailbox's and a group repo's file-mode ref.
	refName []byte
}

// The store over repo's ref named refName, main when nil.
func newMailEvsStore(repo *EvsRepo, refName []byte) *mailEvsStore {
	return &mailEvsStore{repo: repo, refName: refName}
}

// ReadHead's verified newest version, held to maxByteCount.
func (self *mailEvsStore) Read(ctx context.Context, path string, maxByteCount int) ([]byte, uint64, error) {
	out := &mailBoundedBuffer{maxByteCount: maxByteCount}
	info, err := self.repo.ReadHead(ctx, &EvsReadArgs{RefName: self.refName, Path: path}, out)
	if err != nil {
		if errors.Is(err, ErrMailStoreTooLarge) {
			return nil, 0, ErrMailStoreTooLarge
		}
		return nil, 0, err
	}
	return out.buffer.Bytes(), info.Version, nil
}

// List's verified children.
func (self *mailEvsStore) List(ctx context.Context, directory string) ([]string, error) {
	listing, err := self.repo.List(ctx, &EvsReadArgs{RefName: self.refName, Path: directory})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(listing.Entries))
	for _, entry := range listing.Entries {
		names = append(names, string(entry.Name))
	}
	return names, nil
}

// Refuses, closed: see the file header.
func (self *mailEvsStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	return nil, ErrMailStoreWriteHeld
}
