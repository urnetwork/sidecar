//go:build !ios_extension && !sidecar_http

// Sparse checkout by prefix (DESIGN-COMPUTE §13.4's clone row, D-GIT-2; GIT-M13-02): a worktree that writes only the
// paths under one directory, for phones and other small workspaces, its other paths kept in the index, marked
// unwritten (GitIndexEntry.Unwritten), so status reads none of them as deleted and a commit keeps them as they were.
//
//	lazy     a worktree cloned sparse defers every blob from then on, and keeps doing so whatever its prefix becomes:
//	         its unfetched blobs and paths mean stock git cannot open it (D-GIT-1), which status says (GIT-M13-05)
//	change   SetSparse checks the head's tree out again under the new prefix: what it now covers is fetched through the
//	         promisor and written, what it no longer covers is removed and marked, refused where such a file holds a
//	         change the index does not, so nothing the agent wrote is lost
//
// Not safe for concurrent use: one command's.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// A file outside a new sparse prefix that holds a change, which narrowing the checkout would lose.
var ErrGitSparseWouldLoseWork = errors.New("git: a file the new sparse prefix leaves out holds a change; commit or restore it first")

// The file whose change a sparse checkout would lose: its text the rule alone, its path for the porcelain to show.
type GitSparseLossError struct {
	Path string
}

// The rule alone (I-13).
func (self *GitSparseLossError) Error() string {
	return ErrGitSparseWouldLoseWork.Error()
}

// Wraps ErrGitSparseWouldLoseWork.
func (self *GitSparseLossError) Unwrap() error {
	return ErrGitSparseWouldLoseWork
}

// A sparse checkout's prefix.
type GitSparse struct {
	// A directory's path with a trailing slash, "" for every path.
	Prefix string
}

// Whether the checkout writes path.
func (self GitSparse) Covers(path string) bool {
	return self.Prefix == "" || strings.HasPrefix(path, self.Prefix)
}

// The worktree's sparse checkout.
func (self *GitRepository) SparseCheckout() GitSparse {
	return GitSparse{Prefix: self.state.Sparse}
}

// Whether the worktree defers blobs: once cloned sparse, always.
func (self *GitRepository) Lazy() bool {
	return self.state.Lazy
}

// Checks the head's tree out again under prefix ("" for every path): see the file header's change row.
func (self *GitRepository) SetSparse(ctx context.Context, prefix string) (*GitCheckoutResult, error) {
	sparse := GitSparse{Prefix: gitSparsePrefix(prefix)}
	if sparse.Prefix != "" {
		if err := gitCheckPath(strings.TrimSuffix(sparse.Prefix, "/"), 0); err != nil {
			return nil, err
		}
	}
	head, err := self.refs.ResolveHead()
	if err != nil {
		return nil, err
	}
	lock, err := self.worktree.LockIndex()
	if err != nil {
		return nil, err
	}
	held, err := self.worktree.ReadIndex()
	if err != nil {
		lock.Abandon()
		return nil, err
	}
	for _, entry := range held.Entries {
		if entry.Unwritten || sparse.Covers(entry.Path) {
			continue
		}
		state, err := self.worktree.EntryState(ctx, entry, nil)
		if err != nil {
			lock.Abandon()
			return nil, err
		}
		if state != GitEntryUnchanged {
			lock.Abandon()
			return nil, &GitSparseLossError{Path: entry.Path}
		}
	}
	previous, previousLazy := self.state.Sparse, self.state.Lazy
	self.state.Sparse = sparse.Prefix
	self.state.Lazy = previousLazy || sparse.Prefix != ""
	if err := self.saveState(); err != nil {
		self.state.Sparse, self.state.Lazy = previous, previousLazy
		lock.Abandon()
		return nil, err
	}
	if head == nil {
		lock.Abandon()
		return &GitCheckoutResult{Index: held}, nil
	}
	commit, err := self.objects.ReadCommit(ctx, *head)
	if err != nil {
		lock.Abandon()
		return nil, err
	}
	result, err := self.worktree.Checkout(ctx, &GitCheckoutArgs{Tree: commit.TreeOid, SparsePrefix: sparse.Prefix}, held)
	if err != nil {
		lock.Abandon()
		return nil, fmt.Errorf("git: the sparse checkout stopped part way, the index left as it was: %w", err)
	}
	if err := lock.Commit(result.Index); err != nil {
		return nil, err
	}
	return result, nil
}
