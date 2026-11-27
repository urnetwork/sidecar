//go:build !ios_extension && !sidecar_http

// Clone (DESIGN-COMPUTE §13.4's clone row, §13.5's `clone ur://<net>/<repo> [dir] [--branch b] [--sparse <prefix>]`;
// GIT-M13-02): a new repository in an empty worktree, its one remote the URL, its branch's history fetched from evs
// through the replayer, the branch made locally with origin's as its upstream, and its tree checked out, every path or
// only those under the sparse prefix.
//
//	refusals  a remote that is not ur:// (Q-GIT-2), a worktree that holds anything, and a bad branch name are refused
//	          before anything is written
//	taint     the fetch taints the run before its first object where a push it takes is untrusted (git_fetch.go), so
//	          the checkout's first byte always follows the taint
//	sparse    with a prefix, every blob is deferred to the promisor and only the prefix's are fetched, by the checkout;
//	          the worktree is lazy from then on (git_sparse.go)
//	empty     a branch evs does not hold yet leaves HEAD on it, unborn, as stock git clones an empty repository
//	failure   a clone that fails removes what it made, as stock git's does, but never a taint it took
//
// Not safe for concurrent use: one command's.

package sidecar

import (
	"context"
	"errors"
	"io/fs"
	"path"
)

// A clone's target that holds something already.
var ErrGitCloneTargetNotEmpty = errors.New("git: the clone's directory is not empty")

// What a clone is asked to do.
type GitCloneArgs struct {
	// The remote, ur://<net>/<repo>.
	Url string
	// The new worktree's file system, its root empty.
	FileSystem GitFileSystem
	Settings   *GitSettings
	// The branch to clone, main when empty.
	Branch string
	// The sparse prefix, "" for every path.
	Sparse string
	// The remote's network's evs client, the run's taint and the provenance judge.
	Evs *GitEvsArgs
}

// What a clone did.
type GitCloneResult struct {
	Branch string
	// The branch's tip, nil for a branch evs does not hold yet.
	Tip      *EvsGitOid
	Fetch    *GitFetchResult
	Checkout *GitCheckoutResult
}

// Clones args.Url into args.FileSystem: see the file header.
func GitClone(ctx context.Context, args *GitCloneArgs) (*GitRepository, *GitCloneResult, error) {
	remote, err := ParseGitRemoteUrl(args.Url)
	if err != nil {
		return nil, nil, err
	}
	if args.Evs == nil || args.Evs.Evs == nil {
		return nil, nil, ErrGitNotConnected
	}
	branch := args.Branch
	if branch == "" {
		branch = string(EvsMainRefName)
	}
	if err := GitCheckRefName(GitBranchPrefix + branch); err != nil {
		return nil, nil, err
	}
	entries, err := args.FileSystem.ReadDir(".")
	if err != nil {
		return nil, nil, err
	}
	if 0 < len(entries) {
		return nil, nil, ErrGitCloneTargetNotEmpty
	}
	repository, err := InitGitRepository(ctx, &GitInitArgs{
		FileSystem: args.FileSystem, Settings: args.Settings, Remote: remote.String(), Branch: branch, Sparse: args.Sparse,
	})
	if err != nil {
		gitRemoveAll(args.FileSystem, ".")
		return nil, nil, err
	}
	result, err := repository.cloneInto(ctx, branch, args.Evs)
	if err != nil {
		gitRemoveAll(args.FileSystem, ".")
		return nil, nil, err
	}
	return repository, result, nil
}

// The clone's steps once the repository stands.
func (self *GitRepository) cloneInto(ctx context.Context, branch string, evsArgs *GitEvsArgs) (*GitCloneResult, error) {
	if err := self.Connect(evsArgs); err != nil {
		return nil, err
	}
	fetched, err := self.Fetch(ctx, []string{branch})
	if err != nil {
		return nil, err
	}
	result := &GitCloneResult{Branch: branch, Fetch: fetched, Tip: fetched.Refs[0].Tip}
	if err := self.SetUpstream(branch, GitBranchPrefix+branch); err != nil {
		return nil, err
	}
	if result.Tip == nil {
		return result, nil
	}
	if err := self.refs.Update(GitBranchPrefix+branch, *result.Tip, nil); err != nil {
		return nil, err
	}
	commit, err := self.objects.ReadCommit(ctx, *result.Tip)
	if err != nil {
		return nil, err
	}
	lock, err := self.worktree.LockIndex()
	if err != nil {
		return nil, err
	}
	checkout, err := self.worktree.Checkout(ctx, &GitCheckoutArgs{Tree: commit.TreeOid, SparsePrefix: self.state.Sparse}, &GitIndex{})
	if err != nil {
		lock.Abandon()
		return nil, err
	}
	if err := lock.Commit(checkout.Index); err != nil {
		return nil, err
	}
	result.Checkout = checkout
	return result, nil
}

// Removes name and everything under it, best effort: what a failed clone made.
func gitRemoveAll(fileSystem GitFileSystem, name string) {
	info, err := fileSystem.Lstat(name)
	if err != nil {
		return
	}
	if info.IsDir() {
		entries, err := fileSystem.ReadDir(name)
		if err == nil {
			for _, entry := range entries {
				gitRemoveAll(fileSystem, path.Join(name, entry.Name()))
			}
		}
	}
	if name != "." {
		if err := fileSystem.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return
		}
	}
}
