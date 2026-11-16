//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The git-lfs store's daily prune (§11.11's prune row; R-EVS-20, D-EVS-41, I-EVS-9, FS-73; EVS2-M10-28). Daily, an
// indexer or another device holding every ref runs it (reading 10): a second prune loses at path-level CAS harmlessly.
//
//	start    s, the clock at the start, and N, the store's window at s (evs_lfs_settings.go), never under 7 days
//	tips     every git-mode ref's head read from evs at s (ur/lfs itself no tip), each held to a tip the mount holds at
//	         that version, synced first where it lacks one; a ref still lacking its tip refuses the prune
//	         (ErrEvsLfsPruneRefMissing), since a tip it cannot see could need an object
//	required R(tip) for each tip of that read, and R(c) for each commit of the window: one whose committer date, or the
//	         time_ms of the push that introduced it (reading 9), is after s - N
//	remove   each object on ur/lfs whose newest version, its last upload or touch, was signed before s - N and that
//	         nothing above requires, in one push (parts as the sender needs), each naming its version, so a concurrent
//	         touch wins at path-level CAS: the prune then reruns from its start read, at most LfsPruneRerunCount times
//	purge    deletes the content a minute after the removal commits (§11.13); a repo locked since keeps it, its
//	         removal a versioned one
//
// R reads every tip and every commit in the window, so the prune runs off the daemon's foreground work. Plaintext paths
// never reach a log (I-13): only oids and counts do.
//
// Desktop legs only. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A git-mode ref evs holds whose tip the pruning device does not hold, even after a sync: nothing is removed.
	ErrEvsLfsPruneRefMissing = errors.New("evs: a git-lfs prune on a device missing a ref's tip")
	// Every rerun lost path-level CAS to a concurrent touch or prune.
	ErrEvsLfsPruneBusy = errors.New("evs: a git-lfs prune lost to concurrent writes every time")
)

// One git-mode ref as the prune's start read found it: its name, its head's version at evs, and the tip the device
// holds of it at that version, nil when it holds none.
type EvsLfsPruneTip struct {
	RefName []byte
	Version uint64
	Tip     *EvsGitOid
}

// What one prune runs on.
type EvsLfsPruneArgs struct {
	Store *EvsLfsStore
	// R's repository: the mount's bare repository, read by the system git.
	Git *EvsLfsGitRepo
	// Every git-mode ref's head at evs and the tip the device holds of it, read at the start: a device that holds
	// every ref syncs a tip it lacks before it answers, and leaves Tip nil where it still lacks one.
	Tips func(ctx context.Context) ([]*EvsLfsPruneTip, error)
	// The commits pushes introduced after since, by their pushes' time_ms (reading 9); nil adds none beyond the
	// commits whose committer date is in the window.
	PushedSince func(ctx context.Context, since time.Time) ([]EvsGitOid, error)
	// Whether a settings version's signer held repo admin at its signed time (evs_lfs_settings.go); nil checks none.
	IsAdmin func(signerId Id, signedAt time.Time) bool
	// Alarms: a settings version no admin signed. nil discards.
	Alarm func(err error)
	// a test's: called between the reads and the removal, where a racing touch or prune lands
	beforeRemove func(ctx context.Context)
}

// What one prune did: oids and counts, never a path.
type EvsLfsPruneResult struct {
	Start  time.Time
	Window time.Duration
	// Objects the store held, those required, those too young, and those removed.
	ObjectCount   int
	RequiredCount int
	YoungCount    int
	Removed       []EvsLfsOid
	// Pushes the removal took, and reruns after a lost CAS.
	RerunCount int
}

// The prune: see the file header.
func EvsLfsPrune(ctx context.Context, args *EvsLfsPruneArgs) (*EvsLfsPruneResult, error) {
	settings := args.Store.settings
	result := &EvsLfsPruneResult{}
	for attempt := 0; attempt <= settings.LfsPruneRerunCount; attempt += 1 {
		removed, err := evsLfsPruneOnce(ctx, args, result)
		var conflict *EvsPathConflictError
		switch {
		case errors.As(err, &conflict):
			// a touch or another prune moved an object after the start read: from the start again
			result.RerunCount += 1
			continue
		case err != nil:
			return result, err
		}
		result.Removed = removed
		return result, nil
	}
	return result, ErrEvsLfsPruneBusy
}

// One run from its start read.
func evsLfsPruneOnce(ctx context.Context, args *EvsLfsPruneArgs, result *EvsLfsPruneResult) ([]EvsLfsOid, error) {
	store := args.Store
	start := store.clock.Now()
	// after the start's clock read, before any read: a schedule holds a prune between its start and its removal here
	testHookBarrier("evs.lfs.prune.start", EvsKeyId(store.repo.repoId))
	window, err := store.Window(ctx, args.IsAdmin, args.Alarm)
	if err != nil {
		return nil, err
	}
	window = max(window, store.settings.LfsPruneWindowFloor)
	result.Start, result.Window = start, window
	since := start.Add(-window)

	tips, err := args.Tips(ctx)
	if err != nil {
		return nil, err
	}
	commits := []EvsGitOid{}
	for _, tip := range tips {
		if bytes.Equal(tip.RefName, EvsLfsRefName) {
			continue
		}
		if tip.Tip == nil {
			return nil, fmt.Errorf("%w: a ref at version %d", ErrEvsLfsPruneRefMissing, tip.Version)
		}
		commits = append(commits, *tip.Tip)
	}
	recent, err := evsLfsCommitsSince(ctx, args.Git, commits, since)
	if err != nil {
		return nil, err
	}
	commits = append(commits, recent...)
	if args.PushedSince != nil {
		pushed, err := args.PushedSince(ctx, since)
		if err != nil {
			return nil, err
		}
		commits = append(commits, pushed...)
	}
	required := map[EvsLfsOid]bool{}
	seen := map[EvsGitOid]bool{}
	for _, commit := range commits {
		if seen[commit] {
			continue
		}
		seen[commit] = true
		requirements, err := EvsLfsRequired(ctx, args.Git, commit)
		if err != nil {
			return nil, err
		}
		for _, requirement := range requirements {
			required[requirement.Oid] = true
		}
	}

	oids, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	result.ObjectCount, result.RequiredCount, result.YoungCount = len(oids), 0, 0
	objects, err := store.Newest(ctx, oids, true)
	if err != nil {
		return nil, err
	}
	stale := []*EvsLfsObject{}
	for _, object := range objects {
		switch {
		case !object.Present():
		case required[object.Oid]:
			result.RequiredCount += 1
		case !object.SignedAt.Before(since):
			result.YoungCount += 1
		default:
			stale = append(stale, object)
		}
	}
	if args.beforeRemove != nil {
		args.beforeRemove(ctx)
	}
	if _, err := store.RemoveMany(ctx, stale); err != nil {
		return nil, err
	}
	removed := make([]EvsLfsOid, len(stale))
	for i, object := range stale {
		removed[i] = object.Oid
	}
	return removed, nil
}

// The commits reachable from tips whose committer date is after since: `git rev-list --since`, which stops a walk at
// commits older than since.
func evsLfsCommitsSince(ctx context.Context, repo *EvsLfsGitRepo, tips []EvsGitOid, since time.Time) ([]EvsGitOid, error) {
	if len(tips) == 0 {
		return nil, nil
	}
	gitArgs := []string{"rev-list", "--since=" + strconv.FormatInt(since.Unix(), 10)}
	for _, tip := range tips {
		gitArgs = append(gitArgs, tip.String())
	}
	out, err := repo.Git.RunWith(ctx, &EvsGitRunArgs{Dir: repo.Dir, Args: gitArgs, Env: repo.Env})
	if err != nil {
		return nil, err
	}
	commits := []EvsGitOid{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		oid, err := evsGitOidDecodeHex([]byte(line))
		if err != nil {
			return nil, err
		}
		commits = append(commits, oid)
	}
	return commits, nil
}

// Every object on ur/lfs, by oid: its two fan-out levels listed from the root, the settings file and anything that is
// no object's path skipped.
func (self *EvsLfsStore) List(ctx context.Context) ([]EvsLfsOid, error) {
	isHexName := func(name []byte, length int) bool {
		if len(name) != length {
			return false
		}
		for _, character := range name {
			if !('0' <= character && character <= '9' || 'a' <= character && character <= 'f') {
				return false
			}
		}
		return true
	}
	list := func(path string) (*EvsListing, error) {
		listing, err := self.repo.List(ctx, &EvsReadArgs{RefName: EvsLfsRefName, Path: path, Fresh: true})
		if errors.Is(err, ErrEvsPathAbsent) {
			return &EvsListing{}, nil
		}
		return listing, err
	}
	root, err := list("")
	if err != nil {
		return nil, err
	}
	oids := []EvsLfsOid{}
	for _, first := range root.Entries {
		if first.Kind != protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY || !isHexName(first.Name, 2) {
			continue
		}
		middle, err := list(string(first.Name))
		if err != nil {
			return nil, err
		}
		for _, second := range middle.Entries {
			if second.Kind != protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY || !isHexName(second.Name, 2) {
				continue
			}
			leaves, err := list(string(first.Name) + "/" + string(second.Name))
			if err != nil {
				return nil, err
			}
			for _, leaf := range leaves.Entries {
				if leaf.Kind != protocol.EvsEntryKind_EVS_ENTRY_FILE || !isHexName(leaf.Name, 64) {
					continue
				}
				oid, err := EvsLfsOidDecodeHex(string(leaf.Name))
				if err != nil {
					continue
				}
				oids = append(oids, oid)
			}
		}
	}
	return oids, nil
}
