//go:build !ios_extension

// search_status (§16.10's search_status and coverage rows; §18.5's GetStatus; SEARCH-M10-26): per repo in scope, its
// index state, what its cache holds of all, what all lacks, and where the buckets cover from, read from the sync
// engine's snapshots and the cache, never a query. A secret repo and a repo this sidecar cannot read are never listed;
// CORE fills the policy and the remote mode after. With a nil repo, every repo's together: on while any is, the
// earliest coverage, the sums of what all holds and lacks. Safe for concurrent use.

package sidecar

import (
	"context"
	"time"
)

// A repo's status, or with a nil repoId every repo's together (SidecarSearchEngine).
func (self *SearchEngine) Status(repoId *Id) (*SearchStatus, error) {
	repos, err := self.args.Scope.Repos(context.Background())
	if err != nil {
		return nil, err
	}
	request := &SearchRequest{}
	if repoId != nil {
		request.Repos = []Id{*repoId}
	}
	scoped, _ := searchResolveScope(repos, request)
	status := &SearchStatus{FormatSupported: true}
	for _, entry := range scoped {
		refStatus, err := self.refStatus(entry)
		if err != nil {
			return nil, err
		}
		status.IndexOn = status.IndexOn || refStatus.IndexOn
		status.FormatSupported = status.FormatSupported && refStatus.FormatSupported
		if !refStatus.LatestFrom.IsZero() && (status.LatestFrom.IsZero() || refStatus.LatestFrom.Before(status.LatestFrom)) {
			status.LatestFrom = refStatus.LatestFrom
		}
		if status.AllCachedThrough.IsZero() || (!refStatus.AllCachedThrough.IsZero() && refStatus.AllCachedThrough.Before(status.AllCachedThrough)) {
			status.AllCachedThrough = refStatus.AllCachedThrough
		}
		status.AllCachedByteCount += refStatus.AllCachedByteCount
		status.AllMissingByteCount += refStatus.AllMissingByteCount
		status.Uncovered += refStatus.Uncovered
	}
	return status, nil
}

// One ref's status from its snapshot and the cache.
func (self *SearchEngine) refStatus(entry *searchScopedRef) (*SearchStatus, error) {
	status := &SearchStatus{FormatSupported: true, IndexOn: !entry.ref.IndexOff && !entry.ref.Unbuilt}
	if !status.IndexOn {
		return status, nil
	}
	repoId, refId := entry.repo.RepoId, entry.ref.RefId
	snapshot, err := self.args.Sync.Snapshot(repoId, refId)
	if err != nil {
		// not synced yet: on, nothing cached
		return status, nil
	}
	defer snapshot.Release()
	holding := searchHoldingOfSnapshot(snapshot, repoId, refId, nil)
	status.FormatSupported = !holding.newerFormat
	status.IndexOn = !holding.off
	if fromMs := snapshot.LatestFromMs(); 0 < fromMs {
		status.LatestFrom = time.UnixMilli(fromMs).UTC()
	}
	for _, file := range snapshot.manifest.Files {
		if file.Partition.All && file.State == SearchManifestHeld {
			status.AllCachedByteCount += file.ByteCount
		}
	}
	lastDay := uint32(0)
	for _, shard := range holding.allShards {
		if shard.held {
			lastDay = max(lastDay, shard.lastDay+1)
		}
	}
	if 0 < lastDay {
		status.AllCachedThrough = time.UnixMilli(int64(lastDay) * indexDayMs).UTC()
	}
	missing, _, err := self.args.Sync.moreMissing(repoId, refId)
	if err != nil {
		return nil, err
	}
	for _, wanted := range missing {
		status.AllMissingByteCount += wanted.ByteCount
	}
	return status, nil
}
