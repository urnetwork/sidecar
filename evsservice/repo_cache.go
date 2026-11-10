// repo/<repo> as a process reads it: §11.8 step 4's "repo/<repo> (cached at most 5 s)", the state every write and
// every P2 issue rereads (§11.13's skip row), and the format a format-1 binary refuses to write past (§11.6). A
// cached answer, a 404 included, is good for RepoCacheTtl, which Validate holds to 5 s, the bound linearization
// relies on: a write validated against a cached state commits within 5 s of that state's read.
//
// The codec and the state machine are the root's (evs_repo_state.go), which gkm and taskworker read by too. Safe for
// concurrent use.

package evsservice

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// repo/ as one read found it.
type EvsRepoRead struct {
	Object *protocol.EvsRepoObject
	// For an If-Match of a lifecycle CAS (§11.12).
	Etag string
	// When the read was issued, by the engine's clock: a cached answer is good until ReadAt plus RepoCacheTtl.
	ReadAt time.Time
}

// One cached answer: a read, or a 404 good until notFoundUntil.
type repoCacheEntry struct {
	read          *EvsRepoRead
	notFoundUntil time.Time
}

// See the file header.
type RepoCache struct {
	clock    sidecar.Clock
	settings *EvsSettings

	stateLock   sync.Mutex
	repoEntries map[sidecar.Id]*repoCacheEntry
}

// An empty cache on clock.
func NewRepoCache(clock sidecar.Clock, settings *EvsSettings) *RepoCache {
	return &RepoCache{clock: clock, settings: settings, repoEntries: map[sidecar.Id]*repoCacheEntry{}}
}

// repo/ from this process's cache while its answer is under RepoCacheTtl old, else one GET on cluster.
// sidecar.ErrEvsRepoNotFound for a 404, sidecar.ErrEvsRepoInvalid for bytes that break its shape (not cached).
func (self *RepoCache) Read(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (*EvsRepoRead, error) {
	var cached *EvsRepoRead
	var notFound bool
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry, ok := self.repoEntries[repoId]
		if !ok {
			return
		}
		now := self.clock.Now()
		switch {
		case entry.read != nil && now.Before(entry.read.ReadAt.Add(self.settings.RepoCacheTtl)):
			cached = entry.read
		case entry.read == nil && now.Before(entry.notFoundUntil):
			notFound = true
		default:
			delete(self.repoEntries, repoId)
		}
	}()
	switch {
	case cached != nil:
		return cached, nil
	case notFound:
		return nil, sidecar.ErrEvsRepoNotFound
	}
	return self.ReadFresh(ctx, cluster, repoId)
}

// repo/ from the cluster, replacing what the cache held: what a refusal rests on, and a lifecycle CAS's read.
func (self *RepoCache) ReadFresh(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (*EvsRepoRead, error) {
	readAt := self.clock.Now()
	object, err := cluster.Get(ctx, RepoKey(repoId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		self.remember(repoId, &repoCacheEntry{notFoundUntil: readAt.Add(self.settings.RepoCacheTtl)})
		return nil, sidecar.ErrEvsRepoNotFound
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	objectBytes, err := io.ReadAll(io.LimitReader(object.Body, sidecar.EvsRepoObjectMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	parsed, err := sidecar.ParseEvsRepoObject(repoId, objectBytes)
	if err != nil {
		return nil, err
	}
	read := &EvsRepoRead{Object: parsed, Etag: object.Etag, ReadAt: readAt}
	self.remember(repoId, &repoCacheEntry{read: read})
	return read, nil
}

// Keeps entry while caching is on, evicting another first when the cache is full.
func (self *RepoCache) remember(repoId sidecar.Id, entry *repoCacheEntry) {
	if self.settings.RepoCacheTtl <= 0 || self.settings.RepoCacheCount <= 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.repoEntries[repoId]; !ok && self.settings.RepoCacheCount <= len(self.repoEntries) {
		for evictedRepoId := range self.repoEntries {
			delete(self.repoEntries, evictedRepoId)
			break
		}
	}
	self.repoEntries[repoId] = entry
}

// Drops what the cache holds for repoId: after this process wrote repo/, so its next read is the cluster's.
func (self *RepoCache) Forget(repoId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.repoEntries, repoId)
}
