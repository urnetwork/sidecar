// repo/<repo> as a process reads it: §11.8 step 4's "repo/<repo> (cached at most 5 s)", the state every write and
// every P2 issue rereads (§11.13's skip row), and the format a format-1 binary refuses to write past (§11.6). A
// cached answer is good for RepoCacheTtl, which Validate holds to 5 s, the bound linearization relies on: a write
// validated against a cached state commits within 5 s of that state's read.
//
// Two answers a creation moves on from within moments are kept only RepoKeyingCacheTtl, 0 by default: keying, which
// the creator's activation ends right after KF1's deliveries, and a 404, a placed repo whose repo/ the creator's PUT
// writes right after place/. Each is seen at once by a request on any process after the change, a push right after
// the activation above all, where a cached keying answer would refuse 409 REPO_KEYING, recorded, on a process the
// activation did not run on. An answer the cache held says so (EvsRepoRead.Cached), so a push records no refusal on
// one whose state can still move on to active (push.go's restsOnCache).
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
	// When the read was issued, by the engine's clock: a cached answer is good until ReadAt plus its ttl, RepoCacheTtl
	// or for a keying one RepoKeyingCacheTtl.
	ReadAt time.Time
	// Whether the answer is one the process's cache held rather than a GET issued for this call, so its state may
	// have moved on since: what a push reads again from the cluster before it refuses on a state that can (push.go's
	// restsOnCache).
	Cached bool
}

// One cached answer, good until expiresAt: a read, or a 404 when read is nil.
type repoCacheEntry struct {
	read      *EvsRepoRead
	expiresAt time.Time
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

// repo/ from this process's cache while its answer is under its ttl old, marked Cached, else one GET on cluster.
// sidecar.ErrEvsRepoNotFound for a 404, sidecar.ErrEvsRepoInvalid for bytes that break its shape (not cached).
func (self *RepoCache) Read(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (*EvsRepoRead, error) {
	var cached *repoCacheEntry
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry, ok := self.repoEntries[repoId]
		if !ok {
			return
		}
		if !self.clock.Now().Before(entry.expiresAt) {
			delete(self.repoEntries, repoId)
			return
		}
		cached = entry
	}()
	switch {
	case cached == nil:
		return self.ReadFresh(ctx, cluster, repoId)
	case cached.read == nil:
		return nil, sidecar.ErrEvsRepoNotFound
	}
	return cached.read, nil
}

// repo/ from the cluster, replacing what the cache held: what a refusal rests on, and a lifecycle CAS's read. A
// keying repo/, or a 404, is kept only RepoKeyingCacheTtl (the file header).
func (self *RepoCache) ReadFresh(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (*EvsRepoRead, error) {
	readAt := self.clock.Now()
	object, err := cluster.Get(ctx, RepoKey(repoId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		// placed, with repo/ still to be written: its creation writes it right after place/
		self.remember(repoId, nil, readAt, min(self.settings.RepoCacheTtl, self.settings.RepoKeyingCacheTtl))
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
	ttl := self.settings.RepoCacheTtl
	if parsed.GetState() == protocol.EvsRepoState_EVS_REPO_KEYING {
		// keying until the creator's activation, right after KF1's deliveries
		ttl = min(ttl, self.settings.RepoKeyingCacheTtl)
	}
	self.remember(repoId, &EvsRepoRead{Object: parsed, Etag: object.Etag, ReadAt: readAt, Cached: true}, readAt, ttl)
	return &EvsRepoRead{Object: parsed, Etag: object.Etag, ReadAt: readAt}, nil
}

// Keeps read, nil for a 404, until readAt plus ttl, evicting another repo's first when the cache is full. An answer
// not kept, its ttl or the cache's count not positive, drops what the cache held for repoId instead, which it
// replaces.
func (self *RepoCache) remember(repoId sidecar.Id, read *EvsRepoRead, readAt time.Time, ttl time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ttl <= 0 || self.settings.RepoCacheCount <= 0 {
		delete(self.repoEntries, repoId)
		return
	}
	if _, ok := self.repoEntries[repoId]; !ok && self.settings.RepoCacheCount <= len(self.repoEntries) {
		for evictedRepoId := range self.repoEntries {
			delete(self.repoEntries, evictedRepoId)
			break
		}
	}
	self.repoEntries[repoId] = &repoCacheEntry{read: read, expiresAt: readAt.Add(ttl)}
}

// Drops what the cache holds for repoId: after this process wrote repo/, so its next read is the cluster's.
func (self *RepoCache) Forget(repoId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.repoEntries, repoId)
}
