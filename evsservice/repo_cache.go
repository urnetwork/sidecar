// repo/<repo> as a process reads it: §11.8 step 4's "repo/<repo> (cached at most 5 s)", the state every write and
// every P2 issue rereads (§11.13's skip row), and the format a format-1 binary refuses to write past (§11.6). A
// cached answer, a 404 included, is good for RepoCacheTtl, which Validate holds to 5 s, the bound linearization
// relies on: a write validated against a cached state commits within 5 s of that state's read.
//
// The codec here is the draft's: EVS1-M2-19 owns repo/'s state machine and the root codec gkm rereads, and moves
// ParseEvsRepoObject there. Safe for concurrent use.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.8's bound on repo/'s bytes.
const evsRepoMaxByteCount = 4 * 1024

// The formats a repo may be in (§11.6): 1, and 2 from its first push carrying a format-2 value.
const (
	evsRepoFormat1 = 1
	evsRepoFormat2 = 2
)

var (
	// No repo/ object: a placed repo whose create has not written it yet, or a key never created.
	ErrEvsRepoNotFound = errors.New("evs repo not found")
	// A repo/ object whose bytes break its shape: a fault that alarms, never a state to act on.
	ErrEvsRepoInvalid = errors.New("evs repo object invalid")
)

// repo/'s bytes held to their shape: its bound, a 16-byte repo id equal to the key's, a kind acl.proto has, a
// state EvsRepoState has, format 1 or 2, and a network id of 16 bytes or none (plan-EVSB-repo-network: absent
// reads as held).
func ParseEvsRepoObject(repoId sidecar.Id, objectBytes []byte) (*protocol.EvsRepoObject, error) {
	if evsRepoMaxByteCount < len(objectBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsRepoInvalid, len(objectBytes))
	}
	object := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(objectBytes, object); err != nil {
		return nil, fmt.Errorf("%w: does not parse", ErrEvsRepoInvalid)
	}
	if !bytes.Equal(object.GetRepoId(), repoId.Bytes()) {
		return nil, fmt.Errorf("%w: another repo's id", ErrEvsRepoInvalid)
	}
	if _, ok := protocol.RepoKind_name[int32(object.GetKind())]; !ok || object.GetKind() == 0 {
		return nil, fmt.Errorf("%w: kind %d", ErrEvsRepoInvalid, object.GetKind())
	}
	if object.GetState() < protocol.EvsRepoState_EVS_REPO_KEYING || protocol.EvsRepoState_EVS_REPO_SHREDDED < object.GetState() {
		return nil, fmt.Errorf("%w: state %d", ErrEvsRepoInvalid, object.GetState())
	}
	if object.GetFormat() != evsRepoFormat1 && object.GetFormat() != evsRepoFormat2 {
		return nil, fmt.Errorf("%w: format %d", ErrEvsRepoInvalid, object.GetFormat())
	}
	if networkIdLength := len(object.GetNetworkId()); networkIdLength != 0 && networkIdLength != 16 {
		return nil, fmt.Errorf("%w: a network id of %d bytes", ErrEvsRepoInvalid, networkIdLength)
	}
	if ownerLength := len(object.GetOwnerMemberId()); ownerLength != 0 && ownerLength != 16 {
		return nil, fmt.Errorf("%w: an owner of %d bytes", ErrEvsRepoInvalid, ownerLength)
	}
	return object, nil
}

// repo/ as one read found it.
type EvsRepoRead struct {
	Object *protocol.EvsRepoObject
	// For an If-Match of a lifecycle CAS (§11.12).
	Etag string
	// When the read was issued, by the engine's clock: a cached answer is good until ReadAt plus RepoCacheTtl.
	ReadAt time.Time
}

// Whether a format-1 binary may write to the repo: a format-2 repo/ answers 503 before step 4 and writes nothing
// (plan-EVS1-format-unsupported#4).
func (self *EvsRepoRead) Format1() bool {
	return self.Object.GetFormat() == evsRepoFormat1
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
// ErrEvsRepoNotFound for a 404, ErrEvsRepoInvalid for bytes that break its shape (not cached).
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
		return nil, ErrEvsRepoNotFound
	}
	return self.ReadFresh(ctx, cluster, repoId)
}

// repo/ from the cluster, replacing what the cache held: what a refusal rests on, and a lifecycle CAS's read.
func (self *RepoCache) ReadFresh(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (*EvsRepoRead, error) {
	readAt := self.clock.Now()
	object, err := cluster.Get(ctx, RepoKey(repoId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		self.remember(repoId, &repoCacheEntry{notFoundUntil: readAt.Add(self.settings.RepoCacheTtl)})
		return nil, ErrEvsRepoNotFound
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	objectBytes, err := io.ReadAll(io.LimitReader(object.Body, evsRepoMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	parsed, err := ParseEvsRepoObject(repoId, objectBytes)
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
