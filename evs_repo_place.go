//go:build !sidecar_http

// place/<repo_id> (§11.8's placement, owner decision 145, evs-25): the create-only object on the first
// metadata cluster that names the one metadata cluster holding every metadata object of a repo and of its gkm
// group, batch records included, so each ref keeps one commit point while the tier grows by whole clusters.
// evs writes it once, at PUT /evs/v1/repos/<id> (evsservice/place.go); evs and gkm resolve it here, once per
// process, and keep it for the process's life, since it never changes, and a 404 for 5 s.
//
// The body is EvsRepoPlacement {cluster_id, creator_sidecar_id}. In keys an id is 32 lowercase hex characters
// with no dashes (plan-EVS1-format-bytes#9), EvsKeyId's form, which every evs object family shares.
//
// A host file's tag, since it names BlobStore, which no page Worker holds (§4.4). An EvsRepoPlaceResolver is
// safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The placement family's prefix, on the first metadata cluster only.
const EvsPlaceKeyPrefix = "place/"

// §11.8's bound on a placement's bytes.
const EvsPlaceMaxByteCount = 256

var (
	// No place/ object names the repo: it was never created, or its creation has not reached place/ yet.
	ErrEvsRepoNotPlaced = errors.New("evs repo not placed")
	// A place/ object whose bytes are no placement: a fault the caller alarms, never a reason to place again.
	ErrEvsRepoPlaceInvalid = errors.New("evs repo placement invalid")
)

// An id as §11.8's object keys write it: 32 lowercase hex characters, no dashes.
func EvsKeyId(id Id) string {
	return hex.EncodeToString(id[:])
}

// The repo's placement key on the first metadata cluster: place/<repo_id>.
func EvsPlaceKey(repoId Id) string {
	return EvsPlaceKeyPrefix + EvsKeyId(repoId)
}

// One repo's placement, as place/ holds it.
type EvsRepoPlace struct {
	// The metadata cluster holding the repo's objects: BlobStore's id, as sidecar.yml's place_new names it.
	ClusterId string
	// Who placed it: a retry of that sidecar's create continues on ClusterId, and any other creator gets 409.
	CreatorSidecarId Id
}

// The placement's bytes: EvsRepoPlacement, deterministic, so a retry of one creator's create on the same
// cluster writes equal bytes.
func (self *EvsRepoPlace) Marshal() ([]byte, error) {
	if err := self.validate(); err != nil {
		return nil, err
	}
	placementBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsRepoPlacement{
		ClusterId:        self.ClusterId,
		CreatorSidecarId: self.CreatorSidecarId.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	if EvsPlaceMaxByteCount < len(placementBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsRepoPlaceInvalid, len(placementBytes))
	}
	return placementBytes, nil
}

// A cluster id and a creator, each present.
func (self *EvsRepoPlace) validate() error {
	if self.ClusterId == "" {
		return fmt.Errorf("%w: no cluster", ErrEvsRepoPlaceInvalid)
	}
	if self.CreatorSidecarId == (Id{}) {
		return fmt.Errorf("%w: no creator", ErrEvsRepoPlaceInvalid)
	}
	return nil
}

// A placement from place/'s bytes, held to its bound, a cluster id and a 16-byte creator.
func ParseEvsRepoPlace(placementBytes []byte) (*EvsRepoPlace, error) {
	if EvsPlaceMaxByteCount < len(placementBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsRepoPlaceInvalid, len(placementBytes))
	}
	placement := &protocol.EvsRepoPlacement{}
	if err := proto.Unmarshal(placementBytes, placement); err != nil {
		return nil, fmt.Errorf("%w: does not parse", ErrEvsRepoPlaceInvalid)
	}
	creatorSidecarId, err := IdFromBytes(placement.GetCreatorSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: a creator of %d bytes", ErrEvsRepoPlaceInvalid, len(placement.GetCreatorSidecarId()))
	}
	place := &EvsRepoPlace{ClusterId: placement.GetClusterId(), CreatorSidecarId: creatorSidecarId}
	if err := place.validate(); err != nil {
		return nil, err
	}
	return place, nil
}

// Reads a repo's placement on the first cluster, one GET: ErrEvsRepoNotPlaced on a 404.
func ReadEvsRepoPlace(ctx context.Context, firstCluster BlobCluster, repoId Id) (*EvsRepoPlace, error) {
	object, err := firstCluster.Get(ctx, EvsPlaceKey(repoId))
	if errors.Is(err, ErrBlobNotFound) {
		return nil, ErrEvsRepoNotPlaced
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	// one byte past the bound is enough to refuse it
	placementBytes, err := io.ReadAll(io.LimitReader(object.Body, EvsPlaceMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	return ParseEvsRepoPlace(placementBytes)
}

// How a resolver caches. One per process, through its host's settings.
type EvsRepoPlaceSettings struct {
	// How long a 404 stays cached: §11.8's resolve row, 5 s, after which a repo placed meanwhile resolves.
	// Non-positive caches no 404.
	NotFoundTtl time.Duration
	// The most placements one process keeps. A placement never changes, so one evicted costs only its next
	// read. Non-positive keeps none, every resolve reading place/.
	CacheCount int
}

// §11.8's 5 s, and room for a million repos, about 100 MiB at most.
func DefaultEvsRepoPlaceSettings() *EvsRepoPlaceSettings {
	return &EvsRepoPlaceSettings{
		NotFoundTtl: 5 * time.Second,
		CacheCount:  1000 * 1000,
	}
}

// What a resolver holds for one repo: its placement, or a 404 good until notFoundUntil.
type evsRepoPlaceEntry struct {
	place         *EvsRepoPlace
	notFoundUntil time.Time
}

// One read of place/ in flight, which concurrent resolves of the repo wait on.
type evsRepoPlaceCall struct {
	done  chan struct{}
	place *EvsRepoPlace
	err   error
}

// Resolves repos to their metadata clusters for one process (evs, gkm, taskworker). See the file header.
type EvsRepoPlaceResolver struct {
	blobs    BlobStore
	clock    Clock
	settings *EvsRepoPlaceSettings

	stateLock    sync.Mutex
	repoEntries  map[Id]*evsRepoPlaceEntry
	repoCalls    map[Id]*evsRepoPlaceCall
	readCount    int
	evictedCount int
}

// A resolver over blobs, whose first cluster holds place/. clock may be nil for real time, settings nil for
// the defaults.
func NewEvsRepoPlaceResolver(blobs BlobStore, clock Clock, settings *EvsRepoPlaceSettings) *EvsRepoPlaceResolver {
	if settings == nil {
		settings = DefaultEvsRepoPlaceSettings()
	}
	return &EvsRepoPlaceResolver{
		blobs:       blobs,
		clock:       clockOrReal(clock),
		settings:    settings,
		repoEntries: map[Id]*evsRepoPlaceEntry{},
		repoCalls:   map[Id]*evsRepoPlaceCall{},
	}
}

// The repo's placement: from this process's cache, else one GET of place/ that concurrent resolves of the repo
// share. ErrEvsRepoNotPlaced for a repo place/ does not name, cached NotFoundTtl; ErrEvsRepoPlaceInvalid for
// bytes that are no placement, which is not cached; any other error says nothing and is not cached.
func (self *EvsRepoPlaceResolver) Resolve(ctx context.Context, repoId Id) (*EvsRepoPlace, error) {
	for {
		place, leader, err := self.resolveOnce(ctx, repoId)
		// another resolve's read ended with that resolve's ctx: this one reads again, under its own
		if !leader && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) && ctx.Err() == nil {
			continue
		}
		return place, err
	}
}

// One pass of Resolve: the cache, a read in flight, or a read of its own, which leader reports.
func (self *EvsRepoPlaceResolver) resolveOnce(ctx context.Context, repoId Id) (place *EvsRepoPlace, leader bool, err error) {
	var call *evsRepoPlaceCall
	var notFound bool
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if entry, ok := self.repoEntries[repoId]; ok {
			if entry.place != nil {
				place = entry.place
				return
			}
			if self.clock.Now().Before(entry.notFoundUntil) {
				notFound = true
				return
			}
			delete(self.repoEntries, repoId)
		}
		if existing, ok := self.repoCalls[repoId]; ok {
			call = existing
			return
		}
		call = &evsRepoPlaceCall{done: make(chan struct{})}
		self.repoCalls[repoId] = call
		self.readCount += 1
		leader = true
	}()
	switch {
	case place != nil:
		return place, false, nil
	case notFound:
		return nil, false, ErrEvsRepoNotPlaced
	}
	if leader {
		self.read(ctx, repoId, call)
	}
	select {
	case <-call.done:
		return call.place, leader, call.err
	case <-ctx.Done():
		return nil, leader, ctx.Err()
	}
}

// One read of place/ for every resolve waiting on call, whose answer it caches.
func (self *EvsRepoPlaceResolver) read(ctx context.Context, repoId Id, call *evsRepoPlaceCall) {
	place, err := func() (*EvsRepoPlace, error) {
		firstCluster, err := self.blobs.FirstCluster()
		if err != nil {
			return nil, err
		}
		return ReadEvsRepoPlace(ctx, firstCluster, repoId)
	}()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.repoCalls, repoId)
		switch {
		case err == nil:
			self.rememberWithLock(repoId, &evsRepoPlaceEntry{place: place})
		case errors.Is(err, ErrEvsRepoNotPlaced) && 0 < self.settings.NotFoundTtl:
			self.rememberWithLock(repoId, &evsRepoPlaceEntry{notFoundUntil: self.clock.Now().Add(self.settings.NotFoundTtl)})
		}
	}()
	call.place = place
	call.err = err
	close(call.done)
}

// Keeps entry for repoId, evicting another first when the cache is full.
func (self *EvsRepoPlaceResolver) rememberWithLock(repoId Id, entry *evsRepoPlaceEntry) {
	if self.settings.CacheCount <= 0 {
		return
	}
	if _, ok := self.repoEntries[repoId]; !ok && self.settings.CacheCount <= len(self.repoEntries) {
		// any entry will do: a placement never changes, so one evicted costs only its next read
		for evictedRepoId := range self.repoEntries {
			delete(self.repoEntries, evictedRepoId)
			self.evictedCount += 1
			break
		}
	}
	self.repoEntries[repoId] = entry
}

// Records a placement this process wrote or read itself, replacing a cached 404, so the repo it just placed
// resolves at once.
func (self *EvsRepoPlaceResolver) Remember(repoId Id, place *EvsRepoPlace) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rememberWithLock(repoId, &evsRepoPlaceEntry{place: place})
}

// The repo's cluster: its placement resolved, then the store's cluster of that id. ErrBlobClusterUnknown when
// this process holds no credentials for it.
func (self *EvsRepoPlaceResolver) Cluster(ctx context.Context, repoId Id) (BlobCluster, *EvsRepoPlace, error) {
	place, err := self.Resolve(ctx, repoId)
	if err != nil {
		return nil, nil, err
	}
	cluster, err := self.blobs.Cluster(place.ClusterId)
	if err != nil {
		return nil, place, err
	}
	return cluster, place, nil
}

// How many reads of place/ this resolver has issued, and how many placements it has evicted, for tests and
// §19.8's gauges.
func (self *EvsRepoPlaceResolver) Counts() (readCount int, evictedCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.readCount, self.evictedCount
}
