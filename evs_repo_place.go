//go:build !sidecar_http && !ios_extension

// place/<repo_id> (§11.8's placement, owner decision 145, evs-25): the create-only object on the first
// metadata cluster that names the one metadata cluster holding every metadata object of a repo and of its gkm
// group, batch records included, so each ref keeps one commit point while the tier grows by whole clusters.
// evs writes it once, at PUT /evs/v1/repos/<id> (evsservice/place.go); evs and gkm resolve it here, once per
// process, and keep it for the process's life, since it never changes, and a 404 for 5 s.
//
// The 404 is the one answer that changes, once, at the placement, and a creation's readers ask before it: each
// reader's sync of a new repo goes out when its RepoCreate lands, ahead of the creator's PUT. So a cached 404 answers
// reads alone. A write is answered by ResolveCurrent, which takes a 404 only from a read of place/ begun after the
// write did, never a cached one or one already in flight, so no 404 a reader's request planted moments before the
// placement refuses the creator's next write, KF1's POST /gkm/groups above all. A placement, once known, is never
// replaced by a 404 from a read that began before it was written.
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
// cluster writes equal bytes. Held to the format's bound, DefaultEvsRepoPlaceSettings' PlaceMaxByteCount.
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
	if maxByteCount := DefaultEvsRepoPlaceSettings().PlaceMaxByteCount; maxByteCount < len(placementBytes) {
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

// A placement from place/'s bytes, held to the format's bound, DefaultEvsRepoPlaceSettings' PlaceMaxByteCount, a
// cluster id and a 16-byte creator.
func ParseEvsRepoPlace(placementBytes []byte) (*EvsRepoPlace, error) {
	return parseEvsRepoPlace(placementBytes, DefaultEvsRepoPlaceSettings().PlaceMaxByteCount)
}

// ParseEvsRepoPlace held to maxByteCount.
func parseEvsRepoPlace(placementBytes []byte, maxByteCount int) (*EvsRepoPlace, error) {
	if maxByteCount < len(placementBytes) {
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

// Reads a repo's placement on the first cluster, one GET: ErrEvsRepoNotPlaced on a 404. Held to the format's bound,
// DefaultEvsRepoPlaceSettings' PlaceMaxByteCount.
func ReadEvsRepoPlace(ctx context.Context, firstCluster BlobCluster, repoId Id) (*EvsRepoPlace, error) {
	return readEvsRepoPlace(ctx, firstCluster, repoId, DefaultEvsRepoPlaceSettings().PlaceMaxByteCount)
}

// ReadEvsRepoPlace held to maxByteCount.
func readEvsRepoPlace(ctx context.Context, firstCluster BlobCluster, repoId Id, maxByteCount int) (*EvsRepoPlace, error) {
	object, err := firstCluster.Get(ctx, EvsPlaceKey(repoId))
	if errors.Is(err, ErrBlobNotFound) {
		return nil, ErrEvsRepoNotPlaced
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	// one byte past the bound is enough to refuse it
	placementBytes, err := io.ReadAll(io.LimitReader(object.Body, int64(max(0, maxByteCount))+1))
	if err != nil {
		return nil, err
	}
	return parseEvsRepoPlace(placementBytes, maxByteCount)
}

// How a resolver caches, and place/'s format bound. One per process, through its host's settings.
type EvsRepoPlaceSettings struct {
	// §11.8's bound on a placement's bytes, 256 B: a format value every writer and reader of place/ holds to, so a
	// deployment never changes it on one side alone. Non-positive refuses every placement as past it.
	PlaceMaxByteCount int
	// How long a 404 stays cached for reads: §11.8's resolve row, 5 s, after which a repo placed meanwhile resolves.
	// A write never takes a cached 404 (ResolveCurrent). Non-positive caches no 404.
	NotFoundTtl time.Duration
	// The most placements one process keeps. A placement never changes, so one evicted costs only its next
	// read. Non-positive keeps none, every resolve reading place/.
	CacheCount int
}

// §11.8's 256 B and 5 s, and room for a million repos, about 100 MiB at most.
func DefaultEvsRepoPlaceSettings() *EvsRepoPlaceSettings {
	return &EvsRepoPlaceSettings{
		PlaceMaxByteCount: 256,
		NotFoundTtl:       5 * time.Second,
		CacheCount:        1000 * 1000,
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
// bytes that are no placement, which is not cached; any other error says nothing and is not cached. For a read: a
// caller that acts on a 404, a write above all, resolves by ResolveCurrent.
func (self *EvsRepoPlaceResolver) Resolve(ctx context.Context, repoId Id) (*EvsRepoPlace, error) {
	return self.resolve(ctx, repoId, false)
}

// Resolve for a caller that acts on the answer, a write above all: a placement from the cache as Resolve gives it,
// but ErrEvsRepoNotPlaced only from a read of place/ begun after this call, never a cached 404 or a read already in
// flight, either of which may predate the placement the caller's own create made just before it asked (§11.8's
// place then resolve rows: KF1's POST /gkm/groups follows the creator's PUT). So a write to a repo not yet placed
// costs one GET of place/ each; the read it makes is shared with the resolves that come after it, and its answer
// cached as any.
func (self *EvsRepoPlaceResolver) ResolveCurrent(ctx context.Context, repoId Id) (*EvsRepoPlace, error) {
	return self.resolve(ctx, repoId, true)
}

// Resolve, or with current ResolveCurrent.
func (self *EvsRepoPlaceResolver) resolve(ctx context.Context, repoId Id, current bool) (*EvsRepoPlace, error) {
	for {
		place, leader, err := self.resolveOnce(ctx, repoId, current)
		// another resolve's read ended with that resolve's ctx: this one reads again, under its own
		if !leader && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) && ctx.Err() == nil {
			continue
		}
		return place, err
	}
}

// One pass of resolve: the cache, a read in flight, or a read of its own, which leader reports. A current pass takes
// neither a cached 404 nor a read in flight, which began before it: it reads place/ itself, its read standing in
// for the older one as the read later resolves share.
func (self *EvsRepoPlaceResolver) resolveOnce(ctx context.Context, repoId Id, current bool) (place *EvsRepoPlace, leader bool, err error) {
	var call *evsRepoPlaceCall
	var notFound bool
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if entry, ok := self.repoEntries[repoId]; ok {
			switch {
			case entry.place != nil:
				place = entry.place
				return
			case !self.clock.Now().Before(entry.notFoundUntil):
				delete(self.repoEntries, repoId)
			case !current:
				notFound = true
				return
			}
		}
		if existing, ok := self.repoCalls[repoId]; ok && !current {
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
		return readEvsRepoPlace(ctx, firstCluster, repoId, self.settings.PlaceMaxByteCount)
	}()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// a current resolve's read may have taken this one's place: that read is the one later resolves share
		if self.repoCalls[repoId] == call {
			delete(self.repoCalls, repoId)
		}
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

// Keeps entry for repoId, evicting another first when the cache is full. A placement held is never replaced by a 404:
// a placement never changes, so such a 404 comes from a read begun before the placement was written, one a Remember
// or a current resolve's read overtook.
func (self *EvsRepoPlaceResolver) rememberWithLock(repoId Id, entry *evsRepoPlaceEntry) {
	if self.settings.CacheCount <= 0 {
		return
	}
	if held, ok := self.repoEntries[repoId]; ok && held.place != nil && entry.place == nil {
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
// this process holds no credentials for it. For a read, as Resolve's.
func (self *EvsRepoPlaceResolver) Cluster(ctx context.Context, repoId Id) (BlobCluster, *EvsRepoPlace, error) {
	return self.cluster(ctx, repoId, false)
}

// Cluster for a write, its placement resolved as ResolveCurrent resolves it.
func (self *EvsRepoPlaceResolver) ClusterCurrent(ctx context.Context, repoId Id) (BlobCluster, *EvsRepoPlace, error) {
	return self.cluster(ctx, repoId, true)
}

// Cluster, or with current ClusterCurrent.
func (self *EvsRepoPlaceResolver) cluster(ctx context.Context, repoId Id, current bool) (BlobCluster, *EvsRepoPlace, error) {
	place, err := self.resolve(ctx, repoId, current)
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
