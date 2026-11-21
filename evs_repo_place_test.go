//go:build !sidecar_http && !ios_extension

// §11.8's resolve row on sidecartest's fake store: a read keeps a 404 5 s, and a write's resolve (ResolveCurrent)
// takes a 404 only from a read of place/ begun after it, so a creation's own readers, whose syncs ask as its RepoCreate
// lands and ahead of its PUT, never refuse the creator's next write; a placement once known is never replaced by a
// 404 a read begun before it brings back late; and place/'s bound is the resolver's settings'. Each case before the
// fix answered the write 404 or held it on the reader's read.

package sidecar_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A store whose first cluster answers the first read of one key from the store and then holds that answer until
// released, as a read the network delays past writes issued after it. Every other read passes.
type evsPlaceHeldStore struct {
	sidecar.BlobStore
	key     string
	taken   atomic.Bool
	held    chan struct{}
	release chan struct{}
}

func newEvsPlaceHeldStore(t *testing.T, inner sidecar.BlobStore, repoId sidecar.Id) *evsPlaceHeldStore {
	store := &evsPlaceHeldStore{
		BlobStore: inner,
		key:       sidecar.EvsPlaceKey(repoId),
		held:      make(chan struct{}),
		release:   make(chan struct{}),
	}
	t.Cleanup(store.let)
	return store
}

// Lets the held read answer, once.
func (self *evsPlaceHeldStore) let() {
	select {
	case <-self.release:
	default:
		close(self.release)
	}
}

func (self *evsPlaceHeldStore) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &evsPlaceHeldCluster{BlobCluster: cluster, store: self}, nil
}

type evsPlaceHeldCluster struct {
	sidecar.BlobCluster
	store *evsPlaceHeldStore
}

func (self *evsPlaceHeldCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	object, err := self.BlobCluster.Get(ctx, key)
	if key == self.store.key && self.store.taken.CompareAndSwap(false, true) {
		close(self.store.held)
		<-self.store.release
	}
	return object, err
}

// Writes place/ for repoId on the first cluster as evs's PUT does, naming that cluster and a creator.
func evsPlaceTestPut(t *testing.T, blobs sidecar.BlobStore, repoId sidecar.Id) *sidecar.EvsRepoPlace {
	t.Helper()
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	place := &sidecar.EvsRepoPlace{ClusterId: cluster.ClusterId(), CreatorSidecarId: sidecar.NewId()}
	placeBytes, err := place.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.PutIfNoneMatch(sidecar.WithWriteClass(t.Context(), sidecar.WriteClassP1), sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	return place
}

// Whether got is want.
func evsPlaceTestSame(got *sidecar.EvsRepoPlace, want *sidecar.EvsRepoPlace) bool {
	return got != nil && got.ClusterId == want.ClusterId && got.CreatorSidecarId == want.CreatorSidecarId
}

// A reader's request caches the 404 just before the creator's PUT places the repo. A read within the 404's 5 s still
// meets it (§11.8's resolve row); the creator's next write, its resolve current, finds the placement, and every read
// after it does too, the clock unmoved throughout.
func TestEvsRepoPlaceCurrentResolveTakesNoNotFoundCachedBeforeThePlacement(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	resolver := sidecar.NewEvsRepoPlaceResolver(blobs, clock, nil)
	repoId := sidecar.NewId()
	if _, err := resolver.Resolve(ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Fatalf("a reader before the placement: %v", err)
	}
	place := evsPlaceTestPut(t, blobs, repoId)
	if _, err := resolver.Resolve(ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Errorf("a read within the 404's 5 s: %v", err)
	}
	got, err := resolver.ResolveCurrent(ctx, repoId)
	if err != nil || !evsPlaceTestSame(got, place) {
		t.Fatalf("the creator's write after the placement: %v %v", got, err)
	}
	if got, err := resolver.Resolve(ctx, repoId); err != nil || !evsPlaceTestSame(got, place) {
		t.Errorf("a read after the write: %v %v", got, err)
	}
	cluster, got, err := resolver.ClusterCurrent(ctx, repoId)
	if err != nil || cluster.ClusterId() != place.ClusterId || !evsPlaceTestSame(got, place) {
		t.Errorf("a write's cluster: %v %v", got, err)
	}
	// the reader's read and the write's, the rest answered from the cache
	if reads, _ := resolver.Counts(); reads != 2 {
		t.Errorf("place/ read %d times", reads)
	}
}

// A write's resolve of a repo place/ does not name answers 404 from its own read, cached for reads as any 404 is, and
// a write after it reads again.
func TestEvsRepoPlaceCurrentResolveOfAnUnplacedRepoAnswersNotPlaced(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	resolver := sidecar.NewEvsRepoPlaceResolver(blobs, clock, nil)
	repoId := sidecar.NewId()
	if _, err := resolver.ResolveCurrent(ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Fatalf("a write to an unplaced repo: %v", err)
	}
	if _, err := resolver.Resolve(ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Errorf("a read after it: %v", err)
	}
	if _, _, err := resolver.ClusterCurrent(ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Errorf("a second write: %v", err)
	}
	if reads, _ := resolver.Counts(); reads != 2 {
		t.Errorf("place/ read %d times: each write reads, the read takes the cached 404", reads)
	}
}

// A reader's read of place/ answered 404 by the store just before the placement, its answer held on the way back. The
// creator's write meanwhile takes no part of that read: it reads place/ itself and finds the placement, a read after
// it shares that, and the held 404, coming back last, answers its own reader and replaces nothing. Before the fix the
// write waited on the reader's read and answered its 404.
func TestEvsRepoPlaceCurrentResolveTakesNoReadInFlightBeforeIt(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	repoId := sidecar.NewId()
	store := newEvsPlaceHeldStore(t, blobs, repoId)
	resolver := sidecar.NewEvsRepoPlaceResolver(store, clock, nil)
	readerErrs := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(ctx, repoId)
		readerErrs <- err
	}()
	<-store.held
	place := evsPlaceTestPut(t, blobs, repoId)
	// real time bounds only the failure: a write that waits on the held read waits until it is let go
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	got, err := resolver.ResolveCurrent(writeCtx, repoId)
	if err != nil || !evsPlaceTestSame(got, place) {
		t.Fatalf("the creator's write while the reader's read is held: %v %v", got, err)
	}
	if got, err := resolver.Resolve(ctx, repoId); err != nil || !evsPlaceTestSame(got, place) {
		t.Errorf("a read after the write: %v %v", got, err)
	}
	store.let()
	if err := <-readerErrs; !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Errorf("the held reader: %v", err)
	}
	if got, err := resolver.Resolve(ctx, repoId); err != nil || !evsPlaceTestSame(got, place) {
		t.Errorf("a read after the held 404 came back: %v %v", got, err)
	}
	if reads, _ := resolver.Counts(); reads != 2 {
		t.Errorf("place/ read %d times", reads)
	}
}

// evs's own PUT remembers its placement while a reader's read on the same process, begun before the PUT, is held: the
// read's late 404 leaves the placement standing, so the creation's activation there resolves at once. Before the fix
// that 404 replaced the placement for 5 s.
func TestEvsRepoPlaceRememberedPlacementOutlivesALateNotFound(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	repoId := sidecar.NewId()
	store := newEvsPlaceHeldStore(t, blobs, repoId)
	resolver := sidecar.NewEvsRepoPlaceResolver(store, clock, nil)
	readerErrs := make(chan error, 1)
	go func() {
		_, err := resolver.Resolve(ctx, repoId)
		readerErrs <- err
	}()
	<-store.held
	place := evsPlaceTestPut(t, blobs, repoId)
	resolver.Remember(repoId, place)
	store.let()
	if err := <-readerErrs; !errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
		t.Errorf("the held reader: %v", err)
	}
	if got, err := resolver.Resolve(ctx, repoId); err != nil || !evsPlaceTestSame(got, place) {
		t.Errorf("the activation's read after the late 404: %v %v", got, err)
	}
}

// place/'s bound is the resolver's settings' (PlaceMaxByteCount, §11.8's 256 B by default): a placement past a
// smaller one is refused as invalid, and not cached, so the bound is read where it is used.
func TestEvsRepoPlaceHoldsAPlacementToItsSettingsBound(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	blobs := sidecartest.NewFakeBlobs(clock, nil, nil, nil)
	repoId := sidecar.NewId()
	place := evsPlaceTestPut(t, blobs, repoId)
	settings := sidecar.DefaultEvsRepoPlaceSettings()
	if settings.PlaceMaxByteCount != 256 {
		t.Errorf("the default bound: %d", settings.PlaceMaxByteCount)
	}
	settings.PlaceMaxByteCount = 8
	narrow := sidecar.NewEvsRepoPlaceResolver(blobs, clock, settings)
	if _, err := narrow.Resolve(ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoPlaceInvalid) {
		t.Errorf("a placement past an 8-byte bound: %v", err)
	}
	if _, err := narrow.ResolveCurrent(ctx, repoId); !errors.Is(err, sidecar.ErrEvsRepoPlaceInvalid) {
		t.Errorf("again, read again: %v", err)
	}
	if reads, _ := narrow.Counts(); reads != 2 {
		t.Errorf("an invalid placement cached: %d reads", reads)
	}
	if got, err := sidecar.NewEvsRepoPlaceResolver(blobs, clock, nil).Resolve(ctx, repoId); err != nil || !evsPlaceTestSame(got, place) {
		t.Errorf("under the default bound: %v %v", got, err)
	}
}
