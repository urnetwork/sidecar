// §10.6's networks row in the reconciler (owner decision 371; QD-893): a start's listing reads every network its host
// lists, a page at once and the next NetworkPageInterval later, asking the state for each network it holds nothing
// of; a read at a wake that finds no state, as an evicted network's, asks again and owes the network that wake, so an
// expiry passed while it was out still has its gate checked; a read a change woke asks nothing; and a state that keeps
// failing is read again on a wait that doubles to StateRetryMaxInterval. These run on T2's fake state; the real state
// over the gate cache, the Postgres listing and sidecar.yml's gate run on the private test stack
// (server/taskworker/gkm_reconciler_networks_test.go).

package gkmservice

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// T2's state behind a cache that holds only what it was asked for, as AclGkmReconcilerState's does after a restart:
// each network's state stands stored, and a Load installs it, which the watch tells as the cache's install would.
type fakeGkmLoadingState struct {
	*fakeGkmReconcilerState

	loadLock sync.Mutex
	stored   map[sidecar.Id]*GkmNetworkState
	loadIds  []sidecar.Id
	// while set, a Load installs nothing, as a store that fails
	failing bool
}

func newFakeGkmLoadingState(inner *fakeGkmReconcilerState) *fakeGkmLoadingState {
	return &fakeGkmLoadingState{fakeGkmReconcilerState: inner, stored: map[sidecar.Id]*GkmNetworkState{}}
}

var _ GkmReconcilerStateLoader = (*fakeGkmLoadingState)(nil)

func (self *fakeGkmLoadingState) Load(networkId sidecar.Id) {
	stored := func() *GkmNetworkState {
		self.loadLock.Lock()
		defer self.loadLock.Unlock()
		self.loadIds = append(self.loadIds, networkId)
		if self.failing {
			return nil
		}
		return self.stored[networkId]
	}()
	if stored != nil {
		self.set(networkId, stored.View, stored.RepoIds, nil)
	}
}

// Stores a network's state, which the cache loads only when asked.
func (self *fakeGkmLoadingState) store(networkId sidecar.Id, view sidecar.GkmAuthView, repoIds []sidecar.Id) {
	self.loadLock.Lock()
	defer self.loadLock.Unlock()
	self.stored[networkId] = &GkmNetworkState{View: view, RepoIds: slices.Clone(repoIds)}
}

// Drops a network's loaded state, as the cache's byte budget evicts it: State answers not loaded until a load.
func (self *fakeGkmLoadingState) evict(networkId sidecar.Id) {
	self.fakeGkmReconcilerState.stateLock.Lock()
	defer self.fakeGkmReconcilerState.stateLock.Unlock()
	delete(self.networkStates, networkId)
}

func (self *fakeGkmLoadingState) setFailing(failing bool) {
	self.loadLock.Lock()
	defer self.loadLock.Unlock()
	self.failing = failing
}

// Every ask so far, in order.
func (self *fakeGkmLoadingState) loads() []sidecar.Id {
	self.loadLock.Lock()
	defer self.loadLock.Unlock()
	return slices.Clone(self.loadIds)
}

// The host's listing over networks with a config log, in id order: a page holds those of up to limit networks after
// the cursor that the gkm gate admits, as taskworker's network_acl_head under sidecar.yml's gate does.
type fakeGkmNetworkPages struct {
	stateLock  sync.Mutex
	networkIds []sidecar.Id
	admitted   map[sidecar.Id]bool
	// pages to fail before the next that reads
	failCount int
	// the cursor of every page read, nil for the first
	cursors []*sidecar.Id
}

func newFakeGkmNetworkPages(networkIds []sidecar.Id, admitted []sidecar.Id) *fakeGkmNetworkPages {
	pages := &fakeGkmNetworkPages{networkIds: slices.Clone(networkIds), admitted: map[sidecar.Id]bool{}}
	slices.SortFunc(pages.networkIds, sidecar.Id.Cmp)
	for _, networkId := range admitted {
		pages.admitted[networkId] = true
	}
	return pages
}

func (self *fakeGkmNetworkPages) page(ctx context.Context, afterNetworkId *sidecar.Id, limit int) ([]sidecar.Id, *sidecar.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cursors = append(self.cursors, afterNetworkId)
	if 0 < self.failCount {
		self.failCount -= 1
		return nil, nil, errors.New("the listing's store failed")
	}
	start := 0
	if afterNetworkId != nil {
		start = len(self.networkIds)
		for i, networkId := range self.networkIds {
			if 0 < networkId.Cmp(*afterNetworkId) {
				start = i
				break
			}
		}
	}
	examined := self.networkIds[start:min(start+limit, len(self.networkIds))]
	listed := []sidecar.Id{}
	for _, networkId := range examined {
		if self.admitted[networkId] {
			listed = append(listed, networkId)
		}
	}
	if len(examined) < limit {
		return listed, nil, nil
	}
	last := examined[len(examined)-1]
	return listed, &last, nil
}

func (self *fakeGkmNetworkPages) pageCursors() []*sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.cursors)
}

// Networks ids sorted, each with an empty state of its own log.
func gkmListingNetworks(labels ...string) ([]sidecar.Id, map[sidecar.Id]*sidecartest.FakeGkmAuthView) {
	networkIds := []sidecar.Id{}
	views := map[sidecar.Id]*sidecartest.FakeGkmAuthView{}
	for _, label := range labels {
		networkId := testId(label)
		networkIds = append(networkIds, networkId)
		views[networkId] = sidecartest.NewFakeGkmAuthLog().Append(&sidecartest.FakeGkmAuthFixture{Rows: sidecartest.FakeGkmAuthRows()})
	}
	slices.SortFunc(networkIds, sidecar.Id.Cmp)
	return networkIds, views
}

// Waits, a pass at a time, until done holds.
func awaitGkmReconcilerPasses(t *testing.T, ctx context.Context, reconciler *GkmReconciler, what string, done func() bool) {
	t.Helper()
	for {
		_, changed := reconciler.Passes()
		if done() {
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("never %s", what)
		}
	}
}

// Moves the clock by step once the loop waits, then waits for the pass the move starts. step is at most the gate's hint
// interval, so the loop's timer falls within it, and the clock never moves while a pass runs (GkmReconciler.Idle).
func stepGkmReconciler(t *testing.T, ctx context.Context, clock *sidecartest.FakeClock, reconciler *GkmReconciler, step time.Duration) {
	t.Helper()
	for {
		idle, changed := reconciler.Idle()
		if idle {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("the reconciler never waited")
		}
	}
	count, changed := reconciler.Passes()
	clock.Advance(step)
	for {
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("no pass after the clock moved")
		}
		var passed int
		passed, changed = reconciler.Passes()
		if count < passed {
			return
		}
	}
}

// Waits until the listing has read count pages.
func awaitGkmListing(t *testing.T, ctx context.Context, reconciler *GkmReconciler, count int) GkmNetworkListing {
	t.Helper()
	for {
		listing, changed := reconciler.NetworkListing()
		if count <= listing.PageCount {
			return listing
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("the listing never read %d pages: %+v", count, listing)
		}
	}
}

// Whether the reconciler holds a state of the network.
func (self *GkmReconciler) holdsNetworkState(networkId sidecar.Id) bool {
	held, _, _ := self.networkReads(networkId)
	return held
}

// What the reconciler holds of a network's reads: a state, the reads in a row that found none, and a wake owed.
func (self *GkmReconciler) networkReads(networkId sidecar.Id) (held bool, failureCount int, wakeOwed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.networkEntries[networkId]
	if !ok {
		return false, 0, false
	}
	return entry.state != nil, entry.stateFailureCount, entry.wakeOwed
}

// The listing reads a page at once and the next only NetworkPageInterval later, from the cursor past the last network
// the page looked at; it asks the state for each network the gkm gate admits that the reconciler holds nothing of,
// and the reconciler reads each once its install is told. A network the gate does not admit is never asked for, nor
// one the reconciler already read from a change of its own.
func TestGkmReconcilerListsEveryNetworkAPageAnInterval(t *testing.T) {
	fixture := newGkmFixture(t)
	ctx := fixture.ctx
	networkIds, views := gkmListingNetworks("listed-1", "listed-2", "listed-3", "listed-4", "listed-5")
	closed, eventful := networkIds[1], networkIds[3]
	admitted := slices.DeleteFunc(slices.Clone(networkIds), func(networkId sidecar.Id) bool { return networkId == closed })
	pages := newFakeGkmNetworkPages(networkIds, admitted)
	state := newFakeGkmLoadingState(newFakeGkmReconcilerState())
	for networkId, view := range views {
		state.store(networkId, view, nil)
	}
	settings := DefaultGkmReconcilerSettings()
	settings.NetworkPageCount = 2
	settings.NetworkPageInterval = 10 * time.Second
	reconciler, err := NewGkmReconciler(ctx, fixture.host.ServiceHost(), settings, &GkmReconcilerDeps{State: state, Networks: pages.page})
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.Close()
	held := func(networkIds ...sidecar.Id) func() bool {
		return func() bool {
			for _, networkId := range networkIds {
				if !reconciler.holdsNetworkState(networkId) {
					return false
				}
			}
			return true
		}
	}

	// the first page at once: the first network asked for and read, the closed one passed over
	if listing := awaitGkmListing(t, ctx, reconciler, 1); listing.Done || listing.FailureCount != 0 {
		t.Fatalf("the first page: %+v", listing)
	}
	if loads := state.loads(); !slices.Equal(loads, networkIds[:1]) {
		t.Fatalf("asked for %v after the first page", loads)
	}
	awaitGkmReconcilerPasses(t, ctx, reconciler, "read the first page's network", held(networkIds[0]))

	// nothing more before the interval ends; meanwhile the fourth network's log moves, so a change reads it
	fixture.clock.Advance(settings.NetworkPageInterval - time.Second)
	if listing, _ := reconciler.NetworkListing(); listing.PageCount != 1 {
		t.Fatalf("a page before the interval ended: %+v", listing)
	}
	state.set(eventful, views[eventful], nil, nil)
	awaitGkmReconcilerPasses(t, ctx, reconciler, "read the network a change told", held(eventful))

	// the second page at the interval's end: the third asked for, the fourth already read and not asked again
	fixture.clock.Advance(time.Second)
	awaitGkmListing(t, ctx, reconciler, 2)
	if loads := state.loads(); !slices.Equal(loads, []sidecar.Id{networkIds[0], networkIds[2]}) {
		t.Fatalf("asked for %v after the second page", loads)
	}
	awaitGkmReconcilerPasses(t, ctx, reconciler, "read the second page's network", held(networkIds[2]))

	// the third page holds the last network, and the listing is done
	fixture.clock.Advance(settings.NetworkPageInterval)
	if listing := awaitGkmListing(t, ctx, reconciler, 3); !listing.Done || listing.PageCount != 3 {
		t.Fatalf("the last page: %+v", listing)
	}
	if loads := state.loads(); !slices.Equal(loads, []sidecar.Id{networkIds[0], networkIds[2], networkIds[4]}) {
		t.Fatalf("asked for %v after the last page", loads)
	}
	awaitGkmReconcilerPasses(t, ctx, reconciler, "read the last page's network", held(networkIds[4]))
	if reconciler.holdsNetworkState(closed) {
		t.Error("a network the gkm gate does not admit was read")
	}
	cursors := pages.pageCursors()
	if len(cursors) != 3 || cursors[0] != nil || *cursors[1] != networkIds[1] || *cursors[2] != networkIds[3] {
		t.Errorf("the pages' cursors: %v", cursors)
	}
}

// A page that fails is read again from the same cursor at the next interval, and nothing is asked for meanwhile.
func TestGkmReconcilerReadsAFailedPageAgainAtTheInterval(t *testing.T) {
	fixture := newGkmFixture(t)
	ctx := fixture.ctx
	networkIds, views := gkmListingNetworks("retried-1", "retried-2")
	pages := newFakeGkmNetworkPages(networkIds, networkIds)
	pages.failCount = 1
	state := newFakeGkmLoadingState(newFakeGkmReconcilerState())
	for networkId, view := range views {
		state.store(networkId, view, nil)
	}
	settings := DefaultGkmReconcilerSettings()
	reconciler, err := NewGkmReconciler(ctx, fixture.host.ServiceHost(), settings, &GkmReconcilerDeps{State: state, Networks: pages.page})
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.Close()
	if listing := awaitGkmListing(t, ctx, reconciler, 1); listing.FailureCount != 1 || listing.Done {
		t.Fatalf("the failed page: %+v", listing)
	}
	if loads := state.loads(); len(loads) != 0 {
		t.Fatalf("asked for %v on a failed page", loads)
	}
	fixture.clock.Advance(settings.NetworkPageInterval)
	if listing := awaitGkmListing(t, ctx, reconciler, 2); listing.FailureCount != 1 || !listing.Done {
		t.Fatalf("the page read again: %+v", listing)
	}
	if loads := state.loads(); !slices.Equal(loads, networkIds) {
		t.Errorf("asked for %v", loads)
	}
	if cursors := pages.pageCursors(); len(cursors) != 2 || cursors[0] != nil || cursors[1] != nil {
		t.Errorf("the pages' cursors: %v", cursors)
	}
	// a reconciler with no listing has none to wait for
	unlisted, err := NewGkmReconciler(ctx, fixture.host.ServiceHost(), settings, &GkmReconcilerDeps{State: newFakeGkmReconcilerState()})
	if err != nil {
		t.Fatal(err)
	}
	defer unlisted.Close()
	if listing, _ := unlisted.NetworkListing(); !listing.Done || listing.PageCount != 0 {
		t.Errorf("a reconciler with no listing: %+v", listing)
	}
	for _, adjust := range []func(settings *GkmReconcilerSettings){
		func(settings *GkmReconcilerSettings) { settings.NetworkPageCount = 0 },
		func(settings *GkmReconcilerSettings) { settings.NetworkPageInterval = 0 },
		func(settings *GkmReconcilerSettings) { settings.StateRetryMaxInterval = 0 },
	} {
		adjusted := DefaultGkmReconcilerSettings()
		adjust(adjusted)
		if err := adjusted.Validate(); !errors.Is(err, ErrGkmSettings) {
			t.Errorf("settings the listing cannot take: %v", err)
		}
	}
}

// Swaps the world's reconciler for one on a loading state over the world's own, as a restart would.
func (self *gkmReconcilerWorld) restartLoading(settings *GkmReconcilerSettings) *fakeGkmLoadingState {
	self.t.Helper()
	self.reconciler.Close()
	state := newFakeGkmLoadingState(self.state)
	reconciler, err := NewGkmReconciler(self.fixture.ctx, self.fixture.host.ServiceHost(), settings, &GkmReconcilerDeps{State: state})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(reconciler.Close)
	self.reconciler = reconciler
	return state
}

// An expiry that comes while the bounded cache has evicted the network: its wake's read finds no state and asks for
// it once, and the read its install's change brings checks every gate as the wake would have, so the writer's pending
// hint goes within the pass. Without the owed wake, the change read would see the same view as before and check no
// gate.
func TestGkmReconcilerAsksForAnEvictedNetworkAtItsWakeAndKeepsTheWake(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	state := world.restartLoading(DefaultGkmReconcilerSettings())
	writer, reader := testId("sc-writer"), testId("sc-reader")
	for _, sidecarId := range []sidecar.Id{writer, reader} {
		fixture.clientOf(sidecarId)
	}
	expiry := fixture.clock.Now().Add(time.Hour)
	view := world.appendState([]sidecar.Id{writer, reader}, []sidecar.Id{writer}, 0, map[sidecar.Id]time.Time{reader: expiry})
	world.key1 = world.putGeneration(nil, view.Pin())
	state.store(world.networkId, view, []sidecar.Id{world.repoId})
	world.awaitState(view, func() { state.set(world.networkId, view, []sidecar.Id{world.repoId}, nil) })
	if count := world.pendingHints(writer); count != 0 {
		t.Fatalf("a first sight with the gate open hinted: %d", count)
	}

	state.evict(world.networkId)
	for fixture.clock.Now().Before(expiry) {
		stepGkmReconciler(t, fixture.ctx, fixture.clock, world.reconciler, world.reconciler.settings.PendingHintInterval)
	}
	awaitGkmReconcilerPasses(t, fixture.ctx, world.reconciler, "hint the expiry", func() bool { return world.pendingHints(writer) == 1 })
	if loads := state.loads(); !slices.Equal(loads, []sidecar.Id{world.networkId}) {
		t.Errorf("asked for %v at the wake", loads)
	}
	if held, failureCount, wakeOwed := world.reconciler.networkReads(world.networkId); !held || failureCount != 0 || wakeOwed {
		t.Errorf("after the install's read: held %t, %d failures, wake owed %t", held, failureCount, wakeOwed)
	}
}

// A read a change woke that finds no state, a network evicted between its install and the read, asks for nothing,
// so two networks a small cache loads in turn cannot load each other out in a ring; its retry wake asks.
func TestGkmReconcilerAsksNothingAtAChangeThatFindsNoState(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	settings := DefaultGkmReconcilerSettings()
	state := world.restartLoading(settings)
	view := world.appendState([]sidecar.Id{testId("sc-writer")}, []sidecar.Id{testId("sc-writer")}, 0, nil)
	state.store(world.networkId, view, []sidecar.Id{world.repoId})
	world.awaitState(view, func() { state.set(world.networkId, view, []sidecar.Id{world.repoId}, nil) })

	// evicted, then a change: its read finds nothing, and asks nothing
	state.evict(world.networkId)
	state.changed(&GkmStateChange{NetworkId: world.networkId})
	awaitGkmReconcilerPasses(t, fixture.ctx, world.reconciler, "read the change", func() bool {
		_, failureCount, _ := world.reconciler.networkReads(world.networkId)
		return failureCount == 1
	})
	if loads := state.loads(); len(loads) != 0 {
		t.Fatalf("a change's read asked for %v", loads)
	}
	if _, _, wakeOwed := world.reconciler.networkReads(world.networkId); wakeOwed {
		t.Error("a change's read owes a wake")
	}
	// its retry wake asks, and its install is read
	world.awaitIdle()
	fixture.clock.Advance(settings.PendingHintInterval - time.Second)
	world.awaitIdle()
	if loads := state.loads(); len(loads) != 0 {
		t.Fatalf("asked for %v before the retry wake", loads)
	}
	fixture.clock.Advance(time.Second)
	awaitGkmReconcilerPasses(t, fixture.ctx, world.reconciler, "read the network again", func() bool {
		_, failureCount, wakeOwed := world.reconciler.networkReads(world.networkId)
		return failureCount == 0 && !wakeOwed
	})
	if loads := state.loads(); !slices.Equal(loads, []sidecar.Id{world.networkId}) {
		t.Errorf("asked for %v at the retry wake", loads)
	}
}

// A listed network whose state never loads is read and asked for again PendingHintInterval after the listing asked,
// then after twice that, and so on up to StateRetryMaxInterval, never sooner; once its load installs, it is read and
// its failures end.
func TestGkmReconcilerBacksOffAStateThatDoesNotLoad(t *testing.T) {
	fixture := newGkmFixture(t)
	ctx := fixture.ctx
	networkIds, views := gkmListingNetworks("failing-1")
	networkId := networkIds[0]
	pages := newFakeGkmNetworkPages(networkIds, networkIds)
	state := newFakeGkmLoadingState(newFakeGkmReconcilerState())
	state.store(networkId, views[networkId], nil)
	state.setFailing(true)
	settings := DefaultGkmReconcilerSettings()
	interval := settings.PendingHintInterval
	settings.StateRetryMaxInterval = 4 * interval
	reconciler, err := NewGkmReconciler(ctx, fixture.host.ServiceHost(), settings, &GkmReconcilerDeps{State: state, Networks: pages.page})
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.Close()
	awaitGkmListing(t, ctx, reconciler, 1)
	listedAt := fixture.clock.Now()
	// the loop's first pass, and the one the listing's wake brings
	awaitGkmReconcilerPasses(t, ctx, reconciler, "pass after the listing", func() bool {
		count, _ := reconciler.Passes()
		return 2 <= count
	})
	if loads := state.loads(); len(loads) != 1 {
		t.Fatalf("the listing asked %v", loads)
	}
	// asked again PendingHintInterval after the listing, then after waits doubling to StateRetryMaxInterval and held
	// there: at 1, 2, 4, 8, 12 and 16 intervals, and at no step between
	askedAfter := []time.Duration{interval, 2 * interval, 4 * interval, 8 * interval, 12 * interval, 16 * interval}
	for step := 1; step <= 16; step += 1 {
		if step == 13 {
			// the store recovers: the ask at 16 intervals installs
			state.setFailing(false)
		}
		stepGkmReconciler(t, ctx, fixture.clock, reconciler, interval)
		elapsed := fixture.clock.Now().Sub(listedAt)
		want := 1
		for _, after := range askedAfter {
			if after <= elapsed {
				want += 1
			}
		}
		if loads := state.loads(); len(loads) != want {
			t.Fatalf("asked %d times %s after the listing, want %d", len(loads), elapsed, want)
		}
	}
	// the install's change is read, which holds the state and ends the failures
	awaitGkmReconcilerPasses(t, ctx, reconciler, "read the recovered network", func() bool { return reconciler.holdsNetworkState(networkId) })
	if _, failureCount, wakeOwed := reconciler.networkReads(networkId); failureCount != 0 || wakeOwed {
		t.Errorf("after the install: %d failures, wake owed %t", failureCount, wakeOwed)
	}
}

// The real state's Load tells the gate cache, and nothing else it answers does; a state with no gate is told nothing.
func TestAclGkmReconcilerStateLoadTellsTheCache(t *testing.T) {
	gate := &coldGkmAclGate{status: sidecar.AclGateNotLoaded}
	state := NewAclGkmReconcilerState(gate)
	networkId := testId("network-load")
	if _, err := state.State(t.Context(), networkId); err == nil {
		t.Fatal("a state the cache does not hold")
	}
	state.Networks()
	state.SidecarStanding(t.Context(), testId("sc-anyone"))
	if changed := gate.changed(); len(changed) != 0 {
		t.Fatalf("a read told the cache of %v", changed)
	}
	state.Load(networkId)
	if changed := gate.changed(); !slices.Equal(changed, []sidecar.Id{networkId}) {
		t.Errorf("Load told the cache of %v", changed)
	}
	NewAclGkmReconcilerState(nil).Load(networkId)
}
