//go:build !sidecar_http

package sidecartest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

// The fake on clock with settings.
func newTestFakeSocketStore(clock sidecar.Clock, settings *socketsservice.SocketStoreSettings) socketsservice.SocketStore {
	return NewFakeSocketStore(clock, settings, nil)
}

func TestFakeSocketStorePassesItsSuite(t *testing.T) {
	RunSocketStoreSuite(t, newTestFakeSocketStore)
}

// DESIGN-DETAILS 13.6's twins of SockRegTwin-NoTombstone, -NoPairFloor and -NoSetVersion: each fails when
// the store's rule is taken out.
func TestRemovalLeavesATombstone(t *testing.T) {
	RunSocketStoreSuiteCase(t, SocketSuiteCaseRemovalLeavesATombstone, newTestFakeSocketStore)
}

func TestPairWriteBelowFloorRefused(t *testing.T) {
	RunSocketStoreSuiteCase(t, SocketSuiteCasePairWriteBelowFloor, newTestFakeSocketStore)
}

func TestOlderPageIsStale(t *testing.T) {
	RunSocketStoreSuiteCase(t, SocketSuiteCaseOlderPageIsStale, newTestFakeSocketStore)
}

// QD-656: a touch gives a pair the lesser of its grant's remaining life and EdgePairTtl, lengthening a
// short one and never passing the grant, on the store's clock.
func TestFakeSocketPairTouchLivesToItsGrant(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	settings := socketsservice.DefaultSocketStoreSettings()
	store := NewFakeSocketStore(clock, settings, nil)
	listenerId := socketSuiteId()
	shortGrant := socketSuiteId()
	longGrant := socketSuiteId()
	nowMillis := uint64(clock.Now().UnixMilli())
	if _, _, err := store.SetServicePair(ctx, listenerId, shortGrant, nowMillis+uint64((5*time.Minute).Milliseconds()), time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SetServicePair(ctx, listenerId, longGrant, nowMillis+uint64((24*time.Hour).Milliseconds()), time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	if err := store.TouchServicePairs(ctx, listenerId); err != nil {
		t.Fatal(err)
	}
	found := func(dialerId connect.Id) bool {
		_, found, err := store.GetServicePair(ctx, listenerId, dialerId)
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	// past the minute each was written for
	clock.Advance(5*time.Minute - time.Millisecond)
	if !found(shortGrant) || !found(longGrant) {
		t.Fatal("a touched pair ended at its first ttl")
	}
	clock.Advance(time.Millisecond)
	if found(shortGrant) {
		t.Fatal("a touched pair outlived its grant")
	}
	clock.Advance(settings.EdgePairTtl - 5*time.Minute - time.Millisecond)
	if !found(longGrant) {
		t.Fatal("a touched pair ended before EdgePairTtl")
	}
	clock.Advance(time.Millisecond)
	if found(longGrant) {
		t.Fatal("a touched pair outlived EdgePairTtl")
	}
}

// §9.6: a pair lives its ttl on the store's clock, rounded up to the millisecond HPEXPIRE keeps.
func TestFakeSocketPairEndsAtItsTtl(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	store := NewFakeSocketStore(clock, nil, nil)
	listenerId := socketSuiteId()
	dialerId := socketSuiteId()
	if _, _, err := store.SetServicePair(ctx, listenerId, dialerId, 99, 1500*time.Microsecond, 0); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Millisecond)
	if _, found, err := store.GetServicePair(ctx, listenerId, dialerId); err != nil || !found {
		t.Fatalf("before its ttl: %v %v", found, err)
	}
	clock.Advance(time.Millisecond)
	if _, found, err := store.GetServicePair(ctx, listenerId, dialerId); err != nil || found {
		t.Fatalf("at its ttl: %v %v", found, err)
	}
}

// §9.8: a client's set outlives its last call by ClientSetTtl and no more, so a page after that is no
// retry of anything.
func TestFakeSocketClientSetEndsAtItsTtl(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	settings := socketsservice.DefaultSocketStoreSettings()
	env := &socketSuiteEnv{ctx: ctx, clock: clock, settings: settings, store: NewFakeSocketStore(clock, settings, nil)}
	networkId := socketSuiteId()
	clientId := socketSuiteId()
	if err := env.mustApplyWhole(networkId, clientId, 9, socketSuiteRegistration("")); err != nil {
		t.Fatal(err)
	}
	clock.Advance(settings.ClientSetTtl - time.Millisecond)
	if result, err := env.applyWhole(networkId, clientId, 8); err != nil || !result.Stale {
		t.Fatalf("inside the set's ttl: %+v %v", result, err)
	}
	clock.Advance(time.Millisecond)
	if result, err := env.applyWhole(networkId, clientId, 8); err != nil || result.Stale {
		t.Fatalf("at the set's ttl: %+v %v", result, err)
	}
}

// One Find is one call, whatever it carries (§22.5's one script per Find).
func TestFakeSocketPickIsOneCall(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	store := NewFakeSocketStore(clock, nil, nil)
	env := &socketSuiteEnv{ctx: ctx, clock: clock, settings: socketsservice.DefaultSocketStoreSettings(), store: store}
	networkId := socketSuiteId()
	listenerId := socketSuiteId()
	registration := socketSuiteRegistration("")
	if err := env.mustApplyWhole(networkId, listenerId, 1, registration); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pick(ctx, &socketsservice.SocketStorePickRequest{
		NetworkId:       networkId,
		NameKey:         registration.NameKey(),
		DialerClientId:  socketSuiteId(),
		DialerNetworkId: networkId,
		Reports:         []*socketsservice.SocketStoreReport{{ListenerClientId: listenerId, ListenId: *registration.ListenId}},
	}); err != nil {
		t.Fatal(err)
	}
	if count := store.OpCount("Pick"); count != 1 {
		t.Errorf("%d picks", count)
	}
	if count := store.OpCount("ListListeners"); count != 0 {
		t.Errorf("a pick read %d groups beside its own", count)
	}
}

// A wipe loses everything, as Redis loss does, and one round of pages brings it back (§9.5).
func TestFakeSocketWipeLosesEverything(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	store := NewFakeSocketStore(clock, nil, nil)
	env := &socketSuiteEnv{ctx: ctx, clock: clock, settings: socketsservice.DefaultSocketStoreSettings(), store: store}
	networkId := socketSuiteId()
	clientId := socketSuiteId()
	registration := socketSuiteRegistration("")
	if err := env.mustApplyWhole(networkId, clientId, 4, registration); err != nil {
		t.Fatal(err)
	}
	store.Wipe()
	if pick, err := env.pick(networkId, registration.NameKey(), socketSuiteId(), 0, 0); err != nil || pick.Outcome != socketsservice.SocketPickNoListener {
		t.Fatalf("after a wipe: %+v %v", pick, err)
	}
	if result, err := env.applyWhole(networkId, clientId, 4, registration); err != nil || result.Stale || !result.Outcomes[0].FirstListener {
		t.Fatalf("the next page: %+v %v", result, err)
	}
	if pick, err := env.pick(networkId, registration.NameKey(), socketSuiteId(), 0, 0); err != nil || pick.Outcome != socketsservice.SocketPickFound {
		t.Fatalf("after the next page: %+v %v", pick, err)
	}
}

func TestFakeSocketStoreTakesAFaultPlan(t *testing.T) {
	ctx := context.Background()
	clock := NewFakeClock(DefaultClockStart())
	store := NewFakeSocketStore(clock, nil, nil)
	if _, err := store.Faults().Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "sockets.ApplyPage", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	env := &socketSuiteEnv{ctx: ctx, clock: clock, settings: socketsservice.DefaultSocketStoreSettings(), store: store}
	networkId := socketSuiteId()
	registration := socketSuiteRegistration("")
	if _, err := env.applyWhole(networkId, socketSuiteId(), 1, registration); err == nil {
		t.Fatal("the planned failure did not fire")
	}
	if pick, err := env.pick(networkId, registration.NameKey(), socketSuiteId(), 0, 0); err != nil || pick.Outcome != socketsservice.SocketPickNoListener {
		t.Fatalf("a page that failed before applying wrote: %+v %v", pick, err)
	}
}

// A page the engine should never send is refused whole, before anything is written.
func TestFakeSocketStoreRefusesMalformedPages(t *testing.T) {
	ctx := context.Background()
	store := NewFakeSocketStore(NewFakeClock(DefaultClockStart()), nil, nil)
	first := socketSuiteRegistration("")
	second := socketSuiteRegistration("")
	sorted := socketSuiteSorted([]*sidecar.SocketRegistration{first, second})
	empty := socketSuiteRegistration("")
	empty.NameToken = nil
	for _, page := range []*socketsservice.SocketStorePage{
		{Registrations: []*sidecar.SocketRegistration{sorted[1], sorted[0]}},
		{Registrations: []*sidecar.SocketRegistration{sorted[0], sorted[0]}},
		{KeyStart: sorted[1].NameKey(), Registrations: []*sidecar.SocketRegistration{sorted[0]}},
		{KeyEnd: sorted[0].NameKey(), Registrations: []*sidecar.SocketRegistration{sorted[0]}},
		{Registrations: []*sidecar.SocketRegistration{empty}},
	} {
		page.NetworkId = socketSuiteId()
		page.ListenerClientId = socketSuiteId()
		if _, err := store.ApplyPage(ctx, page); !errors.Is(err, socketsservice.ErrSocketStoreRequest) {
			t.Errorf("a malformed page: %v", err)
		}
	}
}
