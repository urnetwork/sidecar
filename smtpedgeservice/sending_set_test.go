// The sending set (SMTP-M9-12, §14.6, owner decision 124): no address sends before its FCrDNS holds,
// checked at start and periodically; a listed address leaves the set and the next dial avoids it; with
// none usable the engine is not ready.

package smtpedgeservice_test

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

var testSecondSendingAddress = netip.MustParseAddr("192.0.2.11")

const testSecondHeloName = "o2.out.root.example"

// A PTR resolver that fails for now while told to.
type flakyPtr struct {
	inner   smtpedgeservice.SmtpPtrResolver
	failing atomic.Bool
}

func (self *flakyPtr) LookupPtr(ctx context.Context, address netip.Addr) ([]string, error) {
	if self.failing.Load() {
		return nil, sidecar.ErrSmtpMxTemporary
	}
	return self.inner.LookupPtr(ctx, address)
}

// A breaker state a test changes.
type testBreaker struct {
	stateLock sync.Mutex
	state     *smtpedgeservice.SmtpBreakerState
}

func (self *testBreaker) set(state *smtpedgeservice.SmtpBreakerState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = state
}

func (self *testBreaker) get() (*smtpedgeservice.SmtpBreakerState, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state, self.state != nil
}

// Two sending addresses in a world; setup chooses what DNS says of each before the first check.
type sendingWorld struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	world    *sidecartest.MxWorld
	ptr      *flakyPtr
	breaker  *testBreaker
	settings *smtpedgeservice.SmtpEdgeSettings
	set      *smtpedgeservice.SmtpSendingSet
	caps     *smtpedgeservice.SmtpDestinationCaps
}

func newSendingWorld(t *testing.T, setup func(world *sidecartest.MxWorld)) *sendingWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	mxWorldSettings := sidecartest.DefaultMxWorldSettings()
	mxWorldSettings.Clock = clock
	world, err := sidecartest.NewMxWorld(mxWorldSettings)
	if err != nil {
		t.Fatal(err)
	}
	setup(world)
	settings := worldSettings()
	settings.SendingAddresses = append(settings.SendingAddresses, smtpedgeservice.SmtpSendingAddress{Address: testSecondSendingAddress, HeloName: testSecondHeloName})
	self := &sendingWorld{t: t, ctx: ctx, clock: clock, host: host, world: world, ptr: &flakyPtr{inner: world}, breaker: &testBreaker{state: &smtpedgeservice.SmtpBreakerState{}}, settings: settings}
	self.set = smtpedgeservice.NewSmtpSendingSet(ctx, settings, clock, host.Metrics, self.ptr, world, self.breaker.get)
	t.Cleanup(self.set.Close)
	if err := self.set.AwaitChecks(ctx, 1); err != nil {
		t.Fatal(err)
	}
	sidecartest.RegisterSmtpQuotaScripts(host.Redis)
	quota, err := smtpedgeservice.NewSmtpQuota(ctx, host.ServiceHost(), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Breaker().Close)
	self.caps = quota.DestinationCaps()
	return self
}

// Both addresses' FCrDNS holding.
func bothFcrdns(world *sidecartest.MxWorld) {
	world.SetPtr(testSendingAddress, testHeloName)
	world.SetPtr(testSecondSendingAddress, testSecondHeloName+".")
	world.AddMx(testHeloName, testSendingAddress, nil)
	world.AddMx(testSecondHeloName, testSecondSendingAddress, nil)
}

func (self *sendingWorld) usable() []netip.Addr {
	addresses := []netip.Addr{}
	for _, sendingAddress := range self.set.Usable() {
		addresses = append(addresses, sendingAddress.Address)
	}
	return addresses
}

// Moves the clock one check interval and waits for the count'th check. The move comes once the check before was
// counted (newSendingWorld's await, or the last recheck's), and the set counts a check only once its wait for the next
// is armed, so the move always passes that wait's timer. FakeClock.AwaitTimers could tell the same thing here only by
// counting every timer on the clock, the quota's and the breaker's among them; the set's own order says it for every
// caller (loop_arming_test.go).
func (self *sendingWorld) recheck(count int) {
	self.t.Helper()
	self.clock.Advance(self.settings.FcrdnsCheckInterval)
	if err := self.set.AwaitChecks(self.ctx, count); err != nil {
		self.t.Fatal(err)
	}
}

func TestSendingSetUsesOnlyAddressesWhoseFcrdnsHolds(t *testing.T) {
	s := newSendingWorld(t, func(world *sidecartest.MxWorld) {
		// the first holds; the second's PTR names another host
		world.SetPtr(testSendingAddress, testHeloName)
		world.AddMx(testHeloName, testSendingAddress, nil)
		world.SetPtr(testSecondSendingAddress, "other.out.root.example")
		world.AddMx(testSecondHeloName, testSecondSendingAddress, nil)
	})
	if usable := s.usable(); len(usable) != 1 || usable[0] != testSendingAddress {
		t.Fatalf("usable %v", usable)
	}
	if value := s.host.Metrics.Value("urnetwork_smtpedge_sending_addresses", "failing"); value != 1 {
		t.Fatalf("%v failing", value)
	}
}

func TestSendingSetNeedsTheHeloNamesARecord(t *testing.T) {
	s := newSendingWorld(t, func(world *sidecartest.MxWorld) {
		world.SetPtr(testSendingAddress, testHeloName)
		world.SetPtr(testSecondSendingAddress, testSecondHeloName)
		// the second's HELO name holds another address
		world.AddMx(testHeloName, testSendingAddress, nil)
		world.AddMx(testSecondHeloName, netip.MustParseAddr("192.0.2.99"), nil)
	})
	if usable := s.usable(); len(usable) != 1 || usable[0] != testSendingAddress {
		t.Fatalf("usable %v", usable)
	}
}

func TestSendingSetRechecksPeriodically(t *testing.T) {
	s := newSendingWorld(t, func(world *sidecartest.MxWorld) {
		world.AddMx(testHeloName, testSendingAddress, nil)
		world.AddMx(testSecondHeloName, testSecondSendingAddress, nil)
	})
	if usable := s.usable(); len(usable) != 0 {
		t.Fatalf("usable %v with no PTR", usable)
	}
	s.world.SetPtr(testSendingAddress, testHeloName)
	s.recheck(2)
	if usable := s.usable(); len(usable) != 1 || usable[0] != testSendingAddress {
		t.Fatalf("usable %v after its PTR appeared", usable)
	}
	// an answer that disagrees takes it out again
	s.world.SetPtr(testSendingAddress, "moved.out.root.example")
	s.recheck(3)
	if usable := s.usable(); len(usable) != 0 {
		t.Fatalf("usable %v after its PTR moved", usable)
	}
}

func TestSendingSetKeepsItsVerdictThroughALookupThatFailsForNow(t *testing.T) {
	s := newSendingWorld(t, bothFcrdns)
	if usable := s.usable(); len(usable) != 2 {
		t.Fatalf("usable %v", usable)
	}
	s.ptr.failing.Store(true)
	s.recheck(2)
	if usable := s.usable(); len(usable) != 2 {
		t.Fatalf("a DNS hiccup emptied the set: %v", usable)
	}
}

func TestSendingSetListedAddressLeavesTheSetAndTheNextDialAvoidsIt(t *testing.T) {
	s := newSendingWorld(t, bothFcrdns)
	mx := netip.MustParseAddr("203.0.113.25")
	picked, release, ok := s.set.Pick(mx, s.caps, 10)
	if !ok || picked != testSendingAddress {
		t.Fatalf("picked %v", picked)
	}
	release()
	s.breaker.set(&smtpedgeservice.SmtpBreakerState{Level: smtpedgeservice.SmtpBreakerLevelCommunity, ListedAddresses: []netip.Addr{testSendingAddress}})
	if usable := s.usable(); len(usable) != 1 || usable[0] != testSecondSendingAddress {
		t.Fatalf("usable %v while the first is listed", usable)
	}
	picked, release, ok = s.set.Pick(mx, s.caps, 10)
	if !ok || picked != testSecondSendingAddress {
		t.Fatalf("picked %v while the first is listed", picked)
	}
	release()
	// delisted, it is back within the feed refresh, with no recheck of its FCrDNS
	s.breaker.set(&smtpedgeservice.SmtpBreakerState{})
	if usable := s.usable(); len(usable) != 2 {
		t.Fatalf("usable %v after delisting", usable)
	}
}

func TestSendingSetPicksTheLeastLoadedAddress(t *testing.T) {
	s := newSendingWorld(t, bothFcrdns)
	mx := netip.MustParseAddr("203.0.113.25")
	first, releaseFirst, ok := s.set.Pick(mx, s.caps, 10)
	if !ok {
		t.Fatal("no pick")
	}
	second, releaseSecond, ok := s.set.Pick(mx, s.caps, 10)
	if !ok || second == first {
		t.Fatalf("picked %v twice", first)
	}
	releaseFirst()
	releaseSecond()
	// at cap 1 a third dial to that /24 finds no slot
	_, releaseA, _ := s.set.Pick(mx, s.caps, 1)
	_, releaseB, _ := s.set.Pick(mx, s.caps, 1)
	if _, _, ok := s.set.Pick(netip.MustParseAddr("203.0.113.26"), s.caps, 1); ok {
		t.Fatal("a third slot to one /24 at cap 1")
	}
	releaseA()
	releaseB()
}

func TestSmtpEdgeNotReadyWithoutFcrdns(t *testing.T) {
	w := newEdgeWorld(t, func(w *edgeWorld) {
		w.world.SetPtr(testSendingAddress)
		// a check interval shorter than the timeout of any call a move of it could bring, and than the store probe's
		// interval, so the move to the second check brings that check alone. A move of the default ten minutes
		// brought ten store probes as well, and one whose StoreTimeout the moving clock passed mid-call left the
		// store unreachable for the readiness read after it.
		w.settings.FcrdnsCheckInterval = time.Second
		// every probe after the first fails, as such a probe did, so readiness holds only while no probe runs
		if _, err := w.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "smtpedge.ActiveHalts", Nth: 2, Repeat: -1, Result: sidecartest.FailBeforeApply}); err != nil {
			t.Fatal(err)
		}
	})
	w.awaitProbes(1)
	if w.service.Ready() {
		t.Fatal("ready with no address whose FCrDNS holds")
	}
	w.world.SetPtr(testSendingAddress, testHeloName)
	w.clock.Advance(w.settings.FcrdnsCheckInterval)
	if err := w.service.AwaitSendingChecks(w.ctx, 2); err != nil {
		t.Fatal(err)
	}
	if !w.service.Ready() {
		t.Fatal("not ready once FCrDNS holds")
	}
}
