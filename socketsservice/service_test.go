// The engine's lifecycle, readiness and settings: it constructs on a fake host and stays not ready until
// its store answers, its gate has loaded and a ticket key signs, and a route not built yet is absent.

package socketsservice_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A gate whose readiness a test sets, allowing nothing.
type testSocketGate struct {
	socketsservice.ClosedSocketGate
	ready bool
}

// What the test set.
func (self *testSocketGate) Ready() bool {
	return self.ready
}

// One fixed key, or none.
type testSocketTicketKeys struct {
	privateKey ed25519.PrivateKey
}

// The key, when there is one.
func (self *testSocketTicketKeys) SigningKey() (string, ed25519.PrivateKey, bool) {
	return "k1", self.privateKey, self.privateKey != nil
}

// Its public half.
func (self *testSocketTicketKeys) VerifyKeys() []*sidecar.SocketTicketKey {
	if self.privateKey == nil {
		return nil
	}
	return []*sidecar.SocketTicketKey{{KeyId: "k1", PublicKey: self.privateKey.Public().(ed25519.PublicKey), ExpireTimeMillis: 1 << 62}}
}

// An engine on a fake host and clock with store and gate, nil allowed.
func testSocketsService(t *testing.T, store socketsservice.SocketStore, gate socketsservice.SocketGate) (*socketsservice.SocketsService, *sidecartest.FakeClock) {
	t.Helper()
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	service, err := socketsservice.NewSocketsService(ctx, host.ServiceHost(), store, gate, socketsservice.DefaultSocketsSettings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return service, clock
}

func TestSocketsServiceReadyOnlyWithStoreGateAndKeys(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	store := sidecartest.NewFakeSocketStore(clock, nil, nil)
	gate := &testSocketGate{}
	service, _ := testSocketsService(t, store, gate)
	if err := service.AwaitProbes(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if service.Ready() {
		t.Fatal("ready with an unloaded gate and no key")
	}
	gate.ready = true
	if service.Ready() {
		t.Fatal("ready with no ticket key")
	}
	service.SetTicketKeys(&testSocketTicketKeys{})
	if service.Ready() {
		t.Fatal("ready with keys that do not sign")
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	service.SetTicketKeys(&testSocketTicketKeys{privateKey: privateKey})
	if !service.Ready() {
		t.Fatal("not ready with store, gate and key")
	}
	service.SetTicketKeys(nil)
	if service.Ready() {
		t.Fatal("ready once the keys were taken away")
	}
	service.SetTicketKeys(&testSocketTicketKeys{privateKey: privateKey})
	service.Drain()
	if service.Ready() {
		t.Fatal("ready while draining")
	}
}

// A store that does not answer leaves the engine not ready, and its next answer brings it back.
func TestSocketsServiceReadinessFollowsTheStore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	store := sidecartest.NewFakeSocketStore(clock, nil, nil)
	if _, err := store.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "sockets.Ping", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	ctxHost := context.Background()
	host := sidecartest.NewFakeHost(ctxHost, clock, nil, nil, nil)
	service, err := socketsservice.NewSocketsService(ctxHost, host.ServiceHost(), store, &testSocketGate{ready: true}, socketsservice.DefaultSocketsSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	service.SetTicketKeys(&testSocketTicketKeys{privateKey: privateKey})
	if err := service.AwaitProbes(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if service.Ready() {
		t.Fatal("ready on a store that did not answer")
	}
	clock.Advance(socketsservice.DefaultSocketsSettings().ProbeInterval)
	if err := service.AwaitProbes(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if !service.Ready() {
		t.Fatal("not ready once the store answered")
	}
}

// With no store, or only the closed gate, an engine is never ready, which is what a host has until
// SOCK-M5-04 and SOCK-M5-07 land.
func TestSocketsServiceNeverReadyWithoutItsParts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	for _, parts := range []struct {
		store socketsservice.SocketStore
		gate  socketsservice.SocketGate
	}{
		{store: nil, gate: &testSocketGate{ready: true}},
		{store: sidecartest.NewFakeSocketStore(clock, nil, nil), gate: nil},
		{store: sidecartest.NewFakeSocketStore(clock, nil, nil), gate: socketsservice.ClosedSocketGate{}},
	} {
		service, _ := testSocketsService(t, parts.store, parts.gate)
		service.SetTicketKeys(&testSocketTicketKeys{privateKey: privateKey})
		if err := service.AwaitProbes(ctx, 1); err != nil {
			t.Fatal(err)
		}
		if service.Ready() {
			t.Errorf("ready with store %v and gate %T", parts.store != nil, parts.gate)
		}
	}
}

// The closed gate is every check's closed direction.
func TestClosedSocketGateAllowsNothing(t *testing.T) {
	ctx := context.Background()
	gate := socketsservice.ClosedSocketGate{}
	request := &socketsservice.SocketGateRequest{NetworkId: testSocketId(), Name: "tls/443/blog"}
	for _, check := range []func(context.Context, *socketsservice.SocketGateRequest) (*socketsservice.SocketGateVerdict, error){
		gate.MayListen, gate.MayDial, gate.MayPublish,
	} {
		if verdict, err := check(ctx, request); verdict != nil || !errors.Is(err, socketsservice.ErrSocketGateUnloaded) {
			t.Errorf("a closed gate answered %v, %v", verdict, err)
		}
	}
	if _, found, err := gate.IdentityKey(ctx, testSocketId(), testSocketId()); found || err == nil {
		t.Error("a closed gate knew a key")
	}
	if !gate.Spent(testSocketId()) || gate.Ready() {
		t.Error("a closed gate was ready or a network unspent")
	}
}

// §9.15's four routes are served: the three Client-class ones refuse a call with no token, GET /socket/keys
// answers anyone, and any other path is the mux's 404.
func TestSocketsServiceServesItsFourRoutes(t *testing.T) {
	service, _ := testSocketsService(t, nil, nil)
	for _, route := range []struct {
		method string
		path   string
		code   int
	}{
		{method: http.MethodPost, path: "/socket/registrations", code: http.StatusUnauthorized},
		{method: http.MethodPost, path: "/socket/find", code: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/socket/list", code: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/socket/keys", code: http.StatusOK},
		{method: http.MethodGet, path: "/socket/other", code: http.StatusNotFound},
	} {
		recorder := httptest.NewRecorder()
		service.Handler().ServeHTTP(recorder, httptest.NewRequest(route.method, route.path, nil))
		if recorder.Code != route.code {
			t.Errorf("%s %s answered %d", route.method, route.path, recorder.Code)
		}
	}
}

// A hook that records nothing.
type testSocketHooks struct{}

// Allows everything.
func (self testSocketHooks) ValidateListen(ctx context.Context, check *socketsservice.SocketListenCheck) error {
	return nil
}

// Nothing.
func (self testSocketHooks) FirstListen(networkId connect.Id, name string) {}

// Nothing.
func (self testSocketHooks) LastUnlisten(networkId connect.Id, name string) {}

// Only edge namespaces take hooks, each once, and an edge namespace nobody registered has none, which
// refuses its names (§9.4).
func TestSocketsServiceRegistersEdgeNamespacesOnce(t *testing.T) {
	service, _ := testSocketsService(t, nil, nil)
	for _, namespace := range []sidecar.SocketNamespace{
		sidecar.SocketNamespaceApplication, sidecar.SocketNamespaceShare, sidecar.SocketNamespaceReserved, 0,
	} {
		if err := service.RegisterNamespace(namespace, testSocketHooks{}); err == nil {
			t.Errorf("namespace %d took hooks", namespace)
		}
	}
	if _, registered := service.LookupNamespace(sidecar.SocketNamespaceSmtp); registered {
		t.Fatal("smtp/ has hooks nobody registered")
	}
	if err := service.RegisterNamespace(sidecar.SocketNamespaceTls, nil); err == nil {
		t.Fatal("nil hooks registered")
	}
	if err := service.RegisterNamespace(sidecar.SocketNamespaceTls, testSocketHooks{}); err != nil {
		t.Fatal(err)
	}
	if err := service.RegisterNamespace(sidecar.SocketNamespaceTls, testSocketHooks{}); err == nil {
		t.Fatal("tls/ registered twice")
	}
	if _, registered := service.LookupNamespace(sidecar.SocketNamespaceTls); !registered {
		t.Fatal("tls/'s hooks are not there")
	}
}

func TestSocketsSettingsRefuseWhatIsNotPositive(t *testing.T) {
	if err := socketsservice.DefaultSocketsSettings().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(settings *socketsservice.SocketsSettings){
		func(settings *socketsservice.SocketsSettings) { settings.Store.Lease = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.Store.SampleCount = 1 },
		func(settings *socketsservice.SocketsSettings) { settings.Store.Scheduler.TicketLifetime = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.Store.Scheduler.ClampPercent = 101 },
		func(settings *socketsservice.SocketsSettings) { settings.Store.Scheduler.EjectionMax = time.Second },
		func(settings *socketsservice.SocketsSettings) { settings.Bound.CallsPerSecond = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.Bound.EdgeBurst = -1 },
		func(settings *socketsservice.SocketsSettings) { settings.FairQueue.Concurrency = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.Store.EdgePairTtl = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.Store.TombstoneTtl = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.Store.UnlistenFenceTtl = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.Store.RemoveClientBatchCount = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.StoreTimeout = -time.Second },
		func(settings *socketsservice.SocketsSettings) { settings.Bound = nil },
		func(settings *socketsservice.SocketsSettings) { settings.Store = nil },
		func(settings *socketsservice.SocketsSettings) { settings.Format = nil },
		func(settings *socketsservice.SocketsSettings) { settings.Format.TicketMaxByteCount = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.Format.DefaultWeight = settings.Format.MaxWeight + 1 },
		func(settings *socketsservice.SocketsSettings) { settings.Format.AlpnMaxCount = -1 },
		func(settings *socketsservice.SocketsSettings) { settings.RegistrationsMaxBodyByteCount = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.FindMaxBodyByteCount = 0 },
		func(settings *socketsservice.SocketsSettings) { settings.FindMaxClientIdCount = 0 },
	} {
		settings := socketsservice.DefaultSocketsSettings()
		mutate(settings)
		if err := settings.Validate(); !errors.Is(err, socketsservice.ErrSocketsSettingsRefused) {
			t.Errorf("a bad setting passed: %v", err)
		}
	}
	host := sidecartest.NewFakeHost(context.Background(), nil, nil, nil, nil)
	settings := socketsservice.DefaultSocketsSettings()
	settings.ProbeInterval = 0
	if _, err := socketsservice.NewSocketsService(context.Background(), host.ServiceHost(), nil, nil, settings); err == nil {
		t.Fatal("an engine started on bad settings")
	}
	if _, err := socketsservice.NewSocketsService(context.Background(), &sidecar.ServiceHost{}, nil, nil, socketsservice.DefaultSocketsSettings()); err == nil {
		t.Fatal("an engine started with no metrics")
	}
}
