// The engine's contract on sidecartest's FakeHost, FakeClock and FakeTlsEdgeStore: readiness, the two
// loops that fill memory off the path, the kill switch's key events and Serve's ports. Every wait is on a
// monitor or the fake clock; a real timer here is only a guard that fails a hung test.

package tlsedgeservice_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

const testServiceRoot = "root.example"

// A dialer that holds clients and opens nothing, which is all readiness reads.
type testServiceDialer struct {
	stateLock sync.Mutex
	clientIds []sidecar.Id
}

func newTestServiceDialer(clientCount int) *testServiceDialer {
	dialer := &testServiceDialer{}
	for range clientCount {
		dialer.clientIds = append(dialer.clientIds, sidecar.NewId())
	}
	return dialer
}

func (self *testServiceDialer) ClientIds() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.clientIds)
}

func (self *testServiceDialer) setClientCount(clientCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clientIds = self.clientIds[:clientCount]
}

func (self *testServiceDialer) Dial(ctx context.Context, request *tlsedgeservice.TlsEdgeDialRequest) (tlsedgeservice.TlsEdgeStream, error) {
	return nil, &sidecar.SocketCodeError{Err: sidecar.ErrSocketNoListener}
}

var _ tlsedgeservice.TlsEdgeDialer = (*testServiceDialer)(nil)

// Settings a test can run: the defaults with a root and one block.
func testServiceSettings() *tlsedgeservice.TlsEdgeSettings {
	settings := tlsedgeservice.DefaultTlsEdgeSettings()
	settings.Root = testServiceRoot
	settings.Blocks = 1
	return settings
}

type testServiceWorld struct {
	ctx     context.Context
	clock   *sidecartest.FakeClock
	host    *sidecartest.FakeHost
	store   *sidecartest.FakeTlsEdgeStore
	dialer  *testServiceDialer
	service *tlsedgeservice.TlsEdgeService
}

// An engine over a fake store and a dialer with K clients, closed at the test's end.
func newTestServiceWorld(t *testing.T, store *sidecartest.FakeTlsEdgeStore, dialer *testServiceDialer) *testServiceWorld {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	var engineStore tlsedgeservice.TlsEdgeStore
	if store != nil {
		engineStore = store
	}
	var engineDialer tlsedgeservice.TlsEdgeDialer
	if dialer != nil {
		engineDialer = dialer
	}
	service, err := tlsedgeservice.NewTlsEdgeService(ctx, host.ServiceHost(), engineStore, engineDialer, testServiceSettings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	return &testServiceWorld{ctx: ctx, clock: clock, host: host, store: store, dialer: dialer, service: service}
}

// Waits until monitor reaches at least target, failing the test past the guard.
func testAwaitCount(t *testing.T, monitor *sidecar.MonitorValue[uint64], target uint64) {
	t.Helper()
	guard := time.After(30 * time.Second)
	for {
		value, changed := monitor.Get()
		if target <= value {
			return
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("waited for %d, at %d", target, value)
		}
	}
}

// With no store the engine loads nothing and is never ready, and with no dialer it is not ready either.
func TestTlsEdgeServiceNotReadyWithoutStoreOrDialer(t *testing.T) {
	world := newTestServiceWorld(t, nil, newTestServiceDialer(4))
	if world.service.Ready() {
		t.Fatal("ready with no store")
	}
	if world.service.Names().Loaded() {
		t.Fatal("names loaded with no store")
	}

	store := sidecartest.NewFakeTlsEdgeStore(nil)
	noDialer := newTestServiceWorld(t, store, nil)
	testAwaitCount(t, noDialer.service.NameLoadCountForTest(), 1)
	testAwaitCount(t, noDialer.service.KillLoadCountForTest(), 1)
	if noDialer.service.Ready() {
		t.Fatal("ready with no dialer")
	}
}

// Ready needs the label map's snapshot, the kill switch read and K clients, and loses the last when a
// client goes.
func TestTlsEdgeServiceReadyNeedsNamesKillsAndClients(t *testing.T) {
	store := sidecartest.NewFakeTlsEdgeStore(nil)
	dialer := newTestServiceDialer(4)
	world := newTestServiceWorld(t, store, dialer)
	testAwaitCount(t, world.service.NameLoadCountForTest(), 1)
	testAwaitCount(t, world.service.KillLoadCountForTest(), 1)
	if !world.service.Ready() {
		t.Fatal("not ready with names, kills and K clients")
	}
	dialer.setClientCount(3)
	if world.service.Ready() {
		t.Fatal("ready with fewer than K clients")
	}
}

// A first snapshot that fails leaves the engine not ready, keeps trying on the reload interval, and is
// ready once one answers.
func TestTlsEdgeServiceFirstSnapshotFailure(t *testing.T) {
	faults := sidecartest.NewFaultQueue()
	store := sidecartest.NewFakeTlsEdgeStore(faults)
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "tlsedge.NameSnapshot", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	world := newTestServiceWorld(t, store, newTestServiceDialer(4))
	testAwaitCount(t, world.service.NameLoadCountForTest(), 1)
	testAwaitCount(t, world.service.KillLoadCountForTest(), 1)
	if world.service.Ready() || world.service.Names().Loaded() {
		t.Fatal("ready on a failed snapshot")
	}
	world.clock.Advance(5 * time.Second)
	testAwaitCount(t, world.service.NameLoadCountForTest(), 2)
	if !world.service.Ready() {
		t.Fatal("not ready once the snapshot answered")
	}
	if got := world.host.Metrics.Value("urnetwork_tlsedge_name_loads_total", "failed"); got != 1 {
		t.Fatalf("failed loads %v", got)
	}
}

// A label added after the snapshot maps once the next change read lands, and a withdrawn one stops
// mapping, both inside one reload interval (plan-TLS-edge-data-source's 10 s).
func TestTlsEdgeServiceNamesFollowChanges(t *testing.T) {
	store := sidecartest.NewFakeTlsEdgeStore(nil)
	networkId := sidecar.NewId()
	label, err := store.AddLabel(testServiceRoot, networkId)
	if err != nil {
		t.Fatal(err)
	}
	world := newTestServiceWorld(t, store, newTestServiceDialer(4))
	testAwaitCount(t, world.service.NameLoadCountForTest(), 1)
	if _, ok := world.service.Names().Resolve("blog."+label+"."+testServiceRoot, 443); !ok {
		t.Fatal("the snapshot's label did not map")
	}

	newNetworkId := sidecar.NewId()
	newLabel, err := store.AddLabel(testServiceRoot, newNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	store.WithdrawNetwork(networkId)
	world.clock.Advance(5 * time.Second)
	testAwaitCount(t, world.service.NameLoadCountForTest(), 2)
	target, ok := world.service.Names().Resolve("blog."+newLabel+"."+testServiceRoot, 443)
	if !ok || target.NetworkId != newNetworkId {
		t.Fatalf("the new label mapped to %+v, %v", target, ok)
	}
	if _, ok := world.service.Names().Resolve("blog."+label+"."+testServiceRoot, 443); ok {
		t.Fatal("a withdrawn label still mapped")
	}
	if counts := store.OpCounts(); counts["NameSnapshot"] != 1 || counts["NamesSince"] != 1 {
		t.Fatalf("store calls %v", counts)
	}
}

// A moved restore serial makes the next read a snapshot (§12.6), and a failed change read keeps the
// last view.
func TestTlsEdgeServiceRestoreTakesSnapshot(t *testing.T) {
	faults := sidecartest.NewFaultQueue()
	store := sidecartest.NewFakeTlsEdgeStore(faults)
	label, err := store.AddLabel(testServiceRoot, sidecar.NewId())
	if err != nil {
		t.Fatal(err)
	}
	world := newTestServiceWorld(t, store, newTestServiceDialer(4))
	testAwaitCount(t, world.service.NameLoadCountForTest(), 1)

	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "tlsedge.NamesSince", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(5 * time.Second)
	testAwaitCount(t, world.service.NameLoadCountForTest(), 2)
	if _, ok := world.service.Names().Resolve(label+"."+testServiceRoot, 443); !ok {
		t.Fatal("a failed change read dropped the view")
	}

	store.RestoreRoot(testServiceRoot)
	world.clock.Advance(5 * time.Second)
	testAwaitCount(t, world.service.NameLoadCountForTest(), 3)
	if counts := store.OpCounts(); counts["NameSnapshot"] != 2 {
		t.Fatalf("store calls %v", counts)
	}
	if _, restoreSerial := world.service.Names().Serials(); restoreSerial == 0 {
		t.Fatal("the view did not take the restore serial")
	}
}

// A kill written to {tes_} reaches the set on its key event alone, with no store call and no clock
// moved, and its lift reaches it the same way once the row is gone too.
func TestTlsEdgeServiceKillChangedReadsTheKey(t *testing.T) {
	store := sidecartest.NewFakeTlsEdgeStore(nil)
	world := newTestServiceWorld(t, store, newTestServiceDialer(4))
	testAwaitCount(t, world.service.KillLoadCountForTest(), 1)
	networkId := sidecar.NewId()
	value, err := json.Marshal(&sidecar.TlsKillEntry{Host: "blog", Reason: "case"})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.host.Redis.HashSet(world.ctx, sidecar.TlsKillKey(networkId), map[string][]byte{"blog": value}); err != nil {
		t.Fatal(err)
	}
	suspensionsBefore := store.OpCounts()["Suspensions"]
	world.service.KillChanged(networkId)
	testAwaitCount(t, world.service.KillChangeCountForTest(), 1)
	if !world.service.Kills().Kills(networkId, "blog") {
		t.Fatal("the key's kill did not land")
	}
	if store.OpCounts()["Suspensions"] != suspensionsBefore {
		t.Fatal("a key event read the store")
	}

	if err := world.host.Redis.HashDelete(world.ctx, sidecar.TlsKillKey(networkId), []string{"blog"}); err != nil {
		t.Fatal(err)
	}
	world.service.KillChanged(networkId)
	testAwaitCount(t, world.service.KillChangeCountForTest(), 2)
	if world.service.Kills().Kills(networkId, "blog") {
		t.Fatal("the lift did not land")
	}
}

// A key read that fails stays pending and lands on its retry, KillRetryDelay later.
func TestTlsEdgeServiceKillReadRetries(t *testing.T) {
	faults := sidecartest.NewFaultQueue()
	store := sidecartest.NewFakeTlsEdgeStore(nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, faults, nil, nil)
	settings := testServiceSettings()
	// apart from RedisTimeout's 1 s, so the retry's timer is the only one at its time
	settings.KillRetryDelay = 3 * time.Second
	service, err := tlsedgeservice.NewTlsEdgeService(ctx, host.ServiceHost(), store, newTestServiceDialer(4), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	testAwaitCount(t, service.KillLoadCountForTest(), 1)

	networkId := sidecar.NewId()
	value, err := json.Marshal(&sidecar.TlsKillEntry{Host: sidecar.TlsKillAllHosts, Reason: "case"})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Redis.HashSet(ctx, sidecar.TlsKillKey(networkId), map[string][]byte{sidecar.TlsKillAllHosts: value}); err != nil {
		t.Fatal(err)
	}
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: sidecar.TlsKillKey(networkId), Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	service.KillChanged(networkId)
	// the failed read leaves the loop waiting KillRetryDelay; nothing landed
	timerCtx, timerCancel := context.WithTimeout(ctx, 30*time.Second)
	defer timerCancel()
	for {
		pending, added := clock.WatchTimers()
		if slices.Contains(pending, clock.Now().Add(3*time.Second)) {
			break
		}
		select {
		case <-added:
		case <-timerCtx.Done():
			t.Fatal("the retry was never set")
		}
	}
	if service.Kills().Kills(networkId, "www") {
		t.Fatal("a failed read landed a kill")
	}
	clock.Advance(3 * time.Second)
	testAwaitCount(t, service.KillChangeCountForTest(), 1)
	if !service.Kills().Kills(networkId, "www") {
		t.Fatal("the retried read did not land")
	}
}

// The 60 s reload reads the rows and each named network's key: a row lands with no key event, and a
// row's lift lands only once its key is gone too.
func TestTlsEdgeServiceReloadMergesRowsAndKeys(t *testing.T) {
	store := sidecartest.NewFakeTlsEdgeStore(nil)
	world := newTestServiceWorld(t, store, newTestServiceDialer(4))
	testAwaitCount(t, world.service.KillLoadCountForTest(), 1)
	networkId := sidecar.NewId()
	store.SetSuspension(&sidecar.TlsSuspendArgs{NetworkId: networkId, Host: "blog", Reason: "case"})
	value, err := json.Marshal(&sidecar.TlsKillEntry{Host: "blog", Reason: "case"})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.host.Redis.HashSet(world.ctx, sidecar.TlsKillKey(networkId), map[string][]byte{"blog": value}); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(60 * time.Second)
	testAwaitCount(t, world.service.KillLoadCountForTest(), 2)
	if !world.service.Kills().Kills(networkId, "blog") {
		t.Fatal("the reload did not land the row")
	}

	// a restore loses the row: the key holds the kill
	store.LiftSuspension(networkId, "blog")
	world.clock.Advance(60 * time.Second)
	testAwaitCount(t, world.service.KillLoadCountForTest(), 3)
	if !world.service.Kills().Kills(networkId, "blog") {
		t.Fatal("a missing row lifted a kill its key holds")
	}

	// the case lifts the key too: the next reload drops it
	if err := world.host.Redis.Delete(world.ctx, []string{sidecar.TlsKillKey(networkId)}); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(60 * time.Second)
	testAwaitCount(t, world.service.KillLoadCountForTest(), 4)
	if world.service.Kills().Kills(networkId, "blog") {
		t.Fatal("a kill neither place holds still refused")
	}
}

// A listener whose address reads as a port of the test's choosing, since tests cannot bind 443.
type testPortListener struct {
	net.Listener
	port int
}

func (self *testPortListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: self.port}
}

func testLoopbackListener(t *testing.T, port int) *testPortListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return &testPortListener{Listener: listener, port: port}
}

// Serve refuses every port but 443, 8443, 8883 and 5671 before accepting anything.
func TestTlsEdgeServiceServeRefusesOtherPorts(t *testing.T) {
	world := newTestServiceWorld(t, sidecartest.NewFakeTlsEdgeStore(nil), newTestServiceDialer(4))
	for _, port := range []int{80, 25, 8080, 5672, 9443} {
		err := world.service.Serve(testLoopbackListener(t, port))
		if !errors.Is(err, tlsedgeservice.ErrTlsEdgePort) {
			t.Errorf("port %d: %v", port, err)
		}
	}
}

// On each listed port, behind a gate no file opened, a hello gets one internal_error alert and a close,
// with no record written.
func TestTlsEdgeServiceServeAnswersInternalErrorBehindAClosedGate(t *testing.T) {
	store := sidecartest.NewFakeTlsEdgeStore(nil)
	world := newTestServiceWorld(t, store, newTestServiceDialer(4))
	for _, port := range []int{443, 8443, 8883, 5671} {
		listener := testLoopbackListener(t, port)
		served := make(chan error, 1)
		go func() {
			served <- world.service.Serve(listener)
		}()
		conn, err := net.Dial("tcp", listener.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(testEdgeHello("blog.a1b2c3d4e5."+testServiceRoot, []string{"h2"}, 0)); err != nil {
			t.Fatal(err)
		}
		answer, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(answer, []byte{21, 3, 3, 0, 2, 2, byte(tlsedgeservice.TlsAlertInternalError)}) {
			t.Fatalf("port %d answered %x", port, answer)
		}
		listener.Close()
		if err := <-served; err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
	}
	counts := store.OpCounts()
	if 0 < counts["InsertConnectionRecords"] {
		t.Fatalf("store calls %v", counts)
	}
}

// Close ends Serve and the loops, and a Serve after Close returns at once.
func TestTlsEdgeServiceCloseEndsEverything(t *testing.T) {
	world := newTestServiceWorld(t, sidecartest.NewFakeTlsEdgeStore(nil), newTestServiceDialer(4))
	listener := testLoopbackListener(t, 443)
	served := make(chan error, 1)
	go func() {
		served <- world.service.Serve(listener)
	}()
	testAwaitCount(t, world.service.NameLoadCountForTest(), 1)
	world.service.Close()
	world.service.Close()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Serve outlived Close")
	}
	if world.service.Ready() {
		t.Fatal("ready after Close")
	}
	if err := world.service.Serve(testLoopbackListener(t, 8443)); err != nil {
		t.Fatal(err)
	}
}
