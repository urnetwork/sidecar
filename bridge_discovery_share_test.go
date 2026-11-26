//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// Sharing a LAN device (§17.7.1, D-BRIDGE-24; owner decision 778), §22.5's §17 row from M6: the person's confirmed act
// alone; a served prefix serving the device as it is; otherwise a /32 route remapped to an exposed /32, approved as an
// expose, the share waiting on it; unshare withdrawing that route; a /32 share withdrawn when its device moves, and a
// share kept, its route withdrawn, after ShareRouteAbsentTimeout unseen; and the daemon's switches and one hide set,
// unhide the person's act.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// A filer that records what a share files, answering each Expose with a route or, while pending is set, an approval.
type discoveryTestFiler struct {
	stateLock sync.Mutex
	exposes   []*BridgeRouteRequest
	closes    [][]byte
	pending   *Id
	closed    chan []byte
}

func newDiscoveryTestFiler() *discoveryTestFiler {
	return &discoveryTestFiler{closed: make(chan []byte, 16)}
}

func (self *discoveryTestFiler) Expose(ctx context.Context, origin *BridgeFileOrigin, request *BridgeRouteRequest) (*BridgeFiling, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.exposes = append(self.exposes, request)
	if self.pending != nil {
		return nil, &ApprovalPendingError{ApprovalId: *self.pending}
	}
	ruleId := make([]byte, 32)
	ruleId[0] = byte(len(self.exposes))
	return &BridgeFiling{RuleId: ruleId}, nil
}

func (self *discoveryTestFiler) Close(ctx context.Context, origin *BridgeFileOrigin, id []byte, reset bool) (*BridgeFiling, error) {
	self.stateLock.Lock()
	self.closes = append(self.closes, id)
	self.stateLock.Unlock()
	self.closed <- id
	return &BridgeFiling{RuleId: id}, nil
}

// A host whose LAN holds a printer its served subnet covers and a phone none does.
type discoveryTestShareHost struct {
	t         *testing.T
	clock     *discoveryTestClock
	gatherer  *discoveryTestGatherer
	filer     *discoveryTestFiler
	component *BridgeDiscoveryComponent
	confirmed *BridgeFileOrigin
}

func newDiscoveryTestShareHost(t *testing.T) *discoveryTestShareHost {
	t.Helper()
	return newDiscoveryTestShareHostWith(t, nil)
}

// A share host whose settings edit adjusts, nil for the defaults.
func newDiscoveryTestShareHostWith(t *testing.T, edit func(settings *BridgeDiscoverySettings)) *discoveryTestShareHost {
	t.Helper()
	printer := discoveryTestGathered("Synthetic Printer", "_ipp._tcp", 631, "printer", "192.168.50.20")
	phone := discoveryTestGathered("Synthetic Phone", "_remotepairing._tcp", 49152, "phone", "192.168.80.5")
	for _, gathered := range []*BridgeDiscoveryGathered{printer, phone} {
		gathered.Expires = discoveryTestNow.Add(30 * 24 * time.Hour)
	}
	host := &discoveryTestShareHost{
		t:         t,
		clock:     newDiscoveryTestClock(),
		gatherer:  newDiscoveryTestGatherer(printer, phone),
		filer:     newDiscoveryTestFiler(),
		confirmed: &BridgeFileOrigin{Act: SidecarActConfirmed},
	}
	routes := discoveryTestRoutes()
	settings := DefaultBridgeDiscoverySettings()
	if edit != nil {
		edit(settings)
	}
	component, err := NewBridgeDiscoveryComponent(&BridgeDiscoveryArgs{
		SidecarId: Id{0xA1},
		Routes:    func() *BridgeDiscoveryRoutes { return routes },
		Gatherer:  host.gatherer,
		Filer:     host.filer,
		Clock:     host.clock,
		Settings:  settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(component.Close)
	component.loadState(newDiscoveryTestStore())
	host.component = component
	// the person's own view runs the gatherer, which a share picks from
	component.Devices()
	discoveryTestAwait(t, host.gatherer.running, func(count int) bool { return count == 1 })
	host.awaitGathered("phone")
	return host
}

// Checks the component holds label's device: the test gatherer reports before it counts itself running, so a
// report has landed once running counts it.
func (self *discoveryTestShareHost) awaitGathered(label string) {
	self.t.Helper()
	if address, _, _ := self.component.gatheredDevice(label); !address.IsValid() {
		self.t.Fatalf("the gatherer's report holds no %s", label)
	}
}

// Only the person's confirmed act shares, and only a device the host's view lists.
func TestBridgeDiscoveryShareIsThePersonsAct(t *testing.T) {
	host := newDiscoveryTestShareHost(t)
	for _, act := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := host.component.Share(context.Background(), &BridgeFileOrigin{Act: act}, "phone"); !errors.Is(err, ErrBridgeDiscoveryRefused) {
			t.Errorf("act %d shared: %v", act, err)
		}
	}
	if _, err := host.component.Share(context.Background(), nil, "phone"); !errors.Is(err, ErrBridgeDiscoveryRefused) {
		t.Errorf("no origin shared: %v", err)
	}
	if _, err := host.component.Share(context.Background(), host.confirmed, "tablet"); !errors.Is(err, ErrBridgeDiscoveryNoDevice) {
		t.Errorf("an unknown device shared: %v", err)
	}
	if len(host.filer.exposes) != 0 {
		t.Fatalf("%d filings", len(host.filer.exposes))
	}
}

// A device a served prefix covers is shared as it is, filing nothing; one none covers files its /32 remapped, waiting
// while the approval waits, then active; unshare withdraws that route, draining.
func TestBridgeDiscoverySharesFileTheirRoute(t *testing.T) {
	host := newDiscoveryTestShareHost(t)
	printer, err := host.component.Share(context.Background(), host.confirmed, "printer")
	if err != nil || printer.State != bridgeDiscoveryShareActive || printer.RuleId != nil || len(host.filer.exposes) != 0 {
		t.Fatalf("the printer's share: %+v, %v, %d filings", printer, err, len(host.filer.exposes))
	}
	approvalId := Id{0xAA}
	host.filer.pending = &approvalId
	waiting, err := host.component.Share(context.Background(), host.confirmed, "Phone")
	if err != nil || waiting.State != bridgeDiscoveryShareWaiting || waiting.ApprovalPendingId == nil || *waiting.ApprovalPendingId != approvalId {
		t.Fatalf("the phone's waiting share: %+v, %v", waiting, err)
	}
	request := host.filer.exposes[0]
	if !request.Remap || !slices.Equal(request.Prefixes, []netip.Prefix{netip.MustParsePrefix("192.168.80.5/32")}) {
		t.Fatalf("the filing: %+v", request)
	}
	host.filer.pending = nil
	active, err := host.component.Share(context.Background(), host.confirmed, "phone")
	if err != nil || active.State != bridgeDiscoveryShareActive || len(active.RuleId) != 32 {
		t.Fatalf("the phone's share once approved: %+v, %v", active, err)
	}
	if _, err := host.component.Unshare(context.Background(), host.confirmed, "phone"); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-host.filer.closed:
		if hex.EncodeToString(id) != hex.EncodeToString(active.RuleId) {
			t.Errorf("withdrew %x, want %x", id, active.RuleId)
		}
	case <-time.After(time.Minute):
		t.Fatal("unshare withdrew nothing")
	}
	if host.component.stateWithLockForTest().share("phone") != nil {
		t.Errorf("the share stayed")
	}
}

// A /32 share's device moving unpublishes it and withdraws the route at once; unseen for ShareRouteAbsentTimeout, the
// route goes and the share stays.
func TestBridgeDiscoverySharesFollowTheirDevice(t *testing.T) {
	host := newDiscoveryTestShareHost(t)
	active, err := host.component.Share(context.Background(), host.confirmed, "phone")
	if err != nil || active.State != bridgeDiscoveryShareActive {
		t.Fatalf("the share: %+v, %v", active, err)
	}
	moved := discoveryTestGathered("Synthetic Phone", "_remotepairing._tcp", 49152, "phone", "192.168.80.6")
	moved.Expires = discoveryTestNow.Add(30 * 24 * time.Hour)
	host.gatherer.set(moved)
	select {
	case <-host.filer.closed:
	case <-time.After(time.Minute):
		t.Fatal("a moved device's route was not withdrawn")
	}
	if share := host.component.stateWithLockForTest().share("phone"); share == nil || share.State != bridgeDiscoveryShareMoved || share.RuleId != "" {
		t.Fatalf("the moved share: %+v", share)
	}

	// the gatherer looks the whole time, so the device's absence counts: the person's view keeps it running for 30 days
	absent := newDiscoveryTestShareHostWith(t, func(settings *BridgeDiscoverySettings) {
		settings.GatherDemandTimeout = 30 * 24 * time.Hour
	})
	if _, err := absent.component.Share(context.Background(), absent.confirmed, "phone"); err != nil {
		t.Fatal(err)
	}
	absent.gatherer.set()
	settings := DefaultBridgeDiscoverySettings()
	// the host loop waits on its upkeep timer, which the move past the absence fires
	absent.clock.awaitWaitAt(t, absent.clock.Now().Add(settings.ShareUpkeepInterval))
	absent.clock.Advance(settings.ShareRouteAbsentTimeout + settings.ShareUpkeepInterval)
	select {
	case <-absent.filer.closed:
	case <-time.After(time.Minute):
		t.Fatal("an absent device's route was not withdrawn")
	}
	if share := absent.component.stateWithLockForTest().share("phone"); share == nil || share.State != bridgeDiscoveryShareAbsent {
		t.Fatalf("the absent share: %+v", share)
	}
}

// The switches and the one hide set: own off, proxy off, a port, an instance and the device hidden; unhide only as the
// person's act through bridge.discovery.unhide; a value that names nothing refused.
func TestBridgeDiscoverySwitchesAndHides(t *testing.T) {
	host := newDiscoveryTestShareHost(t)
	component := host.component
	steps := []struct {
		setting string
		value   string
		unhide  bool
	}{
		{setting: DaemonBridgeDiscoveryOwn, value: DaemonBridgeDiscoveryOff},
		{setting: DaemonBridgeDiscoveryProxy, value: DaemonBridgeDiscoveryOff},
		{setting: DaemonBridgeDiscoveryHide, value: "445"},
		{setting: DaemonBridgeDiscoveryHide, value: "51820/udp"},
		{setting: DaemonBridgeDiscoveryHide, value: "Synthetic Printer.v2._ipp._tcp"},
		{setting: DaemonBridgeDiscoveryHide, value: DaemonBridgeDiscoveryDevice},
	}
	for _, step := range steps {
		if err := component.Set(step.setting, step.value, step.unhide); err != nil {
			t.Fatalf("%s %s: %v", step.setting, step.value, err)
		}
	}
	state := component.stateWithLockForTest()
	if !state.OwnOff || !state.ProxyOff || !state.HiddenDevice || !slices.Equal(state.HiddenPorts, []string{"tcp/445", "udp/51820"}) ||
		!slices.Equal(state.HiddenInstances, []string{bridgeDiscoveryInstanceKey("synthetic printer.v2", "_ipp._tcp")}) {
		t.Fatalf("the state: %+v", state)
	}
	if component.ProxyOn() {
		t.Errorf("the proxy is on")
	}
	if err := component.Set(DaemonBridgeDiscoveryHide, "445", true); err != nil {
		t.Fatal(err)
	}
	if err := component.Set(DaemonBridgeDiscoveryHide, DaemonBridgeDiscoveryDevice, true); err != nil {
		t.Fatal(err)
	}
	state = component.stateWithLockForTest()
	if state.HiddenDevice || !slices.Equal(state.HiddenPorts, []string{"udp/51820"}) {
		t.Fatalf("after unhide: %+v", state)
	}
	for _, bad := range []struct{ setting, value string }{
		{setting: DaemonBridgeDiscoveryOwn, value: "maybe"},
		{setting: DaemonBridgeDiscoveryHide, value: "nothing"},
		{setting: DaemonBridgeDiscoveryHide, value: "0"},
		{setting: "color", value: "on"},
	} {
		if err := component.Set(bad.setting, bad.value, false); !errors.Is(err, ErrBridgeDiscoveryRefused) {
			t.Errorf("%s %s: %v", bad.setting, bad.value, err)
		}
	}
	// the daemon's unhide method is the person's confirmed act alone, and the plain method cannot unhide
	underHarness := false
	methods := NewDaemonBridgeDiscovery(&DaemonBridgeDiscoveryArgs{
		Component:       func(networkId Id, running *Sidecar) *BridgeDiscoveryComponent { return component },
		HarnessAncestor: func(ctx context.Context, call *DaemonCall) bool { return underHarness },
	}).Methods()
	byName := map[string]*DaemonMethod{}
	for _, method := range methods {
		byName[method.Name] = method
	}
	if !byName[DaemonMethodBridgeDiscoveryUnhide].Confirm || !byName[DaemonMethodBridgeShare].Confirm ||
		byName[DaemonMethodBridgeDiscovery].Confirm || byName[DaemonMethodBridgeDevices].Confirm {
		t.Fatalf("the methods' Confirm marks are wrong")
	}
	unconfirmed := &DaemonCall{Params: []byte(`{"setting":"hide","value":"51820/udp"}`)}
	if _, err := byName[DaemonMethodBridgeDiscoveryUnhide].Handler(context.Background(), unconfirmed); !errors.Is(err, ErrBridgeDiscoveryRefused) {
		t.Errorf("an unconfirmed unhide: %v", err)
	}
	confirmed := &DaemonCall{Params: []byte(`{"setting":"hide","value":"51820/udp"}`), Confirmed: true}
	underHarness = true
	if _, err := byName[DaemonMethodBridgeDiscoveryUnhide].Handler(context.Background(), confirmed); !errors.Is(err, ErrBridgeDiscoveryRefused) {
		t.Errorf("a confirmed unhide under a harness: %v", err)
	}
	if _, err := NewDaemonBridgeDiscovery(&DaemonBridgeDiscoveryArgs{
		Component: func(networkId Id, running *Sidecar) *BridgeDiscoveryComponent { return component },
	}).Methods()[3].Handler(context.Background(), confirmed); !errors.Is(err, ErrBridgeDiscoveryRefused) {
		t.Errorf("a confirmed unhide with no Sidecar to ask: %v", err)
	}
	underHarness = false
	if _, err := byName[DaemonMethodBridgeDiscoveryUnhide].Handler(context.Background(), confirmed); err != nil {
		t.Errorf("a confirmed unhide: %v", err)
	}
	if state := component.stateWithLockForTest(); len(state.HiddenPorts) != 0 {
		t.Errorf("after the confirmed unhide: %+v", state.HiddenPorts)
	}
}

// The person's view lists the LAN's devices with why each instance is withheld, and shows the notice until seen.
func TestBridgeDiscoveryDevicesListsTheLan(t *testing.T) {
	host := newDiscoveryTestShareHost(t)
	if _, err := host.component.Share(context.Background(), host.confirmed, "printer"); err != nil {
		t.Fatal(err)
	}
	devices := host.component.Devices()
	if len(devices.Lan) != 2 || devices.Lan[0].HostLabel != "phone" || devices.Lan[1].HostLabel != "printer" {
		t.Fatalf("the LAN: %+v", devices.Lan)
	}
	if phone := devices.Lan[0]; phone.Share != "" || len(phone.Services) != 1 || phone.Services[0].Withheld != "not shared" {
		t.Errorf("the phone's line: %+v", phone)
	}
	if printer := devices.Lan[1]; printer.Share != bridgeDiscoveryShareActive || printer.Services[0].Withheld != "" {
		t.Errorf("the printer's line: %+v", printer)
	}
	if !slices.ContainsFunc(devices.Published, func(instance *DaemonBridgeInstance) bool {
		return instance.Name == "Synthetic Printer" && instance.Address == "192.168.50.20"
	}) {
		t.Errorf("published: %+v", devices.Published)
	}
	if devices.Notice != "" || host.component.PendingNotice() != "" {
		t.Errorf("the notice still shows after a listing that showed it")
	}
}

// The settings in force, for a test.
func (self *BridgeDiscoveryComponent) stateWithLockForTest() *bridgeDiscoveryState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.stateWithLock().clone()
}

// The listeners read the one hide set: a port hidden by discovery is hidden to them, and the device hidden whole hides
// every port.
func TestBridgeDiscoveryHideSetServesTheListeners(t *testing.T) {
	host := newDiscoveryTestShareHost(t)
	if host.component.HidesPort("tcp", 445) {
		t.Fatal("hidden before any hide")
	}
	if err := host.component.Set(DaemonBridgeDiscoveryHide, "445", false); err != nil {
		t.Fatal(err)
	}
	if !host.component.HidesPort("tcp", 445) || host.component.HidesPort("udp", 445) || host.component.HidesPort("tcp", 22) {
		t.Fatal("the port hide reads wrong")
	}
	if err := host.component.Set(DaemonBridgeDiscoveryHide, DaemonBridgeDiscoveryDevice, false); err != nil {
		t.Fatal(err)
	}
	if !host.component.HidesPort("tcp", 22) {
		t.Fatal("the device hidden whole leaves a port open")
	}
}
