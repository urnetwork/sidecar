// ur tun's plan for the host's default traffic (tun_default.go; QD-1052), T1 on fakes: every combination of default
// egress on or off, a destination or none and route local traffic on or off, under exits, auto and none, as the plan
// reads it and as the tun applies it through the fake platform, a default packet reaching the destination under auto
// and being refused where the plan refuses it; each platform's own file runs the same combinations over its recorder
// (tun_darwin_test.go, tun_linux_test.go, tun_windows_test.go). Switching default egress off and on, route local
// traffic, an exit or a destination that comes and goes, each re-applies the default route at once with the tun up
// throughout; the daemon keeps a network's choices across a tun that goes down and comes up, refuses a change it could
// not keep, and refuses to guess choices it cannot read; and ur tun passes and prints them. Every wait is on a
// channel, bounded by urTestTimeout.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One combination of the plan's inputs, and what the tun does with default traffic under it.
type testTunDefaultCase struct {
	mode bridge.BridgeEgressMode
	// a destination: under exits an exit the bridge can use, under auto the connect client's; under none both are
	// given, and neither is one
	destination   bool
	defaultEgress bool
	routeLocal    bool
	// what the plan answers
	take    bool
	traffic string
}

// Every combination, each written out (QD-1052): default egress on or off, a destination or none, route local traffic
// on or off, under exits, auto and none.
var testTunDefaultCases = []testTunDefaultCase{
	// exits: the network's exits are the destination
	{mode: testTunExits, destination: true, defaultEgress: true, routeLocal: true, take: true, traffic: urTunDefaultTrafficEgress},
	{mode: testTunExits, destination: true, defaultEgress: true, routeLocal: false, take: true, traffic: urTunDefaultTrafficEgress},
	{mode: testTunExits, destination: true, defaultEgress: false, routeLocal: true, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunExits, destination: true, defaultEgress: false, routeLocal: false, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunExits, destination: false, defaultEgress: true, routeLocal: true, take: false, traffic: urTunDefaultTrafficLocal},
	{mode: testTunExits, destination: false, defaultEgress: true, routeLocal: false, take: true, traffic: urTunDefaultTrafficRefused},
	{mode: testTunExits, destination: false, defaultEgress: false, routeLocal: true, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunExits, destination: false, defaultEgress: false, routeLocal: false, take: false, traffic: urTunDefaultTrafficOff},
	// auto: the connect client's destination
	{mode: testTunAuto, destination: true, defaultEgress: true, routeLocal: true, take: true, traffic: urTunDefaultTrafficEgress},
	{mode: testTunAuto, destination: true, defaultEgress: true, routeLocal: false, take: true, traffic: urTunDefaultTrafficEgress},
	{mode: testTunAuto, destination: true, defaultEgress: false, routeLocal: true, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunAuto, destination: true, defaultEgress: false, routeLocal: false, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunAuto, destination: false, defaultEgress: true, routeLocal: true, take: false, traffic: urTunDefaultTrafficLocal},
	{mode: testTunAuto, destination: false, defaultEgress: true, routeLocal: false, take: true, traffic: urTunDefaultTrafficRefused},
	{mode: testTunAuto, destination: false, defaultEgress: false, routeLocal: true, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunAuto, destination: false, defaultEgress: false, routeLocal: false, take: false, traffic: urTunDefaultTrafficOff},
	// none: no destination, whatever an exit or the connect client offers
	{mode: testTunNone, destination: true, defaultEgress: true, routeLocal: true, take: false, traffic: urTunDefaultTrafficLocal},
	{mode: testTunNone, destination: true, defaultEgress: true, routeLocal: false, take: true, traffic: urTunDefaultTrafficRefused},
	{mode: testTunNone, destination: true, defaultEgress: false, routeLocal: true, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunNone, destination: true, defaultEgress: false, routeLocal: false, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunNone, destination: false, defaultEgress: true, routeLocal: true, take: false, traffic: urTunDefaultTrafficLocal},
	{mode: testTunNone, destination: false, defaultEgress: true, routeLocal: false, take: true, traffic: urTunDefaultTrafficRefused},
	{mode: testTunNone, destination: false, defaultEgress: false, routeLocal: true, take: false, traffic: urTunDefaultTrafficOff},
	{mode: testTunNone, destination: false, defaultEgress: false, routeLocal: false, take: false, traffic: urTunDefaultTrafficOff},
}

// The egress modes, short.
const (
	testTunExits = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	testTunAuto  = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO
	testTunNone  = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE
)

// The case's choices.
func (self testTunDefaultCase) choices() urTunChoices {
	return urTunChoices{DefaultEgress: self.defaultEgress, RouteLocal: self.routeLocal}
}

// Sets the fake bridge to the case's mode, with an exit it can use where the case has a destination.
func (self testTunDefaultCase) applyTo(tunBridge *testTunBridge) {
	tunBridge.stateLock.Lock()
	defer tunBridge.stateLock.Unlock()
	tunBridge.status.EgressMode = self.mode
	tunBridge.status.EgressExitCount = 0
	if self.destination {
		tunBridge.status.EgressExitCount = 1
	}
}

// A connect client's destination whose client a test sets, calling each change callback as it does.
type testTunDestination struct {
	stateLock      sync.Mutex
	client         connect.UserNatClient
	callbacks      map[int]func()
	nextCallbackId int
}

var _ urTunDestination = (*testTunDestination)(nil)

func newTestTunDestination(client connect.UserNatClient) *testTunDestination {
	return &testTunDestination{client: client, callbacks: map[int]func(){}}
}

func (self *testTunDestination) Client() connect.UserNatClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.client
}

func (self *testTunDestination) AddChangeCallback(changed func()) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	callbackId := self.nextCallbackId
	self.nextCallbackId += 1
	self.callbacks[callbackId] = changed
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.callbacks, callbackId)
	}
}

// Sets the client, nil for none, and calls each change callback.
func (self *testTunDestination) set(client connect.UserNatClient) {
	self.stateLock.Lock()
	self.client = client
	callbacks := []func(){}
	for _, callback := range self.callbacks {
		callbacks = append(callbacks, callback)
	}
	self.stateLock.Unlock()
	for _, callback := range callbacks {
		callback()
	}
}

func (self *testTunDestination) callbackCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.callbacks)
}

// A platform whose device a platform's own system opens over its recorder, and whose local addresses and watch are the
// fake platform's, so no test reads this host's own.
type testTunPlatformSystem struct {
	*testTunSystem
	open func(name string, mtu int) (urTunInterface, error)
}

func (self *testTunPlatformSystem) Open(name string, mtu int) (urTunInterface, error) {
	self.stateLock.Lock()
	self.opened = append(self.opened, name)
	self.stateLock.Unlock()
	return self.open(name, mtu)
}

// Starts a tun over system for the case: the fake bridge at its mode, a destination under auto and none where it has
// one, and its choices. The first sync has applied once it returns. Closed at the test's end.
func startTestTunDefaultCase(t *testing.T, system urTunSystem, c testTunDefaultCase) (*urTun, *testTunBridge, *testTunLink) {
	t.Helper()
	tunBridge := newTestTunBridge()
	c.applyTo(tunBridge)
	destinationLink := &testTunLink{}
	var destination urTunDestination
	if c.destination {
		destination = newTestTunDestination(destinationLink)
	}
	choices := c.choices()
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:        "ur-test",
		NetworkId:   sidecar.NewId(),
		System:      system,
		Bridge:      tunBridge,
		Links:       &testTunLinks{source: connect.SourceId(connect.NewId())},
		Settings:    testUrTunSettings(),
		Choices:     &choices,
		Destination: destination,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tun.close)
	return tun, tunBridge, destinationLink
}

// Runs every case over a platform: open answers a fresh interface over its recorder for each, and held whether that
// interface holds the host's default routes now. Each case's tun takes them exactly where the plan does, says so in
// its status, and leaves none behind its close.
func testTunDefaultCasesOnPlatform(t *testing.T, open func(t *testing.T) (urTunInterface, func() bool)) {
	t.Helper()
	for _, c := range testTunDefaultCases {
		iface, held := open(t)
		system := &testTunPlatformSystem{testTunSystem: newTestTunSystem(), open: func(name string, mtu int) (urTunInterface, error) {
			return iface, nil
		}}
		tun, _, _ := startTestTunDefaultCase(t, system, c)
		status := tun.status()
		if held() != c.take || status.DefaultRoute != c.take || status.ExitsHeld || status.DefaultTraffic != c.traffic ||
			status.SyncError != "" {
			t.Errorf("%+v: held %t, status %+v", c, held(), status)
		}
		tun.close()
		if held() {
			t.Errorf("%+v: the default route outlived the tun", c)
		}
	}
}

// Over a platform's interface on its recorder, held reading whether it holds the host's default routes: default egress
// off takes them off at once and on puts them back, with the tun up throughout; route local traffic off with no exit
// keeps them on, refusing, and on takes them off; an exit that comes and goes puts them on and takes them off at the
// next sync. Nothing closes the device or opens another.
func testTunDefaultSwitchOnPlatform(t *testing.T, iface urTunInterface, held func() bool) {
	t.Helper()
	system := &testTunPlatformSystem{testTunSystem: newTestTunSystem(), open: func(name string, mtu int) (urTunInterface, error) {
		return iface, nil
	}}
	syncs := make(chan struct{}, 1024)
	tunBridge := newTestTunBridge()
	tunBridge.status.EgressMode = testTunExits
	tunBridge.status.EgressExitCount = 1
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:      "ur-test",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     &testTunLinks{},
		Settings:  testUrTunSettings(),
		OnSync: func(err error) {
			select {
			case syncs <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tun.close)
	if !held() || !tun.status().DefaultRoute {
		t.Fatalf("up: %+v", tun.status())
	}
	// off, then on again: each answer follows its sync
	off := tun.setChoices(urTunChoices{DefaultEgress: false, RouteLocal: true})
	if held() || off.DefaultRoute || off.DefaultEgress || off.DefaultTraffic != urTunDefaultTrafficOff {
		t.Fatalf("off: held %t, %+v", held(), off)
	}
	on := tun.setChoices(urTunChoices{DefaultEgress: true, RouteLocal: true})
	if !held() || !on.DefaultRoute || on.DefaultTraffic != urTunDefaultTrafficEgress {
		t.Fatalf("on: held %t, %+v", held(), on)
	}
	// each sync's end is a chance for what a change waits on, read off the status, which the sync wrote first
	waitTraffic := func(what string, traffic string) {
		t.Helper()
		deadline := time.After(urTestTimeout)
		for {
			if status := tun.status(); status.DefaultTraffic == traffic && held() == status.DefaultRoute {
				return
			}
			select {
			case <-syncs:
			case <-deadline:
				t.Fatalf("waited too long for %s", what)
			}
		}
	}
	// the exit goes: with route local traffic on, the host's own routes keep default traffic
	tunBridge.stateLock.Lock()
	tunBridge.status.EgressExitCount = 0
	tunBridge.stateLock.Unlock()
	tunBridge.changed()
	waitTraffic("the exit to go", urTunDefaultTrafficLocal)
	if held() {
		t.Fatal("the default route stayed with no exit")
	}
	// route local traffic off: taken, and refused
	refused := tun.setChoices(urTunChoices{DefaultEgress: true, RouteLocal: false})
	if !held() || !refused.DefaultRoute || refused.DefaultTraffic != urTunDefaultTrafficRefused {
		t.Fatalf("refused: held %t, %+v", held(), refused)
	}
	// the exit comes back: taken, to it
	tunBridge.stateLock.Lock()
	tunBridge.status.EgressExitCount = 2
	tunBridge.stateLock.Unlock()
	tunBridge.changed()
	waitTraffic("the exit to come back", urTunDefaultTrafficEgress)
	system.stateLock.Lock()
	opened := slices.Clone(system.opened)
	system.stateLock.Unlock()
	if len(opened) != 1 || !held() {
		t.Fatalf("opened %v, held %t", opened, held())
	}
	tun.close()
	if held() {
		t.Fatal("the default route outlived the tun")
	}
}

// The plan for every combination, as the plan reads it.
func TestTunPlansDefaultTrafficForEveryCombination(t *testing.T) {
	if len(testTunDefaultCases) != 24 {
		t.Fatalf("%d cases", len(testTunDefaultCases))
	}
	for _, c := range testTunDefaultCases {
		status := newTestTunBridge()
		c.applyTo(status)
		plan := urTunPlanDefault(status.Status(), c.destination, c.choices())
		hasDestination := c.destination && c.mode != testTunNone
		if plan.Take != c.take || plan.Traffic != c.traffic || plan.DefaultEgress != c.defaultEgress ||
			plan.Destination != hasDestination {
			t.Errorf("%+v: %+v", c, plan)
		}
	}
	// a state that names no mode, a pending one's, reads as auto
	pending := newTestTunBridge()
	pending.status.EgressMode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED
	if plan := urTunPlanDefault(pending.Status(), false, urTunChoices{DefaultEgress: true}); !plan.Take ||
		plan.Traffic != urTunDefaultTrafficRefused {
		t.Fatalf("pending, route local traffic off: %+v", plan)
	}
	// an exit count under auto is no destination
	auto := newTestTunBridge()
	auto.status.EgressExitCount = 3
	if plan := urTunPlanDefault(auto.Status(), false, urTunChoices{DefaultEgress: true, RouteLocal: true}); plan.Take ||
		plan.Destination {
		t.Fatalf("auto with exits: %+v", plan)
	}
}

// Every combination through the tun's sync on the fake platform, with what a default packet meets: under auto with a
// destination the destination takes it; where the plan refuses it, under auto it is dropped and counted, and under
// exits and none the bridge's route, a reject here, takes it; where the plan leaves it to the host, none reaches the tun.
func TestTunTakesTheDefaultRouteForEveryCombination(t *testing.T) {
	for _, c := range testTunDefaultCases {
		system := newTestTunSystem()
		tun, tunBridge, destinationLink := startTestTunDefaultCase(t, system, c)
		system.iface.stateLock.Lock()
		exits := system.iface.exits
		system.iface.stateLock.Unlock()
		status := tun.status()
		if exits != c.take || status.DefaultRoute != c.take || status.DefaultTraffic != c.traffic ||
			status.DefaultEgress != c.defaultEgress || status.DefaultEgressChosen != c.defaultEgress ||
			status.RouteLocal != c.routeLocal {
			t.Errorf("%+v: exits %t, status %+v", c, exits, status)
			continue
		}
		if !c.take {
			tun.close()
			continue
		}
		// what the bridge does with a default packet: today's route, nil, under auto; a reject client of the test's under
		// exits and none, standing for the exits or the bridge's reject
		reject := &testTunLink{}
		tunBridge.stateLock.Lock()
		tunBridge.route = func(packet []byte) connect.UserNatClient {
			if c.mode == testTunAuto {
				return nil
			}
			return reject
		}
		tunBridge.stateLock.Unlock()
		packet := testTunPacket("100.70.9.9", "203.0.113.7", 17, []byte("default traffic"))
		system.iface.reads <- testTunRead{packets: [][]byte{packet}}
		// a second read follows only once the first batch has gone through the bridge
		system.iface.reads <- testTunRead{}
		status = tun.status()
		switch {
		case c.mode == testTunAuto && c.traffic == urTunDefaultTrafficEgress:
			if taken := destinationLink.taken(); len(taken) != 1 || !bytes.Equal(taken[0], packet) || status.DefaultCount != 0 {
				t.Errorf("%+v: the destination took %d, default %d", c, len(taken), status.DefaultCount)
			}
		case c.mode == testTunAuto:
			if len(destinationLink.taken()) != 0 || status.DefaultCount != 1 || status.SentCount != 0 {
				t.Errorf("%+v: refused as %+v", c, status)
			}
		default:
			if len(reject.taken()) != 1 || len(destinationLink.taken()) != 0 || status.DefaultCount != 0 {
				t.Errorf("%+v: the bridge's route took %d, the destination %d", c, len(reject.taken()), len(destinationLink.taken()))
			}
		}
		tun.close()
	}
}

// Through the daemon: ur tun --default-egress=off takes the default route off a tun that carries it, at once and with
// no restart, and on puts it back; the choice is the network's from then on, kept across a tun that goes down and
// comes up again, and a change of route local traffic leaves default egress as it was.
func TestTunSwitchesDefaultEgressWithNoRestart(t *testing.T) {
	system := newTestTunSystem()
	networkId := sidecar.NewId()
	bridges, tunBridge := newTestUrBridgeDaemon(t, system, networkId, false)
	tunBridge.stateLock.Lock()
	tunBridge.status.EgressMode = testTunExits
	tunBridge.status.EgressExitCount = 1
	tunBridge.stateLock.Unlock()
	status, err := bridges.tunUp(networkId, nil, nil)
	if err != nil || !status.DefaultRoute || !status.DefaultEgress || !status.RouteLocal {
		t.Fatalf("up: %+v %v", status, err)
	}
	off := false
	on := true
	status, err = bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &off})
	if err != nil || status.DefaultRoute || status.DefaultEgress || status.DefaultEgressChosen ||
		status.DefaultTraffic != urTunDefaultTrafficOff {
		t.Fatalf("off: %+v %v", status, err)
	}
	system.iface.stateLock.Lock()
	exits, exitsSets, closeCount := system.iface.exits, slices.Clone(system.iface.exitsSets), system.iface.closeCount
	system.iface.stateLock.Unlock()
	if exits || exitsSets[len(exitsSets)-1] || closeCount != 0 {
		t.Fatalf("off: exits %t %v, closed %d", exits, exitsSets, closeCount)
	}
	status, err = bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &on})
	if err != nil || !status.DefaultRoute || status.DefaultTraffic != urTunDefaultTrafficEgress {
		t.Fatalf("on: %+v %v", status, err)
	}
	// off again, then down and up: the network keeps the choice
	if _, err := bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &off}); err != nil {
		t.Fatal(err)
	}
	if !bridges.tunDown() {
		t.Fatal("down found no tun")
	}
	// the next tun opens a device of its own, as the platform's would
	system.iface = newTestTunInterface()
	status, err = bridges.tunUp(networkId, nil, nil)
	if err != nil || status.DefaultRoute || status.DefaultEgress || status.DefaultTraffic != urTunDefaultTrafficOff {
		t.Fatalf("up again: %+v %v", status, err)
	}
	// route local traffic off leaves default egress off
	status, err = bridges.tunUp(networkId, nil, &urTunChoiceChange{RouteLocal: &off})
	if err != nil || status.DefaultEgress || status.RouteLocal || status.DefaultRoute {
		t.Fatalf("route local traffic off: %+v %v", status, err)
	}
	system.stateLock.Lock()
	defer system.stateLock.Unlock()
	if len(system.opened) != 2 {
		t.Fatalf("opened %v: a change restarted the tun", system.opened)
	}
}

// Under auto, a destination that appears puts the default route on and takes default traffic, and one that goes takes
// the route off again, the tun up throughout; its change callback goes with the tun.
func TestTunFollowsADestinationThatComesAndGoes(t *testing.T) {
	system := newTestTunSystem()
	tunBridge := newTestTunBridge()
	destination := newTestTunDestination(nil)
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:        "ur-test",
		NetworkId:   sidecar.NewId(),
		System:      system,
		Bridge:      tunBridge,
		Links:       &testTunLinks{},
		Settings:    testUrTunSettings(),
		Destination: destination,
		OnSync: func(err error) {
			system.iface.announce("synced")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tun.close)
	if status := tun.status(); status.DefaultRoute || status.Destination || status.DefaultTraffic != urTunDefaultTrafficLocal {
		t.Fatalf("none: %+v", status)
	}
	link := &testTunLink{}
	destination.set(link)
	waitTunEvents(t, system.iface.events, "the destination's route", func() bool { return tun.status().DefaultRoute })
	if status := tun.status(); !status.Destination || status.DefaultTraffic != urTunDefaultTrafficEgress {
		t.Fatalf("a destination: %+v", status)
	}
	packet := testTunPacket("100.70.9.9", "203.0.113.7", 6, []byte("to the destination"))
	system.iface.reads <- testTunRead{packets: [][]byte{packet}}
	system.iface.reads <- testTunRead{}
	if taken := link.taken(); len(taken) != 1 || !bytes.Equal(taken[0], packet) {
		t.Fatalf("the destination took %d", len(taken))
	}
	destination.set(nil)
	waitTunEvents(t, system.iface.events, "the route to come off", func() bool { return !tun.status().DefaultRoute })
	// a packet that reaches the tun now, as one already on its way, goes nowhere near the old destination
	system.iface.reads <- testTunRead{packets: [][]byte{testTunPacket("100.70.9.9", "203.0.113.7", 6, nil)}}
	system.iface.reads <- testTunRead{}
	if status := tun.status(); len(link.taken()) != 1 || status.DefaultCount != 1 {
		t.Fatalf("after: %d taken, %+v", len(link.taken()), status)
	}
	tun.close()
	if destination.callbackCount() != 0 {
		t.Fatal("the destination's callback outlived the tun")
	}
}

// The daemon refuses to guess choices it cannot read, unless the change makes both anew, and refuses a change it could
// not keep, leaving the tun as it was.
func TestTunRefusesChoicesItCannotKeep(t *testing.T) {
	system := newTestTunSystem()
	networkId := sidecar.NewId()
	bridges, _ := newTestUrBridgeDaemon(t, system, networkId, false)
	store := &testTunChoiceStore{loadErr: errors.New("a locked store")}
	func() {
		bridges.stateLock.Lock()
		defer bridges.stateLock.Unlock()
		bridges.networks[networkId].choices = store
	}()
	if _, err := bridges.tunUp(networkId, nil, nil); err == nil || !strings.Contains(err.Error(), "do not read") {
		t.Fatalf("unread: %v", err)
	}
	off := false
	on := true
	if _, err := bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &off}); err == nil {
		t.Fatal("one choice over choices that do not read")
	}
	status, err := bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &on, RouteLocal: &off})
	if err != nil || !status.DefaultEgress || status.RouteLocal {
		t.Fatalf("both anew: %+v %v", status, err)
	}
	store.stateLock.Lock()
	store.loadErr = nil
	store.saveErr = errors.New("a full disk")
	store.stateLock.Unlock()
	if _, err := bridges.tunUp(networkId, nil, &urTunChoiceChange{RouteLocal: &on}); err == nil ||
		!strings.Contains(err.Error(), "were not kept") {
		t.Fatalf("unkept: %v", err)
	}
	if status := bridges.tunStatus(); status == nil || status.RouteLocal {
		t.Fatalf("after an unkept change: %+v", status)
	}
}

// A choice store whose load and save a test fails.
type testTunChoiceStore struct {
	urTunMemoryChoices
	stateLock sync.Mutex
	loadErr   error
	saveErr   error
}

func (self *testTunChoiceStore) Load() (*urTunChoiceRecord, error) {
	self.stateLock.Lock()
	loadErr := self.loadErr
	self.stateLock.Unlock()
	if loadErr != nil {
		return nil, loadErr
	}
	return self.urTunMemoryChoices.Load()
}

func (self *testTunChoiceStore) Save(record *urTunChoiceRecord) error {
	self.stateLock.Lock()
	saveErr := self.saveErr
	self.stateLock.Unlock()
	if saveErr != nil {
		return saveErr
	}
	return self.urTunMemoryChoices.Save(record)
}

// The sealed choices read back what they wrote, a choice never made absent, and refuse a record of another version.
func TestTunSealedChoicesReadBack(t *testing.T) {
	root := sidecartest.NewFakeStore().Root()
	choices := &urTunSealedChoices{store: func() (sidecar.SidecarStore, error) {
		return root.Directory(urTunChoicesDirectory, urTunChoicesClass)
	}}
	if record, err := choices.Load(); err != nil || record != nil {
		t.Fatalf("none: %+v %v", record, err)
	}
	off := false
	if err := choices.Save(&urTunChoiceRecord{Version: urTunChoicesRecordVersion, RouteLocal: &off}); err != nil {
		t.Fatal(err)
	}
	record, err := choices.Load()
	if err != nil || record.DefaultEgress != nil || record.RouteLocal == nil || *record.RouteLocal {
		t.Fatalf("read back %+v %v", record, err)
	}
	settings := testUrTunSettings()
	if read := record.choices(settings); !read.DefaultEgress || read.RouteLocal {
		t.Fatalf("choices %+v", read)
	}
	if err := choices.Save(&urTunChoiceRecord{Version: urTunChoicesRecordVersion + 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := choices.Load(); err == nil {
		t.Fatal("another version read")
	}
}

// ur tun passes its choices to the daemon and prints the plan; a choice that is neither on nor off is refused before
// any daemon is reached.
func TestTunCommandSetsTheChoices(t *testing.T) {
	previous := urTunPlatform
	t.Cleanup(func() { urTunPlatform = previous })
	urTunPlatform = func(settings *urTunSettings, log sidecar.Logger) urTunSystem { return newTestTunSystem() }
	daemon := &testUrSocketDaemon{}
	cli, stdout, stderr := startTestUrSocketCli(t,
		daemon.method(urMethodTunUp, func(params json.RawMessage) (any, error) {
			return &urTunStatus{
				Device:              "ur-test",
				EgressMode:          "auto",
				DefaultEgress:       true,
				DefaultEgressChosen: true,
				RouteLocal:          false,
				DefaultRoute:        true,
				DefaultTraffic:      urTunDefaultTrafficRefused,
			}, nil
		}),
	)
	if code := cli.main(context.Background(), []string{"ur", "tun", "--default-egress=on", "--route-local=off"}); code != urExitOk {
		t.Fatalf("ur tun exited %d: %s", code, stderr.String())
	}
	params := &urTunParams{}
	daemon.lastParams(t, params)
	if params.DefaultEgress != "on" || params.RouteLocal != "off" {
		t.Fatalf("params %+v", params)
	}
	printed := stdout.String()
	for _, want := range []string{"choices    default egress on, route local traffic off",
		"default    the default route rides ur tun, which refuses it: the client has no egress destination"} {
		if !strings.Contains(printed, want) {
			t.Errorf("ur tun printed no %q:\n%s", want, printed)
		}
	}
	stderr.Reset()
	if code := cli.main(context.Background(), []string{"ur", "tun", "--route-local=maybe"}); code != urExitFailed ||
		!strings.Contains(stderr.String(), "on or off") {
		t.Fatalf("a bad choice exited %d: %s", code, stderr.String())
	}
}

// What each plan prints, in the egress mode's words.
func TestTunPrintsThePlanForDefaultTraffic(t *testing.T) {
	cases := []struct {
		status *urTunStatus
		want   string
	}{
		{&urTunStatus{EgressMode: "exits", DefaultEgress: true, DefaultEgressChosen: true, RouteLocal: true, DefaultRoute: true,
			DefaultTraffic: urTunDefaultTrafficEgress}, "exits      the default route rides ur tun to the network's exits"},
		{&urTunStatus{EgressMode: "exits", DefaultEgress: true, DefaultEgressChosen: true, RouteLocal: true,
			DefaultTraffic: urTunDefaultTrafficLocal}, "exits      default traffic keeps this host's own routes: no exit the network names is usable now"},
		{&urTunStatus{EgressMode: "exits", DefaultEgress: true, DefaultEgressChosen: true, DefaultRoute: true,
			DefaultTraffic: urTunDefaultTrafficRefused}, "exits      the default route rides ur tun, which refuses it: no exit the network names is usable now"},
		{&urTunStatus{EgressMode: "auto", DefaultEgress: true, DefaultEgressChosen: true, RouteLocal: true, DefaultRoute: true,
			DefaultTraffic: urTunDefaultTrafficEgress}, "default    the default route rides ur tun to the client's egress destination"},
		{&urTunStatus{EgressMode: "none", DefaultEgress: true, DefaultEgressChosen: true, DefaultRoute: true,
			DefaultTraffic: urTunDefaultTrafficRefused}, "default    the default route rides ur tun, which refuses it: the egress mode none sends nothing out"},
		{&urTunStatus{EgressMode: "auto", RouteLocal: true, DefaultTraffic: urTunDefaultTrafficOff},
			"default    default traffic keeps this host's own routes, since default egress is off"},
		{&urTunStatus{EgressMode: "auto", RouteLocal: true, DefaultTraffic: urTunDefaultTrafficOff},
			"choices    default egress off, route local traffic on"},
	}
	for _, c := range cases {
		cli, stdout, _ := newTestUrCli("/nonexistent/socket")
		printUrTunStatus(cli, c.status)
		if !strings.Contains(stdout.String(), c.want) {
			t.Errorf("%+v printed no %q:\n%s", c.status, c.want, stdout.String())
		}
	}
}

// Under exits the network's requirement holds default egress on whatever the person chose (QD-1053), and the plan is
// then the one default egress on gives: with an exit the default route rides the tun, and with none it keeps the host's
// routes or is refused as route local traffic says. Under auto and none a requirement, which no spec could carry, holds
// nothing.
func TestTunPlansDefaultTrafficUnderTheRequirement(t *testing.T) {
	for _, c := range testTunDefaultCases {
		tunBridge := newTestTunBridge()
		c.applyTo(tunBridge)
		tunBridge.status.DefaultEgressRequired = true
		plan := urTunPlanDefault(tunBridge.Status(), c.destination, c.choices())
		want := c
		if c.mode == testTunExits {
			// the case default egress on gives
			for _, on := range testTunDefaultCases {
				if on.mode == c.mode && on.destination == c.destination && on.routeLocal == c.routeLocal && on.defaultEgress {
					want = on
				}
			}
		}
		if plan.Take != want.take || plan.Traffic != want.traffic || plan.DefaultEgress != want.defaultEgress ||
			plan.Required != (c.mode == testTunExits) {
			t.Errorf("%+v required: %+v", c, plan)
		}
	}
}

// A network that requires default egress keeps it on through ur tun --default-egress=off, which is refused naming the
// requirement and keeps nothing; one that does not lets it go off. A choice of off made before the requirement waits
// under it, the default route riding the tun, and holds again once it is lifted. Route local traffic still decides
// with no exit under the requirement.
func TestTunKeepsDefaultEgressOnUnderTheRequirement(t *testing.T) {
	system := newTestTunSystem()
	networkId := sidecar.NewId()
	bridges, tunBridge := newTestUrBridgeDaemon(t, system, networkId, false)
	setStatus := func(exitCount int, required bool) {
		tunBridge.stateLock.Lock()
		tunBridge.status.EgressMode = testTunExits
		tunBridge.status.EgressExitCount = exitCount
		tunBridge.status.DefaultEgressRequired = required
		tunBridge.stateLock.Unlock()
	}
	syncs := make(chan struct{}, 1024)
	bridges.onTunSync = func(err error) {
		select {
		case syncs <- struct{}{}:
		default:
		}
	}
	waitStatus := func(what string, done func(status *urTunStatus) bool) *urTunStatus {
		t.Helper()
		deadline := time.After(urTestTimeout)
		for {
			if status := bridges.tunStatus(); status != nil && done(status) {
				return status
			}
			select {
			case <-syncs:
			case <-deadline:
				t.Fatalf("waited too long for %s", what)
			}
		}
	}
	off := false
	on := true
	setStatus(1, true)
	status, err := bridges.tunUp(networkId, nil, nil)
	if err != nil || !status.DefaultRoute || !status.DefaultEgressRequired || !status.DefaultEgress {
		t.Fatalf("up: %+v %v", status, err)
	}
	if _, err := bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &off, RouteLocal: &off}); !errors.Is(err, errUrTunDefaultEgressRequired) ||
		!strings.Contains(err.Error(), networkId.String()) {
		t.Fatalf("off under the requirement: %v", err)
	}
	status = bridges.tunStatus()
	if !status.DefaultRoute || !status.DefaultEgressChosen || !status.RouteLocal {
		t.Fatalf("after the refusal: %+v", status)
	}
	if record, _ := bridges.networks[networkId].choices.Load(); record != nil {
		t.Fatalf("a refused change was kept: %+v", record)
	}

	// lifted: default egress goes off
	setStatus(1, false)
	tunBridge.changed()
	waitStatus("the requirement to lift", func(status *urTunStatus) bool { return !status.DefaultEgressRequired })
	status, err = bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &off})
	if err != nil || status.DefaultRoute || status.DefaultEgress || status.DefaultTraffic != urTunDefaultTrafficOff {
		t.Fatalf("off with no requirement: %+v %v", status, err)
	}

	// required again: the person's off waits, and the default route rides the tun
	setStatus(1, true)
	tunBridge.changed()
	status = waitStatus("the requirement to hold", func(status *urTunStatus) bool { return status.DefaultRoute })
	if !status.DefaultEgress || status.DefaultEgressChosen || !status.DefaultEgressRequired ||
		status.DefaultTraffic != urTunDefaultTrafficEgress {
		t.Fatalf("required over an off: %+v", status)
	}
	// no exit under the requirement: route local traffic on keeps the host's routes, off refuses
	setStatus(0, true)
	tunBridge.changed()
	status = waitStatus("the exit to go", func(status *urTunStatus) bool { return !status.DefaultRoute })
	if status.DefaultTraffic != urTunDefaultTrafficLocal || !status.DefaultEgress {
		t.Fatalf("no exit, route local traffic on: %+v", status)
	}
	status, err = bridges.tunUp(networkId, nil, &urTunChoiceChange{RouteLocal: &off})
	if err != nil || !status.DefaultRoute || status.DefaultTraffic != urTunDefaultTrafficRefused {
		t.Fatalf("no exit, route local traffic off: %+v %v", status, err)
	}
	// turning default egress on is no refusal under the requirement
	if _, err := bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &on}); err != nil {
		t.Fatalf("on under the requirement: %v", err)
	}

	// lifted again: the person's choice holds
	if _, err := bridges.tunUp(networkId, nil, &urTunChoiceChange{DefaultEgress: &off, RouteLocal: &on}); !errors.Is(err, errUrTunDefaultEgressRequired) {
		t.Fatalf("off under the requirement again: %v", err)
	}
	setStatus(1, false)
	tunBridge.changed()
	waitStatus("the requirement to lift again", func(status *urTunStatus) bool {
		return !status.DefaultEgressRequired && status.DefaultTraffic == urTunDefaultTrafficEgress
	})
	system.iface.stateLock.Lock()
	defer system.iface.stateLock.Unlock()
	if system.iface.closeCount != 0 {
		t.Fatal("a change closed the tun")
	}
}

// ur tun shows the requirement beside the person's choice.
func TestTunPrintsTheRequirement(t *testing.T) {
	cli, stdout, _ := newTestUrCli("/nonexistent/socket")
	networkId := sidecar.NewId()
	printUrTunStatus(cli, &urTunStatus{Device: "ur-test", NetworkId: networkId, EgressMode: "exits", DefaultEgress: true,
		DefaultEgressRequired: true, RouteLocal: true, DefaultRoute: true, DefaultTraffic: urTunDefaultTrafficEgress})
	printed := stdout.String()
	for _, want := range []string{"choices    default egress off, route local traffic on",
		"required   default egress stays on: network " + networkId.String() + " requires it of its devices",
		"exits      the default route rides ur tun to the network's exits"} {
		if !strings.Contains(printed, want) {
			t.Errorf("printed no %q:\n%s", want, printed)
		}
	}
}
