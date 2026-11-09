// device.Bridge's foundation: what it restores before NewBridge returns, what its status shows in each posture state,
// rules that do not parse, the run loop on the injected clock, and its settings.

package device_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Settings on clock.
func bridgeTestSettings(clock device.Clock) *device.BridgeSettings {
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	return settings
}

// A bridge on store that closes with the test.
func bridgeTestNew(t *testing.T, store device.PostureStore, settings *device.BridgeSettings) *device.Bridge {
	t.Helper()
	bridgeBridge, err := device.NewBridge(context.Background(), store, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridgeBridge.Close)
	return bridgeBridge
}

// DP1: the restored state is in force when NewBridge returns, with nothing awaited.
func TestNewBridgeRestoresTheStateBeforeReturning(t *testing.T) {
	clock := sidecartest.NewFakeClock(time.UnixMilli(bridgeRulesTestTimeMs))
	store := device.EnforcingPostureStoreForTest(t, bridgeRulesTestFixture().Bytes(), true)
	status := bridgeTestNew(t, store, bridgeTestSettings(clock)).Status()
	if status.State != device.PostureEnforcingDocument || !status.HasDocument || status.PinN == 0 {
		t.Fatalf("state %v, document %v, pin %d", status.State, status.HasDocument, status.PinN)
	}
	if status.Block != netip.MustParsePrefix("100.80.0.0/16") || status.PreviousBlock != netip.MustParsePrefix("100.81.0.0/16") {
		t.Fatalf("blocks %v and %v", status.Block, status.PreviousBlock)
	}
	if !status.PreviousBlockDrainUntil.Equal(time.UnixMilli(bridgeRulesTestTimeMs + bridgeRulesTestHourMs)) {
		t.Fatalf("previous block drains until %v", status.PreviousBlockDrainUntil)
	}
	wantAddresses := []netip.Addr{netip.MustParseAddr("100.80.1.2"), netip.MustParseAddr("100.81.1.2")}
	if len(status.Addresses) != 2 || status.Addresses[0] != wantAddresses[0] || status.Addresses[1] != wantAddresses[1] {
		t.Fatalf("addresses %v", status.Addresses)
	}
	if status.EntryCount != 6 || status.MapCount != 3 || status.ServedCount != 3 || status.SubjectCount != 2 {
		t.Fatalf("counts %+v", status)
	}
	if 0 < len(status.Waits) || 0 < len(status.Alarms) {
		t.Fatalf("waits %v, alarms %v", status.Waits, status.Alarms)
	}
	// at the fixture's base: the previous block, the draining link and the draining served prefix
	if status.DrainingCount != 3 || status.ExpiredCount != 0 {
		t.Fatalf("draining %d, expired %d", status.DrainingCount, status.ExpiredCount)
	}
}

// A device no sidecar role has enrolled on keeps today's behavior and waits on nothing.
func TestNewBridgeOnAnEmptyStoreIsLegacy(t *testing.T) {
	status := bridgeTestNew(t, device.EmptyPostureStoreForTest(), nil).Status()
	if status.State != device.PostureLegacy || 0 < len(status.Waits) || status.Block.IsValid() {
		t.Fatalf("%+v", status)
	}
}

// Pending: an anchor and no state, which the status shows as a wait.
func TestNewBridgePendingWaitsForAState(t *testing.T) {
	status := bridgeTestNew(t, device.PendingPostureStoreForTest(t), nil).Status()
	if status.State != device.PosturePending || len(status.Waits) != 1 || status.Waits[0].Kind != device.BridgeWaitState {
		t.Fatalf("%+v", status)
	}
	if status.Block.IsValid() || status.EntryCount != 0 {
		t.Fatalf("pending held rules: %+v", status)
	}
}

// Rules that do not parse are none: the state stays as the posture verified it, nothing of the rules is held, and the
// status says why, naming no value.
func TestBridgeHoldsNoRulesThatDoNotParse(t *testing.T) {
	rules := bridgeRulesTestFixture().Rules()
	rules.Entries[3].Kind = 0
	store := device.EnforcingPostureStoreForTest(t, bridgeRulesTestBytes(t, rules), false)
	status := bridgeTestNew(t, store, nil).Status()
	if status.State != device.PostureEnforcingNoDocument {
		t.Fatalf("state %v", status.State)
	}
	if len(status.Alarms) != 1 || status.Alarms[0].Kind != device.BridgeAlarmRulesRefused {
		t.Fatalf("alarms %v", status.Alarms)
	}
	if status.Block.IsValid() || status.EntryCount != 0 || 0 < len(status.Addresses) {
		t.Fatalf("held refused rules: %+v", status)
	}
}

// run checks the clock at each time a row's meaning changes, on the injected clock: a map's expiry, a reach row's,
// then the end of a drain at no less than its idle floor.
func TestBridgeRunChecksTheClockAtEachChange(t *testing.T) {
	start := time.UnixMilli(bridgeRulesTestTimeMs)
	clock := sidecartest.NewFakeClock(start)
	fixture := &sidecartest.BridgeRulesFixture{
		Block:     "100.80.0.0/16",
		Addresses: []string{"100.80.1.2"},
		Maps: []sidecartest.BridgeRulesFixtureMap{
			{Map: 1, Match: "100.80.1.2", Ports: "tcp:5432", Target: "127.0.0.1:5432", Expires: bridgeRulesTestTimeMs + 10_000},
		},
		Entries: []sidecartest.BridgeRulesFixtureEntry{
			// drains for 30 s by its rule, and no less than 600 s by its TCP idle
			{Prefix: "192.0.2.0/24", Links: []sidecartest.BridgeRulesFixtureLink{
				{Target: 4, Route: 1, DrainingSince: bridgeRulesTestTimeMs, DrainUntil: bridgeRulesTestTimeMs + 30_000},
			}},
		},
		Subjects: []sidecartest.BridgeRulesFixtureSubject{
			{Sidecar: 6, Dial: []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:5432", Grant: 1, Expires: bridgeRulesTestTimeMs + 20_000}}},
		},
	}
	store := device.EnforcingPostureStoreForTest(t, fixture.Bytes(), true)
	bridgeBridge := bridgeTestNew(t, store, bridgeTestSettings(clock))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	awaitTimerAt := func(at time.Time) {
		t.Helper()
		for {
			pending, added := clock.WatchTimers()
			if 0 < len(pending) && pending[0].Equal(at) {
				return
			}
			select {
			case <-added:
			case <-ctx.Done():
				t.Fatalf("no timer at %v; pending %v", at, pending)
			}
		}
	}
	steps := []struct {
		advanceTo    time.Time
		nextTimer    time.Time
		wantDraining int
		wantExpired  int
	}{
		{advanceTo: start, nextTimer: start.Add(10 * time.Second), wantDraining: 1, wantExpired: 0},
		{advanceTo: start.Add(10 * time.Second), nextTimer: start.Add(20 * time.Second), wantDraining: 1, wantExpired: 1},
		{advanceTo: start.Add(20 * time.Second), nextTimer: start.Add(600 * time.Second), wantDraining: 1, wantExpired: 2},
	}
	for _, step := range steps {
		clock.AdvanceTo(step.advanceTo)
		awaitTimerAt(step.nextTimer)
		status := bridgeBridge.Status()
		if status.DrainingCount != step.wantDraining || status.ExpiredCount != step.wantExpired {
			t.Fatalf("at %v: draining %d, expired %d", step.advanceTo.Sub(start), status.DrainingCount, status.ExpiredCount)
		}
	}
}

// Close stops run and returns: a closed bridge sets no further timer.
func TestBridgeCloseStopsRun(t *testing.T) {
	clock := sidecartest.NewFakeClock(time.UnixMilli(bridgeRulesTestTimeMs))
	store := device.EnforcingPostureStoreForTest(t, bridgeRulesTestFixture().Bytes(), true)
	bridgeBridge, err := device.NewBridge(context.Background(), store, nil, bridgeTestSettings(clock))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	bridgeBridge.Close()
	clock.Advance(2 * time.Hour)
	if pending := clock.PendingTimers(); 0 < len(pending) {
		t.Fatalf("a closed bridge set timers at %v", pending)
	}
}

// §17's values, the mobile pin table, and settings no bridge can run on.
func TestBridgeSettingsDefaults(t *testing.T) {
	settings := device.DefaultBridgeSettings()
	if settings.PinSlotCount != 8192 || settings.PinTcpIdleTimeout != 600*time.Second ||
		settings.PinIdleTimeout != 5*time.Minute || settings.LinkDownTimeout != 30*time.Second ||
		settings.LinkConnectTimeout != 3*time.Second || settings.LinkRebuildInterval != 6*24*time.Hour ||
		settings.LinkIdleTimeout != 600*time.Second || settings.RejectPerSecond != 20 || settings.RejectBurst != 40 ||
		settings.RejectEntryHoldTimeout != 600*time.Second || settings.PinTouchInterval != time.Second {
		t.Fatalf("%+v", settings)
	}
	mobile := device.MobileBridgeSettings()
	if mobile.PinSlotCount != 1024 {
		t.Fatalf("mobile pins %d", mobile.PinSlotCount)
	}
	invalid := []func(settings *device.BridgeSettings){
		func(settings *device.BridgeSettings) { settings.PinSlotCount = 0 },
		func(settings *device.BridgeSettings) { settings.PinTcpIdleTimeout = 0 },
		func(settings *device.BridgeSettings) { settings.PinIdleTimeout = -time.Second },
		func(settings *device.BridgeSettings) { settings.PinTouchInterval = -time.Second },
		func(settings *device.BridgeSettings) { settings.LinkDownTimeout = 0 },
		func(settings *device.BridgeSettings) { settings.RejectBurst = 0 },
		func(settings *device.BridgeSettings) { settings.RulesMaxFieldCount = 0 },
	}
	for i, mutate := range invalid {
		settings := device.DefaultBridgeSettings()
		mutate(settings)
		_, err := device.NewBridge(context.Background(), device.EmptyPostureStoreForTest(), nil, settings)
		if !errors.Is(err, device.ErrBridgeSettingsInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

// The fake host builds a link only after sign returns a delegation, counts builds per target, and a sign that fails
// leaves no link.
func TestFakeBridgeHostSignsBeforeItBuilds(t *testing.T) {
	notAfter := time.UnixMilli(bridgeRulesTestTimeMs + 7*24*bridgeRulesTestHourMs)
	host := sidecartest.NewFakeBridgeHost(notAfter)
	target := sidecartest.BridgeFixtureClientId(3)
	subject := sidecartest.BridgeFixtureClientId(6)
	signedNotAfter := time.Time{}
	sign := func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error) {
		signedNotAfter = notAfter
		return []byte("delegation"), nil
	}
	link, err := host.NewBridgeLink(context.Background(), target, subject, nil, sign)
	if err != nil || link == nil {
		t.Fatal(err)
	}
	if !signedNotAfter.Equal(notAfter) || host.BuildCount(target) != 1 {
		t.Fatalf("signed to %v, %d builds", signedNotAfter, host.BuildCount(target))
	}
	refusing := func(windowClientId connect.Id, windowClientPublicKey []byte, notAfter time.Time) ([]byte, error) {
		return nil, errors.New("no delegation")
	}
	if link, err := host.NewBridgeLink(context.Background(), target, subject, nil, refusing); err == nil || link != nil {
		t.Fatal("a link with no delegation")
	}
	if host.BuildCount(target) != 1 || len(host.Builds()) != 2 {
		t.Fatalf("%d links of %d builds", host.BuildCount(target), len(host.Builds()))
	}
	if string(host.Builds()[0].Delegation) != "delegation" || host.Builds()[1].Link != nil {
		t.Fatal("builds recorded wrongly")
	}
}
