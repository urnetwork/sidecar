// The compile fixture on a real Forwarder (BRIDGE-M8-03; DESIGN-DETAILS 4.2.4, 4.4): a small network compiles to S's
// state through the rows-only judge, the admission rule takes 4.2.4's sizes as 4.4's table states them, and a base the
// judge must refuse is refused, so the fixture's network is held to the rules a real one is.

package forwardcell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How long a fixture's run may take before the test fails it: a watchdog, never a wait.
const testRunWatchdog = 2 * time.Minute

// The Forwarder's log in the test's.
type testLogger struct {
	t *testing.T
}

func (self testLogger) Info(args ...any) {
	self.t.Log(args...)
}

func (self testLogger) Infof(format string, args ...any) {
	self.t.Logf(format, args...)
}

func (self testLogger) Warningf(format string, args ...any) {
	self.t.Logf("warning: "+format, args...)
}

func (self testLogger) Errorf(format string, args ...any) {
	self.t.Logf("error: "+format, args...)
}

func (self testLogger) V(level int32) sidecar.Verbose {
	return sidecar.NewNoopLogger().V(level)
}

// Builds the network of deviceCount devices under settings and compiles it once under forwarderSettings.
func testCompile(t *testing.T, deviceCount int, settings *NetworkSettings, forwarderSettings *sidecar.ForwarderSettings) (*Network, *CompileResult) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testRunWatchdog)
	defer cancel()
	network, err := NewNetwork(deviceCount, settings)
	if err != nil {
		t.Fatal(err)
	}
	run, err := network.Start(ctx, &RunArgs{Settings: forwarderSettings, Log: testLogger{t: t}})
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	result, err := run.Compile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return network, result
}

// A personal network's six devices compile to S's state: one compile, admitted, its state at the base's pin and
// anchored on the network's genesis, with no document; every other device of the no-document network is among its
// identities, S itself not, since the identities are the subjects that reach the host; and a subject with a forwarding
// Delegation in the mix carries that Delegation and its key, one with none carries neither.
func TestASmallNetworkCompilesToItsHostsState(t *testing.T) {
	network, result := testCompile(t, 6, nil, nil)
	if result.Admission != sidecar.ForwarderCompileAdmitted || result.CompileCount != 1 || result.CompileErrorCount != 0 || result.State == nil {
		t.Fatalf("the compile: %+v", result)
	}
	state := result.State
	if !bytes.Equal(state.GetAuth().GetChain(), network.BasePin().GetChain()) || state.GetAuth().GetVersion() != network.BasePin().GetVersion() {
		t.Fatalf("the state's pin %v, the base's %v", state.GetAuth(), network.BasePin())
	}
	if !bytes.Equal(state.GetGenesisSha256(), network.Pending().GetGenesisSha256()) || state.GetHasDocument() {
		t.Fatalf("the state's anchor or document: %x %t", state.GetGenesisSha256(), state.GetHasDocument())
	}
	identity := func(i int) *bridge.BridgeIdentity {
		index := slices.IndexFunc(state.GetIdentities(), func(identity *bridge.BridgeIdentity) bool {
			return bytes.Equal(identity.GetSidecarId(), SidecarId(i))
		})
		if index < 0 {
			return nil
		}
		return state.GetIdentities()[index]
	}
	if len(state.GetIdentities()) != network.DeviceCount-1 || identity(1) != nil {
		t.Fatalf("%d identities of %d devices, S among them: %t", len(state.GetIdentities()), network.DeviceCount, identity(1) != nil)
	}
	forwarding, plain := identity(0), identity(2)
	if forwarding == nil || !bytes.Equal(forwarding.GetForwardDelegationId(), DelegationId(0)) ||
		!bytes.Equal(forwarding.GetForwardPublicKey(), ForwardKey(0).Public().(ed25519.PublicKey)) {
		t.Fatalf("device 0's identity: %v", forwarding)
	}
	if plain == nil || len(plain.GetForwardDelegationId()) != 0 || len(plain.GetForwardPublicKey()) != 0 {
		t.Fatalf("device 2's identity: %v", plain)
	}
	t.Logf("%d devices: rows %d B, estimate %d B, state %d B, compiled in %s", network.DeviceCount, result.RowsByteCount,
		result.EstimateByteCount, result.StateByteCount, result.Duration)
}

// The Apple extensions' admission rule on 4.2.4's sizes, as 4.4's table states them: 3,000 devices' rows compile under
// the 10 MiB cap, and 5,000 devices' are refused with compile_over_budget, nothing handed and nothing compiled.
func TestTheAppleCapAdmitsThreeThousandDevicesAndRefusesFiveThousand(t *testing.T) {
	settings := sidecar.DefaultForwarderSettings(sidecar.ForwarderHostApple)
	_, admitted := testCompile(t, 3_000, nil, settings)
	if admitted.Admission != sidecar.ForwarderCompileAdmitted || admitted.State == nil || admitted.CompileCount != 1 ||
		settings.CompileMemoryMaxByteCount < admitted.EstimateByteCount {
		t.Fatalf("3,000 devices: %+v", admitted)
	}
	_, refused := testCompile(t, 5_000, nil, settings)
	if refused.Admission != sidecar.ForwarderCompileOverBudget || refused.State != nil || refused.CompileCount != 0 ||
		refused.CompileRefusedCount != 1 || !slices.Contains(refused.Alarms, sidecar.ForwarderAlarmCompileOverBudget) ||
		refused.EstimateByteCount <= settings.CompileMemoryMaxByteCount {
		t.Fatalf("5,000 devices: %+v", refused)
	}
	for _, result := range []*CompileResult{admitted, refused} {
		t.Logf("%5d devices: rows %9d B, estimate %10d B against the cap's %d B, state %d B", result.DeviceCount,
			result.RowsByteCount, result.EstimateByteCount, settings.CompileMemoryMaxByteCount, result.StateByteCount)
	}
}

// LiveAtHand reports the heap a compile holds live at its hand: at 1,000 devices more than the rows' bytes, since the
// judged state holds them decoded there, and the figure is logged beside the admission rule's estimate.
func TestTheLiveHeapAtTheHandIsReported(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), testRunWatchdog)
	defer cancel()
	network, err := NewNetwork(1_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := network.Start(ctx, &RunArgs{LiveAtHand: true})
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	result, err := run.Compile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.State == nil || result.HandLiveByteCount <= result.RowsByteCount {
		t.Fatalf("live at the hand %d B over rows of %d B: %+v", result.HandLiveByteCount, result.RowsByteCount, result)
	}
	t.Logf("%d devices: rows %d B, live at the hand %d B, the rule's estimate %d B", result.DeviceCount, result.RowsByteCount,
		result.HandLiveByteCount, result.EstimateByteCount)
}

// The six-device rows' SHA-256, which the root's TestTheCompileEstimateCoversTheLoadedRows holds its own copy of the
// generator to as well (bridge_forward_rows_test.go), so the two copies of 4.2.4's mix cannot drift apart.
const testSixDeviceRowsSha256 = "032b2dbcd53a97393e0f3bac4c4c1efe174a65e9e57243d5c35790c749fa3ba2"

// The rows are the root test's mix, byte for byte.
func TestTheRowsAreTheRootTestsMix(t *testing.T) {
	rows, err := Rows(6, DefaultRowsSettings())
	if err != nil {
		t.Fatal(err)
	}
	rowsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if digest := sha256.Sum256(rowsBytes); hex.EncodeToString(digest[:]) != testSixDeviceRowsSha256 {
		t.Fatalf("the six-device rows hash to %x, the root test's copy to %s", digest, testSixDeviceRowsSha256)
	}
}

// The fixture's base is judged as any other: signed by a device that is no config writer in its own rows (device 3, of
// member 1, who is no admin), it is refused, nothing is handed and the compile counts its failure, beside the twin above.
func TestABaseNoConfigWriterSignedIsRefused(t *testing.T) {
	settings := DefaultNetworkSettings()
	settings.BaseSignerIndex = 3
	_, result := testCompile(t, 6, settings, nil)
	if result.State != nil || result.CompileCount != 0 || result.CompileErrorCount != 1 {
		t.Fatalf("a base its writer may not sign: %+v", result)
	}
	if !slices.Contains(result.Alarms, string(sidecar.SidecarBridgeAlarmStateUnverified)) {
		t.Errorf("no state_unverified alarm: %v", result.Alarms)
	}
}

// A Run compiles once, and a held compile lets its Forwarder close.
func TestARunCompilesOnceAndClosesWhileHeld(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), testRunWatchdog)
	defer cancel()
	network, err := NewNetwork(6, nil)
	if err != nil {
		t.Fatal(err)
	}
	held, err := network.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	held.Close()
	run, err := network.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	if _, err := run.Compile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := run.Compile(ctx); err == nil {
		t.Fatal("a second compile ran")
	}
	if _, err := NewNetwork(6, &NetworkSettings{HostIndex: 2}); err == nil {
		t.Fatal("a host with no forwarding Delegation built")
	}
}
