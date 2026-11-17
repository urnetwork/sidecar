//go:build !sidecar_http && !ios_extension

// BRIDGE-M8-07's forwarding rows on T2 (fs_bridge_forwarding_m8.go): FS-38's forwarding twin, its refusals beside it,
// and its forged case, each schedule on a Net of its own; server/controller/connect_bridge_forwarding_test.go runs the
// same builders on T3.

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs builder's schedule on a Net of its own on T2, failing t with its trace.
func fsForwardingRun(t *testing.T, name string, builder Builder) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	if result := Run(t.Context(), builder(net), net); result.Err != nil {
		t.Fatalf("%s: %s", name, result)
	}
}

func TestFs38ForwardingDelegation(t *testing.T) {
	fsForwardingRun(t, "FS-38's forwarding twin", Fs38ForwardingDelegation)
}

func TestFs38ForwardingRefusals(t *testing.T) {
	fsForwardingRun(t, "FS-38's forwarding refusals", Fs38ForwardingCase)
}

func TestFs38ForwardingForged(t *testing.T) {
	fsForwardingRun(t, "FS-38's forwarding forged case", Fs38ForwardingForgedCase)
}

func TestFs38ForwardingRevokeEndsItsFlows(t *testing.T) {
	fsForwardingRun(t, "FS-38's forwarding revocation twin", Fs38ForwardingFlowsStayUnrevoked)
	fsForwardingRun(t, "FS-38's forwarding revocation", Fs38ForwardingRevokeCase)
}

func TestFs38ForwardingSupersessionEndsItsFlows(t *testing.T) {
	fsForwardingRun(t, "FS-38's forwarding supersession", Fs38ForwardingSupersedeCase)
}

// The app host's twin: the subject's forwarding key admitted where only the host's own Forwarder feeds its device role.
func TestFwdAppHostAdmits(t *testing.T) {
	fsForwardingRun(t, "an app host's forwarding twin", FwdAppHostAdmits)
}

// A grant at the Forwarder's CompileDelay after its hint and a revocation at once, with no compile.
func TestFwdAppWithinTargets(t *testing.T) {
	fsForwardingRun(t, "an app host within §8.9's targets", FwdAppWithinTargetsCase)
}

func TestFwdAppRevokeRacesCompile(t *testing.T) {
	fsForwardingRun(t, "a DelegationRevoke racing an app host's compile", FwdAppRevokeRacesCompileCase)
}

func TestFwdAppSupersedeRacesContract(t *testing.T) {
	fsForwardingRun(t, "a supersession racing a contract at an app host", FwdAppSupersedeRacesContractCase)
}

// Fwd.tla's LowerStateAccepted and StateDropsOverlay as schedules.
func TestFwdAppCompileBelowANewerState(t *testing.T) {
	fsForwardingRun(t, "a compile below the state in force", FwdAppLowerStateDroppedCase)
	fsForwardingRun(t, "a compile below an overlay revocation", FwdAppStateKeepsOverlayCase)
}

// Fwd.tla's OverlayLifts as schedules: a valid Unsuspend waits for its compile, and a refused one lifts nothing.
func TestFwdAppUnsuspend(t *testing.T) {
	fsForwardingRun(t, "an Unsuspend no compile judged", FwdAppUnsuspendWaitsCase)
	fsForwardingRun(t, "a refused Unsuspend", FwdAppRefusedUnsuspendCase)
}

// FwdReach-NoCompile and Fwd.tla's RepeatsOnly as schedules, under the heap ceiling and over the memory cap.
func TestFwdAppNoCompile(t *testing.T) {
	fsForwardingRun(t, "an uncheckable revocation with compiles deferred", FwdAppNoCompileCase)
	fsForwardingRun(t, "an uncheckable revocation over the memory cap", FwdAppOverCapCase)
}

// Fwd.tla's NoFloor as a schedule, beside its twin.
func TestFwdAppRollback(t *testing.T) {
	fsForwardingRun(t, "a restart with no rollback", FwdAppRestartKeepsTheState)
	fsForwardingRun(t, "a rolled-back posture store", FwdAppRollbackCase)
}
