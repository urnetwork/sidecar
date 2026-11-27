//go:build !sidecar_http && !ios_extension

// bridgeNetAppAdopted against the early return FS-38's app host rows had (sidecartest/fault/fs_bridge_forwarding_app_m8.go):
// the posture shows a new entry's pin, and that the ApplyDeltas that took it wanted a compile, before the sink records
// that want, so a WaitAdopted read between the two found every condition met by the state before the entry and
// returned, and the schedule's next check found the host's state lacking the forwarding Delegation it had just filed
// (TestFwdAppHostAdmits and five more rows, a few in a thousand runs under load).

package sidecartest

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What WaitAdopted reads of an app host whose posture enforces a state at statePin with its pin at pin and
// compileWanted as its last call left it, and whose Forwarder stored the log through pin and compiled the state at
// statePin.
func bridgeNetAdoptedReading(statePin uint64, pin uint64, compileWanted bool) (sidecar.ForwarderStatus, device.PostureDecision) {
	status := sidecar.ForwarderStatus{Tip: &bridge.AuthPin{Version: pin}, CompiledPin: &bridge.AuthPin{Version: statePin}}
	decision := device.PostureDecision{
		State:         device.PostureEnforcingNoDocument,
		Pin:           &bridge.AuthPin{Version: pin},
		BridgeState:   &bridge.BridgeState{Auth: &bridge.AuthPin{Version: statePin}},
		CompileWanted: compileWanted,
	}
	return status, decision
}

// Read between the posture's take of an entry that wants a compile and the sink's record of the want, the state before
// the entry is not adopted, nor once the sink has recorded it; the compile's state in force is, and so is a state
// below an entry that wanted none.
func TestBridgeNetAppAdoptedCountsTheWantThePostureShowsBeforeTheSinkRecordsIt(t *testing.T) {
	status, decision := bridgeNetAdoptedReading(7, 8, true)
	// the sink's record still at the state's pin
	if bridgeNetAppAdopted(8, status, decision, 7, false) {
		t.Fatal("8 adopted with the state at 7 while the posture shows it wanted a compile through 8")
	}
	if bridgeNetAppAdopted(8, status, decision, 8, false) {
		t.Fatal("8 adopted with the state at 7 while the sink wants a compile through 8")
	}
	// the compile's state at 8, its SetState the posture's last call
	status, decision = bridgeNetAdoptedReading(8, 8, false)
	if !bridgeNetAppAdopted(8, status, decision, 8, false) {
		t.Fatal("8 not adopted with the compile's state at 8 in force")
	}
	// a denial at 9 the posture applied, which wanted no compile
	status, decision = bridgeNetAdoptedReading(8, 9, false)
	if !bridgeNetAppAdopted(9, status, decision, 8, false) {
		t.Fatal("9 not adopted with a denial that wanted no compile above the state at 8")
	}
	if bridgeNetAppAdopted(9, status, decision, 8, true) {
		t.Fatal("9 adopted while the newest compile waits for something the world serves")
	}
}
