package sidecar

// CACL-M11-04: DESIGN-COMPUTE.md §16.3's kinds 19 to 26 reach §5.4's gate, and with no kind row the real gate refuses
// each as the action it cannot parse, so none is approved, spent or run before its rules and its effect lookup land.

import (
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §16.3's kinds in their order.
var testComputeKinds = []SidecarActionKind{
	SidecarActionEnclaveCreate, SidecarActionEnclaveEgressDirect, SidecarActionComputeBudgetRaise,
	SidecarActionEnclaveDelete, SidecarActionFetchUnlistedUrl, SidecarActionTaintedSend, SidecarActionCalendarWrite,
	SidecarActionServiceWrite,
}

// Each of 19 to 26 is on the gate's list in its place, and the real gate refuses an action of each, built at version
// 5 by hand, as the action it cannot parse, filing nothing and running no effect: no row names its fields yet.
func TestComputeKindsReachGateRefusedForWantOfARow(t *testing.T) {
	for i, kind := range testComputeKinds {
		if int(kind) != 19+i || sidecarGateKinds[18+i] != kind || !sidecarGateKindKnown(kind) {
			t.Errorf("kind %d is not the gate's %dth", kind, 19+i)
		}
		if _, ok := CanonicalActionFields(kind); ok {
			t.Errorf("kind %d has a row", kind)
		}
		if _, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(kind), Version: 5}); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d built: %v", kind, err)
		}
	}
	if !slices.Equal(sidecarGateKinds[18:], testComputeKinds) {
		t.Errorf("the gate's list ends %v", sidecarGateKinds[18:])
	}

	world := newTestApprovalWorld(t)
	sidecar, _, _ := newIdentityTestSidecar(t)
	defer sidecar.InstallGate(world.gate)()
	for _, kind := range testComputeKinds {
		canonical, err := proto.Marshal(&protocol.CanonicalAction{
			Kind: uint32(kind), Version: 5, TaintReasons: []string{"mail"}, Auto: &protocol.AutoFields{Basis: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		action := world.action(&StoredCanonicalAction{Action: &protocol.CanonicalAction{Kind: uint32(kind)}, Bytes: canonical})
		if err := sidecar.Authorize(t.Context(), action, nil); !errors.Is(err, ErrSidecarActionInvalid) {
			t.Errorf("kind %d: %v", kind, err)
		}
	}
	if world.log.filedCount() != 0 {
		t.Errorf("%d requests filed", world.log.filedCount())
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("an effect ran %d times", runCount)
	}
}
