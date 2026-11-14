// Bridge.SetFork and Bridge.Decision (bridge_state.go), which BRIDGE-M4-17's sink adapter in cli/ calls: a legacy bridge
// refuses a fork; an anchored one is pending while a fork is reported, the decision says so, and it clears.

package device

import (
	"context"
	"errors"
	"testing"
)

func TestBridgeSetForkHoldsTheBridgePending(t *testing.T) {
	fixture := newPostureFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge, err := NewBridge(ctx, newMemoryPostureStore(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	if decision := bridge.Decision(); decision.State != PostureLegacy || decision.Fork {
		t.Fatalf("a fresh bridge: %v", decision.State)
	}
	if err := bridge.SetFork(true); !errors.Is(err, ErrPostureLegacy) {
		t.Fatalf("a fork on a legacy bridge: %v", err)
	}
	if err := bridge.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	if err := bridge.SetFork(true); err != nil {
		t.Fatal(err)
	}
	if decision := bridge.Decision(); decision.State != PosturePending || !decision.Fork {
		t.Fatalf("a reported fork: %v, fork %t", decision.State, decision.Fork)
	}
	if err := bridge.SetFork(false); err != nil {
		t.Fatal(err)
	}
	if decision := bridge.Decision(); decision.Fork {
		t.Fatal("a cleared fork is still held")
	}
}
