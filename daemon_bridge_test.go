//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// BRIDGE-M8-06's control methods: they answer a paired app's control session alone, a hook's, MCP's or an unpaired
// sidecar's refused with nothing signed; the setup's reply is the hand-off, which the daemon's reply walk lets pass, and
// the witness's the pin and why a setup is due; and a setup past another's revocation takes a confirmed call.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The methods answer the paired app's control session alone, and its confirmed call for a setup past another signer's
// revocation.
func TestForwardingMethodsAnswerThePairedAppAlone(t *testing.T) {
	world := newTestForwardingWorld(t)
	ctx := context.Background()
	paired := false
	methods := daemonForwardingMethods(func(sidecar *Sidecar) bool { return paired })
	if len(methods) != 2 || methods[0].Name != DaemonMethodForwardingSetup || methods[1].Name != DaemonMethodForwardingWitness ||
		!methods[0].Network || !methods[1].Network || len(DaemonForwardingMethods()) != 2 {
		t.Fatalf("the methods: %+v", methods)
	}
	setup, witness := methods[0], methods[1]
	params := func(label string, confirm bool) []byte {
		keys, err := proto.Marshal(testForwardingKeys(label))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(&DaemonForwardingSetupParams{Keys: keys, ConfirmAfterRevocation: confirm})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	call := func(mode string, confirmed bool, params []byte) *DaemonCall {
		return &DaemonCall{
			Hello: &DaemonHello{Mode: mode}, Params: params, NetworkId: world.networkId(), Sidecar: world.sidecar, Confirmed: confirmed,
		}
	}

	for _, refused := range []*DaemonCall{
		call(DaemonModeHook, false, params("hook", false)),
		call(DaemonModeMcp, false, params("mcp", false)),
		call(DaemonModeControl, true, params("unpaired", false)),
	} {
		if _, err := setup.Handler(ctx, refused); !errors.Is(err, ErrDaemonForwardingCaller) {
			t.Errorf("a setup from %s: %v", refused.Hello.Mode, err)
		}
		if _, err := witness.Handler(ctx, refused); !errors.Is(err, ErrDaemonForwardingCaller) {
			t.Errorf("a witness from %s: %v", refused.Hello.Mode, err)
		}
	}
	if world.api.postCount() != 0 {
		t.Fatal("a refused caller signed")
	}

	paired = true
	reply, err := setup.Handler(ctx, call(DaemonModeControl, false, params("first", false)))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDaemonReply(reply); err != nil {
		t.Fatalf("the reply walk refused the hand-off: %v", err)
	}
	handOff := &bridge.ForwardingHandOff{}
	if err := proto.Unmarshal(reply.(*DaemonForwardingSetupReply).HandOff, handOff); err != nil || handOff.GetForwardClientJwt() == "" ||
		len(handOff.GetPending().GetForwardDelegationId()) == 0 {
		t.Fatalf("the hand-off: %v %v", handOff, err)
	}
	witnessReply, err := witness.Handler(ctx, call(DaemonModeControl, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	pin := &bridge.AuthPin{}
	if err := proto.Unmarshal(witnessReply.(*DaemonForwardingWitnessReply).Pin, pin); err != nil || !proto.Equal(pin, world.net.log.State().Pin()) ||
		witnessReply.(*DaemonForwardingWitnessReply).SetupDue != "" {
		t.Fatalf("the witness: %+v %v", witnessReply, err)
	}

	// past an admin's revocation, a setup takes the person's confirmation, which only a confirmed call carries
	world.net.mustPost(world.net.owner, bridge.SignedType_SIGNED_DELEGATION_REVOKE, &protocol.DelegationRevoke{
		Header: world.net.header(), DelegationId: handOff.GetPending().GetForwardDelegationId(),
	})
	posts := world.api.postCount()
	if _, err := setup.Handler(ctx, call(DaemonModeControl, false, params("second", false))); !errors.Is(err, ErrForwardingSetupNeedsConfirm) {
		t.Errorf("a setup past the revocation: %v", err)
	}
	if _, err := setup.Handler(ctx, call(DaemonModeControl, false, params("second", true))); err == nil {
		t.Error("an unconfirmed call confirmed the setup")
	}
	if world.api.postCount() != posts {
		t.Fatal("an unconfirmed setup signed")
	}
	if _, err := setup.Handler(ctx, call(DaemonModeControl, true, params("second", true))); err != nil {
		t.Fatalf("a confirmed setup: %v", err)
	}
}
