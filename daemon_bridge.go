//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// The daemon's control methods for a paired remote-mode app's forwarding (BRIDGE-M8-06; §5.8, §18.6's setup and witness
// rows, DESIGN-DETAILS 4.2.6): the desktop app, paired with ur daemon per §5.8, asks it to set up forwarding for its VPN
// component, the macOS extension or the Windows or Linux app service, and takes the witness hint to hand on.
//
//	bridge.forwarding.setup    the component's ForwardingKeys in, Sidecar.SetUpForwarding's hand-off out; with
//	                           confirm_after_revocation the person's confirmation in the app first
//	                           (ConfirmForwardingSetup), which only a confirmed call carries
//	bridge.forwarding.witness  Sidecar.ForwardingWitness: the pin, whether it is §6.4's witnessed one, a fork, and why
//	                           a setup is due
//
// Both answer a control session alone, for a network whose Sidecar is a paired child (§5.8): a hook session, and a
// control session for a sidecar no app paired, are refused; MCP sessions speak MCP and reach no method. The names are
// proposed (BRIDGE-M8-06). The setup's reply is the one reply that carries a token, F's, which the paired app hands
// its component and nothing else (DESIGN-DETAILS 4.2.6's S6; I-7): it rides inside the hand-off's encoded bytes and
// is never logged.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The forwarding methods' names.
const (
	DaemonMethodForwardingSetup   = "bridge.forwarding.setup"
	DaemonMethodForwardingWitness = "bridge.forwarding.witness"
)

// A forwarding method asked from anything but a paired app's control session.
var ErrDaemonForwardingCaller = errors.New("forwarding's setup answers the app this network's sidecar is paired with, in control mode, alone")

// bridge.forwarding.setup's params.
type DaemonForwardingSetupParams struct {
	Network string `json:"network,omitempty"`
	// The component's bridge.ForwardingKeys, encoded: public halves only.
	Keys []byte `json:"keys"`
	// The person confirmed in the app's UI setting forwarding up again after another signer's revocation.
	ConfirmAfterRevocation bool `json:"confirm_after_revocation,omitempty"`
}

// bridge.forwarding.setup's reply.
type DaemonForwardingSetupReply struct {
	// The bridge.ForwardingHandOff, encoded: F's token, for the paired app's component alone.
	HandOff []byte `json:"hand_off"`
}

// bridge.forwarding.witness's params.
type DaemonForwardingWitnessParams struct {
	Network string `json:"network,omitempty"`
}

// bridge.forwarding.witness's reply.
type DaemonForwardingWitnessReply struct {
	// The bridge.AuthPin, encoded.
	Pin       []byte `json:"pin"`
	Witnessed bool   `json:"witnessed"`
	Fork      bool   `json:"fork"`
	// A ForwardingSetupReason, empty when no setup is due.
	SetupDue string `json:"setup_due,omitempty"`
}

// The forwarding methods, which ur daemon registers.
func DaemonForwardingMethods() []*DaemonMethod {
	return daemonForwardingMethods(func(sidecar *Sidecar) bool { return sidecar.Paired() })
}

// The forwarding methods over paired, which says whether a network's Sidecar is a paired child.
func daemonForwardingMethods(paired func(sidecar *Sidecar) bool) []*DaemonMethod {
	check := func(call *DaemonCall) error {
		if call.Hello == nil || call.Hello.Mode != DaemonModeControl || call.Sidecar == nil || !paired(call.Sidecar) {
			return ErrDaemonForwardingCaller
		}
		return nil
	}
	return []*DaemonMethod{
		{
			Name:    DaemonMethodForwardingSetup,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				if err := check(call); err != nil {
					return nil, err
				}
				params := &DaemonForwardingSetupParams{}
				if len(call.Params) == 0 || json.Unmarshal(call.Params, params) != nil {
					return nil, errors.New("bridge.forwarding.setup takes the component's keys")
				}
				keys := &bridge.ForwardingKeys{}
				if err := proto.Unmarshal(params.Keys, keys); err != nil {
					return nil, errors.New("bridge.forwarding.setup's keys do not read")
				}
				if params.ConfirmAfterRevocation {
					if !call.Confirmed {
						return nil, errors.New("setting forwarding up after another's revocation needs the person's confirmation in the app")
					}
					if err := call.Sidecar.ConfirmForwardingSetup(call.NetworkId); err != nil {
						return nil, err
					}
				}
				handOff, err := call.Sidecar.SetUpForwarding(ctx, call.NetworkId, keys)
				if err != nil {
					return nil, err
				}
				encoded, err := proto.Marshal(handOff)
				if err != nil {
					return nil, err
				}
				return &DaemonForwardingSetupReply{HandOff: encoded}, nil
			},
		},
		{
			Name:    DaemonMethodForwardingWitness,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				if err := check(call); err != nil {
					return nil, err
				}
				witness, err := call.Sidecar.ForwardingWitness(call.NetworkId)
				if err != nil {
					return nil, err
				}
				pin, err := proto.Marshal(witness.Pin)
				if err != nil {
					return nil, err
				}
				return &DaemonForwardingWitnessReply{Pin: pin, Witnessed: witness.Witnessed, Fork: witness.Fork, SetupDue: string(witness.SetupDue)}, nil
			},
		},
	}
}
