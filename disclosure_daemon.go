//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's disclosure methods (DESIGN-COMPUTE §2.8, §15.1, §15.3; CTRUST-M11-01): what `ur disclosures` and a
// remote-mode app's Disclosures() call, on desktop legs only, each on its call's network (§5.8's network rule):
//
//	compute.disclosure.list  every disclosure of the newest verified policy in the caller's locale, each with the
//	                         version the acknowledgments that cover this sidecar hold and its changed mark, no Confirm;
//	                         with no verified policy the reply's unavailable is policy_unavailable and nothing is listed
//	compute.disclosure.ack   the person's acknowledgment of an id at the version they were shown (CTRUST-M12-01): a
//	                         Confirm method, refused unconfirmed and to a caller with a harness process among its
//	                         ancestors, the daemon reading the caller's ancestry from the peer's pid, which the caller
//	                         cannot set, and treating a caller it cannot name as one; a version not the current one
//	                         answers disclosure_changed as the reply's refusal, with nothing written
//	compute.disclosure.open  that the person opened an id's whole text at its current version, which ends its lines'
//	                         changed mark: a Confirm method under the same rules
//
// Params are read strictly. A reply carries the policy's printable texts and the device's words, nothing else. ur daemon
// registers the methods (cli/cmd_disclosures.go); ur native-host relays none of them. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

// The methods.
const (
	DaemonMethodComputeDisclosureList = "compute.disclosure.list"
	DaemonMethodComputeDisclosureAck  = "compute.disclosure.ack"
	DaemonMethodComputeDisclosureOpen = "compute.disclosure.open"
)

// compute.disclosure.list's params.
type DaemonComputeDisclosureListParams struct {
	// The call's network, empty for .ur's or the only one (§5.8).
	Network string `json:"network,omitempty"`
	// The person's locale, a BCP 47 tag or a POSIX locale; empty for English.
	Locale string `json:"locale,omitempty"`
}

// compute.disclosure.ack's and compute.disclosure.open's params: the id and the version the person was shown.
type DaemonComputeDisclosureActParams struct {
	Network string `json:"network,omitempty"`
	Id      string `json:"id"`
	Version uint32 `json:"version"`
}

// compute.disclosure.ack's and compute.disclosure.open's reply: the id and version the act recorded, or the refusal's
// code where the version shown is not the current one (disclosure_changed) or the policy holds nothing to act on
// (disclosure_required, policy_unavailable).
type DaemonComputeDisclosureActReply struct {
	Id      string `json:"id"`
	Version uint32 `json:"version,omitempty"`
	Refusal string `json:"refusal,omitempty"`
}

var (
	// The params of a call that do not decode, or of an unbound call: the text names nothing they held.
	errDaemonComputeDisclosureParams = errors.New("the disclosure params do not decode")
	// An acknowledgment or an opening no person confirmed.
	errDaemonComputeDisclosureUnconfirmed = fmt.Errorf("%w: the call is not the person's confirmed act", ErrDisclosureAckRefused)
	// An acknowledgment or an opening from under a harness process.
	errDaemonComputeDisclosureUnderHarness = fmt.Errorf("%w: a harness process is among the caller's ancestors", ErrDisclosureAckRefused)
)

// What the disclosure methods act through: a nil List takes the call's Sidecar's ComputeDisclosures, a nil Ack its
// AckComputeDisclosure, a nil Open its OpenedComputeDisclosure and a nil UnderHarness its HarnessAncestor on the peer's
// pid, true where the caller cannot be named.
type DaemonComputeDisclosureBackends struct {
	List         func(ctx context.Context, sidecar *Sidecar, locale string) (*ComputeDisclosureList, error)
	Ack          func(ctx context.Context, sidecar *Sidecar, args *ComputeDisclosureAckArgs) error
	Open         func(ctx context.Context, sidecar *Sidecar, id string, version uint32) error
	UnderHarness func(ctx context.Context, call *DaemonCall) bool
}

// The act's refusal as its reply's code, nil for any other error, which stands.
func daemonComputeDisclosureRefusal(id string, err error) *DaemonComputeDisclosureActReply {
	switch {
	case errors.Is(err, ErrDisclosureChanged):
		return &DaemonComputeDisclosureActReply{Id: id, Refusal: ComputeDisclosureCodeChanged}
	case errors.Is(err, ErrComputeDisclosurePolicyUnavailable):
		return &DaemonComputeDisclosureActReply{Id: id, Refusal: ComputeDisclosureCodePolicyUnavailable}
	case errors.Is(err, ErrComputeDisclosureNotCarried), errors.Is(err, ErrComputeDisclosureRefused):
		return &DaemonComputeDisclosureActReply{Id: id, Refusal: ComputeDisclosureCodeRequired}
	}
	return nil
}

// The daemon's disclosure methods over backends. The daemon's composition registers them with RegisterMethod.
func DaemonComputeDisclosureMethods(backends *DaemonComputeDisclosureBackends) []*DaemonMethod {
	if backends == nil {
		backends = &DaemonComputeDisclosureBackends{}
	}
	listOf := backends.List
	if listOf == nil {
		listOf = func(ctx context.Context, sidecar *Sidecar, locale string) (*ComputeDisclosureList, error) {
			return sidecar.ComputeDisclosures(ctx, locale)
		}
	}
	ackOf := backends.Ack
	if ackOf == nil {
		ackOf = func(ctx context.Context, sidecar *Sidecar, args *ComputeDisclosureAckArgs) error {
			return sidecar.AckComputeDisclosure(ctx, args)
		}
	}
	openOf := backends.Open
	if openOf == nil {
		openOf = func(ctx context.Context, sidecar *Sidecar, id string, version uint32) error {
			return sidecar.OpenedComputeDisclosure(ctx, id, version, SidecarActConfirmed)
		}
	}
	underHarness := backends.UnderHarness
	if underHarness == nil {
		underHarness = func(ctx context.Context, call *DaemonCall) bool {
			if call.Hello == nil || call.Hello.PeerPid <= 0 || call.Sidecar == nil {
				return true
			}
			return call.Sidecar.HarnessAncestor(ctx, int(call.Hello.PeerPid))
		}
	}
	// a Confirm method's guard and params: the person's confirmed act, from no harness process
	act := func(ctx context.Context, call *DaemonCall) (*DaemonComputeDisclosureActParams, error) {
		if !call.Confirmed {
			return nil, errDaemonComputeDisclosureUnconfirmed
		}
		params := &DaemonComputeDisclosureActParams{}
		if err := decodeDaemonSocketParams(call, params); err != nil {
			return nil, fmt.Errorf("%w: %w", errDaemonComputeDisclosureParams, err)
		}
		if call.Sidecar == nil {
			return nil, fmt.Errorf("%w: no network's sidecar", errDaemonComputeDisclosureParams)
		}
		if underHarness(ctx, call) {
			return nil, errDaemonComputeDisclosureUnderHarness
		}
		return params, nil
	}
	return []*DaemonMethod{
		{
			Name:    DaemonMethodComputeDisclosureAck,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params, err := act(ctx, call)
				if err != nil {
					return nil, err
				}
				err = ackOf(ctx, call.Sidecar, &ComputeDisclosureAckArgs{Id: params.Id, Version: params.Version, Origin: SidecarActConfirmed})
				if refusal := daemonComputeDisclosureRefusal(params.Id, err); refusal != nil {
					return refusal, nil
				}
				if err != nil {
					return nil, err
				}
				return &DaemonComputeDisclosureActReply{Id: params.Id, Version: params.Version}, nil
			},
		},
		{
			Name:    DaemonMethodComputeDisclosureOpen,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params, err := act(ctx, call)
				if err != nil {
					return nil, err
				}
				err = openOf(ctx, call.Sidecar, params.Id, params.Version)
				if refusal := daemonComputeDisclosureRefusal(params.Id, err); refusal != nil {
					return refusal, nil
				}
				if err != nil {
					return nil, err
				}
				return &DaemonComputeDisclosureActReply{Id: params.Id, Version: params.Version}, nil
			},
		},
		{
			Name:    DaemonMethodComputeDisclosureList,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonComputeDisclosureListParams{}
				if err := decodeDaemonSocketParams(call, params); err != nil {
					return nil, fmt.Errorf("%w: %w", errDaemonComputeDisclosureParams, err)
				}
				if call.Sidecar == nil {
					return nil, fmt.Errorf("%w: no network's sidecar", errDaemonComputeDisclosureParams)
				}
				list, err := listOf(ctx, call.Sidecar, params.Locale)
				if errors.Is(err, ErrComputeDisclosurePolicyUnavailable) {
					// a code the surface prints with its fix, never an empty list
					return &ComputeDisclosureList{Disclosures: []*ComputeDisclosureView{}, Unavailable: ComputeDisclosureCodePolicyUnavailable}, nil
				}
				if err != nil {
					return nil, err
				}
				return list, nil
			},
		},
	}
}
