//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's disclosure methods (DESIGN-COMPUTE §2.8, §15.1, §15.3; CTRUST-M11-01): what `ur disclosures` and a
// remote-mode app's Disclosures() call, on desktop legs only, each on its call's network (§5.8's network rule):
//
//	compute.disclosure.list  every disclosure of the newest verified policy in the caller's locale, no Confirm; with no
//	                         verified policy the reply's unavailable is policy_unavailable and nothing is listed
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
)

// compute.disclosure.list's params.
type DaemonComputeDisclosureListParams struct {
	// The call's network, empty for .ur's or the only one (§5.8).
	Network string `json:"network,omitempty"`
	// The person's locale, a BCP 47 tag or a POSIX locale; empty for English.
	Locale string `json:"locale,omitempty"`
}

// The params of a call that do not decode, or of an unbound call: the text names nothing they held.
var errDaemonComputeDisclosureParams = errors.New("the disclosure params do not decode")

// What the disclosure methods act through: a nil List takes the call's Sidecar's ComputeDisclosures.
type DaemonComputeDisclosureBackends struct {
	List func(ctx context.Context, sidecar *Sidecar, locale string) (*ComputeDisclosureList, error)
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
	return []*DaemonMethod{
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
