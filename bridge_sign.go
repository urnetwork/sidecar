//go:build !ios_extension && !sidecar_http

// Sidecar.SignWindowDelegation (DESIGN-DETAILS 12.2.6, §17.9's sign row; landed early for SDK-M8-08 by BRIDGE-M4-17,
// since ur tun's links need it at M4): the WindowDelegation a link's window client carries in CreateContract, signed by
// this sidecar's identity key, which a host verifies once per contract before its first flow (bridge.
// VerifyWindowDelegation). It signs only for this sidecar's own network and itself as the subject, a window client key
// of 32 bytes, a not_after ahead and at most WindowDelegationMaxLifetime away, and a target the newest compiled state
// names in a link, an entry's or an exit's; with no compiled state, pending, it signs nothing. A share link's
// delegation, signed with the share's BridgeShareSigner, is BRIDGE-M6-04's, and refused until then.
//
// Neither the delegation nor the signed bytes reach a log line, an event, BridgeState, a device RPC reply or an MCP
// tool: the bytes go to the caller, the link's generator, alone. The identity key never leaves Sidecar.Sign.

package sidecar

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A delegation SignWindowDelegation will not sign, named by the rule it breaks, never by a value (I-13).
var ErrBridgeDelegationRefused = errors.New("window delegation refused")

// What a link asks to have signed for one window client (§17.9's sign row).
type BridgeDelegationRequest struct {
	NetworkId        Id
	SubjectSidecarId Id
	WindowClientId   Id
	// The window client's ClientKey public key, 32 bytes.
	WindowClientPublicKey []byte
	TargetSidecarId       Id
	// The window client's strict_exp (§7.4).
	NotAfter time.Time
	// Zero on a same-network link.
	ShareId Id
}

// Signs a link's WindowDelegation, or refuses it with ErrBridgeDelegationRefused (the file's comment).
func (self *Sidecar) SignWindowDelegation(request *BridgeDelegationRequest) ([]byte, error) {
	component := self.bridgeComponent()
	if component == nil {
		return nil, fmt.Errorf("%w: no bridge component", ErrBridgeDelegationRefused)
	}
	return bridgeSignWindowDelegation(request, self.currentIdentity(), component.Compiled(), component.settings.WindowDelegationMaxLifetime,
		self.clock.Now(), func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
			return self.Sign(purpose, signedType, body, nil)
		})
}

// SignWindowDelegation's rules over this sidecar's identity, the newest compile and the time, signing with sign.
func bridgeSignWindowDelegation(request *BridgeDelegationRequest, identity *SidecarIdentity, compiled *BridgeCompiled,
	maxLifetime time.Duration, now time.Time, sign func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error)) ([]byte, error) {
	switch {
	case request == nil:
		return nil, fmt.Errorf("%w: no request", ErrBridgeDelegationRefused)
	case identity == nil:
		return nil, fmt.Errorf("%w: no identity", ErrBridgeDelegationRefused)
	case request.NetworkId != identity.NetworkId:
		return nil, fmt.Errorf("%w: another network", ErrBridgeDelegationRefused)
	case request.SubjectSidecarId != identity.SidecarId:
		return nil, fmt.Errorf("%w: another subject", ErrBridgeDelegationRefused)
	case len(request.WindowClientPublicKey) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("%w: a window client key of %d bytes", ErrBridgeDelegationRefused, len(request.WindowClientPublicKey))
	case request.WindowClientId == (Id{}) || request.TargetSidecarId == (Id{}):
		return nil, fmt.Errorf("%w: no window client or target", ErrBridgeDelegationRefused)
	case !request.NotAfter.After(now):
		return nil, fmt.Errorf("%w: a not_after in the past", ErrBridgeDelegationRefused)
	case maxLifetime < request.NotAfter.Sub(now):
		return nil, fmt.Errorf("%w: a not_after past the longest a delegation lives", ErrBridgeDelegationRefused)
	case request.ShareId != (Id{}):
		// a share link's signer is the share's BridgeShareSigner (BRIDGE-M6-04)
		return nil, fmt.Errorf("%w: a share link, which this build does not sign", ErrBridgeDelegationRefused)
	case compiled == nil || compiled.State == nil:
		return nil, fmt.Errorf("%w: no compiled state", ErrBridgeDelegationRefused)
	case !slices.Contains(compiled.LinkTargets, request.TargetSidecarId):
		return nil, fmt.Errorf("%w: a target the compiled state links to nowhere", ErrBridgeDelegationRefused)
	}
	delegation := &bridge.WindowDelegation{
		NetworkId:             request.NetworkId.Bytes(),
		SubjectSidecarId:      request.SubjectSidecarId.Bytes(),
		WindowClientId:        request.WindowClientId.Bytes(),
		WindowClientPublicKey: append([]byte(nil), request.WindowClientPublicKey...),
		TargetSidecarId:       request.TargetSidecarId.Bytes(),
		NotAfterMs:            request.NotAfter.UnixMilli(),
	}
	return bridge.WindowDelegationSigned(delegation, sign)
}

// This Sidecar's bridge component, nil for none.
func (self *Sidecar) bridgeComponent() *BridgeComponent {
	leg, ok := self.leg.(*sidecarConnectLeg)
	if !ok {
		return nil
	}
	for _, component := range leg.componentList() {
		if bridgeComponent, ok := component.(*BridgeComponent); ok {
			return bridgeComponent
		}
	}
	return nil
}
