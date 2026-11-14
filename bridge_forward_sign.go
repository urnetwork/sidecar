// ForwardingSigner (BRIDGE-M8-05; DESIGN-DETAILS 4.2.4, 4.2.5; §17.9's sign row; owner decision 197, QD-597): what a
// VPN component signs its links' WindowDelegations with while no sidecar role runs. It holds no identity key and
// signs no statement: only the WindowDelegation of a window client of its own sidecar's links, with the forwarding
// key its sidecar's forwarding Delegation names.
//
// A delegation it signs has subject S, the sidecar the forwarding Delegation belongs to, signer_id the Delegation's
// 32-byte id, key_id the SHA-256 of the forwarding public key, and not_after_ms at most the window client's
// strict_exp (§7.4) and at most WindowDelegationMaxLifetime away. A host verifies it by the signer's length alone
// (bridge.VerifyWindowDelegationAdmission), under the forward_public_key its state lists for S while the Delegation is
// live. The signer refuses another network or subject, a target the state in force links to nowhere, and everything
// while no state is in force. A share link's delegation is signed with the share's current ShareSigner
// (BRIDGE-M6-04), which this build does not hold, and is refused.
//
// Neither the delegation nor the signed bytes reach a log line or an event: the bytes go to the caller, the link's
// generator, alone. The forwarding private key stays behind Sign, with its holder (ForwarderKeys).
//
// Safe for concurrent use.

package sidecar

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A delegation the forwarding signer will not sign, named by the rule it breaks, never by a value (I-13).
var ErrForwardingDelegationRefused = errors.New("forwarding window delegation refused")

// Tunables of a forwarding signer.
type ForwardingSignerSettings struct {
	// The longest a delegation lives from its signing: 168 h, the sidecar role's own bound. Non-positive signs nothing.
	WindowDelegationMaxLifetime time.Duration
	// The format's limits, nil its defaults.
	WindowDelegation *bridge.WindowDelegationSettings
}

// The values above.
func DefaultForwardingSignerSettings() *ForwardingSignerSettings {
	return &ForwardingSignerSettings{
		WindowDelegationMaxLifetime: 168 * time.Hour,
		WindowDelegation:            bridge.DefaultWindowDelegationSettings(),
	}
}

// What a link asks to have signed for one window client.
type ForwardingSignRequest struct {
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

// What a forwarding signer is built over.
type ForwardingSignerArgs struct {
	NetworkId Id
	// S: the sidecar the forwarding Delegation belongs to.
	SidecarId Id
	// The forwarding Delegation's id and the public key it names.
	DelegationId [sha256.Size]byte
	PublicKey    ed25519.PublicKey
	// Signs message with the forwarding private key, which stays with its holder.
	Sign func(message []byte) ([]byte, error)
	// The sidecars the state in force links to, and false while none is in force: the Forwarder's last compile.
	LinkTargets func() ([]Id, bool)
	Clock       Clock
	Settings    *ForwardingSignerSettings
}

// The forwarding signer (the file's comment).
type ForwardingSigner struct {
	args     *ForwardingSignerArgs
	settings *ForwardingSignerSettings
	clock    Clock
	keyId    [sha256.Size]byte
}

// A signer over args, whose ids, key, Sign and LinkTargets are required.
func NewForwardingSigner(args *ForwardingSignerArgs) (*ForwardingSigner, error) {
	if args == nil || args.NetworkId == (Id{}) || args.SidecarId == (Id{}) || args.DelegationId == ([sha256.Size]byte{}) ||
		len(args.PublicKey) != ed25519.PublicKeySize || args.Sign == nil || args.LinkTargets == nil {
		return nil, fmt.Errorf("%w: a forwarding signer needs its network, sidecar, delegation, key and state", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultForwardingSignerSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return &ForwardingSigner{args: args, settings: settings, clock: clock, keyId: sha256.Sum256(args.PublicKey)}, nil
}

// Signs a link's WindowDelegation with the forwarding key, or refuses it with ErrForwardingDelegationRefused (the
// file's comment).
func (self *ForwardingSigner) SignWindowDelegation(request *ForwardingSignRequest) ([]byte, error) {
	now := self.clock.Now()
	switch {
	case request == nil:
		return nil, fmt.Errorf("%w: no request", ErrForwardingDelegationRefused)
	case request.NetworkId != self.args.NetworkId:
		return nil, fmt.Errorf("%w: another network", ErrForwardingDelegationRefused)
	case request.SubjectSidecarId != self.args.SidecarId:
		return nil, fmt.Errorf("%w: another subject", ErrForwardingDelegationRefused)
	case len(request.WindowClientPublicKey) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("%w: a window client key of %d bytes", ErrForwardingDelegationRefused, len(request.WindowClientPublicKey))
	case request.WindowClientId == (Id{}) || request.TargetSidecarId == (Id{}):
		return nil, fmt.Errorf("%w: no window client or target", ErrForwardingDelegationRefused)
	case !request.NotAfter.After(now):
		return nil, fmt.Errorf("%w: a not_after in the past", ErrForwardingDelegationRefused)
	case self.settings.WindowDelegationMaxLifetime < request.NotAfter.Sub(now):
		return nil, fmt.Errorf("%w: a not_after past the longest a delegation lives", ErrForwardingDelegationRefused)
	case request.ShareId != (Id{}):
		// a share link's signer is the share's ShareSigner from the compiled state (BRIDGE-M6-04)
		return nil, fmt.Errorf("%w: a share link, which this build does not sign", ErrForwardingDelegationRefused)
	}
	targets, inForce := self.args.LinkTargets()
	if !inForce {
		return nil, fmt.Errorf("%w: no state in force", ErrForwardingDelegationRefused)
	}
	if !slices.Contains(targets, request.TargetSidecarId) {
		return nil, fmt.Errorf("%w: a target the state in force links to nowhere", ErrForwardingDelegationRefused)
	}
	delegation := &bridge.WindowDelegation{
		NetworkId:             request.NetworkId.Bytes(),
		SubjectSidecarId:      request.SubjectSidecarId.Bytes(),
		WindowClientId:        request.WindowClientId.Bytes(),
		WindowClientPublicKey: append([]byte(nil), request.WindowClientPublicKey...),
		TargetSidecarId:       request.TargetSidecarId.Bytes(),
		NotAfterMs:            request.NotAfter.UnixMilli(),
	}
	signedBytes, err := bridge.WindowDelegationSigned(delegation, self.sign, self.settings.WindowDelegation)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrForwardingDelegationRefused, err)
	}
	return signedBytes, nil
}

// The Signed envelope under the forwarding key: signer_id the Delegation's id, key_id the key's SHA-256.
func (self *ForwardingSigner) sign(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
	testHookBarrier("bridge_forward.sign", "")
	signature, err := self.args.Sign(bridge.SignedBytes(purpose, signedType, body))
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("a signature of the wrong length")
	}
	return &bridge.Signed{
		Body:      body,
		SignerId:  self.args.DelegationId[:],
		KeyId:     self.keyId[:],
		Signature: signature,
		Type:      uint32(signedType),
	}, nil
}
