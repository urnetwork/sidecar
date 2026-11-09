//go:build !sidecar_http

// Hello's identity check (§6.4, D-PROTO-13, I-3, R-PROTO-11): what a Hello or HelloResult must show
// before this side opens its gate to the peer that sent it. Each side checks the one it receives, on its
// own, so a pair is open both ways only once both have verified.
//
// The checks, in order, each failure leaving the gate closed:
//
//  1. a version both sides speak, and a secure_version at or above this side's floor, else VERSION;
//  2. the binding: canonical, with both signatures verifying over the bytes received
//     (VerifySidecarIdentityBinding, the one decoder; never a second here);
//  3. its network_id is this sidecar's network;
//  4. its client_id is the frame's authenticated source;
//  5. its client_public_key is C15's key on this frame's Peer, an empty key being a refusal, never a pass;
//  6. its identity_public_key is the pin for its sidecar_id and its generation is no lower than the
//     highest seen, else UNAUTHENTICATED, and a key that differs raises key_changed. The pin is M1's
//     first use (rpc_pins.go) or, from M2, the peer's SidecarAdmit (rpc_admission.go), which must also
//     stand: neither revoked nor parked, else UNAUTHENTICATED. A side with no verified state, or not
//     itself admitted, takes no peer and answers UNAVAILABLE.
//
// The floor, the version range, Required, the Signed rules and the chunk limits are never gated by a
// feature bit (D-PROTO-16): a Hello's features are recorded and grant nothing (rpc_features.go).

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// §6.4's security floor, facts of a release rather than tunables (D-PROTO-16).
const (
	// This release's security level, which its Hello carries as secure_version. A release that closes a
	// hole older peers must not reach across raises it.
	SecureVersion = 1
	// The lowest secure_version this release accepts: a peer below it gets VERSION. core may raise the
	// floor only live and only up to SecureVersion (QD-032), never below this and never stored.
	MinSecureVersion = 1
)

var (
	// The peer speaks no version this side does, or its secure_version is below the floor.
	errHelloVersion = errors.New("hello: no common version, or below the secure floor")
	// The binding names another network than this sidecar's.
	errHelloNetwork = errors.New("hello: binding names another network")
	// The binding names another client than the frame's source.
	errHelloClient = errors.New("hello: binding names another client")
	// The binding's client key is not C15's on the frame, or the frame carries none.
	errHelloSessionKey = errors.New("hello: binding's client key is not the session's")
	// A Hello or HelloResult that does not decode.
	errHelloMalformed = errors.New("hello: malformed")
)

// A verified peer, as its Hello or HelloResult showed it. Every slice is this value's own.
type SubprotocolPeerIdentity struct {
	SidecarId         Id
	IdentityPublicKey []byte
	// The bound client generation (§5.5).
	Generation int64
	// The marshalled SignedSidecarIdentityBinding, as received.
	Binding []byte
	// Hello's feature bits (§6.11): recorded, granting nothing (D-PROTO-16).
	Features uint64
	// The credit the peer grants a stream before accepting it (§6.7).
	InitialWindow uint32
	// The largest body the peer reassembles, past which a call to it is TOO_LARGE here.
	MaxBodyByteCount uint32
	// The peer's admission as this side's verified state held it when its Hello verified (§6.4,
	// rpc_admission.go): its SidecarAdmit's row, with the member or tags it names. Neither revoked nor
	// parked then. Nil under M1's first-use pins, which know of no admission.
	Admission *AclSidecar
	// The position n of the state Admission was read at. A gate that finds the state past it reads the
	// admission again before it lets another frame through (rpc_admission.go).
	AdmissionVersion uint64
}

// A copy sharing no slice.
func (self *SubprotocolPeerIdentity) clone() *SubprotocolPeerIdentity {
	clone := *self
	clone.IdentityPublicKey = bytes.Clone(self.IdentityPublicKey)
	clone.Binding = bytes.Clone(self.Binding)
	clone.Admission = cloneAclSidecar(self.Admission)
	return &clone
}

// The fields Hello and HelloResult share, which are the same fields with the same numbers (reading 4).
type helloFields struct {
	minVersion       uint32
	maxVersion       uint32
	secureVersion    uint32
	features         uint64
	maxBodyByteCount uint32
	initialWindow    uint32
	binding          []byte
}

// A Hello's fields.
func helloFieldsOf(hello *protocol.Hello) *helloFields {
	return &helloFields{
		minVersion:       hello.MinVersion,
		maxVersion:       hello.MaxVersion,
		secureVersion:    hello.SecureVersion,
		features:         hello.Features,
		maxBodyByteCount: hello.MaxBodyByteCount,
		initialWindow:    hello.InitialWindow,
		binding:          hello.Binding,
	}
}

// A HelloResult's fields.
func helloFieldsOfResult(result *protocol.HelloResult) *helloFields {
	return &helloFields{
		minVersion:       result.MinVersion,
		maxVersion:       result.MaxVersion,
		secureVersion:    result.SecureVersion,
		features:         result.Features,
		maxBodyByteCount: result.MaxBodyByteCount,
		initialWindow:    result.InitialWindow,
		binding:          result.Binding,
	}
}

// The floor a peer's secure_version must reach: the compiled MinSecureVersion, or core's live raise,
// never past this release's own SecureVersion (QD-032).
func (self *Subprotocol) secureFloor() uint32 {
	floor := min(self.raisedSecureFloor.Load(), SecureVersion)
	return max(floor, MinSecureVersion)
}

// Applies core's raise of the secure floor (§6.4) for as long as core keeps asserting it: in memory
// only, and never past this release's SecureVersion, so a forged raise cannot refuse a peer at this
// device's version or newer, and it ends when the operator stops asserting it (QD-032). A raise above
// SecureVersion is this release's to show in ur status as an upgrade due. Zero drops the raise.
func (self *Subprotocol) SetRaisedSecureFloor(floor uint32) {
	self.raisedSecureFloor.Store(floor)
}

// Runs the file header's checks on a Hello or HelloResult from sourceId whose frame carried
// clientPublicKey. The answer is the verified peer, or the code to refuse with and why. A pin that names
// another key raises key_changed. ctx bounds the admission source's one catch-up of the config.
func (self *Subprotocol) checkHello(
	ctx context.Context,
	sourceId connect.Id,
	fields *helloFields,
	clientPublicKey [ed25519.PublicKeySize]byte,
	hasClientPublicKey bool,
) (*SubprotocolPeerIdentity, protocol.ErrorCode, error) {
	// (1) versions and the floor, by this side's own state alone
	if WireVersionMajor < fields.minVersion || fields.maxVersion < WireVersionMajor || fields.maxVersion < fields.minVersion {
		return nil, protocol.ErrorCode_ERR_VERSION, errHelloVersion
	}
	if fields.secureVersion < self.secureFloor() {
		return nil, protocol.ErrorCode_ERR_VERSION, errHelloVersion
	}
	// (2) the binding and its signatures, over the bytes as received
	binding, err := VerifySidecarIdentityBinding(fields.binding)
	if err != nil {
		return nil, protocol.ErrorCode_ERR_UNAUTHENTICATED, err
	}
	// (3) this network
	if binding.NetworkId != self.networkId {
		return nil, protocol.ErrorCode_ERR_UNAUTHENTICATED, errHelloNetwork
	}
	// (4) the frame's source
	if binding.ClientId != Id(sourceId) {
		return nil, protocol.ErrorCode_ERR_UNAUTHENTICATED, errHelloClient
	}
	// (5) C15's key on this frame, none being a refusal
	if !hasClientPublicKey || !bytes.Equal(binding.ClientPublicKey, clientPublicKey[:]) {
		return nil, protocol.ErrorCode_ERR_UNAUTHENTICATED, errHelloSessionKey
	}
	// (6) the pin and the generation, and from M2 the admission standing
	admission, err := self.pins.checkPin(ctx, binding.SidecarId, binding.IdentityPublicKey, binding.Generation)
	if err != nil {
		switch {
		case errors.Is(err, errHelloPinMismatch):
			sidecarId := binding.SidecarId
			self.raiseEvent(SidecarEvent{Kind: SidecarEventKeyChanged, SidecarId: &sidecarId})
			return nil, protocol.ErrorCode_ERR_UNAUTHENTICATED, err
		case errors.Is(err, errHelloGenerationBelow), errors.Is(err, errHelloUnadmitted),
			errors.Is(err, errHelloRevoked), errors.Is(err, errHelloParked):
			return nil, protocol.ErrorCode_ERR_UNAUTHENTICATED, err
		case errors.Is(err, errHelloNotAdmitted):
			return nil, protocol.ErrorCode_ERR_UNAVAILABLE, err
		}
		// a store that cannot answer, or a catch-up that failed, pins nothing and opens nothing
		return nil, protocol.ErrorCode_ERR_UNAVAILABLE, fmt.Errorf("hello: pin: %w", err)
	}
	peer := &SubprotocolPeerIdentity{
		SidecarId:         binding.SidecarId,
		IdentityPublicKey: bytes.Clone(binding.IdentityPublicKey),
		Generation:        binding.Generation,
		Binding:           bytes.Clone(fields.binding),
		Features:          fields.features,
		InitialWindow:     fields.initialWindow,
		MaxBodyByteCount:  fields.maxBodyByteCount,
	}
	if admission != nil {
		peer.Admission = admission.admission
		peer.AdmissionVersion = admission.stateVersion
	}
	return peer, protocol.ErrorCode_ERR_OK, nil
}

// Hands an event to the host, if it gave a sink.
func (self *Subprotocol) raiseEvent(event SidecarEvent) {
	if self.event != nil {
		self.event(event)
	}
}
