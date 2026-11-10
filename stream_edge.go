//go:build !sidecar_http

// §6.10.1's edges on the subprotocol (C9, D-PROTO-6, D-PROTO-9, D-PROTO-15): the role a dispatcher runs
// in, what a Service-mode source may send, and the provide modes an owner holds on top of a client's own.
//
// An edge is a platform client in urnetwork-edge (tlsedge, smtpedge, mxedge's engines): it carries no
// binding and sends no Hello, and a sidecar never sends it one. Its tickets' dialer_network_id identifies
// it (§9.6's step 3), so a Service-mode source's open is admitted on its ticket by the acceptor's function
// (SOCK-M5-11), never by Hello's identity check, and that open's stream takes frames only from a
// Service-mode source. A sidecar opening to an edge, as §14's stream to smtpedge does, runs no Hello
// either (StreamOpenRequest.Edge). Edges never run HeadCheck.
//
// The inline handler's step 4 (rpc_guard.go) admits a Service-mode source only for the 21842 traffic an
// edge's relationship carries: at a sidecar, an edge's stream frames, Ping and Pong and its answers to calls
// the sidecar made of it; at an edge, a sidecar's stream frames, Ping, Pong, Cancel and the requests the
// edge's engine handles, never Hello, HeadCheck or SEARCH, which only sidecars of one network exchange.
// Every other mode is dropped: FriendsAndFamily reaches a sidecar only by IP until PROTO-M6-01, and Public
// never (D-PROTO-6).

package sidecar

import (
	"context"
	"errors"
	"maps"
	"sync"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A mode HoldProvideMode does not add: Public, which would list a sidecar in VPN exits' egress index,
	// and anything but Service and FriendsAndFamily (D-PROTO-6).
	errProvideModeRefused = errors.New("subprotocol: provide mode refused")
	// An edge runs no Hello and no HeadCheck, with anyone.
	errSubprotocolEdgeRole = errors.New("subprotocol: an edge runs no hello or head check")
)

// Which side of §6.10.1's relationships a dispatcher runs as.
type SubprotocolRole int

const (
	// A sidecar: Hello's identity check before any stream or RPC (D-PROTO-13), HeadCheck with its
	// network's admitted peers, and edges' streams admitted on their tickets. The zero value.
	SubprotocolRoleSidecar SubprotocolRole = 0
	// An engine's platform client in urnetwork-edge: no binding either way, no Hello, never HeadCheck, and
	// only Service-mode sources, whose every stream is an edge stream.
	SubprotocolRoleEdge SubprotocolRole = 1
)

// An edge's pins: none, so a Hello that reached a check would verify nothing. An edge registers no Hello
// dispatch and sends none, so this is the closed default behind that, never a path in use.
type edgeIdentityPins struct{}

// Refuses every pin.
func (self edgeIdentityPins) checkPin(ctx context.Context, sidecarId Id, identityPublicKey []byte, generation int64) (*identityPinAdmission, error) {
	return nil, errSubprotocolEdgeRole
}

// Whether a type is one of §6.7's stream frames, StreamOpen through StreamReset (service 0x02).
func streamMessageType(messageType uint32) bool {
	return protocol.MessageType_STREAM_OPEN <= protocol.MessageType(messageType) && protocol.MessageType(messageType) <= protocol.MessageType_STREAM_RESET
}

// Whether a type belongs only between sidecars of one network: Hello's exchange, HeadCheck's and SEARCH's.
func sidecarOnlyMessageType(messageType uint32) bool {
	switch protocol.MessageType(messageType) {
	case protocol.MessageType_HELLO, protocol.MessageType_HELLO_RESULT,
		protocol.MessageType_HEAD_CHECK, protocol.MessageType_HEAD_CHECK_RESULT,
		protocol.MessageType_HEAD_CHECK_PROOF_REQUEST, protocol.MessageType_HEAD_CHECK_PROOF,
		protocol.MessageType_SEARCH, protocol.MessageType_SEARCH_RESULT:
		return true
	}
	return false
}

// What a Service-mode source may send a dispatcher of role. See the file header.
func serviceMessageAdmits(role SubprotocolRole, messageType uint32, flags uint32) bool {
	switch {
	case streamMessageType(messageType):
		return true
	case sidecarOnlyMessageType(messageType):
		return false
	}
	switch protocol.MessageType(messageType) {
	case protocol.MessageType_PING, protocol.MessageType_PONG:
		return true
	}
	if role == SubprotocolRoleEdge {
		// a sidecar's requests of the edge's engine, such as §14's SmtpProof, and the Cancel naming one
		return true
	}
	// an edge's answers to calls a sidecar made of it
	return flags&EnvelopeFlagResponse != 0
}

// The modes a dispatcher's client always provides: Network for a sidecar, whose peers are its network's
// sidecars, and Service for an edge, which edges always advertise (§6.10.1's item 2).
func baseProvideModes(role SubprotocolRole) map[connectprotocol.ProvideMode]bool {
	if role == SubprotocolRoleEdge {
		return map[connectprotocol.ProvideMode]bool{connectprotocol.ProvideMode_Service: true}
	}
	return map[connectprotocol.ProvideMode]bool{connectprotocol.ProvideMode_Network: true}
}

// The modes owners hold on top of the client's own, and the lock that orders their application.
type subprotocolProvideModes struct {
	// held across the provide frame's send, so two changes apply in the order they were counted; it is
	// taken before stateLock, never under it, and connect's call takes neither
	applyLock sync.Mutex

	stateLock sync.Mutex
	// how many holds each mode has
	heldModeCounts map[connectprotocol.ProvideMode]int
}

// Adds mode to what this dispatcher's client provides until the answer is called, on top of its own
// Network (an edge's Service): Service while a tls/ or smtp/ registration lives (§13.6, SOCK-M5-11), and
// FriendsAndFamily while an inbound share lives (PROTO-M6-01, ACL-M6-03). Holds count, so the mode goes
// only once its last hold is released, and a release past the first does nothing. Public, and every mode
// but those two, is refused, since no sidecar provides Public (D-PROTO-6). The client's provide frame
// goes to the platform at each change, so a hold costs one control message and the release another.
func (self *Subprotocol) HoldProvideMode(mode connectprotocol.ProvideMode) (release func(), err error) {
	switch mode {
	case connectprotocol.ProvideMode_Service, connectprotocol.ProvideMode_FriendsAndFamily:
	default:
		return nil, errProvideModeRefused
	}
	if !self.countProvideMode(mode, 1) {
		return nil, errSubprotocolClosed
	}
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			self.countProvideMode(mode, -1)
		})
	}, nil
}

// Moves mode's count by delta and applies the modes this leaves, unless the dispatcher has closed: a
// closed client provides nothing more, and a release then changes nothing.
func (self *Subprotocol) countProvideMode(mode connectprotocol.ProvideMode, delta int) bool {
	provideModes := &self.provideModes
	provideModes.applyLock.Lock()
	defer provideModes.applyLock.Unlock()
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed
	}()
	if closed {
		return false
	}
	modes := baseProvideModes(self.role)
	changed := func() bool {
		provideModes.stateLock.Lock()
		defer provideModes.stateLock.Unlock()
		if provideModes.heldModeCounts == nil {
			provideModes.heldModeCounts = map[connectprotocol.ProvideMode]int{}
		}
		before := 0 < provideModes.heldModeCounts[mode]
		provideModes.heldModeCounts[mode] = max(provideModes.heldModeCounts[mode]+delta, 0)
		for heldMode, count := range provideModes.heldModeCounts {
			if 0 < count {
				modes[heldMode] = true
			}
		}
		return before != (0 < provideModes.heldModeCounts[mode])
	}()
	if changed {
		self.client.ContractManager().SetProvideModes(modes)
	}
	return true
}

// The modes this dispatcher's client provides now: its own and every one held.
func (self *Subprotocol) providedModes() map[connectprotocol.ProvideMode]bool {
	modes := baseProvideModes(self.role)
	self.provideModes.stateLock.Lock()
	defer self.provideModes.stateLock.Unlock()
	for mode, count := range self.provideModes.heldModeCounts {
		if 0 < count {
			modes[mode] = true
		}
	}
	return maps.Clone(modes)
}
