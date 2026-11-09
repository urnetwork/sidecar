//go:build !sidecar_http

// The inline handler's checks on where an envelope came from: the source guard (D-PROTO-8) and the
// provide mode. Both read only what connect hands the handler, so they cost a few comparisons.
//
// The platform sends clients hints from ControlId, which carry no contract and no end-to-end session
// (§6.8's exposure), and a P2P carrier checks no source, so on P2P anyone can claim to be ControlId
// (connect/transport_p2p.go). A peer's TransportType comes from the carrier that read the frame, never
// from the frame, which is why the guard keys on it. connect's C3 already holds ControlId's frames to
// platform carriers and opted-in listeners; this guard holds the same line on its own, so the rule
// does not rest on one layer.

package sidecar

import (
	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
)

// MessageType's service byte for ControlId-to-client push, PUSH_RESET 0x0101 and PUSH_HINT 0x0102
// (§6.11). A protocol value, so a constant.
const subprotocolPushService = 0x01

// Whether a type is one ControlId sends: §6.11's service 0x01.
func pushMessageType(messageType uint32) bool {
	return messageType>>8 == subprotocolPushService
}

// Whether a carrier is the platform's own: h1, h3, h3dns or h3dnspump (connect/transfer_route_manager.go).
// P2P and an unknown or custom carrier are not, so neither can deliver ControlId.
func platformCarrier(transportType connect.TransportType) bool {
	switch transportType {
	case connect.TransportTypeH1, connect.TransportTypeH3, connect.TransportTypeH3Dns, connect.TransportTypeH3DnsPump:
		return true
	}
	return false
}

// Step 3, the source guard (D-PROTO-8): a push type only from ControlId over a platform carrier, and
// nothing else from ControlId. A source id of ControlId counts as ControlId's wherever the path says it
// goes, so a frame that names it with a destination or a stream is dropped rather than taken for a
// peer's.
func sourceAdmits(source connect.TransferPath, messageType uint32, transportType connect.TransportType) bool {
	if source.SourceId == connect.ControlId {
		return source.IsControlSource() && pushMessageType(messageType) && platformCarrier(transportType)
	}
	return !pushMessageType(messageType)
}

// Step 4, the provide mode: Network for a sidecar's peers, and a Service-mode source for the traffic an
// edge's relationship carries (stream_edge.go): at a sidecar an edge's streams, keepalive and answers, at an
// edge whatever a sidecar sends it but Hello, HeadCheck and SEARCH. An edge takes no Network source.
// Cross-network peers reach sidecars only by IP (§6.4), and shares arrive as FriendsAndFamily with
// PROTO-M6-01. Anything else is dropped unanswered, so a peer this sidecar does not serve learns nothing
// from it.
func provideModeAdmits(role SubprotocolRole, provideMode connectprotocol.ProvideMode, messageType uint32, flags uint32) bool {
	switch provideMode {
	case connectprotocol.ProvideMode_Network:
		return role == SubprotocolRoleSidecar
	case connectprotocol.ProvideMode_Service:
		return serviceMessageAdmits(role, messageType, flags)
	}
	return false
}
