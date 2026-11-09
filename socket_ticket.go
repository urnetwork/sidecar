// §9.6's tickets on every leg: what a Find signs and a dialer presents in StreamOpen.ticket, and what
// §6.11 registers for §9. This file names no connect type and carries no build tag. socket_api.go
// holds the routes' bodies, which do name one.
//
// A ticket is §6's Signed format in a message of its own, so VerifySigned checks it as it does any
// statement: Ed25519 over bridge.SignedBytes, which is purpose, type and the ticket's bytes as received.
// Those bytes are parsed only once they verify and never re-encoded on the way, because protobuf's
// encoding is not canonical and a re-marshal need not be what was signed (§22.6).
//
// Only the service signs (§9.8), and a ticket proves only that it did: the listener's own evaluation of
// its config decides a dial (§9.6's step 6). Errors never repeat a name, which may be a private one
// (I-13). No key is created, derived or unwrapped here, so nothing calls testHookSecret: a signing key
// comes from whatever loads it.

package sidecar

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §6.11's purposes for §9's two signed types.
const (
	// SocketRegistrationClaim, by a sidecar's identity key.
	SocketRegistrationPurpose = "socket-registration"
	// SocketTicket, by a service key.
	SocketTicketPurpose = "socket-ticket"
)

// §9.6's formats.
const (
	// A signed ticket's bytes, with a 112-byte name or an 8-segment token path.
	socketTicketMaxByteCount = 370
	// All of StreamOpen.ticket.
	signedSocketTicketMaxByteCount = 512
	// ticket_id, listen_id and every network and client id.
	socketTicketIdByteCount = 16
)

var (
	// Past a bound, undecodable, or a ticket §9.6 does not allow, such as one with both a name and a
	// token path.
	ErrSocketTicketMalformed = errors.New("socket ticket malformed")
	// key_id names no key this verifier holds.
	ErrSocketTicketKeyUnknown = errors.New("socket ticket key unknown")
	// The named key has passed its expiry.
	ErrSocketTicketKeyExpired = errors.New("socket ticket key expired")
)

// A service key, as registration responses and GET /socket/keys publish it (§9.8). Keys rotate every
// 30 days with overlap, so a holder keeps every key it was last given. key_id fixes the algorithm, and
// the one there is is Ed25519 (§9.6).
type SocketTicketKey struct {
	KeyId string `json:"key_id"`
	// 32 bytes.
	PublicKey []byte `json:"public_key"`
	// Nothing verifies under it from this time on, in milliseconds. Every key expires, so 0 is one
	// that already has.
	ExpireTimeMillis uint64 `json:"expire_time_millis"`
}

// Holds §9.6's rules on a ticket's own fields, which both ends apply: every id is whole, and exactly one
// of name and name_token says what is dialed. A plaintext name is an edge name, tls/, smtp/ or ur/, in
// canonical form (D-SOCK-13), and only the first segment decides that: which ports and hosts a
// namespace takes is §9.4's to refuse at registration and Find, so a later port needs no ticket change.
func checkSocketTicket(ticket *protocol.SocketTicket) error {
	if ticket == nil {
		return fmt.Errorf("%w: no ticket", ErrSocketTicketMalformed)
	}
	for _, id := range [][]byte{
		ticket.GetTicketId(),
		ticket.GetNetworkId(),
		ticket.GetListenerClientId(),
		ticket.GetListenId(),
		ticket.GetDialerClientId(),
		ticket.GetDialerNetworkId(),
	} {
		if len(id) != socketTicketIdByteCount {
			return fmt.Errorf("%w: an id of %d bytes", ErrSocketTicketMalformed, len(id))
		}
	}
	if ticket.GetExpireTimeMillis() <= ticket.GetIssueTimeMillis() {
		return fmt.Errorf("%w: it expires before it issues", ErrSocketTicketMalformed)
	}

	name := ticket.GetName()
	nameToken := ticket.GetNameToken()
	if name != "" && len(nameToken) != 0 {
		return fmt.Errorf("%w: both a name and a token path", ErrSocketTicketMalformed)
	}
	if name == "" {
		segmentCount := len(nameToken) / socketTokenByteCount
		if len(nameToken)%socketTokenByteCount != 0 || segmentCount < 1 || socketNameMaxSegmentCount < segmentCount {
			return fmt.Errorf("%w: a token path of %d bytes", ErrSocketTicketMalformed, len(nameToken))
		}
		return nil
	}
	segments, err := socketSegments(name)
	if err != nil || foldSocketText(name) != name {
		return fmt.Errorf("%w: not a canonical name", ErrSocketTicketMalformed)
	}
	switch socketFirstSegmentNamespace(segments[0]) {
	case SocketNamespaceTls, SocketNamespaceSmtp, SocketNamespacePlatform:
		return nil
	}
	return fmt.Errorf("%w: a plaintext name outside the edge namespaces", ErrSocketTicketMalformed)
}

// What StreamOpen.ticket carries once marshaled, for a key the service holds under keyId. Signs exactly
// the bytes it returns, so nothing downstream re-encodes them. Refuses what VerifySocketTicket would and
// a ticket past §9.6's bounds, so a Find never hands out what a listener must refuse.
func SignSocketTicket(keyId string, privateKey ed25519.PrivateKey, ticket *protocol.SocketTicket) (*protocol.SignedSocketTicket, error) {
	if keyId == "" {
		return nil, fmt.Errorf("%w: no key id", ErrSocketTicketMalformed)
	}
	// ed25519.Sign panics on any other length
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: a private key of %d bytes", bridge.ErrSignedKey, len(privateKey))
	}
	if err := checkSocketTicket(ticket); err != nil {
		return nil, err
	}
	ticketBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(ticket)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSocketTicketMalformed, err)
	}
	if socketTicketMaxByteCount < len(ticketBytes) {
		return nil, fmt.Errorf("%w: a ticket of %d bytes", ErrSocketTicketMalformed, len(ticketBytes))
	}
	signedTicket := &protocol.SignedSocketTicket{
		KeyId:  keyId,
		Ticket: ticketBytes,
		Signature: ed25519.Sign(
			privateKey,
			bridge.SignedBytes(SocketTicketPurpose, bridge.SignedType_SIGNED_SOCKET_TICKET, ticketBytes),
		),
	}
	if size := proto.Size(signedTicket); signedSocketTicketMaxByteCount < size {
		return nil, fmt.Errorf("%w: a signed ticket of %d bytes", ErrSocketTicketMalformed, size)
	}
	return signedTicket, nil
}

// The ticket in received, StreamOpen.ticket's bytes or a SocketFindTicket's, once it verifies under the
// key it names. keys is the holder's newest set, and nowMillis the holder's clock as the service's:
// local time plus the server_time offset, or for the service its own. Any error is admission step 1's
// invalid (§9.6).
//
// Only the signature and the key are checked against the world here. The ticket's own expiry, its
// listener, its dialer and the rest are the caller's, in step order, because a later step's refusal
// is a different code: a ticket for a listen that just ended answers retry, not invalid, even past
// its expiry.
func VerifySocketTicket(received []byte, keys []*SocketTicketKey, nowMillis uint64) (*protocol.SocketTicket, error) {
	if signedSocketTicketMaxByteCount < len(received) {
		return nil, fmt.Errorf("%w: %d bytes", ErrSocketTicketMalformed, len(received))
	}
	signedTicket := &protocol.SignedSocketTicket{}
	if err := proto.Unmarshal(received, signedTicket); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSocketTicketMalformed, err)
	}

	var key *SocketTicketKey
	for _, candidate := range keys {
		if candidate != nil && candidate.KeyId == signedTicket.GetKeyId() {
			key = candidate
			break
		}
	}
	if key == nil {
		return nil, ErrSocketTicketKeyUnknown
	}
	if key.ExpireTimeMillis <= nowMillis {
		return nil, ErrSocketTicketKeyExpired
	}

	signed := &bridge.Signed{
		Body:      signedTicket.GetTicket(),
		Signature: signedTicket.GetSignature(),
		Type:      uint32(bridge.SignedType_SIGNED_SOCKET_TICKET),
	}
	err := bridge.VerifySigned(
		signed,
		SocketTicketPurpose,
		bridge.SignedType_SIGNED_SOCKET_TICKET,
		bridge.SignedKeyAlgEd25519,
		key.PublicKey,
	)
	if err != nil {
		return nil, err
	}

	ticket := &protocol.SocketTicket{}
	if err := proto.Unmarshal(signedTicket.GetTicket(), ticket); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSocketTicketMalformed, err)
	}
	if err := checkSocketTicket(ticket); err != nil {
		return nil, err
	}
	return ticket, nil
}

// The code a dialer acts on for StreamReject.code. §9.6 takes §6.7's five one to one, and a 0 or a value
// past them is a protocol error, taken as invalid and never as a retry or a success (§6.11).
func SocketRejectCode(code uint32) protocol.StreamRejectCode {
	switch rejectCode := protocol.StreamRejectCode(code); rejectCode {
	case protocol.StreamRejectCode_SR_RETRY,
		protocol.StreamRejectCode_SR_BUSY,
		protocol.StreamRejectCode_SR_DENIED,
		protocol.StreamRejectCode_SR_INVALID,
		protocol.StreamRejectCode_SR_QUOTA:
		return rejectCode
	}
	return protocol.StreamRejectCode_SR_INVALID
}
