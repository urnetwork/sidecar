//go:build !sidecar_http

// FuzzSocketTicket, §22.6's target for what §9.6 parses from a peer. It stays off the sidecar_http leg
// because go test reads a target's corpus from a file system the page Worker does not have, and
// socket_ticket_test.go tables the same rules on that leg.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Decoding is total, and verifying is over the bytes received. Any received bytes come back as a ticket or
// an error, and a ticket came from a signature over what those bytes carry. Any ticketBytes, once signed,
// come back only if they parse to a ticket §9.6 allows, as exactly what they parse to, and a signature
// never covers what a re-marshal writes unless that is what was signed. The seeds are the vector file's,
// which reach every refusal and hold an encoding no marshal writes.
func FuzzSocketTicket(f *testing.F) {
	vectors := testReadSocketTicketVectors(f)
	for _, vector := range vectors.Tickets {
		f.Add(testSocketHex(f, vector.Received), testSocketHex(f, vector.Ticket))
	}
	for _, vector := range vectors.Refusals {
		received := testSocketHex(f, vector.Received)
		f.Add(received, received)
	}
	f.Add([]byte{}, []byte{})

	// the file's keys hold at its clock, and testSocketTicketPrivateKey's at its own, which is long before
	keys := vectors.ticketKeys(f)
	nowMillis := vectors.NowMillis
	syntheticKeys := testSocketTicketPublicKeys()
	publicKeys := map[string]ed25519.PublicKey{}
	for _, key := range keys {
		publicKeys[key.KeyId] = key.PublicKey
	}
	ticketType := bridge.SignedType_SIGNED_SOCKET_TICKET

	f.Fuzz(func(t *testing.T, received []byte, ticketBytes []byte) {
		ticket, err := VerifySocketTicket(received, keys, nowMillis)
		if (ticket == nil) == (err == nil) {
			t.Fatalf("%x: ticket %v with error %v", received, ticket, err)
		}
		if err == nil {
			signedTicket := &protocol.SignedSocketTicket{}
			if err := proto.Unmarshal(received, signedTicket); err != nil {
				t.Fatalf("%x verified, and does not parse: %v", received, err)
			}
			signedBytes := bridge.SignedBytes(SocketTicketPurpose, ticketType, signedTicket.GetTicket())
			if !ed25519.Verify(publicKeys[signedTicket.GetKeyId()], signedBytes, signedTicket.GetSignature()) {
				t.Fatalf("%x verified over other bytes", received)
			}
			parsed := &protocol.SocketTicket{}
			if err := proto.Unmarshal(signedTicket.GetTicket(), parsed); err != nil || !proto.Equal(ticket, parsed) {
				t.Fatalf("%x: %v parses to %v, %v", received, ticket, parsed, err)
			}
		}

		signed := &protocol.SignedSocketTicket{
			KeyId:  testSocketTicketKeyId,
			Ticket: ticketBytes,
			Signature: ed25519.Sign(
				testSocketTicketPrivateKey,
				bridge.SignedBytes(SocketTicketPurpose, ticketType, ticketBytes),
			),
		}
		encoded, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		ticket, err = VerifySocketTicket(encoded, syntheticKeys, testSocketTicketNow)
		parsed := &protocol.SocketTicket{}
		allowed := len(encoded) <= signedSocketTicketMaxByteCount &&
			proto.Unmarshal(ticketBytes, parsed) == nil && checkSocketTicket(parsed) == nil
		if !allowed {
			if !errors.Is(err, ErrSocketTicketMalformed) {
				t.Fatalf("%x: %v", ticketBytes, err)
			}
			return
		}
		if err != nil {
			t.Fatalf("%x: %v", ticketBytes, err)
		}
		if !proto.Equal(ticket, parsed) {
			t.Fatalf("%x: %v, and it parses to %v", ticketBytes, ticket, parsed)
		}

		reencoded, err := proto.Marshal(ticket)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(reencoded, ticketBytes) {
			return
		}
		signed.Ticket = reencoded
		encoded, err = proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifySocketTicket(encoded, syntheticKeys, testSocketTicketNow); err == nil {
			t.Fatalf("%x verified over its re-marshal", ticketBytes)
		}
	})
}
