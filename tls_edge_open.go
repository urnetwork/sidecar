//go:build !ios_extension

// TlsEdgeOpen's bound and its two ends (§13.5): the list tlsedge may put in it, and what a listener reads back. A
// listener still trusts it only as §9.6's admission step 3 allows, which is its caller's check, so a parse here says
// the bytes are well formed and nothing about who sent them.
//
// client_ip is edge memory only: it reaches a listener and nothing else, so no error here repeats a field's value
// (I-13), and a caller keeps it out of every log and record.

package sidecar

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The most TlsEdgeOpen may take on the wire (§13.5). A format value: StreamOpen's budget rests on it.
const TlsEdgeOpenMaxByteCount = 512

const (
	// The bytes of client_ip: IPv4's or IPv6's.
	tlsEdgeOpenClientIpv4ByteCount = 4
	tlsEdgeOpenClientIpv6ByteCount = 16
	// connection_id's 16 random bytes.
	tlsEdgeOpenConnectionIdByteCount = 16
	// The largest client_port.
	tlsEdgeOpenClientPortMax = 65535

	// TlsEdgeOpen's field numbers, as tls.proto writes them.
	tlsEdgeOpenServerNameField = 3
	tlsEdgeOpenAlpnField       = 4

	// The most every field but server_name and alpn can take: client_ip and connection_id at 18 B each, tag and length
	// included, two uint32s at 6 B and a uint64 at 11 B, each varint at its longest.
	tlsEdgeOpenFixedMaxByteCount = 18 + 18 + 6 + 6 + 11
)

// The bytes are not a TlsEdgeOpen this file could have let through, or are not one at all.
var ErrTlsEdgeOpen = errors.New("tls edge open refused")

// The ALPN ids tlsedge passes on for a hello to serverName: offered ids in hello order for as long as TlsEdgeOpen stays
// within its bound (plan-TLS-small-readings' reading 6), the same list going to Find. Nothing past the first id that
// does not fit is kept, so a shorter id cannot jump the visitor's order. The bound holds whatever the other fields turn
// out to be, since Find's ticket gives expire_time_millis only after Find took this list.
//
// An id that is not UTF-8 is left out, since a proto3 string cannot hold it and encoding would then refuse the whole
// message: half of RFC 8701's GREASE ids, 0x8A8A to 0xFAFA, are not, and a visitor offering one is an ordinary
// visitor. The listener decides from the real hello, so this list is informational, and an id trimmed here costs at
// most a Find with no listener, the closed direction.
func TrimTlsEdgeOpenAlpn(serverName string, offeredAlpn []string) []string {
	byteCount := tlsEdgeOpenFixedMaxByteCount +
		protowire.SizeTag(tlsEdgeOpenServerNameField) + protowire.SizeBytes(len(serverName))
	alpn := make([]string, 0, len(offeredAlpn))
	for _, id := range offeredAlpn {
		if !utf8.ValidString(id) {
			continue
		}
		byteCount += protowire.SizeTag(tlsEdgeOpenAlpnField) + protowire.SizeBytes(len(id))
		if TlsEdgeOpenMaxByteCount < byteCount {
			break
		}
		alpn = append(alpn, id)
	}
	return alpn
}

// Decodes StreamOpen.metadata for a listener, whatever the bytes: each is either a TlsEdgeOpen that keeps §13.5's rules
// or an error, and only the error's nil-ness depends on them. Fields a newer tlsedge adds are kept, as protobuf keeps
// them, inside the same bound.
func ParseTlsEdgeOpen(metadata []byte) (*protocol.TlsEdgeOpen, error) {
	if TlsEdgeOpenMaxByteCount < len(metadata) {
		return nil, fmt.Errorf("%w: past its bound", ErrTlsEdgeOpen)
	}
	open := &protocol.TlsEdgeOpen{}
	if err := proto.Unmarshal(metadata, open); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTlsEdgeOpen, err)
	}
	clientIpByteCount := len(open.GetClientIp())
	if clientIpByteCount != tlsEdgeOpenClientIpv4ByteCount && clientIpByteCount != tlsEdgeOpenClientIpv6ByteCount {
		return nil, fmt.Errorf("%w: client_ip size", ErrTlsEdgeOpen)
	}
	if tlsEdgeOpenClientPortMax < open.GetClientPort() {
		return nil, fmt.Errorf("%w: client_port", ErrTlsEdgeOpen)
	}
	if !tlsDnsNameCanonical(open.GetServerName()) {
		return nil, fmt.Errorf("%w: server_name", ErrTlsEdgeOpen)
	}
	if len(open.GetConnectionId()) != tlsEdgeOpenConnectionIdByteCount {
		return nil, fmt.Errorf("%w: connection_id size", ErrTlsEdgeOpen)
	}
	return open, nil
}
