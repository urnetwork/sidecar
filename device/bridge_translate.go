// §17.5's IPv6 to discovered instances (D-BRIDGE-26; owner decision 778): Apple documents Xcode's device connections
// as needing IPv6 and the overlay carries IPv4 alone, so `ur tun` gives each instance the advertising proxy registers
// an IPv6 address too: its IPv4 address in the low 32 bits of a /96 inside a ULA /48 the device draws at random once
// (RFC 4193, in RFC 6052's layout), which `ur tun` routes into the tun, the tun holding one other address of that /48
// as its own IPv6 source.
//
//	out      the router translates a packet to that /96 statelessly into IPv4 (RFC 7915 §5) before it classifies it,
//	         its destination the embedded address and its source <block>.0.46, the services address kept for it
//	         (§17.4), and routes the result as any packet
//	back     a reply to <block>.0.46 is translated back the same way (RFC 7915 §4), to the tun's own IPv6 address, so
//	         the host's own IPv4 flows never mix with translated ones; TranslateReply writes it for the tun
//	sizes    a translated packet leaves 20 bytes smaller, TCP's MSS keeps replies within the tun's MTU, and a UDP reply
//	         that would exceed the MTU once translated is dropped, which QUIC's path MTU discovery absorbs (RFC 9000
//	         §14); checksums are rewritten, and ICMP's echo and its errors translated with the packet they quote
//	headers  hop-by-hop, destination options and a routing header with no segments left are read past and not carried,
//	         and a fragment header becomes IPv4's fragment fields (RFC 7915 §5.1); on the way back an IPv4 fragment takes
//	         an IPv6 fragment header (§4.1), an ICMP fragment and a UDP fragment with no checksum refused (§4.5)
//	errors   the ICMPv6 errors this host's own stack sends an instance, unreachable, packet too big, time exceeded and
//	         parameter problem, go as ICMPv4 with the packet they quote translated back too (§5.2, §5.3)
//	never    every other IPv6 packet meets the router's rows as before; what does not translate is dropped and counted
//
// SetTranslator turns it on: ur tun calls it while it carries the network, once the platform holds the /48's own
// address and routes the /96 into the tun, over the /48 it drew once and keeps (cli's tun_translator.go). Counts are
// atomic, and nothing here takes a lock on the packet path.

package device

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// How many bytes a reply grows on its way back at most, IPv6's header past IPv4's and a fragment's header: what
// TranslateReply's out holds beyond the packet. A format fact, so a constant.
const BridgeTranslateReplyGrowth = bridgeIpv6HeaderByteCount - bridgeIpv4HeaderByteCount + bridgeFragmentByteCount

// The layout's identifiers inside the device's /48 (RFC 6052 §2.2's /96 form): the subnet holding the instances' /96,
// and the tun's own address in subnet 0.
const (
	bridgeTranslateInstanceSubnet = 1
	bridgeTranslateOwnInterfaceId = 1
	// the translator's address in each block, <block>.0.46 (§17.4)
	bridgeTranslateHost = 46
)

// IPv6's and ICMP's numbers the translator reads and writes (RFC 8200, RFC 4443, RFC 792).
const (
	bridgeIpv6HeaderByteCount = 40
	bridgeIpv6NextFragment    = 44
	bridgeProtocolIcmpv6      = 58
	bridgeFragmentByteCount   = 8
	bridgeIcmpv6EchoRequest   = 128
	bridgeIcmpv6EchoReply     = 129
	bridgeIcmpv6Unreachable   = 1
	bridgeIcmpv6TooBig        = 2
	bridgeIcmpv6TimeExceeded  = 3
	bridgeIcmpv4EchoRequest   = 8
	bridgeIcmpv4EchoReply     = 0
	bridgeIcmpv4Unreachable   = 3
	bridgeIcmpv4TimeExceeded  = 11
	// ICMPv4 unreachable codes (RFC 792, RFC 1812)
	bridgeIcmpv4HostUnreachable  = 1
	bridgeIcmpv4PortUnreachable  = 3
	bridgeIcmpv4FragmentNeeded   = 4
	bridgeIcmpv4AdminProhibited  = 13
	bridgeIcmpv6NoRoute          = 0
	bridgeIcmpv6AdminProhibited  = 1
	bridgeIcmpv6AddressUnreached = 3
	bridgeIcmpv6PortUnreachable  = 4
	// the extension headers the translator reads past, and the ICMP types and codes its errors take (RFC 8200 §4,
	// RFC 4443, RFC 792, RFC 1812)
	bridgeIpv6NextHopByHop           = 0
	bridgeIpv6NextRouting            = 43
	bridgeIpv6NextDestinationOptions = 60
	bridgeIcmpv6BeyondScope          = 2
	bridgeIcmpv6ParameterProblem     = 4
	bridgeIcmpv4ProtocolUnreachable  = 2
	bridgeIcmpv4HostAdminProhibited  = 10
	bridgeIcmpv4ParameterProblem     = 12
)

// A translator's addresses: the device's /48, the instances' /96 and the tun's own address.
type bridgeTranslator struct {
	ula      netip.Prefix
	instance [12]byte
	own      netip.Addr
	mtu      int
}

// The translator's counts.
type bridgeTranslateCounts struct {
	outCount     atomic.Uint64
	backCount    atomic.Uint64
	droppedCount atomic.Uint64
	// draws IPv4 identifications for translated packets that may fragment
	identification atomic.Uint32
}

// The ULA translator a device would draw: a random /48 of fd00::/8 (RFC 4193 §3.2's random global id).
func NewBridgeTranslatorPrefix() (netip.Prefix, error) {
	var octets [16]byte
	octets[0] = 0xFD
	if _, err := rand.Read(octets[1:6]); err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(netip.AddrFrom16(octets), 48), nil
}

// Errors SetTranslator refuses with.
var ErrBridgeTranslatorInvalid = errors.New("bridge translator invalid")

// Turns the translator on over ula, the device's /48 of fd00::/8, for a tun of mtu; an invalid ula turns it off.
func (self *Bridge) SetTranslator(ula netip.Prefix, mtu int) error {
	if !ula.IsValid() {
		self.translator.Store(nil)
		return nil
	}
	ula = ula.Masked()
	octets := ula.Addr().As16()
	if !ula.Addr().Is6() || ula.Addr().Is4In6() || ula.Bits() != 48 || octets[0] != 0xFD || mtu < self.settings.TranslatorMinMtu {
		return ErrBridgeTranslatorInvalid
	}
	translator := &bridgeTranslator{ula: ula, mtu: mtu}
	copy(translator.instance[:6], octets[:6])
	binary.BigEndian.PutUint16(translator.instance[6:8], bridgeTranslateInstanceSubnet)
	own := octets
	own[15] = bridgeTranslateOwnInterfaceId
	translator.own = netip.AddrFrom16(own)
	self.translator.Store(translator)
	return nil
}

// The /96 the instances' addresses sit in and the tun's own address, which ur tun routes and holds; invalid while the
// translator is off.
func (self *Bridge) TranslatorAddresses() (netip.Prefix, netip.Addr) {
	translator := self.translator.Load()
	if translator == nil {
		return netip.Prefix{}, netip.Addr{}
	}
	var octets [16]byte
	copy(octets[:12], translator.instance[:])
	return netip.PrefixFrom(netip.AddrFrom16(octets), 96), translator.own
}

// An instance's IPv6 address for its IPv4 one, invalid while the translator is off or for no IPv4 address.
func (self *Bridge) TranslatedAddress(address netip.Addr) netip.Addr {
	translator := self.translator.Load()
	address = address.Unmap()
	if translator == nil || !address.Is4() {
		return netip.Addr{}
	}
	var octets [16]byte
	copy(octets[:12], translator.instance[:])
	ipv4 := address.As4()
	copy(octets[12:], ipv4[:])
	return netip.AddrFrom16(octets)
}

// Packets translated out and back, and dropped.
func (self *Bridge) TranslatorCounts() (outCount uint64, backCount uint64, droppedCount uint64) {
	return self.translateCounts.outCount.Load(), self.translateCounts.backCount.Load(), self.translateCounts.droppedCount.Load()
}

// The translator's IPv4 source, <block>.0.46 of the block in force; invalid before a block.
func (self *Bridge) translatorSource() netip.Addr {
	state := self.routeState.Load()
	if state == nil || len(state.resolverAddrs) == 0 {
		return netip.Addr{}
	}
	value := state.resolverAddrs[0]&^0xFFFF | bridgeTranslateHost
	return bridgeDiscoveryAddrOfValue(value)
}

// An IPv4 value's address.
func bridgeDiscoveryAddrOfValue(value uint32) netip.Addr {
	var octets [4]byte
	binary.BigEndian.PutUint32(octets[:], value)
	return netip.AddrFrom4(octets)
}

// Whether packet is IPv6 to the instances' /96.
func (self *bridgeTranslator) outbound(packet []byte) bool {
	return bridgeIpv6HeaderByteCount <= len(packet) && packet[0]>>4 == 6 && [12]byte(packet[24:36]) == self.instance
}

// What Route hands a packet to the instances' /96: translates it into IPv4 and routes the result as any packet.
type bridgeTranslateClient struct {
	bridge *Bridge
}

var _ connect.UserNatClient = (*bridgeTranslateClient)(nil)

// Takes packet when the translated packet's route takes it; returns false, leaving packet the caller's, where that
// route refuses it. A packet that does not translate, or translates to the default route, is dropped and counted.
func (self *bridgeTranslateClient) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	bridge := self.bridge
	translator := bridge.translator.Load()
	ipv4Source := bridge.translatorSource()
	if translator == nil || !ipv4Source.IsValid() {
		bridge.translateCounts.droppedCount.Add(1)
		connect.MessagePoolReturn(packet)
		return true
	}
	translated := connect.MessagePoolGet(len(packet))
	n, ok := bridgeTranslateOut(translated, packet, translator, ipv4Source, bridge.settings.TranslatorFragmentableByteCount, &bridge.translateCounts)
	if !ok {
		connect.MessagePoolReturn(translated)
		bridge.translateCounts.droppedCount.Add(1)
		connect.MessagePoolReturn(packet)
		return true
	}
	translated = translated[:n]
	client := bridge.Route(translated)
	if client == nil {
		// no default route serves a translated packet: its instance sits in the overlay
		connect.MessagePoolReturn(translated)
		bridge.translateCounts.droppedCount.Add(1)
		connect.MessagePoolReturn(packet)
		return true
	}
	if !client.SendPacket(source, provideMode, translated, timeout) {
		connect.MessagePoolReturn(translated)
		return false
	}
	bridge.translateCounts.outCount.Add(1)
	connect.MessagePoolReturn(packet)
	return true
}

func (self *bridgeTranslateClient) Close() {}

func (self *bridgeTranslateClient) Shuffle() {}

func (self *bridgeTranslateClient) SecurityPolicyStats(reset bool) connect.SecurityPolicyStats {
	return connect.SecurityPolicyStats{}
}

func (self *bridgeTranslateClient) SetLocalSecurityBypass(localSecurityBypass bool) {}

// Writes into out, which holds at least len(packet) + BridgeTranslateReplyGrowth bytes, packet translated back to IPv6
// when it is an IPv4 reply to <block>.0.46, and answers its length and true; 0 and true for a reply that does not
// translate, which the caller drops; false for any other packet, which the caller writes as it is.
func (self *Bridge) TranslateReply(out []byte, packet []byte) (int, bool) {
	translator := self.translator.Load()
	if translator == nil || len(packet) < bridgeIpv4HeaderByteCount || packet[0]>>4 != 4 {
		return 0, false
	}
	source := self.translatorSource()
	if !source.IsValid() || netip.AddrFrom4([4]byte(packet[16:20])) != source {
		return 0, false
	}
	n, ok := bridgeTranslateBack(out, packet, translator)
	if !ok {
		self.translateCounts.droppedCount.Add(1)
		return 0, true
	}
	self.translateCounts.backCount.Add(1)
	return n, true
}

// IPv6's pseudo-header sum for a transport segment of length (RFC 8200 §8.1).
func bridgeIpv6PseudoSum(source []byte, destination []byte, nextHeader byte, length int) uint32 {
	sum := bridgeChecksumAdd(0, source)
	sum = bridgeChecksumAdd(sum, destination)
	var tail [8]byte
	binary.BigEndian.PutUint32(tail[0:4], uint32(length))
	tail[7] = nextHeader
	return bridgeChecksumAdd(sum, tail[:])
}

// IPv4's pseudo-header sum for a transport segment of length.
func bridgeIpv4PseudoSum(source []byte, destination []byte, ipProtocol byte, length int) uint32 {
	sum := bridgeChecksumAdd(0, source)
	sum = bridgeChecksumAdd(sum, destination)
	var tail [4]byte
	tail[1] = ipProtocol
	binary.BigEndian.PutUint16(tail[2:4], uint16(length))
	return bridgeChecksumAdd(sum, tail[:])
}

// Rewrites a TCP or UDP segment's checksum under a new pseudo-header sum.
func bridgeTranslateTransportChecksum(segment []byte, ipProtocol byte, pseudo uint32) bool {
	switch ipProtocol {
	case bridgeProtocolTcp:
		if len(segment) < bridgeTcpHeaderByteCount {
			return false
		}
		binary.BigEndian.PutUint16(segment[16:18], 0)
		binary.BigEndian.PutUint16(segment[16:18], bridgeChecksumFinish(bridgeChecksumAdd(pseudo, segment)))
	case bridgeProtocolUdp:
		if len(segment) < 8 {
			return false
		}
		binary.BigEndian.PutUint16(segment[6:8], 0)
		checksum := bridgeChecksumFinish(bridgeChecksumAdd(pseudo, segment))
		if checksum == 0 {
			checksum = 0xFFFF
		}
		binary.BigEndian.PutUint16(segment[6:8], checksum)
	}
	return true
}

// Translates an IPv6 packet into an IPv4 one in out from source (RFC 7915 §5): its length and true, or false for one
// it does not translate. out holds at least len(packet) bytes. Hop-by-hop, destination options and a routing header
// with no segments left are read past and not carried (§5.1), a routing header with segments left refused; a fragment
// header becomes the IPv4 header's fragment fields; ICMPv6 echo and errors become ICMPv4 (§5.2). A translated packet of
// at most fragmentableByteCount takes an identification and may fragment downstream; a larger one goes with DF set.
func bridgeTranslateOut(out []byte, packet []byte, translator *bridgeTranslator, source netip.Addr, fragmentableByteCount int,
	counts *bridgeTranslateCounts) (int, bool) {
	payloadByteCount := int(binary.BigEndian.Uint16(packet[4:6]))
	end := bridgeIpv6HeaderByteCount + payloadByteCount
	if len(packet) < end || packet[7] <= 1 {
		return 0, false
	}
	nextHeader := packet[6]
	at := bridgeIpv6HeaderByteCount
	fragmentOffset, moreFragments, identification := uint16(0), false, uint32(0)
	fragmented := false
walk:
	for {
		switch nextHeader {
		case bridgeIpv6NextHopByHop, bridgeIpv6NextDestinationOptions, bridgeIpv6NextRouting:
			if end < at+8 {
				return 0, false
			}
			length := (int(packet[at+1]) + 1) * 8
			// a routing header with segments left names a hop past this one (RFC 7915 §5.1)
			if end < at+length || (nextHeader == bridgeIpv6NextRouting && packet[at+3] != 0) {
				return 0, false
			}
			nextHeader = packet[at]
			at += length
		case bridgeIpv6NextFragment:
			if fragmented || end < at+bridgeFragmentByteCount {
				return 0, false
			}
			fragmented = true
			nextHeader = packet[at]
			fragmentOffset = binary.BigEndian.Uint16(packet[at+2:at+4]) >> 3
			moreFragments = packet[at+3]&1 != 0
			identification = binary.BigEndian.Uint32(packet[at+4 : at+8])
			at += bridgeFragmentByteCount
		default:
			break walk
		}
	}
	payload := packet[at:end]
	ipProtocol := nextHeader
	switch nextHeader {
	case bridgeProtocolTcp, bridgeProtocolUdp:
	case bridgeProtocolIcmpv6:
		ipProtocol = bridgeProtocolIcmp
	default:
		return 0, false
	}
	if len(out) < bridgeIpv4HeaderByteCount+len(payload) {
		return 0, false
	}
	header := out[:bridgeIpv4HeaderByteCount]
	clear(header)
	sourceOctets := source.As4()
	copy(header[12:16], sourceOctets[:])
	copy(header[16:20], packet[36:40])
	segment := out[bridgeIpv4HeaderByteCount:]
	segmentByteCount := len(payload)
	switch {
	case ipProtocol == bridgeProtocolIcmp:
		// ICMP is never fragmented here: its checksum covers the whole message
		if fragmented {
			return 0, false
		}
		n, ok := bridgeTranslateIcmpOut(segment, payload, translator, source)
		if !ok {
			return 0, false
		}
		segmentByteCount = n
	case fragmented && fragmentOffset != 0:
		// a later fragment carries no transport header
		copy(segment, payload)
	case fragmented && moreFragments:
		// a first fragment's checksum covers every fragment: adjust it by the pseudo-headers' difference
		copy(segment, payload)
		if !bridgeTranslateChecksumDelta(segment[:segmentByteCount], ipProtocol,
			bridgeIpv6PseudoSum(packet[8:24], packet[24:40], nextHeader, 0),
			bridgeIpv4PseudoSum(header[12:16], header[16:20], ipProtocol, 0)) {
			return 0, false
		}
	default:
		copy(segment, payload)
		if !bridgeTranslateTransportChecksum(segment[:segmentByteCount], ipProtocol,
			bridgeIpv4PseudoSum(header[12:16], header[16:20], ipProtocol, segmentByteCount)) {
			return 0, false
		}
	}
	totalByteCount := bridgeIpv4HeaderByteCount + segmentByteCount
	if 0xFFFF < totalByteCount {
		return 0, false
	}
	header[0] = 0x45
	header[1] = packet[0]<<4 | packet[1]>>4
	binary.BigEndian.PutUint16(header[2:4], uint16(totalByteCount))
	switch {
	case fragmented:
		binary.BigEndian.PutUint16(header[4:6], uint16(identification))
		flags := fragmentOffset & 0x1FFF
		if moreFragments {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(header[6:8], flags)
	case totalByteCount <= fragmentableByteCount:
		// RFC 7915 §5.1: a small packet may fragment downstream, so it takes an identification
		binary.BigEndian.PutUint16(header[4:6], uint16(counts.identification.Add(1)))
	default:
		binary.BigEndian.PutUint16(header[6:8], 0x4000)
	}
	header[8] = packet[7] - 1
	header[9] = ipProtocol
	binary.BigEndian.PutUint16(header[10:12], bridgeChecksumFinish(bridgeChecksumAdd(0, header)))
	return totalByteCount, true
}

// Adjusts a first fragment's TCP or UDP checksum by the difference of two pseudo-header sums, both taken with a zero
// length, since the datagram's length is unchanged (RFC 1624).
func bridgeTranslateChecksumDelta(segment []byte, ipProtocol byte, oldSum uint32, newSum uint32) bool {
	at := 16
	if ipProtocol == bridgeProtocolUdp {
		at = 6
	}
	if len(segment) < at+2 {
		return false
	}
	checksum := binary.BigEndian.Uint16(segment[at : at+2])
	if ipProtocol == bridgeProtocolUdp && checksum == 0 {
		return false
	}
	// RFC 1624's HC' = ~(~HC + ~m + m'), m and m' the old and new pseudo-headers' folded sums
	sum := uint32(^checksum) + uint32(bridgeChecksumFinish(oldSum)) + uint32(^bridgeChecksumFinish(newSum))
	updated := bridgeChecksumFinish(sum)
	if ipProtocol == bridgeProtocolUdp && updated == 0 {
		updated = 0xFFFF
	}
	binary.BigEndian.PutUint16(segment[at:at+2], updated)
	return true
}

// Writes into out an ICMPv6 message translated into ICMPv4 (RFC 7915 §5.2), answering its length: echo, and the errors
// this host's own stack sends an instance, whose quoted packet, one the instance sent to the tun's own address, it
// translates too (§5.3), the message 20 bytes shorter for the quote's smaller header. ICMPv4 carries no pseudo-header,
// so its checksum is the message's alone. out holds at least len(message) bytes.
func bridgeTranslateIcmpOut(out []byte, message []byte, translator *bridgeTranslator, source netip.Addr) (int, bool) {
	if len(message) < 8 {
		return 0, false
	}
	icmpType, code := message[0], message[1]
	var n int
	switch icmpType {
	case bridgeIcmpv6EchoRequest, bridgeIcmpv6EchoReply:
		n = copy(out, message)
		out[0] = bridgeIcmpv4EchoRequest
		if icmpType == bridgeIcmpv6EchoReply {
			out[0] = bridgeIcmpv4EchoReply
		}
		out[1] = 0
	case bridgeIcmpv6Unreachable, bridgeIcmpv6TooBig, bridgeIcmpv6TimeExceeded, bridgeIcmpv6ParameterProblem:
		copy(out[:8], message[:8])
		clear(out[4:8])
		switch icmpType {
		case bridgeIcmpv6Unreachable:
			out[0] = bridgeIcmpv4Unreachable
			switch code {
			case bridgeIcmpv6NoRoute, bridgeIcmpv6BeyondScope, bridgeIcmpv6AddressUnreached:
				out[1] = bridgeIcmpv4HostUnreachable
			case bridgeIcmpv6AdminProhibited:
				out[1] = bridgeIcmpv4HostAdminProhibited
			case bridgeIcmpv6PortUnreachable:
				out[1] = bridgeIcmpv4PortUnreachable
			default:
				return 0, false
			}
		case bridgeIcmpv6TooBig:
			// the next hop's MTU less the 20 bytes IPv4's header saves (RFC 7915 §5.2)
			mtu := binary.BigEndian.Uint32(message[4:8])
			if mtu <= bridgeIpv6HeaderByteCount-bridgeIpv4HeaderByteCount {
				return 0, false
			}
			out[0], out[1] = bridgeIcmpv4Unreachable, bridgeIcmpv4FragmentNeeded
			binary.BigEndian.PutUint16(out[6:8], uint16(min(mtu-20, 0xFFFF)))
		case bridgeIcmpv6TimeExceeded:
			out[0], out[1] = bridgeIcmpv4TimeExceeded, code
		case bridgeIcmpv6ParameterProblem:
			switch code {
			case 0:
				pointer, ok := bridgeTranslateParameterPointer(binary.BigEndian.Uint32(message[4:8]))
				if !ok {
					return 0, false
				}
				out[0], out[1], out[4] = bridgeIcmpv4ParameterProblem, 0, pointer
			case 1:
				// an unrecognized next header: the protocol is unreachable
				out[0], out[1] = bridgeIcmpv4Unreachable, bridgeIcmpv4ProtocolUnreachable
			default:
				return 0, false
			}
		}
		quoted, ok := bridgeTranslateQuotedOut(out[8:], message[8:], translator, source)
		if !ok {
			return 0, false
		}
		n = 8 + quoted
	default:
		return 0, false
	}
	binary.BigEndian.PutUint16(out[2:4], 0)
	binary.BigEndian.PutUint16(out[2:4], bridgeChecksumFinish(bridgeChecksumAdd(0, out[:n])))
	return n, true
}

// The pointer of an IPv4 Parameter Problem for an IPv6 one's (RFC 7915 §5.2, figure 6), false for a field IPv4's
// header has none of.
func bridgeTranslateParameterPointer(pointer uint32) (byte, bool) {
	switch {
	case pointer == 0, pointer == 1:
		return byte(pointer), true
	case pointer == 4, pointer == 5:
		return 2, true
	case pointer == 6:
		return 9, true
	case pointer == 7:
		return 8, true
	case 8 <= pointer && pointer <= 23:
		return 12, true
	case 24 <= pointer && pointer <= 39:
		return 16, true
	}
	return 0, false
}

// Writes into out the IPv6 packet an ICMPv6 error quotes, one an instance sent to the tun's own address, as the IPv4
// packet it was before its translation (RFC 7915 §5.3): from the instance's embedded address to source, the IPv4 header
// whole, the quoted payload as it came but an ICMPv6 echo's type, which takes ICMPv4's. Answers its length: the quote's
// less 20. A quote from elsewhere, or with an extension header, is refused.
func bridgeTranslateQuotedOut(out []byte, quoted []byte, translator *bridgeTranslator, source netip.Addr) (int, bool) {
	if len(quoted) < bridgeIpv6HeaderByteCount || quoted[0]>>4 != 6 || [12]byte(quoted[8:20]) != translator.instance ||
		netip.AddrFrom16([16]byte(quoted[24:40])) != translator.own {
		return 0, false
	}
	nextHeader := quoted[6]
	switch nextHeader {
	case bridgeProtocolTcp, bridgeProtocolUdp:
	case bridgeProtocolIcmpv6:
		nextHeader = bridgeProtocolIcmp
	default:
		return 0, false
	}
	inner := out[:bridgeIpv4HeaderByteCount]
	clear(inner)
	inner[0] = 0x45
	inner[1] = quoted[0]<<4 | quoted[1]>>4
	binary.BigEndian.PutUint16(inner[2:4], uint16(min(0xFFFF, bridgeIpv4HeaderByteCount+int(binary.BigEndian.Uint16(quoted[4:6])))))
	inner[8] = quoted[7]
	inner[9] = nextHeader
	// the instance's IPv4 address, the low 32 bits of its translated source
	copy(inner[12:16], quoted[20:24])
	sourceOctets := source.As4()
	copy(inner[16:20], sourceOctets[:])
	binary.BigEndian.PutUint16(inner[10:12], bridgeChecksumFinish(bridgeChecksumAdd(0, inner)))
	n := bridgeIpv4HeaderByteCount + copy(out[bridgeIpv4HeaderByteCount:], quoted[bridgeIpv6HeaderByteCount:])
	if nextHeader == bridgeProtocolIcmp && bridgeIpv4HeaderByteCount < n {
		switch out[bridgeIpv4HeaderByteCount] {
		case bridgeIcmpv6EchoRequest:
			out[bridgeIpv4HeaderByteCount] = bridgeIcmpv4EchoRequest
		case bridgeIcmpv6EchoReply:
			out[bridgeIpv4HeaderByteCount] = bridgeIcmpv4EchoReply
		}
	}
	return n, true
}

// Translates an IPv4 reply into IPv6 in out, to the tun's own address from the instance's (RFC 7915 §4): its length
// and true, or false for one it does not translate or that would pass the tun's MTU. A fragment takes an IPv6 fragment
// header carrying its offset, its more-fragments flag and its identification (§4.1), the first one's transport checksum
// adjusted by the pseudo-headers' difference; an ICMP fragment, whose checksum would need the whole message under
// ICMPv6's pseudo-header, and a UDP fragment with no checksum are refused (§4.5).
func bridgeTranslateBack(out []byte, packet []byte, translator *bridgeTranslator) (int, bool) {
	headerByteCount := int(packet[0]&0x0F) * 4
	totalByteCount := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerByteCount < bridgeIpv4HeaderByteCount || totalByteCount < headerByteCount || len(packet) < totalByteCount ||
		packet[8] <= 1 {
		return 0, false
	}
	fragmentField := binary.BigEndian.Uint16(packet[6:8])
	fragmentOffset, moreFragments := fragmentField&0x1FFF, fragmentField&0x2000 != 0
	fragmented := fragmentOffset != 0 || moreFragments
	nextHeader := packet[9]
	switch nextHeader {
	case bridgeProtocolTcp, bridgeProtocolUdp:
	case bridgeProtocolIcmp:
		if fragmented {
			return 0, false
		}
		nextHeader = bridgeProtocolIcmpv6
	default:
		return 0, false
	}
	payload := packet[headerByteCount:totalByteCount]
	headersByteCount := bridgeIpv6HeaderByteCount
	if fragmented {
		headersByteCount += bridgeFragmentByteCount
	}
	outByteCount := headersByteCount + len(payload)
	if translator.mtu < outByteCount || len(out) < outByteCount {
		return 0, false
	}
	header := out[:bridgeIpv6HeaderByteCount]
	clear(header)
	header[0] = 0x60 | packet[1]>>4
	header[1] = packet[1] << 4
	binary.BigEndian.PutUint16(header[4:6], uint16(outByteCount-bridgeIpv6HeaderByteCount))
	header[6] = nextHeader
	header[7] = packet[8] - 1
	copy(header[8:20], translator.instance[:])
	copy(header[20:24], packet[12:16])
	own := translator.own.As16()
	copy(header[24:40], own[:])
	if fragmented {
		fragment := out[bridgeIpv6HeaderByteCount:headersByteCount]
		header[6] = bridgeIpv6NextFragment
		fragment[0] = nextHeader
		fragment[1] = 0
		flags := fragmentOffset << 3
		if moreFragments {
			flags |= 1
		}
		binary.BigEndian.PutUint16(fragment[2:4], flags)
		binary.BigEndian.PutUint32(fragment[4:8], uint32(binary.BigEndian.Uint16(packet[4:6])))
	}
	segment := out[headersByteCount:outByteCount]
	copy(segment, payload)
	switch {
	case nextHeader == bridgeProtocolIcmpv6:
		if !bridgeTranslateIcmpBack(segment, header, translator) {
			return 0, false
		}
	case fragmented && fragmentOffset != 0:
		// a later fragment carries no transport header
	case fragmented:
		if !bridgeTranslateChecksumDelta(segment, nextHeader, bridgeIpv4PseudoSum(packet[12:16], packet[16:20], nextHeader, 0),
			bridgeIpv6PseudoSum(header[8:24], header[24:40], nextHeader, 0)) {
			return 0, false
		}
	default:
		if !bridgeTranslateTransportChecksum(segment, nextHeader, bridgeIpv6PseudoSum(header[8:24], header[24:40], nextHeader, len(segment))) {
			return 0, false
		}
	}
	return outByteCount, true
}

// Translates an ICMPv4 reply in place into ICMPv6 (RFC 7915 §4.2): echo replies, and the errors an instance's path may
// send, whose quoted packet, one this host sent from <block>.0.46, it translates back too.
func bridgeTranslateIcmpBack(segment []byte, header []byte, translator *bridgeTranslator) bool {
	if len(segment) < 8 {
		return false
	}
	switch segment[0] {
	case bridgeIcmpv4EchoReply:
		segment[0] = bridgeIcmpv6EchoReply
		segment[1] = 0
	case bridgeIcmpv4EchoRequest:
		segment[0] = bridgeIcmpv6EchoRequest
		segment[1] = 0
	case bridgeIcmpv4Unreachable:
		switch segment[1] {
		case 0, bridgeIcmpv4HostUnreachable:
			segment[0], segment[1] = bridgeIcmpv6Unreachable, bridgeIcmpv6NoRoute
		case bridgeIcmpv4PortUnreachable:
			segment[0], segment[1] = bridgeIcmpv6Unreachable, bridgeIcmpv6PortUnreachable
		case bridgeIcmpv4FragmentNeeded:
			// Packet Too Big, its MTU 20 more for the larger header (RFC 7915 §4.2)
			mtu := uint32(binary.BigEndian.Uint16(segment[6:8])) + 20
			segment[0], segment[1] = bridgeIcmpv6TooBig, 0
			binary.BigEndian.PutUint32(segment[4:8], max(mtu, 1280))
		case 9, 10, bridgeIcmpv4AdminProhibited:
			segment[0], segment[1] = bridgeIcmpv6Unreachable, bridgeIcmpv6AdminProhibited
		default:
			return false
		}
		if !bridgeTranslateQuotedBack(segment, translator) {
			return false
		}
	case bridgeIcmpv4TimeExceeded:
		segment[0] = bridgeIcmpv6TimeExceeded
		if !bridgeTranslateQuotedBack(segment, translator) {
			return false
		}
	default:
		return false
	}
	binary.BigEndian.PutUint16(segment[2:4], 0)
	sum := bridgeIpv6PseudoSum(header[8:24], header[24:40], bridgeProtocolIcmpv6, len(segment))
	binary.BigEndian.PutUint16(segment[2:4], bridgeChecksumFinish(bridgeChecksumAdd(sum, segment)))
	return true
}

// The packet an ICMPv4 error quotes, an IPv4 header this host's translator wrote and the start of its payload,
// rewritten in place as the IPv6 one the host sent; the message keeps its length, so a quote with IPv4 options, which
// the translator never writes, is refused, and the quoted payload is cut by the 20 bytes the larger header takes.
func bridgeTranslateQuotedBack(segment []byte, translator *bridgeTranslator) bool {
	quoted := segment[8:]
	if len(quoted) < bridgeIpv4HeaderByteCount || quoted[0] != 0x45 {
		return false
	}
	inner := make([]byte, bridgeIpv6HeaderByteCount+len(quoted)-bridgeIpv4HeaderByteCount)
	inner[0] = 0x60 | quoted[1]>>4
	inner[1] = quoted[1] << 4
	binary.BigEndian.PutUint16(inner[4:6], uint16(max(0, int(binary.BigEndian.Uint16(quoted[2:4]))-bridgeIpv4HeaderByteCount)))
	inner[6] = quoted[9]
	if inner[6] == bridgeProtocolIcmp {
		inner[6] = bridgeProtocolIcmpv6
	}
	inner[7] = quoted[8]
	own := translator.own.As16()
	copy(inner[8:24], own[:])
	copy(inner[24:36], translator.instance[:])
	copy(inner[36:40], quoted[16:20])
	copy(inner[bridgeIpv6HeaderByteCount:], quoted[bridgeIpv4HeaderByteCount:])
	// the message keeps its length: the quote loses its last 20 bytes, a truncation RFC 4443 §2.4 allows
	copy(quoted, inner[:len(quoted)])
	return true
}
