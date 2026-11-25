// §17.5's translator past the plain cases (bridge_translate.go; RFC 7915, owner decision 778): extension headers read
// past on the way out and a routing header with segments left refused; the ICMPv6 errors this host's stack sends an
// instance carried as ICMPv4 with their quoted packet translated back; and an IPv4 reply that came in fragments
// translated fragment by fragment, its first fragment's checksum adjusted so the whole datagram's holds, an ICMP fragment
// refused.

package device_test

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// Sends packet through the router and answers what the link carried for it.
func translateTestSend(t *testing.T, test *routeTest, packet []byte) []byte {
	t.Helper()
	link := test.awaitLink(routeTestTcp(routeTestSource, "100.80.1.4", 22))
	client := test.bridge.Route(packet)
	if client == nil {
		t.Fatal("the router passed the packet by")
	}
	before := len(link.Packets())
	for !client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, connect.MessagePoolCopy(packet), time.Second) {
		<-test.passes
	}
	packets := link.Packets()
	if len(packets) == before {
		t.Fatal("the link carried nothing")
	}
	return packets[len(packets)-1]
}

// A UDP datagram's transport from port 50000 to port, with payload and a checksum under source and destination's
// pseudo-header.
func translateTestUdp(source netip.Addr, destination netip.Addr, port uint16, payload []byte) []byte {
	transport := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], 50000)
	binary.BigEndian.PutUint16(transport[2:4], port)
	binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
	copy(transport[8:], payload)
	sum := translateTestSum(0, source.AsSlice())
	sum = translateTestSum(sum, destination.AsSlice())
	if source.Is4() {
		sum = translateTestSum(sum, []byte{0, 17, byte(len(transport) >> 8), byte(len(transport))})
	} else {
		sum = translateTestSum(sum, []byte{0, 0, byte(len(transport) >> 8), byte(len(transport)), 0, 0, 0, 17})
	}
	binary.BigEndian.PutUint16(transport[6:8], ^uint16(translateTestSum(sum, transport)))
	return transport
}

func TestBridgeTranslatorReadsPastExtensionHeaders(t *testing.T) {
	test := newTranslateTest(t)
	own := netip.MustParseAddr("fd12:3456:789a::1")
	instance := test.bridge.TranslatedAddress(netip.MustParseAddr("100.80.1.4"))
	udp := translateTestUdp(own, instance, 5353, []byte("through two options"))
	// hop-by-hop, then destination options, each 8 bytes of padding, then UDP
	extensions := []byte{60, 0, 1, 4, 0, 0, 0, 0, 17, 0, 1, 4, 0, 0, 0, 0}
	packet := routeTestIpv6Packet(0, own.String(), instance.String(), append(extensions, udp...))
	sent := translateTestSend(t, test, packet)
	if sent[9] != 17 || len(sent) != 20+len(udp) || !translateTestChecksumHolds(sent[12:16], sent[16:20], 17, sent[20:]) ||
		string(sent[28:]) != "through two options" {
		t.Fatalf("translated %x", sent)
	}
	// a routing header with a segment left names a hop past this one, and is refused
	routing := []byte{17, 0, 0, 1, 0, 0, 0, 0}
	refused := routeTestIpv6Packet(43, own.String(), instance.String(), append(routing, udp...))
	client := test.bridge.Route(refused)
	_, _, droppedBefore := test.bridge.TranslatorCounts()
	client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, connect.MessagePoolCopy(refused), time.Second)
	if _, _, dropped := test.bridge.TranslatorCounts(); dropped != droppedBefore+1 {
		t.Fatalf("a routing header with segments left: dropped %d", dropped-droppedBefore)
	}
}

func TestBridgeTranslatorCarriesTheHostsIcmpErrors(t *testing.T) {
	test := newTranslateTest(t)
	own := netip.MustParseAddr("fd12:3456:789a::1")
	instance := test.bridge.TranslatedAddress(netip.MustParseAddr("100.80.1.4"))
	// the instance's datagram to a port this host holds closed, as the host's stack quotes it
	quoted := routeTestIpv6Packet(17, instance.String(), own.String(), translateTestUdp(instance, own, 9, []byte("closed")))
	unreachable := append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, quoted...)
	packet := routeTestIpv6Packet(58, own.String(), instance.String(), unreachable)
	sent := translateTestSend(t, test, packet)
	if sent[9] != 1 || sent[20] != 3 || sent[21] != 3 || translateTestSum(0, sent[20:]) != 0xFFFF || len(sent) != len(packet)-40 {
		t.Fatalf("port unreachable as ICMPv4 %x", sent[:28])
	}
	inner := sent[28:]
	if inner[0] != 0x45 || inner[9] != 17 || netip.AddrFrom4([4]byte(inner[12:16])) != netip.MustParseAddr("100.80.1.4") ||
		netip.AddrFrom4([4]byte(inner[16:20])) != netip.MustParseAddr("100.80.0.46") || translateTestSum(0, inner[:20]) != 0xFFFF {
		t.Fatalf("the quote as IPv4 %x", inner[:20])
	}
	// Packet Too Big: fragmentation needed, its MTU 20 less
	tooBig := append([]byte{2, 0, 0, 0, 0, 0, 0x05, 0x00}, quoted...)
	sent = translateTestSend(t, test, routeTestIpv6Packet(58, own.String(), instance.String(), tooBig))
	if sent[20] != 3 || sent[21] != 4 || binary.BigEndian.Uint16(sent[26:28]) != 0x500-20 {
		t.Fatalf("Packet Too Big as ICMPv4 %x", sent[20:28])
	}
	// a parameter problem at the next header field points at the protocol field
	problem := append([]byte{4, 0, 0, 0, 0, 0, 0, 6}, quoted...)
	sent = translateTestSend(t, test, routeTestIpv6Packet(58, own.String(), instance.String(), problem))
	if sent[20] != 12 || sent[21] != 0 || sent[24] != 9 {
		t.Fatalf("parameter problem as ICMPv4 %x", sent[20:28])
	}
	// an error quoting a packet that was not the instance's to this host is refused
	foreign := routeTestIpv6Packet(17, "fd00::9", own.String(), translateTestUdp(netip.MustParseAddr("fd00::9"), own, 9, nil))
	_, _, droppedBefore := test.bridge.TranslatorCounts()
	stray := routeTestIpv6Packet(58, own.String(), instance.String(), append([]byte{1, 4, 0, 0, 0, 0, 0, 0}, foreign...))
	test.bridge.Route(stray).SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, connect.MessagePoolCopy(stray), time.Second)
	if _, _, dropped := test.bridge.TranslatorCounts(); dropped != droppedBefore+1 {
		t.Fatalf("an error quoting another's packet: dropped %d", dropped-droppedBefore)
	}
}

func TestBridgeTranslatorCarriesAFragmentedReply(t *testing.T) {
	test := newTranslateTest(t)
	own := netip.MustParseAddr("fd12:3456:789a::1")
	instance := test.bridge.TranslatedAddress(netip.MustParseAddr("100.80.1.4"))
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}
	datagram := translateTestUdp(netip.MustParseAddr("100.80.1.4"), netip.MustParseAddr("100.80.0.46"), 50000, payload)
	// two fragments: the first 32 bytes, with the UDP header, and the rest at offset 4 (32 bytes)
	fragment := func(part []byte, offset uint16, more bool) []byte {
		packet := routeTestPacket(17, "100.80.1.4", "100.80.0.46", part)
		binary.BigEndian.PutUint16(packet[4:6], 0x4242)
		flags := offset
		if more {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(packet[6:8], flags)
		binary.BigEndian.PutUint16(packet[10:12], ^uint16(translateTestSum(0, packet[:20])))
		return packet
	}
	reassembled := []byte{}
	for i, part := range [][]byte{fragment(datagram[:32], 0, true), fragment(datagram[32:], 4, false)} {
		out := make([]byte, len(part)+64)
		n, translated := test.bridge.TranslateReply(out, part)
		if !translated || n != len(part)-20+40+8 {
			t.Fatalf("fragment %d: %d, %t", i, n, translated)
		}
		back := out[:n]
		if back[6] != 44 || back[40] != 17 || binary.BigEndian.Uint32(back[44:48]) != 0x4242 ||
			binary.BigEndian.Uint16(back[42:44])>>3 != uint16(i*4) || (back[43]&1 == 1) != (i == 0) {
			t.Fatalf("fragment %d's headers %x", i, back[:48])
		}
		reassembled = append(reassembled, back[48:]...)
	}
	// the whole datagram's checksum holds under IPv6's pseudo-header
	if !translateTestChecksumHolds(instance.AsSlice(), own.AsSlice(), 17, reassembled) {
		t.Fatal("the reassembled datagram's checksum does not hold")
	}
	// an ICMP fragment is refused
	icmp := routeTestPacket(1, "100.80.1.4", "100.80.0.46", make([]byte, 16))
	binary.BigEndian.PutUint16(icmp[6:8], 0x2000)
	if n, translated := test.bridge.TranslateReply(make([]byte, 128), icmp); !translated || n != 0 {
		t.Fatalf("an ICMP fragment: %d, %t", n, translated)
	}
}
