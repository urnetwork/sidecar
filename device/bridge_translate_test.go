// §17.5's IPv6 translator (bridge_translate.go; D-BRIDGE-26, owner decision 778), §22.5's §17 row from M6: RFC 7915's
// cases for TCP, UDP and ICMP echo out and back, checksums rewritten and verified against the pseudo-headers, a reply
// that would pass the tun's MTU dropped, an ICMPv4 fragmentation-needed answered as Packet Too Big 20 bytes larger, a
// packet to <block>.0.46 from no instance passed by, and every other IPv6 packet still meeting the router's rows.

package device_test

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
)

// The device's /48, synthetic.
var translateTestUla = netip.MustParsePrefix("fd12:3456:789a::/48")

// The one's complement sum of data as 16-bit words, folded.
func translateTestSum(sum uint32, data []byte) uint32 {
	for 1 < len(data) {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if 0 < len(data) {
		sum += uint32(data[0]) << 8
	}
	for 0xFFFF < sum {
		sum = sum&0xFFFF + sum>>16
	}
	return sum
}

// Whether a segment's checksum holds under an IPv6 or IPv4 pseudo-header, by summing to 0xFFFF.
func translateTestChecksumHolds(source []byte, destination []byte, ipProtocol byte, segment []byte) bool {
	sum := translateTestSum(0, source)
	sum = translateTestSum(sum, destination)
	if len(source) == 16 {
		var tail [8]byte
		binary.BigEndian.PutUint32(tail[0:4], uint32(len(segment)))
		tail[7] = ipProtocol
		sum = translateTestSum(sum, tail[:])
	} else {
		sum = translateTestSum(sum, []byte{0, ipProtocol, byte(len(segment) >> 8), byte(len(segment))})
	}
	return translateTestSum(sum, segment) == 0xFFFF
}

// An IPv6 TCP SYN from the tun's own address to address's instance, with a valid checksum.
func translateTestIpv6Syn(t *testing.T, source netip.Addr, destination netip.Addr, port uint16) []byte {
	t.Helper()
	transport := make([]byte, 24)
	binary.BigEndian.PutUint16(transport[0:2], 50000)
	binary.BigEndian.PutUint16(transport[2:4], port)
	binary.BigEndian.PutUint32(transport[4:8], 1000)
	transport[12] = 0x60
	transport[13] = 0x02
	binary.BigEndian.PutUint16(transport[14:16], 65535)
	// an MSS option of 1420, which the translator leaves as it is
	copy(transport[20:24], []byte{2, 4, 0x05, 0x8C})
	packet := routeTestIpv6Packet(6, source.String(), destination.String(), transport)
	sum := translateTestSum(0, packet[8:40])
	sum = translateTestSum(sum, []byte{0, 0, 0, byte(len(transport)), 0, 0, 0, 6})
	binary.BigEndian.PutUint16(packet[56:58], ^uint16(translateTestSum(sum, transport)))
	if !translateTestChecksumHolds(packet[8:24], packet[24:40], 6, packet[40:]) {
		t.Fatal("the test's own checksum does not hold")
	}
	return packet
}

// A route test whose bridge translates over translateTestUla, for a 1500 B tun.
func newTranslateTest(t *testing.T) *routeTest {
	t.Helper()
	test := newRouteTest(t, routeTestFixture(), nil)
	if err := test.bridge.SetTranslator(translateTestUla, 1500); err != nil {
		t.Fatal(err)
	}
	return test
}

// The translator's addresses: the /96 in subnet 1 of the /48 and the tun's own ::1; an instance's IPv6 address embeds
// its IPv4 one; a prefix outside fd00::/8 or not a /48 is refused.
func TestBridgeTranslatorAddresses(t *testing.T) {
	test := newTranslateTest(t)
	instances, own := test.bridge.TranslatorAddresses()
	if instances != netip.MustParsePrefix("fd12:3456:789a:1::/96") || own != netip.MustParseAddr("fd12:3456:789a::1") {
		t.Fatalf("instances %v, own %v", instances, own)
	}
	if got := test.bridge.TranslatedAddress(netip.MustParseAddr("100.80.1.4")); got != netip.MustParseAddr("fd12:3456:789a:1::6450:104") {
		t.Fatalf("translated %v", got)
	}
	for _, bad := range []netip.Prefix{netip.MustParsePrefix("2001:db8::/48"), netip.MustParsePrefix("fd12:3456::/32")} {
		if err := test.bridge.SetTranslator(bad, 1500); err == nil {
			t.Errorf("%v was taken", bad)
		}
	}
	if err := test.bridge.SetTranslator(netip.Prefix{}, 0); err != nil || test.bridge.TranslatedAddress(netip.MustParseAddr("100.80.1.4")).IsValid() {
		t.Fatalf("the translator did not turn off: %v", err)
	}
	prefix, err := device.NewBridgeTranslatorPrefix()
	if err != nil || prefix.Bits() != 48 || prefix.Addr().As16()[0] != 0xFD {
		t.Fatalf("a drawn prefix %v, %v", prefix, err)
	}
}

// A SYN to an instance's IPv6 address leaves as IPv4 from <block>.0.46 to the embedded address over the link the
// router picks, its checksums whole; the SYN-ACK back to <block>.0.46 enters the tun as IPv6 from the instance's
// address to the tun's own, its checksum whole.
func TestBridgeTranslatorCarriesTcpBothWays(t *testing.T) {
	test := newTranslateTest(t)
	own := netip.MustParseAddr("fd12:3456:789a::1")
	instance := test.bridge.TranslatedAddress(netip.MustParseAddr("100.80.1.4"))
	syn := translateTestIpv6Syn(t, own, instance, 62078)
	client := test.bridge.Route(syn)
	if client == nil {
		t.Fatal("the router passed the instance's IPv6 by")
	}
	// the first packet asks for the link's build, and is refused while it builds
	link := test.awaitLink(routeTestTcp(routeTestSource, "100.80.1.4", 62078))
	for !client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, connect.MessagePoolCopy(syn), time.Second) {
		<-test.passes
	}
	packets := link.Packets()
	sent := packets[len(packets)-1]
	if sent[0] != 0x45 || netip.AddrFrom4([4]byte(sent[12:16])) != netip.MustParseAddr("100.80.0.46") ||
		netip.AddrFrom4([4]byte(sent[16:20])) != netip.MustParseAddr("100.80.1.4") || sent[9] != 6 || sent[8] != 63 {
		t.Fatalf("the translated header %x", sent[:20])
	}
	if translateTestSum(0, sent[:20]) != 0xFFFF {
		t.Errorf("the IPv4 header's checksum does not hold")
	}
	if !translateTestChecksumHolds(sent[12:16], sent[16:20], 6, sent[20:]) || len(sent) != len(syn)-20 {
		t.Errorf("the TCP checksum does not hold, or the length is %d", len(sent))
	}
	if binary.BigEndian.Uint16(sent[42:44]) != 1420 {
		t.Errorf("the MSS changed")
	}

	// the reply: swap the addresses and ports, a SYN-ACK
	reply := make([]byte, len(sent))
	copy(reply, sent)
	copy(reply[12:16], sent[16:20])
	copy(reply[16:20], sent[12:16])
	copy(reply[20:22], sent[22:24])
	copy(reply[22:24], sent[20:22])
	reply[33] = 0x12
	binary.BigEndian.PutUint16(reply[10:12], 0)
	binary.BigEndian.PutUint16(reply[10:12], ^uint16(translateTestSum(0, reply[:20])))
	binary.BigEndian.PutUint16(reply[36:38], 0)
	sum := translateTestSum(0, reply[12:20])
	sum = translateTestSum(sum, []byte{0, 6, 0, byte(len(reply) - 20)})
	binary.BigEndian.PutUint16(reply[36:38], ^uint16(translateTestSum(sum, reply[20:])))
	out := make([]byte, len(reply)+20)
	n, translated := test.bridge.TranslateReply(out, reply)
	if !translated || n != len(reply)+20 {
		t.Fatalf("the reply: %d, %t", n, translated)
	}
	back := out[:n]
	if back[0]>>4 != 6 || netip.AddrFrom16([16]byte(back[8:24])) != instance || netip.AddrFrom16([16]byte(back[24:40])) != own ||
		back[6] != 6 || !translateTestChecksumHolds(back[8:24], back[24:40], 6, back[40:]) {
		t.Fatalf("the reply as IPv6 %x", back[:40])
	}
	outCount, backCount, droppedCount := test.bridge.TranslatorCounts()
	if outCount != 1 || backCount != 1 || droppedCount != 0 {
		t.Errorf("counts out %d, back %d, dropped %d", outCount, backCount, droppedCount)
	}
}

// A UDP reply that would pass the tun's MTU once translated is dropped and counted; one within it passes; a packet to
// <block>.0.46 is the translator's whatever its source, and one to another address is not.
func TestBridgeTranslatorHoldsTheMtu(t *testing.T) {
	test := newTranslateTest(t)
	udp := func(payloadByteCount int) []byte {
		transport := make([]byte, 8+payloadByteCount)
		binary.BigEndian.PutUint16(transport[0:2], 4433)
		binary.BigEndian.PutUint16(transport[2:4], 50000)
		binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
		packet := routeTestPacket(17, "100.80.1.4", "100.80.0.46", transport)
		binary.BigEndian.PutUint16(packet[10:12], ^uint16(translateTestSum(0, packet[:20])))
		return packet
	}
	out := make([]byte, 2000)
	if n, translated := test.bridge.TranslateReply(out, udp(1500-48-1)); !translated || n != 1500-1 ||
		!translateTestChecksumHolds(out[8:24], out[24:40], 17, out[40:n]) {
		t.Errorf("a reply within the MTU: %d, %t", n, translated)
	}
	if n, translated := test.bridge.TranslateReply(out, udp(1500-48+1)); !translated || n != 0 {
		t.Errorf("a reply past the MTU: %d, %t", n, translated)
	}
	other := routeTestPacket(17, "100.80.1.4", "100.80.1.2", make([]byte, 8))
	if _, translated := test.bridge.TranslateReply(out, other); translated {
		t.Errorf("a packet to this host's own address was taken")
	}
	if _, _, droppedCount := test.bridge.TranslatorCounts(); droppedCount != 1 {
		t.Errorf("dropped %d", droppedCount)
	}
}

// ICMP: an echo request out and its reply back; a fragmentation-needed back as Packet Too Big, its MTU 20 more and its
// quote the IPv6 packet this host sent.
func TestBridgeTranslatorCarriesIcmp(t *testing.T) {
	test := newTranslateTest(t)
	own := netip.MustParseAddr("fd12:3456:789a::1")
	instance := test.bridge.TranslatedAddress(netip.MustParseAddr("100.80.1.4"))
	echo := make([]byte, 16)
	echo[0] = 128
	binary.BigEndian.PutUint16(echo[4:6], 7)
	binary.BigEndian.PutUint16(echo[6:8], 1)
	packet := routeTestIpv6Packet(58, own.String(), instance.String(), echo)
	link := test.awaitLink(routeTestTcp(routeTestSource, "100.80.1.4", 22))
	client := test.bridge.Route(packet)
	for !client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, connect.MessagePoolCopy(packet), time.Second) {
		<-test.passes
	}
	packets := link.Packets()
	sent := packets[len(packets)-1]
	if sent[9] != 1 || sent[20] != 8 || translateTestSum(0, sent[20:]) != 0xFFFF {
		t.Fatalf("the echo request as ICMPv4 %x", sent)
	}

	tooBig := make([]byte, 8+28)
	tooBig[0], tooBig[1] = 3, 4
	binary.BigEndian.PutUint16(tooBig[6:8], 1400)
	quoted := sent[:28]
	copy(tooBig[8:], quoted)
	reply := routeTestPacket(1, "100.80.1.4", "100.80.0.46", tooBig)
	out := make([]byte, 200)
	n, translated := test.bridge.TranslateReply(out, reply)
	if !translated || n == 0 {
		t.Fatalf("the error: %d, %t", n, translated)
	}
	back := out[:n]
	if back[40] != 2 || binary.BigEndian.Uint32(back[44:48]) != 1420 || !translateTestChecksumHolds(back[8:24], back[24:40], 58, back[40:]) {
		t.Fatalf("Packet Too Big %x", back[40:48])
	}
	if netip.AddrFrom16([16]byte(back[48+8:48+24])) != own {
		t.Errorf("the quote's source is not this host's own address")
	}
}

// With the translator off an IPv6 packet to the /96 meets the router's rows as before: under the fixture's auto, the
// default route.
func TestBridgeTranslatorOffLeavesIpv6Alone(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	packet := routeTestIpv6Tcp("fd12:3456:789a::1", "fd12:3456:789a:1::6450:104", 62078)
	if client := test.bridge.Route(packet); client != nil {
		t.Fatalf("an IPv6 packet took %T with the translator off", client)
	}
}
