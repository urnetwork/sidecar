// The mDNS codec and the responder Linux's advertising proxy runs on ur tun's link (§17.7.1; owner decision 778), on
// every platform over a fake link: a label holding a dot and a space survives a round trip, compression is followed and
// a pointer loop refused; the responder announces each instance's records twice, answers a browse with its PTR and the
// SRV, TXT, A and AAAA as additionals, leaves out what the known-answer list holds, answers a legacy query to its asker
// alone with its id and capped TTLs, ignores a query from elsewhere, says goodbye at a withdrawal and at close, and under
// Avahi's reflector sends nothing and says why. Over IPv6 it does each of these from <block>.0.53's address in the
// translator's /96, announcing and saying goodbye on both families, splits within each family's bound, and answers no
// IPv6 query while the translator is off; its packets read back on either family with their checksums, and the tun
// hands it only a query to mDNS's group from the host's own address, or over IPv6 a link-local one.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

func TestMdnsWireRoundTripsLabelsAndFollowsCompression(t *testing.T) {
	instance := urMdnsNameOf("Alice's Phone v2.1 (main)", "_remotepairing", "_tcp", "local")
	message := &urMdnsMessage{
		id:       7,
		response: true,
		questions: []urMdnsQuestion{
			{name: urMdnsNameParse("_remotepairing._tcp.local"), qtype: urMdnsTypePtr, unicast: true},
		},
		answers: []urMdnsRecord{
			{name: urMdnsNameParse("_remotepairing._tcp.local"), rrtype: urMdnsTypePtr, ttl: 4500, target: instance},
		},
		additionals: []urMdnsRecord{
			{name: instance, rrtype: urMdnsTypeSrv, cacheFlush: true, ttl: 120, port: 49152, target: urMdnsNameParse("iphone.host-a.local")},
			{name: instance, rrtype: urMdnsTypeTxt, ttl: 4500, txt: []byte("\x05a=b c")},
			{name: urMdnsNameParse("iphone.host-a.local"), rrtype: urMdnsTypeA, cacheFlush: true, ttl: 120, address: netip.MustParseAddr("100.80.128.7")},
			{name: urMdnsNameParse("iphone.host-a.local"), rrtype: urMdnsTypeAaaa, cacheFlush: true, ttl: 120, address: netip.MustParseAddr("fd12::1:6450:8007")},
		},
	}
	packed := message.pack(9000)
	if len(packed) != 1 {
		t.Fatalf("packed into %d messages", len(packed))
	}
	parsed, err := parseUrMdnsMessage(packed[0])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.id != 7 || !parsed.response || len(parsed.questions) != 1 || !parsed.questions[0].unicast ||
		len(parsed.answers) != 1 || len(parsed.additionals) != 4 {
		t.Fatalf("parsed %+v", parsed)
	}
	if target := parsed.answers[0].target; len(target) != 4 || target[0] != "Alice's Phone v2.1 (main)" || !target.equal(instance) {
		t.Fatalf("the instance's label came back as %q", target)
	}
	srv := parsed.additionals[0]
	if !srv.cacheFlush || srv.port != 49152 || !srv.target.equal(urMdnsNameParse("IPHONE.host-a.local")) {
		t.Fatalf("SRV %+v", srv)
	}
	if string(parsed.additionals[1].txt) != "\x05a=b c" || parsed.additionals[2].address != netip.MustParseAddr("100.80.128.7") ||
		parsed.additionals[3].address != netip.MustParseAddr("fd12::1:6450:8007") {
		t.Fatalf("TXT and addresses %+v", parsed.additionals[1:])
	}
	// a name that points back at the question's name, and a pointer loop
	compressed := append([]byte{}, packed[0][:12]...)
	binary.BigEndian.PutUint16(compressed[4:6], 1)
	binary.BigEndian.PutUint16(compressed[6:8], 1)
	binary.BigEndian.PutUint16(compressed[8:10], 0)
	binary.BigEndian.PutUint16(compressed[10:12], 0)
	question, _ := (&urMdnsQuestion{name: urMdnsNameParse("_ipp._tcp.local"), qtype: urMdnsTypePtr}).wire()
	compressed = append(compressed, question...)
	// the answer's name: a pointer to the question's name at offset 12; its PTR rdata: a label then a pointer there too
	compressed = append(compressed, 0xC0, 12, 0, urMdnsTypePtr, 0, 1, 0, 0, 0x11, 0x94, 0, 8, 5, 'P', 'r', 'i', 'n', 't', 0xC0, 12)
	parsed, err = parseUrMdnsMessage(compressed)
	if err != nil || len(parsed.answers) != 1 || !parsed.answers[0].name.equal(urMdnsNameParse("_ipp._tcp.local")) ||
		!parsed.answers[0].target.equal(urMdnsNameParse("Print._ipp._tcp.local")) {
		t.Fatalf("compression read %+v, %v", parsed, err)
	}
	loop := append([]byte{}, compressed[:12]...)
	binary.BigEndian.PutUint16(loop[4:6], 1)
	binary.BigEndian.PutUint16(loop[6:8], 0)
	loop = append(loop, 0xC0, 12, 0, 12, 0, 1)
	if _, err := parseUrMdnsMessage(loop); err == nil {
		t.Fatal("a pointer loop read")
	}
	// a split: each message stands under the bound with the questions in each
	split := message.pack(160)
	if len(split) < 2 {
		t.Fatalf("a 160 B bound packed into %d", len(split))
	}
	recordCount := 0
	for _, part := range split {
		if 160 < len(part) {
			t.Fatalf("a message of %d B", len(part))
		}
		parsed, err := parseUrMdnsMessage(part)
		if err != nil || len(parsed.questions) != 1 {
			t.Fatalf("a part read %+v, %v", parsed, err)
		}
		recordCount += len(parsed.answers) + len(parsed.additionals)
	}
	if recordCount != 5 {
		t.Fatalf("the parts held %d records", recordCount)
	}
}

// A link that records what the responder writes and hands it what the test sends. It holds the responder no IPv6
// address, as with the translator off, unless a test sets resolverIpv6 before it starts the responder.
type testMdnsProxyLink struct {
	stateLock    sync.Mutex
	receive      func(packet []byte)
	written      chan []byte
	resolver     netip.Addr
	resolverIpv6 netip.Addr
	mdnsOn       []bool
}

func newTestMdnsProxyLink() *testMdnsProxyLink {
	return &testMdnsProxyLink{written: make(chan []byte, 256), resolver: netip.MustParseAddr("100.80.0.53")}
}

// The translator's mapping the tests give the responder: an IPv4 address in the low 32 bits of fd12:3456:789a:1::/96.
func testMdnsProxyTranslated(address netip.Addr) netip.Addr {
	octets := address.As4()
	return netip.AddrFrom16([16]byte{0xFD, 0x12, 0x34, 0x56, 0x78, 0x9A, 0, 1, 12: octets[0], 13: octets[1], 14: octets[2], 15: octets[3]})
}

func (self *testMdnsProxyLink) ResolverIpv6Address() netip.Addr {
	return self.resolverIpv6
}

func (self *testMdnsProxyLink) SetMdnsReceiver(receive func(packet []byte)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.receive = receive
}

func (self *testMdnsProxyLink) WritePacket(packet []byte) {
	self.written <- slices.Clone(packet)
}

func (self *testMdnsProxyLink) ResolverAddress() netip.Addr {
	return self.resolver
}

func (self *testMdnsProxyLink) SetLinkMulticastDns(on bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mdnsOn = append(self.mdnsOn, on)
	return nil
}

// Hands the responder a query packet from source to its family's group.
func (self *testMdnsProxyLink) query(t *testing.T, source netip.AddrPort, message *urMdnsMessage) {
	t.Helper()
	self.stateLock.Lock()
	receive := self.receive
	self.stateLock.Unlock()
	if receive == nil {
		t.Fatal("no receiver on the link")
	}
	group := urMdnsProxyGroup
	if source.Addr().Is6() {
		group = urMdnsProxyIpv6Group
	}
	receive(urMdnsProxyUdpPacket(source, netip.AddrPortFrom(group, urMdnsProxyPort), message.pack(9000)[0]))
}

// The next message written, read back, with where it went.
func (self *testMdnsProxyLink) next(t *testing.T) (netip.AddrPort, netip.AddrPort, *urMdnsMessage) {
	t.Helper()
	select {
	case packet := <-self.written:
		source, destination, payload := testMdnsProxyPacketRead(t, packet)
		message, err := parseUrMdnsMessage(payload)
		if err != nil {
			t.Fatal(err)
		}
		return source, destination, message
	case <-time.After(10 * time.Second):
		t.Fatal("nothing written within 10 s")
	}
	return netip.AddrPort{}, netip.AddrPort{}, nil
}

// Nothing more written now.
func (self *testMdnsProxyLink) quiet(t *testing.T) {
	t.Helper()
	select {
	case packet := <-self.written:
		_, destination, payload := testMdnsProxyPacketRead(t, packet)
		message, _ := parseUrMdnsMessage(payload)
		t.Fatalf("written unasked to %v: %+v", destination, message)
	default:
	}
}

// A written packet's source, destination and payload, failing t where its TTL or hop limit is not 255 or a length or
// checksum does not hold. Each family's pseudo-header is laid out here apart from the responder's own, byte by byte as
// RFC 768 and RFC 8200 §8.1 draw them.
func testMdnsProxyPacketRead(t *testing.T, packet []byte) (netip.AddrPort, netip.AddrPort, []byte) {
	t.Helper()
	var source, destination netip.Addr
	var udp, pseudo []byte
	switch {
	case 28 <= len(packet) && packet[0] == 0x45:
		if packet[8] != 255 || packet[9] != 17 || urMdnsProxyChecksum(0, packet[:20]) != 0 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			t.Fatalf("an IPv4 packet of TTL %d, protocol %d, or a bad header checksum or length", packet[8], packet[9])
		}
		source, destination, udp = netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), packet[20:]
		pseudo = append(slices.Clone(packet[12:20]), 0, 17, byte(len(udp)>>8), byte(len(udp)))
	case 48 <= len(packet) && packet[0] == 0x60:
		if packet[7] != 255 || packet[6] != 17 || int(binary.BigEndian.Uint16(packet[4:6])) != len(packet)-40 {
			t.Fatalf("an IPv6 packet of hop limit %d, next header %d, or a bad length", packet[7], packet[6])
		}
		source, destination, udp = netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40])), packet[40:]
		pseudo = append(slices.Clone(packet[8:40]), 0, 0, byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, 17)
	default:
		t.Fatalf("a packet neither IPv4 nor IPv6: %x", packet[:min(len(packet), 8)])
	}
	if int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) || binary.BigEndian.Uint16(udp[6:8]) == 0 ||
		urMdnsProxyChecksum(urMdnsProxySum(0, pseudo), udp) != 0 {
		t.Fatal("a bad UDP length or checksum")
	}
	return netip.AddrPortFrom(source, binary.BigEndian.Uint16(udp[0:2])), netip.AddrPortFrom(destination, binary.BigEndian.Uint16(udp[2:4])), udp[8:]
}

// The types and names of a message's records, in a section.
func testMdnsRecordNames(records []urMdnsRecord) []string {
	names := []string{}
	for _, record := range records {
		names = append(names, map[uint16]string{urMdnsTypePtr: "PTR", urMdnsTypeSrv: "SRV", urMdnsTypeTxt: "TXT",
			urMdnsTypeA: "A", urMdnsTypeAaaa: "AAAA"}[record.rrtype]+" "+record.name.key())
	}
	slices.Sort(names)
	return names
}

func TestMdnsDiscoveryProxyAnswersOnTheLink(t *testing.T) {
	link := newTestMdnsProxyLink()
	settings := defaultUrMdnsProxySettings()
	settings.AnnounceInterval = time.Hour
	applied := make(chan urDiscoveryProxyStatus, 16)
	proxy := newUrMdnsDiscoveryProxy(context.Background(), nil, link, settings, nil, func(status urDiscoveryProxyStatus) { applied <- status })
	testMdnsProxyNext(t, applied)
	registrations := []*sidecar.BridgeDiscoveryRegistration{
		testMdnsProxyRegistration("Alice's iPhone", "_remotepairing._tcp", "iphone", "host-a", "100.80.128.7", 49152, "\x0aauthTag=xy"),
	}
	translated := func(address netip.Addr) netip.Addr {
		octets := address.As4()
		return netip.AddrFrom16([16]byte{0xfd, 0x12, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, octets[0], octets[1], octets[2], octets[3]})
	}
	proxy.Set(registrations, translated)
	if status := testMdnsProxyNext(t, applied); status.RegisteredCount != 1 {
		t.Fatalf("applied %+v", status)
	}
	// the announcement: every record, from the block's resolver to the group, multicast
	source, destination, announcement := link.next(t)
	if source != netip.MustParseAddrPort("100.80.0.53:5353") || destination != netip.MustParseAddrPort("224.0.0.251:5353") || !announcement.response {
		t.Fatalf("announced from %v to %v", source, destination)
	}
	if names := testMdnsRecordNames(announcement.answers); len(names) != 6 {
		t.Fatalf("announced %v", names)
	}
	link.quiet(t)

	host := netip.MustParseAddrPort("100.80.4.2:5353")
	browse := &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("_remotepairing._tcp.local"), qtype: urMdnsTypePtr}}}
	link.query(t, host, browse)
	_, destination, answer := link.next(t)
	if destination != netip.MustParseAddrPort("224.0.0.251:5353") || len(answer.answers) != 1 || answer.answers[0].rrtype != urMdnsTypePtr ||
		answer.answers[0].target[0] != "Alice's iPhone" {
		t.Fatalf("answered %+v to %v", answer.answers, destination)
	}
	if names := testMdnsRecordNames(answer.additionals); len(names) != 4 {
		t.Fatalf("additionals %v", names)
	}
	for _, record := range answer.additionals {
		if record.rrtype == urMdnsTypeAaaa && record.address != translated(netip.MustParseAddr("100.80.128.7")) {
			t.Fatalf("AAAA %v", record.address)
		}
		if record.rrtype == urMdnsTypeSrv && (record.port != 49152 || record.target[0] != "iphone" || record.ttl != 120) {
			t.Fatalf("SRV %+v", record)
		}
	}
	// a known answer with half its TTL or more left is left out, and with nothing left there is no answer
	known := &urMdnsMessage{questions: browse.questions, answers: []urMdnsRecord{answer.answers[0]}}
	known.answers[0].ttl = 2250
	link.query(t, host, known)
	link.quiet(t)
	// one with less than half left is answered again
	known.answers[0].ttl = 2249
	link.query(t, host, known)
	if _, _, again := link.next(t); len(again.answers) != 1 {
		t.Fatalf("answered %+v", again.answers)
	}
	// a legacy query: to its asker alone, with its id and question, TTLs capped and no cache-flush
	legacy := &urMdnsMessage{id: 0x4242, questions: []urMdnsQuestion{{name: urMdnsNameParse("iphone.host-a.local"), qtype: urMdnsTypeA}}}
	link.query(t, netip.MustParseAddrPort("100.80.4.2:40000"), legacy)
	_, destination, reply := link.next(t)
	if destination != netip.MustParseAddrPort("100.80.4.2:40000") || reply.id != 0x4242 || len(reply.questions) != 1 ||
		len(reply.answers) != 1 || reply.answers[0].ttl != 10 || reply.answers[0].cacheFlush ||
		reply.answers[0].address != netip.MustParseAddr("100.80.128.7") {
		t.Fatalf("legacy reply %+v to %v", reply, destination)
	}
	// the service enumeration
	link.query(t, host, &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsServicesName, qtype: urMdnsTypePtr}}})
	if _, _, services := link.next(t); len(services.answers) != 1 || !services.answers[0].target.equal(urMdnsNameParse("_remotepairing._tcp.local")) {
		t.Fatalf("services %+v", services.answers)
	}

	// the instance goes: a goodbye for each of its records
	proxy.Set(nil, translated)
	testMdnsProxyNext(t, applied)
	_, _, goodbye := link.next(t)
	if len(goodbye.answers) != 6 {
		t.Fatalf("goodbye of %d", len(goodbye.answers))
	}
	for _, record := range goodbye.answers {
		if record.ttl != 0 {
			t.Fatalf("a goodbye with TTL %d", record.ttl)
		}
	}
	link.query(t, host, browse)
	link.quiet(t)
	proxy.Close()
	if !slices.Equal(link.mdnsOn, []bool{true, false}) {
		t.Fatalf("the link's mDNS went %v", link.mdnsOn)
	}
}

// Under Avahi's reflector the responder sends nothing on either family: no announcement, no answer to a query over
// IPv4 or IPv6, and no goodbye at close.
func TestMdnsDiscoveryProxyStaysOffUnderAvahisReflector(t *testing.T) {
	link := newTestMdnsProxyLink()
	link.resolverIpv6 = testMdnsProxyTranslated(netip.MustParseAddr("100.80.0.53"))
	applied := make(chan urDiscoveryProxyStatus, 16)
	proxy := newUrMdnsDiscoveryProxy(context.Background(), nil, link, defaultUrMdnsProxySettings(), func() (bool, string) {
		return true, "/etc/avahi/avahi-daemon.conf"
	}, func(status urDiscoveryProxyStatus) { applied <- status })
	defer proxy.Close()
	testMdnsProxyNext(t, applied)
	proxy.Set([]*sidecar.BridgeDiscoveryRegistration{
		testMdnsProxyRegistration("Files", "_smb._tcp", "nas", "host-a", "100.80.128.9", 445, ""),
	}, testMdnsProxyTranslated)
	status := testMdnsProxyNext(t, applied)
	if status.Note == "" || status.RegisteredCount != 0 {
		t.Fatalf("under the reflector %+v", status)
	}
	browse := &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("_smb._tcp.local"), qtype: urMdnsTypePtr}}}
	link.query(t, netip.MustParseAddrPort("100.80.4.2:5353"), browse)
	link.query(t, netip.MustParseAddrPort("[fe80::1234]:5353"), browse)
	proxy.Close()
	link.quiet(t)
	if len(link.mdnsOn) != 0 {
		t.Fatalf("the link's mDNS went %v under the reflector", link.mdnsOn)
	}
}

// The next status applied.
func testMdnsProxyNext(t *testing.T, applied chan urDiscoveryProxyStatus) urDiscoveryProxyStatus {
	t.Helper()
	select {
	case status := <-applied:
		return status
	case <-time.After(10 * time.Second):
		t.Fatal("no apply within 10 s")
	}
	return urDiscoveryProxyStatus{}
}

// One registration of an instance at address under host, as the names rule makes it.
func testMdnsProxyRegistration(name string, service string, label string, host string, address string, port uint16, txt string) *sidecar.BridgeDiscoveryRegistration {
	return &sidecar.BridgeDiscoveryRegistration{
		Instance: &sidecar.BridgeDiscoveryViewInstance{
			HostName:  host,
			Name:      name,
			Service:   service,
			Port:      port,
			Txt:       []byte(txt),
			HostLabel: label,
			Address:   netip.MustParseAddr(address),
		},
		Name:   name,
		Target: label + "." + host,
	}
}

func TestAvahiReflectorSettingReads(t *testing.T) {
	cases := []struct {
		text string
		on   bool
	}{
		{text: "", on: false},
		{text: "[server]\nenable-reflector=yes\n", on: false},
		{text: "[reflector]\n#enable-reflector=yes\n", on: false},
		{text: "[reflector]\nenable-reflector=no\n", on: false},
		{text: "[Reflector]\n Enable-Reflector = Yes \n", on: true},
		{text: "[reflector]\nenable-reflector=1\n[server]\nuse-ipv4=yes\n", on: true},
		{text: "[reflector]\nenable-reflector=true\nenable-reflector=no\n", on: false},
	}
	for _, c := range cases {
		if on := urAvahiReflectorOnIn(c.text); on != c.on {
			t.Fatalf("%q read %v", c.text, on)
		}
	}
	if on, _ := urAvahiReflectorOn(t.TempDir() + "/none.conf"); on {
		t.Fatal("a missing file turned the reflector on")
	}
}

// A type a name the proxy owns does not hold is denied by an NSEC listing what the name holds: an AAAA while the
// translator is off, a TXT of a host name; a name it does not own, a type's, gets nothing.
func TestMdnsDiscoveryProxyDeniesAnAbsentTypeByNsec(t *testing.T) {
	link := newTestMdnsProxyLink()
	settings := defaultUrMdnsProxySettings()
	settings.AnnounceInterval = time.Hour
	applied := make(chan urDiscoveryProxyStatus, 16)
	proxy := newUrMdnsDiscoveryProxy(context.Background(), nil, link, settings, nil, func(status urDiscoveryProxyStatus) { applied <- status })
	defer proxy.Close()
	testMdnsProxyNext(t, applied)
	proxy.Set([]*sidecar.BridgeDiscoveryRegistration{
		testMdnsProxyRegistration("Files", "_smb._tcp", "nas", "host-a", "100.80.128.9", 445, ""),
	}, nil)
	testMdnsProxyNext(t, applied)
	link.next(t)
	host := netip.MustParseAddrPort("100.80.4.2:5353")
	for _, qtype := range []uint16{urMdnsTypeAaaa, urMdnsTypeTxt} {
		link.query(t, host, &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("nas.host-a.local"), qtype: qtype}}})
		_, _, answer := link.next(t)
		if len(answer.answers) != 1 || answer.answers[0].rrtype != urMdnsTypeNsec || !answer.answers[0].cacheFlush {
			t.Fatalf("type %d answered %+v", qtype, answer.answers)
		}
		data := answer.answers[0].data
		next, at, err := urMdnsReadName(data, 0)
		// the next name its own, window 0, and a bitmap whose one bit is A's
		if err != nil || !next.equal(urMdnsNameParse("nas.host-a.local")) || len(data) != at+3 || data[at] != 0 || data[at+1] != 1 || data[at+2] != 0x40 {
			t.Fatalf("NSEC %x, %v", data, err)
		}
	}
	// a type's name is shared, not this responder's alone: no NSEC for it
	link.query(t, host, &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("_smb._tcp.local"), qtype: urMdnsTypeTxt}}})
	link.quiet(t)
}

// Over IPv6 the responder answers as over IPv4, from <block>.0.53's address in the translator's /96: it announces on
// both families, answers an IPv6 browse to IPv6's group alone with the same records, leaves out a known answer,
// answers a legacy query from a link-local address to that address alone, denies an absent type by an NSEC, and says
// goodbye on both families at a withdrawal and at close.
func TestMdnsDiscoveryProxyAnswersOverIpv6Too(t *testing.T) {
	link := newTestMdnsProxyLink()
	link.resolverIpv6 = testMdnsProxyTranslated(netip.MustParseAddr("100.80.0.53"))
	settings := defaultUrMdnsProxySettings()
	settings.AnnounceInterval = time.Hour
	applied := make(chan urDiscoveryProxyStatus, 16)
	proxy := newUrMdnsDiscoveryProxy(context.Background(), nil, link, settings, nil, func(status urDiscoveryProxyStatus) { applied <- status })
	testMdnsProxyNext(t, applied)
	iphone := testMdnsProxyRegistration("Alice's iPhone", "_remotepairing._tcp", "iphone", "host-a", "100.80.128.7", 49152, "\x0aauthTag=xy")
	files := testMdnsProxyRegistration("Files", "_smb._tcp", "nas", "host-a", "100.80.128.9", 445, "")
	proxy.Set([]*sidecar.BridgeDiscoveryRegistration{iphone, files}, testMdnsProxyTranslated)
	if status := testMdnsProxyNext(t, applied); status.RegisteredCount != 2 {
		t.Fatalf("applied %+v", status)
	}
	ipv4Group, ipv6Group := netip.MustParseAddrPort("224.0.0.251:5353"), netip.MustParseAddrPort("[ff02::fb]:5353")
	resolverIpv6 := netip.AddrPortFrom(link.resolverIpv6, 5353)
	// the announcement: IPv4's group first, then IPv6's from the resolver's address in the /96, the same 12 records
	ipv4Source, ipv4Destination, ipv4Announcement := link.next(t)
	ipv6Source, ipv6Destination, ipv6Announcement := link.next(t)
	if ipv4Source != netip.MustParseAddrPort("100.80.0.53:5353") || ipv4Destination != ipv4Group || ipv6Source != resolverIpv6 ||
		ipv6Destination != ipv6Group || len(ipv6Announcement.answers) != 12 ||
		!slices.Equal(testMdnsRecordNames(ipv4Announcement.answers), testMdnsRecordNames(ipv6Announcement.answers)) {
		t.Fatalf("announced from %v to %v and from %v to %v: %v and %v", ipv4Source, ipv4Destination, ipv6Source, ipv6Destination,
			testMdnsRecordNames(ipv4Announcement.answers), testMdnsRecordNames(ipv6Announcement.answers))
	}
	link.quiet(t)

	// a browse over IPv6 from the tun's own address: answered to IPv6's group alone
	host := netip.MustParseAddrPort("[fd12:3456:789a::1]:5353")
	browse := &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("_remotepairing._tcp.local"), qtype: urMdnsTypePtr}}}
	link.query(t, host, browse)
	source, destination, answer := link.next(t)
	if source != resolverIpv6 || destination != ipv6Group || len(answer.answers) != 1 || answer.answers[0].rrtype != urMdnsTypePtr ||
		answer.answers[0].target[0] != "Alice's iPhone" || len(answer.additionals) != 4 {
		t.Fatalf("answered %+v and %v from %v to %v", answer.answers, testMdnsRecordNames(answer.additionals), source, destination)
	}
	for _, record := range answer.additionals {
		if record.rrtype == urMdnsTypeAaaa && record.address != testMdnsProxyTranslated(netip.MustParseAddr("100.80.128.7")) {
			t.Fatalf("AAAA %v", record.address)
		}
	}
	link.quiet(t)
	// a known answer with half its TTL or more left is left out
	known := &urMdnsMessage{questions: browse.questions, answers: []urMdnsRecord{answer.answers[0]}}
	known.answers[0].ttl = 2250
	link.query(t, host, known)
	link.quiet(t)
	// a legacy query from the host's link-local address: to it alone, with its id and question, TTLs capped
	asker := netip.MustParseAddrPort("[fe80::1234]:40000")
	link.query(t, asker, &urMdnsMessage{id: 0x4243, questions: []urMdnsQuestion{{name: urMdnsNameParse("iphone.host-a.local"), qtype: urMdnsTypeAaaa}}})
	source, destination, reply := link.next(t)
	if source != resolverIpv6 || destination != asker || reply.id != 0x4243 || len(reply.questions) != 1 || len(reply.answers) != 1 ||
		reply.answers[0].rrtype != urMdnsTypeAaaa || reply.answers[0].ttl != 10 || reply.answers[0].cacheFlush ||
		reply.answers[0].address != testMdnsProxyTranslated(netip.MustParseAddr("100.80.128.7")) {
		t.Fatalf("legacy reply %+v from %v to %v", reply, source, destination)
	}
	// a type the target's name does not hold: an NSEC naming its A and AAAA
	link.query(t, host, &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("nas.host-a.local"), qtype: urMdnsTypeTxt}}})
	_, destination, denial := link.next(t)
	if destination != ipv6Group || len(denial.answers) != 1 || denial.answers[0].rrtype != urMdnsTypeNsec {
		t.Fatalf("denied %+v to %v", denial.answers, destination)
	}
	data := denial.answers[0].data
	// window 0 and a bitmap of four octets whose bits are A's (type 1) and AAAA's (type 28)
	if _, at, err := urMdnsReadName(data, 0); err != nil || len(data) != at+6 || data[at] != 0 || data[at+1] != 4 ||
		!bytes.Equal(data[at+2:], []byte{0x40, 0, 0, 0x08}) {
		t.Fatalf("NSEC %x, %v", data, err)
	}

	// Files goes: a goodbye of its six records on each family; then the close says goodbye to the iPhone's
	proxy.Set([]*sidecar.BridgeDiscoveryRegistration{iphone}, testMdnsProxyTranslated)
	testMdnsProxyNext(t, applied)
	goodbyes := func(what string) {
		t.Helper()
		for _, group := range []netip.AddrPort{ipv4Group, ipv6Group} {
			_, destination, goodbye := link.next(t)
			if destination != group || len(goodbye.answers) != 6 {
				t.Fatalf("%s: a goodbye of %d to %v", what, len(goodbye.answers), destination)
			}
			for _, record := range goodbye.answers {
				if record.ttl != 0 {
					t.Fatalf("%s: a goodbye with TTL %d", what, record.ttl)
				}
			}
		}
		link.quiet(t)
	}
	goodbyes("the withdrawal")
	proxy.Close()
	goodbyes("the close")
}

// With the translator off the link holds the responder no IPv6 address: it announces over IPv4 alone, an IPv6 query
// goes unanswered, and its IPv4 twin is answered, its AAAA denied by an NSEC.
func TestMdnsDiscoveryProxyLeavesIpv6UnansweredWithoutTheTranslator(t *testing.T) {
	link := newTestMdnsProxyLink()
	settings := defaultUrMdnsProxySettings()
	settings.AnnounceInterval = time.Hour
	applied := make(chan urDiscoveryProxyStatus, 16)
	proxy := newUrMdnsDiscoveryProxy(context.Background(), nil, link, settings, nil, func(status urDiscoveryProxyStatus) { applied <- status })
	defer proxy.Close()
	testMdnsProxyNext(t, applied)
	proxy.Set([]*sidecar.BridgeDiscoveryRegistration{
		testMdnsProxyRegistration("Files", "_smb._tcp", "nas", "host-a", "100.80.128.9", 445, ""),
	}, nil)
	testMdnsProxyNext(t, applied)
	if _, destination, _ := link.next(t); destination != netip.MustParseAddrPort("224.0.0.251:5353") {
		t.Fatalf("announced to %v", destination)
	}
	link.quiet(t)
	question := &urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("nas.host-a.local"), qtype: urMdnsTypeAaaa}}}
	// the queue is one goroutine's, in order, so the IPv4 answer comes only once the IPv6 query has been passed over
	link.query(t, netip.MustParseAddrPort("[fe80::1234]:5353"), question)
	link.query(t, netip.MustParseAddrPort("100.80.4.2:5353"), question)
	_, destination, denial := link.next(t)
	if destination != netip.MustParseAddrPort("224.0.0.251:5353") || len(denial.answers) != 1 || denial.answers[0].rrtype != urMdnsTypeNsec {
		t.Fatalf("answered %+v to %v", denial.answers, destination)
	}
	link.quiet(t)
}

// An announcement past one message is split within each family's own bound, 1,252 B over IPv4 and 1,232 B over IPv6,
// so no packet of either outgrows the tun's 1,280 B MTU, and the two families carry the same records.
func TestMdnsDiscoveryProxySplitsWithinEachFamilysBound(t *testing.T) {
	link := newTestMdnsProxyLink()
	link.resolverIpv6 = testMdnsProxyTranslated(netip.MustParseAddr("100.80.0.53"))
	settings := defaultUrMdnsProxySettings()
	settings.AnnounceInterval = time.Hour
	applied := make(chan urDiscoveryProxyStatus, 16)
	proxy := newUrMdnsDiscoveryProxy(context.Background(), nil, link, settings, nil, func(status urDiscoveryProxyStatus) { applied <- status })
	defer proxy.Close()
	testMdnsProxyNext(t, applied)
	registrations := []*sidecar.BridgeDiscoveryRegistration{}
	for i := range 24 {
		registrations = append(registrations, testMdnsProxyRegistration(fmt.Sprintf("Printer %02d", i), "_ipp._tcp",
			fmt.Sprintf("printer-%02d", i), "host-a", fmt.Sprintf("100.80.128.%d", 10+i), 631, "\x40"+strings.Repeat("x", 64)))
	}
	proxy.Set(registrations, testMdnsProxyTranslated)
	testMdnsProxyNext(t, applied)
	// the announcement was written before the apply was heard
	messageCounts := map[bool]int{}
	familyNames := map[bool][]string{}
	for drained := false; !drained; {
		select {
		case packet := <-link.written:
			_, destination, payload := testMdnsProxyPacketRead(t, packet)
			ipv6 := destination.Addr().Is6()
			byteCount := settings.MessageByteCount
			if ipv6 {
				byteCount = settings.Ipv6MessageByteCount
			}
			if 1280 < len(packet) || byteCount < len(payload) {
				t.Fatalf("a packet of %d B carrying %d B to %v", len(packet), len(payload), destination)
			}
			message, err := parseUrMdnsMessage(payload)
			if err != nil {
				t.Fatal(err)
			}
			messageCounts[ipv6] += 1
			familyNames[ipv6] = append(familyNames[ipv6], testMdnsRecordNames(message.answers)...)
		default:
			drained = true
		}
	}
	slices.Sort(familyNames[false])
	slices.Sort(familyNames[true])
	// one _services PTR, and per printer its type's PTR, SRV, TXT, A and AAAA
	if messageCounts[false] < 2 || messageCounts[true] < 2 || len(familyNames[true]) != 1+24*5 || !slices.Equal(familyNames[false], familyNames[true]) {
		t.Fatalf("split into %d and %d messages carrying %d and %d records", messageCounts[false], messageCounts[true],
			len(familyNames[false]), len(familyNames[true]))
	}
}

// The responder's packets read back on either family with their checksums, an IPv6 one's equal to the IPv4 one's
// where the addresses' 16-bit words sum alike, as RFC 768's and RFC 8200 §8.1's pseudo-headers make them; a packet
// is read only as a query to mDNS's group and port, and the tun hands one over only from the host's own addresses or,
// over IPv6, from a link-local one.
func TestMdnsProxyPacketsReadBackOnEitherFamily(t *testing.T) {
	payload := (&urMdnsMessage{questions: []urMdnsQuestion{{name: urMdnsNameParse("_ipp._tcp.local"), qtype: urMdnsTypePtr}}}).pack(9000)[0]
	ipv4 := urMdnsProxyUdpPacket(netip.MustParseAddrPort("100.80.0.53:5353"), netip.MustParseAddrPort("224.0.0.251:5353"), payload)
	// the same addresses in the low 32 bits of ::/96, whose words sum as theirs do
	ipv6 := urMdnsProxyUdpPacket(netip.MustParseAddrPort("[::6450:35]:5353"), netip.MustParseAddrPort("[::e000:fb]:5353"), payload)
	if len(ipv4) != 28+len(payload) || len(ipv6) != 48+len(payload) || !bytes.Equal(ipv4[20:], ipv6[40:]) {
		t.Fatalf("UDP %x over IPv4 and %x over IPv6", ipv4[20:28], ipv6[40:48])
	}
	if urMdnsProxyUdpPacket(netip.MustParseAddrPort("100.80.0.53:5353"), netip.MustParseAddrPort("[ff02::fb]:5353"), payload) != nil {
		t.Fatal("a packet across two families")
	}
	for _, c := range []struct {
		source      string
		destination string
	}{
		{source: "100.80.4.2:5353", destination: "224.0.0.251:5353"},
		{source: "[fe80::1234]:40000", destination: "[ff02::fb]:5353"},
	} {
		packet := urMdnsProxyUdpPacket(netip.MustParseAddrPort(c.source), netip.MustParseAddrPort(c.destination), payload)
		testMdnsProxyPacketRead(t, packet)
		source, read, ok := urMdnsProxyUdpPayload(packet)
		if !ok || source != netip.MustParseAddrPort(c.source) || !bytes.Equal(read, payload) {
			t.Fatalf("%s read back from %v, %v", c.source, source, ok)
		}
	}
	query := urMdnsProxyUdpPacket(netip.MustParseAddrPort("[fe80::1234]:5353"), netip.MustParseAddrPort("[ff02::fb]:5353"), payload)
	edited := func(edit func(packet []byte) []byte) []byte {
		return edit(slices.Clone(query))
	}
	refused := []struct {
		what   string
		packet []byte
	}{
		{what: "another group", packet: urMdnsProxyUdpPacket(netip.MustParseAddrPort("[fe80::1234]:5353"), netip.MustParseAddrPort("[ff02::1]:5353"), payload)},
		{what: "another port", packet: urMdnsProxyUdpPacket(netip.MustParseAddrPort("[fe80::1234]:5353"), netip.MustParseAddrPort("[ff02::fb]:5355"), payload)},
		{what: "a hop-by-hop header", packet: edited(func(packet []byte) []byte { packet[6] = 0; return packet })},
		{what: "a fragment header", packet: edited(func(packet []byte) []byte { packet[6] = 44; return packet })},
		{what: "a payload length short of UDP's", packet: edited(func(packet []byte) []byte {
			binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-41))
			return packet
		})},
		{what: "a truncated packet", packet: query[:len(query)-1]},
		{what: "a short header", packet: query[:44]},
		{what: "another version", packet: edited(func(packet []byte) []byte { packet[0] = 0x50; return packet })},
	}
	for _, c := range refused {
		if _, _, ok := urMdnsProxyUdpPayload(c.packet); ok {
			t.Errorf("%s read", c.what)
		}
	}
	// the tun names its IPv4 address and the translator's own; a link-local IPv6 source is the host's too
	addresses := []netip.Addr{netip.MustParseAddr("100.80.4.2"), netip.MustParseAddr("fd12:3456:789a::1")}
	for _, c := range []struct {
		source string
		from   bool
	}{
		{source: "100.80.4.2:5353", from: true},
		{source: "100.80.4.3:5353"},
		{source: "169.254.1.2:5353"},
		{source: "[fd12:3456:789a::1]:5353", from: true},
		{source: "[fe80::1234]:40000", from: true},
		{source: "[fd12:3456:789a:1::6450:35]:5353"},
		{source: "[2001:db8::7]:5353"},
		{source: "[::ffff:169.254.1.2]:5353"},
	} {
		source := netip.MustParseAddrPort(c.source)
		group := urMdnsProxyGroup
		if source.Addr().Is6() {
			group = urMdnsProxyIpv6Group
		}
		if from := urMdnsProxyQueryFrom(urMdnsProxyUdpPacket(source, netip.AddrPortFrom(group, urMdnsProxyPort), payload), addresses); from != c.from {
			t.Errorf("from %s: handed %v", c.source, from)
		}
	}
}
