// The mDNS codec and the responder Linux's advertising proxy runs on ur tun's link (§17.7.1; owner decision 778), on
// every platform over a fake link: a label holding a dot and a space survives a round trip, compression is followed and
// a pointer loop refused; the responder announces each instance's records twice, answers a browse with its PTR and the
// SRV, TXT, A and AAAA as additionals, leaves out what the known-answer list holds, answers a legacy query to its asker
// alone with its id and capped TTLs, ignores a query from elsewhere, says goodbye at a withdrawal and at close, and under
// Avahi's reflector sends nothing and says why.

package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
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

// A link that records what the responder writes and hands it what the test sends.
type testMdnsProxyLink struct {
	stateLock sync.Mutex
	receive   func(packet []byte)
	written   chan []byte
	resolver  netip.Addr
	mdnsOn    []bool
}

func newTestMdnsProxyLink() *testMdnsProxyLink {
	return &testMdnsProxyLink{written: make(chan []byte, 256), resolver: netip.MustParseAddr("100.80.0.53")}
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

// Hands the responder a query packet from source.
func (self *testMdnsProxyLink) query(t *testing.T, source netip.AddrPort, message *urMdnsMessage) {
	t.Helper()
	self.stateLock.Lock()
	receive := self.receive
	self.stateLock.Unlock()
	if receive == nil {
		t.Fatal("no receiver on the link")
	}
	receive(urMdnsProxyUdpPacket(source, netip.AddrPortFrom(urMdnsProxyGroup, urMdnsProxyPort), message.pack(9000)[0]))
}

// The next message written, read back, with where it went.
func (self *testMdnsProxyLink) next(t *testing.T) (netip.AddrPort, netip.AddrPort, *urMdnsMessage) {
	t.Helper()
	select {
	case packet := <-self.written:
		if packet[8] != 255 || urMdnsProxyChecksum(0, packet[:20]) != 0 {
			t.Fatalf("a packet of TTL %d or a bad header checksum", packet[8])
		}
		source := netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[12:16])), binary.BigEndian.Uint16(packet[20:22]))
		destination := netip.AddrPortFrom(netip.AddrFrom4([4]byte(packet[16:20])), binary.BigEndian.Uint16(packet[22:24]))
		var pseudo [12]byte
		copy(pseudo[0:8], packet[12:20])
		pseudo[9] = urMdnsProxyUdpProto
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(packet)-20))
		if urMdnsProxyChecksum(urMdnsProxySum(0, pseudo[:]), packet[20:]) != 0 {
			t.Fatal("a bad UDP checksum")
		}
		message, err := parseUrMdnsMessage(packet[28:])
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
		message, _ := parseUrMdnsMessage(packet[28:])
		t.Fatalf("written unasked: %+v", message)
	default:
	}
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

func TestMdnsDiscoveryProxyStaysOffUnderAvahisReflector(t *testing.T) {
	link := newTestMdnsProxyLink()
	applied := make(chan urDiscoveryProxyStatus, 16)
	proxy := newUrMdnsDiscoveryProxy(context.Background(), nil, link, defaultUrMdnsProxySettings(), func() (bool, string) {
		return true, "/etc/avahi/avahi-daemon.conf"
	}, func(status urDiscoveryProxyStatus) { applied <- status })
	defer proxy.Close()
	testMdnsProxyNext(t, applied)
	proxy.Set([]*sidecar.BridgeDiscoveryRegistration{
		testMdnsProxyRegistration("Files", "_smb._tcp", "nas", "host-a", "100.80.128.9", 445, ""),
	}, nil)
	status := testMdnsProxyNext(t, applied)
	if status.Note == "" || status.RegisteredCount != 0 {
		t.Fatalf("under the reflector %+v", status)
	}
	link.query(t, netip.MustParseAddrPort("100.80.4.2:5353"), &urMdnsMessage{questions: []urMdnsQuestion{
		{name: urMdnsNameParse("_smb._tcp.local"), qtype: urMdnsTypePtr},
	}})
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
