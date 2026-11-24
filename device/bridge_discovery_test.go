// §12.9.1's DNS-SD names (bridge_discovery.go; owner decision 778), §22.5's §12 row from M6: each form, in the zone and
// the block's reverse zone, answered on the device per qtype with 10 s TTLs, b and db naming the zone and lb, r and dr
// empty, and not one query reaching the fake upstream; answers within the asker's UDP size or TC; a view holding only
// instances of its shape; and from M8 an app's LocalZone answering each NODATA.

package device_test

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/device"
)

// One record read off a response.
type discoveryTestRecord struct {
	owner  string
	rrtype uint16
	ttl    uint32
	rdata  []byte
	// the rdata's names, read for PTR, SRV and SOA
	name string
	port uint16
}

// A response read whole.
type discoveryTestResponse struct {
	flags       uint16
	rcode       uint16
	answers     []discoveryTestRecord
	authorities []discoveryTestRecord
	additionals []discoveryTestRecord
}

// Reads a name at at, uncompressed, as dotted labels with no trailing dot, and where it ends.
func discoveryTestName(t testing.TB, message []byte, at int) (string, int) {
	t.Helper()
	labels := []string{}
	for {
		if len(message) <= at {
			t.Fatalf("a name runs past the message")
		}
		count := int(message[at])
		at += 1
		if count == 0 {
			return strings.Join(labels, "."), at
		}
		if 63 < count {
			t.Fatalf("a compressed or overlong label")
		}
		labels = append(labels, string(message[at:at+count]))
		at += count
	}
}

// Reads a whole response.
func discoveryTestRead(t testing.TB, message []byte) discoveryTestResponse {
	t.Helper()
	if len(message) < 12 {
		t.Fatalf("a response of %d bytes", len(message))
	}
	response := discoveryTestResponse{flags: binary.BigEndian.Uint16(message[2:4])}
	response.rcode = response.flags & 0x000F
	at := 12
	for range binary.BigEndian.Uint16(message[4:6]) {
		_, at = discoveryTestName(t, message, at)
		at += 4
	}
	readRecords := func(count uint16) []discoveryTestRecord {
		records := []discoveryTestRecord{}
		for range count {
			record := discoveryTestRecord{}
			record.owner, at = discoveryTestName(t, message, at)
			record.rrtype = binary.BigEndian.Uint16(message[at : at+2])
			if class := binary.BigEndian.Uint16(message[at+2 : at+4]); class != 1 {
				t.Fatalf("a record of class %d", class)
			}
			record.ttl = binary.BigEndian.Uint32(message[at+4 : at+8])
			length := int(binary.BigEndian.Uint16(message[at+8 : at+10]))
			at += 10
			record.rdata = message[at : at+length]
			switch record.rrtype {
			case 12, 6:
				record.name, _ = discoveryTestName(t, message, at)
			case 33:
				record.port = binary.BigEndian.Uint16(message[at+4 : at+6])
				record.name, _ = discoveryTestName(t, message, at+6)
			}
			at += length
			records = append(records, record)
		}
		return records
	}
	response.answers = readRecords(binary.BigEndian.Uint16(message[6:8]))
	response.authorities = readRecords(binary.BigEndian.Uint16(message[8:10]))
	response.additionals = readRecords(binary.BigEndian.Uint16(message[10:12]))
	if at != len(message) {
		t.Fatalf("%d bytes after the records", len(message)-at)
	}
	return response
}

// A query whose labels are given whole, so an instance name may hold a dot or a space.
func discoveryTestQuery(id uint16, labels []string, qtype uint16, opt int) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range labels {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, byte(qtype>>8), byte(qtype), 0, 1)
	if 0 < opt {
		binary.BigEndian.PutUint16(message[10:12], 1)
		message = append(message, 0, 0, 41, byte(opt>>8), byte(opt), 0, 0, 0, 0, 0, 0)
	}
	return message
}

// The view the tests answer from: a printer below the laptop and a phone below the build box, both client names of
// zoneTestZone's table.
func discoveryTestInstances() []*device.BridgeDiscoveryInstance {
	return []*device.BridgeDiscoveryInstance{
		{
			Name:       "Synthetic Printer",
			Service:    "_ipp._tcp",
			Subtypes:   []string{"_universal"},
			Port:       631,
			Txt:        []byte("\x06rp=ipp\x07pdl=raw"),
			HostLabel:  "printer",
			ClientName: "laptop",
			Ipv4:       netip.MustParseAddr("100.80.200.10"),
		},
		{
			Name:       "Synthetic Phone.2",
			Service:    "_RemotePairing._tcp",
			Port:       49152,
			HostLabel:  "phone",
			ClientName: "build-box",
			Ipv4:       netip.MustParseAddr("100.80.200.11"),
		},
	}
}

// A resolver test whose zone holds the block 100.80/16 and whose view is instances.
func newDiscoveryTest(t *testing.T, instances []*device.BridgeDiscoveryInstance, edit func(settings *device.BridgeSettings)) *resolverTest {
	t.Helper()
	test := newResolverTest(t, true, edit)
	test.setUpstream(nil, func(query []byte) []byte {
		return resolverTestUpstreamAnswer(query)
	})
	test.zone.Store(zoneTestZone().WithBlocksForTest([]netip.Prefix{netip.MustParsePrefix("100.80.0.0/16")}))
	view, droppedCount := device.NewBridgeDiscoveryView(instances, nil)
	if droppedCount != 0 {
		t.Fatalf("%d instances dropped", droppedCount)
	}
	test.resolver.SetDiscoveryForTest(func() *device.BridgeDiscoveryView { return view })
	return test
}

// An upstream answer: the query echoed as a response with no record.
func resolverTestUpstreamAnswer(query []byte) []byte {
	response := slices.Clone(query)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	return response
}

// Asks labels of qtype over UDP and reads the answer.
func (self *resolverTest) askDiscovery(labels []string, qtype uint16, opt int) discoveryTestResponse {
	self.t.Helper()
	self.send(resolverTestUdp(5353, discoveryTestQuery(7, labels, qtype, opt)))
	transport := resolverTestReply(self.t, self.next(), 17)
	return discoveryTestRead(self.t, transport[8:])
}

// The names of records, sorted.
func discoveryTestNames(records []discoveryTestRecord) []string {
	names := []string{}
	for _, record := range records {
		names = append(names, record.name)
	}
	slices.Sort(names)
	return names
}

// Every form of §12.9.1's table, in both zones, answered on the device with 10 s TTLs; none reaches the upstream.
func TestBridgeDiscoveryAnswersEachForm(t *testing.T) {
	test := newDiscoveryTest(t, discoveryTestInstances(), nil)
	zone := []string{"acme", "ur", "example"}
	under := func(labels ...string) []string {
		return slices.Concat(labels, zone)
	}
	const (
		typeA    = 1
		typeSoa  = 6
		typePtr  = 12
		typeTxt  = 16
		typeAaaa = 28
		typeSrv  = 33
	)
	checkTtls := func(name string, response discoveryTestResponse) {
		for _, records := range [][]discoveryTestRecord{response.answers, response.authorities, response.additionals} {
			for _, record := range records {
				if record.ttl != 10 {
					t.Errorf("%s: a record of type %d at ttl %d", name, record.rrtype, record.ttl)
				}
			}
		}
		if response.flags&0x0400 == 0 {
			t.Errorf("%s: not authoritative", name)
		}
	}
	denied := func(name string, response discoveryTestResponse, rcode uint16) {
		t.Helper()
		checkTtls(name, response)
		if response.rcode != rcode || len(response.answers) != 0 {
			t.Errorf("%s: rcode %d with %d answers, want rcode %d and none", name, response.rcode, len(response.answers), rcode)
		}
		if len(response.authorities) != 1 || response.authorities[0].rrtype != typeSoa || response.authorities[0].owner != "acme.ur.example" {
			t.Errorf("%s: authority %+v, want the zone's SOA", name, response.authorities)
		}
	}

	for _, browse := range []string{"b", "db"} {
		response := test.askDiscovery(under(browse, "_dns-sd", "_udp"), typePtr, 0)
		checkTtls(browse, response)
		if names := discoveryTestNames(response.answers); !slices.Equal(names, []string{"acme.ur.example"}) {
			t.Errorf("%s names %v", browse, names)
		}
	}
	for _, empty := range []string{"lb", "r", "dr"} {
		denied(empty, test.askDiscovery(under(empty, "_dns-sd", "_udp"), typePtr, 0), 0)
	}
	services := test.askDiscovery(under("_services", "_dns-sd", "_udp"), typePtr, 0)
	checkTtls("services", services)
	if names := discoveryTestNames(services.answers); !slices.Equal(names, []string{"_ipp._tcp.acme.ur.example", "_remotepairing._tcp.acme.ur.example"}) {
		t.Errorf("_services names %v", names)
	}

	printers := test.askDiscovery(under("_ipp", "_tcp"), typePtr, 0)
	checkTtls("type", printers)
	if names := discoveryTestNames(printers.answers); !slices.Equal(names, []string{"Synthetic Printer._ipp._tcp.acme.ur.example"}) {
		t.Errorf("_ipp._tcp names %v", names)
	}
	if len(printers.additionals) != 3 {
		t.Errorf("a browse carries %d additionals, want the SRV, TXT and A", len(printers.additionals))
	}
	subtyped := test.askDiscovery(under("_universal", "_sub", "_ipp", "_tcp"), typePtr, 0)
	if names := discoveryTestNames(subtyped.answers); !slices.Equal(names, []string{"Synthetic Printer._ipp._tcp.acme.ur.example"}) {
		t.Errorf("the subtype names %v", names)
	}
	// an instance name holding a dot is one label, asked in any case
	phone := test.askDiscovery(under("SYNTHETIC phone.2", "_remotepairing", "_TCP"), typeSrv, 0)
	checkTtls("srv", phone)
	if len(phone.answers) != 1 || phone.answers[0].port != 49152 || phone.answers[0].name != "phone.build-box.acme.ur.example" {
		t.Errorf("the phone's SRV %+v", phone.answers)
	}
	if len(phone.additionals) != 1 || netip.AddrFrom4([4]byte(phone.additionals[0].rdata)) != netip.MustParseAddr("100.80.200.11") {
		t.Errorf("the phone's SRV additionals %+v", phone.additionals)
	}
	txt := test.askDiscovery(under("Synthetic Printer", "_ipp", "_tcp"), typeTxt, 0)
	if len(txt.answers) != 1 || string(txt.answers[0].rdata) != "\x06rp=ipp\x07pdl=raw" {
		t.Errorf("the printer's TXT %+v", txt.answers)
	}
	emptyTxt := test.askDiscovery(under("Synthetic phone.2", "_remotepairing", "_tcp"), typeTxt, 0)
	if len(emptyTxt.answers) != 1 || string(emptyTxt.answers[0].rdata) != "\x00" {
		t.Errorf("an instance with no TXT answers %+v, want one empty string", emptyTxt.answers)
	}
	address := test.askDiscovery(under("printer", "laptop"), typeA, 0)
	if len(address.answers) != 1 || netip.AddrFrom4([4]byte(address.answers[0].rdata)) != netip.MustParseAddr("100.80.200.10") {
		t.Errorf("the target's A %+v", address.answers)
	}
	denied("target aaaa", test.askDiscovery(under("printer", "laptop"), typeAaaa, 0), 0)
	denied("instance aaaa", test.askDiscovery(under("Synthetic Printer", "_ipp", "_tcp"), typeAaaa, 0), 0)
	denied("dns-sd non-terminal", test.askDiscovery(under("_dns-sd", "_udp"), typePtr, 0), 0)

	denied("no such type", test.askDiscovery(under("_http", "_tcp"), typePtr, 0), 3)
	denied("no such instance", test.askDiscovery(under("Elsewhere", "_ipp", "_tcp"), typeSrv, 0), 3)
	denied("no such subtype", test.askDiscovery(under("_scanner", "_sub", "_ipp", "_tcp"), typePtr, 0), 3)
	denied("no such target", test.askDiscovery(under("tablet", "laptop"), typeA, 0), 3)
	denied("below a target", test.askDiscovery(under("x", "printer", "laptop"), typeA, 0), 3)
	denied("another dns-sd name", test.askDiscovery(under("x", "_dns-sd", "_udp"), typePtr, 0), 3)

	alias := test.askDiscovery([]string{"b", "_dns-sd", "_udp", "alias", "example"}, typePtr, 0)
	if names := discoveryTestNames(alias.answers); !slices.Equal(names, []string{"alias.example"}) {
		t.Errorf("the alias zone's b names %v", names)
	}
	if queries := test.upstreamQueries(); len(queries) != 0 {
		t.Fatalf("%d DNS-SD queries reached the upstream", len(queries))
	}

	// the zone's own name and its private names stay as they were: the apex passes, a client name answers its A
	test.send(resolverTestUdp(5353, discoveryTestQuery(8, zone, typeA, 0)))
	test.next()
	if queries := test.upstreamQueries(); len(queries) != 1 {
		t.Errorf("the zone's apex reached the upstream %d times", len(queries))
	}
	test.send(resolverTestUdp(5353, discoveryTestQuery(10, under("laptop"), typeA, 0)))
	private := resolverTestReadAnswer(t, resolverTestReply(t, test.next(), 17)[8:])
	if !slices.Equal(private.addresses, []netip.Addr{netip.MustParseAddr("100.80.1.4")}) {
		t.Errorf("a private name answers %v", private.addresses)
	}
}

// The block's reverse zone (§12.9.1): b and db under the name RFC 6763 §11 derives name the zones, an assigned address's
// PTR its private name, every other name NXDOMAIN or, where it exists, NODATA; and none of it reaches the upstream,
// while another reverse name passes.
func TestBridgeDiscoveryAnswersTheReverseZone(t *testing.T) {
	test := newDiscoveryTest(t, discoveryTestInstances(), nil)
	reverse := []string{"80", "100", "in-addr", "arpa"}
	under := func(labels ...string) []string {
		return slices.Concat(labels, reverse)
	}
	browse := test.askDiscovery(under("b", "_dns-sd", "_udp", "0", "0"), 12, 0)
	if names := discoveryTestNames(browse.answers); !slices.Equal(names, []string{"acme.ur.example", "alias.example"}) {
		t.Errorf("b names %v", names)
	}
	if names := discoveryTestNames(test.askDiscovery(under("db", "_dns-sd", "_udp", "0", "0"), 12, 0).answers); len(names) != 2 {
		t.Errorf("db names %v", names)
	}
	assigned := test.askDiscovery(under("4", "1"), 12, 0)
	if names := discoveryTestNames(assigned.answers); !slices.Equal(names, []string{"laptop.acme.ur.example"}) {
		t.Errorf("an assigned address's PTR names %v", names)
	}
	cases := []struct {
		labels []string
		rcode  uint16
	}{
		{labels: under("5", "1"), rcode: 3},
		{labels: under("x", "1"), rcode: 3},
		{labels: under("b", "_dns-sd", "_udp", "1", "0"), rcode: 3},
		{labels: under("0", "0"), rcode: 0},
		{labels: under("_dns-sd", "_udp", "0", "0"), rcode: 0},
		{labels: under("1"), rcode: 0},
		{labels: reverse, rcode: 0},
		{labels: under("1", "2", "3"), rcode: 3},
	}
	for _, c := range cases {
		response := test.askDiscovery(c.labels, 12, 0)
		if response.rcode != c.rcode || len(response.answers) != 0 {
			t.Errorf("%v: rcode %d with %d answers, want %d", c.labels, response.rcode, len(response.answers), c.rcode)
		}
	}
	if queries := test.upstreamQueries(); len(queries) != 0 {
		t.Fatalf("%d reverse queries of the block reached the upstream", len(queries))
	}
	test.send(resolverTestUdp(5353, discoveryTestQuery(9, []string{"1", "2", "0", "192", "in-addr", "arpa"}, 12, 0)))
	test.next()
	if queries := test.upstreamQueries(); len(queries) != 1 {
		t.Fatalf("another reverse name reached the upstream %d times", len(queries))
	}
}

// A UDP answer past 512 B drops its additionals, then sets TC and carries no answer; an EDNS0 asker's size raises the
// bound to at most DiscoveryEdnsByteCount; TCP carries the whole.
func TestBridgeDiscoveryAnswersFitTheAskersSize(t *testing.T) {
	instances := []*device.BridgeDiscoveryInstance{}
	for i := range 40 {
		instances = append(instances, &device.BridgeDiscoveryInstance{
			Name:       "Synthetic Share " + strings.Repeat("x", 20) + string(rune('A'+i%26)) + string(rune('a'+i/26)),
			Service:    "_smb._tcp",
			Port:       445,
			HostLabel:  "nas",
			ClientName: "laptop",
			Ipv4:       netip.MustParseAddr("100.80.200.20"),
		})
	}
	test := newDiscoveryTest(t, instances, nil)
	labels := []string{"_smb", "_tcp", "acme", "ur", "example"}
	plain := test.askDiscovery(labels, 12, 0)
	if plain.flags&0x0200 == 0 || len(plain.answers) != 0 {
		t.Errorf("a 40-instance browse over plain UDP: TC %t with %d answers", plain.flags&0x0200 != 0, len(plain.answers))
	}
	// three answers fit 512 B, their nine additionals do not; under EDNS0's 1,232 B all fit
	few := newDiscoveryTest(t, instances[:3], nil)
	trimmed := few.askDiscovery(labels, 12, 0)
	if trimmed.flags&0x0200 != 0 || len(trimmed.answers) != 3 || len(trimmed.additionals) != 0 {
		t.Errorf("a 3-instance browse over plain UDP: TC %t, %d answers, %d additionals", trimmed.flags&0x0200 != 0, len(trimmed.answers), len(trimmed.additionals))
	}
	edns := few.askDiscovery(labels, 12, 4096)
	if edns.flags&0x0200 != 0 || len(edns.answers) != 3 || len(edns.additionals) != 9 {
		t.Errorf("a 3-instance browse over EDNS0: TC %t, %d answers, %d additionals", edns.flags&0x0200 != 0, len(edns.answers), len(edns.additionals))
	}

	// over TCP the whole answer arrives across segments
	query := discoveryTestQuery(11, labels, 12, 0)
	test.send(resolverTestTcp(40000, 100, 0, 0x02, nil))
	synAck := resolverTestReply(t, test.next(), 6)
	isn := binary.BigEndian.Uint32(synAck[4:8])
	test.send(resolverTestTcp(40000, 101, isn+1, 0x18, resolverTestFramed(query)))
	stream := []byte{}
	for {
		segment := resolverTestReply(t, test.next(), 6)
		stream = append(stream, segment[20:]...)
		if segment[13]&0x01 != 0 {
			break
		}
	}
	whole := discoveryTestRead(t, stream[2:])
	if whole.flags&0x0200 != 0 || len(whole.answers) != 40 {
		t.Errorf("over TCP: TC %t with %d answers", whole.flags&0x0200 != 0, len(whole.answers))
	}
}

// A view keeps only instances of its shape, the first of a name and type, and the first address of a target.
func TestBridgeDiscoveryViewKeepsOnlyItsShape(t *testing.T) {
	good := func() *device.BridgeDiscoveryInstance {
		return &device.BridgeDiscoveryInstance{
			Name: "Synthetic", Service: "_ssh._tcp", Port: 22, HostLabel: "box", ClientName: "laptop",
			Ipv4: netip.MustParseAddr("100.80.1.4"),
		}
	}
	faults := []func(instance *device.BridgeDiscoveryInstance){
		func(instance *device.BridgeDiscoveryInstance) { instance.Name = "" },
		func(instance *device.BridgeDiscoveryInstance) { instance.Name = strings.Repeat("n", 64) },
		func(instance *device.BridgeDiscoveryInstance) { instance.Name = "a\x00b" },
		func(instance *device.BridgeDiscoveryInstance) { instance.Service = "_ssh" },
		func(instance *device.BridgeDiscoveryInstance) { instance.Service = "ssh._tcp" },
		func(instance *device.BridgeDiscoveryInstance) { instance.Subtypes = []string{"a.b"} },
		func(instance *device.BridgeDiscoveryInstance) { instance.Port = 0 },
		func(instance *device.BridgeDiscoveryInstance) { instance.Txt = []byte{5, 'a'} },
		func(instance *device.BridgeDiscoveryInstance) { instance.HostLabel = "box.lan" },
		func(instance *device.BridgeDiscoveryInstance) { instance.ClientName = "" },
		func(instance *device.BridgeDiscoveryInstance) { instance.Ipv4 = netip.MustParseAddr("2001:db8::1") },
	}
	instances := []*device.BridgeDiscoveryInstance{good()}
	for _, fault := range faults {
		instance := good()
		instance.Name = "Fault " + string(rune('a'+len(instances)))
		fault(instance)
		instances = append(instances, instance)
	}
	sameName := good()
	sameName.Name = "SYNTHETIC"
	moved := good()
	moved.Name = "Other"
	moved.Ipv4 = netip.MustParseAddr("100.80.1.5")
	instances = append(instances, sameName, moved, nil)
	view, droppedCount := device.NewBridgeDiscoveryView(instances, nil)
	if view.InstanceCount() != 1 || droppedCount != len(faults)+3 {
		t.Fatalf("the view holds %d and dropped %d", view.InstanceCount(), droppedCount)
	}
	settings := device.DefaultBridgeSettings()
	settings.DiscoveryInstanceCount = 1
	other := good()
	other.Name = "Second"
	if view, droppedCount := device.NewBridgeDiscoveryView([]*device.BridgeDiscoveryInstance{good(), other}, settings); view.InstanceCount() != 1 || droppedCount != 1 {
		t.Fatalf("past the cap the view holds %d and dropped %d", view.InstanceCount(), droppedCount)
	}
}

// On app paths the LocalZone owns §12.9.1's names and answers each NODATA (owner decision 778): owned, with no address,
// at DiscoveryTtl; what lies outside those forms is untouched.
func TestBridgeZoneOwnsDiscoveryNamesAsNodata(t *testing.T) {
	zone := zoneTestZone()
	owned := []string{
		"b._dns-sd._udp.acme.ur.example",
		"lb._dns-sd._udp.acme.ur.example",
		"_dns-sd._udp.acme.ur.example",
		"_services._dns-sd._udp.alias.example",
		"_ipp._tcp.acme.ur.example",
		"Synthetic Printer._ipp._tcp.acme.ur.example",
		"_universal._sub._ipp._tcp.acme.ur.example",
		"printer.laptop.acme.ur.example",
		"x.y.build-box.acme.ur.example",
	}
	for _, host := range owned {
		for _, qtype := range []uint16{1, 12, 28, 33} {
			addrs, ttl, isOwned := zone.Answer(host, qtype)
			if !isOwned || len(addrs) != 0 || ttl != 10 {
				t.Errorf("%s %d: owned %t with %v at %d", host, qtype, isOwned, addrs, ttl)
			}
		}
	}
	passed := []string{
		"_udp.acme.ur.example",
		"_tcp.acme.ur.example",
		"www.acme.ur.example",
		"_x._tcp.www.acme.ur.example",
		"printer.desk.acme.ur.example",
		"b._dns-sd._udp.other.example",
	}
	for _, host := range passed {
		if _, _, isOwned := zone.Answer(host, 12); isOwned {
			t.Errorf("%s is owned", host)
		}
	}
	if addrs, _, isOwned := zone.Answer("laptop.acme.ur.example", 1); !isOwned || len(addrs) != 1 {
		t.Errorf("a private name answers %v, %t", addrs, isOwned)
	}
}
