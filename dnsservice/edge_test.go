package dnsservice_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The edge tests' root, and visibly synthetic KSK and ZSK scalars. No key here signs anything outside
// tests.
const (
	edgeTestRoot      = "zone.example."
	edgeTestKskHex    = "5555555555555555555555555555555555555555555555555555555555555555"
	edgeTestZskHex    = "6666666666666666666666666666666666666666666666666666666666666666"
	edgeTestOtherHex  = "7777777777777777777777777777777777777777777777777777777777777777"
	edgeTestSoaRdata  = "ns1.zone.example. hostmaster.zone.example. 1 7200 3600 1209600 60"
	edgeTestUserV4    = "11.22.33.44"
	edgeTestHealthyV4 = "192.0.2.10"
)

func edgeTestKey(t testing.TB, scalarHex string) *ecdsa.PrivateKey {
	t.Helper()
	scalar, err := hex.DecodeString(scalarHex)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func edgeTestDnskey(t testing.TB, root string, flags uint16, key *ecdsa.PrivateKey) *dns.DNSKEY {
	t.Helper()
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: root, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: base64.StdEncoding.EncodeToString(point[1:]),
	}
}

func edgeTestRdata(record dns.RR) string {
	return strings.TrimPrefix(record.String(), record.Header().String())
}

// A KSK, a ZSK and the window the KSK signed over both.
type edgeTestKeys struct {
	ksk       *ecdsa.PrivateKey
	zsk       *ecdsa.PrivateKey
	kskRecord *dns.DNSKEY
	zskRecord *dns.DNSKEY
	window    *dnsservice.DnsKeyWindow
	anchors   []*dns.DNSKEY
}

// A window over records, current from notBefore to notAfter, signed by signer.
func edgeTestWindow(t testing.TB, root string, notBefore time.Time, notAfter time.Time, signer *ecdsa.PrivateKey, records ...*dns.DNSKEY) *dnsservice.DnsKeyWindow {
	t.Helper()
	rrset := []dns.RR{}
	dnskeys := []string{}
	for _, record := range records {
		rrset = append(rrset, record)
		dnskeys = append(dnskeys, edgeTestRdata(record))
	}
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: root, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ECDSAP256SHA256,
		KeyTag:     records[0].KeyTag(),
		SignerName: root,
		Inception:  uint32(notBefore.Unix()),
		Expiration: uint32(notAfter.Unix()),
	}
	if err := rrsig.Sign(signer, rrset); err != nil {
		t.Fatal(err)
	}
	return &dnsservice.DnsKeyWindow{Root: root, NotBefore: notBefore, NotAfter: notAfter, Dnskeys: dnskeys, Rrsigs: []string{edgeTestRdata(rrsig)}}
}

// Keys whose 14-day window started a day before start.
func newEdgeTestKeys(t testing.TB, root string, start time.Time) *edgeTestKeys {
	t.Helper()
	self := &edgeTestKeys{ksk: edgeTestKey(t, edgeTestKskHex), zsk: edgeTestKey(t, edgeTestZskHex)}
	self.kskRecord = edgeTestDnskey(t, root, dns.ZONE|dns.SEP, self.ksk)
	self.zskRecord = edgeTestDnskey(t, root, dns.ZONE, self.zsk)
	self.window = edgeTestWindow(t, root, start.Add(-24*time.Hour), start.Add(13*24*time.Hour), self.ksk, self.kskRecord, self.zskRecord)
	self.anchors = []*dns.DNSKEY{self.kskRecord}
	return self
}

func (self *edgeTestKeys) keySet() *dnsservice.DnsKeySet {
	return &dnsservice.DnsKeySet{Window: self.window, Zsk: self.zsk}
}

// Valid settings for edgeTestRoot: generous signing, RRL at two a second with no debt, one UDP reader so
// packets are answered in the order sent, and two connections a source.
func edgeTestSettings(t testing.TB) *dnsservice.DnsSettings {
	t.Helper()
	settings := dnsservice.DefaultDnsSettings()
	settings.Roots = []string{edgeTestRoot}
	settings.SignaturesPerSecond = 1000
	settings.Tcp.ConnectionsPerSource = 2
	settings.Rrl.ResponsesPerSecond = 2
	settings.Rrl.WindowSeconds = 0
	settings.Edge.UdpReaderCount = 1
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	return settings
}

// An apex, a network with a wildcard, and a user's host.
func edgeTestRows() []dnsservice.DnsRecordSet {
	return []dnsservice.DnsRecordSet{
		{Owner: edgeTestRoot, Type: dns.TypeSOA, Ttl: 3600, Kind: dnsservice.DnsRecordKindSystem, Rdata: []string{edgeTestSoaRdata}},
		{Owner: edgeTestRoot, Type: dns.TypeNS, Ttl: 86400, Kind: dnsservice.DnsRecordKindSystem, Rdata: []string{"ns1.zone.example."}},
		{Owner: "*.net1." + edgeTestRoot, Type: dns.TypeA, Ttl: 60, Kind: dnsservice.DnsRecordKindEdge},
		{Owner: "*.net1." + edgeTestRoot, Type: dns.TypeMX, Ttl: 300, Kind: dnsservice.DnsRecordKindSystem, Rdata: []string{"10 mx.net1.zone.example."}},
		{Owner: "www.net1." + edgeTestRoot, Type: dns.TypeA, Ttl: 300, Kind: dnsservice.DnsRecordKindUser, Rdata: []string{edgeTestUserV4}},
	}
}

func edgeTestView(t testing.TB, settings *dnsservice.DnsSettings, serial uint64, rows []dnsservice.DnsRecordSet) *dnsservice.ZoneView {
	t.Helper()
	snapshot := dnsservice.DnsSnapshot{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: serial}
	view, err := dnsservice.NewZoneView(settings, dnsservice.NewDnsSnapshotRows(snapshot, rows))
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// Every line a Logger was given, for CC4's scan.
type capturingLog struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *capturingLog) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *capturingLog) all() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.lines...)
}

// Every level on, so a guarded call reaches the capture too.
type capturingVerbose struct {
	log *capturingLog
}

func (self capturingVerbose) Enabled() bool    { return true }
func (self capturingVerbose) Info(args ...any) { self.log.add(fmt.Sprint(args...)) }
func (self capturingVerbose) Infof(format string, args ...any) {
	self.log.add(fmt.Sprintf(format, args...))
}

// One edge on fakes, with its keys.
type testEdge struct {
	edge     *dnsservice.DnsEdge
	host     *sidecartest.FakeHost
	clock    *sidecartest.FakeClock
	keys     *edgeTestKeys
	settings *dnsservice.DnsSettings
	log      *edgeTestLogger
}

func newTestEdge(t testing.TB, settings *dnsservice.DnsSettings) *testEdge {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	log := &edgeTestLogger{capture: &capturingLog{}}
	edge, err := dnsservice.NewDnsEdge(t.Context(), host.ServiceHost(), settings, &dnsservice.DnsEdgeDeps{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(edge.Close)
	return &testEdge{
		edge:     edge,
		host:     host,
		clock:    clock,
		keys:     newEdgeTestKeys(t, edgeTestRoot, sidecartest.DefaultClockStart()),
		settings: settings,
		log:      log,
	}
}

// Self-checks view with the edge's keys and serves it.
func (self *testEdge) publish(t testing.TB, view *dnsservice.ZoneView) {
	t.Helper()
	keys, err := dnsservice.SelfCheck(view, self.keys.keySet(), self.keys.anchors, self.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	self.edge.PublishForTest(view, keys)
}

// A sidecar.Logger over a capture.
type edgeTestLogger struct {
	capture *capturingLog
}

func (self *edgeTestLogger) Info(args ...any) { self.capture.add(fmt.Sprint(args...)) }
func (self *edgeTestLogger) Infof(format string, args ...any) {
	self.capture.add(fmt.Sprintf(format, args...))
}
func (self *edgeTestLogger) Warningf(format string, args ...any) {
	self.capture.add(fmt.Sprintf(format, args...))
}
func (self *edgeTestLogger) Errorf(format string, args ...any) {
	self.capture.add(fmt.Sprintf(format, args...))
}
func (self *edgeTestLogger) V(level int32) sidecar.Verbose {
	return capturingVerbose{log: self.capture}
}

// One datagram and its peer.
type testPacket struct {
	data []byte
	addr net.Addr
}

// A net.PacketConn in memory: a test hands it datagrams from any source it likes and reads the edge's
// replies in the order written.
type testPacketConn struct {
	inbound   chan testPacket
	outbound  chan testPacket
	closed    chan struct{}
	closeOnce sync.Once
}

func newTestPacketConn() *testPacketConn {
	return &testPacketConn{
		inbound:  make(chan testPacket),
		outbound: make(chan testPacket, 1024),
		closed:   make(chan struct{}),
	}
}

func (self *testPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case packet := <-self.inbound:
		return copy(buffer, packet.data), packet.addr, nil
	case <-self.closed:
		return 0, nil, net.ErrClosed
	}
}

func (self *testPacketConn) WriteTo(buffer []byte, addr net.Addr) (int, error) {
	self.outbound <- testPacket{data: append([]byte{}, buffer...), addr: addr}
	return len(buffer), nil
}

func (self *testPacketConn) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

func (self *testPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}
}

func (self *testPacketConn) SetDeadline(deadline time.Time) error      { return nil }
func (self *testPacketConn) SetReadDeadline(deadline time.Time) error  { return nil }
func (self *testPacketConn) SetWriteDeadline(deadline time.Time) error { return nil }

// Serves conn on the edge until the test ends.
func (self *testEdge) serveUdp(t testing.TB) *testPacketConn {
	t.Helper()
	conn := newTestPacketConn()
	done := make(chan struct{})
	go func() {
		defer close(done)
		self.edge.ServePacket(conn)
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	return conn
}

// Sends message from source.
func (self *testPacketConn) send(t testing.TB, message *dns.Msg, source string) {
	t.Helper()
	data, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	self.sendBytes(t, data, source)
}

func (self *testPacketConn) sendBytes(t testing.TB, data []byte, source string) {
	t.Helper()
	addr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(source), 5353))
	select {
	case self.inbound <- testPacket{data: data, addr: addr}:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
}

// The next reply the edge wrote.
func (self *testPacketConn) receive(t testing.TB) (*dns.Msg, net.Addr) {
	t.Helper()
	select {
	case packet := <-self.outbound:
		reply := &dns.Msg{}
		if err := reply.Unpack(packet.data); err != nil {
			t.Fatal(err)
		}
		return reply, packet.addr
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	return nil, nil
}

// Whether the edge wrote anything not yet received.
func (self *testPacketConn) pending() int {
	return len(self.outbound)
}

// A query with EDNS at 1232, DO as asked, and a fixed id.
func edgeTestQuery(name string, rrType uint16, signed bool) *dns.Msg {
	message := &dns.Msg{}
	message.Id = 4242
	message.SetQuestion(name, rrType)
	message.SetEdns0(1232, signed)
	return message
}

// Every RRSIG in reply verifies with the edge's ZSK, and nothing is unsigned.
func (self *testEdge) wantSigned(t testing.TB, reply *dns.Msg) {
	t.Helper()
	signed := 0
	for _, section := range [][]dns.RR{reply.Answer, reply.Ns} {
		data := map[string][]dns.RR{}
		for _, record := range section {
			if _, ok := record.(*dns.RRSIG); !ok {
				key := dns.CanonicalName(record.Header().Name) + " " + dns.TypeToString[record.Header().Rrtype]
				data[key] = append(data[key], record)
			}
		}
		for _, record := range section {
			rrsig, ok := record.(*dns.RRSIG)
			if !ok {
				continue
			}
			key := dns.CanonicalName(rrsig.Hdr.Name) + " " + dns.TypeToString[rrsig.TypeCovered]
			if err := rrsig.Verify(self.keys.zskRecord, data[key]); err != nil {
				t.Errorf("%s: %v", key, err)
			}
			if !rrsig.ValidityPeriod(self.clock.Now()) {
				t.Errorf("%s: not current", key)
			}
			delete(data, key)
			signed += 1
		}
		if len(data) != 0 {
			t.Errorf("unsigned: %v", data)
		}
	}
	if signed == 0 {
		t.Errorf("nothing signed: %v", reply)
	}
}

// A fresh edge serves nothing: not ready, and a query for its root gets no answer at all.
func TestEdgeServesNothingBeforeACheckedView(t *testing.T) {
	edge := newTestEdge(t, edgeTestSettings(t))
	conn := edge.serveUdp(t)
	if edge.edge.Ready() {
		t.Fatal("ready with no view")
	}
	conn.send(t, edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, true), "192.0.2.1")
	// a name in no root is still refused, which tells the first packet was read and dropped
	conn.send(t, edgeTestQuery("www.other.example.", dns.TypeA, true), "192.0.2.1")
	reply, _ := conn.receive(t)
	if reply.Rcode != dns.RcodeRefused || reply.Question[0].Name != "www.other.example." || conn.pending() != 0 {
		t.Errorf("before a view %v", reply)
	}
	if dropped := edge.host.Metrics.Value("urnetwork_dnsedge_dropped_total", "not_ready"); dropped != 1 {
		t.Errorf("dropped %v", dropped)
	}

	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	if !edge.edge.Ready() {
		t.Fatal("not ready with a checked view")
	}
	if serial, _ := edge.edge.ServedSerial(edgeTestRoot); serial != 7 {
		t.Errorf("served serial %d", serial)
	}
	conn.send(t, edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, true), "192.0.2.1")
	reply, _ = conn.receive(t)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 2 || !reply.Authoritative {
		t.Fatalf("after a view %v", reply)
	}
	edge.wantSigned(t, reply)
}

// Over UDP the edge answers from its view: signed under DO, plain without, the healthy set's addresses
// for a wildcard's edge row, FORMERR for a header with nothing behind it, and nothing for a response.
func TestEdgeAnswersUdpFromItsView(t *testing.T) {
	settings := edgeTestSettings(t)
	settings.Rrl.ResponsesPerSecond = 1000
	edge := newTestEdge(t, settings)
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	edge.edge.SetHealthySet(dnsservice.NewHealthySet([]dnsservice.DnsLbInterface{{Name: "lb-1", Ipv4: netip.MustParseAddr(edgeTestHealthyV4)}}, nil))
	conn := edge.serveUdp(t)

	conn.send(t, edgeTestQuery("anything.net1."+edgeTestRoot, dns.TypeA, true), "192.0.2.1")
	reply, addr := conn.receive(t)
	if len(reply.Answer) != 2 || reply.Answer[0].(*dns.A).A.String() != edgeTestHealthyV4 {
		t.Fatalf("a wildcard %v", reply)
	}
	if addr.String() != "192.0.2.1:5353" {
		t.Errorf("answered to %v", addr)
	}
	edge.wantSigned(t, reply)

	conn.send(t, edgeTestQuery("nosuch."+edgeTestRoot, dns.TypeA, true), "192.0.2.1")
	reply, _ = conn.receive(t)
	if reply.Rcode != dns.RcodeSuccess || len(reply.Ns) != 4 {
		t.Fatalf("a compact denial %v", reply)
	}
	edge.wantSigned(t, reply)

	conn.send(t, edgeTestQuery("nosuch."+edgeTestRoot, dns.TypeA, false), "192.0.2.1")
	reply, _ = conn.receive(t)
	if reply.Rcode != dns.RcodeNameError || len(reply.Ns) != 1 {
		t.Errorf("a plain denial %v", reply)
	}

	conn.sendBytes(t, []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, "192.0.2.1")
	reply, _ = conn.receive(t)
	if reply.Rcode != dns.RcodeFormatError || reply.Id != 0x1234 {
		t.Errorf("a header with no question %v", reply)
	}

	response := edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, false)
	response.Response = true
	conn.send(t, response, "192.0.2.1")
	conn.sendBytes(t, []byte{1, 2, 3}, "192.0.2.1")
	conn.send(t, edgeTestQuery("www.other.example.", dns.TypeA, false), "192.0.2.1")
	if reply, _ = conn.receive(t); reply.Rcode != dns.RcodeRefused || conn.pending() != 0 {
		t.Errorf("after a response and a fragment %v", reply)
	}
	if dropped := edge.host.Metrics.Value("urnetwork_dnsedge_dropped_total", "malformed"); dropped != 1 {
		t.Errorf("malformed %v", dropped)
	}
}

// RRL over UDP: a flood from one /24 is dropped, every second drop slipping out empty with TC, while
// another /24 and the flooding /24's other classes are answered.
func TestEdgeRrlLimitsAFloodAndNoOneElse(t *testing.T) {
	settings := edgeTestSettings(t)
	settings.Rrl.Slip = 2
	edge := newTestEdge(t, settings)
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	conn := edge.serveUdp(t)
	query := edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, true)

	// two answers, then drop, slip, drop, slip
	for range 6 {
		conn.send(t, query, "192.0.2.77")
	}
	// another /24, after the flood, answered whole: so every flood packet before it was decided
	conn.send(t, query, "198.51.100.5")
	answered, slipped := 0, 0
	for {
		reply, addr := conn.receive(t)
		if addr.String() == "198.51.100.5:5353" {
			if len(reply.Answer) != 2 || reply.Truncated {
				t.Errorf("the other /24 %v", reply)
			}
			break
		}
		if reply.Truncated && len(reply.Answer) == 0 && len(reply.Ns) == 0 {
			slipped += 1
		} else {
			answered += 1
		}
	}
	if answered != 2 || slipped != 2 || conn.pending() != 0 {
		t.Errorf("answered %d, slipped %d", answered, slipped)
	}
	// the flooding /24's denials have their own bucket
	conn.send(t, edgeTestQuery("nosuch."+edgeTestRoot, dns.TypeA, true), "192.0.2.78")
	if reply, _ := conn.receive(t); reply.Rcode != dns.RcodeSuccess || len(reply.Ns) == 0 {
		t.Errorf("a denial from the flooding /24 %v", reply)
	}
	metrics := edge.host.Metrics
	if metrics.Value("urnetwork_dnsedge_rrl_limited_total", "answer", "drop") != 2 ||
		metrics.Value("urnetwork_dnsedge_rrl_limited_total", "answer", "slip") != 2 {
		t.Errorf("rrl metrics %v", metrics.Dump())
	}
	// a second later the bucket has earned two more
	edge.clock.Advance(time.Second)
	conn.send(t, query, "192.0.2.77")
	if reply, _ := conn.receive(t); len(reply.Answer) != 2 {
		t.Errorf("after a second %v", reply)
	}
}

// I-12: the edge takes no store and touches no Redis on the serving path. Its constructor has no
// store to take, and a whole serving run leaves the host's Redis uncalled. DenyPostgresForTest is
// server's, and DNS-M5-18 runs the edge process under it.
func TestEdgeServesWithNoStoreAndNoRedis(t *testing.T) {
	settings := edgeTestSettings(t)
	settings.Rrl.ResponsesPerSecond = 1000
	edge := newTestEdge(t, settings)
	edge.host.Redis.ResetOpCounts()
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	conn := edge.serveUdp(t)
	for _, name := range []string{"www.net1.", "nosuch.", "x.net1.", ""} {
		conn.send(t, edgeTestQuery(name+edgeTestRoot, dns.TypeA, true), "192.0.2.1")
		conn.receive(t)
	}
	if counts := edge.host.Redis.OpCounts(); len(counts) != 0 {
		t.Errorf("redis calls %v", counts)
	}
}

// CC4 (§22.7) at the edge: random names driven through it, every way it answers, reach neither its
// logs nor its metrics, and neither does any resolver's address.
func TestEdgeLogsAndCountsNoNameOrAddress(t *testing.T) {
	settings := edgeTestSettings(t)
	settings.Rrl.Slip = 1
	edge := newTestEdge(t, settings)
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	conn := edge.serveUdp(t)
	canaries := []string{}
	sources := []string{"192.0.2.31", "198.51.100.32", "2001:db8:31::1"}
	for index := range 40 {
		label := fmt.Sprintf("canary%08x", 0x5eed0000+index)
		canaries = append(canaries, label)
		name := label + ".net1." + edgeTestRoot
		if index%3 == 0 {
			name = label + "." + edgeTestRoot
		}
		conn.send(t, edgeTestQuery(name, dns.TypeA, index%2 == 0), sources[index%len(sources)])
	}
	conn.send(t, edgeTestQuery("www.other.example.", dns.TypeA, false), "203.0.113.200")
	for {
		reply, addr := conn.receive(t)
		if addr.String() == "203.0.113.200:5353" && reply.Rcode == dns.RcodeRefused {
			break
		}
	}
	haystack := strings.Join(append(edge.log.capture.all(), edge.host.Metrics.Dump()...), "\n")
	for _, needle := range append(canaries, sources...) {
		if strings.Contains(strings.ToLower(haystack), strings.ToLower(needle)) {
			t.Errorf("%s reached a log or a metric", needle)
		}
	}
	if violations := edge.host.Metrics.Violations(); len(violations) != 0 {
		t.Errorf("metric violations %v", violations)
	}
}

// An edge serves only roots it was given; a view of another root is ignored.
func TestEdgeIgnoresAViewOfAnotherRoot(t *testing.T) {
	edge := newTestEdge(t, edgeTestSettings(t))
	otherSettings := edgeTestSettings(t)
	otherSettings.Roots = []string{"other.example."}
	snapshot := dnsservice.DnsSnapshot{Format: dnsservice.DnsFormat, Root: "other.example.", Serial: 3}
	view, err := dnsservice.NewZoneView(otherSettings, dnsservice.NewDnsSnapshotRows(snapshot, []dnsservice.DnsRecordSet{{
		Owner: "other.example.", Type: dns.TypeSOA, Ttl: 3600, Kind: dnsservice.DnsRecordKindSystem,
		Rdata: []string{"ns1.other.example. hostmaster.other.example. 1 7200 3600 1209600 60"},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	keys := newEdgeTestKeys(t, "other.example.", sidecartest.DefaultClockStart())
	checked, err := dnsservice.SelfCheck(view, keys.keySet(), keys.anchors, edge.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	edge.edge.PublishForTest(view, checked)
	if edge.edge.Ready() {
		t.Error("ready on another root's view")
	}
	if serial, changed := edge.edge.ServedSerial("other.example."); serial != 0 || changed == nil {
		t.Errorf("another root's serial %d", serial)
	}
}
