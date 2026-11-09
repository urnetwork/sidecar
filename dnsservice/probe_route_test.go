package dnsservice_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// The probe name of the versions these tests report.
const (
	routeTestProbeName      = "0123456789ab.map.probe.invalid"
	routeTestOtherProbeName = "ba9876543210.map.probe.invalid"
)

// One hello the fake lb read, as tlsedge's own parser reads it.
type routeTestHello struct {
	address    netip.AddrPort
	serverName string
	alpnIds    []string
}

// A DnsProbeDialer standing in for the lb's split on every interface: tlsedge's code answers a hello
// whose name the map routes to it, and a probe of probe.edge.<root>, which the wildcard routes there;
// crypto/tls answers every other hello as the http branch does, selecting http/1.1 and presenting the
// platform certificate. It records each hello and any byte a probe sends after one.
type routeTestLb struct {
	certificate tls.Certificate

	stateLock      sync.Mutex
	routedNames    map[string]bool
	hellos         []routeTestHello
	extraByteCount int64
}

func newRouteTestLb(t *testing.T, routedNames ...string) *routeTestLb {
	self := &routeTestLb{certificate: probeTestCertificate(t), routedNames: map[string]bool{}}
	self.route(routedNames...)
	return self
}

// Adds names to the map, as a reload that loads them does.
func (self *routeTestLb) route(names ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, name := range names {
		self.routedNames[name] = true
	}
}

// The route probes read since the last call, by name.
func (self *routeTestLb) takeRouteHellos() []routeTestHello {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	routeHellos := []routeTestHello{}
	for _, hello := range self.hellos {
		if slices.Contains(hello.alpnIds, dnsservice.DnsRouteProbeAlpn) {
			routeHellos = append(routeHellos, hello)
		}
	}
	self.hellos = nil
	return routeHellos
}

// A conn that reads bytes already taken from it first.
type routeTestReplayConn struct {
	net.Conn
	reader io.Reader
}

func (self *routeTestReplayConn) Read(buffer []byte) (int, error) {
	return self.reader.Read(buffer)
}

func (self *routeTestLb) DialProbe(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		hello, err := tlsedgeservice.ReadClientHello(server, 16*1024)
		if err != nil {
			return
		}
		routed := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.hellos = append(self.hellos, routeTestHello{address: address, serverName: hello.ServerName, alpnIds: hello.AlpnIds})
			return self.routedNames[hello.ServerName] || strings.HasPrefix(hello.ServerName, "probe.edge.")
		}()
		if routed {
			// tlsedge: a route probe or a reserved probe.edge name gets unrecognized_name, before any lookup
			tlsedgeservice.WriteTlsAlert(server, tlsedgeservice.TlsAlertUnrecognizedName)
		} else {
			replay := &routeTestReplayConn{Conn: server, reader: io.MultiReader(strings.NewReader(string(hello.RawBytes)), server)}
			tls.Server(replay, &tls.Config{Certificates: []tls.Certificate{self.certificate}, NextProtos: []string{"http/1.1"}}).Handshake()
		}
		extraByteCount, _ := io.Copy(io.Discard, server)
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.extraByteCount += extraByteCount
	}()
	return client, nil
}

// Takes every report, or refuses each while refusing is set.
type routeTestSink struct {
	stateLock sync.Mutex
	refusing  bool
	reports   []*dnsservice.DnsRouteProbeReport
	refused   int
}

func (self *routeTestSink) RouteProbes(ctx context.Context, report *dnsservice.DnsRouteProbeReport) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.refusing {
		self.refused += 1
		return errors.New("refused")
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	decoded, err := dnsservice.DecodeDnsRouteProbeReport(data)
	if err != nil {
		return err
	}
	self.reports = append(self.reports, decoded)
	return nil
}

func (self *routeTestSink) setRefusing(refusing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusing = refusing
}

// The reports taken since the last call.
func (self *routeTestSink) take() []*dnsservice.DnsRouteProbeReport {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reports := self.reports
	self.reports = nil
	return reports
}

// A prober with route probes on, over lb and sink, on a fake clock.
type routeTestProber struct {
	prober   *dnsservice.Prober
	host     *sidecartest.FakeHost
	clock    *sidecartest.FakeClock
	settings *dnsservice.DnsSettings

	stateLock sync.Mutex
	healthy   []*dnsservice.HealthySet
}

// Every set the prober published.
func (self *routeTestProber) published() []*dnsservice.HealthySet {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.healthy)
}

func newRouteTestProber(t *testing.T, lb *routeTestLb, sink dnsservice.DnsRouteProbeSink) *routeTestProber {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	self := &routeTestProber{
		host:     sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil),
		clock:    clock,
		settings: probeTestSettings(t),
	}
	prober, err := dnsservice.NewProber(t.Context(), self.host.ServiceHost(), self.settings,
		&dnsservice.ProberDeps{Dialer: lb, RouteProbes: sink},
		func(healthy *dnsservice.HealthySet) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.healthy = append(self.healthy, healthy)
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prober.Close)
	self.prober = prober
	self.awaitRounds(t, 1)
	return self
}

func (self *routeTestProber) awaitRounds(t *testing.T, count int) {
	t.Helper()
	for {
		current, changed := self.prober.Rounds()
		if count <= current {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("rounds %d, want %d", current, count)
		}
	}
}

// Moves the clock to the next round and waits for it, its report included.
func (self *routeTestProber) round(t *testing.T) {
	t.Helper()
	count, _ := self.prober.Rounds()
	self.clock.Advance(time.Duration(self.settings.Probe.IntervalSeconds) * time.Second)
	self.awaitRounds(t, count+1)
}

// One interface reporting version with its probe name and added hosts, on documentation addresses.
func routeTestInterface(name string, last byte, version uint64, probeName string, addedHosts ...string) dnsservice.DnsLbInterface {
	return dnsservice.DnsLbInterface{
		Name:            name,
		Ipv4:            netip.AddrFrom4([4]byte{192, 0, 2, last}),
		Ipv6:            netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: last}),
		ReportedVersion: version,
		ProbeName:       probeName,
		AddedHosts:      addedHosts,
	}
}

// The names hellos asked for, sorted.
func routeTestNames(hellos []routeTestHello) []string {
	names := []string{}
	for _, hello := range hellos {
		names = append(names, hello.serverName)
	}
	slices.Sort(names)
	return names
}

// The hello offers ur-route-probe then http/1.1, in that order, for the name asked, as crypto/tls reads
// it, and tlsedge's own parser reads it as a route probe.
func TestRouteProbeHelloOffersBothAlpnIdsInOrder(t *testing.T) {
	hello, err := dnsservice.RouteProbeClientHelloForTest("shop.customer.example")
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	infos := make(chan *tls.ClientHelloInfo, 1)
	go func() {
		defer server.Close()
		tls.Server(server, &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			infos <- info
			return nil, errors.New("seen")
		}}).Handshake()
	}()
	go io.Copy(io.Discard, client)
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case info := <-infos:
		if info.ServerName != "shop.customer.example" || !slices.Equal(info.SupportedProtos, []string{"ur-route-probe", "http/1.1"}) {
			t.Errorf("crypto/tls read %q offering %q", info.ServerName, info.SupportedProtos)
		}
	case <-t.Context().Done():
		t.Fatal("crypto/tls read no hello")
	}
	parsed, err := tlsedgeservice.ReadClientHello(strings.NewReader(string(hello)), 16*1024)
	if err != nil || !parsed.OffersRouteProbe() || parsed.ServerName != "shop.customer.example" {
		t.Errorf("tlsedge read %v %v", parsed, err)
	}
	if dnsservice.DnsRouteProbeAlpn != "ur-route-probe" {
		t.Errorf("%q", dnsservice.DnsRouteProbeAlpn)
	}
	// the interface probe's hello offers no ALPN, so tlsedge reads it as no route probe
	plain, err := dnsservice.ProbeClientHelloForTest("probe.edge.zone.example")
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := tlsedgeservice.ReadClientHello(strings.NewReader(string(plain)), 16*1024); err != nil || parsed.OffersRouteProbe() || len(parsed.AlpnIds) != 0 {
		t.Errorf("the interface probe's hello: %v %v", parsed, err)
	}
}

// tlsedge's alert passes a route probe and the http branch's ServerHello fails one, and neither moves
// the healthy set: a route probe's result is the block's to judge. Every probe sends its hello and
// nothing after.
func TestRouteProbesPassOnTlsedgesAlertAndFailOnTheHttpBranch(t *testing.T) {
	lb := newRouteTestLb(t, routeTestProbeName, "routed.customer.example")
	sink := &routeTestSink{}
	prober := newRouteTestProber(t, lb, sink)
	prober.prober.SetInterfaces([]dnsservice.DnsLbInterface{
		routeTestInterface("lb-1", 1, 7, routeTestProbeName, "routed.customer.example", "missing.customer.example"),
		routeTestInterface("lb-2", 2, 6, routeTestOtherProbeName),
	})
	for range prober.settings.Probe.FailureCount + 1 {
		prober.round(t)
	}
	reports := sink.take()
	if len(reports) != prober.settings.Probe.FailureCount+1 {
		t.Fatalf("%d reports", len(reports))
	}
	first := reports[0]
	if first.Format != dnsservice.DnsFormat || len(first.Interfaces) != 2 {
		t.Fatalf("report %+v", first)
	}
	lb1, lb2 := first.Interfaces[0], first.Interfaces[1]
	if lb1.Name != "lb-1" || lb1.Version != 7 || lb1.ProbeName != routeTestProbeName || !lb1.ProbePassed {
		t.Errorf("lb-1 %+v", lb1)
	}
	wantHosts := []dnsservice.DnsRouteProbeHost{{Host: "routed.customer.example", Passed: true}, {Host: "missing.customer.example", Passed: false}}
	if !slices.Equal(lb1.Hosts, wantHosts) {
		t.Errorf("lb-1 hosts %+v", lb1.Hosts)
	}
	if lb2.Name != "lb-2" || lb2.Version != 6 || lb2.ProbePassed || len(lb2.Hosts) != 0 {
		t.Errorf("lb-2, whose map lacks its probe name: %+v", lb2)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")}
	for _, healthy := range prober.published() {
		if addresses := healthy.EdgeAddressesForTest(); !slices.Equal(addresses, want) {
			t.Errorf("a route probe moved the healthy set: %v", addresses)
		}
	}
	routeHellos := lb.takeRouteHellos()
	if len(routeHellos) == 0 {
		t.Fatal("no route probe reached the lb")
	}
	for _, hello := range routeHellos {
		if !slices.Equal(hello.alpnIds, []string{"ur-route-probe", "http/1.1"}) || hello.address.Port() != 443 {
			t.Errorf("a route probe of %s offered %q on %v", hello.serverName, hello.alpnIds, hello.address)
		}
	}
	if extraByteCount := func() int64 {
		lb.stateLock.Lock()
		defer lb.stateLock.Unlock()
		return lb.extraByteCount
	}(); extraByteCount != 0 {
		t.Errorf("probes sent %d bytes after their hellos", extraByteCount)
	}
	if passes := prober.host.Metrics.Value("urnetwork_dnsedge_route_probes_total", "pass"); passes == 0 {
		t.Error("no pass counted")
	}
	if posted := prober.host.Metrics.Value("urnetwork_dnsedge_route_reports_total", "posted"); posted != float64(len(reports)) {
		t.Errorf("posted %v", posted)
	}
}

// At most probe.route_hosts of a version's added hosts are probed, the first the feed names, each once
// a round; the version's probe name is probed every round, and a passing host is not probed again for
// that version once the block has taken its pass.
func TestRouteProbesTakeAtMostSixteenHostsOncePerVersion(t *testing.T) {
	hosts := []string{}
	for index := range 20 {
		hosts = append(hosts, strings.Repeat(string(rune('a'+index)), 3)+".customer.example")
	}
	lb := newRouteTestLb(t, append([]string{routeTestProbeName}, hosts...)...)
	sink := &routeTestSink{}
	prober := newRouteTestProber(t, lb, sink)
	if prober.settings.Probe.RouteHostCount != 16 {
		t.Fatalf("route_hosts %d", prober.settings.Probe.RouteHostCount)
	}
	prober.prober.SetInterfaces([]dnsservice.DnsLbInterface{routeTestInterface("lb-1", 1, 7, routeTestProbeName, hosts...)})
	prober.round(t)
	want := append([]string{routeTestProbeName}, hosts[:16]...)
	slices.Sort(want)
	if names := routeTestNames(lb.takeRouteHellos()); !slices.Equal(names, want) {
		t.Errorf("first round probed %v", names)
	}
	reports := sink.take()
	if len(reports) != 1 || len(reports[0].Interfaces[0].Hosts) != 16 {
		t.Fatalf("reports %+v", reports)
	}
	prober.round(t)
	if names := routeTestNames(lb.takeRouteHellos()); !slices.Equal(names, []string{routeTestProbeName}) {
		t.Errorf("second round probed %v", names)
	}
	// a new version's hosts are probed once each in their turn
	prober.prober.SetInterfaces([]dnsservice.DnsLbInterface{routeTestInterface("lb-1", 1, 8, routeTestOtherProbeName, hosts[16:]...)})
	lb.route(routeTestOtherProbeName)
	prober.round(t)
	want = append([]string{routeTestOtherProbeName}, hosts[16:]...)
	slices.Sort(want)
	if names := routeTestNames(lb.takeRouteHellos()); !slices.Equal(names, want) {
		t.Errorf("the new version's round probed %v", names)
	}
	reports = sink.take()
	if len(reports) != 2 || reports[1].Interfaces[0].Version != 8 || len(reports[1].Interfaces[0].Hosts) != 4 {
		t.Errorf("reports %+v", reports)
	}
}

// A failing host is probed again each round until it passes, and then no more; a pass the block did
// not take is probed again, so a lost report loses nothing.
func TestRouteProbesRepeatAFailingHostUntilItPasses(t *testing.T) {
	lb := newRouteTestLb(t, routeTestProbeName, "early.customer.example")
	sink := &routeTestSink{}
	prober := newRouteTestProber(t, lb, sink)
	prober.prober.SetInterfaces([]dnsservice.DnsLbInterface{
		routeTestInterface("lb-1", 1, 7, routeTestProbeName, "early.customer.example", "late.customer.example"),
	})
	sink.setRefusing(true)
	prober.round(t)
	if names := routeTestNames(lb.takeRouteHellos()); !slices.Contains(names, "early.customer.example") {
		t.Fatalf("the refused round probed %v", names)
	}
	sink.setRefusing(false)
	// early's pass went with the refused report, so it is probed once more, then no more
	for round := range 3 {
		prober.round(t)
		names := routeTestNames(lb.takeRouteHellos())
		if !slices.Contains(names, "late.customer.example") {
			t.Errorf("round %d did not probe the failing host: %v", round, names)
		}
		if wantEarly := round == 0; slices.Contains(names, "early.customer.example") != wantEarly {
			t.Errorf("round %d probed %v", round, names)
		}
	}
	lb.route("late.customer.example")
	prober.round(t)
	if names := routeTestNames(lb.takeRouteHellos()); !slices.Contains(names, "late.customer.example") {
		t.Errorf("the fixed host was not probed: %v", names)
	}
	prober.round(t)
	if names := routeTestNames(lb.takeRouteHellos()); !slices.Equal(names, []string{routeTestProbeName}) {
		t.Errorf("after the pass the round probed %v", names)
	}
	reports := sink.take()
	last := reports[len(reports)-2].Interfaces[0]
	if !slices.Equal(last.Hosts, []dnsservice.DnsRouteProbeHost{{Host: "late.customer.example", Passed: true}}) {
		t.Errorf("the fixing round reported %+v", last.Hosts)
	}
	if refused := prober.host.Metrics.Value("urnetwork_dnsedge_route_reports_total", "failed"); refused != 1 {
		t.Errorf("failed reports %v", refused)
	}
}

// An interface that reports no version is probed for health only, and nothing is posted; nor is any
// route probe sent without a sink.
func TestRouteProbesNeedAReportedVersionAndASink(t *testing.T) {
	lb := newRouteTestLb(t, routeTestProbeName)
	sink := &routeTestSink{}
	prober := newRouteTestProber(t, lb, sink)
	prober.prober.SetInterfaces([]dnsservice.DnsLbInterface{routeTestInterface("lb-1", 1, 0, "")})
	prober.round(t)
	if hellos := lb.takeRouteHellos(); len(hellos) != 0 || len(sink.take()) != 0 {
		t.Errorf("no version, yet %d route probes", len(hellos))
	}
	noSink := newRouteTestProber(t, lb, nil)
	noSink.prober.SetInterfaces([]dnsservice.DnsLbInterface{routeTestInterface("lb-1", 1, 7, routeTestProbeName, "host.customer.example")})
	noSink.round(t)
	if hellos := lb.takeRouteHellos(); len(hellos) != 0 {
		t.Errorf("no sink, yet %d route probes", len(hellos))
	}
}

// The edges' client posts each report as JSON with the dnsedge bearer and takes the block's 204; the
// block refuses with no route of its own until DNS-M6-03 adds one.
func TestRouteProbeSinkPostsOverHttp(t *testing.T) {
	bodies := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != dnsservice.DnsRouteProbesPath ||
			request.Header.Get("Authorization") != "Bearer "+apiTestBearers[dnsservice.DnsCallerEdge] {
			http.Error(writer, "no", http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(request.Body)
		bodies <- body
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	settings := edgeTestSettings(t)
	sink, err := dnsservice.NewDnsRouteProbeSinkHttp(server.URL, apiTestBearers[dnsservice.DnsCallerEdge], server.Client(), settings)
	if err != nil {
		t.Fatal(err)
	}
	report := &dnsservice.DnsRouteProbeReport{Format: dnsservice.DnsFormat, Interfaces: []dnsservice.DnsRouteProbeResult{{
		Name: "lb-1", Version: 7, ProbeName: routeTestProbeName, ProbePassed: true,
		Hosts: []dnsservice.DnsRouteProbeHost{{Host: "shop.customer.example", Passed: false}},
	}}}
	if err := sink.RouteProbes(t.Context(), report); err != nil {
		t.Fatal(err)
	}
	decoded, err := dnsservice.DecodeDnsRouteProbeReport(<-bodies)
	if err != nil || decoded.Interfaces[0].Hosts[0].Host != "shop.customer.example" || !decoded.Interfaces[0].ProbePassed {
		t.Errorf("the block read %+v %v", decoded, err)
	}
	api := newTestApi(t, nil)
	apiServer := httptest.NewServer(api.api.Handler())
	defer apiServer.Close()
	toApi, err := dnsservice.NewDnsRouteProbeSinkHttp(apiServer.URL, apiTestBearers[dnsservice.DnsCallerEdge], apiServer.Client(), settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := toApi.RouteProbes(t.Context(), report); !errors.Is(err, dnsservice.ErrDnsFeedRefused) {
		t.Errorf("a block with no route-probes route: %v", err)
	}
}

// A report the block cannot keep is refused whole, and one of a format this release does not read
// stops at its format.
func TestDnsRouteProbeReportRefusals(t *testing.T) {
	good := `{"format":1,"interfaces":[{"name":"lb-1","version":7,"probe_name":"0123456789ab.map.probe.invalid","probe_passed":true,"hosts":[{"host":"a.customer.example","passed":true}]}]}`
	if _, err := dnsservice.DecodeDnsRouteProbeReport([]byte(good)); err != nil {
		t.Fatalf("a good report: %v", err)
	}
	for name, data := range map[string]string{
		"a host with its final dot": strings.Replace(good, `a.customer.example"`, `a.customer.example."`, 1),
		"a host no hello asks for":  strings.Replace(good, `a.customer.example`, `a..customer.example`, 1),
	} {
		if _, err := dnsservice.DecodeDnsRouteProbeReport([]byte(data)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := dnsservice.DecodeDnsRouteProbeReport([]byte(strings.Replace(good, `"format":1`, `"format":2`, 1))); !errors.Is(err, dnsservice.ErrDnsFormatTooNew) {
		t.Errorf("format 2: %v", err)
	}
	refused := map[string]string{
		"no format":       strings.Replace(good, `"format":1,`, ``, 1),
		"no name":         strings.Replace(good, `"name":"lb-1"`, `"name":""`, 1),
		"version zero":    strings.Replace(good, `"version":7`, `"version":0`, 1),
		"no probe name":   strings.Replace(good, `"probe_name":"0123456789ab.map.probe.invalid"`, `"probe_name":""`, 1),
		"a host twice":    strings.Replace(good, `{"host":"a.customer.example","passed":true}`, `{"host":"a.customer.example","passed":true},{"host":"a.customer.example","passed":false}`, 1),
		"not json":        `{"format":1,`,
		"an empty host":   strings.Replace(good, `"host":"a.customer.example"`, `"host":""`, 1),
		"a host too long": strings.Replace(good, `a.customer.example`, strings.Repeat("a.", 127)+"customer.example", 1),
		"interface twice": strings.Replace(good, `"interfaces":[{`, `"interfaces":[{"name":"lb-1","version":7,"probe_name":"0123456789ab.map.probe.invalid"},{`, 1),
	}
	for name, data := range refused {
		if _, err := dnsservice.DecodeDnsRouteProbeReport([]byte(data)); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
}

// A name the feed gives with its final dot is asked for without it, as SNI carries names, and
// reported as the feed gave it.
func TestRouteProbesAskWithoutAFinalDot(t *testing.T) {
	lb := newRouteTestLb(t, routeTestProbeName, "dotted.customer.example")
	sink := &routeTestSink{}
	prober := newRouteTestProber(t, lb, sink)
	prober.prober.SetInterfaces([]dnsservice.DnsLbInterface{
		routeTestInterface("lb-1", 1, 7, routeTestProbeName+".", "dotted.customer.example."),
	})
	prober.round(t)
	if names := routeTestNames(lb.takeRouteHellos()); !slices.Equal(names, []string{routeTestProbeName, "dotted.customer.example"}) {
		t.Errorf("asked for %v", names)
	}
	reports := sink.take()
	if len(reports) != 1 {
		t.Fatalf("%d reports", len(reports))
	}
	result := reports[0].Interfaces[0]
	if result.ProbeName != routeTestProbeName+"." || !result.ProbePassed ||
		!slices.Equal(result.Hosts, []dnsservice.DnsRouteProbeHost{{Host: "dotted.customer.example.", Passed: true}}) {
		t.Errorf("reported %+v", result)
	}
}

// A name no hello can ask for is never sent, and is reported failed, the closed direction: the block
// keeps that host pending, and the rest of the report still lands.
func TestRouteProbesFailANameNoHelloCanAskFor(t *testing.T) {
	lb := newRouteTestLb(t, routeTestProbeName, "good.customer.example")
	sink := &routeTestSink{}
	prober := newRouteTestProber(t, lb, sink)
	prober.prober.SetInterfaces([]dnsservice.DnsLbInterface{
		routeTestInterface("lb-1", 1, 7, routeTestProbeName, "bad..customer.example", "good.customer.example"),
	})
	prober.round(t)
	if names := routeTestNames(lb.takeRouteHellos()); !slices.Equal(names, []string{routeTestProbeName, "good.customer.example"}) {
		t.Errorf("asked for %v", names)
	}
	reports := sink.take()
	if len(reports) != 1 {
		t.Fatalf("%d reports", len(reports))
	}
	want := []dnsservice.DnsRouteProbeHost{{Host: "bad..customer.example", Passed: false}, {Host: "good.customer.example", Passed: true}}
	if result := reports[0].Interfaces[0]; !result.ProbePassed || !slices.Equal(result.Hosts, want) {
		t.Errorf("reported %+v", result)
	}
}
