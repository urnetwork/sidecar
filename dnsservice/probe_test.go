package dnsservice_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How a fake lb interface answers a probe.
type probeBehavior string

const (
	// tlsedge's plaintext unrecognized_name alert
	probeTlsedge probeBehavior = "tlsedge"
	// a ServerHello's record, as the http branch answers
	probeHttp probeBehavior = "http"
	// another alert than unrecognized_name
	probeOtherAlert probeBehavior = "other_alert"
	// nothing at all, until the probe gives up
	probeSilent probeBehavior = "silent"
	// no connection
	probeRefuse probeBehavior = "refuse"
	// mxedge's greeting on 25, which it sends before reading anything
	probeMxedge probeBehavior = "mxedge"
	// mxedge's greeting while it drains
	probeMxedgeDraining probeBehavior = "mxedge_draining"
)

// The port the fake answers as mxedge does: DefaultDnsSettings' smtp_port.
const fakeProbeSmtpPort = 25

// mxedge's greetings, as its dialog writes them for a synthetic host.
const (
	fakeMxedgeBanner   = "220 mx.zone.example ESMTP\r\n"
	fakeMxedgeDraining = "421 4.3.2 mx.zone.example Service closing, try again later\r\n"
)

// DnsProbeDialer over in-memory pipes, each address answering as a test sets it: tlsedge by default,
// and on fakeProbeSmtpPort mxedge.
type fakeProbeDialer struct {
	stateLock sync.Mutex
	behaviors map[netip.AddrPort]probeBehavior
	dials     map[netip.AddrPort]int
	// Bytes probes wrote to each address on fakeProbeSmtpPort, which a banner probe never does.
	smtpWrittenByteCounts map[netip.AddrPort]int64
}

func newFakeProbeDialer() *fakeProbeDialer {
	return &fakeProbeDialer{
		behaviors:             map[netip.AddrPort]probeBehavior{},
		dials:                 map[netip.AddrPort]int{},
		smtpWrittenByteCounts: map[netip.AddrPort]int64{},
	}
}

// Bytes probes have written to address on fakeProbeSmtpPort.
func (self *fakeProbeDialer) smtpWrittenByteCount(address string) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.smtpWrittenByteCounts[netip.AddrPortFrom(netip.MustParseAddr(address), fakeProbeSmtpPort)]
}

// A probe's end of a fake 25, counting what it writes as it writes it, on the probe's own goroutine,
// so a round that has finished has counted every byte.
type fakeProbeSmtpConn struct {
	net.Conn
	dialer  *fakeProbeDialer
	address netip.AddrPort
}

func (self *fakeProbeSmtpConn) Write(data []byte) (int, error) {
	func() {
		self.dialer.stateLock.Lock()
		defer self.dialer.stateLock.Unlock()
		self.dialer.smtpWrittenByteCounts[self.address] += int64(len(data))
	}()
	return self.Conn.Write(data)
}

func (self *fakeProbeDialer) set(address string, port uint16, behavior probeBehavior) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.behaviors[netip.AddrPortFrom(netip.MustParseAddr(address), port)] = behavior
}

func (self *fakeProbeDialer) dialCount(address string, port uint16) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.dials[netip.AddrPortFrom(netip.MustParseAddr(address), port)]
}

func (self *fakeProbeDialer) DialProbe(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	smtp := address.Port() == fakeProbeSmtpPort
	behavior := func() probeBehavior {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.dials[address] += 1
		if behavior, ok := self.behaviors[address]; ok {
			return behavior
		}
		if smtp {
			return probeMxedge
		}
		return probeTlsedge
	}()
	if behavior == probeRefuse {
		return nil, errors.New("refused")
	}
	client, server := net.Pipe()
	if smtp {
		// a greeting first, as SMTP's server speaks first, then whatever the probe writes until it
		// closes; tlsedge's alert is followed by its close, as tlsedge's is
		go func() {
			defer server.Close()
			switch behavior {
			case probeMxedge:
				server.Write([]byte(fakeMxedgeBanner))
			case probeMxedgeDraining:
				server.Write([]byte(fakeMxedgeDraining))
			case probeTlsedge:
				server.Write([]byte{21, 3, 3, 0, 2, 2, 112})
				return
			}
			io.Copy(io.Discard, server)
		}()
		return &fakeProbeSmtpConn{Conn: client, dialer: self, address: address}, nil
	}
	go func() {
		defer server.Close()
		header := make([]byte, 5)
		if _, err := io.ReadFull(server, header); err != nil {
			return
		}
		if _, err := io.ReadFull(server, make([]byte, int(header[3])<<8|int(header[4]))); err != nil {
			return
		}
		switch behavior {
		case probeTlsedge:
			server.Write([]byte{21, 3, 3, 0, 2, 2, 112})
		case probeOtherAlert:
			server.Write([]byte{21, 3, 3, 0, 2, 2, 80})
		case probeHttp:
			server.Write([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0})
		case probeSilent:
			io.Copy(io.Discard, server)
		}
	}()
	return client, nil
}

// One prober on fakes, publishing to the last set it gave.
type testProber struct {
	prober   *dnsservice.Prober
	host     *sidecartest.FakeHost
	clock    *sidecartest.FakeClock
	dialer   *fakeProbeDialer
	settings *dnsservice.DnsSettings

	stateLock sync.Mutex
	healthy   *dnsservice.HealthySet
}

func newTestProber(t testing.TB, settings *dnsservice.DnsSettings, publish func(healthy *dnsservice.HealthySet)) *testProber {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	self := &testProber{
		host:     sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil),
		clock:    clock,
		dialer:   newFakeProbeDialer(),
		settings: settings,
	}
	prober, err := dnsservice.NewProber(t.Context(), self.host.ServiceHost(), settings, &dnsservice.ProberDeps{Dialer: self.dialer},
		func(healthy *dnsservice.HealthySet) {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.healthy = healthy
			}()
			if publish != nil {
				publish(healthy)
			}
		})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prober.Close)
	self.prober = prober
	self.awaitRounds(t, 1)
	return self
}

// Waits until count rounds have finished.
func (self *testProber) awaitRounds(t testing.TB, count int) {
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

// Moves the clock to the next round and waits for it to finish. Every probe here answers at once.
func (self *testProber) round(t testing.TB) {
	t.Helper()
	count, _ := self.prober.Rounds()
	self.clock.Advance(time.Duration(self.settings.Probe.IntervalSeconds) * time.Second)
	self.awaitRounds(t, count+1)
}

// The edge and router addresses last published.
func (self *testProber) addresses() (edge []string, router []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, address := range self.healthy.EdgeAddressesForTest() {
		edge = append(edge, address.String())
	}
	for _, address := range self.healthy.RouterAddressesForTest() {
		router = append(router, address.String())
	}
	return edge, router
}

func (self *testProber) wantEdge(t testing.TB, what string, want ...string) {
	t.Helper()
	if edge, _ := self.addresses(); !slices.Equal(edge, want) {
		t.Errorf("%s: edge %v, want %v", what, edge, want)
	}
}

// Probes on 443 alone, unless a test asks for more.
func probeTestSettings(t testing.TB) *dnsservice.DnsSettings {
	t.Helper()
	settings := edgeTestSettings(t)
	settings.Probe.Ports = []int{443}
	return settings
}

func probeTestInterfaces() []dnsservice.DnsLbInterface {
	return []dnsservice.DnsLbInterface{
		{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.1"), Ipv6: netip.MustParseAddr("2001:db8::1")},
		{Name: "lb-2", Ipv4: netip.MustParseAddr("192.0.2.2"), Ipv6: netip.MustParseAddr("2001:db8::2"), Router: true},
		{Name: "lb-3", Ipv4: netip.MustParseAddr("192.0.2.3"), Router: true},
	}
}

// Two failures keep an address, the third drops it, and one pass brings it back.
func TestProberDropsOnTheThirdFailureAndRestoresOnAPass(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	all := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2"}
	prober.wantEdge(t, "joined", all...)
	prober.dialer.set("192.0.2.2", 443, probeHttp)
	prober.round(t)
	prober.round(t)
	prober.wantEdge(t, "two failures", all...)
	prober.round(t)
	prober.wantEdge(t, "three failures", "192.0.2.1", "192.0.2.3", "2001:db8::1", "2001:db8::2")
	prober.dialer.set("192.0.2.2", 443, probeTlsedge)
	prober.round(t)
	prober.wantEdge(t, "a pass", all...)
	if dials := prober.dialer.dialCount("192.0.2.2", 443); dials != 4 {
		t.Errorf("dials %d", dials)
	}
}

// One port failing drops the address, since a visitor cannot pick a port (reading 7), and every
// way a probe can fail counts.
func TestProberDropsForAnyOnePortAndAnyFailure(t *testing.T) {
	settings := probeTestSettings(t)
	settings.Probe.Ports = []int{443, 8443, 8883, 5671}
	prober := newTestProber(t, settings, nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	prober.dialer.set("192.0.2.1", 8883, probeRefuse)
	prober.dialer.set("192.0.2.2", 5671, probeOtherAlert)
	prober.dialer.set("2001:db8::2", 8443, probeHttp)
	for range 3 {
		prober.round(t)
	}
	prober.wantEdge(t, "three rounds", "192.0.2.3", "2001:db8::1")
}

// A silent interface fails at probe.timeout_s on the clock. It is the only interface, so its probe's
// timer is the only one a round arms, and never-all then keeps it in the set while its gauge and the
// held gauge say it failed.
func TestProberCountsATimeoutAsAFailure(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces([]dnsservice.DnsLbInterface{{Name: "lb-9", Ipv4: netip.MustParseAddr("192.0.2.9")}})
	prober.dialer.set("192.0.2.9", 443, probeSilent)
	for range 3 {
		count, _ := prober.prober.Rounds()
		prober.clock.Advance(time.Duration(prober.settings.Probe.IntervalSeconds) * time.Second)
		if err := prober.clock.AwaitTimers(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
		prober.clock.Advance(time.Duration(prober.settings.Probe.TimeoutSeconds) * time.Second)
		prober.awaitRounds(t, count+1)
	}
	prober.wantEdge(t, "three timeouts", "192.0.2.9")
	metrics := prober.host.Metrics
	if healthy := metrics.Value("urnetwork_dnsedge_interface_healthy", "lb-9", "ipv4"); healthy != 0 {
		t.Errorf("healthy %v", healthy)
	}
	if held := metrics.Value("urnetwork_dnsedge_healthy_held", "edge", "ipv4"); held != 1 {
		t.Errorf("held %v", held)
	}
}

// The families are judged apart: a broken IPv6 path drops only the AAAA.
func TestProberJudgesFamiliesApart(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	prober.dialer.set("2001:db8::1", 443, probeHttp)
	for range 3 {
		prober.round(t)
	}
	prober.wantEdge(t, "an IPv6 failure", "192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::2")
	metrics := prober.host.Metrics
	if metrics.Value("urnetwork_dnsedge_interface_healthy", "lb-1", "ipv4") != 1 || metrics.Value("urnetwork_dnsedge_interface_healthy", "lb-1", "ipv6") != 0 {
		t.Errorf("gauges %v", metrics.Dump())
	}
	if violations := metrics.Violations(); len(violations) != 0 {
		t.Errorf("metric violations %v", violations)
	}
}

// sidecar.yml's drained takes an interface out of user names and mx at once, and back when it is
// listed no longer.
func TestProberLeavesOutADrainedInterface(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	if err := prober.host.Gates.Set("sidecar:\n  drained: [lb-2]\n"); err != nil {
		t.Fatal(err)
	}
	prober.prober.SetInterfaces(probeTestInterfaces())
	prober.wantEdge(t, "drained", "192.0.2.1", "192.0.2.3", "2001:db8::1")
	if _, router := prober.addresses(); !slices.Equal(router, []string{"192.0.2.3"}) {
		t.Errorf("router %v", router)
	}
	if err := prober.host.Gates.Set("sidecar:\n  drained: []\n"); err != nil {
		t.Fatal(err)
	}
	prober.round(t)
	prober.wantEdge(t, "undrained", "192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2")
	if _, router := prober.addresses(); !slices.Equal(router, []string{"192.0.2.2", "192.0.2.3", "2001:db8::2"}) {
		t.Errorf("router %v", router)
	}
}

// A map-stale interface (M6) leaves user names as a failed one does.
func TestProberLeavesOutAMapStaleInterface(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	interfaces := probeTestInterfaces()
	interfaces[0].MapStale = true
	prober.prober.SetInterfaces(interfaces)
	prober.wantEdge(t, "map-stale", "192.0.2.2", "192.0.2.3", "2001:db8::2")
}

// Never all: a drop that would leave a family with no address keeps that family's last set, and says
// so; the other family is untouched.
func TestProberNeverDropsAll(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	prober.dialer.set("192.0.2.2", 443, probeHttp)
	prober.dialer.set("192.0.2.3", 443, probeHttp)
	for range 3 {
		prober.round(t)
	}
	prober.wantEdge(t, "two dropped", "192.0.2.1", "2001:db8::1", "2001:db8::2")
	prober.dialer.set("192.0.2.1", 443, probeHttp)
	for range 3 {
		prober.round(t)
	}
	prober.wantEdge(t, "the last one failing", "192.0.2.1", "2001:db8::1", "2001:db8::2")
	if held := prober.host.Metrics.Value("urnetwork_dnsedge_healthy_held", "edge", "ipv4"); held != 1 {
		t.Errorf("held %v", held)
	}
	if held := prober.host.Metrics.Value("urnetwork_dnsedge_healthy_held", "edge", "ipv6"); held != 0 {
		t.Errorf("ipv6 held %v", held)
	}
	// every interface failing in one round keeps the whole last set of each family
	prober.dialer.set("192.0.2.2", 443, probeTlsedge)
	prober.dialer.set("192.0.2.3", 443, probeTlsedge)
	prober.round(t)
	prober.wantEdge(t, "two back", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2")
	for _, address := range []string{"192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2"} {
		prober.dialer.set(address, 443, probeRefuse)
	}
	for range 3 {
		prober.round(t)
	}
	prober.wantEdge(t, "all failing at once", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2")
}

// T2 through Answer (§22.5): a drained or failed interface is gone from *, @, every copy of *'s
// records and each mx, at the next query, with no journal write.
func TestHealthDropReachesEveryNameAnsweredFromTheSet(t *testing.T) {
	settings := probeTestSettings(t)
	settings.Rrl.ResponsesPerSecond = 1000
	edge := newTestEdge(t, settings)
	rows := append(edgeTestRows(),
		dnsservice.DnsRecordSet{Owner: "net1." + edgeTestRoot, Type: dns.TypeA, Ttl: 60, Kind: dnsservice.DnsRecordKindEdge},
		dnsservice.DnsRecordSet{Owner: "blog.net1." + edgeTestRoot, Type: dnsservice.DnsCopyType, Kind: dnsservice.DnsRecordKindCopy},
		dnsservice.DnsRecordSet{Owner: "_sip._tcp.blog.net1." + edgeTestRoot, Type: dns.TypeSRV, Ttl: 300, Kind: dnsservice.DnsRecordKindUser,
			Rdata: []string{"10 5 5060 sip.other.example."}},
		dnsservice.DnsRecordSet{Owner: "mx.net1." + edgeTestRoot, Type: dns.TypeA, Ttl: 300, Kind: dnsservice.DnsRecordKindRouter},
	)
	edge.publish(t, edgeTestView(t, edge.settings, 7, rows))
	prober := newTestProber(t, settings, edge.edge.SetHealthySet)
	prober.prober.SetInterfaces(probeTestInterfaces())
	conn := edge.serveUdp(t)
	answered := func(name string) []string {
		conn.send(t, edgeTestQuery(name, dns.TypeA, false), "198.51.100.1")
		reply, _ := conn.receive(t)
		addresses := []string{}
		for _, record := range reply.Answer {
			addresses = append(addresses, record.(*dns.A).A.String())
		}
		return addresses
	}
	names := []string{"net1." + edgeTestRoot, "anything.net1." + edgeTestRoot, "blog.net1." + edgeTestRoot}
	for _, name := range names {
		if got := answered(name); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) {
			t.Errorf("%s before: %v", name, got)
		}
	}
	if got := answered("mx.net1." + edgeTestRoot); !slices.Equal(got, []string{"192.0.2.2", "192.0.2.3"}) {
		t.Errorf("mx before: %v", got)
	}

	prober.dialer.set("192.0.2.1", 443, probeHttp)
	for range 3 {
		prober.round(t)
	}
	if err := prober.host.Gates.Set("sidecar:\n  drained: [lb-3]\n"); err != nil {
		t.Fatal(err)
	}
	prober.round(t)
	for _, name := range names {
		if got := answered(name); !slices.Equal(got, []string{"192.0.2.2"}) {
			t.Errorf("%s after: %v", name, got)
		}
	}
	if got := answered("mx.net1." + edgeTestRoot); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Errorf("mx after: %v", got)
	}
	if serial, _ := edge.edge.ServedSerial(edgeTestRoot); serial != 7 {
		t.Errorf("the serial moved to %d", serial)
	}
}

// An interface gone from the feed is forgotten, its failures with it.
func TestProberForgetsAnInterfaceTheFeedDrops(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	prober.dialer.set("192.0.2.2", 443, probeHttp)
	for range 2 {
		prober.round(t)
	}
	prober.prober.SetInterfaces(probeTestInterfaces()[:1])
	prober.wantEdge(t, "one left", "192.0.2.1", "2001:db8::1")
	prober.prober.SetInterfaces(probeTestInterfaces())
	prober.round(t)
	prober.wantEdge(t, "back with a fresh count", "192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2")
}
