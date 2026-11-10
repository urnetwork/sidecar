package dnsservice_test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

func (self *testProber) wantRouter(t testing.TB, what string, want ...string) {
	t.Helper()
	if _, router := self.addresses(); !slices.Equal(router, want) {
		t.Errorf("%s: router %v, want %v", what, router, want)
	}
}

// A ready greeting passes, single or multiline, and nothing else does: another code, a code that
// changes between lines, a bare LF, an unended line, a line past RFC 5321's 512 bytes, a greeting past
// the bound, a TLS record, or nothing.
func TestSmtpBannerPassesOnlyOnAReadyGreeting(t *testing.T) {
	maxByteCount := dnsservice.DefaultDnsSettings().Probe.SmtpBannerMaxByteCount
	longLine := "220-" + strings.Repeat("a", 400) + "\r\n"
	passes := map[string]string{
		"mxedge's":            "220 mx.zone.example ESMTP\r\n",
		"multiline":           "220-mx.zone.example ESMTP\r\n220-a notice\r\n220 ready\r\n",
		"a code alone":        "220\r\n",
		"a multiline end":     "220-mx.zone.example\r\n220\r\n",
		"the longest line":    "220 " + strings.Repeat("a", 512-len("220 \r\n")) + "\r\n",
		"what follows unread": "220 mx.zone.example ESMTP\r\nEHLO-like bytes a server never sends",
		"long, within bounds": strings.Repeat(longLine, maxByteCount/len(longLine)-1) + "220 ok\r\n",
	}
	for name, greeting := range passes {
		if !dnsservice.SmtpBannerPassesForTest(strings.NewReader(greeting), maxByteCount) {
			t.Errorf("%s failed", name)
		}
	}
	fails := map[string]string{
		"draining":            "421 4.3.2 mx.zone.example Service closing, try again later\r\n",
		"over caps":           "421 4.7.0 mx.zone.example Too many sessions, try again later\r\n",
		"listed":              "554 5.7.1 mx.zone.example Service refused\r\n",
		"a changed code":      "220-mx.zone.example\r\n421 closing\r\n",
		"no last line":        "220-mx.zone.example\r\n220-more\r\n",
		"a bare LF":           "220 mx.zone.example ESMTP\n",
		"no line end":         "220 mx.zone.example ESMTP",
		"a fourth digit":      "2200 mx.zone.example\r\n",
		"no separator":        "220mx.zone.example\r\n",
		"a short code":        "22\r\n",
		"letters for a code":  "abc mx.zone.example\r\n",
		"a line past 512":     "220 " + strings.Repeat("a", 512-len("220 \r\n")+1) + "\r\n",
		"a greeting past max": strings.Repeat(longLine, maxByteCount/len(longLine)+1) + "220 ok\r\n",
		"a tls record":        string([]byte{21, 3, 3, 0, 2, 2, 112}),
		"nothing":             "",
	}
	for name, greeting := range fails {
		if dnsservice.SmtpBannerPassesForTest(strings.NewReader(greeting), maxByteCount) {
			t.Errorf("%s passed", name)
		}
	}
}

// The probe reads at most the greeting's bound, whatever the far side has.
func TestSmtpBannerReadsNoFurtherThanItsBound(t *testing.T) {
	reader := bytes.NewReader([]byte(strings.Repeat("220-"+strings.Repeat("a", 100)+"\r\n", 1000)))
	if dnsservice.SmtpBannerPassesForTest(reader, 512) {
		t.Fatal("an unending greeting passed")
	}
	if read := int64(reader.Size()) - int64(reader.Len()); 512 < read {
		t.Errorf("read %d bytes past a 512 bound", read)
	}
}

// A listener whose connections come from its own DialProbe, each from one TEST-NET-2 sender, as the
// host's PROXY listener hands mxedge a sender's connection.
type mxedgePipeListener struct {
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func newMxedgePipeListener() *mxedgePipeListener {
	return &mxedgePipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (self *mxedgePipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

func (self *mxedgePipeListener) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

func (self *mxedgePipeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 25), Port: 25}
}

func (self *mxedgePipeListener) DialProbe(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case self.conns <- &mxedgeSenderConn{Conn: server}:
		return client, nil
	case <-self.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// mxedge's end of a probe's connection, from the sender a PROXY header would name.
type mxedgeSenderConn struct {
	net.Conn
}

func (self *mxedgeSenderConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(198, 51, 100, 53), Port: 40053}
}

// mxedge's own greeting, from its own engine, passes; the 421 it greets with while it drains fails.
func TestSmtpBannerProbePassesOnMxedgesOwnGreeting(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	settings := mxedgeservice.DefaultMxEdgeSettings()
	settings.BannerHostName = "mx.zone.example"
	settings.DeviationUrl = "https://deviation.zone.example/rfc3207"
	engine, err := mxedgeservice.NewMxEdgeService(t.Context(), host.ServiceHost(), nil, &mxedgeservice.MxEdgeDeps{Clock: clock}, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	listener := newMxedgePipeListener()
	go engine.Serve(listener)
	t.Cleanup(func() { listener.Close() })
	dnsSettings := dnsservice.DefaultDnsSettings()
	address := netip.MustParseAddrPort("192.0.2.25:25")
	if !dnsservice.SmtpProbeOnceForTest(t.Context(), clock, dnsSettings, listener, address) {
		t.Fatal("mxedge's greeting failed")
	}
	// the probe's session has ended, so a drain returns at once and the next greeting is the 421
	engine.Drain()
	if dnsservice.SmtpProbeOnceForTest(t.Context(), clock, dnsSettings, listener, address) {
		t.Error("a draining mxedge's greeting passed")
	}
}

// A router that never greets fails at probe.timeout_s on the clock: the probe's timer is the only one
// armed, so moving the clock past it cuts the connection.
func TestSmtpBannerProbeTimesOutOnASilentRouter(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	dialer := newFakeProbeDialer()
	dialer.set("192.0.2.2", fakeProbeSmtpPort, probeSilent)
	settings := dnsservice.DefaultDnsSettings()
	passed := make(chan bool, 1)
	go func() {
		passed <- dnsservice.SmtpProbeOnceForTest(t.Context(), clock, settings, dialer, netip.MustParseAddrPort("192.0.2.2:25"))
	}()
	if err := clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Duration(settings.Probe.TimeoutSeconds) * time.Second)
	select {
	case pass := <-passed:
		if pass {
			t.Error("a silent router passed")
		}
	case <-t.Context().Done():
		t.Fatal("the probe outlived its timeout")
	}
}

// Three failed banners take a router out of mx and out of nothing else: user names keep it, and its
// edge gauge stays up while its router gauge falls. One ready greeting brings it back.
func TestProberDropsARouterFromMxAloneOnItsBanner(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	allEdge := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2"}
	allRouter := []string{"192.0.2.2", "192.0.2.3", "2001:db8::2"}
	prober.wantRouter(t, "joined", allRouter...)
	prober.dialer.set("192.0.2.3", fakeProbeSmtpPort, probeMxedgeDraining)
	prober.round(t)
	prober.round(t)
	prober.wantRouter(t, "two failures", allRouter...)
	prober.round(t)
	prober.wantRouter(t, "three failures", "192.0.2.2", "2001:db8::2")
	prober.wantEdge(t, "three failures", allEdge...)
	metrics := prober.host.Metrics
	if healthy := metrics.Value("urnetwork_dnsedge_router_healthy", "lb-3", "ipv4"); healthy != 0 {
		t.Errorf("lb-3's router gauge %v", healthy)
	}
	if healthy := metrics.Value("urnetwork_dnsedge_interface_healthy", "lb-3", "ipv4"); healthy != 1 {
		t.Errorf("lb-3's edge gauge %v", healthy)
	}
	if healthy := metrics.Value("urnetwork_dnsedge_router_healthy", "lb-2", "ipv4"); healthy != 1 {
		t.Errorf("lb-2's router gauge %v", healthy)
	}
	prober.dialer.set("192.0.2.3", fakeProbeSmtpPort, probeMxedge)
	prober.round(t)
	prober.wantRouter(t, "a ready greeting", allRouter...)
	if violations := metrics.Violations(); len(violations) != 0 {
		t.Errorf("metric violations %v", violations)
	}
}

// tlsedge failing takes a router out of user names and not out of mx, since mail never meets it.
func TestProberKeepsARouterInMxWhenTlsedgeFails(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	prober.dialer.set("192.0.2.2", 443, probeHttp)
	for range 3 {
		prober.round(t)
	}
	prober.wantEdge(t, "tlsedge failing", "192.0.2.1", "192.0.2.3", "2001:db8::1", "2001:db8::2")
	prober.wantRouter(t, "tlsedge failing", "192.0.2.2", "192.0.2.3", "2001:db8::2")
}

// Only router interfaces take the banner, at each address they have, every round, and the probe writes
// nothing to them: no EHLO, no QUIT. tlsedge's alert on 25 is no greeting.
func TestProberBannerProbesOnlyRoutersAndWritesNothing(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	for range 3 {
		prober.round(t)
	}
	for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
		if dials := prober.dialer.dialCount(address, fakeProbeSmtpPort); dials != 0 {
			t.Errorf("%s, no router, took %d banner probes", address, dials)
		}
	}
	for _, address := range []string{"192.0.2.2", "2001:db8::2", "192.0.2.3"} {
		if dials := prober.dialer.dialCount(address, fakeProbeSmtpPort); dials != 3 {
			t.Errorf("%s took %d banner probes in 3 rounds", address, dials)
		}
		if written := prober.dialer.smtpWrittenByteCount(address); written != 0 {
			t.Errorf("a probe wrote %d bytes to %s's 25", written, address)
		}
	}
	prober.dialer.set("192.0.2.3", fakeProbeSmtpPort, probeTlsedge)
	for range 3 {
		prober.round(t)
	}
	prober.wantRouter(t, "tlsedge's alert on 25", "192.0.2.2", "2001:db8::2")
}

// Two routers with both families, so a family can lose one and keep the other.
func probeTestRouters() []dnsservice.DnsLbInterface {
	return []dnsservice.DnsLbInterface{
		{Name: "lb-1", Ipv4: netip.MustParseAddr("192.0.2.1"), Ipv6: netip.MustParseAddr("2001:db8::1")},
		{Name: "lb-2", Ipv4: netip.MustParseAddr("192.0.2.2"), Ipv6: netip.MustParseAddr("2001:db8::2"), Router: true},
		{Name: "lb-4", Ipv4: netip.MustParseAddr("192.0.2.4"), Ipv6: netip.MustParseAddr("2001:db8::4"), Router: true},
	}
}

// The families' banners are judged apart, as mx's A and AAAA are answered apart.
func TestProberJudgesBannerFamiliesApart(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestRouters())
	prober.dialer.set("2001:db8::2", fakeProbeSmtpPort, probeRefuse)
	for range 3 {
		prober.round(t)
	}
	prober.wantRouter(t, "lb-2's IPv6 banner failing", "192.0.2.2", "192.0.2.4", "2001:db8::4")
	metrics := prober.host.Metrics
	if metrics.Value("urnetwork_dnsedge_router_healthy", "lb-2", "ipv4") != 1 || metrics.Value("urnetwork_dnsedge_router_healthy", "lb-2", "ipv6") != 0 {
		t.Errorf("gauges %v", metrics.Dump())
	}
}

// Never every router: a round that would leave mx with no IPv4 address keeps the last ones, and says
// so, while IPv6 is judged on its own.
func TestProberNeverDropsEveryRouter(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	prober.prober.SetInterfaces(probeTestInterfaces())
	prober.dialer.set("192.0.2.2", fakeProbeSmtpPort, probeMxedgeDraining)
	prober.dialer.set("192.0.2.3", fakeProbeSmtpPort, probeMxedgeDraining)
	for range 3 {
		prober.round(t)
	}
	prober.wantRouter(t, "every IPv4 router failing", "192.0.2.2", "192.0.2.3", "2001:db8::2")
	metrics := prober.host.Metrics
	if held := metrics.Value("urnetwork_dnsedge_healthy_held", "router", "ipv4"); held != 1 {
		t.Errorf("router ipv4 held %v", held)
	}
	if held := metrics.Value("urnetwork_dnsedge_healthy_held", "router", "ipv6"); held != 0 {
		t.Errorf("router ipv6 held %v", held)
	}
	if healthy := metrics.Value("urnetwork_dnsedge_router_healthy", "lb-2", "ipv4"); healthy != 0 {
		t.Errorf("lb-2's router gauge %v", healthy)
	}
	prober.wantEdge(t, "every IPv4 router failing", "192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2")
}

// An interface the feed takes off the router list loses its banner count, so one listed again starts
// afresh rather than one failure from a drop.
func TestProberForgetsABannerCountWhenAnInterfaceStopsRouting(t *testing.T) {
	prober := newTestProber(t, probeTestSettings(t), nil)
	interfaces := probeTestInterfaces()
	prober.prober.SetInterfaces(interfaces)
	prober.dialer.set("192.0.2.3", fakeProbeSmtpPort, probeMxedgeDraining)
	prober.round(t)
	prober.round(t)
	interfaces[2].Router = false
	prober.prober.SetInterfaces(interfaces)
	prober.wantRouter(t, "off the list", "192.0.2.2", "2001:db8::2")
	interfaces[2].Router = true
	prober.prober.SetInterfaces(interfaces)
	prober.round(t)
	prober.wantRouter(t, "back on the list, one failure in", "192.0.2.2", "192.0.2.3", "2001:db8::2")
}

// A router whose banner fails leaves mx on both edges, and *, @ and every name under * keep it (§22's
// "a drained or failed interface leaving *, @, every copy and mx on both NS", for the banner's half).
func TestRouterBannerFailureLeavesMxOnBothEdgesAndNotTheWildcard(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	settings := sidecartest.DefaultDnsHarnessSettings()
	settings.Directory = t.TempDir()
	harness, err := sidecartest.NewDnsHarness(t.Context(), net, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(harness.Close)
	if _, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{Upserts: harness.NetworkRows("", "net1")}); err != nil {
		t.Fatal(err)
	}
	answer := func(ns string, name string, rrType uint16) []string {
		t.Helper()
		query := &dns.Msg{}
		query.SetQuestion(name, rrType)
		reply, err := harness.Query(t.Context(), ns, query)
		if err != nil {
			t.Fatalf("%s %s at %s: %v", name, dns.TypeToString[rrType], ns, err)
		}
		addresses := []string{}
		for _, record := range reply.Answer {
			switch record := record.(type) {
			case *dns.A:
				addresses = append(addresses, record.A.String())
			case *dns.AAAA:
				addresses = append(addresses, record.AAAA.String())
			}
		}
		slices.Sort(addresses)
		return addresses
	}
	zone := "net1." + harness.Root()
	check := func(what string, wantMxIpv4s []string, wantMxIpv6s []string) {
		t.Helper()
		for _, ns := range harness.Settings().Ns {
			for _, name := range []string{zone, "*." + zone, "swift-1234." + zone} {
				if got := answer(ns, name, dns.TypeA); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}) {
					t.Errorf("%s: %s answers %s A %v", what, ns, name, got)
				}
				if got := answer(ns, name, dns.TypeAAAA); !slices.Equal(got, []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"}) {
					t.Errorf("%s: %s answers %s AAAA %v", what, ns, name, got)
				}
			}
			if got := answer(ns, "mx."+zone, dns.TypeA); !slices.Equal(got, wantMxIpv4s) {
				t.Errorf("%s: %s answers mx A %v, want %v", what, ns, got, wantMxIpv4s)
			}
			if got := answer(ns, "mx."+zone, dns.TypeAAAA); !slices.Equal(got, wantMxIpv6s) {
				t.Errorf("%s: %s answers mx AAAA %v, want %v", what, ns, got, wantMxIpv6s)
			}
		}
	}
	check("all greeting", []string{"192.0.2.2", "192.0.2.3"}, []string{"2001:db8::2", "2001:db8::3"})
	if err := harness.FailInterfaceBanner(t.Context(), "lb-2"); err != nil {
		t.Fatal(err)
	}
	check("lb-2's banner failed", []string{"192.0.2.3"}, []string{"2001:db8::3"})
	// lb-1 is no router, so its banner is never read
	if err := harness.FailInterfaceBanner(t.Context(), "lb-1"); err != nil {
		t.Fatal(err)
	}
	check("lb-1's banner failed too", []string{"192.0.2.3"}, []string{"2001:db8::3"})
	if err := harness.RestoreInterfaceBanner(t.Context(), "lb-2"); err != nil {
		t.Fatal(err)
	}
	check("lb-2's banner back", []string{"192.0.2.2", "192.0.2.3"}, []string{"2001:db8::2", "2001:db8::3"})
}
