package sidecartest

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar/dnsservice"
)

// A harness named name on net, its snapshots under the test's directory.
func newTestDnsHarness(t *testing.T, net *Net, name string) *DnsHarness {
	t.Helper()
	settings := DefaultDnsHarnessSettings()
	settings.Name = name
	settings.Directory = t.TempDir()
	harness, err := NewDnsHarness(t.Context(), net, settings)
	if err != nil {
		t.Fatal(err)
	}
	// before the directory goes, which an edge writes until it stops
	t.Cleanup(harness.Close)
	return harness
}

// A TXT row at label under net1 of the harness's root.
func dnsHarnessTestTxt(harness *DnsHarness, label string, text string) dnsservice.DnsRecordSet {
	return dnsservice.DnsRecordSet{
		Owner: label + ".net1." + harness.Root(),
		Type:  dns.TypeTXT,
		Ttl:   300,
		Kind:  dnsservice.DnsRecordKindUser,
		Rdata: []string{`"` + text + `"`},
	}
}

// What ns answers for name and rrType over TCP: the rcode and each record's RDATA, sorted.
func dnsHarnessTestAnswer(t *testing.T, harness *DnsHarness, ns string, name string, rrType uint16) (int, []string) {
	t.Helper()
	query := &dns.Msg{}
	query.SetQuestion(name, rrType)
	reply, err := harness.Query(t.Context(), ns, query)
	if err != nil {
		t.Fatalf("%s %s at %s: %v", name, dns.TypeToString[rrType], ns, err)
	}
	rdatas := []string{}
	for _, record := range reply.Answer {
		if record.Header().Rrtype == rrType {
			rdatas = append(rdatas, dnsHarnessRdata(record))
		}
	}
	slices.Sort(rdatas)
	return reply.Rcode, rdatas
}

// The SOA serial ns answers for the harness's root.
func dnsHarnessTestSoaSerial(t *testing.T, harness *DnsHarness, ns string) uint32 {
	t.Helper()
	serial, err := (&dnsHarnessSoaReader{harness: harness}).ReadSoa(t.Context(), harness.Root(), ns)
	if err != nil {
		t.Fatalf("SOA at %s: %v", ns, err)
	}
	return serial
}

// A write is served by both edges at the serial it took: the same SOA and the same record at each,
// over TCP and UDP alike.
func TestDnsHarnessWriteReachesBothEdgesAtOneSerial(t *testing.T) {
	net := newTestNet(t)
	harness := newTestDnsHarness(t, net, "dns")
	if len(harness.Settings().Ns) != 2 {
		t.Fatalf("ns %v", harness.Settings().Ns)
	}
	serial, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{
		Upserts: []dnsservice.DnsRecordSet{dnsHarnessTestTxt(harness, "hello", "one")},
	})
	if err != nil {
		t.Fatal(err)
	}
	name := "hello.net1." + harness.Root()
	for _, ns := range harness.Settings().Ns {
		if soaSerial := dnsHarnessTestSoaSerial(t, harness, ns); soaSerial != uint32(serial) {
			t.Errorf("%s serves SOA %d, want %d", ns, soaSerial, serial)
		}
		if rcode, texts := dnsHarnessTestAnswer(t, harness, ns, name, dns.TypeTXT); rcode != dns.RcodeSuccess || !slices.Equal(texts, []string{`"one"`}) {
			t.Errorf("%s answers %s %v", ns, dns.RcodeToString[rcode], texts)
		}
		query := &dns.Msg{}
		query.SetQuestion(name, dns.TypeTXT)
		reply, err := harness.QueryUdp(t.Context(), ns, query, netip.MustParseAddr("198.51.100.7"))
		if err != nil || len(reply.Answer) != 1 || !reply.Authoritative {
			t.Errorf("%s over udp: %v %v", ns, reply, err)
		}
	}
	// a second write moves both on together
	next, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{
		Upserts: []dnsservice.DnsRecordSet{dnsHarnessTestTxt(harness, "hello", "two")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if next != serial+1 {
		t.Errorf("serial %d after %d", next, serial)
	}
	for _, ns := range harness.Settings().Ns {
		if soaSerial := dnsHarnessTestSoaSerial(t, harness, ns); soaSerial != uint32(next) {
			t.Errorf("%s serves SOA %d, want %d", ns, soaSerial, next)
		}
		if _, texts := dnsHarnessTestAnswer(t, harness, ns, name, dns.TypeTXT); !slices.Equal(texts, []string{`"two"`}) {
			t.Errorf("%s answers %v", ns, texts)
		}
	}
}

// A failed interface leaves *, @ and the network's own names on both edges, and a restored one comes
// back to both. Router rows keep it until DNS-M7-01's banner probe, as a failed alert probe does not
// reach mx.
func TestDnsHarnessFailedInterfaceLeavesBothEdgesAnswers(t *testing.T) {
	net := newTestNet(t)
	harness := newTestDnsHarness(t, net, "dns")
	if _, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{Upserts: harness.NetworkRows("", "net1")}); err != nil {
		t.Fatal(err)
	}
	all := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	check := func(what string, wantEdge []string, wantRouter []string) {
		t.Helper()
		for _, ns := range harness.Settings().Ns {
			for _, name := range []string{"www.net1." + harness.Root(), "net1." + harness.Root()} {
				if _, addresses := dnsHarnessTestAnswer(t, harness, ns, name, dns.TypeA); !slices.Equal(addresses, wantEdge) {
					t.Errorf("%s: %s answers %s with %v, want %v", what, ns, name, addresses, wantEdge)
				}
			}
			if _, addresses := dnsHarnessTestAnswer(t, harness, ns, "mx.net1."+harness.Root(), dns.TypeA); !slices.Equal(addresses, wantRouter) {
				t.Errorf("%s: %s answers mx with %v, want %v", what, ns, addresses, wantRouter)
			}
		}
	}
	check("all healthy", all, all[1:])
	if err := harness.FailInterface(t.Context(), "lb-2"); err != nil {
		t.Fatal(err)
	}
	check("lb-2 failed", []string{"192.0.2.1", "192.0.2.3"}, all[1:])
	for _, ns := range harness.Settings().Ns {
		if _, addresses := dnsHarnessTestAnswer(t, harness, ns, "www.net1."+harness.Root(), dns.TypeAAAA); !slices.Equal(addresses, []string{"2001:db8::1", "2001:db8::3"}) {
			t.Errorf("%s answers AAAA %v", ns, addresses)
		}
	}
	if err := harness.RestoreInterface(t.Context(), "lb-2"); err != nil {
		t.Fatal(err)
	}
	check("lb-2 restored", all, all[1:])
	// a drain takes an interface out of router answers as well
	if err := harness.DrainInterface(t.Context(), "lb-3"); err != nil {
		t.Fatal(err)
	}
	check("lb-3 drained", all[:2], all[1:2])
	if err := harness.UndrainInterface(t.Context(), "lb-3"); err != nil {
		t.Fatal(err)
	}
	check("lb-3 back", all, all[1:])
	if err := harness.FailInterface(t.Context(), "lb-9"); !errors.Is(err, ErrDnsHarnessSettings) {
		t.Errorf("an unknown interface: %v", err)
	}
}

// Two harnesses on one Net share nothing: neither serves the other's writes, a failure in one leaves
// the other's answers alone, and each signs with keys of its own.
func TestDnsHarnessesShareNothing(t *testing.T) {
	net := newTestNet(t)
	first := newTestDnsHarness(t, net, "first")
	second := newTestDnsHarness(t, net, "second")
	for _, harness := range []*DnsHarness{first, second} {
		if _, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{Upserts: harness.NetworkRows("", "net1")}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := first.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{
		Upserts: []dnsservice.DnsRecordSet{dnsHarnessTestTxt(first, "only", "first")},
	}); err != nil {
		t.Fatal(err)
	}
	for _, ns := range second.Settings().Ns {
		if rcode, texts := dnsHarnessTestAnswer(t, second, ns, "only.net1."+second.Root(), dns.TypeTXT); len(texts) != 0 {
			t.Errorf("second's %s answers first's write: %s %v", ns, dns.RcodeToString[rcode], texts)
		}
	}
	if err := first.FailInterface(t.Context(), "lb-1"); err != nil {
		t.Fatal(err)
	}
	for _, ns := range first.Settings().Ns {
		if _, addresses := dnsHarnessTestAnswer(t, first, ns, "www.net1."+first.Root(), dns.TypeA); slices.Contains(addresses, "192.0.2.1") {
			t.Errorf("first's %s still answers lb-1: %v", ns, addresses)
		}
		if _, addresses := dnsHarnessTestAnswer(t, second, ns, "www.net1."+second.Root(), dns.TypeA); !slices.Contains(addresses, "192.0.2.1") {
			t.Errorf("second's %s lost lb-1 to first's failure: %v", ns, addresses)
		}
	}
	_, firstKeys := dnsHarnessTestAnswer(t, first, "ns1", first.Root(), dns.TypeDNSKEY)
	_, secondKeys := dnsHarnessTestAnswer(t, second, "ns1", second.Root(), dns.TypeDNSKEY)
	if len(firstKeys) != 2 || len(secondKeys) != 2 || slices.ContainsFunc(firstKeys, func(key string) bool { return slices.Contains(secondKeys, key) }) {
		t.Errorf("DNSKEYs %v and %v", firstKeys, secondKeys)
	}
	if first.Bearer(dnsservice.DnsCallerEdge) == second.Bearer(dnsservice.DnsCallerEdge) || first.Store() == second.Store() {
		t.Error("the harnesses share a bearer or a store")
	}
	if first.EdgeMetrics("ns1") == second.EdgeMetrics("ns1") || first.EdgeMetrics("ns1") == first.EdgeMetrics("ns2") {
		t.Error("processes share metrics")
	}
}

// A second harness under a name already on the Net is refused before it starts anything.
func TestDnsHarnessRefusesANameAlreadyOnTheNet(t *testing.T) {
	net := newTestNet(t)
	newTestDnsHarness(t, net, "dns")
	settings := DefaultDnsHarnessSettings()
	settings.Directory = t.TempDir()
	if _, err := NewDnsHarness(t.Context(), net, settings); !errors.Is(err, ErrDnsHarnessSettings) {
		t.Errorf("a second dns: %v", err)
	}
	settings.Name = "other"
	settings.Dns.Edge.UdpReaderCount = 4
	if _, err := NewDnsHarness(t.Context(), net, settings); !errors.Is(err, ErrDnsHarnessSettings) {
		t.Errorf("four udp readers: %v", err)
	}
	settings.Dns.Edge.UdpReaderCount = 1
	settings.Directory = ""
	if _, err := NewDnsHarness(t.Context(), net, settings); !errors.Is(err, ErrDnsHarnessSettings) {
		t.Errorf("no directory: %v", err)
	}
}

// A net.Resolver from the harness looks names up through one edge, as TLS's and MAIL's tests do.
func TestDnsHarnessResolverLooksUpThroughAnEdge(t *testing.T) {
	net := newTestNet(t)
	harness := newTestDnsHarness(t, net, "dns")
	upserts := append(harness.NetworkRows("", "net1"), dnsHarnessTestTxt(harness, "notes", "resolved"))
	if _, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{Upserts: upserts}); err != nil {
		t.Fatal(err)
	}
	resolver := harness.Resolver("ns2")
	texts, err := resolver.LookupTXT(t.Context(), "notes.net1."+harness.Root())
	if err != nil || !slices.Equal(texts, []string{"resolved"}) {
		t.Errorf("TXT %v %v", texts, err)
	}
	addresses, err := resolver.LookupHost(t.Context(), "www.net1."+harness.Root())
	slices.Sort(addresses)
	want := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1", "2001:db8::2", "2001:db8::3"}
	if err != nil || !slices.Equal(addresses, want) {
		t.Errorf("host %v %v", addresses, err)
	}
	mxs, err := resolver.LookupMX(t.Context(), "net1."+harness.Root())
	if err != nil || len(mxs) != 1 || mxs[0].Host != "mx.net1."+harness.Root() {
		t.Errorf("MX %v %v", mxs, err)
	}
	if _, err := resolver.LookupHost(t.Context(), "nothing.example."); err == nil {
		t.Error("a name in no root resolved")
	}
}

// With the block down the edges keep answering what they hold (D-DNS-3), and a write waits for it.
func TestDnsHarnessEdgesKeepServingWithTheBlockDown(t *testing.T) {
	net := newTestNet(t)
	harness := newTestDnsHarness(t, net, "dns")
	serial, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{
		Upserts: []dnsservice.DnsRecordSet{dnsHarnessTestTxt(harness, "kept", "before")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := net.Kill(harness.ApiProcess()); err != nil {
		t.Fatal(err)
	}
	if harness.Api() != nil {
		t.Error("a killed block still reads as running")
	}
	if _, err := harness.Write(t.Context(), &dnsservice.DnsZoneWrite{
		Upserts: []dnsservice.DnsRecordSet{dnsHarnessTestTxt(harness, "kept", "after")},
	}); err != nil {
		t.Fatal(err)
	}
	for _, ns := range harness.Settings().Ns {
		if soaSerial := dnsHarnessTestSoaSerial(t, harness, ns); soaSerial != uint32(serial) {
			t.Errorf("%s serves %d with the block down, want %d", ns, soaSerial, serial)
		}
		if _, texts := dnsHarnessTestAnswer(t, harness, ns, "kept.net1."+harness.Root(), dns.TypeTXT); !slices.Equal(texts, []string{`"before"`}) {
			t.Errorf("%s answers %v", ns, texts)
		}
	}
}

// A killed edge answers nothing, the other keeps serving, and a restart catches up from its local
// snapshot and the feed.
func TestDnsHarnessKilledEdgeRestartsAndCatchesUp(t *testing.T) {
	net := newTestNet(t)
	harness := newTestDnsHarness(t, net, "dns")
	if err := net.Kill(harness.EdgeProcess("ns1")); err != nil {
		t.Fatal(err)
	}
	query := &dns.Msg{}
	query.SetQuestion(harness.Root(), dns.TypeSOA)
	if _, err := harness.Query(t.Context(), "ns1", query); !errors.Is(err, ErrDnsHarnessDown) {
		t.Errorf("a killed edge: %v", err)
	}
	serial, err := harness.Write(t.Context(), &dnsservice.DnsZoneWrite{
		Upserts: []dnsservice.DnsRecordSet{dnsHarnessTestTxt(harness, "late", "written")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.AwaitServed(t.Context(), harness.Root(), serial, "ns2"); err != nil {
		t.Fatal(err)
	}
	if err := net.Restart(harness.EdgeProcess("ns1"), harness.EdgeProcess("ns1")); err != nil {
		t.Fatal(err)
	}
	if err := harness.AwaitServed(t.Context(), harness.Root(), serial); err != nil {
		t.Fatal(err)
	}
	if _, texts := dnsHarnessTestAnswer(t, harness, "ns1", "late.net1."+harness.Root(), dns.TypeTXT); !slices.Equal(texts, []string{`"written"`}) {
		t.Errorf("the restarted edge answers %v", texts)
	}
}

// GET ready through the harness's block reads both edges' SOAs in memory: canary_failing until the
// site monitor reports, then ready, and waiting is never the answer once both serve the serial.
func TestDnsHarnessReadyReadsBothEdges(t *testing.T) {
	net := newTestNet(t)
	harness := newTestDnsHarness(t, net, "dns")
	challenge := dnsservice.DnsRecordSet{
		Owner: "_acme-challenge.www.net1." + harness.Root(),
		Type:  dns.TypeTXT,
		Ttl:   harness.Settings().Ttl.Challenge,
		Kind:  dnsservice.DnsRecordKindChallenge,
		Rdata: []string{`"challenge-digest"`},
	}
	serial, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{Upserts: []dnsservice.DnsRecordSet{challenge}})
	if err != nil {
		t.Fatal(err)
	}
	answer, err := harness.Ready(t.Context(), harness.Root(), serial)
	if err != nil || answer.Answer != dnsservice.DnsReadyCanaryFailing {
		t.Fatalf("with no verdict: %v %v", answer, err)
	}
	harness.ReportCanary(harness.Root(), dnsservice.DnsCanarySourceSite, serial, true)
	answer, err = harness.Ready(t.Context(), harness.Root(), serial)
	if err != nil || answer.Answer != dnsservice.DnsReadyReady || answer.Serial != serial {
		t.Errorf("with a clean verdict: %v %v", answer, err)
	}
}

// Close stops every edge's writes before it returns, the local snapshots written, so the directory can
// go while the Net still runs, and nothing answers afterwards.
func TestDnsHarnessCloseStopsEveryWriteBeforeItReturns(t *testing.T) {
	net := newTestNet(t)
	settings := DefaultDnsHarnessSettings()
	settings.Directory = t.TempDir()
	harness, err := NewDnsHarness(t.Context(), net, settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.WriteServed(t.Context(), &dnsservice.DnsZoneWrite{Upserts: harness.NetworkRows("", "net1")}); err != nil {
		t.Fatal(err)
	}
	// moves the clock past the snapshot writers' interval, so their writes are in flight
	if err := harness.ProbeRounds(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	harness.Close()
	for _, ns := range harness.Settings().Ns {
		matches, err := filepath.Glob(filepath.Join(settings.Directory, harness.EdgeProcess(ns), "*", "*"))
		if err != nil || len(matches) == 0 {
			t.Errorf("%s left no local snapshot: %v %v", ns, matches, err)
		}
	}
	if err := os.RemoveAll(settings.Directory); err != nil {
		t.Fatal(err)
	}
	query := &dns.Msg{}
	query.SetQuestion(harness.Root(), dns.TypeSOA)
	if _, err := harness.Query(t.Context(), "ns1", query); !errors.Is(err, ErrDnsHarnessDown) {
		t.Errorf("a closed harness answered: %v", err)
	}
	if _, err := os.Stat(settings.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something wrote after Close: %v", err)
	}
	harness.Close()
}
