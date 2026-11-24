package main

// The daemon's zone watch (daemon_dns.go; D-TRUST-9, DNS-M5-22): startUrDns, which network.start runs for each network
// the daemon hosts, adds the core's zone watch beside the dns component. At the network's first client generation the
// watch composes on the daemon's settings, its resolvers the ones those settings name; it reads the file an earlier
// run left in the network's dns/ directory, reads the zone from the dns block through the network's own DnsClient,
// and raises the split its resolvers show as the network's dns_alarm; and closing the Sidecar ends it and releases its
// resolvers. Every name and address is synthetic, and no query leaves the test.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// One resolver for the daemon's zone watch: host, given without its final dot, holds addresses as its A and AAAA, and
// every other name and type answers NODATA.
type testUrDnsWatchForwarder struct {
	host      string
	addresses []netip.Addr
}

func (self *testUrDnsWatchForwarder) Forward(ctx context.Context, qType dnsmessage.Type, domain string) ([]byte, bool) {
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		return nil, false
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess})
	if builder.StartQuestions() != nil || builder.Question(dnsmessage.Question{Name: name, Type: qType, Class: dnsmessage.ClassINET}) != nil || builder.StartAnswers() != nil {
		return nil, false
	}
	if domain == self.host {
		for _, address := range self.addresses {
			header := dnsmessage.ResourceHeader{Name: name, Type: qType, Class: dnsmessage.ClassINET, TTL: 60}
			switch {
			case qType == dnsmessage.TypeA && address.Is4():
				err = builder.AResource(header, dnsmessage.AResource{A: address.As4()})
			case qType == dnsmessage.TypeAAAA && address.Is6():
				err = builder.AAAAResource(header, dnsmessage.AAAAResource{AAAA: address.As16()})
			}
			if err != nil {
				return nil, false
			}
		}
	}
	response, err := builder.Finish()
	return response, err == nil
}

// The watch's resolvers as its settings' ForwarderFactory builds them: two, the second answering another IPv4
// address at host than the first, so every pass sees a split there. Builds and releases are counted.
type testUrDnsWatchForwarders struct {
	host     string
	builds   atomic.Int32
	releases atomic.Int32
}

func (self *testUrDnsWatchForwarders) factory() (*sidecar.DnsWatchForwarders, error) {
	self.builds.Add(1)
	return &sidecar.DnsWatchForwarders{
		Forwarders: []sidecar.DnsWatchForwarder{
			&testUrDnsWatchForwarder{host: self.host, addresses: []netip.Addr{netip.MustParseAddr("192.0.2.44"), netip.MustParseAddr("2001:db8::44")}},
			&testUrDnsWatchForwarder{host: self.host, addresses: []netip.Addr{netip.MustParseAddr("198.51.100.44"), netip.MustParseAddr("2001:db8::44")}},
		},
		Close: func() { self.releases.Add(1) },
	}, nil
}

// The file's comment: the daemon's composition of a network runs its zone watch on the daemon's settings, and the
// watch's split reaches the network's events.
func TestDaemonRunsEachNetworksZoneWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	running, _, _ := bootstrapTestDaemonOwner(t, ctx, net, engines)
	networkId := running.Identity().NetworkId
	api := engines.Api()
	// the dns block's GET /dns/zone for the network's own sidecars: a host the edge answers
	const label, root = "a7q2m9x4k1", "users.example"
	host := "shop." + label + "." + root
	api.ServeService("dns", http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		bearer, _ := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
		principal, err := api.Authenticator().Authenticate(request.Context(), "dns", bearer)
		if err != nil || request.Method != http.MethodGet || request.URL.Path != sidecar.DnsZonePath || principal.NetworkId != connect.Id(networkId) {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(&sidecar.DnsZone{NetworkId: networkId, Root: root, Label: label, Version: 1, RecordSets: []sidecar.DnsZoneRecordSet{
			{Name: host + ".", Type: "A", Ttl: 60, Kind: "edge"},
			{Name: host + ".", Type: "AAAA", Ttl: 60, Kind: "edge"},
		}})
	}))
	t.Cleanup(func() { api.ServeService("dns", nil) })

	// what an earlier run's watch kept in the network's dns/ directory (the core's dns_watch.go, its file's format 1):
	// the host, which this run's passes ask about
	store, err := running.LocalStore().Directory("dns", "dns")
	if err != nil {
		t.Fatal(err)
	}
	writer, err := store.Create("watch.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(`{"format":1,"expected":[],"names":["` + host + `."]}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	writer.Close()

	alarms := make(chan sidecar.SidecarDnsAlarm, 1)
	removeCallback := running.AddEventCallback(func(event sidecar.SidecarEvent) {
		if event.Kind != sidecar.SidecarEventDnsAlarm {
			return
		}
		select {
		case alarms <- event.DnsAlarm:
		default:
		}
	})
	defer removeCallback()
	forwarders := &testUrDnsWatchForwarders{host: host}
	settings := sidecar.DefaultDnsWatchComponentSettings()
	// shorter than any other wait on the Net's clock, and no other's length, so moving the clock by it fires the
	// watch's wait alone
	settings.Watch.Interval = 1007 * time.Nanosecond
	settings.Watch.Jitter = 0
	settings.Watch.PassMinWait = time.Nanosecond
	settings.Doh.ForwarderFactory = forwarders.factory

	startUrDns(running, settings, sidecar.NewNoopLogger())
	if remove, err := running.AddComponent(&testUrNamedComponent{name: "dns-watch"}); err == nil {
		remove()
		t.Fatal("the daemon's composition added no zone watch")
	}
	follower := startUrConfigFollower(running, sidecar.NewNoopLogger())
	if follower == nil {
		t.Fatal("no follower started")
	}
	if _, err := follower.WaitStanding(ctx); err != nil {
		t.Fatal(err)
	}
	// a generation attaches its components in the order they were added, so the follower standing means the zone
	// watch has attached, composing its watch over the settings' resolvers
	if builds, releases := forwarders.builds.Load(), forwarders.releases.Load(); builds != 1 || releases != 0 {
		t.Fatalf("the daemon's zone watch built %d resolvers and released %d", builds, releases)
	}
	// the watch waits on the Sidecar's clock, the Net's, which moves only when a test moves it: once its first wait is
	// set, moving the clock to it runs a pass
	clock := net.Clock()
	due := clock.Now().Add(settings.Watch.Interval)
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, due.Equal) {
			break
		}
		select {
		case <-added:
		case <-ctx.Done():
			t.Fatal("the daemon's zone watch set no wait for its first pass")
		}
	}
	clock.Advance(settings.Watch.Interval)
	select {
	case alarm := <-alarms:
		if alarm != sidecar.SidecarDnsAlarmSplit {
			t.Fatalf("the daemon's zone watch alarmed %s", alarm)
		}
	case <-ctx.Done():
		t.Fatal("the daemon's zone watch raised no alarm on its resolvers' split")
	}
	if err := running.CloseAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	if builds, releases := forwarders.builds.Load(), forwarders.releases.Load(); builds != 1 || releases != 1 {
		t.Fatalf("the closed Sidecar's zone watch: %d resolvers built, %d released", builds, releases)
	}
}
