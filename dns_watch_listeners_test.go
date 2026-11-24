//go:build !sidecar_http && !js && !ios_extension

package sidecar

// The zone watch's published names on a host that publishes through app listeners (D-TRUST-9, QD-1384): an sdk host's
// names are its tls/ app listeners' (ListenTls), and the watch its component composes asks about each name they
// serve, and the zone's apex, judging the name as a published host the edge answers, as it judges a publish's; a name
// no listener serves any more is asked no more. Every name and address is synthetic.

import (
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// An app listener's names join the watch's next pass, as the edge's, and leave it with the listener: before the
// listen a pass asks nothing; with tls/443/app served, a pass asks A, AAAA and CAA at its name and at the apex, the
// edge's addresses at the name raising no alarm; after its Close a pass asks nothing again.
func TestDnsWatchComponentWatchesTheAppListenersNames(t *testing.T) {
	clock := newTokenTestClock()
	running, _ := newTestDnsWatchSidecar(t, clock, &DnsZone{
		NetworkId: testNetworkId,
		Root:      tlsCertTestRoot + ".",
		Label:     tlsCertTestLabel,
		Version:   1,
	})
	alarms := make(chan SidecarDnsAlarm, 16)
	removeCallback := running.AddEventCallback(func(event SidecarEvent) {
		if event.Kind == SidecarEventDnsAlarm {
			alarms <- event.DnsAlarm
		}
	})
	defer removeCallback()

	// the tls component an sdk host runs, its certificate issued and its listens registering in memory
	running.leg = &sidecarConnectLeg{sidecar: running}
	fixture := newAttachedTlsCertFixture(t)
	fixture.ensureIssued()
	tlsComponent, parts := newTlsListenTestComponent(t, fixture, &testTlsListenRegistrations{edgeNetworkId: NewId()})
	if _, err := running.AddComponent(tlsComponent); err != nil {
		t.Fatal(err)
	}

	forwarders := &testDnsWatchComponentForwarders{}
	settings := testDnsWatchComponentSettings(forwarders)
	component := running.NewDnsWatchComponent(settings)
	defer component.Close()
	if err := component.Attach(&SidecarEnv{Ctx: t.Context(), Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	watch := running.mailDnsWatch()
	if watch == nil {
		t.Fatal("the first generation composed no watch")
	}
	interval := settings.Watch.Interval
	if wait := clock.awaitArmed(t, 1); wait != interval {
		t.Fatalf("the first pass waits %s, not the settings' %s", wait, interval)
	}
	pair, _ := forwarders.build(0)
	askedCount := func() int {
		return len(pair[0].asked()) + len(pair[1].asked())
	}

	// nothing listens yet: the pass asks nothing
	clock.Advance(interval)
	armed := awaitTestDnsWatchNextWait(t, clock, 1, interval)
	if status := watch.Status(); status.NameCount != 0 || askedCount() != 0 {
		t.Fatalf("a pass before any listen watched %d names and types, asking %d questions", status.NameCount, askedCount())
	}

	// the app serves tls/443/app: the next pass asks about its name, as the edge's, and about the apex
	listener, err := tlsComponent.listen(t.Context(), "tls/443/app", nil, parts)
	if err != nil {
		t.Fatal(err)
	}
	serverName := "app." + tlsCertTestLabel + "." + tlsCertTestRoot
	apex := tlsCertTestLabel + "." + tlsCertTestRoot
	for _, forwarder := range pair {
		forwarder.set(serverName, netip.MustParseAddr("192.0.2.44"), netip.MustParseAddr("2001:db8::44"))
	}
	clock.Advance(interval)
	armed = awaitTestDnsWatchNextWait(t, clock, armed, interval)
	if status := watch.Status(); status.NameCount != 6 || status.Degraded {
		t.Fatalf("a pass with the listener watched %d names and types, degraded %t", status.NameCount, status.Degraded)
	}
	for index, forwarder := range pair {
		questions := forwarder.asked()
		for _, name := range []string{serverName, apex} {
			for _, qType := range []uint16{DnsWatchTypeA, DnsWatchTypeAaaa, DnsWatchTypeCaa} {
				if !slices.Contains(questions, testDnsWatchSeamQuestion{qType: dnsmessage.Type(qType), domain: name}) {
					t.Errorf("resolver %d was not asked type %d at %s", index, qType, name)
				}
			}
		}
	}
	// addresses at a name the device does not publish would alarm as unrequested
	select {
	case alarm := <-alarms:
		t.Fatalf("the edge's addresses at the listener's name alarmed %s", alarm)
	default:
	}

	// the listener closed: the next pass asks nothing
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	before := askedCount()
	clock.Advance(interval)
	awaitTestDnsWatchNextWait(t, clock, armed, interval)
	if status := watch.Status(); status.NameCount != 0 || askedCount() != before {
		t.Fatalf("a pass after the listener's Close watched %d names and types, asking %d more questions", status.NameCount, askedCount()-before)
	}
}
