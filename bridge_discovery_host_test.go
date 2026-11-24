//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §17.7.1's host (owner decision 778), §22.5's §17 row from M6: the default and effective lists; what a host publishes,
// row by row: its own services at its overlay address, a shared device at the address its route serves, an exposed
// /32 keeping host bits, a map's port, never a link-local or IPv6 address, a point-to-point or LocalOnly answer, an
// overlay address or a device not shared; the hide set and the switches; listed entries' names from M13a; and a host's
// answer to each viewer equal to its hook's verdicts for that viewer, truncated past the caps.

package sidecar

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The time the host tests run at.
var discoveryTestNow = time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)

// The default list parses and holds Apple's device types; the document's block adds and removes; the port table types
// TCP alone.
func TestBridgeDiscoveryTypes(t *testing.T) {
	defaults := BridgeDiscoveryDefaultTypes()
	for _, want := range []string{"_remotepairing._tcp", "_remotepairing-manual-pairing._tcp", "_apple-mobdev2._tcp", "_device-info._tcp", "_smb._tcp", "_ipp._tcp", "_http._tcp"} {
		if !slices.Contains(defaults, want) {
			t.Errorf("the default list lacks %s", want)
		}
	}
	if !slices.IsSorted(defaults) {
		t.Errorf("the default list is not sorted")
	}
	effective := BridgeDiscoveryEffectiveTypes(&AclDiscoveryBlock{Allow: []string{"_airplay._tcp"}, Deny: []string{"_ipp._tcp"}})
	if !slices.Contains(effective, "_airplay._tcp") || slices.Contains(effective, "_ipp._tcp") || !slices.IsSorted(effective) {
		t.Errorf("the effective list %v", effective)
	}
	if !slices.Equal(BridgeDiscoveryEffectiveTypes(nil), defaults) {
		t.Errorf("with no block the effective list is not the default")
	}
	if bridgeDiscoveryPortType("tcp", 3000) != "_http._tcp" || bridgeDiscoveryPortType("tcp", 445) != "_smb._tcp" ||
		bridgeDiscoveryPortType("udp", 22) != "" || bridgeDiscoveryPortType("tcp", 5432) != "" {
		t.Errorf("the port table reads wrong")
	}
	for _, bad := range []string{"_ipp\n", "_ipp._tcp\n_ipp._tcp\n", "_IPP._tcp\n"} {
		if _, err := parseBridgeDiscoveryTypes(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	for _, bad := range []string{"22 _ssh._tcp\n", "22/udp _ssh._tcp\n", "22/tcp _ssh._udp\n", "22/tcp _ssh._tcp\n22/tcp _sftp-ssh._tcp\n"} {
		if _, err := parseBridgeDiscoveryPorts(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// A host's routes: its overlay address in 100.80/16, a plain served subnet, a remapped one, and maps to a LAN device.
func discoveryTestRoutes() *BridgeDiscoveryRoutes {
	return &BridgeDiscoveryRoutes{
		Blocks:    []netip.Prefix{netip.MustParsePrefix("100.80.0.0/16")},
		Addresses: []netip.Addr{netip.MustParseAddr("100.80.1.2")},
		Served: []BridgeDiscoveryServed{
			{Prefix: netip.MustParsePrefix("192.168.50.0/24")},
			{Prefix: netip.MustParsePrefix("192.168.60.0/24"), Exposed: netip.MustParsePrefix("100.80.200.0/24")},
		},
		Maps: []BridgeDiscoveryMap{
			{Address: netip.MustParseAddr("100.80.1.2"), Transport: "_tcp", FirstPort: 8631, LastPort: 8631, Target: netip.MustParseAddr("192.168.70.9"), TargetPort: 631},
		},
	}
}

// A gathered instance of service at port on host, at address.
func discoveryTestGathered(name string, service string, port uint16, host string, address string) *BridgeDiscoveryGathered {
	return &BridgeDiscoveryGathered{
		Name:      name,
		Service:   service,
		Port:      port,
		Txt:       []byte("\x05txt=1"),
		HostName:  host + ".local.",
		Addresses: []netip.Addr{netip.MustParseAddr(address)},
		Expires:   discoveryTestNow.Add(2 * time.Minute),
	}
}

// What the host publishes from gathered with state, by "<name>|<address>:<port>".
func discoveryTestPublish(gathered []*BridgeDiscoveryGathered, listed []*BridgeDiscoveryListedEntry, state *bridgeDiscoveryState, routes *BridgeDiscoveryRoutes) []string {
	input := &bridgeDiscoveryHostInput{
		routes:    routes,
		gathered:  gathered,
		listed:    listed,
		types:     BridgeDiscoveryEffectiveTypes(nil),
		state:     state,
		hostLabel: "host-a",
	}
	published := []string{}
	for _, item := range bridgeDiscoveryPublish(input, discoveryTestNow, DefaultBridgeDiscoverySettings()) {
		published = append(published, item.instance.GetName()+"|"+netip.AddrPortFrom(item.address, uint16(item.instance.GetPort())).String())
	}
	slices.Sort(published)
	return published
}

// Own services stand at the overlay address with their own ports; shared devices at their route's address, an exposed
// prefix's with host bits kept, or a map's port; nothing else is published.
func TestBridgeDiscoveryPublishesByRow(t *testing.T) {
	own := discoveryTestGathered("Host Files", "_smb._tcp", 445, "Host-A", "192.168.50.2")
	own.Own = true
	served := discoveryTestGathered("Synthetic Printer", "_ipp._tcp", 631, "printer", "192.168.50.20")
	exposed := discoveryTestGathered("Synthetic Phone", "_remotepairing._tcp", 49152, "phone", "192.168.60.33")
	mapped := discoveryTestGathered("Mapped Printer", "_ipp._tcp", 631, "mapped", "192.168.70.9")
	unserved := discoveryTestGathered("Elsewhere", "_ipp._tcp", 631, "elsewhere", "192.168.80.9")
	unshared := discoveryTestGathered("Neighbor's TV", "_http._tcp", 80, "tv", "192.168.50.77")
	linkLocal := discoveryTestGathered("Link Local", "_ssh._tcp", 22, "linklocal", "169.254.3.4")
	ipv6 := discoveryTestGathered("Only Six", "_ssh._tcp", 22, "six", "2001:db8::6")
	pointToPoint := discoveryTestGathered("Tunnel", "_ssh._tcp", 22, "tunnel", "192.168.50.21")
	pointToPoint.PointToPoint = true
	localOnly := discoveryTestGathered("Proxied", "_ssh._tcp", 22, "proxied", "192.168.50.22")
	localOnly.LocalOnly = true
	overlay := discoveryTestGathered("Overlay", "_ssh._tcp", 22, "overlay", "100.80.9.9")
	untyped := discoveryTestGathered("Cast", "_googlecast._tcp", 8009, "printer", "192.168.50.20")
	state := newBridgeDiscoveryState()
	for _, label := range []string{"printer", "phone", "mapped", "elsewhere", "linklocal", "six", "tunnel", "proxied", "overlay"} {
		state.Shares = append(state.Shares, &bridgeDiscoveryShare{HostLabel: label, State: bridgeDiscoveryShareActive})
	}
	gathered := []*BridgeDiscoveryGathered{own, served, exposed, mapped, unserved, unshared, linkLocal, ipv6, pointToPoint, localOnly, overlay, untyped}
	got := discoveryTestPublish(gathered, nil, state, discoveryTestRoutes())
	want := []string{
		"Host Files|100.80.1.2:445",
		"Mapped Printer|100.80.1.2:8631",
		"Synthetic Phone|100.80.200.33:49152",
		"Synthetic Printer|192.168.50.20:631",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("published %v\nwant %v", got, want)
	}

	// a share waiting for its approval publishes nothing; no overlay address publishes no own service
	waiting := state.clone()
	waiting.share("printer").State = bridgeDiscoveryShareWaiting
	if got := discoveryTestPublish([]*BridgeDiscoveryGathered{served}, nil, waiting, discoveryTestRoutes()); len(got) != 0 {
		t.Errorf("a waiting share published %v", got)
	}
	homeless := discoveryTestRoutes()
	homeless.Addresses = nil
	if got := discoveryTestPublish([]*BridgeDiscoveryGathered{own}, nil, state, homeless); len(got) != 0 {
		t.Errorf("a host with no overlay address published %v", got)
	}
}

// One hide set: a port at the overlay address takes the own service and a listed entry on it; an instance takes that
// instance; the device hidden whole takes every own and listed instance, while a shared device's stays; off withholds
// own and listed names alone.
func TestBridgeDiscoveryHidesAndSwitches(t *testing.T) {
	own := discoveryTestGathered("Host Files", "_smb._tcp", 445, "Host-A", "192.168.50.2")
	own.Own = true
	ownSsh := discoveryTestGathered("Host Shell", "_ssh._tcp", 22, "Host-A", "192.168.50.2")
	ownSsh.Own = true
	served := discoveryTestGathered("Synthetic Printer", "_ipp._tcp", 631, "printer", "192.168.50.20")
	listed := []*BridgeDiscoveryListedEntry{{Protocol: "tcp", Port: 3000, Description: "node"}}
	gathered := []*BridgeDiscoveryGathered{own, ownSsh, served}
	base := newBridgeDiscoveryState()
	base.Shares = []*bridgeDiscoveryShare{{HostLabel: "printer", State: bridgeDiscoveryShareActive}}
	cases := []struct {
		name string
		edit func(state *bridgeDiscoveryState)
		want []string
	}{
		{name: "nothing hidden", edit: func(state *bridgeDiscoveryState) {}, want: []string{
			"Host Files|100.80.1.2:445", "Host Shell|100.80.1.2:22", "Synthetic Printer|192.168.50.20:631", "node :3000|100.80.1.2:3000",
		}},
		{name: "a port", edit: func(state *bridgeDiscoveryState) { state.HiddenPorts = []string{"tcp/445", "tcp/3000"} }, want: []string{
			"Host Shell|100.80.1.2:22", "Synthetic Printer|192.168.50.20:631",
		}},
		{name: "an instance", edit: func(state *bridgeDiscoveryState) {
			state.HiddenInstances = []string{bridgeDiscoveryInstanceKey("SYNTHETIC printer", "_ipp._tcp")}
		}, want: []string{"Host Files|100.80.1.2:445", "Host Shell|100.80.1.2:22", "node :3000|100.80.1.2:3000"}},
		{name: "the device", edit: func(state *bridgeDiscoveryState) { state.HiddenDevice = true }, want: []string{
			"Synthetic Printer|192.168.50.20:631",
		}},
		{name: "off", edit: func(state *bridgeDiscoveryState) { state.OwnOff = true }, want: []string{
			"Synthetic Printer|192.168.50.20:631",
		}},
	}
	for _, c := range cases {
		state := base.clone()
		c.edit(state)
		if got := discoveryTestPublish(gathered, listed, state, discoveryTestRoutes()); !slices.Equal(got, c.want) {
			t.Errorf("%s: published %v\nwant %v", c.name, got, c.want)
		}
	}
}

// Listed entries (M13a): the person's type, else the port's, TCP alone; none labeled none, of a type off the list, or
// where the host's own mDNS holds the port; "<description> :<port>" cut to 63 octets at a character.
func TestBridgeDiscoveryListedEntriesTakeNames(t *testing.T) {
	own := discoveryTestGathered("Host Files", "_smb._tcp", 445, "Host-A", "192.168.50.2")
	own.Own = true
	long := strings.Repeat("é", 40)
	listed := []*BridgeDiscoveryListedEntry{
		{Protocol: "tcp", Port: 3000, Description: "node"},
		{Protocol: "tcp", Port: 445, Description: "samba"},
		{Protocol: "tcp", Port: 5432, Description: "postgres"},
		{Protocol: "tcp", Port: 9000, Description: "shop", Type: "_http._tcp"},
		{Protocol: "tcp", Port: 8080, Description: "hidden by label", Type: BridgeDiscoveryListedTypeNone},
		{Protocol: "udp", Port: 5353, Description: "udp, no label"},
		{Protocol: "udp", Port: 51820, Description: "wireguard", Type: "_wg._udp"},
		{Protocol: "tcp", Port: 8000, Description: long},
	}
	got := discoveryTestPublish([]*BridgeDiscoveryGathered{own}, listed, newBridgeDiscoveryState(), discoveryTestRoutes())
	cut := strings.Repeat("é", 28) + " :8000"
	want := []string{"Host Files|100.80.1.2:445", cut + "|100.80.1.2:8000", "node :3000|100.80.1.2:3000", "shop :9000|100.80.1.2:9000"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("published %v\nwant %v", got, want)
	}
	if 63 < len(cut) {
		t.Errorf("a cut name of %d octets", len(cut))
	}
}

// A host's answer for a viewer holds exactly the instances its hook passes for that viewer, with each one's seconds
// left; past InstanceCount or AnswerByteCount it truncates; serving false carries none.
func TestBridgeDiscoveryAnswerIsTheHooksVerdict(t *testing.T) {
	viewer := Id{0x01}
	other := Id{0x02}
	published := []*bridgeDiscoveryPublished{}
	for i := range 10 {
		published = append(published, &bridgeDiscoveryPublished{
			instance: &protocol.DnsSdInstance{Name: "Share " + string(rune('A'+i)), Service: "_smb._tcp", Port: uint32(445 + i), HostLabel: "nas", Ipv4: 0x6450010A},
			address:  netip.MustParseAddr("100.80.1.10"),
			expires:  discoveryTestNow.Add(time.Duration(30+i) * time.Second),
		})
	}
	view := &bridgeDiscoveryHostView{version: 7, serving: true, published: published}
	// the viewer reaches the even ports alone, the other none
	reach := func(source Id, address netip.AddrPort, transport string) bool {
		return source == viewer && address.Port()%2 == 1 && transport == "_tcp"
	}
	wire := protocol.DefaultDnsSdWireSettings()
	answer := bridgeDiscoveryAnswer(view, viewer, reach, discoveryTestNow, wire)
	if answer.GetVersion() != 7 || !answer.GetServing() || answer.GetTruncated() || len(answer.GetInstances()) != 5 {
		t.Fatalf("the viewer's answer: version %d, serving %t, truncated %t, %d instances", answer.GetVersion(), answer.GetServing(), answer.GetTruncated(), len(answer.GetInstances()))
	}
	if ttl := answer.GetInstances()[0].GetTtl(); ttl != 30 {
		t.Errorf("the first instance's ttl %d", ttl)
	}
	if none := bridgeDiscoveryAnswer(view, other, reach, discoveryTestNow, wire); len(none.GetInstances()) != 0 {
		t.Errorf("a viewer the hook refuses got %d instances", len(none.GetInstances()))
	}
	if none := bridgeDiscoveryAnswer(view, viewer, nil, discoveryTestNow, wire); len(none.GetInstances()) != 0 {
		t.Errorf("no hook gave %d instances", len(none.GetInstances()))
	}
	capped := *wire
	capped.InstanceCount = 2
	if truncated := bridgeDiscoveryAnswer(view, viewer, reach, discoveryTestNow, &capped); !truncated.GetTruncated() || len(truncated.GetInstances()) != 2 {
		t.Errorf("past InstanceCount: truncated %t with %d", truncated.GetTruncated(), len(truncated.GetInstances()))
	}
	sized := *wire
	sized.AnswerByteCount = 60
	if truncated := bridgeDiscoveryAnswer(view, viewer, reach, discoveryTestNow, &sized); !truncated.GetTruncated() || len(truncated.GetInstances()) != 1 {
		t.Errorf("past AnswerByteCount: truncated %t with %d", truncated.GetTruncated(), len(truncated.GetInstances()))
	}
	expired := bridgeDiscoveryAnswer(view, viewer, reach, discoveryTestNow.Add(time.Hour), wire)
	if len(expired.GetInstances()) != 0 {
		t.Errorf("expired instances answered: %d", len(expired.GetInstances()))
	}
	quiet := bridgeDiscoveryAnswer(&bridgeDiscoveryHostView{version: 8, published: published}, viewer, reach, discoveryTestNow, wire)
	if quiet.GetServing() || len(quiet.GetInstances()) != 0 {
		t.Errorf("a host serving nothing answered %d instances", len(quiet.GetInstances()))
	}
}

// A host label is an mDNS host name's first label as LDH.
func TestBridgeDiscoveryHostLabel(t *testing.T) {
	cases := map[string]string{
		"Synthetic-Phone.local.": "synthetic-phone",
		"Alice's iPhone.local":   "alice-s-iphone",
		"--x--.local":            "x",
		"é.local":                "",
		"":                       "",
	}
	for name, want := range cases {
		if got := BridgeDiscoveryHostLabel(name); got != want {
			t.Errorf("%q: %q, want %q", name, got, want)
		}
	}
}
