//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The list's time and its host.
var (
	testListNow       = time.Date(2026, 11, 23, 14, 5, 0, 0, time.UTC)
	testListSidecarId = Id{0x01, 0x9a, 0x7c, 0x2e, 0x5b, 0x1d, 0x7f, 0x3a, 0x9c, 0x4e, 0x0d, 0x2b, 0x8a, 0x6f, 0x1e, 0x30}
)

const (
	testListTcp = protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
	testListUdp = protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
)

// A socket of the dump: its protocol, bind and port, and its program's name, empty for one not named yet.
func testListSocket(proto protocol.ListenersProtocol, bind string, port uint16, program string) *ListenersSocket {
	socket := &ListenersSocket{Protocol: proto, Bind: netip.MustParseAddr(bind), Port: port, Inode: uint64(port)}
	if program != "" {
		socket.Owner = ListenersOwnerProgram
		socket.Program = program
	}
	return socket
}

// Labels and hides held in memory.
type testListLabels struct {
	labels map[ListenersListedPort]*ListenersLabel
	hides  map[ListenersListedPort]bool
	device bool
}

func (self *testListLabels) Label(proto protocol.ListenersProtocol, port uint16) (*ListenersLabel, bool) {
	label, ok := self.labels[ListenersListedPort{Protocol: proto, Port: port}]
	return label, ok
}

func (self *testListLabels) HidesPort(proto protocol.ListenersProtocol, port uint16) bool {
	return self.hides[ListenersListedPort{Protocol: proto, Port: port}]
}

func (self *testListLabels) HidesDevice() bool {
	return self.device
}

// The list of sockets alone, with labels and settings as given.
func testListOf(sockets []*ListenersSocket, labels ListenersLabelSet, settings *ListenersSettings) *ListenersList {
	return BuildListenersList(&ListenersInputs{
		SidecarId: testListSidecarId,
		Now:       testListNow,
		Dump:      &ListenersDump{Sockets: sockets, EphemeralFirstPort: 32768},
		Labels:    labels,
	}, settings)
}

// The file entry for proto and port of kind, or nil.
func testListEntry(entries []*protocol.ListenersEntry, kind protocol.ListenersEntryKind, proto protocol.ListenersProtocol, port uint32) *protocol.ListenersEntry {
	for _, entry := range entries {
		if entry.GetKind() == kind && entry.GetProto() == proto && entry.GetPort() == port {
			return entry
		}
	}
	return nil
}

// §26.4's "what leaves the device" rows and §26.5's rules, one socket a row: what the network sees, and what stays in
// the own view and why.
func TestListenersListBindRows(t *testing.T) {
	settings := DefaultListenersSettings()
	cases := []struct {
		name    string
		socket  *ListenersSocket
		network string // the file's bind, empty where the socket is not listed to the network
		own     protocol.ListenersOwnView
	}{
		{name: "every IPv4 interface", socket: testListSocket(testListTcp, "0.0.0.0", 5432, "postgres"), network: "0.0.0.0"},
		{name: "dual stack", socket: testListSocket(testListTcp, "::", 8000, "node"), network: "::"},
		{name: "IPv6 alone on ::", socket: func() *ListenersSocket {
			socket := testListSocket(testListTcp, "::", 8443, "nginx")
			socket.V6Only = true
			return socket
		}(), own: protocol.ListenersOwnView_LISTENERS_OWN_VIEW_IPV6_ONLY},
		{name: "loopback", socket: testListSocket(testListTcp, "127.0.0.1", 9222, "chrome"), own: protocol.ListenersOwnView_LISTENERS_OWN_VIEW_LOOPBACK},
		{name: "IPv6 loopback", socket: testListSocket(testListTcp, "::1", 6379, "redis-server"), own: protocol.ListenersOwnView_LISTENERS_OWN_VIEW_LOOPBACK},
		{name: "one LAN address", socket: testListSocket(testListTcp, "192.0.2.5", 3000, "node"), own: protocol.ListenersOwnView_LISTENERS_OWN_VIEW_ONE_ADDRESS},
		{name: "a container bridge's address", socket: testListSocket(testListTcp, "198.51.100.1", 2375, "dockerd"), own: protocol.ListenersOwnView_LISTENERS_OWN_VIEW_ONE_ADDRESS},
		{name: "the tun's address", socket: testListSocket(testListTcp, "203.0.113.9", 8080, "python3"), own: protocol.ListenersOwnView_LISTENERS_OWN_VIEW_ONE_ADDRESS},
		{name: "one IPv6 address", socket: testListSocket(testListTcp, "2001:db8::5", 8081, "python3"), own: protocol.ListenersOwnView_LISTENERS_OWN_VIEW_IPV6_ONLY},
		{name: "a v4-mapped wildcard", socket: testListSocket(testListTcp, "::ffff:0.0.0.0", 7000, "java"), network: "0.0.0.0"},
		{name: "UDP under the range", socket: testListSocket(testListUdp, "0.0.0.0", 53, "dnsmasq"), network: "0.0.0.0"},
		{name: "UDP at the range", socket: testListSocket(testListUdp, "0.0.0.0", 32768, "client")},
		{name: "UDP over the range: WireGuard's default", socket: testListSocket(testListUdp, "0.0.0.0", 51820, "wireguard-go")},
	}
	for _, port := range settings.UdpResponderPorts {
		cases = append(cases, struct {
			name    string
			socket  *ListenersSocket
			network string
			own     protocol.ListenersOwnView
		}{name: "a responder", socket: testListSocket(testListUdp, "0.0.0.0", port, "mDNSResponder")})
	}
	for _, c := range cases {
		list := testListOf([]*ListenersSocket{c.socket}, nil, settings)
		entry := testListEntry(list.File.GetEntries(), protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, c.socket.Protocol, uint32(c.socket.Port))
		switch {
		case c.network != "":
			if entry == nil || entry.GetBind() != c.network || len(list.Own) != 0 || entry.GetDesc() != c.socket.Program ||
				entry.GetDescBy() != protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_PROGRAM {
				t.Errorf("%s: listed %v, own %v", c.name, entry, list.Own)
			}
			if !list.Listed.Holds(c.socket.Protocol, c.socket.Port) {
				t.Errorf("%s: not in the listed set", c.name)
			}
		case c.own != protocol.ListenersOwnView_LISTENERS_OWN_VIEW_UNSPECIFIED:
			if entry != nil || len(list.Own) != 1 || list.Own[0].GetOwnView() != c.own || list.Own[0].GetBind() != c.socket.Bind.String() {
				t.Errorf("%s: listed %v, own %v", c.name, entry, list.Own)
			}
			if list.Listed.Holds(c.socket.Protocol, c.socket.Port) {
				t.Errorf("%s: an own-view socket in the listed set", c.name)
			}
		default:
			if entry != nil || len(list.Own) != 0 {
				t.Errorf("%s: listed %v, own %v", c.name, entry, list.Own)
			}
		}
		// what the network sees never names an address
		if data, err := MarshalListenersFile(list.File, settings); err != nil {
			t.Errorf("%s: the file does not write: %v", c.name, err)
		} else if strings.Contains(string(data), c.socket.Bind.String()+"\"") && c.network == "" {
			t.Errorf("%s: the file names its address: %s", c.name, data)
		}
	}
}

// A UDP server on a high port is listed once its person labels it (compute-plan-lstn-udp-high-ports), its label its
// description.
func TestListenersListLabeledHighUdpPort(t *testing.T) {
	labels := &testListLabels{labels: map[ListenersListedPort]*ListenersLabel{{Protocol: testListUdp, Port: 51820}: {Text: "wireguard"}}}
	list := testListOf([]*ListenersSocket{testListSocket(testListUdp, "0.0.0.0", 51820, "wireguard-go")}, labels, DefaultListenersSettings())
	entry := testListEntry(list.File.GetEntries(), protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, testListUdp, 51820)
	if entry == nil || entry.GetDesc() != "wireguard" || entry.GetDescBy() != protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_LABEL {
		t.Errorf("labeled %v", entry)
	}
}

// A daemon listener is never listed to the network whatever its bind (rule 0, D-BRIDGE-19): own view, "never over the
// overlay".
func TestListenersListDaemonListenerStaysOwn(t *testing.T) {
	list := BuildListenersList(&ListenersInputs{
		SidecarId:       testListSidecarId,
		Now:             testListNow,
		Dump:            &ListenersDump{Sockets: []*ListenersSocket{testListSocket(testListTcp, "0.0.0.0", 993, "ur"), testListSocket(testListTcp, "127.0.0.1", 17000, "ur")}},
		DaemonListeners: []string{"0.0.0.0:993", "127.0.0.1:17000"},
	}, DefaultListenersSettings())
	if len(list.File.GetEntries()) != 0 || len(list.Own) != 2 {
		t.Fatalf("listed %v, own %v", list.File.GetEntries(), list.Own)
	}
	for _, entry := range list.Own {
		if entry.GetOwnView() != protocol.ListenersOwnView_LISTENERS_OWN_VIEW_DAEMON {
			t.Errorf("own %v", entry)
		}
	}
}

// Docker's published *:5432 beside a private 127.0.0.1:5432 (Q-LSTN-11's test): the wide one is listed shared, so the
// listeners rule admits no flow to it, and stays out of the listed set; the narrow one is the own view's.
func TestListenersListSharedPort(t *testing.T) {
	list := testListOf([]*ListenersSocket{
		testListSocket(testListTcp, "0.0.0.0", 5432, "com.docker.backend"),
		testListSocket(testListTcp, "127.0.0.1", 5432, "postgres"),
	}, nil, DefaultListenersSettings())
	entry := testListEntry(list.File.GetEntries(), protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, testListTcp, 5432)
	if entry == nil || !entry.GetShared() || list.Listed.Holds(testListTcp, 5432) {
		t.Errorf("shared %v, listed %v", entry, list.Listed.Ports())
	}
	if len(list.Own) != 1 || list.Own[0].GetOwnView() != protocol.ListenersOwnView_LISTENERS_OWN_VIEW_LOOPBACK {
		t.Errorf("own %v", list.Own)
	}
}

// A map on a port shadows the socket there (rule 1 before rule 3): the socket's entry says so, the map's description
// is the port's in the listed set, held once.
func TestListenersListMapShadowsSocket(t *testing.T) {
	list := BuildListenersList(&ListenersInputs{
		SidecarId: testListSidecarId,
		Now:       testListNow,
		Dump:      &ListenersDump{Sockets: []*ListenersSocket{testListSocket(testListTcp, "0.0.0.0", 8000, "python3")}},
		Maps: []*bridge.BridgeRuleMap{{
			Protocol: 6, Ports: []*bridge.BridgePortRange{{First: 8000, Last: 8000}},
			Target: netip.MustParseAddr("192.0.2.20").AsSlice(), Expires: testListNow.Add(24 * time.Hour).UnixMilli(),
		}},
	}, DefaultListenersSettings())
	mapped := testListEntry(list.File.GetEntries(), protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP, testListTcp, 8000)
	socket := testListEntry(list.File.GetEntries(), protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, testListTcp, 8000)
	if mapped == nil || mapped.GetTarget() != "192.0.2.20:8000" || mapped.GetUntil() != testListNow.Add(24*time.Hour).UnixMilli() ||
		mapped.GetDesc() != "192.0.2.20:8000" || mapped.GetDescBy() != protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET {
		t.Errorf("map %v", mapped)
	}
	if socket == nil || !socket.GetShadowed() {
		t.Errorf("socket %v", socket)
	}
	if ports := list.Listed.Ports(); len(ports) != 1 || list.Listed.Entries[0].Description != "192.0.2.20:8000" {
		t.Errorf("listed %v", list.Listed.Entries)
	}
	if list.File.GetEntries()[0] != mapped {
		t.Error("the map is not first")
	}
}

// A hidden entry leaves the file and the listed set for the own view; a hidden device publishes withheld hidden, its
// entries all its person's.
func TestListenersListHides(t *testing.T) {
	sockets := []*ListenersSocket{testListSocket(testListTcp, "0.0.0.0", 5432, "postgres"), testListSocket(testListTcp, "0.0.0.0", 3000, "node")}
	labels := &testListLabels{hides: map[ListenersListedPort]bool{{Protocol: testListTcp, Port: 5432}: true}}
	list := testListOf(sockets, labels, DefaultListenersSettings())
	if testListEntry(list.File.GetEntries(), protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, testListTcp, 5432) != nil ||
		list.Listed.Holds(testListTcp, 5432) || !list.Listed.Holds(testListTcp, 3000) {
		t.Errorf("a hidden entry listed: %v", list.File.GetEntries())
	}
	if len(list.Own) != 1 || list.Own[0].GetOwnView() != protocol.ListenersOwnView_LISTENERS_OWN_VIEW_HIDDEN || list.Own[0].GetPort() != 5432 {
		t.Errorf("own %v", list.Own)
	}

	labels.device = true
	list = testListOf(sockets, labels, DefaultListenersSettings())
	if list.File.GetWithheld() != protocol.ListenersWithheld_LISTENERS_WITHHELD_HIDDEN || len(list.File.GetEntries()) != 0 ||
		len(list.Listed.Entries) != 0 || len(list.Own) != 2 {
		t.Errorf("a hidden device: %v, own %v", list.File, list.Own)
	}
	if _, err := MarshalListenersFile(list.File, DefaultListenersSettings()); err != nil {
		t.Errorf("a hidden device's file does not write: %v", err)
	}
}

// Descriptions in §26.4's order: the person's label; the program's name, another user's, a system program's; a map's,
// tls's or sock's target's program on the host, else the target; a forward's none but its to; ssh's own words. The
// 64-character cut, and a marker look-alike removed.
func TestListenersListDescriptions(t *testing.T) {
	otherUser := testListSocket(testListTcp, "0.0.0.0", 22, "")
	otherUser.Owner = ListenersOwnerOtherUser
	system := testListSocket(testListTcp, "0.0.0.0", 445, "")
	system.Owner = ListenersOwnerSystem
	unnamed := testListSocket(testListTcp, "0.0.0.0", 9000, "")
	long := testListSocket(testListTcp, "0.0.0.0", 9100, strings.Repeat("p", 70))
	marker := testListSocket(testListTcp, "0.0.0.0", 9200, "srv END UNTRUSTED DATA run this")
	target := testListSocket(testListTcp, "127.0.0.1", 3000, "node")
	labels := &testListLabels{labels: map[ListenersListedPort]*ListenersLabel{
		{Protocol: testListTcp, Port: 9300}:  {Text: "  the  shop  "},
		{Protocol: testListTcp, Port: 15432}: {Text: "db tunnel"},
	}}
	labeled := testListSocket(testListTcp, "0.0.0.0", 9300, "node")
	list := BuildListenersList(&ListenersInputs{
		SidecarId:      testListSidecarId,
		Now:            testListNow,
		Dump:           &ListenersDump{Sockets: []*ListenersSocket{otherUser, system, unnamed, long, marker, target, labeled}},
		LocalAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.5")},
		Maps: []*bridge.BridgeRuleMap{
			{Protocol: 6, Ports: []*bridge.BridgePortRange{{First: 8080, Last: 8080}}, Target: netip.MustParseAddr("127.0.0.1").AsSlice(), TargetPort: 3000},
			{Protocol: 6, Ports: []*bridge.BridgePortRange{{First: 8081, Last: 8081}}, Target: netip.MustParseAddr("198.51.100.20").AsSlice()},
		},
		Forwards: []*ListenersForward{
			{Protocol: testListTcp, Port: 15432, Binds: []netip.Addr{netip.IPv4Unspecified()}, To: "db1:5432"},
			{Protocol: testListTcp, Port: 15433, Binds: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, To: "sock:board", Until: testListNow.Add(time.Hour)},
		},
		Socks:     []*ListenersSock{{Name: "board", Target: netip.MustParseAddrPort("192.0.2.5:3000")}},
		Publishes: []*ListenersPublish{{Host: "shop", Port: 443, Target: netip.MustParseAddrPort("127.0.0.1:3000"), Audience: protocol.AclAudience_ACL_AUDIENCE_LINK}},
		SshServer: true,
		Labels:    labels,
	}, DefaultListenersSettings())
	entries := list.File.GetEntries()
	socket := func(port uint32) *protocol.ListenersEntry {
		return testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, testListTcp, port)
	}
	want := []struct {
		entry  *protocol.ListenersEntry
		desc   string
		source protocol.ListenersDescriptionSource
	}{
		{entry: socket(22), desc: ListenersDescriptionOtherUser, source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_OTHER_USER},
		{entry: socket(445), desc: ListenersDescriptionSystem, source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_SYSTEM},
		{entry: socket(9000)},
		{entry: socket(9100), desc: strings.Repeat("p", 64), source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_PROGRAM},
		{entry: socket(9200), desc: "srv run this", source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_PROGRAM},
		{entry: socket(9300), desc: "the shop", source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_LABEL},
		{entry: testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP, testListTcp, 8080), desc: "node", source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET_PROGRAM},
		{entry: testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP, testListTcp, 8081), desc: "198.51.100.20:8081", source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET},
		{entry: testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD, testListTcp, 15432), desc: "db tunnel", source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_LABEL},
		{entry: testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD, testListTcp, 15433)},
		{entry: testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS, testListTcp, 443), desc: "node", source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET_PROGRAM},
		{entry: testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SSH, testListTcp, 22), desc: ListenersDescriptionSsh, source: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_FIXED},
	}
	for i, w := range want {
		if w.entry == nil || w.entry.GetDesc() != w.desc || w.entry.GetDescBy() != w.source {
			t.Errorf("%d: %v, want %q by %v", i, w.entry, w.desc, w.source)
		}
	}
	sock := testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCK, testListTcp, 0)
	if sock == nil || sock.GetName() != "board" || sock.GetTarget() != "192.0.2.5:3000" || sock.GetDesc() != "192.0.2.5:3000" {
		t.Errorf("sock %v", sock)
	}
	if forward := testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD, testListTcp, 15433); forward.GetBind() != "" ||
		forward.GetTo() != "sock:board" || forward.GetUntil() != testListNow.Add(time.Hour).UnixMilli() {
		t.Errorf("a loopback forward %v", forward)
	}
	if published := testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS, testListTcp, 443); published.GetName() != "shop" ||
		published.GetAudience() != protocol.AclAudience_ACL_AUDIENCE_LINK || published.GetTarget() != "127.0.0.1:3000" {
		t.Errorf("tls %v", published)
	}
	// the own view's loopback socket the map and the publish lead to
	if len(list.Own) != 1 || list.Own[0].GetPort() != 3000 {
		t.Errorf("own %v", list.Own)
	}
	if _, err := MarshalListenersFile(list.File, DefaultListenersSettings()); err != nil {
		t.Errorf("the file does not write: %v", err)
	}
	// §26.5's order: maps, forwards, tls, ssh and sock entries, then sockets by port
	kinds := []protocol.ListenersEntryKind{}
	for _, entry := range entries {
		if len(kinds) == 0 || kinds[len(kinds)-1] != entry.GetKind() {
			kinds = append(kinds, entry.GetKind())
		}
	}
	if !slices.Equal(kinds, []protocol.ListenersEntryKind{
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD,
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SSH,
		protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCK, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET,
	}) {
		t.Errorf("kinds in order %v", kinds)
	}
}

// The cap keeps maps and forwards first, then sockets by port, truncated set past it; a forward's own listener is not
// listed again as a socket.
func TestListenersListCapKeepsMapsAndForwards(t *testing.T) {
	settings := DefaultListenersSettings()
	settings.EntryMaxCount = 4
	sockets := []*ListenersSocket{testListSocket(testListTcp, "0.0.0.0", 15432, "ur")}
	for port := uint16(9000); port < 9005; port++ {
		sockets = append(sockets, testListSocket(testListTcp, "0.0.0.0", port, "worker"))
	}
	list := BuildListenersList(&ListenersInputs{
		SidecarId: testListSidecarId,
		Now:       testListNow,
		Dump:      &ListenersDump{Sockets: sockets},
		Maps: []*bridge.BridgeRuleMap{
			{Protocol: 6, Ports: []*bridge.BridgePortRange{{First: 8000, Last: 8001}}, Target: netip.MustParseAddr("192.0.2.20").AsSlice()},
		},
		Forwards: []*ListenersForward{{Protocol: testListTcp, Port: 15432, Binds: []netip.Addr{netip.IPv4Unspecified()}, To: "db1:5432"}},
	}, settings)
	entries := list.File.GetEntries()
	if !list.File.GetTruncated() || len(entries) != 4 {
		t.Fatalf("truncated %t, %d entries", list.File.GetTruncated(), len(entries))
	}
	ports := []uint32{}
	for _, entry := range entries {
		ports = append(ports, entry.GetPort())
	}
	if !slices.Equal(ports, []uint32{8000, 8001, 15432, 9000}) {
		t.Errorf("kept %v", ports)
	}
	if testListEntry(entries, protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, testListTcp, 15432) != nil {
		t.Error("a forward's listener listed again")
	}
}

// An expired map, an ICMP map, an every-port map and a map past the cap's ports list nothing more; a map's range maps by
// offset.
func TestListenersListMaps(t *testing.T) {
	list := BuildListenersList(&ListenersInputs{
		SidecarId: testListSidecarId,
		Now:       testListNow,
		Maps: []*bridge.BridgeRuleMap{
			{Protocol: 6, Ports: []*bridge.BridgePortRange{{First: 8000, Last: 8000}}, Target: netip.MustParseAddr("192.0.2.20").AsSlice(), Expires: testListNow.UnixMilli()},
			{Protocol: 1, Target: netip.MustParseAddr("192.0.2.20").AsSlice()},
			{Protocol: 6, Target: netip.MustParseAddr("192.0.2.21").AsSlice()},
			{Protocol: 17, Ports: []*bridge.BridgePortRange{{First: 5000, Last: 5002}}, Target: netip.MustParseAddr("192.0.2.22").AsSlice(), TargetPort: 6000},
		},
	}, DefaultListenersSettings())
	targets := []string{}
	for _, entry := range list.File.GetEntries() {
		targets = append(targets, entry.GetTarget())
	}
	if !slices.Equal(targets, []string{"192.0.2.22:6000", "192.0.2.22:6001", "192.0.2.22:6002"}) {
		t.Errorf("targets %v", targets)
	}
}

// Windows' `::` row is listed with v4_uncertain; beside a 0.0.0.0 row of its port, the certain one's entry stands.
func TestListenersListV4Uncertain(t *testing.T) {
	uncertain := testListSocket(testListTcp, "::", 3389, "svchost.exe")
	uncertain.V4Uncertain = true
	list := testListOf([]*ListenersSocket{uncertain}, nil, DefaultListenersSettings())
	entry := testListEntry(list.File.GetEntries(), protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, testListTcp, 3389)
	if entry == nil || entry.GetBind() != "::" || !entry.GetV4Uncertain() || !list.Listed.Holds(testListTcp, 3389) {
		t.Errorf("uncertain %v", entry)
	}
	certain := testListSocket(testListTcp, "0.0.0.0", 3389, "svchost.exe")
	list = testListOf([]*ListenersSocket{uncertain, certain}, nil, DefaultListenersSettings())
	if entries := list.File.GetEntries(); len(entries) != 1 || entries[0].GetBind() != "0.0.0.0" || entries[0].GetV4Uncertain() {
		t.Errorf("both rows %v", entries)
	}
}

// The listed set holds only socket and map entries neither shared nor hidden, one a port; it names what next drops,
// which goes to the hook at once, and whether next adds a port, which waits for the write.
func TestListenersListedSet(t *testing.T) {
	file := &protocol.ListenersFile{V: 1, Sidecar: testListSidecarId.Bytes(), Updated: testListNow.UnixMilli(), Entries: []*protocol.ListenersEntry{
		{Kind: protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP, Proto: testListTcp, Port: 8000, Target: "192.0.2.20:8000", Desc: "nas admin", DescBy: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_LABEL},
		{Kind: protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD, Proto: testListTcp, Port: 15432, To: "db1:5432"},
		{Kind: protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SSH, Proto: testListTcp, Port: 22},
		{Kind: protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, Proto: testListTcp, Port: 5432, Bind: "0.0.0.0", Shared: true},
		{Kind: protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, Proto: testListTcp, Port: 8000, Bind: "0.0.0.0", Shadowed: true, Desc: "python3", DescBy: protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_PROGRAM},
		{Kind: protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET, Proto: testListUdp, Port: 53, Bind: "0.0.0.0"},
	}}
	set := ListenersListedSetOf(file, map[ListenersListedPort]string{{Protocol: testListTcp, Port: 8000}: "_http._tcp"})
	if ports := set.Ports(); !slices.Equal(ports, []ListenersListedPort{{Protocol: testListTcp, Port: 8000}, {Protocol: testListUdp, Port: 53}}) {
		t.Errorf("ports %v", ports)
	}
	if set.Entries[0].Description != "nas admin" || set.Entries[0].ServiceType != "_http._tcp" {
		t.Errorf("the map's entry %+v", *set.Entries[0])
	}
	next := ListenersListedSetOf(&protocol.ListenersFile{Entries: file.GetEntries()[:1]}, nil)
	if removed := set.Removed(next); !slices.Equal(removed, []ListenersListedPort{{Protocol: testListUdp, Port: 53}}) {
		t.Errorf("removed %v", removed)
	}
	if next.Adds(set) != true || set.Adds(next) {
		t.Error("adds")
	}
	withheld := ListenersListedSetOf(&protocol.ListenersFile{Withheld: protocol.ListenersWithheld_LISTENERS_WITHHELD_DISCLOSURE, Entries: file.GetEntries()}, nil)
	if len(withheld.Entries) != 0 {
		t.Errorf("a withheld file listed %v", withheld.Ports())
	}
}

// The list is a function of its inputs: two builds of one input read alike, whatever the dump's order.
func TestListenersListIsDeterministic(t *testing.T) {
	sockets := []*ListenersSocket{
		testListSocket(testListTcp, "0.0.0.0", 5432, "postgres"), testListSocket(testListTcp, "::", 8000, "node"),
		testListSocket(testListUdp, "0.0.0.0", 53, "dnsmasq"), testListSocket(testListTcp, "127.0.0.1", 9222, "chrome"),
	}
	first, err := MarshalListenersFile(testListOf(sockets, nil, DefaultListenersSettings()).File, DefaultListenersSettings())
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(sockets)
	second, _ := MarshalListenersFile(testListOf(sockets, nil, DefaultListenersSettings()).File, DefaultListenersSettings())
	if string(first) != string(second) {
		t.Errorf("%s\n%s", first, second)
	}
}

// The components' read-only accessors and their converters: a socket component's live listens by namespace then name,
// application names alone becoming sock entries, each with the target a listen forward of that name splices to; a tls
// component's live publishes by host then port, one on its way left out, each a tls entry with its audience's value.
func TestListenersComponentAccessors(t *testing.T) {
	sockets := &SocketComponent{listeners: map[*SocketListener]bool{
		{namespace: SocketNamespaceApplication, name: "board"}:      true,
		{namespace: SocketNamespaceTls, name: "tls/443/shop"}:       true,
		{namespace: SocketNamespaceApplication, name: "api"}:        true,
		{namespace: SocketNamespaceShare, name: "share/token-test"}: true,
	}}
	listens := sockets.Listens()
	if len(listens) != 4 || listens[0].Name != "api" || listens[1].Name != "board" || listens[2].Namespace != SocketNamespaceTls {
		t.Fatalf("listens %v", listens)
	}
	socks := ListenersSocksOf(listens, map[string]netip.AddrPort{"board": netip.MustParseAddrPort("127.0.0.1:8080")})
	if len(socks) != 2 || socks[0].Name != "api" || socks[0].Target.IsValid() || socks[1].Target != netip.MustParseAddrPort("127.0.0.1:8080") {
		t.Errorf("socks %+v %+v", *socks[0], *socks[1])
	}

	expires := testListNow.Add(time.Hour)
	publisher := &tlsPublisher{publishes: map[string]*tlsPublish{
		"tls/443/shop": {result: &TlsPublishResult{Audience: TlsPublishAudienceMembersDevice, Expires: expires}, host: "shop", port: 443,
			localAddress: netip.MustParseAddrPort("127.0.0.1:3000")},
		"tls/8443/@":   {result: &TlsPublishResult{Audience: "public"}, host: "@", port: 8443, localAddress: netip.MustParseAddrPort("127.0.0.1:9000")},
		"tls/443/next": nil,
	}}
	listings := (&TlsComponent{publisher: publisher}).Publishes()
	if len(listings) != 2 || listings[0].Host != "@" || listings[1].Host != "shop" || listings[1].Port != 443 {
		t.Fatalf("listings %v", listings)
	}
	publishes := ListenersPublishesOf(listings)
	if len(publishes) != 2 || publishes[1].Audience != protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE || !publishes[1].Until.Equal(expires) ||
		publishes[0].Audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC || publishes[0].Target != netip.MustParseAddrPort("127.0.0.1:9000") {
		t.Errorf("publishes %+v %+v", *publishes[0], *publishes[1])
	}
	if listings := (&TlsComponent{}).Publishes(); len(listings) != 0 {
		t.Errorf("no publisher listed %v", listings)
	}
}
