//go:build !ios_extension && !sidecar_http

// A device's list (DESIGN-COMPUTE §26.4, §26.5; R-LSTN-1, R-LSTN-3, R-LSTN-8, D-LSTN-1, D-LSTN-2, D-BRIDGE-19;
// LSTN-M13-04): BuildListenersList, a pure function from a dump of the OS's tables and the host's own state to the file
// it publishes, its person's own view, and the listed set the hook admits by.
//
// §26.4's tables, row by row:
//
//	socket   a TCP listener, or a UDP server (§26.5: bound and unconnected, its port under the OS's ephemeral range and
//	         none of UdpResponderPorts, or a port its person labeled), on 0.0.0.0, or on :: taking IPv4 (Windows' `::`
//	         listed v4_uncertain, never read as taking it), is a `socket` entry, bind "0.0.0.0" or "::"; one port's
//	         sockets of both families are one entry, the certain one's
//	own view a socket on loopback alone ("this device only", "map it"), on one other address, a LAN's, a container
//	         bridge's or the tun's ("map it"), or on IPv6 alone; the daemon's own listeners, by rule 0's ports
//	         (BridgeState.daemon_listeners), "never over the overlay" whatever their bind (D-BRIDGE-19); and every
//	         entry its person hid. Own-view entries name their address, and reach only the person's own devices, by
//	         the live ask (§26.8)
//	shared   a socket on a port a second socket binds on a narrower address, loopback or one interface, IPv4's or
//	         IPv6's, is listed shared: the listeners rule admits no flow to it (§26.7)
//	map      each port of a BridgeMap of the host's (the compiled state's BridgeRules.maps, ICMP's and every-port maps
//	         aside), with its target and until; a map on a port shadows the socket there, whose entry says so
//	forward  each of the daemon's forwards, `→ <client>:<port>` or `→ sock:<name>`, its bind a wildcard where it binds
//	         every interface, with until; its own listener is not listed again as a socket
//	sock     each socket name the host listens on (`ur socket listen`), `sock:<net>:<name>`, with its local target
//	tls      each name the host publishes through the TLS edge (`ur bridge public-tls`), its port at the edge, its
//	         target, audience and until
//	ssh      an enclave's SSH server, port 22, "ssh (ur ssh-server)"
//
// Descriptions, the first found (§26.4): the person's label for the port; a socket's program's name, "another user's
// program" or "a system program"; a map's, tls's or sock's target's program where the target is on the host, else the
// target; a forward's is its `to`, written in no desc; ssh's own words. Each is cleaned (ListenersCleanDescription), so
// a writer lists only what its readers take; a socket whose owner is not named yet has none until a dump names it.
//
// Caps (§26.5): EntryMaxCount entries in the file, in §26.5's order, maps, forwards, tls, ssh and sock entries first,
// then sockets by port, truncated set past it; the own view keeps as many. An entry whose name, target or to is past
// FieldMaxByteCount, or holds what a name may not, is dropped, never written for a reader to refuse.
//
// The file carries no address of its host (§26.4): readers take its address and name from the config, and the gate
// (LSTN-M13-10) sets withheld, the time and the version's checks before it writes; a hidden device gives a withheld
// file here already.

package sidecar

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A forward the daemon runs: `ur bridge forward`'s to a client's port, or `ur socket dial --listen`'s to a socket name.
type ListenersForward struct {
	Protocol protocol.ListenersProtocol
	// its listener's port and the addresses it binds
	Port  uint16
	Binds []netip.Addr
	// where it carries each connection, as the config names it: "<client>:<port>" or "sock:<name>"
	To string
	// when its grant ends, zero for none
	Until time.Time
}

// A socket name the host listens on (`ur socket listen`, DESIGN §9.9).
type ListenersSock struct {
	// the name as `sock:<net>:<name>` shows it after its network's label
	Name string
	// the local target its connections splice to; invalid where the host's own process takes them
	Target netip.AddrPort
}

// A name the host publishes through the TLS edge (`ur bridge public-tls`, DESIGN §13.10).
type ListenersPublish struct {
	// its label, "@" for the network's own name
	Host string
	// its port at the edge
	Port uint16
	// the local address the edge's connections reach; invalid where the host's own process takes them
	Target   netip.AddrPort
	Audience protocol.AclAudience
	// when its grant ends, zero for a standing name
	Until time.Time
}

// What a device's list is built from (the file's comment).
type ListenersInputs struct {
	SidecarId Id
	// the list's time, which the file's updated and a map's end are read against
	Now time.Time
	// the last dump, nil where this device has no discoverer (§26.4's phones and the browser)
	Dump *ListenersDump
	// the compiled state's maps (BridgeRules.maps)
	Maps []*bridge.BridgeRuleMap
	// this host's own addresses, its interfaces' and its overlay's: a target there, or on loopback, is on the host
	LocalAddresses []netip.Addr
	Forwards       []*ListenersForward
	Socks          []*ListenersSock
	Publishes      []*ListenersPublish
	// rule 0's binds, BridgeState.daemon_listeners, host:port each
	DaemonListeners []string
	// whether this host runs an enclave's SSH server (§12.4)
	SshServer bool
	// the person's labels and hides; nil holds none
	Labels ListenersLabelSet
}

// A device's list: what it publishes, its person's own view and the hook's set.
type ListenersList struct {
	// the file to publish, V, Sidecar, Updated, Truncated and Entries set, withheld only for a hidden device: the gate
	// (LSTN-M13-10) withholds the rest
	File *protocol.ListenersFile
	// the own view, own_view set on each, addresses named
	Own []*protocol.ListenersEntry
	// the listed set File gives (ListenersListedSetOf), with its labels' Bonjour types
	Listed *ListenersListedSet
}

// §26.5's order: maps, forwards, tls, ssh and sock entries, then sockets.
var listenersKindOrder = map[protocol.ListenersEntryKind]int{
	protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP:     0,
	protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD: 1,
	protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS:     2,
	protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SSH:     3,
	protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCK:    4,
	protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET:  5,
}

// The ssh server's port (§12.4).
const listenersSshPort = 22

// Two entries in §26.5's order: kind, then port, protocol and name.
func listenersEntryCompare(a *protocol.ListenersEntry, b *protocol.ListenersEntry) int {
	if order := listenersKindOrder[a.GetKind()] - listenersKindOrder[b.GetKind()]; order != 0 {
		return order
	}
	if a.GetPort() != b.GetPort() {
		return int(a.GetPort()) - int(b.GetPort())
	}
	if a.GetProto() != b.GetProto() {
		return int(a.GetProto()) - int(b.GetProto())
	}
	if order := strings.Compare(a.GetName(), b.GetName()); order != 0 {
		return order
	}
	return strings.Compare(a.GetBind(), b.GetBind())
}

// The list (the file's comment). Pure: it reads only inputs and settings.
func BuildListenersList(inputs *ListenersInputs, settings *ListenersSettings) *ListenersList {
	labels := inputs.Labels
	if labels == nil {
		labels = listenersNoLabels{}
	}
	clean := func(text string) string {
		return ListenersCleanDescription(text, settings.DescriptionMaxCharCount)
	}
	labelOf := func(proto protocol.ListenersProtocol, port uint16) (string, string, bool) {
		label, ok := labels.Label(proto, port)
		if !ok {
			return "", "", false
		}
		text := clean(label.Text)
		return text, label.Type, text != ""
	}
	describe := func(entry *protocol.ListenersEntry, text string, source protocol.ListenersDescriptionSource) {
		if text = clean(text); text != "" {
			entry.Desc = text
			entry.DescBy = source
		}
	}
	// a label, where its port has one, takes the description first
	labeled := func(entry *protocol.ListenersEntry) bool {
		if entry.GetPort() == 0 {
			return false
		}
		if text, _, ok := labelOf(entry.GetProto(), uint16(entry.GetPort())); ok {
			entry.Desc = text
			entry.DescBy = protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_LABEL
			return true
		}
		return false
	}

	sockets := []*ListenersSocket{}
	firstEphemeral := settings.EphemeralFirstPort
	if inputs.Dump != nil {
		sockets = inputs.Dump.Sockets
		if inputs.Dump.EphemeralFirstPort != 0 {
			firstEphemeral = inputs.Dump.EphemeralFirstPort
		}
	}
	// a target's program, where the target is on the host: the socket that takes its port there
	isLocal := func(address netip.Addr) bool {
		address = address.Unmap()
		return address.IsLoopback() || slices.ContainsFunc(inputs.LocalAddresses, func(local netip.Addr) bool {
			return local.Unmap() == address
		})
	}
	programAt := func(proto protocol.ListenersProtocol, target netip.AddrPort) (string, protocol.ListenersDescriptionSource, bool) {
		if !target.IsValid() || !isLocal(target.Addr()) {
			return "", 0, false
		}
		for _, socket := range sockets {
			if socket.Protocol != proto || socket.Port != target.Port() {
				continue
			}
			bind := socket.Bind.Unmap()
			if !bind.IsUnspecified() && bind != target.Addr().Unmap() {
				continue
			}
			switch socket.Owner {
			case ListenersOwnerProgram:
				return socket.Program, protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET_PROGRAM, true
			case ListenersOwnerOtherUser:
				return ListenersDescriptionOtherUser, protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_OTHER_USER, true
			case ListenersOwnerSystem:
				return ListenersDescriptionSystem, protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_SYSTEM, true
			}
		}
		return "", 0, false
	}
	targetDescription := func(entry *protocol.ListenersEntry, proto protocol.ListenersProtocol, target netip.AddrPort) {
		if labeled(entry) || !target.IsValid() {
			return
		}
		if program, source, ok := programAt(proto, target); ok {
			describe(entry, program, source)
			return
		}
		describe(entry, target.String(), protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET)
	}

	network := []*protocol.ListenersEntry{}
	own := []*protocol.ListenersEntry{}
	types := map[ListenersListedPort]string{}
	// a network entry its person hid goes to the own view instead
	addNetwork := func(entry *protocol.ListenersEntry) {
		if listenersFileEntryCheck(0, entry, settings) != nil {
			// a field a reader would refuse: never written
			return
		}
		// a hide names a port at the host's overlay address, which a tls entry's edge port is not
		hidesPort := entry.GetPort() != 0 && entry.GetKind() != protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS &&
			labels.HidesPort(entry.GetProto(), uint16(entry.GetPort()))
		if labels.HidesDevice() || hidesPort {
			entry.OwnView = protocol.ListenersOwnView_LISTENERS_OWN_VIEW_HIDDEN
			own = append(own, entry)
			return
		}
		network = append(network, entry)
		if _, labelType, ok := labelOf(entry.GetProto(), uint16(entry.GetPort())); ok && labelType != "" {
			types[ListenersListedPort{Protocol: entry.GetProto(), Port: uint16(entry.GetPort())}] = labelType
		}
	}

	// maps: each port of each, ICMP's and every-port maps aside, until they end
	mapped := map[ListenersListedPort]bool{}
	for _, ruleMap := range inputs.Maps {
		proto, ok := listenersMapProtocol(ruleMap.GetProtocol())
		if !ok || len(ruleMap.GetPorts()) == 0 {
			continue
		}
		if expires := ruleMap.GetExpires(); expires != 0 && !inputs.Now.Before(time.UnixMilli(expires)) {
			continue
		}
		target, ok := netip.AddrFromSlice(ruleMap.GetTarget())
		if !ok {
			continue
		}
		target = target.Unmap()
		ranges := ruleMap.GetPorts()
		for _, portRange := range ranges {
			for port := portRange.GetFirst(); port <= portRange.GetLast() && port <= 65535 && port != 0; port++ {
				if settings.EntryMaxCount < len(mapped) {
					break
				}
				targetPort := port
				switch {
				case ruleMap.GetTargetPort() == 0:
				case len(ranges) == 1:
					targetPort = ruleMap.GetTargetPort() + (port - portRange.GetFirst())
				default:
					targetPort = ruleMap.GetTargetPort()
				}
				if 65535 < targetPort {
					continue
				}
				key := ListenersListedPort{Protocol: proto, Port: uint16(port)}
				if mapped[key] {
					continue
				}
				mapped[key] = true
				targetAddrPort := netip.AddrPortFrom(target, uint16(targetPort))
				entry := &protocol.ListenersEntry{
					Kind:   protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_MAP,
					Proto:  proto,
					Port:   port,
					Target: targetAddrPort.String(),
					Until:  ruleMap.GetExpires(),
				}
				targetDescription(entry, proto, targetAddrPort)
				addNetwork(entry)
			}
		}
	}

	// forwards, whose own listeners are not sockets of the list
	forwarded := map[ListenersListedPort]bool{}
	for _, forward := range inputs.Forwards {
		if forward == nil || forward.Port == 0 {
			continue
		}
		forwarded[ListenersListedPort{Protocol: forward.Protocol, Port: forward.Port}] = true
		entry := &protocol.ListenersEntry{
			Kind:  protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_FORWARD,
			Proto: forward.Protocol,
			Port:  uint32(forward.Port),
			To:    forward.To,
			Bind:  listenersForwardBind(forward.Binds),
		}
		if !forward.Until.IsZero() {
			entry.Until = forward.Until.UnixMilli()
		}
		labeled(entry)
		addNetwork(entry)
	}

	for _, publish := range inputs.Publishes {
		if publish == nil {
			continue
		}
		entry := &protocol.ListenersEntry{
			Kind:     protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_TLS,
			Proto:    protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP,
			Port:     uint32(publish.Port),
			Name:     publish.Host,
			Audience: publish.Audience,
		}
		if publish.Target.IsValid() {
			entry.Target = publish.Target.String()
		}
		if !publish.Until.IsZero() {
			entry.Until = publish.Until.UnixMilli()
		}
		// a tls entry's port is the edge's, not the host's: no label of the host's ports names it
		if program, source, ok := programAt(entry.GetProto(), publish.Target); ok {
			describe(entry, program, source)
		} else if publish.Target.IsValid() {
			describe(entry, publish.Target.String(), protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_TARGET)
		}
		addNetwork(entry)
	}

	if inputs.SshServer {
		entry := &protocol.ListenersEntry{
			Kind:  protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SSH,
			Proto: protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP,
			Port:  listenersSshPort,
		}
		if !labeled(entry) {
			describe(entry, ListenersDescriptionSsh, protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_FIXED)
		}
		addNetwork(entry)
	}

	for _, sock := range inputs.Socks {
		if sock == nil {
			continue
		}
		entry := &protocol.ListenersEntry{
			Kind:  protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCK,
			Proto: protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP,
			Name:  sock.Name,
		}
		if sock.Target.IsValid() {
			entry.Target = sock.Target.String()
		}
		targetDescription(entry, entry.GetProto(), sock.Target)
		addNetwork(entry)
	}

	// sockets: rule 0's ports first, then each bind's row of §26.4's table
	daemonPorts := listenersDaemonPorts(inputs.DaemonListeners)
	responders := map[uint16]bool{}
	for _, port := range settings.UdpResponderPorts {
		responders[port] = true
	}
	wide := map[ListenersListedPort][]*ListenersSocket{}
	narrower := map[ListenersListedPort]bool{}
	ownSocket := func(socket *ListenersSocket, reason protocol.ListenersOwnView) {
		entry := &protocol.ListenersEntry{
			Kind:    protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET,
			Proto:   socket.Protocol,
			Port:    uint32(socket.Port),
			Bind:    socket.Bind.String(),
			OwnView: reason,
		}
		if !labeled(entry) {
			listenersSocketDescription(entry, socket, describe)
		}
		own = append(own, entry)
	}
	for _, socket := range sockets {
		if socket == nil || socket.Port == 0 {
			continue
		}
		port := ListenersListedPort{Protocol: socket.Protocol, Port: socket.Port}
		if socket.Protocol == protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP {
			// §26.5's UDP rule: a server's port is under the ephemeral range and no responder's, or its person
			// labeled it (compute-plan-lstn-udp-high-ports)
			_, _, labeledPort := labelOf(socket.Protocol, socket.Port)
			if !labeledPort && (firstEphemeral <= socket.Port || responders[socket.Port]) {
				continue
			}
		}
		if forwarded[port] {
			continue
		}
		if daemonPorts[socket.Port] {
			ownSocket(socket, protocol.ListenersOwnView_LISTENERS_OWN_VIEW_DAEMON)
			continue
		}
		bind := socket.Bind.Unmap()
		switch {
		case bind.Is4() && bind.IsUnspecified():
			wide[port] = append(wide[port], socket)
		case bind.Is6() && bind.IsUnspecified() && (socket.V4Uncertain || !socket.V6Only):
			wide[port] = append(wide[port], socket)
		case bind.Is6() && bind.IsUnspecified():
			ownSocket(socket, protocol.ListenersOwnView_LISTENERS_OWN_VIEW_IPV6_ONLY)
		case bind.IsLoopback():
			narrower[port] = true
			ownSocket(socket, protocol.ListenersOwnView_LISTENERS_OWN_VIEW_LOOPBACK)
		case bind.Is4():
			narrower[port] = true
			ownSocket(socket, protocol.ListenersOwnView_LISTENERS_OWN_VIEW_ONE_ADDRESS)
		default:
			narrower[port] = true
			ownSocket(socket, protocol.ListenersOwnView_LISTENERS_OWN_VIEW_IPV6_ONLY)
		}
	}
	wideSockets := []*ListenersSocket{}
	for _, held := range wide {
		// one port's wide sockets are one entry: the one certain to take IPv4 first, then 0.0.0.0, then the rest
		slices.SortFunc(held, func(a *ListenersSocket, b *ListenersSocket) int {
			if a.V4Uncertain != b.V4Uncertain {
				if a.V4Uncertain {
					return 1
				}
				return -1
			}
			if a.Bind.Is4() != b.Bind.Is4() {
				if a.Bind.Is4() {
					return -1
				}
				return 1
			}
			return listenersSocketCompare(a, b)
		})
		wideSockets = append(wideSockets, held[0])
	}
	for _, socket := range wideSockets {
		port := ListenersListedPort{Protocol: socket.Protocol, Port: socket.Port}
		entry := &protocol.ListenersEntry{
			Kind:        protocol.ListenersEntryKind_LISTENERS_ENTRY_KIND_SOCKET,
			Proto:       socket.Protocol,
			Port:        uint32(socket.Port),
			Bind:        listenersBindAnyIpv4,
			Shared:      narrower[port],
			V4Uncertain: socket.V4Uncertain,
			Shadowed:    mapped[port],
		}
		if socket.Bind.Unmap().Is6() {
			entry.Bind = listenersBindAnyIpv6
		}
		if !labeled(entry) {
			listenersSocketDescription(entry, socket, describe)
		}
		addNetwork(entry)
	}

	slices.SortStableFunc(network, listenersEntryCompare)
	slices.SortStableFunc(own, listenersEntryCompare)
	file := &protocol.ListenersFile{
		V:       ListenersFileVersion,
		Sidecar: inputs.SidecarId.Bytes(),
		Updated: inputs.Now.UnixMilli(),
	}
	switch {
	case labels.HidesDevice():
		file.Withheld = protocol.ListenersWithheld_LISTENERS_WITHHELD_HIDDEN
	case settings.EntryMaxCount < len(network):
		file.Entries = network[:settings.EntryMaxCount]
		file.Truncated = true
	default:
		file.Entries = network
	}
	if settings.EntryMaxCount < len(own) {
		own = own[:settings.EntryMaxCount]
	}
	return &ListenersList{File: file, Own: own, Listed: ListenersListedSetOf(file, types)}
}

// The sock entries of a socket component's live listens (SocketComponent.Listens): application names alone, a tls/
// name being the tls kind's, an smtp/ name the daemon's own mail and a share/ name a file's; each with the local target
// the daemon's listen forward splices its connections to, by name, where one does.
func ListenersSocksOf(names []SocketListenName, targets map[string]netip.AddrPort) []*ListenersSock {
	socks := []*ListenersSock{}
	for _, name := range names {
		if name.Namespace != SocketNamespaceApplication {
			continue
		}
		socks = append(socks, &ListenersSock{Name: name.Name, Target: targets[name.Name]})
	}
	return socks
}

// The tls entries of a tls component's live publishes (TlsComponent.Publishes): an audience whose words the file does not
// know is no entry.
func ListenersPublishesOf(listings []*TlsPublishListing) []*ListenersPublish {
	publishes := []*ListenersPublish{}
	for _, listing := range listings {
		audience, ok := listenersWordValue(listenersAudienceWords, listing.Audience)
		if !ok || listing.Port <= 0 || 65535 < listing.Port {
			continue
		}
		publishes = append(publishes, &ListenersPublish{
			Host:     listing.Host,
			Port:     uint16(listing.Port),
			Target:   listing.LocalAddress,
			Audience: audience,
			Until:    listing.Expires,
		})
	}
	return publishes
}

// A socket entry's description from its owner (§26.4): its program's name, "another user's program" or "a system
// program"; none while its owner is not named.
func listenersSocketDescription(entry *protocol.ListenersEntry, socket *ListenersSocket, describe func(entry *protocol.ListenersEntry, text string, source protocol.ListenersDescriptionSource)) {
	switch socket.Owner {
	case ListenersOwnerProgram:
		describe(entry, socket.Program, protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_PROGRAM)
	case ListenersOwnerOtherUser:
		describe(entry, ListenersDescriptionOtherUser, protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_OTHER_USER)
	case ListenersOwnerSystem:
		describe(entry, ListenersDescriptionSystem, protocol.ListenersDescriptionSource_LISTENERS_DESCRIPTION_SOURCE_SYSTEM)
	}
}

// A map's protocol number as the list's.
func listenersMapProtocol(protocolNumber uint32) (protocol.ListenersProtocol, bool) {
	switch protocolNumber {
	case listenersIpprotoTcp:
		return protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP, true
	case listenersIpprotoUdp:
		return protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP, true
	}
	return 0, false
}

// A forward's bind as its entry names it: a wildcard where it binds every interface, else none.
func listenersForwardBind(binds []netip.Addr) string {
	for _, bind := range binds {
		if bind.Unmap().Is4() && bind.IsUnspecified() {
			return listenersBindAnyIpv4
		}
	}
	for _, bind := range binds {
		if bind.Is6() && bind.IsUnspecified() {
			return listenersBindAnyIpv6
		}
	}
	return ""
}

// The ports of rule 0's binds: every port a daemon listener holds, whatever its address, as rule 0 refuses it.
func listenersDaemonPorts(listeners []string) map[uint16]bool {
	ports := map[uint16]bool{}
	for _, listener := range listeners {
		_, portText, err := net.SplitHostPort(listener)
		if err != nil {
			continue
		}
		if port, err := strconv.ParseUint(portText, 10, 16); err == nil && port != 0 {
			ports[uint16(port)] = true
		}
	}
	return ports
}

// No labels and no hides.
type listenersNoLabels struct{}

// See ListenersLabelSet.
func (self listenersNoLabels) Label(proto protocol.ListenersProtocol, port uint16) (*ListenersLabel, bool) {
	return nil, false
}

// See ListenersLabelSet.
func (self listenersNoLabels) HidesPort(proto protocol.ListenersProtocol, port uint16) bool {
	return false
}

// See ListenersLabelSet.
func (self listenersNoLabels) HidesDevice() bool {
	return false
}
