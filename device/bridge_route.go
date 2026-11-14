// §17.5's router, the sender's half (R-BRIDGE-1, D-BRIDGE-2): Route sits before connect's mux, so every send path
// passes it, and decides per packet with one atomic load of what the bridge publishes, BridgeTable.Classify, and where
// an entry offers a choice one pin probe, two for TCP while it holds 5-tuple pins. It returns a link's client, the
// reject client, the resolver, a refusal while a link builds, or nil for the default route, with no lock and no
// allocation (R-BRIDGE-9):
//
//	carved      a local /32 the physical path needs (SetLocalAddresses) takes the default route, whatever covers it
//	link        TCP to port 25 rejects, since a link's window would dial it on this device's physical network
//	            (plan-BRIDGE-small-readings #3); else the pins pick a link: its client takes the packet, or while it
//	            builds the packet is refused and stays the caller's; an entry no link can carry rejects, and never falls
//	            back to a broader prefix or the default route (§17.7's HA)
//	unassigned  rejects: an address of the block nobody holds is unreachable
//	service     UDP and TCP to <block>.0.53 port 53 go to the resolver (§12.9); the rest of <block>.0.0/24 rejects
//	revoked     an entry left with no advertiser rejects for RejectEntryHoldTimeout, then leaves the table (§17.8's
//	            revocation row): a link the rules dropped with no drain was revoked, so its pins drop at once
//	default     no entry: today's route under the egress spec's auto, or with none set; under exits, the pins pick one
//	            of the approved exits; under none, a reject (§17.9's egress spec)
//
// RouteBurst splits a burst by route in place, keeping flow order. What Route reads is rebuilt off the packet path from
// the state the bridge adopts, the overlay narrowing it, the links Retain names and this device's local addresses, and
// swapped whole by pointer. Each entry's pins live in a BridgeEntryState carried from build to build while its prefix
// stays in the table, so pins, windows and health survive a new state.

package device

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What one split of a burst holds: RouteBurst's stack array.
const bridgeRouteBurstCount = 64

// The resolver's host in a block: <block>.0.53 (§17.4).
const bridgeResolverHost = 53

// The port of SMTP, which no link carries.
const bridgeSmtpPort = 25

// What Route reads. Immutable once stored.
type bridgeRouteState struct {
	table *BridgeTable
	// by BridgeEntry.RuleIndex
	entries []bridgeRouteEntry
	// the carved addresses, sorted, which the default route's rows read; the table already gives them the default route
	carves []uint32
	// each block's <block>.0.53
	resolverAddrs []uint32
	egressMode    bridge.BridgeEgressMode
	// the exits' pins under exits, nil under any other mode
	egress *BridgeEntryState
	// what the export holds (bridge_export.go)
	routes []netip.Prefix
}

// One entry of the table, as Route takes it.
type bridgeRouteEntry struct {
	kind bridge.BridgeRuleEntryKind
	// a link entry's advertisers; nil for one with none left, which rejects
	state *BridgeEntryState
}

// What a build of the route state found, for the status.
type bridgeRouteFindings struct {
	// subnet routes dropped for overlapping a local network (§17.7)
	conflictCount int
	// local /32s carved that are hosts' overlay addresses (D-BRIDGE-16)
	carvedAddressCount int
	// entries held as rejects after losing their last advertiser
	heldCount int
}

// A client that refuses every packet, leaving it its caller's: what Route hands a packet for a link still building.
type bridgeRefusalClient struct{}

var _ connect.UserNatClient = bridgeRefusalClient{}

func (self bridgeRefusalClient) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	return false
}

func (self bridgeRefusalClient) Close() {}

func (self bridgeRefusalClient) Shuffle() {}

func (self bridgeRefusalClient) SecurityPolicyStats(reset bool) connect.SecurityPolicyStats {
	return connect.SecurityPolicyStats{}
}

func (self bridgeRefusalClient) SetLocalSecurityBypass(localSecurityBypass bool) {}

// §18.6's deviceBridge.Route: what carries packet, by the file's rows; nil is the default route. Lock- and
// allocation-free.
func (self *Bridge) Route(packet []byte) connect.UserNatClient {
	state := self.routeState.Load()
	if state == nil {
		return nil
	}
	entry := state.table.Classify(packet)
	if entry == nil {
		return self.routeDefault(state, packet)
	}
	routeEntry := &state.entries[entry.RuleIndex]
	switch routeEntry.kind {
	case bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK:
		if bridgeRouteSmtp(packet) {
			return self.reject
		}
		return self.routeLink(routeEntry.state, packet)
	case bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE:
		if state.resolves(packet) {
			return self.resolver
		}
		return self.reject
	default:
		return self.reject
	}
}

// A link entry's packet: the link the pins pick, a refusal while it builds, or a reject when none can carry it.
func (self *Bridge) routeLink(entryState *BridgeEntryState, packet []byte) connect.UserNatClient {
	if entryState == nil {
		return self.reject
	}
	linkId := self.pins.Pick(entryState, packet)
	if linkId == 0 {
		return self.reject
	}
	client, route := self.links.route(linkId, self.clock.Now())
	switch route {
	case bridgeLinkRouteClient:
		return client
	case bridgeLinkRouteWait:
		return bridgeRefusalClient{}
	default:
		return self.reject
	}
}

// A packet no entry holds, by the egress spec: today's route, an exit, or a reject. A carved address keeps the default
// route under every mode, since the physical path needs it.
func (self *Bridge) routeDefault(state *bridgeRouteState, packet []byte) connect.UserNatClient {
	switch state.egressMode {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS:
		if state.carved(packet) {
			return nil
		}
		if bridgeRouteSmtp(packet) {
			return self.reject
		}
		return self.routeLink(state.egress, packet)
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		if state.carved(packet) {
			return nil
		}
		return self.reject
	default:
		return nil
	}
}

// Whether packet is IPv4 to a carved address.
func (self *bridgeRouteState) carved(packet []byte) bool {
	if len(packet) < bridgeIpv4HeaderByteCount || packet[0]>>4 != 4 {
		return false
	}
	destination := binary.BigEndian.Uint32(packet[bridgeIpv4DestinationOffset : bridgeIpv4DestinationOffset+4])
	_, found := slices.BinarySearch(self.carves, destination)
	return found
}

// Whether packet is a DNS query for the resolver: UDP or TCP to a block's <block>.0.53, port 53, in a first or whole
// fragment.
func (self *bridgeRouteState) resolves(packet []byte) bool {
	if len(packet) < bridgeIpv4HeaderByteCount || packet[0]>>4 != 4 {
		return false
	}
	destination := binary.BigEndian.Uint32(packet[bridgeIpv4DestinationOffset : bridgeIpv4DestinationOffset+4])
	if !slices.Contains(self.resolverAddrs, destination) {
		return false
	}
	protocol := packet[9]
	if protocol != bridgeProtocolUdp && protocol != bridgeProtocolTcp {
		return false
	}
	port, ok := bridgeRouteDestinationPort(packet)
	return ok && port == bridgeResolverHost
}

// The destination port of an IPv4 TCP or UDP packet's first or whole fragment; false for anything else.
func bridgeRouteDestinationPort(packet []byte) (uint16, bool) {
	headerByteCount := int(packet[0]&0x0F) * 4
	if headerByteCount < bridgeIpv4HeaderByteCount || len(packet) < headerByteCount+4 {
		return 0, false
	}
	if binary.BigEndian.Uint16(packet[6:8])&0x1FFF != 0 {
		return 0, false
	}
	return binary.BigEndian.Uint16(packet[headerByteCount+2 : headerByteCount+4]), true
}

// Whether packet is IPv4 TCP to port 25.
func bridgeRouteSmtp(packet []byte) bool {
	if len(packet) < bridgeIpv4HeaderByteCount || packet[0]>>4 != 4 || packet[9] != bridgeProtocolTcp {
		return false
	}
	port, ok := bridgeRouteDestinationPort(packet)
	return ok && port == bridgeSmtpPort
}

// Routes a burst as Route routes each packet, and calls send once for each run of packets one route takes, with the
// route, nil for the default: in place, bridgeRouteBurstCount packets at a time on a stack array, each split grouping
// its packets by route in the order the routes first appear and keeping each route's packets in their order, so a
// flow keeps its order. A burst whose packets all take one route goes to send unchanged, as the same slice, and
// allocates nothing. Borrows the burst: it reorders the slice, and hands every packet to exactly one send, which owns
// it as the call send makes says (SendPacketBatch and SendNativePacketBatch take every packet).
func (self *Bridge) RouteBurst(packets [][]byte, send func(client connect.UserNatClient, packets [][]byte)) {
	var routes [bridgeRouteBurstCount]connect.UserNatClient
	runOpen := false
	runStart := 0
	var runRoute connect.UserNatClient
	for chunkStart := 0; chunkStart < len(packets); chunkStart += bridgeRouteBurstCount {
		chunk := packets[chunkStart:min(chunkStart+bridgeRouteBurstCount, len(packets))]
		uniform := true
		for i, packet := range chunk {
			routes[i] = self.Route(packet)
			if routes[i] != routes[0] {
				uniform = false
			}
		}
		if uniform && runOpen && routes[0] == runRoute {
			continue
		}
		if runOpen {
			send(runRoute, packets[runStart:chunkStart])
			runOpen = false
		}
		if uniform {
			runOpen = true
			runStart = chunkStart
			runRoute = routes[0]
			continue
		}
		bridgeRouteSplit(chunk, routes[:len(chunk)], send)
	}
	if runOpen {
		send(runRoute, packets[runStart:])
	}
}

// Groups chunk in place by routes, which runs beside it, keeping first appearances' order and each group's packets in
// their order, and sends each group.
func bridgeRouteSplit(chunk [][]byte, routes []connect.UserNatClient, send func(client connect.UserNatClient, packets [][]byte)) {
	var grouped [bridgeRouteBurstCount][]byte
	var order [bridgeRouteBurstCount]connect.UserNatClient
	var starts [bridgeRouteBurstCount + 1]int
	orderCount := 0
	for _, route := range routes {
		if !slices.Contains(order[:orderCount], route) {
			order[orderCount] = route
			orderCount += 1
		}
	}
	at := 0
	for group := range orderCount {
		starts[group] = at
		for i, route := range routes {
			if route == order[group] {
				grouped[at] = chunk[i]
				at += 1
			}
		}
	}
	starts[orderCount] = at
	copy(chunk, grouped[:len(chunk)])
	clear(grouped[:len(chunk)])
	for group := range orderCount {
		send(order[group], chunk[starts[group]:starts[group+1]])
	}
}

// Marks link down in every entry holding it, the exits included (§17.5's health row): the link manager's down callback.
func (self *Bridge) markLinkDown(link BridgeLinkId) {
	state := self.routeState.Load()
	if state == nil {
		return
	}
	for i := range state.entries {
		if entryState := state.entries[i].state; entryState != nil {
			entryState.MarkDown(link)
		}
	}
	if state.egress != nil {
		state.egress.MarkDown(link)
	}
}

// The target a rule's link reaches.
func bridgeRouteLinkTarget(link *bridge.BridgeRuleLink) BridgeLinkTarget {
	target := BridgeLinkTarget{
		ClientId:  connect.Id(link.GetTargetClientId()),
		SidecarId: connect.Id(link.GetTargetSidecarId()),
	}
	copy(target.IdentityPublicKey[:], link.GetTargetIdentityPublicKey())
	// an app host's pinned device client key; checkBridgeRuleLink holds it to 32 bytes or none
	copy(target.HostClientPublicKey[:], link.GetTargetClientPublicKey())
	return target
}

// Builds what Route reads, by the file's rows, from rules (nil for none: every packet takes the default route), the
// overlay narrowing them, the links Retain names for their targets and this device's local addresses, at now. Carries
// each link entry's BridgeEntryState over by prefix, resetting the pins of every link it no longer holds. Returns the
// state, what it found and the next time a held entry leaves, zero for none. Under the bridge's operationLock, off the
// packet path; Retain is the only call it makes out.
func (self *Bridge) buildRouteWithLock(rules *bridge.BridgeRules, overlayEntries []PostureOverlayEntry, now time.Time) (*bridgeRouteState, bridgeRouteFindings, time.Time) {
	findings := bridgeRouteFindings{}
	if rules == nil {
		self.links.Retain(nil)
		for prefix, entryState := range self.entryStates {
			self.resetRemovedPins(entryState, entryState.snapshot.Load(), nil)
			delete(self.entryStates, prefix)
		}
		clear(self.heldRejects)
		clear(self.overlayDrainSince)
		self.egressState = nil
		return nil, findings, time.Time{}
	}
	overlay := newBridgePolicyOverlay(overlayEntries)
	for ruleId := range self.overlayDrainSince {
		if !overlay.drainedRuleIds[ruleId] {
			delete(self.overlayDrainSince, ruleId)
		}
	}
	for ruleId := range overlay.drainedRuleIds {
		if _, held := self.overlayDrainSince[ruleId]; !held {
			self.overlayDrainSince[ruleId] = now
		}
	}
	revoked := func(link *bridge.BridgeRuleLink) bool {
		return overlay.narrows(link.GetTargetSidecarId(), link.GetTargetMemberId()) ||
			overlay.resetRuleIds[string(link.GetRuleId())]
	}
	blocks := []netip.Prefix{}
	for _, prefix := range []*bridge.BridgeIpv4Prefix{rules.GetBlock(), rules.GetPreviousBlock()} {
		if block, ok := bridgeRulePrefix(prefix); ok {
			blocks = append(blocks, block)
		}
	}
	inBlock := func(prefix netip.Prefix) bool {
		return slices.ContainsFunc(blocks, func(block netip.Prefix) bool { return bridgePrefixCovers(block, prefix) })
	}

	// every target an entry or the egress reaches, revoked ones left out, so their links leave
	targets := []BridgeLinkTarget{}
	ruleLinkSets := [][]*bridge.BridgeRuleLink{}
	for _, entry := range rules.GetEntries() {
		ruleLinkSets = append(ruleLinkSets, entry.GetLinks())
	}
	egressMode := rules.GetEgress().GetMode()
	if egressMode == bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS {
		ruleLinkSets = append(ruleLinkSets, rules.GetEgress().GetExits())
	}
	for _, ruleLinks := range ruleLinkSets {
		for _, link := range ruleLinks {
			if !revoked(link) {
				targets = append(targets, bridgeRouteLinkTarget(link))
			}
		}
	}
	uses := self.links.Retain(targets)
	entryLinks := func(ruleLinks []*bridge.BridgeRuleLink) []BridgeEntryLink {
		links := []BridgeEntryLink{}
		for _, link := range ruleLinks {
			if revoked(link) {
				continue
			}
			drainingSince := bridgePolicyTime(link.GetDrainingSince())
			drainUntil := bridgePolicyTime(link.GetDrainUntil())
			if since, drained := self.overlayDrainSince[string(link.GetRuleId())]; drained && drainingSince.IsZero() {
				drainingSince = since
				drainUntil = since
			}
			for _, use := range uses[bridgeRouteLinkTarget(link)] {
				entryLink := BridgeEntryLink{Link: use.Link, Weight: link.GetWeight()}
				switch {
				case !drainingSince.IsZero():
					entryLink.DrainingSince = drainingSince
					entryLink.DrainUntil = drainUntil
				case !use.DrainingSince.IsZero():
					entryLink.DrainingSince = use.DrainingSince
					entryLink.DrainUntil = use.DrainUntil
				}
				links = append(links, entryLink)
			}
		}
		return links
	}

	var localNetworks []netip.Prefix
	if self.settings.LocalIpv4Networks != nil {
		localNetworks = self.settings.LocalIpv4Networks()
	} else {
		localNetworks = connect.LocalIpv4Networks()
	}
	state := &bridgeRouteState{egressMode: egressMode}
	tableEntries := []BridgeEntry{}
	entryStates := map[netip.Prefix]*BridgeEntryState{}
	held := map[netip.Prefix]bool{}
	var next time.Time
	add := func(prefix netip.Prefix, kind bridge.BridgeRuleEntryKind, entryState *BridgeEntryState) {
		tableEntries = append(tableEntries, BridgeEntry{Prefix: prefix, Kind: kind, RuleIndex: len(state.entries)})
		state.entries = append(state.entries, bridgeRouteEntry{kind: kind, state: entryState})
	}
	// an entry that lost its last advertiser rejects until its hold ends, then leaves
	hold := func(prefix netip.Prefix) {
		if held[prefix] {
			return
		}
		since, holding := self.heldRejects[prefix]
		if !holding {
			since = now
			self.heldRejects[prefix] = since
		}
		held[prefix] = true
		end := since.Add(self.settings.RejectEntryHoldTimeout)
		if now.Before(end) {
			add(prefix, bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK, nil)
			findings.heldCount += 1
			if next.IsZero() || end.Before(next) {
				next = end
			}
		}
	}
	rulePrefixes := map[netip.Prefix]bool{}
	linkPrefixes := []netip.Prefix{}
	for _, entry := range rules.GetEntries() {
		prefix, _ := bridgeRulePrefix(entry.GetPrefix())
		rulePrefixes[prefix] = true
		if entry.GetKind() != bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK {
			add(prefix, entry.GetKind(), nil)
			continue
		}
		// §17.7's sender conflicts: a subnet route over a local network yields to it, until a remap or block change
		if !inBlock(prefix) && slices.ContainsFunc(localNetworks, prefix.Overlaps) {
			findings.conflictCount += 1
			continue
		}
		links := entryLinks(entry.GetLinks())
		entryState := self.entryStates[prefix]
		if entryState == nil {
			entryState = NewBridgeEntryState(nil, self.settings)
		}
		previous := entryState.snapshot.Load()
		entryState.Set(links)
		self.resetRemovedPins(entryState, previous, links)
		entryStates[prefix] = entryState
		if len(links) == 0 {
			hold(prefix)
			continue
		}
		delete(self.heldRejects, prefix)
		add(prefix, entry.GetKind(), entryState)
		linkPrefixes = append(linkPrefixes, prefix)
	}
	// a link entry the rules dropped was revoked: its pins drop, and it rejects until its hold ends, unless the rules
	// give its prefix to an entry of another kind
	for prefix, entryState := range self.entryStates {
		if _, kept := entryStates[prefix]; kept {
			continue
		}
		self.resetRemovedPins(entryState, entryState.snapshot.Load(), nil)
		if !rulePrefixes[prefix] {
			hold(prefix)
		}
	}
	for prefix := range self.heldRejects {
		if !rulePrefixes[prefix] {
			hold(prefix)
		}
	}
	for prefix, since := range self.heldRejects {
		ended := !now.Before(since.Add(self.settings.RejectEntryHoldTimeout))
		// a hold of a prefix the rules still list stays, ended, so its entry does not hold again; another goes
		if !held[prefix] || (ended && !rulePrefixes[prefix]) {
			delete(self.heldRejects, prefix)
		}
	}
	self.entryStates = entryStates

	// carves: every local IPv4 address, which wins its prefix
	assigned := map[netip.Addr]bool{}
	for _, prefix := range linkPrefixes {
		if prefix.IsSingleIP() && inBlock(prefix) {
			assigned[prefix.Addr()] = true
		}
	}
	for _, addr := range self.localAddrs {
		addr = addr.Unmap()
		if !addr.Is4() {
			continue
		}
		tableEntries = append(tableEntries, BridgeEntry{
			Prefix:    netip.PrefixFrom(addr, 32),
			Kind:      bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_CARVED,
			RuleIndex: -1,
		})
		state.carves = append(state.carves, bridgeIpv4Value(addr))
		if assigned[addr] {
			findings.carvedAddressCount += 1
		}
	}
	slices.Sort(state.carves)
	state.carves = slices.Compact(state.carves)
	table, err := NewBridgeTable(tableEntries)
	if err != nil {
		// parsed rules and carves always build; were they not to, every packet takes the default route's place in
		// the table's absence, which is today's route, so refuse instead: an empty table under none
		table, _ = NewBridgeTable(nil)
		state.egressMode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE
	}
	state.table = table
	for _, block := range blocks {
		state.resolverAddrs = append(state.resolverAddrs, bridgeIpv4Value(block.Addr())|bridgeResolverHost)
	}
	if state.egressMode == bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS {
		if self.egressState == nil {
			self.egressState = NewBridgeEntryState(nil, self.settings)
		}
		links := entryLinks(rules.GetEgress().GetExits())
		previous := self.egressState.snapshot.Load()
		self.egressState.Set(links)
		self.resetRemovedPins(self.egressState, previous, links)
		state.egress = self.egressState
	} else if self.egressState != nil {
		self.resetRemovedPins(self.egressState, self.egressState.snapshot.Load(), nil)
		self.egressState = nil
	}
	state.routes = bridgeExportRoutes(blocks, linkPrefixes, self.localAddrs)
	return state, findings, next
}

// Drops at once the pins of every link previous held that links leaves out (§17.8's revocation row), once the entry
// holds links, so no pick finds a removed link while its pins go.
func (self *Bridge) resetRemovedPins(entryState *BridgeEntryState, previous *bridgeEntrySnapshot, links []BridgeEntryLink) {
	for _, held := range previous.links {
		if !slices.ContainsFunc(links, func(link BridgeEntryLink) bool { return link.Link == held.link }) {
			self.pins.Reset(entryState, held.link)
		}
	}
}

// An IPv4 address as the table's four bytes, most significant first.
func bridgeIpv4Value(addr netip.Addr) uint32 {
	octets := addr.As4()
	return binary.BigEndian.Uint32(octets[:])
}
