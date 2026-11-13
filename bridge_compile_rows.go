// The bridge compile's rows (DESIGN-DETAILS 12.2.4's steps 2 and 7): the reach pass over the rows' sidecars, and the
// BridgeRules it builds, every repeated field in 12.2.4's order:
//
//	addresses  S's live address in the block, and in the previous block while it drains
//	entries    each block's unassigned /16 and services /24; a /32 link entry for each sidecar S may dial that holds a
//	           live address; for each subnet route in force S may use, its prefix, or its exposed prefix in the block,
//	           its links the advertisers of that identical prefix (D-BRIDGE-8's replicas), a withdrawn one until its
//	           drain's end
//	maps       S's maps in force, their match read into the block by host bits; one onto a block address or a daemon
//	           listener, or one the device role would refuse, is void here and alarms map_refused
//	served     S's routes in force, an exposed prefix read into the block, a withdrawn one until its drain's end
//	subjects   each sidecar that reaches S, its member, tag, client ids and dial, route and exit rows, one a rule and
//	           port range, ports and prefixes from AclLocalPolicy; a port-limited rule whose ports the device does not
//	           hold, as an activated grant's (sealed_detail, QD-003), gives no row, the closed direction
//	egress     S's mode from the rows' BridgeRows, and under exits the exits of S's own spec, else of the first atom S
//	           holds that has one, each a link
//	untagged   autogroup:untagged's rows at S, what an sdk provider gives a sealed subject no row binds (QD-733)
//
// Route rows name what a flow is sent to: a served prefix's part a rule's CIDR covers, and for a remapped route the
// same part of its exposed prefix, so a CIDR that happens to cover the block reaches no remap it was not granted.
// On every leg, with no connect import.

package sidecar

import (
	"bytes"
	"cmp"
	"math"
	"net/netip"
	"slices"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What one other sidecar is to S at t.
type bridgeCompileReach struct {
	sidecarId Id
	row       *bridge.SidecarRow
	tagged    bool
	memberId  Id
	// in[X]: the rules by which X reaches S
	dial  []AclReachRule
	route []AclReachRule
	exit  []AclReachRule
	in    bool
	// out[X]: whether S may dial X
	out bool
	// via[X]: the rules by which S routes or exits through X
	viaRoute []AclReachRule
	viaExit  []AclReachRule
}

// One route of S's in force.
type bridgeCompileServed struct {
	rule          *BridgeLedgerRule
	drainingSince int64
	drainUntil    int64
	exit          bool
	prefixes      []bridgePrefix
	// the exposed prefix read into the current block, and whether there is one
	exposed    bridgePrefix
	hasExposed bool
}

// The member of an untagged row, zero for a tagged one.
func bridgeCompileMember(row *bridge.SidecarRow) Id {
	memberId, _ := configRowMember(row)
	return memberId
}

// Step 2: one pass over the rows' sidecars in sidecar_id order, each standing X other than S with no hard deny at t.
// With no document an untagged X reaches S with no rows, which rule 4 passes, and S, untagged, reaches every X.
func (self *bridgeCompiler) reachPass() {
	for _, sidecarId := range self.state.SidecarIds() {
		if sidecarId == self.self {
			continue
		}
		row, standing := self.state.standingSidecar(sidecarId, self.t)
		if !standing {
			continue
		}
		if sidecarState := self.acl.sidecarState(sidecarId); sidecarState == nil || sidecarState.hardDeny(self.t) != 0 {
			continue
		}
		subject := AclSidecarSubject(sidecarId)
		reach := &bridgeCompileReach{sidecarId: sidecarId, row: row, tagged: 0 < len(row.GetTagIds()), memberId: bridgeCompileMember(row)}
		reach.dial = self.acl.DialRules(subject, self.selfSubject, self.now)
		reach.route = self.acl.RouteRules(subject, self.selfSubject, self.now)
		reach.exit = self.acl.ExitRules(subject, self.selfSubject, self.now)
		reach.in = 0 < len(reach.dial)+len(reach.route)+len(reach.exit) || (!self.hasDocument && !reach.tagged)
		if !self.selfDenied {
			reach.out = 0 < len(self.acl.DialRules(self.selfSubject, subject, self.now)) || (!self.hasDocument && !self.selfTagged)
			reach.viaRoute = self.acl.RouteRules(self.selfSubject, subject, self.now)
			reach.viaExit = self.acl.ExitRules(self.selfSubject, subject, self.now)
		}
		self.reach = append(self.reach, reach)
	}
	other := AclClientSubject(Id{}, Id{}, nil, "")
	untagged := &bridge.BridgeRuleSubject{}
	untagged.Dial = self.reachRows(self.acl.DialRules(other, self.selfSubject, self.now), false)
	untagged.Route = self.reachRows(self.acl.RouteRules(other, self.selfSubject, self.now), true)
	untagged.Exit = self.reachRows(self.acl.ExitRules(other, self.selfSubject, self.now), false)
	if 0 < len(untagged.Dial)+len(untagged.Route)+len(untagged.Exit) {
		self.untagged = untagged
	}
}

// The reach of one sidecar, nil for one the pass left out.
func (self *bridgeCompiler) reachOf(sidecarId Id) *bridgeCompileReach {
	index, found := slices.BinarySearchFunc(self.reach, sidecarId, func(reach *bridgeCompileReach, target Id) int {
		return reach.sidecarId.Cmp(target)
	})
	if !found {
		return nil
	}
	return self.reach[index]
}

// S's routes in force, in rule id order: a subnet route's prefixes and its exposed prefix in the current block, or an
// exit's 0.0.0.0/0.
func (self *bridgeCompiler) servedRoutes() {
	if self.selfDenied {
		return
	}
	for _, rule := range self.ledger.Rules(bridge.SignedType_SIGNED_BRIDGE_ROUTE) {
		if rule.Owner != self.self {
			continue
		}
		inForce, since, until := self.ruleInForce(rule)
		if !inForce {
			continue
		}
		served := &bridgeCompileServed{rule: rule, drainingSince: since, drainUntil: until}
		switch rule.Route.GetKind() {
		case bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT:
			served.exit = true
		case bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET:
			for _, wirePrefix := range rule.Route.GetPrefixes() {
				if prefix, err := bridgePrefixOf(wirePrefix); err == nil {
					served.prefixes = append(served.prefixes, prefix)
				}
			}
			if exposed := rule.Route.GetExposedPrefix(); exposed != nil {
				if len(self.blocks) == 0 {
					// a remap reads into the block, and with none it reaches nothing
					continue
				}
				first, _, err := bridgeUpperRangeOf(exposed)
				if err != nil {
					continue
				}
				served.exposed = bridgePrefix{address: bridgeCompileInBlock(self.blocks[0], first), length: exposed.GetLength()}
				served.hasExposed = true
			}
		default:
			continue
		}
		self.served = append(self.served, served)
	}
}

// Step 7: the rules.
func (self *bridgeCompiler) build() *bridge.BridgeRules {
	rules := &bridge.BridgeRules{}
	if 0 < len(self.blocks) {
		rules.Block = bridgeCompileWire(self.blocks[0])
		if 1 < len(self.blocks) {
			rules.PreviousBlock = bridgeCompileWire(self.blocks[1])
			rules.PreviousBlockDrainUntil = self.block.GetDrainUntil()
		}
		rules.Addresses = self.addressesOf(self.self)
	}
	rules.Entries = self.entries()
	rules.Maps = self.maps()
	rules.Served = self.servedRows()
	rules.Subjects = self.subjects()
	rules.Egress = self.egress()
	rules.Untagged = self.untagged
	return rules
}

// A link to a target sidecar, from its current binding, verified under the identity key the config admits; nil, and a
// wait, for one with none. A live forwarding Delegation that names a host client links to that client (§17.9's target
// row; DESIGN-DETAILS 4.7), whose key check is BRIDGE-M8-04's.
func (self *bridgeCompiler) link(target Id) *bridge.BridgeRuleLink {
	identityKey := self.state.IdentityKey(target)
	row := self.state.SidecarRow(target)
	if len(identityKey) != 32 || row == nil {
		return nil
	}
	link := &bridge.BridgeRuleLink{
		TargetSidecarId:         target.Bytes(),
		TargetIdentityPublicKey: bytes.Clone(identityKey),
		Weight:                  1,
	}
	if memberId := bridgeCompileMember(row); memberId != (Id{}) {
		link.TargetMemberId = memberId.Bytes()
	}
	if forwarding := self.state.ForwardingDelegation(target); forwarding != nil && len(forwarding.GetHostClientId()) == len(Id{}) {
		link.TargetClientId = bytes.Clone(forwarding.GetHostClientId())
		return link
	}
	binding := self.bindings.Current(target)
	if binding == nil || !bytes.Equal(binding.IdentityPublicKey, identityKey) || binding.SidecarId != target {
		self.wait(BridgeCompileWait{Kind: BridgeCompileWaitBinding, SidecarId: target})
		return nil
	}
	link.TargetClientId = binding.ClientId.Bytes()
	return link
}

// One entry being built.
type bridgeCompileEntry struct {
	prefix bridgePrefix
	kind   bridge.BridgeRuleEntryKind
	links  []*bridge.BridgeRuleLink
}

// The sender's table: each block's own entries, a /32 for each sidecar S may dial, and each subnet route in force S may
// use, by prefix address then length, an entry's links by target then rule id. A route entry that would collide with
// the table's own, or that the device role would refuse inside a block, is left out and alarms block_conflict.
func (self *bridgeCompiler) entries() []*bridge.BridgeRuleEntry {
	entries := []*bridgeCompileEntry{}
	find := func(prefix bridgePrefix) *bridgeCompileEntry {
		for _, entry := range entries {
			if entry.prefix == prefix {
				return entry
			}
		}
		return nil
	}
	for _, block := range self.blocks {
		entries = append(entries,
			&bridgeCompileEntry{prefix: block, kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNASSIGNED},
			&bridgeCompileEntry{prefix: bridgePrefix{address: block.address, length: 24}, kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE},
		)
	}
	// overlay addresses
	for _, reach := range self.reach {
		if !reach.out {
			continue
		}
		addresses := self.addressesOf(reach.sidecarId)
		if len(addresses) == 0 {
			continue
		}
		link := self.link(reach.sidecarId)
		for _, address := range addresses {
			entry := &bridgeCompileEntry{prefix: bridgePrefix{address: address, length: 32}, kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK}
			if link != nil {
				entry.links = append(entry.links, link)
			}
			entries = append(entries, entry)
		}
	}
	// subnet routes S may use
	if !self.selfDenied {
		for _, rule := range self.ledger.Rules(bridge.SignedType_SIGNED_BRIDGE_ROUTE) {
			self.routeEntries(rule, find, func(entry *bridgeCompileEntry) { entries = append(entries, entry) })
		}
	}
	slices.SortFunc(entries, func(a *bridgeCompileEntry, b *bridgeCompileEntry) int {
		return cmp.Or(cmp.Compare(a.prefix.address, b.prefix.address), cmp.Compare(a.prefix.length, b.prefix.length))
	})
	wireEntries := make([]*bridge.BridgeRuleEntry, 0, len(entries))
	for _, entry := range entries {
		slices.SortFunc(entry.links, func(a *bridge.BridgeRuleLink, b *bridge.BridgeRuleLink) int {
			return cmp.Or(bytes.Compare(a.GetTargetSidecarId(), b.GetTargetSidecarId()), bytes.Compare(a.GetRuleId(), b.GetRuleId()))
		})
		wireEntries = append(wireEntries, &bridge.BridgeRuleEntry{Prefix: bridgeCompileWire(entry.prefix), Kind: entry.kind, Links: entry.links})
	}
	return wireEntries
}

// One route's entries, when it is a subnet route in force that S may use: a link on each of its prefixes, or on its
// exposed prefix in each block, added to the entry of that identical prefix.
func (self *bridgeCompiler) routeEntries(rule *BridgeLedgerRule, find func(prefix bridgePrefix) *bridgeCompileEntry, add func(entry *bridgeCompileEntry)) {
	if rule.Owner == self.self || rule.Route.GetKind() != bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET {
		return
	}
	inForce, since, until := self.ruleInForce(rule)
	if !inForce {
		return
	}
	reach := self.reachOf(rule.Owner)
	if reach == nil {
		return
	}
	prefixes := []bridgePrefix{}
	for _, wirePrefix := range rule.Route.GetPrefixes() {
		if prefix, err := bridgePrefixOf(wirePrefix); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	if !self.mayUseRoute(reach, prefixes) {
		return
	}
	targets := prefixes
	if exposed := rule.Route.GetExposedPrefix(); exposed != nil {
		first, _, err := bridgeUpperRangeOf(exposed)
		if err != nil {
			return
		}
		targets = nil
		for _, block := range self.blocks {
			targets = append(targets, bridgePrefix{address: bridgeCompileInBlock(block, first), length: exposed.GetLength()})
		}
	}
	link := self.link(rule.Owner)
	if link != nil {
		link.RuleId = bytes.Clone(rule.RuleId)
		link.Weight = max(1, rule.Route.GetWeight())
		link.SiteId = bytes.Clone(rule.Route.GetSiteId())
		link.DrainingSince, link.DrainUntil = since, until
	}
	for _, target := range targets {
		entry := find(target)
		switch {
		case entry != nil && entry.kind != bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK:
			self.alarm(SidecarBridgeAlarmBlockConflict, rule.FirstAt, rule.Owner, "a route's prefix is the block's own entry")
			continue
		case rule.Route.GetExposedPrefix() == nil && slices.ContainsFunc(self.blocks, func(block bridgePrefix) bool { return block.contains(target) }):
			// a subnet inside the overlay would take hosts' addresses from them; one around the block leaves the
			// block's own entries the more specific
			self.alarm(SidecarBridgeAlarmBlockConflict, rule.FirstAt, rule.Owner, "a route's prefix lies inside the network's block")
			continue
		case !self.linkEntryFits(target):
			self.alarm(SidecarBridgeAlarmBlockConflict, rule.FirstAt, rule.Owner, "a route's prefix covers the block's services")
			continue
		case entry == nil:
			entry = &bridgeCompileEntry{prefix: target, kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK}
			add(entry)
		}
		if link != nil && !slices.ContainsFunc(entry.links, func(held *bridge.BridgeRuleLink) bool {
			return bytes.Equal(held.GetTargetClientId(), link.GetTargetClientId())
		}) {
			entry.links = append(entry.links, link)
		}
	}
}

// Whether S may use a route of an advertiser: a rule of via[it] whose CIDRs meet one of its prefixes, or no document
// and S untagged.
func (self *bridgeCompiler) mayUseRoute(reach *bridgeCompileReach, prefixes []bridgePrefix) bool {
	if !self.hasDocument && !self.selfTagged {
		return true
	}
	for _, rule := range reach.viaRoute {
		local := self.aclLocal.Rule(rule.RuleId)
		if local == nil {
			continue
		}
		for _, cidr := range local.Cidrs {
			if overlap, ok := bridgeCompileCidr(cidr); ok && slices.ContainsFunc(prefixes, func(prefix bridgePrefix) bool {
				return overlap.contains(prefix) || prefix.contains(overlap)
			}) {
				return true
			}
		}
	}
	return false
}

// A CIDR of the policy as a prefix, false for one that is not IPv4.
func bridgeCompileCidr(cidr netip.Prefix) (bridgePrefix, bool) {
	if !cidr.Addr().Is4() || !cidr.IsValid() {
		return bridgePrefix{}, false
	}
	octets := cidr.Masked().Addr().As4()
	address := uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
	return bridgePrefix{address: address, length: uint32(cidr.Bits())}, true
}

// Whether a link entry at prefix is one the device role takes: inside a block, clear of its services and, as a /32,
// no .0 or .255.
func (self *bridgeCompiler) linkEntryFits(prefix bridgePrefix) bool {
	for _, block := range self.blocks {
		if !block.contains(prefix) {
			continue
		}
		services := bridgePrefix{address: block.address, length: 24}
		if services.contains(prefix) || prefix.contains(services) {
			return false
		}
		if lastOctet := prefix.address & 0xff; prefix.length == 32 && (lastOctet == 0 || lastOctet == 255) {
			return false
		}
	}
	return true
}

// S's maps in force at t, in rule id order, their match read into the current block.
func (self *bridgeCompiler) maps() []*bridge.BridgeRuleMap {
	maps := []*bridge.BridgeRuleMap{}
	if len(self.blocks) == 0 || self.selfDenied {
		return maps
	}
	for _, rule := range self.ledger.Rules(bridge.SignedType_SIGNED_BRIDGE_MAP) {
		if rule.Owner != self.self {
			continue
		}
		inForce, since, until := self.ruleInForce(rule)
		if !inForce || (rule.Expires != 0 && rule.Expires <= self.t) {
			continue
		}
		body := rule.Map
		match, err := bridgePrefixOf(body.GetMatchPrefix())
		if err != nil || match.length < bridgeBlockPrefixLength {
			continue
		}
		ruleMap := &bridge.BridgeRuleMap{
			MapId:         bytes.Clone(rule.RuleId),
			MatchPrefix:   bridgeCompileWire(bridgePrefix{address: bridgeCompileInBlock(self.blocks[0], match.address), length: match.length}),
			Protocol:      body.GetProtocol(),
			Target:        bytes.Clone(body.GetTarget()),
			TargetPort:    body.GetTargetPort(),
			Expires:       rule.Expires,
			DrainingSince: since,
			DrainUntil:    until,
		}
		for _, ports := range body.GetPorts() {
			ruleMap.Ports = append(ruleMap.Ports, &bridge.BridgePortRange{First: ports.GetFirst(), Last: ports.GetLast()})
		}
		if reason := self.mapRefusal(ruleMap); reason != "" {
			self.alarm(SidecarBridgeAlarmMapRefused, rule.FirstAt, self.self, reason)
			continue
		}
		maps = append(maps, ruleMap)
	}
	return maps
}

// Why a map is void here, empty for none: a target in a block, which is another host's overlay address or one a hop
// away (§17.6's rule 2); a target that is one of the daemon's listeners (D-BRIDGE-19); or a form the device role
// refuses, which would refuse the whole state.
func (self *bridgeCompiler) mapRefusal(ruleMap *bridge.BridgeRuleMap) string {
	target, ok := netip.AddrFromSlice(ruleMap.GetTarget())
	if !ok || !target.IsValid() || target.IsUnspecified() {
		return "a target that is no address"
	}
	target = target.Unmap()
	if target.Is4() {
		octets := target.As4()
		if self.inBlocks(uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])) {
			return "a target in the network's block"
		}
	}
	if ruleMap.GetTargetPort() != 0 && len(ruleMap.GetPorts()) != 1 {
		return "a target port with other than one port range"
	}
	firstPort, lastPort := uint32(1), uint32(math.MaxUint16)
	if ruleMap.GetTargetPort() != 0 {
		ports := ruleMap.GetPorts()[0]
		firstPort, lastPort = ruleMap.GetTargetPort(), ruleMap.GetTargetPort()+(ports.GetLast()-ports.GetFirst())
		if math.MaxUint16 < lastPort {
			return "a range that maps past 65535"
		}
	} else if 0 < len(ruleMap.GetPorts()) {
		firstPort, lastPort = math.MaxUint16, 0
		for _, ports := range ruleMap.GetPorts() {
			firstPort, lastPort = min(firstPort, ports.GetFirst()), max(lastPort, ports.GetLast())
		}
	}
	if ruleMap.GetProtocol() != 1 && bridgeCompileListenerHit(self.local.DaemonListeners, target, firstPort, lastPort) {
		return "a target that is one of the daemon's listeners"
	}
	return ""
}

// Whether a target address and port range reaches a daemon listener: a listener's port in the range on a loopback or
// unspecified target, or on the listener's own address. A listener that does not parse holds every port.
func bridgeCompileListenerHit(listeners []string, target netip.Addr, firstPort uint32, lastPort uint32) bool {
	for _, listener := range listeners {
		addrPort, err := netip.ParseAddrPort(listener)
		if err != nil {
			// a name, or no port: every port of a loopback or local target is the daemon's
			if target.IsLoopback() {
				return true
			}
			continue
		}
		port := uint32(addrPort.Port())
		if port < firstPort || lastPort < port {
			continue
		}
		listenerAddr := addrPort.Addr().Unmap()
		if target.IsLoopback() || listenerAddr == target {
			return true
		}
	}
	return false
}

// S's routes in force as served rows: each prefix of a subnet route, with its exposed prefix, or an exit's
// 0.0.0.0/0, by route id then prefix.
func (self *bridgeCompiler) servedRows() []*bridge.BridgeRuleServed {
	servedRows := []*bridge.BridgeRuleServed{}
	for _, served := range self.served {
		if served.exit {
			servedRows = append(servedRows, &bridge.BridgeRuleServed{
				RouteId: bytes.Clone(served.rule.RuleId), Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT,
				Prefix: &bridge.BridgeIpv4Prefix{}, DrainingSince: served.drainingSince, DrainUntil: served.drainUntil,
			})
			continue
		}
		for _, prefix := range served.prefixes {
			row := &bridge.BridgeRuleServed{
				RouteId: bytes.Clone(served.rule.RuleId), Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET,
				Prefix: bridgeCompileWire(prefix), DrainingSince: served.drainingSince, DrainUntil: served.drainUntil,
			}
			if served.hasExposed {
				row.ExposedPrefix = bridgeCompileWire(served.exposed)
			}
			servedRows = append(servedRows, row)
		}
	}
	slices.SortFunc(servedRows, func(a *bridge.BridgeRuleServed, b *bridge.BridgeRuleServed) int {
		return cmp.Or(bytes.Compare(a.GetRouteId(), b.GetRouteId()), cmp.Compare(a.GetPrefix().GetAddress(), b.GetPrefix().GetAddress()),
			cmp.Compare(a.GetPrefix().GetLength(), b.GetPrefix().GetLength()))
	})
	return servedRows
}

// The subjects: each sidecar that reaches S, in sidecar_id order, with its rows. A client id the bindings hand two
// subjects is left out of both and alarms principal_mismatch: a sealed subject resolves through these ids, so one id
// must name one sidecar (QD-009), and the device role refuses a state that binds a client twice.
func (self *bridgeCompiler) subjects() []*bridge.BridgeRuleSubject {
	subjects := []*bridge.BridgeRuleSubject{}
	if self.selfDenied {
		return subjects
	}
	clientIdCounts := map[Id]int{}
	for _, reach := range self.reach {
		if reach.in {
			for _, clientId := range self.bindings.ClientIds(reach.sidecarId) {
				clientIdCounts[clientId] += 1
			}
		}
	}
	for _, reach := range self.reach {
		if !reach.in {
			continue
		}
		subject := &bridge.BridgeRuleSubject{SidecarId: reach.sidecarId.Bytes(), Tagged: reach.tagged}
		if !reach.tagged && reach.memberId != (Id{}) {
			subject.MemberId = reach.memberId.Bytes()
		}
		clientIds := self.bindings.ClientIds(reach.sidecarId)
		if len(clientIds) == 0 {
			self.wait(BridgeCompileWait{Kind: BridgeCompileWaitBinding, SidecarId: reach.sidecarId})
		}
		for _, clientId := range clientIds {
			if 1 < clientIdCounts[clientId] {
				self.alarm(SidecarBridgeAlarmPrincipalMismatch, 0, reach.sidecarId, "a client id the bindings give two sidecars")
				continue
			}
			subject.ClientIds = append(subject.ClientIds, clientId.Bytes())
		}
		subject.Dial = self.reachRows(reach.dial, false)
		subject.Route = self.reachRows(reach.route, true)
		subject.Exit = self.reachRows(reach.exit, false)
		subjects = append(subjects, subject)
	}
	return subjects
}

// The rows of a list of reach rules, by grant id, prefix, protocol and first port: each rule's protocols and port
// ranges, and on route rows its CIDRs' parts of what S serves. A rule expired at t gives none.
func (self *bridgeCompiler) reachRows(rules []AclReachRule, routeRows bool) []*bridge.BridgeRuleReach {
	rows := []*bridge.BridgeRuleReach{}
	for _, rule := range rules {
		if rule.ExpiresMs != 0 && rule.ExpiresMs <= self.t {
			continue
		}
		local := self.aclLocal.Rule(rule.RuleId)
		ports, ok := bridgeCompilePortRows(rule, local)
		if !ok {
			continue
		}
		prefixes := []*bridge.BridgeIpv4Prefix{nil}
		if routeRows {
			prefixes = self.routeRowPrefixes(local)
		}
		for _, prefix := range prefixes {
			for _, port := range ports {
				row := &bridge.BridgeRuleReach{Prefix: prefix, Protocol: port.protocol, Expires: rule.ExpiresMs}
				if 0 < len(rule.GrantId) {
					row.GrantId = bytes.Clone(rule.GrantId)
				}
				if port.ranged {
					row.Ports = []*bridge.BridgePortRange{{First: port.first, Last: port.last}}
				}
				rows = append(rows, row)
			}
		}
	}
	slices.SortStableFunc(rows, bridgeCompileReachCompare)
	return rows
}

// 12.2.4's order of a subject's rows, then the rest of each row, so equal rows sort alike.
func bridgeCompileReachCompare(a *bridge.BridgeRuleReach, b *bridge.BridgeRuleReach) int {
	firstPort := func(row *bridge.BridgeRuleReach) (uint32, uint32) {
		if len(row.GetPorts()) == 0 {
			return 0, 0
		}
		return row.GetPorts()[0].GetFirst(), row.GetPorts()[0].GetLast()
	}
	aFirst, aLast := firstPort(a)
	bFirst, bLast := firstPort(b)
	return cmp.Or(
		bytes.Compare(a.GetGrantId(), b.GetGrantId()),
		cmp.Compare(a.GetPrefix().GetAddress(), b.GetPrefix().GetAddress()),
		cmp.Compare(a.GetPrefix().GetLength(), b.GetPrefix().GetLength()),
		cmp.Compare(a.GetProtocol(), b.GetProtocol()),
		cmp.Compare(aFirst, bFirst),
		cmp.Compare(aLast, bLast),
		cmp.Compare(a.GetExpires(), b.GetExpires()),
	)
}

// One protocol and port range of a rule.
type bridgeCompilePortRow struct {
	protocol uint32
	ranged   bool
	first    uint32
	last     uint32
}

// A rule's protocols and ports as rows take them: every protocol for one that limits no ports; for one that does, each
// of its local ranges, an any-protocol range split into TCP and UDP since ICMP has no port; and false, no row, for a
// port-limited rule whose ports the device does not hold.
func bridgeCompilePortRows(rule AclReachRule, local *AclLocalRule) ([]bridgeCompilePortRow, bool) {
	if !rule.PortsLimited {
		return []bridgeCompilePortRow{{protocol: 0}}, true
	}
	if local == nil {
		return nil, false
	}
	rows := []bridgeCompilePortRow{}
	for _, ports := range local.Ports {
		every := ports.First == 0 && ports.Last == math.MaxUint16
		first, last := max(1, ports.First), min(ports.Last, math.MaxUint16)
		switch ports.Protocol {
		case 0:
			if every {
				rows = append(rows, bridgeCompilePortRow{protocol: 0})
				continue
			}
			rows = append(rows,
				bridgeCompilePortRow{protocol: aclIpProtocolTcp, ranged: true, first: first, last: last},
				bridgeCompilePortRow{protocol: aclIpProtocolUdp, ranged: true, first: first, last: last})
		case aclIpProtocolTcp, aclIpProtocolUdp:
			rows = append(rows, bridgeCompilePortRow{protocol: ports.Protocol, ranged: !every, first: first, last: last})
		case aclIpProtocolIcmp:
			rows = append(rows, bridgeCompilePortRow{protocol: aclIpProtocolIcmp})
		}
	}
	return rows, 0 < len(rows)
}

// A route rule's prefixes on S's route rows: each part of a subnet prefix S serves that one of its CIDRs covers, and
// that part of a remapped route's exposed prefix, which is what a flow to it is sent to. None for a rule whose CIDRs the
// device does not hold.
func (self *bridgeCompiler) routeRowPrefixes(local *AclLocalRule) []*bridge.BridgeIpv4Prefix {
	prefixes := []*bridge.BridgeIpv4Prefix{}
	if local == nil {
		return prefixes
	}
	add := func(prefix bridgePrefix) {
		if !slices.ContainsFunc(prefixes, func(held *bridge.BridgeIpv4Prefix) bool {
			return held.GetAddress() == prefix.address && held.GetLength() == prefix.length
		}) {
			prefixes = append(prefixes, bridgeCompileWire(prefix))
		}
	}
	for _, cidr := range local.Cidrs {
		covered, ok := bridgeCompileCidr(cidr)
		if !ok {
			continue
		}
		for _, served := range self.served {
			for _, prefix := range served.prefixes {
				var part bridgePrefix
				switch {
				case covered.contains(prefix):
					part = prefix
				case prefix.contains(covered):
					part = covered
				default:
					continue
				}
				add(part)
				if served.hasExposed {
					add(bridgePrefix{address: served.exposed.address + (part.address - prefix.address), length: part.length})
				}
			}
		}
	}
	return prefixes
}

// S's default route (§17.9's egress spec): the rows' mode for S, and under exits the exits of the ledger's spec naming
// S, else of the first atom S holds that has one, in atom id order, each a link.
func (self *bridgeCompiler) egress() *bridge.BridgeRuleEgress {
	mode := self.acl.EgressMode(self.selfSubject)
	egress := &bridge.BridgeRuleEgress{Mode: mode}
	if mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS {
		if mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE {
			egress.Mode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO
		}
		return egress
	}
	spec := self.egressSpec()
	if spec == nil {
		return egress
	}
	exits := slices.Clone(spec.ExitSidecarIds)
	if len(spec.ExitTagId) == len(Id{}) {
		tagId := Id(spec.ExitTagId)
		for _, sidecarId := range self.state.SidecarIds() {
			if sidecar := self.state.Sidecar(sidecarId); sidecar != nil && slices.Contains(sidecar.TagIds, tagId) {
				exits = append(exits, sidecarId)
			}
		}
	}
	slices.SortFunc(exits, Id.Cmp)
	for _, exitId := range slices.Compact(exits) {
		if exitId == self.self {
			continue
		}
		if _, standing := self.state.standingSidecar(exitId, self.t); !standing {
			continue
		}
		link := self.link(exitId)
		if link == nil {
			continue
		}
		link.RuleId = self.exitRuleId(exitId)
		if !slices.ContainsFunc(egress.Exits, func(held *bridge.BridgeRuleLink) bool {
			return bytes.Equal(held.GetTargetClientId(), link.GetTargetClientId())
		}) {
			egress.Exits = append(egress.Exits, link)
		}
	}
	return egress
}

// The egress spec S's exits come from: its own, else the first in atom id order of an atom S holds.
func (self *bridgeCompiler) egressSpec() *BridgeLedgerEgress {
	specs := self.ledger.Egress()
	for _, spec := range specs {
		if spec.Subject == self.self {
			return spec
		}
	}
	sidecarState := self.acl.sidecarState(self.self)
	if sidecarState == nil {
		return nil
	}
	for _, spec := range specs {
		index, found := self.acl.atomIndexes[spec.Subject]
		if !found {
			continue
		}
		if _, holds := slices.BinarySearch(sidecarState.atoms, index); holds {
			return spec
		}
	}
	return nil
}

// The id of the lowest exit route in force an exit advertises, nil for none.
func (self *bridgeCompiler) exitRuleId(exitId Id) []byte {
	for _, rule := range self.ledger.Rules(bridge.SignedType_SIGNED_BRIDGE_ROUTE) {
		if rule.Owner != exitId || rule.Route.GetKind() != bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT {
			continue
		}
		if inForce, since, _ := self.ruleInForce(rule); inForce && since == 0 {
			return bytes.Clone(rule.RuleId)
		}
	}
	return nil
}
