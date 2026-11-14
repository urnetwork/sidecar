// What BridgeEgressPolicy publishes, and §17.6's numbered rules over it. newBridgePolicyState indexes a verified state
// once, off the packet path, applying the overlay's narrowing as it goes, so resolve reads only immutable slices and
// maps keyed by fixed-size values, with no lock and no allocation.
//
//	0  one of this device's daemon listeners: a listener's port on loopback, an unspecified address or any of this
//	   device's addresses, which is every address while they are unknown           -> Deny (D-BRIDGE-19, doc or not)
//	1  a map of the destination as sent, its protocol and port                     -> AllowDial ? Map(target) : Deny
//	   a served route's exposed prefix, which is hosted here (rule 6's remap)      -> (no document and untagged) or
//	                                                                                  AllowRoute ? Map(remap) : Deny
//	2  a block address not hosted here                                             -> Deny: one hop, never another host's
//	3  a hosted address                                                            -> (no document and untagged) or
//	                                                                                  AllowDial ? Map(127.0.0.1:port) : Deny
//	4  no document, an untagged subject                                            -> Pass (owner decisions 50, 105, 120)
//	5  loopback, link-local, multicast, unspecified                                -> Deny
//	6  a served prefix                                                             -> AllowRoute ? Pass : Deny
//	7  public unicast                                                              -> AllowExit ? Pass : Deny, and a host
//	                                                                                  only while it serves an exit
//	8                                                                              -> Deny: LAN with no route rule
//
// Rule 0 also holds every map's target and rule 3's 127.0.0.1:port, so a map never reaches the daemon, and a map never
// targets an address of a block. Maps and remaps rewrite ranges by offset, and port 0 keeps the port. A served route's
// exposed prefix is read as hosted here, so rule 2 does not refuse it and rule 4 cannot pass it unmapped; its route rows
// match the destination as sent, the exposed address, which the network names uniquely where real prefixes repeat
// across sites. The sdk provider runs rules 0, 4, 5, 7 and 8, with any address of a block denied in place of rules 1
// to 3.
//
// Times: a map or a row past its expiry admits nothing; a map draining (retargeted or withdrawn) keeps the flows it
// opened and admits no new one; a served route draining, and a hosted address or remap in the previous block, admits
// until its drain ends (§17.8's disposition). A withdraw between states resets at once, or under drain stops a map and
// leaves a route admitting, its drain timed by the next state, since a drain starts at a log time, never a device's.
//
// Tags (BridgeRuleTag): a map's flows carry (subject, map_id), a served route's or remap's (subject, route_id), rule
// 3's (subject, 3 and the hosted address the flow was sent to), and rules 4 and 7 (subject, 4) and (subject, 7). A flow
// whose principal a forwarding key admitted carries BridgeForwardRuleTag of the same pair, with that Delegation in it.
//
// Forwarding keys (owner decision 197; DESIGN-DETAILS 4.2.5): a principal a forwarding key admitted is rechecked per
// flow against the Delegation the state lists live for its subject, and is denied once the state lists another or
// none, and while the overlay holds a DelegationRevoke of it or a supersession of its sidecar by another Delegation. A
// principal the identity key admitted is untouched by any of the three.

package device

import (
	"crypto/sha256"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Ranges that are no public unicast beside those netip names: shared address space (RFC 6598, which C6a makes
// non-public), "this network" and the reserved 240/4.
var bridgeNonPublicIpv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// The address rule 3 maps a hosted address to.
var bridgeHostedTarget = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// A port range of a row.
type bridgePolicyPortRange struct {
	first uint16
	last  uint16
}

// One row of a subject's reach, its grant's revocation applied.
type bridgePolicyReach struct {
	grantId []byte
	// a route row's; invalid on dial and exit rows
	prefix   netip.Prefix
	protocol uint32
	ports    []bridgePolicyPortRange
	// zero for none
	expires time.Time
	// its grant is revoked between states
	revoked bool
}

// A subject, its standing applied.
type bridgePolicySubject struct {
	sidecarId connect.Id
	memberId  []byte
	tagged    bool
	// in the state's identities, with this key
	hasIdentity bool
	identityKey []byte
	// neither revoked nor suspended by the state or the overlay
	admitted bool
	// the forwarding Delegation the state lists live for it and its key, hasForward false for none
	hasForward          bool
	forwardDelegationId [sha256.Size]byte
	forwardKey          []byte
	// the overlay revokes that Delegation, or supersedes this sidecar's forwarding key by another
	forwardDenied bool
	dial          []bridgePolicyReach
	route         []bridgePolicyReach
	exit          []bridgePolicyReach
}

// A map, its withdrawal applied.
type bridgePolicyMap struct {
	mapId      []byte
	match      netip.Prefix
	protocol   uint32
	ports      []bridgePolicyPortRange
	target     netip.Addr
	targetPort uint16
	// zero for none
	expires time.Time
	// retargeted or withdrawn to drain: keeps the flows it opened and admits none
	draining bool
	// when its flows end, zero while the next state is to time it
	drainEnd time.Time
	// withdrawn with reset between states: admits nothing
	withdrawn bool
}

// A served route, its withdrawal applied.
type bridgePolicyServed struct {
	routeId []byte
	exit    bool
	prefix  netip.Prefix
	// invalid for no remap
	exposed netip.Prefix
	// zero while it is not draining; it admits until then
	drainEnd  time.Time
	withdrawn bool
}

// The published state. See the file's comment. Immutable once stored.
type bridgePolicyState struct {
	generation uint64
	posture    PostureState
	// enforcing, with rules that were refused or are none: every Network flow denies
	rulesRefused  bool
	networkId     connect.Id
	hostSidecarId connect.Id

	block                   netip.Prefix
	previousBlock           netip.Prefix
	previousBlockDrainUntil time.Time
	hostedAddrs             []netip.Addr
	maps                    []*bridgePolicyMap
	served                  []*bridgePolicyServed

	subjectBySidecarId map[connect.Id]*bridgePolicySubject
	subjectByClientId  map[connect.Id]*bridgePolicySubject
	// by the forwarding Delegation the state lists live for a subject (BridgeIdentity.forward_delegation_id)
	subjectByForwardDelegationId map[[sha256.Size]byte]*bridgePolicySubject
	// another client at an sdk provider: untagged, admitted, the zero id, holding BridgeRules.untagged's rows, none
	// when the rules carry no such field
	otherClient *bridgePolicySubject

	// rule 0
	daemonPorts []uint16
	// listeners' own non-wildcard addresses
	listenerAddrs []netip.Addr
	// a listener that did not parse: every port of a local address is the daemon's
	listenersUnknown bool
	localAddrsKnown  bool
	localAddrs       []netip.Addr
}

// What the overlay narrows, by id.
type bridgePolicyOverlay struct {
	revokedSidecarIds map[string]bool
	revokedMemberIds  map[string]bool
	suspendedIds      map[string]bool
	revokedGrantIds   map[string]bool
	resetRuleIds      map[string]bool
	drainedRuleIds    map[string]bool
	// forwarding Delegations a DelegationRevoke names
	revokedDelegationIds map[string]bool
	// by sidecar_id, the newer forwarding Delegations that supersede its older ones
	supersedingDelegationIds map[string][]string
}

// Indexes the overlay's entries.
func newBridgePolicyOverlay(entries []PostureOverlayEntry) *bridgePolicyOverlay {
	self := &bridgePolicyOverlay{
		revokedSidecarIds: map[string]bool{},
		revokedMemberIds:  map[string]bool{},
		suspendedIds:      map[string]bool{},
		revokedGrantIds:   map[string]bool{},
		resetRuleIds:      map[string]bool{},
		drainedRuleIds:    map[string]bool{},

		revokedDelegationIds:     map[string]bool{},
		supersedingDelegationIds: map[string][]string{},
	}
	for _, entry := range entries {
		id := string(entry.Id)
		switch entry.Kind {
		case PostureOverlaySidecarRevoke:
			self.revokedSidecarIds[id] = true
		case PostureOverlayMemberRevoke:
			self.revokedMemberIds[id] = true
		case PostureOverlaySuspend:
			self.suspendedIds[id] = true
		case PostureOverlayGrantRevoke:
			self.revokedGrantIds[id] = true
		case PostureOverlayBridgeWithdraw:
			if entry.WithdrawMode == bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN {
				self.drainedRuleIds[id] = true
			} else {
				// reset, and a mode this role does not know, which resets: the stricter
				self.resetRuleIds[id] = true
			}
		case PostureOverlayDelegationRevoke:
			self.revokedDelegationIds[id] = true
		case PostureOverlayForwardSupersede:
			self.supersedingDelegationIds[id] = append(self.supersedingDelegationIds[id], string(entry.DelegationId))
		}
	}
	return self
}

// Whether the overlay denies a sidecar's forwarding key under delegationId: a DelegationRevoke of it, or a
// supersession of the sidecar by any other Delegation. The newer Delegation's own key is not denied here; the state
// that judged it admits it.
func (self *bridgePolicyOverlay) deniesForward(sidecarId []byte, delegationId []byte) bool {
	if self.revokedDelegationIds[string(delegationId)] {
		return true
	}
	for _, supersedingId := range self.supersedingDelegationIds[string(sidecarId)] {
		if supersedingId != string(delegationId) {
			return true
		}
	}
	return false
}

// Whether the subject's forwarding key admits: the state lists a live forwarding Delegation for it, the overlay does
// not deny that Delegation, and the subject itself stands.
func (self *bridgePolicySubject) forwardAdmitted() bool {
	return self.admitted && self.hasIdentity && self.hasForward && !self.forwardDenied
}

// Whether the overlay revokes or suspends a sidecar of memberId.
func (self *bridgePolicyOverlay) narrows(sidecarId []byte, memberId []byte) bool {
	if self.revokedSidecarIds[string(sidecarId)] || self.suspendedIds[string(sidecarId)] {
		return true
	}
	return 0 < len(memberId) && (self.revokedMemberIds[string(memberId)] || self.suspendedIds[string(memberId)])
}

// Indexes input as generation (the file's comment). Rules that fail ParseBridgeRules's checks, or an enforcing state
// with none, deny every Network flow.
func newBridgePolicyState(input *BridgePolicyInput, generation uint64, settings *BridgeSettings) *bridgePolicyState {
	self := &bridgePolicyState{
		generation:         generation,
		posture:            input.State,
		subjectBySidecarId: map[connect.Id]*bridgePolicySubject{},
		subjectByClientId:  map[connect.Id]*bridgePolicySubject{},
		otherClient:        &bridgePolicySubject{admitted: true},

		subjectByForwardDelegationId: map[[sha256.Size]byte]*bridgePolicySubject{},
	}
	if len(input.NetworkId) == bridgeRuleIdByteCount {
		self.networkId = connect.Id(input.NetworkId)
	}
	if len(input.SidecarId) == bridgeRuleIdByteCount {
		self.hostSidecarId = connect.Id(input.SidecarId)
	}
	if input.LocalAddresses != nil {
		self.localAddrsKnown = true
		for _, addr := range input.LocalAddresses {
			self.localAddrs = append(self.localAddrs, addr.Unmap())
		}
	}
	if !input.State.Enforcing() {
		return self
	}
	rules := input.Rules
	if rules == nil || input.BridgeState == nil || checkBridgeRules(rules) != nil {
		self.rulesRefused = true
		return self
	}
	overlay := newBridgePolicyOverlay(input.Overlay)

	self.block, _ = bridgeRulePrefix(rules.GetBlock())
	self.previousBlock, _ = bridgeRulePrefix(rules.GetPreviousBlock())
	if self.previousBlock.IsValid() {
		self.previousBlockDrainUntil = time.UnixMilli(rules.GetPreviousBlockDrainUntil())
	}
	for _, address := range rules.GetAddresses() {
		self.hostedAddrs = append(self.hostedAddrs, bridgeRuleAddr(address))
	}
	for _, ruleMap := range rules.GetMaps() {
		match, _ := bridgeRulePrefix(ruleMap.GetMatchPrefix())
		target, _ := netip.AddrFromSlice(ruleMap.GetTarget())
		policyMap := &bridgePolicyMap{
			mapId:      ruleMap.GetMapId(),
			match:      match,
			protocol:   ruleMap.GetProtocol(),
			ports:      bridgePolicyPorts(ruleMap.GetPorts()),
			target:     target.Unmap(),
			targetPort: uint16(ruleMap.GetTargetPort()),
			expires:    bridgePolicyTime(ruleMap.GetExpires()),
			draining:   ruleMap.GetDrainingSince() != 0 || overlay.drainedRuleIds[string(ruleMap.GetMapId())],
			withdrawn:  overlay.resetRuleIds[string(ruleMap.GetMapId())],
		}
		if ruleMap.GetDrainingSince() != 0 {
			policyMap.drainEnd = bridgeDrainEnd(ruleMap.GetDrainingSince(), ruleMap.GetDrainUntil(), settings)
		}
		self.maps = append(self.maps, policyMap)
	}
	for _, served := range rules.GetServed() {
		prefix, _ := bridgeRulePrefix(served.GetPrefix())
		exposed, _ := bridgeRulePrefix(served.GetExposedPrefix())
		policyServed := &bridgePolicyServed{
			routeId:   served.GetRouteId(),
			exit:      served.GetKind() == bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT,
			prefix:    prefix,
			exposed:   exposed,
			withdrawn: overlay.resetRuleIds[string(served.GetRouteId())],
		}
		if served.GetDrainingSince() != 0 {
			policyServed.drainEnd = bridgeDrainEnd(served.GetDrainingSince(), served.GetDrainUntil(), settings)
		}
		self.served = append(self.served, policyServed)
	}

	type bridgePolicyIdentity struct {
		key                 []byte
		revoked             bool
		suspended           bool
		forwardDelegationId []byte
		forwardKey          []byte
	}
	identities := map[string]bridgePolicyIdentity{}
	for _, identity := range input.BridgeState.GetIdentities() {
		identities[string(identity.GetSidecarId())] = bridgePolicyIdentity{
			key:                 identity.GetIdentityPublicKey(),
			revoked:             identity.GetRevoked(),
			suspended:           identity.GetSuspended(),
			forwardDelegationId: identity.GetForwardDelegationId(),
			forwardKey:          identity.GetForwardPublicKey(),
		}
	}
	reach := func(rows []*bridge.BridgeRuleReach) []bridgePolicyReach {
		policyRows := make([]bridgePolicyReach, 0, len(rows))
		for _, row := range rows {
			prefix, _ := bridgeRulePrefix(row.GetPrefix())
			policyRows = append(policyRows, bridgePolicyReach{
				grantId:  row.GetGrantId(),
				prefix:   prefix,
				protocol: row.GetProtocol(),
				ports:    bridgePolicyPorts(row.GetPorts()),
				expires:  bridgePolicyTime(row.GetExpires()),
				revoked:  0 < len(row.GetGrantId()) && overlay.revokedGrantIds[string(row.GetGrantId())],
			})
		}
		return policyRows
	}
	for _, ruleSubject := range rules.GetSubjects() {
		identity, hasIdentity := identities[string(ruleSubject.GetSidecarId())]
		subject := &bridgePolicySubject{
			sidecarId:   connect.Id(ruleSubject.GetSidecarId()),
			memberId:    ruleSubject.GetMemberId(),
			tagged:      ruleSubject.GetTagged(),
			hasIdentity: hasIdentity,
			identityKey: identity.key,
			admitted: !identity.revoked && !identity.suspended &&
				!overlay.narrows(ruleSubject.GetSidecarId(), ruleSubject.GetMemberId()),
			dial:  reach(ruleSubject.GetDial()),
			route: reach(ruleSubject.GetRoute()),
			exit:  reach(ruleSubject.GetExit()),
		}
		// a forwarding Delegation and its key come as a pair of the right lengths, or the subject has neither
		if len(identity.forwardDelegationId) == sha256.Size && len(identity.forwardKey) == bridgeRuleIdentityByteCount {
			subject.hasForward = true
			subject.forwardDelegationId = [sha256.Size]byte(identity.forwardDelegationId)
			subject.forwardKey = identity.forwardKey
			subject.forwardDenied = overlay.deniesForward(ruleSubject.GetSidecarId(), identity.forwardDelegationId)
			// a Delegation two identities list is one neither's key is read under
			if held := self.subjectByForwardDelegationId[subject.forwardDelegationId]; held != nil {
				held.hasForward, subject.hasForward = false, false
			} else {
				self.subjectByForwardDelegationId[subject.forwardDelegationId] = subject
			}
		}
		self.subjectBySidecarId[subject.sidecarId] = subject
		for _, clientId := range ruleSubject.GetClientIds() {
			self.subjectByClientId[connect.Id(clientId)] = subject
		}
	}
	// autogroup:untagged's rows, which another client takes (bridge-m4-09-other-client-rows): no sidecar or member for
	// the overlay to narrow, and a revoked grant's rows admit nothing, as any subject's
	if untagged := rules.GetUntagged(); untagged != nil {
		self.otherClient.dial = reach(untagged.GetDial())
		self.otherClient.route = reach(untagged.GetRoute())
		self.otherClient.exit = reach(untagged.GetExit())
	}

	for _, listener := range input.BridgeState.GetDaemonListeners() {
		host, portText, err := net.SplitHostPort(listener)
		port, portErr := strconv.ParseUint(portText, 10, 16)
		if err != nil || portErr != nil || port == 0 {
			self.listenersUnknown = true
			continue
		}
		self.daemonPorts = append(self.daemonPorts, uint16(port))
		// a name is a local address already; an address that is no wildcard is one more
		if addr, err := netip.ParseAddr(host); err == nil && !addr.IsUnspecified() {
			self.listenerAddrs = append(self.listenerAddrs, addr.Unmap())
		}
	}
	return self
}

// Ports as the policy reads them; ParseBridgeRules holds them to 1 through 65535.
func bridgePolicyPorts(ports []*bridge.BridgePortRange) []bridgePolicyPortRange {
	policyPorts := make([]bridgePolicyPortRange, 0, len(ports))
	for _, port := range ports {
		policyPorts = append(policyPorts, bridgePolicyPortRange{first: uint16(port.GetFirst()), last: uint16(port.GetLast())})
	}
	return policyPorts
}

// A time of the rules, zero for none.
func bridgePolicyTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// The IP protocol number of a flow's protocol, 0 for one connect does not name.
func bridgeFlowProtocolNumber(ipProtocol connect.IpProtocol) uint32 {
	switch ipProtocol {
	case connect.IpProtocolTcp:
		return bridgeProtocolTcp
	case connect.IpProtocolUdp:
		return bridgeProtocolUdp
	case connect.IpProtocolIcmp:
		return bridgeProtocolIcmp
	default:
		return 0
	}
}

// Whether the address is public unicast: no private, shared, loopback, link-local, multicast, unspecified or reserved
// address, the documentation ranges counting as public, as connect's security policy counts them.
func bridgePublicUnicast(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	if addr.Is4() {
		for _, prefix := range bridgeNonPublicIpv4Prefixes {
			if prefix.Contains(addr) {
				return false
			}
		}
	}
	return true
}

// Rule 5's addresses.
func bridgeRuleFiveAddress(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified()
}

// Whether a row admits a flow of the protocol and port at now: in force, unrevoked, of the flow's protocol or every
// protocol, and of its port or every port. ICMP has no port, so a row naming ports never admits it.
func (self *bridgePolicyReach) admits(protocolNumber uint32, port uint16, now time.Time) bool {
	if self.revoked || (!self.expires.IsZero() && !now.Before(self.expires)) {
		return false
	}
	if self.protocol == 0 {
		return true
	}
	if self.protocol != protocolNumber {
		return false
	}
	if len(self.ports) == 0 {
		return true
	}
	if protocolNumber == bridgeProtocolIcmp {
		return false
	}
	for _, portRange := range self.ports {
		if portRange.first <= port && port <= portRange.last {
			return true
		}
	}
	return false
}

// AllowDial: a dial row admits the flow to this host.
func (self *bridgePolicySubject) allowDial(protocolNumber uint32, port uint16, now time.Time) bool {
	for i := range self.dial {
		if self.dial[i].admits(protocolNumber, port, now) {
			return true
		}
	}
	return false
}

// AllowRoute: a route row covering the destination as sent admits the flow.
func (self *bridgePolicySubject) allowRoute(addr netip.Addr, protocolNumber uint32, port uint16, now time.Time) bool {
	for i := range self.route {
		if self.route[i].prefix.Contains(addr) && self.route[i].admits(protocolNumber, port, now) {
			return true
		}
	}
	return false
}

// AllowExit: an exit row admits the flow out through this host.
func (self *bridgePolicySubject) allowExit(protocolNumber uint32, port uint16, now time.Time) bool {
	for i := range self.exit {
		if self.exit[i].admits(protocolNumber, port, now) {
			return true
		}
	}
	return false
}

// Whether a new flow may take the map at now.
func (self *bridgePolicyMap) admits(now time.Time) bool {
	return !self.withdrawn && !self.draining && (self.expires.IsZero() || now.Before(self.expires))
}

// Where the map sends a destination it matched: its target offset by the destination's place in the match, and its
// port offset by the port's place in its range, or the port kept. False when the offset leaves the address space.
func (self *bridgePolicyMap) mapTarget(addr netip.Addr, port uint16) (netip.AddrPort, bool) {
	target := self.target
	if self.match.Bits() < 32 {
		offset := bridgeAddrUint32(addr) - bridgeAddrUint32(self.match.Addr())
		var ok bool
		target, ok = bridgeAddrAdd(target, offset)
		if !ok {
			return netip.AddrPort{}, false
		}
	}
	targetPort := port
	if self.targetPort != 0 && len(self.ports) == 1 {
		targetPort = self.targetPort + (port - self.ports[0].first)
	}
	return netip.AddrPortFrom(target, targetPort), true
}

// Whether a new flow may take the served route at now.
func (self *bridgePolicyServed) admits(now time.Time) bool {
	return !self.withdrawn && (self.drainEnd.IsZero() || now.Before(self.drainEnd))
}

// An IPv4 address as a number; 0 for any other.
func bridgeAddrUint32(addr netip.Addr) uint32 {
	if !addr.Is4() {
		return 0
	}
	octets := addr.As4()
	return uint32(octets[0])<<24 | uint32(octets[1])<<16 | uint32(octets[2])<<8 | uint32(octets[3])
}

// addr plus offset, and false past the end of its family's space.
func bridgeAddrAdd(addr netip.Addr, offset uint32) (netip.Addr, bool) {
	if addr.Is4() {
		sum := uint64(bridgeAddrUint32(addr)) + uint64(offset)
		if 0xFFFFFFFF < sum {
			return netip.Addr{}, false
		}
		return bridgeRuleAddr(uint32(sum)), true
	}
	octets := addr.As16()
	carry := uint64(offset)
	for i := len(octets) - 1; 0 <= i && carry != 0; i -= 1 {
		sum := uint64(octets[i]) + carry&0xFF
		octets[i] = byte(sum)
		carry = carry>>8 + sum>>8
	}
	if carry != 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16(octets), true
}

// Whether the address is in the block or the block a change replaced.
func (self *bridgePolicyState) inBlock(addr netip.Addr) bool {
	return (self.block.IsValid() && self.block.Contains(addr)) ||
		(self.previousBlock.IsValid() && self.previousBlock.Contains(addr))
}

// Whether the address is in the previous block, whose drain has ended at now.
func (self *bridgePolicyState) lapsedInPreviousBlock(addr netip.Addr, now time.Time) bool {
	return self.previousBlock.IsValid() && self.previousBlock.Contains(addr) && !now.Before(self.previousBlockDrainUntil)
}

// Whether the address is this host's at now.
func (self *bridgePolicyState) hosted(addr netip.Addr, now time.Time) bool {
	return slices.Contains(self.hostedAddrs, addr) && !self.lapsedInPreviousBlock(addr, now)
}

// Whether the address may be this device's own, for rule 0.
func (self *bridgePolicyState) localAddress(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsUnspecified() || !self.localAddrsKnown {
		return true
	}
	return slices.Contains(self.localAddrs, addr) || slices.Contains(self.listenerAddrs, addr)
}

// Rule 0: whether a dial of addr and port could reach one of this device's daemon listeners.
func (self *bridgePolicyState) daemonListener(addr netip.Addr, port uint16) bool {
	if port == 0 || !self.localAddress(addr) {
		return false
	}
	return self.listenersUnknown || slices.Contains(self.daemonPorts, port)
}

// The first map that takes the destination, protocol and port at now; nil for none.
func (self *bridgePolicyState) matchMap(addr netip.Addr, port uint16, protocolNumber uint32, now time.Time) *bridgePolicyMap {
	if self.lapsedInPreviousBlock(addr, now) {
		return nil
	}
	for _, policyMap := range self.maps {
		if policyMap.protocol != protocolNumber || !policyMap.match.Contains(addr) || !policyMap.admits(now) {
			continue
		}
		if 0 < len(policyMap.ports) {
			inRange := false
			for _, portRange := range policyMap.ports {
				if portRange.first <= port && port <= portRange.last {
					inRange = true
					break
				}
			}
			if !inRange {
				continue
			}
		}
		return policyMap
	}
	return nil
}

// The first served subnet whose exposed prefix holds the address at now, and the address it remaps to.
func (self *bridgePolicyState) matchExposed(addr netip.Addr, now time.Time) (*bridgePolicyServed, netip.Addr) {
	if self.lapsedInPreviousBlock(addr, now) {
		return nil, netip.Addr{}
	}
	for _, served := range self.served {
		if served.exit || !served.exposed.IsValid() || !served.exposed.Contains(addr) || !served.admits(now) {
			continue
		}
		offset := bridgeAddrUint32(addr) - bridgeAddrUint32(served.exposed.Addr())
		return served, bridgeRuleAddr(bridgeAddrUint32(served.prefix.Addr()) + offset)
	}
	return nil, netip.Addr{}
}

// The first served subnet whose prefix holds the address at now; nil for none.
func (self *bridgePolicyState) matchServed(addr netip.Addr, now time.Time) *bridgePolicyServed {
	for _, served := range self.served {
		if !served.exit && served.prefix.Contains(addr) && served.admits(now) {
			return served
		}
	}
	return nil
}

// Whether this host serves an exit at now.
func (self *bridgePolicyState) servesExit(now time.Time) bool {
	for _, served := range self.served {
		if served.exit && served.admits(now) {
			return true
		}
	}
	return false
}

// The decision for one flow (bridge_egress.go's table, then this file's).
func (self *bridgePolicyState) resolve(
	profile BridgePolicyProfile,
	settings *BridgeSettings,
	flow *connect.EgressFlow,
	forwardDelegationId *[sha256.Size]byte,
	now time.Time,
) connect.EgressDecision {
	deny := connect.EgressDecision{Verdict: connect.EgressVerdictDeny, PolicyGeneration: self.generation}
	sdk := profile == BridgePolicyProfileSdkProvider
	mode := flow.ProvideMode
	if sdk {
		if self.posture == PostureLegacy || (mode != protocol.ProvideMode_Network && mode != protocol.ProvideMode_Service) {
			return connect.EgressDecision{Verdict: connect.EgressVerdictPass, PolicyGeneration: self.generation}
		}
	} else if mode != protocol.ProvideMode_Network && mode != protocol.ProvideMode_FriendsAndFamily {
		return deny
	}
	if flow.ContractClass != connect.ContractClassData || mode == protocol.ProvideMode_Service {
		return deny
	}
	protocolNumber := bridgeFlowProtocolNumber(flow.Protocol)
	if protocolNumber == 0 {
		return deny
	}

	var subject *bridgePolicySubject
	if sdk {
		subject = self.subjectByClientId[flow.SourceSubject]
		if subject == nil {
			subject = self.otherClient
		} else if !subject.admitted {
			return deny
		}
	} else {
		principal := flow.Principal
		if principal == nil {
			return deny
		}
		subject = self.subjectBySidecarId[principal.Subject]
		if subject == nil || !subject.admitted || !subject.hasIdentity {
			return deny
		}
		if self.networkId == (connect.Id{}) || principal.Network != self.networkId || principal.ShareId != (connect.Id{}) {
			return deny
		}
		if !now.Before(principal.NotAfter) || !flow.Sealed || mode == protocol.ProvideMode_FriendsAndFamily {
			return deny
		}
		// a principal a forwarding key admitted stands only while the state lists that Delegation live for its
		// subject and the overlay denies neither it nor the key
		if forwardDelegationId != nil && (!subject.forwardAdmitted() || subject.forwardDelegationId != *forwardDelegationId) {
			return deny
		}
	}
	if !self.posture.Enforcing() || self.rulesRefused {
		return deny
	}

	addr := flow.To.Addr().Unmap()
	port := flow.To.Port()
	if protocolNumber == bridgeProtocolIcmp {
		port = 0
	}
	var idle time.Duration
	if !sdk {
		idle = settings.PinIdleTimeout
		if protocolNumber == bridgeProtocolTcp {
			idle = settings.PinTcpIdleTimeout
		}
	}
	admit := func(verdict connect.EgressVerdict, target netip.AddrPort, ruleId []byte) connect.EgressDecision {
		ruleTag := BridgeRuleTag(subject.sidecarId, ruleId)
		if !sdk && forwardDelegationId != nil {
			ruleTag = BridgeForwardRuleTag(subject.sidecarId, *forwardDelegationId, ruleId)
		}
		return connect.EgressDecision{
			Verdict:          verdict,
			Target:           target,
			RuleTag:          ruleTag,
			PolicyGeneration: self.generation,
			IdleTimeout:      idle,
		}
	}
	allowAll := self.posture == PostureEnforcingNoDocument && !subject.tagged

	// rule 0
	if self.daemonListener(addr, port) {
		return deny
	}
	if !sdk {
		// rule 1
		if policyMap := self.matchMap(addr, port, protocolNumber, now); policyMap != nil {
			if !subject.allowDial(protocolNumber, port, now) {
				return deny
			}
			target, ok := policyMap.mapTarget(addr, port)
			if !ok || self.inBlock(target.Addr()) || self.daemonListener(target.Addr(), target.Port()) {
				return deny
			}
			return admit(connect.EgressVerdictMap, target, policyMap.mapId)
		}
		// rule 6's remap, hosted here
		if served, remapped := self.matchExposed(addr, now); served != nil {
			if !allowAll && !subject.allowRoute(addr, protocolNumber, port, now) {
				return deny
			}
			if self.daemonListener(remapped, port) {
				return deny
			}
			return admit(connect.EgressVerdictMap, netip.AddrPortFrom(remapped, port), served.routeId)
		}
		hosted := self.hosted(addr, now)
		// rule 2
		if !hosted && self.inBlock(addr) {
			return deny
		}
		// rule 3, tagged by the hosted address the flow was sent to
		if hosted {
			if !allowAll && !subject.allowDial(protocolNumber, port, now) {
				return deny
			}
			if self.daemonListener(bridgeHostedTarget, port) {
				return deny
			}
			ruleId := bridgeHostedRuleId(addr)
			return admit(connect.EgressVerdictMap, netip.AddrPortFrom(bridgeHostedTarget, port), ruleId[:])
		}
	} else if self.inBlock(addr) {
		// the block deny, in place of rules 1 to 3
		return deny
	}
	// rule 4
	if allowAll {
		return admit(connect.EgressVerdictPass, netip.AddrPort{}, []byte{BridgeRuleAllowAll})
	}
	// rule 5
	if bridgeRuleFiveAddress(addr) {
		return deny
	}
	// rule 6
	if !sdk {
		if served := self.matchServed(addr, now); served != nil {
			if !subject.allowRoute(addr, protocolNumber, port, now) {
				return deny
			}
			return admit(connect.EgressVerdictPass, netip.AddrPort{}, served.routeId)
		}
	}
	// rule 7
	if bridgePublicUnicast(addr) {
		if (!sdk && !self.servesExit(now)) || !subject.allowExit(protocolNumber, port, now) {
			return deny
		}
		return admit(connect.EgressVerdictPass, netip.AddrPort{}, []byte{BridgeRuleExit})
	}
	// rule 8
	return deny
}
