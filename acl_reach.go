// The reads BRIDGE's compiler takes reach from (DESIGN-DETAILS 12.2.4's steps 2 and 7, 12.7's ACL-M2-17). The one-flow
// checks return the first rule that allows; a compile needs every one, since each becomes a row of a subject's reach with
// its own grant id, expiry and ports. DialRules, RouteRules and ExitRules run the checks' own search (acl_eval.go's
// nextSubjectRule and nextResourceRule, and routeTakes) to its end, so each is empty exactly where its check refuses:
//
//	DialRules(s, d)   MayDial(s, d): dial rules from s whose subject targets name d, autogroup:self where the two share
//	                  an owner or sponsor; a socket dial reaches no subject here, as in MayDial
//	RouteRules(s, v)  MayRoute(s, a, v) for an address a that is no public one: route rules from s whose via subjects,
//	                  their subject targets, hold v
//	ExitRules(s, v)   MayRoute(s, a, v) for a public address a: those, and autogroup:internet's through any via
//
// Each answers in rule id order, every rule and activated grant in force at now, and nothing for a hard-denied end. A
// rule's ports and prefixes are the device's, from AclLocalPolicy.Rule by RuleId (plan-BRIDGE-gate-row-prefixes #1). A
// route rule with no via reaches no via here, as in MayRoute and at the contract gate: its via subjects are the
// advertisers whose BridgeRoute.route_rule_ids name it (QD-004), which rows do not carry yet, so it opens nothing until
// they do (question acl-m2-17-no-via-route-advertisers).
//
// EgressMode exports the mode the contract gate's egressRestricted reads (§17.9's egress spec, D-BRIDGE-13), and
// StandingCovers answers 12.2.4's "in force" for a bridge rule filed with no approval.
//
// Pure, with no clock, no lock and no map order, on every leg, the ios_extension leg's list naming this file: root Id,
// no connect type. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One rule or activated grant by which a source holds a reach. Its slices point into the state's rows, which the caller
// must not change.
type AclReachRule struct {
	// The row's rule_id: a document's, the implicit document's or a kind default's 16 bytes, or an activated grant's
	// grant_id (plan-ACL-folded-grant-state #2), by which AclLocalPolicy.Rule finds its ports and prefixes.
	RuleId []byte
	// An activated grant's grant_id, which a GrantRevoke names: the same bytes as RuleId. Nil for a rule of the head.
	GrantId []byte
	// ms since the epoch; 0 none.
	ExpiresMs int64
	// Whether the rule's ip field names ports, which only AclLocalPolicy holds.
	PortsLimited bool
	// Whether its dst names autogroup:internet, which takes public destinations through any via; any other exit rule
	// stands on its via subjects and its prefixes.
	Internet bool
}

// A rule as the enumerators answer it.
func aclReachRuleOf(rule *aclRule) AclReachRule {
	reach := AclReachRule{
		RuleId:       rule.row.GetRuleId(),
		ExpiresMs:    rule.expiresMs,
		PortsLimited: rule.portsLimited,
		Internet:     rule.internetTarget,
	}
	if len(rule.row.GetSourceRuleId()) != 0 {
		reach.GrantId = rule.row.GetRuleId()
	}
	return reach
}

// Rules in rule id order. Compiled rows are in that order already, so this only holds rows from elsewhere to it.
func aclSortReachRules(reach []AclReachRule) []AclReachRule {
	slices.SortStableFunc(reach, func(a AclReachRule, b AclReachRule) int {
		return bytes.Compare(a.RuleId, b.RuleId)
	})
	return reach
}

// Every rule in force at now by which source may dial destination, in rule id order: MayDial's search to its end.
func (self *AclState) DialRules(source AclSubject, destination AclSubject, now time.Time) []AclReachRule {
	nowMs := now.UnixMilli()
	sourceResolved := self.resolve(&source, nowMs)
	destinationResolved := self.resolve(&destination, nowMs)
	if sourceResolved.deny != 0 || destinationResolved.deny != 0 {
		return nil
	}
	dial := uint32(1) << uint32(protocol.AclAction_ACL_ACTION_DIAL)
	var reach []AclReachRule
	next := func(from int32) *aclRule {
		return self.nextSubjectRule(&sourceResolved, &destinationResolved, nowMs, dial, nil, false, from)
	}
	for rule := next(0); rule != nil; rule = next(rule.index + 1) {
		reach = append(reach, aclReachRuleOf(rule))
	}
	return aclSortReachRules(reach)
}

// Every rule in force at now by which source may route through via to an address that is no public one, in rule id
// order: MayRoute's search to its end. The prefixes are the device's to meet (AclLocalPolicy).
func (self *AclState) RouteRules(source AclSubject, via AclSubject, now time.Time) []AclReachRule {
	return self.routeRules(source, via, now.UnixMilli(), false)
}

// Every rule in force at now by which source may reach public destinations through via, an exit, in rule id order:
// MayRoute's search to its end for a public address.
func (self *AclState) ExitRules(source AclSubject, via AclSubject, now time.Time) []AclReachRule {
	return self.routeRules(source, via, now.UnixMilli(), true)
}

// RouteRules and ExitRules, by whether the destination is public.
func (self *AclState) routeRules(source AclSubject, via AclSubject, nowMs int64, public bool) []AclReachRule {
	sourceResolved := self.resolve(&source, nowMs)
	viaResolved := self.resolve(&via, nowMs)
	if sourceResolved.deny != 0 || viaResolved.deny != 0 {
		return nil
	}
	match := func(rule *aclRule) bool {
		return self.routeTakes(&sourceResolved, &viaResolved, public, rule)
	}
	var reach []AclReachRule
	next := func(from int32) *aclRule {
		return self.nextResourceRule(&sourceResolved, nowMs, protocol.AclAction_ACL_ACTION_ROUTE, match, from)
	}
	for rule := next(0); rule != nil; rule = next(rule.index + 1) {
		reach = append(reach, aclReachRuleOf(rule))
	}
	return aclSortReachRules(reach)
}

// The egress mode the rows' BridgeRows give a subject (§17.9's egress spec): the mode of the row naming its sidecar or
// client id, else of the first row, in the rows' subject order, naming an atom it holds, which is the spec whose exits
// 12.2.4's step 7 takes; auto where no row names it. Every row is exits or none, since auto removes a subject's row
// (bridge_rows.go), so a mode other than auto is what the contract gate refuses Public contracts on (§8.10). Bytes no
// verifier folded, or a field this build cannot name, anywhere in the section read as none, the closed direction
// ParseBridgeRows takes. A hard-denied subject is answered too: every gate refuses it on its own.
func (self *AclState) EgressMode(subject AclSubject) bridge.BridgeEgressMode {
	resolved := self.resolve(&subject, 0)
	return self.egressMode(&resolved)
}

// EgressMode for a resolved subject, read from AclRows.bridge's bytes in place, so it allocates nothing.
func (self *AclState) egressMode(resolved *aclResolved) bridge.BridgeEgressMode {
	// whether a row's subject is an atom the subject holds: a tag, a group, a derived atom or an autogroup
	holdsAtom := func(subject Id) bool {
		index, found := self.atomIndexes[subject]
		if !found {
			return false
		}
		if resolved.sidecar != nil {
			_, holds := slices.BinarySearch(resolved.sidecar.atoms, index)
			return holds
		}
		return self.holdsAtom(resolved, index)
	}
	var direct, held bridge.BridgeEgressMode
	data := self.rows.GetBridge()
	for 0 < len(data) {
		number, wireType, n := protowire.ConsumeTag(data)
		if n < 0 || number != 1 || wireType != protowire.BytesType {
			return bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE
		}
		data = data[n:]
		row, n := protowire.ConsumeBytes(data)
		if n < 0 {
			return bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE
		}
		data = data[n:]
		subject, mode, ok := aclEgressRow(row)
		if !ok || (mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS && mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE) {
			return bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE
		}
		switch {
		case direct == bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED && resolved.subject.Id == subject:
			direct = mode
		case held == bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED && holdsAtom(subject):
			held = mode
		}
	}
	switch {
	case direct != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED:
		return direct
	case held != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_UNSPECIFIED:
		return held
	}
	return bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO
}

// One BridgeEgressRow's subject and mode, false for bytes CompileBridgeRows never writes.
func aclEgressRow(row []byte) (Id, bridge.BridgeEgressMode, bool) {
	var subject Id
	var mode bridge.BridgeEgressMode
	subjectSet := false
	for 0 < len(row) {
		number, wireType, n := protowire.ConsumeTag(row)
		if n < 0 {
			return Id{}, 0, false
		}
		row = row[n:]
		switch {
		case number == 1 && wireType == protowire.BytesType:
			value, n := protowire.ConsumeBytes(row)
			if n < 0 || len(value) != len(Id{}) {
				return Id{}, 0, false
			}
			subject, subjectSet = Id(value), true
			row = row[n:]
		case number == 2 && wireType == protowire.VarintType:
			value, n := protowire.ConsumeVarint(row)
			if n < 0 {
				return Id{}, 0, false
			}
			mode = bridge.BridgeEgressMode(value)
			row = row[n:]
		default:
			return Id{}, 0, false
		}
	}
	return subject, mode, subjectSet
}

// Whether a grant of the policy in force covers a bridge rule filed with no approval, which 12.2.4 holds in force only
// while one does (§17.7: a standing grant activates it):
//
//	route   a route rule of the head among the ids its route_rule_ids name, in force at now, whose prefixes hold every
//	        prefix of a subnet route, or for an exit route reach public destinations (autogroup:internet, or a /0 such as
//	        a bare * gives), and whose via subjects hold its advertiser; a rule with no via is held by every advertiser
//	        whose route names it (QD-004)
//	map     a dial rule of the head in force at now whose subject targets name its host, autogroup:self naming any host
//	        with an owner or sponsor, and whose ports cover the map's protocol and ports
//
// With no document an untagged owner's rules are covered (owner decision 120), and a tagged owner's only by the implicit
// document's rules, which this judges as it does a document's. A rule of the head is the document's or the implicit
// one's: an activated grant is no standing grant. Ports and prefixes are this policy's; a nil policy with no document
// reads the implicit document's own, so it judges as CompileAclLocal's, and a nil one under a document holds none, so a
// map is covered only by a rule that limits no ports and a route by none, the closed direction AclEngine takes. The owner
// must be a sidecar the state admits with no hard deny at now. Whether the rule's body is active is the ledger's to say.
func (self *AclLocalPolicy) StandingCovers(state *AclState, rule *BridgeLedgerRule, now time.Time) bool {
	if state == nil || rule == nil {
		return false
	}
	nowMs := now.UnixMilli()
	owner := state.sidecarState(rule.Owner)
	if owner == nil || owner.hardDeny(nowMs) != 0 {
		return false
	}
	if !state.HasDocument() && !owner.tagged {
		return true
	}
	local := self
	if local == nil && !state.HasDocument() {
		local = aclImplicitLocalPolicy()
	}
	switch {
	case rule.SignedType == bridge.SignedType_SIGNED_BRIDGE_ROUTE && rule.Route != nil:
		return local.routeCovered(state, owner, rule.RouteRuleIds, rule.Route, nowMs)
	case rule.SignedType == bridge.SignedType_SIGNED_BRIDGE_MAP && rule.Map != nil:
		return local.mapCovered(state, owner, rule.Map, nowMs)
	}
	return false
}

// Whether a rule of the head among routeRuleIds holds a route for its advertiser.
func (self *AclLocalPolicy) routeCovered(state *AclState, advertiser *aclSidecarState, routeRuleIds [][]byte,
	route *bridge.BridgeRouteBody, nowMs int64) bool {
	prefixes := []netip.Prefix{}
	for _, wirePrefix := range route.GetPrefixes() {
		if wirePrefix == nil || 32 < wirePrefix.GetLength() {
			return false
		}
		address := wirePrefix.GetAddress()
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)}),
			int(wirePrefix.GetLength()))
		if prefix.Masked() != prefix {
			return false
		}
		prefixes = append(prefixes, prefix)
	}
	exit := route.GetKind() == bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT
	if !exit && (route.GetKind() != bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET || len(prefixes) == 0) {
		return false
	}
	// whether every prefix lies in one of the cidrs, a /0 holding none inside loopback or link-local, which it leaves
	// out (§8.4)
	holdsPrefixes := func(cidrs []netip.Prefix) bool {
		for _, prefix := range prefixes {
			held := slices.ContainsFunc(cidrs, func(cidr netip.Prefix) bool {
				if cidr.Bits() == 0 && (prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast()) {
					return false
				}
				return cidr.Addr().Is4() == prefix.Addr().Is4() && cidr.Bits() <= prefix.Bits() && cidr.Contains(prefix.Addr())
			})
			if !held {
				return false
			}
		}
		return true
	}
	// whether a cidr is IPv4's 0.0.0.0/0, which reaches public destinations as an exit does
	ipv4Default := func(cidr netip.Prefix) bool {
		return cidr.Bits() == 0 && cidr.Addr().Is4()
	}
	for _, routeRuleId := range routeRuleIds {
		for i := range state.rules {
			rule := &state.rules[i]
			if !bytes.Equal(rule.row.GetRuleId(), routeRuleId) || !state.standingRule(rule, nowMs, protocol.AclAction_ACL_ACTION_ROUTE) {
				continue
			}
			if rule.hasSubjectTargets() && !state.namesTarget(advertiser, rule) {
				continue
			}
			local := self.Rule(rule.row.GetRuleId())
			if exit {
				if rule.internetTarget || (local != nil && slices.ContainsFunc(local.Cidrs, ipv4Default)) {
					return true
				}
				continue
			}
			if local != nil && holdsPrefixes(local.Cidrs) {
				return true
			}
		}
	}
	return false
}

// Whether a dial rule of the head names the map's host and covers its ports: an ICMP map by icmp:* or *; a TCP or UDP
// map's every range, none meaning every port, by the union of its protocol's ranges and the any-protocol ones; another
// protocol only by a rule that limits no ports.
func (self *AclLocalPolicy) mapCovered(state *AclState, host *aclSidecarState, body *bridge.BridgeMapBody, nowMs int64) bool {
	protocolNumber := body.GetProtocol()
	// whether the union of the ranges of the map's protocol, and of any protocol, holds first to last
	coverRange := func(ports []AclPortRange, first uint32, last uint32) bool {
		for next := first; ; {
			advanced := false
			for _, held := range ports {
				if (held.Protocol == 0 || held.Protocol == protocolNumber) && held.First <= next && next <= held.Last {
					if last <= held.Last {
						return true
					}
					next = held.Last + 1
					advanced = true
				}
			}
			if !advanced {
				return false
			}
		}
	}
	cover := func(ports []AclPortRange) bool {
		switch protocolNumber {
		case aclIpProtocolIcmp:
			return slices.ContainsFunc(ports, func(held AclPortRange) bool {
				return held.Protocol == aclIpProtocolIcmp || (held.Protocol == 0 && held.First == 0 && held.Last == math.MaxUint16)
			})
		case aclIpProtocolTcp, aclIpProtocolUdp:
		default:
			return false
		}
		if len(body.GetPorts()) == 0 {
			return coverRange(ports, 1, math.MaxUint16)
		}
		for _, mapRange := range body.GetPorts() {
			if mapRange.GetLast() < mapRange.GetFirst() || !coverRange(ports, mapRange.GetFirst(), mapRange.GetLast()) {
				return false
			}
		}
		return true
	}
	for i := range state.rules {
		rule := &state.rules[i]
		if !state.standingRule(rule, nowMs, protocol.AclAction_ACL_ACTION_DIAL) || !state.namesTarget(host, rule) {
			continue
		}
		if !rule.portsLimited {
			return true
		}
		if local := self.Rule(rule.row.GetRuleId()); local != nil && cover(local.Ports) {
			return true
		}
	}
	return false
}

// Whether a rule is a rule of the head, the document's or the implicit one's rather than an activated grant, in force
// at nowMs and allowing the action.
func (self *AclState) standingRule(rule *aclRule, nowMs int64, action protocol.AclAction) bool {
	return len(rule.row.GetSourceRuleId()) == 0 && rule.activeAt(nowMs) && rule.allows(action)
}

// Whether a rule's subject targets name a sidecar for some source: an atom it holds, its id, or autogroup:self, which
// names it for the sources sharing its owner or sponsor.
func (self *AclState) namesTarget(sidecar *aclSidecarState, rule *aclRule) bool {
	return (rule.selfTarget && sidecar.hasOwner) || self.sidecarIsSubjectTarget(sidecar, rule)
}

// The implicit document's local policy, compiled once from the binary's own document, which never changes (acl_implicit.go):
// what a nil policy reads with no document.
var aclImplicitLocal struct {
	once   sync.Once
	policy *AclLocalPolicy
}

// The implicit document's local policy, nil if the binary's document did not compile, which acl_reach_test.go holds.
func aclImplicitLocalPolicy() *AclLocalPolicy {
	aclImplicitLocal.once.Do(func() {
		if policy, err := CompileAclLocal(&AclCompileInput{}); err == nil {
			aclImplicitLocal.policy = policy
		}
	})
	return aclImplicitLocal.policy
}
