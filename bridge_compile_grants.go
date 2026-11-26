// The bridge compile's activated dial and route grants (§8.8's folded grants, §17.8's placement; owner decisions 220
// and 679; QD-003, QD-740, QD-1164, QD-1428). A requested dial or route grant keeps only ids in the clear: its prefixes
// and ports ride its CanonicalAction's sealed_detail. So the compile opens the detail of each surviving, unexpired
// activated grant a rule list names, where this device holds the config key of the generation it is sealed under, and
// reads it by the readers the save's tests and AclEngine read it by (acl_grant_route.go): the route reader
// (aclGrantRouteOfDetail, which aclReadGrantRoute composes with the opening) for the sender's table (mayUseRoute) and
// the host's route and exit rows (reachRows, exitRules), and its dial counterpart (aclGrantDialPortsOf) for the host's
// dial rows (reachRows), so an accept the save counts is one the compile serves, at the same prefixes and ports:
//
//	prefixes   a route grant's detail's cidrs and its ip: destinations, each once
//	ports      a route grant's: the ports its sidecar destinations name, taken together, each once, since rows mark
//	           ports for the rule whole, none meaning every port; a port-limited dial grant's: the ports its detail
//	           names at this host, a target_port keeping only the destinations whose port it is, none at this host
//	           giving no dial row
//	unread     no entry and no row, the closed direction, with why named: an action the state does not hold or a
//	           detail that does not open under the key held or does not hold to its action, for a dial or a route
//	           grant alike, and for a route grant a prefix or destination that does not read or a target_port naming
//	           no protocol, each alarm state_unverified; a generation whose key this device does not hold is named in
//	           Waits instead, so the component fetches it and compiles again
//
// A route grant whose action seals no detail, one from before version 4 (record_action_rules.go's version-4 grants
// always seal one), names nothing this device can read: it stays closed, alarming nothing, as QD-003 left every
// activated grant, and the save's tests and AclEngine read it so too, so a deny the save passes is one no reader opens.
// A dial grant whose action seals none limits no ports, as its rows say, so its dial rows stand at every port and its
// detail is never asked. An expired grant's rows are left out with every rule's at t (reachRows), and a revoked one is
// gone from the rows the enumerators read, so its entries and rows go at the next compile; between compiles a host's
// device role ends a row past its expiry by its own clock.
//
// Each grant's detail is opened once a compile, by grant id, for its route and its dial readings both, so a grant
// allowing both waits or alarms once for an opening that fails; and read through no Go map's order. testHookSecret runs
// where the detail's key derives, inside OpenConfigBody. On every leg, the ios_extension legs' included, with no
// connect import.

package sidecar

import (
	"encoding/hex"

	"github.com/urnetwork/sidecar/protocol"
)

// One activated grant's sealed detail as this compile opened it (aclOpenGrantDetail): the detail, or nil and why it
// gives nothing here.
type bridgeCompileGrantOpening struct {
	detail *protocol.CanonicalActionDetail
	unread aclGrantRouteUnread
}

// An activated grant's sealed detail, opened once a compile by the shared opening, which raises its wait or alarm then
// (the file's comment): nil where it does not open here, and for a grant whose action seals none.
func (self *bridgeCompiler) grantDetail(rule AclReachRule) *protocol.CanonicalActionDetail {
	if opening, found := self.grantOpenings[string(rule.GrantId)]; found {
		return opening.detail
	}
	detail, unread := aclOpenGrantDetail(rule.GrantId, rule.PortsLimited, self.grantDetails)
	if self.grantOpenings == nil {
		self.grantOpenings = map[string]*bridgeCompileGrantOpening{}
	}
	self.grantOpenings[string(rule.GrantId)] = &bridgeCompileGrantOpening{detail: detail, unread: unread}
	switch unread {
	case aclGrantRouteUnreadNone, aclGrantRouteUnreadUnsealed:
		// read, or its action seals no detail (acl_grant.go's fold marks every one that does): nothing to wait on
		return detail
	case aclGrantRouteUnreadGeneration:
		if _, generation := self.grantDetails.sealing(rule.GrantId); 0 < generation {
			self.wait(BridgeCompileWait{Kind: BridgeCompileWaitGeneration, Generation: generation})
		}
		return nil
	}
	self.grantAlarm(rule, unread)
	return nil
}

// Alarms state_unverified for a grant whose detail gives nothing here, naming the grant and why, never a prefix, port
// or key (I-13).
func (self *bridgeCompiler) grantAlarm(rule AclReachRule, unread aclGrantRouteUnread) {
	subjectId, _ := self.grantDetails.sealing(rule.GrantId)
	self.alarm(SidecarBridgeAlarmStateUnverified, 0, subjectId,
		"grant "+hex.EncodeToString(rule.GrantId)+": its sealed detail "+unread.String()+", so it gives no entry and no row")
}

// An activated grant's prefixes and ports as route and exit rows read them, nil where its detail does not open here
// or does not read as a route (the file's comment). Read once a compile.
func (self *bridgeCompiler) grantRoute(rule AclReachRule) *AclLocalRule {
	if local, found := self.grantRoutes[string(rule.GrantId)]; found {
		return local
	}
	local := self.openGrantRoute(rule)
	self.grantRoutes[string(rule.GrantId)] = local
	return local
}

// An activated grant as route and exit rows take it: its detail (grantRoute), and its rule limiting ports only where
// the detail names some, none meaning every port. A detail that does not open stays port-limited with no detail, which
// gives no row (bridgeCompilePortRows).
func (self *bridgeCompiler) grantRouteRule(rule AclReachRule) (AclReachRule, *AclLocalRule) {
	local := self.grantRoute(rule)
	rule.PortsLimited = local == nil || 0 < len(local.Ports)
	return rule, local
}

// grantRoute's read of one grant: its detail opened by the shared opening, then read by the route reader, raising the
// alarm a detail that opens but does not read as a route gives.
func (self *bridgeCompiler) openGrantRoute(rule AclReachRule) *AclLocalRule {
	detail := self.grantDetail(rule)
	if detail == nil {
		return nil
	}
	local, unread := aclGrantRouteOfDetail(detail)
	if unread != aclGrantRouteUnreadNone {
		self.grantAlarm(rule, unread)
		return nil
	}
	return local
}

// A port-limited activated dial grant as this host's dial rows take it: the ports its detail names at S by the dial
// reader (aclGrantDialPortsOf), none at S giving no row, and nil, no row, where its detail does not open here, whose
// wait or alarm the opening raised (the file's comment). A grant whose action seals no detail never comes here: its
// rows limit no ports.
func (self *bridgeCompiler) grantDialRule(rule AclReachRule) *AclLocalRule {
	detail := self.grantDetail(rule)
	if detail == nil {
		return nil
	}
	return aclGrantDialPortsOf(detail).at(self.self)
}
