// The bridge compile's activated route grants (§8.8's folded grants, §17.8's placement; owner decisions 220 and 679;
// QD-003, QD-1164). A requested route grant keeps only ids in the clear: its prefixes and ports ride its
// CanonicalAction's sealed_detail. So the compile opens the detail of each surviving, unexpired activated grant a
// route or exit rule list names, where this device holds the config key of the generation it is sealed under, and
// reads it by the one reader the save's ip: tests and AclEngine read it by (acl_grant_route.go's aclReadGrantRoute),
// so an accept the save counts is one the compile serves, at the sender's table (mayUseRoute) and in the host's route
// and exit rows (reachRows, exitRules), at the same prefixes and ports:
//
//	prefixes   the detail's cidrs and its ip: destinations, each once
//	ports      the ports its sidecar destinations name, taken together, each once, since rows mark ports for the
//	           rule whole; none means every port
//	unread     no entry and no row, the closed direction, with why named: an action the state does not hold, a
//	           detail that does not open under the key held or does not hold to its action, a prefix or destination
//	           that does not read, and a target_port naming no protocol each alarm state_unverified; a generation
//	           whose key this device does not hold is named in Waits instead, so the component fetches it and
//	           compiles again
//
// A grant whose action seals no detail, one from before version 4 (record_action_rules.go's version-4 grants always
// seal one), names nothing this device can read: it stays closed, alarming nothing, as QD-003 left every activated
// grant, and the save's tests and AclEngine read it so too, so a deny the save passes is one no reader opens. Dial rows
// keep their own reading, the ports the detail names at this host (grantPortRule). An expired grant's rows are left
// out with every rule's at t (reachRows), and a revoked one is gone from the rows the enumerators read, so its entries
// and rows go at the next compile; between compiles a host's device role ends a row past its expiry by its own clock.
//
// Each grant's detail is opened once a compile, by grant id, and read through no Go map's order. testHookSecret runs
// where the detail's key derives, inside OpenConfigBody. On every leg, the ios_extension legs' included, with no
// connect import.

package sidecar

import (
	"encoding/hex"
)

// An activated grant's prefixes and ports as route and exit rows read them, nil where its detail does not open here
// (the file's comment). Opened once a compile.
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

// grantRoute's read of one grant by the shared reader, raising its alarm or wait.
func (self *bridgeCompiler) openGrantRoute(rule AclReachRule) *AclLocalRule {
	route := aclReadGrantRoute(rule.GrantId, rule.PortsLimited, self.grantDetails)
	switch route.unread {
	case aclGrantRouteUnreadNone:
		return route.local
	case aclGrantRouteUnreadUnsealed:
		// its action seals no detail (acl_grant.go's fold marks every one that does): QD-003's closed direction
		return nil
	}
	subjectId, generation := self.grantDetails.sealing(rule.GrantId)
	if route.unread == aclGrantRouteUnreadGeneration {
		if 0 < generation {
			self.wait(BridgeCompileWait{Kind: BridgeCompileWaitGeneration, Generation: generation})
		}
		return nil
	}
	self.alarm(SidecarBridgeAlarmStateUnverified, 0, subjectId,
		"grant "+hex.EncodeToString(rule.GrantId)+": its sealed detail "+route.unread.String()+", so it gives no entry and no row")
	return nil
}
