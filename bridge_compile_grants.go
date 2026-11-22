// The bridge compile's activated route grants (§8.8's folded grants, §17.8's placement; owner decisions 220 and 679;
// QD-003, QD-1164). A requested route grant keeps only ids in the clear: its prefixes and ports ride its
// CanonicalAction's sealed_detail. So the compile opens the detail of each surviving, unexpired activated grant a
// route or exit rule list names, where this device holds the config key of the generation it is sealed under, and
// reads it as the save's ip: tests read it (acl_tests.go's grantRoute), so an accept the save counts is one the compile
// serves, at the sender's table (mayUseRoute) and in the host's route and exit rows (reachRows, exitRules):
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
// seal one), names nothing this device can read, so whether it reaches anything is not the compile's to say: it stays
// closed, as QD-003 left every activated grant, while the save's tests read it as routing by its subjects, the stricter
// reading for a deny. Dial rows keep their own reading, the ports the detail names at this host (grantPortRule). An
// expired grant's rows are left out with every rule's at t (reachRows), and a revoked one is gone from the rows the
// enumerators read, so its entries and rows go at the next compile; between compiles a host's device role ends a row
// past its expiry by its own clock.
//
// Each grant's detail is opened once a compile, by grant id, and read through no Go map's order. testHookSecret runs
// where the detail's key derives, inside OpenConfigBody. On every leg, the ios_extension legs' included, with no
// connect import.

package sidecar

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
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

// grantRoute's read of one grant, raising its alarm or wait.
func (self *bridgeCompiler) openGrantRoute(rule AclReachRule) *AclLocalRule {
	if !rule.PortsLimited {
		// its action seals no detail (acl_grant.go's fold marks every one that does): QD-003's closed direction
		return nil
	}
	grantName := "grant " + hex.EncodeToString(rule.GrantId)
	unread := func(subjectId Id, why string) *AclLocalRule {
		self.alarm(SidecarBridgeAlarmStateUnverified, 0, subjectId, grantName+": its sealed detail "+why+", so it gives no entry and no row")
		return nil
	}
	encoded := self.grantActions[string(rule.GrantId)]
	if len(encoded) == 0 {
		return unread(Id{}, "is not held here: the state keeps no action for it")
	}
	action, err := ParseStoredCanonicalAction(encoded)
	if err != nil {
		return unread(Id{}, "rides an action that does not parse")
	}
	subjectId, _ := IdFromBytes(action.Action.GetSubject())
	detail, err := OpenCanonicalActionDetail(action, self.state.NetworkId(), self.view.RepoKeyAt)
	switch {
	case errors.Is(err, ErrConfigSealGenerationMissing):
		if generation, generationErr := ConfigSealedGeneration(action.Action.GetSealedDetail()); generationErr == nil && 0 < generation {
			self.wait(BridgeCompileWait{Kind: BridgeCompileWaitGeneration, Generation: generation})
		}
		return nil
	case err != nil:
		return unread(subjectId, "does not open here")
	case detail == nil:
		return unread(subjectId, "is missing")
	}
	local, why := bridgeCompileGrantDetail(detail)
	if why != "" {
		return unread(subjectId, why)
	}
	return local
}

// A route grant's opened detail as its rows read it (the file's comment): its prefixes and its ports, each once; or
// why not, for a detail whose prefixes or destinations do not read, or whose target_port names no protocol.
func bridgeCompileGrantDetail(detail *protocol.CanonicalActionDetail) (*AclLocalRule, string) {
	local := &AclLocalRule{}
	addPrefix := func(text string) bool {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return false
		}
		if prefix = prefix.Masked(); !slices.Contains(local.Cidrs, prefix) {
			local.Cidrs = append(local.Cidrs, prefix)
		}
		return true
	}
	for _, text := range detail.GetCidrs() {
		if !addPrefix(text) {
			return nil, "holds a prefix that does not read"
		}
	}
	for _, dst := range detail.GetGrantDst() {
		if text, isPrefix := strings.CutPrefix(dst, "ip:"); isPrefix {
			if !addPrefix(text) {
				return nil, "holds a prefix that does not read"
			}
			continue
		}
		_, ports, err := ParseAclGrantDst(dst)
		if err != nil || ports == nil {
			return nil, "holds a destination that does not read"
		}
		portRange := AclPortRange{Protocol: ports.GetProtocol(), First: ports.GetFirst(), Last: ports.GetLast()}
		if !slices.Contains(local.Ports, portRange) {
			local.Ports = append(local.Ports, portRange)
		}
	}
	if detail.GetTargetPort() != 0 && len(local.Ports) == 0 {
		return nil, "names a port with no protocol"
	}
	return local, ""
}
