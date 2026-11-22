//go:build !ios_extension

// §16.6's step 2 for an exposure (§17.7, §17.8's approval row; §5.4, I-8, I-9, TS1): "approval is separate from access
// ... a standing grant in a config head or an I-8 approval (§16.6) activates it", and bridge_expose files "a BridgeRoute
// or BridgeMap under a standing grant or its decision". An exposure's CanonicalAction carries no grant fields, its
// target, prefixes, port and expiry alone, so ActiveGrant, which reads a grant's subject, destinations and actions,
// covers none, and before this the gate held every exposure for a person even where the document's standing route or
// dial rule activated the rule it files. Here the exposure's effect names the rule it files under an empty key
// (SidecarStandingRuleEffect), and the gate's standing-grants source judges it by the predicate every reader holds a
// rule filed with no approval in force by (ApprovalStandingRules; AclEngine's is AclLocalPolicy.StandingCovers):
//
//	held      the rule is the action's, as every reader holds a rule to the action a decision approved: the spender
//	          its owner and the action's target, a single exposure no template, its body carrying no approval, and by
//	          bridgeApprovalCovers a route only for an action naming no target_port or expiry and a map only for one
//	          naming no cidrs (QD-1184), a route's prefixes inside the action's cidrs and an exit only where it lists
//	          0.0.0.0/0, a map's target_port and expiry the action's where it sets them; a rule its action does not
//	          describe stands for nothing
//	covered   the source answers for the spender at now; a source that judges no rule, an effect that names none, or
//	          no source at all passes no exposure, which then takes a decision as before
//
// The gate asks only in an untainted run, for an action that is no template (TS1; the multi-use row), and runs the
// effect under an empty key with no ledger row and nothing filed, so a standing exposure files no ApprovalRequest. The
// filed rule carries no approval, and every reader holds it in force only while a standing grant covers it at its
// state (§17.7; DESIGN-DETAILS 12's in-force row), so the gate's answer opens nothing the document does not: it only
// spares a person a decision the readers would not need. Safe for concurrent use, as the gate is. On every leg but the
// ios_extension legs, whose forwarding role spends nothing.

package sidecar

import (
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// ACL-M4-02's standing grants as the gate asks them for a bridge exposure, beside ApprovalStandingGrants: whether the
// rule the exposure files with no approval, a route or a map the spender owns, stands for the spender at now, by the
// predicate every reader holds such a rule in force by (AclLocalPolicy.StandingCovers). A standing-grants source that
// implements it passes the exposures it covers; one that does not passes none. The gate never asks in a tainted run.
type ApprovalStandingRules interface {
	StandingRule(rule *BridgeLedgerRule, spender Id, now time.Time) bool
}

// An effect that files a rule a standing grant activates with no approval in place of a grant its action would name:
// a bridge exposure's route or map (§17.8's approval row). The rule as the effect files it under an empty key, its owner
// and body, its approval none, for the gate to ask ApprovalStandingRules about; nil where it cannot say, which leaves
// the action to a decision. The answer is the caller's to keep.
type SidecarStandingRuleEffect interface {
	SidecarEffect
	StandingRule() *BridgeLedgerRule
}

// Whether a standing grant covers action for this sidecar at now (the file header): ActiveGrant over the action's grant
// fields, or for an exposure whose effect names the rule it files, that rule held to the action and judged by the
// standing-grants source. No source covers nothing.
func (self *ApprovalGate) standingCovers(action *SidecarAction, stored *StoredCanonicalAction, now time.Time) bool {
	if self.grants == nil {
		return false
	}
	if self.grants.ActiveGrant(stored, self.args.SidecarId, now) {
		return true
	}
	rules, ok := self.grants.(ApprovalStandingRules)
	if !ok {
		return false
	}
	effect, ok := action.Effect.(SidecarStandingRuleEffect)
	if !ok {
		return false
	}
	rule := effect.StandingRule()
	if rule == nil || rule.Owner != self.args.SidecarId {
		return false
	}
	// the rule is the action's, as a reader holds a filed rule to the action its approval names (CheckBridgeApproval)
	exposure := stored.Action
	if SidecarActionKind(exposure.GetKind()) != SidecarActionExpose || exposure.GetScope() ||
		len(exposure.GetTargetSidecarId()) != len(Id{}) || Id(exposure.GetTargetSidecarId()) != self.args.SidecarId {
		return false
	}
	statement := &BridgeLogStatement{SignedType: rule.SignedType, Signer: rule.Owner, Subject: rule.Owner, Expires: rule.Expires}
	var body proto.Message
	switch {
	case rule.SignedType == bridge.SignedType_SIGNED_BRIDGE_ROUTE && rule.Route != nil && rule.Map == nil && rule.Route.GetApproval() == nil:
		body = rule.Route
	case rule.SignedType == bridge.SignedType_SIGNED_BRIDGE_MAP && rule.Map != nil && rule.Route == nil && rule.Map.GetApproval() == nil:
		body = rule.Map
	default:
		return false
	}
	if bridgeApprovalCovers(exposure, statement, body) != nil {
		return false
	}
	return rules.StandingRule(rule, self.args.SidecarId, now)
}
