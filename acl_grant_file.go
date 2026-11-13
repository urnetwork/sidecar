//go:build !ios_extension

// §8.6's requested grants on the device (ACL-M4-02; R-ACL-4, R-ACL-5, D-ACL-7, D-ACL-23, I-8, I-9, D-CTX-5): the flow
// behind Sidecar.Authorize for an action a grant must cover.
//
//	active    under an active grant Authorize passes with no decision (§16.6's step 2, untainted runs only, TS1):
//	          AclEngine.ActiveGrant, which MCP's ApprovalGate reads as its ApprovalStandingGrants
//	request   otherwise MatchAclRequest finds the requests rule at the installed state, and AclGrantFiler.Action fills
//	          the CanonicalAction's grant fields, rule_id, subject and expires_millis, on the caller's action of its
//	          kind, which the gate files as the ApprovalRequest; a grant defaults to the rule's expiresDefault, 1 h
//	activate  on a spendable decision the gate runs the grant component, AclGrantFiler.Effect: it files GrantActivate
//	          under the grant_id the approval fixes, AclGrantId(approval_id, payload_sha256), through sidecarAct, whose
//	          pending statements retry the same bytes against POST /network/config/delta until they land; the grant
//	          acts at once as a §7.9 delta, so nothing waits for an admin (owner decisions 8, 74)
//	lookup    the component's Lookup is that grant_id in the log, the rows' active rule or spent id, so a restart
//	          reconciles a use and a replay adds no second grant
//	revoke    GrantRevoke by the subject, an approver or an admin (§8.8's rule, at every verifier); bridge_close files
//	          it for a forward's grant
//
// A daemon reserves a server-gated use only until 60 s before not_after (§8.6, §16.6), so ActiveGrant holds a rule to
// AclEngineSettings.ClockSkew before its expiry. In a tainted run harness evidence counts only where the rule itself
// names it (owner decision 142), which the gate reads from AclLocalPolicy, never evidenceDefault. A gate's view of a
// grant carries no run id, agent id, recipient or preview (AD4): Grants answers only what rows hold. api counts
// tls_endpoints at activation in the delta route (§20.7; QUOTA-M4-04's model.CheckGrantActivationLimits).
// §13.10's and §17.9's callers and MCP's tools are theirs; this gives them ActiveGrant, Grants and AclGrantFiler.
//
// Of the kinds whose action carries a grant, socket_listen and tls_publish build at version 1, and bridge_forward,
// a dial or route grant, at version 4 (QD-740): its base carries the sealed_detail its caller sealed, the target's
// port inside, and the grant_dst a request gives names subjects alone. Action refuses a forward with none, as
// NewCanonicalAction does. Safe for concurrent use. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Why AclGrantFiler refused: no state installed, an action with no grant, or a grant no requests rule takes.
var ErrAclGrantFile = errors.New("acl grant filing refused")

var _ ApprovalStandingGrants = (*AclEngine)(nil)

// Whether an active grant covers the action for the spender at now: the action's grant fields (QD-064's 8, 10, 11,
// 28, 29) name the spender as subject, and each action it asks is allowed on each destination of a kind the action
// applies to (§8.4: publish on a dns host and listen on its tls/ socket, as one publish's grant asks both) by a rule or
// activated grant in force until now plus the clock skew, ports matching where the grant names one; a destination no
// asked action applies to, or an action that applies to no destination, is covered by nothing. So is an action with no
// grant fields, a route (whose prefix rides sealed_detail, which this does not open) and another network's
// destination. A version-4 action's ports ride sealed_detail too, so its ask names none, and only a rule that limits
// no ports covers it. Reads the installed state with no lock.
func (self *AclEngine) ActiveGrant(action *StoredCanonicalAction, spender Id, now time.Time) bool {
	installed := self.installed.Load()
	if installed == nil || action == nil || action.Action == nil {
		return false
	}
	ask, err := ParseAclGrantAction(action.Action)
	if err != nil || ask.Subject != spender {
		return false
	}
	// a use is reserved only until the skew before its grant ends (§16.6)
	nowMs := now.UnixMilli() + max(0, self.settings.ClockSkew.Milliseconds())
	subject := AclSidecarSubject(spender)
	appliedActions := map[protocol.AclAction]bool{}
	for _, target := range ask.Dst {
		applied := false
		for _, allow := range ask.Allow {
			if !aclGrantActionApplies(target, allow) {
				continue
			}
			applied = true
			appliedActions[allow] = true
			if !installed.covers(subject, target, allow, ask.Ports, nowMs) {
				return false
			}
		}
		if !applied {
			return false
		}
	}
	return len(appliedActions) == len(ask.Allow)
}

// Whether an action applies to a grant destination's kind (§8.4's resources): dial and route to a subject, dial and
// listen to a socket, publish and admin to a dns host, an evs action to a repo, send to mail.
func aclGrantActionApplies(target *protocol.AclTarget, action protocol.AclAction) bool {
	switch {
	case len(target.GetSidecarId()) != 0 || len(target.GetClientId()) != 0 || len(target.GetNetworkId()) != 0 || len(target.GetAtom()) != 0:
		return action == protocol.AclAction_ACL_ACTION_DIAL || action == protocol.AclAction_ACL_ACTION_ROUTE
	case len(target.GetSocketTokens()) != 0 || target.GetSocketPrefix() || strings.Contains(target.GetPublicName(), "/"):
		return action == protocol.AclAction_ACL_ACTION_DIAL || action == protocol.AclAction_ACL_ACTION_LISTEN
	case target.GetPublicName() != "":
		return action == protocol.AclAction_ACL_ACTION_PUBLISH || action == protocol.AclAction_ACL_ACTION_ADMIN
	case len(target.GetRepoId()) != 0:
		return action == protocol.AclAction_ACL_ACTION_READ || action == protocol.AclAction_ACL_ACTION_WRITE ||
			action == protocol.AclAction_ACL_ACTION_ADMIN || action == protocol.AclAction_ACL_ACTION_DEPOSIT
	case target.GetMailSend():
		return action == protocol.AclAction_ACL_ACTION_SEND
	}
	return false
}

// Whether a rule in force at nowMs allows the subject one action on one grant destination.
func (self *aclEngineInstall) covers(subject AclSubject, target *protocol.AclTarget, action protocol.AclAction, ports []*protocol.AclPortRange, nowMs int64) bool {
	state := self.state
	at := time.UnixMilli(nowMs)
	// a rule's ports take each port the grant names, or with none every port, which only a rule limiting none gives
	portsMatch := func(rule *aclRule) bool {
		if len(ports) == 0 {
			return !rule.portsLimited
		}
		for _, port := range ports {
			if !aclLocalPortsMatch(rule, self.localRules[rule.index], port.GetProtocol(), port.GetFirst()) {
				return false
			}
		}
		return true
	}
	switch {
	case len(target.GetSidecarId()) != 0 && action == protocol.AclAction_ACL_ACTION_DIAL:
		destinationId, ok := aclTargetId(target.GetSidecarId())
		return ok && state.mayDial(subject, AclSidecarSubject(destinationId), nowMs, portsMatch).Allowed
	case len(target.GetClientId()) != 0 && action == protocol.AclAction_ACL_ACTION_DIAL:
		clientId, ok := aclTargetId(target.GetClientId())
		return ok && state.mayDial(subject, AclClientSubject(clientId, Id{}, nil, ""), nowMs, portsMatch).Allowed
	case len(target.GetSocketTokens()) == 1 && action == protocol.AclAction_ACL_ACTION_DIAL:
		return state.MayDialSocket(subject, target.GetSocketTokens()[0], at).Allowed
	case len(target.GetSocketTokens()) == 1 && action == protocol.AclAction_ACL_ACTION_LISTEN:
		return state.MayListen(subject, AclSocketName{NameToken: target.GetSocketTokens()[0]}, at).Allowed
	case target.GetPublicName() != "" && action == protocol.AclAction_ACL_ACTION_LISTEN:
		return state.MayListen(subject, AclSocketName{PublicName: target.GetPublicName()}, at).Allowed
	case target.GetPublicName() != "" && action == protocol.AclAction_ACL_ACTION_PUBLISH:
		return state.MayPublish(subject, target.GetPublicName(), at).Allowed
	case target.GetPublicName() != "" && action == protocol.AclAction_ACL_ACTION_ADMIN:
		// dns:<host>'s admin, a host's zone records (§12.8)
		return state.resourceDecision(subject, nowMs, protocol.AclAction_ACL_ACTION_ADMIN, func(rule *aclRule) bool {
			return slices.ContainsFunc(rule.publicNames, func(pattern string) bool {
				return !strings.Contains(pattern, "/") && aclDnsHostCovers(pattern, target.GetPublicName())
			})
		}).Allowed
	case target.GetMailSend() && action == protocol.AclAction_ACL_ACTION_SEND:
		return state.MaySend(subject, at).Allowed
	case len(target.GetRepoId()) != 0:
		repoId, ok := aclTargetId(target.GetRepoId())
		want := map[protocol.AclAction]AclEvsRights{
			protocol.AclAction_ACL_ACTION_READ: AclEvsRead, protocol.AclAction_ACL_ACTION_WRITE: AclEvsWrite,
			protocol.AclAction_ACL_ACTION_ADMIN: AclEvsAdmin, protocol.AclAction_ACL_ACTION_DEPOSIT: AclEvsDeposit,
		}[action]
		return ok && want != 0 && state.EvsAccess(subject, repoId, AclTokenAudienceEvs, at).Rights.Has(want)
	}
	return false
}

// One grant a subject holds, as rows show it: what MCP's acl_grants lists, with no run id, agent id, recipient or
// preview (AD4).
type AclGrantInfo struct {
	// The rule's id: an activated grant's grant_id, or a document rule's id.
	GrantId []byte
	// An activated grant's requests rule; nil for a standing rule of the document.
	SourceRuleId []byte
	Actions      []protocol.AclAction
	// As rows carry them: ids, token paths and public names, never a prefix or a port.
	Targets []*protocol.AclTarget
	// ms since the epoch; 0 none.
	ExpiresMs int64
	// Whether the rule's ip field names ports, which the device's AclLocalPolicy holds.
	PortsLimited bool
}

// Every rule and activated grant in force at now whose src holds the subject, in rule id order: MCP's acl_grants data.
// The rows' own values, copied.
func (self *AclEngine) Grants(subject AclSubject, now time.Time) []AclGrantInfo {
	installed := self.installed.Load()
	if installed == nil {
		return nil
	}
	state := installed.state
	nowMs := self.checkMs(now)
	resolved := state.resolve(&subject, nowMs)
	if resolved.deny != 0 {
		return nil
	}
	grants := []AclGrantInfo{}
	for i := range state.rules {
		rule := &state.rules[i]
		if !rule.activeAt(nowMs) || !state.inSrc(&resolved, rule) {
			continue
		}
		grant := AclGrantInfo{
			GrantId:      append([]byte{}, rule.row.GetRuleId()...),
			SourceRuleId: append([]byte(nil), rule.row.GetSourceRuleId()...),
			ExpiresMs:    rule.expiresMs,
			PortsLimited: rule.portsLimited,
		}
		for action := protocol.AclAction_ACL_ACTION_DIAL; action <= aclActionMax; action += 1 {
			if rule.allows(action) {
				grant.Actions = append(grant.Actions, action)
			}
		}
		for _, target := range rule.row.GetTargets() {
			grant.Targets = append(grant.Targets, proto.Clone(target).(*protocol.AclTarget))
		}
		grants = append(grants, grant)
	}
	slices.SortStableFunc(grants, func(a AclGrantInfo, b AclGrantInfo) int { return bytes.Compare(a.GrantId, b.GrantId) })
	return grants
}

// The device's requested grants: building a grant's action, the grant component that activates it, and revoking it.
type AclGrantFiler struct {
	sidecar *Sidecar
	engine  *AclEngine
}

// A filer acting as sidecar, matching requests on engine's installed state.
func NewAclGrantFiler(sidecar *Sidecar, engine *AclEngine) *AclGrantFiler {
	return &AclGrantFiler{sidecar: sidecar, engine: engine}
}

// The grant an action asks for, before its rule is found: the destinations and actions in §8.4's grant forms
// (ParseAclGrantDst, ParseAclGrantAllow), and an expiry, 0 for the rule's default.
type AclGrantRequest struct {
	Subject    Id
	GrantDst   []string
	GrantAllow []string
	ExpiresMs  int64
}

// The CanonicalAction a grant needs (§16.8): base, the caller's action of its kind with its own fields set (a
// forward's target and port, a publish's host, port, audience, app_mode and pin), with the grant's fields filled from
// the requests rule MatchAclRequest finds at the installed state: rule_id, subject, grant_dst, grant_allow and
// expires_millis. Built through NewCanonicalAction, which holds it to its kind's row.
func (self *AclGrantFiler) Action(base *protocol.CanonicalAction, request *AclGrantRequest, now time.Time) (*StoredCanonicalAction, error) {
	state := self.engine.State()
	if state == nil {
		return nil, fmt.Errorf("%w: no state installed", ErrAclGrantFile)
	}
	if base == nil || request == nil {
		return nil, fmt.Errorf("%w: no action", ErrAclGrantFile)
	}
	action := proto.Clone(base).(*protocol.CanonicalAction)
	action.Subject = request.Subject.Bytes()
	action.GrantDst = slices.Clone(request.GrantDst)
	action.GrantAllow = slices.Clone(request.GrantAllow)
	action.ExpiresMillis = request.ExpiresMs
	// a rule id of the right size for the parse; the match fills the real one
	action.RuleId = make([]byte, aclAtomByteCount)
	ask, err := ParseAclGrantAction(action)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAclGrantFile, err)
	}
	ask.RuleId = nil
	match, err := MatchAclRequest(state, ask, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAclGrantFile, err)
	}
	action.RuleId = append([]byte{}, match.Rule.GetRuleId()...)
	action.ExpiresMillis = match.ExpiresMs
	return NewCanonicalAction(action)
}

// The grant component of action (§16.6): the effect the gate runs on a spendable decision.
func (self *AclGrantFiler) Effect(action *StoredCanonicalAction) SidecarEffect {
	return &aclGrantEffect{filer: self, action: action}
}

// The grant component's effect for one action.
type aclGrantEffect struct {
	filer  *AclGrantFiler
	action *StoredCanonicalAction
}

// Files the GrantActivate the spend in ctx fixes, under its grant_id, and answers that id; under a standing grant, an
// empty key, there is nothing to file and nothing done. A grant the log already holds is done again with no filing, so
// a retry of a lost answer adds none. A post whose answer was lost stays pending and is retried with the same bytes,
// so it answers uncertain.
func (self *aclGrantEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	if len(effectKey) == 0 {
		return nil, nil
	}
	spend, ok := ApprovalSpendFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: %w: no spend to file a grant under", ErrSidecarEffectNotDone, ErrAclGrantFile)
	}
	grantId := AclGrantId(spend.ApprovalId, sha256.Sum256(spend.Action))
	if self.filer.held(grantId[:]) {
		return grantId[:], nil
	}
	activate := &protocol.GrantActivate{GrantId: grantId[:], CanonicalAction: append([]byte{}, self.action.Bytes...)}
	for _, decisionBytes := range spend.Decisions {
		decision := &bridge.Signed{}
		if err := proto.Unmarshal(decisionBytes, decision); err != nil {
			return nil, fmt.Errorf("%w: %w: a decision that is no Signed", ErrSidecarEffectNotDone, ErrAclGrantFile)
		}
		activate.Decisions = append(activate.Decisions, decision)
	}
	act, err := self.filer.sidecar.newAct(SidecarActUnconfirmed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	testHookBarrier("acl_grant_file.activate.before", "")
	_, err = act.Run(ctx, nil)
	testHookBarrier("acl_grant_file.activate.after", "")
	if err != nil {
		if self.filer.held(grantId[:]) {
			return grantId[:], nil
		}
		return nil, err
	}
	return grantId[:], nil
}

// Whether the installed state holds a grant_id: an active rule, or a spent id, which every activation and revocation
// leaves (plan-ACL-folded-grant-state #3).
func (self *AclGrantFiler) held(grantId []byte) bool {
	state := self.engine.State()
	if state == nil {
		return false
	}
	if state.spentGrant(grantId) != nil {
		return true
	}
	return slices.ContainsFunc(state.rules, func(rule aclRule) bool { return bytes.Equal(rule.row.GetRuleId(), grantId) })
}

// The grant component's Lookup (§16.6), from the stored action and the spend the gate carries in ctx: done with the
// grant_id once the log holds it, uncertain while it does not, since a pending post may still land.
func (self *AclGrantFiler) Lookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	spend, ok := ApprovalSpendFromContext(ctx)
	if !ok || len(effectKey) == 0 {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	grantId := AclGrantId(spend.ApprovalId, sha256.Sum256(spend.Action))
	if self.held(grantId[:]) {
		return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: grantId[:]}, nil
	}
	return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
}

// Registers the grant component's Lookup for the kinds whose action activates a grant: bridge_forward, socket_listen
// and tls_publish. The answer removes them.
func (self *AclGrantFiler) Register() func() {
	removes := []func(){}
	for _, kind := range []SidecarActionKind{SidecarActionForward, SidecarActionListen, SidecarActionPublish} {
		removes = append(removes, self.sidecar.RegisterEffectLookup(kind, self.Lookup))
	}
	return func() {
		for _, remove := range removes {
			remove()
		}
	}
}

// Files GrantRevoke of grantId, as a grant's subject, an approver or an admin may (§8.8, whose rule every verifier
// judges): bridge_close's for a forward's grant, an own-resource filing from any mode, the person's confirmation for
// the rest. It answers once the revoke lands, or with why not.
func (self *AclGrantFiler) Revoke(ctx context.Context, grantId []byte, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if len(grantId) != sha256.Size {
		return fmt.Errorf("%w: a grant_id of %d bytes", ErrAclGrantFile, len(grantId))
	}
	act, err := self.sidecar.newAct(origin)
	if err != nil {
		return err
	}
	if err := act.Add(bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{GrantId: append([]byte{}, grantId...)}); err != nil {
		return err
	}
	_, err = act.Run(ctx, check)
	return err
}
