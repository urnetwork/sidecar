//go:build !ios_extension

// §8.6's requested grants on the device (ACL-M4-02; R-ACL-4, R-ACL-5, D-ACL-7, D-ACL-23, I-8, I-9, D-CTX-5): the flow
// behind Sidecar.Authorize for an action a grant must cover.
//
//	active    under an active grant Authorize passes with no decision (§16.6's step 2, untainted runs only, TS1):
//	          AclEngine.ActiveGrant, which MCP's ApprovalGate reads as its ApprovalStandingGrants, and for a bridge
//	          exposure, whose action names no grant, AclEngine.StandingRule over the rule it files, its
//	          ApprovalStandingRules (record_gate_standing.go)
//	request   otherwise MatchAclRequest finds the requests rule at the installed state, and AclGrantFiler.Action fills
//	          the CanonicalAction's grant fields, rule_id, subject and expires_millis, on the caller's action of its
//	          kind, and only then seals a dial or route grant's detail beside them, which the gate files as the
//	          ApprovalRequest; a grant defaults to the rule's expiresDefault, 1 h
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
// §13.10's and §17.9's callers and MCP's tools are theirs; this gives them ActiveGrant, StandingRule, Grants and
// AclGrantFiler.
//
// Of the kinds whose action carries a grant, socket_listen and tls_publish build at version 1, and bridge_forward,
// a dial or route grant, at version 4 (QD-740): its request carries the detail, the target's port inside, which the
// filer's device seals into sealed_detail once the grant's clear fields are filled, bound to them (QD-771;
// CanonicalActionDetailSealer, the sidecar's by default), and the grant_dst a request gives names subjects alone.
// Action refuses a forward with no detail, as NewCanonicalAction does, and a base sealed already, whose seal binds no
// field the filer fills. Safe for concurrent use. Nothing here creates, derives or unwraps a key: the sealer derives a
// detail's (Sidecar.SealActionDetail).

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

var _ ApprovalStandingRules = (*AclEngine)(nil)

// Whether a rule the spender files with no approval, a bridge exposure's route or map (§17.7, §17.8's approval row),
// stands under the installed state and local policy for the spender, by the predicate every reader holds such a rule
// in force by (AclLocalPolicy.StandingCovers), so §16.6's gate passes the exposure with nothing filed. As ActiveGrant
// holds a grant, the rule must still stand at now plus the clock skew, which only narrows: a standing rule's expiry and
// the owner's admission both end in time, so a cover that ends within the skew asks a person instead. A rule another
// sidecar owns covers nothing here, and nothing installed covers nothing. Reads the installed state with no lock.
func (self *AclEngine) StandingRule(rule *BridgeLedgerRule, spender Id, now time.Time) bool {
	installed := self.installed.Load()
	if installed == nil || rule == nil || rule.Owner != spender {
		return false
	}
	return installed.local.StandingCovers(installed.state, rule, now.Add(max(0, self.settings.ClockSkew)))
}

// Whether an active grant covers the action for the spender at now: the action's grant fields (QD-064's 8, 10, 11,
// 28, 29) name the spender as subject, and each action it asks is allowed on each destination of a kind the action
// applies to (§8.4: publish on a dns host and listen on its tls/ socket, as one publish's grant asks both) by a rule or
// activated grant in force until now plus the clock skew, ports matching where the grant names one; a destination no
// asked action applies to, or an action that applies to no destination, is covered by nothing. So is an action with no
// grant fields, a route (whose prefixes ride sealed_detail, which this reads for ports alone) and another network's
// destination. A version-4 action's ports ride sealed_detail too (QD-740): its ask at each sidecar is the ports its
// detail names there, read by the dial reader the engine reads an activated dial grant by (aclGrantDialPortsOf), its
// detail opened in the state's network under the config keys the installed opener holds (aclActionDetails); a detail
// that does not open here, naming no port at a sidecar, or an opener that cannot open an action, asks every port
// there, which only a rule limiting none covers, the closed direction. A rule's ports take an asked port as AllowInbound
// and the host's dial rows read them: a document rule's its local detail, a port-limited activated dial grant's the
// ports its sealed detail names at that sidecar, as InstallWithGrants read it (QD-1428, owner decision 804), so a
// forward asked again once its own grant is in force, or one another grant covers, passes on that grant (§16.6's step
// 2). A share's grant (QD-820) is covered by none: its inbound half is another network's reach, not
// the spender's, so the spender's own standing reach to the same sidecars says nothing of it, and each share is its
// own admin-approved activation (§8.11). A listen or a publish that no requests rule takes names no rule_id
// (socket_listen.go, socket_listen_grant.go, tls_publish.go): what covers a grant is its subject, destinations and
// actions, never the rule it would be requested under, so such an action is judged on those alone, and only a
// standing grant can cover it. A publish binds its audience, app mode and a raw link's pin besides, which the
// listener's front enforces from the grant (§8.10, §13.7): only a grant that gives exactly those, by PublishGrant's
// agreement rule, covers it (acl_grant_publish.go), so a publish never passes on a grant that would serve it to
// another audience than it asked. Reads the installed state with no lock; a version-4 action's detail is opened here,
// testHookSecret running where its key derives, inside OpenConfigBody, which no packet path reaches.
func (self *AclEngine) ActiveGrant(action *StoredCanonicalAction, spender Id, now time.Time) bool {
	installed := self.installed.Load()
	if installed == nil || action == nil || action.Action == nil {
		return false
	}
	grantAction := action.Action
	kind := SidecarActionKind(grantAction.GetKind())
	if (kind == SidecarActionListen || kind == SidecarActionPublish) && len(grantAction.GetRuleId()) == 0 {
		// a rule id of the right size for the parse alone, as Action's ask takes one; coverage never reads it
		grantAction = proto.Clone(grantAction).(*protocol.CanonicalAction)
		grantAction.RuleId = make([]byte, aclAtomByteCount)
	}
	ask, err := ParseAclGrantAction(grantAction)
	if err != nil || ask.Subject != spender || ask.share() {
		return false
	}
	// a use is reserved only until the skew before its grant ends (§16.6)
	nowMs := now.UnixMilli() + max(0, self.settings.ClockSkew.Milliseconds())
	subject := AclSidecarSubject(spender)
	asked := installed.askedPorts(action, ask)
	appliedActions := map[protocol.AclAction]bool{}
	for _, target := range ask.Dst {
		applied := false
		for _, allow := range ask.Allow {
			if !aclGrantActionApplies(target, allow) {
				continue
			}
			applied = true
			appliedActions[allow] = true
			if !installed.covers(subject, target, allow, asked.at(target), nowMs) {
				return false
			}
		}
		if !applied {
			return false
		}
	}
	if len(appliedActions) != len(ask.Allow) {
		return false
	}
	if kind == SidecarActionPublish {
		// acl_grant_publish.go, and acl_grant_publish_http.go on the page Worker's leg, which publishes nothing
		return installed.publishAgrees(subject, grantAction, nowMs)
	}
	return true
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

// An opener of the state's activated grants' details that also opens an action's own sealed detail, in the state's
// network under the same config keys: aclStateGrantDetails, which the acl follower installs with
// (newAclStateGrantDetails). ActiveGrant reads a forward's asked ports through it; an opener without it opens no
// action, so a forward asks every port.
type aclActionDetails interface {
	actionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error)
}

var _ aclActionDetails = (*aclStateGrantDetails)(nil)

// Opens action's own sealed detail in the state's network under the keys repoKeyAt answers, held to the action
// (OpenCanonicalActionDetail): nil with no error for an action that seals none. testHookSecret runs where the detail's
// key derives, inside OpenConfigBody.
func (self *aclStateGrantDetails) actionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error) {
	return OpenCanonicalActionDetail(action, self.networkId, self.repoKeyAt)
}

// The ports a grant's action asks at each of its destinations (ActiveGrant's comment): for an action that seals a
// detail, the ports the opened detail names at each sidecar, by the dial reader (aclGrantDialPortsOf); otherwise the
// ports its clear grant_dst names, which apply to every destination and which no action builds since QD-740.
type aclAskedPorts struct {
	// whether the ports are the detail's
	sealed bool
	// the detail's ports by sidecar, none where the detail does not open here
	dial aclGrantDialPorts
	// the clear grant_dst's, for an action sealing no detail
	clear []*protocol.AclPortRange
}

// The ports action asks, given its ask: its sealed detail's where it seals one, opened through the installed opener
// where that opens actions (aclActionDetails), and none, every port, where the detail does not open here.
func (self *aclEngineInstall) askedPorts(action *StoredCanonicalAction, ask *AclGrantAsk) aclAskedPorts {
	if len(action.Action.GetSealedDetail()) == 0 {
		return aclAskedPorts{clear: ask.Ports}
	}
	asked := aclAskedPorts{sealed: true}
	opener, ok := self.grants.(aclActionDetails)
	if !ok {
		return asked
	}
	detail, err := opener.actionDetail(action)
	if err != nil || detail == nil {
		return asked
	}
	asked.dial = aclGrantDialPortsOf(detail)
	return asked
}

// The ports asked at one grant destination: a sealed detail's at a sidecar it names a port at, none, every port,
// anywhere else; the clear ones at every destination.
func (self aclAskedPorts) at(target *protocol.AclTarget) []*protocol.AclPortRange {
	if !self.sealed {
		return self.clear
	}
	sidecarId, ok := aclTargetId(target.GetSidecarId())
	if !ok {
		return nil
	}
	ports := []*protocol.AclPortRange{}
	for _, dialPort := range self.dial {
		if dialPort.sidecarId == sidecarId {
			ports = append(ports, &protocol.AclPortRange{Protocol: dialPort.ports.Protocol, First: dialPort.ports.First, Last: dialPort.ports.Last})
		}
	}
	if len(ports) == 0 {
		return nil
	}
	return ports
}

// Whether a rule in force at nowMs allows the subject one action on one grant destination, the ports asked there each
// taken where ports is not empty.
func (self *aclEngineInstall) covers(subject AclSubject, target *protocol.AclTarget, action protocol.AclAction, ports []*protocol.AclPortRange, nowMs int64) bool {
	state := self.state
	at := time.UnixMilli(nowMs)
	// a rule's ports at the destination take each port the grant names, a single port by §8.4's grammar, or with none
	// every port, which only a rule limiting none gives: a document rule's ports are its local detail's, and a
	// port-limited activated dial grant's those its sealed detail names at that destination, as InstallWithGrants read
	// them and as AllowInbound and the host's dial rows take them (aclGrantDialPorts)
	portsMatch := func(destination AclSubject) func(rule *aclRule) bool {
		return func(rule *aclRule) bool {
			if len(ports) == 0 {
				return !rule.portsLimited
			}
			read := self.grantDials[rule.index]
			for _, port := range ports {
				if read != nil {
					if destination.Kind != AclSubjectSidecar || !read.dial.takes(destination.Id, port.GetProtocol(), port.GetFirst()) {
						return false
					}
					continue
				}
				if !aclLocalPortsMatch(rule.portsLimited, self.localRules[rule.index], port.GetProtocol(), port.GetFirst()) {
					return false
				}
			}
			return true
		}
	}
	switch {
	case len(target.GetSidecarId()) != 0 && action == protocol.AclAction_ACL_ACTION_DIAL:
		destinationId, ok := aclTargetId(target.GetSidecarId())
		destination := AclSidecarSubject(destinationId)
		return ok && state.mayDial(subject, destination, nowMs, portsMatch(destination)).Allowed
	case len(target.GetClientId()) != 0 && action == protocol.AclAction_ACL_ACTION_DIAL:
		clientId, ok := aclTargetId(target.GetClientId())
		destination := AclClientSubject(clientId, Id{}, nil, "")
		return ok && state.mayDial(subject, destination, nowMs, portsMatch(destination)).Allowed
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
	// seals a dial or route grant's detail once its clear fields are filled; nil seals none
	details CanonicalActionDetailSealer
}

// A filer acting as sidecar, matching requests on engine's installed state and sealing a grant's detail on sidecar
// (Sidecar.SealActionDetail).
func NewAclGrantFiler(sidecar *Sidecar, engine *AclEngine) *AclGrantFiler {
	filer := &AclGrantFiler{sidecar: sidecar, engine: engine}
	if sidecar != nil {
		filer.details = sidecar
	}
	return filer
}

// The grant an action asks for, before its rule is found: the destinations and actions in §8.4's grant forms
// (ParseAclGrantDst, ParseAclGrantAllow), an expiry, 0 for the rule's default, and a dial or route grant's detail.
type AclGrantRequest struct {
	Subject    Id
	GrantDst   []string
	GrantAllow []string
	ExpiresMs  int64
	// A dial or route grant's prefixes and ports (QD-740), which the filer seals into the action's sealed_detail once
	// the grant's clear fields are filled (QD-771); nil for a grant that seals nothing.
	Detail *protocol.CanonicalActionDetail
	// A share's other network (§8.11; QD-820), which the action names in share_network_id; the zero id for a grant
	// that is no share. GrantDst then names this network's own resources, or that network alone (acl_request.go).
	ShareNetworkId Id
}

// The CanonicalAction a grant needs (§16.8): base, the caller's action of its kind with its own fields set (a
// publish's host, port, audience, app_mode and pin), with the grant's fields filled from the requests rule
// MatchAclRequest finds at the installed state: rule_id, subject, grant_dst, grant_allow and expires_millis, and a
// share's share_network_id, which is the request's alone to name, never the base's. A dial or
// route grant's request.Detail is sealed only then, beside those final fields, by the filer's sealer
// (NewSealedCanonicalAction); a base that carries a sealed_detail already is refused, since its seal binds none of
// them. Built through NewCanonicalAction or NewSealedCanonicalAction, which hold it to its kind's row.
func (self *AclGrantFiler) Action(ctx context.Context, base *protocol.CanonicalAction, request *AclGrantRequest, now time.Time) (*StoredCanonicalAction, error) {
	state := self.engine.State()
	if state == nil {
		return nil, fmt.Errorf("%w: no state installed", ErrAclGrantFile)
	}
	if base == nil || request == nil {
		return nil, fmt.Errorf("%w: no action", ErrAclGrantFile)
	}
	if len(base.GetSealedDetail()) != 0 {
		return nil, fmt.Errorf("%w: a sealed_detail sealed before the grant's fields were filled: %w", ErrAclGrantFile, ErrCanonicalActionInvalid)
	}
	action := proto.Clone(base).(*protocol.CanonicalAction)
	action.Subject = request.Subject.Bytes()
	action.GrantDst = slices.Clone(request.GrantDst)
	action.GrantAllow = slices.Clone(request.GrantAllow)
	action.ExpiresMillis = request.ExpiresMs
	action.ShareNetworkId = nil
	if request.ShareNetworkId != (Id{}) {
		action.ShareNetworkId = request.ShareNetworkId.Bytes()
	}
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
	if request.Detail == nil {
		return NewCanonicalAction(action)
	}
	// the clear fields are final, so the detail is sealed beside them now
	if self.details == nil {
		return nil, fmt.Errorf("%w: no device here seals a grant's detail", ErrAclGrantFile)
	}
	return self.details.SealActionDetail(ctx, action, request.Detail)
}

// The grant component of action (§16.6): the effect the gate runs on a spendable decision.
func (self *AclGrantFiler) Effect(action *StoredCanonicalAction) SidecarEffect {
	return &aclGrantEffect{filer: self, action: action}
}

// The grant component's effect for one action.
type aclGrantEffect struct {
	filer  *AclGrantFiler
	action *StoredCanonicalAction
	// When set, a newly posted grant must also be confirmed at its receipt.
	confirm func(context.Context, *bridge.AuthPin, []byte, []byte) error
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
	pins, err := act.Run(ctx, nil)
	testHookBarrier("acl_grant_file.activate.after", "")
	if err != nil {
		if self.filer.held(grantId[:]) {
			return grantId[:], nil
		}
		return nil, err
	}
	if self.confirm != nil {
		var pin *bridge.AuthPin
		if len(pins) == 1 {
			pin = pins[0]
		}
		if err := self.confirm(ctx, pin, act.Signed()[0], grantId[:]); err != nil {
			return nil, err
		}
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
