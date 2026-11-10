// §8.8's GrantActivate: a requested grant activated by its approvals, as a §7.9 delta any admitted sidecar may file,
// its authority only from the ApprovalDecisions it embeds (D-ACL-7, owner decisions 74, 75, 142, 180). api's verifier
// and every reader run the four checks alike, at the statement's position:
//
//	grant_id  SHA-256("urnetwork-sidecar-v1/grant" || approval_id || payload_sha256), fixed by the approval
//	match     SHA-256(canonical_action) is every decision's payload_sha256, and the action's subject every
//	          decision's requester_sidecar_id; the decisions share one approval_id and request_sha256
//	quorum    k distinct approvers the matching requests rule names (autogroup:dst-owner resolved from grant_dst at
//	          the position), each approving, on a channel the rule's evidence lists, unexpired at the entry's time
//	          within §8.6's 60 s skew, and passing §16.6's spend check (AclSpendCheck); and §8.6's admin clause
//	refuse    a grant_id in spent_grants or in an active rule, or one a GrantRevoke named
//	          (plan-ACL-folded-grant-state #3)
//
// The admin clause: a grant touching another member's devices, a share or autogroup:public needs an admin's approval
// whatever the rule says, except that a touched member who approves as autogroup:dst-owner meets it for reach to a
// device it owns or sponsors (owner decision 180). An admin's approval counts toward k there even where the rule
// names no admin.
//
// A GrantActivate folds to an AclRule (plan-ACL-folded-grant-state #2): rule_id the grant_id, src its subject's
// sidecar atom, targets and actions from grant_dst and grant_allow, ports_limited when grant_dst names a port, whose
// value stays out of rows (plan-BRIDGE-gate-row-prefixes #1), expires the matching rule's lifetime, a publish's audience, app_mode and pin, and source_rule_id the requests rule, whose deletion by a
// later config head ends the grant at that base for every reader (FS-14). Its grant_id enters spent_grants until the
// latest of its decisions' not_after_millis plus 60 s, so a re-signed GrantActivate under a fresh header is refused
// for as long as any of its decisions could spend.
//
// Harness evidence in a tainted run needs the rule itself to name harness, which only the signing daemon's harness_ok
// checks from AclLocalPolicy (owner decision 142); rows hold the effective evidence list, and gates check the channel
// against it.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §8.6's clock skew between a gate's server time and a decision's not_after, which also pads a spent grant_id's
// retention (plan-ACL-folded-grant-state #3): a protocol value every reader holds alike.
const aclDecisionSkewMs = int64(60 * 1000)

// The domain of grant_id (§8.8).
const aclGrantIdDomain = "urnetwork-sidecar-v1/grant"

// The spend check is not installed, so no decision spends (MCP-M3-03).
var ErrAclSpendCheckUnbuilt = fmt.Errorf("%w: §16.6's spend check is not installed", ErrConfigRuleMissing)

// grant_id = SHA-256("urnetwork-sidecar-v1/grant" || approval_id || payload_sha256), which an approval fixes, so one
// approval activates at most one grant (§8.8, D-MCP-12's AD2).
func AclGrantId(approvalId Id, payloadSha256 [sha256.Size]byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(aclGrantIdDomain))
	hash.Write(approvalId[:])
	hash.Write(payloadSha256[:])
	var grantId [sha256.Size]byte
	hash.Sum(grantId[:0])
	return grantId
}

// §16.6's spend check, spendable(d, a, s, P), on one decision a GrantActivate embeds: d verifies under its signer's
// key and that signer fits d.channel (an approval-capable device of d.approver_member_id other than s, a presence key
// registered to that member, or s itself under harness_ok); d.requester_sidecar_id is s; d.payload_sha256 is
// SHA-256(a); now is within d.not_after_millis and §8.6's skew; d.auth_pin is at or below P and on its chain where
// P's state retains that position; and under P the approver is still eligible and d.channel in the governing
// evidence list. state is S(n-1), the state the GrantActivate lands on, pin its (n-1, A_{n-1}) and now the entry's
// time. MCP-M3-03 implements it; a gate and every reader install the same one. Safe for concurrent use.
type AclSpendCheck interface {
	Spendable(state *AclState, decision *StoredApprovalDecision, action *StoredCanonicalAction, spender Id, pin *bridge.AuthPin, now time.Time) error
}

// Refuses every decision, so no GrantActivate takes effect until §16.6's check is installed.
type AclSpendCheckUnbuilt struct{}

// ErrAclSpendCheckUnbuilt.
func (self AclSpendCheckUnbuilt) Spendable(state *AclState, decision *StoredApprovalDecision, action *StoredCanonicalAction, spender Id, pin *bridge.AuthPin, now time.Time) error {
	return ErrAclSpendCheckUnbuilt
}

// What a GrantActivate folds to.
type aclGrantFold struct {
	grantId []byte
	// the AclRule, rule_id the grant_id
	rule *protocol.AclRule
	// the subject's sidecar atom, which rows lacking it gain, a new base's included
	atom *protocol.AclAtom
	// AclSpentGrant.retain_until_ms
	retainUntilMs int64
}

// §8.8's four checks on a GrantActivate at this state, S(n-1), and what it folds to. spendCheck nil refuses every
// decision.
func (self *AclState) CheckGrantActivate(statement *AclStatement, spendCheck AclSpendCheck) (*AclStatementVerdict, error) {
	if spendCheck == nil {
		spendCheck = AclSpendCheckUnbuilt{}
	}
	activate, ok := statement.Body.(*protocol.GrantActivate)
	if !ok || statement.Type != bridge.SignedType_SIGNED_GRANT_ACTIVATE {
		return nil, fmt.Errorf("%w: no GrantActivate", ErrConfigRule)
	}
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	action, err := ParseStoredCanonicalAction(activate.GetCanonicalAction())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	if err := CheckCanonicalActionForServer(action); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	ask, err := ParseAclGrantAction(action.Action)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	decisions, approvalId, err := aclGrantDecisions(activate, action, ask.Subject)
	if err != nil {
		return nil, err
	}

	// grant_id, then refuse
	grantId := AclGrantId(approvalId, action.PayloadSha256())
	if !bytes.Equal(activate.GetGrantId(), grantId[:]) {
		return nil, fmt.Errorf("%w: a grant_id the approval does not fix", ErrConfigRule)
	}
	if self.spentGrant(grantId[:]) != nil || self.grantRule(grantId[:]) != nil {
		return nil, fmt.Errorf("%w: a grant_id already in the log", ErrConfigReplay)
	}

	now := aclTime(statement.TimeMs)
	match, err := MatchAclRequest(self, ask, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigAuthority, err)
	}
	if err := self.grantQuorum(statement, match.Rule, ask, action, decisions, spendCheck); err != nil {
		return nil, err
	}

	atomId := AclDerivedAtom(AclDerivedAtomSidecar, ask.Subject.Bytes())
	fold := &aclGrantFold{
		grantId: grantId[:],
		rule: &protocol.AclRule{
			RuleId:       grantId[:],
			SrcAtoms:     [][]byte{atomId.Bytes()},
			Targets:      ask.Dst,
			PortsLimited: 0 < len(ask.Ports),
			Expires:      match.ExpiresMs,
			SourceRuleId: bytes.Clone(match.Rule.GetRuleId()),
		},
	}
	for _, allow := range ask.Allow {
		fold.rule.Actions = append(fold.rule.Actions, uint32(allow))
	}
	if slices.Contains(ask.Allow, protocol.AclAction_ACL_ACTION_PUBLISH) {
		fold.rule.Audience = protocol.AclAudience(action.Action.GetAudience())
		fold.rule.AppMode = protocol.AclAppMode(action.Action.GetAppMode())
		fold.rule.LinkSpkiSha256 = bytes.Clone(action.Action.GetLinkSpkiSha256())
	}
	if _, found := self.atomIndexes[atomId]; !found && aclRowsMaxAtomCount <= len(self.rows.GetAtoms()) {
		return nil, fmt.Errorf("%w: the rows hold %d atoms already", ErrConfigRule, aclRowsMaxAtomCount)
	}
	fold.atom = &protocol.AclAtom{Atom: atomId.Bytes(), SidecarIds: [][]byte{ask.Subject.Bytes()}}
	for _, decision := range decisions {
		fold.retainUntilMs = max(fold.retainUntilMs, decision.Decision.GetNotAfterMillis()+aclDecisionSkewMs)
	}
	return &AclStatementVerdict{Signer: signer.id, grant: fold}, nil
}

// The decisions a GrantActivate embeds, parsed, each an approval naming the action's bytes and its subject (match),
// all of one approval and one request, and their approval_id.
func aclGrantDecisions(activate *protocol.GrantActivate, action *StoredCanonicalAction, subjectId Id) ([]*StoredApprovalDecision, Id, error) {
	if len(activate.GetDecisions()) == 0 {
		return nil, Id{}, fmt.Errorf("%w: a GrantActivate with no decision", ErrConfigRule)
	}
	payloadSha256 := action.PayloadSha256()
	decisions := []*StoredApprovalDecision{}
	for _, signed := range activate.GetDecisions() {
		decision, err := ParseSignedApprovalDecision(signed)
		if err != nil {
			return nil, Id{}, fmt.Errorf("%w: %w", ErrConfigRule, err)
		}
		body := decision.Decision
		switch {
		case protocol.ApprovalVerdict(body.GetDecision()) != protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE:
			return nil, Id{}, fmt.Errorf("%w: a decision that does not approve", ErrConfigRule)
		case !bytes.Equal(body.GetPayloadSha256(), payloadSha256[:]):
			return nil, Id{}, fmt.Errorf("%w: a decision for another action", ErrConfigRule)
		case !bytes.Equal(body.GetRequesterSidecarId(), subjectId.Bytes()):
			return nil, Id{}, fmt.Errorf("%w: a decision for another requester", ErrConfigRule)
		}
		if 0 < len(decisions) {
			first := decisions[0].Decision
			if !bytes.Equal(body.GetApprovalId(), first.GetApprovalId()) || !bytes.Equal(body.GetRequestSha256(), first.GetRequestSha256()) {
				return nil, Id{}, fmt.Errorf("%w: decisions of more than one request", ErrConfigRule)
			}
		}
		decisions = append(decisions, decision)
	}
	return decisions, Id(decisions[0].Decision.GetApprovalId()), nil
}

// Whether a member acts as an admin approver: an Owner or Admin, autogroup:admin's roles.
func (self *AclState) memberAdmin(memberId Id) bool {
	member := self.view.Member(memberId)
	return member != nil && aclRoleAutogroups(member.GetRole())&aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN) != 0
}

// §8.6's admin clause for an ask: whether only an admin meets it (a share, autogroup:public, or a destination whose
// owner the rows cannot tell), and the other members whose devices it reaches.
func (self *AclState) grantTouches(ask *AclGrantAsk, audience protocol.AclAudience, nowMs int64) (adminOnly bool, touchedMemberIds []Id) {
	requester := self.sidecarState(ask.Subject)
	touch := func(destination *aclSidecarState) {
		switch {
		case !destination.hasOwner:
			adminOnly = true
		case !requester.hasOwner || destination.owner != requester.owner:
			if !slices.Contains(touchedMemberIds, destination.owner) {
				touchedMemberIds = append(touchedMemberIds, destination.owner)
			}
		}
	}
	if audience == protocol.AclAudience_ACL_AUDIENCE_PUBLIC {
		adminOnly = true
	}
	for _, target := range ask.Dst {
		switch {
		case len(target.GetSidecarId()) != 0:
			destinationId, ok := aclTargetId(target.GetSidecarId())
			destination := self.sidecarState(destinationId)
			if !ok || destination == nil || !destination.valid {
				adminOnly = true
				continue
			}
			touch(destination)
		case len(target.GetSocketTokens()) != 0:
			socket := aclSocketTarget{tokenPaths: target.GetSocketTokens()}
			for i := range self.sidecars {
				listener := &self.sidecars[i]
				if listener.hardDeny(nowMs) == 0 && self.sidecarListensOnTarget(listener, &socket, nowMs) {
					touch(listener)
				}
			}
		case len(target.GetNetworkId()) != 0, len(target.GetClientId()) != 0, len(target.GetAtom()) != 0:
			// a share, a client whose owner rows do not hold, or an atom of many subjects
			adminOnly = true
		}
	}
	return adminOnly, touchedMemberIds
}

// quorum: k distinct eligible approvers, each decision on an evidence channel, unexpired and spendable, and §8.6's
// admin clause.
func (self *AclState) grantQuorum(statement *AclStatement, rule *protocol.AclRequestRule, ask *AclGrantAsk, action *StoredCanonicalAction,
	decisions []*StoredApprovalDecision, spendCheck AclSpendCheck) error {
	now := aclTime(statement.TimeMs)
	subject := AclSidecarSubject(ask.Subject)
	approvers := self.ResolveApprovers(rule.GetApproverAtoms(), subject, ask.Dst, now)
	required := max(1, int(rule.GetApprovers()))
	evidence := rule.GetEvidence()
	if len(evidence) == 0 {
		// the format's default, all three channels (§8.8's AclRequestRule)
		evidence = []uint32{uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE), uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE),
			uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS)}
	}
	adminOnly, touchedMemberIds := self.grantTouches(ask, protocol.AclAudience(action.Action.GetAudience()), statement.TimeMs)
	adminNeeded := adminOnly || 0 < len(touchedMemberIds)

	counted := []Id{}
	adminApproved := false
	var spendError error
	for _, decision := range decisions {
		body := decision.Decision
		memberId := Id(body.GetApproverMemberId())
		if !slices.Contains(evidence, body.GetChannel()) || body.GetNotAfterMillis()+aclDecisionSkewMs < statement.TimeMs ||
			slices.Contains(counted, memberId) {
			continue
		}
		admin := self.memberAdmin(memberId)
		if !self.Approves(approvers, memberId) && !(adminNeeded && admin) {
			continue
		}
		if err := spendCheck.Spendable(self, decision, action, ask.Subject, self.pin, now); err != nil {
			spendError = err
			continue
		}
		counted = append(counted, memberId)
		adminApproved = adminApproved || admin
	}
	if len(counted) < required {
		if spendError != nil {
			return fmt.Errorf("%w: %d of %d approvers spend: %w", ErrConfigAuthority, len(counted), required, spendError)
		}
		return fmt.Errorf("%w: %d of %d approvers", ErrConfigAuthority, len(counted), required)
	}
	if !adminNeeded || adminApproved {
		return nil
	}
	// a touched member approving as autogroup:dst-owner meets the clause for reach to its own devices
	if !adminOnly && self.dstOwnerApproved(rule, ask, touchedMemberIds, counted, now) {
		return nil
	}
	return fmt.Errorf("%w: a grant touching others needs an admin's approval", ErrConfigAuthority)
}

// Owner decision 180's exception: a reach grant (dial or route only) whose one touched member is the destinations'
// one owner, autogroup:dst-owner in the rule's approvers, and that member among those who approved.
func (self *AclState) dstOwnerApproved(rule *protocol.AclRequestRule, ask *AclGrantAsk, touchedMemberIds []Id, counted []Id, now time.Time) bool {
	for _, action := range ask.Allow {
		if action != protocol.AclAction_ACL_ACTION_DIAL && action != protocol.AclAction_ACL_ACTION_ROUTE {
			return false
		}
	}
	dstOwnerAtom := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER)
	if !slices.ContainsFunc(rule.GetApproverAtoms(), func(atom []byte) bool { return bytes.Equal(atom, dstOwnerAtom.Bytes()) }) {
		return false
	}
	owner, ok := self.destinationOwner(ask.Dst, now)
	return ok && len(touchedMemberIds) == 1 && touchedMemberIds[0] == owner && slices.Contains(counted, owner)
}

// Why a GrantActivate's fold does not take over a new base: the requests rule it came from is gone (FS-14).
var errAclGrantRuleGone = errors.New("the grant's requests rule is gone")

// GrantActivate's fold: its AclRule, its subject's atom when the rows lack one, and its grant_id spent. Over a new base
// whose head deleted the requests rule, the grant ends there and folds nothing.
func aclFoldGrantActivate(rows *protocol.AclRows, verdict *AclStatementVerdict, reapply bool) (*protocol.AclRows, error) {
	fold := verdict.grant
	if fold == nil {
		return nil, fmt.Errorf("%w: a GrantActivate folded without its check", ErrConfigRule)
	}
	if reapply && !slices.ContainsFunc(rows.GetRequests(), func(request *protocol.AclRequestRule) bool {
		return bytes.Equal(request.GetRuleId(), fold.rule.GetSourceRuleId())
	}) {
		return nil, fmt.Errorf("%w: %w", ErrConfigRule, errAclGrantRuleGone)
	}
	next := aclRowsCopy(rows)
	if !slices.ContainsFunc(rows.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), fold.grantId) }) {
		next.Rules = append(slices.Clone(rows.GetRules()), fold.rule)
	}
	if fold.atom != nil && !slices.ContainsFunc(rows.GetAtoms(), func(atom *protocol.AclAtom) bool { return bytes.Equal(atom.GetAtom(), fold.atom.GetAtom()) }) {
		next.Atoms = append(slices.Clone(rows.GetAtoms()), fold.atom)
	}
	next.SpentGrants = aclSpendGrant(rows.GetSpentGrants(), fold.grantId, fold.retainUntilMs)
	return next, nil
}
