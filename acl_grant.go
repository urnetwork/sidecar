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
// device it owns or sponsors (owner decision 180). An Owner's or Admin's approval meets the clause wherever it
// applies, but counts toward k only as any approver's does, where the rule's approvers name it (the owner's answer to
// acl-m6-05-admin-alone-reach, QD-863): autogroup:admin, a user or group listing the member, another role autogroup
// it holds, or an owner slot that resolves to autogroup:admin because no one owner or sponsor stands, as
// autogroup:dst-owner does for a worker whose sponsor is gone (D-ACL-23, acl_approver.go). So the approvers the log
// counts are the ones the directory asks (directory_auth.go; FI-26), and:
//
//	autogroup:dst-owner alone   an admin's lone decision activates no reach to another member's device or to a
//	                            worker another member sponsors: that owner's or sponsor's decision does
//	autogroup:self alone        reach to another member's device takes the requester's owner, who is the k, and an
//	                            admin, whose decision meets the clause and counts for nothing else
//	autogroup:admin named       an admin's decision is one of the k and meets the clause
//
// An admin's decision that only meets the clause is held to everything a counted one is: the rule's evidence, its
// expiry and the spend check.
//
// A GrantActivate folds to an AclRule (plan-ACL-folded-grant-state #2): rule_id the grant_id, src its subject's
// sidecar atom, targets and actions from grant_dst and grant_allow, a route grant's subjects in grant_dst its via too
// (QD-764), since what it routes through is all its clear grant_dst names, ports_limited when the action carries a
// sealed_detail, whose prefixes and ports no server reads (QD-740), so a grant with sealed ports never folds to one
// with none: the closed direction, until the device reads its ports from the detail. A clear grant_dst names no port
// at any version, which every parser holds, so no port's value reaches rows (plan-BRIDGE-gate-row-prefixes #1); the
// ask's own ports still mark the rule, should a parser ever admit one. A bridge_forward's grant is version 4's
// alone, so each one seals what it reaches. Then expires the matching rule's lifetime, a publish's audience,
// app_mode and pin, and source_rule_id the requests rule, whose deletion by a later config head ends the grant at
// that base for every reader (FS-14). Its grant_id enters spent_grants until the
// latest of its decisions' not_after_millis plus 60 s, so a re-signed GrantActivate under a fresh header is refused
// for as long as any of its decisions could spend.
//
// A base's re-application of a GrantActivate that took effect judges none of the four checks again (§7.9's base row;
// QD-954): its fold is built from its body as the check builds it (aclGrantFoldOf), its expiry from the requests rule
// its action names in the rows it folds into, so a grant re-applied where its check would now refuse, a decision's
// approver no longer eligible under a new head or a reader with no spend check installed, folds as it did. Where those
// rows hold that requests rule no more, or cannot take its src atom, the grant ends at that base, as a compile ends it
// (FS-14), and its grant_id is still spent, so no re-signed copy of it activates (aclReapplyGrantFold).
//
// A share's grant (§8.11; the owner's answer to acl-m6-03-share-grant-subject, QD-820) names the other network in its
// action's share_network_id, and stays its requesting sidecar's: the action's subject, every decision's requester and
// the spender are that sidecar, as for any grant. Its inbound half, which gives the other network reach to this
// one's resources, folds with src the derived network atom (kind 4) over that network's id, the atom a document's
// network:<net> compiles to, and its row names the network, so the contract gate's share half finds the rule naming
// network:Y in X's rows (acl_share.go). Its outbound half, whose destination is the other network itself, folds as
// any grant does, src its subject, its target that network: the rule targeting network:X in Y's rows. Either half
// needs an admin's approval whatever its rule says, and its activation is the delta §8.11 asks, on each side. An
// inbound share's rule names no sidecar, so only an admin revokes it (checkGrantRevoke).
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
	"fmt"
	"maps"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

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
	// the AclRule, rule_id the grant_id; nil for a grant a base's re-application ends at that base, which folds its
	// grant_id spent and nothing else (aclReapplyGrantFold)
	rule *protocol.AclRule
	// the rule's src atom, its subject's sidecar atom or an inbound share's network atom, which rows lacking it gain,
	// a new base's included; nil with no rule
	atom *protocol.AclAtom
	// AclSpentGrant.retain_until_ms
	retainUntilMs int64
}

// A GrantActivate's body as the checks and its fold read it, a function of the body alone: its canonical action, the
// ask the action carries, its decisions, each an approval naming the action's bytes and its subject (match), all of
// one approval and one request, and the grant_id that approval fixes.
type aclGrantBody struct {
	action    *StoredCanonicalAction
	ask       *AclGrantAsk
	decisions []*StoredApprovalDecision
	grantId   [sha256.Size]byte
}

// Parses a GrantActivate's body as CheckGrantActivate and a base's re-application both read it, refusing one that
// does not parse or whose decisions do not match its action (aclGrantDecisions).
func aclParseGrantActivate(activate *protocol.GrantActivate) (*aclGrantBody, error) {
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
	return &aclGrantBody{action: action, ask: ask, decisions: decisions, grantId: AclGrantId(approvalId, action.PayloadSha256())}, nil
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
	body, err := aclParseGrantActivate(activate)
	if err != nil {
		return nil, err
	}

	// grant_id, then refuse
	if !bytes.Equal(activate.GetGrantId(), body.grantId[:]) {
		return nil, fmt.Errorf("%w: a grant_id the approval does not fix", ErrConfigRule)
	}
	if self.spentGrant(body.grantId[:]) != nil || self.grantRule(body.grantId[:]) != nil {
		return nil, fmt.Errorf("%w: a grant_id already in the log", ErrConfigReplay)
	}

	now := aclTime(statement.TimeMs)
	match, err := MatchAclRequest(self, body.ask, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigAuthority, err)
	}
	if err := self.grantQuorum(statement, match.Rule, body.ask, body.action, body.decisions, spendCheck); err != nil {
		return nil, err
	}

	fold, err := aclGrantFoldOf(body, match.ExpiresMs)
	if err != nil {
		return nil, err
	}
	if !aclRowsTakeAtom(self.rows, fold.atom) {
		return nil, fmt.Errorf("%w: the rows hold %d atoms already", ErrConfigRule, aclRowsMaxAtomCount)
	}
	return &AclStatementVerdict{Signer: signer.id, grant: fold}, nil
}

// What a GrantActivate whose body is body folds to, its rule ending at endMs: CheckGrantActivate's, with the end the
// matching requests rule gives, and a base's re-application's, with the end that rule gives in the rows it folds into
// (aclReapplyGrantFold), so the two build one fold from one body. Refuses a share whose ask mixes its halves.
func aclGrantFoldOf(body *aclGrantBody, endMs int64) (*aclGrantFold, error) {
	ask, action := body.ask, body.action
	// the rule's src: the subject, or for a share's inbound half the other network (QD-820)
	atomId := AclDerivedAtom(AclDerivedAtomSidecar, ask.Subject.Bytes())
	atom := &protocol.AclAtom{Atom: atomId.Bytes(), SidecarIds: [][]byte{ask.Subject.Bytes()}}
	if ask.share() {
		outbound, err := ask.shareHalf()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfigRule, err)
		}
		if !outbound {
			atomId = AclDerivedAtom(AclDerivedAtomNetwork, ask.ShareNetworkId.Bytes())
			atom = &protocol.AclAtom{Atom: atomId.Bytes(), NetworkIds: [][]byte{ask.ShareNetworkId.Bytes()}}
		}
	}
	fold := &aclGrantFold{
		grantId: bytes.Clone(body.grantId[:]),
		rule: &protocol.AclRule{
			RuleId:       bytes.Clone(body.grantId[:]),
			SrcAtoms:     [][]byte{atomId.Bytes()},
			Targets:      ask.Dst,
			PortsLimited: 0 < len(ask.Ports) || 0 < len(action.Action.GetSealedDetail()),
			Expires:      endMs,
			// the requests rule the action names, the only one MatchAclRequest asks
			SourceRuleId: bytes.Clone(ask.RuleId),
		},
		atom:          atom,
		retainUntilMs: aclGrantRetainUntilMs(body.decisions),
	}
	for _, allow := range ask.Allow {
		fold.rule.Actions = append(fold.rule.Actions, uint32(allow))
	}
	if slices.Contains(ask.Allow, protocol.AclAction_ACL_ACTION_ROUTE) {
		// a route grant's subject-only grant_dst names what it routes through, its prefixes riding sealed_detail (QD-740):
		// its via subjects, apart from its targets as every rule's are (QD-764)
		for _, target := range ask.Dst {
			if len(target.GetAtom())+len(target.GetSidecarId())+len(target.GetClientId())+len(target.GetNetworkId()) != 0 {
				fold.rule.Via = append(fold.rule.Via, target)
			}
		}
	}
	if slices.Contains(ask.Allow, protocol.AclAction_ACL_ACTION_PUBLISH) {
		fold.rule.Audience = protocol.AclAudience(action.Action.GetAudience())
		fold.rule.AppMode = protocol.AclAppMode(action.Action.GetAppMode())
		fold.rule.LinkSpkiSha256 = bytes.Clone(action.Action.GetLinkSpkiSha256())
	}
	return fold, nil
}

// The retain_until_ms a GrantActivate's spent row keeps (plan-ACL-folded-grant-state #3): the latest of its
// decisions' not_after_millis plus §8.6's skew, so a re-signed copy is refused while any of them could spend.
func aclGrantRetainUntilMs(decisions []*StoredApprovalDecision) int64 {
	retainUntilMs := int64(0)
	for _, decision := range decisions {
		retainUntilMs = max(retainUntilMs, decision.Decision.GetNotAfterMillis()+aclDecisionSkewMs)
	}
	return retainUntilMs
}

// Whether rows can take a grant's src atom: they hold it already, or hold fewer atoms than §8.8's bound. A derived
// atom never takes an autogroup's form, so the rows' atoms are every atom it could already be.
func aclRowsTakeAtom(rows *protocol.AclRows, atom *protocol.AclAtom) bool {
	if atom == nil || len(rows.GetAtoms()) < aclRowsMaxAtomCount {
		return true
	}
	return slices.ContainsFunc(rows.GetAtoms(), func(held *protocol.AclAtom) bool { return bytes.Equal(held.GetAtom(), atom.GetAtom()) })
}

// The fold a GrantActivate that took effect at its own position re-applies with over rows, the base's with the tail
// before it re-applied (§7.9's base row), judging nothing: the fold its check built, from its body, its expiry the end
// the requests rule its action names gives in these rows (aclRequestGrantEnd, MatchAclRequest's), so a grant re-applied
// where nothing changed folds exactly as it did. Where the rows hold that requests rule no more, or cannot take its
// src atom, the grant ends at this base, as a base's compile ends it (FS-14; plan-ACL-folded-grant-state #2): its rule
// and atom fold nothing, and its grant_id is still spent until its decisions' latest not_after plus the skew (#3). An
// error is a body that does not parse, which no GrantActivate that took effect has.
func aclReapplyGrantFold(rows *protocol.AclRows, statement *AclStatement, activate *protocol.GrantActivate) (*aclGrantFold, error) {
	body, err := aclParseGrantActivate(activate)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(rows.GetRequests(), func(request *protocol.AclRequestRule) bool {
		return bytes.Equal(request.GetRuleId(), body.ask.RuleId)
	})
	if index < 0 {
		return &aclGrantFold{grantId: bytes.Clone(body.grantId[:]), retainUntilMs: aclGrantRetainUntilMs(body.decisions)}, nil
	}
	endMs, _ := aclRequestGrantEnd(rows.GetRequests()[index], body.ask.ExpiresMs, statement.TimeMs)
	fold, err := aclGrantFoldOf(body, endMs)
	if err != nil {
		return nil, err
	}
	if !aclRowsTakeAtom(rows, fold.atom) {
		fold.rule, fold.atom = nil, nil
	}
	return fold, nil
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
	if audience == protocol.AclAudience_ACL_AUDIENCE_PUBLIC || ask.share() {
		// a share needs an admin whichever half it is and whatever it reaches (§8.11, owner decision 74)
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

// quorum: k distinct approvers the rule names, each decision on an evidence channel, unexpired and spendable, and
// §8.6's admin clause, which an admin's decision meets whether or not it is one of the k (QD-863).
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

	// the members whose decision was taken, and those of them the rule's approvers name, who alone count toward k
	taken := []Id{}
	counted := []Id{}
	adminApproved := false
	var spendError error
	for _, decision := range decisions {
		body := decision.Decision
		memberId := Id(body.GetApproverMemberId())
		if !slices.Contains(evidence, body.GetChannel()) || body.GetNotAfterMillis()+aclDecisionSkewMs < statement.TimeMs ||
			slices.Contains(taken, memberId) {
			continue
		}
		named := self.Approves(approvers, memberId)
		admin := self.memberAdmin(memberId)
		if !named && !(adminNeeded && admin) {
			continue
		}
		if err := spendCheck.Spendable(self, decision, action, ask.Subject, self.pin, now); err != nil {
			spendError = err
			continue
		}
		taken = append(taken, memberId)
		if named {
			counted = append(counted, memberId)
		}
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

// GrantActivate's fold: its AclRule and its src atom when the rows lack one, and its grant_id spent. A grant a base's
// re-application ended there, its requests rule gone (FS-14), has no rule and folds its grant_id alone.
func aclFoldGrantActivate(rows *protocol.AclRows, verdict *AclStatementVerdict) (*protocol.AclRows, error) {
	fold := verdict.grant
	if fold == nil {
		return nil, fmt.Errorf("%w: a GrantActivate folded without its check", ErrConfigRule)
	}
	next := aclRowsCopy(rows)
	if fold.rule != nil {
		if !slices.ContainsFunc(rows.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), fold.grantId) }) {
			next.Rules = append(slices.Clone(rows.GetRules()), fold.rule)
		}
		if fold.atom != nil && !slices.ContainsFunc(rows.GetAtoms(), func(atom *protocol.AclAtom) bool { return bytes.Equal(atom.GetAtom(), fold.atom.GetAtom()) }) {
			next.Atoms = append(slices.Clone(rows.GetAtoms()), fold.atom)
		}
	}
	next.SpentGrants = aclSpendGrant(rows.GetSpentGrants(), fold.grantId, fold.retainUntilMs)
	return next, nil
}

// The log has already verified the grant id, decisions and action at this point. States share earlier maps.
func (self *ConfigState) rememberGrantAction(body proto.Message) {
	switch statement := body.(type) {
	case *protocol.GrantActivate:
		action := &protocol.CanonicalAction{}
		if proto.Unmarshal(statement.GetCanonicalAction(), action) != nil || len(action.GetSealedDetail()) == 0 {
			return
		}
		actions := maps.Clone(self.grantActions)
		if actions == nil {
			actions = map[string][]byte{}
		}
		actions[string(statement.GetGrantId())] = statement.GetCanonicalAction()
		self.grantActions = actions
	case *bridge.GrantRevoke:
		if _, found := self.grantActions[string(statement.GetGrantId())]; found {
			self.grantActions = maps.Clone(self.grantActions)
			delete(self.grantActions, string(statement.GetGrantId()))
		}
	}
}

// A base retains ciphertext only for the activated rules still present in its folded rows.
func (self *ConfigState) retainGrantActions() {
	if len(self.grantActions) == 0 {
		return
	}
	actions := map[string][]byte{}
	for _, rule := range self.aclRows.GetRules() {
		id := string(rule.GetRuleId())
		if action := self.grantActions[id]; len(rule.GetSourceRuleId()) != 0 && action != nil {
			actions[id] = action
		}
	}
	self.grantActions = actions
}

// A cold reader can join at a base after an active grant landed. Recover its exact action from the head's
// folded records and recompute the grant id from the approval and payload hash before using its sealed ports.
func (self *ConfigState) grantActionsAtHead(head *ConfigHead) map[string][]byte {
	actions := self.grantActions
	if head == nil || head.FoldedThrough() == 0 || head.FoldedThrough() != self.Base().GetFoldedThrough() {
		return actions
	}
	missing := map[string]bool{}
	for _, rule := range self.aclRows.GetRules() {
		id := string(rule.GetRuleId())
		if rule.GetPortsLimited() && len(rule.GetSourceRuleId()) != 0 && actions[id] == nil {
			missing[id] = true
		}
	}
	if len(missing) == 0 {
		return actions
	}
	_, genesis := head.Genesis()
	if bridge.GenesisChain(genesis) != self.genesisChain {
		return actions
	}
	actions = maps.Clone(actions)
	if actions == nil {
		actions = map[string][]byte{}
	}
	for _, fold := range head.folds {
		for _, record := range fold.GetRecords() {
			if record.GetKind() != bridge.AuthEntryKindStatement {
				continue
			}
			signed := &bridge.Signed{}
			if proto.Unmarshal(record.GetBody(), signed) != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GRANT_ACTIVATE) {
				continue
			}
			activated := &protocol.GrantActivate{}
			if proto.Unmarshal(signed.GetBody(), activated) != nil || !missing[string(activated.GetGrantId())] {
				continue
			}
			body, err := aclParseGrantActivate(activated)
			if err != nil || !bytes.Equal(body.grantId[:], activated.GetGrantId()) || len(body.action.Action.GetSealedDetail()) == 0 {
				continue
			}
			id := string(activated.GetGrantId())
			actions[id] = body.action.Bytes
			delete(missing, id)
			if len(missing) == 0 {
				return actions
			}
		}
	}
	return actions
}

// Only the ports authorized for this particular destination are eligible. A receipt, row or key on its own
// supplies no port. Never infer a protocol from target_port, which alone does not name one.
func (self *ConfigState) grantPortRule(encoded []byte, target Id, repoKeyAt func(uint64) *EvsRepoKey) *AclLocalRule {
	if len(encoded) == 0 {
		return nil
	}
	action, err := ParseStoredCanonicalAction(encoded)
	if err != nil {
		return nil
	}
	detail, err := OpenCanonicalActionDetail(action, self.NetworkId(), repoKeyAt)
	if err != nil || detail == nil {
		return nil
	}
	local := &AclLocalRule{}
	for _, destination := range detail.GetGrantDst() {
		recipient, ports, err := ParseAclGrantDst(destination)
		if err == nil && ports != nil && bytes.Equal(recipient.GetSidecarId(), target[:]) &&
			(detail.GetTargetPort() == 0 || ports.GetFirst() == detail.GetTargetPort()) {
			local.Ports = append(local.Ports, AclPortRange{Protocol: ports.GetProtocol(), First: ports.GetFirst(), Last: ports.GetLast()})
		}
	}
	return local
}
