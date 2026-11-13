// §8.8's GrantActivate on the fake view: grant_id's fixed vectors, each quorum branch (k = 1 and 2, a non-eligible
// approver, evidence, expiry, the spend check), the admin clause and its dst-owner exception, the match checks, the
// fold, and replays refused after activation, expiry and a GrantRevoke. Then FS-14 through TEAM's log: a grant whose
// requests rule a new config head deleted ends at that base. A dial or route grant here is a bridge_forward's at
// version 4, its ports and prefixes in a sealed_detail no verifier opens (QD-740), and the match checks hold the
// shape before it, a port or a prefix in the clear or a forward at version 1, refused. Pure, on every leg.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/acl/grant
var testAclGrantFiles embed.FS

// grant_id over fixed vectors computed apart from this code (testdata/acl/grant/grant_id.json).
func TestAclGrantIdVectors(t *testing.T) {
	data, err := testAclGrantFiles.ReadFile("testdata/acl/grant/grant_id.json")
	if err != nil {
		t.Fatal(err)
	}
	document := struct {
		Vectors []struct {
			Name          string `json:"name"`
			ApprovalId    string `json:"approval_id"`
			PayloadSha256 string `json:"payload_sha256"`
			GrantId       string `json:"grant_id"`
		} `json:"vectors"`
	}{}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vector := range document.Vectors {
		approvalId, err1 := hex.DecodeString(vector.ApprovalId)
		payload, err2 := hex.DecodeString(vector.PayloadSha256)
		if err := errors.Join(err1, err2); err != nil || len(approvalId) != 16 || len(payload) != 32 {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		grantId := AclGrantId(Id(approvalId), [sha256.Size]byte(payload))
		if hex.EncodeToString(grantId[:]) != vector.GrantId {
			t.Errorf("%s: %x", vector.Name, grantId)
		}
	}
}

// A spend check that lets a decision spend unless its approver is listed, or its requester is not the spender.
type aclTestSpendCheck struct {
	refused map[Id]bool
}

func (self *aclTestSpendCheck) Spendable(state *AclState, decision *StoredApprovalDecision, action *StoredCanonicalAction, spender Id, pin *bridge.AuthPin, now time.Time) error {
	if self.refused[Id(decision.Decision.GetApproverMemberId())] {
		return errors.New("refused by the test's spend check")
	}
	if Id(decision.Decision.GetRequesterSidecarId()) != spender || pin == nil {
		return errors.New("another spender")
	}
	return nil
}

// A requests rule in the fixture's rows, returning its id.
func (self *aclTestFixture) requestRule(src []Id, targets []*protocol.AclTarget, actions []protocol.AclAction, approverAtoms []Id, approvers uint32, evidence ...protocol.ApprovalChannel) []byte {
	rule := &protocol.AclRequestRule{RuleId: NewId().Bytes(), Targets: targets, Approvers: approvers}
	for _, atom := range src {
		rule.SrcAtoms = append(rule.SrcAtoms, atom.Bytes())
	}
	for _, action := range actions {
		rule.Actions = append(rule.Actions, uint32(action))
	}
	for _, atom := range approverAtoms {
		rule.ApproverAtoms = append(rule.ApproverAtoms, atom.Bytes())
	}
	for _, channel := range evidence {
		rule.Evidence = append(rule.Evidence, uint32(channel))
	}
	self.rows.Requests = append(self.rows.Requests, rule)
	return rule.RuleId
}

// One grant asked and approved: its action as stored, its approval and request, and the decisions made so far.
type aclTestGrant struct {
	actionBytes []byte
	approvalId  Id
	requestSha  [sha256.Size]byte
	subject     Id
	decisions   []*bridge.Signed
}

// The port a test forward names on its target, which its detail always holds.
const aclTestForwardPort = 22

// The CanonicalAction a test's grant rides, as a daemon fills it (QD-740). A grant asking dial or route alone is a
// bridge_forward's, at version 4: its target's port and each destination's port or prefix text ride its
// sealed_detail, and the clear grant_dst names the same sidecars by id alone, a prefix nowhere. A grant asking
// anything else is no forward's, so it rides a socket_listen action at version 1 with the grant's fields alone,
// which seals nothing.
func aclTestGrantAction(ruleId []byte, subject Id, dst []string, allow []string, expiresMs int64) *protocol.CanonicalAction {
	action := &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_LISTEN), Version: 1,
		RuleId: ruleId, Subject: subject.Bytes(), GrantDst: dst, GrantAllow: allow, ExpiresMillis: expiresMs,
	}
	if slices.ContainsFunc(allow, func(name string) bool { return !slices.Contains(canonicalActionSealedGrantAllows, name) }) {
		return action
	}
	action.Kind = uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD)
	action.Version = canonicalActionVersionSealedGrant
	action.GrantDst = nil
	detail := &protocol.CanonicalActionDetail{TargetPort: aclTestForwardPort}
	for _, entry := range dst {
		clear := entry
		if !canonicalActionGrantDstClear(entry) {
			detail.GrantDst = append(detail.GrantDst, entry)
			kind, value, _ := strings.Cut(entry, ":")
			if kind != "sidecar" {
				// a prefix has no clear form
				continue
			}
			sidecarIdText, _, _ := strings.Cut(value, ":")
			clear = kind + ":" + sidecarIdText
		}
		if !slices.Contains(action.GrantDst, clear) {
			action.GrantDst = append(action.GrantDst, clear)
		}
	}
	action.SealedDetail = testSealActionDetail(detail)
	return action
}

// A grant of dst and allow to subject under the requests rule, its action as stored (aclTestGrantAction).
func newAclTestGrant(t *testing.T, ruleId []byte, subject Id, dst []string, allow []string, expiresMs int64) *aclTestGrant {
	return newAclTestGrantOf(testConfigMarshal(t, aclTestGrantAction(ruleId, subject, dst, allow, expiresMs)), subject)
}

// A grant to subject whose action is these stored bytes, under a fresh approval.
func newAclTestGrantOf(actionBytes []byte, subject Id) *aclTestGrant {
	approvalId := NewId()
	return &aclTestGrant{
		actionBytes: actionBytes,
		approvalId:  approvalId,
		requestSha:  sha256.Sum256(append([]byte("request "), approvalId[:]...)),
		subject:     subject,
	}
}

// Rewrites the grant's action by hand, as no builder would, and drops the decisions made over the old bytes.
func (self *aclTestGrant) rewrite(t *testing.T, edit func(action *protocol.CanonicalAction)) *aclTestGrant {
	action := &protocol.CanonicalAction{}
	if err := proto.Unmarshal(self.actionBytes, action); err != nil {
		t.Fatal(err)
	}
	edit(action)
	self.actionBytes = testConfigMarshal(t, action)
	self.decisions = nil
	return self
}

// Adds an approver's decision on channel, expiring at notAfterMs.
func (self *aclTestGrant) approve(t *testing.T, approver Id, channel protocol.ApprovalChannel, notAfterMs int64) *aclTestGrant {
	payload := sha256.Sum256(self.actionBytes)
	decision := &protocol.ApprovalDecision{
		ApprovalId: self.approvalId.Bytes(), RequestSha256: self.requestSha[:], PayloadSha256: payload[:],
		Decision: uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE), Uses: 1, NotAfterMillis: notAfterMs,
		ApproverMemberId: approver.Bytes(), Channel: uint32(channel), RequesterSidecarId: self.subject.Bytes(),
		AuthPin: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)}, Version: 1,
	}
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
		decision.EvidenceSha256 = bytes.Repeat([]byte{0xee}, 32)
	}
	self.decisions = append(self.decisions, &bridge.Signed{
		Body: testConfigMarshal(t, decision), Signature: make([]byte, 64), Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	})
	return self
}

// The GrantActivate carrying the decisions so far.
func (self *aclTestGrant) activate() *protocol.GrantActivate {
	grantId := AclGrantId(self.approvalId, sha256.Sum256(self.actionBytes))
	return &protocol.GrantActivate{GrantId: grantId[:], CanonicalAction: self.actionBytes, Decisions: self.decisions}
}

// A sidecar's grant_dst string.
func aclTestDst(sidecarId Id) string {
	return "sidecar:" + hex.EncodeToString(sidecarId.Bytes())
}

// An hour from aclTestNow, an approval's expiry.
var aclTestDecisionNotAfter = aclTestNow.Add(time.Hour).UnixMilli()

// The quorum: k distinct approvers the rule names, each on an evidence channel, unexpired and spendable; at k = 2 two
// members, never one twice; a non-eligible approver counts for nothing.
func TestAclGrantActivateQuorum(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	group := fixture.group(cast.owner, cast.admin)
	dial := []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	ownDevices := []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}
	selfRule := fixture.requestRule([]Id{member}, ownDevices, dial, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	twoRule := fixture.requestRule([]Id{member}, ownDevices, dial, []Id{group}, 2)
	deviceOnly := fixture.requestRule([]Id{member}, ownDevices, dial, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0, device)
	state := fixture.state(t)
	spend := &aclTestSpendCheck{refused: map[Id]bool{}}
	harness := protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS
	grant := func(ruleId []byte) *aclTestGrant {
		return newAclTestGrant(t, ruleId, cast.laptop, []string{aclTestDst(cast.phone) + ":tcp:22"}, []string{"dial"}, 0)
	}
	cases := []struct {
		name    string
		grant   *aclTestGrant
		spend   AclSpendCheck
		refusal error
	}{
		{name: "the requester's owner", grant: grant(selfRule).approve(t, cast.member, device, aclTestDecisionNotAfter)},
		{name: "a member the rule does not name", grant: grant(selfRule).approve(t, cast.strangerUser, device, aclTestDecisionNotAfter), refusal: ErrConfigAuthority},
		{name: "two of the group", grant: grant(twoRule).approve(t, cast.owner, device, aclTestDecisionNotAfter).approve(t, cast.admin, device, aclTestDecisionNotAfter)},
		{name: "one of two", grant: grant(twoRule).approve(t, cast.owner, device, aclTestDecisionNotAfter), refusal: ErrConfigAuthority},
		{name: "one member twice", grant: grant(twoRule).approve(t, cast.owner, device, aclTestDecisionNotAfter).approve(t, cast.owner, device, aclTestDecisionNotAfter), refusal: ErrConfigAuthority},
		{name: "a channel the evidence leaves out", grant: grant(deviceOnly).approve(t, cast.member, harness, aclTestDecisionNotAfter), refusal: ErrConfigAuthority},
		{name: "a channel the evidence lists", grant: grant(deviceOnly).approve(t, cast.member, device, aclTestDecisionNotAfter)},
		{name: "an expired decision", grant: grant(selfRule).approve(t, cast.member, device, aclTestNow.Add(-2*time.Minute).UnixMilli()), refusal: ErrConfigAuthority},
		{name: "within the skew", grant: grant(selfRule).approve(t, cast.member, device, aclTestNow.Add(-30*time.Second).UnixMilli())},
		{name: "the spend check refuses", grant: grant(selfRule).approve(t, cast.member, device, aclTestDecisionNotAfter), spend: &aclTestSpendCheck{refused: map[Id]bool{cast.member: true}}, refusal: ErrConfigAuthority},
		{name: "no spend check installed", grant: grant(selfRule).approve(t, cast.member, device, aclTestDecisionNotAfter), spend: AclSpendCheckUnbuilt{}, refusal: ErrConfigRuleMissing},
	}
	for _, c := range cases {
		check := c.spend
		if check == nil {
			check = spend
		}
		_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, c.grant.activate(), cast.laptop), check)
		if c.refusal == nil && err != nil || c.refusal != nil && !errors.Is(err, c.refusal) {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
	// nil spend check: the unbuilt one
	_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, grant(selfRule).approve(t, cast.member, device, aclTestDecisionNotAfter).activate(), cast.laptop), nil)
	if !errors.Is(err, ErrAclSpendCheckUnbuilt) {
		t.Errorf("a nil spend check: %v", err)
	}
}

// §8.6's admin clause: reach to another member's device needs an admin whatever the rule says, unless that member
// approves as autogroup:dst-owner (owner decision 180); a share always needs an admin.
func TestAclGrantActivateAdminClause(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	members := []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)}
	dial := []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	selfRule := fixture.requestRule([]Id{member}, members, dial, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	dstOwnerRule := fixture.requestRule([]Id{member}, members, dial, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER)}, 0)
	dstOwnerListen := fixture.requestRule([]Id{member}, members, []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_LISTEN},
		[]Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER)}, 0)
	otherNetwork := NewId()
	shareRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{{NetworkId: otherNetwork.Bytes()}}, dial, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	state := fixture.state(t)
	spend := &aclTestSpendCheck{}
	reachStranger := func(ruleId []byte, allow ...string) *aclTestGrant {
		return newAclTestGrant(t, ruleId, cast.laptop, []string{aclTestDst(cast.stranger)}, allow, 0)
	}
	cases := []struct {
		name    string
		grant   *aclTestGrant
		refusal error
	}{
		{name: "the requester's owner alone, reaching another member", grant: reachStranger(selfRule, "dial").approve(t, cast.member, device, aclTestDecisionNotAfter), refusal: ErrConfigAuthority},
		{name: "the requester's owner and an admin", grant: reachStranger(selfRule, "dial").approve(t, cast.member, device, aclTestDecisionNotAfter).approve(t, cast.admin, device, aclTestDecisionNotAfter)},
		{name: "the touched member as dst-owner", grant: reachStranger(dstOwnerRule, "dial").approve(t, cast.strangerUser, device, aclTestDecisionNotAfter)},
		{name: "dst-owner for more than reach", grant: reachStranger(dstOwnerListen, "dial", "listen").approve(t, cast.strangerUser, device, aclTestDecisionNotAfter), refusal: ErrConfigAuthority},
		{name: "a share by the owner alone", grant: newAclTestGrant(t, shareRule, cast.laptop, []string{"network:" + hex.EncodeToString(otherNetwork.Bytes())}, []string{"dial"}, 0).
			approve(t, cast.member, device, aclTestDecisionNotAfter), refusal: ErrConfigAuthority},
		{name: "a share with an admin", grant: newAclTestGrant(t, shareRule, cast.laptop, []string{"network:" + hex.EncodeToString(otherNetwork.Bytes())}, []string{"dial"}, 0).
			approve(t, cast.member, device, aclTestDecisionNotAfter).approve(t, cast.owner, device, aclTestDecisionNotAfter)},
		{name: "the owner's own device, no admin", grant: newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone)}, []string{"dial"}, 0).
			approve(t, cast.member, device, aclTestDecisionNotAfter)},
	}
	for _, c := range cases {
		_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, c.grant.activate(), cast.laptop), spend)
		if c.refusal == nil && err != nil || c.refusal != nil && !errors.Is(err, c.refusal) {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
}

// The match checks and the action's own: every decision approves this action for this requester under one approval,
// the grant_id is the one it fixes, the action keeps to its kind's server fields, the signer stands, and the rule
// takes the grant.
func TestAclGrantActivateMatch(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	state := fixture.state(t)
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	valid := func() *aclTestGrant {
		return newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone)}, []string{"dial"}, 0).approve(t, cast.member, device, aclTestDecisionNotAfter)
	}
	cases := []struct {
		name     string
		activate func() *protocol.GrantActivate
		signer   Id
		refusal  error
	}{
		{name: "valid", activate: func() *protocol.GrantActivate { return valid().activate() }, signer: cast.laptop},
		{name: "filed by another admitted sidecar", activate: func() *protocol.GrantActivate { return valid().activate() }, signer: cast.agent},
		{name: "filed by a read_only device", activate: func() *protocol.GrantActivate { return valid().activate() }, signer: cast.pageWorker, refusal: ErrConfigReadOnly},
		{name: "another grant_id", activate: func() *protocol.GrantActivate {
			activate := valid().activate()
			activate.GrantId = bytes.Repeat([]byte{1}, 32)
			return activate
		}, signer: cast.laptop, refusal: ErrConfigRule},
		{name: "a decision for another action", activate: func() *protocol.GrantActivate {
			grant := valid()
			other := newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.revoked)}, []string{"dial"}, 0)
			other.approvalId, other.requestSha = grant.approvalId, grant.requestSha
			grant.decisions = append(grant.decisions, other.approve(t, cast.owner, device, aclTestDecisionNotAfter).decisions...)
			return grant.activate()
		}, signer: cast.laptop, refusal: ErrConfigRule},
		{name: "a decision for another requester", activate: func() *protocol.GrantActivate {
			grant := valid()
			grant.subject = cast.phone
			grant.approve(t, cast.owner, device, aclTestDecisionNotAfter)
			grant.subject = cast.laptop
			return grant.activate()
		}, signer: cast.laptop, refusal: ErrConfigRule},
		{name: "decisions of two approvals", activate: func() *protocol.GrantActivate {
			grant := valid()
			grant.approvalId = NewId()
			grant.approve(t, cast.owner, device, aclTestDecisionNotAfter)
			return grant.activate()
		}, signer: cast.laptop, refusal: ErrConfigRule},
		{name: "no decision", activate: func() *protocol.GrantActivate {
			activate := valid().activate()
			activate.Decisions = nil
			return activate
		}, signer: cast.laptop, refusal: ErrConfigRule},
		{name: "a denial", activate: func() *protocol.GrantActivate {
			grant := valid()
			body := &protocol.ApprovalDecision{}
			if err := proto.Unmarshal(grant.decisions[0].GetBody(), body); err != nil {
				t.Fatal(err)
			}
			body.Decision = uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY)
			grant.decisions[0].Body = testConfigMarshal(t, body)
			return grant.activate()
		}, signer: cast.laptop, refusal: ErrConfigRule},
		{name: "a field off the kind's server row", activate: func() *protocol.GrantActivate {
			return valid().rewrite(t, func(action *protocol.CanonicalAction) {
				action.Preview = "a preview no server sees"
			}).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrConfigRule},
		{name: "a destination the rule does not take", activate: func() *protocol.GrantActivate {
			return newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.stranger)}, []string{"dial"}, 0).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrConfigAuthority},
		{name: "an action the rule does not take", activate: func() *protocol.GrantActivate {
			return newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone)}, []string{"route"}, 0).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrConfigAuthority},
		{name: "another kind's action the rule does not take", activate: func() *protocol.GrantActivate {
			return newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone)}, []string{"listen"}, 0).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrConfigAuthority},
		{name: "a port sealed with its sidecar in the clear", activate: func() *protocol.GrantActivate {
			return newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone) + ":tcp:22"}, []string{"dial"}, 0).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop},
		// QD-740: a dial or route grant shows a verifier no prefix and no port, and is a forward's at version 4 alone
		{name: "a prefix sealed and no destination in the clear", activate: func() *protocol.GrantActivate {
			return newAclTestGrant(t, selfRule, cast.laptop, []string{"ip:10.0.0.0/8"}, []string{"route"}, 0).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrAclGrantFieldInvalid},
		{name: "a prefix in the clear grant_dst", activate: func() *protocol.GrantActivate {
			return valid().rewrite(t, func(action *protocol.CanonicalAction) {
				action.GrantDst = append(action.GrantDst, "ip:10.0.0.0/8")
			}).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrCanonicalActionInvalid},
		{name: "a port in the clear grant_dst", activate: func() *protocol.GrantActivate {
			return valid().rewrite(t, func(action *protocol.CanonicalAction) {
				action.GrantDst = []string{aclTestDst(cast.phone) + ":tcp:22"}
			}).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrCanonicalActionInvalid},
		{name: "a forward with no sealed_detail", activate: func() *protocol.GrantActivate {
			return valid().rewrite(t, func(action *protocol.CanonicalAction) {
				action.SealedDetail = nil
			}).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrCanonicalActionInvalid},
		{name: "a forward whose sealed_detail is no sealed body", activate: func() *protocol.GrantActivate {
			return valid().rewrite(t, func(action *protocol.CanonicalAction) {
				action.SealedDetail = testConfigMarshal(t, &protocol.CanonicalActionDetail{TargetPort: aclTestForwardPort})
			}).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrCanonicalActionInvalid},
		{name: "a forward at version 1, its port in the clear", activate: func() *protocol.GrantActivate {
			return valid().rewrite(t, func(action *protocol.CanonicalAction) {
				action.Version = 1
				action.SealedDetail = nil
				action.GrantDst = []string{aclTestDst(cast.phone) + ":tcp:22"}
			}).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrCanonicalActionInvalid},
		{name: "a forward at version 1 with no port", activate: func() *protocol.GrantActivate {
			return valid().rewrite(t, func(action *protocol.CanonicalAction) {
				action.Version = 1
				action.SealedDetail = nil
			}).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrCanonicalActionInvalid},
		{name: "another kind's grant naming a port in the clear", activate: func() *protocol.GrantActivate {
			return valid().rewrite(t, func(action *protocol.CanonicalAction) {
				action.Kind = uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_LISTEN)
				action.Version = 1
				action.SealedDetail = nil
				action.GrantDst = []string{aclTestDst(cast.phone) + ":tcp:22"}
			}).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
		}, signer: cast.laptop, refusal: ErrCanonicalActionInvalid},
	}
	spend := &aclTestSpendCheck{}
	for _, c := range cases {
		_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, c.activate(), c.signer), spend)
		if c.refusal == nil && err != nil || c.refusal != nil && !errors.Is(err, c.refusal) {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
}

// An activated grant folds to a rule from its subject's atom to its destinations, its expiry the rule's lifetime, its
// grant_id spent until its decisions' latest not_after plus the skew; and its replay is refused while it stands,
// after it expires and after a GrantRevoke, a re-signed one under a fresh header included.
func TestAclGrantActivateFoldsAndRefusesReplays(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	state := fixture.state(t)
	spend := &aclTestSpendCheck{}
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	grant := newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone) + ":tcp:22"}, []string{"dial"}, 0).
		approve(t, cast.member, device, aclTestDecisionNotAfter).approve(t, cast.owner, device, aclTestDecisionNotAfter+5000)
	if reach := state.Reach(AclSidecarSubject(cast.laptop), AclSidecarSubject(cast.phone), aclTestNow); reach.Allowed {
		t.Fatal("reach before the grant")
	}
	activate := grant.activate()
	if bytes.Contains(activate.GetCanonicalAction(), []byte(":tcp:")) {
		t.Fatal("the GrantActivate shows its port in the clear")
	}
	statement := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop)
	verdict, err := state.CheckStatement(statement, spend)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(testConfigMarshal(t, rows), []byte(":tcp:")) {
		t.Fatal("the rows hold the grant's port")
	}
	fixture.rows = rows
	state = fixture.state(t)
	reach := state.Reach(AclSidecarSubject(cast.laptop), AclSidecarSubject(cast.phone), aclTestNow)
	if !reach.Allowed || !bytes.Equal(reach.Rule.GetRuleId(), activate.GetGrantId()) || !bytes.Equal(reach.Rule.GetSourceRuleId(), selfRule) ||
		reach.Rule.GetExpires() != aclTestNow.UnixMilli()+aclRequestDefaultExpiryMs {
		t.Fatalf("the activated grant: %+v", reach)
	}
	if !reach.Rule.GetPortsLimited() {
		t.Error("the grant's port did not fold as ports_limited")
	}
	if spent := state.spentGrant(activate.GetGrantId()); spent.GetRetainUntilMs() != aclTestDecisionNotAfter+5000+aclDecisionSkewMs {
		t.Errorf("retain_until_ms %d", spent.GetRetainUntilMs())
	}
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop), spend); !errors.Is(err, ErrConfigReplay) {
		t.Errorf("a replay while it stands: %v", err)
	}
	expired := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop)
	expired.TimeMs = aclTestNow.UnixMilli() + 2*aclRequestDefaultExpiryMs
	if _, err := state.CheckStatement(expired, spend); !errors.Is(err, ErrConfigReplay) {
		t.Errorf("a replay after its expiry: %v", err)
	}
	revoke := fixture.statement(bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{GrantId: activate.GetGrantId()}, cast.laptop)
	state, _ = fixture.apply(t, state, revoke)
	if reach := state.Reach(AclSidecarSubject(cast.laptop), AclSidecarSubject(cast.phone), aclTestNow); reach.Allowed {
		t.Error("the revoked grant reaches")
	}
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop), spend); !errors.Is(err, ErrConfigReplay) {
		t.Errorf("a replay after its revoke: %v", err)
	}
}

// A network whose log runs §16.6's spend check as the test's, and a requests rule and atom in its acl rows by a base.
func newAclTestGrantNet(t *testing.T, request *protocol.AclRequestRule) *testConfigNet {
	net := newTestConfigNet(t)
	settings := testConfigLogSettings()
	settings.AclSpendCheck = &aclTestSpendCheck{}
	log, err := NewConfigLog(settings, net.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	for _, entryBytes := range net.entries {
		if _, err := log.Apply(entryBytes, net.source); err != nil {
			t.Fatal(err)
		}
	}
	net.log = log
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = append(rows.Requests, request)
	})
	return net
}

// A base at the tip folding everything, its acl rows edited.
func (self *testConfigNet) withAclRows(edit func(rows *protocol.AclRows)) {
	self.t.Helper()
	state := self.log.State()
	rows := state.Rows()
	aclRows := &protocol.AclRows{}
	if state.aclRows != nil {
		aclRows = proto.Clone(state.aclRows).(*protocol.AclRows)
	}
	edit(aclRows)
	rows.Acl = testConfigMarshal(self.t, aclRows)
	if verdict := self.pushBase(self.owner, rows, self.n, state.Base().GetConfigVersion()+1, state.threshold); !verdict.Accepted() {
		self.t.Fatal(verdict.Refusal)
	}
}

// FS-14's GrantActivate case through TEAM's log: a grant activated under a requests rule ends at the base whose config
// head deleted that rule, for this reader and for one that re-applies the activation over that base.
func TestAclGrantEndsWithItsRequestsRuleAtABase(t *testing.T) {
	requestId := testConfigId("fs-14 requests rule").Bytes()
	request := &protocol.AclRequestRule{
		RuleId:        requestId,
		SrcAtoms:      [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
		Targets:       []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
		ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
	}
	net := newAclTestGrantNet(t, request)
	phone := net.device("owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, phone, 0)
	grant := newAclTestGrant(t, requestId, net.owner.sidecarId, []string{aclTestDst(phone.sidecarId)}, []string{"dial"}, 0).
		approve(t, net.ownerMemberId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, net.timeMs+60*60*1000)
	activate := grant.activate()
	activate.Header = net.header()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate)
	reaches := func(state *ConfigState) bool {
		acl, err := state.Acl()
		if err != nil {
			t.Fatal(err)
		}
		return acl.Reach(AclSidecarSubject(net.owner.sidecarId), AclSidecarSubject(phone.sidecarId), time.UnixMilli(net.timeMs)).Allowed
	}
	if !reaches(net.log.State()) {
		t.Fatal("the activated grant does not reach")
	}

	// a base that folds the activation but whose head deleted the requests rule ends the grant there
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = nil
	})
	if reaches(net.log.State()) {
		t.Error("the grant outlived its requests rule at the base")
	}

	// a base below the activation re-applies it over rows without the rule, and it folds nothing
	other := newAclTestGrantNet(t, request)
	other.admitDevice(other.owner, phone, 0)
	second := newAclTestGrant(t, requestId, other.owner.sidecarId, []string{aclTestDst(phone.sidecarId)}, []string{"dial"}, 0).
		approve(t, other.ownerMemberId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, other.timeMs+60*60*1000)
	secondActivate := second.activate()
	secondActivate.Header = other.header()
	activatedAt := other.mustPost(other.owner, bridge.SignedType_SIGNED_GRANT_ACTIVATE, secondActivate).Pin.GetVersion()
	folded := other.statesAt[activatedAt-1]
	rows := folded.Rows()
	aclRows := proto.Clone(folded.aclRows).(*protocol.AclRows)
	aclRows.Requests = nil
	rows.Acl = testConfigMarshal(t, aclRows)
	if verdict := other.pushBase(other.owner, rows, activatedAt-1, folded.Base().GetConfigVersion()+1, folded.threshold); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	state := other.log.State()
	if reaches(state) || 0 < len(state.aclRows.GetRules()) {
		t.Errorf("the re-applied activation folded %d rules", len(state.aclRows.GetRules()))
	}
	if kept := other.log.keptEntry(activatedAt); kept == nil || !kept.verdict.Accepted() {
		t.Error("the activation's own verdict changed at the base")
	}
}
