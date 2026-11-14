//go:build !sidecar_http && !ios_extension

// §8.11's share as a requested grant (the owner's answer to acl-m6-03-share-grant-subject, QD-820): a share's
// CanonicalAction names the other network, a requests rule whose src is network:* or network:<net> takes it, an
// admin's approval activates it, and its fold gives the contract gate's share half the rule it reads, the one naming
// network:Y in X's rows and the one targeting network:X in Y's. Two networks with no document, on the implicit
// document's compiled rows, share through its shares rule, each way; without an admin's approval, or with a grant
// naming another network, the pair stays uncovered; a standing document grant naming network:<net> still covers a
// pair, and a document's network:<net> requests rule takes that network's share alone; and an action stored before
// the field folds as it did. The filer builds a share's action and no standing grant covers one.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A share's action as a daemon fills it: a dial or route grant, a forward's at version 4, naming the other network,
// its detail sealed beside its final clear fields, the network among them.
func aclTestShareAction(ruleId []byte, subject Id, dst []string, allow []string, shareNetworkId Id) *protocol.CanonicalAction {
	action := &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: canonicalActionVersionSealedGrant,
		RuleId: ruleId, Subject: subject.Bytes(), GrantDst: dst, GrantAllow: allow, ShareNetworkId: shareNetworkId.Bytes(),
	}
	return testWithSealedDetail(action, &protocol.CanonicalActionDetail{TargetPort: aclTestForwardPort})
}

// A network's grant_dst string.
func aclTestNetworkDst(networkId Id) string {
	return "network:" + hex.EncodeToString(networkId.Bytes())
}

// One network of a share on compiled rows: an Owner with a device, a Member with a device, and the log's statements
// as they fold.
type aclShareGrantNet struct {
	world       *aclCompileWorld
	networkId   Id
	owner       Id
	ownerDevice Id
	member      Id
	laptop      Id
	rows        *protocol.AclRows
	view        *aclTestView
	position    uint64
}

// A network compiled from its head: the implicit document's rows unless setPolicy gave it one.
func newAclShareGrantNet(t *testing.T, label string, policy func(world *aclCompileWorld) string) *aclShareGrantNet {
	t.Helper()
	world := newAclCompileWorld(label)
	self := &aclShareGrantNet{world: world, networkId: world.networkId}
	domain := strings.ReplaceAll(label, " ", "-") + ".example"
	self.owner = world.member("owner@"+domain, bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.ownerDevice = world.device(label+" owner device", self.owner)
	self.member = world.member("member@"+domain, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.laptop = world.device(label+" member laptop", self.member)
	if policy != nil {
		world.setPolicy(t, policy(world))
	}
	self.rows = world.compile(t)
	self.view = world.view()
	self.position = world.position
	return self
}

func (self *aclShareGrantNet) state(t *testing.T) *AclState {
	t.Helper()
	state, err := NewAclState(self.rows, self.view)
	if err != nil {
		t.Fatalf("NewAclState: %v", err)
	}
	return state
}

// A GrantActivate of grant, filed by signer at aclTestNow, checked at the network's state under the test's spend check.
func (self *aclShareGrantNet) check(t *testing.T, grant *aclTestGrant, signer Id) (*AclStatement, *AclStatementVerdict, error) {
	t.Helper()
	self.position += 1
	statement := &AclStatement{
		Type:    bridge.SignedType_SIGNED_GRANT_ACTIVATE,
		Body:    grant.activate(),
		Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: signer}},
		N:       self.position,
		TimeMs:  aclTestNow.UnixMilli(),
	}
	verdict, err := self.state(t).CheckStatement(statement, &aclTestSpendCheck{})
	return statement, verdict, err
}

// Activates grant, which must take effect, and returns its grant_id.
func (self *aclShareGrantNet) activate(t *testing.T, grant *aclTestGrant, signer Id) []byte {
	t.Helper()
	statement, verdict, err := self.check(t, grant, signer)
	if err != nil {
		t.Fatalf("GrantActivate: %v", err)
	}
	rows, _, err := self.state(t).ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatalf("GrantActivate fold: %v", err)
	}
	self.rows = rows
	return statement.Body.(*protocol.GrantActivate).GetGrantId()
}

// The share's inbound half: other may dial this network's sidecar target, asked by requester under ruleId.
func (self *aclShareGrantNet) inbound(t *testing.T, ruleId Id, requester Id, target Id, other Id) *aclTestGrant {
	t.Helper()
	return newAclTestGrantOf(testConfigMarshal(t, aclTestShareAction(ruleId.Bytes(), requester, []string{aclTestDst(target)}, []string{"dial"}, other)), requester)
}

// The share's outbound half: requester may dial network other, under ruleId.
func (self *aclShareGrantNet) outbound(t *testing.T, ruleId Id, requester Id, other Id) *aclTestGrant {
	t.Helper()
	return newAclTestGrantOf(testConfigMarshal(t, aclTestShareAction(ruleId.Bytes(), requester, []string{aclTestNetworkDst(other)}, []string{"dial"}, other)), requester)
}

// A bound sidecar's end of a contract.
func (self *aclShareGrantNet) end(sidecarId Id) AclContractEnd {
	return AclContractEnd{Known: true, NetworkId: self.networkId, SubjectClientId: NewId(), SidecarId: sidecarId, SidecarHeld: true}
}

// The contract gate over the two networks' states as they now stand.
func aclShareGrantGate(t *testing.T, networks ...*aclShareGrantNet) *AclContractGate {
	t.Helper()
	states := newAclContractTestStates()
	heads := &aclContractTestHeads{}
	headRows := map[Id]uint64{}
	for _, network := range networks {
		states.install(network.networkId, network.state(t))
		headRows[network.networkId] = 1
	}
	heads.set(headRows, nil)
	gate, _, _ := newAclContractTestGate(t, states, heads)
	return gate
}

// The implicit document's shares rule, its third requests rule after four grants (§8.5).
func aclTestImplicitSharesRule() Id {
	return aclImplicitRuleId(6)
}

const aclTestDeviceChannel = protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE

// Two networks with no document share through the implicit document's shares rule once each side's admin approves:
// X's fold names network:Y as the src of the rule reaching its sidecar, Y's names network:X as its dialer's target,
// and the gate covers the pair, in that direction alone until the other direction's halves are approved too.
func TestAclShareGrantThroughTheImplicitRule(t *testing.T) {
	x := newAclShareGrantNet(t, "share x", nil)
	y := newAclShareGrantNet(t, "share y", nil)
	if x.rows.GetHasDocument() || y.rows.GetHasDocument() {
		t.Fatal("a network holds a document")
	}
	sharesRule := aclTestImplicitSharesRule()
	if !slices.ContainsFunc(x.rows.GetRequests(), func(rule *protocol.AclRequestRule) bool {
		return bytes.Equal(rule.GetRuleId(), sharesRule.Bytes()) && len(rule.GetSrcAtoms()) == 1 &&
			bytes.Equal(rule.GetSrcAtoms()[0], aclNetworkWildcardAtom().Bytes())
	}) {
		t.Fatal("the implicit document's third requests rule is not network:*'s")
	}
	forward := func() AclContractVerdict {
		return aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.laptop), x.end(x.laptop), false)
	}
	reverse := func() AclContractVerdict {
		return aclContractDecide(aclShareGrantGate(t, x, y), x.end(x.laptop), y.end(y.laptop), false)
	}
	if verdict := forward(); verdict.Shared() {
		t.Fatalf("before any grant: %+v", verdict)
	}

	// X's half: its admin approves network:Y's reach to X's laptop, asked by the admin's own device
	xGrant := x.inbound(t, sharesRule, x.ownerDevice, x.laptop, y.networkId).approve(t, x.owner, aclTestDeviceChannel, aclTestDecisionNotAfter)
	xGrantId := x.activate(t, xGrant, x.ownerDevice)
	networkAtom := AclDerivedAtom(AclDerivedAtomNetwork, y.networkId.Bytes())
	xRule := x.state(t).grantRule(xGrantId)
	if xRule == nil {
		t.Fatal("X's share is no active rule")
	}
	row := xRule.row
	if len(row.GetSrcAtoms()) != 1 || !bytes.Equal(row.GetSrcAtoms()[0], networkAtom.Bytes()) {
		t.Errorf("X's rule's src %x, want network:Y's atom %x", row.GetSrcAtoms(), networkAtom.Bytes())
	}
	if len(row.GetTargets()) != 1 || !bytes.Equal(row.GetTargets()[0].GetSidecarId(), x.laptop.Bytes()) || !row.GetPortsLimited() ||
		!bytes.Equal(row.GetSourceRuleId(), sharesRule.Bytes()) || row.GetExpires() != aclTestNow.UnixMilli()+aclRequestDefaultExpiryMs {
		t.Errorf("X's rule: %+v", row)
	}
	if !slices.ContainsFunc(x.rows.GetAtoms(), func(atom *protocol.AclAtom) bool {
		return bytes.Equal(atom.GetAtom(), networkAtom.Bytes()) && len(atom.GetNetworkIds()) == 1 &&
			bytes.Equal(atom.GetNetworkIds()[0], y.networkId.Bytes()) && len(atom.GetSidecarIds()) == 0
	}) {
		t.Error("X's rows hold no row naming network Y under its atom")
	}
	// the requester gained nothing of its own from the share
	if slices.ContainsFunc(x.rows.GetAtoms(), func(atom *protocol.AclAtom) bool {
		return bytes.Equal(atom.GetAtom(), AclDerivedAtom(AclDerivedAtomSidecar, x.ownerDevice.Bytes()).Bytes())
	}) {
		t.Error("X's rows gained the requester's atom")
	}
	if verdict := forward(); verdict.Shared() {
		t.Fatalf("with X's half alone: %+v", verdict)
	}

	// Y's half: its admin approves its laptop's dial on network:X, asked by the laptop
	yGrant := y.outbound(t, sharesRule, y.laptop, x.networkId).approve(t, y.owner, aclTestDeviceChannel, aclTestDecisionNotAfter)
	yGrantId := y.activate(t, yGrant, y.laptop)
	yRule := y.state(t).grantRule(yGrantId)
	if yRule == nil {
		t.Fatal("Y's share is no active rule")
	}
	row = yRule.row
	if len(row.GetSrcAtoms()) != 1 || !bytes.Equal(row.GetSrcAtoms()[0], AclDerivedAtom(AclDerivedAtomSidecar, y.laptop.Bytes()).Bytes()) ||
		len(row.GetTargets()) != 1 || !bytes.Equal(row.GetTargets()[0].GetNetworkId(), x.networkId.Bytes()) {
		t.Errorf("Y's rule: %+v", row)
	}
	verdict := forward()
	if !verdict.Shared() || verdict.Class != AclContractClassData || verdict.NetworkId != y.networkId {
		t.Fatalf("with both halves: %+v", verdict)
	}
	if !bytes.Equal(verdict.Decision.Rule.GetRuleId(), yGrantId) || !bytes.Equal(verdict.ShareDecision.Rule.GetRuleId(), xGrantId) {
		t.Errorf("the halves name %x and %x", verdict.Decision.Rule.GetRuleId(), verdict.ShareDecision.Rule.GetRuleId())
	}
	outbound, inbound := AclShareReach(y.state(t), y.networkId, AclSidecarSubject(y.laptop), x.state(t), x.networkId, AclSidecarSubject(x.laptop), aclTestNow)
	if !outbound.Allowed || !inbound.Allowed {
		t.Errorf("AclShareReach: %+v, %+v", outbound, inbound)
	}
	// Y's other device holds no grant of its own, and X's other device is not what X shared
	if verdict := aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.ownerDevice), x.end(x.laptop), false); verdict.Shared() {
		t.Errorf("a Y device with no grant: %+v", verdict)
	}
	if verdict := aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.laptop), x.end(x.ownerDevice), false); verdict.Shared() {
		t.Errorf("an X device X did not share: %+v", verdict)
	}
	// a share is directed: the other way waits for its own two halves
	if verdict := reverse(); verdict.Shared() {
		t.Fatalf("the other way before its halves: %+v", verdict)
	}
	y.activate(t, y.inbound(t, sharesRule, y.ownerDevice, y.laptop, x.networkId).approve(t, y.owner, aclTestDeviceChannel, aclTestDecisionNotAfter), y.ownerDevice)
	if verdict := reverse(); verdict.Shared() {
		t.Fatalf("the other way with Y's half alone: %+v", verdict)
	}
	x.activate(t, x.outbound(t, sharesRule, x.laptop, y.networkId).approve(t, x.owner, aclTestDeviceChannel, aclTestDecisionNotAfter), x.laptop)
	if verdict := reverse(); !verdict.Shared() || verdict.NetworkId != x.networkId {
		t.Fatalf("the other way with both halves: %+v", verdict)
	}
	if verdict := forward(); !verdict.Shared() {
		t.Fatalf("the first way after the second: %+v", verdict)
	}

	// an admin revokes X's share, and the pair is uncovered again; the requester's rule names no sidecar, so a
	// member who is no admin revokes nothing
	x.position += 1
	revoke := &AclStatement{
		Type: bridge.SignedType_SIGNED_GRANT_REVOKE, Body: &bridge.GrantRevoke{GrantId: xGrantId},
		Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: x.laptop}}, N: x.position, TimeMs: aclTestNow.UnixMilli(),
	}
	if _, err := x.state(t).CheckStatement(revoke, nil); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("a member revoking the share: %v", err)
	}
	revoke.Signers = []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: x.ownerDevice}}
	revokeVerdict, err := x.state(t).CheckStatement(revoke, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := x.state(t).ApplyStatement(revoke, revokeVerdict)
	if err != nil {
		t.Fatal(err)
	}
	x.rows = rows
	if verdict := forward(); verdict.Shared() {
		t.Errorf("after X's revoke: %+v", verdict)
	}
}

// Without an admin's approval no share activates: with no decision, a member's alone, a decision for another
// requester or no spend check, each half is refused and the gate covers nothing; a requester that does not stand asks
// nothing.
func TestAclShareGrantNeedsAnAdminsApproval(t *testing.T) {
	x := newAclShareGrantNet(t, "approval x", nil)
	y := newAclShareGrantNet(t, "approval y", nil)
	sharesRule := aclTestImplicitSharesRule()
	cases := []struct {
		name    string
		network *aclShareGrantNet
		grant   *aclTestGrant
		signer  Id
		refusal error
	}{
		{name: "an inbound share with no decision", network: x, grant: x.inbound(t, sharesRule, x.ownerDevice, x.laptop, y.networkId), signer: x.ownerDevice, refusal: ErrConfigRule},
		{name: "an inbound share a member approves", network: x, signer: x.ownerDevice, refusal: ErrConfigAuthority,
			grant: x.inbound(t, sharesRule, x.ownerDevice, x.laptop, y.networkId).approve(t, x.member, aclTestDeviceChannel, aclTestDecisionNotAfter)},
		{name: "an inbound share to the member's own device, which the member approves", network: x, signer: x.laptop, refusal: ErrConfigAuthority,
			grant: x.inbound(t, sharesRule, x.laptop, x.laptop, y.networkId).approve(t, x.member, aclTestDeviceChannel, aclTestDecisionNotAfter)},
		{name: "an outbound share with no decision", network: y, grant: y.outbound(t, sharesRule, y.laptop, x.networkId), signer: y.laptop, refusal: ErrConfigRule},
		{name: "an outbound share its member approves", network: y, signer: y.laptop, refusal: ErrConfigAuthority,
			grant: y.outbound(t, sharesRule, y.laptop, x.networkId).approve(t, y.member, aclTestDeviceChannel, aclTestDecisionNotAfter)},
	}
	for _, c := range cases {
		if _, _, err := c.network.check(t, c.grant, c.signer); !errors.Is(err, c.refusal) {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
	// the decision names the requesting sidecar: an admin's approval for another requester covers none
	stolen := x.inbound(t, sharesRule, x.ownerDevice, x.laptop, y.networkId)
	stolen.subject = x.laptop
	stolen.approve(t, x.owner, aclTestDeviceChannel, aclTestDecisionNotAfter)
	if _, _, err := x.check(t, stolen, x.ownerDevice); !errors.Is(err, ErrConfigRule) {
		t.Errorf("a decision for another requester: %v", err)
	}
	// no spend check, no share
	approved := x.inbound(t, sharesRule, x.ownerDevice, x.laptop, y.networkId).approve(t, x.owner, aclTestDeviceChannel, aclTestDecisionNotAfter)
	x.position += 1
	statement := &AclStatement{
		Type: bridge.SignedType_SIGNED_GRANT_ACTIVATE, Body: approved.activate(),
		Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: x.ownerDevice}}, N: x.position, TimeMs: aclTestNow.UnixMilli(),
	}
	if _, err := x.state(t).CheckStatement(statement, nil); !errors.Is(err, ErrAclSpendCheckUnbuilt) {
		t.Errorf("no spend check: %v", err)
	}
	// a revoked requester asks nothing, whatever an admin approves
	x.view.sidecars[x.ownerDevice].Row.RevokedAt = 99
	if _, _, err := x.check(t, approved, x.laptop); !errors.Is(err, ErrConfigAuthority) || !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a revoked requester: %v", err)
	}
	x.view.sidecars[x.ownerDevice].Row.RevokedAt = 0
	if verdict := aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.laptop), x.end(x.laptop), false); verdict.Shared() {
		t.Errorf("with nothing approved: %+v", verdict)
	}
	// and the same grant with its admin's approval activates
	x.activate(t, approved, x.ownerDevice)
}

// A grant naming another network covers nothing of this pair: X's share with Z, or Y's dial on Z, leaves X and Y
// uncovered, and an action whose destination names another network than its share's, mixes the halves, asks more than
// dial or route or names no network's id is refused.
func TestAclShareGrantNamingAnotherNetworkFailsClosed(t *testing.T) {
	sharesRule := aclTestImplicitSharesRule()
	z := NewId()
	approve := func(network *aclShareGrantNet, grant *aclTestGrant) *aclTestGrant {
		return grant.approve(t, network.owner, aclTestDeviceChannel, aclTestDecisionNotAfter)
	}

	// X shares with Z, and Y dials X: X's half names another network
	x := newAclShareGrantNet(t, "other x", nil)
	y := newAclShareGrantNet(t, "other y", nil)
	x.activate(t, approve(x, x.inbound(t, sharesRule, x.ownerDevice, x.laptop, z)), x.ownerDevice)
	y.activate(t, approve(y, y.outbound(t, sharesRule, y.laptop, x.networkId)), y.laptop)
	if verdict := aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.laptop), x.end(x.laptop), false); verdict.Shared() {
		t.Errorf("X shared with another network: %+v", verdict)
	}

	// X shares with Y, and Y dials Z: Y's half names another network
	x = newAclShareGrantNet(t, "other x", nil)
	y = newAclShareGrantNet(t, "other y", nil)
	x.activate(t, approve(x, x.inbound(t, sharesRule, x.ownerDevice, x.laptop, y.networkId)), x.ownerDevice)
	y.activate(t, approve(y, y.outbound(t, sharesRule, y.laptop, z)), y.laptop)
	if verdict := aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.laptop), x.end(x.laptop), false); verdict.Shared() {
		t.Errorf("Y dials another network: %+v", verdict)
	}

	// shapes no share takes
	shape := func(dst []string, allow []string, shareNetworkId Id) *aclTestGrant {
		return approve(y, newAclTestGrantOf(testConfigMarshal(t, aclTestShareAction(sharesRule.Bytes(), y.laptop, dst, allow, shareNetworkId)), y.laptop))
	}
	rewritten := func(edit func(action *protocol.CanonicalAction)) *aclTestGrant {
		grant := newAclTestGrantOf(testConfigMarshal(t, aclTestShareAction(sharesRule.Bytes(), y.laptop, []string{aclTestNetworkDst(x.networkId)}, []string{"dial"}, x.networkId)), y.laptop)
		return approve(y, grant.rewrite(t, edit))
	}
	cases := []struct {
		name  string
		grant *aclTestGrant
	}{
		{name: "a destination naming another network than the share's", grant: shape([]string{aclTestNetworkDst(z)}, []string{"dial"}, x.networkId)},
		{name: "the share's network beside a sidecar", grant: shape([]string{aclTestNetworkDst(x.networkId), aclTestDst(y.ownerDevice)}, []string{"dial"}, x.networkId)},
		{name: "a share_network_id of 15 bytes", grant: rewritten(func(action *protocol.CanonicalAction) { action.ShareNetworkId = action.ShareNetworkId[:15] })},
		{name: "a share_network_id of zeros", grant: rewritten(func(action *protocol.CanonicalAction) { action.ShareNetworkId = make([]byte, 16) })},
	}
	for _, c := range cases {
		if _, _, err := y.check(t, c.grant, y.laptop); !errors.Is(err, ErrConfigRule) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// a share asking more than dial or route is no ask at all
	ask := &AclGrantAsk{
		Subject: y.laptop, Dst: []*protocol.AclTarget{{NetworkId: x.networkId.Bytes()}}, ShareNetworkId: x.networkId,
		Allow: []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_LISTEN},
	}
	if _, err := MatchAclRequest(y.state(t), ask, aclTestNow); !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a share asking listen: %v", err)
	}
	// a grant that is no share is never taken through the shares rule: its requester holds no network atom
	plain := newAclTestGrant(t, sharesRule.Bytes(), y.laptop, []string{aclTestDst(y.ownerDevice)}, []string{"dial"}, 0)
	if _, _, err := y.check(t, approve(y, plain), y.laptop); !errors.Is(err, ErrConfigAuthority) || !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a plain grant under the shares rule: %v", err)
	}
	// a network shares nothing with itself
	y.view.genesis = &bridge.Genesis{NetworkId: y.networkId.Bytes(), OwnerSidecarId: y.ownerDevice.Bytes(), OwnerMemberId: y.owner.Bytes()}
	if _, _, err := y.check(t, approve(y, y.outbound(t, sharesRule, y.laptop, y.networkId)), y.laptop); !errors.Is(err, ErrConfigAuthority) || !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a share with the network itself: %v", err)
	}
	// and a share is taken by no rule whose src names no network: the directory's reach rule, the implicit document's last
	directory := y.inbound(t, aclImplicitRuleId(7), y.laptop, y.ownerDevice, x.networkId)
	if _, _, err := y.check(t, approve(y, directory), y.laptop); !errors.Is(err, ErrConfigAuthority) || !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a share under the directory's rule: %v", err)
	}
}

// Standing document grants naming network:<net> still cover a pair with no activation, and a document's requests rule
// whose src is network:<net> takes that network's share and no other's.
func TestAclShareStandingDocumentGrantStillCovers(t *testing.T) {
	var xNamesY, xNamesOther, yNamesX Id
	x := newAclShareGrantNet(t, "document x", func(world *aclCompileWorld) string {
		xNamesY = world.network("partner")
		xNamesOther = world.network("other")
		server := hex.EncodeToString(world.id("sidecar document x member laptop").Bytes())
		return `{
			"grants": [
				{ "src": ["autogroup:member"], "dst": ["*"], "allow": ["*"] },
				{ "src": ["network:partner"], "dst": ["sidecar:` + server + `"], "allow": ["dial"] }
			],
			"requests": [
				{ "src": ["network:partner"], "dst": ["autogroup:member"], "allow": ["dial"], "approver": ["autogroup:admin"] }
			]
		}`
	})
	y := newAclShareGrantNet(t, "document y", func(world *aclCompileWorld) string {
		yNamesX = world.network("host")
		return `{
			"grants": [
				{ "src": ["autogroup:member"], "dst": ["*"], "allow": ["*"] },
				{ "src": ["autogroup:member"], "dst": ["network:host"], "allow": ["dial"] }
			]
		}`
	})
	// each document resolves the other network to the id the gate knows it by
	x.networkId, y.networkId = yNamesX, xNamesY
	if !x.rows.GetHasDocument() || !y.rows.GetHasDocument() {
		t.Fatal("a network holds no document")
	}
	if verdict := aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.laptop), x.end(x.laptop), false); !verdict.Shared() {
		t.Fatalf("standing grants on both sides: %+v", verdict)
	}
	// what X's standing grant does not name stays uncovered
	if verdict := aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.laptop), x.end(x.ownerDevice), false); verdict.Shared() {
		t.Errorf("an X device the document does not share: %+v", verdict)
	}

	// X's requests rule names network:partner: a share with that network is taken, and reaches the owner's device once
	// an admin approves; a share with another network the document resolves is not taken
	if len(x.rows.GetRequests()) != 1 {
		t.Fatalf("X's requests: %v", x.rows.GetRequests())
	}
	ruleId := Id(x.rows.GetRequests()[0].GetRuleId())
	other := x.inbound(t, ruleId, x.ownerDevice, x.ownerDevice, xNamesOther).approve(t, x.owner, aclTestDeviceChannel, aclTestDecisionNotAfter)
	if _, _, err := x.check(t, other, x.ownerDevice); !errors.Is(err, ErrConfigAuthority) || !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a share with a network the rule does not name: %v", err)
	}
	x.activate(t, x.inbound(t, ruleId, x.ownerDevice, x.ownerDevice, xNamesY).approve(t, x.owner, aclTestDeviceChannel, aclTestDecisionNotAfter), x.ownerDevice)
	if verdict := aclContractDecide(aclShareGrantGate(t, x, y), y.end(y.laptop), x.end(x.ownerDevice), false); !verdict.Shared() {
		t.Errorf("the activated share beside the standing one: %+v", verdict)
	}
	// the document's own atom row for network:partner is the one the fold's rule rides
	atom := AclDerivedAtom(AclDerivedAtomNetwork, xNamesY.Bytes())
	count := 0
	for _, row := range x.rows.GetAtoms() {
		if bytes.Equal(row.GetAtom(), atom.Bytes()) {
			count += 1
		}
	}
	if count != 1 {
		t.Errorf("network:partner's atom has %d rows", count)
	}
}

// An action stored before share_network_id existed opens and folds as before: no field 40 on its wire, no share in
// its ask, and its rule's src its subject's sidecar atom.
func TestAclGrantWithNoShareNetworkFoldsAsBefore(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	state := fixture.state(t)
	grant := newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone)}, []string{"dial"}, 0).
		approve(t, cast.member, aclTestDeviceChannel, aclTestDecisionNotAfter)
	if slices.Contains(testWireFieldNumbers(t, grant.actionBytes), canonicalActionFieldShareNetworkId) {
		t.Fatal("the older action carries field 40")
	}
	stored, err := ParseStoredCanonicalAction(grant.actionBytes)
	if err != nil {
		t.Fatal(err)
	}
	ask, err := ParseAclGrantAction(stored.Action)
	if err != nil || ask.share() || ask.ShareNetworkId != (Id{}) {
		t.Fatalf("the older action's ask: %+v, %v", ask, err)
	}
	statement := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, grant.activate(), cast.laptop)
	verdict, err := state.CheckStatement(statement, &aclTestSpendCheck{})
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	fixture.rows = rows
	rule := fixture.state(t).grantRule(statement.Body.(*protocol.GrantActivate).GetGrantId())
	subjectAtom := AclDerivedAtom(AclDerivedAtomSidecar, cast.laptop.Bytes())
	if rule == nil || len(rule.row.GetSrcAtoms()) != 1 || !bytes.Equal(rule.row.GetSrcAtoms()[0], subjectAtom.Bytes()) {
		t.Fatalf("the older grant's rule: %+v", rule)
	}
	if !slices.ContainsFunc(rows.GetAtoms(), func(atom *protocol.AclAtom) bool {
		return bytes.Equal(atom.GetAtom(), subjectAtom.Bytes()) && len(atom.GetSidecarIds()) == 1 && len(atom.GetNetworkIds()) == 0
	}) {
		t.Error("the older grant's subject atom")
	}
	if reach := fixture.state(t).Reach(AclSidecarSubject(cast.laptop), AclSidecarSubject(cast.phone), aclTestNow); !reach.Allowed {
		t.Errorf("the older grant: %+v", reach)
	}

	// bytes stored before the field read the same way
	older, err := hex.DecodeString(aclTestForwardStoredBeforeShareNetwork)
	if err != nil {
		t.Fatal(err)
	}
	old, err := ParseStoredCanonicalAction(older)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCanonicalActionForServer(old); err != nil {
		t.Errorf("the older bytes on a server path: %v", err)
	}
	if ask, err := ParseAclGrantAction(old.Action); err != nil || ask.share() {
		t.Errorf("the older bytes' ask: %+v, %v", ask, err)
	}
}

// A forward's grant as stored before share_network_id existed: testdata/record/canonical_action.json's bridge_forward
// vector as it stood then, kept here so a later rewrite of that file cannot move it.
const aclTestForwardStoredBeforeShareNetwork = "" +
	"0803408090dab3a5335228736964656361723a35313532353335343535353635373538353935613562356335643565356636" +
	"305a046469616c6004e2011046464646464646464646464646464646ea011047474747474747474747474747474747b202b0" +
	"020000000000000003242424242424242424242424242424242424242424242424c82b01f852b5b19f8eedcffdc8ba5e70bd" +
	"c52614361502b54376a588f3df11cd6bbc8a407517b5ce2536c947afae372336c84a72d85fa537921985c8d29dd6becf64ed" +
	"4edd7ab33a70b7cc364d16d26ba705b5cf7b3ac27f4b496ae2f81bf5d79671f58b90da0d75b7ce65a40863ec16d8de9e8dda" +
	"ef2b702e7d74af254ebccdb31c98510ec136f968159da7a035bf92bc445c01a6d8ee1652ee4669be3ceafbc88488fd593775" +
	"f16a4c6c15dc427fed15446dc6f84916b6ba07f2687decdfe19f20c52355654e9c0620def53b7a2f9d668e397511b182637e" +
	"2fd29174df09add741e6c389ff323af2371b44f1a31c24c9606a39ae3cce47b59a1dfd858892b14c673f9284b52b7de0b457" +
	"bd3ce99e88"

// The filer builds a share's action from its request, the network sealed into the detail's context with the other
// clear fields, and no standing grant covers a share: its requester's own reach to the same sidecar is not the other
// network's.
func TestAclGrantFilerBuildsAShare(t *testing.T) {
	x := newAclShareGrantNet(t, "filer x", nil)
	other := NewId()
	engine := NewAclEngine(x.ownerDevice, nil, nil, nil)
	if err := engine.Install(x.state(t), nil); err != nil {
		t.Fatal(err)
	}
	filer := NewAclGrantFiler(nil, engine)
	filer.details = testActionDetailSealer{}
	ctx := context.Background()
	detail := &protocol.CanonicalActionDetail{TargetPort: aclTestForwardPort}
	base := &protocol.CanonicalAction{Kind: uint32(SidecarActionForward)}
	request := &AclGrantRequest{
		Subject: x.ownerDevice, GrantDst: []string{aclTestDst(x.laptop)}, GrantAllow: []string{"dial"}, Detail: detail, ShareNetworkId: other,
	}
	action, err := filer.Action(ctx, base, request, aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(action.Action.GetShareNetworkId(), other.Bytes()) || !bytes.Equal(action.Action.GetRuleId(), aclTestImplicitSharesRule().Bytes()) ||
		!bytes.Equal(action.Action.GetSubject(), x.ownerDevice.Bytes()) {
		t.Errorf("the share as built: %+v", action.Action)
	}
	if err := CheckCanonicalActionForServer(action); err != nil {
		t.Errorf("the share on a server path: %v", err)
	}
	opened, err := OpenCanonicalActionDetail(action, testActionDetailNetworkId(), testConfigSealKeyAt(testConfigSealKey(testActionDetailGeneration)))
	if err != nil || !proto.Equal(opened, detail) {
		t.Errorf("the share's detail opened to %+v: %v", opened, err)
	}
	// the owner's device already reaches the laptop under the implicit document, which covers no share
	if !x.state(t).Reach(AclSidecarSubject(x.ownerDevice), AclSidecarSubject(x.laptop), aclTestNow).Allowed {
		t.Fatal("the requester does not reach the laptop itself")
	}
	if engine.ActiveGrant(action, x.ownerDevice, aclTestNow) {
		t.Error("a standing grant covers a share")
	}
	// a base may not name the network: the request alone does
	named := &protocol.CanonicalAction{Kind: uint32(SidecarActionForward), ShareNetworkId: other.Bytes()}
	plain := &AclGrantRequest{Subject: x.laptop, GrantDst: []string{aclTestNetworkDst(other)}, GrantAllow: []string{"dial"}, Detail: detail}
	if _, err := filer.Action(ctx, named, plain, aclTestNow); !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a base naming the network for a request that names none: %v", err)
	}
	// the outbound half, a member's device asking reach to the other network
	outbound := &AclGrantRequest{Subject: x.laptop, GrantDst: []string{aclTestNetworkDst(other)}, GrantAllow: []string{"dial"}, Detail: detail, ShareNetworkId: other}
	if action, err := filer.Action(ctx, base, outbound, aclTestNow); err != nil || !bytes.Equal(action.Action.GetShareNetworkId(), other.Bytes()) {
		t.Errorf("the outbound half: %v", err)
	}
}
