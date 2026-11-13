//go:build !ios_extension

// MCP-M3-03's tests. On TEAM's real log: §22.7's decisions row (another requester's decision, an auth_pin off the
// chain, an approver revoked after signing, k = 2), AD3, FS-29's unit form, a self-signed device decision, the
// harness and presence channels, evidenceDefault only where it is held, and the spend check installed as
// AclSpendCheck activating a GrantActivate. Then the gate's field comparison and clock, AD4 by reflection over the
// gate's inputs, every refusal's code on a fixture state, and testdata/record/spend/vectors.json. Pure, on every leg but
// the ios_extension legs.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/record/spend
var testSpendFiles embed.FS

var updateSpendVectors = flag.Bool("update-spend-vectors", false, "rewrite testdata/record/spend/vectors.json")

const testSpendVectorsPath = "testdata/record/spend/vectors.json"

// A spend test network: the owner O, an admin by its role, and its genesis device; member M's laptop, the requester s,
// and phone; and member N's device, each consented and approval-capable.
type testSpendNet struct {
	*testConfigNet
	member      Id
	laptop      testConfigDevice
	phone       testConfigDevice
	other       Id
	otherDevice testConfigDevice
}

// The network, each device checked approval-capable for its member.
func newTestSpendNet(t *testing.T) *testSpendNet {
	t.Helper()
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("spend member")
	// the phone is M's second device, consented by the scoped clause: M's consented laptop signs its admission
	phone := net.device("spend member phone", member)
	net.admitDevice(laptop, phone, 0)
	other, otherDevice := net.consentedMember("spend other")
	self := &testSpendNet{
		testConfigNet: net,
		member:        member,
		laptop:        laptop,
		phone:         phone,
		other:         other,
		otherDevice:   otherDevice,
	}
	acl := self.acl()
	for _, device := range []testConfigDevice{net.owner, laptop, phone, otherDevice} {
		if !acl.ApprovalCapable(device.sidecarId) || !acl.ConsentedFor(device.sidecarId, device.memberId) {
			t.Fatalf("device %s is not approval-capable for its member", device.sidecarId)
		}
	}
	return self
}

// The tip's acl state.
func (self *testSpendNet) acl() *AclState {
	self.t.Helper()
	acl, err := self.log.State().Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	return acl
}

// The tip's spend state, its evidenceDefault as given.
func (self *testSpendNet) spendState(forked bool, evidenceDefault []protocol.ApprovalChannel) *ConfigSpendState {
	self.t.Helper()
	state, err := NewConfigSpendState(self.log.State(), forked, evidenceDefault)
	if err != nil {
		self.t.Fatal(err)
	}
	return state
}

// A spend of action by spender at the tip's time.
func (self *testSpendNet) input(action *StoredCanonicalAction, spender Id) *SpendInput {
	return &SpendInput{Action: action, Spender: spender, Now: time.UnixMilli(self.timeMs)}
}

// A requests rule taking a dial grant to the requester's own devices, approved by approverAtoms, k approvers, and
// any atoms the rule names, by a base at the tip.
func (self *testSpendNet) withDialRule(ruleId []byte, approverAtoms []Id, k uint32, atoms ...*protocol.AclAtom) {
	self.t.Helper()
	self.withDialRuleTo(ruleId, protocol.AclAutogroup_ACL_AUTOGROUP_SELF, approverAtoms, k, atoms...)
}

// withDialRule to the devices an autogroup target names.
func (self *testSpendNet) withDialRuleTo(ruleId []byte, target protocol.AclAutogroup, approverAtoms []Id, k uint32, atoms ...*protocol.AclAtom) {
	self.t.Helper()
	rule := &protocol.AclRequestRule{
		RuleId:    ruleId,
		SrcAtoms:  [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
		Targets:   []*protocol.AclTarget{aclAutogroupTarget(target)},
		Actions:   []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
		Approvers: k,
	}
	for _, atom := range approverAtoms {
		rule.ApproverAtoms = append(rule.ApproverAtoms, atom.Bytes())
	}
	self.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = slices.DeleteFunc(rows.Requests, func(existing *protocol.AclRequestRule) bool {
			return bytes.Equal(existing.GetRuleId(), ruleId)
		})
		rows.Requests = append(rows.Requests, rule)
		for _, atom := range atoms {
			rows.Atoms = slices.DeleteFunc(rows.Atoms, func(existing *protocol.AclAtom) bool {
				return bytes.Equal(existing.GetAtom(), atom.GetAtom())
			})
			rows.Atoms = append(rows.Atoms, atom)
		}
	})
}

// A dns_set action as the daemon builds it: no requests rule names it.
func testSpendDnsAction(t testing.TB, value string) *StoredCanonicalAction {
	t.Helper()
	action, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind:     uint32(SidecarActionDnsSet),
		DnsName:  "www",
		DnsType:  "A",
		DnsValue: value,
		DnsTtl:   300,
	})
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// A bridge_forward grant to dst for subject under the requests rule, as a daemon builds it: version 4, the target's
// port and a port dst names sealed in its detail, its clear grant_dst the target alone (QD-740).
func testSpendGrantAction(t testing.TB, ruleId []byte, subject Id, dst string) *StoredCanonicalAction {
	t.Helper()
	filled := aclTestGrantAction(ruleId, subject, []string{dst}, []string{"dial"}, 0)
	filled.Version = 0
	action, err := NewCanonicalAction(filled)
	if err != nil {
		t.Fatal(err)
	}
	if action.Action.GetVersion() != canonicalActionVersionSealedGrant || bytes.Contains(action.Bytes, []byte(":tcp:")) {
		t.Fatalf("a forward at version %d", action.Action.GetVersion())
	}
	return action
}

// A decision body: approver approves action on channel for requester under approval, at pin, expiring at notAfterMs.
func testSpendDecisionBody(action *StoredCanonicalAction, approvalId Id, approver Id, channel protocol.ApprovalChannel, requester Id,
	pin *bridge.AuthPin, notAfterMs int64) *protocol.ApprovalDecision {
	payload := action.PayloadSha256()
	requestSha256 := sha256.Sum256(append([]byte("spend test request "), approvalId[:]...))
	body := &protocol.ApprovalDecision{
		ApprovalId:         approvalId.Bytes(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payload[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     notAfterMs,
		ApproverMemberId:   approver.Bytes(),
		Channel:            uint32(channel),
		RequesterSidecarId: requester.Bytes(),
		AuthPin:            pin,
		Version:            1,
	}
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
		evidence := sha256.Sum256(append([]byte("spend test hook event "), approvalId[:]...))
		body.EvidenceSha256 = evidence[:]
	}
	return body
}

// body as a Signed by a sidecar's identity key, signer_id its sidecar_id.
func testSpendSignedBy(t testing.TB, sidecarId Id, key ed25519.PrivateKey, body *protocol.ApprovalDecision) *bridge.Signed {
	bodyBytes := testConfigMarshal(t, body)
	return &bridge.Signed{
		Body:      bodyBytes,
		SignerId:  sidecarId.Bytes(),
		Signature: ed25519.Sign(key, bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, bodyBytes)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	}
}

// body as a Signed by a presence key, key_id its KeyRegister's.
func testSpendSignedByPresence(t testing.TB, key *testPresenceKey, body *protocol.ApprovalDecision) *bridge.Signed {
	return key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testConfigMarshal(t, body))
}

// A Signed decision parsed as the spender and every gate parse it.
func testSpendParse(t testing.TB, signed *bridge.Signed) *StoredApprovalDecision {
	t.Helper()
	decision, err := ParseSignedApprovalDecision(signed)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

// A device's decision at the tip's pin, an hour from the tip's time.
func (self *testSpendNet) deviceDecision(device testConfigDevice, action *StoredCanonicalAction, approvalId Id, approver Id, requester Id) *StoredApprovalDecision {
	self.t.Helper()
	body := testSpendDecisionBody(action, approvalId, approver, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, requester,
		self.log.State().Pin(), self.timeMs+testConfigHourMs)
	return testSpendParse(self.t, testSpendSignedBy(self.t, device.sidecarId, device.key, body))
}

// Fails the test unless err is a refusal with want, or nil for an empty want.
func testSpendExpect(t testing.TB, name string, err error, want SpendRefusalCode) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		return
	}
	if !errors.Is(err, ErrSpendRefused) || SpendRefusalCodeOf(err) != want {
		t.Errorf("%s: %v, want %s", name, err, want)
	}
}

// §22.7's decisions row: S2 presenting S1's unspent decision for one sponsor and one action is refused by the daemon
// and the gate (AD1), while S1 spends it.
func TestSpendRefusesAnotherRequestersDecision(t *testing.T) {
	net := newTestSpendNet(t)
	action := testSpendDnsAction(t, "192.0.2.10")
	decision := net.deviceDecision(net.phone, action, NewId(), net.member, net.laptop.sidecarId)
	state := net.spendState(false, spendAllChannels)

	testSpendExpect(t, "S1", Spendable(decision, net.input(action, net.laptop.sidecarId), state, nil), "")
	testSpendExpect(t, "S2 at the daemon", Spendable(decision, net.input(action, net.otherDevice.sidecarId), state, nil), SpendRefusalRequester)
	fields := &SpendGateFields{Kind: SidecarActionDnsSet, DnsName: "www", DnsType: "A", DnsValue: "192.0.2.10", DnsTtl: 300}
	_, err := SpendableAtGate([]*StoredApprovalDecision{decision}, net.input(action, net.otherDevice.sidecarId), fields, state)
	testSpendExpect(t, "S2 at the gate", err, SpendRefusalRequester)
}

// §22.7's decisions row: a decision whose auth_pin digest differs from the spender's retained one is refused, and so
// is one ahead of P; one at a position P no longer retains checks its number alone.
func TestSpendRefusesAnAuthPinOffTheChain(t *testing.T) {
	net := newTestSpendNet(t)
	action := testSpendDnsAction(t, "192.0.2.11")
	state := net.spendState(false, spendAllChannels)
	pin := net.log.State().Pin()
	sign := func(decisionPin *bridge.AuthPin) *StoredApprovalDecision {
		body := testSpendDecisionBody(action, NewId(), net.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
			net.laptop.sidecarId, decisionPin, net.timeMs+testConfigHourMs)
		return testSpendParse(t, testSpendSignedBy(t, net.phone.sidecarId, net.phone.key, body))
	}
	input := net.input(action, net.laptop.sidecarId)

	testSpendExpect(t, "at P", Spendable(sign(pin), input, state, nil), "")
	retainedChain, retained := state.ChainAt(pin.GetVersion() - 1)
	if !retained {
		t.Fatal("P does not retain the position before it")
	}
	testSpendExpect(t, "a retained position", Spendable(sign(&bridge.AuthPin{Version: pin.GetVersion() - 1, Chain: retainedChain[:]}), input, state, nil), "")
	offChain := sha256.Sum256([]byte("another chain"))
	testSpendExpect(t, "a digest off the chain", Spendable(sign(&bridge.AuthPin{Version: pin.GetVersion() - 1, Chain: offChain[:]}), input, state, nil), SpendRefusalPin)
	testSpendExpect(t, "ahead of P", Spendable(sign(&bridge.AuthPin{Version: pin.GetVersion() + 1, Chain: offChain[:]}), input, state, nil), SpendRefusalPin)
	testSpendExpect(t, "a short chain", Spendable(sign(&bridge.AuthPin{Version: pin.GetVersion(), Chain: offChain[:16]}), input, state, nil), SpendRefusalPin)

	// a base whose previous base is past the decision's position: P keeps no digest there, so only its number checks
	early := sign(pin)
	earlyOff := sign(&bridge.AuthPin{Version: 2, Chain: offChain[:]})
	net.fold(net.owner, net.n, 2)
	net.fold(net.owner, net.n, 3)
	later := net.spendState(false, spendAllChannels)
	if _, retained := later.ChainAt(2); retained {
		t.Fatal("the later state still retains position 2")
	}
	laterInput := net.input(action, net.laptop.sidecarId)
	testSpendExpect(t, "a pin P no longer retains", Spendable(early, laterInput, later, nil), "")
	testSpendExpect(t, "an unretained position checks its number alone", Spendable(earlyOff, laterInput, later, nil), "")
}

// §22.7's decisions row: an approver revoked after signing approves nothing, whether its device is revoked or the
// member removed.
func TestSpendApproverRevokedAfterSigningApprovesNothing(t *testing.T) {
	net := newTestSpendNet(t)
	action := testSpendDnsAction(t, "192.0.2.12")
	decision := net.deviceDecision(net.phone, action, NewId(), net.member, net.laptop.sidecarId)
	testSpendExpect(t, "before", Spendable(decision, net.input(action, net.laptop.sidecarId), net.spendState(false, spendAllChannels), nil), "")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	testSpendExpect(t, "its device revoked", Spendable(decision, net.input(action, net.laptop.sidecarId), net.spendState(false, spendAllChannels), nil), SpendRefusalSigner)

	// a grant member N approved through the rule's group, N removed after
	ruleId := testConfigId("spend group rule").Bytes()
	group := testConfigId("spend group")
	net.withDialRule(ruleId, []Id{group}, 1, &protocol.AclAtom{Atom: group.Bytes(), MemberIds: [][]byte{net.other.Bytes()}})
	grant := testSpendGrantAction(t, ruleId, net.laptop.sidecarId, aclTestDst(net.laptop.sidecarId)+":tcp:22")
	otherDecision := net.deviceDecision(net.otherDevice, grant, NewId(), net.other, net.laptop.sidecarId)
	testSpendExpect(t, "N's, before", Spendable(otherDecision, net.input(grant, net.laptop.sidecarId), net.spendState(false, nil), nil), "")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: net.other.Bytes()})
	testSpendExpect(t, "N removed", Spendable(otherDecision, net.input(grant, net.laptop.sidecarId), net.spendState(false, nil), nil), SpendRefusalSigner)
}

// §22.7's decisions row at k = 2: one approver's and one non-eligible signer's decisions are refused, two eligible
// approvers' pass, the budget the smaller uses and the earlier expiry; one approver twice and two requests refused.
func TestSpendNeedsTwoEligibleApproversAtTwo(t *testing.T) {
	net := newTestSpendNet(t)
	ruleId := testConfigId("spend k two rule").Bytes()
	group := testConfigId("spend k two group")
	net.withDialRule(ruleId, []Id{group}, 2, &protocol.AclAtom{Atom: group.Bytes(), MemberIds: [][]byte{net.ownerMemberId.Bytes(), net.other.Bytes()}})
	grant := testSpendGrantAction(t, ruleId, net.laptop.sidecarId, aclTestDst(net.phone.sidecarId)+":tcp:22")
	approvalId := NewId()
	state := net.spendState(false, nil)
	input := net.input(grant, net.laptop.sidecarId)
	sign := func(device testConfigDevice, approver Id, uses uint32, notAfterMs int64) *StoredApprovalDecision {
		body := testSpendDecisionBody(grant, approvalId, approver, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
			net.laptop.sidecarId, net.log.State().Pin(), notAfterMs)
		body.Uses = uses
		return testSpendParse(t, testSpendSignedBy(t, device.sidecarId, device.key, body))
	}
	owner := sign(net.owner, net.ownerMemberId, 1, net.timeMs+2*testConfigHourMs)
	admin := sign(net.otherDevice, net.other, 1, net.timeMs+testConfigHourMs)
	notEligible := sign(net.phone, net.member, 1, net.timeMs+testConfigHourMs)

	_, err := SpendableSet([]*StoredApprovalDecision{owner}, input, state, nil)
	testSpendExpect(t, "one approver", err, SpendRefusalQuorum)
	_, err = SpendableSet([]*StoredApprovalDecision{owner, notEligible}, input, state, nil)
	testSpendExpect(t, "one approver and one non-eligible signer", err, SpendRefusalApprover)
	budget, err := SpendableSet([]*StoredApprovalDecision{owner, admin}, input, state, nil)
	testSpendExpect(t, "two eligible approvers", err, "")
	if budget == nil || budget.Uses != 1 || budget.NotAfterMillis != net.timeMs+testConfigHourMs || len(budget.ApproverMemberIds) != 2 ||
		budget.ApprovalId != approvalId {
		t.Errorf("the budget %+v", budget)
	}
	_, err = SpendableSet([]*StoredApprovalDecision{owner, sign(net.owner, net.ownerMemberId, 1, net.timeMs+testConfigHourMs)}, input, state, nil)
	testSpendExpect(t, "one approver twice", err, SpendRefusalSet)
	otherRequest := testSpendDecisionBody(grant, NewId(), net.other, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		net.laptop.sidecarId, net.log.State().Pin(), net.timeMs+testConfigHourMs)
	_, err = SpendableSet([]*StoredApprovalDecision{owner, testSpendParse(t, testSpendSignedBy(t, net.otherDevice.sidecarId, net.otherDevice.key, otherRequest))}, input, state, nil)
	testSpendExpect(t, "two requests", err, SpendRefusalSet)
	// one decision alone at k = 2 is refused by the set check, never by Spendable, which judges one decision
	testSpendExpect(t, "one decision judged alone", Spendable(owner, input, state, nil), "")
}

// §8.6's admin clause on the log: a grant reaching another member's device needs an admin's approval whatever the
// rule says, the owner's counting though the rule names only the requester's owner, unless the touched member approves
// as autogroup:dst-owner for reach to its own device (owner decision 180).
func TestSpendAdminClauseOnTheLog(t *testing.T) {
	net := newTestSpendNet(t)
	selfRule := testConfigId("spend admin clause rule").Bytes()
	net.withDialRuleTo(selfRule, protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 1)
	grant := testSpendGrantAction(t, selfRule, net.laptop.sidecarId, aclTestDst(net.otherDevice.sidecarId))
	approvalId := NewId()
	state := net.spendState(false, nil)
	input := net.input(grant, net.laptop.sidecarId)
	own := net.deviceDecision(net.phone, grant, approvalId, net.member, net.laptop.sidecarId)
	owner := net.deviceDecision(net.owner, grant, approvalId, net.ownerMemberId, net.laptop.sidecarId)
	_, err := SpendableSet([]*StoredApprovalDecision{own}, input, state, nil)
	testSpendExpect(t, "the requester's owner alone", err, SpendRefusalQuorum)
	_, err = SpendableSet([]*StoredApprovalDecision{own, owner}, input, state, nil)
	testSpendExpect(t, "with the owner's", err, "")
	testSpendExpect(t, "the owner's alone, eligible by the clause", Spendable(owner, input, state, nil), "")

	dstOwnerRule := testConfigId("spend dst-owner rule").Bytes()
	net.withDialRuleTo(dstOwnerRule, protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER)}, 1)
	reach := testSpendGrantAction(t, dstOwnerRule, net.laptop.sidecarId, aclTestDst(net.otherDevice.sidecarId))
	touched := net.deviceDecision(net.otherDevice, reach, NewId(), net.other, net.laptop.sidecarId)
	_, err = SpendableSet([]*StoredApprovalDecision{touched}, net.input(reach, net.laptop.sidecarId), net.spendState(false, nil), nil)
	testSpendExpect(t, "the destination's owner as autogroup:dst-owner", err, "")
}

// AD3: a decision evaluated on a projection the spender knows to be forked is refused, before anything else.
func TestSpendRefusesOnAForkedProjection(t *testing.T) {
	net := newTestSpendNet(t)
	action := testSpendDnsAction(t, "192.0.2.13")
	decision := net.deviceDecision(net.phone, action, NewId(), net.member, net.laptop.sidecarId)
	testSpendExpect(t, "unforked", Spendable(decision, net.input(action, net.laptop.sidecarId), net.spendState(false, spendAllChannels), nil), "")
	testSpendExpect(t, "forked", Spendable(decision, net.input(action, net.laptop.sidecarId), net.spendState(true, spendAllChannels), nil), SpendRefusalForked)
	other := net.deviceDecision(net.phone, action, NewId(), net.member, net.otherDevice.sidecarId)
	testSpendExpect(t, "forked before another requester", Spendable(other, net.input(action, net.laptop.sidecarId), net.spendState(true, spendAllChannels), nil), SpendRefusalForked)
	_, err := SpendableSet([]*StoredApprovalDecision{decision}, net.input(action, net.laptop.sidecarId), net.spendState(true, spendAllChannels), nil)
	testSpendExpect(t, "a forked set", err, SpendRefusalForked)
}

// FS-29's unit form: an approval evaluated under pin P; the pin moves to P', whose group no longer holds its
// approver: the approval authorizes nothing under P'.
func TestSpendApprovalUnderAPinThatDropsItsApprover(t *testing.T) {
	net := newTestSpendNet(t)
	ruleId := testConfigId("spend fs-29 rule").Bytes()
	group := testConfigId("spend fs-29 group")
	approvers := &protocol.AclAtom{Atom: group.Bytes(), MemberIds: [][]byte{net.ownerMemberId.Bytes(), net.other.Bytes()}}
	net.withDialRule(ruleId, []Id{group}, 1, approvers)
	grant := testSpendGrantAction(t, ruleId, net.laptop.sidecarId, aclTestDst(net.phone.sidecarId))
	decision := net.deviceDecision(net.otherDevice, grant, NewId(), net.other, net.laptop.sidecarId)
	testSpendExpect(t, "under P", Spendable(decision, net.input(grant, net.laptop.sidecarId), net.spendState(false, nil), nil), "")

	net.withDialRule(ruleId, []Id{group}, 1, &protocol.AclAtom{Atom: group.Bytes(), MemberIds: [][]byte{net.ownerMemberId.Bytes()}})
	testSpendExpect(t, "under P'", Spendable(decision, net.input(grant, net.laptop.sidecarId), net.spendState(false, nil), nil), SpendRefusalApprover)

	// and a P'' whose head deleted the rule: no rule governs the grant
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = nil
	})
	testSpendExpect(t, "the rule gone", Spendable(decision, net.input(grant, net.laptop.sidecarId), net.spendState(false, nil), nil), SpendRefusalRule)
}

// A device decision the spender signed itself is refused, as is one by a device of another member or a harness
// decision another sidecar signed.
func TestSpendRefusesASelfSignedDeviceDecision(t *testing.T) {
	net := newTestSpendNet(t)
	action := testSpendDnsAction(t, "192.0.2.14")
	state := net.spendState(false, spendAllChannels)
	input := net.input(action, net.laptop.sidecarId)
	testSpendExpect(t, "self-signed", Spendable(net.deviceDecision(net.laptop, action, NewId(), net.member, net.laptop.sidecarId), input, state, nil), SpendRefusalSigner)
	testSpendExpect(t, "another member's device", Spendable(net.deviceDecision(net.otherDevice, action, NewId(), net.member, net.laptop.sidecarId), input, state, nil), SpendRefusalSigner)
	harness := testSpendDecisionBody(action, NewId(), net.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS, net.laptop.sidecarId,
		net.log.State().Pin(), net.timeMs+testConfigHourMs)
	testSpendExpect(t, "harness by another sidecar", Spendable(testSpendParse(t, testSpendSignedBy(t, net.phone.sidecarId, net.phone.key, harness)), input, state, nil), SpendRefusalSigner)
}

// The harness channel: s itself signs for its own member, so a harness decision naming another member as approver is
// refused; and the presence channel: a key registered to the approver signs, a key of another member's does not.
func TestSpendHarnessAndPresenceChannels(t *testing.T) {
	net := newTestSpendNet(t)
	action := testSpendDnsAction(t, "192.0.2.15")
	harness := protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS
	presence := protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE
	key := newTestPresenceKey(t, "spend member presence", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	net.registerPresenceKey(net.phone, key)
	otherKey := newTestPresenceKey(t, "spend other presence", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	net.registerPresenceKey(net.otherDevice, otherKey)
	state := net.spendState(false, spendAllChannels)
	input := net.input(action, net.laptop.sidecarId)
	pin := net.log.State().Pin()
	notAfter := net.timeMs + testConfigHourMs

	ownHarness := testSpendDecisionBody(action, NewId(), net.member, harness, net.laptop.sidecarId, pin, notAfter)
	testSpendExpect(t, "harness", Spendable(testSpendParse(t, testSpendSignedBy(t, net.laptop.sidecarId, net.laptop.key, ownHarness)), input, state, nil), "")
	otherApprover := testSpendDecisionBody(action, NewId(), net.other, harness, net.laptop.sidecarId, pin, notAfter)
	testSpendExpect(t, "harness for another member", Spendable(testSpendParse(t, testSpendSignedBy(t, net.laptop.sidecarId, net.laptop.key, otherApprover)), input, state, nil), SpendRefusalSigner)

	ownPresence := testSpendDecisionBody(action, NewId(), net.member, presence, net.laptop.sidecarId, pin, notAfter)
	testSpendExpect(t, "presence", Spendable(testSpendParse(t, testSpendSignedByPresence(t, key, ownPresence)), input, state, nil), "")
	testSpendExpect(t, "presence again, no counter compared", Spendable(testSpendParse(t, testSpendSignedByPresence(t, key, ownPresence)), input, state, nil), "")
	testSpendExpect(t, "another member's key", Spendable(testSpendParse(t, testSpendSignedByPresence(t, otherKey, ownPresence)), input, state, nil), SpendRefusalSigner)
	forgedPresence := testSpendSignedByPresence(t, key, ownPresence)
	forgedPresence.Body = testConfigMarshal(t, testSpendDecisionBody(action, NewId(), net.member, presence, net.laptop.sidecarId, pin, notAfter))
	testSpendExpect(t, "presence over other bytes", Spendable(testSpendParse(t, forgedPresence), input, state, nil), SpendRefusalSignature)
}

// An action no requests rule names takes the document's evidenceDefault, which only a verifier holding the compiled
// policy knows: a rows-only verifier refuses every channel, and a daemon's narrower default refuses what it omits.
func TestSpendEvidenceDefaultOnlyWhereHeld(t *testing.T) {
	net := newTestSpendNet(t)
	action := testSpendDnsAction(t, "192.0.2.16")
	device := net.deviceDecision(net.phone, action, NewId(), net.member, net.laptop.sidecarId)
	harnessBody := testSpendDecisionBody(action, NewId(), net.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS, net.laptop.sidecarId,
		net.log.State().Pin(), net.timeMs+testConfigHourMs)
	harness := testSpendParse(t, testSpendSignedBy(t, net.laptop.sidecarId, net.laptop.key, harnessBody))
	input := net.input(action, net.laptop.sidecarId)

	testSpendExpect(t, "rows only", Spendable(device, input, net.spendState(false, nil), nil), SpendRefusalEvidenceUnknown)
	deviceOnly := net.spendState(false, []protocol.ApprovalChannel{protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE})
	testSpendExpect(t, "device under a device default", Spendable(device, input, deviceOnly, nil), "")
	testSpendExpect(t, "harness under a device default", Spendable(harness, input, deviceOnly, nil), SpendRefusalEvidence)
	// another member is no approver of s's own action, whose approvers are its owner or sponsor (§8.6's default)
	otherBody := testSpendDecisionBody(action, NewId(), net.other, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, net.laptop.sidecarId,
		net.log.State().Pin(), net.timeMs+testConfigHourMs)
	other := testSpendParse(t, testSpendSignedBy(t, net.otherDevice.sidecarId, net.otherDevice.key, otherBody))
	testSpendExpect(t, "another member approving", Spendable(other, input, deviceOnly, nil), SpendRefusalApprover)
	if _, err := NewConfigSpendState(net.log.State(), false, []protocol.ApprovalChannel{protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED}); !errors.Is(err, ErrSpendStateInvalid) {
		t.Errorf("an unknown channel in evidenceDefault: %v", err)
	}
}

// A use already reserved skips the expiry test (spend step 1), and the gate allows no skew past not_after while a
// client allows §8.6's 60 s.
func TestSpendExpiryReservedAndAtTheGate(t *testing.T) {
	net := newTestSpendNet(t)
	action := testSpendDnsAction(t, "192.0.2.17")
	state := net.spendState(false, spendAllChannels)
	body := testSpendDecisionBody(action, NewId(), net.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, net.laptop.sidecarId,
		net.log.State().Pin(), net.timeMs)
	decision := testSpendParse(t, testSpendSignedBy(t, net.phone.sidecarId, net.phone.key, body))
	within := &SpendInput{Action: action, Spender: net.laptop.sidecarId, Now: time.UnixMilli(net.timeMs + 30*1000)}
	past := &SpendInput{Action: action, Spender: net.laptop.sidecarId, Now: time.UnixMilli(net.timeMs + 61*1000)}
	reserved := &SpendInput{Action: action, Spender: net.laptop.sidecarId, Now: time.UnixMilli(net.timeMs + 11*60*1000), Reserved: true}

	testSpendExpect(t, "within the skew", Spendable(decision, within, state, nil), "")
	testSpendExpect(t, "past the skew", Spendable(decision, past, state, nil), SpendRefusalExpired)
	testSpendExpect(t, "reserved", Spendable(decision, reserved, state, nil), "")
	noSkew := DefaultSpendSettings()
	noSkew.DecisionSkew = 0
	testSpendExpect(t, "no skew", Spendable(decision, within, state, noSkew), SpendRefusalExpired)
	fields := &SpendGateFields{Kind: SidecarActionDnsSet, DnsName: "www", DnsType: "A", DnsValue: "192.0.2.17", DnsTtl: 300}
	_, err := SpendableAtGate([]*StoredApprovalDecision{decision}, within, fields, state)
	testSpendExpect(t, "the gate within a client's skew", err, SpendRefusalExpired)
	_, err = SpendableAtGate([]*StoredApprovalDecision{decision}, &SpendInput{Action: action, Spender: net.laptop.sidecarId, Now: time.UnixMilli(net.timeMs)}, fields, state)
	testSpendExpect(t, "the gate at not_after", err, "")
}

// The spend check installed as ACL-M2-07's AclSpendCheck: a GrantActivate whose decision spends activates its grant
// through TEAM's log, and one carrying a self-signed device decision is refused there with the spend refusal.
func TestSpendCheckActivatesAGrant(t *testing.T) {
	net := newTestSpendNet(t)
	net.log.settings.AclSpendCheck = NewSpendCheck(nil)
	ruleId := testConfigId("spend activate rule").Bytes()
	net.withDialRule(ruleId, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 1)
	activate := func(device testConfigDevice) *protocol.GrantActivate {
		grant := testSpendGrantAction(t, ruleId, net.laptop.sidecarId, aclTestDst(net.phone.sidecarId))
		approvalId := NewId()
		decision := net.deviceDecision(device, grant, approvalId, net.member, net.laptop.sidecarId)
		grantId := AclGrantId(approvalId, grant.PayloadSha256())
		return &protocol.GrantActivate{
			Header: net.header(), GrantId: grantId[:], CanonicalAction: grant.Bytes, Decisions: []*bridge.Signed{decision.Signed},
		}
	}
	net.mustPost(net.laptop, bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate(net.phone))
	if !net.acl().Reach(AclSidecarSubject(net.laptop.sidecarId), AclSidecarSubject(net.phone.sidecarId), time.UnixMilli(net.timeMs)).Allowed {
		t.Error("the activated grant does not reach")
	}
	verdict := net.post(net.laptop, bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate(net.laptop))
	if verdict.Accepted() || !errors.Is(verdict.Refusal, ErrSpendRefused) {
		t.Errorf("a self-signed decision's activation: %v", verdict.Refusal)
	}

	// a state over a view that holds no keys refuses, as does a pin other than the state's
	fixture := newAclStatementCast().fixture
	fakeState := fixture.state(t)
	grant := testSpendGrantAction(t, ruleId, net.laptop.sidecarId, aclTestDst(net.phone.sidecarId))
	decision := net.deviceDecision(net.phone, grant, NewId(), net.member, net.laptop.sidecarId)
	err := NewSpendCheck(nil).Spendable(fakeState, decision, grant, net.laptop.sidecarId, fakeState.Pin(), time.UnixMilli(net.timeMs))
	testSpendExpect(t, "a view that holds no keys", err, SpendRefusalState)
	err = NewSpendCheck(nil).Spendable(net.acl(), decision, grant, net.laptop.sidecarId, &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)}, time.UnixMilli(net.timeMs))
	testSpendExpect(t, "a pin other than the state's", err, SpendRefusalState)
}

// The gate clause: every field a gate sees must equal its request's, the action may carry none its server column
// leaves out, and only a gated kind compares.
func TestGateFieldsMustEqualRequest(t *testing.T) {
	dns := testSpendDnsAction(t, "192.0.2.18")
	dnsFields := func() *SpendGateFields {
		return &SpendGateFields{Kind: SidecarActionDnsSet, DnsName: "www", DnsType: "A", DnsValue: "192.0.2.18", DnsTtl: 300}
	}
	if err := CheckSpendGateFields(dns, dnsFields()); err != nil {
		t.Errorf("equal dns fields: %v", err)
	}
	for _, change := range []func(fields *SpendGateFields){
		func(fields *SpendGateFields) { fields.DnsName = "mail" },
		func(fields *SpendGateFields) { fields.DnsType = "AAAA" },
		func(fields *SpendGateFields) { fields.DnsValue = "192.0.2.19" },
		func(fields *SpendGateFields) { fields.DnsTtl = 60 },
		func(fields *SpendGateFields) { fields.Kind = SidecarActionDnsDelete },
	} {
		fields := dnsFields()
		change(fields)
		testSpendExpect(t, "a dns field changed", CheckSpendGateFields(dns, fields), SpendRefusalGateField)
	}
	deleteAction, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionDnsDelete), DnsName: "www", DnsType: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckSpendGateFields(deleteAction, &SpendGateFields{Kind: SidecarActionDnsDelete, DnsName: "www", DnsType: "A", DnsValue: "any", DnsTtl: 5}); err != nil {
		t.Errorf("a delete naming only its name and type: %v", err)
	}

	publish, err := ParseStoredCanonicalAction(testConfigMarshal(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionPublish), Version: 1, Host: "app.example", Port: 443,
		Audience: uint32(protocol.AclAudience_ACL_AUDIENCE_MEMBERS), ExpiresMillis: 1_900_000_000_000, AppMode: 1,
	}))
	if err != nil {
		t.Fatal(err)
	}
	publishFields := func() *SpendGateFields {
		return &SpendGateFields{Kind: SidecarActionPublish, Host: "app.example", Port: 443, ExpiresMillis: 1_900_000_000_000}
	}
	if err := CheckSpendGateFields(publish, publishFields()); err != nil {
		t.Errorf("equal publish fields, a request's audience 0 as members: %v", err)
	}
	for _, change := range []func(fields *SpendGateFields){
		func(fields *SpendGateFields) { fields.Host = "other.example" },
		func(fields *SpendGateFields) { fields.Port = 8443 },
		func(fields *SpendGateFields) { fields.Audience = uint32(protocol.AclAudience_ACL_AUDIENCE_PUBLIC) },
		func(fields *SpendGateFields) { fields.ExpiresMillis = 1_900_000_000_001 },
	} {
		fields := publishFields()
		change(fields)
		testSpendExpect(t, "a publish field changed", CheckSpendGateFields(publish, fields), SpendRefusalGateField)
	}

	// a field outside the kind's server column, and a kind no server path takes
	withPreview, err := ParseStoredCanonicalAction(testConfigMarshal(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionDnsSet), Version: 1, DnsName: "www", DnsType: "A", DnsValue: "192.0.2.18", DnsTtl: 300, Preview: "words",
	}))
	if err != nil {
		t.Fatal(err)
	}
	testSpendExpect(t, "a preview on a dns action", CheckSpendGateFields(withPreview, dnsFields()), SpendRefusalGateField)
	mail, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Recipients: []string{"someone@example.com"}, BodySha256: make([]byte, 32), Alias: "me",
	})
	if err != nil {
		t.Fatal(err)
	}
	testSpendExpect(t, "a mail action", CheckSpendGateFields(mail, &SpendGateFields{Kind: SidecarActionMail}), SpendRefusalGateField)
}

// AD4: a gate's inputs hold no run id, agent id, recipient or preview, so neither the gate's entry point, the spend
// check's input nor SpendState and SpendRule take one. CanonicalAction is the one message that names recipients and
// a preview, and its server column keeps every gated action from carrying them (TestGateFieldsMustEqualRequest).
func TestAd4NoRunOrAgentInInputs(t *testing.T) {
	forbidden := []string{"run", "agent", "recipient", "preview"}
	canonicalAction := reflect.TypeOf(protocol.CanonicalAction{})
	seen := map[reflect.Type]bool{}
	var walk func(path string, typ reflect.Type)
	walk = func(path string, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array || typ.Kind() == reflect.Map {
			if typ.Kind() == reflect.Map {
				walk(path+"[key]", typ.Key())
			}
			typ = typ.Elem()
		}
		if seen[typ] || typ == canonicalAction || !strings.HasPrefix(typ.PkgPath(), "github.com/urnetwork/sidecar") {
			return
		}
		seen[typ] = true
		check := func(name string) {
			for _, word := range forbidden {
				if strings.Contains(strings.ToLower(name), word) {
					t.Errorf("%s.%s names a %s", path, name, word)
				}
			}
		}
		check(typ.Name())
		if typ.Kind() == reflect.Interface {
			for i := 0; i < typ.NumMethod(); i += 1 {
				method := typ.Method(i)
				check(method.Name)
				for j := 0; j < method.Type.NumIn(); j += 1 {
					walk(path+"."+method.Name, method.Type.In(j))
				}
				for j := 0; j < method.Type.NumOut(); j += 1 {
					walk(path+"."+method.Name, method.Type.Out(j))
				}
			}
			return
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i += 1 {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			check(field.Name)
			walk(path+"."+field.Name, field.Type)
		}
	}
	gate := reflect.TypeOf(SpendableAtGate)
	for i := 0; i < gate.NumIn(); i += 1 {
		walk("SpendableAtGate", gate.In(i))
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(SpendInput{}), reflect.TypeOf((*SpendState)(nil)).Elem(), reflect.TypeOf((*SpendRule)(nil)).Elem()} {
		walk(typ.Name(), typ)
	}
	if !seen[reflect.TypeOf(protocol.ApprovalDecision{})] || !seen[reflect.TypeOf(SpendGateFields{})] {
		t.Error("the walk missed the decision or the gate's fields")
	}
	if err := CheckCanonicalActionForServer(testSpendMailAction(t)); err == nil {
		t.Error("a mail action, which carries recipients and a preview, passes a server path")
	}
}

// A mail_send action with recipients and a preview.
func testSpendMailAction(t testing.TB) *StoredCanonicalAction {
	t.Helper()
	action, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Recipients: []string{"someone@example.com"}, BodySha256: make([]byte, 32), Alias: "me", Preview: "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// A SpendState from fixed facts, for the vectors and every refusal's code.
type testSpendFixtureState struct {
	pin             *bridge.AuthPin
	chains          map[uint64][sha256.Size]byte
	forked          bool
	identityKeys    map[Id][]byte
	approvalCapable map[[2]Id]bool
	presenceKeys    []*bridge.KeyRow
	rule            *testSpendFixtureRule
}

// The fixture's governing rule.
type testSpendFixtureRule struct {
	refused       bool
	evidence      []protocol.ApprovalChannel
	evidenceKnown bool
	count         int
	eligible      []Id
	admins        []Id
	adminNeeded   bool
}

// The fixture's pin.
func (self *testSpendFixtureState) Pin() *bridge.AuthPin {
	return self.pin
}

// The fixture's retained digest at version.
func (self *testSpendFixtureState) ChainAt(version uint64) ([sha256.Size]byte, bool) {
	chain, ok := self.chains[version]
	return chain, ok
}

// Whether the fixture says forked.
func (self *testSpendFixtureState) Forked() bool {
	return self.forked
}

// The fixture's key of the sidecar.
func (self *testSpendFixtureState) IdentityKey(sidecarId Id) []byte {
	return self.identityKeys[sidecarId]
}

// Whether the fixture lists the pair.
func (self *testSpendFixtureState) ApprovalCapable(sidecarId Id, memberId Id) bool {
	return self.approvalCapable[[2]Id{sidecarId, memberId}]
}

// The fixture's row of key_id when it is the member's.
func (self *testSpendFixtureState) PresenceKey(keyId []byte, memberId Id) *bridge.KeyRow {
	for _, key := range self.presenceKeys {
		if bytes.Equal(key.GetKeyId(), keyId) && bytes.Equal(key.GetMemberId(), memberId.Bytes()) {
			return key
		}
	}
	return nil
}

// The fixture's rule, or a refusal where it says so.
func (self *testSpendFixtureState) Govern(action *StoredCanonicalAction, spender Id, now time.Time) (SpendRule, error) {
	if self.rule.refused {
		return nil, ErrAclRequestNoMatch
	}
	return self.rule, nil
}

// The fixture's list and whether it is known.
func (self *testSpendFixtureRule) Evidence() ([]protocol.ApprovalChannel, bool) {
	return self.evidence, self.evidenceKnown
}

// The fixture's k.
func (self *testSpendFixtureRule) ApproverCount() int {
	return self.count
}

// Listed eligible, or an admin where the clause applies.
func (self *testSpendFixtureRule) Eligible(memberId Id) bool {
	return slices.Contains(self.eligible, memberId) || (self.adminNeeded && slices.Contains(self.admins, memberId))
}

// An admin among them where the clause applies.
func (self *testSpendFixtureRule) AdminClauseMet(memberIds []Id) bool {
	return !self.adminNeeded || slices.ContainsFunc(memberIds, func(memberId Id) bool { return slices.Contains(self.admins, memberId) })
}

// One vector: a state, the decisions as Signeds, the action as stored, the spender, the time and the code it ends in.
type testSpendVectorCase struct {
	name      string
	state     *testSpendFixtureState
	decisions []*bridge.Signed
	action    []byte
	spender   Id
	nowMs     int64
	reserved  bool
	set       bool
	refusal   SpendRefusalCode
}

// The fixture world the vectors share: member M, its requester laptop s and phone d, member N with device e, an
// admin A with device f, a presence key of M's, a pin at 7 retaining 5 to 7, and a dns_set action.
type testSpendWorld struct {
	member, other, admin        Id
	laptop, phone, otherDevice  Id
	adminDevice                 Id
	keys                        map[Id]ed25519.PrivateKey
	presence                    *testPresenceKey
	pin                         *bridge.AuthPin
	chains                      map[uint64][sha256.Size]byte
	action                      *StoredCanonicalAction
	template                    *StoredCanonicalAction
	nowMs                       int64
	approvalId, otherApprovalId Id
}

// The world, its keys from fixed seeds.
func newTestSpendWorld(t testing.TB) *testSpendWorld {
	world := &testSpendWorld{
		member:          testConfigId("spend vector member"),
		other:           testConfigId("spend vector other"),
		admin:           testConfigId("spend vector admin"),
		laptop:          testConfigId("spend vector laptop"),
		phone:           testConfigId("spend vector phone"),
		otherDevice:     testConfigId("spend vector other device"),
		adminDevice:     testConfigId("spend vector admin device"),
		keys:            map[Id]ed25519.PrivateKey{},
		presence:        newTestPresenceKey(t, "spend vector presence", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256),
		chains:          map[uint64][sha256.Size]byte{},
		action:          testSpendDnsAction(t, "192.0.2.20"),
		nowMs:           testConfigStartMs + 100*1000,
		approvalId:      testConfigId("spend vector approval"),
		otherApprovalId: testConfigId("spend vector other approval"),
	}
	for _, sidecarId := range []Id{world.laptop, world.phone, world.otherDevice, world.adminDevice} {
		world.keys[sidecarId] = testConfigDeviceKey("spend vector " + sidecarId.String())
	}
	for version := uint64(5); version <= 7; version += 1 {
		world.chains[version] = sha256.Sum256([]byte{byte(version)})
	}
	chain := world.chains[7]
	world.pin = &bridge.AuthPin{Version: 7, Chain: chain[:]}
	template, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionDnsSet), Scope: true, DnsName: "www", DnsType: "A"})
	if err != nil {
		t.Fatal(err)
	}
	world.template = template
	return world
}

// The world's state, with every device approval-capable for its member and an evidence list of all three channels.
func (self *testSpendWorld) state() *testSpendFixtureState {
	state := &testSpendFixtureState{
		pin:          self.pin,
		chains:       self.chains,
		identityKeys: map[Id][]byte{},
		approvalCapable: map[[2]Id]bool{
			{self.laptop, self.member}: true, {self.phone, self.member}: true,
			{self.otherDevice, self.other}: true, {self.adminDevice, self.admin}: true,
		},
		presenceKeys: []*bridge.KeyRow{{
			KeyId: bytes.Clone(self.presence.keyId), MemberId: self.member.Bytes(), Alg: self.presence.alg,
			PublicKey: bytes.Clone(self.presence.publicKey), Purpose: bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
			Signer: self.phone.Bytes(), At: 6, NotAfter: self.nowMs + 24*testConfigHourMs,
		}},
		rule: &testSpendFixtureRule{evidence: slices.Clone(spendAllChannels), evidenceKnown: true, count: 1, eligible: []Id{self.member}},
	}
	for sidecarId, key := range self.keys {
		state.identityKeys[sidecarId] = key.Public().(ed25519.PublicKey)
	}
	return state
}

// A decision body of the world's approval for its action, requested by the laptop at the pin, an hour away.
func (self *testSpendWorld) body(approver Id, channel protocol.ApprovalChannel) *protocol.ApprovalDecision {
	return testSpendDecisionBody(self.action, self.approvalId, approver, channel, self.laptop, self.pin, self.nowMs+testConfigHourMs)
}

// body signed by a device of the world.
func (self *testSpendWorld) signed(t testing.TB, sidecarId Id, body *protocol.ApprovalDecision) *bridge.Signed {
	return testSpendSignedBy(t, sidecarId, self.keys[sidecarId], body)
}

// Every vector, by name.
func testSpendVectorCases(t testing.TB) []*testSpendVectorCase {
	world := newTestSpendWorld(t)
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	presence := protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE
	harness := protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS
	one := func(name string, state *testSpendFixtureState, signed *bridge.Signed, refusal SpendRefusalCode) *testSpendVectorCase {
		return &testSpendVectorCase{
			name: name, state: state, decisions: []*bridge.Signed{signed}, action: world.action.Bytes,
			spender: world.laptop, nowMs: world.nowMs, refusal: refusal,
		}
	}
	edited := func(edit func(body *protocol.ApprovalDecision), channel protocol.ApprovalChannel) *protocol.ApprovalDecision {
		body := world.body(world.member, channel)
		edit(body)
		return body
	}
	phoneSigned := world.signed(t, world.phone, world.body(world.member, device))
	cases := []*testSpendVectorCase{
		one("device", world.state(), phoneSigned, ""),
		one("presence", world.state(), testSpendSignedByPresence(t, world.presence, world.body(world.member, presence)), ""),
		one("harness", world.state(), world.signed(t, world.laptop, world.body(world.member, harness)), ""),
	}

	forked := world.state()
	forked.forked = true
	cases = append(cases, one("forked", forked, phoneSigned, SpendRefusalForked))
	unknownSigner := world.signed(t, world.phone, world.body(world.member, device))
	unknownSigner.SignerId = testConfigId("spend vector stranger").Bytes()
	cases = append(cases, one("device by an unknown sidecar", world.state(), unknownSigner, SpendRefusalSigner))
	otherBytes := world.signed(t, world.phone, world.body(world.member, device))
	otherBytes.Body = testConfigMarshal(t, edited(func(body *protocol.ApprovalDecision) { body.Uses = 1; body.NotAfterMillis += 1 }, device))
	cases = append(cases, one("device over other bytes", world.state(), otherBytes, SpendRefusalSignature))
	cases = append(cases, one("deny", world.state(), world.signed(t, world.phone, edited(func(body *protocol.ApprovalDecision) {
		body.Decision = uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY)
	}, device)), SpendRefusalVerdict))
	cases = append(cases, one("device self-signed", world.state(), world.signed(t, world.laptop, world.body(world.member, device)), SpendRefusalSigner))
	notCapable := world.state()
	delete(notCapable.approvalCapable, [2]Id{world.phone, world.member})
	cases = append(cases, one("device not approval-capable", notCapable, phoneSigned, SpendRefusalSigner))
	cases = append(cases, one("harness by another sidecar", world.state(), world.signed(t, world.phone, world.body(world.member, harness)), SpendRefusalSigner))
	cases = append(cases, one("presence of another member", world.state(), testSpendSignedByPresence(t, world.presence, world.body(world.other, presence)), SpendRefusalSigner))
	cases = append(cases, one("another requester", world.state(), world.signed(t, world.phone, edited(func(body *protocol.ApprovalDecision) {
		body.RequesterSidecarId = world.otherDevice.Bytes()
	}, device)), SpendRefusalRequester))
	otherAction := testSpendDnsAction(t, "192.0.2.21")
	cases = append(cases, one("another action", world.state(), world.signed(t, world.phone, edited(func(body *protocol.ApprovalDecision) {
		payload := otherAction.PayloadSha256()
		body.PayloadSha256 = payload[:]
	}, device)), SpendRefusalPayload))
	cases = append(cases, one("a multi-use decision of one action", world.state(), world.signed(t, world.phone, edited(func(body *protocol.ApprovalDecision) {
		body.Uses = 3
	}, device)), SpendRefusalTemplate))
	templateBody := world.body(world.member, device)
	templatePayload := world.template.PayloadSha256()
	templateBody.PayloadSha256 = templatePayload[:]
	templateBody.Uses = 3
	templateCase := one("a template under a multi-use decision", world.state(), world.signed(t, world.phone, templateBody), "")
	templateCase.action = world.template.Bytes
	singleTemplate := proto.Clone(templateBody).(*protocol.ApprovalDecision)
	singleTemplate.Uses = 1
	singleTemplateCase := one("a template under a single-use decision", world.state(), world.signed(t, world.phone, singleTemplate), SpendRefusalTemplate)
	singleTemplateCase.action = world.template.Bytes
	cases = append(cases, templateCase, singleTemplateCase)
	expired := one("expired", world.state(), world.signed(t, world.phone, edited(func(body *protocol.ApprovalDecision) {
		body.NotAfterMillis = world.nowMs - 61*1000
	}, device)), SpendRefusalExpired)
	expiredReserved := one("expired but reserved", world.state(), expired.decisions[0], "")
	expiredReserved.reserved = true
	cases = append(cases, expired, expiredReserved)
	offChain := sha256.Sum256([]byte("off the chain"))
	cases = append(cases,
		one("pin ahead", world.state(), world.signed(t, world.phone, edited(func(body *protocol.ApprovalDecision) {
			body.AuthPin = &bridge.AuthPin{Version: 8, Chain: offChain[:]}
		}, device)), SpendRefusalPin),
		one("pin off the chain", world.state(), world.signed(t, world.phone, edited(func(body *protocol.ApprovalDecision) {
			body.AuthPin = &bridge.AuthPin{Version: 6, Chain: offChain[:]}
		}, device)), SpendRefusalPin),
		one("pin not retained", world.state(), world.signed(t, world.phone, edited(func(body *protocol.ApprovalDecision) {
			body.AuthPin = &bridge.AuthPin{Version: 3, Chain: offChain[:]}
		}, device)), ""),
	)
	ruleRefused := world.state()
	ruleRefused.rule.refused = true
	cases = append(cases, one("no rule governs", ruleRefused, phoneSigned, SpendRefusalRule))
	notEligible := world.state()
	notEligible.rule.eligible = nil
	cases = append(cases, one("approver not eligible", notEligible, phoneSigned, SpendRefusalApprover))
	deviceOutside := world.state()
	deviceOutside.rule.evidence = []protocol.ApprovalChannel{presence}
	cases = append(cases, one("channel outside the evidence", deviceOutside, phoneSigned, SpendRefusalEvidence))
	unknown := world.state()
	unknown.rule.evidence, unknown.rule.evidenceKnown = nil, false
	cases = append(cases, one("evidence unknown", unknown, phoneSigned, SpendRefusalEvidenceUnknown))

	// sets at k = 2, with the admin clause
	quorum := world.state()
	quorum.rule.count = 2
	quorum.rule.eligible = []Id{world.member, world.other}
	set := func(name string, state *testSpendFixtureState, refusal SpendRefusalCode, signeds ...*bridge.Signed) *testSpendVectorCase {
		vector := one(name, state, nil, refusal)
		vector.decisions = signeds
		vector.set = true
		return vector
	}
	otherSigned := world.signed(t, world.otherDevice, world.body(world.other, device))
	adminSigned := world.signed(t, world.adminDevice, world.body(world.admin, device))
	adminClause := world.state()
	adminClause.rule.count = 2
	adminClause.rule.eligible = []Id{world.member, world.other}
	adminClause.rule.admins = []Id{world.admin}
	adminClause.rule.adminNeeded = true
	otherRequestBody := world.body(world.other, device)
	otherRequestBody.ApprovalId = world.otherApprovalId.Bytes()
	cases = append(cases,
		set("two eligible at k = 2", quorum, "", phoneSigned, otherSigned),
		set("one at k = 2", quorum, SpendRefusalQuorum, phoneSigned),
		set("an approver twice", quorum, SpendRefusalSet, phoneSigned, world.signed(t, world.phone, world.body(world.member, device))),
		set("two requests", quorum, SpendRefusalSet, phoneSigned, world.signed(t, world.otherDevice, otherRequestBody)),
		set("the admin clause unmet", adminClause, SpendRefusalQuorum, phoneSigned, otherSigned),
		set("the admin clause met", adminClause, "", phoneSigned, adminSigned),
	)
	return cases
}

// The case's verdict: Spendable on one decision, SpendableSet on a set.
func testSpendRun(t testing.TB, vector *testSpendVectorCase) error {
	t.Helper()
	action, err := ParseStoredCanonicalAction(vector.action)
	if err != nil {
		t.Fatalf("%s: %v", vector.name, err)
	}
	decisions := []*StoredApprovalDecision{}
	for _, signed := range vector.decisions {
		decision, err := ParseSignedApprovalDecision(signed)
		if err != nil {
			t.Fatalf("%s: %v", vector.name, err)
		}
		decisions = append(decisions, decision)
	}
	input := &SpendInput{Action: action, Spender: vector.spender, Now: time.UnixMilli(vector.nowMs), Reserved: vector.reserved}
	if vector.set {
		_, err := SpendableSet(decisions, input, vector.state, nil)
		return err
	}
	return Spendable(decisions[0], input, vector.state, nil)
}

// Every refusal returns its SpendRefusal: each case on the fixture state ends in its code.
func TestSpendEachRefusalHasItsCode(t *testing.T) {
	codes := map[SpendRefusalCode]bool{}
	for _, vector := range testSpendVectorCases(t) {
		testSpendExpect(t, vector.name, testSpendRun(t, vector), vector.refusal)
		codes[vector.refusal] = true
	}
	for _, code := range []SpendRefusalCode{
		SpendRefusalForked, SpendRefusalSigner, SpendRefusalSignature, SpendRefusalVerdict, SpendRefusalRequester,
		SpendRefusalPayload, SpendRefusalTemplate, SpendRefusalExpired, SpendRefusalPin, SpendRefusalRule,
		SpendRefusalApprover, SpendRefusalEvidence, SpendRefusalEvidenceUnknown, SpendRefusalSet, SpendRefusalQuorum,
	} {
		if !codes[code] {
			t.Errorf("no case ends in %s", code)
		}
	}
	// nothing to judge
	world := newTestSpendWorld(t)
	testSpendExpect(t, "no decision", Spendable(nil, &SpendInput{Action: world.action}, world.state(), nil), SpendRefusalState)
	testSpendExpect(t, "no state", Spendable(testSpendParse(t, world.signed(t, world.phone, world.body(world.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE))),
		&SpendInput{Action: world.action}, nil, nil), SpendRefusalState)
	_, err := SpendableSet(nil, &SpendInput{Action: world.action}, world.state(), nil)
	testSpendExpect(t, "an empty set", err, SpendRefusalSet)
}

// testdata/record/spend/vectors.json in its JSON form.
type testSpendVectorFile struct {
	Comment string                `json:"comment"`
	Vectors []testSpendVectorJson `json:"vectors"`
}

// One vector in the file.
type testSpendVectorJson struct {
	Name      string             `json:"name"`
	State     testSpendStateJson `json:"state"`
	Decisions []string           `json:"decisions"`
	Action    string             `json:"action"`
	Spender   string             `json:"spender"`
	NowMs     int64              `json:"now_ms"`
	Reserved  bool               `json:"reserved"`
	Set       bool               `json:"set"`
	Refusal   string             `json:"refusal"`
}

// A vector's state in the file.
type testSpendStateJson struct {
	Pin             testSpendPinJson        `json:"pin"`
	Chains          []testSpendPinJson      `json:"chains"`
	Forked          bool                    `json:"forked"`
	IdentityKeys    []testSpendIdentityJson `json:"identity_keys"`
	ApprovalCapable []testSpendDeviceJson   `json:"approval_capable"`
	PresenceKeys    []string                `json:"presence_keys"`
	Rule            testSpendRuleJson       `json:"rule"`
}

// A pin or a retained digest in the file.
type testSpendPinJson struct {
	Version uint64 `json:"version"`
	Chain   string `json:"chain"`
}

// An identity key in the file.
type testSpendIdentityJson struct {
	SidecarId string `json:"sidecar_id"`
	PublicKey string `json:"public_key"`
}

// An approval-capable device of a member in the file.
type testSpendDeviceJson struct {
	SidecarId string `json:"sidecar_id"`
	MemberId  string `json:"member_id"`
}

// The governing rule in the file.
type testSpendRuleJson struct {
	Refused       bool     `json:"refused"`
	EvidenceKnown bool     `json:"evidence_known"`
	Evidence      []uint32 `json:"evidence"`
	Count         int      `json:"count"`
	Eligible      []string `json:"eligible"`
	Admins        []string `json:"admins"`
	AdminNeeded   bool     `json:"admin_needed"`
}

// Hex ids, sorted, for a deterministic file.
func testSpendHexIds(ids []Id) []string {
	texts := []string{}
	for _, id := range ids {
		texts = append(texts, hex.EncodeToString(id.Bytes()))
	}
	slices.Sort(texts)
	return texts
}

// A vector in its JSON form.
func testSpendVectorToJson(t testing.TB, vector *testSpendVectorCase) testSpendVectorJson {
	state := vector.state
	stateJson := testSpendStateJson{
		Pin:    testSpendPinJson{Version: state.pin.GetVersion(), Chain: hex.EncodeToString(state.pin.GetChain())},
		Forked: state.forked,
		Rule: testSpendRuleJson{
			Refused: state.rule.refused, EvidenceKnown: state.rule.evidenceKnown, Count: state.rule.count,
			Eligible: testSpendHexIds(state.rule.eligible), Admins: testSpendHexIds(state.rule.admins), AdminNeeded: state.rule.adminNeeded,
		},
	}
	for _, channel := range state.rule.evidence {
		stateJson.Rule.Evidence = append(stateJson.Rule.Evidence, uint32(channel))
	}
	for version, chain := range state.chains {
		stateJson.Chains = append(stateJson.Chains, testSpendPinJson{Version: version, Chain: hex.EncodeToString(chain[:])})
	}
	slices.SortFunc(stateJson.Chains, func(a testSpendPinJson, b testSpendPinJson) int { return int(a.Version) - int(b.Version) })
	for sidecarId, key := range state.identityKeys {
		stateJson.IdentityKeys = append(stateJson.IdentityKeys, testSpendIdentityJson{SidecarId: hex.EncodeToString(sidecarId.Bytes()), PublicKey: hex.EncodeToString(key)})
	}
	slices.SortFunc(stateJson.IdentityKeys, func(a testSpendIdentityJson, b testSpendIdentityJson) int {
		return strings.Compare(a.SidecarId, b.SidecarId)
	})
	for pair, capable := range state.approvalCapable {
		if capable {
			stateJson.ApprovalCapable = append(stateJson.ApprovalCapable, testSpendDeviceJson{SidecarId: hex.EncodeToString(pair[0].Bytes()), MemberId: hex.EncodeToString(pair[1].Bytes())})
		}
	}
	slices.SortFunc(stateJson.ApprovalCapable, func(a testSpendDeviceJson, b testSpendDeviceJson) int {
		return strings.Compare(a.SidecarId, b.SidecarId)
	})
	for _, key := range state.presenceKeys {
		stateJson.PresenceKeys = append(stateJson.PresenceKeys, hex.EncodeToString(testConfigMarshal(t, key)))
	}
	vectorJson := testSpendVectorJson{
		Name: vector.name, State: stateJson, Action: hex.EncodeToString(vector.action), Spender: hex.EncodeToString(vector.spender.Bytes()),
		NowMs: vector.nowMs, Reserved: vector.reserved, Set: vector.set, Refusal: string(vector.refusal),
	}
	for _, signed := range vector.decisions {
		vectorJson.Decisions = append(vectorJson.Decisions, hex.EncodeToString(testConfigMarshal(t, signed)))
	}
	return vectorJson
}

// A vector from its JSON form.
func testSpendVectorFromJson(t testing.TB, vectorJson testSpendVectorJson) *testSpendVectorCase {
	t.Helper()
	unhex := func(text string) []byte {
		value, err := hex.DecodeString(text)
		if err != nil {
			t.Fatalf("%s: %v", vectorJson.Name, err)
		}
		return value
	}
	id := func(text string) Id {
		value, err := IdFromBytes(unhex(text))
		if err != nil {
			t.Fatalf("%s: %v", vectorJson.Name, err)
		}
		return value
	}
	stateJson := vectorJson.State
	state := &testSpendFixtureState{
		pin:             &bridge.AuthPin{Version: stateJson.Pin.Version, Chain: unhex(stateJson.Pin.Chain)},
		chains:          map[uint64][sha256.Size]byte{},
		forked:          stateJson.Forked,
		identityKeys:    map[Id][]byte{},
		approvalCapable: map[[2]Id]bool{},
		rule: &testSpendFixtureRule{
			refused: stateJson.Rule.Refused, evidenceKnown: stateJson.Rule.EvidenceKnown, count: stateJson.Rule.Count,
			adminNeeded: stateJson.Rule.AdminNeeded,
		},
	}
	for _, chain := range stateJson.Chains {
		state.chains[chain.Version] = [sha256.Size]byte(unhex(chain.Chain))
	}
	for _, identity := range stateJson.IdentityKeys {
		state.identityKeys[id(identity.SidecarId)] = unhex(identity.PublicKey)
	}
	for _, device := range stateJson.ApprovalCapable {
		state.approvalCapable[[2]Id{id(device.SidecarId), id(device.MemberId)}] = true
	}
	for _, keyHex := range stateJson.PresenceKeys {
		key := &bridge.KeyRow{}
		if err := proto.Unmarshal(unhex(keyHex), key); err != nil {
			t.Fatalf("%s: %v", vectorJson.Name, err)
		}
		state.presenceKeys = append(state.presenceKeys, key)
	}
	for _, channel := range stateJson.Rule.Evidence {
		state.rule.evidence = append(state.rule.evidence, protocol.ApprovalChannel(channel))
	}
	for _, member := range stateJson.Rule.Eligible {
		state.rule.eligible = append(state.rule.eligible, id(member))
	}
	for _, member := range stateJson.Rule.Admins {
		state.rule.admins = append(state.rule.admins, id(member))
	}
	vector := &testSpendVectorCase{
		name: vectorJson.Name, state: state, action: unhex(vectorJson.Action), spender: id(vectorJson.Spender),
		nowMs: vectorJson.NowMs, reserved: vectorJson.Reserved, set: vectorJson.Set, refusal: SpendRefusalCode(vectorJson.Refusal),
	}
	for _, signedHex := range vectorJson.Decisions {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(unhex(signedHex), signed); err != nil {
			t.Fatalf("%s: %v", vectorJson.Name, err)
		}
		vector.decisions = append(vector.decisions, signed)
	}
	return vector
}

// The file the cases make today.
func testComputeSpendVectors(t testing.TB) []byte {
	file := &testSpendVectorFile{
		Comment: "MCP-M3-03's spend check vectors: each case's state (P's pin and retained chains, whether it is known " +
			"forked, identity keys, approval-capable devices, presence key rows as stored and the governing rule), its " +
			"Signed ApprovalDecisions and CanonicalAction as stored, the spender, the verifier's time in ms, whether a " +
			"use is reserved, whether it is judged as a k-approver set, and the SpendRefusalCode it ends in, empty when " +
			"it spends. Synthetic keys from fixed seeds; signatures are deterministic. go test -run TestSpendVectors " +
			"-update-spend-vectors rewrites this file.",
	}
	for _, vector := range testSpendVectorCases(t) {
		file.Vectors = append(file.Vectors, testSpendVectorToJson(t, vector))
	}
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

// testdata/record/spend/vectors.json is what the cases make today, byte for byte, and every vector read from it ends in
// its code.
func TestSpendVectors(t *testing.T) {
	computed := testComputeSpendVectors(t)
	encoded := computed
	if *updateSpendVectors {
		if err := os.WriteFile(testSpendVectorsPath, computed, 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		read, err := testSpendFiles.ReadFile(testSpendVectorsPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(read, computed) {
			t.Error("the vectors file differs from what the cases make; rerun with -update-spend-vectors after checking why")
		}
		encoded = read
	}
	file := &testSpendVectorFile{}
	if err := json.Unmarshal(encoded, file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, vectorJson := range file.Vectors {
		vector := testSpendVectorFromJson(t, vectorJson)
		testSpendExpect(t, vector.name, testSpendRun(t, vector), vector.refusal)
	}
}

// CheckApprovalCancel: the approver's device or presence key cancels its decision, whatever the decision's expiry; a
// cancel another member's device signed, one naming another approval, one over a decision whose signature fails, and
// one of another type are refused.
func TestApprovalCancelIsTheApprovers(t *testing.T) {
	net := newTestSpendNet(t)
	key := newTestPresenceKey(t, "spend cancel presence", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	net.registerPresenceKey(net.phone, key)
	state := net.spendState(false, spendAllChannels)
	action := testSpendDnsAction(t, "192.0.2.70")
	approvalId := NewId()
	body := testSpendDecisionBody(action, approvalId, net.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, net.laptop.sidecarId,
		net.log.State().Pin(), net.timeMs-testConfigHourMs)
	decision := testSpendParse(t, testSpendSignedBy(t, net.phone.sidecarId, net.phone.key, body))
	cancelBody := func(id Id) *protocol.ApprovalCancel { return &protocol.ApprovalCancel{ApprovalId: id.Bytes()} }
	signCancel := func(device testConfigDevice, id Id) *bridge.Signed {
		bodyBytes := testConfigMarshal(t, cancelBody(id))
		return &bridge.Signed{
			Body: bodyBytes, SignerId: device.sidecarId.Bytes(), Type: uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL),
			Signature: ed25519.Sign(device.key, bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, bodyBytes)),
		}
	}
	testSpendExpect(t, "the approver's device, past the decision's expiry", CheckApprovalCancel(signCancel(net.phone, approvalId), decision, state), "")
	presenceCancel := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, testConfigMarshal(t, cancelBody(approvalId)))
	testSpendExpect(t, "the approver's presence key", CheckApprovalCancel(presenceCancel, decision, state), "")
	testSpendExpect(t, "another member's device", CheckApprovalCancel(signCancel(net.otherDevice, approvalId), decision, state), SpendRefusalSigner)
	testSpendExpect(t, "another approval", CheckApprovalCancel(signCancel(net.phone, NewId()), decision, state), SpendRefusalCancel)
	asDecision := signCancel(net.phone, approvalId)
	asDecision.Type = uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION)
	testSpendExpect(t, "a cancel of another type", CheckApprovalCancel(asDecision, decision, state), SpendRefusalCancel)
	forged := testSpendParse(t, testSpendSignedBy(t, net.phone.sidecarId, net.phone.key, body))
	forged.Signed.Signature = bytes.Repeat([]byte{1}, 64)
	testSpendExpect(t, "a decision whose signature fails", CheckApprovalCancel(signCancel(net.phone, approvalId), forged, state), SpendRefusalSignature)
	testSpendExpect(t, "nothing", CheckApprovalCancel(nil, decision, state), SpendRefusalState)
}
