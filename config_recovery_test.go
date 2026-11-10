// §7.9's Recovery on the test network, FS-16's verifier cases on entry times: each row of the members' table (a plain
// SidecarAdmit by the key with self_admit on, a recovery-scoped proposal completing at an admission signer's cosign
// with it off, an AdminSet member's proposal activating only at a tick 72 h on, a restored binding's admission with no
// counted cosign), a late recovery cosign restarting the window, a veto between the proposal and the activation
// winning, voids by a rebind of the cosigning code's member, an AdminSet change and the subject's removal, a veto a
// device holds forking it at the activation, and proposals and windows surviving folds at a long-running reader, a new
// device and a rows-only gate alike.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An hour of entry time.
const testConfigHourMs = int64(60 * 60 * 1000)

// A member's recovery key in the test network.
type testConfigRecoveryKey struct {
	memberId Id
	key      ed25519.PrivateKey
}

// The key's hash, as rows and RecoveryBind name it.
func (self testConfigRecoveryKey) sha256() []byte {
	digest := sha256.Sum256(self.key.Public().(ed25519.PublicKey))
	return digest[:]
}

// A recovery key of a member from its label.
func testConfigRecovery(memberId Id, label string) testConfigRecoveryKey {
	return testConfigRecoveryKey{memberId: memberId, key: testConfigDeviceKey("recovery " + label)}
}

// A RecoveryBind of key for its member at the tip, replacing the binding in effect.
func (self *testConfigNet) recoveryBind(key testConfigRecoveryKey) *protocol.RecoveryBind {
	return &protocol.RecoveryBind{
		Header:                 self.header(),
		MemberId:               key.memberId.Bytes(),
		PrevSha256:             bytes.Clone(self.log.State().Member(key.memberId).GetRecoveryKeySha256()),
		Ed25519PublicKeySha256: key.sha256(),
		SealedBody:             []byte("sealed body: opened only by a reader holding RK_g"),
	}
}

// body signed by a member's recovery key, as §6.9's Signers name it: signer_id the member, key_id the raw key.
func (self *testConfigNet) signByRecovery(key testConfigRecoveryKey, signedType bridge.SignedType, body proto.Message) []byte {
	bodyBytes := testConfigMarshal(self.t, body)
	purpose, _ := ConfigStatementPurpose(signedType)
	return testConfigMarshal(self.t, &bridge.Signed{
		Body:      bodyBytes,
		SignerId:  key.memberId.Bytes(),
		KeyId:     bytes.Clone(key.key.Public().(ed25519.PublicKey)),
		Signature: ed25519.Sign(key.key, bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	})
}

// Signs by the recovery key, sequences and applies.
func (self *testConfigNet) postByRecovery(key testConfigRecoveryKey, signedType bridge.SignedType, body proto.Message) ConfigVerdict {
	self.t.Helper()
	return self.push(self.makeEntry(bridge.AuthEntryKindStatement, self.signByRecovery(key, signedType, body)))
}

// An AuthorityProposal of body at the tip, good for 7 days, which a recovery window needs.
func (self *testConfigNet) longProposal(signedType bridge.SignedType, body proto.Message) *protocol.AuthorityProposal {
	header := self.header()
	header.NotAfterMs = self.timeMs + 7*24*testConfigHourMs
	return &protocol.AuthorityProposal{Header: header, StatementType: uint32(signedType), Statement: testConfigMarshal(self.t, body)}
}

// Moves the entry clock on.
func (self *testConfigNet) wait(ms int64) {
	self.timeMs += ms
}

// A tick activating a proposal.
func (self *testConfigNet) activate(proposalId []byte) ConfigVerdict {
	self.t.Helper()
	return self.tick(&bridge.ApiTick{ActivatedProposalIds: [][]byte{proposalId}})
}

// Outside the AdminSet with self_admit on, a member's recovery key admits its member's untagged device at its position,
// which is the member's consent (§8.5); it admits no tagged, ephemeral or other member's device, nor proposes one.
func TestARecoveryKeyAdmitsItsMembersDeviceWithSelfAdmitOn(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	key := testConfigRecovery(member, "m")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	state := net.log.State()
	if binding := state.CurrentBinding(member); binding == nil || !bytes.Equal(binding.GetKeySha256(), key.sha256()) ||
		!bytes.Equal(binding.GetSigner(), laptop.sidecarId.Bytes()) || state.BindingRestored(member) {
		t.Fatalf("the binding: %v", binding)
	}

	tablet := net.device("m tablet", member)
	admitted := net.postByRecovery(key, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(tablet, nil, false, 0, 0))
	if !admitted.Accepted() {
		t.Fatal(admitted.Refusal)
	}
	row := net.log.State().SidecarRow(tablet.sidecarId)
	if row.GetAdmittedAt() != admitted.Pin.GetVersion() || len(row.GetAdmissionSigners()) != 1 || !bytes.Equal(row.GetAdmissionSigners()[0], key.sha256()) {
		t.Errorf("the row: %v", row)
	}
	acl, err := net.log.State().Acl()
	if err != nil || !acl.ConsentedFor(tablet.sidecarId, member) {
		t.Errorf("the recovery key's admission is not the member's consent: %v", err)
	}

	other, _ := net.consentedMember("other")
	for _, admit := range []*protocol.SidecarAdmit{
		net.admission(net.device("m agent", Id{}), []Id{testConfigId("tag")}, false, net.timeMs+testConfigHourMs, 0),
		net.admission(net.device("m worker", member), nil, true, net.timeMs+testConfigHourMs, 0),
		net.admission(net.device("other device", other), nil, false, 0, 0),
	} {
		if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
			t.Errorf("%v", verdict.Refusal)
		}
	}
	if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		net.admission(net.device("m phone", member), nil, false, 0, 0))); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Errorf("a proposal with self_admit on: %v", verdict.Refusal)
	}
	if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("by a key")); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
		t.Errorf("a key's MemberAdmit: %v", verdict.Refusal)
	}
	net.everyReaderAgrees()
}

// RecoveryBind and RecoveryRebind: the member's consented device, prev_sha256 the binding in effect, a rebind's reason,
// and no key another member bound.
func TestRecoveryBindingsShape(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	other, otherLaptop := net.consentedMember("other")
	key := testConfigRecovery(member, "m")
	net.mustRefuse(otherLaptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key), ErrConfigAuthority)
	stale := net.recoveryBind(key)
	stale.PrevSha256 = make([]byte, 32)
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, stale, ErrConfigRule)
	rebind := &protocol.RecoveryRebind{Header: net.header(), MemberId: member.Bytes(), Ed25519PublicKeySha256: key.sha256(),
		Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE}
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_RECOVERY_REBIND, rebind, ErrConfigRule)
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))

	taken := testConfigRecoveryKey{memberId: other, key: key.key}
	net.mustRefuse(otherLaptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(taken), ErrConfigRule)
	next := testConfigRecovery(member, "m next")
	unreasoned := &protocol.RecoveryRebind{Header: net.header(), MemberId: member.Bytes(), PrevSha256: key.sha256(), Ed25519PublicKeySha256: next.sha256()}
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_RECOVERY_REBIND, unreasoned, ErrConfigRule)
	rebind = &protocol.RecoveryRebind{Header: net.header(), MemberId: member.Bytes(), PrevSha256: key.sha256(), Ed25519PublicKeySha256: next.sha256(),
		Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_LOST}
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_REBIND, rebind)
	memberRow := net.log.State().Member(member)
	if !bytes.Equal(memberRow.GetRecoveryKeySha256(), next.sha256()) || len(memberRow.GetBindings()) != 2 ||
		memberRow.GetBindings()[0].GetReason() != bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_LOST {
		t.Errorf("the member's bindings: %v", memberRow)
	}
	// the replaced key signs no more
	if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(net.device("m tablet", member), nil, false, 0, 0)); verdict.Accepted() {
		t.Error("a replaced key admitted")
	}
	net.everyReaderAgrees()
}

// Outside the AdminSet with self_admit off, a plain SidecarAdmit by the key is refused, and its proposal completes at
// one cosign by an Owner's, Admin's or IT admin's device, never a member's own.
func TestARecoveryScopedAdmissionCompletesAtAnAdmissionSignersCosign(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	key := testConfigRecovery(member, "m")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(2))] = &protocol.ServiceSettings{SelfAdmit: protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF}
	net.fold(net.owner, net.n, 2)

	tablet := net.device("m tablet", member)
	if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(tablet, nil, false, 0, 0)); verdict.Accepted() {
		t.Fatal("a plain admission by the key with self_admit off")
	}
	proposed := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(tablet, nil, false, 0, 0)))
	if !proposed.Accepted() {
		t.Fatal(proposed.Refusal)
	}
	proposalId := proposed.StatementId[:]
	row := net.log.State().openProposalRows()[0]
	if row.GetKind() != uint32(bridge.ProposalKind_PROPOSAL_KIND_RECOVERY_SCOPED) || row.GetWindowEntry() != proposed.Pin.GetVersion() {
		t.Errorf("the proposal's row: %v", row)
	}
	if verdict := net.cosign(laptop, proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
		t.Errorf("the member's own cosign: %v", verdict.Refusal)
	}
	completed := net.cosign(net.owner, proposalId)
	if !completed.Accepted() || !bytes.Equal(completed.CompletedProposalId, proposalId) {
		t.Fatalf("the admin's cosign: %v", completed.Refusal)
	}
	if row := net.log.State().SidecarRow(tablet.sidecarId); row == nil || row.GetAdmittedAt() != completed.Pin.GetVersion() {
		t.Errorf("the tablet: %v", row)
	}
	net.everyReaderAgrees()
}

// A personal network (k = 1): the owner's key proposes its new device alone, which activates only at a tick 72 h after
// the proposal's entry, live from the tick's position; a tick earlier is refused and changes nothing.
func TestAPersonalNetworksRecoveryActivatesAfterTheWindow(t *testing.T) {
	net := newTestConfigNet(t)
	key := testConfigRecovery(net.ownerMemberId, "owner")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	phone := net.device("owner phone", net.ownerMemberId)
	if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)); verdict.Accepted() {
		t.Fatal("an AdminSet member's key admitted at once")
	}
	proposed := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)))
	if !proposed.Accepted() || len(proposed.CompletedProposalId) != 0 {
		t.Fatalf("the proposal: %v", proposed.Refusal)
	}
	proposalId := proposed.StatementId[:]
	if pending := net.log.State().PendingProposals(); len(pending) != 1 || !bytes.Equal(pending[0].GetProposalId(), proposalId) {
		t.Fatalf("pending %v", pending)
	}
	net.wait(71 * testConfigHourMs)
	if verdict := net.activate(proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Errorf("an activation at 71 h: %v", verdict.Refusal)
	}
	net.wait(testConfigHourMs)
	activated := net.activate(proposalId)
	if !activated.Accepted() {
		t.Fatalf("the activation: %v", activated.Refusal)
	}
	state := net.log.State()
	row := state.SidecarRow(phone.sidecarId)
	if row.GetAdmittedAt() != activated.Pin.GetVersion() || row.GetLiveSince() != activated.Pin.GetVersion() {
		t.Errorf("the phone: %v", row)
	}
	window, ok := state.RecoveryWindow(proposalId)
	if !ok || window.Closed != ConfigProposalActivated || window.ClosedAt != activated.Pin.GetVersion() || window.MemberId != net.ownerMemberId ||
		window.SidecarId == nil || *window.SidecarId != phone.sidecarId {
		t.Errorf("the window: %+v", window)
	}
	if len(state.PendingProposals()) != 0 {
		t.Error("an activated proposal is pending")
	}
	if verdict := net.activate(proposalId); verdict.Accepted() {
		t.Error("a second activation")
	}
	net.everyReaderAgrees()
}

// k = 2: an admin's key and another admin's device: the k-th signature does not complete a proposal a recovery key
// signed; a tick 72 h after the newest recovery-key signature activates it. A recovery cosign 72 h after an admin's own
// proposal restarts the window, and a veto between the cosign and the activation wins.
func TestALateRecoveryCosignRestartsTheWindow(t *testing.T) {
	team := newTestConfigTeam(t)
	keyB := testConfigRecovery(team.adminB.memberId, "b")
	team.mustRefuse(team.adminB, bridge.SignedType_SIGNED_RECOVERY_BIND, team.recoveryBind(keyB), ErrConfigAuthority)
	_, bindId := team.propose(team.adminB, bridge.SignedType_SIGNED_RECOVERY_BIND, team.recoveryBind(keyB))
	team.cosign(team.adminC, bindId)
	if binding := team.log.State().CurrentBinding(team.adminB.memberId); binding == nil {
		t.Fatal("b has no binding")
	}

	bPhone := team.device("b phone", team.adminB.memberId)
	proposed := team.postByRecovery(keyB, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, team.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(bPhone, nil, false, 0, 0)))
	if !proposed.Accepted() {
		t.Fatal(proposed.Refusal)
	}
	cosigned := team.cosign(team.adminC, proposed.StatementId[:])
	if !cosigned.Accepted() || len(cosigned.CompletedProposalId) != 0 {
		t.Fatalf("the k-th signature completed a recovery proposal: %v", cosigned.Refusal)
	}
	team.wait(72 * testConfigHourMs)
	if activated := team.activate(proposed.StatementId[:]); !activated.Accepted() || team.log.State().SidecarRow(bPhone.sidecarId) == nil {
		t.Fatalf("the activation: %v", activated.Refusal)
	}

	// the owner's device proposes c's tablet; b's key cosigns 72 h later and restarts the window there
	cTablet := team.device("c tablet", team.adminC.memberId)
	adminProposal := team.mustPost(team.owner, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, team.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(cTablet, nil, false, 0, 0)))
	adminProposalId := adminProposal.StatementId[:]
	team.wait(72 * testConfigHourMs)
	late := team.postByRecovery(keyB, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, &protocol.AuthorityCosign{Header: team.header(), ProposalId: adminProposalId})
	if !late.Accepted() {
		t.Fatalf("the late recovery cosign: %v", late.Refusal)
	}
	row := team.log.State().openProposalRows()
	if len(row) != 1 || row[0].GetWindowEntry() != late.Pin.GetVersion() {
		t.Fatalf("the window: %v", row)
	}
	team.wait(71 * testConfigHourMs)
	if verdict := team.activate(adminProposalId); verdict.Accepted() {
		t.Fatal("an activation 71 h after the newest recovery signature")
	}
	vetoed := team.mustPost(team.adminC, bridge.SignedType_SIGNED_RECOVERY_VETO, &protocol.RecoveryVeto{Header: team.header(), ProposalId: adminProposalId})
	team.wait(2 * testConfigHourMs)
	if verdict := team.activate(adminProposalId); verdict.Accepted() {
		t.Fatal("a vetoed proposal activated")
	}
	if window, ok := team.log.State().RecoveryWindow(adminProposalId); !ok || window.Closed != ConfigProposalVetoed || window.ClosedAt != vetoed.Pin.GetVersion() {
		t.Errorf("the window: %+v", window)
	}
	team.everyReaderAgrees()
}

// A veto needs an AdminSet member's admitted device, never the proposed device or a read_only one, and an open proposal
// a window holds.
func TestAVetosSigners(t *testing.T) {
	team := newTestConfigTeam(t)
	member, laptop := team.consentedMember("m")
	_ = member
	key := testConfigRecovery(team.ownerMemberId, "owner")
	_, bindId := team.propose(team.owner, bridge.SignedType_SIGNED_RECOVERY_BIND, team.recoveryBind(key))
	team.cosign(team.adminB, bindId)
	phone := team.device("owner phone", team.ownerMemberId)
	proposed := team.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, team.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(phone, nil, false, 0, 0)))
	if !proposed.Accepted() {
		t.Fatal(proposed.Refusal)
	}
	veto := func() *protocol.RecoveryVeto {
		return &protocol.RecoveryVeto{Header: team.header(), ProposalId: proposed.StatementId[:]}
	}
	team.mustRefuse(laptop, bridge.SignedType_SIGNED_RECOVERY_VETO, veto(), ErrConfigAuthority)
	_, plainId := team.propose(team.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, team.memberAdmitStatement("plain"))
	team.mustRefuse(team.adminB, bridge.SignedType_SIGNED_RECOVERY_VETO, &protocol.RecoveryVeto{Header: team.header(), ProposalId: plainId}, ErrConfigRule)
	team.mustPost(team.owner, bridge.SignedType_SIGNED_RECOVERY_VETO, veto())
	team.mustRefuse(team.adminB, bridge.SignedType_SIGNED_RECOVERY_VETO, veto(), ErrConfigRule)
}

// FS-16's voids: a RecoveryRebind of the cosigning code's member, an AdminSet change, and the subject's removal each
// close the window's proposal, which then activates nowhere.
func TestARebindAdminSetChangeOrRemovalVoidsAWindow(t *testing.T) {
	cases := []struct {
		name string
		void func(team *testConfigTeam, keyB testConfigRecoveryKey)
	}{
		{name: "a rebind of the cosigning code's member", void: func(team *testConfigTeam, keyB testConfigRecoveryKey) {
			next := testConfigRecovery(team.adminB.memberId, "b next")
			rebind := &protocol.RecoveryRebind{Header: team.header(), MemberId: team.adminB.memberId.Bytes(), PrevSha256: keyB.sha256(),
				Ed25519PublicKeySha256: next.sha256(), Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE}
			_, rebindId := team.propose(team.adminB, bridge.SignedType_SIGNED_RECOVERY_REBIND, rebind)
			team.cosign(team.adminC, rebindId)
		}},
		{name: "an AdminSet change", void: func(team *testConfigTeam, keyB testConfigRecoveryKey) {
			extra := testConfigId("extra admin")
			team.admitMember(team.owner, extra, bridge.MemberRole_MEMBER_ROLE_MEMBER)
			_, setId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0, extra))
			team.cosign(team.adminC, setId)
		}},
		{name: "the subject's removal", void: func(team *testConfigTeam, keyB testConfigRecoveryKey) {
			_, revokeId := team.propose(team.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: team.header(), MemberId: team.adminB.memberId.Bytes()})
			team.cosign(team.adminC, revokeId)
		}},
	}
	for _, c := range cases {
		team := newTestConfigTeam(t)
		keyB := testConfigRecovery(team.adminB.memberId, "b")
		_, bindId := team.propose(team.adminB, bridge.SignedType_SIGNED_RECOVERY_BIND, team.recoveryBind(keyB))
		team.cosign(team.adminC, bindId)
		bPhone := team.device("b phone", team.adminB.memberId)
		proposed := team.postByRecovery(keyB, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, team.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(bPhone, nil, false, 0, 0)))
		if !proposed.Accepted() {
			t.Fatalf("%s: %v", c.name, proposed.Refusal)
		}
		team.cosign(team.adminC, proposed.StatementId[:])
		c.void(team, keyB)
		window, ok := team.log.State().RecoveryWindow(proposed.StatementId[:])
		if !ok || window.Closed != ConfigProposalVoided {
			t.Errorf("%s: the window %+v", c.name, window)
		}
		team.wait(73 * testConfigHourMs)
		if verdict := team.activate(proposed.StatementId[:]); verdict.Accepted() {
			t.Errorf("%s: a voided proposal activated", c.name)
		}
		team.everyReaderAgrees()
	}
}

// §22.7's restored code: a member whose binding a compromise void restored admits by its key only through the window:
// a plain SidecarAdmit is refused, and its proposal activates 72 h on with no counted cosign.
func TestARestoredBindingAdmitsOnlyThroughTheWindow(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	keyOne := testConfigRecovery(member, "m one")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(keyOne))
	stolen := net.device("m stolen", member)
	net.admitDevice(laptop, stolen, 0)
	sinceN := net.n + 1
	keyTwo := testConfigRecovery(member, "m two")
	net.mustPost(stolen, bridge.SignedType_SIGNED_RECOVERY_REBIND, &protocol.RecoveryRebind{Header: net.header(), MemberId: member.Bytes(),
		PrevSha256: keyOne.sha256(), Ed25519PublicKeySha256: keyTwo.sha256(), Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE})
	plan, err := net.log.State().CascadePlan(stolen.sidecarId, sinceN)
	if err != nil || len(plan.VoidedBindings) != 1 || !bytes.Equal(plan.VoidedBindings[0].KeySha256, keyTwo.sha256()) || len(plan.Reseals) == 0 {
		t.Fatalf("the plan: %+v, %v", plan, err)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(stolen, sinceN))
	state := net.log.State()
	if !bytes.Equal(state.Member(member).GetRecoveryKeySha256(), keyOne.sha256()) || !state.BindingRestored(member) ||
		!state.CascadeVoids(keyTwo.sha256(), net.n) || state.CascadeVoids(keyOne.sha256(), net.n) {
		t.Fatal("the void did not restore the earlier binding")
	}
	if verdict := net.postByRecovery(keyTwo, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(net.device("m by two", member), nil, false, 0, 0)); verdict.Accepted() {
		t.Error("the voided key admitted")
	}
	phone := net.device("m phone", member)
	if verdict := net.postByRecovery(keyOne, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)); verdict.Accepted() {
		t.Error("a plain admission under a restored binding")
	}
	proposed := net.postByRecovery(keyOne, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)))
	if !proposed.Accepted() {
		t.Fatal(proposed.Refusal)
	}
	if rows := net.log.State().openProposalRows(); len(rows) != 1 || rows[0].GetKind() != uint32(bridge.ProposalKind_PROPOSAL_KIND_RESTORED) {
		t.Fatalf("the proposal: %v", rows)
	}
	net.wait(72 * testConfigHourMs)
	if activated := net.activate(proposed.StatementId[:]); !activated.Accepted() || net.log.State().SidecarRow(phone.sidecarId) == nil {
		t.Fatalf("the activation: %v", activated.Refusal)
	}
	net.everyReaderAgrees()
}

// §7.9's precedence row: a device that holds a valid veto before the activation forks there; a reader without it
// applies the activation; a veto first verified after it only alarms; and a held veto's at before the proposal is no
// valid veto.
func TestAHeldVetoForksTheActivation(t *testing.T) {
	net := newTestConfigNet(t)
	key := testConfigRecovery(net.ownerMemberId, "owner")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	backdated := net.header()
	ownerPhone := net.device("owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, ownerPhone, 0)
	thiefDevice := net.device("thief's device", net.ownerMemberId)
	proposed := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(thiefDevice, nil, false, 0, 0)))
	if !proposed.Accepted() {
		t.Fatal(proposed.Refusal)
	}
	vetoBytes := net.sign(ownerPhone, bridge.SignedType_SIGNED_RECOVERY_VETO, &protocol.RecoveryVeto{Header: net.header(), ProposalId: proposed.StatementId[:]})
	early := net.sign(ownerPhone, bridge.SignedType_SIGNED_RECOVERY_VETO, &protocol.RecoveryVeto{Header: backdated, ProposalId: proposed.StatementId[:]})
	holder := net.newReader()
	if err := holder.HoldVeto(early); !errors.Is(err, ErrConfigReplay) {
		t.Errorf("a veto dated before its proposal: %v", err)
	}
	if err := holder.HoldVeto(vetoBytes); err != nil {
		t.Fatal(err)
	}
	net.wait(72 * testConfigHourMs)
	activation := net.makeEntry(bridge.AuthEntryKindTick, testConfigMarshal(t, &bridge.ApiTick{ActivatedProposalIds: [][]byte{proposed.StatementId[:]}}))
	for _, entryBytes := range net.entries[holder.Pin().GetVersion():] {
		if _, err := holder.Apply(entryBytes, net.source); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := holder.Apply(activation, net.source); !errors.Is(err, ErrConfigFork) {
		t.Fatalf("the holder applied the activation: %v", err)
	}
	if verdict := net.push(activation); !verdict.Accepted() {
		t.Fatalf("a reader without the veto: %v", verdict.Refusal)
	}
	if err := net.log.HoldVeto(vetoBytes); !errors.Is(err, ErrConfigVetoLate) {
		t.Errorf("a veto verified after the activation: %v", err)
	}
}

// DESIGN-DETAILS 5.6's TestAProposalSurvivesAFold: k = 2, a proposal, a base folding it, then a cosign completes it at a
// long-running reader, a new device and a rows-only gate alike; and the same with two bases between.
func TestAProposalSurvivesAFold(t *testing.T) {
	for _, bases := range []int{1, 2} {
		team := newTestConfigTeam(t)
		phone := team.device("owner phone", team.ownerMemberId)
		_, proposalId := team.propose(team.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(phone, nil, false, 0, 0))
		for i := range bases {
			team.fold(team.owner, team.n, uint64(2+i))
		}
		if open := team.log.State().OpenProposalIds(); len(open) != 1 || !bytes.Equal(open[0], proposalId) {
			t.Fatalf("%d bases: open %x", bases, open)
		}
		team.everyReaderAgrees()
		completed := team.cosign(team.adminB, proposalId)
		if !completed.Accepted() || team.log.State().SidecarRow(phone.sidecarId) == nil {
			t.Fatalf("%d bases: the cosign %v", bases, completed.Refusal)
		}
		team.everyReaderAgrees()
	}
}

// DESIGN-DETAILS 5.6's TestARecoveryWindowSurvivesAFold: a recovery proposal, a base folding it, and a tick 72 h on
// activates it at every reader; a veto in a base's tail closes it at every reader.
func TestARecoveryWindowSurvivesAFold(t *testing.T) {
	for _, vetoed := range []bool{false, true} {
		net := newTestConfigNet(t)
		key := testConfigRecovery(net.ownerMemberId, "owner")
		net.mustPost(net.owner, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
		phone := net.device("owner phone", net.ownerMemberId)
		proposed := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)))
		net.fold(net.owner, net.n, 2)
		foldPoint := net.n
		if vetoed {
			net.mustPost(net.owner, bridge.SignedType_SIGNED_RECOVERY_VETO, &protocol.RecoveryVeto{Header: net.header(), ProposalId: proposed.StatementId[:]})
		}
		net.fold(net.owner, foldPoint, 3)
		net.everyReaderAgrees()
		net.wait(72 * testConfigHourMs)
		activated := net.activate(proposed.StatementId[:])
		if activated.Accepted() == vetoed || (net.log.State().SidecarRow(phone.sidecarId) != nil) == vetoed {
			t.Errorf("vetoed %v: the activation %v", vetoed, activated.Refusal)
		}
		net.everyReaderAgrees()
	}
}
