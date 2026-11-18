// A cascade's void of a recovery binding on the test network (§7.9's cascade; QD-1034): the void leaves the member no
// binding, nothing earlier restored, so neither the voided code nor the one it replaced signs anything, at every
// reader, across a base, with self_admit on or off; a device of the member outside the cascade binds a fresh code by a
// RecoveryBind whose prev_sha256 is empty, and a rebind, which has nothing to replace, is refused; an admin still
// admits the member's new device; a void of a binding that is not the one in effect leaves the one in effect; and rows
// refuse the two reserved restored kinds, 3 and 4, as any kind no verifier judges.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A test network where a compromise cascade voided member m's binding in effect: m's laptop binds key one, a stolen
// device of m's rebinds m to key two, and a compromise revocation of the stolen device from before that rebind voids
// key two. Returns the network, m, m's laptop, which is outside the cascade, and both keys.
func newTestConfigVoidedNet(t *testing.T) (*testConfigNet, Id, testConfigDevice, testConfigRecoveryKey, testConfigRecoveryKey) {
	t.Helper()
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
	return net, member, laptop, keyOne, keyTwo
}

// The ServiceSettings a head at configVersion holds, setting self_admit on or off.
func (self *testConfigNet) setHeadSelfAdmit(configVersion uint64, on bool) {
	mode := protocol.SelfAdmitMode_SELF_ADMIT_MODE_ON
	if !on {
		mode = protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF
	}
	self.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{SelfAdmit: mode}
}

// A base at configVersion whose head turns self_admit on or off, folding the log through its tip.
func (self *testConfigNet) foldSelfAdmit(configVersion uint64, on bool) {
	self.t.Helper()
	self.setHeadSelfAdmit(configVersion, on)
	if verdict := self.fold(self.owner, self.n, configVersion); !verdict.Accepted() {
		self.t.Fatalf("the base at config version %d: %v", configVersion, verdict.Refusal)
	}
	if self.log.State().SelfAdmit() != on {
		self.t.Fatalf("self_admit is not %v after the base", on)
	}
}

// Fails the test unless neither key signs anything at the net's tip: a plain SidecarAdmit of a new device of member's
// and an AuthorityProposal of one are each refused as by no signer, and nothing opens or is admitted.
func testConfigExpectNoRecoveryKeySigns(t *testing.T, net *testConfigNet, member Id, why string, keys ...testConfigRecoveryKey) {
	t.Helper()
	for i, key := range keys {
		phone := net.device("m phone "+why, member)
		if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
			t.Errorf("%s: key %d's plain admission: %v", why, i+1, verdict.Refusal)
		}
		proposal := net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0))
		if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, proposal); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigSigner) {
			t.Errorf("%s: key %d's proposal: %v", why, i+1, verdict.Refusal)
		}
		if net.log.State().SidecarRow(phone.sidecarId) != nil {
			t.Errorf("%s: key %d admitted a device", why, i+1)
		}
	}
	if rows := net.log.State().openProposalRows(); len(rows) != 0 {
		t.Errorf("%s: open proposals %v", why, rows)
	}
	if pending := net.log.State().PendingProposals(); len(pending) != 0 {
		t.Errorf("%s: pending proposals %v", why, pending)
	}
}

// The void leaves m no binding: the rows keep both bindings as history and name no key in effect, the cascade still
// voids what key two signed and not what key one did, and neither key admits or proposes, with self_admit on, across a
// base at a new device and a rows-only gate, and with self_admit off.
func TestACascadesVoidLeavesTheMemberNoBinding(t *testing.T) {
	net, member, _, keyOne, keyTwo := newTestConfigVoidedNet(t)
	state := net.log.State()
	row := state.Member(member)
	if len(row.GetRecoveryKeySha256()) != 0 || state.CurrentBinding(member) != nil {
		t.Fatalf("the void left a binding in effect: %x", row.GetRecoveryKeySha256())
	}
	if bindings := row.GetBindings(); len(bindings) != 2 || !bytes.Equal(bindings[0].GetKeySha256(), keyTwo.sha256()) || !bytes.Equal(bindings[1].GetKeySha256(), keyOne.sha256()) {
		t.Fatalf("the member's bindings: %v", bindings)
	}
	if !state.CascadeVoids(keyTwo.sha256(), net.n) || state.CascadeVoids(keyOne.sha256(), net.n-2) {
		t.Error("the cascade's voids are not key two's alone")
	}
	for _, key := range []testConfigRecoveryKey{keyOne, keyTwo} {
		if state.recoveryKeyCurrent(ConfigSigner{Kind: ConfigSignerRecovery, MemberId: member, RecoveryKeySha256: key.sha256()}) {
			t.Error("a key counts as its member with no binding in effect")
		}
	}
	testConfigExpectNoRecoveryKeySigns(t, net, member, "self_admit on", keyOne, keyTwo)
	net.everyReaderAgrees()

	// a base carries the member's row as it stands: no key in effect, at a new device and a rows-only gate alike
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatalf("the base: %v", verdict.Refusal)
	}
	for i, reader := range net.everyReader() {
		if row := reader.State().Member(member); len(row.GetRecoveryKeySha256()) != 0 || len(row.GetBindings()) != 2 || reader.State().CurrentBinding(member) != nil {
			t.Errorf("reader %d after the base: %v", i, row)
		}
	}
	testConfigExpectNoRecoveryKeySigns(t, net, member, "after a base", keyOne, keyTwo)
	net.everyReaderAgrees()

	net.foldSelfAdmit(3, false)
	testConfigExpectNoRecoveryKeySigns(t, net, member, "self_admit off", keyOne, keyTwo)
	net.everyReaderAgrees()
}

// After the void m's device outside the cascade binds a fresh code: a rebind has nothing to replace, a bind naming
// either earlier key as prev_sha256 is refused, the revoked device binds nothing, and a RecoveryBind with an empty
// prev_sha256 takes effect. The fresh key then admits m's new device plainly, and the earlier keys stay dead.
func TestAFreshCodeIsBoundAfterAVoid(t *testing.T) {
	net, member, laptop, keyOne, keyTwo := newTestConfigVoidedNet(t)
	keyThree := testConfigRecovery(member, "m three")
	for _, prev := range []testConfigRecoveryKey{keyOne, keyTwo} {
		rebind := &protocol.RecoveryRebind{Header: net.header(), MemberId: member.Bytes(), PrevSha256: prev.sha256(), Ed25519PublicKeySha256: keyThree.sha256(),
			Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE}
		net.mustRefuse(laptop, bridge.SignedType_SIGNED_RECOVERY_REBIND, rebind, ErrConfigRule)
		bind := net.recoveryBind(keyThree)
		bind.PrevSha256 = prev.sha256()
		net.mustRefuse(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, bind, ErrConfigRule)
	}
	rebind := &protocol.RecoveryRebind{Header: net.header(), MemberId: member.Bytes(), Ed25519PublicKeySha256: keyThree.sha256(),
		Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE}
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_RECOVERY_REBIND, rebind, ErrConfigRule)
	stolen := net.device("m stolen", member)
	if verdict := net.post(stolen, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(keyThree)); verdict.Accepted() {
		t.Fatal("the revoked device bound a code")
	}

	bind := net.recoveryBind(keyThree)
	if len(bind.GetPrevSha256()) != 0 {
		t.Fatalf("a bind after a void names prev_sha256 %x", bind.GetPrevSha256())
	}
	bound := net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, bind)
	state := net.log.State()
	binding := state.CurrentBinding(member)
	if binding == nil || !bytes.Equal(binding.GetKeySha256(), keyThree.sha256()) || binding.GetAt() != bound.Pin.GetVersion() ||
		!bytes.Equal(binding.GetSigner(), laptop.sidecarId.Bytes()) || len(state.Member(member).GetBindings()) != 3 {
		t.Fatalf("the fresh binding: %v of %v", binding, state.Member(member))
	}
	if state.CascadeVoids(keyThree.sha256(), net.n+1) {
		t.Error("the cascade voids the fresh binding")
	}

	phone := net.device("m phone", member)
	admitted := net.postByRecovery(keyThree, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0))
	if !admitted.Accepted() {
		t.Fatalf("the fresh key's admission: %v", admitted.Refusal)
	}
	if row := net.log.State().SidecarRow(phone.sidecarId); row == nil || row.GetAdmittedAt() != admitted.Pin.GetVersion() {
		t.Errorf("the phone: %v", row)
	}
	for i, key := range []testConfigRecoveryKey{keyOne, keyTwo} {
		if verdict := net.postByRecovery(key, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(net.device("m by an earlier key", member), nil, false, 0, 0)); verdict.Accepted() {
			t.Errorf("key %d admitted once a fresh code was bound", i+1)
		}
	}
	net.everyReaderAgrees()
}

// With no binding, m's new device still comes in by an admin's admission (§7.9's admission row), which needs no code.
func TestAnAdminAdmitsAMembersDeviceAfterAVoid(t *testing.T) {
	net, member, _, _, _ := newTestConfigVoidedNet(t)
	phone := net.device("m phone", member)
	net.admitDevice(net.owner, phone, 0)
	if row := net.log.State().SidecarRow(phone.sidecarId); row == nil || row.GetRevokedAt() != 0 || row.GetParkedAt() != 0 {
		t.Fatalf("the phone an admin admitted: %v", row)
	}
	if net.log.State().CurrentBinding(member) != nil {
		t.Error("an admission bound a code")
	}
	net.everyReaderAgrees()
}

// A void of a binding that is not the one in effect leaves the one in effect: a device later found compromised bound
// key one, m's laptop then rebound m to key two, and the cascade voids only key one's binding, so key two still admits.
func TestAVoidOfAnEarlierBindingLeavesTheOneInEffect(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	stolen := net.device("m stolen", member)
	net.admitDevice(laptop, stolen, 0)
	// the member's own confirmation of the device its laptop admitted, so the stolen device signs for the member
	net.mustPost(laptop, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(stolen))
	sinceN := net.n + 1
	keyOne := testConfigRecovery(member, "m one")
	net.mustPost(stolen, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(keyOne))
	keyTwo := testConfigRecovery(member, "m two")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_REBIND, &protocol.RecoveryRebind{Header: net.header(), MemberId: member.Bytes(),
		PrevSha256: keyOne.sha256(), Ed25519PublicKeySha256: keyTwo.sha256(), Reason: bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE})
	plan, err := net.log.State().CascadePlan(stolen.sidecarId, sinceN)
	if err != nil || len(plan.VoidedBindings) != 1 || !bytes.Equal(plan.VoidedBindings[0].KeySha256, keyOne.sha256()) {
		t.Fatalf("the plan: %+v, %v", plan, err)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(stolen, sinceN))

	state := net.log.State()
	if binding := state.CurrentBinding(member); binding == nil || !bytes.Equal(binding.GetKeySha256(), keyTwo.sha256()) {
		t.Fatalf("the binding in effect after a void below it: %v", binding)
	}
	phone := net.device("m phone", member)
	if admitted := net.postByRecovery(keyTwo, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)); !admitted.Accepted() {
		t.Fatalf("the key in effect: %v", admitted.Refusal)
	}
	if verdict := net.postByRecovery(keyOne, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(net.device("m by one", member), nil, false, 0, 0)); verdict.Accepted() {
		t.Error("the voided key admitted")
	}
	net.everyReaderAgrees()
}

// A proposal the voided key signed closes at the void, and no tick activates it: an AdminSet member's key proposes its
// member's device, the cascade voids that key's binding, and a tick 72 h on is refused at api's check and every reader.
func TestAVoidClosesWhatTheVoidedKeyProposed(t *testing.T) {
	net := newTestConfigNet(t)
	stolen := net.device("owner stolen", net.ownerMemberId)
	net.admitDevice(net.owner, stolen, 0)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(stolen))
	sinceN := net.n + 1
	key := testConfigRecovery(net.ownerMemberId, "owner")
	net.mustPost(stolen, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	phone := net.device("owner phone", net.ownerMemberId)
	proposed := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(phone, nil, false, 0, 0)))
	if !proposed.Accepted() {
		t.Fatalf("the proposal: %v", proposed.Refusal)
	}
	proposalId := bytes.Clone(proposed.StatementId[:])
	if window, ok := net.log.State().RecoveryWindow(proposalId); !ok || window.ClosedAt != 0 ||
		bridge.ProposalKind(window.Row.GetKind()) != bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY {
		t.Fatalf("the proposal's window: %+v", window)
	}

	voided := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(stolen, sinceN))
	state := net.log.State()
	if state.CurrentBinding(net.ownerMemberId) != nil {
		t.Fatal("the void left the owner a binding")
	}
	if window, ok := state.RecoveryWindow(proposalId); !ok || window.ClosedAt != voided.Pin.GetVersion() || window.Closed != ConfigProposalVoided {
		t.Fatalf("the proposal after the void: %+v", window)
	}
	net.wait(72 * testConfigHourMs)
	if err := net.log.CheckTick(&bridge.ApiTick{ActivatedProposalIds: [][]byte{proposalId}}, net.timeMs+1000); !errors.Is(err, ErrConfigRule) {
		t.Errorf("api's check of the voided proposal's tick: %v", err)
	}
	if verdict := net.activate(proposalId); verdict.Accepted() {
		t.Error("a voided proposal activated")
	}
	if net.log.State().SidecarRow(phone.sidecarId) != nil {
		t.Error("the voided proposal admitted the phone")
	}
	net.everyReaderAgrees()
}

// Rows carry a recovery-scoped proposal through a base unchanged, to a new device and a rows-only gate alike, and api
// takes the base; the same rows with the row's kind one of the reserved restored kinds, 3 or 4 (QD-1034), past them, 5,
// or unspecified, 0, are refused at api and a fork at a reader, so no verifier holds a kind it cannot judge.
func TestRowsRefuseTheReservedRestoredKinds(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	key := testConfigRecovery(member, "m")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	net.foldSelfAdmit(2, false)
	tablet := net.device("m tablet", member)
	proposed := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(tablet, nil, false, 0, 0)))
	if !proposed.Accepted() {
		t.Fatalf("the proposal: %v", proposed.Refusal)
	}
	proposalId := bytes.Clone(proposed.StatementId[:])
	rows := net.log.State().Rows()
	index := -1
	for i, row := range rows.GetProposals() {
		if bytes.Equal(row.GetProposalId(), proposalId) {
			index = i
		}
	}
	if index < 0 || bridge.ProposalKind(rows.GetProposals()[index].GetKind()) != bridge.ProposalKind_PROPOSAL_KIND_RECOVERY_SCOPED {
		t.Fatalf("the rows hold no recovery-scoped row of the proposal: %v", rows.GetProposals())
	}

	net.setHeadSelfAdmit(3, false)
	for _, kind := range []uint32{3, 4, 5, 0} {
		bad := proto.Clone(rows).(*bridge.ProjectionRows)
		bad.Proposals[index].Kind = kind
		entryBytes := net.makeBase(net.owner, bad, net.n, 3, 0)
		signedHeader, rowsBytes, timeMs := net.baseParts(entryBytes)
		if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes, timeMs); !errors.Is(err, ErrConfigRule) {
			t.Errorf("kind %d: api's check %v", kind, err)
		}
		if _, err := net.newReader().Apply(entryBytes, net.source); !errors.Is(err, ErrConfigFork) {
			t.Errorf("kind %d: a reader %v", kind, err)
		}
	}

	entryBytes := net.makeBase(net.owner, rows, net.n, 3, 0)
	signedHeader, rowsBytes, timeMs := net.baseParts(entryBytes)
	if err := net.apiAtTip().CheckBase(signedHeader, rowsBytes, timeMs); err != nil {
		t.Fatalf("api's check of the honest base: %v", err)
	}
	if verdict := net.push(entryBytes); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	want := rows.GetProposals()[index]
	for i, reader := range net.everyReader() {
		got := reader.State().openProposalRows()
		if len(got) != 1 || !proto.Equal(got[0], want) {
			t.Errorf("reader %d: the proposals %v, want %v", i, got, want)
		}
	}
	net.everyReaderAgrees()
}

// No window activates a proposal that is not k of n: a recovery-scoped admission, which completes only at its cosign,
// is refused at a tick 72 h on, at api's check and at every reader, and admits nothing.
func TestNoTickActivatesARecoveryScopedAdmission(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	key := testConfigRecovery(member, "m")
	net.mustPost(laptop, bridge.SignedType_SIGNED_RECOVERY_BIND, net.recoveryBind(key))
	net.foldSelfAdmit(2, false)
	tablet := net.device("m tablet", member)
	proposed := net.postByRecovery(key, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, net.longProposal(bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(tablet, nil, false, 0, 0)))
	if !proposed.Accepted() {
		t.Fatalf("the proposal: %v", proposed.Refusal)
	}
	proposalId := bytes.Clone(proposed.StatementId[:])
	net.wait(72 * testConfigHourMs)
	if err := net.log.CheckTick(&bridge.ApiTick{ActivatedProposalIds: [][]byte{proposalId}}, net.timeMs+1000); !errors.Is(err, ErrConfigRule) {
		t.Errorf("api's check of the tick: %v", err)
	}
	if verdict := net.activate(proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Errorf("the activation: %v", verdict.Refusal)
	}
	if net.log.State().SidecarRow(tablet.sidecarId) != nil {
		t.Error("a tick admitted a recovery-scoped admission's device")
	}
	net.everyReaderAgrees()
}
