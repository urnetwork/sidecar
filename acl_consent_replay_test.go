// §8.5's confirmed clause counts every confirmation a device's row keeps (QD-1208): acl_consent.go's replay takes each
// ConfirmationRow of SidecarRow.confirmations as its own event, kind 1 an AdmissionConfirm and kind 2 an OwnerConfirm,
// judged at its own entry, so a newer confirmation of the same kind hides no older one. An admin's second
// AdmissionConfirm of a device its member's laptop consented leaves that consent standing; an OwnerConfirm by the laptop
// outside a cascade's P keeps the device consented, and out of P, when a later one by the phone is void; and a device
// whose every confirmation is void or by a signer that was not its member's consented device when it signed is not
// consented. QD-1191's consented list follows the replay at every reader, a rows-only gate and a reader started at a
// later base included. Hand-made rows and the test network, on every leg.

package sidecar

import (
	"bytes"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A confirmation of kind by signer at the next position, as configConfirmSidecar records one: the newest of its kind,
// where the kind is one the rules write, and one more ConfirmationRow in the row's history. Its position.
func (self *aclTestFixture) confirm(sidecarId Id, kind uint32, signer []byte) uint64 {
	row := self.admission(sidecarId).Row
	at := self.next()
	switch kind {
	case configConfirmAdmission:
		row.ConfirmSigner, row.ConfirmedAt = bytes.Clone(signer), at
	case configConfirmOwner:
		row.OwnerConfirmSigner, row.OwnerConfirmedAt = bytes.Clone(signer), at
	}
	row.Confirmations = append(row.Confirmations, &bridge.ConfirmationRow{Kind: kind, Signer: bytes.Clone(signer), At: at})
	return at
}

// Fails unless the state's row of repoId lists exactly devices, in their order.
func testConsentReplayRequireListed(t *testing.T, state *ConfigState, repoId Id, label string, devices ...testConfigDevice) {
	t.Helper()
	want := [][]byte{}
	for _, device := range devices {
		want = append(want, device.sidecarId.Bytes())
	}
	if listed := state.Repo(repoId).GetConsentedSidecarIds(); !slices.EqualFunc(listed, want, bytes.Equal) {
		t.Errorf("%s: the vault lists %x, want %x", label, listed, want)
	}
}

// The state's AclState, failing the test where it cannot be built.
func testConsentReplayAcl(t *testing.T, state *ConfigState) *AclState {
	t.Helper()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

// The replay over hand-made rows: a confirmation the history keeps counts at its own position whatever the newest of
// its kind names, the device consented from the first that counts; one void, by another member's device or by a device
// consented only after it signed counts for nothing; and so does one of a kind no rule writes.
func TestAclEveryConfirmationARowKeepsCountsForConsent(t *testing.T) {
	fixture := newAclTestFixture()
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admin := fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	adminDevice := fixture.invitedDevice(admin)
	laptop := fixture.invitedDevice(member)
	phone := fixture.device(member, laptop.Bytes())

	// the laptop's AdmissionConfirm, then the admin's, the newest of its kind
	reconfirmed := fixture.device(member, adminDevice.Bytes())
	laptopConfirmedAt := fixture.confirm(reconfirmed, configConfirmAdmission, laptop.Bytes())
	fixture.confirm(reconfirmed, configConfirmAdmission, adminDevice.Bytes())

	// the laptop's OwnerConfirm, then the phone's, which the phone's cascade voids
	outsideP := fixture.device(member, adminDevice.Bytes())
	laptopOwnerConfirmedAt := fixture.confirm(outsideP, configConfirmOwner, laptop.Bytes())
	sinceN := fixture.next()
	fixture.confirm(outsideP, configConfirmOwner, phone.Bytes())

	// the phone's OwnerConfirm in P, the admin's AdmissionConfirm, and an OwnerConfirm by a device of the member the
	// laptop consents only after it signed
	late := fixture.device(member, adminDevice.Bytes())
	allVoid := fixture.device(member, adminDevice.Bytes())
	fixture.confirm(allVoid, configConfirmOwner, phone.Bytes())
	fixture.confirm(allVoid, configConfirmAdmission, adminDevice.Bytes())
	fixture.confirm(allVoid, configConfirmOwner, late.Bytes())
	fixture.confirm(late, configConfirmOwner, laptop.Bytes())

	// the phone's OwnerConfirm in P, then the laptop's AdmissionConfirm, the first that counts
	restored := fixture.device(member, adminDevice.Bytes())
	fixture.confirm(restored, configConfirmOwner, phone.Bytes())
	laptopRestoredAt := fixture.confirm(restored, configConfirmAdmission, laptop.Bytes())

	// the laptop's confirmations of kinds no rule writes
	unknownKind := fixture.device(member, adminDevice.Bytes())
	fixture.confirm(unknownKind, 0, laptop.Bytes())
	fixture.confirm(unknownKind, configConfirmOwner+1, laptop.Bytes())

	// the phone revoked for compromise from since_n, what it signed there void
	fixture.admission(phone).Row.RevokedAt = fixture.next()
	fixture.view.voidFrom[string(phone.Bytes())] = sinceN
	state := fixture.state(t)

	consented := map[string]Id{"reconfirmed": reconfirmed, "outside P": outsideP, "late": late, "restored": restored, "laptop": laptop}
	for name, sidecarId := range consented {
		if !state.ConsentedFor(sidecarId, member) {
			t.Errorf("%s is not consented", name)
		}
	}
	for name, sidecarId := range map[string]Id{"all void": allVoid, "unknown kind": unknownKind, "the revoked phone": phone} {
		if state.Consented(sidecarId) {
			t.Errorf("%s is consented", name)
		}
	}
	consentedAts := map[string]uint64{"reconfirmed": laptopConfirmedAt, "outside P": laptopOwnerConfirmedAt, "restored": laptopRestoredAt}
	for name, want := range consentedAts {
		if consentedAt := state.sidecarState(consented[name]).consentedAt; consentedAt != want {
			t.Errorf("%s consented from %d, its laptop's confirmation at %d", name, consentedAt, want)
		}
	}
}

// QD-1208's first case on the test network: the network owner's device, an admin, admits m's tablet; the laptop's
// AdmissionConfirm consents it and lists it in m's vault; and the admin's second AdmissionConfirm, which takes the row's
// confirm_signer, leaves it consented from the laptop's confirmation and listed, reading and writing the vault, where
// before it stripped the consent and the list dropped the tablet. Every reader agrees, after a base whose rows carry the
// history too.
func TestAclAnAdminsSecondAdmissionConfirmLeavesALaptopsConsent(t *testing.T) {
	net := newTestConfigNet(t)
	memberId, laptop := net.consentedMember("m")
	vaultId := testConsentRowsRepo(net, laptop, "consent replay reconfirmed vault", protocol.RepoKind_REPO_KIND_VAULT)
	tablet := net.device("m reconfirmed tablet", memberId)
	net.admitDevice(net.owner, tablet, 0)
	testConsentReplayRequireListed(t, net.log.State(), vaultId, "at the admin's admission", laptop)
	confirm := func(signer testConfigDevice) ConfigVerdict {
		return net.mustPost(signer, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{
			Header: net.header(), SidecarId: tablet.sidecarId.Bytes(),
		})
	}
	laptopConfirmed := confirm(laptop)
	testConsentReplayRequireListed(t, net.log.State(), vaultId, "at the laptop's AdmissionConfirm", laptop, tablet)
	confirm(net.owner)

	row := net.log.State().SidecarRow(tablet.sidecarId)
	if !bytes.Equal(row.GetConfirmSigner(), net.owner.sidecarId.Bytes()) || len(row.GetConfirmations()) != 2 ||
		!bytes.Equal(row.GetConfirmations()[0].GetSigner(), laptop.sidecarId.Bytes()) {
		t.Fatalf("the row: confirm_signer %x, confirmations %v", row.GetConfirmSigner(), row.GetConfirmations())
	}
	check := func(label string) {
		t.Helper()
		state := net.log.State()
		acl := testConsentReplayAcl(t, state)
		if !acl.ConsentedFor(tablet.sidecarId, memberId) {
			t.Fatalf("%s: the admin's second AdmissionConfirm stripped the laptop's consent", label)
		}
		if consentedAt := acl.sidecarState(tablet.sidecarId).consentedAt; consentedAt != laptopConfirmed.Pin.GetVersion() {
			t.Errorf("%s: the tablet consented from %d, the laptop's confirmation at %d", label, consentedAt, laptopConfirmed.Pin.GetVersion())
		}
		testConsentReplayRequireListed(t, state, vaultId, label, laptop, tablet)
		if rights := testConsentRowsRights(t, state, tablet.sidecarId, vaultId, AclTokenAudienceGkm); !rights.Has(AclEvsRead) || !rights.Has(AclEvsWrite) {
			t.Errorf("%s: the tablet in m's vault: %b", label, rights)
		}
		net.everyReaderAgrees()
	}
	check("at the admin's second AdmissionConfirm")
	net.fold(net.owner, net.n, 2)
	check("after the base")
}

// QD-1208's second case: the laptop admits the phone, the network owner's device admits g, the laptop's OwnerConfirm
// consents g, and from since_n the phone's OwnerConfirm takes the row's owner_confirm_signer. The phone's compromise
// revocation from since_n voids the phone's confirmation but not the laptop's, outside P, so g's consent rests on a
// signature outside P and the cascade's consent clause, which asks the same replay, leaves g out of P: g stays unparked,
// consented from the laptop's confirmation and in m's vault's list, which drops the phone alone. Before, P took g from
// the phone's confirmation and parked it. Every reader agrees, after a base too.
func TestAclAnOwnerConfirmOutsidePKeepsADeviceConsentedPastAVoidedNewerOne(t *testing.T) {
	net := newTestConfigNet(t)
	memberId, laptop := net.consentedMember("m")
	vaultId := testConsentRowsRepo(net, laptop, "consent replay outside p vault", protocol.RepoKind_REPO_KIND_VAULT)
	phone, deviceG := net.device("m outside p phone", memberId), net.device("m outside p g", memberId)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(net.owner, deviceG, 0)
	laptopConfirmed := net.mustPost(laptop, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(deviceG))
	sinceN := net.n + 1
	net.mustPost(phone, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(deviceG))
	testConsentReplayRequireListed(t, net.log.State(), vaultId, "at the phone's OwnerConfirm", laptop, phone, deviceG)
	row := net.log.State().SidecarRow(deviceG.sidecarId)
	if !bytes.Equal(row.GetOwnerConfirmSigner(), phone.sidecarId.Bytes()) || len(row.GetConfirmations()) != 2 {
		t.Fatalf("the row: owner_confirm_signer %x, confirmations %v", row.GetOwnerConfirmSigner(), row.GetConfirmations())
	}

	closure, err := net.log.State().CascadeClosure(phone.sidecarId, sinceN)
	if err != nil {
		t.Fatal(err)
	}
	if from, held := closure.From(deviceG.sidecarId); held {
		t.Errorf("P holds g from %d, though the laptop's OwnerConfirm stands outside it: %v", from, closure.Members)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	check := func(label string) {
		t.Helper()
		state := net.log.State()
		if state.Parked(deviceG.sidecarId) {
			t.Fatalf("%s: the phone's revocation parked g", label)
		}
		acl := testConsentReplayAcl(t, state)
		if !acl.ConsentedFor(deviceG.sidecarId, memberId) {
			t.Fatalf("%s: g lost the laptop's consent to the phone's voided OwnerConfirm", label)
		}
		if consentedAt := acl.sidecarState(deviceG.sidecarId).consentedAt; consentedAt != laptopConfirmed.Pin.GetVersion() {
			t.Errorf("%s: g consented from %d, the laptop's OwnerConfirm at %d", label, consentedAt, laptopConfirmed.Pin.GetVersion())
		}
		testConsentReplayRequireListed(t, state, vaultId, label, laptop, deviceG)
		if rights := testConsentRowsRights(t, state, deviceG.sidecarId, vaultId, AclTokenAudienceGkm); !rights.Has(AclEvsRead) || !rights.Has(AclEvsWrite) {
			t.Errorf("%s: g in m's vault: %b", label, rights)
		}
		net.everyReaderAgrees()
	}
	check("at the phone's compromise revocation")
	net.fold(net.owner, net.n, 2)
	check("after the base")
}

// QD-1208's refusal: a device whose every confirmation is void or by a signer that is not its member's consented device
// is not consented. The network owner's device admits k; from since_n the phone's OwnerConfirm consents k and lists it,
// and the owner's AdmissionConfirm, an admin's, neither adds nor takes away. The phone's compromise revocation voids
// the phone's confirmation, so P takes k from it and the list drops k; the admin's AdmissionConfirm that lifts k's park
// restores all but owner-bound reads (§7.9's lift): k is unparked but neither consented nor listed, and deposits alone
// in m's vault. Every reader agrees, after a base too.
func TestAclADeviceWhoseEveryConfirmationIsVoidOrAnAdminsIsNotConsented(t *testing.T) {
	net := newTestConfigNet(t)
	memberId, laptop := net.consentedMember("m")
	vaultId := testConsentRowsRepo(net, laptop, "consent replay all void vault", protocol.RepoKind_REPO_KIND_VAULT)
	phone, deviceK := net.device("m all void phone", memberId), net.device("m all void k", memberId)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(net.owner, deviceK, 0)
	sinceN := net.n + 1
	phoneConfirmed := net.mustPost(phone, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(deviceK))
	adminConfirm := func() {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{
			Header: net.header(), SidecarId: deviceK.sidecarId.Bytes(),
		})
	}
	adminConfirm()
	if !testConsentReplayAcl(t, net.log.State()).ConsentedFor(deviceK.sidecarId, memberId) {
		t.Fatal("the admin's AdmissionConfirm hid the phone's OwnerConfirm")
	}
	testConsentReplayRequireListed(t, net.log.State(), vaultId, "at the admin's AdmissionConfirm", laptop, phone, deviceK)

	closure, err := net.log.State().CascadeClosure(phone.sidecarId, sinceN)
	if err != nil {
		t.Fatal(err)
	}
	if from, held := closure.From(deviceK.sidecarId); !held || from != phoneConfirmed.Pin.GetVersion() {
		t.Errorf("k: from %d, held %v, want from the phone's OwnerConfirm at %d: %v", from, held, phoneConfirmed.Pin.GetVersion(), closure.Members)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	if !net.log.State().Parked(deviceK.sidecarId) {
		t.Fatal("the phone's revocation left k unparked")
	}
	testConsentReplayRequireListed(t, net.log.State(), vaultId, "at the phone's compromise revocation", laptop)
	adminConfirm()

	row := net.log.State().SidecarRow(deviceK.sidecarId)
	if confirmations := row.GetConfirmations(); len(confirmations) != 3 || confirmations[0].GetKind() != configConfirmOwner ||
		confirmations[1].GetLiftedPark() || !confirmations[2].GetLiftedPark() {
		t.Fatalf("the confirmations: %v", confirmations)
	}
	check := func(label string) {
		t.Helper()
		state := net.log.State()
		if state.Parked(deviceK.sidecarId) {
			t.Fatalf("%s: the admin's AdmissionConfirm did not lift k's park", label)
		}
		if testConsentReplayAcl(t, state).Consented(deviceK.sidecarId) {
			t.Fatalf("%s: k is consented on a void OwnerConfirm and an admin's AdmissionConfirms", label)
		}
		testConsentReplayRequireListed(t, state, vaultId, label, laptop)
		if rights := testConsentRowsRights(t, state, deviceK.sidecarId, vaultId, AclTokenAudienceGkm); rights != AclEvsDeposit {
			t.Errorf("%s: k in m's vault: %b", label, rights)
		}
		net.everyReaderAgrees()
	}
	check("at the admin's lift")
	net.fold(net.owner, net.n, 2)
	check("after the base")
}
