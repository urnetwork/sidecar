// §7.9's compromise cascade on the test network: §22.7's cascade list (an admission chain parked at every depth, an
// OwnerConfirm that is a device's only consent and one that adds nothing, a personal network revoking its stolen first
// device from a device that one admitted, a Delegation the stolen device signed), each record counting from its
// carrying entry whatever its signer's at, a lifted park pulled back in by its lifter's revocation from the
// confirmation history, what P signed staying void after a lift, the plan's items, and P from rows alone equal to a
// reference and to a reader that kept every entry, over generated logs with bases between since_n and the revocation.

package sidecar

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A compromise revocation of device from sinceN at the tip.
func (self *testConfigNet) compromise(device testConfigDevice, sinceN uint64) *bridge.SidecarRevoke {
	revoke := self.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE)
	revoke.SinceN = sinceN
	return revoke
}

// An OwnerConfirm of device at the tip.
func (self *testConfigNet) ownerConfirm(device testConfigDevice) *protocol.OwnerConfirm {
	return &protocol.OwnerConfirm{Header: self.header(), SidecarId: device.sidecarId.Bytes()}
}

// The closure as a map from each sidecar P holds to the position it holds it from.
func testConfigClosureMap(closure *ConfigCascadeClosure) map[Id]uint64 {
	from := map[Id]uint64{}
	for _, member := range closure.Members {
		from[member.SidecarId] = member.From
	}
	return from
}

// §22.7: A admits B and B admits C after since_n, so a compromise revocation of A parks both; from a since_n after C's
// admission it parks neither.
func TestACascadeParksAnAdmissionChainAtEveryDepth(t *testing.T) {
	for _, late := range []bool{false, true} {
		net := newTestConfigNet(t)
		member, laptop := net.consentedMember("m")
		phone, tablet, watch := net.device("m phone", member), net.device("m tablet", member), net.device("m watch", member)
		net.admitDevice(laptop, phone, 0)
		sinceN := net.n + 1
		net.admitDevice(phone, tablet, 0)
		net.admitDevice(tablet, watch, 0)
		if late {
			sinceN = net.n + 1
			net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("a later entry"))
		}
		revoked := net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
		state := net.log.State()
		if state.SidecarRow(phone.sidecarId).GetRevokedAt() != revoked.Pin.GetVersion() {
			t.Errorf("late %v: the phone is not revoked", late)
		}
		for _, device := range []testConfigDevice{tablet, watch} {
			if state.Parked(device.sidecarId) == late {
				t.Errorf("late %v: %s parked %v", late, device.sidecarId, state.Parked(device.sidecarId))
			}
		}
		if state.Parked(laptop.sidecarId) {
			t.Errorf("late %v: the laptop parked", late)
		}
		if !late && !slices.Equal(state.ParkedSet(), slices.SortedFunc(slices.Values([]Id{tablet.sidecarId, watch.sidecarId}), Id.Cmp)) {
			t.Errorf("the parked set %v", state.ParkedSet())
		}
		net.everyReaderAgrees()
	}
}

// §22.7: the stolen phone's OwnerConfirm of an admin-admitted G, G's only consent, parks G; its OwnerConfirm of H, which
// the laptop admitted and so consented, adds nothing and parks nothing. From rows alone, at a new device and a
// rows-only gate started at a base after the confirmations, P is the same.
func TestAnOwnerConfirmParksOnlyADeviceWhoseConsentRestsOnIt(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, deviceG, deviceH := net.device("m phone", member), net.device("m g", member), net.device("m h", member)
	net.admitDevice(laptop, phone, 0)
	net.admitDevice(net.owner, deviceG, 0)
	net.admitDevice(laptop, deviceH, 0)
	sinceN := net.n + 1
	confirmedG := net.mustPost(phone, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(deviceG))
	net.mustPost(phone, bridge.SignedType_SIGNED_OWNER_CONFIRM, net.ownerConfirm(deviceH))
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if !acl.ConsentedFor(deviceG.sidecarId, member) || !acl.ConsentedFor(deviceH.sidecarId, member) {
		t.Fatal("G or H not consented")
	}
	net.fold(net.owner, net.n, 2)

	want, err := net.log.State().CascadeClosure(phone.sidecarId, sinceN)
	if err != nil {
		t.Fatal(err)
	}
	if from, held := want.From(deviceG.sidecarId); !held || want.Members[1].Reason != ConfigCascadeConsent || from != confirmedG.Pin.GetVersion() {
		t.Errorf("G: from %d, held %v, %v", from, held, want.Members)
	}
	if _, held := want.From(deviceH.sidecarId); held {
		t.Error("H, consented otherwise, is in P")
	}
	for i, reader := range net.everyReader() {
		got, err := reader.State().CascadeClosure(phone.sidecarId, sinceN)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got.Members, want.Members) {
			t.Errorf("reader %d: %v, want %v", i, got.Members, want.Members)
		}
	}

	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	state := net.log.State()
	if !state.Parked(deviceG.sidecarId) || state.Parked(deviceH.sidecarId) {
		t.Errorf("G parked %v, H parked %v", state.Parked(deviceG.sidecarId), state.Parked(deviceH.sidecarId))
	}
	net.everyReaderAgrees()
}

// §22.7: a personal network revokes its stolen first device from the phone that device admitted: refused from since_n
// 1, where P would hold the phone, and accepted from the loss position, after the phone's admission.
func TestAPersonalNetworkRevokesItsStolenFirstDeviceFromTheLossPosition(t *testing.T) {
	net := newTestConfigNet(t)
	phone := net.device("owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, phone, 0)
	lossN := net.n + 1
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("after the loss"))

	net.mustRefuse(phone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(net.owner, 1), ErrConfigAuthority)
	revoked := net.mustPost(phone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(net.owner, lossN))
	state := net.log.State()
	if state.SidecarRow(net.owner.sidecarId).GetRevokedAt() != revoked.Pin.GetVersion() || state.Parked(phone.sidecarId) {
		t.Error("the stolen device is not revoked or the phone parked")
	}
	if !state.IsConfigWriter(phone.sidecarId) || state.IsConfigWriter(net.owner.sidecarId) {
		t.Error("the phone does not write the config, or the stolen device does")
	}
	net.everyReaderAgrees()
}

// A compromise revocation's shape: never by the device itself, since_n from 1 to before its entry, and only by one that
// may revoke the device.
func TestACompromiseRevocationsShape(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone := net.device("m phone", member)
	net.admitDevice(laptop, phone, 0)
	other, otherLaptop := net.consentedMember("other")
	_ = other
	net.mustRefuse(phone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, 1), ErrConfigAuthority)
	net.mustRefuse(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, net.n+1), ErrConfigRule)
	net.mustRefuse(otherLaptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, 1), ErrConfigAuthority)
	if _, err := net.log.State().CascadeClosure(testConfigId("nobody"), 1); !errors.Is(err, ErrConfigRule) {
		t.Errorf("a closure of no sidecar: %v", err)
	}
	if _, err := net.log.State().CascadeClosure(phone.sidecarId, 0); !errors.Is(err, ErrConfigRule) {
		t.Errorf("a closure with no since_n: %v", err)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, 1))
}

// §7.9's cascade row: a record counts from the entry that carried it, never its signer's at, so a stolen device that
// dates its admission before since_n still parks what it admitted.
func TestACascadeCountsFromTheCarryingEntryNotTheSignersAt(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, tablet := net.device("m phone", member), net.device("m tablet", member)
	net.admitDevice(laptop, phone, 0)
	early := net.statesAt[net.n-1].Pin()
	sinceN := net.n + 1
	admit := net.admission(tablet, nil, false, 0, 0)
	admit.Header.At = early
	net.mustPost(phone, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	if !net.log.State().Parked(tablet.sidecarId) {
		t.Error("a backdated admission escaped the cascade")
	}
}

// §7.9's lift: an admin's AdmissionConfirm lifts a park, which the row's history keeps; a later compromise
// revocation of that admin's device pulls the lifted device back into P from the confirmation alone, though a newer
// confirmation by someone else took the row's confirm_signer since (DESIGN-DETAILS 5.2.3's confirmations), at every
// reader, a rows-only gate and a new device included.
func TestAnAdmissionConfirmThatLiftedAParkJoinsTheCascade(t *testing.T) {
	net := newTestConfigNet(t)
	memberTwo, stolenFirst := net.consentedMember("m2")
	parkedDevice := net.device("m2 tablet", memberTwo)
	sinceFirst := net.n + 1
	net.admitDevice(stolenFirst, parkedDevice, 0)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(stolenFirst, sinceFirst))
	if !net.log.State().Parked(parkedDevice.sidecarId) {
		t.Fatal("the first cascade did not park the tablet")
	}

	ownerPhone := net.device("owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, ownerPhone, 0)
	sinceSecond := net.n + 1
	lift := net.mustPost(ownerPhone, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: parkedDevice.sidecarId.Bytes()})
	if net.log.State().Parked(parkedDevice.sidecarId) {
		t.Fatal("the admin's confirmation did not lift the park")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: parkedDevice.sidecarId.Bytes()})
	row := net.log.State().SidecarRow(parkedDevice.sidecarId)
	if !bytes.Equal(row.GetConfirmSigner(), net.owner.sidecarId.Bytes()) || len(row.GetConfirmations()) != 2 ||
		!row.GetConfirmations()[0].GetLiftedPark() || row.GetConfirmations()[1].GetLiftedPark() {
		t.Fatalf("the confirmations: %v", row.GetConfirmations())
	}
	net.fold(net.owner, net.n, 2)

	closure, err := net.log.State().CascadeClosure(ownerPhone.sidecarId, sinceSecond)
	if err != nil {
		t.Fatal(err)
	}
	if from, held := closure.From(parkedDevice.sidecarId); !held || from != lift.Pin.GetVersion() {
		t.Errorf("the tablet from %d, held %v", from, held)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(ownerPhone, sinceSecond))
	if !net.log.State().Parked(parkedDevice.sidecarId) {
		t.Error("the lifter's revocation left the tablet unparked")
	}
	net.everyReaderAgrees()
}

// §7.9's lift row: what a sidecar signed in P stays void after its park is lifted, and what it signs after counts;
// the device it admitted in P stays parked.
func TestWhatPSignedStaysVoidAfterALift(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	phone, tablet, watch := net.device("m phone", member), net.device("m tablet", member), net.device("m watch", member)
	net.admitDevice(laptop, phone, 0)
	sinceN := net.n + 1
	net.admitDevice(phone, tablet, 0)
	inP := net.n + 1
	net.admitDevice(tablet, watch, 0)
	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(phone, sinceN))
	net.mustPost(laptop, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: tablet.sidecarId.Bytes()})
	state := net.log.State()
	if state.Parked(tablet.sidecarId) || !state.Parked(watch.sidecarId) {
		t.Fatalf("tablet parked %v, watch parked %v", state.Parked(tablet.sidecarId), state.Parked(watch.sidecarId))
	}
	if !state.CascadeVoids(tablet.sidecarId.Bytes(), inP) || state.CascadeVoids(tablet.sidecarId.Bytes(), net.n+1) ||
		state.CascadeVoids(laptop.sidecarId.Bytes(), inP) {
		t.Error("the tablet's span is not what it signed in P")
	}
	afterLift := net.device("m pen", member)
	net.admitDevice(tablet, afterLift, 0)
	if net.log.State().Parked(afterLift.sidecarId) || !net.log.State().Parked(watch.sidecarId) {
		t.Error("the lift moved what the tablet signed in P, or parked what it signed after")
	}
	net.everyReaderAgrees()
}

// §22.7: a Delegation the stolen device signed is void: it ends at the revocation and its agents park.
func TestADelegationAStolenDeviceSignedEnds(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	ownerPhone := net.device("owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, ownerPhone, 0)
	sinceN := net.n + 1
	delegation := net.delegate(ownerPhone, "d", []Id{ci}, 5, net.timeMs+30*day)
	agent := net.device("agent", Id{})
	if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, false, delegation.notAfter)); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if net.log.State().CascadeVoids(delegation.id, net.n) {
		t.Fatal("a Delegation is void before any cascade")
	}
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.compromise(ownerPhone, sinceN))
	state := net.log.State()
	if at, ended := state.DelegationEnded(delegation.id); !ended || at != revoked.Pin.GetVersion() || !state.Parked(agent.sidecarId) {
		t.Errorf("D ended at %d (%v), the agent parked %v", at, ended, state.Parked(agent.sidecarId))
	}
	if !state.CascadeVoids(delegation.id, net.n) {
		t.Error("the Delegation's records are not void")
	}
	net.everyReaderAgrees()
}

// The plan lists what P parks, the Delegations it ends and what P signed that stands, with their positions, as
// DeviceRevokeItem's items.
func TestACascadePlansItems(t *testing.T) {
	net, ci, _ := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	ownerPhone := net.device("owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, ownerPhone, 0)
	sinceN := net.n + 1
	member := testConfigId("m")
	net.admitMember(ownerPhone, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	device := net.device("m device", member)
	net.admitDevice(ownerPhone, device, 0)
	delegation := net.delegate(ownerPhone, "d", []Id{ci}, 5, net.timeMs+30*day)
	plan, err := net.log.State().CascadePlan(ownerPhone.sidecarId, sinceN)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Parks, []Id{device.sidecarId}) || len(plan.EndedDelegationIds) != 1 || !bytes.Equal(plan.EndedDelegationIds[0], delegation.id) {
		t.Fatalf("parks %v, ended %x", plan.Parks, plan.EndedDelegationIds)
	}
	items := plan.Items()
	kinds := []string{}
	for _, item := range items {
		kinds = append(kinds, item.Effect+" "+item.Kind)
	}
	if !slices.Contains(kinds, "park device") || !slices.Contains(kinds, "void delegation") {
		t.Errorf("items %v", kinds)
	}
}

// The reference P: one pass over every admission and park-lifting confirmation in position order from since_n, each
// joining P when a signer then in P signed it, as §7.9's cascade row reads, without the consent clause.
func testConfigReferenceClosure(state *ConfigState, targetId Id, sinceN uint64) map[Id]uint64 {
	type record struct {
		at        uint64
		subjectId Id
		signers   [][]byte
		byTarget  bool
	}
	records := []record{}
	targetDelegationId := state.SidecarRow(targetId).GetDelegationId()
	for _, sidecarId := range state.SidecarIds() {
		row := state.SidecarRow(sidecarId)
		records = append(records, record{
			at: row.GetAdmittedAt(), subjectId: sidecarId, signers: row.GetAdmissionSigners(),
			byTarget: len(targetDelegationId) != 0 && bytes.Equal(row.GetDelegationId(), targetDelegationId),
		})
		for _, confirmation := range row.GetConfirmations() {
			if confirmation.GetLiftedPark() {
				records = append(records, record{at: confirmation.GetAt(), subjectId: sidecarId, signers: [][]byte{confirmation.GetSigner()}})
			}
		}
	}
	slices.SortStableFunc(records, func(a record, b record) int { return cmp.Compare(a.at, b.at) })
	from := map[Id]uint64{targetId: sinceN}
	var voids func(signer []byte, at uint64) bool
	voids = func(signer []byte, at uint64) bool {
		if len(signer) == len(Id{}) {
			position, held := from[Id(signer)]
			return held && position <= at
		}
		if delegation := state.Delegation(signer); delegation != nil {
			return voids(delegation.GetSigner(), delegation.GetAt())
		}
		return false
	}
	for _, record := range records {
		if record.at < sinceN {
			continue
		}
		if _, held := from[record.subjectId]; held {
			continue
		}
		joins := record.byTarget
		for _, signer := range record.signers {
			joins = joins || voids(signer, record.at)
		}
		if joins {
			from[record.subjectId] = record.at
		}
	}
	return from
}

// A generated log of admissions by admins and members' own devices, lost revocations, compromise revocations that
// park, admins' confirmations that lift, and folds, from a seed; it returns the member devices admitted.
func (self *testConfigNet) generateCascades(seed uint64, count int) []testConfigDevice {
	self.t.Helper()
	random := rand.New(rand.NewPCG(seed, seed^0x51ed270b2f35a6c1))
	pick := func(count int) int { return random.IntN(count) }
	devices := []testConfigDevice{}
	for i := range 3 {
		_, first := self.consentedMember(fmt.Sprintf("generated member %d %d", seed, i))
		devices = append(devices, first)
	}
	configVersion := self.log.State().Base().GetConfigVersion()
	for i := range count {
		state := self.log.State()
		standing := []testConfigDevice{}
		for _, device := range devices {
			if _, ok := state.standingSidecar(device.sidecarId, state.TimeMs()); ok {
				standing = append(standing, device)
			}
		}
		switch op := pick(8); {
		case op <= 2 && 0 < len(standing):
			signer := standing[pick(len(standing))]
			device := self.device(fmt.Sprintf("generated %d %d", seed, i), signer.memberId)
			if pick(3) == 0 {
				signer = self.owner
			}
			if verdict := self.post(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, self.admission(device, nil, false, 0, 0)); verdict.Accepted() {
				devices = append(devices, device)
			}
		case op == 3:
			target := devices[pick(len(devices))]
			self.post(self.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, self.compromise(target, 1+uint64(pick(int(self.n)))))
		case op == 4:
			target := devices[pick(len(devices))]
			self.post(self.owner, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: self.header(), SidecarId: target.sidecarId.Bytes()})
		case op == 5 && 0 < len(standing):
			target := standing[pick(len(standing))]
			self.post(self.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, self.revocation(target, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
		case op == 6:
			configVersion += 1
			self.fold(self.owner, self.n, configVersion)
		default:
			self.mustPost(self.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, self.memberAdmitStatement(fmt.Sprintf("generated filler %d %d", seed, i)))
		}
	}
	return devices
}

// Property: over generated logs with bases between since_n and the end, P at the end equals the reference for every
// device and since_n tried, the devices that admitted others most often among them, and a new device, a rows-only gate
// and another long-running reader compute the same P from what they hold.
func TestTheCascadeFromRowsEqualsAReferenceOverGeneratedLogs(t *testing.T) {
	parks := 0
	for seed := uint64(1); seed <= 8; seed += 1 {
		net := newTestConfigNet(t)
		devices := net.generateCascades(seed, 120)
		net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)
		net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(fmt.Sprintf("after %d", seed)))
		readers := net.everyReader()
		state := net.log.State()
		// the devices that signed some admission, which a cascade reaches beyond itself
		admitters := []testConfigDevice{}
		for _, device := range devices {
			for _, sidecarId := range state.SidecarIds() {
				signers := state.SidecarRow(sidecarId).GetAdmissionSigners()
				if slices.ContainsFunc(signers, func(signer []byte) bool { return bytes.Equal(signer, device.sidecarId.Bytes()) }) {
					admitters = append(admitters, device)
					break
				}
			}
		}
		random := rand.New(rand.NewPCG(seed, 7))
		for trial := range 12 {
			target := devices[random.IntN(len(devices))]
			if trial%2 == 0 && 0 < len(admitters) {
				target = admitters[random.IntN(len(admitters))]
			}
			sinceN := 1 + uint64(random.IntN(int(net.n)))
			closure, err := state.CascadeClosure(target.sidecarId, sinceN)
			if err != nil {
				t.Fatal(err)
			}
			want := testConfigReferenceClosure(state, target.sidecarId, sinceN)
			got := testConfigClosureMap(closure)
			if len(got) != len(want) {
				t.Fatalf("seed %d, %s from %d: %v, the reference %v", seed, target.sidecarId, sinceN, got, want)
			}
			for sidecarId, from := range want {
				if got[sidecarId] != from {
					t.Fatalf("seed %d, %s from %d: %s from %d, the reference %d", seed, target.sidecarId, sinceN, sidecarId, got[sidecarId], from)
				}
			}
			parks += len(closure.Members) - 1
			for i, reader := range readers {
				other, err := reader.State().CascadeClosure(target.sidecarId, sinceN)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(other.Members, closure.Members) {
					t.Fatalf("seed %d, reader %d: %v, want %v", seed, i, other.Members, closure.Members)
				}
			}
		}
		testConfigStatesEqual(t, readers[0].State(), state)
	}
	if parks < 20 {
		t.Errorf("the generated closures held %d sidecars beyond their targets", parks)
	}
}
