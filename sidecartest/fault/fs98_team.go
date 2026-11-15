//go:build !js && !ios && !android && !sdk_mobile_bind

// FS-98's Team cases (§22.8; §5.6's revocation, D-CORE-20, D-CORE-13, §7.9's scoped, authority and cascade rows;
// CORE-M6-04) on the CLI world (sidecartest.Fs98World): a real Sidecar in a real Daemon revokes as `ur devices revoke`
// does, by the daemon's devices methods, in a team at k = 2 whose AdminSet is the owner and admins b and c.
//
//   - A member outside the AdminSet revokes another of its own devices from its consented laptop with self_admit on,
//     its devices admitted by its own first device, and off, each admitted by an admin and confirmed by the member:
//     one SidecarRevoke{lost} signed alone either way (§7.9's scoped row: whatever self_admit says). With self_admit off
//     a device an admin admitted that the member never confirmed is still the member's to revoke, another member's
//     device and an admin's are not (REVOKE_NOT_OWN), and a compromise from the entry where the phone confirmed a
//     watch parks the watch, whose consent rested on that confirmation alone, the laptop standing.
//   - An AdminSet member's device at k = 2 answers authority_pending: its proposal and, in the same act, the target's
//     Suspend, so the target, a host itself here, is suspended at once; its revocation of the proposer and its cosign
//     of its own revocation are REVOKE_NOT_CAPABLE, signing nothing, and it is revoked at another admin's cosign.
//
// Registered, the refusal beside the twin that must succeed: FS-98's team (T2+T3): the suspended target's revocation
// of the proposer and its cosign of its own revocation are refused with nothing signed; its twin, the member's laptop
// revoking its lost phone with self_admit off, lands once and every reader drops the phone. The proposal another admin
// approves by `ur approve <proposal_id>` and the one that expires unsigned at its not_after leaving the target
// suspended are the CLI case's, already run in a team at k = 2 (fs98.go). A T2 test runs each named clause
// (fs98_team_test.go), and server's T3 test the same on its sequencer (server/api/fs98_team_db_test.go).
//
// What waits: the phone and remote-mode Team rows (CORE-M8-03), and FS-97's and FS-124's Team cases (TEAM-M6-12).

package fault

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs98Team = Register("FS-98", "team", []Tier{TierT2, TierT3}, Twin(Fs98TeamSuspendedTargetRefused, Fs98TeamSelfAdmitOff))

// The owner admits admins b and c and their first devices from invites, then names them in the AdminSet beside
// itself: k = 2 of 3.
func fs98TeamAdminSet(world *fs98World) error {
	net := world.net()
	owner := net.Owner()
	memberB := net.AdmitMember(owner, "admin b", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	memberC := net.AdmitMember(owner, "admin c", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	adminB, adminC := net.Device("admin b first device", memberB), net.Device("admin c first device", memberC)
	net.AdmitDevice(owner, adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	net.AdmitDevice(owner, adminC, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	world.devices["admin b"], world.devices["admin c"] = adminB, adminC
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{memberB, memberC}, 0)))
	if k, n := net.State().Threshold(); k != 2 || n != 3 {
		return fmt.Errorf("k %d of n %d", k, n)
	}
	return nil
}

// A team at k = 2, then member m outside the AdminSet: with self_admit on its invited first device, a fixture, admits
// its laptop, a host, and its phone; with it off the owner's first device admits each and m's first device confirms
// each, so the laptop is m's consented device and the phone stands live.
func fs98TeamMember(world *fs98World, selfAdmit bool) *Step {
	return fs98Setup(world, func() error {
		net := world.net()
		owner := net.Owner()
		if err := fs98TeamAdminSet(world); err != nil {
			return err
		}
		memberId, first := net.ConsentedMember("m")
		world.devices["first"] = first
		admitter := first
		if !selfAdmit {
			world.world.SetSelfAdmit(false)
			admitter = owner
		}
		laptop := world.world.AddHost("laptop", memberId, admitter, 0)
		world.hosts["laptop"] = laptop
		phone := net.Device("m phone", memberId)
		net.AdmitDevice(admitter, phone, 0)
		world.devices["phone"] = phone
		if !selfAdmit {
			world.world.OwnerConfirm(first, laptop.Device)
			world.world.OwnerConfirm(first, phone)
		}
		if net.State().SelfAdmit() != selfAdmit {
			return fmt.Errorf("self_admit %t", net.State().SelfAdmit())
		}
		world.world.Settle()
		return nil
	})
}

// FS-98's team twin: with self_admit off the member's laptop, which an admin admitted and the member confirmed,
// revokes its lost phone, an admin's admission the member confirmed: one SidecarRevoke{lost} signed alone, and every
// reader drops the phone.
func Fs98TeamSelfAdmitOff(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 team a member's lost phone, self_admit off", world, fs98TeamMember(world, false), fs98RevokeLost(world, 1))
}

// FS-98's team with self_admit on: the member's laptop, which its own first device admitted, revokes its lost phone the
// same way.
func Fs98TeamSelfAdmitOn(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 team a member's lost phone, self_admit on", world, fs98TeamMember(world, true), fs98RevokeLost(world, 1))
}

// FS-98's team with self_admit off, the bounds of the member's own: a watch an admin admitted under the member, which
// the member never confirmed, is the member's to revoke, and the laptop revokes it alone; an admin's device and the
// owner's are another member's, REVOKE_NOT_OWN, signing nothing.
func Fs98TeamSelfAdmitOffBounds(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 team self_admit off: an unconfirmed device and another member's", world,
		fs98TeamMember(world, false),
		fs98Do("laptop", world, func() error {
			net := world.net()
			laptop := world.hosts["laptop"]
			memberId := laptop.Device.MemberId
			watch := net.Device("m watch", memberId)
			net.AdmitDevice(net.Owner(), watch, 0)
			world.world.Settle()
			if net.Consented(watch, memberId) {
				return errors.New("an admin's admission is consented before the member's OwnerConfirm")
			}
			before := net.Tip().GetVersion()
			for name, other := range map[string]*sidecartest.AdmissionDevice{"an admin's device": world.devices["admin b"], "the owner's first device": net.Owner()} {
				if preview := laptop.Preview(other.SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{}); preview.Refusal == nil || preview.Refusal.Code != sidecar.DeviceRevokeCodeNotOwn {
					return fmt.Errorf("%s: %+v", name, preview)
				}
			}
			if net.Tip().GetVersion() != before {
				return fmt.Errorf("a refused preview moved the log from %d to %d", before, net.Tip().GetVersion())
			}
			preview := laptop.Preview(watch.SidecarId, sidecar.DeviceRevokeLost, 0, time.Time{})
			if preview.Refusal != nil || preview.Plan == nil || preview.Plan.Signatures != 1 {
				return fmt.Errorf("the unconfirmed watch's plan: %+v", preview)
			}
			if reply := laptop.Revoke(preview.Plan); reply.Refusal != nil || reply.ProposalId != "" || reply.Position != before+1 {
				return fmt.Errorf("the unconfirmed watch's revocation: %+v", reply)
			}
			if net.Admitted(watch) || !net.Admitted(world.devices["phone"]) {
				return errors.New("the watch stands, or the phone went with it")
			}
			return nil
		}),
	)
}

// FS-98's team with self_admit off, a compromise: an admin admits a watch under the member and the phone alone confirms
// it; the laptop revokes the phone as compromise from that confirmation's entry, which parks the watch, whose consent
// rested on it alone (§7.9's cascade, its consent clause), and leaves the laptop and the first device, confirmed by
// the first device outside P, standing.
func Fs98TeamCompromiseSelfAdmitOff(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 team self_admit off: a compromise parks what the phone confirmed", world,
		fs98TeamMember(world, false),
		fs98Do("laptop", world, func() error {
			net := world.net()
			laptop, phone := world.hosts["laptop"], world.devices["phone"]
			memberId := laptop.Device.MemberId
			watch := net.Device("m watch", memberId)
			net.AdmitDevice(net.Owner(), watch, 0)
			world.world.OwnerConfirm(phone, watch)
			confirmedAt := net.Tip().GetVersion()
			preview := laptop.Preview(phone.SidecarId, sidecar.DeviceRevokeCompromise, confirmedAt, time.Time{})
			if preview.Refusal != nil || preview.Plan == nil {
				return fmt.Errorf("the preview: %+v", preview.Refusal)
			}
			parked := false
			for _, item := range preview.Plan.Items {
				if item.Id == hex.EncodeToString(laptop.Device.SidecarId.Bytes()) && item.Effect == sidecar.DeviceRevokeEffectPark {
					return errors.New("the plan parks the laptop")
				}
				parked = parked || (item.Id == hex.EncodeToString(watch.SidecarId.Bytes()) && item.Effect == sidecar.DeviceRevokeEffectPark)
			}
			if !parked || preview.Plan.SinceN != confirmedAt {
				return fmt.Errorf("the plan: %+v, items %+v", preview.Plan, preview.Plan.Items)
			}
			if reply := laptop.Revoke(preview.Plan); reply.Refusal != nil || reply.Position == 0 {
				return fmt.Errorf("the revocation: %+v", reply)
			}
			if net.Admitted(phone) || net.Admitted(watch) || !net.Admitted(laptop.Device) || !net.Admitted(world.devices["first"]) {
				return errors.New("the cascade: the phone and the watch should be out, the laptop and the first device in")
			}
			if row := net.Row(watch); row.GetParkedAt() == 0 {
				return errors.New("the watch is not parked")
			}
			return nil
		}),
	)
}

// A team at k = 2 as fs98Team's, the owner's phone a host too: before the AdminSet names b and c, while one signer
// still admits, the owner's first device admits the owner's laptop and phone, hosts, and b's first device admits b's
// desk, a host.
func fs98TeamPhoneHost(world *fs98World) *Step {
	return fs98Setup(world, func() error {
		net := world.net()
		owner := net.Owner()
		memberB := net.AdmitMember(owner, "admin b", bridge.MemberRole_MEMBER_ROLE_MEMBER)
		memberC := net.AdmitMember(owner, "admin c", bridge.MemberRole_MEMBER_ROLE_MEMBER)
		adminB, adminC := net.Device("admin b first device", memberB), net.Device("admin c first device", memberC)
		net.AdmitDevice(owner, adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
		net.AdmitDevice(owner, adminC, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
		world.devices["first"], world.devices["admin b"], world.devices["admin c"] = owner, adminB, adminC
		world.hosts["laptop"] = world.world.AddHost("laptop", owner.MemberId, owner, 0)
		world.hosts["desk"] = world.world.AddHost("desk", memberB, adminB, 0)
		phone := world.world.AddHost("phone", owner.MemberId, owner, 0)
		world.hosts["phone"] = phone
		world.devices["phone"] = phone.Device
		net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{memberB, memberC}, 0)))
		if k, n := net.State().Threshold(); k != 2 || n != 3 {
			return fmt.Errorf("k %d of n %d", k, n)
		}
		world.world.Settle()
		return nil
	})
}

// The suspended phone, a host: its revocation of the laptop that proposed its own, lost or compromise, is
// REVOKE_NOT_CAPABLE, and so is its cosign of that proposal, which never counts its target; nothing is signed, and the
// phone stays admitted and suspended.
func fs98SuspendedPhoneRefuses(world *fs98World) *Step {
	return fs98Do("phone", world, func() error {
		net := world.net()
		phone, laptop := world.hosts["phone"], world.hosts["laptop"]
		if !phone.Suspended() {
			return errors.New("the phone is not suspended while its revocation's cosigns are due")
		}
		before := net.Tip().GetVersion()
		for _, reason := range []string{sidecar.DeviceRevokeLost, sidecar.DeviceRevokeCompromise} {
			sinceN := uint64(0)
			if reason == sidecar.DeviceRevokeCompromise {
				sinceN = before
			}
			if preview := phone.Preview(laptop.Device.SidecarId, reason, sinceN, time.Time{}); preview.Refusal == nil || preview.Refusal.Code != sidecar.DeviceRevokeCodeNotCapable {
				return fmt.Errorf("the suspended phone's %s revocation of the laptop: %+v", reason, preview)
			}
		}
		if reply := phone.Cosign(hex.EncodeToString(world.ids["proposal"])); reply.Refusal == nil || reply.Refusal.Code != sidecar.DeviceRevokeCodeNotCapable {
			return fmt.Errorf("the target's cosign of its own revocation: %+v", reply)
		}
		if net.Tip().GetVersion() != before || !net.Admitted(laptop.Device) || !net.Admitted(phone.Device) || !phone.Suspended() {
			return fmt.Errorf("a refused path moved the log from %d to %d, or the phone's standing", before, net.Tip().GetVersion())
		}
		return nil
	})
}

// FS-98's team: an AdminSet member's device at k = 2 answers authority_pending and suspends the target at once, whose
// own revocation of the caller and cosign of its revocation are refused with nothing signed.
func Fs98TeamSuspendedTargetRefused(net *Net) *Schedule {
	world := newFs98World()
	schedule := fs98Schedule("FS-98 team a suspended target's revocation of its proposer", world,
		fs98TeamPhoneHost(world),
		fs98Propose(world),
		fs98SuspendedPhoneRefuses(world),
	)
	schedule.Refuses = "a suspended target's revocation of the admin device that proposed its own, and its cosign of that proposal"
	return schedule
}

// FS-98's team at k = 2, to the end: the suspended phone is refused, then admin b's desk reads the proposal and approves
// it as `ur approve <proposal_id>` does, which revokes the phone.
func Fs98TeamSuspendedTargetRevokedAtCosign(net *Net) *Schedule {
	world := newFs98World()
	return fs98Schedule("FS-98 team a suspended target revoked at another admin's cosign", world,
		fs98TeamPhoneHost(world),
		fs98Propose(world),
		fs98SuspendedPhoneRefuses(world),
		fs98Do("desk", world, func() error {
			net := world.net()
			desk, phone := world.hosts["desk"], world.hosts["phone"]
			proposalId := hex.EncodeToString(world.ids["proposal"])
			shown := desk.Proposal(proposalId)
			if shown.Proposal == nil || shown.Proposal.SidecarId != phone.Device.SidecarId || !shown.Proposal.Suspended {
				return fmt.Errorf("admin b's desk reads the proposal as %+v", shown)
			}
			if reply := desk.Cosign(proposalId); reply.Refusal != nil || reply.Unknown || reply.Position == 0 {
				return fmt.Errorf("the cosign: %+v", reply)
			}
			if net.Admitted(phone.Device) {
				return errors.New("the phone stands after admin b's cosign")
			}
			return nil
		}),
	)
}
