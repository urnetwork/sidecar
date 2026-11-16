// FS-97's and FS-124's Team cases (§22.8; §7.9's presence, several, counted and read_only rows, §7.10's stale and
// cleanup rows; D-TEAM-29, D-TEAM-32; owner decisions 110, 112, 126, 185, 187, 189, 192; TEAM-M6-12), and S3b's and
// S4b's statements (§22.7's S3 and S4 in their member forms), on the admission suite's world with its network a Team
// (sidecartest.NewTeamNet): ACL's compile, the team tier, Team's starting document and the team directory. These are
// the api-side halves of the Team device rows: what api's check and every reader, each new device and gate at a base
// among them, take or refuse of the statements a device signs in each act. The devices' own acts (CORE-M4-02's stale
// act on an Admin's device, CORE-M6-04's cleanup prompt, ur approve) are CORE's rows and are not run here.
//
// Registered, each a refusal beside the twin that must succeed, on T2 and on T3 through server's sequencer
// (server/api/fs_team_m6_db_test.go):
//
//   - FS-124's team: in a Team at k = 2 whose Admin's device D registered a presence key, D's Suspend of a member's
//     device, its RecoveryVeto of another Admin's recovery proposal, its cosign of the Owner's AdminSet change, its own
//     AdminSet change proposal, its MemberRevoke of a member and its parking DelegationRevoke are each refused by api
//     and every reader with no countersignature and with one by a key D never registered, and land with D's own; the
//     twin, each countersigned once, lands.
//   - FS-97's team: with self_admit off, member m's consented device admits no page Worker of m's, though it revokes
//     m's stale one alone; an Admin's device whose presence key is live admits m's next Worker in one act with
//     SidecarRevoke{removed} of m's stale Worker, both under one countersignature, the act refused statement by
//     statement without it; the twin is that act countersigned alone.
//
// Named schedules beside them: FS-97's AdminSet member at k = 2, whose stale Worker goes only by its own proposal
// beside its new Worker's, each completed by the cosigner, a proposal never cosigned expiring at its not_after and the
// next admission proposing it again; FS-97's cleanup at 90% of config_admissions, the list the same at every reader
// and an Admin's revocations freeing it; and TeamMemberAdmitStatements and TeamMemberRevokeStatements, S3b's and S4b's
// statement parts, which sidecartest/scenarios/team.go composes with ACL's and KEYS's parts.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs97Team  = Register("FS-97", "team", []Tier{TierT2, TierT3}, Twin(Fs97TeamUncountersignedAct, Fs97TeamCountersignedAct))
	Fs124Team = Register("FS-124", "team", []Tier{TierT2, TierT3}, Twin(Fs124TeamUncountersigned, Fs124TeamCountersigned))
)

// A Team schedule's world: the admission suite's, its network a Team.
type teamM6World struct {
	*fsTeamWorld
	team *sidecartest.TeamNet
}

func newTeamM6World() *teamM6World {
	return &teamM6World{fsTeamWorld: newFsTeamWorld()}
}

// The first step: a Team network on the Net's tier, then body.
func (self *teamM6World) start(body func(team *sidecartest.TeamNet) error) *Step {
	world := self
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			tier, err := net.AdmissionTier()
			if err != nil {
				return err
			}
			world.team = sidecartest.NewTeamNet(fsTeamFailer{}, tier, nil)
			world.net = world.team.AdmissionNet
			world.devices["owner"] = world.team.Owner()
			if body == nil {
				return nil
			}
			return body(world.team)
		})
	}}
}

// A step by actor on the Team.
func (self *teamM6World) do(actor string, body func(team *sidecartest.TeamNet) error) *Step {
	world := self
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		return fsTeamCatch(func() error {
			return body(world.team)
		})
	}}
}

// A Team schedule: its steps, the world's close, and the readers' agreement after every step.
func (self *teamM6World) schedule(id string, steps ...*Step) *Schedule {
	return fsTeamSchedule(id, self.fsTeamWorld, steps...)
}

// Admins b and c from invites, the Owner granting each alone while k is 1: k = 2 of 3.
func (self *teamM6World) adminSet(team *sidecartest.TeamNet) {
	owner := team.Owner()
	adminB := team.AdminFromInvite(owner, "admin b", []sidecar.Id{owner.MemberId}, nil, 0)
	adminC := team.AdminFromInvite(owner, "admin c", []sidecar.Id{owner.MemberId}, []sidecar.Id{adminB.MemberId}, 0)
	team.RequireThreshold(2, 3)
	self.devices["admin b"], self.devices["admin c"] = adminB, adminC
}

// Three versions of one statement of device's: bare, countersigned by a key no device registered, and countersigned
// by key, each as one act of device's.
func teamM6Versions(team *sidecartest.TeamNet, device *sidecartest.AdmissionDevice, key *sidecartest.FixturePresenceKey, signed *bridge.Signed) (bare []byte, foreign []byte, own []byte) {
	bare = team.Marshal(signed)
	foreignSigned := proto.Clone(signed).(*bridge.Signed)
	team.Countersign(sidecartest.NewFixturePresenceKey("a key no device registered", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256), device, foreignSigned)
	ownSigned := proto.Clone(signed).(*bridge.Signed)
	team.Countersign(key, device, ownSigned)
	return bare, team.Marshal(foreignSigned), team.Marshal(ownSigned)
}

// Lands own after api and every reader refused bare and foreign with ErrConfigPresence, or lands own alone for the
// twin.
func teamM6Covered(team *sidecartest.TeamNet, bare []byte, foreign []byte, own []byte, refuse bool) sidecar.ConfigVerdict {
	if refuse {
		team.MustRefuse(bare, sidecar.ErrConfigPresence)
		team.MustRefuse(foreign, sidecar.ErrConfigPresence)
	}
	return team.MustLand(own)
}

// FS-124's team start: the Team at k = 2; admin b's first device D registers a presence key; members m and n with
// their consented devices; m's laptop; admin c's recovery key; and a Delegation of tag:recurd the Owner declared, with
// one agent admitted before the position noted and one after.
func fs124TeamStart(world *teamM6World) *Step {
	return world.start(func(team *sidecartest.TeamNet) error {
		owner := team.Owner()
		world.adminSet(team)
		key := sidecartest.NewFixturePresenceKey("fs-124 team admin b", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
		team.RegisterPresenceKey(world.devices["admin b"], key, nil)
		world.presenceKeys["admin b"] = key
		memberM, mFirst := team.ConsentedMember("m")
		_, nFirst := team.ConsentedMember("n")
		mLaptop := team.Device("m laptop", memberM)
		team.AdmitDevice(mFirst, mLaptop, 0)
		world.devices["m first"], world.devices["n first"], world.devices["m laptop"] = mFirst, nFirst, mLaptop
		// admin c's recovery key, bound by c's proposal and the Owner's cosign: its admissions wait out Recovery's window
		adminC := world.devices["admin c"]
		keyC := team.RecoveryKey(adminC.MemberId, "admin c")
		team.CosignCompletes(owner, team.ProposeOpen(adminC, bridge.SignedType_SIGNED_RECOVERY_BIND, team.RecoveryBind(keyC)))
		world.recoveryKeys["admin c"] = keyC
		tagId := team.TagAtom("recurd")
		notAfter := team.Clock().Now().Add(30 * 24 * time.Hour).UnixMilli()
		delegation := team.Delegate(owner, "recurd", []sidecar.Id{tagId}, 10, notAfter)
		world.delegations["recurd"] = delegation
		early, late := team.Device("recurd early", sidecar.Id{}), team.Device("recurd late", sidecar.Id{})
		team.MustLand(team.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.Admission(early, []sidecar.Id{tagId}, false, notAfter, 0)))
		world.positions["before late"] = team.Tip().GetVersion() + 1
		team.MustLand(team.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.Admission(late, []sidecar.Id{tagId}, false, notAfter, 0)))
		world.devices["recurd early"], world.devices["recurd late"] = early, late
		team.Fold(true)
		return nil
	})
}

// D's covered statements, each refused without D's countersignature and with a foreign one when refuse is set, then
// landing with D's own, and their effects at every reader.
func fs124TeamStatements(world *teamM6World, refuse bool) *Step {
	return world.do("adminB", func(team *sidecartest.TeamNet) error {
		owner, d, key := team.Owner(), world.devices["admin b"], world.presenceKeys["admin b"]
		covered := func(signedType bridge.SignedType, body proto.Message) sidecar.ConfigVerdict {
			bare, foreign, own := teamM6Versions(team, d, key, team.SignedBy(d, signedType, body))
			return teamM6Covered(team, bare, foreign, own, refuse)
		}

		// a Suspend of m's laptop
		mLaptop := world.devices["m laptop"]
		covered(bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: team.Header(), Subject: mLaptop.SidecarId.Bytes(), SuspendId: team.Id("m laptop's suspend").Bytes()})
		if !team.State().Suspended(mLaptop.SidecarId) {
			return errors.New("m's laptop is not suspended after D's countersigned Suspend")
		}

		// a RecoveryVeto of admin c's recovery proposal
		proposalId := team.ProposeByRecovery(world.recoveryKeys["admin c"], team.Device("admin c by recovery", world.devices["admin c"].MemberId))
		covered(bridge.SignedType_SIGNED_RECOVERY_VETO, team.RecoveryVeto(proposalId))
		if window := team.Window(proposalId); window.Closed != sidecar.ConfigProposalVetoed {
			return fmt.Errorf("the vetoed window: %+v", window)
		}

		// a cosign of the Owner's AdminSet change, which completes it
		memberE := team.AdmitMember(owner, "e", bridge.MemberRole_MEMBER_ROLE_MEMBER)
		admins := []sidecar.Id{d.MemberId, world.devices["admin c"].MemberId}
		grantE := team.ProposeOpen(owner, bridge.SignedType_SIGNED_ADMIN_SET, team.AdminSet([]sidecar.Id{owner.MemberId}, append(slices.Clone(admins), memberE), 0))
		if verdict := covered(bridge.SignedType_SIGNED_AUTHORITY_COSIGN, team.Cosign(grantE)); !verdict.Completed() {
			return errors.New("D's countersigned cosign did not complete the Owner's AdminSet change")
		}
		admins = append(admins, memberE)

		// D's own AdminSet change, a proposal that stays open
		memberF := team.AdmitMember(owner, "f", bridge.MemberRole_MEMBER_ROLE_MEMBER)
		proposal := team.Proposal(bridge.SignedType_SIGNED_ADMIN_SET, team.AdminSet([]sidecar.Id{owner.MemberId}, append(slices.Clone(admins), memberF), 0))
		if verdict := covered(bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, proposal); verdict.Completed() {
			return errors.New("D's AdminSet change completed alone at k = 2")
		}

		// a MemberRevoke of n
		nFirst := world.devices["n first"]
		covered(bridge.SignedType_SIGNED_MEMBER_REVOKE, team.MemberRevoke(nFirst.MemberId))
		if team.State().Member(nFirst.MemberId) != nil || team.Admitted(nFirst) {
			return errors.New("n or its device stands after D's countersigned MemberRevoke")
		}

		// a parking DelegationRevoke, since_n > 0: the agent it admitted from since_n parks, the earlier one reads on
		delegation := world.delegations["recurd"]
		covered(bridge.SignedType_SIGNED_DELEGATION_REVOKE, team.DelegationRevoke(delegation.Id, world.positions["before late"]))
		if state := team.State(); !state.Parked(world.devices["recurd late"].SidecarId) || state.Parked(world.devices["recurd early"].SidecarId) {
			return errors.New("the parking DelegationRevoke parked the wrong agents")
		}
		if _, ended := team.State().DelegationEnded(delegation.Id); !ended {
			return errors.New("the DelegationRevoke left the Delegation admitting")
		}
		team.Fold(true)
		return nil
	})
}

// FS-124's team: see the file header.
func Fs124TeamUncountersigned(net *Net) *Schedule {
	world := newTeamM6World()
	schedule := world.schedule("FS-124 team an Admin's uncountersigned statements", fs124TeamStart(world), fs124TeamStatements(world, true))
	schedule.Refuses = "an Admin's covered Suspend, veto, cosign, AdminSet change, MemberRevoke and parking DelegationRevoke without its presence countersignature"
	return schedule
}

// FS-124's team twin: each countersigned once lands.
func Fs124TeamCountersigned(net *Net) *Schedule {
	world := newTeamM6World()
	return world.schedule("FS-124 team an Admin's countersigned statements", fs124TeamStart(world), fs124TeamStatements(world, false))
}

// A page Worker's capability bits (§18.8).
const teamM6ReadOnly = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)

// FS-97's team start: the Team at k = 2; admin b's first device registers a presence key; member m outside the
// AdminSet with its consented first device, whose page Workers 1 and 2 m's first device admits while self_admit is on;
// then the head turns self_admit off.
func fs97TeamStart(world *teamM6World) *Step {
	return world.start(func(team *sidecartest.TeamNet) error {
		world.adminSet(team)
		key := sidecartest.NewFixturePresenceKey("fs-97 team admin b", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
		team.RegisterPresenceKey(world.devices["admin b"], key, nil)
		world.presenceKeys["admin b"] = key
		memberM, mFirst := team.ConsentedMember("m")
		world.devices["m first"] = mFirst
		for _, label := range []string{"m worker 1", "m worker 2"} {
			worker := team.Device(label, memberM)
			team.AdmitDevice(mFirst, worker, teamM6ReadOnly)
			world.devices[label] = worker
		}
		team.SetServiceSettings(&protocol.ServiceSettings{SelfAdmit: protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF})
		if team.State().SelfAdmit() {
			return errors.New("self_admit is on after the head turned it off")
		}
		return nil
	})
}

// The Admin's act: SidecarRevoke{removed} of m's Worker 1, stale in every group the Admin's device is a leaf of, then
// the admission of m's Worker 3, both under one countersignature of the device's key, so one presence check covers the
// act (owner decision 187). Without the countersignature, and with a foreign key's, api and every reader refuse each
// statement of the act; with it, both land in act order. m's consented device admits no Worker of m's with self_admit
// off, and revokes m's stale Worker 2 alone, as a member's device revokes whatever self_admit says.
func fs97TeamAct(world *teamM6World, refuse bool) *Step {
	return world.do("adminB", func(team *sidecartest.TeamNet) error {
		adminB, key, mFirst := world.devices["admin b"], world.presenceKeys["admin b"], world.devices["m first"]
		worker1, worker2 := world.devices["m worker 1"], world.devices["m worker 2"]
		worker3 := team.Device("m worker 3", mFirst.MemberId)
		if refuse {
			team.MustRefuse(team.Sign(mFirst, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.Admission(worker3, nil, false, 0, teamM6ReadOnly)), sidecar.ErrConfigAuthority)
		}
		act := func() []*bridge.Signed {
			return []*bridge.Signed{
				team.SignedBy(adminB, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.Revocation(worker1, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)),
				team.SignedBy(adminB, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.Admission(worker3, nil, false, 0, teamM6ReadOnly)),
			}
		}
		if refuse {
			for _, signed := range act() {
				team.MustRefuse(team.Marshal(signed), sidecar.ErrConfigPresence)
			}
			foreign := act()
			team.Countersign(sidecartest.NewFixturePresenceKey("fs-97 a key no device registered", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256), adminB, foreign...)
			for _, signed := range foreign {
				team.MustRefuse(team.Marshal(signed), sidecar.ErrConfigPresence)
			}
		}
		own := act()
		team.Countersign(key, adminB, own...)
		for _, signed := range own {
			team.MustLand(team.Marshal(signed))
		}
		if team.Admitted(worker1) || !team.Admitted(worker3) || !team.State().ReadOnly(worker3.SidecarId) {
			return errors.New("the act left m's stale Worker standing or did not admit its new one read_only")
		}
		// the member's own device revokes m's other stale Worker alone, with self_admit off
		team.MustLand(team.Sign(mFirst, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.Revocation(worker2, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
		workers := team.State().PageWorkers(mFirst.MemberId)
		if len(workers) != 1 || workers[0].SidecarId != worker3.SidecarId {
			return fmt.Errorf("m's page Workers after the act: %+v", workers)
		}
		team.Fold(true)
		return nil
	})
}

// FS-97's team: see the file header.
func Fs97TeamUncountersignedAct(net *Net) *Schedule {
	world := newTeamM6World()
	schedule := world.schedule("FS-97 team an Admin's uncountersigned stale act", fs97TeamStart(world), fs97TeamAct(world, true))
	schedule.Refuses = "an Admin's admission of a member's page Worker and its stale revocation without its presence countersignature, and the member's own admission with self_admit off"
	return schedule
}

// FS-97's team twin: the Admin's act countersigned once lands.
func Fs97TeamCountersignedAct(net *Net) *Schedule {
	world := newTeamM6World()
	return world.schedule("FS-97 team an Admin's countersigned stale act", fs97TeamStart(world), fs97TeamAct(world, false))
}

// FS-97's team, an AdminSet member at k = 2 (§7.10's stale row; §7.9's counted row): admin c's laptop admits c's page
// Worker 1; later c's Worker 2's admission goes as c's proposal, c counting as one, beside c's proposal revoking Worker
// 1 as removed, and b's cosign of each completes it; a plain revocation of c's stale Worker by c alone is refused.
// c's next stale revocation, never cosigned, expires at its not_after, its Worker standing and a cosign after that
// refused; the next admission proposes it again, and b's cosign completes it.
func Fs97TeamAdminSetMember(net *Net) *Schedule {
	world := newTeamM6World()
	return world.schedule("FS-97 team an AdminSet member's stale Workers at k = 2",
		world.start(func(team *sidecartest.TeamNet) error {
			world.adminSet(team)
			adminC := world.devices["admin c"]
			worker1 := team.Device("c worker 1", adminC.MemberId)
			team.CosignCompletes(world.devices["admin b"], team.ProposeOpen(adminC, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.Admission(worker1, nil, false, 0, teamM6ReadOnly)))
			world.devices["c worker 1"] = worker1
			return nil
		}),
		world.do("adminC", func(team *sidecartest.TeamNet) error {
			adminB, adminC, worker1 := world.devices["admin b"], world.devices["admin c"], world.devices["c worker 1"]
			team.MustRefuse(team.Sign(adminC, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.Revocation(worker1, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)), sidecar.ErrConfigAuthority)
			worker2 := team.Device("c worker 2", adminC.MemberId)
			revokeId := team.ProposeOpen(adminC, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.Revocation(worker1, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0))
			admitId := team.ProposeOpen(adminC, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.Admission(worker2, nil, false, 0, teamM6ReadOnly))
			team.CosignCompletes(adminB, revokeId)
			team.CosignCompletes(adminB, admitId)
			if team.Admitted(worker1) || !team.Admitted(worker2) {
				return errors.New("c's stale Worker stands, or its new one is not admitted")
			}
			world.devices["c worker 2"] = worker2
			// the next stale revocation, never cosigned
			world.ids["expiring"] = team.ProposeOpen(adminC, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.Revocation(worker2, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0))
			return nil
		}),
		&Step{Actor: "clock", Advance: 7*24*time.Hour + time.Hour},
		world.do("adminC", func(team *sidecartest.TeamNet) error {
			adminB, adminC, worker2 := world.devices["admin b"], world.devices["admin c"], world.devices["c worker 2"]
			// an entry past the proposal's not_after: it is no longer open, its Worker stands, and a cosign is refused
			team.AdmitMember(team.Owner(), "after the expiry", bridge.MemberRole_MEMBER_ROLE_MEMBER)
			if slices.ContainsFunc(team.State().OpenProposalIds(), func(id []byte) bool { return bytes.Equal(id, world.ids["expiring"]) }) {
				return errors.New("the stale revocation's proposal is open past its not_after")
			}
			team.MustRefuse(team.Sign(adminB, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, team.Cosign(world.ids["expiring"])), sidecar.ErrConfigRule)
			if !team.Admitted(worker2) {
				return errors.New("an expired proposal revoked c's Worker")
			}
			// the next admission proposes it again, and the cosigner completes both
			worker3 := team.Device("c worker 3", adminC.MemberId)
			revokeId := team.ProposeOpen(adminC, bridge.SignedType_SIGNED_SIDECAR_REVOKE, team.Revocation(worker2, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0))
			admitId := team.ProposeOpen(adminC, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.Admission(worker3, nil, false, 0, teamM6ReadOnly))
			team.CosignCompletes(adminB, revokeId)
			team.CosignCompletes(adminB, admitId)
			if team.Admitted(worker2) || !team.Admitted(worker3) {
				return errors.New("the proposal again did not revoke c's stale Worker, or the new one is not admitted")
			}
			team.Fold(true)
			return nil
		}),
	)
}

// FS-97's team cleanup (§7.10's cleanup row; CORE-M6-04's prompt reads this list): member m holds only page Workers,
// which an Admin's device admits one each eviction with self_admit off, no group of the Admin's seating them; at 90%
// of the network's config_admissions, every reader's cleanup list names m's Workers but its newest, oldest first, with
// each admission's time from the rows; an Admin's revocations of them, each as removed and countersigned where its key
// is live, land, and the list empties once the count falls below 90%, before any admission meets the cap.
func Fs97TeamCleanup(net *Net) *Schedule {
	world := newTeamM6World()
	return world.schedule("FS-97 team cleanup at 90% of config_admissions",
		fs97TeamStart(world),
		world.do("adminB", func(team *sidecartest.TeamNet) error {
			adminB, key, memberM := world.devices["admin b"], world.presenceKeys["admin b"], world.devices["m first"].MemberId
			// the two Workers m's own device admitted go first, as the member's device would
			for _, label := range []string{"m worker 1", "m worker 2"} {
				team.MustLand(team.Sign(world.devices["m first"], bridge.SignedType_SIGNED_SIDECAR_REVOKE,
					team.Revocation(world.devices[label], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
			}
			// the page Workers m holds, its admissions then near the cap
			workerCount := 6
			admitted := []sidecar.Id{}
			for i := range workerCount {
				worker := team.Device(fmt.Sprintf("m evicted worker %d", i), memberM)
				signed := team.SignedBy(adminB, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.Admission(worker, nil, false, 0, teamM6ReadOnly))
				team.Countersign(key, adminB, signed)
				team.MustLand(team.Marshal(signed))
				admitted = append(admitted, worker.SidecarId)
				team.Wait(7 * 24 * time.Hour)
			}
			team.Fold(true)
			count := team.State().AdmissionCount()
			// the cap the count stands at 90% of
			admissionCap := count * 10 / 9
			var list []sidecar.ConfigCleanupMember
			team.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
				got := sidecar.CleanupList(state, admissionCap)
				if len(got) != 1 || got[0].MemberId != memberM || len(got[0].Workers) != workerCount-1 {
					return fmt.Errorf("the cleanup list at %d of a cap of %d: %+v", count, admissionCap, got)
				}
				for i, worker := range got[0].Workers {
					if worker.SidecarId != admitted[i] || worker.AdmittedTime.IsZero() || (0 < i && !got[0].Workers[i-1].AdmittedTime.Before(worker.AdmittedTime)) {
						return fmt.Errorf("listed %d: %+v", i, worker)
					}
				}
				if list == nil {
					list = got
				} else if !slices.EqualFunc(list[0].Workers, got[0].Workers, func(a sidecar.ConfigPageWorker, b sidecar.ConfigPageWorker) bool { return a == b }) {
					return errors.New("two readers list differently at one pin")
				}
				return nil
			})
			// the Admin revokes what the list names, each countersigned
			for _, worker := range list[0].Workers {
				signed := team.SignedBy(adminB, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
					Header: team.Header(), SidecarId: worker.SidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED,
				})
				team.Countersign(key, adminB, signed)
				team.MustLand(team.Marshal(signed))
			}
			team.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
				if got := sidecar.CleanupList(state, admissionCap); len(got) != 0 {
					return fmt.Errorf("the cleanup list below 90%%: %+v", got)
				}
				if workers := state.PageWorkers(memberM); len(workers) != 1 || workers[0].SidecarId != admitted[len(admitted)-1] {
					return fmt.Errorf("m's Workers after the cleanup: %+v", workers)
				}
				return nil
			})
			team.Fold(true)
			return nil
		}),
	)
}

// S3b's statements (§22.7's S3, F3 in its member form; §7.9's several and commit rows; owner decisions 110, 113, 128):
// in a Team at k = 2, an Admin's device admits member p, one signature for a member outside the AdminSet, and p's
// first device from an invite, which every reader then holds consented, ranked among the leaves and reading the
// directory; the admission's signer is the granting device that commits p's Add, a leaf that signed nothing commits
// none, and a device of a member the log never admitted is nobody's to add; a MemberAdmit signed by a stranger, or by
// a member's device that is no admin, is refused by api and every reader, and on a tier whose api appends what it
// refuses, every reader refuses each at its position, so the log adds no member a server forged.
func TeamMemberAdmitStatements(net *Net) *Schedule {
	world := newTeamM6World()
	return world.schedule("S3b's member admission statements",
		world.start(func(team *sidecartest.TeamNet) error {
			world.adminSet(team)
			_, world.devices["m first"] = team.ConsentedMember("m")
			return nil
		}),
		world.do("adminB", func(team *sidecartest.TeamNet) error {
			adminB, adminC, mFirst := world.devices["admin b"], world.devices["admin c"], world.devices["m first"]
			// forged: a stranger's MemberAdmit, and one by m's device, which is no admin
			stranger := team.Device("a stranger", team.Id("a stranger's member"))
			forged := [][]byte{
				team.Sign(stranger, bridge.SignedType_SIGNED_MEMBER_ADMIT, team.MemberAdmit(team.Id("member by a stranger"), bridge.MemberRole_MEMBER_ROLE_MEMBER)),
				team.Sign(mFirst, bridge.SignedType_SIGNED_MEMBER_ADMIT, team.MemberAdmit(team.Id("member by m"), bridge.MemberRole_MEMBER_ROLE_MEMBER)),
			}
			team.MustRefuse(forged[0], sidecar.ErrConfigRefused)
			team.MustRefuse(forged[1], sidecar.ErrConfigAuthority)
			if team.ForgedAppends() {
				for i, statement := range forged {
					pin := team.SequenceAnyway(bridge.AuthEntryKindStatement, statement)
					if team.VerdictAt(pin.GetVersion()).Accepted() {
						return fmt.Errorf("the forged MemberAdmit %d took effect at %d", i, pin.GetVersion())
					}
				}
				for _, label := range []string{"member by a stranger", "member by m"} {
					if team.State().Member(team.Id(label)) != nil {
						return fmt.Errorf("a forged MemberAdmit added %s", label)
					}
				}
			}
			// the Admin admits p alone, and p's first device from an invite
			memberP := team.AdmitMember(adminB, "p", bridge.MemberRole_MEMBER_ROLE_MEMBER)
			pFirst := team.Device("p first device", memberP)
			team.AdmitDevice(adminB, pFirst, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
			outsider := team.Device("a device of no member", team.Id("member never admitted"))
			directoryId, now := team.DirectoryId(), team.Clock().Now()
			team.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
				if !acl.ConsentedFor(pFirst.SidecarId, memberP) || !state.LeafEntitled(pFirst.SidecarId) {
					return errors.New("p's first device is not consented or not leaf-entitled")
				}
				if !slices.Contains(acl.RepoReaders(directoryId, now), pFirst.SidecarId) || slices.Contains(acl.RepoReaders(directoryId, now), outsider.SidecarId) {
					return errors.New("the directory's readers do not hold p's device, or hold a device of no member")
				}
				if commits := state.MayCommit(adminB.SidecarId, pFirst.SidecarId); !commits.Add {
					return fmt.Errorf("the admission's signer may commit %+v", commits)
				}
				if commits := state.MayCommit(adminC.SidecarId, pFirst.SidecarId); commits.Add || commits.FirstWrap {
					return fmt.Errorf("a leaf that signed nothing may commit %+v", commits)
				}
				if commits := state.MayCommit(adminB.SidecarId, outsider.SidecarId); commits != (sidecar.ConfigCommits{}) {
					return fmt.Errorf("a device of no member may be committed: %+v", commits)
				}
				return nil
			})
			team.Fold(true)
			return nil
		}),
	)
}

// S4b's statements (§22.7's S4, F9 in its member form; TEAM-M6-11's MemberRevoke; §7.10's cards row; I-15): in a Team
// at k = 2, the plan of x's removal at the tip names x's untagged devices and the agent x sponsors; an Admin's device
// signs the MemberRevoke alone, x being outside the AdminSet, and at its position every reader revokes every device of
// x's, masks each in the directory, drops each from the directory's readers and lets each leaf's revoker commit its
// Remove, while x's tagged agent keeps its admission and its sponsor gone, unmasked; a MemberRevoke by a member's
// device that is no admin is refused by api and every reader, and on a tier whose api appends what it refuses, every
// reader refuses it at its position; an AdminSet member's removal takes k signatures, which the plan says.
func TeamMemberRevokeStatements(net *Net) *Schedule {
	world := newTeamM6World()
	return world.schedule("S4b's member removal statements",
		world.start(func(team *sidecartest.TeamNet) error {
			world.adminSet(team)
			memberX, xFirst := team.ConsentedMember("x")
			xLaptop := team.Device("x laptop", memberX)
			team.AdmitDevice(xFirst, xLaptop, 0)
			// the document's autogroup:member owns tag:recurd over the folded members, x among them from this base
			team.Fold(true)
			agent := team.Device("x's agent", sidecar.Id{})
			team.MustLand(team.Sign(xFirst, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
				team.Admission(agent, []sidecar.Id{team.TagAtom("recurd")}, false, team.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
			_, world.devices["m first"] = team.ConsentedMember("m")
			world.devices["x first"], world.devices["x laptop"], world.devices["x's agent"] = xFirst, xLaptop, agent
			team.Fold(true)
			return nil
		}),
		world.do("adminB", func(team *sidecartest.TeamNet) error {
			adminB, adminC, mFirst := world.devices["admin b"], world.devices["admin c"], world.devices["m first"]
			xFirst, xLaptop, agent := world.devices["x first"], world.devices["x laptop"], world.devices["x's agent"]
			memberX := xFirst.MemberId
			plan, err := team.State().MemberRevokePlan(memberX)
			if err != nil {
				return err
			}
			wantDevices := []sidecar.Id{xFirst.SidecarId, xLaptop.SidecarId}
			slices.SortFunc(wantDevices, sidecar.Id.Cmp)
			if plan.AdminSet || plan.Signatures != 1 || !slices.Equal(plan.DeviceIds, wantDevices) || !slices.Equal(plan.AgentIds, []sidecar.Id{agent.SidecarId}) {
				return fmt.Errorf("x's removal plan: %+v", plan)
			}
			if adminPlan, err := team.State().MemberRevokePlan(adminC.MemberId); err != nil || !adminPlan.AdminSet || adminPlan.Signatures != 2 {
				return fmt.Errorf("an AdminSet member's removal plan: %+v, %v", adminPlan, err)
			}
			// a member's device that is no admin removes no one
			byM := team.Sign(mFirst, bridge.SignedType_SIGNED_MEMBER_REVOKE, team.MemberRevoke(memberX))
			team.MustRefuse(byM, sidecar.ErrConfigAuthority)
			if team.ForgedAppends() {
				pin := team.SequenceAnyway(bridge.AuthEntryKindStatement, byM)
				if team.VerdictAt(pin.GetVersion()).Accepted() || team.State().Member(memberX) == nil {
					return fmt.Errorf("the forged MemberRevoke took effect at %d", pin.GetVersion())
				}
			}
			removal := team.MustLand(team.Sign(adminB, bridge.SignedType_SIGNED_MEMBER_REVOKE, team.MemberRevoke(memberX)))
			nPrime := removal.Pin.GetVersion()
			directoryId, now := team.DirectoryId(), team.Clock().Now()
			team.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
				if state.Member(memberX) != nil {
					return errors.New("x is a member after the MemberRevoke")
				}
				readers := acl.RepoReaders(directoryId, now)
				for _, device := range []*sidecartest.AdmissionDevice{xFirst, xLaptop} {
					row := state.SidecarRow(device.SidecarId)
					if row.GetRevokedAt() != nPrime || !state.MaskedInDirectory(device.SidecarId) || slices.Contains(readers, device.SidecarId) {
						return fmt.Errorf("%s: revoked at %d, masked %t, reading %t", device.Name, row.GetRevokedAt(), state.MaskedInDirectory(device.SidecarId), slices.Contains(readers, device.SidecarId))
					}
					if commits := state.MayCommit(adminB.SidecarId, device.SidecarId); !commits.Remove {
						return fmt.Errorf("the revoker may not Remove %s: %+v", device.Name, commits)
					}
				}
				if state.MaskedInDirectory(agent.SidecarId) || state.SidecarRow(agent.SidecarId).GetRevokedAt() != 0 {
					return errors.New("x's tagged agent is revoked or masked")
				}
				if sponsor, ok := state.Sponsor(agent.SidecarId); ok {
					return fmt.Errorf("x's agent still has the sponsor %s", sponsor)
				}
				return nil
			})
			team.Fold(true)
			return nil
		}),
	)
}
