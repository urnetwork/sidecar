// §22.7's suites in their Team forms (TEAM-M6-12; R-TEAM-2, R-TEAM-3; owner decisions 110, 112, 144, 182; FS-19,
// FS-101), on the admission suite's world (suite_admission.go) with its network on the team tier: ACL's own compile,
// Team's starting document and the team directory the Owner's first device files as team-create does (TEAM-M6-10), so
// every reader standing, each new device and gate at a base and the writer's follower answers each row alike, and the
// world fails a row the moment one stands elsewhere than the reference. T2 runs the rows on FakeApi here, T3 on
// server's sequencer (server/api/sidecar_team_db_test.go, and over the local stack's MinIO sidecar_team_t3_test.go).
//
//	k of n       an Owner alone, an Admin from an invite (n = 2, k still 1), then a third AdminSet member: k = 2,
//	             every authority statement a proposal its cosign completes and one signature refused, across bases,
//	             a proposal never cosigned expiring at its not_after, the threshold field raising k and lowering it
//	n <= 2       an AdminSet of two that asks a threshold above 1 is refused, since n <= 2 forces k = 1, so either
//	             admin alone changes the AdminSet or removes the other, and a third AdminSet member makes it 2
//	seats        the 1,001st live member device, most of the first 1,000 one member's (no member-device cap), is
//	             wrapped in the config group and the team directory's alike: it reads both, commits nothing, and
//	             moves into the first 1,000 when a leaf-entitled device is revoked, nothing shrinking
//	admissions   §20.4's Team config_admissions, 5,000 at full scale, member devices and agents, every one landing at
//	             api and every reader with no member-device cap, the count every reader takes the same
//	ephemeral    FS-19's log part under a Team's Admin: an ephemeral the Admin's device admitted writes no config head,
//	             and api and every reader refuse its base though its member is in the AdminSet
//
// TeamLogRetention is FS-101's log-retention fixture (§7.9's fold, retain and retention rows): the same network with
// the production fold and retention values on the fake clock, so §16.11's schedules (RECORD-M6-25) run the log 30
// days and 10 folds past a pin, api deleting what its retention pass deletes, and then start a fresh member device
// from what api still holds.
//
// FS-97's and FS-124's Team cases, and S3b's and S4b's statements, are fault's (sidecartest/fault/fs_team_m6.go),
// on this world. A row is a top-level test on each tier (TeamRows, RunTeamRow); nothing here sleeps.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Tunables of the Team suite.
type TeamSuiteSettings struct {
	// The admissions the admissions row holds: §20.4's Team config_admissions, 5,000 (pro.yml's team block).
	AdmissionCount int
	// How many of them are tagged agents; the rest are member devices.
	AgentCount int
	// How many members hold the member devices: the first holds every device past an even share of the others',
	// so one member's count meets no cap.
	MemberCount int
	// The member devices the seats row admits before its 1,001st: §7.9's leaves rule's 1,000 (D-KEYS-2).
	LeafEntitledCount int
	// How long a proposal lives: a StatementHeader's longest not_after, 7 days (§7.9's statement header).
	ProposalLife time.Duration
}

// Full scale: 5,000 admissions.
func DefaultTeamSuiteSettings() *TeamSuiteSettings {
	return &TeamSuiteSettings{
		AdmissionCount:    5000,
		AgentCount:        100,
		MemberCount:       4,
		LeafEntitledCount: 1000,
		ProposalLife:      7 * 24 * time.Hour,
	}
}

// What a T2 or T3 run takes when it is not the full-scale run: just past the leaves' first 1,000, so the count still
// passes the rank's edge.
func ReducedTeamSuiteSettings() *TeamSuiteSettings {
	settings := DefaultTeamSuiteSettings()
	settings.AdmissionCount = settings.LeafEntitledCount + 24
	settings.AgentCount = 8
	return settings
}

// A Team network on the admission suite's world: the team tier its api says, ACL's compile, Team's starting document
// saved by the Owner's first device, and the team directory, which that device files.
type TeamNet struct {
	*AdmissionNet
	settings    *TeamSuiteSettings
	directoryId sidecar.Id
	// the starting document's save, whose atoms name its tags
	startPlan *sidecar.AclSavePlan
}

// A fresh Team network on tier, the Owner's first device its writer. settings nil takes the reduced ones. The caller
// closes it.
func NewTeamNet(t AdmissionT, tier *AdmissionTier, settings *TeamSuiteSettings) *TeamNet {
	t.Helper()
	if settings == nil {
		settings = ReducedTeamSuiteSettings()
	}
	teamTier := *tier
	teamTier.Team = true
	if teamTier.AclCompile == nil {
		teamTier.AclCompile = AclAdmissionCompile
	}
	net := NewAdmissionNet(t, &teamTier)
	self := &TeamNet{AdmissionNet: net, settings: settings}
	self.startPlan, _ = net.SaveAclPolicy(sidecar.AclTeamStartDocument(), nil)
	if !self.startPlan.Rows.GetHasDocument() {
		t.Fatalf("Team's starting document saved no document")
	}
	self.directoryId = net.Id("repo team directory")
	net.MustLand(net.Sign(net.Owner(), bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: net.Header(), RepoId: self.directoryId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY,
	}))
	if directoryId, ok := sidecar.NewDirectoryAuthView(net.State()).Directory(); !ok || directoryId != self.directoryId {
		t.Fatalf("the team's directory: %s, %t", directoryId, ok)
	}
	return self
}

// The team directory's repo id.
func (self *TeamNet) DirectoryId() sidecar.Id {
	return self.directoryId
}

// The atom of a tag Team's starting document declares: "recurd", which every member owns (§8.4's tagOwners).
func (self *TeamNet) TagAtom(name string) sidecar.Id {
	self.t.Helper()
	tagId, found := AclTagAtom(self.startPlan, name)
	if !found {
		self.t.Fatalf("Team's starting document declares no tag:%s", name)
	}
	return tagId
}

// The suite's tunables.
func (self *TeamNet) Settings() *TeamSuiteSettings {
	return self.settings
}

// An AdminSet member and its first device from an invite: admitted as a member by signer and named in the AdminSet
// by one AdminSet change signed by signer alone, which only lands while k is 1. Answers the device.
func (self *TeamNet) AdminFromInvite(signer *AdmissionDevice, label string, owners []sidecar.Id, admins []sidecar.Id, threshold uint32) *AdmissionDevice {
	self.t.Helper()
	memberId := self.AdmitMember(signer, label, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	first := self.Device(label+" first device", memberId)
	self.AdmitDevice(signer, first, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	self.MustLand(self.Sign(signer, bridge.SignedType_SIGNED_ADMIN_SET, self.AdminSet(owners, append(slices.Clone(admins), memberId), threshold)))
	if role := self.State().Member(memberId).GetRole(); role != bridge.MemberRole_MEMBER_ROLE_ADMIN {
		self.t.Fatalf("%s's role after the AdminSet change: %s", label, role)
	}
	return first
}

// Fails the row unless every reader standing holds k of n.
func (self *TeamNet) RequireThreshold(k int, n int) {
	self.t.Helper()
	self.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if gotK, gotN := state.Threshold(); gotK != k || gotN != n {
			return fmt.Errorf("k %d of n %d, want %d of %d", gotK, gotN, k, n)
		}
		return nil
	})
}

// Posts a proposal of body by proposer, which must land open; its proposal_id.
func (self *TeamNet) ProposeOpen(proposer *AdmissionDevice, signedType bridge.SignedType, body proto.Message) []byte {
	self.t.Helper()
	proposalId, verdict := self.Propose(proposer, signedType, body)
	if verdict.Completed() {
		self.t.Fatalf("a proposal of %s by %s completed alone", signedType, proposer.Name)
	}
	if !slices.ContainsFunc(self.State().OpenProposalIds(), func(id []byte) bool { return bytes.Equal(id, proposalId) }) {
		self.t.Fatalf("the proposal of %s by %s is not open", signedType, proposer.Name)
	}
	return proposalId
}

// Cosigner's cosign of proposalId, which must land and complete it.
func (self *TeamNet) CosignCompletes(cosigner *AdmissionDevice, proposalId []byte) sidecar.ConfigVerdict {
	self.t.Helper()
	verdict := self.MustLand(self.Sign(cosigner, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, self.Cosign(proposalId)))
	if !verdict.Completed() {
		self.t.Fatalf("%s's cosign did not complete the proposal", cosigner.Name)
	}
	return verdict
}

// One row of the Team suite.
type TeamRow struct {
	// The row's name, as the T2 and T3 tests run it.
	Name string
	Run  func(t testing.TB, net *TeamNet)
}

// The suite's rows.
func TeamRows() []*TeamRow {
	return []*TeamRow{
		{Name: "k of n end to end", Run: teamRowKOfN},
		{Name: "n at most 2 forces k = 1", Run: teamRowTwoForceOne},
		{Name: "seats in the directory group", Run: teamRowSeats},
		{Name: "admissions meet no member-device cap", Run: teamRowAdmissions},
		{Name: "an ephemeral writes no config", Run: teamRowEphemeralConfig},
	}
}

// Runs the row named on tier, on a Team network of its own, failing t with the row's first failure. settings nil
// takes the reduced ones.
func RunTeamRow(t testing.TB, name string, tier *AdmissionTier, settings *TeamSuiteSettings) {
	t.Helper()
	index := slices.IndexFunc(TeamRows(), func(row *TeamRow) bool { return row.Name == name })
	if index < 0 {
		t.Fatalf("no Team row %q", name)
	}
	net := NewTeamNet(t, tier, settings)
	defer net.Close()
	TeamRows()[index].Run(t, net)
}

// §7.9's authority at k of n, end to end in a Team (owner decisions 110, 112; §22.7's signers). The Owner admits an
// Admin from an invite and names it in the AdminSet alone at n = 2, where k stays 1; a third AdminSet member makes it
// k = 2 of 3, which every reader holds across a base. Then each authority statement one signer posts is refused by
// api and every reader and lands as a proposal another AdminSet member's cosign completes: an AdminSet change, an
// Admin's new device (its own laptop counting as one), an Admin's revocation of its own lost laptop by its phone, a
// RecoveryBind of an Admin's key and a MemberRevoke of an Admin; a proposal open across a base completes after it; one
// never cosigned expires at its not_after, a cosign after that refused and its target unchanged; a member outside the
// AdminSet admits and revokes its own device alone, an Admin alone removes such a member, and that member's cosign of
// a proposal is refused; the threshold field raises k to 3 of 3, and an AdminSet change at k = 3 back to 0
// lowers it to 2.
func teamRowKOfN(t testing.TB, net *TeamNet) {
	owner := net.Owner()
	net.RequireThreshold(1, 1)
	adminB := net.AdminFromInvite(owner, "admin b", []sidecar.Id{owner.MemberId}, nil, 0)
	net.RequireThreshold(1, 2)
	// at n = 2 the Owner alone grants a third
	adminC := net.AdminFromInvite(owner, "admin c", []sidecar.Id{owner.MemberId}, []sidecar.Id{adminB.MemberId}, 0)
	net.RequireThreshold(2, 3)
	net.Fold(true)
	net.RequireThreshold(2, 3)
	admins := []sidecar.Id{adminB.MemberId, adminC.MemberId}

	// an AdminSet change: one signer refused, its proposal completed by another's cosign, the target's never counting
	memberD := net.AdmitMember(owner, "d", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	dLaptop := net.Device("d laptop", memberD)
	net.AdmitDevice(owner, dLaptop, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	grantD := func() *protocol.AdminSet {
		return net.AdminSet([]sidecar.Id{owner.MemberId}, append(slices.Clone(admins), memberD), 0)
	}
	net.MustRefuse(net.Sign(adminB, bridge.SignedType_SIGNED_ADMIN_SET, grantD()), sidecar.ErrConfigAuthority)
	grantId := net.ProposeOpen(adminB, bridge.SignedType_SIGNED_ADMIN_SET, grantD())
	net.MustRefuse(net.Sign(dLaptop, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(grantId)), sidecar.ErrConfigAuthority)
	// open across a base, completed after it
	net.Fold(true)
	net.CosignCompletes(adminC, grantId)
	net.RequireThreshold(2, 4)
	admins = append(admins, memberD)

	// an Admin's new device: b's laptop counts as one for b's own phone, and c's cosign completes it
	bPhone := net.Device("admin b phone", adminB.MemberId)
	net.MustRefuse(net.Sign(adminB, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(bPhone, nil, false, 0, 0)), sidecar.ErrConfigAuthority)
	phoneId := net.ProposeOpen(adminB, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(bPhone, nil, false, 0, 0))
	net.CosignCompletes(adminC, phoneId)
	if !net.Admitted(bPhone) {
		t.Fatal("b's phone is not admitted after c's cosign")
	}
	// b's phone revokes b's lost laptop: alone refused, by its proposal and d's cosign completed
	net.MustRefuse(net.Sign(bPhone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(adminB, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)), sidecar.ErrConfigAuthority)
	lostId := net.ProposeOpen(bPhone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(adminB, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0))
	net.MustRefuse(net.Sign(adminB, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(lostId)), sidecar.ErrConfigAuthority)
	net.CosignCompletes(dLaptop, lostId)
	if net.Admitted(adminB) || !net.Admitted(bPhone) {
		t.Fatal("b's laptop stands, or b's phone went with it")
	}

	// a RecoveryBind of c's key: c alone refused, c's proposal and the Owner's cosign
	keyC := net.RecoveryKey(adminC.MemberId, "admin c")
	net.MustRefuse(net.Sign(adminC, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(keyC)), sidecar.ErrConfigAuthority)
	bindId := net.ProposeOpen(adminC, bridge.SignedType_SIGNED_RECOVERY_BIND, net.RecoveryBind(keyC))
	net.CosignCompletes(owner, bindId)
	if net.State().CurrentBinding(adminC.MemberId) == nil {
		t.Fatal("c holds no binding after the Owner's cosign")
	}

	// a member outside the AdminSet admits and revokes its own devices alone; an Admin alone removes such a member;
	// its cosign of an authority proposal is refused
	memberM, mFirst := net.ConsentedMember("m")
	mTablet := net.Device("m tablet", memberM)
	net.AdmitDevice(mFirst, mTablet, 0)
	net.MustLand(net.Sign(mFirst, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(mTablet, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	dropC := func() *protocol.AdminSet {
		return net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{adminB.MemberId, memberD}, 0)
	}
	dropId := net.ProposeOpen(owner, bridge.SignedType_SIGNED_ADMIN_SET, dropC())
	net.MustRefuse(net.Sign(mFirst, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(dropId)), sidecar.ErrConfigAuthority)
	memberN, _ := net.ConsentedMember("n")
	net.MustLand(net.Sign(dLaptop, bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(memberN)))
	if net.State().Member(memberN) != nil {
		t.Fatal("n is a member after an Admin's lone MemberRevoke")
	}

	// a proposal never cosigned expires at its not_after; a cosign after that is refused, and c stays an Admin
	net.Wait(net.settings.ProposalLife + time.Hour)
	net.AdmitMember(owner, "after the expiry", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	if slices.ContainsFunc(net.State().OpenProposalIds(), func(id []byte) bool { return bytes.Equal(id, dropId) }) {
		t.Fatal("a proposal past its not_after is still open")
	}
	net.MustRefuse(net.Sign(adminB, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(dropId)), sidecar.ErrConfigRule)
	if net.State().Member(adminC.MemberId).GetRole() != bridge.MemberRole_MEMBER_ROLE_ADMIN {
		t.Fatal("an expired proposal removed c from the AdminSet")
	}

	// a MemberRevoke of an Admin: alone refused, by proposal and cosign; c's own cosign never counts
	net.MustRefuse(net.Sign(owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(adminC.MemberId)), sidecar.ErrConfigAuthority)
	removeId := net.ProposeOpen(owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(adminC.MemberId))
	net.MustRefuse(net.Sign(adminC, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(removeId)), sidecar.ErrConfigAuthority)
	net.CosignCompletes(bPhone, removeId)
	if net.State().Member(adminC.MemberId) != nil || net.Admitted(adminC) {
		t.Fatal("c or its device stands after the completed MemberRevoke")
	}
	net.RequireThreshold(2, 3)
	admins = []sidecar.Id{adminB.MemberId, memberD}

	// the threshold field: 3 of 3 by proposal and cosign, then a change at k = 3 back to 0, which takes all three
	raiseId := net.ProposeOpen(owner, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, admins, 3))
	net.CosignCompletes(dLaptop, raiseId)
	net.RequireThreshold(3, 3)
	lowerId := net.ProposeOpen(owner, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, admins, 0))
	if verdict := net.MustLand(net.Sign(dLaptop, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, net.Cosign(lowerId))); verdict.Completed() {
		t.Fatal("two of three completed an AdminSet change at k = 3")
	}
	net.CosignCompletes(bPhone, lowerId)
	net.RequireThreshold(2, 3)
	net.Fold(true)
	net.RequireThreshold(2, 3)
}

// §7.9's several row with n <= 2 forcing k = 1 (7.18's accepted risk): an AdminSet of two that asks a threshold of 2
// is refused by api and every reader, since n <= 2 forces k = 1, and one asking none holds k = 1, so the Admin alone
// grants a third AdminSet member, with a threshold of 2 now taken, after which k = 2; a completed MemberRevoke of that
// member returns n to 2 and k to 1 at that position, and from there either admin alone admits its own new device,
// changes the AdminSet and removes the other.
func teamRowTwoForceOne(t testing.TB, net *TeamNet) {
	owner := net.Owner()
	memberB := net.AdmitMember(owner, "admin b", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	adminB := net.Device("admin b first device", memberB)
	net.AdmitDevice(owner, adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	net.MustRefuse(net.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{memberB}, 2)), sidecar.ErrConfigRule)
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{memberB}, 0)))
	net.RequireThreshold(1, 2)
	adminC := net.AdminFromInvite(adminB, "admin c", []sidecar.Id{owner.MemberId}, []sidecar.Id{memberB}, 2)
	net.RequireThreshold(2, 3)
	net.MustRefuse(net.Sign(owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(adminC.MemberId)), sidecar.ErrConfigAuthority)
	removeId := net.ProposeOpen(owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(adminC.MemberId))
	completed := net.CosignCompletes(adminB, removeId)
	net.RequireThreshold(1, 2)
	if completed.Pin.GetVersion() != net.Tip().GetVersion() {
		t.Fatalf("the removal completed at %d, the tip is %d", completed.Pin.GetVersion(), net.Tip().GetVersion())
	}
	net.Fold(true)
	net.RequireThreshold(1, 2)

	// either admin alone: b's own new device, an AdminSet change, the other's removal
	bPhone := net.Device("admin b phone", memberB)
	net.AdmitDevice(adminB, bPhone, 0)
	net.MustRefuse(net.Sign(adminB, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{memberB}, 2)), sidecar.ErrConfigRule)
	net.MustLand(net.Sign(adminB, bridge.SignedType_SIGNED_ADMIN_SET, net.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{memberB}, 1)))
	net.RequireThreshold(1, 2)
	net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, net.MemberRevoke(memberB)))
	if net.State().Member(memberB) != nil || net.Admitted(bPhone) {
		t.Fatal("b or its phone stands after the Owner's lone MemberRevoke at n = 2")
	}
	net.RequireThreshold(1, 1)
	net.Fold(true)
}

// §22.7's seats in a Team (owner decisions 144, 182; D-KEYS-23): LeafEntitledCount member devices, nine in ten one
// member's, then the 1,001st, which every reader ranks past the first 1,000 alike in the config group and the team
// directory's: it reads the directory (ACL's directory default) and is no leaf there or in the config group, its
// admission's signer writing its first wrap and committing no Add; a wrapped device's admission writes the new
// device's first wrap; the revocation of a leaf-entitled device by a wrapped one rotates and commits no Remove, and
// moves the first wrapped device into the first 1,000, where it keeps reading the directory; and no admission meets a
// member-device cap. Readers are compared at each base and at the end.
func teamRowSeats(t testing.TB, net *TeamNet) {
	owner := net.Owner()
	count := net.settings.LeafEntitledCount
	memberM, mFirst := net.ConsentedMember("m")
	memberN, nFirst := net.ConsentedMember("n")
	net.CompareEveryEntry(false)
	// the owner's first device, m's and n's first devices rank first; the rest are m's but for every tenth, n's
	devices := []*AdmissionDevice{owner, mFirst, nFirst}
	for i := 0; len(devices) < count; i += 1 {
		admitter, memberId := mFirst, memberM
		if i%10 == 0 {
			admitter, memberId = nFirst, memberN
		}
		device := net.Device(fmt.Sprintf("member device %d", i), memberId)
		net.AdmitDevice(admitter, device, 0)
		devices = append(devices, device)
		if len(devices) == count/2 {
			net.Fold(true)
		}
	}
	last := net.Device("the first device past the leaves", memberM)
	net.AdmitDevice(mFirst, last, 0)
	devices = append(devices, last)
	net.Fold(true)
	net.CompareEveryEntry(true)
	net.CheckAgreement()

	directoryId, configRepoId := net.DirectoryId(), net.ConfigRepoId()
	now := net.Clock().Now()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if rank, live := state.LeafRank(last.SidecarId); !live || rank != count || state.LeafEntitled(last.SidecarId) {
			return fmt.Errorf("the device past the leaves: rank %d, live %t, entitled %t", rank, live, state.LeafEntitled(last.SidecarId))
		}
		for _, repoId := range []sidecar.Id{configRepoId, directoryId} {
			if sidecar.GkmLeafEntitled(state, repoId, last.SidecarId, now) || !sidecar.GkmLeafEntitled(state, repoId, devices[count-1].SidecarId, now) {
				return fmt.Errorf("repo %s: the 1,000th or the 1,001st device's entitlement", repoId)
			}
			if wrapped := sidecar.GkmWrappedMembers(state, repoId, now); !slices.Equal(wrapped, []sidecar.Id{last.SidecarId}) {
				return fmt.Errorf("repo %s's wrapped members %v", repoId, wrapped)
			}
		}
		if !slices.Contains(acl.RepoReaders(directoryId, now), last.SidecarId) {
			return errors.New("the device past the leaves does not read the directory")
		}
		if commits := state.MayCommit(mFirst.SidecarId, last.SidecarId); commits.Add || !commits.FirstWrap {
			return fmt.Errorf("the admission's signer may commit %+v", commits)
		}
		mCount := 0
		for _, sidecarId := range state.SidecarIds() {
			if admission := state.Sidecar(sidecarId); admission != nil && admission.MemberId == memberM {
				mCount += 1
			}
		}
		if mCount < count*8/10 {
			return fmt.Errorf("m holds %d devices, no member-device cap reached", mCount)
		}
		return nil
	})

	// a wrapped device's admission writes the new device's first wrap
	next := net.Device("a device the wrapped one admits", memberM)
	net.AdmitDevice(last, next, 0)
	if commits := net.State().MayCommit(last.SidecarId, next.SidecarId); commits.Add || !commits.FirstWrap {
		t.Fatalf("a wrapped signer's admission commits %+v", commits)
	}
	// next, wrapped, revokes a leaf-entitled device of m's: it rotates and commits no Remove, and last moves in
	leaf := devices[slices.IndexFunc(devices[3:], func(device *AdmissionDevice) bool { return device.MemberId == memberM })+3]
	net.MustLand(net.Sign(next, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.Revocation(leaf, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if commits := state.MayCommit(next.SidecarId, leaf.SidecarId); commits.Remove || !commits.Rotate {
			return fmt.Errorf("a wrapped signer's revocation commits %+v", commits)
		}
		if !state.LeafEntitled(last.SidecarId) || state.LeafEntitled(next.SidecarId) {
			return errors.New("the revocation moved no entitlement to the first wrapped device, or one past it")
		}
		for _, repoId := range []sidecar.Id{configRepoId, directoryId} {
			if !sidecar.GkmLeafEntitled(state, repoId, last.SidecarId, now) {
				return fmt.Errorf("repo %s: the moved device is not entitled", repoId)
			}
		}
		readers := acl.RepoReaders(directoryId, now)
		if !slices.Contains(readers, last.SidecarId) || !slices.Contains(readers, next.SidecarId) || slices.Contains(readers, leaf.SidecarId) {
			return errors.New("the directory's readers after the move")
		}
		return nil
	})
	net.Fold(true)
}

// §20.4's Team config_admissions with no member-device cap (owner decision 144; QUOTA-M6-06's number): AdmissionCount
// admissions, AgentCount of them tagged agents a Delegation admits and the rest member devices, each admitted by its own
// member's first device, the Owner holding all past a quarter of an even share for each other member, land at api and
// every reader; every
// reader then counts AdmissionCount, the first 1,000 member devices by rank are leaf-entitled and the rest read by
// wraps, and the cleanup list stays empty below 90% of a cap of twice the count. Readers start only at the bases a
// fifth of the way apart and are compared there and at the end, since comparing every entry would cost the square.
func teamRowAdmissions(t testing.TB, net *TeamNet) {
	owner := net.Owner()
	settings := net.settings
	net.CompareEveryEntry(false)
	tagId := net.TagAtom("recurd")
	notAfter := net.Clock().Now().Add(30 * 24 * time.Hour).UnixMilli()
	delegation := net.Delegate(owner, "recurd", []sidecar.Id{tagId}, uint32(settings.AgentCount), notAfter)
	// the Owner's first device and every other member's first device stand already
	members := []*AdmissionDevice{owner}
	for i := 1; i < settings.MemberCount; i += 1 {
		_, first := net.ConsentedMember(fmt.Sprintf("member %d", i))
		members = append(members, first)
	}
	memberDeviceCount := settings.AdmissionCount - settings.AgentCount
	admitted := len(members)
	fifth := max(settings.AdmissionCount/5, 1)
	countAdmission := func() {
		admitted += 1
		if admitted%fifth == 0 {
			net.Fold(true)
		}
	}
	for agent := range settings.AgentCount {
		device := net.Device(fmt.Sprintf("agent %d", agent), sidecar.Id{})
		net.MustLand(net.SignByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(device, []sidecar.Id{tagId}, false, notAfter, 0)))
		countAdmission()
	}
	// each member past the first takes a quarter of an even share by its own first device, the first member the rest
	share := memberDeviceCount / (settings.MemberCount * 4)
	for _, member := range members[1:] {
		for i := 1; i < share; i += 1 {
			net.AdmitDevice(member, net.Device(fmt.Sprintf("%s device %d", member.Name, i), member.MemberId), 0)
			countAdmission()
		}
	}
	for i := 0; admitted < settings.AdmissionCount; i += 1 {
		net.AdmitDevice(owner, net.Device(fmt.Sprintf("owner device %d", i), owner.MemberId), 0)
		countAdmission()
	}
	net.FoldIfAny(true)
	net.CompareEveryEntry(true)
	net.CheckAgreement()
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if got := state.AdmissionCount(); got != settings.AdmissionCount {
			return fmt.Errorf("%d admissions, want %d", got, settings.AdmissionCount)
		}
		entitled, wrapped := 0, 0
		byMember := map[sidecar.Id]int{}
		for _, sidecarId := range state.SidecarIds() {
			admission := state.Sidecar(sidecarId)
			if admission == nil || len(admission.TagIds) != 0 {
				continue
			}
			byMember[admission.MemberId] += 1
			if state.LeafEntitled(sidecarId) {
				entitled += 1
			} else if _, live := state.LeafRank(sidecarId); live {
				wrapped += 1
			}
		}
		if want := min(settings.LeafEntitledCount, memberDeviceCount); entitled != want || entitled+wrapped != memberDeviceCount {
			return fmt.Errorf("%d leaf-entitled and %d wrapped of %d member devices", entitled, wrapped, memberDeviceCount)
		}
		if byMember[owner.MemberId] <= memberDeviceCount/settings.MemberCount {
			return fmt.Errorf("the first member holds %d member devices, no more than an even share", byMember[owner.MemberId])
		}
		if list := sidecar.CleanupList(state, 2*settings.AdmissionCount); len(list) != 0 {
			return fmt.Errorf("the cleanup list below 90%% of the cap: %+v", list)
		}
		return nil
	})
}

// FS-19's log part in a Team (§7.9's commit row, §10.6; D-ACL-24 is ACL's): under an Admin of a Team at k = 2, an
// ephemeral the Admin's first device admitted writes no config: every reader refuses it as a config head's writer,
// api refuses a base it signs though its member is in the AdminSet, leaving the tip where it was, and on a tier
// whose api appends what it refuses that base forks every reader at its position, as §7.9's BASE row forks on a base
// whose signer writes no config.
func teamRowEphemeralConfig(t testing.TB, net *TeamNet) {
	owner := net.Owner()
	adminB := net.AdminFromInvite(owner, "admin b", []sidecar.Id{owner.MemberId}, nil, 0)
	net.AdminFromInvite(owner, "admin c", []sidecar.Id{owner.MemberId}, []sidecar.Id{adminB.MemberId}, 0)
	net.RequireThreshold(2, 3)
	// an AdminSet member's admission at k = 2: b's laptop counts as one for its own ephemeral, the Owner's cosign two
	burner := net.Device("admin b burner", adminB.MemberId)
	burnerAdmission := net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)
	net.MustRefuse(net.Sign(adminB, bridge.SignedType_SIGNED_SIDECAR_ADMIT, burnerAdmission), sidecar.ErrConfigAuthority)
	net.CosignCompletes(owner, net.ProposeOpen(adminB, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.Admission(burner, nil, true, net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
	if !net.Admitted(burner) {
		t.Fatal("the Admin's ephemeral is not admitted")
	}
	net.Fold(true)
	net.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		if state.IsConfigWriter(burner.SidecarId) || sidecar.CheckConfigHeadWriter(state, burner.SidecarId) == nil {
			return errors.New("the ephemeral writes the config")
		}
		if !state.IsConfigWriter(adminB.SidecarId) || sidecar.CheckConfigHeadWriter(state, adminB.SidecarId) != nil {
			return errors.New("the Admin's own device writes no config")
		}
		return nil
	})
	before := net.Tip()
	signedHeader, rows := net.BaseKeepingTheFold(burner, nil)
	_, err := net.AppendBase(signedHeader, rows)
	refusal := &ConfigLogRefusal{}
	if !errors.As(err, &refusal) || refusal.Status != http.StatusForbidden {
		t.Fatalf("api's answer to the ephemeral's base: %v, want 403", err)
	}
	if !proto.Equal(net.Tip(), before) {
		t.Fatalf("a refused base moved the tip from %d to %d", before.GetVersion(), net.Tip().GetVersion())
	}
	if !net.ForgedAppends() {
		t.Logf("this tier's api appends nothing it refuses, so the forged base was not run here")
		return
	}
	net.AllowForks()
	signedHeader, rows = net.BaseKeepingTheFold(burner, nil)
	net.rows[sha256.Sum256(rows)] = bytes.Clone(rows)
	pin := net.SequenceAnyway(bridge.AuthEntryKindBase, signedHeader)
	forks := net.Forks()
	if len(forks) != net.ReaderCount() {
		t.Fatalf("%d of %d readers forked at the ephemeral's base: %v", len(forks), net.ReaderCount(), forks)
	}
	for name, forkN := range forks {
		if forkN != pin.GetVersion() {
			t.Fatalf("%s forked at %d, not %d", name, forkN, pin.GetVersion())
		}
	}
}

// Tunables of FS-101's log-retention fixture: the production values, which a schedule leaves alone.
type TeamLogRetentionSettings struct {
	// §7.9's fold row: a base once the oldest unfolded statement is FoldEntryCount positions behind the tip or
	// FoldAge old, DefaultConfigWriterSettings' 1,024 and 24 h.
	FoldEntryCount int
	FoldAge        time.Duration
	// §7.9's retention row at api: the entries a newer base retires stay this long after that base, 30 days, the
	// span readers keep each base's pin (ConfigLogSettings.BasePinRetention).
	KeepAfterNewerBase time.Duration
	// How far api's clock moves between two of the run's statements: 1 h, so a day's tail holds 24 and each fold is
	// due by age.
	StatementInterval time.Duration
	// The span past a pin a run lasts at the least, and the bases it publishes at the least: FS-101's 30 days and 10
	// folds.
	RunSpan  time.Duration
	RunFolds int
	// How many entries api's retention pass deletes at most at a time; the next pass goes on, as server's does.
	DeleteMaxCount int
	// The page one List asks for.
	ListPageCount int
}

// The production values (§7.9; FS-101).
func DefaultTeamLogRetentionSettings() *TeamLogRetentionSettings {
	writerSettings := sidecar.DefaultConfigWriterSettings()
	return &TeamLogRetentionSettings{
		FoldEntryCount:     writerSettings.FoldEntryCount,
		FoldAge:            writerSettings.FoldAge,
		KeepAfterNewerBase: sidecar.DefaultConfigLogSettings().BasePinRetention,
		StatementInterval:  time.Hour,
		RunSpan:            30 * 24 * time.Hour,
		RunFolds:           10,
		DeleteMaxCount:     1000,
		ListPageCount:      500,
	}
}

// FS-101's log-retention fixture (TEAM-M6-12; §7.9's fold, retain and retention rows; §16.11's repo file row): a Team
// network whose writer publishes a base whenever §7.9's fold row calls for one with the production values, and whose
// api, after each base, deletes what its retention pass deletes (server's ConfigLogSequencer.RetainNetwork): every entry
// below the retention point the newest base at least KeepAfterNewerBase old sets, the Signed Genesis never, and the
// rows no retained base names; all on the world's fake clock. A schedule makes its own statements on Net (a repo and
// its admin, an announcement), notes the position n0 it cares about, runs the log past it (RunPast), and then reads
// what a fresh member device makes of what api still holds (FreshDevice), while the world's long-running readers keep
// what they applied. Every reader also drops each base's pin older than BasePinRetention, the production value, so a
// pin at n0 no longer checks anywhere once the run is past it. Not safe for concurrent use: one schedule drives it.
type TeamLogRetention struct {
	net      *TeamNet
	settings *TeamLogRetentionSettings
	// the bases the run published, and api's retention point after its newest pass
	folds int
	point uint64
	// the members whose admissions fill the run, one a statement
	filler int
}

// The fixture on tier, a Team network with its directory as NewTeamNet makes it. settings nil takes the production
// values. The caller closes it.
func NewTeamLogRetention(t AdmissionT, tier *AdmissionTier, settings *TeamLogRetentionSettings) *TeamLogRetention {
	t.Helper()
	if settings == nil {
		settings = DefaultTeamLogRetentionSettings()
	}
	net := NewTeamNet(t, tier, nil)
	// a run of a month publishes a base a day: a new device and a gate at each would hold the run to their square
	net.StartReadersAtBases(false)
	return &TeamLogRetention{net: net, settings: settings, point: 1}
}

// The Team network the fixture runs.
func (self *TeamLogRetention) Net() *TeamNet {
	return self.net
}

// Stops the world.
func (self *TeamLogRetention) Close() {
	self.net.Close()
}

// The fixture's tunables.
func (self *TeamLogRetention) Settings() *TeamLogRetentionSettings {
	return self.settings
}

// The bases the fixture's runs published.
func (self *TeamLogRetention) Folds() int {
	return self.folds
}

// api's retention point after its newest pass: the oldest position its store still holds past the genesis.
func (self *TeamLogRetention) RetentionPoint() uint64 {
	return self.point
}

// Whether a fold is due by §7.9's fold row at the tip and api's clock: the oldest statement or tick past the newest
// base's folded_through is FoldEntryCount positions behind the tip or FoldAge old.
func (self *TeamLogRetention) foldDue() bool {
	net := self.net.AdmissionNet
	base := net.State().Base()
	if base == nil {
		return false
	}
	tip := net.Tip().GetVersion()
	for k := base.GetFoldedThrough() + 1; k <= tip; k += 1 {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(net.entries[k], entry); err != nil {
			net.t.Fatalf("entry %d: %v", k, err)
		}
		if entry.GetKind() == bridge.AuthEntryKindBase {
			continue
		}
		if uint64(self.settings.FoldEntryCount) <= tip-k+1 {
			return true
		}
		return self.settings.FoldAge <= net.Clock().Now().Sub(time.UnixMilli(entry.GetTimeMs()))
	}
	return false
}

// One statement of the run: a MemberAdmit of a fresh member by the writer's device.
func (self *TeamLogRetention) fill() {
	self.filler += 1
	self.net.AdmitMember(self.net.WriterDevice(), fmt.Sprintf("retention filler %d", self.filler), bridge.MemberRole_MEMBER_ROLE_MEMBER)
}

// Runs the log on api's clock until RunSpan has passed since entry n0's time and the run has published RunFolds
// bases, and until api's retention pass has deleted n0's entry: one statement each StatementInterval, a base whenever
// §7.9's fold row is due, and api's retention pass after each base. Fails the schedule if n0 is not a position the
// world has read.
func (self *TeamLogRetention) RunPast(n0 uint64) {
	net := self.net.AdmissionNet
	net.t.Helper()
	entryBytes, found := net.entries[n0]
	if !found {
		net.t.Fatalf("no entry at %d to run past", n0)
	}
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		net.t.Fatal(err)
	}
	until := time.UnixMilli(entry.GetTimeMs()).Add(self.settings.RunSpan)
	folds := 0
	for net.Clock().Now().Before(until) || folds < self.settings.RunFolds || self.point <= n0 {
		net.Wait(self.settings.StatementInterval)
		self.fill()
		if self.foldDue() {
			net.Fold(true)
			folds += 1
			self.folds += 1
			self.Retain()
		}
	}
}

// api's retention pass now, as server's ConfigLogSequencer.RetainNetwork runs it: the newest base at least
// KeepAfterNewerBase old sets the point, min(its folded_through + 1, the base before it), and the entries below it and
// the rows no base at or past it names are deleted from the first metadata cluster, entry 0 never, a pass at most
// DeleteMaxCount objects, passes repeating until one deletes nothing. The point.
func (self *TeamLogRetention) Retain() uint64 {
	net := self.net.AdmissionNet
	net.t.Helper()
	type base struct {
		n             uint64
		timeMs        int64
		foldedThrough uint64
		rowsSha256    []byte
	}
	bases := []*base{}
	positions := []uint64{}
	for n := range net.entries {
		positions = append(positions, n)
	}
	slices.Sort(positions)
	for _, n := range positions {
		entry := &bridge.AuthEntry{}
		signed := &bridge.Signed{}
		header := &bridge.ProjectionHeader{}
		if proto.Unmarshal(net.entries[n], entry) != nil || entry.GetKind() != bridge.AuthEntryKindBase {
			continue
		}
		if proto.Unmarshal(entry.GetBody(), signed) != nil || proto.Unmarshal(signed.GetBody(), header) != nil {
			net.t.Fatalf("the base at %d does not parse", n)
		}
		bases = append(bases, &base{n: n, timeMs: entry.GetTimeMs(), foldedThrough: header.GetFoldedThrough(), rowsSha256: header.GetRowsSha256()})
	}
	nowMs := net.Clock().Now().UnixMilli()
	point := uint64(1)
	for i := len(bases) - 1; 0 <= i; i -= 1 {
		if nowMs-bases[i].timeMs < self.settings.KeepAfterNewerBase.Milliseconds() {
			continue
		}
		point = bases[i].foldedThrough + 1
		if 0 < i {
			point = min(point, bases[i-1].n)
		}
		point = max(point, 1)
		break
	}
	retainedRows := map[string]bool{}
	for _, base := range bases {
		if point <= base.n {
			retainedRows[string(base.rowsSha256)] = true
		}
	}
	ctx := net.Context()
	for {
		deleted := 0
		for _, n := range positions {
			if n == 0 || point <= n || self.settings.DeleteMaxCount <= deleted {
				continue
			}
			key := sidecar.ConfigEntryKey(net.networkId, n)
			if _, err := net.cluster.Head(ctx, key); errors.Is(err, sidecar.ErrBlobNotFound) {
				continue
			} else if err != nil {
				net.t.Fatalf("api's retention pass at %d: %v", n, err)
			}
			if err := net.cluster.Delete(ctx, key); err != nil {
				net.t.Fatalf("api's retention pass at %d: %v", n, err)
			}
			deleted += 1
		}
		for _, key := range self.rowKeys(ctx) {
			rowsSha256, ok := teamRowsKeySha256(net.networkId, key)
			if !ok || retainedRows[string(rowsSha256)] || self.settings.DeleteMaxCount <= deleted {
				continue
			}
			info, err := net.cluster.Head(ctx, key)
			if err != nil || nowMs-info.LastModified.UnixMilli() < self.settings.KeepAfterNewerBase.Milliseconds() {
				continue
			}
			if err := net.cluster.Delete(ctx, key); err != nil {
				net.t.Fatalf("api's retention pass on %s: %v", key, err)
			}
			deleted += 1
		}
		if deleted == 0 {
			break
		}
	}
	self.point = point
	return point
}

// Every projrows/ key of the network in the first metadata cluster.
func (self *TeamLogRetention) rowKeys(ctx context.Context) []string {
	net := self.net.AdmissionNet
	prefix := teamRowsKeyPrefix(net.networkId)
	keys := []string{}
	startAfter := ""
	for {
		infos, more, err := net.cluster.List(ctx, prefix, startAfter, self.settings.ListPageCount)
		if err != nil {
			net.t.Fatalf("listing %s: %v", prefix, err)
		}
		for _, info := range infos {
			keys = append(keys, info.Key)
			startAfter = info.Key
		}
		if !more || len(infos) == 0 {
			return keys
		}
	}
}

// projrows/<network_id>/'s prefix, from ConfigRowsKey's own form with no digest.
func teamRowsKeyPrefix(networkId sidecar.Id) string {
	return strings.TrimSuffix(sidecar.ConfigRowsKey(networkId, nil), "/_")
}

// The rows_sha256 a projrows/ key of the network names, false for another key.
func teamRowsKeySha256(networkId sidecar.Id, key string) ([]byte, bool) {
	prefix := teamRowsKeyPrefix(networkId)
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, "/_") {
		return nil, false
	}
	rowsSha256, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(key, prefix), "/_"))
	if err != nil || len(rowsSha256) != sha256.Size || sidecar.ConfigRowsKey(networkId, rowsSha256) != key {
		return nil, false
	}
	return rowsSha256, true
}

// Whether api's store still holds entry n.
func (self *TeamLogRetention) Held(n uint64) bool {
	net := self.net.AdmissionNet
	net.t.Helper()
	_, err := net.cluster.Head(net.Context(), sidecar.ConfigEntryKey(net.networkId, n))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return false
	}
	if err != nil {
		net.t.Fatalf("entry %d: %v", n, err)
	}
	return true
}

// A fresh member device's full reader, started now as §7.9's retention row starts one: from api's read of the log
// from 0, which answers the Signed Genesis and the entries its store still holds, at the newest base among them, its
// config head read from the config repo and checked, then every entry after it. The reader holds nothing the run
// deleted.
func (self *TeamLogRetention) FreshDevice() *sidecar.ConfigLog {
	net := self.net.AdmissionNet
	net.t.Helper()
	retained := &sidecar.ConfigRetained{Rows: map[[sha256.Size]byte][]byte{}}
	after := uint64(0)
	for {
		projection, err := net.api.ReadConfigProjection(net.Context(), net.networkId, after)
		if err != nil {
			net.t.Fatalf("a fresh device's read after %d: %v", after, err)
		}
		if after == 0 {
			retained.SignedGenesis = projection.SignedGenesis
		}
		for _, rows := range projection.Rows {
			retained.Rows[sha256.Sum256(rows)] = bytes.Clone(rows)
		}
		for _, entryBytes := range projection.Entries {
			entry := &bridge.AuthEntry{}
			if err := proto.Unmarshal(entryBytes, entry); err != nil {
				net.t.Fatal(err)
			}
			retained.Entries = append(retained.Entries, bytes.Clone(entryBytes))
			after = entry.GetN()
		}
		if !projection.More || len(projection.Entries) == 0 {
			break
		}
	}
	log, err := sidecar.RestoreConfigLog(net.logSettings(), retained, teamFreshDeviceSource{net: net, rows: retained.Rows})
	if err != nil {
		net.t.Fatalf("a fresh device at %d: %v", after, err)
	}
	return log
}

// A fresh device's rows source: the rows api served it, then the world's, each base's config head read from the
// config repo and checked.
type teamFreshDeviceSource struct {
	net  *AdmissionNet
	rows map[[sha256.Size]byte][]byte
}

func (self teamFreshDeviceSource) Rows(networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
	if len(rowsSha256) == sha256.Size {
		if rows, found := self.rows[[sha256.Size]byte(rowsSha256)]; found {
			return bytes.Clone(rows), nil
		}
	}
	// the rows of a base api still names: GET them from the store, as the projection read would
	object, err := self.net.cluster.Get(self.net.Context(), sidecar.ConfigRowsKey(networkId, rowsSha256))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", sidecar.ErrConfigRowsUnavailable, err)
	}
	defer object.Body.Close()
	return io.ReadAll(object.Body)
}

func (self teamFreshDeviceSource) CheckHead(check *sidecar.ConfigHeadCheck) (*sidecar.ConfigHeadFacts, error) {
	return admissionHeadSource{net: self.net}.CheckHead(check)
}
