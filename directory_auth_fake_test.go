//go:build !sidecar_http

// RECORD-M6-12's fake and real views on one fixture: sidecartest's FakeDirectoryAuth, written from what the shared
// network's log holds, answers every directory question as NewDirectoryAuthView does over TEAM's ConfigState, so a
// test on the fake judges what a reader judges. The log is folded past retention first, so positions before the tip
// come from each view's head positions.

package sidecar_test

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The fake's fixture of the shared network, from its facts as a test writes them.
func directoryAuthFakeOf(network *sidecar.DirectoryAuthTestNetwork) sidecar.DirectoryAuthView {
	id := func(value sidecar.Id) *sidecar.Id {
		return &value
	}
	fixture := &sidecartest.FakeDirectoryAuthFixture{
		Sidecars: map[sidecar.Id]*sidecartest.FakeDirectorySidecar{
			network.OwnerDevice:  {MemberId: id(network.OwnerMemberId), ConfigWriter: true},
			network.AdminDevice:  {MemberId: id(network.AdminMemberId), ConfigWriter: true, ConsentedAt: network.AdmittedAt[network.AdminDevice]},
			network.MemberDevice: {MemberId: id(network.MemberId), ConsentedAt: network.MemberAdmittedAt},
			network.Confirmed:    {MemberId: id(network.MemberId), ConsentedAt: network.ConfirmedAt},
			network.ReadOnly:     {MemberId: id(network.MemberId), Standing: sidecar.DirectoryStandingReadOnly},
			network.Revoked:      {MemberId: id(network.MemberId), RevokedAt: network.RevokedAt, ConsentedAt: network.AdmittedAt[network.Revoked]},
			network.Suspended:    {MemberId: id(network.MemberId), SuspendedAt: network.BeforeConfirm, ConsentedAt: network.AdmittedAt[network.Suspended]},
			network.Parked:       {MemberId: id(network.MemberId), Standing: sidecar.DirectoryStandingParked},
			network.Unconsented:  {MemberId: id(network.MemberId), Standing: sidecar.DirectoryStandingUnconsented},
			network.LeftDevice:   {RevokedAt: network.LeftAt},
			network.Tagged:       {SponsorId: id(network.MemberId)},
			network.Orphan:       {},
		},
		AdminMemberIds: []sidecar.Id{network.OwnerMemberId, network.AdminMemberId},
		Repos: map[sidecar.Id]*sidecartest.FakeDirectoryRepo{
			network.DirectoryId:   {Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: network.OwnerDevice, At: network.DirectoryAt}}},
			network.GeneralRepoId: {Kind: protocol.RepoKind_REPO_KIND_GENERAL, Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: network.MemberDevice, At: network.GeneralAt}}},
			network.VaultId: {Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: id(network.MemberId),
				Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: network.MemberDevice, At: network.VaultAt}}},
		},
		DirectoryId: id(network.DirectoryId),
	}
	// as many positions as the log, the tip alone retained, so earlier ones come from the tip's positions as in the log
	auth := sidecartest.NewFakeDirectoryAuth()
	for position := uint64(1); position <= network.Tip(); position += 1 {
		auth.Append(fixture)
	}
	auth.RetainFrom(network.Tip())
	return auth.Tip()
}

// The fake and the real view agree on the shared fixture: standing, admins, D-MCP-35's right at every position the
// fixture names, the Requests table, members, sponsors and masks.
func TestDirectoryAuthFakeAgreesWithTheRealView(t *testing.T) {
	network := sidecar.NewDirectoryAuthTestNetwork(t)
	network.FoldPastRetention(t)
	real := network.View()
	fake := directoryAuthFakeOf(network)
	views := map[string]sidecar.DirectoryAuthView{"real": real, "fake": fake}

	sidecarIds := []sidecar.Id{
		network.OwnerDevice, network.AdminDevice, network.MemberDevice, network.Confirmed, network.ReadOnly, network.Revoked,
		network.Suspended, network.Parked, network.Unconsented, network.LeftDevice, network.Tagged, network.Orphan,
		sidecar.NewId(),
	}
	for _, sidecarId := range sidecarIds {
		realStanding, realErr := real.SignerStanding(sidecarId, real.Pin())
		fakeStanding, fakeErr := fake.SignerStanding(sidecarId, fake.Pin())
		if realStanding != fakeStanding || (realErr == nil) != (fakeErr == nil) {
			t.Errorf("standing of %s: real %s %v, fake %s %v", sidecarId, realStanding, realErr, fakeStanding, fakeErr)
		}
		realMember, realOk := real.MemberOf(sidecarId)
		fakeMember, fakeOk := fake.MemberOf(sidecarId)
		if realMember != fakeMember || realOk != fakeOk {
			t.Errorf("member of %s: real %s %v, fake %s %v", sidecarId, realMember, realOk, fakeMember, fakeOk)
		}
		realSponsor, realOk := real.SponsorOf(sidecarId)
		fakeSponsor, fakeOk := fake.SponsorOf(sidecarId)
		if realSponsor != fakeSponsor || realOk != fakeOk {
			t.Errorf("sponsor of %s: real %s %v, fake %s %v", sidecarId, realSponsor, realOk, fakeSponsor, fakeOk)
		}
		if real.Masked(sidecarId) != fake.Masked(sidecarId) {
			t.Errorf("masked %s: real %v", sidecarId, real.Masked(sidecarId))
		}
	}

	answers := map[string][]sidecar.Id{}
	for name, view := range views {
		directoryId, ok := view.Directory()
		if !ok || directoryId != network.DirectoryId {
			t.Errorf("%s directory %s %v", name, directoryId, ok)
		}
		admins, err := view.DirectoryAdmins(view.Pin())
		if err != nil {
			t.Fatalf("%s admins: %v", name, err)
		}
		answers[name] = admins
	}
	if !slices.Equal(answers["real"], answers["fake"]) {
		t.Errorf("admins: real %v, fake %v", answers["real"], answers["fake"])
	}

	positions := []uint64{
		network.MemberAdmittedAt, network.DirectoryAt, network.GeneralAt - 1, network.GeneralAt, network.VaultAt - 1, network.VaultAt,
		network.RevokedAt - 1, network.RevokedAt, network.BeforeConfirm, network.ConfirmedAt, network.LeftAt, network.Tip(),
	}
	for _, repoId := range []sidecar.Id{network.DirectoryId, network.GeneralRepoId, network.VaultId} {
		for _, sidecarId := range sidecarIds {
			for _, position := range positions {
				realRight, realErr := real.RepoAdminRight(repoId, sidecarId, position)
				fakeRight, fakeErr := fake.RepoAdminRight(repoId, sidecarId, position)
				if realRight != fakeRight || (realErr == nil) != (fakeErr == nil) {
					t.Errorf("right of %s on %s at %d: real %v %v, fake %v %v", sidecarId, repoId, position, realRight, realErr, fakeRight, fakeErr)
				}
			}
		}
	}

	for _, repoId := range []sidecar.Id{network.GeneralRepoId, network.VaultId, network.DirectoryId} {
		request := &protocol.DirectoryRequest{Target: &protocol.RequestTarget{RepoId: repoId.Bytes()}}
		realApprovers, realErr := real.EligibleApprovers(request, network.Tagged, real.Pin())
		fakeApprovers, fakeErr := fake.EligibleApprovers(request, network.Tagged, fake.Pin())
		if (realErr == nil) != (fakeErr == nil) {
			t.Fatalf("approvers of %s: real %v, fake %v", repoId, realErr, fakeErr)
		}
		if realErr == nil && (!slices.Equal(realApprovers.SidecarIds, fakeApprovers.SidecarIds) ||
			!slices.Equal(realApprovers.MemberIds, fakeApprovers.MemberIds) || realApprovers.OwnerBound != fakeApprovers.OwnerBound ||
			realApprovers.Count != fakeApprovers.Count) {
			t.Errorf("approvers of %s: real %+v, fake %+v", repoId, realApprovers, fakeApprovers)
		}
		for _, deciderId := range sidecarIds {
			realDecides, realErr := real.Decides(request, network.Tagged, deciderId, real.Pin())
			fakeDecides, fakeErr := fake.Decides(request, network.Tagged, deciderId, fake.Pin())
			if realDecides != fakeDecides || (realErr == nil) != (fakeErr == nil) {
				t.Errorf("decider %s of %s: real %v %v, fake %v %v", deciderId, repoId, realDecides, realErr, fakeDecides, fakeErr)
			}
		}
	}
}
