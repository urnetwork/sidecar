// RECORD-M6-12's DirectoryAuthView over TEAM's ConfigState and ACL's AclState, through a real log: a table for each
// standing state, an admin who left the AdminSet, an owner-bound repo's consent positions, a position older than the
// log retains answered from the head, the Requests table's approvers, and the unbound view refusing. The shared
// fixture below is exported to the external test that holds sidecartest's FakeDirectoryAuth to the same answers.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One team network's log as RECORD-M6-12's tests drive it: an owner, an admin, a member with a consented device, and
// a device in each standing state; the directory, a general repo and the member's vault; and the positions each came
// in at.
type DirectoryAuthTestNetwork struct {
	net *testConfigNet

	OwnerMemberId Id
	AdminMemberId Id
	MemberId      Id
	// A member whose MemberRevoke came in at LeftAt.
	LeftMemberId Id

	OwnerDevice  Id
	AdminDevice  Id
	MemberDevice Id
	// Admitted by an admin alone, then consented by its member's OwnerConfirm at ConfirmedAt.
	Confirmed   Id
	ReadOnly    Id
	Revoked     Id
	Suspended   Id
	Parked      Id
	Unconsented Id
	LeftDevice  Id
	// Tagged, its sponsor the member.
	Tagged Id
	// Tagged, its sponsor the member who left.
	Orphan Id

	DirectoryId   Id
	GeneralRepoId Id
	VaultId       Id

	// Each device's admission position.
	AdmittedAt       map[Id]uint64
	MemberAdmittedAt uint64
	DirectoryAt      uint64
	GeneralAt        uint64
	VaultAt          uint64
	RevokedAt        uint64
	ConfirmedAt      uint64
	LeftAt           uint64
	AdminSetAt       uint64
	BeforeConfirm    uint64
}

// The view at the log's tip.
func (self *DirectoryAuthTestNetwork) View() DirectoryAuthView {
	return NewDirectoryAuthView(self.net.log.State())
}

// The tip's pin.
func (self *DirectoryAuthTestNetwork) Pin() *bridge.AuthPin {
	return self.net.log.Pin()
}

// The pin of an earlier position of the log.
func (self *DirectoryAuthTestNetwork) PinAt(position uint64) *bridge.AuthPin {
	return self.net.statesAt[position].Pin()
}

// Builds the shared fixture through TEAM's log, failing t on any refusal.
func NewDirectoryAuthTestNetwork(t testing.TB) *DirectoryAuthTestNetwork {
	net := newTestConfigNet(t)
	self := &DirectoryAuthTestNetwork{net: net, OwnerMemberId: net.ownerMemberId, OwnerDevice: net.owner.sidecarId, AdmittedAt: map[Id]uint64{}}
	// an Admin whose device came from an invite, so it is consented, as a real admin's is
	self.AdminMemberId = testConfigId("directory admin member")
	net.admitMember(net.owner, self.AdminMemberId, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()}, Admins: [][]byte{self.AdminMemberId.Bytes()},
	})
	admin := net.device("directory admin device", self.AdminMemberId)
	net.admitDevice(net.owner, admin, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	self.AdminDevice = admin.sidecarId
	self.AdmittedAt[admin.sidecarId] = net.n
	member, memberDevice := net.consentedMember("directory member")
	self.MemberId, self.MemberDevice, self.MemberAdmittedAt = member, memberDevice.sidecarId, net.n
	self.AdmittedAt[memberDevice.sidecarId] = net.n
	admitByMember := func(label string, capabilities uint32) testConfigDevice {
		device := net.device(label, member)
		net.admitDevice(memberDevice, device, capabilities)
		self.AdmittedAt[device.sidecarId] = net.n
		return device
	}
	self.ReadOnly = admitByMember("directory read only", uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)).sidecarId
	revoked := admitByMember("directory revoked", 0)
	self.Revoked = revoked.sidecarId
	suspended := admitByMember("directory suspended", 0)
	self.Suspended = suspended.sidecarId
	parked := admitByMember("directory parked", 0)
	self.Parked = parked.sidecarId
	unconsented := net.device("directory unconsented", member)
	net.admitDevice(admin, unconsented, 0)
	self.Unconsented = unconsented.sidecarId
	self.AdmittedAt[unconsented.sidecarId] = net.n
	confirmed := net.device("directory confirmed", member)
	net.admitDevice(admin, confirmed, 0)
	self.Confirmed = confirmed.sidecarId
	self.AdmittedAt[confirmed.sidecarId] = net.n
	leftMember, leftDevice := net.consentedMember("directory leaving member")
	self.LeftMemberId, self.LeftDevice = leftMember, leftDevice.sidecarId
	self.AdmittedAt[leftDevice.sidecarId] = net.n

	// a base adds what no statement here can: a cascade's park, and two tagged sidecars with their sponsors
	state := net.log.State()
	rows := state.Rows()
	for _, row := range rows.Sidecars {
		if bytes.Equal(row.GetSidecarId(), parked.sidecarId.Bytes()) {
			row.ParkedAt = net.n
		}
	}
	tagId := testConfigId("directory tag")
	addTagged := func(label string, sponsor Id) Id {
		device := net.device(label, Id{})
		rows.Sidecars = append(rows.Sidecars, &bridge.SidecarRow{
			SidecarId: device.sidecarId.Bytes(), AdmissionSigners: [][]byte{net.owner.sidecarId.Bytes()}, AdmittedAt: net.n,
			IdentityPublicKey: device.publicKey(), IdentityAlg: configIdentityAlgEd25519, TagIds: [][]byte{tagId.Bytes()},
			Sponsor: sponsor.Bytes(),
		})
		return device.sidecarId
	}
	self.Tagged = addTagged("directory tagged", member)
	self.Orphan = addTagged("directory orphan", leftMember)
	if verdict := net.pushBase(net.owner, rows, net.n, state.Base().GetConfigVersion()+1, state.threshold); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}

	self.DirectoryId, self.GeneralRepoId, self.VaultId = testConfigId("directory repo"), testConfigId("directory general"), testConfigId("directory vault")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: self.DirectoryId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY})
	self.DirectoryAt = net.n
	net.mustPost(memberDevice, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: self.GeneralRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	self.GeneralAt = net.n
	net.mustPost(memberDevice, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: self.VaultId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT})
	self.VaultAt = net.n

	net.mustPost(memberDevice, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(revoked, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	self.RevokedAt = net.n
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: suspended.sidecarId.Bytes(), SuspendId: bytes.Repeat([]byte{0x5d}, 16)})
	self.BeforeConfirm = net.n
	net.mustPost(memberDevice, bridge.SignedType_SIGNED_OWNER_CONFIRM, &protocol.OwnerConfirm{Header: net.header(), SidecarId: confirmed.sidecarId.Bytes()})
	self.ConfirmedAt = net.n
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: leftMember.Bytes()})
	self.LeftAt = net.n
	return self
}

// The tip's position.
func (self *DirectoryAuthTestNetwork) Tip() uint64 {
	return self.net.n
}

// Moves the log 31 days on through 10 folds, each over a fresh member's admission, so every position the fixture
// built is before what the log retains.
func (self *DirectoryAuthTestNetwork) FoldPastRetention(t testing.TB) {
	net := self.net
	net.timeMs += 31 * 24 * 60 * 60 * 1000
	configVersion := net.log.State().Base().GetConfigVersion()
	for fold := 0; fold < 10; fold += 1 {
		net.admitMemberDevice(fmt.Sprintf("directory filler %d", fold))
		configVersion += 1
		if verdict := net.fold(net.owner, net.n, configVersion); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
	}
}

// The admin leaves the AdminSet: its device writes no config heads from the returned position on.
func (self *DirectoryAuthTestNetwork) AdminLeavesTheAdminSet(t testing.TB) uint64 {
	self.net.mustPost(self.net.owner, bridge.SignedType_SIGNED_ADMIN_SET, &protocol.AdminSet{
		Header: self.net.header(), Owners: [][]byte{self.OwnerMemberId.Bytes()},
	})
	if self.net.log.State().IsConfigWriter(self.AdminDevice) {
		t.Fatal("the admin's device still writes config heads")
	}
	self.AdminSetAt = self.net.n
	return self.net.n
}

// A table for each standing state, judged at the tip's pin.
func TestDirectoryAuthSignerStandingTable(t *testing.T) {
	network := NewDirectoryAuthTestNetwork(t)
	view := network.View()
	cases := []struct {
		name      string
		sidecarId Id
		want      DirectoryStanding
	}{
		{name: "the owner's device", sidecarId: network.OwnerDevice, want: DirectoryStandingStanding},
		{name: "an admin's device", sidecarId: network.AdminDevice, want: DirectoryStandingStanding},
		{name: "a consented member device", sidecarId: network.MemberDevice, want: DirectoryStandingStanding},
		{name: "a device its member confirmed", sidecarId: network.Confirmed, want: DirectoryStandingStanding},
		{name: "a tagged sidecar", sidecarId: network.Tagged, want: DirectoryStandingStanding},
		{name: "a tagged sidecar whose sponsor left", sidecarId: network.Orphan, want: DirectoryStandingStanding},
		{name: "never admitted", sidecarId: testConfigId("directory stranger"), want: DirectoryStandingUnadmitted},
		{name: "revoked", sidecarId: network.Revoked, want: DirectoryStandingRevoked},
		{name: "its member removed", sidecarId: network.LeftDevice, want: DirectoryStandingRevoked},
		{name: "parked by a cascade", sidecarId: network.Parked, want: DirectoryStandingParked},
		{name: "suspended", sidecarId: network.Suspended, want: DirectoryStandingSuspended},
		{name: "read_only", sidecarId: network.ReadOnly, want: DirectoryStandingReadOnly},
		{name: "admitted by an admin alone", sidecarId: network.Unconsented, want: DirectoryStandingUnconsented},
	}
	for _, c := range cases {
		standing, err := view.SignerStanding(c.sidecarId, network.Pin())
		if err != nil || standing != c.want {
			t.Errorf("%s: %s, %v; want %s", c.name, standing, err, c.want)
		}
	}
	// judged where it came in: before its revocation the revoked device stood, and before its OwnerConfirm the
	// confirmed one did not
	if standing, err := view.SignerStanding(network.Revoked, network.PinAt(network.RevokedAt-1)); err != nil || standing != DirectoryStandingStanding {
		t.Errorf("the revoked device before its revocation: %s, %v", standing, err)
	}
	if standing, err := view.SignerStanding(network.Confirmed, network.PinAt(network.BeforeConfirm)); err != nil || standing != DirectoryStandingUnconsented {
		t.Errorf("the confirmed device before its confirmation: %s, %v", standing, err)
	}
	// a pin this log does not hold is no verdict
	ahead := &bridge.AuthPin{Version: network.Pin().GetVersion() + 1, Chain: bytes.Repeat([]byte{1}, 32)}
	if standing, err := view.SignerStanding(network.MemberDevice, ahead); standing != DirectoryStandingUnjudged || !errors.Is(err, ErrDirectoryAuthAhead) {
		t.Errorf("a pin ahead: %s, %v", standing, err)
	}
	forked := &bridge.AuthPin{Version: network.GeneralAt, Chain: bytes.Repeat([]byte{2}, 32)}
	if standing, err := view.SignerStanding(network.MemberDevice, forked); standing != DirectoryStandingUnjudged || !errors.Is(err, ErrDirectoryAuthOffChain) {
		t.Errorf("a pin off the chain: %s, %v", standing, err)
	}
}

// The directory's admins are its creator and every config writer, each consented, standing and not read_only: an
// admin who leaves the AdminSet stops being one at that position, and the creator stays one while it stands.
func TestDirectoryAuthAdminWhoLeftTheAdminSet(t *testing.T) {
	network := NewDirectoryAuthTestNetwork(t)
	if directoryId, ok := network.View().Directory(); !ok || directoryId != network.DirectoryId {
		t.Fatalf("the directory: %s %v", directoryId, ok)
	}
	want := []Id{network.OwnerDevice, network.AdminDevice}
	slices.SortFunc(want, Id.Cmp)
	admins, err := network.View().DirectoryAdmins(network.Pin())
	if err != nil || !slices.Equal(admins, want) {
		t.Fatalf("admins %v, %v; want %v", admins, err, want)
	}
	before := network.Pin()
	leftAt := network.AdminLeavesTheAdminSet(t)
	view := network.View()
	admins, err = view.DirectoryAdmins(network.PinAt(leftAt))
	if err != nil || !slices.Equal(admins, []Id{network.OwnerDevice}) {
		t.Errorf("after the AdminSet: %v, %v", admins, err)
	}
	if admins, err := view.DirectoryAdmins(before); err != nil || !slices.Equal(admins, want) {
		t.Errorf("judged before it: %v, %v", admins, err)
	}
	// before the directory's RepoCreate there are none
	if admins, err := view.DirectoryAdmins(network.PinAt(network.DirectoryAt - 1)); err != nil || len(admins) != 0 {
		t.Errorf("before the directory: %v, %v", admins, err)
	}
}

// An owner-bound repo's right is its owner's consented device's, by the rows' admission, confirmation and revocation
// positions: a device an admin admitted holds it from its OwnerConfirm on, a revoked device until its revocation, and
// no admin or other member's device ever.
func TestDirectoryAuthOwnerBoundConsentPositions(t *testing.T) {
	network := NewDirectoryAuthTestNetwork(t)
	view := network.View()
	cases := []struct {
		name      string
		sidecarId Id
		position  uint64
		want      bool
	}{
		{name: "the vault's creator", sidecarId: network.MemberDevice, position: network.VaultAt, want: true},
		{name: "before the vault", sidecarId: network.MemberDevice, position: network.VaultAt - 1, want: false},
		{name: "confirmed, before its OwnerConfirm", sidecarId: network.Confirmed, position: network.BeforeConfirm, want: false},
		{name: "confirmed, at its OwnerConfirm", sidecarId: network.Confirmed, position: network.ConfirmedAt, want: true},
		{name: "revoked, before its revocation", sidecarId: network.Revoked, position: network.RevokedAt - 1, want: true},
		{name: "revoked, at its revocation", sidecarId: network.Revoked, position: network.RevokedAt, want: false},
		{name: "an admin's device", sidecarId: network.AdminDevice, position: network.ConfirmedAt, want: false},
		{name: "the owner's device", sidecarId: network.OwnerDevice, position: network.ConfirmedAt, want: false},
		{name: "read_only", sidecarId: network.ReadOnly, position: network.ConfirmedAt, want: false},
		{name: "never consented", sidecarId: network.Unconsented, position: network.ConfirmedAt, want: false},
	}
	for _, c := range cases {
		right, err := view.RepoAdminRight(network.VaultId, c.sidecarId, c.position)
		if err != nil || right != c.want {
			t.Errorf("%s: %v, %v", c.name, right, err)
		}
	}
	// a general repo's right is its admins', and the directory's repo file is ignored
	if right, err := view.RepoAdminRight(network.GeneralRepoId, network.MemberDevice, network.GeneralAt); err != nil || !right {
		t.Errorf("the general repo's creator: %v, %v", right, err)
	}
	if right, err := view.RepoAdminRight(network.GeneralRepoId, network.Confirmed, network.ConfirmedAt); err != nil || right {
		t.Errorf("a device that is no admin of it: %v, %v", right, err)
	}
	if right, err := view.RepoAdminRight(network.DirectoryId, network.OwnerDevice, network.DirectoryAt); err != nil || right {
		t.Errorf("the directory's own repo file: %v, %v", right, err)
	}
	if _, err := view.RepoAdminRight(network.VaultId, network.MemberDevice, network.Pin().GetVersion()+1); !errors.Is(err, ErrDirectoryAuthAhead) {
		t.Errorf("a position ahead: %v", err)
	}
}

// A position older than the log retains, past 30 days and 10 folds, is answered from the head's positions: the
// creator's add, a consented device's consent and revocation positions; a pin there is no longer judged by its state.
func TestDirectoryAuthOldPositionAnsweredFromTheHead(t *testing.T) {
	network := NewDirectoryAuthTestNetwork(t)
	oldPin := network.PinAt(network.ConfirmedAt)
	network.FoldPastRetention(t)
	view := network.View()
	if _, err := view.SignerStanding(network.MemberDevice, oldPin); !errors.Is(err, ErrDirectoryAuthNotRetained) {
		t.Fatalf("the old pin is still judged by its state: %v", err)
	}
	cases := []struct {
		name      string
		repoId    Id
		sidecarId Id
		position  uint64
		want      bool
	}{
		{name: "the general repo's creator", repoId: network.GeneralRepoId, sidecarId: network.MemberDevice, position: network.GeneralAt, want: true},
		{name: "before the general repo", repoId: network.GeneralRepoId, sidecarId: network.MemberDevice, position: network.GeneralAt - 1, want: false},
		{name: "the vault's creator", repoId: network.VaultId, sidecarId: network.MemberDevice, position: network.VaultAt, want: true},
		{name: "confirmed, before its OwnerConfirm", repoId: network.VaultId, sidecarId: network.Confirmed, position: network.BeforeConfirm, want: false},
		{name: "confirmed, at its OwnerConfirm", repoId: network.VaultId, sidecarId: network.Confirmed, position: network.ConfirmedAt, want: true},
		{name: "revoked, before its revocation", repoId: network.VaultId, sidecarId: network.Revoked, position: network.RevokedAt - 1, want: true},
		{name: "revoked, at its revocation", repoId: network.VaultId, sidecarId: network.Revoked, position: network.RevokedAt, want: false},
		{name: "an admin of nothing", repoId: network.GeneralRepoId, sidecarId: network.AdminDevice, position: network.ConfirmedAt, want: false},
	}
	for _, c := range cases {
		right, err := view.RepoAdminRight(c.repoId, c.sidecarId, c.position)
		if err != nil || right != c.want {
			t.Errorf("%s: %v, %v", c.name, right, err)
		}
	}
}

// §16.11's Requests table: a general repo's admins decide by their own right, an owner-bound repo's owner's consented
// devices and never an admin, a repo kind that takes no request has no approver, and a reach request whose action this
// build cannot parse fails closed.
func TestDirectoryAuthEligibleApprovers(t *testing.T) {
	network := NewDirectoryAuthTestNetwork(t)
	view := network.View()
	requester := network.Tagged
	general := &protocol.DirectoryRequest{Target: &protocol.RequestTarget{RepoId: network.GeneralRepoId.Bytes()}}
	approvers, err := view.EligibleApprovers(general, requester, network.Pin())
	if err != nil || !slices.Equal(approvers.SidecarIds, []Id{network.MemberDevice}) || approvers.OwnerBound || approvers.Count != 1 {
		t.Fatalf("the general repo: %+v, %v", approvers, err)
	}
	for _, c := range []struct {
		decider Id
		want    bool
	}{{network.MemberDevice, true}, {network.AdminDevice, false}, {network.OwnerDevice, false}} {
		if decides, err := view.Decides(general, requester, c.decider, network.Pin()); err != nil || decides != c.want {
			t.Errorf("decider %s of the general repo: %v, %v", c.decider, decides, err)
		}
	}
	vault := &protocol.DirectoryRequest{Target: &protocol.RequestTarget{RepoId: network.VaultId.Bytes()}}
	approvers, err = view.EligibleApprovers(vault, requester, network.Pin())
	if err != nil || !approvers.OwnerBound || !slices.Equal(approvers.MemberIds, []Id{network.MemberId}) {
		t.Fatalf("the vault: %+v, %v", approvers, err)
	}
	for _, c := range []struct {
		decider Id
		want    bool
	}{
		{network.MemberDevice, true}, {network.Confirmed, true}, {network.Unconsented, false}, {network.ReadOnly, false},
		{network.AdminDevice, false}, {network.OwnerDevice, false},
	} {
		if decides, err := view.Decides(vault, requester, c.decider, network.Pin()); err != nil || decides != c.want {
			t.Errorf("decider %s of the vault: %v, %v", c.decider, decides, err)
		}
	}
	directory := &protocol.DirectoryRequest{Target: &protocol.RequestTarget{RepoId: network.DirectoryId.Bytes()}}
	if _, err := view.EligibleApprovers(directory, requester, network.Pin()); !errors.Is(err, ErrDirectoryAuthNoApprovers) {
		t.Errorf("a request to the directory: %v", err)
	}
	unknown := &protocol.DirectoryRequest{Target: &protocol.RequestTarget{RepoId: testConfigId("no such repo").Bytes()}}
	if _, err := view.EligibleApprovers(unknown, requester, network.Pin()); !errors.Is(err, ErrDirectoryAuthNoApprovers) {
		t.Errorf("a request to an unknown repo: %v", err)
	}
	worker := &protocol.DirectoryRequest{Target: &protocol.RequestTarget{SidecarId: network.MemberDevice.Bytes()}}
	if _, err := view.EligibleApprovers(worker, requester, network.Pin()); !errors.Is(err, ErrDirectoryAuthNoApprovers) {
		t.Errorf("a reach request with no action: %v", err)
	}
	if decides, err := view.Decides(worker, requester, network.MemberDevice, network.Pin()); decides || err == nil {
		t.Errorf("a decider of an unparsed reach request: %v, %v", decides, err)
	}
}

// Whom a sidecar speaks for, and whom a removal masks: a member device's member, a tagged sidecar's sponsor until it
// leaves, and every device a revocation or its member's removal revoked, at the position it came in.
func TestDirectoryAuthMembersSponsorsAndMasks(t *testing.T) {
	network := NewDirectoryAuthTestNetwork(t)
	view := network.View()
	if memberId, ok := view.MemberOf(network.MemberDevice); !ok || memberId != network.MemberId {
		t.Errorf("a member device's member: %s %v", memberId, ok)
	}
	if _, ok := view.MemberOf(network.Tagged); ok {
		t.Error("a tagged sidecar has a member")
	}
	if _, ok := view.MemberOf(network.LeftDevice); ok {
		t.Error("a removed member is still a member")
	}
	if sponsorId, ok := view.SponsorOf(network.Tagged); !ok || sponsorId != network.MemberId {
		t.Errorf("the tagged sidecar's sponsor: %s %v", sponsorId, ok)
	}
	if _, ok := view.SponsorOf(network.Orphan); ok {
		t.Error("a sponsor who left still sponsors")
	}
	if who, ok := DirectoryWhoMember(view, network.Tagged); !ok || who != network.MemberId {
		t.Errorf("who of the tagged sidecar: %s %v", who, ok)
	}
	if _, ok := DirectoryWhoMember(view, network.Orphan); ok {
		t.Error("who of an orphan is not autogroup:admin")
	}
	for _, masked := range []Id{network.Revoked, network.LeftDevice} {
		if !view.Masked(masked) {
			t.Errorf("%s is not masked", masked)
		}
	}
	for _, shown := range []Id{network.MemberDevice, network.Tagged, network.Orphan, network.Suspended} {
		if view.Masked(shown) {
			t.Errorf("%s is masked", shown)
		}
	}
	before, err := view.At(network.PinAt(network.LeftAt - 1))
	if err != nil || before.Masked(network.LeftDevice) {
		t.Errorf("masked before the removal's position: %v", err)
	}
}

// With nothing bound every check refuses and everyone is masked.
func TestDirectoryAuthUnavailableRefuses(t *testing.T) {
	view := NewDirectoryAuthView(nil)
	sidecarId := testConfigId("anyone")
	if _, ok := view.Directory(); ok {
		t.Error("a directory")
	}
	if standing, err := view.SignerStanding(sidecarId, &bridge.AuthPin{}); standing != DirectoryStandingUnjudged || !errors.Is(err, ErrDirectoryAuthUnavailable) {
		t.Errorf("standing %s, %v", standing, err)
	}
	if right, err := view.RepoAdminRight(sidecarId, sidecarId, 1); right || err == nil {
		t.Error("a repo admin right")
	}
	if admins, err := view.DirectoryAdmins(nil); len(admins) != 0 || err == nil {
		t.Error("directory admins")
	}
	request := &protocol.DirectoryRequest{Target: &protocol.RequestTarget{RepoId: sidecarId.Bytes()}}
	if _, err := view.EligibleApprovers(request, sidecarId, nil); err == nil {
		t.Error("approvers")
	}
	if decides, err := view.Decides(request, sidecarId, sidecarId, nil); decides || err == nil {
		t.Error("a decider")
	}
	if !view.Masked(sidecarId) {
		t.Error("not masked")
	}
}
