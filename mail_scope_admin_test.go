//go:build !sidecar_http && !js && !ios_extension

package sidecar

// An AdminSet member's Team scope mail (QD-1108) and a scope's mailcfg out of the admins' reach (QD-1107), on a state
// built by §8's own statement rules: an Owner's and an Admin's device create no scope mailcfg while no network mailcfg
// stands and each its own member's once it does, read only by that member's consented devices; two config writers
// racing to the network's mailcfg leave one network mailcfg and the loser's scope's; a config writer's scope creation
// that lands after the network's was deleted is the network's and is not answered as the scope's; and an Owner's scope
// receiver plans and starts on its own mailcfg once the network's stands.

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One device's MailRepos reading the state view gives, which a test holds behind the log.
func (self *mailReposTestWorld) reposAt(sidecarId Id, view func() *AclState) *MailRepos {
	return newMailRepos(&mailReposTestEvs{world: self, sidecarId: sidecarId}, &MailReposArgs{
		State:     view,
		Gkm:       &mailReposTestGkm{world: self, sidecarId: sidecarId},
		SidecarId: sidecarId,
	})
}

// A state a test sets, read by the devices it hands out.
type mailTestStaleView struct {
	stateLock sync.Mutex
	state     *AclState
}

func (self *mailTestStaleView) set(state *AclState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = state
}

func (self *mailTestStaleView) get() *AclState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state
}

// QD-1108: an Owner's and an Admin's devices, every one of them a config writer, create no scope mailcfg while no
// network mailcfg stands, since the log would read it as the network's; once the network's stands each creates its own
// member's, owner-bound to that member with its consented devices, which the member's other device is answered and
// another member's scope never is; each is out of the other admin's reach (QD-1107), and the network's stays the
// network's.
func TestMailReposEnsureScopeMailConfigOfAnAdminSetMember(t *testing.T) {
	world := newMailReposTestWorld(t)
	ownerId, ownerDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	adminId, adminDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	adminSecond := world.fixture.device(adminId, adminDevice.Bytes())
	world.fixture.view.configWriters[adminSecond] = true
	memberId, memberDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.rebuild()
	ctx := context.Background()

	for _, c := range []struct {
		device Id
		member Id
	}{{device: ownerDevice, member: ownerId}, {device: adminDevice, member: adminId}, {device: adminSecond, member: adminId}} {
		if _, err := world.repos(c.device).EnsureScopeMailConfig(ctx, c.member); !errors.Is(err, ErrMailReposConfigWriter) {
			t.Fatalf("an AdminSet member's scope mailcfg with no network mailcfg: %v", err)
		}
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 0 {
		t.Fatal("a scope creation that would read as the network's was filed")
	}

	network, err := world.repos(ownerDevice).EnsureMailConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	adminScope, err := world.repos(adminDevice).EnsureScopeMailConfig(ctx, adminId)
	if err != nil || adminScope.RepoId() == network.RepoId() {
		t.Fatalf("the admin's scope mailcfg: %v", err)
	}
	row := world.state().Repo(adminScope.RepoId())
	if aclTestRowOwner(row) != adminId || len(row.GetConsentedSidecarIds()) != 2 {
		t.Fatalf("the admin's scope mailcfg's row: %+v", row)
	}
	ownerScope, err := world.repos(ownerDevice).EnsureScopeMailConfig(ctx, ownerId)
	if err != nil || aclTestRowOwner(world.state().Repo(ownerScope.RepoId())) != ownerId {
		t.Fatalf("the owner's scope mailcfg: %v", err)
	}
	if repo, err := world.repos(adminSecond).EnsureScopeMailConfig(ctx, adminId); err != nil || repo.RepoId() != adminScope.RepoId() {
		t.Fatalf("the admin's other device's scope mailcfg: %v", err)
	}
	if _, err := world.repos(adminDevice).EnsureScopeMailConfig(ctx, memberId); !errors.Is(err, ErrMailReposNotConsented) {
		t.Fatalf("an admin's device on a member's scope: %v", err)
	}
	if count := world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE); count != 3 {
		t.Fatalf("%d RepoCreates", count)
	}
	for _, device := range []Id{ownerDevice, adminDevice, memberDevice} {
		repos := world.repos(device)
		if found, ok := repos.MailConfigRepo(); !ok || found != network.RepoId() {
			t.Fatal("the network's mailcfg moved")
		}
		if found, ok := repos.ScopeMailConfigRepo(adminId); !ok || found != adminScope.RepoId() {
			t.Fatal("the admin's scope mailcfg is not its scope's")
		}
		if found, ok := repos.ScopeMailConfigRepo(ownerId); !ok || found != ownerScope.RepoId() {
			t.Fatal("the owner's scope mailcfg is not its scope's")
		}
	}

	state := world.state()
	for _, c := range []struct {
		name      string
		sidecarId Id
		repoId    Id
		rights    AclEvsRights
	}{
		{name: "the owner's device in the admin's scope's", sidecarId: ownerDevice, repoId: adminScope.RepoId()},
		{name: "the admin's device in the owner's scope's", sidecarId: adminDevice, repoId: ownerScope.RepoId()},
		{name: "a member's device in the admin's scope's", sidecarId: memberDevice, repoId: adminScope.RepoId()},
		{name: "the admin's other device in its scope's", sidecarId: adminSecond, repoId: adminScope.RepoId(), rights: AclEvsRead | AclEvsWrite},
		{name: "a member's device in the network's", sidecarId: memberDevice, repoId: network.RepoId(), rights: AclEvsRead | AclEvsWrite},
	} {
		for _, audience := range []AclTokenAudience{AclTokenAudienceEvs, AclTokenAudienceGkm} {
			if rights := state.EvsAccess(AclSidecarSubject(c.sidecarId), c.repoId, audience, aclTestNow).Rights; rights != c.rights {
				t.Errorf("%s at audience %d: %b, want %b", c.name, audience, rights, c.rights)
			}
		}
	}
	reader := protocol.RepoGrantRole_REPO_GRANT_ROLE_READER
	if err := world.file(ownerDevice, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{RepoId: adminScope.RepoId().Bytes(), Subject: ownerDevice.Bytes(), Role: reader}); !errors.Is(err, ErrConfigRule) {
		t.Errorf("the owner's RepoGrant on the admin's scope mailcfg: %v", err)
	}
	add := protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD
	if err := world.file(ownerDevice, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{RepoId: adminScope.RepoId().Bytes(), SidecarId: ownerDevice.Bytes(), Change: add}); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("the owner's RepoAdmin add on the admin's scope mailcfg: %v", err)
	}
	if err := world.file(ownerDevice, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{RepoId: adminScope.RepoId().Bytes(), DeletionId: NewId().Bytes()}); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("the owner's RepoDelete of the admin's scope mailcfg: %v", err)
	}
}

// QD-1108: two config writers decide on the same state, with no network mailcfg, and both file the network's; the
// first to land is the network's and the other its member's scope's own, harmless: every device then answers the one
// network mailcfg, and the loser's scope setup takes up the mailcfg its race left, filing nothing more.
func TestMailReposTwoConfigWritersRacingLeaveOneNetworkMailcfg(t *testing.T) {
	world := newMailReposTestWorld(t)
	ownerId, ownerDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	adminId, adminDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	world.rebuild()
	ctx := context.Background()
	view := &mailTestStaleView{state: world.state()}
	ownerRepos, adminRepos := world.reposAt(ownerDevice, view.get), world.reposAt(adminDevice, view.get)

	first, err := ownerRepos.EnsureMailConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := adminRepos.EnsureMailConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.RepoId() == second.RepoId() {
		t.Fatal("the race made one repo")
	}
	if row := world.state().Repo(first.RepoId()); aclTestRowOwner(row) != (Id{}) {
		t.Fatalf("the first to land: %+v", row)
	}
	if row := world.state().Repo(second.RepoId()); aclTestRowOwner(row) != adminId {
		t.Fatalf("the second to land: %+v", row)
	}

	view.set(world.state())
	for name, repos := range map[string]*MailRepos{"the owner's device": ownerRepos, "the admin's device": adminRepos} {
		repo, err := repos.EnsureMailConfig(ctx)
		if err != nil || repo.RepoId() != first.RepoId() {
			t.Errorf("%s's network mailcfg after the race: %v", name, err)
		}
		if found, ok := repos.MailConfigRepo(); !ok || found != first.RepoId() {
			t.Errorf("%s reads another network mailcfg", name)
		}
	}
	if found, ok := adminRepos.ScopeMailConfigRepo(adminId); !ok || found != second.RepoId() {
		t.Fatal("the race's loser is not the admin's scope mailcfg")
	}
	if _, ok := ownerRepos.ScopeMailConfigRepo(ownerId); ok {
		t.Fatal("the owner holds a scope mailcfg it never made")
	}
	scope, err := adminRepos.EnsureScopeMailConfig(ctx, adminId)
	if err != nil || scope.RepoId() != second.RepoId() {
		t.Fatalf("the admin's scope setup after the race: %v", err)
	}
	if count := world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE); count != 2 {
		t.Fatalf("%d RepoCreates", count)
	}
}

// QD-1108's other order: an Admin's device files its scope's mailcfg with the network's standing, which is deleted
// before the RepoCreate lands, so it lands as the network's: the device is answered no scope mailcfg, never that repo,
// every device reads it as the network's, and with it standing the device's next creation is its scope's own.
func TestMailReposConfigWritersScopeMailcfgThatLandedAsTheNetworks(t *testing.T) {
	world := newMailReposTestWorld(t)
	_, ownerDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	adminId, adminDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	world.rebuild()
	ctx := context.Background()
	network, err := world.repos(ownerDevice).EnsureMailConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	view := &mailTestStaleView{state: world.state()}
	adminRepos := world.reposAt(adminDevice, view.get)
	deletion := &protocol.RepoDelete{RepoId: network.RepoId().Bytes(), DeletionId: NewId().Bytes(), Now: true}
	if err := world.file(ownerDevice, bridge.SignedType_SIGNED_REPO_DELETE, deletion); err != nil {
		t.Fatal(err)
	}

	landed, err := adminRepos.EnsureScopeMailConfig(ctx, adminId)
	if err != nil {
		t.Fatal(err)
	}
	if row := world.state().Repo(landed.RepoId()); aclTestRowOwner(row) != (Id{}) {
		t.Fatalf("a config writer's mailcfg with none standing folded owned: %+v", row)
	}
	view.set(world.state())
	if _, err := adminRepos.EnsureScopeMailConfig(ctx, adminId); !errors.Is(err, ErrMailReposAbsent) {
		t.Fatalf("a scope creation that landed as the network's: %v", err)
	}
	if _, ok := adminRepos.ScopeMailConfigRepo(adminId); ok {
		t.Fatal("the network's mailcfg was read as the admin's scope's")
	}
	if found, ok := world.repos(ownerDevice).MailConfigRepo(); !ok || found != landed.RepoId() {
		t.Fatal("the landed mailcfg is not the network's")
	}
	scope, err := adminRepos.EnsureScopeMailConfig(ctx, adminId)
	if err != nil || scope.RepoId() == landed.RepoId() || aclTestRowOwner(world.state().Repo(scope.RepoId())) != adminId {
		t.Fatalf("the admin's scope mailcfg beside the new network's: %v", err)
	}
}

// QD-1108's receiver: an Owner's scope plans no receiver and files nothing while no network mailcfg stands; once the
// network's stands its device's setup creates the scope's own mailcfg, the receiver is planned with it and starts on
// smtp/25/mx.<scope>, publishing its key under mx.<scope>, and an Admin's device sets up its own scope beside it. Each
// scope's mailcfg is out of the other admin's reach (QD-1107).
func TestMailScopeReceiverStartsForAnAdminSetMembersScope(t *testing.T) {
	net := newTestConfigNet(t)
	net.setTeamMail(protocol.TeamMailMode_TEAM_MAIL_MODE_MEMBER_SCOPES)
	memberScopes := net.log.State()

	world := newMailReposTestWorld(t)
	fixture := world.fixture
	owner, ownerDevice := fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	admin, adminDevice := fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	for _, device := range []Id{ownerDevice, adminDevice} {
		fixture.rule([]Id{fixture.sidecarAtom(device)}, []*protocol.AclTarget{
			{PublicName: "smtp/25/mx.adm"}, {PublicName: "smtp/25/mx.ops"},
		}, protocol.AclAction_ACL_ACTION_LISTEN)
	}
	world.rebuild()
	scopes := []AclScope{{Label: "adm", MemberId: owner}, {Label: "ops", MemberId: admin}}
	now := aclTestNow
	ctx := context.Background()

	plans, err := world.repos(ownerDevice).EnsureScopeReceivers(ctx, memberScopes, scopes, now)
	if !errors.Is(err, ErrMailReposConfigWriter) || len(plans) != 0 || world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 0 {
		t.Fatalf("an Owner's scope with no network mailcfg: %+v, %v", plans, err)
	}

	network, err := world.repos(ownerDevice).EnsureMailConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plans, err = world.repos(ownerDevice).EnsureScopeReceivers(ctx, memberScopes, scopes, now)
	if err != nil || len(plans) != 1 {
		t.Fatalf("the Owner's device's setup: %+v, %v", plans, err)
	}
	plan := plans[0]
	scopeConfigId, found := world.repos(ownerDevice).ScopeMailConfigRepo(owner)
	if !found || scopeConfigId == network.RepoId() || plan.MailConfigRepoId != scopeConfigId || plan.Host != "mx.adm" || plan.ListenName() != "smtp/25/mx.adm" {
		t.Fatalf("the plan %+v, the scope's mailcfg %s %t", plan, scopeConfigId, found)
	}
	if row := world.state().Repo(scopeConfigId); aclTestRowOwner(row) != owner {
		t.Fatalf("the Owner's scope mailcfg's row: %+v", row)
	}
	adminPlans, err := world.repos(adminDevice).EnsureScopeReceivers(ctx, memberScopes, scopes, now)
	if err != nil || len(adminPlans) != 1 || adminPlans[0].Host != "mx.ops" || adminPlans[0].MailConfigRepoId == scopeConfigId ||
		adminPlans[0].MailConfigRepoId == network.RepoId() {
		t.Fatalf("the Admin's device's setup: %+v, %v", adminPlans, err)
	}
	if again, err := world.repos(ownerDevice).EnsureScopeReceivers(ctx, memberScopes, scopes, now); err != nil || len(again) != 1 || again[0] != plan {
		t.Fatalf("a second setup: %+v, %v", again, err)
	}
	if count := world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE); count != 3 {
		t.Fatalf("%d RepoCreates", count)
	}

	receiverWorld := newMailReceiverTestWorld(t, nil)
	listened := make(chan string, 4)
	receiverWorld.newReceiver(func(args *MailReceiverArgs) {
		args.Host = plan.Host
		args.Listen = func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error) {
			listened <- address
			return receiverWorld.listener, nil
		}
	})
	receiverWorld.startServing()
	if address := <-listened; address != plan.ListenName() {
		t.Fatalf("the Owner's scope receiver listens on %q", address)
	}
	if publishes := receiverWorld.publisher.publishes(); len(publishes) != 1 || publishes[0].host != "mx.adm" {
		t.Fatalf("the Owner's scope receiver's key records: %+v", publishes)
	}
	if status := receiverWorld.receiver.Status(); !status.Listening || !status.Serving {
		t.Fatalf("the Owner's scope receiver's status %+v", status)
	}

	state := world.state()
	for _, audience := range []AclTokenAudience{AclTokenAudienceEvs, AclTokenAudienceGkm} {
		if rights := state.EvsAccess(AclSidecarSubject(adminDevice), scopeConfigId, audience, now).Rights; rights != 0 {
			t.Errorf("the Admin's device holds %b on the Owner's scope mailcfg at audience %d", rights, audience)
		}
		if rights := state.EvsAccess(AclSidecarSubject(ownerDevice), adminPlans[0].MailConfigRepoId, audience, now).Rights; rights != 0 {
			t.Errorf("the Owner's device holds %b on the Admin's scope mailcfg at audience %d", rights, audience)
		}
	}
	if readers := state.RepoReaders(scopeConfigId, now); !slices.Equal(readers, []Id{ownerDevice}) {
		t.Errorf("the Owner's scope mailcfg's readers %v", readers)
	}
	if plans := MailScopeReceiverPlans(memberScopes, state, scopes, adminDevice, now); len(plans) != 1 || plans[0].Host != "mx.ops" {
		t.Errorf("the Admin's device plans %+v", plans)
	}
}
