// MAIL-M7-05's tests: mail's repos on a state built by §8's own statement rules, so each RepoCreate, RepoAdmin and
// RepoGrant MailRepos files is one the access log takes, or refuses, as a network's would.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network's access log as MailRepos meets it: a state every filed statement is checked against and folded into
// by AclState's own rules, a stand-in for evs's repo creation that files the RepoCreate as its caller, and which
// device holds which repo's key.
type mailReposTestWorld struct {
	t       *testing.T
	fixture *aclTestFixture
	handles *EvsClient

	stateLock sync.Mutex
	current   *AclState
	// every creation asked of evs, and every statement the log took, in order
	creations []*EvsCreateRepoArgs
	filed     []bridge.SignedType
	// answered once by the next creation after its RepoCreate landed, as a crash before keying leaves it
	failCreation error
	// answered once by the next RepoGrant or RepoAdmin, nothing filed
	failStatement error
	keyedRepoIds  map[Id]map[Id]bool
}

func newMailReposTestWorld(t *testing.T) *mailReposTestWorld {
	t.Helper()
	world := &mailReposTestWorld{
		t:            t,
		fixture:      newAclTestFixture(),
		handles:      newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t)).client,
		keyedRepoIds: map[Id]map[Id]bool{},
	}
	return world
}

// Rebuilds the state from the fixture's rows and view, after a test changed either.
func (self *mailReposTestWorld) rebuild() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.current = self.fixture.state(self.t)
}

func (self *mailReposTestWorld) state() *AclState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

// Files one statement as signer: checked at the state and folded into it, or refused as the log would.
func (self *mailReposTestWorld) file(signer Id, signedType bridge.SignedType, body proto.Message) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.failStatement; err != nil && signedType != bridge.SignedType_SIGNED_REPO_CREATE {
		self.failStatement = nil
		return err
	}
	statement := self.fixture.statement(signedType, body, signer)
	verdict, err := self.current.CheckStatement(statement, nil)
	if err != nil {
		return err
	}
	rows, _, err := self.current.ApplyStatement(statement, verdict)
	if err != nil {
		return err
	}
	self.fixture.rows = rows
	self.current = self.fixture.state(self.t)
	self.filed = append(self.filed, signedType)
	return nil
}

// How many statements of a type the log took.
func (self *mailReposTestWorld) filedCount(signedType bridge.SignedType) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, filed := range self.filed {
		if filed == signedType {
			count += 1
		}
	}
	return count
}

func (self *mailReposTestWorld) setKeyed(sidecarId Id, repoId Id, keyed bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.keyedRepoIds[sidecarId] == nil {
		self.keyedRepoIds[sidecarId] = map[Id]bool{}
	}
	self.keyedRepoIds[sidecarId][repoId] = keyed
}

// evs's creation as one device sees it: the RepoCreate filed as that device, then the repo keyed for it.
type mailReposTestEvs struct {
	world     *mailReposTestWorld
	sidecarId Id
}

func (self *mailReposTestEvs) CreateRepo(ctx context.Context, args *EvsCreateRepoArgs) (*EvsRepo, error) {
	func() {
		self.world.stateLock.Lock()
		defer self.world.stateLock.Unlock()
		copied := *args
		self.world.creations = append(self.world.creations, &copied)
	}()
	repoId := NewEvsRepoId()
	if args.ResumeRepoId != nil {
		repoId = *args.ResumeRepoId
	} else if err := self.world.file(self.sidecarId, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: args.Kind}); err != nil {
		return nil, err
	}
	failure := func() error {
		self.world.stateLock.Lock()
		defer self.world.stateLock.Unlock()
		failure := self.world.failCreation
		self.world.failCreation = nil
		return failure
	}()
	if failure != nil {
		return self.world.handles.Repo(repoId), failure
	}
	self.world.setKeyed(self.sidecarId, repoId, true)
	return self.world.handles.Repo(repoId), nil
}

func (self *mailReposTestEvs) Repo(repoId Id) *EvsRepo {
	return self.world.handles.Repo(repoId)
}

// gkm as one device sees it: the newest key of each repo the world says it holds.
type mailReposTestGkm struct {
	gkmRefusingClient
	world     *mailReposTestWorld
	sidecarId Id
}

func (self *mailReposTestGkm) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	if !self.world.keyedRepoIds[self.sidecarId][repoId] {
		return nil, ErrGkmKeyMissing
	}
	return evsTestRepoKey(repoId, 1), nil
}

// One device's MailRepos.
func (self *mailReposTestWorld) repos(sidecarId Id) *MailRepos {
	return newMailRepos(&mailReposTestEvs{world: self, sidecarId: sidecarId}, &MailReposArgs{
		State: self.state,
		FileStatement: func(ctx context.Context, signedType bridge.SignedType, body proto.Message) error {
			return self.file(sidecarId, signedType, body)
		},
		Gkm:       &mailReposTestGkm{world: self, sidecarId: sidecarId},
		SidecarId: sidecarId,
	})
}

// A member's mailbox is created once, by a consented device of that member that may write; every other device is
// answered the one that stands; a creation cut short after its RepoCreate is taken up again under its id; and of two
// mailboxes two devices raced to create, every device takes the first in log order.
func TestMailReposEnsureMailboxKeepsOnePerMember(t *testing.T) {
	world := newMailReposTestWorld(t)
	ownerId := world.fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	otherId := world.fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	// the owner's first device by its invite, the others admitted by that device (§8.5)
	phone := world.fixture.invitedDevice(ownerId)
	desktop := world.fixture.device(ownerId, phone.Bytes())
	worker := world.fixture.device(ownerId, phone.Bytes())
	world.fixture.admission(worker).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	otherPhone := world.fixture.invitedDevice(otherId)
	ctx := context.Background()

	if _, err := world.repos(phone).EnsureMailbox(ctx, ownerId); !errors.Is(err, ErrMailReposNoState) {
		t.Fatalf("with no verified state: %v", err)
	}
	world.rebuild()
	if _, found := world.repos(phone).Mailbox(ownerId); found {
		t.Fatal("a mailbox before any was created")
	}
	// another member's device and a read_only one create nothing
	for _, sidecarId := range []Id{otherPhone, worker} {
		if _, err := world.repos(sidecarId).EnsureMailbox(ctx, ownerId); !errors.Is(err, ErrMailReposNotConsented) {
			t.Fatalf("a device that may not create the mailbox: %v", err)
		}
	}
	if _, err := world.repos(phone).EnsureMailbox(ctx, Id{}); !errors.Is(err, ErrMailReposInvalid) {
		t.Fatalf("no member: %v", err)
	}
	if len(world.creations) != 0 {
		t.Fatal("a refused creation reached evs")
	}

	// a creation cut short after its RepoCreate landed is finished under the same id, not filed again
	world.failCreation = errors.New("the process stopped before the repo was keyed")
	phoneRepos := world.repos(phone)
	if _, err := phoneRepos.EnsureMailbox(ctx, ownerId); err == nil {
		t.Fatal("a creation cut short answered a repo")
	}
	repo, err := phoneRepos.EnsureMailbox(ctx, ownerId)
	if err != nil {
		t.Fatal(err)
	}
	mailboxId := repo.RepoId()
	if len(world.creations) != 2 || world.creations[0].Kind != protocol.RepoKind_REPO_KIND_MAILBOX || *world.creations[0].OwnerMemberId != ownerId ||
		world.creations[0].ResumeRepoId != nil || world.creations[1].ResumeRepoId == nil || *world.creations[1].ResumeRepoId != mailboxId ||
		world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 1 {
		t.Fatalf("creations %+v", world.creations)
	}
	// the same after a restart, where only the state remembers the creation
	world.setKeyed(phone, mailboxId, false)
	if repo, err := world.repos(phone).EnsureMailbox(ctx, ownerId); err != nil || repo.RepoId() != mailboxId || len(world.creations) != 3 ||
		*world.creations[2].ResumeRepoId != mailboxId || world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 1 {
		t.Fatalf("a restart's resume: %v", err)
	}
	row := world.state().Repo(mailboxId)
	if row == nil || row.GetKind() != protocol.RepoKind_REPO_KIND_MAILBOX || !slices.Equal(row.GetOwnerMemberId(), ownerId.Bytes()) {
		t.Fatalf("the mailbox's row: %+v", row)
	}

	// every device is answered that one mailbox, and nothing more is created
	for _, sidecarId := range []Id{phone, desktop, worker, otherPhone} {
		repo, err := world.repos(sidecarId).EnsureMailbox(ctx, ownerId)
		if err != nil || repo.RepoId() != mailboxId {
			t.Fatalf("the mailbox as another device finds it: %v", err)
		}
		if found, ok := world.repos(sidecarId).Mailbox(ownerId); !ok || found != mailboxId {
			t.Fatal("Mailbox does not name it")
		}
	}
	if len(world.creations) != 3 {
		t.Fatalf("%d creations", len(world.creations))
	}
	if _, found := world.repos(phone).Mailbox(otherId); found {
		t.Fatal("another member's mailbox")
	}

	// the desktop raced a second one into the log: both devices still take the first
	if err := world.file(desktop, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: NewEvsRepoId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX}); err != nil {
		t.Fatal(err)
	}
	for _, sidecarId := range []Id{phone, desktop} {
		if found, ok := world.repos(sidecarId).Mailbox(ownerId); !ok || found != mailboxId {
			t.Fatal("two mailboxes of one member are not read alike")
		}
	}
}

// Each consented device of the owner that is not read_only files RepoAdmin{add} for itself once it holds the
// mailbox's key, so it erases after the creating device is gone (§15.7); a device not yet seated, a read_only
// Worker, a parked device, a tagged sidecar and another member's device file nothing.
func TestMailReposEachOwnerDeviceFilesItsOwnRepoAdmin(t *testing.T) {
	world := newMailReposTestWorld(t)
	ownerId := world.fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	otherId := world.fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	phone := world.fixture.invitedDevice(ownerId)
	desktop := world.fixture.device(ownerId, phone.Bytes())
	worker := world.fixture.device(ownerId, phone.Bytes())
	world.fixture.admission(worker).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	// a device an admin admitted under the owner, parked until an OwnerConfirm
	parked := world.fixture.device(ownerId, NewId().Bytes())
	world.fixture.view.parked[parked] = true
	agent := world.fixture.agent(ownerId)
	otherPhone := world.fixture.invitedDevice(otherId)
	world.rebuild()
	ctx := context.Background()

	repo, err := world.repos(phone).EnsureMailbox(ctx, ownerId)
	if err != nil {
		t.Fatal(err)
	}
	mailboxId := repo.RepoId()
	// the creating device is its admin already
	if filed, err := world.repos(phone).EnsureRepoAdmin(ctx, mailboxId); err != nil || filed {
		t.Fatalf("the creating device: %t, %v", filed, err)
	}
	// an unseated device waits
	desktopRepos := world.repos(desktop)
	if filed, err := desktopRepos.EnsureRepoAdmin(ctx, mailboxId); err != nil || filed {
		t.Fatalf("an unseated device: %t, %v", filed, err)
	}
	for _, sidecarId := range []Id{desktop, worker, parked, agent, otherPhone} {
		world.setKeyed(sidecarId, mailboxId, true)
	}
	for _, sidecarId := range []Id{worker, parked, agent, otherPhone} {
		if filed, err := world.repos(sidecarId).EnsureRepoAdmin(ctx, mailboxId); err != nil || filed {
			t.Fatalf("a device that never administers the mailbox: %t, %v", filed, err)
		}
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_ADMIN) != 0 {
		t.Fatal("a RepoAdmin was filed for a device that files none")
	}
	// a statement the log refuses is not remembered as filed
	world.failStatement = errors.New("the log is away")
	if filed, err := desktopRepos.EnsureRepoAdmin(ctx, mailboxId); err == nil || filed {
		t.Fatalf("a refused filing: %t, %v", filed, err)
	}
	if filed, err := desktopRepos.EnsureRepoAdmin(ctx, mailboxId); err != nil || !filed {
		t.Fatalf("the second device, seated: %t, %v", filed, err)
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_ADMIN) != 1 {
		t.Fatalf("%d RepoAdmins", world.filedCount(bridge.SignedType_SIGNED_REPO_ADMIN))
	}
	// once more, on the same process and on a new one that reads the state: nothing
	for _, repos := range []*MailRepos{desktopRepos, world.repos(desktop)} {
		if filed, err := repos.EnsureRepoAdmin(ctx, mailboxId); err != nil || filed {
			t.Fatalf("a second filing: %t, %v", filed, err)
		}
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_ADMIN) != 1 {
		t.Fatal("a RepoAdmin was filed twice")
	}

	// the creating device is revoked: the second still administers the mailbox, so it erases
	world.fixture.admission(phone).Row.RevokedAt = world.fixture.next()
	world.rebuild()
	state := world.state()
	if !state.RepoAdminAt(mailboxId, desktop, world.fixture.position) {
		t.Fatal("the second device is no admin of the mailbox")
	}
	if access := state.EvsAccess(AclSidecarSubject(desktop), mailboxId, AclTokenAudienceEvs, aclTestNow); !access.Rights.Has(AclEvsAdmin) {
		t.Fatalf("the second device's rights after the first is gone: %v (%s)", access.Rights, access.Reason)
	}
	if access := state.EvsAccess(AclSidecarSubject(phone), mailboxId, AclTokenAudienceEvs, aclTestNow); access.Rights.Has(AclEvsAdmin) {
		t.Fatal("a revoked device still administers the mailbox")
	}

	// a repo that is no mailbox takes none, and one the state does not hold is absent
	if err := world.file(desktop, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: evsTestId("a general repo").Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}); err != nil {
		t.Fatal(err)
	}
	if filed, err := world.repos(desktop).EnsureRepoAdmin(ctx, evsTestId("a general repo")); err != nil || filed {
		t.Fatalf("a general repo: %t, %v", filed, err)
	}
	if _, err := world.repos(desktop).EnsureRepoAdmin(ctx, evsTestId("no repo")); !errors.Is(err, ErrMailReposAbsent) {
		t.Fatalf("a repo the state does not hold: %v", err)
	}
}

// The network's mailcfg is created once, by a config writer: the log refuses any other device's RepoCreate, and a
// refused creation is not remembered.
func TestMailReposEnsureMailConfig(t *testing.T) {
	world := newMailReposTestWorld(t)
	ownerId, ownerDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	_, memberDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.rebuild()
	ctx := context.Background()
	if _, found := world.repos(ownerDevice).MailConfigRepo(); found {
		t.Fatal("a mailcfg before any was created")
	}
	memberRepos := world.repos(memberDevice)
	if _, err := memberRepos.EnsureMailConfig(ctx); err == nil {
		t.Fatal("a mailcfg created by a device that writes no config")
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 0 {
		t.Fatal("the log took a member device's mailcfg")
	}
	repo, err := world.repos(ownerDevice).EnsureMailConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mailConfigId := repo.RepoId()
	if row := world.state().Repo(mailConfigId); row == nil || row.GetKind() != protocol.RepoKind_REPO_KIND_MAILCFG || len(row.GetOwnerMemberId()) != 0 {
		t.Fatalf("the mailcfg's row: %+v", row)
	}
	for _, repos := range []*MailRepos{memberRepos, world.repos(ownerDevice), world.repos(memberDevice)} {
		repo, err := repos.EnsureMailConfig(ctx)
		if err != nil || repo.RepoId() != mailConfigId {
			t.Fatalf("the mailcfg as another call finds it: %v", err)
		}
		if found, ok := repos.MailConfigRepo(); !ok || found != mailConfigId {
			t.Fatal("MailConfigRepo does not name it")
		}
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 1 {
		t.Fatalf("%d RepoCreates", world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE))
	}
	// a mailbox is no mailcfg
	if _, err := world.repos(ownerDevice).EnsureMailbox(ctx, ownerId); err != nil {
		t.Fatal(err)
	}
	if found, ok := world.repos(ownerDevice).MailConfigRepo(); !ok || found != mailConfigId {
		t.Fatal("a mailbox was read as the mailcfg")
	}
}

// group-add writes the member into the group's mailcfg record and files the RepoGrant, together: the record first,
// the grant after, each once; a call cut short between them is finished by the same call again; past
// mail_group_members nothing is filed; a RepoGrant alone joins no group; and a group inbox is not created until
// RepoCreate carries its marker.
func TestMailReposGroupAddWritesTheRecordAndTheGrantTogether(t *testing.T) {
	world := newMailReposTestWorld(t)
	_, adminDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	_, memberDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.rebuild()
	ctx := context.Background()
	groupId := evsTestId("the group's repo")
	if err := world.file(adminDevice, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: groupId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}); err != nil {
		t.Fatal(err)
	}

	// the group's mailcfg, where the repo's admin may change the group's record
	mailcfg := newMailConfigTestRepo()
	authority := newMailConfigTestAuthority()
	authority.grant(adminDevice, "*")
	authority.grant(memberDevice, "*")
	authority.own(groupId, adminDevice)
	admin := newMailConfigTestDevice(t, mailcfg, authority, adminDevice, nil)
	member := newMailConfigTestDevice(t, mailcfg, authority, memberDevice, nil)
	adminRepos := world.repos(adminDevice)

	// a group inbox needs RepoCreate's marker
	creations := len(world.creations)
	if _, err := adminRepos.CreateGroup(ctx, admin.config, &MailCreateGroupArgs{LocalPart: "team"}); !errors.Is(err, ErrMailGroupInboxNotBuilt) {
		t.Fatalf("a group creation: %v", err)
	}
	if _, err := adminRepos.CreateGroup(ctx, admin.config, &MailCreateGroupArgs{LocalPart: "postmaster"}); !errors.Is(err, ErrMailLocalPartReserved) {
		t.Fatalf("a group at a reserved name: %v", err)
	}
	if len(world.creations) != creations || len(mailcfg.standingPaths()) != 0 {
		t.Fatal("a refused group creation made something")
	}

	if _, err := admin.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "team", Kind: protocol.MailAddressKind_MAIL_ADDRESS_GROUP, MailboxRepoId: groupId}); err != nil {
		t.Fatal(err)
	}
	path := testMailConfigAddressPath(t, "team@acme.root.example")
	grants := func() []*protocol.AclRepoGrantRow { return world.state().Repo(groupId).GetGrants() }
	first := evsTestId("group member 1")

	// the grant's filing fails after the record landed: the same call again files it and writes no second version
	world.failStatement = errors.New("the log is away")
	if err := adminRepos.AddGroupMember(ctx, admin.config, "team", first); err == nil {
		t.Fatal("a group-add whose grant failed answered done")
	}
	if held, _, err := admin.config.GroupMembers(ctx, "team"); err != nil || !slices.Equal(held, []Id{first}) || len(grants()) != 0 {
		t.Fatalf("after the cut: members %v, %v", held, err)
	}
	versions := mailcfg.versionCount(path)
	if err := adminRepos.AddGroupMember(ctx, admin.config, "team", first); err != nil {
		t.Fatal(err)
	}
	if mailcfg.versionCount(path) != versions || len(grants()) != 1 || !slices.Equal(grants()[0].GetSubject(), first.Bytes()) ||
		grants()[0].GetRole() != protocol.RepoGrantRole_REPO_GRANT_ROLE_READER || grants()[0].GetExpires() != 0 {
		t.Fatalf("the finished group-add: %+v", grants())
	}
	// a member already in changes nothing
	if err := adminRepos.AddGroupMember(ctx, admin.config, "team", first); err != nil || mailcfg.versionCount(path) != versions || len(grants()) != 1 {
		t.Fatalf("a member added twice: %v", err)
	}

	// up to mail_group_members, and no further
	for index := 2; index <= admin.config.settings.GroupMemberMaxCount; index += 1 {
		if err := adminRepos.AddGroupMember(ctx, admin.config, "team", NewId()); err != nil {
			t.Fatalf("member %d: %v", index, err)
		}
	}
	versions = mailcfg.versionCount(path)
	if err := adminRepos.AddGroupMember(ctx, admin.config, "team", NewId()); !errors.Is(err, ErrMailConfigGroupFull) {
		t.Fatalf("a member past the bound: %v", err)
	}
	held, mailboxRepoId, err := admin.config.GroupMembers(ctx, "team")
	if err != nil || len(held) != 100 || mailboxRepoId != groupId || mailcfg.versionCount(path) != versions || len(grants()) != 100 {
		t.Fatalf("at the bound: %d members, %d grants, %v", len(held), len(grants()), err)
	}

	// a device that may not change the group's record adds nobody, and files no grant
	if err := world.repos(memberDevice).AddGroupMember(ctx, member.config, "team", NewId()); !errors.Is(err, ErrMailConfigNotOwner) || len(grants()) != 100 {
		t.Fatalf("another member's group-add: %v", err)
	}
	// a RepoGrant alone joins no group: the group's members are its record's
	outsider := evsTestId("granted with no record")
	if err := world.file(adminDevice, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{RepoId: groupId.Bytes(), Subject: outsider.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}); err != nil {
		t.Fatal(err)
	}
	member.sync(t)
	if lookup := member.resolve(t, "team@acme.root.example"); !lookup.Known || len(lookup.MemberIds) != 100 || slices.Contains(lookup.MemberIds, outsider) {
		t.Fatalf("the group after a RepoGrant alone: %d members", len(lookup.MemberIds))
	}
	// no group, and a repo that is no group's
	if err := adminRepos.AddGroupMember(ctx, admin.config, "nobody", NewId()); !errors.Is(err, ErrMailConfigAddressAbsent) {
		t.Fatalf("a group-add to no group: %v", err)
	}
	if err := adminRepos.AddGroupMember(ctx, admin.config, "team", Id{}); !errors.Is(err, ErrMailReposInvalid) {
		t.Fatalf("a group-add of no member: %v", err)
	}
}

// The network mail key's repo is the mailbox the admin@ record names: absent until that record stands.
func TestMailReposNetworkMailKeyRepo(t *testing.T) {
	world := newMailReposTestWorld(t)
	_, ownerDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.rebuild()
	ctx := context.Background()
	mailcfg := newMailConfigTestRepo()
	authority := newMailConfigTestAuthority()
	authority.grant(ownerDevice, "*")
	owner := newMailConfigTestDevice(t, mailcfg, authority, ownerDevice, nil)
	repos := world.repos(ownerDevice)
	if _, err := repos.NetworkMailKeyRepo(ctx, owner.config); !errors.Is(err, ErrMailReposAbsent) {
		t.Fatalf("before the admin record: %v", err)
	}
	if _, err := repos.NetworkMailKeyRepo(ctx, nil); !errors.Is(err, ErrMailReposInvalid) {
		t.Fatalf("with no mailcfg: %v", err)
	}
	if _, err := owner.config.CreateAddress(ctx, &MailCreateAddressArgs{Kind: protocol.MailAddressKind_MAIL_ADDRESS_ADMIN, MailboxRepoId: testMailConfigMailboxId}); err != nil {
		t.Fatal(err)
	}
	if repoId, err := repos.NetworkMailKeyRepo(ctx, owner.config); err != nil || repoId != testMailConfigMailboxId {
		t.Fatalf("the network mail key's repo: %s, %v", repoId, err)
	}
	// policy withdraws the creator's grant: the record routes nothing, and names no key
	authority.grant(ownerDevice)
	if _, err := repos.NetworkMailKeyRepo(ctx, owner.config); !errors.Is(err, ErrMailReposAbsent) {
		t.Fatalf("once the admin record is not honored: %v", err)
	}
}
