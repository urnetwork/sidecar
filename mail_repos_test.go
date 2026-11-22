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
	if !AclRepoKindOwnerFits(args.Kind, args.OwnerMemberId != nil) {
		return nil, errInvalidSettings
	}
	repoId := NewEvsRepoId()
	if args.proposedRepoId != nil {
		repoId = *args.proposedRepoId
	}
	if args.ResumeRepoId != nil {
		repoId = *args.ResumeRepoId
	} else if err := self.world.file(self.sidecarId, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: args.Kind, Inbox: args.inboxRole()}); err != nil {
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

// The network's mailcfg is created once, by a config writer: any other device files no RepoCreate for it, since the log
// would take one as its member's scope's own (QD-1093), and a refused creation is not remembered.
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
	if _, err := memberRepos.EnsureMailConfig(ctx); !errors.Is(err, ErrMailReposConfigWriter) {
		t.Fatalf("a mailcfg created by a device that writes no config: %v", err)
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

// A restarted group creation resumes the same signed repo, keeps its original private choice, and grants
// only deposits to the Team's current mail tag. The first call stops after RepoCreate and before keying.
func TestMailGroupCreateResumesItsApprovedPrivateInbox(t *testing.T) {
	world := newMailReposTestWorld(t)
	member, device := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tag := world.fixture.tag(member)
	indexer := world.fixture.agent(member, tag)
	world.fixture.repo(protocol.RepoKind_REPO_KIND_TEAM_RECORD, Id{})
	world.rebuild()
	mailcfg := newMailConfigTestRepo()
	authority := newMailConfigTestAuthority()
	authority.grant(device, "*")
	config := newMailConfigTestDevice(t, mailcfg, authority, device, nil).config
	resume := func() *MailRepos {
		repos := world.repos(device)
		repos.mailIndexerTag = func(*AclState) (Id, bool) { return tag, true }
		return repos
	}
	args := &MailCreateGroupArgs{LocalPart: "team", DisplayName: "Support", Confirmed: true, Private: true}
	withoutTag := world.repos(device)
	if _, err := withoutTag.CreateGroup(t.Context(), config, args); !errors.Is(err, ErrMailGroupIndexerTag) || len(mailcfg.standingPaths()) != 0 {
		t.Fatalf("unavailable Team tag: %v", err)
	}
	cut := errors.New("keying interrupted")
	world.failCreation = cut
	if _, err := resume().CreateGroup(t.Context(), config, args); !errors.Is(err, cut) {
		t.Fatalf("interrupted creation: %v", err)
	}
	retry := &MailCreateGroupArgs{LocalPart: "team", Confirmed: true}
	repo, err := resume().CreateGroup(t.Context(), config, retry)
	if err != nil {
		t.Fatal(err)
	}
	id := repo.RepoId()
	if again, err := resume().CreateGroup(t.Context(), config, retry); err != nil || again.RepoId() != id {
		t.Fatalf("completed replay: %v, %v", again, err)
	}
	state := world.state()
	row := state.Repo(id)
	if row.GetInbox() != protocol.RepoInbox_REPO_INBOX_GROUP || len(row.GetGrants()) != 1 ||
		aclTestRights(state, indexer, id, AclTokenAudienceEvs) != AclEvsDeposit || !mailRepoGrantStands(row, tag, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT) {
		t.Fatalf("group role and projected deposit grant: %v", row)
	}
	if len(world.creations) != 2 || world.creations[1].ResumeRepoId == nil || *world.creations[1].ResumeRepoId != id ||
		!world.creations[1].Private || world.creations[1].DisplayName != args.DisplayName || world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 1 {
		t.Fatalf("private group creation and resume: %v", world.creations)
	}
	if members, named, err := config.GroupMembers(t.Context(), args.LocalPart); err != nil || len(members) != 0 || named != id {
		t.Fatalf("signed address: %v, %v, %v", members, named, err)
	}
}

// group-add writes the member into the group's mailcfg record and files the RepoGrant, together: the record first,
// the grant after, each once; a call cut short between them is finished by the same call again; past
// mail_group_members nothing is filed; a RepoGrant alone joins no group; and only a confirmed command creates a group inbox.
func TestMailReposGroupAddWritesTheRecordAndTheGrantTogether(t *testing.T) {
	world := newMailReposTestWorld(t)
	_, adminDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	_, memberDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.rebuild()
	ctx := context.Background()
	groupId := evsTestId("the group's repo")
	if err := world.file(adminDevice, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: groupId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: protocol.RepoInbox_REPO_INBOX_GROUP}); err != nil {
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

	// Rejected confirmations and reserved names write neither a repo nor an address.
	creations := len(world.creations)
	if _, err := adminRepos.CreateGroup(ctx, admin.config, &MailCreateGroupArgs{LocalPart: "team"}); !errors.Is(err, ErrMailGroupUnconfirmed) {
		t.Fatalf("a group creation: %v", err)
	}
	if _, err := adminRepos.CreateGroup(ctx, admin.config, &MailCreateGroupArgs{LocalPart: "postmaster"}); !errors.Is(err, ErrMailLocalPartReserved) {
		t.Fatalf("a group at a reserved name: %v", err)
	}
	if len(world.creations) != creations || len(mailcfg.standingPaths()) != 0 {
		t.Fatal("a refused group creation made something")
	}

	adminId := NewId()
	if err := world.file(adminDevice, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		RepoId: adminId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: protocol.RepoInbox_REPO_INBOX_ADMIN,
	}); err != nil {
		t.Fatal(err)
	}
	authority.own(adminId, adminDevice)
	if _, err := admin.config.CreateAddress(ctx, &MailCreateAddressArgs{LocalPart: "office", Kind: protocol.MailAddressKind_MAIL_ADDRESS_GROUP, MailboxRepoId: adminId}); err != nil {
		t.Fatal(err)
	}
	if err := adminRepos.AddGroupMember(ctx, admin.config, "office", NewId()); !errors.Is(err, ErrMailReposAbsent) {
		t.Fatalf("group-add for the signed admin inbox: %v", err)
	}
	if members, _, err := admin.config.GroupMembers(ctx, "office"); err != nil || len(members) != 0 || len(world.state().Repo(adminId).GetGrants()) != 0 {
		t.Fatalf("admin inbox group members: %v, %v", members, err)
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

// One device's group, created confirmed on world's network, the member joined to it by group-add from the same
// device, which administers the group's record as its repo's admin; and the group's repo id.
func mailReposTestGroupWithMember(t *testing.T, world *mailReposTestWorld, repos *MailRepos, device Id, memberId Id) Id {
	t.Helper()
	authority := newMailConfigTestAuthority()
	authority.grant(device, "*")
	config := newMailConfigTestDevice(t, newMailConfigTestRepo(), authority, device, nil).config
	args := &MailCreateGroupArgs{LocalPart: "team", Confirmed: true}
	repo, err := repos.CreateGroup(t.Context(), config, args)
	if err != nil {
		t.Fatal(err)
	}
	groupId := repo.RepoId()
	authority.own(groupId, device)
	if err := repos.AddGroupMember(t.Context(), config, args.LocalPart, memberId); err != nil {
		t.Fatal(err)
	}
	// a completed creation asked again files nothing more
	grants := world.filedCount(bridge.SignedType_SIGNED_REPO_GRANT)
	if again, err := repos.CreateGroup(t.Context(), config, args); err != nil || again.RepoId() != groupId || world.filedCount(bridge.SignedType_SIGNED_REPO_GRANT) != grants {
		t.Fatalf("a completed creation asked again: %v, %v", again, err)
	}
	return groupId
}

// On a personal network group-create grants the group's deposit to autogroup:member (QD-1177), so once group-add has
// joined the member, a receiver on another of the member's devices, and every device of the member a same-network send
// goes from, both reads the group and deposits its mail, while the creating device administers it. The grants name
// two subjects, since the access log keeps one RepoGrant a subject: a deposit grant to the member would give way to
// group-add's reader grant, and the receiver would read alone (rights 10, as the e2e case's receivers held). The deposit
// grant reaches the sidecars a grant to the member names and no others: no ephemeral device of the member, and no
// tagged sidecar it sponsors.
func TestMailGroupOnAPersonalNetworkGrantsDepositToTheMembersDevices(t *testing.T) {
	world := newMailReposTestWorld(t)
	member, owner := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	receiver := world.fixture.device(member, NewId().Bytes())
	sender := world.fixture.device(member, NewId().Bytes())
	ephemeral := world.fixture.device(member, NewId().Bytes())
	world.fixture.admission(ephemeral).Ephemeral = true
	agent := world.fixture.agent(member, world.fixture.tag(member))
	world.fixture.configRepo(owner, member)
	world.rebuild()
	if world.state().teamNetwork() {
		t.Fatal("the personal network reads as a Team")
	}
	groupId := mailReposTestGroupWithMember(t, world, world.repos(owner), owner, member)

	state := world.state()
	row := state.Repo(groupId)
	everyMember := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	if len(row.GetGrants()) != 2 || !mailRepoGrantStands(row, everyMember, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT) ||
		!mailRepoGrantStands(row, member, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER) {
		t.Fatalf("the group's grants: %v", row.GetGrants())
	}
	for _, device := range []Id{receiver, sender} {
		if rights := aclTestRights(state, device, groupId, AclTokenAudienceEvs); rights != AclEvsDeposit|AclEvsRead {
			t.Fatalf("another device of the member holds %b on the group", rights)
		}
	}
	if rights := aclTestRights(state, owner, groupId, AclTokenAudienceEvs); !rights.Has(AclEvsAdmin | AclEvsWrite | AclEvsRead | AclEvsDeposit) {
		t.Fatalf("the creating device holds %b on the group", rights)
	}
	for _, outside := range []Id{ephemeral, agent} {
		if rights := aclTestRights(state, outside, groupId, AclTokenAudienceEvs); rights != 0 {
			t.Fatalf("a sidecar no grant to the member names holds %b on the group", rights)
		}
	}
}

// On a Team network group-create still grants the group's deposit to tag:mail alone (§15.8; QD-102): once group-add
// has joined a member, the group holds the tag's deposit grant and the member's reader grant and no autogroup:member
// grant, so the member's other device reads the group and deposits nothing, and the tag's mail indexer deposits and
// reads nothing.
func TestMailGroupOnATeamNetworkGrantsDepositToTagMailAlone(t *testing.T) {
	world := newMailReposTestWorld(t)
	member, device := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	other := world.fixture.device(member, NewId().Bytes())
	tag := world.fixture.tag(member)
	indexer := world.fixture.agent(member, tag)
	world.fixture.repo(protocol.RepoKind_REPO_KIND_TEAM_RECORD, Id{})
	world.rebuild()
	repos := world.repos(device)
	repos.mailIndexerTag = func(*AclState) (Id, bool) { return tag, true }
	groupId := mailReposTestGroupWithMember(t, world, repos, device, member)

	state := world.state()
	row := state.Repo(groupId)
	everyMember := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	personal := slices.ContainsFunc(row.GetGrants(), func(grant *protocol.AclRepoGrantRow) bool {
		return slices.Equal(grant.GetSubject(), everyMember.Bytes())
	})
	if len(row.GetGrants()) != 2 || personal || !mailRepoGrantStands(row, tag, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT) ||
		!mailRepoGrantStands(row, member, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER) {
		t.Fatalf("the group's grants: %v", row.GetGrants())
	}
	if rights := aclTestRights(state, other, groupId, AclTokenAudienceEvs); rights != AclEvsRead {
		t.Fatalf("the member's other device holds %b on the group", rights)
	}
	if rights := aclTestRights(state, indexer, groupId, AclTokenAudienceEvs); rights != AclEvsDeposit {
		t.Fatalf("the mail indexer holds %b on the group", rights)
	}
}

// A grant stands for the right its role gives (aclGrantRoleRights), not for every role numbered below it: a reader
// grant stands for no deposit, though the reader role's number is above the deposit role's, so a group whose deposit
// subject held one would get its deposit grant still; a deposit grant stands for no read; a writer's stands for read,
// and for deposit in a repo that takes deposits, as a group inbox does (QD-1173), but not in one that takes none; and
// no grant stands that expires, names another subject, or meets a config writer's standing revoke of its subject.
func TestMailRepoGrantStandsForTheRightItsRoleGives(t *testing.T) {
	subject := NewId()
	deposit := protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT
	reader := protocol.RepoGrantRole_REPO_GRANT_ROLE_READER
	writer := protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER
	grant := func(subject Id, role protocol.RepoGrantRole) *protocol.AclRepoGrantRow {
		return &protocol.AclRepoGrantRow{Subject: subject.Bytes(), Role: role}
	}
	inbox := func(grants ...*protocol.AclRepoGrantRow) *protocol.AclRepo {
		return &protocol.AclRepo{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: protocol.RepoInbox_REPO_INBOX_GROUP, Grants: grants}
	}
	plain := &protocol.AclRepo{Kind: protocol.RepoKind_REPO_KIND_GENERAL, Grants: []*protocol.AclRepoGrantRow{grant(subject, writer)}}
	expiring := grant(subject, deposit)
	expiring.Expires = aclTestNow.UnixMilli()
	revoked := inbox(grant(subject, deposit))
	revoked.Revokes = []*protocol.AclRepoRevokeRow{{Subject: subject.Bytes()}}
	cases := []struct {
		name   string
		repo   *protocol.AclRepo
		role   protocol.RepoGrantRole
		stands bool
	}{
		{name: "a deposit grant, for deposit", repo: inbox(grant(subject, deposit)), role: deposit, stands: true},
		{name: "a deposit grant, for read", repo: inbox(grant(subject, deposit)), role: reader, stands: false},
		{name: "a reader grant, for read", repo: inbox(grant(subject, reader)), role: reader, stands: true},
		{name: "a reader grant, for deposit", repo: inbox(grant(subject, reader)), role: deposit, stands: false},
		{name: "a writer grant, for read", repo: inbox(grant(subject, writer)), role: reader, stands: true},
		{name: "a writer grant, for deposit in a group inbox", repo: inbox(grant(subject, writer)), role: deposit, stands: true},
		{name: "a writer grant, for deposit in a repo that takes none", repo: plain, role: deposit, stands: false},
		{name: "another subject's grant", repo: inbox(grant(NewId(), deposit)), role: deposit, stands: false},
		{name: "a grant that expires", repo: inbox(expiring), role: deposit, stands: false},
		{name: "a revoked subject's grant", repo: revoked, role: deposit, stands: false},
	}
	for _, c := range cases {
		if stands := mailRepoGrantStands(c.repo, subject, c.role); stands != c.stands {
			t.Errorf("%s: stands %t", c.name, stands)
		}
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

func TestMailTeamNetworkKeyRequiresTheSignedAdminInbox(t *testing.T) {
	world := newMailReposTestWorld(t)
	_, device := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.fixture.repo(protocol.RepoKind_REPO_KIND_TEAM_RECORD, Id{})
	world.rebuild()
	repos := world.repos(device)
	authority := newMailConfigTestAuthority()
	authority.grant(device, "*")
	for _, role := range []protocol.RepoInbox{protocol.RepoInbox_REPO_INBOX_GROUP, protocol.RepoInbox_REPO_INBOX_ADMIN} {
		id := NewId()
		if err := world.file(device, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
			RepoId: id.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: role,
		}); err != nil {
			t.Fatal(err)
		}
		config := newMailConfigTestDevice(t, newMailConfigTestRepo(), authority, device, nil).config
		if _, err := config.CreateAddress(t.Context(), &MailCreateAddressArgs{Kind: protocol.MailAddressKind_MAIL_ADDRESS_ADMIN, MailboxRepoId: id}); err != nil {
			t.Fatal(err)
		}
		got, err := repos.NetworkMailKeyRepo(t.Context(), config)
		if role == protocol.RepoInbox_REPO_INBOX_ADMIN {
			if err != nil || got != id {
				t.Fatalf("the signed admin inbox: %s, %v", got, err)
			}
		} else if !errors.Is(err, ErrMailReposAbsent) {
			t.Fatalf("an ordinary group's key was selected as the network key: %v", err)
		}
	}
}

// A Team scope's own mailcfg is created once, by a consented device of the scope's member that writes no config heads
// (QD-1093): the log binds it to that member; a config writer, another member's device and a read_only one file
// nothing; the member's other devices are answered the one that stands; a creation cut short is taken up again under
// its id; and it is never read as the network's, nor the network's as it.
func TestMailReposEnsureScopeMailConfig(t *testing.T) {
	world := newMailReposTestWorld(t)
	ownerId, ownerDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	memberId := world.fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	phone := world.fixture.invitedDevice(memberId)
	desktop := world.fixture.device(memberId, phone.Bytes())
	worker := world.fixture.device(memberId, phone.Bytes())
	world.fixture.admission(worker).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	otherId, otherDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	ctx := context.Background()

	if _, err := world.repos(phone).EnsureScopeMailConfig(ctx, memberId); !errors.Is(err, ErrMailReposNoState) {
		t.Fatalf("with no verified state: %v", err)
	}
	world.rebuild()
	if _, err := world.repos(phone).EnsureScopeMailConfig(ctx, Id{}); !errors.Is(err, ErrMailReposInvalid) {
		t.Fatalf("no member: %v", err)
	}
	// a config writer's RepoCreate would be the network's, so it files none for its own scope
	if _, err := world.repos(ownerDevice).EnsureScopeMailConfig(ctx, ownerId); !errors.Is(err, ErrMailReposConfigWriter) {
		t.Fatalf("a config writer's scope mailcfg: %v", err)
	}
	// the fold would bind another member's device's creation to that other member, and a read_only device files nothing
	for _, sidecarId := range []Id{otherDevice, ownerDevice, worker} {
		if _, err := world.repos(sidecarId).EnsureScopeMailConfig(ctx, memberId); !errors.Is(err, ErrMailReposNotConsented) {
			t.Fatalf("a device that may not create the member's scope mailcfg: %v", err)
		}
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 0 {
		t.Fatal("a refused creation filed a RepoCreate")
	}

	// a crash after the RepoCreate landed: the next call takes the same repo up again
	world.failCreation = errors.New("synthetic failure: the group was not formed")
	phoneRepos := world.repos(phone)
	if _, err := phoneRepos.EnsureScopeMailConfig(ctx, memberId); err == nil {
		t.Fatal("a creation cut short answered a repo")
	}
	scopeConfigId, found := phoneRepos.ScopeMailConfigRepo(memberId)
	if !found {
		t.Fatal("the log holds no scope mailcfg after its RepoCreate")
	}
	row := world.state().Repo(scopeConfigId)
	if row.GetKind() != protocol.RepoKind_REPO_KIND_MAILCFG || Id(row.GetOwnerMemberId()) != memberId || len(row.GetConsentedSidecarIds()) != 3 {
		t.Fatalf("the scope mailcfg's row: %+v", row)
	}
	repo, err := phoneRepos.EnsureScopeMailConfig(ctx, memberId)
	if err != nil || repo.RepoId() != scopeConfigId {
		t.Fatalf("the creation taken up again: %v", err)
	}
	if last := world.creations[len(world.creations)-1]; last.ResumeRepoId == nil || *last.ResumeRepoId != scopeConfigId ||
		last.OwnerMemberId == nil || *last.OwnerMemberId != memberId {
		t.Fatalf("the resumed creation: %+v", last)
	}
	// the member's other devices, and a fresh process on the creating one, are answered the one that stands
	for _, sidecarId := range []Id{desktop, worker, phone} {
		repo, err := world.repos(sidecarId).EnsureScopeMailConfig(ctx, memberId)
		if err != nil || repo.RepoId() != scopeConfigId {
			t.Fatalf("the scope mailcfg as another device finds it: %v", err)
		}
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 1 {
		t.Fatalf("%d RepoCreates for one scope mailcfg", world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE))
	}

	// it is no network's mailcfg, which a config writer still creates, and the network's is no scope's
	if _, found := world.repos(ownerDevice).MailConfigRepo(); found {
		t.Fatal("a scope's mailcfg was read as the network's")
	}
	networkRepo, err := world.repos(ownerDevice).EnsureMailConfig(ctx)
	if err != nil || networkRepo.RepoId() == scopeConfigId {
		t.Fatalf("the network's mailcfg beside a scope's: %v", err)
	}
	if found, ok := world.repos(phone).MailConfigRepo(); !ok || found != networkRepo.RepoId() {
		t.Fatal("MailConfigRepo does not name the network's")
	}
	if found, ok := world.repos(ownerDevice).ScopeMailConfigRepo(memberId); !ok || found != scopeConfigId {
		t.Fatal("the scope's mailcfg changed once the network's was made")
	}
	for _, other := range []Id{ownerId, otherId} {
		if _, ok := world.repos(phone).ScopeMailConfigRepo(other); ok {
			t.Fatal("a member with no scope mailcfg was answered one")
		}
	}

	// a second mailcfg a device of the member raced in is owned too and replaces nothing: the first in log order
	// stays the scope's
	second := NewEvsRepoId()
	if err := world.file(desktop, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{RepoId: second.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILCFG}); err != nil {
		t.Fatal(err)
	}
	if row := world.state().Repo(second); Id(row.GetOwnerMemberId()) != memberId {
		t.Fatalf("the second mailcfg's row: %+v", row)
	}
	for _, sidecarId := range []Id{phone, desktop, ownerDevice} {
		if found, ok := world.repos(sidecarId).ScopeMailConfigRepo(memberId); !ok || found != scopeConfigId {
			t.Fatal("a second mailcfg from the member replaced the first")
		}
		if found, ok := world.repos(sidecarId).MailConfigRepo(); !ok || found != networkRepo.RepoId() {
			t.Fatal("a second mailcfg from the member was read as the network's")
		}
	}
}

// A scope mailcfg whose creator had become a config writer by the time its RepoCreate landed, with no network mailcfg
// standing, folds as a network's: the device is answered no scope mailcfg, never that repo, and then, that network's
// standing, creates its scope's own as a config writer (QD-1108). The other way, a network mailcfg whose creator wrote
// no config heads when it landed folds as its member's scope's, and is never answered as the network's.
func TestMailReposCreationThatFoldedAsTheOtherMailcfgIsNotReadAsAsked(t *testing.T) {
	world := newMailReposTestWorld(t)
	memberId, device := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.rebuild()
	ctx := context.Background()
	// what the device reads while it decides, which the log has moved past
	var viewLock sync.Mutex
	view := world.state()
	setView := func(state *AclState) {
		viewLock.Lock()
		defer viewLock.Unlock()
		view = state
	}
	repos := newMailRepos(&mailReposTestEvs{world: world, sidecarId: device}, &MailReposArgs{
		State: func() *AclState {
			viewLock.Lock()
			defer viewLock.Unlock()
			return view
		},
		Gkm:       &mailReposTestGkm{world: world, sidecarId: device},
		SidecarId: device,
	})

	world.fixture.view.configWriters[device] = true
	world.rebuild()
	created, err := repos.EnsureScopeMailConfig(ctx, memberId)
	if err != nil {
		t.Fatal(err)
	}
	if row := world.state().Repo(created.RepoId()); len(row.GetOwnerMemberId()) != 0 {
		t.Fatalf("a config writer's mailcfg folded owned: %+v", row)
	}
	setView(world.state())
	if _, err := repos.EnsureScopeMailConfig(ctx, memberId); !errors.Is(err, ErrMailReposAbsent) {
		t.Fatalf("a creation that folded as the network's: %v", err)
	}
	if _, found := repos.ScopeMailConfigRepo(memberId); found {
		t.Fatal("the network's mailcfg was read as the member's scope's")
	}
	// the network's now stands, so the log reads the config writer's next mailcfg as its member's scope's own
	// (QD-1108): the device creates it, and it is never the network's
	scope, err := repos.EnsureScopeMailConfig(ctx, memberId)
	if err != nil || scope.RepoId() == created.RepoId() {
		t.Fatalf("a config writer's scope mailcfg beside the network's: %v", err)
	}
	if row := world.state().Repo(scope.RepoId()); aclTestRowOwner(row) != memberId {
		t.Fatalf("the config writer's scope mailcfg's row: %+v", row)
	}
	setView(world.state())
	if found, ok := repos.ScopeMailConfigRepo(memberId); !ok || found != scope.RepoId() {
		t.Fatal("the config writer's scope mailcfg is not its scope's")
	}
	if found, ok := repos.MailConfigRepo(); !ok || found != created.RepoId() {
		t.Fatal("the network's mailcfg moved")
	}
	if world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 2 {
		t.Fatalf("%d RepoCreates", world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE))
	}

	// the other way: a second member's device believes it writes config heads, and no longer does when its RepoCreate
	// lands
	otherId, otherDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.fixture.view.configWriters[otherDevice] = true
	// the first network mailcfg is deleted, so none stands and a config writer would create one
	deletion := &protocol.RepoDelete{RepoId: created.RepoId().Bytes(), DeletionId: NewId().Bytes(), Now: true}
	if err := world.file(device, bridge.SignedType_SIGNED_REPO_DELETE, deletion); err != nil {
		t.Fatal(err)
	}
	world.rebuild()
	stale := world.state()
	otherRepos := newMailRepos(&mailReposTestEvs{world: world, sidecarId: otherDevice}, &MailReposArgs{
		State: func() *AclState {
			viewLock.Lock()
			defer viewLock.Unlock()
			return view
		},
		Gkm:       &mailReposTestGkm{world: world, sidecarId: otherDevice},
		SidecarId: otherDevice,
	})
	setView(stale)
	delete(world.fixture.view.configWriters, otherDevice)
	world.rebuild()
	misfiled, err := otherRepos.EnsureMailConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if row := world.state().Repo(misfiled.RepoId()); Id(row.GetOwnerMemberId()) != otherId {
		t.Fatalf("a member device's mailcfg folded unowned: %+v", row)
	}
	setView(world.state())
	if _, found := otherRepos.MailConfigRepo(); found {
		t.Fatal("a member's scope mailcfg was read as the network's")
	}
	if _, err := otherRepos.EnsureMailConfig(ctx); !errors.Is(err, ErrMailReposAbsent) {
		t.Fatalf("a creation that folded as a scope's: %v", err)
	}
	if _, err := otherRepos.EnsureMailConfig(ctx); !errors.Is(err, ErrMailReposConfigWriter) {
		t.Fatalf("a network mailcfg from a device that writes no config heads: %v", err)
	}
}
