//go:build !sidecar_http && !js && !ios_extension

// Same-network mail into a group's repo (MAIL-M7-18; R-MAIL-5, D-MAIL-8, I-5; §15.8, §8.5's group-inbox sentence,
// D-KEYS-17, QD-1173), and a burner's reply to another member: a send deposits only where the exchange mints the sender
// repo:<id>:deposit and the repo takes deposits, so a group's repo its RepoCreate does not mark an inbox answers
// refused, MailSendNoDepositRight, before anything is asked of the exchange or gkm, whoever writes it or holds its
// deposit grant. It answered failed before, once the exchange had refused a writer's token or gkm had served a deposit
// grant's subject no drop key. A reply from a burner, whose From the send grants on mail: do not judge, from a device no
// send grant marks, answers refused at another member's mailbox and deposits nothing there.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One state, both ends: for each sender and general repo the send side answers delivered only where the exchange
// mints repo:<id>:deposit (AclExchangeScopes) and the repo is marked an inbox, and refused everywhere else. A group
// inbox's writer deposits there by its write (QD-1173), its deposit grant's subject by its grant, and the admin inbox's
// writer by its write; the inbox's reader, a read_only device whatever its grant, and a device with no grant hold no
// deposit there. A general repo not marked an inbox takes none: its writer holds no deposit, which the exchange
// refuses, and its deposit grant's subject holds a scope no drop key serves (D-KEYS-17), so both are refused here,
// where the send side answered both delivered and each deposit then failed.
func TestMailSendToAGroupRepoAnswersWhatTheExchangeMints(t *testing.T) {
	net := newAclExchangeNet(t)
	inboxWriterId := testConfigId("group deposit inbox writer")
	inboxDepositId := testConfigId("group deposit inbox deposit grant")
	inboxReaderId := testConfigId("group deposit inbox reader")
	adminInboxId := testConfigId("group deposit admin inbox")
	plainWriterId := testConfigId("group deposit plain writer")
	plainDepositId := testConfigId("group deposit plain deposit grant")
	net.withAclRows(func(rows *protocol.AclRows) {
		grant := func(device testConfigDevice, role protocol.RepoGrantRole) *protocol.AclRepoGrantRow {
			return &protocol.AclRepoGrantRow{Subject: device.sidecarId.Bytes(), Role: role, Signer: net.owner.sidecarId.Bytes(), At: 1}
		}
		repo := func(repoId Id, inbox protocol.RepoInbox, grants ...*protocol.AclRepoGrantRow) {
			rows.Repos = append(rows.Repos, &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: inbox, Grants: grants})
		}
		writer, depositor, reader := protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER
		group, admin, none := protocol.RepoInbox_REPO_INBOX_GROUP, protocol.RepoInbox_REPO_INBOX_ADMIN, protocol.RepoInbox_REPO_INBOX_NONE
		repo(inboxWriterId, group, grant(net.phone, writer), grant(net.readOnly, writer))
		repo(inboxDepositId, group, grant(net.phone, depositor))
		repo(inboxReaderId, group, grant(net.phone, reader))
		repo(adminInboxId, admin, grant(net.phone, writer))
		repo(plainWriterId, none, grant(net.phone, writer))
		repo(plainDepositId, none, grant(net.phone, depositor))
	})
	state := net.log.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(net.timeMs)
	engine := NewAclEngine(net.phone.sidecarId, nil, nil, nil)
	if err := engine.Install(acl, nil); err != nil {
		t.Fatal(err)
	}
	authority := &MailSendAclAuthority{Engine: engine, Clock: fixedClock{at: now}}
	cases := []struct {
		name     string
		sender   testConfigDevice
		repoId   Id
		outcome  MailSendOutcome
		exchange bool
	}{
		{name: "a group inbox's writer", sender: net.phone, repoId: inboxWriterId, outcome: MailSendDelivered, exchange: true},
		{name: "a group inbox's deposit grant's subject", sender: net.phone, repoId: inboxDepositId, outcome: MailSendDelivered, exchange: true},
		{name: "the admin inbox's writer", sender: net.phone, repoId: adminInboxId, outcome: MailSendDelivered, exchange: true},
		{name: "a group inbox's reader", sender: net.phone, repoId: inboxReaderId, outcome: MailSendNoDepositRight, exchange: false},
		{name: "a read_only device a group inbox's writer grant names", sender: net.readOnly, repoId: inboxWriterId, outcome: MailSendNoDepositRight, exchange: false},
		{name: "a device no grant names, at a group inbox", sender: net.owner, repoId: inboxWriterId, outcome: MailSendNoDepositRight, exchange: false},
		{name: "an unmarked general repo's writer", sender: net.phone, repoId: plainWriterId, outcome: MailSendNoDepositRight, exchange: false},
		{name: "an unmarked general repo's deposit grant's subject", sender: net.phone, repoId: plainDepositId, outcome: MailSendNoDepositRight, exchange: true},
	}
	for _, c := range cases {
		outcome := mailSendMayDeposit(acl, c.sender.sidecarId, c.repoId, now)
		if outcome != c.outcome {
			t.Errorf("%s: %s, not %s", c.name, outcome, c.outcome)
		}
		if outcome := authority.MayDeposit(c.sender.sidecarId, c.repoId); outcome != c.outcome {
			t.Errorf("%s, through the installed engine: %s, not %s", c.name, outcome, c.outcome)
		}
		scope := aclExchangeScope(c.repoId, "deposit")
		minted := slices.Contains(net.exchange(t, c.sender, AclTokenAudienceEvs, scope).Scopes, scope)
		if minted != c.exchange {
			t.Errorf("%s: the exchange mints the deposit scope: %t, not %t", c.name, minted, c.exchange)
		}
		if outcome == MailSendDelivered && !minted {
			t.Errorf("%s: delivered where the exchange mints no deposit", c.name)
		}
	}
}

// The member world's parts with group repos beside the two mailboxes, counting every deposit asked of each repo, made
// or refused. A group repo's deposit is refused as EvsRepo.Deposit would refuse it: where the repo takes no deposits,
// gkm serving no drop key (D-KEYS-17), and where the exchange would mint the sending device no repo:<id>:deposit.
type mailGroupRepoDepositTestParts struct {
	*mailMemberDepositTestParts
	stateLock sync.Mutex
	asked     map[Id]int
	deposits  []*mailSendTestDeposit
}

func (self *mailGroupRepoDepositTestParts) depositRepo(repoId Id) mailSendDepositRepo {
	return &mailGroupRepoDepositTestRepo{parts: self, repoId: repoId, mailbox: self.mailMemberDepositTestParts.depositRepo(repoId)}
}

// The deposits asked of repoId so far.
func (self *mailGroupRepoDepositTestParts) askedOf(repoId Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.asked[repoId]
}

// The group repos' deposits so far.
func (self *mailGroupRepoDepositTestParts) groupDeposits() []*mailSendTestDeposit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.deposits)
}

// One repo's deposit as the send hands it to evs: a member's mailbox's through the member world, a group repo's here.
type mailGroupRepoDepositTestRepo struct {
	parts   *mailGroupRepoDepositTestParts
	repoId  Id
	mailbox mailSendDepositRepo
}

func (self *mailGroupRepoDepositTestRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	func() {
		self.parts.stateLock.Lock()
		defer self.parts.stateLock.Unlock()
		self.parts.asked[self.repoId] += 1
	}()
	if self.mailbox != nil {
		return self.mailbox.Deposit(ctx, args)
	}
	world := self.parts.members
	state := world.annEngine.State()
	if !gkmRepoTakesDeposits(state.Repo(self.repoId)) {
		return nil, fmt.Errorf("%w: the repo's generations carry no drop key", ErrGkmKeyMissing)
	}
	if !state.EvsAccess(AclSidecarSubject(world.device), self.repoId, AclTokenAudienceEvs, aclTestNow).Rights.Has(AclEvsDeposit) {
		return nil, errors.New("the exchange mints no deposit scope for this repo")
	}
	plaintext, err := io.ReadAll(args.Body)
	if err != nil {
		return nil, err
	}
	if int64(len(plaintext)) != args.Size {
		return nil, errors.New("a body of another size than stated")
	}
	message, trailer, err := mailSplitDeposit(plaintext, 64*1024)
	if err != nil {
		return nil, err
	}
	self.parts.stateLock.Lock()
	defer self.parts.stateLock.Unlock()
	self.parts.deposits = append(self.parts.deposits, &mailSendTestDeposit{repoId: self.repoId, message: message, deposit: trailer, plaintext: plaintext})
	return &EvsDepositResult{EntryId: NewEvsRandomToken(), Version: uint64(len(self.parts.deposits))}, nil
}

// The member world (ann, whose phone sends, and bo) with the counting parts installed in ann's client.
func newMailGroupRepoDepositTestWorld(t *testing.T) (*mailMemberDepositTestWorld, *mailGroupRepoDepositTestParts) {
	t.Helper()
	world := newMailMemberDepositTestWorld(t)
	parts := &mailGroupRepoDepositTestParts{mailMemberDepositTestParts: world.parts, asked: map[Id]int{}}
	world.client.stateLock.Lock()
	world.client.partsOverride = parts
	world.client.stateLock.Unlock()
	return world, parts
}

// ann's phone sends to three groups, each a general repo it holds a RepoGrant in: team, a group inbox it writes, which
// takes its deposit by that write (QD-1173); plain, a general repo it writes that is not marked an inbox; and drop, one
// not marked whose deposit grant names it. team is delivered, one deposit naming team alone; plain and drop answer
// refused and are asked for no deposit, where the send asked each for one and answered failed, plain's refused by the
// exchange and drop's by gkm, which serves no drop key for a repo that takes no deposits. A send to plain alone
// answers refused and keeps no copy of a message that went nowhere.
func TestMailSendToAGroupRepoNotMarkedAnInboxIsRefusedBeforeAnyDeposit(t *testing.T) {
	world, parts := newMailGroupRepoDepositTestWorld(t)
	fixture := world.repos.fixture
	group := func(inbox protocol.RepoInbox, role protocol.RepoGrantRole) Id {
		repoId, row := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
		row.Inbox = inbox
		row.Grants = []*protocol.AclRepoGrantRow{{Subject: world.device.Bytes(), Role: role, Signer: world.device.Bytes(), At: fixture.next()}}
		return repoId
	}
	teamId := group(protocol.RepoInbox_REPO_INBOX_GROUP, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)
	plainId := group(protocol.RepoInbox_REPO_INBOX_NONE, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)
	dropId := group(protocol.RepoInbox_REPO_INBOX_NONE, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT)
	world.repos.rebuild()
	world.install()
	state := world.annEngine.State()
	for _, c := range []struct {
		name   string
		repoId Id
		rights AclEvsRights
	}{
		{name: "team", repoId: teamId, rights: AclEvsRead | AclEvsWrite | AclEvsDeposit},
		{name: "plain", repoId: plainId, rights: AclEvsRead | AclEvsWrite},
		{name: "drop", repoId: dropId, rights: AclEvsDeposit},
	} {
		if rights := state.EvsAccess(AclSidecarSubject(world.device), c.repoId, AclTokenAudienceEvs, aclTestNow).Rights; rights != c.rights {
			t.Fatalf("ann's phone holds %b in %s, not %b", rights, c.name, c.rights)
		}
	}
	ctx := context.Background()
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []struct {
		localPart string
		repoId    Id
	}{{localPart: "team", repoId: teamId}, {localPart: "plain", repoId: plainId}, {localPart: "drop", repoId: dropId}} {
		if _, err := config.CreateAddress(ctx, &MailCreateAddressArgs{
			LocalPart: address.localPart, Kind: protocol.MailAddressKind_MAIL_ADDRESS_GROUP, MailboxRepoId: address.repoId, MemberIds: []Id{world.member},
		}); err != nil {
			t.Fatal(err)
		}
	}
	team, plain, drop := "team@acme.root.example", "plain@acme.root.example", "drop@acme.root.example"

	result, err := world.client.Send(ctx, &MailSendArgs{From: testMailSendFrom, To: []string{team, plain, drop}, Subject: "Groups", Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]MailSendOutcome{}
	for _, recipient := range result.Recipients {
		outcomes[recipient.Address] = recipient.Outcome
	}
	if len(outcomes) != 3 || outcomes[team] != MailSendDelivered || outcomes[plain] != MailSendNoDepositRight || outcomes[drop] != MailSendNoDepositRight || !result.SentCopy {
		t.Fatalf("outcomes %v, copy %t", outcomes, result.SentCopy)
	}
	if asked := []int{parts.askedOf(teamId), parts.askedOf(plainId), parts.askedOf(dropId)}; !slices.Equal(asked, []int{1, 0, 0}) {
		t.Fatalf("deposits asked of team, plain and drop: %v", asked)
	}
	deposits := parts.groupDeposits()
	if len(deposits) != 1 || deposits[0].repoId != teamId || !slices.Equal(deposits[0].deposit.GetRecipients(), []string{team}) {
		t.Fatalf("deposits %+v", deposits)
	}

	result, err = world.client.Send(ctx, &MailSendArgs{From: testMailSendFrom, To: []string{plain}, Subject: "Plain", Text: "y"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].Outcome != MailSendNoDepositRight || result.SentCopy || parts.askedOf(plainId) != 0 {
		t.Fatalf("a send to plain alone %+v, copy %t, %d deposits asked", result.Recipients, result.SentCopy, parts.askedOf(plainId))
	}
	if sent := testMailSendRead(t, world.mailClientTestWorld, MailFolderSent, "Plain"); sent != nil {
		t.Fatal("a sent copy kept of a message that went nowhere")
	}
}

// ann's send grant on mail: lapses, so the state marks no device of ann's mail_send and ann's phone holds no deposit in
// bo's mailbox, its From check refusing every send of its from ann's address. A burner's reply is the one send whose
// From no send grant judges, only the burner's live label in ann's mailbox (mail_burner_reply.go), so it is the one
// that reaches bo's mailbox's deposit right: a reply from ann's burner to bo answers refused, asks bo's mailbox for no
// deposit and keeps no copy. The same reply naming ann's own address beside bo's delivers that one, into ann's mailbox,
// which ann's phone deposits into by its write (QD-1173), with the copy kept, and still asks nothing of bo's mailbox.
func TestMailBurnerReplyFromADeviceNoSendGrantMarksIsRefusedAtAnotherMembersMailbox(t *testing.T) {
	world, parts := newMailGroupRepoDepositTestWorld(t)
	world.sendRule.Expires = aclTestNow.Add(-time.Minute).UnixMilli()
	world.repos.rebuild()
	world.install()
	state := world.annEngine.State()
	if state.MaySend(AclSidecarSubject(world.device), aclTestNow).Allowed {
		t.Fatal("the lapsed grant still marks ann's phone")
	}
	if rights := state.EvsAccess(AclSidecarSubject(world.device), world.boMailbox, AclTokenAudienceEvs, aclTestNow).Rights; rights != 0 {
		t.Fatalf("ann's phone holds %b in bo's mailbox", rights)
	}
	ctx := context.Background()
	if _, err := world.client.Send(ctx, &MailSendArgs{From: testMailSendFrom, To: []string{testMailIngestRecipient}, Text: "x"}); !errors.Is(err, ErrMailSendFromRefused) {
		t.Fatalf("a send from ann's address: %v", err)
	}
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	burner, err := config.CreateBurnerRecord(ctx, &MailCreateBurnerArgs{Alias: "shop", MailboxRepoId: world.annMailbox})
	if err != nil {
		t.Fatal(err)
	}
	from := "shop@" + burner.Label + ".acme.root.example"

	result, err := world.client.Reply(ctx, &MailReplyArgs{From: from, To: []string{testMailIngestRecipient}, Subject: "Re: alone", Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].Outcome != MailSendNoDepositRight || result.SentCopy || 0 < len(result.EffectKey) {
		t.Fatalf("a reply to bo %+v, copy %t", result.Recipients, result.SentCopy)
	}
	if asked := parts.askedOf(world.boMailbox); asked != 0 || len(parts.snapshot()) != 0 || world.bo.repo.standingCount(world.device) != 0 {
		t.Fatalf("%d deposits asked of bo's mailbox, %d made", asked, len(parts.snapshot()))
	}

	result, err = world.client.Reply(ctx, &MailReplyArgs{From: from, To: []string{testMailIngestRecipient, testMailSendFrom}, Subject: "Re: both", Text: "y"})
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]MailSendOutcome{}
	for _, recipient := range result.Recipients {
		outcomes[recipient.Address] = recipient.Outcome
	}
	if len(outcomes) != 2 || outcomes[testMailIngestRecipient] != MailSendNoDepositRight || outcomes[testMailSendFrom] != MailSendDelivered || !result.SentCopy {
		t.Fatalf("outcomes %v, copy %t", outcomes, result.SentCopy)
	}
	deposits := parts.snapshot()
	if len(deposits) != 1 || deposits[0].repoId != world.annMailbox || !slices.Equal(deposits[0].deposit.GetRecipients(), []string{testMailSendFrom}) ||
		string(deposits[0].deposit.GetMailFrom()) != from {
		t.Fatalf("deposits %+v", deposits)
	}
	if asked := parts.askedOf(world.boMailbox); asked != 0 || world.bo.repo.standingCount(world.device) != 0 {
		t.Fatalf("%d deposits asked of bo's mailbox", asked)
	}
}
