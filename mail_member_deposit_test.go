//go:build !sidecar_http && !js && !ios_extension

// Same-network mail between members (MAIL-M7-18; R-MAIL-5, D-MAIL-8, I-5; §15.8, §8.5's mailbox row, owner decision
// 333, QD-1173), with plan-MAIL-member-deposit's interim gone: a send deposits into another member's mailbox under the
// deposit §8.5 gives every subject of the network the projection marks mail_send, as into its own member's by its
// write, and the recipient's reader takes it as a member's mail, labeled by its signer. Where the state gives the
// sender no deposit that carries mail there, the send answers that recipient refused and deposits nothing there, and
// ingest makes the same call of a deposit pushed anyway.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The detail CompileAclLocal gives a document's send grants on mail:*, which rows carry only as mail_send (D-ACL-12):
// each rule takes every alias.
func testMailMemberDepositLocal(rules ...*protocol.AclRule) *AclLocalPolicy {
	local := &AclLocalPolicy{HasDocument: true}
	for _, rule := range rules {
		local.Rules = append(local.Rules, AclLocalRule{RuleId: Id(rule.GetRuleId()), Aliases: []string{"*"}})
	}
	slices.SortFunc(local.Rules, func(a AclLocalRule, b AclLocalRule) int { return a.RuleId.Cmp(b.RuleId) })
	return local
}

// Whether a zone is the test network's own.
func testMailMemberDepositOwnZone(zone MailZone) bool {
	return zone.OfNetwork(testMailIngestNetwork())
}

// At one state, the send side's answer for each sender and repo, and ingest's class of a deposit that sender pushed at
// that state, agree: a sender a send grant on mail: marks deposits into another member's mailbox as mail (owner
// decision 333), and so does an agent its sponsor's tag grant marks; a member's own devices deposit into its mailbox
// by their write, with no send grant (QD-1173); a sender whose only grant lapsed has no deposit in another member's
// mailbox, nor has a read_only device; one an EvsShare lets read the mailbox holds only §16.8's receipt deposit there,
// which ingest leaves to the record; and a deleted mailbox, or a repo the state does not hold, takes nothing. The
// From check agrees with the mark: each sender a grant in force marks may send as its member's address.
func TestMailSendBetweenMembersTakesTheDepositTheStateGives(t *testing.T) {
	fixture := newAclTestFixture()
	ann, annPhone := fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	annLaptop := fixture.device(ann, annPhone.Bytes())
	annPageWorker := fixture.device(ann, annPhone.Bytes())
	fixture.admission(annPageWorker).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	mailerTag := fixture.tag(ann)
	annAgent := fixture.agent(ann, mailerTag)
	bo := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	boLaptop := fixture.invitedDevice(bo)
	cy := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	cyPhone := fixture.invitedDevice(cy)
	dee := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	deePhone := fixture.invitedDevice(dee)
	mailbox := func(memberId Id, consented ...Id) (Id, *protocol.AclRepo) {
		repoId, repo := fixture.repo(protocol.RepoKind_REPO_KIND_MAILBOX, memberId)
		for _, sidecarId := range consented {
			repo.ConsentedSidecarIds = append(repo.ConsentedSidecarIds, sidecarId.Bytes())
		}
		return repoId, repo
	}
	annMailboxId, _ := mailbox(ann, annPhone, annLaptop, annPageWorker)
	boMailboxId, _ := mailbox(bo, boLaptop)
	cyMailboxId, cyMailbox := mailbox(cy, cyPhone)
	cyMailbox.Shares = []*protocol.AclRepoShareRow{{Subject: annLaptop.Bytes(), Signer: cyPhone.Bytes(), At: fixture.next()}}
	deeMailboxId, deeMailbox := mailbox(dee, deePhone)
	deeMailbox.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: fixture.next()}
	mailSend := []*protocol.AclTarget{{MailSend: true}}
	send := protocol.AclAction_ACL_ACTION_SEND
	annRule := fixture.rule([]Id{fixture.group(ann)}, mailSend, send)
	agentRule := fixture.rule([]Id{mailerTag}, mailSend, send)
	lapsedRule := fixture.rule([]Id{fixture.group(bo)}, mailSend, send)
	lapsedRule.Expires = aclTestNow.Add(-time.Minute).UnixMilli()
	state := fixture.state(t)
	// every device's engine at the state answers alike, the sender's and each mailbox's reader's: bo's laptop's here
	engine := NewAclEngine(boLaptop, nil, nil, nil)
	if err := engine.Install(state, testMailMemberDepositLocal(annRule, agentRule, lapsedRule)); err != nil {
		t.Fatal(err)
	}
	clock := fixedClock{at: aclTestNow}
	authority := &MailSendAclAuthority{Engine: engine, Root: testMailIngestRoot, OwnZone: testMailMemberDepositOwnZone, Clock: clock}
	ingest := &MailIngestAclAuthority{Engine: engine, Root: testMailIngestRoot, OwnZone: testMailMemberDepositOwnZone, Clock: clock}
	pin := state.Pin()
	cases := []struct {
		name    string
		sender  Id
		repoId  Id
		outcome MailSendOutcome
		class   MailDepositorClass
	}{
		{name: "ann's phone to bo's mailbox", sender: annPhone, repoId: boMailboxId, outcome: MailSendDelivered, class: MailDepositorMail},
		{name: "ann's laptop to bo's mailbox", sender: annLaptop, repoId: boMailboxId, outcome: MailSendDelivered, class: MailDepositorMail},
		{name: "ann's agent to bo's mailbox", sender: annAgent, repoId: boMailboxId, outcome: MailSendDelivered, class: MailDepositorMail},
		{name: "ann's phone to cy's mailbox", sender: annPhone, repoId: cyMailboxId, outcome: MailSendDelivered, class: MailDepositorMail},
		{name: "ann's phone to its own mailbox", sender: annPhone, repoId: annMailboxId, outcome: MailSendDelivered, class: MailDepositorMail},
		{name: "ann's agent to its sponsor's mailbox", sender: annAgent, repoId: annMailboxId, outcome: MailSendDelivered, class: MailDepositorMail},
		{name: "bo's laptop to its own mailbox, with no grant in force", sender: boLaptop, repoId: boMailboxId, outcome: MailSendDelivered, class: MailDepositorMail},
		{name: "bo's laptop to ann's mailbox, its grant lapsed", sender: boLaptop, repoId: annMailboxId, outcome: MailSendNoDepositRight, class: MailDepositorNone},
		{name: "ann's read_only page worker to bo's mailbox", sender: annPageWorker, repoId: boMailboxId, outcome: MailSendNoDepositRight, class: MailDepositorNone},
		{name: "ann's read_only page worker to its own mailbox", sender: annPageWorker, repoId: annMailboxId, outcome: MailSendNoDepositRight, class: MailDepositorReceipts},
		{name: "ann's laptop to cy's mailbox, which cy shared with it", sender: annLaptop, repoId: cyMailboxId, outcome: MailSendNoDepositRight, class: MailDepositorReceipts},
		{name: "ann's phone to dee's deleted mailbox", sender: annPhone, repoId: deeMailboxId, outcome: MailSendNoDepositRight, class: MailDepositorNone},
		{name: "ann's phone to a repo the state does not hold", sender: annPhone, repoId: NewId(), outcome: MailSendNoDepositRight, class: MailDepositorNone},
	}
	for _, c := range cases {
		if outcome := mailSendMayDeposit(state, c.sender, c.repoId, aclTestNow); outcome != c.outcome {
			t.Errorf("%s: %s, not %s", c.name, outcome, c.outcome)
		}
		if outcome := authority.MayDeposit(c.sender, c.repoId); outcome != c.outcome {
			t.Errorf("%s, through the installed engine: %s, not %s", c.name, outcome, c.outcome)
		}
		if class := ingest.DepositorClass(c.repoId, c.sender, pin); class != c.class {
			t.Errorf("%s: ingest classes the depositor %d, not %d", c.name, class, c.class)
		}
	}
	for _, c := range []struct {
		name    string
		sender  Id
		maySend bool
	}{
		{name: "ann's phone", sender: annPhone, maySend: true},
		{name: "ann's agent", sender: annAgent, maySend: true},
		{name: "bo's laptop, its grant lapsed", sender: boLaptop, maySend: false},
	} {
		if maySend := authority.MaySendAs(c.sender, testMailSendFrom); maySend != c.maySend {
			t.Errorf("%s may send as ann: %t", c.name, maySend)
		}
		if marked := state.MaySend(AclSidecarSubject(c.sender), aclTestNow).Allowed; marked != c.maySend {
			t.Errorf("%s marked mail_send: %t", c.name, marked)
		}
	}
}

// Two members of one network on MAIL-M7-17's client world: ann, the world's own member, whose phone is the world's
// device and sends, and bo, another member, whose laptop reads bo's mailbox. One state holds both, with a send grant on
// mail: for ann's devices, and each device's engine holds that state and the grant's detail, so the send's From check
// and deposit right, and the reader's class and label, are §8's own answers rather than a test's.
type mailMemberDepositTestWorld struct {
	*mailClientTestWorld
	boMember   Id
	boLaptop   Id
	annMailbox Id
	boMailbox  Id
	// bo's mailbox: its deposit refs and its file-mode store
	bo        *mailIngestTestWorld
	sendRule  *protocol.AclRule
	annEngine *AclEngine
	boEngine  *AclEngine
	parts     *mailMemberDepositTestParts
}

func newMailMemberDepositTestWorld(t *testing.T) *mailMemberDepositTestWorld {
	t.Helper()
	world := &mailMemberDepositTestWorld{mailClientTestWorld: newMailClientTestWorld(t), bo: newMailIngestTestWorld(t)}
	fixture := world.repos.fixture
	world.boMember = fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.boLaptop = fixture.invitedDevice(world.boMember)
	world.sendRule = fixture.rule([]Id{fixture.group(world.member)}, []*protocol.AclTarget{{MailSend: true}}, protocol.AclAction_ACL_ACTION_SEND)
	world.repos.rebuild()
	ctx := context.Background()
	world.annMailbox = world.enable()
	mailbox, err := world.repos.repos(world.boLaptop).EnsureMailbox(ctx, world.boMember)
	if err != nil {
		t.Fatal(err)
	}
	world.boMailbox = mailbox.RepoId()
	world.bo.repoId = world.boMailbox
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	world.annEngine = binding.Engine
	world.boEngine = NewAclEngine(world.boLaptop, nil, nil, nil)
	world.install()
	state := world.repos.state()
	if !state.MaySend(AclSidecarSubject(world.device), aclTestNow).Allowed || state.MaySend(AclSidecarSubject(world.boLaptop), aclTestNow).Allowed {
		t.Fatal("the send grant marks other devices than ann's")
	}
	if rights := state.EvsAccess(AclSidecarSubject(world.boLaptop), world.boMailbox, AclTokenAudienceEvs, aclTestNow).Rights; !rights.Has(AclEvsRead | AclEvsWrite) {
		t.Fatalf("bo's laptop holds %b in bo's mailbox", rights)
	}

	// ann's address in ann's mailbox, by ann's phone, and bo's in bo's, by bo's laptop
	if _, err := world.client.CreateAlias(ctx, &MailAliasCreateArgs{LocalPart: "ann"}); err != nil {
		t.Fatal(err)
	}
	world.configAuthority.grant(world.boLaptop, "*")
	world.configAuthority.own(world.boMailbox, world.boLaptop)
	boConfig := newMailConfigTestDevice(t, world.configRepo, world.configAuthority, world.boLaptop, func(args *MailConfigArgs) {
		args.Network = testMailIngestNetwork
	})
	if _, err := boConfig.config.CreateAddress(ctx, &MailCreateAddressArgs{
		LocalPart: "bo", Kind: protocol.MailAddressKind_MAIL_ADDRESS_ID, MailboxRepoId: world.boMailbox,
	}); err != nil {
		t.Fatal(err)
	}
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	world.parts = &mailMemberDepositTestParts{mailClientTestParts: &mailClientTestParts{world: world.mailClientTestWorld}, members: world}
	world.client.stateLock.Lock()
	world.client.partsOverride = world.parts
	world.client.stateLock.Unlock()
	return world
}

// Installs the repos world's newest state, with the send grant's detail, in both devices' engines.
func (self *mailMemberDepositTestWorld) install() {
	self.t.Helper()
	state := self.repos.state()
	local := testMailMemberDepositLocal(self.sendRule)
	for _, engine := range []*AclEngine{self.annEngine, self.boEngine} {
		if err := engine.Install(state, local); err != nil {
			self.t.Fatal(err)
		}
	}
}

// An EvsShare of repoId to subject, signed by signer, a consented device of the repo's owner, in the access log's
// rows, which both engines then hold.
func (self *mailMemberDepositTestWorld) share(repoId Id, subject Id, signer Id) {
	self.t.Helper()
	fixture := self.repos.fixture
	for _, repo := range fixture.rows.GetRepos() {
		if bytes.Equal(repo.GetRepoId(), repoId.Bytes()) {
			repo.Shares = append(repo.Shares, &protocol.AclRepoShareRow{Subject: subject.Bytes(), Signer: signer.Bytes(), At: fixture.next()})
		}
	}
	self.repos.rebuild()
	self.install()
}

// bo's laptop's pass over bo's mailbox, under the authority its engine gives, as the mail component's ingestor runs.
func (self *mailMemberDepositTestWorld) ingestBo() *MailIngestPass {
	self.t.Helper()
	ingestor := self.bo.ingestor(func(args *MailIngestArgs) {
		args.SidecarId = self.boLaptop
		args.Authority = &MailIngestAclAuthority{
			Engine: self.boEngine, Root: testMailIngestRoot, OwnZone: testMailMemberDepositOwnZone, Clock: fixedClock{at: aclTestNow},
		}
	})
	return self.bo.ingest(ingestor)
}

// The client world's parts with Send's authority over ann's engine, built as Send builds it, and deposits that land in
// ann's or bo's deposit refs as the sending device's, pinned at the state its engine holds, as evs hands a reader a
// deposit push. A deposit the exchange would mint no repo:<id>:deposit for is refused, as evs's gate refuses one.
type mailMemberDepositTestParts struct {
	*mailClientTestParts
	members   *mailMemberDepositTestWorld
	stateLock sync.Mutex
	deposits  []*mailSendTestDeposit
}

func (self *mailMemberDepositTestParts) sendAuthority() MailSendAuthority {
	return &MailSendAclAuthority{
		Engine: self.members.annEngine, Root: testMailIngestRoot, OwnZone: testMailMemberDepositOwnZone, Clock: fixedClock{at: aclTestNow},
	}
}

func (self *mailMemberDepositTestParts) depositRepo(repoId Id) mailSendDepositRepo {
	switch repoId {
	case self.members.annMailbox:
		return &mailMemberDepositTestRepo{parts: self, repoId: repoId, refs: self.members.ingest.repo}
	case self.members.boMailbox:
		return &mailMemberDepositTestRepo{parts: self, repoId: repoId, refs: self.members.bo.repo}
	}
	return nil
}

// The deposits so far.
func (self *mailMemberDepositTestParts) snapshot() []*mailSendTestDeposit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.deposits)
}

// One mailbox's deposit, as the send hands it to evs.
type mailMemberDepositTestRepo struct {
	parts  *mailMemberDepositTestParts
	repoId Id
	refs   *mailIngestTestRepo
}

func (self *mailMemberDepositTestRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
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
	world := self.parts.members
	engine := world.annEngine
	if rights := engine.State().EvsAccess(AclSidecarSubject(world.device), self.repoId, AclTokenAudienceEvs, aclTestNow).Rights; !rights.Has(AclEvsDeposit) {
		return nil, errors.New("the exchange mints no deposit scope for this repo")
	}
	pushed := self.refs.deposit(world.device, world.device, plaintext)
	pushed.pin = engine.Pin()
	self.parts.stateLock.Lock()
	defer self.parts.stateLock.Unlock()
	self.parts.deposits = append(self.parts.deposits, &mailSendTestDeposit{repoId: self.repoId, message: message, deposit: trailer, plaintext: plaintext})
	return &EvsDepositResult{EntryId: EvsToken(pushed.id), Version: pushed.version}, nil
}

// ann's mail to bo's address is one deposit into bo's mailbox, signed by ann's phone and naming bo alone, with a sent
// copy kept in ann's mailbox and nothing deposited there; bo's laptop takes the deposit as a member's mail, labeled
// member-signed by its signer, since that signer may send as its From.
func TestMailSendBetweenTwoMembersDeliversToTheRecipientsMailbox(t *testing.T) {
	world := newMailMemberDepositTestWorld(t)
	ctx := context.Background()
	result, err := world.client.Send(ctx, &MailSendArgs{
		From: testMailSendFrom, To: []string{testMailIngestRecipient}, Subject: "Lunch", Text: "At noon, by the river.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].Outcome != MailSendDelivered || !result.SentCopy {
		t.Fatalf("the result %+v, copy %t", result.Recipients, result.SentCopy)
	}
	deposits := world.parts.snapshot()
	if len(deposits) != 1 || deposits[0].repoId != world.boMailbox {
		t.Fatalf("%d deposits", len(deposits))
	}
	trailer := deposits[0].deposit
	if string(trailer.GetMailFrom()) != testMailSendFrom || !slices.Equal(trailer.GetRecipients(), []string{testMailIngestRecipient}) ||
		trailer.GetIngress() != nil || trailer.GetEvidence() != nil || len(trailer.GetReceiverSidecarId()) != 0 {
		t.Fatalf("a same-network trailer sets version, mail_from and recipients only: %+v", trailer)
	}
	if count := world.ingest.repo.standingCount(world.device); count != 0 {
		t.Fatalf("%d deposits in ann's own mailbox", count)
	}

	pass := world.ingestBo()
	if pass.Ingested != 1 || pass.Consumed != 1 || pass.Left+pass.Refused != 0 {
		t.Fatalf("bo's pass %+v", pass)
	}
	if len(world.bo.messages) != 1 {
		t.Fatalf("%d messages", len(world.bo.messages))
	}
	message := world.bo.messages[0]
	if message.RepoId != world.boMailbox || message.DepositorId != world.device || message.ReceiverDeposit || message.Untrusted ||
		message.Entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED || message.Entry.GetSubject() != "Lunch" {
		t.Fatalf("bo's message %+v", message)
	}
	if world.bo.repo.standingCount(world.device) != 0 {
		t.Fatal("bo's reader left ann's deposit standing")
	}
	sent := testMailSendRead(t, world.mailClientTestWorld, MailFolderSent, "Lunch")
	if sent == nil || mailEntryId(sent.Entry) != result.SendId || sent.Trust == MailTrustUntrusted {
		t.Fatalf("ann's sent copy %+v", sent)
	}
}

// bo shares bo's mailbox with ann's phone, which then reads it and does not write it, so its one deposit there is
// §16.8's receipt deposit, which carries no mail: ann's send to bo answers refused, deposits nothing and keeps no copy
// of a message that went nowhere, while the same send with ann's own address beside it delivers that one and keeps the
// copy. ann's From check passes throughout: the recipient's mailbox, not the sender's grant, refuses. A deposit pushed
// there anyway is a receipt depositor's to bo's reader, whose ref it never opens: left standing for the record, never
// written as mail.
func TestMailSendAnswersRefusedWhereTheMembersMailboxGivesNoMailDeposit(t *testing.T) {
	world := newMailMemberDepositTestWorld(t)
	world.share(world.boMailbox, world.device, world.boLaptop)
	if rights := world.annEngine.State().EvsAccess(AclSidecarSubject(world.device), world.boMailbox, AclTokenAudienceEvs, aclTestNow).Rights; rights != AclEvsRead|AclEvsDeposit {
		t.Fatalf("ann's phone holds %b in bo's mailbox", rights)
	}
	ctx := context.Background()
	result, err := world.client.Send(ctx, &MailSendArgs{From: testMailSendFrom, To: []string{testMailIngestRecipient}, Subject: "Alone", Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].Outcome != MailSendNoDepositRight || result.SentCopy || len(world.parts.snapshot()) != 0 {
		t.Fatalf("a send into the shared mailbox %+v, copy %t, %d deposits", result.Recipients, result.SentCopy, len(world.parts.snapshot()))
	}

	result, err = world.client.Send(ctx, &MailSendArgs{From: testMailSendFrom, To: []string{testMailIngestRecipient, testMailSendFrom}, Subject: "Both", Text: "y"})
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]MailSendOutcome{}
	for _, recipient := range result.Recipients {
		outcomes[recipient.Address] = recipient.Outcome
	}
	if outcomes[testMailIngestRecipient] != MailSendNoDepositRight || outcomes[testMailSendFrom] != MailSendDelivered || len(outcomes) != 2 || !result.SentCopy {
		t.Fatalf("outcomes %v, copy %t", outcomes, result.SentCopy)
	}
	deposits := world.parts.snapshot()
	if len(deposits) != 1 || deposits[0].repoId != world.annMailbox || !slices.Equal(deposits[0].deposit.GetRecipients(), []string{testMailSendFrom}) {
		t.Fatalf("deposits %+v", deposits)
	}

	plaintext, err := MailSameNetworkDeposit(testMailIngestMessage("Pushed anyway", "x"), testMailSendFrom, []string{testMailIngestRecipient})
	if err != nil {
		t.Fatal(err)
	}
	world.bo.repo.deposit(world.device, world.device, plaintext).pin = world.annEngine.Pin()
	pass := world.ingestBo()
	if pass.Ingested != 0 || pass.Consumed != 0 || len(world.bo.messages) != 0 || world.bo.repo.standingCount(world.device) != 1 {
		t.Fatalf("a receipt depositor's deposit: pass %+v, %d messages", pass, len(world.bo.messages))
	}
}
