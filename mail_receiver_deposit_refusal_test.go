//go:build !sidecar_http && !js && !ios_extension

// A receiver's deposit right is the send side's (mail_deposit.go's right and never rows; QD-1173, D-KEYS-17, §15.5):
// it deposits mail only where the exchange mints it repo:<id>:deposit and the repo takes mail, a mailbox or a general
// repo its RepoCreate marks an inbox, and never as §16.8's receipt deposit. A repo its state holds as taking no mail,
// such as a group's repo left unmarked whose deposit grant the exchange honors but for which gkm serves no drop key,
// is answered 550 5.1.1 at RCPT on the sender's first try, before gkm is asked, where the receiver answered 451 4.3.0
// on every retry for days. A deposit into an inbox repo still lands.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A gkm that serves no drop key, as gkm serves none for a repo whose generations publish none, counting each repo's
// asks.
type mailReceiverRefusalTestGkm struct {
	gkmRefusingClient
	stateLock   sync.Mutex
	dropKeyAsks map[Id]int
}

func (self *mailReceiverRefusalTestGkm) DropKey(ctx context.Context, repoId Id) (*GkmDropKey, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dropKeyAsks[repoId] += 1
	return nil, fmt.Errorf("%w: generation 1 publishes no drop key", ErrGkmKeyMissing)
}

// The drop keys asked of repoId so far.
func (self *mailReceiverRefusalTestGkm) asks(repoId Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.dropKeyAsks[repoId]
}

// A repo the production rule judges on its client's verified state (mailEvsDepositRepo), whose deposit lands in land
// rather than at evs.
type mailReceiverRefusalTestRepo struct {
	mailEvsDepositRepo
	land mailDepositRepo
}

func (self *mailReceiverRefusalTestRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	return self.land.Deposit(ctx, args)
}

// Adds two group repos to net, each with group-create's deposit grant to autogroup:member as a personal network files
// it (QD-1180): unmarked, which takes no mail, and marked a group inbox.
func mailReceiverRefusalTestGroups(net *aclExchangeNet) (unmarkedId Id, inboxId Id) {
	unmarkedId = testConfigId("receiver refusal unmarked group")
	inboxId = testConfigId("receiver refusal group inbox")
	net.withAclRows(func(rows *protocol.AclRows) {
		groups := []struct {
			repoId Id
			inbox  protocol.RepoInbox
		}{
			{repoId: unmarkedId, inbox: protocol.RepoInbox_REPO_INBOX_NONE},
			{repoId: inboxId, inbox: protocol.RepoInbox_REPO_INBOX_GROUP},
		}
		for _, group := range groups {
			rows.Repos = append(rows.Repos, &protocol.AclRepo{
				RepoId: group.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: group.inbox,
				Grants: []*protocol.AclRepoGrantRow{{
					Subject: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes(),
					Role:    protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT, Signer: net.owner.sidecarId.Bytes(), At: 1,
				}},
			})
		}
	})
	return unmarkedId, inboxId
}

// One state, both ends: for each receiver and repo the receiver's right is the send side's verdict, it deposits only
// where the exchange mints the deposit scope, and only a repo the state holds as taking no mail, by its kind or its
// unmarked RepoCreate, is refused for good. The old rule, the deposit bit alone, took four of these: a deposit grant in
// an unmarked general repo, the bug, whether the grant names the device or autogroup:member, for which gkm serves no
// drop key, so every retry answered 451; the vault, whose drop key ingest never reads mail under; and a mailbox's
// EvsShare subject, whose deposit is the receipt deposit, which ingest takes as no mail after the sender had its 250.
func TestMailReceiverDepositRightIsTheSendSides(t *testing.T) {
	net := newAclExchangeNet(t)
	unmarkedDepositId, inboxDepositId := mailReceiverRefusalTestGroups(net)
	inboxWriterId := testConfigId("receiver refusal inbox writer")
	adminInboxId := testConfigId("receiver refusal admin inbox")
	inboxReaderId := testConfigId("receiver refusal inbox reader")
	unmarkedDeviceDepositId := testConfigId("receiver refusal unmarked device deposit grant")
	unmarkedWriterId := testConfigId("receiver refusal unmarked writer")
	mailboxId := testConfigId("receiver refusal mailbox")
	absentId := testConfigId("receiver refusal absent")
	net.withAclRows(func(rows *protocol.AclRows) {
		grant := func(device testConfigDevice, role protocol.RepoGrantRole) *protocol.AclRepoGrantRow {
			return &protocol.AclRepoGrantRow{Subject: device.sidecarId.Bytes(), Role: role, Signer: net.owner.sidecarId.Bytes(), At: 1}
		}
		repo := func(repoId Id, inbox protocol.RepoInbox, grants ...*protocol.AclRepoGrantRow) {
			rows.Repos = append(rows.Repos, &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: inbox, Grants: grants})
		}
		writer, depositor, reader := protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER
		group, admin, none := protocol.RepoInbox_REPO_INBOX_GROUP, protocol.RepoInbox_REPO_INBOX_ADMIN, protocol.RepoInbox_REPO_INBOX_NONE
		repo(inboxWriterId, group, grant(net.phone, writer))
		repo(adminInboxId, admin, grant(net.phone, writer))
		repo(inboxReaderId, group, grant(net.phone, reader))
		repo(unmarkedDeviceDepositId, none, grant(net.phone, depositor))
		repo(unmarkedWriterId, none, grant(net.phone, writer))
		rows.Repos = append(rows.Repos, &protocol.AclRepo{
			RepoId: mailboxId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX, OwnerMemberId: net.ownerMemberId.Bytes(),
			ConsentedSidecarIds: [][]byte{net.owner.sidecarId.Bytes()},
			Shares:              []*protocol.AclRepoShareRow{{Subject: net.phone.sidecarId.Bytes(), Signer: net.owner.sidecarId.Bytes(), At: 1}},
		})
	})
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	test.client.args.Config = func() GkmAuthView { return net.log.State() }
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	now := test.client.clock.Now()
	cases := []struct {
		name     string
		receiver testConfigDevice
		repoId   Id
		// the deposit it may make now
		allowed bool
		// the repo is held as one that takes no mail: refused for good
		never bool
		// what the old rule, EvsAccess's deposit bit alone, answered
		oldAllowed bool
	}{
		{name: "a group inbox's deposit grant to autogroup:member", receiver: net.phone, repoId: inboxDepositId, allowed: true, oldAllowed: true},
		{name: "a group inbox's writer", receiver: net.phone, repoId: inboxWriterId, allowed: true, oldAllowed: true},
		{name: "the admin inbox's writer", receiver: net.phone, repoId: adminInboxId, allowed: true, oldAllowed: true},
		{name: "the mailbox's consented device, by its write", receiver: net.owner, repoId: mailboxId, allowed: true, oldAllowed: true},
		{name: "a group inbox's reader", receiver: net.phone, repoId: inboxReaderId},
		{name: "a read_only device the inbox's deposit grant names", receiver: net.readOnly, repoId: inboxDepositId},
		{name: "a repo the state does not hold", receiver: net.phone, repoId: absentId},
		{name: "the mailbox's EvsShare subject, whose deposit is a receipt", receiver: net.phone, repoId: mailboxId, oldAllowed: true},
		{name: "an unmarked group repo's deposit grant to autogroup:member", receiver: net.phone, repoId: unmarkedDepositId, never: true, oldAllowed: true},
		{name: "an unmarked group repo's deposit grant to the device", receiver: net.phone, repoId: unmarkedDeviceDepositId, never: true, oldAllowed: true},
		{name: "an unmarked group repo's writer", receiver: net.phone, repoId: unmarkedWriterId, never: true},
		{name: "an unmarked general repo members write", receiver: net.phone, repoId: net.notesId, never: true},
		{name: "the vault, by its consented device's write", receiver: net.owner, repoId: net.vaultId, never: true, oldAllowed: true},
	}
	for _, c := range cases {
		repo := mailEvsDepositRepo{EvsRepo: test.client.Repo(c.repoId)}
		allowed, known := repo.depositRight(c.receiver.sidecarId)
		if allowed != c.allowed || !known {
			t.Errorf("%s: deposit %t known %t, not %t", c.name, allowed, known, c.allowed)
		}
		if takes, known := repo.takesMail(); (known && !takes) != c.never {
			t.Errorf("%s: takes mail %t known %t, never %t", c.name, takes, known, c.never)
		}
		depositor, err := NewMailDepositor(&MailDepositorArgs{Repo: test.client.Repo, ReceiverSidecarId: c.receiver.sidecarId})
		if err != nil {
			t.Fatal(err)
		}
		targets := []*MailDepositTarget{{RepoId: c.repoId, Recipients: []string{testMailSessionAlice}}}
		if depositor.takesNoMail(c.repoId) != c.never || depositor.refuses(targets) == c.allowed {
			t.Errorf("%s: the depositor's never %t and refuses %t", c.name, depositor.takesNoMail(c.repoId), depositor.refuses(targets))
		}
		if delivered := mailSendMayDeposit(acl, c.receiver.sidecarId, c.repoId, now) == MailSendDelivered; delivered != allowed {
			t.Errorf("%s: the send side answers delivered %t, the receiver %t", c.name, delivered, allowed)
		}
		scope := aclExchangeScope(c.repoId, "deposit")
		if allowed && !slices.Contains(net.exchange(t, c.receiver, AclTokenAudienceEvs, scope).Scopes, scope) {
			t.Errorf("%s: allowed where the exchange mints no deposit", c.name)
		}
		if old := acl.EvsAccess(AclSidecarSubject(c.receiver.sidecarId), c.repoId, AclTokenAudienceEvs, now).Rights.Has(AclEvsDeposit); old != c.oldAllowed {
			t.Errorf("%s: the deposit bit %t, not %t", c.name, old, c.oldAllowed)
		}
	}
}

// Through the production depositor and evs client, a deposit into a group repo left unmarked, which the exchange
// would mint the receiver's deposit scope for, is refused for good on the first try and on every retry, before gkm is
// asked, alone or beside an inbox, so no repo takes a copy; where it reached gkm, which serves such a repo no drop key,
// and answered 451 4.3.0 each time. A group inbox's deposit passes the receiver's judgment and goes on to gkm.
func TestMailReceiverRefusesARepoThatTakesNoMailBeforeGkmIsAsked(t *testing.T) {
	net := newAclExchangeNet(t)
	unmarkedId, inboxId := mailReceiverRefusalTestGroups(net)
	for _, repoId := range []Id{unmarkedId, inboxId} {
		scope := aclExchangeScope(repoId, "deposit")
		if !slices.Contains(net.exchange(t, net.phone, AclTokenAudienceEvs, scope).Scopes, scope) {
			t.Fatalf("the exchange mints the receiver no deposit scope on %s", repoId)
		}
	}
	gkm := &mailReceiverRefusalTestGkm{dropKeyAsks: map[Id]int{}}
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	test.client.args.Config = func() GkmAuthView { return net.log.State() }
	test.client.args.Gkm = gkm
	depositor, err := NewMailDepositor(&MailDepositorArgs{Repo: test.client.Repo, ReceiverSidecarId: net.phone.sidecarId})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	deposit := func(subject string, repoIds ...Id) error {
		targets := []*MailDepositTarget{}
		for _, repoId := range repoIds {
			targets = append(targets, &MailDepositTarget{RepoId: repoId, Recipients: []string{testMailSessionAlice}})
		}
		return depositor.Deposit(ctx, &MailDepositInput{Spool: newMailDepositTestSpool(t, testMailSessionMessage(subject)), Targets: targets})
	}
	for try := range 3 {
		if err := deposit(fmt.Sprintf("try %d", try), unmarkedId); !errors.Is(err, ErrMailDepositRefused) || !errors.Is(err, ErrMailDepositFailed) {
			t.Fatalf("try %d: %v", try, err)
		}
	}
	if err := deposit("beside an inbox", inboxId, unmarkedId); !errors.Is(err, ErrMailDepositRefused) {
		t.Fatalf("beside an inbox: %v", err)
	}
	if unmarked, inbox := gkm.asks(unmarkedId), gkm.asks(inboxId); unmarked != 0 || inbox != 0 {
		t.Fatalf("gkm asked for %d drop keys of the unmarked repo and %d of the inbox", unmarked, inbox)
	}
	// what the session reads at RCPT
	if !depositor.takesNoMail(unmarkedId) || depositor.takesNoMail(inboxId) {
		t.Fatalf("takes no mail: unmarked %t, inbox %t", depositor.takesNoMail(unmarkedId), depositor.takesNoMail(inboxId))
	}
	if err := deposit("to the inbox", inboxId); errors.Is(err, ErrMailDepositRefused) || !errors.Is(err, ErrGkmKeyMissing) {
		t.Fatalf("to the inbox: %v", err)
	}
	if asks := gkm.asks(inboxId); asks != 1 {
		t.Fatalf("gkm asked for %d drop keys of the inbox", asks)
	}
}

// Through the session, a recipient whose group repo takes no mail is answered 550 5.1.1 at RCPT on the sender's first
// try, that recipient alone: a recipient whose group repo is an inbox in the same transaction is taken, its message
// lands there with a trailer naming it alone, and the refused recipient's answer stays the same in a later
// transaction, nothing of it reaching a repo. The old rule took the recipient at RCPT, and its deposit, its deposit
// grant honored, waited on gkm for a drop key that never comes and answered 451 4.3.0 on every retry.
func TestMailSessionAnswers550AtRcptForARepoThatTakesNoMail(t *testing.T) {
	net := newAclExchangeNet(t)
	unmarkedId, inboxId := mailReceiverRefusalTestGroups(net)
	test := newEvsTestClient(t, http.NotFoundHandler(), newEvsTestStore(t))
	test.client.args.Config = func() GkmAuthView { return net.log.State() }
	var world *mailSessionTestWorld
	world = newMailSessionTestWorld(t, func(args *MailSessionArgs) {
		args.Depositor = newMailDepositor(func(repoId Id) mailDepositRepo {
			return &mailReceiverRefusalTestRepo{
				mailEvsDepositRepo: mailEvsDepositRepo{EvsRepo: test.client.Repo(repoId)},
				land:               &mailSessionTestRepo{world: world, repoId: repoId},
			}
		}, &MailDepositorArgs{ReceiverSidecarId: net.phone.sidecarId})
	})
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		// two group records: one naming a repo left unmarked, one naming an inbox
		world.recipients[testMailSessionAlice].RepoId = unmarkedId
		world.recipients[testMailSessionBob].RepoId = inboxId
	}()
	sender := world.open(testMailSessionIngress(t))
	sender.expect("EHLO mail.sender.example", 250)
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	if code, message := sender.command("RCPT TO:<" + testMailSessionAlice + ">"); code != 550 || !strings.HasPrefix(message, "5.1.1") {
		t.Fatalf("RCPT to the unmarked group answered %d %s", code, message)
	}
	sender.expect("RCPT TO:<"+testMailSessionBob+">", 250)
	codes, messages := sender.data(testMailSessionMessage("to both groups"))
	if code, message := <-codes, <-messages; code != 250 {
		t.Fatalf("DATA answered %d %s", code, message)
	}
	deposits := world.takenDeposits()
	if len(deposits) != 1 || deposits[0].repoId != inboxId || !slices.Equal(deposits[0].trailer.GetRecipients(), []string{testMailSessionBob}) {
		t.Fatalf("deposits %+v", deposits)
	}
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	if code, message := sender.command("RCPT TO:<" + testMailSessionAlice + ">"); code != 550 || !strings.HasPrefix(message, "5.1.1") {
		t.Fatalf("a later RCPT to the unmarked group answered %d %s", code, message)
	}
	if calls, _ := world.depositCalls.Get(); calls != 1 {
		t.Fatalf("%d deposits reached a repo", calls)
	}
}
