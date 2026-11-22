// The group mail lost after a delivered answer (TestE2eChurnLoad's runs 4, 5 and 8, track mail-group-ingest-loss): a
// deposit whose push is pinned before what the ingesting device retains, as a lagging depositor's is once two bases
// landed since it read, was classed MailDepositorUnknown on every pass and so stood forever, never written to m/ or
// i/, while its depositor had been answered delivered. It is now classed at the installed state, unjudged (QD-1178),
// and ingested. Beside it, the invariants a racing or refused ingest keeps: two passes racing on a group's deposits
// land each message once, a push refused 429 or 409 leaves its deposit for the next pass, and a message answered
// delivered is listed in the member's view through its r/ reference.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A group on a real authorization log: a general repo with the group inbox marker that the network's owner device
// created and so administers and ingests, a receiver device granted its deposit, and the ACL engine of the owner's
// device over that log, the tip installed.
type mailIngestRetainedGroup struct {
	net      *testConfigNet
	groupId  Id
	receiver testConfigDevice
	engine   *AclEngine
}

func newMailIngestRetainedGroup(t *testing.T) *mailIngestRetainedGroup {
	t.Helper()
	net := newTestConfigNet(t)
	receiver := net.admitMemberDevice("receiver")
	groupId := testConfigId("group repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: net.header(), RepoId: groupId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, Inbox: protocol.RepoInbox_REPO_INBOX_GROUP,
	})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: groupId.Bytes(), Subject: receiver.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT,
	})
	return &mailIngestRetainedGroup{
		net: net, groupId: groupId, receiver: receiver,
		engine: NewAclEngine(net.owner.sidecarId, AclEngineStatesOf(net.log), nil, nil),
	}
}

// Installs the log's tip in the owner device's engine, as its follower does at each entry.
func (self *mailIngestRetainedGroup) installTip(t *testing.T) {
	t.Helper()
	state, err := self.net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if err := self.engine.Install(state, nil); err != nil {
		t.Fatal(err)
	}
}

// Two bases folded past pin, as every confirmed ACL save lands one, and the tip installed: the log no longer
// retains pin.
func (self *mailIngestRetainedGroup) foldPast(t *testing.T, pin *bridge.AuthPin) {
	t.Helper()
	self.net.foldPast(pin.GetVersion())
	if _, err := self.net.log.StateAt(pin); !errors.Is(err, ErrConfigPinNotRetained) {
		t.Fatalf("the pin %d is still retained: %v", pin.GetVersion(), err)
	}
	self.installTip(t)
}

// The owner device's ingest authority over the engine.
func (self *mailIngestRetainedGroup) authority() *MailIngestAclAuthority {
	return &MailIngestAclAuthority{Engine: self.engine, Root: testMailIngestRoot, Clock: fixedClock{at: time.UnixMilli(self.net.timeMs)}}
}

// An ingest world over the group's repo, ingested by the owner device through the real authority.
func (self *mailIngestRetainedGroup) world(t *testing.T) (*mailIngestTestWorld, func() *MailIngestor) {
	t.Helper()
	world := newMailIngestTestWorld(t)
	world.repoId = self.groupId
	world.receiverId = self.receiver.sidecarId
	ingestor := func() *MailIngestor {
		return world.ingestor(func(args *MailIngestArgs) {
			args.SidecarId = self.net.owner.sidecarId
			args.Authority = self.authority()
		})
	}
	return world, ingestor
}

// A receiver's deposit of an internet message to the group, its push pinned at pin.
func (self *mailIngestRetainedGroup) deposit(t *testing.T, world *mailIngestTestWorld, subject string, pin *bridge.AuthPin) *mailIngestTestDeposit {
	t.Helper()
	message := testMailIngestMessage(subject, "body")
	trailer := testMailIngestTrailer(self.receiver.sidecarId, message)
	trailer.Recipients = []string{testMailIngestGroupAddress}
	return world.depositAt(self.receiver.sidecarId, testMailIngestPlaintext(t, message, trailer), pin)
}

// The root cause of the lost group mail, on a real authorization log: the receiver deposits on the state it holds, the
// group's writer then lands two bases, as its ACL saves did in the churn's rounds, and its pass reads the deposit at a
// pin its log answers ErrConfigPinNotRetained for. Before, ingest classed the receiver MailDepositorUnknown at that pin
// on every pass, so the deposit stood, its m/ and i/ never written, though the receiver had answered 250; a deposit
// the receiver pushed once it caught up was ingested beside it, as in run 5. Now the receiver, which still holds the
// group's deposit, is classed at the installed state and both are written once and consumed, with no alarm.
func TestMailIngestTakesAGroupDepositPinnedBeforeWhatTheWriterRetains(t *testing.T) {
	group := newMailIngestRetainedGroup(t)
	lagging := group.net.log.Pin()
	world, ingestor := group.world(t)
	behind := group.deposit(t, world, "Behind the saves", lagging)
	group.foldPast(t, lagging)
	caughtUp := group.deposit(t, world, "After the saves", group.net.log.Pin())

	authority := group.authority()
	if class := authority.DepositorClass(group.groupId, group.receiver.sidecarId, lagging); class != MailDepositorMail {
		t.Fatalf("the receiver at a pin the writer no longer retains is depositor class %d", class)
	}
	if !authority.Ingests(group.groupId, group.net.owner.sidecarId) {
		t.Fatal("the group's creating device does not ingest it")
	}
	pass := world.ingest(ingestor())
	if pass.Ingested != 2 || pass.Consumed != 2 || pass.Left+pass.Pending+pass.Unjudged+pass.Refused != 0 {
		t.Fatalf("pass %+v", pass)
	}
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	entries := world.entries(month)
	for _, deposit := range []*mailIngestTestDeposit{behind, caughtUp} {
		if world.store.file(MailMessagePath(month, deposit.id)) == nil {
			t.Errorf("no m/ file among %v", world.store.paths())
		}
		held := slices.ContainsFunc(entries, func(entry *protocol.IndexEntry) bool { return bytes.Equal(entry.GetId(), deposit.id.Bytes()) })
		if !held {
			t.Errorf("i/ holds no row of a deposit")
		}
	}
	if len(entries) != 2 || len(world.messagePaths()) != 2 {
		t.Errorf("%d rows and %d messages", len(entries), len(world.messagePaths()))
	}
	if world.repo.standingCount(group.receiver.sidecarId) != 0 || len(world.alarms) != 0 {
		t.Errorf("standing %d, alarms %v", world.repo.standingCount(group.receiver.sidecarId), world.alarmKinds())
	}
}

// The class of a depositor whose push is pinned before what the ingester retains, read at the installed state: in a
// personal network's group the member's device deposits mail, its read_only device none (its row's, whatever the pin)
// and a tagged sidecar the group's deposit grant does not reach stands unjudged rather than refused; in the member's
// mailbox an EvsShare subject stays a receipt depositor and the owner's receiver a mail depositor, while another
// member's device, which deposits nothing there now, stands unjudged. A pin ahead of the state, one off its chain,
// and a pin asked of an engine with no log stay unknown, as does any pin of an engine that holds no state. The same
// depositors at the installed pin keep their judged classes, the unjudged ones None.
func TestMailIngestClassesAnUnjudgedDepositorAtTheInstalledState(t *testing.T) {
	repos := newMailReposTestWorld(t)
	repos.fixture.view.pin = aclTestEnginePin(20, "tip")
	member, owner := repos.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	receiver := repos.fixture.device(member, owner.Bytes())
	pageWorker := repos.fixture.device(member, owner.Bytes())
	repos.fixture.admission(pageWorker).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	agent := repos.fixture.agent(member, repos.fixture.tag(member))
	other := repos.fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	friend := repos.fixture.invitedDevice(other)
	stranger := repos.fixture.invitedDevice(other)
	repos.fixture.configRepo(owner, member)
	mailboxId, mailbox := repos.fixture.repo(protocol.RepoKind_REPO_KIND_MAILBOX, member)
	mailbox.ConsentedSidecarIds = [][]byte{owner.Bytes(), receiver.Bytes()}
	mailbox.Shares = []*protocol.AclRepoShareRow{{Subject: friend.Bytes(), Signer: owner.Bytes(), At: repos.fixture.next()}}
	repos.rebuild()
	groupId := mailReposTestGroupWithMember(t, repos, repos.repos(owner), owner, member)
	state := repos.state()
	if rights := aclTestRights(state, agent, groupId, AclTokenAudienceEvs); rights != 0 {
		t.Fatalf("the tagged sidecar holds %b on the group", rights)
	}
	if rights := aclTestRights(state, stranger, mailboxId, AclTokenAudienceEvs); rights != 0 {
		t.Fatalf("another member's device holds %b on the mailbox", rights)
	}

	installed := state.Pin()
	engine := NewAclEngine(owner, &aclTestEngineStates{states: map[uint64]*AclState{20: state}, tip: 20, floor: 18}, nil, nil)
	if err := engine.Install(state, nil); err != nil {
		t.Fatal(err)
	}
	authority := &MailIngestAclAuthority{Engine: engine, Root: testMailIngestRoot, Clock: fixedClock{at: aclTestNow}}
	unretained := aclTestEnginePin(17, "tip")
	cases := []struct {
		label     string
		repoId    Id
		depositor Id
		unjudged  MailDepositorClass
		judged    MailDepositorClass
	}{
		{label: "the member's receiver in the group", repoId: groupId, depositor: receiver, unjudged: MailDepositorMail, judged: MailDepositorMail},
		{label: "the member's read_only device in the group", repoId: groupId, depositor: pageWorker, unjudged: MailDepositorNone, judged: MailDepositorNone},
		{label: "a tagged sidecar in the group", repoId: groupId, depositor: agent, unjudged: MailDepositorUnjudged, judged: MailDepositorNone},
		{label: "the share's subject in the mailbox", repoId: mailboxId, depositor: friend, unjudged: MailDepositorReceipts, judged: MailDepositorReceipts},
		{label: "the owner's receiver in the mailbox", repoId: mailboxId, depositor: receiver, unjudged: MailDepositorMail, judged: MailDepositorMail},
		{label: "another member's device in the mailbox", repoId: mailboxId, depositor: stranger, unjudged: MailDepositorUnjudged, judged: MailDepositorNone},
	}
	for _, c := range cases {
		if class := authority.DepositorClass(c.repoId, c.depositor, unretained); class != c.unjudged {
			t.Errorf("%s, pinned before what the ingester retains: class %d, not %d", c.label, class, c.unjudged)
		}
		if class := authority.DepositorClass(c.repoId, c.depositor, installed); class != c.judged {
			t.Errorf("%s, at the installed pin: class %d, not %d", c.label, class, c.judged)
		}
		if class := authority.DepositorClass(c.repoId, c.depositor, nil); class == MailDepositorUnjudged {
			t.Errorf("%s, at the installed state: unjudged", c.label)
		}
	}
	for _, pin := range []*bridge.AuthPin{aclTestEnginePin(21, "tip"), aclTestEnginePin(19, "fork")} {
		if class := authority.DepositorClass(groupId, receiver, pin); class != MailDepositorUnknown {
			t.Errorf("the receiver at a pin ahead of the state or off its chain (%d): class %d", pin.GetVersion(), class)
		}
	}
	// an engine with no log judges no pin but the installed one's, and tells none before its window
	noLog := NewAclEngine(owner, nil, nil, nil)
	if err := noLog.Install(state, nil); err != nil {
		t.Fatal(err)
	}
	unlogged := &MailIngestAclAuthority{Engine: noLog, Root: testMailIngestRoot, Clock: fixedClock{at: aclTestNow}}
	if class := unlogged.DepositorClass(groupId, receiver, unretained); class != MailDepositorUnknown {
		t.Errorf("an engine with no log classes an unretained pin %d", class)
	}
	empty := &MailIngestAclAuthority{Engine: NewAclEngine(owner, &aclTestEngineStates{tip: 20, floor: 18}, nil, nil), Root: testMailIngestRoot}
	if class := empty.DepositorClass(groupId, receiver, unretained); class != MailDepositorUnknown {
		t.Errorf("an engine with no state classes an unretained pin %d", class)
	}
}

// A deposit no state of the device judges stands, counting against no one: no alarm, no CONSUME, no m/, counted left
// and unjudged but not pending, so Run's next pass comes at its resync, not RetryInterval, since no later state
// judges the pin. A later deposit of the same depositor that is judged is ingested past it, the CONSUME naming it
// alone and consumed_through staying below the one left.
func TestMailIngestLeavesAnUnjudgedDepositStandingWithNoAlarmOrRetry(t *testing.T) {
	world := newMailIngestTestWorld(t)
	unjudged := world.depositMessage(testMailIngestMessage("Unjudged", "body"))
	unjudged.pin = aclTestEnginePin(3, "old")
	judged := world.depositMessage(testMailIngestMessage("Judged", "body"))
	judged.pin = aclTestEnginePin(9, "tip")
	world.authority.classes[world.receiverId] = MailDepositorUnjudged
	authority := &mailIngestTestPinAuthority{mailIngestTestAuthority: world.authority, unjudgedBelow: 5}

	clock := newTestConfigClock()
	settings := DefaultMailIngestSettings()
	settings.MinPassInterval = 0
	ingestor := world.ingestor(func(args *MailIngestArgs) {
		args.Authority = authority
		args.Settings = settings
		args.Clock = clock
	})
	pass := world.ingest(ingestor)
	if pass.Ingested != 1 || pass.Left != 1 || pass.Unjudged != 1 || pass.Pending != 0 || pass.Refused != 0 || pass.Consumed != 1 {
		t.Fatalf("pass %+v", pass)
	}
	if len(world.repo.consumes) != 1 || !slices.Equal(world.repo.consumes[0].depositIds, []Id{judged.id}) || world.repo.consumes[0].consumedThrough != 0 {
		t.Errorf("consumes %+v", world.repo.consumes)
	}
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	if world.store.file(MailMessagePath(month, unjudged.id)) != nil || world.repo.standingCount(world.receiverId) != 1 || len(world.alarms) != 0 {
		t.Errorf("m/ %v, standing %d, alarms %v", world.messagePaths(), world.repo.standingCount(world.receiverId), world.alarmKinds())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ingestor.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	// Run's first pass leaves the unjudged deposit again and arms only its resync
	if armed := <-clock.armed; armed != settings.ResyncInterval {
		t.Fatalf("the next pass is armed %s on, not the resync's %s", armed, settings.ResyncInterval)
	}
}

// The world's authority where a depositor it classes MailDepositorUnjudged is one the installed state gives no right:
// its deposits pinned below unjudgedBelow are unjudged, as a device whose log no longer retains their pins classes
// them, and those pinned at or above it, which the log judges, and the installed state's own answer are mail. Every
// other depositor is as the world's authority classes it.
type mailIngestTestPinAuthority struct {
	*mailIngestTestAuthority
	unjudgedBelow uint64
}

func (self *mailIngestTestPinAuthority) DepositorClass(repoId Id, depositorId Id, pin *bridge.AuthPin) MailDepositorClass {
	class := self.mailIngestTestAuthority.DepositorClass(repoId, depositorId, pin)
	if class != MailDepositorUnjudged {
		return class
	}
	if pin != nil && pin.GetVersion() < self.unjudgedBelow {
		return MailDepositorUnjudged
	}
	return MailDepositorMail
}

// A deposit ref takes only its depositor's own deposits (§11.8's refs table), which the evs read no longer holds for
// a push it takes unjudged (QD-1178): a deposit on the receiver's ref that another sidecar signed is consumed
// unrecorded with the depositor alarm, whatever the class the ref's depositor holds, and the receiver's own is ingested.
func TestMailIngestRefusesADepositAnotherSidecarSigned(t *testing.T) {
	world := newMailIngestTestWorld(t)
	message := testMailIngestMessage("Planted", "body")
	planted := world.repo.deposit(world.receiverId, NewId(), testMailIngestPlaintext(t, message, testMailIngestTrailer(world.receiverId, message)))
	own := world.depositMessage(testMailIngestMessage("Own", "body"))
	pass := world.ingest(world.ingestor(nil))
	if pass.Ingested != 1 || pass.Refused != 1 || pass.Consumed != 2 || pass.Left != 0 {
		t.Fatalf("pass %+v", pass)
	}
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	if world.store.file(MailMessagePath(month, planted.id)) != nil || world.store.file(MailMessagePath(month, own.id)) == nil {
		t.Errorf("m/ holds %v", world.messagePaths())
	}
	if !slices.Equal(world.alarmKinds(), []MailIngestAlarmKind{MailIngestAlarmDepositor}) || world.alarms[0].MessageId != planted.id {
		t.Errorf("alarms %+v", world.alarms)
	}
}

// Two passes racing on a group's deposits, a receiver's two and a same-network sender's, land each message once: the
// second pass runs whole between the first's read of i/ and its first push, so the first meets the conflict on that
// message's m/ and only consumes it, finds the receiver's later message, which its read of the ref still held, standing
// in m/ too, and reads the sender's ref with nothing left standing. Each message holds one m/ and one i/ row, every
// deposit is consumed, and only the pass whose push wrote a message announces it.
func TestMailIngestRacingPassesOnAGroupLandEachMessageOnce(t *testing.T) {
	world := newMailIngestTestWorld(t)
	senderId := NewId()
	deposits := []*mailIngestTestDeposit{}
	for _, subject := range []string{"First", "Second"} {
		message := testMailIngestMessage(subject, "body")
		trailer := testMailIngestTrailer(world.receiverId, message)
		trailer.Recipients = []string{testMailIngestGroupAddress}
		deposits = append(deposits, world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, trailer)))
	}
	sent := world.repo.deposit(senderId, senderId, testMailIngestGroupSend(t, testMailIngestRecipient, "lunch"))
	first, second := world.ingestor(nil), world.ingestor(nil)
	var secondPass *MailIngestPass
	world.store.beforeWrite = func() {
		pass, err := second.Ingest(context.Background())
		if err != nil {
			t.Error(err)
		}
		secondPass = pass
	}
	firstPass := world.ingest(first)
	if secondPass == nil || secondPass.Ingested != 3 || secondPass.Consumed != 3 {
		t.Fatalf("the pass that won: %+v", secondPass)
	}
	if firstPass.Present != 2 || firstPass.Ingested != 0 || firstPass.Consumed != 2 || firstPass.Left != 0 {
		t.Fatalf("the pass that lost: %+v", firstPass)
	}
	ids := []Id{deposits[0].id, deposits[1].id, sent.id}
	months := []MailYearMonth{MailYearMonthOf(testMailIngestReceiveMillis), MailYearMonthOf(testMailIngestReceiveMillis), MailYearMonthOf(uint64(testMailIngestPushMillis))}
	rows := map[Id]int{}
	for _, month := range []MailYearMonth{months[0], months[2]} {
		for _, entry := range world.entries(month) {
			rows[Id(entry.GetId())] += 1
		}
	}
	for i, id := range ids {
		if world.store.file(MailMessagePath(months[i], id)) == nil || rows[id] != 1 {
			t.Errorf("message %d: m/ %v, %d rows", i, world.messagePaths(), rows[id])
		}
	}
	if len(world.messagePaths()) != 3 || len(rows) != 3 {
		t.Errorf("%d messages and %d ids in i/", len(world.messagePaths()), len(rows))
	}
	if world.repo.standingCount(world.receiverId) != 0 || world.repo.standingCount(senderId) != 0 || len(world.messages) != 3 {
		t.Errorf("standing %d and %d, %d message callbacks", world.repo.standingCount(world.receiverId), world.repo.standingCount(senderId), len(world.messages))
	}
}

// An ingest push evs refuses leaves its deposit standing for the next pass, which ingests it once: 429
// RESOURCE_EXHAUSTED past the governor's shed, and a 409 PATH_CONFLICT the store gave back without naming m/, a parent
// directory's delta that a racing creation kept refusing. Nothing of the refused pass is written or consumed, the
// deposits before it are, and no message is announced until its push lands.
func TestMailIngestRefusedPushLeavesItsDepositForTheNextPass(t *testing.T) {
	refusals := []struct {
		label string
		err   error
	}{
		{label: "429 RESOURCE_EXHAUSTED", err: &EvsError{
			Status: http.StatusTooManyRequests, Code: protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED, RetryAfter: time.Second,
		}},
		{label: "409 PATH_CONFLICT on a directory", err: &EvsPathConflictError{
			Refusal: &EvsError{Status: http.StatusConflict, Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT}, Paths: []string{},
		}},
	}
	for _, refusal := range refusals {
		world := newMailIngestTestWorld(t)
		landed := world.depositMessage(testMailIngestMessage("Landed", "body"))
		refused := world.depositMessage(testMailIngestMessage("Refused", "body"))
		// the first push lands; the second's is refused
		world.store.beforeWrite = func() {
			world.store.beforeWrite = func() {
				world.store.failWrite = refusal.err
			}
		}
		pass, err := world.ingestor(nil).Ingest(context.Background())
		if !errors.Is(err, refusal.err) || pass.Ingested != 1 || pass.Consumed != 1 {
			t.Fatalf("%s: the refused pass %+v, %v", refusal.label, pass, err)
		}
		month := MailYearMonthOf(testMailIngestReceiveMillis)
		if world.store.file(MailMessagePath(month, refused.id)) != nil || world.repo.standingCount(world.receiverId) != 1 {
			t.Fatalf("%s: m/ %v, standing %d", refusal.label, world.messagePaths(), world.repo.standingCount(world.receiverId))
		}
		if len(world.repo.consumes) != 1 || !slices.Equal(world.repo.consumes[0].depositIds, []Id{landed.id}) || len(world.messages) != 1 {
			t.Errorf("%s: consumes %+v, %d message callbacks", refusal.label, world.repo.consumes, len(world.messages))
		}

		next := world.ingest(world.ingestor(nil))
		if next.Ingested != 1 || next.Consumed != 1 || next.Present+next.Left != 0 {
			t.Fatalf("%s: the next pass %+v", refusal.label, next)
		}
		entries := world.entries(month)
		if len(world.messagePaths()) != 2 || len(entries) != 2 || world.repo.standingCount(world.receiverId) != 0 || len(world.messages) != 2 {
			t.Errorf("%s: %v, %d rows, standing %d", refusal.label, world.messagePaths(), len(entries), world.repo.standingCount(world.receiverId))
		}
	}
}

// A message answered delivered is listed: a group's deposit pinned before what its writer retains, beside one pinned
// at the tip, is written to the group's m/ and i/ by the writer's pass, the member's device then adds its r/ reference
// in the member's mailbox, and the member's view lists both, in the group's repo, once each. Before, the first stood
// as a deposit through every pass and the view never listed it.
func TestMailGroupMessageAnsweredDeliveredIsListed(t *testing.T) {
	group := newMailIngestRetainedGroup(t)
	lagging := group.net.log.Pin()
	world, ingestor := group.world(t)
	behind := group.deposit(t, world, "Behind the saves", lagging)
	group.foldPast(t, lagging)
	caughtUp := group.deposit(t, world, "After the saves", group.net.log.Pin())
	if pass := world.ingest(ingestor()); pass.Ingested != 2 || pass.Consumed != 2 {
		t.Fatalf("the writer's pass %+v", pass)
	}

	mailboxId := NewId()
	mailbox := &mailTestRemoveStore{mailTestStore: newMailTestStore()}
	refs := newMailGroupRefs(group.groupId, world.store, mailbox, world.repo.Erasures, nil)
	if result, err := refs.Sync(context.Background()); err != nil || result.Added != 2 {
		t.Fatalf("the member's sync: %+v, %v", result, err)
	}
	view := NewMailView(&MailViewArgs{
		MailboxId: mailboxId,
		Mailbox:   mailbox,
		Groups: func(ctx context.Context, repoId Id) (mailStore, error) {
			if repoId == group.groupId {
				return world.store, nil
			}
			return nil, ErrEvsPathAbsent
		},
		Settings: DefaultMailStoreSettings(),
	})
	listed, _ := testMailListAll(t, view, MailFolderAll, "", 0)
	counts := map[Id]int{}
	for _, entry := range listed {
		if entry.RepoId != group.groupId {
			t.Errorf("an entry listed in repo %s, not the group's", entry.RepoId)
		}
		counts[Id(entry.Entry.GetId())] += 1
	}
	if len(listed) != 2 || counts[behind.id] != 1 || counts[caughtUp.id] != 1 {
		t.Errorf("the view lists %d entries: %v", len(listed), counts)
	}
}
