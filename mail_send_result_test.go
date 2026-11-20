//go:build !sidecar_http && !js && !ios_extension

// QD-1122's calls on MAIL-M7-17's client world (mail_send_result.go): CheckSend hands the bound sender the message Send
// would make and keeps, deposits, queues and asks nothing, and with no sender bound prices it through the member's
// consented prover hosts' p/ records with modes from or/; SendResult finds a send's record by the send_id it names, on
// the composing device and on another device of the member, after the o/ entry is gone too, answers queued for an entry
// no host has written outcomes for yet, and unknown for anything else; and the send watch raises mail_send once for each
// outcome that changed since its last read, none for a change of time alone, none at its baseline, none for a record
// naming no send, and a restart raises only what changed since its kept read.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The send world with the outbox's signer the device's identity key in the verified state, a second consented device of
// the member, its phone, and a device of another member, and every mail_send the client raised.
type mailSendResultTestWorld struct {
	*mailClientTestWorld
	parts     *mailSendTestParts
	mailboxId Id
	signer    *testMailOutboxSigner
	phone     Id
	stranger  Id

	stateLock sync.Mutex
	events    []SidecarEvent
}

func newMailSendResultTestWorld(t *testing.T) *mailSendResultTestWorld {
	t.Helper()
	world, parts, mailboxId := newMailSendTestWorld(t)
	self := &mailSendResultTestWorld{mailClientTestWorld: world, parts: parts, mailboxId: mailboxId, signer: newTestMailOutboxSigner(world.device)}
	testMailSendBindOutbox(world, self.signer, testMailOutboxStanding(AbuseStandingStandard, true))
	fixture := world.repos.fixture
	fixture.admission(world.device).Row.IdentityPublicKey = self.signer.publicKey()
	self.phone = fixture.device(world.member, world.device.Bytes())
	_, self.stranger = fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.repos.rebuild()
	self.bindClient(world.client)
	return self
}

// Binds client on the world's newest state, its mail_send events kept.
func (self *mailSendResultTestWorld) bindClient(client *MailClient) {
	self.t.Helper()
	binding, _, err := client.bound()
	if err != nil {
		self.t.Fatal(err)
	}
	if err := binding.Engine.Install(self.repos.state(), nil); err != nil {
		self.t.Fatal(err)
	}
	copied := *binding
	copied.Event = func(event SidecarEvent) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.events = append(self.events, event)
	}
	client.Bind(&copied)
}

// The mail_send events raised so far, by the send each names.
func (self *mailSendResultTestWorld) mailSends() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sendIds := []Id{}
	for _, event := range self.events {
		if event.Kind == SidecarEventMailSend && event.SendId != nil {
			sendIds = append(sendIds, *event.SendId)
		}
	}
	return sendIds
}

// A client of another device of the member over the same mailbox, as a phone of the member reads it.
func (self *mailSendResultTestWorld) deviceClient(sidecarId Id) *MailClient {
	self.t.Helper()
	client, err := NewMailClient(&MailClientArgs{NetworkId: testNetworkId, SidecarId: sidecarId, Store: newTestMemoryStore(), Log: self.log})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	engine := NewAclEngine(sidecarId, nil, nil, nil)
	if err := engine.Install(self.repos.state(), nil); err != nil {
		self.t.Fatal(err)
	}
	client.partsOverride = self.parts
	client.Bind(&MailBinding{Engine: engine, Network: testMailIngestNetwork, Gate: self.gate, Api: self.api})
	return client
}

// The member's mailbox as a prover host reaches it.
func (self *mailSendResultTestWorld) mailbox() *mailSmtpMailbox {
	return newMailSmtpMailbox(self.ingest.store, nil, nil, nil, nil)
}

// An o/ entry under effectKey whose message names sendId, as a prover host finds one, its signature not one any reader
// here holds it to.
func (self *mailSendResultTestWorld) plantOutbox(effectKey []byte, sendId Id) {
	self.t.Helper()
	path, err := MailOutboxPath(effectKey)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.ingest.store.Write(context.Background(), []*mailStoreWrite{{Path: path, Content: mailOutboxFileBytes([]byte("signed"), testMailOutboxMessage(sendId)), IfVersion: 0}}); err != nil {
		self.t.Fatal(err)
	}
}

// Writes or/ under effectKey as a prover host does.
func (self *mailSendResultTestWorld) writeOutcomes(effectKey []byte, outcomes ...*SmtpDomainOutcome) {
	self.t.Helper()
	if err := self.mailbox().WriteOutcomes(context.Background(), effectKey, outcomes); err != nil {
		self.t.Fatal(err)
	}
}

// The outcomes result holds, as domain:outcome words in order.
func testMailSendResultWords(result *SmtpSendResult) []string {
	words := []string{}
	for _, outcome := range result.Domains {
		words = append(words, outcome.Domain+":"+[]string{"", "sent", "queued", "deferred", "too_large", "refused", "tls_refused", "failed"}[outcome.Outcome])
	}
	return words
}

// A bound sender's check, kept as it was called.
type testMailSendChecker struct {
	stateLock sync.Mutex
	messages  []*SmtpOutboundMessage
}

func (self *testMailSendChecker) Check(ctx context.Context, message *SmtpOutboundMessage) (*SmtpSendCheck, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.messages = append(self.messages, message)
	return &SmtpSendCheck{Domains: []*SmtpDomainCheck{{Domain: "outside.example", Mode: SmtpModeBdat, ByteCount: 1, CapByteCount: 2, Prediction: SmtpCheckOk}}}, nil
}

// With a sender bound, CheckSend hands it the message Send would make: the internet recipients alone, Bcc gone from the
// header, a send id its Message-ID names under the From's domain, a fresh 32-byte effect key and an envelope sender of
// the bounce address's form; it answers the sender's check, and keeps, deposits and queues nothing and asks no gate. A
// draft to members alone checks no domain and reaches no sender, and a From Send refuses is refused.
func TestMailCheckSendHandsTheBoundSenderTheMessageSendWouldMake(t *testing.T) {
	world := newMailSendResultTestWorld(t)
	checker := &testMailSendChecker{}
	binding, _, _ := world.client.bound()
	copied := *binding
	copied.Sender = checker
	world.client.Bind(&copied)
	writesBefore := world.ingest.store.writeCount
	actionsBefore, _ := world.gate.counts()

	check, err := world.client.CheckSend(context.Background(), testMailSubmitDraft())
	if err != nil {
		t.Fatal(err)
	}
	if len(check.Domains) != 1 || check.Domains[0].Domain != "outside.example" || check.Domains[0].CapByteCount != 2 {
		t.Fatalf("the check answered %+v", check.Domains)
	}
	if len(checker.messages) != 1 {
		t.Fatalf("the sender checked %d messages", len(checker.messages))
	}
	message := checker.messages[0]
	if !slices.Equal(message.Recipients, []string{"someone@outside.example", "hidden@elsewhere.example"}) {
		t.Errorf("the check's recipients %v", message.Recipients)
	}
	if bytes.Contains(message.Message, []byte("hidden@")) || !bytes.Contains(message.Message, []byte("From: "+testMailSendFrom+"\r\n")) ||
		!bytes.Contains(message.Message, []byte("Subject: Plans\r\n")) {
		t.Errorf("the checked message:\n%s", message.Message)
	}
	if sendId, ok := MailOutboxSendIdOf(message.Message); !ok || sendId != message.SendId ||
		!bytes.Contains(message.Message, []byte("@acme.root.example>\r\n")) {
		t.Error("the message's id is not an internet send's under the From's domain")
	}
	if len(message.EffectKey) != mailEffectKeyByteCount {
		t.Errorf("an effect key of %d bytes", len(message.EffectKey))
	}
	if local, domain, ok := SplitSmtpEnvelopeAddress(message.Sender); !ok || !strings.HasPrefix(local, "bounces+") || domain != "b.acme.root.example" {
		t.Errorf("the envelope sender is no bounce address of the network")
	}
	if world.ingest.store.writeCount != writesBefore || len(world.parts.snapshot()) != 0 {
		t.Errorf("a check wrote %d times and deposited %d", world.ingest.store.writeCount-writesBefore, len(world.parts.snapshot()))
	}
	if actionsAfter, _ := world.gate.counts(); actionsAfter != actionsBefore {
		t.Error("a check asked the gate")
	}

	members, err := world.client.CheckSend(context.Background(), &MailSendArgs{From: testMailSendFrom, To: []string{testMailIngestRecipient}, Text: "x"})
	if err != nil || members == nil || len(members.Domains) != 0 || len(checker.messages) != 1 {
		t.Errorf("a check of mail to members answered %+v, %v, the sender called %d times", members, err, len(checker.messages))
	}
	if _, err := world.client.CheckSend(context.Background(), &MailSendArgs{From: "someone@outside.example", To: []string{"a@outside.example"}}); !errors.Is(err, ErrMailSendFromRefused) {
		t.Errorf("a From outside the network checked: %v", err)
	}
}

// With no sender bound, CheckSend prices the message on the member's consented prover hosts' p/ records: the largest
// cap among them, another member's device's passed over, a delay on the host the hash picks, the mode unknown until
// or/ names it; the prediction follows the size against that cap; and the check writes nothing.
func TestMailCheckSendWithNoSenderPricesOnTheMembersProverRecords(t *testing.T) {
	world := newMailSendResultTestWorld(t)
	ctx := context.Background()
	now := time.UnixMilli(testMailIngestPushMillis)
	for sidecarId, capByteCount := range map[Id]uint64{world.device: 1024, world.phone: 2048, world.stranger: 8192} {
		record := &SmtpProverRecord{
			Measure: SmtpProverMeasure{
				DataProofBytes: capByteCount, DataBytesPerSecond: 512, MeasureTime: now, UnitTime: 5 * time.Second,
				HeadByteCount: 831, HeaderRecordByteCount: 1199, EnvelopeGroupCount: 13,
			},
			KeySet:      bytes.Repeat([]byte{0x6b}, 32),
			ReadySuites: []uint16{0x1301},
		}
		if err := world.mailbox().WriteProverRecord(ctx, sidecarId, record); err != nil {
			t.Fatal(err)
		}
	}
	draft := func(text string) *MailSendArgs {
		return &MailSendArgs{From: testMailSendFrom, To: []string{"someone@outside.example"}, Subject: "Plans", Text: text}
	}
	checkOne := func(text string) *SmtpDomainCheck {
		t.Helper()
		writesBefore := world.ingest.store.writeCount
		check, err := world.client.CheckSend(ctx, draft(text))
		if err != nil {
			t.Fatal(err)
		}
		if world.ingest.store.writeCount != writesBefore {
			t.Fatal("a check wrote to the mailbox")
		}
		if len(check.Domains) != 1 || check.Domains[0].Domain != "outside.example" {
			t.Fatalf("the check answered %+v", check.Domains)
		}
		return check.Domains[0]
	}
	large := strings.Repeat("A line of the body, long enough to pass a small cap.\r\n", 80)

	if small := checkOne("Dinner at eight."); small.CapByteCount != 2048 || small.Mode != SmtpModeUnknown || small.Prediction != SmtpCheckOk ||
		small.ExpectedDelay <= 0 || 2048 <= small.ByteCount {
		t.Errorf("a small message before any outcome: %+v", small)
	}
	if over := checkOne(large); over.Prediction != SmtpCheckUnknown || over.ByteCount <= 2048 {
		t.Errorf("a large message to a domain of unknown mode: %+v", over)
	}
	// or/ names the domain's mode, as a prover host's session found it
	world.writeOutcomes(testMailOutboxEffectKey(), &SmtpDomainOutcome{Domain: "outside.example", Mode: SmtpModeData, Outcome: SmtpOutcomeSent, UpdateTime: now, TlsLevel: SmtpTlsLevelDane})
	if over := checkOne(large); over.Mode != SmtpModeData || over.Prediction != SmtpCheckTooLarge || over.CapByteCount != 2048 {
		t.Errorf("a large message to a DATA domain: %+v", over)
	}
	if small := checkOne("Dinner at eight."); small.Mode != SmtpModeData || small.Prediction != SmtpCheckOk {
		t.Errorf("a small message to a DATA domain: %+v", small)
	}
}

// SendResult finds a send by its id: queued at each domain while its entry stands and no host has written outcomes,
// then the outcomes a prover host wrote, in its order, on the composing device and on the member's phone alike, and
// after the entry is gone; an id no record or entry names is unknown, as is an entry signed by another member's device,
// and no send_id is invalid.
func TestMailSendResultReadsASendByItsId(t *testing.T) {
	world := newMailSendResultTestWorld(t)
	ctx := context.Background()
	sent, err := world.client.Send(ctx, testMailSubmitDraft())
	if err != nil {
		t.Fatal(err)
	}
	if len(sent.EffectKey) == 0 {
		t.Fatal("nothing was queued")
	}

	queued, err := world.client.SendResult(ctx, sent.SendId)
	if err != nil {
		t.Fatal(err)
	}
	if words := testMailSendResultWords(queued); !slices.Equal(words, []string{"outside.example:queued", "elsewhere.example:queued"}) || !bytes.Equal(queued.EffectKey, sent.EffectKey) {
		t.Fatalf("before any host: %v", words)
	}

	now := time.UnixMilli(testMailIngestPushMillis)
	world.writeOutcomes(sent.EffectKey,
		&SmtpDomainOutcome{Domain: "outside.example", Mode: SmtpModeBdat, Outcome: SmtpOutcomeSent, UpdateTime: now, TlsLevel: SmtpTlsLevelDane},
		&SmtpDomainOutcome{Domain: "elsewhere.example", Mode: SmtpModeData, Outcome: SmtpOutcomeDeferred, RetryAfter: time.Minute, UpdateTime: now},
	)
	if named, _, err := world.mailbox().ReadSendOutcomes(ctx, sent.EffectKey); err != nil || named != sent.SendId {
		t.Fatalf("the record names another send: %v", err)
	}
	want := []string{"outside.example:sent", "elsewhere.example:deferred"}
	phone := world.deviceClient(world.phone)
	for name, client := range map[string]*MailClient{"the composing device": world.client, "the phone": phone} {
		result, err := client.SendResult(ctx, sent.SendId)
		if err != nil || !slices.Equal(testMailSendResultWords(result), want) || result.Domains[1].RetryAfter != time.Minute {
			t.Errorf("%s reads %+v: %v", name, result, err)
		}
	}

	if err := world.mailbox().RemoveOutbox(ctx, sent.EffectKey); err != nil {
		t.Fatal(err)
	}
	for name, client := range map[string]*MailClient{"the composing device": world.client, "the phone": phone} {
		result, err := client.SendResult(ctx, sent.SendId)
		if err != nil || !slices.Equal(testMailSendResultWords(result), want) {
			t.Errorf("once the entry went, %s reads %+v: %v", name, result, err)
		}
	}

	// an entry another member's device signed names none of this member's sends
	forged := NewId()
	strangerSigner := newTestMailOutboxSigner(world.stranger)
	world.repos.fixture.admission(world.stranger).Row.IdentityPublicKey = strangerSigner.publicKey()
	world.repos.rebuild()
	world.bindClient(world.client)
	outbox := newTestMailOutbox(t, world.ingest.store, strangerSigner, testMailOutboxStanding(AbuseStandingStandard, true))
	if _, err := outbox.Queue(ctx, testMailOutboxQueueArgs(testMailOutboxEffectKey(), testMailOutboxMessage(forged))); err != nil {
		t.Fatal(err)
	}
	for _, sendId := range []Id{forged, NewId()} {
		if _, err := world.client.SendResult(ctx, sendId); !errors.Is(err, ErrMailSendUnknown) {
			t.Errorf("a send no consented device of the member queued read %v", err)
		}
	}
	if _, err := world.client.SendResult(ctx, Id{}); !errors.Is(err, ErrMailSendInvalid) {
		t.Errorf("no send_id read %v", err)
	}
}

// The send watch raises mail_send once for each outcome that changed since its last read: none at its baseline, none
// for a rewrite that changes only the time, none for a record that names no send or one that did not change, and a
// restart over the read it kept raises only what changed since.
func TestMailSendWatchRaisesOncePerChangedOutcome(t *testing.T) {
	world := newMailSendResultTestWorld(t)
	ctx := context.Background()
	now := time.UnixMilli(testMailIngestPushMillis)
	pass := func(client *MailClient, want int) {
		t.Helper()
		raised, err := client.passSendWatch(ctx)
		if err != nil || raised != want {
			t.Fatalf("a read raised %d, want %d: %v", raised, want, err)
		}
	}
	earlier, earlierKey := NewId(), testMailOutboxEffectKey()
	world.plantOutbox(earlierKey, earlier)
	world.writeOutcomes(earlierKey, &SmtpDomainOutcome{Domain: "outside.example", Outcome: SmtpOutcomeSent, UpdateTime: now, TlsLevel: SmtpTlsLevelDane})
	// a device's first read is its baseline
	pass(world.client, 0)

	sendId, effectKey := NewId(), testMailOutboxEffectKey()
	world.plantOutbox(effectKey, sendId)
	world.writeOutcomes(effectKey,
		&SmtpDomainOutcome{Domain: "a.example", Outcome: SmtpOutcomeQueued, UpdateTime: now},
		&SmtpDomainOutcome{Domain: "b.example", Outcome: SmtpOutcomeQueued, UpdateTime: now},
	)
	// a record naming no send
	world.writeOutcomes(testMailOutboxEffectKey(), &SmtpDomainOutcome{Domain: "c.example", Outcome: SmtpOutcomeQueued, UpdateTime: now})
	pass(world.client, 2)
	if sends := world.mailSends(); !slices.Equal(sends, []Id{sendId, sendId}) {
		t.Fatalf("raised for %v", sends)
	}
	// the progress rewrite: the time alone moved
	later := now.Add(5 * time.Minute)
	world.writeOutcomes(effectKey,
		&SmtpDomainOutcome{Domain: "a.example", Outcome: SmtpOutcomeQueued, UpdateTime: later},
		&SmtpDomainOutcome{Domain: "b.example", Outcome: SmtpOutcomeQueued, UpdateTime: later},
	)
	pass(world.client, 0)
	world.writeOutcomes(effectKey,
		&SmtpDomainOutcome{Domain: "a.example", Mode: SmtpModeBdat, Outcome: SmtpOutcomeSent, UpdateTime: later, TlsLevel: SmtpTlsLevelDane},
		&SmtpDomainOutcome{Domain: "b.example", Outcome: SmtpOutcomeQueued, UpdateTime: later},
	)
	pass(world.client, 1)
	pass(world.client, 0)

	// a restart reads back what it kept
	restarted := world.newClient()
	restarted.partsOverride = world.parts
	world.bindClient(restarted)
	pass(restarted, 0)
	world.writeOutcomes(effectKey,
		&SmtpDomainOutcome{Domain: "a.example", Mode: SmtpModeBdat, Outcome: SmtpOutcomeSent, UpdateTime: later, TlsLevel: SmtpTlsLevelDane},
		&SmtpDomainOutcome{Domain: "b.example", Mode: SmtpModeData, Outcome: SmtpOutcomeDeferred, RetryAfter: time.Minute, UpdateTime: later},
	)
	pass(restarted, 1)
	if sends := world.mailSends(); len(sends) != 4 || sends[3] != sendId || slices.Contains(sends, earlier) {
		t.Errorf("raised for %v", sends)
	}
	// the watch's last read names the send, so a result reads its one record
	if effectKeyOf, ok := restarted.sendWatchState().effectKeyOf(sendId); !ok || !bytes.Equal(effectKeyOf, effectKey) {
		t.Error("the last read does not name the send's record")
	}
}

// The watch a component run starts reads at once and again at each wake, raising each change once, whichever read
// sees it first; a second start of the same run starts nothing, and a new run carries the last read on.
func TestMailSendWatchFollowsItsRun(t *testing.T) {
	world := newMailSendResultTestWorld(t)
	now := time.UnixMilli(testMailIngestPushMillis)
	raised := make(chan Id, 8)
	binding, _, _ := world.client.bound()
	copied := *binding
	copied.Event = func(event SidecarEvent) {
		if event.Kind == SidecarEventMailSend {
			raised <- *event.SendId
		}
	}
	world.client.Bind(&copied)
	await := func() Id {
		t.Helper()
		select {
		case sendId := <-raised:
			return sendId
		case <-time.After(60 * time.Second):
			t.Fatal("no mail_send was raised")
			return Id{}
		}
	}
	sendId, effectKey := NewId(), testMailOutboxEffectKey()
	world.plantOutbox(effectKey, sendId)
	world.writeOutcomes(effectKey, &SmtpDomainOutcome{Domain: "a.example", Outcome: SmtpOutcomeQueued, UpdateTime: now})
	// the baseline, before any run, so every change after it is raised once
	if count, err := world.client.passSendWatch(context.Background()); err != nil || count != 0 {
		t.Fatalf("the baseline raised %d: %v", count, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &mailComponentRun{ctx: ctx, cancel: cancel}
	world.client.followSends(run)
	world.client.followSends(run)
	world.writeOutcomes(effectKey, &SmtpDomainOutcome{Domain: "a.example", Mode: SmtpModeBdat, Outcome: SmtpOutcomeSent, UpdateTime: now, TlsLevel: SmtpTlsLevelDane})
	world.client.wakeSends()
	if got := await(); got != sendId {
		t.Fatal("raised for another send")
	}

	// a new run carries the last read on: only the change after it is raised
	cancel()
	nextCtx, nextCancel := context.WithCancel(context.Background())
	defer nextCancel()
	world.client.followSends(&mailComponentRun{ctx: nextCtx, cancel: nextCancel})
	other, otherKey := NewId(), testMailOutboxEffectKey()
	world.plantOutbox(otherKey, other)
	world.writeOutcomes(otherKey, &SmtpDomainOutcome{Domain: "b.example", Outcome: SmtpOutcomeQueued, UpdateTime: now})
	world.client.wakeSends()
	if got := await(); got != other {
		t.Fatal("the new run raised for a change it had read")
	}
	select {
	case extra := <-raised:
		if extra == sendId {
			t.Error("a change was raised twice")
		}
	default:
	}
}
