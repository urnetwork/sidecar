//go:build !sidecar_http && !js && !ios_extension

// MAIL-M9-02's outbox on an in-memory mailbox and on MAIL-M7-17's client world: o/ created only if absent, so a crash
// after the push leaves its Lookup one entry to find and two devices queueing one effect leave one object; a probation,
// suspended or unverified network queues nothing; the entry verifies as SMTP-M9-09's runner holds it; a send's
// internet part queued under the gate's key with the mailbox's bounce address, its member part deposited; a DSN
// deposited to the sending mailbox; or/ kept its 30 days. The contract suite runs in mail_outbox_suite_test.go.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One device's identity key, which signs its outbox entries as Sidecar.Sign does.
type testMailOutboxSigner struct {
	sidecarId Id
	key       ed25519.PrivateKey
}

func newTestMailOutboxSigner(sidecarId Id) *testMailOutboxSigner {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &testMailOutboxSigner{sidecarId: sidecarId, key: key}
}

func (self *testMailOutboxSigner) sign(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      body,
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

func (self *testMailOutboxSigner) publicKey() ed25519.PublicKey {
	return self.key.Public().(ed25519.PublicKey)
}

// A network's standing as GET /abuse/status would answer it.
func testMailOutboxStanding(standing AbuseStanding, verified bool) MailOutboxStanding {
	return func(ctx context.Context) (*AbuseStatus, error) {
		return &AbuseStatus{Standing: standing, Verified: verified}, nil
	}
}

// 32 random bytes, as D-MCP-11's keys are.
func testMailOutboxEffectKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

// An internet message whose Message-ID carries sendId, as a send names it.
func testMailOutboxMessage(sendId Id) []byte {
	return []byte("From: ann@acme.root.example\r\nTo: someone@outside.example\r\nSubject: Plans\r\n" +
		"Message-ID: <" + MailOutboxMessageId(sendId, "acme.root.example") + ">\r\n\r\nDinner at eight.\r\n")
}

// An outbox over store for signer.
func newTestMailOutbox(t *testing.T, store mailStore, signer *testMailOutboxSigner, standing MailOutboxStanding) *MailOutbox {
	t.Helper()
	outbox, err := NewMailOutbox(&MailOutboxArgs{Store: store, Sign: signer.sign, Standing: standing})
	if err != nil {
		t.Fatal(err)
	}
	return outbox
}

// What one queue of message names.
func testMailOutboxQueueArgs(effectKey []byte, message []byte) *MailOutboxQueueArgs {
	return &MailOutboxQueueArgs{
		EffectKey:        effectKey,
		Sender:           "bounces+testtoken@b.acme.root.example",
		Recipients:       []string{"someone@outside.example", "hidden@elsewhere.example"},
		Message:          message,
		Flags:            SmtpFlagRequireTls,
		ApprovalNotAfter: time.UnixMilli(testMailIngestPushMillis),
	}
}

// A queue writes o/<h>/<effect_key> once: the same key again finds the entry and writes nothing, and the entry
// verifies as SMTP-M9-09's runner holds it, signed by the composing device over this key and the message's hash.
func TestMailOutboxQueuesOnceUnderItsKey(t *testing.T) {
	store := newMailTestStore()
	signer := newTestMailOutboxSigner(testMailId(0xb1))
	outbox := newTestMailOutbox(t, store, signer, testMailOutboxStanding(AbuseStandingStandard, true))
	ctx := context.Background()
	effectKey := testMailOutboxEffectKey()
	sendId := newMailOutboxSendId()
	queued, err := outbox.Queue(ctx, testMailOutboxQueueArgs(effectKey, testMailOutboxMessage(sendId)))
	if err != nil || !queued.Created || !bytes.Equal(queued.EffectKey, effectKey) {
		t.Fatalf("the first queue %+v: %v", queued, err)
	}
	writesBefore := store.writeCount
	again, err := outbox.Queue(ctx, testMailOutboxQueueArgs(effectKey, testMailOutboxMessage(sendId)))
	if err != nil || again.Created || store.writeCount != writesBefore {
		t.Fatalf("a second queue under the key %+v, %d writes: %v", again, store.writeCount-writesBefore, err)
	}
	path, _ := MailOutboxPath(effectKey)
	if paths := store.paths(); !slices.Equal(paths, []string{path}) {
		t.Fatalf("the store holds %v", paths)
	}

	file, err := outbox.mailbox.ReadOutbox(ctx, effectKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySmtpOutboxEntry(file, func(sidecarId Id) ed25519.PublicKey {
		if sidecarId == signer.sidecarId {
			return signer.publicKey()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	message := verified.Message
	if verified.SignerId != signer.sidecarId || message.Sender != "bounces+testtoken@b.acme.root.example" ||
		!slices.Equal(message.Recipients, []string{"someone@outside.example", "hidden@elsewhere.example"}) ||
		message.Flags != SmtpFlagRequireTls || !message.ApprovalNotAfter.Equal(time.UnixMilli(testMailIngestPushMillis)) {
		t.Fatalf("the verified entry %+v", message)
	}
	// another member's device verifies nothing
	if _, err := VerifySmtpOutboxEntry(file, func(sidecarId Id) ed25519.PublicKey { return newTestMailOutboxSigner(sidecarId).publicKey() }); err == nil {
		t.Fatal("an entry verified under another key")
	}
}

// A crash after the push: a restart's Lookup, on a fresh outbox, finds the entry as done with the send's id, and a
// retry queues no second entry; a key never queued is not done, and an entry sent and removed whose or/ stands is
// done; a mailbox that cannot be read leaves the use uncertain.
func TestMailOutboxLookupFindsItsEntryAfterARestart(t *testing.T) {
	store := newMailTestStore()
	signer := newTestMailOutboxSigner(testMailId(0xb1))
	ctx := context.Background()
	effectKey := testMailOutboxEffectKey()
	sendId := newMailOutboxSendId()
	if _, err := newTestMailOutbox(t, store, signer, testMailOutboxStanding(AbuseStandingStandard, true)).Queue(ctx, testMailOutboxQueueArgs(effectKey, testMailOutboxMessage(sendId))); err != nil {
		t.Fatal(err)
	}

	restarted := newTestMailOutbox(t, store, signer, nil)
	outcome, err := restarted.Lookup(ctx, nil, effectKey)
	if err != nil || outcome.State != ApprovalOutcomeDone || !bytes.Equal(outcome.EffectRef, sendId.Bytes()) {
		t.Fatalf("the restart's lookup %+v: %v", outcome, err)
	}
	if queued, err := newTestMailOutbox(t, store, signer, testMailOutboxStanding(AbuseStandingStandard, true)).Queue(ctx, testMailOutboxQueueArgs(effectKey, testMailOutboxMessage(sendId))); err != nil || queued.Created {
		t.Fatalf("the retry after the restart %+v: %v", queued, err)
	}
	if count := len(store.paths()); count != 1 {
		t.Fatalf("%d entries after the retry", count)
	}

	if outcome, err := restarted.Lookup(ctx, nil, testMailOutboxEffectKey()); err != nil || outcome.State != ApprovalOutcomeNotDone {
		t.Fatalf("a key never queued %+v: %v", outcome, err)
	}
	if err := restarted.mailbox.WriteOutcomes(ctx, effectKey, []*SmtpDomainOutcome{{Domain: "outside.example", Outcome: SmtpOutcomeSent, UpdateTime: time.UnixMilli(testMailIngestPushMillis)}}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.mailbox.RemoveOutbox(ctx, effectKey); err != nil {
		t.Fatal(err)
	}
	if outcome, err := restarted.Lookup(ctx, nil, effectKey); err != nil || outcome.State != ApprovalOutcomeDone {
		t.Fatalf("an entry sent and removed, its or/ standing %+v: %v", outcome, err)
	}
	broken := newTestMailOutbox(t, &mailOutboxTestBrokenStore{}, signer, nil)
	if outcome, err := broken.Lookup(ctx, nil, effectKey); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("an unreadable mailbox %+v: %v", outcome, err)
	}
}

// A mailbox every read of which fails.
type mailOutboxTestBrokenStore struct{}

func (self *mailOutboxTestBrokenStore) Read(ctx context.Context, path string, maxByteCount int) ([]byte, uint64, error) {
	return nil, 0, errors.New("the mailbox is not readable")
}

func (self *mailOutboxTestBrokenStore) List(ctx context.Context, directory string) ([]string, error) {
	return nil, errors.New("the mailbox is not readable")
}

func (self *mailOutboxTestBrokenStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	return nil, errors.New("the mailbox is not writable")
}

// Two devices of the member queueing one effect, one racing the other between its read and its write, leave one
// object, the one written first, and each answers it.
func TestMailOutboxTwoDevicesQueueOneObject(t *testing.T) {
	store := newMailTestStore()
	first := newTestMailOutboxSigner(testMailId(0xb1))
	second := newTestMailOutboxSigner(testMailId(0xb2))
	standing := testMailOutboxStanding(AbuseStandingStandard, true)
	ctx := context.Background()
	effectKey := testMailOutboxEffectKey()
	message := testMailOutboxMessage(newMailOutboxSendId())
	firstOutbox := newTestMailOutbox(t, store, first, standing)
	secondOutbox := newTestMailOutbox(t, store, second, standing)
	// the second device's write lands between the first's read and its write
	store.beforeWrite = func() {
		if _, err := secondOutbox.Queue(ctx, testMailOutboxQueueArgs(effectKey, message)); err != nil {
			t.Error(err)
		}
	}
	queued, err := firstOutbox.Queue(ctx, testMailOutboxQueueArgs(effectKey, message))
	if err != nil || queued.Created {
		t.Fatalf("the racing first device %+v: %v", queued, err)
	}
	if count := len(store.paths()); count != 1 {
		t.Fatalf("%d objects", count)
	}
	file, err := firstOutbox.mailbox.ReadOutbox(ctx, effectKey)
	if err != nil {
		t.Fatal(err)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(file.Signed, signed); err != nil || !bytes.Equal(signed.GetSignerId(), second.sidecarId.Bytes()) {
		t.Fatalf("the object kept is not the one written first: %v", err)
	}
}

// A probation, suspended or unverified network, or one whose standing cannot be read, queues nothing; a restricted
// one queues at Community caps, as a standard or trusted one does.
func TestMailOutboxProbationNetworkQueuesNothing(t *testing.T) {
	signer := newTestMailOutboxSigner(testMailId(0xb1))
	ctx := context.Background()
	for _, standing := range []MailOutboxStanding{
		testMailOutboxStanding(AbuseStandingProbation, true),
		testMailOutboxStanding(AbuseStandingSuspended, true),
		testMailOutboxStanding(AbuseStandingStandard, false),
		func(ctx context.Context) (*AbuseStatus, error) { return nil, errors.New("api is away") },
		nil,
	} {
		store := newMailTestStore()
		_, err := newTestMailOutbox(t, store, signer, standing).Queue(ctx, testMailOutboxQueueArgs(testMailOutboxEffectKey(), testMailOutboxMessage(newMailOutboxSendId())))
		if !errors.Is(err, ErrMailOutboxStanding) || len(store.paths()) != 0 {
			t.Fatalf("a network that may not send queued: %v, %v", err, store.paths())
		}
	}
	for _, standing := range []AbuseStanding{AbuseStandingRestricted, AbuseStandingStandard, AbuseStandingTrusted} {
		store := newMailTestStore()
		if _, err := newTestMailOutbox(t, store, signer, testMailOutboxStanding(standing, true)).Queue(ctx, testMailOutboxQueueArgs(testMailOutboxEffectKey(), testMailOutboxMessage(newMailOutboxSendId()))); err != nil {
			t.Fatalf("a %s network: %v", standing, err)
		}
	}
}

// or/ is kept its 30 days from its newest outcome's update and then removed; one still within them stays.
func TestMailSmtpMailboxRemovesExpiredOutcomes(t *testing.T) {
	clock := newTestMailCredentialClock(time.UnixMilli(testMailIngestPushMillis))
	store := newMailTestStore()
	mailbox := newMailSmtpMailbox(store, nil, nil, nil, clock)
	ctx := context.Background()
	old, young := testMailOutboxEffectKey(), testMailOutboxEffectKey()
	if err := mailbox.WriteOutcomes(ctx, old, []*SmtpDomainOutcome{{Domain: "outside.example", Outcome: SmtpOutcomeSent, UpdateTime: clock.Now()}}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(20 * 24 * time.Hour)
	if err := mailbox.WriteOutcomes(ctx, young, []*SmtpDomainOutcome{{Domain: "outside.example", Outcome: SmtpOutcomeSent, UpdateTime: clock.Now()}}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * 24 * time.Hour)
	removed, err := mailbox.RemoveExpiredOutcomes(ctx)
	if err != nil || removed != 1 {
		t.Fatalf("removed %d: %v", removed, err)
	}
	if _, err := mailbox.ReadOutcomes(ctx, old); !errors.Is(err, ErrSmtpMailboxNotFound) {
		t.Fatalf("an expired record: %v", err)
	}
	if _, err := mailbox.ReadOutcomes(ctx, young); err != nil {
		t.Fatalf("a record within its days: %v", err)
	}
}

// The component's pass sweeps the member's or/ while mail is on, once an OutcomeSweepInterval: a record past its 30
// days goes at the first pass, one that expires later stays until the interval has passed, and a pass before then
// lists nothing.
func TestMailComponentSweepsExpiredOutcomesOnceAnInterval(t *testing.T) {
	world, _, _ := newMailSendTestWorld(t)
	clock := newTestMailCredentialClock(time.UnixMilli(testMailIngestPushMillis))
	world.client.clock = clock
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &mailComponentRun{ctx: ctx, cancel: cancel}
	mailbox, err := world.client.SmtpMailbox()
	if err != nil {
		t.Fatal(err)
	}
	keep := world.client.outboxSettings().OutcomeKeepDuration
	interval := world.client.outboxSettings().OutcomeSweepInterval
	old, young := testMailOutboxEffectKey(), testMailOutboxEffectKey()
	write := func(effectKey []byte, updateTime time.Time) {
		t.Helper()
		if err := mailbox.WriteOutcomes(ctx, effectKey, []*SmtpDomainOutcome{{Domain: "outside.example", Outcome: SmtpOutcomeSent, UpdateTime: updateTime}}); err != nil {
			t.Fatal(err)
		}
	}
	stands := func(effectKey []byte) bool {
		t.Helper()
		_, err := mailbox.ReadOutcomes(ctx, effectKey)
		if err != nil && !errors.Is(err, ErrSmtpMailboxNotFound) {
			t.Fatal(err)
		}
		return err == nil
	}
	write(old, clock.Now().Add(-keep-time.Hour))
	write(young, clock.Now().Add(-keep+time.Hour))
	world.client.passOutcomes(run)
	if stands(old) || !stands(young) {
		t.Fatalf("after the first pass: old %t, young %t", stands(old), stands(young))
	}
	// the young record's days end, and a pass within the interval does not look
	clock.Advance(2 * time.Hour)
	world.client.passOutcomes(run)
	if !stands(young) {
		t.Fatal("a pass within the interval swept")
	}
	clock.Advance(interval)
	world.client.passOutcomes(run)
	if stands(young) {
		t.Fatal("a record past its days outlived the next interval's pass")
	}
	if removed, err := world.client.RemoveExpiredOutcomes(ctx); err != nil || removed != 0 {
		t.Fatalf("a sweep of an empty or/: %d %v", removed, err)
	}
}

// The send world bound with an outbox: a signer and the network's standing.
func testMailSendBindOutbox(world *mailClientTestWorld, signer *testMailOutboxSigner, standing MailOutboxStanding) {
	binding, _, err := world.client.bound()
	if err != nil {
		world.t.Fatal(err)
	}
	copied := *binding
	copied.Sign = signer.sign
	copied.Standing = standing
	world.client.Bind(&copied)
}

// The o/ entries the world's mailbox holds, by key.
func testMailSendOutbox(t *testing.T, world *mailClientTestWorld) map[string]*SmtpOutboxFile {
	t.Helper()
	mailbox := newMailSmtpMailbox(world.ingest.store, nil, nil, nil, nil)
	ctx := context.Background()
	keys, err := mailbox.ListOutbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*SmtpOutboxFile{}
	for _, key := range keys {
		file, err := mailbox.ReadOutbox(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		files[string(key)] = file
	}
	return files
}

// A send naming members and the internet, once the gate passes it: the member part deposits, the internet part,
// Bcc included and nothing else, queues at o/ under the gate's key with the mailbox's bounce address as its envelope
// sender, the message naming no Bcc and a random id under the From's domain; the sent copy is kept; the bounce
// address resolves to the mailbox. A run of the effect again under the key queues no second entry.
func TestMailSendQueuesTheInternetPartAtTheOutbox(t *testing.T) {
	world, parts, mailboxId := newMailSendTestWorld(t)
	signer := newTestMailOutboxSigner(world.device)
	testMailSendBindOutbox(world, signer, testMailOutboxStanding(AbuseStandingStandard, true))
	ctx := context.Background()
	result, err := world.client.Send(ctx, testMailSubmitDraft())
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]MailSendOutcome{}
	for _, recipient := range result.Recipients {
		outcomes[recipient.Address] = recipient.Outcome
	}
	if outcomes[testMailIngestRecipient] != MailSendDelivered || outcomes["someone@outside.example"] != MailSendQueued ||
		outcomes["hidden@elsewhere.example"] != MailSendQueued || !result.SentCopy {
		t.Fatalf("outcomes %v, sent copy %t", outcomes, result.SentCopy)
	}
	held := world.gate.lastAction()
	if !bytes.Equal(result.EffectKey, mailConfigTestEffectKey(held.Canonical)) {
		t.Fatal("the entry is not under the gate's key")
	}
	files := testMailSendOutbox(t, world)
	file := files[string(result.EffectKey)]
	if len(files) != 1 || file == nil {
		t.Fatalf("%d entries", len(files))
	}
	verified, err := VerifySmtpOutboxEntry(file, func(sidecarId Id) ed25519.PublicKey {
		if sidecarId == world.device {
			return signer.publicKey()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(verified.Message.Recipients, []string{"someone@outside.example", "hidden@elsewhere.example"}) {
		t.Fatalf("the entry names %v, not the internet part alone", verified.Message.Recipients)
	}
	if !strings.HasPrefix(verified.Message.Sender, "bounces+") || !strings.HasSuffix(verified.Message.Sender, "@b.acme.root.example") {
		t.Fatal("the envelope sender is not the mailbox's bounce address")
	}
	if bytes.Contains(file.Message, []byte("hidden@")) {
		t.Fatal("the queued message names its Bcc")
	}
	if sendId, ok := MailOutboxSendIdOf(file.Message); !ok || sendId != result.SendId {
		t.Fatal("the message's id is not the send's")
	}
	deposits := parts.snapshot()
	if len(deposits) != 1 || deposits[0].repoId != mailboxId || !slices.Equal(deposits[0].deposit.GetRecipients(), []string{testMailIngestRecipient}) {
		t.Fatalf("deposits %+v", deposits)
	}
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bounce, err := ParseMailRecipient(testMailIngestRoot, verified.Message.Sender)
	if err != nil {
		t.Fatal(err)
	}
	if lookup, err := config.Resolve(ctx, bounce); err != nil || !lookup.Known || lookup.MailboxRepoId != mailboxId ||
		lookup.Kind != protocol.MailAddressKind_MAIL_ADDRESS_BOUNCE {
		t.Fatalf("the bounce address resolves %+v: %v", lookup, err)
	}

	// the gate runs the effect again under the same key, as after an uncertain outcome: one entry still
	world.gate.stateLock.Lock()
	delete(world.gate.outcomes, string(held.Canonical))
	world.gate.stateLock.Unlock()
	if _, err := world.client.Send(ctx, testMailSubmitDraft()); err != nil {
		t.Fatal(err)
	}
	if count := len(testMailSendOutbox(t, world)); count != 1 {
		t.Fatalf("%d entries after the effect ran again", count)
	}
}

// A probation network's send delivers its member part and queues nothing: its internet recipients answer
// internet_refused.
func TestMailSendProbationNetworkQueuesNothing(t *testing.T) {
	world, parts, _ := newMailSendTestWorld(t)
	testMailSendBindOutbox(world, newTestMailOutboxSigner(world.device), testMailOutboxStanding(AbuseStandingProbation, true))
	result, err := world.client.Send(context.Background(), testMailSubmitDraft())
	if err != nil {
		t.Fatal(err)
	}
	for _, recipient := range result.Recipients {
		want := MailSendInternetRefused
		if recipient.Address == testMailIngestRecipient {
			want = MailSendDelivered
		}
		if recipient.Outcome != want {
			t.Fatalf("%s answered %s", recipient.Address, recipient.Outcome)
		}
	}
	if len(testMailSendOutbox(t, world)) != 0 || len(parts.snapshot()) != 1 || len(result.EffectKey) != 0 {
		t.Fatal("a probation network queued")
	}
}

// A DSN goes to the sending mailbox as a deposit, filed under its To and read there as outside mail.
func TestMailSmtpMailboxDepositsADsnToTheSendingMailbox(t *testing.T) {
	world, parts, mailboxId := newMailSendTestWorld(t)
	mailbox, err := world.client.SmtpMailbox()
	if err != nil {
		t.Fatal(err)
	}
	dsn := []byte("From: Mail Delivery System <mailer-daemon@b.acme.root.example>\r\nTo: <" + testMailSendFrom + ">\r\n" +
		"Subject: Undelivered mail to outside.example\r\nMessage-ID: <dsn1@b.acme.root.example>\r\n\r\nThe message could not be sent.\r\n")
	if err := mailbox.DepositDsn(context.Background(), testMailOutboxEffectKey(), dsn); err != nil {
		t.Fatal(err)
	}
	deposits := parts.snapshot()
	if len(deposits) != 1 || deposits[0].repoId != mailboxId || len(deposits[0].deposit.GetMailFrom()) != 0 ||
		!slices.Equal(deposits[0].deposit.GetRecipients(), []string{testMailSendFrom}) {
		t.Fatalf("the dsn's deposit %+v", deposits)
	}
	world.ingestAll(mailboxId)
	read := testMailSendRead(t, world, MailFolderAll, "Undelivered mail to outside.example")
	if read == nil || read.Trust != MailTrustUntrusted {
		t.Fatal("the dsn was not filed as outside mail")
	}
}
