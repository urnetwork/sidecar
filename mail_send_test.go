//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-18's same-network delivery on MAIL-M7-17's client world: two devices of one member, the deposit labeled by
// its signer's signature and kept as a sent copy, never routed to the internet path; a group's one deposit; a mixed
// list delivering its local part only; a From this device may not send as refused; a forged signer shown as outside
// mail at ingest; and no address in a log. Mail between members is mail_member_deposit_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One deposit a send made.
type mailSendTestDeposit struct {
	repoId    Id
	message   []byte
	deposit   *protocol.MailDeposit
	plaintext []byte
}

// The client world's parts with a send's authority and deposits: deposits to the world's mailbox land in its deposit
// refs as the sending device's, so ingest takes them; every other repo's are kept.
type mailSendTestParts struct {
	*mailClientTestParts
	stateLock sync.Mutex
	// each (sidecar, From address) that may send
	maySend map[string]bool
	// each repo's deposit outcome; a repo not here is delivered
	repoOutcomes map[Id]MailSendOutcome
	// repos whose deposit fails
	failing  map[Id]bool
	deposits []*mailSendTestDeposit
	// what other device signs the world's mailbox deposits; zero for the client's own
	signer Id
}

func (self *mailSendTestParts) sendAuthority() MailSendAuthority {
	return self
}

func (self *mailSendTestParts) MaySendAs(senderSidecarId Id, fromAddress string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.maySend[senderSidecarId.String()+" "+fromAddress]
}

func (self *mailSendTestParts) MayDeposit(senderSidecarId Id, repoId Id) MailSendOutcome {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if outcome, ok := self.repoOutcomes[repoId]; ok {
		return outcome
	}
	return MailSendDelivered
}

func (self *mailSendTestParts) Writes(senderSidecarId Id, repoId Id) bool {
	return true
}

func (self *mailSendTestParts) depositRepo(repoId Id) mailSendDepositRepo {
	return &mailSendTestDepositRepo{parts: self, repoId: repoId}
}

// The deposits so far.
func (self *mailSendTestParts) snapshot() []*mailSendTestDeposit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.deposits)
}

// One repo's deposit, as the send hands it to evs.
type mailSendTestDepositRepo struct {
	parts  *mailSendTestParts
	repoId Id
}

func (self *mailSendTestDepositRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	plaintext, err := io.ReadAll(args.Body)
	if err != nil {
		return nil, err
	}
	if int64(len(plaintext)) != args.Size {
		return nil, errors.New("a body of another size than stated")
	}
	message, deposit, err := mailSplitDeposit(plaintext, 64*1024)
	if err != nil {
		return nil, err
	}
	parts := self.parts
	failing, signer := func() (bool, Id) {
		parts.stateLock.Lock()
		defer parts.stateLock.Unlock()
		return parts.failing[self.repoId], parts.signer
	}()
	if failing {
		return nil, errors.New("evs refused the deposit")
	}
	world := parts.world
	if self.repoId == world.ingest.repoId {
		if signer == (Id{}) {
			signer = world.device
		}
		world.ingest.repo.deposit(signer, signer, plaintext)
	}
	parts.stateLock.Lock()
	defer parts.stateLock.Unlock()
	parts.deposits = append(parts.deposits, &mailSendTestDeposit{repoId: self.repoId, message: message, deposit: deposit, plaintext: plaintext})
	return &EvsDepositResult{EntryId: NewEvsRandomToken(), Version: uint64(len(parts.deposits))}, nil
}

// The client world with mail on, the aliases bo (the ingest world's recipient) and ann in the member's mailbox, and
// the send's parts installed: the device may send as ann.
func newMailSendTestWorld(t *testing.T) (*mailClientTestWorld, *mailSendTestParts, Id) {
	t.Helper()
	world := newMailClientTestWorld(t)
	mailboxId := world.enable()
	ctx := context.Background()
	for _, localPart := range []string{"bo", "ann"} {
		if _, err := world.client.CreateAlias(ctx, &MailAliasCreateArgs{LocalPart: localPart}); err != nil {
			t.Fatal(err)
		}
	}
	parts := &mailSendTestParts{
		mailClientTestParts: &mailClientTestParts{world: world},
		maySend:             map[string]bool{world.device.String() + " " + testMailSendFrom: true},
		repoOutcomes:        map[Id]MailSendOutcome{},
		failing:             map[Id]bool{},
	}
	world.client.stateLock.Lock()
	world.client.partsOverride = parts
	world.client.stateLock.Unlock()
	// ingest holds the deposit's signer to the same rule
	world.ingest.authority.maySend[world.device.String()+" "+testMailSendFrom] = true
	// internet mail queues at o/, signed by the device, on a standard network (MAIL-M9-02)
	testMailSendBindOutbox(world, newTestMailOutboxSigner(world.device), testMailOutboxStanding(AbuseStandingStandard, true))
	return world, parts, mailboxId
}

const testMailSendFrom = "ann@acme.root.example"

// The entry of subject in folder, read; nil where the folder holds none.
func testMailSendRead(t *testing.T, world *mailClientTestWorld, folder MailFolder, subject string) *MailReadResult {
	t.Helper()
	ctx := context.Background()
	page, err := world.client.List(ctx, &MailListArgs{Folder: folder})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range page.Entries {
		if entry.Entry.GetSubject() != subject {
			continue
		}
		read, err := world.client.Read(ctx, &MailReadArgs{Month: MailYearMonthOf(entry.Entry.GetTime()), Id: mailEntryId(entry.Entry)})
		if err != nil {
			t.Fatal(err)
		}
		return read
	}
	return nil
}

// A device's mail to an address of its own member is deposited to the member's mailbox, where the member's other
// devices read it, signed by the sender and shown as from a member; a sent copy is kept; nothing went to smtpedge,
// since nothing here has a path there.
func TestMailSendDeliversWithinOneMemberLabeledBySignature(t *testing.T) {
	world, parts, mailboxId := newMailSendTestWorld(t)
	ctx := context.Background()
	result, err := world.client.Send(ctx, &MailSendArgs{
		From: testMailSendFrom, To: []string{testMailIngestRecipient}, Subject: "Lunch", Text: "At noon, by the river.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].Outcome != MailSendDelivered || !result.SentCopy {
		t.Fatalf("the result %+v", result.Recipients[0])
	}
	deposits := parts.snapshot()
	if len(deposits) != 1 || deposits[0].repoId != mailboxId {
		t.Fatalf("deposits %d", len(deposits))
	}
	trailer := deposits[0].deposit
	if string(trailer.GetMailFrom()) != testMailSendFrom || !slices.Equal(trailer.GetRecipients(), []string{testMailIngestRecipient}) ||
		trailer.GetIngress() != nil || trailer.GetEvidence() != nil || len(trailer.GetReceiverSidecarId()) != 0 || trailer.GetTlsVersion() != 0 {
		t.Fatalf("a same-network trailer sets version, mail_from and recipients only: %+v", trailer)
	}

	world.ingestAll(mailboxId)
	received := testMailSendRead(t, world, MailFolderInbox, "Lunch")
	if received == nil {
		t.Fatal("the inbox holds no deposit")
	}
	if received.Trust != MailTrustMember || received.Label != "member-signed" || !strings.Contains(received.Text, "by the river") {
		t.Fatalf("the received copy %+v", received)
	}
	sent := testMailSendRead(t, world, MailFolderSent, "Lunch")
	if sent == nil || mailEntryId(sent.Entry) != result.SendId || sent.Trust == MailTrustUntrusted {
		t.Fatalf("the sent copy %+v", sent)
	}
	// a sent copy is no inbox message, and the inbox's is no sent copy
	if mailEntryId(sent.Entry) == mailEntryId(received.Entry) {
		t.Fatal("the deposit and the sent copy are one message")
	}
}

// A group address is one deposit to the group's repo naming only the group, beside one to the mailbox naming its own
// recipients: one deposit a repo.
func TestMailSendFansOutOneDepositARepo(t *testing.T) {
	world, parts, mailboxId := newMailSendTestWorld(t)
	ctx := context.Background()
	groupRepoId := NewId()
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.CreateAddress(ctx, &MailCreateAddressArgs{
		LocalPart: "team", Kind: protocol.MailAddressKind_MAIL_ADDRESS_GROUP, MailboxRepoId: groupRepoId, MemberIds: []Id{world.member},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.client.CreateAlias(ctx, &MailAliasCreateArgs{LocalPart: "cy"}); err != nil {
		t.Fatal(err)
	}
	result, err := world.client.Send(ctx, &MailSendArgs{
		From: testMailSendFrom,
		To:   []string{"team@acme.root.example", testMailIngestRecipient},
		Bcc:  []string{"cy@acme.root.example"},
		Text: "Hello all.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if delivered := result.Delivered(); len(delivered) != 3 {
		t.Fatalf("delivered %v", delivered)
	}
	byRepo := map[Id][]string{}
	for _, deposit := range parts.snapshot() {
		if _, ok := byRepo[deposit.repoId]; ok {
			t.Fatal("two deposits to one repo")
		}
		byRepo[deposit.repoId] = deposit.deposit.GetRecipients()
		if bytes.Contains(deposit.message, []byte("cy@")) {
			t.Error("a Bcc recipient is named in a header")
		}
	}
	if !slices.Equal(byRepo[groupRepoId], []string{"team@acme.root.example"}) ||
		!slices.Equal(byRepo[mailboxId], []string{testMailIngestRecipient, "cy@acme.root.example"}) || len(byRepo) != 2 {
		t.Fatalf("deposits by repo %v", byRepo)
	}
}

// A mixed list deposits its same-network part and queues the rest for the internet (MAIL-M9-01): the outside address
// is queued at o/, named in no deposit's trailer, and an unknown member address answered unknown. An all-outside list
// deposits nothing, queues its one recipient and keeps a copy of what went.
func TestMailSendMixedListDepositsItsLocalPartAndQueuesTheRest(t *testing.T) {
	world, parts, _ := newMailSendTestWorld(t)
	result, err := world.client.Send(context.Background(), &MailSendArgs{
		From: testMailSendFrom, To: []string{testMailIngestRecipient, "Someone@Outside.Example"}, Cc: []string{"nobody@acme.root.example"}, Text: "x",
	})
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]MailSendOutcome{}
	for _, recipient := range result.Recipients {
		outcomes[recipient.Address] = recipient.Outcome
	}
	if outcomes[testMailIngestRecipient] != MailSendDelivered || outcomes["Someone@outside.example"] != MailSendQueued ||
		outcomes["nobody@acme.root.example"] != MailSendUnknown {
		t.Fatalf("outcomes %v", outcomes)
	}
	deposits := parts.snapshot()
	if len(deposits) != 1 || !slices.Equal(deposits[0].deposit.GetRecipients(), []string{testMailIngestRecipient}) ||
		!bytes.Contains(deposits[0].message, []byte("To: "+testMailIngestRecipient+", Someone@outside.example\r\n")) {
		t.Fatalf("deposits %+v", deposits)
	}
	// an all-outside list deposits nothing, queues, and keeps the copy
	result, err = world.client.Send(context.Background(), &MailSendArgs{From: testMailSendFrom, To: []string{"a@outside.example"}, Text: "x"})
	if err != nil || result.Recipients[0].Outcome != MailSendQueued || !result.SentCopy || len(parts.snapshot()) != 1 {
		t.Fatalf("an outside-only send %+v: %v", result, err)
	}
	if count := len(testMailSendOutbox(t, world)); count != 2 {
		t.Fatalf("%d entries for two sends", count)
	}
}

// A From this device may not send as is refused before anything is sent: one policy does not grant, a burner's
// (replies are M9's), an outside one, and one of no form.
func TestMailSendRefusesAFromItMayNotSendAs(t *testing.T) {
	world, parts, _ := newMailSendTestWorld(t)
	ctx := context.Background()
	for _, from := range []string{"bo@acme.root.example", "x@otter-4821.acme.root.example", "ann@outside.example", "not an address"} {
		_, err := world.client.Send(ctx, &MailSendArgs{From: from, To: []string{testMailIngestRecipient}, Text: "x"})
		if !errors.Is(err, ErrMailSendFromRefused) {
			t.Errorf("a From of %q: %v", from, err)
		}
	}
	for _, args := range []*MailSendArgs{
		{From: testMailSendFrom, Text: "no recipient"},
		{From: testMailSendFrom, To: []string{"a@acme.root.example\r\nBcc: b@outside.example"}},
		{From: testMailSendFrom, To: []string{testMailIngestRecipient}, Subject: "two\r\nlines"},
	} {
		if _, err := world.client.Send(ctx, args); !errors.Is(err, ErrMailSendInvalid) {
			t.Errorf("a send out of shape %+v: %v", args, err)
		}
	}
	if len(parts.snapshot()) != 0 {
		t.Fatal("a refused send deposited")
	}
}

// A same-network deposit whose signer may not send as its From is outside mail at ingest: untrusted, never
// member-signed, whatever its From says.
func TestMailSendForgedSignerIsOutsideMailAtIngest(t *testing.T) {
	world, _, mailboxId := newMailSendTestWorld(t)
	forger := world.repos.fixture.device(world.member)
	message := []byte("From: Ann <" + testMailSendFrom + ">\r\nTo: " + testMailIngestRecipient + "\r\nSubject: Forged\r\n" +
		"Message-ID: <forged@acme.root.example>\r\n\r\nNot from ann.\r\n")
	plaintext, err := MailSameNetworkDeposit(message, testMailSendFrom, []string{testMailIngestRecipient})
	if err != nil {
		t.Fatal(err)
	}
	world.ingest.repo.deposit(forger, forger, plaintext)
	world.ingestAll(mailboxId)
	read := testMailSendRead(t, world, MailFolderAll, "Forged")
	if read == nil {
		t.Fatal("the forged deposit was not written")
	}
	if read.Trust != MailTrustUntrusted || read.Label == "member-signed" {
		t.Fatalf("a forged signer reads as %s, %s", read.Trust, read.Label)
	}
}

// The message is plain text with its headers, the subject encoded, the Bcc in no header, quoted-printable, CRLF.
func TestMailSendBuildsAPlainTextMessage(t *testing.T) {
	sendId := NewId()
	message, err := mailSendBuildMessageWithId(&MailSendArgs{
		To: []string{"Bo@Acme.Root.Example"}, Cc: []string{"cy@acme.root.example"}, Bcc: []string{"dee@acme.root.example"},
		Subject: "Grüße", Text: "line one\nline two = three",
	}, NetworkLabelRow{Root: "root.example", Label: "acme"}, testMailSendFrom, strings.ToLower(sendId.String())+"@acme.root.example", time.UnixMilli(testMailIngestPushMillis))
	if err != nil {
		t.Fatal(err)
	}
	text := string(message)
	for _, want := range []string{
		"From: " + testMailSendFrom + "\r\n", "To: bo@acme.root.example\r\n", "Cc: cy@acme.root.example\r\n",
		"Message-ID: <" + strings.ToLower(sendId.String()) + "@acme.root.example>\r\n", "Content-Transfer-Encoding: quoted-printable\r\n",
		"line one\r\nline two =3D three",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "dee@") {
		t.Error("the Bcc is named")
	}
	decoder := &mime.WordDecoder{}
	subject := ""
	for _, line := range strings.Split(text, "\r\n") {
		if value, ok := strings.CutPrefix(line, "Subject: "); ok {
			subject, err = decoder.DecodeHeader(value)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if subject != "Grüße" {
		t.Fatalf("the subject %q", subject)
	}
	parsed, err := MailParseMessage(bytes.NewReader(message), nil)
	if err != nil || parsed.FromDomain != "acme.root.example" || parsed.Subject != "Grüße" {
		t.Fatalf("the walk %+v: %v", parsed, err)
	}
}

// A deposit that fails is answered failed for its recipients, the others delivered.
func TestMailSendAnswersAFailedDepositPerRecipient(t *testing.T) {
	world, parts, mailboxId := newMailSendTestWorld(t)
	parts.failing[mailboxId] = true
	result, err := world.client.Send(context.Background(), &MailSendArgs{From: testMailSendFrom, To: []string{testMailIngestRecipient}, Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Recipients[0].Outcome != MailSendFailed {
		t.Fatalf("a failed deposit %+v", result.Recipients[0])
	}
}

// Sending logs no address and no subject (I-13).
func TestMailSendLogsNoAddress(t *testing.T) {
	world, _, mailboxId := newMailSendTestWorld(t)
	if _, err := world.client.Send(context.Background(), &MailSendArgs{
		From: testMailSendFrom, To: []string{testMailIngestRecipient, "x@outside.example"}, Subject: "Secret plans", Text: "x",
	}); err != nil {
		t.Fatal(err)
	}
	world.ingestAll(mailboxId)
	for _, line := range world.log.snapshot() {
		if strings.Contains(line, "@") || strings.Contains(line, "Secret") {
			t.Errorf("a line names an address or the subject: %q", line)
		}
	}
}
