//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension && !windows

// MAIL-M9-01's submission server on MAIL-M7-18's send world, through go-smtp's own client: §22.5's §5 row, plaintext
// only on loopback; AUTH over the local credential at a bounded rate and MAIL refused before it; a From outside
// mail:<alias>#send refused; an unapproved recipient held, then released by an approval of the same bytes; a mixed
// message splitting into its deposit and its queued rest; an unknown member address refused at RCPT; a tainted run's
// send needing a fresh decision; and FuzzMailSubmission.

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The network's client world behind one submission server, its credential made, on a clock the test moves.
type testMailSubmissionWorld struct {
	t         *testing.T
	clock     *testMailCredentialClock
	send      *mailClientTestWorld
	parts     *mailSendTestParts
	mailboxId Id
	secret    string
	server    *MailSubmissionServer
	fed       *testMailImapListener
}

func newTestMailSubmissionWorld(t *testing.T, settings *MailSubmissionSettings) *testMailSubmissionWorld {
	t.Helper()
	send, parts, mailboxId := newMailSendTestWorld(t)
	credential, err := NewMailLocalCredential(&testMailSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewMailLocalCredentialSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.Install(secret.Verifier); err != nil {
		t.Fatal(err)
	}
	world := &testMailSubmissionWorld{
		t:         t,
		clock:     newTestMailCredentialClock(time.UnixMilli(testMailIngestPushMillis)),
		send:      send,
		parts:     parts,
		mailboxId: mailboxId,
		secret:    secret.Text,
		fed:       newTestMailImapListener(),
	}
	account := &MailSubmissionAccount{NetworkId: testNetworkId, Credential: credential, Submitter: send.client}
	world.server, err = NewMailSubmissionServer(context.Background(), &MailSubmissionServerArgs{
		Accounts: func() []*MailSubmissionAccount { return []*MailSubmissionAccount{account} },
		Clock:    world.clock,
		Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		world.server.Serve(world.fed)
		close(served)
	}()
	t.Cleanup(func() {
		world.server.Close()
		<-served
	})
	return world
}

// A client on a connection the server reads as loopback plaintext.
func (self *testMailSubmissionWorld) loopbackClient() *smtp.Client {
	self.t.Helper()
	server, client := net.Pipe()
	self.fed.offer(self.t, server, true, false)
	smtpClient := smtp.NewClient(client)
	self.t.Cleanup(func() { smtpClient.Close() })
	if err := smtpClient.Hello("client.example"); err != nil {
		self.t.Fatal(err)
	}
	return smtpClient
}

// A loopback client signed in with the world's credential.
func (self *testMailSubmissionWorld) signedIn() *smtp.Client {
	self.t.Helper()
	client := self.loopbackClient()
	if err := client.Auth(sasl.NewPlainClient("", MailLocalCredentialUser, self.secret)); err != nil {
		self.t.Fatalf("AUTH: %v", err)
	}
	return client
}

// Sends message to recipients on client: the first error, of MAIL, a RCPT or DATA.
func testMailSubmit(client *smtp.Client, recipients []string, message string) error {
	if err := client.Mail(testMailSendFrom, nil); err != nil {
		return err
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient, nil); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write([]byte(message)); err != nil {
		return err
	}
	return writer.Close()
}

// A message from from, as a mail client writes one.
func testMailSubmissionMessage(from string, subject string) string {
	return "From: Ann <" + from + ">\r\nTo: " + testMailIngestRecipient + ", someone@outside.example\r\nSubject: " + subject +
		"\r\nDate: Wed, 02 Dec 2026 09:30:12 +0100\r\nMessage-ID: <client-1@laptop.example>\r\nUser-Agent: Example Mail 1.0\r\n\r\n" +
		"Dinner at eight.\r\n"
}

// The SMTP code of err, 0 for none.
func testMailSubmitCode(err error) int {
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr.Code
	}
	return 0
}

// A connection off loopback that is not TLS gets no greeting, only a close; a TLS one is served and takes AUTH; a
// connection marked TLS that is not one is closed; a loopback one is served plaintext.
func TestMailSubmissionPlaintextOnlyOnLoopback(t *testing.T) {
	world := newTestMailSubmissionWorld(t, nil)

	plainServer, plainClient := net.Pipe()
	defer plainClient.Close()
	world.fed.offer(t, plainServer, false, false)
	if read, err := plainClient.Read(make([]byte, 64)); err == nil {
		t.Fatalf("a plain connection off loopback read %d bytes", read)
	}

	serverConfig, _, _, err := EvsGitSelfSignedTls([]string{"submission.example"}, world.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(serverConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	tlsServer, tlsClient := net.Pipe()
	world.fed.offer(t, tls.Server(tlsServer, serverConfig), false, true)
	client := smtp.NewClient(tls.Client(tlsClient, &tls.Config{ServerName: "submission.example", RootCAs: roots, Time: world.clock.Now}))
	defer client.Close()
	if err := client.Hello("client.example"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := client.Extension("STARTTLS"); ok {
		t.Fatal("STARTTLS offered on a TLS connection")
	}
	if err := client.Auth(sasl.NewPlainClient("", MailLocalCredentialUser, world.secret)); err != nil {
		t.Fatalf("AUTH over TLS: %v", err)
	}

	fakeServer, fakeClient := net.Pipe()
	defer fakeClient.Close()
	world.fed.offer(t, fakeServer, false, true)
	if read, err := fakeClient.Read(make([]byte, 64)); err == nil {
		t.Fatalf("a connection marked TLS but plain read %d bytes", read)
	}

	world.signedIn()
}

// MAIL before AUTH is refused 530; a wrong credential is refused 535 only once its cost has passed on the clock, and
// the right one opens the session.
func TestMailSubmissionAuthenticatesItsCallerAtABoundedRate(t *testing.T) {
	world := newTestMailSubmissionWorld(t, nil)
	client := world.loopbackClient()
	if err := client.Mail(testMailSendFrom, nil); testMailSubmitCode(err) != 530 {
		t.Fatalf("MAIL before AUTH: %v", err)
	}
	answered := make(chan error, 1)
	go func() {
		answered <- client.Auth(sasl.NewPlainClient("", MailLocalCredentialUser, "not the secret"))
	}()
	for !slices.Contains(world.clock.pending(), DefaultMailLocalCredentialSettings().FailureDelay) {
		select {
		case err := <-answered:
			t.Fatalf("a refusal answered before its wait: %v", err)
		case <-world.clock.added:
		}
	}
	world.clock.Advance(DefaultMailLocalCredentialSettings().FailureDelay)
	if err := <-answered; testMailSubmitCode(err) != 535 {
		t.Fatalf("a wrong credential: %v", err)
	}
	world.signedIn()
}

// A From this account may not send as is refused 553 at DATA, and nothing is kept, deposited or queued.
func TestMailSubmissionRefusesAFromOutsideItsSendGrant(t *testing.T) {
	world := newTestMailSubmissionWorld(t, nil)
	err := testMailSubmit(world.signedIn(), []string{testMailIngestRecipient}, testMailSubmissionMessage("bo@acme.root.example", "Forged"))
	if testMailSubmitCode(err) != 553 {
		t.Fatalf("a From outside the grant: %v", err)
	}
	if len(world.parts.snapshot()) != 0 || len(testMailSendOutbox(t, world.send)) != 0 {
		t.Fatal("a refused From sent")
	}
}

// A message to an unapproved internet recipient is held for an I-8 approval, answered 451 4.7.1 naming it, nothing
// kept, deposited or queued; once a person approves, the same bytes sent again go: the member part deposits and the
// rest queues at o/, answered 250. The action is the submission's, its body the message's bytes.
func TestMailSubmissionHoldsAnUnapprovedRecipientUntilApproved(t *testing.T) {
	world := newTestMailSubmissionWorld(t, nil)
	message := testMailSubmissionMessage(testMailSendFrom, "Plans")
	recipients := []string{testMailIngestRecipient, "Someone@outside.example", "someone@outside.example", "hidden@elsewhere.example"}

	testMailSubmitHold(world.send.gate, true)
	err := testMailSubmit(world.signedIn(), recipients, message)
	var smtpErr *smtp.SMTPError
	if !errors.As(err, &smtpErr) || smtpErr.Code != 451 || smtpErr.EnhancedCode != (smtp.EnhancedCode{4, 7, 1}) ||
		!strings.Contains(smtpErr.Message, evsTestId("pending approval").String()) {
		t.Fatalf("a held submission: %v", err)
	}
	if len(world.parts.snapshot()) != 0 || len(testMailSendOutbox(t, world.send)) != 0 || testMailSendRead(t, world.send, MailFolderSent, "Plans") != nil {
		t.Fatal("a held submission kept, deposited or queued")
	}
	held := world.send.gate.lastAction()
	stored, err := ParseStoredCanonicalAction(held.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored.Action.GetRecipients(), recipients) || stored.Action.GetAlias() != testMailSendFrom ||
		!strings.Contains(stored.Action.GetPreview(), "Dinner at eight.") {
		t.Fatalf("the held action %+v", stored.Action)
	}

	testMailSubmitHold(world.send.gate, false)
	if err := testMailSubmit(world.signedIn(), recipients, message); err != nil {
		t.Fatalf("the approved submission: %v", err)
	}
	if passed := world.send.gate.lastAction(); !bytes.Equal(passed.Canonical, held.Canonical) {
		t.Fatal("the same bytes built another action")
	}
	deposits := world.parts.snapshot()
	if len(deposits) != 1 || deposits[0].repoId != world.mailboxId || !slices.Equal(deposits[0].deposit.GetRecipients(), []string{testMailIngestRecipient}) {
		t.Fatalf("deposits %+v", deposits)
	}
	files := testMailSendOutbox(t, world.send)
	if len(files) != 1 {
		t.Fatalf("%d entries", len(files))
	}
	for _, file := range files {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(file.Signed, signed); err != nil {
			t.Fatal(err)
		}
		entry := &protocol.SmtpOutboxEntry{}
		if err := proto.Unmarshal(signed.Body, entry); err != nil || !slices.Equal(entry.GetRecipients(), recipients[1:]) {
			t.Fatalf("submitted envelope %v: %v", entry.GetRecipients(), err)
		}
		if bytes.Contains(file.Message, []byte("hidden@")) || !bytes.Contains(file.Message, []byte("Dinner at eight.")) {
			t.Fatal("the queued message is not the submission's, Bcc stripped")
		}
	}
	if testMailSendRead(t, world.send, MailFolderSent, "Plans") == nil {
		t.Fatal("no sent copy")
	}
}

// A message to members alone goes at once with no approval, and a same-network address no record holds is refused
// at RCPT, 550 5.1.1.
func TestMailSubmissionDeliversToMembersAndRefusesAnUnknownOne(t *testing.T) {
	world := newTestMailSubmissionWorld(t, nil)
	testMailSubmitHold(world.send.gate, true)
	actionsBefore, _ := world.send.gate.counts()
	if err := testMailSubmit(world.signedIn(), []string{testMailIngestRecipient}, testMailSubmissionMessage(testMailSendFrom, "Lunch")); err != nil {
		t.Fatalf("mail to members: %v", err)
	}
	if actionsAfter, _ := world.send.gate.counts(); actionsAfter != actionsBefore || len(world.parts.snapshot()) != 1 {
		t.Fatal("mail to members waited on the gate or was not deposited")
	}
	client := world.signedIn()
	if err := client.Mail(testMailSendFrom, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.Rcpt("nobody@acme.root.example", nil); testMailSubmitCode(err) != 550 {
		t.Fatalf("an unknown member address: %v", err)
	}
}

// A tainted run's send needs a fresh decision, mail to members included: it waits on the gate, and an untainted
// run's same send goes at once (I-9).
func TestMailSendTaintedRunNeedsAFreshDecision(t *testing.T) {
	world, parts, _ := newMailSendTestWorld(t)
	tainted := map[Id]bool{testMailId(0x7a): true}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.RunTainted = func(runId Id) bool { return tainted[runId] }
	world.client.Bind(&copied)
	testMailSubmitHold(world.gate, true)
	taintedRun, cleanRun := testMailId(0x7a), testMailId(0x7b)
	_, err = world.client.Send(context.Background(), &MailSendArgs{
		From: testMailSendFrom, To: []string{testMailIngestRecipient}, Text: "x", Action: MailConfigActionArgs{RunId: &taintedRun},
	})
	var pending *ApprovalPendingError
	if !errors.As(err, &pending) || len(parts.snapshot()) != 0 {
		t.Fatalf("a tainted run's send to members: %v", err)
	}
	if held := world.gate.lastAction(); held.RunId == nil || *held.RunId != taintedRun {
		t.Fatal("the held action binds no run")
	}
	if _, err := world.client.Send(context.Background(), &MailSendArgs{
		From: testMailSendFrom, To: []string{testMailIngestRecipient}, Text: "x", Action: MailConfigActionArgs{RunId: &cleanRun},
	}); err != nil || len(parts.snapshot()) != 1 {
		t.Fatalf("an untainted run's send to members: %v", err)
	}
}

// A submitter that takes nothing, for the fuzz: every recipient known, every message refused as invalid.
type testMailSubmissionFuzzSubmitter struct{}

func (self *testMailSubmissionFuzzSubmitter) CheckSubmitRecipient(ctx context.Context, recipient string) error {
	return nil
}

func (self *testMailSubmissionFuzzSubmitter) SubmitMessage(ctx context.Context, args *MailSubmitArgs) (*MailSendResult, error) {
	return nil, ErrMailSendInvalid
}

// Whatever a client sends, the session neither panics nor outlives its connection, and its replies stay bounded.
func FuzzMailSubmission(f *testing.F) {
	f.Add([]byte("EHLO a\r\nAUTH PLAIN AHVyAHNlY3JldA==\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nx\r\n.\r\nQUIT\r\n"))
	f.Add([]byte("HELO a\r\nMAIL FROM:<a@b>\r\nRSET\r\nNOOP\r\nVRFY x\r\nQUIT\r\n"))
	f.Add([]byte("EHLO a\r\nAUTH PLAIN\r\n*\r\nAUTH LOGIN\r\nBDAT 3 LAST\r\nabc"))
	settings := DefaultMailSubmissionSettings()
	settings.ReadTimeout = 5 * time.Second
	settings.WriteTimeout = 5 * time.Second
	credential, err := NewMailLocalCredential(&testMailSecrets{})
	if err != nil {
		f.Fatal(err)
	}
	secret, err := NewMailLocalCredentialSecret(nil)
	if err != nil {
		f.Fatal(err)
	}
	if err := credential.Install(secret.Verifier); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		login, err := NewMailLocalLogin(nil, &MailLocalCredentialSettings{
			CredentialByteCount: 32, FailureDelay: time.Nanosecond, FailureDelayMax: time.Nanosecond, FailureWindow: time.Minute, FailureAddressCount: 4,
		})
		if err != nil {
			t.Fatal(err)
		}
		account := &MailSubmissionAccount{Credential: credential, Submitter: &testMailSubmissionFuzzSubmitter{}}
		server, err := NewMailSubmissionServer(context.Background(), &MailSubmissionServerArgs{
			Accounts: func() []*MailSubmissionAccount { return []*MailSubmissionAccount{account} },
			Login:    login,
			Settings: settings,
		})
		if err != nil {
			t.Fatal(err)
		}
		fed := newTestMailImapListener()
		served := make(chan struct{})
		go func() {
			server.Serve(fed)
			close(served)
		}()
		defer func() {
			server.Close()
			<-served
		}()
		serverConn, clientConn := net.Pipe()
		fed.offer(t, serverConn, true, false)
		readDone := make(chan int)
		go func() {
			total := 0
			buffer := make([]byte, 4096)
			for {
				read, err := clientConn.Read(buffer)
				total += read
				if err != nil {
					readDone <- total
					return
				}
			}
		}()
		clientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		clientConn.Write(input)
		clientConn.Close()
		if total := <-readDone; 1024*1024 < total {
			t.Fatalf("replies of %d bytes", total)
		}
	})
}
