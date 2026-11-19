//go:build !sidecar_http && !ios_extension

// §22.7's S6 and FS-123 on SmtpSendWorld (SMTP-M9-31; FS-123, D-SMTP-20, R-SMTP-6), one copy for both tiers: each
// row builds its world through the maker it is given, so s6_test.go and fs123_test.go run it on the stub edge (T2),
// and server/cli/smtpedge's s6_test.go on the smtpedge block's engine over server's stores and Redis (T3). That is
// §22.8's builders row for a row on T2 and T3: the tier's test is the thin call, never a second copy.
//
// S6 (F5, send mail, M9): what MAIL hands SmtpSender at §15.10's step 4 reaches a ScriptedMx through the edge, and
// no client record reaches the MX before a part that covers it has verified; no unauthenticated MX gets a byte
// inside TLS; and a message over the DATA cap is too_large at the non-CHUNKING recipient domain alone. §15.10's
// forwarding rows are MAIL's (MAIL-M9-04, MAIL-M9-06).
//
// FS-123: a message 1 KiB over the prover host's measured smtp_data_proof_bytes to one CHUNKING and one
// non-CHUNKING scripted MX, sent from a desktop and queued from a phone. Check predicts ok for the first once its
// mode is known and, once the second's is, too_large with both byte counts, else unknown; the send delivers to the
// first and stops before MAIL at the second, whose outcome alone is too_large with size and cap, its DSN naming that
// domain; a second prover host whose recorded cap fits takes the phone's message instead; deferred, refused and
// tls_refused outcomes per domain reach or/ and mail_send; and no outcome or DSN names an indexer, receiver or
// coverage setting. GetSendResult and CheckSend are the sdk's over MAIL's MailClient (MAIL-M9-01, MAIL-M9-02),
// which have not landed: the rows read what they would, or/ and SmtpSender.Check. GetReceiverCoverage's copy is
// MAIL-M8-03's.
//
// The privacy row (R-SMTP-7, R-SMTP-10, I-2, I-13): canaries in a mail body, its subject, its From display name and
// a recipient's local part are found in nothing the edge read, answered or kept and nothing the sender logged, and
// no DKIM key testHookSecret reported is found anywhere; the MX, the destination, holds them all, which shows they
// were there to leak. What the edge read and kept is what its world adds to the capture: the stub's records on T2;
// on T3 the engine's stream bytes, its calls and answers, its log lines and server's stores.
//
// Names are .example, addresses RFC 5737's, and every wait is on the world's fake clock.

package sidecartest

import (
	"bytes"
	"context"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Builds a row's world: NewSmtpSendWorld on T2, the engine's on T3.
type SmtpSendWorldMaker func(t testing.TB, settings *SmtpSendWorldSettings) *SmtpSendWorld

// The rows' MX addresses, RFC 5737's.
var (
	smtpRowMailAddress   = netip.MustParseAddr("198.51.100.25")
	smtpRowDataAddress   = netip.MustParseAddr("198.51.100.77")
	smtpRowRefuseAddress = netip.MustParseAddr("198.51.100.30")
	smtpRowPlainAddress  = netip.MustParseAddr("198.51.100.66")
)

// No copy points to an inbound indexer, receiver or coverage setting (§14.5's Copy, §18.5).
var smtpRowInboundWords = regexp.MustCompile(`(?i)\b(indexers?|receivers?|coverage)\b`)

// A body that brings the message's DATA count to exactly target octets, from the count of world's message to
// recipients with a one-line body.
func smtpRowBody(t testing.TB, world *SmtpSendWorld, recipients []string, target uint64) string {
	t.Helper()
	probe := world.Message(recipients, nil, "", "FS-123", "x\r\n")
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{Message: probe.Message, HeaderFromDomain: world.NetworkDomain,
		MessageIdDomain: world.NetworkDomain, Now: world.Clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	base, err := wire.ByteCount(sidecar.SmtpModeData)
	if err != nil {
		t.Fatal(err)
	}
	pad := int(target - base)
	return strings.Repeat(strings.Repeat("y", 70)+"\r\n", pad/72) + strings.Repeat("z", pad%72) + "x\r\n"
}

// S6: under a verifier that holds every client record past the handshake's three until a part covers it, the MX
// gets exactly the records the session released, each only once a verified part covered it, and the message
// arrives.
func RunS6NoRecordReachesTheMxBeforeItsPart(t testing.TB, newWorld SmtpSendWorldMaker) {
	t.Helper()
	world := newWorld(t, &SmtpSendWorldSettings{
		Verifier: &FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5},
	})
	mx := world.AddDomain("mail.example", "mx.mail.example", smtpRowMailAddress, nil, true)
	desktop := world.AddHost(SmtpSendWorldProver(1024*1024), nil, nil)
	message := world.Message([]string{"bob@mail.example"}, nil, "", "S6", "A body line.\r\n")
	result, err := desktop.Sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeSent || outcome.TlsLevel != sidecar.SmtpTlsLevelIndependentMx {
		t.Fatalf("outcome %+v", outcome)
	}
	if len(mx.Transactions()) != 1 {
		t.Fatalf("%d transactions", len(mx.Transactions()))
	}
	sessions := world.Verifier.Sessions()
	if len(sessions) != 1 || !sessions[0].MailForwarded() {
		t.Fatalf("%d sessions", len(sessions))
	}
	// walk the session's calls in order: credit is the handshake's three records and each verified part's records
	credit := uint64(3)
	released := uint64(0)
	clientRecords := uint64(0)
	parts := 0
	for _, call := range sessions[0].Calls() {
		switch call.Method {
		case "ClientRecord":
			clientRecords += 1
		case "VerifyPart":
			if call.Err != nil {
				t.Fatalf("part %d refused: %v", call.Part.Index, call.Err)
			}
			parts += 1
			if call.Part.FirstRecord <= call.Part.LastRecord {
				credit += call.Part.LastRecord - call.Part.FirstRecord + 1
			}
		}
		released += uint64(len(call.Released))
		if credit < released {
			t.Fatalf("%d records reached the MX on %d of credit, at a %s", released, credit, call.Method)
		}
	}
	if parts < 3 || released != clientRecords {
		t.Errorf("%d parts; %d of %d client records released", parts, released, clientRecords)
	}
}

// S6: an MX that cannot be authenticated, a self-signed certificate the device's DoH does not name, is refused
// inside the handshake: the MX sees no command inside TLS, and the domain's outcome is tls_refused with a DSN.
func RunS6NoUnauthenticatedMx(t testing.TB, newWorld SmtpSendWorldMaker) {
	t.Helper()
	world := newWorld(t, nil)
	mx := world.AddDomain("plain.example", "mx.plain.example", smtpRowPlainAddress, nil, false)
	desktop := world.AddHost(SmtpSendWorldProver(1024*1024), nil, nil)
	result, err := desktop.Sender.Send(context.Background(), world.Message([]string{"bob@plain.example"}, nil, "", "S6", "body\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeTlsRefused || outcome.TlsLevel != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("outcome %+v", outcome)
	}
	for _, event := range mx.Events() {
		if event.Secure {
			t.Errorf("the MX saw %q inside TLS", event.Command)
		}
	}
	if len(mx.Transactions()) != 0 || len(world.Mailbox.Dsns()) != 1 {
		t.Errorf("%d transactions, %d DSNs", len(mx.Transactions()), len(world.Mailbox.Dsns()))
	}
}

// S6: a message over the host's DATA cap goes to the CHUNKING domain and is too_large at the other alone, whose MX
// gets no command past EHLO.
func RunS6TooLargeForTheNonChunkingDomainAlone(t testing.TB, newWorld SmtpSendWorldMaker) {
	t.Helper()
	world := newWorld(t, nil)
	mx := world.AddDomain("mail.example", "mx.mail.example", smtpRowMailAddress, nil, true)
	dataMx := world.AddDomain("data.example", "mx.data.example", smtpRowDataAddress, SmtpDataOnlyMxScript(), true)
	desktop := world.AddHost(SmtpSendWorldProver(2*1024), nil, nil)
	body := strings.Repeat("A line of the body, long enough to pass a small cap.\r\n", 60)
	result, err := desktop.Sender.Send(context.Background(), world.Message([]string{"bob@mail.example", "dave@data.example"}, nil, "", "S6", body))
	if err != nil {
		t.Fatal(err)
	}
	if result.Domains[0].Outcome != sidecar.SmtpOutcomeSent || result.Domains[1].Outcome != sidecar.SmtpOutcomeTooLarge || result.Domains[1].CapByteCount != 2*1024 {
		t.Errorf("outcomes %+v %+v", result.Domains[0], result.Domains[1])
	}
	if len(mx.Transactions()) != 1 || len(dataMx.Transactions()) != 0 {
		t.Errorf("%d and %d transactions", len(mx.Transactions()), len(dataMx.Transactions()))
	}
	for _, event := range dataMx.Events() {
		if event.Secure && !strings.HasPrefix(event.Command, "EHLO") {
			t.Errorf("the DATA MX saw %q", event.Command)
		}
	}
}

// FS-123 from a desktop: Check before any session knows no mode; the send delivers to the CHUNKING domain and is
// too_large at the DATA one with both counts; Check after it knows both modes; the one DSN names the DATA domain
// and its size and nothing inbound; each domain's change raised mail_send.
func RunFs123SentFromADesktop(t testing.TB, newWorld SmtpSendWorldMaker) {
	t.Helper()
	const capByteCount = 4 * 1024
	world := newWorld(t, nil)
	chunking := world.AddDomain("mail.example", "mx.mail.example", smtpRowMailAddress, nil, true)
	data := world.AddDomain("data.example", "mx.data.example", smtpRowDataAddress, SmtpDataOnlyMxScript(), true)
	desktop := world.AddHost(SmtpSendWorldProver(capByteCount), nil, nil)
	recipients := []string{"bob@mail.example", "dave@data.example"}
	message := world.Message(recipients, nil, "", "FS-123", smtpRowBody(t, world, recipients, capByteCount+1024))

	check, err := desktop.Sender.Check(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range check.Domains {
		if domain.Mode != sidecar.SmtpModeUnknown || domain.Prediction != sidecar.SmtpCheckUnknown || domain.CapByteCount != capByteCount {
			t.Errorf("before any session: %+v", domain)
		}
	}
	result, err := desktop.Sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Domains[0].Outcome != sidecar.SmtpOutcomeSent || len(chunking.Transactions()) != 1 {
		t.Errorf("the CHUNKING domain: %+v", result.Domains[0])
	}
	tooLarge := result.Domains[1]
	if tooLarge.Outcome != sidecar.SmtpOutcomeTooLarge || tooLarge.ByteCount != capByteCount+1024 || tooLarge.CapByteCount != capByteCount || len(data.Transactions()) != 0 {
		t.Errorf("the DATA domain: %+v", tooLarge)
	}
	check, err = desktop.Sender.Check(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if domain := check.Domains[0]; domain.Mode != sidecar.SmtpModeBdat || domain.Prediction != sidecar.SmtpCheckOk {
		t.Errorf("the CHUNKING domain's check: %+v", domain)
	}
	if domain := check.Domains[1]; domain.Mode != sidecar.SmtpModeData || domain.Prediction != sidecar.SmtpCheckTooLarge ||
		domain.ByteCount != capByteCount+1024 || domain.CapByteCount != capByteCount {
		t.Errorf("the DATA domain's check: %+v", domain)
	}
	dsns := world.Mailbox.Dsns()
	if len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte("data.example")) || !bytes.Contains(dsns[0].Dsn, []byte("5120 bytes")) {
		t.Fatalf("dsns %d", len(dsns))
	}
	if match := smtpRowInboundWords.Find(dsns[0].Dsn); match != nil {
		t.Errorf("the DSN names %q", match)
	}
	if events := world.MailSendEvents(); len(events) != 2 || *events[0].SendId != message.SendId {
		t.Errorf("%d mail_send events", len(events))
	}
}

// FS-123 queued from a phone: the host the hash picks among the member's prover hosts, under the cap, leaves the
// DATA domain as deferred, and a second host whose recorded cap fits sends it; the phone reads the outcome, and its
// Check prices on the member's records.
func RunFs123QueuedFromAPhone(t testing.TB, newWorld SmtpSendWorldMaker) {
	t.Helper()
	world := newWorld(t, nil)
	data := world.AddDomain("data.example", "mx.data.example", smtpRowDataAddress, SmtpDataOnlyMxScript(), true)
	phone := world.AddHost(nil, nil, nil)
	small := world.AddHost(SmtpSendWorldProver(2*1024), nil, nil)
	large := world.AddHost(SmtpSendWorldProver(1024*1024), nil, nil)
	recipients := []string{"dave@data.example"}
	body := smtpRowBody(t, world, recipients, 2*1024+1024)
	message := world.Message(recipients, nil, "", "FS-123", body)
	queued, err := phone.Sender.Send(context.Background(), message)
	if err != nil || queued.Domains[0].Outcome != sidecar.SmtpOutcomeQueued {
		t.Fatalf("the phone: %+v, %v", queued, err)
	}
	world.Queue(phone, message)
	// whichever host the hash picks, the message ends at the one whose cap fits
	for range 3 {
		world.RunOnce(small)
		world.RunOnce(large)
	}
	outcome := world.Outcome(message, "data.example")
	if outcome == nil || outcome.Outcome != sidecar.SmtpOutcomeSent || outcome.Mode != sidecar.SmtpModeData {
		t.Fatalf("or/ for the phone: %+v", outcome)
	}
	if transactions := data.Transactions(); len(transactions) != 1 {
		t.Fatalf("%d transactions", len(transactions))
	}
	if sends := small.Prover.Sends(); 1 < len(sends) {
		t.Errorf("the small host sent %d times", len(sends))
	}
	check, err := phone.Sender.Check(context.Background(), world.Message(recipients, nil, "", "FS-123", body))
	if err != nil {
		t.Fatal(err)
	}
	if domain := check.Domains[0]; domain.CapByteCount != 1024*1024 || domain.Mode != sidecar.SmtpModeData || domain.Prediction != sidecar.SmtpCheckOk || domain.ExpectedDelay <= 0 {
		t.Errorf("the phone's check: %+v", domain)
	}
}

// FS-123's other outcomes: refused and tls_refused, each at a domain of its own, then deferred while the edge holds
// every preamble, reach or/ with the wait it answered and a mail_send event each, a held send never failed; and no
// copy names an indexer, receiver or coverage setting, nor cites a size outside too_large.
func RunFs123OtherOutcomesReachTheResult(t testing.TB, newWorld SmtpSendWorldMaker) {
	t.Helper()
	world := newWorld(t, nil)
	refusing := DefaultMxScript()
	refusing.Replies["MAIL"] = "550 5.7.1 Sender refused"
	world.AddDomain("refuse.example", "mx.refuse.example", smtpRowRefuseAddress, refusing, true)
	world.AddDomain("plain.example", "mx.plain.example", smtpRowPlainAddress, nil, false)
	desktop := world.AddHost(SmtpSendWorldProver(1024*1024), nil, nil)
	message := world.Message([]string{"bob@refuse.example", "carol@plain.example"}, nil, "", "FS-123", "body\r\n")
	result, err := desktop.Sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Domains[0].Outcome != sidecar.SmtpOutcomeRefused || result.Domains[0].ReplyCode != 550 || result.Domains[1].Outcome != sidecar.SmtpOutcomeTlsRefused {
		t.Errorf("outcomes %+v %+v", result.Domains[0], result.Domains[1])
	}

	// the edge holds every preamble: deferred, with its wait, never failed
	wait := world.HoldPreambles(2 * time.Minute)
	held := world.Message([]string{"erin@refuse.example"}, nil, "", "FS-123", "body\r\n")
	if _, err := desktop.Sender.Send(context.Background(), held); err != nil {
		t.Fatal(err)
	}
	if outcome := world.Outcome(held, "refuse.example"); outcome == nil || outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter != wait {
		t.Errorf("deferred for %v: %+v", wait, outcome)
	}
	for _, check := range []struct {
		message *sidecar.SmtpOutboundMessage
		domain  string
		want    sidecar.SmtpOutcomeKind
	}{
		{message: message, domain: "refuse.example", want: sidecar.SmtpOutcomeRefused},
		{message: message, domain: "plain.example", want: sidecar.SmtpOutcomeTlsRefused},
		{message: held, domain: "refuse.example", want: sidecar.SmtpOutcomeDeferred},
	} {
		if outcome := world.Outcome(check.message, check.domain); outcome == nil || outcome.Outcome != check.want {
			t.Errorf("%s: or/ holds %+v", check.domain, outcome)
		}
	}
	if events := world.MailSendEvents(); len(events) != 3 {
		t.Errorf("%d mail_send events", len(events))
	}
	for _, dsn := range world.Mailbox.Dsns() {
		if match := smtpRowInboundWords.Find(dsn.Dsn); match != nil {
			t.Errorf("a DSN names %q", match)
		}
		if bytes.Contains(dsn.Dsn, []byte(" bytes")) {
			t.Errorf("a DSN that is not too_large's cites a size")
		}
	}
}

// The privacy row: a send carrying canaries in its body, subject, From display name and a recipient's local part
// leaves none of them, and no DKIM key testHookSecret reported, in anything the edge read, answered or kept or the
// sender logged, while the MX holds them all. Needs the sidecar_testhooks build, for the keys.
func RunSmtpSendCarriesNoCanaryPastTheDevice(t testing.TB, newWorld SmtpSendWorldMaker) {
	t.Helper()
	capture := NewPrivacyCapture()
	var secretLock sync.Mutex
	secretKinds := map[string]int{}
	remove, err := InstallTestHooks(func(kind string, secret []byte) {
		secretLock.Lock()
		secretKinds[kind] += 1
		secretLock.Unlock()
		capture.AddSecret(kind, secret)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	world := newWorld(t, &SmtpSendWorldSettings{
		Verifier: &FakeSmtpProofScript{HoldAfterClientRecords: 3},
		Capture:  capture,
	})
	mx := world.AddDomain("mail.example", "mx.mail.example", smtpRowMailAddress, nil, true)
	host := world.AddHost(SmtpSendWorldProver(1024*1024), nil, capture.Logger("smtp sender"))
	body := capture.CanaryText("mail body")
	subject := capture.CanaryText("mail subject")
	local := capture.CanaryText("recipient local part")
	name := capture.CanaryText("from display name")
	message := world.Message([]string{local + "@mail.example"}, nil, name, subject, "Hello "+body+"\r\n")
	result, err := host.Sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Domains[0].Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("outcome %+v", result.Domains[0])
	}
	transactions := mx.Transactions()
	if len(transactions) != 1 {
		t.Fatalf("%d transactions", len(transactions))
	}
	// the destination holds every canary, so a leak would have had them to leak
	for _, canary := range []string{body, subject, name} {
		if !bytes.Contains(transactions[0].Message, []byte(canary)) {
			t.Errorf("the MX got no %q", canary)
		}
	}
	if !bytes.Contains([]byte(transactions[0].Recipients[0]), []byte(local)) {
		t.Errorf("the MX got recipients %v", transactions[0].Recipients)
	}
	// what the edge kept is in its stores once it has written them
	world.Settle()
	if capture.ItemCount(PrivacyClassHandler) < 10 {
		t.Fatalf("the edge read %d items", capture.ItemCount(PrivacyClassHandler))
	}
	for _, finding := range capture.Scan() {
		t.Error(finding)
	}
	secretLock.Lock()
	signingKeys := secretKinds["dkim_private_key"]
	secretLock.Unlock()
	if signingKeys == 0 {
		t.Error("no DKIM key reached the scan")
	}
	// a canary planted where a server would see it is found, so the clean scan read what it says it read
	capture.Add(PrivacyClassLog, "planted", []byte("a leak of "+body))
	if len(capture.Scan()) == 0 {
		t.Error("the scan missed a planted canary")
	}
}
