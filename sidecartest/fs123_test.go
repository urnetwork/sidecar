//go:build !sidecar_http && !ios_extension

// FS-123 at T2 on SmtpSendWorld (SMTP-M9-31, D-SMTP-20): a message 1 KiB over the prover host's measured
// smtp_data_proof_bytes to one CHUNKING and one non-CHUNKING scripted MX, sent from a desktop and queued from a
// phone. Check predicts ok for the first once its mode is known and, once the second's is, too_large with both byte
// counts, else unknown; the send delivers to the first and stops before MAIL at the second, whose outcome alone is
// too_large with size and cap, its DSN naming that domain; a second prover host whose recorded cap fits takes the
// phone's message instead; deferred, refused and tls_refused outcomes per domain reach or/ and mail_send; and no
// outcome or DSN names an indexer, receiver or coverage setting.
//
// GetSendResult and CheckSend are the sdk's over MAIL's MailClient (MAIL-M9-01, MAIL-M9-02), which have not landed:
// this reads what they would, or/ and SmtpSender.Check. GetReceiverCoverage's copy is MAIL-M8-03's.

package sidecartest_test

import (
	"bytes"
	"context"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// No copy points to an inbound indexer, receiver or coverage setting (§14.5's Copy, §18.5).
var fs123InboundWords = regexp.MustCompile(`(?i)\b(indexers?|receivers?|coverage)\b`)

// A body that brings the message's DATA count to exactly target octets, from message's count with a one-line body.
func fs123Body(t *testing.T, world *sidecartest.SmtpSendWorld, recipients []string, target uint64) string {
	t.Helper()
	probe := world.Message(recipients, nil, "", "FS-123", "x\r\n")
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{Message: probe.Message, HeaderFromDomain: sidecartest.SmtpSendWorldNetworkDomain,
		MessageIdDomain: sidecartest.SmtpSendWorldNetworkDomain, Now: world.Clock.Now()})
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

func TestFs123SentFromADesktop(t *testing.T) {
	const capByteCount = 4 * 1024
	world := sidecartest.NewSmtpSendWorld(t, nil)
	chunking := world.AddDomain("mail.example", "mx.mail.example", netip.MustParseAddr("198.51.100.25"), nil, true)
	data := world.AddDomain("data.example", "mx.data.example", netip.MustParseAddr("198.51.100.77"), sidecartest.SmtpDataOnlyMxScript(), true)
	desktop := world.AddHost(sidecartest.SmtpSendWorldProver(capByteCount), nil, nil)
	recipients := []string{"bob@mail.example", "dave@data.example"}
	message := world.Message(recipients, nil, "", "FS-123", fs123Body(t, world, recipients, capByteCount+1024))

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
	if match := fs123InboundWords.Find(dsns[0].Dsn); match != nil {
		t.Errorf("the DSN names %q", match)
	}
	if events := world.MailSendEvents(); len(events) != 2 || *events[0].SendId != message.SendId {
		t.Errorf("%d mail_send events", len(events))
	}
}

// Queued from a phone: the host the hash picks among the member's prover hosts, under the cap, leaves the DATA domain
// as deferred, and a second host whose recorded cap fits sends it; the phone reads the outcome, and its Check prices
// on the member's records.
func TestFs123QueuedFromAPhone(t *testing.T) {
	world := sidecartest.NewSmtpSendWorld(t, nil)
	data := world.AddDomain("data.example", "mx.data.example", netip.MustParseAddr("198.51.100.77"), sidecartest.SmtpDataOnlyMxScript(), true)
	phone := world.AddHost(nil, nil, nil)
	small := world.AddHost(sidecartest.SmtpSendWorldProver(2*1024), nil, nil)
	large := world.AddHost(sidecartest.SmtpSendWorldProver(1024*1024), nil, nil)
	recipients := []string{"dave@data.example"}
	body := fs123Body(t, world, recipients, 2*1024+1024)
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

// deferred, refused and tls_refused, each at a domain of its own, reach or/ and a mail_send event each, and no copy
// names an indexer, receiver or coverage setting.
func TestFs123OtherOutcomesReachTheResult(t *testing.T) {
	edgeSettings := sidecartest.DefaultStubSmtpEdgeSettings()
	world := sidecartest.NewSmtpSendWorld(t, &sidecartest.SmtpSendWorldSettings{Edge: edgeSettings})
	refusing := sidecartest.DefaultMxScript()
	refusing.Replies["MAIL"] = "550 5.7.1 Sender refused"
	world.AddDomain("refuse.example", "mx.refuse.example", netip.MustParseAddr("198.51.100.30"), refusing, true)
	world.AddDomain("plain.example", "mx.plain.example", netip.MustParseAddr("198.51.100.66"), nil, false)
	desktop := world.AddHost(sidecartest.SmtpSendWorldProver(1024*1024), nil, nil)
	message := world.Message([]string{"bob@refuse.example", "carol@plain.example"}, nil, "", "FS-123", "body\r\n")
	result, err := desktop.Sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Domains[0].Outcome != sidecar.SmtpOutcomeRefused || result.Domains[0].ReplyCode != 550 || result.Domains[1].Outcome != sidecar.SmtpOutcomeTlsRefused {
		t.Errorf("outcomes %+v %+v", result.Domains[0], result.Domains[1])
	}

	// the edge holds every preamble: deferred, with its wait, never failed
	edgeSettings.Code = protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER
	edgeSettings.RetryAfter = 2 * time.Minute
	held := world.Message([]string{"erin@refuse.example"}, nil, "", "FS-123", "body\r\n")
	result, err = desktop.Sender.Send(context.Background(), held)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := world.Outcome(held, "refuse.example"); outcome == nil || outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter != 2*time.Minute {
		t.Errorf("deferred: %+v", outcome)
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
		if match := fs123InboundWords.Find(dsn.Dsn); match != nil {
			t.Errorf("a DSN names %q", match)
		}
		if bytes.Contains(dsn.Dsn, []byte(" bytes")) {
			t.Errorf("a DSN that is not too_large's cites a size")
		}
	}
}
