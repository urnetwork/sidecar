//go:build !sidecar_http && !ios_extension

// §22.7's S6 (F5, send mail, M9) at T2 on SmtpSendWorld (SMTP-M9-31): what MAIL hands SmtpSender at §15.10's step 4
// reaches a ScriptedMx through the stub edge, and no client record reaches the MX before a part that covers it has
// verified; no unauthenticated MX gets a byte inside TLS; and a message over the DATA cap is too_large at the
// non-CHUNKING recipient domain alone. The real engine's run of the same send is smtpedgeservice's sender_test.go,
// and §15.10's forwarding rows are MAIL's (MAIL-M9-04, MAIL-M9-06).

package sidecartest_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	s6MailAddress = netip.MustParseAddr("198.51.100.25")
	s6DataAddress = netip.MustParseAddr("198.51.100.77")
	s6Tl4Address  = netip.MustParseAddr("198.51.100.66")
)

// Under a verifier that holds every client record past the handshake's three until a part covers it, the MX gets
// exactly the records the session released, each only once a verified part covered it, and the message arrives.
func TestS6NoRecordReachesTheMxBeforeItsPart(t *testing.T) {
	world := sidecartest.NewSmtpSendWorld(t, &sidecartest.SmtpSendWorldSettings{
		Verifier: &sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5},
	})
	mx := world.AddDomain("mail.example", "mx.mail.example", s6MailAddress, nil, true)
	desktop := world.AddHost(sidecartest.SmtpSendWorldProver(1024*1024), nil, nil)
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

// An MX that cannot be authenticated, a self-signed certificate the device's DoH does not name, is refused inside
// the handshake: the MX sees no command inside TLS, and the domain's outcome is tls_refused with a DSN.
func TestS6NoUnauthenticatedMx(t *testing.T) {
	world := sidecartest.NewSmtpSendWorld(t, nil)
	mx := world.AddDomain("plain.example", "mx.plain.example", s6Tl4Address, nil, false)
	desktop := world.AddHost(sidecartest.SmtpSendWorldProver(1024*1024), nil, nil)
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

// A message over the host's DATA cap goes to the CHUNKING domain and is too_large at the other alone, whose MX gets
// no command past EHLO.
func TestS6TooLargeForTheNonChunkingDomainAlone(t *testing.T) {
	world := sidecartest.NewSmtpSendWorld(t, nil)
	mx := world.AddDomain("mail.example", "mx.mail.example", s6MailAddress, nil, true)
	dataMx := world.AddDomain("data.example", "mx.data.example", s6DataAddress, sidecartest.SmtpDataOnlyMxScript(), true)
	desktop := world.AddHost(sidecartest.SmtpSendWorldProver(2*1024), nil, nil)
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
