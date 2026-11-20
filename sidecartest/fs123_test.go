//go:build !sidecar_http && !ios_extension

// FS-123 at T2 (SMTP-M9-31, D-SMTP-20): smtp_send_rows.go's rows on SmtpSendWorld's stub edge, sent from a desktop
// and queued from a phone, with deferred, refused and tls_refused reaching or/ and mail_send. T3 runs the same rows
// on the smtpedge block's engine over server's stores (server/cli/smtpedge's s6_test.go). And QD-1122's runner row: a
// phone's entry a prover host sends names its send by its Message-ID, in the host's mail_send and in or/'s record.

package sidecartest_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs123SentFromADesktop(t *testing.T) {
	sidecartest.RunFs123SentFromADesktop(t, sidecartest.NewSmtpSendWorld)
}

func TestFs123QueuedFromAPhone(t *testing.T) {
	sidecartest.RunFs123QueuedFromAPhone(t, sidecartest.NewSmtpSendWorld)
}

func TestFs123OtherOutcomesReachTheResult(t *testing.T) {
	sidecartest.RunFs123OtherOutcomesReachTheResult(t, sidecartest.NewSmtpSendWorld)
}

// QD-1122 at T2: a phone's entry, whose signed body carries no send id, is sent by a prover host's runner, whose
// mail_send names the send the entry's Message-ID names, as or/'s record does once the host writes it, so the host's
// own events and the composing device's GetSendResult name one send.
func TestFs123RunnerNamesTheSendItsEntryNames(t *testing.T) {
	world := sidecartest.NewSmtpSendWorld(t, nil)
	world.AddDomain("chunking.example", "mx.chunking.example", netip.MustParseAddr("198.51.100.77"), nil, true)
	phone := world.AddHost(nil, nil, nil)
	desktop := world.AddHost(sidecartest.SmtpSendWorldProver(1024*1024), nil, nil)
	message := world.Message([]string{"bob@chunking.example"}, nil, "", "FS-123", "body\r\n")
	sendId, ok := sidecar.MailOutboxSendIdOf(message.Message)
	if !ok {
		t.Fatal("the message names no send")
	}
	// the composing device's send id reaches the host by the message alone
	message.SendId = sidecar.Id{}
	world.Queue(phone, message)
	if pass := world.RunOnce(desktop); pass.Sent != 1 {
		t.Fatalf("the pass %+v", pass)
	}
	events := world.MailSendEvents()
	if len(events) != 1 || events[0].SendId == nil || *events[0].SendId != sendId {
		t.Errorf("the host raised %+v", events)
	}
	named, outcomes, err := world.Mailbox.ReadSendOutcomes(context.Background(), message.EffectKey)
	if err != nil || named != sendId || len(outcomes) != 1 || outcomes[0].Outcome != sidecar.SmtpOutcomeSent {
		t.Errorf("or/ names %v with %+v: %v", named, outcomes, err)
	}
}
