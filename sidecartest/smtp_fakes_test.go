//go:build !sidecar_http

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestFakeSmtpMailboxPassesItsSuite(t *testing.T) {
	mailbox := NewFakeSmtpMailbox(nil)
	RunSmtpMailboxSuite(t, mailbox, func(ctx context.Context, effectKey []byte, signed []byte, message []byte) error {
		if !mailbox.PutOutbox(effectKey, signed, message) {
			return errors.New("the key was taken")
		}
		return nil
	})
}

// §15.10: o/ is created only if absent, so a second queueing of one effect keeps the first bytes.
func TestFakeSmtpMailboxKeepsTheFirstOutboxEntry(t *testing.T) {
	mailbox := NewFakeSmtpMailbox(nil)
	effectKey := []byte("effect")
	if !mailbox.PutOutbox(effectKey, []byte("first"), []byte("message")) || mailbox.PutOutbox(effectKey, []byte("second"), []byte("other")) {
		t.Fatal("the second put took the key")
	}
	file, err := mailbox.ReadOutbox(context.Background(), effectKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(file.Signed) != "first" {
		t.Errorf("signed %q", file.Signed)
	}
}

func TestFakeSmtpMailboxTakesAFaultPlan(t *testing.T) {
	faults := NewFaultQueue()
	mailbox := NewFakeSmtpMailbox(faults)
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "smtpmailbox.WriteOutcomes", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	outcomes := []*sidecar.SmtpDomainOutcome{{Domain: "mail.example", Outcome: sidecar.SmtpOutcomeQueued}}
	if err := mailbox.WriteOutcomes(context.Background(), []byte("effect"), outcomes); err == nil {
		t.Fatal("the planned failure did not fire")
	}
	if _, err := mailbox.ReadOutcomes(context.Background(), []byte("effect")); !errors.Is(err, sidecar.ErrSmtpMailboxNotFound) {
		t.Errorf("a failure before apply wrote: %v", err)
	}
	if mailbox.OpCount("WriteOutcomes") != 0 {
		t.Errorf("counted %d", mailbox.OpCount("WriteOutcomes"))
	}
}

func testFakeSmtpPreamble() *sidecar.SmtpProofPreamble {
	return &sidecar.SmtpProofPreamble{RecipientDomain: "mail.example", RecipientCount: 1, MxHost: "mx1.mail.example"}
}

// A zero script holds nothing: every record goes to the MX as it comes.
func TestFakeSmtpProofSessionWithNoScriptReleasesEveryRecord(t *testing.T) {
	verifier := NewFakeSmtpProofVerifier(nil)
	session, err := verifier.NewSmtpProofSession(testFakeSmtpPreamble())
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []string{"one", "two", "three"} {
		released, err := session.ClientRecord([]byte(record))
		if err != nil || len(released) != 1 || string(released[0]) != record {
			t.Errorf("%s: %q, %v", record, released, err)
		}
	}
	if fake := verifier.Sessions()[0]; len(fake.Released()) != 3 || fake.Preamble().MxHost != "mx1.mail.example" {
		t.Errorf("released %q", fake.Released())
	}
}

// E3's shape by counts: past the handshake a record waits for a part, and a part releases what it
// covers, oldest first, and clears what follows up to its count.
func TestFakeSmtpProofSessionHoldsRecordsForTheirPart(t *testing.T) {
	verifier := NewFakeSmtpProofVerifier(&FakeSmtpProofScript{HoldAfterClientRecords: 2, MailForwardedAtClientRecord: 4})
	session, _ := verifier.NewSmtpProofSession(testFakeSmtpPreamble())
	ctx := context.Background()
	for _, record := range []string{"hello", "finished"} {
		if released, err := session.ClientRecord([]byte(record)); err != nil || len(released) != 1 {
			t.Fatalf("%s: %q, %v", record, released, err)
		}
	}
	if released, err := session.ClientRecord([]byte("ehlo")); err != nil || len(released) != 0 {
		t.Fatalf("ehlo went ahead of its part: %q, %v", released, err)
	}
	released, err := session.VerifyPart(ctx, &sidecar.SmtpProofPart{Index: 1, FirstRecord: 1, LastRecord: 1})
	if err != nil || len(released) != 1 || string(released[0]) != "ehlo" {
		t.Fatalf("pi1 released %q, %v", released, err)
	}
	if session.MailForwarded() {
		t.Error("mail forwarded before MAIL")
	}
	// pi2 verifies ahead of its records, as a part may (D-SMTP-22), so they pass as they come
	if released, err = session.VerifyPart(ctx, &sidecar.SmtpProofPart{Index: 2, FirstRecord: 2, LastRecord: 3}); err != nil || len(released) != 0 {
		t.Fatalf("pi2 released %q, %v", released, err)
	}
	for _, record := range []string{"mail", "rcpt"} {
		if released, err := session.ClientRecord([]byte(record)); err != nil || len(released) != 1 {
			t.Fatalf("%s: %q, %v", record, released, err)
		}
	}
	if !session.MailForwarded() {
		t.Error("MAIL went and the session does not say so")
	}
	if released, err := session.ClientRecord([]byte("bdat")); err != nil || len(released) != 0 {
		t.Fatalf("a record past pi2's count went: %q, %v", released, err)
	}
	want := [][]byte{[]byte("hello"), []byte("finished"), []byte("ehlo"), []byte("mail"), []byte("rcpt")}
	if got := verifier.Sessions()[0].Released(); len(got) != len(want) || !bytes.Equal(bytes.Join(got, nil), bytes.Join(want, nil)) {
		t.Errorf("released %q", got)
	}
}

// A refused part and a cut each end the session: nothing goes to the MX after either.
func TestFakeSmtpProofSessionEndsAtARefusal(t *testing.T) {
	ctx := context.Background()
	verifier := NewFakeSmtpProofVerifier(&FakeSmtpProofScript{HoldAfterClientRecords: 1, RefuseParts: map[uint32]error{1: sidecar.ErrSmtpRecordCut}})
	session, _ := verifier.NewSmtpProofSession(testFakeSmtpPreamble())
	session.ClientRecord([]byte("hello"))
	session.ClientRecord([]byte("ehlo"))
	if _, err := session.VerifyPart(ctx, &sidecar.SmtpProofPart{Index: 1, FirstRecord: 1, LastRecord: 1}); !errors.Is(err, sidecar.ErrSmtpRecordCut) {
		t.Fatalf("pi1: %v", err)
	}
	if released, err := session.ClientRecord([]byte("mail")); err == nil || len(released) != 0 {
		t.Errorf("a record after the refusal: %q, %v", released, err)
	}
	if err := session.ServerRecord([]byte("reply")); err == nil {
		t.Error("a server record after the refusal")
	}

	verifier = NewFakeSmtpProofVerifier(&FakeSmtpProofScript{CutAtClientRecord: 2, RefuseShts: errors.New("E2")})
	session, _ = verifier.NewSmtpProofSession(testFakeSmtpPreamble())
	session.ClientRecord([]byte("hello"))
	if _, err := session.ClientRecord([]byte("forged")); !errors.Is(err, sidecar.ErrSmtpRecordCut) {
		t.Errorf("the cut: %v", err)
	}
	if !verifier.Sessions()[0].Ended() {
		t.Error("a cut session goes on")
	}

	verifier = NewFakeSmtpProofVerifier(&FakeSmtpProofScript{RefuseShts: errors.New("E2")})
	session, _ = verifier.NewSmtpProofSession(testFakeSmtpPreamble())
	if _, err := session.DiscloseShts([]byte("secret")); err == nil {
		t.Error("a refused SHTS passed")
	}
	calls := verifier.Sessions()[0].Calls()
	if len(calls) != 1 || calls[0].Method != "DiscloseShts" || string(calls[0].Data) != "secret" || calls[0].Err == nil {
		t.Errorf("calls %+v", calls)
	}

	verifier.RefuseSessions(errors.New("unready"))
	if _, err := verifier.NewSmtpProofSession(testFakeSmtpPreamble()); err == nil {
		t.Error("a refused session opened")
	}
}
