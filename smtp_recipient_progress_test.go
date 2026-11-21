//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A newer composing device can sign fields that the current prover does not interpret.
func TestSmtpRecipientProgressKeepsTheExactSignedEnvelope(t *testing.T) {
	signerId := NewId()
	signer := newTestMailOutboxSigner(signerId)
	message := &SmtpOutboundMessage{
		EffectKey: testMailOutboxEffectKey(), Sender: "bounce@sender.example",
		Recipients: []string{"a@outside.example"}, Message: []byte("From: a@sender.example\r\n\r\ntest\r\n"),
	}
	var authenticated []byte
	signed, err := SignSmtpOutboxEntry(message, func(purpose string, kind bridge.SignedType, body []byte) (*bridge.Signed, error) {
		// Unknown field 15, varint 1.
		authenticated = append(bytes.Clone(body), 0x78, 0x01)
		return signer.sign(purpose, kind, authenticated)
	})
	if err != nil {
		t.Fatal(err)
	}
	file := &SmtpOutboxFile{EffectKey: message.EffectKey, Message: message.Message, Signed: signed}
	entry, err := VerifySmtpOutboxEntry(file, func(id Id) ed25519.PublicKey {
		if id != signerId {
			return nil
		}
		return signer.publicKey()
	})
	if err != nil || !bytes.Equal(entry.signedBody, authenticated) {
		t.Fatalf("the verified envelope bytes changed: %v", err)
	}
}

func TestSmtpRecipientProgressSurvivesConcurrentMailboxWrites(t *testing.T) {
	message := &SmtpOutboundMessage{Sender: "b@x.example", EffectKey: []byte("example"), Message: []byte("immutable")}
	domain := &smtpDomainPlan{domain: "outside.example", recipients: []string{"a@outside.example", "b@outside.example", "c@outside.example"}}
	message.Recipients = slices.Clone(domain.recipients)
	entry, err := smtpOutboxEntryBody(message)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(entry)
	left, err := newSmtpRecipientProgress(digest, domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	right, err := newSmtpRecipientProgress(digest, domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	left.finish(domain.recipients[0], true)
	right.finish(domain.recipients[1], false)
	clock := time.Now()
	outcome := &SmtpDomainOutcome{Domain: domain.domain, Outcome: SmtpOutcomeDeferred, UpdateTime: clock, progress: left.record}
	first, err := SmtpMailboxOutcomeRecord([]*SmtpDomainOutcome{outcome}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome.progress = right.record
	second, err := SmtpMailboxOutcomeRecord([]*SmtpDomainOutcome{outcome}, first)
	if err != nil {
		t.Fatal(err)
	}
	outcomes, err := SmtpMailboxOutcomes(second)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := newSmtpRecipientProgress(digest, domain, outcomes[0].progress)
	if err != nil || !slices.Equal(merged.remaining(domain.recipients), domain.recipients[2:]) {
		t.Fatalf("a completed recipient was lost: %v", err)
	}
	slices.Reverse(domain.recipients)
	if _, err := newSmtpRecipientProgress(digest, domain, outcomes[0].progress); !errors.Is(err, ErrMailOutboxFileInvalid) {
		t.Fatalf("ordinals from a different envelope were accepted: %v", err)
	}
	legacy, err := SmtpMailboxOutcomes(&protocol.MailOutcomeRecord{Outcomes: second.Outcomes})
	if err != nil || len(legacy) != 1 || legacy[0].progress != nil || legacy[0].Outcome != SmtpOutcomeDeferred {
		t.Fatalf("historical outcome could not be read: %+v, %v", legacy, err)
	}
	outcome.Outcome = SmtpOutcomeSent
	sent, err := SmtpMailboxOutcomeRecord([]*SmtpDomainOutcome{outcome}, second)
	if err != nil {
		t.Fatal(err)
	}
	outcome.Outcome = SmtpOutcomeRefused
	late, err := SmtpMailboxOutcomeRecord([]*SmtpDomainOutcome{outcome}, sent)
	if err != nil || late.Outcomes[0].GetOutcome() != protocol.MailOutcomeKind_MAIL_OUTCOME_SENT {
		t.Fatalf("a late refusal undid a confirmed delivery: %+v, %v", late, err)
	}
}
