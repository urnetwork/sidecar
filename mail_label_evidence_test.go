//go:build !sidecar_http && !js

// MAIL-M7-10's labels through MAIL-M7-09's checks and evidence, as ingest would decide them from a receiver's sealed
// deposit: FS-39's second hop, whose REQUIRETLS labels as stated with no exact path claim, and S7's cut message,
// labeled from what was verified. Every name, key and address is synthetic.

package sidecar_test

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The deposit a receiver makes of message with evidence, and its label against list, as ingest would decide it.
func testMailLabelOfEvidence(t *testing.T, evidence *protocol.MailAuthEvidence, message []byte, requireTls bool, fromDomain string, list *sidecar.MailOperatorList) *sidecar.MailLabelResult {
	t.Helper()
	hash := sha256.Sum256(message)
	return sidecar.MailLabelDecide(&sidecar.MailLabelInput{
		Deposit: &protocol.MailDeposit{
			Version: 1, Evidence: evidence, RequireTls: requireTls, Recipients: []string{"id@acme.root.example"},
			ReceiverSidecarId: testMailEvidenceReceiver.Bytes(),
		},
		MessageSha256: hash[:],
		FromDomain:    fromDomain,
		Root:          "root.example",
		Operators:     list,
	})
}

// FS-39's second hop through the receiver's own checks: a first hop that read the message's canary kept its DKIM
// signature and sent it on with REQUIRETLS; the receiver's evidence passes DKIM, and the label is validated by
// REQUIRETLS as stated, naming only the final hop, with no exact path claim.
func TestMailLabelOfASecondHopRequireTls(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	signer, err := sidecartest.NewMailDkimSigner("origin.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("s1", "origin.example"), signer.KeyRecord())
	canary := "canary-7f3a9c the first hop read"
	message, err := signer.Sign([]byte(strings.Replace(string(testMailAuthMessage("origin.example", "second-hop")), "A synthetic body.", canary, 1)))
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message, "origin.example"))
	evidence := testMailEvidenceOf(t, outcome, message)
	if len(evidence.GetDkim()) != 1 || evidence.GetDkim()[0].GetResult() != protocol.DkimVerdict_DKIM_PASS {
		t.Fatalf("dkim %v", evidence.GetDkim())
	}
	result := testMailLabelOfEvidence(t, evidence, message, true, "origin.example", nil)
	statement := result.Statement()
	if result.Label != protocol.MailTlsLabel_MAIL_TLS_VALIDATED || result.Basis.GetRule() != protocol.MailTlsRule_MAIL_TLS_RULE_REQUIRETLS ||
		!strings.Contains(statement, "only the final hop's requirement") {
		t.Errorf("%v: %q", result.Label, statement)
	}
	for _, claim := range []string{"end-to-end", "end to end", "confidential", "unread"} {
		if strings.Contains(strings.ToLower(statement), claim) {
			t.Errorf("%q claims %q", statement, claim)
		}
	}
	// without REQUIRETLS, an unlisted sender's mail is opportunistic, its TLSA live or not
	if opportunistic := testMailLabelOfEvidence(t, evidence, message, false, "origin.example", nil); opportunistic.Label != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC {
		t.Errorf("without REQUIRETLS: %v", opportunistic.Label)
	}
}

// S7's cut message through the receiver's own checks: the DKIM key the 30 s cut is incomplete and counts for nothing,
// while the PTR and TLSA the receiver did confirm still match a listed operator, so the message is validated by what
// was verified and marked checks incomplete; with the PTR cut too it is opportunistic.
func TestMailLabelOfACutCheckRestsOnWhatWasVerified(t *testing.T) {
	list, err := sidecar.ParseMailOperatorList("version: 4\noperators:\n  - id: listed\n    name: Listed Mail\n" +
		"    ptr_suffixes: [sender.example]\n    dkim_domains: [sender.example]\n    dane: https://sender.example/dane\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, cutPtr := range []bool{false, true} {
		world := newMailAuthCheckWorld(t)
		world.settings.QueryTimeout = time.Minute
		world.publishSender("sender.example")
		signer, err := sidecartest.NewMailDkimSigner("sender.example", "slow", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(1024))
		if err != nil {
			t.Fatal(err)
		}
		world.zone.AddTxt(sidecartest.MailDkimKeyName("slow", "sender.example"), signer.KeyRecord())
		world.zone.SetDelay(sidecartest.MailDkimKeyName("slow", "sender.example"), 40*time.Second)
		delayed := 1
		if cutPtr {
			world.zone.SetDelay(sidecartest.MailZoneReverseName(netip.MustParseAddr(testMailAuthSender)), 40*time.Second)
			delayed = 2
		}
		message, err := signer.Sign(testMailAuthMessage("sender.example", "cut"))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan *sidecar.MailAuthOutcome, 1)
		go func() {
			outcome, err := world.checker.Check(context.Background(), testMailAuthInput(message, "sender.example"))
			if err != nil {
				t.Error(err)
			}
			done <- outcome
		}()
		awaitMailZoneDelays(t, world.clock, delayed, 40*time.Second)
		world.clock.Advance(30 * time.Second)
		outcome := <-done
		world.clock.Advance(20 * time.Second)
		evidence := testMailEvidenceOf(t, outcome, message)
		if evidence.GetLimits().GetReason()&sidecar.MailAuthLimitDeadline == 0 || evidence.GetDkim()[0].GetResult() != protocol.DkimVerdict_DKIM_INCOMPLETE {
			t.Fatalf("cut ptr %t: limits %v, dkim %v", cutPtr, evidence.GetLimits(), evidence.GetDkim())
		}
		result := testMailLabelOfEvidence(t, evidence, message, false, "sender.example", list)
		want := protocol.MailTlsLabel_MAIL_TLS_VALIDATED
		if cutPtr {
			want = protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC
		}
		if result.Label != want || !result.ChecksIncomplete || (!cutPtr && result.MatchedBy != sidecar.MailLabelMatchPtr) {
			t.Errorf("cut ptr %t: %v, incomplete %t, match %d", cutPtr, result.Label, result.ChecksIncomplete, result.MatchedBy)
		}
	}
}
