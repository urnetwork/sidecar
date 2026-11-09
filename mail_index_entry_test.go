// MAIL-M7-11's IndexEntry builder: each field from its source and within its MAIL-FORMAT.md cap, auth_results
// summarized from the sealed evidence, and every label the deposit cannot support refused. Every name is
// synthetic.

package sidecar

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A receiver's deposit with full evidence: SPF pass, one DKIM temperror then one pass, DMARC pass, ARC none, and a
// PTR, at a sealed time a few ms after the router's.
func testMailReceiverDeposit() *protocol.MailDeposit {
	receiverId := []byte{0x01, 0x9a, 0x5b, 0x10, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a}
	return &protocol.MailDeposit{
		Version: 1,
		Ingress: &protocol.MailIngress{
			Version:           1,
			SenderIp:          []byte{192, 0, 2, 25},
			SenderPort:        49152,
			Sni:               "mx.k3j4h5g6f7.root.example",
			EhloName:          "mail.sender.example",
			ReceiveTimeMillis: 1793923200000,
		},
		Evidence: &protocol.MailAuthEvidence{
			Version:           1,
			MessageSha256:     make([]byte, 32),
			ReceiveTimeMillis: 1793923200040,
			ReceiverSidecarId: receiverId,
			Spf:               &protocol.SpfResult{Result: protocol.SpfVerdict_SPF_PASS, Domain: "sender.example", Ip: []byte{192, 0, 2, 25}},
			Dkim: []*protocol.DkimResult{
				{Domain: "other.example", Selector: "s2", Result: protocol.DkimVerdict_DKIM_TEMPERROR},
				{Domain: "sender.example", Selector: "s1", Result: protocol.DkimVerdict_DKIM_PASS},
			},
			Dmarc:   &protocol.DmarcResult{P: "reject", Adkim: "s", Aspf: "r", Alignment: 2, Result: protocol.DmarcVerdict_DMARC_PASS},
			PtrName: "mail.sender.example",
			Arc:     &protocol.ArcResult{Cv: protocol.ArcVerdict_ARC_NONE},
		},
		MailFrom:          []byte("bounce@sender.example"),
		Recipients:        []string{"ada@k3j4h5g6f7.root.example", "abuse@k3j4h5g6f7.root.example"},
		TlsVersion:        0x0304,
		TlsSuite:          0x1301,
		ReceiverSidecarId: receiverId,
	}
}

// A same-network deposit (D-MAIL-8): version, MAIL FROM and recipients, nothing a receiver seals.
func testMailSameNetworkDeposit() *protocol.MailDeposit {
	return &protocol.MailDeposit{
		Version:    1,
		MailFrom:   []byte("grace@k3j4h5g6f7.root.example"),
		Recipients: []string{"ada@k3j4h5g6f7.root.example"},
	}
}

// A walk's result as the builder takes it, every field set.
func testMailParsedFull() *MailParsed {
	return &MailParsed{
		From:            "Ada Lovelace <ada@sender.example>",
		FromDomain:      "sender.example",
		Subject:         "Lunch",
		MessageId:       "m1@sender.example",
		ThreadMessageId: "root@sender.example",
		Text:            "Shall we meet at noon?",
		Snippet:         "Shall we meet at noon?",
		Attachments:     []*protocol.MailAttachment{{Name: "menu.pdf", Type: "application/pdf", Size: 1234}},
		AttachmentCount: 1,
		PartCount:       3,
	}
}

// A receiver's deposit: each field from its source, the sealed evidence's time, and auth_results summarized.
func TestMailBuildIndexEntryFromAReceiversDeposit(t *testing.T) {
	parsed := testMailParsedFull()
	basis := &protocol.MailTlsBasis{Rule: protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR, OperatorId: "synthetic-operator", ListVersion: 3}
	entry, err := MailBuildIndexEntry(&MailIndexEntryInput{
		Id:             Id{0x01, 0x9a},
		Deposit:        testMailReceiverDeposit(),
		PushTimeMillis: 1793923300000,
		ByteCount:      4321,
		Parsed:         parsed,
		TlsLabel:       protocol.MailTlsLabel_MAIL_TLS_VALIDATED,
		TlsBasis:       basis,
		SpamScore:      12,
		OneTimeCode:    "482915",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &protocol.IndexEntry{
		Id:          Id{0x01, 0x9a}.Bytes(),
		Address:     "ada@k3j4h5g6f7.root.example",
		Time:        1793923200040,
		From:        "Ada Lovelace <ada@sender.example>",
		Subject:     "Lunch",
		Snippet:     "Shall we meet at noon?",
		MessageId:   "m1@sender.example",
		ThreadKey:   parsed.ThreadKey(Id{0x01, 0x9a}),
		Size:        4321,
		Attachments: []*protocol.MailAttachment{{Name: "menu.pdf", Type: "application/pdf", Size: 1234}},
		AuthResults: &protocol.MailAuthResults{
			Spf:   protocol.SpfVerdict_SPF_PASS,
			Dkim:  protocol.DkimVerdict_DKIM_PASS,
			Dmarc: protocol.DmarcVerdict_DMARC_PASS,
			Arc:   protocol.ArcVerdict_ARC_NONE,
		},
		TlsLabel:    protocol.MailTlsLabel_MAIL_TLS_VALIDATED,
		TlsBasis:    basis,
		SpamScore:   12,
		OneTimeCode: "482915",
	}
	if !proto.Equal(entry, want) {
		t.Errorf("got %v\nwant %v", entry, want)
	}
	// the entry holds its own basis, not the caller's
	basis.OperatorId = "changed"
	if entry.GetTlsBasis().GetOperatorId() != "synthetic-operator" {
		t.Error("the entry shares the caller's basis")
	}
}

// auth_results' dkim is pass if any selected signature passed, else the first selected one's verdict, else none;
// limits marks the checks incomplete; and a receiver's deposit with no evidence is evidence unavailable.
func TestMailAuthResultsSummary(t *testing.T) {
	cases := []struct {
		evidence *protocol.MailAuthEvidence
		want     *protocol.MailAuthResults
	}{
		{evidence: nil, want: &protocol.MailAuthResults{EvidenceUnavailable: true}},
		{evidence: &protocol.MailAuthEvidence{}, want: &protocol.MailAuthResults{}},
		{evidence: &protocol.MailAuthEvidence{Dkim: []*protocol.DkimResult{
			{Result: protocol.DkimVerdict_DKIM_FAIL}, {Result: protocol.DkimVerdict_DKIM_TEMPERROR},
		}}, want: &protocol.MailAuthResults{Dkim: protocol.DkimVerdict_DKIM_FAIL}},
		{evidence: &protocol.MailAuthEvidence{
			Dkim:   []*protocol.DkimResult{{Result: protocol.DkimVerdict_DKIM_INCOMPLETE}, {Result: protocol.DkimVerdict_DKIM_PASS}},
			Limits: &protocol.AuthLimits{Reason: 2, DkimSeen: 64, DkimChecked: 8},
		}, want: &protocol.MailAuthResults{Dkim: protocol.DkimVerdict_DKIM_PASS, ChecksIncomplete: true}},
		{evidence: &protocol.MailAuthEvidence{
			Spf:   &protocol.SpfResult{Result: protocol.SpfVerdict_SPF_INCOMPLETE},
			Dmarc: &protocol.DmarcResult{Result: protocol.DmarcVerdict_DMARC_TEMPERROR},
			Arc:   &protocol.ArcResult{Cv: protocol.ArcVerdict_ARC_INCOMPLETE},
		}, want: &protocol.MailAuthResults{Spf: protocol.SpfVerdict_SPF_INCOMPLETE, Dmarc: protocol.DmarcVerdict_DMARC_TEMPERROR, Arc: protocol.ArcVerdict_ARC_INCOMPLETE}},
	}
	for index, c := range cases {
		deposit := testMailReceiverDeposit()
		deposit.Evidence = c.evidence
		entry, err := MailBuildIndexEntry(&MailIndexEntryInput{Id: Id{1}, Deposit: deposit, Parsed: &MailParsed{}})
		if err != nil {
			t.Fatalf("case %d: %v", index, err)
		}
		if !proto.Equal(entry.GetAuthResults(), c.want) {
			t.Errorf("case %d: %v, want %v", index, entry.GetAuthResults(), c.want)
		}
	}
}

// A same-network deposit has no auth_results and no basis, takes member-signed or no label, and dates by its push.
func TestMailBuildIndexEntryFromASameNetworkDeposit(t *testing.T) {
	for _, label := range []protocol.MailTlsLabel{protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED, protocol.MailTlsLabel_MAIL_TLS_LABEL_UNSPECIFIED} {
		entry, err := MailBuildIndexEntry(&MailIndexEntryInput{
			Id: Id{2}, Deposit: testMailSameNetworkDeposit(), PushTimeMillis: 1793923300000, Parsed: &MailParsed{Subject: "lunch"}, TlsLabel: label,
		})
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if entry.GetAuthResults() != nil || entry.GetTlsBasis() != nil || entry.GetTime() != 1793923300000 || entry.GetTlsLabel() != label {
			t.Errorf("%s: %v", label, entry)
		}
		// no ids, so the thread is the message's own
		if string(entry.GetThreadKey()) != string(Id{2}.Bytes()) {
			t.Errorf("%s: thread %x", label, entry.GetThreadKey())
		}
	}
}

// Every label a deposit cannot support is refused, so no caller writes a row that claims more than reception sealed.
func TestMailBuildIndexEntryRefusesLabelsTheDepositCannotSupport(t *testing.T) {
	noEvidence := testMailReceiverDeposit()
	noEvidence.Evidence = nil
	strictChain := testMailReceiverDeposit()
	strictChain.Evidence.StrictChain = true
	cases := []struct {
		name    string
		deposit *protocol.MailDeposit
		label   protocol.MailTlsLabel
		basis   *protocol.MailTlsBasis
		refused bool
	}{
		{name: "validated without evidence", deposit: noEvidence, label: protocol.MailTlsLabel_MAIL_TLS_VALIDATED, refused: true},
		{name: "validated on a same-network deposit", deposit: testMailSameNetworkDeposit(), label: protocol.MailTlsLabel_MAIL_TLS_VALIDATED, refused: true},
		{name: "member-signed from a receiver", deposit: testMailReceiverDeposit(), label: protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED, refused: true},
		{name: "a basis on a same-network deposit", deposit: testMailSameNetworkDeposit(), label: protocol.MailTlsLabel_MAIL_TLS_MEMBER_SIGNED, basis: &protocol.MailTlsBasis{}, refused: true},
		{name: "strict_custom_mx without strict_chain", deposit: testMailReceiverDeposit(), label: protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC, basis: &protocol.MailTlsBasis{StrictCustomMx: true}, refused: true},
		{name: "an operator id past 64 bytes", deposit: testMailReceiverDeposit(), label: protocol.MailTlsLabel_MAIL_TLS_VALIDATED, basis: &protocol.MailTlsBasis{Rule: protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR, OperatorId: strings.Repeat("o", 65)}, refused: true},
		{name: "a label the format lacks", deposit: testMailReceiverDeposit(), label: protocol.MailTlsLabel(9), refused: true},
		{name: "opportunistic without evidence", deposit: noEvidence, label: protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC},
		{name: "strict_custom_mx with strict_chain", deposit: strictChain, label: protocol.MailTlsLabel_MAIL_TLS_VALIDATED, basis: &protocol.MailTlsBasis{Rule: protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR, StrictCustomMx: true}},
	}
	for _, c := range cases {
		entry, err := MailBuildIndexEntry(&MailIndexEntryInput{Id: Id{3}, Deposit: c.deposit, Parsed: &MailParsed{}, TlsLabel: c.label, TlsBasis: c.basis})
		if c.refused != errors.Is(err, ErrMailIndexEntryInvalid) || (c.refused && entry != nil) {
			t.Errorf("%s: %v, %v", c.name, entry, err)
		}
	}
	// and a deposit with no recipient, an address past its bound, or no walk
	for _, input := range []*MailIndexEntryInput{
		nil,
		{Deposit: testMailReceiverDeposit()},
		{Parsed: &MailParsed{}},
		{Deposit: &protocol.MailDeposit{Version: 1}, Parsed: &MailParsed{}},
		{Deposit: &protocol.MailDeposit{Version: 1, Recipients: []string{strings.Repeat("a", MailAddressMaxByteCount+1)}}, Parsed: &MailParsed{}},
		{Deposit: &protocol.MailDeposit{Version: 1, Recipients: []string{"\xff@k3j4h5g6f7.root.example"}}, Parsed: &MailParsed{}},
	} {
		if _, err := MailBuildIndexEntry(input); !errors.Is(err, ErrMailIndexEntryInvalid) {
			t.Errorf("%+v: %v", input, err)
		}
	}
}

// Each field at once at its cap, and past it: text cut on a UTF-8 boundary, an id or a code left empty, attachments
// past 32 left out, a spam score held to 1,000. An entry at every cap stays under 16 KiB (MAIL-FORMAT.md).
func TestMailBuildIndexEntryCaps(t *testing.T) {
	attachments := []*protocol.MailAttachment{}
	for range 40 {
		attachments = append(attachments, &protocol.MailAttachment{Name: strings.Repeat("é", 200), Type: strings.Repeat("t", 200), Size: 1})
	}
	parsed := &MailParsed{
		From:        strings.Repeat("é", 300),
		Subject:     strings.Repeat("s", 600),
		Snippet:     strings.Repeat("東", 100),
		MessageId:   strings.Repeat("i", 257),
		Attachments: attachments,
	}
	deposit := testMailReceiverDeposit()
	deposit.Recipients = []string{strings.Repeat("a", 64) + "@" + strings.Repeat(strings.Repeat("b", 62)+".", 3) + "k3j4h5g6f7.root.example"}
	entry, err := MailBuildIndexEntry(&MailIndexEntryInput{
		Id: Id{4}, Deposit: deposit, Parsed: parsed, SpamScore: 4000, OneTimeCode: strings.Repeat("9", 33),
		TlsLabel: protocol.MailTlsLabel_MAIL_TLS_VALIDATED,
		TlsBasis: &protocol.MailTlsBasis{Rule: protocol.MailTlsRule_MAIL_TLS_RULE_OPERATOR, OperatorId: strings.Repeat("o", 64), ListVersion: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.GetFrom()) != 512 || len(entry.GetSubject()) != 512 || len(entry.GetSnippet()) > 200 || entry.GetSnippet() != strings.Repeat("東", 66) {
		t.Errorf("from %d, subject %d, snippet %d B", len(entry.GetFrom()), len(entry.GetSubject()), len(entry.GetSnippet()))
	}
	if entry.GetMessageId() != "" || entry.GetOneTimeCode() != "" || entry.GetSpamScore() != 1000 || len(entry.GetAttachments()) != 32 {
		t.Errorf("id %q, code %q, score %d, attachments %d", entry.GetMessageId(), entry.GetOneTimeCode(), entry.GetSpamScore(), len(entry.GetAttachments()))
	}
	for _, attachment := range entry.GetAttachments() {
		if len(attachment.GetName()) > 256 || len(attachment.GetType()) != 128 {
			t.Fatalf("attachment %d, %d B", len(attachment.GetName()), len(attachment.GetType()))
		}
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if 16*1024 <= len(encoded) {
		t.Errorf("an entry at its caps takes %d B", len(encoded))
	}
	// an id and a code at their caps are kept
	parsed.MessageId = strings.Repeat("i", 256)
	entry, err = MailBuildIndexEntry(&MailIndexEntryInput{Id: Id{4}, Deposit: deposit, Parsed: parsed, OneTimeCode: strings.Repeat("9", 32)})
	if err != nil || len(entry.GetMessageId()) != 256 || len(entry.GetOneTimeCode()) != 32 {
		t.Errorf("%v, %v", entry, err)
	}
}
