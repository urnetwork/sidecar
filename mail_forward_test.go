//go:build !sidecar_http && !js && !ios_extension

// MAIL-M9-04's forwarding on MAIL-M9-03's reply world, S6's §15.10 rows through MAIL's code: an address confirmed by
// its code, a wrong code refused and an unconfirmed address forwarded nothing; a <root> target refused; mail above the
// spam threshold, with a DMARC fail or carrying X-UR-Forwarded not forwarded; a forward From r-<token> with the rules
// and X-UR-Forwarded, two readers queueing one; and a relay from the confirmed address passing DMARC sent From the
// burner to the original sender, from any other address or failing DMARC sent nowhere.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

const testMailForwardAddress = "me@personal.example"

// The reply world with forwarding confirmed to testMailForwardAddress for its burner: the world, and the label.
func newTestMailForwardWorld(t *testing.T) (*mailClientTestWorld, string) {
	t.Helper()
	world, _, _, label := newTestMailBurnerReplyWorld(t)
	ctx := context.Background()
	pending, err := world.client.SetForward(ctx, &MailSetForwardArgs{Address: testMailForwardAddress, Burners: []string{label}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.client.ConfirmForward(ctx, testMailForwardCode(t, world, pending)); err != nil {
		t.Fatal(err)
	}
	return world, label
}

var testMailForwardCodePattern = regexp.MustCompile(`this address: ([0-9]{6})`)

// The code the pending address's send carries, read from its o/ entry.
func testMailForwardCode(t *testing.T, world *mailClientTestWorld, pending *MailForwardPending) string {
	t.Helper()
	file := testMailSendOutbox(t, world)[string(pending.Send.EffectKey)]
	if file == nil {
		t.Fatal("the code was not queued")
	}
	match := testMailForwardCodePattern.FindSubmatch(file.Message)
	if match == nil {
		t.Fatalf("no code in\n%s", file.Message)
	}
	return string(match[1])
}

// A message ingest wrote to address in the world's mailbox, From from, its spam score and DMARC verdict as sealed.
func testMailForwardIngested(t *testing.T, world *mailClientTestWorld, address string, from string, spamScore uint32, dmarc protocol.DmarcVerdict, extra string) *MailMessage {
	t.Helper()
	id := NewId()
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	message := "Received: from mx.shop.example by mx.acme.root.example\r\nFrom: " + from + "\r\nTo: " + address +
		"\r\nSubject: Your receipt\r\nDate: Tue, 10 Nov 2026 12:00:00 +0000\r\nMessage-ID: <r1@shop.example>\r\n" +
		"DKIM-Signature: v=1; d=shop.example; s=s1; b=abc\r\n" + extra + "\r\nThanks for your order.\r\n"
	if _, err := world.ingest.store.Write(context.Background(), []*mailStoreWrite{{Path: MailMessagePath(month, id), Content: []byte(message)}}); err != nil {
		t.Fatal(err)
	}
	mailboxId, err := world.client.mailboxId()
	if err != nil {
		t.Fatal(err)
	}
	return &MailMessage{
		RepoId: mailboxId,
		Id:     id,
		Month:  month,
		Entry: &protocol.IndexEntry{
			Id: id.Bytes(), Address: address, From: from, Subject: "Your receipt", SpamScore: spamScore,
			AuthResults: &protocol.MailAuthResults{Dmarc: dmarc},
		},
		Untrusted: true,
	}
}

// The code confirms the address: a wrong one is refused and counted, the right one writes the signed forward entry
// naming the address and the burner, and a confirmed code is spent. An address under the user root is refused, and
// a burner that is not this member's live one.
func TestMailForwardConfirmsItsAddressByCode(t *testing.T) {
	world, _, _, label := newTestMailBurnerReplyWorld(t)
	ctx := context.Background()
	for _, address := range []string{"ada@acme.root.example", "x@other.root.example", "x@root.example", "not an address"} {
		if _, err := world.client.SetForward(ctx, &MailSetForwardArgs{Address: address, Burners: []string{label}}); !errors.Is(err, ErrMailForwardAddressRefused) {
			t.Errorf("a forward to %q: %v", address, err)
		}
	}
	if _, err := world.client.SetForward(ctx, &MailSetForwardArgs{Address: testMailForwardAddress, Burners: []string{"zebra-0001"}}); !errors.Is(err, ErrMailForwardBurnerRefused) {
		t.Fatalf("a burner no record holds: %v", err)
	}
	pending, err := world.client.SetForward(ctx, &MailSetForwardArgs{Address: testMailForwardAddress, Burners: []string{label}})
	if err != nil {
		t.Fatal(err)
	}
	code := testMailForwardCode(t, world, pending)
	if forward, err := world.client.Forward(ctx); err != nil || forward != nil {
		t.Fatalf("a forward before its code %+v: %v", forward, err)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if _, err := world.client.ConfirmForward(ctx, wrong); !errors.Is(err, ErrMailForwardCodeWrong) {
		t.Fatalf("a wrong code: %v", err)
	}
	forward, err := world.client.ConfirmForward(ctx, code)
	if err != nil {
		t.Fatal(err)
	}
	if forward.GetAddress() != testMailForwardAddress || len(forward.GetBurners()) != 1 || forward.GetBurners()[0] != label || forward.GetVerifiedTimeMs() == 0 {
		t.Fatalf("the forward %+v", forward)
	}
	if stored, err := world.client.Forward(ctx); err != nil || stored.GetAddress() != testMailForwardAddress {
		t.Fatalf("the stored forward %+v: %v", stored, err)
	}
	if _, err := world.client.ConfirmForward(ctx, code); !errors.Is(err, ErrMailForwardNoCode) {
		t.Fatalf("a spent code: %v", err)
	}
}

// Past CodeAttemptMaxCount wrong tries the code is spent, the right one refused with it.
func TestMailForwardCodeIsSpentAfterItsTries(t *testing.T) {
	world, _, _, label := newTestMailBurnerReplyWorld(t)
	ctx := context.Background()
	pending, err := world.client.SetForward(ctx, &MailSetForwardArgs{Address: testMailForwardAddress, Burners: []string{label}})
	if err != nil {
		t.Fatal(err)
	}
	code := testMailForwardCode(t, world, pending)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for range world.client.forwardSettings().CodeAttemptMaxCount {
		if _, err := world.client.ConfirmForward(ctx, wrong); !errors.Is(err, ErrMailForwardCodeWrong) {
			t.Fatal(err)
		}
	}
	if _, err := world.client.ConfirmForward(ctx, code); !errors.Is(err, ErrMailForwardNoCode) {
		t.Fatalf("the right code after the tries: %v", err)
	}
}

// An unconfirmed address forwards nothing.
func TestMailForwardUnconfirmedForwardsNothing(t *testing.T) {
	world, _, _, label := newTestMailBurnerReplyWorld(t)
	ctx := context.Background()
	if _, err := world.client.SetForward(ctx, &MailSetForwardArgs{Address: testMailForwardAddress, Burners: []string{label}}); err != nil {
		t.Fatal(err)
	}
	entriesBefore := len(testMailSendOutbox(t, world))
	message := testMailForwardIngested(t, world, "shop@"+label+".acme.root.example", "store@shop.example", 10, protocol.DmarcVerdict_DMARC_PASS, "")
	if decision, err := world.client.considerForward(ctx, message); err != nil || decision != mailForwardNone {
		t.Fatalf("an unconfirmed forward %q: %v", decision, err)
	}
	if count := len(testMailSendOutbox(t, world)); count != entriesBefore {
		t.Fatal("an unconfirmed address was forwarded to")
	}
}

// A message to the opted-in burner, below the threshold with no DMARC fail, is forwarded: From r-<token> under the
// label, To the confirmed address, with X-UR-Forwarded, no Received or signature of the original's, under the key
// its id derives; a second reader queues no second entry. Above the threshold, with a DMARC fail or carrying
// X-UR-Forwarded, nothing is forwarded.
func TestMailForwardForwardsOptedInBurnerMail(t *testing.T) {
	world, label := newTestMailForwardWorld(t)
	ctx := context.Background()
	burner := "shop@" + label + ".acme.root.example"
	message := testMailForwardIngested(t, world, burner, "Store <store@shop.example>", 10, protocol.DmarcVerdict_DMARC_PASS, "")
	decision, err := world.client.considerForward(ctx, message)
	if err != nil || decision != mailForwardForwarded {
		t.Fatalf("the forward %q: %v", decision, err)
	}
	key := mailForwardEffectKey(mailForwardEffectKeyLabel, message.Id)
	file := testMailSendOutbox(t, world)[string(key)]
	if file == nil {
		t.Fatal("no entry under the message's key")
	}
	text := string(file.Message)
	if !strings.HasPrefix(text, MailForwardedHeader+": 1\r\n") || !strings.Contains(text, "To: "+testMailForwardAddress+"\r\n") ||
		!strings.Contains(text, "Subject: Your receipt\r\n") || !strings.Contains(text, "Thanks for your order.") {
		t.Fatalf("the forward\n%s", text)
	}
	if strings.Contains(text, "Received:") || strings.Contains(text, "DKIM-Signature") || strings.Contains(text, "store@shop.example") {
		t.Fatalf("the forward carries the original's trace\n%s", text)
	}
	fromLine := regexp.MustCompile(`From: (r-[a-z2-7]{26})@` + regexp.QuoteMeta(label) + `\.acme\.root\.example\r\n`).FindStringSubmatch(text)
	if fromLine == nil {
		t.Fatalf("no reverse alias From in\n%s", text)
	}
	mailboxId, _ := world.client.mailboxId()
	_, parts, _ := world.client.bound()
	record, err := newMailReverseAlias(parts.store(mailboxId), nil, nil).Find(ctx, strings.TrimPrefix(fromLine[1], "r-"))
	if err != nil || record.GetOriginalSender() != "store@shop.example" || record.GetBurnerAddress() != burner {
		t.Fatalf("the reverse alias %+v: %v", record, err)
	}

	// a second reader of the same message queues no second entry
	entries := len(testMailSendOutbox(t, world))
	if _, err := world.client.considerForward(ctx, message); err != nil {
		t.Fatal(err)
	}
	if count := len(testMailSendOutbox(t, world)); count != entries {
		t.Fatalf("%d entries after a second reader, %d before", count, entries)
	}

	for _, refused := range []*MailMessage{
		testMailForwardIngested(t, world, burner, "store@shop.example", world.client.settings.Store.SpamScoreThreshold, protocol.DmarcVerdict_DMARC_PASS, ""),
		testMailForwardIngested(t, world, burner, "store@shop.example", 10, protocol.DmarcVerdict_DMARC_FAIL, ""),
		testMailForwardIngested(t, world, burner, "store@shop.example", 10, protocol.DmarcVerdict_DMARC_PASS, MailForwardedHeader+": 1\r\n"),
	} {
		if decision, err := world.client.considerForward(ctx, refused); err != nil || decision != mailForwardRefused {
			t.Errorf("a message the rows refuse %q: %v", decision, err)
		}
	}
	if count := len(testMailSendOutbox(t, world)); count != entries {
		t.Fatal("a refused message was forwarded")
	}
}

// Mail to r-<token> from the confirmed address, passing DMARC, is relayed From the burner to the original sender;
// from another address, or failing DMARC, it is relayed nowhere.
func TestMailForwardRelaysTheConfirmedAddressesReply(t *testing.T) {
	world, label := newTestMailForwardWorld(t)
	ctx := context.Background()
	burner := "shop@" + label + ".acme.root.example"
	original := testMailForwardIngested(t, world, burner, "store@shop.example", 10, protocol.DmarcVerdict_DMARC_PASS, "")
	if _, err := world.client.considerForward(ctx, original); err != nil {
		t.Fatal(err)
	}
	mailboxId, _ := world.client.mailboxId()
	_, parts, _ := world.client.bound()
	vault, err := world.client.Vault()
	if err != nil {
		t.Fatal(err)
	}
	token, err := newMailReverseAlias(parts.store(mailboxId), vault.ReverseAliasKey, nil).Token(ctx, "store@shop.example")
	if err != nil {
		t.Fatal(err)
	}
	alias := "r-" + token + "@" + label + ".acme.root.example"

	reply := testMailForwardIngested(t, world, alias, testMailForwardAddress, 10, protocol.DmarcVerdict_DMARC_PASS, "")
	decision, err := world.client.considerForward(ctx, reply)
	if err != nil || decision != mailForwardRelayed {
		t.Fatalf("the relay %q: %v", decision, err)
	}
	file := testMailSendOutbox(t, world)[string(mailForwardEffectKey(mailRelayEffectKeyLabel, reply.Id))]
	if file == nil {
		t.Fatal("no relay queued")
	}
	if !bytes.Contains(file.Message, []byte("From: "+burner+"\r\n")) || !bytes.Contains(file.Message, []byte("To: store@shop.example\r\n")) ||
		bytes.Contains(file.Message, []byte(testMailForwardAddress)) || bytes.Contains(file.Message, []byte(MailForwardedHeader)) {
		t.Fatalf("the relay\n%s", file.Message)
	}

	entries := len(testMailSendOutbox(t, world))
	for _, refused := range []*MailMessage{
		testMailForwardIngested(t, world, alias, "someone@else.example", 10, protocol.DmarcVerdict_DMARC_PASS, ""),
		testMailForwardIngested(t, world, alias, testMailForwardAddress, 10, protocol.DmarcVerdict_DMARC_FAIL, ""),
		testMailForwardIngested(t, world, "r-"+strings.Repeat("a", 26)+"@"+label+".acme.root.example", testMailForwardAddress, 10, protocol.DmarcVerdict_DMARC_PASS, ""),
	} {
		if decision, err := world.client.considerForward(ctx, refused); err != nil || decision != mailForwardRefused {
			t.Errorf("a reply the relay row refuses %q: %v", decision, err)
		}
	}
	if count := len(testMailSendOutbox(t, world)); count != entries {
		t.Fatal("a refused reply was relayed")
	}
}

// A reverse alias reaches its burner's mailbox while the burner is live, as a receiver resolves it.
func TestMailForwardReverseAliasResolvesToItsBurner(t *testing.T) {
	world, label := newTestMailForwardWorld(t)
	ctx := context.Background()
	config, err := world.client.syncedConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ParseMailRecipient(testMailIngestRoot, "r-anything@"+label+".acme.root.example")
	if err != nil {
		t.Fatal(err)
	}
	mailboxId, _ := world.client.mailboxId()
	if lookup, err := config.Resolve(ctx, recipient); err != nil || !lookup.Known || lookup.MailboxRepoId != mailboxId {
		t.Fatalf("the reverse alias resolves %+v: %v", lookup, err)
	}
}

// The reverse aliases' key is the mailbox's, in vault/ (QD-1095): every consented device of the owner reads the one key,
// so one sender gets one reverse alias from any of them, and a device the owner has not consented reads none.
func TestMailForwardReverseAliasKeyIsTheMailboxes(t *testing.T) {
	world, _, _, _ := newTestMailBurnerReplyWorld(t)
	ctx := context.Background()
	vault, err := world.client.Vault()
	if err != nil {
		t.Fatal(err)
	}
	key, err := vault.ReverseAliasKey(ctx)
	if err != nil || len(key) != 32 {
		t.Fatalf("the key %d bytes: %v", len(key), err)
	}
	parts := world.client.partsOverride.(*testMailBurnerReplyParts).vaultParts
	other := testMailId(0x6a)
	parts.authority.set(other, world.member, true)
	otherVault := newMailVault(parts.vaultStore, world.member, other, parts.authority, parts.clock, nil, DefaultMailVaultSettings())
	otherKey, err := otherVault.ReverseAliasKey(ctx)
	if err != nil || !bytes.Equal(otherKey, key) {
		t.Fatalf("another device's key: %v", err)
	}
	mine, err := newMailReverseAlias(newMailTestStore(), vault.ReverseAliasKey, nil).Token(ctx, "store@shop.example")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := newMailReverseAlias(newMailTestStore(), otherVault.ReverseAliasKey, nil).Token(ctx, "Store@Shop.Example")
	if err != nil || theirs != mine {
		t.Fatalf("two devices' tokens for one sender differ: %v", err)
	}
	stranger := newMailVault(parts.vaultStore, world.member, testMailId(0x6b), parts.authority, parts.clock, nil, DefaultMailVaultSettings())
	if _, err := stranger.ReverseAliasKey(ctx); !errors.Is(err, ErrMailVaultNotConsented) {
		t.Fatalf("an unconsented device read the key: %v", err)
	}
}
