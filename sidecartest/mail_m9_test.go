//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// M9-out's mail rows of §22 on T2 (MAIL-M9-06; R-MAIL-6, D-MAIL-8, FS-123): composed from what MAIL-M9-01 to MAIL-M9-05
// landed, with SMTP's outbound path behind them, adding no mechanism. A failure goes back to the task that owns it.
//
//	S10      the replying half (mailworld's S10Replying, which server's sidecart3 runs on T3): a replying burner's
//	         first selector keeps its <blabel> MX and A, a burn changes no DNS and refuses the label at once, and its
//	         last selector restores the wildcard-only state
//	S6       §15.10's forwarding rules through MAIL's code with SMTP's scripted MX: the code goes out through §14 and is
//	         read where the confirmed address's MX took it; a burner's mail, received by the network's receiver and
//	         ingested by the member's own device, goes on From r-<token> with the header rules and X-UR-Forwarded,
//	         DKIM-signed under the burner's selector, and the confirmed address's reply to r-<token>, passing DMARC as
//	         received, goes back From the burner to the original sender; a loop, a DMARC fail, mail to a burner not opted
//	         in, a reply from any other address or one failing DMARC go nowhere; no target is in URnetwork's zones; and
//	         each code, forward and relay is one connection
//	FS-123   the mail side: what a send through MailClient meets per domain, refused, tls_refused, too_large and
//	         deferred, stands in the member's or/ as the composing device reads it, the DSNs reach the mailbox as mail,
//	         and no copy MAIL hands a person of a send names an inbound indexer, receiver or coverage setting, nor does
//	         GetReceiverCoverage's copy speak of sending
//
// The world is mailworld's M9World (m9_world.go): M8's network, whose owner's laptop sends through MailClient and, as
// the member's prover host, through SmtpSender to ScriptedMxs behind SMTP's stub edge; for S6 and FS-123 the laptop's
// client runs its component, whose ingest is the reader that forwards and files DSNs. Every name and address is
// synthetic: .example names and RFC 5737 addresses (connect/CODESTYLE.md's test data rule). Nothing sleeps: an ingest
// pass is waited for at its CONSUME barrier.
//
// Not composed here, and named in MAIL-M9-06's report: GetSendResult reads a send's outcomes by its send_id, which no
// MailClient call does yet (QD-853's "MailClient's check and results"), and a send through the outbox raises no mail_send
// on either device, since the runner's message carries no send_id and the composing device raises none from or/; the
// rows read or/ as the composing device's MailClient serves it instead. Mail above the spam threshold is MAIL-M9-04's
// unit rows', since no row here trains the filter.

package sidecartest_test

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// S10's replying half under the harness and guard (RunScenario's T2 defaults).
func TestScenarioS10ReplyingBurner(t *testing.T) {
	sidecartest.RunScenario(t, mailworld.S10Replying(t, nil), nil)
}

// The confirmed address and the original sender.
const (
	mailM9ForwardAddress = "me@personal.example"
	mailM9ShopSender     = "signup@" + mailworld.M8SenderDomain
)

// The outside domains' MX addresses, RFC 5737's.
var (
	mailM9PersonalMxAddress = netip.MustParseAddr("198.51.100.81")
	mailM9ShopMxAddress     = netip.MustParseAddr("198.51.100.82")
	mailM9RefuseMxAddress   = netip.MustParseAddr("198.51.100.83")
	mailM9PlainMxAddress    = netip.MustParseAddr("198.51.100.84")
	mailM9DataMxAddress     = netip.MustParseAddr("198.51.100.85")
)

// A forwarding code as SetForward's message words it.
var mailM9CodePattern = regexp.MustCompile(`this address: ([0-9]{6})`)

// A reverse alias's local part (§15.10's forwarding step 3).
var mailM9ReverseAliasPattern = regexp.MustCompile(`^r-[a-z2-7]{26}$`)

// No copy points to an inbound indexer, receiver or coverage setting (§14.5's copy, §18.5), SMTP's own scan's words
// (smtp_send_rows.go): "the receiving mail server" of a TL4 refusal (§14.4) is the destination's MX, no inbound setting.
var mailM9InboundWords = regexp.MustCompile(`(?i)\b(indexers?|receivers?|coverage)\b`)

// Coverage copy speaks of receiving alone (§18.5's every value row).
var mailM9SendingWords = regexp.MustCompile(`(?i)\b(send|sends|sent|sending|outbound|deliver|delivery|smtp)\b`)

// A message from from to to, with messageId's left side, extra header lines and body.
func mailM9Message(from string, to string, subject string, messageId string, extra string, body string) []byte {
	return []byte("From: " + from + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\nDate: Thu, 19 Nov 2026 12:00:00 +0000\r\n" +
		"Message-ID: <" + messageId + "@sender.example>\r\n" + extra + "\r\n" + body + "\r\n")
}

// One message through the network's router to recipient, its envelope from from: the reply to its end of DATA.
func mailM9Receive(world *mailworld.M9World, from string, recipient string, message []byte) *sidecartest.MailReply {
	return world.M8.Mail.Send(mailworld.M8Sender, world.M8.Mail.Settings().MxHost(), from, []string{recipient}, message)
}

// The keys in after and not in before.
func mailM9NewKeys(before [][]byte, after [][]byte) [][]byte {
	added := [][]byte{}
	for _, key := range after {
		if !slices.ContainsFunc(before, func(other []byte) bool { return bytes.Equal(other, key) }) {
			added = append(added, key)
		}
	}
	return added
}

// The header block of message as one string, each field on one line.
func mailM9Header(message []byte) string {
	header, _, _ := strings.Cut(string(message), "\r\n\r\n")
	return strings.NewReplacer("\r\n ", " ", "\r\n\t", " ").Replace(header) + "\r\n"
}

// The values of header's fields named name, in order, each unfolded.
func mailM9Fields(header string, name string) []string {
	values := []string{}
	for _, field := range strings.Split(header, "\r\n") {
		fieldName, value, found := strings.Cut(field, ":")
		if found && strings.EqualFold(strings.TrimSpace(fieldName), name) {
			values = append(values, strings.TrimSpace(value))
		}
	}
	return values
}

// The one address header's field name holds, lowercase, "" when it holds no one address.
func mailM9Address(header string, name string) string {
	values := mailM9Fields(header, name)
	if len(values) != 1 {
		return ""
	}
	address, err := mail.ParseAddress(values[0])
	if err != nil {
		return ""
	}
	return strings.ToLower(address.Address)
}

// A DKIM-Signature's tag in header, "" for none.
func mailM9DkimTag(header string, tag string) string {
	for _, field := range strings.Split(header, "\r\n") {
		name, value, _ := strings.Cut(field, ":")
		if !strings.EqualFold(strings.TrimSpace(name), "DKIM-Signature") {
			continue
		}
		for _, part := range strings.Split(value, ";") {
			key, tagValue, _ := strings.Cut(strings.TrimSpace(part), "=")
			if key == tag {
				return strings.TrimSpace(tagValue)
			}
		}
	}
	return ""
}

// The world for S6's rows: forwarding to mailM9ForwardAddress's MX for a burner whose mail comes from the shop, whose MX
// takes relays; the laptop's client runs its component. The world, the burner, and both MXs.
func newMailM9ForwardWorld(t *testing.T) (*mailworld.M9World, *sidecar.MailBurnerCreated, *sidecartest.ScriptedMx, *sidecartest.ScriptedMx) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	settings := mailworld.DefaultM9WorldSettings()
	settings.Component = true
	world := mailworld.NewM9World(t, net, settings)
	personal := world.AddDomain("personal.example", mailM9PersonalMxAddress, nil, true)
	shop := world.AddDomain(mailworld.M8SenderDomain, mailM9ShopMxAddress, nil, true)
	burner, err := world.Owner.CreateBurner(world.Context(), &sidecar.MailBurnerCreateArgs{Site: "https://" + mailworld.M8SenderDomain + "/signup"})
	if err != nil {
		t.Fatal(err)
	}
	world.M8.SyncReceiver()
	return world, burner, personal, shop
}

// S6's code row: the forwarding address is confirmed by a code sent through §14, which reaches that address's MX From
// forward@<blabel> under the burner's selector and nothing else, a wrong code refused; no address in URnetwork's zones
// takes forwards; and nothing is forwarded until the code is confirmed.
func TestS6ForwardingAddressIsConfirmedByACodeThroughSmtp(t *testing.T) {
	world, burner, personal, _ := newMailM9ForwardWorld(t)
	ctx := world.Context()
	burnerDomain := world.BurnerDomain(burner.Label)
	for _, address := range []string{"me@" + world.M8.Zone(), "me@" + burnerDomain, "me@other." + world.M8.Root, "me@" + world.M8.Root} {
		if _, err := world.Owner.SetForward(ctx, &sidecar.MailSetForwardArgs{Address: address, Burners: []string{burner.Label}}); !errors.Is(err, sidecar.ErrMailForwardAddressRefused) {
			t.Errorf("a forward to %s: %v", address, err)
		}
	}
	if keys := world.Outbox(); len(keys) != 0 {
		t.Fatalf("a refused address queued %d entries", len(keys))
	}

	pending, err := world.Owner.SetForward(ctx, &sidecar.MailSetForwardArgs{Address: mailM9ForwardAddress, Burners: []string{burner.Label}})
	if err != nil {
		t.Fatal(err)
	}
	if pending.Send == nil || len(pending.Send.EffectKey) == 0 {
		t.Fatalf("the code's send %+v", pending.Send)
	}
	// before its code is confirmed, the burner's mail goes nowhere
	world.Ingest(func() {
		message := mailM9Message("Shop <"+mailM9ShopSender+">", burner.Address, "An early receipt", "receipt-0", "", "Thanks for your order.")
		if reply := mailM9Receive(world, mailM9ShopSender, burner.Address, message); !reply.Is(250) {
			t.Fatalf("the burner's mail: %s", reply)
		}
	})
	if keys := world.Outbox(); len(keys) != 1 || !bytes.Equal(keys[0], pending.Send.EffectKey) {
		t.Fatalf("o/ holds %d entries before the code is confirmed", len(keys))
	}
	if pass := world.RunOutbox(); pass.Sent != 1 {
		t.Fatalf("the code's pass %+v", pass)
	}
	transactions := personal.Transactions()
	if len(transactions) != 1 || len(transactions[0].Recipients) != 1 || !strings.Contains(transactions[0].Recipients[0], mailM9ForwardAddress) {
		t.Fatalf("the address's MX took %d transactions", len(transactions))
	}
	header := mailM9Header(transactions[0].Message)
	if from := mailM9Address(header, "From"); from != "forward@"+burnerDomain {
		t.Fatalf("the code's message is From %q, not forward@<blabel>", from)
	}
	if mailM9DkimTag(header, "d") != burnerDomain || len(world.Publisher.Published(burnerDomain)) != 1 {
		t.Fatalf("the code's message is signed d=%s, with %d selectors published for the burner", mailM9DkimTag(header, "d"), len(world.Publisher.Published(burnerDomain)))
	}
	match := mailM9CodePattern.FindSubmatch(transactions[0].Message)
	if match == nil {
		t.Fatalf("no code in\n%s", transactions[0].Message)
	}
	code := string(match[1])
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if _, err := world.Owner.ConfirmForward(ctx, wrong); !errors.Is(err, sidecar.ErrMailForwardCodeWrong) {
		t.Fatalf("a wrong code: %v", err)
	}
	forward, err := world.Owner.ConfirmForward(ctx, code)
	if err != nil {
		t.Fatal(err)
	}
	if forward.GetAddress() != mailM9ForwardAddress || !slices.Equal(forward.GetBurners(), []string{burner.Label}) {
		t.Fatalf("the forward entry %+v", forward)
	}
	if outcome := world.Outcomes(pending.Send.EffectKey)["personal.example"]; outcome == nil || outcome.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("the code's outcome %+v", outcome)
	}
}

// Confirms mailM9ForwardAddress for burner's label through the code its MX takes.
func mailM9ConfirmForward(t *testing.T, world *mailworld.M9World, burner *sidecar.MailBurnerCreated, personal *sidecartest.ScriptedMx) {
	t.Helper()
	ctx := world.Context()
	if _, err := world.Owner.SetForward(ctx, &sidecar.MailSetForwardArgs{Address: mailM9ForwardAddress, Burners: []string{burner.Label}}); err != nil {
		t.Fatal(err)
	}
	if pass := world.RunOutbox(); pass.Sent != 1 {
		t.Fatalf("the code's pass %+v", pass)
	}
	transactions := personal.Transactions()
	match := mailM9CodePattern.FindSubmatch(transactions[len(transactions)-1].Message)
	if match == nil {
		t.Fatal("no code reached the address's MX")
	}
	if _, err := world.Owner.ConfirmForward(ctx, string(match[1])); err != nil {
		t.Fatal(err)
	}
}

// S6's forward and relay rows: the burner's mail, received by the network's receiver and ingested by the member's device,
// is forwarded From r-<token> under the burner's domain with X-UR-Forwarded and no trace of its carriage, signed under
// the burner's selector; a loop, a DMARC fail and mail to a burner not opted in are not; the confirmed address's reply to
// r-<token>, passing DMARC, is relayed From the burner to the original sender, and one from any other address, or
// failing DMARC, is not; and the code, the forward and the relay are a connection each.
func TestS6ForwardAndRelayThroughMailsCode(t *testing.T) {
	world, burner, personal, shop := newMailM9ForwardWorld(t)
	burnerDomain := world.BurnerDomain(burner.Label)
	mailM9ConfirmForward(t, world, burner, personal)
	zone := world.M8.Mail.Zone

	// the forward: below the threshold with no DMARC fail as received
	before := world.Outbox()
	world.Ingest(func() {
		message := mailM9Message("Shop <"+mailM9ShopSender+">", burner.Address, "Your receipt", "receipt-1", "", "Thanks for your order.")
		if reply := mailM9Receive(world, mailM9ShopSender, burner.Address, message); !reply.Is(250) {
			t.Fatalf("the burner's mail: %s", reply)
		}
	})
	if added := mailM9NewKeys(before, world.Outbox()); len(added) != 1 {
		t.Fatalf("the burner's mail queued %d entries, not one forward", len(added))
	}
	if pass := world.RunOutbox(); pass.Sent != 1 {
		t.Fatalf("the forward's pass %+v", pass)
	}
	transactions := personal.Transactions()
	if len(transactions) != 2 {
		t.Fatalf("the address's MX took %d transactions", len(transactions))
	}
	forwarded := transactions[1]
	header := mailM9Header(forwarded.Message)
	reverseAlias := mailM9Address(header, "From")
	aliasLocalPart, aliasDomain, _ := strings.Cut(reverseAlias, "@")
	if !mailM9ReverseAliasPattern.MatchString(aliasLocalPart) || aliasDomain != burnerDomain {
		t.Fatalf("the forward is From %q, not r-<token>@<blabel>", reverseAlias)
	}
	if !slices.Equal(mailM9Fields(header, sidecar.MailForwardedHeader), []string{"1"}) || mailM9Address(header, "To") != mailM9ForwardAddress ||
		!slices.Equal(mailM9Fields(header, "Subject"), []string{"Your receipt"}) || !bytes.Contains(forwarded.Message, []byte("Thanks for your order.")) {
		t.Fatalf("the forward:\n%s", forwarded.Message)
	}
	if len(mailM9Fields(header, "Received")) != 0 || strings.Contains(header, mailM9ShopSender) || strings.Contains(header, "receipt-1@") {
		t.Fatalf("the forward carries the original's carriage:\n%s", header)
	}
	if mailM9DkimTag(header, "d") != burnerDomain {
		t.Fatalf("the forward is signed d=%s", mailM9DkimTag(header, "d"))
	}

	// no forward: a message carrying X-UR-Forwarded, one failing DMARC as received, and mail to a burner not opted in
	zone.AddTxt("_dmarc.fail.example", "v=DMARC1; p=reject")
	otherBurner, err := world.Owner.CreateBurner(world.Context(), &sidecar.MailBurnerCreateArgs{Site: "https://other.example/signup"})
	if err != nil {
		t.Fatal(err)
	}
	world.M8.SyncReceiver()
	for i, refused := range []struct {
		from      string
		recipient string
		message   []byte
	}{
		{from: "news@" + mailworld.M8SenderDomain, recipient: burner.Address, message: mailM9Message("news@"+mailworld.M8SenderDomain, burner.Address, "A forwarded loop", "loop-1", sidecar.MailForwardedHeader+": 1\r\n", "Round and round.")},
		{from: "someone@fail.example", recipient: burner.Address, message: mailM9Message("someone@fail.example", burner.Address, "A DMARC fail", "fail-1", "", "Not who it says.")},
		{from: mailM9ShopSender, recipient: otherBurner.Address, message: mailM9Message(mailM9ShopSender, otherBurner.Address, "Another receipt", "receipt-2", "", "Thanks again.")},
	} {
		before := world.Outbox()
		world.Ingest(func() {
			if reply := mailM9Receive(world, refused.from, refused.recipient, refused.message); !reply.Is(250) {
				t.Fatalf("refused row %d's mail: %s", i, reply)
			}
		})
		if added := mailM9NewKeys(before, world.Outbox()); len(added) != 0 {
			t.Fatalf("refused row %d queued %d entries", i, len(added))
		}
	}

	// the relay: the confirmed address's reply to r-<token>, passing DMARC as received under its own DKIM key
	signer, err := sidecartest.NewMailDkimSigner("personal.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	zone.AddTxt(sidecartest.MailDkimKeyName("s1", "personal.example"), signer.KeyRecord())
	zone.AddTxt("_dmarc.personal.example", "v=DMARC1; p=reject")
	signed, err := signer.Sign(mailM9Message(mailM9ForwardAddress, reverseAlias, "Re: Your receipt", "reply-1", "", "Where is my order?"))
	if err != nil {
		t.Fatal(err)
	}
	before = world.Outbox()
	world.Ingest(func() {
		if reply := mailM9Receive(world, mailM9ForwardAddress, reverseAlias, signed); !reply.Is(250) {
			t.Fatalf("the reply to the reverse alias: %s", reply)
		}
	})
	if added := mailM9NewKeys(before, world.Outbox()); len(added) != 1 {
		t.Fatalf("the reply queued %d entries, not one relay", len(added))
	}
	if pass := world.RunOutbox(); pass.Sent != 1 {
		t.Fatalf("the relay's pass %+v", pass)
	}
	relayed := shop.Transactions()
	if len(relayed) != 1 || len(relayed[0].Recipients) != 1 || !strings.Contains(relayed[0].Recipients[0], mailM9ShopSender) {
		t.Fatalf("the shop's MX took %d transactions", len(relayed))
	}
	header = mailM9Header(relayed[0].Message)
	if mailM9Address(header, "From") != burner.Address || mailM9Address(header, "To") != mailM9ShopSender ||
		!bytes.Contains(relayed[0].Message, []byte("Where is my order?")) || mailM9DkimTag(header, "d") != burnerDomain {
		t.Fatalf("the relay:\n%s", relayed[0].Message)
	}
	if strings.Contains(header, mailM9ForwardAddress) || len(mailM9Fields(header, sidecar.MailForwardedHeader)) != 0 || len(mailM9Fields(header, "Received")) != 0 {
		t.Fatalf("the relay names the confirmed address or its carriage:\n%s", header)
	}

	// no relay: a reply from another address, though it passes DMARC, and the confirmed address's failing DMARC
	other, err := sidecartest.NewMailDkimSigner("else.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	zone.AddTxt(sidecartest.MailDkimKeyName("s1", "else.example"), other.KeyRecord())
	zone.AddTxt("_dmarc.else.example", "v=DMARC1; p=reject")
	otherSigned, err := other.Sign(mailM9Message("someone@else.example", reverseAlias, "Re: Your receipt", "reply-2", "", "Me too."))
	if err != nil {
		t.Fatal(err)
	}
	for i, refused := range []struct {
		from    string
		message []byte
	}{
		{from: "someone@else.example", message: otherSigned},
		{from: mailM9ForwardAddress, message: mailM9Message(mailM9ForwardAddress, reverseAlias, "Re: Your receipt", "reply-3", "", "Unsigned.")},
	} {
		before := world.Outbox()
		world.Ingest(func() {
			if reply := mailM9Receive(world, refused.from, reverseAlias, refused.message); !reply.Is(250) {
				t.Fatalf("refused relay %d's mail: %s", i, reply)
			}
		})
		if added := mailM9NewKeys(before, world.Outbox()); len(added) != 0 {
			t.Fatalf("refused relay %d queued %d entries", i, len(added))
		}
	}

	// a connection each: the code, the forward and the relay, and nothing for what was refused
	world.RunOutbox()
	if preambles := len(world.Send.Edge.Preambles()); preambles != 3 || personal.Connections() != 2 || shop.Connections() != 1 {
		t.Fatalf("%d connections at the edge, %d to the address's MX, %d to the shop's", preambles, personal.Connections(), shop.Connections())
	}
}

// FS-123's mail side: a send through MailClient to a refusing, an unauthenticated and a DATA-only domain past the
// prover host's cap stands in the member's or/ as the composing device reads it, refused with the MX's code, tls_refused,
// and too_large with both byte counts; held at the edge, deferred with its wait; the DSNs reach the mailbox as mail, and
// no answer MAIL gives the sender, no outcome and no DSN as the person reads it names an inbound indexer, receiver or
// coverage setting, only too_large's DSN citing a size.
func TestFs123MailOutcomesStandInTheSendingMailbox(t *testing.T) {
	const capByteCount = 4 * 1024
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	settings := mailworld.DefaultM9WorldSettings()
	settings.Component = true
	settings.DataProofByteCount = capByteCount
	world := mailworld.NewM9World(t, net, settings)
	ctx := world.Context()
	refusing := sidecartest.DefaultMxScript()
	refusing.Replies["MAIL"] = "550 5.7.1 Sender refused"
	world.AddDomain("refuse.example", mailM9RefuseMxAddress, refusing, true)
	plain := world.AddDomain("plain.example", mailM9PlainMxAddress, nil, false)
	data := world.AddDomain("data.example", mailM9DataMxAddress, sidecartest.SmtpDataOnlyMxScript(), true)
	from := "admin@" + world.M8.Zone()
	body := strings.Repeat("A line of the body, long enough to pass a small cap.\r\n", 120)

	var result *sidecar.MailSendResult
	world.Ingest(func() {
		var err error
		result, err = world.Owner.Send(ctx, &sidecar.MailSendArgs{
			From: from, To: []string{"bob@refuse.example", "carol@plain.example", "dave@data.example"}, Subject: "FS-123", Text: body,
		})
		if err != nil {
			t.Fatal(err)
		}
		if pass := world.RunOutbox(); pass.Sent != 1 {
			t.Fatalf("the outbox pass %+v", pass)
		}
	})
	for _, recipient := range result.Recipients {
		if recipient.Outcome != sidecar.MailSendQueued {
			t.Errorf("%s answered %s, not queued", recipient.Address, recipient.Outcome)
		}
		if match := mailM9InboundWords.FindString(string(recipient.Outcome)); match != "" {
			t.Errorf("a send's answer names %q", match)
		}
	}
	outcomes := world.Outcomes(result.EffectKey)
	if outcome := outcomes["refuse.example"]; outcome == nil || outcome.Outcome != sidecar.SmtpOutcomeRefused || outcome.ReplyCode != 550 {
		t.Errorf("refuse.example: %+v", outcome)
	}
	if outcome := outcomes["plain.example"]; outcome == nil || outcome.Outcome != sidecar.SmtpOutcomeTlsRefused {
		t.Errorf("plain.example: %+v", outcome)
	}
	tooLarge := outcomes["data.example"]
	if tooLarge == nil || tooLarge.Outcome != sidecar.SmtpOutcomeTooLarge || tooLarge.CapByteCount != capByteCount || tooLarge.ByteCount <= capByteCount {
		t.Fatalf("data.example: %+v", tooLarge)
	}
	if len(data.Transactions()) != 0 || len(plain.Transactions()) != 0 {
		t.Errorf("the DATA MX took %d and the plain one %d transactions", len(data.Transactions()), len(plain.Transactions()))
	}

	// the DSNs as the person reads them, in the mailbox
	page, err := world.Owner.List(ctx, &sidecar.MailListArgs{Folder: sidecar.MailFolderAll})
	if err != nil {
		t.Fatal(err)
	}
	dsnDomains := []string{}
	for _, entry := range page.Entries {
		subject := entry.Entry.GetSubject()
		domain, found := strings.CutPrefix(subject, "Undelivered mail to ")
		if !found {
			continue
		}
		read, err := world.Owner.Read(ctx, &sidecar.MailReadArgs{Month: sidecar.MailYearMonthOf(entry.Entry.GetTime()), Id: mailM9EntryId(t, entry.Entry)})
		if err != nil {
			t.Fatal(err)
		}
		text := subject + "\n" + read.Text
		if match := mailM9InboundWords.FindString(text); match != "" {
			t.Errorf("the DSN for %s names %q", domain, match)
		}
		citesSize := strings.Contains(text, fmt.Sprintf("%d bytes", tooLarge.ByteCount)) && strings.Contains(text, fmt.Sprintf("%d bytes", capByteCount))
		if citesSize != (domain == "data.example") {
			t.Errorf("the DSN for %s cites the sizes %t:\n%s", domain, citesSize, read.Text)
		}
		dsnDomains = append(dsnDomains, domain)
	}
	slices.Sort(dsnDomains)
	if !slices.Equal(dsnDomains, []string{"data.example", "plain.example", "refuse.example"}) {
		t.Fatalf("the mailbox holds DSNs for %v", dsnDomains)
	}

	// held at the edge: deferred, with the edge's wait
	wait := world.Send.HoldPreambles(2 * time.Minute)
	held, err := world.Owner.Send(ctx, &sidecar.MailSendArgs{From: from, To: []string{"erin@refuse.example"}, Subject: "FS-123 held", Text: "Later."})
	if err != nil {
		t.Fatal(err)
	}
	world.RunOutbox()
	if outcome := world.Outcomes(held.EffectKey)["refuse.example"]; outcome == nil || outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter != wait {
		t.Errorf("deferred for %v: %+v", wait, outcome)
	}
}

// The id of an i/ entry.
func mailM9EntryId(t *testing.T, entry *protocol.IndexEntry) sidecar.Id {
	t.Helper()
	id, err := sidecar.IdFromBytes(entry.GetId())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// FS-123's coverage row: GetReceiverCoverage's value and copy speak of receiving alone under none, foreground-only and
// indexer (§18.5's every value row), outbound limits being CheckSend's and GetSendResult's.
func TestFs123CoverageCopySaysNothingOfSending(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	noReceiver := `{"grants": [{"src": ["autogroup:member"], "dst": ["mail:*"], "allow": ["listen", "send"]}]}`
	cases := []struct {
		policy    string
		designate bool
		coverage  sidecar.MailCoverage
	}{
		{policy: noReceiver, coverage: sidecar.MailCoverageNone},
		{policy: mailworld.M9PolicySend, coverage: sidecar.MailCoverageForegroundOnly},
		{policy: mailworld.M9PolicySend, designate: true, coverage: sidecar.MailCoverageIndexer},
	}
	for i, c := range cases {
		settings := mailworld.DefaultM9WorldSettings()
		settings.M8 = &mailworld.M8WorldSettings{Policy: c.policy, Label: fmt.Sprintf("lbl%07d", i+1), Host: mailworld.NewM8FakeHost(t, net)}
		world := mailworld.NewM9World(t, net, settings)
		if c.designate {
			world.Designate(world.M8.Receiver, protocol.IndexerService_INDEXER_SERVICE_MAIL)
		}
		coverage, err := world.Owner.ReceiverCoverage(world.Context())
		if err != nil || coverage != c.coverage {
			t.Fatalf("coverage %s, not %s: %v", coverage, c.coverage, err)
		}
		text := string(coverage) + " " + sidecar.MailCoverageCopy(coverage)
		if match := mailM9SendingWords.FindString(text); match != "" {
			t.Errorf("coverage %s speaks of sending: %q", coverage, match)
		}
	}
}
