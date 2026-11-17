//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// S7 (§22.7; §3.7's F6, receive mail; R-MAIL-2, R-MAIL-16, D-MAIL-1, D-MAIL-2, D-MAIL-5, D-MAIL-14, I-11, I-13; MAIL-M7-27)
// on T2, under §22.7's harness and guard (RunScenario): MailWorld on the scenario's Net, so the router's FakeRedis and
// FakeMxEdgeStore, evs's engine and its objects and the gkm objects are the Net's, which the capture and the schema
// guard read at the end. Canaries go in a recipient's local part, a subject and a body. The flow:
//
//   - plaintext: MAIL before STARTTLS gets 530 5.7.0 linking the published deviation, no closed handshake behind it;
//   - unroutable: a name no route holds closes in the handshake with unrecognized_name, nothing is dialed or deposited,
//     and a plaintext retry from a sibling in the sender's /24 then gets 451 4.7.0, a temporary failure;
//   - reception-time DNS: a DKIM-signed, SPF-passing message under p=reject reaches the receiver through the splice, 250
//     once its deposit is durable; the sender's DNS then changes (the selector gone, SPF failing), and the reader's
//     ingest labels it from the sealed evidence alone, spf, dkim and dmarc pass, asking the zone nothing;
//   - tampered evidence: a deposit whose evidence names another message is written "evidence unavailable", labeled
//     opportunistic, with an evidence alarm; one whose trailer names another receiver than its push's signer the same,
//     with a wrong_signer alarm;
//   - a bound cut: a message carrying 64 DKIM signatures is deposited and answered 250, its evidence's limits naming the
//     count bound, and labeled from what was verified, checks incomplete, never validated.
//
// SNI-less abuse@<root> reaching the platform listener is S7's M5 part, mail_platform_scenario_test.go's, which the
// registrations below name, as server's T3 runs do.

package sidecartest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// The flow's sender and its sibling in the same /24, RFC 5737's.
var (
	s7Sender        = netip.MustParseAddr("203.0.113.9")
	s7SenderSibling = netip.MustParseAddr("203.0.113.77")
	s7OtherSender   = netip.MustParseAddr("198.51.100.20")
)

const (
	s7SenderDomain = "sender.example"
	s7Selector     = "s7"
)

// A message from sender@sender.example to recipient, DKIM-signed by s7's key, with subject and body.
func s7Message(t testing.TB, world *mailworld.MailWorld, signer *sidecartest.MailDkimSigner, recipient string, subject string, body string) []byte {
	t.Helper()
	message := []byte(strings.Join([]string{
		"From: Sender <sender@" + s7SenderDomain + ">",
		"To: <" + recipient + ">",
		"Subject: " + subject,
		"Date: Tue, 17 Nov 2026 12:00:00 +0000",
		"Message-ID: <" + fmt.Sprintf("%x", sha256.Sum256([]byte(subject)))[:16] + "@" + s7SenderDomain + ">",
		"",
		body,
		"",
	}, "\r\n"))
	signed, err := signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// The sender's DNS: SPF passing the /24, DMARC p=reject and the selector's key.
func s7PublishSender(world *mailworld.MailWorld, signer *sidecartest.MailDkimSigner) {
	world.Zone.AddTxt(s7SenderDomain, "v=spf1 ip4:203.0.113.0/24 -all")
	world.Zone.AddTxt("_dmarc."+s7SenderDomain, "v=DMARC1; p=reject")
	world.Zone.AddTxt(sidecartest.MailDkimKeyName(s7Selector, s7SenderDomain), signer.KeyRecord())
}

// A deposit as a receiver writes one, by hand: the message, then trailer, then u32be of its length.
func s7DepositBody(t testing.TB, message []byte, trailer *protocol.MailDeposit) []byte {
	t.Helper()
	trailerBytes, err := proto.Marshal(trailer)
	if err != nil {
		t.Fatal(err)
	}
	body := append(bytes.Clone(message), trailerBytes...)
	return binary.BigEndian.AppendUint32(body, uint32(len(trailerBytes)))
}

// S7's flow on run's Net.
func s7Run(t *testing.T) func(ctx context.Context, run *sidecartest.ScenarioRun) error {
	return func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		localPart := run.CanaryText("mail local part")
		subject := run.CanaryText("mail subject")
		bodyCanary := run.CanaryText("mail body")
		settings := mailworld.DefaultMailWorldSettings()
		recipient := localPart + "@" + settings.Label + "." + settings.Root
		settings.Addresses = []string{recipient}
		world := mailworld.NewMailWorld(t, run.Net.Fakes(), run.Net.Clock(), settings)
		owner := world.Device(world.Owner, false, sidecartest.NewFakeStore().Root(), nil)

		// plaintext: 530 linking the deviation, since no handshake closed for this /24
		plain := world.Connect(s7Sender)
		world.Greet(plain, "relay.sender.example")
		reply, err := plain.PlaintextTransaction("sender@" + s7SenderDomain)
		if err != nil || !reply.Is(530) || len(reply.Lines) != 1 || !strings.HasPrefix(reply.Lines[0], "5.7.0 ") || !strings.HasSuffix(reply.Lines[0], settings.DeviationUrl) {
			return fmt.Errorf("plaintext MAIL: %s %v", reply, err)
		}
		plain.Close()

		// unroutable: closed in the handshake, nothing dialed or deposited, and the sibling's plaintext retry gets 451
		opensBefore := len(world.Opens())
		unroutable := world.Connect(s7Sender)
		world.Greet(unroutable, "relay.sender.example")
		_, err = world.StartTls(unroutable, sidecartest.MailMtaTlsConfig("mx.nosuchlabel."+settings.Root, tls.VersionTLS13))
		if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
			return fmt.Errorf("an unroutable name's handshake: %v", err)
		}
		unroutable.Close()
		retry := world.Connect(s7SenderSibling)
		world.Greet(retry, "relay.sender.example")
		reply, err = retry.PlaintextTransaction("sender@" + s7SenderDomain)
		if err != nil || !reply.Is(451) || len(reply.Lines) != 1 || !strings.HasPrefix(reply.Lines[0], "4.7.0 ") {
			return fmt.Errorf("the sibling's plaintext retry after a closed handshake: %s %v", reply, err)
		}
		retry.Close()
		if opens := len(world.Opens()); opens != opensBefore {
			return fmt.Errorf("an unroutable name was opened to a receiver %d times", opens-opensBefore)
		}
		if deposits, err := world.StandingDeposits(owner); err != nil || len(deposits) != 0 {
			return fmt.Errorf("deposits after the refusals: %d, %v", len(deposits), err)
		}

		// reception-time DNS: a signed message through the splice, 250 once its deposit is durable
		signer, err := sidecartest.NewMailDkimSigner(s7SenderDomain, s7Selector, sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
		if err != nil {
			return err
		}
		s7PublishSender(world, signer)
		message := s7Message(t, world, signer, recipient, subject, bodyCanary)
		if reply := world.Send(s7Sender, settings.MxHost(), "sender@"+s7SenderDomain, []string{recipient}, message); !reply.Is(250) {
			return fmt.Errorf("a signed message through the splice: %s", reply)
		}
		deposits, err := world.StandingDeposits(owner)
		if err != nil || len(deposits) != 1 {
			return fmt.Errorf("deposits after the 250: %d, %v", len(deposits), err)
		}
		evidence := deposits[0].Trailer.GetEvidence()
		if !bytes.Equal(deposits[0].Message, message) || evidence.GetSpf().GetResult() != protocol.SpfVerdict_SPF_PASS ||
			evidence.GetDmarc().GetResult() != protocol.DmarcVerdict_DMARC_PASS || evidence.GetLimits() != nil {
			return fmt.Errorf("the deposit's evidence: %v", evidence)
		}
		// the sender's DNS changes before the reader ingests: the selector gone, SPF failing every address
		world.Zone.Fail(sidecartest.MailDkimKeyName(s7Selector, s7SenderDomain), dnsmessage.TypeTXT, sidecartest.FakeMailZoneNxDomain)
		world.Zone.Fail(s7SenderDomain, dnsmessage.TypeTXT, sidecartest.FakeMailZoneNxDomain)
		queriesBefore := len(world.Zone.Queries())
		messages := []*sidecar.MailMessage{}
		alarms := []*sidecar.MailIngestAlarm{}
		ingestor := world.Ingestor(owner, world.Owner.SidecarId, func(message *sidecar.MailMessage) {
			messages = append(messages, message)
		}, func(alarm *sidecar.MailIngestAlarm) {
			alarms = append(alarms, alarm)
		})
		pass, err := ingestor.Ingest(ctx)
		if err != nil || pass.Ingested != 1 || pass.Consumed != 1 {
			return fmt.Errorf("the first ingest: %+v, %v", pass, err)
		}
		results := messages[0].Entry.GetAuthResults()
		if results.GetSpf() != protocol.SpfVerdict_SPF_PASS || results.GetDkim() != protocol.DkimVerdict_DKIM_PASS ||
			results.GetDmarc() != protocol.DmarcVerdict_DMARC_PASS || results.GetChecksIncomplete() || results.GetEvidenceUnavailable() {
			return fmt.Errorf("the reception-time results after a DNS change: %v", results)
		}
		if label := messages[0].Entry.GetTlsLabel(); label != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC {
			return fmt.Errorf("a message with no REQUIRETLS and no listed operator labeled %v", label)
		}
		if queries := len(world.Zone.Queries()); queries != queriesBefore {
			return fmt.Errorf("ingest asked the zone %d times", queries-queriesBefore)
		}
		if 0 < len(alarms) {
			return fmt.Errorf("an honest deposit alarmed: %+v", alarms[0])
		}

		// tampered evidence: a deposit whose evidence names another message's hash
		tampered := s7Message(t, world, signer, recipient, "tampered "+subject, bodyCanary)
		otherSha256 := sha256.Sum256([]byte("another message"))
		trailer := proto.Clone(deposits[0].Trailer).(*protocol.MailDeposit)
		trailer.Evidence.MessageSha256 = otherSha256[:]
		body := s7DepositBody(t, tampered, trailer)
		if _, err := world.ReceiverEvs.Repo(world.RepoId).Deposit(ctx, &sidecar.EvsDepositArgs{Body: bytes.NewReader(body), Size: int64(len(body))}); err != nil {
			return fmt.Errorf("the tampered deposit: %v", err)
		}
		// and one whose trailer names a receiver other than its push's signer
		misnamed := s7Message(t, world, signer, recipient, "misnamed "+subject, bodyCanary)
		misnamedSha256 := sha256.Sum256(misnamed)
		trailer = proto.Clone(deposits[0].Trailer).(*protocol.MailDeposit)
		otherReceiver := sidecar.NewId()
		trailer.ReceiverSidecarId = otherReceiver.Bytes()
		trailer.Evidence.ReceiverSidecarId = otherReceiver.Bytes()
		trailer.Evidence.MessageSha256 = misnamedSha256[:]
		body = s7DepositBody(t, misnamed, trailer)
		if _, err := world.ReceiverEvs.Repo(world.RepoId).Deposit(ctx, &sidecar.EvsDepositArgs{Body: bytes.NewReader(body), Size: int64(len(body))}); err != nil {
			return fmt.Errorf("the misnamed deposit: %v", err)
		}
		messages = messages[:0]
		pass, err = ingestor.Ingest(ctx)
		if err != nil || pass.Ingested != 2 || pass.Consumed != 2 || len(messages) != 2 {
			return fmt.Errorf("the second ingest: %+v, %v", pass, err)
		}
		for _, written := range messages {
			if !written.Entry.GetAuthResults().GetEvidenceUnavailable() || written.Entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC {
				return fmt.Errorf("a deposit with tampered evidence was written %v, %v", written.Entry.GetAuthResults(), written.Entry.GetTlsLabel())
			}
		}
		kinds := map[sidecar.MailIngestAlarmKind]int{}
		for _, alarm := range alarms {
			kinds[alarm.Kind] += 1
		}
		if kinds[sidecar.MailIngestAlarmEvidence] != 1 || kinds[sidecar.MailIngestAlarmWrongSigner] != 1 || len(alarms) != 2 {
			return fmt.Errorf("the tampered deposits' alarms: %v", kinds)
		}

		// a bound cut: 64 DKIM signatures, deposited and labeled from what was verified
		corpus := sidecartest.NewMailCorpus(world.Zone, world.Clock.Now())
		maximal, err := corpus.MaximalSignatures(64)
		if err != nil {
			return err
		}
		// sent as signed: RCPT routes it, and its To field stays the one its signatures cover
		if reply := world.Send(s7OtherSender, settings.MxHost(), "sender@"+maximal.FromDomain, []string{recipient}, maximal.Bytes); !reply.Is(250) {
			return fmt.Errorf("a message whose checks a bound cuts: %s", reply)
		}
		deposits, err = world.StandingDeposits(owner)
		if err != nil || len(deposits) != 1 {
			return fmt.Errorf("deposits after the cut message: %d, %v", len(deposits), err)
		}
		limits := deposits[0].Trailer.GetEvidence().GetLimits()
		if limits.GetReason()&1 == 0 || limits.GetDkimSeen() != 64 || limits.GetDkimChecked() != 8 || len(deposits[0].Trailer.GetEvidence().GetDkim()) != 8 {
			return fmt.Errorf("the cut message's limits %v", limits)
		}
		// what was verified: the 8 selected signatures, each valid, none aligned with From
		for _, dkim := range deposits[0].Trailer.GetEvidence().GetDkim() {
			if dkim.GetResult() != protocol.DkimVerdict_DKIM_PASS {
				return fmt.Errorf("a selected valid signature sealed %v", dkim.GetResult())
			}
		}
		messages = messages[:0]
		if pass, err := ingestor.Ingest(ctx); err != nil || pass.Ingested != 1 || len(messages) != 1 {
			return fmt.Errorf("the third ingest: %+v, %v", pass, err)
		}
		if results := messages[0].Entry.GetAuthResults(); !results.GetChecksIncomplete() || messages[0].Entry.GetTlsLabel() == protocol.MailTlsLabel_MAIL_TLS_VALIDATED {
			return fmt.Errorf("a cut check's message: %v, %v", results, messages[0].Entry.GetTlsLabel())
		}

		// the router's last batch at its close: one mail_connection_record a session that named the network, the two
		// spliced ones, each of mx-2's four fields alone; the plaintext and unroutable sessions named none and left none
		world.Router.Drain()
		world.Router.Close()
		records := world.Records.Records()
		if len(records) != 2 {
			return fmt.Errorf("%d mail_connection_record rows for two routed sessions", len(records))
		}
		for _, record := range records {
			if record.NetworkId != world.NetworkId || record.ByteCount <= 0 || record.Result == "" {
				return fmt.Errorf("a record %+v", record)
			}
		}

		// the capture reads the router's and the session's logs, the host's metrics and the records beside the stores,
		// none of which may hold a sender's address or its EHLO name (I-13)
		capture := run.Net.Capture()
		// mx-1 keeps the fleet's daily key k in Redis at {vhk}mx:<yyyymmdd>, which testHookSecret hands the capture
		if err := capture.Declare("mx-1", "K_mxc_day", sidecartest.PrivacyClassRedis); err != nil {
			return err
		}
		for _, sender := range []netip.Addr{s7Sender, s7SenderSibling, s7OtherSender} {
			capture.Forbid("sender address", []byte(sender.String()))
		}
		capture.Forbid("ehlo name", []byte("relay.sender.example"))
		for _, line := range world.LogLines() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassLog, Name: "mail log", Body: []byte(line)})
		}
		for _, line := range run.Net.Fakes().Metrics.Dump() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassMetric, Name: "metric", Body: []byte(line)})
		}
		for _, record := range records {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassObject, Name: "mail_connection_record", Body: []byte(fmt.Sprintf("%+v", record))})
		}
		return nil
	}
}

// S7 on T2 under the harness and guard.
func TestScenarioS7ReceiveMail(t *testing.T) {
	sidecartest.RunScenario(t, &sidecartest.Scenario{Id: "S7", Run: s7Run(t)}, nil)
}

// FS-39's labels case at M7 (§22.8; §22.7's mail-labels row; owner decision 135, D-MAIL-14) through the receiver on T2,
// labels as stated:
//
//   - delayed DNS evidence: a message whose author's selector the zone does not hold at reception is deposited with its
//     DKIM check failing and labeled opportunistic; the selector published before the reader ingests changes nothing,
//     since ingest decides from the sealed evidence and asks no name;
//   - REQUIRETLS added by an active second hop: a forwarder that read the message, kept its author's valid DKIM
//     signature and sent the last hop with REQUIRETLS gets it labeled validated on the REQUIRETLS rule, its statement
//     naming only the final hop's requirement, URnetwork included in what it does not exclude, and claiming no path.
func TestFs39LabelsAsStatedThroughTheReceiver(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	settings := mailworld.DefaultMailWorldSettings()
	world := mailworld.NewMailWorld(t, host, clock, settings)
	owner := world.Device(world.Owner, false, sidecartest.NewFakeStore().Root(), nil)
	recipient := settings.Addresses[0]

	// delayed DNS evidence
	late, err := sidecartest.NewMailDkimSigner("late.example", "late", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	world.Zone.AddTxt("_dmarc.late.example", "v=DMARC1; p=none")
	lateMessage, err := late.Sign([]byte("From: <author@late.example>\r\nTo: <" + recipient + ">\r\nSubject: delayed\r\n" +
		"Date: Tue, 17 Nov 2026 12:00:00 +0000\r\nMessage-ID: <delayed@late.example>\r\n\r\nA message whose selector comes later.\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if reply := world.Send(s7Sender, settings.MxHost(), "author@late.example", []string{recipient}, lateMessage); !reply.Is(250) {
		t.Fatalf("the delayed message: %s", reply)
	}
	world.Zone.AddTxt(sidecartest.MailDkimKeyName("late", "late.example"), late.KeyRecord())

	// REQUIRETLS from an active second hop, which kept the author's signature
	origin, err := sidecartest.NewMailDkimSigner("origin.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	world.Zone.AddTxt("_dmarc.origin.example", "v=DMARC1; p=reject")
	world.Zone.AddTxt(sidecartest.MailDkimKeyName("s1", "origin.example"), origin.KeyRecord())
	hopMessage, err := origin.Sign([]byte("From: <author@origin.example>\r\nTo: <" + recipient + ">\r\nSubject: second hop\r\n" +
		"Date: Tue, 17 Nov 2026 12:00:00 +0000\r\nMessage-ID: <hop@origin.example>\r\n\r\nA message a forwarder read and sent on.\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	reply := world.SendWith(&mailworld.MailWorldSend{
		Sender: s7OtherSender, Sni: settings.MxHost(), From: "forwarder@hop.example", FromParameters: "REQUIRETLS",
		Recipients: []string{recipient}, Message: hopMessage,
	})
	if !reply.Is(250) {
		t.Fatalf("the second hop's message: %s", reply)
	}

	queriesBefore := len(world.Zone.Queries())
	messages := map[string]*sidecar.MailMessage{}
	ingestor := world.Ingestor(owner, world.Owner.SidecarId, func(message *sidecar.MailMessage) {
		messages[message.Entry.GetSubject()] = message
	}, nil)
	if pass, err := ingestor.Ingest(ctx); err != nil || pass.Ingested != 2 {
		t.Fatalf("ingest: %+v, %v", pass, err)
	}
	if queries := len(world.Zone.Queries()); queries != queriesBefore {
		t.Fatalf("ingest asked the zone %d times", queries-queriesBefore)
	}
	delayed := messages["delayed"]
	if delayed == nil || delayed.Entry.GetAuthResults().GetDkim() == protocol.DkimVerdict_DKIM_PASS ||
		delayed.Entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_OPPORTUNISTIC {
		t.Fatalf("the delayed message: %v, %v", delayed.Entry.GetAuthResults(), delayed.Entry.GetTlsLabel())
	}
	hop := messages["second hop"]
	if hop == nil || hop.Entry.GetTlsLabel() != protocol.MailTlsLabel_MAIL_TLS_VALIDATED ||
		hop.Entry.GetTlsBasis().GetRule() != protocol.MailTlsRule_MAIL_TLS_RULE_REQUIRETLS ||
		hop.Entry.GetAuthResults().GetDkim() != protocol.DkimVerdict_DKIM_PASS {
		t.Fatalf("the second hop's message: %v, %v, %v", hop.Entry.GetTlsLabel(), hop.Entry.GetTlsBasis(), hop.Entry.GetAuthResults())
	}
	statement := hop.Label.Statement()
	if !strings.Contains(statement, "only the final hop's requirement") || !strings.Contains(statement, "URnetwork included") ||
		strings.Contains(statement, "end-to-end") || strings.Contains(strings.ToLower(statement), "encrypted all the way") {
		t.Fatalf("the second hop's statement: %q", statement)
	}
}
