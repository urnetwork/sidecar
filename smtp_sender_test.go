//go:build !sidecar_http && !ios_extension

// SmtpSender.Send (SMTP-M9-08) on testSenderWorld: a two-domain send whose domains come out apart, one sent and one
// too_large; each outcome kind reaching SmtpDomainOutcome, or/ and a mail_send event; a replay after a crash between
// MAIL and the result sending at most once more and saying so; a hundred recipients at one domain on one connection;
// KEYS falling back to an older key set once, else deferred for KeysRetryTimeout; EnvelopeRetry retrying once with
// groups of one and keeping the count, a second failed; mixed recipients resent to the taken alone; Bcc out of the
// header block and in the receipts; a host with no key set only queuing; and FS-123's sender half on a fake clock.
//
// Names are .example and addresses RFC 5737's.

package sidecar_test

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	// a domain whose MX offers no CHUNKING after TLS, so a send goes in DATA
	testDataDomain = "data.example"
	testDataHost   = "mx.data.example"
)

var testDataAddress = netip.MustParseAddr("198.51.100.77")

// An MX script with no CHUNKING inside TLS.
func testDataOnlyScript() *sidecartest.MxScript {
	script := sidecartest.DefaultMxScript()
	script.Keywords = []string{"PIPELINING", "SIZE 52428800", "8BITMIME"}
	return script
}

// A two-domain send: the CHUNKING MX takes it, while the non-CHUNKING MX gets nothing past EHLO, its domain too_large
// with the size and the cap; each domain's outcome stands alone, both in or/ and in the answer, and only the
// too_large domain's DSN cites the cap.
func TestSmtpSenderTwoDomainsComeOutApart(t *testing.T) {
	proverSettings := sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.DataProofByteCount = 2 * 1024
	world := newTestSenderWorld(t, &testSenderOptions{prover: proverSettings})
	dataMx := world.addDomain(testDataDomain, testDataHost, testDataAddress, testDataOnlyScript())
	body := strings.Repeat("A line of the body, long enough to pass a small cap.\r\n", 60)
	message := world.message([]string{"bob@" + testTlsDomain, "dave@" + testDataDomain}, nil, body)
	result := world.send(message)

	sent := testDomainOutcome(t, result, testTlsDomain)
	if sent.Outcome != sidecar.SmtpOutcomeSent || sent.Mode != sidecar.SmtpModeBdat || sent.TlsLevel != sidecar.SmtpTlsLevelIndependentMx {
		t.Errorf("the CHUNKING domain: %+v", sent)
	}
	tooLarge := testDomainOutcome(t, result, testDataDomain)
	if tooLarge.Outcome != sidecar.SmtpOutcomeTooLarge || tooLarge.Mode != sidecar.SmtpModeData || tooLarge.CapByteCount != 2*1024 || tooLarge.ByteCount <= 2*1024 {
		t.Errorf("the DATA domain: %+v", tooLarge)
	}
	if len(world.mx.Transactions()) != 1 || len(dataMx.Transactions()) != 0 {
		t.Errorf("%d and %d transactions", len(world.mx.Transactions()), len(dataMx.Transactions()))
	}
	for _, event := range dataMx.Events() {
		if event.Secure && !strings.HasPrefix(event.Command, "EHLO") {
			t.Errorf("the DATA MX saw %q inside TLS", event.Command)
		}
	}
	stored, err := world.mailbox.ReadOutcomes(context.Background(), message.EffectKey)
	if err != nil || len(stored) != 2 || stored[0].Outcome != sidecar.SmtpOutcomeSent || stored[1].Outcome != sidecar.SmtpOutcomeTooLarge {
		t.Errorf("or/ holds %+v, %v", stored, err)
	}
	dsns := world.mailbox.Dsns()
	if len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte(testDataDomain)) || !bytes.Contains(dsns[0].Dsn, []byte("2048 bytes")) ||
		!bytes.Contains(dsns[0].Dsn, []byte("Final-Recipient: rfc822; dave@"+testDataDomain)) || bytes.Contains(dsns[0].Dsn, []byte("Final-Recipient: rfc822; bob@")) {
		t.Errorf("dsns %s", testDsnText(dsns))
	}
	if count := world.mailSendEvents(); count != 2 {
		t.Errorf("%d mail_send events", count)
	}
	// the mode is pinned for the domain, so Check knows it from here
	if mode, err := world.pins.DomainMode(testDataDomain); err != nil || mode != sidecar.SmtpModeData {
		t.Errorf("the DATA domain's mode %d, %v", mode, err)
	}
}

// Each outcome kind reaches SmtpDomainOutcome and or/: deferred with the edge's wait, failed with a DSN for NO_MX,
// refused with the MX's code, tls_refused below TL3 with no allowance.
func TestSmtpSenderOutcomesReachTheResult(t *testing.T) {
	// TRY_LATER: deferred with the edge's wait, a held send never failed
	edgeSettings := sidecartest.DefaultStubSmtpEdgeSettings()
	edgeSettings.Code = protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER
	edgeSettings.RetryAfter = 90 * time.Second
	world := newTestSenderWorld(t, &testSenderOptions{edge: edgeSettings})
	result := world.send(world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))
	if outcome := testDomainOutcome(t, result, testTlsDomain); outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter != 90*time.Second {
		t.Errorf("TRY_LATER: %+v", outcome)
	}
	if len(world.mailbox.Dsns()) != 0 {
		t.Error("a held send made a DSN")
	}

	// NO_MX: failed, with a DSN that names no cap
	world = newTestSenderWorld(t, nil)
	result = world.send(world.message([]string{"bob@nowhere.example"}, nil, "body\r\n"))
	if outcome := testDomainOutcome(t, result, "nowhere.example"); outcome.Outcome != sidecar.SmtpOutcomeFailed {
		t.Errorf("NO_MX: %+v", outcome)
	}
	if dsns := world.mailbox.Dsns(); len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte("no mail server")) || bytes.Contains(dsns[0].Dsn, []byte(" bytes")) {
		t.Errorf("NO_MX's dsns %s", testDsnText(dsns))
	}

	// MAIL refused: refused with the MX's code
	script := sidecartest.DefaultMxScript()
	script.Replies["MAIL"] = "550 5.7.1 Sender refused"
	world = newTestSenderWorld(t, &testSenderOptions{script: script})
	result = world.send(world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))
	if outcome := testDomainOutcome(t, result, testTlsDomain); outcome.Outcome != sidecar.SmtpOutcomeRefused || outcome.ReplyCode != 550 {
		t.Errorf("a refused MAIL: %+v", outcome)
	}
	if dsns := world.mailbox.Dsns(); len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte("Diagnostic-Code: smtp; 550")) {
		t.Errorf("a refused MAIL's dsns %s", testDsnText(dsns))
	}

	// a self-signed MX the device's DoH does not name: TL4, refused inside the handshake with no allowance
	world = newTestSenderWorld(t, nil)
	if err := world.tls.world.SetMx(testTlsOtherZone, &sidecar.SmtpMxHost{Preference: 10, Host: testTlsOtherHost}); err != nil {
		t.Fatal(err)
	}
	unauthenticated := world.tls.addMx(t, testTlsOtherHost, testTlsOtherAddress, nil)
	result = world.send(world.message([]string{"bob@" + testTlsOtherZone}, nil, "body\r\n"))
	if outcome := testDomainOutcome(t, result, testTlsOtherZone); outcome.Outcome != sidecar.SmtpOutcomeTlsRefused || outcome.TlsLevel != sidecar.SmtpTlsLevelUnreached {
		t.Errorf("TL4: %+v", outcome)
	}
	if secure, transactions := testTlsMxSaw(unauthenticated); secure != 0 || transactions != 0 {
		t.Errorf("a refused MX saw %d commands inside TLS", secure)
	}
	if dsns := world.mailbox.Dsns(); len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte(sidecar.SmtpTlsRefusalStatus)) {
		t.Errorf("TL4's dsns %s", testDsnText(dsns))
	}
}

// A host with no ready key set only queues: no dial, no or/, nothing else.
func TestSmtpSenderWithNoProverQueues(t *testing.T) {
	world := newTestSenderWorld(t, &testSenderOptions{noProver: true})
	message := world.message([]string{"bob@" + testTlsDomain, "carol@" + testTlsOtherZone}, nil, "body\r\n")
	result := world.send(message)
	for _, outcome := range result.Domains {
		if outcome.Outcome != sidecar.SmtpOutcomeQueued {
			t.Errorf("%s: %+v", outcome.Domain, outcome)
		}
	}
	if world.stub.DialCount() != 0 || world.mailbox.OpCount("WriteOutcomes") != 0 || len(world.mailbox.Dsns()) != 0 || world.mailSendEvents() != 0 {
		t.Errorf("a queued send dialed %d times and wrote or/ %d times", world.stub.DialCount(), world.mailbox.OpCount("WriteOutcomes"))
	}

	// keys not ready yet: the same
	proverSettings := sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.PrepareShapeCount = 3
	world = newTestSenderWorld(t, &testSenderOptions{prover: proverSettings})
	result = world.send(world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeQueued || world.stub.DialCount() != 0 {
		t.Errorf("unready keys: %+v after %d dials", result.Domains, world.stub.DialCount())
	}
}

// A crash between MAIL and the result leaves or/ queued; the replay, once the take-over time has passed, sends at most
// once more and says so, and a replay of a sent message sends nothing.
func TestSmtpSenderReplaySendsAtMostOnceMore(t *testing.T) {
	world := newTestSenderWorld(t, nil)
	message := world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n")
	// what a crash after MAIL leaves: queued, never rewritten
	crashed := &sidecar.SmtpDomainOutcome{Domain: testTlsDomain, Outcome: sidecar.SmtpOutcomeQueued, UpdateTime: world.tls.clock.Now()}
	if err := world.mailbox.WriteOutcomes(context.Background(), message.EffectKey, []*sidecar.SmtpDomainOutcome{crashed}); err != nil {
		t.Fatal(err)
	}
	// while it is fresh, another host may still be on it: nothing goes
	result := world.send(message)
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeQueued || world.stub.DialCount() != 0 {
		t.Fatalf("a live send was taken over: %+v", result.Domains)
	}
	world.tls.clock.Advance(world.settings.OutboxTakeoverTimeout)
	result = world.send(message)
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeSent || !slices.Equal(result.ResentDomains, []string{testTlsDomain}) {
		t.Errorf("the replay %+v, resent %v", result.Domains, result.ResentDomains)
	}
	result = world.send(message)
	if len(world.mx.Transactions()) != 1 || len(result.ResentDomains) != 0 || testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeSent {
		t.Errorf("%d transactions after replaying a sent message", len(world.mx.Transactions()))
	}
}

// A hundred recipients at one domain make one connection, the whole envelope one transaction (owner decision 434).
func TestSmtpSenderOneConnectionADomain(t *testing.T) {
	world := newTestSenderWorld(t, nil)
	recipients := []string{}
	for i := range 100 {
		recipients = append(recipients, "r"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+strings.Repeat("0", i/26)+"@"+testTlsDomain)
	}
	result := world.send(world.message(recipients, nil, "body\r\n"))
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("%+v", result.Domains)
	}
	transactions := world.mx.Transactions()
	if world.stub.DialCount() != 1 || len(transactions) != 1 || len(transactions[0].Recipients) != 100 || world.edge.Preambles()[0].GetRecipientCount() != 100 {
		t.Errorf("%d dials, transactions %d", world.stub.DialCount(), len(transactions))
	}
	if notes := world.reachNotes(); len(notes) != 100 {
		t.Errorf("%d reach notes", len(notes))
	}
}

// KEYS: the next older ready key set sends, once; with none, the send is deferred for KeysRetryTimeout and its entry
// left for another host.
func TestSmtpSenderKeysFallsBackOnce(t *testing.T) {
	newer := bytes.Repeat([]byte{0x4e}, 32)
	older := sidecartest.FakeSmtpProverKeySet()
	proverSettings := sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.KeySets = [][]byte{newer, older}
	world := newTestSenderWorld(t, &testSenderOptions{
		prover:         proverSettings,
		readyKeySets:   [][]byte{newer, older},
		verifierScript: &sidecartest.FakeSmtpProofScript{RefuseKeySets: [][]byte{newer}},
	})
	result := world.send(world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("%+v", result.Domains)
	}
	preambles := world.edge.Preambles()
	if len(preambles) != 2 || !bytes.Equal(preambles[0].GetProofKeySet(), newer) || !bytes.Equal(preambles[1].GetProofKeySet(), older) {
		t.Errorf("preambles named %d key sets", len(preambles))
	}

	// no older set: deferred 6 h, no MX dialed
	proverSettings = sidecartest.DefaultFakeSmtpProverSettings()
	world = newTestSenderWorld(t, &testSenderOptions{
		prover:         proverSettings,
		verifierScript: &sidecartest.FakeSmtpProofScript{RefuseKeySets: [][]byte{sidecartest.FakeSmtpProverKeySet()}},
	})
	result = world.send(world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))
	if outcome := testDomainOutcome(t, result, testTlsDomain); outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter != world.settings.KeysRetryTimeout {
		t.Errorf("KEYS alone: %+v", outcome)
	}
	if len(world.tls.world.Dials()) != 0 || len(world.mailbox.Dsns()) != 0 {
		t.Errorf("KEYS dialed %d MXs", len(world.tls.world.Dials()))
	}
}

// EnvelopeRetry retries once with groups of EnvelopeRetryGroupCount and retry_of_send_id, the count kept on the MX
// host's pin entry; a second overflow is failed.
func TestSmtpSenderEnvelopeRetryOnceAndKeepsTheCount(t *testing.T) {
	proverSettings := sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.EnvelopeRetry = func(job *sidecar.SmtpProofJob) bool { return job.EnvelopeGroupMaxCount == 0 }
	world := newTestSenderWorld(t, &testSenderOptions{prover: proverSettings})
	result := world.send(world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("%+v", result.Domains)
	}
	sends := world.prover.Sends()
	preambles := world.edge.Preambles()
	if len(sends) != 2 || len(preambles) != 2 || len(preambles[1].GetRetryOfSendId()) != sidecar.SmtpSendIdByteCount {
		t.Fatalf("%d sends, %d preambles", len(sends), len(preambles))
	}
	if count, err := world.pins.EnvelopeGroupMaxCount(testTlsDomain); err != nil || count != world.settings.EnvelopeRetryGroupCount {
		t.Errorf("the host's group count %d, %v", count, err)
	}
	// the next send starts there, and so needs no retry
	world.send(world.message([]string{"carol@" + testTlsDomain}, nil, "body\r\n"))
	if sends := world.prover.Sends(); len(sends) != 3 {
		t.Errorf("%d sends", len(sends))
	}

	proverSettings = sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.EnvelopeRetry = func(job *sidecar.SmtpProofJob) bool { return true }
	world = newTestSenderWorld(t, &testSenderOptions{prover: proverSettings})
	result = world.send(world.message([]string{"bob@" + testTlsDomain}, nil, "body\r\n"))
	if outcome := testDomainOutcome(t, result, testTlsDomain); outcome.Outcome != sidecar.SmtpOutcomeFailed || len(world.prover.Sends()) != 2 {
		t.Errorf("a second overflow: %+v after %d sends", outcome, len(world.prover.Sends()))
	}
}

// A send refused at one RCPT and taken at another resends at once to the taken alone; the refused gets a DSN.
func TestSmtpSenderMixedRecipientsResendToTheTaken(t *testing.T) {
	script := sidecartest.DefaultMxScript()
	script.RcptReplies["carol"] = "550 5.1.1 No such user"
	world := newTestSenderWorld(t, &testSenderOptions{script: script})
	result := world.send(world.message([]string{"bob@" + testTlsDomain, "carol@" + testTlsDomain}, nil, "body\r\n"))
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("%+v", result.Domains)
	}
	transactions := world.mx.Transactions()
	if len(transactions) != 1 || !slices.Equal(transactions[0].Recipients, []string{"<bob@" + testTlsDomain + ">"}) || world.stub.DialCount() != 2 {
		t.Errorf("transactions %+v after %d dials", transactions, world.stub.DialCount())
	}
	dsns := world.mailbox.Dsns()
	if len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte("carol@"+testTlsDomain)) || bytes.Contains(dsns[0].Dsn, []byte("Final-Recipient: rfc822; bob@")) {
		t.Errorf("dsns %s", testDsnText(dsns))
	}
}

// Bcc leaves the header block and every copy, and still gets its receipt (§16.8).
func TestSmtpSenderBccInReceiptsNotHeaders(t *testing.T) {
	world := newTestSenderWorld(t, nil)
	message := world.message([]string{"bob@" + testTlsDomain}, []string{"eve@" + testTlsDomain}, "body\r\n")
	result := world.send(message)
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("%+v", result.Domains)
	}
	transactions := world.mx.Transactions()
	if len(transactions) != 1 || len(transactions[0].Recipients) != 2 || bytes.Contains(transactions[0].Message, []byte("eve@")) ||
		bytes.Contains(bytes.ToLower(transactions[0].Message), []byte("bcc:")) {
		t.Errorf("transactions %+v", transactions)
	}
	notes := world.reachNotes()
	peers := []string{}
	for _, note := range notes {
		if note.Kind != sidecar.RecordReachKindSend || len(note.Peers) != 2 || note.Relays[0].Host != testTlsHost {
			t.Errorf("note %+v", note)
		}
		peers = append(peers, string(note.Peers[0])+"@"+string(note.Peers[1]))
	}
	if !slices.Equal(peers, []string{"bob@" + testTlsDomain, "eve@" + testTlsDomain}) {
		t.Errorf("receipts for %v", peers)
	}
}

// The retry schedule: 30 min, doubling to 4 h, then every 4 h, given up at 5 days; a hold honors its wait and still
// ends there; a retry spends at most two units a UTC day.
func TestSmtpRetryPolicySchedule(t *testing.T) {
	settings := sidecar.DefaultSmtpSenderSettings()
	policy := sidecar.NewSmtpRetryPolicy(settings)
	created := time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)
	want := []time.Duration{30 * time.Minute, 90 * time.Minute, 210 * time.Minute, 450 * time.Minute, 690 * time.Minute}
	now := created
	for _, offset := range want {
		next, ok := policy.Next(created, now)
		if !ok || !next.Equal(created.Add(offset)) {
			t.Fatalf("after %v: %v, %v; want %v", now.Sub(created), next.Sub(created), ok, offset)
		}
		now = next
	}
	if _, ok := policy.Next(created, created.Add(5*24*time.Hour-time.Minute)); ok {
		t.Error("a try past 5 days")
	}
	if next, ok := policy.Hold(created, created.Add(time.Hour), 90*time.Second); !ok || !next.Equal(created.Add(time.Hour+90*time.Second)) {
		t.Errorf("a hold: %v %v", next, ok)
	}
	if _, ok := policy.Hold(created, created.Add(5*24*time.Hour-time.Minute), time.Hour); ok {
		t.Error("a hold past 5 days")
	}

	units := sidecar.NewSmtpRetryUnits(settings)
	effectKey := []byte("one message")
	for range settings.RetryUnitsPerMessagePerDay {
		if allowed, _ := units.Allows(effectKey, now); !allowed {
			t.Fatal("refused under the day's units")
		}
		units.Spend(effectKey, now)
	}
	allowed, next := units.Allows(effectKey, now)
	if allowed || !next.Equal(time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("past the day's units: %v until %v", allowed, next)
	}
	if allowed, _ := units.Allows(effectKey, next); !allowed {
		t.Error("the next UTC day refused")
	}
}

// FS-123's sender half, on a fake clock: a message 1 KiB over the host's measured cap, to one CHUNKING and one
// non-CHUNKING MX, sent from a desktop. Check predicts ok for the first and unknown for the second until its mode is
// known, then too_large with both byte counts; the send delivers to the first and stops before MAIL at the second,
// whose outcome alone is too_large with size and cap, its copy naming that domain.
func TestSmtpSenderFs123SenderHalf(t *testing.T) {
	measure := &sidecar.SmtpProverMeasure{
		DataProofBytes: 4 * 1024, DataBytesPerSecond: 512, UnitTime: 5 * time.Second,
		HeadByteCount: 831, HeaderRecordByteCount: 1199, EnvelopeGroupCount: 13,
	}
	proverSettings := sidecartest.DefaultFakeSmtpProverSettings()
	proverSettings.DataProofByteCount = measure.DataProofBytes
	world := newTestSenderWorld(t, &testSenderOptions{prover: proverSettings, measure: measure})
	world.addDomain(testDataDomain, testDataHost, testDataAddress, testDataOnlyScript())
	// the body brings the DATA count 1 KiB past the cap
	message := world.message([]string{"bob@" + testTlsDomain, "dave@" + testDataDomain}, nil, "x\r\n")
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{Message: message.Message, HeaderFromDomain: "n1.root.example", MessageIdDomain: "n1.root.example", Now: world.tls.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := wire.ByteCount(sidecar.SmtpModeData)
	pad := int(measure.DataProofBytes + 1024 - base)
	body := strings.Repeat(strings.Repeat("y", 70)+"\r\n", pad/72) + strings.Repeat("z", pad%72) + "x\r\n"
	message = world.message([]string{"bob@" + testTlsDomain, "dave@" + testDataDomain}, nil, body)

	check, err := world.sender.Check(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if len(check.Domains) != 2 || check.Domains[0].Prediction != sidecar.SmtpCheckUnknown || check.Domains[1].Prediction != sidecar.SmtpCheckUnknown ||
		check.Domains[1].ByteCount != measure.DataProofBytes+1024 || check.Domains[1].CapByteCount != measure.DataProofBytes {
		t.Errorf("before any mode is known: %+v %+v", check.Domains[0], check.Domains[1])
	}
	result := world.send(message)
	if testDomainOutcome(t, result, testTlsDomain).Outcome != sidecar.SmtpOutcomeSent {
		t.Errorf("the CHUNKING domain: %+v", result.Domains)
	}
	tooLarge := testDomainOutcome(t, result, testDataDomain)
	if tooLarge.Outcome != sidecar.SmtpOutcomeTooLarge || tooLarge.ByteCount != measure.DataProofBytes+1024 || tooLarge.CapByteCount != measure.DataProofBytes {
		t.Errorf("the DATA domain: %+v", tooLarge)
	}
	check, err = world.sender.Check(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if check.Domains[0].Mode != sidecar.SmtpModeBdat || check.Domains[0].Prediction != sidecar.SmtpCheckOk {
		t.Errorf("the CHUNKING domain's check: %+v", check.Domains[0])
	}
	if check.Domains[1].Mode != sidecar.SmtpModeData || check.Domains[1].Prediction != sidecar.SmtpCheckTooLarge ||
		check.Domains[1].ByteCount != measure.DataProofBytes+1024 || check.Domains[1].CapByteCount != measure.DataProofBytes {
		t.Errorf("the DATA domain's check: %+v", check.Domains[1])
	}
	if check.Domains[0].ExpectedDelay <= 0 || check.Domains[1].ExpectedDelay <= check.Domains[0].ExpectedDelay {
		t.Errorf("delays %v and %v", check.Domains[0].ExpectedDelay, check.Domains[1].ExpectedDelay)
	}
	dsns := world.mailbox.Dsns()
	if len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte(testDataDomain)) {
		t.Errorf("dsns %s", testDsnText(dsns))
	}
}

// Check prices D-SMTP-16's gate send, 10 recipients and a 4,095-octet header block, at six units under an AES
// measure and five under ChaCha20 (DESIGN-DETAILS 3.2.6), and the table's other rows likewise, but for X: the unit a
// last group's replies past the msg shape's server records add, which the measure does not record.
func TestSmtpCheckPricesTheGateSendInUnits(t *testing.T) {
	aes := &sidecar.SmtpProverMeasure{HeadByteCount: 831, HeaderRecordByteCount: 1199, EnvelopeGroupCount: 13}
	chacha := &sidecar.SmtpProverMeasure{HeadByteCount: 1215, HeaderRecordByteCount: 2239, EnvelopeGroupCount: 19}
	for _, c := range []struct {
		recipients int
		header     uint64
		measure    *sidecar.SmtpProverMeasure
		want       uint64
	}{
		{recipients: 12, header: 831, measure: aes, want: 3},
		{recipients: 3, header: 2000, measure: aes, want: 4},
		{recipients: 10, header: 4095, measure: aes, want: 6},
		{recipients: 50, header: 4095, measure: aes, want: 9},
		{recipients: 100, header: 4095, measure: aes, want: 13},
		{recipients: 100, header: 16383, measure: aes, want: 23},
		{recipients: 10, header: 4095, measure: chacha, want: 5},
		// the table's 8 holds X, a unit for the last group's 13 replies past the msg shape's 12 server records, which no
		// measure field gives: Check prices it at 7 (a reading)
		{recipients: 50, header: 4095, measure: chacha, want: 7},
		{recipients: 100, header: 16383, measure: chacha, want: 15},
	} {
		if got := sidecar.SmtpSendUnitsForTest(c.recipients, c.header, sidecar.SmtpModeBdat, c.measure); got != c.want {
			t.Errorf("%d recipients, %d header octets: %d units, want %d", c.recipients, c.header, got, c.want)
		}
	}
	// DATA's envelope holds DATA too: the gate's header block and 10 recipients, 3 units before the body
	if got := sidecar.SmtpSendUnitsForTest(10, 4095, sidecar.SmtpModeData, aes); got != 6 {
		t.Errorf("DATA: %d units", got)
	}
}

// Check's delay for a send on this host is its units times UnitTime: six units for the gate's send.
func TestSmtpCheckDelayIsUnitsTimesUnitTime(t *testing.T) {
	measure := &sidecar.SmtpProverMeasure{
		DataProofBytes: 1024 * 1024, DataBytesPerSecond: 1000, UnitTime: 5 * time.Second,
		HeadByteCount: 831, HeaderRecordByteCount: 1199, EnvelopeGroupCount: 13,
	}
	world := newTestSenderWorld(t, &testSenderOptions{measure: measure})
	recipients := []string{}
	for i := range 10 {
		recipients = append(recipients, "r"+string(rune('a'+i))+"@"+testTlsDomain)
	}
	// a long Subject brings the signed header block into (3,229, 4,428], where the gate's three header parts lie
	message := world.message(recipients, nil, "body\r\n")
	message.Message = []byte(strings.Replace(string(message.Message), "Subject: A synthetic message", "Subject: "+strings.TrimSpace(strings.Repeat("word ", 400)), 1))
	wire, err := sidecar.AssembleSmtpMessage(&sidecar.SmtpAssembleArgs{Message: message.Message, HeaderFromDomain: "n1.root.example", MessageIdDomain: "n1.root.example", Now: world.tls.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	headerByteCount, err := sidecar.SmtpWireHeaderByteCountForTest(wire)
	if err != nil || headerByteCount <= 3229 || 4428 < headerByteCount {
		t.Fatalf("a header block of %d octets, %v", headerByteCount, err)
	}
	check, err := world.sender.Check(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if delay := check.Domains[0].ExpectedDelay; delay != 6*measure.UnitTime {
		t.Errorf("a delay of %v, want %v", delay, 6*measure.UnitTime)
	}
}

// The DSNs' bytes, for a failure's message.
func testDsnText(dsns []*sidecartest.FakeSmtpDsn) string {
	texts := []string{}
	for _, dsn := range dsns {
		texts = append(texts, string(dsn.Dsn))
	}
	return strings.Join(texts, "\n----\n")
}
