// The sidecar's own SmtpSender (SMTP-M9-07, SMTP-M9-08) through the real engine (SMTP-M9-13), S6's T2 leg on the
// engine (SMTP-M9-31): the driver's dialer opens each stream as the ur/smtpedge listener hands one over, its parts
// land on the engine's SMTP_PROOF and SMTP_HANDSHAKE handlers, and its SmtpOutcome on AcceptOutcome. The engine's gate,
// quota, issued values and send log run as in production, on the fakes, and a session that holds every record past
// the handshake's until a part covers it shows no record reaches the MX before its part. TL4 passes here by the
// message's own allowance, the only way an unauthenticated ScriptedMx can be sent to, so the outcome carries EX4's
// label; the TLS levels themselves are smtp_tls_policy_test.go's.

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// The sidecar's end of a stream the engine serves.
type testEngineStream struct {
	net.Conn
	w *edgeWorld
}

func (self *testEngineStream) ProofChannel(sendId []byte) sidecar.SmtpProofChannel {
	return &testProofChannel{w: self.w, sendId: bytes.Clone(sendId)}
}

func (self *testEngineStream) SendOutcome(ctx context.Context, outcome *protocol.SmtpOutcome) error {
	body, err := proto.Marshal(outcome)
	if err != nil {
		return err
	}
	return self.w.service.AcceptOutcome(self.w.clientId, body)
}

func (self *testEngineStream) Abort() error {
	return self.Conn.Close()
}

// A sidecar.SmtpEdgeDialer onto the engine: each stream served as the listener would one admitted on the world's
// ticket.
type testEngineDialer struct {
	w       *edgeWorld
	serving sync.WaitGroup
}

func (self *testEngineDialer) DialSmtpEdge(ctx context.Context) (sidecar.SmtpEdgeStream, error) {
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	self.serving.Add(1)
	go func() {
		defer self.serving.Done()
		self.w.service.ServeTestStream(self.w.networkId, self.w.clientId, self.w.sidecarId, edgeEnd)
	}()
	return &testEngineStream{Conn: sidecarEnd, w: self.w}, nil
}

// An in-memory keychain namespace.
type testEngineSecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

func (self *testEngineSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *testEngineSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = bytes.Clone(value)
	return nil
}

func (self *testEngineSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *testEngineSecrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.values {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
}

// POST /smtp/dkim-keys answering every publish.
type testEnginePublisher struct{}

func (self testEnginePublisher) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	result := &sidecar.SmtpDkimKeysResult{}
	for _, publish := range args.Publish {
		result.Published = append(result.Published, publish.Selector)
	}
	return result, nil
}

// A sender of the world's network on the fake prover, whose MX the message's own allowance lets go at TL4.
func newTestEngineSender(t *testing.T, w *edgeWorld, dialer sidecar.SmtpEdgeDialer) (*sidecar.SmtpSender, *sidecartest.FakeSmtpProver, *captureLogger) {
	t.Helper()
	settings := sidecar.DefaultSmtpSenderSettings()
	store := sidecartest.NewFakeStore()
	anchors, err := sidecar.NewSmtpDnssecAnchors(w.world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	zone := sidecartest.NewFakeMailZone(w.clock)
	pins := sidecar.NewSmtpPinStore(store.Root(), settings, w.clock, nil)
	policy := sidecar.NewSmtpTlsPolicy(sidecar.NewSmtpDane(anchors, w.clock, nil),
		sidecar.NewSmtpMtaSts(zone, w.world.MtaStsTransport(), store.Root(), settings, w.clock), pins,
		sidecar.NewSmtpTlsAllowanceStore(store.Root(), settings, w.clock), nil, zone, nil, settings, w.clock)
	prover := sidecartest.NewFakeSmtpProver(nil)
	senderLog := &captureLogger{}
	sender, err := sidecar.NewSmtpSender(&sidecar.SmtpSenderArgs{
		Dialer: dialer, Prover: prover, Policy: policy, Pins: pins,
		Dkim:    sidecar.NewSmtpDkimKeys(&testEngineSecrets{values: map[string][]byte{}}, testEnginePublisher{}, settings, w.clock, nil),
		Mailbox: sidecartest.NewFakeSmtpMailbox(nil), Settings: settings, Clock: w.clock, Log: senderLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.Close)
	return sender, prover, senderLog
}

// One message from the world's network to bob at dest.example, its MX let go at TL4 by the message's own allowance.
func testEngineMessage(w *edgeWorld, effectKey byte) *sidecar.SmtpOutboundMessage {
	return &sidecar.SmtpOutboundMessage{
		EffectKey:  bytes.Repeat([]byte{effectKey}, 32),
		SendId:     sidecar.NewId(),
		Sender:     "bounce-1@b." + testLabel + "." + testRoot,
		Recipients: []string{"bob@" + testRecipientDomain},
		Message: []byte("From: alice@" + testLabel + "." + testRoot + "\r\nTo: bob@" + testRecipientDomain + "\r\nSubject: through the engine\r\n" +
			"Message-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@" + testLabel + "." + testRoot + ">\r\n\r\nA body line.\r\n"),
		// the scripted MX's certificate is its own, so only the message's allowance lets it through
		Tl4Domains: []string{testRecipientDomain},
		CreateTime: w.clock.Now(),
	}
}

// A world whose network's report token is in its one spelling, 16 octets' base32, as the root holds Feedback-ID to.
func newTestEngineWorld(t *testing.T, change func(world *edgeWorld)) *edgeWorld {
	t.Helper()
	return newEdgeWorld(t, func(world *edgeWorld) {
		world.gate.SetFacts(world.networkId, &smtpedgeservice.SmtpGateFacts{
			MailEnableTime: world.clock.Now().Add(-48 * time.Hour),
			Label:          testLabel,
			ReportToken:    strings.Repeat("a", 26),
			Limits:         proLimits(),
		})
		if change != nil {
			change(world)
		}
	})
}

// A halt the ladder applies reaches the sender's next preamble within one HaltReloadInterval (§14.8's 60 s), and the
// sender holds the message as deferred with the halt's wait, never failed.
func TestSmtpSenderHaltReachesTheNextSendWithinAReload(t *testing.T) {
	w := newTestEngineWorld(t, nil)
	dialer := &testEngineDialer{w: w}
	sender, _, _ := newTestEngineSender(t, w, dialer)
	result, err := sender.Send(context.Background(), testEngineMessage(w, 0x41))
	if err != nil || result.Domains[0].Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("before the halt: %+v, %v", result, err)
	}
	dialer.serving.Wait()
	ladder, err := smtpedgeservice.NewSmtpHaltLadder(w.host.ServiceHost(), &smtpedgeservice.SmtpHaltLadderDeps{Store: w.store, Lookups: w.store, Halts: w.store, Sink: sidecartest.NewFakeSmtpAbuseSink()}, w.settings)
	if err != nil {
		t.Fatal(err)
	}
	complaint := &smtpedgeservice.SmtpComplaint{
		ComplaintId:   sidecar.NewId(),
		NetworkId:     w.networkId,
		Type:          smtpedgeservice.SmtpComplaintTypeFraud,
		ArrivalTime:   w.clock.Now(),
		Domain:        testLabel + "." + testRoot,
		MessageIdHash: smtpedgeservice.SmtpMessageIdHash("<qvsc2zbwd5c3m5rbnvzxjzpnay@" + testLabel + "." + testRoot + ">"),
		JoinResult:    string(smtpedgeservice.SmtpConfidenceHigh),
	}
	if err := w.store.InsertComplaint(w.ctx, complaint); err != nil {
		t.Fatal(err)
	}
	if halts, err := ladder.Apply(w.ctx, &smtpedgeservice.SmtpHaltEvent{Kind: smtpedgeservice.SmtpHaltEventComplaint, NetworkId: w.networkId, Time: complaint.ArrivalTime, Complaint: complaint}); err != nil || len(halts) != 1 {
		t.Fatalf("halts %v, %v", halts, err)
	}
	if w.settings.HaltReloadInterval > time.Minute {
		t.Fatalf("a reload interval of %v passes §14.8's 60 s", w.settings.HaltReloadInterval)
	}
	w.clock.Advance(w.settings.HaltReloadInterval)
	w.awaitProbes(2)
	held := testEngineMessage(w, 0x42)
	result, err = sender.Send(context.Background(), held)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter <= 0 {
		t.Errorf("a halted send: %+v", outcome)
	}
	if len(w.mx.Transactions()) != 1 {
		t.Errorf("%d transactions", len(w.mx.Transactions()))
	}
}

func TestSmtpSenderThroughTheEngine(t *testing.T) {
	w := newEdgeWorld(t, func(world *edgeWorld) {
		world.verifier = sidecartest.NewFakeSmtpProofVerifier(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
		// a report token in its one spelling, 16 octets' base32, as the root holds Feedback-ID to
		world.gate.SetFacts(world.networkId, &smtpedgeservice.SmtpGateFacts{
			MailEnableTime: world.clock.Now().Add(-48 * time.Hour),
			Label:          testLabel,
			ReportToken:    strings.Repeat("a", 26),
			Limits:         proLimits(),
		})
	})
	// a connection that fails ends at the engine's Close, which the world's cleanup runs; one that sends ends at the
	// MX's close after QUIT, which the end of this test waits for
	dialer := &testEngineDialer{w: w}
	settings := sidecar.DefaultSmtpSenderSettings()
	store := sidecartest.NewFakeStore()
	anchors, err := sidecar.NewSmtpDnssecAnchors(w.world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	zone := sidecartest.NewFakeMailZone(w.clock)
	pins := sidecar.NewSmtpPinStore(store.Root(), settings, w.clock, nil)
	policy := sidecar.NewSmtpTlsPolicy(sidecar.NewSmtpDane(anchors, w.clock, nil),
		sidecar.NewSmtpMtaSts(zone, w.world.MtaStsTransport(), store.Root(), settings, w.clock), pins,
		sidecar.NewSmtpTlsAllowanceStore(store.Root(), settings, w.clock), nil, zone, nil, settings, w.clock)
	mailbox := sidecartest.NewFakeSmtpMailbox(nil)
	prover := sidecartest.NewFakeSmtpProver(nil)
	senderLog := &captureLogger{}
	sender, err := sidecar.NewSmtpSender(&sidecar.SmtpSenderArgs{
		Dialer: dialer, Prover: prover, Policy: policy, Pins: pins,
		Dkim:    sidecar.NewSmtpDkimKeys(&testEngineSecrets{values: map[string][]byte{}}, testEnginePublisher{}, settings, w.clock, nil),
		Mailbox: mailbox, Settings: settings, Clock: w.clock, Log: senderLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	message := &sidecar.SmtpOutboundMessage{
		EffectKey:  bytes.Repeat([]byte{0x3c}, 32),
		SendId:     sidecar.NewId(),
		Sender:     "bounce-1@b." + testLabel + "." + testRoot,
		Recipients: []string{"bob@" + testRecipientDomain},
		Message: []byte("From: alice@" + testLabel + "." + testRoot + "\r\nTo: bob@" + testRecipientDomain + "\r\nSubject: through the engine\r\n" +
			"Message-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@" + testLabel + "." + testRoot + ">\r\n\r\nA body line.\r\n"),
		// the scripted MX's certificate is its own, so only the message's allowance lets it through
		Tl4Domains: []string{testRecipientDomain},
		CreateTime: w.clock.Now(),
	}
	result, err := sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	outcome := result.Domains[0]
	if outcome.Outcome != sidecar.SmtpOutcomeSent || outcome.TlsLevel != sidecar.SmtpTlsLevelUnauthenticated || outcome.TlsLevel.Label() == "" {
		t.Fatalf("outcome %+v; the sender logged %q; the prover saw %+v", outcome, senderLog.Lines(), prover.Sends())
	}
	transactions := w.mx.Transactions()
	if len(transactions) != 1 || transactions[0].Sender != "<bounce-1@b."+testLabel+"."+testRoot+">" {
		t.Fatalf("transactions %+v", transactions)
	}
	// the engine issued the X-UR-Ref and Feedback-ID the message carries, and DKIM signed them
	if !bytes.Contains(transactions[0].Message, []byte("X-UR-Ref: 1.")) || !bytes.Contains(transactions[0].Message, []byte("Feedback-ID: n:")) ||
		!bytes.Contains(transactions[0].Message, []byte("DKIM-Signature: ")) {
		t.Errorf("the message as taken: %s", transactions[0].Message)
	}
	dialer.serving.Wait()
	// no record reached the MX before a part covered it
	sessions := w.verifier.Sessions()
	if len(sessions) != 1 || !sessions[0].MailForwarded() {
		t.Fatalf("%d sessions", len(sessions))
	}
	credit, released := uint64(3), uint64(0)
	for _, call := range sessions[0].Calls() {
		if call.Method == "VerifyPart" && call.Err == nil && call.Part.FirstRecord <= call.Part.LastRecord {
			credit += call.Part.LastRecord - call.Part.FirstRecord + 1
		}
		released += uint64(len(call.Released))
		if credit < released {
			t.Fatalf("%d records released on %d of credit at a %s", released, credit, call.Method)
		}
	}
}
