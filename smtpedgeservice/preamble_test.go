// The preamble's path through the composed engine (SMTP-M9-10): bounds, gate, halts and quota, the key
// set, the MX and pre-TLS, the issued values and the session, on the fakes and MxWorld, with no port 25
// and no sleep. The shared fixture, an edge in an MX world, is here too.

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// An engine on the fakes in an MX world, everything the preamble path reads loaded for one network.
type edgeWorld struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	faults   *sidecartest.FaultQueue
	host     *sidecartest.FakeHost
	store    *sidecartest.FakeSmtpEdgeStore
	gate     *sidecartest.FakeSmtpGate
	world    *sidecartest.MxWorld
	mx       *sidecartest.ScriptedMx
	verifier *sidecartest.FakeSmtpProofVerifier
	settings *smtpedgeservice.SmtpEdgeSettings
	service  *smtpedgeservice.SmtpEdgeService

	networkId sidecar.Id
	clientId  sidecar.Id
	sidecarId sidecar.Id

	// Set by a change: start the engine with no store or no verifier.
	storeOff    bool
	verifierOff bool
}

// The world's network, standard and verified, mail enabled two days ago, sending from n1.root.example
// at Pro limits; dest.example's MX a ScriptedMx at 192.0.2.25; the sending address's FCrDNS holding.
// change runs before the engine starts.
func newEdgeWorld(t *testing.T, change func(world *edgeWorld)) *edgeWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	host := sidecartest.NewFakeHost(ctx, clock, faults, nil, nil)
	sidecartest.RegisterSmtpQuotaScripts(host.Redis)
	mxWorldSettings := sidecartest.DefaultMxWorldSettings()
	mxWorldSettings.Clock = clock
	world, err := sidecartest.NewMxWorld(mxWorldSettings)
	if err != nil {
		t.Fatal(err)
	}
	mx, err := sidecartest.NewScriptedMx(testMxHost, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	self := &edgeWorld{
		t:         t,
		ctx:       ctx,
		clock:     clock,
		faults:    faults,
		host:      host,
		store:     sidecartest.NewFakeSmtpEdgeStore(clock, faults),
		gate:      sidecartest.NewFakeSmtpGate(),
		world:     world,
		mx:        mx,
		verifier:  sidecartest.NewFakeSmtpProofVerifier(nil),
		settings:  worldSettings(),
		networkId: sidecar.NewId(),
		clientId:  sidecar.NewId(),
		sidecarId: sidecar.NewId(),
	}
	self.mustWorld(world.SetMx(testRecipientDomain, &sidecar.SmtpMxHost{Preference: 10, Host: testMxHost}))
	self.mustWorld(world.AddMx(testMxHost, testMxAddress, mx))
	self.mustWorld(world.AddMx(testHeloName, testSendingAddress, nil))
	world.SetPtr(testSendingAddress, testHeloName)
	host.Abuse.Set(connect.Id(self.networkId), sidecar.AbuseStandingStandard, true)
	self.gate.SetFacts(self.networkId, &smtpedgeservice.SmtpGateFacts{
		MailEnableTime: clock.Now().Add(-48 * time.Hour),
		Label:          testLabel,
		ReportToken:    testReportToken,
		Limits:         proLimits(),
	})
	self.gate.SetMailSend(self.networkId, self.sidecarId, true)
	self.gate.SetBreaker(&smtpedgeservice.SmtpBreakerState{})
	self.gate.SetCommunityLimits(communityLimits())
	if change != nil {
		change(self)
	}
	var store smtpedgeservice.SmtpEdgeStore = self.store
	if self.storeOff {
		store = nil
	}
	var verifier sidecar.SmtpProofVerifier = self.verifier
	if self.verifierOff {
		verifier = nil
	}
	service, err := smtpedgeservice.NewSmtpEdgeServiceWithDeps(ctx, host.ServiceHost(), store, verifier, &smtpedgeservice.SmtpEdgeDeps{
		Gate:     self.gate,
		Resolver: world,
		Dialer:   world,
		Ptr:      world,
	}, self.settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		service.Close()
		world.Wait()
	})
	self.service = service
	if err := service.AwaitProbes(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := service.AwaitSendingChecks(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := service.TestQuota().Breaker().AwaitMedianReads(ctx, 1); err != nil {
		t.Fatal(err)
	}
	return self
}

func (self *edgeWorld) mustWorld(err error) {
	self.t.Helper()
	if err != nil {
		self.t.Fatal(err)
	}
}

// A preamble the gate and quota pass, to dest.example from n1.root.example.
func (self *edgeWorld) preamble() *protocol.SmtpPreamble {
	return &protocol.SmtpPreamble{
		Version:          sidecar.SmtpPreambleVersion,
		RecipientDomain:  testRecipientDomain,
		RecipientCount:   2,
		MessageId:        "aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example",
		HeaderFromDomain: "n1.root.example",
		DkimSelector:     testSelector,
		MessageByteCount: 4096,
		ProofKeySet:      bytes.Repeat([]byte{0x11}, 32),
	}
}

// Sends preamble as the world's sidecar on a stream, and returns what the engine made of it and the
// result the sidecar read. The outcome is abandoned at the test's end.
func (self *edgeWorld) send(preamble *protocol.SmtpPreamble) (*smtpedgeservice.TestPreambleOutcome, *protocol.SmtpPreambleResult) {
	self.t.Helper()
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(nil, nil)
	defer sidecarEnd.Close()
	type read struct {
		result *protocol.SmtpPreambleResult
		err    error
	}
	reads := make(chan read, 1)
	go func() {
		if err := sidecar.WriteSmtpPreamble(sidecarEnd, preamble, nil); err != nil {
			reads <- read{err: err}
			return
		}
		result, err := sidecar.ReadSmtpPreambleResult(sidecarEnd, nil)
		reads <- read{result: result, err: err}
	}()
	outcome, err := self.service.ServeTestPreamble(self.ctx, self.networkId, self.clientId, self.sidecarId, edgeEnd)
	if err != nil {
		self.t.Fatalf("serve: %v", err)
	}
	self.t.Cleanup(func() { outcome.Abandon(context.Background()) })
	got := <-reads
	if got.err != nil {
		self.t.Fatalf("the sidecar's read: %v", got.err)
	}
	return outcome, got.result
}

// Sends and expects a code, returning the outcome.
func (self *edgeWorld) expect(preamble *protocol.SmtpPreamble, code protocol.SmtpPreambleCode) *smtpedgeservice.TestPreambleOutcome {
	self.t.Helper()
	outcome, result := self.send(preamble)
	if result.GetCode() != uint32(code) {
		self.t.Fatalf("answered %d (%s), want %d", result.GetCode(), outcome.Reason, code)
	}
	return outcome
}

func TestPreambleOkIssuesTheValuesAndReachesTheMx(t *testing.T) {
	w := newEdgeWorld(t, nil)
	if !w.service.Ready() {
		t.Fatal("the world's engine is not ready")
	}
	outcome, result := w.send(w.preamble())
	if result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		t.Fatalf("answered %d (%s)", result.GetCode(), outcome.Reason)
	}
	if len(result.GetSendId()) != smtpedgeservice.SmtpSendIdByteCount {
		t.Fatalf("send_id %x", result.GetSendId())
	}
	ref, err := smtpedgeservice.VerifySmtpXUrRef([]*smtpedgeservice.SmtpXUrRefKey{testXUrRefKey}, result.GetXUrRef(), w.networkId, smtpedgeservice.SmtpXUrRefDay(w.clock.Now()))
	if err != nil {
		t.Fatalf("X-UR-Ref %q: %v", result.GetXUrRef(), err)
	}
	if !bytes.Equal(ref.SendId, result.GetSendId()) {
		t.Fatal("the X-UR-Ref names another send")
	}
	if result.GetFeedbackId() != "n:p:"+testReportToken+":urnetwork" {
		t.Fatalf("Feedback-ID %q", result.GetFeedbackId())
	}
	if result.GetHeloName() != testHeloName || result.GetMxHost() != testMxHost {
		t.Fatalf("helo %q, mx %q", result.GetHeloName(), result.GetMxHost())
	}
	if !slices.Contains(result.GetEhloKeywords(), "STARTTLS") {
		t.Fatalf("keywords %q", result.GetEhloKeywords())
	}
	if len(result.GetDnssecChain()) == 0 {
		t.Fatal("no dnssec_chain for a signed MX")
	}
	sessions := w.verifier.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("%d sessions", len(sessions))
	}
	preamble := sessions[0].Preamble()
	if preamble.EnvelopeDomain != "b.n1.root.example" || preamble.MxHost != testMxHost || preamble.XUrRef != result.GetXUrRef() ||
		preamble.FeedbackId != result.GetFeedbackId() || preamble.HeloName != testHeloName || preamble.RecipientCount != 2 {
		t.Fatalf("the session's preamble %+v", preamble)
	}
	send := outcome.Send
	if !bytes.Equal(send.SendId, result.GetSendId()) || send.NetworkId != w.networkId || send.ClientId != w.clientId ||
		send.MxHost != testMxHost || send.SendingAddress != testSendingAddress || send.XUrRefKeyId != 1 ||
		send.RecipientCount != 2 || send.MessageByteCount != 4096 || !bytes.Equal(send.MessageIdHash, smtpedgeservice.SmtpMessageIdHash(w.preamble().GetMessageId())) {
		t.Fatalf("the send record %+v", send)
	}
	if outcome.MxAddress != testMxAddress || outcome.SendingAddress != testSendingAddress {
		t.Fatalf("dialed %v from %v", outcome.MxAddress, outcome.SendingAddress)
	}
	if value := w.host.Metrics.Value("urnetwork_smtpedge_preambles_total", "ok"); value != 1 {
		t.Fatalf("%v ok preambles counted", value)
	}
	// the edge ran the banner, EHLO with the PTR name, and STARTTLS, and nothing else
	outcome.Abandon(w.ctx)
	w.world.Wait()
	accepted := w.mx.Accepted()
	if len(accepted) != 2 || accepted[0] != "EHLO "+testHeloName || accepted[1] != "STARTTLS" {
		t.Fatalf("the MX accepted %q", accepted)
	}
}

func TestPreambleBoundsDeniedBeforeAnything(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.host.Redis.ResetOpCounts()
	cases := []struct {
		name   string
		change func(preamble *protocol.SmtpPreamble)
	}{
		{name: "another version", change: func(preamble *protocol.SmtpPreamble) { preamble.Version = 2 }},
		{name: "an IP literal recipient domain", change: func(preamble *protocol.SmtpPreamble) { preamble.RecipientDomain = "[192.0.2.1]" }},
		{name: "a one-label recipient domain", change: func(preamble *protocol.SmtpPreamble) { preamble.RecipientDomain = "localhost" }},
		{name: "no recipient", change: func(preamble *protocol.SmtpPreamble) { preamble.RecipientCount = 0 }},
		{name: "a Message-ID with no @", change: func(preamble *protocol.SmtpPreamble) { preamble.MessageId = "aaaa" }},
		{name: "a Message-ID in brackets", change: func(preamble *protocol.SmtpPreamble) { preamble.MessageId = "<a@n1.root.example>" }},
		{name: "a From with a space", change: func(preamble *protocol.SmtpPreamble) { preamble.HeaderFromDomain = "n1 .root.example" }},
		{name: "a selector not of the form", change: func(preamble *protocol.SmtpPreamble) { preamble.DkimSelector = "selector1" }},
		{name: "no message bytes", change: func(preamble *protocol.SmtpPreamble) { preamble.MessageByteCount = 0 }},
		{name: "a short retry-of", change: func(preamble *protocol.SmtpPreamble) { preamble.RetryOfSendId = []byte{1, 2, 3} }},
		{name: "an unknown flag", change: func(preamble *protocol.SmtpPreamble) { preamble.Flags = 8 }},
	}
	for _, c := range cases {
		preamble := w.preamble()
		c.change(preamble)
		outcome, result := w.send(preamble)
		if result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED) || outcome.Reason != "bounds" {
			t.Errorf("%s: answered %d (%s)", c.name, result.GetCode(), outcome.Reason)
		}
	}
	if dials := w.world.Dials(); len(dials) != 0 {
		t.Fatalf("dialed %v", dials)
	}
	if counts := w.host.Redis.OpCounts(); len(counts) != 0 {
		t.Fatalf("redis calls %v", counts)
	}
}

func TestPreambleGateRefusalReachesNoMx(t *testing.T) {
	w := newEdgeWorld(t, func(w *edgeWorld) {
		w.host.Abuse.SetStanding(connect.Id(w.networkId), sidecar.AbuseStandingProbation)
	})
	w.host.Redis.ResetOpCounts()
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED)
	if dials := w.world.Dials(); len(dials) != 0 {
		t.Fatalf("dialed %v", dials)
	}
	if counts := w.host.Redis.OpCounts(); len(counts) != 0 {
		t.Fatalf("redis calls %v", counts)
	}
}

func TestPreambleKeysDialsNothingAndReleasesTheReservation(t *testing.T) {
	keySet := bytes.Repeat([]byte{0x11}, 32)
	w := newEdgeWorld(t, func(w *edgeWorld) {
		w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{RefuseKeySets: [][]byte{keySet}})
		facts, _ := w.gate.Facts(w.networkId)
		facts.Limits.Limits[smtpedgeservice.SmtpLimitConcurrentConnections] = 1
		w.gate.SetFacts(w.networkId, facts)
	})
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS)
	if dials := w.world.Dials(); len(dials) != 0 {
		t.Fatalf("KEYS dialed %v", dials)
	}
	if value := w.host.Metrics.Value("urnetwork_smtpedge_preambles_total", "keys"); value != 1 {
		t.Fatalf("%v keys preambles counted", value)
	}
	// the one concurrency slot came back, so a preamble under another key set passes
	preamble := w.preamble()
	preamble.ProofKeySet = bytes.Repeat([]byte{0x22}, 32)
	w.expect(preamble, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
}

func TestPreambleSessionRefusingTheKeySetAnswersKeys(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.verifier.RefuseSessions(sidecar.ErrSmtpProofKeySet)
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS)
	w.world.Wait()
	if transactions := w.mx.Transactions(); len(transactions) != 0 {
		t.Fatalf("the MX took %d transactions", len(transactions))
	}
}

func TestPreambleHaltedLabelRefusedWhileOtherLabelsPass(t *testing.T) {
	w := newEdgeWorld(t, nil)
	if err := w.service.TestQuota().ApplyHalt(w.ctx, &smtpedgeservice.SmtpHalt{
		HaltId:    sidecar.NewId(),
		NetworkId: w.networkId,
		Label:     "otter-4821",
		Trigger:   smtpedgeservice.SmtpHaltTriggerLabelComplaint,
		StartTime: w.clock.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	burner := func(label string) *protocol.SmtpPreamble {
		preamble := w.preamble()
		preamble.HeaderFromDomain = label + ".n1.root.example"
		preamble.MessageId = "aaaaaaaaaaaaaaaaaaaaaaaaaa@" + label + ".n1.root.example"
		preamble.Flags = sidecar.SmtpFlagBurner
		return preamble
	}
	halted := w.expect(burner("otter-4821"), protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED)
	if halted.Result.GetRetryAfterMs() == 0 || uint32((24*time.Hour).Milliseconds()) < halted.Result.GetRetryAfterMs() {
		t.Fatalf("retry after %d ms", halted.Result.GetRetryAfterMs())
	}
	other := w.expect(burner("heron-1234"), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if !strings.HasPrefix(other.Result.GetFeedbackId(), "b:p:"+testReportToken) {
		t.Fatalf("a burner's Feedback-ID %q", other.Result.GetFeedbackId())
	}
	other.Abandon(w.ctx)
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
}

func TestPreambleHaltsReloadFromTheStoreAndOutliveRedis(t *testing.T) {
	w := newEdgeWorld(t, nil)
	if err := w.store.SetHalt(w.ctx, &smtpedgeservice.SmtpHalt{
		HaltId:    sidecar.NewId(),
		NetworkId: w.networkId,
		Trigger:   smtpedgeservice.SmtpHaltTriggerCommunityComplaint,
		StartTime: w.clock.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(w.settings.HaltReloadInterval)
	if err := w.service.AwaitProbes(w.ctx, 2); err != nil {
		t.Fatal(err)
	}
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED)
	// Redis forgets the flag; the memory holds it, and the next probe writes it again
	w.host.Redis.LoseEverything()
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED)
	w.clock.Advance(w.settings.HaltReloadInterval)
	if err := w.service.AwaitProbes(w.ctx, 3); err != nil {
		t.Fatal(err)
	}
	value, ok := w.host.Redis.Dump()["{smq_"+w.networkId.String()+"}"]
	if !ok || !(bytes.HasPrefix(value, []byte("h\x00")) || bytes.Contains(value, []byte("\x00h\x00"))) {
		t.Fatalf("the halt was not written again: %q", value)
	}
}

// §22.5: the preamble path asks Postgres nothing, here the fake store that stands where Postgres does,
// and runs one script for a network outside Community.
func TestPreamblePathAsksNoStoreAndOneScript(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.store.ResetOpCounts()
	w.host.Redis.ResetOpCounts()
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if counts := w.store.OpCounts(); len(counts) != 0 {
		t.Fatalf("store calls %v", counts)
	}
	if counts := w.host.Redis.OpCounts(); len(counts) != 1 || counts["script:smtp_quota_reserve"] != 1 {
		t.Fatalf("redis calls %v", counts)
	}
}

func TestPreambleCommunityRunsTheFleetCounters(t *testing.T) {
	w := newEdgeWorld(t, func(w *edgeWorld) {
		facts, _ := w.gate.Facts(w.networkId)
		facts.Limits = communityLimits()
		w.gate.SetFacts(w.networkId, facts)
	})
	w.host.Redis.ResetOpCounts()
	outcome := w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	if !strings.HasPrefix(outcome.Result.GetFeedbackId(), "n:c:") {
		t.Fatalf("Feedback-ID %q", outcome.Result.GetFeedbackId())
	}
	counts := w.host.Redis.OpCounts()
	if counts["script:smtp_quota_reserve"] != 1 || counts["script:smtp_hour_count"] != 2 {
		t.Fatalf("redis calls %v", counts)
	}
}

func TestPreambleDestinationCapRefusesCommunityTryLater(t *testing.T) {
	w := newEdgeWorld(t, func(w *edgeWorld) {
		facts, _ := w.gate.Facts(w.networkId)
		facts.Limits = communityLimits()
		facts.Limits.Limits[smtpedgeservice.SmtpLimitDestinationConnectionsPerHour] = 0
		w.gate.SetFacts(w.networkId, facts)
	})
	outcome := w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
	if outcome.Reason != "destination" {
		t.Fatalf("reason %q", outcome.Reason)
	}
	if dials := w.world.Dials(); len(dials) != 0 {
		t.Fatalf("dialed %v", dials)
	}
	if value := w.host.Metrics.Value("urnetwork_smtpedge_breaker_trips_total", "destination"); value != 1 {
		t.Fatalf("%v destination trips", value)
	}
	// the one concurrency slot came back with the reservation
	facts, _ := w.gate.Facts(w.networkId)
	facts.Limits.Limits[smtpedgeservice.SmtpLimitDestinationConnectionsPerHour] = 200
	w.gate.SetFacts(w.networkId, facts)
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
}

func TestPreambleNoMxAndNoTlsReleaseTheReservation(t *testing.T) {
	w := newEdgeWorld(t, func(w *edgeWorld) {
		facts, _ := w.gate.Facts(w.networkId)
		facts.Limits.Limits[smtpedgeservice.SmtpLimitConcurrentConnections] = 1
		w.gate.SetFacts(w.networkId, facts)
		w.mustWorld(w.world.SetNullMx("null.example"))
		plain, err := sidecartest.NewScriptedMx("mx.plain.example", &sidecartest.MxScript{NoStartTls: true, Keywords: []string{"PIPELINING"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.mustWorld(w.world.SetMx("plain.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.plain.example"}))
		w.mustWorld(w.world.AddMx("mx.plain.example", netip.MustParseAddr("192.0.2.26"), plain))
	})
	preamble := w.preamble()
	preamble.RecipientDomain = "null.example"
	w.expect(preamble, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX)
	preamble.RecipientDomain = "plain.example"
	w.expect(preamble, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS)
	// neither held the one slot, and neither debited a unit
	w.expect(w.preamble(), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK)
	for key, value := range w.host.Redis.Dump() {
		if strings.HasPrefix(key, "{smq_") && (bytes.HasPrefix(value, []byte("c:")) || bytes.Contains(value, []byte("\x00c:"))) {
			t.Fatalf("a unit debited: %q", value)
		}
	}
}

func BenchmarkSmtpGate(b *testing.B) {
	gate := sidecartest.NewFakeSmtpGate()
	abuse := sidecartest.NewFakeAbuseGate()
	networkId := sidecar.NewId()
	sidecarId := sidecar.NewId()
	now := sidecartest.DefaultClockStart()
	abuse.Set(connect.Id(networkId), sidecar.AbuseStandingStandard, true)
	gate.SetFacts(networkId, &smtpedgeservice.SmtpGateFacts{MailEnableTime: now.Add(-48 * time.Hour), Label: testLabel, ReportToken: testReportToken, Limits: proLimits()})
	gate.SetMailSend(networkId, sidecarId, true)
	gate.SetBreaker(&smtpedgeservice.SmtpBreakerState{})
	settings := worldSettings()
	request := &smtpedgeservice.SmtpGateRequest{NetworkId: networkId, SidecarId: sidecarId, HeaderFromDomain: "n1.root.example"}
	b.ReportAllocs()
	for b.Loop() {
		if decision := smtpedgeservice.CheckSmtpGateForTest(gate, abuse, request, now, settings); decision.Code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
			b.Fatalf("answered %d", decision.Code)
		}
	}
	if counts := gate.OpCounts(); counts["Facts"] == 0 {
		b.Fatal("the gate was not asked")
	}
}
