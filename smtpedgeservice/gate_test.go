// The send gate's rows (SMTP-M9-10, §14.5, §14.7, §21.5), each with its refusal, one test each, on
// FakeSmtpGate and FakeAbuseGate: memory only, a miss answering TRY_LATER and asking for a load. A suspension's
// HALTED (QD-1124) also runs through the engine and the sidecar's own sender.

package smtpedgeservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// One network loaded in every fact the gate reads, standard and verified at Pro.
type gateWorld struct {
	t         *testing.T
	gate      *sidecartest.FakeSmtpGate
	abuse     *sidecartest.FakeAbuseGate
	settings  *smtpedgeservice.SmtpEdgeSettings
	now       time.Time
	networkId sidecar.Id
	sidecarId sidecar.Id
	facts     *smtpedgeservice.SmtpGateFacts
}

func newGateWorld(t *testing.T) *gateWorld {
	now := sidecartest.DefaultClockStart()
	self := &gateWorld{
		t:         t,
		gate:      sidecartest.NewFakeSmtpGate(),
		abuse:     sidecartest.NewFakeAbuseGate(),
		settings:  worldSettings(),
		now:       now,
		networkId: sidecar.NewId(),
		sidecarId: sidecar.NewId(),
		facts: &smtpedgeservice.SmtpGateFacts{
			MailEnableTime:  now.Add(-48 * time.Hour),
			Label:           testLabel,
			Aliases:         []string{"quiet-net"},
			ScopeLabels:     []string{"sales"},
			VerifiedDomains: []string{"brand.example"},
			ReportToken:     testReportToken,
			Limits:          proLimits(),
		},
	}
	self.abuse.Set(connect.Id(self.networkId), sidecar.AbuseStandingStandard, true)
	self.gate.SetFacts(self.networkId, self.facts)
	self.gate.SetMailSend(self.networkId, self.sidecarId, true)
	self.gate.SetBreaker(&smtpedgeservice.SmtpBreakerState{})
	self.gate.SetCommunityLimits(communityLimits())
	return self
}

// Reloads the facts after a test changed them.
func (self *gateWorld) reload() {
	self.gate.SetFacts(self.networkId, self.facts)
}

func (self *gateWorld) check(from string, flags uint32) *smtpedgeservice.SmtpGateDecision {
	return smtpedgeservice.CheckSmtpGateForTest(self.gate, self.abuse, &smtpedgeservice.SmtpGateRequest{
		NetworkId:        self.networkId,
		SidecarId:        self.sidecarId,
		HeaderFromDomain: from,
		Flags:            flags,
	}, self.now, self.settings)
}

func (self *gateWorld) expect(from string, flags uint32, code protocol.SmtpPreambleCode, reason string) *smtpedgeservice.SmtpGateDecision {
	self.t.Helper()
	decision := self.check(from, flags)
	if decision.Code != code || decision.Reason != reason {
		self.t.Fatalf("from %s: answered %d %q, want %d %q", from, decision.Code, decision.Reason, code, reason)
	}
	return decision
}

func TestSmtpGatePassesANetworksOwnMail(t *testing.T) {
	g := newGateWorld(t)
	decision := g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	if decision.EnvelopeDomain != "b.n1.root.example" || decision.Tier != "pro" || decision.Burner || decision.Label != "" || decision.Community {
		t.Fatalf("decision %+v", decision)
	}
	if decision.Limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay] != 200 {
		t.Fatalf("limits %v", decision.Limits.Limits)
	}
}

func TestSmtpGateUnloadedAnswersTryLaterAndAsksForALoad(t *testing.T) {
	g := newGateWorld(t)
	g.gate.Unload(g.networkId)
	decision := g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "unloaded")
	if decision.RetryAfter != g.settings.GateRetryTimeout {
		t.Fatalf("retry after %v", decision.RetryAfter)
	}
	if g.gate.LoadAsks(g.networkId) == 0 {
		t.Fatal("a miss asked for no load")
	}
	g.reload()
	g.abuse.Unload(connect.Id(g.networkId))
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "unloaded")
	g.abuse.Set(connect.Id(g.networkId), sidecar.AbuseStandingStandard, true)
	g.gate.SetBreaker(nil)
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "unloaded")
}

func TestSmtpGateColdNetworkAsksForEveryLoadAtOnce(t *testing.T) {
	g := newGateWorld(t)
	g.gate.Unload(g.networkId)
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "unloaded")
	// the facts and the mail_send state each asked for theirs in one preamble
	if asks := g.gate.LoadAsks(g.networkId); asks != 2 {
		t.Fatalf("%d loads asked", asks)
	}
}

func TestSmtpGateDeniesProbation(t *testing.T) {
	g := newGateWorld(t)
	g.abuse.SetStanding(connect.Id(g.networkId), sidecar.AbuseStandingProbation)
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "standing")
}

// §21.7's mail halt (QD-1124): a suspended network's preamble is held at its sender with the setting's wait, never
// failed, a burner's From as its network's.
func TestSmtpGateHaltsSuspended(t *testing.T) {
	g := newGateWorld(t)
	g.settings.SuspendedRetryTimeout = 90 * time.Minute
	g.abuse.SetStanding(connect.Id(g.networkId), sidecar.AbuseStandingSuspended)
	for _, c := range []struct {
		from  string
		flags uint32
	}{
		{from: "n1.root.example"},
		{from: "otter-4821.n1.root.example", flags: sidecar.SmtpFlagBurner},
	} {
		decision := g.expect(c.from, c.flags, protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, "suspended")
		if decision.RetryAfter != 90*time.Minute {
			t.Fatalf("from %s: retry after %v, want the setting's", c.from, decision.RetryAfter)
		}
	}
}

// A lift restores mail at once (owner decision 531): the next preamble after the standing goes back to standard
// passes, with nothing of the suspension kept.
func TestSmtpGateLiftedSuspensionSendsAtTheNextPreamble(t *testing.T) {
	g := newGateWorld(t)
	g.abuse.SetStanding(connect.Id(g.networkId), sidecar.AbuseStandingSuspended)
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, "suspended")
	g.abuse.SetStanding(connect.Id(g.networkId), sidecar.AbuseStandingStandard)
	decision := g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	if decision.Standing != sidecar.AbuseStandingStandard || decision.RetryAfter != 0 {
		t.Fatalf("decision %+v", decision)
	}
}

// The edge writes no smtp_halt row for a suspension, so the halt ladder's 3 network halts in 30 days does not count
// it (QD-1124), and the HALTED goes out before any MX is dialed or Redis asked.
func TestPreambleSuspendedHaltsWithNoHaltRow(t *testing.T) {
	w := newEdgeWorld(t, func(w *edgeWorld) {
		w.host.Abuse.SetStanding(connect.Id(w.networkId), sidecar.AbuseStandingSuspended)
	})
	w.host.Redis.ResetOpCounts()
	outcome, result := w.send(w.preamble())
	if result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED) || outcome.Reason != "suspended" {
		t.Fatalf("answered %d (%s)", result.GetCode(), outcome.Reason)
	}
	if want := uint32(w.settings.SuspendedRetryTimeout.Milliseconds()); result.GetRetryAfterMs() != want {
		t.Fatalf("retry_after_ms %d, want %d", result.GetRetryAfterMs(), want)
	}
	if dials := w.world.Dials(); len(dials) != 0 {
		t.Fatalf("dialed %v", dials)
	}
	if counts := w.host.Redis.OpCounts(); len(counts) != 0 {
		t.Fatalf("redis calls %v", counts)
	}
	halts, err := w.store.ActiveHalts(w.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(halts) != 0 {
		t.Fatalf("a suspension wrote halts %+v", halts)
	}
}

// The sidecar's own sender holds a suspended network's message for the gate's wait, deferred and never failed, and
// nothing reaches an MX; once the suspension lifts, the held message sends at its next try.
func TestSmtpSenderHoldsASuspendedNetworksMail(t *testing.T) {
	w := newTestEngineWorld(t, func(world *edgeWorld) {
		world.host.Abuse.SetStanding(connect.Id(world.networkId), sidecar.AbuseStandingSuspended)
	})
	dialer := &testEngineDialer{w: w}
	sender, _, _ := newTestEngineSender(t, w, dialer)
	message := testEngineMessage(w, 0x43)
	result, err := sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter != w.settings.SuspendedRetryTimeout {
		t.Fatalf("a suspended send: %+v", outcome)
	}
	if dials := w.world.Dials(); len(dials) != 0 {
		t.Fatalf("dialed %v", dials)
	}
	w.host.Abuse.SetStanding(connect.Id(w.networkId), sidecar.AbuseStandingStandard)
	// the queue holds the message to its retry time, whatever happens meanwhile
	result, err = sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeDeferred {
		t.Fatalf("before the retry time: %+v", outcome)
	}
	w.clock.Advance(w.settings.SuspendedRetryTimeout)
	result, err = sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("after the lift: %+v", outcome)
	}
	dialer.serving.Wait()
	if len(w.mx.Transactions()) != 1 {
		t.Fatalf("%d transactions", len(w.mx.Transactions()))
	}
}

func TestSmtpGateDeniesAStandingThisBuildDoesNotKnow(t *testing.T) {
	g := newGateWorld(t)
	g.abuse.SetStanding(connect.Id(g.networkId), sidecar.AbuseStanding("exalted"))
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "standing")
}

func TestSmtpGateRestrictedSendsAtCommunityCaps(t *testing.T) {
	g := newGateWorld(t)
	g.abuse.SetStanding(connect.Id(g.networkId), sidecar.AbuseStandingRestricted)
	decision := g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	if !decision.Community || decision.Tier != "pro" {
		t.Fatalf("decision %+v", decision)
	}
	if got := decision.Limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay]; got != 5 {
		t.Fatalf("restricted connections per day %d, want Community's 5", got)
	}
	if got := decision.Limits.Limits[smtpedgeservice.SmtpLimitConcurrentConnections]; got != 1 {
		t.Fatalf("restricted concurrency %d", got)
	}
	g.gate.SetCommunityLimits(nil)
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "unloaded")
}

func TestSmtpGateDeniesAnUnverifiedNetwork(t *testing.T) {
	g := newGateWorld(t)
	g.abuse.SetVerified(connect.Id(g.networkId), false)
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "unverified")
}

func TestSmtpGateDeniesMailNeverEnabled(t *testing.T) {
	g := newGateWorld(t)
	g.facts.MailEnableTime = time.Time{}
	g.reload()
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "mail_off")
}

func TestSmtpGateHoldsMailUntilADayAfterEnable(t *testing.T) {
	g := newGateWorld(t)
	g.facts.MailEnableTime = g.now.Add(-23 * time.Hour)
	g.reload()
	decision := g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "mail_new")
	if decision.RetryAfter != time.Hour {
		t.Fatalf("retry after %v, want the hour left", decision.RetryAfter)
	}
}

func TestSmtpGateDeniesWithoutMailSend(t *testing.T) {
	g := newGateWorld(t)
	g.gate.SetMailSend(g.networkId, g.sidecarId, false)
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "mail_send")
	g.gate.SetMailSendDecision(g.networkId, g.sidecarId, sidecar.AclDecision{Reason: sidecar.AclReasonAbuseHalt})
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "mail_send")
}

func TestSmtpGateSpentNetworkAnswersQuota(t *testing.T) {
	g := newGateWorld(t)
	g.gate.SetMailSendDecision(g.networkId, g.sidecarId, sidecar.AclDecision{Reason: sidecar.AclReasonQuota})
	decision := g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "spent")
	if decision.RetryAfter != g.settings.SpentRetryTimeout {
		t.Fatalf("retry after %v", decision.RetryAfter)
	}
}

func TestSmtpGateDeniesAFromInAnotherNetworksZone(t *testing.T) {
	g := newGateWorld(t)
	g.expect("n2.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	g.expect("root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	g.expect("sub.n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	g.expect("otter-4821.n2.root.example", sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	g.expect("other.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
}

func TestSmtpGatePassesAliasScopeAndVerifiedDomain(t *testing.T) {
	g := newGateWorld(t)
	for _, from := range []string{"quiet-net.root.example", "sales.n1.root.example", "brand.example"} {
		decision := g.expect(from, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
		if decision.EnvelopeDomain != "b.n1.root.example" {
			t.Fatalf("from %s: envelope %s", from, decision.EnvelopeDomain)
		}
	}
}

func TestSmtpGateHoldsTheBurnerFlagToABurnersFrom(t *testing.T) {
	g := newGateWorld(t)
	// a burner's From as network mail would get network mail's Feedback-ID class
	g.expect("otter-4821.n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	g.expect("n1.root.example", sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	g.expect("otter.n1.root.example", sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	g.expect("otter-4821.brand.example", sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	for _, from := range []string{"otter-4821.n1.root.example", "otter-4821.quiet-net.root.example", "otter-4821.sales.n1.root.example"} {
		decision := g.expect(from, sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
		if !decision.Burner || decision.Label != "otter-4821" {
			t.Fatalf("from %s: decision %+v", from, decision)
		}
	}
}

func TestSmtpGateScreensABurnersWord(t *testing.T) {
	g := newGateWorld(t)
	// a brand no domain of the network unlocks, and URnetwork's own name, which nothing unlocks
	g.expect("paypal-1234.n1.root.example", sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "screen")
	g.expect("urnetwork-1234.n1.root.example", sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "screen")
	g.expect("heron-1234.n1.root.example", sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	// a live name is never screened again: the network's own label sends whatever it reads as
	g.facts.Label = "paypal"
	g.reload()
	g.expect("paypal.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
}

func TestSmtpGateBreakerLevels(t *testing.T) {
	cases := []struct {
		level    smtpedgeservice.SmtpBreakerLevel
		tier     string
		standing sidecar.AbuseStanding
		code     protocol.SmtpPreambleCode
	}{
		{level: smtpedgeservice.SmtpBreakerLevelRestrict, tier: "pro", standing: sidecar.AbuseStandingRestricted, code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED},
		{level: smtpedgeservice.SmtpBreakerLevelRestrict, tier: "free", standing: sidecar.AbuseStandingStandard, code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK},
		{level: smtpedgeservice.SmtpBreakerLevelCommunity, tier: "free", standing: sidecar.AbuseStandingStandard, code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED},
		{level: smtpedgeservice.SmtpBreakerLevelCommunity, tier: "pro", standing: sidecar.AbuseStandingStandard, code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK},
		{level: smtpedgeservice.SmtpBreakerLevelCommunity, tier: "pro", standing: sidecar.AbuseStandingRestricted, code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED},
		{level: smtpedgeservice.SmtpBreakerLevelAll, tier: "pro", standing: sidecar.AbuseStandingStandard, code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED},
		{level: smtpedgeservice.SmtpBreakerLevelAll, tier: "team", standing: sidecar.AbuseStandingStandard, code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED},
		{level: smtpedgeservice.SmtpBreakerLevelAll, tier: "team", standing: sidecar.AbuseStandingTrusted, code: protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK},
	}
	for _, c := range cases {
		g := newGateWorld(t)
		g.facts.Limits.Tier = c.tier
		g.reload()
		g.abuse.SetStanding(connect.Id(g.networkId), c.standing)
		g.gate.SetBreaker(&smtpedgeservice.SmtpBreakerState{Level: c.level})
		decision := g.check("n1.root.example", 0)
		if decision.Code != c.code {
			t.Errorf("level %d, %s %s: answered %d %q, want %d", c.level, c.tier, c.standing, decision.Code, decision.Reason, c.code)
		}
		if c.code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED && (decision.Reason != "breaker" || decision.RetryAfter != g.settings.BreakerRetryTimeout) {
			t.Errorf("level %d: reason %q, retry %v", c.level, decision.Reason, decision.RetryAfter)
		}
	}
}

func TestSmtpGateHalvesCommunityRatesAtLevelOne(t *testing.T) {
	g := newGateWorld(t)
	g.facts.Limits = communityLimits()
	g.reload()
	g.gate.SetBreaker(&smtpedgeservice.SmtpBreakerState{Level: smtpedgeservice.SmtpBreakerLevelRestrict})
	decision := g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	for key, want := range map[string]int64{
		smtpedgeservice.SmtpLimitConnectionsPerDay:     2,
		smtpedgeservice.SmtpLimitRecipientsPerDay:      12,
		smtpedgeservice.SmtpLimitBurst:                 2,
		smtpedgeservice.SmtpLimitBytesPerDay:           5 * 1024 * 1024 / 2,
		smtpedgeservice.SmtpLimitRecipientsPerMessage:  5,
		smtpedgeservice.SmtpLimitConcurrentConnections: 1,
	} {
		if got := decision.Limits.Limits[key]; got != want {
			t.Errorf("%s: %d, want %d", key, got, want)
		}
	}
	// the gate's copy is its own: the facts' limits are as loaded
	if facts, _ := g.gate.Facts(g.networkId); facts.Limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay] != 5 {
		t.Fatal("halving changed the facts")
	}
}

func TestSmtpGateTierThisBuildDoesNotKnowAnswersTryLater(t *testing.T) {
	g := newGateWorld(t)
	g.facts.Limits.Tier = "enterprise"
	g.reload()
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "unloaded")
}
