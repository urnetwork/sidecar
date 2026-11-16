// §14.7's enforcement (SMTP-M9-11) on a fake clock, over FakeRedis and the scripts' twins: the day's
// connections and recipients, the burst, concurrency that heals, UTC rollover, a debit only at MAIL,
// halts in memory and in Redis, one script a preamble, and §22.5's §14 row, that losing Redis fails open
// by at most a day's quota.

package smtpedgeservice_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// A quota on a fake host, its scripts' twins registered.
type quotaWorld struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	faults    *sidecartest.FaultQueue
	host      *sidecartest.FakeHost
	settings  *smtpedgeservice.SmtpEdgeSettings
	quota     *smtpedgeservice.SmtpQuota
	networkId sidecar.Id
}

func newQuotaWorld(t *testing.T) *quotaWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	host := sidecartest.NewFakeHost(ctx, clock, faults, nil, nil)
	sidecartest.RegisterSmtpQuotaScripts(host.Redis)
	settings := worldSettings()
	quota, err := smtpedgeservice.NewSmtpQuota(ctx, host.ServiceHost(), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Breaker().Close)
	if err := quota.Breaker().AwaitMedianReads(ctx, 1); err != nil {
		t.Fatal(err)
	}
	return &quotaWorld{t: t, ctx: ctx, clock: clock, faults: faults, host: host, settings: settings, quota: quota, networkId: sidecar.NewId()}
}

func (self *quotaWorld) request(limits *sidecar.QuotaLimits, recipients uint32) *smtpedgeservice.SmtpQuotaRequest {
	return &smtpedgeservice.SmtpQuotaRequest{
		NetworkId:        self.networkId,
		RecipientCount:   recipients,
		MessageByteCount: 4096,
		RecipientDomain:  testRecipientDomain,
		Limits:           limits,
		Community:        limits.Tier == "free",
	}
}

func (self *quotaWorld) reserve(request *smtpedgeservice.SmtpQuotaRequest, code protocol.SmtpPreambleCode, reason string) *smtpedgeservice.SmtpQuotaDecision {
	self.t.Helper()
	decision, err := self.quota.Reserve(self.ctx, request)
	if err != nil {
		self.t.Fatal(err)
	}
	if decision.Code != code || decision.Reason != reason {
		self.t.Fatalf("reserve answered %d %q, want %d %q", decision.Code, decision.Reason, code, reason)
	}
	return decision
}

// One whole connection: reserved, debited at MAIL, closed with its bytes.
func (self *quotaWorld) send(limits *sidecar.QuotaLimits) {
	self.t.Helper()
	decision := self.reserve(self.request(limits, 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	if err := self.quota.DebitMail(self.ctx, decision.Reservation); err != nil {
		self.t.Fatal(err)
	}
	if err := self.quota.Close(self.ctx, decision.Reservation, 1000); err != nil {
		self.t.Fatal(err)
	}
}

// The network's {smq_} field.
func (self *quotaWorld) field(field string) string {
	self.t.Helper()
	value, _, err := self.host.Redis.HashGet(self.ctx, "{smq_"+self.networkId.String()+"}", field)
	if err != nil {
		self.t.Fatal(err)
	}
	return string(value)
}

func (self *quotaWorld) day() string {
	return strconv.FormatInt(smtpedgeservice.SmtpSendDay(self.clock.Now()), 10)
}

// The time left to the next UTC midnight.
func (self *quotaWorld) untilTomorrow() time.Duration {
	now := self.clock.Now().UTC()
	return now.Truncate(24 * time.Hour).Add(24 * time.Hour).Sub(now)
}

func TestQuotaSixthCommunityConnectionRefused(t *testing.T) {
	q := newQuotaWorld(t)
	for range 5 {
		q.send(communityLimits())
		q.clock.Advance(time.Minute)
	}
	decision := q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "connections_per_day")
	if decision.RetryAfter != q.untilTomorrow() {
		t.Fatalf("retry after %v, want %v", decision.RetryAfter, q.untilTomorrow())
	}
	if got := q.field("c:" + q.day()); got != "5" {
		t.Fatalf("connections %q", got)
	}
	if got := q.field("b:" + q.day()); got != "5000" {
		t.Fatalf("bytes %q", got)
	}
}

func TestQuotaRefusalBeforeMailChargesOnlyABurstToken(t *testing.T) {
	q := newQuotaWorld(t)
	for range 5 {
		decision := q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
		if err := q.quota.Release(q.ctx, decision.Reservation); err != nil {
			t.Fatal(err)
		}
	}
	if got := q.field("c:" + q.day()); got != "" {
		t.Fatalf("a refusal before MAIL debited %q", got)
	}
	// five refusals took the window's five tokens and no unit
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "burst")
	q.clock.Advance(10 * time.Minute)
	for range 5 {
		q.send(communityLimits())
	}
}

func TestQuotaRecipientsReservedThenReleased(t *testing.T) {
	q := newQuotaWorld(t)
	limits := proLimits()
	limits.Limits[smtpedgeservice.SmtpLimitRecipientsPerDay] = 25
	first := q.reserve(q.request(limits, 20), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	q.reserve(q.request(limits, 10), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "recipients_per_day")
	if err := q.quota.Release(q.ctx, first.Reservation); err != nil {
		t.Fatal(err)
	}
	q.reserve(q.request(limits, 10), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
}

func TestQuotaPerMessageCaps(t *testing.T) {
	q := newQuotaWorld(t)
	q.reserve(q.request(communityLimits(), 6), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "recipients_per_message")
	request := q.request(communityLimits(), 1)
	request.MessageByteCount = 5*1024*1024 + 1
	q.reserve(request, protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "message_bytes")
}

func TestQuotaUtcRollover(t *testing.T) {
	q := newQuotaWorld(t)
	for range 5 {
		q.send(communityLimits())
	}
	decision := q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "connections_per_day")
	q.clock.Advance(decision.RetryAfter)
	q.send(communityLimits())
}

func TestQuotaConcurrencyHealsAfterAKilledEdge(t *testing.T) {
	q := newQuotaWorld(t)
	// an edge reserves and dies: no Close
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "concurrent_connections")
	q.clock.Advance(q.settings.QuotaMemberTimeout)
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
}

func TestQuotaRenewKeepsALiveConnectionsSlot(t *testing.T) {
	q := newQuotaWorld(t)
	live := q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	for range 3 {
		q.clock.Advance(q.settings.QuotaMemberRenewInterval)
		if err := q.quota.Renew(q.ctx, live.Reservation); err != nil {
			t.Fatal(err)
		}
	}
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "concurrent_connections")
}

func TestQuotaDebitsOnceAtMailAndBytesAtClose(t *testing.T) {
	q := newQuotaWorld(t)
	decision := q.reserve(q.request(proLimits(), 3), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	for range 2 {
		if err := q.quota.DebitMail(q.ctx, decision.Reservation); err != nil {
			t.Fatal(err)
		}
	}
	if got := q.field("c:" + q.day()); got != "1" {
		t.Fatalf("connections %q", got)
	}
	if got := q.field("r:" + q.day()); got != "3" {
		t.Fatalf("recipients %q", got)
	}
	for range 2 {
		if err := q.quota.Close(q.ctx, decision.Reservation, 777); err != nil {
			t.Fatal(err)
		}
	}
	if got := q.field("b:" + q.day()); got != "777" {
		t.Fatalf("bytes %q", got)
	}
}

func TestQuotaOneScriptPerPreamble(t *testing.T) {
	q := newQuotaWorld(t)
	q.host.Redis.ResetOpCounts()
	q.reserve(q.request(proLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	if counts := q.host.Redis.OpCounts(); len(counts) != 1 || counts["script:smtp_quota_reserve"] != 1 {
		t.Fatalf("a Pro preamble's calls %v", counts)
	}
	q.host.Redis.ResetOpCounts()
	q.networkId = sidecar.NewId()
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	// a Community preamble adds one single-key script for each fleet counter (plan-SMTP-shared-counters)
	if counts := q.host.Redis.OpCounts(); len(counts) != 2 || counts["script:smtp_quota_reserve"] != 1 || counts["script:smtp_hour_count"] != 2 {
		t.Fatalf("a Community preamble's calls %v", counts)
	}
	if violations := q.host.Redis.Violations(); len(violations) != 0 {
		t.Fatalf("CROSSSLOT: %v", violations)
	}
}

// §22.5's §14 row: losing Redis fails open by at most one day's quota.
func TestQuotaRedisLossFailsOpenAtMostOneDaysQuota(t *testing.T) {
	q := newQuotaWorld(t)
	for range 5 {
		q.send(communityLimits())
		q.clock.Advance(time.Minute)
	}
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "connections_per_day")
	q.host.Redis.LoseEverything()
	// the counters restart: one more day's quota, and no more
	q.clock.Advance(10 * time.Minute)
	for range 5 {
		q.send(communityLimits())
		q.clock.Advance(time.Minute)
	}
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "connections_per_day")
}

func TestQuotaRedisFailingFailsOpenOnOneDaysCount(t *testing.T) {
	q := newQuotaWorld(t)
	if _, err := q.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: "{smq_", Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		q.send(communityLimits())
	}
	q.reserve(q.request(communityLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "fail_open_day")
	if value := q.host.Metrics.Value("urnetwork_smtpedge_quota_fail_open_total"); value != 5 {
		t.Fatalf("%v fail-open passes counted", value)
	}
	// the per-message caps hold while failing open
	q.reserve(q.request(communityLimits(), 6), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "recipients_per_message")
}

func TestQuotaHaltsHoldInMemoryAndInRedis(t *testing.T) {
	q := newQuotaWorld(t)
	halt := &smtpedgeservice.SmtpHalt{HaltId: sidecar.NewId(), NetworkId: q.networkId, Trigger: smtpedgeservice.SmtpHaltTriggerRecordCuts, StartTime: q.clock.Now()}
	if err := q.quota.ApplyHalt(q.ctx, halt); err != nil {
		t.Fatal(err)
	}
	decision := q.reserve(q.request(proLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, "halt")
	if decision.RetryAfter != smtpedgeservice.SmtpHaltDuration {
		t.Fatalf("retry after %v", decision.RetryAfter)
	}
	// another edge, whose memory has no halt, finds it in Redis
	other, err := smtpedgeservice.NewSmtpQuota(q.ctx, q.host.ServiceHost(), q.settings)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Breaker().Close()
	if decision, err := other.Reserve(q.ctx, q.request(proLimits(), 1)); err != nil || decision.Code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED || decision.Reason != "halt" {
		t.Fatalf("another edge answered %+v, %v", decision, err)
	}
	// and with Redis failing, this edge's memory still refuses
	if _, err := q.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpRedis, KeyPrefix: "{smq_", Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	q.reserve(q.request(proLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, "halt")
	q.clock.Advance(smtpedgeservice.SmtpHaltDuration)
	q.reserve(q.request(proLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
}

func TestQuotaRefusesAHaltOnALabelNotABurners(t *testing.T) {
	q := newQuotaWorld(t)
	halt := &smtpedgeservice.SmtpHalt{HaltId: sidecar.NewId(), NetworkId: q.networkId, Label: "h:x", StartTime: q.clock.Now()}
	if err := q.quota.ApplyHalt(q.ctx, halt); err == nil {
		t.Fatal("a halt naming a field-breaking label applied")
	}
}

func TestQuotaBurstWithNoWindowIncludesNothing(t *testing.T) {
	q := newQuotaWorld(t)
	limits := proLimits()
	delete(limits.Limits, smtpedgeservice.SmtpLimitBurstWindow)
	q.reserve(q.request(limits, 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA, "unconfigured")
}
