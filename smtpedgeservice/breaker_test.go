// §14.7's Community breaker and destination caps (SMTP-M9-11, plan-SMTP-shared-counters): a trip
// answers TRY_LATER until the next hour and is counted for §19's alert, the cap follows the trailing
// median, a destination domain's hour is its own, and concurrency per (sending address, destination /24)
// is held in memory.

package smtpedgeservice_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// Community limits whose hourly breaker floor is floor.
func breakerLimits(floor int64) *sidecar.QuotaLimits {
	limits := communityLimits()
	limits.Limits[smtpedgeservice.SmtpLimitCommunityConnectionsPerHour] = floor
	limits.Limits[smtpedgeservice.SmtpLimitConcurrentConnections] = 100
	limits.Limits[smtpedgeservice.SmtpLimitConnectionsPerDay] = 100
	limits.Limits[smtpedgeservice.SmtpLimitRecipientsPerDay] = 1000
	limits.Limits[smtpedgeservice.SmtpLimitBurst] = 100
	return limits
}

func TestBreakerTripsPastTheHoursCapAndClearsNextHour(t *testing.T) {
	q := newQuotaWorld(t)
	limits := breakerLimits(2)
	for range 2 {
		q.networkId = sidecar.NewId()
		q.reserve(q.request(limits, 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	}
	q.networkId = sidecar.NewId()
	decision := q.reserve(q.request(limits, 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "community_breaker")
	now := q.clock.Now()
	if want := now.Truncate(time.Hour).Add(time.Hour).Sub(now); decision.RetryAfter != want {
		t.Fatalf("retry after %v, want %v", decision.RetryAfter, want)
	}
	if value := q.host.Metrics.Value("urnetwork_smtpedge_breaker_trips_total", "community"); value != 1 {
		t.Fatalf("%v trips counted", value)
	}
	// the trip took back its count, and a Pro preamble never counts
	q.networkId = sidecar.NewId()
	q.reserve(q.request(proLimits(), 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	q.clock.Advance(decision.RetryAfter)
	q.networkId = sidecar.NewId()
	q.reserve(q.request(limits, 1), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
}

func TestBreakerCapFollowsTheTrailingMedian(t *testing.T) {
	q := newQuotaWorld(t)
	limits := breakerLimits(2)
	breaker := q.quota.Breaker()
	if got := breaker.Cap(limits); got != 2 {
		t.Fatalf("with no median the cap is %d, want the floor", got)
	}
	if err := q.host.Redis.Set(q.ctx, "{smg_median}", []byte("10"), 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	q.clock.Advance(q.settings.BreakerMedianRefreshInterval)
	if err := breaker.AwaitMedianReads(q.ctx, 2); err != nil {
		t.Fatal(err)
	}
	if got := breaker.Cap(limits); got != 30 {
		t.Fatalf("cap %d, want 3 x 10", got)
	}
	if got := breaker.Cap(breakerLimits(500)); got != 500 {
		t.Fatalf("cap %d, want the floor over 3 x 10", got)
	}
	// a median that is lost or garbled means the floor again
	if err := q.host.Redis.Set(q.ctx, "{smg_median}", []byte("ten"), 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	q.clock.Advance(q.settings.BreakerMedianRefreshInterval)
	if err := breaker.AwaitMedianReads(q.ctx, 3); err != nil {
		t.Fatal(err)
	}
	if got := breaker.Cap(limits); got != 2 {
		t.Fatalf("cap %d after a garbled median", got)
	}
}

func TestDestinationCapCountsEachDomainsHour(t *testing.T) {
	q := newQuotaWorld(t)
	limits := breakerLimits(500)
	limits.Limits[smtpedgeservice.SmtpLimitDestinationConnectionsPerHour] = 1
	request := func(domain string) *smtpedgeservice.SmtpQuotaRequest {
		q.networkId = sidecar.NewId()
		request := q.request(limits, 1)
		request.RecipientDomain = domain
		return request
	}
	q.reserve(request("a.example"), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	refused := q.reserve(request("A.example."), protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER, "destination")
	q.reserve(request("b.example"), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	q.clock.Advance(refused.RetryAfter)
	q.reserve(request("a.example"), protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	// no key names a domain, only its hash
	for key := range q.host.Redis.Dump() {
		if strings.Contains(key, "a.example") || strings.Contains(key, "b.example") {
			t.Fatalf("a key names a domain: %s", key)
		}
	}
}

func TestDestinationConcurrencyPerSendingAddressAndSlash24(t *testing.T) {
	q := newQuotaWorld(t)
	caps := q.quota.DestinationCaps()
	sendingA, sendingB := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")
	mx1, mx2, other := netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("203.0.113.200"), netip.MustParseAddr("203.0.114.5")
	releaseOne, ok := caps.Acquire(sendingA, mx1, 2)
	if !ok {
		t.Fatal("the first slot refused")
	}
	if _, ok := caps.Acquire(sendingA, mx2, 2); !ok {
		t.Fatal("the second slot refused")
	}
	if _, ok := caps.Acquire(sendingA, mx1, 2); ok {
		t.Fatal("a third slot to one /24 taken")
	}
	if _, ok := caps.Acquire(sendingB, mx1, 2); !ok {
		t.Fatal("another sending address's slot refused")
	}
	if _, ok := caps.Acquire(sendingA, other, 2); !ok {
		t.Fatal("another /24's slot refused")
	}
	releaseOne()
	releaseOne()
	if got := caps.Count(sendingA, mx2); got != 1 {
		t.Fatalf("a release given twice counted %d", got)
	}
	if _, ok := caps.Acquire(sendingA, mx1, 2); !ok {
		t.Fatal("a released slot not given back")
	}
}
