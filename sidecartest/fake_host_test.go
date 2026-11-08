package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

func newHostFixture(t *testing.T) (*FakeHost, *FakeClock, *FaultQueue) {
	clock := NewFakeClock(DefaultClockStart())
	faults := NewFaultQueue()
	host := NewFakeHost(t.Context(), clock, faults, nil, nil)
	t.Cleanup(host.Redis.Close)
	return host, clock, faults
}

// Stops compiling if a fake drifts from what ServiceHost holds.
var (
	_ sidecar.Authenticator       = (*FakeAuthenticator)(nil)
	_ sidecar.Quota               = (*FakeQuota)(nil)
	_ sidecar.QuotaLease          = (*fakeQuotaLease)(nil)
	_ sidecar.Metrics             = (*FakeMetrics)(nil)
	_ sidecar.Tasks               = (*FakeTasks)(nil)
	_ sidecar.Redis               = (*FakeRedis)(nil)
	_ sidecar.BlobStore           = (*FakeBlobs)(nil)
	_ sidecar.ClockCheck          = (*FakeClockCheck)(nil)
	_ sidecar.Push                = (*FakePush)(nil)
	_ sidecar.ServiceClientSource = (*FakeServiceClientSource)(nil)
	_ sidecar.ServiceGates        = (*FakeServiceGates)(nil)
	_ sidecar.Clock               = (*FakeClock)(nil)
)

func TestFakeHostFillsEveryInterface(t *testing.T) {
	host, _, _ := newHostFixture(t)
	serviceHost := host.ServiceHost()
	if serviceHost.Authenticator == nil || serviceHost.Quota == nil || serviceHost.Metrics == nil ||
		serviceHost.Tasks == nil || serviceHost.Redis == nil || serviceHost.Blobs == nil ||
		serviceHost.ClockCheck == nil || serviceHost.Push == nil || serviceHost.ServiceClient == nil ||
		serviceHost.Clock == nil || serviceHost.Gates == nil {
		t.Errorf("host %+v", serviceHost)
	}
}

// A Principal Principal.Validate passes, good for an hour on clock.
func validPrincipal(clock Clock) *sidecar.Principal {
	return &sidecar.Principal{
		NetworkId: connect.NewId(),
		ClientId:  connect.NewId(),
		Audience:  "evs",
		Scopes:    []string{"repo:r:rw"},
		ExpiresAt: clock.Now().Add(1 * time.Hour),
	}
}

func TestAuthenticatorKnowsOnlyWhatItIssued(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	jwt := host.Authenticator.Issue(validPrincipal(clock))
	principal, err := host.Authenticator.Authenticate(t.Context(), "evs", jwt)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Audience != "evs" || len(principal.Scopes) != 1 {
		t.Errorf("principal %+v", principal)
	}
	if _, err := host.Authenticator.Authenticate(t.Context(), "evs", "a guess"); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("a guess: %v", err)
	}
}

// §7.8: every service audience shares one key set, so the audience check is what tells them apart.
func TestAuthenticatorRefusesAnotherAudienceAndNone(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	jwt := host.Authenticator.Issue(validPrincipal(clock))
	for _, audience := range []string{"gkm", ""} {
		if _, err := host.Authenticator.Authenticate(t.Context(), audience, jwt); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
			t.Errorf("audience %q: %v", audience, err)
		}
	}
}

func TestAuthenticatorRefusesExpiredAndRevoked(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	expiring := host.Authenticator.Issue(validPrincipal(clock))
	if _, err := host.Authenticator.Authenticate(t.Context(), "evs", expiring); err != nil {
		t.Fatal(err)
	}
	clock.Advance(1 * time.Hour)
	if _, err := host.Authenticator.Authenticate(t.Context(), "evs", expiring); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("expired: %v", err)
	}

	revoked := host.Authenticator.Issue(validPrincipal(clock))
	host.Authenticator.Revoke(revoked)
	if _, err := host.Authenticator.Authenticate(t.Context(), "evs", revoked); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("revoked: %v", err)
	}
}

// host_auth.go: a zero ExpiresAt has passed, so a token that names no end has none left.
func TestATokenWithNoExpiryHasExpired(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	principal := validPrincipal(clock)
	principal.ExpiresAt = time.Time{}
	jwt := host.Authenticator.Issue(principal)
	if _, err := host.Authenticator.Authenticate(t.Context(), "evs", jwt); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("err %v", err)
	}
}

// host_auth.go: a token that does not name its network and client never authenticates with zero ids,
// or a removed client's unexpired token would read as not revoked.
func TestATokenPrincipalValidateRefusesDoesNotAuthenticate(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	zeroId := connect.Id{}
	for name, change := range map[string]func(principal *sidecar.Principal){
		"no network":     func(principal *sidecar.Principal) { principal.NetworkId = connect.Id{} },
		"no client":      func(principal *sidecar.Principal) { principal.ClientId = connect.Id{} },
		"a zero subject": func(principal *sidecar.Principal) { principal.SubjectClientId = &zeroId },
		"a zero sidecar": func(principal *sidecar.Principal) { principal.SidecarId = &zeroId },
		"a zero member":  func(principal *sidecar.Principal) { principal.MemberId = &zeroId },
	} {
		principal := validPrincipal(clock)
		change(principal)
		jwt := host.Authenticator.Issue(principal)
		if _, err := host.Authenticator.Authenticate(t.Context(), "evs", jwt); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The other kind of failure: an engine answers unavailable, so a client retries and stays signed in.
func TestADroppedAuthenticateIsNoRefusal(t *testing.T) {
	host, clock, faults := newHostFixture(t)
	jwt := host.Authenticator.Issue(validPrincipal(clock))
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "authenticator.", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	_, err := host.Authenticator.Authenticate(t.Context(), "evs", jwt)
	if err == nil || errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("err %v", err)
	}
}

func TestAuthenticatorReturnsItsOwnCopy(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	jwt := host.Authenticator.Issue(validPrincipal(clock))
	first, err := host.Authenticator.Authenticate(t.Context(), "evs", jwt)
	if err != nil {
		t.Fatal(err)
	}
	first.Scopes[0] = "tampered"
	second, err := host.Authenticator.Authenticate(t.Context(), "evs", jwt)
	if err != nil {
		t.Fatal(err)
	}
	if second.Scopes[0] != "repo:r:rw" {
		t.Errorf("scopes %v", second.Scopes)
	}
}

// host_quota.go: a zero id is the caller's bug and an error, never a lookup, so nothing is counted.
func TestAZeroQuotaIdIsAnError(t *testing.T) {
	host, _, _ := newHostFixture(t)
	ctx := t.Context()
	networkId := connect.NewId()
	zeroId := connect.Id{}
	host.Quota.SetRateLimit(networkId, "a", 10)
	if _, err := host.Quota.Limits(ctx, zeroId); err == nil {
		t.Error("Limits took a zero network")
	}
	if _, err := host.Quota.CountRate(ctx, zeroId, map[string]int64{"a": 1}, connect.NewId()); err == nil {
		t.Error("CountRate took a zero network")
	}
	if _, _, err := host.Quota.Lease(ctx, zeroId, "tls"); err == nil {
		t.Error("Lease took a zero network")
	}
	// two debits sharing a zero id would read as one retried, the second counting nothing
	for range 2 {
		if _, err := host.Quota.CountRate(ctx, networkId, map[string]int64{"a": 1}, zeroId); err == nil {
			t.Error("CountRate took a zero debit")
		}
	}
	event := &sidecar.UsageEvent{NetworkId: networkId, Meter: "tls", TransferByteCount: 7}
	if err := host.Quota.ReportUsage(ctx, &sidecar.UsageBatch{Events: []*sidecar.UsageEvent{event}}); err == nil {
		t.Error("ReportUsage took a zero batch")
	}
	badEvent := &sidecar.UsageEvent{Meter: "tls", TransferByteCount: 7}
	if err := host.Quota.ReportUsage(ctx, &sidecar.UsageBatch{BatchId: connect.NewId(), Events: []*sidecar.UsageEvent{event, badEvent}}); err == nil {
		t.Error("ReportUsage took an event for a zero network")
	}
	if got := host.Quota.TransferUsed(networkId, "tls"); got != 0 {
		t.Errorf("a refused batch counted %d", got)
	}
	if len(host.Quota.Batches()) != 0 {
		t.Errorf("batches %d", len(host.Quota.Batches()))
	}
	// the cap is untouched, so all of it is still there to count
	refusal, err := host.Quota.CountRate(ctx, networkId, map[string]int64{"a": 10}, connect.NewId())
	if err != nil || refusal != nil {
		t.Errorf("refusal %+v, %v", refusal, err)
	}
}

func TestQuotaLimitsReadZeroForWhatWasNotGiven(t *testing.T) {
	host, _, _ := newHostFixture(t)
	networkId := connect.NewId()
	limits, err := host.Quota.Limits(t.Context(), networkId)
	if err != nil {
		t.Fatal(err)
	}
	if limits.Limits["storage_bytes"] != 0 {
		t.Errorf("limits %+v", limits)
	}
	host.Quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"storage_bytes": 100}})
	limits, err = host.Quota.Limits(t.Context(), networkId)
	if err != nil {
		t.Fatal(err)
	}
	if limits.Tier != "pro" || limits.Limits["storage_bytes"] != 100 {
		t.Errorf("limits %+v", limits)
	}
}

func TestCountRateIsAllOrNone(t *testing.T) {
	host, _, _ := newHostFixture(t)
	networkId := connect.NewId()
	host.Quota.SetRateLimit(networkId, "a", 10)
	host.Quota.SetRateLimit(networkId, "b", 1)

	refusal, err := host.Quota.CountRate(t.Context(), networkId, map[string]int64{"a": 5, "b": 2}, connect.NewId())
	if err != nil {
		t.Fatal(err)
	}
	if refusal == nil || refusal.LimitKey != "b" {
		t.Fatalf("refusal %+v", refusal)
	}
	// nothing of that debit counted, so a's whole allowance still stands
	refusal, err = host.Quota.CountRate(t.Context(), networkId, map[string]int64{"a": 10}, connect.NewId())
	if err != nil || refusal != nil {
		t.Errorf("refusal %+v, %v", refusal, err)
	}
}

// §20.7: a retry of one debit id counts nothing twice, even after a lost response.
func TestCountRateCountsOncePerDebit(t *testing.T) {
	host, _, faults := newHostFixture(t)
	networkId := connect.NewId()
	host.Quota.SetRateLimit(networkId, "a", 10)
	debitId := connect.NewId()
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "quota.CountRate", Result: ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Quota.CountRate(t.Context(), networkId, map[string]int64{"a": 10}, debitId); err == nil {
		t.Fatal("the plan did not fire")
	}
	refusal, err := host.Quota.CountRate(t.Context(), networkId, map[string]int64{"a": 10}, debitId)
	if err != nil || refusal != nil {
		t.Errorf("the retry: %+v, %v", refusal, err)
	}
	refusal, err = host.Quota.CountRate(t.Context(), networkId, map[string]int64{"a": 1}, connect.NewId())
	if err != nil || refusal == nil {
		t.Errorf("a new debit past the limit: %+v, %v", refusal, err)
	}
}

func TestAnUncappedRateIsRefused(t *testing.T) {
	host, _, _ := newHostFixture(t)
	refusal, err := host.Quota.CountRate(t.Context(), connect.NewId(), map[string]int64{"a": 1}, connect.NewId())
	if err != nil || refusal == nil {
		t.Errorf("refusal %+v, %v", refusal, err)
	}
}

func TestResetRatesStartsAWindow(t *testing.T) {
	host, _, _ := newHostFixture(t)
	networkId := connect.NewId()
	host.Quota.SetRateLimit(networkId, "a", 1)
	for range 2 {
		if refusal, err := host.Quota.CountRate(t.Context(), networkId, map[string]int64{"a": 1}, connect.NewId()); err != nil || refusal != nil {
			t.Errorf("refusal %+v, %v", refusal, err)
		}
		host.Quota.ResetRates(networkId)
	}
}

func TestLeaseSpendsAndReturnsTheRest(t *testing.T) {
	host, _, _ := newHostFixture(t)
	networkId := connect.NewId()
	host.Quota.SetBalance(networkId, 1000)
	lease, refusal, err := host.Quota.Lease(t.Context(), networkId, "tls")
	if err != nil || refusal != nil {
		t.Fatalf("refusal %+v, %v", refusal, err)
	}
	if host.Quota.Balance(networkId) != 0 {
		t.Errorf("balance %d after the draw", host.Quota.Balance(networkId))
	}
	if !lease.Spend(400) {
		t.Fatal("spend refused")
	}
	lease.Close()
	if got := host.Quota.Balance(networkId); got != 600 {
		t.Errorf("balance %d", got)
	}
	if lease.Spend(1) {
		t.Error("a closed lease spent")
	}
}

func TestLeaseDrawsAgainPastItsFractionAndRefusesPastTheBalance(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	settings := DefaultFakeHostSettings()
	settings.Quota.LeaseDrawByteCount = 100
	host := NewFakeHost(t.Context(), clock, nil, nil, settings)
	t.Cleanup(host.Redis.Close)
	networkId := connect.NewId()
	host.Quota.SetBalance(networkId, 150)
	lease, _, err := host.Quota.Lease(t.Context(), networkId, "tls")
	if err != nil {
		t.Fatal(err)
	}
	if got := host.Quota.Balance(networkId); got != 50 {
		t.Errorf("after the first draw: %d", got)
	}
	if !lease.Spend(80) {
		t.Fatal("spend refused")
	}
	// 80 of 100 is past 75%, so the rest of the balance came over
	if got := host.Quota.Balance(networkId); got != 0 {
		t.Errorf("after the renewal: %d", got)
	}
	if !lease.Spend(70) {
		t.Fatal("spend past the first draw refused")
	}
	if lease.Spend(1) {
		t.Error("spent past the balance")
	}
	overLimit, err := host.Quota.OverLimit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if overLimit.SpentNetworkIdRefusals[networkId] == nil {
		t.Error("a lease run out left the network unspent")
	}
}

func TestLeaseSpendIsAtomicAcrossGoroutines(t *testing.T) {
	host, _, _ := newHostFixture(t)
	networkId := connect.NewId()
	host.Quota.SetBalance(networkId, 1000)
	lease, _, err := host.Quota.Lease(t.Context(), networkId, "tls")
	if err != nil {
		t.Fatal(err)
	}
	spent := make(chan int, 16)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			count := 0
			for lease.Spend(1) {
				count += 1
			}
			spent <- count
		}()
	}
	wait.Wait()
	close(spent)
	total := 0
	for count := range spent {
		total += count
	}
	if total != 1000 {
		t.Errorf("spent %d", total)
	}
}

func TestARefusedLeaseMarksTheNetworkSpent(t *testing.T) {
	host, _, _ := newHostFixture(t)
	networkId := connect.NewId()
	lease, refusal, err := host.Quota.Lease(t.Context(), networkId, "tls")
	if err != nil {
		t.Fatal(err)
	}
	if lease != nil || refusal == nil {
		t.Fatalf("lease %v refusal %+v", lease, refusal)
	}
	overLimit, err := host.Quota.OverLimit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if overLimit.SpentNetworkIdRefusals[networkId] == nil {
		t.Error("not marked spent")
	}
	host.Quota.SetBalance(networkId, 10)
	if _, refusal, _ := host.Quota.Lease(t.Context(), networkId, "tls"); refusal != nil {
		t.Errorf("refusal %+v", refusal)
	}
	overLimit, err = host.Quota.OverLimit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if overLimit.SpentNetworkIdRefusals[networkId] != nil {
		t.Error("a new Lease did not say otherwise")
	}
}

// FS-44: a usage batch retried after a lost response debits once.
func TestReportUsageDebitsOncePerBatch(t *testing.T) {
	host, _, faults := newHostFixture(t)
	networkId := connect.NewId()
	batch := &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: "evs",
		Events: []*sidecar.UsageEvent{
			{NetworkId: networkId, Meter: "tls", TransferByteCount: 100, StoredByteDelta: 7},
		},
	}
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	if err := host.Quota.ReportUsage(t.Context(), batch); err == nil {
		t.Fatal("the plan did not fire")
	}
	if err := host.Quota.ReportUsage(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if got := host.Quota.TransferUsed(networkId, "tls"); got != 100 {
		t.Errorf("debited %d", got)
	}
	if got := host.Quota.StoredDelta(networkId); got != 7 {
		t.Errorf("stored %d", got)
	}
	if len(host.Quota.Batches()) != 1 {
		t.Errorf("batches %d", len(host.Quota.Batches()))
	}
}

func TestOverLimitKeepsTheTwoReasonsApart(t *testing.T) {
	host, _, _ := newHostFixture(t)
	storage, spent := connect.NewId(), connect.NewId()
	host.Quota.SetStorageRefusal(storage, &sidecar.QuotaRefusal{LimitKey: "storage"})
	host.Quota.SetSpentRefusal(spent, &sidecar.QuotaRefusal{LimitKey: "balance"})
	overLimit, err := host.Quota.OverLimit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if overLimit.StorageNetworkIdRefusals[storage] == nil || overLimit.StorageNetworkIdRefusals[spent] != nil {
		t.Errorf("storage %v", overLimit.StorageNetworkIdRefusals)
	}
	if overLimit.SpentNetworkIdRefusals[spent] == nil || overLimit.SpentNetworkIdRefusals[storage] != nil {
		t.Errorf("spent %v", overLimit.SpentNetworkIdRefusals)
	}
	host.Quota.SetStorageRefusal(storage, nil)
	overLimit, err = host.Quota.OverLimit(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(overLimit.StorageNetworkIdRefusals) != 0 {
		t.Error("a cleared refusal stayed")
	}
}

func TestMetricsCountAndRead(t *testing.T) {
	metrics := NewFakeMetrics(nil)
	counter := metrics.Counter("urnetwork_evs_requests_total", "help", "route", "code")
	counter.Add(1, "/evs/v1/x", "200")
	counter.Add(2, "/evs/v1/x", "200")
	counter.Add(5, "/evs/v1/x", "500")
	if got := metrics.Value("urnetwork_evs_requests_total", "/evs/v1/x", "200"); got != 3 {
		t.Errorf("value %v", got)
	}

	gauge := metrics.Gauge("urnetwork_evs_depth", "help")
	gauge.Set(4)
	gauge.Set(2)
	if got := metrics.Value("urnetwork_evs_depth"); got != 2 {
		t.Errorf("gauge %v", got)
	}

	histogram := metrics.Histogram("urnetwork_evs_seconds", "help", nil, "route")
	histogram.Observe(0.5, "a")
	histogram.Observe(1.5, "a")
	if got := metrics.Value("urnetwork_evs_seconds", "a"); got != 2 {
		t.Errorf("sum %v", got)
	}
	if got := metrics.ObservationCount("urnetwork_evs_seconds", "a"); got != 2 {
		t.Errorf("count %v", got)
	}
	if len(metrics.Violations()) != 0 {
		t.Errorf("violations %v", metrics.Violations())
	}
}

func TestMetricsRedeclaredAlikeShareOneSeries(t *testing.T) {
	metrics := NewFakeMetrics(nil)
	metrics.Counter("urnetwork_evs_total", "help", "code").Add(1, "200")
	metrics.Counter("urnetwork_evs_total", "help", "code").Add(1, "200")
	if got := metrics.Value("urnetwork_evs_total", "200"); got != 2 {
		t.Errorf("value %v", got)
	}
}

func TestMetricsPanicWherePrometheusWould(t *testing.T) {
	metrics := NewFakeMetrics(nil)
	counter := metrics.Counter("urnetwork_evs_total", "help", "code")
	cases := []func(){
		func() { metrics.Gauge("urnetwork_evs_total", "help", "code") },
		func() { metrics.Counter("urnetwork_evs_total", "help", "route") },
		func() { counter.Add(1) },
		func() { counter.Add(1, "200", "extra") },
		func() { counter.Add(-1, "200") },
	}
	for index, c := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("case %d did not panic", index)
				}
			}()
			c()
		}()
	}
}

func TestMetricsCatchANameOffThePatternAndAnIdentityInALabel(t *testing.T) {
	metrics := NewFakeMetrics(nil)
	metrics.Counter("requests_total", "help")
	if len(metrics.Violations()) != 1 {
		t.Errorf("violations %v", metrics.Violations())
	}

	counter := metrics.Counter("urnetwork_evs_total", "help", "peer")
	for _, value := range []string{"01ARZ3NDEKTSV4RRFFQ69G5FAV", "018f3a2c-0000-7000-8000-000000000000", "192.0.2.1", "2001:db8::1"} {
		before := len(metrics.Violations())
		counter.Add(1, value)
		if len(metrics.Violations()) != before+1 {
			t.Errorf("%q passed", value)
		}
	}
	before := len(metrics.Violations())
	counter.Add(1, "/evs/v1/repos/{repo_id}/head")
	counter.Add(1, "precondition")
	if len(metrics.Violations()) != before {
		t.Errorf("a fixed vocabulary failed: %v", metrics.Violations())
	}
}

func TestTasksRunOnlyWhenDueAndOnce(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	ctx := t.Context()
	runs := [][]byte{}
	host.Tasks.Register("evacuate", func(ctx context.Context, args []byte) error {
		runs = append(runs, args)
		return nil
	})
	request := &sidecar.TaskRequest{Name: "evacuate", OnceKey: "evacuate-meta-1", Args: []byte("first"), RunAt: clock.Now().Add(1 * time.Hour)}
	if err := host.Tasks.Schedule(ctx, request); err != nil {
		t.Fatal(err)
	}
	// asking twice runs once
	if err := host.Tasks.Schedule(ctx, request); err != nil {
		t.Fatal(err)
	}
	if ran, err := host.Tasks.RunDue(ctx); err != nil || ran != 0 {
		t.Fatalf("early: ran %d, %v", ran, err)
	}
	clock.Advance(1 * time.Hour)
	if ran, err := host.Tasks.RunDue(ctx); err != nil || ran != 1 {
		t.Fatalf("due: ran %d, %v", ran, err)
	}
	if len(runs) != 1 || string(runs[0]) != "first" {
		t.Errorf("runs %q", runs)
	}
	if len(host.Tasks.Pending()) != 0 {
		t.Errorf("pending %v", host.Tasks.Pending())
	}
}

func TestATaskNeedsItsOnceKey(t *testing.T) {
	host, _, _ := newHostFixture(t)
	if err := host.Tasks.Schedule(t.Context(), &sidecar.TaskRequest{Name: "evacuate"}); err == nil {
		t.Error("a request with no key passed")
	}
}

func TestARegistrationTwicePanics(t *testing.T) {
	host, _, _ := newHostFixture(t)
	function := func(ctx context.Context, args []byte) error { return nil }
	host.Tasks.Register("evacuate", function)
	defer func() {
		if recover() == nil {
			t.Error("a second function passed")
		}
	}()
	host.Tasks.Register("evacuate", function)
}

func TestAFailedRunRerunsAfterTheBackoff(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	ctx := t.Context()
	attempts := 0
	host.Tasks.Register("evacuate", func(ctx context.Context, args []byte) error {
		attempts += 1
		if attempts == 1 {
			return errors.New("the store is down")
		}
		return nil
	})
	if err := host.Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "evacuate", OnceKey: "k"}); err != nil {
		t.Fatal(err)
	}
	if ran, err := host.Tasks.RunDue(ctx); err != nil || ran != 1 {
		t.Fatalf("ran %d, %v", ran, err)
	}
	if ran, _ := host.Tasks.RunDue(ctx); ran != 0 {
		t.Fatal("reran inside the backoff")
	}
	clock.Advance(DefaultFakeTasksSettings().RetryTimeout)
	if ran, _ := host.Tasks.RunDue(ctx); ran != 1 {
		t.Fatal("did not rerun")
	}
	if attempts != 2 {
		t.Errorf("attempts %d", attempts)
	}
}

// host_tasks.go: a request during a run owns one successor after it ends, the running args left alone.
func TestARequestDuringARunWaitsAndKeepsItsOwnArgs(t *testing.T) {
	host, _, _ := newHostFixture(t)
	ctx := t.Context()
	runs := []string{}
	host.Tasks.Register("evacuate", func(ctx context.Context, args []byte) error {
		runs = append(runs, string(args))
		if len(runs) == 1 {
			if err := host.Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "evacuate", OnceKey: "k", Args: []byte("successor")}); err != nil {
				t.Error(err)
			}
			if err := host.Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "evacuate", OnceKey: "k", Args: []byte("coalesced")}); err != nil {
				t.Error(err)
			}
		}
		return nil
	})
	if err := host.Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "evacuate", OnceKey: "k", Args: []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if ran, err := host.Tasks.RunDue(ctx); err != nil || ran != 2 {
		t.Fatalf("ran %d, %v", ran, err)
	}
	if !slices.Equal(runs, []string{"first", "successor"}) {
		t.Errorf("runs %q", runs)
	}
}

func TestARunsContextEndsAtItsMaxTime(t *testing.T) {
	host, clock, _ := newHostFixture(t)
	ctx := t.Context()
	started := make(chan struct{})
	ended := make(chan error, 1)
	host.Tasks.Register("slow", func(ctx context.Context, args []byte) error {
		close(started)
		<-ctx.Done()
		ended <- ctx.Err()
		return ctx.Err()
	})
	if err := host.Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "slow", OnceKey: "k", MaxTime: 1 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	go host.Tasks.RunDue(ctx)
	<-started
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(1 * time.Minute)
	if err := <-ended; !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

func TestAnUnregisteredJobStaysPendingAndIsReported(t *testing.T) {
	host, _, _ := newHostFixture(t)
	ctx := t.Context()
	if err := host.Tasks.Schedule(ctx, &sidecar.TaskRequest{Name: "unknown", OnceKey: "k"}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Tasks.RunDue(ctx); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Errorf("err %v", err)
	}
	if len(host.Tasks.Pending()) != 1 {
		t.Errorf("pending %v", host.Tasks.Pending())
	}
}

func TestARunLostToACrashIsReclaimed(t *testing.T) {
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	host, clock, _ := newHostFixture(t)
	table := NewActorTable(clock, driver)
	attempts := 0
	host.Tasks.Register("evacuate", func(ctx context.Context, args []byte) error {
		attempts += 1
		if attempts == 1 {
			// the worker dies here
			crashCaller(ctx)
		}
		return nil
	})
	if err := host.Tasks.Schedule(t.Context(), &sidecar.TaskRequest{Name: "evacuate", OnceKey: "k"}); err != nil {
		t.Fatal(err)
	}
	worker := table.Actor(t.Context(), "taskworker1")
	run := driver.Start(worker, func() error {
		_, err := host.Tasks.RunDue(worker.Context())
		return err
	})
	awaitEnded(t, run)
	if len(host.Tasks.Pending()) != 0 {
		t.Fatal("a run in progress looked pending")
	}
	if got := host.Tasks.ReclaimRunning(); got != 1 {
		t.Fatalf("reclaimed %d", got)
	}
	if ran, err := host.Tasks.RunDue(t.Context()); err != nil || ran != 1 {
		t.Fatalf("ran %d, %v", ran, err)
	}
	if attempts != 2 {
		t.Errorf("attempts %d", attempts)
	}
}

func TestPushKeepsVersionsFromLowering(t *testing.T) {
	host, _, _ := newHostFixture(t)
	clientId := connect.NewId()
	for _, version := range []uint64{5, 3, 9} {
		if err := host.Push.Hint(t.Context(), []connect.Id{clientId}, &sidecar.ClientHint{Topic: "evs:r", Version: version}); err != nil {
			t.Fatal(err)
		}
	}
	if got := host.Push.Version(clientId, "evs:r"); got != 9 {
		t.Errorf("version %d", got)
	}
	versions := []uint64{}
	for _, hint := range host.Push.Hints(clientId) {
		versions = append(versions, hint.Version)
	}
	if !slices.Equal(versions, []uint64{5, 5, 9}) {
		t.Errorf("versions %v", versions)
	}
}

func TestPushRefusesAHintPastItsSize(t *testing.T) {
	host, _, _ := newHostFixture(t)
	hint := &sidecar.ClientHint{Topic: "core", Body: make([]byte, 257)}
	if err := host.Push.Hint(t.Context(), []connect.Id{connect.NewId()}, hint); err == nil {
		t.Error("a 257 byte body passed")
	}
	hint.Body = hint.Body[:256]
	if err := host.Push.Hint(t.Context(), []connect.Id{connect.NewId()}, hint); err != nil {
		t.Error(err)
	}
}

func TestPushResolvesSidecarsAndCountsAMiss(t *testing.T) {
	host, _, _ := newHostFixture(t)
	sidecarId, clientId, unbound := connect.NewId(), connect.NewId(), connect.NewId()
	host.Push.BindSidecar(sidecarId, clientId)
	hint := &sidecar.ClientHint{Topic: "gkm", Version: 1}
	if err := host.Push.HintSidecars(t.Context(), []connect.Id{sidecarId, unbound}, hint); err != nil {
		t.Fatal(err)
	}
	if len(host.Push.Hints(clientId)) != 1 {
		t.Errorf("hints %v", host.Push.Hints(clientId))
	}
	if got := host.Push.MissedSidecarIds(); len(got) != 1 || got[0] != unbound {
		t.Errorf("missed %v", got)
	}
}

func TestPushFaultsFailTheCall(t *testing.T) {
	host, _, faults := newHostFixture(t)
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "push.", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	clientId := connect.NewId()
	if err := host.Push.Hint(t.Context(), []connect.Id{clientId}, &sidecar.ClientHint{Topic: "core"}); err == nil {
		t.Error("the plan did not fire")
	}
	if len(host.Push.Hints(clientId)) != 0 {
		t.Error("a failed hint reached the client")
	}
}

// host_client.go: a source that cannot fill every field answers an error.
func TestAServiceClientWithNoUrlIsNoSuccess(t *testing.T) {
	for _, change := range []func(settings *FakeServiceClientSettings){
		func(settings *FakeServiceClientSettings) { settings.ApiUrl = "" },
		func(settings *FakeServiceClientSettings) { settings.PlatformUrl = "" },
	} {
		settings := DefaultFakeServiceClientSettings()
		change(settings)
		source := NewFakeServiceClientSource(NewFaultQueue(), settings)
		if auth, err := source.ServiceClient(t.Context(), 0); err == nil {
			t.Errorf("auth %+v", auth)
		}
	}
}

func TestServiceClientStaysOneClientWithANewerJwt(t *testing.T) {
	host, _, _ := newHostFixture(t)
	first, err := host.ServiceClient.ServiceClient(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := host.ServiceClient.ServiceClient(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := host.ServiceClient.ServiceClient(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.ClientId != second.ClientId {
		t.Error("one index, two clients")
	}
	if first.ByJwt == second.ByJwt {
		t.Error("a later answer carried no newer jwt")
	}
	if other.ClientId == first.ClientId {
		t.Error("two indexes, one client")
	}
	if _, err := host.ServiceClient.ServiceClient(t.Context(), -1); err == nil {
		t.Error("a negative index passed")
	}
}

func TestHostFakesRefuseDelayWhereTheyHaveNoParking(t *testing.T) {
	faults := NewFaultQueue()
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, Result: Delay}); err == nil {
		t.Error("armed a delay no host fake can carry out")
	}
}

func TestCrashAtAHostCallDiesThere(t *testing.T) {
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	host, clock, faults := newHostFixture(t)
	table := NewActorTable(clock, driver)
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: CrashAfterApply}); err != nil {
		t.Fatal(err)
	}
	networkId := connect.NewId()
	batch := &sidecar.UsageBatch{BatchId: connect.NewId(), Events: []*sidecar.UsageEvent{{NetworkId: networkId, Meter: "tls", TransferByteCount: 1}}}
	actor := table.Actor(t.Context(), "evs1")
	returned := false
	run := driver.Start(actor, func() error {
		err := host.Quota.ReportUsage(actor.Context(), batch)
		returned = true
		return fmt.Errorf("still here: %w", err)
	})
	awaitEnded(t, run)
	if run.Err() != nil || returned {
		t.Errorf("returned %v, err %v", returned, run.Err())
	}
	if got := host.Quota.TransferUsed(networkId, "tls"); got != 1 {
		t.Errorf("debited %d", got)
	}
}
