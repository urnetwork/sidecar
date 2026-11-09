// Caps per network loaded off the path through ServiceHost.Quota.Limits (reading 11), on FakeQuota and
// FakeClock.

package tlsedgeservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// pro.yml's Team caps with the sidecar_abuse visitor caps, as Quota.Limits answers them.
func testTeamQuotaLimits() *sidecar.QuotaLimits {
	return &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{
		"tls_endpoint_concurrent":        8192,
		"tls_endpoint_new_per_s":         1000,
		"tls_endpoint_mbit_per_s":        1000,
		"tls_visitor_concurrent":         64,
		"tls_visitor_new_per_s":          20,
		"tls_visitor_aggregate_multiple": 4,
	}}
}

// A cold network gets Community's caps at once, never a refusal, and its tier's once a load lands; §21's
// tightening lands at the next refresh.
func TestTlsEdgeLimitsColdThenTier(t *testing.T) {
	world := newTestServiceWorld(t, sidecartest.NewFakeTlsEdgeStore(nil), newTestServiceDialer(4))
	networkId := sidecar.NewId()
	world.host.Quota.SetLimits(connect.Id(networkId), testTeamQuotaLimits())
	passes := world.service.LimitsPassCountForTest()
	// the loader's first pass ran before any network was asked for
	testAwaitCount(t, passes, 1)
	before := passes.Value()

	cold := world.service.EndpointLimits(networkId)
	if *cold != *tlsedgeservice.DefaultColdTlsEndpointLimits() {
		t.Fatalf("a cold network got %+v", cold)
	}
	// the cold read woke the loader, which loads it with no clock moved
	testAwaitCount(t, passes, before+1)
	loaded := world.service.EndpointLimits(networkId)
	if loaded.EndpointConcurrent != 8192 || loaded.EndpointNewPerS != 1000 || loaded.EndpointMbitPerS != 1000 || loaded.VisitorConcurrent != 64 {
		t.Fatalf("the tier's caps did not land: %+v", loaded)
	}

	// §21 tightens the network: it lands at the next refresh
	tightened := testTeamQuotaLimits()
	tightened.Limits["tls_endpoint_concurrent"] = 16
	tightened.Limits["tls_visitor_concurrent"] = 2
	world.host.Quota.SetLimits(connect.Id(networkId), tightened)
	passCount := passes.Value()
	// the count rises only once the next pass's wait is armed
	world.clock.Advance(5 * time.Second)
	testAwaitCount(t, passes, passCount+1)
	if limits := world.service.EndpointLimits(networkId); limits.EndpointConcurrent != 16 || limits.VisitorConcurrent != 2 {
		t.Fatalf("the tightening did not land: %+v", limits)
	}
}

// A load that fails keeps what the network had: cold stays cold, and loaded caps stay loaded.
func TestTlsEdgeLimitsFailedLoadKeepsLast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	faults := sidecartest.NewFaultQueue()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, faults, nil, nil)
	service, err := tlsedgeservice.NewTlsEdgeService(ctx, host.ServiceHost(), sidecartest.NewFakeTlsEdgeStore(nil), newTestServiceDialer(4), testServiceSettings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	networkId := sidecar.NewId()
	host.Quota.SetLimits(connect.Id(networkId), testTeamQuotaLimits())
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.Limits", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	passes := service.LimitsPassCountForTest()
	testAwaitCount(t, passes, 1)
	before := passes.Value()
	service.EndpointLimits(networkId)
	testAwaitCount(t, passes, before+1)
	if limits := service.EndpointLimits(networkId); *limits != *tlsedgeservice.DefaultColdTlsEndpointLimits() {
		t.Fatalf("a failed load left %+v", limits)
	}
}
