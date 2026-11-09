// §9.10's control-plane bound on a fake clock (D-SOCK-15): the burst, the rate, the edge rate, and a
// refusal that costs nothing.

package socketsservice_test

import (
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A random client id.
func testSocketId() connect.Id {
	return connect.Id(sidecar.NewId())
}

// A bound at the defaults on its own fake clock.
func testSocketBound() (*socketsservice.SocketControlBound, *sidecartest.FakeClock, *socketsservice.SocketControlBoundSettings) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := socketsservice.DefaultSocketControlBoundSettings()
	return socketsservice.NewSocketControlBound(settings, clock), clock, settings
}

// Charges count calls and returns how many were allowed.
func testSocketChargeCount(bound *socketsservice.SocketControlBound, clientId connect.Id, edge bool, count int) int {
	allowedCount := 0
	for range count {
		if allowed, _ := bound.Charge(clientId, edge); allowed {
			allowedCount += 1
		}
	}
	return allowedCount
}

func TestSocketControlBoundAllowsItsBurstAndNoMore(t *testing.T) {
	bound, clock, settings := testSocketBound()
	clientId := testSocketId()
	if allowedCount := testSocketChargeCount(bound, clientId, false, settings.Burst); allowedCount != settings.Burst {
		t.Fatalf("%d of the burst allowed", allowedCount)
	}
	allowed, retryAfter := bound.Charge(clientId, false)
	if allowed {
		t.Fatal("a call past the burst was allowed")
	}
	if want := time.Second / time.Duration(settings.CallsPerSecond); retryAfter != want {
		t.Fatalf("retry after %v, want %v", retryAfter, want)
	}
	clock.Advance(retryAfter - time.Nanosecond)
	if allowed, _ := bound.Charge(clientId, false); allowed {
		t.Fatal("a call before its token was allowed")
	}
	clock.Advance(time.Nanosecond)
	if allowed, _ := bound.Charge(clientId, false); !allowed {
		t.Fatal("a call at its token was refused")
	}
}

// After a burst of 500, 50 calls a second and no more (§9.10).
func TestSocketControlBoundRefillsAtItsRate(t *testing.T) {
	bound, clock, settings := testSocketBound()
	clientId := testSocketId()
	testSocketChargeCount(bound, clientId, false, settings.Burst)
	for second := range 5 {
		clock.Advance(time.Second)
		if allowedCount := testSocketChargeCount(bound, clientId, false, 2*settings.CallsPerSecond); allowedCount != settings.CallsPerSecond {
			t.Fatalf("second %d: %d allowed", second, allowedCount)
		}
	}
	// a long rest refills to the burst and no further
	clock.Advance(time.Hour)
	if allowedCount := testSocketChargeCount(bound, clientId, false, 2*settings.Burst); allowedCount != settings.Burst {
		t.Fatalf("after a rest, %d allowed", allowedCount)
	}
}

// A refused call takes no token, so a client hammering a full bucket waits no longer for it.
func TestSocketControlBoundRefusalTakesNoToken(t *testing.T) {
	bound, clock, settings := testSocketBound()
	clientId := testSocketId()
	testSocketChargeCount(bound, clientId, false, settings.Burst)
	if allowedCount := testSocketChargeCount(bound, clientId, false, 10000); allowedCount != 0 {
		t.Fatalf("%d allowed past the burst", allowedCount)
	}
	clock.Advance(time.Second / time.Duration(settings.CallsPerSecond))
	if allowed, _ := bound.Charge(clientId, false); !allowed {
		t.Fatal("refusals took tokens")
	}
}

func TestSocketControlBoundKeepsClientsApart(t *testing.T) {
	bound, _, settings := testSocketBound()
	firstId := testSocketId()
	testSocketChargeCount(bound, firstId, false, settings.Burst+1)
	if allowed, _ := bound.Charge(testSocketId(), false); !allowed {
		t.Fatal("one client's burst refused another")
	}
}

// W2's edge rate replaces the bucket for urnetwork-edge callers (§9.10, §19.5).
func TestSocketControlBoundGivesEdgesTheirRate(t *testing.T) {
	bound, clock, settings := testSocketBound()
	edgeId := testSocketId()
	if allowedCount := testSocketChargeCount(bound, edgeId, true, settings.EdgeBurst+10); allowedCount != settings.EdgeBurst {
		t.Fatalf("%d of an edge's burst allowed", allowedCount)
	}
	clock.Advance(time.Second)
	if allowedCount := testSocketChargeCount(bound, edgeId, true, 2*settings.EdgeCallsPerSecond); allowedCount != settings.EdgeCallsPerSecond {
		t.Fatalf("an edge's second allowed %d", allowedCount)
	}
}

// Buckets that refilled to full are dropped, so the map holds only recent clients.
func TestSocketControlBoundSweepsFullBuckets(t *testing.T) {
	bound, clock, settings := testSocketBound()
	for range 100 {
		bound.Charge(testSocketId(), false)
	}
	if count := bound.BucketCount(); count != 100 {
		t.Fatalf("%d buckets", count)
	}
	clock.Advance(settings.SweepInterval)
	bound.Charge(testSocketId(), false)
	if count := bound.BucketCount(); count != 1 {
		t.Fatalf("%d buckets after a sweep", count)
	}
}
