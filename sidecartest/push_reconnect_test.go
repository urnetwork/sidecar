package sidecartest

// §6.8's reconnect on the connect legs (QD-906) on T2, through a real Sidecar's generation and push
// client: the Net's api refuses the push's versions refetches until it waits out the longest retry,
// RetryMaxInterval on the Net's clock, which only the test moves; the platform then cuts the client off
// and lets it back, and the connect generation's reconnect, PushClient.Resync, refetches at once, the
// clock unmoved. push_poll_retry_test.go holds the rest of the retry rules, on the long-poll client.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Waits until a timer due at is pending on clock, or guard ends the wait.
func awaitPushTimerAt(t *testing.T, clock *FakeClock, at time.Time, guard <-chan time.Time) {
	t.Helper()
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-guard:
			t.Fatalf("no timer at %s: %v", at, pending)
		}
	}
}

func TestPushPlatformReconnectEndsTheRetryWait(t *testing.T) {
	net := newTestNet(t)
	ctx, cancel := context.WithTimeout(t.Context(), testPushTimeout)
	defer cancel()
	settings := sidecar.DefaultPushClientSettings()
	// one plan for each refetch refused, the start's first, each taking its own match of the route, armed
	// before the sidecar starts so the requests they count are the push's
	type pushRefusal struct {
		refused <-chan struct{}
		// the retry wait it starts
		wait time.Duration
	}
	refusals := []pushRefusal{}
	for wait := settings.RetryMinInterval; ; wait = min(2*wait, settings.RetryMaxInterval) {
		refused, err := net.Faults().Add(&FaultPlan{Op: FaultOpHttp, KeyPrefix: "/sidecar/sync/versions", Nth: len(refusals) + 1, Result: FailBeforeApply})
		if err != nil {
			t.Fatal(err)
		}
		refusals = append(refusals, pushRefusal{refused: refused, wait: wait})
		if wait == settings.RetryMaxInterval {
			break
		}
	}
	sidecars, _, err := net.AddSubprotocolSidecars("laptop")
	if err != nil {
		t.Fatal(err)
	}
	laptop := sidecars[0]
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	// every applied refetch gives core a notice, and nothing else here does
	cores := make(chan sidecar.PushNotice, 16)
	if _, err := laptop.Subprotocol().Subscribe(sidecar.PushTopicCore, func(notice sidecar.PushNotice) {
		select {
		case cores <- notice:
		default:
			t.Errorf("the test's notices are full")
		}
	}); err != nil {
		t.Fatal(err)
	}

	// each refusal's wait is set on a clock standing where it stood at the refusal, and the test moves it
	// to the end of every wait but the longest
	clock := net.Clock()
	guard := time.After(testPushTimeout)
	retryTime := time.Time{}
	for i, refusal := range refusals {
		select {
		case <-refusal.refused:
		case <-guard:
			t.Fatalf("refusal %d of %d never came", i+1, len(refusals))
		}
		retryTime = clock.Now().Add(refusal.wait)
		awaitPushTimerAt(t, clock, retryTime, guard)
		if i < len(refusals)-1 {
			clock.AdvanceTo(retryTime)
		}
	}
	waitTime := clock.Now()
	if wait := retryTime.Sub(waitTime); wait != 5*time.Minute {
		t.Fatalf("the longest wait is %s", wait)
	}
	versionsBefore := api.RouteCount("GET /sidecar/sync/versions")
	expectNoTopicNotice(t, cores, sidecar.PushTopicCore)

	laptop.SetPlatformReachable(false)
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateOffline); err != nil {
		t.Fatal(err)
	}
	laptop.SetPlatformReachable(true)
	if err := laptop.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	if notice := awaitNotice(t, cores, "the reconnect's refetch"); !notice.Resync {
		t.Errorf("core's notice is no refetch's: %+v", notice)
	}
	if versionCount := api.RouteCount("GET /sidecar/sync/versions"); versionCount != versionsBefore+1 {
		t.Errorf("%d versions refetches served after the reconnect, want 1", versionCount-versionsBefore)
	}
	if !clock.Now().Equal(waitTime) || !slices.ContainsFunc(clock.PendingTimers(), retryTime.Equal) {
		t.Errorf("the clock moved to %s, its wait ending at %s: %v", clock.Now(), retryTime, clock.PendingTimers())
	}
	if status := laptop.Sidecar().Status(); status.Generation != 1 {
		t.Errorf("the reconnect took generation %d", status.Generation)
	}
}
