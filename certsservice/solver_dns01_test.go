// §13.8's fenced block on a scripted CertsDns and FakeClock: every wait the solver makes is a timer the
// test moves past, so each answer's handling is forced, not raced.

package certsservice_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"

	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A solver on a scripted DNS and a fake clock.
type testSolver struct {
	ctx      context.Context
	clock    *sidecartest.FakeClock
	dns      *sidecartest.FakeCertsDns
	settings *certsservice.CertsSettings
	solver   *certsservice.CertsDnsSolver
}

func newTestSolver(t *testing.T) *testSolver {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	dns := sidecartest.NewFakeCertsDns(clock)
	settings := testSettings()
	return &testSolver{ctx: ctx, clock: clock, dns: dns, settings: settings, solver: certsservice.NewCertsDnsSolver(dns, settings, clock)}
}

// A dns-01 challenge for name, as acmez hands one to a solver. A set's wildcard authorization names the
// same identifier with another token, so wildcard only tells a test's two apart.
func testChallenge(name string, token string, wildcard bool) acme.Challenge {
	return acme.Challenge{
		Type:             acme.ChallengeTypeDNS01,
		Token:            token,
		KeyAuthorization: token + ".thumbprint",
		Identifier:       acme.Identifier{Type: "dns", Value: name},
	}
}

// Runs call on its own goroutine and returns its answer's channel.
func testGo(call func() error) chan error {
	done := make(chan error, 1)
	go func() {
		done <- call()
	}()
	return done
}

// Waits for a timer at the clock's now plus timeout, then moves the clock past it.
func (self *testSolver) advancePast(t *testing.T, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, 30*time.Second)
	defer cancel()
	target := self.clock.Now().Add(timeout)
	for {
		pending, added := self.clock.WatchTimers()
		if slices.Contains(pending, target) {
			break
		}
		select {
		case <-added:
		case <-ctx.Done():
			t.Fatalf("no timer at %v; pending %v", target, pending)
		}
	}
	self.clock.Advance(timeout)
}

// The answer of done, failing the test past the guard.
func testAwait(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("the solver never returned")
	}
	return nil
}

// A set's name and wildcard share _acme-challenge.<name>: two writes, the second holding both values;
// the wait asks about the newest serial; the first cleanup leaves the other value, and the last
// removes the name.
func TestCertsDnsSolverSetAndWildcardShareAName(t *testing.T) {
	world := newTestSolver(t)
	name := "k5solver01." + testRoot
	base := testChallenge(name, "token-base", false)
	wildcard := testChallenge(name, "token-wild", true)
	if err := world.solver.Present(world.ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := world.solver.Present(world.ctx, wildcard); err != nil {
		t.Fatal(err)
	}
	values := world.dns.Values(name)
	if !slices.Equal(values, []string{base.DNS01KeyAuthorization(), wildcard.DNS01KeyAuthorization()}) {
		t.Fatalf("values %v", values)
	}
	if err := world.solver.Wait(world.ctx, base); err != nil {
		t.Fatal(err)
	}
	if serials := world.dns.ReadySerials(); !slices.Equal(serials, []uint64{2}) {
		t.Fatalf("ready asked about %v", serials)
	}
	if err := world.solver.CleanUp(world.ctx, base); err != nil {
		t.Fatal(err)
	}
	if _, removeCount, _ := world.dns.Counts(); removeCount != 0 || len(world.dns.Values(name)) == 0 {
		t.Fatal("the first cleanup took the name while the wildcard's value was in use")
	}
	if err := world.solver.CleanUp(world.ctx, wildcard); err != nil {
		t.Fatal(err)
	}
	if writeCount, removeCount, _ := world.dns.Counts(); writeCount != 2 || removeCount != 1 || 0 < len(world.dns.Names()) {
		t.Fatalf("writes %d, removes %d, names %v", writeCount, removeCount, world.dns.Names())
	}
}

// A 503 while a restore runs is tried again after DnsRetryDelay, then twice that, and the write lands.
func TestCertsDnsSolverRetriesWhileRestoring(t *testing.T) {
	world := newTestSolver(t)
	world.dns.ScriptWriteErrors(certsservice.ErrCertsDnsRestoring, certsservice.ErrCertsDnsRestoring)
	challenge := testChallenge("k5solver02."+testRoot, "token", false)
	done := testGo(func() error { return world.solver.Present(world.ctx, challenge) })
	world.advancePast(t, world.settings.DnsRetryDelay)
	world.advancePast(t, 2*world.settings.DnsRetryDelay)
	if err := testAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 3 {
		t.Fatalf("writes %d", writeCount)
	}
}

// stale is final for its serial: the same values are written again, once for each stale, and the
// wait follows the new serial until ready.
func TestCertsDnsSolverStaleWritesAgain(t *testing.T) {
	for _, staleCount := range []int{1, 2} {
		world := newTestSolver(t)
		for range staleCount {
			world.dns.ScriptReady(certsservice.CertsDnsStale)
		}
		name := "k5solver03." + testRoot
		challenge := testChallenge(name, "token", false)
		if err := world.solver.Present(world.ctx, challenge); err != nil {
			t.Fatal(err)
		}
		if err := world.solver.Wait(world.ctx, challenge); err != nil {
			t.Fatal(err)
		}
		writeCount, _, readyCount := world.dns.Counts()
		if writeCount != 1+staleCount || readyCount != 1+staleCount {
			t.Fatalf("%d stale: writes %d, ready asked %d", staleCount, writeCount, readyCount)
		}
		serials := world.dns.ReadySerials()
		for index := 1; index < len(serials); index += 1 {
			if serials[index] <= serials[index-1] {
				t.Fatalf("%d stale: the wait did not follow the new serial: %v", staleCount, serials)
			}
		}
		if !slices.Equal(world.dns.Values(name), []string{challenge.DNS01KeyAuthorization()}) {
			t.Fatalf("%d stale: the rewrite changed the values", staleCount)
		}
	}
}

// canary_failing holds the order with no new write until the canary is clean, and a ready answer
// whose canary reads not clean waits the same way; waiting asks again.
func TestCertsDnsSolverWaitsOnTheCanary(t *testing.T) {
	world := newTestSolver(t)
	world.dns.ScriptReady(certsservice.CertsDnsCanaryFailing, certsservice.CertsDnsWaiting)
	world.dns.ScriptCanaryClean(false)
	challenge := testChallenge("k5solver04."+testRoot, "token", false)
	if err := world.solver.Present(world.ctx, challenge); err != nil {
		t.Fatal(err)
	}
	done := testGo(func() error { return world.solver.Wait(world.ctx, challenge) })
	// canary_failing
	world.advancePast(t, world.settings.CanaryRetryDelay)
	// waiting
	world.advancePast(t, world.settings.DnsWaitingDelay)
	// ready, canary not clean
	world.advancePast(t, world.settings.CanaryRetryDelay)
	if err := testAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, readyCount := world.dns.Counts(); writeCount != 1 || readyCount != 4 {
		t.Fatalf("writes %d, ready asked %d", writeCount, readyCount)
	}
}

// Past 10 writes a name an hour the route refuses, and the solver fails at once rather than retrying.
func TestCertsDnsSolverWriteRefusedPastTheCap(t *testing.T) {
	world := newTestSolver(t)
	name := "k5solver05." + testRoot
	for index := range 10 {
		if _, err := world.dns.WriteAcmeChallenge(world.ctx, name, []string{"value"}); err != nil {
			t.Fatalf("write %d: %v", index, err)
		}
	}
	err := world.solver.Present(world.ctx, testChallenge(name, "token", false))
	if !errors.Is(err, certsservice.ErrCertsDnsWriteRefused) {
		t.Fatalf("an eleventh write in the hour: %v", err)
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 11 {
		t.Fatalf("the refusal was retried: %d writes", writeCount)
	}
	// an hour later the name takes writes again
	world.clock.Advance(time.Hour)
	if err := world.solver.Present(world.ctx, testChallenge(name, "token-2", false)); err != nil {
		t.Fatal(err)
	}
}

// A cleanup runs on its own context, so an order whose context ended still takes its challenge out.
func TestCertsDnsSolverCleanUpOutlivesTheOrder(t *testing.T) {
	world := newTestSolver(t)
	name := "k5solver06." + testRoot
	challenge := testChallenge(name, "token", false)
	if err := world.solver.Present(world.ctx, challenge); err != nil {
		t.Fatal(err)
	}
	orderCtx, cancel := context.WithCancel(world.ctx)
	cancel()
	if err := world.solver.CleanUp(orderCtx, challenge); err != nil {
		t.Fatal(err)
	}
	if 0 < len(world.dns.Names()) {
		t.Fatal("an ended order left its challenge")
	}
}
