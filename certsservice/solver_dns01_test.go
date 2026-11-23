// §13.8's fenced block on a scripted CertsDns and FakeClock: every wait the solver makes is a timer the
// test moves past, so each answer's handling is forced, not raced. A gated CertsDns holds a write once
// it is entered, so what comes while a write is under way is forced too.

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

// A CertsDns whose writes each stop once entered, telling the test the values they hold, until the test
// lets one through to the scripted DNS behind it.
type testGatedCertsDns struct {
	*sidecartest.FakeCertsDns
	entered chan []string
	release chan struct{}
}

func (self *testGatedCertsDns) WriteAcmeChallenge(ctx context.Context, name string, values []string) (uint64, error) {
	select {
	case self.entered <- slices.Clone(values):
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	select {
	case <-self.release:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	return self.FakeCertsDns.WriteAcmeChallenge(ctx, name, values)
}

// The values of the next write entered, failing the test past the guard.
func (self *testGatedCertsDns) awaitWrite(t *testing.T) []string {
	t.Helper()
	select {
	case values := <-self.entered:
		return values
	case <-time.After(30 * time.Second):
		t.Fatal("no write came")
	}
	return nil
}

// Lets the write entered through.
func (self *testGatedCertsDns) letThrough(t *testing.T) {
	t.Helper()
	select {
	case self.release <- struct{}{}:
	case <-time.After(30 * time.Second):
		t.Fatal("no write to let through")
	}
}

// A solver whose writes stop at a gate before the scripted DNS.
func newTestGatedSolver(t *testing.T) (*testSolver, *testGatedCertsDns) {
	t.Helper()
	world := newTestSolver(t)
	gated := &testGatedCertsDns{FakeCertsDns: world.dns, entered: make(chan []string), release: make(chan struct{})}
	world.solver = certsservice.NewCertsDnsSolver(gated, world.settings, world.clock)
	return world, gated
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

// Waits for a timer at the clock's now plus timeout.
func (self *testSolver) awaitTimer(t *testing.T, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, 30*time.Second)
	defer cancel()
	target := self.clock.Now().Add(timeout)
	for {
		pending, added := self.clock.WatchTimers()
		if slices.Contains(pending, target) {
			return
		}
		select {
		case <-added:
		case <-ctx.Done():
			t.Fatalf("no timer at %v; pending %v", target, pending)
		}
	}
}

// Waits for a timer at the clock's now plus timeout, then moves the clock past it.
func (self *testSolver) advancePast(t *testing.T, timeout time.Duration) {
	t.Helper()
	self.awaitTimer(t, timeout)
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

// A set's name and wildcard share _acme-challenge.<name>, and an order writes it once (QD-1189): the two
// presents write nothing, the first wait writes both values and asks about that serial, and the second
// wait writes nothing more; the first cleanup leaves the other value, and the last removes the name.
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
	if writeCount, _, _ := world.dns.Counts(); writeCount != 0 || 0 < len(world.dns.Names()) {
		t.Fatalf("the presents wrote: %d writes, names %v", writeCount, world.dns.Names())
	}
	if err := world.solver.Wait(world.ctx, base); err != nil {
		t.Fatal(err)
	}
	values := world.dns.Values(name)
	if !slices.Equal(values, []string{base.DNS01KeyAuthorization(), wildcard.DNS01KeyAuthorization()}) {
		t.Fatalf("values %v", values)
	}
	if err := world.solver.Wait(world.ctx, wildcard); err != nil {
		t.Fatal(err)
	}
	if serials := world.dns.ReadySerials(); !slices.Equal(serials, []uint64{1, 1}) {
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
	if writeCount, removeCount, _ := world.dns.Counts(); writeCount != 1 || removeCount != 1 || 0 < len(world.dns.Names()) {
		t.Fatalf("writes %d, removes %d, names %v", writeCount, removeCount, world.dns.Names())
	}
}

// A 503 while a restore runs is tried again after DnsRetryDelay, then twice that, and the write lands.
func TestCertsDnsSolverRetriesWhileRestoring(t *testing.T) {
	world := newTestSolver(t)
	world.dns.ScriptWriteErrors(certsservice.ErrCertsDnsRestoring, certsservice.ErrCertsDnsRestoring)
	challenge := testChallenge("k5solver02."+testRoot, "token", false)
	if err := world.solver.Present(world.ctx, challenge); err != nil {
		t.Fatal(err)
	}
	done := testGo(func() error { return world.solver.Wait(world.ctx, challenge) })
	world.advancePast(t, world.settings.DnsRetryDelay)
	world.advancePast(t, 2*world.settings.DnsRetryDelay)
	if err := testAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 3 {
		t.Fatalf("writes %d", writeCount)
	}
}

// A write tried again after a restore's 503 sends what the name holds by then: a wildcard presented while
// the base's write waits goes in the same write, and its wait writes nothing.
func TestCertsDnsSolverRetryAfterARestoreSendsTheValuesPresentedMeanwhile(t *testing.T) {
	world := newTestSolver(t)
	world.dns.ScriptWriteErrors(certsservice.ErrCertsDnsRestoring)
	name := "k5solver08." + testRoot
	base := testChallenge(name, "token-base", false)
	wildcard := testChallenge(name, "token-wild", true)
	if err := world.solver.Present(world.ctx, base); err != nil {
		t.Fatal(err)
	}
	done := testGo(func() error { return world.solver.Wait(world.ctx, base) })
	// the 503's wait is under way once its timer is
	world.awaitTimer(t, world.settings.DnsRetryDelay)
	if err := world.solver.Present(world.ctx, wildcard); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(world.settings.DnsRetryDelay)
	if err := testAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if err := world.solver.Wait(world.ctx, wildcard); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 2 {
		t.Fatalf("writes %d, the 503 among them", writeCount)
	}
	if values := world.dns.Values(name); !slices.Equal(values, []string{base.DNS01KeyAuthorization(), wildcard.DNS01KeyAuthorization()}) {
		t.Fatalf("values %v", values)
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

// Past 10 writes a name an hour the route refuses, and the wait fails at once rather than retrying, with
// the refusal of its own that names the name and how long until it takes a write again (QD-1204); the
// order's cleanup takes the name out, since a write was sent there.
func TestCertsDnsSolverWriteRefusedPastTheCap(t *testing.T) {
	world := newTestSolver(t)
	name := "k5solver05." + testRoot
	for index := range 10 {
		if _, err := world.dns.WriteAcmeChallenge(world.ctx, name, []string{"value"}); err != nil {
			t.Fatalf("write %d: %v", index, err)
		}
		world.clock.Advance(time.Minute)
	}
	challenge := testChallenge(name, "token", false)
	if err := world.solver.Present(world.ctx, challenge); err != nil {
		t.Fatal(err)
	}
	err := world.solver.Wait(world.ctx, challenge)
	var rateLimit *certsservice.CertsDnsWriteRateLimitError
	if !errors.Is(err, certsservice.ErrCertsDnsWriteRefused) || !errors.Is(err, certsservice.ErrCertsDnsWriteRateLimited) || !errors.As(err, &rateLimit) {
		t.Fatalf("an eleventh write in the hour: %v", err)
	}
	// the first write, ten minutes back, leaves the hour in fifty
	if rateLimit.Name != name || rateLimit.RetryAfter != 50*time.Minute {
		t.Fatalf("the refusal named %q, %v", rateLimit.Name, rateLimit.RetryAfter)
	}
	if writeCount, _, readyCount := world.dns.Counts(); writeCount != 11 || readyCount != 0 {
		t.Fatalf("the refusal was retried or waited on: %d writes, ready asked %d", writeCount, readyCount)
	}
	if err := world.solver.CleanUp(world.ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, removeCount, _ := world.dns.Counts(); removeCount != 1 || 0 < len(world.dns.Names()) {
		t.Fatalf("removes %d, names %v", removeCount, world.dns.Names())
	}
	// an hour later the name takes writes again
	world.clock.Advance(time.Hour)
	next := testChallenge(name, "token-2", false)
	if err := world.solver.Present(world.ctx, next); err != nil {
		t.Fatal(err)
	}
	if err := world.solver.Wait(world.ctx, next); err != nil {
		t.Fatal(err)
	}
}

// A write that failed is still owed: the next wait on the name makes it.
func TestCertsDnsSolverFailedWriteIsOwedToTheNextWait(t *testing.T) {
	world := newTestSolver(t)
	world.dns.ScriptWriteErrors(errors.New("the answer was lost"))
	name := "k5solver09." + testRoot
	challenge := testChallenge(name, "token", false)
	if err := world.solver.Present(world.ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if err := world.solver.Wait(world.ctx, challenge); err == nil {
		t.Fatal("a failed write answered nothing")
	}
	if err := world.solver.Wait(world.ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 2 || !slices.Equal(world.dns.Values(name), []string{challenge.DNS01KeyAuthorization()}) {
		t.Fatalf("writes %d, values %v", writeCount, world.dns.Values(name))
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
	if err := world.solver.Wait(world.ctx, challenge); err != nil {
		t.Fatal(err)
	}
	orderCtx, cancel := context.WithCancel(world.ctx)
	cancel()
	if err := world.solver.CleanUp(orderCtx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, removeCount, _ := world.dns.Counts(); removeCount != 1 || 0 < len(world.dns.Names()) {
		t.Fatalf("an ended order left its challenge: removes %d, names %v", removeCount, world.dns.Names())
	}
}

// An order that ends before it waits, as one whose second present was refused does, wrote nothing at its
// name and removes nothing there.
func TestCertsDnsSolverCleanUpBeforeAnyWriteTouchesNoZone(t *testing.T) {
	world := newTestSolver(t)
	name := "k5solver10." + testRoot
	base := testChallenge(name, "token-base", false)
	wildcard := testChallenge(name, "token-wild", true)
	for _, challenge := range []acme.Challenge{base, wildcard} {
		if err := world.solver.Present(world.ctx, challenge); err != nil {
			t.Fatal(err)
		}
	}
	for _, challenge := range []acme.Challenge{base, wildcard} {
		if err := world.solver.CleanUp(world.ctx, challenge); err != nil {
			t.Fatal(err)
		}
	}
	if writeCount, removeCount, readyCount := world.dns.Counts(); writeCount != 0 || removeCount != 0 || readyCount != 0 {
		t.Fatalf("writes %d, removes %d, ready asked %d", writeCount, removeCount, readyCount)
	}
}

// A name holds DnsChallengeValueMaxCount values: a third present is refused, and its order's cleanup leaves
// the other two, which the first order's wait writes in one write. A wait for a value never presented
// writes nothing.
func TestCertsDnsSolverRefusesAThirdValue(t *testing.T) {
	world := newTestSolver(t)
	name := "k5solver11." + testRoot
	base := testChallenge(name, "token-base", false)
	wildcard := testChallenge(name, "token-wild", true)
	third := testChallenge(name, "token-third", false)
	for _, challenge := range []acme.Challenge{base, wildcard} {
		if err := world.solver.Present(world.ctx, challenge); err != nil {
			t.Fatal(err)
		}
	}
	if err := world.solver.Present(world.ctx, third); err == nil {
		t.Fatal("a third value was taken")
	}
	if err := world.solver.CleanUp(world.ctx, third); err != nil {
		t.Fatal(err)
	}
	if err := world.solver.Wait(world.ctx, third); err == nil {
		t.Fatal("a wait for a value never presented answered ready")
	}
	if err := world.solver.Wait(world.ctx, base); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 1 || !slices.Equal(world.dns.Values(name), []string{base.DNS01KeyAuthorization(), wildcard.DNS01KeyAuthorization()}) {
		t.Fatalf("writes %d, values %v", writeCount, world.dns.Values(name))
	}
}

// A value presented while the name's write is under way is not in it, so it is owed a write of its own,
// which the wait makes before it asks about a serial; the value's own wait then writes nothing.
func TestCertsDnsSolverValuePresentedDuringAWriteIsWrittenAgain(t *testing.T) {
	world, gated := newTestGatedSolver(t)
	name := "k5solver07." + testRoot
	base := testChallenge(name, "token-base", false)
	wildcard := testChallenge(name, "token-wild", true)
	if err := world.solver.Present(world.ctx, base); err != nil {
		t.Fatal(err)
	}
	done := testGo(func() error { return world.solver.Wait(world.ctx, base) })
	if values := gated.awaitWrite(t); !slices.Equal(values, []string{base.DNS01KeyAuthorization()}) {
		t.Fatalf("the first write holds %v", values)
	}
	if err := world.solver.Present(world.ctx, wildcard); err != nil {
		t.Fatal(err)
	}
	gated.letThrough(t)
	if values := gated.awaitWrite(t); !slices.Equal(values, []string{base.DNS01KeyAuthorization(), wildcard.DNS01KeyAuthorization()}) {
		t.Fatalf("the second write holds %v", values)
	}
	gated.letThrough(t)
	if err := testAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if err := world.solver.Wait(world.ctx, wildcard); err != nil {
		t.Fatal(err)
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 2 {
		t.Fatalf("writes %d", writeCount)
	}
	if serials := world.dns.ReadySerials(); !slices.Equal(serials, []uint64{2, 2}) {
		t.Fatalf("ready asked about %v", serials)
	}
}

// Two waits on one name while its write is under way: whichever way the second runs, it waits for that
// write rather than making another, and both go on to that serial.
func TestCertsDnsSolverWaitsOnANameShareTheWriteUnderWay(t *testing.T) {
	world, gated := newTestGatedSolver(t)
	name := "k5solver12." + testRoot
	base := testChallenge(name, "token-base", false)
	wildcard := testChallenge(name, "token-wild", true)
	for _, challenge := range []acme.Challenge{base, wildcard} {
		if err := world.solver.Present(world.ctx, challenge); err != nil {
			t.Fatal(err)
		}
	}
	first := testGo(func() error { return world.solver.Wait(world.ctx, base) })
	if values := gated.awaitWrite(t); len(values) != 2 {
		t.Fatalf("the write holds %v", values)
	}
	second := testGo(func() error { return world.solver.Wait(world.ctx, wildcard) })
	gated.letThrough(t)
	for _, done := range []chan error{first, second} {
		if err := testAwait(t, done); err != nil {
			t.Fatal(err)
		}
	}
	if writeCount, _, _ := world.dns.Counts(); writeCount != 1 {
		t.Fatalf("writes %d", writeCount)
	}
	if serials := world.dns.ReadySerials(); !slices.Equal(serials, []uint64{1, 1}) {
		t.Fatalf("ready asked about %v", serials)
	}
}
