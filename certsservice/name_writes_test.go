// dns's refusal of a challenge write past dns_challenges_per_name_hour holds the name's orders (QD-1204),
// on the chains' scripted CA and a fake clock: the order queues again and the name's next order goes to
// no CA until dns's Retry-After and the margin have passed, or NameWritesHold when dns named none; the
// hold is the process's, so a restart forgets it and the next refusal sets it again; it holds by
// challenge name, so another network's set and a scope's set go while a set sharing the name waits, a
// renewal too; and a refusal that names no name holds every name of the order. On Pebble, the order's
// failure carries the refused name up through the solver and acmez, and a set past the cap sends one
// newOrder a refusal. Nothing here sleeps.

package certsservice_test

import (
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The error an order meets when dns refused its challenge write at name past the name's writes an hour,
// as acmez and the solver wrap the DNS client's.
func testNameWritesRefused(name string, retryAfter time.Duration) error {
	return fmt.Errorf(
		"solving challenges: waiting for solver *certsservice.CertsDnsSolver to be ready: writing the challenge: %w (order=https://ca.example/order/1)",
		&certsservice.CertsDnsWriteRateLimitError{Name: name, RetryAfter: retryAfter},
	)
}

// The wait of certId in waits, nil for none.
func testWaitOf(waits []*certsservice.CertsWait, certId sidecar.Id) *certsservice.CertsWait {
	for _, wait := range waits {
		if wait.CertId == certId {
			return wait
		}
	}
	return nil
}

// A set whose challenge write dns refused past the cap sends no further newOrder until the hold ends,
// which is dns's Retry-After and the margin: a pass a millisecond before leaves the row waiting with no CA
// asked, and the pass at the time orders and issues it.
func TestCertsNameWritesHoldSendsNoNewOrderUntilItEnds(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k8nmwr01")
	certId := run.accept(device)
	retryAfter := 23*time.Minute + 17*time.Second
	run.acme.script(testNameWritesRefused("k8nmwr01."+testRoot, retryAfter))
	refusedAt := run.clock.Now()

	report := run.runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{certId}) || !slices.Equal(report.Requeued, []sidecar.Id{certId}) || len(report.Issued) != 0 {
		t.Fatalf("the refused pass: %+v", report)
	}
	if state := run.row(certId).State; state != sidecar.TlsCertStateQueued {
		t.Fatalf("state %s", state)
	}
	until := refusedAt.Add(retryAfter + run.settings.RetryAfterMargin)
	for _, at := range []time.Time{refusedAt, until.Add(-time.Millisecond)} {
		run.clock.AdvanceTo(at)
		report = run.runOrders()
		wait := testWaitOf(report.Waiting, certId)
		if len(report.Admitted) != 0 || wait == nil || wait.Reason != certsservice.CertsWaitNameWrites || !wait.Until.Equal(until) {
			t.Fatalf("at %v: %+v, wait %+v", at.Sub(refusedAt), report, wait)
		}
		if orders := run.acme.ordered(); len(orders) != 1 {
			t.Fatalf("at %v a held name sent %d orders", at.Sub(refusedAt), len(orders))
		}
	}
	run.clock.AdvanceTo(until)
	report = run.runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{certId}) || !slices.Equal(report.Issued, []sidecar.Id{certId}) {
		t.Fatalf("once the hold ended: %+v", report)
	}
	if orders := run.acme.ordered(); len(orders) != 2 {
		t.Fatalf("%d orders", len(orders))
	}
}

// A refusal whose 429 named no Retry-After holds the name NameWritesHold, an hour by default, with no
// margin, as a CA's refusal with none holds DefaultRetryAfter; a second refusal while held never shortens
// the hold.
func TestCertsNameWritesHoldWithNoRetryAfterHoldsTheCapsWindow(t *testing.T) {
	run := newTestRun(t, nil)
	if run.settings.NameWritesHold != time.Hour {
		t.Fatalf("NameWritesHold %v", run.settings.NameWritesHold)
	}
	device := run.device("k8nmwr02")
	certId := run.accept(device)
	run.acme.script(testNameWritesRefused("k8nmwr02."+testRoot, 0))
	refusedAt := run.clock.Now()
	if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{certId}) {
		t.Fatalf("the refused pass: %+v", report)
	}
	// a shorter hold set later leaves the longer one
	run.service.HoldChallengeName("k8nmwr02."+testRoot, time.Minute)
	report := run.runOrders()
	if wait := testWaitOf(report.Waiting, certId); wait == nil || wait.Reason != certsservice.CertsWaitNameWrites || !wait.Until.Equal(refusedAt.Add(time.Hour)) {
		t.Fatalf("waits %+v", report.Waiting)
	}
	run.clock.AdvanceTo(refusedAt.Add(time.Hour))
	if report := run.runOrders(); !slices.Equal(report.Issued, []sidecar.Id{certId}) {
		t.Fatalf("an hour on: %+v", report)
	}
}

// The hold is the process's, as a CA's is: a service over the same store and Redis, a restart, admits the
// row and orders it again, and dns's next refusal sets the hold again there.
func TestCertsNameWritesHoldIsForgottenOnARestart(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k8nmwr03")
	certId := run.accept(device)
	name := "k8nmwr03." + testRoot
	run.acme.script(testNameWritesRefused(name, 40*time.Minute))
	if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{certId}) {
		t.Fatalf("the refused pass: %+v", report)
	}
	if report := run.runOrders(); testWaitReasons(report.Waiting)[certId] != certsservice.CertsWaitNameWrites {
		t.Fatalf("before the restart: %+v", report)
	}

	restarted, err := certsservice.NewCertsService(run.ctx, run.host.ServiceHost(), run.store, nil, run.acme, run.settings)
	if err != nil {
		t.Fatal(err)
	}
	run.acme.script(testNameWritesRefused(name, 40*time.Minute))
	report, err := restarted.RunOrders(run.ctx, sidecar.Id{})
	if err != nil || !slices.Equal(report.Admitted, []sidecar.Id{certId}) || !slices.Equal(report.Requeued, []sidecar.Id{certId}) {
		t.Fatalf("after the restart: %+v, %v", report, err)
	}
	if orders := run.acme.ordered(); len(orders) != 2 {
		t.Fatalf("%d orders", len(orders))
	}
	report, err = restarted.RunOrders(run.ctx, sidecar.Id{})
	if err != nil || len(report.Admitted) != 0 || testWaitReasons(report.Waiting)[certId] != certsservice.CertsWaitNameWrites {
		t.Fatalf("the restarted service's next pass: %+v, %v", report, err)
	}
	if orders := run.acme.ordered(); len(orders) != 2 {
		t.Fatalf("the hold set again sent %d orders", len(orders))
	}
}

// A hold is a challenge name's: while the network's pair is held, another network's set and the network's
// scope set, whose names it does not share, go in the same pass, while a set with a live alias's pair
// beside the network's, which validates at the held name too, waits.
func TestCertsNameWritesHoldLeavesOtherNamesAlone(t *testing.T) {
	run := newTestRun(t, nil)
	held := run.device("k8nmwr04")
	heldId := run.accept(held)
	run.acme.script(testNameWritesRefused("k8nmwr04."+testRoot, 30*time.Minute))
	if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{heldId}) {
		t.Fatalf("the refused pass: %+v", report)
	}

	scopeSet, err := sidecar.TlsIdentifierSet(testRoot, "k8nmwr04", "team-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	aliasSet, err := sidecar.TlsIdentifierSet(testRoot, "k8nmwr04", "", []string{"k8nmwr04-alias"})
	if err != nil {
		t.Fatal(err)
	}
	otherId := run.accept(run.device("k8nmwr05"))
	scopeId := run.accept(newTestDeviceOf(t, held.networkId, scopeSet))
	aliasId := run.accept(newTestDeviceOf(t, held.networkId, aliasSet))
	report := run.runOrders()
	slices.SortFunc(report.Issued, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
	if !slices.Equal(report.Admitted, []sidecar.Id{otherId, scopeId}) || !slices.Equal(report.Issued, []sidecar.Id{otherId, scopeId}) {
		t.Fatalf("beside the held name: %+v", report)
	}
	reasons := testWaitReasons(report.Waiting)
	if len(reasons) != 2 || reasons[heldId] != certsservice.CertsWaitNameWrites || reasons[aliasId] != certsservice.CertsWaitNameWrites {
		t.Fatalf("waits %v", reasons)
	}
}

// A renewal writes its set's name as any order does, so the held name holds it too, past the holds it
// otherwise skips; once the hold ends it goes to its certificate's CA with its replaces.
func TestCertsNameWritesHoldHoldsARenewal(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k8nmwr06")
	serial := big.NewInt(0x5e7a06)
	run.issuedWithChain(device, certsservice.CertsCaLetsEncrypt, serial)
	run.clock.Advance(time.Millisecond)
	retryAfter := 10 * time.Minute
	run.service.HoldChallengeName("*.k8nmwr06."+testRoot, retryAfter)
	until := run.clock.Now().Add(retryAfter + run.settings.RetryAfterMargin)

	renewal := device.order(t)
	renewal.Args.Replaces = testCertificateId(run.acme.issuer.SubjectKeyId, serial)
	renewalResult, err := run.service.Accept(run.ctx, renewal)
	if err != nil {
		t.Fatal(err)
	}
	report := run.runOrders()
	if wait := testWaitOf(report.Waiting, renewalResult.CertId); len(report.Admitted) != 0 || wait == nil || wait.Reason != certsservice.CertsWaitNameWrites || !wait.Until.Equal(until) {
		t.Fatalf("while held: %+v", report)
	}
	run.clock.AdvanceTo(until)
	report = run.runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{renewalResult.CertId}) || !slices.Equal(report.Issued, []sidecar.Id{renewalResult.CertId}) {
		t.Fatalf("once the hold ended: %+v", report)
	}
	orders := run.acme.ordered()
	if len(orders) != 1 || orders[0].Ca != certsservice.CertsCaLetsEncrypt || orders[0].Replaces != renewal.Args.Replaces {
		t.Fatalf("orders %+v", orders)
	}
}

// A refusal that names no name, ErrCertsDnsWriteRateLimited with no CertsDnsWriteRateLimitError, holds
// every challenge name of the order for NameWritesHold, so a set with an alias's pair holds both of its
// names: the network's own pair waits too.
func TestCertsNameWritesRefusalNamingNoNameHoldsEveryName(t *testing.T) {
	run := newTestRun(t, nil)
	network := run.device("k8nmwr07")
	aliasSet, err := sidecar.TlsIdentifierSet(testRoot, "k8nmwr07", "", []string{"k8nmwr07-alias"})
	if err != nil {
		t.Fatal(err)
	}
	aliasId := run.accept(newTestDeviceOf(t, network.networkId, aliasSet))
	run.acme.script(fmt.Errorf("writing the challenge: %w", certsservice.ErrCertsDnsWriteRateLimited))
	refusedAt := run.clock.Now()
	if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{aliasId}) {
		t.Fatalf("the refused pass: %+v", report)
	}
	// a set of the alias's pair alone shares only the alias's name
	aliasOnly := newTestDeviceOf(t, network.networkId, []string{"*.k8nmwr07-alias." + testRoot, "k8nmwr07-alias." + testRoot})
	networkId := run.accept(network)
	aliasOnlyId := run.accept(aliasOnly)
	report := run.runOrders()
	if len(report.Admitted) != 0 {
		t.Fatalf("a held name was admitted: %+v", report)
	}
	for _, certId := range []sidecar.Id{aliasId, networkId, aliasOnlyId} {
		if wait := testWaitOf(report.Waiting, certId); wait == nil || wait.Reason != certsservice.CertsWaitNameWrites || !wait.Until.Equal(refusedAt.Add(run.settings.NameWritesHold)) {
			t.Fatalf("%s waits %+v", certId, wait)
		}
	}
}

// On Pebble, with the network's _acme-challenge name at its ten writes in the fake dns's hour: an order of
// a set with a live alias's pair beside the network's sends its newOrder, its write at the network's name
// is refused, and the refusal reaches the order pass through the solver and acmez naming that name and
// dns's Retry-After (NameWritesHold is set far from it, so a hold that read neither would show), so the row
// queues again held by that name alone: the next pass sends it no newOrder, while a set of the alias's
// pair alone, whose name holds writes, orders and issues. Once the hold has ended the next newOrder goes
// and, the window still full, is refused and held again: one newOrder a refusal, never one a pass.
func TestCertsNameWritesHoldOnPebble(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	settings.NameWritesHold = 5 * time.Hour
	ctx := testAcmeContext(t)
	start := time.Now().UTC().Truncate(time.Microsecond)
	clock := sidecartest.NewFakeClock(start)
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterCertsBudgetTwins(host.Redis)
	store := sidecartest.NewFakeCertsStore(host.Redis.Faults())
	acme := &testCountingAcme{CertsAcme: testAcme(t, settings, pebble, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))}
	service, err := certsservice.NewCertsService(ctx, host.ServiceHost(), store, nil, acme, settings)
	if err != nil {
		t.Fatal(err)
	}
	certs := &testCerts{t: t, ctx: ctx, clock: clock, host: host, store: store, settings: settings, service: service}

	aliasSet, err := sidecar.TlsIdentifierSet(testRoot, "k8nmwr08", "", []string{"k8nmwr08-alias"})
	if err != nil {
		t.Fatal(err)
	}
	device := newTestDeviceOf(t, sidecar.NewId(), aliasSet)
	name := "k8nmwr08." + testRoot
	for index := range 10 {
		if _, err := pebble.Dns.WriteAcmeChallenge(ctx, name, []string{fmt.Sprintf("earlier-%d", index)}); err != nil {
			t.Fatalf("write %d: %v", index+1, err)
		}
	}
	certId := certs.accept(device)

	runOrders := func() *certsservice.CertsOrdersReport {
		t.Helper()
		report, err := service.RunOrders(ctx, sidecar.Id{})
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	report := runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{certId}) || !slices.Equal(report.Requeued, []sidecar.Id{certId}) || acme.orderCount() != 1 {
		t.Fatalf("the refused pass: %+v, %d orders", report, acme.orderCount())
	}

	aliasOnly := newTestDeviceOf(t, device.networkId, []string{"*.k8nmwr08-alias." + testRoot, "k8nmwr08-alias." + testRoot})
	aliasOnlyId := certs.accept(aliasOnly)
	report = runOrders()
	wait := testWaitOf(report.Waiting, certId)
	// the fake dns's Retry-After is read on real time: an hour from its first write, less what has passed
	if wait == nil || wait.Reason != certsservice.CertsWaitNameWrites || !wait.Until.After(start) || wait.Until.After(start.Add(time.Hour+settings.RetryAfterMargin)) {
		t.Fatalf("the next pass: %+v, wait %+v", report, wait)
	}
	if !slices.Equal(report.Admitted, []sidecar.Id{aliasOnlyId}) || !slices.Equal(report.Issued, []sidecar.Id{aliasOnlyId}) || acme.orderCount() != 2 {
		t.Fatalf("the alias's own set beside the held name: %+v, %d orders", report, acme.orderCount())
	}
	if leaf := testVerifyChain(t, pebble, certs.row(aliasOnlyId).Chain, aliasOnly.identifierSet); !aliasOnly.tlsKey.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("the chain is not on its device's key")
	}

	clock.AdvanceTo(wait.Until)
	report = runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{certId}) || !slices.Equal(report.Requeued, []sidecar.Id{certId}) || acme.orderCount() != 3 {
		t.Fatalf("once the hold ended: %+v, %d orders", report, acme.orderCount())
	}
	report = runOrders()
	if len(report.Admitted) != 0 || testWaitReasons(report.Waiting)[certId] != certsservice.CertsWaitNameWrites || acme.orderCount() != 3 {
		t.Fatalf("held again: %+v, %d orders", report, acme.orderCount())
	}
}
