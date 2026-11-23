// A failing name's backoff at a CA (QD-857; the owner's answer to ca-numbers-2026-11-m5-consecutive-
// failures), on the chains' scripted CA and a fake clock: each failed authorization of a name at a CA
// doubles its wait there to a day and no further; the store keeps it, so a restart does too; a success
// there ends it; it holds that name's orders at that CA alone, never another name's; an ARI renewal skips
// it; an order sent after a failure of one of its names waits it out too; it goes once its retention is
// past; and a backoff the store cannot read sends no order. Nothing here sleeps.

package certsservice_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a CA answers when names fail authorization at LE.
func testAuthorizationRefused(names []string) error {
	return &certsservice.CertsAcmeAuthorizationError{Ca: certsservice.CertsCaLetsEncrypt, Names: names}
}

// The reason each waiting row waits for.
func testWaitReasons(waits []*certsservice.CertsWait) map[sidecar.Id]certsservice.CertsWaitReason {
	reasons := map[sidecar.Id]certsservice.CertsWaitReason{}
	for _, wait := range waits {
		reasons[wait.CertId] = wait.Reason
	}
	return reasons
}

// Fails the test unless every name of names backs off at ca alone, with count failures, until until.
func (self *testRun) wantBackoffs(names []string, ca certsservice.CertsCa, count int, until time.Time) {
	self.t.Helper()
	backoffs := self.store.NameBackoffs()
	if len(backoffs) != len(names) {
		self.t.Fatalf("%d backoffs for %d names", len(backoffs), len(names))
	}
	for _, backoff := range backoffs {
		if !slices.Contains(names, backoff.Name) || backoff.Ca != ca || backoff.FailureCount != count || !backoff.NextOrderTime.Equal(until) {
			self.t.Fatalf("%s at %s: %d failures until %s, want %d until %s", backoff.Name, backoff.Ca, backoff.FailureCount, backoff.NextOrderTime, count, until)
		}
	}
}

// A name whose authorizations keep failing at LE backs off there, 30 min after its first failure,
// doubling with each one after, to a day from its seventh and no further: a pass a millisecond before the
// time leaves its order waiting with no CA asked, and one at the time sends it to LE again. LE alone is
// open here, and its orders live long enough that the one row keeps queueing again; once it issues, the
// backoff is gone.
func TestCertsNameBackoffDoublesToADayAndNoFurther(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	settings.Cas[certsservice.CertsCaLetsEncrypt].OrderLifetime = 0
	settings.OrderGiveUpAge = 30 * 24 * time.Hour
	run := newTestRun(t, settings)
	device := run.device("k9backoff01")
	certId := run.accept(device)
	waits := []time.Duration{
		30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour,
		24 * time.Hour, 24 * time.Hour, 24 * time.Hour,
	}
	for index, wait := range waits {
		run.acme.script(testAuthorizationRefused(device.identifierSet))
		failedAt := run.clock.Now()
		if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{certId}) {
			t.Fatalf("failure %d: %+v", index+1, report)
		}
		run.wantBackoffs(device.identifierSet, certsservice.CertsCaLetsEncrypt, index+1, failedAt.Add(wait))

		asked := len(run.acme.ordered())
		run.clock.AdvanceTo(failedAt.Add(wait - time.Millisecond))
		report := run.runOrders()
		if len(report.Admitted) != 0 || len(report.Waiting) != 1 || report.Waiting[0].Reason != certsservice.CertsWaitNameBackoff ||
			!report.Waiting[0].Until.Equal(failedAt.Add(wait)) {
			t.Fatalf("before the backoff's end %d: %+v", index+1, report)
		}
		if len(run.acme.ordered()) != asked {
			t.Fatal("a name backing off reached LE")
		}
		run.clock.AdvanceTo(failedAt.Add(wait))
	}
	if report := run.runOrders(); !slices.Equal(report.Issued, []sidecar.Id{certId}) {
		t.Fatalf("at the last backoff's end: %+v", report)
	}
	if backoffs := run.store.NameBackoffs(); len(backoffs) != 0 {
		t.Fatalf("the issuance left %d backoffs", len(backoffs))
	}
	if orders := run.acme.ordered(); len(orders) != len(waits)+1 {
		t.Fatalf("LE was asked %d times", len(orders))
	}
}

// The backoff is the store's: a service started again over the same store, its process's holds gone,
// still keeps the name off LE until its time, and orders it there at the time.
func TestCertsNameBackoffOutlivesARestart(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	run := newTestRun(t, settings)
	device := run.device("k9backoff02")
	certId := run.accept(device)
	run.acme.script(testAuthorizationRefused(device.identifierSet))
	failedAt := run.clock.Now()
	if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{certId}) {
		t.Fatalf("report %+v", report)
	}

	restarted, err := certsservice.NewCertsService(run.ctx, run.host.ServiceHost(), run.store, nil, run.acme, settings)
	if err != nil {
		t.Fatal(err)
	}
	run.clock.Advance(10 * time.Minute)
	report, err := restarted.RunOrders(run.ctx, sidecar.Id{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Admitted) != 0 || len(report.Waiting) != 1 || report.Waiting[0].Reason != certsservice.CertsWaitNameBackoff ||
		!report.Waiting[0].Until.Equal(failedAt.Add(settings.FailureBackoff)) {
		t.Fatalf("after the restart: %+v", report)
	}
	if orders := run.acme.ordered(); len(orders) != 1 {
		t.Fatalf("LE was asked %d times", len(orders))
	}
	run.clock.AdvanceTo(failedAt.Add(settings.FailureBackoff))
	report, err = restarted.RunOrders(run.ctx, sidecar.Id{})
	if err != nil || !slices.Equal(report.Issued, []sidecar.Id{certId}) {
		t.Fatalf("at the backoff's end: %+v, %v", report, err)
	}
}

// A success at LE ends the name's backoff there: after two failures and an issuance, another device's
// order for the same set fails at LE and waits 30 min, a first failure's wait, not the 2 h of a third.
func TestCertsNameBackoffEndsWithASuccess(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	run := newTestRun(t, settings)
	device := run.device("k9backoff03")
	firstId := run.accept(device)
	for _, wait := range []time.Duration{30 * time.Minute, time.Hour} {
		run.acme.script(testAuthorizationRefused(device.identifierSet))
		if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{firstId}) {
			t.Fatalf("report %+v", report)
		}
		run.clock.Advance(wait)
	}
	if report := run.runOrders(); !slices.Equal(report.Issued, []sidecar.Id{firstId}) {
		t.Fatalf("the third try: %+v", report)
	}
	if backoffs := run.store.NameBackoffs(); len(backoffs) != 0 {
		t.Fatalf("the success left %d backoffs", len(backoffs))
	}

	run.clock.Advance(time.Millisecond)
	secondId := run.accept(newTestDeviceOf(t, device.networkId, device.identifierSet))
	run.acme.script(testAuthorizationRefused(device.identifierSet))
	failedAt := run.clock.Now()
	if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{secondId}) {
		t.Fatalf("the second device: %+v", report)
	}
	run.wantBackoffs(device.identifierSet, certsservice.CertsCaLetsEncrypt, 1, failedAt.Add(settings.FailureBackoff))
}

// One network's name failing at LE holds only its own orders there: while it backs off, another network's
// order goes to LE in the same pass and issues, and no hold falls on LE; after its next failure there, the
// same again. LE alone is open, so nothing reaches another CA.
func TestCertsFailingNameHoldsNoOtherNamesAtLetsEncrypt(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	run := newTestRun(t, settings)
	failing := run.device("k9backoff04")
	failingId := run.accept(failing)
	for round, wait := range []time.Duration{30 * time.Minute, time.Hour} {
		run.acme.script(testAuthorizationRefused(failing.identifierSet))
		if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{failingId}) {
			t.Fatalf("round %d's failure: %+v", round, report)
		}
		run.clock.Advance(time.Millisecond)
		otherId := run.accept(run.device("k9backoff05"))
		report := run.runOrders()
		if !slices.Equal(report.Issued, []sidecar.Id{otherId}) || testWaitReasons(report.Waiting)[failingId] != certsservice.CertsWaitNameBackoff {
			t.Fatalf("round %d's other order: %+v", round, report)
		}
		if row := run.row(otherId); row.Ca != string(certsservice.CertsCaLetsEncrypt) {
			t.Fatalf("round %d's other order went to %s", round, row.Ca)
		}
		run.clock.Advance(wait)
	}
	for _, order := range run.acme.ordered() {
		if order.Ca != certsservice.CertsCaLetsEncrypt {
			t.Fatalf("an order went to %s", order.Ca)
		}
	}
}

// While a name backs off at LE, its order goes to GTS rather than waiting, as the budget rules allow.
func TestCertsNameBackingOffAtLetsEncryptGoesToGts(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9backoff06")
	certId := run.accept(device)
	run.acme.script(testAuthorizationRefused(device.identifierSet))
	if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{certId}) {
		t.Fatalf("report %+v", report)
	}
	report := run.runOrders()
	if !slices.Equal(report.Issued, []sidecar.Id{certId}) {
		t.Fatalf("the next pass: %+v", report)
	}
	if row := run.row(certId); row.Ca != string(certsservice.CertsCaGts) {
		t.Fatalf("the order went to %s", row.Ca)
	}
	// GTS's success ends nothing at LE
	if backoffs := run.store.NameBackoffs(); len(backoffs) != len(device.identifierSet) {
		t.Fatalf("%d backoffs", len(backoffs))
	}
}

// An ARI renewal goes to its certificate's CA though its names back off there, as it skips every limit
// and hold (A7), while an order of the same set that renews nothing waits; the renewal's success ends the
// backoff, and the waiting order goes.
func TestCertsAriRenewalSkipsTheNameBackoff(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	run := newTestRun(t, settings)
	device := run.device("k9backoff07")
	serial := big.NewInt(0x77ae01)
	run.issuedWithChain(device, certsservice.CertsCaLetsEncrypt, serial)
	// rows accepted from here sort after the certificate's, so its set reads as issued before them
	run.clock.Advance(time.Millisecond)
	for range 2 {
		if err := run.service.RecordAuthorizationFailures(run.ctx, certsservice.CertsCaLetsEncrypt, device.identifierSet); err != nil {
			t.Fatal(err)
		}
	}
	rekeyed := *device
	var err error
	rekeyed.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repeatId := run.accept(&rekeyed)
	renewal := device.order(t)
	renewal.Args.Replaces = testCertificateId(run.acme.issuer.SubjectKeyId, serial)
	renewalResult, err := run.service.Accept(run.ctx, renewal)
	if err != nil {
		t.Fatal(err)
	}

	report := run.runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{renewalResult.CertId}) || !slices.Equal(report.Issued, []sidecar.Id{renewalResult.CertId}) ||
		testWaitReasons(report.Waiting)[repeatId] != certsservice.CertsWaitNameBackoff {
		t.Fatalf("report %+v", report)
	}
	sent := run.acme.ordered()
	if len(sent) != 1 || sent[0].Ca != certsservice.CertsCaLetsEncrypt || sent[0].Replaces != renewal.Args.Replaces {
		t.Fatalf("orders sent %+v", sent)
	}
	if backoffs := run.store.NameBackoffs(); len(backoffs) != 0 {
		t.Fatalf("the renewal's success left %d backoffs", len(backoffs))
	}
	if report := run.runOrders(); !slices.Equal(report.Issued, []sidecar.Id{repeatId}) {
		t.Fatalf("the waiting order: %+v", report)
	}
}

// Two orders sharing names under way at LE at once, as two passes at once may leave them, since a pass
// admits one order of a set or a challenge name at a time (QD-1189, QD-1203), taken up in one pass and
// sent one at a time: the first fails there, and the second, not yet sent, waits out the backoff the first
// set on their shared names, queued again with LE never asked; the passes after take them to GTS, one at
// a time.
func TestCertsOrderAdmittedBeforeAFailureWaitsOutTheBackoff(t *testing.T) {
	settings := testSettings()
	settings.OrderConcurrency = 1
	run := newTestRun(t, settings)
	first := run.device("k9backoff08")
	firstId := run.accept(first)
	secondId := run.accept(newTestDeviceOf(t, first.networkId, first.identifierSet))
	// the first under way by this pass's admission, the second by another pass's at once
	if admitted := run.admit(); len(admitted.Admitted) != 1 || admitted.Admitted[0].Cert.CertId != firstId {
		t.Fatalf("admitted %+v", admitted)
	}
	if moved, err := run.store.TransitionCert(run.ctx, &certsservice.CertsTransition{
		CertId:  secondId,
		From:    []sidecar.TlsCertState{sidecar.TlsCertStateQueued},
		To:      sidecar.TlsCertStateOrdering,
		At:      run.clock.Now(),
		Ca:      certsservice.CertsCaLetsEncrypt,
		Profile: settings.Cas[certsservice.CertsCaLetsEncrypt].Profile,
	}); err != nil || !moved {
		t.Fatalf("the other pass's admission: %v, %v", moved, err)
	}
	run.acme.script(testAuthorizationRefused(first.identifierSet))
	report := run.runOrders()
	both := []sidecar.Id{firstId, secondId}
	if len(report.Resumed) != 2 || len(report.Requeued) != 2 || !slices.Contains(report.Requeued, firstId) || !slices.Contains(report.Requeued, secondId) {
		t.Fatalf("report %+v", report)
	}
	if orders := run.acme.ordered(); len(orders) != 1 || orders[0].Ca != certsservice.CertsCaLetsEncrypt {
		t.Fatalf("orders %+v", orders)
	}
	report = run.runOrders()
	if !slices.Equal(report.Issued, []sidecar.Id{firstId}) || testWaitReasons(report.Waiting)[secondId] != certsservice.CertsWaitSetUnderWay {
		t.Fatalf("the next pass: %+v", report)
	}
	report = run.runOrders()
	if !slices.Equal(report.Issued, []sidecar.Id{secondId}) {
		t.Fatalf("the pass after: %+v", report)
	}
	for _, certId := range both {
		if row := run.row(certId); row.State != sidecar.TlsCertStateIssued || row.Ca != string(certsservice.CertsCaGts) {
			t.Fatalf("row %+v", row)
		}
	}
}

// An order a pass left under way, whose names have failed at its CA since, is not sent there when the
// next pass takes it up: it queues again, and the pass after takes it to GTS.
func TestCertsResumedOrderWaitsOutABackoffSetSinceItsAdmission(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("k9backoff09")
	certId := run.accept(device)
	if admitted := run.admit(); len(admitted.Admitted) != 1 || admitted.Admitted[0].Ca != certsservice.CertsCaLetsEncrypt {
		t.Fatalf("admitted %+v", admitted)
	}
	if err := run.service.RecordAuthorizationFailures(run.ctx, certsservice.CertsCaLetsEncrypt, device.identifierSet); err != nil {
		t.Fatal(err)
	}
	report := run.runOrders()
	if !slices.Equal(report.Resumed, []sidecar.Id{certId}) || !slices.Equal(report.Requeued, []sidecar.Id{certId}) || len(run.acme.ordered()) != 0 {
		t.Fatalf("report %+v", report)
	}
	if state := run.row(certId).State; state != sidecar.TlsCertStateQueued {
		t.Fatalf("state %s", state)
	}
	report = run.runOrders()
	if !slices.Equal(report.Issued, []sidecar.Id{certId}) || run.row(certId).Ca != string(certsservice.CertsCaGts) {
		t.Fatalf("the pass after: %+v", report)
	}
}

// A backoff the store cannot read sends no order: at admission the pass ends with the error and the row
// stays queued, and just before an order goes the row stays under way for the next pass. A failure the
// store cannot count still queues the order again and holds the name for the hour, and the pass says so.
func TestCertsBackoffTheStoreCannotReadSendsNoOrder(t *testing.T) {
	run := newTestRun(t, nil)
	faults := run.host.Redis.Faults()
	device := run.device("k9backoff10")
	certId := run.accept(device)
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "certs.ListNameBackoffs", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	report, err := run.service.RunOrders(run.ctx, sidecar.Id{})
	if err == nil || len(report.Admitted) != 0 || run.row(certId).State != sidecar.TlsCertStateQueued {
		t.Fatalf("at admission: %+v, %v", report, err)
	}

	if admitted := run.admit(); len(admitted.Admitted) != 1 {
		t.Fatalf("admitted %+v", admitted)
	}
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "certs.ListNameBackoffs", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	report, err = run.service.RunOrders(run.ctx, sidecar.Id{})
	if err == nil || !slices.Equal(report.Interrupted, []sidecar.Id{certId}) || run.row(certId).State != sidecar.TlsCertStateOrdering {
		t.Fatalf("before the order: %+v, %v", report, err)
	}
	if orders := run.acme.ordered(); len(orders) != 0 {
		t.Fatalf("orders %+v", orders)
	}

	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "certs.AddNameFailure", Result: sidecartest.FailBeforeApply, Repeat: 1}); err != nil {
		t.Fatal(err)
	}
	run.acme.script(testAuthorizationRefused(device.identifierSet))
	report, err = run.service.RunOrders(run.ctx, sidecar.Id{})
	if err == nil || !slices.Equal(report.Requeued, []sidecar.Id{certId}) {
		t.Fatalf("an uncounted failure: %+v, %v", report, err)
	}
	if backoffs := run.store.NameBackoffs(); len(backoffs) != 0 {
		t.Fatalf("%d backoffs", len(backoffs))
	}
	// the process still counts it toward the hour's hold
	for range run.settings.FailedAuthorizationCount - 1 {
		if err := run.service.RecordAuthorizationFailures(run.ctx, certsservice.CertsCaGts, device.identifierSet); err != nil {
			t.Fatal(err)
		}
	}
	if admitted := run.admit(); len(admitted.Waiting) != 1 || admitted.Waiting[0].Reason != certsservice.CertsWaitNameHold {
		t.Fatalf("the hour's hold: %+v", admitted)
	}
}

// A name's backoff goes FailureBackoffRetention past the time it held orders until, and not before.
func TestCertsPurgeTakesNameBackoffsPastTheirRetention(t *testing.T) {
	certs := newTestCerts(t, nil)
	name := "k9backoff11." + testRoot
	if err := certs.service.RecordAuthorizationFailures(certs.ctx, certsservice.CertsCaLetsEncrypt, []string{name}); err != nil {
		t.Fatal(err)
	}
	heldUntil := certs.clock.Now().Add(certs.settings.FailureBackoff)
	certs.clock.AdvanceTo(heldUntil.Add(certs.settings.FailureBackoffRetention))
	report, err := certs.service.Purge(certs.ctx)
	if err != nil || report.NameBackoffCount != 0 || len(certs.store.NameBackoffs()) != 1 {
		t.Fatalf("at the retention's end: %+v, %v", report, err)
	}
	certs.clock.Advance(time.Millisecond)
	report, err = certs.service.Purge(certs.ctx)
	if err != nil || report.NameBackoffCount != 1 || len(certs.store.NameBackoffs()) != 0 {
		t.Fatalf("past it: %+v, %v", report, err)
	}
}
