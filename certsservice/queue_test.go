// The admission pass (TLS-M5-14) on a fake clock: a new set spends LE's budget and moves to GTS once LE's
// is spent, an ephemeral sidecar goes to GTS first, a repeated set gets five at LE and one per 34 h, a
// CA's Retry-After holds every capped order while a renewal goes on, failed authorizations hold a name,
// a waiting order spends nothing, and the pass resumes from its cursor.
//
// A set has one order under way at a time (QD-1189): its next order waits, a renewal too, asking no CA and
// spending nothing, until that one ends, and then goes as a repeated set when it issued or as a new one
// when it failed; two sets that share a challenge name take turns the same way (QD-1203), while other
// networks' sets and a scope's go in the same pass; a pass reads every row under way, a batch at a time,
// and one that cannot read them admits nothing. On Pebble, two devices of each of two networks
// make one CA order, spend one unit of the budget and write their name once a network in the first pass,
// and the other two issue as repeated sets in the next.
package certsservice_test

import (
	"context"
	"errors"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A new set goes to LE under its profile and spends one unit there; once LE's budget is spent, the next
// goes to GTS, and the one after that past GTS's to ZeroSSL.
func TestNewSetsSpendLetsEncryptThenFallBack(t *testing.T) {
	settings := testSettings()
	settings.Cas[certsservice.CertsCaLetsEncrypt].BudgetCap = 1
	settings.Cas[certsservice.CertsCaGts].BudgetCap = 1
	certs := newTestCerts(t, settings)
	ids := []sidecar.Id{}
	for _, label := range []string{"new-a", "new-b", "new-c"} {
		ids = append(ids, certs.accept(newTestDevice(t, label)))
	}
	report := certs.admit()
	if len(report.Admitted) != 3 || len(report.Waiting) != 0 {
		t.Fatalf("report %+v", report)
	}
	for index, want := range []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt, certsservice.CertsCaGts, certsservice.CertsCaZeroSsl} {
		admission := report.Admitted[index]
		if admission.Ca != want || admission.Kind != certsservice.CertsOrderNewSet || admission.Cert.CertId != ids[index] {
			t.Errorf("order %d went to %s as %s", index, admission.Ca, admission.Kind)
		}
		row := certs.row(ids[index])
		if row.State != sidecar.TlsCertStateOrdering || row.Ca != string(want) || row.Profile != settings.Cas[want].Profile {
			t.Errorf("row %d %+v", index, row)
		}
	}
	if members := testBudgetMembers(t, certs); len(members) != 1 {
		t.Fatalf("LE's budget %v", members)
	}
}

// An ephemeral sidecar's order goes to GTS ahead of LE (D-TLS-7), and spends none of LE's budget.
func TestEphemeralSidecarsGoToGtsFirst(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "ephemeral")
	certs.store.SetClientEphemeral(device.clientId)
	certs.accept(device)
	report := certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Ca != certsservice.CertsCaGts {
		t.Fatalf("report %+v", report)
	}
	if members := testBudgetMembers(t, certs); len(members) != 0 {
		t.Fatalf("an ephemeral order spent LE's budget: %v", members)
	}
}

// With LE alone open, a set gets five certificates at once, the sixth waits 34 h for one unit, and the
// seventh 34 h more; another set is not held by it.
func TestRepeatedSetGetsFiveThenOnePer34Hours(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	certs := newTestCerts(t, settings)
	first := newTestDevice(t, "repeat")
	issueNext := func(device *testDevice) sidecar.Id {
		t.Helper()
		id := certs.accept(device)
		report := certs.admit()
		if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != id {
			t.Fatalf("not admitted: %+v", report)
		}
		certs.issue(id, id.String()[:12])
		return id
	}
	issueNext(first)
	// four more devices of the network, each its own key for the same set: repeated sets
	for range 4 {
		issueNext(newTestDeviceOf(t, first.networkId, first.identifierSet))
	}
	sixth := newTestDeviceOf(t, first.networkId, first.identifierSet)
	sixthId := certs.accept(sixth)
	report := certs.admit()
	if len(report.Admitted) != 0 || len(report.Waiting) != 1 {
		t.Fatalf("the sixth: %+v", report)
	}
	wait := report.Waiting[0]
	// the set's five certificates at LE, its first included, empty the bucket
	if wait.CertId != sixthId || wait.Reason != certsservice.CertsWaitRepeatSet {
		t.Fatalf("wait %+v", wait)
	}
	if !wait.Until.Equal(certs.clock.Now().Add(settings.RepeatSetRefill)) {
		t.Fatalf("waits until %s, %s from now", wait.Until, wait.Until.Sub(certs.clock.Now()))
	}
	// another network's set is not held by this one's
	other := certs.accept(newTestDevice(t, "repeat-other"))
	certs.clock.Advance(settings.RepeatSetRefill - time.Millisecond)
	report = certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != other {
		t.Fatalf("a millisecond before the refill: %+v", report)
	}
	certs.clock.Advance(time.Millisecond)
	report = certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != sixthId || report.Admitted[0].Kind != certsservice.CertsOrderRepeatSet {
		t.Fatalf("at the refill: %+v", report)
	}
}

// A set spent at LE goes on to GTS, which has no repeated-set rule: a team adding devices quickly is
// not stopped (§13.16).
func TestRepeatedSetSpentAtLetsEncryptGoesToGts(t *testing.T) {
	certs := newTestCerts(t, nil)
	first := newTestDevice(t, "spent")
	for index := range 6 {
		device := first
		if 0 < index {
			device = newTestDeviceOf(t, first.networkId, first.identifierSet)
		}
		id := certs.accept(device)
		report := certs.admit()
		if len(report.Admitted) != 1 {
			t.Fatalf("order %d: %+v", index, report)
		}
		want := certsservice.CertsCaLetsEncrypt
		if index == 5 {
			want = certsservice.CertsCaGts
		}
		if report.Admitted[0].Ca != want {
			t.Fatalf("order %d went to %s", index, report.Admitted[0].Ca)
		}
		certs.issue(id, id.String()[:12])
	}
}

// A CA's Retry-After holds every new or repeated set there until it and its margin pass, the next CA
// taking them; with no other CA open they wait, spending nothing. A renewal goes on through the hold.
func TestCaHoldHoldsCappedOrdersAndNotRenewals(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	certs := newTestCerts(t, settings)
	device := newTestDevice(t, "held")
	firstId := certs.accept(device)
	if report := certs.admit(); len(report.Admitted) != 1 {
		t.Fatalf("report %+v", report)
	}
	certs.issue(firstId, "c0ffee")
	retryAfter := certs.clock.Now().Add(2 * time.Hour)
	certs.service.HoldCa(certsservice.CertsCaLetsEncrypt, retryAfter)

	newSetId := certs.accept(newTestDevice(t, "held-new"))
	budgetBefore := testBudgetMembers(t, certs)
	report := certs.admit()
	if len(report.Admitted) != 0 || len(report.Waiting) != 1 || report.Waiting[0].Reason != certsservice.CertsWaitCaHold ||
		!report.Waiting[0].Until.Equal(retryAfter.Add(settings.RetryAfterMargin)) {
		t.Fatalf("during the hold: %+v", report)
	}
	if after := testBudgetMembers(t, certs); len(after) != len(budgetBefore) {
		t.Fatalf("a held order spent budget: %v", after)
	}

	// the device renews its live certificate, which goes to LE through the hold
	renewal := device.order(t)
	renewal.Args.Replaces = testAriId("c0ffee")
	renewalResult, err := certs.service.Accept(certs.ctx, renewal)
	if err != nil {
		t.Fatal(err)
	}
	report = certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != renewalResult.CertId ||
		report.Admitted[0].Kind != certsservice.CertsOrderRenewal || report.Admitted[0].Replaces.CertId != firstId ||
		report.Admitted[0].Ca != certsservice.CertsCaLetsEncrypt {
		t.Fatalf("the renewal: %+v", report)
	}

	certs.clock.AdvanceTo(retryAfter.Add(settings.RetryAfterMargin))
	report = certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != newSetId {
		t.Fatalf("after the hold: %+v", report)
	}
}

// A refusal that names no Retry-After holds DefaultRetryAfter, and a later, shorter hold never shortens
// it.
func TestCaHoldWithNoTimeHoldsTheDefault(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaGts}
	certs := newTestCerts(t, settings)
	heldAt := certs.clock.Now()
	certs.service.HoldCa(certsservice.CertsCaGts, time.Time{})
	certs.service.HoldCa(certsservice.CertsCaGts, heldAt.Add(time.Minute))
	certs.accept(newTestDevice(t, "held-gts"))
	certs.clock.Advance(settings.RetryAfterMargin + time.Minute)
	report := certs.admit()
	if len(report.Waiting) != 1 || report.Waiting[0].Reason != certsservice.CertsWaitCaHold || !report.Waiting[0].Until.Equal(heldAt.Add(settings.DefaultRetryAfter)) {
		t.Fatalf("GTS's hold: %+v", report)
	}
}

// Four failed authorizations of a name inside the hour hold every order naming it, at every CA, until the
// oldest leaves the hour; then the order goes to a CA where the name does not back off.
func TestFailedAuthorizationsHoldAName(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "failing")
	for range certs.settings.FailedAuthorizationCount {
		if err := certs.service.RecordAuthorizationFailures(certs.ctx, certsservice.CertsCaLetsEncrypt, []string{device.identifierSet[0]}); err != nil {
			t.Fatal(err)
		}
		certs.clock.Advance(time.Minute)
	}
	firstFailure := certs.clock.Now().Add(-time.Duration(certs.settings.FailedAuthorizationCount) * time.Minute)
	id := certs.accept(device)
	report := certs.admit()
	if len(report.Waiting) != 1 || report.Waiting[0].Reason != certsservice.CertsWaitNameHold ||
		!report.Waiting[0].Until.Equal(firstFailure.Add(certs.settings.FailedAuthorizationWindow)) {
		t.Fatalf("held: %+v", report)
	}
	certs.clock.AdvanceTo(firstFailure.Add(certs.settings.FailedAuthorizationWindow))
	report = certs.admit()
	// the four failures were LE's, where the name backs off 4 h from the last
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != id || report.Admitted[0].Ca != certsservice.CertsCaGts {
		t.Fatalf("after the hour: %+v", report)
	}
}

// A stored CSR that no longer parses can never be ordered: it fails, and the pass goes on.
func TestUnreadableQueuedRowFails(t *testing.T) {
	certs := newTestCerts(t, nil)
	good := certs.accept(newTestDevice(t, "readable"))
	broken := newTestDevice(t, "unreadable")
	brokenId := certs.accept(broken)
	row := certs.row(brokenId)
	row.CertId = sidecar.NewId()
	row.Csr = []byte("no longer a CSR")
	if err := certs.store.InsertCert(certs.ctx, row); err != nil {
		t.Fatal(err)
	}
	report := certs.admit()
	if len(report.Failed) != 1 || report.Failed[0] != row.CertId || certs.row(row.CertId).State != sidecar.TlsCertStateFailed {
		t.Fatalf("report %+v", report)
	}
	if len(report.Admitted) != 2 || report.Admitted[0].Cert.CertId != good {
		t.Fatalf("the rest: %+v", report)
	}
}

// A pass reads at most a batch and says where the next resumes; the next reads the rest.
func TestAdmissionResumesFromItsCursor(t *testing.T) {
	settings := testSettings()
	settings.AdmitBatchCount = 2
	certs := newTestCerts(t, settings)
	ids := []sidecar.Id{}
	for _, label := range []string{"cursor-a", "cursor-b", "cursor-c"} {
		ids = append(ids, certs.accept(newTestDevice(t, label)))
	}
	report := certs.admit()
	if len(report.Admitted) != 2 || report.NextCertId != ids[1] {
		t.Fatalf("the first pass: %+v", report)
	}
	next, err := certs.service.Admit(certs.ctx, report.NextCertId)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Admitted) != 1 || next.Admitted[0].Cert.CertId != ids[2] || next.NextCertId != (sidecar.Id{}) {
		t.Fatalf("the second pass: %+v", next)
	}
}

// GET /tls/cert-order/<id> answers its own caller and no one else, and GET /tls/certs shows a network's
// rows with no CSR.
func TestOrderStatusAndCertsAnswerTheirCallerOnly(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "status")
	id := certs.accept(device)
	status, err := certs.service.OrderStatus(certs.ctx, device.networkId, device.clientId, id)
	if err != nil || status.State != sidecar.TlsCertStateQueued || status.RetryAfterMs == 0 {
		t.Fatalf("own order: %+v, %v", status, err)
	}
	for _, stranger := range []struct {
		networkId sidecar.Id
		clientId  sidecar.Id
	}{{device.networkId, sidecar.NewId()}, {sidecar.NewId(), device.clientId}} {
		if _, err := certs.service.OrderStatus(certs.ctx, stranger.networkId, stranger.clientId, id); err != certsservice.ErrCertsNotFound {
			t.Fatalf("a stranger: %v", err)
		}
	}
	result, err := certs.service.Certs(certs.ctx, device.networkId)
	if err != nil || len(result.Certs) != 1 || result.Certs[0].CertId != id || result.Certs[0].Csr != nil || len(result.Certs[0].Attestation) == 0 {
		t.Fatalf("certs %+v, %v", result, err)
	}
}

// Two devices of one network queued together: a pass admits the first, which spends the set's one unit of
// LE's budget, and leaves the second waiting on its set, with no time, asking for nothing, for as long as
// the first is under way; once the first has issued, the second goes as a repeated set and spends none.
func TestSetHasOneOrderUnderWayAtATime(t *testing.T) {
	certs := newTestCerts(t, nil)
	first := newTestDevice(t, "one-set")
	firstId := certs.accept(first)
	secondId := certs.accept(newTestDeviceOf(t, first.networkId, first.identifierSet))
	report := certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != firstId || report.Admitted[0].Kind != certsservice.CertsOrderNewSet {
		t.Fatalf("the first pass: %+v", report)
	}
	if len(report.Waiting) != 1 || report.Waiting[0].CertId != secondId || report.Waiting[0].Reason != certsservice.CertsWaitSetUnderWay ||
		!report.Waiting[0].Until.IsZero() {
		t.Fatalf("the second waits %+v", report.Waiting)
	}
	// still under way at the next pass, which holds the second again
	report = certs.admit()
	if len(report.Admitted) != 0 || len(report.Waiting) != 1 || report.Waiting[0].Reason != certsservice.CertsWaitSetUnderWay {
		t.Fatalf("the next pass: %+v", report)
	}
	if row := certs.row(secondId); row.State != sidecar.TlsCertStateQueued || row.Ca != "" {
		t.Fatalf("the waiting row %+v", row)
	}
	if members := testBudgetMembers(t, certs); len(members) != 1 || members[firstId.String()] == 0 {
		t.Fatalf("LE's budget %v", members)
	}
	certs.issue(firstId, "5e7a01")
	report = certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != secondId || report.Admitted[0].Kind != certsservice.CertsOrderRepeatSet ||
		report.Admitted[0].Ca != certsservice.CertsCaLetsEncrypt {
		t.Fatalf("once the first issued: %+v", report)
	}
	if members := testBudgetMembers(t, certs); len(members) != 1 {
		t.Fatalf("the repeated set spent budget: %v", members)
	}
}

// Other networks' sets are not held by one another: a pass admits the first device of each, and holds
// only the second devices of their sets.
func TestSetsOfOtherNetworksOrderInOnePass(t *testing.T) {
	certs := newTestCerts(t, nil)
	firstIds := []sidecar.Id{}
	secondIds := []sidecar.Id{}
	for _, label := range []string{"sets-a", "sets-b", "sets-c"} {
		first := newTestDevice(t, label)
		firstIds = append(firstIds, certs.accept(first))
		secondIds = append(secondIds, certs.accept(newTestDeviceOf(t, first.networkId, first.identifierSet)))
	}
	report := certs.admit()
	admittedIds := []sidecar.Id{}
	for _, admission := range report.Admitted {
		admittedIds = append(admittedIds, admission.Cert.CertId)
	}
	if !slices.Equal(admittedIds, firstIds) {
		t.Fatalf("admitted %v, want %v", admittedIds, firstIds)
	}
	reasons := testWaitReasons(report.Waiting)
	for _, secondId := range secondIds {
		if reasons[secondId] != certsservice.CertsWaitSetUnderWay {
			t.Fatalf("waits %+v", reasons)
		}
	}
	if members := testBudgetMembers(t, certs); len(members) != len(firstIds) {
		t.Fatalf("LE's budget %v", members)
	}
}

// A pass reads every row under way, a batch at a time: the held set's row is the last of three under way
// with a batch of one, and still holds its set's next row, after four reads.
func TestRowsUnderWayAreReadWholeABatchAtATime(t *testing.T) {
	settings := testSettings()
	settings.UnderWayBatchCount = 1
	certs := newTestCerts(t, settings)
	for _, label := range []string{"batch-a", "batch-b"} {
		certs.accept(newTestDevice(t, label))
	}
	held := newTestDevice(t, "batch-held")
	certs.accept(held)
	// left under way, as a pass that died leaves its orders
	if report := certs.admit(); len(report.Admitted) != 3 {
		t.Fatalf("admitted %+v", report)
	}
	nextId := certs.accept(newTestDeviceOf(t, held.networkId, held.identifierSet))
	readCount := certs.store.OpCounts()["ListInStates"]
	report := certs.admit()
	if len(report.Admitted) != 0 || testWaitReasons(report.Waiting)[nextId] != certsservice.CertsWaitSetUnderWay {
		t.Fatalf("report %+v", report)
	}
	if reads := certs.store.OpCounts()["ListInStates"] - readCount; reads != 4 {
		t.Fatalf("%d reads of the rows under way", reads)
	}
}

// A pass that cannot read the rows under way admits nothing and spends nothing: the row stays queued for
// the next, which admits it.
func TestAdmissionThatCannotReadTheRowsUnderWayAdmitsNothing(t *testing.T) {
	certs := newTestCerts(t, nil)
	certId := certs.accept(newTestDevice(t, "unread"))
	if _, err := certs.host.Redis.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "certs.ListInStates", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	report, err := certs.service.Admit(certs.ctx, sidecar.Id{})
	if err == nil || len(report.Admitted) != 0 || len(report.Waiting) != 0 || certs.row(certId).State != sidecar.TlsCertStateQueued {
		t.Fatalf("report %+v, %v", report, err)
	}
	if members := testBudgetMembers(t, certs); len(members) != 0 {
		t.Fatalf("LE's budget %v", members)
	}
	if report := certs.admit(); len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != certId {
		t.Fatalf("the next pass: %+v", report)
	}
}

// A set whose order fails frees its next: while the first order queues again after a young failure, the
// next pass admits it again and the second still waits; once it fails past its give-up age, the second
// goes, as a new set, since no certificate came of the first, and spends a unit of its own.
func TestSetWhoseFirstOrderFailsFreesTheNext(t *testing.T) {
	settings := testSettings()
	run := newTestRun(t, settings)
	first := run.device("first-fails")
	firstId := run.accept(first)
	secondId := run.accept(newTestDeviceOf(t, first.networkId, first.identifierSet))
	run.acme.script(errors.New("the CA answered 500"))
	report := run.runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{firstId}) || !slices.Equal(report.Requeued, []sidecar.Id{firstId}) ||
		testWaitReasons(report.Waiting)[secondId] != certsservice.CertsWaitSetUnderWay {
		t.Fatalf("the first pass: %+v", report)
	}
	// past LE's order lifetime, the first order's next failure ends it
	run.clock.Advance(settings.Cas[certsservice.CertsCaLetsEncrypt].OrderLifetime)
	run.acme.script(errors.New("the CA called the order invalid"))
	report = run.runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{firstId}) || !slices.Equal(report.Failed, []sidecar.Id{firstId}) ||
		testWaitReasons(report.Waiting)[secondId] != certsservice.CertsWaitSetUnderWay {
		t.Fatalf("the second pass: %+v", report)
	}
	report = run.runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{secondId}) || !slices.Equal(report.Issued, []sidecar.Id{secondId}) {
		t.Fatalf("the third pass: %+v", report)
	}
	if orders := run.acme.ordered(); len(orders) != 3 {
		t.Fatalf("%d orders", len(orders))
	}
	if members := testBudgetMembers(t, run.testCerts); len(members) != 2 || members[secondId.String()] == 0 {
		t.Fatalf("LE's budget %v", members)
	}
}

// A renewal writes its set's names too, so it waits while another device's order of the set is under way,
// as one a pass that died left; the pass that takes that order up issues it, and the renewal goes at the
// next, to its certificate's CA with its replaces.
func TestRenewalWaitsOnItsSetsOrderUnderWay(t *testing.T) {
	run := newTestRun(t, nil)
	device := run.device("renewal-waits")
	serial := big.NewInt(0x5e7a02)
	run.issuedWithChain(device, certsservice.CertsCaLetsEncrypt, serial)
	// rows accepted from here sort after the certificate's, so its set reads as issued before them
	run.clock.Advance(time.Millisecond)
	otherId := run.accept(newTestDeviceOf(t, device.networkId, device.identifierSet))
	if admitted := run.admit(); len(admitted.Admitted) != 1 {
		t.Fatalf("admitted %+v", admitted)
	}
	renewal := device.order(t)
	renewal.Args.Replaces = testCertificateId(run.acme.issuer.SubjectKeyId, serial)
	renewalResult, err := run.service.Accept(run.ctx, renewal)
	if err != nil {
		t.Fatal(err)
	}
	report := run.runOrders()
	if !slices.Equal(report.Resumed, []sidecar.Id{otherId}) || !slices.Equal(report.Issued, []sidecar.Id{otherId}) || len(report.Admitted) != 0 ||
		testWaitReasons(report.Waiting)[renewalResult.CertId] != certsservice.CertsWaitSetUnderWay {
		t.Fatalf("while the other order is under way: %+v", report)
	}
	report = run.runOrders()
	if !slices.Equal(report.Admitted, []sidecar.Id{renewalResult.CertId}) || !slices.Equal(report.Issued, []sidecar.Id{renewalResult.CertId}) {
		t.Fatalf("the next pass: %+v", report)
	}
	sent := run.acme.ordered()
	if last := sent[len(sent)-1]; last.Ca != certsservice.CertsCaLetsEncrypt || last.Replaces != renewal.Args.Replaces {
		t.Fatalf("the renewal went %+v", last)
	}
}

// A CertsAcme counting the orders certs sends its CAs.
type testCountingAcme struct {
	certsservice.CertsAcme

	stateLock sync.Mutex
	orders    []*certsservice.CertsAcmeOrder
}

func (self *testCountingAcme) Order(ctx context.Context, order *certsservice.CertsAcmeOrder) (*certsservice.CertsAcmeIssued, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.orders = append(self.orders, order)
	}()
	return self.CertsAcme.Order(ctx, order)
}

func (self *testCountingAcme) orderCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.orders)
}

// Two devices of each of two networks queued at once, on Pebble, which asks for both of each order's
// authorizations: the first pass makes one CA order a network, spends one unit of LE's budget a network
// and writes each network's _acme-challenge name once, its set's name and wildcard in one write, while
// the second devices wait on their sets; the next pass issues those as repeated sets, one order and one
// write a network more and no unit, and every chain verifies on its device's key. No challenge is left.
func TestOneSetOneOrderAPassOnPebble(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	ctx := testAcmeContext(t)
	clock := sidecartest.NewFakeClock(time.Now().UTC().Truncate(time.Microsecond))
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterCertsBudgetTwins(host.Redis)
	store := sidecartest.NewFakeCertsStore(host.Redis.Faults())
	acme := &testCountingAcme{CertsAcme: testAcme(t, settings, pebble, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))}
	service, err := certsservice.NewCertsService(ctx, host.ServiceHost(), store, nil, acme, settings)
	if err != nil {
		t.Fatal(err)
	}
	certs := &testCerts{t: t, ctx: ctx, clock: clock, host: host, store: store, settings: settings, service: service}

	devices := map[sidecar.Id]*testDevice{}
	firstIds := []sidecar.Id{}
	secondIds := []sidecar.Id{}
	for _, label := range []string{"k7oneset01", "k7oneset02"} {
		first := newTestDevice(t, label)
		second := newTestDeviceOf(t, first.networkId, first.identifierSet)
		firstId := certs.accept(first)
		secondId := certs.accept(second)
		devices[firstId] = first
		devices[secondId] = second
		firstIds = append(firstIds, firstId)
		secondIds = append(secondIds, secondId)
	}
	sorted := func(ids []sidecar.Id) []sidecar.Id {
		ids = slices.Clone(ids)
		slices.SortFunc(ids, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
		return ids
	}

	report, err := service.RunOrders(ctx, sidecar.Id{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(report.Admitted, firstIds) || !slices.Equal(sorted(report.Issued), firstIds) {
		t.Fatalf("the first pass: %+v", report)
	}
	reasons := testWaitReasons(report.Waiting)
	for _, secondId := range secondIds {
		if reasons[secondId] != certsservice.CertsWaitSetUnderWay {
			t.Fatalf("the first pass's waits %+v", reasons)
		}
	}
	writeCount, _, _ := pebble.Dns.Counts()
	if orderCount := acme.orderCount(); orderCount != 2 || writeCount != 2 {
		t.Fatalf("the first pass: %d CA orders, %d challenge writes", orderCount, writeCount)
	}
	if members := testBudgetMembers(t, certs); len(members) != 2 || members[firstIds[0].String()] == 0 || members[firstIds[1].String()] == 0 {
		t.Fatalf("LE's budget %v", members)
	}

	report, err = service.RunOrders(ctx, sidecar.Id{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(report.Admitted, secondIds) || !slices.Equal(sorted(report.Issued), secondIds) || len(report.Waiting) != 0 {
		t.Fatalf("the second pass: %+v", report)
	}
	writeCount, removeCount, _ := pebble.Dns.Counts()
	if orderCount := acme.orderCount(); orderCount != 4 || writeCount != 4 || removeCount != 4 {
		t.Fatalf("both passes: %d CA orders, %d challenge writes, %d removals", orderCount, writeCount, removeCount)
	}
	if members := testBudgetMembers(t, certs); len(members) != 2 {
		t.Fatalf("the repeated sets spent budget: %v", members)
	}
	for certId, device := range devices {
		row := certs.row(certId)
		if row.State != sidecar.TlsCertStateIssued {
			t.Fatalf("row %+v", row)
		}
		if leaf := testVerifyChain(t, pebble, row.Chain, device.identifierSet); !device.tlsKey.PublicKey.Equal(leaf.PublicKey) {
			t.Fatal("a chain is not on its device's key")
		}
	}
	if names := pebble.Dns.Names(); len(names) != 0 {
		t.Fatalf("challenges left at %v", names)
	}
}

// Two sets that share a challenge name have one order under way at a time too (QD-1203): the network's
// pair alone and a set with a live alias's pair beside it both validate at _acme-challenge.<net>.<root>,
// so a pass admits the first and holds the second by that name, whether the first was admitted in the
// same pass or an earlier one; once the first has issued the second goes, a new set of its own.
func TestSetsSharingAChallengeNameOrderOneAtATime(t *testing.T) {
	certs := newTestCerts(t, nil)
	first := newTestDevice(t, "shared-name")
	aliasSet, err := sidecar.TlsIdentifierSet(testRoot, "shared-name", "", []string{"shared-name-alias"})
	if err != nil {
		t.Fatal(err)
	}
	firstId := certs.accept(first)
	aliasId := certs.accept(newTestDeviceOf(t, first.networkId, aliasSet))
	report := certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != firstId ||
		testWaitReasons(report.Waiting)[aliasId] != certsservice.CertsWaitNameUnderWay {
		t.Fatalf("the first pass: %+v", report)
	}
	// the next pass reads the name from the row under way
	report = certs.admit()
	if len(report.Admitted) != 0 || testWaitReasons(report.Waiting)[aliasId] != certsservice.CertsWaitNameUnderWay {
		t.Fatalf("the next pass: %+v", report)
	}
	certs.issue(firstId, "5e7a03")
	report = certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != aliasId || report.Admitted[0].Kind != certsservice.CertsOrderNewSet {
		t.Fatalf("once the first issued: %+v", report)
	}
}

// A scope's set validates at a name of its own, _acme-challenge.<scope>.<net>.<root>, which the network's
// pair does not share, so a scope device's order goes in the same pass as the network's.
func TestScopeSetOrdersBesideItsNetworksSet(t *testing.T) {
	certs := newTestCerts(t, nil)
	network := newTestDevice(t, "scoped-net")
	scopeSet, err := sidecar.TlsIdentifierSet(testRoot, "scoped-net", "team-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	networkId := certs.accept(network)
	scopeId := certs.accept(newTestDeviceOf(t, network.networkId, scopeSet))
	report := certs.admit()
	admittedIds := []sidecar.Id{}
	for _, admission := range report.Admitted {
		admittedIds = append(admittedIds, admission.Cert.CertId)
	}
	if !slices.Equal(admittedIds, []sidecar.Id{networkId, scopeId}) || len(report.Waiting) != 0 {
		t.Fatalf("report %+v", report)
	}
}
