// The admission pass (TLS-M5-14) on a fake clock: a new set spends LE's budget and moves to GTS once LE's
// is spent, an ephemeral sidecar goes to GTS first, a repeated set gets five at LE and one per 34 h, a
// CA's Retry-After holds every capped order while a renewal goes on, failed authorizations hold a name,
// a waiting order spends nothing, and the pass resumes from its cursor.
package certsservice_test

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
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

// Four failed authorizations of a name inside the hour hold every order naming it until the oldest
// leaves the hour.
func TestFailedAuthorizationsHoldAName(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "failing")
	for range certs.settings.FailedAuthorizationCount {
		certs.service.RecordAuthorizationFailures([]string{device.identifierSet[0]})
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
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != id {
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
