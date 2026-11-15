// What certs does with the CA's numbers as Let's Encrypt's rate-limits and profiles pages gave them, read
// 2026-11-15 (QD-784): an order gives up no later than its CA keeps an order alive, while a renewal of a
// live certificate keeps trying; and an ARI renewal is exempt from every limit and hold, in its window or
// not, since the CA's exemption names no window. On the chains' scripted CA and a fake clock.

package certsservice_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

// The millisecond an id carries, its row's acceptance.
func testIdTime(id sidecar.Id) time.Time {
	var ms int64
	for index := range 6 {
		ms = ms<<8 | int64(id[index])
	}
	return time.UnixMilli(ms).UTC()
}

// An order that keeps failing at LE fails once it is LE's order lifetime old, 8 h, though OrderGiveUpAge
// is a day, and a shorter lifetime moves the give-up with it; at GTS, whose lifetime is not known, the
// same order queues again past 8 h until the day is up.
func TestCertsRunOrdersGiveUpFollowsTheCasOrderLifetime(t *testing.T) {
	cases := []struct {
		label string
		ca    certsservice.CertsCa
		// LE's OrderLifetime, zero keeping its default
		letsEncryptLifetime time.Duration
		// ages at which a failure queues the order again, then the age at which one fails it
		requeuedAges []time.Duration
		failedAge    time.Duration
	}{
		{
			label:        "k9giveup01",
			ca:           certsservice.CertsCaLetsEncrypt,
			requeuedAges: []time.Duration{0, 8*time.Hour - time.Millisecond},
			failedAge:    8 * time.Hour,
		},
		{
			label:               "k9giveup02",
			ca:                  certsservice.CertsCaLetsEncrypt,
			letsEncryptLifetime: 2 * time.Hour,
			requeuedAges:        []time.Duration{2*time.Hour - time.Millisecond},
			failedAge:           2 * time.Hour,
		},
		{
			label:        "k9giveup03",
			ca:           certsservice.CertsCaGts,
			requeuedAges: []time.Duration{8 * time.Hour, 24*time.Hour - time.Millisecond},
			failedAge:    24 * time.Hour,
		},
	}
	for _, c := range cases {
		settings := testSettings()
		settings.CaOrder = []certsservice.CertsCa{c.ca}
		if c.letsEncryptLifetime != 0 {
			settings.Cas[certsservice.CertsCaLetsEncrypt].OrderLifetime = c.letsEncryptLifetime
		}
		run := newTestRun(t, settings)
		certId := run.accept(run.device(c.label))
		acceptedAt := testIdTime(certId)
		for _, age := range c.requeuedAges {
			run.clock.AdvanceTo(acceptedAt.Add(age))
			run.acme.script(errors.New("the CA is down"))
			if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{certId}) || len(report.Failed) != 0 {
				t.Fatalf("%s at %v: %+v", c.label, age, report)
			}
		}
		run.clock.AdvanceTo(acceptedAt.Add(c.failedAge))
		run.acme.script(errors.New("the CA is down"))
		if report := run.runOrders(); !slices.Equal(report.Failed, []sidecar.Id{certId}) {
			t.Fatalf("%s at %v: %+v", c.label, c.failedAge, report)
		}
		if state := run.row(certId).State; state != sidecar.TlsCertStateFailed {
			t.Fatalf("%s: state %s", c.label, state)
		}
		for _, order := range run.acme.ordered() {
			if order.Ca != c.ca {
				t.Fatalf("%s: an order went to %s", c.label, order.Ca)
			}
		}
	}
}

// A renewal of a live certificate keeps trying past LE's order lifetime and past OrderGiveUpAge, since
// nothing else would renew it: the give-up bounds only orders that renew nothing.
func TestCertsRunOrdersRenewalOutlivesTheGiveUpAge(t *testing.T) {
	run := newTestRun(t, nil)
	run.issuedWithChain(run.device("k9giveup04"), certsservice.CertsCaLetsEncrypt, big.NewInt(0x77ac01))
	run.clock.Advance(30 * 24 * time.Hour)
	renewals := run.runRenewals()
	if len(renewals.Queued) != 1 {
		t.Fatalf("renewals %+v", renewals)
	}
	renewalId := renewals.Queued[0]
	queuedAt := testIdTime(renewalId)
	for _, age := range []time.Duration{8 * time.Hour, run.settings.OrderGiveUpAge, run.settings.OrderGiveUpAge + time.Hour} {
		run.clock.AdvanceTo(queuedAt.Add(age))
		run.acme.script(errors.New("the CA is down"))
		if report := run.runOrders(); !slices.Equal(report.Requeued, []sidecar.Id{renewalId}) || len(report.Failed) != 0 {
			t.Fatalf("at %v: %+v", age, report)
		}
	}
	if state := run.row(renewalId).State; state != sidecar.TlsCertStateQueued {
		t.Fatalf("state %s", state)
	}
}

// An ARI renewal goes to its certificate's CA past every limit and hold at once, before the window the
// CA suggested: LE's Retry-After, a spent new-set budget, its set's spent repeated-set bucket and a name
// held for failed authorizations. LE exempts it from every rate limit and names no window. Its order
// names the certificate it replaces and spends no budget, while a new set of another network and an
// order of the same set that renews nothing wait.
func TestCertsAriRenewalSkipsEveryLimitAndHold(t *testing.T) {
	settings := testSettings()
	settings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	settings.Cas[certsservice.CertsCaLetsEncrypt].BudgetCap = 1
	settings.RepeatSetCount = 1
	run := newTestRun(t, settings)
	device := run.device("k9arinew01")
	serial := big.NewInt(0x77ad01)
	predecessor := run.issuedWithChain(device, certsservice.CertsCaLetsEncrypt, serial)
	// rows accepted from here sort after the predecessor, as rows of a later millisecond do, so its set
	// reads as issued before them
	run.clock.Advance(time.Millisecond)
	// the CA suggests renewing 20 days on: a renewal now is before its window
	windowStart := run.clock.Now().Add(20 * 24 * time.Hour)
	moved, err := run.store.TransitionCert(run.ctx, &certsservice.CertsTransition{
		CertId:         predecessor.CertId,
		From:           []sidecar.TlsCertState{sidecar.TlsCertStateIssued},
		To:             sidecar.TlsCertStateIssued,
		At:             run.clock.Now(),
		AriWindowStart: windowStart,
		AriWindowEnd:   windowStart.Add(5 * 24 * time.Hour),
	})
	if err != nil || !moved {
		t.Fatalf("the window: %v, %v", moved, err)
	}

	// the budget's one unit is the predecessor's, and its set's one order too
	newSetId := run.accept(run.device("k9arinew02"))
	rekeyed := *device
	rekeyed.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repeatId := run.accept(&rekeyed)
	waits := func(report *certsservice.CertsAdmitReport) map[sidecar.Id]certsservice.CertsWaitReason {
		reasons := map[sidecar.Id]certsservice.CertsWaitReason{}
		for _, wait := range report.Waiting {
			reasons[wait.CertId] = wait.Reason
		}
		return reasons
	}
	report := run.admit()
	if reasons := waits(report); len(report.Admitted) != 0 || reasons[newSetId] != certsservice.CertsWaitBudget ||
		reasons[repeatId] != certsservice.CertsWaitRepeatSet {
		t.Fatalf("the limits: %+v", report)
	}
	// then the CA holds, and the set's names fail authorization
	run.service.HoldCa(certsservice.CertsCaLetsEncrypt, run.clock.Now().Add(2*time.Hour))
	for range settings.FailedAuthorizationCount {
		run.service.RecordAuthorizationFailures(device.identifierSet)
	}
	report = run.admit()
	if reasons := waits(report); len(report.Admitted) != 0 || reasons[newSetId] != certsservice.CertsWaitCaHold ||
		reasons[repeatId] != certsservice.CertsWaitNameHold {
		t.Fatalf("the holds: %+v", report)
	}

	budgetBefore := testBudgetMembers(t, run.testCerts)
	renewal := device.order(t)
	renewal.Args.Replaces = testCertificateId(run.acme.issuer.SubjectKeyId, serial)
	renewalResult, err := run.service.Accept(run.ctx, renewal)
	if err != nil {
		t.Fatal(err)
	}
	if run.row(predecessor.CertId).SuccessorCertId != renewalResult.CertId {
		t.Fatal("the renewal is not the predecessor's successor")
	}
	orders := run.runOrders()
	if !slices.Equal(orders.Admitted, []sidecar.Id{renewalResult.CertId}) || !slices.Equal(orders.Issued, []sidecar.Id{renewalResult.CertId}) {
		t.Fatalf("orders %+v", orders)
	}
	if reasons := waits(&certsservice.CertsAdmitReport{Waiting: orders.Waiting}); reasons[newSetId] != certsservice.CertsWaitCaHold ||
		reasons[repeatId] != certsservice.CertsWaitNameHold {
		t.Fatalf("the others: %+v", orders.Waiting)
	}
	sent := run.acme.ordered()
	if len(sent) != 1 || sent[0].Ca != certsservice.CertsCaLetsEncrypt || sent[0].Replaces != renewal.Args.Replaces ||
		string(sent[0].Csr) != string(renewal.Args.Csr) {
		t.Fatalf("orders sent %+v", sent)
	}
	if !run.clock.Now().Before(windowStart) {
		t.Fatal("the renewal ran inside its window")
	}
	if budgetAfter := testBudgetMembers(t, run.testCerts); len(budgetAfter) != len(budgetBefore) {
		t.Fatalf("the renewal spent budget: %v, then %v", budgetBefore, budgetAfter)
	}
}
