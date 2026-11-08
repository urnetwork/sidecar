// The admission pass over network_tls_cert's queue (§13.8's Budget; D-TLS-7): queued rows, oldest first,
// each admitted to a CA under the policy (ca_policy.go) and moved to ordering with its CA and profile,
// or left queued with why. The order itself is the chains' (TLS-M5-17's RunOrders, on TLS-M5-15's
// CertsAcme), which take what this pass admitted.
//
// A pass reads at most AdmitBatchCount rows and resumes from its cursor, so one row that waits never
// holds back the scan (connect/CODESTYLE.md:135). A row moves only from queued, so two passes never
// admit one row twice; a budget unit spent for a row another pass admitted first is spent once, under
// the row's own id, and only overcounts.

package certsservice

import (
	"bytes"
	"context"
	"time"

	"github.com/urnetwork/sidecar"
)

// A row this pass admitted.
type CertsAdmission struct {
	// The row as it now stands: ordering, with its CA and profile.
	Cert *sidecar.TlsCertRecord
	Ca   CertsCa
	Kind CertsOrderKind
	// The live certificate a renewal replaces, whose CA it goes to. Nil for any other order.
	Replaces *sidecar.TlsCertRecord
}

// A row that stays queued, and why.
type CertsWait struct {
	CertId sidecar.Id
	Reason CertsWaitReason
	// When it may go, zero when only the budget's window can say.
	Until time.Time
}

// What one pass did.
type CertsAdmitReport struct {
	Admitted []*CertsAdmission
	Waiting  []*CertsWait
	// Rows no CA can ever take, moved to failed: a stored CSR that no longer parses.
	Failed []sidecar.Id
	// The last row read when the batch was full, where the next pass resumes; zero once the queue was
	// read to its end.
	NextCertId sidecar.Id
}

// When the set's earlier orders at a CA count against the repeated-set rule: an order under way counts
// now, an issued one from its certificate's not_before or its id, whichever is later, and a failed one
// not at all, since no certificate came of it.
func certsSetOrderTimes(rows []*sidecar.TlsCertRecord, now time.Time) []time.Time {
	times := []time.Time{}
	for _, row := range rows {
		switch {
		case row.State == sidecar.TlsCertStateOrdering || row.State == sidecar.TlsCertStateWaitingDns:
			times = append(times, now)
		case row.Serial != "":
			orderTime := certsIdTime(row.CertId)
			if row.NotBefore.After(orderTime) {
				orderTime = row.NotBefore
			}
			times = append(times, orderTime)
		}
	}
	return times
}

// One pass from after afterCertId. A store or budget error ends the pass with what it has done, and the
// rows it did not reach stay queued for the next.
func (self *CertsService) Admit(ctx context.Context, afterCertId sidecar.Id) (*CertsAdmitReport, error) {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	report := &CertsAdmitReport{}
	rows, err := self.store.ListQueued(callCtx, afterCertId, self.settings.AdmitBatchCount)
	if err != nil {
		return report, err
	}
	if len(rows) == self.settings.AdmitBatchCount {
		report.NextCertId = rows[len(rows)-1].CertId
	}
	for _, row := range rows {
		if err := self.admitRow(callCtx, row, report); err != nil {
			return report, err
		}
	}
	return report, nil
}

// Admits row to the first CA the policy opens, or notes why it waits.
func (self *CertsService) admitRow(ctx context.Context, row *sidecar.TlsCertRecord, report *CertsAdmitReport) error {
	now := self.clock.Now()
	names, err := certsCsrNames(row.Csr)
	if err != nil || len(names) == 0 {
		moved, err := self.store.TransitionCert(ctx, &CertsTransition{
			CertId: row.CertId,
			From:   []sidecar.TlsCertState{sidecar.TlsCertStateQueued},
			To:     sidecar.TlsCertStateFailed,
		})
		if err != nil {
			return err
		}
		if moved {
			report.Failed = append(report.Failed, row.CertId)
		}
		return nil
	}

	// a renewal goes to its certificate's CA past every limit and hold
	predecessor, err := self.store.GetPredecessor(ctx, row.CertId)
	if err != nil {
		return err
	}
	if predecessor != nil && predecessor.State == sidecar.TlsCertStateIssued && now.Before(predecessor.NotAfter) &&
		bytes.Equal(predecessor.IdentifierSetSha256, row.IdentifierSetSha256) {
		ca := CertsCa(predecessor.Ca)
		if self.settings.Cas[ca] != nil {
			return self.admitTo(ctx, row, ca, CertsOrderRenewal, predecessor, report)
		}
	}

	for _, name := range names {
		if held, until := certsNameHeldUntil(self.nameFailureTimes(name), now, self.settings.FailedAuthorizationCount, self.settings.FailedAuthorizationWindow); held {
			report.Waiting = append(report.Waiting, &CertsWait{CertId: row.CertId, Reason: CertsWaitNameHold, Until: until})
			return nil
		}
	}

	ephemeral, err := self.store.ClientEphemeral(ctx, row.ClientId)
	if err != nil {
		return err
	}
	repeated, err := self.store.SetIssuedBefore(ctx, row.IdentifierSetSha256, row.CertId)
	if err != nil {
		return err
	}
	kind := CertsOrderNewSet
	if repeated {
		kind = CertsOrderRepeatSet
	}
	// the first CA's reason names the wait, and the earliest time any CA opens bounds it
	wait := &CertsWait{CertId: row.CertId}
	note := func(reason CertsWaitReason, until time.Time) {
		if wait.Reason == "" {
			wait.Reason = reason
		}
		if !until.IsZero() && (wait.Until.IsZero() || until.Before(wait.Until)) {
			wait.Until = until
		}
	}
	for _, ca := range self.settings.caOrder(ephemeral) {
		caSettings := self.settings.Cas[ca]
		if hold := self.caHold(ca); certsCaHeld(hold, now) {
			note(CertsWaitCaHold, hold)
			continue
		}
		if kind == CertsOrderRepeatSet && caSettings.RepeatSetLimited {
			since := now.Add(-time.Duration(self.settings.RepeatSetCount) * self.settings.RepeatSetRefill)
			setRows, err := self.store.ListSetOrders(ctx, row.IdentifierSetSha256, ca, since)
			if err != nil {
				return err
			}
			fits, at := certsRepeatSetNext(certsSetOrderTimes(setRows, now), now, self.settings.RepeatSetCount, self.settings.RepeatSetRefill)
			if !fits {
				note(CertsWaitRepeatSet, at)
				continue
			}
		}
		if kind == CertsOrderNewSet {
			spent, err := self.budget.Spend(ctx, ca, row.CertId, now)
			if err != nil {
				return err
			}
			if !spent {
				note(CertsWaitBudget, time.Time{})
				continue
			}
		}
		return self.admitTo(ctx, row, ca, kind, nil, report)
	}
	report.Waiting = append(report.Waiting, wait)
	return nil
}

// Moves row from queued to ordering at ca.
func (self *CertsService) admitTo(ctx context.Context, row *sidecar.TlsCertRecord, ca CertsCa, kind CertsOrderKind, replaces *sidecar.TlsCertRecord, report *CertsAdmitReport) error {
	profile := self.settings.Cas[ca].Profile
	testHookBarrier("certs.admit.transition", row.CertId.String())
	moved, err := self.store.TransitionCert(ctx, &CertsTransition{
		CertId:  row.CertId,
		From:    []sidecar.TlsCertState{sidecar.TlsCertStateQueued},
		To:      sidecar.TlsCertStateOrdering,
		Ca:      ca,
		Profile: profile,
	})
	if err != nil || !moved {
		// another pass admitted it first
		return err
	}
	admitted := *row
	admitted.State = sidecar.TlsCertStateOrdering
	admitted.Ca = string(ca)
	admitted.Profile = profile
	report.Admitted = append(report.Admitted, &CertsAdmission{Cert: &admitted, Ca: ca, Kind: kind, Replaces: replaces})
	return nil
}
