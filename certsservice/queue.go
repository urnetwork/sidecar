// The admission pass over network_tls_cert's queue (§13.8's Budget; D-TLS-7): queued rows, oldest first,
// each admitted to a CA under the policy (ca_policy.go) and moved to ordering with its CA and profile,
// or left queued with why. The order itself is the chains' (TLS-M5-17's RunOrders, on TLS-M5-15's
// CertsAcme), which take what this pass admitted.
//
// A pass reads at most AdmitBatchCount rows and resumes from its cursor, so one row that waits never
// holds back the scan (connect/CODESTYLE.md:135). A row moves only from queued, so two passes never
// admit one row twice; a budget unit spent for a row another pass admitted first is spent once, under
// the row's own id, and only overcounts.
//
// A name's failure backoff at a CA (QD-857) is read from the store once a row, and holds the row at that
// CA alone: the next CA in the order is tried, under its own hold, rule and budget, and the row waits
// only when none is open. A renewal skips it, as it skips every limit.
//
// An identifier set has one order under way at a time (QD-1189). Its orders validate at the same
// _acme-challenge names, which hold two values (§12.7), so a second order of the set beside the first
// would be refused at a name only after it had opened its order at the CA, spent a unit of the budget as
// a new set and perhaps one of the name's ten writes an hour. A queued row whose set has a row ordering or
// waiting_dns waits, a renewal too, since it writes the same names; once that order has ended the row
// goes, as a repeated set when the order issued. The budget's unit is then the set's first certificate,
// as §13.8's Budget reads. Two sets that share a challenge name are held the same way (QD-1203), as the
// network's pair alone and a set with a live alias's pair beside it are around the alias's start or
// retirement, a device renewing its stored set until it orders anew: a queued row also waits while an
// order under way holds one of its challenge names, its CSR's DNS names with a leading *. trimmed. A
// pass reads every row under way, a batch at a time, before it reads the queue, and counts each row it
// admits as under way from then: the order pass admits only while it has taken up fewer rows under way
// than OrderResumeCount (run.go), so there are few to read. Two passes at once, which the order chain's
// one task makes rare, may still each admit a row of one set, as before.

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

// What the orders under way hold, each with one such row's id: their identifier sets, and their
// challenge names (certsChallengeNameOf), whose _acme-challenge names their challenges write. A pass's
// own, not safe for concurrent use.
type certsUnderWay struct {
	setCertIds  map[string]sidecar.Id
	nameCertIds map[string]sidecar.Id
}

// Holds row's set, and the challenge names of names, its CSR's.
func (self *certsUnderWay) hold(row *sidecar.TlsCertRecord, names []string) {
	self.setCertIds[string(row.IdentifierSetSha256)] = row.CertId
	for _, name := range names {
		self.nameCertIds[certsChallengeNameOf(name)] = row.CertId
	}
}

// Why row, whose CSR names names, waits on an order under way: its set's, then one sharing a challenge
// name. Empty when none holds it.
func (self *certsUnderWay) waitReason(row *sidecar.TlsCertRecord, names []string) CertsWaitReason {
	if _, held := self.setCertIds[string(row.IdentifierSetSha256)]; held {
		return CertsWaitSetUnderWay
	}
	for _, name := range names {
		if _, held := self.nameCertIds[certsChallengeNameOf(name)]; held {
			return CertsWaitNameUnderWay
		}
	}
	return ""
}

// One pass from after afterCertId. A store or budget error ends the pass with what it has done, and the
// rows it did not reach stay queued for the next; one reading the rows under way admits none.
func (self *CertsService) Admit(ctx context.Context, afterCertId sidecar.Id) (*CertsAdmitReport, error) {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	report := &CertsAdmitReport{}
	underWay, err := self.readUnderWay(callCtx)
	if err != nil {
		return report, err
	}
	rows, err := self.store.ListQueued(callCtx, afterCertId, self.settings.AdmitBatchCount)
	if err != nil {
		return report, err
	}
	if len(rows) == self.settings.AdmitBatchCount {
		report.NextCertId = rows[len(rows)-1].CertId
	}
	for _, row := range rows {
		if err := self.admitRow(callCtx, row, underWay, report); err != nil {
			return report, err
		}
	}
	return report, nil
}

// What the rows under way at a CA (ordering, waiting_dns) hold, read whole, UnderWayBatchCount rows at a
// time.
func (self *CertsService) readUnderWay(ctx context.Context) (*certsUnderWay, error) {
	states := []sidecar.TlsCertState{sidecar.TlsCertStateOrdering, sidecar.TlsCertStateWaitingDns}
	underWay := &certsUnderWay{setCertIds: map[string]sidecar.Id{}, nameCertIds: map[string]sidecar.Id{}}
	afterCertId := sidecar.Id{}
	for {
		rows, err := self.store.ListInStates(ctx, states, afterCertId, self.settings.UnderWayBatchCount)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			// admission took the row, so its CSR parsed; one that no longer does holds its set alone
			names, _ := certsCsrNames(row.Csr)
			underWay.hold(row, names)
		}
		if len(rows) < self.settings.UnderWayBatchCount {
			return underWay, nil
		}
		afterCertId = rows[len(rows)-1].CertId
	}
}

// Admits row to the first CA the policy opens, or notes why it waits. underWay holds what the orders
// under way hold, and takes row's once row is admitted.
func (self *CertsService) admitRow(ctx context.Context, row *sidecar.TlsCertRecord, underWay *certsUnderWay, report *CertsAdmitReport) error {
	now := self.clock.Now()
	names, err := certsCsrNames(row.Csr)
	if err != nil || len(names) == 0 {
		moved, err := self.store.TransitionCert(ctx, &CertsTransition{
			CertId: row.CertId,
			From:   []sidecar.TlsCertState{sidecar.TlsCertStateQueued},
			To:     sidecar.TlsCertStateFailed,
			At:     now,
		})
		if err != nil {
			return err
		}
		if moved {
			report.Failed = append(report.Failed, row.CertId)
		}
		return nil
	}

	// one order of a set, or of a challenge name, at a time, a renewal's too (the file header): a row that
	// waits on one asks no CA, budget or name for anything, and its wait has no time, since only the other
	// order's end frees it
	if reason := underWay.waitReason(row, names); reason != "" {
		report.Waiting = append(report.Waiting, &CertsWait{CertId: row.CertId, Reason: reason})
		return nil
	}
	admit := func(ca CertsCa, kind CertsOrderKind, replaces *sidecar.TlsCertRecord) error {
		// held from the move's try on: a row another pass moved first is under way there
		underWay.hold(row, names)
		return self.admitTo(ctx, row, ca, kind, replaces, report)
	}

	// a renewal goes to its certificate's CA past every limit and hold, in its ARI window or not: LE
	// exempts an order from every rate limit when its replaces names a certificate not already replaced
	// through ARI, and names no window (rate-limits page, read 2026-11-15)
	predecessor, err := self.store.GetPredecessor(ctx, row.CertId)
	if err != nil {
		return err
	}
	if predecessor != nil && predecessor.State == sidecar.TlsCertStateIssued && now.Before(predecessor.NotAfter) &&
		bytes.Equal(predecessor.IdentifierSetSha256, row.IdentifierSetSha256) {
		ca := CertsCa(predecessor.Ca)
		if self.settings.Cas[ca] != nil {
			return admit(ca, CertsOrderRenewal, predecessor)
		}
	}

	for _, name := range names {
		if held, until := certsNameHeldUntil(self.nameFailureTimes(name), now, self.settings.FailedAuthorizationCount, self.settings.FailedAuthorizationWindow); held {
			report.Waiting = append(report.Waiting, &CertsWait{CertId: row.CertId, Reason: CertsWaitNameHold, Until: until})
			return nil
		}
	}
	// each name's backoff at every CA, which the loop below reads a CA at a time
	backoffs, err := self.store.ListNameBackoffs(ctx, names)
	if err != nil {
		return err
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
		if until := certsNameBackoffUntil(backoffs, ca, now); !until.IsZero() {
			note(CertsWaitNameBackoff, until)
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
		return admit(ca, kind, nil)
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
		At:      self.clock.Now(),
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
