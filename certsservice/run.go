// The chains' passes (TLS-M5-17; §13.8, §19.4): what taskworker runs on a schedule, each pass bounded and
// resumable, as the extender's issuance chain is (server/taskworker/work/extender_measurement_work.go).
//
//   - RunOrders takes up the rows an earlier pass left under way, admits queued rows under the policy
//     (queue.go), and takes each to its CA through CertsAcme: issued, queued again or failed.
//   - RunRenewals reads the issued rows: one past its validity is expired, and one due (renew.go) queues
//     its stored CSR as its successor, so a device that is offline still renews. It also rolls an
//     account's key over once it is a year old and its next key is there (accounts.go).
//   - RunRevocations is the sweep: it asks the host which issued certificates must go, without a hook
//     from any other area, marks them revoking, and takes every revoking row to its CA.
//
// Every row moves through CertsStore.TransitionCert, which applies only from the states named, so two
// passes never both move a row, and a pass that dies leaves a row where the next finds it: an order
// under way is ordered again, and a revoking row is asked again. A row that fails does not stop the
// scan. No lock is held across a store, DNS or CA call (connect/CODESTYLE.md's durable-state rule):
// a pass reads its rows, then works on its copies.
//
// A host with no ACME client (ClosedCertsAcme) admits and queues nothing, so no row waits on a CA that
// will never answer and no budget is spent; its sweep still marks, since a certificate that must go
// stops renewing and its device is told at once.
//
// What a pass cannot do yet, because a URnetwork-zone row keeps no chain until
// tls-m5-05-cert-row-values' columns land (QD-741): an issued chain is not written to its row, a
// renewal carries `replaces` only where its predecessor's row has a chain, an ARI window is read again
// only for such a row, and a revoking row with no chain waits, since a CA revokes a certificate it is
// shown (RFC 8555 §7.6). A marked row's reason is not kept either: the sweep tells the CA the reason of
// the cause it found in the same pass, and cessationOfOperation otherwise.
//
// Each move publishes a TlsHint (hints.go).

package certsservice

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The hints one pass published, and those its host did not take.
type CertsHintCounts struct {
	Sent   int
	Failed int
}

func (self *CertsHintCounts) add(other CertsHintCounts) {
	self.Sent += other.Sent
	self.Failed += other.Failed
}

// Publishes a hint and counts it. A host with no Push counts nothing.
func (self *CertsService) hintCounted(ctx context.Context, counts *CertsHintCounts, row *sidecar.TlsCertRecord, kind protocol.TlsHintKind) {
	if self.push == nil {
		return
	}
	if self.hint(ctx, row, kind) {
		counts.Sent += 1
	} else {
		counts.Failed += 1
	}
}

// Whether this host can reach a CA at all.
func (self *CertsService) acmeClosed() bool {
	_, closed := self.acme.(ClosedCertsAcme)
	return closed
}

// A store read under its own bound.
func (self *CertsService) listInStates(ctx context.Context, states []sidecar.TlsCertState, afterCertId sidecar.Id, count int) ([]*sidecar.TlsCertRecord, error) {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	return self.store.ListInStates(callCtx, states, afterCertId, count)
}

// A row's move under its own bound, which outlives the pass: what a CA did is recorded even when the
// pass's time ended while it answered.
func (self *CertsService) transition(ctx context.Context, transition *CertsTransition) (bool, error) {
	callCtx, cancel := self.callContext(context.WithoutCancel(ctx))
	defer cancel()
	return self.store.TransitionCert(callCtx, transition)
}

// RFC 9773's certificate id of leaf: base64url of its authority key id, a dot, and base64url of its
// serial's DER content octets. Empty for a leaf with no authority key id.
func certsCertificateId(leaf *x509.Certificate) string {
	if len(leaf.AuthorityKeyId) == 0 || leaf.SerialNumber == nil {
		return ""
	}
	serialDer, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil || len(serialDer) < 3 {
		return ""
	}
	// a serial is at most 20 octets (RFC 5280 §4.1.2.2), so its DER length is one octet
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serialDer[2:])
}

// The live certificate row's order renews, nil when it renews none: its predecessor, issued, still
// valid at now and of the same set, as the admission pass reads it (queue.go).
func (self *CertsService) livePredecessor(ctx context.Context, row *sidecar.TlsCertRecord, now time.Time) (*sidecar.TlsCertRecord, error) {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	predecessor, err := self.store.GetPredecessor(callCtx, row.CertId)
	if err != nil || predecessor == nil {
		return nil, err
	}
	if predecessor.State != sidecar.TlsCertStateIssued || !now.Before(predecessor.NotAfter) ||
		!bytes.Equal(predecessor.IdentifierSetSha256, row.IdentifierSetSha256) {
		return nil, nil
	}
	return predecessor, nil
}

// The `replaces` an order renewing predecessor carries: its certificate's id, when its row has a chain
// and the order goes to the CA that issued it. Empty otherwise, and the CA counts the order as a
// repeated one.
func certsOrderReplaces(row *sidecar.TlsCertRecord, predecessor *sidecar.TlsCertRecord) string {
	if predecessor == nil || len(predecessor.Chain) == 0 || predecessor.Ca != row.Ca {
		return ""
	}
	leaf, err := x509.ParseCertificate(predecessor.Chain[0])
	if err != nil {
		return ""
	}
	return certsCertificateId(leaf)
}

// What one order pass did. Ids are the rows'.
type CertsOrdersReport struct {
	// The host has no ACME client: nothing was admitted and nothing ordered.
	Unavailable bool
	// Rows an earlier pass left under way, ordered again by this one.
	Resumed []sidecar.Id
	// Rows this pass admitted to a CA.
	Admitted []sidecar.Id
	// Rows the policy left queued, and why.
	Waiting []*CertsWait
	// Orders their CA issued.
	Issued []sidecar.Id
	// Orders that queue again: a CA's refusal on a limit, which holds the CA, a failed authorization,
	// which counts against its names, or a failure that may pass.
	Requeued []sidecar.Id
	// Rows moved to failed: a CSR no CA can take, or an order past OrderGiveUpAge.
	Failed []sidecar.Id
	// Orders the pass's end cut short, left under way for the next.
	Interrupted []sidecar.Id
	Hints       CertsHintCounts
	// Where the next pass reads the queue from: the last row read when the batch was full, zero once the
	// queue was read to its end.
	NextCertId sidecar.Id
	// More work is waiting than this pass took: the next should not wait a whole interval.
	More bool
}

// One order of a pass.
type certsRunOrder struct {
	cert *sidecar.TlsCertRecord
	// the live certificate it renews, nil for any other order
	predecessor *sidecar.TlsCertRecord
}

type certsOrderEnd int

const (
	certsOrderIssued certsOrderEnd = iota
	certsOrderRequeued
	certsOrderFailed
	certsOrderInterrupted
)

type certsOrderOutcome struct {
	end   certsOrderEnd
	hints CertsHintCounts
}

// One pass of the order chain from after afterCertId in the queue. A store or budget error ends the
// admission with what it has admitted, whose orders still run, and is returned with the report.
func (self *CertsService) RunOrders(ctx context.Context, afterCertId sidecar.Id) (*CertsOrdersReport, error) {
	report := &CertsOrdersReport{}
	if self.acmeClosed() {
		report.Unavailable = true
		return report, nil
	}
	now := self.clock.Now()
	orders := []*certsRunOrder{}

	// a pass that died left these with their CA chosen and their budget spent
	underWay := []sidecar.TlsCertState{sidecar.TlsCertStateOrdering, sidecar.TlsCertStateWaitingDns}
	resumed, err := self.listInStates(ctx, underWay, sidecar.Id{}, self.settings.OrderResumeCount)
	if err != nil {
		return report, err
	}
	for _, row := range resumed {
		predecessor, err := self.livePredecessor(ctx, row, now)
		if err != nil {
			return report, err
		}
		orders = append(orders, &certsRunOrder{cert: row, predecessor: predecessor})
		report.Resumed = append(report.Resumed, row.CertId)
	}

	var passErr error
	if len(resumed) < self.settings.OrderResumeCount {
		admitReport, admitErr := self.Admit(ctx, afterCertId)
		passErr = admitErr
		for _, admission := range admitReport.Admitted {
			orders = append(orders, &certsRunOrder{cert: admission.Cert, predecessor: admission.Replaces})
			report.Admitted = append(report.Admitted, admission.Cert.CertId)
			self.hintCounted(ctx, &report.Hints, admission.Cert, protocol.TlsHintKind_TLS_HINT_ORDER)
		}
		for _, certId := range admitReport.Failed {
			report.Failed = append(report.Failed, certId)
			self.hintFailed(ctx, &report.Hints, certId)
		}
		report.Waiting = admitReport.Waiting
		report.NextCertId = admitReport.NextCertId
		report.More = admitReport.NextCertId != (sidecar.Id{})
	} else {
		// full of earlier work: the queue is read from the same place next time
		report.NextCertId = afterCertId
		report.More = true
	}

	outcomes := make([]certsOrderOutcome, len(orders))
	slots := make(chan struct{}, self.settings.OrderConcurrency)
	var running sync.WaitGroup
	for index, order := range orders {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			outcomes[index] = certsOrderOutcome{end: certsOrderInterrupted}
			continue
		}
		running.Add(1)
		go func() {
			defer running.Done()
			defer func() { <-slots }()
			outcomes[index] = self.runOrder(ctx, order)
		}()
	}
	running.Wait()
	for index, outcome := range outcomes {
		certId := orders[index].cert.CertId
		switch outcome.end {
		case certsOrderIssued:
			report.Issued = append(report.Issued, certId)
		case certsOrderRequeued:
			report.Requeued = append(report.Requeued, certId)
		case certsOrderFailed:
			report.Failed = append(report.Failed, certId)
		case certsOrderInterrupted:
			report.Interrupted = append(report.Interrupted, certId)
			report.More = true
		}
		report.Hints.add(outcome.hints)
	}
	return report, passErr
}

// The hint of a row the admission pass failed, which its report names only by id.
func (self *CertsService) hintFailed(ctx context.Context, counts *CertsHintCounts, certId sidecar.Id) {
	if self.push == nil {
		return
	}
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	row, err := self.store.GetCert(callCtx, certId)
	if err != nil {
		counts.Failed += 1
		return
	}
	self.hintCounted(ctx, counts, row, protocol.TlsHintKind_TLS_HINT_ORDER)
}

// Takes one admitted row to its CA and records how it ended.
func (self *CertsService) runOrder(ctx context.Context, order *certsRunOrder) certsOrderOutcome {
	outcome := certsOrderOutcome{}
	row := order.cert
	ca := CertsCa(row.Ca)
	underWay := []sidecar.TlsCertState{sidecar.TlsCertStateOrdering, sidecar.TlsCertStateWaitingDns}
	testHookBarrier("certs.run_order.before", row.CertId.String())
	issued, err := self.acme.Order(ctx, &CertsAcmeOrder{
		Ca:       ca,
		Profile:  row.Profile,
		Csr:      row.Csr,
		Replaces: certsOrderReplaces(row, order.predecessor),
	})
	if err == nil && (issued == nil || len(issued.Chain) == 0) {
		err = errors.New("the CA answered no certificate")
	}
	if err != nil {
		if ctx.Err() != nil {
			// the pass ended, not the order: the row stays under way and the next pass orders it again
			outcome.end = certsOrderInterrupted
			return outcome
		}
		var rateLimit *CertsAcmeRateLimitError
		var authorization *CertsAcmeAuthorizationError
		switch {
		case errors.As(err, &rateLimit):
			self.HoldCa(ca, rateLimit.RetryAfter)
		case errors.As(err, &authorization):
			self.RecordAuthorizationFailures(authorization.Names)
		}
		// an order that keeps failing ends, so its device hears and may order again; a renewal of a
		// certificate still valid keeps trying, since nothing else would renew it
		to := sidecar.TlsCertStateQueued
		outcome.end = certsOrderRequeued
		if order.predecessor == nil && self.settings.OrderGiveUpAge <= self.clock.Now().Sub(certsIdTime(row.CertId)) {
			to = sidecar.TlsCertStateFailed
			outcome.end = certsOrderFailed
		}
		moved, moveErr := self.transition(ctx, &CertsTransition{CertId: row.CertId, From: underWay, To: to})
		if moveErr != nil || !moved {
			// the row stays under way, or another pass moved it: the next pass reads it as it stands
			outcome.end = certsOrderInterrupted
			return outcome
		}
		self.hintCounted(ctx, &outcome.hints, row, protocol.TlsHintKind_TLS_HINT_ORDER)
		return outcome
	}

	move := &CertsTransition{
		CertId:     row.CertId,
		From:       underWay,
		To:         sidecar.TlsCertStateIssued,
		AccountUri: issued.AccountUri,
		Serial:     issued.Serial,
		NotBefore:  issued.NotBefore,
		NotAfter:   issued.NotAfter,
	}
	// the CA's suggested window, when it gives one: without it the row renews at two thirds
	if windowStart, windowEnd, ariErr := self.acme.RenewalInfo(ctx, ca, issued.Chain[0]); ariErr == nil && windowStart.Before(windowEnd) {
		move.AriWindowStart = windowStart
		move.AriWindowEnd = windowEnd
	}
	testHookBarrier("certs.run_order.issued", row.CertId.String())
	moved, moveErr := self.transition(ctx, move)
	if moveErr != nil || !moved {
		outcome.end = certsOrderInterrupted
		return outcome
	}
	outcome.end = certsOrderIssued
	self.hintCounted(ctx, &outcome.hints, row, protocol.TlsHintKind_TLS_HINT_ISSUED)
	return outcome
}

// An account whose key is due to roll over.
type CertsAccountRollover struct {
	Ca CertsCa
	// Whether it rolled over. False with a nil Err: its file holds no next key yet, which an operator
	// places (tls-m5-15-acme-account-rollover).
	RolledOver bool
	Err        error
}

// Rolls over each account whose key is AccountRolloverAge old and whose file holds its next key (RFC
// 8555 §7.3.5), and names each that is due and has none.
func (self *CertsAcmeClient) RunAccountRollovers(ctx context.Context) []*CertsAccountRollover {
	rollovers := []*CertsAccountRollover{}
	for _, ca := range self.accounts.Cas() {
		due, ready := self.accounts.RolloverDue(ca, self.clock.Now(), self.settings.AccountRolloverAge)
		if !due {
			continue
		}
		rollover := &CertsAccountRollover{Ca: ca}
		if ready {
			rollover.Err = self.RolloverAccount(ctx, ca)
			rollover.RolledOver = rollover.Err == nil
		}
		rollovers = append(rollovers, rollover)
	}
	return rollovers
}

// A CertsAcme that keeps accounts, as *CertsAcmeClient does.
type certsAccountRoller interface {
	RunAccountRollovers(ctx context.Context) []*CertsAccountRollover
}

// What one renewal pass did.
type CertsRenewalsReport struct {
	// The host has no ACME client: nothing was queued.
	Unavailable bool
	// Issued rows whose validity ended, now expired.
	Expired []sidecar.Id
	// The renewals queued: each a new row, its predecessor's successor.
	Queued []sidecar.Id
	// Rows whose ARI window the CA gave anew.
	WindowsRead int
	// Rows the pass could not move, left for the next.
	FailedCount int
	// Accounts due a key rollover, rolled or not.
	Rollovers []*CertsAccountRollover
	Hints     CertsHintCounts
	// Where the next pass reads from: the last row read when the batch was full, zero once every issued
	// row was read.
	NextCertId sidecar.Id
}

// One pass of the renewal chain over the issued rows after afterCertId. A store error reading the
// rows ends the pass; one row's failure does not.
func (self *CertsService) RunRenewals(ctx context.Context, afterCertId sidecar.Id) (*CertsRenewalsReport, error) {
	report := &CertsRenewalsReport{Unavailable: self.acmeClosed()}
	if roller, ok := self.acme.(certsAccountRoller); ok && afterCertId == (sidecar.Id{}) {
		// once a scan, at its start
		report.Rollovers = roller.RunAccountRollovers(ctx)
	}
	rows, err := self.listInStates(ctx, []sidecar.TlsCertState{sidecar.TlsCertStateIssued}, afterCertId, self.settings.RenewalBatchCount)
	if err != nil {
		return report, err
	}
	if len(rows) == self.settings.RenewalBatchCount {
		report.NextCertId = rows[len(rows)-1].CertId
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			// the rest are read again from this pass's start
			report.NextCertId = afterCertId
			return report, ctx.Err()
		}
		now := self.clock.Now()
		if !row.NotAfter.IsZero() && !now.Before(row.NotAfter) {
			moved, err := self.transition(ctx, &CertsTransition{
				CertId: row.CertId,
				From:   []sidecar.TlsCertState{sidecar.TlsCertStateIssued},
				To:     sidecar.TlsCertStateExpired,
			})
			switch {
			case err != nil:
				report.FailedCount += 1
			case moved:
				report.Expired = append(report.Expired, row.CertId)
			}
			continue
		}
		if row.SuccessorCertId != (sidecar.Id{}) {
			continue
		}
		if len(row.Chain) != 0 && !report.Unavailable {
			// RFC 9773 has a client ask again through a certificate's life: a CA moves a window up
			// when it must replace a certificate early
			windowStart, windowEnd, ariErr := self.acme.RenewalInfo(ctx, CertsCa(row.Ca), row.Chain[0])
			if ariErr == nil && windowStart.Before(windowEnd) && (!windowStart.Equal(row.AriWindowStart) || !windowEnd.Equal(row.AriWindowEnd)) {
				moved, err := self.transition(ctx, &CertsTransition{
					CertId:         row.CertId,
					From:           []sidecar.TlsCertState{sidecar.TlsCertStateIssued},
					To:             sidecar.TlsCertStateIssued,
					AriWindowStart: windowStart,
					AriWindowEnd:   windowEnd,
				})
				if err == nil && moved {
					row.AriWindowStart = windowStart
					row.AriWindowEnd = windowEnd
					report.WindowsRead += 1
				}
			}
		}
		if report.Unavailable || !self.RenewalDue(row, now) {
			continue
		}
		renewal, err := self.QueueRenewal(ctx, row.CertId)
		switch {
		case errors.Is(err, ErrCertsNotRenewable):
			// another pass renewed it, or it left issued since the read
		case err != nil:
			report.FailedCount += 1
		default:
			report.Queued = append(report.Queued, renewal.CertId)
			self.hintCounted(ctx, &report.Hints, renewal, protocol.TlsHintKind_TLS_HINT_ORDER)
		}
	}
	return report, nil
}

// A certificate the sweep asks its host about: the row and the DNS names its CSR holds.
type CertsRevocationCandidate struct {
	Cert  *sidecar.TlsCertRecord
	Names []string
}

// What the revocation sweep reads of the rows other areas keep (§13.8's Revocation; I-14, I-15), so no
// other area calls certs: server answers it from Postgres (TLS-M5-17's work.TlsCertRevocations). Safe
// for concurrent use.
type CertsRevocationSource interface {
	// For each candidate that must be revoked, why, by its row's id: its client removed or reaped
	// (CertsRevocationCauseRemoval), its sidecar revoked (the same, or CertsRevocationCauseKeyCompromise
	// for a compromise), its network deleted (CertsRevocationCauseDeletion), or an alias among its
	// names retired (CertsRevocationCauseAliasRetired). A candidate that stays has no entry.
	RevocationCauses(ctx context.Context, candidates []*CertsRevocationCandidate) (map[sidecar.Id]CertsRevocationCause, error)
}

// Where a revocation pass reads from: the sweep over the issued rows, and the revoking rows.
type CertsRevocationCursor struct {
	AfterIssuedCertId   sidecar.Id
	AfterRevokingCertId sidecar.Id
}

// What one revocation pass did.
type CertsRevocationsReport struct {
	// The host has no ACME client: rows were marked and none taken to a CA.
	Unavailable bool
	// Issued rows the sweep found a cause for, now revoking.
	Marked []sidecar.Id
	// Rows their CA revoked.
	Revoked []sidecar.Id
	// Revoking rows whose validity ended before a CA was asked, now expired.
	Expired []sidecar.Id
	// Revoking rows with no chain to show a CA, which wait (run.go's header).
	WaitingCount int
	// Rows the pass could not move or their CA would not take, left for the next.
	FailedCount int
	Hints       CertsHintCounts
	// Where the next pass reads from, each zero once its rows were read to their end.
	Next CertsRevocationCursor
}

func certsCandidates(rows []*sidecar.TlsCertRecord) []*CertsRevocationCandidate {
	candidates := make([]*CertsRevocationCandidate, 0, len(rows))
	for _, row := range rows {
		// a CSR that does not parse names nothing, and its row is still asked about
		names, _ := certsCsrNames(row.Csr)
		candidates = append(candidates, &CertsRevocationCandidate{Cert: row, Names: names})
	}
	return candidates
}

// One pass of the revocation chain. source is asked about the issued rows after the cursor, and about
// the revoking rows for their reason; a nil source finds nothing, and the pass only takes the rows
// already marked (model.RequestTlsCertRevocation's, or an earlier pass's) to their CAs. No budget hold
// and no CA's Retry-After stops a revocation. A store or source error ends the pass with what it has
// done.
func (self *CertsService) RunRevocations(ctx context.Context, source CertsRevocationSource, cursor *CertsRevocationCursor) (*CertsRevocationsReport, error) {
	report := &CertsRevocationsReport{Unavailable: self.acmeClosed()}
	if cursor == nil {
		cursor = &CertsRevocationCursor{}
	}
	report.Next = *cursor
	batchCount := self.settings.RevocationBatchCount
	// the reason of each cause this pass found, which no column keeps
	reasons := map[sidecar.Id]CertsRevocationReason{}

	if source != nil {
		issued, err := self.listInStates(ctx, []sidecar.TlsCertState{sidecar.TlsCertStateIssued}, cursor.AfterIssuedCertId, batchCount)
		if err != nil {
			return report, err
		}
		causes, err := self.revocationCauses(ctx, source, issued)
		if err != nil {
			return report, err
		}
		for _, row := range issued {
			cause, found := causes[row.CertId]
			if !found {
				continue
			}
			testHookBarrier("certs.revocation.mark", row.CertId.String())
			moved, err := self.transition(ctx, &CertsTransition{
				CertId: row.CertId,
				From:   []sidecar.TlsCertState{sidecar.TlsCertStateIssued},
				To:     sidecar.TlsCertStateRevoking,
			})
			if err != nil {
				report.FailedCount += 1
				continue
			}
			if !moved {
				continue
			}
			reasons[row.CertId] = CertsRevocationReasonFor(cause)
			report.Marked = append(report.Marked, row.CertId)
			// the device stops serving the certificate now, whenever its CA hears
			self.hintCounted(ctx, &report.Hints, row, protocol.TlsHintKind_TLS_HINT_REVOKED)
		}
		report.Next.AfterIssuedCertId = sidecar.Id{}
		if len(issued) == batchCount {
			report.Next.AfterIssuedCertId = issued[len(issued)-1].CertId
		}
	}

	revoking, err := self.listInStates(ctx, []sidecar.TlsCertState{sidecar.TlsCertStateRevoking}, cursor.AfterRevokingCertId, batchCount)
	if err != nil {
		return report, err
	}
	report.Next.AfterRevokingCertId = sidecar.Id{}
	if len(revoking) == batchCount {
		report.Next.AfterRevokingCertId = revoking[len(revoking)-1].CertId
	}
	if source != nil && !report.Unavailable {
		// a row marked before this pass: its cause, where its host still shows one
		unreasoned := []*sidecar.TlsCertRecord{}
		for _, row := range revoking {
			if _, found := reasons[row.CertId]; !found && len(row.Chain) != 0 {
				unreasoned = append(unreasoned, row)
			}
		}
		causes, err := self.revocationCauses(ctx, source, unreasoned)
		if err != nil {
			return report, err
		}
		for certId, cause := range causes {
			reasons[certId] = CertsRevocationReasonFor(cause)
		}
	}
	for index, row := range revoking {
		if ctx.Err() != nil {
			// the rest are read again from this row
			report.Next.AfterRevokingCertId = cursor.AfterRevokingCertId
			if 0 < index {
				report.Next.AfterRevokingCertId = revoking[index-1].CertId
			}
			return report, ctx.Err()
		}
		if !row.NotAfter.IsZero() && !self.clock.Now().Before(row.NotAfter) {
			// no CA revokes a certificate that has ended
			moved, err := self.transition(ctx, &CertsTransition{
				CertId: row.CertId,
				From:   []sidecar.TlsCertState{sidecar.TlsCertStateRevoking},
				To:     sidecar.TlsCertStateExpired,
			})
			switch {
			case err != nil:
				report.FailedCount += 1
			case moved:
				report.Expired = append(report.Expired, row.CertId)
			}
			continue
		}
		if len(row.Chain) == 0 || report.Unavailable {
			report.WaitingCount += 1
			continue
		}
		// a marked row with no cause to read is a takedown's or its device's own request: the names
		// stop being served
		reason, found := reasons[row.CertId]
		if !found {
			reason = CertsRevocationCessationOfOperation
		}
		if err := self.RevokeIssued(ctx, row.CertId, row.Chain[0], reason); err != nil {
			report.FailedCount += 1
			continue
		}
		report.Revoked = append(report.Revoked, row.CertId)
		self.hintCounted(ctx, &report.Hints, row, protocol.TlsHintKind_TLS_HINT_REVOKED)
	}
	return report, nil
}

// source's causes for rows, under the call's bound. No rows asks nothing.
func (self *CertsService) revocationCauses(ctx context.Context, source CertsRevocationSource, rows []*sidecar.TlsCertRecord) (map[sidecar.Id]CertsRevocationCause, error) {
	if len(rows) == 0 {
		return map[sidecar.Id]CertsRevocationCause{}, nil
	}
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	return source.RevocationCauses(callCtx, certsCandidates(rows))
}
