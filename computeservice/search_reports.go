// ComputeSearchReportLoop: the broker's pull of searchsigner's final authorizations (DESIGN-COMPUTE §21.5's Billing and
// Finality and attribution, §14.5's compute_search_settle, D-SRCH-13; compute-plan-signer-report-path, QD-1377;
// SRCH-M13-08). Only the broker reaches the signer, over mTLS, so the broker pulls: every ReportPollInterval, one
// puller at a time across broker instances under a lease on {cmpa} (search_tickets.go), it asks the signer for the
// final authorizations it holds unanswered, answers each by its ticket (search_settle.go) and sends the answers back,
// which the signer counts into its day's totals, attributed or not, and drops its half of the ticket at.
//
// A report the broker could not answer (the ledger or {cmpa} did not), is left out of the answers and comes again at
// the next pull. A pull that cannot reach the signer counts and waits for the next. The loop runs on the engine's
// context, so the engine's Close ends it, and gives its lease up as it ends.
//
// Nothing here logs a report: its counts go to urnetwork_compute_search_authorizations_total (search_admit.go).
// Safe for concurrent use; one pull at a time an instance.

package computeservice

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// What one pull did.
type ComputeSearchPull struct {
	// This instance held the lease: it pulled.
	Leased bool
	// Reports the signer gave, those answered, and those left for the next pull.
	ReportCount   int
	AnsweredCount int
	FailedCount   int
}

// The loop for one engine. See the file header.
type ComputeSearchReportLoop struct {
	admission *ComputeSearchAdmission
	holder    []byte
	// one pull at a time on this instance
	pullLock sync.Mutex
}

// No signer to pull from.
var errComputeSearchNoSigner = errors.New("compute search: no signer client")

// The loop for admission, started on the engine's context where a signer, {cmpa} and a poll interval stand.
func newComputeSearchReportLoop(admission *ComputeSearchAdmission) *ComputeSearchReportLoop {
	holder := make([]byte, admission.settings.LeaseHolderByteCount)
	if _, err := rand.Read(holder); err != nil {
		// no token, no lease: this instance never pulls, and another does
		holder = nil
	}
	self := &ComputeSearchReportLoop{admission: admission, holder: holder}
	engine := admission.engine
	if 0 < admission.settings.ReportPollInterval && admission.signer != nil && engine.deps.AdmissionsRedis != nil && holder != nil {
		go self.run(engine.ctx)
	}
	return self
}

// Pulls every ReportPollInterval until ctx ends, then gives the lease up.
func (self *ComputeSearchReportLoop) run(ctx context.Context) {
	engine := self.admission.engine
	defer func() {
		// a fresh context: the engine's has ended, and the lease is best given back, else it lapses at its ttl
		self.admission.tickets.unlease(context.Background(), self.holder)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-engine.clock.After(self.admission.settings.ReportPollInterval):
		}
		if _, err := self.Pull(ctx); err != nil && ctx.Err() == nil {
			engine.metrics.alarms.Add(1, "search_report_pull")
		}
	}
}

// One pull (see the file header): what it did, and an error where it could not lease, read or answer the signer.
func (self *ComputeSearchReportLoop) Pull(ctx context.Context) (*ComputeSearchPull, error) {
	self.pullLock.Lock()
	defer self.pullLock.Unlock()
	admission := self.admission
	if admission.signer == nil {
		return nil, errComputeSearchNoSigner
	}
	if self.holder == nil {
		return &ComputeSearchPull{}, nil
	}
	held, err := admission.tickets.lease(ctx, self.holder)
	if err != nil {
		return nil, err
	}
	if !held {
		return &ComputeSearchPull{}, nil
	}
	reports, err := admission.signer.Reports(ctx)
	if err != nil {
		return nil, err
	}
	pull := &ComputeSearchPull{Leased: true, ReportCount: len(reports.GetReports())}
	answers := &protocol.SearchSignerAnswers{}
	for i, report := range reports.GetReports() {
		if admission.settings.ReportBatchMaxCount <= i {
			// past the batch: left for the next pull
			pull.FailedCount += pull.ReportCount - i
			break
		}
		answer, err := admission.AnswerReport(ctx, report)
		if err != nil {
			pull.FailedCount += 1
			continue
		}
		answers.Answers = append(answers.Answers, &protocol.SearchSignerAnswer{Ticket: report.GetTicket(), Answer: answer})
	}
	if 0 < len(answers.Answers) {
		if err := admission.signer.Answer(ctx, answers); err != nil {
			// kept by ticket here: the next pull answers the same again, and books nothing twice
			return pull, err
		}
	}
	pull.AnsweredCount = len(answers.Answers)
	return pull, nil
}
