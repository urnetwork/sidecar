// A search's settlement at the broker (DESIGN-COMPUTE §21.5's Billing, Retries and No shared key, §21.8's Settle and
// Failures rows, §14.4, D-SRCH-11, D-SRCH-12, D-SRCH-13, R2-08, compute-10; SRCH-M13-08): the answer to one of the
// signer's reports of a final authorization, by its ticket.
//
//	settled      the ticket {cmpa} holds: the outcome committed to the search's operation row, then the ledger's
//	             script turns its hold into an unsettled kind-6 charge of the hold, the authorization's value times
//	             the markup, timed to the authorization's minute, which compute_settle books (§9.7): charged
//	lapsed       the hold released and the row voided: released
//	out_of_band  charged as settled, and its payee and transaction kept with the network and sidecar as a sanctions
//	             record, the network flagged for review (§21.10) and paged (search_flag.go)
//	lost         a ticket {cmpa} no longer holds, its map lost at a failover or its admission an hour past its window:
//	             unknown, and the signer counts a settled one unattributed (D-SRCH-13); a row the tickets job already
//	             released answers unknown too, its settlement URnetwork's expense
//
// Each answer replaces the ticket's record, which held the network, with the answer alone, kept AnswerLife, so a
// report sent twice gets the same answer and books one charge: the ledger's settlement is conditional on the row's
// state, and the record's compare keeps the first answer given. A step that cannot tell (the ledger, {cmpa}, the
// record's write) answers nothing, and the report comes again at the next pull.
//
// The charge's key is D-BAL-14's, the network, request id and attempt, timed to the minute: never the ticket, the
// nonce, the payee or the transaction (R2-08). A charge never passes its hold. Safe for concurrent use.

package computeservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

// A report the broker does not answer: a ticket of another size, a kind the format does not name.
var errComputeSearchReport = errors.New("compute search: a report that does not read")

// The alarms a report can raise beside the sanctions record's.
const (
	// A lapsed report for a search the ledger had charged, or a report whose minute is not its admission's.
	computeAlarmSearchReportConflict = "search_report_conflict"
	// An out-of-band settlement whose ticket {cmpa} lost: no network to keep its record with.
	computeAlarmSearchOutOfBandUnknown = "search_out_of_band_unknown"
)

// The outcome of a settled search: one search, its amount the hold, its cost the authorization's value in nano-USD, its
// end the authorization's minute and its settlement's time to the minute (compute-10).
func (self *ComputeSearchAdmission) settledOutcome(record *computeSearchTicketRecord, now time.Time) *model.ComputeOpOutcome {
	grain := self.settings.webSearch().AuthorizationGrain
	return &model.ComputeOpOutcome{
		Units:         model.ComputeUnits{Searches: 1},
		AmountNanoUsd: record.hold,
		CostNanoUsd:   int64(record.amount) * self.settings.webSearch().AssetUnitNanoUsd,
		EndTime:       time.Unix(record.minuteUnix, 0).UTC(),
		SettleTime:    now.UTC().Truncate(grain),
	}
}

// Charges record's search as settled: charged where the ledger settled it, or had; unknown where its row was released
// or is gone.
func (self *ComputeSearchAdmission) charge(ctx context.Context, record *computeSearchTicketRecord) (protocol.SearchReportAnswer, error) {
	state, err := self.ledger().Settle(ctx, &ComputeSearchSettleRequest{
		NetworkId: record.networkId,
		OpKey:     record.opKey,
		Outcome:   self.settledOutcome(record, self.engine.clock.Now()),
	})
	if err != nil {
		return 0, err
	}
	switch state {
	case controller.ComputeSettleSettled, controller.ComputeSettleRepeat:
		return protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_CHARGED, nil
	case controller.ComputeSettleReleased, controller.ComputeSettleGone:
		return protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_UNKNOWN, nil
	}
	return 0, fmt.Errorf("compute search: a settlement answered %q", state)
}

// Releases record's search: released, unless the ledger had charged it, whose charge stands.
func (self *ComputeSearchAdmission) release(ctx context.Context, record *computeSearchTicketRecord) (protocol.SearchReportAnswer, error) {
	state, err := self.ledger().Release(ctx, record.networkId, record.opKey)
	if err != nil {
		return 0, err
	}
	switch state {
	case controller.ComputeReleaseReleased, controller.ComputeReleaseGone:
		return protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_RELEASED, nil
	case controller.ComputeReleaseSettled:
		self.engine.alarm(computeAlarmSearchReportConflict, "a lapsed web search authorization's row was charged")
		return protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_CHARGED, nil
	}
	return 0, fmt.Errorf("compute search: a release answered %q", state)
}

// Answers one report (see the file header): the answer the broker gives, kept by its ticket with no network. An error
// answers nothing, and the report comes again.
func (self *ComputeSearchAdmission) AnswerReport(ctx context.Context, report *protocol.SearchSignerReport) (protocol.SearchReportAnswer, error) {
	ticket := report.GetTicket()
	if len(ticket) != self.settings.TicketByteCount {
		return 0, errComputeSearchReport
	}
	kind := report.GetKind()
	switch kind {
	case protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_SETTLED, protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_LAPSED,
		protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_OUT_OF_BAND:
	default:
		return 0, errComputeSearchReport
	}
	standing, err := self.tickets.read(ctx, ticket)
	if err != nil {
		return 0, err
	}
	if standing != nil && standing.state == computeSearchTicketAnswered {
		return standing.answer, nil
	}
	barrierKey := "lost"
	if standing != nil {
		barrierKey = sidecar.EvsKeyId(standing.opKey)
	}
	testHookBarrier(BarrierComputeSearchAnswerBefore, barrierKey)
	answer := protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_UNKNOWN
	switch {
	case standing == nil:
		if kind == protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_OUT_OF_BAND {
			self.engine.alarm(computeAlarmSearchOutOfBandUnknown, "an out-of-band web search settlement's ticket was lost")
		}
	case kind == protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_LAPSED:
		if answer, err = self.release(ctx, standing); err != nil {
			return 0, err
		}
	default:
		if report.GetMinuteS() != standing.minuteUnix {
			// the signer's minute is the admission's; the admission's own is what the charge takes
			self.engine.alarm(computeAlarmSearchReportConflict, "a web search report's minute is not its admission's")
		}
		if answer, err = self.charge(ctx, standing); err != nil {
			return 0, err
		}
		if kind == protocol.SearchSignerReportKind_SEARCH_SIGNER_REPORT_KIND_OUT_OF_BAND {
			if len(report.GetPayee()) != len(sidecar.WebSearchAddress{}) || len(report.GetTransaction()) != 32 {
				self.engine.alarm(computeAlarmSearchReportConflict, "an out-of-band web search report names no payee or transaction")
			} else if err := self.suspend.Record(ctx, standing.networkId, standing.sidecarId, model.ComputeSearchFlagReasonOutOfBand, report.GetPayee(), report.GetTransaction()); err != nil {
				// charged already; the record and the answer wait for the report's next pull, which charges nothing more
				return 0, err
			}
		}
	}
	given, set, err := self.tickets.answer(ctx, ticket, standing, answer)
	testHookBarrier(BarrierComputeSearchAnswerAfter, barrierKey)
	if err != nil {
		return 0, err
	}
	if set {
		switch given {
		case protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_CHARGED:
			self.authorizations.Add(1, computeSearchAuthorizationSettled)
		case protocol.SearchReportAnswer_SEARCH_REPORT_ANSWER_RELEASED:
			self.authorizations.Add(1, computeSearchAuthorizationLapsed)
		}
	}
	return given, nil
}
