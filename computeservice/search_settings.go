// Web search's broker settings (DESIGN-COMPUTE §21.5, §21.8, §21.9, §21.10, §14.4, §14.5, §14.7; SRCH-M13-07; QD-702):
// every limit the broker's search admission, its settlement, its jobs and its outcome counts read, each a field set only
// by DefaultComputeSearchSettings, which ComputeEngineSettings.Search carries, so SRCH-M13-08 and SRCH-M13-09 only read
// it. The format both ends share (the request id's and nonce's sizes, the attempts, the authorization's minute and its
// window, USDC's unit, the network name's bound) is the root's WebSearchSettings, which these carry rather than copy
// (connect/CODESTYLE.md's "a limit both ends share"); the price rule, a search's minute grain and the per-search rows'
// retention are the ledger's (model.ComputeLedgerSettings, which ComputeBrokerSettings.Ledger carries). Identifiers
// (route names, refusal codes and reasons, the vault file's name, the Redis fields) stay constants in their files.

package computeservice

import (
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// The broker's search tunables.
type ComputeSearchSettings struct {
	// The format both ends share (§21.5): the 16-byte request id, the 32-byte nonce, 3 attempts, the minute an
	// authorization is timed to and its window of 60 s before it to 120 s after it, USDC's 1,000 nano-USD a unit and
	// the network name's bound. nil: sidecar.DefaultWebSearchSettings.
	WebSearch *sidecar.WebSearchSettings

	// The gateway's price per search, in the asset's units: 10,000 ($0.01), the same in every mode (§21.3, D-SRCH-6).
	// The catalog's search section lists each mode at this times the compute markup (§21.8), so a price change within
	// the policy's ceiling is this setting, and a rise past the ceiling a new signed policy.
	GatewayAmount uint64

	// The most bytes a request's sealed payee may hold: 4 KiB, where X-Wing's encapsulation and one AES-128-GCM payee
	// take under 1.2 KiB. A larger one is refused invalid before anything is held.
	SealedPayeeMaxByteCount int

	// A network's rate (§21.9): at most NetworkRateCount searches each NetworkRateInterval, 2 a second, with bursts of
	// NetworkBurstCount, 20, by GCRA on {cmpr_<network_id>}: the emission interval is the interval over the count, and
	// the burst's tolerance that interval times one less than the burst. Each must be positive.
	NetworkRateCount    int
	NetworkRateInterval time.Duration
	NetworkBurstCount   int
	// A network's searches a UTC day where its compute block sets no day_max: 2,000, the block's search object's
	// default (§21.9), which the broker applies to the field a block leaves unset (§16.4, §16.5). A block's own day_max
	// replaces it, and §9.11's search cap bounds either, so a cap a review raises past 2,000 still holds a network that
	// set none at 2,000. Must be positive.
	DefaultDayMaxCount int
	// The payer's global rate (§21.9, §21.5): at most GlobalWindowCount searches each GlobalWindow across all networks
	// on {cmps}, each network active in the window, or in the window before it, given an equal share of it before any
	// takes more. "Set from G-SRCH-parallel's test": 10 a second is the draft's figure until that load test (§21.11)
	// sets it and Parallel's word raises it, and the signer's max_unsettled is an hour of it. Each must be positive.
	GlobalWindow      time.Duration
	GlobalWindowCount int
	// How long {cmpr_<network_id>} outlives its last search: 48 hours, past the UTC day its count is of, so the day's
	// count never expires before its day does. A key found absent is rebuilt from the day's search rows (§9.7).
	NetworkRateKeyTtl time.Duration
	// How long {cmps} outlives its last search: a minute, many windows.
	LimiterKeyTtl time.Duration
	// How long a broker instance answers a network's search cap (§9.11) from what it last read of the ledger: a
	// minute. The cap moves only at a network's seventh day after its first paid lot or by an operator's review.
	// Non-positive reads the ledger at every admission. At most CacheMaxCount networks are kept, the cache emptied
	// past it, as the suspension's cache is.
	SearchCapCacheMaxAge time.Duration
	CacheMaxCount        int

	// The ticket the broker draws for each admitted authorization (§21.5's No shared key): 32 bytes, a size the
	// signer's API takes, so a format limit.
	TicketByteCount int
	// How long past its window an admission waits for the signer's report (§21.5, §14.5's compute_search_tickets): an
	// hour. Its ticket lives that long in {cmpa}, and compute_search_tickets releases its hold once it passes.
	TicketReportGrace time.Duration
	// How long the answer the broker gave a report is kept, with no network, so a report sent twice gets one answer
	// (§21.5): an hour.
	AnswerLife time.Duration
	// How long a claim on a request id and attempt stands before its admission confirms it: 30 s, past the hold's and
	// the scripts' bounds, so a broker stopped mid-admission leaves a claim that lapses rather than one that blocks the
	// request's retries until its window.
	PendingClaimTtl time.Duration

	// The signer's mTLS API (§14.2): each call's bound, 10 s; the most bytes an answer may hold, 1 MiB, room for a pull
	// of ReportBatchMaxCount reports; and the most bytes the client's vault file may hold, 64 KiB.
	SignerTimeout                time.Duration
	SignerAnswerMaxByteCount     int64
	SignerClientFileMaxByteCount int
	// The retry time a signer's rate refusal answers with, which its answer does not carry: 10 s.
	SignerRefusalRetryAfter time.Duration
	// The retry time a capacity refusal of the broker's own carries (no signer, no ledger, {cmpa} unsure): 5 s, as
	// the ledger's CapacityRetry.
	CapacityRetryAfter time.Duration

	// The report loop (§21.5, compute-plan-signer-report-path, QD-1377): the broker pulls the signer's final
	// authorizations every ReportPollInterval, 10 s, one puller at a time across broker instances under a lease of
	// ReportLeaseTtl, 30 s, and takes at most ReportBatchMaxCount reports a pull, 500. A non-positive interval starts no
	// loop, which a test that drives pulls itself sets.
	ReportPollInterval  time.Duration
	ReportLeaseTtl      time.Duration
	ReportBatchMaxCount int
	// The lease's holder token: 16 random bytes an engine, which only tell broker instances apart.
	LeaseHolderByteCount int

	// compute_search_tickets (§14.5): at most TicketsBatchMaxCount admissions released a run, 500.
	TicketsBatchMaxCount int
	// compute_search_purge (§14.5, §21.5, D-SRCH-13): at most PurgeBatchMaxCount searches' rows deleted a run, 1,000;
	// the ages are the ledger's SearchChargePurgeAge (71 h 55 min) and SearchChargeRetention (72 hours).
	PurgeBatchMaxCount int

	// The sanctions records (compute_search_flag, compute-10): kept for OFAC's recordkeeping period, 10 years since 2025
	// (31 CFR 501.601), which counsel confirms at G-SRCH-parallel (§21.11); compute_search_purge deletes a reviewed
	// record past it, never one still open.
	FlagRetention time.Duration
	// The longest reference a review keeps on the records it closes (`sidecarctl compute resume <network> --search
	// --review <reference>`, QD-1374), in printable ASCII bytes: 256, a ticket or case reference, never content. A
	// reading: QD-1374 names no figure.
	ReviewReferenceMaxByteCount int
	// How long a broker instance answers whether a network's search is suspended for review from what it last read:
	// 15 s, so a suspension one instance records reaches the others within it, and the instance that records one
	// answers it at once. Non-positive reads at every admission.
	SuspensionCacheMaxAge time.Duration

	// The outcome counts (§21.8, compute-11): {cmpo} holds each hour's counts by class, each hour's fields outliving
	// their last report by OutcomesKeyTtl, 3 hours, so compute_search_outcomes moves an hour into
	// compute_search_outcome_hour before it goes; the hourly rows are kept OutcomeHourRetention, 400 days, deleted by
	// compute_search_purge. The hour is OutcomeHour, a format of {cmpo}'s fields.
	OutcomesKeyTtl       time.Duration
	OutcomeHour          time.Duration
	OutcomeHourRetention time.Duration
	// A device's daily outcomes report (§21.8, SRCH-M13-09): at most one a device each OutcomesReportInterval, a day.
	OutcomesReportInterval time.Duration
	// Parallel's failure rate (§21.8, SRCH-M13-09): an hour above FailurePageBasisPoints, 500 (5%), of at least
	// FailurePageMinCount searches, 100, pages; a month above FailureReviewBasisPoints, 200 (2%), or
	// FailureReviewPageHours paging hours, 3, in FailureReviewWeek, a week, opens the owner's review.
	FailurePageBasisPoints   int
	FailurePageMinCount      int
	FailureReviewBasisPoints int
	FailureReviewPageHours   int
	FailureReviewWeek        time.Duration
	// The volume review (§21.10, SRCH-M13-09): a network that reached its search cap on each of its last
	// VolumeReviewDayCount UTC days, 3, within VolumeReviewWindow of its first paid lot, 14 days, is flagged to §17's
	// review. §21.10 gives no numbers: these are the plan's.
	VolumeReviewDayCount int
	VolumeReviewWindow   time.Duration
	// The day's reconciliation (§21.8, SRCH-M13-09): a day's unattributed value above
	// ReconcileUnattributedPageNanoUsd, $10, or above ReconcileUnattributedPageBasisPoints of its settled value, 100
	// (1%), pages.
	ReconcileUnattributedPageNanoUsd     int64
	ReconcileUnattributedPageBasisPoints int

	// {cmpa}'s instance must keep nothing (§14.4): the engine asks its persistence at start within
	// PersistenceCheckTimeout, 5 s, and, while the answer was not sure, again at an admission at most each
	// PersistenceRecheckInterval, a minute. Until it is sure persistence is off, every search answers capacity.
	PersistenceCheckTimeout    time.Duration
	PersistenceRecheckInterval time.Duration
}

// The defaults, the only place one is set.
func DefaultComputeSearchSettings() *ComputeSearchSettings {
	return &ComputeSearchSettings{
		WebSearch: sidecar.DefaultWebSearchSettings(),

		GatewayAmount: 10_000,

		SealedPayeeMaxByteCount: 4 * 1024,

		NetworkRateCount:     2,
		NetworkRateInterval:  1 * time.Second,
		NetworkBurstCount:    20,
		DefaultDayMaxCount:   2_000,
		GlobalWindow:         1 * time.Second,
		GlobalWindowCount:    10,
		NetworkRateKeyTtl:    48 * time.Hour,
		LimiterKeyTtl:        1 * time.Minute,
		SearchCapCacheMaxAge: 1 * time.Minute,
		CacheMaxCount:        100_000,

		TicketByteCount:   32,
		TicketReportGrace: 1 * time.Hour,
		AnswerLife:        1 * time.Hour,
		PendingClaimTtl:   30 * time.Second,

		SignerTimeout:                10 * time.Second,
		SignerAnswerMaxByteCount:     1024 * 1024,
		SignerClientFileMaxByteCount: 64 * 1024,
		SignerRefusalRetryAfter:      10 * time.Second,
		CapacityRetryAfter:           5 * time.Second,

		ReportPollInterval:   10 * time.Second,
		ReportLeaseTtl:       30 * time.Second,
		ReportBatchMaxCount:  500,
		LeaseHolderByteCount: 16,

		TicketsBatchMaxCount: 500,
		PurgeBatchMaxCount:   1000,

		FlagRetention:               10 * 365 * 24 * time.Hour,
		ReviewReferenceMaxByteCount: 256,
		SuspensionCacheMaxAge:       15 * time.Second,

		OutcomesKeyTtl:         3 * time.Hour,
		OutcomeHour:            1 * time.Hour,
		OutcomeHourRetention:   400 * 24 * time.Hour,
		OutcomesReportInterval: 24 * time.Hour,

		FailurePageBasisPoints:   500,
		FailurePageMinCount:      100,
		FailureReviewBasisPoints: 200,
		FailureReviewPageHours:   3,
		FailureReviewWeek:        7 * 24 * time.Hour,

		VolumeReviewDayCount: 3,
		VolumeReviewWindow:   14 * 24 * time.Hour,

		ReconcileUnattributedPageNanoUsd:     10 * 1000 * 1000 * 1000,
		ReconcileUnattributedPageBasisPoints: 100,

		PersistenceCheckTimeout:    5 * time.Second,
		PersistenceRecheckInterval: 1 * time.Minute,
	}
}

// The shared format, the defaults where none is set.
func (self *ComputeSearchSettings) webSearch() *sidecar.WebSearchSettings {
	if self.WebSearch == nil {
		return sidecar.DefaultWebSearchSettings()
	}
	return self.WebSearch
}

// GCRA's emission interval and burst tolerance for a network's rate, in milliseconds.
func (self *ComputeSearchSettings) networkRateMillis() (emission int64, tolerance int64) {
	emission = max(1, self.NetworkRateInterval.Milliseconds()/int64(self.NetworkRateCount))
	return emission, emission * int64(self.NetworkBurstCount-1)
}

// An error for settings no broker could admit a search under: a rate, window, size or life that is not positive, a
// window the format does not give, or a ticket that outlives nothing it must.
func (self *ComputeSearchSettings) Validate() error {
	webSearch := self.webSearch()
	switch {
	case webSearch.RequestIdByteCount <= 0 || webSearch.NonceByteCount <= 0 || webSearch.AttemptMaxCount <= 0:
		return fmt.Errorf("compute search: the format's request id, nonce and attempts are positive")
	case webSearch.AuthorizationGrain < time.Second || webSearch.AuthorizationGrain%time.Second != 0:
		return fmt.Errorf("compute search: the authorization's grain is whole seconds")
	case webSearch.WindowAfter <= 0 || webSearch.AssetUnitNanoUsd <= 0 || webSearch.NetworkMaxByteCount <= 0:
		return fmt.Errorf("compute search: the window, the asset's unit and the network's bound are positive")
	case self.GatewayAmount == 0:
		return fmt.Errorf("compute search: the gateway's price is positive")
	case self.SealedPayeeMaxByteCount <= 0 || self.TicketByteCount <= 0:
		return fmt.Errorf("compute search: the sealed payee's bound and the ticket's size are positive")
	case self.NetworkRateCount <= 0 || self.NetworkRateInterval < time.Millisecond || self.NetworkBurstCount <= 0:
		return fmt.Errorf("compute search: a network's rate and burst are positive")
	case self.DefaultDayMaxCount <= 0:
		return fmt.Errorf("compute search: the default day_max is positive")
	case self.GlobalWindowCount <= 0 || self.GlobalWindow < time.Millisecond:
		return fmt.Errorf("compute search: the global rate is positive")
	case self.NetworkRateKeyTtl < 24*time.Hour || self.LimiterKeyTtl < self.GlobalWindow*2:
		return fmt.Errorf("compute search: the rate keys outlive the day and two windows")
	case self.CacheMaxCount <= 0:
		return fmt.Errorf("compute search: the caches hold at least one network")
	case self.TicketReportGrace <= 0 || self.AnswerLife <= 0 || self.PendingClaimTtl <= 0:
		return fmt.Errorf("compute search: a ticket's, an answer's and a claim's lives are positive")
	case self.SignerTimeout <= 0 || self.SignerAnswerMaxByteCount <= 0 || self.SignerClientFileMaxByteCount <= 0:
		return fmt.Errorf("compute search: the signer's bounds are positive")
	case self.ReportLeaseTtl <= 0 || self.ReportBatchMaxCount <= 0 || self.TicketsBatchMaxCount <= 0 || self.PurgeBatchMaxCount <= 0 ||
		self.LeaseHolderByteCount <= 0:
		return fmt.Errorf("compute search: the report loop's lease and the batches are positive")
	case 0 < self.ReportPollInterval && self.ReportLeaseTtl <= self.ReportPollInterval:
		return fmt.Errorf("compute search: the report lease outlives its poll")
	case self.FlagRetention <= 0 || self.OutcomeHourRetention <= 0 || self.ReviewReferenceMaxByteCount <= 0:
		return fmt.Errorf("compute search: the records' retentions and the review's reference bound are positive")
	case self.OutcomeHour < time.Second || self.OutcomeHour%time.Second != 0 || self.OutcomesKeyTtl <= self.OutcomeHour:
		return fmt.Errorf("compute search: {cmpo}'s hour is whole seconds and its fields outlive it")
	case self.PersistenceCheckTimeout <= 0:
		return fmt.Errorf("compute search: the persistence check's bound is positive")
	}
	return nil
}
