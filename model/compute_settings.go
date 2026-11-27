// The compute ledger's settings (DESIGN-COMPUTE §9, §14.4, §14.5, §16.5; BAL-M12-01): every limit §9 names, each
// defaulting to the design's figure, so no later ledger task adds a constant (QD-702). Every value that sets a limit,
// size, count, time, interval, threshold, retry or budget is a field here, set only in DefaultComputeLedgerSettings and
// read from the instance; only identifiers stay constants (compute_kinds.go).
//
// Money is int64 nano-USD, USD × 10^9 (D-BAL-2), never a float; packs and plans are counted in credits, one credit a
// dollar. Days are UTC days (Q-BAL-8).
//
// Where the device's compute client shares a format value with the routes (the packs, the plans, the promotion
// code's length, the charges page, the spend view's days), each side's settings carry it at the same default, and
// compute_kinds_client_test.go holds them to one another.

package model

import (
	"time"
)

// One credit, a US dollar, in nano-USD (D-BAL-2): a unit, not a limit.
const ComputeCreditNanoUsd int64 = 1_000_000_000

// What one price unit of tokens counts: §6.3's prices are per million tokens.
const computeTokensPerPriceUnit int64 = 1_000_000

// The ledger's settings. See the file header.
type ComputeLedgerSettings struct {
	// §9.6's markup, a ratio: 6/5, the 1.20 Q-BAL-2 and CO-35 set on every model and shape, whichever market bought
	// the credits. The denominator is positive.
	MarkupNumerator   int64
	MarkupDenominator int64
	// The steps §9.6 rounds a retail price up to: $0.001 a million tokens, $0.001 an hour, $0.0001 a search. A GiB of
	// host egress takes the hour's $0.001, which §9.6 does not name (a reading; kind 4 is M14's). Each is positive.
	TokenPriceStepNanoUsd  int64
	HourPriceStepNanoUsd   int64
	GibPriceStepNanoUsd    int64
	SearchPriceStepNanoUsd int64

	// §9.5's Stripe packs, in credits: 10, 25, 50, 100, 250 and 500, none of 5, on which Stripe's fees take 9%.
	StripePackCredits []int64
	// §9.5's store consumables and monthly subscriptions, in credits: 10, 25, 50 and 100 each.
	StoreConsumableCredits   []int64
	StoreSubscriptionCredits []int64
	// §9.8's Stripe monthly plan, M, in credits: 10, 25, 50, 100 or 250.
	MonthlyPlanCredits []int64
	// The longest store subscription a store's monthly plan names, the App Store's original transaction id or Play's
	// purchase token, in bytes: 1024, past both stores' ids. A reading: neither store bounds a purchase token.
	StoreSubscriptionRefMaxByteCount int

	// §9.11's balance cap: $10,000 a network. A purchase that would pass it is refused before payment.
	BalanceCapNanoUsd int64
	// §9.11's new-account purchase limits, for each network and for each payer: $100 a UTC day and $200 in the first
	// NewAccountWindow (7 days), a payer's counted from its first purchase anywhere.
	NewAccountDayNanoUsd    int64
	NewAccountWindowNanoUsd int64
	NewAccountWindow        time.Duration
	// §9.11's daily load: at most $1,500 a UTC day for each network and each payer, across markets, promotion codes
	// counted with purchases (Q-BAL-15).
	DailyLoadNanoUsd int64
	// The most uncovered charges a credit or a reversal draws an overrun for (§9.4's "drawn from the next lot
	// credited"), oldest first within the charges' retention: 500, past any overrun the floor and the direct-call
	// exposure leave. An overrun no charge found within it stays in settled's negative, for the next lot. Not
	// positive draws none. A reading: §9.4 names no figure.
	OverrunDrawMaxChargeCount int
	// §9.11: 3-D Secure is requested on a first purchase above this: $50.
	ThreeDSecureAboveNanoUsd int64

	// §9.8's threshold top-up: T, the balance under which it fires ($5); P, the pack it buys (20 credits); L, the
	// most its top-ups charge in a calendar month ($200).
	ThresholdBelowNanoUsd      int64
	ThresholdPackCredits       int64
	ThresholdMonthLimitNanoUsd int64
	// At most 3 top-ups a UTC day.
	ThresholdDayMaxCount int
	// A failed top-up's retries, after the failure: 1 h, then 6 h.
	ThresholdRetryIntervals []time.Duration
	// The failures in a row after which threshold turns off and says so: 3.
	ThresholdFailureMaxCount int
	// The networks with threshold on that one compute_auto_renew run examines, by its cursor, before it continues where
	// it stopped: 500. A reading: §14.5 names no figure.
	AutoRenewBatchCount int

	// §9.11's promotion codes: each lot at most $10; lapsing PromoLapse (30 days) after redemption; one code a
	// network in PromoNetworkInterval (30 days); after PromoFailureDayMaxCount (5) failed codes in a UTC day, a
	// network's attempts answer rate_limited until the next.
	PromoMaxNanoUsd         int64
	PromoLapse              time.Duration
	PromoNetworkInterval    time.Duration
	PromoFailureDayMaxCount int
	// A code is 8 to 32 letters and digits; one made for a single network is 16 random characters, about 80 bits.
	PromoCodeMinCharacterCount     int
	PromoCodeMaxCharacterCount     int
	PromoNetworkCodeCharacterCount int
	// A network's repeat of its redemption of a code within this answers the redemption's lot again, a retry; past
	// it, code_redeemed: 24 hours, past any client's retries of one request. A reading: §9.11 says a retry answers
	// the lot and names no window.
	PromoRetryWindow time.Duration
	// How long {cmpk_<network_id>} lives past its last write: a day, compute-2's ttl. Each UTC day's count is its own
	// field, so no count carries into the next day whatever the key's life.
	PromoFailureKeyTtl time.Duration
	// The most promotional lots one run of compute_promo_lapse lapses: 500, the rest left for the next hour's run. A
	// reading: §14.5 names no figure.
	PromoLapseBatchCount int
	// The longest campaign, operator's name or reason a code keeps, in bytes: 256. A reading: §14.4 names no figure.
	PromoTextMaxByteCount int

	// §9.12: a Stripe lot's unspent part is refundable for 30 days from purchase.
	RefundWindow time.Duration
	// §9.12: a deleted network's unspent purchased credit goes back to the card within 90 days of purchase.
	ClosureRefundWindow time.Duration
	// How far back a closure reads the App Store's monthly grants for subscriptions that may still bill, as Pro's are
	// checked at deletion: 92 days, a period of at most 31 days and the App Store's 60 days of billing retry, past which
	// a subscription with no grant renews nothing. A reading: §9.12 names no figure.
	ClosureStoreWindow time.Duration
	// The most of those grants a closure asks the App Store about: 24, three months of eight subscriptions; past it the
	// closure counts the network's App Store subscriptions as renewing, so its deletion waits (fails closed). A
	// reading: §9.12 names no figure.
	ClosureStoreGrantMaxCount int

	// §9.4's and §14.6's retention: per-request rows 90 days; a web search's at most 72 hours, purged from 71 h 55 min
	// (§14.5); the day rows 400 days; lots, promotion codes and redemptions 7 years (financial records); a payer's
	// first day 2 years and its days 30 days; disputes 400 days.
	ChargeRetention          time.Duration
	SearchChargeRetention    time.Duration
	SearchChargePurgeAge     time.Duration
	DayRowRetention          time.Duration
	FinancialRecordRetention time.Duration
	PayerRetention           time.Duration
	PayerDayRetention        time.Duration
	DisputeRetention         time.Duration
	// How many UTC days of compute_charge partitions compute_rollup_day keeps made ahead of today: 7, so a missed
	// run or a week of them leaves no charge without its partition. A reading: §14.5 names no figure.
	ChargePartitionDaysAhead int
	// The networks one of compute_rollup_day's batches checks and prunes, each batch its own transactions, its indexed
	// cursor advancing past them: 100, so a batch's 400 days of day rows stay one short transaction's work. Must be
	// positive. A reading: §14.5 names no figure.
	RollupNetworkBatchCount int
	// How long a charge partition's drop waits for its locks on compute_charge: 5 s. A detach waits for an ACCESS
	// EXCLUSIVE lock, and every booking queues behind it while it waits, so the wait stays short and a busy pass drops
	// the partition on its next run. Must be positive. A reading: §14.5 names no figure.
	RollupDropLockTimeout time.Duration

	// §9.7's settlement: compute_settle runs every 2 s and books up to 500 settled operation rows a shard a run.
	SettleInterval      time.Duration
	SettleBatchRowCount int
	// The shards compute_op.shard spreads networks over, which compute_settle's runs take apart: 16. A reading: §9.4
	// names the column, not the count.
	SettleShardCount int
	// §9.7's handoff: a hold still unconfirmed after 60 s is dropped by the network's next script.
	UnconfirmedHoldMaxAge time.Duration
	// The most an admission waits for PostgreSQL to take its operation's row before it voids its hold and refuses
	// capacity: 10 s, well inside UnconfirmedHoldMaxAge, so a confirm follows the hold it confirms. A reading: §9.7
	// gives no figure.
	OpRowWriteMaxTime time.Duration
	// The retry a capacity refusal carries where PostgreSQL could not take the row (§9.7, §6.6): 5 s, a few of
	// compute_settle's runs. A reading: §9.7 asks for a retry time and gives none.
	CapacityRetry time.Duration
	// How long after its outcome's commit a settlement still turns its hold into an unsettled charge: 5 minutes, half
	// of ProjectionMemoTtl, so a script that runs late never meets a booked operation whose memo has gone, and
	// counts it twice. Past it, compute_settle's drop releases the hold with its charge counted. Must stay below
	// ProjectionMemoTtl.
	SettleScriptWindow time.Duration
	// The grain a search's and a direct call's times are kept to, and a search's key is timed to: a minute (§9.7,
	// §14.6's compute-1 and compute-10).
	OpMinuteGrain time.Duration
	// The period of kind 4's charges, an enclave's host egress, and of an egress hour's key: an hour (§9.6).
	EnclaveHostEgressInterval time.Duration
	// The longest catalog id a row may name, in bytes: 96, the device's label bound (ComputeClientSettings'
	// LabelMaxCharacterCount), past which the device refuses an answer naming it.
	CatalogIdMaxByteCount int
	// The longest provider reference a row keeps, a TEE call's instance and provider nonce, in bytes: 256. A
	// reading: §9.4 gives no figure.
	ProviderRefMaxByteCount int
	// The most open rows compute_op_recover examines in a run: 500, as a settle batch, so a backlog is worked through
	// run by run rather than in one pass.
	RecoverBatchRowCount int
	// §14.7: a row settled and unbooked past 60 s pages.
	SettledUnbookedPageAge time.Duration
	// §9.7's recovery: a TEE call open 10 minutes settles from its provider's usage record; any row open 24 hours is
	// released at no charge, its cost URnetwork's.
	TeeRecoverAfter time.Duration
	OpReleaseAfter  time.Duration
	// §14.5's runs: compute_op_recover every minute, compute_auto_renew every minute, compute_suspend every minute,
	// compute_promo_lapse hourly, compute_rollup_day daily at RollupDayOffset past 00:00 UTC (02:00).
	RecoverInterval    time.Duration
	AutoRenewInterval  time.Duration
	SuspendInterval    time.Duration
	PromoLapseInterval time.Duration
	RollupDayOffset    time.Duration

	// §9.7's exposure rule: a network's open direct calls may leave it at most $5 below its floor, and their
	// shortfalls at most $5.
	DirectExposureNanoUsd int64
	// §14.7: absorbed direct-call charges past $50 in a day across networks page.
	AbsorbedPageDayNanoUsd int64
	// §9.11: a second direct-call mismatch within 30 days refuses a network's direct calls.
	DirectMismatchWindow time.Duration

	// §9.9's floor: the smaller of $5 and FloorEnclaveTime (an hour) of the network's running enclaves' rates.
	FloorMaxNanoUsd  int64
	FloorEnclaveTime time.Duration
	// §9.9's grace: grace older than an hour suspends.
	GraceMaxAge time.Duration
	// §9.9's burn: the trailing 24 h of charges, or the running enclaves' hourly rates × 24 if larger; low under
	// LowBurnTime (24 h) of it.
	BurnWindow  time.Duration
	LowBurnTime time.Duration
	// compute_suspend's accounts: one run examines at most SuspendBatchCount, by its cursor, before it continues where
	// it stopped (500), and takes every account not active and every one whose update_time moved in the last
	// SuspendLookback (10 minutes, past several missed runs of its minute). A reading: §14.5 names no figure.
	SuspendBatchCount int
	SuspendLookback   time.Duration

	// §9.11's search cap: at most 200 searches a UTC day for a network until 7 days after its oldest unreversed paid
	// lot, then 2,000; more only by URnetwork's review (`sidecarctl compute search-cap`).
	SearchCapNew         int64
	SearchCapEstablished int64
	SearchCapAge         time.Duration

	// §9.11's new-account enclave gates: 1 CPU enclave until 24 h after the first successful payment; GPU shapes after
	// $50 of lifetime purchases.
	EnclaveNewAccountCpuCount  int
	EnclaveNewAccountWait      time.Duration
	EnclaveGpuPurchasesNanoUsd int64
	// §9.6's enclave interval: running time is written every 10 minutes and the next 10 held.
	EnclaveInterval time.Duration
	// §9.9's indexer enclave: a reserve of 7 days of its price, then 72 hours of grace.
	IndexerReserveTime time.Duration
	IndexerGraceTime   time.Duration

	// D-BAL-11: at most 10 disputes a network a UTC day; disputes from at least 3 networks past 0.5% of a provider's
	// requests in a day page (DisputePageBasisPoints 50, in hundredths of a percent).
	DisputeNetworkDayMaxCount int
	DisputePageNetworkCount   int
	DisputePageBasisPoints    int64

	// §16.5's budgets the broker enforces by default, until CACL's resolver reads the policy's (C§16.4): per agent
	// id and per tagged subject $5 a UTC day and $50 a month; per untagged device, for calls naming no agent, $20 a
	// day and $200 a month; per untagged device across all its agents and calls, $50 a day (CO-41, Q-CACL-4).
	DefaultAgentDayNanoUsd         int64
	DefaultAgentMonthNanoUsd       int64
	DefaultDeviceDayNanoUsd        int64
	DefaultDeviceMonthNanoUsd      int64
	DefaultDeviceCeilingDayNanoUsd int64

	// §9.7's lost cache: an absent or marked projection answers held with this retry: one second.
	ProjectionRebuildRetry time.Duration
	// A hold that open holds, not the balance or a budget, stand in the way of answers held with this retry: 2 s,
	// compute_settle's run, after which a booked batch has freed room. A reading: §6.6 asks for a retry time.
	HeldRetry time.Duration
	// How long a projection script remembers an operation it voided or dropped, so a repeat answers its first
	// outcome: 10 minutes, past every retry of a call or search; the operation row's state is the lasting record.
	// Within compute-1's hour for what Redis holds of a call.
	ProjectionMemoTtl time.Duration
	// A subject's budget counters live this long past their last write: 63 days, past this UTC month and the last,
	// the two a counter's fields name.
	BudgetCounterTtl time.Duration
	// The longest budget name a counter's field carries: 24 bytes of [a-z0-9_], room for §16.5's names and a
	// policy budget's own, short enough that a hold's field stays small. A reading: §16.4 names no figure.
	ProjectionBudgetNameMaxByteCount int
	// The most budget lines one hold carries: 32, past any policy's lines for one call's subjects (its agent, device,
	// member and network, a day's and a month's each, and their defaults), so one script's work stays bounded. A
	// reading: §16.4 names no figure.
	ProjectionHoldMaxLineCount int

	// The most decisions one POST compute/v1/budget/raise presents (§16.3's kind 21): 16, past any requests rule's k,
	// so a body of many tiny decisions makes the gate verify no more than that many signatures. A reading: §16.6
	// names no figure.
	BudgetRaiseDecisionMaxCount int

	// §9.13's spend view: today so far and the 6 UTC days before it.
	SpendDayCount int
	// §14.3's charges route: 100 rows a page, the device's ChargesPageRowCount.
	ChargesPageRowCount int
	// The most rows a charges, statement or spend answer holds: 10,000, the device's AnswerMaxRowCount, past which
	// the device refuses an answer whole.
	AnswerMaxRowCount int
}

// The ledger's defaults, the only place one is set.
func DefaultComputeLedgerSettings() *ComputeLedgerSettings {
	usd := func(dollars int64) int64 {
		return dollars * ComputeCreditNanoUsd
	}
	day := 24 * time.Hour
	return &ComputeLedgerSettings{
		MarkupNumerator:        6,
		MarkupDenominator:      5,
		TokenPriceStepNanoUsd:  1_000_000,
		HourPriceStepNanoUsd:   1_000_000,
		GibPriceStepNanoUsd:    1_000_000,
		SearchPriceStepNanoUsd: 100_000,

		StripePackCredits:        []int64{10, 25, 50, 100, 250, 500},
		StoreConsumableCredits:   []int64{10, 25, 50, 100},
		StoreSubscriptionCredits: []int64{10, 25, 50, 100},
		MonthlyPlanCredits:       []int64{10, 25, 50, 100, 250},

		StoreSubscriptionRefMaxByteCount: 1024,

		BalanceCapNanoUsd:         usd(10_000),
		NewAccountDayNanoUsd:      usd(100),
		NewAccountWindowNanoUsd:   usd(200),
		NewAccountWindow:          7 * day,
		DailyLoadNanoUsd:          usd(1_500),
		OverrunDrawMaxChargeCount: 500,
		ThreeDSecureAboveNanoUsd:  usd(50),

		ThresholdBelowNanoUsd:      usd(5),
		ThresholdPackCredits:       20,
		ThresholdMonthLimitNanoUsd: usd(200),
		ThresholdDayMaxCount:       3,
		ThresholdRetryIntervals:    []time.Duration{1 * time.Hour, 6 * time.Hour},
		ThresholdFailureMaxCount:   3,
		AutoRenewBatchCount:        500,

		PromoMaxNanoUsd:                usd(10),
		PromoLapse:                     30 * day,
		PromoNetworkInterval:           30 * day,
		PromoFailureDayMaxCount:        5,
		PromoCodeMinCharacterCount:     8,
		PromoCodeMaxCharacterCount:     32,
		PromoNetworkCodeCharacterCount: 16,
		PromoRetryWindow:               24 * time.Hour,
		PromoFailureKeyTtl:             24 * time.Hour,
		PromoLapseBatchCount:           500,
		PromoTextMaxByteCount:          256,

		RefundWindow:              30 * day,
		ClosureRefundWindow:       90 * day,
		ClosureStoreWindow:        92 * day,
		ClosureStoreGrantMaxCount: 24,

		ChargeRetention:          90 * day,
		SearchChargeRetention:    72 * time.Hour,
		SearchChargePurgeAge:     71*time.Hour + 55*time.Minute,
		DayRowRetention:          400 * day,
		FinancialRecordRetention: 7 * 365 * day,
		PayerRetention:           2 * 365 * day,
		PayerDayRetention:        30 * day,
		DisputeRetention:         400 * day,
		ChargePartitionDaysAhead: 7,
		RollupNetworkBatchCount:  100,
		RollupDropLockTimeout:    5 * time.Second,

		SettleInterval:        2 * time.Second,
		SettleBatchRowCount:   500,
		SettleShardCount:      16,
		UnconfirmedHoldMaxAge: 60 * time.Second,
		OpRowWriteMaxTime:     10 * time.Second,
		CapacityRetry:         5 * time.Second,
		SettleScriptWindow:    5 * time.Minute,
		OpMinuteGrain:         time.Minute,

		EnclaveHostEgressInterval: time.Hour,
		CatalogIdMaxByteCount:     96,
		ProviderRefMaxByteCount:   256,
		RecoverBatchRowCount:      500,

		SettledUnbookedPageAge: 60 * time.Second,
		TeeRecoverAfter:        10 * time.Minute,
		OpReleaseAfter:         24 * time.Hour,
		RecoverInterval:        1 * time.Minute,
		AutoRenewInterval:      1 * time.Minute,
		SuspendInterval:        1 * time.Minute,
		PromoLapseInterval:     1 * time.Hour,
		RollupDayOffset:        2 * time.Hour,

		DirectExposureNanoUsd:  usd(5),
		AbsorbedPageDayNanoUsd: usd(50),
		DirectMismatchWindow:   30 * day,

		FloorMaxNanoUsd:   usd(5),
		FloorEnclaveTime:  1 * time.Hour,
		GraceMaxAge:       1 * time.Hour,
		BurnWindow:        24 * time.Hour,
		LowBurnTime:       24 * time.Hour,
		SuspendBatchCount: 500,
		SuspendLookback:   10 * time.Minute,

		SearchCapNew:         200,
		SearchCapEstablished: 2_000,
		SearchCapAge:         7 * day,

		EnclaveNewAccountCpuCount:  1,
		EnclaveNewAccountWait:      24 * time.Hour,
		EnclaveGpuPurchasesNanoUsd: usd(50),
		EnclaveInterval:            10 * time.Minute,
		IndexerReserveTime:         7 * day,
		IndexerGraceTime:           72 * time.Hour,

		DisputeNetworkDayMaxCount: 10,
		DisputePageNetworkCount:   3,
		DisputePageBasisPoints:    50,

		DefaultAgentDayNanoUsd:         usd(5),
		DefaultAgentMonthNanoUsd:       usd(50),
		DefaultDeviceDayNanoUsd:        usd(20),
		DefaultDeviceMonthNanoUsd:      usd(200),
		DefaultDeviceCeilingDayNanoUsd: usd(50),

		ProjectionRebuildRetry: 1 * time.Second,
		HeldRetry:              2 * time.Second,
		ProjectionMemoTtl:      10 * time.Minute,
		BudgetCounterTtl:       63 * day,

		ProjectionBudgetNameMaxByteCount: 24,
		ProjectionHoldMaxLineCount:       32,

		BudgetRaiseDecisionMaxCount: 16,

		SpendDayCount:       7,
		ChargesPageRowCount: 100,
		AnswerMaxRowCount:   10_000,
	}
}
