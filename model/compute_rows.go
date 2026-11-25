// MG-C1's rows as Go values (DESIGN-COMPUTE §9.4, §14.4; BAL-M12-01): one type a table, each field a column of
// compute_schema.go's statements, named as the column is. A nullable column is a pointer, nil for SQL NULL. Ids are
// operator.Id, which scans from and writes to uuid; money is int64 nano-USD; times are UTC, and a day is a UTC
// date at midnight.
//
// What a row may hold is what §14.6's rows say the servers see (compute-1, compute-2, compute-3, compute-6, compute-8):
// ids, amounts, units, codes and times, never a prompt, an output, a file or a query (R-BAL-6), and no row of these
// shares a table or a column with the transfer balance's (IC-4, R-BAL-2).

package model

import (
	"encoding/json"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// compute_account: a network's settled balance and state (§9.4, §9.9).
type ComputeAccount struct {
	NetworkId operator.Id
	// The sum of lots' remaining, less settled charges' overrun.
	SettledNanoUsd int64
	State          ComputeAccountState
	// How far below zero settlement may go: the smaller of $5 and an hour of the running enclaves' rates.
	NegativeFloorNanoUsd int64
	// The UTC day of the network's first charge, the spend view's "since"; nil before any.
	FirstChargeDay *time.Time
	// §9.9's indexer reserve, which neither available nor the balance the states read counts
	// (compute-plan-money-schema-gaps, QD-1252); zero while the network has none.
	IndexerReserveNanoUsd int64
	// §9.11's per-network search cap set by URnetwork's review (`sidecarctl compute search-cap`), nil for the
	// default cap (compute-plan-money-schema-gaps, QD-1252).
	SearchCapOverride *int64
	// Rises at every change of the account: what orders the projection's writes (§9.7). The projection carries it
	// as a decimal string.
	Version    int64
	UpdateTime time.Time
}

// compute_lot: one credit and what is left of it (§9.4).
type ComputeLot struct {
	LotId     operator.Id
	NetworkId operator.Id
	Kind      ComputeLotKind
	Market    ComputeMarket
	// The PaymentIntent's id, the App Store's transaction id, Play's order id (never its purchase token, which a
	// subscription keeps across renewals), or a redemption's id: unique with the market, so a replayed webhook
	// credits once.
	MarketRef        string
	AmountNanoUsd    int64
	RemainingNanoUsd int64
	CreateTime       time.Time
	// A promotion's lapse; nil for the rest.
	ExpireTime *time.Time
	// A refund's or a chargeback's.
	ReversedTime *time.Time
	// What of a promotion was left at its expire time.
	LapsedNanoUsd *int64
	// A self-serve refund's amount back to the card (§9.12; compute-plan-money-schema-gaps, QD-1252).
	RefundedNanoUsd *int64
}

// compute_charge: one charge of one kind (§9.4, §9.6), partitioned by its UTC day.
type ComputeCharge struct {
	// Its operation key (§9.7).
	ChargeId  operator.Id
	NetworkId operator.Id
	Kind      ComputeChargeKind
	// The request (inference, search), the enclave, the charge a refund returns, or a support case's id.
	SubjectRef operator.Id
	// Who caused it, an opaque id (I-13); the nil id for a support adjustment.
	SidecarId operator.Id
	AgentId   *operator.Id
	// Whom it counts to (§9.13), from the projection at the hold; nil for the network's own line.
	MemberId  *operator.Id
	EnclaveId *operator.Id
	// The model or shape id (§6.3, §11.5).
	CatalogId *string
	// §4.6's provider code; 0 for an adjustment.
	Provider int16
	Units    ComputeUnits
	// What the network pays; negative for a refund.
	AmountNanoUsd int64
	// What URnetwork pays the provider.
	CostNanoUsd int64
	// What URnetwork forgave of a direct call past its budget reservation (§9.7).
	AbsorbedNanoUsd int64
	StartTime       time.Time
	EndTime         time.Time
	SettleTime      time.Time
}

// compute_charge_lot: one lot a charge drew (§9.4), in draw order; a refund's draws are negative.
type ComputeChargeDraw struct {
	ChargeId      operator.Id
	LotId         operator.Id
	AmountNanoUsd int64
	// The draw's place in the charge's order, from 0: promotions by nearest expiry, then subscription grants, then
	// purchases, oldest first; a refund returns them in reverse.
	DrawIndex int16
}

// compute_charge_day: one day's charges of one key, the statement and spend rollup, kept 400 days (§9.13).
type ComputeChargeDay struct {
	NetworkId operator.Id
	// A UTC day.
	Day       time.Time
	Kind      ComputeChargeKind
	SidecarId operator.Id
	AgentId   *operator.Id
	CatalogId *string
	MemberId  *operator.Id
	Provider  int16
	EnclaveId *operator.Id
	Units     ComputeUnits
	// Net of refunds; the refunds, positive.
	AmountNanoUsd   int64
	RefundedNanoUsd int64
	// Charges; a refund adds none.
	Count int64
}

// compute_charge_total: the spend view's totals, kept for the account's life, with no day, sidecar or agent
// (Q-BAL-10).
type ComputeChargeTotal struct {
	NetworkId       operator.Id
	Kind            ComputeChargeKind
	MemberId        *operator.Id
	CatalogId       *string
	Provider        int16
	EnclaveId       *operator.Id
	Units           ComputeUnits
	AmountNanoUsd   int64
	RefundedNanoUsd int64
	Count           int64
}

// compute_charge_pruned: per kind, the sums of the day rows dropped past 400 days, for the totals' check (§9.13).
type ComputeChargePruned struct {
	NetworkId     operator.Id
	Kind          ComputeChargeKind
	AmountNanoUsd int64
	Count         int64
}

// compute_op: one billable operation, from before its liability arises until it is booked and dropped (§9.7).
type ComputeOp struct {
	// Its charge's charge_id.
	OpKey     operator.Id
	NetworkId operator.Id
	// compute_settle's shard, from the network (ComputeOpShard).
	Shard int16
	State ComputeOpState
	Kind  ComputeChargeKind
	// As the charge's.
	SubjectRef operator.Id
	// A search's attempt; nil for the rest.
	Attempt *int16
	// Its subjects, whose budgets it counts to.
	SidecarId operator.Id
	AgentId   *operator.Id
	MemberId  *operator.Id
	EnclaveId *operator.Id
	// What admitted it: the model or shape, the catalog version named, the provider, the provider price read.
	CatalogId      *string
	CatalogVersion *int64
	Provider       int16
	PriceRead      *int64
	// A TEE call's instance and provider nonce, until it settles; never a direct call's nonce or hash (compute-1).
	ProviderRef *string
	// The balance hold.
	HoldNanoUsd int64
	// The budget reservation: the hold, or a direct call's (§9.7).
	ReserveNanoUsd int64
	// Its charge's start time, fixed here: a direct call's and a search's to the minute.
	StartTime time.Time
	// Once settled; nil before.
	Outcome *ComputeOpOutcome
}

// compute_op.outcome: what a settled operation came to (§9.7), JSON.
type ComputeOpOutcome struct {
	Units           ComputeUnits `json:"units"`
	AmountNanoUsd   int64        `json:"amount_nano_usd"`
	CostNanoUsd     int64        `json:"cost_nano_usd"`
	AbsorbedNanoUsd int64        `json:"absorbed_nano_usd"`
	EndTime         time.Time    `json:"end_time"`
	SettleTime      time.Time    `json:"settle_time"`
}

// The outcome as compute_op.outcome holds it, its times in UTC.
func (self *ComputeOpOutcome) Json() ([]byte, error) {
	utc := *self
	utc.EndTime = utc.EndTime.UTC()
	utc.SettleTime = utc.SettleTime.UTC()
	return json.Marshal(&utc)
}

// An outcome from compute_op.outcome, its units held to ParseComputeUnits' rules and every amount but a refund's
// non-negative: an outcome that is not §9.7's never reads as one.
func ParseComputeOpOutcome(data []byte) (*ComputeOpOutcome, error) {
	raw := struct {
		Units           json.RawMessage `json:"units"`
		AmountNanoUsd   *int64          `json:"amount_nano_usd"`
		CostNanoUsd     *int64          `json:"cost_nano_usd"`
		AbsorbedNanoUsd *int64          `json:"absorbed_nano_usd"`
		EndTime         *time.Time      `json:"end_time"`
		SettleTime      *time.Time      `json:"settle_time"`
	}{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("compute op outcome: %w", err)
	}
	if raw.Units == nil || raw.AmountNanoUsd == nil || raw.CostNanoUsd == nil || raw.AbsorbedNanoUsd == nil ||
		raw.EndTime == nil || raw.SettleTime == nil {
		return nil, fmt.Errorf("compute op outcome: a field is missing")
	}
	units, err := ParseComputeUnits(raw.Units)
	if err != nil {
		return nil, err
	}
	// a refund's cost moves only as far as the provider's bill moved, so only a refund's may be negative (§9.6)
	if (*raw.CostNanoUsd < 0 && 0 <= *raw.AmountNanoUsd) || *raw.AbsorbedNanoUsd < 0 {
		return nil, fmt.Errorf("compute op outcome: a negative cost or absorbed amount")
	}
	return &ComputeOpOutcome{
		Units:           units,
		AmountNanoUsd:   *raw.AmountNanoUsd,
		CostNanoUsd:     *raw.CostNanoUsd,
		AbsorbedNanoUsd: *raw.AbsorbedNanoUsd,
		EndTime:         raw.EndTime.UTC(),
		SettleTime:      raw.SettleTime.UTC(),
	}, nil
}

// compute_settle's shard for a network: the network id's first two bytes over the settings' shard count, so a
// network's operations always fall to one shard. Zero where the count is not positive.
func ComputeOpShard(settings *ComputeLedgerSettings, networkId operator.Id) int16 {
	if settings.SettleShardCount <= 0 {
		return 0
	}
	return int16((int(networkId[0])<<8 | int(networkId[1])) % settings.SettleShardCount)
}

// §9.8's two auto-renew modes, as compute_auto_renew.mode holds them.
type ComputeAutoRenewMode int16

const (
	// A top-up of pack P when the balance falls below T, on the card its payer saved for it: Stripe only.
	ComputeAutoRenewModeThreshold ComputeAutoRenewMode = 1
	// M credits on the same day each month: a Stripe subscription or a store subscription.
	ComputeAutoRenewModeMonthly ComputeAutoRenewMode = 2
)

// Why threshold top-up turned off (§9.8), as compute_auto_renew.off_reason holds it.
type ComputeAutoRenewOffReason int16

const (
	// A charge asked for authentication: a link was emailed, and threshold waits for the owner.
	ComputeAutoRenewOffAuthenticationRequired ComputeAutoRenewOffReason = 1
	// The third failure in a row.
	ComputeAutoRenewOffFailed ComputeAutoRenewOffReason = 2
	// The payer left the network, or lost the role that let them buy, and their card was detached.
	ComputeAutoRenewOffPayerLeft ComputeAutoRenewOffReason = 3
)

// compute_auto_renew: one network's mode (§9.8, compute-6).
type ComputeAutoRenew struct {
	NetworkId operator.Id
	Mode      ComputeAutoRenewMode
	Enabled   bool
	// The market the monthly plan runs on; Stripe for threshold.
	Market ComputeMarket
	// Threshold's T, P (in credits) and L; nil for monthly.
	BelowNanoUsd      *int64
	PackCredits       *int64
	MonthLimitNanoUsd *int64
	// Monthly's M; nil for threshold.
	MonthlyCredits *int64
	// The member whose card it charges, who saved it for this (§9.5); nil while none is saved, and for a store's.
	PayerMemberId *operator.Id
	// The payer's Stripe customer for this network and its saved payment method, or the plan's subscription.
	StripeCustomerId      *string
	StripePaymentMethodId *string
	StripeSubscriptionId  *string
	OffReason             *ComputeAutoRenewOffReason
	TopUpDay              *time.Time
	TopUpDayCount         int32
	FailureDayCount       int32
	FailureRunCount       int32
	TopUpMonth            *time.Time
	TopUpMonthNanoUsd     int64
	NextRetryTime         *time.Time
	UpdateTime            time.Time
}

// What a dispute came to (D-BAL-11), as compute_dispute.state holds it.
type ComputeDisputeState int16

const (
	ComputeDisputeStateOpen     ComputeDisputeState = 1
	ComputeDisputeStateUpheld   ComputeDisputeState = 2
	ComputeDisputeStateRejected ComputeDisputeState = 3
)

// compute_dispute: a device's charge_mismatch (§6.7, compute-8).
type ComputeDispute struct {
	RequestId     operator.Id
	NetworkId     operator.Id
	Provider      int16
	DeviceUnits   ComputeUnits
	ProviderUnits ComputeUnits
	// The charge it holds.
	ChargeId   *operator.Id
	State      ComputeDisputeState
	CreateTime time.Time
	UpdateTime time.Time
}

// A budget's period (§16.4), as compute_budget_raise.period holds it.
type ComputeBudgetPeriod int16

const (
	// The UTC day.
	ComputeBudgetPeriodDay ComputeBudgetPeriod = 1
	// The UTC month.
	ComputeBudgetPeriodMonth ComputeBudgetPeriod = 2
	// One run, which the device's Harness bounds: kept for kind 21's record, never a broker counter.
	ComputeBudgetPeriodRun ComputeBudgetPeriod = 3
)

// The period's word, or period<n> for a number §16.3 does not name.
func (self ComputeBudgetPeriod) String() string {
	switch self {
	case ComputeBudgetPeriodDay:
		return "day"
	case ComputeBudgetPeriodMonth:
		return "month"
	case ComputeBudgetPeriodRun:
		return "run"
	}
	return fmt.Sprintf("period%d", int(self))
}

// compute_budget_raise: one raise kind 21 approved (§16.3, compute-6), unique by approval and use, and by effect key.
type ComputeBudgetRaise struct {
	ApprovalId  operator.Id
	ApprovalUse int32
	EffectKey   operator.Id
	NetworkId   operator.Id
	SubjectId   operator.Id
	Period      ComputeBudgetPeriod
	// The raised cap.
	AmountNanoUsd int64
	ExpireTime    time.Time
	CreateTime    time.Time
}

// compute_promo_code: one of URnetwork's promotion codes (§9.11, compute-2), held as a keyed hash of the code, its
// case folded.
type ComputePromoCode struct {
	CodeId   operator.Id
	CodeHash []byte
	Campaign string
	// At most $10.
	AmountNanoUsd  int64
	RedeemMaxCount int64
	RedeemCount    int64
	// The last UTC day it redeems.
	LastDay         time.Time
	PaidLotRequired bool
	// Who made it and why: an operator's name and words about a campaign, never a person's content.
	CreatedBy  string
	Reason     string
	CreateTime time.Time
}

// compute_promo_redemption: one network's redemption of one code (§9.11, compute-2), unique per code and network.
type ComputePromoRedemption struct {
	RedemptionId operator.Id
	CodeId       operator.Id
	NetworkId    operator.Id
	LotId        operator.Id
	// The redeeming sidecar's opaque id.
	SidecarId  operator.Id
	RedeemTime time.Time
}

// compute_payer: a payer's keyed hash and first purchase day, kept apart from any network (§9.11, compute-2).
type ComputePayer struct {
	PayerHash        []byte
	FirstPurchaseDay time.Time
}

// compute_payer_day: a payer's purchases on one UTC day, apart from any network (§9.11, compute-2).
type ComputePayerDay struct {
	PayerHash     []byte
	Day           time.Time
	AmountNanoUsd int64
}

// compute_terms: one clause of the compute terms a network accepted, by whom and when (§21.9, compute-2).
type ComputeTerms struct {
	NetworkId operator.Id
	// The clause, such as web_search.
	Clause       string
	TermsVersion int64
	// The accepting user's opaque id.
	UserId     operator.Id
	AcceptTime time.Time
}
