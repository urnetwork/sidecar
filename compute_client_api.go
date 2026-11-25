//go:build !ios_extension && !sidecar_http && !js

// DESIGN-COMPUTE §14.3's api compute routes on SidecarApi (BAL-M12-17), on api's host as api/compute/x reads (host api,
// path /compute/x), each with the client's jwt as bearer, as /mail/status is, and each answered as JSON:
//
//	GET  /compute/balance        available, held, the balance the states read, the state, auto-renew, whether the
//	                             caller may buy and whether sales are open (Q-BAL-13), and §9.9's notice's enclaves
//	                             and indexer days
//	POST /compute/checkout       a Stripe Checkout session for a pack, or the monthly plan, with the auto-renew mode
//	                             the paying person turns on in that act (§9.5)
//	GET  /compute/auto-renew     threshold and monthly settings (§9.8)
//	POST /compute/auto-renew     one mode's change, a mode turned on naming a card the person turning it on saved
//	GET  /compute/charges        per-request charges, a page at a time (§9.10's roles, filtered server-side)
//	GET  /compute/statement      a month's day rows and the lots bought or redeemed (§9.13)
//	GET  /compute/spend          §9.13's spend view: each charge kind's total since the first charge day and its last
//	                             7 UTC days, net of refunds with the refunds apart, broken down by one dimension
//	POST /compute/refund         a Stripe lot's unspent part, within 30 days of its purchase (§9.12)
//	POST /compute/promo/redeem   one promotion code (§9.11)
//
// These are the formats the routes' handlers (BAL-M12-06 on) answer: the server answers ids and typed numbers alone
// (I-13, R-BAL-6), so every answer is read into these types, which hold nothing else, and any other field a body
// carries is dropped unread (§9.13's last sentence). An answer that lacks a required field, names a value outside its
// type, or holds more rows than ComputeClientSettings.AnswerMaxRowCount is refused whole (ErrSidecarApiReply), never
// taken in part. A refusal is a *SidecarApiError, its code §9.11's, §9.8's or §14.3's own (code_unknown, card_required,
// sales_closed, not_built ...). Arguments a route cannot take are refused before anything is sent
// (ErrSidecarApiArgs). A code, a Checkout url and a lot are never logged: a SidecarApiError names its route alone.
//
// Money is int64 nano-USD, USD × 10^9 (D-BAL-2), never a float; a credit is one dollar, and packs and plans are counted
// in credits. Times travel as Unix milliseconds and read as UTC; days as YYYY-MM-DD and months as YYYY-MM, both UTC
// (Q-BAL-8). Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The routes, as errors name them.
const (
	computeBalanceRoute        = "GET /compute/balance"
	computeCheckoutRoute       = "POST /compute/checkout"
	computeAutoRenewRoute      = "GET /compute/auto-renew"
	computeSetAutoRenewRoute   = "POST /compute/auto-renew"
	computeChargesRoute        = "GET /compute/charges"
	computeStatementRoute      = "GET /compute/statement"
	computeSpendRoute          = "GET /compute/spend"
	computeRefundRoute         = "POST /compute/refund"
	computePromoRedeemRoute    = "POST /compute/promo/redeem"
	computeDayLayout           = "2006-01-02"
	computeMonthLayout         = "2006-01"
	computeCursorAlphabet      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~"
	computeCheckoutSchemeHttps = "https"
)

// §14.3's and §9's refusal codes the device acts on, as api answers them in a refusal's code.
const (
	// The network's balance cannot pay (§9.9): grace or suspended.
	ComputeRefusalBalance = "compute_balance"
	// Credits are not sold yet: nothing the network may use can spend them (Q-BAL-13).
	ComputeRefusalSalesClosed = "sales_closed"
	// The caller may not buy (§9.10): not an Owner, a Billing admin or a member granted compute:buy, or not an untagged
	// member device.
	ComputeRefusalMayNotBuy = "may_not_buy"
	// A mode turned on names no card its person saved for it in that act: buy a pack with the mode turned on (§9.5).
	ComputeRefusalCardRequired = "card_required"
	// A purchase that would pass the $10,000 cap (§9.11).
	ComputeRefusalBalanceCap = "balance_cap"
	// A purchase or code past a day's load (§9.11).
	ComputeRefusalDailyLimit = "daily_limit"
	// §9.11's promotion code refusals.
	ComputeRefusalCodeUnknown      = "code_unknown"
	ComputeRefusalCodeEnded        = "code_ended"
	ComputeRefusalCodeRedeemed     = "code_redeemed"
	ComputeRefusalRedeemedRecently = "redeemed_recently"
	ComputeRefusalPaidLotRequired  = "paid_lot_required"
	ComputeRefusalRateLimited      = "rate_limited"
	// A refund of a lot past its 30 days, spent, or not a Stripe purchase (§9.12).
	ComputeRefusalNotRefundable = "not_refundable"
	// The route's handler is not built yet (BAL-M12-06's frame).
	ComputeRefusalNotBuilt = "not_built"
)

// What a charge is for (§9.6), as compute_charge.kind holds it.
type ComputeChargeKind int16

const (
	// One remote inference request.
	ComputeChargeKindInference ComputeChargeKind = 1
	// One enclave's running time.
	ComputeChargeKindEnclaveRun ComputeChargeKind = 2
	// Reserved for persistent enclave volumes, which are Later: never written at launch.
	ComputeChargeKindEnclaveDisk ComputeChargeKind = 3
	// Bytes an enclave sends out through its provider's own network.
	ComputeChargeKindEnclaveHostEgress ComputeChargeKind = 4
	// A support credit or debit naming no charge.
	ComputeChargeKindAdjustment ComputeChargeKind = 5
	// One web search.
	ComputeChargeKindWebSearch ComputeChargeKind = 6
)

// The kinds a charge may carry at launch: every one but enclave_disk.
var computeChargeKindsWritten = []ComputeChargeKind{
	ComputeChargeKindInference,
	ComputeChargeKindEnclaveRun,
	ComputeChargeKindEnclaveHostEgress,
	ComputeChargeKindAdjustment,
	ComputeChargeKindWebSearch,
}

// §9.6's name, or kind<n> for a number §9.6 does not name.
func (self ComputeChargeKind) String() string {
	switch self {
	case ComputeChargeKindInference:
		return "inference"
	case ComputeChargeKindEnclaveRun:
		return "enclave_run"
	case ComputeChargeKindEnclaveDisk:
		return "enclave_disk"
	case ComputeChargeKindEnclaveHostEgress:
		return "enclave_host_egress"
	case ComputeChargeKindAdjustment:
		return "adjustment"
	case ComputeChargeKindWebSearch:
		return "web_search"
	}
	return "kind" + strconv.Itoa(int(self))
}

// The service of §9.13's spend view a kind counts to.
func (self ComputeChargeKind) Service() ComputeService {
	switch self {
	case ComputeChargeKindInference:
		return ComputeServiceInference
	case ComputeChargeKindEnclaveRun, ComputeChargeKindEnclaveHostEgress, ComputeChargeKindEnclaveDisk:
		return ComputeServiceEnclaves
	case ComputeChargeKindWebSearch:
		return ComputeServiceWebSearch
	}
	return ComputeServiceAdjustments
}

// §9.13's services: where credits went.
type ComputeService string

const (
	// Remote inference: kind 1.
	ComputeServiceInference ComputeService = "inference"
	// Enclaves: kinds 2 and 4, each its own line.
	ComputeServiceEnclaves ComputeService = "enclaves"
	// Web search: kind 6.
	ComputeServiceWebSearch ComputeService = "web_search"
	// Adjustments: kind 5, net.
	ComputeServiceAdjustments ComputeService = "adjustments"
)

// §9.13's services that cost nothing, whose bytes count toward the transfer balance, which the view shows at no
// charge: web fetch, calendar calls and connected services' calls.
func ComputeServicesWithoutCharge() []string {
	return []string{"web_fetch", "calendar", "connected_services"}
}

// What a lot is (§9.4), as compute_lot.kind holds it.
type ComputeLotKind int16

const (
	ComputeLotKindPurchase     ComputeLotKind = 1
	ComputeLotKindSubscription ComputeLotKind = 2
	ComputeLotKindPromotion    ComputeLotKind = 3
	ComputeLotKindAdjustment   ComputeLotKind = 4
)

// Where a lot came from (§9.4), as compute_lot.market holds it.
type ComputeMarket int16

const (
	ComputeMarketStripe     ComputeMarket = 1
	ComputeMarketAppStore   ComputeMarket = 2
	ComputeMarketGooglePlay ComputeMarket = 3
	ComputeMarketManual     ComputeMarket = 4
	ComputeMarketPromotion  ComputeMarket = 5
)

// The market's word: stripe, app_store, google_play, manual or promotion, or market<n> for one §9.4 does not name.
func (self ComputeMarket) String() string {
	switch self {
	case ComputeMarketStripe:
		return "stripe"
	case ComputeMarketAppStore:
		return "app_store"
	case ComputeMarketGooglePlay:
		return "google_play"
	case ComputeMarketManual:
		return "manual"
	case ComputeMarketPromotion:
		return "promotion"
	}
	return "market" + strconv.Itoa(int(self))
}

// The market a word names, for the surfaces that take one: stripe, app_store or google_play, the three that sell.
func ParseComputeMarket(word string) (ComputeMarket, error) {
	for _, market := range []ComputeMarket{ComputeMarketStripe, ComputeMarketAppStore, ComputeMarketGooglePlay} {
		if market.String() == word {
			return market, nil
		}
	}
	return 0, fmt.Errorf("%w: not a market that sells compute credit", ErrSidecarApiArgs)
}

// One of §9.8's two auto-renew modes.
type ComputeAutoRenewMode string

const (
	// A top-up of pack P when the balance falls below T, on the card its payer saved for it: Stripe only.
	ComputeAutoRenewThreshold ComputeAutoRenewMode = "threshold"
	// M credits on the same day each month: a Stripe subscription, or a store subscription.
	ComputeAutoRenewMonthly ComputeAutoRenewMode = "monthly"
)

// Why threshold top-up is off where it was on (§9.8), as the balance and auto-renew routes answer it.
const (
	// A charge asked for authentication: a link was emailed, and threshold waits for the owner.
	ComputeAutoRenewOffAuthenticationRequired = "authentication_required"
	// The third failure in a row.
	ComputeAutoRenewOffFailed = "failed"
	// The payer left the network, or lost the role that let them buy, and their card was detached.
	ComputeAutoRenewOffPayerLeft = "payer_left"
)

// A charge's units (§9.4's typed columns), each a count: tokens, seconds in running, egress bytes and searches.
type ComputeUnits struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	CachedTokens int64 `json:"cached_tokens"`
	Seconds      int64 `json:"seconds"`
	EgressBytes  int64 `json:"egress_bytes"`
	Searches     int64 `json:"searches"`
}

// The sum of two units.
func (self ComputeUnits) add(other ComputeUnits) ComputeUnits {
	return ComputeUnits{
		InputTokens:  self.InputTokens + other.InputTokens,
		OutputTokens: self.OutputTokens + other.OutputTokens,
		CachedTokens: self.CachedTokens + other.CachedTokens,
		Seconds:      self.Seconds + other.Seconds,
		EgressBytes:  self.EgressBytes + other.EgressBytes,
		Searches:     self.Searches + other.Searches,
	}
}

// What GET /compute/balance answers (§9.7, §9.9, §14.3).
type ComputeBalance struct {
	// settled less unsettled charges less open holds: what admission reads.
	AvailableNanoUsd int64 `json:"available_nano_usd"`
	// Open holds and a running enclave's current 10 minutes, shown apart as held (§9.13).
	HeldNanoUsd int64 `json:"held_nano_usd"`
	// settled less unsettled charges less the running enclaves' accrued time, holds left out: what auto-renew and the
	// states read (§9.7).
	BalanceNanoUsd int64 `json:"balance_nano_usd"`
	// The unexpired promotional credit left, which pays no search (§9.11).
	PromoNanoUsd int64               `json:"promo_nano_usd"`
	State        ComputeAccountState `json:"state"`
	// The account's version, which rises at each change: what orders two reads.
	Version uint64 `json:"version"`
	// Both modes; a mode absent is off.
	AutoRenew *ComputeAutoRenew `json:"auto_renew"`
	// Whether the caller may buy (§9.10), so the apps offer credit only to one who may.
	MayBuy bool `json:"may_buy"`
	// Whether credits are on sale: something the network may use can spend them (Q-BAL-13).
	SalesOpen bool `json:"sales_open"`
	// From low on, the enclaves a suspension would stop (§9.9).
	AtRiskEnclaveIds []Id `json:"at_risk_enclave_ids"`
	// From low on, whole days the network's indexer enclave's reserve and grace leave; nil where it has none.
	IndexerDaysLeft *int64 `json:"indexer_days_left"`
	// The settlement time the figures are exact to.
	UpdateTime time.Time `json:"update_time"`
}

// §9.8's two modes, as the balance and auto-renew routes answer them.
type ComputeAutoRenew struct {
	Threshold *ComputeThreshold `json:"threshold"`
	Monthly   *ComputeMonthly   `json:"monthly"`
}

// §9.8's threshold top-up.
type ComputeThreshold struct {
	On bool `json:"on"`
	// T: a top-up fires once the balance, holds left out, falls below it.
	BelowNanoUsd int64 `json:"below_nano_usd"`
	// P: the pack each top-up buys, in credits.
	PackCredits int64 `json:"pack_credits"`
	// L: the most top-ups charge in a calendar month.
	MonthLimitNanoUsd int64 `json:"month_limit_nano_usd"`
	// Why it is off where it was on: authentication_required, failed or payer_left; empty for none.
	OffReason string `json:"off_reason"`
	// The member whose card it charges, who saved it for this; nil while no card is saved.
	PayerMemberId *Id `json:"payer_member_id"`
	// Today's top-ups and failures, and the month's top-ups' sum (§9.8's limits).
	TopUpsToday   int64 `json:"top_ups_today"`
	FailuresToday int64 `json:"failures_today"`
	MonthNanoUsd  int64 `json:"month_nano_usd"`
}

// §9.8's monthly plan.
type ComputeMonthly struct {
	On bool `json:"on"`
	// M: the credits each month grants.
	Credits int64 `json:"credits"`
	// stripe, app_store or google_play.
	Market ComputeMarket `json:"market"`
	// The member who pays for it; nil for a store's, whose payer the store keeps.
	PayerMemberId *Id `json:"payer_member_id"`
}

// One change of one mode (POST /compute/auto-renew). A zero amount keeps the mode's current value, or its default.
type ComputeAutoRenewChange struct {
	Mode ComputeAutoRenewMode `json:"mode"`
	On   bool                 `json:"on"`
	// threshold's T, P and L
	BelowNanoUsd      int64 `json:"below_nano_usd,omitempty"`
	PackCredits       int64 `json:"pack_credits,omitempty"`
	MonthLimitNanoUsd int64 `json:"month_limit_nano_usd,omitempty"`
	// monthly's M
	Credits int64 `json:"credits,omitempty"`
}

// What POST /compute/checkout takes: a pack bought once, with threshold top-up turned on in the same act or not, or
// the monthly plan alone, which Checkout opens as a subscription (§9.5, §9.8).
type ComputeCheckoutArgs struct {
	// A Stripe pack, in credits; zero for the monthly plan alone.
	PackCredits int64 `json:"pack_credits,omitempty"`
	// The mode the paying person turns on in this act, which saves their card for it; empty for none.
	AutoRenew ComputeAutoRenewMode `json:"auto_renew,omitempty"`
	// threshold's T, P and L, where AutoRenew is threshold; zero for the defaults
	BelowNanoUsd      int64 `json:"below_nano_usd,omitempty"`
	TopUpPackCredits  int64 `json:"top_up_pack_credits,omitempty"`
	MonthLimitNanoUsd int64 `json:"month_limit_nano_usd,omitempty"`
	// monthly's M, where AutoRenew is monthly
	MonthlyCredits int64 `json:"monthly_credits,omitempty"`
}

// What POST /compute/checkout answers: the url a surface opens, which no log carries.
type ComputeCheckout struct {
	Url        string    `json:"url"`
	ExpireTime time.Time `json:"expire_time"`
}

// What POST /compute/promo/redeem answers: the redemption's lot, which lapses at its expire time (§9.11).
type ComputeRedemption struct {
	LotId         Id        `json:"lot_id"`
	CreditNanoUsd int64     `json:"credit_nano_usd"`
	ExpireTime    time.Time `json:"expire_time"`
}

// What POST /compute/refund answers: the lot and what of it went back to the card (§9.12).
type ComputeRefund struct {
	LotId           Id    `json:"lot_id"`
	RefundedNanoUsd int64 `json:"refunded_nano_usd"`
}

// One per-request charge (§9.4's compute_charge): ids, units, amounts and times, and nothing of what it served.
type ComputeChargeRow struct {
	ChargeId ComputeChargeId   `json:"charge_id"`
	Kind     ComputeChargeKind `json:"kind"`
	// The request (inference, search), the enclave, the charge a refund returns, or a support case.
	SubjectRef Id `json:"subject_ref"`
	// Who caused it: a sidecar, the nil id for a support adjustment.
	SidecarId Id  `json:"sidecar_id"`
	AgentId   *Id `json:"agent_id"`
	// Whom it counts to; nil for the network's own line.
	MemberId  *Id    `json:"member_id"`
	EnclaveId *Id    `json:"enclave_id"`
	CatalogId string `json:"catalog_id"`
	// §4.6's provider code; 0 for none.
	Provider int16        `json:"provider"`
	Units    ComputeUnits `json:"units"`
	// What the network pays; negative for a refund.
	AmountNanoUsd int64 `json:"amount_nano_usd"`
	// What URnetwork covered of a direct call past its budget reservation (§9.7): in no figure.
	AbsorbedNanoUsd int64     `json:"absorbed_nano_usd"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	SettleTime      time.Time `json:"settle_time"`
}

// A charge's key: the 16 bytes of its operation key, which a random draw or a UUIDv5 makes, so not always a time
// ordered id.
type ComputeChargeId = Id

// One page of GET /compute/charges.
type ComputeCharges struct {
	Charges []*ComputeChargeRow `json:"charges"`
	// The next page's cursor, opaque; empty after the last page.
	NextCursor string `json:"next_cursor"`
}

// One day row of a statement (§9.4's compute_charge_day): a day, its dimensions, its units and sums.
type ComputeStatementRow struct {
	Day       string            `json:"day"`
	Kind      ComputeChargeKind `json:"kind"`
	SidecarId Id                `json:"sidecar_id"`
	AgentId   *Id               `json:"agent_id"`
	CatalogId string            `json:"catalog_id"`
	MemberId  *Id               `json:"member_id"`
	Provider  int16             `json:"provider"`
	EnclaveId *Id               `json:"enclave_id"`
	Units     ComputeUnits      `json:"units"`
	// Net of refunds, and the refunds, positive.
	AmountNanoUsd   int64 `json:"amount_nano_usd"`
	RefundedNanoUsd int64 `json:"refunded_nano_usd"`
	Count           int64 `json:"count"`
}

// One lot bought, granted or redeemed in a statement's month (§9.4's compute_lot), without its market's reference.
type ComputeLotRow struct {
	LotId            Id             `json:"lot_id"`
	Kind             ComputeLotKind `json:"kind"`
	Market           ComputeMarket  `json:"market"`
	AmountNanoUsd    int64          `json:"amount_nano_usd"`
	RemainingNanoUsd int64          `json:"remaining_nano_usd"`
	CreateTime       time.Time      `json:"create_time"`
	// A promotion's; nil for the rest.
	ExpireTime *time.Time `json:"expire_time"`
	// A refund's or a chargeback's.
	ReversedTime *time.Time `json:"reversed_time"`
	// What of a promotion was left at its expiry.
	LapsedNanoUsd *int64 `json:"lapsed_nano_usd"`
}

// What GET /compute/statement answers.
type ComputeStatement struct {
	Month string                 `json:"month"`
	Rows  []*ComputeStatementRow `json:"rows"`
	Lots  []*ComputeLotRow       `json:"lots"`
}

// The dimension §9.13's breakdowns read.
type ComputeSpendBy string

const (
	// No breakdown: each line's figures alone.
	ComputeSpendByNone     ComputeSpendBy = ""
	ComputeSpendByProvider ComputeSpendBy = "provider"
	// A model by its canonical name, or an enclave's shape.
	ComputeSpendByModel   ComputeSpendBy = "model"
	ComputeSpendByEnclave ComputeSpendBy = "enclave"
	// Whom each charge counts to, the network's own line among them.
	ComputeSpendByMember ComputeSpendBy = "member"
	// The last 7 days only: no total is kept by agent (Q-BAL-10).
	ComputeSpendByAgent ComputeSpendBy = "agent"
)

// The dimension a word names, for the surfaces that take one: none, provider, model, enclave, member or agent.
func ParseComputeSpendBy(word string) (ComputeSpendBy, error) {
	for _, by := range []ComputeSpendBy{ComputeSpendByNone, ComputeSpendByProvider, ComputeSpendByModel,
		ComputeSpendByEnclave, ComputeSpendByMember, ComputeSpendByAgent} {
		if string(by) == word {
			return by, nil
		}
	}
	return "", fmt.Errorf("%w: a breakdown is provider, model, enclave, member or agent", ErrSidecarApiArgs)
}

// One figure of the spend view: settled charges, net of refunds, with the refunds apart, the charges' count and their
// units. A refund adds to Refunded and nets out of Amount, and changes neither Count nor the units (§9.13).
type ComputeSpendFigures struct {
	AmountNanoUsd   int64        `json:"amount_nano_usd"`
	RefundedNanoUsd int64        `json:"refunded_nano_usd"`
	Count           int64        `json:"count"`
	Units           ComputeUnits `json:"units"`
}

// The sum of two figures.
func (self *ComputeSpendFigures) add(other *ComputeSpendFigures) *ComputeSpendFigures {
	return &ComputeSpendFigures{
		AmountNanoUsd:   self.AmountNanoUsd + other.AmountNanoUsd,
		RefundedNanoUsd: self.RefundedNanoUsd + other.RefundedNanoUsd,
		Count:           self.Count + other.Count,
		Units:           self.Units.add(other.Units),
	}
}

// One line of the spend view: one charge kind's total since the network's first charge day, each of its last 7 UTC
// days, and its rows by the view's dimension.
type ComputeSpendLine struct {
	Kind  ComputeChargeKind      `json:"kind"`
	Total *ComputeSpendFigures   `json:"total"`
	Days  []*ComputeSpendFigures `json:"days"`
	Rows  []*ComputeSpendRow     `json:"rows"`
}

// One row of a line's breakdown: its key, by the view's dimension, and its figures. A row by agent carries no total.
type ComputeSpendRow struct {
	// by provider: §4.6's code
	Provider *int16 `json:"provider"`
	// by model: the model's canonical name or the shape; nil for charges that name none
	CatalogId *string `json:"catalog_id"`
	// by enclave: nil for charges that name none
	EnclaveId *Id `json:"enclave_id"`
	// by member, and by agent the agent's member: nil for the network's own line
	MemberId *Id `json:"member_id"`
	// by agent: nil for calls no agent named
	AgentId *Id                    `json:"agent_id"`
	Total   *ComputeSpendFigures   `json:"total"`
	Days    []*ComputeSpendFigures `json:"days"`
}

// What GET /compute/spend answers (§9.13).
type ComputeSpend struct {
	By ComputeSpendBy `json:"by"`
	// The window's UTC days, oldest first, the last today so far.
	Days []string `json:"days"`
	// The network's first charge day, the totals' since; empty before any.
	FirstChargeDay string `json:"first_charge_day"`
	// The holds that count to the viewer: the network's for a role that sees it, else the member's (§9.13).
	HeldNanoUsd int64 `json:"held_nano_usd"`
	// compute_account.update_time: the settlement time every figure is exact to.
	UpdateTime time.Time           `json:"update_time"`
	Lines      []*ComputeSpendLine `json:"lines"`
}

// A route's url: the api's origin and path, with query when not empty.
func (self *SidecarApi) computeUrl(path string, query url.Values) string {
	if len(query) == 0 {
		return self.settings.ApiUrl + path
	}
	return self.settings.ApiUrl + path + "?" + query.Encode()
}

// The compute client's settings this api reads, its defaults where the host gave none.
func (self *SidecarApi) computeSettings() *ComputeClientSettings {
	if self.settings.Compute == nil {
		return DefaultComputeClientSettings()
	}
	return self.settings.Compute
}

// An answer that is not the route's, saying which field, never its value.
func computeReplyError(route string, format string, a ...any) error {
	return fmt.Errorf("sidecar api %s: %w: %s", route, ErrSidecarApiReply, fmt.Sprintf(format, a...))
}

// Arguments the route cannot take. Nothing was sent.
func computeArgsError(route string, format string, a ...any) error {
	return fmt.Errorf("sidecar api %s: %w: %s", route, ErrSidecarApiArgs, fmt.Sprintf(format, a...))
}

// A time from Unix milliseconds, UTC; the zero time for 0.
func computeTimeOf(millis int64) time.Time {
	if millis == 0 {
		return time.Time{}
	}
	return time.UnixMilli(millis).UTC()
}

// Whether day is a UTC day, YYYY-MM-DD, in its one form.
func computeDayValid(day string) bool {
	parsed, err := time.ParseInLocation(computeDayLayout, day, time.UTC)
	return err == nil && parsed.Format(computeDayLayout) == day
}

// Whether month is a UTC month, YYYY-MM, in its one form.
func computeMonthValid(month string) bool {
	parsed, err := time.ParseInLocation(computeMonthLayout, month, time.UTC)
	return err == nil && parsed.Format(computeMonthLayout) == month
}

// Whether id is a catalog id as a charge may name one: ASCII without spaces or controls, within the label bound, so
// one that is no model's still travels as an id; the labeler holds it to §6.3's grammar before it shows it.
func computeCatalogIdValid(catalogId string, settings *ComputeClientSettings) bool {
	if catalogId == "" || settings.LabelMaxCharacterCount < len(catalogId) {
		return false
	}
	for i := 0; i < len(catalogId); i += 1 {
		if catalogId[i] <= ' ' || '~' < catalogId[i] {
			return false
		}
	}
	return true
}

// Whether a charge kind is one a charge may carry.
func computeChargeKindValid(kind ComputeChargeKind) bool {
	return slices.Contains(computeChargeKindsWritten, kind)
}

// GET /compute/balance's body, every required field a pointer, so an absent one is told from a zero.
type computeBalanceAnswer struct {
	AvailableNanoUsd *int64                  `json:"available_nano_usd"`
	HeldNanoUsd      *int64                  `json:"held_nano_usd"`
	BalanceNanoUsd   *int64                  `json:"balance_nano_usd"`
	PromoNanoUsd     int64                   `json:"promo_nano_usd"`
	State            *ComputeAccountState    `json:"state"`
	Version          *uint64                 `json:"version"`
	AutoRenew        *computeAutoRenewAnswer `json:"auto_renew"`
	MayBuy           *bool                   `json:"may_buy"`
	SalesOpen        *bool                   `json:"sales_open"`
	AtRiskEnclaveIds []Id                    `json:"at_risk_enclave_ids"`
	IndexerDaysLeft  *int64                  `json:"indexer_days_left"`
	UpdateTimeMs     *int64                  `json:"update_time_ms"`
}

// The auto-renew routes' body, as the balance route nests it.
type computeAutoRenewAnswer struct {
	Threshold *computeThresholdAnswer `json:"threshold"`
	Monthly   *computeMonthlyAnswer   `json:"monthly"`
}

// threshold's body.
type computeThresholdAnswer struct {
	On                *bool  `json:"on"`
	BelowNanoUsd      int64  `json:"below_nano_usd"`
	PackCredits       int64  `json:"pack_credits"`
	MonthLimitNanoUsd int64  `json:"month_limit_nano_usd"`
	OffReason         string `json:"off_reason"`
	PayerMemberId     *Id    `json:"payer_member_id"`
	TopUpsToday       int64  `json:"top_ups_today"`
	FailuresToday     int64  `json:"failures_today"`
	MonthNanoUsd      int64  `json:"month_nano_usd"`
}

// monthly's body.
type computeMonthlyAnswer struct {
	On            *bool         `json:"on"`
	Credits       int64         `json:"credits"`
	Market        ComputeMarket `json:"market"`
	PayerMemberId *Id           `json:"payer_member_id"`
}

// The modes an answer names, held to their shapes: a mode absent is off, an off reason is a code, never text, and no
// amount is negative.
func (self *computeAutoRenewAnswer) read(route string) (*ComputeAutoRenew, error) {
	autoRenew := &ComputeAutoRenew{
		Threshold: &ComputeThreshold{},
		Monthly:   &ComputeMonthly{},
	}
	if self == nil {
		return autoRenew, nil
	}
	if threshold := self.Threshold; threshold != nil {
		if threshold.On == nil {
			return nil, computeReplyError(route, "threshold without on")
		}
		if threshold.OffReason != "" && !isSidecarApiCode(threshold.OffReason) {
			return nil, computeReplyError(route, "threshold's off reason is not a code")
		}
		if threshold.BelowNanoUsd < 0 || threshold.PackCredits < 0 || threshold.MonthLimitNanoUsd < 0 ||
			threshold.TopUpsToday < 0 || threshold.FailuresToday < 0 || threshold.MonthNanoUsd < 0 {
			return nil, computeReplyError(route, "a negative threshold figure")
		}
		autoRenew.Threshold = &ComputeThreshold{
			On:                *threshold.On,
			BelowNanoUsd:      threshold.BelowNanoUsd,
			PackCredits:       threshold.PackCredits,
			MonthLimitNanoUsd: threshold.MonthLimitNanoUsd,
			OffReason:         threshold.OffReason,
			PayerMemberId:     computeIdCopy(threshold.PayerMemberId),
			TopUpsToday:       threshold.TopUpsToday,
			FailuresToday:     threshold.FailuresToday,
			MonthNanoUsd:      threshold.MonthNanoUsd,
		}
	}
	if monthly := self.Monthly; monthly != nil {
		if monthly.On == nil {
			return nil, computeReplyError(route, "monthly without on")
		}
		if monthly.Credits < 0 {
			return nil, computeReplyError(route, "a negative monthly plan")
		}
		if monthly.Market != 0 && monthly.Market != ComputeMarketStripe && monthly.Market != ComputeMarketAppStore &&
			monthly.Market != ComputeMarketGooglePlay {
			return nil, computeReplyError(route, "monthly's market")
		}
		autoRenew.Monthly = &ComputeMonthly{
			On:            *monthly.On,
			Credits:       monthly.Credits,
			Market:        monthly.Market,
			PayerMemberId: computeIdCopy(monthly.PayerMemberId),
		}
	}
	return autoRenew, nil
}

// A copy of an optional id.
func computeIdCopy(id *Id) *Id {
	if id == nil {
		return nil
	}
	copied := *id
	return &copied
}

// GET /compute/balance (§14.3): the token's network's balance as the caller may see it. Never the packet path.
func (self *SidecarApi) ComputeBalance(ctx context.Context) (*ComputeBalance, error) {
	answer := &computeBalanceAnswer{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computeBalanceRoute,
		operation: "compute_balance",
		method:    "GET",
		url:       self.computeUrl("/compute/balance", nil),
		bearer:    true,
	}, nil, answer)
	if err != nil {
		return nil, err
	}
	if answer.AvailableNanoUsd == nil || answer.HeldNanoUsd == nil || answer.BalanceNanoUsd == nil || answer.State == nil ||
		answer.Version == nil || answer.MayBuy == nil || answer.SalesOpen == nil || answer.UpdateTimeMs == nil {
		return nil, computeReplyError(computeBalanceRoute, "a required field is absent")
	}
	if !answer.State.Valid() {
		return nil, computeReplyError(computeBalanceRoute, "a state §9.9 does not name")
	}
	if *answer.HeldNanoUsd < 0 || answer.PromoNanoUsd < 0 || *answer.UpdateTimeMs < 0 {
		return nil, computeReplyError(computeBalanceRoute, "a negative hold, promotion or time")
	}
	if answer.IndexerDaysLeft != nil && *answer.IndexerDaysLeft < 0 {
		return nil, computeReplyError(computeBalanceRoute, "a negative count of the indexer's days")
	}
	if self.computeSettings().AnswerMaxRowCount < len(answer.AtRiskEnclaveIds) {
		return nil, computeReplyError(computeBalanceRoute, "past %d enclaves", self.computeSettings().AnswerMaxRowCount)
	}
	autoRenew, err := answer.AutoRenew.read(computeBalanceRoute)
	if err != nil {
		return nil, err
	}
	balance := &ComputeBalance{
		AvailableNanoUsd: *answer.AvailableNanoUsd,
		HeldNanoUsd:      *answer.HeldNanoUsd,
		BalanceNanoUsd:   *answer.BalanceNanoUsd,
		PromoNanoUsd:     answer.PromoNanoUsd,
		State:            *answer.State,
		Version:          *answer.Version,
		AutoRenew:        autoRenew,
		MayBuy:           *answer.MayBuy,
		SalesOpen:        *answer.SalesOpen,
		AtRiskEnclaveIds: slices.Clone(answer.AtRiskEnclaveIds),
		IndexerDaysLeft:  answer.IndexerDaysLeft,
		UpdateTime:       computeTimeOf(*answer.UpdateTimeMs),
	}
	if balance.AtRiskEnclaveIds == nil {
		balance.AtRiskEnclaveIds = []Id{}
	}
	return balance, nil
}

// Whether a Checkout url is one a surface may open: https, a host CheckoutHosts names, no user, within the bound.
func computeCheckoutUrlValid(checkoutUrl string, settings *ComputeClientSettings) bool {
	if checkoutUrl == "" || settings.CheckoutUrlMaxByteCount < len(checkoutUrl) {
		return false
	}
	parsed, err := url.Parse(checkoutUrl)
	if err != nil || parsed.Scheme != computeCheckoutSchemeHttps || parsed.User != nil || parsed.Opaque != "" {
		return false
	}
	return slices.Contains(settings.CheckoutHosts, parsed.Host)
}

// POST /compute/checkout (§9.5, §14.3): a Checkout session for args, whose url a surface opens in the person's
// browser. A pack must be one of §9.5's, a monthly plan one of §9.8's, and threshold rides a pack; the server refuses
// a caller who may not buy, closed sales and a purchase past the limits.
func (self *SidecarApi) ComputeCheckout(ctx context.Context, args *ComputeCheckoutArgs) (*ComputeCheckout, error) {
	settings := self.computeSettings()
	if args == nil {
		return nil, computeArgsError(computeCheckoutRoute, "no purchase")
	}
	switch args.AutoRenew {
	case "", ComputeAutoRenewThreshold:
		if !slices.Contains(settings.StripePackCredits, args.PackCredits) {
			return nil, computeArgsError(computeCheckoutRoute, "a pack is one of %v credits", settings.StripePackCredits)
		}
		if args.MonthlyCredits != 0 {
			return nil, computeArgsError(computeCheckoutRoute, "a monthly plan without the monthly mode")
		}
		if args.AutoRenew == "" && (args.BelowNanoUsd != 0 || args.TopUpPackCredits != 0 || args.MonthLimitNanoUsd != 0) {
			return nil, computeArgsError(computeCheckoutRoute, "threshold settings without the threshold mode")
		}
		if args.BelowNanoUsd < 0 || args.TopUpPackCredits < 0 || args.MonthLimitNanoUsd < 0 {
			return nil, computeArgsError(computeCheckoutRoute, "a negative threshold")
		}
	case ComputeAutoRenewMonthly:
		if args.PackCredits != 0 || args.BelowNanoUsd != 0 || args.TopUpPackCredits != 0 || args.MonthLimitNanoUsd != 0 {
			return nil, computeArgsError(computeCheckoutRoute, "the monthly plan opens alone")
		}
		if !slices.Contains(settings.MonthlyPlanCredits, args.MonthlyCredits) {
			return nil, computeArgsError(computeCheckoutRoute, "a monthly plan is one of %v credits", settings.MonthlyPlanCredits)
		}
	default:
		return nil, computeArgsError(computeCheckoutRoute, "an auto-renew mode is threshold or monthly")
	}
	answer := struct {
		Url          *string `json:"url"`
		ExpireTimeMs *int64  `json:"expire_time_ms"`
	}{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computeCheckoutRoute,
		operation: "compute_checkout",
		method:    "POST",
		url:       self.computeUrl("/compute/checkout", nil),
		bearer:    true,
	}, args, &answer)
	if err != nil {
		return nil, err
	}
	if answer.Url == nil || answer.ExpireTimeMs == nil || *answer.ExpireTimeMs <= 0 {
		return nil, computeReplyError(computeCheckoutRoute, "no url or expiry")
	}
	if !computeCheckoutUrlValid(*answer.Url, settings) {
		return nil, computeReplyError(computeCheckoutRoute, "a url that is not Checkout's")
	}
	return &ComputeCheckout{Url: *answer.Url, ExpireTime: computeTimeOf(*answer.ExpireTimeMs)}, nil
}

// GET /compute/auto-renew (§9.8, §14.3).
func (self *SidecarApi) ComputeAutoRenew(ctx context.Context) (*ComputeAutoRenew, error) {
	answer := &computeAutoRenewAnswer{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computeAutoRenewRoute,
		operation: "compute_auto_renew",
		method:    "GET",
		url:       self.computeUrl("/compute/auto-renew", nil),
		bearer:    true,
	}, nil, answer)
	if err != nil {
		return nil, err
	}
	return answer.read(computeAutoRenewRoute)
}

// POST /compute/auto-renew (§9.8, §14.3): one mode's change, answered with both modes as they now stand. A mode
// turned on must name a card the person turning it on saved for it, which api checks (card_required otherwise).
func (self *SidecarApi) ComputeSetAutoRenew(ctx context.Context, change *ComputeAutoRenewChange) (*ComputeAutoRenew, error) {
	settings := self.computeSettings()
	if change == nil {
		return nil, computeArgsError(computeSetAutoRenewRoute, "no change")
	}
	switch change.Mode {
	case ComputeAutoRenewThreshold:
		if change.Credits != 0 {
			return nil, computeArgsError(computeSetAutoRenewRoute, "a monthly plan on the threshold mode")
		}
		if change.BelowNanoUsd < 0 || change.PackCredits < 0 || change.MonthLimitNanoUsd < 0 {
			return nil, computeArgsError(computeSetAutoRenewRoute, "a negative threshold")
		}
	case ComputeAutoRenewMonthly:
		if change.BelowNanoUsd != 0 || change.PackCredits != 0 || change.MonthLimitNanoUsd != 0 {
			return nil, computeArgsError(computeSetAutoRenewRoute, "threshold settings on the monthly mode")
		}
		if change.Credits != 0 && !slices.Contains(settings.MonthlyPlanCredits, change.Credits) {
			return nil, computeArgsError(computeSetAutoRenewRoute, "a monthly plan is one of %v credits", settings.MonthlyPlanCredits)
		}
	default:
		return nil, computeArgsError(computeSetAutoRenewRoute, "a mode is threshold or monthly")
	}
	answer := &computeAutoRenewAnswer{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computeSetAutoRenewRoute,
		operation: "compute_set_auto_renew",
		method:    "POST",
		url:       self.computeUrl("/compute/auto-renew", nil),
		bearer:    true,
	}, change, answer)
	if err != nil {
		return nil, err
	}
	return answer.read(computeSetAutoRenewRoute)
}

// Whether cursor is one a page may carry: the url-safe alphabet, within the settings' bound.
func computeCursorValid(cursor string, settings *ComputeClientSettings) bool {
	if settings.CursorMaxByteCount < len(cursor) {
		return false
	}
	for i := 0; i < len(cursor); i += 1 {
		if strings.IndexByte(computeCursorAlphabet, cursor[i]) < 0 {
			return false
		}
	}
	return true
}

// One charge row's body.
type computeChargeAnswer struct {
	ChargeId        *Id                `json:"charge_id"`
	Kind            *ComputeChargeKind `json:"kind"`
	SubjectRef      *Id                `json:"subject_ref"`
	SidecarId       *Id                `json:"sidecar_id"`
	AgentId         *Id                `json:"agent_id"`
	MemberId        *Id                `json:"member_id"`
	EnclaveId       *Id                `json:"enclave_id"`
	CatalogId       string             `json:"catalog_id"`
	Provider        *int16             `json:"provider"`
	Units           ComputeUnits       `json:"units"`
	AmountNanoUsd   *int64             `json:"amount_nano_usd"`
	AbsorbedNanoUsd int64              `json:"absorbed_nano_usd"`
	StartTimeMs     *int64             `json:"start_time_ms"`
	EndTimeMs       *int64             `json:"end_time_ms"`
	SettleTimeMs    *int64             `json:"settle_time_ms"`
}

// GET /compute/charges (§9.10, §14.3): one page of the charges the caller may see, from cursor ("" for the first),
// at most ChargesPageRowCount rows.
func (self *SidecarApi) ComputeCharges(ctx context.Context, cursor string) (*ComputeCharges, error) {
	settings := self.computeSettings()
	if !computeCursorValid(cursor, settings) {
		return nil, computeArgsError(computeChargesRoute, "a cursor no page answered")
	}
	query := url.Values{"limit": []string{strconv.Itoa(settings.ChargesPageRowCount)}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	answer := struct {
		Charges    []*computeChargeAnswer `json:"charges"`
		NextCursor string                 `json:"next_cursor"`
	}{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computeChargesRoute,
		operation: "compute_charges",
		method:    "GET",
		url:       self.computeUrl("/compute/charges", query),
		bearer:    true,
	}, nil, &answer)
	if err != nil {
		return nil, err
	}
	if answer.Charges == nil || settings.AnswerMaxRowCount < len(answer.Charges) || !computeCursorValid(answer.NextCursor, settings) {
		return nil, computeReplyError(computeChargesRoute, "no charges, too many, or a cursor out of form")
	}
	charges := &ComputeCharges{Charges: []*ComputeChargeRow{}, NextCursor: answer.NextCursor}
	for index, row := range answer.Charges {
		if row == nil || row.ChargeId == nil || row.Kind == nil || row.SubjectRef == nil || row.SidecarId == nil ||
			row.Provider == nil || row.AmountNanoUsd == nil || row.StartTimeMs == nil || row.EndTimeMs == nil || row.SettleTimeMs == nil {
			return nil, computeReplyError(computeChargesRoute, "charge %d lacks a required field", index)
		}
		if !computeChargeKindValid(*row.Kind) || *row.Provider < 0 || row.AbsorbedNanoUsd < 0 {
			return nil, computeReplyError(computeChargesRoute, "charge %d's kind, provider or absorbed amount", index)
		}
		if row.CatalogId != "" && !computeCatalogIdValid(row.CatalogId, settings) {
			return nil, computeReplyError(computeChargesRoute, "charge %d's catalog id", index)
		}
		charges.Charges = append(charges.Charges, &ComputeChargeRow{
			ChargeId:        *row.ChargeId,
			Kind:            *row.Kind,
			SubjectRef:      *row.SubjectRef,
			SidecarId:       *row.SidecarId,
			AgentId:         computeIdCopy(row.AgentId),
			MemberId:        computeIdCopy(row.MemberId),
			EnclaveId:       computeIdCopy(row.EnclaveId),
			CatalogId:       row.CatalogId,
			Provider:        *row.Provider,
			Units:           row.Units,
			AmountNanoUsd:   *row.AmountNanoUsd,
			AbsorbedNanoUsd: row.AbsorbedNanoUsd,
			StartTime:       computeTimeOf(*row.StartTimeMs),
			EndTime:         computeTimeOf(*row.EndTimeMs),
			SettleTime:      computeTimeOf(*row.SettleTimeMs),
		})
	}
	return charges, nil
}

// One statement day row's body.
type computeStatementRowAnswer struct {
	Day             string             `json:"day"`
	Kind            *ComputeChargeKind `json:"kind"`
	SidecarId       *Id                `json:"sidecar_id"`
	AgentId         *Id                `json:"agent_id"`
	CatalogId       string             `json:"catalog_id"`
	MemberId        *Id                `json:"member_id"`
	Provider        *int16             `json:"provider"`
	EnclaveId       *Id                `json:"enclave_id"`
	Units           ComputeUnits       `json:"units"`
	AmountNanoUsd   *int64             `json:"amount_nano_usd"`
	RefundedNanoUsd int64              `json:"refunded_nano_usd"`
	Count           int64              `json:"count"`
}

// One statement lot's body.
type computeLotAnswer struct {
	LotId            *Id             `json:"lot_id"`
	Kind             *ComputeLotKind `json:"kind"`
	Market           *ComputeMarket  `json:"market"`
	AmountNanoUsd    *int64          `json:"amount_nano_usd"`
	RemainingNanoUsd int64           `json:"remaining_nano_usd"`
	CreateTimeMs     *int64          `json:"create_time_ms"`
	ExpireTimeMs     *int64          `json:"expire_time_ms"`
	ReversedTimeMs   *int64          `json:"reversed_time_ms"`
	LapsedNanoUsd    *int64          `json:"lapsed_nano_usd"`
}

// An optional time from optional Unix milliseconds.
func computeOptionalTimeOf(millis *int64) *time.Time {
	if millis == nil {
		return nil
	}
	timeOf := computeTimeOf(*millis)
	return &timeOf
}

// GET /compute/statement (§9.13, §14.3): month's day rows, by kind, model, enclave, member, agent and sidecar, and the
// lots bought or redeemed in it. month is YYYY-MM, UTC.
func (self *SidecarApi) ComputeStatement(ctx context.Context, month string) (*ComputeStatement, error) {
	settings := self.computeSettings()
	if !computeMonthValid(month) {
		return nil, computeArgsError(computeStatementRoute, "a month is YYYY-MM")
	}
	answer := struct {
		Month *string                      `json:"month"`
		Rows  []*computeStatementRowAnswer `json:"rows"`
		Lots  []*computeLotAnswer          `json:"lots"`
	}{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computeStatementRoute,
		operation: "compute_statement",
		method:    "GET",
		url:       self.computeUrl("/compute/statement", url.Values{"month": []string{month}}),
		bearer:    true,
	}, nil, &answer)
	if err != nil {
		return nil, err
	}
	if answer.Month == nil || *answer.Month != month || answer.Rows == nil || answer.Lots == nil ||
		settings.AnswerMaxRowCount < len(answer.Rows)+len(answer.Lots) {
		return nil, computeReplyError(computeStatementRoute, "another month, no rows or lots, or too many")
	}
	statement := &ComputeStatement{Month: month, Rows: []*ComputeStatementRow{}, Lots: []*ComputeLotRow{}}
	for index, row := range answer.Rows {
		if row == nil || !computeDayValid(row.Day) || !strings.HasPrefix(row.Day, month+"-") || row.Kind == nil ||
			row.SidecarId == nil || row.Provider == nil || row.AmountNanoUsd == nil {
			return nil, computeReplyError(computeStatementRoute, "row %d lacks a required field or is of another month", index)
		}
		if !computeChargeKindValid(*row.Kind) || *row.Provider < 0 || row.RefundedNanoUsd < 0 || row.Count < 0 {
			return nil, computeReplyError(computeStatementRoute, "row %d's kind, provider, refunds or count", index)
		}
		if row.CatalogId != "" && !computeCatalogIdValid(row.CatalogId, settings) {
			return nil, computeReplyError(computeStatementRoute, "row %d's catalog id", index)
		}
		statement.Rows = append(statement.Rows, &ComputeStatementRow{
			Day:             row.Day,
			Kind:            *row.Kind,
			SidecarId:       *row.SidecarId,
			AgentId:         computeIdCopy(row.AgentId),
			CatalogId:       row.CatalogId,
			MemberId:        computeIdCopy(row.MemberId),
			Provider:        *row.Provider,
			EnclaveId:       computeIdCopy(row.EnclaveId),
			Units:           row.Units,
			AmountNanoUsd:   *row.AmountNanoUsd,
			RefundedNanoUsd: row.RefundedNanoUsd,
			Count:           row.Count,
		})
	}
	for index, lot := range answer.Lots {
		if lot == nil || lot.LotId == nil || lot.Kind == nil || lot.Market == nil || lot.AmountNanoUsd == nil || lot.CreateTimeMs == nil {
			return nil, computeReplyError(computeStatementRoute, "lot %d lacks a required field", index)
		}
		if *lot.Kind < ComputeLotKindPurchase || ComputeLotKindAdjustment < *lot.Kind ||
			*lot.Market < ComputeMarketStripe || ComputeMarketPromotion < *lot.Market {
			return nil, computeReplyError(computeStatementRoute, "lot %d's kind or market", index)
		}
		if *lot.AmountNanoUsd < 0 || lot.RemainingNanoUsd < 0 || (lot.LapsedNanoUsd != nil && *lot.LapsedNanoUsd < 0) {
			return nil, computeReplyError(computeStatementRoute, "lot %d's amounts", index)
		}
		var lapsed *int64
		if lot.LapsedNanoUsd != nil {
			value := *lot.LapsedNanoUsd
			lapsed = &value
		}
		statement.Lots = append(statement.Lots, &ComputeLotRow{
			LotId:            *lot.LotId,
			Kind:             *lot.Kind,
			Market:           *lot.Market,
			AmountNanoUsd:    *lot.AmountNanoUsd,
			RemainingNanoUsd: lot.RemainingNanoUsd,
			CreateTime:       computeTimeOf(*lot.CreateTimeMs),
			ExpireTime:       computeOptionalTimeOf(lot.ExpireTimeMs),
			ReversedTime:     computeOptionalTimeOf(lot.ReversedTimeMs),
			LapsedNanoUsd:    lapsed,
		})
	}
	return statement, nil
}

// One spend figure's body.
type computeSpendFiguresAnswer struct {
	AmountNanoUsd   *int64       `json:"amount_nano_usd"`
	RefundedNanoUsd int64        `json:"refunded_nano_usd"`
	Count           int64        `json:"count"`
	Units           ComputeUnits `json:"units"`
}

// The figures, refusing an absent amount or a negative refund or count.
func (self *computeSpendFiguresAnswer) read() (*ComputeSpendFigures, bool) {
	if self == nil || self.AmountNanoUsd == nil || self.RefundedNanoUsd < 0 || self.Count < 0 {
		return nil, false
	}
	return &ComputeSpendFigures{
		AmountNanoUsd:   *self.AmountNanoUsd,
		RefundedNanoUsd: self.RefundedNanoUsd,
		Count:           self.Count,
		Units:           self.Units,
	}, true
}

// A line's days, exactly dayCount of them.
func computeSpendDaysOf(days []*computeSpendFiguresAnswer, dayCount int) ([]*ComputeSpendFigures, bool) {
	if len(days) != dayCount {
		return nil, false
	}
	figures := make([]*ComputeSpendFigures, 0, dayCount)
	for _, day := range days {
		figure, ok := day.read()
		if !ok {
			return nil, false
		}
		figures = append(figures, figure)
	}
	return figures, true
}

// One spend row's body.
type computeSpendRowAnswer struct {
	Provider  *int16                       `json:"provider"`
	CatalogId *string                      `json:"catalog_id"`
	EnclaveId *Id                          `json:"enclave_id"`
	MemberId  *Id                          `json:"member_id"`
	AgentId   *Id                          `json:"agent_id"`
	Total     *computeSpendFiguresAnswer   `json:"total"`
	Days      []*computeSpendFiguresAnswer `json:"days"`
}

// One spend line's body.
type computeSpendLineAnswer struct {
	Kind  *ComputeChargeKind           `json:"kind"`
	Total *computeSpendFiguresAnswer   `json:"total"`
	Days  []*computeSpendFiguresAnswer `json:"days"`
	Rows  []*computeSpendRowAnswer     `json:"rows"`
}

// The row by by, held to its key: by provider a code alone, by model a catalog id or none, by enclave an enclave or
// none, by member a member or the network's own line, by agent an agent or none with its member, and no total.
func (self *computeSpendRowAnswer) read(by ComputeSpendBy, dayCount int, settings *ComputeClientSettings) (*ComputeSpendRow, bool) {
	if self == nil {
		return nil, false
	}
	row := &ComputeSpendRow{}
	switch by {
	case ComputeSpendByProvider:
		if self.Provider == nil || *self.Provider < 0 || self.CatalogId != nil || self.EnclaveId != nil || self.MemberId != nil || self.AgentId != nil {
			return nil, false
		}
		provider := *self.Provider
		row.Provider = &provider
	case ComputeSpendByModel:
		if self.Provider != nil || self.EnclaveId != nil || self.MemberId != nil || self.AgentId != nil {
			return nil, false
		}
		if self.CatalogId != nil {
			if !computeCatalogIdValid(*self.CatalogId, settings) {
				return nil, false
			}
			catalogId := *self.CatalogId
			row.CatalogId = &catalogId
		}
	case ComputeSpendByEnclave:
		if self.Provider != nil || self.CatalogId != nil || self.MemberId != nil || self.AgentId != nil {
			return nil, false
		}
		row.EnclaveId = computeIdCopy(self.EnclaveId)
	case ComputeSpendByMember:
		if self.Provider != nil || self.CatalogId != nil || self.EnclaveId != nil || self.AgentId != nil {
			return nil, false
		}
		row.MemberId = computeIdCopy(self.MemberId)
	case ComputeSpendByAgent:
		if self.Provider != nil || self.CatalogId != nil || self.EnclaveId != nil || self.Total != nil {
			return nil, false
		}
		row.AgentId = computeIdCopy(self.AgentId)
		row.MemberId = computeIdCopy(self.MemberId)
	default:
		return nil, false
	}
	if by != ComputeSpendByAgent {
		total, ok := self.Total.read()
		if !ok {
			return nil, false
		}
		row.Total = total
	}
	days, ok := computeSpendDaysOf(self.Days, dayCount)
	if !ok {
		return nil, false
	}
	row.Days = days
	return row, true
}

// GET /compute/spend (§9.13, §14.3): the spend view as the caller's role sees it, broken down by by. The window is
// SpendDayCount consecutive UTC days, oldest first; each line a charge kind at most once, with a total, a figure for
// each day, and rows by by.
func (self *SidecarApi) ComputeSpend(ctx context.Context, by ComputeSpendBy) (*ComputeSpend, error) {
	settings := self.computeSettings()
	if _, err := ParseComputeSpendBy(string(by)); err != nil {
		return nil, computeArgsError(computeSpendRoute, "a breakdown is provider, model, enclave, member or agent")
	}
	var query url.Values
	if by != ComputeSpendByNone {
		query = url.Values{"by": []string{string(by)}}
	}
	answer := struct {
		By             *ComputeSpendBy           `json:"by"`
		Days           []string                  `json:"days"`
		FirstChargeDay string                    `json:"first_charge_day"`
		HeldNanoUsd    *int64                    `json:"held_nano_usd"`
		UpdateTimeMs   *int64                    `json:"update_time_ms"`
		Lines          []*computeSpendLineAnswer `json:"lines"`
	}{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computeSpendRoute,
		operation: "compute_spend",
		method:    "GET",
		url:       self.computeUrl("/compute/spend", query),
		bearer:    true,
	}, nil, &answer)
	if err != nil {
		return nil, err
	}
	if answer.By == nil || *answer.By != by || answer.HeldNanoUsd == nil || *answer.HeldNanoUsd < 0 ||
		answer.UpdateTimeMs == nil || *answer.UpdateTimeMs < 0 || answer.Lines == nil {
		return nil, computeReplyError(computeSpendRoute, "another breakdown, or a required field absent or negative")
	}
	if len(answer.Days) != settings.SpendDayCount {
		return nil, computeReplyError(computeSpendRoute, "%d days, not %d", len(answer.Days), settings.SpendDayCount)
	}
	for index, day := range answer.Days {
		if !computeDayValid(day) {
			return nil, computeReplyError(computeSpendRoute, "day %d is not a UTC day", index)
		}
		if 0 < index {
			previous, _ := time.ParseInLocation(computeDayLayout, answer.Days[index-1], time.UTC)
			if previous.AddDate(0, 0, 1).Format(computeDayLayout) != day {
				return nil, computeReplyError(computeSpendRoute, "day %d does not follow the day before it", index)
			}
		}
	}
	if answer.FirstChargeDay != "" && !computeDayValid(answer.FirstChargeDay) {
		return nil, computeReplyError(computeSpendRoute, "the first charge day is not a UTC day")
	}
	rowCount := 0
	for _, line := range answer.Lines {
		if line != nil {
			rowCount += len(line.Rows)
		}
	}
	if settings.AnswerMaxRowCount < len(answer.Lines)+rowCount {
		return nil, computeReplyError(computeSpendRoute, "past %d rows", settings.AnswerMaxRowCount)
	}
	spend := &ComputeSpend{
		By:             by,
		Days:           slices.Clone(answer.Days),
		FirstChargeDay: answer.FirstChargeDay,
		HeldNanoUsd:    *answer.HeldNanoUsd,
		UpdateTime:     computeTimeOf(*answer.UpdateTimeMs),
		Lines:          []*ComputeSpendLine{},
	}
	kinds := []ComputeChargeKind{}
	for index, line := range answer.Lines {
		if line == nil || line.Kind == nil || !computeChargeKindValid(*line.Kind) || slices.Contains(kinds, *line.Kind) {
			return nil, computeReplyError(computeSpendRoute, "line %d's kind is absent, unknown or repeated", index)
		}
		kinds = append(kinds, *line.Kind)
		total, ok := line.Total.read()
		if !ok {
			return nil, computeReplyError(computeSpendRoute, "line %d's total", index)
		}
		days, ok := computeSpendDaysOf(line.Days, settings.SpendDayCount)
		if !ok {
			return nil, computeReplyError(computeSpendRoute, "line %d's days", index)
		}
		if by == ComputeSpendByNone && len(line.Rows) != 0 {
			return nil, computeReplyError(computeSpendRoute, "line %d has rows and no breakdown was asked", index)
		}
		rows := []*ComputeSpendRow{}
		for rowIndex, rowAnswer := range line.Rows {
			row, ok := rowAnswer.read(by, settings.SpendDayCount, settings)
			if !ok {
				return nil, computeReplyError(computeSpendRoute, "line %d's row %d is not a %s row", index, rowIndex, by)
			}
			rows = append(rows, row)
		}
		spend.Lines = append(spend.Lines, &ComputeSpendLine{Kind: *line.Kind, Total: total, Days: days, Rows: rows})
	}
	return spend, nil
}

// POST /compute/refund (§9.12, §14.3): the unspent part of a Stripe lot back to its card, within 30 days of its
// purchase; an Owner's or a Billing admin's.
func (self *SidecarApi) ComputeRefund(ctx context.Context, lotId Id) (*ComputeRefund, error) {
	if lotId == (Id{}) {
		return nil, computeArgsError(computeRefundRoute, "no lot")
	}
	answer := struct {
		LotId           *Id    `json:"lot_id"`
		RefundedNanoUsd *int64 `json:"refunded_nano_usd"`
	}{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computeRefundRoute,
		operation: "compute_refund",
		method:    "POST",
		url:       self.computeUrl("/compute/refund", nil),
		bearer:    true,
	}, map[string]Id{"lot_id": lotId}, &answer)
	if err != nil {
		return nil, err
	}
	if answer.LotId == nil || *answer.LotId != lotId || answer.RefundedNanoUsd == nil || *answer.RefundedNanoUsd < 0 {
		return nil, computeReplyError(computeRefundRoute, "another lot, or no refunded amount")
	}
	return &ComputeRefund{LotId: lotId, RefundedNanoUsd: *answer.RefundedNanoUsd}, nil
}

// Whether code is a promotion code's form (§9.11): letters and digits, within the settings' bounds.
func computePromoCodeValid(code string, settings *ComputeClientSettings) bool {
	if len(code) < settings.PromoCodeMinCharacterCount || settings.PromoCodeMaxCharacterCount < len(code) {
		return false
	}
	for i := 0; i < len(code); i += 1 {
		c := code[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// POST /compute/promo/redeem (§9.11, §14.3): one promotion code for the token's network. A refusal names its reason
// in its code (code_unknown, code_ended, code_redeemed, redeemed_recently, paid_lot_required, daily_limit,
// balance_cap, rate_limited); a retry of a redemption that went answers its lot again. The code is sent and never
// logged.
func (self *SidecarApi) ComputePromoRedeem(ctx context.Context, code string) (*ComputeRedemption, error) {
	if !computePromoCodeValid(code, self.computeSettings()) {
		return nil, computeArgsError(computePromoRedeemRoute, "a code is %d to %d letters and digits",
			self.computeSettings().PromoCodeMinCharacterCount, self.computeSettings().PromoCodeMaxCharacterCount)
	}
	answer := struct {
		LotId         *Id    `json:"lot_id"`
		CreditNanoUsd *int64 `json:"credit_nano_usd"`
		ExpireTimeMs  *int64 `json:"expire_time_ms"`
	}{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     computePromoRedeemRoute,
		operation: "compute_promo_redeem",
		method:    "POST",
		url:       self.computeUrl("/compute/promo/redeem", nil),
		bearer:    true,
	}, map[string]string{"code": code}, &answer)
	if err != nil {
		return nil, err
	}
	if answer.LotId == nil || *answer.LotId == (Id{}) || answer.CreditNanoUsd == nil || *answer.CreditNanoUsd <= 0 ||
		answer.ExpireTimeMs == nil || *answer.ExpireTimeMs <= 0 {
		return nil, computeReplyError(computePromoRedeemRoute, "no lot, credit or expiry")
	}
	return &ComputeRedemption{
		LotId:         *answer.LotId,
		CreditNanoUsd: *answer.CreditNanoUsd,
		ExpireTime:    computeTimeOf(*answer.ExpireTimeMs),
	}, nil
}

// The refusal code err carries, a *SidecarApiError's, or "" for none: what a surface shows with its fix.
func ComputeRefusalCodeOf(err error) string {
	var apiErr *SidecarApiError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return ""
}
