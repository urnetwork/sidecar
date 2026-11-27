// Auto-renew (DESIGN-COMPUTE §9.5, §9.8, §14.3, §14.5, D-BAL-9, CF-5; BAL-M12-11): §9.8's two modes per network, set
// by a person who may buy (the route's frame checks §9.10), each charging only a card its own holder saved for it.
//
//	threshold  when the balance, holds left out (D-BAL-9), falls below T, an off-session PaymentIntent for pack P on the
//	           card its payer saved, at most the settings' 3 a UTC day and L a calendar month, Stripe only. A failure
//	           retries after 1 h and 6 h and emails the billing contacts each time; the third turns threshold off. An
//	           authentication_required answer emails a link and turns threshold off until its holder buys again with
//	           it on. Before each charge the payer is checked to be a member whose role or grant still lets them buy,
//	           and otherwise their card is detached, which stops threshold until another is saved.
//	monthly    M credits each month: a Stripe subscription made by Checkout in subscription mode, its invoice.paid
//	           crediting a kind-2 lot under the invoice's PaymentIntent; unused credits carry over.
//
// What runs here, and who calls it:
//
//	ComputeAutoRenew            both modes as they stand: GET api/compute/auto-renew, and the balance route
//	ComputeSetAutoRenew         one mode's change: POST api/compute/auto-renew; a mode turned on, or threshold's
//	                            figures changed, by anyone but the card's own holder is refused card_required, so no
//	                            one's change charges another person's card (R1-31); turning one off cancels only what
//	                            was not yet sent to Stripe
//	ComputeAutoRenewRun         compute_auto_renew, every minute: the networks with threshold on, by an indexed cursor,
//	                            each charged at most once a run under an idempotency key of network, UTC day, attempt
//	                            and pack, so a retried run charges once
//	ComputeTopUpCredit          a top-up's money final, from the job's own answer or the webhook's
//	                            payment_intent.succeeded: its lot credited once by its PaymentIntent, and the day's and
//	                            month's counts moved in the same transaction, so whichever comes first counts it
//	ComputeMonthlySubscribed    the webhook's checkout.session.completed of the plan's subscription
//	ComputeMonthlyGrant         the webhook's invoice.paid: the month's lot
//	ComputeMonthlyEnded         the webhook's customer.subscription.deleted
//	ComputeMonthlyPaymentFailed the webhook's invoice.payment_failed: the billing contacts told, Stripe's own billing
//	                            retry following
//
// It registers at init BAL-M12-08's two seams, so a pack's checkout with threshold turned on saves its payer's card
// (RegisterComputeAutoRenewCards) and the monthly plan opens through Checkout (RegisterComputeMonthlyCheckout). Stripe's
// API is the host's (ComputeStripeRenew, server's ComputeServerStripe), and whether a payer may still buy is the host's
// too (ComputeAutoRenewPayers); a host that registered neither charges no card: every threshold run waits, failing
// closed. A call that costs a cent fires no top-up, since the balance leaves holds out (R1-33).

package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// Why a change of auto-renew was refused (§9.8, §14.3), as the device's client reads its code.
type ComputeAutoRenewRefusal string

const (
	// A mode turned on, or threshold's figures changed, names no card the person changing it saved for it: they buy a
	// pack with threshold turned on, or open the monthly plan, which saves their own (§9.5).
	ComputeAutoRenewRefusalCardRequired ComputeAutoRenewRefusal = "card_required"
	// The monthly plan runs on a store, which keeps its own subscription: its person changes it there (§9.5).
	ComputeAutoRenewRefusalStoreSubscription ComputeAutoRenewRefusal = "store_subscription"
	// A change of a running Stripe plan's credits: a plan change on Stripe's subscription, not built in this draft.
	ComputeAutoRenewRefusalNotBuilt ComputeAutoRenewRefusal = "not_built"
	// The monthly plan is on already: a second subscription would grant twice.
	ComputeAutoRenewRefusalMonthlyOn ComputeAutoRenewRefusal = "monthly_on"
)

var (
	// An auto-renew change or record the ledger cannot take: a mode §9.8 does not name, a figure out of its bounds.
	ErrComputeAutoRenewArgs = errors.New("compute auto-renew: arguments refused")
	// The host registered no Stripe for auto-renew: no top-up, plan or cancellation reaches Stripe (fails closed).
	ErrComputeStripeRenewUnavailable = errors.New("compute auto-renew: this host holds no Stripe for auto-renew")
)

// One off-session charge of a saved card (§9.8): a PaymentIntent with confirm=true and off_session=true.
type ComputeOffSessionCharge struct {
	NetworkId     operator.Id
	PayerMemberId operator.Id
	// The payer's Stripe customer for this network and member, and the card they saved on it.
	StripeCustomerId      string
	StripePaymentMethodId string
	// The pack P, in credits, and its price, a credit a dollar.
	PackCredits   int64
	AmountNanoUsd int64
	// The charge's idempotency key at Stripe: of network, UTC day, attempt and pack (computeTopUpKey).
	IdempotencyKey string
}

// What an off-session charge came to.
type ComputeOffSessionOutcome string

const (
	// The money is final: the lot is credited.
	ComputeOffSessionSucceeded ComputeOffSessionOutcome = "succeeded"
	// Not final yet: payment_intent.succeeded credits it, and the job waits a retry's interval.
	ComputeOffSessionProcessing ComputeOffSessionOutcome = "processing"
	// The card's bank asks for its holder: threshold turns off and a link is mailed.
	ComputeOffSessionAuthenticationRequired ComputeOffSessionOutcome = "authentication_required"
	// Declined, or the card is gone: a failure, retried.
	ComputeOffSessionFailed ComputeOffSessionOutcome = "failed"
)

// An off-session charge's answer.
type ComputeOffSessionAnswer struct {
	Outcome         ComputeOffSessionOutcome
	PaymentIntentId string
}

// The monthly plan's Checkout in subscription mode (§9.8): M credits a month, a credit a dollar, tax added by Stripe Tax.
type ComputeStripeMonthlyRequest struct {
	NetworkId operator.Id
	MemberId  operator.Id
	Credits   int64
	// The month's price before tax.
	AmountNanoUsd int64
}

// The host's Stripe for auto-renew (server's ComputeServerStripe). Implementations are safe for concurrent use.
type ComputeStripeRenew interface {
	// The fingerprint of a saved card, which the payer's keyed hash is made from; "" for a payment method that is no
	// card.
	CardFingerprint(ctx context.Context, paymentMethodId string) (string, error)
	// Charges a saved card off-session under the charge's idempotency key.
	ChargeOffSession(ctx context.Context, charge *ComputeOffSessionCharge) (*ComputeOffSessionAnswer, error)
	// Makes the monthly plan's Checkout session in subscription mode on the customer of its network and member.
	MonthlyCheckout(ctx context.Context, request *ComputeStripeMonthlyRequest) (*ComputeStripeCheckoutSession, error)
	// Cancels a subscription, so no invoice follows; one already cancelled is no error.
	CancelSubscription(ctx context.Context, subscriptionId string) error
	// Detaches a saved card from its customer; one already detached is no error.
	DetachCard(ctx context.Context, paymentMethodId string) error
}

// Whether a payer may still buy (§9.10): the host's reading of the network's roles and grants.
type ComputeAutoRenewPayers interface {
	// Whether memberId is still a member of networkId whose role or grant lets them buy.
	MayBuy(env operator.Env, ctx context.Context, networkId operator.Id, memberId operator.Id) (bool, error)
}

var (
	computeAutoRenewLock   sync.Mutex
	computeStripeRenew     ComputeStripeRenew
	computeAutoRenewPayers ComputeAutoRenewPayers
)

// Registers the host's Stripe for auto-renew, once a process. A second registration, or a nil one, panics.
func RegisterComputeStripeRenew(renew ComputeStripeRenew) {
	if renew == nil {
		panic("compute auto-renew: nil Stripe")
	}
	computeAutoRenewLock.Lock()
	defer computeAutoRenewLock.Unlock()
	if computeStripeRenew != nil {
		panic("compute auto-renew: the Stripe is registered once")
	}
	computeStripeRenew = renew
}

// Registers the host's payer check, once a process. A second registration, or a nil one, panics.
func RegisterComputeAutoRenewPayers(payers ComputeAutoRenewPayers) {
	if payers == nil {
		panic("compute auto-renew: nil payers")
	}
	computeAutoRenewLock.Lock()
	defer computeAutoRenewLock.Unlock()
	if computeAutoRenewPayers != nil {
		panic("compute auto-renew: the payers are registered once")
	}
	computeAutoRenewPayers = payers
}

// The registered Stripe for auto-renew, nil until registered.
func ComputeRegisteredStripeRenew() ComputeStripeRenew {
	computeAutoRenewLock.Lock()
	defer computeAutoRenewLock.Unlock()
	return computeStripeRenew
}

// The registered payer check, nil until registered.
func ComputeRegisteredAutoRenewPayers() ComputeAutoRenewPayers {
	computeAutoRenewLock.Lock()
	defer computeAutoRenewLock.Unlock()
	return computeAutoRenewPayers
}

func init() {
	RegisterComputeAutoRenewCards(computeAutoRenewCardTaker{})
	RegisterComputeMonthlyCheckout(computeMonthlyCheckoutTaker{})
}

// Threshold's T, P and L in force for a row, each the row's or the settings' default.
type computeThresholdFigures struct {
	belowNanoUsd      int64
	packCredits       int64
	monthLimitNanoUsd int64
}

// The most a top-up's pack may be, in credits: the largest Stripe pack. A reading: §9.8 bounds P by L alone.
func computeThresholdPackMax(settings *model.ComputeLedgerSettings) int64 {
	if len(settings.StripePackCredits) == 0 {
		return 0
	}
	return slices.Max(settings.StripePackCredits)
}

// Threshold's figures from the given ones, zero taking fallback's: within their bounds (T and L at most the balance
// cap, P a positive count of credits up to the largest pack, L at least one P), or ErrComputeAutoRenewArgs.
func computeThresholdFiguresOf(settings *model.ComputeLedgerSettings, fallback *computeThresholdFigures, below int64, pack int64, limit int64) (*computeThresholdFigures, error) {
	figures := *fallback
	if below != 0 {
		figures.belowNanoUsd = below
	}
	if pack != 0 {
		figures.packCredits = pack
	}
	if limit != 0 {
		figures.monthLimitNanoUsd = limit
	}
	if figures.belowNanoUsd < 0 || settings.BalanceCapNanoUsd < figures.belowNanoUsd ||
		figures.packCredits <= 0 || computeThresholdPackMax(settings) < figures.packCredits ||
		figures.monthLimitNanoUsd < figures.packCredits*model.ComputeCreditNanoUsd || settings.BalanceCapNanoUsd < figures.monthLimitNanoUsd {
		return nil, fmt.Errorf("%w: threshold's T, P and L are out of their bounds", ErrComputeAutoRenewArgs)
	}
	return &figures, nil
}

// The settings' default figures.
func computeThresholdDefaults(settings *model.ComputeLedgerSettings) *computeThresholdFigures {
	return &computeThresholdFigures{
		belowNanoUsd:      settings.ThresholdBelowNanoUsd,
		packCredits:       settings.ThresholdPackCredits,
		monthLimitNanoUsd: settings.ThresholdMonthLimitNanoUsd,
	}
}

// The figures a threshold row holds, the defaults where it holds none.
func computeThresholdFiguresOfRow(settings *model.ComputeLedgerSettings, row *model.ComputeAutoRenew) *computeThresholdFigures {
	figures := computeThresholdDefaults(settings)
	if row == nil {
		return figures
	}
	if row.BelowNanoUsd != nil {
		figures.belowNanoUsd = *row.BelowNanoUsd
	}
	if row.PackCredits != nil {
		figures.packCredits = *row.PackCredits
	}
	if row.MonthLimitNanoUsd != nil {
		figures.monthLimitNanoUsd = *row.MonthLimitNanoUsd
	}
	return figures
}

// Writes figures into row.
func (self *computeThresholdFigures) into(row *model.ComputeAutoRenew) {
	below, pack, limit := self.belowNanoUsd, self.packCredits, self.monthLimitNanoUsd
	row.BelowNanoUsd, row.PackCredits, row.MonthLimitNanoUsd = &below, &pack, &limit
}

// A threshold row's counts as they stand at now: the day's top-ups and failures and the month's sum, each zero once its
// UTC day or month has passed.
type computeThresholdCounts struct {
	topUpsToday   int32
	failuresToday int32
	monthNanoUsd  int64
}

func computeThresholdCountsOf(row *model.ComputeAutoRenew, now time.Time) *computeThresholdCounts {
	counts := &computeThresholdCounts{}
	if row == nil {
		return counts
	}
	if row.TopUpDay != nil && row.TopUpDay.Equal(model.ComputeUtcDay(now)) {
		counts.topUpsToday = row.TopUpDayCount
		counts.failuresToday = row.FailureDayCount
	}
	if row.TopUpMonth != nil && row.TopUpMonth.Equal(model.ComputeUtcMonth(now)) {
		counts.monthNanoUsd = row.TopUpMonthNanoUsd
	}
	return counts
}

// Writes counts into row as of now's UTC day and month.
func (self *computeThresholdCounts) into(row *model.ComputeAutoRenew, now time.Time) {
	day := model.ComputeUtcDay(now)
	month := model.ComputeUtcMonth(now)
	row.TopUpDay, row.TopUpMonth = &day, &month
	row.TopUpDayCount, row.FailureDayCount, row.TopUpMonthNanoUsd = self.topUpsToday, self.failuresToday, self.monthNanoUsd
}

// One top-up's idempotency key at Stripe: of its network, UTC day, attempt that day and pack, so a run retried after a
// crash sends the same request and Stripe charges it once.
func computeTopUpKey(networkId operator.Id, now time.Time, attempt int32, packCredits int64) string {
	return fmt.Sprintf("compute_top_up_%s_%s_%d_%d", networkId, model.ComputeUtcDay(now).Format("20060102"), attempt, packCredits)
}

// §9.8's threshold as it stands.
type ComputeThresholdState struct {
	On bool
	// T, P and L in force: the row's, or the defaults.
	BelowNanoUsd      int64
	PackCredits       int64
	MonthLimitNanoUsd int64
	// Why it turned off, where it did; nil for none, and for a person's turning it off.
	OffReason *model.ComputeAutoRenewOffReason
	// The member whose card it charges, nil while none is saved.
	PayerMemberId *operator.Id
	// Today's top-ups and failures, and the month's top-ups' sum.
	TopUpsToday   int64
	FailuresToday int64
	MonthNanoUsd  int64
	// When a failed top-up retries; nil for none.
	NextRetryTime *time.Time
}

// §9.8's monthly plan as it stands.
type ComputeMonthlyState struct {
	On      bool
	Credits int64
	// stripe, or a store's; zero while there is none.
	Market model.ComputeMarket
	// The member who pays for it; nil for a store's.
	PayerMemberId *operator.Id
}

// Both modes as they stand.
type ComputeAutoRenewState struct {
	Threshold *ComputeThresholdState
	Monthly   *ComputeMonthlyState
}

// The state threshold's and monthly's rows give at now.
func computeAutoRenewStateOf(settings *model.ComputeLedgerSettings, threshold *model.ComputeAutoRenew, monthly *model.ComputeAutoRenew, now time.Time) *ComputeAutoRenewState {
	figures := computeThresholdFiguresOfRow(settings, threshold)
	counts := computeThresholdCountsOf(threshold, now)
	state := &ComputeAutoRenewState{
		Threshold: &ComputeThresholdState{
			BelowNanoUsd:      figures.belowNanoUsd,
			PackCredits:       figures.packCredits,
			MonthLimitNanoUsd: figures.monthLimitNanoUsd,
			TopUpsToday:       int64(counts.topUpsToday),
			FailuresToday:     int64(counts.failuresToday),
			MonthNanoUsd:      counts.monthNanoUsd,
		},
		Monthly: &ComputeMonthlyState{},
	}
	if threshold != nil {
		state.Threshold.On = threshold.Enabled
		state.Threshold.OffReason = threshold.OffReason
		if threshold.StripePaymentMethodId != nil {
			state.Threshold.PayerMemberId = threshold.PayerMemberId
		}
		state.Threshold.NextRetryTime = threshold.NextRetryTime
	}
	if monthly != nil {
		state.Monthly.On = monthly.Enabled
		state.Monthly.Market = monthly.Market
		state.Monthly.PayerMemberId = monthly.PayerMemberId
		if monthly.MonthlyCredits != nil {
			state.Monthly.Credits = *monthly.MonthlyCredits
		}
	}
	return state
}

// networkId's two modes as they stand (§9.8): what GET api/compute/auto-renew and the balance route answer.
func ComputeAutoRenew(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (*ComputeAutoRenewState, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var state *ComputeAutoRenewState
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		threshold, monthly, err := model.ComputeAutoRenewsInTx(env, ctx, tx, networkId)
		if err != nil {
			return err
		}
		state = computeAutoRenewStateOf(settings, threshold, monthly, clock.Now())
		return nil
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	return state, err
}

// One change of one mode (POST api/compute/auto-renew), as the route reads it from the device's ComputeAutoRenewChange
// and its verified caller.
type ComputeAutoRenewChange struct {
	NetworkId operator.Id
	// The person making the change: a mode turned on, or threshold's figures changed, must name a card they saved.
	// nil for a caller the mount names no member for, who turns modes off and nothing else.
	MemberId *operator.Id
	Mode     model.ComputeAutoRenewMode
	On       bool
	// Threshold's T, P and L; zero keeps the value in force.
	BelowNanoUsd      int64
	PackCredits       int64
	MonthLimitNanoUsd int64
	// Monthly's M; zero keeps the plan's.
	Credits int64
}

// A change's answer: both modes as they now stand, or the refusal.
type ComputeAutoRenewChangeAnswer struct {
	Refusal ComputeAutoRenewRefusal
	State   *ComputeAutoRenewState
}

// Makes change (see the file header). A refusal is an answer, never an error.
func ComputeSetAutoRenew(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, change *ComputeAutoRenewChange) (*ComputeAutoRenewChangeAnswer, error) {
	var zero operator.Id
	if change.NetworkId == zero || !change.Mode.Valid() || change.BelowNanoUsd < 0 || change.PackCredits < 0 ||
		change.MonthLimitNanoUsd < 0 || change.Credits < 0 {
		return nil, fmt.Errorf("%w: a change names its network and a mode §9.8 names, with no negative figure", ErrComputeAutoRenewArgs)
	}
	thresholdSet := change.BelowNanoUsd != 0 || change.PackCredits != 0 || change.MonthLimitNanoUsd != 0
	if (change.Mode == model.ComputeAutoRenewModeThreshold && change.Credits != 0) || (change.Mode == model.ComputeAutoRenewModeMonthly && thresholdSet) {
		return nil, fmt.Errorf("%w: one mode's figures on the other", ErrComputeAutoRenewArgs)
	}
	if change.Mode == model.ComputeAutoRenewModeMonthly && change.Credits != 0 && !slices.Contains(settings.MonthlyPlanCredits, change.Credits) {
		return nil, fmt.Errorf("%w: a monthly plan is one of %v credits", ErrComputeAutoRenewArgs, settings.MonthlyPlanCredits)
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	if change.Mode == model.ComputeAutoRenewModeMonthly {
		return computeSetMonthly(env, ctx, settings, db, change, now)
	}
	var refusal ComputeAutoRenewRefusal
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		refusal = ""
		row, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, change.NetworkId, model.ComputeAutoRenewModeThreshold, true)
		if err != nil {
			return err
		}
		if !change.On {
			// anyone who may buy turns it off; the card stays its holder's, for them to turn it on again
			if row == nil || !row.Enabled {
				return nil
			}
			row.Enabled = false
			row.NextRetryTime = nil
			return model.ComputeAutoRenewPutInTx(env, ctx, tx, row, now)
		}
		// turned on, or its figures changed: only by the holder of the card it charges (R1-31)
		if row == nil || row.PayerMemberId == nil || row.StripePaymentMethodId == nil || row.StripeCustomerId == nil ||
			change.MemberId == nil || *change.MemberId != *row.PayerMemberId {
			refusal = ComputeAutoRenewRefusalCardRequired
			return nil
		}
		figures, err := computeThresholdFiguresOf(settings, computeThresholdFiguresOfRow(settings, row), change.BelowNanoUsd, change.PackCredits, change.MonthLimitNanoUsd)
		if err != nil {
			return err
		}
		figures.into(row)
		if !row.Enabled {
			row.Enabled = true
			row.OffReason = nil
			row.FailureRunCount = 0
			row.NextRetryTime = nil
		}
		return model.ComputeAutoRenewPutInTx(env, ctx, tx, row, now)
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	if refusal != "" {
		return &ComputeAutoRenewChangeAnswer{Refusal: refusal}, nil
	}
	state, err := ComputeAutoRenew(env, ctx, settings, change.NetworkId)
	if err != nil {
		return nil, err
	}
	return &ComputeAutoRenewChangeAnswer{State: state}, nil
}

// The monthly mode's change: turning a Stripe plan off cancels its subscription first, so no invoice follows; turning
// it on, or another M, opens through Checkout (card_required) or is a plan change not built; a store's plan is the
// store's.
func computeSetMonthly(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, db operator.Db, change *ComputeAutoRenewChange, now time.Time) (*ComputeAutoRenewChangeAnswer, error) {
	var row *model.ComputeAutoRenew
	err := db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		row, err = model.ComputeAutoRenewGetInTx(env, ctx, tx, change.NetworkId, model.ComputeAutoRenewModeMonthly, false)
		return err
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	if err != nil {
		return nil, err
	}
	running := row != nil && row.Enabled
	if running && row.Market != model.ComputeMarketStripe {
		return &ComputeAutoRenewChangeAnswer{Refusal: ComputeAutoRenewRefusalStoreSubscription}, nil
	}
	switch {
	case change.On && !running:
		return &ComputeAutoRenewChangeAnswer{Refusal: ComputeAutoRenewRefusalCardRequired}, nil
	case change.On && change.Credits != 0 && (row.MonthlyCredits == nil || *row.MonthlyCredits != change.Credits):
		return &ComputeAutoRenewChangeAnswer{Refusal: ComputeAutoRenewRefusalNotBuilt}, nil
	case !change.On && running:
		if row.StripeSubscriptionId != nil {
			stripe := ComputeRegisteredStripeRenew()
			if stripe == nil {
				return nil, ErrComputeStripeRenewUnavailable
			}
			if err := stripe.CancelSubscription(ctx, *row.StripeSubscriptionId); err != nil {
				return nil, err
			}
		}
		err := db.Tx(ctx, func(tx operator.DbTx) error {
			locked, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, change.NetworkId, model.ComputeAutoRenewModeMonthly, true)
			if err != nil || locked == nil || !locked.Enabled {
				return err
			}
			locked.Enabled = false
			return model.ComputeAutoRenewPutInTx(env, ctx, tx, locked, now)
		}, operator.DbIsolationReadCommitted)
		if err != nil {
			return nil, err
		}
	}
	state, err := ComputeAutoRenew(env, ctx, settings, change.NetworkId)
	if err != nil {
		return nil, err
	}
	return &ComputeAutoRenewChangeAnswer{State: state}, nil
}

// Auto-renew's taker of the card a pack's checkout saved with threshold turned on (BAL-M12-08's seam).
type computeAutoRenewCardTaker struct{}

// Takes saved (see ComputeAutoRenewCards): threshold turned on with the card, its payer the member who saved it, so
// their card is the one it charges; a card another member saved before is detached. A delivery that names the card
// the row holds already changes nothing, so a webhook delivered again after its person turned threshold off leaves
// it off.
func (self computeAutoRenewCardTaker) CardSaved(env operator.Env, ctx context.Context, saved *ComputeCardSaved) error {
	var zero operator.Id
	if saved.Mode != model.ComputeAutoRenewModeThreshold || saved.NetworkId == zero || saved.PayerMemberId == zero ||
		saved.StripeCustomerId == "" || saved.StripePaymentMethodId == "" {
		return fmt.Errorf("%w: a saved card names its network, payer, customer and card, for threshold", ErrComputeAutoRenewArgs)
	}
	settings := model.DefaultComputeLedgerSettings()
	clock, err := env.Clock()
	if err != nil {
		return err
	}
	db, err := env.Db()
	if err != nil {
		return err
	}
	now := clock.Now()
	replaced := ""
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		replaced = ""
		row, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, saved.NetworkId, model.ComputeAutoRenewModeThreshold, true)
		if err != nil {
			return err
		}
		if row != nil && row.PayerMemberId != nil && *row.PayerMemberId == saved.PayerMemberId &&
			row.StripePaymentMethodId != nil && *row.StripePaymentMethodId == saved.StripePaymentMethodId {
			return nil
		}
		if row == nil {
			row = &model.ComputeAutoRenew{NetworkId: saved.NetworkId, Mode: model.ComputeAutoRenewModeThreshold}
		} else if row.StripePaymentMethodId != nil && *row.StripePaymentMethodId != saved.StripePaymentMethodId {
			replaced = *row.StripePaymentMethodId
		}
		figures, err := computeThresholdFiguresOf(settings, computeThresholdDefaults(settings), saved.BelowNanoUsd, saved.PackCredits, saved.MonthLimitNanoUsd)
		if err != nil {
			// figures the checkout let through and the bounds do not: the defaults, rather than no top-up at all
			figures = computeThresholdDefaults(settings)
		}
		figures.into(row)
		payer, customer, card := saved.PayerMemberId, saved.StripeCustomerId, saved.StripePaymentMethodId
		row.Enabled = true
		row.Market = model.ComputeMarketStripe
		row.PayerMemberId, row.StripeCustomerId, row.StripePaymentMethodId = &payer, &customer, &card
		row.OffReason = nil
		row.FailureRunCount = 0
		row.NextRetryTime = nil
		return model.ComputeAutoRenewPutInTx(env, ctx, tx, row, now)
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return err
	}
	if replaced != "" {
		// the card no longer charged; a detach that fails leaves it on its holder's own customer, charged by nothing
		if stripe := ComputeRegisteredStripeRenew(); stripe != nil {
			stripe.DetachCard(ctx, replaced)
		}
	}
	return nil
}

// Auto-renew's monthly plan through Checkout in subscription mode (BAL-M12-08's seam).
type computeMonthlyCheckoutTaker struct{}

// Opens request's plan (see ComputeMonthlyCheckout), in this order: no Stripe on the host, or no payer key, refused
// before anything is read; sales closed; the network's limits and the cap for the month's credits; a plan on already;
// then the session.
func (self computeMonthlyCheckoutTaker) MonthlyCheckout(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeCheckoutRequest) (*ComputeCheckoutAnswer, error) {
	stripe := ComputeRegisteredStripeRenew()
	if stripe == nil {
		return nil, ErrComputeStripeUnavailable
	}
	if _, err := computePayerKey(ComputeRegisteredLedgerSecrets()); err != nil {
		return nil, err
	}
	if !ComputeSalesOpen(env, ctx, request.NetworkId) {
		return &ComputeCheckoutAnswer{Refusal: ComputeCheckoutRefusalSalesClosed}, nil
	}
	amount := request.MonthlyCredits * model.ComputeCreditNanoUsd
	limits, err := ComputePurchaseCheck(env, ctx, settings, ComputeRegisteredLedgerSecrets(), &ComputePurchaseRequest{NetworkId: request.NetworkId, AmountNanoUsd: amount})
	if err != nil {
		return nil, err
	}
	if !limits.Allowed {
		return &ComputeCheckoutAnswer{Refusal: ComputeCheckoutRefusal(limits.Code())}, nil
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	on := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		row, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, request.NetworkId, model.ComputeAutoRenewModeMonthly, false)
		on = err == nil && row != nil && row.Enabled
		return err
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	if err != nil {
		return nil, err
	}
	if on {
		return &ComputeCheckoutAnswer{Refusal: ComputeCheckoutRefusal(ComputeAutoRenewRefusalMonthlyOn)}, nil
	}
	session, err := stripe.MonthlyCheckout(ctx, &ComputeStripeMonthlyRequest{
		NetworkId: request.NetworkId, MemberId: request.MemberId, Credits: request.MonthlyCredits, AmountNanoUsd: amount,
	})
	if err != nil {
		return nil, err
	}
	return &ComputeCheckoutAnswer{Session: session}, nil
}

// One top-up whose money is final.
type ComputeTopUpCreditRequest struct {
	NetworkId       operator.Id
	PaymentIntentId string
	AmountNanoUsd   int64
	// The card's payer hash, nil where it could not be made.
	PayerHash []byte
}

// Credits a top-up's lot once by its PaymentIntent and, in the same transaction, counts it among threshold's day and
// month (see the file header); then the projection, and the account's state at once (§9.9). A replay credits and
// counts nothing. A deleted network's closed account credits nothing: ErrComputeAccountClosed, for the caller to
// refund.
func ComputeTopUpCredit(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeTopUpCreditRequest) (*ComputeCreditAnswer, error) {
	credit := &ComputeCreditRequest{
		NetworkId: request.NetworkId, Kind: model.ComputeLotKindPurchase, Market: model.ComputeMarketStripe,
		MarketRef: request.PaymentIntentId, AmountNanoUsd: request.AmountNanoUsd, PayerHash: request.PayerHash,
	}
	if err := computeCreditCheck(credit); err != nil {
		return nil, err
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	var answer *ComputeCreditAnswer
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		if err := model.ComputeFenceInTx(env, ctx, tx, request.NetworkId); err != nil {
			return err
		}
		var err error
		answer, err = computeCreditLotInTx(env, ctx, tx, settings, credit, now)
		if err != nil || !answer.Credited {
			return err
		}
		row, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, request.NetworkId, model.ComputeAutoRenewModeThreshold, true)
		if err != nil || row == nil {
			return err
		}
		counts := computeThresholdCountsOf(row, now)
		counts.topUpsToday += 1
		counts.monthNanoUsd += request.AmountNanoUsd
		counts.into(row, now)
		row.FailureRunCount = 0
		row.NextRetryTime = nil
		return model.ComputeAutoRenewPutInTx(env, ctx, tx, row, now)
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	if answer.Credited {
		answer.Projected = computeProjectionRefresh(env, ctx, settings, request.NetworkId, now, false)
		computeStateReview(env, ctx, settings, request.NetworkId)
	}
	return answer, nil
}

// The monthly plan's subscription, as its checkout's completion names it.
type ComputeMonthlySubscription struct {
	NetworkId     operator.Id
	PayerMemberId operator.Id
	Credits       int64
	// The payer's Stripe customer for this network and member, and the plan's subscription on it.
	StripeCustomerId     string
	StripeSubscriptionId string
}

// Records the plan's subscription (the webhook's checkout.session.completed): monthly turned on, its payer the member
// who opened it. A delivery naming the subscription the row holds changes nothing; another subscription replaces the
// one it held, which is cancelled after the commit, so no network holds two.
func ComputeMonthlySubscribed(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, subscription *ComputeMonthlySubscription) error {
	var zero operator.Id
	if subscription.NetworkId == zero || subscription.PayerMemberId == zero || subscription.StripeCustomerId == "" ||
		subscription.StripeSubscriptionId == "" || !slices.Contains(settings.MonthlyPlanCredits, subscription.Credits) {
		return fmt.Errorf("%w: a plan names its network, payer, customer, subscription and one of %v credits", ErrComputeAutoRenewArgs, settings.MonthlyPlanCredits)
	}
	clock, err := env.Clock()
	if err != nil {
		return err
	}
	db, err := env.Db()
	if err != nil {
		return err
	}
	now := clock.Now()
	replaced := ""
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		replaced = ""
		row, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, subscription.NetworkId, model.ComputeAutoRenewModeMonthly, true)
		if err != nil {
			return err
		}
		if row != nil && row.StripeSubscriptionId != nil && *row.StripeSubscriptionId == subscription.StripeSubscriptionId {
			return nil
		}
		if row == nil {
			row = &model.ComputeAutoRenew{NetworkId: subscription.NetworkId, Mode: model.ComputeAutoRenewModeMonthly}
		} else if row.Enabled && row.StripeSubscriptionId != nil {
			replaced = *row.StripeSubscriptionId
		}
		credits, payer := subscription.Credits, subscription.PayerMemberId
		customer, subscriptionId := subscription.StripeCustomerId, subscription.StripeSubscriptionId
		row.Enabled = true
		row.Market = model.ComputeMarketStripe
		row.MonthlyCredits = &credits
		row.PayerMemberId, row.StripeCustomerId, row.StripeSubscriptionId = &payer, &customer, &subscriptionId
		row.OffReason = nil
		return model.ComputeAutoRenewPutInTx(env, ctx, tx, row, now)
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return err
	}
	if replaced != "" {
		stripe := ComputeRegisteredStripeRenew()
		if stripe == nil {
			return ErrComputeStripeRenewUnavailable
		}
		return stripe.CancelSubscription(ctx, replaced)
	}
	return nil
}

// One month's grant of the plan, as its paid invoice names it.
type ComputeMonthlyGrantRequest struct {
	NetworkId operator.Id
	// The invoice's PaymentIntent: the lot's market_ref, new at every renewal.
	PaymentIntentId string
	Credits         int64
	// The card's payer hash, nil where it could not be made.
	PayerHash []byte
}

// Credits one month of the plan as a kind-2 lot under its invoice's PaymentIntent (the webhook's invoice.paid), once,
// the account's state reviewed at once (§9.9). A closed account credits nothing: ErrComputeAccountClosed.
func ComputeMonthlyGrant(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeMonthlyGrantRequest) (*ComputeCreditAnswer, error) {
	if !slices.Contains(settings.MonthlyPlanCredits, request.Credits) {
		return nil, fmt.Errorf("%w: a monthly plan is one of %v credits", ErrComputeAutoRenewArgs, settings.MonthlyPlanCredits)
	}
	// ComputeCreditLot reviews the account's state at once
	return ComputeCreditLot(env, ctx, settings, &ComputeCreditRequest{
		NetworkId: request.NetworkId, Kind: model.ComputeLotKindSubscription, Market: model.ComputeMarketStripe,
		MarketRef: request.PaymentIntentId, AmountNanoUsd: request.Credits * model.ComputeCreditNanoUsd, PayerHash: request.PayerHash,
	})
}

// Turns the plan of a Stripe subscription off (the webhook's customer.subscription.deleted): whoever cancelled it, it
// grants nothing more. A subscription no row names changes nothing.
func ComputeMonthlyEnded(env operator.Env, ctx context.Context, subscriptionId string) error {
	if subscriptionId == "" {
		return fmt.Errorf("%w: no subscription", ErrComputeAutoRenewArgs)
	}
	clock, err := env.Clock()
	if err != nil {
		return err
	}
	db, err := env.Db()
	if err != nil {
		return err
	}
	return db.Tx(ctx, func(tx operator.DbTx) error {
		row, err := model.ComputeAutoRenewBySubscriptionInTx(env, ctx, tx, subscriptionId)
		if err != nil || row == nil || !row.Enabled {
			return err
		}
		row.Enabled = false
		return model.ComputeAutoRenewPutInTx(env, ctx, tx, row, clock.Now())
	}, operator.DbIsolationReadCommitted)
}

// Tells the billing contacts a plan's invoice was not paid (the webhook's invoice.payment_failed), once an invoice;
// Stripe's billing retry follows, and the credits of a period are granted only once it is paid.
func ComputeMonthlyPaymentFailed(env operator.Env, ctx context.Context, subscriptionId string, invoiceId string) error {
	if subscriptionId == "" || invoiceId == "" {
		return fmt.Errorf("%w: no subscription or invoice", ErrComputeAutoRenewArgs)
	}
	db, err := env.Db()
	if err != nil {
		return err
	}
	return db.Tx(ctx, func(tx operator.DbTx) error {
		row, err := model.ComputeAutoRenewBySubscriptionInTx(env, ctx, tx, subscriptionId)
		if err != nil || row == nil {
			return err
		}
		amount := int64(0)
		if row.MonthlyCredits != nil {
			amount = *row.MonthlyCredits * model.ComputeCreditNanoUsd
		}
		return computeNoticeInTx(env, ctx, tx, &ComputeNotice{
			NetworkId: row.NetworkId, Kind: ComputeNoticeMonthlyFailed, Key: "monthly/" + row.NetworkId.String() + "/" + invoiceId, AmountNanoUsd: amount,
		})
	}, operator.DbIsolationReadCommitted)
}

// What one run of compute_auto_renew did.
type ComputeAutoRenewRunResult struct {
	// Where the next run continues, a full batch having been examined; nil once the pass reached its end.
	Cursor *operator.Id
	// Networks with threshold on examined.
	NetworkCount int
	// What each examined network came to, by result (computeAutoRenewResult).
	Results map[string]int
}

// What one network's turn of a run came to, as the auto-renew metric counts it: identifiers.
const (
	computeAutoRenewResultAbove          = "above"
	computeAutoRenewResultLimited        = "limited"
	computeAutoRenewResultWaiting        = "waiting"
	computeAutoRenewResultUnavailable    = "unavailable"
	computeAutoRenewResultCharged        = "charged"
	computeAutoRenewResultProcessing     = "processing"
	computeAutoRenewResultFailed         = "failed"
	computeAutoRenewResultOff            = "off"
	computeAutoRenewResultAuthentication = "authentication_required"
	computeAutoRenewResultPayerLeft      = "payer_left"
	computeAutoRenewResultSkipped        = "skipped"
)

// The auto-renew metric, by result, which §14.7's ledger family reads.
const computeAutoRenewMetric = "urnetwork_compute_auto_renew_total"

// One run's continuation args: its cursor's id, empty for a pass's start.
func ComputeAutoRenewCursorArgs(cursor *operator.Id) []byte {
	if cursor == nil {
		return nil
	}
	return []byte(cursor.String())
}

// The cursor of a run's args, nil for a pass's start.
func ParseComputeAutoRenewCursor(args []byte) (*operator.Id, error) {
	if len(args) == 0 {
		return nil, nil
	}
	id, err := sidecar.ParseId(string(args))
	if err != nil {
		return nil, fmt.Errorf("%w: a cursor %q", ErrComputeAutoRenewArgs, string(args))
	}
	return &id, nil
}

// Runs one batch of compute_auto_renew from cursor (see the file header): each network with threshold on whose
// balance, holds left out, is below T is charged P once, within its limits. A network whose turn fails is left for the
// next run; the batch goes on.
func ComputeAutoRenewRun(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, cursor *operator.Id) (*ComputeAutoRenewRunResult, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	networkIds, err := model.ComputeAutoRenewThresholdNetworks(env, ctx, cursor, settings.AutoRenewBatchCount)
	if err != nil {
		return nil, err
	}
	result := &ComputeAutoRenewRunResult{Results: map[string]int{}}
	counter := func(string) {}
	if metrics, err := env.Metrics(); err == nil {
		declared := metrics.Counter(computeAutoRenewMetric, "compute auto-renew's top-ups, by result", "result")
		counter = func(outcome string) { declared.Add(1, outcome) }
	}
	var firstErr error
	for _, networkId := range networkIds {
		outcome, err := computeAutoRenewNetwork(env, ctx, settings, networkId, clock.Now())
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		result.NetworkCount += 1
		result.Results[outcome] += 1
		counter(outcome)
	}
	if len(networkIds) == settings.AutoRenewBatchCount && 0 < len(networkIds) {
		last := networkIds[len(networkIds)-1]
		result.Cursor = &last
	}
	return result, firstErr
}

// One network's turn of a run at now (see the file header).
func computeAutoRenewNetwork(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, now time.Time) (string, error) {
	db, err := env.Db()
	if err != nil {
		return "", err
	}
	var row *model.ComputeAutoRenew
	var balance *model.ComputeAccountBalance
	chargeback := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		if row, err = model.ComputeAutoRenewGetInTx(env, ctx, tx, networkId, model.ComputeAutoRenewModeThreshold, false); err != nil {
			return err
		}
		if balance, err = model.ComputeAccountBalanceInTx(env, ctx, tx, settings, networkId); err != nil {
			return err
		}
		chargeback, err = model.ComputeChargebackSuspendedInTx(env, ctx, tx, networkId)
		return err
	}, operator.DbIsolationRepeatableRead, operator.DbReadOnly)
	if err != nil {
		return "", err
	}
	// a closed account takes no credit, and a chargeback's suspension charges no saved card until a person's review lifts
	// it: the credit would land on an account the states hold suspended (§9.9, §9.11's chargeback row; a reading)
	if row == nil || !row.Enabled || row.PayerMemberId == nil || row.StripeCustomerId == nil || row.StripePaymentMethodId == nil ||
		(balance.Account != nil && balance.Account.State == model.ComputeAccountStateClosed) || chargeback {
		return computeAutoRenewResultSkipped, nil
	}
	figures := computeThresholdFiguresOfRow(settings, row)
	if figures.belowNanoUsd <= balance.BalanceNanoUsd {
		return computeAutoRenewResultAbove, nil
	}
	counts := computeThresholdCountsOf(row, now)
	amount := figures.packCredits * model.ComputeCreditNanoUsd
	if int32(settings.ThresholdDayMaxCount) <= counts.topUpsToday || figures.monthLimitNanoUsd < counts.monthNanoUsd+amount {
		return computeAutoRenewResultLimited, nil
	}
	if row.NextRetryTime != nil && now.Before(*row.NextRetryTime) {
		return computeAutoRenewResultWaiting, nil
	}
	stripe := ComputeRegisteredStripeRenew()
	payers := ComputeRegisteredAutoRenewPayers()
	secrets := ComputeRegisteredLedgerSecrets()
	if stripe == nil || payers == nil {
		// no Stripe or no payer check on the host: no card is charged
		return computeAutoRenewResultUnavailable, nil
	}
	payer, card := *row.PayerMemberId, *row.StripePaymentMethodId
	mayBuy, err := payers.MayBuy(env, ctx, networkId, payer)
	if err != nil {
		return "", err
	}
	if !mayBuy {
		return computeAutoRenewResultPayerLeft, computeThresholdDetach(env, ctx, stripe, networkId, payer, card, now)
	}
	fingerprint, err := stripe.CardFingerprint(ctx, card)
	if err != nil {
		return "", err
	}
	var payerHash []byte
	if fingerprint != "" {
		if payerHash, err = ComputePayerHash(secrets, ComputePayerStripeCard, fingerprint); err != nil {
			// no key to hash the payer with: every purchase refuses, top-ups among them
			return computeAutoRenewResultUnavailable, nil
		}
	}
	limits, err := ComputePurchaseCheck(env, ctx, settings, secrets, &ComputePurchaseRequest{NetworkId: networkId, PayerHash: payerHash, AmountNanoUsd: amount})
	if errors.Is(err, ErrComputeLedgerSecretsUnset) {
		return computeAutoRenewResultUnavailable, nil
	}
	if err != nil {
		return "", err
	}
	if !limits.Allowed {
		return computeAutoRenewResultLimited, nil
	}
	attempt := counts.topUpsToday + counts.failuresToday + 1
	testHookBarrier("compute_auto_renew.charge.before", networkId.String())
	charged, err := stripe.ChargeOffSession(ctx, &ComputeOffSessionCharge{
		NetworkId: networkId, PayerMemberId: payer, StripeCustomerId: *row.StripeCustomerId, StripePaymentMethodId: card,
		PackCredits: figures.packCredits, AmountNanoUsd: amount, IdempotencyKey: computeTopUpKey(networkId, now, attempt, figures.packCredits),
	})
	testHookBarrier("compute_auto_renew.charge.after", networkId.String())
	if err != nil {
		// Stripe did not answer: no count moved, so the next run sends the same key
		return "", err
	}
	switch charged.Outcome {
	case ComputeOffSessionSucceeded:
		if _, err := ComputeTopUpCredit(env, ctx, settings, &ComputeTopUpCreditRequest{
			NetworkId: networkId, PaymentIntentId: charged.PaymentIntentId, AmountNanoUsd: amount, PayerHash: payerHash,
		}); err != nil {
			return "", err
		}
		return computeAutoRenewResultCharged, nil
	case ComputeOffSessionProcessing:
		// not final: the webhook's success credits and counts it, and the job waits a retry's interval meanwhile
		return computeAutoRenewResultProcessing, computeThresholdWait(env, ctx, settings, networkId, row, now)
	case ComputeOffSessionAuthenticationRequired, ComputeOffSessionFailed:
		return computeThresholdFailed(env, ctx, settings, networkId, row, attempt, amount, charged.Outcome, now)
	}
	return "", fmt.Errorf("compute auto-renew: an off-session charge answered %q", charged.Outcome)
}

// Whether row stands at the attempt the job read: its card and counts unmoved, so a failure is recorded once.
func computeThresholdSameAttempt(read *model.ComputeAutoRenew, locked *model.ComputeAutoRenew, now time.Time) bool {
	if locked == nil || !locked.Enabled || locked.StripePaymentMethodId == nil || read.StripePaymentMethodId == nil ||
		*locked.StripePaymentMethodId != *read.StripePaymentMethodId {
		return false
	}
	before, after := computeThresholdCountsOf(read, now), computeThresholdCountsOf(locked, now)
	return *before == *after && locked.FailureRunCount == read.FailureRunCount
}

// Records a failed top-up (§9.8): the day's failures and the run of them counted; under the settings' third in a row a
// retry after 1 h then 6 h and its notice, at the third threshold off and its notice; an authentication_required answer
// turns threshold off at once, its notice the link. A row moved since the job read it records nothing.
func computeThresholdFailed(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, read *model.ComputeAutoRenew, attempt int32, amount int64, outcome ComputeOffSessionOutcome, now time.Time) (string, error) {
	db, err := env.Db()
	if err != nil {
		return "", err
	}
	result := computeAutoRenewResultFailed
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		result = computeAutoRenewResultFailed
		row, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, networkId, model.ComputeAutoRenewModeThreshold, true)
		if err != nil {
			return err
		}
		if !computeThresholdSameAttempt(read, row, now) {
			return nil
		}
		counts := computeThresholdCountsOf(row, now)
		counts.failuresToday += 1
		counts.into(row, now)
		row.FailureRunCount += 1
		notice := &ComputeNotice{
			NetworkId: networkId, AmountNanoUsd: amount, FailureCount: int(row.FailureRunCount),
			Key: fmt.Sprintf("top_up/%s/%s/%d", networkId, model.ComputeUtcDay(now).Format("20060102"), attempt),
		}
		switch {
		case outcome == ComputeOffSessionAuthenticationRequired:
			reason := model.ComputeAutoRenewOffAuthenticationRequired
			row.Enabled, row.OffReason, row.NextRetryTime = false, &reason, nil
			notice.Kind = ComputeNoticeAuthenticationRequired
			result = computeAutoRenewResultAuthentication
		case settings.ThresholdFailureMaxCount <= int(row.FailureRunCount) || len(settings.ThresholdRetryIntervals) < int(row.FailureRunCount):
			reason := model.ComputeAutoRenewOffFailed
			row.Enabled, row.OffReason, row.NextRetryTime = false, &reason, nil
			notice.Kind = ComputeNoticeTopUpOff
			result = computeAutoRenewResultOff
		default:
			retry := now.Add(settings.ThresholdRetryIntervals[row.FailureRunCount-1])
			row.NextRetryTime = &retry
			notice.Kind = ComputeNoticeTopUpFailed
			notice.RetryTime = &retry
		}
		if err := model.ComputeAutoRenewPutInTx(env, ctx, tx, row, now); err != nil {
			return err
		}
		return computeNoticeInTx(env, ctx, tx, notice)
	}, operator.DbIsolationReadCommitted)
	return result, err
}

// Holds threshold's next charge a retry's interval while a top-up's money is not final, its count unmoved.
func computeThresholdWait(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, read *model.ComputeAutoRenew, now time.Time) error {
	if len(settings.ThresholdRetryIntervals) == 0 {
		return nil
	}
	db, err := env.Db()
	if err != nil {
		return err
	}
	return db.Tx(ctx, func(tx operator.DbTx) error {
		row, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, networkId, model.ComputeAutoRenewModeThreshold, true)
		if err != nil || !computeThresholdSameAttempt(read, row, now) {
			return err
		}
		retry := now.Add(settings.ThresholdRetryIntervals[0])
		row.NextRetryTime = &retry
		return model.ComputeAutoRenewPutInTx(env, ctx, tx, row, now)
	}, operator.DbIsolationReadCommitted)
}

// Detaches the card of a payer who may no longer buy (§9.5): threshold off, payer_left, the card dropped from the row,
// and the notice; then the card detached at Stripe. A row whose card has changed since is left.
func computeThresholdDetach(env operator.Env, ctx context.Context, stripe ComputeStripeRenew, networkId operator.Id, payer operator.Id, card string, now time.Time) error {
	db, err := env.Db()
	if err != nil {
		return err
	}
	detached := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		detached = false
		row, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, networkId, model.ComputeAutoRenewModeThreshold, true)
		if err != nil || row == nil || row.PayerMemberId == nil || *row.PayerMemberId != payer ||
			row.StripePaymentMethodId == nil || *row.StripePaymentMethodId != card {
			return err
		}
		reason := model.ComputeAutoRenewOffPayerLeft
		row.Enabled, row.OffReason, row.NextRetryTime = false, &reason, nil
		row.StripePaymentMethodId = nil
		if err := model.ComputeAutoRenewPutInTx(env, ctx, tx, row, now); err != nil {
			return err
		}
		detached = true
		return computeNoticeInTx(env, ctx, tx, &ComputeNotice{
			NetworkId: networkId, Kind: ComputeNoticeCardDetached, Key: "card_detached/" + networkId.String() + "/" + card,
		})
	}, operator.DbIsolationReadCommitted)
	if err != nil || !detached {
		return err
	}
	return stripe.DetachCard(ctx, card)
}

// The off reason's code for an answer, "" for none.
func ComputeAutoRenewOffCode(reason *model.ComputeAutoRenewOffReason) string {
	if reason == nil {
		return ""
	}
	return reason.Code()
}
