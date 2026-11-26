// Stripe purchases (DESIGN-COMPUTE §9.5, §9.8, §9.11, §14.3, D-BAL-10, CF-4; BAL-M12-08): POST api/compute/checkout's
// ledger half, and what the Stripe webhooks' compute branch (server's ComputeStripeWebhook) asks of the ledger beside
// ComputePurchaseCheck, ComputeCreditLot and ComputeReverseLot.
//
//	ComputeCheckout               one of §9.5's Stripe packs for a person who may buy (the frame's check), refused
//	                              while sales are closed (Q-BAL-13) and past the network's limits or the balance cap
//	                              (ComputePurchaseCheck, before any card is known), then a Checkout session from the
//	                              host's ComputeStripeCheckout: mode payment, the PaymentIntent captured by hand only
//	                              once its card passes its payer's limits (the webhook's), 3-D Secure asked for on the
//	                              network's first purchase above $50, and the card saved for off-session use only
//	                              where its payer turns threshold top-up on in this act
//	ComputeRecordPurchaseTerms    the compute terms' version a purchase accepts (§21.9), recorded with the first
//	                              purchase and again where a later one accepts a newer version
//	ComputeCardSavedForAutoRenew  hands auto-renew the card a payment saved for the mode its payer turned on
//
// Two parts are auto-renew's (BAL-M12-11) and answer not_built until it registers them, so no card is saved for a mode
// nothing can run and no subscription opens that nothing credits: the monthly plan alone, a Checkout in subscription
// mode (RegisterComputeMonthlyCheckout), and the card a threshold checkout saves (RegisterComputeAutoRenewCards).
//
// Stripe's API and its webhooks are server's (server/controller/compute_stripe.go), since this repository links no
// Stripe client (§4.7): server registers its ComputeStripeCheckout at its start, and a host with none answers
// ErrComputeStripeUnavailable. Nothing here sees a card: the payer hash is made from the card's fingerprint by the
// webhook (ComputePayerHash), and a session's url is answered to the person and logged nowhere.

package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// Why a checkout was refused (§14.3), the code the route answers, as the device's client reads it.
type ComputeCheckoutRefusal string

const (
	// Credits are not sold yet: nothing the network may use can spend them (Q-BAL-13).
	ComputeCheckoutRefusalSalesClosed ComputeCheckoutRefusal = "sales_closed"
	// The purchase would pass the $10,000 cap (§9.11).
	ComputeCheckoutRefusalBalanceCap ComputeCheckoutRefusal = "balance_cap"
	// The purchase would pass a day's load, a new account's limits among them (§9.11).
	ComputeCheckoutRefusalDailyLimit ComputeCheckoutRefusal = "daily_limit"
	// A part of the request auto-renew (BAL-M12-11) builds: the monthly plan, or the card threshold top-up saves.
	ComputeCheckoutRefusalNotBuilt ComputeCheckoutRefusal = "not_built"
)

var (
	// A checkout the ledger cannot take: a pack §9.5 does not sell, settings of a mode not turned on, a negative value.
	ErrComputeCheckoutArgs = errors.New("compute checkout: arguments refused")
	// The host registered no Stripe checkout: every checkout refuses (fails closed).
	ErrComputeStripeUnavailable = errors.New("compute checkout: this host holds no Stripe checkout")
	// Auto-renew registered nothing to take a saved card: a payment that saved one detaches it.
	ErrComputeAutoRenewUnbuilt = errors.New("compute checkout: auto-renew takes no saved card yet")
)

// One checkout (§14.3), as the route reads it from the device's ComputeCheckoutArgs and its verified caller.
type ComputeCheckoutRequest struct {
	NetworkId operator.Id
	// The paying person: the member whose Stripe customer, card and mandate the session names.
	MemberId operator.Id
	// A pack of §9.5's, in credits; zero for the monthly plan alone.
	PackCredits int64
	// The mode the payer turns on in this act, which saves their card for it; zero for none.
	AutoRenew model.ComputeAutoRenewMode
	// Threshold's T, P (in credits) and L where AutoRenew is threshold, zero for auto-renew's defaults.
	BelowNanoUsd      int64
	TopUpPackCredits  int64
	MonthLimitNanoUsd int64
	// Monthly's M where AutoRenew is monthly.
	MonthlyCredits int64
}

// A checkout's answer: the session, or the refusal.
type ComputeCheckoutAnswer struct {
	Refusal ComputeCheckoutRefusal
	Session *ComputeStripeCheckoutSession
}

// One Checkout session the host makes (§9.5, §9.11).
type ComputeStripeCheckoutRequest struct {
	NetworkId operator.Id
	MemberId  operator.Id
	// The pack and its price, a credit a dollar, before Stripe Tax adds the tax.
	PackCredits   int64
	AmountNanoUsd int64
	// Save the card for off-session use (setup_future_usage=off_session): only where its payer turns a mode on in this
	// act, which AutoRenew names with its settings.
	SaveCard          bool
	AutoRenew         model.ComputeAutoRenewMode
	BelowNanoUsd      int64
	TopUpPackCredits  int64
	MonthLimitNanoUsd int64
	// Ask for 3-D Secure: the network's first purchase above the settings' $50.
	ThreeDSecure bool
}

// A Checkout session made: the url the person opens, and when it lapses unpaid.
type ComputeStripeCheckoutSession struct {
	SessionId  string
	Url        string
	ExpireTime time.Time
}

// The host's Stripe Checkout (server's ComputeServerStripe). Implementations are safe for concurrent use.
type ComputeStripeCheckout interface {
	// Makes request's session on the Stripe customer of its network and member, which it finds or makes.
	CreateCheckout(ctx context.Context, request *ComputeStripeCheckoutRequest) (*ComputeStripeCheckoutSession, error)
}

// The card a payment saved for a mode its payer turned on in that act (§9.5, §9.8): what auto-renew takes.
type ComputeCardSaved struct {
	NetworkId     operator.Id
	PayerMemberId operator.Id
	Mode          model.ComputeAutoRenewMode
	// The payer's Stripe customer for this network and member, and the card saved on it.
	StripeCustomerId      string
	StripePaymentMethodId string
	// The payment that saved it.
	PaymentIntentId string
	// Threshold's T, P and L as the checkout named them, zero for auto-renew's defaults.
	BelowNanoUsd      int64
	PackCredits       int64
	MonthLimitNanoUsd int64
}

// Auto-renew's taker of saved cards (BAL-M12-11), which turns the mode on with the card.
type ComputeAutoRenewCards interface {
	CardSaved(env operator.Env, ctx context.Context, saved *ComputeCardSaved) error
}

// Auto-renew's monthly plan through Checkout in subscription mode (BAL-M12-11).
type ComputeMonthlyCheckout interface {
	MonthlyCheckout(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeCheckoutRequest) (*ComputeCheckoutAnswer, error)
}

var (
	computeCheckoutLock    sync.Mutex
	computeStripeCheckout  ComputeStripeCheckout
	computeAutoRenewCards  ComputeAutoRenewCards
	computeMonthlyCheckout ComputeMonthlyCheckout
)

// Registers the host's Stripe Checkout, once, from the host's own file at its start. A second registration, or a nil
// one, is a build error, which panics.
func RegisterComputeStripeCheckout(checkout ComputeStripeCheckout) {
	if checkout == nil {
		panic("compute checkout: nil Stripe checkout")
	}
	computeCheckoutLock.Lock()
	defer computeCheckoutLock.Unlock()
	if computeStripeCheckout != nil {
		panic("compute checkout: the Stripe checkout is registered once")
	}
	computeStripeCheckout = checkout
}

// The host's registered Stripe Checkout, nil until registered: what the route hands ComputeCheckout.
func ComputeRegisteredStripeCheckout() ComputeStripeCheckout {
	computeCheckoutLock.Lock()
	defer computeCheckoutLock.Unlock()
	return computeStripeCheckout
}

// Registers auto-renew's taker of saved cards from its own file at init (BAL-M12-11). A second registration, or a nil
// one, panics.
func RegisterComputeAutoRenewCards(cards ComputeAutoRenewCards) {
	if cards == nil {
		panic("compute checkout: nil auto-renew cards")
	}
	computeCheckoutLock.Lock()
	defer computeCheckoutLock.Unlock()
	if computeAutoRenewCards != nil {
		panic("compute checkout: auto-renew's cards are registered once")
	}
	computeAutoRenewCards = cards
}

// Registers auto-renew's monthly Checkout from its own file at init (BAL-M12-11). A second registration, or a nil one,
// panics.
func RegisterComputeMonthlyCheckout(checkout ComputeMonthlyCheckout) {
	if checkout == nil {
		panic("compute checkout: nil monthly checkout")
	}
	computeCheckoutLock.Lock()
	defer computeCheckoutLock.Unlock()
	if computeMonthlyCheckout != nil {
		panic("compute checkout: the monthly checkout is registered once")
	}
	computeMonthlyCheckout = checkout
}

func computeRegisteredAutoRenewCards() ComputeAutoRenewCards {
	computeCheckoutLock.Lock()
	defer computeCheckoutLock.Unlock()
	return computeAutoRenewCards
}

func computeRegisteredMonthlyCheckout() ComputeMonthlyCheckout {
	computeCheckoutLock.Lock()
	defer computeCheckoutLock.Unlock()
	return computeMonthlyCheckout
}

// Checks request's shape against the settings' packs and plans, as the device's client does before it sends one:
// a pack with threshold turned on in the same act or not, or the monthly plan alone.
func computeCheckoutCheck(settings *model.ComputeLedgerSettings, request *ComputeCheckoutRequest) error {
	var zero operator.Id
	if request.NetworkId == zero || request.MemberId == zero {
		return fmt.Errorf("%w: a checkout names its network and its paying member", ErrComputeCheckoutArgs)
	}
	if request.BelowNanoUsd < 0 || request.TopUpPackCredits < 0 || request.MonthLimitNanoUsd < 0 || request.MonthlyCredits < 0 {
		return fmt.Errorf("%w: a negative setting", ErrComputeCheckoutArgs)
	}
	thresholdSet := request.BelowNanoUsd != 0 || request.TopUpPackCredits != 0 || request.MonthLimitNanoUsd != 0
	switch request.AutoRenew {
	case 0, model.ComputeAutoRenewModeThreshold:
		if !slices.Contains(settings.StripePackCredits, request.PackCredits) {
			return fmt.Errorf("%w: a pack is one of %v credits", ErrComputeCheckoutArgs, settings.StripePackCredits)
		}
		if request.MonthlyCredits != 0 {
			return fmt.Errorf("%w: a monthly plan without the monthly mode", ErrComputeCheckoutArgs)
		}
		if request.AutoRenew == 0 && thresholdSet {
			return fmt.Errorf("%w: threshold settings without the threshold mode", ErrComputeCheckoutArgs)
		}
	case model.ComputeAutoRenewModeMonthly:
		if request.PackCredits != 0 || thresholdSet {
			return fmt.Errorf("%w: the monthly plan opens alone", ErrComputeCheckoutArgs)
		}
		if !slices.Contains(settings.MonthlyPlanCredits, request.MonthlyCredits) {
			return fmt.Errorf("%w: a monthly plan is one of %v credits", ErrComputeCheckoutArgs, settings.MonthlyPlanCredits)
		}
	default:
		return fmt.Errorf("%w: an auto-renew mode is threshold or monthly", ErrComputeCheckoutArgs)
	}
	return nil
}

// Opens request's checkout (see the file header), in this order: its shape; the monthly plan handed to auto-renew,
// or not_built; threshold refused not_built while auto-renew takes no card; no Stripe on the host, or no payer key,
// refused before anything is read (ErrComputeStripeUnavailable, ErrComputeLedgerSecretsUnset); sales closed; the
// network's limits and the cap; then the session, asking 3-D Secure of the network's first purchase above the settings'
// $50.
func ComputeCheckout(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, secrets ComputeLedgerSecrets, stripe ComputeStripeCheckout, request *ComputeCheckoutRequest) (*ComputeCheckoutAnswer, error) {
	if err := computeCheckoutCheck(settings, request); err != nil {
		return nil, err
	}
	if request.AutoRenew == model.ComputeAutoRenewModeMonthly {
		monthly := computeRegisteredMonthlyCheckout()
		if monthly == nil {
			return &ComputeCheckoutAnswer{Refusal: ComputeCheckoutRefusalNotBuilt}, nil
		}
		return monthly.MonthlyCheckout(env, ctx, settings, request)
	}
	if request.AutoRenew == model.ComputeAutoRenewModeThreshold && computeRegisteredAutoRenewCards() == nil {
		return &ComputeCheckoutAnswer{Refusal: ComputeCheckoutRefusalNotBuilt}, nil
	}
	if stripe == nil {
		return nil, ErrComputeStripeUnavailable
	}
	if _, err := computePayerKey(secrets); err != nil {
		return nil, err
	}
	if !ComputeSalesOpen(env, ctx, request.NetworkId) {
		return &ComputeCheckoutAnswer{Refusal: ComputeCheckoutRefusalSalesClosed}, nil
	}
	amount := request.PackCredits * model.ComputeCreditNanoUsd
	limits, err := ComputePurchaseCheck(env, ctx, settings, secrets, &ComputePurchaseRequest{NetworkId: request.NetworkId, AmountNanoUsd: amount})
	if err != nil {
		return nil, err
	}
	if !limits.Allowed {
		return &ComputeCheckoutAnswer{Refusal: ComputeCheckoutRefusal(limits.Code())}, nil
	}
	first, err := computeFirstPurchase(env, ctx, request.NetworkId)
	if err != nil {
		return nil, err
	}
	session, err := stripe.CreateCheckout(ctx, &ComputeStripeCheckoutRequest{
		NetworkId:         request.NetworkId,
		MemberId:          request.MemberId,
		PackCredits:       request.PackCredits,
		AmountNanoUsd:     amount,
		SaveCard:          request.AutoRenew != 0,
		AutoRenew:         request.AutoRenew,
		BelowNanoUsd:      request.BelowNanoUsd,
		TopUpPackCredits:  request.TopUpPackCredits,
		MonthLimitNanoUsd: request.MonthLimitNanoUsd,
		ThreeDSecure:      first && settings.ThreeDSecureAboveNanoUsd < amount,
	})
	if err != nil {
		return nil, err
	}
	return &ComputeCheckoutAnswer{Session: session}, nil
}

// Whether networkId holds no unreversed paid lot: its next purchase is its first (§9.11's 3-D Secure rule). A network
// whose only lots were charged back buys as a first purchase again.
func computeFirstPurchase(env operator.Env, ctx context.Context, networkId operator.Id) (bool, error) {
	db, err := env.Db()
	if err != nil {
		return false, err
	}
	first := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		paid, err := model.ComputePaidLotsInTx(env, ctx, tx, networkId)
		if err != nil {
			return err
		}
		first = paid.OldestTime == nil
		return nil
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	return first, err
}

// Records that networkId accepted the compute terms' current version with a purchase by userId (§21.9): the first
// purchase writes it, a later one only a newer version. Whether this call wrote it.
func ComputeRecordPurchaseTerms(env operator.Env, ctx context.Context, networkId operator.Id, userId operator.Id) (bool, error) {
	clock, err := env.Clock()
	if err != nil {
		return false, err
	}
	db, err := env.Db()
	if err != nil {
		return false, err
	}
	written := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		written, err = model.ComputeTermsAcceptInTx(env, ctx, tx, &model.ComputeTerms{
			NetworkId: networkId, Clause: model.ComputeTermsClauseCompute, TermsVersion: model.ComputeTermsVersion,
			UserId: userId, AcceptTime: clock.Now(),
		})
		return err
	}, operator.DbIsolationReadCommitted)
	return written, err
}

// Raises one of the ledger's alarms by kind, where env holds metrics: what a host's purchase paths raise beside the
// ledger's own (a purchase refused at capture, one no checkout of ours made, a refund made outside the ledger).
func ComputeRaiseAlarm(env operator.Env, kind string) {
	computeAlarm(env)(kind)
}

// Hands auto-renew the card saved (BAL-M12-11); ErrComputeAutoRenewUnbuilt while it registers none, which the
// webhook answers by detaching the card. It is called for every delivery of a payment's success, so the taker acts
// once by the PaymentIntent's id.
func ComputeCardSavedForAutoRenew(env operator.Env, ctx context.Context, saved *ComputeCardSaved) error {
	cards := computeRegisteredAutoRenewCards()
	if cards == nil {
		return ErrComputeAutoRenewUnbuilt
	}
	return cards.CardSaved(env, ctx, saved)
}
