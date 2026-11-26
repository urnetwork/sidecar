// §9.11's limits (DESIGN-COMPUTE §9.5, §9.11, R-BAL-8, D-BAL-10; BAL-M12-07): what a purchase may load and what a new
// network may use, each counted in UTC days.
//
//	balance cap     a network's balance at most $10,000: a purchase that would pass it is refused before payment
//	new account     $100 a UTC day and $200 in the first 7 days, for each network and each payer, a network's 7 days
//	                from its first purchase and a payer's from its first purchase anywhere
//	daily load      at most $1,500 a UTC day for each network and each payer, across markets (Q-BAL-15)
//	the search cap  200 searches a day until 7 days after the oldest unreversed paid lot, then 2,000, or the override
//	                URnetwork's review sets (`sidecarctl compute search-cap`, BAL-M13-02)
//	enclaves        one CPU enclave until 24 hours after the first successful payment; GPU shapes after $50 of
//	                lifetime purchases
//
// A purchase is checked before payment for its network and, once its card is known, its payer (ComputePurchaseCheck);
// a store purchase, whose payer is known only after the store took the money, is credited and, past a limit, flagged
// for review (ComputeCreditLot). A promotion counts as a load toward the daily load and the cap, and toward no payer
// and no new-account limit, which bound cards. Each limit's figure is the ledger's settings'.

package controller

import (
	"context"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// Which limit a load would pass.
type ComputeLimitReason string

const (
	// The network's balance past its cap.
	ComputeLimitBalanceCap ComputeLimitReason = "balance_cap"
	// The UTC day's loads past the daily load.
	ComputeLimitDailyLoad ComputeLimitReason = "daily_load"
	// The UTC day's purchases past a new network's or payer's day limit.
	ComputeLimitNewAccountDay ComputeLimitReason = "new_account_day"
	// The first 7 days' purchases past a new network's or payer's window limit.
	ComputeLimitNewAccountWindow ComputeLimitReason = "new_account_window"
)

// The refusal code the routes answer for the reason (§14.3, the device's compute_client_api.go): balance_cap for the
// cap, daily_limit for every load limit, a new account's among them.
func (self ComputeLimitReason) Code() string {
	if self == ComputeLimitBalanceCap {
		return "balance_cap"
	}
	return "daily_limit"
}

// One limit a load would pass, the network's or its payer's.
type ComputeLimitBreach struct {
	Reason ComputeLimitReason
	// The payer's limit, not the network's.
	Payer bool
}

// What a load is checked as.
type computeLoad struct {
	networkId operator.Id
	// nil for no payer: a card not yet known, a Play purchase, a promotion
	payerHash []byte
	amount    int64
	// a purchase, which the new-account limits bound; a promotion is not one
	purchase bool
}

// The limits load would pass at now, read in tx: the network's cap, daily load and, for a purchase, its new-account
// limits; then, for a payer, the payer's daily load and new-account limits.
func computeLoadBreachesInTx(env operator.Env, ctx context.Context, tx operator.DbTx, settings *model.ComputeLedgerSettings, load *computeLoad, now time.Time) ([]*ComputeLimitBreach, error) {
	breaches := []*ComputeLimitBreach{}
	add := func(reason ComputeLimitReason, payer bool) {
		breaches = append(breaches, &ComputeLimitBreach{Reason: reason, Payer: payer})
	}
	account, err := model.ComputeAccountInTx(env, ctx, tx, load.networkId)
	if err != nil {
		return nil, err
	}
	settled := int64(0)
	if account != nil {
		settled = account.SettledNanoUsd
	}
	if settings.BalanceCapNanoUsd < settled+load.amount {
		add(ComputeLimitBalanceCap, false)
	}
	loads, err := model.ComputeNetworkLoadsInTx(env, ctx, tx, load.networkId, now, settings.NewAccountWindow)
	if err != nil {
		return nil, err
	}
	if settings.DailyLoadNanoUsd < loads.LoadedNanoUsd+load.amount {
		add(ComputeLimitDailyLoad, false)
	}
	// a network or payer is new until its first purchase's window ends; one with none is new, this purchase its first
	inWindow := func(first *time.Time) bool {
		return first == nil || now.Before(model.ComputeUtcDay(*first).Add(settings.NewAccountWindow))
	}
	if load.purchase && inWindow(loads.FirstPurchaseTime) {
		if settings.NewAccountDayNanoUsd < loads.PurchasedNanoUsd+load.amount {
			add(ComputeLimitNewAccountDay, false)
		}
		if settings.NewAccountWindowNanoUsd < loads.WindowPurchasedNanoUsd+load.amount {
			add(ComputeLimitNewAccountWindow, false)
		}
	}
	if load.payerHash == nil {
		return breaches, nil
	}
	payer, err := model.ComputePayerInTx(env, ctx, tx, load.payerHash, now, settings.NewAccountWindow)
	if err != nil {
		return nil, err
	}
	if settings.DailyLoadNanoUsd < payer.DayNanoUsd+load.amount {
		add(ComputeLimitDailyLoad, true)
	}
	if load.purchase && inWindow(payer.FirstPurchaseDay) {
		if settings.NewAccountDayNanoUsd < payer.DayNanoUsd+load.amount {
			add(ComputeLimitNewAccountDay, true)
		}
		if settings.NewAccountWindowNanoUsd < payer.WindowNanoUsd+load.amount {
			add(ComputeLimitNewAccountWindow, true)
		}
	}
	return breaches, nil
}

// One purchase to check before payment.
type ComputePurchaseRequest struct {
	NetworkId operator.Id
	// The payer's keyed hash (ComputePayerHash) once its card is known; nil before it is, and for a Play purchase.
	PayerHash     []byte
	AmountNanoUsd int64
}

// What a purchase check answered.
type ComputePurchaseAnswer struct {
	// No limit stands in the way: checkout may take the payment.
	Allowed bool
	// Every limit the purchase would pass, the network's first.
	Breaches []*ComputeLimitBreach
}

// The refusal code the routes answer for a refused purchase: balance_cap where the cap stands in the way, else
// daily_limit; "" for an allowed one.
func (self *ComputePurchaseAnswer) Code() string {
	if self.Allowed {
		return ""
	}
	for _, breach := range self.Breaches {
		if breach.Reason == ComputeLimitBalanceCap {
			return breach.Reason.Code()
		}
	}
	return ComputeLimitDailyLoad.Code()
}

// Checks request against §9.11's limits before payment (see the file header): the network's always, the payer's
// once its card is known. Unset secrets refuse every purchase: ErrComputeLedgerSecretsUnset, before anything is read.
func ComputePurchaseCheck(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, secrets ComputeLedgerSecrets, request *ComputePurchaseRequest) (*ComputePurchaseAnswer, error) {
	if _, err := computeLedgerKey(secrets, "payer", func(secrets ComputeLedgerSecrets) ([]byte, error) { return secrets.PayerHashKey() }); err != nil {
		return nil, err
	}
	if request.AmountNanoUsd <= 0 {
		return nil, fmt.Errorf("%w: a purchase's amount is positive", ErrComputeLedgerArgs)
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var breaches []*ComputeLimitBreach
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		breaches, err = computeLoadBreachesInTx(env, ctx, tx, settings, &computeLoad{
			networkId: request.NetworkId, payerHash: request.PayerHash, amount: request.AmountNanoUsd, purchase: true,
		}, clock.Now())
		return err
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	return &ComputePurchaseAnswer{Allowed: len(breaches) == 0, Breaches: breaches}, nil
}

// The most searches networkId may make a UTC day by URnetwork's limit (§9.11), whatever its policy's day_max says
// beneath it: the override URnetwork's review set, else 200 until 7 days after its oldest unreversed paid lot, then
// 2,000. A network with no paid lot takes the new account's.
func ComputeSearchCap(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (int64, error) {
	clock, err := env.Clock()
	if err != nil {
		return 0, err
	}
	db, err := env.Db()
	if err != nil {
		return 0, err
	}
	searchCap := int64(0)
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		account, err := model.ComputeAccountInTx(env, ctx, tx, networkId)
		if err != nil {
			return err
		}
		if account != nil && account.SearchCapOverride != nil {
			searchCap = *account.SearchCapOverride
			return nil
		}
		paid, err := model.ComputePaidLotsInTx(env, ctx, tx, networkId)
		if err != nil {
			return err
		}
		searchCap = settings.SearchCapNew
		if paid.OldestTime != nil && !clock.Now().Before(paid.OldestTime.Add(settings.SearchCapAge)) {
			searchCap = settings.SearchCapEstablished
		}
		return nil
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	return searchCap, err
}

// What enclaves a network may run by §9.11's new-account gates.
type ComputeEnclaveAllowance struct {
	// Its CPU enclaves are bounded by CpuEnclaveMaxCount: until 24 hours after its first successful payment.
	CpuBounded         bool
	CpuEnclaveMaxCount int
	// It may run GPU shapes: after $50 of lifetime purchases.
	GpuShapes bool
}

// networkId's enclave allowance now (§9.11): one CPU enclave until 24 hours after its first unreversed paid lot, none
// of a GPU shape before $50 of unreversed paid lots. A network that never paid stays at one CPU enclave.
func ComputeEnclaveAllowanceOf(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (*ComputeEnclaveAllowance, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var paid *model.ComputePaidLots
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		paid, err = model.ComputePaidLotsInTx(env, ctx, tx, networkId)
		return err
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	if err != nil {
		return nil, err
	}
	allowance := &ComputeEnclaveAllowance{
		CpuBounded:         paid.OldestTime == nil || clock.Now().Before(paid.OldestTime.Add(settings.EnclaveNewAccountWait)),
		CpuEnclaveMaxCount: settings.EnclaveNewAccountCpuCount,
		GpuShapes:          settings.EnclaveGpuPurchasesNanoUsd <= paid.LifetimeNanoUsd,
	}
	if !allowance.CpuBounded {
		allowance.CpuEnclaveMaxCount = 0
	}
	return allowance, nil
}
