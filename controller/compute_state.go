// Low balance, grace and suspension (DESIGN-COMPUTE §9.9, D-BAL-5, D-BAL-9, IC-5, CF-12; BAL-M12-12): §9.9's states,
// which compute_suspend sets each minute and a credit sets at once, from the balance holds leave out, so one open hold
// moves no state (R1-33):
//
//	active     the balance at least 24 h of the network's burn, and at least T
//	low        under 24 h of burn, or under T: the billing contacts emailed
//	grace      at or under zero: new remote calls and searches refused (402 COMPUTE_BALANCE), which the projection's
//	           state makes the hold script do; running enclaves keep running down to the floor
//	suspended  at or under minus the floor (R1-46: at -floor, never at the floor), or grace older than the settings'
//	           hour, or a chargeback's suspension, which stands until a person's review (§9.11): remote inference
//	           refused and enclaves stopped through ComputeSuspendListener
//	closed     the network deleted (compute_close.go): nothing moves it again
//
// The floor is the smaller of the settings' $5 and an hour of the network's running enclaves' rates, written to the
// account and the projection; burn is the trailing 24 h of charges, or the running enclaves' hourly rates times 24 if
// larger, those rates ENC's (ComputeEnclaveRates, C§11.6), zero until it registers, so the M12 floor is zero and a
// balance at zero is suspended. A balance lifted above zero returns the account to active or low at once and asks the
// listener to restart what suspension stopped (ComputeSuspendListener.Resumed, C§11.11).
//
// Each change happens in one transaction under the network's fence with its account locked, so two workers never set
// one change twice; it raises the account's version, owes the notice of a move into low, grace or suspended to the
// billing contacts under a key of that version, then takes the account into the projection through the drop script's
// version guard and hints every member device on the compute topic (QD-1238). From low on, a notice names the
// enclaves a suspension would stop and the days the network's indexer enclave's reserve and grace leave (BAL-M14-02's,
// through the rates' seam). Local inference reads none of this and runs in every state (CO-9, IC-5).

package controller

import (
	"context"
	"math/big"
	"strconv"
	"sync"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// What the running enclaves of a network cost and hold (ENC's, C§11.6, C§11.10).
type ComputeEnclaveRateSet struct {
	// Their rates in all, the indexer's among them, in nano-USD an hour.
	HourlyNanoUsd int64
	// The enclaves a suspension would stop: every running one but the network's indexer enclave (§9.9).
	StoppableEnclaveIds []operator.Id
	// Whole days the network's indexer enclave's reserve and grace leave, nil where it has none (BAL-M14-02).
	IndexerDaysLeft *int64
}

// The running enclaves' rates by network: ENC's (C§11.6), which registers it. None registered reads zero, so the
// floor is zero and burn is the charges alone until M14.
type ComputeEnclaveRates interface {
	Rates(env operator.Env, ctx context.Context, networkId operator.Id) (*ComputeEnclaveRateSet, error)
}

// What suspension stops and a top-up restarts: ENC's (C§11.11), which registers it. None registered stops nothing,
// since no enclave runs before M14. Each call is idempotent: a network suspended, or resumed, twice does it once.
type ComputeSuspendListener interface {
	// Stops every enclave of networkId but its indexer enclave, which runs on its reserve and grace (§9.9).
	Suspended(env operator.Env, ctx context.Context, networkId operator.Id) error
	// Restarts what suspension stopped, as new incarnations, by their keepers or sponsors (§9.9, §11.11).
	Resumed(env operator.Env, ctx context.Context, networkId operator.Id) error
}

var (
	computeStateLock    sync.Mutex
	computeEnclaveRates ComputeEnclaveRates
	computeSuspendTaker ComputeSuspendListener
)

// Registers ENC's rates from its own file. A second registration, or a nil one, panics.
func RegisterComputeEnclaveRates(rates ComputeEnclaveRates) {
	if rates == nil {
		panic("compute state: nil enclave rates")
	}
	computeStateLock.Lock()
	defer computeStateLock.Unlock()
	if computeEnclaveRates != nil {
		panic("compute state: the enclave rates are registered once")
	}
	computeEnclaveRates = rates
}

// Registers ENC's suspension listener from its own file. A second registration, or a nil one, panics.
func RegisterComputeSuspendListener(listener ComputeSuspendListener) {
	if listener == nil {
		panic("compute state: nil suspend listener")
	}
	computeStateLock.Lock()
	defer computeStateLock.Unlock()
	if computeSuspendTaker != nil {
		panic("compute state: the suspend listener is registered once")
	}
	computeSuspendTaker = listener
}

func computeRegisteredEnclaveRates() ComputeEnclaveRates {
	computeStateLock.Lock()
	defer computeStateLock.Unlock()
	return computeEnclaveRates
}

func computeRegisteredSuspendListener() ComputeSuspendListener {
	computeStateLock.Lock()
	defer computeStateLock.Unlock()
	return computeSuspendTaker
}

// The alarm kind of a suspension or resumption the listener did not take: the next change, or a person, makes it good.
const ComputeAlarmSuspendListener = "suspend_listener"

// The accounts gauge, by state, which §14.7's ledger family reads.
const computeAccountsMetric = "urnetwork_compute_accounts"

// networkId's running enclaves' rates, zero where ENC registered none.
func computeRatesOf(env operator.Env, ctx context.Context, networkId operator.Id) (*ComputeEnclaveRateSet, error) {
	rates := computeRegisteredEnclaveRates()
	if rates == nil {
		return &ComputeEnclaveRateSet{}, nil
	}
	set, err := rates.Rates(env, ctx, networkId)
	if err != nil {
		return nil, err
	}
	if set == nil || set.HourlyNanoUsd < 0 {
		return &ComputeEnclaveRateSet{}, nil
	}
	return set, nil
}

// amount × numerator ÷ denominator, rounded down, in exact integer arithmetic, capped at the largest int64; zero for a
// denominator that is not positive.
func computeScaleNanoUsd(amount int64, numerator time.Duration, denominator time.Duration) int64 {
	if denominator <= 0 || amount <= 0 || numerator <= 0 {
		return 0
	}
	scaled := new(big.Int).Mul(big.NewInt(amount), big.NewInt(int64(numerator)))
	scaled.Quo(scaled, big.NewInt(int64(denominator)))
	if !scaled.IsInt64() {
		return int64(^uint64(0) >> 1)
	}
	return scaled.Int64()
}

// §9.9's floor for hourly rates: the smaller of the settings' $5 and the settings' hour of the rates.
func computeFloorOf(settings *model.ComputeLedgerSettings, hourlyNanoUsd int64) int64 {
	return min(settings.FloorMaxNanoUsd, computeScaleNanoUsd(hourlyNanoUsd, settings.FloorEnclaveTime, time.Hour))
}

// §9.9's burn: charged over the burn window, or the hourly rates over it if larger.
func computeBurnOf(settings *model.ComputeLedgerSettings, chargedNanoUsd int64, hourlyNanoUsd int64) int64 {
	return max(chargedNanoUsd, computeScaleNanoUsd(hourlyNanoUsd, settings.BurnWindow, time.Hour))
}

// networkId's floor now (§9.9): the smaller of $5 and an hour of its running enclaves' rates, zero until ENC registers
// them.
func ComputeFloor(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (int64, error) {
	rates, err := computeRatesOf(env, ctx, networkId)
	if err != nil {
		return 0, err
	}
	return computeFloorOf(settings, rates.HourlyNanoUsd), nil
}

// networkId's burn now (§9.9): the trailing 24 h of its charges, or its running enclaves' hourly rates times 24 if
// larger.
func ComputeBurn(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (int64, error) {
	clock, err := env.Clock()
	if err != nil {
		return 0, err
	}
	rates, err := computeRatesOf(env, ctx, networkId)
	if err != nil {
		return 0, err
	}
	db, err := env.Db()
	if err != nil {
		return 0, err
	}
	charged := int64(0)
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		charged, err = model.ComputeChargesSinceInTx(env, ctx, tx, networkId, clock.Now().Add(-settings.BurnWindow))
		return err
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	if err != nil {
		return 0, err
	}
	return computeBurnOf(settings, charged, rates.HourlyNanoUsd), nil
}

// networkId's state as its account holds it (§9.9): what the broker refuses by, through the projection the account's
// changes reach. A network with no account is active: it has no balance, which refuses every hold by itself.
func ComputeAccountStateOf(env operator.Env, ctx context.Context, networkId operator.Id) (model.ComputeAccountState, error) {
	account, err := model.ComputeAccountGet(env, ctx, networkId)
	if err != nil {
		return 0, err
	}
	if account == nil {
		return model.ComputeAccountStateActive, nil
	}
	return account.State, nil
}

// The state an account moves to (see the file header): from current, its balance, the balance under which it is low
// (24 h of burn), T, the floor, when it entered current, and whether a chargeback suspended it.
func computeStateTarget(settings *model.ComputeLedgerSettings, current model.ComputeAccountState, balance int64, lowBelow int64, below int64, floor int64, stateTime *time.Time, now time.Time, chargeback bool) model.ComputeAccountState {
	switch {
	case current == model.ComputeAccountStateClosed:
		return model.ComputeAccountStateClosed
	case chargeback:
		return model.ComputeAccountStateSuspended
	case 0 < balance:
		if balance < lowBelow || balance < below {
			return model.ComputeAccountStateLow
		}
		return model.ComputeAccountStateActive
	case current == model.ComputeAccountStateSuspended || balance <= -floor:
		return model.ComputeAccountStateSuspended
	case current == model.ComputeAccountStateGrace && stateTime != nil && !now.Before(stateTime.Add(settings.GraceMaxAge)):
		return model.ComputeAccountStateSuspended
	}
	return model.ComputeAccountStateGrace
}

// The notice a move into state owes, "" for none: low, grace and suspended each email the billing contacts.
func computeStateNoticeKind(state model.ComputeAccountState) ComputeNoticeKind {
	switch state {
	case model.ComputeAccountStateLow:
		return ComputeNoticeLow
	case model.ComputeAccountStateGrace:
		return ComputeNoticeGrace
	case model.ComputeAccountStateSuspended:
		return ComputeNoticeSuspended
	}
	return ""
}

// What one account's review came to.
type ComputeStateChange struct {
	NetworkId operator.Id
	From      model.ComputeAccountState
	To        model.ComputeAccountState
	// The balance it read, holds left out, its burn over 24 h and the floor it wrote.
	BalanceNanoUsd int64
	BurnNanoUsd    int64
	FloorNanoUsd   int64
	// Whether the state or the floor changed, and the account's version after.
	Changed bool
	Version int64
	// Whether the projection took the change; where it did not, a worse state marked it for a rebuild.
	Projected bool
}

// Reviews networkId's account now (see the file header): its state and floor set where they changed, the notice owed,
// the projection told, the devices hinted and the listener asked. A network with no account, or a closed one, changes
// nothing.
func ComputeSuspendEvaluate(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (*ComputeStateChange, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	// ENC's rates before the transaction, so no lock waits on its read
	rates, err := computeRatesOf(env, ctx, networkId)
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	change := &ComputeStateChange{NetworkId: networkId}
	previousFloor := int64(0)
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*change = ComputeStateChange{NetworkId: networkId}
		if err := model.ComputeFenceInTx(env, ctx, tx, networkId); err != nil {
			return err
		}
		review, err := model.ComputeAccountReviewInTx(env, ctx, tx, networkId)
		if err != nil || review == nil {
			return err
		}
		account := review.Account
		change.From, change.To, change.Version = account.State, account.State, account.Version
		previousFloor = account.NegativeFloorNanoUsd
		if account.State == model.ComputeAccountStateClosed {
			return nil
		}
		balance, err := model.ComputeAccountBalanceInTx(env, ctx, tx, settings, networkId)
		if err != nil {
			return err
		}
		charged, err := model.ComputeChargesSinceInTx(env, ctx, tx, networkId, now.Add(-settings.BurnWindow))
		if err != nil {
			return err
		}
		threshold, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, networkId, model.ComputeAutoRenewModeThreshold, false)
		if err != nil {
			return err
		}
		chargeback, err := model.ComputeChargebackSuspendedInTx(env, ctx, tx, networkId)
		if err != nil {
			return err
		}
		change.BalanceNanoUsd = balance.BalanceNanoUsd
		change.BurnNanoUsd = computeBurnOf(settings, charged, rates.HourlyNanoUsd)
		change.FloorNanoUsd = computeFloorOf(settings, rates.HourlyNanoUsd)
		lowBelow := computeScaleNanoUsd(change.BurnNanoUsd, settings.LowBurnTime, settings.BurnWindow)
		below := computeThresholdFiguresOfRow(settings, threshold).belowNanoUsd
		change.To = computeStateTarget(settings, account.State, balance.BalanceNanoUsd, lowBelow, below, change.FloorNanoUsd, review.StateTime, now, chargeback)
		if change.To == account.State && change.FloorNanoUsd == account.NegativeFloorNanoUsd {
			return nil
		}
		testHookBarrier("compute_state.set.before", networkId.String())
		moved, err := model.ComputeAccountStateSetInTx(env, ctx, tx, networkId, change.To, change.FloorNanoUsd, now)
		if err != nil {
			return err
		}
		change.Changed = true
		change.Version = moved.Version
		kind := computeStateNoticeKind(change.To)
		if kind == "" || change.To == account.State {
			return nil
		}
		return computeNoticeInTx(env, ctx, tx, &ComputeNotice{
			NetworkId: networkId, Kind: kind, Key: "state/" + networkId.String() + "/" + strconv.FormatInt(moved.Version, 10),
			BalanceNanoUsd: balance.BalanceNanoUsd, AtRiskEnclaveIds: rates.StoppableEnclaveIds, IndexerDaysLeft: rates.IndexerDaysLeft,
		})
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	testHookBarrier("compute_state.set.after", networkId.String())
	if !change.Changed {
		return change, nil
	}
	// a worse state, or less room under zero for enclaves, marks the projection for a rebuild where it did not take
	// the change, so it admits nothing on room it no longer has
	worse := computeStateRank(change.From) < computeStateRank(change.To) || change.FloorNanoUsd < previousFloor
	change.Projected = computeProjectionRefresh(env, ctx, settings, networkId, now, worse)
	computeStateEffects(env, ctx, networkId, change.From, change.To)
	return change, nil
}

// What a committed move of networkId's state from from to to owes after its commit: every member device hinted, and
// the listener asked to stop the enclaves at a suspension, or to restart what a suspension stopped once the account
// can pay again. A listener that fails is alarmed: the next change, or a person, makes it good.
func computeStateEffects(env operator.Env, ctx context.Context, networkId operator.Id, from model.ComputeAccountState, to model.ComputeAccountState) {
	if from == to {
		return
	}
	computeHintDevices(env, ctx, networkId)
	listener := computeRegisteredSuspendListener()
	if listener == nil {
		return
	}
	switch {
	case to == model.ComputeAccountStateSuspended:
		if err := listener.Suspended(env, ctx, networkId); err != nil {
			computeAlarm(env)(ComputeAlarmSuspendListener)
		}
	case from == model.ComputeAccountStateSuspended && to.CanPay():
		if err := listener.Resumed(env, ctx, networkId); err != nil {
			computeAlarm(env)(ComputeAlarmSuspendListener)
		}
	}
}

// Owes in tx the notice of a suspension a chargeback made (§9.11, ComputeReverseLot), as a change of compute_suspend's
// owes one, keyed by the account's version after it; an account suspended already owes none.
func computeChargebackSuspendedInTx(env operator.Env, ctx context.Context, tx operator.DbTx, before *model.ComputeAccount, after *model.ComputeAccount) error {
	if before.State == model.ComputeAccountStateSuspended || after.State != model.ComputeAccountStateSuspended {
		return nil
	}
	return computeNoticeInTx(env, ctx, tx, &ComputeNotice{
		NetworkId: after.NetworkId, Kind: ComputeNoticeSuspended, BalanceNanoUsd: after.SettledNanoUsd,
		Key: "state/" + after.NetworkId.String() + "/" + strconv.FormatInt(after.Version, 10),
	})
}

// How far a state stands from paying: active 0, low 1, grace 2, suspended 3, closed 4.
func computeStateRank(state model.ComputeAccountState) int {
	switch state {
	case model.ComputeAccountStateActive:
		return 0
	case model.ComputeAccountStateLow:
		return 1
	case model.ComputeAccountStateGrace:
		return 2
	case model.ComputeAccountStateSuspended:
		return 3
	}
	return 4
}

// A review at once of an account a credit or a reversal moved (§9.9's "at once"): a failure is no error, since
// compute_suspend's next run reviews the account again, its update_time having moved.
func computeStateReview(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) {
	ComputeSuspendEvaluate(env, ctx, settings, networkId)
}

// What one run of compute_suspend did.
type ComputeSuspendRunResult struct {
	// Where the next run continues, a full batch having been examined; nil once the pass reached its end.
	Cursor *operator.Id
	// Accounts examined, and those whose state or floor changed.
	AccountCount int
	ChangedCount int
}

// Runs one batch of compute_suspend from cursor, nil beginning a pass (see the file header): the accounts the cursor
// finds reviewed one by one, a failure leaving its account for the next run. A pass's first batch sets the accounts
// gauge by state.
func ComputeSuspendRun(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, cursor *operator.Id) (*ComputeSuspendRunResult, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	if cursor == nil {
		computeAccountsGauge(env, ctx)
	}
	networkIds, err := model.ComputeSuspendCandidates(env, ctx, clock.Now().Add(-settings.SuspendLookback), cursor, settings.SuspendBatchCount)
	if err != nil {
		return nil, err
	}
	result := &ComputeSuspendRunResult{}
	var firstErr error
	for _, networkId := range networkIds {
		change, err := ComputeSuspendEvaluate(env, ctx, settings, networkId)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		result.AccountCount += 1
		if change.Changed {
			result.ChangedCount += 1
		}
	}
	if len(networkIds) == settings.SuspendBatchCount && 0 < len(networkIds) {
		last := networkIds[len(networkIds)-1]
		result.Cursor = &last
	}
	return result, firstErr
}

// Sets the accounts gauge by state where env holds metrics; a failed count leaves it as it stood.
func computeAccountsGauge(env operator.Env, ctx context.Context) {
	metrics, err := env.Metrics()
	if err != nil {
		return
	}
	counts, err := model.ComputeAccountStateCounts(env, ctx)
	if err != nil {
		return
	}
	gauge := metrics.Gauge(computeAccountsMetric, "compute accounts by §9.9's state", "state")
	for state := model.ComputeAccountStateActive; state <= model.ComputeAccountStateClosed; state += 1 {
		gauge.Set(float64(counts[state]), state.String())
	}
}
