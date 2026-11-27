// GET api/compute/balance's figures (DESIGN-COMPUTE §9.7, §9.9, §14.3; BAL-M12-15): a network's balance as its
// PostgreSQL ledger holds it, read in one REPEATABLE READ snapshot, so the figures are of one moment:
//
//	available   settled less unsettled charges less open holds: what admission reads (§9.7)
//	held        the open operations' holds, a running enclave's current interval among them, shown apart (§9.13)
//	balance     settled less unsettled charges less the running enclaves' time accrued in their current interval,
//	            holds left out: what auto-renew and §9.9's states read (D-BAL-9); accrued is BAL-M14-01's, zero until
//	            it lands
//	promo       the unexpired promotional credit left, which pays no search (§9.11)
//	state       §9.9's, as compute_suspend last set it; a network with no account reads active, version 0
//
// From low on, §9.9's notice also names the enclaves a suspension would stop and the days the network's indexer
// enclave's reserve and grace leave, which ENC's rates give (ComputeEnclaveRates); none registered names none.
//
// The figures come from PostgreSQL, not the projection: the projection admits, while this answers a person, and a
// committed row is the record of a hold or a charge (§9.7). An unconfirmed hold the projection holds in its first
// moments is not here yet; its row commits before its call is forwarded.

package controller

import (
	"context"
	"slices"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// A network's balance as the route answers it.
type ComputeBalanceState struct {
	AvailableNanoUsd int64
	HeldNanoUsd      int64
	BalanceNanoUsd   int64
	PromoNanoUsd     int64
	State            model.ComputeAccountState
	// The account's version, which orders two reads; 0 before the network's first booking or credit.
	Version int64
	// The account's update_time: the settlement the figures are exact to; zero before any.
	UpdateTime time.Time
	// From low on: the enclaves a suspension would stop, and whole days the indexer enclave's reserve and grace leave,
	// nil where it has none (§9.9).
	AtRiskEnclaveIds []operator.Id
	IndexerDaysLeft  *int64
}

// networkId's balance now (see the file header).
func ComputeBalanceOf(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (*ComputeBalanceState, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	state := &ComputeBalanceState{}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*state = ComputeBalanceState{State: model.ComputeAccountStateActive}
		balance, err := model.ComputeAccountBalanceInTx(env, ctx, tx, settings, networkId)
		if err != nil {
			return err
		}
		held, err := model.ComputeHeldInTx(env, ctx, tx, settings, networkId, nil)
		if err != nil {
			return err
		}
		projection, err := model.ComputeAccountProjectionInTx(env, ctx, tx, networkId, now)
		if err != nil {
			return err
		}
		state.HeldNanoUsd = held
		state.BalanceNanoUsd = balance.BalanceNanoUsd
		state.AvailableNanoUsd = balance.BalanceNanoUsd - held
		state.PromoNanoUsd = projection.PromoNanoUsd
		if account := balance.Account; account != nil {
			state.State = account.State
			state.Version = account.Version
			state.UpdateTime = account.UpdateTime
		}
		return nil
	}, operator.DbIsolationRepeatableRead, operator.DbReadOnly)
	if err != nil {
		return nil, err
	}
	state.AtRiskEnclaveIds = []operator.Id{}
	if state.State != model.ComputeAccountStateActive {
		// ENC's rates, read after the transaction so no snapshot waits on them
		rates, err := computeRatesOf(env, ctx, networkId)
		if err != nil {
			return nil, err
		}
		state.AtRiskEnclaveIds = slices.Clone(rates.StoppableEnclaveIds)
		if state.AtRiskEnclaveIds == nil {
			state.AtRiskEnclaveIds = []operator.Id{}
		}
		if rates.IndexerDaysLeft != nil {
			days := max(0, *rates.IndexerDaysLeft)
			state.IndexerDaysLeft = &days
		}
	}
	return state, nil
}
