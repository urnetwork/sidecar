// §9.9's states' reads and writes (DESIGN-COMPUTE §9.7, §9.9, D-BAL-9; BAL-M12-12), and the balance auto-renew reads
// too (BAL-M12-11), each in the caller's transaction:
//
//	ComputeAccountBalanceInTx    the balance the states and auto-renew read: the account's settled less its settled
//	                             operations not yet booked, holds left out (and the running enclaves' time accrued in
//	                             their current interval, BAL-M14-01's, zero until it lands)
//	ComputeChargesSinceInTx      what a network was charged since a time, adjustments and refunds left out: §9.9's burn
//	ComputeAccountReviewInTx     an account locked with when it entered its state, for compute_suspend
//	ComputeAccountStateSetInTx   its state and floor moved, the version raised, the state's time set on a change
//	ComputeSuspendCandidates     compute_suspend's cursor: the accounts not active, and those whose update_time moved
//	                             within the lookback, closed ones never
//	ComputeAccountStateCounts    the accounts by state, for §14.7's gauge
//
// The balance comes from PostgreSQL, under the network's fence where the caller takes it, so a state is read from the
// same committed account bookings write, never from a projection a failover may have lost. The day is the UTC day.

package model

import (
	"context"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// The balance the states and auto-renew read (§9.7, D-BAL-9).
type ComputeAccountBalance struct {
	// The network's account, nil where it has none, which reads nothing settled.
	Account *ComputeAccount
	// The settled balance, as bookings committed it.
	SettledNanoUsd int64
	// The settled operations not yet booked: their charges, a refund's negative.
	UnsettledNanoUsd int64
	// settled less unsettled, holds left out: what a hold, a worst case, never moves.
	BalanceNanoUsd int64
}

// networkId's balance in tx (see the file header).
func ComputeAccountBalanceInTx(env operator.Env, ctx context.Context, tx operator.DbTx, settings *ComputeLedgerSettings, networkId operator.Id) (*ComputeAccountBalance, error) {
	account, err := ComputeAccountInTx(env, ctx, tx, networkId)
	if err != nil {
		return nil, err
	}
	balance := &ComputeAccountBalance{Account: account}
	if account == nil {
		return balance, nil
	}
	balance.SettledNanoUsd = account.SettledNanoUsd
	// the shard's index finds the network's settled rows, which compute_settle books within seconds
	rows, err := tx.Query(ctx, `
		SELECT coalesce(sum((outcome->>'amount_nano_usd')::bigint), 0)::bigint FROM compute_op
		WHERE shard = $1 AND state = $2 AND network_id = $3
	`, ComputeOpShard(settings, networkId), int16(ComputeOpStateSettled), networkId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&balance.UnsettledNanoUsd); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	balance.BalanceNanoUsd = balance.SettledNanoUsd - balance.UnsettledNanoUsd
	return balance, nil
}

// What networkId was charged for calls, searches and enclaves since since, in tx: its positive charges, a refund and
// an adjustment left out, on the network's (network_id, start_time) index.
func ComputeChargesSinceInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, since time.Time) (int64, error) {
	rows, err := tx.Query(ctx, `
		SELECT coalesce(sum(amount_nano_usd), 0)::bigint FROM compute_charge
		WHERE network_id = $1 AND start_time >= $2 AND amount_nano_usd > 0 AND kind <> $3
	`, networkId, since.UTC(), int16(ComputeChargeKindAdjustment))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	charged := int64(0)
	if rows.Next() {
		if err := rows.Scan(&charged); err != nil {
			return 0, err
		}
	}
	return charged, rows.Err()
}

// An account as compute_suspend reviews it: the row, locked, and when it entered its state.
type ComputeAccountReview struct {
	Account *ComputeAccount
	// When the account entered its state; nil where no change of compute_suspend's set it.
	StateTime *time.Time
}

// networkId's account in tx, locked FOR UPDATE, with its state's time; nil for a network with none, which has nothing
// to review.
func ComputeAccountReviewInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) (*ComputeAccountReview, error) {
	accounts, err := computeAccountQuery(ctx, tx, `SELECT `+computeAccountColumns+` FROM compute_account WHERE network_id = $1 FOR UPDATE`, networkId)
	if err != nil || len(accounts) == 0 {
		return nil, err
	}
	review := &ComputeAccountReview{Account: accounts[0]}
	rows, err := tx.Query(ctx, `SELECT state_time FROM compute_account WHERE network_id = $1`, networkId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&review.StateTime); err != nil {
			return nil, err
		}
	}
	if review.StateTime != nil {
		stateTime := review.StateTime.UTC()
		review.StateTime = &stateTime
	}
	return review, rows.Err()
}

// Sets networkId's state and floor in tx, its version raised by one and update_time now; where the state changes, its
// state_time is now. The account as it stands after.
func ComputeAccountStateSetInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, state ComputeAccountState, floorNanoUsd int64, now time.Time) (*ComputeAccount, error) {
	if !state.Valid() || floorNanoUsd < 0 || computeLuaMaxExactInteger < floorNanoUsd {
		return nil, fmt.Errorf("%w: a state and a floor of zero or more", ErrComputeLotArgs)
	}
	accounts, err := computeAccountQuery(ctx, tx, `
		UPDATE compute_account SET
			state_time = CASE WHEN state = $2 THEN state_time ELSE $4 END,
			state = $2,
			negative_floor_nano_usd = $3,
			version = version + 1,
			update_time = $4
		WHERE network_id = $1
		RETURNING `+computeAccountColumns,
		networkId, int16(state), floorNanoUsd, now.UTC())
	if err != nil {
		return nil, err
	}
	if len(accounts) != 1 {
		return nil, fmt.Errorf("compute state: the network has no account to set")
	}
	return accounts[0], nil
}

// Up to limit accounts compute_suspend examines, past after, nil for the first, in network order: every account
// neither active nor closed, and every one whose update_time is at or after since; never a closed one.
func ComputeSuspendCandidates(env operator.Env, ctx context.Context, since time.Time, after *operator.Id, limit int) ([]operator.Id, error) {
	if limit <= 0 {
		return []operator.Id{}, nil
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	networkIds := []operator.Id{}
	err = db.Db(ctx, func(conn operator.DbConn) error {
		networkIds = networkIds[:0]
		sql := `
			SELECT network_id FROM compute_account
			WHERE state <> $1 AND (state <> $2 OR update_time >= $3)`
		args := []any{int16(ComputeAccountStateClosed), int16(ComputeAccountStateActive), since.UTC()}
		if after != nil {
			sql += ` AND network_id > $4`
			args = append(args, *after)
		}
		sql += fmt.Sprintf(` ORDER BY network_id LIMIT %d`, limit)
		rows, err := conn.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var networkId operator.Id
			if err := rows.Scan(&networkId); err != nil {
				return err
			}
			networkIds = append(networkIds, networkId)
		}
		return rows.Err()
	})
	return networkIds, err
}

// The accounts by state, for §14.7's gauge of accounts by §9.9's state.
func ComputeAccountStateCounts(env operator.Env, ctx context.Context) (map[ComputeAccountState]int64, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	counts := map[ComputeAccountState]int64{}
	err = db.Db(ctx, func(conn operator.DbConn) error {
		clear(counts)
		rows, err := conn.Query(ctx, `SELECT state, count(*) FROM compute_account GROUP BY state`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var state int16
			var count int64
			if err := rows.Scan(&state, &count); err != nil {
				return err
			}
			counts[ComputeAccountState(state)] = count
		}
		return rows.Err()
	})
	return counts, err
}
