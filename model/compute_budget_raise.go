// Kind 21's table and the raised caps it puts in the projection (DESIGN-COMPUTE §9.7, §14.3, §14.4, §16.3, §16.4,
// compute-6; BAL-M12-16): compute_budget_raise keeps each use a compute_budget_raise decision spent at the broker's
// gate, under its effect key, with the raise it made, as DESIGN §16.6's gate keeps approval_use, and the projection
// carries each raise in force as its subject's raised cap, which every hold's budget check takes where it passes the
// line's own (compute_projection_scripts.go's cmp_check_budgets):
//
//	ComputeBudgetRaiseByEffectKeyInTx   the use a request's effect key already took, nil for none: the gate's step 1
//	ComputeBudgetRaiseClaimInTx         the first free use of the approval, its raise stored in the same row: step 2,
//	                                    a racing request with the same key answering the first's row, and none left
//	                                    ErrComputeBudgetRaiseSpent
//	ComputeBudgetRaisesInForceInTx      the network's raises the broker applies now, for a lost projection's rebuild
//	ComputeBudgetRaisePruneInTx         the rows past their expiry, which compute_rollup_day deletes (compute-6's ttl)
//	ComputeProjectionRaise              a raise's cap into its subject's counters, k:<period>, never lowering one
//
// A raise acts on one subject's budgets for one UTC day or month at the broker (§16.4): every budget line whose subject
// it is, for that period, is capped at the larger of the line's own cap and the raise. A raise of period run, and one
// naming no subject the broker reads (a gateway grant's, its grant sealed in field 38), is kept for its use and its
// record, and raises no counter: the device applies it, in the Harness's run budget or the grant's own, and its row's
// subject is the nil id. The keys serialize racing gates, never a session lock, which PgBouncer's transaction pooling
// forbids (server/model/approval_use_model.go says why); the caller's transaction runs READ COMMITTED under the
// network's fence, so a racer waits for the first's commit and then reads its row.
//
// The effect key is §16.6's SHA-256; the row's uuid column holds its first 16 bytes, which the gate derives again from
// the action and the approval before it looks or stores, so no request reads another action's row.

package model

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// Every use of the approval is taken (§16.6's 409 SPENT).
var ErrComputeBudgetRaiseSpent = errors.New("compute budget raise: every use of the approval is spent")

// A raise the table cannot take: no approval, a period §16.3 does not name, an amount out of range.
var ErrComputeBudgetRaiseArgs = errors.New("compute budget raise: arguments refused")

// The column a raise's 32-byte effect key is kept under: its first 16 bytes.
func ComputeBudgetRaiseEffectKeyId(effectKey [32]byte) operator.Id {
	var id operator.Id
	copy(id[:], effectKey[:16])
	return id
}

// Whether a raise acts at the broker: a day's or a month's, naming a subject. A run's, and one naming no subject, the
// device alone applies.
func (self *ComputeBudgetRaise) AtBroker() bool {
	return (self.Period == ComputeBudgetPeriodDay || self.Period == ComputeBudgetPeriodMonth) && self.SubjectId != (operator.Id{})
}

// compute_budget_raise's columns, in the order a scan reads them.
const computeBudgetRaiseColumns = `approval_id, approval_use, effect_key, network_id, subject_id, period, amount_nano_usd, expire_time, create_time`

func computeBudgetRaiseQuery(ctx context.Context, tx operator.DbTx, sql string, args ...any) ([]*ComputeBudgetRaise, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	raises := []*ComputeBudgetRaise{}
	for rows.Next() {
		raise := &ComputeBudgetRaise{}
		var period int16
		err := rows.Scan(&raise.ApprovalId, &raise.ApprovalUse, &raise.EffectKey, &raise.NetworkId, &raise.SubjectId, &period,
			&raise.AmountNanoUsd, &raise.ExpireTime, &raise.CreateTime)
		if err != nil {
			return nil, err
		}
		raise.Period = ComputeBudgetPeriod(period)
		raise.ExpireTime, raise.CreateTime = raise.ExpireTime.UTC(), raise.CreateTime.UTC()
		raises = append(raises, raise)
	}
	return raises, rows.Err()
}

// The use networkId's effect key took, in tx; nil where none stands. A row of the key in another network is no use of
// this one's.
func ComputeBudgetRaiseByEffectKeyInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, effectKey operator.Id) (*ComputeBudgetRaise, error) {
	raises, err := computeBudgetRaiseQuery(ctx, tx, `SELECT `+computeBudgetRaiseColumns+` FROM compute_budget_raise WHERE effect_key = $1 AND network_id = $2`,
		effectKey, networkId)
	if err != nil || len(raises) == 0 {
		return nil, err
	}
	return raises[0], nil
}

// Claims the first free of uses of raise's approval in tx, storing raise in its row (see the file header): the row
// that stands for raise's effect key afterwards, and whether this call took it. A racing request with the same key
// that committed first answers with its row and taken false; with no use left and no row of the key,
// ErrComputeBudgetRaiseSpent.
func ComputeBudgetRaiseClaimInTx(env operator.Env, ctx context.Context, tx operator.DbTx, raise *ComputeBudgetRaise, uses uint32) (*ComputeBudgetRaise, bool, error) {
	var zero operator.Id
	if raise.ApprovalId == zero || raise.EffectKey == zero || raise.NetworkId == zero || uses == 0 {
		return nil, false, fmt.Errorf("%w: a raise names its approval, its key and its network, with a use", ErrComputeBudgetRaiseArgs)
	}
	if raise.Period != ComputeBudgetPeriodDay && raise.Period != ComputeBudgetPeriodMonth && raise.Period != ComputeBudgetPeriodRun {
		return nil, false, fmt.Errorf("%w: period %s", ErrComputeBudgetRaiseArgs, raise.Period)
	}
	if raise.AmountNanoUsd <= 0 || computeLuaMaxExactInteger < raise.AmountNanoUsd {
		return nil, false, fmt.Errorf("%w: an amount out of range", ErrComputeBudgetRaiseArgs)
	}
	rows, err := tx.Query(ctx, `SELECT approval_use FROM compute_budget_raise WHERE approval_id = $1`, raise.ApprovalId)
	if err != nil {
		return nil, false, err
	}
	taken := []int32{}
	for rows.Next() {
		var use int32
		if err := rows.Scan(&use); err != nil {
			rows.Close()
			return nil, false, err
		}
		taken = append(taken, use)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	for use := int32(0); use < int32(min(uses, uint32(1<<31-1))); use += 1 {
		if slices.Contains(taken, use) {
			continue
		}
		claimed, err := computeBudgetRaiseQuery(ctx, tx, `
			INSERT INTO compute_budget_raise (`+computeBudgetRaiseColumns+`)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT DO NOTHING
			RETURNING `+computeBudgetRaiseColumns,
			raise.ApprovalId, use, raise.EffectKey, raise.NetworkId, raise.SubjectId, int16(raise.Period), raise.AmountNanoUsd,
			raise.ExpireTime.UTC(), raise.CreateTime.UTC())
		if err != nil {
			return nil, false, err
		}
		if len(claimed) == 1 {
			return claimed[0], true, nil
		}
		// a racer took this use, or committed this key under another
	}
	stands, err := ComputeBudgetRaiseByEffectKeyInTx(env, ctx, tx, raise.NetworkId, raise.EffectKey)
	if err != nil {
		return nil, false, err
	}
	if stands != nil {
		return stands, false, nil
	}
	return nil, false, ErrComputeBudgetRaiseSpent
}

// networkId's raises in force at now, in tx, on its (network_id, subject_id, expire_time) index: every day's and
// month's raise naming a subject whose expiry has not passed. What a lost projection's rebuild writes back.
func ComputeBudgetRaisesInForceInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, now time.Time) ([]*ComputeBudgetRaise, error) {
	return computeBudgetRaiseQuery(ctx, tx, `
		SELECT `+computeBudgetRaiseColumns+` FROM compute_budget_raise
		WHERE network_id = $1 AND subject_id <> $2 AND expire_time > $3 AND period IN ($4, $5)
		ORDER BY subject_id, period, create_time
	`, networkId, operator.Id{}, now.UTC(), int16(ComputeBudgetPeriodDay), int16(ComputeBudgetPeriodMonth))
}

// Deletes the raises whose expiry is before before, in tx: a raise is kept until its expiry (compute-6), which is
// never before its decision's, so a replay past the delete meets an expired decision at the gate and spends nothing.
func ComputeBudgetRaisePruneInTx(env operator.Env, ctx context.Context, tx operator.DbTx, before time.Time) (int64, error) {
	result, err := tx.Exec(ctx, `DELETE FROM compute_budget_raise WHERE expire_time < $1`, before.UTC())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected, nil
}

// A raise's field in its subject's counters, k:<period>, beside the counters' r: and c: fields: its UTC day's or month's.
func ComputeBudgetRaiseField(period ComputeBudgetPeriod, at time.Time) (string, error) {
	field, err := ComputeBudgetPeriodField(period, at)
	if err != nil {
		return "", err
	}
	return "k:" + field, nil
}

// Puts raise's cap into its subject's counters for the UTC day or month it was taken in, never lowering a cap the
// field holds (§16.4): what a hold's budget check takes where it passes a line's own. absent where the network has no
// projection, which its rebuild writes with every raise in force. A raise the broker does not apply writes nothing.
func ComputeProjectionRaise(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, raise *ComputeBudgetRaise) (ComputeScriptOutcome, error) {
	if !raise.AtBroker() {
		return "", fmt.Errorf("%w: a run's raise or one naming no subject raises no counter", ErrComputeBudgetRaiseArgs)
	}
	if err := computeProjectionAmount("a raised cap", raise.AmountNanoUsd); err != nil {
		return "", err
	}
	field, err := ComputeBudgetPeriodField(raise.Period, raise.CreateTime)
	if err != nil {
		return "", err
	}
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return "", err
	}
	projectionKey := ComputeProjectionKey(raise.NetworkId)
	reply, err := redis.RunScript(ctx, computeProjectionRaiseScript,
		[]string{projectionKey, computeUnconfirmedKey(raise.NetworkId), computeBudgetKeyOf(projectionKey, raise.SubjectId)},
		[]string{
			fmt.Sprintf("%x", raise.SubjectId[:]),
			field,
			strconv.FormatInt(raise.AmountNanoUsd, 10),
			computeMillis(settings.BudgetCounterTtl),
		})
	if err != nil {
		return "", err
	}
	return computeScriptOutcome(reply, ComputeScriptRaised, ComputeScriptAbsent)
}

// What a raise's script came to: its cap stands in the subject's counters.
const ComputeScriptRaised ComputeScriptOutcome = "raised"
