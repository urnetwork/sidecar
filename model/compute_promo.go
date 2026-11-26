// Promotion codes' rows and the failed attempts' counter (DESIGN-COMPUTE §9.11, §14.4, §14.5, compute-2, D-BAL-12;
// BAL-M12-13), which the controller's compute_promo.go runs:
//
//	ComputePromoCodeInsertInTx         a code, by its keyed hash: a hash that stands is ErrComputePromoCodeTaken
//	ComputePromoCodeByHashInTx         the code of a hash, locked, so its count and cap move under the lock
//	ComputePromoCodeCountInTx          a redemption counted to its code
//	ComputePromoRedemptionInTx         a network's redemption of a code, and the network's latest of any
//	ComputePromoRedemptionInsertInTx   a redemption, unique per code and network
//	ComputeLotGetInTx                  a redemption's lot, which a retry answers
//	ComputePromoLapsing                the promotional lots past their expiry with something left, oldest first
//	ComputePromoFailureKey             {cmpk_<network_id>}: a network's failed codes, by UTC day
//	ComputePromoFailures, ComputePromoFailureAdd   the UTC day's count read and raised
//
// A code is never kept in clear: compute_promo_code holds a keyed hash of it, its case folded (the controller's), with
// its campaign, value, cap, count, last day, the operator and the reason, and nothing here logs a hash or a code.
//
// {cmpk_<network_id>} is a hash of UTC days to that day's failed codes, its key living a day past its last write, so a
// count belongs to its day whatever the clocks say about midnight, and no day's count carries into the next. Every call
// names the one key, so each is one slot (host_redis.go's rule).

package model

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	operator "github.com/urnetwork/operator-core"
)

var (
	// A code's hash that stands already: the operator draws or names another.
	ErrComputePromoCodeTaken = errors.New("compute promo: a code with this hash stands")
	// A code or redemption the ledger cannot take.
	ErrComputePromoArgs = errors.New("compute promo: arguments refused")
)

// compute_promo_code's columns, in the order computePromoCodeScan reads them.
const computePromoCodeColumns = `code_id, code_hash, campaign, amount_nano_usd, redeem_max_count, redeem_count, last_day::text,
	paid_lot_required, created_by, reason, create_time`

func computePromoCodeQuery(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) ([]*ComputePromoCode, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	codes := []*ComputePromoCode{}
	for rows.Next() {
		code := &ComputePromoCode{}
		var lastDay string
		err := rows.Scan(&code.CodeId, &code.CodeHash, &code.Campaign, &code.AmountNanoUsd, &code.RedeemMaxCount, &code.RedeemCount,
			&lastDay, &code.PaidLotRequired, &code.CreatedBy, &code.Reason, &code.CreateTime)
		if err != nil {
			return nil, err
		}
		day, err := time.ParseInLocation(computeDayLayout, lastDay, time.UTC)
		if err != nil {
			return nil, err
		}
		code.LastDay = day
		code.CreateTime = code.CreateTime.UTC()
		codes = append(codes, code)
	}
	return codes, rows.Err()
}

// Inserts code in tx; a hash that stands answers ErrComputePromoCodeTaken and inserts nothing.
func ComputePromoCodeInsertInTx(env operator.Env, ctx context.Context, tx operator.DbTx, code *ComputePromoCode) error {
	if len(code.CodeHash) == 0 || code.AmountNanoUsd <= 0 || code.RedeemMaxCount <= 0 || code.Campaign == "" || code.CreatedBy == "" || code.Reason == "" {
		return fmt.Errorf("%w: a code has its hash, value, cap, campaign, operator and reason", ErrComputePromoArgs)
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO compute_promo_code (code_id, code_hash, campaign, amount_nano_usd, redeem_max_count, redeem_count, last_day,
			paid_lot_required, created_by, reason, create_time)
		VALUES ($1, $2, $3, $4, $5, 0, $6::date, $7, $8, $9, $10)
		ON CONFLICT (code_hash) DO NOTHING
	`, code.CodeId, code.CodeHash, code.Campaign, code.AmountNanoUsd, code.RedeemMaxCount, ComputeUtcDay(code.LastDay).Format(computeDayLayout),
		code.PaidLotRequired, code.CreatedBy, code.Reason, code.CreateTime.UTC())
	if err != nil {
		return err
	}
	if result.RowsAffected != 1 {
		return ErrComputePromoCodeTaken
	}
	return nil
}

// The code of codeHash in tx, locked FOR UPDATE; nil for none.
func ComputePromoCodeByHashInTx(env operator.Env, ctx context.Context, tx operator.DbTx, codeHash []byte) (*ComputePromoCode, error) {
	codes, err := computePromoCodeQuery(ctx, tx, `SELECT `+computePromoCodeColumns+` FROM compute_promo_code WHERE code_hash = $1 FOR UPDATE`, codeHash)
	if err != nil || len(codes) == 0 {
		return nil, err
	}
	return codes[0], nil
}

// Counts one redemption to codeId in tx.
func ComputePromoCodeCountInTx(env operator.Env, ctx context.Context, tx operator.DbTx, codeId operator.Id) error {
	result, err := tx.Exec(ctx, `UPDATE compute_promo_code SET redeem_count = redeem_count + 1 WHERE code_id = $1`, codeId)
	if err != nil {
		return err
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("%w: no code %s", ErrComputePromoArgs, codeId)
	}
	return nil
}

// compute_promo_redemption's columns, in the order computePromoRedemptionQuery reads them.
const computePromoRedemptionColumns = `redemption_id, code_id, network_id, lot_id, sidecar_id, redeem_time`

func computePromoRedemptionQuery(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) ([]*ComputePromoRedemption, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	redemptions := []*ComputePromoRedemption{}
	for rows.Next() {
		redemption := &ComputePromoRedemption{}
		if err := rows.Scan(&redemption.RedemptionId, &redemption.CodeId, &redemption.NetworkId, &redemption.LotId, &redemption.SidecarId, &redemption.RedeemTime); err != nil {
			return nil, err
		}
		redemption.RedeemTime = redemption.RedeemTime.UTC()
		redemptions = append(redemptions, redemption)
	}
	return redemptions, rows.Err()
}

// networkId's redemption of codeId in tx, nil for none.
func ComputePromoRedemptionInTx(env operator.Env, ctx context.Context, tx operator.DbTx, codeId operator.Id, networkId operator.Id) (*ComputePromoRedemption, error) {
	redemptions, err := computePromoRedemptionQuery(ctx, tx, `
		SELECT `+computePromoRedemptionColumns+` FROM compute_promo_redemption WHERE code_id = $1 AND network_id = $2
	`, codeId, networkId)
	if err != nil || len(redemptions) == 0 {
		return nil, err
	}
	return redemptions[0], nil
}

// networkId's latest redemption of any code in tx, nil for none: what §9.11's one code a network in 30 days reads.
func ComputePromoLastRedemptionInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) (*ComputePromoRedemption, error) {
	redemptions, err := computePromoRedemptionQuery(ctx, tx, `
		SELECT `+computePromoRedemptionColumns+` FROM compute_promo_redemption WHERE network_id = $1
		ORDER BY redeem_time DESC, redemption_id DESC LIMIT 1
	`, networkId)
	if err != nil || len(redemptions) == 0 {
		return nil, err
	}
	return redemptions[0], nil
}

// Inserts redemption in tx; one of its code and network that stands is ErrComputePromoArgs, which the network's fence
// keeps from happening.
func ComputePromoRedemptionInsertInTx(env operator.Env, ctx context.Context, tx operator.DbTx, redemption *ComputePromoRedemption) error {
	result, err := tx.Exec(ctx, `
		INSERT INTO compute_promo_redemption (redemption_id, code_id, network_id, lot_id, sidecar_id, redeem_time)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (code_id, network_id) DO NOTHING
	`, redemption.RedemptionId, redemption.CodeId, redemption.NetworkId, redemption.LotId, redemption.SidecarId, redemption.RedeemTime.UTC())
	if err != nil {
		return err
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("%w: the network redeemed the code already", ErrComputePromoArgs)
	}
	return nil
}

// lotId's lot in tx, nil for none.
func ComputeLotGetInTx(env operator.Env, ctx context.Context, tx operator.DbTx, lotId operator.Id) (*ComputeLot, error) {
	lots, err := computeLotQuery(ctx, tx, `SELECT `+computeLotColumns+` FROM compute_lot WHERE lot_id = $1`, lotId)
	if err != nil || len(lots) == 0 {
		return nil, err
	}
	return lots[0], nil
}

// Up to limit promotional lots whose expiry is at or before now and that have something left, unreversed, oldest
// expiry first: one run of compute_promo_lapse. The statement names the promotion kind as its literal, so the partial
// index compute_lot_lapse, whose predicate it is, serves it.
func ComputePromoLapsing(env operator.Env, ctx context.Context, now time.Time, limit int) ([]*ComputeLot, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: a positive limit", ErrComputePromoArgs)
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var lots []*ComputeLot
	err = db.Db(ctx, func(conn operator.DbConn) error {
		var err error
		lots, err = computeLotQuery(ctx, conn, `
			SELECT `+computeLotColumns+` FROM compute_lot
			WHERE kind = `+strconv.Itoa(int(ComputeLotKindPromotion))+` AND remaining_nano_usd > 0 AND expire_time <= $1 AND reversed_time IS NULL
			ORDER BY expire_time, lot_id
			LIMIT $2
		`, now.UTC(), limit)
		return err
	})
	return lots, err
}

// A network's failed promotion codes, by UTC day: {cmpk_<network_id>} (§14.4, compute-2).
func ComputePromoFailureKey(networkId operator.Id) string {
	return "{cmpk_" + hex.EncodeToString(networkId[:]) + "}"
}

// The field of now's UTC day in the failure key: YYYYMMDD.
func computePromoFailureField(now time.Time) string {
	return now.UTC().Format("20060102")
}

// Raises the UTC day's count by one and keeps the key ttl past this write.
var computePromoFailureScript = &operator.RedisScript{
	Name: "compute-promo-failure",
	Source: `
local count = redis.call('HINCRBY', KEYS[1], ARGV[1], 1)
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return count
`,
}

// networkId's failed codes on now's UTC day.
func ComputePromoFailures(env operator.Env, ctx context.Context, networkId operator.Id, now time.Time) (int64, error) {
	redis, err := env.Redis()
	if err != nil {
		return 0, err
	}
	value, found, err := redis.HashGet(ctx, ComputePromoFailureKey(networkId), computePromoFailureField(now))
	if err != nil || !found {
		return 0, err
	}
	count, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: a failure count %q", ErrComputeProjectionReply, value)
	}
	return count, nil
}

// Counts one failed code to networkId's now's UTC day, the key living ttl past this write: the day's count after it.
func ComputePromoFailureAdd(env operator.Env, ctx context.Context, networkId operator.Id, now time.Time, ttl time.Duration) (int64, error) {
	redis, err := env.Redis()
	if err != nil {
		return 0, err
	}
	reply, err := redis.RunScript(ctx, computePromoFailureScript, []string{ComputePromoFailureKey(networkId)}, []string{
		computePromoFailureField(now), computeMillis(ttl),
	})
	if err != nil {
		return 0, err
	}
	if reply == nil || reply.Kind != operator.RedisReplyInteger {
		return 0, fmt.Errorf("%w: a failure count", ErrComputeProjectionReply)
	}
	return reply.Integer, nil
}
