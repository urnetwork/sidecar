// compute_auto_renew's reads and writes (DESIGN-COMPUTE §9.8, §14.4, compute-6; BAL-M12-11), which the controller's
// compute_auto_renew.go runs in its transactions:
//
//	ComputeAutoRenewGetInTx            one network's mode, locked where asked
//	ComputeAutoRenewsInTx              both of a network's modes
//	ComputeAutoRenewPutInTx            a mode written whole, made where the network has none
//	ComputeAutoRenewBySubscriptionInTx the monthly row of a Stripe subscription
//	ComputeAutoRenewThresholdNetworks  compute_auto_renew's cursor: the networks with threshold on, by network id, on
//	                                   the table's primary key
//	ComputeAutoRenewOffInTx            both of a network's modes off, at its closure
//
// A row holds the mode's settings, the member whose card it charges and that card's Stripe customer and payment
// method, or the plan's subscription, never a card itself; and the day's and month's counts its limits read. Days and
// months are UTC dates, written as YYYY-MM-DD, never a cast in the session's zone.

package model

import (
	"context"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// compute_auto_renew's columns, in the order computeAutoRenewScan reads them.
const computeAutoRenewColumns = `network_id, mode, enabled, market, below_nano_usd, pack_credits, month_limit_nano_usd,
	monthly_credits, payer_member_id, stripe_customer_id, stripe_payment_method_id, stripe_subscription_id, off_reason,
	top_up_day::text, top_up_day_count, failure_day_count, failure_run_count, top_up_month::text, top_up_month_nano_usd,
	next_retry_time, update_time`

// A UTC date's text, nil for none.
func computeDayText(day *time.Time) *string {
	if day == nil {
		return nil
	}
	text := ComputeUtcDay(*day).Format(computeDayLayout)
	return &text
}

// A UTC date from its text, nil for none.
func computeDayParse(text *string) (*time.Time, error) {
	if text == nil {
		return nil, nil
	}
	day, err := time.ParseInLocation(computeDayLayout, *text, time.UTC)
	if err != nil {
		return nil, err
	}
	return &day, nil
}

func computeAutoRenewQuery(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) ([]*ComputeAutoRenew, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	autoRenews := []*ComputeAutoRenew{}
	for rows.Next() {
		row := &ComputeAutoRenew{}
		var mode, market int16
		var offReason *int16
		var topUpDay, topUpMonth *string
		err := rows.Scan(&row.NetworkId, &mode, &row.Enabled, &market, &row.BelowNanoUsd, &row.PackCredits,
			&row.MonthLimitNanoUsd, &row.MonthlyCredits, &row.PayerMemberId, &row.StripeCustomerId,
			&row.StripePaymentMethodId, &row.StripeSubscriptionId, &offReason, &topUpDay, &row.TopUpDayCount,
			&row.FailureDayCount, &row.FailureRunCount, &topUpMonth, &row.TopUpMonthNanoUsd, &row.NextRetryTime,
			&row.UpdateTime)
		if err != nil {
			return nil, err
		}
		row.Mode = ComputeAutoRenewMode(mode)
		row.Market = ComputeMarket(market)
		if offReason != nil {
			reason := ComputeAutoRenewOffReason(*offReason)
			row.OffReason = &reason
		}
		if row.TopUpDay, err = computeDayParse(topUpDay); err != nil {
			return nil, err
		}
		if row.TopUpMonth, err = computeDayParse(topUpMonth); err != nil {
			return nil, err
		}
		if row.NextRetryTime != nil {
			retry := row.NextRetryTime.UTC()
			row.NextRetryTime = &retry
		}
		row.UpdateTime = row.UpdateTime.UTC()
		autoRenews = append(autoRenews, row)
	}
	return autoRenews, rows.Err()
}

// Whether §9.8 names the mode.
func (self ComputeAutoRenewMode) Valid() bool {
	return self == ComputeAutoRenewModeThreshold || self == ComputeAutoRenewModeMonthly
}

// The mode's word, as the routes spell it: threshold or monthly, or mode<n> for one §9.8 does not name.
func (self ComputeAutoRenewMode) String() string {
	switch self {
	case ComputeAutoRenewModeThreshold:
		return "threshold"
	case ComputeAutoRenewModeMonthly:
		return "monthly"
	}
	return fmt.Sprintf("mode%d", int(self))
}

// The off reason's code, as the balance and auto-renew routes answer it, or "" for one §9.8 does not name.
func (self ComputeAutoRenewOffReason) Code() string {
	switch self {
	case ComputeAutoRenewOffAuthenticationRequired:
		return "authentication_required"
	case ComputeAutoRenewOffFailed:
		return "failed"
	case ComputeAutoRenewOffPayerLeft:
		return "payer_left"
	}
	return ""
}

// networkId's row of mode in tx, nil where it has none; locked FOR UPDATE where lock is set.
func ComputeAutoRenewGetInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, mode ComputeAutoRenewMode, lock bool) (*ComputeAutoRenew, error) {
	sql := `SELECT ` + computeAutoRenewColumns + ` FROM compute_auto_renew WHERE network_id = $1 AND mode = $2`
	if lock {
		sql += ` FOR UPDATE`
	}
	rows, err := computeAutoRenewQuery(ctx, tx, sql, networkId, int16(mode))
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// Both of networkId's modes in tx, as it holds them: threshold's and monthly's, each nil where the network has none.
func ComputeAutoRenewsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) (threshold *ComputeAutoRenew, monthly *ComputeAutoRenew, returnErr error) {
	rows, err := computeAutoRenewQuery(ctx, tx, `SELECT `+computeAutoRenewColumns+` FROM compute_auto_renew WHERE network_id = $1 ORDER BY mode`, networkId)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		switch row.Mode {
		case ComputeAutoRenewModeThreshold:
			threshold = row
		case ComputeAutoRenewModeMonthly:
			monthly = row
		}
	}
	return threshold, monthly, nil
}

// Writes row whole in tx, its update_time now, making it where the network has none of its mode. A row that names no
// valid mode or market, or a negative count, is refused.
func ComputeAutoRenewPutInTx(env operator.Env, ctx context.Context, tx operator.DbTx, row *ComputeAutoRenew, now time.Time) error {
	var zero operator.Id
	if row.NetworkId == zero || !row.Mode.Valid() || !row.Market.Valid() {
		return fmt.Errorf("%w: an auto-renew row names its network, mode and market", ErrComputeLotArgs)
	}
	if row.TopUpDayCount < 0 || row.FailureDayCount < 0 || row.FailureRunCount < 0 || row.TopUpMonthNanoUsd < 0 {
		return fmt.Errorf("%w: an auto-renew row's counts are zero or more", ErrComputeLotArgs)
	}
	var offReason *int16
	if row.OffReason != nil {
		value := int16(*row.OffReason)
		offReason = &value
	}
	var nextRetry *time.Time
	if row.NextRetryTime != nil {
		retry := row.NextRetryTime.UTC()
		nextRetry = &retry
	}
	row.UpdateTime = now.UTC()
	_, err := tx.Exec(ctx, `
		INSERT INTO compute_auto_renew (network_id, mode, enabled, market, below_nano_usd, pack_credits,
			month_limit_nano_usd, monthly_credits, payer_member_id, stripe_customer_id, stripe_payment_method_id,
			stripe_subscription_id, off_reason, top_up_day, top_up_day_count, failure_day_count, failure_run_count,
			top_up_month, top_up_month_nano_usd, next_retry_time, update_time)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::date, $15, $16, $17, $18::date, $19, $20, $21)
		ON CONFLICT (network_id, mode) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			market = EXCLUDED.market,
			below_nano_usd = EXCLUDED.below_nano_usd,
			pack_credits = EXCLUDED.pack_credits,
			month_limit_nano_usd = EXCLUDED.month_limit_nano_usd,
			monthly_credits = EXCLUDED.monthly_credits,
			payer_member_id = EXCLUDED.payer_member_id,
			stripe_customer_id = EXCLUDED.stripe_customer_id,
			stripe_payment_method_id = EXCLUDED.stripe_payment_method_id,
			stripe_subscription_id = EXCLUDED.stripe_subscription_id,
			off_reason = EXCLUDED.off_reason,
			top_up_day = EXCLUDED.top_up_day,
			top_up_day_count = EXCLUDED.top_up_day_count,
			failure_day_count = EXCLUDED.failure_day_count,
			failure_run_count = EXCLUDED.failure_run_count,
			top_up_month = EXCLUDED.top_up_month,
			top_up_month_nano_usd = EXCLUDED.top_up_month_nano_usd,
			next_retry_time = EXCLUDED.next_retry_time,
			update_time = EXCLUDED.update_time
	`, row.NetworkId, int16(row.Mode), row.Enabled, int16(row.Market), row.BelowNanoUsd, row.PackCredits,
		row.MonthLimitNanoUsd, row.MonthlyCredits, row.PayerMemberId, row.StripeCustomerId, row.StripePaymentMethodId,
		row.StripeSubscriptionId, offReason, computeDayText(row.TopUpDay), row.TopUpDayCount, row.FailureDayCount,
		row.FailureRunCount, computeDayText(row.TopUpMonth), row.TopUpMonthNanoUsd, nextRetry, row.UpdateTime)
	return err
}

// The monthly row of a Stripe subscription in tx, locked, nil where none names it.
func ComputeAutoRenewBySubscriptionInTx(env operator.Env, ctx context.Context, tx operator.DbTx, subscriptionId string) (*ComputeAutoRenew, error) {
	rows, err := computeAutoRenewQuery(ctx, tx, `
		SELECT `+computeAutoRenewColumns+` FROM compute_auto_renew
		WHERE mode = $1 AND stripe_subscription_id = $2
		ORDER BY network_id
		FOR UPDATE
	`, int16(ComputeAutoRenewModeMonthly), subscriptionId)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// Up to limit networks with threshold on whose id is past after, nil for the first, in network order: one run of
// compute_auto_renew's cursor, on the primary key's order.
func ComputeAutoRenewThresholdNetworks(env operator.Env, ctx context.Context, after *operator.Id, limit int) ([]operator.Id, error) {
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
		sql := `SELECT network_id FROM compute_auto_renew WHERE mode = $1 AND enabled`
		args := []any{int16(ComputeAutoRenewModeThreshold)}
		if after != nil {
			sql += ` AND network_id > $2`
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

// Turns both of networkId's modes off in tx (its closure, §9.12): what each was is answered, so the caller cancels its
// subscription and detaches its card after the commit.
func ComputeAutoRenewOffInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, now time.Time) ([]*ComputeAutoRenew, error) {
	rows, err := computeAutoRenewQuery(ctx, tx, `
		SELECT `+computeAutoRenewColumns+` FROM compute_auto_renew WHERE network_id = $1 ORDER BY mode FOR UPDATE
	`, networkId)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE compute_auto_renew SET enabled = false, next_retry_time = NULL, update_time = $2 WHERE network_id = $1
	`, networkId, now.UTC()); err != nil {
		return nil, err
	}
	return rows, nil
}
