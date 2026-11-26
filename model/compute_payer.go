// compute_payer and compute_payer_day (DESIGN-COMPUTE §9.11, §14.4, compute-2; BAL-M12-07): a payer's keyed hash, its
// first purchase day and each UTC day's sum, kept apart from any network, so the purchase limits follow the money's
// source across the networks a fraudster makes. Neither table has a network column, and no lot names a payer, so no
// row joins a payer to a network. The hash is the controller's (ComputePayerHash); these rows hold only its bytes.
//
//	ComputePayerInTx         a payer's first purchase day and its sums over a span of days
//	ComputePayerRecordInTx   a purchase counted to its payer: its first day where it had none, the day's sum raised
//	ComputePayerPruneInTx    the rows past their retention: a payer's day sums past 30 days, a payer past 2 years
//
// Each takes the caller's transaction after the Env (connect/CODESTYLE.md's locking).

package model

import (
	"context"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// A payer's limits' inputs (§9.11).
type ComputePayerLoads struct {
	// The UTC day of its first purchase anywhere, nil for a payer never seen.
	FirstPurchaseDay *time.Time
	// The UTC day of now's purchases.
	DayNanoUsd int64
	// Its purchases from its first purchase's day through the window after it.
	WindowNanoUsd int64
}

// Checks a payer's hash: a keyed hash's bytes, never empty.
func computePayerHashValid(payerHash []byte) error {
	if len(payerHash) == 0 {
		return fmt.Errorf("%w: a payer's keyed hash", ErrComputeLotArgs)
	}
	return nil
}

// payerHash's loads for now's UTC day and its first purchase's window of window, in tx.
func ComputePayerInTx(env operator.Env, ctx context.Context, tx operator.DbTx, payerHash []byte, now time.Time, window time.Duration) (*ComputePayerLoads, error) {
	if err := computePayerHashValid(payerHash); err != nil {
		return nil, err
	}
	loads := &ComputePayerLoads{}
	var firstText *string
	rows, err := tx.Query(ctx, `SELECT first_purchase_day::text FROM compute_payer WHERE payer_hash = $1`, payerHash)
	if err != nil {
		return nil, err
	}
	if rows.Next() {
		err = rows.Scan(&firstText)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return nil, err
	}
	sum := func(from time.Time, to time.Time) (int64, error) {
		rows, err := tx.Query(ctx, `
			SELECT coalesce(sum(amount_nano_usd), 0)::bigint FROM compute_payer_day
			WHERE payer_hash = $1 AND day >= $2::date AND day < $3::date
		`, payerHash, from.Format(computeDayLayout), to.Format(computeDayLayout))
		if err != nil {
			return 0, err
		}
		defer rows.Close()
		total := int64(0)
		if rows.Next() {
			if err := rows.Scan(&total); err != nil {
				return 0, err
			}
		}
		return total, rows.Err()
	}
	today := ComputeUtcDay(now)
	if loads.DayNanoUsd, err = sum(today, today.AddDate(0, 0, 1)); err != nil {
		return nil, err
	}
	if firstText == nil {
		return loads, nil
	}
	first, err := time.ParseInLocation(computeDayLayout, *firstText, time.UTC)
	if err != nil {
		return nil, err
	}
	loads.FirstPurchaseDay = &first
	if loads.WindowNanoUsd, err = sum(first, ComputeUtcDay(first.Add(window))); err != nil {
		return nil, err
	}
	return loads, nil
}

// Counts a purchase of amount on now's UTC day to payerHash, in tx: its first purchase day set where it had none, the
// day's sum raised.
func ComputePayerRecordInTx(env operator.Env, ctx context.Context, tx operator.DbTx, payerHash []byte, amount int64, now time.Time) error {
	if err := computePayerHashValid(payerHash); err != nil {
		return err
	}
	if amount <= 0 {
		return fmt.Errorf("%w: a payer's purchase is positive", ErrComputeLotArgs)
	}
	day := ComputeUtcDay(now).Format(computeDayLayout)
	if _, err := tx.Exec(ctx, `
		INSERT INTO compute_payer (payer_hash, first_purchase_day) VALUES ($1, $2::date)
		ON CONFLICT (payer_hash) DO NOTHING
	`, payerHash, day); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO compute_payer_day (payer_hash, day, amount_nano_usd) VALUES ($1, $2::date, $3)
		ON CONFLICT (payer_hash, day) DO UPDATE SET amount_nano_usd = compute_payer_day.amount_nano_usd + EXCLUDED.amount_nano_usd
	`, payerHash, day, amount)
	return err
}

// Deletes, in tx, the payer day sums before dayBefore's UTC day and the payers whose first purchase day is before
// payerBefore's (compute-2's 30 days and 2 years): how many of each went.
func ComputePayerPruneInTx(env operator.Env, ctx context.Context, tx operator.DbTx, dayBefore time.Time, payerBefore time.Time) (int64, int64, error) {
	days, err := tx.Exec(ctx, `DELETE FROM compute_payer_day WHERE day < $1::date`, ComputeUtcDay(dayBefore).Format(computeDayLayout))
	if err != nil {
		return 0, 0, err
	}
	payers, err := tx.Exec(ctx, `DELETE FROM compute_payer WHERE first_purchase_day < $1::date`, ComputeUtcDay(payerBefore).Format(computeDayLayout))
	if err != nil {
		return 0, 0, err
	}
	return days.RowsAffected, payers.RowsAffected, nil
}
