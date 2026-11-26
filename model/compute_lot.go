// compute_lot's writes and the limits' reads (DESIGN-COMPUTE §9.4, §9.5, §9.11, §9.12; BAL-M12-07), which the
// controller's compute_lot.go and compute_limits.go run in their transactions, under the network's fence where they
// change its balance:
//
//	ComputeLotInsertInTx            a lot under UNIQUE (market, market_ref): a replay answers the lot that stands
//	ComputeLotByMarketRefInTx       the lot of a market's reference, locked where asked
//	ComputeAccountForUpdateInTx     a network's account, made where it has none, locked
//	ComputeAccountMoveInTx          its settled balance moved, its version raised, its state set where asked
//	ComputeLotsRemainingInTx        what the network's lots have left, the overrun's other half
//	ComputeUncoveredChargesInTx     the network's charges no unreversed lot fully paid, oldest first: an overrun's
//	ComputeOverrunLotsInTx          the lots that may pay an overrun, in §9.4's draw order, promotions never among them
//	ComputeLotReverseInTx           a lot reversed: its remaining removed, reversed_time set
//	ComputeLotLapseInTx             a promotion lapsed: what is left kept as lapsed_nano_usd, nothing left
//	ComputeNetworkPromotionsInTx    the network's promotional lots with something left
//	ComputeNetworkLoadsInTx         what a network loaded in a UTC day and in its first purchase's window
//	ComputePaidLotsInTx             its unreversed paid lots: the oldest's time and their lifetime sum
//	ComputeChargebackSuspendedInTx  whether a chargeback suspended it
//
// A paid lot is a purchase or a subscription grant, bought with money; a promotion and an operator's adjustment are
// not. A lot holds no payer, and no row here joins a payer to a network (§9.11, compute-2).

package model

import (
	"context"
	"errors"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// A lot the ledger cannot take: an amount out of range, a kind and market that do not go together, no reference.
var ErrComputeLotArgs = errors.New("compute lot: arguments refused")

// The kinds that were bought with money (§9.11's "paid lot"): a purchase and a subscription grant.
func (self ComputeLotKind) Paid() bool {
	return self == ComputeLotKindPurchase || self == ComputeLotKindSubscription
}

// The lot's state as the statement takes and returns it.
func computeLotArgs(lot *ComputeLot) []any {
	return []any{lot.LotId, lot.NetworkId, int16(lot.Kind), int16(lot.Market), lot.MarketRef, lot.AmountNanoUsd,
		lot.RemainingNanoUsd, lot.CreateTime.UTC(), lot.ExpireTime}
}

// Inserts lot in tx, skipping one whose (market, market_ref) stands: inserted is false and stands is that lot, the
// first credit of a replayed webhook's reference. A lot that stands in another network answers ErrComputeLotArgs, since
// one market reference is one network's money.
func ComputeLotInsertInTx(env operator.Env, ctx context.Context, tx operator.DbTx, lot *ComputeLot) (inserted bool, stands *ComputeLot, returnErr error) {
	if !lot.Kind.Valid() || !lot.Market.Valid() || lot.MarketRef == "" {
		return false, nil, fmt.Errorf("%w: a lot names its kind, market and reference", ErrComputeLotArgs)
	}
	if lot.AmountNanoUsd <= 0 || computeLuaMaxExactInteger < lot.AmountNanoUsd || lot.RemainingNanoUsd < 0 || lot.AmountNanoUsd < lot.RemainingNanoUsd {
		return false, nil, fmt.Errorf("%w: a lot's amount is positive and its remaining within it", ErrComputeLotArgs)
	}
	if (lot.Kind == ComputeLotKindPromotion) != (lot.ExpireTime != nil) || (lot.Kind == ComputeLotKindPromotion) != (lot.Market == ComputeMarketPromotion) {
		return false, nil, fmt.Errorf("%w: a promotion, and only a promotion, has its market and an expiry", ErrComputeLotArgs)
	}
	lots, err := computeLotQuery(ctx, tx, `
		INSERT INTO compute_lot (lot_id, network_id, kind, market, market_ref, amount_nano_usd, remaining_nano_usd, create_time, expire_time)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (market, market_ref) DO NOTHING
		RETURNING `+computeLotColumns, computeLotArgs(lot)...)
	if err != nil {
		return false, nil, err
	}
	if len(lots) == 1 {
		return true, lots[0], nil
	}
	stands, err = ComputeLotByMarketRefInTx(env, ctx, tx, lot.Market, lot.MarketRef, true)
	if err != nil {
		return false, nil, err
	}
	if stands == nil {
		// inserted and deleted between the two statements: ask for a rerun, which inserts it
		return false, nil, operator.ErrDbRerun
	}
	if stands.NetworkId != lot.NetworkId {
		return false, nil, fmt.Errorf("%w: the market reference is another network's lot", ErrComputeLotArgs)
	}
	return false, stands, nil
}

// The lot of market's reference, nil where none stands; locked FOR UPDATE where lock is set.
func ComputeLotByMarketRefInTx(env operator.Env, ctx context.Context, tx operator.DbTx, market ComputeMarket, marketRef string, lock bool) (*ComputeLot, error) {
	sql := `SELECT ` + computeLotColumns + ` FROM compute_lot WHERE market = $1 AND market_ref = $2`
	if lock {
		sql += ` FOR UPDATE`
	}
	lots, err := computeLotQuery(ctx, tx, sql, int16(market), marketRef)
	if err != nil || len(lots) == 0 {
		return nil, err
	}
	return lots[0], nil
}

// networkId's account in tx as it stands, unlocked; nil for a network with none.
func ComputeAccountInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) (*ComputeAccount, error) {
	accounts, err := computeAccountQuery(ctx, tx, `SELECT `+computeAccountColumns+` FROM compute_account WHERE network_id = $1`, networkId)
	if err != nil || len(accounts) == 0 {
		return nil, err
	}
	return accounts[0], nil
}

// networkId's account in tx, locked FOR UPDATE; a network with none gets one first, active with no floor and nothing
// settled, as its first credit or booking makes it.
func ComputeAccountForUpdateInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, now time.Time) (*ComputeAccount, error) {
	_, err := tx.Exec(ctx, `
		INSERT INTO compute_account (network_id, settled_nano_usd, state, negative_floor_nano_usd, first_charge_day, version, update_time)
		VALUES ($1, 0, $2, 0, NULL, 0, $3)
		ON CONFLICT (network_id) DO NOTHING
	`, networkId, int16(ComputeAccountStateActive), now.UTC())
	if err != nil {
		return nil, err
	}
	accounts, err := computeAccountQuery(ctx, tx, `SELECT `+computeAccountColumns+` FROM compute_account WHERE network_id = $1 FOR UPDATE`, networkId)
	if err != nil {
		return nil, err
	}
	if len(accounts) != 1 {
		return nil, fmt.Errorf("compute lot: the network's account did not read")
	}
	return accounts[0], nil
}

// Moves networkId's settled balance by settledDelta in tx, raises its version by one and sets update_time; state, where
// given, becomes its state. first_charge_day is the booking's alone. The account as it stands after.
func ComputeAccountMoveInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, settledDelta int64, state *ComputeAccountState, now time.Time) (*ComputeAccount, error) {
	var stateArg *int16
	if state != nil {
		if !state.Valid() {
			return nil, fmt.Errorf("%w: no account state %d", ErrComputeLotArgs, *state)
		}
		value := int16(*state)
		stateArg = &value
	}
	accounts, err := computeAccountQuery(ctx, tx, `
		UPDATE compute_account SET
			settled_nano_usd = settled_nano_usd + $2,
			version = version + 1,
			update_time = $3,
			state = coalesce($4::smallint, state)
		WHERE network_id = $1
		RETURNING `+computeAccountColumns,
		networkId, settledDelta, now.UTC(), stateArg)
	if err != nil {
		return nil, err
	}
	if len(accounts) != 1 {
		return nil, fmt.Errorf("compute lot: the network has no account to move")
	}
	return accounts[0], nil
}

// The sum of what networkId's lots have left, reversed and lapsed ones holding nothing.
func ComputeLotsRemainingInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT coalesce(sum(remaining_nano_usd), 0)::bigint FROM compute_lot WHERE network_id = $1`, networkId)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	remaining := int64(0)
	if rows.Next() {
		if err := rows.Scan(&remaining); err != nil {
			return 0, err
		}
	}
	return remaining, rows.Err()
}

// A charge no unreversed lot fully paid: part of a network's overrun (§9.4).
type ComputeUncoveredCharge struct {
	ChargeId operator.Id
	Kind     ComputeChargeKind
	// Its amount less what its draws to unreversed lots paid.
	UncoveredNanoUsd int64
	// Its last draw's index, -1 for none: a new draw takes the next.
	LastDrawIndex int16
}

// Up to limit of networkId's charges started since since whose draws to unreversed lots fall short of their amounts,
// oldest first: the charges an overrun is drawn for. A refund and a support credit, negative, owe nothing.
func ComputeUncoveredChargesInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, since time.Time, limit int) ([]*ComputeUncoveredCharge, error) {
	if limit <= 0 {
		return []*ComputeUncoveredCharge{}, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT c.charge_id, c.kind,
			(c.amount_nano_usd - coalesce(sum(d.amount_nano_usd) FILTER (WHERE l.reversed_time IS NULL), 0))::bigint,
			coalesce(max(d.draw_index), -1)::smallint
		FROM compute_charge c
		LEFT JOIN compute_charge_lot d ON d.charge_id = c.charge_id
		LEFT JOIN compute_lot l ON l.lot_id = d.lot_id
		WHERE c.network_id = $1 AND c.amount_nano_usd > 0 AND c.start_time >= $2
		GROUP BY c.charge_id, c.kind, c.amount_nano_usd, c.start_time
		HAVING c.amount_nano_usd > coalesce(sum(d.amount_nano_usd) FILTER (WHERE l.reversed_time IS NULL), 0)
		ORDER BY c.start_time, c.charge_id
		LIMIT $3
	`, networkId, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	charges := []*ComputeUncoveredCharge{}
	for rows.Next() {
		charge := &ComputeUncoveredCharge{}
		var kind int16
		if err := rows.Scan(&charge.ChargeId, &kind, &charge.UncoveredNanoUsd, &charge.LastDrawIndex); err != nil {
			return nil, err
		}
		charge.Kind = ComputeChargeKind(kind)
		charges = append(charges, charge)
	}
	return charges, rows.Err()
}

// networkId's lots that may pay an overrun, locked, in §9.4's draw order past the promotions: subscription grants,
// then purchases, then adjustments, oldest first; unreversed and with something left. A promotion never pays one, for
// it pays no search and no reversed purchase's debt (§9.11).
func ComputeOverrunLotsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, excludeLotId *operator.Id) ([]*ComputeLot, error) {
	sql := `
		SELECT ` + computeLotColumns + ` FROM compute_lot
		WHERE network_id = $1 AND remaining_nano_usd > 0 AND reversed_time IS NULL AND kind <> $2`
	args := []any{networkId, int16(ComputeLotKindPromotion), int16(ComputeLotKindSubscription), int16(ComputeLotKindPurchase)}
	if excludeLotId != nil {
		sql += ` AND lot_id <> $5`
		args = append(args, *excludeLotId)
	}
	sql += `
		ORDER BY CASE kind WHEN $3 THEN 0 WHEN $4 THEN 1 ELSE 2 END, create_time, lot_id
		FOR UPDATE`
	return computeLotQuery(ctx, tx, sql, args...)
}

// Reverses lotId in tx (§9.12): reversed_time now, its remaining removed. The lot as it stands after; a lot already
// reversed is answered as it stands.
func ComputeLotReverseInTx(env operator.Env, ctx context.Context, tx operator.DbTx, lotId operator.Id, now time.Time) (*ComputeLot, error) {
	lots, err := computeLotQuery(ctx, tx, `
		UPDATE compute_lot SET reversed_time = $2, remaining_nano_usd = 0
		WHERE lot_id = $1 AND reversed_time IS NULL
		RETURNING `+computeLotColumns, lotId, now.UTC())
	if err != nil {
		return nil, err
	}
	if len(lots) == 1 {
		return lots[0], nil
	}
	lots, err = computeLotQuery(ctx, tx, `SELECT `+computeLotColumns+` FROM compute_lot WHERE lot_id = $1`, lotId)
	if err != nil {
		return nil, err
	}
	if len(lots) == 0 {
		return nil, fmt.Errorf("%w: no lot %s", ErrComputeLotArgs, lotId)
	}
	return lots[0], nil
}

// Lapses promotional lotId in tx (§9.11): what is left added to lapsed_nano_usd and nothing left. What lapsed now,
// zero for a lot with nothing left or no promotion.
func ComputeLotLapseInTx(env operator.Env, ctx context.Context, tx operator.DbTx, lotId operator.Id) (int64, error) {
	lots, err := computeLotQuery(ctx, tx, `SELECT `+computeLotColumns+` FROM compute_lot WHERE lot_id = $1 FOR UPDATE`, lotId)
	if err != nil {
		return 0, err
	}
	if len(lots) == 0 || lots[0].Kind != ComputeLotKindPromotion || lots[0].RemainingNanoUsd <= 0 {
		return 0, nil
	}
	lapsing := lots[0].RemainingNanoUsd
	result, err := tx.Exec(ctx, `
		UPDATE compute_lot SET lapsed_nano_usd = coalesce(lapsed_nano_usd, 0) + $2, remaining_nano_usd = 0
		WHERE lot_id = $1 AND remaining_nano_usd = $2
	`, lotId, lapsing)
	if err != nil {
		return 0, err
	}
	if result.RowsAffected != 1 {
		return 0, fmt.Errorf("compute lot: the promotion locked for its lapse did not move")
	}
	return lapsing, nil
}

// networkId's promotional lots with something left, locked, expired or not.
func ComputeNetworkPromotionsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) ([]*ComputeLot, error) {
	return computeLotQuery(ctx, tx, `
		SELECT `+computeLotColumns+` FROM compute_lot
		WHERE network_id = $1 AND kind = $2 AND remaining_nano_usd > 0
		ORDER BY lot_id
		FOR UPDATE
	`, networkId, int16(ComputeLotKindPromotion))
}

// What a network loaded (§9.11): the day's loads and purchases, and its first purchase's window.
type ComputeNetworkLoads struct {
	// The UTC day's lots that count as a load: purchases, subscription grants and promotions.
	LoadedNanoUsd int64
	// The UTC day's paid lots: purchases and subscription grants.
	PurchasedNanoUsd int64
	// The first paid lot's creation, nil before any.
	FirstPurchaseTime *time.Time
	// The paid lots from the first one's UTC day through the window after it.
	WindowPurchasedNanoUsd int64
}

// networkId's loads for the UTC day of now, and its first purchase's window of window, in tx. Reversed lots count: the
// money was loaded on its day.
func ComputeNetworkLoadsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, now time.Time, window time.Duration) (*ComputeNetworkLoads, error) {
	day := ComputeUtcDay(now)
	loads := &ComputeNetworkLoads{}
	rows, err := tx.Query(ctx, `
		SELECT
			coalesce(sum(amount_nano_usd) FILTER (WHERE kind IN ($2, $3, $4) AND create_time >= $5 AND create_time < $6), 0)::bigint,
			coalesce(sum(amount_nano_usd) FILTER (WHERE kind IN ($2, $3) AND create_time >= $5 AND create_time < $6), 0)::bigint,
			min(create_time) FILTER (WHERE kind IN ($2, $3))
		FROM compute_lot
		WHERE network_id = $1
	`, networkId, int16(ComputeLotKindPurchase), int16(ComputeLotKindSubscription), int16(ComputeLotKindPromotion), day, day.AddDate(0, 0, 1))
	if err != nil {
		return nil, err
	}
	if rows.Next() {
		err = rows.Scan(&loads.LoadedNanoUsd, &loads.PurchasedNanoUsd, &loads.FirstPurchaseTime)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return nil, err
	}
	if loads.FirstPurchaseTime == nil {
		return loads, nil
	}
	first := loads.FirstPurchaseTime.UTC()
	loads.FirstPurchaseTime = &first
	start := ComputeUtcDay(first)
	rows, err = tx.Query(ctx, `
		SELECT coalesce(sum(amount_nano_usd), 0)::bigint FROM compute_lot
		WHERE network_id = $1 AND kind IN ($2, $3) AND create_time >= $4 AND create_time < $5
	`, networkId, int16(ComputeLotKindPurchase), int16(ComputeLotKindSubscription), start, start.Add(window))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&loads.WindowPurchasedNanoUsd); err != nil {
			return nil, err
		}
	}
	return loads, rows.Err()
}

// A network's unreversed paid lots (§9.11): what the search cap and the enclave gates read.
type ComputePaidLots struct {
	// The oldest's creation, nil while there is none.
	OldestTime *time.Time
	// Their amounts, less what of each a self-serve refund returned.
	LifetimeNanoUsd int64
}

// networkId's unreversed paid lots, in tx.
func ComputePaidLotsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) (*ComputePaidLots, error) {
	paid := &ComputePaidLots{}
	rows, err := tx.Query(ctx, `
		SELECT min(create_time), coalesce(sum(amount_nano_usd - coalesce(refunded_nano_usd, 0)), 0)::bigint
		FROM compute_lot
		WHERE network_id = $1 AND kind IN ($2, $3) AND reversed_time IS NULL
	`, networkId, int16(ComputeLotKindPurchase), int16(ComputeLotKindSubscription))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&paid.OldestTime, &paid.LifetimeNanoUsd); err != nil {
			return nil, err
		}
	}
	if paid.OldestTime != nil {
		oldest := paid.OldestTime.UTC()
		paid.OldestTime = &oldest
	}
	return paid, rows.Err()
}

// Whether a chargeback suspended networkId's compute (§9.11): it holds a reversed Stripe lot. A Stripe purchase is
// reversed only by a chargeback, a refund of one being a self-serve refund's refunded_nano_usd (§9.12), while a store's
// refund reverses its lot and suspends nothing past what the balance says (a reading the report names). A
// chargeback's suspension stands until a person reviews it, which nothing here undoes.
func ComputeChargebackSuspendedInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) (bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT EXISTS (SELECT 1 FROM compute_lot WHERE network_id = $1 AND market = $2 AND reversed_time IS NOT NULL)
	`, networkId, int16(ComputeMarketStripe))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	suspended := false
	if rows.Next() {
		if err := rows.Scan(&suspended); err != nil {
			return false, err
		}
	}
	return suspended, rows.Err()
}
