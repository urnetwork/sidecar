// compute_settle's and the rebuild's queries (DESIGN-COMPUTE §9.4, §9.7, §9.13, §14.5, D-BAL-13; BAL-M12-04): the
// network's fence, a shard's settled rows, the charges inserted ON CONFLICT DO NOTHING RETURNING, the lots a charge
// draws and the draws a refund returns, the account's booking, the day and lifetime rollups, each row's move to
// applied and the booked rows' delete; and the account, the open and settled rows and the booked days a rebuild reads.
// The controller's compute_book.go and compute_rebuild.go run them in their transactions, which is why each takes its
// transaction after the Env: never a second connection, never a nested transaction (connect/CODESTYLE.md's locking).
//
// The fence is the network's transaction-scoped advisory lock (compute-plan-settle-fence-pooling, QD-1376): a session
// lock cannot hold under PgBouncer's transaction pooling. The booking takes it in its transaction, the drop in the
// transaction around its script, and the rebuild in its own, with the drop script's version guard carrying the order a
// session lock would have.
//
// Ids travel as text arrays cast to uuid[], and every batch statement takes its rows as arrays through unnest, so one
// statement books a batch. Days are UTC dates written as YYYY-MM-DD, never a cast in the session's zone.

package model

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// The fence's lock key: the namespace and the network id, hashed to the bigint pg_advisory_xact_lock takes. An
// identifier.
const computeFenceNamespace = "compute_fence:"

// The layout of a UTC day as the statements take it.
const computeDayLayout = "2006-01-02"

// The UTC day t falls in, as a date at midnight UTC.
func ComputeUtcDay(t time.Time) time.Time {
	utc := t.UTC()
	return time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
}

// The UTC month t falls in, its first day at midnight UTC.
func ComputeUtcMonth(t time.Time) time.Time {
	utc := t.UTC()
	return time.Date(utc.Year(), utc.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// Ids as the text array a statement casts to uuid[].
func computeIdTexts(ids []operator.Id) []string {
	texts := make([]string, 0, len(ids))
	for _, id := range ids {
		texts = append(texts, id.String())
	}
	return texts
}

// A nullable id as a nullable text.
func computeIdText(id *operator.Id) *string {
	if id == nil {
		return nil
	}
	text := id.String()
	return &text
}

// Takes networkId's fence in tx, waiting for any booking, drop or rebuild of the network that holds it. It ends with tx.
func ComputeFenceInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, computeFenceNamespace+networkId.String())
	return err
}

// Makes compute_charge's partition for each UTC day days fall in where none stands: what a booking runs before its
// batch, so a charge never waits on compute_rollup_day's days ahead (BAL-M12-05). A partition that stands is left, and
// each one made is its own statement, so no batch holds the parent's lock while it books.
func ComputeChargePartitionsEnsure(env operator.Env, ctx context.Context, days []time.Time) error {
	db, err := env.Db()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, day := range days {
		name := ComputeChargePartitionName(day)
		if seen[name] {
			continue
		}
		seen[name] = true
		exists := false
		err := db.Db(ctx, func(conn operator.DbConn) error {
			rows, err := conn.Query(ctx, `SELECT to_regclass($1) IS NOT NULL`, name)
			if err != nil {
				return err
			}
			defer rows.Close()
			if rows.Next() {
				if err := rows.Scan(&exists); err != nil {
					return err
				}
			}
			return rows.Err()
		})
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		err = db.Db(ctx, func(conn operator.DbConn) error {
			_, err := conn.Exec(ctx, ComputeChargePartitionStatement(day))
			return err
		}, operator.DbReadWrite)
		if err != nil {
			return err
		}
	}
	return nil
}

// The UTC days a shard's settled rows start on: the partitions a booking needs. A handful of days at most, since a row
// is open a day at most before it settles.
func ComputeBookDays(env operator.Env, ctx context.Context, shard int16) ([]time.Time, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	days := []time.Time{}
	err = db.Db(ctx, func(conn operator.DbConn) error {
		days = days[:0]
		rows, err := conn.Query(ctx, `
			SELECT DISTINCT ((start_time AT TIME ZONE 'UTC')::date)::text FROM compute_op WHERE shard = $1 AND state = $2
		`, shard, int16(ComputeOpStateSettled))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var text string
			if err := rows.Scan(&text); err != nil {
				return err
			}
			day, err := time.ParseInLocation(computeDayLayout, text, time.UTC)
			if err != nil {
				return err
			}
			days = append(days, day)
		}
		return rows.Err()
	})
	return days, err
}

// Up to limit of shard's settled rows, locked, by network and key: one booking's batch. Rows another booking holds are
// passed over.
func ComputeBookSelectInTx(env operator.Env, ctx context.Context, tx operator.DbTx, shard int16, limit int) ([]*ComputeOp, error) {
	return computeOpQuery(ctx, tx, `
		SELECT `+computeOpColumns+` FROM compute_op
		WHERE shard = $1 AND state = $2
		ORDER BY network_id, op_key
		LIMIT $3
		FOR UPDATE SKIP LOCKED
	`, shard, int16(ComputeOpStateSettled), limit)
}

// Whether op's row is kept once booked (§9.7): a search's, as long as its charge, which compute_search_purge deletes
// within 72 hours, and a refund's or an adjustment's, as long as the charge it names. Every other booked row is
// deleted after its drop.
func ComputeOpKeptOnceBooked(op *ComputeOp) bool {
	if op.Kind == ComputeChargeKindWebSearch || op.Kind == ComputeChargeKindAdjustment {
		return true
	}
	return op.Outcome != nil && op.Outcome.AmountNanoUsd < 0
}

// The charge a settled row books: its key, subjects, units, amounts and times, the row's start fixing the charge's.
func ComputeChargeOf(op *ComputeOp) (*ComputeCharge, error) {
	if op.Outcome == nil {
		return nil, fmt.Errorf("%w: a row with no outcome books no charge", ErrComputeOpArgs)
	}
	return &ComputeCharge{
		ChargeId:        op.OpKey,
		NetworkId:       op.NetworkId,
		Kind:            op.Kind,
		SubjectRef:      op.SubjectRef,
		SidecarId:       op.SidecarId,
		AgentId:         op.AgentId,
		MemberId:        op.MemberId,
		EnclaveId:       op.EnclaveId,
		CatalogId:       op.CatalogId,
		Provider:        op.Provider,
		Units:           op.Outcome.Units,
		AmountNanoUsd:   op.Outcome.AmountNanoUsd,
		CostNanoUsd:     op.Outcome.CostNanoUsd,
		AbsorbedNanoUsd: op.Outcome.AbsorbedNanoUsd,
		StartTime:       op.StartTime.UTC(),
		EndTime:         op.Outcome.EndTime.UTC(),
		SettleTime:      op.Outcome.SettleTime.UTC(),
	}, nil
}

// Inserts charges, skipping any whose (start_time, charge_id) stands, and answers the ids inserted: the only ones a
// booking books, so a charge delivered twice adds one debit in all.
func ComputeChargeInsertInTx(env operator.Env, ctx context.Context, tx operator.DbTx, charges []*ComputeCharge) (map[operator.Id]bool, error) {
	inserted := map[operator.Id]bool{}
	if len(charges) == 0 {
		return inserted, nil
	}
	chargeIds, networkIds, subjectRefs, sidecarIds := []string{}, []string{}, []string{}, []string{}
	agentIds, memberIds, enclaveIds, catalogIds := []*string{}, []*string{}, []*string{}, []*string{}
	kinds, providers := []int16{}, []int16{}
	units := []string{}
	amounts, costs, absorbeds := []int64{}, []int64{}, []int64{}
	starts, ends, settles := []time.Time{}, []time.Time{}, []time.Time{}
	for _, charge := range charges {
		data, err := charge.Units.Json()
		if err != nil {
			return nil, err
		}
		chargeIds = append(chargeIds, charge.ChargeId.String())
		networkIds = append(networkIds, charge.NetworkId.String())
		subjectRefs = append(subjectRefs, charge.SubjectRef.String())
		sidecarIds = append(sidecarIds, charge.SidecarId.String())
		agentIds = append(agentIds, computeIdText(charge.AgentId))
		memberIds = append(memberIds, computeIdText(charge.MemberId))
		enclaveIds = append(enclaveIds, computeIdText(charge.EnclaveId))
		catalogIds = append(catalogIds, charge.CatalogId)
		kinds = append(kinds, int16(charge.Kind))
		providers = append(providers, charge.Provider)
		units = append(units, string(data))
		amounts = append(amounts, charge.AmountNanoUsd)
		costs = append(costs, charge.CostNanoUsd)
		absorbeds = append(absorbeds, charge.AbsorbedNanoUsd)
		starts = append(starts, charge.StartTime.UTC())
		ends = append(ends, charge.EndTime.UTC())
		settles = append(settles, charge.SettleTime.UTC())
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO compute_charge (charge_id, network_id, kind, subject_ref, sidecar_id, agent_id, member_id, enclave_id,
			catalog_id, provider, units, amount_nano_usd, cost_nano_usd, absorbed_nano_usd, start_time, end_time, settle_time)
		SELECT * FROM unnest($1::uuid[], $2::uuid[], $3::smallint[], $4::uuid[], $5::uuid[], $6::uuid[], $7::uuid[],
			$8::uuid[], $9::text[], $10::smallint[], $11::jsonb[], $12::bigint[], $13::bigint[], $14::bigint[],
			$15::timestamptz[], $16::timestamptz[], $17::timestamptz[])
		ON CONFLICT DO NOTHING
		RETURNING charge_id
	`, chargeIds, networkIds, kinds, subjectRefs, sidecarIds, agentIds, memberIds, enclaveIds, catalogIds, providers,
		units, amounts, costs, absorbeds, starts, ends, settles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id operator.Id
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		inserted[id] = true
	}
	return inserted, rows.Err()
}

// compute_lot's columns, in the order computeLotScan reads them.
const computeLotColumns = `lot_id, network_id, kind, market, market_ref, amount_nano_usd, remaining_nano_usd, create_time,
	expire_time, reversed_time, lapsed_nano_usd, refunded_nano_usd`

func computeLotScan(rows operator.DbRows) (*ComputeLot, error) {
	lot := &ComputeLot{}
	var kind, market int16
	err := rows.Scan(&lot.LotId, &lot.NetworkId, &kind, &market, &lot.MarketRef, &lot.AmountNanoUsd, &lot.RemainingNanoUsd,
		&lot.CreateTime, &lot.ExpireTime, &lot.ReversedTime, &lot.LapsedNanoUsd, &lot.RefundedNanoUsd)
	if err != nil {
		return nil, err
	}
	lot.Kind = ComputeLotKind(kind)
	lot.Market = ComputeMarket(market)
	lot.CreateTime = lot.CreateTime.UTC()
	return lot, nil
}

func computeLotQuery(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) ([]*ComputeLot, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	lots := []*ComputeLot{}
	for rows.Next() {
		lot, err := computeLotScan(rows)
		if err != nil {
			return nil, err
		}
		lots = append(lots, lot)
	}
	return lots, rows.Err()
}

// A network's lots a charge may draw at now, locked, in §9.4's order: unexpired promotions by nearest expiry, then
// subscription grants, then purchases, oldest first, then adjustment lots, oldest first; reversed lots and those with
// nothing left are passed over.
func ComputeLotsForDrawInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, now time.Time) ([]*ComputeLot, error) {
	return computeLotQuery(ctx, tx, `
		SELECT `+computeLotColumns+` FROM compute_lot
		WHERE network_id = $1 AND remaining_nano_usd > 0 AND reversed_time IS NULL
			AND (kind <> $2 OR expire_time > $3)
		ORDER BY CASE kind WHEN $2 THEN 0 WHEN $4 THEN 1 WHEN $5 THEN 2 ELSE 3 END,
			CASE WHEN kind = $2 THEN expire_time END, create_time, lot_id
		FOR UPDATE
	`, networkId, int16(ComputeLotKindPromotion), now.UTC(), int16(ComputeLotKindSubscription), int16(ComputeLotKindPurchase))
}

// The lots of lotIds, locked, whatever their state: the lots a refund returns to.
func ComputeLotsGetInTx(env operator.Env, ctx context.Context, tx operator.DbTx, lotIds []operator.Id) (map[operator.Id]*ComputeLot, error) {
	lotIdLots := map[operator.Id]*ComputeLot{}
	if len(lotIds) == 0 {
		return lotIdLots, nil
	}
	lots, err := computeLotQuery(ctx, tx, `SELECT `+computeLotColumns+` FROM compute_lot WHERE lot_id = ANY($1::uuid[]) ORDER BY lot_id FOR UPDATE`, computeIdTexts(lotIds))
	if err != nil {
		return nil, err
	}
	for _, lot := range lots {
		lotIdLots[lot.LotId] = lot
	}
	return lotIdLots, nil
}

// The draws of chargeIds, in their draw order: what a refund of each returns in reverse.
func ComputeChargeDrawsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, chargeIds []operator.Id) (map[operator.Id][]*ComputeChargeDraw, error) {
	chargeIdDraws := map[operator.Id][]*ComputeChargeDraw{}
	if len(chargeIds) == 0 {
		return chargeIdDraws, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT charge_id, lot_id, amount_nano_usd, draw_index FROM compute_charge_lot
		WHERE charge_id = ANY($1::uuid[])
		ORDER BY charge_id, draw_index
	`, computeIdTexts(chargeIds))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		draw := &ComputeChargeDraw{}
		if err := rows.Scan(&draw.ChargeId, &draw.LotId, &draw.AmountNanoUsd, &draw.DrawIndex); err != nil {
			return nil, err
		}
		chargeIdDraws[draw.ChargeId] = append(chargeIdDraws[draw.ChargeId], draw)
	}
	return chargeIdDraws, rows.Err()
}

// Inserts draws: each lot a booked charge drew, a refund's negative.
func ComputeDrawsInsertInTx(env operator.Env, ctx context.Context, tx operator.DbTx, draws []*ComputeChargeDraw) error {
	if len(draws) == 0 {
		return nil
	}
	chargeIds, lotIds := []string{}, []string{}
	amounts := []int64{}
	indexes := []int16{}
	for _, draw := range draws {
		chargeIds = append(chargeIds, draw.ChargeId.String())
		lotIds = append(lotIds, draw.LotId.String())
		amounts = append(amounts, draw.AmountNanoUsd)
		indexes = append(indexes, draw.DrawIndex)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO compute_charge_lot (charge_id, lot_id, amount_nano_usd, draw_index)
		SELECT * FROM unnest($1::uuid[], $2::uuid[], $3::bigint[], $4::smallint[])
	`, chargeIds, lotIds, amounts, indexes)
	return err
}

// One lot's change in a booking: what its remaining and its lapsed amount move by.
type ComputeLotChange struct {
	LotId            operator.Id
	RemainingDelta   int64
	LapsedAddNanoUsd int64
}

// Applies changes to their lots, in lot order.
func ComputeLotsChangeInTx(env operator.Env, ctx context.Context, tx operator.DbTx, changes []*ComputeLotChange) error {
	if len(changes) == 0 {
		return nil
	}
	sorted := slices.Clone(changes)
	slices.SortFunc(sorted, func(a *ComputeLotChange, b *ComputeLotChange) int { return a.LotId.Cmp(b.LotId) })
	lotIds := []string{}
	deltas, lapses := []int64{}, []int64{}
	for _, change := range sorted {
		lotIds = append(lotIds, change.LotId.String())
		deltas = append(deltas, change.RemainingDelta)
		lapses = append(lapses, change.LapsedAddNanoUsd)
	}
	_, err := tx.Exec(ctx, `
		UPDATE compute_lot SET
			remaining_nano_usd = remaining_nano_usd + change.delta,
			lapsed_nano_usd = CASE WHEN change.lapse = 0 THEN lapsed_nano_usd ELSE coalesce(lapsed_nano_usd, 0) + change.lapse END
		FROM unnest($1::uuid[], $2::bigint[], $3::bigint[]) AS change(lot_id, delta, lapse)
		WHERE compute_lot.lot_id = change.lot_id
	`, lotIds, deltas, lapses)
	return err
}

// Books a batch's net change into networkId's account: settled falls by settledDelta (negative raises it), the
// version rises by one, update_time is now, and first_charge_day takes the earlier of its own and firstDay, since
// charges settle out of start order. A network with no account gets one, active with no floor, as its first booking
// makes it. The account as it stands after.
func ComputeAccountBookInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, settledDelta int64, firstDay time.Time, now time.Time) (*ComputeAccount, error) {
	_, err := tx.Exec(ctx, `
		INSERT INTO compute_account (network_id, settled_nano_usd, state, negative_floor_nano_usd, first_charge_day, version, update_time)
		VALUES ($1, 0, $2, 0, NULL, 0, $3)
		ON CONFLICT (network_id) DO NOTHING
	`, networkId, int16(ComputeAccountStateActive), now.UTC())
	if err != nil {
		return nil, err
	}
	accounts, err := computeAccountQuery(ctx, tx, `
		UPDATE compute_account SET
			settled_nano_usd = settled_nano_usd - $2,
			version = version + 1,
			update_time = $3,
			first_charge_day = LEAST(first_charge_day, $4::date)
		WHERE network_id = $1
		RETURNING `+computeAccountColumns,
		networkId, settledDelta, now.UTC(), ComputeUtcDay(firstDay).Format(computeDayLayout))
	if err != nil {
		return nil, err
	}
	if len(accounts) != 1 {
		return nil, fmt.Errorf("compute book: the account of the network did not book")
	}
	return accounts[0], nil
}

// compute_account's columns, in the order computeAccountScan reads them.
const computeAccountColumns = `network_id, settled_nano_usd, state, negative_floor_nano_usd, first_charge_day::text,
	indexer_reserve_nano_usd, search_cap_override, version, update_time`

func computeAccountQuery(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) ([]*ComputeAccount, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := []*ComputeAccount{}
	for rows.Next() {
		account := &ComputeAccount{}
		var state int16
		var firstDay *string
		err := rows.Scan(&account.NetworkId, &account.SettledNanoUsd, &state, &account.NegativeFloorNanoUsd, &firstDay,
			&account.IndexerReserveNanoUsd, &account.SearchCapOverride, &account.Version, &account.UpdateTime)
		if err != nil {
			return nil, err
		}
		account.State = ComputeAccountState(state)
		account.UpdateTime = account.UpdateTime.UTC()
		if firstDay != nil {
			day, err := time.ParseInLocation(computeDayLayout, *firstDay, time.UTC)
			if err != nil {
				return nil, err
			}
			account.FirstChargeDay = &day
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

// One network's account, nil where it has none.
func ComputeAccountGet(env operator.Env, ctx context.Context, networkId operator.Id) (*ComputeAccount, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var account *ComputeAccount
	err = db.Db(ctx, func(conn operator.DbConn) error {
		accounts, err := computeAccountQuery(ctx, conn, `SELECT `+computeAccountColumns+` FROM compute_account WHERE network_id = $1`, networkId)
		if err != nil {
			return err
		}
		account = nil
		if len(accounts) == 1 {
			account = accounts[0]
		}
		return nil
	})
	return account, err
}

// The committed account as the projection carries it (§9.7): its version, settled balance, floor and state, and
// promo, the unexpired promotional credit left at now. A network with no account reads version 0, nothing settled,
// active: every hold of it is refused balance.
func ComputeAccountProjectionInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, now time.Time) (*ComputeProjectionAccount, error) {
	rows, err := tx.Query(ctx, `
		SELECT a.version, a.settled_nano_usd, a.negative_floor_nano_usd, a.state,
			(SELECT coalesce(sum(remaining_nano_usd), 0)::bigint FROM compute_lot
				WHERE network_id = $1 AND kind = $2 AND reversed_time IS NULL AND expire_time > $3)
		FROM compute_account a WHERE a.network_id = $1
	`, networkId, int16(ComputeLotKindPromotion), now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	account := &ComputeProjectionAccount{State: ComputeAccountStateActive}
	if rows.Next() {
		var state int16
		if err := rows.Scan(&account.Version, &account.SettledNanoUsd, &account.FloorNanoUsd, &state, &account.PromoNanoUsd); err != nil {
			return nil, err
		}
		account.State = ComputeAccountState(state)
	}
	return account, rows.Err()
}

// One rollup row's key and sums as a booking adds them: a day row's (§9.13), or with no day, sidecar or agent, a
// lifetime total's.
type ComputeRollupAdd struct {
	NetworkId operator.Id
	Day       time.Time
	Kind      ComputeChargeKind
	SidecarId operator.Id
	AgentId   *operator.Id
	CatalogId *string
	MemberId  *operator.Id
	Provider  int16
	EnclaveId *operator.Id
	Units     ComputeUnits
	// Net of refunds; a refund's size, positive; charges counted, a refund none.
	AmountNanoUsd   int64
	RefundedNanoUsd int64
	Count           int64
}

// A rollup's key as text, which orders the upserts: the same order in every batch, so two never deadlock.
func (self *ComputeRollupAdd) dayKey() string {
	text := func(id *operator.Id) string {
		if id == nil {
			return "-"
		}
		return id.String()
	}
	catalog := "-"
	if self.CatalogId != nil {
		catalog = "+" + *self.CatalogId
	}
	return strings.Join([]string{self.NetworkId.String(), self.Day.Format(computeDayLayout), fmt.Sprintf("%05d", self.Kind),
		self.SidecarId.String(), text(self.AgentId), catalog, text(self.MemberId), fmt.Sprintf("%05d", self.Provider), text(self.EnclaveId)}, "|")
}

func (self *ComputeRollupAdd) totalKey() string {
	text := func(id *operator.Id) string {
		if id == nil {
			return "-"
		}
		return id.String()
	}
	catalog := "-"
	if self.CatalogId != nil {
		catalog = "+" + *self.CatalogId
	}
	return strings.Join([]string{self.NetworkId.String(), fmt.Sprintf("%05d", self.Kind), text(self.MemberId), catalog,
		fmt.Sprintf("%05d", self.Provider), text(self.EnclaveId)}, "|")
}

// The rollup a booked charge adds (§9.13): typed units, its amount, and a count of one; a refund adds its negative
// amount and its size to refunded, and changes neither the count nor the units.
func ComputeRollupAddOf(charge *ComputeCharge) *ComputeRollupAdd {
	add := &ComputeRollupAdd{
		NetworkId: charge.NetworkId,
		Day:       ComputeUtcDay(charge.StartTime),
		Kind:      charge.Kind,
		SidecarId: charge.SidecarId,
		AgentId:   charge.AgentId,
		CatalogId: charge.CatalogId,
		MemberId:  charge.MemberId,
		Provider:  charge.Provider,
		EnclaveId: charge.EnclaveId,
	}
	if charge.AmountNanoUsd < 0 && charge.Kind != ComputeChargeKindAdjustment {
		add.AmountNanoUsd = charge.AmountNanoUsd
		add.RefundedNanoUsd = -charge.AmountNanoUsd
		return add
	}
	add.Units = charge.Units
	add.AmountNanoUsd = charge.AmountNanoUsd
	add.Count = 1
	return add
}

// Sums adds by their keys, in key order.
func computeRollupMerge(adds []*ComputeRollupAdd, key func(add *ComputeRollupAdd) string) []*ComputeRollupAdd {
	keyAdds := map[string]*ComputeRollupAdd{}
	keys := []string{}
	for _, add := range adds {
		k := key(add)
		merged, ok := keyAdds[k]
		if !ok {
			copied := *add
			keyAdds[k] = &copied
			keys = append(keys, k)
			continue
		}
		merged.Units = merged.Units.Add(add.Units)
		merged.AmountNanoUsd += add.AmountNanoUsd
		merged.RefundedNanoUsd += add.RefundedNanoUsd
		merged.Count += add.Count
	}
	slices.Sort(keys)
	merged := []*ComputeRollupAdd{}
	for _, k := range keys {
		merged = append(merged, keyAdds[k])
	}
	return merged
}

// Upserts adds into compute_charge_day and compute_charge_total, each summed by its key and in key order, in tx: the
// charges' own transaction, so the rollups never drift from them.
func ComputeRollupsUpsertInTx(env operator.Env, ctx context.Context, tx operator.DbTx, adds []*ComputeRollupAdd) error {
	if len(adds) == 0 {
		return nil
	}
	days := computeRollupMerge(adds, (*ComputeRollupAdd).dayKey)
	totals := computeRollupMerge(adds, (*ComputeRollupAdd).totalKey)
	columns := func(rows []*ComputeRollupAdd) []any {
		networkIds, dayTexts, sidecarIds := []string{}, []string{}, []string{}
		agentIds, memberIds, enclaveIds, catalogIds := []*string{}, []*string{}, []*string{}, []*string{}
		kinds, providers := []int16{}, []int16{}
		inputs, outputs, cacheds, seconds, egresses, searches := []int64{}, []int64{}, []int64{}, []int64{}, []int64{}, []int64{}
		amounts, refundeds, counts := []int64{}, []int64{}, []int64{}
		for _, row := range rows {
			networkIds = append(networkIds, row.NetworkId.String())
			dayTexts = append(dayTexts, row.Day.Format(computeDayLayout))
			sidecarIds = append(sidecarIds, row.SidecarId.String())
			agentIds = append(agentIds, computeIdText(row.AgentId))
			memberIds = append(memberIds, computeIdText(row.MemberId))
			enclaveIds = append(enclaveIds, computeIdText(row.EnclaveId))
			catalogIds = append(catalogIds, row.CatalogId)
			kinds = append(kinds, int16(row.Kind))
			providers = append(providers, row.Provider)
			inputs = append(inputs, row.Units.InputTokens)
			outputs = append(outputs, row.Units.OutputTokens)
			cacheds = append(cacheds, row.Units.CachedTokens)
			seconds = append(seconds, row.Units.Seconds)
			egresses = append(egresses, row.Units.EgressBytes)
			searches = append(searches, row.Units.Searches)
			amounts = append(amounts, row.AmountNanoUsd)
			refundeds = append(refundeds, row.RefundedNanoUsd)
			counts = append(counts, row.Count)
		}
		return []any{networkIds, dayTexts, kinds, sidecarIds, agentIds, catalogIds, memberIds, providers, enclaveIds,
			inputs, outputs, cacheds, seconds, egresses, searches, amounts, refundeds, counts}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO compute_charge_day (network_id, day, kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id,
			input_tokens, output_tokens, cached_tokens, seconds, egress_bytes, searches, amount_nano_usd, refunded_nano_usd, count)
		SELECT * FROM unnest($1::uuid[], $2::date[], $3::smallint[], $4::uuid[], $5::uuid[], $6::text[], $7::uuid[],
			$8::smallint[], $9::uuid[], $10::bigint[], $11::bigint[], $12::bigint[], $13::bigint[], $14::bigint[],
			$15::bigint[], $16::bigint[], $17::bigint[], $18::bigint[])
		ON CONFLICT (network_id, day, kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id) DO UPDATE SET
			input_tokens = compute_charge_day.input_tokens + EXCLUDED.input_tokens,
			output_tokens = compute_charge_day.output_tokens + EXCLUDED.output_tokens,
			cached_tokens = compute_charge_day.cached_tokens + EXCLUDED.cached_tokens,
			seconds = compute_charge_day.seconds + EXCLUDED.seconds,
			egress_bytes = compute_charge_day.egress_bytes + EXCLUDED.egress_bytes,
			searches = compute_charge_day.searches + EXCLUDED.searches,
			amount_nano_usd = compute_charge_day.amount_nano_usd + EXCLUDED.amount_nano_usd,
			refunded_nano_usd = compute_charge_day.refunded_nano_usd + EXCLUDED.refunded_nano_usd,
			count = compute_charge_day.count + EXCLUDED.count
	`, columns(days)...)
	if err != nil {
		return err
	}
	totalColumns := columns(totals)
	// a total has no day, sidecar or agent (Q-BAL-10)
	_, err = tx.Exec(ctx, `
		INSERT INTO compute_charge_total (network_id, kind, member_id, catalog_id, provider, enclave_id,
			input_tokens, output_tokens, cached_tokens, seconds, egress_bytes, searches, amount_nano_usd, refunded_nano_usd, count)
		SELECT * FROM unnest($1::uuid[], $2::smallint[], $3::uuid[], $4::text[], $5::smallint[], $6::uuid[],
			$7::bigint[], $8::bigint[], $9::bigint[], $10::bigint[], $11::bigint[], $12::bigint[], $13::bigint[],
			$14::bigint[], $15::bigint[])
		ON CONFLICT (network_id, kind, member_id, catalog_id, provider, enclave_id) DO UPDATE SET
			input_tokens = compute_charge_total.input_tokens + EXCLUDED.input_tokens,
			output_tokens = compute_charge_total.output_tokens + EXCLUDED.output_tokens,
			cached_tokens = compute_charge_total.cached_tokens + EXCLUDED.cached_tokens,
			seconds = compute_charge_total.seconds + EXCLUDED.seconds,
			egress_bytes = compute_charge_total.egress_bytes + EXCLUDED.egress_bytes,
			searches = compute_charge_total.searches + EXCLUDED.searches,
			amount_nano_usd = compute_charge_total.amount_nano_usd + EXCLUDED.amount_nano_usd,
			refunded_nano_usd = compute_charge_total.refunded_nano_usd + EXCLUDED.refunded_nano_usd,
			count = compute_charge_total.count + EXCLUDED.count
	`, totalColumns[0], totalColumns[2], totalColumns[6], totalColumns[5], totalColumns[7], totalColumns[8],
		totalColumns[9], totalColumns[10], totalColumns[11], totalColumns[12], totalColumns[13], totalColumns[14],
		totalColumns[15], totalColumns[16], totalColumns[17])
	return err
}

// Moves opKeys' rows from settled to applied, the booking's last statement.
func ComputeOpApplyInTx(env operator.Env, ctx context.Context, tx operator.DbTx, opKeys []operator.Id) error {
	if len(opKeys) == 0 {
		return nil
	}
	result, err := tx.Exec(ctx, `UPDATE compute_op SET state = $2 WHERE op_key = ANY($1::uuid[]) AND state = $3`,
		computeIdTexts(opKeys), int16(ComputeOpStateApplied), int16(ComputeOpStateSettled))
	if err != nil {
		return err
	}
	if result.RowsAffected != int64(len(opKeys)) {
		// every row was locked settled by this transaction
		return fmt.Errorf("compute book: %d of %d locked rows moved to applied", result.RowsAffected, len(opKeys))
	}
	return nil
}

// Deletes opKeys' applied rows, once their drop ran.
func ComputeOpDeleteAppliedInTx(env operator.Env, ctx context.Context, tx operator.DbTx, opKeys []operator.Id) error {
	if len(opKeys) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `DELETE FROM compute_op WHERE op_key = ANY($1::uuid[]) AND state = $2`, computeIdTexts(opKeys), int16(ComputeOpStateApplied))
	return err
}

// Up to limit of shard's booked rows that a booking's drop has not yet deleted, by network and key: those an
// interrupted run left, which the next run drops and deletes. Rows kept once booked are not among them.
func ComputeOpListUndropped(env operator.Env, ctx context.Context, shard int16, limit int) ([]*ComputeOp, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var ops []*ComputeOp
	err = db.Db(ctx, func(conn operator.DbConn) error {
		var err error
		ops, err = computeOpQuery(ctx, conn, `
			SELECT `+computeOpColumns+` FROM compute_op
			WHERE shard = $1 AND state = $2 AND kind <> $3 AND kind <> $4 AND (outcome->>'amount_nano_usd')::bigint >= 0
			ORDER BY network_id, op_key
			LIMIT $5
		`, shard, int16(ComputeOpStateApplied), int16(ComputeChargeKindWebSearch), int16(ComputeChargeKindAdjustment), limit)
		return err
	})
	return ops, err
}

// Up to limit void rows started before before, oldest first, but a search's, which its purge deletes: what
// compute_op_recover drops from Redis again and deletes.
func ComputeOpListVoid(env operator.Env, ctx context.Context, before time.Time, limit int) ([]*ComputeOp, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var ops []*ComputeOp
	err = db.Db(ctx, func(conn operator.DbConn) error {
		var err error
		ops, err = computeOpQuery(ctx, conn, `
			SELECT `+computeOpColumns+` FROM compute_op
			WHERE state = $1 AND kind <> $2 AND start_time < $3
			ORDER BY start_time, op_key
			LIMIT $4
		`, int16(ComputeOpStateVoid), int16(ComputeChargeKindWebSearch), before.UTC(), limit)
		return err
	})
	return ops, err
}

// Deletes opKeys' void rows.
func ComputeOpDeleteVoid(env operator.Env, ctx context.Context, opKeys []operator.Id) error {
	if len(opKeys) == 0 {
		return nil
	}
	db, err := env.Db()
	if err != nil {
		return err
	}
	return db.Db(ctx, func(conn operator.DbConn) error {
		_, err := conn.Exec(ctx, `DELETE FROM compute_op WHERE op_key = ANY($1::uuid[]) AND state = $2`, computeIdTexts(opKeys), int16(ComputeOpStateVoid))
		return err
	}, operator.DbReadWrite)
}

// A network's open and settled rows, in one statement, so one snapshot holds both: a row moving between them is in
// one and only one (§9.7's lost cache). Applied and void rows are not.
func ComputeRebuildOpsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) ([]*ComputeOp, error) {
	return computeOpQuery(ctx, tx, `
		SELECT `+computeOpColumns+` FROM compute_op
		WHERE network_id = $1 AND state IN ($2, $3)
		ORDER BY op_key
	`, networkId, int16(ComputeOpStateOpen), int16(ComputeOpStateSettled))
}

// One booked day's charges of calls and searches by subject: what a rebuild's budget counters start from.
type ComputeBookedDay struct {
	Day       time.Time
	Kind      ComputeChargeKind
	SidecarId operator.Id
	AgentId   *operator.Id
	MemberId  *operator.Id
	// What the day's charges counted to their budgets: their amounts before refunds, as the live counters took them.
	ChargedNanoUsd int64
}

// networkId's booked charges of calls and searches since since's UTC day, by day, kind, sidecar, agent and member,
// from compute_charge_day.
func ComputeRebuildDaysInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, since time.Time) ([]*ComputeBookedDay, error) {
	rows, err := tx.Query(ctx, `
		SELECT day::text, kind, sidecar_id, agent_id, member_id, sum(amount_nano_usd + refunded_nano_usd)::bigint
		FROM compute_charge_day
		WHERE network_id = $1 AND day >= $2::date AND kind IN ($3, $4)
		GROUP BY day, kind, sidecar_id, agent_id, member_id
		ORDER BY day, kind, sidecar_id
	`, networkId, ComputeUtcDay(since).Format(computeDayLayout), int16(ComputeChargeKindInference), int16(ComputeChargeKindWebSearch))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	days := []*ComputeBookedDay{}
	for rows.Next() {
		booked := &ComputeBookedDay{}
		var dayText string
		var kind int16
		if err := rows.Scan(&dayText, &kind, &booked.SidecarId, &booked.AgentId, &booked.MemberId, &booked.ChargedNanoUsd); err != nil {
			return nil, err
		}
		day, err := time.ParseInLocation(computeDayLayout, dayText, time.UTC)
		if err != nil {
			return nil, err
		}
		booked.Day = day
		booked.Kind = ComputeChargeKind(kind)
		days = append(days, booked)
	}
	return days, rows.Err()
}
