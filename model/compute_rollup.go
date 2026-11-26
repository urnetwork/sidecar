// compute_rollup_day's queries (DESIGN-COMPUTE §9.4, §9.13, §14.5, D-BAL-6; BAL-M12-05), which the controller's
// compute_rollup.go runs in its transactions:
//
//	ComputeRollupNetworks             the networks a pass works through, an indexed cursor over compute_account
//	ComputeRollupDerivedDayInTx       a closed day's day rows as its charges give them, grouped by their stored columns
//	ComputeRollupStoredDayInTx        the same day's rows as compute_settle wrote them
//	ComputeRollupDayDifferences       the networks and kinds whose two disagree
//	ComputeRollupSumsInTx             each network and kind's lifetime totals beside its day rows and pruned sums
//	ComputeRollupPruneInTx            the day rows past their retention moved into compute_charge_pruned, one statement
//	ComputeChargePartitionDays        compute_charge's daily partitions
//	ComputeChargePartitionDropInTx    a partition past its retention dropped, with the kept operation rows that name its
//	                                  charges and the charges' lot draws
//
// A day row's sums are what compute_settle adds for each charge (ComputeRollupAddOf): typed units, the amount net of
// refunds and a count of one; a refund, a negative charge of the kind it returns, adds its negative amount, its size
// to refunded, and neither a count nor units; a support credit, a negative adjustment, counts as a charge. The
// re-derivation reads the same columns the booking wrote, so the two agree in every snapshot unless a row was changed
// by hand or by a bug, which is what the job alarms on.
//
// Every statement reads by network through an index: compute_account's key, compute_charge_day's (network_id, day,
// ...) key, compute_charge_total's (network_id, ...) key, compute_charge_pruned's key and compute_charge's (network_id,
// start_time) index within one day's partition; none scans the rollups across networks.

package model

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// What compute_charge's partitions are named: compute_charge_YYYYMMDD, the UTC day.
var computeChargePartitionNamePattern = regexp.MustCompile(`^compute_charge_([0-9]{8})$`)

// Up to limit networks with an account, after after (nil starts at the first), in id order: one batch of a pass.
func ComputeRollupNetworks(env operator.Env, ctx context.Context, after *operator.Id, limit int) ([]operator.Id, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: a positive limit", ErrComputeOpArgs)
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	networkIds := []operator.Id{}
	err = db.Db(ctx, func(conn operator.DbConn) error {
		networkIds = networkIds[:0]
		sql := `SELECT network_id FROM compute_account ORDER BY network_id LIMIT $1`
		args := []any{limit}
		if after != nil {
			sql = `SELECT network_id FROM compute_account WHERE network_id > $2 ORDER BY network_id LIMIT $1`
			args = append(args, *after)
		}
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

// One day row's columns from rows: its key, then the typed units, amount, refunded and count.
func computeRollupDayScan(rows operator.DbRows, day time.Time) (*ComputeChargeDay, error) {
	row := &ComputeChargeDay{Day: day}
	var kind int16
	err := rows.Scan(&row.NetworkId, &kind, &row.SidecarId, &row.AgentId, &row.CatalogId, &row.MemberId, &row.Provider,
		&row.EnclaveId, &row.Units.InputTokens, &row.Units.OutputTokens, &row.Units.CachedTokens, &row.Units.Seconds,
		&row.Units.EgressBytes, &row.Units.Searches, &row.AmountNanoUsd, &row.RefundedNanoUsd, &row.Count)
	if err != nil {
		return nil, err
	}
	row.Kind = ComputeChargeKind(kind)
	return row, nil
}

func computeRollupDayQuery(ctx context.Context, querier operator.DbQuerier, day time.Time, sql string, args ...any) ([]*ComputeChargeDay, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	days := []*ComputeChargeDay{}
	for rows.Next() {
		row, err := computeRollupDayScan(rows, day)
		if err != nil {
			return nil, err
		}
		days = append(days, row)
	}
	return days, rows.Err()
}

// networkIds' day rows of the UTC day day as their charges give them (see the file header): the charges started in
// the day, grouped by the day row's key, NULLs grouping together as the key's NULLS NOT DISTINCT does. Only day's
// partition is read.
func ComputeRollupDerivedDayInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkIds []operator.Id, day time.Time) ([]*ComputeChargeDay, error) {
	start := ComputeUtcDay(day)
	if len(networkIds) == 0 {
		return []*ComputeChargeDay{}, nil
	}
	unit := func(name string) string {
		return `sum(CASE WHEN refund THEN 0 ELSE coalesce((units->>'` + name + `')::bigint, 0) END)::bigint`
	}
	return computeRollupDayQuery(ctx, tx, start, `
		SELECT network_id, kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id,
			`+unit("input_tokens")+`, `+unit("output_tokens")+`, `+unit("cached_tokens")+`,
			`+unit("seconds")+`, `+unit("egress_bytes")+`, `+unit("searches")+`,
			sum(amount_nano_usd)::bigint,
			sum(CASE WHEN refund THEN -amount_nano_usd ELSE 0 END)::bigint,
			sum(CASE WHEN refund THEN 0 ELSE 1 END)::bigint
		FROM (
			SELECT network_id, kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id, units, amount_nano_usd,
				(amount_nano_usd < 0 AND kind <> $4) AS refund
			FROM compute_charge
			WHERE network_id = ANY($1::uuid[]) AND start_time >= $2 AND start_time < $3
		) charges
		GROUP BY network_id, kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id
	`, computeIdTexts(networkIds), start, start.AddDate(0, 0, 1), int16(ComputeChargeKindAdjustment))
}

// networkIds' day rows of the UTC day day as compute_charge_day holds them.
func ComputeRollupStoredDayInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkIds []operator.Id, day time.Time) ([]*ComputeChargeDay, error) {
	start := ComputeUtcDay(day)
	if len(networkIds) == 0 {
		return []*ComputeChargeDay{}, nil
	}
	return computeRollupDayQuery(ctx, tx, start, `
		SELECT network_id, kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id,
			input_tokens, output_tokens, cached_tokens, seconds, egress_bytes, searches,
			amount_nano_usd, refunded_nano_usd, count
		FROM compute_charge_day
		WHERE network_id = ANY($1::uuid[]) AND day = $2::date
	`, computeIdTexts(networkIds), start.Format(computeDayLayout))
}

// A day row's key as text: what two day rows of one key share.
func (self *ComputeChargeDay) rollupKey() string {
	add := &ComputeRollupAdd{
		NetworkId: self.NetworkId, Day: self.Day, Kind: self.Kind, SidecarId: self.SidecarId, AgentId: self.AgentId,
		CatalogId: self.CatalogId, MemberId: self.MemberId, Provider: self.Provider, EnclaveId: self.EnclaveId,
	}
	return add.dayKey()
}

// One network and kind whose rollup disagrees with what it should hold.
type ComputeRollupKey struct {
	NetworkId operator.Id
	Kind      ComputeChargeKind
}

// The networks and kinds whose derived day rows and stored ones differ, each once, in network and kind order: a row
// only one side holds, or one key whose units, amount, refunded or count differ. kinds limits the comparison to the
// kinds given; nil compares every kind.
func ComputeRollupDayDifferences(derived []*ComputeChargeDay, stored []*ComputeChargeDay, kinds []ComputeChargeKind) []*ComputeRollupKey {
	compared := func(kind ComputeChargeKind) bool {
		return kinds == nil || slices.Contains(kinds, kind)
	}
	keyDerived := map[string]*ComputeChargeDay{}
	for _, row := range derived {
		if compared(row.Kind) {
			keyDerived[row.rollupKey()] = row
		}
	}
	differ := map[ComputeRollupKey]bool{}
	for _, row := range stored {
		if !compared(row.Kind) {
			continue
		}
		key := row.rollupKey()
		other, ok := keyDerived[key]
		delete(keyDerived, key)
		if !ok || other.Units != row.Units || other.AmountNanoUsd != row.AmountNanoUsd ||
			other.RefundedNanoUsd != row.RefundedNanoUsd || other.Count != row.Count {
			differ[ComputeRollupKey{NetworkId: row.NetworkId, Kind: row.Kind}] = true
		}
	}
	for _, row := range keyDerived {
		differ[ComputeRollupKey{NetworkId: row.NetworkId, Kind: row.Kind}] = true
	}
	return computeRollupKeysSorted(differ)
}

// The keys of a set, in network and kind order.
func computeRollupKeysSorted(set map[ComputeRollupKey]bool) []*ComputeRollupKey {
	keys := []*ComputeRollupKey{}
	for key := range set {
		copied := key
		keys = append(keys, &copied)
	}
	slices.SortFunc(keys, func(a *ComputeRollupKey, b *ComputeRollupKey) int {
		if c := a.NetworkId.Cmp(b.NetworkId); c != 0 {
			return c
		}
		return int(a.Kind) - int(b.Kind)
	})
	return keys
}

// The sums a rollup holds for one network and kind.
type ComputeRollupFigures struct {
	Units           ComputeUnits
	AmountNanoUsd   int64
	RefundedNanoUsd int64
	Count           int64
}

// One network and kind's lifetime totals beside the sums of its day rows and its pruned row (§9.13).
type ComputeRollupSums struct {
	NetworkId operator.Id
	Kind      ComputeChargeKind
	Total     ComputeRollupFigures
	Day       ComputeRollupFigures
	// compute_charge_pruned's row, its amount and count alone; nil while no day row of the kind was pruned.
	Pruned *ComputeRollupFigures
}

// Whether the totals equal the day rows plus the pruned sums, which holds in every snapshot: the amount and the count
// always, and the units and refunds too while nothing of the kind was pruned, since compute_charge_pruned keeps only
// the amount and the count.
func (self *ComputeRollupSums) Balanced() bool {
	pruned := ComputeRollupFigures{}
	if self.Pruned != nil {
		pruned = *self.Pruned
	}
	if self.Total.AmountNanoUsd != self.Day.AmountNanoUsd+pruned.AmountNanoUsd || self.Total.Count != self.Day.Count+pruned.Count {
		return false
	}
	if self.Pruned == nil && (self.Total.Units != self.Day.Units || self.Total.RefundedNanoUsd != self.Day.RefundedNanoUsd) {
		return false
	}
	return true
}

// networkIds' totals, day sums and pruned sums by network and kind, in network and kind order, read in tx: the
// caller's one snapshot, so the three are of one moment.
func ComputeRollupSumsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkIds []operator.Id) ([]*ComputeRollupSums, error) {
	if len(networkIds) == 0 {
		return []*ComputeRollupSums{}, nil
	}
	keySums := map[ComputeRollupKey]*ComputeRollupSums{}
	sumsOf := func(networkId operator.Id, kind int16) *ComputeRollupSums {
		key := ComputeRollupKey{NetworkId: networkId, Kind: ComputeChargeKind(kind)}
		sums, ok := keySums[key]
		if !ok {
			sums = &ComputeRollupSums{NetworkId: networkId, Kind: ComputeChargeKind(kind)}
			keySums[key] = sums
		}
		return sums
	}
	figures := `sum(input_tokens)::bigint, sum(output_tokens)::bigint, sum(cached_tokens)::bigint, sum(seconds)::bigint,
		sum(egress_bytes)::bigint, sum(searches)::bigint, sum(amount_nano_usd)::bigint, sum(refunded_nano_usd)::bigint,
		sum(count)::bigint`
	read := func(table string, target func(sums *ComputeRollupSums) *ComputeRollupFigures) error {
		rows, err := tx.Query(ctx, `
			SELECT network_id, kind, `+figures+` FROM `+table+`
			WHERE network_id = ANY($1::uuid[])
			GROUP BY network_id, kind
		`, computeIdTexts(networkIds))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var networkId operator.Id
			var kind int16
			figure := ComputeRollupFigures{}
			err := rows.Scan(&networkId, &kind, &figure.Units.InputTokens, &figure.Units.OutputTokens, &figure.Units.CachedTokens,
				&figure.Units.Seconds, &figure.Units.EgressBytes, &figure.Units.Searches, &figure.AmountNanoUsd,
				&figure.RefundedNanoUsd, &figure.Count)
			if err != nil {
				return err
			}
			*target(sumsOf(networkId, kind)) = figure
		}
		return rows.Err()
	}
	if err := read("compute_charge_total", func(sums *ComputeRollupSums) *ComputeRollupFigures { return &sums.Total }); err != nil {
		return nil, err
	}
	if err := read("compute_charge_day", func(sums *ComputeRollupSums) *ComputeRollupFigures { return &sums.Day }); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT network_id, kind, amount_nano_usd, count FROM compute_charge_pruned WHERE network_id = ANY($1::uuid[])
	`, computeIdTexts(networkIds))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var networkId operator.Id
		var kind int16
		pruned := &ComputeRollupFigures{}
		if err := rows.Scan(&networkId, &kind, &pruned.AmountNanoUsd, &pruned.Count); err != nil {
			return nil, err
		}
		sumsOf(networkId, kind).Pruned = pruned
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keys := map[ComputeRollupKey]bool{}
	for key := range keySums {
		keys[key] = true
	}
	all := []*ComputeRollupSums{}
	for _, key := range computeRollupKeysSorted(keys) {
		all = append(all, keySums[*key])
	}
	return all, nil
}

// Moves networkIds' day rows before before's UTC day into compute_charge_pruned, summed per network and kind, in one
// statement in tx: the rows' delete and the pruned sums' upsert commit together, so the totals check holds in every
// snapshot (§9.13). The day rows it moved.
func ComputeRollupPruneInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkIds []operator.Id, before time.Time) (int64, error) {
	if len(networkIds) == 0 {
		return 0, nil
	}
	rows, err := tx.Query(ctx, `
		WITH moved AS (
			DELETE FROM compute_charge_day
			WHERE network_id = ANY($1::uuid[]) AND day < $2::date
			RETURNING network_id, kind, amount_nano_usd, count
		),
		summed AS (
			SELECT network_id, kind, sum(amount_nano_usd)::bigint AS amount_nano_usd, sum(count)::bigint AS count,
				count(*)::bigint AS row_count
			FROM moved
			GROUP BY network_id, kind
		),
		upserted AS (
			INSERT INTO compute_charge_pruned (network_id, kind, amount_nano_usd, count)
			SELECT network_id, kind, amount_nano_usd, count FROM summed
			ORDER BY network_id, kind
			ON CONFLICT (network_id, kind) DO UPDATE SET
				amount_nano_usd = compute_charge_pruned.amount_nano_usd + EXCLUDED.amount_nano_usd,
				count = compute_charge_pruned.count + EXCLUDED.count
		)
		SELECT coalesce(sum(row_count), 0)::bigint FROM summed
	`, computeIdTexts(networkIds), ComputeUtcDay(before).Format(computeDayLayout))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	moved := int64(0)
	if rows.Next() {
		if err := rows.Scan(&moved); err != nil {
			return 0, err
		}
	}
	return moved, rows.Err()
}

// compute_charge's daily partitions, by their UTC days, oldest first. A partition whose name is not a day's is not
// one of the ledger's and is left out.
func ComputeChargePartitionDays(env operator.Env, ctx context.Context) ([]time.Time, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	days := []time.Time{}
	err = db.Db(ctx, func(conn operator.DbConn) error {
		days = days[:0]
		rows, err := conn.Query(ctx, `
			SELECT child.relname::text FROM pg_inherits
			JOIN pg_class child ON child.oid = pg_inherits.inhrelid
			JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
			WHERE parent.relname = 'compute_charge'
		`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			match := computeChargePartitionNamePattern.FindStringSubmatch(name)
			if match == nil {
				continue
			}
			day, err := time.ParseInLocation("20060102", match[1], time.UTC)
			if err != nil || ComputeChargePartitionName(day) != name {
				continue
			}
			days = append(days, day)
		}
		return rows.Err()
	})
	slices.SortFunc(days, time.Time.Compare)
	return days, err
}

// What a partition's drop removed with it.
type ComputeChargePartitionDropped struct {
	Day time.Time
	// compute_op rows kept once booked whose charges were in it: a search's, a refund's, an adjustment's, and a
	// refund's that named one of them (§9.7).
	OpRowCount int64
	// Lot draws of its charges (compute_charge_lot).
	DrawCount int64
}

// Drops day's partition of compute_charge in tx (§14.5): first the operation rows kept once booked that name its
// charges, a refund's by the charge it returns and every kept row by its own charge, then the charges' lot draws, then
// the partition, detached and dropped. A partition that is not there drops nothing. The caller bounds the
// transaction's lock waits, since the detach waits for an ACCESS EXCLUSIVE lock on compute_charge.
func ComputeChargePartitionDropInTx(env operator.Env, ctx context.Context, tx operator.DbTx, day time.Time) (*ComputeChargePartitionDropped, error) {
	dropped := &ComputeChargePartitionDropped{Day: ComputeUtcDay(day)}
	name := ComputeChargePartitionName(day)
	if !computeChargePartitionNamePattern.MatchString(name) {
		return nil, fmt.Errorf("%w: the partition %s", ErrComputeOpArgs, name)
	}
	exists := false
	rows, err := tx.Query(ctx, `SELECT to_regclass($1) IS NOT NULL`, name)
	if err != nil {
		return nil, err
	}
	if rows.Next() {
		err = rows.Scan(&exists)
	}
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err != nil {
		return nil, err
	}
	if !exists {
		return dropped, nil
	}
	// the name passed the pattern above: compute_charge_ and eight digits
	charges := `(SELECT charge_id FROM ` + name + `)`
	own, err := tx.Exec(ctx, `DELETE FROM compute_op WHERE state = $1 AND op_key IN `+charges, int16(ComputeOpStateApplied))
	if err != nil {
		return nil, err
	}
	named, err := tx.Exec(ctx, `
		DELETE FROM compute_op
		WHERE state = $1 AND kind <> $2 AND (outcome->>'amount_nano_usd')::bigint < 0 AND subject_ref IN `+charges,
		int16(ComputeOpStateApplied), int16(ComputeChargeKindAdjustment))
	if err != nil {
		return nil, err
	}
	draws, err := tx.Exec(ctx, `DELETE FROM compute_charge_lot WHERE charge_id IN `+charges)
	if err != nil {
		return nil, err
	}
	for _, statement := range []string{
		`ALTER TABLE compute_charge DETACH PARTITION ` + name,
		`DROP TABLE ` + name,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return nil, err
		}
	}
	dropped.OpRowCount = own.RowsAffected + named.RowsAffected
	dropped.DrawCount = draws.RowsAffected
	return dropped, nil
}
