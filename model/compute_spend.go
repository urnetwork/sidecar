// The read routes' reads (DESIGN-COMPUTE §9.10, §9.13, §14.3, D-BAL-6, D-BAL-7; BAL-M12-15): what GET
// api/compute/balance, /charges, /statement and /spend answer from, each in the caller's transaction, which a route
// opens REPEATABLE READ and read-only, so every figure of one answer is of one snapshot:
//
//	ComputeHeldInTx            the open operations' holds: the network's, or those that count to one member
//	ComputeSpendTotalsInTx     compute_charge_total's sums by kind and the view's breakdown
//	ComputeSpendDaysInTx       compute_charge_day's sums by day, kind and the breakdown, over a window of UTC days
//	ComputeChargesPageInTx     a page of compute_charge's per-request rows, newest first, after a cursor
//	ComputeStatementDaysInTx   a UTC month's day rows as compute_settle wrote them
//	ComputeStatementLotsInTx   the lots a UTC month bought, granted or redeemed, and the promotions that lapsed in it
//
// No spend figure reads a per-request row: the spend view reads the rollups alone, and only the charges route reads
// compute_charge. A Member's reads are filtered to the rows whose stored member is theirs (§9.10), which the broker
// wrote at the hold, so a later SponsorSet moves no earlier charge. Days are UTC dates the caller computes and passes as
// YYYY-MM-DD, and every day read back is to_char'd the same way, so no session's time zone or date style moves a day
// (Q-BAL-8). Nothing here reads what URnetwork absorbed of a direct call into a spend figure (absorbed is a charge's own
// column, which the charges route shows beside the charge), nor a lot's market reference.

package model

import (
	"context"
	"errors"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// The spend view's breakdowns (§9.13's --by), as the device's compute client names them.
type ComputeSpendBy string

const (
	// No breakdown: each kind's figures alone.
	ComputeSpendByNone ComputeSpendBy = ""
	// §4.6's provider code.
	ComputeSpendByProvider ComputeSpendBy = "provider"
	// The model's canonical name, or an enclave's shape.
	ComputeSpendByModel   ComputeSpendBy = "model"
	ComputeSpendByEnclave ComputeSpendBy = "enclave"
	// Whom a charge counts to, the network's own line among them.
	ComputeSpendByMember ComputeSpendBy = "member"
	// The last 7 days only: no total is kept by agent (Q-BAL-10).
	ComputeSpendByAgent ComputeSpendBy = "agent"
)

// Every breakdown, in §9.13's order.
var computeSpendBys = []ComputeSpendBy{
	ComputeSpendByNone,
	ComputeSpendByProvider,
	ComputeSpendByModel,
	ComputeSpendByEnclave,
	ComputeSpendByMember,
	ComputeSpendByAgent,
}

// The breakdown word names, or an error for one §9.13 does not name.
func ParseComputeSpendBy(word string) (ComputeSpendBy, error) {
	for _, by := range computeSpendBys {
		if string(by) == word {
			return by, nil
		}
	}
	return "", fmt.Errorf("compute spend: %q is no breakdown", word)
}

// Whether the breakdown keeps a total: every one but agent, which counts the last 7 days alone (Q-BAL-10).
func (self ComputeSpendBy) HasTotal() bool {
	return self != ComputeSpendByAgent
}

// The rollup columns a breakdown groups by, in the order they are scanned.
func (self ComputeSpendBy) columns() []string {
	switch self {
	case ComputeSpendByProvider:
		return []string{"provider"}
	case ComputeSpendByModel:
		return []string{"catalog_id"}
	case ComputeSpendByEnclave:
		return []string{"enclave_id"}
	case ComputeSpendByMember:
		return []string{"member_id"}
	case ComputeSpendByAgent:
		return []string{"agent_id", "member_id"}
	}
	return []string{}
}

// One sum of the rollups' typed columns: units, the amount net of refunds, the refunds apart and the charges counted.
type ComputeSpendSums struct {
	Units           ComputeUnits
	AmountNanoUsd   int64
	RefundedNanoUsd int64
	Count           int64
}

// Whether every figure is zero.
func (self *ComputeSpendSums) Zero() bool {
	return self.AmountNanoUsd == 0 && self.RefundedNanoUsd == 0 && self.Count == 0 && self.Units == (ComputeUnits{})
}

// The sum of two sums.
func (self ComputeSpendSums) Add(other ComputeSpendSums) ComputeSpendSums {
	return ComputeSpendSums{
		Units:           self.Units.Add(other.Units),
		AmountNanoUsd:   self.AmountNanoUsd + other.AmountNanoUsd,
		RefundedNanoUsd: self.RefundedNanoUsd + other.RefundedNanoUsd,
		Count:           self.Count + other.Count,
	}
}

// One group of a spend read: its kind, its UTC day (nil for a total), its key by the breakdown, and its sums. Of the
// key's fields only the breakdown's are read: provider by provider, catalog id by model, enclave by enclave, member by
// member, agent and member by agent; each may be nil for charges that name none but provider, which every charge has.
type ComputeSpendGroup struct {
	Kind      ComputeChargeKind
	Day       *time.Time
	Provider  *int16
	CatalogId *string
	EnclaveId *operator.Id
	MemberId  *operator.Id
	AgentId   *operator.Id
	Sums      ComputeSpendSums
}

// The sums' columns, as each read selects them.
const computeSpendSumColumns = `sum(input_tokens)::bigint, sum(output_tokens)::bigint, sum(cached_tokens)::bigint,
	sum(seconds)::bigint, sum(egress_bytes)::bigint, sum(searches)::bigint,
	sum(amount_nano_usd)::bigint, sum(refunded_nano_usd)::bigint, sum(count)::bigint`

// The breakdown's key columns as a select list, ordering list and group list, each led by a comma, or empty.
func (self ComputeSpendBy) clauses() (selected string, ordered string) {
	for _, column := range self.columns() {
		selected += ", " + column
		if column == "provider" {
			ordered += ", " + column
		} else {
			ordered += ", " + column + " NULLS FIRST"
		}
	}
	return selected, ordered
}

// Scans one group's key and sums from rows, after day where withDay.
func computeSpendGroupScan(rows operator.DbRows, by ComputeSpendBy, withDay bool) (*ComputeSpendGroup, error) {
	group := &ComputeSpendGroup{}
	var dayText string
	var kind int16
	dest := []any{}
	if withDay {
		dest = append(dest, &dayText)
	}
	dest = append(dest, &kind)
	var provider int16
	switch by {
	case ComputeSpendByProvider:
		dest = append(dest, &provider)
	case ComputeSpendByModel:
		dest = append(dest, &group.CatalogId)
	case ComputeSpendByEnclave:
		dest = append(dest, &group.EnclaveId)
	case ComputeSpendByMember:
		dest = append(dest, &group.MemberId)
	case ComputeSpendByAgent:
		dest = append(dest, &group.AgentId, &group.MemberId)
	}
	sums := &group.Sums
	dest = append(dest, &sums.Units.InputTokens, &sums.Units.OutputTokens, &sums.Units.CachedTokens, &sums.Units.Seconds,
		&sums.Units.EgressBytes, &sums.Units.Searches, &sums.AmountNanoUsd, &sums.RefundedNanoUsd, &sums.Count)
	if err := rows.Scan(dest...); err != nil {
		return nil, err
	}
	group.Kind = ComputeChargeKind(kind)
	if by == ComputeSpendByProvider {
		group.Provider = &provider
	}
	if withDay {
		day, err := time.ParseInLocation(computeDayLayout, dayText, time.UTC)
		if err != nil {
			return nil, err
		}
		group.Day = &day
	}
	return group, nil
}

// Runs a spend read and scans its groups.
func computeSpendQuery(ctx context.Context, tx operator.DbTx, by ComputeSpendBy, withDay bool, sql string, args ...any) ([]*ComputeSpendGroup, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []*ComputeSpendGroup{}
	for rows.Next() {
		group, err := computeSpendGroupScan(rows, by, withDay)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

// networkId's lifetime totals in tx, from compute_charge_total, by kind and by's key, a member's alone where memberId
// is set: what the spend view's "since the first charge" reads. By agent there is no total (Q-BAL-10): it answers none.
func ComputeSpendTotalsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, memberId *operator.Id, by ComputeSpendBy) ([]*ComputeSpendGroup, error) {
	if !by.HasTotal() {
		return []*ComputeSpendGroup{}, nil
	}
	selected, ordered := by.clauses()
	args := []any{networkId}
	filter := ""
	if memberId != nil {
		filter = ` AND member_id = $2`
		args = append(args, *memberId)
	}
	return computeSpendQuery(ctx, tx, by, false, `
		SELECT kind`+selected+`, `+computeSpendSumColumns+`
		FROM compute_charge_total
		WHERE network_id = $1`+filter+`
		GROUP BY kind`+selected+`
		ORDER BY kind`+ordered, args...)
}

// networkId's day rows in tx from the UTC day first through the UTC day last, both included, from compute_charge_day,
// by day, kind and by's key, a member's alone where memberId is set: what the spend view's last 7 days read.
func ComputeSpendDaysInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, memberId *operator.Id, by ComputeSpendBy, first time.Time, last time.Time) ([]*ComputeSpendGroup, error) {
	selected, ordered := by.clauses()
	args := []any{networkId, ComputeUtcDay(first).Format(computeDayLayout), ComputeUtcDay(last).Format(computeDayLayout)}
	filter := ""
	if memberId != nil {
		filter = ` AND member_id = $4`
		args = append(args, *memberId)
	}
	return computeSpendQuery(ctx, tx, by, true, `
		SELECT to_char(day, 'YYYY-MM-DD'), kind`+selected+`, `+computeSpendSumColumns+`
		FROM compute_charge_day
		WHERE network_id = $1 AND day >= $2::date AND day <= $3::date`+filter+`
		GROUP BY day, kind`+selected+`
		ORDER BY day, kind`+ordered, args...)
}

// What networkId's open operations hold in tx (§9.13's "held"): every open row's balance hold, a running enclave's
// current interval among them, or only the rows that count to memberId where it is set, which each row records from
// the projection at its hold. Settled rows are charges, not holds, and booked within seconds.
func ComputeHeldInTx(env operator.Env, ctx context.Context, tx operator.DbTx, settings *ComputeLedgerSettings, networkId operator.Id, memberId *operator.Id) (int64, error) {
	args := []any{ComputeOpShard(settings, networkId), int16(ComputeOpStateOpen), networkId}
	filter := ""
	if memberId != nil {
		filter = ` AND member_id = $4`
		args = append(args, *memberId)
	}
	rows, err := tx.Query(ctx, `
		SELECT coalesce(sum(hold_nano_usd), 0)::bigint FROM compute_op
		WHERE shard = $1 AND state = $2 AND network_id = $3`+filter, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	held := int64(0)
	if rows.Next() {
		if err := rows.Scan(&held); err != nil {
			return 0, err
		}
	}
	return held, rows.Err()
}

// A page's position: the last row a page answered, newest first, so the next page holds what started before it.
type ComputeChargesCursor struct {
	StartTime time.Time
	ChargeId  operator.Id
}

// A page of the charges a caller may see.
type ComputeChargesPageArgs struct {
	NetworkId operator.Id
	// A Member's: only the charges whose stored member is theirs; nil for the network's.
	MemberId *operator.Id
	// After this row, nil for the first page.
	After *ComputeChargesCursor
	// The most rows the page holds; at most one more is read, to tell whether another page follows.
	Limit int
	// The retention the route holds every answer to (§9.4): no charge that started before Since, and no web search's
	// that started before SearchSince, whatever the partitions and the purge have not dropped yet.
	Since       time.Time
	SearchSince time.Time
}

// One page of charges and whether another follows.
type ComputeChargesPage struct {
	Charges []*ComputeCharge
	More    bool
}

// A page of networkId's per-request charges in tx, newest first by (start_time, charge_id) on the network's
// (network_id, start_time) index: each row's ids, units, amount, absorbed and times. cost_nano_usd, URnetwork's own
// cost, is read as zero and never answered.
func ComputeChargesPageInTx(env operator.Env, ctx context.Context, tx operator.DbTx, args *ComputeChargesPageArgs) (*ComputeChargesPage, error) {
	if args.Limit <= 0 {
		return nil, fmt.Errorf("compute charges: a page holds at least one row")
	}
	sqlArgs := []any{args.NetworkId, args.Since.UTC(), int16(ComputeChargeKindWebSearch), args.SearchSince.UTC()}
	filter := ""
	if args.MemberId != nil {
		sqlArgs = append(sqlArgs, *args.MemberId)
		filter += fmt.Sprintf(` AND member_id = $%d`, len(sqlArgs))
	}
	if args.After != nil {
		sqlArgs = append(sqlArgs, args.After.StartTime.UTC(), args.After.ChargeId)
		filter += fmt.Sprintf(` AND (start_time, charge_id) < ($%d, $%d)`, len(sqlArgs)-1, len(sqlArgs))
	}
	sqlArgs = append(sqlArgs, args.Limit+1)
	rows, err := tx.Query(ctx, `
		SELECT charge_id, kind, subject_ref, sidecar_id, agent_id, member_id, enclave_id, catalog_id, provider, units,
			amount_nano_usd, absorbed_nano_usd, start_time, end_time, settle_time
		FROM compute_charge
		WHERE network_id = $1 AND start_time >= $2 AND (kind <> $3 OR start_time >= $4)`+filter+`
		ORDER BY start_time DESC, charge_id DESC
		LIMIT $`+fmt.Sprint(len(sqlArgs)), sqlArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &ComputeChargesPage{Charges: []*ComputeCharge{}}
	for rows.Next() {
		charge := &ComputeCharge{NetworkId: args.NetworkId}
		var kind int16
		var units []byte
		err := rows.Scan(&charge.ChargeId, &kind, &charge.SubjectRef, &charge.SidecarId, &charge.AgentId, &charge.MemberId,
			&charge.EnclaveId, &charge.CatalogId, &charge.Provider, &units, &charge.AmountNanoUsd, &charge.AbsorbedNanoUsd,
			&charge.StartTime, &charge.EndTime, &charge.SettleTime)
		if err != nil {
			return nil, err
		}
		charge.Kind = ComputeChargeKind(kind)
		charge.Units, err = ParseComputeUnits(units)
		if err != nil {
			return nil, err
		}
		charge.StartTime, charge.EndTime, charge.SettleTime = charge.StartTime.UTC(), charge.EndTime.UTC(), charge.SettleTime.UTC()
		page.Charges = append(page.Charges, charge)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if args.Limit < len(page.Charges) {
		page.Charges = page.Charges[:args.Limit]
		page.More = true
	}
	return page, nil
}

// networkId's day rows of the UTC month month falls in, in tx, a member's alone where memberId is set, at most limit:
// each row of compute_charge_day as compute_settle wrote it, ordered by day and its key. More than limit answers an
// error wrapping ErrComputeAnswerTooLarge, never a part.
func ComputeStatementDaysInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, memberId *operator.Id, month time.Time, limit int) ([]*ComputeChargeDay, error) {
	start := ComputeUtcMonth(month)
	end := start.AddDate(0, 1, 0)
	args := []any{networkId, start.Format(computeDayLayout), end.Format(computeDayLayout)}
	filter := ""
	if memberId != nil {
		filter = ` AND member_id = $4`
		args = append(args, *memberId)
	}
	args = append(args, limit+1)
	rows, err := tx.Query(ctx, `
		SELECT to_char(day, 'YYYY-MM-DD'), kind, sidecar_id, agent_id, catalog_id, member_id, provider, enclave_id,
			input_tokens, output_tokens, cached_tokens, seconds, egress_bytes, searches,
			amount_nano_usd, refunded_nano_usd, count
		FROM compute_charge_day
		WHERE network_id = $1 AND day >= $2::date AND day < $3::date`+filter+`
		ORDER BY day, kind, sidecar_id, agent_id NULLS FIRST, catalog_id NULLS FIRST, member_id NULLS FIRST, provider,
			enclave_id NULLS FIRST
		LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	days := []*ComputeChargeDay{}
	for rows.Next() {
		row := &ComputeChargeDay{NetworkId: networkId}
		var dayText string
		var kind int16
		err := rows.Scan(&dayText, &kind, &row.SidecarId, &row.AgentId, &row.CatalogId, &row.MemberId, &row.Provider, &row.EnclaveId,
			&row.Units.InputTokens, &row.Units.OutputTokens, &row.Units.CachedTokens, &row.Units.Seconds, &row.Units.EgressBytes,
			&row.Units.Searches, &row.AmountNanoUsd, &row.RefundedNanoUsd, &row.Count)
		if err != nil {
			return nil, err
		}
		row.Day, err = time.ParseInLocation(computeDayLayout, dayText, time.UTC)
		if err != nil {
			return nil, err
		}
		row.Kind = ComputeChargeKind(kind)
		days = append(days, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if limit < len(days) {
		return nil, fmt.Errorf("%w: past %d day rows", ErrComputeAnswerTooLarge, limit)
	}
	return days, nil
}

// An answer a route will not cut: more rows than its bound, which the device refuses whole (§14.3's answers).
var ErrComputeAnswerTooLarge = errors.New("compute: the answer holds more rows than its bound")

// networkId's lots of the UTC month month falls in, in tx, at most limit: every lot made in it, bought, granted, an
// adjustment or a redemption's, and every promotion whose expiry fell in it with what of it lapsed (§9.11's "the
// month's statement shows it"), each without its market's reference. More than limit answers an error wrapping
// ErrComputeAnswerTooLarge.
func ComputeStatementLotsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, month time.Time, limit int) ([]*ComputeLot, error) {
	start := ComputeUtcMonth(month)
	end := start.AddDate(0, 1, 0)
	rows, err := tx.Query(ctx, `
		SELECT lot_id, kind, market, amount_nano_usd, remaining_nano_usd, create_time, expire_time, reversed_time,
			lapsed_nano_usd
		FROM compute_lot
		WHERE network_id = $1 AND (
			(create_time >= $2 AND create_time < $3) OR
			(kind = $4 AND lapsed_nano_usd IS NOT NULL AND expire_time >= $2 AND expire_time < $3))
		ORDER BY create_time, lot_id
		LIMIT $5
	`, networkId, start, end, int16(ComputeLotKindPromotion), limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	lots := []*ComputeLot{}
	for rows.Next() {
		lot := &ComputeLot{NetworkId: networkId}
		var kind, market int16
		err := rows.Scan(&lot.LotId, &kind, &market, &lot.AmountNanoUsd, &lot.RemainingNanoUsd, &lot.CreateTime,
			&lot.ExpireTime, &lot.ReversedTime, &lot.LapsedNanoUsd)
		if err != nil {
			return nil, err
		}
		lot.Kind, lot.Market = ComputeLotKind(kind), ComputeMarket(market)
		lot.CreateTime = lot.CreateTime.UTC()
		for _, at := range []**time.Time{&lot.ExpireTime, &lot.ReversedTime} {
			if *at != nil {
				utc := (**at).UTC()
				*at = &utc
			}
		}
		lots = append(lots, lot)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if limit < len(lots) {
		return nil, fmt.Errorf("%w: past %d lots", ErrComputeAnswerTooLarge, limit)
	}
	return lots, nil
}
