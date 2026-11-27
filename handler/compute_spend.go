// GET /compute/spend?by= (DESIGN-COMPUTE §9.10, §9.13, §14.3, D-BAL-6, D-BAL-7, CO-22; BAL-M12-15): §9.13's spend view,
// registered with the api/compute frame (compute_api.go), which has checked by then that the call comes from the
// person's consented device, untagged and neither an enclave, ephemeral nor Delegation-admitted (DESIGN §8.5, owner
// decision 126; Q-BAL-11), and that the caller sees the network's charges or a Member's own:
//
//	lines   one a charge kind with any figure, in kind order: remote inference (1), an enclave's running time (2)
//	        and its host egress (4), each its own line, adjustments (5, net) and web search (6); each with its
//	        total since the network's first charge, from compute_charge_total, and each of the last SpendDayCount
//	        UTC days, today so far and the 6 before, from compute_charge_day, in nano-USD net of refunds with the
//	        refunds apart, the charges counted and their typed units
//	rows    by the breakdown: provider, model (a shape for an enclave), enclave or member, each with its total and its
//	        days; by agent the days alone, since no total is kept by agent (Q-BAL-10); none with no breakdown
//	held    the open operations' holds apart, which are not spend: the network's for a role that sees the network,
//	        a Member's view the holds that count to its member
//	exact   compute_account.update_time, the last settlement every figure is exact to, read with the figures in one
//	        REPEATABLE READ transaction, so they are of one moment
//
// A Member's view holds only what counts to its member (§9.13's who): the rows whose stored member is theirs, which the
// broker wrote at the hold, so a SponsorSet moves no earlier charge. The view reads the rollups alone, never a
// per-request row; what URnetwork absorbed of a direct call is in no figure. The days are UTC days the route computes
// from its own clock, never a session's zone (Q-BAL-8), and the device shows their local bounds beside "UTC".
//
// The answer is the device's computeSpend body (sidecar/compute_client_api.go): ids and typed numbers only (I-13); the
// device names the ids (BAL-M12-17's labeler). An answer past the ledger's AnswerMaxRowCount is refused as too_large,
// never cut.

package handler

import (
	"bytes"
	"cmp"
	"context"
	"net/http"
	"slices"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

func init() {
	RegisterComputeApiHandler(http.MethodGet, "/compute/spend", NewComputeSpendHandler(nil))
}

// One figure of the view as the device reads it.
type ComputeSpendFiguresBody struct {
	AmountNanoUsd   int64              `json:"amount_nano_usd"`
	RefundedNanoUsd int64              `json:"refunded_nano_usd"`
	Count           int64              `json:"count"`
	Units           model.ComputeUnits `json:"units"`
}

// One row of a line's breakdown: its key by the view's dimension, and its figures. A row by agent has no total.
type ComputeSpendRowBody struct {
	Provider  *int16                     `json:"provider,omitempty"`
	CatalogId *string                    `json:"catalog_id,omitempty"`
	EnclaveId *operator.Id               `json:"enclave_id,omitempty"`
	MemberId  *operator.Id               `json:"member_id,omitempty"`
	AgentId   *operator.Id               `json:"agent_id,omitempty"`
	Total     *ComputeSpendFiguresBody   `json:"total,omitempty"`
	Days      []*ComputeSpendFiguresBody `json:"days"`
}

// One line of the view: a charge kind's figures and its rows.
type ComputeSpendLineBody struct {
	Kind  int16                      `json:"kind"`
	Total *ComputeSpendFiguresBody   `json:"total"`
	Days  []*ComputeSpendFiguresBody `json:"days"`
	Rows  []*ComputeSpendRowBody     `json:"rows"`
}

// GET /compute/spend's answer.
type ComputeSpendAnswer struct {
	By string `json:"by"`
	// The window's UTC days, oldest first, the last today so far.
	Days []string `json:"days"`
	// The network's first charge day, the totals' since; empty before any.
	FirstChargeDay string                  `json:"first_charge_day"`
	HeldNanoUsd    int64                   `json:"held_nano_usd"`
	UpdateTimeMs   int64                   `json:"update_time_ms"`
	Lines          []*ComputeSpendLineBody `json:"lines"`
}

// What one spend read holds, from one snapshot.
type ComputeSpendRead struct {
	By model.ComputeSpendBy
	// The window's UTC days, oldest first, the last today.
	Days []time.Time
	// The lifetime totals by kind and the breakdown; by agent, by kind alone.
	Totals  []*model.ComputeSpendGroup
	DayRows []*model.ComputeSpendGroup
	// The network's account, nil before any.
	Account     *model.ComputeAccount
	HeldNanoUsd int64
}

// The window of dayCount UTC days that ends with now's.
func ComputeSpendWindow(now time.Time, dayCount int) []time.Time {
	today := model.ComputeUtcDay(now)
	days := make([]time.Time, 0, max(0, dayCount))
	for i := dayCount - 1; 0 <= i; i -= 1 {
		days = append(days, today.AddDate(0, 0, -i))
	}
	return days
}

// A row's key by the view's dimension, comparable, so groups of one key sum together.
type computeSpendKey struct {
	provider     int16
	hasProvider  bool
	catalogId    string
	hasCatalogId bool
	enclaveId    operator.Id
	hasEnclaveId bool
	memberId     operator.Id
	hasMemberId  bool
	agentId      operator.Id
	hasAgentId   bool
}

// A group's key.
func computeSpendKeyOf(group *model.ComputeSpendGroup) computeSpendKey {
	key := computeSpendKey{}
	if group.Provider != nil {
		key.provider, key.hasProvider = *group.Provider, true
	}
	if group.CatalogId != nil {
		key.catalogId, key.hasCatalogId = *group.CatalogId, true
	}
	if group.EnclaveId != nil {
		key.enclaveId, key.hasEnclaveId = *group.EnclaveId, true
	}
	if group.MemberId != nil {
		key.memberId, key.hasMemberId = *group.MemberId, true
	}
	if group.AgentId != nil {
		key.agentId, key.hasAgentId = *group.AgentId, true
	}
	return key
}

// The order rows answer in: a key's absent parts first, then by value.
func computeSpendKeyCompare(a computeSpendKey, b computeSpendKey) int {
	present := func(x bool) int {
		if x {
			return 1
		}
		return 0
	}
	if c := cmp.Compare(present(a.hasProvider), present(b.hasProvider)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.provider, b.provider); c != 0 {
		return c
	}
	if c := cmp.Compare(present(a.hasCatalogId), present(b.hasCatalogId)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.catalogId, b.catalogId); c != 0 {
		return c
	}
	for _, pair := range [][2]struct {
		has bool
		id  operator.Id
	}{
		{{has: a.hasEnclaveId, id: a.enclaveId}, {has: b.hasEnclaveId, id: b.enclaveId}},
		{{has: a.hasAgentId, id: a.agentId}, {has: b.hasAgentId, id: b.agentId}},
		{{has: a.hasMemberId, id: a.memberId}, {has: b.hasMemberId, id: b.memberId}},
	} {
		if c := cmp.Compare(present(pair[0].has), present(pair[1].has)); c != 0 {
			return c
		}
		if c := bytes.Compare(pair[0].id[:], pair[1].id[:]); c != 0 {
			return c
		}
	}
	return 0
}

// The figures of sums.
func computeSpendFiguresOf(sums model.ComputeSpendSums) *ComputeSpendFiguresBody {
	return &ComputeSpendFiguresBody{
		AmountNanoUsd:   sums.AmountNanoUsd,
		RefundedNanoUsd: sums.RefundedNanoUsd,
		Count:           sums.Count,
		Units:           sums.Units,
	}
}

// The answer of one read: a line per charge kind with any figure, its rows by the breakdown, and the window's days,
// past maxRowCount lines and rows refused as too_large.
func ComputeSpendAnswerOf(read *ComputeSpendRead, maxRowCount int) (*ComputeSpendAnswer, error) {
	dayIndexes := map[time.Time]int{}
	answer := &ComputeSpendAnswer{
		By:          string(read.By),
		Days:        []string{},
		HeldNanoUsd: max(0, read.HeldNanoUsd),
		Lines:       []*ComputeSpendLineBody{},
	}
	for i, day := range read.Days {
		dayIndexes[day] = i
		answer.Days = append(answer.Days, day.Format(computeStatementDayLayout))
	}
	if account := read.Account; account != nil {
		answer.UpdateTimeMs = account.UpdateTime.UnixMilli()
		if account.FirstChargeDay != nil {
			answer.FirstChargeDay = account.FirstChargeDay.UTC().Format(computeStatementDayLayout)
		}
	}
	// one line's sums: the total, each day, and per key the same
	type keySums struct {
		total model.ComputeSpendSums
		days  []model.ComputeSpendSums
	}
	type lineSums struct {
		keySums
		keys    []computeSpendKey
		keyRows map[computeSpendKey]*keySums
	}
	kindLines := map[model.ComputeChargeKind]*lineSums{}
	lineOf := func(kind model.ComputeChargeKind) *lineSums {
		line, ok := kindLines[kind]
		if !ok {
			line = &lineSums{keySums: keySums{days: make([]model.ComputeSpendSums, len(read.Days))}, keyRows: map[computeSpendKey]*keySums{}}
			kindLines[kind] = line
		}
		return line
	}
	rowOf := func(line *lineSums, key computeSpendKey) *keySums {
		row, ok := line.keyRows[key]
		if !ok {
			row = &keySums{days: make([]model.ComputeSpendSums, len(read.Days))}
			line.keyRows[key] = row
			line.keys = append(line.keys, key)
		}
		return row
	}
	for _, group := range read.Totals {
		if !group.Kind.Written() {
			continue
		}
		line := lineOf(group.Kind)
		line.total = line.total.Add(group.Sums)
		// by agent the totals are the kinds' alone, which no row carries (Q-BAL-10)
		if read.By != model.ComputeSpendByNone && read.By.HasTotal() {
			row := rowOf(line, computeSpendKeyOf(group))
			row.total = row.total.Add(group.Sums)
		}
	}
	for _, group := range read.DayRows {
		if !group.Kind.Written() || group.Day == nil {
			continue
		}
		index, ok := dayIndexes[model.ComputeUtcDay(*group.Day)]
		if !ok {
			continue
		}
		line := lineOf(group.Kind)
		line.days[index] = line.days[index].Add(group.Sums)
		if read.By != model.ComputeSpendByNone {
			row := rowOf(line, computeSpendKeyOf(group))
			row.days[index] = row.days[index].Add(group.Sums)
		}
	}
	kinds := []model.ComputeChargeKind{}
	for kind := range kindLines {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	rowCount := 0
	for _, kind := range kinds {
		line := kindLines[kind]
		body := &ComputeSpendLineBody{Kind: int16(kind), Total: computeSpendFiguresOf(line.total), Days: []*ComputeSpendFiguresBody{}, Rows: []*ComputeSpendRowBody{}}
		for _, sums := range line.days {
			body.Days = append(body.Days, computeSpendFiguresOf(sums))
		}
		slices.SortFunc(line.keys, computeSpendKeyCompare)
		for _, key := range line.keys {
			sums := line.keyRows[key]
			row := &ComputeSpendRowBody{Days: []*ComputeSpendFiguresBody{}}
			switch read.By {
			case model.ComputeSpendByProvider:
				provider := key.provider
				row.Provider = &provider
			case model.ComputeSpendByModel:
				if key.hasCatalogId {
					catalogId := key.catalogId
					row.CatalogId = &catalogId
				}
			case model.ComputeSpendByEnclave:
				if key.hasEnclaveId {
					enclaveId := key.enclaveId
					row.EnclaveId = &enclaveId
				}
			case model.ComputeSpendByMember:
				if key.hasMemberId {
					memberId := key.memberId
					row.MemberId = &memberId
				}
			case model.ComputeSpendByAgent:
				if key.hasAgentId {
					agentId := key.agentId
					row.AgentId = &agentId
				}
				if key.hasMemberId {
					memberId := key.memberId
					row.MemberId = &memberId
				}
			}
			if read.By.HasTotal() {
				row.Total = computeSpendFiguresOf(sums.total)
			}
			for _, day := range sums.days {
				row.Days = append(row.Days, computeSpendFiguresOf(day))
			}
			body.Rows = append(body.Rows, row)
		}
		rowCount += 1 + len(body.Rows)
		answer.Lines = append(answer.Lines, body)
	}
	if maxRowCount < rowCount {
		return nil, computeApiRefusal(http.StatusRequestEntityTooLarge, ComputeApiRefusalTooLarge)
	}
	return answer, nil
}

// The view's read for caller's role by by at now, in one REPEATABLE READ, read-only transaction.
func ComputeSpendReadOf(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, memberId *operator.Id, by model.ComputeSpendBy, now time.Time) (*ComputeSpendRead, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	read := &ComputeSpendRead{By: by, Days: ComputeSpendWindow(now, settings.SpendDayCount)}
	if len(read.Days) == 0 {
		return read, nil
	}
	// every line has its total; by agent, which keeps no total of its own, the kinds' totals alone (Q-BAL-10)
	totalsBy := by
	if !by.HasTotal() {
		totalsBy = model.ComputeSpendByNone
	}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		read.Totals, err = model.ComputeSpendTotalsInTx(env, ctx, tx, networkId, memberId, totalsBy)
		if err != nil {
			return err
		}
		read.DayRows, err = model.ComputeSpendDaysInTx(env, ctx, tx, networkId, memberId, by, read.Days[0], read.Days[len(read.Days)-1])
		if err != nil {
			return err
		}
		read.HeldNanoUsd, err = model.ComputeHeldInTx(env, ctx, tx, settings, networkId, memberId)
		if err != nil {
			return err
		}
		read.Account, err = model.ComputeAccountInTx(env, ctx, tx, networkId)
		return err
	}, operator.DbIsolationRepeatableRead, operator.DbReadOnly)
	if err != nil {
		return nil, err
	}
	return read, nil
}

// The route's handler over the ledger's settings, nil taking the defaults.
func NewComputeSpendHandler(settings *model.ComputeLedgerSettings) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		by, err := model.ParseComputeSpendBy(request.Query.Get("by"))
		if err != nil {
			return nil, computeApiBadRequest()
		}
		if settings.SpendDayCount <= 0 {
			return nil, computeApiRefusal(http.StatusInternalServerError, ComputeApiRefusalInternal)
		}
		clock, err := env.Clock()
		if err != nil {
			return nil, err
		}
		read, err := ComputeSpendReadOf(env, ctx, settings, caller.NetworkId, computeApiViewMember(caller), by, clock.Now())
		if err != nil {
			return nil, err
		}
		return ComputeSpendAnswerOf(read, settings.AnswerMaxRowCount)
	}
}
