// GET /compute/charges and GET /compute/statement (DESIGN-COMPUTE §9.4, §9.10, §9.11, §9.13, §14.3, R-BAL-7; BAL-M12-15),
// registered with the api/compute frame (compute_api.go), which has checked by then that the caller sees the network's
// charges (an Owner, Billing admin, Admin, Network admin, IT admin or Auditor) or a Member's own, from a person's
// surface, and that the query names only the route's keys:
//
//	charges    ?cursor=&limit=: per-request charges, newest first, a page at a time, each as ids, units, its amount
//	           and what URnetwork covered of it (absorbed) and its times; never URnetwork's cost. A Member's are the
//	           charges whose stored member is theirs, which the broker wrote at the hold, so a SponsorSet moves no
//	           earlier charge (§9.10). A page holds at most limit rows, limit at most the ledger's ChargesPageRowCount
//	           (the device's own, 100), and its next_cursor, empty after the last page, is the opaque position of its
//	           last row. Rows past §9.4's retention are never answered: none started more than ChargeRetention ago (90
//	           days), and no web search's more than SearchChargeRetention ago (72 hours), whatever the partitions and
//	           the purge have not dropped yet.
//	statement  ?month=YYYY-MM: the UTC month's day rows by kind, model, enclave, member, agent and sidecar, as
//	           compute_settle wrote them, and the lots bought, granted or redeemed in it, with each promotion whose
//	           expiry fell in it and what of it lapsed (§9.11). A Member's statement holds the day rows that count to
//	           them and no lot: the lots are the network's credit, which no charge of theirs is (a reading, reported).
//	           Each lot is answered without its market's reference (the PaymentIntent, the store's transaction).
//
// The answers are the device's computeChargeAnswer and statement bodies (sidecar/compute_client_api.go): ids and typed
// numbers only (I-13), times as Unix milliseconds, days and months in UTC (Q-BAL-8). An answer past the ledger's
// AnswerMaxRowCount, which the device refuses whole, is refused here as too_large rather than cut.

package handler

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

func init() {
	RegisterComputeApiHandler(http.MethodGet, "/compute/charges", NewComputeChargesHandler(nil))
	RegisterComputeApiHandler(http.MethodGet, "/compute/statement", NewComputeStatementHandler(nil))
}

// An answer past the ledger's AnswerMaxRowCount, which the device would refuse whole: refused, never cut.
const ComputeApiRefusalTooLarge = "too_large"

// A cursor's layout: the last row's start time in Unix microseconds, big-endian, then its charge id, base64url
// without padding, so it holds only the device's cursor alphabet. An identifier of the format, not a limit.
const (
	computeChargesCursorTimeByteCount = 8
	computeChargesCursorByteCount     = computeChargesCursorTimeByteCount + 16
	computeStatementMonthLayout       = "2006-01"
	computeStatementDayLayout         = "2006-01-02"
)

// One charge as the device reads it.
type ComputeChargeBody struct {
	ChargeId        operator.Id        `json:"charge_id"`
	Kind            int16              `json:"kind"`
	SubjectRef      operator.Id        `json:"subject_ref"`
	SidecarId       operator.Id        `json:"sidecar_id"`
	AgentId         *operator.Id       `json:"agent_id,omitempty"`
	MemberId        *operator.Id       `json:"member_id,omitempty"`
	EnclaveId       *operator.Id       `json:"enclave_id,omitempty"`
	CatalogId       string             `json:"catalog_id,omitempty"`
	Provider        int16              `json:"provider"`
	Units           model.ComputeUnits `json:"units"`
	AmountNanoUsd   int64              `json:"amount_nano_usd"`
	AbsorbedNanoUsd int64              `json:"absorbed_nano_usd"`
	StartTimeMs     int64              `json:"start_time_ms"`
	EndTimeMs       int64              `json:"end_time_ms"`
	SettleTimeMs    int64              `json:"settle_time_ms"`
}

// GET /compute/charges' answer.
type ComputeChargesAnswer struct {
	Charges []*ComputeChargeBody `json:"charges"`
	// The next page's cursor; empty after the last page.
	NextCursor string `json:"next_cursor"`
}

// One day row of a statement as the device reads it.
type ComputeStatementRowBody struct {
	Day             string             `json:"day"`
	Kind            int16              `json:"kind"`
	SidecarId       operator.Id        `json:"sidecar_id"`
	AgentId         *operator.Id       `json:"agent_id,omitempty"`
	CatalogId       string             `json:"catalog_id,omitempty"`
	MemberId        *operator.Id       `json:"member_id,omitempty"`
	Provider        int16              `json:"provider"`
	EnclaveId       *operator.Id       `json:"enclave_id,omitempty"`
	Units           model.ComputeUnits `json:"units"`
	AmountNanoUsd   int64              `json:"amount_nano_usd"`
	RefundedNanoUsd int64              `json:"refunded_nano_usd"`
	Count           int64              `json:"count"`
}

// One lot of a statement as the device reads it, without its market's reference.
type ComputeStatementLotBody struct {
	LotId            operator.Id `json:"lot_id"`
	Kind             int16       `json:"kind"`
	Market           int16       `json:"market"`
	AmountNanoUsd    int64       `json:"amount_nano_usd"`
	RemainingNanoUsd int64       `json:"remaining_nano_usd"`
	CreateTimeMs     int64       `json:"create_time_ms"`
	ExpireTimeMs     *int64      `json:"expire_time_ms,omitempty"`
	ReversedTimeMs   *int64      `json:"reversed_time_ms,omitempty"`
	LapsedNanoUsd    *int64      `json:"lapsed_nano_usd,omitempty"`
}

// GET /compute/statement's answer.
type ComputeStatementAnswer struct {
	Month string                     `json:"month"`
	Rows  []*ComputeStatementRowBody `json:"rows"`
	Lots  []*ComputeStatementLotBody `json:"lots"`
}

// The cursor of a page's last row.
func ComputeChargesCursorText(cursor *model.ComputeChargesCursor) string {
	data := make([]byte, computeChargesCursorByteCount)
	binary.BigEndian.PutUint64(data, uint64(cursor.StartTime.UnixMicro()))
	copy(data[computeChargesCursorTimeByteCount:], cursor.ChargeId[:])
	return base64.RawURLEncoding.EncodeToString(data)
}

// The position a cursor names, or an error for one no page answered.
func ParseComputeChargesCursor(text string) (*model.ComputeChargesCursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(data) != computeChargesCursorByteCount {
		return nil, errors.New("compute charges: a cursor no page answered")
	}
	cursor := &model.ComputeChargesCursor{
		StartTime: time.UnixMicro(int64(binary.BigEndian.Uint64(data))).UTC(),
	}
	copy(cursor.ChargeId[:], data[computeChargesCursorTimeByteCount:])
	return cursor, nil
}

// The member a caller's reads are filtered to: nil for one who sees the network's, theirs for a Member. The frame has
// refused every other caller.
func computeApiViewMember(caller *ComputeApiCaller) *operator.Id {
	if caller.SeesNetwork() {
		return nil
	}
	if memberId, ok := caller.SeesMember(); ok {
		return &memberId
	}
	// unreachable past the frame's check; a caller that sees neither reads a member no row names
	none := operator.Id{}
	return &none
}

// A bad request's refusal.
func computeApiBadRequest() *ComputeApiRefusal {
	return computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
}

// The body of a charge.
func computeChargeBodyOf(charge *model.ComputeCharge) *ComputeChargeBody {
	body := &ComputeChargeBody{
		ChargeId:        charge.ChargeId,
		Kind:            int16(charge.Kind),
		SubjectRef:      charge.SubjectRef,
		SidecarId:       charge.SidecarId,
		AgentId:         charge.AgentId,
		MemberId:        charge.MemberId,
		EnclaveId:       charge.EnclaveId,
		Provider:        charge.Provider,
		Units:           charge.Units,
		AmountNanoUsd:   charge.AmountNanoUsd,
		AbsorbedNanoUsd: charge.AbsorbedNanoUsd,
		StartTimeMs:     charge.StartTime.UnixMilli(),
		EndTimeMs:       charge.EndTime.UnixMilli(),
		SettleTimeMs:    charge.SettleTime.UnixMilli(),
	}
	if charge.CatalogId != nil {
		body.CatalogId = *charge.CatalogId
	}
	return body
}

// GET /compute/charges' handler over the ledger's settings, nil taking the defaults.
func NewComputeChargesHandler(settings *model.ComputeLedgerSettings) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		limit := settings.ChargesPageRowCount
		if text := request.Query.Get("limit"); text != "" {
			asked, err := strconv.Atoi(text)
			if err != nil || asked <= 0 || strconv.Itoa(asked) != text {
				return nil, computeApiBadRequest()
			}
			limit = min(limit, asked)
		}
		if limit <= 0 || settings.AnswerMaxRowCount < limit {
			return nil, computeApiRefusal(http.StatusRequestEntityTooLarge, ComputeApiRefusalTooLarge)
		}
		var after *model.ComputeChargesCursor
		if text := request.Query.Get("cursor"); text != "" {
			cursor, err := ParseComputeChargesCursor(text)
			if err != nil {
				return nil, computeApiBadRequest()
			}
			after = cursor
		}
		clock, err := env.Clock()
		if err != nil {
			return nil, err
		}
		db, err := env.Db()
		if err != nil {
			return nil, err
		}
		now := clock.Now()
		var page *model.ComputeChargesPage
		err = db.Tx(ctx, func(tx operator.DbTx) error {
			var err error
			page, err = model.ComputeChargesPageInTx(env, ctx, tx, &model.ComputeChargesPageArgs{
				NetworkId:   caller.NetworkId,
				MemberId:    computeApiViewMember(caller),
				After:       after,
				Limit:       limit,
				Since:       now.Add(-settings.ChargeRetention),
				SearchSince: now.Add(-settings.SearchChargeRetention),
			})
			return err
		}, operator.DbIsolationRepeatableRead, operator.DbReadOnly)
		if err != nil {
			return nil, err
		}
		answer := &ComputeChargesAnswer{Charges: []*ComputeChargeBody{}}
		for _, charge := range page.Charges {
			answer.Charges = append(answer.Charges, computeChargeBodyOf(charge))
		}
		if page.More && 0 < len(page.Charges) {
			last := page.Charges[len(page.Charges)-1]
			answer.NextCursor = ComputeChargesCursorText(&model.ComputeChargesCursor{StartTime: last.StartTime, ChargeId: last.ChargeId})
		}
		return answer, nil
	}
}

// The UTC month a statement names, YYYY-MM in its one form.
func computeStatementMonthOf(text string) (time.Time, bool) {
	month, err := time.ParseInLocation(computeStatementMonthLayout, text, time.UTC)
	if err != nil || month.Format(computeStatementMonthLayout) != text {
		return time.Time{}, false
	}
	return month, true
}

// The answer of a month's day rows and lots.
func ComputeStatementAnswerOf(month time.Time, days []*model.ComputeChargeDay, lots []*model.ComputeLot) *ComputeStatementAnswer {
	answer := &ComputeStatementAnswer{
		Month: month.UTC().Format(computeStatementMonthLayout),
		Rows:  []*ComputeStatementRowBody{},
		Lots:  []*ComputeStatementLotBody{},
	}
	for _, day := range days {
		row := &ComputeStatementRowBody{
			Day:             day.Day.UTC().Format(computeStatementDayLayout),
			Kind:            int16(day.Kind),
			SidecarId:       day.SidecarId,
			AgentId:         day.AgentId,
			MemberId:        day.MemberId,
			Provider:        day.Provider,
			EnclaveId:       day.EnclaveId,
			Units:           day.Units,
			AmountNanoUsd:   day.AmountNanoUsd,
			RefundedNanoUsd: day.RefundedNanoUsd,
			Count:           day.Count,
		}
		if day.CatalogId != nil {
			row.CatalogId = *day.CatalogId
		}
		answer.Rows = append(answer.Rows, row)
	}
	millis := func(at *time.Time) *int64 {
		if at == nil {
			return nil
		}
		value := at.UnixMilli()
		return &value
	}
	for _, lot := range lots {
		answer.Lots = append(answer.Lots, &ComputeStatementLotBody{
			LotId:            lot.LotId,
			Kind:             int16(lot.Kind),
			Market:           int16(lot.Market),
			AmountNanoUsd:    lot.AmountNanoUsd,
			RemainingNanoUsd: lot.RemainingNanoUsd,
			CreateTimeMs:     lot.CreateTime.UnixMilli(),
			ExpireTimeMs:     millis(lot.ExpireTime),
			ReversedTimeMs:   millis(lot.ReversedTime),
			LapsedNanoUsd:    lot.LapsedNanoUsd,
		})
	}
	return answer
}

// GET /compute/statement's handler over the ledger's settings, nil taking the defaults.
func NewComputeStatementHandler(settings *model.ComputeLedgerSettings) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		month, ok := computeStatementMonthOf(request.Query.Get("month"))
		if !ok {
			return nil, computeApiBadRequest()
		}
		db, err := env.Db()
		if err != nil {
			return nil, err
		}
		memberId := computeApiViewMember(caller)
		var days []*model.ComputeChargeDay
		lots := []*model.ComputeLot{}
		err = db.Tx(ctx, func(tx operator.DbTx) error {
			var err error
			lots = lots[:0]
			days, err = model.ComputeStatementDaysInTx(env, ctx, tx, caller.NetworkId, memberId, month, settings.AnswerMaxRowCount)
			if err != nil {
				return err
			}
			if memberId != nil {
				// a Member's statement holds what counts to them, and the lots are the network's credit
				return nil
			}
			lots, err = model.ComputeStatementLotsInTx(env, ctx, tx, caller.NetworkId, month, settings.AnswerMaxRowCount-len(days))
			return err
		}, operator.DbIsolationRepeatableRead, operator.DbReadOnly)
		if errors.Is(err, model.ErrComputeAnswerTooLarge) {
			return nil, computeApiRefusal(http.StatusRequestEntityTooLarge, ComputeApiRefusalTooLarge)
		}
		if err != nil {
			return nil, err
		}
		return ComputeStatementAnswerOf(month, days, lots), nil
	}
}
