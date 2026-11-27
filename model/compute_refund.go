// Refunds' and closure's reads and writes (DESIGN-COMPUTE §9.6, §9.12; BAL-M12-14), each in the caller's transaction
// under the network's fence where it moves the balance:
//
//	ComputeLotForUpdateInTx  one lot, locked
//	ComputeLotRefundInTx     a lot's money back to the card: refunded_nano_usd set and its remaining lowered by it,
//	                         once (compute-plan-money-schema-gaps, QD-1252); a lot refunded before stands as it is
//	ComputeNetworkLotsInTx   a network's lots, locked, in lot order: what its closure refunds or forfeits
//	ComputeChargeGetInTx     one charge by its id, the network's where given, started since a time (the charges'
//	                         retention), which a refund returns
//
// A self-serve refund and a closure's refund are a lot's money back; a charge's refund is a negative charge the
// booking returns to the lots its charge drew (compute_book.go), never these.

package model

import (
	"context"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// lotId's lot in tx, locked FOR UPDATE; nil where none stands.
func ComputeLotForUpdateInTx(env operator.Env, ctx context.Context, tx operator.DbTx, lotId operator.Id) (*ComputeLot, error) {
	lots, err := computeLotQuery(ctx, tx, `SELECT `+computeLotColumns+` FROM compute_lot WHERE lot_id = $1 FOR UPDATE`, lotId)
	if err != nil || len(lots) == 0 {
		return nil, err
	}
	return lots[0], nil
}

// Keeps refundedNanoUsd as lotId's money back to its card in tx, its remaining lowered by as much, where the lot was
// refunded nothing before, is not reversed and holds that much: the lot after, and whether this call refunded it. A
// lot refunded before is answered as it stands.
func ComputeLotRefundInTx(env operator.Env, ctx context.Context, tx operator.DbTx, lotId operator.Id, refundedNanoUsd int64) (*ComputeLot, bool, error) {
	if refundedNanoUsd <= 0 || computeLuaMaxExactInteger < refundedNanoUsd {
		return nil, false, fmt.Errorf("%w: a refund's amount is positive", ErrComputeLotArgs)
	}
	lots, err := computeLotQuery(ctx, tx, `
		UPDATE compute_lot SET refunded_nano_usd = $2, remaining_nano_usd = remaining_nano_usd - $2
		WHERE lot_id = $1 AND refunded_nano_usd IS NULL AND reversed_time IS NULL AND remaining_nano_usd >= $2
		RETURNING `+computeLotColumns, lotId, refundedNanoUsd)
	if err != nil {
		return nil, false, err
	}
	if len(lots) == 1 {
		return lots[0], true, nil
	}
	lot, err := ComputeLotForUpdateInTx(env, ctx, tx, lotId)
	if err != nil {
		return nil, false, err
	}
	if lot == nil {
		return nil, false, fmt.Errorf("%w: no lot %s", ErrComputeLotArgs, lotId)
	}
	return lot, false, nil
}

// networkId's lots in tx, locked FOR UPDATE, in lot order.
func ComputeNetworkLotsInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) ([]*ComputeLot, error) {
	return computeLotQuery(ctx, tx, `SELECT `+computeLotColumns+` FROM compute_lot WHERE network_id = $1 ORDER BY lot_id FOR UPDATE`, networkId)
}

// compute_charge's columns, in the order computeChargeScan reads them.
const computeChargeColumns = `charge_id, network_id, kind, subject_ref, sidecar_id, agent_id, member_id, enclave_id, catalog_id,
	provider, units::text, amount_nano_usd, cost_nano_usd, absorbed_nano_usd, start_time, end_time, settle_time`

// chargeId's charge in tx, of networkId where given, started at or after since; nil where none stands, as past the
// charges' retention, whose partitions are dropped.
func ComputeChargeGetInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId *operator.Id, chargeId operator.Id, since time.Time) (*ComputeCharge, error) {
	sql := `SELECT ` + computeChargeColumns + ` FROM compute_charge WHERE charge_id = $1 AND start_time >= $2`
	args := []any{chargeId, since.UTC()}
	if networkId != nil {
		sql += ` AND network_id = $3`
		args = append(args, *networkId)
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	charge := &ComputeCharge{}
	var kind int16
	var units string
	err = rows.Scan(&charge.ChargeId, &charge.NetworkId, &kind, &charge.SubjectRef, &charge.SidecarId, &charge.AgentId,
		&charge.MemberId, &charge.EnclaveId, &charge.CatalogId, &charge.Provider, &units, &charge.AmountNanoUsd,
		&charge.CostNanoUsd, &charge.AbsorbedNanoUsd, &charge.StartTime, &charge.EndTime, &charge.SettleTime)
	if err != nil {
		return nil, err
	}
	charge.Kind = ComputeChargeKind(kind)
	if charge.Units, err = ParseComputeUnits([]byte(units)); err != nil {
		return nil, err
	}
	charge.StartTime, charge.EndTime, charge.SettleTime = charge.StartTime.UTC(), charge.EndTime.UTC(), charge.SettleTime.UTC()
	return charge, rows.Err()
}
