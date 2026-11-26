// compute_dispute's reads and writes (DESIGN-COMPUTE §6.7, D-BAL-11, compute-8; BAL-M12-14), which the controller's
// compute_dispute.go runs in its transactions:
//
//	ComputeDisputeInsertInTx        a device's charge_mismatch, once by its request id
//	ComputeDisputeGetInTx           one dispute, locked where asked
//	ComputeDisputeNetworkCountInTx  a network's disputes since a time: D-BAL-11's count a UTC day
//	ComputeDisputeProviderDayInTx   a provider's disputes in a UTC day and the networks they came from
//	ComputeProviderRequestsDayInTx  a provider's booked requests in a UTC day, from the day rows
//	ComputeDisputeDecideInTx        a dispute moved from open to upheld or rejected, once
//
// A dispute holds ids and usage numbers alone: the request, the network, the provider, the device's and the
// provider's counts, the charge it holds for review, its state and times.

package model

import (
	"context"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// compute_dispute's columns, in the order computeDisputeQuery reads them.
const computeDisputeColumns = `request_id, network_id, provider, device_units::text, provider_units::text, charge_id, state,
	create_time, update_time`

func computeDisputeQuery(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) ([]*ComputeDispute, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	disputes := []*ComputeDispute{}
	for rows.Next() {
		dispute := &ComputeDispute{}
		var deviceUnits, providerUnits string
		var state int16
		err := rows.Scan(&dispute.RequestId, &dispute.NetworkId, &dispute.Provider, &deviceUnits, &providerUnits,
			&dispute.ChargeId, &state, &dispute.CreateTime, &dispute.UpdateTime)
		if err != nil {
			return nil, err
		}
		if dispute.DeviceUnits, err = ParseComputeUnits([]byte(deviceUnits)); err != nil {
			return nil, err
		}
		if dispute.ProviderUnits, err = ParseComputeUnits([]byte(providerUnits)); err != nil {
			return nil, err
		}
		dispute.State = ComputeDisputeState(state)
		dispute.CreateTime, dispute.UpdateTime = dispute.CreateTime.UTC(), dispute.UpdateTime.UTC()
		disputes = append(disputes, dispute)
	}
	return disputes, rows.Err()
}

// Inserts dispute in tx unless its request id stands: whether this call inserted it, and the dispute that stands.
func ComputeDisputeInsertInTx(env operator.Env, ctx context.Context, tx operator.DbTx, dispute *ComputeDispute) (bool, *ComputeDispute, error) {
	var zero operator.Id
	if dispute.RequestId == zero || dispute.NetworkId == zero || dispute.Provider <= 0 || !dispute.DeviceUnits.Valid() || !dispute.ProviderUnits.Valid() {
		return false, nil, fmt.Errorf("%w: a dispute names its request, network, provider and two counts", ErrComputeLotArgs)
	}
	deviceUnits, err := dispute.DeviceUnits.Json()
	if err != nil {
		return false, nil, err
	}
	providerUnits, err := dispute.ProviderUnits.Json()
	if err != nil {
		return false, nil, err
	}
	inserted, err := computeDisputeQuery(ctx, tx, `
		INSERT INTO compute_dispute (request_id, network_id, provider, device_units, provider_units, charge_id, state, create_time, update_time)
		VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8, $8)
		ON CONFLICT (request_id) DO NOTHING
		RETURNING `+computeDisputeColumns,
		dispute.RequestId, dispute.NetworkId, dispute.Provider, string(deviceUnits), string(providerUnits), dispute.ChargeId,
		int16(ComputeDisputeStateOpen), dispute.CreateTime.UTC())
	if err != nil {
		return false, nil, err
	}
	if len(inserted) == 1 {
		return true, inserted[0], nil
	}
	stands, err := ComputeDisputeGetInTx(env, ctx, tx, dispute.RequestId, false)
	if err != nil {
		return false, nil, err
	}
	if stands == nil {
		return false, nil, operator.ErrDbRerun
	}
	if stands.NetworkId != dispute.NetworkId {
		return false, nil, fmt.Errorf("%w: the request is another network's dispute", ErrComputeLotArgs)
	}
	return false, stands, nil
}

// requestId's dispute in tx, nil where none stands; locked FOR UPDATE where lock is set.
func ComputeDisputeGetInTx(env operator.Env, ctx context.Context, tx operator.DbTx, requestId operator.Id, lock bool) (*ComputeDispute, error) {
	sql := `SELECT ` + computeDisputeColumns + ` FROM compute_dispute WHERE request_id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	disputes, err := computeDisputeQuery(ctx, tx, sql, requestId)
	if err != nil || len(disputes) == 0 {
		return nil, err
	}
	return disputes[0], nil
}

// One count a query selects.
func computeCountInTx(ctx context.Context, tx operator.DbTx, sql string, args ...any) (int64, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := int64(0)
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return 0, err
		}
	}
	return count, rows.Err()
}

// networkId's disputes made at or after since, in tx, on the network's (network_id, create_time) index.
func ComputeDisputeNetworkCountInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, since time.Time) (int64, error) {
	return computeCountInTx(ctx, tx, `SELECT count(*) FROM compute_dispute WHERE network_id = $1 AND create_time >= $2`, networkId, since.UTC())
}

// provider's disputes in the UTC day of day and the networks they came from, in tx.
func ComputeDisputeProviderDayInTx(env operator.Env, ctx context.Context, tx operator.DbTx, provider int16, day time.Time) (disputes int64, networks int64, returnErr error) {
	start := ComputeUtcDay(day)
	rows, err := tx.Query(ctx, `
		SELECT count(*), count(DISTINCT network_id) FROM compute_dispute
		WHERE provider = $1 AND create_time >= $2 AND create_time < $3
	`, provider, start, start.AddDate(0, 0, 1))
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&disputes, &networks); err != nil {
			return 0, 0, err
		}
	}
	return disputes, networks, rows.Err()
}

// provider's booked inference requests in the UTC day of day, across networks, from compute_charge_day.
func ComputeProviderRequestsDayInTx(env operator.Env, ctx context.Context, tx operator.DbTx, provider int16, day time.Time) (int64, error) {
	return computeCountInTx(ctx, tx, `
		SELECT coalesce(sum(count), 0)::bigint FROM compute_charge_day WHERE provider = $1 AND day = $2::date AND kind = $3
	`, provider, ComputeUtcDay(day).Format(computeDayLayout), int16(ComputeChargeKindInference))
}

// Moves requestId's dispute from open to state in tx: the dispute after, and whether this call moved it. A dispute
// decided before is answered as it stands.
func ComputeDisputeDecideInTx(env operator.Env, ctx context.Context, tx operator.DbTx, requestId operator.Id, state ComputeDisputeState, now time.Time) (*ComputeDispute, bool, error) {
	if state != ComputeDisputeStateUpheld && state != ComputeDisputeStateRejected {
		return nil, false, fmt.Errorf("%w: a dispute is upheld or rejected", ErrComputeLotArgs)
	}
	moved, err := computeDisputeQuery(ctx, tx, `
		UPDATE compute_dispute SET state = $2, update_time = $3 WHERE request_id = $1 AND state = $4
		RETURNING `+computeDisputeColumns, requestId, int16(state), now.UTC(), int16(ComputeDisputeStateOpen))
	if err != nil {
		return nil, false, err
	}
	if len(moved) == 1 {
		return moved[0], true, nil
	}
	stands, err := ComputeDisputeGetInTx(env, ctx, tx, requestId, true)
	return stands, false, err
}
