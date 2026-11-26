// compute_op's queries (DESIGN-COMPUTE §9.4, §9.7, D-BAL-13, D-BAL-14; BAL-M12-03): one row a billable operation, from
// before its liability arises until it is booked, keyed by its operation key, which is its charge's charge_id, and
// fixing its charge's start_time. Every move is conditional on the state before it, so a repeated receipt, report or
// interval changes nothing and one whose row is gone books nothing:
//
//	ComputeOpInsertOpen     an admission's row, open, before anything binds URnetwork to a provider for it
//	ComputeOpSettle         open to settled, with its outcome, a kind held at its worst case never past its hold
//	ComputeOpVoid           open to void: released at no charge
//	ComputeOpInsertSettled  a host egress hour's, a refund's or an adjustment's row, written already settled, its key
//	                        claiming its subject once
//	ComputeOpGet            one row as it stands
//	ComputeOpListOpen       the rows open past an age, oldest first, which compute_op_recover works through
//	ComputeOpCheck          what an admission checks of its row before it takes a hold
//
// compute_book.go moves settled rows to applied and deletes booked ones (BAL-M12-04). A row holds ids, amounts, units,
// codes and times, never a prompt, an output, a file or a query (R-BAL-6): the two strings it keeps are a catalog id,
// held to the settings' bound and to printable ASCII without spaces, and a TEE call's provider reference, held the
// same way and cleared once the row settles (compute-1).
//
// Each function takes the Env first (owner decision 594) and runs its own statements, a transaction where it reads
// before it writes; none is called inside another's transaction.

package model

import (
	"context"
	"errors"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

var (
	// An operation's row the ledger cannot take: a field out of range or a string that is no id.
	ErrComputeOpArgs = errors.New("compute op: arguments refused")
	// No row of the key in the network: never admitted, or booked and deleted, or another network's.
	ErrComputeOpNotFound = errors.New("compute op: no row of this key")
)

// compute_op's columns, in the order computeOpScan reads them.
const computeOpColumns = `op_key, network_id, shard, state, kind, subject_ref, attempt, sidecar_id, agent_id, member_id,
	enclave_id, catalog_id, catalog_version, provider, price_read, provider_ref, hold_nano_usd, reserve_nano_usd,
	start_time, outcome::text`

// One compute_op row from rows, in computeOpColumns' order.
func computeOpScan(rows operator.DbRows) (*ComputeOp, error) {
	op := &ComputeOp{}
	var shard, state, kind, provider int16
	var outcome *string
	err := rows.Scan(
		&op.OpKey, &op.NetworkId, &shard, &state, &kind, &op.SubjectRef, &op.Attempt, &op.SidecarId, &op.AgentId,
		&op.MemberId, &op.EnclaveId, &op.CatalogId, &op.CatalogVersion, &provider, &op.PriceRead, &op.ProviderRef,
		&op.HoldNanoUsd, &op.ReserveNanoUsd, &op.StartTime, &outcome,
	)
	if err != nil {
		return nil, err
	}
	op.Shard = shard
	op.State = ComputeOpState(state)
	op.Kind = ComputeChargeKind(kind)
	op.Provider = provider
	op.StartTime = op.StartTime.UTC()
	if outcome != nil {
		parsed, err := ParseComputeOpOutcome([]byte(*outcome))
		if err != nil {
			return nil, err
		}
		op.Outcome = parsed
	}
	return op, nil
}

// The rows a query selects, each scanned.
func computeOpQuery(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) ([]*ComputeOp, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ops := []*ComputeOp{}
	for rows.Next() {
		op, err := computeOpScan(rows)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, rows.Err()
}

// The one row a query selects, or ErrComputeOpNotFound.
func computeOpQueryOne(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) (*ComputeOp, error) {
	ops, err := computeOpQuery(ctx, querier, sql, args...)
	if err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, ErrComputeOpNotFound
	}
	return ops[0], nil
}

// Whether text may stand in a row's string column: printable ASCII without spaces, within bound. Such a string is an
// id, never words a person or a model wrote.
func computeOpTokenValid(text string, bound int) bool {
	if text == "" || bound < len(text) {
		return false
	}
	for i := 0; i < len(text); i += 1 {
		if text[i] <= ' ' || '~' < text[i] {
			return false
		}
	}
	return true
}

// Checks op as a row the ledger takes: a kind it writes, a provider code, amounts in range, strings that are ids. An
// admission checks its row before it takes a hold, so a row the ledger would refuse holds nothing.
func ComputeOpCheck(settings *ComputeLedgerSettings, op *ComputeOp) error {
	if !op.Kind.Written() {
		return fmt.Errorf("%w: kind %s is not written", ErrComputeOpArgs, op.Kind)
	}
	if op.Provider < 0 {
		return fmt.Errorf("%w: a negative provider code", ErrComputeOpArgs)
	}
	if op.HoldNanoUsd < 0 || op.ReserveNanoUsd < 0 || computeLuaMaxExactInteger < op.HoldNanoUsd || computeLuaMaxExactInteger < op.ReserveNanoUsd {
		return fmt.Errorf("%w: a hold or reservation out of range", ErrComputeOpArgs)
	}
	if op.CatalogId != nil && !computeOpTokenValid(*op.CatalogId, settings.CatalogIdMaxByteCount) {
		return fmt.Errorf("%w: the catalog id is no id within %d bytes", ErrComputeOpArgs, settings.CatalogIdMaxByteCount)
	}
	if op.ProviderRef != nil && !computeOpTokenValid(*op.ProviderRef, settings.ProviderRefMaxByteCount) {
		return fmt.Errorf("%w: the provider reference is no id within %d bytes", ErrComputeOpArgs, settings.ProviderRefMaxByteCount)
	}
	if op.StartTime.IsZero() {
		return fmt.Errorf("%w: no start time", ErrComputeOpArgs)
	}
	return nil
}

// The statement that inserts a row, skipping one whose key stands.
const computeOpInsertSql = `
	INSERT INTO compute_op (op_key, network_id, shard, state, kind, subject_ref, attempt, sidecar_id, agent_id, member_id,
		enclave_id, catalog_id, catalog_version, provider, price_read, provider_ref, hold_nano_usd, reserve_nano_usd,
		start_time, outcome)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20::jsonb)
	ON CONFLICT (op_key) DO NOTHING
`

// The insert's args for op, its outcome as JSON or NULL.
func computeOpInsertArgs(settings *ComputeLedgerSettings, op *ComputeOp) ([]any, error) {
	var outcome *string
	if op.Outcome != nil {
		data, err := op.Outcome.Json()
		if err != nil {
			return nil, err
		}
		text := string(data)
		outcome = &text
	}
	return []any{
		op.OpKey, op.NetworkId, ComputeOpShard(settings, op.NetworkId), int16(op.State), int16(op.Kind), op.SubjectRef,
		op.Attempt, op.SidecarId, op.AgentId, op.MemberId, op.EnclaveId, op.CatalogId, op.CatalogVersion, op.Provider,
		op.PriceRead, op.ProviderRef, op.HoldNanoUsd, op.ReserveNanoUsd, op.StartTime.UTC(), outcome,
	}, nil
}

// Inserts op's row open (§9.7's handoff): what an admission commits before anything reaches a provider. A row of its
// key that already stands is left as it is: inserted is false and the row answered is that one, a derived key's
// first admission.
func ComputeOpInsertOpen(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, op *ComputeOp) (inserted bool, stands *ComputeOp, returnErr error) {
	if op.State != ComputeOpStateOpen || op.Outcome != nil {
		return false, nil, fmt.Errorf("%w: an admission's row is open, with no outcome", ErrComputeOpArgs)
	}
	if err := ComputeOpCheck(settings, op); err != nil {
		return false, nil, err
	}
	return computeOpInsert(env, ctx, settings, op)
}

// Inserts op's row already settled, with its outcome (§9.7): a host egress hour's, a refund's or an adjustment's. The
// key claims its subject once: a row of its key that stands is left as it is, inserted is false, and the row answered
// is the claim's.
func ComputeOpInsertSettled(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, op *ComputeOp) (inserted bool, stands *ComputeOp, returnErr error) {
	if op.State != ComputeOpStateSettled || op.Outcome == nil {
		return false, nil, fmt.Errorf("%w: a row written settled carries its outcome", ErrComputeOpArgs)
	}
	if err := ComputeOpCheck(settings, op); err != nil {
		return false, nil, err
	}
	return computeOpInsert(env, ctx, settings, op)
}

// The insert and, where the key stood, a read of the row that stands, in one transaction.
func computeOpInsert(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, op *ComputeOp) (bool, *ComputeOp, error) {
	db, err := env.Db()
	if err != nil {
		return false, nil, err
	}
	args, err := computeOpInsertArgs(settings, op)
	if err != nil {
		return false, nil, err
	}
	inserted := false
	var stands *ComputeOp
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		inserted = false
		stands = nil
		result, err := tx.Exec(ctx, computeOpInsertSql, args...)
		if err != nil {
			return err
		}
		if result.RowsAffected == 1 {
			inserted = true
			return nil
		}
		stands, err = computeOpQueryOne(ctx, tx, `SELECT `+computeOpColumns+` FROM compute_op WHERE op_key = $1`, op.OpKey)
		if errors.Is(err, ErrComputeOpNotFound) {
			// deleted between the two statements: ask for a rerun, which inserts it
			return operator.ErrDbRerun
		}
		return err
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return false, nil, err
	}
	if stands != nil && stands.NetworkId != op.NetworkId {
		// a key is unique across networks, so another network's row is no claim of this one's
		return false, nil, fmt.Errorf("%w: the key names another network's operation", ErrComputeOpArgs)
	}
	return inserted, stands, nil
}

// One row as it stands, in its network.
func ComputeOpGet(env operator.Env, ctx context.Context, networkId operator.Id, opKey operator.Id) (*ComputeOp, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var op *ComputeOp
	err = db.Db(ctx, func(conn operator.DbConn) error {
		var err error
		op, err = computeOpQueryOne(ctx, conn, `SELECT `+computeOpColumns+` FROM compute_op WHERE op_key = $1 AND network_id = $2`, opKey, networkId)
		return err
	})
	return op, err
}

// Whether a kind is held at its worst case and so never charged past its hold: every kind with a hold but a direct
// call's, which is charged up to its budget reservation (§9.7, BAL-M12-21).
func ComputeOpHeldAtWorstCase(kind ComputeChargeKind, direct bool) bool {
	return !direct && (kind == ComputeChargeKindInference || kind == ComputeChargeKindWebSearch || kind == ComputeChargeKindEnclaveRun)
}

// What a settlement's move did.
type ComputeOpSettleResult struct {
	// The row moved from open to settled now.
	Moved bool
	// The row as it stands after the call: settled with the outcome committed now, or as it stood (settled, applied
	// or void) where it did not move.
	Op *ComputeOp
}

// Moves opKey's row from open to settled with outcome (§9.7, step 4): the outcome is committed to the row before the
// hold becomes an unsettled charge. A kind held at its worst case (ComputeOpHeldAtWorstCase) is never charged past its
// hold: an amount above it is cut to it and the rest kept as absorbed, URnetwork's. A row not open is left as it is
// and answered; no row answers ErrComputeOpNotFound, and nothing is booked for it.
func ComputeOpSettle(env operator.Env, ctx context.Context, networkId operator.Id, opKey operator.Id, direct bool, outcome *ComputeOpOutcome) (*ComputeOpSettleResult, error) {
	if !outcome.Units.Valid() || outcome.AmountNanoUsd < 0 || outcome.CostNanoUsd < 0 || outcome.AbsorbedNanoUsd < 0 {
		return nil, fmt.Errorf("%w: a settlement's outcome is a charge, never a negative amount", ErrComputeOpArgs)
	}
	if computeLuaMaxExactInteger < outcome.AmountNanoUsd {
		return nil, fmt.Errorf("%w: the charge is out of range", ErrComputeOpArgs)
	}
	if outcome.EndTime.IsZero() || outcome.SettleTime.IsZero() {
		return nil, fmt.Errorf("%w: a settlement's outcome carries its end and settle times", ErrComputeOpArgs)
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	result := &ComputeOpSettleResult{}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*result = ComputeOpSettleResult{}
		op, err := computeOpQueryOne(ctx, tx, `SELECT `+computeOpColumns+` FROM compute_op WHERE op_key = $1 AND network_id = $2 FOR UPDATE`, opKey, networkId)
		if err != nil {
			return err
		}
		result.Op = op
		if op.State != ComputeOpStateOpen {
			return nil
		}
		committed := *outcome
		committed.EndTime = committed.EndTime.UTC()
		committed.SettleTime = committed.SettleTime.UTC()
		if ComputeOpHeldAtWorstCase(op.Kind, direct) && op.HoldNanoUsd < committed.AmountNanoUsd {
			committed.AbsorbedNanoUsd += committed.AmountNanoUsd - op.HoldNanoUsd
			committed.AmountNanoUsd = op.HoldNanoUsd
		}
		data, err := committed.Json()
		if err != nil {
			return err
		}
		update, err := tx.Exec(ctx, `
			UPDATE compute_op SET state = $3, outcome = $4::jsonb, provider_ref = NULL
			WHERE op_key = $1 AND network_id = $2 AND state = $5
		`, opKey, networkId, int16(ComputeOpStateSettled), string(data), int16(ComputeOpStateOpen))
		if err != nil {
			return err
		}
		if update.RowsAffected != 1 {
			return fmt.Errorf("compute op: the row locked for its settlement did not move")
		}
		settled := *op
		settled.State = ComputeOpStateSettled
		settled.ProviderRef = nil
		settled.Outcome = &committed
		result.Moved = true
		result.Op = &settled
		return nil
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// What a release's move did.
type ComputeOpVoidResult struct {
	// The row moved from open to void now.
	Moved bool
	// The row as it stands after the call.
	Op *ComputeOp
}

// Moves opKey's row from open to void, released at no charge (§9.7). A row not open is left as it is and answered, so
// a release after a settlement changes nothing; no row answers ErrComputeOpNotFound.
func ComputeOpVoid(env operator.Env, ctx context.Context, networkId operator.Id, opKey operator.Id) (*ComputeOpVoidResult, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	result := &ComputeOpVoidResult{}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*result = ComputeOpVoidResult{}
		ops, err := computeOpQuery(ctx, tx, `
			UPDATE compute_op SET state = $3, provider_ref = NULL
			WHERE op_key = $1 AND network_id = $2 AND state = $4
			RETURNING `+computeOpColumns,
			opKey, networkId, int16(ComputeOpStateVoid), int16(ComputeOpStateOpen))
		if err != nil {
			return err
		}
		if len(ops) == 1 {
			result.Moved = true
			result.Op = ops[0]
			return nil
		}
		result.Op, err = computeOpQueryOne(ctx, tx, `SELECT `+computeOpColumns+` FROM compute_op WHERE op_key = $1 AND network_id = $2`, opKey, networkId)
		return err
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Every network's rows open since before before, oldest first, at most limit: what compute_op_recover works through.
func ComputeOpListOpen(env operator.Env, ctx context.Context, before time.Time, limit int) ([]*ComputeOp, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: a positive limit", ErrComputeOpArgs)
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var ops []*ComputeOp
	err = db.Db(ctx, func(conn operator.DbConn) error {
		var err error
		ops, err = computeOpQuery(ctx, conn, `
			SELECT `+computeOpColumns+` FROM compute_op
			WHERE state = $1 AND start_time < $2
			ORDER BY start_time, op_key
			LIMIT $3
		`, int16(ComputeOpStateOpen), before.UTC(), limit)
		return err
	})
	return ops, err
}

// The ids a row names, for its budgets' counters and a script's keys: its sidecar, agent, member, enclave and network.
func (self *ComputeOp) SubjectIds() []operator.Id {
	subjectIds := []operator.Id{self.SidecarId, self.NetworkId}
	for _, id := range []*operator.Id{self.AgentId, self.MemberId, self.EnclaveId} {
		if id != nil {
			subjectIds = append(subjectIds, *id)
		}
	}
	return subjectIds
}
