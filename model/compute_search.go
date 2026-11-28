// Web search's rows in the broker's database (DESIGN-COMPUTE §14.4, §21.5, §21.8, §21.10, compute-10, compute-11;
// SRCH-M13-08): SRCH's part of MG-C2, registered here at init as CONTRACTS C-30 has every owner's part registered from
// this package, and the reads and writes computeservice's admission, report loop and jobs make on them, beside the two
// reads they make of BAL's operation rows.
//
//	compute_search_flag          the sanctions records (§21.5): a payee the signer's screen refused, which suspends
//	                             the network's search until reviewed, or an authorization settled by a sender outside
//	                             the facilitator's addresses, which flags the network for review. Each keeps the
//	                             network, sidecar, reason, payee, transaction and time, and, once an operator reviewed
//	                             it, the review's time and reference (`sidecarctl compute resume <network> --search
//	                             --review <reference>`, QD-1374, CARCH's command). One open record a network, reason,
//	                             payee and transaction, so a refusal repeated before review keeps the first; kept for
//	                             OFAC's recordkeeping period, which counsel confirms (ComputeSearchSettings'
//	                             FlagRetention), and never deleted while open
//	compute_search_outcome_hour  each hour's search outcome counts by class across all networks (§21.8, compute-11),
//	                             which compute_search_outcomes moves from {cmpo} (SRCH-M13-09); 400 days
//
// No row here holds a ticket, a nonce, a query, a mode or a result, and an outcome hour names no network (compute-11).
// The sanctions records are the one exception §21.5 makes to keeping no payee with a network, and join no search: a
// refused payee was never paid, and an authorization settled outside the gateway bought none.
//
// Every step is additive, and the group's steps change no more once its Gn-out registers it (§19.7). Each function
// takes the Env first (owner decision 594).

package model

import (
	"context"
	"errors"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// SRCH's part of MG-C2, registered once at init after GAMMA's, before server builds its migrations slice.
func init() {
	RegisterComputeMigrationPart(ComputeMigrationGroupC2, ComputeMigrationOwnerSrch, ComputeSearchMigrations())
}

// MG-C2's search part, in order (CONTRACTS C-30).
func ComputeSearchMigrations() []*operator.Migration {
	return []*operator.Migration{
		{
			Id: "compute_search_flag",
			Sql: `
				CREATE TABLE compute_search_flag (
					flag_id uuid NOT NULL,
					network_id uuid NOT NULL,
					sidecar_id uuid NOT NULL,
					reason smallint NOT NULL,
					payee bytea NOT NULL,
					transaction bytea,
					flag_time timestamptz NOT NULL,
					reviewed_time timestamptz,
					review_reference text,
					PRIMARY KEY (flag_id),
					CHECK (reason IN (1, 2)),
					CHECK (octet_length(payee) = 20),
					CHECK ((reason = 1 AND transaction IS NULL) OR (reason = 2 AND transaction IS NOT NULL AND octet_length(transaction) = 32)),
					CHECK ((reviewed_time IS NULL) = (review_reference IS NULL))
				)
			`,
		},
		{
			// one open record a network, reason, payee and transaction; a reviewed one leaves room for the next
			Id: "compute_search_flag_open",
			Sql: `
				CREATE UNIQUE INDEX compute_search_flag_open ON compute_search_flag (network_id, reason, payee, transaction)
				NULLS NOT DISTINCT WHERE reviewed_time IS NULL
			`,
		},
		{
			// the retention's sweep
			Id: "compute_search_flag_time",
			Sql: `
				CREATE INDEX compute_search_flag_time ON compute_search_flag (flag_time)
			`,
		},
		{
			Id: "compute_search_outcome_hour",
			Sql: `
				CREATE TABLE compute_search_outcome_hour (
					hour_time timestamptz NOT NULL,
					outcome smallint NOT NULL,
					count bigint NOT NULL,
					PRIMARY KEY (hour_time, outcome),
					CHECK (outcome IN (1, 2, 3, 4)),
					CHECK (0 <= count)
				)
			`,
		},
	}
}

// Why a sanctions record was kept, as compute_search_flag.reason holds it. Identifiers.
type ComputeSearchFlagReason int16

const (
	// The signer's screen refused the payee (§21.5): never paid, and the network's search suspended until reviewed.
	ComputeSearchFlagReasonPayeeRefused ComputeSearchFlagReason = 1
	// An authorization settled by a sender outside the facilitator's settlement addresses (§21.5): charged, and the
	// network flagged for review (§21.10).
	ComputeSearchFlagReasonOutOfBand ComputeSearchFlagReason = 2
)

// The reason's word, as §21.5 names it.
func (self ComputeSearchFlagReason) String() string {
	switch self {
	case ComputeSearchFlagReasonPayeeRefused:
		return "payee_refused"
	case ComputeSearchFlagReasonOutOfBand:
		return "out_of_band"
	}
	return fmt.Sprintf("reason%d", int16(self))
}

// A search outcome's class (§21.8), as compute_search_outcome_hour.outcome holds it: SearchOutcomes' field numbers.
// Identifiers.
type ComputeSearchOutcome int16

const (
	ComputeSearchOutcomeOk            ComputeSearchOutcome = 1
	ComputeSearchOutcomeProviderError ComputeSearchOutcome = 2
	ComputeSearchOutcomeTimeout       ComputeSearchOutcome = 3
	ComputeSearchOutcomeRefused       ComputeSearchOutcome = 4
)

// Every class, in field order.
var ComputeSearchOutcomes = []ComputeSearchOutcome{
	ComputeSearchOutcomeOk, ComputeSearchOutcomeProviderError, ComputeSearchOutcomeTimeout, ComputeSearchOutcomeRefused,
}

// The class's word, as §21.8 and the metrics name it.
func (self ComputeSearchOutcome) String() string {
	switch self {
	case ComputeSearchOutcomeOk:
		return "ok"
	case ComputeSearchOutcomeProviderError:
		return "provider_error"
	case ComputeSearchOutcomeTimeout:
		return "timeout"
	case ComputeSearchOutcomeRefused:
		return "refused"
	}
	return fmt.Sprintf("outcome%d", int16(self))
}

// A search row change the store does not take.
var ErrComputeSearchArgs = errors.New("compute search: arguments refused")

// One sanctions record.
type ComputeSearchFlag struct {
	FlagId    operator.Id
	NetworkId operator.Id
	SidecarId operator.Id
	Reason    ComputeSearchFlagReason
	// The payee, 20 bytes.
	Payee []byte
	// An out-of-band settlement's transaction, 32 bytes; nil for a refused payee.
	Transaction []byte
	FlagTime    time.Time
	// Once reviewed: when and the operator's reference.
	ReviewedTime    *time.Time
	ReviewReference *string
}

// Whether the record stands unreviewed.
func (self *ComputeSearchFlag) Open() bool {
	return self.ReviewedTime == nil
}

// Checks a record before it is written.
func computeSearchFlagCheck(flag *ComputeSearchFlag) error {
	var zero operator.Id
	switch {
	case flag.FlagId == zero || flag.NetworkId == zero || flag.SidecarId == zero || flag.FlagTime.IsZero():
		return fmt.Errorf("%w: a record names its id, network, sidecar and time", ErrComputeSearchArgs)
	case len(flag.Payee) != 20:
		return fmt.Errorf("%w: a payee is 20 bytes", ErrComputeSearchArgs)
	case flag.Reason == ComputeSearchFlagReasonPayeeRefused && flag.Transaction != nil:
		return fmt.Errorf("%w: a refused payee was never paid, so it names no transaction", ErrComputeSearchArgs)
	case flag.Reason == ComputeSearchFlagReasonOutOfBand && len(flag.Transaction) != 32:
		return fmt.Errorf("%w: an out-of-band settlement names its 32-byte transaction", ErrComputeSearchArgs)
	case flag.Reason != ComputeSearchFlagReasonPayeeRefused && flag.Reason != ComputeSearchFlagReasonOutOfBand:
		return fmt.Errorf("%w: no reason %d", ErrComputeSearchArgs, int16(flag.Reason))
	case flag.ReviewedTime != nil || flag.ReviewReference != nil:
		return fmt.Errorf("%w: a record is written open", ErrComputeSearchArgs)
	}
	return nil
}

// Keeps flag, open: whether this call wrote it. An open record of the same network, reason, payee and transaction
// already standing keeps its first time and sidecar, and this one writes nothing.
func ComputeSearchFlagInsert(env operator.Env, ctx context.Context, flag *ComputeSearchFlag) (bool, error) {
	if err := computeSearchFlagCheck(flag); err != nil {
		return false, err
	}
	db, err := env.Db()
	if err != nil {
		return false, err
	}
	inserted := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		result, err := tx.Exec(ctx, `
			INSERT INTO compute_search_flag (flag_id, network_id, sidecar_id, reason, payee, transaction, flag_time)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (network_id, reason, payee, transaction) WHERE reviewed_time IS NULL DO NOTHING
		`, flag.FlagId, flag.NetworkId, flag.SidecarId, int16(flag.Reason), flag.Payee, flag.Transaction, flag.FlagTime.UTC())
		if err != nil {
			return err
		}
		inserted = result.RowsAffected == 1
		return nil
	})
	return inserted, err
}

// Whether networkId's search is suspended for review: an open record of a refused payee stands (§21.5).
func ComputeSearchSuspended(env operator.Env, ctx context.Context, networkId operator.Id) (bool, error) {
	db, err := env.Db()
	if err != nil {
		return false, err
	}
	suspended := false
	err = db.Db(ctx, func(conn operator.DbConn) error {
		rows, err := conn.Query(ctx, `
			SELECT 1 FROM compute_search_flag
			WHERE network_id = $1 AND reason = $2 AND reviewed_time IS NULL
			LIMIT 1
		`, networkId, int16(ComputeSearchFlagReasonPayeeRefused))
		if err != nil {
			return err
		}
		defer rows.Close()
		suspended = rows.Next()
		return rows.Err()
	})
	return suspended, err
}

// Whether reference is one a review may keep: printable ASCII, from 1 to maxByteCount bytes, an operator's ticket or
// case reference and never content.
func computeSearchReviewReferenceValid(reference string, maxByteCount int) bool {
	if reference == "" || maxByteCount < len(reference) {
		return false
	}
	for i := 0; i < len(reference); i += 1 {
		if reference[i] < 0x20 || 0x7e < reference[i] {
			return false
		}
	}
	return true
}

// Reviews networkId's open records at now under reference, the operator's act that ends its search's suspension
// (QD-1374): how many it closed. A reference that is empty, past maxByteCount (ComputeSearchSettings'
// ReviewReferenceMaxByteCount) or not printable ASCII refuses.
func ComputeSearchFlagReview(env operator.Env, ctx context.Context, networkId operator.Id, reference string, maxByteCount int, now time.Time) (int64, error) {
	if networkId == (operator.Id{}) || !computeSearchReviewReferenceValid(reference, maxByteCount) {
		return 0, fmt.Errorf("%w: a review names its network and a printable reference of at most %d bytes", ErrComputeSearchArgs, maxByteCount)
	}
	db, err := env.Db()
	if err != nil {
		return 0, err
	}
	var reviewedCount int64
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		result, err := tx.Exec(ctx, `
			UPDATE compute_search_flag SET reviewed_time = $2, review_reference = $3
			WHERE network_id = $1 AND reviewed_time IS NULL
		`, networkId, now.UTC(), reference)
		if err != nil {
			return err
		}
		reviewedCount = result.RowsAffected
		return nil
	})
	return reviewedCount, err
}

// networkId's records, oldest first: what an operator reads at review and a legal demand produces (§21.10).
func ComputeSearchFlagsOf(env operator.Env, ctx context.Context, networkId operator.Id) ([]*ComputeSearchFlag, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	flags := []*ComputeSearchFlag{}
	err = db.Db(ctx, func(conn operator.DbConn) error {
		flags = []*ComputeSearchFlag{}
		rows, err := conn.Query(ctx, `
			SELECT flag_id, network_id, sidecar_id, reason, payee, transaction, flag_time, reviewed_time, review_reference
			FROM compute_search_flag WHERE network_id = $1
			ORDER BY flag_time, flag_id
		`, networkId)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			flag := &ComputeSearchFlag{}
			var reason int16
			if err := rows.Scan(&flag.FlagId, &flag.NetworkId, &flag.SidecarId, &reason, &flag.Payee, &flag.Transaction,
				&flag.FlagTime, &flag.ReviewedTime, &flag.ReviewReference); err != nil {
				return err
			}
			flag.Reason = ComputeSearchFlagReason(reason)
			flag.FlagTime = flag.FlagTime.UTC()
			if flag.ReviewedTime != nil {
				reviewedTime := flag.ReviewedTime.UTC()
				flag.ReviewedTime = &reviewedTime
			}
			flags = append(flags, flag)
		}
		return rows.Err()
	})
	return flags, err
}

// Deletes at most limit reviewed records kept from before before: the recordkeeping period's end. An open record is
// kept whatever its age. How many went.
func ComputeSearchFlagPrune(env operator.Env, ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("%w: a positive limit", ErrComputeSearchArgs)
	}
	db, err := env.Db()
	if err != nil {
		return 0, err
	}
	var deletedCount int64
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		result, err := tx.Exec(ctx, `
			DELETE FROM compute_search_flag WHERE flag_id IN (
				SELECT flag_id FROM compute_search_flag
				WHERE flag_time < $1 AND reviewed_time IS NOT NULL
				ORDER BY flag_time
				LIMIT $2
			)
		`, before.UTC(), limit)
		if err != nil {
			return err
		}
		deletedCount = result.RowsAffected
		return nil
	})
	return deletedCount, err
}

// Adds counts to hour's row of each class, across all networks (compute-11): what compute_search_outcomes writes as it
// moves an hour out of {cmpo}. A count of zero writes nothing.
func ComputeSearchOutcomeHourAdd(env operator.Env, ctx context.Context, hour time.Time, counts map[ComputeSearchOutcome]int64) error {
	for outcome, count := range counts {
		if count < 0 || outcome < ComputeSearchOutcomeOk || ComputeSearchOutcomeRefused < outcome {
			return fmt.Errorf("%w: a count of a class §21.8 names, zero or more", ErrComputeSearchArgs)
		}
	}
	db, err := env.Db()
	if err != nil {
		return err
	}
	return db.Tx(ctx, func(tx operator.DbTx) error {
		for _, outcome := range ComputeSearchOutcomes {
			count := counts[outcome]
			if count == 0 {
				continue
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO compute_search_outcome_hour (hour_time, outcome, count) VALUES ($1, $2, $3)
				ON CONFLICT (hour_time, outcome) DO UPDATE SET count = compute_search_outcome_hour.count + EXCLUDED.count
			`, hour.UTC(), int16(outcome), count); err != nil {
				return err
			}
		}
		return nil
	})
}

// hour's counts by class, a class with no row reading zero.
func ComputeSearchOutcomeHourOf(env operator.Env, ctx context.Context, hour time.Time) (map[ComputeSearchOutcome]int64, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	counts := map[ComputeSearchOutcome]int64{}
	err = db.Db(ctx, func(conn operator.DbConn) error {
		counts = map[ComputeSearchOutcome]int64{}
		rows, err := conn.Query(ctx, `SELECT outcome, count FROM compute_search_outcome_hour WHERE hour_time = $1`, hour.UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var outcome int16
			var count int64
			if err := rows.Scan(&outcome, &count); err != nil {
				return err
			}
			counts[ComputeSearchOutcome(outcome)] = count
		}
		return rows.Err()
	})
	return counts, err
}

// Deletes at most limit hourly rows from before before: their 400 days' end. How many went.
func ComputeSearchOutcomeHourPrune(env operator.Env, ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("%w: a positive limit", ErrComputeSearchArgs)
	}
	db, err := env.Db()
	if err != nil {
		return 0, err
	}
	var deletedCount int64
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		result, err := tx.Exec(ctx, `
			DELETE FROM compute_search_outcome_hour WHERE (hour_time, outcome) IN (
				SELECT hour_time, outcome FROM compute_search_outcome_hour
				WHERE hour_time < $1
				ORDER BY hour_time, outcome
				LIMIT $2
			)
		`, before.UTC(), limit)
		if err != nil {
			return err
		}
		deletedCount = result.RowsAffected
		return nil
	})
	return deletedCount, err
}

// Up to limit open web search operation rows started before before, oldest first: what compute_search_tickets
// releases, an admission no report reached an hour past its window (§14.5).
func ComputeSearchOpListOpen(env operator.Env, ctx context.Context, before time.Time, limit int) ([]*ComputeOp, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: a positive limit", ErrComputeSearchArgs)
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
			WHERE state = $1 AND kind = $2 AND start_time < $3
			ORDER BY start_time, op_key
			LIMIT $4
		`, int16(ComputeOpStateOpen), int16(ComputeChargeKindWebSearch), before.UTC(), limit)
		return err
	})
	return ops, err
}

// How many of networkId's web search operations started at or after since and were not released at no charge: what
// rebuilds {cmpr_<network_id>}'s searches today after its key was lost (§9.7's lost cache). A search's row is kept to
// its purge, booked or not, so a day's rows are all there.
func ComputeSearchOpCountSince(env operator.Env, ctx context.Context, networkId operator.Id, since time.Time) (int64, error) {
	db, err := env.Db()
	if err != nil {
		return 0, err
	}
	var count int64
	err = db.Db(ctx, func(conn operator.DbConn) error {
		rows, err := conn.Query(ctx, `
			SELECT count(*) FROM compute_op
			WHERE network_id = $1 AND kind = $2 AND state <> $3 AND start_time >= $4
		`, networkId, int16(ComputeChargeKindWebSearch), int16(ComputeOpStateVoid), since.UTC())
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&count); err != nil {
				return err
			}
		}
		return rows.Err()
	})
	return count, err
}
