// An operator's suspension of a network's compute (DESIGN-COMPUTE §17.2, D-CABUSE-1, D-CABUSE-2; CARCH-M12-01): the
// abuse hold every broker admission reads, remote calls, searches and enclave creates and starts, answering
// `suspended`. Mining, scanning and spam are prohibited by the compute terms with suspension of the network's compute
// (D-CABUSE-2); a provider's complaint, card fraud and a takedown (§17.3) take the same act. It acts on the account,
// never on content (D-CABUSE-1): a held network keeps its balance, its lots and its records, and no ledger row moves.
// "Hold" here is never the ledger's worst-case hold on a balance (§9.7), nor DESIGN §21.9's preservation hold.
//
//	compute_abuse_hold     one row a network once it was ever held: the reason class, who placed the hold and when,
//	                       who resumed it and when (null while it stands), and a version raised by each change, which
//	                       the projection carries; kept for the network's life, as its account
//	{cmp_<network_id>}:a   the projection every broker instance reads, "<version>:<reason>", reason 0 for no hold,
//	                       beside the network's ledger keys in its slot: written after each commit and filled from
//	                       Postgres on a miss, a lower version never replacing a higher; it expires after
//	                       ComputeAbuseHoldSettings.ProjectionMaxAge, which bounds what a projection write that failed
//	                       after its commit can leave standing
//
// The hold is not §9.9's state: compute_account exists only once a network is credited, and compute_suspend rewrites
// its state from the balance each minute, so a top-up would lift a hold kept there, and its move back to active would
// ask ENC to restart what the suspension stopped, where a resume restarts nothing on its own.
//
// No row of §2.8's list names the table or the key yet: question carch-m12-01-compute-hold-row asks compute-3's words
// for them (I-18), and the list, server's column map and both guards take them only with the owner's answer. Until
// then CARCH's part of MG-C1, ComputeAbuseHoldMigrations, is not registered and no database holds the table, so every
// read of it fails: every broker admission refuses, unavailable, and every staff act answers 503. Failing closed is
// the hold's own rule, an admission that cannot read the hold refusing; and no admission route has a handler before
// M12b's. The change that carries the answer registers the part at init, beside its lines in metadata_list.yml and
// server's local/sidecar-columns.yml.
//
// The staff ids are the opaque reviewer ids of api's abuse-staff.yml, as §21.10's rows keep theirs (I-13). Every
// statement runs in the caller's transaction or on one connection; the projection is written only after the
// transaction returns, since a Tx callback may run twice and publishes nothing outside the database.

package model

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// MG-C1's hold part, in order: what CSRV's group registration takes after BAL's ledger (CONTRACTS C-30), once the
// owner's answer to question carch-m12-01-compute-hold-row lets it register (see the file header): until then this
// package registers nothing for CARCH, and server's slot for the part reads it empty.
func ComputeAbuseHoldMigrations() []*operator.Migration {
	return []*operator.Migration{
		{
			Id: "compute_abuse_hold",
			Sql: `
				CREATE TABLE compute_abuse_hold (
					network_id uuid NOT NULL,
					reason smallint NOT NULL,
					hold_staff_id uuid NOT NULL,
					hold_time timestamptz NOT NULL,
					resume_staff_id uuid,
					resume_time timestamptz,
					version bigint NOT NULL,
					PRIMARY KEY (network_id)
				)
			`,
		},
	}
}

// Why an operator suspended a network's compute, as compute_abuse_hold.reason holds it: the classes §17.2's controls
// act on, a closed set an operator names with --reason. Identifiers.
type ComputeAbuseHoldReason int16

const (
	// No hold: a projection's word for a network none holds. Never a row's reason.
	ComputeAbuseHoldReasonNone ComputeAbuseHoldReason = 0
	// Mining in an enclave, which the compute terms prohibit (D-CABUSE-2).
	ComputeAbuseHoldReasonMining ComputeAbuseHoldReason = 1
	// Scanning or attacks from an enclave (D-CABUSE-2).
	ComputeAbuseHoldReasonScanning ComputeAbuseHoldReason = 2
	// Spam from an enclave (D-CABUSE-2).
	ComputeAbuseHoldReasonSpam ComputeAbuseHoldReason = 3
	// Stolen cards buying compute, or cashing it out through searches (§17.2's first row, §9.11).
	ComputeAbuseHoldReasonFraud ComputeAbuseHoldReason = 4
	// A provider's complaint about the network's use, which could suspend URnetwork's account there (E6, §4.3).
	ComputeAbuseHoldReasonProviderComplaint ComputeAbuseHoldReason = 5
	// Reports of harmful content from inference, acting on the account (DESIGN §21.8).
	ComputeAbuseHoldReasonHarmfulContent ComputeAbuseHoldReason = 6
	// Another breach of the compute terms, the web search clause's among them (§21.11).
	ComputeAbuseHoldReasonTerms ComputeAbuseHoldReason = 7
	// A takedown under legal process (§17.3).
	ComputeAbuseHoldReasonTakedown ComputeAbuseHoldReason = 8
)

// Every reason a row may hold, in code order.
var computeAbuseHoldReasons = []ComputeAbuseHoldReason{
	ComputeAbuseHoldReasonMining,
	ComputeAbuseHoldReasonScanning,
	ComputeAbuseHoldReasonSpam,
	ComputeAbuseHoldReasonFraud,
	ComputeAbuseHoldReasonProviderComplaint,
	ComputeAbuseHoldReasonHarmfulContent,
	ComputeAbuseHoldReasonTerms,
	ComputeAbuseHoldReasonTakedown,
}

// The reason's word, the one --reason and the staff route take, or reason<n> for a number the build does not name.
func (self ComputeAbuseHoldReason) String() string {
	switch self {
	case ComputeAbuseHoldReasonNone:
		return "none"
	case ComputeAbuseHoldReasonMining:
		return "mining"
	case ComputeAbuseHoldReasonScanning:
		return "scanning"
	case ComputeAbuseHoldReasonSpam:
		return "spam"
	case ComputeAbuseHoldReasonFraud:
		return "fraud"
	case ComputeAbuseHoldReasonProviderComplaint:
		return "provider_complaint"
	case ComputeAbuseHoldReasonHarmfulContent:
		return "harmful_content"
	case ComputeAbuseHoldReasonTerms:
		return "terms"
	case ComputeAbuseHoldReasonTakedown:
		return "takedown"
	}
	return "reason" + strconv.Itoa(int(self))
}

// Whether a row may hold the reason: one the build names, never none.
func (self ComputeAbuseHoldReason) Valid() bool {
	return ComputeAbuseHoldReasonMining <= self && self <= ComputeAbuseHoldReasonTakedown
}

// The words a row's reason may take, in code order.
func ComputeAbuseHoldReasonWords() []string {
	words := []string{}
	for _, reason := range computeAbuseHoldReasons {
		words = append(words, reason.String())
	}
	return words
}

// The reason a word names, refusing none and every word the build does not know.
func ParseComputeAbuseHoldReason(word string) (ComputeAbuseHoldReason, error) {
	for _, reason := range computeAbuseHoldReasons {
		if reason.String() == word {
			return reason, nil
		}
	}
	return 0, fmt.Errorf("%w: %q is no hold reason", ErrComputeAbuseHoldArgs, word)
}

// A hold change the store does not take: a reason that is no row's, a zero network or staff id.
var ErrComputeAbuseHoldArgs = errors.New("compute abuse hold: arguments refused")

// A projection value this package does not write: the Redis it reached holds another build's, or a broken one.
var ErrComputeAbuseHoldProjection = errors.New("compute abuse hold: a projection that does not read")

// The hold's tunables (QD-702), which the broker's settings and the staff route's writer both carry, so the
// projection's life stays in one place.
type ComputeAbuseHoldSettings struct {
	// How long the projection of a network's hold stands in Redis before an admission reads Postgres again: 30 s. It
	// bounds how long a projection write that failed after its commit leaves a stale answer standing, a resume's or a
	// hold's, and how often a network's row is read across every broker instance, once a network a period. Non-positive
	// keeps no projection: writers write none, and every admission reads Postgres.
	ProjectionMaxAge time.Duration
	// How many times one projection write tries again against a concurrent one before it gives up: 3. A write that
	// gives up leaves the newer version a concurrent writer put, or an expiry, to stand. Non-positive tries once.
	ProjectionAttemptCount int
}

// The defaults, each with its field's reason.
func DefaultComputeAbuseHoldSettings() *ComputeAbuseHoldSettings {
	return &ComputeAbuseHoldSettings{
		ProjectionMaxAge:       30 * time.Second,
		ProjectionAttemptCount: 3,
	}
}

// One network's row.
type ComputeAbuseHold struct {
	NetworkId operator.Id
	// The class it was placed for, or last changed to.
	Reason ComputeAbuseHoldReason
	// The staff member who placed it, or last changed its reason, and when it was placed.
	HoldStaffId operator.Id
	HoldTime    time.Time
	// The staff member who resumed it and when: nil while it stands.
	ResumeStaffId *operator.Id
	ResumeTime    *time.Time
	// Raised by each change, from 1.
	Version int64
}

// Whether the hold stands.
func (self *ComputeAbuseHold) Held() bool {
	return self != nil && self.ResumeTime == nil
}

// What the broker reads of a network's hold: its version and, while it stands, its reason. A network no row names
// reads version 0 and no reason.
type ComputeAbuseHoldState struct {
	Version int64
	Reason  ComputeAbuseHoldReason
}

// Whether the state holds the network.
func (self *ComputeAbuseHoldState) Held() bool {
	return self.Reason != ComputeAbuseHoldReasonNone
}

// The state of hold: for nil, a network no row names, version 0 and no reason.
func ComputeAbuseHoldStateOf(hold *ComputeAbuseHold) *ComputeAbuseHoldState {
	if hold == nil {
		return &ComputeAbuseHoldState{}
	}
	state := &ComputeAbuseHoldState{Version: hold.Version}
	if hold.Held() {
		state.Reason = hold.Reason
	}
	return state
}

const computeAbuseHoldColumns = `network_id, reason, hold_staff_id, hold_time, resume_staff_id, resume_time, version`

func computeAbuseHoldQuery(ctx context.Context, querier operator.DbQuerier, sql string, args ...any) ([]*ComputeAbuseHold, error) {
	rows, err := querier.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	holds := []*ComputeAbuseHold{}
	for rows.Next() {
		hold := &ComputeAbuseHold{}
		var reason int16
		if err := rows.Scan(&hold.NetworkId, &reason, &hold.HoldStaffId, &hold.HoldTime, &hold.ResumeStaffId, &hold.ResumeTime, &hold.Version); err != nil {
			return nil, err
		}
		hold.Reason = ComputeAbuseHoldReason(reason)
		hold.HoldTime = hold.HoldTime.UTC()
		if hold.ResumeTime != nil {
			resumeTime := hold.ResumeTime.UTC()
			hold.ResumeTime = &resumeTime
		}
		holds = append(holds, hold)
	}
	return holds, rows.Err()
}

// networkId's row, nil for a network never held.
func ComputeAbuseHoldGet(env operator.Env, ctx context.Context, networkId operator.Id) (*ComputeAbuseHold, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var hold *ComputeAbuseHold
	err = db.Db(ctx, func(conn operator.DbConn) error {
		hold = nil
		holds, err := computeAbuseHoldQuery(ctx, conn, `SELECT `+computeAbuseHoldColumns+` FROM compute_abuse_hold WHERE network_id = $1`, networkId)
		if err != nil || len(holds) == 0 {
			return err
		}
		hold = holds[0]
		return nil
	})
	return hold, err
}

// networkId's row in tx, locked, nil for a network never held.
func ComputeAbuseHoldInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id) (*ComputeAbuseHold, error) {
	holds, err := computeAbuseHoldQuery(ctx, tx, `SELECT `+computeAbuseHoldColumns+` FROM compute_abuse_hold WHERE network_id = $1 FOR UPDATE`, networkId)
	if err != nil || len(holds) == 0 {
		return nil, err
	}
	return holds[0], nil
}

// Holds networkId's compute for reason in tx, by staffId at now, answering the row as it stands after and whether this
// changed it: a network not held takes the hold (its hold_time now), one held for another reason takes this reason
// and staffId (its hold_time kept), and one held for this reason already is left as it is, so a retry changes nothing.
func ComputeAbuseHoldSuspendInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, reason ComputeAbuseHoldReason, staffId operator.Id, now time.Time) (*ComputeAbuseHold, bool, error) {
	if networkId == (operator.Id{}) || staffId == (operator.Id{}) || !reason.Valid() {
		return nil, false, fmt.Errorf("%w: a network, a staff member and a reason the build names", ErrComputeAbuseHoldArgs)
	}
	before, err := ComputeAbuseHoldInTx(env, ctx, tx, networkId)
	if err != nil {
		return nil, false, err
	}
	switch {
	case before == nil:
		holds, err := computeAbuseHoldQuery(ctx, tx, `
			INSERT INTO compute_abuse_hold (network_id, reason, hold_staff_id, hold_time, version)
			VALUES ($1, $2, $3, $4, 1)
			RETURNING `+computeAbuseHoldColumns,
			networkId, int16(reason), staffId, now.UTC())
		if err != nil {
			return nil, false, err
		}
		if len(holds) != 1 {
			return nil, false, errors.New("compute abuse hold: the insert answered no row")
		}
		return holds[0], true, nil
	case before.Held() && before.Reason == reason:
		return before, false, nil
	}
	holdTime := before.HoldTime
	if !before.Held() {
		holdTime = now.UTC()
	}
	holds, err := computeAbuseHoldQuery(ctx, tx, `
		UPDATE compute_abuse_hold SET
			reason = $2,
			hold_staff_id = $3,
			hold_time = $4,
			resume_staff_id = NULL,
			resume_time = NULL,
			version = version + 1
		WHERE network_id = $1
		RETURNING `+computeAbuseHoldColumns,
		networkId, int16(reason), staffId, holdTime)
	if err != nil {
		return nil, false, err
	}
	if len(holds) != 1 {
		return nil, false, errors.New("compute abuse hold: the update answered no row")
	}
	return holds[0], true, nil
}

// Resumes networkId's compute in tx, by staffId at now, answering the row as it stands after, nil for a network never
// held, and whether this changed it: a hold that stands ends, and one already resumed, or none, is left as it is.
// Nothing restarts: an enclave the hold stopped waits for its keeper or sponsor to start it (§17.2's trap).
func ComputeAbuseHoldResumeInTx(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, staffId operator.Id, now time.Time) (*ComputeAbuseHold, bool, error) {
	if networkId == (operator.Id{}) || staffId == (operator.Id{}) {
		return nil, false, fmt.Errorf("%w: a network and a staff member", ErrComputeAbuseHoldArgs)
	}
	before, err := ComputeAbuseHoldInTx(env, ctx, tx, networkId)
	if err != nil || before == nil || !before.Held() {
		return before, false, err
	}
	holds, err := computeAbuseHoldQuery(ctx, tx, `
		UPDATE compute_abuse_hold SET resume_staff_id = $2, resume_time = $3, version = version + 1
		WHERE network_id = $1
		RETURNING `+computeAbuseHoldColumns,
		networkId, staffId, now.UTC())
	if err != nil {
		return nil, false, err
	}
	if len(holds) != 1 {
		return nil, false, errors.New("compute abuse hold: the update answered no row")
	}
	return holds[0], true, nil
}

// The network's hold projection, beside its ledger keys in its slot: {cmp_<network_id>}:a.
func ComputeAbuseHoldRedisKey(networkId operator.Id) string {
	return ComputeProjectionKey(networkId) + ":a"
}

// The projection's value of state: "<version>:<reason>".
func ComputeAbuseHoldProjectionValue(state *ComputeAbuseHoldState) []byte {
	return []byte(strconv.FormatInt(state.Version, 10) + ":" + strconv.Itoa(int(state.Reason)))
}

// The state a projection's value holds, ErrComputeAbuseHoldProjection for one this package does not write: a version
// that is no decimal of zero or more, a reason the build does not name, a hold at version 0, anything more.
func ParseComputeAbuseHoldProjection(value []byte) (*ComputeAbuseHoldState, error) {
	versionText, reasonText, ok := strings.Cut(string(value), ":")
	if !ok {
		return nil, ErrComputeAbuseHoldProjection
	}
	version, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || version < 0 || strconv.FormatInt(version, 10) != versionText {
		return nil, ErrComputeAbuseHoldProjection
	}
	reasonNumber, err := strconv.ParseInt(reasonText, 10, 16)
	if err != nil || strconv.FormatInt(reasonNumber, 10) != reasonText {
		return nil, ErrComputeAbuseHoldProjection
	}
	reason := ComputeAbuseHoldReason(reasonNumber)
	if reason != ComputeAbuseHoldReasonNone && !reason.Valid() {
		return nil, ErrComputeAbuseHoldProjection
	}
	if reason != ComputeAbuseHoldReasonNone && version == 0 {
		// a hold is a row, whose version starts at 1
		return nil, ErrComputeAbuseHoldProjection
	}
	return &ComputeAbuseHoldState{Version: version, Reason: reason}, nil
}

// The network's projection as it stands: nil, with no error, where none stands or where its value does not read, which
// a reader treats as absent and fills again from Postgres.
func ComputeAbuseHoldProjected(ctx context.Context, redis operator.Redis, networkId operator.Id) (*ComputeAbuseHoldState, error) {
	value, found, err := redis.Get(ctx, ComputeAbuseHoldRedisKey(networkId))
	if err != nil || !found {
		return nil, err
	}
	state, err := ParseComputeAbuseHoldProjection(value)
	if err != nil {
		return nil, nil
	}
	return state, nil
}

// Writes state as networkId's projection unless the projection holds a newer version, compare-and-set against what it
// read, a few tries against a concurrent writer; true where the projection holds state's version or a newer one
// after, false where it gave up. A value that does not read is replaced. Settings with no projection write none and
// answer true, since every admission then reads Postgres.
func ComputeAbuseHoldProject(ctx context.Context, redis operator.Redis, settings *ComputeAbuseHoldSettings, networkId operator.Id, state *ComputeAbuseHoldState) (bool, error) {
	if settings.ProjectionMaxAge <= 0 {
		return true, nil
	}
	key := ComputeAbuseHoldRedisKey(networkId)
	value := ComputeAbuseHoldProjectionValue(state)
	attemptCount := max(1, settings.ProjectionAttemptCount)
	for attempt := 0; attempt < attemptCount; attempt += 1 {
		current, found, err := redis.Get(ctx, key)
		if err != nil {
			return false, err
		}
		if !found {
			set, err := redis.SetIfAbsent(ctx, key, value, settings.ProjectionMaxAge)
			if err != nil {
				return false, err
			}
			if set {
				return true, nil
			}
			continue
		}
		if standing, err := ParseComputeAbuseHoldProjection(current); err == nil && state.Version <= standing.Version {
			// as new or newer stands: a lower version never replaces a higher
			return true, nil
		}
		set, err := redis.CompareAndSet(ctx, key, current, value, settings.ProjectionMaxAge)
		if err != nil {
			return false, err
		}
		if set {
			return true, nil
		}
	}
	return false, nil
}
