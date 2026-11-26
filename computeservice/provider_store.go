// The provider store (DESIGN-COMPUTE §4.7, §9.6, §14.4's MG-C2): compute_provider, one row a provider, and
// compute_provider_price, one row a model or shape a provider and hour. Their tables are PROV's part of MG-C2, which
// sidecar/model registers (compute_provider_migrations.go, CONTRACTS C-30), so they exist only where the binary links
// MG-C2; this file is their one reader and writer, over the operator.Db the process's Env grants (owner decision 594).
// What a server sees here is compute-7's row: a provider's id, kind, status and gate results, and its hourly price
// reads, no network's anything.
//
// A provider's row moves through four statuses (§4.7):
//
//	listed     its row exists and its gate has not passed: out of the catalog
//	gated      its gate passed: it serves where this deployment's settings enable it
//	suspended  the compute rota suspended it, as when the provider suspends URnetwork's account (§14.10): no new work
//	out        a gate failed after it had passed, a failed G-PROV-any above all: no new work until a gate passes
//
// Only a pass of the provider's own gate admits it, from listed or out; a pass of G-PROV-any readmits a provider that
// is out only while its own gate's latest result is a pass. A failed gate takes a gated or suspended provider out. The
// rota suspends a gated provider and resumes a suspended one, and nothing else moves a row. Every change and every
// gate result is an entry of the row's history, dated, with who recorded it, so `sidecarctl compute provider ls`
// shows each gate's latest result and when G-PROV-any is next due (§14.10).
//
// A row a reader cannot read, or that names a slug, kind or status this build does not know, refuses its provider:
// Statuses leaves it out, and the registry refuses what Statuses does not answer gated (§4.7).
//
// Safe for concurrent use: every write is one transaction holding the provider's row.

package computeservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// A provider's status, as compute_provider.status holds it (§14.4).
type ComputeProviderStatus int16

const (
	ComputeProviderStatusListed    ComputeProviderStatus = 1
	ComputeProviderStatusGated     ComputeProviderStatus = 2
	ComputeProviderStatusSuspended ComputeProviderStatus = 3
	ComputeProviderStatusOut       ComputeProviderStatus = 4
)

// Every status, by its word.
var computeProviderStatusWords = map[ComputeProviderStatus]string{
	ComputeProviderStatusListed:    "listed",
	ComputeProviderStatusGated:     "gated",
	ComputeProviderStatusSuspended: "suspended",
	ComputeProviderStatusOut:       "out",
}

// Whether the status is one of the four.
func (self ComputeProviderStatus) Valid() bool {
	_, ok := computeProviderStatusWords[self]
	return ok
}

// The status's word.
func (self ComputeProviderStatus) String() string {
	if word, ok := computeProviderStatusWords[self]; ok {
		return word
	}
	return fmt.Sprintf("status %d", int16(self))
}

// The word, as the history's JSON holds it.
func (self ComputeProviderStatus) MarshalText() ([]byte, error) {
	if !self.Valid() {
		return nil, fmt.Errorf("compute provider status %d is none of the four", int16(self))
	}
	return []byte(self.String()), nil
}

// A word the history holds; any other refuses the row.
func (self *ComputeProviderStatus) UnmarshalText(text []byte) error {
	for status, word := range computeProviderStatusWords {
		if word == string(text) {
			*self = status
			return nil
		}
	}
	return fmt.Errorf("compute provider status %q is none of the four", text)
}

// What a history entry records. Identifiers.
const (
	ComputeProviderHistoryGate    = "gate"
	ComputeProviderHistorySuspend = "suspend"
	ComputeProviderHistoryResume  = "resume"
)

// A gate entry's result. Identifiers.
const (
	ComputeProviderGatePass = "pass"
	ComputeProviderGateFail = "fail"
)

// One entry of a provider's history, as compute_provider.history holds it, oldest first.
type ComputeProviderHistoryEntry struct {
	// gate, suspend or resume.
	Kind string `json:"kind"`
	// A gate entry's gate and result, pass or fail.
	Gate   string `json:"gate,omitempty"`
	Result string `json:"result,omitempty"`
	// The status before and after.
	From ComputeProviderStatus `json:"from"`
	To   ComputeProviderStatus `json:"to"`
	// When it was recorded, in unix milliseconds.
	TimeMs int64 `json:"time_ms"`
	// The operator who recorded it.
	By string `json:"by"`
	// What the gate's evidence is filed under, such as its report's SHA-256; a gate entry's alone.
	Evidence string `json:"evidence,omitempty"`
	// A suspension's reason, or a note.
	Note string `json:"note,omitempty"`
}

// When it was recorded.
func (self *ComputeProviderHistoryEntry) Time() time.Time {
	return time.UnixMilli(self.TimeMs).UTC()
}

// One provider's row.
type ComputeProviderRow struct {
	Id   ComputeProviderId
	Code ComputeProviderCode
	Kind ComputeProviderKind
	// Its status and when it took it.
	Status     ComputeProviderStatus
	StatusTime time.Time
	// Every gate result and status change, oldest first.
	History []*ComputeProviderHistoryEntry
}

// The latest result of gate, nil where it has none.
func (self *ComputeProviderRow) LastGate(gate string) *ComputeProviderHistoryEntry {
	return computeProviderLastGate(self.History, gate)
}

// When G-PROV-any is next due: interval after the latest pass of the provider's own gate or of G-PROV-any; zero where
// neither has passed, so nothing is due.
func (self *ComputeProviderRow) RecheckDue(interval time.Duration) time.Time {
	gate, _ := ComputeProviderGateOf(self.Id)
	due := time.Time{}
	for _, entry := range self.History {
		if entry.Kind == ComputeProviderHistoryGate && entry.Result == ComputeProviderGatePass &&
			(entry.Gate == gate || entry.Gate == ComputeProviderGateAny) {
			due = entry.Time().Add(interval)
		}
	}
	return due
}

// The latest entry of gate in history, nil for none.
func computeProviderLastGate(history []*ComputeProviderHistoryEntry, gate string) *ComputeProviderHistoryEntry {
	for i := len(history) - 1; 0 <= i; i -= 1 {
		if history[i].Kind == ComputeProviderHistoryGate && history[i].Gate == gate {
			return history[i]
		}
	}
	return nil
}

// One gate's result, as the compute rota records it (§4.7, §14.10).
type ComputeProviderGateResult struct {
	// The provider's own gate, as ComputeProviderGateOf names it, or G-PROV-any.
	Gate string
	// Whether every check of the gate passed.
	Passed bool
	// The operator recording it.
	By string
	// Where its evidence is filed, such as its report's SHA-256; may be empty.
	Evidence string
	// Anything else; may be empty.
	Note string
}

// A suspension or a resumption, as the compute rota records it.
type ComputeProviderStatusChange struct {
	// The operator recording it.
	By string
	// Why: a suspension needs one, a resumption may give one.
	Reason string
}

var (
	// A status change the row's status does not allow: a suspension of a provider not gated, a resumption of one not
	// suspended, or a gate that is not the provider's own or G-PROV-any.
	ErrComputeProviderTransition = errors.New("compute provider status change refused")
	// A slug this build does not know, or a row that disagrees with this build's table.
	ErrComputeProviderUnknown = errors.New("no such compute provider")
)

// The status id moves to from status when gate's result is recorded, given the row's history before it.
func computeProviderGateTransition(id ComputeProviderId, status ComputeProviderStatus, history []*ComputeProviderHistoryEntry, gate string, passed bool) (ComputeProviderStatus, error) {
	spec := computeProviderSpecOf(id)
	if spec == nil {
		return 0, fmt.Errorf("%w: %q", ErrComputeProviderUnknown, id)
	}
	if !status.Valid() {
		return 0, fmt.Errorf("%w: %s's row reads %s", ErrComputeProviderTransition, id, status)
	}
	own := gate == spec.gate
	if !own && !(gate == ComputeProviderGateAny && spec.kind != ComputeProviderKindSearch) {
		return 0, fmt.Errorf("%w: %s is admitted by %s and re-checked by %s, not by %q", ErrComputeProviderTransition, id, spec.gate, ComputeProviderGateAny, gate)
	}
	switch {
	case passed && own:
		// a pass of its own gate admits it, from listed or out, and lifts no suspension
		if status == ComputeProviderStatusSuspended {
			return status, nil
		}
		return ComputeProviderStatusGated, nil
	case passed:
		// a re-check readmits a provider that is out only while its own gate's latest result stands passed
		if status == ComputeProviderStatusOut {
			if last := computeProviderLastGate(history, spec.gate); last != nil && last.Result == ComputeProviderGatePass {
				return ComputeProviderStatusGated, nil
			}
		}
		return status, nil
	}
	// a failed gate takes out a provider that serves or could serve again; one never gated stays listed
	if status == ComputeProviderStatusListed {
		return status, nil
	}
	return ComputeProviderStatusOut, nil
}

// The status a suspension or resumption moves status to.
func computeProviderChangeTransition(id ComputeProviderId, status ComputeProviderStatus, kind string) (ComputeProviderStatus, error) {
	switch {
	case kind == ComputeProviderHistorySuspend && status == ComputeProviderStatusGated:
		return ComputeProviderStatusSuspended, nil
	case kind == ComputeProviderHistoryResume && status == ComputeProviderStatusSuspended:
		return ComputeProviderStatusGated, nil
	case kind == ComputeProviderHistorySuspend:
		return 0, fmt.Errorf("%w: %s is %s, and only a gated provider is suspended", ErrComputeProviderTransition, id, status)
	case kind == ComputeProviderHistoryResume:
		return 0, fmt.Errorf("%w: %s is %s, and only a suspended provider is resumed", ErrComputeProviderTransition, id, status)
	}
	return 0, fmt.Errorf("%w: no change %q", ErrComputeProviderTransition, kind)
}

// What compute_provider_price's item is.
type ComputeProviderPriceItem int16

const (
	// A model, priced per million tokens.
	ComputeProviderPriceItemModel ComputeProviderPriceItem = 1
	// An enclave shape, priced per hour and per GiB of egress.
	ComputeProviderPriceItemShape ComputeProviderPriceItem = 2
)

// One hourly read of one model's or shape's prices (§9.6), in nano-gamma, as the provider answered.
type ComputeProviderPriceRead struct {
	Provider ComputeProviderId
	Item     ComputeProviderPriceItem
	// The provider's own id for the model, or the shape's name.
	ItemId string
	// When it was read; its hour is the read's, one a model and hour.
	ReadTime time.Time
	// One gamma's USD value at the read, in nano-USD (ComputeProviderCatalog.GammaNanoUsd).
	GammaNanoUsd int64
	// A model's prices per million tokens; 0 for a shape.
	InputNanoGammaPerMillion       int64
	OutputNanoGammaPerMillion      int64
	CachedInputNanoGammaPerMillion int64
	// A shape's prices per hour and per GiB of egress; 0 for a model.
	HourNanoGamma         int64
	EgressNanoGammaPerGib int64
	// Whether the price varies by request, the prices then the most it charges (§6.3).
	PriceVaries bool
	// What it can serve now, where CapacityKnown.
	Capacity      int64
	CapacityKnown bool
}

// The hour the read counts for: its time's UTC hour.
func (self *ComputeProviderPriceRead) ReadHour() time.Time {
	return self.ReadTime.UTC().Truncate(time.Hour)
}

// compute_provider and compute_provider_price over a database.
type ComputeProviderStore struct {
	db       operator.Db
	settings *ComputeProviderSettings
}

// A store over db, which must link MG-C2: on a database without its tables every call fails, never answers.
func NewComputeProviderStore(db operator.Db, settings *ComputeProviderSettings) *ComputeProviderStore {
	if settings == nil {
		settings = DefaultComputeProviderSettings()
	}
	return &ComputeProviderStore{db: db, settings: settings}
}

// Each provider's status, by slug, for the rows that read whole and agree with this build's table; a provider whose
// row is absent, unreadable or foreign is left out, which refuses it.
func (self *ComputeProviderStore) Statuses(ctx context.Context) (map[ComputeProviderId]ComputeProviderStatus, error) {
	if self.db == nil {
		return nil, errors.New("compute providers: no database")
	}
	statuses := map[ComputeProviderId]ComputeProviderStatus{}
	err := self.db.Db(ctx, func(conn operator.DbConn) error {
		clear(statuses)
		rows, err := conn.Query(ctx, `SELECT provider, slug, kind, status FROM compute_provider`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var code, kind, status int16
			var slug string
			if err := rows.Scan(&code, &slug, &kind, &status); err != nil {
				return err
			}
			id, ok := computeProviderRowId(code, slug, kind)
			if !ok || !ComputeProviderStatus(status).Valid() {
				continue
			}
			statuses[id] = ComputeProviderStatus(status)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return statuses, nil
}

// The slug a row names, where its code, slug and kind agree with this build's table.
func computeProviderRowId(code int16, slug string, kind int16) (ComputeProviderId, bool) {
	id, ok := ComputeProviderIdOf(ComputeProviderCode(code))
	if !ok || string(id) != slug {
		return "", false
	}
	if specKind, _ := ComputeProviderKindOf(id); specKind != ComputeProviderKind(kind) {
		return "", false
	}
	return id, true
}

// Every row, in code order, each read whole: a row whose history does not parse or that disagrees with this build's
// table fails the read, so an operator sees it rather than a list without it.
func (self *ComputeProviderStore) Providers(ctx context.Context) ([]*ComputeProviderRow, error) {
	if self.db == nil {
		return nil, errors.New("compute providers: no database")
	}
	providerRows := []*ComputeProviderRow{}
	err := self.db.Db(ctx, func(conn operator.DbConn) error {
		providerRows = providerRows[:0]
		rows, err := conn.Query(ctx, `SELECT provider, slug, kind, status, status_time, history FROM compute_provider ORDER BY provider`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			row, err := scanComputeProviderRow(rows)
			if err != nil {
				return err
			}
			providerRows = append(providerRows, row)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return providerRows, nil
}

// One row from a query that selects provider, slug, kind, status, status_time and history in that order.
func scanComputeProviderRow(rows operator.DbRows) (*ComputeProviderRow, error) {
	var code, kind, status int16
	var slug string
	var statusTime time.Time
	var history []byte
	if err := rows.Scan(&code, &slug, &kind, &status, &statusTime, &history); err != nil {
		return nil, err
	}
	id, ok := computeProviderRowId(code, slug, kind)
	if !ok || !ComputeProviderStatus(status).Valid() {
		return nil, fmt.Errorf("%w: compute_provider's row %d (%q) disagrees with this build", ErrComputeProviderUnknown, code, slug)
	}
	entries := []*ComputeProviderHistoryEntry{}
	if err := json.Unmarshal(history, &entries); err != nil {
		return nil, fmt.Errorf("compute_provider's row for %s: its history does not parse: %w", id, err)
	}
	return &ComputeProviderRow{
		Id:         id,
		Code:       ComputeProviderCode(code),
		Kind:       ComputeProviderKind(kind),
		Status:     ComputeProviderStatus(status),
		StatusTime: statusTime.UTC(),
		History:    entries,
	}, nil
}

// Records gate's result for id at at, moving its status by the rules above, and answers the row as it stands after.
// A row not yet written is written listed first. A gate that is not id's own or G-PROV-any, and text past the
// settings' bounds, are refused with nothing written.
func (self *ComputeProviderStore) RecordGate(ctx context.Context, id ComputeProviderId, result *ComputeProviderGateResult, at time.Time) (*ComputeProviderRow, error) {
	if result == nil {
		return nil, fmt.Errorf("%w: no gate result", ErrComputeProviderTransition)
	}
	if err := self.checkText(result.By, result.Evidence, result.Note); err != nil {
		return nil, err
	}
	// a gate that is not id's own or G-PROV-any is refused whatever the row reads, so before anything is written
	if _, err := computeProviderGateTransition(id, ComputeProviderStatusListed, nil, result.Gate, result.Passed); err != nil {
		return nil, err
	}
	gateResult := ComputeProviderGateFail
	if result.Passed {
		gateResult = ComputeProviderGatePass
	}
	return self.change(ctx, id, at, func(row *ComputeProviderRow) (*ComputeProviderHistoryEntry, error) {
		to, err := computeProviderGateTransition(id, row.Status, row.History, result.Gate, result.Passed)
		if err != nil {
			return nil, err
		}
		return &ComputeProviderHistoryEntry{
			Kind:     ComputeProviderHistoryGate,
			Gate:     result.Gate,
			Result:   gateResult,
			From:     row.Status,
			To:       to,
			By:       result.By,
			Evidence: result.Evidence,
			Note:     result.Note,
		}, nil
	})
}

// Suspends a gated provider (§14.10): no new work until it is resumed. Refused, with nothing written, for a provider
// that is not gated and for a change with no reason.
func (self *ComputeProviderStore) Suspend(ctx context.Context, id ComputeProviderId, change *ComputeProviderStatusChange, at time.Time) (*ComputeProviderRow, error) {
	if change == nil || change.Reason == "" {
		return nil, fmt.Errorf("%w: a suspension needs its reason", ErrComputeProviderTransition)
	}
	return self.statusChange(ctx, id, change, ComputeProviderHistorySuspend, at)
}

// Resumes a suspended provider, gated again. Refused, with nothing written, for a provider that is not suspended.
func (self *ComputeProviderStore) Resume(ctx context.Context, id ComputeProviderId, change *ComputeProviderStatusChange, at time.Time) (*ComputeProviderRow, error) {
	if change == nil {
		return nil, fmt.Errorf("%w: no change", ErrComputeProviderTransition)
	}
	return self.statusChange(ctx, id, change, ComputeProviderHistoryResume, at)
}

// A suspension or a resumption.
func (self *ComputeProviderStore) statusChange(ctx context.Context, id ComputeProviderId, change *ComputeProviderStatusChange, kind string, at time.Time) (*ComputeProviderRow, error) {
	if err := self.checkText(change.By, change.Reason); err != nil {
		return nil, err
	}
	return self.change(ctx, id, at, func(row *ComputeProviderRow) (*ComputeProviderHistoryEntry, error) {
		to, err := computeProviderChangeTransition(id, row.Status, kind)
		if err != nil {
			return nil, err
		}
		return &ComputeProviderHistoryEntry{
			Kind: kind,
			From: row.Status,
			To:   to,
			By:   change.By,
			Note: change.Reason,
		}, nil
	})
}

// Refuses an entry with no operator, or text past the settings' bound.
func (self *ComputeProviderStore) checkText(by string, texts ...string) error {
	if by == "" {
		return fmt.Errorf("%w: no operator named", ErrComputeProviderTransition)
	}
	for _, text := range append([]string{by}, texts...) {
		if self.settings.HistoryTextMaxByteCount < len(text) {
			return fmt.Errorf("%w: a text longer than %d bytes", ErrComputeProviderTransition, self.settings.HistoryTextMaxByteCount)
		}
	}
	return nil
}

// One status change of id in one transaction: the row written listed where absent, then read under its lock, entry
// made from it, its status, time and history written. The commit is the change's linearization point, which the
// barriers bracket, keyed by the provider's code.
func (self *ComputeProviderStore) change(ctx context.Context, id ComputeProviderId, at time.Time, entry func(row *ComputeProviderRow) (*ComputeProviderHistoryEntry, error)) (*ComputeProviderRow, error) {
	spec := computeProviderSpecOf(id)
	if spec == nil {
		return nil, fmt.Errorf("%w: %q", ErrComputeProviderUnknown, id)
	}
	if self.db == nil {
		return nil, errors.New("compute providers: no database")
	}
	// whole microseconds, as Postgres keeps a timestamp
	at = at.UTC().Truncate(time.Microsecond)
	var changed *ComputeProviderRow
	barrierKey := strconv.Itoa(int(spec.code))
	testHookBarrier(BarrierComputeProviderStatusBefore, barrierKey)
	err := self.db.Tx(ctx, func(tx operator.DbTx) error {
		changed = nil
		if _, err := tx.Exec(ctx, `
			INSERT INTO compute_provider (provider, slug, kind, status, status_time, history)
			VALUES ($1, $2, $3, $4, $5, '[]'::jsonb)
			ON CONFLICT (provider) DO NOTHING
		`, int16(spec.code), string(spec.id), int16(spec.kind), int16(ComputeProviderStatusListed), at); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT provider, slug, kind, status, status_time, history FROM compute_provider WHERE provider = $1 FOR UPDATE
		`, int16(spec.code))
		if err != nil {
			return err
		}
		var row *ComputeProviderRow
		func() {
			defer rows.Close()
			if rows.Next() {
				row, err = scanComputeProviderRow(rows)
			}
		}()
		if err == nil {
			err = rows.Err()
		}
		if err != nil {
			return err
		}
		if row == nil {
			return fmt.Errorf("compute_provider holds no row for %s", id)
		}
		next, err := entry(row)
		if err != nil {
			return err
		}
		next.TimeMs = at.UnixMilli()
		row.History = append(row.History, next)
		if over := len(row.History) - self.settings.HistoryMaxCount; 0 < over {
			row.History = row.History[over:]
		}
		history, err := json.Marshal(row.History)
		if err != nil {
			return err
		}
		if next.To != row.Status {
			row.StatusTime = at
		}
		row.Status = next.To
		if _, err := tx.Exec(ctx, `
			UPDATE compute_provider SET status = $2, status_time = $3, history = $4::jsonb WHERE provider = $1
		`, int16(spec.code), int16(row.Status), row.StatusTime, string(history)); err != nil {
			return err
		}
		changed = row
		return nil
	})
	testHookBarrier(BarrierComputeProviderStatusAfter, barrierKey)
	if err != nil {
		return nil, err
	}
	return changed, nil
}

// Stores reads, each the read of its model or shape for its hour: a later read in the hour replaces an earlier one,
// and an earlier never replaces a later. All in one transaction, so an hour's reads land together or not at all.
func (self *ComputeProviderStore) WritePriceReads(ctx context.Context, reads []*ComputeProviderPriceRead) error {
	if self.db == nil {
		return errors.New("compute providers: no database")
	}
	batch := &operator.DbBatch{}
	for _, read := range reads {
		code, known := ComputeProviderCodeOf(read.Provider)
		if !known {
			return fmt.Errorf("%w: a price read for %q", ErrComputeProviderUnknown, read.Provider)
		}
		if read.Item != ComputeProviderPriceItemModel && read.Item != ComputeProviderPriceItemShape {
			return fmt.Errorf("compute providers: a price read of no known item for %s", read.Provider)
		}
		var capacity *int64
		if read.CapacityKnown {
			capacity = &read.Capacity
		}
		batch.Queue(`
			INSERT INTO compute_provider_price (
				provider, item_kind, item_id, read_hour, read_time, gamma_nano_usd,
				input_nano_gamma_per_million, output_nano_gamma_per_million, cached_input_nano_gamma_per_million,
				hour_nano_gamma, egress_nano_gamma_per_gib, price_varies, capacity
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			ON CONFLICT (provider, item_kind, item_id, read_hour) DO UPDATE SET
				read_time = EXCLUDED.read_time,
				gamma_nano_usd = EXCLUDED.gamma_nano_usd,
				input_nano_gamma_per_million = EXCLUDED.input_nano_gamma_per_million,
				output_nano_gamma_per_million = EXCLUDED.output_nano_gamma_per_million,
				cached_input_nano_gamma_per_million = EXCLUDED.cached_input_nano_gamma_per_million,
				hour_nano_gamma = EXCLUDED.hour_nano_gamma,
				egress_nano_gamma_per_gib = EXCLUDED.egress_nano_gamma_per_gib,
				price_varies = EXCLUDED.price_varies,
				capacity = EXCLUDED.capacity
			WHERE compute_provider_price.read_time <= EXCLUDED.read_time
		`, int16(code), int16(read.Item), read.ItemId, read.ReadHour(), read.ReadTime.UTC().Truncate(time.Microsecond),
			read.GammaNanoUsd, read.InputNanoGammaPerMillion, read.OutputNanoGammaPerMillion,
			read.CachedInputNanoGammaPerMillion, read.HourNanoGamma, read.EgressNanoGammaPerGib, read.PriceVaries, capacity)
	}
	if batch.Len() == 0 {
		return nil
	}
	return self.db.Tx(ctx, func(tx operator.DbTx) error {
		return tx.Batch(ctx, batch, func(results operator.DbBatchResults) error {
			for range batch.Len() {
				if _, err := results.Exec(); err != nil {
					return err
				}
			}
			return nil
		})
	})
}

// id's newest read of each model or shape, by item and id.
func (self *ComputeProviderStore) LatestPriceReads(ctx context.Context, id ComputeProviderId) ([]*ComputeProviderPriceRead, error) {
	return self.priceReads(ctx, id, `
		SELECT DISTINCT ON (item_kind, item_id) `+computeProviderPriceColumns+`
		FROM compute_provider_price WHERE provider = $1
		ORDER BY item_kind, item_id, read_hour DESC
	`)
}

// id's reads of the hours from from up to until, oldest hour first, then by item and id.
func (self *ComputeProviderStore) PriceReads(ctx context.Context, id ComputeProviderId, from time.Time, until time.Time) ([]*ComputeProviderPriceRead, error) {
	return self.priceReads(ctx, id, `
		SELECT `+computeProviderPriceColumns+`
		FROM compute_provider_price WHERE provider = $1 AND $2 <= read_hour AND read_hour < $3
		ORDER BY read_hour, item_kind, item_id
	`, from.UTC(), until.UTC())
}

// What priceReads selects, in scanComputeProviderPriceRead's order.
const computeProviderPriceColumns = `provider, item_kind, item_id, read_time, gamma_nano_usd, input_nano_gamma_per_million,
	output_nano_gamma_per_million, cached_input_nano_gamma_per_million, hour_nano_gamma, egress_nano_gamma_per_gib,
	price_varies, capacity`

// The reads sql selects for id, its first arg the provider's code and the rest args.
func (self *ComputeProviderStore) priceReads(ctx context.Context, id ComputeProviderId, sql string, args ...any) ([]*ComputeProviderPriceRead, error) {
	code, known := ComputeProviderCodeOf(id)
	if !known {
		return nil, fmt.Errorf("%w: %q", ErrComputeProviderUnknown, id)
	}
	if self.db == nil {
		return nil, errors.New("compute providers: no database")
	}
	reads := []*ComputeProviderPriceRead{}
	err := self.db.Db(ctx, func(conn operator.DbConn) error {
		reads = reads[:0]
		rows, err := conn.Query(ctx, sql, append([]any{int16(code)}, args...)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			read := &ComputeProviderPriceRead{Provider: id}
			var provider, item int16
			var capacity *int64
			if err := rows.Scan(&provider, &item, &read.ItemId, &read.ReadTime, &read.GammaNanoUsd,
				&read.InputNanoGammaPerMillion, &read.OutputNanoGammaPerMillion, &read.CachedInputNanoGammaPerMillion,
				&read.HourNanoGamma, &read.EgressNanoGammaPerGib, &read.PriceVaries, &capacity); err != nil {
				return err
			}
			read.Item = ComputeProviderPriceItem(item)
			read.ReadTime = read.ReadTime.UTC()
			if capacity != nil {
				read.Capacity = *capacity
				read.CapacityKnown = true
			}
			reads = append(reads, read)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return slices.Clip(reads), nil
}
