package computeservice

// The provider store's rules that need no database (PROV-M12-01; DESIGN-COMPUTE §4.7): each gate result's and each
// change's move between listed, gated, suspended and out, the re-check's due date, the history's words, and the
// refusals made before anything is written. Its SQL runs against the private test stack in server's
// sidecarctl/cmd_compute_provider_server_test.go, through `sidecarctl compute provider` and the store itself: a price
// read per model and hour, and each status change recorded with its gate result.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// A database a test records: every statement queued or run, never a row answered. A Query answers an error, so a
// store reading through it fails; Exec and Batch take their statements.
type recordingComputeDb struct {
	stateLock  sync.Mutex
	statements []*recordedComputeStatement
	// what each call answers instead, where set
	err error
}

// One statement as the store sent it.
type recordedComputeStatement struct {
	sql  string
	args []any
}

func (self *recordingComputeDb) record(sql string, args []any) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return self.err
	}
	self.statements = append(self.statements, &recordedComputeStatement{sql: sql, args: args})
	return nil
}

func (self *recordingComputeDb) recorded() []*recordedComputeStatement {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*recordedComputeStatement{}, self.statements...)
}

func (self *recordingComputeDb) Db(ctx context.Context, callback func(conn operator.DbConn) error, options ...operator.DbOption) error {
	return callback(&recordingComputeTx{db: self})
}

func (self *recordingComputeDb) Tx(ctx context.Context, callback func(tx operator.DbTx) error, options ...operator.DbOption) error {
	return callback(&recordingComputeTx{db: self})
}

// A connection or transaction of a recordingComputeDb.
type recordingComputeTx struct {
	db *recordingComputeDb
}

func (self *recordingComputeTx) Query(ctx context.Context, sql string, args ...any) (operator.DbRows, error) {
	if err := self.db.record(sql, args); err != nil {
		return nil, err
	}
	return nil, errors.New("a recording database answers no rows")
}

func (self *recordingComputeTx) Exec(ctx context.Context, sql string, args ...any) (operator.DbResult, error) {
	return operator.DbResult{RowsAffected: 1}, self.db.record(sql, args)
}

func (self *recordingComputeTx) Batch(ctx context.Context, batch *operator.DbBatch, read func(results operator.DbBatchResults) error) error {
	for index := range batch.Len() {
		sql, args := batch.Statement(index)
		if err := self.db.record(sql, args); err != nil {
			return err
		}
	}
	if read == nil {
		return nil
	}
	return read(&recordingComputeBatchResults{})
}

func (self *recordingComputeTx) CreateTempTable(ctx context.Context, spec string, values ...any) error {
	return errors.New("not recorded")
}

func (self *recordingComputeTx) CreateTempTableAllowDuplicates(ctx context.Context, spec string, values ...any) error {
	return errors.New("not recorded")
}

func (self *recordingComputeTx) CreateTempJoinTable(ctx context.Context, spec string, keyValues map[any]any) error {
	return errors.New("not recorded")
}

// Every statement of a batch ran.
type recordingComputeBatchResults struct{}

func (self *recordingComputeBatchResults) Exec() (operator.DbResult, error) {
	return operator.DbResult{RowsAffected: 1}, nil
}

func (self *recordingComputeBatchResults) Query() (operator.DbRows, error) {
	return nil, errors.New("a recording database answers no rows")
}

// A history entry of gate's result.
func testGateEntry(gate string, result string) *ComputeProviderHistoryEntry {
	return &ComputeProviderHistoryEntry{Kind: ComputeProviderHistoryGate, Gate: gate, Result: result}
}

// Each status a gate result moves engy to: its own gate's pass admits from listed and out and lifts no suspension;
// G-PROV-any's pass readmits from out only while its own gate's latest result is a pass; any failure takes a gated or
// suspended provider out and leaves a listed one listed; and no gate but its own and G-PROV-any is engy's.
func TestComputeProviderGateTransitions(t *testing.T) {
	ownPassed := []*ComputeProviderHistoryEntry{testGateEntry("G-PROV-engy", ComputeProviderGatePass)}
	ownFailed := []*ComputeProviderHistoryEntry{testGateEntry("G-PROV-engy", ComputeProviderGatePass), testGateEntry("G-PROV-engy", ComputeProviderGateFail)}
	cases := []struct {
		status  ComputeProviderStatus
		history []*ComputeProviderHistoryEntry
		gate    string
		passed  bool
		want    ComputeProviderStatus
	}{
		{status: ComputeProviderStatusListed, gate: "G-PROV-engy", passed: true, want: ComputeProviderStatusGated},
		{status: ComputeProviderStatusGated, history: ownPassed, gate: "G-PROV-engy", passed: true, want: ComputeProviderStatusGated},
		{status: ComputeProviderStatusSuspended, history: ownPassed, gate: "G-PROV-engy", passed: true, want: ComputeProviderStatusSuspended},
		{status: ComputeProviderStatusOut, history: ownFailed, gate: "G-PROV-engy", passed: true, want: ComputeProviderStatusGated},
		{status: ComputeProviderStatusListed, gate: "G-PROV-engy", passed: false, want: ComputeProviderStatusListed},
		{status: ComputeProviderStatusGated, history: ownPassed, gate: "G-PROV-engy", passed: false, want: ComputeProviderStatusOut},
		{status: ComputeProviderStatusSuspended, history: ownPassed, gate: "G-PROV-engy", passed: false, want: ComputeProviderStatusOut},
		{status: ComputeProviderStatusOut, history: ownFailed, gate: "G-PROV-engy", passed: false, want: ComputeProviderStatusOut},
		{status: ComputeProviderStatusListed, gate: ComputeProviderGateAny, passed: true, want: ComputeProviderStatusListed},
		{status: ComputeProviderStatusGated, history: ownPassed, gate: ComputeProviderGateAny, passed: true, want: ComputeProviderStatusGated},
		{status: ComputeProviderStatusSuspended, history: ownPassed, gate: ComputeProviderGateAny, passed: true, want: ComputeProviderStatusSuspended},
		{status: ComputeProviderStatusOut, history: ownPassed, gate: ComputeProviderGateAny, passed: true, want: ComputeProviderStatusGated},
		{status: ComputeProviderStatusOut, history: ownFailed, gate: ComputeProviderGateAny, passed: true, want: ComputeProviderStatusOut},
		{status: ComputeProviderStatusListed, gate: ComputeProviderGateAny, passed: false, want: ComputeProviderStatusListed},
		{status: ComputeProviderStatusGated, history: ownPassed, gate: ComputeProviderGateAny, passed: false, want: ComputeProviderStatusOut},
		{status: ComputeProviderStatusSuspended, history: ownPassed, gate: ComputeProviderGateAny, passed: false, want: ComputeProviderStatusOut},
	}
	for _, c := range cases {
		got, err := computeProviderGateTransition(ComputeProviderIdEngy, c.status, c.history, c.gate, c.passed)
		if err != nil || got != c.want {
			t.Errorf("%s, %s passed %v: moved to %s, %v; want %s", c.status, c.gate, c.passed, got, err, c.want)
		}
	}
	for _, c := range []struct {
		id   ComputeProviderId
		gate string
	}{
		{id: ComputeProviderIdEngy, gate: "G-PROV-saygm"},
		{id: ComputeProviderIdEngy, gate: "G-SRCH-parallel"},
		{id: ComputeProviderIdEngy, gate: ""},
		{id: ComputeProviderIdParallel, gate: ComputeProviderGateAny},
		{id: "targon", gate: ComputeProviderGateAny},
	} {
		if _, err := computeProviderGateTransition(c.id, ComputeProviderStatusGated, nil, c.gate, true); err == nil {
			t.Errorf("%s took %q", c.id, c.gate)
		}
	}
	if status, err := computeProviderGateTransition(ComputeProviderIdParallel, ComputeProviderStatusListed, nil, "G-SRCH-parallel", true); err != nil || status != ComputeProviderStatusGated {
		t.Errorf("Parallel's own gate: %s, %v", status, err)
	}
}

// Only a gated provider is suspended and only a suspended one resumed.
func TestComputeProviderSuspendResumeTransitions(t *testing.T) {
	for status := range computeProviderStatusWords {
		suspended, err := computeProviderChangeTransition(ComputeProviderIdHippius, status, ComputeProviderHistorySuspend)
		if (status == ComputeProviderStatusGated) != (err == nil) || (err == nil && suspended != ComputeProviderStatusSuspended) {
			t.Errorf("suspend from %s: %s, %v", status, suspended, err)
		}
		resumed, err := computeProviderChangeTransition(ComputeProviderIdHippius, status, ComputeProviderHistoryResume)
		if (status == ComputeProviderStatusSuspended) != (err == nil) || (err == nil && resumed != ComputeProviderStatusGated) {
			t.Errorf("resume from %s: %s, %v", status, resumed, err)
		}
	}
}

// G-PROV-any falls due its interval after the latest pass of the provider's own gate or of G-PROV-any; a failure or
// another kind of entry moves nothing, and a provider never passed has nothing due.
func TestComputeProviderRecheckDue(t *testing.T) {
	start := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	interval := DefaultComputeProviderSettings().GateRecheckInterval
	at := func(days int) int64 {
		return start.AddDate(0, 0, days).UnixMilli()
	}
	row := &ComputeProviderRow{Id: ComputeProviderIdEngy}
	if due := row.RecheckDue(interval); !due.IsZero() {
		t.Fatalf("a provider never passed is due %s", due)
	}
	row.History = []*ComputeProviderHistoryEntry{
		{Kind: ComputeProviderHistoryGate, Gate: "G-PROV-engy", Result: ComputeProviderGatePass, TimeMs: at(0)},
		{Kind: ComputeProviderHistorySuspend, TimeMs: at(10)},
		{Kind: ComputeProviderHistoryGate, Gate: ComputeProviderGateAny, Result: ComputeProviderGatePass, TimeMs: at(80)},
		{Kind: ComputeProviderHistoryGate, Gate: ComputeProviderGateAny, Result: ComputeProviderGateFail, TimeMs: at(85)},
		{Kind: ComputeProviderHistoryGate, Gate: "G-PROV-saygm", Result: ComputeProviderGatePass, TimeMs: at(86)},
	}
	if due := row.RecheckDue(interval); !due.Equal(start.AddDate(0, 0, 80).Add(interval)) {
		t.Fatalf("due %s", due)
	}
	if last := row.LastGate(ComputeProviderGateAny); last == nil || last.Result != ComputeProviderGateFail {
		t.Fatalf("G-PROV-any's latest reads %+v", last)
	}
}

// The history's statuses are words, and a word none of the four refuses the entry.
func TestComputeProviderHistoryWords(t *testing.T) {
	entry := &ComputeProviderHistoryEntry{Kind: ComputeProviderHistoryGate, Gate: "G-PROV-engy", Result: ComputeProviderGatePass,
		From: ComputeProviderStatusListed, To: ComputeProviderStatusGated, TimeMs: 1, By: "rota-a"}
	data, err := json.Marshal(entry)
	if err != nil || !strings.Contains(string(data), `"from":"listed"`) || !strings.Contains(string(data), `"to":"gated"`) {
		t.Fatalf("an entry encodes as %s, %v", data, err)
	}
	read := &ComputeProviderHistoryEntry{}
	if err := json.Unmarshal(data, read); err != nil || *read != *entry {
		t.Fatalf("an entry reads back as %+v, %v", read, err)
	}
	if err := json.Unmarshal([]byte(`{"kind":"gate","from":"retired","to":"gated"}`), read); err == nil {
		t.Fatal("a status none of the four read")
	}
	if _, err := json.Marshal(&ComputeProviderHistoryEntry{From: 9}); err == nil {
		t.Fatal("a status none of the four encoded")
	}
}

// A gate result with no result, no operator or text past the bound, a suspension with no reason, and a slug no table
// names are refused before the store sends a statement.
func TestComputeProviderStoreRefusesBeforeWriting(t *testing.T) {
	ctx := context.Background()
	db := &recordingComputeDb{}
	settings := DefaultComputeProviderSettings()
	store := NewComputeProviderStore(db, settings)
	at := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	long := strings.Repeat("x", settings.HistoryTextMaxByteCount+1)
	for label, write := range map[string]func() (*ComputeProviderRow, error){
		"no result": func() (*ComputeProviderRow, error) { return store.RecordGate(ctx, ComputeProviderIdEngy, nil, at) },
		"no operator": func() (*ComputeProviderRow, error) {
			return store.RecordGate(ctx, ComputeProviderIdEngy, &ComputeProviderGateResult{Gate: "G-PROV-engy", Passed: true}, at)
		},
		"a long note": func() (*ComputeProviderRow, error) {
			return store.RecordGate(ctx, ComputeProviderIdEngy, &ComputeProviderGateResult{Gate: "G-PROV-engy", Passed: true, By: "rota-a", Note: long}, at)
		},
		"a long evidence reference": func() (*ComputeProviderRow, error) {
			return store.RecordGate(ctx, ComputeProviderIdEngy, &ComputeProviderGateResult{Gate: "G-PROV-engy", Passed: true, By: "rota-a", Evidence: long}, at)
		},
		"a suspension without its reason": func() (*ComputeProviderRow, error) {
			return store.Suspend(ctx, ComputeProviderIdEngy, &ComputeProviderStatusChange{By: "rota-a"}, at)
		},
		"a resumption without its operator": func() (*ComputeProviderRow, error) {
			return store.Resume(ctx, ComputeProviderIdEngy, &ComputeProviderStatusChange{}, at)
		},
		"another provider's gate": func() (*ComputeProviderRow, error) {
			return store.RecordGate(ctx, ComputeProviderIdEngy, &ComputeProviderGateResult{Gate: "G-PROV-saygm", Passed: true, By: "rota-a"}, at)
		},
		"no table's slug": func() (*ComputeProviderRow, error) {
			return store.RecordGate(ctx, "targon", &ComputeProviderGateResult{Gate: ComputeProviderGateAny, Passed: true, By: "rota-a"}, at)
		},
	} {
		if row, err := write(); err == nil || row != nil {
			t.Errorf("%s: wrote %+v", label, row)
		}
	}
	if statements := db.recorded(); len(statements) != 0 {
		t.Fatalf("a refused write sent %d statements", len(statements))
	}
	// a read that fails is a store error, never an empty answer
	if statuses, err := store.Statuses(ctx); err == nil || statuses != nil {
		t.Fatalf("a failing read answered %v", statuses)
	}
	if statuses, err := NewComputeProviderStore(nil, settings).Statuses(ctx); err == nil || statuses != nil {
		t.Fatalf("no database answered %v", statuses)
	}
}

// A row whose code, slug or kind disagree with this build's table names no provider, so Statuses leaves it out.
func TestComputeProviderRowMustAgreeWithTheTable(t *testing.T) {
	cases := []struct {
		code int16
		slug string
		kind int16
		ok   bool
	}{
		{code: 2, slug: "engy", kind: 1, ok: true},
		{code: 2, slug: "saygm", kind: 1, ok: false},
		{code: 2, slug: "engy", kind: 2, ok: false},
		{code: 9, slug: "targon", kind: 1, ok: false},
		{code: 0, slug: "", kind: 0, ok: false},
	}
	for _, c := range cases {
		if id, ok := computeProviderRowId(c.code, c.slug, c.kind); ok != c.ok || (ok && id != ComputeProviderIdEngy) {
			t.Errorf("row %d %q %d: %q, %v", c.code, c.slug, c.kind, id, ok)
		}
	}
}
