package controller

// compute_rollup_day's pass with no database (BAL-M12-05): a pass begins on the day before its own, its cursor reads
// back from a run's args and refuses one that is not a UTC day or a phase; an open day is refused; and the day check
// leaves out a web search's day once its purge may have begun, and every kind once the day's partition is past its
// retention.

import (
	"slices"
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

func TestComputeRollupCursorReadsBack(t *testing.T) {
	now := time.Date(2026, 11, 25, 2, 0, 0, 0, time.UTC)
	cursor := NewComputeRollupCursor(now)
	if !cursor.Day.Equal(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)) || cursor.Phase != ComputeRollupPhaseNetworks || cursor.After != nil {
		t.Fatalf("a new pass: %+v", cursor)
	}
	// a pass begun before midnight in a zone west of UTC still reads the UTC day before
	west := time.Date(2026, 11, 24, 18, 30, 0, 0, time.FixedZone("UTC-8", -8*60*60))
	if day := NewComputeRollupCursor(west).Day; !day.Equal(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("the day before 02:30 UTC is %v", day)
	}
	after := operator.Id{1, 2, 3}
	cursor.After = &after
	cursor.Phase = ComputeRollupPhaseDrops
	args, err := cursor.Args()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseComputeRollupCursor(args)
	if err != nil || !parsed.Day.Equal(cursor.Day) || parsed.Phase != cursor.Phase || parsed.After == nil || *parsed.After != after {
		t.Fatalf("the cursor read back as %+v, %v", parsed, err)
	}
	if parsed, err := ParseComputeRollupCursor(nil); parsed != nil || err != nil {
		t.Fatalf("no args read as %+v, %v", parsed, err)
	}
	for _, refused := range []string{
		`{"day":"2026-11-24T05:00:00Z","phase":"networks"}`,
		`{"day":"2026-11-24T00:00:00Z","phase":"sweeping"}`,
		`{"phase":"networks"}`,
		`not json`,
	} {
		if _, err := ParseComputeRollupCursor([]byte(refused)); err == nil {
			t.Errorf("%s read as a cursor", refused)
		}
	}
}

// A cursor naming today or later is no closed day, refused before anything is read.
func TestComputeRollupRefusesAnOpenDay(t *testing.T) {
	env := newTestLedgerEnv()
	now := env.clock.now
	for _, day := range []time.Time{model.ComputeUtcDay(now), model.ComputeUtcDay(now).AddDate(0, 0, 1)} {
		if _, err := ComputeRollupDay(env, t.Context(), model.DefaultComputeLedgerSettings(), &ComputeRollupCursor{Day: day, Phase: ComputeRollupPhaseNetworks}); err == nil {
			t.Errorf("the open day %s was re-derived", day.Format(time.DateOnly))
		}
	}
	if env.db.callCount != 0 {
		t.Error("an open day reached the database")
	}
}

func TestComputeRollupDayKindsLeaveOutWhatIsPurged(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	day := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	everyKind := model.ComputeChargeKinds()
	// at 02:00 the next day, every kind is held whole
	compared, skipped := computeRollupDayKinds(settings, day, day.Add(26*time.Hour))
	if !slices.Equal(compared, everyKind) || len(skipped) != 0 {
		t.Fatalf("the next day: %v, %v", compared, skipped)
	}
	// once the day's first minute is past the purge's 71 h 55 min, its searches may be gone
	compared, skipped = computeRollupDayKinds(settings, day, day.Add(settings.SearchChargePurgeAge))
	if slices.Contains(compared, model.ComputeChargeKindWebSearch) || !slices.Equal(skipped, []model.ComputeChargeKind{model.ComputeChargeKindWebSearch}) {
		t.Fatalf("past the search purge: %v, %v", compared, skipped)
	}
	// once the day's partition is past its 90 days, nothing of it is re-derived
	compared, skipped = computeRollupDayKinds(settings, day, day.AddDate(0, 0, 1).Add(settings.ChargeRetention))
	if len(compared) != 0 || !slices.Equal(skipped, everyKind) {
		t.Fatalf("past the retention: %v, %v", compared, skipped)
	}
}
