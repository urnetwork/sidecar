//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package bench

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The search row at reduced scale, settings production's: two rates of a 75-day mailbox, each giving §22.8's fields.
func benchSmallSearchSettings() *SearchBenchSettings {
	settings := DefaultSearchBenchSettings()
	settings.Corpus.Days = 75
	settings.Corpus.VocabularyCount = 2000
	settings.Corpus.RareWordCount = 24
	settings.Corpus.BodyWordCount = 30
	settings.Corpus.ShardDocumentCount = 64
	settings.MessagesPerDays = []int{4, 8}
	settings.WarmQueryCount = 24
	settings.ColdQueryCount = 3
	return settings
}

// Each rate gives the warm figures with their failures beside them, the cold contract's clauses, the quality figures
// and one roll-up's time, and a run at this scale is a smoke.
func TestSearchBenchGivesTheRowsFieldsAtReducedScale(t *testing.T) {
	settings := benchSmallSearchSettings()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	report, err := RunSearchBench(context.Background(), settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Smoke || len(report.Rates) != 2 || len(report.Settings) == 0 {
		t.Fatalf("the report: smoke %v, %d rates, settings %v", report.Smoke, len(report.Rates), report.Settings)
	}
	for _, rate := range report.Rates {
		if rate.MessageCount != rate.Days*rate.MessagesPerDay || rate.AllByteCount == 0 {
			t.Errorf("%d a day: %d messages, all %d B", rate.MessagesPerDay, rate.MessageCount, rate.AllByteCount)
		}
		for name, figure := range map[string]*BenchLatency{"buckets": rate.Buckets, "all": rate.All} {
			if figure == nil || figure.Queries != settings.WarmQueryCount || figure.Failed != 0 || figure.LatencyMillis.Count != int64(figure.Queries) {
				t.Errorf("%d a day, %s: %+v", rate.MessagesPerDay, name, figure)
			}
		}
		quality := rate.Quality
		if quality == nil || quality.Queries != settings.WarmQueryCount || quality.Failed != 0 {
			t.Fatalf("%d a day, quality: %+v", rate.MessagesPerDay, quality)
		}
		// the desktop holds the text: its top hits verify, and a rare word's messages lead its hits; the typo figure is
		// what the engine gives, held here only to be taken
		if quality.VerifiedHitCount == 0 || quality.TopOneConfirmed < settings.TopOneConfirmed || quality.PrecisionAtFive < settings.PrecisionAtFive ||
			quality.TypoTopFive < 0 || 1 < quality.TypoTopFive {
			t.Errorf("%d a day, quality: %+v", rate.MessagesPerDay, quality)
		}
		cold := rate.Cold
		if cold == nil || len(cold.Queries) != settings.ColdQueryCount || cold.Failed != 0 {
			t.Fatalf("%d a day, cold: %+v", rate.MessagesPerDay, cold)
		}
		for _, query := range cold.Queries {
			if query.CompletionMillis <= 0 || query.BoundMillis <= 0 || query.Failure != "" {
				t.Errorf("%d a day, a cold query: %+v", rate.MessagesPerDay, query)
			}
		}
		if !cold.CompletionMet || !cold.FirstReportMet {
			t.Errorf("%d a day: the cold contract's clauses: %+v", rate.MessagesPerDay, cold)
		}
		if !rate.RollUpCommitted || rate.RollUpMillis <= 0 {
			t.Errorf("%d a day: the roll-up committed %v in %v ms", rate.MessagesPerDay, rate.RollUpCommitted, rate.RollUpMillis)
		}
	}
	if _, err := json.Marshal(report); err != nil {
		t.Fatal(err)
	}
}

// A search that finds nothing reads zero on every quality figure, and fails the clause: what the row's quality clause
// rests on.
func TestSearchBenchQualityFailsAMissedQuery(t *testing.T) {
	settings := benchSmallSearchSettings()
	queries := []*BenchRareQuery{{Word: "zorvak", Typo: "zorvek", IntendedPath: "m/x.eml", Paths: []string{"m/x.eml"}}}
	quality := benchQualityOf(settings, queries, func(text string, fuzzy bool) ([]sidecar.SearchHit, error) {
		return nil, nil
	})
	if quality.PrecisionAtFive != 0 || quality.TopOneConfirmed != 0 || quality.TypoTopFive != 0 {
		t.Fatalf("a search finding nothing: %+v", quality)
	}
}
