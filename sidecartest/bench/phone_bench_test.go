//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package bench

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The phone row at reduced scale: each host class decrypts in 64 KiB frames, samples its search heap against §18.4's
// budget, downloads all once for "search more" and searches it again from the cache with the same hits, and gives its
// quality figures; a run at this scale is a smoke.
func TestPhoneBenchGivesTheRowsFieldsAtReducedScale(t *testing.T) {
	settings := DefaultPhoneBenchSettings()
	settings.Corpus.Days = 75
	settings.Corpus.MessagesPerDay = 6
	settings.Corpus.VocabularyCount = 2000
	settings.Corpus.RareWordCount = 16
	settings.Corpus.BodyWordCount = 30
	settings.Corpus.ShardDocumentCount = 64
	settings.DecryptByteCount = 1024*1024 + 77
	settings.MemoryQueryCount = 8
	settings.QualityQueryCount = 16
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	report, err := RunPhoneBench(context.Background(), settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Smoke || len(report.Hosts) != 3 {
		t.Fatalf("the report: smoke %v, %d hosts", report.Smoke, len(report.Hosts))
	}
	for _, host := range report.Hosts {
		// a megabyte and 77 bytes is 17 frames, the last of 77 bytes
		if host.DecryptByteCount != settings.DecryptByteCount || host.DecryptFrameCount != 17 || host.DecryptMegabytesPerSecond <= 0 {
			t.Errorf("%s decrypted %d B in %d frames at %v MB/s", host.Host, host.DecryptByteCount, host.DecryptFrameCount, host.DecryptMegabytesPerSecond)
		}
		if host.MemorySearches != settings.MemoryQueryCount || host.MemoryFailed != 0 || host.BudgetByteCount <= 0 || host.PeakLabel == "" {
			t.Errorf("%s's memory figure: %+v", host.Host, host)
		}
		more := host.More
		if more == nil || more.Failure != "" || more.AllByteCount == 0 || more.FetchedByteCount < more.AllByteCount || more.FirstFetchMillis <= 0 ||
			more.FirstHitCount == 0 || more.CachedHitCount != more.FirstHitCount {
			t.Errorf("%s's search more: %+v", host.Host, more)
		}
		if host.Quality == nil || host.Quality.Queries != settings.QualityQueryCount || host.Quality.Failed != 0 || host.Quality.PrecisionAtFive <= 0 {
			t.Errorf("%s's quality: %+v", host.Host, host.Quality)
		}
	}
	if _, err := json.Marshal(report); err != nil {
		t.Fatal(err)
	}
}
