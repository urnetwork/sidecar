//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package bench

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The remote row at reduced scale on T2's tier: pre-warmed and cold taps with their compute apart, the indexers'
// service time, and two requesters' load beside the indexer's own searches, every field given; a run at this scale is a
// smoke.
func TestRemoteBenchGivesTheRowsFieldsAtReducedScale(t *testing.T) {
	settings := DefaultRemoteBenchSettings()
	settings.Corpus.Days = 40
	settings.Corpus.MessagesPerDay = 3
	settings.Corpus.VocabularyCount = 1000
	settings.Corpus.RareWordCount = 8
	settings.Corpus.BodyWordCount = 20
	settings.TapCount = 6
	settings.RequesterCount = 2
	settings.RequesterSearchCount = 2
	settings.LocalSearchCount = 6
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	report, err := RunRemoteBench(context.Background(), settings, tier)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Smoke || report.MessageCount != settings.Corpus.Days*settings.Corpus.MessagesPerDay {
		t.Fatalf("smoke %v, %d messages", report.Smoke, report.MessageCount)
	}
	for name, tap := range map[string]*RemoteBenchTap{"first": report.First, "cold": report.Cold} {
		if tap == nil || tap.Tap.Failed != 0 || tap.Tap.LatencyMillis.Count == 0 || tap.ComputeMillis.Count != tap.Tap.LatencyMillis.Count {
			t.Errorf("%s: %+v", name, tap)
		}
	}
	if report.Cold.Tap.LatencyMillis.Count != int64(settings.RequesterCount) {
		t.Errorf("%d cold taps for %d requesters", report.Cold.Tap.LatencyMillis.Count, settings.RequesterCount)
	}
	if report.ServiceMillis.Count == 0 || report.LoadSearches != int64(settings.RequesterCount*settings.RequesterSearchCount) || report.LoadFailed != 0 {
		t.Errorf("service %+v, load %d searches, %d failed", report.ServiceMillis, report.LoadSearches, report.LoadFailed)
	}
	if report.Local == nil || report.Local.Queries != settings.LocalSearchCount || report.Local.Failed != 0 {
		t.Errorf("local: %+v", report.Local)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", encoded)
}
