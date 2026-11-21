//go:build sidecar_testhooks

package fault

// FS-87's index case on T2 (fs87_index_evs.go): the row's format-2 case under the explorer's seeds, the moderated
// run still running when its writer's card returns, and across that writer's restart (QD-1144); and the same case in
// the dropped-listing order (fs87_index_dropped_evs.go), where later erasures' CUTs drop the moderation from the cards
// ref's erasure set before the writer returns, which the moderation's note holds (QD-1148).

import (
	"testing"
)

func TestFs87Index(t *testing.T) {
	RunRow(t, "FS-87", "index", nil)
}

// The dropped-listing order, fixed and under the explorer's merge seeds, as RunRow runs a case: no catalog case names
// the order, so it runs here beside the registered one, and a failing seed writes no trace to replay as that case's.
func TestFs87IndexDroppedListing(t *testing.T) {
	settings := DefaultRuleSettings()
	settings.WriteTraces = false
	if fixed := runBuilt(t.Context(), Fs87IndexDroppedOnEvs, settings.Net, nil); fixed.Err != nil {
		t.Fatalf("%s", fixed)
	}
	report := Explore(t.Context(), Fs87IndexDroppedOnEvs, settings)
	t.Log(report.String())
	for _, failure := range report.Failures {
		t.Errorf("%s", failure)
	}
}
