//go:build sidecar_testhooks

// FS-91's races (a) and (b) on T2 (EVS2-M10-31): the reuse copy released after the DROP beside its twin, the copy
// released before it (fs91.go), under every rule §22.8 gives the row. The schedules hold an evs instance at a barrier,
// so this needs the sidecar_testhooks tag.

package fault

import "testing"

func TestFs91(t *testing.T) {
	RunRow(t, "FS-91", "", nil)
}
