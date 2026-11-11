//go:build sidecar_testhooks

// FS-63 on T2 (EVS1-M2-41): the registered case under every rule §22.8 gives the row. The schedules hold evs instances
// at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs63(t *testing.T) {
	RunRow(t, "FS-63", "", nil)
}
