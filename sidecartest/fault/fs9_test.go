//go:build sidecar_testhooks

// FS-9 on T2 (EVS1-M2-41): the registered case under every rule §22.8 gives the row. The schedules run the evs
// world's instances under the barrier driver, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs9(t *testing.T) {
	RunRow(t, "FS-9", "", nil)
}
