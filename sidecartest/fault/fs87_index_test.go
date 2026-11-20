//go:build sidecar_testhooks

package fault

// FS-87's index case on T2 (fs87_index_evs.go): the row's format-2 case under the explorer's seeds, the moderated
// run still running when its writer's card returns, and across that writer's restart (QD-1144).

import (
	"testing"
)

func TestFs87Index(t *testing.T) {
	RunRow(t, "FS-87", "index", nil)
}
