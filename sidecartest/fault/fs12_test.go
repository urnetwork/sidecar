//go:build sidecar_testhooks

// FS-12 on T2 (EVS1-M2-41): the registered case under every rule §22.8 gives the row. Its subscriber's rounds run
// through the root's sidecar_testhooks seam, and its instances hold at barriers, so it needs the tag.

package fault

import (
	"testing"
)

func TestFs12(t *testing.T) {
	RunRow(t, "FS-12", "", nil)
}
