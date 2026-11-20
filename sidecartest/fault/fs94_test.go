//go:build sidecar_testhooks

// FS-94 on T2 (EVS2-M10-31): the shared inline record in a general repo, the registered case, and its record-class
// twin (fs94.go), under every rule §22.8 gives the row.

package fault

import "testing"

func TestFs94(t *testing.T) {
	RunRow(t, "FS-94", "", nil)
}

func TestFs94RecordClass(t *testing.T) {
	RunRegisteredClause(t, "FS-94", "record class", nil)
}
