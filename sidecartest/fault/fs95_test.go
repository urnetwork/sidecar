//go:build sidecar_testhooks

// FS-95's M10 case on T2 (EVS2-M10-31): the registered refusals beside their twin, and each further clause (fs95.go)
// under every rule §22.8 gives the row. The world's hand-built pushes go through evs instances a schedule may hold at
// barriers, so this needs the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs95(t *testing.T) {
	RunRow(t, "FS-95", "", nil)
}

func TestFs95Locked(t *testing.T) {
	RunRegisteredClause(t, "FS-95", "locked", nil)
}

func TestFs95Config(t *testing.T) {
	RunRegisteredClause(t, "FS-95", "config", nil)
}

func TestFs95Mailcfg(t *testing.T) {
	RunRegisteredClause(t, "FS-95", "mailcfg", nil)
}

func TestFs95OwnerBound(t *testing.T) {
	RunRegisteredClause(t, "FS-95", "owner-bound", nil)
}

func TestFs95ListMissingAVersion(t *testing.T) {
	RunRegisteredClause(t, "FS-95", "list missing a version", nil)
}

func TestFs95ListAddingAVersion(t *testing.T) {
	RunRegisteredClause(t, "FS-95", "list adding a version", nil)
}
