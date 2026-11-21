package fault

// FS-47 on T2 (EVSB-M2-15): the registered case and the clause of fs47.go, each under every rule §22.8 gives the row, on
// evs's QuotaGate over the Net's fake Quota. No schedule here holds a barrier, so these run on both legs.

import (
	"testing"
)

func TestFs47(t *testing.T) {
	RunRow(t, "FS-47", "", nil)
}

func TestFs47OneEraserKeepsItsOwnRate(t *testing.T) {
	RunRegisteredClause(t, "FS-47", "one eraser keeps its own rate", nil)
}
