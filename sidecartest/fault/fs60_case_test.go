//go:build sidecar_testhooks

// FS-60 on T2 (EVSB-M2-11): the registered case and the clauses of fs60.go, each under every rule §22.8 gives the
// row. The pending-record clause holds an evs instance at its head CAS, so these need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs60(t *testing.T) {
	RunRow(t, "FS-60", "", nil)
}

func TestFs60PendingRecordFencedThenDropped(t *testing.T) {
	RunRegisteredClause(t, "FS-60", "pending record fenced then dropped", nil)
}

func TestFs60ParcelsPackAtSevenDays(t *testing.T) {
	RunRegisteredClause(t, "FS-60", "parcels pack at seven days", nil)
}
