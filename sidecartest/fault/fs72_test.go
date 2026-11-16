//go:build sidecar_testhooks

// FS-72's M10 cases on T2 (EVS2-M10-30): the migration and rollback cases under every rule §22.8 gives the row, and
// the migration killed at each of its push's steps (fs72.go) under the same rules. The schedules hold evs instances
// at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/evsservice"
)

func TestFs72Migration(t *testing.T) {
	RunRow(t, "FS-72", "migration", nil)
}

func TestFs72Rollback(t *testing.T) {
	RunRow(t, "FS-72", "rollback", nil)
}

func TestFs72MigrationKilledAtStepSix(t *testing.T) {
	RunClause(t, "FS-72", "migration killed after step 6", Fs72MigrationKilledAt(evsservice.BarrierPushStep6After), nil)
}

func TestFs72MigrationKilledBeforeTheRaise(t *testing.T) {
	RunClause(t, "FS-72", "migration killed before the raise", Fs72MigrationKilledAt(evsservice.BarrierMigrateRaiseBefore), nil)
}

func TestFs72MigrationKilledAfterTheRaise(t *testing.T) {
	RunClause(t, "FS-72", "migration killed after the raise", Fs72MigrationKilledAt(evsservice.BarrierMigrateRaiseAfter), nil)
}

func TestFs72MigrationKilledBeforeTheHeadCas(t *testing.T) {
	RunClause(t, "FS-72", "migration killed before the head CAS", Fs72MigrationKilledAt(evsservice.BarrierHeadCasBefore), nil)
}

func TestFs72MigrationKilledAfterTheHeadCas(t *testing.T) {
	RunClause(t, "FS-72", "migration killed after the head CAS", Fs72MigrationKilledAt(evsservice.BarrierHeadCasAfter), nil)
}
