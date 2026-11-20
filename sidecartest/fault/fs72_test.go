//go:build sidecar_testhooks

// FS-72's M10 cases on T2 (EVS2-M10-30): the migration and rollback cases under every rule §22.8 gives the row, and
// the migration killed at each of its push's steps (fs72.go) under the same rules. The schedules hold evs instances
// at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs72Migration(t *testing.T) {
	RunRow(t, "FS-72", "migration", nil)
}

func TestFs72Rollback(t *testing.T) {
	RunRow(t, "FS-72", "rollback", nil)
}

func TestFs72MigrationMigrationKilledAfterStep6(t *testing.T) {
	RunRegisteredClause(t, "FS-72", "migration killed after step 6", nil)
}

func TestFs72MigrationMigrationKilledBeforeTheRaise(t *testing.T) {
	RunRegisteredClause(t, "FS-72", "migration killed before the raise", nil)
}

func TestFs72MigrationMigrationKilledAfterTheRaise(t *testing.T) {
	RunRegisteredClause(t, "FS-72", "migration killed after the raise", nil)
}

func TestFs72MigrationMigrationKilledBeforeTheHeadCas(t *testing.T) {
	RunRegisteredClause(t, "FS-72", "migration killed before the head CAS", nil)
}

func TestFs72MigrationMigrationKilledAfterTheHeadCas(t *testing.T) {
	RunRegisteredClause(t, "FS-72", "migration killed after the head CAS", nil)
}
