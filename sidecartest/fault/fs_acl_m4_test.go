// ACL-M4-04's schedules on T2 (fs_acl_m4.go): FS-19's grant and share under every rule §22.8 gives their cases.
// server's sidecart3 runs the same registrations on T3.

package fault

import (
	"testing"
)

func TestFs19Grant(t *testing.T) {
	RunRow(t, "FS-19", "grant", nil)
}

func TestFs19Share(t *testing.T) {
	RunRow(t, "FS-19", "share", nil)
}
