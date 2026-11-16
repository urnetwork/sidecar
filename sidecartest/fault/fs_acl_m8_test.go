//go:build !sidecar_http && !ios_extension

// ACL-M8-01's schedules on T2 (fs_acl_m8.go): FS-19's quick-burner case under every rule §22.8 gives it, and FS-85's acl
// wakes as a clause beside RECORD-M8-01's wakes case. server's sidecart3 runs FS-19's registration on T3 (TestT3Rows).

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs19QuickBurner(t *testing.T) {
	RunRow(t, "FS-19", "quick-burner", nil)
}

func TestFs85AclWakes(t *testing.T) {
	RunClause(t, "FS-85", "acl wakes", Fs85AclWakes, nil)
}

// FS-85's acl wakes run outside the registry, which TestEveryRegisteredActorFitsATrace walks: each actor is one word,
// so a failing seed's trace replays.
func TestAclM8WakeActorsFitATrace(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	expectActorsFitATrace(t, "FS-85's acl wakes", Fs85AclWakes(net))
}
