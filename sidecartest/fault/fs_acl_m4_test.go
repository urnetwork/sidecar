// ACL-M4-04's schedules on T2 (fs_acl_m4.go): FS-19's grant and share under every rule §22.8 gives their cases.
// server's sidecart3 runs the same registrations on T3, and FS-21 (fs21.go) there alone.

package fault

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs19Grant(t *testing.T) {
	RunRow(t, "FS-19", "grant", nil)
}

func TestFs19Share(t *testing.T) {
	RunRow(t, "FS-19", "share", nil)
}

// FS-21 runs on server's exchange under its contract gate: a Net that names no AclExchangeTier, as T2's names none,
// fails the row at its first step rather than running it on the fake issuer, which seals whatever class a test sets.
func TestFs21RefusesANetWithNoExchangeTier(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	result := Run(t.Context(), Fs21(net), net)
	if result.Err == nil || result.FailedStep != 0 || !strings.Contains(result.Err.Error(), "AclExchangeTier") {
		t.Fatalf("%s", result)
	}
}
