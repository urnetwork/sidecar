//go:build !sidecar_http && !ios_extension

// BRIDGE-M4-22's schedules on T2 (fs_bridge_m4.go): FS-38's M4 part and its forged case, and FS-56, each under every
// rule §22.8 gives its case. server/controller/connect_bridge_m4_test.go runs the same builders on T3.

package fault

import (
	"testing"
)

func TestFs38(t *testing.T) {
	RunRow(t, "FS-38", "", nil)
}

func TestFs38Forged(t *testing.T) {
	RunRow(t, "FS-38", "forged", nil)
}

func TestFs56(t *testing.T) {
	RunRow(t, "FS-56", "", nil)
}
