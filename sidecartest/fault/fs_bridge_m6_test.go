//go:build !sidecar_http && !ios_extension

// BRIDGE-M6-08's schedules on T2 (fs_bridge_m6.go): FS-38's share rows, under every rule §22.8 gives the case;
// server/controller/connect_bridge_m6_test.go runs the same builders on T3.

package fault

import (
	"testing"
)

func TestFs38Share(t *testing.T) {
	RunRow(t, "FS-38", "shares", nil)
}
