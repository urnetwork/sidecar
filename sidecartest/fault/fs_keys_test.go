// FS-15, FS-18, FS-20, FS-22, FS-23, FS-24 and FS-105 on T2 (KEYS-M2-27, KEYS-M2-28): each registered case under every
// rule §22.8 gives its row (fs_keys.go). Without sidecar_testhooks the barriers are no-ops, so the explorer's seeds
// repeat the fixed order; under it they choose who runs at each barrier.

package fault

import (
	"testing"
)

func TestFs15(t *testing.T) {
	RunRow(t, "FS-15", "", nil)
}

func TestFs18(t *testing.T) {
	RunRow(t, "FS-18", "", nil)
}

func TestFs20(t *testing.T) {
	RunRow(t, "FS-20", "", nil)
}

func TestFs22(t *testing.T) {
	RunRow(t, "FS-22", "", nil)
}

func TestFs23(t *testing.T) {
	RunRow(t, "FS-23", "", nil)
}

func TestFs24(t *testing.T) {
	RunRow(t, "FS-24", "", nil)
}

func TestFs105(t *testing.T) {
	RunRow(t, "FS-105", "", nil)
}
