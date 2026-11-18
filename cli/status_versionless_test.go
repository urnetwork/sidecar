// `ur status`'s versionless lines (EVS2-M10-23): a fixture repo's lines carry its bytes and the person's own path names,
// and the daemon with no evs client says so in one line.

package main

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestStatusVersionlessLines(t *testing.T) {
	repoId, refId := sidecar.NewId(), sidecar.NewId()
	lines := strings.Join(sidecar.EvsStorageStatusLines(repoId, &sidecar.EvsStorageStatus{
		RefId: refId, VersionlessByteCount: 65536, IndexByteCount: 4096,
		Paths:            []*sidecar.EvsStoragePath{{Path: "models/big.bin", ByteCount: 9000000}, {Path: "notes.md", ByteCount: 4000}},
		UnnamedByteCount: 77,
	}), "\n")
	for _, want := range []string{"65536 bytes of versionless files, 4096 bytes of search index", "9000000 bytes of history: models/big.bin",
		"4000 bytes of history: notes.md", "77 bytes of history in paths this device cannot name"} {
		if !strings.Contains(lines, want) {
			t.Errorf("the lines do not show %q:\n%s", want, lines)
		}
	}
	if urDaemonVersionless != nil {
		t.Fatalf("a composition set the seam in a test binary")
	}
}
