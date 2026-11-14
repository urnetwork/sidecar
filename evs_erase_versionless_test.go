// EVS2-M10-12's root test: SlotKeysOf over a general repo's file names no key, since a general repo's versions name
// no slot and a versionless segment's key rides its header (§11.12's versionless row), and a path that never stood
// names none. The slot-keyed and versionless cases need evs's format-2 checks and its purge, so they run end to end
// in sidecartest/evs_erase_versionless_test.go, and evs's own in evsservice/closure_versionless_test.go.

package sidecar

import (
	"context"
	"testing"
)

func TestEvsSlotKeysOfAGeneralRepoNamesNone(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
	for round := range 2 {
		if _, err := writer.write(t, "index.bin", evsTestContent("index", 64*1024+round)); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := writer.repo.SlotKeysOf(context.Background(), nil, []string{"index.bin"})
	if err != nil || len(keys) != 0 {
		t.Fatalf("a general repo's slot keys: %v %v", keys, err)
	}
}
