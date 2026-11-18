//go:build !ios_extension

// A ref's storage as `ur status` shows it (EVS2-M10-23), against the stand-in evs at format 2: a versionless file's newest
// version's padded size, a versioned file's every version's summed, the paths named as this device names them.

package sidecar

import (
	"bytes"
	"context"
	"testing"
)

func TestEvsStorageStatusCountsVersionlessAndHistory(t *testing.T) {
	writer, server, _ := newEvsTestDropPusher(t)
	ctx := context.Background()
	for i := 0; i < 2; i += 1 {
		content := evsTestEdited("big.txt", 2000, i)
		writer.server.know("big.txt")
		if _, err := writer.repo.Write(ctx, &EvsWriteArgs{
			Path: "big.txt", Content: bytes.NewReader(content), Size: int64(len(content)), Versioning: EvsVersioningOff,
		}); err != nil {
			t.Fatal(err)
		}
	}
	evsTestDropHistory(t, writer, server, "notes.md", 3000, 3)
	evsTestDropHistory(t, writer, server, "small.md", 100, 1)
	status, err := writer.repo.StorageStatus(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status.VersionlessByteCount == 0 || status.IndexByteCount != 0 {
		t.Fatalf("versionless %d, index %d", status.VersionlessByteCount, status.IndexByteCount)
	}
	if len(status.Paths) != 2 || status.Paths[0].Path != "notes.md" || status.Paths[1].Path != "small.md" ||
		status.Paths[0].ByteCount <= status.Paths[1].ByteCount {
		for _, path := range status.Paths {
			t.Logf("path %q: %d bytes", path.Path, path.ByteCount)
		}
		t.Fatalf("the versioned paths: %d, unnamed %d", len(status.Paths), status.UnnamedByteCount)
	}
}
