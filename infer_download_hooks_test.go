//go:build sidecar_testhooks && !ios_extension && !sidecar_http

// The download's crash points, on its barriers: what a crash at each would leave, copied while the download is held
// there, then resumed by a new download.

package sidecar

import (
	"context"
	"os"
	"slices"
	"sync"
	"testing"
)

// A crash between a chunk's sync and its mark, its bytes in the part and no record of them, fetches that chunk again
// on the restart and gives the file whole and correct.
func TestModelDownloadCrashBetweenSyncAndMark(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.settings.ModelChunkFetchConcurrency = 1
	crash := t.TempDir()
	key := world.file.Sha256 + ":3"
	copied := make(chan error, 1)
	once := sync.Once{}
	SetTestHooks(&TestHooks{
		Barrier: func(name string, barrierKey string) {
			if name == "infer_download.chunk.synced" && barrierKey == key {
				once.Do(func() {
					copied <- testInferCopyFiles(world.directory, crash)
				})
			}
		},
	})
	t.Cleanup(func() {
		SetTestHooks(nil)
	})
	download := world.newDownload(t, world.directory)
	if _, err := download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-copied; err != nil {
		t.Fatal(err)
	}
	SetTestHooks(nil)

	// the crash's state: chunk 3 synced in the part, chunks 0 to 2 marked
	if done := world.doneChunks(t, crash); !slices.Equal(done, testInferRange(0, 2)) {
		t.Fatalf("at the crash the list reads %v", done)
	}
	part, err := os.ReadFile(newInferModelFilePaths(crash, world.file.Sha256).part)
	if err != nil {
		t.Fatal(err)
	}
	chunk, _ := world.index.Chunk(3)
	if !chunk.Matches(part[chunk.Offset : chunk.Offset+chunk.ByteCount]) {
		t.Fatal("at the crash chunk 3's bytes are not in the part")
	}

	world.resetCounts()
	restarted := world.newDownload(t, crash)
	file, err := restarted.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if asked, once := testInferAskedOnce(world.chunkCounts("api")); !slices.Equal(asked, testInferRange(3, 10)) || !once {
		t.Fatalf("the restart asked for %v", world.chunkCounts("api"))
	}
}

// A crash after the whole mark and before the rename leaves a part beside its mark, which opens nothing, and which the
// restart makes whole asking nothing.
func TestModelDownloadCrashAfterWholeMark(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4*1024+10, 1024)
	crash := t.TempDir()
	copied := make(chan error, 1)
	SetTestHooks(&TestHooks{
		Barrier: func(name string, barrierKey string) {
			if name == "infer_download.whole.marked" && barrierKey == world.file.Sha256 {
				copied <- testInferCopyFiles(world.directory, crash)
			}
		},
	})
	t.Cleanup(func() {
		SetTestHooks(nil)
	})
	download := world.newDownload(t, world.directory)
	if _, err := download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-copied; err != nil {
		t.Fatal(err)
	}
	SetTestHooks(nil)

	restarted := world.newDownload(t, crash)
	crashed, err := restarted.File(world.file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crashed.OpenWhole(context.Background()); err == nil {
		t.Fatal("a part beside its mark opened")
	}
	world.resetCounts()
	file, err := restarted.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if len(world.chunkCounts("api")) != 0 || world.countOf("api index") != 0 {
		t.Fatalf("the restart asked for %v", world.counts)
	}
}
