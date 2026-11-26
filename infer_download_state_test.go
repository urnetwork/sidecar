//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Stops a download at chunk stop with chunks 0 to stop-1 done, fetching one chunk at a time: the api drops the
// connection there and is gone after it, and there is no fallback. It answers the api's chunk requests of the run.
func testInferStopAt(t *testing.T, world *testInferDownloadWorld, download *InferModelDownload, stop int) map[int]int {
	t.Helper()
	concurrency := world.settings.ModelChunkFetchConcurrency
	fallback := world.settings.ModelHubFallback
	world.settings.ModelChunkFetchConcurrency = 1
	world.settings.ModelHubFallback = false
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk "+strconv.Itoa(stop) && attempt == 1 {
			world.apiRefused.Store(true)
			return testInferDownloadDrop
		}
		return testInferDownloadServe
	})
	if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("a download stopped at chunk %d answered %v", stop, err)
	}
	world.apiRefused.Store(false)
	world.setAnswer(nil)
	counts := world.chunkCounts("api")
	world.resetCounts()
	world.settings.ModelChunkFetchConcurrency = concurrency
	world.settings.ModelHubFallback = fallback
	if done := world.doneChunks(t, world.directory); !slices.Equal(done, testInferRange(0, stop-1)) {
		t.Fatalf("done before the stop: %v", done)
	}
	return counts
}

// A torn last record in the done list is ignored and its chunk fetched again, and a record of another index is ignored
// though whole; the records before them stand, and the list goes on at a record's boundary.
func TestModelDownloadTornDoneRecordIgnored(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	download := world.newDownload(t, world.directory)
	testInferStopAt(t, world, download, 5)
	paths := newInferModelFilePaths(world.directory, world.file.Sha256)
	info, err := os.Stat(paths.done)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 5*inferModelDoneRecordByteCount {
		t.Fatalf("the done list holds %d bytes for 5 chunks", info.Size())
	}
	// chunk 4's record torn
	if err := os.Truncate(paths.done, info.Size()-5); err != nil {
		t.Fatal(err)
	}
	if done := world.doneChunks(t, world.directory); !slices.Equal(done, testInferRange(0, 3)) {
		t.Fatalf("with chunk 4's record torn, the list reads %v", done)
	}

	// the resume fetches chunk 4 again and writes on at a record's boundary, so the list reads whole when it stops again
	resumed := testInferStopAt(t, world, download, 7)
	if asked, once := testInferAskedOnce(resumed); !slices.Equal(asked, testInferRange(4, 7)) || resumed[7] != 1 || !once {
		t.Fatalf("the resume asked for %v", resumed)
	}
	if info, err := os.Stat(paths.done); err != nil || info.Size() != 7*inferModelDoneRecordByteCount {
		t.Fatalf("after the resume the done list is %v, %v", info, err)
	}
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if asked, once := testInferAskedOnce(world.chunkCounts("api")); !slices.Equal(asked, testInferRange(7, 10)) || !once {
		t.Fatalf("the last resume asked for %v", world.chunkCounts("api"))
	}

	// a whole record of another index's pin marks nothing
	forged := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	download = forged.newDownload(t, forged.directory)
	testInferStopAt(t, forged, download, 3)
	forgedPaths := newInferModelFilePaths(forged.directory, forged.file.Sha256)
	records, err := os.ReadFile(forgedPaths.done)
	if err != nil {
		t.Fatal(err)
	}
	other := [32]byte{}
	copy(other[:], "another index pin, not this one.")
	records = append(records, inferModelDoneRecord(other, 7)...)
	if err := os.WriteFile(forgedPaths.done, records, 0o600); err != nil {
		t.Fatal(err)
	}
	if done := forged.doneChunks(t, forged.directory); !slices.Equal(done, testInferRange(0, 2)) {
		t.Fatalf("with another index's record, the list reads %v", done)
	}
	file, err = download.Fetch(context.Background(), forged.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	forged.assertWhole(t, file)
	if asked, once := testInferAskedOnce(forged.chunkCounts("api")); !slices.Equal(asked, testInferRange(3, 10)) || !once {
		t.Fatalf("the resume asked for %v", forged.chunkCounts("api"))
	}
}

// A whole file whose modification time changed is checked again chunk by chunk and, every chunk passing, opens and is
// marked anew; one whose chunk changed goes back to its part with that chunk not done, refusing to open, and a fetch
// takes that chunk alone; one cut short, or grown, likewise, the chunks it no longer holds whole fetched again.
func TestModelDownloadRechecksChangedSizeOrMtime(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	paths := newInferModelFilePaths(world.directory, world.file.Sha256)
	stamp := time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC)
	touch := func() {
		t.Helper()
		stamp = stamp.Add(time.Hour)
		if err := os.Chtimes(paths.whole, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}

	// its time alone: checked, passing, opened and marked with the new time
	touch()
	world.assertWhole(t, file)
	mark := file.readMark()
	if mark == nil || mark.ModTimeUnixNano != stamp.UnixNano() {
		t.Fatalf("the mark after a check reads %+v", mark)
	}

	// a chunk changed
	whole, err := os.OpenFile(paths.whole, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := whole.WriteAt([]byte{world.content[2*1024+10] ^ 0xff}, 2*1024+10); err != nil {
		t.Fatal(err)
	}
	whole.Close()
	touch()
	if _, err := file.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) || !strings.Contains(err.Error(), "chunk 2") {
		t.Fatalf("a whole file with a chunk changed answered %v", err)
	}
	if _, err := os.Stat(paths.whole); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a file whose chunk changed stayed whole")
	}
	if done := world.doneChunks(t, world.directory); !slices.Equal(done, []int{0, 1, 3, 4, 5, 6, 7, 8, 9, 10}) {
		t.Fatalf("back in its part, the list reads %v", done)
	}
	world.resetCounts()
	if file, err = download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if asked, once := testInferAskedOnce(world.chunkCounts("api")); !slices.Equal(asked, []int{2}) || !once {
		t.Fatalf("after a changed chunk the fetch asked for %v", world.chunkCounts("api"))
	}

	// cut short in chunk 7
	if err := os.Truncate(paths.whole, 7*1024+10); err != nil {
		t.Fatal(err)
	}
	touch()
	if _, err := file.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) {
		t.Fatalf("a whole file cut short answered %v", err)
	}
	world.resetCounts()
	if file, err = download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if asked, once := testInferAskedOnce(world.chunkCounts("api")); !slices.Equal(asked, testInferRange(7, 10)) || !once {
		t.Fatalf("after a cut the fetch asked for %v", world.chunkCounts("api"))
	}

	// grown past its size: every chunk passes, and the fetch asks nothing
	grown, err := os.OpenFile(paths.whole, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grown.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	grown.Close()
	touch()
	if _, err := file.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) || !strings.Contains(err.Error(), "size") {
		t.Fatalf("a whole file grown answered %v", err)
	}
	world.resetCounts()
	if file, err = download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if len(world.chunkCounts("api")) != 0 || world.countOf("api index") != 0 {
		t.Fatalf("after a growth the fetch asked for %v", world.counts)
	}
}

// A whole file that changed with no index kept to check it opens nothing until a fetch takes the index and checks it.
func TestModelDownloadChangedFileWithoutIndexWaitsForFetch(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4*1024+10, 1024)
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	paths := newInferModelFilePaths(world.directory, world.file.Sha256)
	if err := os.Remove(paths.index); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, time.November, 25, 13, 0, 0, 0, time.UTC)
	if err := os.Chtimes(paths.whole, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := file.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) {
		t.Fatalf("a changed file with no index answered %v", err)
	}
	world.resetCounts()
	if file, err = download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if world.countOf("api index") != 1 || len(world.chunkCounts("api")) != 0 {
		t.Fatalf("the check asked for %v", world.counts)
	}
}

// Remove deletes every state of a file, its part and done list or its whole file and mark, and its kept index, and
// waits for a fetch of it to end.
func TestModelDownloadRemoveDeletesEveryState(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	download := world.newDownload(t, world.directory)
	testInferStopAt(t, world, download, 4)
	file, err := download.File(world.file)
	if err != nil {
		t.Fatal(err)
	}
	listed := func() []string {
		t.Helper()
		entries, err := os.ReadDir(world.directory)
		if err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		return names
	}
	if len(listed()) == 0 {
		t.Fatal("a stopped download left nothing")
	}
	if err := file.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if names := listed(); len(names) != 0 {
		t.Fatalf("after Remove the directory holds %v", names)
	}
	if file, err = download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	if err := file.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if names := listed(); len(names) != 0 {
		t.Fatalf("after Remove of a whole file the directory holds %v", names)
	}
	if _, err := file.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) {
		t.Fatalf("a removed file answered %v", err)
	}

	// a removal waits for the fetch that holds the file's slot
	release, ok := download.tryTakeSlot(world.file.Sha256)
	if !ok {
		t.Fatal("the file's slot is held")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := file.Remove(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("a removal while the slot is held answered %v", err)
	}
	release()
}

// What a crash after the whole mark and before the rename leaves, a mark and a part, opens nothing, and a fetch makes
// it whole with no chunk asked for; a crash after the rename and before the cleanup leaves a whole file, whose stale
// part a fetch removes.
func TestModelDownloadCrashAroundWholeMark(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4*1024+10, 1024)
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	paths := newInferModelFilePaths(world.directory, world.file.Sha256)
	// back to a part with every chunk done and its mark written, as a crash before the rename would leave it
	if err := os.Rename(paths.whole, paths.part); err != nil {
		t.Fatal(err)
	}
	records := []byte{}
	for n := 0; n < world.index.ChunkCount(); n += 1 {
		records = append(records, inferModelDoneRecord(file.pinDigest, n)...)
	}
	if err := os.WriteFile(paths.done, records, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.mark); err != nil {
		t.Fatal(err)
	}
	if _, err := file.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) {
		t.Fatalf("a part beside its mark answered %v", err)
	}
	world.resetCounts()
	if file, err = download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if len(world.chunkCounts("api")) != 0 || world.countOf("api index") != 0 {
		t.Fatalf("finishing a marked part asked for %v", world.counts)
	}

	// a stale part and list beside a whole file are removed by the next fetch
	if err := os.WriteFile(paths.part, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.done, records, 0o600); err != nil {
		t.Fatal(err)
	}
	if file, err = download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	for _, path := range []string{paths.part, paths.done} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a stale %s stayed beside the whole file", path)
		}
	}
}
