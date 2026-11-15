//go:build !ios_extension

package sidecar

// QD-838 through the sync engine's fetch path (search_fetch.go): every record a round keeps carries the 72 B block its
// segment header held, its generation and its file id into the cache, so a file kept in one round reopens in a later
// round under RK_g alone, with no read of evs; and a record the cache kept before it kept them is fetched again by the
// next round, alone and in the fetch order, after which it reopens and no further round fetches it.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// Opens every file a snapshot holds through OpenRecordRead, with gkm's RK_1 as the fake source sealed under, and
// checks each reads back whole to its content_sha256. Answers how many it opened.
func (self *testSyncWorld) assertReopens(t *testing.T, snapshot *SearchSyncSnapshot) int {
	t.Helper()
	gkm := &evsTestReadGkm{newest: 1}
	for _, file := range snapshot.Files() {
		key := SearchCacheKey{RepoId: self.repoId, RefId: self.refId, Path: file.Path, Version: file.Version}
		read, err := self.cache.cache.OpenRecordRead(t.Context(), key, gkm)
		if err != nil {
			t.Fatalf("%s@%d: %v", file.Path, file.Version, err)
		}
		whole, err := testReadThrough(t, read)
		read.Close()
		if err != nil {
			t.Fatalf("%s@%d: %v", file.Path, file.Version, err)
		}
		if sha256.Sum256(whole) != file.ContentSha256 {
			t.Fatalf("%s@%d reads back otherwise", file.Path, file.Version)
		}
	}
	return len(snapshot.Files())
}

// QD-838: a file kept in one round reopens in a later round under RK_g alone. The first round's snapshot, held open
// so the later round's retirement keeps its files, reopens whole after a push and a second round, each file with its
// 72 B block, generation 1 and file id kept, as does the later snapshot.
func TestAKeptFileReopensInALaterRound(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer"), "first", 2)
	world.round(t)
	first := world.snapshot(t)
	world.push(t, evsTestId("second writer"), "second", 2)
	world.round(t)
	later := world.snapshot(t)
	if later.Pin().Version <= first.Pin().Version {
		t.Fatal("the second round did not move past the first")
	}
	if world.assertReopens(t, first) == 0 {
		t.Fatal("the first round kept no file")
	}
	for _, file := range first.Files() {
		frames, err := world.cache.cache.OpenRecord(SearchCacheKey{RepoId: world.repoId, RefId: world.refId, Path: file.Path, Version: file.Version})
		if err != nil {
			t.Fatal(err)
		}
		if len(frames.WrappedObjectKey()) != EvsWrappedKeyByteCount || frames.Generation() != 1 {
			t.Fatalf("%s kept a block of %d bytes at generation %d", file.Path, len(frames.WrappedObjectKey()), frames.Generation())
		}
		if fileId, err := frames.FileId(); err != nil || fileId == (Id{}) {
			t.Fatalf("%s lost its file id: %v", file.Path, err)
		}
	}
	world.assertReopens(t, later)
}

// QD-838: a record the cache kept before it kept the keys that reopen it is fetched again by the next round, though
// the head has not moved: that round's reads ask for it alone, its new copy replaces the one held, the swap keeps one
// version whole, every file then reopens under RK_1, and a third round fetches nothing.
func TestARecordKeptBeforeKeysIsFetchedAgain(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer"), "first", 2)
	world.round(t)
	files := world.snapshot(t).Files()
	if len(files) == 0 {
		t.Fatal("no file kept")
	}
	// the record kept before the keys: the first that is not a small file kept whole in the manifest, else the first
	lacking := files[0]
	for _, file := range files {
		if file.Small == nil {
			lacking = file
			break
		}
	}
	key := SearchCacheKey{RepoId: world.repoId, RefId: world.refId, Path: lacking.Path, Version: lacking.Version}
	world.cache.keptBeforeKeys(t, key, func(meta *searchCacheMetaWire) { meta.WrappedKey, meta.FileId, meta.Generation = nil, "", 0 })
	if _, err := world.cache.cache.OpenRecordRead(t.Context(), key, &evsTestReadGkm{newest: 1}); !errors.Is(err, ErrSearchCacheKeysLacking) {
		t.Fatalf("a record kept before its keys: %v", err)
	}

	before := len(world.source.fetched())
	world.round(t)
	fetched := world.source.fetched()[before:]
	if want := []string{fmt.Sprintf("%s@%d", lacking.Path, lacking.Version)}; !slices.Equal(fetched, want) {
		t.Fatalf("the round fetched %v, not %v", fetched, want)
	}
	after := world.snapshot(t)
	world.assertOneVersion(t, after)
	if world.assertReopens(t, after) != len(files) {
		t.Fatalf("the snapshot holds %d files where it held %d", len(after.Files()), len(files))
	}
	held, err := world.cache.cache.Ref(world.repoId, world.refId)
	if err != nil || held == nil {
		t.Fatalf("held %+v, %v", held, err)
	}
	for _, file := range held.Files {
		if file.Kind == searchCacheKindRecord && !file.KeysKept {
			t.Errorf("%s@%d is still kept without its keys", file.Key.Path, file.Key.Version)
		}
	}

	before = len(world.source.fetched())
	world.round(t)
	if fetched := world.source.fetched()[before:]; len(fetched) != 0 {
		t.Errorf("a third round fetched %v", fetched)
	}
}
