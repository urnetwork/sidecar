package sidecar

// CORE-M10-01: §5.9's index cache keeps a file only once its plaintext is its entry version's content_sha256, keeps no
// query, drops and refetches a file that fails AEAD, reads one frame at a time, and drops decoded state and cursors at a
// lock.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A cache over a fresh instance's network on the memory backend, whose backend a test reads and damages.
type testSearchCacheWorld struct {
	backend   SidecarStoreBackend
	instance  *SidecarInstance
	networkId Id
	settings  *SidecarSearchSettings
	clock     *identityTestClock
	cache     *SearchCache
}

func newTestSearchCacheWorld(t *testing.T, cacheByteCount int64) *testSearchCacheWorld {
	t.Helper()
	backend := NewSidecarMemoryBackend()
	instance := newInstanceOn(t, backend, newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	networkId := NewId()
	if _, err := instance.createKeychain(networkId); err != nil {
		t.Fatal(err)
	}
	settings := DefaultSidecarSettings().Search
	settings.CacheByteCount = cacheByteCount
	clock := newIdentityTestClock()
	cache, err := NewSearchCache(context.Background(), instance.Store(&networkId), settings, clock, NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.Close)
	return &testSearchCacheWorld{backend: backend, instance: instance, networkId: networkId, settings: settings, clock: clock, cache: cache}
}

// An index file's record, sealed as evs seals one, with what opens it.
type testSearchRecord struct {
	record    *SearchCacheRecord
	plaintext []byte
}

func newTestSearchRecord(t *testing.T, key SearchCacheKey, partition SearchCachePartition, plaintext []byte) *testSearchRecord {
	t.Helper()
	manifestKey, err := NewEvsManifestKey(evsTestRepoKey(key.RepoId, 1))
	if err != nil {
		t.Fatal(err)
	}
	objectKey := NewEvsObjectKey()
	fileId := NewId()
	sealed, header := evsTestWriteRecord(t, manifestKey, objectKey, fileId, evsTestHeader(key.Path, protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, len(plaintext)), plaintext)
	return &testSearchRecord{
		plaintext: plaintext,
		record: &SearchCacheRecord{
			Key:           key,
			RefVersion:    9,
			ContentSha256: sha256.Sum256(plaintext),
			Partition:     partition,
			SealedHeader:  sealed[:EvsRecordHeaderByteCount],
			SealedFrames:  sealed[EvsRecordHeaderByteCount:],
			Header:        &header,
			ObjectKey:     objectKey,
			FileId:        fileId,
		},
	}
}

// A plaintext of byteCount bytes no other file shares.
func testSearchPlaintext(label string, byteCount int) []byte {
	plaintext := make([]byte, byteCount)
	seed := sha256.Sum256([]byte(label))
	for i := range plaintext {
		plaintext[i] = seed[i%len(seed)] ^ byte(i/len(seed))
	}
	return plaintext
}

// Every backend path under this network's search directory.
func (self *testSearchCacheWorld) searchPaths(t *testing.T) []string {
	t.Helper()
	entries, err := self.backend.List("")
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{}
	for _, entry := range entries {
		if strings.Contains(entry.Name, "/search/") {
			paths = append(paths, entry.Name)
		}
	}
	return paths
}

// Reads a kept record whole, frame by frame, under its keys.
func testReadKeptRecord(t *testing.T, cache *SearchCache, record *SearchCacheRecord) ([]byte, error) {
	t.Helper()
	frames, err := cache.OpenRecord(record.Key)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(frames.SealedHeader(), record.SealedHeader) {
		t.Error("the sealed header came back changed")
	}
	whole := []byte{}
	for index := 0; int64(index)*EvsRecordFrameByteCount < frames.Length() || index == 0; index += 1 {
		frame, err := frames.ReadFrame(index, record.Header, record.ObjectKey, record.FileId, nil)
		if err != nil {
			return nil, err
		}
		whole = append(whole, frame...)
	}
	return whole, nil
}

// §5.9's holds row: a record is kept only once every frame opens and its plaintext hashes to its entry version's
// content_sha256; otherwise nothing reaches the medium. A kept one reads back a frame at a time.
func TestKeptOnlyAfterContentSha256(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/a/0", Version: 3}
	plaintext := testSearchPlaintext("shard", 3*EvsRecordFrameByteCount/2)

	wrongSum := newTestSearchRecord(t, key, SearchCachePartition{All: true}, plaintext)
	wrongSum.record.ContentSha256[0] ^= 1
	if err := world.cache.PutRecord(t.Context(), wrongSum.record); !errors.Is(err, ErrSearchCacheContent) {
		t.Errorf("a wrong content_sha256: %v", err)
	}
	tampered := newTestSearchRecord(t, key, SearchCachePartition{All: true}, plaintext)
	tampered.record.SealedFrames = bytes.Clone(tampered.record.SealedFrames)
	tampered.record.SealedFrames[EvsRecordFrameByteCount+20] ^= 1
	if err := world.cache.PutRecord(t.Context(), tampered.record); !errors.Is(err, ErrSearchCacheContent) {
		t.Errorf("a tampered frame: %v", err)
	}
	cut := newTestSearchRecord(t, key, SearchCachePartition{All: true}, plaintext)
	cut.record.SealedFrames = cut.record.SealedFrames[:len(cut.record.SealedFrames)-1]
	if err := world.cache.PutRecord(t.Context(), cut.record); !errors.Is(err, ErrSearchCacheContent) {
		t.Errorf("a cut record: %v", err)
	}
	if paths := world.searchPaths(t); len(paths) != 0 {
		t.Fatalf("refused records left %v", paths)
	}
	if ref, err := world.cache.Ref(key.RepoId, key.RefId); err != nil || ref != nil {
		t.Fatalf("a refused record is held: %+v, %v", ref, err)
	}

	good := newTestSearchRecord(t, key, SearchCachePartition{All: true}, plaintext)
	if err := world.cache.PutRecord(t.Context(), good.record); err != nil {
		t.Fatal(err)
	}
	read, err := testReadKeptRecord(t, world.cache, good.record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read, plaintext) {
		t.Error("the kept record reads back otherwise")
	}
	ref, err := world.cache.Ref(key.RepoId, key.RefId)
	if err != nil || ref == nil || len(ref.Files) != 1 || ref.Files[0].ContentSha256 != good.record.ContentSha256 || ref.RefVersion != 9 {
		t.Fatalf("held %+v, %v", ref, err)
	}
	// the record stays as evs sealed it: nothing of its plaintext is on the medium, sealed locally or not
	for _, path := range world.searchPaths(t) {
		reader, err := world.backend.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(reader)
		reader.Close()
		if bytes.Contains(raw, plaintext[:64]) {
			t.Errorf("%s holds plaintext", path)
		}
	}
}

// R-CORE-18, §5.9's never row: nothing a search asks or finds reaches the store. Under a canary query, a search's
// calls (marking a partition searched, reading frames, decoding, a cursor) write nothing, every part but the closed list
// is refused, and no backend byte or sealed file's plaintext holds the canary in any encoding.
func TestNoQueryOnDisk(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	canary := "q-canary-7f3a9c-zebra"
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20000/0", Version: 1}
	kept := newTestSearchRecord(t, key, SearchCachePartition{StartDay: 20000}, testSearchPlaintext("bucket", 4096))
	if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	if err := world.cache.PutDerived(t.Context(), &SearchCacheDerived{Key: key, Part: SearchCachePartBlockIndex, Plaintext: []byte("blocks")}); err != nil {
		t.Fatal(err)
	}
	before := backendSnapshot(t, world.backend)

	// a search under the canary: the cache is asked only what a sync state names, never the query
	world.cache.MarkSearched(key.RepoId, key.RefId, SearchCachePartition{StartDay: 20000})
	if _, err := testReadKeptRecord(t, world.cache, kept.record); err != nil {
		t.Fatal(err)
	}
	if _, err := world.cache.Decoded(SearchDecodedKey{Key: key, Part: string(SearchCachePartBlockIndex)}, func() (any, int64, error) {
		return []string{"decoded", canary}, 64, nil
	}); err != nil {
		t.Fatal(err)
	}
	end := world.cache.AddCursor(func() {})
	end()
	if after := backendSnapshot(t, world.backend); len(after) != len(before) {
		t.Errorf("a search wrote %d files", len(after)-len(before))
	} else {
		for path, content := range before {
			if !bytes.Equal(after[path], content) {
				t.Errorf("a search rewrote %s", path)
			}
		}
	}
	for _, part := range []SearchCachePart{"query", "hits", "snippet", "cursor", "results", "verdict"} {
		err := world.cache.PutDerived(t.Context(), &SearchCacheDerived{Key: key, Part: part, Plaintext: []byte(canary)})
		if !errors.Is(err, ErrSearchCacheUnnamed) {
			t.Errorf("part %q: %v", part, err)
		}
	}

	encodings := []string{canary, hex.EncodeToString([]byte(canary)), base64.StdEncoding.EncodeToString([]byte(canary)),
		base64.RawURLEncoding.EncodeToString([]byte(canary))}
	store, err := world.instance.Store(&world.networkId).Directory(sidecarSearchCacheDir, SidecarSearchFileClass)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := store.List("")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		reader, err := store.Open(entry.Name)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, encoding := range encodings {
			if bytes.Contains(plaintext, []byte(encoding)) || strings.Contains(entry.Name, encoding) {
				t.Errorf("%s holds the canary", entry.Name)
			}
		}
	}
	for path, raw := range backendSnapshot(t, world.backend) {
		for _, encoding := range encodings {
			if bytes.Contains(raw, []byte(encoding)) || strings.Contains(path, encoding) {
				t.Errorf("%s holds the canary", path)
			}
		}
	}
}

// Flips a byte past the seal header of the one backend file whose path ends in suffix.
func (self *testSearchCacheWorld) damage(t *testing.T, suffix string) {
	t.Helper()
	for _, path := range self.searchPaths(t) {
		if !strings.HasSuffix(path, suffix) {
			continue
		}
		reader, err := self.backend.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(reader)
		reader.Close()
		content[len(content)-5] ^= 1
		if err := writeBackendFile(self.backend, path, content); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("no kept file ends in %s", suffix)
}

// §5.9's rebuild row: everything here but state is derived, so a kept frame that fails AEAD drops the file, which the
// caller fetches again, where the keychain's would be Failed; a damaged derived part goes the same way.
func TestAeadFailureRefetches(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/a/1", Version: 2}
	kept := newTestSearchRecord(t, key, SearchCachePartition{All: true}, testSearchPlaintext("all", 2*EvsRecordFrameByteCount))
	if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	if err := world.cache.PutDerived(t.Context(), &SearchCacheDerived{Key: key, Part: SearchCachePartDocCounts, Plaintext: []byte("n_d")}); err != nil {
		t.Fatal(err)
	}
	world.damage(t, "/record/1")
	if _, err := testReadKeptRecord(t, world.cache, kept.record); !errors.Is(err, ErrSearchCacheRefetch) {
		t.Fatalf("a damaged frame: %v", err)
	}
	if ref, err := world.cache.Ref(key.RepoId, key.RefId); err != nil || (ref != nil && len(ref.Files) != 0) {
		t.Errorf("the damaged file is still held: %+v, %v", ref, err)
	}
	if paths := world.searchPaths(t); len(paths) != 1 || !strings.HasSuffix(paths[0], "/holdings") {
		t.Errorf("the dropped file left %v", paths)
	}
	// fetched again, it is kept again
	if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	if _, err := testReadKeptRecord(t, world.cache, kept.record); err != nil {
		t.Fatal(err)
	}

	if err := world.cache.PutDerived(t.Context(), &SearchCacheDerived{Key: key, Part: SearchCachePartBlockIndex, Plaintext: testSearchPlaintext("blocks", 100)}); err != nil {
		t.Fatal(err)
	}
	world.damage(t, "/blocks/0")
	frames, err := world.cache.OpenDerived(key, SearchCachePartBlockIndex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := frames.ReadFrame(0); !errors.Is(err, ErrSearchCacheRefetch) {
		t.Errorf("a damaged derived frame: %v", err)
	}
	if _, err := world.cache.OpenDerived(key, SearchCachePartBlockIndex); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("the damaged part is still there: %v", err)
	}
	if _, err := testReadKeptRecord(t, world.cache, kept.record); err != nil {
		t.Errorf("a derived part's damage took its file: %v", err)
	}
}

// §5.9's delete row: a lock drops the decoded state and ends every open cursor; the sealed files stay.
func TestLockedDropsDecoded(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/a/2", Version: 1}
	kept := newTestSearchRecord(t, key, SearchCachePartition{All: true}, testSearchPlaintext("locked", 1000))
	if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	decodes := 0
	decode := func() (any, int64, error) {
		decodes += 1
		return "a decoded dictionary", 1024, nil
	}
	decodedKey := SearchDecodedKey{Key: key, Part: searchCachePartRecord}
	for range 2 {
		if _, err := world.cache.Decoded(decodedKey, decode); err != nil {
			t.Fatal(err)
		}
	}
	if decodes != 1 {
		t.Fatalf("decoded %d times before the lock", decodes)
	}
	ended := make(chan struct{})
	world.cache.AddCursor(func() { close(ended) })
	before := len(world.searchPaths(t))

	world.instance.Lock()
	<-ended
	if world.cache.decoded.heldByteCount() != 0 {
		t.Error("decoded state survived the lock")
	}
	if after := len(world.searchPaths(t)); after != before {
		t.Errorf("the lock took %d files", before-after)
	}
	if err := world.instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := world.cache.Decoded(decodedKey, decode); err != nil {
		t.Fatal(err)
	}
	if decodes != 2 {
		t.Errorf("decoded %d times", decodes)
	}
}

// A reproduced file is kept only at its entry version's content_sha256, and then counts as held; a part of one file is
// kept only while the file is held; derived data reads back a frame at a time.
func TestDerivedNeedsAVerifiedFile(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20010/m", Version: 4}
	if err := world.cache.PutDerived(t.Context(), &SearchCacheDerived{Key: key, Part: SearchCachePartBlockIndex, Plaintext: []byte("x")}); !errors.Is(err, ErrSearchCacheUnnamed) {
		t.Errorf("a part of a file not held: %v", err)
	}
	if err := world.cache.PutDerived(t.Context(), &SearchCacheDerived{Key: key, Part: SearchCachePartManifest, Plaintext: []byte("x")}); !errors.Is(err, ErrSearchCacheUnnamed) {
		t.Errorf("a manifest of a ref not followed: %v", err)
	}
	plaintext := testSearchPlaintext("reproduced", EvsRecordFrameByteCount+77)
	reproduced := &SearchCacheDerived{Key: key, Part: SearchCachePartFile, Plaintext: plaintext, ContentSha256: sha256.Sum256(plaintext),
		Partition: SearchCachePartition{StartDay: 20010}}
	wrong := *reproduced
	wrong.ContentSha256[3] ^= 1
	if err := world.cache.PutDerived(t.Context(), &wrong); !errors.Is(err, ErrSearchCacheContent) {
		t.Errorf("a reproduction that differs: %v", err)
	}
	if err := world.cache.PutDerived(t.Context(), reproduced); err != nil {
		t.Fatal(err)
	}
	ref, err := world.cache.Ref(key.RepoId, key.RefId)
	if err != nil || ref == nil || len(ref.Files) != 1 || ref.Files[0].Kind != searchCacheKindFile {
		t.Fatalf("held %+v, %v", ref, err)
	}
	frames, err := world.cache.OpenDerived(key, SearchCachePartFile)
	if err != nil {
		t.Fatal(err)
	}
	second, err := frames.ReadFrame(1)
	if err != nil || !bytes.Equal(second, plaintext[EvsRecordFrameByteCount:]) || frames.FrameCount() != 2 {
		t.Errorf("frame 1 of %d: %v", frames.FrameCount(), err)
	}
	if err := world.cache.PutDerived(t.Context(), &SearchCacheDerived{Key: key, Part: SearchCachePartBlockIndex, Plaintext: []byte("blocks")}); err != nil {
		t.Errorf("a part of a reproduced file: %v", err)
	}
	if err := world.cache.PutDerived(t.Context(), &SearchCacheDerived{Key: SearchCacheKey{RepoId: key.RepoId, RefId: key.RefId, Path: SearchCacheRefPath, Version: 12},
		Part: SearchCachePartManifest, Plaintext: []byte("manifest")}); err != nil {
		t.Errorf("a followed ref's manifest: %v", err)
	}

	// a file's removal takes what derives from it
	if err := world.cache.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err := world.cache.OpenDerived(key, SearchCachePartBlockIndex); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("a removed file's block index: %v", err)
	}
}

// Search.CacheByteCount 0, an ephemeral sidecar's: the cache works and the medium holds none of it.
func TestMemoryCacheWritesNothing(t *testing.T) {
	world := newTestSearchCacheWorld(t, 0)
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20020/0", Version: 1}
	kept := newTestSearchRecord(t, key, SearchCachePartition{StartDay: 20020}, testSearchPlaintext("memory", 5000))
	if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	if _, err := testReadKeptRecord(t, world.cache, kept.record); err != nil {
		t.Fatal(err)
	}
	if paths := world.searchPaths(t); len(paths) != 0 {
		t.Errorf("an in-memory cache wrote %v", paths)
	}
}
