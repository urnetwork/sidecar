package sidecar

// CORE-M10-01: §5.9's index cache keeps a file only once its plaintext is its entry version's content_sha256, keeps no
// query, drops and refetches a file that fails AEAD, reads one frame at a time, and drops decoded state and cursors at a
// lock. QD-838: a kept record reopens in a later round under RK_g alone, from the wrapped object key, generation and
// file id kept beside it; no other generation's key opens it; no plaintext key is ever stored; a record kept before
// those reads as lacking them for the next round to fetch again. A slot-keyed record's keys and its drop at an ERASE's
// hint (QD-845) are state_search_cache_slot_test.go's.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
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

func newTestSearchRecord(t testing.TB, key SearchCacheKey, partition SearchCachePartition, plaintext []byte) *testSearchRecord {
	t.Helper()
	return newTestSearchRecordAt(t, key, partition, plaintext, 1)
}

// newTestSearchRecord's record under generation g of evsTestRepoKey, as a general repo's kind-5 segment carries one:
// its header sealed under manifest_g and its object key's 72 B block wrapped under fek_g (QD-524).
func newTestSearchRecordAt(t testing.TB, key SearchCacheKey, partition SearchCachePartition, plaintext []byte, generation uint64) *testSearchRecord {
	t.Helper()
	repoKey := evsTestRepoKey(key.RepoId, generation)
	manifestKey, err := NewEvsManifestKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	fekKey, err := NewEvsFekKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	objectKey := NewEvsObjectKey()
	wrapped, err := EvsWrapObjectKey(fekKey, objectKey)
	if err != nil {
		t.Fatal(err)
	}
	fileId := NewId()
	header := evsTestHeader(key.Path, protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, len(plaintext))
	header.Generation = generation
	sealed, opened := evsTestWriteRecord(t, manifestKey, objectKey, fileId, header, plaintext)
	return &testSearchRecord{
		plaintext: plaintext,
		record: &SearchCacheRecord{
			Key:              key,
			RefVersion:       9,
			ContentSha256:    sha256.Sum256(plaintext),
			Partition:        partition,
			SealedHeader:     sealed[:EvsRecordHeaderByteCount],
			SealedFrames:     sealed[EvsRecordHeaderByteCount:],
			Header:           &opened,
			ObjectKey:        objectKey,
			FileId:           fileId,
			WrappedObjectKey: wrapped,
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
	// a reader's one frame buffer takes each frame it reads, so a cursor holds one frame and no more
	frames, err := world.cache.OpenRecord(key)
	if err != nil {
		t.Fatal(err)
	}
	source := frames.frameSource(good.record.Header, good.record.ObjectKey, good.record.FileId)
	buffer := make([]byte, EvsRecordFrameByteCount)
	for index := range 2 {
		frame, err := source.indexReadFrame(index, buffer)
		if err != nil {
			t.Fatal(err)
		}
		if &frame[0] != &buffer[0] {
			t.Errorf("frame %d was read into a buffer of its own", index)
		}
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

	// a lock takes the in-memory files with the decoded state: everything in them is fetched or derived again
	ended := make(chan struct{})
	world.cache.AddCursor(func() { close(ended) })
	world.instance.Lock()
	<-ended
	if ref, err := world.cache.Ref(key.RepoId, key.RefId); err != nil || ref != nil || world.cache.ByteCount() != 0 {
		t.Errorf("after a lock the memory cache holds %+v, %d bytes: %v", ref, world.cache.ByteCount(), err)
	}
}

// A logger keeping every line, which a test scans for keys.
type testSearchCacheLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testSearchCacheLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testSearchCacheLogger) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *testSearchCacheLogger) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testSearchCacheLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testSearchCacheLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *testSearchCacheLogger) V(level int32) Verbose {
	return testSearchCacheVerbose{log: self}
}

func (self *testSearchCacheLogger) text() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return strings.Join(self.lines, "\n")
}

// Every level of testSearchCacheLogger, enabled.
type testSearchCacheVerbose struct {
	log *testSearchCacheLogger
}

func (self testSearchCacheVerbose) Enabled() bool {
	return true
}

func (self testSearchCacheVerbose) Info(args ...any) {
	self.log.Info(args...)
}

func (self testSearchCacheVerbose) Infof(format string, args ...any) {
	self.log.Infof(format, args...)
}

// Reads a kept record whole through a read opened with its repo key, frame by frame into one buffer.
func testReadThrough(t *testing.T, read *SearchCacheRecordRead) ([]byte, error) {
	t.Helper()
	whole := []byte{}
	buffer := make([]byte, EvsRecordFrameByteCount)
	for index := range read.FrameCount() {
		frame, err := read.ReadFrame(index, buffer)
		if err != nil {
			return nil, err
		}
		whole = append(whole, frame...)
	}
	return whole, nil
}

// Rewrites a kept record as the cache kept it before QD-838: its meta through strip, its holdings entry unmarked.
func (self *testSearchCacheWorld) keptBeforeKeys(t *testing.T, key SearchCacheKey, strip func(meta *searchCacheMetaWire)) {
	t.Helper()
	cache := self.cache
	base := searchCachePartName(key, searchCachePartRecord)
	meta, err := cache.readMeta(base)
	if err != nil {
		t.Fatal(err)
	}
	strip(meta)
	encoded, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.writeSmall(base+"/"+searchCacheMetaName, encoded, true); err != nil {
		t.Fatal(err)
	}
	cache.operationLock.Lock()
	defer cache.operationLock.Unlock()
	ref, err := cache.loadRefWithLock(key.RepoId, key.RefId)
	if err != nil {
		t.Fatal(err)
	}
	cache.stateLock.Lock()
	for index := range ref.Files {
		if ref.Files[index].Key == key {
			ref.Files[index].KeysKept = false
		}
	}
	cache.stateLock.Unlock()
	if err := cache.storeRefWithLock(ref); err != nil {
		t.Fatal(err)
	}
}

// QD-838: a record kept in one round reopens in a later one, a new cache over the same store standing for a restart,
// from its cache key and RK_g alone, asked of gkm as any evs read asks it: every frame reads back byte for byte, one
// frame decrypted at a time, also as an index reader's frame source, and the read holds its key only until Close or
// a lock, after which the file still reopens.
func TestKeptRecordReopensInALaterRound(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/a/3", Version: 5}
	plaintext := testSearchPlaintext("reopened", 5*EvsRecordFrameByteCount/2)
	kept := newTestSearchRecordAt(t, key, SearchCachePartition{All: true}, plaintext, 3)
	if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	world.cache.Close()

	// a later round: a cache over the same store, holding nothing of the round that kept the record
	later, err := NewSearchCache(t.Context(), world.instance.Store(&world.networkId), world.settings, world.clock, NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(later.Close)
	frames, err := later.OpenRecord(key)
	if err != nil {
		t.Fatal(err)
	}
	if frames.Generation() != 3 || !bytes.Equal(frames.WrappedObjectKey(), kept.record.WrappedObjectKey) {
		t.Fatalf("kept generation %d and a block of %d bytes", frames.Generation(), len(frames.WrappedObjectKey()))
	}
	if fileId, err := frames.FileId(); err != nil || fileId != kept.record.FileId {
		t.Fatalf("kept file id %v: %v", fileId, err)
	}
	gkm := &evsTestReadGkm{newest: 3}
	read, err := later.OpenRecordRead(t.Context(), key, gkm)
	if err != nil {
		t.Fatal(err)
	}
	if read.FrameCount() != 3 || read.Length() != int64(len(plaintext)) {
		t.Fatalf("a read of %d frames and %d bytes", read.FrameCount(), read.Length())
	}
	whole, err := testReadThrough(t, read)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(whole, plaintext) {
		t.Fatal("the reopened record reads back otherwise")
	}
	// the index's readers take the read as their frame source
	across := make([]byte, 100)
	if err := indexNewFrameCursor(read).read(EvsRecordFrameByteCount-50, across); err != nil ||
		!bytes.Equal(across, plaintext[EvsRecordFrameByteCount-50:EvsRecordFrameByteCount+50]) {
		t.Fatalf("a read across two frames: %v", err)
	}

	// Close clears the key the read held and ends it
	objectKey := read.objectKey
	read.Close()
	read.Close()
	if read.objectKey != nil || !bytes.Equal(objectKey.key, make([]byte, len(objectKey.key))) {
		t.Error("a closed read kept its object key")
	}
	if _, err := read.ReadFrame(0, nil); !errors.Is(err, ErrSearchCacheReadEnded) {
		t.Errorf("a frame after Close: %v", err)
	}

	// a lock ends an open read as it ends a cursor (the instance's lock calls Locked, TestLockedDropsDecoded); the file
	// stays and reopens
	open, err := later.OpenRecordRead(t.Context(), key, gkm)
	if err != nil {
		t.Fatal(err)
	}
	openKey := open.objectKey
	later.Locked()
	if _, err := open.ReadFrame(0, nil); !errors.Is(err, ErrSearchCacheReadEnded) {
		t.Errorf("a frame after a lock: %v", err)
	}
	if !bytes.Equal(openKey.key, make([]byte, len(openKey.key))) {
		t.Error("a lock left a read's object key")
	}
	open.Close()
	again, err := later.OpenRecordRead(t.Context(), key, gkm)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if frame, err := again.ReadFrame(2, nil); err != nil || !bytes.Equal(frame, plaintext[2*EvsRecordFrameByteCount:]) {
		t.Errorf("the last frame after a lock: %v", err)
	}

	// a lock between the record's open and its read's start: the read is refused and never holds the key
	frames, err = later.OpenRecord(key)
	if err != nil {
		t.Fatal(err)
	}
	world.instance.Lock()
	if read, err := frames.OpenRead(evsTestRepoKey(key.RepoId, 3)); !errors.Is(err, ErrSidecarStoreLocked) || read != nil {
		t.Errorf("a read started on a locked instance: %v", err)
	}
	if err := world.instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
}

// QD-838: only RK_g of the record's own repo at its own generation opens it. Another generation's key, another repo's,
// and one that names the generation but is not its RK_g, as a forked ladder would give, are refused, the last failing
// the block's unwrap itself, and so do a wrong generation's fek_g on the kept block; nothing is dropped, so the right
// key still opens it. A gkm that reaches no such generation answers its own refusal.
func TestKeptRecordRefusesAnotherGenerationsKey(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20030/0", Version: 2}
	plaintext := testSearchPlaintext("generations", 3*EvsRecordFrameByteCount/2)
	kept := newTestSearchRecordAt(t, key, SearchCachePartition{StartDay: 20030}, plaintext, 2)
	if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	frames, err := world.cache.OpenRecord(key)
	if err != nil {
		t.Fatal(err)
	}
	forked := &EvsRepoKey{repoId: key.RepoId, generation: 2, repoKey: evsTestBytes("RK forked", evsKeyByteCount), firstRepoKey: evsTestBytes("RK 1", evsKeyByteCount)}
	for label, wrong := range map[string]*EvsRepoKey{
		"generation 1": evsTestRepoKey(key.RepoId, 1), "generation 3": evsTestRepoKey(key.RepoId, 3),
		"another repo": evsTestRepoKey(NewId(), 2), "a forked RK_2": forked, "none": nil,
	} {
		read, err := frames.OpenRead(wrong)
		if !errors.Is(err, ErrSearchCacheKey) {
			t.Errorf("%s: %v", label, err)
		}
		if read != nil {
			t.Errorf("%s: a read was opened", label)
		}
	}
	if _, err := frames.OpenRead(forked); !errors.Is(err, ErrEvsSealInvalid) {
		t.Errorf("a forked RK_2 failed otherwise than at the unwrap: %v", err)
	}
	for _, generation := range []uint64{1, 3} {
		fekKey, err := NewEvsFekKey(evsTestRepoKey(key.RepoId, generation))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := EvsUnwrapObjectKey(fekKey, frames.WrappedObjectKey()); !errors.Is(err, ErrEvsSealInvalid) {
			t.Errorf("fek_%d unwrapped generation 2's block: %v", generation, err)
		}
	}
	if _, err := world.cache.OpenRecordRead(t.Context(), key, gkmRefusingClient{}); !errors.Is(err, ErrGkmUnavailable) {
		t.Errorf("a gkm that refuses: %v", err)
	}
	if _, err := world.cache.OpenRecordRead(t.Context(), key, nil); !errors.Is(err, ErrSearchCacheArgs) {
		t.Errorf("no gkm: %v", err)
	}

	ref, err := world.cache.Ref(key.RepoId, key.RefId)
	if err != nil || ref == nil || len(ref.Files) != 1 {
		t.Fatalf("a refused key dropped the record: %+v, %v", ref, err)
	}
	read, err := frames.OpenRead(evsTestRepoKey(key.RepoId, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if whole, err := testReadThrough(t, read); err != nil || !bytes.Equal(whole, plaintext) {
		t.Errorf("the record's own key: %v", err)
	}
}

// QD-838: the cache keeps a record's object key only wrapped. No byte on the medium, no sealed file's plaintext and no
// file of an in-memory cache holds the object key, fek_g, manifest_g or RK_g, raw or encoded, the wrapped block being
// what the meta keeps; a read writes nothing, and a refused key's error and a damaged frame's log hold none of them.
func TestNoPlaintextObjectKeyKept(t *testing.T) {
	for _, cacheByteCount := range []int64{1 << 30, 0} {
		world := newTestSearchCacheWorld(t, cacheByteCount)
		world.cache.Close()
		logger := &testSearchCacheLogger{}
		cache, err := NewSearchCache(t.Context(), world.instance.Store(&world.networkId), world.settings, world.clock, logger)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(cache.Close)
		key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: ".ur-index/i1/b/20050/0", Version: 1}
		kept := newTestSearchRecordAt(t, key, SearchCachePartition{StartDay: 20050}, testSearchPlaintext("private", 2*EvsRecordFrameByteCount), 2)
		if err := cache.PutRecord(t.Context(), kept.record); err != nil {
			t.Fatal(err)
		}
		repoKey := evsTestRepoKey(key.RepoId, 2)
		fekKey, err := NewEvsFekKey(repoKey)
		if err != nil {
			t.Fatal(err)
		}
		manifestKey, err := NewEvsManifestKey(repoKey)
		if err != nil {
			t.Fatal(err)
		}
		secrets := map[string][]byte{"object key": kept.record.ObjectKey.key, "fek_g": fekKey.key, "manifest_g": manifestKey.key, "RK_g": repoKey.repoKey}
		scan := func(where string, content []byte) {
			for name, secret := range secrets {
				for _, encoding := range []string{string(secret), hex.EncodeToString(secret), strings.ToUpper(hex.EncodeToString(secret)),
					base64.StdEncoding.EncodeToString(secret), base64.RawStdEncoding.EncodeToString(secret),
					base64.URLEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret)} {
					if bytes.Contains(content, []byte(encoding)) {
						t.Errorf("cache of %d bytes: %s holds the %s", cacheByteCount, where, name)
					}
				}
			}
		}

		before := backendSnapshot(t, world.backend)
		read, err := cache.OpenRecordRead(t.Context(), key, &evsTestReadGkm{newest: 2})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testReadThrough(t, read); err != nil {
			t.Fatal(err)
		}
		read.Close()
		frames, err := cache.OpenRecord(key)
		if err != nil {
			t.Fatal(err)
		}
		forked := &EvsRepoKey{repoId: key.RepoId, generation: 2, repoKey: evsTestBytes("RK forked", evsKeyByteCount)}
		_, refused := frames.OpenRead(forked)
		if refused == nil {
			t.Fatal("a forked key opened the record")
		}
		scan("a refused key's error", []byte(refused.Error()))
		if after := backendSnapshot(t, world.backend); len(after) != len(before) {
			t.Errorf("a read wrote %d files", len(after)-len(before))
		} else {
			for path, content := range before {
				if !bytes.Equal(after[path], content) {
					t.Errorf("a read rewrote %s", path)
				}
			}
		}

		entries, err := cache.store.List("")
		if err != nil {
			t.Fatal(err)
		}
		block := base64.StdEncoding.EncodeToString(kept.record.WrappedObjectKey)
		blocks := 0
		for _, entry := range entries {
			reader, err := cache.store.Open(entry.Name)
			if err != nil {
				t.Fatal(err)
			}
			content, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			scan(entry.Name, content)
			if strings.HasSuffix(entry.Name, "/record/m") && bytes.Contains(content, []byte(block)) {
				blocks += 1
			}
		}
		if blocks != 1 {
			t.Errorf("cache of %d bytes: %d metas keep the wrapped block", cacheByteCount, blocks)
		}
		for path, raw := range backendSnapshot(t, world.backend) {
			scan(path, raw)
		}

		if 0 < cacheByteCount {
			// a damaged frame drops the file, logging it, and nothing of a key goes into the line
			world.damage(t, "/record/1")
			reread, err := cache.OpenRecordRead(t.Context(), key, &evsTestReadGkm{newest: 2})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := testReadThrough(t, reread); !errors.Is(err, ErrSearchCacheRefetch) {
				t.Errorf("a damaged frame: %v", err)
			}
			reread.Close()
			if logger.text() == "" {
				t.Error("the dropped file logged nothing")
			}
		}
		scan("the log", []byte(logger.text()))
	}
}

// QD-838: a record kept before the cache kept its keys, in either earlier meta (no block, file id or generation; or a
// block and file id with no generation), reads as lacking them. It stays held and reads to a reader holding its keys,
// as the round that fetched it did, while a reader with RK_g alone is answered ErrSearchCacheKeysLacking and its
// holdings entry is unmarked, so the next sync round fetches it again (search_fetch.go); the copy that round keeps
// replaces it and reopens.
func TestRecordKeptBeforeKeysReadsAsLacking(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	gkm := &evsTestReadGkm{newest: 1}
	strips := []func(meta *searchCacheMetaWire){
		func(meta *searchCacheMetaWire) { meta.WrappedKey, meta.FileId, meta.Generation = nil, "", 0 },
		func(meta *searchCacheMetaWire) { meta.Generation = 0 },
	}
	for index, strip := range strips {
		key := SearchCacheKey{RepoId: NewId(), RefId: NewId(), Path: fmt.Sprintf(".ur-index/i1/b/20040/%d", index), Version: 1}
		kept := newTestSearchRecord(t, key, SearchCachePartition{StartDay: 20040}, testSearchPlaintext(key.Path, EvsRecordFrameByteCount+10))
		if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
			t.Fatal(err)
		}
		world.keptBeforeKeys(t, key, strip)

		ref, err := world.cache.Ref(key.RepoId, key.RefId)
		if err != nil || ref == nil || len(ref.Files) != 1 || ref.Files[0].KeysKept {
			t.Fatalf("earlier meta %d: held %+v, %v", index, ref, err)
		}
		frames, err := world.cache.OpenRecord(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := frames.FileId(); index == 0 && !errors.Is(err, ErrSearchCacheKeysLacking) {
			t.Errorf("earlier meta %d: its file id: %v", index, err)
		}
		if _, err := frames.OpenRead(evsTestRepoKey(key.RepoId, 1)); !errors.Is(err, ErrSearchCacheKeysLacking) {
			t.Errorf("earlier meta %d: a read under RK_1: %v", index, err)
		}
		if _, err := world.cache.OpenRecordRead(t.Context(), key, gkm); !errors.Is(err, ErrSearchCacheKeysLacking) {
			t.Errorf("earlier meta %d: a read through gkm: %v", index, err)
		}
		if whole, err := testReadKeptRecord(t, world.cache, kept.record); err != nil || !bytes.Equal(whole, kept.plaintext) {
			t.Errorf("earlier meta %d: the round's own read: %v", index, err)
		}
		if ref, err := world.cache.Ref(key.RepoId, key.RefId); err != nil || ref == nil || len(ref.Files) != 1 {
			t.Fatalf("earlier meta %d: a record lacking its keys was dropped: %+v, %v", index, ref, err)
		}

		// fetched again, it is kept with its keys and reopens
		if err := world.cache.PutRecord(t.Context(), kept.record); err != nil {
			t.Fatal(err)
		}
		if ref, err := world.cache.Ref(key.RepoId, key.RefId); err != nil || ref == nil || len(ref.Files) != 1 || !ref.Files[0].KeysKept {
			t.Fatalf("earlier meta %d: fetched again, held %+v, %v", index, ref, err)
		}
		read, err := world.cache.OpenRecordRead(t.Context(), key, gkm)
		if err != nil {
			t.Fatal(err)
		}
		whole, err := testReadThrough(t, read)
		read.Close()
		if err != nil || !bytes.Equal(whole, kept.plaintext) {
			t.Errorf("earlier meta %d: fetched again, it reads %v", index, err)
		}
	}
}
