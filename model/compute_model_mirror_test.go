package model

// The api's model mirror (CSRV-M11-02; DESIGN-COMPUTE §14.5, §6.5; CO-49) over an in-memory store that keeps
// server's ComputeModelBlobStore's rules and a fake hub: a copy at the pinned commit alone, a branch refused; a size or
// hash mismatch leaving nothing copied or served; the index computed from the mirrored bytes, equal to
// InferModelIndexBuild over the source; Serve checking every chunk against the signed pin; a cut read resumed at its
// chunk; and testdata/compute/models/'s vectors.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// The fixtures' directory, testdata/compute/models/.
const testComputeModelVectorDirectory = "../testdata/compute/models"

// A file's bytes as testdata/compute/models/README.md gives them: byte i is (i + seed) mod 251.
func testComputeModelBytes(byteCount int, seed int) []byte {
	data := make([]byte, byteCount)
	for i := range data {
		data[i] = byte((i + seed) % 251)
	}
	return data
}

// The draft's files' bytes, by SHA-256.
func testComputeModelDraftBytes() map[string][]byte {
	sha256Bytes := map[string][]byte{}
	for _, data := range [][]byte{testComputeModelBytes(2621440, 0), testComputeModelBytes(1048577, 7)} {
		digest := sha256.Sum256(data)
		sha256Bytes[hex.EncodeToString(digest[:])] = data
	}
	return sha256Bytes
}

// The SHA-256 of data, in lowercase hex.
func testComputeModelSha256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// The format's settings at 1 MiB chunks, the least the format takes, so the vectors' files have a few chunks.
func testComputeModelInferSettings() *sidecar.InferSettings {
	settings := sidecar.DefaultInferSettings()
	settings.ModelChunkByteCount = 1024 * 1024
	return settings
}

// The mirror's settings for the fake hub at hub.example, retrying at once.
func testComputeModelMirrorSettings(t *testing.T) *ComputeModelMirrorSettings {
	settings := DefaultComputeModelMirrorSettings()
	settings.HubHost = "hub.example"
	settings.HubRedirectHostSuffixes = []string{"cdn.example"}
	settings.HubRetryInterval = 0
	settings.StagingDirectory = t.TempDir()
	return settings
}

// An in-memory store with server's rules: a served file's chunks, index and state are final but for its own state
// again. Safe for concurrent use.
type testComputeModelStore struct {
	stateLock          sync.Mutex
	sha256Records      map[string]*ComputeModelFileRecord
	sha256Indexes      map[string][]byte
	sha256NumberChunks map[string]map[int][]byte
	chunkPutCount      int
}

func newTestComputeModelStore() *testComputeModelStore {
	return &testComputeModelStore{
		sha256Records:      map[string]*ComputeModelFileRecord{},
		sha256Indexes:      map[string][]byte{},
		sha256NumberChunks: map[string]map[int][]byte{},
	}
}

// The record kept, or absent.
func (self *testComputeModelStore) FileRecord(ctx context.Context, sha256Text string) (*ComputeModelFileRecord, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	record, ok := self.sha256Records[sha256Text]
	if !ok {
		return nil, ErrComputeModelObjectAbsent
	}
	copied := *record
	return &copied, nil
}

// The index kept, or absent.
func (self *testComputeModelStore) OpenIndex(ctx context.Context, sha256Text string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	index, ok := self.sha256Indexes[sha256Text]
	if !ok {
		return nil, ErrComputeModelObjectAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(index))), nil
}

// The chunk kept, or absent.
func (self *testComputeModelStore) OpenChunk(ctx context.Context, sha256Text string, n int) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	chunk, ok := self.sha256NumberChunks[sha256Text][n]
	if !ok {
		return nil, ErrComputeModelObjectAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(chunk))), nil
}

// Whether the file is served, under the lock.
func (self *testComputeModelStore) servedWithLock(sha256Text string) bool {
	record, ok := self.sha256Records[sha256Text]
	return ok && record.State == ComputeModelFileStateServed
}

// Keeps the local file as the index.
func (self *testComputeModelStore) PutIndex(ctx context.Context, sha256Text string, localPath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.servedWithLock(sha256Text) {
		return errors.New("served")
	}
	self.sha256Indexes[sha256Text] = data
	return nil
}

// Keeps the local file as chunk n.
func (self *testComputeModelStore) PutChunk(ctx context.Context, sha256Text string, n int, localPath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.servedWithLock(sha256Text) {
		return errors.New("served")
	}
	if self.sha256NumberChunks[sha256Text] == nil {
		self.sha256NumberChunks[sha256Text] = map[int][]byte{}
	}
	self.sha256NumberChunks[sha256Text][n] = data
	self.chunkPutCount += 1
	return nil
}

// Keeps the record, as server's store takes one.
func (self *testComputeModelStore) PutFileRecord(ctx context.Context, sha256Text string, record *ComputeModelFileRecord) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch record.State {
	case ComputeModelFileStateCopied:
		if record.IndexSha256 != "" {
			return errors.New("a copied file pins no index")
		}
	case ComputeModelFileStateIndexed, ComputeModelFileStateServed:
		if !computeModelSha256Valid(record.IndexSha256) {
			return errors.New("no index pin")
		}
	default:
		return fmt.Errorf("the state %q", record.State)
	}
	if self.servedWithLock(sha256Text) {
		if *self.sha256Records[sha256Text] == *record {
			return nil
		}
		return errors.New("served")
	}
	copied := *record
	self.sha256Records[sha256Text] = &copied
	return nil
}

// Replaces a stored chunk's bytes, as a fault or an attacker on the store would.
func (self *testComputeModelStore) alterChunk(sha256Text string, n int, data []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sha256NumberChunks[sha256Text][n] = data
}

// The chunks stored for a file, in order.
func (self *testComputeModelStore) chunks(sha256Text string) [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	chunks := [][]byte{}
	for n := 0; ; n += 1 {
		chunk, ok := self.sha256NumberChunks[sha256Text][n]
		if !ok {
			return chunks
		}
		chunks = append(chunks, chunk)
	}
}

// A fake hub: each url's bytes and what it declares, with faults a test sets. Safe for concurrent use.
type testComputeModelHub struct {
	stateLock sync.Mutex
	urlBytes  map[string][]byte
	// a size to declare in place of the bytes' own, by url
	urlDeclaredByteCounts map[string]int64
	// the number of requests whose body is cut with an error after this many bytes, and the cut
	cutRequestCount int
	cutAfter        int64
	// every request, as "<url> @<offset>"
	requests []string
}

func newTestComputeModelHub() *testComputeModelHub {
	return &testComputeModelHub{
		urlBytes:              map[string][]byte{},
		urlDeclaredByteCounts: map[string]int64{},
	}
}

// The hub's answer: the url's bytes from offset, a 404 refusal for a url it does not hold.
func (self *testComputeModelHub) Open(ctx context.Context, fileUrl string, offset int64) (io.ReadCloser, int64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, fmt.Sprintf("%s @%d", fileUrl, offset))
	data, ok := self.urlBytes[fileUrl]
	if !ok {
		return nil, 0, fmt.Errorf("%w: the hub answered 404", ErrComputeModelFetchRefused)
	}
	byteCount := int64(len(data))
	if declared, ok := self.urlDeclaredByteCounts[fileUrl]; ok {
		byteCount = declared
	}
	var reader io.Reader = bytes.NewReader(data[min(offset, int64(len(data))):])
	if 0 < self.cutRequestCount {
		self.cutRequestCount -= 1
		reader = io.MultiReader(io.LimitReader(reader, self.cutAfter), &testComputeModelCut{})
	}
	return io.NopCloser(reader), byteCount, nil
}

// The requests the hub saw.
func (self *testComputeModelHub) seen() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.requests)
}

// A connection cut mid-body.
type testComputeModelCut struct{}

// Always the cut.
func (self *testComputeModelCut) Read(out []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// The draft's files, each served by a fresh fake hub at its url, and a mirror over a fresh store.
type testComputeModelSetup struct {
	store    *testComputeModelStore
	hub      *testComputeModelHub
	mirror   *ComputeModelMirror
	manifest *sidecar.InferManifest
	files    []*sidecar.InferManifestModelFile
	bytes    map[string][]byte
}

func newTestComputeModelSetup(t *testing.T) *testComputeModelSetup {
	t.Helper()
	inferSettings := testComputeModelInferSettings()
	data, err := os.ReadFile(filepath.Join(testComputeModelVectorDirectory, "draft.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseComputeModelDraftManifest(data, inferSettings)
	if err != nil {
		t.Fatal(err)
	}
	setup := &testComputeModelSetup{
		store:    newTestComputeModelStore(),
		hub:      newTestComputeModelHub(),
		manifest: manifest,
		files:    ComputeModelManifestFiles(manifest),
		bytes:    testComputeModelDraftBytes(),
	}
	for _, file := range setup.files {
		fileBytes, ok := setup.bytes[file.Sha256]
		if !ok {
			t.Fatalf("draft.json names %s, which the README's rule does not make", file.Sha256)
		}
		setup.hub.urlBytes[file.Url] = fileBytes
	}
	setup.mirror = NewComputeModelMirror(setup.store, setup.hub, testComputeModelMirrorSettings(t), inferSettings, nil, nil)
	return setup
}

// The file's state, which must read.
func testComputeModelState(t *testing.T, mirror *ComputeModelMirror, sha256Text string) *ComputeModelFileRecord {
	t.Helper()
	record, err := mirror.Status(context.Background(), sha256Text)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

// A copy of the draft's two files from the hub at their pinned commits: each stored chunk by chunk at the format's
// chunk size, its state copied with no pin, the file listed under two models copied once; a second copy asks the hub
// nothing; and a url naming a branch, a tag-like word or another organization is refused before any request.
func TestComputeModelMirrorCopiesAtPinnedCommit(t *testing.T) {
	setup := newTestComputeModelSetup(t)
	ctx := context.Background()
	if len(setup.files) != 2 {
		t.Fatalf("%d files, want the draft's 2", len(setup.files))
	}
	for _, file := range setup.files {
		record, copied, err := setup.mirror.Copy(ctx, file)
		if err != nil {
			t.Fatal(err)
		}
		if !copied || record.State != ComputeModelFileStateCopied || record.IndexSha256 != "" {
			t.Fatalf("%s: %+v, copied %t", file.Sha256, record, copied)
		}
		chunks := setup.store.chunks(file.Sha256)
		source := setup.bytes[file.Sha256]
		if !bytes.Equal(bytes.Join(chunks, nil), source) {
			t.Fatalf("%s's stored chunks are not its bytes", file.Sha256)
		}
		for n, chunk := range chunks[:len(chunks)-1] {
			if len(chunk) != 1024*1024 {
				t.Fatalf("%s's chunk %d is %d bytes", file.Sha256, n, len(chunk))
			}
		}
	}
	if seen := setup.hub.seen(); len(seen) != 2 || !strings.Contains(seen[0], "/resolve/0123456789abcdef0123456789abcdef01234567/") {
		t.Fatalf("the hub saw %q", seen)
	}
	for _, file := range setup.files {
		record, copied, err := setup.mirror.Copy(ctx, file)
		if err != nil || copied || record.State != ComputeModelFileStateCopied {
			t.Fatalf("a second copy: %+v, %t, %v", record, copied, err)
		}
	}
	if seen := setup.hub.seen(); len(seen) != 2 {
		t.Fatalf("a second copy asked the hub: %q", seen)
	}

	for _, fileUrl := range []string{
		"https://hub.example/litert-community/test-mirror-a-litert-lm/resolve/main/test-mirror-a.litertlm",
		"https://hub.example/litert-community/test-mirror-a-litert-lm/resolve/v1.0/test-mirror-a.litertlm",
		"https://hub.example/litert-community/test-mirror-a-litert-lm/resolve/0123456789ABCDEF0123456789abcdef01234567/test-mirror-a.litertlm",
		"https://hub.example/litert-community/test-mirror-a-litert-lm/resolve/0123456789abcdef0123456789abcdef0123456/test-mirror-a.litertlm",
		"https://hub.example/other-org/test-mirror-a-litert-lm/resolve/0123456789abcdef0123456789abcdef01234567/test-mirror-a.litertlm",
		"https://hub.example/litert-community/test-mirror-a-litert-lm/blob/0123456789abcdef0123456789abcdef01234567/test-mirror-a.litertlm",
		"http://hub.example/litert-community/test-mirror-a-litert-lm/resolve/0123456789abcdef0123456789abcdef01234567/test-mirror-a.litertlm",
		"https://other.example/litert-community/test-mirror-a-litert-lm/resolve/0123456789abcdef0123456789abcdef01234567/test-mirror-a.litertlm",
	} {
		branch := newTestComputeModelSetup(t)
		file := *branch.files[0]
		file.Url = fileUrl
		branch.hub.urlBytes[fileUrl] = branch.bytes[file.Sha256]
		record, copied, err := branch.mirror.Copy(ctx, &file)
		if !errors.Is(err, ErrComputeModelMirrorRefused) || copied || record != nil {
			t.Fatalf("%s: %+v, %t, %v; want a refusal", fileUrl, record, copied, err)
		}
		if seen := branch.hub.seen(); len(seen) != 0 {
			t.Fatalf("%s: the hub saw %q", fileUrl, seen)
		}
		if state := testComputeModelState(t, branch.mirror, file.Sha256); state.State != ComputeModelFileStateAbsent {
			t.Fatalf("%s: the file reads %s", fileUrl, state.State)
		}
	}
}

// The hub's bytes not the manifest's file: one byte altered, a size declared other than the manifest's, a file that
// ends short and one that runs past its size. Each copy is refused as a mismatch, the file's state stays absent, so
// nothing reads copied, Index and Serve refuse it, and the hub is not asked again.
func TestComputeModelMirrorRefusesSizeOrHashMismatch(t *testing.T) {
	ctx := context.Background()
	faults := map[string]func(setup *testComputeModelSetup, file *sidecar.InferManifestModelFile){
		"altered": func(setup *testComputeModelSetup, file *sidecar.InferManifestModelFile) {
			altered := bytes.Clone(setup.bytes[file.Sha256])
			altered[len(altered)/2] ^= 0x01
			setup.hub.urlBytes[file.Url] = altered
		},
		"declared": func(setup *testComputeModelSetup, file *sidecar.InferManifestModelFile) {
			setup.hub.urlDeclaredByteCounts[file.Url] = file.ByteCount + 1
		},
		"short": func(setup *testComputeModelSetup, file *sidecar.InferManifestModelFile) {
			setup.hub.urlBytes[file.Url] = setup.bytes[file.Sha256][:file.ByteCount-1]
			setup.hub.urlDeclaredByteCounts[file.Url] = file.ByteCount
		},
		"long": func(setup *testComputeModelSetup, file *sidecar.InferManifestModelFile) {
			setup.hub.urlBytes[file.Url] = append(bytes.Clone(setup.bytes[file.Sha256]), 0)
			setup.hub.urlDeclaredByteCounts[file.Url] = file.ByteCount
		},
	}
	for name, fault := range faults {
		setup := newTestComputeModelSetup(t)
		file := setup.files[0]
		fault(setup, file)
		record, copied, err := setup.mirror.Copy(ctx, file)
		if !errors.Is(err, ErrComputeModelMirrorRefused) || !errors.Is(err, ErrComputeModelMirrorMismatch) || copied || record != nil {
			t.Fatalf("%s: %+v, %t, %v; want a mismatch", name, record, copied, err)
		}
		if state := testComputeModelState(t, setup.mirror, file.Sha256); state.State != ComputeModelFileStateAbsent {
			t.Fatalf("%s: the file reads %s after a mismatch", name, state.State)
		}
		if _, err := setup.mirror.Index(ctx, file); !errors.Is(err, ErrComputeModelMirrorRefused) {
			t.Fatalf("%s: Index of a file not copied: %v", name, err)
		}
		served := *file
		served.IndexSha256 = testComputeModelSha256([]byte("any pin"))
		if err := setup.mirror.Serve(ctx, &served); !errors.Is(err, ErrComputeModelMirrorRefused) {
			t.Fatalf("%s: Serve of a file not copied: %v", name, err)
		}
		if seen := setup.hub.seen(); len(seen) != 1 {
			t.Fatalf("%s: a mismatch was asked of the hub again: %q", name, seen)
		}
	}
}

// Index reads the copied chunks back and computes the index from them: equal byte for byte to InferModelIndexBuild
// over the source file, its SHA-256 the pin returned, stored, and the state indexed under it; asked again it answers
// the stored index's pin. A file not copied, and chunks stored that are not the manifest's file, are refused, the
// latter mended by Recopy.
func TestComputeModelIndexFromMirroredBytes(t *testing.T) {
	setup := newTestComputeModelSetup(t)
	ctx := context.Background()
	inferSettings := testComputeModelInferSettings()
	file := setup.files[0]
	if _, err := setup.mirror.Index(ctx, file); !errors.Is(err, ErrComputeModelMirrorRefused) {
		t.Fatalf("Index of a file not copied: %v", err)
	}
	if _, _, err := setup.mirror.Copy(ctx, file); err != nil {
		t.Fatal(err)
	}
	pin, err := setup.mirror.Index(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	want, err := sidecar.InferModelIndexBuild(bytes.NewReader(setup.bytes[file.Sha256]), inferSettings.ModelChunkByteCount, inferSettings)
	if err != nil {
		t.Fatal(err)
	}
	if pin != want.IndexSha256() {
		t.Fatalf("the pin %s, InferModelIndexBuild's %s", pin, want.IndexSha256())
	}
	if !bytes.Equal(setup.store.sha256Indexes[file.Sha256], want.Bytes()) {
		t.Fatal("the stored index is not InferModelIndexBuild's over the source")
	}
	if record := testComputeModelState(t, setup.mirror, file.Sha256); record.State != ComputeModelFileStateIndexed || record.IndexSha256 != pin {
		t.Fatalf("the state %+v", record)
	}
	again, err := setup.mirror.Index(ctx, file)
	if err != nil || again != pin {
		t.Fatalf("again: %s, %v", again, err)
	}

	// a stored chunk that is not the file's: Index refuses and writes nothing, and Recopy mends it
	other := setup.files[1]
	if _, _, err := setup.mirror.Copy(ctx, other); err != nil {
		t.Fatal(err)
	}
	setup.store.alterChunk(other.Sha256, 1, []byte{0xff})
	if _, err := setup.mirror.Index(ctx, other); !errors.Is(err, ErrComputeModelMirrorMismatch) {
		t.Fatalf("Index over an altered chunk: %v", err)
	}
	if record := testComputeModelState(t, setup.mirror, other.Sha256); record.State != ComputeModelFileStateCopied {
		t.Fatalf("the altered file reads %+v", record)
	}
	setup.store.alterChunk(other.Sha256, 0, append(bytes.Clone(setup.store.chunks(other.Sha256)[0]), 0))
	if _, err := setup.mirror.Index(ctx, other); !errors.Is(err, ErrComputeModelMirrorMismatch) {
		t.Fatalf("Index over a long chunk: %v", err)
	}
	if record, err := setup.mirror.Recopy(ctx, other); err != nil || record.State != ComputeModelFileStateCopied {
		t.Fatalf("Recopy: %+v, %v", record, err)
	}
	if _, err := setup.mirror.Index(ctx, other); err != nil {
		t.Fatal(err)
	}
}

// Serve checks the stored index against the signed manifest's pin and every stored chunk against the index: one
// altered chunk, a chunk short, a chunk long and a chunk gone are each refused naming the chunk, the state staying
// indexed; a pin other than the index's is refused; then the whole file serves, Serve again is a no-op, and a served
// file is refused another pin, more chunks and Recopy.
func TestComputeModelServeChecksEveryChunk(t *testing.T) {
	setup := newTestComputeModelSetup(t)
	ctx := context.Background()
	file := setup.files[0]
	if _, _, err := setup.mirror.Copy(ctx, file); err != nil {
		t.Fatal(err)
	}
	signed := *file
	signed.IndexSha256 = testComputeModelSha256([]byte("not yet indexed"))
	if err := setup.mirror.Serve(ctx, &signed); !errors.Is(err, ErrComputeModelMirrorRefused) {
		t.Fatalf("Serve of a copied file: %v", err)
	}
	pin, err := setup.mirror.Index(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	if err := setup.mirror.Serve(ctx, &signed); !errors.Is(err, ErrComputeModelMirrorRefused) {
		t.Fatalf("Serve under another pin: %v", err)
	}
	signed.IndexSha256 = pin

	good := setup.store.chunks(file.Sha256)
	for _, fault := range []struct {
		n    int
		data []byte
	}{
		{n: 1, data: func() []byte { altered := bytes.Clone(good[1]); altered[0] ^= 0x80; return altered }()},
		{n: 2, data: good[2][:len(good[2])-1]},
		{n: 0, data: append(bytes.Clone(good[0]), 0)},
	} {
		setup.store.alterChunk(file.Sha256, fault.n, fault.data)
		err := setup.mirror.Serve(ctx, &signed)
		if !errors.Is(err, ErrComputeModelMirrorRefused) || !strings.Contains(err.Error(), fmt.Sprintf("chunk %d", fault.n)) {
			t.Fatalf("chunk %d altered: %v", fault.n, err)
		}
		if record := testComputeModelState(t, setup.mirror, file.Sha256); record.State != ComputeModelFileStateIndexed {
			t.Fatalf("chunk %d altered: the file reads %s", fault.n, record.State)
		}
		setup.store.alterChunk(file.Sha256, fault.n, good[fault.n])
	}
	func() {
		setup.store.stateLock.Lock()
		defer setup.store.stateLock.Unlock()
		delete(setup.store.sha256NumberChunks[file.Sha256], 2)
	}()
	if err := setup.mirror.Serve(ctx, &signed); !errors.Is(err, ErrComputeModelMirrorRefused) || !strings.Contains(err.Error(), "chunk 2") {
		t.Fatalf("chunk 2 gone: %v", err)
	}
	setup.store.alterChunk(file.Sha256, 2, good[2])

	if err := setup.mirror.Serve(ctx, &signed); err != nil {
		t.Fatal(err)
	}
	if record := testComputeModelState(t, setup.mirror, file.Sha256); record.State != ComputeModelFileStateServed || record.IndexSha256 != pin {
		t.Fatalf("the state %+v", record)
	}
	if err := setup.mirror.Serve(ctx, &signed); err != nil {
		t.Fatalf("Serve again: %v", err)
	}
	other := signed
	other.IndexSha256 = testComputeModelSha256([]byte("another pin"))
	if err := setup.mirror.Serve(ctx, &other); !errors.Is(err, ErrComputeModelMirrorRefused) {
		t.Fatalf("a served file under another pin: %v", err)
	}
	if _, err := setup.mirror.Recopy(ctx, file); !errors.Is(err, ErrComputeModelMirrorRefused) {
		t.Fatalf("Recopy of a served file: %v", err)
	}
	if pinAgain, err := setup.mirror.Index(ctx, file); err != nil || pinAgain != pin {
		t.Fatalf("Index of a served file: %s, %v", pinAgain, err)
	}
}

// A read the hub cuts partway through a chunk is asked again from that chunk's start, by offset, and the file still
// checks whole; a hub that keeps failing stops the copy after HubRetryCount retries with nothing copied; a refusal
// from the hub is never retried.
func TestComputeModelMirrorResumesAfterACutRead(t *testing.T) {
	ctx := context.Background()
	setup := newTestComputeModelSetup(t)
	file := setup.files[0]
	setup.hub.cutRequestCount = 1
	setup.hub.cutAfter = 1024*1024 + 512*1024
	if _, copied, err := setup.mirror.Copy(ctx, file); err != nil || !copied {
		t.Fatalf("%t, %v", copied, err)
	}
	if seen := setup.hub.seen(); !slices.Equal(seen, []string{file.Url + " @0", file.Url + " @1048576"}) {
		t.Fatalf("the hub saw %q", seen)
	}
	if !bytes.Equal(bytes.Join(setup.store.chunks(file.Sha256), nil), setup.bytes[file.Sha256]) {
		t.Fatal("the resumed copy stored other bytes")
	}

	failing := newTestComputeModelSetup(t)
	failing.hub.cutRequestCount = 100
	failing.hub.cutAfter = 10
	if _, _, err := failing.mirror.Copy(ctx, failing.files[0]); err == nil || errors.Is(err, ErrComputeModelMirrorMismatch) {
		t.Fatalf("a hub that keeps failing: %v", err)
	}
	if seen := failing.hub.seen(); len(seen) != DefaultComputeModelMirrorSettings().HubRetryCount+1 {
		t.Fatalf("the hub was asked %d times", len(seen))
	}
	if state := testComputeModelState(t, failing.mirror, failing.files[0].Sha256); state.State != ComputeModelFileStateAbsent {
		t.Fatalf("the failed file reads %s", state.State)
	}

	refused := newTestComputeModelSetup(t)
	delete(refused.hub.urlBytes, refused.files[0].Url)
	if _, _, err := refused.mirror.Copy(ctx, refused.files[0]); !errors.Is(err, ErrComputeModelFetchRefused) {
		t.Fatalf("a refused file: %v", err)
	}
	if seen := refused.hub.seen(); len(seen) != 1 {
		t.Fatalf("a refusal was asked again: %q", seen)
	}
}

// draft.json copied and indexed by the mirror at 1 MiB chunks pins to indexed.json byte for byte, which parses as a
// released manifest; SIDECAR_REGENERATE_COMPUTE_MODEL_VECTORS=1 writes it again.
func TestComputeModelMirrorVectorsAreCurrent(t *testing.T) {
	setup := newTestComputeModelSetup(t)
	ctx := context.Background()
	pins := map[string]string{}
	for _, file := range setup.files {
		if _, _, err := setup.mirror.Copy(ctx, file); err != nil {
			t.Fatal(err)
		}
		pin, err := setup.mirror.Index(ctx, file)
		if err != nil {
			t.Fatal(err)
		}
		pins[file.Sha256] = pin
	}
	pinned, err := ComputeModelDraftManifestPinned(setup.manifest, pins, testComputeModelInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(testComputeModelVectorDirectory, "indexed.json")
	if os.Getenv("SIDECAR_REGENERATE_COMPUTE_MODEL_VECTORS") == "1" {
		if err := os.WriteFile(path, pinned, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pinned, want) {
		t.Fatalf("indexed.json is not what the tooling writes; regenerate it (testdata/compute/models/README.md)")
	}
	manifest, err := sidecar.ParseInferManifest(want, testComputeModelInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range ComputeModelManifestFiles(manifest) {
		if file.IndexSha256 != pins[file.Sha256] {
			t.Fatalf("%s pins %s, the mirror's %s", file.Sha256, file.IndexSha256, pins[file.Sha256])
		}
	}
}
