//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Where the chunk index's vectors are, which the browser's engine Worker's tests read too (INFER-M13-02).
const testInferModelIndexVectorDirectory = "testdata/infer/index"

// Set to 1 to write the vectors from this build's encoder rather than check them.
const testInferModelIndexRegenerateVariable = "SIDECAR_REGENERATE_INFER_INDEX_VECTORS"

// testdata/infer/index/vectors.json.
type testInferModelIndexVectors struct {
	About   string                       `json:"about"`
	Content string                       `json:"content"`
	Vectors []*testInferModelIndexVector `json:"vectors"`
}

// One vector: a file of byte_count bytes, each byte i being i mod 251, its index in the file index names, and the
// SHA-256s of the file and of the index's bytes.
type testInferModelIndexVector struct {
	Name           string `json:"name"`
	ByteCount      int64  `json:"byte_count"`
	ChunkByteCount int64  `json:"chunk_byte_count"`
	Sha256         string `json:"sha256"`
	Index          string `json:"index"`
	IndexSha256    string `json:"index_sha256"`
}

// The vectors' files, as vectors.json's content member says: byte i is i mod 251, a prime, so no two of a file's whole
// 16 MiB chunks are alike.
func testInferModelIndexContent(byteCount int64) []byte {
	content := make([]byte, byteCount)
	for i := range content {
		content[i] = byte(i % 251)
	}
	return content
}

// The manifest's pins of a file and its index.
func testInferModelIndexFile(content []byte, indexData []byte) *InferManifestModelFile {
	fileDigest := sha256.Sum256(content)
	indexDigest := sha256.Sum256(indexData)
	return &InferManifestModelFile{
		InferManifestFile: InferManifestFile{
			Name:      "test-model.litertlm",
			Url:       "https://hub.example/test-org/test-model/resolve/0123456789abcdef0123456789abcdef01234567/test-model.litertlm",
			ByteCount: int64(len(content)),
			Sha256:    hex.EncodeToString(fileDigest[:]),
		},
		IndexSha256: hex.EncodeToString(indexDigest[:]),
	}
}

// Settings whose chunk bounds let a test build indexes of a few bytes a chunk.
func testInferModelIndexSmallSettings() *InferSettings {
	settings := DefaultInferSettings()
	settings.ModelChunkMinByteCount = 1
	return settings
}

// Each vector's file gives, through InferModelIndexBuild at the vector's chunk size, the index's bytes the vector holds,
// byte for byte, and their SHA-256; the bytes parse against the pins; and the chunks tile the file. The five files: no
// bytes, one byte, one whole chunk, a chunk and a byte, and three chunks and a tail.
func TestInferModelIndexVectors(t *testing.T) {
	settings := DefaultInferSettings()
	if os.Getenv(testInferModelIndexRegenerateVariable) == "1" {
		testInferModelIndexWriteVectors(t, settings)
	}
	data, err := os.ReadFile(filepath.Join(testInferModelIndexVectorDirectory, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testInferModelIndexVectors{}
	if err := json.Unmarshal(data, vectors); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, vector := range vectors.Vectors {
		names = append(names, vector.Name)
	}
	if want := "empty one-byte one-chunk one-chunk-and-one-byte three-chunks-and-a-tail"; strings.Join(names, " ") != want {
		t.Fatalf("the vectors are %v, not %s", names, want)
	}
	for _, vector := range vectors.Vectors {
		want, err := os.ReadFile(filepath.Join(testInferModelIndexVectorDirectory, vector.Index))
		if err != nil {
			t.Fatal(err)
		}
		content := testInferModelIndexContent(vector.ByteCount)
		index, err := InferModelIndexBuild(bytes.NewReader(content), vector.ChunkByteCount, settings)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if !bytes.Equal(index.Bytes(), want) {
			t.Errorf("%s: built %s, the vector holds %s", vector.Name, index.Bytes(), want)
		}
		wantDigest := sha256.Sum256(want)
		if index.IndexSha256() != vector.IndexSha256 || hex.EncodeToString(wantDigest[:]) != vector.IndexSha256 {
			t.Errorf("%s: the index's SHA-256 is %s, the vector's %s", vector.Name, index.IndexSha256(), vector.IndexSha256)
		}
		fileDigest := sha256.Sum256(content)
		if index.FileSha256() != vector.Sha256 || hex.EncodeToString(fileDigest[:]) != vector.Sha256 {
			t.Errorf("%s: the file's SHA-256 is %s, the vector's %s", vector.Name, index.FileSha256(), vector.Sha256)
		}

		parsed, err := ParseInferModelIndex(want, testInferModelIndexFile(content, want), settings)
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		chunkCount := (vector.ByteCount + vector.ChunkByteCount - 1) / vector.ChunkByteCount
		if parsed.ChunkCount() != int(chunkCount) || parsed.ByteCount() != vector.ByteCount || parsed.ChunkByteCount() != vector.ChunkByteCount {
			t.Errorf("%s: %d chunks of %d over %d bytes", vector.Name, parsed.ChunkCount(), parsed.ChunkByteCount(), parsed.ByteCount())
		}
		next := int64(0)
		for n := 0; n < parsed.ChunkCount(); n += 1 {
			chunk, ok := parsed.Chunk(n)
			if !ok || chunk.Offset != next || chunk.ByteCount <= 0 || vector.ChunkByteCount < chunk.ByteCount {
				t.Fatalf("%s: chunk %d is %+v", vector.Name, n, chunk)
			}
			if !chunk.Matches(content[chunk.Offset : chunk.Offset+chunk.ByteCount]) {
				t.Errorf("%s: chunk %d does not match its bytes", vector.Name, n)
			}
			next += chunk.ByteCount
		}
		if next != vector.ByteCount {
			t.Errorf("%s: the chunks cover %d of %d bytes", vector.Name, next, vector.ByteCount)
		}
	}
}

// Writes the vectors from this build's encoder, for a change to the format.
func testInferModelIndexWriteVectors(t *testing.T, settings *InferSettings) {
	chunk := settings.ModelChunkByteCount
	vectors := &testInferModelIndexVectors{
		About: "A local model file's chunk index (DESIGN-COMPUTE §6.5, CO-49; compute-plan-model-index-format, QD-1408): " +
			"RFC 8785 canonical JSON of the file's byte count, the chunk size, each chunk's lowercase hex SHA-256 in order, " +
			"the file's SHA-256 and the version, written by sidecar's InferModelIndexBuild. Each index file holds the index's " +
			"bytes exactly, with no newline, and index_sha256 is their SHA-256, the pin a manifest carries.",
		Content: "byte i of a vector's file is i mod 251, for i from 0",
		Vectors: []*testInferModelIndexVector{
			{Name: "empty", ByteCount: 0},
			{Name: "one-byte", ByteCount: 1},
			{Name: "one-chunk", ByteCount: chunk},
			{Name: "one-chunk-and-one-byte", ByteCount: chunk + 1},
			{Name: "three-chunks-and-a-tail", ByteCount: 3*chunk + 12345},
		},
	}
	if err := os.MkdirAll(testInferModelIndexVectorDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.Vectors {
		content := testInferModelIndexContent(vector.ByteCount)
		index, err := InferModelIndexBuild(bytes.NewReader(content), chunk, settings)
		if err != nil {
			t.Fatal(err)
		}
		vector.ChunkByteCount = chunk
		vector.Sha256 = index.FileSha256()
		vector.Index = vector.Name + ".json"
		vector.IndexSha256 = index.IndexSha256()
		if err := os.WriteFile(filepath.Join(testInferModelIndexVectorDirectory, vector.Index), index.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testInferModelIndexVectorDirectory, "vectors.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A document of members, canonical, and the pins that hold it: the file's SHA-256 and size as given, the index's own
// SHA-256.
func testInferModelIndexPinned(t *testing.T, members map[string]any, fileSha256 string, byteCount int64) ([]byte, *InferManifestModelFile) {
	t.Helper()
	encoded, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	data, err := CanonicalJson(encoded)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return data, &InferManifestModelFile{
		InferManifestFile: InferManifestFile{Name: "test-model.litertlm", ByteCount: byteCount, Sha256: fileSha256},
		IndexSha256:       hex.EncodeToString(digest[:]),
	}
}

// The members of the index of content at chunkByteCount, for a test to change.
func testInferModelIndexMembers(t *testing.T, content []byte, chunkByteCount int64) (map[string]any, string) {
	t.Helper()
	index, err := InferModelIndexBuild(bytes.NewReader(content), chunkByteCount, testInferModelIndexSmallSettings())
	if err != nil {
		t.Fatal(err)
	}
	chunks := []any{}
	for n := 0; n < index.ChunkCount(); n += 1 {
		chunk, _ := index.Chunk(n)
		chunks = append(chunks, chunk.Sha256)
	}
	return map[string]any{
		"byte_count":       len(content),
		"chunk_byte_count": chunkByteCount,
		"chunks":           chunks,
		"sha256":           index.FileSha256(),
		"version":          1,
	}, index.FileSha256()
}

// Every fault refuses, and only the whole document parses: one off its pin, not canonical, of an unknown version,
// with a size or a file hash other than the manifest's, a wrong chunk count, a malformed hash, a chunk size out of
// bounds, past its bound, or not the five members.
func TestInferModelIndexRefuses(t *testing.T) {
	settings := testInferModelIndexSmallSettings()
	settings.ModelChunkMinByteCount = 4
	settings.ModelChunkMaxByteCount = 64
	content := testInferModelIndexContent(100)
	byteCount := int64(len(content))
	good, fileSha256 := testInferModelIndexMembers(t, content, 16)
	goodData, goodFile := testInferModelIndexPinned(t, good, fileSha256, byteCount)
	if _, err := ParseInferModelIndex(goodData, goodFile, settings); err != nil {
		t.Fatalf("the whole document: %v", err)
	}

	changed := func(change func(members map[string]any)) map[string]any {
		members, _ := testInferModelIndexMembers(t, content, 16)
		change(members)
		return members
	}
	chunksOf := func(members map[string]any) []any {
		return members["chunks"].([]any)
	}
	cases := []struct {
		why     string
		members map[string]any
	}{
		{why: "an unknown version", members: changed(func(m map[string]any) { m["version"] = 2 })},
		{why: "version 0", members: changed(func(m map[string]any) { m["version"] = 0 })},
		{why: "a chunk dropped", members: changed(func(m map[string]any) { m["chunks"] = chunksOf(m)[1:] })},
		{why: "a chunk added", members: changed(func(m map[string]any) { m["chunks"] = append(chunksOf(m), chunksOf(m)[0]) })},
		{why: "a hash in capitals", members: changed(func(m map[string]any) {
			chunksOf(m)[2] = strings.ToUpper(chunksOf(m)[2].(string))
		})},
		{why: "a short hash", members: changed(func(m map[string]any) { chunksOf(m)[2] = chunksOf(m)[2].(string)[:62] })},
		{why: "a hash that is no hex", members: changed(func(m map[string]any) { chunksOf(m)[2] = strings.Repeat("g", 64) })},
		{why: "a hash that is a number", members: changed(func(m map[string]any) { chunksOf(m)[2] = 7 })},
		{why: "a chunk size under the bound", members: changed(func(m map[string]any) {
			m["chunk_byte_count"] = 2
			m["chunks"] = make([]any, 50)
		})},
		{why: "a chunk size over the bound", members: changed(func(m map[string]any) {
			m["chunk_byte_count"] = 128
			m["chunks"] = chunksOf(m)[:1]
		})},
		{why: "a chunk size of zero", members: changed(func(m map[string]any) { m["chunk_byte_count"] = 0 })},
		{why: "a fractional chunk size", members: changed(func(m map[string]any) { m["chunk_byte_count"] = 16.5 })},
		{why: "a negative byte count", members: changed(func(m map[string]any) { m["byte_count"] = -100 })},
		{why: "an unknown member", members: changed(func(m map[string]any) { m["weights"] = "open" })},
		{why: "no version", members: changed(func(m map[string]any) { delete(m, "version") })},
		{why: "no chunks", members: changed(func(m map[string]any) { delete(m, "chunks") })},
		{why: "no SHA-256", members: changed(func(m map[string]any) { delete(m, "sha256") })},
		{why: "no byte count", members: changed(func(m map[string]any) { delete(m, "byte_count") })},
		{why: "no chunk size", members: changed(func(m map[string]any) { delete(m, "chunk_byte_count") })},
		{why: "null chunks", members: changed(func(m map[string]any) { m["chunks"] = nil })},
		{why: "a version as text", members: changed(func(m map[string]any) { m["version"] = "1" })},
	}
	for _, c := range cases {
		data, file := testInferModelIndexPinned(t, c.members, fileSha256, byteCount)
		if _, err := ParseInferModelIndex(data, file, settings); !errors.Is(err, ErrInferModelIndexInvalid) {
			t.Errorf("%s: %v", c.why, err)
		}
	}

	// another size or file than the manifest's, each pinned
	for _, file := range []*InferManifestModelFile{
		{InferManifestFile: InferManifestFile{ByteCount: byteCount + 1, Sha256: fileSha256}, IndexSha256: goodFile.IndexSha256},
		{InferManifestFile: InferManifestFile{ByteCount: byteCount - 1, Sha256: fileSha256}, IndexSha256: goodFile.IndexSha256},
		{InferManifestFile: InferManifestFile{ByteCount: byteCount, Sha256: testInferSha256("another file")}, IndexSha256: goodFile.IndexSha256},
	} {
		if _, err := ParseInferModelIndex(goodData, file, settings); !errors.Is(err, ErrInferModelIndexInvalid) {
			t.Errorf("a size or file hash other than the manifest's (%d, %s): %v", file.ByteCount, file.Sha256, err)
		}
	}

	// off its pin: another pin, a malformed one, none, and the bytes changed under the pin
	for _, pin := range []string{testInferSha256("another index"), strings.ToUpper(goodFile.IndexSha256), ""} {
		file := *goodFile
		file.IndexSha256 = pin
		if _, err := ParseInferModelIndex(goodData, &file, settings); !errors.Is(err, ErrInferModelIndexInvalid) {
			t.Errorf("the index pin %q: %v", pin, err)
		}
	}
	altered := bytes.Replace(goodData, []byte(`"version":1`), []byte(`"version":2`), 1)
	if _, err := ParseInferModelIndex(altered, goodFile, settings); !errors.Is(err, ErrInferModelIndexInvalid) {
		t.Errorf("bytes changed under the pin: %v", err)
	}

	// not canonical, each pinned as it stands: indented, members out of order, a number in exponent form, an escape
	// where none is needed, and what is no single document
	indented := &bytes.Buffer{}
	if err := json.Indent(indented, goodData, "", "  "); err != nil {
		t.Fatal(err)
	}
	reordered := `{"version":1,` + strings.TrimPrefix(strings.Replace(string(goodData), `,"version":1`, "", 1), "{")
	raws := []struct {
		why  string
		data string
	}{
		{why: "indented", data: indented.String()},
		{why: "members out of order", data: reordered},
		{why: "a number in exponent form", data: strings.Replace(string(goodData), `"chunk_byte_count":16`, `"chunk_byte_count":1.6e1`, 1)},
		{why: "an escape no character needs", data: strings.Replace(string(goodData), `"sha256":"`, `"sha`+string([]byte{92, 'u', '0', '0', '3', '2'})+`56":"`, 1)},
		{why: "a trailing newline", data: string(goodData) + "\n"},
		{why: "two documents", data: string(goodData) + string(goodData)},
		{why: "a member twice", data: strings.Replace(string(goodData), `"version":1`, `"version":1,"version":1`, 1)},
		{why: "not an object", data: `[1]`},
		{why: "null", data: `null`},
		{why: "nothing", data: ``},
		{why: "invalid utf-8", data: strings.Replace(string(goodData), `"sha256"`, "\"sha256\xff\"", 1)},
	}
	for _, c := range raws {
		digest := sha256.Sum256([]byte(c.data))
		file := *goodFile
		file.IndexSha256 = hex.EncodeToString(digest[:])
		if _, err := ParseInferModelIndex([]byte(c.data), &file, settings); !errors.Is(err, ErrInferModelIndexInvalid) {
			t.Errorf("%s: %v", c.why, err)
		}
	}

	// the document's bound, before its hash: one byte under it refuses, at it parses
	bounded := testInferModelIndexSmallSettings()
	bounded.ModelChunkMinByteCount = 4
	bounded.ModelChunkMaxByteCount = 64
	bounded.ModelIndexMaxByteCount = len(goodData) - 1
	if _, err := ParseInferModelIndex(goodData, goodFile, bounded); !errors.Is(err, ErrInferModelIndexInvalid) {
		t.Errorf("a document past its bound: %v", err)
	}
	bounded.ModelIndexMaxByteCount = len(goodData)
	if _, err := ParseInferModelIndex(goodData, goodFile, bounded); err != nil {
		t.Errorf("a document at its bound: %v", err)
	}

	// the defaults' own bounds: 16 MiB chunks pass, a 512 KiB one is under ModelChunkMinByteCount
	defaults := DefaultInferSettings()
	small := testInferModelIndexContent(1024)
	for _, c := range []struct {
		chunkByteCount int64
		parses         bool
	}{{chunkByteCount: defaults.ModelChunkByteCount, parses: true}, {chunkByteCount: 512 * 1024, parses: false}} {
		members, sha := testInferModelIndexMembers(t, small, c.chunkByteCount)
		data, file := testInferModelIndexPinned(t, members, sha, int64(len(small)))
		if _, err := ParseInferModelIndex(data, file, defaults); (err == nil) != c.parses {
			t.Errorf("a chunk size of %d under the defaults: %v", c.chunkByteCount, err)
		}
	}
}

// What InferModelIndexBuild writes parses back to itself, for files on and off a chunk's edge, and each chunk tiles
// and matches the file it came from; the builder refuses a chunk size out of bounds, an index past its bound, and
// passes on a read's error.
func TestInferModelIndexBuildRoundTrips(t *testing.T) {
	settings := testInferModelIndexSmallSettings()
	for _, c := range []struct {
		byteCount      int64
		chunkByteCount int64
	}{
		{0, 7}, {1, 7}, {6, 7}, {7, 7}, {8, 7}, {70, 7}, {71, 7}, {1000, 64}, {4096, 1024}, {4097, 1024},
	} {
		content := testInferModelIndexContent(c.byteCount)
		built, err := InferModelIndexBuild(bytes.NewReader(content), c.chunkByteCount, settings)
		if err != nil {
			t.Fatalf("%d bytes at %d: %v", c.byteCount, c.chunkByteCount, err)
		}
		parsed, err := ParseInferModelIndex(built.Bytes(), testInferModelIndexFile(content, built.Bytes()), settings)
		if err != nil {
			t.Fatalf("%d bytes at %d: %v", c.byteCount, c.chunkByteCount, err)
		}
		if parsed.IndexSha256() != built.IndexSha256() || parsed.FileSha256() != built.FileSha256() ||
			parsed.ByteCount() != c.byteCount || parsed.ChunkByteCount() != c.chunkByteCount ||
			parsed.ChunkCount() != built.ChunkCount() || !bytes.Equal(parsed.Bytes(), built.Bytes()) {
			t.Fatalf("%d bytes at %d: parsed %+v, built %+v", c.byteCount, c.chunkByteCount, parsed, built)
		}
		covered := int64(0)
		for n := 0; n < parsed.ChunkCount(); n += 1 {
			chunk, ok := parsed.Chunk(n)
			builtChunk, _ := built.Chunk(n)
			if !ok || chunk.Number != n || chunk.Offset != covered || *chunk != *builtChunk {
				t.Fatalf("%d bytes at %d: chunk %d is %+v, built %+v", c.byteCount, c.chunkByteCount, n, chunk, builtChunk)
			}
			bytesOf := bytes.Clone(content[chunk.Offset : chunk.Offset+chunk.ByteCount])
			if !chunk.Matches(bytesOf) {
				t.Errorf("chunk %d does not match its bytes", n)
			}
			bytesOf[0] ^= 1
			if chunk.Matches(bytesOf) || chunk.Matches(append(bytesOf, 0)) || chunk.Matches(bytesOf[1:]) {
				t.Errorf("chunk %d matches bytes it is not", n)
			}
			covered += chunk.ByteCount
		}
		if covered != c.byteCount {
			t.Errorf("%d bytes at %d: the chunks cover %d", c.byteCount, c.chunkByteCount, covered)
		}
		if _, ok := parsed.Chunk(-1); ok {
			t.Error("a chunk before the first")
		}
		if _, ok := parsed.Chunk(parsed.ChunkCount()); ok {
			t.Error("a chunk past the last")
		}
		// a copy each time, so a caller changing one changes no index
		copied := parsed.Bytes()
		if 0 < len(copied) {
			copied[0] = 'x'
		}
		if !bytes.Equal(parsed.Bytes(), built.Bytes()) {
			t.Fatal("changing Bytes' answer changed the index")
		}
	}

	bounded := testInferModelIndexSmallSettings()
	bounded.ModelChunkMinByteCount = 4
	bounded.ModelChunkMaxByteCount = 64
	content := testInferModelIndexContent(200)
	for _, chunkByteCount := range []int64{0, -1, 3, 65} {
		if _, err := InferModelIndexBuild(bytes.NewReader(content), chunkByteCount, bounded); !errors.Is(err, ErrInferModelIndexInvalid) {
			t.Errorf("a chunk size of %d: %v", chunkByteCount, err)
		}
	}
	// an index past its bound is built nowhere, so no manifest pins one a device would refuse
	built, err := InferModelIndexBuild(bytes.NewReader(content), 4, bounded)
	if err != nil {
		t.Fatal(err)
	}
	bounded.ModelIndexMaxByteCount = len(built.Bytes()) - 1
	if _, err := InferModelIndexBuild(bytes.NewReader(content), 4, bounded); !errors.Is(err, ErrInferModelIndexInvalid) {
		t.Errorf("an index past its bound: %v", err)
	}
	// a long file stops being read once its index would pass the bound
	bounded.ModelIndexMaxByteCount = 4 * inferModelIndexChunkEntryByteCount
	counter := &testInferCountingReader{reader: bytes.NewReader(testInferModelIndexContent(4096))}
	if _, err := InferModelIndexBuild(counter, 4, bounded); !errors.Is(err, ErrInferModelIndexInvalid) {
		t.Errorf("a long file past the bound: %v", err)
	}
	if 64 < counter.byteCount {
		t.Errorf("read %d bytes of a file whose index passed its bound at its fifth chunk", counter.byteCount)
	}
	failure := errors.New("the disk went away")
	if _, err := InferModelIndexBuild(io.MultiReader(bytes.NewReader(content[:10]), &testInferFailingReader{err: failure}), 4, bounded); !errors.Is(err, failure) {
		t.Errorf("a read's error: %v", err)
	}
}

// Counts what is read through it.
type testInferCountingReader struct {
	reader    io.Reader
	byteCount int64
}

func (self *testInferCountingReader) Read(p []byte) (int, error) {
	n, err := self.reader.Read(p)
	self.byteCount += int64(n)
	return n, err
}

// Fails every read.
type testInferFailingReader struct {
	err error
}

func (self *testInferFailingReader) Read(p []byte) (int, error) {
	return 0, self.err
}
