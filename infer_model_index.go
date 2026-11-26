//go:build !ios_extension && !sidecar_http

// A local model file's chunk index (DESIGN-COMPUTE §6.5's model downloads, §6.3's local fields; CO-49, R-INFER-10,
// D-INFER-12): the one document per file every platform's download checks each chunk against, whose SHA-256 the
// signed manifest pins as the file's index_sha256 beside the file's own SHA-256 and size, so neither the api nor a
// cache between is trusted for a byte. Its bytes are compute-plan-model-index-format's (QD-1408): RFC 8785 canonical
// JSON of
//
//	{"byte_count":<the file's size>,"chunk_byte_count":<the chunk size>,"chunks":["<lowercase hex SHA-256>",...],
//	 "sha256":"<the file's lowercase hex SHA-256>","version":1}
//
// with chunk n covering [n × chunk_byte_count, min((n + 1) × chunk_byte_count, byte_count)), so every chunk but the
// last is chunk_byte_count long, the last is that or shorter, and a file of no bytes has no chunk.
//
// InferModelIndexBuild is the one encoder: the release tooling computes each file's index with it from the api's
// mirrored bytes before the manifest is signed (CSRV-M11-02), the mirror's check uses it, and testdata/infer/index/'s
// vectors are its output, which the browser's engine Worker's tests read too (INFER-M13-02). ParseInferModelIndex is
// the one reader: it hashes the bytes as received and checks the pin before anything else, then parses strictly, so
// an index is trusted only through its pin, never because the api, a cache or a kept copy answered it. Both are total
// and bounded by the format's limits, ModelIndexMaxByteCount, ModelChunkMinByteCount and ModelChunkMaxByteCount, which
// every end reads from InferSettings (QD-702). A refusal names the first fault and never the document's bytes.
//
// An index is read only, so safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// The format's version, which the document's version member carries.
const inferModelIndexVersion = 1

// The largest integer a JSON number carries exactly, 2^53 - 1 (ECMAScript's Number.MAX_SAFE_INTEGER): RFC 8785
// writes a number as the double nearest it, so a byte count past this has no canonical form that reads back as
// itself.
const inferModelIndexMaxExactInteger = 9007199254740991

// What one chunk's entry adds to a document at least: its 64 hex digits, two quotes and a comma.
const inferModelIndexChunkEntryByteCount = 2*sha256.Size + 3

// An index that does not parse, is off its pin, or does not describe the file the manifest names; or a file no index
// can be built for. The message names the first fault, never the document's bytes.
var ErrInferModelIndexInvalid = errors.New("model index refused")

// A file's chunk index, as ParseInferModelIndex read it or InferModelIndexBuild wrote it.
type InferModelIndex struct {
	byteCount      int64
	chunkByteCount int64
	// the file's SHA-256, lowercase hex
	sha256       string
	chunkDigests [][sha256.Size]byte
	// the document's canonical bytes, and their SHA-256 in lowercase hex: what the manifest pins
	data        []byte
	indexSha256 string
}

// One chunk of a file, as its index gives it.
type InferModelChunk struct {
	// Its number, from 0.
	Number int
	// Where it starts in the file, in bytes.
	Offset int64
	// Its length, in bytes: the index's chunk size, the last chunk's that or less.
	ByteCount int64
	// Its SHA-256, in lowercase hex.
	Sha256 string
	digest [sha256.Size]byte
}

// Whether data is this chunk: its length, and its SHA-256.
func (self *InferModelChunk) Matches(data []byte) bool {
	return int64(len(data)) == self.ByteCount && sha256.Sum256(data) == self.digest
}

// The document's members, by their RFC 8785 order. Pointers, so a parse tells a member left out, or null, from a
// zero.
type inferModelIndexDocument struct {
	ByteCount      *int64    `json:"byte_count"`
	ChunkByteCount *int64    `json:"chunk_byte_count"`
	Chunks         *[]string `json:"chunks"`
	Sha256         *string   `json:"sha256"`
	Version        *int      `json:"version"`
}

// An index fault, wrapping ErrInferModelIndexInvalid.
func inferModelIndexFault(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInferModelIndexInvalid, fmt.Sprintf(format, a...))
}

// The index of the file reader holds, read to its end, in chunks of chunkByteCount, which must lie within the
// settings' ModelChunkMinByteCount and ModelChunkMaxByteCount (the release's is ModelChunkByteCount). Refused with
// ErrInferModelIndexInvalid for a chunk size out of bounds and for a file whose index would pass
// ModelIndexMaxByteCount, which it stops reading at, so every index it builds parses; a read's error is returned as
// it is. It reads the file once, holding one chunk's hash state at a time and never a chunk.
func InferModelIndexBuild(reader io.Reader, chunkByteCount int64, settings *InferSettings) (*InferModelIndex, error) {
	if chunkByteCount <= 0 || chunkByteCount < settings.ModelChunkMinByteCount || settings.ModelChunkMaxByteCount < chunkByteCount {
		return nil, inferModelIndexFault("a chunk size of %d bytes, outside %d to %d", chunkByteCount,
			settings.ModelChunkMinByteCount, settings.ModelChunkMaxByteCount)
	}
	fileHash := sha256.New()
	chunkHash := sha256.New()
	both := io.MultiWriter(fileHash, chunkHash)
	digests := [][sha256.Size]byte{}
	byteCount := int64(0)
	for {
		chunkHash.Reset()
		copied, err := io.CopyN(both, reader, chunkByteCount)
		if 0 < copied {
			digests = append(digests, [sha256.Size]byte(chunkHash.Sum(nil)))
			byteCount += copied
			// bounded before the file is read further: each entry takes at least its hex and its punctuation
			if settings.ModelIndexMaxByteCount < len(digests)*inferModelIndexChunkEntryByteCount {
				return nil, inferModelIndexFault("a file whose index passes %d bytes", settings.ModelIndexMaxByteCount)
			}
			if inferModelIndexMaxExactInteger < byteCount {
				return nil, inferModelIndexFault("a file past %d bytes", int64(inferModelIndexMaxExactInteger))
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("model index build: %w", err)
		}
	}
	data, err := inferModelIndexEncode(byteCount, chunkByteCount, hex.EncodeToString(fileHash.Sum(nil)), digests)
	if err != nil {
		return nil, err
	}
	if settings.ModelIndexMaxByteCount < len(data) {
		return nil, inferModelIndexFault("a file whose index passes %d bytes", settings.ModelIndexMaxByteCount)
	}
	indexDigest := sha256.Sum256(data)
	return &InferModelIndex{
		byteCount:      byteCount,
		chunkByteCount: chunkByteCount,
		sha256:         hex.EncodeToString(fileHash.Sum(nil)),
		chunkDigests:   digests,
		data:           data,
		indexSha256:    hex.EncodeToString(indexDigest[:]),
	}, nil
}

// The canonical document of an index's fields.
func inferModelIndexEncode(byteCount int64, chunkByteCount int64, fileSha256 string, digests [][sha256.Size]byte) ([]byte, error) {
	chunks := make([]string, 0, len(digests))
	for _, digest := range digests {
		chunks = append(chunks, hex.EncodeToString(digest[:]))
	}
	version := inferModelIndexVersion
	encoded, err := json.Marshal(&inferModelIndexDocument{
		ByteCount:      &byteCount,
		ChunkByteCount: &chunkByteCount,
		Chunks:         &chunks,
		Sha256:         &fileSha256,
		Version:        &version,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: does not encode", ErrInferModelIndexInvalid)
	}
	// RFC 8785's form: the members sorted, no space, the numbers as ECMAScript writes them
	return CanonicalJson(encoded)
}

// The index data holds for file, refused with ErrInferModelIndexInvalid unless, in this order: data is at most the
// settings' ModelIndexMaxByteCount; its SHA-256 is the file's index_sha256, the manifest's pin; it is one canonical
// RFC 8785 document, its bytes exactly what canonicalization writes; it has the five members and no other, of this
// version; its SHA-256 and byte count are the manifest's; its chunk size lies within ModelChunkMinByteCount and
// ModelChunkMaxByteCount; it lists as many chunks as the byte count over the chunk size, rounded up; and every
// chunk's hash is a lowercase hex SHA-256. file's pins are read as they stand, with no check of their own, so a file
// whose pins are not well formed matches no index.
func ParseInferModelIndex(data []byte, file *InferManifestModelFile, settings *InferSettings) (*InferModelIndex, error) {
	if settings.ModelIndexMaxByteCount < len(data) {
		return nil, inferModelIndexFault("longer than %d bytes", settings.ModelIndexMaxByteCount)
	}
	digest := sha256.Sum256(data)
	indexSha256 := hex.EncodeToString(digest[:])
	if !inferManifestSha256Pattern.MatchString(file.IndexSha256) || indexSha256 != file.IndexSha256 {
		return nil, inferModelIndexFault("off its pin")
	}
	canonical, err := CanonicalJson(data)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, inferModelIndexFault("not canonical")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	document := &inferModelIndexDocument{}
	if err := decoder.Decode(document); err != nil {
		return nil, inferModelIndexFault("does not decode")
	}
	switch {
	case document.Version == nil:
		return nil, inferModelIndexFault("no version")
	case *document.Version != inferModelIndexVersion:
		return nil, inferModelIndexFault("version %d, not %d", *document.Version, inferModelIndexVersion)
	case document.ByteCount == nil || document.ChunkByteCount == nil || document.Chunks == nil || document.Sha256 == nil:
		return nil, inferModelIndexFault("a member missing")
	case *document.Sha256 != file.Sha256:
		return nil, inferModelIndexFault("another file's SHA-256")
	case *document.ByteCount < 0 || *document.ByteCount != file.ByteCount:
		return nil, inferModelIndexFault("a byte count other than the manifest's")
	}
	byteCount := *document.ByteCount
	chunkByteCount := *document.ChunkByteCount
	if chunkByteCount <= 0 || chunkByteCount < settings.ModelChunkMinByteCount || settings.ModelChunkMaxByteCount < chunkByteCount {
		return nil, inferModelIndexFault("a chunk size of %d bytes, outside %d to %d", chunkByteCount,
			settings.ModelChunkMinByteCount, settings.ModelChunkMaxByteCount)
	}
	chunkCount := byteCount / chunkByteCount
	if byteCount%chunkByteCount != 0 {
		chunkCount += 1
	}
	chunks := *document.Chunks
	if int64(len(chunks)) != chunkCount {
		return nil, inferModelIndexFault("%d chunks where its sizes give %d", len(chunks), chunkCount)
	}
	digests := make([][sha256.Size]byte, 0, len(chunks))
	for n, chunk := range chunks {
		if !inferManifestSha256Pattern.MatchString(chunk) {
			return nil, inferModelIndexFault("chunk %d's hash is not a lowercase hex SHA-256", n)
		}
		decoded, err := hex.DecodeString(chunk)
		if err != nil {
			return nil, inferModelIndexFault("chunk %d's hash is not a lowercase hex SHA-256", n)
		}
		digests = append(digests, [sha256.Size]byte(decoded))
	}
	return &InferModelIndex{
		byteCount:      byteCount,
		chunkByteCount: chunkByteCount,
		sha256:         *document.Sha256,
		chunkDigests:   digests,
		data:           bytes.Clone(data),
		indexSha256:    indexSha256,
	}, nil
}

// The file's size, in bytes.
func (self *InferModelIndex) ByteCount() int64 {
	return self.byteCount
}

// The chunk size, in bytes.
func (self *InferModelIndex) ChunkByteCount() int64 {
	return self.chunkByteCount
}

// How many chunks the file has.
func (self *InferModelIndex) ChunkCount() int {
	return len(self.chunkDigests)
}

// The file's SHA-256, in lowercase hex.
func (self *InferModelIndex) FileSha256() string {
	return self.sha256
}

// The document's SHA-256, in lowercase hex: the pin a manifest carries as index_sha256.
func (self *InferModelIndex) IndexSha256() string {
	return self.indexSha256
}

// The document's canonical bytes, a copy: what the api serves and the pin covers.
func (self *InferModelIndex) Bytes() []byte {
	return bytes.Clone(self.data)
}

// The offset, length and hash of chunk n; false for an n outside the file's chunks.
func (self *InferModelIndex) Chunk(n int) (*InferModelChunk, bool) {
	if n < 0 || len(self.chunkDigests) <= n {
		return nil, false
	}
	offset := int64(n) * self.chunkByteCount
	digest := self.chunkDigests[n]
	return &InferModelChunk{
		Number:    n,
		Offset:    offset,
		ByteCount: min(self.chunkByteCount, self.byteCount-offset),
		Sha256:    hex.EncodeToString(digest[:]),
		digest:    digest,
	}, true
}
