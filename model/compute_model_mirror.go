// The api's mirror of the local model files (DESIGN-COMPUTE §14.5's compute_model_mirror, §6.5's model downloads'
// mirror row, §14.3; CO-49, D-INFER-12; CSRV-M11-02): the logic that copies each local file a manifest pins from
// Hugging Face's litert-community at its pinned commit into the api's store, computes its chunk index from the copied
// bytes for the release's tooling, and serves it only once every stored chunk checks against the index the signed
// manifest pins. The store is server's blob store (compute-plan-model-mirror-store, QD-1409; metadata row compute-12):
// one object family, compute-models/<sha256>/, which server's ComputeModelBlobStore holds:
//
//	index       the file's chunk index, the bytes sidecar's InferModelIndexBuild wrote from the mirrored chunks
//	chunks/<n>  chunk n's bytes, n decimal from 0, each InferSettings.ModelChunkByteCount long but the last
//	state       the file's record, written last: copied; indexed with its index's SHA-256; or served with it
//
// A file moves through three states, one a step of the release (§6.5):
//
//	copied   Copy streamed the file from the hub through ComputeModelFetcher, the job's one outside host, checking its
//	         size and its whole SHA-256 against the manifest as it streamed, each chunk stored as it came
//	indexed  Index read the copied chunks back and computed the index from those bytes, never from the hub's word;
//	         its SHA-256 is what the release's tooling writes into the draft manifest before the release is signed
//	served   Serve checked the stored index against the pin the signed manifest carries and every stored chunk
//	         against the index, after which CSRV-M11-01's routes answer the file (handler/compute_models.go)
//
// No route answers a file before its state is served, so a copy in flight, one that failed and one not yet indexed
// are never downloaded. The blob store has no Delete (server/blob.go), so a copy that fails, a mismatch among them,
// writes no state and deletes only its local staging: the chunks it stored stay unreferenced and unserved until a
// later copy of the file writes them again. A served file's objects never change (server refuses the write), so
// nothing moves under the routes or the caches before them.
//
// Nothing here signs a manifest, reads a member's data or names one: the files are public, kept by SHA-256.
//
// Safe for concurrent use: a mirror holds nothing of its own beyond its store and its fetcher, which are. Two copies of
// one file at once each write the bytes they checked; the job that will run Copy (CSRV-M12-05) is keyed by the file's
// SHA-256, so it runs once a file.

package model

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/urnetwork/sidecar"
)

// A file's state in the mirror, as its state object records it (compute-plan-model-mirror-store, QD-1409).
type ComputeModelFileState string

const (
	// No state object: the mirror does not hold the file. Never written; what Status reads for such a file.
	ComputeModelFileStateAbsent ComputeModelFileState = "absent"
	// compute_model_mirror copied the file's chunks from Hugging Face at its pinned commit (§14.5)
	ComputeModelFileStateCopied ComputeModelFileState = "copied"
	// the release tooling computed the file's index from the copied chunks (§6.5's mirror row)
	ComputeModelFileStateIndexed ComputeModelFileState = "indexed"
	// Serve checked every chunk against the index and the index against the signed manifest's pin: the one state the
	// routes answer
	ComputeModelFileStateServed ComputeModelFileState = "served"
)

// What a file's state object records.
type ComputeModelFileRecord struct {
	State ComputeModelFileState
	// The index's SHA-256, lowercase hex, once the file is indexed: for a served file, the pin Serve checked the
	// index against.
	IndexSha256 string
}

// An object the mirror does not hold: a file with no state, or a missing index or chunk.
var ErrComputeModelObjectAbsent = errors.New("compute model mirror: no such object")

var (
	// A mirror step refused: a file it may not copy, bytes that are not the manifest's file, a state the step does not
	// take, or an index or chunk that is not the pin's. Each refusal names the file's SHA-256 and what failed, never
	// the bytes.
	ErrComputeModelMirrorRefused = errors.New("compute model mirror refused")
	// The hub's or the store's bytes are not the manifest's file: another size or another SHA-256. Wrapped beside
	// ErrComputeModelMirrorRefused.
	ErrComputeModelMirrorMismatch = errors.New("not the manifest's file")
)

// The mirror's objects as the mirror reads and writes them: server's ComputeModelBlobStore over its blob store, whose
// read half is the routes' handler.ComputeModelStore. An opened reader streams its object, and its caller closes it.
// A Put takes the bytes of a local file. Safe for concurrent use.
type ComputeModelMirrorStore interface {
	// The file's state, or ErrComputeModelObjectAbsent for a file with none.
	FileRecord(ctx context.Context, sha256 string) (*ComputeModelFileRecord, error)
	// The index's bytes, or ErrComputeModelObjectAbsent.
	OpenIndex(ctx context.Context, sha256 string) (io.ReadCloser, error)
	// Chunk n's bytes, or ErrComputeModelObjectAbsent.
	OpenChunk(ctx context.Context, sha256 string, n int) (io.ReadCloser, error)
	// Stores the file at localPath as the file's index; refused once the file is served.
	PutIndex(ctx context.Context, sha256 string, localPath string) error
	// Stores the file at localPath as the file's chunk n; refused once the file is served.
	PutChunk(ctx context.Context, sha256 string, n int, localPath string) error
	// Writes the file's state, the last of its objects; refused once the file is served, but for the same record.
	PutFileRecord(ctx context.Context, sha256 string, record *ComputeModelFileRecord) error
}

// The mirror's settings (QD-702). DefaultComputeModelMirrorSettings is the only place a default is set. The index's
// format limits, the chunk size among them, are the format's, in sidecar.InferSettings, which the mirror reads too.
type ComputeModelMirrorSettings struct {
	// The one host a model file's url may name: huggingface.co, the hub whose litert-community repositories the
	// manifest pins (§6.5). The mirror's one outside host (§14.5).
	HubHost string
	// The one organization a model file's url may name under HubHost: litert-community (§6.5).
	HubOrganization string
	// The hosts a hub request may be redirected to besides the url's own, each matching itself and every name under
	// it: huggingface.co and hf.co, the hub's CDN, where a resolve url sends its large files. Any other is refused
	// unfollowed.
	HubRedirectHostSuffixes []string
	// The most redirects one hub request follows: 3, a resolve url's one to its CDN with room for one more. Negative
	// follows none.
	HubRedirectMaxCount int
	// How long a hub connection may take to dial: 30 s. Non-positive leaves it to the system.
	HubDialTimeout time.Duration
	// How long a hub connection's TLS handshake may take: 30 s. Non-positive sets no bound.
	HubTlsHandshakeTimeout time.Duration
	// How long the hub may take to answer a request's headers: 60 s, its CDN being slow to start a large file at
	// times. Non-positive sets no bound.
	HubResponseHeaderTimeout time.Duration
	// How long a read of the hub's answer may bring no byte before the request is cut: 2 minutes. The mirror reads a
	// cut as a failed read and resumes. Non-positive sets no bound.
	HubReadIdleTimeout time.Duration
	// How many failed hub requests or reads in a row a copy takes before it stops, each followed by a wait of
	// HubRetryInterval and a request from the start of the chunk the failure cut, the count starting again at each
	// chunk stored: 5. Zero tries once; negative is zero. A refusal, the hub's file not being the manifest's among
	// them, is never retried.
	HubRetryCount int
	// The wait before a failed hub request or read is tried again: 10 s. Non-positive tries again at once.
	HubRetryInterval time.Duration

	// The most a copy of one file may take, its hub reads and its stores together: 12 hours, the largest launch file,
	// about 16 GB, at under half a megabyte a second. Non-positive sets no bound.
	CopyTimeout time.Duration
	// The most Index may take over one file, reading its chunks back: 2 hours, 16 GB at over 2 MB a second.
	// Non-positive sets no bound.
	IndexTimeout time.Duration
	// The most Serve may take over one file, reading its index and every chunk: 2 hours, as IndexTimeout.
	// Non-positive sets no bound.
	ServeTimeout time.Duration
	// Where a copy stages a chunk, and Index its index, before the store takes it from a local file: empty for the
	// system's temporary directory. A copy holds one chunk there at a time.
	StagingDirectory string

	// The largest SHA256SUMS the release tooling reads: 1 MiB, a line of about 90 bytes for each of a release's few
	// dozen files many times over. A larger one is refused unread.
	ReleaseSumsMaxByteCount int64
	// The largest SHA256SUMS.sig it reads: 64 KiB, an armored SSHSIG of an RSA key of 16384 bits with room to spare.
	// A larger one is refused unread.
	ReleaseSignatureMaxByteCount int64
}

// The mirror's defaults.
func DefaultComputeModelMirrorSettings() *ComputeModelMirrorSettings {
	return &ComputeModelMirrorSettings{
		HubHost:                      "huggingface.co",
		HubOrganization:              "litert-community",
		HubRedirectHostSuffixes:      []string{"huggingface.co", "hf.co"},
		HubRedirectMaxCount:          3,
		HubDialTimeout:               30 * time.Second,
		HubTlsHandshakeTimeout:       30 * time.Second,
		HubResponseHeaderTimeout:     60 * time.Second,
		HubReadIdleTimeout:           2 * time.Minute,
		HubRetryCount:                5,
		HubRetryInterval:             10 * time.Second,
		CopyTimeout:                  12 * time.Hour,
		IndexTimeout:                 2 * time.Hour,
		ServeTimeout:                 2 * time.Hour,
		StagingDirectory:             "",
		ReleaseSumsMaxByteCount:      1024 * 1024,
		ReleaseSignatureMaxByteCount: 64 * 1024,
	}
}

// The mirror over one store, copying through one fetcher.
type ComputeModelMirror struct {
	store         ComputeModelMirrorStore
	fetcher       ComputeModelFetcher
	settings      *ComputeModelMirrorSettings
	inferSettings *sidecar.InferSettings
	clock         sidecar.Clock
	log           sidecar.Logger
}

// The mirror over store, copying through fetcher. A nil settings or inferSettings takes the defaults, a nil clock the
// real one and a nil log none.
func NewComputeModelMirror(store ComputeModelMirrorStore, fetcher ComputeModelFetcher, settings *ComputeModelMirrorSettings, inferSettings *sidecar.InferSettings, clock sidecar.Clock, log sidecar.Logger) *ComputeModelMirror {
	if settings == nil {
		settings = DefaultComputeModelMirrorSettings()
	}
	if inferSettings == nil {
		inferSettings = sidecar.DefaultInferSettings()
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &ComputeModelMirror{
		store:         store,
		fetcher:       fetcher,
		settings:      settings,
		inferSettings: inferSettings,
		clock:         clock,
		log:           log,
	}
}

// A refusal naming what failed, wrapping ErrComputeModelMirrorRefused.
func computeModelMirrorRefusal(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrComputeModelMirrorRefused, fmt.Sprintf(format, a...))
}

// A refusal for bytes that are not the manifest's file, wrapping both errors.
func computeModelMirrorMismatch(format string, a ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrComputeModelMirrorRefused, ErrComputeModelMirrorMismatch, fmt.Sprintf(format, a...))
}

// Whether text is a SHA-256 in lowercase hex.
func computeModelSha256Valid(text string) bool {
	if len(text) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(text); i += 1 {
		c := text[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// ctx bounded by timeout where it is positive.
func computeModelMirrorBound(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// The file's state: its record, or one of ComputeModelFileStateAbsent where it has none.
func (self *ComputeModelMirror) Status(ctx context.Context, sha256Text string) (*ComputeModelFileRecord, error) {
	if !computeModelSha256Valid(sha256Text) {
		return nil, computeModelMirrorRefusal("%q is no lowercase hex SHA-256", sha256Text)
	}
	record, err := self.store.FileRecord(ctx, sha256Text)
	if errors.Is(err, ErrComputeModelObjectAbsent) {
		return &ComputeModelFileRecord{State: ComputeModelFileStateAbsent}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("compute model mirror: %s's state does not read: %w", sha256Text, err)
	}
	if record == nil {
		return nil, fmt.Errorf("compute model mirror: %s's state read as nothing", sha256Text)
	}
	return record, nil
}

// Copies file, a local model file a manifest names, into the mirror unless the mirror holds it already, in any state:
// the file's record after, and whether this call copied it. The copy streams the file from the hub at the url's pinned
// commit, refusing a url that pins none, checks its size and SHA-256 against the manifest's as it streams, and stores
// it chunk by chunk, writing its state copied only once the whole file checked. A mismatch, or any other failure,
// writes no state.
func (self *ComputeModelMirror) Copy(ctx context.Context, file *sidecar.InferManifestModelFile) (*ComputeModelFileRecord, bool, error) {
	if file == nil {
		return nil, false, computeModelMirrorRefusal("no file")
	}
	record, err := self.Status(ctx, file.Sha256)
	if err != nil {
		return nil, false, err
	}
	if record.State != ComputeModelFileStateAbsent {
		return record, false, nil
	}
	if err := self.copyFile(ctx, file); err != nil {
		return nil, false, err
	}
	return &ComputeModelFileRecord{State: ComputeModelFileStateCopied}, true, nil
}

// As Copy, but copying again a file the mirror holds copied or indexed, as after Index found its stored chunks are
// not the manifest's file; a served file's objects are final, so one is refused. The file's state reads copied after,
// whatever index it had.
func (self *ComputeModelMirror) Recopy(ctx context.Context, file *sidecar.InferManifestModelFile) (*ComputeModelFileRecord, error) {
	if file == nil {
		return nil, computeModelMirrorRefusal("no file")
	}
	record, err := self.Status(ctx, file.Sha256)
	if err != nil {
		return nil, err
	}
	if record.State == ComputeModelFileStateServed {
		return nil, computeModelMirrorRefusal("%s is served, and a served file's objects are final", file.Sha256)
	}
	if err := self.copyFile(ctx, file); err != nil {
		return nil, err
	}
	return &ComputeModelFileRecord{State: ComputeModelFileStateCopied}, nil
}

// The chunk size the mirror stores at, InferSettings.ModelChunkByteCount, refused outside the format's bounds, and
// the file's chunk count at it.
func (self *ComputeModelMirror) chunking(file *sidecar.InferManifestModelFile) (int64, int, error) {
	chunkByteCount := self.inferSettings.ModelChunkByteCount
	if chunkByteCount <= 0 || chunkByteCount < self.inferSettings.ModelChunkMinByteCount || self.inferSettings.ModelChunkMaxByteCount < chunkByteCount {
		return 0, 0, computeModelMirrorRefusal("a chunk size of %d bytes, outside %d to %d", chunkByteCount,
			self.inferSettings.ModelChunkMinByteCount, self.inferSettings.ModelChunkMaxByteCount)
	}
	if file.ByteCount <= 0 || self.inferSettings.ManifestFileMaxByteCount < file.ByteCount {
		return 0, 0, computeModelMirrorRefusal("%s's size of %d bytes, outside 1 to %d", file.Sha256, file.ByteCount,
			self.inferSettings.ManifestFileMaxByteCount)
	}
	chunkCount := file.ByteCount / chunkByteCount
	if file.ByteCount%chunkByteCount != 0 {
		chunkCount += 1
	}
	return chunkByteCount, int(chunkCount), nil
}

// The copy itself: every chunk from the hub into the store, then the state copied once the whole file checked.
func (self *ComputeModelMirror) copyFile(ctx context.Context, file *sidecar.InferManifestModelFile) error {
	if !computeModelSha256Valid(file.Sha256) {
		return computeModelMirrorRefusal("%q is no lowercase hex SHA-256", file.Sha256)
	}
	hubUrl, err := ComputeModelHubFileUrl(file.Url, self.settings)
	if err != nil {
		return fmt.Errorf("%s: %w", file.Sha256, err)
	}
	chunkByteCount, chunkCount, err := self.chunking(file)
	if err != nil {
		return err
	}
	ctx, cancel := computeModelMirrorBound(ctx, self.settings.CopyTimeout)
	defer cancel()

	stagingDirectory, err := os.MkdirTemp(self.settings.StagingDirectory, "compute-model-copy-*")
	if err != nil {
		return fmt.Errorf("compute model mirror: no staging for %s: %w", file.Sha256, err)
	}
	defer os.RemoveAll(stagingDirectory)
	stagingPath := filepath.Join(stagingDirectory, "chunk")

	source := &computeModelHubSource{
		mirror: self,
		ctx:    ctx,
		hubUrl: hubUrl,
		file:   file,
	}
	defer source.close()
	fileHash := sha256.New()
	for n := 0; n < chunkCount; n += 1 {
		offset := int64(n) * chunkByteCount
		if err := source.readChunk(n, offset, min(chunkByteCount, file.ByteCount-offset), stagingPath, fileHash); err != nil {
			return err
		}
		if err := self.store.PutChunk(ctx, file.Sha256, n, stagingPath); err != nil {
			return fmt.Errorf("compute model mirror: %s's chunk %d does not store: %w", file.Sha256, n, err)
		}
	}
	if err := source.end(); err != nil {
		return err
	}
	if hex.EncodeToString(fileHash.Sum(nil)) != file.Sha256 {
		return computeModelMirrorMismatch("the hub's bytes for %s hash to another SHA-256", file.Sha256)
	}
	if err := self.store.PutFileRecord(ctx, file.Sha256, &ComputeModelFileRecord{State: ComputeModelFileStateCopied}); err != nil {
		return fmt.Errorf("compute model mirror: %s's state does not store: %w", file.Sha256, err)
	}
	if self.log.V(1).Enabled() {
		self.log.Infof("[compute-models]copied %s, %d bytes in %d chunks\n", file.Sha256, file.ByteCount, chunkCount)
	}
	return nil
}

// One copy's reads of the hub: one request at a time, opened at the start and again from the start of the chunk a
// failure cut, for at most HubRetryCount failures in a row. Not safe for concurrent use.
type computeModelHubSource struct {
	mirror *ComputeModelMirror
	ctx    context.Context
	hubUrl string
	file   *sidecar.InferManifestModelFile
	// the open answer, read up to the chunk the copy is at, or nil
	body io.ReadCloser
}

// A failed hub request or read that a later one may not meet: a timeout, a cut connection, a 5xx.
type computeModelTransientError struct {
	err error
}

// Names the cause.
func (self *computeModelTransientError) Error() string {
	return self.err.Error()
}

// The cause.
func (self *computeModelTransientError) Unwrap() error {
	return self.err
}

// Closes the open answer, if any.
func (self *computeModelHubSource) close() {
	if self.body != nil {
		self.body.Close()
		self.body = nil
	}
}

// Reads chunk n's byteCount bytes at offset into stagingPath and fileHash. A failed request or read closes the
// answer, sets fileHash back to the chunk's start and, after HubRetryInterval, asks the hub again from offset, until
// HubRetryCount failures in a row; a refusal stops at once.
func (self *computeModelHubSource) readChunk(n int, offset int64, byteCount int64, stagingPath string, fileHash hash.Hash) error {
	chunkStart, err := fileHash.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return err
	}
	settings := self.mirror.settings
	failureCount := 0
	for {
		err := self.tryChunk(offset, byteCount, stagingPath, fileHash)
		if err == nil {
			return nil
		}
		transient := &computeModelTransientError{}
		if !errors.As(err, &transient) {
			return err
		}
		self.close()
		if err := fileHash.(encoding.BinaryUnmarshaler).UnmarshalBinary(chunkStart); err != nil {
			return err
		}
		if ctxErr := self.ctx.Err(); ctxErr != nil {
			return fmt.Errorf("compute model mirror: %s's copy stopped at chunk %d: %w", self.file.Sha256, n, ctxErr)
		}
		failureCount += 1
		if max(0, settings.HubRetryCount) < failureCount {
			return fmt.Errorf("compute model mirror: %s's chunk %d failed %d times in a row: %w", self.file.Sha256, n, failureCount, transient.err)
		}
		if self.mirror.log.V(1).Enabled() {
			self.mirror.log.Infof("[compute-models]%s's chunk %d is asked of the hub again after: %s\n", self.file.Sha256, n, transient.err)
		}
		if 0 < settings.HubRetryInterval {
			select {
			case <-self.ctx.Done():
				return fmt.Errorf("compute model mirror: %s's copy stopped at chunk %d: %w", self.file.Sha256, n, self.ctx.Err())
			case <-self.mirror.clock.After(settings.HubRetryInterval):
			}
		}
	}
}

// One attempt at a chunk: the hub asked from offset where no answer is open, then byteCount bytes of it staged and
// hashed. A failed request or read is a computeModelTransientError; a refusal or a local fault is not.
func (self *computeModelHubSource) tryChunk(offset int64, byteCount int64, stagingPath string, fileHash hash.Hash) error {
	if self.body == nil {
		body, hubByteCount, err := self.mirror.fetcher.Open(self.ctx, self.hubUrl, offset)
		if err != nil {
			if errors.Is(err, ErrComputeModelFetchRefused) || self.ctx.Err() != nil {
				return fmt.Errorf("compute model mirror: %s: %w", self.file.Sha256, err)
			}
			return &computeModelTransientError{err: err}
		}
		if hubByteCount != self.file.ByteCount {
			body.Close()
			return computeModelMirrorMismatch("the hub declares %s as %d bytes, the manifest %d", self.file.Sha256, hubByteCount, self.file.ByteCount)
		}
		self.body = body
	}
	staged, err := os.Create(stagingPath)
	if err != nil {
		return fmt.Errorf("compute model mirror: no staging for %s: %w", self.file.Sha256, err)
	}
	hub := &computeModelReadFault{reader: self.body}
	copiedByteCount, copyErr := io.CopyN(io.MultiWriter(staged, fileHash), hub, byteCount)
	closeErr := staged.Close()
	switch {
	case errors.Is(copyErr, io.EOF):
		return computeModelMirrorMismatch("the hub's %s ends at %d bytes, short of the manifest's %d", self.file.Sha256, offset+copiedByteCount, self.file.ByteCount)
	case copyErr != nil && self.ctx.Err() != nil:
		return fmt.Errorf("compute model mirror: %s: %w", self.file.Sha256, self.ctx.Err())
	case copyErr != nil && hub.err != nil:
		return &computeModelTransientError{err: copyErr}
	case copyErr != nil:
		// the staging's write failed, which another request from the hub would not mend
		return fmt.Errorf("compute model mirror: %s's staging does not write: %w", self.file.Sha256, copyErr)
	case closeErr != nil:
		return fmt.Errorf("compute model mirror: %s's staging does not write: %w", self.file.Sha256, closeErr)
	}
	return nil
}

// A reader that keeps the last error its reads met other than io.EOF, so a failed copy tells the hub's fault from
// the staging's. Not safe for concurrent use.
type computeModelReadFault struct {
	reader io.Reader
	err    error
}

// The reader's next bytes.
func (self *computeModelReadFault) Read(out []byte) (int, error) {
	readByteCount, err := self.reader.Read(out)
	if err != nil && !errors.Is(err, io.EOF) {
		self.err = err
	}
	return readByteCount, err
}

// Nil when the hub's answer ends where the manifest's size does: a byte past it is a file longer than the manifest's.
func (self *computeModelHubSource) end() error {
	if self.body == nil {
		return nil
	}
	var extra [1]byte
	if extraByteCount, _ := io.ReadFull(self.body, extra[:]); 0 < extraByteCount {
		return computeModelMirrorMismatch("the hub's %s runs past the manifest's %d bytes", self.file.Sha256, self.file.ByteCount)
	}
	return nil
}

// The file as the mirror stores it, its chunks read back one after another, each to exactly the length its number
// gives at chunkByteCount, so the bytes Index hashes are the ones the routes answer chunk by chunk. A chunk absent,
// short or long is an error. Not safe for concurrent use.
type computeModelStoredFile struct {
	ctx            context.Context
	store          ComputeModelMirrorStore
	file           *sidecar.InferManifestModelFile
	chunkByteCount int64
	chunkCount     int
	// the chunk being read, and what is left of it
	n         int
	reader    io.ReadCloser
	remaining int64
}

// The next bytes of the stored file.
func (self *computeModelStoredFile) Read(out []byte) (int, error) {
	for {
		if self.reader == nil {
			if self.chunkCount <= self.n {
				return 0, io.EOF
			}
			reader, err := self.store.OpenChunk(self.ctx, self.file.Sha256, self.n)
			if errors.Is(err, ErrComputeModelObjectAbsent) {
				return 0, computeModelMirrorRefusal("%s's chunk %d is not stored", self.file.Sha256, self.n)
			}
			if err != nil {
				return 0, fmt.Errorf("compute model mirror: %s's chunk %d does not read: %w", self.file.Sha256, self.n, err)
			}
			self.reader = reader
			self.remaining = min(self.chunkByteCount, self.file.ByteCount-int64(self.n)*self.chunkByteCount)
		}
		if self.remaining == 0 {
			var extra [1]byte
			extraByteCount, _ := io.ReadFull(self.reader, extra[:])
			self.reader.Close()
			self.reader = nil
			if 0 < extraByteCount {
				return 0, computeModelMirrorMismatch("%s's stored chunk %d is longer than its %d bytes", self.file.Sha256, self.n,
					min(self.chunkByteCount, self.file.ByteCount-int64(self.n)*self.chunkByteCount))
			}
			self.n += 1
			continue
		}
		if len(out) == 0 {
			return 0, nil
		}
		readByteCount, err := self.reader.Read(out[:min(int64(len(out)), self.remaining)])
		self.remaining -= int64(readByteCount)
		switch {
		case errors.Is(err, io.EOF) && 0 < self.remaining:
			return readByteCount, computeModelMirrorMismatch("%s's stored chunk %d is short of its length", self.file.Sha256, self.n)
		case err != nil && !errors.Is(err, io.EOF):
			return readByteCount, fmt.Errorf("compute model mirror: %s's chunk %d does not read: %w", self.file.Sha256, self.n, err)
		}
		// a chunk read to its end is checked for more at the next read
		return readByteCount, nil
	}
}

// Closes the chunk being read, if any.
func (self *computeModelStoredFile) Close() {
	if self.reader != nil {
		self.reader.Close()
		self.reader = nil
	}
}

// The file's index, as the release's tooling needs it for the draft manifest: its SHA-256, the pin. A copied file's is
// computed from the chunks the mirror stored, with sidecar's InferModelIndexBuild, the one encoder, and stored, the
// file's state then indexed; an indexed or served file's is the stored one, read back and checked against its state's
// pin and the file. The index comes from the mirrored bytes, never from the hub's word: stored chunks that are not the
// manifest's file, by size or SHA-256, are refused, writing nothing, and the file wants Recopy.
func (self *ComputeModelMirror) Index(ctx context.Context, file *sidecar.InferManifestModelFile) (string, error) {
	if file == nil {
		return "", computeModelMirrorRefusal("no file")
	}
	record, err := self.Status(ctx, file.Sha256)
	if err != nil {
		return "", err
	}
	chunkByteCount, chunkCount, err := self.chunking(file)
	if err != nil {
		return "", err
	}
	ctx, cancel := computeModelMirrorBound(ctx, self.settings.IndexTimeout)
	defer cancel()
	switch record.State {
	case ComputeModelFileStateAbsent:
		return "", computeModelMirrorRefusal("%s is not copied", file.Sha256)
	case ComputeModelFileStateIndexed, ComputeModelFileStateServed:
		if _, err := self.storedIndex(ctx, file, record.IndexSha256); err != nil {
			return "", err
		}
		return record.IndexSha256, nil
	case ComputeModelFileStateCopied:
	default:
		return "", computeModelMirrorRefusal("%s's state is %q", file.Sha256, record.State)
	}

	stored := &computeModelStoredFile{
		ctx:            ctx,
		store:          self.store,
		file:           file,
		chunkByteCount: chunkByteCount,
		chunkCount:     chunkCount,
	}
	index, err := sidecar.InferModelIndexBuild(stored, chunkByteCount, self.inferSettings)
	stored.Close()
	if err != nil {
		return "", fmt.Errorf("compute model mirror: %s's index: %w", file.Sha256, err)
	}
	if index.ByteCount() != file.ByteCount || index.FileSha256() != file.Sha256 {
		return "", computeModelMirrorMismatch("the stored chunks of %s are %d bytes hashing to another file than the manifest's", file.Sha256, index.ByteCount())
	}
	indexSha256 := index.IndexSha256()
	// the index as every device will read it, under the pin the manifest will carry
	pinned := *file
	pinned.IndexSha256 = indexSha256
	if _, err := sidecar.ParseInferModelIndex(index.Bytes(), &pinned, self.inferSettings); err != nil {
		return "", fmt.Errorf("compute model mirror: %s's index: %w", file.Sha256, err)
	}

	stagingDirectory, err := os.MkdirTemp(self.settings.StagingDirectory, "compute-model-index-*")
	if err != nil {
		return "", fmt.Errorf("compute model mirror: no staging for %s: %w", file.Sha256, err)
	}
	defer os.RemoveAll(stagingDirectory)
	stagingPath := filepath.Join(stagingDirectory, "index")
	if err := os.WriteFile(stagingPath, index.Bytes(), 0o600); err != nil {
		return "", fmt.Errorf("compute model mirror: %s's index does not stage: %w", file.Sha256, err)
	}
	if err := self.store.PutIndex(ctx, file.Sha256, stagingPath); err != nil {
		return "", fmt.Errorf("compute model mirror: %s's index does not store: %w", file.Sha256, err)
	}
	if err := self.store.PutFileRecord(ctx, file.Sha256, &ComputeModelFileRecord{State: ComputeModelFileStateIndexed, IndexSha256: indexSha256}); err != nil {
		return "", fmt.Errorf("compute model mirror: %s's state does not store: %w", file.Sha256, err)
	}
	if self.log.V(1).Enabled() {
		self.log.Infof("[compute-models]indexed %s as %s\n", file.Sha256, indexSha256)
	}
	return indexSha256, nil
}

// The stored index of file, read within the format's bound and parsed as a device parses it under pin: its SHA-256 is
// the pin, it is canonical, and it describes the manifest's file.
func (self *ComputeModelMirror) storedIndex(ctx context.Context, file *sidecar.InferManifestModelFile, pin string) (*sidecar.InferModelIndex, error) {
	if !computeModelSha256Valid(pin) {
		return nil, computeModelMirrorRefusal("%s's index pin %q is no lowercase hex SHA-256", file.Sha256, pin)
	}
	reader, err := self.store.OpenIndex(ctx, file.Sha256)
	if errors.Is(err, ErrComputeModelObjectAbsent) {
		return nil, computeModelMirrorRefusal("%s's index is not stored", file.Sha256)
	}
	if err != nil {
		return nil, fmt.Errorf("compute model mirror: %s's index does not read: %w", file.Sha256, err)
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(max(0, self.inferSettings.ModelIndexMaxByteCount))+1))
	reader.Close()
	if err != nil {
		return nil, fmt.Errorf("compute model mirror: %s's index does not read: %w", file.Sha256, err)
	}
	pinned := *file
	pinned.IndexSha256 = pin
	index, err := sidecar.ParseInferModelIndex(data, &pinned, self.inferSettings)
	if err != nil {
		return nil, computeModelMirrorRefusal("%s's stored index is not the one pinned: %s", file.Sha256, err)
	}
	return index, nil
}

// Serves file, a local model file of a released manifest whose signature the caller checked, so its IndexSha256 is
// the pin the signed manifest carries: the stored index is checked against that pin, every stored chunk against the
// index, by length and SHA-256, and only then is the file's state written served, after which the routes answer it.
// A file indexed under another pin, or not indexed, is refused, as is any chunk that does not check, which the
// refusal names; nothing is written then. A file served already under the pin is served again as a no-op.
func (self *ComputeModelMirror) Serve(ctx context.Context, file *sidecar.InferManifestModelFile) error {
	if file == nil {
		return computeModelMirrorRefusal("no file")
	}
	pin := file.IndexSha256
	if !computeModelSha256Valid(pin) {
		return computeModelMirrorRefusal("%s carries no index pin", file.Sha256)
	}
	record, err := self.Status(ctx, file.Sha256)
	if err != nil {
		return err
	}
	switch record.State {
	case ComputeModelFileStateAbsent, ComputeModelFileStateCopied:
		return computeModelMirrorRefusal("%s is %s, not indexed", file.Sha256, record.State)
	case ComputeModelFileStateServed:
		if record.IndexSha256 == pin {
			return nil
		}
		return computeModelMirrorRefusal("%s is served under the index %s, not the signed manifest's %s", file.Sha256, record.IndexSha256, pin)
	case ComputeModelFileStateIndexed:
		if record.IndexSha256 != pin {
			return computeModelMirrorRefusal("%s is indexed as %s, not the signed manifest's %s", file.Sha256, record.IndexSha256, pin)
		}
	default:
		return computeModelMirrorRefusal("%s's state is %q", file.Sha256, record.State)
	}
	ctx, cancel := computeModelMirrorBound(ctx, self.settings.ServeTimeout)
	defer cancel()
	index, err := self.storedIndex(ctx, file, pin)
	if err != nil {
		return err
	}
	for n := 0; n < index.ChunkCount(); n += 1 {
		chunk, _ := index.Chunk(n)
		if err := self.checkChunk(ctx, file, chunk); err != nil {
			return err
		}
	}
	if err := self.store.PutFileRecord(ctx, file.Sha256, &ComputeModelFileRecord{State: ComputeModelFileStateServed, IndexSha256: pin}); err != nil {
		return fmt.Errorf("compute model mirror: %s's state does not store: %w", file.Sha256, err)
	}
	if self.log.V(1).Enabled() {
		self.log.Infof("[compute-models]served %s under %s\n", file.Sha256, pin)
	}
	return nil
}

// Nil when the stored chunk is the index's: its length, nothing past it, and its SHA-256, hashed as it streams.
func (self *ComputeModelMirror) checkChunk(ctx context.Context, file *sidecar.InferManifestModelFile, chunk *sidecar.InferModelChunk) error {
	reader, err := self.store.OpenChunk(ctx, file.Sha256, chunk.Number)
	if errors.Is(err, ErrComputeModelObjectAbsent) {
		return computeModelMirrorRefusal("%s's chunk %d is not stored", file.Sha256, chunk.Number)
	}
	if err != nil {
		return fmt.Errorf("compute model mirror: %s's chunk %d does not read: %w", file.Sha256, chunk.Number, err)
	}
	defer reader.Close()
	chunkHash := sha256.New()
	copiedByteCount, err := io.CopyN(chunkHash, reader, chunk.ByteCount)
	if errors.Is(err, io.EOF) {
		return computeModelMirrorRefusal("%s's stored chunk %d holds %d bytes of its index's %d", file.Sha256, chunk.Number, copiedByteCount, chunk.ByteCount)
	}
	if err != nil {
		return fmt.Errorf("compute model mirror: %s's chunk %d does not read: %w", file.Sha256, chunk.Number, err)
	}
	var extra [1]byte
	if extraByteCount, _ := io.ReadFull(reader, extra[:]); 0 < extraByteCount {
		return computeModelMirrorRefusal("%s's stored chunk %d holds more than its index's %d bytes", file.Sha256, chunk.Number, chunk.ByteCount)
	}
	if hex.EncodeToString(chunkHash.Sum(nil)) != chunk.Sha256 {
		return computeModelMirrorRefusal("%s's stored chunk %d is not the index's", file.Sha256, chunk.Number)
	}
	return nil
}
