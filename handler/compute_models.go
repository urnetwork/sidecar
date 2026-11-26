// The api's model routes (DESIGN-COMPUTE §14.3, §6.5, §14.8; CO-49; R-INFER-10, D-INFER-12): a local model file's
// chunk index and its chunks, from the api's mirror of the files the signed manifest pins, for every platform's
// downloader. Server mounts them on api (server/api/compute_models_mount.go):
//
//	GET|HEAD /compute/models/{sha256}/index        the index's bytes as the release tooling stored them
//	GET|HEAD /compute/models/{sha256}/chunks/{n}   chunk n's bytes, n decimal from 0
//
// Public, and read with no credential: the routes take no token and read none, no Authorization header and no
// cookie, so the api learns a file and an address and never a member (§2's api line). Neither the api nor a cache
// between is trusted for a byte: the device checks the index against the manifest's pin and each chunk against the
// index (§6.5). So these routes check only that what they answer is what the mirror served: the index's bytes against
// the pin the mirror's Serve checked them against, which the file's state records, and each chunk's length against
// the index.
//
// The mirror keeps each file under its SHA-256 (compute-plan-model-mirror-store, QD-1409; metadata row compute-12):
// its index, its chunks and its state, written last, which server's ComputeModelBlobStore holds over the api's blob
// store. A file answers only once its state is served, after Serve checked every chunk against the index and the
// index against the signed manifest's pin (CSRV-M11-02): a file the mirror is still writing, copied or indexed, answers
// 404 as one it does not have, so no chunk is ever answered while the mirror writes it. A served file's index and its
// chunks' hashes are kept in memory for ServedFileCacheTimeout, so a chunk's answer reads only its own object.
//
// Every answer is immutable and cacheable: Cache-Control public, max-age and immutable, a strong ETag of the index's
// or the chunk's SHA-256, Content-Length, no cookie (the router drops them) and no Vary; an If-None-Match naming the
// tag answers 304, and HEAD answers the same status and headers with no body, a chunk's from the served index without
// reading the chunk. A Range header is ignored: a chunk answers whole. A refusal is plain text with Cache-Control
// no-store, so no cache keeps a 404 for a file about to be served: 400 for a SHA-256 that is not 64 lowercase hex
// digits, a chunk number that is not a decimal from 0, or a query string, which would only split the caches' keys;
// 404 for a file not served and a chunk past the last; 429 with Retry-After past the caller address's limit; 503 with
// Retry-After where the store or the count did not answer; 500 where the mirror's objects disagree, which is logged.
//
// Each request is counted against its caller address's limit before anything is read, the index route's and the
// chunk route's apart, through a ComputeModelLimiter: server's counts the address's peppered /29 or /56 hash, never the
// address. No answer and no log line names a member, a network, a token or an address; a line names a file's SHA-256
// and a chunk number, which are public.
//
// ComputeModelRoutes is safe for concurrent use.

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// The two routes, by the limit each counts under.
const (
	ComputeModelRouteIndex = "index"
	ComputeModelRouteChunk = "chunk"
)

// A file's state in the mirror (compute-plan-model-mirror-store, QD-1409), as its state object records it: the
// mirror's own, model's, which writes it (CSRV-M11-02), so one store serves the routes and the mirror alike.
type ComputeModelFileState = model.ComputeModelFileState

const (
	// compute_model_mirror copied the file's chunks from Hugging Face at its pinned commit (§14.5)
	ComputeModelFileStateCopied = model.ComputeModelFileStateCopied
	// the release tooling computed the file's index from the copied chunks (§6.5's mirror row)
	ComputeModelFileStateIndexed = model.ComputeModelFileStateIndexed
	// Serve checked every chunk against the index and the index against the signed manifest's pin: the one state the
	// routes answer
	ComputeModelFileStateServed = model.ComputeModelFileStateServed
)

// What a file's state object records: the mirror's record, model's.
type ComputeModelFileRecord = model.ComputeModelFileRecord

// An object the mirror does not hold: a file with no state, or a missing index or chunk. The mirror's, model's.
var ErrComputeModelObjectAbsent = model.ErrComputeModelObjectAbsent

// The mirror's objects as the routes read them; server's ComputeModelBlobStore over its blob store. An opened reader
// streams its object rather than holding it whole, and its caller closes it. Safe for concurrent use.
type ComputeModelStore interface {
	// The file's state, or ErrComputeModelObjectAbsent for a file with none.
	FileRecord(ctx context.Context, sha256 string) (*ComputeModelFileRecord, error)
	// The index's bytes, or ErrComputeModelObjectAbsent.
	OpenIndex(ctx context.Context, sha256 string) (io.ReadCloser, error)
	// Chunk n's bytes, or ErrComputeModelObjectAbsent.
	OpenChunk(ctx context.Context, sha256 string, n int) (io.ReadCloser, error)
}

// One route's limit, from the settings.
type ComputeModelAddressLimit struct {
	// ComputeModelRouteIndex or ComputeModelRouteChunk: the limiter keeps each route's counts apart
	Route  string
	Window time.Duration
	Count  int64
}

// What one count decided.
type ComputeModelLimitAnswer struct {
	Allowed bool
	// for a refused request, how long until its window ends
	RetryAfter time.Duration
}

// Counts requests against their caller's address. Server's counts the address's peppered /29 or /56 hash on the
// attempt histories every public route keeps (api-3's {address_<hash>} family), under each route's own key prefix,
// never storing the address, and counts no infrastructure address. An error is a count it could not keep, which
// refuses the request. Safe for concurrent use.
type ComputeModelLimiter interface {
	// Counts request under limit, as of now.
	Count(ctx context.Context, request *http.Request, limit *ComputeModelAddressLimit, now time.Time) (*ComputeModelLimitAnswer, error)
}

// The answers' content types.
const (
	computeModelIndexContentType = "application/json"
	computeModelChunkContentType = "application/octet-stream"
)

// The refusals' plain-text bodies, fixed, so none carries anything the request sent.
const (
	computeModelRefusalMalformed   = "A model route takes a file's SHA-256, 64 lowercase hex digits, a chunk number from 0, and no query."
	computeModelRefusalNotServed   = "No such model file or chunk is served."
	computeModelRefusalLimited     = "Too many model requests from this address; retry after Retry-After."
	computeModelRefusalUnavailable = "The model mirror is unavailable; retry after Retry-After."
	computeModelRefusalInternal    = "The model mirror's objects do not agree."
	computeModelRefusalMethod      = "A model route answers GET and HEAD."
)

// The index's format version the routes read (compute-plan-model-index-format, QD-1408).
const computeModelIndexVersion = 1

// A SHA-256 in lowercase hex.
const computeModelSha256HexLength = 2 * sha256.Size

// The routes over one store and one limiter.
type ComputeModelRoutes struct {
	store    ComputeModelStore
	limiter  ComputeModelLimiter
	settings *ComputeModelRouteSettings
	clock    sidecar.Clock
	log      sidecar.Logger

	stateLock sync.Mutex
	// the served files kept in memory, by their SHA-256
	sha256ServedFiles map[string]*computeModelServedFile
}

// A served file as the routes answer it: its index's bytes, which the index route answers, and what the chunk route
// reads of it. Never changed once kept.
type computeModelServedFile struct {
	indexBytes     []byte
	indexSha256    string
	byteCount      int64
	chunkByteCount int64
	chunkSha256s   []string
	// when it was read from the store, on the routes' clock
	keepTime time.Time
}

// Chunk n's length: the chunk size, the last chunk shorter. n is within the file's chunks.
func (self *computeModelServedFile) chunkLength(n int) int64 {
	start := int64(n) * self.chunkByteCount
	return min(self.chunkByteCount, self.byteCount-start)
}

// The routes over store, counting each request through limiter. A nil settings takes the defaults, a nil clock the
// real one and a nil log none.
func NewComputeModelRoutes(store ComputeModelStore, limiter ComputeModelLimiter, settings *ComputeModelRouteSettings, clock sidecar.Clock, log sidecar.Logger) *ComputeModelRoutes {
	if settings == nil {
		settings = DefaultComputeModelRouteSettings()
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &ComputeModelRoutes{
		store:             store,
		limiter:           limiter,
		settings:          settings,
		clock:             clock,
		log:               log,
		sha256ServedFiles: map[string]*computeModelServedFile{},
	}
}

// Answers GET or HEAD /compute/models/{sha256}/index, sha256Text being the path's value as the router matched it.
func (self *ComputeModelRoutes) ServeIndex(w http.ResponseWriter, r *http.Request, sha256Text string) {
	if !self.admit(w, r, &ComputeModelAddressLimit{
		Route:  ComputeModelRouteIndex,
		Window: self.settings.IndexAddressWindow,
		Count:  self.settings.IndexAddressCount,
	}) {
		return
	}
	if !computeModelSha256Valid(sha256Text) || computeModelHasQuery(r) {
		self.refuse(w, http.StatusBadRequest, computeModelRefusalMalformed)
		return
	}
	file, status := self.servedFile(r.Context(), sha256Text)
	if file == nil {
		self.refuseStatus(w, status)
		return
	}
	etag := computeModelEtag(file.indexSha256)
	if self.answerWithoutBody(w, r, etag, computeModelIndexContentType, int64(len(file.indexBytes))) {
		return
	}
	self.writeServedHeader(w, etag, computeModelIndexContentType, int64(len(file.indexBytes)))
	w.WriteHeader(http.StatusOK)
	// a write that fails is a client gone, which nothing here can tell more
	w.Write(file.indexBytes)
}

// Answers GET or HEAD /compute/models/{sha256}/chunks/{n}, sha256Text and chunkText being the path's values as the
// router matched them.
func (self *ComputeModelRoutes) ServeChunk(w http.ResponseWriter, r *http.Request, sha256Text string, chunkText string) {
	if !self.admit(w, r, &ComputeModelAddressLimit{
		Route:  ComputeModelRouteChunk,
		Window: self.settings.ChunkAddressWindow,
		Count:  self.settings.ChunkAddressCount,
	}) {
		return
	}
	n, wellFormed, inRange := computeModelChunkNumber(chunkText)
	if !computeModelSha256Valid(sha256Text) || !wellFormed || computeModelHasQuery(r) {
		self.refuse(w, http.StatusBadRequest, computeModelRefusalMalformed)
		return
	}
	ctx := r.Context()
	file, status := self.servedFile(ctx, sha256Text)
	if file == nil {
		self.refuseStatus(w, status)
		return
	}
	if !inRange || len(file.chunkSha256s) <= n {
		self.refuse(w, http.StatusNotFound, computeModelRefusalNotServed)
		return
	}
	etag := computeModelEtag(file.chunkSha256s[n])
	chunkByteCount := file.chunkLength(n)
	if self.answerWithoutBody(w, r, etag, computeModelChunkContentType, chunkByteCount) {
		return
	}

	reader, err := self.store.OpenChunk(ctx, sha256Text, n)
	if errors.Is(err, ErrComputeModelObjectAbsent) {
		// a file no longer served has its chunks taken away; one still served without a chunk is the mirror's fault
		self.forget(sha256Text)
		record, recordErr := self.store.FileRecord(ctx, sha256Text)
		switch {
		case errors.Is(recordErr, ErrComputeModelObjectAbsent) || (recordErr == nil && (record == nil || record.State != ComputeModelFileStateServed)):
			self.refuse(w, http.StatusNotFound, computeModelRefusalNotServed)
		case recordErr != nil:
			self.refuseUnavailable(w, recordErr)
		default:
			self.log.Errorf("[compute-models]%s is served without its chunk %d\n", sha256Text, n)
			self.refuse(w, http.StatusInternalServerError, computeModelRefusalInternal)
		}
		return
	}
	if err != nil {
		self.refuseUnavailable(w, err)
		return
	}
	defer reader.Close()

	if 0 < self.settings.ChunkWriteTimeout {
		// the connection's deadline is the wall clock's, whatever clock the routes read; a writer that has no
		// deadline to set, as a test's recorder, keeps none
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(self.settings.ChunkWriteTimeout))
	}
	self.writeServedHeader(w, etag, computeModelChunkContentType, chunkByteCount)
	w.WriteHeader(http.StatusOK)
	copiedByteCount, err := io.CopyN(w, reader, chunkByteCount)
	if err != nil {
		if errors.Is(err, io.EOF) {
			self.log.Errorf("[compute-models]%s's chunk %d holds %d bytes of its index's %d\n", sha256Text, n, copiedByteCount, chunkByteCount)
		} else if self.log.V(1).Enabled() {
			self.log.Infof("[compute-models]%s's chunk %d ended after %d of %d bytes: %s\n", sha256Text, n, copiedByteCount, chunkByteCount, err)
		}
		// the answer is cut, never completed short: its Content-Length promised more
		panic(http.ErrAbortHandler)
	}
	var extra [1]byte
	if extraByteCount, _ := reader.Read(extra[:]); 0 < extraByteCount {
		// what was sent is the index entry's length; the device's check of its hash decides
		self.log.Errorf("[compute-models]%s's chunk %d holds more than its index's %d bytes\n", sha256Text, n, chunkByteCount)
	}
}

// Whether the request may be answered: a GET or a HEAD that its caller's address has room for. Otherwise it has been
// refused.
func (self *ComputeModelRoutes) admit(w http.ResponseWriter, r *http.Request, limit *ComputeModelAddressLimit) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		self.refuse(w, http.StatusMethodNotAllowed, computeModelRefusalMethod)
		return false
	}
	if limit.Window < time.Millisecond {
		self.refuseUnavailable(w, fmt.Errorf("the %s route's window is under a millisecond", limit.Route))
		return false
	}
	if limit.Count <= 0 {
		w.Header().Set("Retry-After", computeModelRetryAfterSeconds(limit.Window))
		self.refuse(w, http.StatusTooManyRequests, computeModelRefusalLimited)
		return false
	}
	answer, err := self.limiter.Count(r.Context(), r, limit, self.clock.Now())
	if err == nil && answer == nil {
		err = errors.New("the limiter gave no answer")
	}
	if err != nil {
		self.refuseUnavailable(w, err)
		return false
	}
	if !answer.Allowed {
		w.Header().Set("Retry-After", computeModelRetryAfterSeconds(answer.RetryAfter))
		self.refuse(w, http.StatusTooManyRequests, computeModelRefusalLimited)
		return false
	}
	return true
}

// The file's served form: kept, or read from the store and kept. Otherwise nil, with the status that answers it: 404
// for a file the mirror does not serve, 503 for a store that did not answer, 500 for objects that disagree.
func (self *ComputeModelRoutes) servedFile(ctx context.Context, sha256Text string) (*computeModelServedFile, int) {
	now := self.clock.Now()
	if file := self.keptFile(sha256Text, now); file != nil {
		return file, http.StatusOK
	}
	record, err := self.store.FileRecord(ctx, sha256Text)
	switch {
	case errors.Is(err, ErrComputeModelObjectAbsent):
		return nil, http.StatusNotFound
	case err != nil:
		self.logUnavailable(err)
		return nil, http.StatusServiceUnavailable
	case record == nil || record.State != ComputeModelFileStateServed:
		return nil, http.StatusNotFound
	case !computeModelSha256Valid(record.IndexSha256):
		self.log.Errorf("[compute-models]%s is served with no index pin\n", sha256Text)
		return nil, http.StatusInternalServerError
	}

	reader, err := self.store.OpenIndex(ctx, sha256Text)
	if errors.Is(err, ErrComputeModelObjectAbsent) {
		self.log.Errorf("[compute-models]%s is served without its index\n", sha256Text)
		return nil, http.StatusInternalServerError
	}
	if err != nil {
		self.logUnavailable(err)
		return nil, http.StatusServiceUnavailable
	}
	indexBytes, err := io.ReadAll(io.LimitReader(reader, max(0, self.settings.IndexMaxByteCount)+1))
	reader.Close()
	if err != nil {
		self.logUnavailable(err)
		return nil, http.StatusServiceUnavailable
	}
	if self.settings.IndexMaxByteCount < int64(len(indexBytes)) {
		self.log.Errorf("[compute-models]%s's index is past the %d bytes the routes read\n", sha256Text, self.settings.IndexMaxByteCount)
		return nil, http.StatusInternalServerError
	}
	indexDigest := sha256.Sum256(indexBytes)
	if hex.EncodeToString(indexDigest[:]) != record.IndexSha256 {
		self.log.Errorf("[compute-models]%s's index is not the one its state pins\n", sha256Text)
		return nil, http.StatusInternalServerError
	}
	document, err := computeModelReadIndex(indexBytes, sha256Text, self.settings)
	if err != nil {
		self.log.Errorf("[compute-models]%s's index does not read: %s\n", sha256Text, err)
		return nil, http.StatusInternalServerError
	}
	file := &computeModelServedFile{
		indexBytes:     indexBytes,
		indexSha256:    record.IndexSha256,
		byteCount:      document.ByteCount,
		chunkByteCount: document.ChunkByteCount,
		chunkSha256s:   document.Chunks,
		keepTime:       now,
	}
	self.keep(sha256Text, file)
	return file, http.StatusOK
}

// The kept file, unless none is kept or it was kept past ServedFileCacheTimeout, when it is dropped.
func (self *ComputeModelRoutes) keptFile(sha256Text string, now time.Time) *computeModelServedFile {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	file := self.sha256ServedFiles[sha256Text]
	if file == nil {
		return nil
	}
	if !now.Before(file.keepTime.Add(self.settings.ServedFileCacheTimeout)) {
		delete(self.sha256ServedFiles, sha256Text)
		return nil
	}
	return file
}

// Keeps file, dropping the file kept longest when ServedFileCacheCount are kept already.
func (self *ComputeModelRoutes) keep(sha256Text string, file *computeModelServedFile) {
	if self.settings.ServedFileCacheCount <= 0 || self.settings.ServedFileCacheTimeout <= 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, kept := self.sha256ServedFiles[sha256Text]; !kept && self.settings.ServedFileCacheCount <= len(self.sha256ServedFiles) {
		oldestSha256 := ""
		for keptSha256, keptFile := range self.sha256ServedFiles {
			if oldestSha256 == "" || keptFile.keepTime.Before(self.sha256ServedFiles[oldestSha256].keepTime) {
				oldestSha256 = keptSha256
			}
		}
		delete(self.sha256ServedFiles, oldestSha256)
	}
	self.sha256ServedFiles[sha256Text] = file
}

// Drops the file, so its next answer reads its state again.
func (self *ComputeModelRoutes) forget(sha256Text string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.sha256ServedFiles, sha256Text)
}

// A served answer's headers: immutable and cacheable, its strong tag, its type and its length.
func (self *ComputeModelRoutes) writeServedHeader(w http.ResponseWriter, etag string, contentType string, contentLength int64) {
	header := w.Header()
	header.Set("Cache-Control", self.cacheControl())
	header.Set("ETag", etag)
	header.Set("Content-Type", contentType)
	header.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	header.Set("X-Content-Type-Options", "nosniff")
}

// Answers a served request that takes no body, true when it did: 304 to an If-None-Match naming the tag, and the
// headers of a 200 to a HEAD.
func (self *ComputeModelRoutes) answerWithoutBody(w http.ResponseWriter, r *http.Request, etag string, contentType string, contentLength int64) bool {
	if computeModelEtagMatches(r.Header.Values("If-None-Match"), etag) {
		header := w.Header()
		header.Set("Cache-Control", self.cacheControl())
		header.Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	if r.Method == http.MethodHead {
		self.writeServedHeader(w, etag, contentType, contentLength)
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

// Cache-Control of a served answer.
func (self *ComputeModelRoutes) cacheControl() string {
	return fmt.Sprintf("public, max-age=%d, immutable", int64(max(0, self.settings.CacheMaxAge)/time.Second))
}

// A refusal: its status and a fixed plain-text body, kept by no cache.
func (self *ComputeModelRoutes) refuse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, status)
}

// The refusal of a status servedFile gave.
func (self *ComputeModelRoutes) refuseStatus(w http.ResponseWriter, status int) {
	switch status {
	case http.StatusNotFound:
		self.refuse(w, status, computeModelRefusalNotServed)
	case http.StatusServiceUnavailable:
		w.Header().Set("Retry-After", computeModelRetryAfterSeconds(self.settings.UnavailableRetryAfter))
		self.refuse(w, status, computeModelRefusalUnavailable)
	default:
		self.refuse(w, http.StatusInternalServerError, computeModelRefusalInternal)
	}
}

// 503 for a store or a count that did not answer.
func (self *ComputeModelRoutes) refuseUnavailable(w http.ResponseWriter, err error) {
	self.logUnavailable(err)
	w.Header().Set("Retry-After", computeModelRetryAfterSeconds(self.settings.UnavailableRetryAfter))
	self.refuse(w, http.StatusServiceUnavailable, computeModelRefusalUnavailable)
}

// A store or a count that did not answer, at V(1): one is a burst of them, and each names only what failed.
func (self *ComputeModelRoutes) logUnavailable(err error) {
	if self.log.V(1).Enabled() {
		self.log.Infof("[compute-models]unavailable: %s\n", err)
	}
}

// What the routes read of a served index (compute-plan-model-index-format, QD-1408: RFC 8785 canonical JSON of the
// file's byte count, the chunk size, each chunk's lowercase hex SHA-256 in order, the file's SHA-256 and the version).
// The device holds the index to the signed manifest's pin and parses it strictly (INFER-M11-10's ParseInferModelIndex);
// the mirror's Serve did the same before it served the file. This reads only what the routes answer from, each chunk's
// hash and length, and refuses an index that is not the route's file's or that names chunks its sizes do not give.
type computeModelIndexDocument struct {
	ByteCount      int64    `json:"byte_count"`
	ChunkByteCount int64    `json:"chunk_byte_count"`
	Chunks         []string `json:"chunks"`
	Sha256         string   `json:"sha256"`
	Version        int      `json:"version"`
}

// The index's document, as computeModelIndexDocument reads it.
func computeModelReadIndex(indexBytes []byte, sha256Text string, settings *ComputeModelRouteSettings) (*computeModelIndexDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(indexBytes))
	decoder.DisallowUnknownFields()
	document := &computeModelIndexDocument{}
	if err := decoder.Decode(document); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more follows the document")
	}
	switch {
	case document.Version != computeModelIndexVersion:
		return nil, fmt.Errorf("version %d", document.Version)
	case document.Sha256 != sha256Text:
		return nil, errors.New("it is another file's index")
	case document.ByteCount < 0:
		return nil, errors.New("a negative byte count")
	case document.ChunkByteCount <= 0 || settings.ChunkMaxByteCount < document.ChunkByteCount:
		return nil, fmt.Errorf("a chunk size of %d", document.ChunkByteCount)
	}
	chunkCount := document.ByteCount / document.ChunkByteCount
	if document.ByteCount%document.ChunkByteCount != 0 {
		chunkCount += 1
	}
	if int64(len(document.Chunks)) != chunkCount {
		return nil, fmt.Errorf("%d chunks where its sizes give %d", len(document.Chunks), chunkCount)
	}
	for n, chunkSha256 := range document.Chunks {
		if !computeModelSha256Valid(chunkSha256) {
			return nil, fmt.Errorf("chunk %d's hash is malformed", n)
		}
	}
	return document, nil
}

// Whether the request carries a query, an empty one ("?") included: the routes take none.
func computeModelHasQuery(r *http.Request) bool {
	return r.URL.RawQuery != "" || r.URL.ForceQuery
}

// Whether text is a SHA-256 in lowercase hex.
func computeModelSha256Valid(text string) bool {
	if len(text) != computeModelSha256HexLength {
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

// The chunk number text names: well formed for a decimal from 0 with no sign and no leading zero, and in range when
// it also fits an int, a number past that being past any file's last chunk.
func computeModelChunkNumber(text string) (n int, wellFormed bool, inRange bool) {
	if text == "" || (text[0] == '0' && 1 < len(text)) {
		return 0, false, false
	}
	for i := 0; i < len(text); i += 1 {
		if text[i] < '0' || '9' < text[i] {
			return 0, false, false
		}
	}
	n, err := strconv.Atoi(text)
	if err != nil {
		return 0, true, false
	}
	return n, true, true
}

// The strong tag of a SHA-256.
func computeModelEtag(sha256Text string) string {
	return "\"" + sha256Text + "\""
}

// Whether an If-None-Match names etag, by the weak comparison RFC 9110 gives a GET's (§13.1.2), or is "*".
func computeModelEtagMatches(ifNoneMatchValues []string, etag string) bool {
	for _, value := range ifNoneMatchValues {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
			if candidate == "*" || candidate == etag {
				return true
			}
		}
	}
	return false
}

// A Retry-After of d, in whole seconds rounded up, at least one.
func computeModelRetryAfterSeconds(d time.Duration) string {
	seconds := int64((d + time.Second - 1) / time.Second)
	return strconv.FormatInt(max(1, seconds), 10)
}
