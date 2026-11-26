package handler

// The model routes (CSRV-M11-01; DESIGN-COMPUTE §14.3, §6.5, CO-49) over a fake mirror and a fake limiter: an index
// served as stored and a chunk's bytes, each with its immutable headers, HEAD and If-None-Match; a file the mirror is
// writing and a chunk past the last answering 404; malformed requests 400; the limit's 429 and a count not kept 503,
// each route under its own limit; a token, a cookie and none answered alike; a served file read once and kept; and
// mirror objects that disagree answering 500, never served.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// A file as the mirror holds it: its bytes in chunks, its index and the state written last.
type testComputeModelFile struct {
	sha256      string
	data        []byte
	chunks      [][]byte
	chunkHashes []string
	index       []byte
	indexSha256 string
}

// The file data cut into chunks of chunkByteCount, with its index in QD-1408's bytes: the canonical JSON that
// encoding/json writes of these members in this order.
func newTestComputeModelFile(t *testing.T, data []byte, chunkByteCount int64) *testComputeModelFile {
	t.Helper()
	digest := sha256.Sum256(data)
	file := &testComputeModelFile{sha256: hex.EncodeToString(digest[:]), data: data}
	for start := int64(0); start < int64(len(data)); start += chunkByteCount {
		chunk := data[start:min(start+chunkByteCount, int64(len(data)))]
		chunkDigest := sha256.Sum256(chunk)
		file.chunks = append(file.chunks, chunk)
		file.chunkHashes = append(file.chunkHashes, hex.EncodeToString(chunkDigest[:]))
	}
	index, err := json.Marshal(&computeModelIndexDocument{
		ByteCount:      int64(len(data)),
		ChunkByteCount: chunkByteCount,
		Chunks:         append([]string{}, file.chunkHashes...),
		Sha256:         file.sha256,
		Version:        computeModelIndexVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	file.index = index
	indexDigest := sha256.Sum256(index)
	file.indexSha256 = hex.EncodeToString(indexDigest[:])
	return file
}

// The mirror, in memory, counting what the routes read. Safe for concurrent use.
type testComputeModelStore struct {
	stateLock sync.Mutex
	records   map[string]*ComputeModelFileRecord
	indexes   map[string][]byte
	chunks    map[string][][]byte
	// a read of any object answers this, when set
	failure error

	recordReadCount int
	indexReadCount  int
	chunkReadCount  int
}

func newTestComputeModelStore() *testComputeModelStore {
	return &testComputeModelStore{
		records: map[string]*ComputeModelFileRecord{},
		indexes: map[string][]byte{},
		chunks:  map[string][][]byte{},
	}
}

// Puts file's chunks and index in the mirror under state; any state but copied pins the file's index.
func (self *testComputeModelStore) put(file *testComputeModelFile, state ComputeModelFileState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.chunks[file.sha256] = file.chunks
	if state == ComputeModelFileStateCopied {
		self.records[file.sha256] = &ComputeModelFileRecord{State: state}
		return
	}
	self.indexes[file.sha256] = file.index
	self.records[file.sha256] = &ComputeModelFileRecord{State: state, IndexSha256: file.indexSha256}
}

func (self *testComputeModelStore) reads() (recordReadCount int, indexReadCount int, chunkReadCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.recordReadCount, self.indexReadCount, self.chunkReadCount
}

func (self *testComputeModelStore) FileRecord(ctx context.Context, sha256Text string) (*ComputeModelFileRecord, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.recordReadCount += 1
	if self.failure != nil {
		return nil, self.failure
	}
	record, ok := self.records[sha256Text]
	if !ok {
		return nil, ErrComputeModelObjectAbsent
	}
	copied := *record
	return &copied, nil
}

func (self *testComputeModelStore) OpenIndex(ctx context.Context, sha256Text string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.indexReadCount += 1
	if self.failure != nil {
		return nil, self.failure
	}
	index, ok := self.indexes[sha256Text]
	if !ok {
		return nil, ErrComputeModelObjectAbsent
	}
	return io.NopCloser(bytes.NewReader(index)), nil
}

func (self *testComputeModelStore) OpenChunk(ctx context.Context, sha256Text string, n int) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.chunkReadCount += 1
	if self.failure != nil {
		return nil, self.failure
	}
	chunks := self.chunks[sha256Text]
	if n < 0 || len(chunks) <= n || chunks[n] == nil {
		return nil, ErrComputeModelObjectAbsent
	}
	return io.NopCloser(bytes.NewReader(chunks[n])), nil
}

// A limiter answering by a function, recording each limit it was asked under.
type testComputeModelLimiter struct {
	stateLock sync.Mutex
	limits    []ComputeModelAddressLimit
	nows      []time.Time
	answer    func(request *http.Request, limit *ComputeModelAddressLimit) (*ComputeModelLimitAnswer, error)
}

func (self *testComputeModelLimiter) Count(ctx context.Context, request *http.Request, limit *ComputeModelAddressLimit, now time.Time) (*ComputeModelLimitAnswer, error) {
	self.stateLock.Lock()
	self.limits = append(self.limits, *limit)
	self.nows = append(self.nows, now)
	answer := self.answer
	self.stateLock.Unlock()
	if answer == nil {
		return &ComputeModelLimitAnswer{Allowed: true}, nil
	}
	return answer(request, limit)
}

func (self *testComputeModelLimiter) counted() []ComputeModelAddressLimit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.limits)
}

// The routes over store and limiter on a fake clock.
type testComputeModelFixture struct {
	store   *testComputeModelStore
	limiter *testComputeModelLimiter
	clock   *sidecartest.FakeClock
	routes  *ComputeModelRoutes
}

func newTestComputeModelFixture(t *testing.T, settings *ComputeModelRouteSettings) *testComputeModelFixture {
	t.Helper()
	fixture := &testComputeModelFixture{
		store:   newTestComputeModelStore(),
		limiter: &testComputeModelLimiter{},
		clock:   sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
	}
	fixture.routes = NewComputeModelRoutes(fixture.store, fixture.limiter, settings, fixture.clock, nil)
	return fixture
}

// Serves method on the index route of sha256Text, with the header's lines set.
func (self *testComputeModelFixture) serveIndex(method string, sha256Text string, query string, header map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/compute/models/"+url.PathEscape(sha256Text)+"/index"+query, nil)
	request.RemoteAddr = "198.51.100.10:4000"
	for name, value := range header {
		request.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	self.routes.ServeIndex(w, request, sha256Text)
	return w
}

// Serves method on the chunk route of sha256Text and chunkText, with the header's lines set.
func (self *testComputeModelFixture) serveChunk(method string, sha256Text string, chunkText string, query string, header map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/compute/models/"+url.PathEscape(sha256Text)+"/chunks/"+url.PathEscape(chunkText)+query, nil)
	request.RemoteAddr = "198.51.100.10:4000"
	for name, value := range header {
		request.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	self.routes.ServeChunk(w, request, sha256Text, chunkText)
	return w
}

// A served answer's headers, all of them: no cookie, no Vary.
func testComputeModelServedHeaders(t *testing.T, w *httptest.ResponseRecorder, etag string, contentType string, contentLength int) {
	t.Helper()
	header := w.Result().Header
	want := map[string]string{
		"Cache-Control":          "public, max-age=31536000, immutable",
		"Etag":                   "\"" + etag + "\"",
		"Content-Type":           contentType,
		"Content-Length":         strconv.Itoa(contentLength),
		"X-Content-Type-Options": "nosniff",
	}
	for name, value := range want {
		if got := header.Values(name); len(got) != 1 || got[0] != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	for name := range header {
		if _, wanted := want[name]; !wanted {
			t.Errorf("a served answer carries %s: %q", name, header.Values(name))
		}
	}
}

// A refusal: its status, a plain-text body and no cache keeping it.
func testComputeModelRefusal(t *testing.T, w *httptest.ResponseRecorder, status int, what string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("%s: status = %d %q, want %d", what, w.Code, w.Body.String(), status)
	}
	if got := w.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("%s: Cache-Control = %q, want no-store", what, got)
	}
	if got := w.Result().Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("%s: Content-Type = %q", what, got)
	}
	if w.Result().Header.Get("ETag") != "" {
		t.Errorf("%s carries an ETag", what)
	}
}

// 1,000 bytes with no two chunks alike.
func testComputeModelData() []byte {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}
	return data
}

// The index route answers the bytes the release tooling stored, byte for byte, with the immutable headers and the
// index's SHA-256 as its tag; HEAD answers the same headers and no body; an If-None-Match naming the tag answers 304.
func TestComputeModelIndexServedAsStored(t *testing.T) {
	fixture := newTestComputeModelFixture(t, nil)
	file := newTestComputeModelFile(t, testComputeModelData(), 400)
	fixture.store.put(file, ComputeModelFileStateServed)

	w := fixture.serveIndex(http.MethodGet, file.sha256, "", nil)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), file.index) {
		t.Fatalf("GET: %d %q, want the stored index %q", w.Code, w.Body.String(), file.index)
	}
	testComputeModelServedHeaders(t, w, file.indexSha256, "application/json", len(file.index))

	head := fixture.serveIndex(http.MethodHead, file.sha256, "", nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD: %d with %d bytes", head.Code, head.Body.Len())
	}
	testComputeModelServedHeaders(t, head, file.indexSha256, "application/json", len(file.index))

	for _, ifNoneMatch := range []string{"\"" + file.indexSha256 + "\"", "W/\"" + file.indexSha256 + "\"", "\"other\", \"" + file.indexSha256 + "\"", "*"} {
		w := fixture.serveIndex(http.MethodGet, file.sha256, "", map[string]string{"If-None-Match": ifNoneMatch})
		if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
			t.Fatalf("If-None-Match %s: %d with %d bytes", ifNoneMatch, w.Code, w.Body.Len())
		}
		if w.Result().Header.Get("ETag") != "\""+file.indexSha256+"\"" || w.Result().Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("If-None-Match %s: headers %v", ifNoneMatch, w.Result().Header)
		}
	}
	if w := fixture.serveIndex(http.MethodGet, file.sha256, "", map[string]string{"If-None-Match": "\"other\""}); w.Code != http.StatusOK {
		t.Fatalf("an If-None-Match naming another tag: %d", w.Code)
	}
}

// Each chunk answers its bytes, the last one shorter, with its own SHA-256 as its tag and its own length; HEAD answers
// the same headers from the served index without reading the chunk; an If-None-Match naming the chunk's tag answers
// 304; a Range header changes nothing.
func TestComputeModelChunkBytesAndHeaders(t *testing.T) {
	fixture := newTestComputeModelFixture(t, nil)
	file := newTestComputeModelFile(t, testComputeModelData(), 400)
	fixture.store.put(file, ComputeModelFileStateServed)
	if len(file.chunks) != 3 || len(file.chunks[2]) != 200 {
		t.Fatalf("the file has %d chunks", len(file.chunks))
	}

	for n, chunk := range file.chunks {
		chunkText := strconv.Itoa(n)
		w := fixture.serveChunk(http.MethodGet, file.sha256, chunkText, "", map[string]string{"Range": "bytes=0-9"})
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), chunk) {
			t.Fatalf("chunk %d: %d with %d bytes, want its %d", n, w.Code, w.Body.Len(), len(chunk))
		}
		testComputeModelServedHeaders(t, w, file.chunkHashes[n], "application/octet-stream", len(chunk))

		_, _, chunkReadCount := fixture.store.reads()
		head := fixture.serveChunk(http.MethodHead, file.sha256, chunkText, "", nil)
		if head.Code != http.StatusOK || head.Body.Len() != 0 {
			t.Fatalf("HEAD chunk %d: %d with %d bytes", n, head.Code, head.Body.Len())
		}
		testComputeModelServedHeaders(t, head, file.chunkHashes[n], "application/octet-stream", len(chunk))
		if _, _, after := fixture.store.reads(); after != chunkReadCount {
			t.Fatalf("HEAD chunk %d read the chunk", n)
		}

		notModified := fixture.serveChunk(http.MethodGet, file.sha256, chunkText, "", map[string]string{"If-None-Match": "\"" + file.chunkHashes[n] + "\""})
		if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 {
			t.Fatalf("chunk %d If-None-Match: %d with %d bytes", n, notModified.Code, notModified.Body.Len())
		}
	}
	var whole []byte
	for n := range file.chunks {
		whole = append(whole, fixture.serveChunk(http.MethodGet, file.sha256, strconv.Itoa(n), "", nil).Body.Bytes()...)
	}
	if !bytes.Equal(whole, file.data) {
		t.Fatal("the chunks do not make the file")
	}
}

// A file the mirror is writing, copied or indexed but not yet served, answers 404 on both routes as one it does not
// have, as does a file it has none of; no index or chunk of it is read.
func TestComputeModelUnservedFileAnswers404(t *testing.T) {
	fixture := newTestComputeModelFixture(t, nil)
	copied := newTestComputeModelFile(t, testComputeModelData(), 400)
	indexed := newTestComputeModelFile(t, testComputeModelData()[:900], 400)
	absent := newTestComputeModelFile(t, testComputeModelData()[:800], 400)
	fixture.store.put(copied, ComputeModelFileStateCopied)
	fixture.store.put(indexed, ComputeModelFileStateIndexed)

	for _, file := range []*testComputeModelFile{copied, indexed, absent} {
		testComputeModelRefusal(t, fixture.serveIndex(http.MethodGet, file.sha256, "", nil), http.StatusNotFound, "an unserved file's index")
		testComputeModelRefusal(t, fixture.serveIndex(http.MethodHead, file.sha256, "", nil), http.StatusNotFound, "an unserved file's index by HEAD")
		testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, file.sha256, "0", "", nil), http.StatusNotFound, "an unserved file's chunk")
	}
	if _, indexReadCount, chunkReadCount := fixture.store.reads(); indexReadCount != 0 || chunkReadCount != 0 {
		t.Fatalf("an unserved file's objects were read: %d indexes, %d chunks", indexReadCount, chunkReadCount)
	}

	// once served, the same file answers
	fixture.store.put(indexed, ComputeModelFileStateServed)
	if w := fixture.serveChunk(http.MethodGet, indexed.sha256, "2", "", nil); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), indexed.chunks[2]) {
		t.Fatalf("the file once served: %d", w.Code)
	}
}

// A chunk number past the file's last answers 404, a number past any int's range included; the file's chunks before
// it answer.
func TestComputeModelChunkPastLastAnswers404(t *testing.T) {
	fixture := newTestComputeModelFixture(t, nil)
	file := newTestComputeModelFile(t, testComputeModelData(), 400)
	fixture.store.put(file, ComputeModelFileStateServed)
	empty := newTestComputeModelFile(t, nil, 400)
	fixture.store.put(empty, ComputeModelFileStateServed)

	for _, chunkText := range []string{"3", "4", "1000000", "99999999999999999999999999"} {
		testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, file.sha256, chunkText, "", nil), http.StatusNotFound, "chunk "+chunkText)
		testComputeModelRefusal(t, fixture.serveChunk(http.MethodHead, file.sha256, chunkText, "", nil), http.StatusNotFound, "HEAD chunk "+chunkText)
	}
	// a file of no bytes has an index and no chunk
	if w := fixture.serveIndex(http.MethodGet, empty.sha256, "", nil); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), empty.index) {
		t.Fatalf("the empty file's index: %d", w.Code)
	}
	testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, empty.sha256, "0", "", nil), http.StatusNotFound, "the empty file's chunk 0")
	if w := fixture.serveChunk(http.MethodGet, file.sha256, "2", "", nil); w.Code != http.StatusOK {
		t.Fatalf("the last chunk: %d", w.Code)
	}
}

// A SHA-256 that is not 64 lowercase hex digits, a chunk number that is not a decimal from 0, or any query string
// answers 400 before the mirror is read; the request still counts against its address.
func TestComputeModelMalformedAnswers400(t *testing.T) {
	fixture := newTestComputeModelFixture(t, nil)
	file := newTestComputeModelFile(t, testComputeModelData(), 400)
	fixture.store.put(file, ComputeModelFileStateServed)

	for _, sha256Text := range []string{
		strings.ToUpper(file.sha256), file.sha256[:63], file.sha256 + "0", strings.Repeat("g", 64), "", "..", "x",
	} {
		testComputeModelRefusal(t, fixture.serveIndex(http.MethodGet, sha256Text, "", nil), http.StatusBadRequest, "index "+sha256Text)
		testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, sha256Text, "0", "", nil), http.StatusBadRequest, "chunk of "+sha256Text)
	}
	for _, chunkText := range []string{"", "-1", "+1", "01", "00", "1a", "0x1", " 1", "1.0", "x"} {
		testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, file.sha256, chunkText, "", nil), http.StatusBadRequest, "chunk "+strconv.Quote(chunkText))
	}
	testComputeModelRefusal(t, fixture.serveIndex(http.MethodGet, file.sha256, "?v=1", nil), http.StatusBadRequest, "an index with a query")
	testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, file.sha256, "0", "?", nil), http.StatusBadRequest, "a chunk with an empty query")
	testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, file.sha256, "0", "?v=1", nil), http.StatusBadRequest, "a chunk with a query")

	if recordReadCount, indexReadCount, chunkReadCount := fixture.store.reads(); recordReadCount != 0 || indexReadCount != 0 || chunkReadCount != 0 {
		t.Fatalf("a malformed request read the mirror: %d states, %d indexes, %d chunks", recordReadCount, indexReadCount, chunkReadCount)
	}
	if counted := len(fixture.limiter.counted()); counted != 2*7+10+3 {
		t.Fatalf("counted %d malformed requests, want every one", counted)
	}
	// another method is no route's
	request := httptest.NewRequest(http.MethodPost, "/compute/models/"+file.sha256+"/index", nil)
	w := httptest.NewRecorder()
	fixture.routes.ServeIndex(w, request, file.sha256)
	testComputeModelRefusal(t, w, http.StatusMethodNotAllowed, "POST")
}

// Each request counts under its route's own limit, from the settings, at the routes' clock's time, before the mirror
// is read: past it the route answers 429 with the limiter's Retry-After in whole seconds, rounded up; a count the
// limiter could not keep answers 503 with the settings' Retry-After; a limit of no requests refuses every one and a
// window under a millisecond answers 503, neither asking the limiter. Nothing of the mirror is read for any of them.
func TestComputeModelLimitRefusesBeforeTheMirror(t *testing.T) {
	settings := DefaultComputeModelRouteSettings()
	settings.IndexAddressWindow = 2 * time.Minute
	settings.IndexAddressCount = 7
	settings.ChunkAddressWindow = 3 * time.Minute
	settings.ChunkAddressCount = 11
	fixture := newTestComputeModelFixture(t, settings)
	file := newTestComputeModelFile(t, testComputeModelData(), 400)
	fixture.store.put(file, ComputeModelFileStateServed)

	fixture.serveIndex(http.MethodGet, file.sha256, "", nil)
	fixture.serveChunk(http.MethodHead, file.sha256, "1", "", nil)
	counted := fixture.limiter.counted()
	want := []ComputeModelAddressLimit{
		{Route: ComputeModelRouteIndex, Window: 2 * time.Minute, Count: 7},
		{Route: ComputeModelRouteChunk, Window: 3 * time.Minute, Count: 11},
	}
	if !slices.Equal(counted, want) {
		t.Fatalf("counted under %v, want %v", counted, want)
	}
	if !fixture.limiter.nows[0].Equal(fixture.clock.Now()) {
		t.Fatalf("counted at %s, want the routes' clock's %s", fixture.limiter.nows[0], fixture.clock.Now())
	}
	recordReadCount, indexReadCount, chunkReadCount := fixture.store.reads()

	fixture.limiter.answer = func(request *http.Request, limit *ComputeModelAddressLimit) (*ComputeModelLimitAnswer, error) {
		return &ComputeModelLimitAnswer{Allowed: false, RetryAfter: 41*time.Second + time.Millisecond}, nil
	}
	for _, w := range []*httptest.ResponseRecorder{
		fixture.serveIndex(http.MethodGet, file.sha256, "", nil),
		fixture.serveChunk(http.MethodGet, file.sha256, "0", "", nil),
		fixture.serveChunk(http.MethodGet, "malformed", "x", "", nil),
	} {
		testComputeModelRefusal(t, w, http.StatusTooManyRequests, "past the limit")
		if got := w.Result().Header.Get("Retry-After"); got != "42" {
			t.Fatalf("Retry-After = %q, want 42", got)
		}
	}
	fixture.limiter.answer = func(request *http.Request, limit *ComputeModelAddressLimit) (*ComputeModelLimitAnswer, error) {
		return nil, errors.New("the count's store did not answer")
	}
	for _, w := range []*httptest.ResponseRecorder{
		fixture.serveIndex(http.MethodGet, file.sha256, "", nil),
		fixture.serveChunk(http.MethodGet, file.sha256, "0", "", nil),
	} {
		testComputeModelRefusal(t, w, http.StatusServiceUnavailable, "a count not kept")
		if got := w.Result().Header.Get("Retry-After"); got != "5" {
			t.Fatalf("Retry-After = %q, want the settings' 5", got)
		}
	}
	if after, indexAfter, chunkAfter := fixture.store.reads(); after != recordReadCount || indexAfter != indexReadCount || chunkAfter != chunkReadCount {
		t.Fatal("a refused request read the mirror")
	}

	fixture.limiter.answer = nil
	askedCount := len(fixture.limiter.counted())
	closed := DefaultComputeModelRouteSettings()
	closed.ChunkAddressCount = 0
	closed.IndexAddressWindow = time.Microsecond
	closedFixture := &testComputeModelFixture{store: fixture.store, limiter: fixture.limiter, clock: fixture.clock}
	closedFixture.routes = NewComputeModelRoutes(fixture.store, fixture.limiter, closed, fixture.clock, nil)
	refused := closedFixture.serveChunk(http.MethodGet, file.sha256, "0", "", nil)
	testComputeModelRefusal(t, refused, http.StatusTooManyRequests, "a limit of no requests")
	if got := refused.Result().Header.Get("Retry-After"); got != "60" {
		t.Fatalf("a closed route's Retry-After = %q, want its window's 60", got)
	}
	testComputeModelRefusal(t, closedFixture.serveIndex(http.MethodGet, file.sha256, "", nil), http.StatusServiceUnavailable, "a window under a millisecond")
	if len(fixture.limiter.counted()) != askedCount {
		t.Fatal("a closed route asked the limiter")
	}
}

// The routes never read a credential: a sidecar's bearer, a malformed one, an API key and a cookie are answered
// exactly as a request with none, on both routes, and the limiter is handed the request as it came.
func TestComputeModelTokenNotRead(t *testing.T) {
	fixture := newTestComputeModelFixture(t, nil)
	file := newTestComputeModelFile(t, testComputeModelData(), 400)
	fixture.store.put(file, ComputeModelFileStateServed)
	unserved := newTestComputeModelFile(t, testComputeModelData()[:10], 4)

	credentials := []map[string]string{
		nil,
		{"Authorization": "Bearer eyJhbGciOiJFZERTQSJ9.eyJzdHJpY3RfZXhwIjp0cnVlfQ.c2lnbmF0dXJl"},
		{"Authorization": "Bearer not-a-token"},
		{"Authorization": "Bearer urn_" + strings.Repeat("k", 52)},
		{"Cookie": "by_jwt=eyJhbGciOiJFZERTQSJ9.e30.c2ln"},
	}
	answer := func(w *httptest.ResponseRecorder) string {
		header := w.Result().Header.Clone()
		return strconv.Itoa(w.Code) + " " + strings.Join(func() []string {
			lines := []string{}
			for name, values := range header {
				lines = append(lines, name+"="+strings.Join(values, ","))
			}
			slices.Sort(lines)
			return lines
		}(), ";") + " " + hex.EncodeToString(w.Body.Bytes())
	}
	requests := []func(header map[string]string) *httptest.ResponseRecorder{
		func(header map[string]string) *httptest.ResponseRecorder {
			return fixture.serveIndex(http.MethodGet, file.sha256, "", header)
		},
		func(header map[string]string) *httptest.ResponseRecorder {
			return fixture.serveChunk(http.MethodGet, file.sha256, "1", "", header)
		},
		func(header map[string]string) *httptest.ResponseRecorder {
			return fixture.serveChunk(http.MethodHead, file.sha256, "2", "", header)
		},
		func(header map[string]string) *httptest.ResponseRecorder {
			return fixture.serveIndex(http.MethodGet, unserved.sha256, "", header)
		},
	}
	for i, request := range requests {
		bare := answer(request(nil))
		for _, header := range credentials[1:] {
			if got := answer(request(header)); got != bare {
				t.Fatalf("request %d with %v: %s, want as with none: %s", i, header, got, bare)
			}
		}
	}
}

// A served file's state and index are read once and kept: a download's chunk requests read only their chunks until
// ServedFileCacheTimeout passes on the routes' clock, when the state is read again; past ServedFileCacheCount files
// the one kept longest is dropped; with no files kept every answer reads the state.
func TestComputeModelServedFileKept(t *testing.T) {
	settings := DefaultComputeModelRouteSettings()
	settings.ServedFileCacheCount = 2
	settings.ServedFileCacheTimeout = time.Minute
	fixture := newTestComputeModelFixture(t, settings)
	files := []*testComputeModelFile{
		newTestComputeModelFile(t, testComputeModelData(), 400),
		newTestComputeModelFile(t, testComputeModelData()[:900], 400),
		newTestComputeModelFile(t, testComputeModelData()[:800], 400),
	}
	for _, file := range files {
		fixture.store.put(file, ComputeModelFileStateServed)
	}

	for range 5 {
		for n := range files[0].chunks {
			if w := fixture.serveChunk(http.MethodGet, files[0].sha256, strconv.Itoa(n), "", nil); w.Code != http.StatusOK {
				t.Fatalf("chunk %d: %d", n, w.Code)
			}
		}
		fixture.serveIndex(http.MethodGet, files[0].sha256, "", nil)
	}
	if recordReadCount, indexReadCount, chunkReadCount := fixture.store.reads(); recordReadCount != 1 || indexReadCount != 1 || chunkReadCount != 15 {
		t.Fatalf("read %d states, %d indexes and %d chunks, want 1, 1 and 15", recordReadCount, indexReadCount, chunkReadCount)
	}

	fixture.clock.Advance(time.Minute)
	fixture.serveIndex(http.MethodGet, files[0].sha256, "", nil)
	if recordReadCount, indexReadCount, _ := fixture.store.reads(); recordReadCount != 2 || indexReadCount != 2 {
		t.Fatalf("past the timeout: read %d states and %d indexes, want 2 and 2", recordReadCount, indexReadCount)
	}

	// two more files: the third drops the one kept longest, files[0]
	fixture.clock.Advance(time.Second)
	fixture.serveIndex(http.MethodGet, files[1].sha256, "", nil)
	fixture.clock.Advance(time.Second)
	fixture.serveIndex(http.MethodGet, files[2].sha256, "", nil)
	fixture.serveIndex(http.MethodGet, files[1].sha256, "", nil)
	fixture.serveIndex(http.MethodGet, files[2].sha256, "", nil)
	if recordReadCount, _, _ := fixture.store.reads(); recordReadCount != 4 {
		t.Fatalf("read %d states, want 4", recordReadCount)
	}
	fixture.serveIndex(http.MethodGet, files[0].sha256, "", nil)
	if recordReadCount, _, _ := fixture.store.reads(); recordReadCount != 5 {
		t.Fatalf("the dropped file: read %d states, want 5", recordReadCount)
	}

	none := DefaultComputeModelRouteSettings()
	none.ServedFileCacheCount = 0
	noneFixture := newTestComputeModelFixture(t, none)
	noneFixture.store.put(files[0], ComputeModelFileStateServed)
	for range 3 {
		noneFixture.serveChunk(http.MethodGet, files[0].sha256, "0", "", nil)
	}
	if recordReadCount, indexReadCount, _ := noneFixture.store.reads(); recordReadCount != 3 || indexReadCount != 3 {
		t.Fatalf("keeping none: read %d states and %d indexes, want 3 and 3", recordReadCount, indexReadCount)
	}
}

// Mirror objects that disagree are never served: an index other than the one its state pins, a served file without
// its index or with an index that does not read, and a served file missing a chunk answer 500; a chunk taken away
// with its file answers 404 and drops the kept file; a store that does not answer answers 503 with Retry-After; a
// stored chunk shorter than its index's entry cuts the answer rather than completing it short.
func TestComputeModelMirrorDisagreementIsNotServed(t *testing.T) {
	fixture := newTestComputeModelFixture(t, nil)
	file := newTestComputeModelFile(t, testComputeModelData(), 400)

	// an index other than the pinned one
	fixture.store.put(file, ComputeModelFileStateServed)
	fixture.store.stateLock.Lock()
	fixture.store.indexes[file.sha256] = append(slices.Clone(file.index), ' ')
	fixture.store.stateLock.Unlock()
	testComputeModelRefusal(t, fixture.serveIndex(http.MethodGet, file.sha256, "", nil), http.StatusInternalServerError, "an index off its pin")
	testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, file.sha256, "0", "", nil), http.StatusInternalServerError, "a chunk of an index off its pin")

	// served without an index
	fixture.store.stateLock.Lock()
	delete(fixture.store.indexes, file.sha256)
	fixture.store.stateLock.Unlock()
	testComputeModelRefusal(t, fixture.serveIndex(http.MethodGet, file.sha256, "", nil), http.StatusInternalServerError, "served without an index")

	// an index that pins but names another file
	other := newTestComputeModelFile(t, testComputeModelData()[:500], 400)
	fixture.store.stateLock.Lock()
	fixture.store.indexes[file.sha256] = other.index
	fixture.store.records[file.sha256] = &ComputeModelFileRecord{State: ComputeModelFileStateServed, IndexSha256: other.indexSha256}
	fixture.store.stateLock.Unlock()
	testComputeModelRefusal(t, fixture.serveIndex(http.MethodGet, file.sha256, "", nil), http.StatusInternalServerError, "another file's index")

	// a served file missing a chunk; then the file taken away
	fixture.store.put(file, ComputeModelFileStateServed)
	fixture.store.stateLock.Lock()
	fixture.store.chunks[file.sha256] = [][]byte{file.chunks[0], nil, file.chunks[2]}
	fixture.store.stateLock.Unlock()
	testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, file.sha256, "1", "", nil), http.StatusInternalServerError, "a served file missing a chunk")
	fixture.store.stateLock.Lock()
	delete(fixture.store.records, file.sha256)
	delete(fixture.store.chunks, file.sha256)
	fixture.store.stateLock.Unlock()
	testComputeModelRefusal(t, fixture.serveChunk(http.MethodGet, file.sha256, "0", "", nil), http.StatusNotFound, "a chunk taken away with its file")
	testComputeModelRefusal(t, fixture.serveIndex(http.MethodGet, file.sha256, "", nil), http.StatusNotFound, "the index of a file taken away")

	// a store that does not answer
	fixture.store.put(file, ComputeModelFileStateServed)
	fixture.store.stateLock.Lock()
	fixture.store.failure = errors.New("the store did not answer")
	fixture.store.stateLock.Unlock()
	unavailable := fixture.serveIndex(http.MethodGet, file.sha256, "", nil)
	testComputeModelRefusal(t, unavailable, http.StatusServiceUnavailable, "a store that did not answer")
	if got := unavailable.Result().Header.Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q", got)
	}
	fixture.store.stateLock.Lock()
	fixture.store.failure = nil
	fixture.store.stateLock.Unlock()

	// a chunk shorter than its entry: the response is aborted, never completed short
	fixture.store.stateLock.Lock()
	fixture.store.chunks[file.sha256] = [][]byte{file.chunks[0][:10], file.chunks[1], file.chunks[2]}
	fixture.store.stateLock.Unlock()
	aborted := func() (recovered any) {
		defer func() {
			recovered = recover()
		}()
		fixture.serveChunk(http.MethodGet, file.sha256, "0", "", nil)
		return nil
	}()
	if aborted != http.ErrAbortHandler {
		t.Fatalf("a short chunk: recovered %v, want the handler aborted", aborted)
	}
}

// The routes' reading of an index refuses one that is not its route's file's, of another version, with more or fewer
// chunks than its sizes give, a malformed chunk hash, a chunk size past the settings' bound or none, an unknown member
// or more after the document; QD-1408's form reads.
func TestComputeModelIndexReadRefuses(t *testing.T) {
	settings := DefaultComputeModelRouteSettings()
	file := newTestComputeModelFile(t, testComputeModelData(), 400)
	if document, err := computeModelReadIndex(file.index, file.sha256, settings); err != nil || len(document.Chunks) != 3 || document.ByteCount != 1000 {
		t.Fatalf("the index reads: %v %v", document, err)
	}
	edit := func(change func(document map[string]any)) []byte {
		document := map[string]any{}
		if err := json.Unmarshal(file.index, &document); err != nil {
			t.Fatal(err)
		}
		change(document)
		edited, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return edited
	}
	for what, indexBytes := range map[string][]byte{
		"another file":       edit(func(document map[string]any) { document["sha256"] = strings.Repeat("0", 64) }),
		"version 2":          edit(func(document map[string]any) { document["version"] = 2 }),
		"a chunk too few":    edit(func(document map[string]any) { document["chunks"] = document["chunks"].([]any)[:2] }),
		"a chunk too many":   edit(func(document map[string]any) { document["byte_count"] = 800 }),
		"a malformed hash":   edit(func(document map[string]any) { document["chunks"].([]any)[1] = strings.Repeat("A", 64) }),
		"a chunk too large":  edit(func(document map[string]any) { document["chunk_byte_count"] = settings.ChunkMaxByteCount + 1 }),
		"no chunk size":      edit(func(document map[string]any) { document["chunk_byte_count"] = 0 }),
		"an unknown member":  edit(func(document map[string]any) { document["extra"] = 1 }),
		"a negative size":    edit(func(document map[string]any) { document["byte_count"] = -1 }),
		"more after it":      append(slices.Clone(file.index), []byte(" {}")...),
		"no document at all": []byte("[]"),
	} {
		if _, err := computeModelReadIndex(indexBytes, file.sha256, settings); err == nil {
			t.Errorf("%s: read", what)
		}
	}
}
