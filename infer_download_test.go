//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// What a test server does with one request.
type testInferDownloadAnswer int

const (
	// the bytes asked for
	testInferDownloadServe testInferDownloadAnswer = iota
	// the bytes with one flipped
	testInferDownloadAlter
	// half the bytes under the whole one's Content-Length, then the connection closed
	testInferDownloadDrop
	// the bytes and one more, with a Content-Length to match
	testInferDownloadLonger
	// the bytes and one more, with no Content-Length
	testInferDownloadLongerUnsized
	// a byte short, with a Content-Length to match
	testInferDownloadShorter
	// 503
	testInferDownloadUnavailable
	// 404
	testInferDownloadNotFound
	// 429, with a Retry-After of 0
	testInferDownloadLimited
	// the hub's: a 200 of the whole file
	testInferDownloadWhole
	// the hub's: a 206 of another range than the one asked
	testInferDownloadOtherRange
	// the hub's: a redirect to the hub's CDN, cdn.hub.example
	testInferDownloadRedirectCdn
	// the hub's: a redirect to a host off the hub's, other.example
	testInferDownloadRedirectOther
)

// The hub's path of the test file, at a pinned commit.
const testInferHubPath = "/test-org/test-model/resolve/0123456789abcdef0123456789abcdef01234567/test-model.litertlm"

// One request a test server saw.
type testInferDownloadRequest struct {
	server string
	header http.Header
	query  string
}

// A local api, hub, the hub's CDN and another host, each an httptest TLS server, reached by synthetic names through
// one transport, and the file they serve.
type testInferDownloadWorld struct {
	content   []byte
	index     *InferModelIndex
	file      *InferManifestModelFile
	settings  *InferSettings
	directory string
	transport *http.Transport
	// each server's listening address, by its name
	addresses map[string]string
	// whether a dial to the api is refused
	apiRefused atomic.Bool

	stateLock sync.Mutex
	// requests by what they asked: "api index", "api probe", "api chunk 3", "hub chunk 3", "cdn chunk 3", "other chunk 3"
	counts   map[string]int
	requests []*testInferDownloadRequest
	// each request's answer, by what it asked and its attempt from 1; nil serves every one
	answer func(asked string, attempt int) testInferDownloadAnswer
	// called in each chunk request's handler before its answer, outside the world's lock
	gate func(asked string)
	// what the api answers for the index, nil for the file's own
	indexData     []byte
	freeByteCount int64
}

// A world serving a file of byteCount bytes in chunks of chunkByteCount, whose byte i is i mod 251.
func newTestInferDownloadWorld(t *testing.T, byteCount int64, chunkByteCount int64) *testInferDownloadWorld {
	t.Helper()
	settings := DefaultInferSettings()
	settings.ModelChunkMinByteCount = 1
	settings.ModelFetchRetryInterval = 0
	settings.ModelRetryAfterMaxDuration = 0
	settings.ModelApiProbeInterval = time.Hour
	settings.ModelHubRedirectHostSuffixes = []string{"hub.example"}
	content := testInferModelIndexContent(byteCount)
	index, err := InferModelIndexBuild(bytes.NewReader(content), chunkByteCount, settings)
	if err != nil {
		t.Fatal(err)
	}
	world := &testInferDownloadWorld{
		content:  content,
		index:    index,
		settings: settings,
		file: &InferManifestModelFile{
			InferManifestFile: InferManifestFile{
				Name:      "test-model.litertlm",
				Url:       "https://hub.example" + testInferHubPath,
				ByteCount: byteCount,
				Sha256:    index.FileSha256(),
			},
			IndexSha256: index.IndexSha256(),
		},
		directory:     t.TempDir(),
		addresses:     map[string]string{},
		counts:        map[string]int{},
		freeByteCount: 1024 * 1024 * 1024 * 1024,
	}
	servers := map[string]http.HandlerFunc{
		"api.example":     world.serveApi,
		"hub.example":     world.serveHub("hub"),
		"cdn.hub.example": world.serveHub("cdn"),
		"other.example":   world.serveHub("other"),
	}
	pool := x509.NewCertPool()
	for name, handler := range servers {
		server := httptest.NewUnstartedServer(handler)
		// a connection the download drops mid-handshake is its business, not the log's
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		t.Cleanup(server.Close)
		world.addresses[name] = server.Listener.Addr().String()
		// every httptest server presents the same certificate, for 127.0.0.1
		pool.AddCert(server.Certificate())
	}
	world.transport = &http.Transport{
		DialContext:       world.dial,
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"},
		DisableKeepAlives: true,
	}
	t.Cleanup(world.transport.CloseIdleConnections)
	return world
}

// Dials a server by its name: refused for the api while apiRefused is set, no name for a name no server has.
func (self *testInferDownloadWorld) dial(ctx context.Context, network string, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == "api.example" && self.apiRefused.Load() {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	target, ok := self.addresses[host]
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}}
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

// Counts a request for asked, and gives its attempt, from 1.
func (self *testInferDownloadWorld) count(asked string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.counts[asked] += 1
	return self.counts[asked]
}

// How many requests asked for asked.
func (self *testInferDownloadWorld) countOf(asked string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.counts[asked]
}

// The requests for server's chunks, by chunk.
func (self *testInferDownloadWorld) chunkCounts(server string) map[int]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	chunkCounts := map[int]int{}
	for asked, count := range self.counts {
		if numberText, ok := strings.CutPrefix(asked, server+" chunk "); ok {
			n, _ := strconv.Atoi(numberText)
			chunkCounts[n] = count
		}
	}
	return chunkCounts
}

// Starts the counts again, as for a restart.
func (self *testInferDownloadWorld) resetCounts() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.counts = map[string]int{}
}

// The answer to a request for asked at attempt.
func (self *testInferDownloadWorld) answerOf(asked string, attempt int) testInferDownloadAnswer {
	self.stateLock.Lock()
	answer := self.answer
	self.stateLock.Unlock()
	if answer == nil {
		return testInferDownloadServe
	}
	return answer(asked, attempt)
}

// Sets the answers.
func (self *testInferDownloadWorld) setAnswer(answer func(asked string, attempt int) testInferDownloadAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answer = answer
}

// Sets the gate each chunk request passes.
func (self *testInferDownloadWorld) setGate(gate func(asked string)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.gate = gate
}

// Sets what the api answers for the index, nil for the file's own.
func (self *testInferDownloadWorld) setIndexData(data []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.indexData = data
}

// Sets the room the volume reports, negative for a volume that reports none.
func (self *testInferDownloadWorld) setFreeByteCount(freeByteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.freeByteCount = freeByteCount
}

// How many requests the servers saw.
func (self *testInferDownloadWorld) requestCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// Keeps what a request carried, and sets a cookie on its answer, which no later request may carry.
func (self *testInferDownloadWorld) record(server string, w http.ResponseWriter, r *http.Request) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, &testInferDownloadRequest{server: server, header: r.Header.Clone(), query: r.URL.RawQuery})
	}()
	http.SetCookie(w, &http.Cookie{Name: "test-session", Value: server})
}

// The api's model routes, for the world's file.
func (self *testInferDownloadWorld) serveApi(w http.ResponseWriter, r *http.Request) {
	self.record("api", w, r)
	rest, ok := strings.CutPrefix(r.URL.Path, "/compute/models/"+self.file.Sha256+"/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	if rest == "index" {
		if r.Method == http.MethodHead {
			self.count("api probe")
			w.WriteHeader(http.StatusOK)
			return
		}
		attempt := self.count("api index")
		data := self.index.Bytes()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.indexData != nil {
				data = bytes.Clone(self.indexData)
			}
		}()
		switch self.answerOf("api index", attempt) {
		case testInferDownloadAlter:
			data[len(data)/2] ^= 1
		case testInferDownloadUnavailable:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		case testInferDownloadNotFound:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
		return
	}
	numberText, ok := strings.CutPrefix(rest, "chunks/")
	n, err := strconv.Atoi(numberText)
	chunk, inIndex := self.index.Chunk(n)
	if !ok || err != nil || !inIndex {
		http.NotFound(w, r)
		return
	}
	asked := "api chunk " + strconv.Itoa(n)
	attempt := self.count(asked)
	self.passGate(asked)
	self.writeChunk(w, self.answerOf(asked, attempt), chunk, false)
}

// The hub's file by ranges, as server: the hub itself, its CDN, or another host.
func (self *testInferDownloadWorld) serveHub(server string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		self.record(server, w, r)
		start, end, ok := testInferParseRange(r.Header.Get("Range"))
		chunk, inIndex := self.index.Chunk(int(start / self.index.ChunkByteCount()))
		if r.URL.Path != testInferHubPath || !ok || !inIndex || chunk.Offset != start || chunk.Offset+chunk.ByteCount-1 != end {
			http.Error(w, "no such range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		asked := server + " chunk " + strconv.Itoa(chunk.Number)
		attempt := self.count(asked)
		self.passGate(asked)
		answer := self.answerOf(asked, attempt)
		switch answer {
		case testInferDownloadRedirectCdn:
			http.Redirect(w, r, "https://cdn.hub.example"+testInferHubPath, http.StatusFound)
			return
		case testInferDownloadRedirectOther:
			http.Redirect(w, r, "https://other.example"+testInferHubPath, http.StatusFound)
			return
		case testInferDownloadWhole:
			w.Header().Set("Content-Length", strconv.Itoa(len(self.content)))
			w.WriteHeader(http.StatusOK)
			w.Write(self.content)
			return
		case testInferDownloadOtherRange:
			other := chunk.Offset + chunk.ByteCount
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", other, other+chunk.ByteCount-1, len(self.content)))
			w.Header().Set("Content-Length", strconv.FormatInt(chunk.ByteCount, 10))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(make([]byte, chunk.ByteCount))
			return
		}
		self.writeChunk(w, answer, chunk, true)
	}
}

// Runs the gate a test set, if any.
func (self *testInferDownloadWorld) passGate(asked string) {
	self.stateLock.Lock()
	gate := self.gate
	self.stateLock.Unlock()
	if gate != nil {
		gate(asked)
	}
}

// Answers chunk as answer says, as a 206 of its range where ranged.
func (self *testInferDownloadWorld) writeChunk(w http.ResponseWriter, answer testInferDownloadAnswer, chunk *InferModelChunk, ranged bool) {
	data := bytes.Clone(self.content[chunk.Offset : chunk.Offset+chunk.ByteCount])
	status := http.StatusOK
	if ranged {
		status = http.StatusPartialContent
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", chunk.Offset, chunk.Offset+chunk.ByteCount-1, len(self.content)))
	}
	switch answer {
	case testInferDownloadAlter:
		data[len(data)/2] ^= 0xff
	case testInferDownloadLonger:
		data = append(data, 0)
	case testInferDownloadLongerUnsized:
		// no Content-Length: the answer goes chunked, its length known only as it is read
		w.WriteHeader(status)
		w.(http.Flusher).Flush()
		w.Write(append(data, 0))
		return
	case testInferDownloadShorter:
		data = data[:len(data)-1]
	case testInferDownloadUnavailable:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	case testInferDownloadNotFound:
		http.NotFound(w, nil)
		return
	case testInferDownloadLimited:
		w.Header().Set("Retry-After", "0")
		http.Error(w, "limited", http.StatusTooManyRequests)
		return
	case testInferDownloadDrop:
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(status)
		w.Write(data[:len(data)/2])
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	w.Write(data)
}

// A Range header's one range, bytes=start-end.
func testInferParseRange(value string) (int64, int64, bool) {
	span, ok := strings.CutPrefix(value, "bytes=")
	if !ok {
		return 0, 0, false
	}
	first, last, ok := strings.Cut(span, "-")
	if !ok {
		return 0, 0, false
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	end, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return start, end, true
}

// A download of the world's file into directory.
func (self *testInferDownloadWorld) newDownload(t *testing.T, directory string) *InferModelDownload {
	t.Helper()
	return self.newDownloadOn(t, directory, nil)
}

// A download of the world's file into directory, on clock, nil for real time.
func (self *testInferDownloadWorld) newDownloadOn(t *testing.T, directory string, clock Clock) *InferModelDownload {
	t.Helper()
	download, err := NewInferModelDownload(&InferModelDownloadArgs{
		ApiUrl:    "https://api.example",
		Transport: self.transport,
		Directory: directory,
		Settings:  self.settings,
		Clock:     clock,
		Log:       NewNoopLogger(),
		FreeByteCount: func(directory string) (int64, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.freeByteCount < 0 {
				return 0, errors.New("the volume tells nothing")
			}
			return self.freeByteCount, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return download
}

// The whole file opens and holds the world's content.
func (self *testInferDownloadWorld) assertWhole(t *testing.T, file *InferModelFile) {
	t.Helper()
	opened, err := file.OpenWhole(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	data, err := io.ReadAll(opened)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, self.content) {
		t.Fatal("the whole file is not the content")
	}
}

// The chunks the done list in directory marks, in order.
func (self *testInferDownloadWorld) doneChunks(t *testing.T, directory string) []int {
	t.Helper()
	done, _, err := readInferModelDoneList(newInferModelFilePaths(directory, self.file.Sha256).done, testInferPinDigest(t, self.file), self.index.ChunkCount())
	if err != nil {
		t.Fatal(err)
	}
	chunks := []int{}
	for n, isDone := range done {
		if isDone {
			chunks = append(chunks, n)
		}
	}
	return chunks
}

// The index pin's bytes.
func testInferPinDigest(t *testing.T, file *InferManifestModelFile) [32]byte {
	t.Helper()
	modelFile, err := (&InferModelDownload{settings: DefaultInferSettings()}).File(file)
	if err != nil {
		t.Fatal(err)
	}
	return modelFile.pinDigest
}

// The numbers from first to last.
func testInferRange(first int, last int) []int {
	numbers := []int{}
	for n := first; n <= last; n += 1 {
		numbers = append(numbers, n)
	}
	return numbers
}

// The chunks a count map holds, in order, and whether each was asked for once.
func testInferAskedOnce(counts map[int]int) ([]int, bool) {
	chunks := []int{}
	once := true
	for n, count := range counts {
		chunks = append(chunks, n)
		once = once && count == 1
	}
	slices.Sort(chunks)
	return chunks, once
}

// Copies the files of from into to, their modification times kept, as a crash would leave them.
func testInferCopyFiles(from string, to string) error {
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		target := filepath.Join(to, entry.Name())
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return err
		}
		if err := os.Chtimes(target, info.ModTime(), info.ModTime()); err != nil {
			return err
		}
	}
	return nil
}

// A download fetches every chunk once from the api, writes the file whole, and keeps nothing but the whole file, its
// mark and its index; a second fetch asks nothing, even with the kept index gone, since the mark matches.
func TestModelDownloadFetchesWholeFile(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	download := world.newDownload(t, world.directory)
	progresses := []*InferModelDownloadProgress{}
	file, err := download.Fetch(context.Background(), world.file, func(progress *InferModelDownloadProgress) {
		progresses = append(progresses, progress)
	})
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if chunks, once := testInferAskedOnce(world.chunkCounts("api")); !slices.Equal(chunks, testInferRange(0, 10)) || !once {
		t.Fatalf("the api was asked for %v", world.chunkCounts("api"))
	}
	if world.countOf("api index") != 1 {
		t.Fatalf("the index was asked for %d times", world.countOf("api index"))
	}
	last := progresses[len(progresses)-1]
	if len(progresses) != 12 || progresses[0].DoneChunkCount != 0 || last.DoneChunkCount != 11 || last.ChunkCount != 11 ||
		last.DoneByteCount != int64(len(world.content)) || last.ByteCount != int64(len(world.content)) || last.Source != InferModelDownloadSourceApi {
		t.Fatalf("%d progresses, the last %+v", len(progresses), last)
	}
	for i := 1; i < len(progresses); i += 1 {
		if progresses[i].DoneChunkCount != progresses[i-1].DoneChunkCount+1 || progresses[i].DoneByteCount <= progresses[i-1].DoneByteCount {
			t.Fatalf("progress %d after %d: %+v after %+v", i, i-1, progresses[i], progresses[i-1])
		}
	}
	entries, err := os.ReadDir(world.directory)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sha := world.file.Sha256
	if want := []string{sha, sha + ".index", sha + ".whole"}; !slices.Equal(names, want) {
		t.Fatalf("the directory holds %v", names)
	}

	world.resetCounts()
	if _, err := download.Fetch(context.Background(), world.file, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(world.directory, sha+".index")); err != nil {
		t.Fatal(err)
	}
	again := world.newDownload(t, world.directory)
	file, err = again.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if len(world.chunkCounts("api")) != 0 || world.countOf("api index") != 0 {
		t.Fatalf("a whole file asked for %v", world.counts)
	}
}

// After the connection drops mid-file and the download stops, a restart resumes at the first chunk not marked done:
// the chunks done are not fetched again, and every other chunk is fetched once.
func TestModelDownloadResumesAtFirstMissingChunk(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.settings.ModelChunkFetchConcurrency = 1
	world.settings.ModelHubFallback = false
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk 5" && attempt == 1 {
			// the connection drops mid-chunk, and the api is gone after it
			world.apiRefused.Store(true)
			return testInferDownloadDrop
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("a download whose api went away answered %v", err)
	}
	if done := world.doneChunks(t, world.directory); !slices.Equal(done, testInferRange(0, 4)) {
		t.Fatalf("done before the drop: %v", done)
	}
	firstCounts := world.chunkCounts("api")

	// a restart: a new download on the same directory, the api back
	world.setAnswer(nil)
	world.apiRefused.Store(false)
	world.resetCounts()
	restarted := world.newDownload(t, world.directory)
	askedLock := sync.Mutex{}
	asked := []int{}
	world.setGate(func(name string) {
		if numberText, ok := strings.CutPrefix(name, "api chunk "); ok {
			n, _ := strconv.Atoi(numberText)
			askedLock.Lock()
			defer askedLock.Unlock()
			asked = append(asked, n)
		}
	})
	file, err := restarted.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	askedLock.Lock()
	defer askedLock.Unlock()
	if !slices.Equal(asked, testInferRange(5, 10)) {
		t.Fatalf("the restart asked for %v", asked)
	}
	for n := 0; n <= 4; n += 1 {
		if firstCounts[n] != 1 || world.chunkCounts("api")[n] != 0 {
			t.Fatalf("chunk %d, done before the drop, was asked for again", n)
		}
	}
	if world.countOf("api index") != 0 {
		t.Fatal("the restart asked for the index it kept")
	}
}

// A chunk that fails its check is fetched again and accepted; one that fails every time stops the download with
// download_corrupt naming it after two more fetches, its part kept, and the next fetch takes it and what was not done.
// A longer answer, with or without its length, and a shorter one fail the check alike, and none is cut to fit.
func TestModelDownloadFailingChunkFetchedAgain(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch {
		case asked == "api chunk 3" && attempt == 1:
			return testInferDownloadAlter
		case asked == "api chunk 6" && attempt == 1:
			return testInferDownloadLonger
		case asked == "api chunk 7" && attempt == 1:
			return testInferDownloadLongerUnsized
		case asked == "api chunk 8" && attempt == 1:
			return testInferDownloadShorter
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	counts := world.chunkCounts("api")
	for n := 0; n <= 10; n += 1 {
		want := 1
		if slices.Contains([]int{3, 6, 7, 8}, n) {
			want = 2
		}
		if counts[n] != want {
			t.Errorf("chunk %d was asked for %d times, not %d", n, counts[n], want)
		}
	}

	// altered every time
	altered := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	altered.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk 4" {
			return testInferDownloadAlter
		}
		return testInferDownloadServe
	})
	download = altered.newDownload(t, altered.directory)
	_, err = download.Fetch(context.Background(), altered.file, nil)
	downloadError := &InferDownloadError{}
	if !errors.Is(err, ErrInferDownloadCorrupt) || !errors.As(err, &downloadError) || downloadError.Chunk != 4 ||
		downloadError.Sha256 != altered.file.Sha256 || !strings.Contains(err.Error(), "chunk 4") {
		t.Fatalf("a chunk altered every time answered %v", err)
	}
	if count := altered.countOf("api chunk 4"); count != 3 {
		t.Fatalf("the altered chunk was asked for %d times, not 3", count)
	}
	paths := newInferModelFilePaths(altered.directory, altered.file.Sha256)
	if _, err := os.Stat(paths.part); err != nil {
		t.Fatalf("the part was not kept: %v", err)
	}
	modelFile, err := download.File(altered.file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := modelFile.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) {
		t.Fatalf("a download stopped corrupt opened: %v", err)
	}
	done := altered.doneChunks(t, altered.directory)
	if slices.Contains(done, 4) {
		t.Fatal("the altered chunk is marked done")
	}
	altered.setAnswer(nil)
	altered.resetCounts()
	file, err = download.Fetch(context.Background(), altered.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	altered.assertWhole(t, file)
	for n, count := range altered.chunkCounts("api") {
		if slices.Contains(done, n) || count != 1 {
			t.Errorf("the next fetch asked for chunk %d %d times, done before: %v", n, count, done)
		}
	}
	if _, ok := altered.chunkCounts("api")[4]; !ok {
		t.Error("the next fetch did not take the altered chunk")
	}
}

// OpenWhole refuses at every step before the whole mark: while the fetch runs, and in what a crash at each chunk's
// mark would leave, the last chunk's included; then the file opens. A download that stops corrupt leaves no whole file.
func TestModelDownloadNoFileOpenedBeforeEveryChunkPasses(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	download := world.newDownload(t, world.directory)
	live, err := download.File(world.file)
	if err != nil {
		t.Fatal(err)
	}
	crashRoot := t.TempDir()
	crashes := []string{}
	file, err := download.Fetch(context.Background(), world.file, func(progress *InferModelDownloadProgress) {
		if _, err := live.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) {
			t.Errorf("at %d chunks done, the running download's file opened: %v", progress.DoneChunkCount, err)
		}
		// what a crash at this step would leave, checked once the fetch is done
		crash := filepath.Join(crashRoot, strconv.Itoa(progress.DoneChunkCount))
		if err := os.Mkdir(crash, 0o700); err != nil {
			t.Error(err)
			return
		}
		if err := testInferCopyFiles(world.directory, crash); err != nil {
			t.Error(err)
			return
		}
		crashes = append(crashes, crash)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(crashes) != 12 {
		t.Fatalf("%d steps", len(crashes))
	}
	for i, crash := range crashes {
		crashed, err := world.newDownload(t, crash).File(world.file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := crashed.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) {
			t.Errorf("at %d chunks done, what a crash would leave opened: %v", i, err)
		}
		if _, err := os.Stat(crashed.Path()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("at %d chunks done, a whole file is in place", i)
		}
	}
	world.assertWhole(t, file)

	// the last chunk failing every time: no whole file, ever
	corrupt := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	corrupt.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk 10" {
			return testInferDownloadAlter
		}
		return testInferDownloadServe
	})
	download = corrupt.newDownload(t, corrupt.directory)
	if _, err := download.Fetch(context.Background(), corrupt.file, nil); !errors.Is(err, ErrInferDownloadCorrupt) {
		t.Fatalf("the last chunk altered every time answered %v", err)
	}
	modelFile, err := download.File(corrupt.file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := modelFile.OpenWhole(context.Background()); !errors.Is(err, ErrInferModelNotWhole) {
		t.Fatalf("a file whose last chunk failed opened: %v", err)
	}
	if _, err := os.Stat(modelFile.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a whole file is in place")
	}
}

// An index off its pin is refused, fetched again twice and then download_corrupt naming the index, with no chunk asked
// for and no part made; a kept index changed on disk is fetched again.
func TestModelDownloadIndexOffPinRefused(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	// another file's index, well formed, which the pin does not name
	other, err := InferModelIndexBuild(bytes.NewReader(bytes.Repeat([]byte{7}, 10*1024+300)), 1024, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	world.setIndexData(other.Bytes())
	download := world.newDownload(t, world.directory)
	_, err = download.Fetch(context.Background(), world.file, nil)
	downloadError := &InferDownloadError{}
	if !errors.Is(err, ErrInferDownloadCorrupt) || !errors.Is(err, ErrInferModelIndexInvalid) || !errors.As(err, &downloadError) || downloadError.Chunk != -1 {
		t.Fatalf("an index off its pin answered %v", err)
	}
	if world.countOf("api index") != 3 || len(world.chunkCounts("api")) != 0 {
		t.Fatalf("an index off its pin: %v", world.counts)
	}
	paths := newInferModelFilePaths(world.directory, world.file.Sha256)
	for _, path := range []string{paths.index, paths.part, paths.done, paths.whole} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s is in place after an index off its pin", filepath.Base(path))
		}
	}
	// an altered index once, then the pinned one
	world.setIndexData(nil)
	world.resetCounts()
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api index" && attempt == 1 {
			return testInferDownloadAlter
		}
		return testInferDownloadServe
	})
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if world.countOf("api index") != 2 {
		t.Fatalf("the index was asked for %d times", world.countOf("api index"))
	}

	// a kept index changed on disk is fetched again, and the download takes the pinned one
	world.setAnswer(nil)
	world.resetCounts()
	if err := os.Remove(paths.whole); err != nil {
		t.Fatal(err)
	}
	kept, err := os.ReadFile(paths.index)
	if err != nil {
		t.Fatal(err)
	}
	kept[len(kept)/2] ^= 1
	if err := os.WriteFile(paths.index, kept, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err = download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if world.countOf("api index") != 1 {
		t.Fatalf("a changed kept index: the index was asked for %d times", world.countOf("api index"))
	}
}

// At most ModelChunkFetchConcurrency chunks are asked for at once: the api holds each request until four are in
// flight, or every chunk left is, and never sees a fifth.
func TestModelDownloadConcurrencyBound(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	total := world.index.ChunkCount()
	width := world.settings.ModelChunkFetchConcurrency
	if width != 4 {
		t.Fatalf("the default concurrency is %d, not 4", width)
	}
	gateLock := sync.Mutex{}
	inFlight := 0
	maxInFlight := 0
	passed := 0
	// the batch a request waits in, closed once four, or every chunk left, are in flight together
	batch := make(chan struct{})
	world.setGate(func(asked string) {
		if !strings.HasPrefix(asked, "api chunk ") {
			return
		}
		mine := func() chan struct{} {
			gateLock.Lock()
			defer gateLock.Unlock()
			inFlight += 1
			maxInFlight = max(maxInFlight, inFlight)
			mine := batch
			if min(width, total-passed) <= inFlight {
				close(batch)
				batch = make(chan struct{})
			}
			return mine
		}()
		select {
		case <-mine:
		case <-time.After(30 * time.Second):
			t.Errorf("%s waited for company that never came", asked)
		}
		gateLock.Lock()
		defer gateLock.Unlock()
		inFlight -= 1
		passed += 1
	})
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	gateLock.Lock()
	defer gateLock.Unlock()
	if maxInFlight != width || passed != total {
		t.Fatalf("at most %d in flight of %d, %d passed", maxInFlight, width, passed)
	}
}

// No request carries a credential: not to the api, its probe, the hub or the hub's CDN, though every answer set a
// cookie; each carries no query, and nothing but the range, the identity encoding and the client's name.
func TestModelDownloadSendsNoCredential(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	world.settings.ModelChunkFetchConcurrency = 1
	world.settings.ModelApiProbeInterval = 0
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		switch {
		case asked == "api chunk 1":
			world.apiRefused.Store(true)
		case strings.HasPrefix(asked, "hub chunk "):
			return testInferDownloadRedirectCdn
		case asked == "cdn chunk 3":
			world.apiRefused.Store(false)
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	servers := map[string]bool{}
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	for _, request := range world.requests {
		servers[request.server] = true
		if request.query != "" {
			t.Errorf("a request to the %s carried a query", request.server)
		}
		for name := range request.header {
			// Connection is the test transport's, which keeps no connection so a refused dial takes at once
			if !slices.Contains([]string{"Accept-Encoding", "User-Agent", "Range", "Connection"}, name) {
				t.Errorf("a request to the %s carried %s", request.server, name)
			}
		}
		if request.header.Get("Accept-Encoding") != "identity" {
			t.Errorf("a request to the %s took encodings %q", request.server, request.header.Get("Accept-Encoding"))
		}
		if request.server != "api" && request.header.Get("Range") == "" {
			t.Errorf("a request to the %s carried no range", request.server)
		}
	}
	if !servers["api"] || !servers["hub"] || !servers["cdn"] || world.counts["api probe"] == 0 {
		t.Fatalf("the download reached %v, probing %d times", servers, world.counts["api probe"])
	}
}

// A download refuses to start without what is left to write free and a tenth of the file more, asking nothing of any
// server; one resumed needs room only for what is left.
func TestModelDownloadRefusesWithoutSpace(t *testing.T) {
	world := newTestInferDownloadWorld(t, 10*1024+300, 1024)
	byteCount := int64(len(world.content))
	margin := int64(math.Ceil(world.settings.ModelFreeSpaceMarginFraction * float64(byteCount)))
	if margin != 1054 {
		t.Fatalf("a tenth of %d bytes is %d", byteCount, margin)
	}
	download := world.newDownload(t, world.directory)
	for _, freeByteCount := range []int64{byteCount + margin - 1, 0, -1} {
		world.setFreeByteCount(freeByteCount)
		if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadNoSpace) {
			t.Fatalf("with %d bytes free: %v", freeByteCount, err)
		}
	}
	if count := world.requestCount(); count != 0 {
		t.Fatalf("a download without room asked %d requests", count)
	}

	// stopped at chunk 5, then resumed with room for what is left
	world.settings.ModelChunkFetchConcurrency = 1
	world.settings.ModelHubFallback = false
	world.setFreeByteCount(byteCount + margin)
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk 5" && attempt == 1 {
			world.apiRefused.Store(true)
			return testInferDownloadDrop
		}
		return testInferDownloadServe
	})
	if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("a download whose api went away answered %v", err)
	}
	world.apiRefused.Store(false)
	left := byteCount - 5*1024
	world.setFreeByteCount(left + margin - 1)
	if _, err := download.Fetch(context.Background(), world.file, nil); !errors.Is(err, ErrInferDownloadNoSpace) {
		t.Fatalf("a resume with %d bytes free: %v", left+margin-1, err)
	}
	world.setFreeByteCount(left + margin)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatalf("a resume with %d bytes free: %v", left+margin, err)
	}
	world.assertWhole(t, file)
}

// A download is refused an api url that is not https with a host, no transport and a relative directory, and a file
// whose pins are not whole.
func TestModelDownloadRefusesUnfitArgs(t *testing.T) {
	world := newTestInferDownloadWorld(t, 100, 10)
	for _, args := range []*InferModelDownloadArgs{
		{ApiUrl: "http://api.example", Transport: world.transport, Directory: world.directory},
		{ApiUrl: "https://", Transport: world.transport, Directory: world.directory},
		{ApiUrl: "https://user:pass@api.example", Transport: world.transport, Directory: world.directory},
		{ApiUrl: "https://api.example?x=1", Transport: world.transport, Directory: world.directory},
		{ApiUrl: "https://api.example", Directory: world.directory},
		{ApiUrl: "https://api.example", Transport: world.transport, Directory: "models"},
		{ApiUrl: "https://api.example", Transport: world.transport},
	} {
		if _, err := NewInferModelDownload(args); err == nil {
			t.Errorf("%+v made a download", args)
		}
	}
	download := world.newDownload(t, world.directory)
	for _, change := range []func(file *InferManifestModelFile){
		func(file *InferManifestModelFile) { file.Sha256 = "" },
		func(file *InferManifestModelFile) { file.IndexSha256 = strings.ToUpper(file.IndexSha256) },
		func(file *InferManifestModelFile) { file.ByteCount = -1 },
		func(file *InferManifestModelFile) { file.ByteCount = world.settings.ManifestFileMaxByteCount + 1 },
	} {
		file := *world.file
		change(&file)
		if _, err := download.Fetch(context.Background(), &file, nil); !errors.Is(err, ErrInferManifestInvalid) {
			t.Errorf("a file whose pins are not whole: %v", err)
		}
	}
	if count := world.requestCount(); count != 0 {
		t.Fatalf("unfit files asked %d requests", count)
	}
}

// A clock a test fires: its time stands still, an After of no time fires at once and any other never, and each
// AfterFunc waits for the test to fire the timers armed for its timeout.
type testInferDownloadClock struct {
	stateLock sync.Mutex
	now       time.Time
	timers    map[*testInferDownloadTimer]bool
}

// One armed AfterFunc.
type testInferDownloadTimer struct {
	timeout  time.Duration
	function func()
}

// A clock at a fixed instant.
func newTestInferDownloadClock() *testInferDownloadClock {
	return &testInferDownloadClock{
		now:    time.Date(2026, time.November, 25, 12, 0, 0, 0, time.UTC),
		timers: map[*testInferDownloadTimer]bool{},
	}
}

// The fixed instant.
func (self *testInferDownloadClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Fires at once for no time, and never for any other.
func (self *testInferDownloadClock) After(timeout time.Duration) <-chan time.Time {
	fire := make(chan time.Time, 1)
	if timeout <= 0 {
		fire <- self.Now()
	}
	return fire
}

// Arms function until fire is called with timeout, or stop.
func (self *testInferDownloadClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	timer := &testInferDownloadTimer{timeout: timeout, function: function}
	self.stateLock.Lock()
	self.timers[timer] = true
	self.stateLock.Unlock()
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		armed := self.timers[timer]
		delete(self.timers, timer)
		return armed
	}
}

// Fires every timer armed for timeout, outside the clock's lock, and says how many.
func (self *testInferDownloadClock) fire(timeout time.Duration) int {
	functions := []func(){}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for timer := range self.timers {
			if timer.timeout == timeout {
				functions = append(functions, timer.function)
				delete(self.timers, timer)
			}
		}
	}()
	for _, function := range functions {
		function()
	}
	return len(functions)
}

// A chunk whose answer does not come within ModelChunkTimeout is asked for again, on the download's clock: the api
// holds chunk 2's first request, the test fires its timeout, and the second request gives the file whole.
func TestModelDownloadTimeoutAskedAgain(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4*1024+10, 1024)
	world.settings.ModelChunkFetchConcurrency = 1
	held := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := sync.Once{}
	releaseHeld := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	// before the servers close, which waits for the held handler
	defer releaseHeld()
	world.setGate(func(asked string) {
		if asked == "api chunk 2" && world.countOf(asked) == 1 {
			close(held)
			<-release
		}
	})
	clock := newTestInferDownloadClock()
	download := world.newDownloadOn(t, world.directory, clock)
	type answer struct {
		file *InferModelFile
		err  error
	}
	answered := make(chan answer, 1)
	go func() {
		file, err := download.Fetch(context.Background(), world.file, nil)
		answered <- answer{file: file, err: err}
	}()
	<-held
	if fired := clock.fire(world.settings.ModelChunkTimeout); fired != 1 {
		t.Fatalf("%d chunk timeouts were armed", fired)
	}
	result := <-answered
	releaseHeld()
	if result.err != nil {
		t.Fatal(result.err)
	}
	world.assertWhole(t, result.file)
	if count := world.countOf("api chunk 2"); count != 2 {
		t.Fatalf("the chunk that timed out was asked for %d times", count)
	}
}

// A 429 is waited out and the chunk asked for again; one past ModelRateLimitedMaxCount in a row stops the download with
// download_unavailable, the api never counted unreachable for it.
func TestModelDownloadRateLimitWaitedOut(t *testing.T) {
	world := newTestInferDownloadWorld(t, 4*1024+10, 1024)
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk 1" && attempt <= 2 {
			return testInferDownloadLimited
		}
		return testInferDownloadServe
	})
	download := world.newDownload(t, world.directory)
	file, err := download.Fetch(context.Background(), world.file, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.assertWhole(t, file)
	if count := world.countOf("api chunk 1"); count != 3 {
		t.Fatalf("the limited chunk was asked for %d times", count)
	}

	limited := newTestInferDownloadWorld(t, 4*1024+10, 1024)
	limited.settings.ModelRateLimitedMaxCount = 2
	limited.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk 0" {
			return testInferDownloadLimited
		}
		return testInferDownloadServe
	})
	download = limited.newDownload(t, limited.directory)
	if _, err := download.Fetch(context.Background(), limited.file, nil); !errors.Is(err, ErrInferDownloadUnavailable) {
		t.Fatalf("a chunk limited every time answered %v", err)
	}
	if count := limited.countOf("api chunk 0"); count != 3 {
		t.Fatalf("the limited chunk was asked for %d times, not 3", count)
	}
	if hub := limited.chunkCounts("hub"); len(hub) != 0 {
		t.Fatalf("a limited api moved the download to the hub: %v", hub)
	}
}
