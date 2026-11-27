//go:build !ios_extension && !sidecar_http

// The one model downloader of every Go host (DESIGN-COMPUTE §6.5's model downloads; CO-49, R-INFER-10, D-INFER-12,
// IC-5; CONTRACTS C-44): the daemon's, the sdk's sidecar's in the apps and `ur models pull`'s, through INFER-M11-06's
// InferPull. The browser's engine Worker keeps the same rules in its own JS, on the same vectors (INFER-M13-02).
//
// Fetch takes one local file the signed manifest names:
//
//   - the index first, from the api, GET <api>/compute/models/{sha256}/index, the api's address the host list's
//     (SidecarSettings.ApiUrl, which SidecarHostList.ApplyServiceUrls fills), checked against the manifest's
//     index_sha256 by ParseInferModelIndex and kept beside the file, where it is read again only through that pin;
//   - then the chunks, GET <api>/compute/models/{sha256}/chunks/{n}, at most ModelChunkFetchConcurrency at a time, from
//     the first chunk not done on, each read whole and no longer than its index entry, checked against the index,
//     written at its offset in the part, the part synced, and only then marked done (infer_download_state.go);
//   - a chunk that fails its check is fetched again ModelChunkRetryCount times, then the download stops with
//     download_corrupt naming it, its part kept, so the next try takes only what is missing;
//   - once every chunk is done the part becomes the whole file, the one state InferModelFile.OpenWhole opens.
//
// A dropped connection, a crash or a restart costs at most the chunks in flight: the next Fetch resumes at the first
// chunk not marked done and fetches nothing done again. Where the api cannot be reached, the chunks come from the
// manifest's Hugging Face URL at its pinned commit by Range requests, checked against the same index, and go back to
// the api once it answers (infer_download_fallback.go). The index comes from the api alone, since the hub serves none:
// a download with no index kept whose api cannot give one stops.
//
// No request carries a credential: no token, cookie, DPoP proof or member id reaches the api, a cache or the hub, so
// the api learns a file and an address and never a member (CO-49), and no request is an inference's (IC-5). Every
// request goes through the host's transport, the daemon's egress-bound SidecarApi transport, never net/http's default
// one. Every count, size, time and retry is an InferSettings field (QD-702).
//
// Fetches, opens and removals of one file run one at a time in a download, a second fetch or removal waiting for the
// first and an open refusing while a fetch runs. InferModelDownload is safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// What a download's error says went wrong (§6.5).
type InferDownloadErrorCode string

const (
	// A chunk, or the index, failed its check every time it was fetched: Chunk names it, -1 for the index.
	InferDownloadErrorCorrupt InferDownloadErrorCode = "download_corrupt"
	// Neither the api nor the hub gave what the download asked for: unreachable, refusing, or past its retries.
	InferDownloadErrorUnavailable InferDownloadErrorCode = "download_unavailable"
	// The directory's volume lacks room for what is left to write and the margin, or tells nothing of its room.
	InferDownloadErrorNoSpace InferDownloadErrorCode = "download_no_space"
)

// A download's error: coded, naming the file and, for download_corrupt, the chunk. A message is the download's own
// words, never text a source sent.
type InferDownloadError struct {
	Code InferDownloadErrorCode
	// The file's SHA-256.
	Sha256 string
	// The chunk download_corrupt names, from 0, or -1 for the index; the chunk the download stopped at for another
	// code, or -1 for none.
	Chunk int
	// Why, in the download's words.
	Message string
	// what it came from, where something did: the index's refusal, for an index off its pin
	err error
}

// The code, the file and the chunk, and why.
func (self *InferDownloadError) Error() string {
	if self.Sha256 == "" {
		return "model " + string(self.Code)
	}
	where := ""
	switch {
	case 0 <= self.Chunk:
		where = fmt.Sprintf(" chunk %d", self.Chunk)
	case self.Code == InferDownloadErrorCorrupt:
		where = " index"
	}
	return fmt.Sprintf("model %s: %s%s: %s", self.Code, self.Sha256, where, self.Message)
}

// errors.Is matches another *InferDownloadError of the same code, ErrInferDownloadCorrupt among them, whatever its
// other fields.
func (self *InferDownloadError) Is(target error) bool {
	other, ok := target.(*InferDownloadError)
	return ok && other.Code == self.Code
}

// What it came from, where something did.
func (self *InferDownloadError) Unwrap() error {
	return self.err
}

// What errors.Is matches each code by.
var (
	ErrInferDownloadCorrupt     = &InferDownloadError{Code: InferDownloadErrorCorrupt, Chunk: -1}
	ErrInferDownloadUnavailable = &InferDownloadError{Code: InferDownloadErrorUnavailable, Chunk: -1}
	ErrInferDownloadNoSpace     = &InferDownloadError{Code: InferDownloadErrorNoSpace, Chunk: -1}
)

// A model file that is not whole: none, a part, one a download of is running, or one whose check found a chunk changed,
// which it was returned to its part for. A fetch makes it whole.
var ErrInferModelNotWhole = errors.New("model file not whole")

// Where a download's chunks come from.
type InferModelDownloadSource string

const (
	// The api's model routes: every download's first.
	InferModelDownloadSourceApi InferModelDownloadSource = "api"
	// The manifest's Hugging Face URL, by ranges, while the api cannot be reached.
	InferModelDownloadSourceHub InferModelDownloadSource = "hub"
)

// How far a download is, as Pull and the bot tab show it (§15.4): by chunks done, and bytes.
type InferModelDownloadProgress struct {
	// The file's SHA-256.
	Sha256         string
	ChunkCount     int
	DoneChunkCount int
	// The file's size, and the bytes of the chunks done, in bytes.
	ByteCount     int64
	DoneByteCount int64
	// Where the chunks come from now.
	Source InferModelDownloadSource
}

// What a download needs from its host.
type InferModelDownloadArgs struct {
	// The api's base url, https://<host>[:<port>]: the host list's (SidecarSettings.ApiUrl, which
	// SidecarHostList.ApplyServiceUrls fills). Refused unless https, with a host and no user, query or fragment.
	ApiUrl string
	// What every request goes through, the api's and the hub's: the daemon's SidecarApi transport, bound to its egress,
	// or the sdk's. Required: the download never takes net/http's default transport, whose sockets would follow a
	// tunnel's route back into this process.
	Transport http.RoundTripper
	// The directory the download keeps its files in, absolute, made 0700 where missing.
	Directory string
	// nil takes DefaultInferSettings.
	Settings *InferSettings
	// nil is real time.
	Clock Clock
	// nil logs to connect's default logger.
	Log Logger
	// The bytes free to this process on the volume of a directory; nil reads the OS's (infer_download_space_*.go).
	FreeByteCount func(directory string) (int64, error)
}

// Downloads local model files into one directory (see the file's comment). A directory has one download: the slots
// that keep a file's fetch, open and removal apart are the download's, so two downloads over one directory, or two
// processes, would write one part at once. The daemon's state directory is its alone (DESIGN §5.8's instance lock),
// as an app's is its process's.
type InferModelDownload struct {
	apiUrl        *url.URL
	transport     http.RoundTripper
	directory     string
	settings      *InferSettings
	clock         Clock
	log           Logger
	freeByteCount func(directory string) (int64, error)
	// the api's client, which follows no redirect, since the api sends none
	apiClient *http.Client

	stateLock sync.Mutex
	// one slot a file, by its SHA-256, which a fetch, an open or a removal of it holds
	sha256Slots map[string]chan struct{}
}

// A download on args, refused unless its api url, transport and directory are fit.
func NewInferModelDownload(args *InferModelDownloadArgs) (*InferModelDownload, error) {
	apiUrl, err := url.Parse(args.ApiUrl)
	if err != nil || apiUrl.Scheme != "https" || apiUrl.Hostname() == "" || apiUrl.User != nil || apiUrl.RawQuery != "" ||
		apiUrl.ForceQuery || apiUrl.Fragment != "" {
		// its text would repeat the url
		return nil, errors.New("model download: the api url is no https://<host>")
	}
	if args.Transport == nil {
		return nil, errors.New("model download: no transport")
	}
	if args.Directory == "" || !filepath.IsAbs(args.Directory) {
		return nil, errors.New("model download: the directory is not absolute")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultInferSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	freeByteCount := args.FreeByteCount
	if freeByteCount == nil {
		freeByteCount = inferDownloadFreeByteCount
	}
	return &InferModelDownload{
		apiUrl:        apiUrl,
		transport:     args.Transport,
		directory:     filepath.Clean(args.Directory),
		settings:      settings,
		clock:         clock,
		log:           loggerOrDefault(args.Log),
		freeByteCount: freeByteCount,
		apiClient: &http.Client{
			Transport: args.Transport,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		sha256Slots: map[string]chan struct{}{},
	}, nil
}

// The state of file in the download's directory, refused unless its pins are whole: a lowercase hex SHA-256 and index
// pin, and a size from 0 to the settings' ManifestFileMaxByteCount.
func (self *InferModelDownload) File(file *InferManifestModelFile) (*InferModelFile, error) {
	if file == nil || !inferManifestSha256Pattern.MatchString(file.Sha256) || !inferManifestSha256Pattern.MatchString(file.IndexSha256) ||
		file.ByteCount < 0 || self.settings.ManifestFileMaxByteCount < file.ByteCount {
		return nil, fmt.Errorf("%w: a model file whose pins are not whole", ErrInferManifestInvalid)
	}
	pins := *file
	pins.Platforms = slices.Clone(file.Platforms)
	pinDigest, _ := hex.DecodeString(pins.IndexSha256)
	return &InferModelFile{
		download:  self,
		file:      &pins,
		pinDigest: [sha256.Size]byte(pinDigest),
		paths:     newInferModelFilePaths(self.directory, pins.Sha256),
	}, nil
}

// The file's slot, made at first use.
func (self *InferModelDownload) slot(sha256 string) chan struct{} {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	slot, ok := self.sha256Slots[sha256]
	if !ok {
		slot = make(chan struct{}, 1)
		self.sha256Slots[sha256] = slot
	}
	return slot
}

// Takes the file's slot, waiting for it until ctx ends.
func (self *InferModelDownload) takeSlot(ctx context.Context, sha256 string) (func(), error) {
	slot := self.slot(sha256)
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Takes the file's slot where it is free.
func (self *InferModelDownload) tryTakeSlot(sha256 string) (func(), bool) {
	slot := self.slot(sha256)
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, true
	default:
		return nil, false
	}
}

// Downloads file into the directory and answers it whole, so OpenWhole opens it. A file already whole answers at
// once, and one whose size or modification time changed since it was marked whole is checked again first. listener,
// where not nil, hears the progress at the start and after each chunk is done, on the download's goroutines one call at
// a time, in order; it should return promptly, and of the download may call only OpenWhole, which refuses while this
// runs. An error is ctx's, an *InferDownloadError, ErrInferManifestInvalid for pins that are not whole, or a local
// file's; the part and the chunks done are kept for the next try whatever stopped it.
func (self *InferModelDownload) Fetch(ctx context.Context, file *InferManifestModelFile, listener func(*InferModelDownloadProgress)) (*InferModelFile, error) {
	modelFile, err := self.File(file)
	if err != nil {
		return nil, err
	}
	release, err := self.takeSlot(ctx, modelFile.file.Sha256)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := os.MkdirAll(self.directory, 0o700); err != nil {
		return nil, fmt.Errorf("model download: %w", err)
	}
	run := newInferDownloadRun(self, modelFile, listener)
	defer run.closeFiles()
	if err := run.fetch(ctx); err != nil {
		return nil, err
	}
	return modelFile, nil
}

// The api's url of the file's object: its index, or one of its chunks.
func (self *InferModelDownload) apiObjectUrl(sha256 string, object ...string) string {
	target := *self.apiUrl
	target.Path = path.Join(append([]string{"/", self.apiUrl.Path, "compute", "models", sha256}, object...)...)
	target.RawPath = ""
	return target.String()
}

// A byte count of blockCount blocks of blockByteCount bytes, held to an int64.
func inferDownloadByteCountOf(blockCount uint64, blockByteCount uint64) int64 {
	if blockByteCount != 0 && math.MaxInt64/blockByteCount < blockCount {
		return math.MaxInt64
	}
	return int64(blockCount * blockByteCount)
}

// What one request gave.
type inferFetchOutcome int

const (
	// the bytes, whole and checked
	inferFetchOk inferFetchOutcome = iota
	// an answer the source gave whole that is not what was asked: another hash or length, or a longer body
	inferFetchCorrupt
	// the source could not be reached: a connection refused, no route, no name
	inferFetchUnreachable
	// no answer in time, a 5xx answer, or a connection dropped mid-answer
	inferFetchUnanswered
	// the source's rate limit: a 429, asked again after its wait
	inferFetchLimited
	// an answer the download refuses outright: another 4xx, a redirect it may not follow, a whole file to a range
	inferFetchRefused
	// the caller's context ended
	inferFetchCanceled
	// an answer's body failed to read, which exchange classifies as a transport's failure
	inferFetchReadFailed
)

// One request's outcome.
type inferFetchResult struct {
	outcome inferFetchOutcome
	// ok: a chunk's bytes, in the worker's buffer
	data []byte
	// ok: the index
	index *InferModelIndex
	// limited: the wait the source asked for, 0 for none given, and when its answer was read, which the wait runs from
	retryAfter time.Duration
	answeredAt time.Time
	// what went wrong, in the download's words
	why string
	// corrupt: what refused it, where something did
	cause error
	// canceled: ctx's error; read failed: the read's
	err error
}

// One request through client, its answer read by answer while the request's timeout runs. A transport's failure,
// before an answer or as its body is read, is classified: unreachable for a dial or a name that failed, unanswered for a
// timeout or a dropped connection, refused for a redirect the client may not follow, canceled for ctx's end.
func (self *InferModelDownload) exchange(ctx context.Context, client *http.Client, method string, target string, header http.Header, timeout time.Duration, answer func(response *http.Response) *inferFetchResult) *inferFetchResult {
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timedOut := atomic.Bool{}
	if 0 < timeout {
		stop := self.clock.AfterFunc(timeout, func() {
			timedOut.Store(true)
			cancel()
		})
		defer stop()
	}
	request, err := http.NewRequestWithContext(requestCtx, method, target, nil)
	if err != nil {
		return &inferFetchResult{outcome: inferFetchRefused, why: "a request that does not build"}
	}
	for name, values := range header {
		request.Header[name] = slices.Clone(values)
	}
	// so no encoding changes what a length or a range covers
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return self.transportFailure(ctx, timedOut.Load(), err)
	}
	defer response.Body.Close()
	result := answer(response)
	if result.outcome == inferFetchReadFailed {
		return self.transportFailure(ctx, timedOut.Load(), result.err)
	}
	return result
}

// What a transport's failure counts as.
func (self *InferModelDownload) transportFailure(ctx context.Context, timedOut bool, err error) *inferFetchResult {
	var dnsError *net.DNSError
	var opError *net.OpError
	var netError net.Error
	switch {
	case ctx.Err() != nil:
		return &inferFetchResult{outcome: inferFetchCanceled, err: ctx.Err()}
	case timedOut:
		return &inferFetchResult{outcome: inferFetchUnanswered, why: "no answer in time"}
	case errors.Is(err, errInferDownloadRedirectRefused):
		return &inferFetchResult{outcome: inferFetchRefused, why: "a redirect it may not follow"}
	case errors.As(err, &dnsError) && !dnsError.IsTimeout:
		return &inferFetchResult{outcome: inferFetchUnreachable, why: "no name"}
	case errors.As(err, &opError) && opError.Op == "dial" && !opError.Timeout():
		return &inferFetchResult{outcome: inferFetchUnreachable, why: "no connection"}
	case errors.As(err, &netError) && netError.Timeout():
		return &inferFetchResult{outcome: inferFetchUnanswered, why: "no answer in time"}
	}
	return &inferFetchResult{outcome: inferFetchUnanswered, why: "the connection dropped"}
}

// nil when response's status is want, else what it counts as: a 429 limited, with its Retry-After; a 5xx unanswered;
// anything else refused.
func (self *InferModelDownload) statusResult(response *http.Response, source InferModelDownloadSource, want int) *inferFetchResult {
	switch {
	case response.StatusCode == want:
		return nil
	case response.StatusCode == http.StatusTooManyRequests:
		answeredAt := self.clock.Now()
		return &inferFetchResult{outcome: inferFetchLimited, retryAfter: self.retryAfterOf(response, answeredAt), answeredAt: answeredAt, why: "its rate limit"}
	case http.StatusInternalServerError <= response.StatusCode:
		return &inferFetchResult{outcome: inferFetchUnanswered, why: fmt.Sprintf("the %s answered %d", source, response.StatusCode)}
	}
	return &inferFetchResult{outcome: inferFetchRefused, why: fmt.Sprintf("the %s answered %d", source, response.StatusCode)}
}

// The wait a 429's Retry-After asks for, in seconds or as a date on this download's clock, read at now; 0 for none or
// one that does not read.
func (self *InferModelDownload) retryAfterOf(response *http.Response, now time.Time) time.Duration {
	value := strings.TrimSpace(response.Header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(min(seconds, int64(math.MaxInt64/time.Second))) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(0, at.Sub(now))
	}
	return 0
}

// Reads a chunk's answer whole into buffer, which holds the index's chunk size and a byte more: refused as corrupt
// for a Content-Length other than the chunk's, a body longer or shorter than it, which is never cut to fit, and bytes
// that are not its hash's.
func readInferChunkAnswer(response *http.Response, chunk *InferModelChunk, buffer []byte) *inferFetchResult {
	if 0 <= response.ContentLength && response.ContentLength != chunk.ByteCount {
		return &inferFetchResult{outcome: inferFetchCorrupt, why: fmt.Sprintf("an answer of %d bytes", response.ContentLength)}
	}
	bounded := buffer[:chunk.ByteCount+1]
	n := 0
	for n < len(bounded) {
		read, err := response.Body.Read(bounded[n:])
		n += read
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return &inferFetchResult{outcome: inferFetchReadFailed, err: err}
		}
	}
	switch {
	case chunk.ByteCount < int64(n):
		return &inferFetchResult{outcome: inferFetchCorrupt, why: "an answer longer than its entry"}
	case int64(n) < chunk.ByteCount:
		return &inferFetchResult{outcome: inferFetchCorrupt, why: "an answer shorter than its entry"}
	case !chunk.Matches(bounded[:n]):
		return &inferFetchResult{outcome: inferFetchCorrupt, why: "bytes that are not its hash's"}
	}
	return &inferFetchResult{outcome: inferFetchOk, data: bounded[:n]}
}

// One Fetch of one file, which holds the file's slot.
type inferDownloadRun struct {
	download  *InferModelDownload
	modelFile *InferModelFile
	file      *InferManifestModelFile
	settings  *InferSettings
	listener  func(*InferModelDownloadProgress)
	// the fallback's url, nil for none, and the client that follows its redirects
	hubUrl    *url.URL
	hubClient *http.Client

	// set before the chunks are fetched, then only read
	index    *InferModelIndex
	part     *os.File
	doneList *os.File

	// serializes the done list's appends; it guards no state
	appendLock sync.Mutex
	// serializes the listener's calls, so it hears the progress in order; it guards no state
	reportLock sync.Mutex

	stateLock sync.Mutex
	// by chunk, whether it is done
	done           []bool
	doneChunkCount int
	doneByteCount  int64
	// the chunks not done, in order, and the next of them to take
	missing     []int
	nextMissing int
	// the source: the api until it cannot be reached, then the hub until it answers again
	onHub              bool
	apiUnansweredCount int
	hubFailureCount    int
	apiProbeTime       time.Time
}

// A run of file's fetch.
func newInferDownloadRun(download *InferModelDownload, modelFile *InferModelFile, listener func(*InferModelDownloadProgress)) *inferDownloadRun {
	run := &inferDownloadRun{
		download:  download,
		modelFile: modelFile,
		file:      modelFile.file,
		settings:  download.settings,
		listener:  listener,
		hubUrl:    inferDownloadHubUrl(modelFile.file, download.settings),
	}
	if run.hubUrl != nil {
		run.hubClient = &http.Client{Transport: download.transport, CheckRedirect: run.checkHubRedirect}
	}
	return run
}

// The fetch: the whole file's check, the room, the index, the part, the chunks, then whole.
func (self *inferDownloadRun) fetch(ctx context.Context) error {
	file := self.modelFile
	// an index kept beside the file is trusted only through its pin, read again here, and only where it is needed
	var index *InferModelIndex
	indexRead := false
	keptIndex := func() *InferModelIndex {
		if !indexRead {
			index = file.keptIndex()
			indexRead = true
		}
		return index
	}
	state, _, err := file.checkWholeWithLock(ctx, keptIndex)
	if err != nil {
		return err
	}
	if state == inferModelWholeUnchecked {
		// a whole file its mark does not match is checked against its index, so with none kept the index comes first
		fetched, err := self.fetchIndex(ctx)
		if err != nil {
			return err
		}
		index = fetched
		if state, _, err = file.checkWholeWithLock(ctx, func() *InferModelIndex { return fetched }); err != nil {
			return err
		}
	}
	if state == inferModelWholeMarked {
		// what a crash between the rename and the cleanup left
		if err := file.removePartWithLock(); err != nil {
			return err
		}
		if self.listener != nil {
			self.reportWhole(keptIndex())
		}
		return nil
	}

	index = keptIndex()
	doneByteCount := int64(0)
	if index != nil {
		if doneByteCount, err = file.doneByteCountWithLock(index); err != nil {
			return err
		}
	}
	if err := self.checkRoom(file.file.ByteCount - doneByteCount); err != nil {
		return err
	}
	if index == nil {
		if index, err = self.fetchIndex(ctx); err != nil {
			return err
		}
	}
	self.index = index
	if err := self.openPart(); err != nil {
		return err
	}
	self.report()
	if err := self.fetchChunks(ctx); err != nil {
		return err
	}
	return self.finish()
}

// Refuses with download_no_space unless the directory's volume has leftByteCount free and the settings' margin of the
// file's size more.
func (self *inferDownloadRun) checkRoom(leftByteCount int64) error {
	fraction := self.settings.ModelFreeSpaceMarginFraction
	if !(0 < fraction) || math.IsInf(fraction, 0) {
		fraction = 0
	}
	needByteCount := leftByteCount + int64(math.Ceil(fraction*float64(self.file.ByteCount)))
	freeByteCount, err := self.download.freeByteCount(self.download.directory)
	if err != nil {
		return &InferDownloadError{Code: InferDownloadErrorNoSpace, Sha256: self.file.Sha256, Chunk: -1,
			Message: "the room on its volume could not be read"}
	}
	if freeByteCount < needByteCount {
		return &InferDownloadError{Code: InferDownloadErrorNoSpace, Sha256: self.file.Sha256, Chunk: -1,
			Message: fmt.Sprintf("it needs %d bytes free, and its volume has %d", needByteCount, freeByteCount)}
	}
	return nil
}

// The index, from the api alone: kept beside the file once it passes its pin. One off its pin is fetched again
// ModelChunkRetryCount times, then download_corrupt; the api unreachable, refusing, or past its unanswered count or its
// 429s is download_unavailable, since the hub serves no index.
func (self *inferDownloadRun) fetchIndex(ctx context.Context) (*InferModelIndex, error) {
	target := self.download.apiObjectUrl(self.file.Sha256, "index")
	corruptCount := 0
	limitedCount := 0
	unansweredCount := 0
	for {
		result := self.download.exchange(ctx, self.download.apiClient, http.MethodGet, target, nil, self.settings.ModelIndexTimeout, func(response *http.Response) *inferFetchResult {
			if result := self.download.statusResult(response, InferModelDownloadSourceApi, http.StatusOK); result != nil {
				return result
			}
			maxByteCount := int64(max(0, self.settings.ModelIndexMaxByteCount))
			if maxByteCount < response.ContentLength {
				return &inferFetchResult{outcome: inferFetchCorrupt, why: "an index past its bound"}
			}
			data, err := io.ReadAll(io.LimitReader(response.Body, maxByteCount+1))
			if err != nil {
				return &inferFetchResult{outcome: inferFetchReadFailed, err: err}
			}
			index, err := ParseInferModelIndex(data, self.file, self.settings)
			if err != nil {
				return &inferFetchResult{outcome: inferFetchCorrupt, why: "an index off its pin or malformed", cause: err}
			}
			return &inferFetchResult{outcome: inferFetchOk, index: index}
		})
		switch result.outcome {
		case inferFetchCanceled:
			return nil, result.err
		case inferFetchOk:
			if err := self.modelFile.keepIndexWithLock(result.index); err != nil {
				return nil, err
			}
			return result.index, nil
		case inferFetchCorrupt:
			corruptCount += 1
			self.download.log.Warningf("[infer_download]%s's index from the api failed its check (%s), %d of %d\n",
				self.file.Sha256, result.why, corruptCount, max(0, self.settings.ModelChunkRetryCount)+1)
			if max(0, self.settings.ModelChunkRetryCount) < corruptCount {
				return nil, &InferDownloadError{Code: InferDownloadErrorCorrupt, Sha256: self.file.Sha256, Chunk: -1,
					Message: fmt.Sprintf("it failed its check %d times", corruptCount), err: result.cause}
			}
		case inferFetchLimited:
			limitedCount += 1
			if max(0, self.settings.ModelRateLimitedMaxCount) < limitedCount {
				return nil, self.unavailable(-1, "the api kept refusing the index for its rate limit")
			}
			if err := self.waitUntil(ctx, result.answeredAt.Add(self.limitedWait(result))); err != nil {
				return nil, err
			}
		case inferFetchUnreachable:
			return nil, self.unavailable(-1, "the api cannot be reached for the index (%s), which only it serves", result.why)
		case inferFetchRefused:
			return nil, self.unavailable(-1, "the api refused the index: %s", result.why)
		default:
			unansweredCount += 1
			if max(1, self.settings.ModelApiUnreachableCount) <= unansweredCount {
				return nil, self.unavailable(-1, "the api did not answer for the index (%s), which only it serves", result.why)
			}
			if err := self.wait(ctx, self.settings.ModelFetchRetryInterval); err != nil {
				return nil, err
			}
		}
	}
}

// download_unavailable at chunk, -1 for none.
func (self *inferDownloadRun) unavailable(chunk int, format string, a ...any) *InferDownloadError {
	return &InferDownloadError{Code: InferDownloadErrorUnavailable, Sha256: self.file.Sha256, Chunk: chunk, Message: fmt.Sprintf(format, a...)}
}

// Waits timeout on the download's clock, or until ctx ends.
func (self *inferDownloadRun) wait(ctx context.Context, timeout time.Duration) error {
	select {
	case <-self.download.clock.After(timeout):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Waits until at on the download's clock, a wait for that time itself (QD-1425), or until ctx ends: a 429's wait,
// which runs from when its answer was read.
func (self *inferDownloadRun) waitUntil(ctx context.Context, at time.Time) error {
	select {
	case <-ClockAfterAt(self.download.clock, at):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// How long a 429 is waited out: its Retry-After, else the retry interval, at most the settings' bound.
func (self *inferDownloadRun) limitedWait(result *inferFetchResult) time.Duration {
	wait := result.retryAfter
	if wait <= 0 {
		wait = self.settings.ModelFetchRetryInterval
	}
	return max(0, min(wait, self.settings.ModelRetryAfterMaxDuration))
}

// Fetches the chunks not done, at most ModelChunkFetchConcurrency at a time, in order. The first failure stops the
// rest, and is what it answers.
func (self *inferDownloadRun) fetchChunks(ctx context.Context) error {
	if len(self.missing) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failure := error(nil)
	failureOnce := sync.Once{}
	fail := func(err error) {
		failureOnce.Do(func() {
			failure = err
			cancel()
		})
	}
	workerCount := min(max(1, self.settings.ModelChunkFetchConcurrency), len(self.missing))
	waitGroup := sync.WaitGroup{}
	for range workerCount {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			// a chunk is read whole, and a byte more to tell a longer answer, before its check
			buffer := make([]byte, self.index.ChunkByteCount()+1)
			for {
				chunk, ok := self.takeMissing()
				if !ok {
					return
				}
				if err := self.fetchChunk(ctx, chunk, buffer); err != nil {
					fail(err)
					return
				}
			}
		}()
	}
	waitGroup.Wait()
	return failure
}

// The next chunk not done, in order, or false when every one is taken.
func (self *inferDownloadRun) takeMissing() (*InferModelChunk, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.missing) <= self.nextMissing {
		return nil, false
	}
	n := self.missing[self.nextMissing]
	self.nextMissing += 1
	return self.index.Chunk(n)
}

// Fetches one chunk until it is written and marked done, from the source the run is on: fetched again for a failed
// check ModelChunkRetryCount times, waited out for a 429 ModelRateLimitedMaxCount times, and asked again, here or at the
// other source, after a timeout, a 5xx or a dropped connection, as the source's counts allow.
func (self *inferDownloadRun) fetchChunk(ctx context.Context, chunk *InferModelChunk, buffer []byte) error {
	corruptCount := 0
	limitedCount := 0
	for attempt := 0; ; attempt += 1 {
		if err := ctx.Err(); err != nil {
			return err
		}
		// the api is asked again only before a chunk's first request: a chunk moved to the hub stays there
		source := self.source(ctx, attempt == 0)
		var result *inferFetchResult
		if source == InferModelDownloadSourceHub {
			result = self.fetchHubChunk(ctx, chunk, buffer)
		} else {
			result = self.fetchApiChunk(ctx, chunk, buffer)
		}
		switch result.outcome {
		case inferFetchCanceled:
			return result.err
		case inferFetchOk:
			self.answered(source)
			return self.writeChunk(chunk, result.data)
		case inferFetchCorrupt:
			// the source answered, so it is reached
			self.answered(source)
			corruptCount += 1
			self.download.log.Warningf("[infer_download]%s's chunk %d from the %s failed its check (%s), %d of %d\n",
				self.file.Sha256, chunk.Number, source, result.why, corruptCount, max(0, self.settings.ModelChunkRetryCount)+1)
			if max(0, self.settings.ModelChunkRetryCount) < corruptCount {
				return &InferDownloadError{Code: InferDownloadErrorCorrupt, Sha256: self.file.Sha256, Chunk: chunk.Number,
					Message: fmt.Sprintf("it failed its check %d times", corruptCount)}
			}
		case inferFetchLimited:
			limitedCount += 1
			if max(0, self.settings.ModelRateLimitedMaxCount) < limitedCount {
				return self.unavailable(chunk.Number, "the %s kept refusing it for its rate limit", source)
			}
			if err := self.waitUntil(ctx, result.answeredAt.Add(self.limitedWait(result))); err != nil {
				return err
			}
		case inferFetchRefused:
			return self.unavailable(chunk.Number, "the %s refused it: %s", source, result.why)
		default:
			stop, wait := self.failed(source, result)
			if stop != nil {
				stop.Chunk = chunk.Number
				return stop
			}
			if wait {
				if err := self.wait(ctx, self.settings.ModelFetchRetryInterval); err != nil {
					return err
				}
			}
		}
	}
}

// One chunk from the api: GET <api>/compute/models/{sha256}/chunks/{n}, a 200 answered whole.
func (self *inferDownloadRun) fetchApiChunk(ctx context.Context, chunk *InferModelChunk, buffer []byte) *inferFetchResult {
	target := self.download.apiObjectUrl(self.file.Sha256, "chunks", strconv.Itoa(chunk.Number))
	return self.download.exchange(ctx, self.download.apiClient, http.MethodGet, target, nil, self.settings.ModelChunkTimeout, func(response *http.Response) *inferFetchResult {
		if result := self.download.statusResult(response, InferModelDownloadSourceApi, http.StatusOK); result != nil {
			return result
		}
		return readInferChunkAnswer(response, chunk, buffer)
	})
}

// Writes a checked chunk at its offset and syncs the part, and only then marks it done. A crash between the two
// fetches the chunk again; none marks a chunk whose bytes are not durable.
func (self *inferDownloadRun) writeChunk(chunk *InferModelChunk, data []byte) error {
	key := self.file.Sha256 + ":" + strconv.Itoa(chunk.Number)
	if _, err := self.part.WriteAt(data, chunk.Offset); err != nil {
		return fmt.Errorf("model download: writing chunk %d: %w", chunk.Number, err)
	}
	if err := self.part.Sync(); err != nil {
		return fmt.Errorf("model download: syncing chunk %d: %w", chunk.Number, err)
	}
	// the chunk's bytes are durable; until its record is, a crash fetches it again
	testHookBarrier("infer_download.chunk.synced", key)
	if err := self.appendDone(chunk); err != nil {
		return err
	}
	testHookBarrier("infer_download.chunk.marked", key)
	self.countDone(chunk)
	return nil
}

// Appends chunk's record to the done list and syncs it.
func (self *inferDownloadRun) appendDone(chunk *InferModelChunk) error {
	record := inferModelDoneRecord(self.modelFile.pinDigest, chunk.Number)
	self.appendLock.Lock()
	defer self.appendLock.Unlock()
	if _, err := self.doneList.Write(record); err != nil {
		return fmt.Errorf("model download: marking chunk %d done: %w", chunk.Number, err)
	}
	if err := self.doneList.Sync(); err != nil {
		return fmt.Errorf("model download: marking chunk %d done: %w", chunk.Number, err)
	}
	return nil
}

// Counts chunk done and tells the listener, one chunk a call, so it hears each count once and in order.
func (self *inferDownloadRun) countDone(chunk *InferModelChunk) {
	self.reportLock.Lock()
	defer self.reportLock.Unlock()
	progress := func() *InferModelDownloadProgress {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.done[chunk.Number] {
			self.done[chunk.Number] = true
			self.doneChunkCount += 1
			self.doneByteCount += chunk.ByteCount
		}
		return self.progressWithLock()
	}()
	if self.listener != nil {
		self.listener(progress)
	}
}

// Tells the listener where the download starts.
func (self *inferDownloadRun) report() {
	if self.listener == nil {
		return
	}
	self.reportLock.Lock()
	defer self.reportLock.Unlock()
	progress := func() *InferModelDownloadProgress {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.progressWithLock()
	}()
	self.listener(progress)
}

// Where the download is.
func (self *inferDownloadRun) progressWithLock() *InferModelDownloadProgress {
	source := InferModelDownloadSourceApi
	if self.onHub {
		source = InferModelDownloadSourceHub
	}
	return &InferModelDownloadProgress{
		Sha256:         self.file.Sha256,
		ChunkCount:     len(self.done),
		DoneChunkCount: self.doneChunkCount,
		ByteCount:      self.file.ByteCount,
		DoneByteCount:  self.doneByteCount,
		Source:         source,
	}
}

// Tells the listener the file is whole: by its index's chunks where one is known, else by its bytes alone.
func (self *inferDownloadRun) reportWhole(index *InferModelIndex) {
	if self.listener == nil {
		return
	}
	chunkCount := 0
	if index != nil {
		chunkCount = index.ChunkCount()
	}
	self.listener(&InferModelDownloadProgress{
		Sha256:         self.file.Sha256,
		ChunkCount:     chunkCount,
		DoneChunkCount: chunkCount,
		ByteCount:      self.file.ByteCount,
		DoneByteCount:  self.file.ByteCount,
		Source:         InferModelDownloadSourceApi,
	})
}
