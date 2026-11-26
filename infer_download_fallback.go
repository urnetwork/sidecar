//go:build !ios_extension && !sidecar_http

// §6.5's fallback (D-INFER-12), the daemon's and the apps', never the browser's, whose download is JS (INFER-M13-02):
// where the api cannot be reached, a download's chunks come from the manifest's url, the Hugging Face address at the
// file's pinned commit, by a Range request at each chunk's offset, checked against the same index as the api's.
//
// The api cannot be reached when a connection to it is refused, has no route, or its name has none, at once; or after
// ModelApiUnreachableCount timeouts, 5xx answers or dropped connections in a row, any answer of the api's starting
// that count again. While the chunks come from the hub, the api is asked again, a HEAD of the file's index, at most
// every ModelApiProbeInterval and only before a chunk's first request, and the chunks go back to it at the next chunk
// once it answers: a chunk moved to the hub is retried there, so an api that answers its probe and fails its chunks
// cannot hold the download between the two. ModelHubFailureMaxCount failed requests in a row at the hub stop the
// download with download_unavailable, as an api that cannot be reached does where the settings turn the fallback off
// or the manifest gives no https url.
//
// The hub's answer must be a 206 whose Content-Range is exactly the range asked, of the file's size or an unknown one:
// a 200, which would be the whole file, or another range is refused unread, never cut to fit. A request follows at
// most ModelHubRedirectMaxCount redirects, each https and to the manifest url's own host or one under
// ModelHubRedirectHostSuffixes, the hub's CDN; any other is refused. Like the api's, the request carries no credential:
// the Range alone, and an Accept-Encoding of identity, so no encoding changes what the range covers.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// A redirect the hub's request may not follow.
var errInferDownloadRedirectRefused = errors.New("model download: a redirect refused")

// The manifest url file's fallback takes, or nil for none: the settings turn the fallback off, or the url is no https
// url with a host.
func inferDownloadHubUrl(file *InferManifestModelFile, settings *InferSettings) *url.URL {
	if !settings.ModelHubFallback {
		return nil
	}
	hubUrl, err := url.Parse(file.Url)
	if err != nil || hubUrl.Scheme != "https" || hubUrl.Hostname() == "" || hubUrl.User != nil || hubUrl.Fragment != "" {
		return nil
	}
	return hubUrl
}

// Whether target is a host a hub request may be sent to: https, with no user, at hubUrl's own host or one under a
// suffix, a suffix matching itself and every name under it.
func inferDownloadHubHostAllowed(target *url.URL, hubUrl *url.URL, suffixes []string) bool {
	if target.Scheme != "https" || target.User != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "" {
		return false
	}
	if host == strings.ToLower(strings.TrimSuffix(hubUrl.Hostname(), ".")) {
		return true
	}
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.Trim(suffix, "."))
		if suffix != "" && (host == suffix || strings.HasSuffix(host, "."+suffix)) {
			return true
		}
	}
	return false
}

// The hub client's redirect policy. A redirect it follows carries the first request's range and encoding, and no
// Referer, which net/http would add.
func (self *inferDownloadRun) checkHubRedirect(request *http.Request, via []*http.Request) error {
	if max(0, self.settings.ModelHubRedirectMaxCount) < len(via) {
		return errInferDownloadRedirectRefused
	}
	if !inferDownloadHubHostAllowed(request.URL, self.hubUrl, self.settings.ModelHubRedirectHostSuffixes) {
		return errInferDownloadRedirectRefused
	}
	request.Header.Del("Referer")
	return nil
}

// One chunk from the hub: GET of the manifest's url with a Range of the chunk's offsets, a 206 of exactly that range
// read whole.
func (self *inferDownloadRun) fetchHubChunk(ctx context.Context, chunk *InferModelChunk, buffer []byte) *inferFetchResult {
	end := chunk.Offset + chunk.ByteCount - 1
	header := http.Header{"Range": []string{fmt.Sprintf("bytes=%d-%d", chunk.Offset, end)}}
	return self.download.exchange(ctx, self.hubClient, http.MethodGet, self.hubUrl.String(), header, self.settings.ModelChunkTimeout, func(response *http.Response) *inferFetchResult {
		switch response.StatusCode {
		case http.StatusPartialContent:
		case http.StatusOK:
			// the whole file, which is never read to find the range in it
			return &inferFetchResult{outcome: inferFetchRefused, why: "an answer of the whole file to a range"}
		default:
			if result := self.download.statusResult(response, InferModelDownloadSourceHub, http.StatusPartialContent); result != nil {
				return result
			}
		}
		if !inferDownloadContentRangeIs(response.Header.Get("Content-Range"), chunk.Offset, end, self.file.ByteCount) {
			return &inferFetchResult{outcome: inferFetchRefused, why: "an answer of another range than the one asked"}
		}
		return readInferChunkAnswer(response, chunk, buffer)
	})
}

// Whether a Content-Range is exactly bytes start-end of a file of byteCount bytes, or of a size it does not give.
func inferDownloadContentRangeIs(value string, start int64, end int64, byteCount int64) bool {
	rest, ok := strings.CutPrefix(value, "bytes ")
	if !ok {
		return false
	}
	span, total, ok := strings.Cut(rest, "/")
	if !ok {
		return false
	}
	first, last, ok := strings.Cut(span, "-")
	if !ok {
		return false
	}
	number := func(text string) (int64, bool) {
		if text == "" || (text[0] == '0' && 1 < len(text)) {
			return 0, false
		}
		for i := 0; i < len(text); i += 1 {
			if text[i] < '0' || '9' < text[i] {
				return 0, false
			}
		}
		n, err := strconv.ParseInt(text, 10, 64)
		return n, err == nil
	}
	firstN, ok := number(first)
	if !ok || firstN != start {
		return false
	}
	lastN, ok := number(last)
	if !ok || lastN != end {
		return false
	}
	if total == "*" {
		return true
	}
	totalN, ok := number(total)
	return ok && totalN == byteCount
}

// The source a chunk's next request goes to: the api, or the hub while the api cannot be reached, which before a
// chunk's first request, chunkStart, asks the api again at most every ModelApiProbeInterval and takes it back once it
// answers.
func (self *inferDownloadRun) source(ctx context.Context, chunkStart bool) InferModelDownloadSource {
	probe := false
	onHub := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.onHub {
			return false
		}
		now := self.download.clock.Now()
		if chunkStart && self.settings.ModelApiProbeInterval <= now.Sub(self.apiProbeTime) {
			self.apiProbeTime = now
			probe = true
		}
		return true
	}()
	if !onHub {
		return InferModelDownloadSourceApi
	}
	if probe && self.probeApi(ctx) {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.onHub = false
			self.apiUnansweredCount = 0
		}()
		self.download.log.Infof("[infer_download]%s's chunks come from the api again\n", self.file.Sha256)
		return InferModelDownloadSourceApi
	}
	return InferModelDownloadSourceHub
}

// Whether the api answers: a HEAD of the file's index, answered 200.
func (self *inferDownloadRun) probeApi(ctx context.Context) bool {
	target := self.download.apiObjectUrl(self.file.Sha256, "index")
	result := self.download.exchange(ctx, self.download.apiClient, http.MethodHead, target, nil, self.settings.ModelIndexTimeout, func(response *http.Response) *inferFetchResult {
		if response.StatusCode == http.StatusOK {
			return &inferFetchResult{outcome: inferFetchOk}
		}
		return &inferFetchResult{outcome: inferFetchRefused}
	})
	return result.outcome == inferFetchOk
}

// The source answered, so its count of failures starts again.
func (self *inferDownloadRun) answered(source InferModelDownloadSource) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if source == InferModelDownloadSourceHub {
		self.hubFailureCount = 0
	} else {
		self.apiUnansweredCount = 0
	}
}

// Counts a request the source could not answer: at the api, an unreachable one moves the download to the hub at once
// and an unanswered one once there are ModelApiUnreachableCount in a row; at the hub, ModelHubFailureMaxCount in a
// row stop it. The error is the stop, where the download stops; wait is whether to wait the retry interval before the
// next request, which a move to the hub does not.
func (self *inferDownloadRun) failed(source InferModelDownloadSource, result *inferFetchResult) (*InferDownloadError, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if source == InferModelDownloadSourceHub {
		self.hubFailureCount += 1
		if max(1, self.settings.ModelHubFailureMaxCount) <= self.hubFailureCount {
			return self.unavailable(-1, "neither the api nor the hub answered (%s)", result.why), false
		}
		return nil, true
	}
	unreachable := result.outcome == inferFetchUnreachable
	if !unreachable {
		self.apiUnansweredCount += 1
		unreachable = max(1, self.settings.ModelApiUnreachableCount) <= self.apiUnansweredCount
	}
	if !unreachable {
		return nil, true
	}
	if self.hubUrl == nil {
		return self.unavailable(-1, "the api cannot be reached (%s), and this download has no fallback", result.why), false
	}
	if !self.onHub {
		// the hub's count runs on from its last failure, and only its answer starts it again, so an api that answers
		// its probe and fails its chunks, with a hub that fails too, cannot move the download back and forth for ever
		self.onHub = true
		self.apiProbeTime = self.download.clock.Now()
		self.download.log.Infof("[infer_download]%s's chunks come from the hub: the api cannot be reached (%s)\n", self.file.Sha256, result.why)
	}
	return nil, false
}
