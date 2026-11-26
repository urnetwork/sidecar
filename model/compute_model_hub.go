// The hub seam of the api's model mirror (DESIGN-COMPUTE §6.5's mirror row, §14.5; CO-49; CSRV-M11-02):
// compute_model_mirror's one outside host, Hugging Face, read only at a commit a manifest pins, through
// ComputeModelFetcher, which tests stand a fake hub behind.
//
// A model file's url must read https://<HubHost>/<HubOrganization>/<repository>/resolve/<commit>/<path>: the commit
// 40 lowercase hex digits, a commit's id, never a branch or a tag, which could move; the repository and each segment of
// the path plain (letters, digits, ".", "_" and "-", a letter or digit first), so no segment is "." or ".." or
// carries an escape; no port, user, query or fragment. Anything else is refused before any request.
//
// ComputeModelHubFetcher is the https client the job and the release tooling use: GET with no credential and no
// cookie, Accept-Encoding identity so no encoding changes what a range covers, and a Range from the offset a resumed
// copy asks; at most HubRedirectMaxCount redirects, each https to the url's own host or one under
// HubRedirectHostSuffixes (the hub's CDN), any other refused unfollowed and no Referer sent; a 200 from offset 0 or a
// 206 of exactly the range asked from a later one, each declaring the file's whole size, anything else refused unread;
// a body that brings no byte for HubReadIdleTimeout is cut, which the mirror reads as a failed read and resumes.
//
// Safe for concurrent use.

package model

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The hub's path word between a repository and its commit.
const computeModelHubResolve = "resolve"

// The length of a commit's id in lowercase hex.
const computeModelHubCommitHexLength = 40

// A hub request refused, which asking again would not mend: a url that pins no commit, a redirect off the hub, a 4xx
// but 408 and 429, or an answer of another range or no size. Anything else the fetcher returns is a failed request
// the mirror may try again.
var ErrComputeModelFetchRefused = errors.New("compute model fetch refused")

// The mirror's reads of the hub; ComputeModelHubFetcher, or a test's fake hub. Safe for concurrent use.
type ComputeModelFetcher interface {
	// The bytes of the file at fileUrl, a url ComputeModelHubFileUrl gave, from offset to the file's end, and the whole
	// file's size as the hub declares it. The caller closes the body. An error wrapping ErrComputeModelFetchRefused is
	// final; any other is a failed request.
	Open(ctx context.Context, fileUrl string, offset int64) (body io.ReadCloser, byteCount int64, err error)
}

// A refusal of a url, wrapping ErrComputeModelMirrorRefused.
func computeModelHubUrlRefusal(why string) error {
	return computeModelMirrorRefusal("a model file url %s", why)
}

// Whether segment is plain: letters, digits, ".", "_" and "-", a letter or digit first.
func computeModelHubSegmentPlain(segment string) bool {
	if segment == "" {
		return false
	}
	for i := 0; i < len(segment); i += 1 {
		c := segment[i]
		alphanumeric := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
		if !alphanumeric && (i == 0 || (c != '.' && c != '_' && c != '-')) {
			return false
		}
	}
	return true
}

// The url a model file is copied from, fileUrl as it stands, refused unless it names a file of the settings'
// organization on the settings' hub at a pinned commit (see the file's comment).
func ComputeModelHubFileUrl(fileUrl string, settings *ComputeModelMirrorSettings) (string, error) {
	parsed, err := url.Parse(fileUrl)
	if err != nil {
		return "", computeModelHubUrlRefusal("that does not parse")
	}
	switch {
	case parsed.Scheme != "https":
		return "", computeModelHubUrlRefusal("that is not https")
	case parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "":
		return "", computeModelHubUrlRefusal("with a user, a query or a fragment")
	case settings.HubHost == "" || parsed.Host != settings.HubHost:
		return "", computeModelHubUrlRefusal("off the hub's host")
	case parsed.RawPath != "" || parsed.EscapedPath() != parsed.Path:
		return "", computeModelHubUrlRefusal("with an escaped path")
	}
	segments := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if !strings.HasPrefix(parsed.Path, "/") || len(segments) < 5 {
		return "", computeModelHubUrlRefusal("that names no repository's file at a commit")
	}
	if settings.HubOrganization == "" || segments[0] != settings.HubOrganization {
		return "", computeModelHubUrlRefusal("outside the hub's organization")
	}
	if !computeModelHubSegmentPlain(segments[1]) || segments[2] != computeModelHubResolve {
		return "", computeModelHubUrlRefusal("that names no repository's file at a commit")
	}
	commit := segments[3]
	if len(commit) != computeModelHubCommitHexLength || strings.Trim(commit, "0123456789abcdef") != "" {
		return "", computeModelHubUrlRefusal("that names a branch or a tag, not a commit")
	}
	for _, segment := range segments[4:] {
		if !computeModelHubSegmentPlain(segment) {
			return "", computeModelHubUrlRefusal("whose path is not plain")
		}
	}
	return parsed.String(), nil
}

// A redirect a hub request may not follow.
var errComputeModelHubRedirectRefused = errors.New("a redirect off the hub refused")

// The https client of the hub.
type ComputeModelHubFetcher struct {
	settings *ComputeModelMirrorSettings
	client   *http.Client
	clock    sidecar.Clock
}

// The fetcher over transport, nil for one of the settings' own timeouts, with no proxy and no compression. A nil
// clock is the real one.
func NewComputeModelHubFetcher(settings *ComputeModelMirrorSettings, transport http.RoundTripper, clock sidecar.Clock) *ComputeModelHubFetcher {
	if settings == nil {
		settings = DefaultComputeModelMirrorSettings()
	}
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	if transport == nil {
		dialer := &net.Dialer{Timeout: max(0, settings.HubDialTimeout)}
		transport = &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   max(0, settings.HubTlsHandshakeTimeout),
			ResponseHeaderTimeout: max(0, settings.HubResponseHeaderTimeout),
			ForceAttemptHTTP2:     true,
			DisableCompression:    true,
		}
	}
	fetcher := &ComputeModelHubFetcher{
		settings: settings,
		clock:    clock,
	}
	fetcher.client = &http.Client{
		Transport:     transport,
		CheckRedirect: fetcher.checkRedirect,
	}
	return fetcher
}

// Whether target is a host a hub request may be sent to: https with no user, at origin's own host or one under a
// suffix, a suffix matching itself and every name under it.
func computeModelHubHostAllowed(target *url.URL, origin *url.URL, suffixes []string) bool {
	if target.Scheme != "https" || target.User != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "" {
		return false
	}
	if target.Host == origin.Host {
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

// The client's redirect policy: at most HubRedirectMaxCount, each to a host computeModelHubHostAllowed takes, with no
// Referer. A redirect carries the first request's range and encoding.
func (self *ComputeModelHubFetcher) checkRedirect(request *http.Request, via []*http.Request) error {
	if max(0, self.settings.HubRedirectMaxCount) < len(via) {
		return errComputeModelHubRedirectRefused
	}
	if len(via) == 0 || !computeModelHubHostAllowed(request.URL, via[0].URL, self.settings.HubRedirectHostSuffixes) {
		return errComputeModelHubRedirectRefused
	}
	request.Header.Del("Referer")
	return nil
}

// A refusal of the hub's answer, wrapping ErrComputeModelFetchRefused.
func computeModelFetchRefusal(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrComputeModelFetchRefused, fmt.Sprintf(format, a...))
}

// The file at fileUrl from offset: GET, with a Range from a positive offset; see ComputeModelFetcher.
func (self *ComputeModelHubFetcher) Open(ctx context.Context, fileUrl string, offset int64) (io.ReadCloser, int64, error) {
	if _, err := ComputeModelHubFileUrl(fileUrl, self.settings); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrComputeModelFetchRefused, err)
	}
	if offset < 0 {
		return nil, 0, computeModelFetchRefusal("a negative offset")
	}
	requestCtx, cancel := context.WithCancel(ctx)
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, fileUrl, nil)
	if err != nil {
		cancel()
		return nil, 0, computeModelFetchRefusal("a request that does not build")
	}
	request.Header.Set("Accept-Encoding", "identity")
	if 0 < offset {
		request.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	response, err := self.client.Do(request)
	if err != nil {
		cancel()
		if errors.Is(err, errComputeModelHubRedirectRefused) {
			return nil, 0, computeModelFetchRefusal("%s", errComputeModelHubRedirectRefused)
		}
		return nil, 0, err
	}
	byteCount, refusal, retry := computeModelHubAnswer(response, offset)
	if refusal != "" {
		response.Body.Close()
		cancel()
		if retry {
			return nil, 0, fmt.Errorf("the hub answered %s", refusal)
		}
		return nil, 0, computeModelFetchRefusal("the hub answered %s", refusal)
	}
	return &computeModelIdleBody{
		body:   response.Body,
		cancel: cancel,
		clock:  self.clock,
		idle:   self.settings.HubReadIdleTimeout,
	}, byteCount, nil
}

// The whole file's size an answer to a request from offset declares, or why it is not one to read, and whether a
// later request may be answered otherwise: a 200 of the whole file from offset 0, its Content-Length the size; a 206
// of exactly bytes offset to the end from a later one, its Content-Range giving the size.
func computeModelHubAnswer(response *http.Response, offset int64) (int64, string, bool) {
	switch {
	case 500 <= response.StatusCode || response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests:
		return 0, fmt.Sprintf("%d", response.StatusCode), true
	case offset == 0 && response.StatusCode == http.StatusOK:
		if response.ContentLength < 0 {
			return 0, "a file of no declared size", false
		}
		return response.ContentLength, "", false
	case 0 < offset && response.StatusCode == http.StatusPartialContent:
		byteCount, ok := computeModelHubContentRange(response.Header.Get("Content-Range"), offset)
		if !ok || response.ContentLength != byteCount-offset {
			return 0, "another range than the one asked", false
		}
		return byteCount, "", false
	case 0 < offset && response.StatusCode == http.StatusOK:
		// the whole file, which is never read to find the range in it
		return 0, "the whole file to a range", false
	}
	return 0, fmt.Sprintf("%d", response.StatusCode), false
}

// The file's whole size a Content-Range of bytes offset to the file's end gives, as "bytes <offset>-<size - 1>/<size>";
// false for any other range or a size it does not give.
func computeModelHubContentRange(value string, offset int64) (int64, bool) {
	rest, ok := strings.CutPrefix(value, "bytes ")
	if !ok {
		return 0, false
	}
	span, total, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, false
	}
	first, last, ok := strings.Cut(span, "-")
	if !ok {
		return 0, false
	}
	number := func(text string) (int64, bool) {
		if text == "" || (text[0] == '0' && 1 < len(text)) || strings.Trim(text, "0123456789") != "" {
			return 0, false
		}
		n, err := strconv.ParseInt(text, 10, 64)
		return n, err == nil
	}
	firstN, ok := number(first)
	if !ok || firstN != offset {
		return 0, false
	}
	lastN, ok := number(last)
	if !ok {
		return 0, false
	}
	totalN, ok := number(total)
	if !ok || lastN+1 != totalN {
		return 0, false
	}
	return totalN, true
}

// The hub's body, its request cut when a read brings no byte for idle, a non-positive idle cutting none. Not safe for
// concurrent use, as a body is not.
type computeModelIdleBody struct {
	body   io.ReadCloser
	cancel context.CancelFunc
	clock  sidecar.Clock
	idle   time.Duration
}

// The body's next bytes, within the idle bound.
func (self *computeModelIdleBody) Read(out []byte) (int, error) {
	if 0 < self.idle {
		stop := self.clock.AfterFunc(self.idle, self.cancel)
		defer stop()
	}
	return self.body.Read(out)
}

// Closes the body and ends its request.
func (self *computeModelIdleBody) Close() error {
	err := self.body.Close()
	self.cancel()
	return err
}
