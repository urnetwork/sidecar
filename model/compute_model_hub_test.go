package model

// The hub seam (CSRV-M11-02; DESIGN-COMPUTE §6.5, §14.5): the url rule, and ComputeModelHubFetcher against local TLS
// servers standing in for the hub and its CDN: the whole file from offset 0, a range from a later one, each declaring
// the size; a redirect to the CDN followed and one off the hub refused unfollowed; an answer of another range, the
// whole file to a range, a 404 and a 503 each read as they must be; and a body that stalls cut at the idle bound on a
// fake clock.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The url rule: a file of the organization's repository at a pinned commit, on the hub's host, plain throughout.
func TestComputeModelHubFileUrlTakesOnlyAPinnedCommit(t *testing.T) {
	settings := DefaultComputeModelMirrorSettings()
	settings.HubHost = "hub.example"
	commit := "0123456789abcdef0123456789abcdef01234567"
	good := []string{
		"https://hub.example/litert-community/gemma-4-E2B-it-litert-lm/resolve/" + commit + "/gemma-4-E2B-it.litertlm",
		"https://hub.example/litert-community/repo_1.x/resolve/" + commit + "/gpu/model-gpu.litertlm",
	}
	for _, fileUrl := range good {
		if got, err := ComputeModelHubFileUrl(fileUrl, settings); err != nil || got != fileUrl {
			t.Errorf("%s: %s, %v", fileUrl, got, err)
		}
	}
	bad := []string{
		"https://hub.example/litert-community/repo/resolve/main/model.litertlm",
		"https://hub.example/litert-community/repo/resolve/refs%2Fpr%2F1/model.litertlm",
		"https://hub.example/litert-community/repo/resolve/" + commit,
		"https://hub.example/litert-community/repo/resolve/" + commit + "/",
		"https://hub.example/litert-community/repo/resolve/" + commit + "/../secret",
		"https://hub.example/litert-community/repo/resolve/" + commit + "/./model.litertlm",
		"https://hub.example/litert-community/repo/resolve/" + commit + "/.hidden",
		"https://hub.example/litert-community/repo/resolve/" + commit + "/model%20a.litertlm",
		"https://hub.example/litert-community/repo/resolve/" + commit + "/model.litertlm?download=true",
		"https://hub.example/litert-community/repo/resolve/" + commit + "/model.litertlm#x",
		"https://user@hub.example/litert-community/repo/resolve/" + commit + "/model.litertlm",
		"https://hub.example:8443/litert-community/repo/resolve/" + commit + "/model.litertlm",
		"https://HUB.example/litert-community/repo/resolve/" + commit + "/model.litertlm",
		"https://hub.example/Litert-Community/repo/resolve/" + commit + "/model.litertlm",
		"https://hub.example/litert-community/-repo/resolve/" + commit + "/model.litertlm",
		"https://hub.example/litert-community//resolve/" + commit + "/model.litertlm",
		"https://hub.example/litert-community/repo/tree/" + commit + "/model.litertlm",
		"ftp://hub.example/litert-community/repo/resolve/" + commit + "/model.litertlm",
		"hub.example/litert-community/repo/resolve/" + commit + "/model.litertlm",
		"",
	}
	for _, fileUrl := range bad {
		if got, err := ComputeModelHubFileUrl(fileUrl, settings); !errors.Is(err, ErrComputeModelMirrorRefused) {
			t.Errorf("%q: %s, %v; want a refusal", fileUrl, got, err)
		}
	}
	empty := DefaultComputeModelMirrorSettings()
	empty.HubHost = ""
	if _, err := ComputeModelHubFileUrl(good[0], empty); !errors.Is(err, ErrComputeModelMirrorRefused) {
		t.Errorf("no hub host took %v", err)
	}
}

// A local TLS hub serving one file under a pinned path, and the fetcher's settings and transport to reach it. A test
// changes what it answers through set, since its handler runs on the server's goroutines.
type testComputeModelTlsHub struct {
	server   *httptest.Server
	settings *ComputeModelMirrorSettings
	data     []byte
	path     string

	stateLock sync.Mutex
	// a redirect the file's path answers in place of the file, where set
	redirect string
	// a status to answer in place of the file, where set
	status int
	// an answer to a range of the whole file
	ignoreRange bool
	// a range answered off by one
	offRange bool
	// closed by a test to end a stalled body
	stall chan struct{}
	// the Range header of each request
	ranges []string
}

// A hub on a local TLS server, closed with the test, answering the file whole.
func newTestComputeModelTlsHub(t *testing.T) *testComputeModelTlsHub {
	hub := &testComputeModelTlsHub{
		data: testComputeModelBytes(300*1024, 3),
		path: "/litert-community/repo/resolve/0123456789abcdef0123456789abcdef01234567/model.litertlm",
	}
	hub.server = httptest.NewTLSServer(http.HandlerFunc(hub.serve))
	t.Cleanup(hub.server.Close)
	address, err := url.Parse(hub.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	hub.settings = DefaultComputeModelMirrorSettings()
	hub.settings.HubHost = address.Host
	hub.settings.HubRedirectHostSuffixes = []string{"cdn.example"}
	return hub
}

// The file's url on this hub.
func (self *testComputeModelTlsHub) fileUrl() string {
	return self.server.URL + self.path
}

// The fetcher over the hub's own TLS client transport.
func (self *testComputeModelTlsHub) fetcher(clock *sidecartest.FakeClock) *ComputeModelHubFetcher {
	if clock == nil {
		return NewComputeModelHubFetcher(self.settings, self.server.Client().Transport, nil)
	}
	return NewComputeModelHubFetcher(self.settings, self.server.Client().Transport, clock)
}

// Changes what the hub answers, under its lock.
func (self *testComputeModelTlsHub) set(change func(hub *testComputeModelTlsHub)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	change(self)
}

// The Range header of each request so far.
func (self *testComputeModelTlsHub) seenRanges() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.ranges...)
}

// The hub's answer: the file, a range of it, a redirect, a status, or a body that stalls.
func (self *testComputeModelTlsHub) serve(w http.ResponseWriter, r *http.Request) {
	self.stateLock.Lock()
	self.ranges = append(self.ranges, r.Header.Get("Range"))
	redirect, status, ignoreRange, offRange, stall := self.redirect, self.status, self.ignoreRange, self.offRange, self.stall
	self.stateLock.Unlock()
	if r.URL.Path == "/cdn"+self.path || r.URL.Path == self.path && redirect == "" {
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Referer") != "" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		offset := int64(0)
		if value := r.Header.Get("Range"); value != "" && !ignoreRange {
			parsed, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(value, "bytes="), "-"), 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			offset = parsed
			first := offset
			if offRange {
				first += 1
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, len(self.data)-1, len(self.data)))
			w.Header().Set("Content-Length", strconv.Itoa(len(self.data)-int(offset)))
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(self.data)))
			w.WriteHeader(http.StatusOK)
		}
		if stall != nil {
			w.Write(self.data[offset : offset+10])
			w.(http.Flusher).Flush()
			<-stall
			return
		}
		w.Write(self.data[offset:])
		return
	}
	if r.URL.Path == self.path && redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

// The whole file from offset 0 and a range from a later offset, each with the file's size, no credential sent.
func TestComputeModelHubFetcherReadsTheFileAndARange(t *testing.T) {
	hub := newTestComputeModelTlsHub(t)
	ctx := context.Background()
	fetcher := hub.fetcher(nil)
	for _, offset := range []int64{0, 1000} {
		body, byteCount, err := fetcher.Open(ctx, hub.fileUrl(), offset)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(body)
		body.Close()
		if err != nil || byteCount != int64(len(hub.data)) || string(data) != string(hub.data[offset:]) {
			t.Fatalf("offset %d: %d bytes of a declared %d, %v", offset, len(data), byteCount, err)
		}
	}
	if ranges := hub.seenRanges(); len(ranges) != 2 || ranges[0] != "" || ranges[1] != "bytes=1000-" {
		t.Fatalf("the hub saw the ranges %q", ranges)
	}
}

// A redirect to the hub's CDN, a host under a suffix, is followed with the range; one to a host no suffix names, one
// off https, and more than the most redirects are refused unfollowed.
func TestComputeModelHubFetcherFollowsOnlyTheHubsRedirects(t *testing.T) {
	ctx := context.Background()
	hub := newTestComputeModelTlsHub(t)
	address, err := url.Parse(hub.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	hub.set(func(hub *testComputeModelTlsHub) { hub.redirect = hub.server.URL + "/cdn" + hub.path })
	body, _, err := hub.fetcher(nil).Open(ctx, hub.fileUrl(), 5)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(body)
	body.Close()
	if ranges := hub.seenRanges(); string(data) != string(hub.data[5:]) || ranges[len(ranges)-1] != "bytes=5-" {
		t.Fatalf("the redirect's answer, %d bytes, ranges %q", len(data), ranges)
	}

	for _, target := range []string{
		"https://cdn.attacker.example" + hub.path,
		"http://" + address.Host + "/cdn" + hub.path,
	} {
		hub.set(func(hub *testComputeModelTlsHub) { hub.redirect = target })
		_, _, err := hub.fetcher(nil).Open(ctx, hub.fileUrl(), 0)
		if !errors.Is(err, ErrComputeModelFetchRefused) {
			t.Fatalf("a redirect to %s: %v", target, err)
		}
	}

	hub.set(func(hub *testComputeModelTlsHub) { hub.redirect = hub.server.URL + "/cdn" + hub.path })
	hub.settings.HubRedirectMaxCount = -1
	if _, _, err := hub.fetcher(nil).Open(ctx, hub.fileUrl(), 0); !errors.Is(err, ErrComputeModelFetchRefused) {
		t.Fatalf("a redirect past the most: %v", err)
	}
}

// Answers the fetcher refuses for good, and one it reports as a failed request: the whole file to a range, a range off
// the one asked and a 404 are refused; a 503 is a failure to try again.
func TestComputeModelHubFetcherRefusesOtherAnswers(t *testing.T) {
	ctx := context.Background()
	for name, set := range map[string]func(hub *testComputeModelTlsHub){
		"whole file to a range": func(hub *testComputeModelTlsHub) { hub.ignoreRange = true },
		"another range":         func(hub *testComputeModelTlsHub) { hub.offRange = true },
		"404":                   func(hub *testComputeModelTlsHub) { hub.status = http.StatusNotFound },
	} {
		hub := newTestComputeModelTlsHub(t)
		hub.set(set)
		if _, _, err := hub.fetcher(nil).Open(ctx, hub.fileUrl(), 7); !errors.Is(err, ErrComputeModelFetchRefused) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	hub := newTestComputeModelTlsHub(t)
	hub.set(func(hub *testComputeModelTlsHub) { hub.status = http.StatusServiceUnavailable })
	_, _, err := hub.fetcher(nil).Open(ctx, hub.fileUrl(), 0)
	if err == nil || errors.Is(err, ErrComputeModelFetchRefused) {
		t.Fatalf("a 503: %v", err)
	}
	if _, _, err := hub.fetcher(nil).Open(ctx, strings.Replace(hub.fileUrl(), "0123456789abcdef0123456789abcdef01234567", "main", 1), 0); !errors.Is(err, ErrComputeModelFetchRefused) {
		t.Fatalf("a branch url: %v", err)
	}
}

// A body that brings no byte for HubReadIdleTimeout, on a fake clock, is cut: the read fails and the copy may resume.
func TestComputeModelHubFetcherCutsAStalledBody(t *testing.T) {
	hub := newTestComputeModelTlsHub(t)
	stall := make(chan struct{})
	hub.set(func(hub *testComputeModelTlsHub) { hub.stall = stall })
	defer close(stall)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	ctx := context.Background()
	body, _, err := hub.fetcher(clock).Open(ctx, hub.fileUrl(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	first := make([]byte, 10)
	if _, err := io.ReadFull(body, first); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := body.Read(make([]byte, 10))
		read <- err
	}()
	waitCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := clock.AwaitTimers(waitCtx, 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(hub.settings.HubReadIdleTimeout)
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("a stalled read returned no error")
		}
	case <-waitCtx.Done():
		t.Fatal("a stalled read was not cut")
	}
}
