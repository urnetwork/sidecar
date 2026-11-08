package localstack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a scripted store saw, with handler answering each object request. Bucket requests pass.
type scriptedStore struct {
	stateLock sync.Mutex
	requests  []*http.Request
	bodies    [][]byte
}

func (self *scriptedStore) last(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.requests) == 0 {
		t.Fatal("no request reached the store")
	}
	return self.requests[len(self.requests)-1], self.bodies[len(self.bodies)-1]
}

func newScriptedCluster(t *testing.T, handler http.HandlerFunc) (*scriptedStore, sidecar.BlobCluster) {
	return newScriptedClusterOn(t, nil, handler)
}

// As newScriptedCluster, on clock, nil being real time.
func newScriptedClusterOn(t *testing.T, clock sidecartest.Clock, handler http.HandlerFunc) (*scriptedStore, sidecar.BlobCluster) {
	store := &scriptedStore{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Count(request.URL.Path, "/") == 1 && request.Method == http.MethodPut {
			return
		}
		body, _ := io.ReadAll(request.Body)
		func() {
			store.stateLock.Lock()
			defer store.stateLock.Unlock()
			store.requests = append(store.requests, request)
			store.bodies = append(store.bodies, body)
		}()
		handler(writer, request)
	}))
	server.Listener.Close()
	server.Listener = listenOnStackPort(t)
	server.Start()
	t.Cleanup(server.Close)

	settings := DefaultBlobSettings()
	settings.Endpoint = server.URL
	settings.Clock = clock
	blobs, err := NewBlobStore(t.Context(), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(blobs.Close)
	cluster, err := blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	return store, cluster
}

func answer(status int, code string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(status)
		fmt.Fprintf(writer, "<Error><Code>%s</Code><Message>from the script</Message></Error>", code)
	}
}

func TestAnEndpointOffTheStackIsRefused(t *testing.T) {
	for _, endpoint := range []string{"http://203.0.113.7:59000", "http://127.0.0.1:6379", "http://store.example:59000"} {
		settings := DefaultBlobSettings()
		settings.Endpoint = endpoint
		if _, err := NewBlobStore(t.Context(), settings); err == nil {
			t.Errorf("%s was taken", endpoint)
		}
	}
}

// host_blobs.go: only these are definite. Everything else, however it reads, leaves a write unknown.
func TestWhatEachPutAnswerMeans(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
		want   error
	}{
		{status: http.StatusPreconditionFailed, code: "PreconditionFailed", want: sidecar.ErrBlobPrecondition},
		// MinIO's answer to an If-Match on a key that is not there
		{status: http.StatusNotFound, code: "NoSuchKey", want: sidecar.ErrBlobPrecondition},
		{status: http.StatusBadRequest, code: "XAmzContentChecksumMismatch", want: sidecar.ErrBlobChecksum},
		{status: http.StatusBadRequest, code: "BadDigest", want: sidecar.ErrBlobChecksum},
		{status: http.StatusInternalServerError, code: "InternalError"},
		{status: http.StatusServiceUnavailable, code: "SlowDownWrite"},
		{status: http.StatusServiceUnavailable, code: "DeadlinePassed"},
		{status: http.StatusForbidden, code: "AccessDenied"},
		{status: http.StatusNotFound, code: "NoSuchBucket"},
	} {
		_, cluster := newScriptedCluster(t, answer(c.status, c.code))
		_, err := cluster.PutIfMatch(t.Context(), "k", "etag", []byte("v"), nil)
		if c.want != nil {
			if !errors.Is(err, c.want) {
				t.Errorf("%d %s: %v", c.status, c.code, err)
			}
			continue
		}
		var unknown *sidecar.BlobUnknownError
		if !errors.As(err, &unknown) {
			t.Errorf("%d %s: %v, want unknown", c.status, c.code, err)
		}
	}
}

func TestADeleteIsDefiniteOnlyWhenItSucceeds(t *testing.T) {
	_, cluster := newScriptedCluster(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	if err := cluster.Delete(t.Context(), "k"); err != nil {
		t.Errorf("err %v", err)
	}
	_, cluster = newScriptedCluster(t, answer(http.StatusServiceUnavailable, "SlowDownWrite"))
	var unknown *sidecar.BlobUnknownError
	if err := cluster.Delete(t.Context(), "k"); !errors.As(err, &unknown) {
		t.Errorf("err %v", err)
	}
}

// A redirect could go anywhere, and CheckStackAddress passed only the endpoint.
func TestARedirectIsNeverFollowed(t *testing.T) {
	_, cluster := newScriptedCluster(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Location", "http://203.0.113.7:59000/elsewhere")
		writer.WriteHeader(http.StatusTemporaryRedirect)
	})
	var unknown *sidecar.BlobUnknownError
	if _, err := cluster.PutIfNoneMatch(t.Context(), "k", []byte("v"), nil); !errors.As(err, &unknown) {
		t.Errorf("err %v", err)
	}
}

func TestAConditionalPutSaysItsConditionAndContent(t *testing.T) {
	store, cluster := newScriptedCluster(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Etag", `"new-etag"`)
	})
	sum := sha256.Sum256([]byte("body"))
	options := &sidecar.BlobPutOptions{Sha256: sum[:], Metadata: map[string]string{"entry-state": "live"}}
	etag, err := cluster.PutIfMatch(t.Context(), "head/repo/ref", "old-etag", []byte("body"), options)
	if err != nil {
		t.Fatal(err)
	}
	if etag != "new-etag" {
		t.Errorf("etag %q", etag)
	}
	request, body := store.last(t)
	if request.Header.Get("If-Match") != `"old-etag"` || request.Header.Get("If-None-Match") != "" {
		t.Errorf("conditions %q, %q", request.Header.Get("If-Match"), request.Header.Get("If-None-Match"))
	}
	if !bytes.Equal(body, []byte("body")) || request.URL.Path != "/sidecar-test-meta-1/head/repo/ref" {
		t.Errorf("%s holds %q", request.URL.Path, body)
	}
	if request.Header.Get("Content-Type") != blobContentType {
		t.Errorf("content type %q", request.Header.Get("Content-Type"))
	}
	if request.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Errorf("checksum %q", request.Header.Get("X-Amz-Checksum-Sha256"))
	}
	if request.Header.Get("X-Amz-Meta-Entry-State") != "live" {
		t.Errorf("metadata %q", request.Header.Get("X-Amz-Meta-Entry-State"))
	}

	if _, err := cluster.PutIfNoneMatch(t.Context(), "k", []byte("body"), nil); err != nil {
		t.Fatal(err)
	}
	request, _ = store.last(t)
	if request.Header.Get("If-None-Match") != "*" || request.Header.Get("If-Match") != "" {
		t.Errorf("conditions %q, %q", request.Header.Get("If-None-Match"), request.Header.Get("If-Match"))
	}
}

func TestAnEmptyEtagSendsNothing(t *testing.T) {
	store, cluster := newScriptedCluster(t, answer(http.StatusOK, ""))
	if _, err := cluster.PutIfMatch(t.Context(), "k", "", []byte("v"), nil); !errors.Is(err, sidecar.ErrBlobPutOptions) {
		t.Errorf("err %v", err)
	}
	if len(store.requests) != 0 {
		t.Errorf("%d requests", len(store.requests))
	}
}

func deadlineOf(t *testing.T, request *http.Request) time.Time {
	t.Helper()
	milliseconds, err := strconv.ParseInt(request.Header.Get(blobDeadlineHeader), 10, 64)
	if err != nil {
		t.Fatalf("no deadline: %v", err)
	}
	return time.UnixMilli(milliseconds)
}

// §19.6: every request but a streamed PUT carries its deadline, its own or RequestTimeout's.
func TestEveryRequestButAStreamCarriesItsDeadline(t *testing.T) {
	store, cluster := newScriptedCluster(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		switch request.Method {
		case http.MethodDelete:
			writer.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			if request.URL.Query().Get("list-type") != "" {
				fmt.Fprint(writer, "<ListBucketResult></ListBucketResult>")
			}
		}
	})
	before := time.Now()
	ctx := t.Context()
	calls := []func() error{
		func() error {
			_, err := cluster.PutIfNoneMatch(ctx, "k", []byte("v"), nil)
			return err
		},
		func() error {
			object, err := cluster.Get(ctx, "k")
			if err == nil {
				object.Body.Close()
			}
			return err
		},
		func() error {
			_, err := cluster.Head(ctx, "k")
			return err
		},
		func() error {
			_, _, err := cluster.List(ctx, "k", "", 1)
			return err
		},
		func() error {
			return cluster.Delete(ctx, "k")
		},
	}
	for index, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("call %d: %v", index, err)
		}
		request, _ := store.last(t)
		deadline := deadlineOf(t, request)
		if deadline.Before(before.Add(cluster.RequestTimeout()-time.Millisecond)) || time.Now().Add(cluster.RequestTimeout()).Before(deadline) {
			t.Errorf("call %d: deadline %v", index, deadline)
		}
	}

	sum := sha256.Sum256([]byte("v"))
	if _, err := cluster.PutStream(ctx, "s", strings.NewReader("v"), 1, sum[:]); err != nil {
		t.Fatal(err)
	}
	request, _ := store.last(t)
	if value := request.Header.Get(blobDeadlineHeader); value != "" {
		t.Errorf("a stream carried %q", value)
	}
	if request.Header.Get("If-None-Match") != "*" || request.ContentLength != 1 {
		t.Errorf("a stream: %q, %d", request.Header.Get("If-None-Match"), request.ContentLength)
	}
}

func TestAnEarlierDeadlineIsTheOneSent(t *testing.T) {
	store, cluster := newScriptedCluster(t, answer(http.StatusOK, ""))
	own := time.Now().Add(1 * time.Second).Truncate(time.Millisecond)
	if _, err := cluster.PutIfNoneMatch(sidecar.WithBlobDeadline(t.Context(), own), "k", []byte("v"), nil); err != nil {
		t.Fatal(err)
	}
	request, _ := store.last(t)
	if !deadlineOf(t, request).Equal(own) {
		t.Errorf("deadline %v, want %v", deadlineOf(t, request), own)
	}
}

// §19.6: this client cancels at the deadline, and what the store did stays unknown.
func TestAHungWriteIsAbandonedAtItsDeadlineAsUnknown(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	_, cluster := newScriptedClusterOn(t, clock, func(writer http.ResponseWriter, request *http.Request) {
		close(entered)
		<-release
	})
	done := make(chan error, 1)
	go func() {
		_, err := cluster.PutIfNoneMatch(t.Context(), "k", []byte("v"), nil)
		done <- err
	}()
	<-entered
	clock.Advance(cluster.RequestTimeout())
	var unknown *sidecar.BlobUnknownError
	if err := <-done; !errors.As(err, &unknown) {
		t.Errorf("err %v", err)
	}
}

// The deadline covers the response's start: a body then streams under ctx alone (host_blobs.go).
func TestABodyOutlivesTheDeadlineOfItsRequest(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	release := make(chan struct{})
	_, cluster := newScriptedClusterOn(t, clock, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Last-Modified", clock.Now().Format(http.TimeFormat))
		writer.Header().Set("Content-Length", "2")
		fmt.Fprint(writer, "a")
		writer.(http.Flusher).Flush()
		<-release
		fmt.Fprint(writer, "b")
	})
	object, err := cluster.Get(t.Context(), "k")
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	clock.Advance(cluster.RequestTimeout())
	close(release)
	body, err := io.ReadAll(object.Body)
	if err != nil || string(body) != "ab" {
		t.Errorf("body %q, %v", body, err)
	}
}

func TestACancelledReadFailsPlainly(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	_, cluster := newScriptedCluster(t, func(writer http.ResponseWriter, request *http.Request) {
		close(entered)
		<-release
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := cluster.Head(ctx, "k")
		done <- err
	}()
	<-entered
	cancel()
	err := <-done
	var unknown *sidecar.BlobUnknownError
	if err == nil || errors.As(err, &unknown) {
		t.Errorf("err %v: a read is never unknown", err)
	}
}

func TestReadsNameWhatIsMissing(t *testing.T) {
	_, cluster := newScriptedCluster(t, answer(http.StatusNotFound, "NoSuchKey"))
	if _, err := cluster.Get(t.Context(), "k"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Errorf("get: %v", err)
	}
	if _, err := cluster.GetRange(t.Context(), "k", 0, 1); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Errorf("range: %v", err)
	}
	if _, err := cluster.Head(t.Context(), "k"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Errorf("head: %v", err)
	}
	_, cluster = newScriptedCluster(t, answer(http.StatusRequestedRangeNotSatisfiable, "InvalidRange"))
	if _, err := cluster.GetRange(t.Context(), "k", 100, 1); !errors.Is(err, sidecar.ErrBlobRange) {
		t.Errorf("range: %v", err)
	}
}

func TestARangeReadsTheWholeObjectsSize(t *testing.T) {
	store, cluster := newScriptedCluster(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		writer.Header().Set("Etag", `"etag"`)
		writer.Header().Set("Content-Range", "bytes 4-7/16")
		writer.Header().Set("X-Amz-Meta-Entry-State", "live")
		writer.WriteHeader(http.StatusPartialContent)
		fmt.Fprint(writer, "4567")
	})
	object, err := cluster.GetRange(t.Context(), "k", 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Body.Close()
	request, _ := store.last(t)
	if request.Header.Get("Range") != "bytes=4-7" {
		t.Errorf("range %q", request.Header.Get("Range"))
	}
	if object.ByteCount != 16 || object.Etag != "etag" || object.Metadata["entry-state"] != "live" {
		t.Errorf("info %+v", object.BlobInfo)
	}
	if body, err := io.ReadAll(object.Body); err != nil || string(body) != "4567" {
		t.Errorf("body %q, %v", body, err)
	}
}

func TestListReadsItsPage(t *testing.T) {
	store, cluster := newScriptedCluster(t, func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, `<ListBucketResult><IsTruncated>true</IsTruncated>
			<Contents><Key>p/a/_</Key><Size>12</Size><ETag>&#34;etag&#34;</ETag><LastModified>2026-10-21T07:28:00.123Z</LastModified></Contents>
		</ListBucketResult>`)
	})
	objects, more, err := cluster.List(t.Context(), "p/", "p/0", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !more || len(objects) != 1 {
		t.Fatalf("%d objects, more %v", len(objects), more)
	}
	object := objects[0]
	if object.Key != "p/a/_" || object.ByteCount != 12 || object.Etag != "etag" || object.LastModified.UnixMilli() != 1792567680123 {
		t.Errorf("object %+v", object)
	}
	request, _ := store.last(t)
	query := request.URL.Query()
	if query.Get("prefix") != "p/" || query.Get("start-after") != "p/0" || query.Get("max-keys") != "1" || query.Get("list-type") != "2" {
		t.Errorf("query %v", query)
	}
}

func TestAStreamNeverGoesOutCutShort(t *testing.T) {
	for _, c := range []struct {
		body      string
		byteCount int64
		ok        bool
	}{
		{body: "abc", byteCount: 3, ok: true},
		{body: "abcd", byteCount: 3, ok: false},
		{body: "ab", byteCount: 3, ok: false},
		{body: "", byteCount: 0, ok: true},
	} {
		written := []byte{}
		_, cluster := newScriptedCluster(t, func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Etag", `"etag"`)
		})
		sum := sha256.Sum256([]byte(c.body))
		_, err := cluster.PutStream(t.Context(), "s", strings.NewReader(c.body), c.byteCount, sum[:])
		if (err == nil) != c.ok {
			t.Errorf("%q as %d: %v (%q)", c.body, c.byteCount, err, written)
		}
	}
}
