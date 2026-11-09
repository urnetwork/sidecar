// T2's api (§22.4): the routes sidecars and gates call on server's api, in memory, on the Net's clock and fault
// queue, with the first metadata cluster on the Net's fake Blobs. server cannot be imported here, so each route copies
// only the steps a schedule relies on, and T3 reruns the same schedules on server's real routes (Q-TEST-1): a
// divergence fails. fake_api_config.go adds §7.9's authorization log; CORE-M1-13 adds enrollment, bind and refresh
// in its own file.
//
// Requests reach it through Transport, an http.RoundTripper that serves in process, so a client of api built with it
// (SidecarApi's transport, a gate's source) sends real requests with no socket. Each request first takes a fault
// plan of FaultOpHttp keyed by its path: ApplyThenDrop serves it and loses the answer, FailBeforeApply loses the
// request, and the crash results serve it or not and never answer, until the request's context ends.
//
// A bearer names a client of a network, which ClientToken mints; a request without one known here is 401, as api
// answers a bad token. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// The transport's answer when a fault loses a request or its response: what a client sees of a dropped connection.
var errFakeApiTransport = errors.New("connection reset by the fault plan")

type FakeApiSettings struct {
	// The origin requests name. A .example host, which no real api answers (CODESTYLE's test data rule).
	Origin string
	// The most entries one GET /network/config/projection answers; more follow from the last one's position. 1,024,
	// §7.9's fold span, so a reader at the newest base's tail takes it in one read.
	ProjectionPageCount int
	// How many positions one append tries before it answers 503, each a 412 or a lost race (§7.9's statement row).
	// 64: every attempt is another appender's landed entry, so this bounds only a stream of them.
	AppendAttemptCount int
	// The longest request body a route reads: a base's 4 MiB of rows as base64 in JSON, with room.
	MaxRequestByteCount int64
}

func DefaultFakeApiSettings() *FakeApiSettings {
	return &FakeApiSettings{
		Origin:              "https://api.sidecartest.example",
		ProjectionPageCount: 1024,
		AppendAttemptCount:  64,
		MaxRequestByteCount: 8 * 1024 * 1024,
	}
}

// One client a bearer names.
type fakeApiClient struct {
	networkId sidecar.Id
	clientId  sidecar.Id
	// the sidecar the client is bound to, zero for none: an unadmitted client may read the log and post a
	// recovery-signed statement only (§7.9's Recovery `before admission` row)
	sidecarId sidecar.Id
}

type FakeApi struct {
	ctx      context.Context
	clock    Clock
	faults   *FaultQueue
	barriers *BarrierDriver
	// the first metadata cluster, where proj/, projrows/ and rev/ live (owner decision 145)
	cluster  sidecar.BlobCluster
	settings *FakeApiSettings
	mux      *http.ServeMux

	stateLock     sync.Mutex
	clientCount   int
	bearerClients map[string]*fakeApiClient
	// §7.9's log per network, fake_api_config.go's
	configLogs map[sidecar.Id]*fakeApiConfigLog
}

// An api on the first metadata cluster given, its clock, fault queue and barriers a test's or the Net's; barriers may
// be nil. settings may be nil for the defaults.
func NewFakeApi(ctx context.Context, clock Clock, faults *FaultQueue, barriers *BarrierDriver, cluster sidecar.BlobCluster, settings *FakeApiSettings) *FakeApi {
	if settings == nil {
		settings = DefaultFakeApiSettings()
	}
	self := &FakeApi{
		ctx:           ctx,
		clock:         clock,
		faults:        faults,
		barriers:      barriers,
		cluster:       cluster,
		settings:      settings,
		mux:           http.NewServeMux(),
		bearerClients: map[string]*fakeApiClient{},
		configLogs:    map[sidecar.Id]*fakeApiConfigLog{},
	}
	self.addConfigRoutes()
	return self
}

// An api on the Net's host: its Blobs' first cluster, its clock, faults and barriers. settings may be nil for the
// defaults.
func (self *Net) AddApi(settings *FakeApiSettings) (*FakeApi, error) {
	cluster, err := self.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	return NewFakeApi(self.ctx, self.clock, self.faults, self.barriers, cluster, settings), nil
}

// The origin requests name.
func (self *FakeApi) Origin() string {
	return self.settings.Origin
}

// A bearer for a client of networkId, bound to sidecarId when it is not zero. The string is opaque and synthetic, as
// no real api could have made it.
func (self *FakeApi) ClientToken(networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clientCount += 1
	bearer := fmt.Sprintf("fake-client-token-%d", self.clientCount)
	self.bearerClients[bearer] = &fakeApiClient{networkId: networkId, clientId: clientId, sidecarId: sidecarId}
	return bearer
}

// The client a request's bearer names, nil for none.
func (self *FakeApi) client(request *http.Request) *fakeApiClient {
	bearer, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !found {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.bearerClients[bearer]
}

// Serves a request in process, as api's router would.
func (self *FakeApi) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	self.mux.ServeHTTP(writer, request)
}

// A round tripper that serves every request in process, after its fault plan.
func (self *FakeApi) Transport() http.RoundTripper {
	return fakeApiTransport{api: self}
}

type fakeApiTransport struct {
	api *FakeApi
}

// Serves the request, as its path's fault plan says.
func (self fakeApiTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	origin, err := url.Parse(self.api.settings.Origin)
	if err != nil {
		return nil, err
	}
	if request.URL.Scheme != origin.Scheme || request.URL.Host != origin.Host {
		return nil, fmt.Errorf("no route to %s", request.URL.Host)
	}
	if request.Body != nil {
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	serve := func() *http.Response {
		recorder := httptest.NewRecorder()
		self.api.ServeHTTP(recorder, request)
		response := recorder.Result()
		response.Request = request
		return response
	}
	plan := self.api.faults.take(request.Context(), FaultOpHttp, "api", request.URL.Path, request.Method != http.MethodGet)
	if plan == nil {
		return serve(), nil
	}
	switch plan.Result {
	case ApplyThenDrop:
		serve()
		return nil, errFakeApiTransport
	case FailBeforeApply:
		return nil, errFakeApiTransport
	case CrashBeforeApply:
		<-request.Context().Done()
		return nil, request.Context().Err()
	case CrashAfterApply:
		serve()
		<-request.Context().Done()
		return nil, request.Context().Err()
	}
	return nil, fmt.Errorf("fault plan %s: the fake api has no such result", plan)
}

// api's refusal body: {"error": text, "code": code}, with whatever else the route adds, as SidecarApi reads it.
func fakeApiRefuse(writer http.ResponseWriter, status int, code string, text string, extra map[string]any) {
	body := map[string]any{"error": text, "code": code}
	for key, value := range extra {
		body[key] = value
	}
	fakeApiWriteJson(writer, status, body)
}

// Writes value as the JSON body of a status.
func fakeApiWriteJson(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	json.NewEncoder(writer).Encode(value)
}

// Reads a request's JSON body into args, false after answering 400.
func (self *FakeApi) readJson(writer http.ResponseWriter, request *http.Request, args any) bool {
	body, err := io.ReadAll(io.LimitReader(request.Body, self.settings.MaxRequestByteCount+1))
	if err != nil || self.settings.MaxRequestByteCount < int64(len(body)) {
		fakeApiRefuse(writer, http.StatusBadRequest, "bad_request", "The body could not be read.", nil)
		return false
	}
	if err := json.Unmarshal(body, args); err != nil {
		fakeApiRefuse(writer, http.StatusBadRequest, "bad_request", "The body is not the route's JSON.", nil)
		return false
	}
	return true
}
