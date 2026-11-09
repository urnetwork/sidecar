// T2's api (§22.4): the routes sidecars and gates call on server's api, in memory, on the Net's clock and fault
// queue, with the first metadata cluster on the Net's fake Blobs. server cannot be imported here, so each route copies
// only the steps a schedule relies on, and T3 reruns the same schedules on server's real routes (Q-TEST-1): a
// divergence fails. fake_api_config.go adds §7.9's authorization log and fake_api_exchange.go §7.8's token exchange;
// CORE-M1-13 adds enrollment, bind and refresh in its own file.
//
// Requests reach it through Transport, an http.RoundTripper that serves in process, so a client of api built with it
// (SidecarApi's transport, a gate's source) sends real requests with no socket. It answers at two origins, api's and
// the issuer's (SidecarSettings.ApiUrl and AuthUrl), as one api process answers both names. Each request first takes a
// fault plan of FaultOpHttp keyed by its path: ApplyThenDrop serves it and loses the answer, FailBeforeApply loses the
// request, and the crash results serve it or not and never answer, until the request's context ends.
//
// A bearer names a client of a network, which ClientToken mints as a sidecar's strict_exp token (§7.4): a request
// without one known here, with one past its exp or with one of a removed client is 401, as api answers a bad token.
// Safe for concurrent use.

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
	"time"

	"github.com/urnetwork/sidecar"
)

// The transport's answer when a fault loses a request or its response: what a client sees of a dropped connection.
var errFakeApiTransport = errors.New("connection reset by the fault plan")

type FakeApiSettings struct {
	// The origin requests name. A .example host, which no real api answers (CODESTYLE's test data rule).
	Origin string
	// The issuer's origin, where POST /oauth/token's exchange is (SidecarSettings.AuthUrl): its token endpoint is
	// this and /oauth/token, which an exchange's DPoP proof names as htu (§7.8).
	AuthOrigin string
	// The domain whose https://<audience>.<domain> origins name the services the exchange issues for, as server's
	// WARP_DOMAIN does: https://evs.sidecartest.example and the like.
	ServiceDomain string
	// How long a client token lasts from its mint: §7.4's 7-day exp of a sidecar's strict_exp token, which ends it
	// at every route and at the exchange whatever reject_expired says.
	ClientTokenTimeout time.Duration
	// How long a service token lasts: 15 minutes (§7.8, owner decision 2).
	ServiceTokenTimeout time.Duration
	// How far a DPoP proof's iat may sit from the api's clock, either way: §7.4's 60 s.
	DpopIatWindow time.Duration
	// How long a spent jti is kept per client: §7.4's 120 s, twice the iat window, so no proof replays inside it.
	DpopReplayTimeout time.Duration
	// The longest jti a proof may carry, in bytes, as server's check bounds it.
	DpopMaxJtiByteCount int
	// The most entries one GET /network/config/projection answers; more follow from the last one's position. 1,024,
	// §7.9's fold span, so a reader at the newest base's tail takes it in one read.
	ProjectionPageCount int
	// How many positions one append tries before it answers 503, each a 412 or a lost race (§7.9's statement row).
	// 64: every attempt is another appender's landed entry, so this bounds only a stream of them.
	AppendAttemptCount int
	// The longest request body a route reads, as server's router bounds a JSON body: 16 MiB, past a base's 4 MiB of
	// rows and 4,096 config pushes of at most 1 KiB, each base64 in JSON.
	MaxRequestByteCount int64
}

func DefaultFakeApiSettings() *FakeApiSettings {
	return &FakeApiSettings{
		Origin:              "https://api.sidecartest.example",
		AuthOrigin:          "https://auth.sidecartest.example",
		ServiceDomain:       "sidecartest.example",
		ClientTokenTimeout:  7 * 24 * time.Hour,
		ServiceTokenTimeout: 15 * time.Minute,
		DpopIatWindow:       60 * time.Second,
		DpopReplayTimeout:   120 * time.Second,
		DpopMaxJtiByteCount: 256,
		ProjectionPageCount: 1024,
		AppendAttemptCount:  64,
		MaxRequestByteCount: 16 * 1024 * 1024,
	}
}

// One client a bearer names.
type fakeApiClient struct {
	networkId sidecar.Id
	clientId  sidecar.Id
	// the sidecar the client is bound to, zero for none: an unadmitted client may read the log and post a
	// recovery-signed statement only (§7.9's Recovery `before admission` row)
	sidecarId sidecar.Id
	// the token's exp, on the api's clock
	expireTime time.Time
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
	// mints the exchange's service tokens: the Net host's, which T2's engines authenticate with
	authenticator *FakeAuthenticator

	stateLock     sync.Mutex
	clientCount   int
	bearerClients map[string]*fakeApiClient
	// clients removed or reaped, whose tokens no longer authenticate
	removedClientIds map[sidecar.Id]bool
	// §7.9's log per network, fake_api_config.go's
	configLogs map[sidecar.Id]*fakeApiConfigLog
	// fake_api_exchange.go's state
	exchange fakeApiExchangeState
}

// An api on the first metadata cluster given, its clock, fault queue and barriers a test's or the Net's; barriers may
// be nil. Its exchange mints service tokens with an authenticator of its own (Authenticator). settings may be nil for
// the defaults.
func NewFakeApi(ctx context.Context, clock Clock, faults *FaultQueue, barriers *BarrierDriver, cluster sidecar.BlobCluster, settings *FakeApiSettings) *FakeApi {
	return newFakeApi(ctx, clock, faults, barriers, cluster, NewFakeAuthenticator(clock, faults), settings)
}

func newFakeApi(ctx context.Context, clock Clock, faults *FaultQueue, barriers *BarrierDriver, cluster sidecar.BlobCluster, authenticator *FakeAuthenticator, settings *FakeApiSettings) *FakeApi {
	if settings == nil {
		settings = DefaultFakeApiSettings()
	}
	self := &FakeApi{
		ctx:              ctx,
		clock:            clock,
		faults:           faults,
		barriers:         barriers,
		cluster:          cluster,
		settings:         settings,
		mux:              http.NewServeMux(),
		authenticator:    authenticator,
		bearerClients:    map[string]*fakeApiClient{},
		removedClientIds: map[sidecar.Id]bool{},
		configLogs:       map[sidecar.Id]*fakeApiConfigLog{},
		exchange:         newFakeApiExchangeState(),
	}
	self.addConfigRoutes()
	self.addExchangeRoutes()
	return self
}

// An api on the Net's host: its Blobs' first cluster, its clock, faults and barriers, and its exchange minting with
// the Net's FakeHost authenticator, so the engines on the Net take the service tokens it issues. settings may be nil
// for the defaults.
func (self *Net) AddApi(settings *FakeApiSettings) (*FakeApi, error) {
	cluster, err := self.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	return newFakeApi(self.ctx, self.clock, self.faults, self.barriers, cluster, self.fakes.Authenticator, settings), nil
}

// The origin requests name.
func (self *FakeApi) Origin() string {
	return self.settings.Origin
}

// The issuer's origin, where the exchange is.
func (self *FakeApi) AuthOrigin() string {
	return self.settings.AuthOrigin
}

// The authenticator the exchange's service tokens authenticate at.
func (self *FakeApi) Authenticator() *FakeAuthenticator {
	return self.authenticator
}

// A bearer for a client of networkId, bound to sidecarId when it is not zero, as a sidecar's strict_exp token: it
// expires ClientTokenTimeout after now on the api's clock, and every route refuses it after (§7.4). The string is
// opaque and synthetic, as no real api could have made it.
func (self *FakeApi) ClientToken(networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id) string {
	expireTime := self.clock.Now().Add(self.settings.ClientTokenTimeout)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clientCount += 1
	bearer := fmt.Sprintf("fake-client-token-%d", self.clientCount)
	self.bearerClients[bearer] = &fakeApiClient{networkId: networkId, clientId: clientId, sidecarId: sidecarId, expireTime: expireTime}
	return bearer
}

// Removes the client, as POST /network/remove-client or the reaper does: none of its tokens authenticates after, at
// any route or as an exchange's subject (§7.8, §7.10).
func (self *FakeApi) RemoveClient(clientId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.removedClientIds[clientId] = true
}

// The client bearer names, nil for none: an unknown token, one past its exp, or one of a removed client.
func (self *FakeApi) clientOfToken(bearer string) *fakeApiClient {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	client := self.bearerClients[bearer]
	if client == nil || !now.Before(client.expireTime) || self.removedClientIds[client.clientId] {
		return nil
	}
	return client
}

// The client a request's bearer names, nil for none.
func (self *FakeApi) client(request *http.Request) *fakeApiClient {
	bearer, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !found {
		return nil
	}
	return self.clientOfToken(bearer)
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
	served := false
	for _, originUrl := range []string{self.api.settings.Origin, self.api.settings.AuthOrigin} {
		origin, err := url.Parse(originUrl)
		if err != nil {
			return nil, err
		}
		if request.URL.Scheme == origin.Scheme && request.URL.Host == origin.Host {
			served = true
		}
	}
	if !served {
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
