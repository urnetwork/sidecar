// T2's api (§22.4): the routes sidecars and gates call on server's api, in memory, on the Net's clock and fault
// queue, with the first metadata cluster on the Net's fake Blobs. server cannot be imported here, so each route copies
// only the steps a schedule relies on, and T3 reruns the same schedules on server's real routes (Q-TEST-1): a
// divergence fails. fake_api_config.go adds §7.9's authorization log, fake_api_exchange.go §7.8's token exchange,
// fake_api_core.go enrollment, a client's mint and removal, the identity binding and its lookups, and refresh,
// fake_api_sync.go §6.8's poll and versions routes, and http_page.go §18.8's lease, its reap and POST /sidecar/close.
//
// Requests reach it through Transport, an http.RoundTripper that serves in process, so a client of api built with it
// (SidecarApi's transport, a gate's source) sends real requests with no socket. It answers at two origins, api's and
// the issuer's (SidecarSettings.ApiUrl and AuthUrl), as one api process answers both names. Each request first takes a
// fault plan of FaultOpHttp keyed by its path: ApplyThenDrop serves it and loses the answer, FailBeforeApply loses the
// request, and the crash results serve it or not and never answer, until the request's context ends.
//
// A bearer names a client of a network, which ClientToken and the core routes mint as a sidecar's strict_exp token
// (§7.4), JWT-shaped so a sidecar reads its claims as it reads server's: a request without one known here, with one
// past its exp, of a removed client or of a session api ended is 401, as api answers a bad token. Safe for concurrent
// use.

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
	// How long an ephemeral client's lease seen_time and its newest disconnect must both be past before
	// ReapEphemeralClients removes it: §7.7's 35 min, as server's NetworkClientLeaseSettings.ReapAfter (http_page.go).
	LeaseReapAfter time.Duration
	// The longest body POST /sidecar/close reads: 64 bytes, a 22-character capability and room for a newline, as
	// server's handler bounds it.
	MaxCloseByteCount int64
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
		LeaseReapAfter:      35 * time.Minute,
		MaxCloseByteCount:   64,
	}
}

// One client a bearer names. Never changed once a token maps to it: a bind maps the client's tokens to a copy.
type fakeApiClient struct {
	networkId sidecar.Id
	clientId  sidecar.Id
	// the sidecar the client is bound to, zero for none: an unadmitted client may read the log and post a
	// recovery-signed statement only (§7.9's Recovery `before admission` row)
	sidecarId sidecar.Id
	// the token's exp, on the api's clock
	expireTime time.Time
	// the token's device and session claims, which a refresh keeps
	deviceId  sidecar.Id
	sessionId sidecar.Id
	// §7.4's marks, which a client's children inherit; forwardOnly a sidecar's forwarding client's, and its children's
	strictExp    bool
	adminRefused bool
	forwardOnly  bool
	// the parent of a child client, zero for a top-level one
	sourceClientId sidecar.Id
	// the token's create_time, which a refresh keeps (server's RenewSessionCredential)
	createTime time.Time
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
	// where each client token and auth key this api mints goes as a secret: the Net's capture, which scans for it
	// (§22.7's S1); nil for none
	secretSink func(kind string, secret []byte)

	stateLock     sync.Mutex
	bearerClients map[string]*fakeApiClient
	// clients removed or reaped, whose tokens no longer authenticate
	removedClientIds map[sidecar.Id]bool
	// §7.9's log per network, fake_api_config.go's
	configLogs map[sidecar.Id]*fakeApiConfigLog
	// fake_api_exchange.go's state
	exchange fakeApiExchangeState
	// fake_api_core.go's state
	core fakeApiCoreState
	// fake_api_sync.go's hint state, set by Net.AddApi
	sync fakeApiSyncState
	// http_page.go's leases, connections and reaps
	lease fakeApiLeaseState
	// §7.4's allowlist, which a strict_exp bearer's request is held to when set (SetRouteGate), and each route it
	// refused, as "METHOD /path"
	routeGate     func(method string, path string) bool
	refusedRoutes []string
	// counts every client token minted, for a test waiting on one
	mints *sidecar.MonitorValue[uint64]
}

// Holds every request a strict_exp bearer makes to allowed, as route_authz.go's fail-closed allowlist does: a route
// it refuses answers 403 "A sidecar token cannot call this route.", never 401, so a sidecar does not sign out (§7.4).
// §22.7's scenarios run with it on (sidecartest's scenario.go). nil turns it off.
func (self *FakeApi) SetRouteGate(allowed func(method string, path string) bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routeGate = allowed
}

// Each request the route gate refused, as "METHOD /path", in order.
func (self *FakeApi) RefusedRoutes() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.refusedRoutes...)
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
		core:             newFakeApiCoreState(),
		lease:            newFakeApiLeaseState(),
		mints:            sidecar.NewMonitorValue[uint64](0),
	}
	self.addConfigRoutes()
	self.addExchangeRoutes()
	self.addCoreRoutes()
	self.addSyncRoutes()
	self.addLeaseRoutes()
	return self
}

// An api on the Net's host: its Blobs' first cluster, its clock, faults and barriers, and its exchange minting with
// the Net's FakeHost authenticator, so the engines on the Net take the service tokens it issues. Each client token and
// auth key it mints is a secret the Net's capture scans for. settings may be nil for the defaults.
func (self *Net) AddApi(settings *FakeApiSettings) (*FakeApi, error) {
	cluster, err := self.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	api := newFakeApi(self.ctx, self.clock, self.faults, self.barriers, cluster, self.fakes.Authenticator, settings)
	api.secretSink = self.capture.AddSecret
	// §6.8's sync routes from the Net's hint state (fake_api_sync.go)
	api.sync.push = self.push
	return api, nil
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
// expires ClientTokenTimeout after now on the api's clock, and every route refuses it after (§7.4). The token is
// JWT-shaped, its claims server's names, and signed by a key of this api's alone, so it is synthetic and no real api
// could have made it.
func (self *FakeApi) ClientToken(networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id) string {
	now := self.clock.Now()
	return self.mintClientToken(&fakeApiClient{
		networkId:    networkId,
		clientId:     clientId,
		sidecarId:    sidecarId,
		deviceId:     sidecar.NewId(),
		sessionId:    sidecar.NewId(),
		strictExp:    true,
		adminRefused: true,
		createTime:   now,
	})
}

// Removes the client, as POST /network/remove-client or the reaper does: none of its tokens authenticates after, at
// any route or as an exchange's subject (§7.8, §7.10).
func (self *FakeApi) RemoveClient(clientId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.removedClientIds[clientId] = true
	// the removal chain's lease effect: a removed client's lease goes with it (http_page.go)
	delete(self.lease.leases, clientId)
}

// The client bearer names, nil for none: an unknown token, one past its exp, one of a removed client or one whose
// session api ended.
func (self *FakeApi) clientOfToken(bearer string) *fakeApiClient {
	client, _ := self.clientOfTokenRefusal(bearer)
	return client
}

// The client bearer names, or nil and the code its 401 carries: session_revoked for a session api ended, else none.
func (self *FakeApi) clientOfTokenRefusal(bearer string) (*fakeApiClient, string) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	client := self.bearerClients[bearer]
	if client == nil || !now.Before(client.expireTime) || self.removedClientIds[client.clientId] {
		return nil, ""
	}
	if self.core.endedSessionClientIds[client.clientId] {
		return nil, fakeApiCodeSessionRevoked
	}
	return client, ""
}

// The client a request's bearer names, nil for none.
func (self *FakeApi) client(request *http.Request) *fakeApiClient {
	bearer, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !found {
		return nil
	}
	return self.clientOfToken(bearer)
}

// Serves a request in process, as api's router would, the route gate first. Every answer carries the api's clock in
// its Date header, as net/http's server stamps each of api's (RFC 9110 §6.6.1): what a sidecar signs its DPoP iat by
// (§7.4, QD-757).
func (self *FakeApi) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Date", self.clock.Now().UTC().Format(http.TimeFormat))
	refused := func() bool {
		self.stateLock.Lock()
		gate := self.routeGate
		self.stateLock.Unlock()
		if gate == nil {
			return false
		}
		client := self.client(request)
		if client == nil || !client.strictExp || gate(request.Method, request.URL.Path) {
			return false
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.refusedRoutes = append(self.refusedRoutes, request.Method+" "+request.URL.Path)
		return true
	}()
	if refused {
		http.Error(writer, fakeApiStrictExpRefusedText, http.StatusForbidden)
		return
	}
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
