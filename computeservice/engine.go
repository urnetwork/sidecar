// The compute engine (D-CSRV-1, §14.2, §14.3): the broker and orchestrator's HTTP surface at compute.<root>, which
// server/cli/compute hosts through server/computehost. Stateless: every durable thing is a Postgres row the process's
// Env reaches, and Redis holds only soft state, under §14.4's families (engine_redis.go). Every server-side compute
// area builds its handlers in its own computeservice/<area>_*.go file and registers them by route name
// (routes.go), so none edits this file.
//
// One router serves §14.3's routes, and every route runs behind one guard, in this order, so no handler sees a request
// the guard would refuse and none is skipped for a test (a test sets the state, never a bypass):
//
//  1. the route: a method and path no route takes is 404 not_found;
//  2. by the route's ComputeRouteAuth. A sidecar route takes DESIGN §7.8's service token for audience compute,
//     verified offline through the host's Authenticator (401 unauthenticated; 503 when the host cannot tell), a
//     sidecar's only (ur_sidecar_id, else 403 scope); then rev/ for its three subjects (401 when one voids it, 503 when
//     unknown); then the newest verified state (ComputeAuthState): an admitted, unrevoked sidecar of the token's
//     network in standing, else 403 scope, 503 while the network's state is not loaded, never an allow; then §16.6's
//     hold, 503 upgrade_required for a network whose newest base turns on a feature this release does not implement.
//     A route with no caller (collateral) and one that checks its own credential (an enclave VM's evidence) skip it;
//  3. §19.11's compute gate: the caller's network not admitted, or a write while `writes: false` holds, or for a
//     route with no caller the gate not enabled at all, answers 503 with the gate's Retry-After, the engine staying
//     ready;
//  4. the route's migration group linked in this binary (503);
//  5. Idempotency-Key where the route takes one (400 idempotency_key_required);
//  6. on an admission route, every registered ComputeAdmissionCheck (CARCH-M12-01's hold and region refusal);
//  7. on an approval route, ComputeApprovalGate for its kind (19 or 21), 503 while none is installed;
//  8. the route's registered handler, or 503 not_built for a design route no area has built.
//
// Every answer but a route's own success is a ComputeRefusal (engine_refusal.go). Every request but a NoLog route's
// leaves one ComputeServiceLog line, opaque ids only (engine_log.go). A stream clears the status server's deadlines
// and writes an SSE comment every StreamCommentInterval (engine_stream.go); the tunnel hijacks its connection. Drain
// refuses new requests, lets those in flight finish within DrainTimeout, then ends every request's context.
//
// Safe for concurrent use. No lock is held across I/O or a barrier.

package computeservice

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.HttpEngine = (*ComputeEngine)(nil)

// The headers the guard reads.
const (
	computeAuthorizationHeader = "Authorization"
	computeBearerPrefix        = "Bearer "
	// A route that takes it requires it: the effect key of the approved decision (§16.3).
	ComputeIdempotencyKeyHeader = "Idempotency-Key"
)

// What a body travels as: protobuf for every compute/v1 body (QD-1246), JSON for a refusal.
const (
	computeContentTypeProtobuf = "application/x-protobuf"
	computeContentTypeJson     = "application/json"
)

// What the engine takes beyond its host and settings. A nil seam fails closed.
type ComputeEngineDeps struct {
	// The newest verified authorization state (auth_state.go's over the process's AclGateCache). nil answers every
	// sidecar route 503: nothing is honored without it.
	AuthState ComputeAuthState
	// §16.6's broker gate for kinds 19 and 21. nil takes the one an area registered; with none, every approval route
	// answers 503.
	ApprovalGate ComputeApprovalGate
	// The process's Env, through which handlers reach Postgres (owner decision 594). nil reads operator's global one,
	// which the block's main sets before it serves and which refuses every service until then.
	Env operator.Env
	// The Redis instance of its own that holds {cmpa}, with persistence off and outside every backup (§14.4). nil
	// leaves every route that needs it unavailable.
	AdmissionsRedis sidecar.Redis
	// Whether this binary links a pending group (server's SidecarMgC*Linked). nil links none, so every route that
	// names a group answers 503.
	GroupLinked func(group ComputeMigrationGroup) bool
	// One of the block's own vault files, by name, for an area that reads its credentials there (the providers'
	// adapters, K_P's signer, the signer's mTLS client): the host's, absent in tests. nil answers every name with an
	// error.
	SecretFile func(name string) ([]byte, error)
	// Where an admission's address is, for §17.2's region check (abuse_region.go): server's GeoLite2 City lookup, which
	// the block's host passes in. nil answers every admission 503: no region checked, nothing admitted.
	RegionLookup ComputeRegionLookup
	// The newest verified compute policy the broker holds (§5.4), the provider adapters' only source of hosts,
	// receivers, targets and model ids: ATTEST's fetcher on the block, which INFER-M12-04 wires. nil gives every
	// adapter none, so no direct target is made.
	Policy func() *sidecar.ComputePolicy
	// What the provider adapters reach their providers with (§4.6): a test's pointed at a fake provider. nil: a
	// client of the standard transport.
	ProviderHttpClient *http.Client
	// Web search's (SRCH-M13-07, SRCH-M13-08): the signer's mTLS client, nil reading it from the block's vault file
	// through SecretFile, none where that does not read, so every search answers capacity; the ledger's search calls,
	// nil taking BAL's over Env; and {cmpa}'s instance's persistence as the host reads it (CONFIG GET save and
	// appendonly), nil leaving it unsure, so every search answers capacity.
	SearchSigner          SearchSignerClient
	SearchLedger          ComputeSearchLedger
	AdmissionsPersistence func(ctx context.Context) (*ComputeRedisPersistence, error)
	// The service log. nil writes it through Log.
	ServiceLog ComputeServiceLog
	// Lifecycle, alarms and, when ServiceLog is nil, the service log. nil discards.
	Log sidecar.Logger

	// A test's handlers by route name, served in place of the registered ones, so a test holds the guard to a route
	// without touching the registry.
	testHandlers map[string]ComputeHandler
	// A test's admission checks, run after the registered ones.
	testAdmissionChecks []ComputeAdmissionCheck
	// A test's catalog versions, in place of compute_catalog_version over Env (broker_catalog.go).
	testCatalogStore computeCatalogVersionStore
	// A test's abuse holds, in place of compute_abuse_hold over Env (abuse_hold.go).
	testAbuseHoldStore computeAbuseHoldStore
	// A test's web search seams (search_admit.go).
	testSearch *computeSearchTestDeps
}

// The engine. See the file header.
type ComputeEngine struct {
	ctx    context.Context
	cancel context.CancelFunc
	// every request's context ends with this, at the drain's bound or at Close
	endCtx    context.Context
	endCancel context.CancelFunc

	host            *sidecar.ServiceHost
	settings        *ComputeEngineSettings
	deps            *ComputeEngineDeps
	clock           sidecar.Clock
	log             sidecar.Logger
	serviceLog      ComputeServiceLog
	approvalGate    ComputeApprovalGate
	admissionChecks []ComputeAdmissionCheck
	metrics         *computeMetrics
	routes          []*ComputeRoute
	handler         http.Handler
	// the provider adapters this deployment enables, and their gating (provider_registry.go)
	providers *ComputeProviderRegistry
	// the newest catalog versions it read (broker_catalog.go)
	catalog *computeCatalogCache
	// web search's admission, suspension and report loop (search_admit.go)
	search *ComputeSearchAdmission

	// requests in flight, hijacked tunnels and streams among them
	inFlightCount *sidecar.MonitorValue[int]
	draining      chan struct{}
	drainingOnce  sync.Once
}

// Starts the engine on host, which needs Metrics; Redis, Authenticator, Gates and Clock are read per request, a nil
// Authenticator answering every sidecar route 503 and nil Gates closing every route. It runs until ctx ends or Close.
func NewComputeEngine(ctx context.Context, host *sidecar.ServiceHost, settings *ComputeEngineSettings, deps *ComputeEngineDeps) (*ComputeEngine, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("compute needs a host with Metrics")
	}
	if settings == nil {
		settings = DefaultComputeEngineSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil {
		deps = &ComputeEngineDeps{}
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	serviceLog := deps.ServiceLog
	if serviceLog == nil {
		serviceLog = NewLoggerComputeServiceLog(log)
	}
	approvalGate := deps.ApprovalGate
	if approvalGate == nil {
		approvalGate = computeApprovalGate
	}
	admissionChecks := []ComputeAdmissionCheck{}
	for _, registered := range computeAdmissionChecks {
		admissionChecks = append(admissionChecks, registered.check)
	}
	admissionChecks = append(admissionChecks, deps.testAdmissionChecks...)
	handlers := registeredComputeRouteHandlers()
	if deps.testHandlers != nil {
		handlers = deps.testHandlers
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	endCtx, endCancel := context.WithCancel(cancelCtx)
	self := &ComputeEngine{
		ctx:             cancelCtx,
		cancel:          cancel,
		endCtx:          endCtx,
		endCancel:       endCancel,
		host:            host,
		settings:        settings,
		deps:            deps,
		clock:           host.ClockOrReal(),
		log:             log,
		serviceLog:      serviceLog,
		approvalGate:    approvalGate,
		admissionChecks: admissionChecks,
		metrics:         newComputeMetrics(host.Metrics),
		routes:          computeRoutes(handlers),
		inFlightCount:   sidecar.NewMonitorValue(0),
		draining:        make(chan struct{}),
	}
	providers, err := newComputeEngineProviderRegistry(self)
	if err != nil {
		cancel()
		return nil, err
	}
	self.providers = providers
	self.catalog = newComputeCatalogCache(self)
	self.search = newComputeSearchAdmission(self)
	mux := http.NewServeMux()
	for _, route := range self.routes {
		mux.HandleFunc(route.Method+" "+route.Pattern, self.guard(route))
	}
	// every other path and method, the least specific pattern, so a route's own always wins
	mux.HandleFunc("/", self.serveUnrouted)
	self.handler = mux
	return self, nil
}

// Every route the router took, each a copy with no handler, so a caller reads the table and reaches a handler only
// through Handler and its guard: what server/computehost and the api spec test read.
func (self *ComputeEngine) Routes() []*ComputeRoute {
	routes := make([]*ComputeRoute, 0, len(self.routes))
	for _, route := range self.routes {
		copied := *route
		copied.handler = nil
		routes = append(routes, &copied)
	}
	return routes
}

// The names of the design routes no area has built, as this engine serves them: each answers 503 not_built.
func (self *ComputeEngine) UnbuiltRoutes() []string {
	names := []string{}
	for _, route := range self.routes {
		if route.handler == nil {
			names = append(names, route.Name)
		}
	}
	return names
}

// One handler for every route.
func (self *ComputeEngine) Handler() http.Handler {
	return self.handler
}

// The host the engine runs on.
func (self *ComputeEngine) Host() *sidecar.ServiceHost {
	return self.host
}

// The settings it runs under.
func (self *ComputeEngine) Settings() *ComputeEngineSettings {
	return self.settings
}

// The engine's clock.
func (self *ComputeEngine) Clock() sidecar.Clock {
	return self.clock
}

// Lifecycle and alarm lines, never a request's content.
func (self *ComputeEngine) Log() sidecar.Logger {
	return self.log
}

// The process's Env, through which a handler reaches Postgres: deps' or operator's global one.
func (self *ComputeEngine) Env() operator.Env {
	if self.deps.Env != nil {
		return self.deps.Env
	}
	return operator.GlobalEnv()
}

// Whether this binary links group: false for a group the deps' function does not link, and for every group when the
// host gave none.
func (self *ComputeEngine) GroupLinked(group ComputeMigrationGroup) bool {
	return self.deps.GroupLinked != nil && self.deps.GroupLinked(group)
}

// One of the block's own vault files, for an area that reads its credentials there. An error when the host gave no
// reader or the file does not read; the error names the file and nothing it holds.
func (self *ComputeEngine) SecretFile(name string) ([]byte, error) {
	if self.deps.SecretFile == nil {
		return nil, errors.New("this compute block reads no secret files")
	}
	return self.deps.SecretFile(name)
}

// Whether the engine serves: neither draining nor closed. A closed gate leaves this alone: it answers 503 and the
// engine stays ready (§19.11).
func (self *ComputeEngine) Ready() bool {
	select {
	case <-self.ctx.Done():
		return false
	case <-self.draining:
		return false
	default:
		return true
	}
}

// Takes no new request, answering each 503; waits until none is in flight, at most DrainTimeout; then ends every
// request's context, so streams and tunnels stop, and waits for their handlers at most DrainEndTimeout more. Safe to
// call more than once, and from a host's own drain as well as the block's.
func (self *ComputeEngine) Drain() {
	self.drainingOnce.Do(func() { close(self.draining) })
	if self.waitInFlight(self.settings.DrainTimeout) {
		return
	}
	testHookBarrier(BarrierComputeDrainEndBefore, computeBarrierEngineKey)
	self.endCancel()
	testHookBarrier(BarrierComputeDrainEndAfter, computeBarrierEngineKey)
	self.waitInFlight(self.settings.DrainEndTimeout)
}

// Waits until no request is in flight, at most timeout, and says whether none is.
func (self *ComputeEngine) waitInFlight(timeout time.Duration) bool {
	var deadline <-chan time.Time
	for {
		count, changed := self.inFlightCount.Get()
		if count == 0 {
			return true
		}
		if timeout <= 0 {
			return false
		}
		if deadline == nil {
			deadline = self.clock.After(timeout)
		}
		select {
		case <-changed:
		case <-deadline:
			return false
		case <-self.ctx.Done():
			return false
		}
	}
}

// Ends everything at once: every request's context, and the engine's. Safe after Drain, and more than once.
func (self *ComputeEngine) Close() {
	self.drainingOnce.Do(func() { close(self.draining) })
	self.endCancel()
	self.cancel()
}

// Whether Drain or Close has begun.
func (self *ComputeEngine) isDraining() bool {
	select {
	case <-self.draining:
		return true
	default:
		return false
	}
}

// A request on its way in: its id, its context, its writer, in flight until done is called.
func (self *ComputeEngine) begin(route *ComputeRoute, writer http.ResponseWriter, httpRequest *http.Request) (request *ComputeRequest, done func()) {
	ctx, cancel := context.WithCancel(httpRequest.Context())
	stop := context.AfterFunc(self.endCtx, cancel)
	request = &ComputeRequest{
		engine:    self,
		route:     route,
		writer:    &computeResponseWriter{ResponseWriter: writer},
		Http:      httpRequest,
		Ctx:       ctx,
		RequestId: sidecar.NewId(),
		started:   self.clock.Now(),
	}
	requestKey := sidecar.EvsKeyId(request.RequestId)
	testHookBarrier(BarrierComputeRequestAdmitBefore, requestKey)
	self.inFlightCount.Update(func(count int) int { return count + 1 })
	testHookBarrier(BarrierComputeRequestAdmitAfter, requestKey)
	return request, func() {
		request.finish()
		stop()
		cancel()
		self.inFlightCount.Update(func(count int) int { return count - 1 })
	}
}

// The handler every route runs behind: the file header's steps in order, then the route.
func (self *ComputeEngine) guard(route *ComputeRoute) http.HandlerFunc {
	return func(writer http.ResponseWriter, httpRequest *http.Request) {
		request, done := self.begin(route, writer, httpRequest)
		defer done()
		if self.isDraining() {
			request.Unavailable()
			return
		}
		switch route.Auth {
		case ComputeRouteAuthSidecar:
			if !self.authenticate(request) {
				return
			}
		case ComputeRouteAuthNone, ComputeRouteAuthOwn:
		default:
			// a route the design gives no caller kind is a fault, which refuses
			request.Unavailable()
			return
		}
		if !self.checkGate(request) {
			return
		}
		if route.Group != "" && !self.GroupLinked(route.Group) {
			request.Unavailable()
			return
		}
		if route.IdempotencyKey && strings.TrimSpace(request.IdempotencyKey()) == "" {
			request.RefuseCode(ComputeRefusalIdempotencyKeyRequired)
			return
		}
		if route.Admission {
			for _, check := range self.admissionChecks {
				if refusal := check(request); refusal != nil {
					request.Refuse(refusal)
					return
				}
			}
		}
		if route.Approval != 0 {
			if self.approvalGate == nil {
				request.Unavailable()
				return
			}
			if refusal := self.approvalGate.Admit(request, route.Approval); refusal != nil {
				request.Refuse(refusal)
				return
			}
		}
		if route.handler == nil {
			request.RefuseCode(ComputeRefusalNotBuilt)
			return
		}
		route.handler(request)
	}
}

// A request no route takes: 404 not_found, through no guard and before any read, so no near miss of a route reaches a
// handler. It leaves its line as every request does.
func (self *ComputeEngine) serveUnrouted(writer http.ResponseWriter, httpRequest *http.Request) {
	request, done := self.begin(&ComputeRoute{Name: computeUnroutedRouteName}, writer, httpRequest)
	defer done()
	request.RefuseCode(ComputeRefusalNotFound)
}

// Step 2 for a sidecar route: the token, a sidecar's, rev/, the state and the features. false once it has answered the
// refusal.
func (self *ComputeEngine) authenticate(request *ComputeRequest) bool {
	jwt, ok := strings.CutPrefix(request.Http.Header.Get(computeAuthorizationHeader), computeBearerPrefix)
	if !ok || jwt == "" {
		request.RefuseCode(ComputeRefusalUnauthenticated)
		return false
	}
	principal, err := self.host.Authenticate(request.Ctx, ComputeAudience, jwt)
	switch {
	case errors.Is(err, sidecar.ErrAuthenticationRefused):
		request.RefuseCode(ComputeRefusalUnauthenticated)
		return false
	case err != nil:
		request.Unavailable()
		return false
	}
	request.Principal = principal
	if principal.SidecarId == nil {
		request.RefuseCode(ComputeRefusalScope)
		return false
	}
	state := self.deps.AuthState
	if state == nil {
		request.Unavailable()
		return false
	}
	if !request.checkRevocation() {
		return false
	}
	caller, answer := state.Caller(principal)
	switch answer {
	case ComputeAuthAllowed:
	case ComputeAuthDenied:
		request.RefuseCode(ComputeRefusalScope)
		return false
	default:
		request.Unavailable()
		return false
	}
	if caller == nil {
		// an allow with no caller is the state's fault, which refuses
		request.Unavailable()
		return false
	}
	features, answer := state.Features(caller.NetworkId)
	if answer != ComputeAuthAllowed {
		request.Unavailable()
		return false
	}
	if computeFeaturesLacking(features) != 0 {
		// §16.6's hold: the network waits for this broker's update, which no retry time can name
		request.RefuseCode(ComputeRefusalUpgradeRequired)
		return false
	}
	request.Caller = caller
	return true
}

// Step 3: §19.11's compute gate. false once it has answered the refusal.
func (self *ComputeEngine) checkGate(request *ComputeRequest) bool {
	gates := self.host.GatesOrClosed()
	gate := gates.Service(sidecar.ServiceGateCompute)
	open := gate.Enabled()
	if request.Caller != nil {
		open = gate.Admits(request.Caller.Principal.NetworkId)
	}
	if open && request.route.Write() {
		open = gate.Writes()
	}
	if open {
		return true
	}
	self.metrics.gateClosed.Add(1, request.route.Name)
	// a closed gate is asked again at the interval the host rereads it (§19.11)
	request.Refuse(&ComputeRefusal{Code: ComputeRefusalUnavailable, RetryAfter: gates.RetryAfter()})
	return false
}

// Notes a fault the design says alarms.
func (self *ComputeEngine) alarm(kind string, format string, args ...any) {
	self.metrics.alarms.Add(1, kind)
	self.log.Errorf("[compute] "+format, args...)
}

// One request on its way through the guard and its route. Not safe for concurrent use: it lives on its request's
// goroutine, and a stream's writer is its own.
type ComputeRequest struct {
	engine *ComputeEngine
	route  *ComputeRoute
	writer *computeResponseWriter
	// The request as received. A handler reads its body through ReadBody and its path values through PathValue; none
	// of it reaches the service log.
	Http *http.Request
	// Ends when the client leaves, at the drain's bound, or at Close.
	Ctx context.Context
	// The engine's own id for the request, the one its log line carries.
	RequestId sidecar.Id
	// The verified token, on a sidecar route.
	Principal *sidecar.Principal
	// Who the request is, on a sidecar route that passed step 2.
	Caller *ComputeCaller

	started             time.Time
	revocationCheckedAt time.Time
	// the request's stream, which finish ends and joins
	stream   *ComputeStream
	answered bool
	status   int
	code     ComputeRefusalCode
	rowIds   []sidecar.Id
}

// The engine serving it.
func (self *ComputeRequest) Engine() *ComputeEngine {
	return self.engine
}

// Its route.
func (self *ComputeRequest) Route() *ComputeRoute {
	return self.route
}

// The engine's clock now.
func (self *ComputeRequest) Now() time.Time {
	return self.engine.clock.Now()
}

// A path value of the route's pattern, such as an enclave's {id}. The service log never holds one.
func (self *ComputeRequest) PathValue(name string) string {
	return self.Http.PathValue(name)
}

// The request's Idempotency-Key, empty for none.
func (self *ComputeRequest) IdempotencyKey() string {
	return self.Http.Header.Get(ComputeIdempotencyKeyHeader)
}

// Notes compute row ids for the request's log line: operation keys, charges, enclaves, by their opaque ids.
func (self *ComputeRequest) NoteRowIds(rowIds ...sidecar.Id) {
	self.rowIds = append(self.rowIds, rowIds...)
}

// rev/ for the token's subjects: 401 unauthenticated when one voids the token, as for one that does not authenticate,
// since the device's answer to both is a new token. false once it has answered the refusal.
func (self *ComputeRequest) checkRevocation() bool {
	err := self.engine.deps.AuthState.CheckRevocation(self.Ctx, self.Principal)
	switch {
	case err == nil:
		self.revocationCheckedAt = self.Now()
		return true
	case errors.Is(err, ErrComputeTokenRevoked):
		self.RefuseCode(ComputeRefusalUnauthenticated)
		return false
	}
	self.Unavailable()
	return false
}

// For a stream or long poll: reads rev/ again once RevocationStreamInterval has passed since the last read. false
// once it has answered the refusal, or for a request with no token, so the stream stops.
func (self *ComputeRequest) RecheckRevocation() bool {
	if self.Principal == nil || self.engine.deps.AuthState == nil {
		return false
	}
	if !self.revocationCheckedAt.IsZero() && self.Now().Sub(self.revocationCheckedAt) < self.engine.settings.RevocationStreamInterval {
		return true
	}
	return self.checkRevocation()
}

// The body, at most the route's bound (ComputeEngineSettings.RouteBodyMaxByteCounts). false once it has answered 400
// invalid, or 503 for a body that did not arrive.
func (self *ComputeRequest) ReadBody() ([]byte, bool) {
	maxByteCount := self.engine.settings.bodyMaxByteCount(self.route.Name)
	if maxByteCount < self.Http.ContentLength {
		self.RefuseCode(ComputeRefusalInvalid)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(self.Http.Body, maxByteCount+1))
	if err != nil {
		self.Unavailable()
		return nil, false
	}
	if maxByteCount < int64(len(body)) {
		self.RefuseCode(ComputeRefusalInvalid)
		return nil, false
	}
	return body, true
}

// The body as message. false once it has answered.
func (self *ComputeRequest) ReadMessage(message proto.Message) bool {
	body, ok := self.ReadBody()
	if !ok {
		return false
	}
	if err := proto.Unmarshal(body, message); err != nil {
		self.RefuseCode(ComputeRefusalInvalid)
		return false
	}
	return true
}

// 200 with message's bytes, or no body for nil.
func (self *ComputeRequest) Reply(message proto.Message) {
	if self.answered {
		return
	}
	body := []byte{}
	if message != nil {
		var err error
		body, err = proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			self.Unavailable()
			return
		}
	}
	self.write(http.StatusOK, computeContentTypeProtobuf, nil, body)
}

// The refusal, its status from the code's. A code the table does not have is a handler's fault that alarms and
// answers 503 unavailable in its place.
func (self *ComputeRequest) Refuse(refusal *ComputeRefusal) {
	if self.answered {
		return
	}
	status, ok := ComputeRefusalStatus(refusal.Code)
	if !ok {
		self.engine.alarm("refusal_code", "route %s refused with a code the table does not have", self.route.Name)
		refusal = &ComputeRefusal{Code: ComputeRefusalUnavailable}
		status = http.StatusServiceUnavailable
	}
	if status == http.StatusServiceUnavailable && refusal.RetryAfter <= 0 && refusal.Code == ComputeRefusalUnavailable {
		// a store or state that did not answer is asked again soon
		copied := *refusal
		copied.RetryAfter = self.engine.settings.UnavailableRetryAfter
		refusal = &copied
	}
	self.code = refusal.Code
	headers := map[string]string{}
	if 0 < refusal.RetryAfter {
		headers["Retry-After"] = strconv.Itoa(max(1, int(math.Ceil(refusal.RetryAfter.Seconds()))))
	}
	self.write(status, computeContentTypeJson, headers, refusal.body())
}

// A refusal with its code alone.
func (self *ComputeRequest) RefuseCode(code ComputeRefusalCode) {
	self.Refuse(NewComputeRefusal(code))
}

// 503 unavailable, retryable after UnavailableRetryAfter.
func (self *ComputeRequest) Unavailable() {
	self.RefuseCode(ComputeRefusalUnavailable)
}

// Takes the request's connection for the tunnel's WebSocket, which the handler upgrades itself (ATTEST). Its line
// records 101, switching protocols. The handler owns the connection from here and closes it when Ctx ends.
func (self *ComputeRequest) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if self.answered {
		return nil, nil, errors.New("the request has already been answered")
	}
	if !self.route.Hijacks {
		self.engine.alarm("hijack_route", "route %s hijacked its connection, which the design does not give it", self.route.Name)
		return nil, nil, errors.New("the route does not hijack")
	}
	conn, readWriter, err := http.NewResponseController(self.writer).Hijack()
	if err != nil {
		return nil, nil, err
	}
	self.answered = true
	self.status = http.StatusSwitchingProtocols
	return conn, readWriter, nil
}

// Writes the answer once.
func (self *ComputeRequest) write(status int, contentType string, headers map[string]string, body []byte) {
	self.answered = true
	self.status = status
	header := self.writer.Header()
	header.Set("Content-Type", contentType)
	// the broker's clock, which a device's direct-path nonces are proposed from (§6.6)
	header.Set(sidecar.ComputeServiceTimeHeader, strconv.FormatInt(self.Now().UnixMilli(), 10))
	for name, value := range headers {
		header.Set(name, value)
	}
	self.writer.WriteHeader(status)
	self.writer.Write(body)
}

// Counts the request and writes its line.
func (self *ComputeRequest) finish() {
	if self.stream != nil {
		self.stream.Close()
	}
	if !self.answered {
		// a handler that answered nothing has failed closed
		self.Unavailable()
	}
	duration := self.engine.clock.Now().Sub(self.started)
	self.engine.metrics.finish(self.route.Name, self.status, self.code, duration)
	if self.route.NoLog {
		return
	}
	self.engine.serviceLog.Write(&ComputeServiceLogEntry{
		Time:      self.started,
		RequestId: self.RequestId,
		Route:     self.route.Name,
		Status:    self.status,
		Code:      self.code,
		Duration:  duration,
		RowIds:    self.rowIds,
	})
}

// The writer a request answers through. It forwards everything, and Unwrap gives http.ResponseController the writer
// underneath, so flushes, deadlines and the tunnel's hijack still reach the status server's connection.
type computeResponseWriter struct {
	http.ResponseWriter
}

// The writer underneath, for http.ResponseController.
func (self *computeResponseWriter) Unwrap() http.ResponseWriter {
	return self.ResponseWriter
}
