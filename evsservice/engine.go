// The evs engine (§11.8), which server/cli/evs hosts at evs.<root>: stateless, keeping every durable thing as an
// object on the file clusters and only rebuildable soft state in Redis (R-EVS-15, owner decisions 2 and 136), with
// no Postgres. It holds no key and never parses git or names (I-1, X2).
//
// One router serves §11.20's /evs/v1 routes. Each task adds its own route list to routes(), and every route runs
// behind one guard, in this order, so no handler sees a request the guard would refuse:
//
//  1. the bearer token, verified offline for aud evs (ServiceHost.Authenticate): 401 UNAUTHENTICATED when it does
//     not authenticate, 503 when the host cannot tell;
//  2. a sidecar's token only, since only a sidecar holds evs scopes: else 403 SCOPE;
//  3. §19.11's evs gate: a network it does not admit, or a write while `writes: false` holds, answers 503 with
//     Retry-After, and the engine stays ready;
//  4. ur_sidecar_id an admitted, unrevoked sidecar of the token's network, as the exchange bound it to the token's
//     client (EvsAuthState, QD-717): 403 SCOPE, or 503 while the state is not loaded;
//  5. on a repo route, the token's repo:<id>:<role> scopes against the rights the route takes, the strongest held
//     honored only while the newest verified state agrees (D-ACL-21), and then only whole: 403 SCOPE, or 503. The one
//     route that carries §11.12's re-seed exception (EvsRoute.ReseedException, PUT .../segments) passes instead a
//     token's admin that the state honors alone while the host's reseed gate is on, marked, which that route takes
//     only through the exception (QD-977). Then, on one that does not write, §20.6's spent row: a spent network's
//     reply is paced on its own repo and refused on another's (quota_read_gate.go);
//  6. on a write, rev/ for the token's three subjects: 401 UNAUTHENTICATED when one voids it, 503 when evs cannot
//     tell; a read goes on for the token's life (owner decision 377);
//  7. on a route that may issue a head CAS, a process whose clock §19.6 finds unknown or over 50 ms off answers
//     503 before step 4 (§11.8's fence row);
//  8. on a placed repo's route, place/ resolved once per process (a 404 cached 5 s): 404 for a repo never placed,
//     503 for a cluster this process holds no credentials for.
//
// Every answer but a 200 is an EvsRefusalReply carrying its code, which decides its status from §11.8's table
// (EVS-FORMAT.md; owner decision 411): a 401 is UNAUTHENTICATED, which the daemon answers by minting a new token, a
// code outside the table is a fault that alarms and answers 503 UNAVAILABLE, and a path or method no route takes is 404
// NOT_FOUND. Every request leaves one line in evs-7's 7-day service log, opaque ids only (I-13). Every metadata write
// passes the write budget first: the engine wraps its host's Blobs in BudgetedBlobs, so a write that never spent fails
// before it is sent, and it refuses to start without a budget.
//
// Safe for concurrent use. No lock is held across I/O or a barrier.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var _ sidecar.HttpEngine = (*EvsEngine)(nil)

// The audience evs's tokens carry (§7.8).
const EvsAudience = "evs"

// Every route's prefix (§11.20).
const evsRoutePrefix = "/evs/v1/"

// The path value a repo route names its repo by.
const evsRepoIdPathValue = "repo_id"

// What a body travels as (EVS-FORMAT.md's HTTP bodies).
const evsContentType = "application/x-protobuf"

// The route name evs-7 and the metrics give a request no route takes: one closed label, never its path (I-13).
const evsUnroutedRouteName = "unrouted"

// One route: what it takes and how the guard holds it. Each later task builds its own and adds its list to
// routes().
type EvsRoute struct {
	// "GET", "PUT", "POST" or "DELETE".
	Method string
	// net/http's pattern from the root, under /evs/v1/, naming a repo by {repo_id}.
	Pattern string
	// The route's template for metrics and the service log, its method and pattern, which hold no id (I-13).
	Name string
	// On a repo route, the rights a token may present on {repo_id}, any one of them; the strongest the token
	// holds is the one honored. Zero for a route on no one repo, whose handler calls AuthorizeRepo itself.
	Rights sidecar.AclEvsRights
	// The route writes: §19.11's `writes: false` closes it, and rev/ is read before it runs.
	Write bool
	// The route may issue a head CAS, so an unsure clock answers it 503 before step 4.
	NeedsSureClock bool
	// The route needs its repo placed, and gets its cluster. False only for the route that places it.
	Placed bool
	// On a placed route: §11.12's refused row, a deleted repo answering 409 REPO_DELETED and one shredding or shredded
	// 409 SHREDDING before the route runs, from repo/ cached at most 5 s. For a route that reads no repo/ state of its
	// own; the push's 5c and the lifecycle routes hold their own.
	RefuseDeleted bool
	// The route carries §11.12's re-seed exception, the one route of it that takes more than admin: PUT .../segments
	// alone (QD-977). When the state refuses the whole right set the guard asks, the token holds admin, the host's
	// reseed gate is on and the state honors the bare admin right, as it does a deleted repo's standing admin
	// (QD-880), the guard passes the request holding admin alone, marked as admitted by the exception; the route
	// then takes a marked request only through the exception and refuses it 403 SCOPE otherwise, as the guard would
	// have. Every other route honors its rights only whole.
	ReseedException bool
	// Answers the request through its methods. Runs on the request's goroutine.
	Serve func(request *EvsRequest)
}

// What the engine takes beyond its host and settings. A nil seam fails closed.
type EvsEngineDeps struct {
	// The newest verified authorization state (auth.go). nil answers every route 503: nothing is honored
	// without it.
	AuthState EvsAuthState
	// evs-7's service log. nil writes it through Log.
	ServiceLog EvsServiceLog
	// Lifecycle, alarms and, when ServiceLog is nil, the service log. nil discards.
	Log sidecar.Logger
	// The segment route's keys, storage gate, HDD share and usage producer (upload_segment.go). nil answers every
	// upload 503, and every push too, since 5c's storage limit, 5h's receipts and step 8's usage read them.
	Uploads *EvsUploadDeps
	// The newest verified authorization state of each network (push.go): 5b's identity keys and 5d's gate. nil
	// answers every push 503.
	GateViews EvsGateViews
	// Step 8's push sequence and hints. nil takes the engine's own over the host's Redis and Push (hint.go).
	CommitNotifier EvsCommitNotifier
	// A stand-in for EVS2-M10-06's rules of a format-2 push inside §19.11's format2 gate (PushView.Format2Rules): a
	// test's. nil runs check_versioning.go's and check_citation.go's.
	Format2Rules func(view *PushView) *EvsCheckRefusal
	// EVSB-M10-01's purge (purge.go), which EVS2-M10-06's step 7 hands each certain commit's candidates. nil queues
	// nothing, which is safe: evacuation's sweep takes every list.
	Purge PurgeSink
	// EVSB-M10-03's drop table as step 8 appends each committed DROP and cancel to it (EVS2-M10-09; CONTRACTS.md C-14),
	// and a push or read that meets a bit-5 window entry appends it again. nil appends to the engine's own DropTable.
	Drops DropSink
	// The holds a slot takeover reads (DESIGN-DETAILS 14.2.4): nil reads hold/ through a HoldCache of the engine's own.
	Holds *HoldCache
	// Routes a test serves beside the engine's own, to hold the guard to a route shape no task has built yet.
	testRoutes []*EvsRoute
}

// The engine. See the file header.
type EvsEngine struct {
	ctx        context.Context
	cancel     context.CancelFunc
	host       *sidecar.ServiceHost
	settings   *EvsSettings
	deps       *EvsEngineDeps
	clock      sidecar.Clock
	log        sidecar.Logger
	serviceLog EvsServiceLog
	// the host's Blobs, its metadata writes held to the budget
	blobs      sidecar.BlobStore
	budget     sidecar.WriteBudget
	priceTable *PriceTable
	places     *sidecar.EvsRepoPlaceResolver
	repos      *RepoCache
	heads      *HeadStore
	batches    *BatchWriter
	records    *RecordCache
	overlays   *OverlayChains
	folder     *Folder
	// gen/<g> records, which 5d judges a push's generation pin by
	generations *GenerationRecords
	// step 8's push sequence and hints: the deps' notifier, else the engine's own (hint.go)
	notifier EvsCommitNotifier
	// records and log pages past their batches, through pidx/
	locator *RecordLocator
	// segments by id, through spidx/ (EVSB-M2-10)
	segments *SegmentLocator
	// §19.11's format2 gate over the host's gates, read per push (format2_gate.go)
	format2 Format2Gate
	// hold/ as a slot takeover reads it, at most 5 s old
	holds *HoldCache
	// drops/<repo>/_, which the drop routes read and write (drop_table.go)
	drops *DropTable
	// the DROP bodies the fence and the read route meet, and the DROPs this process appended (drop_index.go)
	dropIndex *DropIndex
	metrics   *evsMetrics
	handler   http.Handler
	// what the router took at the start, in its order
	servedRoutes []*EvsRoute

	// whether the first metadata cluster answered the last probe
	storesReachable *sidecar.MonitorValue[bool]
	// probes finished
	probeCount *sidecar.MonitorValue[int]
	// requests in flight, for Drain
	inFlightCount *sidecar.MonitorValue[int]
	// commits whose step 8 has started, and those whose step 8 has finished, for Drain and a test's wait; a step 8
	// starts on its request's goroutine, before the handler returns
	stepEightCount     *sidecar.MonitorValue[int]
	stepEightDoneCount *sidecar.MonitorValue[int]
	draining           chan struct{}
	drainingOnce       sync.Once
}

// Starts the engine. host needs Blobs, Budget and Metrics; a nil Budget refuses to start, since no metadata write
// may go unpriced (§11.13). Its Gates, ClockCheck, Redis and Clock are read per request, a nil gate closing every
// route and a nil clock check reading as unsure. It runs until ctx ends or Close.
func NewEvsEngine(ctx context.Context, host *sidecar.ServiceHost, settings *EvsSettings, deps *EvsEngineDeps) (*EvsEngine, error) {
	if host == nil || host.Blobs == nil || host.Metrics == nil {
		return nil, errors.New("evs needs a host with Blobs and Metrics")
	}
	if host.Budget == nil {
		return nil, errors.New("evs needs a write budget: no metadata write may go unpriced (§11.13)")
	}
	if settings == nil {
		settings = DefaultEvsSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil {
		deps = &EvsEngineDeps{}
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	serviceLog := deps.ServiceLog
	if serviceLog == nil {
		serviceLog = NewLoggerServiceLog(log)
	}
	priceTable, err := DefaultPriceTable(settings.PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := host.ClockOrReal()
	blobs := sidecar.BlobStore(NewBudgetedBlobs(host.Blobs))
	self := &EvsEngine{
		ctx:             cancelCtx,
		cancel:          cancel,
		host:            host,
		settings:        settings,
		deps:            deps,
		clock:           clock,
		log:             log,
		serviceLog:      serviceLog,
		blobs:           blobs,
		budget:          host.Budget,
		priceTable:      priceTable,
		places:          sidecar.NewEvsRepoPlaceResolver(blobs, clock, settings.Place),
		repos:           NewRepoCache(clock, settings),
		metrics:         newEvsMetrics(host.Metrics),
		storesReachable: sidecar.NewMonitorValue(false),
		probeCount:      sidecar.NewMonitorValue(0),
		inFlightCount:   sidecar.NewMonitorValue(0),
		draining:        make(chan struct{}),

		stepEightCount:     sidecar.NewMonitorValue(0),
		stepEightDoneCount: sidecar.NewMonitorValue(0),
	}
	self.format2 = NewFormat2Gate(host)
	self.holds = deps.Holds
	if self.holds == nil {
		self.holds = NewHoldCache(host.Blobs, clock, nil)
	}
	self.heads = NewHeadStore(clock, host.ClockCheck, host.Redis, settings, log)
	self.records = NewRecordCache(settings)
	self.batches = NewBatchWriter(cancelCtx, clock, host.ClockCheck, blobs, self.records, settings, log)
	self.overlays = NewOverlayChains(self.heads, settings)
	self.locator = NewRecordLocator(blobs, nil)
	self.folder = NewFolder(cancelCtx, clock, host.ClockCheck, blobs, host.Budget, self.heads, self.records, self.locator, self.repos, priceTable, settings, log)
	self.generations = NewGenerationRecords(settings, clock)
	self.segments = NewSegmentLocator(blobs)
	if self.drops, err = NewDropTable(host, blobs, settings.Drop, log); err != nil {
		cancel()
		return nil, err
	}
	self.dropIndex = NewDropIndex(settings.Drop, self.records, self.locator)
	self.notifier = deps.CommitNotifier
	if self.notifier == nil {
		notifier := NewEvsHintNotifier(cancelCtx, clock, host.Redis, host.Push, deps.GateViews, log)
		notifier.outcomes = host.Metrics.Counter("urnetwork_evs_head_hints_total", "Eligible committed head notifications handed to push within the delivery target, late or failed.", "result")
		self.notifier = notifier
	}
	mux := http.NewServeMux()
	self.servedRoutes = self.routes()
	for _, route := range self.servedRoutes {
		mux.HandleFunc(route.Method+" "+route.Pattern, self.guard(route))
	}
	// every other path and method, the least specific pattern, so a route's own always wins
	mux.HandleFunc("/", self.serveUnrouted)
	// every request's and reply's body bytes count as the caller's transfer (transfer_meter.go)
	var usage *UsageBatcher
	if deps.Uploads != nil {
		usage = deps.Uploads.Usage
	}
	self.handler = MeterTransfer(mux, usage, nil, log)
	go self.run()
	return self, nil
}

// Every route the engine serves. A later task appends its own list here.
func (self *EvsEngine) routes() []*EvsRoute {
	routes := append(self.placeRoutes(), self.uploadRoutes()...)
	routes = append(routes, self.pushRoutes()...)
	routes = append(routes, self.partRoutes()...)
	routes = append(routes, self.leaseRoutes()...)
	routes = append(routes, self.readRoutes()...)
	routes = append(routes, self.subscriptionRoutes()...)
	routes = append(routes, self.pathEpochRoutes()...)
	routes = append(routes, self.erasureRoutes()...)
	routes = append(routes, self.repoRoutes()...)
	routes = append(routes, self.reseedRoutes()...)
	routes = append(routes, self.dropRoutes()...)
	return append(routes, self.deps.testRoutes...)
}

// Every route the router took at the start, in its order, each a copy with no Serve, so a caller reads the table
// and can reach a handler only through Handler and its guard: what server/evshost holds to connect's
// api/bringyour.yml.
func (self *EvsEngine) Routes() []*EvsRoute {
	routes := make([]*EvsRoute, 0, len(self.servedRoutes))
	for _, route := range self.servedRoutes {
		copied := *route
		copied.Serve = nil
		routes = append(routes, &copied)
	}
	return routes
}

// The settings it runs under.
func (self *EvsEngine) Settings() *EvsSettings {
	return self.settings
}

// The host's Blobs, held to the write budget: what every handler writes through.
func (self *EvsEngine) Blobs() sidecar.BlobStore {
	return self.blobs
}

// The process's placement resolver, shared by every handler.
func (self *EvsEngine) Places() *sidecar.EvsRepoPlaceResolver {
	return self.places
}

// The process's repo/ cache.
func (self *EvsEngine) Repos() *RepoCache {
	return self.repos
}

// The process's head store.
func (self *EvsEngine) Heads() *HeadStore {
	return self.heads
}

// The process's batch writer.
func (self *EvsEngine) Batches() *BatchWriter {
	return self.batches
}

// The process's record cache.
func (self *EvsEngine) Records() *RecordCache {
	return self.records
}

// The process's overlay chains.
func (self *EvsEngine) Overlays() *OverlayChains {
	return self.overlays
}

// The process's folds: step 6's page-out, step 8's triggers and the horizon its commits carry.
func (self *EvsEngine) Folder() *Folder {
	return self.folder
}

// One handler for every route.
func (self *EvsEngine) Handler() http.Handler {
	return self.handler
}

// Whether the first metadata cluster, which holds every repo's place/, answered the last probe. A closed gate
// leaves this alone: it answers 503 and the engine stays ready (§19.11).
func (self *EvsEngine) Ready() bool {
	select {
	case <-self.ctx.Done():
		return false
	default:
	}
	return self.storesReachable.Value()
}

// Probes finished, and a channel that closes at the next: what a test waits on.
func (self *EvsEngine) Probes() (count int, changed chan struct{}) {
	return self.probeCount.Get()
}

// Probes the first cluster until the engine ends: one LIST of place/ for a single key, a read that costs the
// drives nothing. It is a store check (sidecar.WithBlobProbe), which the file clusters send outside their cap on a
// host's connections, so it measures the store and never waits in the block's own queue for it (§11.15's fan-out;
// owner decision 790): a probe that fails is the store's failure, and the engine reads not ready.
func (self *EvsEngine) run() {
	for {
		reachable := func() bool {
			ctx, cancel := context.WithCancel(sidecar.WithBlobProbe(self.ctx))
			defer cancel()
			stop := self.clock.AfterFunc(self.settings.StoreProbeTimeout, cancel)
			defer stop()
			firstCluster, err := self.blobs.FirstCluster()
			if err != nil {
				return false
			}
			_, _, err = firstCluster.List(ctx, sidecar.EvsPlaceKeyPrefix, "", 1)
			return err == nil
		}()
		self.storesReachable.Set(reachable)
		var next <-chan time.Time
		if 0 < self.settings.StoreProbeInterval {
			next = self.clock.After(self.settings.StoreProbeInterval)
		}
		self.probeCount.Update(func(count int) int { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-next:
		}
	}
}

// Takes no new request, answering each 503; waits until none is in flight, at most DrainTimeout; then waits until
// every step 8 they started has finished and the notifier has handed each hint it took to push, at most
// StepEightDrainTimeout more. Step 8 runs off the reply path (§11.8), so a commit answered just before or during the
// drain has its push sequence and hints, its stored-byte delta and its head cache entry still to come when its
// request ends, and the host's Close, which follows, ends the engine's ctx under them: the stored-byte delta must be in
// the usage producer before the host drains it. Nothing on the clock is set while nothing is left to wait for.
func (self *EvsEngine) Drain() {
	self.drainingOnce.Do(func() { close(self.draining) })
	// a request the guard took before the drain may still commit, and its step 8 starts before its handler returns,
	// so once none is in flight every such step 8 is counted
	var deadline <-chan time.Time
requests:
	for {
		count, changed := self.inFlightCount.Get()
		if count == 0 {
			break
		}
		if deadline == nil {
			deadline = self.clock.After(self.settings.DrainTimeout)
		}
		select {
		case <-changed:
		case <-deadline:
			// what is still in flight is past the drain's bound; the step 8s already started still get theirs
			break requests
		case <-self.ctx.Done():
			return
		}
	}
	deadline = nil
	for {
		// finished before started: a step 8 that starts between the two reads makes started the greater, so it is
		// never taken for finished
		finished, finishedChanged := self.stepEightDoneCount.Get()
		started := self.stepEightCount.Value()
		unsent, unsentChanged := self.notifier.Unsent()
		if finished == started && unsent == 0 {
			return
		}
		if deadline == nil {
			deadline = self.clock.After(self.settings.StepEightDrainTimeout)
		}
		select {
		case <-finishedChanged:
		case <-unsentChanged:
		case <-deadline:
			return
		case <-self.ctx.Done():
			return
		}
	}
}

// Ends everything at once: the probe, batches waiting to flush (their waiters answered 503) and requests' work
// under the engine's ctx. Safe after Drain, and more than once.
func (self *EvsEngine) Close() {
	self.drainingOnce.Do(func() { close(self.draining) })
	self.cancel()
}

// Whether Drain or Close has begun.
func (self *EvsEngine) isDraining() bool {
	select {
	case <-self.draining:
		return true
	default:
		return false
	}
}

// The handler every route runs behind: the file header's checks in order, then the route.
func (self *EvsEngine) guard(route *EvsRoute) http.HandlerFunc {
	return func(writer http.ResponseWriter, httpRequest *http.Request) {
		request := &EvsRequest{
			engine:  self,
			route:   route,
			Writer:  writer,
			Http:    httpRequest,
			Ctx:     httpRequest.Context(),
			started: self.clock.Now(),
		}
		self.inFlightCount.Update(func(count int) int { return count + 1 })
		defer self.inFlightCount.Update(func(count int) int { return count - 1 })
		defer request.finish()
		if self.isDraining() {
			request.Unavailable(nil)
			return
		}
		if !self.authenticate(request) {
			return
		}
		if route.Rights != 0 {
			repoId, err := parseEvsHexId(httpRequest.PathValue(evsRepoIdPathValue))
			if err != nil {
				request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
				return
			}
			if !request.authorizeRepo(repoId, route.Rights, route.ReseedException) {
				return
			}
			if !route.Write && !request.checkRead() {
				// a spent network reads its own repos, paced, and no other's (quota_read_gate.go)
				return
			}
		}
		if route.Write {
			if !request.checkRevocation() {
				return
			}
		}
		if route.NeedsSureClock && !self.clockSure() {
			// §11.8's fence row: before step 4, so nothing is read or written
			request.Unavailable(nil)
			return
		}
		if route.Placed && !request.resolvePlace() {
			return
		}
		if route.Placed && route.RefuseDeleted && !request.refuseDeleted() {
			return
		}
		route.Serve(request)
	}
}

// A request no route takes: 404 NOT_FOUND, through no guard and before any read, so no near miss of a route reaches
// a handler and even this answer carries its code. It leaves its evs-7 line as every request does.
func (self *EvsEngine) serveUnrouted(writer http.ResponseWriter, httpRequest *http.Request) {
	request := &EvsRequest{
		engine:  self,
		route:   &EvsRoute{Name: evsUnroutedRouteName},
		Writer:  writer,
		Http:    httpRequest,
		Ctx:     httpRequest.Context(),
		started: self.clock.Now(),
	}
	self.inFlightCount.Update(func(count int) int { return count + 1 })
	defer self.inFlightCount.Update(func(count int) int { return count - 1 })
	defer request.finish()
	request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
}

// Steps 1 to 4 of the guard: the token, a sidecar's, the gate and the binding. A token that does not authenticate is
// 401 UNAUTHENTICATED, which refuses nothing: the daemon mints a new one and asks again (§11.20).
func (self *EvsEngine) authenticate(request *EvsRequest) bool {
	jwt, ok := strings.CutPrefix(request.Http.Header.Get("Authorization"), "Bearer ")
	if !ok || jwt == "" {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_UNAUTHENTICATED)
		return false
	}
	principal, err := self.host.Authenticate(request.Ctx, EvsAudience, jwt)
	switch {
	case errors.Is(err, sidecar.ErrAuthenticationRefused):
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_UNAUTHENTICATED)
		return false
	case err != nil:
		request.Unavailable(nil)
		return false
	}
	request.Principal = principal
	meterTransferCaller(request.Writer, principal.NetworkId)
	if principal.SidecarId == nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return false
	}
	request.SidecarId = sidecar.Id(*principal.SidecarId)
	gates := self.host.GatesOrClosed()
	gate := gates.Service(sidecar.ServiceGateEvs)
	if !gate.Admits(principal.NetworkId) || (request.route.Write && !gate.Writes()) {
		self.metrics.gateClosed.Add(1, request.route.Name)
		// a closed gate is asked again at the interval the host rereads it (§19.11)
		request.retryAfter = gates.RetryAfter()
		request.Unavailable(nil)
		return false
	}
	if self.deps.AuthState == nil {
		request.Unavailable(nil)
		return false
	}
	switch self.deps.AuthState.MatchBinding(principal) {
	case EvsAuthAllowed:
	case EvsAuthDenied:
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return false
	default:
		request.Unavailable(nil)
		return false
	}
	return true
}

// Whether this process's clock is sure: known and within §11.8's 50 ms. A host with no check is unsure.
func (self *EvsEngine) clockSure() bool {
	return self.host.ClockCheck != nil && self.host.ClockCheck.Sure()
}

// An id in a path or query: 32 lowercase hex characters, the form object keys and query values take
// (EVS-FORMAT.md).
func parseEvsHexId(text string) (sidecar.Id, error) {
	if len(text) != 32 || strings.ToLower(text) != text {
		return sidecar.Id{}, fmt.Errorf("%w: not 32 lowercase hex characters", sidecar.ErrEvsTokenInvalid)
	}
	return sidecar.ParseId(text)
}

// The P1 cost of creating one small object: place/ and repo/ at creation (plan-EVSB-write-classes).
func (self *EvsEngine) createCost(objectByteCount int) (sidecar.WriteCost, error) {
	return PricePush(self.priceTable, &PushOperations{
		Immediate: []WriteOperation{{Kind: WriteOperationCreate, ObjectByteCount: int64(objectByteCount), Count: 1}},
	})
}

// One request on its way through the guard and its route. Not safe for concurrent use: it lives on its request's
// goroutine.
type EvsRequest struct {
	engine *EvsEngine
	route  *EvsRoute
	// Where the answer goes. A handler answers through Reply, Refuse and the rest, never directly.
	Writer http.ResponseWriter
	// The request as received.
	Http *http.Request
	// Ends when the client leaves.
	Ctx context.Context
	// The verified token.
	Principal *sidecar.Principal
	// Its ur_sidecar_id, which every check holds it to.
	SidecarId sidecar.Id
	// The route's repo, once AuthorizeRepo passed.
	RepoId sidecar.Id
	// What the token holds on RepoId and the state honored: the strongest right the route takes, with what it
	// implies; admin alone for a request the re-seed exception admitted.
	Rights sidecar.AclEvsRights
	// The repo's placement and metadata cluster, on a placed route.
	Place   *sidecar.EvsRepoPlace
	Cluster sidecar.BlobCluster

	// The guard passed it by §11.12's re-seed exception alone (EvsRoute.ReseedException), holding admin and nothing
	// weaker: its route takes it only through the exception.
	reseedAdmitted bool

	started             time.Time
	revocationCheckedAt time.Time
	answered            bool
	status              int
	code                protocol.EvsRefusalCode
	retryAfter          time.Duration
	requestByteCount    int64
	replyByteCount      int64
	refIds              []sidecar.Id
	notes               []string
}

// The engine's clock now.
func (self *EvsRequest) Now() time.Time {
	return self.engine.clock.Now()
}

// The engine serving it.
func (self *EvsRequest) Engine() *EvsEngine {
	return self.engine
}

// Guard step 5 for repoId: the strongest right the token holds of those rights takes, honored only while the
// newest verified state agrees. The state is asked for that right together with each weaker right of its role that
// the route takes: a live repo's admin writes and reads and its writer reads, so this asks no more of them, while a
// deleted repo's standing admin holds admin alone (QD-880), so its admin token passes only the routes that take
// admin and nothing weaker, DELETE and restore among them, and no read or write route. A route on no one repo
// calls this itself once its body names the repo, and such a call never takes §11.12's re-seed exception, which is
// the guard's alone on the one route that carries it. false once it has answered the refusal.
func (self *EvsRequest) AuthorizeRepo(repoId sidecar.Id, rights sidecar.AclEvsRights) bool {
	return self.authorizeRepo(repoId, rights, false)
}

// AuthorizeRepo, and with reseedException, on the route that carries §11.12's re-seed exception (QD-977): where the
// state refuses the whole set asked of a token whose strongest right here is admin, the host's reseed gate is on and
// the state honors the bare admin right, as it does a deleted repo's standing admin (QD-880), the request passes
// holding admin alone and marked, and its route takes it only through the exception. The state is asked twice only
// then. false once it has answered the refusal.
func (self *EvsRequest) authorizeRepo(repoId sidecar.Id, rights sidecar.AclEvsRights, reseedException bool) bool {
	if repoId == (sidecar.Id{}) {
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return false
	}
	right := strongestRight(TokenRepoRights(self.Principal, repoId) & rights)
	if right == 0 {
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return false
	}
	honored := impliedRights(right)
	answer := self.engine.deps.AuthState.HonorScope(self.Principal, repoId, right|honored&rights, self.Now())
	reseedAdmitted := false
	if answer == EvsAuthDenied && reseedException && right == sidecar.AclEvsAdmin && self.engine.host.GatesOrClosed().Reseed() {
		// the exception's one pass, admin and nothing weaker, which a refused bare admin refuses as the whole set did
		answer = self.engine.deps.AuthState.HonorScope(self.Principal, repoId, sidecar.AclEvsAdmin, self.Now())
		honored = sidecar.AclEvsAdmin
		reseedAdmitted = true
	}
	switch answer {
	case EvsAuthAllowed:
	case EvsAuthDenied:
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return false
	default:
		self.Unavailable(nil)
		return false
	}
	self.RepoId = repoId
	self.Rights = honored
	self.reseedAdmitted = reseedAdmitted
	return true
}

// For a stronger right than the guard honored, as a closure upload's admin (§11.20): the token must hold it and
// the state agree. false once it has answered the refusal.
func (self *EvsRequest) RequireRights(right sidecar.AclEvsRights) bool {
	if self.Rights.Has(right) {
		return true
	}
	if !TokenRepoRights(self.Principal, self.RepoId).Has(right) {
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return false
	}
	switch self.engine.deps.AuthState.HonorScope(self.Principal, self.RepoId, right, self.Now()) {
	case EvsAuthAllowed:
		self.Rights |= impliedRights(right)
		return true
	case EvsAuthDenied:
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return false
	}
	self.Unavailable(nil)
	return false
}

// rev/ for the token's subjects: 401 UNAUTHENTICATED when one voids the token, as for one that does not authenticate,
// since the daemon's answer to both is a new token, whose exchange a voided subject cannot pass. false once it has
// answered the refusal.
func (self *EvsRequest) checkRevocation() bool {
	err := self.engine.deps.AuthState.CheckRevocation(self.Ctx, self.Principal)
	switch {
	case err == nil:
		self.revocationCheckedAt = self.Now()
		return true
	case errors.Is(err, ErrEvsTokenRevoked):
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_UNAUTHENTICATED)
		return false
	}
	self.Unavailable(nil)
	return false
}

// For a stream: reads rev/ again once RevocationStreamInterval has passed since the last read (§11.8: streams
// over 60 s). false once it has answered the refusal, so the stream stops.
func (self *EvsRequest) RecheckRevocation() bool {
	if !self.revocationCheckedAt.IsZero() && self.Now().Sub(self.revocationCheckedAt) < self.engine.settings.RevocationStreamInterval {
		return true
	}
	return self.checkRevocation()
}

// Guard step 8: the repo's placement and cluster. false once it has answered the refusal. A read takes §11.8's 404
// cached 5 s; a write a 404 only from a read of place/ begun after it (EvsRepoPlaceResolver.ResolveCurrent), since a
// reader's request that cached one ahead of the creator's PUT, on another process than the PUT's, must not refuse the
// creation's activation or first push.
func (self *EvsRequest) resolvePlace() bool {
	places := self.engine.places.Cluster
	if self.route.Write {
		places = self.engine.places.ClusterCurrent
	}
	cluster, place, err := places(self.Ctx, self.RepoId)
	switch {
	case err == nil:
		self.Place = place
		self.Cluster = cluster
		return true
	case errors.Is(err, sidecar.ErrEvsRepoNotPlaced):
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		return false
	case errors.Is(err, sidecar.ErrEvsRepoPlaceInvalid):
		self.engine.log.Errorf("[evs] repo %s: place/ holds no placement", sidecar.EvsKeyId(self.RepoId))
		self.engine.metrics.alarms.Add(1, "place_invalid")
	}
	self.Unavailable(nil)
	return false
}

// §11.12's refused row for a route that reads no repo/ state of its own: a deleted repo answers 409 REPO_DELETED and
// one past it 409 SHREDDING; keying and active pass. false once it has answered the refusal.
func (self *EvsRequest) refuseDeleted() bool {
	read, err := self.engine.repos.Read(self.Ctx, self.Cluster, self.RepoId)
	if !self.engine.answerTransition(self, err) {
		return false
	}
	switch read.Object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_KEYING, protocol.EvsRepoState_EVS_REPO_ACTIVE:
		return true
	}
	self.RefuseCode(repoStateRefusal(read.Object).Code)
	return false
}

// Notes ref ids for evs-7's line.
func (self *EvsRequest) NoteRefIds(refIds ...sidecar.Id) {
	self.refIds = append(self.refIds, refIds...)
}

// Notes what the route read, such as ranges or slots, for evs-7's line, opaque ids and numbers only.
func (self *EvsRequest) Note(note string) {
	self.notes = append(self.notes, note)
}

// The body, at most the route's bound and RequestBodyMaxByteCount. false once it has answered 400.
func (self *EvsRequest) ReadBody(maxByteCount int64) ([]byte, bool) {
	maxByteCount = min(maxByteCount, self.engine.settings.RequestBodyMaxByteCount)
	if maxByteCount <= 0 {
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(self.Http.Body, maxByteCount+1))
	self.requestByteCount += int64(len(body))
	if err != nil {
		self.Unavailable(nil)
		return nil, false
	}
	if maxByteCount < int64(len(body)) {
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return nil, false
	}
	return body, true
}

// The body as message. false once it has answered 400.
func (self *EvsRequest) ReadMessage(message proto.Message, maxByteCount int64) bool {
	body, ok := self.ReadBody(maxByteCount)
	if !ok {
		return false
	}
	if err := proto.Unmarshal(body, message); err != nil {
		self.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return false
	}
	return true
}

// 200 with message's bytes, or no body for nil.
func (self *EvsRequest) Reply(message proto.Message) {
	if self.answered {
		return
	}
	body := []byte{}
	if message != nil {
		var err error
		body, err = proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			self.Unavailable(nil)
			return
		}
	}
	self.write(http.StatusOK, body)
}

// The refusal reply's code decides its status, from the fixed table, so every answer but a 200 carries its code; a
// 429 or 503 with retry_after_ms carries Retry-After too. A code the table does not have, code 0 among them, is a
// handler's fault that alarms, and answers 503 UNAVAILABLE in its place, which refuses nothing.
func (self *EvsRequest) Refuse(reply *protocol.EvsRefusalReply) {
	if self.answered {
		return
	}
	status, ok := sidecar.EvsRefusalStatus(reply.GetCode())
	if !ok {
		self.engine.alarm("refusal_code", "route %s refused with code %d, which §11.8's table does not have", self.route.Name, reply.GetCode())
		reply = proto.CloneOf(reply)
		reply.Code = protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE
		status = http.StatusServiceUnavailable
	}
	self.code = reply.GetCode()
	if 0 < reply.GetRetryAfterMs() {
		self.retryAfter = time.Duration(reply.GetRetryAfterMs()) * time.Millisecond
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(reply)
	if err != nil {
		// a reply whose other fields do not marshal still says why, by its code alone
		body, _ = proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsRefusalReply{Code: reply.GetCode()})
	}
	self.write(status, body)
}

// A refusal with only its code.
func (self *EvsRequest) RefuseCode(code protocol.EvsRefusalCode) {
	self.Refuse(&protocol.EvsRefusalReply{Code: code})
}

// 503 UNAVAILABLE, retryable: the store unreachable, the state not loaded, the gate closed or the clock unsure.
// reply may carry a push id and an unknown outcome; nil answers the code alone.
func (self *EvsRequest) Unavailable(reply *protocol.EvsRefusalReply) {
	if reply == nil {
		reply = &protocol.EvsRefusalReply{}
	}
	reply.Code = protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE
	self.Refuse(reply)
}

// Writes the answer once. A 503 always carries Retry-After: a closed gate's interval, the reply's, or
// UnavailableRetryAfter for a store or state that did not answer. A 429 and a 507 CLUSTER_FULL carry the reply's.
func (self *EvsRequest) write(status int, body []byte) {
	self.answered = true
	self.status = status
	self.replyByteCount = int64(len(body))
	header := self.Writer.Header()
	header.Set("Content-Type", evsContentType)
	if status == http.StatusServiceUnavailable && self.retryAfter <= 0 {
		self.retryAfter = max(time.Second, self.engine.settings.UnavailableRetryAfter)
	}
	if 0 < self.retryAfter && (status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests ||
		status == http.StatusInsufficientStorage) {
		header.Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(self.retryAfter.Seconds())))))
	}
	self.Writer.WriteHeader(status)
	self.Writer.Write(body)
}

// Counts the request and writes its evs-7 line.
func (self *EvsRequest) finish() {
	if !self.answered {
		// a handler that answered nothing has failed closed
		self.Unavailable(nil)
	}
	entry := &EvsServiceLogEntry{
		Time:             self.started,
		Route:            self.route.Name,
		Status:           self.status,
		Code:             self.code,
		RepoId:           self.RepoId,
		RefIds:           self.refIds,
		RequestByteCount: self.requestByteCount,
		ReplyByteCount:   self.replyByteCount,
		Duration:         self.engine.clock.Now().Sub(self.started),
		Notes:            self.notes,
	}
	if self.Principal != nil {
		entry.NetworkId = sidecar.Id(self.Principal.NetworkId)
		entry.ClientId = sidecar.Id(self.Principal.ClientId)
		entry.SidecarId = self.SidecarId
	}
	self.engine.serviceLog.Write(entry)
	self.engine.metrics.requests.Add(1, self.route.Name, strconv.Itoa(self.status))
	if self.code != protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED {
		self.engine.metrics.refusals.Add(1, self.route.Name, self.code.String())
	}
	self.engine.metrics.seconds.Observe(entry.Duration.Seconds(), self.route.Name)
}

// One line of evs-7: §2.8's "request log; caller ids, route, repo and ref ids, ranges and slots read, bytes, status,
// time", kept 7 days (§19.8). Opaque ids and numbers only, never a token path or a name (I-13).
type EvsServiceLogEntry struct {
	Time      time.Time
	Route     string
	NetworkId sidecar.Id
	ClientId  sidecar.Id
	SidecarId sidecar.Id
	RepoId    sidecar.Id
	RefIds    []sidecar.Id
	// What a route noted of what it read: ranges, slots, by id and number.
	Notes            []string
	RequestByteCount int64
	ReplyByteCount   int64
	Status           int
	Code             protocol.EvsRefusalCode
	Duration         time.Duration
}

// Where evs-7's lines go: the host's log pipeline, which keeps them 7 days. Write never blocks a request on I/O of
// its own. Safe for concurrent use.
type EvsServiceLog interface {
	Write(entry *EvsServiceLogEntry)
}

// evs-7 through a Logger, one Info line a request.
type loggerServiceLog struct {
	log sidecar.Logger
}

// evs-7's lines through log.
func NewLoggerServiceLog(log sidecar.Logger) EvsServiceLog {
	return &loggerServiceLog{log: log}
}

// One line: time, route, status and code, caller ids, repo and ref ids, notes, bytes and duration.
func (self *loggerServiceLog) Write(entry *EvsServiceLogEntry) {
	refIds := make([]string, len(entry.RefIds))
	for i, refId := range entry.RefIds {
		refIds[i] = sidecar.EvsKeyId(refId)
	}
	self.log.Infof("[evs-7] %d %s %d %s network=%s client=%s sidecar=%s repo=%s refs=%s notes=%s in=%d out=%d ms=%d",
		entry.Time.UnixMilli(), entry.Route, entry.Status, entry.Code,
		sidecar.EvsKeyId(entry.NetworkId), sidecar.EvsKeyId(entry.ClientId), sidecar.EvsKeyId(entry.SidecarId),
		sidecar.EvsKeyId(entry.RepoId), strings.Join(refIds, ","), strings.Join(entry.Notes, ","),
		entry.RequestByteCount, entry.ReplyByteCount, entry.Duration.Milliseconds())
}

// §19.8's evs series. Labels come from closed sets: a route's template, a status, a code's name, an alarm's kind.
type evsMetrics struct {
	requests   sidecar.MetricsCounter
	refusals   sidecar.MetricsCounter
	gateClosed sidecar.MetricsCounter
	seconds    sidecar.MetricsHistogram
	// faults the design says alarm: an immutable key holding other bytes, a placement that does not parse, and a
	// handler's refusal with a code the table does not have
	alarms sidecar.MetricsCounter
	// step 6's slot_foreign: a new slot another statement holds, or no statement, refused 409 SLOT_STALE
	// (DESIGN-DETAILS 14.2.3), which no alarm follows since an honest retry meets one after a rollout
	slotForeign sidecar.MetricsCounter
}

// Declares the series.
func newEvsMetrics(metrics sidecar.Metrics) *evsMetrics {
	return &evsMetrics{
		requests:    metrics.Counter("urnetwork_evs_requests_total", "evs requests by route and status", "route", "status"),
		refusals:    metrics.Counter("urnetwork_evs_refusals_total", "evs refusals by route and code", "route", "code"),
		gateClosed:  metrics.Counter("urnetwork_evs_gate_closed_total", "evs requests the gate answered 503", "route"),
		seconds:     metrics.Histogram("urnetwork_evs_request_seconds", "evs request time by route", nil, "route"),
		alarms:      metrics.Counter("urnetwork_evs_alarms_total", "evs faults that alarm, by kind", "kind"),
		slotForeign: metrics.Counter("urnetwork_evs_slot_foreign_total", "new slots step 6 found another statement's or no statement's"),
	}
}

// The token's network as the root's id.
func networkIdOf(principal *sidecar.Principal) sidecar.Id {
	return sidecar.Id(principal.NetworkId)
}
