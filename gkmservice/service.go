// The gkm engine, which server/cli/gkm hosts: stateless over ServiceHost.Blobs, with no Postgres, and in Redis only
// what the host's Push writes for its hints ({scp_}), §11.13's budget ({nvb_}) and its acks ({gka_}) (§22.7). It
// holds no key and reads no proposal (I-1, owner decision 59).
//
// One router serves §10.14's routes, every one behind one guard, in this order, so no handler sees a request the
// guard would refuse:
//
//  1. the bearer token, verified offline for aud gkm (ServiceHost.Authenticate): 401 when it does not authenticate,
//     503 when the host cannot tell;
//  2. §19.11's gkm gate: a network it does not admit, or a write while `writes: false` holds, answers 503 with
//     Retry-After, and the engine stays ready;
//  3. ids in the path: 32 lowercase hex characters, else 400;
//  4. the token's reach (auth.go): a sidecar's token holding r, rw or admin on some repo, or for drop-key any repo
//     scope, or for a member's recovery read its recovery:<member_id>: 403;
//  5. the sidecar's standing in gkm's newest verified state: admitted and not revoked, and for a write not parked
//     or suspended, and the row's own needs, a member device for a leaf's commit, not read_only for wraps, claims,
//     Welcomes and GroupInfo (D-KEYS-26): 403, or 503 while the state is not loaded;
//  6. a recovery row's member: the token's sidecar a device of the path's member, unless its recovery scope names
//     that member: 403;
//  7. the route's repo, from the path, from the group (store.go), or from the body by the handler: the strongest
//     right the token holds of those the row takes, honored only while the newest verified state agrees (D-ACL-21),
//     the repo's cluster from place/, and for a write repo/'s state: 403, 404 for a repo never placed, or 503;
//  8. on a write, rev/ for the token's three subjects: 401 when one voids it, 503 when gkm cannot tell.
//
// Every request leaves one line in gkm-9's 7-day request log, holding gkm-9's fields and no more: client, route,
// group, time and bytes (§2.8, I-13). URLs carry opaque ids only, and W8's access log, which logs $uri, sees no
// other.
//
// Safe for concurrent use. No lock is held across I/O or a barrier.

package gkmservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var _ sidecar.HttpEngine = (*GkmEngine)(nil)

// What every body travels as: a protocol/gkm.proto message, a bare Signed, or MLS bytes (connect's bringyour.yml).
const gkmContentType = "application/octet-stream"

// What the engine takes beyond its host and settings. A nil seam fails closed.
type GkmEngineDeps struct {
	// gkm's newest verified authorization state and rev/ (auth.go). nil answers every route 503: nothing is
	// honored without it.
	AuthState GkmAuthState
	// gkm-9's request log. nil writes it through Log.
	ServiceLog GkmServiceLog
	// Lifecycle, alarms and, when ServiceLog is nil, the request log. nil discards.
	Log sidecar.Logger
	// Handlers a test serves in place of the table's, by pattern, to hold the guard to rows whose handlers have not
	// landed.
	testServes map[string]func(engine *GkmEngine, request *GkmRequest)
}

// The engine. See the file header.
type GkmEngine struct {
	ctx        context.Context
	cancel     context.CancelFunc
	host       *sidecar.ServiceHost
	settings   *GkmServiceSettings
	deps       *GkmEngineDeps
	clock      sidecar.Clock
	log        sidecar.Logger
	serviceLog GkmServiceLog
	blobs      sidecar.BlobStore
	places     *sidecar.EvsRepoPlaceResolver
	repos      *gkmRepoCache
	forms      *gkmFormCache
	rates      GkmRateCounter
	kinds      *gkmKeyPackageKinds
	metrics    *gkmMetrics
	handler    http.Handler

	newestEpochs *gkmNewestEpochs
	groupInfos   *gkmGroupInfoCache
	generations  *gkmGenerationCache

	hintQueue        chan *gkmQueuedHint
	hintPendingCount *sidecar.MonitorValue[int]

	// whether the first metadata cluster answered the last probe
	storesReachable *sidecar.MonitorValue[bool]
	// probes finished
	probeCount *sidecar.MonitorValue[int]
	// requests in flight, for Drain
	inFlightCount *sidecar.MonitorValue[int]
	draining      chan struct{}
	drainingOnce  sync.Once
}

// Starts the engine. host needs Blobs, Budget and Metrics; a nil Budget refuses to start, since no metadata write may
// go unpriced (§11.13, budget.go). Its Authenticator, Gates, Push and Clock are read per request, a nil gate closing
// every route and a nil Push losing every hint, which the hourly resync covers. It runs until ctx ends or Close.
func NewGkmEngine(ctx context.Context, host *sidecar.ServiceHost, settings *GkmServiceSettings, deps *GkmEngineDeps) (*GkmEngine, error) {
	if host == nil || host.Blobs == nil || host.Metrics == nil {
		return nil, errors.New("gkm needs a host with Blobs and Metrics")
	}
	if host.Budget == nil {
		return nil, errors.New("gkm needs a write budget: no metadata write may go unpriced (§11.13)")
	}
	if settings == nil {
		settings = DefaultGkmServiceSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil {
		deps = &GkmEngineDeps{}
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	serviceLog := deps.ServiceLog
	if serviceLog == nil {
		serviceLog = NewLoggerGkmServiceLog(log)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := host.ClockOrReal()
	self := &GkmEngine{
		ctx:              cancelCtx,
		cancel:           cancel,
		host:             host,
		settings:         settings,
		deps:             deps,
		clock:            clock,
		log:              log,
		serviceLog:       serviceLog,
		blobs:            host.Blobs,
		places:           sidecar.NewEvsRepoPlaceResolver(host.Blobs, clock, settings.Place),
		repos:            newGkmRepoCache(clock, settings),
		forms:            newGkmFormCache(clock, settings),
		rates:            newGkmRateCounters(settings.RateEntryCount),
		kinds:            newGkmKeyPackageKinds(settings.KeyPackageKindCacheCount),
		metrics:          newGkmMetrics(host.Metrics),
		newestEpochs:     newGkmNewestEpochs(settings.NewestEpochCacheCount),
		groupInfos:       newGkmGroupInfoCache(clock, settings),
		generations:      newGkmGenerationCache(settings.GenerationCacheCount),
		hintQueue:        make(chan *gkmQueuedHint, settings.HintQueueCount),
		hintPendingCount: sidecar.NewMonitorValue(0),
		storesReachable:  sidecar.NewMonitorValue(false),
		probeCount:       sidecar.NewMonitorValue(0),
		inFlightCount:    sidecar.NewMonitorValue(0),
		draining:         make(chan struct{}),
	}
	mux := http.NewServeMux()
	for _, route := range gkmRoutes {
		serve := route.Serve
		if testServe, ok := deps.testServes[route.Pattern]; ok {
			serve = testServe
		}
		mux.HandleFunc(route.Pattern, self.guard(route, serve))
	}
	self.handler = mux
	for i := 0; i < settings.HintWorkerCount; i += 1 {
		go self.runHintSender()
	}
	go self.run()
	return self, nil
}

// The settings it runs under.
func (self *GkmEngine) Settings() *GkmServiceSettings {
	return self.settings
}

// One handler for every route.
func (self *GkmEngine) Handler() http.Handler {
	return self.handler
}

// Whether the first metadata cluster, which holds every repo's place/ and every sidecar's objects, answered the
// last probe. A closed gate leaves this alone: it answers 503 and the engine stays ready (§19.11).
func (self *GkmEngine) Ready() bool {
	select {
	case <-self.ctx.Done():
		return false
	default:
	}
	return self.storesReachable.Value()
}

// Probes finished, and a channel that closes at the next: what a test waits on.
func (self *GkmEngine) Probes() (count int, changed chan struct{}) {
	return self.probeCount.Get()
}

// Probes the first cluster until the engine ends: one LIST of place/ for a single key, a read that costs the drives
// nothing.
func (self *GkmEngine) run() {
	for {
		reachable := func() bool {
			ctx, cancel := context.WithCancel(self.ctx)
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

// Takes no new request, answering each 503, and returns once none is in flight or DrainTimeout has passed.
func (self *GkmEngine) Drain() {
	self.drainingOnce.Do(func() { close(self.draining) })
	deadline := self.clock.After(self.settings.DrainTimeout)
	for {
		count, changed := self.inFlightCount.Get()
		if count == 0 {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			return
		case <-self.ctx.Done():
			return
		}
	}
}

// Ends everything at once: the probe, the hint senders and requests' work under the engine's ctx. Hints still
// queued are lost, which the hourly resync covers. Safe after Drain, and more than once.
func (self *GkmEngine) Close() {
	self.drainingOnce.Do(func() { close(self.draining) })
	self.cancel()
}

// Whether Drain or Close has begun.
func (self *GkmEngine) isDraining() bool {
	select {
	case <-self.draining:
		return true
	default:
		return false
	}
}

// Counts and logs a fault the design says alarms. kind is from a closed set.
func (self *GkmEngine) alarm(kind string, err error) {
	self.metrics.alarms.Add(1, kind)
	self.log.Errorf("[gkm] alarm %s: %v", kind, err)
}

// The first metadata cluster, which holds every sidecar's objects.
func (self *GkmEngine) firstCluster() (sidecar.BlobCluster, error) {
	return self.blobs.FirstCluster()
}

// The handler every route runs behind: the file header's checks in order, then serve.
func (self *GkmEngine) guard(route *GkmRoute, serve func(engine *GkmEngine, request *GkmRequest)) http.HandlerFunc {
	return func(writer http.ResponseWriter, httpRequest *http.Request) {
		request := &GkmRequest{
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
			request.Unavailable()
			return
		}
		if !self.authenticate(request) || !request.parsePath() || !request.admitToken() ||
			!request.checkStanding() || !request.checkMember() {
			return
		}
		switch route.Target {
		case gkmTargetPathRepo:
			if !request.AuthorizeRepo(request.pathRepoId) {
				return
			}
		case gkmTargetPathGroup:
			if !request.AuthorizeGroup(request.pathGroupId) {
				return
			}
		case gkmTargetNone, gkmTargetPathMember:
			// the token's reach, standing and member are this route's whole scope
			request.authorized = true
		}
		if route.Write && !request.checkRevocation() {
			return
		}
		if serve == nil {
			request.NotBuilt()
			return
		}
		serve(self, request)
	}
}

// Steps 1 and 2 of the guard: the token and the gate.
func (self *GkmEngine) authenticate(request *GkmRequest) bool {
	jwt, ok := strings.CutPrefix(request.Http.Header.Get("Authorization"), "Bearer ")
	if !ok || jwt == "" {
		request.Unauthorized()
		return false
	}
	principal, err := self.host.Authenticate(request.Ctx, GkmAudience, jwt)
	switch {
	case errors.Is(err, sidecar.ErrAuthenticationRefused):
		request.Unauthorized()
		return false
	case err != nil:
		request.Unavailable()
		return false
	}
	request.Principal = principal
	request.scopes = parseGkmTokenScopes(principal)
	if principal.SidecarId != nil {
		request.SidecarId = sidecar.Id(*principal.SidecarId)
	}
	gates := self.host.GatesOrClosed()
	gate := gates.Service(sidecar.ServiceGateGkm)
	if !gate.Admits(principal.NetworkId) || (request.route.Write && !gate.Writes()) {
		self.metrics.gateClosed.Add(1, request.route.Pattern)
		// a closed gate is asked again at the interval the host rereads it (§19.11)
		request.retryAfter = gates.RetryAfter()
		request.Unavailable()
		return false
	}
	if self.deps.AuthState == nil {
		request.Unavailable()
		return false
	}
	return true
}

// An id in a path or query: 32 lowercase hex characters, the form object keys take (QD-442).
func parseGkmHexId(text string) (sidecar.Id, error) {
	if len(text) != 32 || strings.ToLower(text) != text {
		return sidecar.Id{}, fmt.Errorf("%w: not 32 lowercase hex characters", sidecar.ErrGkmMalformed)
	}
	id, err := sidecar.ParseId(text)
	if err != nil || id == (sidecar.Id{}) {
		return sidecar.Id{}, fmt.Errorf("%w: not an id", sidecar.ErrGkmMalformed)
	}
	return id, nil
}

// A number in a path or query: decimal digits with no sign or leading zero, at most uint64.
func parseGkmNumber(text string) (uint64, error) {
	number, err := strconv.ParseUint(text, 10, 64)
	if err != nil || strconv.FormatUint(number, 10) != text {
		return 0, fmt.Errorf("%w: not a number", sidecar.ErrGkmMalformed)
	}
	return number, nil
}

// One request on its way through the guard and its route. Not safe for concurrent use: it lives on its request's
// goroutine.
type GkmRequest struct {
	engine *GkmEngine
	route  *GkmRoute
	// Where the answer goes. A handler answers through Reply and the rest, never directly.
	Writer http.ResponseWriter
	// The request as received.
	Http *http.Request
	// Ends when the client leaves.
	Ctx context.Context
	// The verified token.
	Principal *sidecar.Principal
	// Its ur_sidecar_id; zero for a recovery read by an unadmitted client.
	SidecarId sidecar.Id
	// What the newest verified state holds of that sidecar, once the guard read it.
	Sidecar *GkmSidecarFacts
	// The route's repo and group, once authorized.
	RepoId  sidecar.Id
	GroupId *sidecar.Id
	// What the token holds on RepoId and the state honored: the strongest right the row takes, with what it implies.
	Rights sidecar.AclEvsRights
	// The repo's metadata cluster, where its group's objects live.
	Cluster sidecar.BlobCluster

	scopes           *gkmTokenScopes
	pathRepoId       sidecar.Id
	pathGroupId      sidecar.Id
	pathMemberId     sidecar.Id
	viaRecoveryScope bool
	authorized       bool

	started          time.Time
	answered         bool
	status           int
	retryAfter       time.Duration
	requestByteCount int64
	replyByteCount   int64
	// what ends each write budget admission the request made, once its writes have (budget.go)
	releases []func()
}

// The engine's clock now.
func (self *GkmRequest) Now() time.Time {
	return self.engine.clock.Now()
}

// The route's pattern.
func (self *GkmRequest) Route() string {
	return self.route.Pattern
}

// Step 3: the path's ids, each 32 lowercase hex characters.
func (self *GkmRequest) parsePath() bool {
	for _, value := range []struct {
		name string
		id   *sidecar.Id
	}{
		{name: gkmPathValueRepoId, id: &self.pathRepoId},
		{name: gkmPathValueGroupId, id: &self.pathGroupId},
		{name: gkmPathValueMemberId, id: &self.pathMemberId},
	} {
		text := self.Http.PathValue(value.name)
		if text == "" {
			continue
		}
		id, err := parseGkmHexId(text)
		if err != nil {
			self.BadRequest()
			return false
		}
		*value.id = id
	}
	return true
}

// Step 4: the token's reach. A token whose only repo scopes are deposit reaches drop-key alone, a recovery scope its
// member's recovery read alone, and every other route needs a sidecar's token holding r, rw or admin on some repo
// (QD-177).
func (self *GkmRequest) admitToken() bool {
	switch self.route.Scope {
	case gkmScopeRecoveryRead:
		if self.scopes.recoveryMemberIds[self.pathMemberId] {
			self.viaRecoveryScope = true
			return true
		}
	case gkmScopeDeposit:
		if self.Principal.SidecarId != nil && self.scopes.holdsRepoScope() {
			return true
		}
		self.Forbidden()
		return false
	}
	if self.Principal.SidecarId == nil || !self.scopes.holdsRepoAccess() {
		self.Forbidden()
		return false
	}
	return true
}

// Step 5: the sidecar's standing, and what its row asks of it (§10.6's scopes).
func (self *GkmRequest) checkStanding() bool {
	if self.viaRecoveryScope {
		// an unadmitted client holds no standing: its scope is its whole reach
		return true
	}
	facts, answer := self.engine.deps.AuthState.Sidecar(self.Principal, self.SidecarId)
	switch answer {
	case GkmAuthAllowed:
	case GkmAuthDenied:
		self.Forbidden()
		return false
	default:
		self.Unavailable()
		return false
	}
	if facts == nil || facts.Revoked {
		self.Forbidden()
		return false
	}
	if (self.route.Write || self.route.Scope == gkmScopeOwn) && (facts.Parked || facts.Suspended) {
		self.Forbidden()
		return false
	}
	switch self.route.Scope {
	case gkmScopeLeaf:
		if !facts.MemberDevice {
			self.Forbidden()
			return false
		}
	case gkmScopeInfo:
		if !facts.MemberDevice || facts.ReadOnly {
			self.Forbidden()
			return false
		}
	case gkmScopeDeliver, gkmScopeStage, gkmScopeWrite, gkmScopeAdmin, gkmScopeRecoveryOwn:
		// a read_only device keeps its key upkeep and loses every wrap, claim, Welcome and GroupInfo it would write,
		// a rebind's recovery wraps among them (§7.9's read_only row)
		if facts.ReadOnly {
			self.Forbidden()
			return false
		}
	}
	self.Sidecar = facts
	return true
}

// Step 6: a recovery row's member, whose device the token's sidecar must be unless its recovery scope names it.
func (self *GkmRequest) checkMember() bool {
	switch self.route.Scope {
	case gkmScopeRecoveryRead, gkmScopeRecoveryOwn:
	default:
		return true
	}
	if self.viaRecoveryScope {
		return true
	}
	if self.Sidecar.MemberId == nil || *self.Sidecar.MemberId != self.pathMemberId {
		self.Forbidden()
		return false
	}
	return true
}

// Step 7 for repoId: the strongest right the token holds of those the route's row takes, honored only while the
// newest verified state agrees, then the repo's cluster from place/, and for a write repo/'s state. A route whose
// body names its repo calls this itself before it answers a success. false once it has answered the refusal.
func (self *GkmRequest) AuthorizeRepo(repoId sidecar.Id) bool {
	if repoId == (sidecar.Id{}) {
		self.BadRequest()
		return false
	}
	right := gkmStrongestRight(self.scopes.repoIdRights[repoId] & self.route.Scope.rights())
	if right == 0 {
		self.Forbidden()
		return false
	}
	switch self.engine.deps.AuthState.HonorScope(self.Principal, repoId, right, self.Now()) {
	case GkmAuthAllowed:
	case GkmAuthDenied:
		self.Forbidden()
		return false
	default:
		self.Unavailable()
		return false
	}
	cluster, _, err := self.engine.places.Cluster(self.Ctx, repoId)
	switch {
	case err == nil:
	case errors.Is(err, sidecar.ErrEvsRepoNotPlaced):
		self.NotFound()
		return false
	case errors.Is(err, sidecar.ErrEvsRepoPlaceInvalid):
		self.engine.alarm("place_invalid", err)
		self.Unavailable()
		return false
	default:
		self.Unavailable()
		return false
	}
	self.RepoId = repoId
	self.Rights = gkmImpliedRights(right)
	self.Cluster = cluster
	if self.route.Write && self.route.RepoState != gkmRepoStateAny && !self.CheckRepoWritable() {
		return false
	}
	self.authorized = true
	return true
}

// Step 7 for a group: the repo among the token's scopes whose GroupForms name it, and for a write whose newest
// GroupForm names it (§10.6's checks row), then AuthorizeRepo on that repo. A route whose body names its group calls
// this itself before it answers a success. false once it has answered the refusal.
func (self *GkmRequest) AuthorizeGroup(groupId sidecar.Id) bool {
	if groupId == (sidecar.Id{}) {
		self.BadRequest()
		return false
	}
	candidateRepoIds := self.scopes.reposWith(self.route.Scope.rights())
	repoId, found, err := self.engine.resolveGroup(self.Ctx, groupId, candidateRepoIds, self.route.Write)
	switch {
	case errors.Is(err, errGkmStoreFault):
		self.engine.alarm("form_invalid", err)
		self.Unavailable()
		return false
	case err != nil:
		self.Unavailable()
		return false
	case !found:
		self.Forbidden()
		return false
	}
	self.GroupId = &groupId
	return self.AuthorizeRepo(repoId)
}

// Whether repo/ is in a state the route's write takes (§10.6's checks row), read as each write issues, cached at
// most RepoCacheTtl. A handler calls this again right before each write it issues, so a write in flight at a shred
// lands before §11.12 repeats the group's deletion. false once it has answered the refusal.
func (self *GkmRequest) CheckRepoWritable() bool {
	object, err := self.engine.repos.read(self.Ctx, self.Cluster, self.RepoId)
	switch {
	case err == nil:
	case errors.Is(err, errGkmRepoNotFound):
		// a placed repo whose creation has not written repo/ yet: a retry finds it
		self.Unavailable()
		return false
	case errors.Is(err, errGkmStoreFault):
		self.engine.alarm("repo_invalid", err)
		self.Unavailable()
		return false
	default:
		self.Unavailable()
		return false
	}
	state := object.GetState()
	allowed := false
	switch self.route.RepoState {
	case gkmRepoStateAny:
		allowed = true
	case gkmRepoStateActive:
		allowed = state == protocol.EvsRepoState_EVS_REPO_ACTIVE
	case gkmRepoStateKeying:
		allowed = state == protocol.EvsRepoState_EVS_REPO_ACTIVE || state == protocol.EvsRepoState_EVS_REPO_KEYING
	case gkmRepoStateReseed:
		allowed = state == protocol.EvsRepoState_EVS_REPO_ACTIVE || state == protocol.EvsRepoState_EVS_REPO_KEYING ||
			state == protocol.EvsRepoState_EVS_REPO_DELETED && self.engine.host.GatesOrClosed().Reseed()
	}
	if !allowed {
		self.Forbidden()
		return false
	}
	return true
}

// Step 8: rev/ for the token's subjects. false once it has answered the refusal.
func (self *GkmRequest) checkRevocation() bool {
	err := self.engine.deps.AuthState.CheckRevocation(self.Ctx, self.Principal)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrGkmTokenRevoked):
		self.Unauthorized()
		return false
	}
	self.Unavailable()
	return false
}

// The repo among candidateRepoIds whose GroupForms tie groupId to it, examining at most GroupResolveRepoMaxCount of
// them: a repo whose newest form names the group, or for a read any of whose forms does. A group's repo, once a
// process has read it, never changes, so a token that does not scope it is refused with no read.
func (self *GkmEngine) resolveGroup(ctx context.Context, groupId sidecar.Id, candidateRepoIds []sidecar.Id, newestOnly bool) (sidecar.Id, bool, error) {
	// whether repoId's forms name the group as the request needs
	named := func(repoId sidecar.Id) (bool, error) {
		cluster, _, err := self.places.Cluster(ctx, repoId)
		if errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		forms, err := self.forms.forms(ctx, cluster, repoId)
		if err != nil {
			return false, err
		}
		if newestOnly {
			return 0 < len(forms) && forms[len(forms)-1].GroupId == groupId, nil
		}
		return slices.ContainsFunc(forms, func(form *gkmForm) bool { return form.GroupId == groupId }), nil
	}
	if repoId, ok := self.forms.groupRepo(groupId); ok {
		if !slices.Contains(candidateRepoIds, repoId) {
			return sidecar.Id{}, false, nil
		}
		found, err := named(repoId)
		return repoId, found, err
	}
	for i, repoId := range candidateRepoIds {
		if self.settings.GroupResolveRepoMaxCount <= i {
			break
		}
		found, err := named(repoId)
		if err != nil {
			return sidecar.Id{}, false, err
		}
		if found {
			return repoId, true, nil
		}
		if formRepoId, ok := self.forms.groupRepo(groupId); ok && formRepoId == repoId {
			// the repo's group, by a form that is no longer its newest: no write reaches it
			return repoId, false, nil
		}
	}
	return sidecar.Id{}, false, nil
}

// The body, at most maxByteCount and RequestBodyMaxByteCount. false once it has answered 400.
func (self *GkmRequest) ReadBody(maxByteCount int64) ([]byte, bool) {
	maxByteCount = min(maxByteCount, self.engine.settings.RequestBodyMaxByteCount)
	body, err := io.ReadAll(io.LimitReader(self.Http.Body, maxByteCount+1))
	self.requestByteCount += int64(len(body))
	if err != nil {
		self.Unavailable()
		return nil, false
	}
	if maxByteCount < int64(len(body)) {
		self.BadRequest()
		return nil, false
	}
	return body, true
}

// The body as message. false once it has answered 400.
func (self *GkmRequest) ReadMessage(message proto.Message, maxByteCount int64) bool {
	body, ok := self.ReadBody(maxByteCount)
	if !ok {
		return false
	}
	if err := proto.Unmarshal(body, message); err != nil {
		self.BadRequest()
		return false
	}
	return true
}

// 200 with message's bytes, or no body for nil.
func (self *GkmRequest) Reply(message proto.Message) {
	body := []byte{}
	if message != nil {
		var err error
		body, err = proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			self.Unavailable()
			return
		}
	}
	self.ReplyBytes(http.StatusOK, body)
}

// A success with body as it stands: a stored Signed or MLS bytes, which gkm serves byte for byte. A success
// before the route authorized its repo is a handler's bug: it fails closed with 503 and alarms.
func (self *GkmRequest) ReplyBytes(status int, body []byte) {
	if !self.authorized {
		self.engine.alarm("unauthorized_success", fmt.Errorf("%s answered %d before authorizing", self.route.Pattern, status))
		self.Unavailable()
		return
	}
	self.write(status, body)
}

// 201 with no body.
func (self *GkmRequest) Created() {
	self.ReplyBytes(http.StatusCreated, []byte{})
}

// 409 with the winner's bytes: another commit won the epoch (§10.6's one-commit row).
func (self *GkmRequest) Conflict(winner []byte) {
	self.write(http.StatusConflict, winner)
}

// 412 with the winner's bytes: a claim or delivery already holds the key (§10.6's claim and wrap checks).
func (self *GkmRequest) PreconditionFailed(winner []byte) {
	self.write(http.StatusPreconditionFailed, winner)
}

// 400: a body or path out of form.
func (self *GkmRequest) BadRequest() {
	self.write(http.StatusBadRequest, nil)
}

// 401: a token that does not authenticate, or one rev/ voids.
func (self *GkmRequest) Unauthorized() {
	self.write(http.StatusUnauthorized, nil)
}

// 403: out of scope, or a check refused it.
func (self *GkmRequest) Forbidden() {
	self.write(http.StatusForbidden, nil)
}

// 404: nothing is there.
func (self *GkmRequest) NotFound() {
	self.write(http.StatusNotFound, nil)
}

// 429 with Retry-After: a rate this process counts.
func (self *GkmRequest) TooManyRequests(retryAfter time.Duration) {
	self.retryAfter = retryAfter
	self.engine.metrics.rateLimited.Add(1, self.route.Pattern)
	self.write(http.StatusTooManyRequests, nil)
}

// 501: the route's handler has not landed (routes.go).
func (self *GkmRequest) NotBuilt() {
	self.write(http.StatusNotImplemented, nil)
}

// 503 with Retry-After, retryable: the store unreachable, the state not loaded, the gate closed or an outcome no
// read resolved.
func (self *GkmRequest) Unavailable() {
	self.write(http.StatusServiceUnavailable, nil)
}

// Writes the answer once. A 503 always carries Retry-After: a closed gate's interval, or UnavailableRetryAfter for a
// store or state that did not answer.
func (self *GkmRequest) write(status int, body []byte) {
	if self.answered {
		return
	}
	self.answered = true
	self.status = status
	self.replyByteCount = int64(len(body))
	header := self.Writer.Header()
	header.Set("Content-Type", gkmContentType)
	if status == http.StatusServiceUnavailable && self.retryAfter <= 0 {
		self.retryAfter = max(time.Second, self.engine.settings.UnavailableRetryAfter)
	}
	if 0 < self.retryAfter && (status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests) {
		header.Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(self.retryAfter.Seconds())))))
	}
	self.Writer.WriteHeader(status)
	if 0 < len(body) {
		self.Writer.Write(body)
	}
}

// Ends the request's budget admissions, counts the request and writes its gkm-9 line.
func (self *GkmRequest) finish() {
	if !self.answered {
		// a handler that answered nothing has failed closed
		self.Unavailable()
	}
	for _, release := range self.releases {
		release()
	}
	self.releases = nil
	entry := &GkmServiceLogEntry{
		Time:             self.started,
		Route:            self.route.Pattern,
		GroupId:          self.GroupId,
		RequestByteCount: self.requestByteCount,
		ReplyByteCount:   self.replyByteCount,
	}
	if self.Principal != nil {
		entry.ClientId = sidecar.Id(self.Principal.ClientId)
	}
	self.engine.serviceLog.Write(entry)
	self.engine.metrics.requests.Add(1, self.route.Pattern, strconv.Itoa(self.status))
	self.engine.metrics.seconds.Observe(self.engine.clock.Now().Sub(self.started).Seconds(), self.route.Pattern)
}

// One line of gkm-9's request log: "client, route, group, time, bytes", kept 7 days (§2.8), and nothing else, so
// no sidecar, member, repo or network id and no status rides it (I-13).
type GkmServiceLogEntry struct {
	Time     time.Time
	Route    string
	ClientId sidecar.Id
	// nil for a route on no group.
	GroupId          *sidecar.Id
	RequestByteCount int64
	ReplyByteCount   int64
}

// Where gkm-9's lines go: the host's log pipeline, which keeps them 7 days. Write never blocks a request on I/O of
// its own. Safe for concurrent use.
type GkmServiceLog interface {
	Write(entry *GkmServiceLogEntry)
}

// gkm-9 through a Logger, one Info line a request.
type loggerGkmServiceLog struct {
	log sidecar.Logger
}

// gkm-9's lines through log.
func NewLoggerGkmServiceLog(log sidecar.Logger) GkmServiceLog {
	return &loggerGkmServiceLog{log: log}
}

// One line: time, route, client, group and bytes.
func (self *loggerGkmServiceLog) Write(entry *GkmServiceLogEntry) {
	groupText := "-"
	if entry.GroupId != nil {
		groupText = sidecar.EvsKeyId(*entry.GroupId)
	}
	self.log.Infof("[gkm-9] %d %s client=%s group=%s in=%d out=%d",
		entry.Time.UnixMilli(), entry.Route, sidecar.EvsKeyId(entry.ClientId), groupText,
		entry.RequestByteCount, entry.ReplyByteCount)
}

// §19.8's gkm series. Labels come from closed sets: a route's pattern, a status, an alarm's or a hint's kind.
type gkmMetrics struct {
	requests     sidecar.MetricsCounter
	seconds      sidecar.MetricsHistogram
	gateClosed   sidecar.MetricsCounter
	rateLimited  sidecar.MetricsCounter
	alarms       sidecar.MetricsCounter
	hintsSent    sidecar.MetricsCounter
	hintsFailed  sidecar.MetricsCounter
	hintsDropped sidecar.MetricsCounter
	budgetShed   sidecar.MetricsCounter
	budgetP0     sidecar.MetricsCounter
}

// Declares the series.
func newGkmMetrics(metrics sidecar.Metrics) *gkmMetrics {
	return &gkmMetrics{
		requests:     metrics.Counter("urnetwork_gkm_requests_total", "gkm requests by route and status", "route", "status"),
		seconds:      metrics.Histogram("urnetwork_gkm_request_seconds", "gkm request time by route", nil, "route"),
		gateClosed:   metrics.Counter("urnetwork_gkm_gate_closed_total", "gkm requests the gate answered 503", "route"),
		rateLimited:  metrics.Counter("urnetwork_gkm_rate_limited_total", "gkm requests a per-process rate answered 429", "route"),
		alarms:       metrics.Counter("urnetwork_gkm_alarms_total", "gkm faults that alarm, by kind", "kind"),
		hintsSent:    metrics.Counter("urnetwork_gkm_hints_sent_total", "gkm hints sent, by kind", "kind"),
		hintsFailed:  metrics.Counter("urnetwork_gkm_hints_failed_total", "gkm hints whose send failed, by kind", "kind"),
		hintsDropped: metrics.Counter("urnetwork_gkm_hints_dropped_total", "gkm hints dropped unsent, by kind", "kind"),
		budgetShed:   metrics.Counter("urnetwork_gkm_budget_shed_total", "gkm P1 writes the write budget refused, by route", "route"),
		budgetP0:     metrics.Counter("urnetwork_gkm_budget_p0_total", "gkm write groups issued as P0, by kind", "kind"),
	}
}
