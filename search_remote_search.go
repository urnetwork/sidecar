//go:build !sidecar_http && !ios_extension

// One remote search on an app host (SEARCH-M10-33, SEARCH-M10-34; DESIGN-DETAILS 7.2.3, 7.2.4 and 7.2.6): its repos'
// states, its legs, the device's own search of its cache, the download its fallen-back repos take, and the merge of
// them all. search_remote_ask.go's header says what each state and leg does.
//
// A page (Next) is one step: at the first, the device's own first page and the plan's page 0 requests; at each later
// one, the next page of every idle leg, the device's own next page and the download's. The step then takes the legs'
// answers until no repo is asking and no page the app asked for is in flight, and answers the merged rows whose claims
// changed, in the merge's order. A leg still waiting on a page 0 whose repos the other own leg already won does not hold
// the step: its answer is taken at a later step, and dropped for those repos.
//
// The legs' calls run on goroutines of their own, which only hand their answers to the step; every state change is the
// step's, under the search's pageLock. Close ends every leg, dropping what is in flight; no Cancel is ever sent.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A repo's state in a search.
type searchRemoteRepoState int

const (
	searchRemoteRepoTodo searchRemoteRepoState = iota + 1
	searchRemoteRepoAsking
	searchRemoteRepoServed
	searchRemoteRepoFallback
)

// One repo of a search.
type searchRemoteRepo struct {
	repoId Id
	state  searchRemoteRepoState
	// the legs that name it and whose page 0 has not come
	asking map[*searchRemoteLeg]bool
	// the leg whose coverage won it
	servedBy *searchRemoteLeg
	// the indexers that failed it in this search
	tried map[Id]bool
	// a fallback's reason, or the last failure's; for a notice, the indexer it names
	reason string
	notice Id
	// the indexer it last fell back from, for seen again
	fellBackFrom Id
	// a download covers it
	streamed bool
	// some indexer was eligible for it, so its fallback reads fallback rather than nothing
	hadIndexer bool
}

// A leg's state.
type searchRemoteLegState int

const (
	searchRemoteLegWaiting searchRemoteLegState = iota + 1
	searchRemoteLegIdle
	searchRemoteLegDone
	searchRemoteLegEnded
)

// One search_id toward one indexer.
type searchRemoteLeg struct {
	indexerId Id
	searchId  uint64
	repos     []Id
	state     searchRemoteLegState
	// the page asked while waiting, the last that came while idle or done
	page uint32
	// the step waits for its answer: a page the app asked for, or a reopen of one
	holds   bool
	untilMs int64
	source  *searchRemoteSource
	served  map[Id]bool
	lost    map[Id]bool
	refs    map[Id]Id
	// the last page of status OK or PARTIAL: its checked_through_ms and phase
	checkedThroughMs int64
	phase            uint32
}

// One answer a leg's call came back with.
type searchRemoteLegEvent struct {
	leg  *searchRemoteLeg
	page uint32
	body []byte
	err  error
}

// One remote search. See the file header.
type searchRemoteSearch struct {
	client  *SearchRemoteClient
	request *SearchRequest
	ctx     context.Context
	cancel  context.CancelFunc
	selfId  Id
	scope   []Id
	// the wire's page 0 fields
	query   string
	filters *protocol.SearchFilters
	sinceMs int64
	untilMs int64

	pageLock    sync.Mutex
	started     bool
	repos       map[Id]*searchRemoteRepo
	legs        []*searchRemoteLeg
	events      chan *searchRemoteLegEvent
	merge       *searchRemoteMerge
	own         *SearchStream
	ownDone     bool
	progress    SearchProgress
	fallbacks   []*searchRemoteFallback
	firstPages  int
	reopens     int
	seenAgain   map[Id]int
	configN     uint64
	configChain [32]byte
	stateCount  uint64
	// what an opened hit's check reads: the query as this device's engine parses it
	parsed *SearchQuery

	stateLock sync.Mutex
	closed    bool
	// indexers other searches' mismatches distrusted, for this search's next step to void
	pendingDistrust []Id
}

// One download over repos no indexer answers.
type searchRemoteFallback struct {
	stream *SearchStream
	done   bool
}

// A remote search over request's scope, or nil where none of it can be asked remotely: a query or filters the wire
// cannot carry stay on the device (FallbackReason none).
func (self *SearchRemoteClient) newSearch(ctx context.Context, request *SearchRequest) (*searchRemoteSearch, error) {
	selfId, ok := self.args.SelfId()
	if !ok {
		return nil, nil
	}
	if self.wire.QueryMaxByteCount < len(request.Text) {
		return nil, nil
	}
	filters, ok := searchRemoteFiltersOf(request.Filters, self.wire)
	if !ok {
		return nil, nil
	}
	state, err := self.args.Config()
	if err != nil || state == nil {
		return nil, nil
	}
	scope := self.scopeOf(state, selfId, request)
	if len(scope) == 0 {
		return nil, nil
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, err
	}
	parsed, err := searchParseQuery(request.Text, normalizer)
	if err != nil {
		return nil, err
	}
	searchCtx, cancel := context.WithCancel(context.Background())
	search := &searchRemoteSearch{
		client: self, request: request, ctx: searchCtx, cancel: cancel, selfId: selfId, scope: scope, query: request.Text,
		filters: filters, repos: map[Id]*searchRemoteRepo{}, events: make(chan *searchRemoteLegEvent, 2*len(scope)+8),
		seenAgain: map[Id]int{}, parsed: parsed,
	}
	if !request.Since.IsZero() {
		search.sinceMs = request.Since.UnixMilli()
	}
	if !request.Until.IsZero() {
		search.untilMs = request.Until.UnixMilli()
	}
	for _, repoId := range scope {
		search.repos[repoId] = &searchRemoteRepo{repoId: repoId, state: searchRemoteRepoTodo, asking: map[*searchRemoteLeg]bool{}, tried: map[Id]bool{}}
	}
	search.merge = newSearchRemoteMerge(self.settings, self.ownIndexOf, self.maskedOf)
	local := *request
	local.Scope = SearchCached
	local.Remote = SearchRemoteOff
	local.Repos = slices.Clone(scope)
	own, err := self.args.Local.Search(ctx, &local)
	if err != nil {
		cancel()
		return nil, err
	}
	search.own = own
	_, search.stateCount, search.configN, search.configChain = search.marks()
	ended := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return true
		}
		self.searches[search] = true
		return false
	}()
	if ended {
		search.Close()
		return nil, ErrSidecarSearchUnavailable
	}
	return search, nil
}

// The repos a search covers, in its order: those it names, else every repo this device reads that remote search may
// name (vault, mailbox and the team kinds), by id.
func (self *SearchRemoteClient) scopeOf(state *ConfigState, selfId Id, request *SearchRequest) []Id {
	acl, err := state.Acl()
	if err != nil {
		return nil
	}
	reads := func(repoId Id) bool {
		repo := acl.Repo(repoId)
		if repo == nil {
			return false
		}
		if _, ok := searchRemoteKindOf(repo.GetKind()); !ok {
			return false
		}
		return slices.Contains(state.RepoReaders(repoId), selfId)
	}
	scope := []Id{}
	if 0 < len(request.Repos) {
		for _, repoId := range request.Repos {
			if !slices.Contains(scope, repoId) && reads(repoId) {
				scope = append(scope, repoId)
			}
		}
		return scope
	}
	for repoId := range acl.repos {
		if reads(repoId) {
			scope = append(scope, repoId)
		}
	}
	slices.SortFunc(scope, Id.Cmp)
	return scope
}

// The device's own index of a ref, as the merge reads it.
func (self *SearchRemoteClient) ownIndexOf(repoId Id, refId Id) (searchRemoteOwnIndex, bool) {
	if self.args.OwnIndex == nil {
		return searchRemoteOwnIndex{}, false
	}
	pin, companion, ring, ok := self.args.OwnIndex(repoId, refId)
	return searchRemoteOwnIndex{pin: pin, companion: companion, ring: ring}, ok
}

// Whether this device hides a version of a document, as the merge reads it.
func (self *SearchRemoteClient) maskedOf(key searchRemoteMergeKey, version uint64) bool {
	return self.args.Masked != nil && self.args.Masked(key.repoId, key.refId, key.docKey, version)
}

// What the step watches move: the mode, the search state's change count, and the config state's position.
func (self *searchRemoteSearch) marks() (string, uint64, uint64, [32]byte) {
	stateCount, _ := self.client.args.State.Changes()
	n, chain := uint64(0), [32]byte{}
	if state, err := self.client.args.Config(); err == nil && state != nil {
		n, chain = state.n, state.chain
	}
	return self.client.mode(), stateCount, n, chain
}

// Whether the search was closed.
func (self *searchRemoteSearch) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// The next page (SearchStreamSource). See the file header.
func (self *searchRemoteSearch) Next() ([]SearchHit, SearchProgress, bool, error) {
	self.pageLock.Lock()
	defer self.pageLock.Unlock()
	if self.isClosed() {
		return nil, self.progress, true, ErrSearchCursorExpired
	}
	touched := []searchRemoteMergeKey{}
	if !self.started {
		self.started = true
		ownTouched, err := self.ownPage()
		if err != nil {
			return nil, self.progress, false, err
		}
		touched = append(touched, ownTouched...)
		touched = append(touched, self.plan()...)
	} else {
		touched = append(touched, self.applyDistrust()...)
		touched = append(touched, self.recheck()...)
		for _, leg := range self.legs {
			if leg.state == searchRemoteLegIdle {
				self.ask(leg, leg.page+1, nil)
			}
		}
		if !self.ownDone {
			ownTouched, err := self.ownPage()
			if err != nil {
				return nil, self.progress, false, err
			}
			touched = append(touched, ownTouched...)
		}
		fallbackTouched, err := self.fallbackPages()
		if err != nil {
			return nil, self.progress, false, err
		}
		touched = append(touched, fallbackTouched...)
	}
	touched = append(touched, self.settle()...)
	opened, err := self.openFallbacks()
	if err != nil {
		return nil, self.progress, false, err
	}
	touched = append(touched, opened...)
	touched = append(touched, self.recheckPins()...)
	rows := self.merge.rows(touched)
	return rows, self.progressNow(), self.done(), nil
}

// The device's own next page: its claims, and its progress as the page's.
func (self *searchRemoteSearch) ownPage() ([]searchRemoteMergeKey, error) {
	hits, progress, done, err := self.own.Next()
	if err != nil && !errors.Is(err, ErrSearchCursorExpired) {
		return nil, err
	}
	self.progress = progress
	self.ownDone = done || err != nil
	return self.merge.add(nil, hits), nil
}

// Each download's next page, its claims the device's own.
func (self *searchRemoteSearch) fallbackPages() ([]searchRemoteMergeKey, error) {
	touched := []searchRemoteMergeKey{}
	for _, fallback := range self.fallbacks {
		if fallback.done {
			continue
		}
		hits, _, done, err := fallback.stream.Next()
		if err != nil && !errors.Is(err, ErrSearchCursorExpired) {
			return nil, err
		}
		fallback.done = done || err != nil
		touched = append(touched, self.merge.add(nil, hits)...)
	}
	return touched, nil
}

// Opens the download over the repos that fell back since the last, and takes its first page: "search more" on the
// device, under §18.4's metered rule and caps (SEARCH-M10-20).
func (self *searchRemoteSearch) openFallbacks() ([]searchRemoteMergeKey, error) {
	repoIds := []Id{}
	for _, repoId := range self.scope {
		repo := self.repos[repoId]
		if repo.state == searchRemoteRepoFallback && !repo.streamed {
			repo.streamed = true
			repoIds = append(repoIds, repoId)
		}
	}
	if len(repoIds) == 0 {
		return nil, nil
	}
	local := *self.request
	local.Scope = SearchAll
	local.Remote = SearchRemoteOff
	local.Repos = repoIds
	stream, err := self.client.args.Local.Search(self.ctx, &local)
	if err != nil {
		return nil, err
	}
	fallback := &searchRemoteFallback{stream: stream}
	self.fallbacks = append(self.fallbacks, fallback)
	hits, _, done, err := stream.Next()
	if err != nil && !errors.Is(err, ErrSearchCursorExpired) {
		return nil, err
	}
	fallback.done = done || err != nil
	return self.merge.add(nil, hits), nil
}

// Takes the legs' answers until no repo is asking and no page the step waits for is in flight.
func (self *searchRemoteSearch) settle() []searchRemoteMergeKey {
	touched := []searchRemoteMergeKey{}
	for self.holding() {
		select {
		case event := <-self.events:
			touched = append(touched, self.handle(event)...)
		case <-self.ctx.Done():
			return touched
		}
	}
	// answers that came meanwhile, a losing page 0 among them, without waiting
	for {
		select {
		case event := <-self.events:
			touched = append(touched, self.handle(event)...)
		default:
			return touched
		}
	}
}

// Whether the step still waits: a repo asking, or a page the app asked for in flight.
func (self *searchRemoteSearch) holding() bool {
	for _, repo := range self.repos {
		if repo.state == searchRemoteRepoAsking {
			return true
		}
	}
	for _, leg := range self.legs {
		if leg.state == searchRemoteLegWaiting && leg.holds {
			return true
		}
	}
	return false
}

// Whether no later page holds a hit: the device's own search and its downloads done, every leg done or ended, and every
// repo served or fallen back.
func (self *searchRemoteSearch) done() bool {
	if !self.ownDone {
		return false
	}
	for _, fallback := range self.fallbacks {
		if !fallback.done {
			return false
		}
	}
	for _, leg := range self.legs {
		if leg.state == searchRemoteLegWaiting || leg.state == searchRemoteLegIdle {
			return false
		}
	}
	for _, repo := range self.repos {
		if repo.state == searchRemoteRepoTodo || repo.state == searchRemoteRepoAsking {
			return false
		}
	}
	return true
}

// The plan over the repos in todo (search_remote_order.go): one reading of the config state, the mode and the answers,
// every request built from it, each through barrier search.remote.asked, then all sent in one step.
func (self *searchRemoteSearch) plan() []searchRemoteMergeKey {
	client := self.client
	todo := []Id{}
	for _, repoId := range self.scope {
		if self.repos[repoId].state == searchRemoteRepoTodo {
			todo = append(todo, repoId)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	view, err := client.orderView(self.scope)
	if err != nil {
		for _, repoId := range todo {
			repo := self.repos[repoId]
			repo.state, repo.reason = searchRemoteRepoFallback, SearchFallbackNone
		}
		return nil
	}
	now := client.clock.Now()
	// the repos each target takes, in the scope's order, at most RemoteRequesterCursorCount requests of RepoMaxCount
	// an indexer a search; past them a repo takes its next choice
	targetRepos := map[Id][]Id{}
	targets := []Id{}
	perIndexer := func(indexerId Id) int {
		count := len(targetRepos[indexerId])
		for _, leg := range self.legs {
			if leg.indexerId == indexerId {
				count += client.wire.RepoMaxCount
			}
		}
		return count
	}
	for _, repoId := range todo {
		repo := self.repos[repoId]
		for {
			assignment := client.assign(view, repoId, repo.tried, repo.reason, now)
			if 0 < len(client.eligibleFor(view, repoId)) {
				repo.hadIndexer = true
			}
			if len(assignment.targets) == 0 {
				repo.state, repo.reason, repo.notice = searchRemoteRepoFallback, assignment.fallback, assignment.notice
				if assignment.fallback == SearchFallbackNone {
					repo.reason = self.skipReason(view, repoId)
				}
				break
			}
			full := []Id{}
			for _, indexerId := range assignment.targets {
				if client.settings.RemoteRequesterCursorCount*client.wire.RepoMaxCount <= perIndexer(indexerId) {
					full = append(full, indexerId)
				}
			}
			if 0 < len(full) {
				for _, indexerId := range full {
					repo.tried[indexerId] = true
				}
				continue
			}
			for _, indexerId := range assignment.targets {
				if _, ok := targetRepos[indexerId]; !ok {
					targets = append(targets, indexerId)
				}
				targetRepos[indexerId] = append(targetRepos[indexerId], repoId)
			}
			repo.state = searchRemoteRepoAsking
			break
		}
	}
	// the requests of this reading, built then sent together
	legs := []*searchRemoteLeg{}
	for _, indexerId := range targets {
		repoIds := targetRepos[indexerId]
		for start := 0; start < len(repoIds); start += client.wire.RepoMaxCount {
			chunk := repoIds[start:min(start+client.wire.RepoMaxCount, len(repoIds))]
			leg := &searchRemoteLeg{
				indexerId: indexerId, searchId: searchRemoteNewSearchId(), repos: slices.Clone(chunk), untilMs: self.untilMs,
				served: map[Id]bool{}, lost: map[Id]bool{}, refs: map[Id]Id{},
			}
			for _, repoId := range chunk {
				self.repos[repoId].asking[leg] = true
			}
			legs = append(legs, leg)
		}
	}
	for _, leg := range legs {
		func() {
			client.stateLock.Lock()
			defer client.stateLock.Unlock()
			client.healthWithLock(leg.indexerId).tokens -= 1
		}()
		self.legs = append(self.legs, leg)
		self.ask(leg, 0, nil)
	}
	return nil
}

// The reason a repo with no indexer to ask falls back for: the skip of an eligible indexer, else none.
func (self *searchRemoteSearch) skipReason(view *searchRemoteOrderView, repoId Id) string {
	client := self.client
	client.stateLock.Lock()
	defer client.stateLock.Unlock()
	now := client.clock.Now()
	for _, indexerId := range view.eligible[repoId] {
		if health := client.health[indexerId]; health != nil && now.Before(health.skipUntil) && health.skipReason != "" {
			return health.skipReason
		}
	}
	return SearchFallbackNone
}

// Builds and sends page of leg: page 0's fields from the search (reopen narrowing until_ms), a later page's alone. The
// leg waits on it; its goroutine answers into the step.
func (self *searchRemoteSearch) ask(leg *searchRemoteLeg, page uint32, supersedes *uint64) {
	client := self.client
	request := &protocol.SearchRequest{SearchVersion: searchVersion, SearchId: leg.searchId, Page: page, Steps: 1}
	if page == 0 {
		previous := uint64(0)
		if supersedes != nil {
			previous = *supersedes
		}
		request.Supersedes = client.openAt(leg.indexerId, leg.searchId, previous)
		request.Scope = 2
		request.Query = self.query
		for _, repoId := range leg.repos {
			request.Repos = append(request.Repos, &protocol.SearchRepo{RepoId: repoId.Bytes()})
		}
		request.SinceMs = self.sinceMs
		request.UntilMs = leg.untilMs
		request.Filters = self.filters
		request.Fuzzy = self.request.Fuzzy
	}
	body, err := searchRemoteBuildRequest(request, client.wire)
	leg.state, leg.page, leg.holds = searchRemoteLegWaiting, page, 0 < page || leg.holds
	if err != nil {
		// within the caps no request fails to build; one that would is no request, and its leg fails
		go self.post(&searchRemoteLegEvent{leg: leg, page: page, err: err})
		return
	}
	testHookBarrier("search.remote.asked", leg.repos[0].String())
	timeout := client.remoteTimeout()
	attempts := 1
	if 0 < page {
		attempts += client.settings.RemotePageRetryCount
	}
	go func() {
		for attempt := 0; attempt < attempts; attempt += 1 {
			transport := client.currentTransport()
			if transport == nil {
				self.post(&searchRemoteLegEvent{leg: leg, page: page, err: errSearchRemoteNoTransport})
				return
			}
			answers := make(chan *searchRemoteLegEvent, 1)
			deadline := client.clock.After(timeout)
			go func() {
				answer, err := transport.Call(self.ctx, leg.indexerId, body)
				answers <- &searchRemoteLegEvent{leg: leg, page: page, body: answer, err: err}
			}()
			select {
			case event := <-answers:
				self.post(event)
				return
			case <-deadline:
			case <-self.ctx.Done():
				return
			}
		}
		self.post(&searchRemoteLegEvent{leg: leg, page: page, err: errSearchRemoteTimeout})
	}()
}

// Hands an answer to the step, unless the search ended.
func (self *searchRemoteSearch) post(event *searchRemoteLegEvent) {
	select {
	case self.events <- event:
	case <-self.ctx.Done():
	}
}

// One answer: a reply taken only by the leg and page that wait for it, after Z8's checks; anything else is no reply.
func (self *searchRemoteSearch) handle(event *searchRemoteLegEvent) []searchRemoteMergeKey {
	leg := event.leg
	if leg.state != searchRemoteLegWaiting || leg.page != event.page {
		// ended, superseded or abandoned: dropped
		return nil
	}
	if event.err != nil {
		return self.failOnError(leg, event.err)
	}
	client := self.client
	reply, ok := searchRemoteParseReply(event.body, 1, leg.searchId, event.page, client.wire)
	if !ok {
		return self.fail(leg, SearchFallbackUnreachable, 0)
	}
	switch protocol.SearchStatus(reply.GetStatus()) {
	case protocol.SearchStatus_SEARCH_OK, protocol.SearchStatus_SEARCH_PARTIAL, protocol.SearchStatus_SEARCH_TOO_BROAD:
	case protocol.SearchStatus_SEARCH_CURSOR_EXPIRED:
		if 0 < event.page && self.reopens < client.settings.RemoteReopenCount {
			return self.reopen(leg)
		}
		return self.fail(leg, SearchFallbackUnreachable, 0)
	case protocol.SearchStatus_SEARCH_INVALID, protocol.SearchStatus_SEARCH_UNSUPPORTED_VERSION:
		return self.fail(leg, SearchFallbackRefused, 0)
	default:
		return self.fail(leg, SearchFallbackUnreachable, 0)
	}
	now := client.clock.Now()
	func() {
		client.stateLock.Lock()
		defer client.stateLock.Unlock()
		health := client.healthWithLock(leg.indexerId)
		health.answeredAt = now
		health.onlineUntil = now.Add(client.settings.RemoteOnlineTimeout)
	}()
	touched := []searchRemoteMergeKey{}
	if event.page == 0 {
		var ok bool
		touched, ok = self.pageZero(leg, reply)
		if !ok {
			return append(touched, self.fail(leg, SearchFallbackUnreachable, 0)...)
		}
	}
	// the hits of the repos this leg serves and has not lost; another repo's is a mismatch, a lost one's is dropped
	hits := []SearchHit{}
	name := client.deviceName(leg.indexerId)
	for _, wireHit := range reply.GetHits() {
		repoId, err := IdFromBytes(wireHit.GetRepoId())
		switch {
		case err != nil:
			continue
		case leg.lost[repoId]:
			continue
		case !leg.served[repoId]:
			touched = append(touched, client.mismatch(self, leg.indexerId, repoId)...)
			continue
		}
		if hit, ok := searchRemoteHitOfWire(wireHit, name); ok {
			hits = append(hits, hit)
		}
	}
	if leg.state == searchRemoteLegEnded {
		// a leg that serves nothing: its hits of repos it lost are dropped, of any other counted above
		return append(touched, self.plan()...)
	}
	if !leg.source.void {
		touched = append(touched, self.merge.add(leg.source, hits)...)
	}
	status := protocol.SearchStatus(reply.GetStatus())
	if status == protocol.SearchStatus_SEARCH_OK || status == protocol.SearchStatus_SEARCH_PARTIAL {
		leg.checkedThroughMs, leg.phase = reply.GetCheckedThroughMs(), reply.GetPhase()
		servedRepos := []Id{}
		for repoId := range leg.served {
			if !leg.lost[repoId] {
				servedRepos = append(servedRepos, repoId)
			}
		}
		touched = append(touched, self.merge.moveSpan(leg.source, servedRepos, reply.GetCheckedThroughMs())...)
	}
	leg.state, leg.holds = searchRemoteLegIdle, false
	if reply.GetComplete() || status == protocol.SearchStatus_SEARCH_TOO_BROAD {
		leg.state = searchRemoteLegDone
		client.unwant(leg.indexerId, leg.searchId)
		touched = append(touched, self.raiseOmissions(leg)...)
	}
	return touched
}

// Page 0's coverage: each row names a repo of the leg once, and every repo of the leg has one, else false; a served row
// wins its repo unless another leg won it first; a refusal sends the repo on. A leg that serves nothing is ended.
func (self *searchRemoteSearch) pageZero(leg *searchRemoteLeg, reply *protocol.SearchReply) ([]searchRemoteMergeKey, bool) {
	client := self.client
	rows := map[Id]*protocol.SearchCoverage{}
	for _, row := range reply.GetCoverage() {
		repoId, err := IdFromBytes(row.GetRepoId())
		if err != nil || !slices.Contains(leg.repos, repoId) || rows[repoId] != nil {
			return nil, false
		}
		rows[repoId] = row
	}
	if len(rows) != len(leg.repos) {
		return nil, false
	}
	leg.source = self.merge.newSource(leg.indexerId, client.deviceName(leg.indexerId), self.firstPages)
	self.firstPages += 1
	now := client.clock.Now()
	touched := []searchRemoteMergeKey{}
	for _, repoId := range leg.repos {
		row, repo := rows[repoId], self.repos[repoId]
		delete(repo.asking, leg)
		served := protocol.SearchServed(row.GetServed())
		if !searchRemoteServes(served) {
			func() {
				client.stateLock.Lock()
				defer client.stateLock.Unlock()
				client.healthWithLock(leg.indexerId).refusedUntil[repoId] = now.Add(client.settings.RemoteRefusedTimeout)
			}()
			repo.tried[leg.indexerId] = true
			repo.reason, repo.fellBackFrom = SearchFallbackRefused, leg.indexerId
			if len(repo.asking) == 0 && repo.servedBy == nil && repo.state == searchRemoteRepoAsking {
				repo.state = searchRemoteRepoTodo
			}
			continue
		}
		if repo.servedBy != nil || repo.state != searchRemoteRepoAsking {
			// the other own leg won it: this leg's hits of it are dropped on every page
			leg.lost[repoId] = true
			continue
		}
		repo.servedBy, repo.state = leg, searchRemoteRepoServed
		// the other leg still waiting on it no longer holds it
		for other := range repo.asking {
			delete(repo.asking, other)
		}
		leg.served[repoId] = true
		refId, err := IdFromBytes(row.GetRefId())
		if err != nil {
			refId = Id{}
		}
		leg.refs[repoId] = refId
		if err := client.args.State.NoteServed(leg.indexerId, repoId); err != nil && client.log.V(1).Enabled() {
			client.log.Infof("[search]the served memory was not written: %s", err)
		}
		leg.source.spans[repoId] = &searchRemoteSpan{
			text: served == protocol.SearchServed_SERVED_TEXT, uncovered: row.GetUncovered(), untilMs: leg.untilMs,
			pinVersion: row.GetRefVersion(), pinChain: row.GetChain(), refTimeMs: row.GetRefTimeMs(),
		}
		forked, waiting := self.merge.checkPin(leg.source, repoId, refId)
		switch {
		case forked:
			touched = append(touched, self.fork(leg, repoId)...)
		case waiting:
			self.merge.waitPin(leg.source, repoId, refId)
		}
	}
	if len(leg.served) == 0 || len(leg.served) == len(leg.lost) {
		// a leg that serves no repo is abandoned
		leg.state = searchRemoteLegEnded
		client.unwant(leg.indexerId, leg.searchId)
	}
	return touched, true
}

// A coverage pin that forks from this device's chain: §6.4's head_alarm fork naming the indexer, the leg void for the
// repo, and the repo to the next eligible indexer.
func (self *searchRemoteSearch) fork(leg *searchRemoteLeg, repoId Id) []searchRemoteMergeKey {
	indexerId := leg.indexerId
	self.client.raise(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork, SidecarId: &indexerId, RepoId: &repoId})
	touched := self.merge.voidRepo(leg.source, repoId)
	repo := self.repos[repoId]
	if repo.servedBy == leg {
		repo.servedBy = nil
		repo.state = searchRemoteRepoTodo
		repo.tried[indexerId] = true
		repo.reason, repo.fellBackFrom = SearchFallbackUnreachable, indexerId
	}
	delete(leg.served, repoId)
	return touched
}

// The waiting pins a replay has reached since: a fork alarms and voids as at page 0.
func (self *searchRemoteSearch) recheckPins() []searchRemoteMergeKey {
	touched := []searchRemoteMergeKey{}
	for _, wait := range self.merge.recheckPins() {
		for _, leg := range self.legs {
			if leg.source == wait.source {
				touched = append(touched, self.fork(leg, wait.repoId)...)
			}
		}
	}
	if 0 < len(touched) {
		touched = append(touched, self.plan()...)
	}
	return touched
}

// A failure the transport answered: a timeout reads offline; RESOURCE_EXHAUSTED busy, skipped at least its
// retry_after_ms; the identity binding or bit 0 failing alarms and drops the indexer; PERMISSION_DENIED and
// UNIMPLEMENTED refused; a lost session offline; anything else unreachable.
func (self *searchRemoteSearch) failOnError(leg *searchRemoteLeg, err error) []searchRemoteMergeKey {
	client := self.client
	if errors.Is(err, errSearchRemoteAuth) {
		indexerId := leg.indexerId
		client.raise(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmUnverified, SidecarId: &indexerId})
		if state, stateErr := client.args.Config(); stateErr == nil && state != nil {
			func() {
				client.stateLock.Lock()
				defer client.stateLock.Unlock()
				health := client.healthWithLock(indexerId)
				health.dropped, health.droppedAs = true, searchRemoteDropMark(state, indexerId)
			}()
		}
		return self.fail(leg, SearchFallbackUnreachable, 0)
	}
	if errors.Is(err, errSearchRemoteTimeout) || errors.Is(err, errSearchRemoteNoTransport) {
		return self.fail(leg, SearchFallbackOffline, 0)
	}
	var subprotocolError *SubprotocolError
	if errors.As(err, &subprotocolError) {
		switch subprotocolError.Code {
		case protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED:
			return self.fail(leg, SearchFallbackBusy, subprotocolError.RetryAfter)
		case protocol.ErrorCode_ERR_PERMISSION_DENIED, protocol.ErrorCode_ERR_UNIMPLEMENTED:
			return self.fail(leg, SearchFallbackRefused, 0)
		case protocol.ErrorCode_ERR_UNAVAILABLE, protocol.ErrorCode_ERR_DEADLINE_EXCEEDED:
			return self.fail(leg, SearchFallbackOffline, 0)
		}
	}
	return self.fail(leg, SearchFallbackUnreachable, 0)
}

// A leg's failure: the indexer skipped RemoteSkipTimeout or retryAfter, whichever is later; the leg ended; each repo it
// asked or served back to the plan with the indexer tried, unless another leg still asks for it; the plan runs.
func (self *searchRemoteSearch) fail(leg *searchRemoteLeg, reason string, retryAfter time.Duration) []searchRemoteMergeKey {
	client := self.client
	now := client.clock.Now()
	func() {
		client.stateLock.Lock()
		defer client.stateLock.Unlock()
		health := client.healthWithLock(leg.indexerId)
		until := now.Add(max(client.settings.RemoteSkipTimeout, retryAfter))
		if health.skipUntil.Before(until) {
			health.skipUntil = until
		}
		health.skippedAt, health.skipReason = now, reason
	}()
	self.endLeg(leg, reason, true)
	return self.plan()
}

// Ends leg, its repos back to the plan; tried marks its indexer as failing them.
func (self *searchRemoteSearch) endLeg(leg *searchRemoteLeg, reason string, tried bool) {
	leg.state, leg.holds = searchRemoteLegEnded, false
	self.client.unwant(leg.indexerId, leg.searchId)
	for _, repoId := range leg.repos {
		repo := self.repos[repoId]
		wasAsking := repo.asking[leg]
		delete(repo.asking, leg)
		if repo.servedBy != leg && !wasAsking {
			continue
		}
		if tried {
			repo.tried[leg.indexerId] = true
		}
		repo.reason, repo.fellBackFrom = reason, leg.indexerId
		if repo.servedBy == leg {
			repo.servedBy = nil
		}
		switch {
		case 0 < len(repo.asking):
			repo.state = searchRemoteRepoAsking
		case repo.state != searchRemoteRepoFallback:
			repo.state = searchRemoteRepoTodo
		}
	}
}

// CURSOR_EXPIRED on a later page, once a search: a new leg superseding the old over the repos it still serves, resumed
// from the last checked_through_ms of a phase 1 or 2 page. The old leg's claims and span stay.
func (self *searchRemoteSearch) reopen(leg *searchRemoteLeg) []searchRemoteMergeKey {
	self.reopens += 1
	repos := []Id{}
	for _, repoId := range leg.repos {
		if leg.served[repoId] && !leg.lost[repoId] && self.repos[repoId].servedBy == leg {
			repos = append(repos, repoId)
		}
	}
	leg.state, leg.holds = searchRemoteLegEnded, false
	if len(repos) == 0 {
		return nil
	}
	reopened := &searchRemoteLeg{
		indexerId: leg.indexerId, searchId: searchRemoteNewSearchId(), repos: repos, untilMs: leg.untilMs, holds: true,
		served: map[Id]bool{}, lost: map[Id]bool{}, refs: map[Id]Id{},
	}
	if (leg.phase == 1 || leg.phase == 2) && 0 < leg.checkedThroughMs && (reopened.untilMs == 0 || leg.checkedThroughMs < reopened.untilMs) {
		reopened.untilMs = leg.checkedThroughMs
	}
	for _, repoId := range repos {
		repo := self.repos[repoId]
		repo.servedBy, repo.state = nil, searchRemoteRepoAsking
		repo.asking[reopened] = true
	}
	self.legs = append(self.legs, reopened)
	supersedes := leg.searchId
	self.ask(reopened, 0, &supersedes)
	return nil
}

// The step's checks before it asks more (DESIGN-DETAILS 7.2.4): where the config state, the mode or the answers moved,
// every open leg judged again, one that may no longer be asked about a repo ended with no skip, and the repos that fell
// back planned again; and each skipped indexer seen again since, its repos that fell back from it planned again once.
func (self *searchRemoteSearch) recheck() []searchRemoteMergeKey {
	client := self.client
	_, stateCount, n, chain := self.marks()
	moved := stateCount != self.stateCount || n != self.configN || chain != self.configChain
	self.stateCount, self.configN, self.configChain = stateCount, n, chain
	if moved {
		view, err := client.orderView(self.scope)
		for _, leg := range self.legs {
			if leg.state != searchRemoteLegWaiting && leg.state != searchRemoteLegIdle {
				continue
			}
			if err != nil || !self.mayAsk(view, leg) {
				self.endLeg(leg, SearchFallbackRefused, false)
			}
		}
		for _, repoId := range self.scope {
			if repo := self.repos[repoId]; repo.state == searchRemoteRepoFallback {
				repo.state = searchRemoteRepoTodo
			}
		}
	}
	if transport := client.currentTransport(); transport != nil {
		now := client.clock.Now()
		for _, repoId := range self.scope {
			repo := self.repos[repoId]
			indexerId := repo.fellBackFrom
			if repo.state != searchRemoteRepoFallback || indexerId == (Id{}) || client.settings.RemoteSeenAgainCount <= self.seenAgain[indexerId] {
				continue
			}
			if repo.reason != SearchFallbackOffline && repo.reason != SearchFallbackBusy && repo.reason != SearchFallbackUnreachable {
				continue
			}
			skippedAt := func() time.Time {
				client.stateLock.Lock()
				defer client.stateLock.Unlock()
				return client.healthWithLock(indexerId).skippedAt
			}()
			if !transport.SeenSince(indexerId, skippedAt) {
				continue
			}
			func() {
				client.stateLock.Lock()
				defer client.stateLock.Unlock()
				health := client.healthWithLock(indexerId)
				health.skipUntil = now
				health.onlineUntil = now.Add(client.settings.RemoteOnlineTimeout)
			}()
			self.seenAgain[indexerId] += 1
			for _, otherId := range self.scope {
				other := self.repos[otherId]
				if other.state == searchRemoteRepoFallback && other.fellBackFrom == indexerId {
					delete(other.tried, indexerId)
					other.state = searchRemoteRepoTodo
				}
			}
		}
	}
	return self.plan()
}

// Whether the view still lets leg's indexer be asked about every repo it asks or serves: E1 to E6, and own or, in mode
// on, its notice member's answer allowing.
func (self *searchRemoteSearch) mayAsk(view *searchRemoteOrderView, leg *searchRemoteLeg) bool {
	client := self.client
	if view.mode == SearchRemoteOff {
		return false
	}
	if !searchRemoteOwn(view.state, leg.indexerId, view.selfId) {
		if view.mode != SearchRemoteOn {
			return false
		}
		memberId, ok := searchRemoteNoticeMember(view.state, leg.indexerId)
		if !ok {
			return false
		}
		if allow, answered := client.answer(memberId); !answered || !allow {
			return false
		}
	}
	for _, repoId := range leg.repos {
		if leg.lost[repoId] {
			continue
		}
		if !slices.Contains(client.eligibleFor(view, repoId), leg.indexerId) {
			return false
		}
	}
	return true
}

// The progress a page carries: the device's own search's, with the remote state, fallback reason and indexer (DESIGN-
// DETAILS 7.2.4's table).
func (self *searchRemoteSearch) progressNow() SearchProgress {
	progress := self.progress
	served := map[Id]int{}
	servedCount, noticeCount, asking, hadIndexer := 0, 0, false, false
	reason, notice := "", Id{}
	for _, repoId := range self.scope {
		repo := self.repos[repoId]
		hadIndexer = hadIndexer || repo.hadIndexer
		switch repo.state {
		case searchRemoteRepoAsking, searchRemoteRepoTodo:
			asking = true
		case searchRemoteRepoServed:
			servedCount += 1
			served[repo.servedBy.indexerId] += 1
		case searchRemoteRepoFallback:
			if reason == "" {
				reason = repo.reason
			}
			if repo.reason == SearchFallbackNotice {
				noticeCount += 1
				if notice == (Id{}) {
					notice = repo.notice
				}
			}
		}
	}
	// asking reads the repos: a losing own leg still waiting on its page 0 holds no repo, so it asks nothing the person
	// waits on (a reading of 7.2.4's "while any leg waits for page 0")
	switch {
	case self.client.mode() == SearchRemoteOff:
		progress.Remote = SearchRemoteStateOff
	case asking:
		progress.Remote = SearchRemoteStateAsking
	case 0 < noticeCount && servedCount == 0:
		progress.Remote = SearchRemoteStateNotice
	case servedCount == len(self.scope):
		progress.Remote = SearchRemoteStateAnswered
	case 0 < servedCount:
		progress.Remote = SearchRemoteStatePartial
	case hadIndexer:
		progress.Remote = SearchRemoteStateFallback
	default:
		progress.Remote = ""
	}
	progress.FallbackReason = reason
	progress.RemoteBy = nil
	most := 0
	for _, leg := range self.legs {
		if count := served[leg.indexerId]; most < count {
			indexerId := leg.indexerId
			progress.RemoteBy, most = &indexerId, count
		}
	}
	if progress.RemoteBy == nil && notice != (Id{}) {
		progress.RemoteBy = &notice
	}
	return progress
}

// Ends the search: every leg ended with what is in flight dropped, the device's own search and downloads closed. No
// Cancel is sent; the cursors left at indexers idle out or are superseded. Safe to call again.
func (self *searchRemoteSearch) Close() {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		return true
	}()
	if !closed {
		return
	}
	self.cancel()
	self.pageLock.Lock()
	for _, leg := range self.legs {
		self.client.unwant(leg.indexerId, leg.searchId)
		leg.state = searchRemoteLegEnded
	}
	own, fallbacks := self.own, self.fallbacks
	self.pageLock.Unlock()
	if own != nil {
		own.Close()
	}
	for _, fallback := range fallbacks {
		fallback.stream.Close()
	}
	self.client.stateLock.Lock()
	delete(self.client.searches, self)
	self.client.stateLock.Unlock()
}

// A reply's hit as §5.4's, labelled with its indexer; false for a state this build does not know, which claims nothing.
func searchRemoteHitOfWire(hit *protocol.SearchHit, by string) (SearchHit, bool) {
	state := SearchHitState(hit.GetState())
	if state < SearchVerified || SearchNear < state {
		return SearchHit{}, false
	}
	repoId, repoErr := IdFromBytes(hit.GetRepoId())
	refId, refErr := IdFromBytes(hit.GetRefId())
	if repoErr != nil || refErr != nil || len(hit.GetDocKey()) != len(Id{}) {
		return SearchHit{}, false
	}
	result := SearchHit{
		Repo: repoId, Ref: refId, Path: hit.GetLocator(), Version: hit.GetVersion(), Time: time.UnixMilli(hit.GetTimeMs()).UTC(),
		Snippet: hit.GetSnippet(), State: state, Correction: hit.GetCorrection(), By: by, DocKey: [16]byte(hit.GetDocKey()),
		DocKind: int(hit.GetDocKind()), Partition: SearchPartitionLatest,
	}
	if hit.GetPartition() == 4 {
		result.Partition = SearchPartitionAll
	}
	if signer, err := IdFromBytes(hit.GetSigner()); err == nil {
		result.Signer = signer
	}
	for _, field := range hit.GetFields() {
		result.Fields = append(result.Fields, SearchField{Field: int(field.GetField()), Text: field.GetText()})
	}
	return result, true
}
