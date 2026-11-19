//go:build !ios_extension

// The search engine (§16.10; §5.4's SearchEngine beneath Sidecar.Search; R-MCP-12, R-MCP-14, R-CORE-18, D-ACL-14,
// D-MCP-18, D-MCP-20, D-MCP-21, D-MCP-25, D-SDK-22, FI-21, FI-23, I-13, I-19, FS-80; DESIGN-DETAILS 7.7;
// SEARCH-M10-26): one network's search over the index cache, one engine a network, on every leg but the forwarding
// one. It implements CORE-M10-03's SidecarSearchEngine, its background window and its cache dropper.
//
//	call      a search resolves its scope (search_scope.go), takes each ref's snapshot from the sync engine, which
//	          freezes the files it reads until the search ends, plans each ref (search_plan.go) and pages phase 1,
//	          then phase 2 (search_phase.go); a page is ranked lazily, masked and confirmed as far as it goes
//	          (search_rank.go), within Search.PageCpu, Search.PageCandidateCount and Search.PageByteCount
//	scope     SearchCached reads the buckets and all where the snapshot holds it usable; SearchLatest the buckets;
//	          SearchAll the buckets, then every all shard, fetching what is missing by "search more"
//	          (search_more.go), whose fixed order reads nothing of the query, a metered fetch past 25 MiB waiting on
//	          AllowMetered; the download runs in a window beside the pages (search_engine_more.go), and a page
//	          answers as soon as it holds a hit rather than waiting on it, so each landed shard's hits reach the
//	          caller within §16.10's arrival bound while what is fetched, and when, stays the sync state's (QD-999)
//	sessions  SearchIn takes the caller's session, for its counts, rate and cursors (search_limits.go,
//	          search_cursor.go); Search runs in the daemon's own session
//	never     a search reads only the cache, never evs, api or gkm but for RK_g to open kept records, and writes
//	          nothing to evs but the read receipts the sync's rounds deposit; queries, hits, snippets and cursors are
//	          never logged or persisted (I-13, R-CORE-18); a repo this sidecar cannot read is never listed; this
//	          file names no connect type, since it links on sidecar_http
//
// Remote search (SEARCH-M10-33) asks an indexer beside this; a request's Remote is CORE's to resolve, and this engine
// answers locally whatever it says. Mail's joins (search_join.go) leave out a mail hit the device knows to be spam or
// trash, unless asked, from what it already holds. Phase 1's near hits are a phone's one-edit variants probed in the partitions
// (search_typo.go); a desktop's local vocabulary is not given yet. Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
)

// An engine built without what every search reads.
var errSearchEngineArgs = errors.New("search engine without its settings, cache, sync, scope or gkm")

// What an engine runs on.
type SearchEngineArgs struct {
	Settings *SidecarSearchSettings
	// Nil takes DefaultSearchResultSettings and DefaultIndexFormatSettings.
	Results *SearchResultSettings
	Format  *IndexFormatSettings
	// search_agents' and grouping's bounds (search_group.go); nil takes DefaultSearchGroupSettings.
	Groups *SearchGroupSettings
	// The sidecars whose rows a member filter matches as their writer: the member's devices and the tagged sidecars it
	// sponsors, at the newest verified state. Nil, and a member it names no sidecar of, match no row.
	Members func(memberId Id) []Id
	Cache   *SearchCache
	Sync    *SearchSync
	// §18.4's policy, which "search more" and the background window follow. Nil fetches nothing: SearchAll then reads
	// all as held, coverage saying what it lacks.
	Policy *SearchPolicy
	Scope  SearchScopeSource
	// RK_g for the kept records a search opens (QD-838).
	Gkm GkmClient
	// A host's plaintext and display fields of a ref, nil where it holds none: a desktop's mirror, a mounted tree, mail's
	// i/ (search_text_source.go).
	Text    func(repoId Id, refId Id) SearchTextSource
	Display func(repoId Id, refId Id) SearchDisplaySource
	// This host's local layer of a ref (search_local_layer.go), nil where it keeps none.
	Local func(repoId Id, refId Id) *SearchLocalLayer
	// Mail's joins (search_join.go): a mail hit's flags from what the device holds of f/ and i/, which leave out spam
	// and trash unless asked. Nil joins nothing, and every mail hit shows.
	Join SearchJoinSource
	// index_malformed's sink (Sidecar.searchEvents); nil drops.
	Events func(event SidecarEvent)
	// Nil is real time.
	Clock Clock
	Log   Logger
}

// One network's search engine.
type SearchEngine struct {
	args       SearchEngineArgs
	results    *SearchResultSettings
	format     *IndexFormatSettings
	groups     *SearchGroupSettings
	clock      Clock
	log        Logger
	limits     *searchLimits
	cursors    *searchCursorTable
	background *SearchBackground

	stateLock sync.Mutex
	streams   map[*searchEngineStream]bool
	closed    bool
}

// An engine over args.
func NewSearchEngine(args *SearchEngineArgs) (*SearchEngine, error) {
	if args == nil || args.Settings == nil || args.Cache == nil || args.Sync == nil || args.Scope == nil || args.Gkm == nil {
		return nil, errSearchEngineArgs
	}
	settings := args.Settings
	if settings.DaemonSearchCount <= 0 || settings.SessionSearchCount <= 0 || settings.SessionCursorCount <= 0 ||
		settings.PageCpu <= 0 || settings.PageCandidateCount <= 0 || settings.TooBroadCandidateCount <= 0 ||
		settings.PageByteCount <= 0 || settings.PageHitCount <= 0 || settings.CursorTimeout <= 0 ||
		settings.SessionSearchRate.Count <= 0 || settings.SessionSearchRate.Burst <= 0 || settings.SessionSearchRate.Interval <= 0 {
		return nil, fmt.Errorf("%w: the search engine's limits", errInvalidSettings)
	}
	results := args.Results
	if results == nil {
		results = DefaultSearchResultSettings()
	}
	if err := results.check(); err != nil {
		return nil, err
	}
	format := args.Format
	if format == nil {
		format = DefaultIndexFormatSettings()
	}
	groups := args.Groups
	if groups == nil {
		groups = DefaultSearchGroupSettings()
	}
	if err := groups.check(); err != nil {
		return nil, err
	}
	clock := clockOrReal(args.Clock)
	cursors, err := newSearchCursorTable(settings, clock)
	if err != nil {
		return nil, err
	}
	engine := &SearchEngine{
		args: *args, results: results, format: format, groups: groups, clock: clock, log: loggerOrDefault(args.Log),
		limits: newSearchLimits(settings, clock), cursors: cursors, streams: map[*searchEngineStream]bool{},
	}
	if args.Policy != nil {
		if engine.background, err = NewSearchBackground(args.Sync, args.Policy, args.Cache); err != nil {
			return nil, err
		}
	}
	return engine, nil
}

// Raises a search event through the engine's sink.
func (self *SearchEngine) raise(event SidecarEvent) {
	if self.args.Events != nil {
		self.args.Events(event)
	}
}

// One search in the daemon's own session (SidecarSearchEngine).
func (self *SearchEngine) Search(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
	stream, _, err := self.SearchIn(ctx, searchLocalSession, request)
	return stream, err
}

// One search in session: the stream, and the cursor token that resumes it in that session alone. Waits for its
// admission until ctx ends (wait_ms), then ErrSearchBusy.
func (self *SearchEngine) SearchIn(ctx context.Context, session Id, request *SearchRequest) (*SearchStream, string, error) {
	stream, token, err := self.open(ctx, session, request)
	if err != nil {
		return nil, "", err
	}
	return NewSearchStream(stream), token, nil
}

// SearchIn's search as the engine's own callers page it (the search tools, search_agents): its stream and cursor
// token.
func (self *SearchEngine) open(ctx context.Context, session Id, request *SearchRequest) (*searchEngineStream, string, error) {
	if request == nil || request.PageSize < 0 {
		return nil, "", ErrSearchRequest
	}
	if request.Scope != SearchCached && request.Scope != SearchLatest && request.Scope != SearchAll {
		return nil, "", fmt.Errorf("%w: scope %d", ErrSearchRequest, request.Scope)
	}
	release, err := self.limits.admit(ctx, session, true)
	if err != nil {
		return nil, "", err
	}
	defer release()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, "", err
	}
	query, err := searchParseQuery(request.Text, normalizer)
	if err != nil {
		return nil, "", err
	}
	if query.Empty() && len(request.Filters) == 0 {
		return nil, "", fmt.Errorf("%w: a query or a filter", ErrSearchRequest)
	}
	filters, err := searchRowFiltersOf(request, normalizer, self.args.Members)
	if err != nil {
		return nil, "", err
	}
	repos, err := self.args.Scope.Repos(ctx)
	if err != nil {
		return nil, "", err
	}
	scoped, excluded := searchResolveScope(repos, request)
	kept := *request
	kept.Repos = slices.Clone(request.Repos)
	kept.Filters = slices.Clone(request.Filters)
	if kept.PageSize == 0 {
		kept.PageSize = self.args.Settings.PageHitCount
	}
	lifetime, endLifetime := context.WithCancel(context.Background())
	stream := &searchEngineStream{
		engine: self, session: session, request: &kept, query: query, filters: filters, normalizer: normalizer,
		excluded: excluded, joinAsk: searchJoinAskOf(&kept), more: newSearchEngineMore(), lifetime: lifetime,
		endLifetime: endLifetime,
	}
	if err := stream.open(ctx, scoped); err != nil {
		stream.Close()
		return nil, "", err
	}
	self.stateLock.Lock()
	if self.closed {
		self.stateLock.Unlock()
		stream.Close()
		return nil, "", ErrSidecarSearchUnavailable
	}
	self.streams[stream] = true
	self.stateLock.Unlock()
	token, err := self.cursors.open(session, stream)
	if err != nil {
		stream.Close()
		return nil, "", err
	}
	return stream, token, nil
}

// The stream of session's cursor token, to page on: ErrSearchCursorInvalid for a token the session cannot hold,
// ErrSearchCursorExpired for one that ended.
func (self *SearchEngine) Resume(session Id, token string) (*SearchStream, error) {
	self.cursors.sweep()
	stream, err := self.cursors.take(session, token)
	if err != nil {
		return nil, err
	}
	return NewSearchStream(stream), nil
}

// Ends what session holds here: every cursor, its stream closed and its snapshots released, its hit ids with it, and
// the session's limits. The session ended (D-MCP-25; MCP-M10-02's session_search.go), so a token or a hit id of it
// opens nothing after. The daemon's own session is never ended.
func (self *SearchEngine) EndSession(session Id) {
	if session == searchLocalSession {
		return
	}
	self.cursors.endSession(session)
	self.limits.forget(session)
}

// One OS window of background sync (SidecarSearchBackgroundSync): the policy's, where one is given.
func (self *SearchEngine) RunBackgroundSync(ctx context.Context) error {
	if self.background == nil {
		return ErrSidecarSearchUnavailable
	}
	return self.background.RunBackgroundSync(ctx)
}

// Drops the cache of repoId, or of every repo, ending the searches reading it first (SidecarSearchCacheDropper), and
// resets the sync's state of every ref it drops, so their next round fetches what the drop removed (QD-1025). A round
// running on one of them finishes before the drop starts; search.state, which is not in the cache, stays.
func (self *SearchEngine) DropCache(repoId *Id) error {
	for _, stream := range self.openStreams() {
		if repoId == nil || stream.reads(*repoId) {
			stream.Close()
		}
	}
	return self.args.Sync.dropAndReset(repoId, func() error {
		if repoId == nil {
			return self.args.Cache.DropAll()
		}
		return self.args.Cache.DropRepo(*repoId)
	})
}

// The searches open now.
func (self *SearchEngine) openStreams() []*searchEngineStream {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	streams := make([]*searchEngineStream, 0, len(self.streams))
	for stream := range self.streams {
		streams = append(streams, stream)
	}
	return streams
}

// Ends every search and cursor.
func (self *SearchEngine) Close() {
	self.stateLock.Lock()
	self.closed = true
	self.stateLock.Unlock()
	self.cursors.closeAll()
	for _, stream := range self.openStreams() {
		stream.Close()
	}
}

// §16.10's doc-table filters and time bounds as a confirmation applies them: from, subject, to and title confined to
// their fields; agent, run and session to a registered class's fields; kind[] to one of its kinds; sidecar to the
// row's writer, field 7 in both registries, as rows spell ids (lowercase hex); member to one of the sidecars members
// names for it; path_prefix to the locator.
func searchRowFiltersOf(request *SearchRequest, normalizer *indexNormalizer, members func(memberId Id) []Id) (*searchRowFilters, error) {
	filters := &searchRowFilters{}
	if !request.Since.IsZero() {
		filters.sinceSeconds = uint64(max(request.Since.Unix(), 0))
	}
	if !request.Until.IsZero() {
		filters.untilSeconds = uint64(max(request.Until.Unix(), 0))
	}
	var kinds *searchFieldFilter
	for _, filter := range request.Filters {
		switch filter.Name {
		case "path_prefix":
			filters.pathPrefix = filter.Value
		case "kind":
			// kind[]: one of the kinds named (§16.10's search in row)
			if kinds == nil {
				kinds = &searchFieldFilter{fieldName: "kind"}
				filters.fields = append(filters.fields, kinds)
			}
			kinds.values = append(kinds.values, filter.Value)
		case "sidecar":
			sidecarId, err := ParseId(filter.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: a sidecar filter that is no id", ErrSearchRequest)
			}
			filters.fields = append(filters.fields, &searchFieldFilter{field: searchFieldWriter, values: []string{hex.EncodeToString(sidecarId[:])}})
		case "member":
			memberId, err := ParseId(filter.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: a member filter that is no id", ErrSearchRequest)
			}
			member := &searchFieldFilter{field: searchFieldWriter}
			if members != nil {
				for _, sidecarId := range members(memberId) {
					member.values = append(member.values, hex.EncodeToString(sidecarId[:]))
				}
			}
			member.none = len(member.values) == 0
			filters.fields = append(filters.fields, member)
		case "from", "subject", "to", "title":
			term, ok, err := searchNewTerm(normalizer, filter.Value)
			if err != nil {
				return nil, err
			}
			if ok {
				filters.fields = append(filters.fields, &searchFieldFilter{field: searchQueryHeaderFields[filter.Name], term: term})
			}
		case "agent", "run", "session":
			name := map[string]string{"agent": "agent", "run": "run_id", "session": "session_ids"}[filter.Name]
			term, ok, err := searchNewTerm(normalizer, filter.Value)
			if err != nil {
				return nil, err
			}
			if ok {
				filters.fields = append(filters.fields, &searchFieldFilter{fieldName: name, term: term})
			}
		default:
			return nil, fmt.Errorf("%w: a filter named %d bytes long that §16.10 does not name", ErrSearchRequest, len(filter.Name))
		}
	}
	return filters, nil
}

// One search: its refs' snapshots, its ranker and its phases, which its cursor names. Its pages are computed one at a
// time; Close is safe beside a page. Scope all's download runs beside the pages (search_engine_more.go).
type searchEngineStream struct {
	engine     *SearchEngine
	session    Id
	request    *SearchRequest
	query      *SearchQuery
	filters    *searchRowFilters
	normalizer *indexNormalizer
	excluded   []SearchExclusion
	// What the request asks of mail's joins.
	joinAsk SearchJoinAsk
	// "search more"'s download and what it landed, shared with its window's goroutine.
	more *searchEngineMore
	// Ends as the search does (Close), and with it any window.
	lifetime    context.Context
	endLifetime context.CancelFunc

	// One page at a time.
	pageLock sync.Mutex
	refs     []*searchOpenedRef
	ranker   *searchRanker
	// 0 before phase 1; 1; 2 and on, phase 2's partitions.
	phase int
	step  int
	// Phase-2 partitions waiting to be ranked, in the order they were matched.
	pending []*searchRankInput
	// The window call whose landed shards matchLanded reads together, and the shards it landed so far.
	landedCall   int
	landedShards []*searchShardSource
	// Hits ranked and held back past PageByteCount, or given back past a caller's limit (holdBack), first on the next
	// page.
	held []SearchHit
	// The calling page's progress report, set for that call alone (nextReporting).
	report func(progress SearchProgress)
	// The running counts of the phases given, and of the one in progress; whether the phase in progress is counted
	// among those given already, so a page that finds it done again counts nothing twice.
	finished     SearchHitCounts
	current      searchRankCounts
	phaseCounted bool
	tooBroad     bool
	searched     int
	done         bool
	// Runs as a page holding hits answers, under pageLock: where a fake clock's world plants a delay in the page loop
	// (SearchTestDeviceArgs.AnswerDelay). Nil but there.
	answerHook func()

	stateLock sync.Mutex
	closed    bool
	// Called once the search ends (onClose).
	ends []func()
}

// Opens each scoped ref: its snapshot, held until the search ends, its plan, its mask and its confirmer. A ref with no
// snapshot, a newer format or an index turned off is left out with its reason.
func (self *searchEngineStream) open(ctx context.Context, scoped []*searchScopedRef) error {
	engine := self.engine
	ranker, err := newSearchRanker(&searchRankerArgs{settings: engine.results, search: engine.args.Settings, query: self.query})
	if err != nil {
		return err
	}
	self.ranker = ranker
	tables := indexLinkedTables()
	nowMs := engine.clock.Now().UnixMilli()
	planScope := map[SearchScope]searchPlanScope{SearchCached: searchPlanCached, SearchLatest: searchPlanLatest, SearchAll: searchPlanAll}[self.request.Scope]
	for _, entry := range scoped {
		repoId, refId := entry.repo.RepoId, entry.ref.RefId
		exclude := func(reason string) {
			self.excluded = append(self.excluded, SearchExclusion{RepoId: repoId, RefId: &refId, Reason: reason})
		}
		if entry.scan {
			// §11.14's off row in repo breadth: no scan source is wired yet, so coverage says the index is off
			if entry.ref.IndexOff {
				exclude(SearchExcludedIndexOff)
			} else {
				exclude(SearchExcludedUnbuilt)
			}
			continue
		}
		snapshot, err := engine.args.Sync.Snapshot(repoId, refId)
		switch {
		case errors.Is(err, ErrSidecarStoreAbsent), errors.Is(err, ErrSearchSyncUnfollowed):
			if entry.repo.ReceiptRequired && errors.Is(engine.args.Sync.lastError(repoId, refId), errSearchSyncReceipt) {
				exclude(SearchExcludedReceipt)
			} else {
				exclude(SearchExcludedUnbuilt)
			}
			continue
		case err != nil:
			return err
		}
		held, err := engine.args.Cache.Ref(repoId, refId)
		if err != nil {
			snapshot.Release()
			return err
		}
		retained := []SearchCacheRetained{}
		if held != nil {
			retained = held.Retained
		}
		holding := searchHoldingOfSnapshot(snapshot, repoId, refId, retained)
		plan := searchPlanRef(&searchPlanArgs{scope: planScope, since: self.request.Since, nowMs: nowMs, tables: tables}, holding)
		switch plan.status {
		case searchRefUpdate:
			snapshot.Release()
			exclude(SearchExcludedUpdate)
			continue
		case searchRefOff:
			snapshot.Release()
			exclude(SearchExcludedIndexOff)
			continue
		}
		companion := searchRootCompanion(snapshot.manifest.Root)
		opened := &searchOpenedRef{
			engine: engine, scoped: entry, repoId: repoId, refId: refId, snap: snapshot, holding: holding, plan: plan,
			probe: searchProbeOf(snapshot.Versions()),
		}
		if engine.args.Local != nil {
			opened.local = engine.args.Local(repoId, refId)
		}
		var localNewest searchLocalNewestFunc
		if opened.local != nil {
			localNewest = opened.local.newest
		}
		probe := opened.probe
		if probe == nil {
			// an index whose snapshot holds no run: nothing in it to find
			probe = func(key [indexIdByteCount]byte) (searchVersionRecord, error) { return searchVersionRecord{}, nil }
			opened.probe = probe
		}
		mask, err := newSearchMask(&searchMaskArgs{probe: probe, companion: companion, refId: refId, local: localNewest})
		if err != nil {
			snapshot.Release()
			return err
		}
		confirmer := &searchConfirmer{
			query: self.query, filters: self.filters, normalizer: self.normalizer, registry: searchRegistryOf(entry.repo.Kind),
			settings: engine.results, repoId: repoId,
		}
		if engine.args.Text != nil {
			confirmer.text = engine.args.Text(repoId, refId)
		}
		if engine.args.Display != nil {
			confirmer.display = engine.args.Display(repoId, refId)
		}
		opened.source = &searchRankSource{repoId: repoId, refId: refId, companion: companion, mask: mask, confirmer: confirmer}
		self.refs = append(self.refs, opened)
		engine.args.Cache.MarkSearched(repoId, refId, SearchCachePartition{})
	}
	return nil
}

// Whether the search reads repoId.
func (self *searchEngineStream) reads(repoId Id) bool {
	for _, ref := range self.refs {
		if ref.repoId == repoId {
			return true
		}
	}
	return false
}

// Whether an erasure, a CUT, a drop or a lost read ended a snapshot the search reads (§16.10's pages row).
func (self *searchEngineStream) ended() bool {
	for _, ref := range self.refs {
		select {
		case <-ref.snap.Ended():
			return true
		default:
		}
	}
	return false
}

// The next page (SearchStreamSource), within Search.PageCpu.
func (self *searchEngineStream) Next() ([]SearchHit, SearchProgress, bool, error) {
	return self.NextContext(context.Background())
}

// The next page, waiting for admission until ctx ends and computing within ctx and Search.PageCpu: phase 1's ranked
// hits, then phase 2's, a page never revised; done once no later page holds a hit. A page holding a hit answers
// rather than wait on "search more"'s download, which goes on beside it (QD-999). ErrSearchCursorExpired once the
// search's scope ended it.
func (self *searchEngineStream) NextContext(ctx context.Context) ([]SearchHit, SearchProgress, bool, error) {
	return self.nextReporting(ctx, nil)
}

// NextContext's page, report getting the search's progress while the page waits on "search more", on this goroutine,
// and never after this returns; nil reports nothing.
func (self *searchEngineStream) nextReporting(ctx context.Context, report func(progress SearchProgress)) ([]SearchHit, SearchProgress, bool, error) {
	self.pageLock.Lock()
	defer self.pageLock.Unlock()
	self.report = report
	defer func() {
		self.report = nil
	}()
	if self.isClosed() {
		return nil, self.progressNow(), true, ErrSearchCursorExpired
	}
	if self.ended() {
		self.Close()
		return nil, self.progressNow(), true, ErrSearchCursorExpired
	}
	if self.done && len(self.held) == 0 {
		return nil, self.progressNow(), true, nil
	}
	release, err := self.engine.limits.admit(ctx, self.session, false)
	if err != nil {
		return nil, self.progressNow(), false, err
	}
	defer release()
	pageCtx, stop := self.engine.limits.pageContext(ctx)
	defer stop()

	settings := self.engine.args.Settings
	page := []SearchHit{}
	byteCount := 0
	give := func(hit SearchHit) bool {
		size := searchHitByteCount(&hit)
		if 0 < len(page) && settings.PageByteCount < byteCount+size {
			self.held = append(self.held, hit)
			return false
		}
		page = append(page, hit)
		byteCount += size
		return true
	}
	held := self.held
	self.held = nil
	for _, hit := range held {
		if len(page) < self.request.PageSize {
			give(hit)
		} else {
			self.held = append(self.held, hit)
		}
	}
	if self.phase == 0 {
		inputs := []*searchRankInput{}
		near := []*searchNearInput{}
		for _, ref := range self.refs {
			refInputs, refNear, err := ref.phaseOne(pageCtx, self.query, &self.step)
			if err != nil {
				return nil, self.progressNow(), false, err
			}
			inputs = append(inputs, refInputs...)
			near = append(near, refNear...)
		}
		if err := self.beginWithNear(pageCtx, inputs, near); err != nil {
			return nil, self.progressNow(), false, err
		}
	}
	for len(page) < self.request.PageSize && len(self.held) == 0 && pageCtx.Err() == nil && !self.done {
		ranked, err := self.ranker.page(pageCtx, self.request.PageSize-len(page))
		if err != nil {
			return nil, self.progressNow(), false, err
		}
		self.tooBroad = self.tooBroad || ranked.counts.tooBroad
		for _, hit := range ranked.hits {
			// mail's joins leave out spam and trash unless asked, on what the device already holds (I-19)
			kept, _, err := searchJoinMailHit(pageCtx, self.engine.args.Join, self.joinAsk, hit.repoId, hit.row)
			if err != nil {
				return nil, self.progressNow(), false, err
			}
			if kept {
				give(searchHitOf(hit))
			}
		}
		if !self.phaseCounted {
			self.current = ranked.counts
		}
		if !ranked.phaseDone {
			// the page is full, or it checked Search.PageCandidateCount, or its time ended: the next page goes on
			break
		}
		if !self.phaseCounted {
			self.finishPhase()
		}
		began, finished, err := self.beginNext(pageCtx, 0 < len(page))
		if err != nil {
			return nil, self.progressNow(), false, err
		}
		if !began {
			self.done = finished
			break
		}
	}
	if 0 < len(page) && self.answerHook != nil {
		self.answerHook()
	}
	return page, self.progressNow(), self.done && len(self.held) == 0, nil
}

// Begins the ranker's next phase over inputs, its near hits settled empty: phase 2's partitions, whose terms phase 1
// already corrected where they needed it.
func (self *searchEngineStream) begin(inputs []*searchRankInput) error {
	if err := self.ranker.beginPhase(inputs); err != nil {
		return err
	}
	self.phase += 1
	self.phaseCounted = false
	self.searched += len(inputs)
	return self.ranker.settleNear(nil, "", 0)
}

// Begins phase 1 over inputs and settles its near hits (§11.14's typos row, search_typo.go): a term with fewer exact
// hits than NearHitExactCount, or every term under Fuzzy, is corrected by its one-edit variants probed in the
// partitions, each masked by its repo's index, and the corrected query is matched in each partition as the query was.
func (self *searchEngineStream) beginWithNear(ctx context.Context, inputs []*searchRankInput, near []*searchNearInput) error {
	if err := self.ranker.beginPhase(inputs); err != nil {
		return err
	}
	self.phase += 1
	self.phaseCounted = false
	self.searched += len(inputs)
	partitions := make([]*searchNearPartition, 0, len(near))
	for _, input := range near {
		partitions = append(partitions, &searchNearPartition{source: input.source, mask: input.ref.source.mask})
	}
	result, err := searchNearHits(ctx, &searchNearArgs{
		query: self.query, normalizer: self.normalizer, settings: self.engine.results, fuzzy: self.request.Fuzzy,
		partitions: partitions, maxCandidateCount: self.engine.args.Settings.TooBroadCandidateCount,
	})
	if err != nil {
		if ctx.Err() != nil {
			// out of time: no near hits this search, the exact ones stand
			return self.ranker.settleNear(nil, "", 0)
		}
		return err
	}
	if result.query == nil || len(result.corrections) == 0 {
		return self.ranker.settleNear(nil, "", 0)
	}
	corrected := []*searchRankInput{}
	for _, input := range near {
		matched, err := input.ref.match(result.query, input.source, input.step)
		if err != nil {
			return err
		}
		corrected = append(corrected, matched)
	}
	correction := searchCorrectionText(result.corrections[0], DefaultSearchWireSettings())
	return self.ranker.settleNear(corrected, correction, len(result.query.trigrams()))
}

// Phase 2 after phase 1, and each further phase-2 partition after the last: all at once where usable (SearchCached),
// or each shard "search more" lands (SearchAll), waited for only while the page holds no hit (holding). Whether one
// began, and where none did, whether none ever will: the search is done.
func (self *searchEngineStream) beginNext(ctx context.Context, holding bool) (bool, bool, error) {
	if 0 < len(self.pending) {
		input := self.pending[0]
		self.pending = self.pending[1:]
		return true, false, self.begin([]*searchRankInput{input})
	}
	switch self.request.Scope {
	case SearchLatest:
		return false, true, nil
	case SearchCached:
		if self.phase != 1 {
			return false, true, nil
		}
		inputs := []*searchRankInput{}
		for _, ref := range self.refs {
			refInputs, err := ref.phaseTwo(ctx, self.query, &self.step)
			if err != nil {
				return false, false, err
			}
			inputs = append(inputs, refInputs...)
		}
		if len(inputs) == 0 {
			return false, true, nil
		}
		return true, false, self.begin(inputs)
	}
	// SearchAll: what is held usable first, then "search more" ref by ref, each shard ranked as it lands
	if self.phase == 1 {
		inputs := []*searchRankInput{}
		for _, ref := range self.refs {
			refInputs, err := ref.phaseTwo(ctx, self.query, &self.step)
			if err != nil {
				return false, false, err
			}
			inputs = append(inputs, refInputs...)
		}
		if 0 < len(inputs) {
			return true, false, self.begin(inputs)
		}
	}
	return self.awaitMore(ctx, holding)
}

// Adds the phase just given to the search's running counts, once.
func (self *searchEngineStream) finishPhase() {
	self.finished.Confirmed += self.current.matches
	self.finished.Possible += self.current.possible
	self.finished.Near += self.current.near
	self.finished.Masked += self.current.masked
	self.current = searchRankCounts{}
	self.phaseCounted = true
}

// The running counts: the phases given, and the one in progress.
func (self *searchEngineStream) countsNow() SearchHitCounts {
	counts := self.finished
	counts.Confirmed += self.current.matches
	counts.Possible += self.current.possible
	counts.Near += self.current.near
	counts.Masked += self.current.masked
	counts.Pending = self.current.pending
	return counts
}

// The progress a page carries (§5.4's SearchProgress; §16.10's coverage and status): the page's own state, and "search
// more"'s as its window last reported it.
func (self *searchEngineStream) progressNow() SearchProgress {
	more, _ := self.more.state()
	progress := SearchProgress{
		Searched: self.searched, FetchBytes: more.progress.MissingByteCount - more.progress.FetchedByteCount,
		FetchedBytes: more.progress.MeteredByteCount, Waiting: more.waiting, TooBroad: self.tooBroad,
		Excluded: slices.Clone(self.excluded),
	}
	total := 0
	for _, ref := range self.refs {
		total += len(ref.plan.steps)
		coverage := ref.coverage()
		if !more.finished[[2]Id{ref.repoId, ref.refId}] && self.request.Scope == SearchAll && 0 < more.progress.ShardCount {
			coverage.All, coverage.AllSearched, coverage.AllTotal = SearchAllFetching, more.progress.SearchedCount, more.progress.ShardCount
		}
		progress.Coverage = append(progress.Coverage, coverage)
		if !coverage.LatestFrom.IsZero() && (progress.CoveredFrom.IsZero() || coverage.LatestFrom.Before(progress.CoveredFrom)) {
			progress.CoveredFrom = coverage.LatestFrom
		}
	}
	progress.Total = max(total, self.searched)
	progress.Counts = self.countsNow()
	progress.Counts.Repos = len(self.refs)
	progress.Counts.Excluded = len(self.excluded)
	return progress
}

// The search's progress now, between pages.
func (self *searchEngineStream) currentProgress() SearchProgress {
	self.pageLock.Lock()
	defer self.pageLock.Unlock()
	return self.progressNow()
}

// Gives hits back to the stream, in their order, first on its next page: what a caller paged past its limit, so no page
// it returned is revised.
func (self *searchEngineStream) holdBack(hits []SearchHit) {
	self.pageLock.Lock()
	defer self.pageLock.Unlock()
	self.held = append(slices.Clone(hits), self.held...)
}

// Calls end once the search ends, as Close does, or at once where it ended already.
func (self *searchEngineStream) onClose(end func()) {
	ended := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return true
		}
		self.ends = append(self.ends, end)
		return false
	}()
	if ended {
		end()
	}
}

// Whether the search was closed.
func (self *searchEngineStream) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// Ends the search: its download stopped first, waited for, then its snapshots released and its reads closed, nothing
// more asked. Safe to call again, and beside a page; not from a page's report.
func (self *searchEngineStream) Close() {
	self.stateLock.Lock()
	if self.closed {
		self.stateLock.Unlock()
		return
	}
	self.closed = true
	refs := self.refs
	ends := self.ends
	self.ends = nil
	self.stateLock.Unlock()
	self.endLifetime()
	self.more.join()
	for _, ref := range refs {
		ref.close()
	}
	for _, end := range ends {
		end()
	}
	self.engine.stateLock.Lock()
	delete(self.engine.streams, self)
	self.engine.stateLock.Unlock()
}

// The engine is CORE-M10-03's: what InstallSearchEngine takes, with its background window and cache dropper.
var (
	_ SidecarSearchEngine         = (*SearchEngine)(nil)
	_ SidecarSearchBackgroundSync = (*SearchEngine)(nil)
	_ SidecarSearchCacheDropper   = (*SearchEngine)(nil)
	_ SearchStreamSource          = (*searchEngineStream)(nil)
)
