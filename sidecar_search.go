//go:build !ios_extension

// §5.4's search methods on the Sidecar (CORE-M10-03; R-CORE-18, R-CORE-19, D-CORE-16, D-CORE-17, I-13, I-19): what
// §16.10's tools, `ur search`, §18.5's SidecarSearch and a remote-mode app's control calls reach, over 9.9's engine,
// which the host builds on this network's SearchCache and SidecarSearchState and installs with InstallSearchEngine.
// Until one is installed every call the engine answers is ErrSidecarSearchUnavailable, so nothing reads like a search
// that found nothing.
//
// What CORE decides here, beside the engine:
//   - a request's Remote: "" reads this network's mode from search.state and "off" keeps the search local; a host
//     without the requester side (Search.RemoteAsk false: daemon hosts, which remote-mode apps reach, and page
//     Workers) never asks, and a state that cannot be read reads off;
//   - SetSearchRemote and AcknowledgeSearchIndexer run only where the requester side does, answering
//     ErrSidecarSearchRefused elsewhere: on the daemon a remote-mode app reaches (§18.7's control row), and on the
//     daemon as the host MCP runs on, so no MCP path sets a mode or an answer (§16.10);
//   - the host's conditions, kept in memory as reported: a host that reports none reads metered and not charging,
//     but a daemon host (Search.RemoteServe, which only daemon hosts set) reads unmetered (D-SDK-23);
//   - a background window's budget, ctx's deadline read on the Sidecar's clock: the window stops there and resumes
//     at the next (§18.5's budgetMillis);
//   - DropSearchCache keeps search.state (§5.9's state row);
//   - index_mismatch, index_malformed and search_alarm reach emitEvent through searchEvents, and no other kind does.
//
// §5.4's types are declared here so the Sidecar's methods carry their signatures before SEARCH-M10-26's engine lands
// (C-16: the task that declares a seam does not wait on its caller). §5.4 gives SearchFieldFilter and SearchField no
// fields: theirs here follow search.proto, a reading the engine may reshape. Nothing here holds a query past the call
// that carries it, logs one or writes one (I-13, §5.9's never row).
//
// On every leg but the forwarding one, which runs no search: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

var (
	// No search engine runs on this Sidecar yet, or its network is not known: nothing was searched.
	ErrSidecarSearchUnavailable = errors.New("search: no search engine runs on this sidecar")
	// This host does not run remote search's requester side, so its mode and notice answers are not its to set.
	ErrSidecarSearchRefused = errors.New("search: refused on this host, which asks no indexer")
	// A search request, or a window, is not well formed.
	ErrSearchRequest = errors.New("search: invalid request")
)

// §5.4's partitions a search reads (QD-572).
type SearchScope int

const (
	// Buckets and any cached all: the default.
	SearchCached SearchScope = 0
	// Buckets only.
	SearchLatest SearchScope = 1
	// Buckets, then all, fetching what is missing ("search more").
	SearchAll SearchScope = 2
)

// What a hit claims (§11.14's confirm row, §18.5's hit states).
type SearchHitState int

const (
	SearchVerified  SearchHitState = 1
	SearchConfirmed SearchHitState = 2
	SearchPossible  SearchHitState = 3
	SearchNear      SearchHitState = 4
	// A local possible or near hit that an indexer's checked span disproved (§11.14's merge).
	SearchUnmatched SearchHitState = 5
)

// Where a hit was found.
type SearchPartition int

const (
	// A bucket: the current, the previous, or an older or retained one.
	SearchPartitionLatest SearchPartition = 1
	SearchPartitionAll    SearchPartition = 2
)

// One display or filter field: §11.14's field number (1 subject, 2 from, ...) and its text, as search.proto's
// SearchField.
type SearchField struct {
	Field int
	Text  string
}

// One of §16.10's doc-table filters: Name is from, subject, agent, sidecar, member, run, session, kind, path_prefix or
// field, and Value what it must hold.
type SearchFieldFilter struct {
	Name  string
	Value string
}

// §5.4's request.
type SearchRequest struct {
	// §16.10's query.
	Text string
	// Empty: every readable repo with its index on (never secret, config or mailcfg).
	Repos []Id
	Scope SearchScope
	// Zero: unbounded.
	Since time.Time
	Until time.Time
	// Near hits even when 3 or more exact hits exist.
	Fuzzy   bool
	Filters []SearchFieldFilter
	// Scope all may fetch past §18.4's 25 MiB on a metered link.
	AllowMetered bool
	// "": this network's remote mode (5.9's state), which Search resolves to on, own or off before the engine sees it;
	// "off": this search stays local.
	Remote string
	// Hits a page. Zero: Search.PageHitCount.
	PageSize int
}

// §5.4's hit.
type SearchHit struct {
	Repo Id
	Ref  Id
	// Or a derived document's registered name (§11.14).
	Path    string
	Version uint64
	Time    time.Time
	// The document version's writer, for grouping by agent (§16.10).
	Signer Id
	// Display fields: title or subject, from, and kind-specific ones.
	Fields []SearchField
	// Verified hits: around the match; mail: i/'s snippet; else empty.
	Snippet   string
	State     SearchHitState
	Partition SearchPartition
	// SearchNear: the corrected term.
	Correction string
	// "": this device; else the answering indexer's config name (§11.14).
	By string
}

// §5.4's progress, which each page carries.
type SearchProgress struct {
	// Partitions.
	Searched int
	Total    int
	// Scope all: bytes still to fetch, and fetched so far.
	FetchBytes   int64
	FetchedBytes int64
	// Changes not yet searchable.
	Uncovered int
	// "", "metered", "offline", "update".
	Waiting     string
	CoveredFrom time.Time
	// §18.5's remote states and fallback reasons.
	Remote         string
	FallbackReason string
	// The indexer asked, or the one a notice names.
	RemoteBy *Id
}

// A repo's search status: §18.5's SidecarSearchStatus.
type SearchStatus struct {
	IndexOn         bool
	FormatSupported bool
	// The policy in force: this device's override, else the host's default (§18.4).
	Policy string
	// This network's remote mode: on, own or off; off where this host asks no indexer.
	Remote string
	// Zero: none.
	LatestFrom       time.Time
	AllCachedThrough time.Time
	// Zero all cached bytes: all not cached.
	AllCachedByteCount  int64
	AllMissingByteCount int64
	Uncovered           int
}

// An indexer that may answer this device: §18.5's SidecarIndexer.
type SearchIndexer struct {
	SidecarId Id
	// Its config device name.
	Name string
	// Its member, or a tagged device's sponsor.
	MemberId *Id
	Member   string
	// A device of this member.
	Own bool
	// online, unreachable, busy or unknown.
	State string
	// Another member's: the person answered its notice and allowed it.
	Acknowledged bool
	// The repos it answered in the last Search.RemoteServedTimeout.
	ServedRepoIds []Id
}

// What a stream's engine answers: SEARCH-M10-26's.
type SearchStreamSource interface {
	// The next page, which replaces the last, with its progress; done once no later page holds a hit.
	Next() (page []SearchHit, progress SearchProgress, done bool, err error)
	// Ends the search: its cursors and remote legs end and nothing more is asked (§11.14: no Cancel is sent).
	Close()
}

// One search's pages (§5.4). Safe for concurrent use as its source is.
type SearchStream struct {
	source    SearchStreamSource
	closeOnce sync.Once
	// takes the stream off the cache's open cursors, so a lock no longer ends it
	unregister func()
}

// A stream over an engine's source.
func NewSearchStream(source SearchStreamSource) *SearchStream {
	return &SearchStream{source: source}
}

// The next page, replacing the last (§5.4).
func (self *SearchStream) Next() (page []SearchHit, progress SearchProgress, done bool, err error) {
	return self.source.Next()
}

// Ends the search. Safe to call again.
func (self *SearchStream) Close() {
	self.closeOnce.Do(func() {
		self.source.Close()
		if self.unregister != nil {
			self.unregister()
		}
	})
}

// §5.4's engine beneath the Sidecar's search methods: SEARCH-M10-26's SearchEngine, with the sync engine, policy and
// remote client beside it, which the host builds on SearchCache and SearchState. Safe for concurrent use.
type SidecarSearchEngine interface {
	// One search, its Remote resolved to on, own or off and its PageSize set.
	Search(ctx context.Context, request *SearchRequest) (*SearchStream, error)
	// A repo's status, or with a nil repoId every repo's together. Policy and Remote are CORE's, filled after.
	Status(repoId *Id) (*SearchStatus, error)
}

// Optional beside SidecarSearchEngine: SEARCH-M10-20's background window.
type SidecarSearchBackgroundSync interface {
	// Syncs until ctx ends, which is the window's budget; what it did not reach it reaches next time.
	RunBackgroundSync(ctx context.Context) error
}

// Optional beside SidecarSearchEngine: SEARCH-M10-33's remote client.
type SidecarSearchIndexerLister interface {
	// The indexers that may answer this device, own first, with Acknowledged and ServedRepoIds left for CORE to fill.
	Indexers() []SearchIndexer
}

// Optional beside SidecarSearchEngine: an engine that must end its searches and forget its sync state before the
// cache's files go. It drops them itself, through SearchCache.
type SidecarSearchCacheDropper interface {
	// repoId nil: every repo.
	DropCache(repoId *Id) error
}

// The host's conditions (§18.7, D-SDK-23), as SetSearchConditions last reported them.
type SidecarSearchConditions struct {
	Unmetered bool
	Charging  bool
	LowPower  bool
	// Whether the host reported them. Unreported reads metered and not charging, but unmetered on a daemon host.
	Reported bool
}

// A Sidecar's search: the network the state and cache are of, the engine, and the host's conditions.
type sidecarSearch struct {
	conditions *MonitorValue[SidecarSearchConditions]

	stateLock sync.Mutex
	networkId Id
	state     *SidecarSearchState
	cache     *SearchCache
	engine    SidecarSearchEngine
}

// The Sidecar's search, made on first use.
func (self *Sidecar) searchOf() *sidecarSearch {
	if search, ok := self.search.Load().(*sidecarSearch); ok {
		return search
	}
	self.search.CompareAndSwap(nil, &sidecarSearch{conditions: NewMonitorValue(SidecarSearchConditions{})})
	return self.search.Load().(*sidecarSearch)
}

// The network the search state and cache are of: the enrolled one.
func (self *Sidecar) searchNetworkId() (Id, error) {
	networkId := self.enrolledNetworkId()
	if networkId == nil || self.instance == nil {
		return Id{}, fmt.Errorf("%w: no network yet", ErrSidecarSearchUnavailable)
	}
	return *networkId, nil
}

// The search of the enrolled network: the state, cache and engine of another network are forgotten, its cache closed
// outside the lock (its files stay in that network's directory).
func (self *Sidecar) searchOfNetwork() (*sidecarSearch, Id, error) {
	networkId, err := self.searchNetworkId()
	if err != nil {
		return nil, Id{}, err
	}
	search := self.searchOf()
	stale := func() *SearchCache {
		search.stateLock.Lock()
		defer search.stateLock.Unlock()
		if search.networkId == networkId {
			return nil
		}
		stale := search.cache
		search.networkId = networkId
		search.state = nil
		search.cache = nil
		search.engine = nil
		return stale
	}()
	if stale != nil {
		stale.Close()
	}
	return search, networkId, nil
}

// This network's search state (§5.9's state row), made on first use.
func (self *Sidecar) SearchState() (*SidecarSearchState, error) {
	search, networkId, err := self.searchOfNetwork()
	if err != nil {
		return nil, err
	}
	if state := func() *SidecarSearchState {
		search.stateLock.Lock()
		defer search.stateLock.Unlock()
		return search.state
	}(); state != nil {
		return state, nil
	}
	state, err := newSidecarSearchState(self.instance.Store(&networkId), self.settings.Search, self.clock, self.log, func() {
		self.emitEvent(SidecarEvent{Kind: SidecarEventRefused})
	})
	if err != nil {
		return nil, err
	}
	search.stateLock.Lock()
	defer search.stateLock.Unlock()
	if search.networkId != networkId {
		return nil, fmt.Errorf("%w: the network changed", ErrSidecarSearchUnavailable)
	}
	if search.state == nil {
		search.state = state
	}
	return search.state, nil
}

// This network's index cache (§5.9's holds row, CORE-M10-01), made on first use: what the host builds the engine on. A
// cache that cannot open yet, as while locked, answers that error, and the next call tries again.
func (self *Sidecar) SearchCache() (*SearchCache, error) {
	if self.ctx == nil {
		return nil, ErrSidecarClosed
	}
	search, networkId, err := self.searchOfNetwork()
	if err != nil {
		return nil, err
	}
	if cache := func() *SearchCache {
		search.stateLock.Lock()
		defer search.stateLock.Unlock()
		return search.cache
	}(); cache != nil {
		return cache, nil
	}
	// opened outside the lock, since it lists the store
	cache, err := NewSearchCache(self.ctx, self.instance.Store(&networkId), self.settings.Search, self.clock, self.log)
	if err != nil {
		return nil, err
	}
	kept, extra := func() (*SearchCache, *SearchCache) {
		search.stateLock.Lock()
		defer search.stateLock.Unlock()
		if search.networkId != networkId {
			return nil, cache
		}
		if search.cache == nil {
			search.cache = cache
			return cache, nil
		}
		return search.cache, cache
	}()
	if extra != nil {
		extra.Close()
	}
	if kept == nil {
		return nil, fmt.Errorf("%w: the network changed", ErrSidecarSearchUnavailable)
	}
	return kept, nil
}

// Installs engine as this network's search engine, replacing any before; the answer removes it, if it is still the one
// installed. The host builds it on SearchCache and SearchState. A re-enrollment into another network removes it.
func (self *Sidecar) InstallSearchEngine(engine SidecarSearchEngine) (func(), error) {
	if engine == nil {
		return nil, fmt.Errorf("%w: no engine", ErrSearchRequest)
	}
	search, networkId, err := self.searchOfNetwork()
	if err != nil {
		return nil, err
	}
	installed := func() bool {
		search.stateLock.Lock()
		defer search.stateLock.Unlock()
		if search.networkId != networkId {
			return false
		}
		search.engine = engine
		return true
	}()
	if !installed {
		return nil, fmt.Errorf("%w: the network changed", ErrSidecarSearchUnavailable)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			search.stateLock.Lock()
			defer search.stateLock.Unlock()
			if search.engine == engine {
				search.engine = nil
			}
		})
	}, nil
}

// The installed engine of the enrolled network, or ErrSidecarSearchUnavailable.
func (self *Sidecar) searchEngine() (SidecarSearchEngine, error) {
	search, _, err := self.searchOfNetwork()
	if err != nil {
		return nil, err
	}
	search.stateLock.Lock()
	defer search.stateLock.Unlock()
	if search.engine == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	return search.engine, nil
}

// The remote mode a search of this network runs under: off where this host asks no indexer, or where search.state
// cannot be read, which fails closed.
func (self *Sidecar) searchRemoteMode() string {
	if !self.settings.Search.RemoteAsk {
		return SearchRemoteOff
	}
	state, err := self.SearchState()
	if err != nil {
		return SearchRemoteOff
	}
	mode, err := state.Mode()
	if err != nil {
		return SearchRemoteOff
	}
	return mode
}

// Runs one search (§5.4): the request's Remote resolved, its page size set, the stream registered with the cache's
// open cursors so a lock ends it.
func (self *Sidecar) Search(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
	if request == nil || request.PageSize < 0 {
		return nil, fmt.Errorf("%w: a request with a page size not below zero", ErrSearchRequest)
	}
	if request.Scope != SearchCached && request.Scope != SearchLatest && request.Scope != SearchAll {
		return nil, fmt.Errorf("%w: scope %d", ErrSearchRequest, request.Scope)
	}
	engine, err := self.searchEngine()
	if err != nil {
		return nil, err
	}
	resolved := *request
	resolved.Repos = slices.Clone(request.Repos)
	resolved.Filters = slices.Clone(request.Filters)
	switch request.Remote {
	case "":
		resolved.Remote = self.searchRemoteMode()
	case SearchRemoteOff:
	default:
		return nil, fmt.Errorf("%w: Remote is \"\" or off", ErrSearchRequest)
	}
	if resolved.PageSize == 0 {
		resolved.PageSize = self.settings.Search.PageHitCount
	}
	stream, err := engine.Search(ctx, &resolved)
	if err != nil {
		return nil, err
	}
	if cache, err := self.SearchCache(); err == nil {
		stream.unregister = cache.AddCursor(stream.Close)
	}
	return stream, nil
}

// A repo's status (§16.10's search_status, §18.5's GetStatus), with the policy in force and this network's mode.
func (self *Sidecar) GetSearchStatus(repoId *Id) (*SearchStatus, error) {
	engine, err := self.searchEngine()
	if err != nil {
		return nil, err
	}
	status, err := engine.Status(repoId)
	if err != nil {
		return nil, err
	}
	reported := *status
	reported.Policy = self.searchPolicy(repoId)
	reported.Remote = self.searchRemoteMode()
	return &reported, nil
}

// The policy for all in force for repoId, nil for every repo: this device's override, else the host's default.
func (self *Sidecar) searchPolicy(repoId *Id) string {
	state, err := self.SearchState()
	if err != nil {
		return self.settings.Search.AllPolicy
	}
	var policy string
	if repoId == nil {
		// the every-repo override, which a repo id no repo has reads
		policy, err = state.Policy(Id{})
	} else {
		policy, err = state.Policy(*repoId)
	}
	if err != nil || policy == "" {
		return self.settings.Search.AllPolicy
	}
	return policy
}

// The host's reports (§18.7): unmetered, charging and low power, which SEARCH-M10-20's policy follows.
func (self *Sidecar) SetSearchConditions(unmetered bool, charging bool, lowPower bool) {
	self.searchOf().conditions.Set(SidecarSearchConditions{Unmetered: unmetered, Charging: charging, LowPower: lowPower, Reported: true})
}

// The conditions in force, and a channel closed at their next change: as reported, or before any report metered and not
// charging, but unmetered on a daemon host (D-SDK-23).
func (self *Sidecar) SearchConditions() (SidecarSearchConditions, chan struct{}) {
	conditions, changed := self.searchOf().conditions.Get()
	if !conditions.Reported && self.settings.Search.RemoteServe {
		conditions.Unmetered = true
	}
	return conditions, changed
}

// Runs one background window (§18.5's RunBackgroundSync): ctx's deadline is its budget, read on the Sidecar's clock, so
// the sync stops there and resumes at the next window. A ctx with no deadline is refused, since an OS window always has
// one. Answers nil when the window ends at its budget.
func (self *Sidecar) RunSearchBackgroundSync(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fmt.Errorf("%w: a background window needs its budget, ctx's deadline", ErrSearchRequest)
	}
	engine, err := self.searchEngine()
	if err != nil {
		return err
	}
	background, ok := engine.(SidecarSearchBackgroundSync)
	if !ok {
		return ErrSidecarSearchUnavailable
	}
	windowCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(deadline.Sub(self.clock.Now()), cancel)
	defer stop()
	err = background.RunBackgroundSync(windowCtx)
	switch {
	case windowCtx.Err() != nil && (ctx.Err() == nil || errors.Is(ctx.Err(), context.DeadlineExceeded)):
		// the window reached its budget: what is left resumes next time
		return nil
	case err != nil:
		return err
	}
	return ctx.Err()
}

// Sets this device's policy for all (§18.4's modes): for repoId, or with nil for every repo; "" restores the host's
// default. Kept in search.state, which eviction and DropSearchCache keep.
func (self *Sidecar) SetSearchPolicy(repoId *Id, mode string) error {
	state, err := self.SearchState()
	if err != nil {
		return err
	}
	return state.SetPolicy(repoId, mode)
}

// Drops the cache of repoId, or with nil of every repo (§5.4): its files and derived data, never search.state. An
// engine that must end its searches first drops them itself.
func (self *Sidecar) DropSearchCache(repoId *Id) error {
	if engine, err := self.searchEngine(); err == nil {
		if dropper, ok := engine.(SidecarSearchCacheDropper); ok {
			return dropper.DropCache(repoId)
		}
	}
	cache, err := self.SearchCache()
	if err != nil {
		return err
	}
	if repoId == nil {
		return cache.DropAll()
	}
	return cache.DropRepo(*repoId)
}

// The indexers that may answer this device, own first (§18.5's GetIndexers): none where this host asks no indexer or no
// remote client runs, each with whether its notice is allowed and the repos it served.
func (self *Sidecar) GetSearchIndexers() []SearchIndexer {
	if !self.settings.Search.RemoteAsk {
		return nil
	}
	engine, err := self.searchEngine()
	if err != nil {
		return nil
	}
	lister, ok := engine.(SidecarSearchIndexerLister)
	if !ok {
		return nil
	}
	indexers := slices.Clone(lister.Indexers())
	state, stateErr := self.SearchState()
	for index := range indexers {
		indexer := &indexers[index]
		indexer.Acknowledged = false
		indexer.ServedRepoIds = nil
		if stateErr != nil {
			continue
		}
		if !indexer.Own && indexer.MemberId != nil {
			allow, answered, err := state.Answer(*indexer.MemberId)
			indexer.Acknowledged = err == nil && answered && allow
		}
		if served, err := state.Served(indexer.SidecarId); err == nil {
			for repoId := range served {
				indexer.ServedRepoIds = append(indexer.ServedRepoIds, repoId)
			}
			slices.SortFunc(indexer.ServedRepoIds, func(a Id, b Id) int { return a.Cmp(b) })
		}
	}
	return indexers
}

// Sets this network's remote mode, on, own or off (§18.4), where this host runs the requester side; elsewhere
// ErrSidecarSearchRefused.
func (self *Sidecar) SetSearchRemote(mode string) error {
	if !self.settings.Search.RemoteAsk {
		return ErrSidecarSearchRefused
	}
	if !isSearchRemoteMode(mode) {
		return fmt.Errorf("%w: a remote mode is on, own or off", ErrSearchStateArgs)
	}
	state, err := self.SearchState()
	if err != nil {
		return err
	}
	return state.SetMode(mode)
}

// Records the notice's answer for memberId (§18.4): allow lets that member's indexer be asked, a refusal sets the mode
// to own, and a nil memberId clears every answer. Only where this host runs the requester side; elsewhere
// ErrSidecarSearchRefused.
func (self *Sidecar) AcknowledgeSearchIndexer(memberId *Id, allow bool) error {
	if !self.settings.Search.RemoteAsk {
		return ErrSidecarSearchRefused
	}
	state, err := self.SearchState()
	if err != nil {
		return err
	}
	return state.SetAnswer(memberId, allow)
}

// Whether kind is one of search's own events, the only ones searchEvents passes.
func isSidecarSearchEventKind(kind SidecarEventKind) bool {
	return kind == SidecarEventIndexMismatch || kind == SidecarEventIndexMalformed || kind == SidecarEventSearchAlarm
}

// The sink the search engine raises its events through: index_mismatch, index_malformed and search_alarm reach
// emitEvent; any other kind is dropped, since search raises no other.
func (self *Sidecar) searchEvents() func(event SidecarEvent) {
	return func(event SidecarEvent) {
		if !isSidecarSearchEventKind(event.Kind) {
			if self.log.V(1).Enabled() {
				self.log.Infof("[search]dropped a %s event, which search does not raise", event.Kind)
			}
			return
		}
		self.emitEvent(event)
	}
}

// index_mismatch (§11.14's reproduce row): a reproduced file's hash is not its entry version's, naming the push's signer.
func (self *Sidecar) raiseIndexMismatch(repoId Id, refId Id, path string, signerId Id) {
	self.searchEvents()(SidecarEvent{Kind: SidecarEventIndexMismatch, RepoId: &repoId, RefId: &refId, Path: path, SidecarId: &signerId})
}

// index_malformed (§11.14's verify row): a file broke its format, naming its signer.
func (self *Sidecar) raiseIndexMalformed(repoId Id, refId Id, path string, signerId Id) {
	self.searchEvents()(SidecarEvent{Kind: SidecarEventIndexMalformed, RepoId: &repoId, RefId: &refId, Path: path, SidecarId: &signerId})
}

// search_alarm (§11.14's merge row, DESIGN-DETAILS 7.2.6): an indexer's hit its text disproves, or a confirmed local hit
// it omitted, naming the indexer and the repo and never the query.
func (self *Sidecar) raiseSearchAlarm(alarm SidecarSearchAlarm, indexerId Id, repoId Id) {
	self.searchEvents()(SidecarEvent{Kind: SidecarEventSearchAlarm, SearchAlarm: alarm, SidecarId: &indexerId, RepoId: &repoId})
}
