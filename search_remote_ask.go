//go:build !sidecar_http && !ios_extension

// Remote search, asking (SEARCH-M10-33; §11.14's who, eligible, auth, order, failover and limits rows; §18.4's remote,
// setting and notice rows; §18.7's foreground row; R-SDK-14, D-EVS-58, D-PROTO-22, D-SDK-26, D-SDK-27, C19, FI-24, I-3,
// FS-83, X9, R-CTX-37; DESIGN-DETAILS 7.2.3, 7.2.4 and 7.7 as amended for QD-707): an app host's "search more" over the
// repos its network's designated indexers may answer, merged with the device's own search of its cache.
//
// SearchRemoteClient wraps the network's local engine: it is the SidecarSearchEngine the host installs on an app host,
// and a SidecarComponent that follows each client generation's dispatcher. A search whose scope is not all ("search
// more"), or whose mode is off, is the local engine's alone: keystrokes never leave the device. A remote-mode Sidecar
// and a page Worker never ask (Search.RemoteAsk false, and the sidecar_http leg does not link this file).
//
// A search's repos are each in one state: todo, waiting for the plan; asking, named in a request whose page 0 has not
// come; served by the leg whose coverage served it; or fallback for a reason, searched on the device by "search more"
// (SearchMore's download, owner decision 155). The plan (search_remote_order.go) reads the config state when it runs,
// and the requests of one run are built from that one reading and sent in one step: each passes barrier
// search.remote.asked, keyed by its first repo, after eligibility, the mode and the answers were read and before it is
// sent. A leg is one search_id toward one indexer:
//
//	waiting(n)  page n asked; its deadline is RemoteTimeout (metered or not, as the conditions read) from the send, page
//	            0's including the Hello
//	idle        page n came; page n + 1 is asked only when the app asks for more (Next)
//	done        a reply said complete
//	ended       failed, superseded, abandoned or the stream closed; nothing more is asked and a reply in flight is
//	            dropped. No Cancel is ever sent
//
//	page 0      the first page 0 to serve a repo wins it; the other own leg's hits of it are dropped on every page, not
//	            merged, and are no mismatch; an indexer that lost a repo leaves the repo's tried set. A refusal sends the
//	            repo on and is remembered RemoteRefusedTimeout. A coverage that names a repo the leg did not, or misses
//	            one it did, fails the leg; a leg that serves no repo is ended
//	failure     no reply by the deadline (page 0 at once, since it is never sent twice under one search_id; a later page
//	            after it is asked once more, RemotePageRetryCount); an envelope Error (RESOURCE_EXHAUSTED skips the
//	            indexer for max(retry_after_ms, RemoteSkipTimeout)); the Hello's identity binding or bit 0 failing
//	            (§11.14's auth row: an alarm, and the indexer dropped until its row or designation changes); INVALID,
//	            UNSUPPORTED_VERSION, no reply, a bad coverage; CURSOR_EXPIRED past RemoteReopenCount. Failing skips the
//	            indexer RemoteSkipTimeout, ends the leg, puts its repos back with it tried, and plans again
//	reopen      CURSOR_EXPIRED on a later page, once a search: a new search_id superseding the old, page 0 over the repos
//	            it still serves, until_ms at the last checked_through_ms of a phase 1 or 2 page; the old leg's hits and
//	            span stay
//	config      every step judges the open legs again in the newest state, mode and answers: a leg whose indexer may no
//	            longer be asked about a repo it asks or serves is ended with no skip, and its repos are planned again
//	seen again  a HelloResult, Pong or session that shows a skipped indexer live clears its skip, and the repos that fell
//	            back from it go back to the plan, once a search for each (RemoteSeenAgainCount)
//
// The open searches this device holds at an indexer stay within RemoteRequesterCursorCount: page 0 supersedes one it
// no longer wants (a closed stream's, a leg's that lost or ended, the leg it reopens), else the older of two. The
// stream's Remote state and fallback reason follow 7.2.4's table. Nothing here persists or logs a query, hit or cursor;
// search.state takes only the served memory and distrust (§5.9).
//
// Safe for concurrent use: the client under its stateLock, each search's state under its own lock, one page at a time.

package sidecar

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A client built without what asking reads.
	errSearchRemoteClientArgs = errors.New("remote search client without its settings, config, services, identity, state or engine")
	// The indexer's identity binding did not verify for its sidecar_id, or its Hello did not show bit 0.
	errSearchRemoteAuth = errors.New("remote search: the indexer's identity or bit 0 did not hold")
	// No reply by a leg's deadline.
	errSearchRemoteTimeout = errors.New("remote search: no reply by the deadline")
	// No transport: no client generation is attached.
	errSearchRemoteNoTransport = errors.New("remote search: no dispatcher attached")
)

// The component the client attaches to each generation as.
const searchAskComponentName = "search-ask"

// What the client sends and asks over: one generation's dispatcher (searchRemoteSubprotocolTransport), or a test's.
type searchRemoteTransport interface {
	// One SEARCH body to the indexer, its Hello first where none stands, checked for the indexer's identity binding and
	// bit 0 before the request goes (errSearchRemoteAuth). The reply's body, or the error.
	Call(ctx context.Context, indexerId Id, body []byte) ([]byte, error)
	// Whether a Hello with the indexer stands, and whether it showed bit 0.
	Peer(indexerId Id) (servesSearch bool, standing bool)
	// Whether a Hello, HelloResult, Ping or Pong showed the indexer live after at.
	SeenSince(indexerId Id, at time.Time) bool
	// Names the warm pairs (Subprotocol.MarkSearchPeers), the own ones first.
	MarkSearchPeers(ctx context.Context, indexerIds []Id) error
	// Tells the dispatcher whether the host is in the foreground (Subprotocol.SetForeground).
	SetForeground(foreground bool)
	// Sets bit 1 toward each indexer asksSearch names (Subprotocol.SetFeatures).
	SetAsksSearch(asksSearch func(indexerId Id) bool) error
}

// What a client reads.
type SearchRemoteClientArgs struct {
	Settings *SidecarSearchSettings
	// SEARCH's wire values: SidecarProtocolSettings.Search.
	Wire *SearchWireSettings
	// This device's newest verified config state, read at every send.
	Config func() (*ConfigState, error)
	// Opens a designation's sealed services (ConfigState.SearchIndexersFor's argument). Required: none opened, none
	// asked.
	Services func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)
	// This device's sidecar_id.
	SelfId func() (Id, bool)
	// The network's search state: the mode, the notice answers, the served memory and distrust.
	State *SidecarSearchState
	// The network's local engine: the device's own search, and the download a repo no indexer answers falls back to.
	Local SidecarSearchEngine
	// The host's conditions: metered or not, which picks RemoteTimeout's value. Nil reads metered.
	Conditions func() SearchConditions
	// The foreground (Sidecar.SearchForeground). Nil reads background.
	Foreground func() (bool, chan struct{})
	// Calls notify at each entry the installed config authority applies (SidecarAuthority.AddEntryCallback), so the warm
	// pairs follow the config's indexers in the foreground; the answer stops it. Nil follows them at
	// Search.ServeRecheckInterval alone.
	ConfigWatch func(notify func()) (stop func())
	// search_alarm and head_alarm's sink (Sidecar.searchEvents and emitEvent). Nil drops.
	Events func(event SidecarEvent)
	// An indexer's config device name, for "verified by <device>". Nil names it by its sidecar_id.
	DeviceName func(sidecarId Id) string
	// The device's own index of a ref: its pin, whether it is a companion, and its ring of replayed versions (the sync
	// engine's manifest). Nil holds none, so no fold rests on a pin and no pin is checked.
	OwnIndex func(repoId Id, refId Id) (SearchSyncPin, bool, []SearchSyncPinPair, bool)
	// Whether this device's ERASE, erasure-set masks or read checks hide a version of a document. Nil hides none.
	Masked func(repoId Id, refId Id, docKey [16]byte, version uint64) bool
	Clock  Clock
	Log    Logger
}

// One network's remote search requester on an app host. See the file header.
type SearchRemoteClient struct {
	args     SearchRemoteClientArgs
	settings *SidecarSearchSettings
	wire     *SearchWireSettings
	clock    Clock
	log      Logger

	stateLock sync.Mutex
	health    map[Id]*searchRemoteHealth
	// the warm own set last named, and the other member's indexer named beside it
	warmOwn   []Id
	warmOther []Id
	warmAt    time.Time
	transport searchRemoteTransport
	// the open searches this device holds at each indexer, oldest first
	open     map[Id][]*searchRemoteOpen
	searches map[*searchRemoteSearch]bool
	closed   bool
}

// One open search at an indexer, and whether this device still wants it.
type searchRemoteOpen struct {
	searchId uint64
	wanted   bool
}

// A client over args.
func NewSearchRemoteClient(args *SearchRemoteClientArgs) (*SearchRemoteClient, error) {
	if args == nil || args.Settings == nil || args.Wire == nil || args.Config == nil || args.Services == nil || args.SelfId == nil ||
		args.State == nil || args.Local == nil {
		return nil, errSearchRemoteClientArgs
	}
	settings := args.Settings
	if settings.RemoteOwnAskCount <= 0 || settings.RemoteRequesterCursorCount <= 0 || settings.RemoteTimeout[0] <= 0 ||
		settings.RemoteTimeout[1] <= 0 || settings.RemoteRequesterRate.Count <= 0 || settings.RemoteRequesterRate.Burst <= 0 ||
		settings.RemoteRequesterRate.Interval <= 0 {
		return nil, fmt.Errorf("%w: the remote search client's limits", errInvalidSettings)
	}
	return &SearchRemoteClient{
		args: *args, settings: settings, wire: args.Wire, clock: clockOrReal(args.Clock), log: loggerOrDefault(args.Log),
		health: map[Id]*searchRemoteHealth{}, open: map[Id][]*searchRemoteOpen{}, searches: map[*searchRemoteSearch]bool{},
	}, nil
}

// The transport now, nil while no generation is attached.
func (self *SearchRemoteClient) currentTransport() searchRemoteTransport {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.transport
}

// Sets the transport, as a generation attaches; nil as it ends.
func (self *SearchRemoteClient) setTransport(transport searchRemoteTransport) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.transport = transport
}

// See SidecarComponent.
func (self *SearchRemoteClient) Name() string {
	return searchAskComponentName
}

// Follows one generation's dispatcher: bit 1 toward the indexers the mode lets this device ask, and the warm pairs at
// each foreground and each change of the mode, the answers or the config while in it. See SidecarComponent.
func (self *SearchRemoteClient) Attach(env *SidecarEnv) error {
	if env.Subprotocol == nil {
		return errors.New("remote search needs the generation's dispatcher")
	}
	transport := newSearchRemoteSubprotocolTransport(env.Subprotocol, env.SidecarApi, self.args.Config, self.clock)
	self.setTransport(transport)
	go func() {
		self.follow(env.Ctx, transport)
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.transport == transport {
			self.transport = nil
		}
	}()
	return nil
}

// Ends every search. See SidecarComponent.
func (self *SearchRemoteClient) Close() {
	searches := func() []*searchRemoteSearch {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		searches := []*searchRemoteSearch{}
		for search := range self.searches {
			searches = append(searches, search)
		}
		return searches
	}()
	for _, search := range searches {
		search.Close()
	}
}

// One search (SidecarSearchEngine): the local engine's alone unless it is "search more" with remote on or own; else a
// remote search over its scope.
func (self *SearchRemoteClient) Search(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
	if request == nil || request.Scope != SearchAll || request.Remote == SearchRemoteOff || request.Remote == "" {
		return self.args.Local.Search(ctx, request)
	}
	search, err := self.newSearch(ctx, request)
	if err != nil {
		return nil, err
	}
	if search == nil {
		local := *request
		local.Remote = SearchRemoteOff
		return self.args.Local.Search(ctx, &local)
	}
	return NewSearchStream(search), nil
}

// A repo's status (SidecarSearchEngine): the local engine's.
func (self *SearchRemoteClient) Status(repoId *Id) (*SearchStatus, error) {
	return self.args.Local.Status(repoId)
}

// The local engine's background window, where it runs one (SidecarSearchBackgroundSync).
func (self *SearchRemoteClient) RunBackgroundSync(ctx context.Context) error {
	if background, ok := self.args.Local.(SidecarSearchBackgroundSync); ok {
		return background.RunBackgroundSync(ctx)
	}
	return ErrSidecarSearchUnavailable
}

// The local engine's cache dropper, every search reading the repo ended first (SidecarSearchCacheDropper).
func (self *SearchRemoteClient) DropCache(repoId *Id) error {
	for _, search := range self.openSearches() {
		if repoId == nil || slices.Contains(search.scope, *repoId) {
			search.Close()
		}
	}
	if dropper, ok := self.args.Local.(SidecarSearchCacheDropper); ok {
		return dropper.DropCache(repoId)
	}
	return ErrSidecarSearchUnavailable
}

// The searches open now.
func (self *SearchRemoteClient) openSearches() []*searchRemoteSearch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	searches := []*searchRemoteSearch{}
	for search := range self.searches {
		searches = append(searches, search)
	}
	return searches
}

// The indexers that may answer this device (SidecarSearchIndexerLister, §18.5's GetIndexers): every designated search
// indexer E1 to E6 lets answer it for some repo it reads, own first, then by rendezvous; Acknowledged and
// ServedRepoIds are CORE's to fill.
func (self *SearchRemoteClient) Indexers() []SearchIndexer {
	state, err := self.args.Config()
	if err != nil || state == nil {
		return nil
	}
	selfId, ok := self.args.SelfId()
	if !ok {
		return nil
	}
	eligible := self.eligibleAnywhere(state, selfId)
	now := self.clock.Now()
	indexers := []SearchIndexer{}
	for _, indexerId := range eligible {
		indexer := SearchIndexer{SidecarId: indexerId, Name: self.deviceName(indexerId), Own: searchRemoteOwn(state, indexerId, selfId), State: "unknown"}
		if memberId, ok := searchRemoteNoticeMember(state, indexerId); ok {
			indexer.MemberId = &memberId
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			health := self.health[indexerId]
			switch {
			case health == nil:
			case now.Before(health.skipUntil) && health.skipReason == SearchFallbackBusy:
				indexer.State = "busy"
			case now.Before(health.skipUntil) || health.dropped:
				indexer.State = "unreachable"
			case now.Before(health.onlineUntil):
				indexer.State = "online"
			}
		}()
		indexers = append(indexers, indexer)
	}
	slices.SortStableFunc(indexers, func(a SearchIndexer, b SearchIndexer) int {
		switch {
		case a.Own && !b.Own:
			return -1
		case b.Own && !a.Own:
			return 1
		}
		return 0
	})
	return indexers
}

// Every indexer E1 to E6 lets answer selfId for some repo it reads, by rendezvous with it.
func (self *SearchRemoteClient) eligibleAnywhere(state *ConfigState, selfId Id) []Id {
	acl, err := state.Acl()
	if err != nil {
		return nil
	}
	seen := map[Id]bool{}
	for repoId := range acl.repos {
		for _, indexerId := range state.SearchIndexersFor(selfId, repoId, self.args.Services) {
			seen[indexerId] = true
		}
	}
	ids := []Id{}
	for indexerId := range seen {
		ids = append(ids, indexerId)
	}
	searchRemoteSortBy(ids, func(indexerId Id) searchRemoteKey {
		return searchRemoteKey{first: 0, second: searchRemoteRendezvous(selfId, indexerId)}
	})
	return ids
}

// An indexer's config device name, else its sidecar_id's text.
func (self *SearchRemoteClient) deviceName(sidecarId Id) string {
	if self.args.DeviceName != nil {
		if name := self.args.DeviceName(sidecarId); name != "" {
			return name
		}
	}
	return sidecarId.String()
}

// RemoteTimeout as the conditions read now: unmetered, else metered.
func (self *SearchRemoteClient) remoteTimeout() time.Duration {
	if self.args.Conditions != nil && !self.args.Conditions().Metered() {
		return self.settings.RemoteTimeout[0]
	}
	return self.settings.RemoteTimeout[1]
}

// Raises an event through the client's sink.
func (self *SearchRemoteClient) raise(event SidecarEvent) {
	if self.args.Events != nil {
		self.args.Events(event)
	}
}

// A random search_id, never 0.
func searchRemoteNewSearchId() uint64 {
	for {
		var buffer [8]byte
		if _, err := rand.Read(buffer[:]); err != nil {
			continue
		}
		if searchId := binary.BigEndian.Uint64(buffer[:]); searchId != 0 {
			return searchId
		}
	}
}

// The search_id page 0 toward indexerId supersedes, and the open list once searchId opens there: a cursor this device
// no longer wants, the oldest first, else the older of two when this would pass RemoteRequesterCursorCount, else 0.
func (self *SearchRemoteClient) openAt(indexerId Id, searchId uint64, supersedes uint64) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	open := self.open[indexerId]
	if supersedes == 0 {
		for _, held := range open {
			if !held.wanted {
				supersedes = held.searchId
				break
			}
		}
	}
	if supersedes == 0 && self.settings.RemoteRequesterCursorCount <= len(open) {
		supersedes = open[0].searchId
	}
	open = slices.DeleteFunc(open, func(held *searchRemoteOpen) bool { return held.searchId == supersedes })
	open = append(open, &searchRemoteOpen{searchId: searchId, wanted: true})
	for self.settings.RemoteRequesterCursorCount < len(open) {
		open = open[1:]
	}
	self.open[indexerId] = open
	return supersedes
}

// Marks searchId at indexerId as no longer wanted, so a later page 0 there supersedes it.
func (self *SearchRemoteClient) unwant(indexerId Id, searchId uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, held := range self.open[indexerId] {
		if held.searchId == searchId {
			held.wanted = false
		}
	}
}

// The filters a request carries on the wire, false where one cannot be said there or the encoding passes
// FiltersMaxByteCount: such a search stays on the device (QD-215, FallbackReason none).
func searchRemoteFiltersOf(filters []SearchFieldFilter, wire *SearchWireSettings) (*protocol.SearchFilters, bool) {
	if len(filters) == 0 {
		return nil, true
	}
	encoded := &protocol.SearchFilters{}
	for _, filter := range filters {
		switch filter.Name {
		case "agent":
			encoded.Agents = append(encoded.Agents, filter.Value)
		case "session":
			encoded.SessionIds = append(encoded.SessionIds, filter.Value)
		case "path_prefix":
			encoded.PathPrefix = filter.Value
		case "sidecar", "member", "run":
			id, err := ParseId(filter.Value)
			if err != nil {
				return nil, false
			}
			switch filter.Name {
			case "sidecar":
				encoded.SidecarIds = append(encoded.SidecarIds, id.Bytes())
			case "member":
				encoded.MemberIds = append(encoded.MemberIds, id.Bytes())
			default:
				encoded.RunIds = append(encoded.RunIds, id.Bytes())
			}
		case "from", "subject", "to", "title":
			encoded.Fields = append(encoded.Fields, &protocol.SearchField{Field: uint32(searchQueryHeaderFields[filter.Name]), Text: filter.Value})
		default:
			return nil, false
		}
	}
	return encoded, proto.Size(encoded) <= wire.FiltersMaxByteCount
}
