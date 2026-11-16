//go:build !sidecar_http && !ios_extension

// Remote search, serving (SEARCH-M10-32; §11.14's serve, eligible, ranking, status and limits rows; R-EVS-25, R-CORE-19,
// D-CORE-17, D-EVS-57, D-EVS-58, D-PROTO-21, FI-24, I-13, I-19, FS-83, R-CTX-37; DESIGN-DETAILS 7.2.2, 7.2.5 and 7.7):
// SearchRemoteServer.Handle answers a designated daemon's SEARCH requests, which CORE-M10-05's search-serve component
// registers beneath rpc_search.go's size rules. Each request runs these steps in order, and the order is part of the
// design: nothing before step 3 reads the body, so nothing a relay can see before then depends on a query.
//
//	1 class      on a control contract SEARCH is accepted only while this side sets bit 0 (rpc_contract_class.go)
//	2 before parsing, each a small envelope Error:
//	     UNAUTHENTICATED     §6.4's identity binding of the caller q does not stand
//	     PERMISSION_DENIED   in this device's newest verified state q fails E3, or this device holds no search
//	                         designation that stands, or Search.RemoteServe is off
//	     RESOURCE_EXHAUSTED  q is past RemoteRequesterRate, RemoteCpuPerMinute is spent, or no compute slot frees within
//	                         RemoteQueueTimeout (SidecarRemoteBudget.Admit), retry_after_ms saying when
//	3 the body   Z8 (b) to (f): INVALID, or UNSUPPORTED_VERSION, as a reply by Z7
//	4 the cursor table (search_remote_cursor.go)
//	5 authorize  in the newest verified state: at page 0 each repo named, by 7.2.2, to a coverage row; at a later page q
//	             and each repo the cursor serves, one that fails ending the cursor: CURSOR_EXPIRED
//	6 pin        at page 0, per repo served: the index snapshot and the text view, held until the cursor ends
//	7 the page   computed within PageCpu and PageCandidateCount, built by Z6 with head(k), stored as the cursor's last
//	             reply, then barrier search.remote.reply, then sent
//
// A request holds its compute slot from step 2 to the end; a repeat gives it back at step 4, computing nothing. A
// failure after parsing is Z7's padded reply, never an Error.
//
// What serving never does: it reads nothing from evs, api or gkm, with a hint pending or not, and starts no sync (the
// corpus reads only the snapshots and text views this device holds, and opens kept records with keys already in its key
// store); it runs outside every MCP session and run, on the dispatcher's handler goroutines, so it taints none; it
// persists and logs no query, hit, snippet, cursor or count. The one thing written is §5.9's served record, {requester,
// repo, time}, at page 0 once a search, when the requester reads an owner-bound repo only by an EvsShare. Phones never
// serve: app hosts set Search.RemoteServe false.
//
// The corpus is what an indexer serves from: SearchEngine's (search_remote_corpus.go) on a daemon, a fake in tests.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A server built without what serving reads.
	errSearchRemoteServerArgs = errors.New("remote search server without its settings, config, services, identity, budget or corpus")
	// The corpus cannot run the query as sent: a query that normalizes past §16.10's caps, or a filter it cannot apply.
	// Answered INVALID in the padded reply, and the requester falls back.
	errSearchRemoteQuery = errors.New("remote search: a query or filter this indexer cannot run")
)

// The query of one cursor as page 0 carried it, held in memory for the cursor's life and never written or logged.
type searchRemoteQuery struct {
	text string
	// scope 2: buckets, then all
	scopeAll bool
	// inclusive bounds on a row's time, 0 for none
	sinceMs int64
	untilMs int64
	filters *protocol.SearchFilters
	fuzzy   bool
}

// One ref a cursor asks the corpus to serve.
type searchRemoteRefAsk struct {
	repoId Id
	// empty: the repo's default ref
	refId []byte
	// the repo's place in the request, which breaks time ties in the candidate order
	place uint16
}

// What the corpus says of one ref asked: rows 4 to 8 of 7.2.2, and the coverage row's fields for a ref it serves.
type searchRemoteRefRow struct {
	served protocol.SearchServed
	// the ref served: the one named, or the repo's default
	refId Id
	// the text pin when served from text; the index pin when served from the index and the index rides the content
	// ref; else 0, empty and 0
	refVersion uint64
	chain      []byte
	refTimeMs  int64
	// the first instant of the oldest bucket the snapshot holds, retained ones included
	latestFromMs int64
	// the content ref's pushes up to the pin that neither a validated index file nor the local layer covers
	uncovered uint32
}

// One candidate of the order, as a page examines it.
type searchRemoteCandidate struct {
	place searchWatermark
	// the hit as a phone would judge it from its row alone, confirmed by its display fields or else possible, and
	// whether its display fields confirm it; what a too-broad page gives
	header          *protocol.SearchHit
	headerConfirmed bool
	// the corpus's own handle on it
	handle any
}

// The hit display fields confirm, where they do.
func (self *searchRemoteCandidate) headerHit() (*protocol.SearchHit, bool) {
	return self.header, self.headerConfirmed && self.header != nil
}

// What an indexer serves remote searches from (DESIGN-DETAILS 7.7): its snapshots and text views, never a fetch.
type searchRemoteCorpus interface {
	// Opens one cursor's view of refs, each a repo rows 1 to 3 let through: its row 4 to 8, and for the refs it serves
	// the snapshot and text view, held until the view closes. errSearchRemoteQuery for a query or filter it cannot run.
	Open(ctx context.Context, query *searchRemoteQuery, refs []searchRemoteRefAsk) (searchRemoteView, []searchRemoteRefRow, error)
}

// One cursor's view of what it serves. Used under the cursor's pageLock, one page at a time.
type searchRemoteView interface {
	// Up to k candidates of the text-served refs after watermark, in 7.2.5's order, each its document's current entry,
	// not erased and inside since and until; the one after them, nil where none is left; and whether the pass counted
	// a partition past TooBroadCandidateCount, once, at page 0 for the buckets and at the first pass that reads an all
	// shard.
	CandidatesAfter(ctx context.Context, watermark searchWatermark, k int) ([]*searchRemoteCandidate, *searchRemoteCandidate, bool, error)
	// The candidate checked against this device's text: matched, with its hit, verified; or, where the text view does
	// not hold that version, the hit as a phone would judge it, confirmed or possible.
	Verify(ctx context.Context, candidate *searchRemoteCandidate) (*protocol.SearchHit, bool, error)
	// The next of the tail, at most k: the hits of the refs served from the index, confirmed then possible, ranked as a
	// phone ranks them; and whether it is exhausted.
	Tail(ctx context.Context, k int) ([]*protocol.SearchHit, bool, error)
	// The newest time of any row of any all partition of the text-served refs, 0 for none.
	AllNewestMs() int64
	// Whether an ERASE, a CUT or an executed drop ended a snapshot the view holds.
	Ended() bool
	// Releases the snapshots and text views.
	Close()
}

// What a server reads.
type SearchRemoteServerArgs struct {
	Settings *SidecarSearchSettings
	// SEARCH's wire values: SidecarProtocolSettings.Search.
	Wire *SearchWireSettings
	// This device's newest verified config state, read at each request.
	Config func() (*ConfigState, error)
	// Opens a designation's sealed services with the config generation's key (ConfigState.SearchIndexersFor's
	// argument). Nil opens none, so nothing is served.
	Services func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)
	// This device's sidecar_id.
	SelfId func() (Id, bool)
	// The daemon's remote budget, through this network's handle (SidecarRemoteBudget.For). Required.
	Budget *SidecarRemoteBudget
	// The network's search state, where the served record is written. Nil writes none, and a repo that would need one
	// is not served.
	State *SidecarSearchState
	// The engine whose snapshots, text views and local layers serving reads (search_remote_corpus.go).
	Engine *SearchEngine
	// The text pin of a content ref this host holds the text of: its mirror's, mounted tree's or bare repository's
	// replay point (§11.11), and the pushes up to it that no validated index file nor the local layer covers. Nil, or
	// false, serves the ref from the index (7.2.2's row 7), claiming no span.
	TextPin func(repoId Id, refId Id) (pin SearchSyncPin, uncovered uint32, ok bool)
	Clock   Clock
	Log     Logger
}

// One network's remote search server on a designated daemon. Safe for concurrent use.
type SearchRemoteServer struct {
	args     SearchRemoteServerArgs
	settings *SidecarSearchSettings
	wire     *SearchWireSettings
	clock    Clock
	log      Logger
	corpus   searchRemoteCorpus
	table    *searchRemoteTable

	closeOnce sync.Once
}

// A server over args, its corpus the engine's.
func NewSearchRemoteServer(args *SearchRemoteServerArgs) (*SearchRemoteServer, error) {
	if args == nil || args.Engine == nil {
		return nil, errSearchRemoteServerArgs
	}
	return newSearchRemoteServer(args, newSearchEngineRemoteCorpus(args.Engine, args.TextPin))
}

// A server over args and corpus, which tests fake.
func newSearchRemoteServer(args *SearchRemoteServerArgs, corpus searchRemoteCorpus) (*SearchRemoteServer, error) {
	if args == nil || args.Settings == nil || args.Wire == nil || args.Config == nil || args.SelfId == nil || args.Budget == nil || corpus == nil {
		return nil, errSearchRemoteServerArgs
	}
	settings := args.Settings
	if settings.CursorTimeout <= 0 || settings.RemoteRequesterCursorCount <= 0 || settings.RemoteEndedIdCount <= 0 ||
		settings.PageCandidateCount <= 0 {
		return nil, fmt.Errorf("%w: the remote search server's limits", errInvalidSettings)
	}
	clock := clockOrReal(args.Clock)
	return &SearchRemoteServer{
		args: *args, settings: settings, wire: args.Wire, clock: clock, log: loggerOrDefault(args.Log), corpus: corpus,
		table: newSearchRemoteTable(settings, clock, args.Budget),
	}, nil
}

// SEARCH's handler: the seven steps of the file header. The answer is the reply's body, or a *SubprotocolError (a
// *SidecarRemoteRefusal for RESOURCE_EXHAUSTED) decided before parsing.
func (self *SearchRemoteServer) Handle(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
	// step 2: the caller's identity, its standing and this device's designation, then the budget; no byte of the body
	if request == nil || request.Peer == nil || request.Peer.SidecarId == (Id{}) {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED}
	}
	requesterId := request.Peer.SidecarId
	state, selfId, ok := self.standing(requesterId)
	if !ok {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_PERMISSION_DENIED}
	}
	admission, err := self.args.Budget.Admit(ctx, requesterId)
	if err != nil {
		var refusal *SidecarRemoteRefusal
		if errors.As(err, &refusal) {
			return nil, refusal
		}
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
	}
	defer admission.Release()

	// step 3: Z8 (b) to (f)
	parsed, status := searchRemoteParseRequest(request.Body, self.wire)
	if status != protocol.SearchStatus_SEARCH_OK {
		return searchRemoteFailureReply(status, parsed, self.wire)
	}

	// step 4
	action, cursor := self.table.lookup(requesterId, parsed)
	switch action {
	case searchRemoteCursorExpired:
		return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED, parsed, self.wire)
	case searchRemoteCursorInvalid:
		return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_INVALID, parsed, self.wire)
	case searchRemoteCursorRepeat:
		admission.Release()
		return self.repeat(cursor, parsed)
	case searchRemoteCursorOpen:
		return self.openPage(ctx, admission, state, selfId, requesterId, cursor, parsed)
	}
	return self.nextPage(ctx, admission, state, selfId, requesterId, cursor, parsed)
}

// Step 2's standing: the newest verified state, in which the requester passes E3 and this device holds a designation
// naming search, with Search.RemoteServe on. False fails closed: no state, no identity, no services.
func (self *SearchRemoteServer) standing(requesterId Id) (*ConfigState, Id, bool) {
	if !self.settings.RemoteServe || self.args.Services == nil {
		return nil, Id{}, false
	}
	selfId, ok := self.args.SelfId()
	if !ok {
		return nil, Id{}, false
	}
	state, err := self.args.Config()
	if err != nil || state == nil {
		return nil, Id{}, false
	}
	if !searchRemoteRequesterStands(state, requesterId) || !searchRemoteServesSearch(state, selfId, self.args.Services) {
		return nil, Id{}, false
	}
	return state, selfId, true
}

// A repeat of the cursor's page: its last reply, unchanged, never computed again. A repeat of page 0 that finds the
// cursor ended, or past page 0, is answered as the table's rows say.
func (self *SearchRemoteServer) repeat(cursor *searchRemoteCursor, request *protocol.SearchRequest) ([]byte, error) {
	cursor.pageLock.Lock()
	defer cursor.pageLock.Unlock()
	switch {
	case cursor.ended:
		return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED, request, self.wire)
	case cursor.page != request.GetPage() || cursor.lastReply == nil:
		return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_INVALID, request, self.wire)
	}
	return cursor.lastReply, nil
}

// Steps 5 to 7 for a new cursor: each repo authorized to its coverage row, the served ones pinned, the served record
// written, then page 0.
func (self *SearchRemoteServer) openPage(ctx context.Context, admission *SidecarRemoteAdmission, state *ConfigState, selfId Id,
	requesterId Id, cursor *searchRemoteCursor, request *protocol.SearchRequest) ([]byte, error) {
	cursor.pageLock.Lock()
	defer cursor.pageLock.Unlock()
	if cursor.ended {
		return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED, request, self.wire)
	}
	query := &searchRemoteQuery{
		text: request.GetQuery(), scopeAll: request.GetScope() == 2, sinceMs: request.GetSinceMs(), untilMs: request.GetUntilMs(),
		filters: request.GetFilters(), fuzzy: request.GetFuzzy(),
	}
	cursor.steps = searchRemoteFailureSteps(request, self.wire)
	cursor.query = query
	// step 5: rows 1 to 3 in this device's state
	asks := []searchRemoteRefAsk{}
	askIndexes := []int{}
	for place, named := range request.GetRepos() {
		repoId, err := IdFromBytes(named.GetRepoId())
		if err != nil {
			self.table.end(cursor)
			return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_INVALID, request, self.wire)
		}
		repo := &searchRemoteCursorRepo{repoId: repoId, refId: named.GetRefId(), place: uint16(place)}
		served, ok := searchRemoteConfigVerdict(state, selfId, requesterId, repoId, self.args.Services)
		repo.row = &protocol.SearchCoverage{RepoId: repoId.Bytes(), RefId: searchRemoteRowRefId(named.GetRefId(), repoId), Served: uint32(served)}
		if ok {
			asks = append(asks, searchRemoteRefAsk{repoId: repoId, refId: named.GetRefId(), place: uint16(place)})
			askIndexes = append(askIndexes, len(cursor.repos))
		}
		cursor.repos = append(cursor.repos, repo)
	}
	// step 6: rows 4 to 8, the snapshots and text views
	if 0 < len(asks) {
		view, rows, err := self.corpus.Open(ctx, query, asks)
		switch {
		case errors.Is(err, errSearchRemoteQuery):
			self.table.end(cursor)
			return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_INVALID, request, self.wire)
		case err != nil:
			self.table.end(cursor)
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
		}
		cursor.view = view
		for i, row := range rows {
			if len(askIndexes) <= i {
				break
			}
			repo := cursor.repos[askIndexes[i]]
			repo.row.Served = uint32(row.served)
			if searchRemoteServes(row.served) {
				repo.row.RefId = row.refId.Bytes()
				repo.row.RefVersion = row.refVersion
				repo.row.Chain = row.chain
				repo.row.RefTimeMs = row.refTimeMs
				repo.row.LatestFromMs = row.latestFromMs
				repo.row.Uncovered = row.uncovered
			}
		}
		// the served record, once a search, for a repo read only by an EvsShare; none written serves it not
		for _, index := range askIndexes {
			repo := cursor.repos[index]
			if !searchRemoteServes(protocol.SearchServed(repo.row.GetServed())) || !searchRemoteSharedRead(state, requesterId, repo.repoId) {
				continue
			}
			if self.args.State == nil || self.args.State.RecordServed(requesterId, repo.repoId) != nil {
				repo.row.Served = uint32(protocol.SearchServed_REFUSED_ALL_ABSENT)
				repo.row.RefVersion, repo.row.Chain, repo.row.RefTimeMs, repo.row.LatestFromMs, repo.row.Uncovered = 0, nil, 0, 0, 0
			}
		}
	}
	return self.pageWithLock(ctx, admission, cursor, request)
}

// Steps 5 to 7 for a later page: the requester and each served repo authorized again, one that fails ending the cursor,
// then the page, or the repeat a page in flight became.
func (self *SearchRemoteServer) nextPage(ctx context.Context, admission *SidecarRemoteAdmission, state *ConfigState, selfId Id,
	requesterId Id, cursor *searchRemoteCursor, request *protocol.SearchRequest) ([]byte, error) {
	cursor.pageLock.Lock()
	switch cursor.decideWithLock(request.GetPage()) {
	case searchRemoteCursorExpired:
		cursor.pageLock.Unlock()
		return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED, request, self.wire)
	case searchRemoteCursorRepeat:
		reply := cursor.lastReply
		cursor.pageLock.Unlock()
		admission.Release()
		return reply, nil
	case searchRemoteCursorInvalid:
		cursor.pageLock.Unlock()
		return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_INVALID, request, self.wire)
	}
	// step 5 at a later page (7.1's K): a read lost since page 0 ends the cursor
	authorized := searchRemoteRequesterStands(state, requesterId)
	for _, repo := range cursor.repos {
		if !authorized || !searchRemoteServes(protocol.SearchServed(repo.row.GetServed())) {
			continue
		}
		if _, ok := searchRemoteConfigVerdict(state, selfId, requesterId, repo.repoId, self.args.Services); !ok {
			authorized = false
		}
	}
	if authorized && cursor.view != nil && cursor.view.Ended() {
		authorized = false
	}
	if !authorized {
		cursor.pageLock.Unlock()
		self.table.end(cursor)
		return searchRemoteFailureReply(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED, request, self.wire)
	}
	defer cursor.pageLock.Unlock()
	return self.pageWithLock(ctx, admission, cursor, request)
}

// Step 7, with the cursor's pageLock held: the page computed and stored as the cursor's last reply, then the barrier,
// then sent. A failure to compute ends the cursor, answered UNAVAILABLE, naming nothing.
func (self *SearchRemoteServer) pageWithLock(ctx context.Context, admission *SidecarRemoteAdmission, cursor *searchRemoteCursor,
	request *protocol.SearchRequest) ([]byte, error) {
	body, err := self.computePageWithLock(ctx, cursor, request.GetPage(), admission.Page())
	if err != nil {
		go self.table.end(cursor)
		if self.log.V(1).Enabled() {
			self.log.Infof("[search]a remote page was not computed: %s", searchRemoteErrorClass(err))
		}
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
	}
	testHookBarrier("search.remote.reply", cursor.barrierKey())
	return body, nil
}

// Ends every cursor that serves repoId, dropping its last reply before it returns: CORE-M10-04's ApplyErase, ApplyCut
// and an executed drop's local deletion call it, so no page sent after the erasure holds what it removed (I5).
func (self *SearchRemoteServer) EndRepo(repoId Id) {
	self.table.endRepo(repoId)
}

// Ends every cursor, for good: the network's serving stopped.
func (self *SearchRemoteServer) Close() {
	self.closeOnce.Do(self.table.close)
}

// A coverage row's ref_id for a repo the request named: the ref named, or where it named none zeros, standing for its
// default ref until the corpus names the ref it serves. Always IdByteCount long, as Z4 holds a row; a refused row says
// nothing of which ref is the repo's default.
func searchRemoteRowRefId(refId []byte, repoId Id) []byte {
	if len(refId) == len(Id{}) {
		return refId
	}
	return make([]byte, len(Id{}))
}

// Whether requesterId reads the owner-bound repoId only as the subject of a live EvsShare, not as a consented device
// of its owner: the read a served record names (§5.9, D-CORE-17).
func searchRemoteSharedRead(state *ConfigState, requesterId Id, repoId Id) bool {
	acl, err := state.Acl()
	if err != nil {
		return false
	}
	repo := acl.Repo(repoId)
	if repo == nil {
		return false
	}
	if ownerBound, _ := searchRemoteKindOf(repo.GetKind()); !ownerBound {
		return false
	}
	ownerId, err := IdFromBytes(repo.GetOwnerMemberId())
	if err != nil {
		return false
	}
	return !acl.ConsentedFor(requesterId, ownerId) && state.evsShareSubject(acl, requesterId, repoId)
}

// A log line's word for an error, which names no query, repo or hit (I-13).
func searchRemoteErrorClass(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	case errors.Is(err, errSearchReplySize):
		return "size"
	}
	return "error"
}
