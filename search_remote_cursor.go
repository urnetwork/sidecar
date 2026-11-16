//go:build !sidecar_http && !ios_extension

// An indexer's remote search cursors (SEARCH-M10-32; §11.14's exchange, ranking, status and limits rows; R-EVS-25,
// D-EVS-57, D-EVS-59, FI-24, I-13, I-19; DESIGN-DETAILS 7.2.5): per requester, at most RemoteRequesterCursorCount live
// cursors by search_id and the ids it ended, and the page a cursor computes from its watermark.
//
//	page 0, an id in the ended set                       CURSOR_EXPIRED
//	page 0, an id with a live cursor at page 0           that cursor's last reply, unchanged
//	page 0, an id with a live cursor past page 0         INVALID; the cursor is not touched
//	page 0, a new id                                     supersedes, if it names a live cursor of the requester's,
//	                                                     ends it; if the requester then holds its most, the oldest
//	                                                     ends; a new cursor opens
//	page n > 0, no live cursor of that id                CURSOR_EXPIRED
//	page n = the cursor's page                           its last reply, unchanged
//	page n = the cursor's page + 1, the cursor not done  the next page
//	any other page                                       INVALID; the cursor is not touched
//
// A cursor ends when the requester supersedes it or opens one past its most; it idles CursorTimeout; RemoteCursorCount
// is passed over every requester and it is the least recently used (SidecarRemoteBudget.AddCursor); an ERASE, a CUT or
// an executed drop lands in a repo it serves (EndRepo, or a snapshot it holds ending); a later page's authorization
// fails; or the server closes. Ending frees its snapshots, drops its last reply and puts its id in the requester's ended
// set for CursorTimeout, so no page of it, page 0 included, is ever computed again (7.1's E).
//
// The page, from the cursor's watermark W, the whole of its position:
//
//	K          up to PageCandidateCount candidates of the text-served repos after W, newest first by (time, the repo's
//	           place, doc_key), and the one after them (the corpus's CandidatesAfter)
//	verify     each of K in order until HitMaxCount hits are held, the page's CPU or verifications are spent, or K is
//	           exhausted: a match is a hit, and a candidate whose text this device does not hold at that version is a
//	           hit as a phone would judge it
//	reply      by Z6 with head(k): W' is the watermark just before hit k + 1 when hits were held back for size, else
//	           just after the last candidate examined; checked_through_ms the time of the first candidate after W', or
//	           0 when there is none; phase 1 while that candidate is newer than every all row served, 2 once all is in
//	           play, 3 with none; status OK when the page stopped at its hits, at the end of K with none left or for
//	           size, PARTIAL when it stopped on its budget with candidates left; complete once no candidate is after
//	           W' and the tail is exhausted
//	tail       after the candidates, the hits of repos served from the index, which claim no span
//	too broad  the corpus's verdict, the first time a pass counts a partition past TooBroadCandidateCount: the reply
//	           holds what display fields confirm and the counts, complete true, and moves no span
//
// So checked_through_ms claims one thing: every candidate of the cursor's text-served repos with a time above it was
// examined, and is in a page already sent exactly when it matched. Nothing here is persisted or logged: the cursor
// lives in memory with its query and last reply, and a log line names no query, hit, snippet, cursor or count (I-13).
//
// Safe for concurrent use: the table under its stateLock, each cursor's pages under its pageLock.

package sidecar

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What step 4 of a request does with its cursor table.
type searchRemoteCursorAction int

const (
	searchRemoteCursorExpired searchRemoteCursorAction = iota + 1
	searchRemoteCursorInvalid
	searchRemoteCursorRepeat
	searchRemoteCursorOpen
	searchRemoteCursorNext
)

// One live remote search at this indexer. Its fields past the ids are its pageLock's.
type searchRemoteCursor struct {
	requesterId Id
	searchId    uint64
	openedAt    time.Time

	pageLock sync.Mutex
	// the page last given, and whether no later page holds a hit
	page uint32
	done bool
	// set when the cursor ends, under the table's lock, and read under either lock
	ended atomic.Bool
	// what page 0 asked: its steps, query and repos
	steps int
	query *searchRemoteQuery
	repos []*searchRemoteCursorRepo
	view  searchRemoteView
	// the place every candidate before which is accounted for, and the last page's claim
	watermark        searchWatermark
	checkedThroughMs int64
	// running totals over the cursor (§11.14's counts)
	counts searchRemoteCounts
	// the corpus said too broad: the cursor's work is over
	tooBroad bool
	// every candidate is accounted for; the tail's hits taken but not yet sent; the tail is exhausted
	candidatesDone bool
	tailHeld       []*protocol.SearchHit
	tailDone       bool
	lastReply      []byte

	// the table's: when it was last used
	usedAt time.Time
	// its place in the budget's least recently used list, set once the cursor is in the table
	budgetLock sync.Mutex
	touch      func()
	release    func()
}

// Takes the cursor off the budget's list, once its place there is known; a cursor that ended before it was placed is
// taken off as it is placed.
func (self *searchRemoteCursor) releaseBudget() {
	self.budgetLock.Lock()
	release := self.release
	self.release = nil
	self.budgetLock.Unlock()
	if release != nil {
		release()
	}
}

// One repo a cursor's page 0 named: its coverage row, and where it stands in the request.
type searchRemoteCursorRepo struct {
	repoId Id
	// empty: the repo's default ref
	refId []byte
	place uint16
	row   *protocol.SearchCoverage
}

// One requester's cursors and the ids it ended.
type searchRemoteRequesterCursors struct {
	live  map[uint64]*searchRemoteCursor
	ended map[uint64]time.Time
}

// Every requester's cursors at this indexer. See the file header.
type searchRemoteTable struct {
	settings *SidecarSearchSettings
	clock    Clock
	// the daemon's cursors over every requester, least recently used ending first; nil keeps no global bound
	budget *SidecarRemoteBudget

	stateLock  sync.Mutex
	requesters map[Id]*searchRemoteRequesterCursors
	closed     bool
}

// A table under settings' CursorTimeout, RemoteRequesterCursorCount and RemoteEndedIdCount, its global bound budget's.
func newSearchRemoteTable(settings *SidecarSearchSettings, clock Clock, budget *SidecarRemoteBudget) *searchRemoteTable {
	return &searchRemoteTable{settings: settings, clock: clock, budget: budget, requesters: map[Id]*searchRemoteRequesterCursors{}}
}

// The requester's cursors, made on first use.
func (self *searchRemoteTable) requesterWithLock(requesterId Id) *searchRemoteRequesterCursors {
	requester := self.requesters[requesterId]
	if requester == nil {
		requester = &searchRemoteRequesterCursors{live: map[uint64]*searchRemoteCursor{}, ended: map[uint64]time.Time{}}
		self.requesters[requesterId] = requester
	}
	return requester
}

// Ends what idled CursorTimeout and forgets ended ids past it, with the table's lock held. Answers the cursors it
// ended, whose views the caller closes outside the lock.
func (self *searchRemoteTable) sweepWithLock(now time.Time) []*searchRemoteCursor {
	ended := []*searchRemoteCursor{}
	for requesterId, requester := range self.requesters {
		for _, cursor := range requester.live {
			if self.settings.CursorTimeout <= now.Sub(cursor.usedAt) {
				ended = append(ended, self.endWithLock(requester, cursor, now))
			}
		}
		for searchId, endedAt := range requester.ended {
			if self.settings.CursorTimeout <= now.Sub(endedAt) {
				delete(requester.ended, searchId)
			}
		}
		if len(requester.live) == 0 && len(requester.ended) == 0 {
			delete(self.requesters, requesterId)
		}
	}
	return ended
}

// Takes cursor out of the live set into the ended set, bounded by RemoteEndedIdCount, the oldest going first, with the
// table's lock held. The caller closes it outside the lock (closeEnded).
func (self *searchRemoteTable) endWithLock(requester *searchRemoteRequesterCursors, cursor *searchRemoteCursor, now time.Time) *searchRemoteCursor {
	delete(requester.live, cursor.searchId)
	cursor.ended.Store(true)
	requester.ended[cursor.searchId] = now
	for self.settings.RemoteEndedIdCount < len(requester.ended) {
		oldestId, oldestAt := uint64(0), time.Time{}
		first := true
		for searchId, endedAt := range requester.ended {
			if first || endedAt.Before(oldestAt) || endedAt.Equal(oldestAt) && searchId < oldestId {
				oldestId, oldestAt, first = searchId, endedAt, false
			}
		}
		delete(requester.ended, oldestId)
	}
	return cursor
}

// Frees what each ended cursor held: its views, last reply and place in the budget. Outside every lock.
func (self *searchRemoteTable) closeEnded(cursors []*searchRemoteCursor) {
	for _, cursor := range cursors {
		key := func() string {
			cursor.pageLock.Lock()
			defer cursor.pageLock.Unlock()
			if cursor.view != nil {
				cursor.view.Close()
				cursor.view = nil
			}
			cursor.lastReply = nil
			cursor.tailHeld = nil
			cursor.query = nil
			return cursor.barrierKey()
		}()
		testHookBarrier("search.remote.ended", key)
		cursor.releaseBudget()
	}
}

// Step 4: what a parsed request of requesterId's does, and its cursor where it names a live one. A new id at page 0
// is opened here, its supersedes and the requester's most applied; its page is computed by the caller under the
// cursor's pageLock.
func (self *searchRemoteTable) lookup(requesterId Id, request *protocol.SearchRequest) (searchRemoteCursorAction, *searchRemoteCursor) {
	now := self.clock.Now()
	var action searchRemoteCursorAction
	var cursor *searchRemoteCursor
	ended := func() []*searchRemoteCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ended := self.sweepWithLock(now)
		if self.closed {
			action = searchRemoteCursorExpired
			return ended
		}
		requester := self.requesterWithLock(requesterId)
		searchId, page := request.GetSearchId(), request.GetPage()
		live := requester.live[searchId]
		if page == 0 {
			_, wasEnded := requester.ended[searchId]
			switch {
			case wasEnded:
				action = searchRemoteCursorExpired
			case live != nil:
				// a repeat of page 0, or INVALID where the cursor is past it, which repeat judges under its pageLock
				action, cursor = searchRemoteCursorRepeat, live
			default:
				if superseded := requester.live[request.GetSupersedes()]; superseded != nil && request.GetSupersedes() != searchId {
					ended = append(ended, self.endWithLock(requester, superseded, now))
				}
				for self.settings.RemoteRequesterCursorCount <= len(requester.live) {
					oldest := (*searchRemoteCursor)(nil)
					for _, held := range requester.live {
						if oldest == nil || held.openedAt.Before(oldest.openedAt) || held.openedAt.Equal(oldest.openedAt) && held.searchId < oldest.searchId {
							oldest = held
						}
					}
					ended = append(ended, self.endWithLock(requester, oldest, now))
				}
				cursor = &searchRemoteCursor{requesterId: requesterId, searchId: searchId, openedAt: now, usedAt: now}
				requester.live[searchId] = cursor
				action = searchRemoteCursorOpen
			}
		} else {
			switch {
			case live == nil:
				action = searchRemoteCursorExpired
			default:
				// the page is judged under the cursor's pageLock, where a page in flight is seen whole (decide)
				action, cursor = searchRemoteCursorNext, live
			}
		}
		if cursor != nil && action != searchRemoteCursorInvalid {
			cursor.usedAt = now
		}
		return ended
	}()
	self.closeEnded(ended)
	if action == searchRemoteCursorOpen && self.budget != nil {
		touch, release := self.budget.AddCursor(func() { self.end(cursor) })
		func() {
			cursor.budgetLock.Lock()
			defer cursor.budgetLock.Unlock()
			cursor.touch, cursor.release = touch, release
		}()
		if cursor.ended.Load() {
			cursor.releaseBudget()
		}
	}
	if cursor != nil && action != searchRemoteCursorInvalid {
		cursor.budgetLock.Lock()
		touch := cursor.touch
		cursor.budgetLock.Unlock()
		if touch != nil {
			touch()
		}
	}
	return action, cursor
}

// A later page's verdict, with the cursor's pageLock held: a repeat of the cursor's page, the next one while it is not
// done, else INVALID; an ended cursor is CURSOR_EXPIRED.
func (self *searchRemoteCursor) decideWithLock(page uint32) searchRemoteCursorAction {
	switch {
	case self.ended.Load():
		return searchRemoteCursorExpired
	case page == self.page && self.lastReply != nil:
		return searchRemoteCursorRepeat
	case page == self.page+1 && !self.done:
		return searchRemoteCursorNext
	}
	return searchRemoteCursorInvalid
}

// Ends cursor if it is still live.
func (self *searchRemoteTable) end(cursor *searchRemoteCursor) {
	ended := func() []*searchRemoteCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		requester := self.requesters[cursor.requesterId]
		if requester == nil || requester.live[cursor.searchId] != cursor {
			return nil
		}
		return []*searchRemoteCursor{self.endWithLock(requester, cursor, self.clock.Now())}
	}()
	self.closeEnded(ended)
}

// Ends every live cursor that serves repoId: an ERASE, a CUT or an executed drop landed there.
func (self *searchRemoteTable) endRepo(repoId Id) {
	ended := func() []*searchRemoteCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		now := self.clock.Now()
		ended := []*searchRemoteCursor{}
		for _, requester := range self.requesters {
			for _, cursor := range requester.live {
				if cursor.serves(repoId) {
					ended = append(ended, self.endWithLock(requester, cursor, now))
				}
			}
		}
		return ended
	}()
	self.closeEnded(ended)
}

// Ends every cursor, for good.
func (self *searchRemoteTable) close() {
	ended := func() []*searchRemoteCursor {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		now := self.clock.Now()
		ended := []*searchRemoteCursor{}
		for _, requester := range self.requesters {
			for _, cursor := range requester.live {
				ended = append(ended, self.endWithLock(requester, cursor, now))
			}
		}
		return ended
	}()
	self.closeEnded(ended)
}

// The live cursors of requesterId, for tests and the budget's count.
func (self *searchRemoteTable) liveCount(requesterId Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if requester := self.requesters[requesterId]; requester != nil {
		return len(requester.live)
	}
	return 0
}

// Sets the cursor's repos once page 0 has decided them, under the table's lock, where an erasure's endRepo reads them.
func (self *searchRemoteTable) setRepos(cursor *searchRemoteCursor, repos []*searchRemoteCursorRepo) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	cursor.repos = repos
}

// Whether the cursor serves repoId, with the table's lock held. Its repos are set once, at page 0, under it.
func (self *searchRemoteCursor) serves(repoId Id) bool {
	for _, repo := range self.repos {
		if repo.repoId == repoId && searchRemoteServes(protocol.SearchServed(repo.row.GetServed())) {
			return true
		}
	}
	return false
}

// The barrier key of the cursor's pages: its first served repo and ref, else empty.
func (self *searchRemoteCursor) barrierKey() string {
	for _, repo := range self.repos {
		if searchRemoteServes(protocol.SearchServed(repo.row.GetServed())) {
			return repo.repoId.String() + "/" + Id(repo.row.GetRefId()).String()
		}
	}
	return ""
}

// A cursor's running totals (§11.14's counts): candidates checked, and the verified and possible hits among them. Kept
// apart from the message, which is not a value to copy.
type searchRemoteCounts struct {
	checked  uint32
	verified uint32
	possible uint32
	near     uint32
	masked   uint32
}

// As the reply carries them.
func (self searchRemoteCounts) message() *protocol.SearchCounts {
	return &protocol.SearchCounts{Checked: self.checked, Verified: self.verified, Possible: self.possible, Near: self.near, Masked: self.masked}
}

// One candidate a page examined, and what it found.
type searchRemoteExamined struct {
	candidate *searchRemoteCandidate
	hit       *protocol.SearchHit
	// what it adds to the counts: checked always, and verified or possible as it judged
	verified bool
	possible bool
}

// The next page of cursor, with its pageLock held: computed within meter, built by Z6 at steps and the cursor's
// position moved to what the reply accounts for. Answers the reply's body.
func (self *SearchRemoteServer) computePageWithLock(ctx context.Context, cursor *searchRemoteCursor, page uint32, meter *SidecarRemotePage) ([]byte, error) {
	settings, wire := self.settings, self.wire
	view := cursor.view
	examined := []*searchRemoteExamined{}
	hitCount := 0
	var next *searchRemoteCandidate
	// why the candidate pass stopped: at its hits, its budget with candidates left, or at the end of K
	stoppedOnBudget := false
	tooBroadNow := false
	candidates := []*searchRemoteCandidate{}
	if !cursor.candidatesDone && !cursor.tooBroad && view != nil {
		var err error
		var tooBroad bool
		candidates, next, tooBroad, err = view.CandidatesAfter(ctx, cursor.watermark, settings.PageCandidateCount)
		if err != nil {
			return nil, err
		}
		tooBroadNow = tooBroad
	}
	if tooBroadNow {
		return self.tooBroadPageWithLock(ctx, cursor, page, candidates)
	}
	for _, candidate := range candidates {
		if hitCount == wire.HitMaxCount {
			break
		}
		if !meter.Verify() {
			stoppedOnBudget = true
			break
		}
		hit, matched, err := view.Verify(ctx, candidate)
		if err != nil {
			return nil, err
		}
		item := &searchRemoteExamined{candidate: candidate}
		if matched && hit != nil {
			if kept, ok := searchRemoteKeepHit(hit, wire); ok {
				item.hit = kept
				hitCount += 1
				item.verified = kept.GetState() == uint32(SearchVerified)
				item.possible = kept.GetState() == uint32(SearchPossible)
			}
		}
		examined = append(examined, item)
	}
	// the candidate after the last examined, which says where the order goes on
	firstAfterExamined := next
	if len(examined) < len(candidates) {
		firstAfterExamined = candidates[len(examined)]
	}
	candidatesLeft := firstAfterExamined != nil
	// the tail, once every candidate is examined: the hits of repos served from the index
	tailHits := slices.Clone(cursor.tailHeld)
	// with nothing served there is no tail
	tailDone := cursor.tailDone || view == nil
	if !candidatesLeft && hitCount < wire.HitMaxCount && !stoppedOnBudget && view != nil {
		for !tailDone && hitCount+len(tailHits) < wire.HitMaxCount {
			taken, done, err := view.Tail(ctx, wire.HitMaxCount-hitCount-len(tailHits))
			if err != nil {
				return nil, err
			}
			for _, hit := range taken {
				if kept, ok := searchRemoteKeepHit(hit, wire); ok {
					tailHits = append(tailHits, kept)
				}
			}
			tailDone = done
			if len(taken) == 0 {
				break
			}
		}
	}

	// the hits in reply order; for each candidate hit its candidate, the place just before it and the counts there
	hits := []*protocol.SearchHit{}
	hitCandidates := []*searchRemoteCandidate{}
	placesBefore := []searchWatermark{}
	prefixCounts := []searchRemoteCounts{}
	counts := cursor.counts
	before := cursor.watermark
	for _, item := range examined {
		if item.hit != nil {
			hits = append(hits, item.hit)
			hitCandidates = append(hitCandidates, item.candidate)
			placesBefore = append(placesBefore, before)
			prefixCounts = append(prefixCounts, counts)
		}
		counts.checked += 1
		if item.verified {
			counts.verified += 1
		}
		if item.possible {
			counts.possible += 1
		}
		before = item.candidate.place
	}
	candidateHitCount := len(hits)
	allCounts := counts
	lastExamined := before
	hits = append(hits, tailHits...)
	allNewestMs := int64(0)
	if view != nil {
		allNewestMs = view.AllNewestMs()
	}
	phaseOf := func(first *searchRemoteCandidate) uint32 {
		switch {
		case first == nil:
			return 3
		case allNewestMs < first.place.timeMs:
			return 1
		}
		return 2
	}

	// where the cursor stands after a reply of k hits, and head(k), pure functions of k
	type position struct {
		watermark        searchWatermark
		first            *searchRemoteCandidate
		checkedThroughMs int64
		counts           searchRemoteCounts
		complete         bool
		tailSent         int
	}
	positionOf := func(hitCount int) position {
		if hitCount < candidateHitCount {
			// a candidate hit held back for size: W' stops just before it, and the order goes on there
			first := hitCandidates[hitCount]
			return position{watermark: placesBefore[hitCount], first: first, checkedThroughMs: first.place.timeMs, counts: prefixCounts[hitCount]}
		}
		tailSent := hitCount - candidateHitCount
		checkedThroughMs := int64(0)
		if firstAfterExamined != nil {
			checkedThroughMs = firstAfterExamined.place.timeMs
		}
		return position{
			watermark: lastExamined, first: firstAfterExamined, checkedThroughMs: checkedThroughMs, counts: allCounts,
			complete: !candidatesLeft && tailDone && tailSent == len(tailHits), tailSent: tailSent,
		}
	}
	head := func(hitCount int) *protocol.SearchReply {
		at := positionOf(hitCount)
		status := protocol.SearchStatus_SEARCH_OK
		if hitCount == len(hits) && stoppedOnBudget && candidatesLeft {
			status = protocol.SearchStatus_SEARCH_PARTIAL
		}
		reply := &protocol.SearchReply{
			SearchVersion: searchVersion, MinVersion: searchVersion, MaxVersion: searchVersion,
			SearchId: cursor.searchId, Page: page, Status: uint32(status), Phase: phaseOf(at.first),
			Complete: at.complete, CheckedThroughMs: at.checkedThroughMs, Counts: at.counts.message(),
		}
		if page == 0 {
			reply.Coverage = cursor.coverageRows()
		}
		return reply
	}
	body, accounted := searchRemoteBuildReply(cursor.steps, hits, head, wire)
	if body == nil {
		return nil, errSearchReplySize
	}
	at := positionOf(accounted)
	cursor.watermark = at.watermark
	cursor.checkedThroughMs = at.checkedThroughMs
	cursor.counts = at.counts
	cursor.candidatesDone = !candidatesLeft && accounted >= candidateHitCount
	cursor.tailHeld = slices.Clone(tailHits[at.tailSent:])
	cursor.tailDone = tailDone
	cursor.done = at.complete
	cursor.page = page
	cursor.lastReply = body
	return body, nil
}

// The page that finds the cursor too broad: what display fields confirm among the candidates, the counts, complete
// true, and no span moved, the earlier pages' claim standing. The cursor's work is over.
func (self *SearchRemoteServer) tooBroadPageWithLock(ctx context.Context, cursor *searchRemoteCursor, page uint32, candidates []*searchRemoteCandidate) ([]byte, error) {
	wire := self.wire
	hits := []*protocol.SearchHit{}
	for _, candidate := range candidates {
		if len(hits) == wire.HitMaxCount {
			break
		}
		hit, confirmed := candidate.headerHit()
		if !confirmed {
			continue
		}
		if kept, ok := searchRemoteKeepHit(hit, wire); ok {
			hits = append(hits, kept)
		}
	}
	counts := cursor.counts
	counts.checked += uint32(len(candidates))
	head := func(hitCount int) *protocol.SearchReply {
		reply := &protocol.SearchReply{
			SearchVersion: searchVersion, MinVersion: searchVersion, MaxVersion: searchVersion,
			SearchId: cursor.searchId, Page: page, Status: uint32(protocol.SearchStatus_SEARCH_TOO_BROAD),
			Phase: 3, Complete: true, CheckedThroughMs: cursor.checkedThroughMs, Counts: counts.message(),
		}
		if page == 0 {
			reply.Coverage = cursor.coverageRows()
		}
		return reply
	}
	body, _ := searchRemoteBuildReply(cursor.steps, hits, head, wire)
	if body == nil {
		return nil, errSearchReplySize
	}
	cursor.tooBroad = true
	cursor.counts = counts
	cursor.done = true
	cursor.page = page
	cursor.lastReply = body
	return body, nil
}

// The coverage rows page 0 carries: one per repo the request named, in its order.
func (self *searchRemoteCursor) coverageRows() []*protocol.SearchCoverage {
	rows := make([]*protocol.SearchCoverage, 0, len(self.repos))
	for _, repo := range self.repos {
		rows = append(rows, repo.row)
	}
	return rows
}
