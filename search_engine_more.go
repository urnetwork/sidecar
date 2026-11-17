//go:build !ios_extension

// A search's "search more" (§16.10's cold contract and async row; D-MCP-20, I-19, FI-23; SEARCH-M10-20,
// SEARCH-M10-26; QD-999): scope all's download of every all shard the search's refs lack runs on a goroutine of its
// own, a window, while the search's pages search each shard as it lands and give the caller its hits as soon as they
// rank, so §16.10's arrival bound holds on delivery to the caller.
//
//	window    a page that reaches the download with no window running begins one: SearchMore calls ref by ref in the
//	          search's order, a call stopped at MoreByteCount followed by the next from its cursor, until every ref is
//	          complete, a call waits (metered), fails or leaves a newer head's shard, the search ends, or
//	          Search.PageCpu has passed since the window began, which bounds it as the page that held the download
//	          before QD-999 bounded it
//	blind     what the window fetches, and when, is the device's sync state's and the clock's alone: it waits for no
//	          page, stops at no hit, and runs on after the page that began it answers, so where the matches lie shows
//	          the server nothing (I-19, D-MCP-20, FI-23). Stopping the download at a hit's shard and resuming it on the
//	          next page would show it: by the pause there, and by the head check the resumed call's round makes first
//	arrival   a landed shard is queued for the pages, never searched on the window's goroutine; a page waiting on the
//	          download takes the queue at once, matches and ranks each shard, and answers as soon as it holds a hit,
//	          the download going on meanwhile (QD-999)
//	reports   the window's progress reaches a caller only through a page waiting on the download, on the page's
//	          goroutine, so none comes after its page returns; between pages the latest stands in the next page's
//	          progress
//	idle      whether a page waits on the download with nothing left to take, which a fake clock's world reads
//	          before each read (search_schedule_testhooks.go), so a read's time passes only while the search has
//	          nothing else to do
//
// A window does outside the page what the page did inside it before QD-999, and holds none of Search.DaemonSearchCount's
// slots. Safe for concurrent use: the window's goroutine and the pages share what stateLock guards.

package sidecar

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
)

// Why the last window ended.
type searchMoreEnd int

const (
	// None has ended yet, or one runs.
	searchMoreEndNone searchMoreEnd = iota
	// Search.PageCpu passed since it began.
	searchMoreEndTime
	// Every ref's missing shards are searched.
	searchMoreEndFinished
	// A call waits on AllowMetered.
	searchMoreEndWaiting
	// A call failed.
	searchMoreEndFailed
	// A call ended neither complete nor partial, leaving a newer head's shard, which the next window fetches.
	searchMoreEndStalled
	// The search ended.
	searchMoreEndClosed
)

// One all shard a window landed, for a page to search.
type searchMoreLanded struct {
	ref  *searchOpenedRef
	file SearchManifestFile
	// The window's call that landed it: one call's landed shards judge the keys its snapshot's table lacks together
	// (matchLanded).
	call int
}

// A search's download state as a page or a test reads it.
type searchEngineMoreState struct {
	// The latest report of the running or last call.
	progress SearchMoreProgress
	waiting  string
	// Each ref whose missing shards are all searched.
	finished map[[2]Id]bool
	running  bool
	ended    searchMoreEnd
	// A window's failure, which take answers once.
	err error
}

// A search's download and what it landed (see the file header).
type searchEngineMore struct {
	stateLock sync.Mutex
	// Per ref: its cursor, and whether every shard it lacked is searched.
	cursors  map[[2]Id]*SearchMoreCursor
	finished map[[2]Id]bool
	progress SearchMoreProgress
	waiting  string
	// A page relayed the latest progress.
	relayed bool
	// A window's failure, which the next page answers once.
	err     error
	running bool
	ended   searchMoreEnd
	// Closed once the running or last window's goroutine returns.
	done      chan struct{}
	callCount int
	// Landed shards no page has taken yet, in landing order.
	landed []*searchMoreLanded
	// A page waits on the download and has taken everything it gave.
	pageWaiting bool
	// Closed and replaced on every change, under stateLock (the monitor contract).
	notify chan struct{}
}

// A search's download before its first window.
func newSearchEngineMore() *searchEngineMore {
	return &searchEngineMore{
		cursors: map[[2]Id]*SearchMoreCursor{}, finished: map[[2]Id]bool{}, relayed: true, notify: make(chan struct{}),
	}
}

func (self *searchEngineMore) notifyWithLock() {
	close(self.notify)
	self.notify = make(chan struct{})
}

// The state now and a channel that closes on its next change, taken together.
func (self *searchEngineMore) state() (searchEngineMoreState, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.stateWithLock(), self.notify
}

func (self *searchEngineMore) stateWithLock() searchEngineMoreState {
	return searchEngineMoreState{
		progress: self.progress, waiting: self.waiting, finished: maps.Clone(self.finished), running: self.running,
		ended: self.ended, err: self.err,
	}
}

// What a page takes: every landed shard queued, and the state, its failure answered once, with a channel that closes
// on the next change.
func (self *searchEngineMore) take() ([]*searchMoreLanded, searchEngineMoreState, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	landed, state := self.landed, self.stateWithLock()
	self.landed, self.err = nil, nil
	return landed, state, self.notify
}

// Gives landed back, first in the queue: what a page took and could not search.
func (self *searchEngineMore) giveBack(landed []*searchMoreLanded) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.landed = append(slices.Clone(landed), self.landed...)
	self.pageWaiting = false
	self.notifyWithLock()
}

// Queues a shard the window landed for the pages.
func (self *searchEngineMore) queue(landed *searchMoreLanded) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.landed = append(self.landed, landed)
	self.pageWaiting = false
	self.notifyWithLock()
}

// A call's progress report, for a waiting page to relay.
func (self *searchEngineMore) reported(progress SearchMoreProgress) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.progress, self.waiting, self.relayed = progress, progress.Waiting, false
	self.pageWaiting = false
	self.notifyWithLock()
}

// Whether the latest progress is still to relay, marking it relayed.
func (self *searchEngineMore) takeRelay() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	relay := !self.relayed
	self.relayed = true
	return relay
}

// The ref whose call goes next, the first in the search's order with shards to search, its cursor and the call's
// number; nil once every ref is finished.
func (self *searchEngineMore) nextCall(refs []*searchOpenedRef) (*searchOpenedRef, *SearchMoreCursor, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, ref := range refs {
		key := [2]Id{ref.repoId, ref.refId}
		if !self.finished[key] {
			self.callCount += 1
			return ref, self.cursors[key], self.callCount
		}
	}
	return nil, nil, 0
}

// A call ended: its cursor goes on, and its last progress stands.
func (self *searchEngineMore) endCall(key [2]Id, cursor *SearchMoreCursor, progress SearchMoreProgress) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cursors[key] = cursor
	self.progress, self.waiting, self.relayed = progress, progress.Waiting, false
	if progress.Complete {
		self.finished[key] = true
	}
	self.pageWaiting = false
	self.notifyWithLock()
}

// Every ref of keys finished, with nothing fetched: a search with no policy reads all as held.
func (self *searchEngineMore) finishAll(keys [][2]Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, key := range keys {
		self.finished[key] = true
	}
	self.notifyWithLock()
}

// A window's failure, which the next page answers.
func (self *searchEngineMore) fail(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.err = err
	self.pageWaiting = false
	self.notifyWithLock()
}

// Marks a window begun unless one runs or ended is done: false then, with nothing changed.
func (self *searchEngineMore) beginWindow(ended context.Context, done chan struct{}) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ended.Err() != nil || self.running {
		return false
	}
	self.running, self.ended, self.done, self.waiting = true, searchMoreEndNone, done, ""
	self.pageWaiting = false
	self.notifyWithLock()
	return true
}

// Marks the running window ended.
func (self *searchEngineMore) endWindow(end searchMoreEnd) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.running, self.ended = false, end
	self.pageWaiting = false
	self.notifyWithLock()
}

// Waits for the running window's goroutine, if one runs, to return. Called once its context is ending.
func (self *searchEngineMore) join() {
	self.stateLock.Lock()
	done := self.done
	self.stateLock.Unlock()
	if done != nil {
		<-done
	}
}

// Waits, as a page with nothing left to take, for the download's next change, ctx's end or ended's: at once where the
// state changed since notify was taken. Errs only as ctx or ended ends.
func (self *searchEngineMore) waitIdle(ctx context.Context, ended context.Context, notify chan struct{}) error {
	changed := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.notify != notify {
			return nil
		}
		self.pageWaiting = true
		self.notifyWithLock()
		return self.notify
	}()
	if changed == nil {
		return nil
	}
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.pageWaiting {
			self.pageWaiting = false
			self.notifyWithLock()
		}
	}()
	select {
	case <-changed:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-ended.Done():
		return ended.Err()
	}
}

// Whether a page waits on the download with nothing left to take, and a channel that closes on the next change.
func (self *searchEngineMore) idle() (bool, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pageWaiting, self.notify
}

// The search's refs as keys.
func (self *searchEngineStream) refKeys() [][2]Id {
	keys := make([][2]Id, 0, len(self.refs))
	for _, ref := range self.refs {
		keys = append(keys, [2]Id{ref.repoId, ref.refId})
	}
	return keys
}

// Whether every ref's missing shards are searched, by finished (or the search does not fetch).
func (self *searchEngineStream) allFinished(finished map[[2]Id]bool) bool {
	if self.request.Scope != SearchAll {
		return true
	}
	for _, key := range self.refKeys() {
		if !finished[key] {
			return false
		}
	}
	return true
}

// Phase 2's next partitions from "search more", on the page, within ctx: each shard landed since, searched now and
// queued in landing order, the first begun; else, where the page holds a hit, false at once, so no hit waits on the
// download (QD-999); else waits for the next landing, the window's end or ctx's. A window is begun where none runs, so
// the download goes on whatever the page answers. False where nothing begins now: every ref finished, a wait, a
// stall, ctx's end or the search's.
func (self *searchEngineStream) awaitMore(ctx context.Context, holding bool) (bool, error) {
	more := self.more
	if self.engine.args.Policy == nil {
		// no policy, no fetch: all is searched as held, and coverage says what it lacks
		more.finishAll(self.refKeys())
		return false, nil
	}
	begun := false
	for {
		if ctx.Err() != nil {
			// what landed waits for the next page
			return false, nil
		}
		landed, state, notify := more.take()
		for index, item := range landed {
			if err := self.searchLanded(item); err != nil {
				more.giveBack(landed[index:])
				return false, err
			}
		}
		if 0 < len(self.pending) {
			input := self.pending[0]
			self.pending = self.pending[1:]
			return true, self.begin([]*searchRankInput{input})
		}
		if state.err != nil {
			return false, state.err
		}
		if self.allFinished(state.finished) {
			return false, nil
		}
		if !state.running {
			if self.lifetime.Err() != nil || (begun && state.ended != searchMoreEndTime) {
				// the window this page began ended in its answer: a wait, a stall or the search's end
				return false, nil
			}
			if !self.beginWindow() {
				return false, nil
			}
			begun = true
			continue
		}
		if holding {
			// a hit waits on no download: the page answers it, the window going on without the page
			return false, nil
		}
		if self.report != nil && more.takeRelay() {
			self.report(self.progressNow())
		}
		if err := more.waitIdle(ctx, self.lifetime, notify); err != nil {
			return false, nil
		}
	}
}

// Searches one landed shard for the query on the page: matched and queued as a phase-2 partition. The match runs within
// the search's life rather than the page's, so a page whose time ends drops no shard its window already counted
// searched.
func (self *searchEngineStream) searchLanded(landed *searchMoreLanded) error {
	ref := landed.ref
	if landed.call != self.landedCall {
		self.landedCall, self.landedShards = landed.call, nil
	}
	source, err := ref.landedSource(self.lifetime, &landed.file)
	if err != nil || source == nil {
		return err
	}
	self.landedShards = append(self.landedShards, source.shards...)
	input, err := ref.matchLanded(self.query, source, self.landedShards, self.step)
	if err != nil {
		return err
	}
	self.step += 1
	self.pending = append(self.pending, input)
	return nil
}

// Begins a window on its own goroutine (see the file header): false where the search ended, true where one runs.
func (self *searchEngineStream) beginWindow() bool {
	more := self.more
	ctx, cancel := context.WithCancel(self.lifetime)
	done := make(chan struct{})
	if !more.beginWindow(self.lifetime, done) {
		cancel()
		state, _ := more.state()
		return state.running
	}
	timeUp := &atomic.Bool{}
	stop := self.engine.clock.AfterFunc(self.engine.args.Settings.PageCpu, func() {
		timeUp.Store(true)
		cancel()
	})
	go func() {
		defer close(done)
		end := self.runWindow(ctx, timeUp)
		stop()
		cancel()
		more.endWindow(end)
	}()
	return true
}

// One window's calls, until ctx ends or one ends the window: why it ended.
func (self *searchEngineStream) runWindow(ctx context.Context, timeUp *atomic.Bool) searchMoreEnd {
	engine, more := self.engine, self.more
	for {
		if ctx.Err() != nil {
			if timeUp.Load() {
				return searchMoreEndTime
			}
			return searchMoreEndClosed
		}
		ref, cursor, call := more.nextCall(self.refs)
		if ref == nil {
			return searchMoreEndFinished
		}
		search, err := NewSearchMore(&SearchMoreArgs{
			Sync: engine.args.Sync, Policy: engine.args.Policy, Settings: engine.args.Settings, RepoId: ref.repoId, RefId: ref.refId,
			AllowMetered: self.request.AllowMetered, Cursor: cursor, Clock: engine.clock,
			OnShard: func(ctx context.Context, file *SearchManifestFile) error {
				more.queue(&searchMoreLanded{ref: ref, file: *file, call: call})
				return nil
			},
			OnProgress: more.reported,
		})
		if err != nil {
			more.fail(err)
			return searchMoreEndFailed
		}
		progress, err := search.Run(ctx)
		more.endCall([2]Id{ref.repoId, ref.refId}, search.Cursor(), progress)
		switch {
		case err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded):
			more.fail(err)
			return searchMoreEndFailed
		case ctx.Err() != nil:
			// the top says why
		case progress.Waiting != "":
			return searchMoreEndWaiting
		case progress.Complete, progress.Partial:
			// the next ref, or this one's next call from its cursor
		default:
			return searchMoreEndStalled
		}
	}
}
