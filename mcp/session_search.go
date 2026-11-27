//go:build !js && !ios && !android && !sdk_mobile_bind

// One MCP session's search (§16.4's sessions row, §16.10's limits and pages rows; MCP-M10-02; R-MCP-12, D-MCP-25,
// FS-80), from Search's settings:
//
//	session   one search session id for the session's life: the key of its cursors, its limits and its hit ids in
//	          every network's engine, so a cursor or a hit id another session got opens nothing here, and none of
//	          this session's opens anything there
//	count     at most Search.SessionSearchCount searches at once, a search being a call of search, a page of a
//	          cursor included, or of search_agents; inside §16.4's SessionCallCount calls in flight, since a search
//	          holds its call's slot while it waits and while it runs
//	rate      at most Search.SessionSearchRate new searches, a token bucket of Count an Interval with its Burst; a
//	          page of a cursor starts no search, so it takes no token
//	wait      a search past either waits up to its wait_ms on the server's clock, then answers busy, retryable; a
//	          wait of 0 answers busy at once, and a token taken for a search that then found no slot is given back
//	networks  the count and the rate are the session's across every network it searches in; each network's engine
//	          keeps the session's cursors under its one id, at most Search.SessionCursorCount there, the oldest dropped
//	end       a session's cursors end with it (D-MCP-25): at its close each network's search it ran in ends its
//	          search session there, closing its streams and forgetting its hit ids and its limits; a search still
//	          running at the close ends it again once it returns, and no search starts after the close
//
// The engine admits a session of its own by the same settings (search_limits.go), and never binds a call this file
// admitted: its bucket refills as this one does and sees no more searches. Time is the server's Clock, so a test
// moves it and never sleeps. Safe for concurrent use.

package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// What ends one search session's cursors in a network's engine: *sidecar.SearchTools.
type McpSearchSessions interface {
	EndSession(session sidecar.Id)
}

var _ McpSearchSessions = (*sidecar.SearchTools)(nil)

// The session's search was refused because the session has ended.
var errMcpSearchSessionEnded = NewMcpError(McpCodeFailed, "the session ended, and its searches with it", false)

// One session's search: its id, its slots and rate, and the networks it searched in.
type mcpSessionSearch struct {
	settings  *sidecar.SidecarSearchSettings
	clock     sidecar.Clock
	sessionId sidecar.Id
	// a token held per search running
	slots chan struct{}
	// called when a search finds no token or no slot and is about to wait: a test's seam, nil otherwise
	waitHook func()

	stateLock sync.Mutex
	// the rate's tokens as of refilledTime
	tokens       float64
	refilledTime time.Time
	// each network the session searched in, by the search that keeps its cursors there
	networkIdSearches map[sidecar.Id]McpSearchSessions
	ended             bool
}

// A session's search, its bucket full.
func newMcpSessionSearch(settings *sidecar.SidecarSearchSettings, clock sidecar.Clock) *mcpSessionSearch {
	return &mcpSessionSearch{
		settings:          settings,
		clock:             clock,
		sessionId:         sidecar.NewId(),
		slots:             make(chan struct{}, max(settings.SessionSearchCount, 0)),
		tokens:            float64(settings.SessionSearchRate.Burst),
		refilledTime:      clock.Now(),
		networkIdSearches: map[sidecar.Id]McpSearchSessions{},
	}
}

// The session's search session id: what its cursors, limits and hit ids are kept under in every network's engine.
func (self *McpSession) SearchSessionId() sidecar.Id {
	return self.search.sessionId
}

// Takes one of the session's searches for a call, newSearch for one that starts a search rather than paging a
// cursor: a rate token, then a slot, each waited for up to wait on the server's clock and then refused with a
// retryable busy error; the session's end, or ctx's, refuses it too. The answer releases the slot. The search tools
// call it before they search (tools_search.go).
func (self *McpSession) AdmitSearch(ctx context.Context, wait time.Duration, newSearch bool) (func(), error) {
	return self.search.admit(ctx, wait, newSearch)
}

// Notes that the session searched in networkId through search, so the session's close ends its cursors there, and
// ends them at once where the session closed meanwhile: a search that ran on past the close leaves none behind.
func (self *McpSession) noteSearch(networkId sidecar.Id, search McpSearch) {
	ender, ok := search.(McpSearchSessions)
	if !ok {
		return
	}
	ended := func() bool {
		self.search.stateLock.Lock()
		defer self.search.stateLock.Unlock()
		self.search.networkIdSearches[networkId] = ender
		return self.search.ended
	}()
	if ended {
		ender.EndSession(self.search.sessionId)
	}
}

// Ends the session's searches: each network's engine it searched in ends its cursors and forgets its hit ids and its
// limits, and no search of the session starts after. The server calls it as the session closes.
func (self *McpSession) endSearch() {
	enders := func() []McpSearchSessions {
		self.search.stateLock.Lock()
		defer self.search.stateLock.Unlock()
		self.search.ended = true
		enders := make([]McpSearchSessions, 0, len(self.search.networkIdSearches))
		for _, ender := range self.search.networkIdSearches {
			enders = append(enders, ender)
		}
		return enders
	}()
	for _, ender := range enders {
		ender.EndSession(self.search.sessionId)
	}
}

// See AdmitSearch.
func (self *mcpSessionSearch) admit(ctx context.Context, wait time.Duration, newSearch bool) (func(), error) {
	if self.isEnded() {
		return nil, errMcpSearchSessionEnded
	}
	// the wait runs from the call's start, on the clock, whatever it waits on
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.clock.AfterFunc(wait, cancel)
	defer stop()
	waited := func() {
		if self.waitHook != nil {
			self.waitHook()
		}
	}
	if newSearch {
		for {
			ok, tokenAt := self.takeToken()
			if ok {
				break
			}
			if wait <= 0 {
				return nil, errMcpSearchBusy
			}
			came := make(chan struct{})
			// for the time the token comes itself (QD-1425)
			stopToken := sidecar.ClockAfterFuncAt(self.clock, tokenAt, func() { close(came) })
			waited()
			select {
			case <-waitCtx.Done():
				stopToken()
				return nil, errMcpSearchBusy
			case <-came:
			}
		}
	}
	refund := func() {
		if newSearch {
			self.giveToken()
		}
	}
	select {
	case self.slots <- struct{}{}:
	default:
		if wait <= 0 {
			refund()
			return nil, errMcpSearchBusy
		}
		waited()
		select {
		case self.slots <- struct{}{}:
		case <-waitCtx.Done():
			refund()
			return nil, errMcpSearchBusy
		}
	}
	if self.isEnded() {
		<-self.slots
		refund()
		return nil, errMcpSearchSessionEnded
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-self.slots
		})
	}, nil
}

// Whether the session ended.
func (self *mcpSessionSearch) isEnded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ended
}

// Takes one of the rate's tokens, or answers when one comes.
func (self *mcpSessionSearch) takeToken() (bool, time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rate := self.settings.SessionSearchRate
	if rate.Count <= 0 || rate.Interval <= 0 {
		// no rate admits nothing
		return false, self.clock.Now().Add(rate.Interval)
	}
	perToken := rate.Interval / time.Duration(rate.Count)
	now := self.refillWithLock()
	if 1 <= self.tokens {
		self.tokens -= 1
		return true, time.Time{}
	}
	return false, now.Add(max(time.Duration((1-self.tokens)*float64(perToken)), time.Nanosecond))
}

// Gives back a token taken for a search that never ran.
func (self *mcpSessionSearch) giveToken() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refillWithLock()
	self.tokens = min(self.tokens+1, float64(self.settings.SessionSearchRate.Burst))
}

// Adds what the rate gave since the last refill, up to its burst, and answers the reading of the clock it refilled at.
func (self *mcpSessionSearch) refillWithLock() time.Time {
	rate := self.settings.SessionSearchRate
	now := self.clock.Now()
	if elapsed := now.Sub(self.refilledTime); 0 < elapsed && 0 < rate.Interval {
		self.tokens = min(float64(rate.Burst), self.tokens+float64(rate.Count)*float64(elapsed)/float64(rate.Interval))
		self.refilledTime = now
	}
	return now
}

// Searches running now.
func (self *mcpSessionSearch) runningCount() int {
	return len(self.slots)
}
