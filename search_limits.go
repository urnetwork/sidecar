//go:build !ios_extension

// Search's limits (§16.10's limits row; D-MCP-21, D-MCP-25; SEARCH-M10-26), from §5.4's Search fields:
//
//	session  Search.SessionSearchCount calls at once a session and Search.SessionSearchRate new searches, each past
//	         either waiting until its context's deadline (wait_ms), then answering ErrSearchBusy, retryable;
//	         Search.SessionCursorCount open cursors, the oldest dropped (search_cursor.go)
//	daemon   Search.DaemonSearchCount calls at once on this engine; a page within Search.PageCpu, charged as a compute
//	         slot's busy time on the engine's clock (QD-420's reading), and Search.PageCandidateCount candidates
//	         checked; a partition past Search.TooBroadCandidateCount answers too_broad
//	result   Search.PageByteCount of hits a page; a hit's fields and snippet within their caps
//
// A call holds one daemon slot and one of its session's from its start to its page's return. Waits are on channels
// and the engine's clock, never a sleep. Safe for concurrent use.

package sidecar

import (
	"context"
	"sync"
	"time"
)

// A session no caller named: the daemon's own calls (ur search, a control-mode method), one session together.
var searchLocalSession = Id{}

// The engine's admission.
type searchLimits struct {
	settings *SidecarSearchSettings
	clock    Clock
	// Search.DaemonSearchCount slots.
	daemon chan struct{}

	stateLock sync.Mutex
	sessions  map[Id]*searchSessionLimits
}

// One session's slots and rate.
type searchSessionLimits struct {
	slots chan struct{}
	// The rate's tokens, as of refilledAt.
	tokens     float64
	refilledAt time.Time
}

// The engine's admission over settings.
func newSearchLimits(settings *SidecarSearchSettings, clock Clock) *searchLimits {
	return &searchLimits{
		settings: settings,
		clock:    clock,
		daemon:   make(chan struct{}, settings.DaemonSearchCount),
		sessions: map[Id]*searchSessionLimits{},
	}
}

// The session's limits, made on first use.
func (self *searchLimits) sessionOf(session Id) *searchSessionLimits {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	limits := self.sessions[session]
	if limits == nil {
		limits = &searchSessionLimits{
			slots:      make(chan struct{}, self.settings.SessionSearchCount),
			tokens:     float64(self.settings.SessionSearchRate.Burst),
			refilledAt: self.clock.Now(),
		}
		self.sessions[session] = limits
	}
	return limits
}

// Takes one of the rate's tokens for a new search of session, or answers how long until one comes.
func (self *searchLimits) takeToken(limits *searchSessionLimits) (bool, time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rate := self.settings.SessionSearchRate
	now := self.clock.Now()
	perToken := rate.Interval / time.Duration(rate.Count)
	if elapsed := now.Sub(limits.refilledAt); 0 < elapsed {
		limits.tokens = min(float64(rate.Burst), limits.tokens+float64(elapsed)/float64(perToken))
		limits.refilledAt = now
	}
	if 1 <= limits.tokens {
		limits.tokens -= 1
		return true, 0
	}
	return false, time.Duration((1 - limits.tokens) * float64(perToken))
}

// Admits one call of session: a new search takes a rate token first; then a session slot and a daemon slot, each
// waited for until ctx ends, which answers ErrSearchBusy. The answer releases both slots.
func (self *searchLimits) admit(ctx context.Context, session Id, newSearch bool) (func(), error) {
	limits := self.sessionOf(session)
	if newSearch && session != searchLocalSession {
		for {
			ok, wait := self.takeToken(limits)
			if ok {
				break
			}
			select {
			case <-ctx.Done():
				return nil, ErrSearchBusy
			case <-self.clock.After(wait):
			}
		}
	}
	select {
	case limits.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ErrSearchBusy
	}
	select {
	case self.daemon <- struct{}{}:
	case <-ctx.Done():
		<-limits.slots
		return nil, ErrSearchBusy
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-self.daemon
			<-limits.slots
		})
	}, nil
}

// A page's context: ctx, ended at Search.PageCpu on the engine's clock as well. The answer releases its timer.
func (self *searchLimits) pageContext(ctx context.Context) (context.Context, func()) {
	pageCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(self.settings.PageCpu, cancel)
	return pageCtx, func() {
		stop()
		cancel()
	}
}
