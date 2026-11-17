//go:build !sidecar_http && !ios_extension

// Remote search's order (SEARCH-M10-33; §11.14's who, eligible, auth, order, failover and limits rows; D-SDK-27, FI-24,
// I-3; DESIGN-DETAILS 7.2.3 as amended for QD-707): which indexer a search asks for which repo, read from this device's
// newest verified config state in the step that builds the requests, never from a list made earlier (7.1's J).
//
//	assign  for each repo still to plan, in the scope's order: own(R), the own indexers E1 to E7 let answer it that are
//	        usable, by ownKey; other(R), the rest, by otherKey. Mode off: the fallback. Own indexers: the members of the
//	        warm own set W that can be asked for it, one or two, asked at once (QD-707); else the first own indexer
//	        alone. Else, in mode on, the first other member's indexer once its notice member's answer allows, else the
//	        repo waits on that notice in the fallback. Else the fallback, for the reason the last indexer tried failed
//	usable  not tried by this search for the repo, not skipped, distrusted or dropped, the repo not refused there within
//	        RemoteRefusedTimeout, and one more request inside RemoteRequesterRate by this device's own count
//	ownKey  (0 for the own indexer that answered last within RemoteOnlineTimeout, else 1; H(p, d))
//	otherKey (0 and the newest time it served a repo of the search's scope within RemoteServedTimeout, else 1;
//	        H(p's member, d)), so another member's queries over a set of repos reach one other device
//	H       the first 8 bytes, big-endian, of SHA-256("UR search rendezvous 1" || a || b), the ids' 16 raw bytes
//
// Nothing else is asked beside another indexer: never a third own one, never another member's beside anything. An own
// indexer outside W is asked only alone, and its pair opens at the search, as a failover's does (owner decision 191).
// The per-indexer health below lives in RAM only: online, answered, skipped and dropped, mismatches, refused repos and
// the request rate. The served memory and distrust live in search.state (§5.9). None of it names a query.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"slices"
	"time"
)

// H's label (DESIGN-DETAILS 7.2.3).
const searchRemoteRendezvousLabel = "UR search rendezvous 1"

// H(a, b): the rendezvous hash of two ids, ascending.
func searchRemoteRendezvous(a Id, b Id) uint64 {
	hash := sha256.New()
	hash.Write([]byte(searchRemoteRendezvousLabel))
	hash.Write(a[:])
	hash.Write(b[:])
	return binary.BigEndian.Uint64(hash.Sum(nil)[:8])
}

// Why a repo fell back (§18.5's FallbackReason, DESIGN-DETAILS 7.2.4).
const (
	SearchFallbackOff         = "off"
	SearchFallbackNotice      = "notice"
	SearchFallbackNone        = "none"
	SearchFallbackOffline     = "offline"
	SearchFallbackBusy        = "busy"
	SearchFallbackRefused     = "refused"
	SearchFallbackUnreachable = "unreachable"
)

// A stream's remote states (§18.5, DESIGN-DETAILS 7.2.4).
const (
	SearchRemoteStateOff      = "off"
	SearchRemoteStateAsking   = "asking"
	SearchRemoteStateNotice   = "notice"
	SearchRemoteStateAnswered = "answered"
	SearchRemoteStatePartial  = "partial"
	SearchRemoteStateFallback = "fallback"
)

// What the asker knows of one indexer, in memory (DESIGN-DETAILS 7.2.3's state).
type searchRemoteHealth struct {
	// a HelloResult, Pong or valid page keeps it online until this
	onlineUntil time.Time
	// its last valid page
	answeredAt time.Time
	// not asked until this; when the skip was set, and why
	skipUntil  time.Time
	skippedAt  time.Time
	skipReason string
	// its identity binding or bit 0 failed: not asked until its row or designation changes, which droppedAs names
	dropped   bool
	droppedAs string
	// mismatches within RemoteMismatchInterval
	mismatches []time.Time
	// repos it refused, each not asked of it until the time
	refusedUntil map[Id]time.Time
	// RemoteRequesterRate by this device's own count
	tokens   float64
	tokensAt time.Time
}

// The health of indexerId, made on first use, with the client's lock held.
func (self *SearchRemoteClient) healthWithLock(indexerId Id) *searchRemoteHealth {
	health := self.health[indexerId]
	if health == nil {
		rate := self.settings.RemoteRequesterRate
		health = &searchRemoteHealth{refusedUntil: map[Id]time.Time{}, tokens: float64(rate.Burst), tokensAt: self.clock.Now()}
		self.health[indexerId] = health
	}
	return health
}

// Whether one more request to the indexer is inside RemoteRequesterRate by this device's count, with the lock held.
func (self *searchRemoteHealth) rateAllowsWithLock(now time.Time, rate SidecarRate) bool {
	if elapsed := now.Sub(self.tokensAt); 0 < elapsed {
		self.tokens = min(float64(rate.Burst), self.tokens+float64(rate.Count)*float64(elapsed)/float64(rate.Interval))
		self.tokensAt = now
	}
	return 1 <= self.tokens
}

// What naming a dropped indexer's state means: its admission row and designations as this state holds them, which a
// change of either moves.
func searchRemoteDropMark(state *ConfigState, indexerId Id) string {
	mark := ""
	if sidecar := state.Sidecar(indexerId); sidecar != nil && sidecar.Row != nil {
		mark = fmt.Sprintf("%x/%d/%d", sidecar.Row.GetAdmissionSha256(), sidecar.Row.GetRevokedAt(), sidecar.Row.GetParkedAt())
	}
	for _, indexer := range state.Indexers() {
		if indexer.SidecarId == indexerId {
			mark += fmt.Sprintf("/%d@%d", indexer.Scope, indexer.At)
		}
	}
	return mark
}

// One search's view of the order: what the plan reads besides the config.
type searchRemoteOrderView struct {
	state    *ConfigState
	selfId   Id
	memberId Id
	mode     string
	// the warm own set the foreground last named, less what the state no longer lets answer
	warm []Id
	// the own indexer that answered last within RemoteOnlineTimeout, if any
	lastOwn    Id
	hasLastOwn bool
	// for otherKey: the newest time each indexer served a repo of the search's scope
	servedAt map[Id]time.Time
	// the repo's E1 to E6 answer, asked once per repo
	eligible map[Id][]Id
}

// The indexers E1 to E6 let answer repoId for this device, in the view's state.
func (self *SearchRemoteClient) eligibleFor(view *searchRemoteOrderView, repoId Id) []Id {
	if indexers, ok := view.eligible[repoId]; ok {
		return indexers
	}
	indexers := view.state.SearchIndexersFor(view.selfId, repoId, self.args.Services)
	view.eligible[repoId] = indexers
	return indexers
}

// E7 on the asker: where a Hello of the pair stands, the indexer must have shown bit 0 in it.
func (self *SearchRemoteClient) showsBitZero(indexerId Id) bool {
	transport := self.currentTransport()
	if transport == nil {
		return false
	}
	serves, standing := transport.Peer(indexerId)
	return !standing || serves
}

// ownKey and otherKey as sortable pairs: the first part, then H.
type searchRemoteKey struct {
	first  int64
	second uint64
}

// Whether the key sorts before other: by its first part, then by H.
func (self searchRemoteKey) less(other searchRemoteKey) bool {
	if self.first != other.first {
		return self.first < other.first
	}
	return self.second < other.second
}

// ownKey(d).
func (self *searchRemoteOrderView) ownKey(indexerId Id) searchRemoteKey {
	first := int64(1)
	if self.hasLastOwn && self.lastOwn == indexerId {
		first = 0
	}
	return searchRemoteKey{first: first, second: searchRemoteRendezvous(self.selfId, indexerId)}
}

// otherKey(d).
func (self *searchRemoteOrderView) otherKey(indexerId Id) searchRemoteKey {
	if at, ok := self.servedAt[indexerId]; ok {
		return searchRemoteKey{first: -at.UnixMilli(), second: 0}
	}
	return searchRemoteKey{first: 1, second: searchRemoteRendezvous(self.memberId, indexerId)}
}

// Sorts ids by key.
func searchRemoteSortBy(ids []Id, key func(Id) searchRemoteKey) {
	slices.SortStableFunc(ids, func(a Id, b Id) int {
		keyA, keyB := key(a), key(b)
		switch {
		case keyA.less(keyB):
			return -1
		case keyB.less(keyA):
			return 1
		}
		return a.Cmp(b)
	})
}

// own(R) and other(R) for one repo of search, in the view: the indexers E1 to E7 let answer it that are usable, each
// sorted by its key. tried is the search's set for the repo.
func (self *SearchRemoteClient) candidatesFor(view *searchRemoteOrderView, repoId Id, tried map[Id]bool, now time.Time) (own []Id, other []Id) {
	for _, indexerId := range self.eligibleFor(view, repoId) {
		if !self.showsBitZero(indexerId) || !self.usable(view.state, indexerId, repoId, tried, now) {
			continue
		}
		if searchRemoteOwn(view.state, indexerId, view.selfId) {
			own = append(own, indexerId)
		} else {
			other = append(other, indexerId)
		}
	}
	searchRemoteSortBy(own, view.ownKey)
	searchRemoteSortBy(other, view.otherKey)
	return own, other
}

// usable(d, R) (the file header).
func (self *SearchRemoteClient) usable(state *ConfigState, indexerId Id, repoId Id, tried map[Id]bool, now time.Time) bool {
	if tried[indexerId] {
		return false
	}
	if distrust, err := self.args.State.DistrustUntil(indexerId); err != nil || now.Before(distrust) {
		// a state that cannot be read fails closed
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	health := self.healthWithLock(indexerId)
	if health.dropped {
		if health.droppedAs == searchRemoteDropMark(state, indexerId) {
			return false
		}
		// its row or designation changed since: asked again
		health.dropped = false
	}
	if now.Before(health.skipUntil) || now.Before(health.refusedUntil[repoId]) {
		return false
	}
	return health.rateAllowsWithLock(now, self.settings.RemoteRequesterRate)
}

// The order view of a search now: the newest verified state, the mode, the warm own set and the memories.
func (self *SearchRemoteClient) orderView(scope []Id) (*searchRemoteOrderView, error) {
	state, err := self.args.Config()
	if err != nil || state == nil {
		return nil, ErrSidecarSearchUnavailable
	}
	selfId, ok := self.args.SelfId()
	if !ok {
		return nil, ErrSidecarSearchUnavailable
	}
	view := &searchRemoteOrderView{state: state, selfId: selfId, mode: self.mode(), servedAt: map[Id]time.Time{}, eligible: map[Id][]Id{}}
	if sidecar := state.Sidecar(selfId); sidecar != nil && sidecar.Row != nil {
		view.memberId, _ = configRowMember(sidecar.Row)
	}
	now := self.clock.Now()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		latest := time.Time{}
		for indexerId, health := range self.health {
			if !searchRemoteOwn(state, indexerId, selfId) || health.answeredAt.IsZero() {
				continue
			}
			if health.answeredAt.After(latest) && now.Sub(health.answeredAt) < self.settings.RemoteOnlineTimeout {
				latest, view.lastOwn, view.hasLastOwn = health.answeredAt, indexerId, true
			}
		}
		for _, indexerId := range self.warmOwn {
			if searchRemoteOwn(state, indexerId, selfId) {
				view.warm = append(view.warm, indexerId)
			}
		}
	}()
	inScope := map[Id]bool{}
	for _, repoId := range scope {
		inScope[repoId] = true
	}
	for _, indexer := range state.Indexers() {
		if _, ok := view.servedAt[indexer.SidecarId]; ok {
			continue
		}
		served, err := self.args.State.Served(indexer.SidecarId)
		if err != nil {
			continue
		}
		for repoId, at := range served {
			if inScope[repoId] && at.After(view.servedAt[indexer.SidecarId]) {
				view.servedAt[indexer.SidecarId] = at
			}
		}
	}
	return view, nil
}

// What the plan decides for one repo: the indexers asked at once (one, or the two warm own ones), or the fallback with
// its reason and, for a notice, the indexer it names.
type searchRemoteAssignment struct {
	targets  []Id
	fallback string
	notice   Id
}

// The plan's choice for one repo (the file header). lastReason is the reason the last indexer tried for it failed.
func (self *SearchRemoteClient) assign(view *searchRemoteOrderView, repoId Id, tried map[Id]bool, lastReason string, now time.Time) searchRemoteAssignment {
	if view.mode == SearchRemoteOff {
		return searchRemoteAssignment{fallback: SearchFallbackOff}
	}
	own, other := self.candidatesFor(view, repoId, tried, now)
	if 0 < len(own) {
		both := []Id{}
		for _, indexerId := range own {
			if slices.Contains(view.warm, indexerId) && len(both) < self.settings.RemoteOwnAskCount {
				both = append(both, indexerId)
			}
		}
		if 0 < len(both) {
			return searchRemoteAssignment{targets: both}
		}
		return searchRemoteAssignment{targets: own[:1]}
	}
	if view.mode == SearchRemoteOn && 0 < len(other) {
		indexerId := other[0]
		memberId, ok := searchRemoteNoticeMember(view.state, indexerId)
		if ok {
			if allow, answered := self.answer(memberId); answered && allow {
				return searchRemoteAssignment{targets: []Id{indexerId}}
			}
		}
		return searchRemoteAssignment{fallback: SearchFallbackNotice, notice: indexerId}
	}
	if lastReason == "" {
		lastReason = SearchFallbackNone
	}
	return searchRemoteAssignment{fallback: lastReason}
}
