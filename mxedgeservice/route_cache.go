// §15.15's route projection as the router reads it (D-MAIL-1, I-12, I-14, QD-480, QD-189): Redis
// {mxr_<net>}, which server's model.ProjectMailRoutes writes and nothing here does, behind an in-process
// cache, so a connection never queries Postgres and reads Redis at most once a name each RouteCacheTtl.
//
//	key    {mxr_<net>}, <net> the SNI's routable part (MailRouteName): the label or alias of
//	       mx.<net>.<root>, a scope's <scope>.<net> of mx.<scope>.<net>.<root>, or a custom MX host's full
//	       name. NormalizeSni has held the SNI to lowercase LDH, so no byte of it can leave the key's tag.
//	value  one JSON MailRoute: the network, its label, which the stream target names, the host its
//	       receivers listen at, flags, and the receivers whose key for that host is published, newest
//	       first, which M8's wake hold hints (plan-MAIL-hints #2)
//
// A name with no key routes nothing: a suspended, direct-MX, tombstoned or mail-off network has its key
// deleted by the projection, and its SNI closes in the handshake. So does a value this package cannot
// read, which the next projection rewrites. The cache keeps an answer, a route or none, for
// RouteCacheTtl: a released label stops routing within that of its key's delete (I-14). A Redis error is
// kept for no one, so the next connection asks again, and closes this one in the handshake, the
// temporary failure §15.4 gives anything it cannot route. Concurrent asks for one name share one read,
// which runs on the engine's context inside StoreTimeout, so a session that leaves does not end a read
// another waits on.
//
// Safe for concurrent use.

package mxedgeservice

import (
	"container/list"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// MailRoute.Flags' bits, as the projection sets them.
const (
	// The name is the network's alias, not its label.
	MailRouteFlagAlias uint32 = 1 << iota
	// The name is a Team scope's: Host is mx.<scope>.
	MailRouteFlagScope
	// The name is a strict-mode custom MX host's full name.
	MailRouteFlagCustomHost
)

// The host every network's receivers listen at (§15.5), and its port and namespace in a socket name:
// smtp/25/mx, or smtp/25/mx.<scope> for a scope's. Identifiers of §15.5's name, not limits.
const (
	mailRouteHost       = "mx"
	mailRouteSocketName = "smtp/25/"
)

// One {mxr_<net>} value: what a name routes to.
type MailRoute struct {
	NetworkId sidecar.Id `json:"network_id"`
	// The network's label, which the stream target <label>:smtp/25/<host> names even when the SNI named an
	// alias, since a receiver listens on its network's label (§9.4).
	Label string `json:"label"`
	// mx, or mx.<scope>: the router Finds <network_id>:smtp/25/<host>.
	Host  string `json:"host"`
	Flags uint32 `json:"flags"`
	// The receivers whose key for Host is published, newest first (plan-MAIL-hints #2), which M8's wake
	// hold hints.
	ReceiverSidecarIds []sidecar.Id `json:"receiver_sidecar_ids"`
}

// The socket name the route's receivers listen at: smtp/25/<host>.
func (self *MailRoute) SocketName() string {
	return mailRouteSocketName + self.Host
}

// The Redis key of name's route.
func MailRouteKey(name string) string {
	return "{mxr_" + name + "}"
}

// The routable part of an SNI under root: <net> of mx.<net>.<root>, which is a label or an alias, or
// <scope>.<net> of a scope's mx.<scope>.<net>.<root>; any other name is a custom MX host and routes by
// its full name. Lowercase, with no final dot. "" for an empty name. server's projection names its keys
// with this same function.
func MailRouteName(root string, sni string) string {
	sni = strings.TrimSuffix(strings.ToLower(sni), ".")
	root = strings.TrimSuffix(strings.ToLower(root), ".")
	if within, found := strings.CutSuffix(sni, "."+root); found && root != "" {
		if name, found := strings.CutPrefix(within, mailRouteHost+"."); found && name != "" {
			return name
		}
	}
	return sni
}

// Whether label is one LDH label within labelMaxByteCount: what a stream target and a socket name may
// carry.
func mailRouteLabelFits(label string, labelMaxByteCount int) bool {
	if label == "" || labelMaxByteCount < len(label) || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := range len(label) {
		c := label[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// A {mxr_} value as a route, or false for anything the projection does not write: no network, a label or
// host that is no LDH name, or a host that is neither mx nor mx.<scope>. labelMaxByteCount is RFC
// 1035's.
func ParseMailRoute(value []byte, labelMaxByteCount int) (*MailRoute, bool) {
	route := &MailRoute{}
	if err := json.Unmarshal(value, route); err != nil {
		return nil, false
	}
	if route.NetworkId == (sidecar.Id{}) || !mailRouteLabelFits(route.Label, labelMaxByteCount) {
		return nil, false
	}
	if route.Host != mailRouteHost {
		scope, found := strings.CutPrefix(route.Host, mailRouteHost+".")
		if !found || !mailRouteLabelFits(scope, labelMaxByteCount) {
			return nil, false
		}
	}
	return route, true
}

// One name's answer, or the read that will give it.
type mxRouteEntry struct {
	name string
	// nil routes nothing
	route      *MailRoute
	expireTime time.Time
	// closed once the read has answered; nil for an answer held
	loading chan struct{}
	// the read's error, which no entry keeps: set before loading closes
	err error
	// where the entry sits in the cache's order, oldest first
	element *list.Element
}

// See the file header.
type mxRouteCache struct {
	ctx      context.Context
	redis    sidecar.Redis
	settings *MxEdgeSettings
	clock    sidecar.Clock
	// Reads of Redis that answered, failed or not, so a test can see one land.
	readCount *sidecar.MonitorValue[int]

	stateLock sync.Mutex
	entries   map[string]*mxRouteEntry
	// every entry, oldest first, so a full cache drops the oldest
	order *list.List
}

// An empty cache on redis, whose reads run on ctx.
func newMxRouteCache(ctx context.Context, redis sidecar.Redis, settings *MxEdgeSettings, clock sidecar.Clock) *mxRouteCache {
	return &mxRouteCache{
		ctx:       ctx,
		redis:     redis,
		settings:  settings,
		clock:     clock,
		readCount: sidecar.NewMonitorValue(0),
		entries:   map[string]*mxRouteEntry{},
		order:     list.New(),
	}
}

// Drops entry. Called with the lock held.
func (self *mxRouteCache) removeWithLock(entry *mxRouteEntry) {
	if self.entries[entry.name] == entry {
		delete(self.entries, entry.name)
	}
	if entry.element != nil {
		self.order.Remove(entry.element)
		entry.element = nil
	}
}

// Makes room for one more entry: expired answers first, then the oldest answer. A read in flight is never
// dropped, so a full cache of reads takes the new one past its bound for the read's life. Called with the
// lock held.
func (self *mxRouteCache) makeRoomWithLock(now time.Time) {
	if len(self.entries) < self.settings.RouteCacheEntryCount {
		return
	}
	for element := self.order.Front(); element != nil && self.settings.RouteCacheEntryCount <= len(self.entries); {
		next := element.Next()
		entry := element.Value.(*mxRouteEntry)
		if entry.loading == nil && !now.Before(entry.expireTime) {
			self.removeWithLock(entry)
		}
		element = next
	}
	for element := self.order.Front(); element != nil && self.settings.RouteCacheEntryCount <= len(self.entries); {
		next := element.Next()
		entry := element.Value.(*mxRouteEntry)
		if entry.loading == nil {
			self.removeWithLock(entry)
		}
		element = next
	}
}

// The route name stands at, nil when it routes nothing, as the cache or one read of Redis has it. An
// error is a read that failed or did not answer within StoreTimeout, which the caller reads as a name it
// cannot route now. ctx bounds only this caller's wait.
func (self *mxRouteCache) Lookup(ctx context.Context, name string) (*MailRoute, error) {
	if name == "" {
		return nil, nil
	}
	now := self.clock.Now()
	entry, first := func() (*mxRouteEntry, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if entry, ok := self.entries[name]; ok {
			if entry.loading != nil || now.Before(entry.expireTime) {
				return entry, false
			}
			self.removeWithLock(entry)
		}
		self.makeRoomWithLock(now)
		entry := &mxRouteEntry{name: name, loading: make(chan struct{})}
		entry.element = self.order.PushBack(entry)
		self.entries[name] = entry
		return entry, true
	}()
	if first {
		self.read(entry)
	}
	loading := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return entry.loading
	}()
	if loading != nil {
		select {
		case <-loading:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return entry.route, entry.err
}

// Reads entry's key, then answers everyone waiting on it. An error leaves no entry behind.
func (self *mxRouteCache) read(entry *mxRouteEntry) {
	route, err := func() (*MailRoute, error) {
		readCtx, cancel := context.WithCancel(self.ctx)
		stop := self.clock.AfterFunc(self.settings.StoreTimeout, cancel)
		defer func() {
			stop()
			cancel()
		}()
		testHookBarrier("mxedge.route_read.before", "")
		value, found, err := self.redis.Get(readCtx, MailRouteKey(entry.name))
		testHookBarrier("mxedge.route_read.after", "")
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, nil
		}
		route, ok := ParseMailRoute(value, self.settings.HostLabelMaxByteCount)
		if !ok {
			// not a value the projection writes: no route, and the next projection rewrites it
			return nil, nil
		}
		return route, nil
	}()
	expireTime := self.clock.Now().Add(self.settings.RouteCacheTtl)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry.route = route
		entry.err = err
		entry.expireTime = expireTime
		loading := entry.loading
		entry.loading = nil
		if err != nil {
			self.removeWithLock(entry)
		}
		close(loading)
	}()
	self.readCount.Update(func(count int) int { return count + 1 })
}

// How many names the cache holds, answers and reads in flight.
func (self *mxRouteCache) Len() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.entries)
}
