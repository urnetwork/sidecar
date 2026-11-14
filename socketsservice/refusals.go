// What the registration and Find paths refuse from memory, before and after they reach the store
// (DESIGN-DETAILS 13.2.3): the removed-client set and the kill set. Both are read on every page and Find and
// never do I/O there (I-12).
//
//   - The removed-client set holds each client whose {X}c_removed event this process received, for
//     RemovedClientTtl, past any lease it held. A page from one answers 401, and a picked lease of one gets
//     no ticket. ClientRemoved (sweep.go) adds to it at once, then a worker runs the store's RemoveClient.
//   - The kill set is §13.9's switch as Find and registration read it: per network, a host or * with a
//     reason and an until, from {tes_<network_id>}, which tlsedge reads too, and one rule for both,
//     sidecar.TlsKillEntry.Kills, so a name tlsedge refuses Find does not admit (SOCK.md reading 4). It
//     refuses tls/ names alone, the switch's own names. The engine's reader (sweep.go's runKills) reads a
//     network's hash on its {tes_}n event (KillChanged), after a resubscription (KillsResync), and when a tls/
//     name of it is first judged here, and replaces the network's entries.
//
// Reads take no lock for the kill set: one immutable view behind an atomic pointer, since kills are few.
// Safe for concurrent use.

package socketsservice

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The removed-client set. newSocketRemovedClients makes one.
type socketRemovedClients struct {
	ttl time.Duration

	stateLock sync.Mutex
	// When each client leaves the set.
	clientIdExpireTimes map[connect.Id]time.Time
	lastSweepTime       time.Time
}

// An empty set whose entries live ttl.
func newSocketRemovedClients(ttl time.Duration) *socketRemovedClients {
	return &socketRemovedClients{
		ttl:                 ttl,
		clientIdExpireTimes: map[connect.Id]time.Time{},
	}
}

// Adds clientId at now, for ttl. A second removal of one client keeps the later end.
func (self *socketRemovedClients) add(clientId connect.Id, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sweepWithLock(now)
	expireTime := now.Add(self.ttl)
	if previous, found := self.clientIdExpireTimes[clientId]; !found || previous.Before(expireTime) {
		self.clientIdExpireTimes[clientId] = expireTime
	}
}

// Whether clientId is in the set at now.
func (self *socketRemovedClients) contains(clientId connect.Id, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	expireTime, found := self.clientIdExpireTimes[clientId]
	return found && now.Before(expireTime)
}

// Drops what has lapsed, at most once a ttl, so the map holds about the removals of the last two ttls.
func (self *socketRemovedClients) sweepWithLock(now time.Time) {
	if now.Sub(self.lastSweepTime) < self.ttl {
		return
	}
	self.lastSweepTime = now
	for clientId, expireTime := range self.clientIdExpireTimes {
		if !now.Before(expireTime) {
			delete(self.clientIdExpireTimes, clientId)
		}
	}
}

// One read of the kill set: each network's entries, and the networks whose {tes_} hash was read, never changed
// once published.
type socketKillView struct {
	networkIdEntries map[connect.Id][]*sidecar.TlsKillEntry
	readNetworkIds   map[connect.Id]bool
}

// The kill set. newSocketKillSet makes one.
type socketKillSet struct {
	view atomic.Pointer[socketKillView]
	// What wakes the engine's reader (sweep.go's runKills).
	wake chan struct{}
	// Reads the reader finished, each counted once its wait is armed, so a test sees one land.
	readCount *sidecar.MonitorValue[int]

	// Serializes writers, each of which publishes a new view, and holds the networks due a read.
	stateLock         sync.Mutex
	pendingNetworkIds map[connect.Id]bool
}

// An empty set, killing nothing.
func newSocketKillSet() *socketKillSet {
	self := &socketKillSet{
		wake:              make(chan struct{}, 1),
		readCount:         sidecar.NewMonitorValue(0),
		pendingNetworkIds: map[connect.Id]bool{},
	}
	self.view.Store(&socketKillView{networkIdEntries: map[connect.Id][]*sidecar.TlsKillEntry{}, readNetworkIds: map[connect.Id]bool{}})
	return self
}

// Replaces networkId's entries with entries, a read of its {tes_} hash: none clears it. The network counts as
// read from now on.
func (self *socketKillSet) set(networkId connect.Id, entries []*sidecar.TlsKillEntry) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	previous := self.view.Load()
	networkIdEntries := make(map[connect.Id][]*sidecar.TlsKillEntry, len(previous.networkIdEntries)+1)
	for otherNetworkId, otherEntries := range previous.networkIdEntries {
		networkIdEntries[otherNetworkId] = otherEntries
	}
	if len(entries) == 0 {
		delete(networkIdEntries, networkId)
	} else {
		kept := make([]*sidecar.TlsKillEntry, 0, len(entries))
		for _, entry := range entries {
			if entry != nil {
				copied := *entry
				kept = append(kept, &copied)
			}
		}
		networkIdEntries[networkId] = kept
	}
	readNetworkIds := previous.readNetworkIds
	if !readNetworkIds[networkId] {
		readNetworkIds = make(map[connect.Id]bool, len(previous.readNetworkIds)+1)
		for otherNetworkId := range previous.readNetworkIds {
			readNetworkIds[otherNetworkId] = true
		}
		readNetworkIds[networkId] = true
	}
	self.view.Store(&socketKillView{networkIdEntries: networkIdEntries, readNetworkIds: readNetworkIds})
}

// Asks the reader for networkId's hash. Never blocks.
func (self *socketKillSet) request(networkId connect.Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.pendingNetworkIds[networkId] = true
	}()
	self.wakeReader()
}

// Asks the reader for every hash it has read. Never blocks.
func (self *socketKillSet) requestAll() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for networkId := range self.view.Load().readNetworkIds {
			self.pendingNetworkIds[networkId] = true
		}
	}()
	self.wakeReader()
}

// Puts back reads that failed.
func (self *socketKillSet) requeue(networkIds []connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, networkId := range networkIds {
		self.pendingNetworkIds[networkId] = true
	}
}

// The networks due a read, taken.
func (self *socketKillSet) takePending() []connect.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := make([]connect.Id, 0, len(self.pendingNetworkIds))
	for networkId := range self.pendingNetworkIds {
		networkIds = append(networkIds, networkId)
	}
	clear(self.pendingNetworkIds)
	return networkIds
}

func (self *socketKillSet) wakeReader() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Whether a kill refuses the name of networkId at now: a tls/ name whose host, or every host, its network's
// entries name. Any other name is no kill switch's. A network whose hash was never read is asked for and judged
// with no kill meanwhile (sweep.go's header). Does no I/O, and takes a lock only for such an ask.
func (self *socketKillSet) kills(networkId connect.Id, name *socketParsedName, now time.Time) bool {
	if name == nil || name.namespace != sidecar.SocketNamespaceTls {
		return false
	}
	view := self.view.Load()
	if !view.readNetworkIds[networkId] {
		self.request(networkId)
	}
	entries := view.networkIdEntries[networkId]
	for _, entry := range entries {
		if entry.Kills(name.host, now) {
			return true
		}
	}
	return false
}
