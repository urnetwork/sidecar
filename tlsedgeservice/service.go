// The engine, §4.5's stream form: §13.5's layer-4 router by SNI, which holds no user key and presents
// no certificate (D-TLS-1, D-TLS-3). This file is the contract the tlsedge tasks share: the engine's
// state, its loops and its lifecycle. names.go maps a name, kill_set.go holds the kill switch and
// negative_cache.go absorbs scans, all in memory, so a connection's path reads no store (I-12).
//
// Two loops feed that memory off every connection's path. The names loop reads the label map, a
// snapshot at start and its changes every NameReloadInterval, a new snapshot when the root's restore
// serial moves (plan-TLS-edge-data-source). The kills loop reads network_tls_suspension every
// KillReloadInterval with each named network's {tes_} hash, and in between the hash of each network a
// key event names (KillChanged). A failed read keeps the last answer, so a running process outlives a
// store outage on what it holds, while one started then stays not ready.
//
// The connection path itself, §13.5's steps in order, is TLS-M5-10's: until it lands, Serve accepts on
// the listed ports and answers every connection with internal_error, the alert of an edge that cannot
// route (reading 5), so nothing reaches a listener and nothing is half-routed.
//
// Every wait is on the host's clock, never a socket deadline or a sleep. Safe for concurrent use.

package tlsedgeservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.StreamEngine = (*TlsEdgeService)(nil)

// Serve was given a listener on a port tlsedge does not serve.
var ErrTlsEdgePort = errors.New("tlsedge serves only TCP 443, 8443, 8883 and 5671")

// The engine. Hosts call Serve once for each listener.
type TlsEdgeService struct {
	ctx      context.Context
	cancel   context.CancelFunc
	host     *sidecar.ServiceHost
	store    TlsEdgeStore
	dialer   TlsEdgeDialer
	settings *TlsEdgeSettings
	clock    sidecar.Clock
	metrics  *tlsEdgeMetrics

	names         *TlsEdgeNames
	kills         *TlsKillSet
	negativeCache *tlsNegativeCache

	// Wakes the kills loop for a key event or a resync.
	killWake chan struct{}
	// Rises at each change to the kill set, so the connection path's walk, and a test, can see one land.
	killChangeCount *sidecar.MonitorValue[uint64]
	// Rise at each finished read of the label map and each finished kill reload, failed or not, so a
	// wait can see one land and then move a fake clock past the next.
	nameLoadCount *sidecar.MonitorValue[uint64]
	killLoadCount *sidecar.MonitorValue[uint64]
	// Whether a kill reload has read the rows and every key they and the last reads named.
	killsLoaded *sidecar.MonitorValue[bool]

	loopGroup       sync.WaitGroup
	connectionGroup sync.WaitGroup

	stateLock             sync.Mutex
	killPendingNetworkIds map[sidecar.Id]bool
	killResyncPending     bool
	draining              bool
	closed                bool
	liveListeners         map[net.Listener]bool
	liveConnections       map[net.Conn]bool
}

// Starts the engine and its loops, which run until ctx ends or Close. host needs Redis, for the {tes_}
// keys, and Metrics. A nil store or dialer is allowed and leaves the engine not ready: with no store it
// loads nothing, and with no dialer nothing could be routed.
func NewTlsEdgeService(
	ctx context.Context,
	host *sidecar.ServiceHost,
	store TlsEdgeStore,
	dialer TlsEdgeDialer,
	settings *TlsEdgeSettings,
) (*TlsEdgeService, error) {
	if host == nil || host.Redis == nil || host.Metrics == nil {
		return nil, errors.New("tlsedge needs a host with Redis and Metrics")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	clock := host.ClockOrReal()
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &TlsEdgeService{
		ctx:                   cancelCtx,
		cancel:                cancel,
		host:                  host,
		store:                 store,
		dialer:                dialer,
		settings:              settings,
		clock:                 clock,
		metrics:               newTlsEdgeMetrics(host.Metrics),
		names:                 NewTlsEdgeNames(settings.Root, clock),
		kills:                 NewTlsKillSet(clock),
		negativeCache:         newTlsNegativeCache(settings.NegativeCacheTtl, settings.NegativeCacheMaxCount, clock),
		killWake:              make(chan struct{}, 1),
		killChangeCount:       sidecar.NewMonitorValue(uint64(0)),
		nameLoadCount:         sidecar.NewMonitorValue(uint64(0)),
		killLoadCount:         sidecar.NewMonitorValue(uint64(0)),
		killsLoaded:           sidecar.NewMonitorValue(false),
		killPendingNetworkIds: map[sidecar.Id]bool{},
		liveListeners:         map[net.Listener]bool{},
		liveConnections:       map[net.Conn]bool{},
	}
	if store != nil {
		self.loopGroup.Add(2)
		go self.runNames()
		go self.runKills()
	}
	return self, nil
}

// The name map, which the connection path resolves through.
func (self *TlsEdgeService) Names() *TlsEdgeNames {
	return self.names
}

// The kill set, which the connection path checks.
func (self *TlsEdgeService) Kills() *TlsKillSet {
	return self.kills
}

// See sidecar.Engine: the store and the dialer given, the label map's first snapshot read, the kill
// switch read, and the dialer holding K clients.
func (self *TlsEdgeService) Ready() bool {
	if self.store == nil || self.dialer == nil {
		return false
	}
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed
	}()
	if closed || !self.names.Loaded() || !self.killsLoaded.Value() {
		return false
	}
	return self.settings.Clients <= len(self.dialer.ClientIds())
}

// A context ended by StoreTimeout or RedisTimeout on the engine's clock, and the call that ends it.
func (self *TlsEdgeService) callContext(timeout time.Duration) (context.Context, func()) {
	callCtx, cancel := context.WithCancel(self.ctx)
	stop := self.clock.AfterFunc(timeout, cancel)
	return callCtx, func() {
		stop()
		cancel()
	}
}

// Reads the label map until the engine ends: a snapshot first, then the changes since the view's
// serial, and a snapshot again when the restore serial moves or the serial goes back.
func (self *TlsEdgeService) runNames() {
	defer self.loopGroup.Done()
	for {
		self.loadNames()
		self.nameLoadCount.Update(func(count uint64) uint64 { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.NameReloadInterval):
		}
	}
}

// One read of the label map, applied.
func (self *TlsEdgeService) loadNames() {
	callCtx, cancel := self.callContext(self.settings.StoreTimeout)
	defer cancel()
	if self.names.Loaded() {
		serial, restoreSerial := self.names.Serials()
		changes, err := self.store.NamesSince(callCtx, self.settings.Root, serial)
		if err != nil || changes == nil {
			self.metrics.nameLoads.Add(1, tlsNameLoadResultFailed)
			return
		}
		if changes.RestoreSerial == restoreSerial && serial <= changes.Serial {
			self.names.Apply(changes, false)
			self.metrics.nameLoads.Add(1, tlsNameLoadResultDelta)
			return
		}
	}
	snapshot, err := self.store.NameSnapshot(callCtx, self.settings.Root)
	if err != nil || snapshot == nil {
		self.metrics.nameLoads.Add(1, tlsNameLoadResultFailed)
		return
	}
	self.names.Apply(snapshot, true)
	self.metrics.nameLoads.Add(1, tlsNameLoadResultSnapshot)
}

// Notes that a network's {tes_} hash changed, as the host's key-event subscriber reports a {tes_*}n
// event (TlsKillTriggerKeyPattern), and returns at once: the kills loop reads the hash. Never blocks and
// does no I/O, so it may be called on the shared subscriber's goroutine.
func (self *TlsEdgeService) KillChanged(networkId sidecar.Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.killPendingNetworkIds[networkId] = true
	}()
	select {
	case self.killWake <- struct{}{}:
	default:
	}
}

// Rereads every kill now, rows and keys, as after the host's subscriber resubscribes: what was published
// in the gap is gone, so only a full read can see it. Never blocks.
func (self *TlsEdgeService) KillsResync() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.killResyncPending = true
	}()
	select {
	case self.killWake <- struct{}{}:
	default:
	}
}

// Reads the kill switch until the engine ends: a reload at start and every KillReloadInterval, and the
// keys of the networks KillChanged named in between. A key read that fails stays pending and is tried
// again after KillRetryDelay.
func (self *TlsEdgeService) runKills() {
	defer self.loopGroup.Done()
	nextReload := self.clock.Now()
	// a reload that fails is tried again sooner than the cadence, backing off to it
	failedReloadCount := 0
	for {
		now := self.clock.Now()
		resync := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			resync := self.killResyncPending
			self.killResyncPending = false
			return resync
		}()
		if resync || !now.Before(nextReload) {
			reloadWait := self.settings.KillReloadInterval
			if self.reloadKills() {
				failedReloadCount = 0
			} else {
				reloadWait = min(reloadWait, self.settings.KillRetryDelay<<min(failedReloadCount, 16))
				failedReloadCount += 1
			}
			nextReload = self.clock.Now().Add(reloadWait)
			self.killLoadCount.Update(func(count uint64) uint64 { return count + 1 })
		}
		pendingNetworkIds := func() []sidecar.Id {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			networkIds := []sidecar.Id{}
			for networkId := range self.killPendingNetworkIds {
				networkIds = append(networkIds, networkId)
			}
			clear(self.killPendingNetworkIds)
			return networkIds
		}()
		failedNetworkIds := []sidecar.Id{}
		for _, networkId := range pendingNetworkIds {
			if !self.readKillKey(networkId) {
				failedNetworkIds = append(failedNetworkIds, networkId)
			}
		}
		wait := nextReload.Sub(self.clock.Now())
		if 0 < len(failedNetworkIds) {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				for _, networkId := range failedNetworkIds {
					self.killPendingNetworkIds[networkId] = true
				}
			}()
			wait = min(wait, self.settings.KillRetryDelay)
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.killWake:
		case <-self.clock.After(wait):
		}
	}
}

// One reload: every row, then the hash of every network a row or an earlier read names. The set is
// loaded once the rows and each of those hashes have been read in one pass. Returns whether every read
// answered.
func (self *TlsEdgeService) reloadKills() bool {
	rows, err := func() ([]*sidecar.TlsSuspendArgs, error) {
		callCtx, cancel := self.callContext(self.settings.StoreTimeout)
		defer cancel()
		return self.store.Suspensions(callCtx)
	}()
	if err != nil {
		self.metrics.killLoads.Add(1, tlsKillLoadResultRowsFailed)
		return false
	}
	self.metrics.killLoads.Add(1, tlsKillLoadResultRows)
	if 0 < len(self.kills.SetRows(rows)) {
		self.killChangeCount.Update(func(count uint64) uint64 { return count + 1 })
	}
	complete := true
	for _, networkId := range self.kills.NetworkIds() {
		if !self.readKillKey(networkId) {
			complete = false
		}
	}
	if complete {
		self.killsLoaded.Set(true)
	}
	return complete
}

// Reads one network's {tes_} hash into the set. False when Redis did not answer, which changes nothing.
func (self *TlsEdgeService) readKillKey(networkId sidecar.Id) bool {
	callCtx, cancel := self.callContext(self.settings.RedisTimeout)
	defer cancel()
	testHookBarrier("tlsedge.kill_read.before", networkId.String())
	fieldValues, err := self.host.Redis.HashGetAll(callCtx, sidecar.TlsKillKey(networkId))
	if err != nil {
		self.metrics.killLoads.Add(1, tlsKillLoadResultKeyFailed)
		return false
	}
	self.metrics.killLoads.Add(1, tlsKillLoadResultKey)
	if self.kills.SetKey(networkId, fieldValues) {
		self.killChangeCount.Update(func(count uint64) uint64 { return count + 1 })
	}
	testHookBarrier("tlsedge.kill_read.after", networkId.String())
	return true
}

// The port a listener accepts on, 0 when its address is not TCP.
func tlsEdgeListenerPort(listener net.Listener) int {
	if address, ok := listener.Addr().(*net.TCPAddr); ok {
		return address.Port
	}
	return 0
}

// See sidecar.StreamEngine. Refuses a listener on any port but 443, 8443, 8883 and 5671 (owner
// decisions 68 and 121) before accepting anything, and otherwise accepts until the listener or the
// engine closes. The host's PROXY listener has already taken each connection's header off.
func (self *TlsEdgeService) Serve(listener net.Listener) error {
	port := tlsEdgeListenerPort(listener)
	if !tlsEdgePortServed(port) {
		return fmt.Errorf("%w: port %d", ErrTlsEdgePort, port)
	}
	defer listener.Close()
	added := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.draining {
			return false
		}
		self.liveListeners[listener] = true
		return true
	}()
	if !added {
		return nil
	}
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.liveListeners, listener)
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			stopped := func() bool {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				return self.closed || self.draining
			}()
			if stopped || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// as net/http's Serve does: descriptors run out and peers reset mid-accept, and neither
			// ends a listener
			var netError net.Error
			if !errors.As(err, &netError) || !netError.Temporary() {
				return err
			}
			self.metrics.acceptFailures.Add(1)
			select {
			case <-self.ctx.Done():
				return nil
			case <-self.clock.After(self.settings.AcceptRetryDelay):
			}
			continue
		}
		admitted := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed || self.draining {
				return false
			}
			self.liveConnections[conn] = true
			self.connectionGroup.Add(1)
			return true
		}()
		if !admitted {
			conn.Close()
			continue
		}
		go func() {
			defer self.connectionGroup.Done()
			defer func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.liveConnections, conn)
			}()
			self.serveConnection(conn, port)
		}()
	}
}

// One connection. TLS-M5-10 builds §13.5's steps here. Until then nothing can be routed, so every
// connection gets the one alert an edge that cannot route sends, internal_error (reading 5), and closes:
// no byte of it is read, no store or dialer is asked, and nothing reaches a listener.
func (self *TlsEdgeService) serveConnection(conn net.Conn, port int) {
	defer conn.Close()
	WriteTlsAlert(conn, TlsAlertInternalError)
}

// See sidecar.Engine: takes no new connection, closing the listeners Serve holds, and waits up to
// drain_s for the connections in flight before resetting what remains.
func (self *TlsEdgeService) Drain() {
	listeners := func() []net.Listener {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.draining = true
		listeners := []net.Listener{}
		for listener := range self.liveListeners {
			listeners = append(listeners, listener)
		}
		return listeners
	}()
	for _, listener := range listeners {
		listener.Close()
	}
	done := make(chan struct{})
	go func() {
		self.connectionGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-self.ctx.Done():
	case <-self.clock.After(self.settings.DrainTimeout):
	}
	self.closeConnections()
}

// Closes every connection still open.
func (self *TlsEdgeService) closeConnections() {
	connections := func() []net.Conn {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		connections := []net.Conn{}
		for conn := range self.liveConnections {
			connections = append(connections, conn)
		}
		return connections
	}()
	for _, conn := range connections {
		conn.Close()
	}
}

// See sidecar.Engine: ends everything at once and waits for the loops. Safe after Drain and more than
// once.
func (self *TlsEdgeService) Close() {
	listeners := func() []net.Listener {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		listeners := []net.Listener{}
		for listener := range self.liveListeners {
			listeners = append(listeners, listener)
		}
		return listeners
	}()
	self.cancel()
	for _, listener := range listeners {
		listener.Close()
	}
	self.closeConnections()
	self.loopGroup.Wait()
	self.connectionGroup.Wait()
}
