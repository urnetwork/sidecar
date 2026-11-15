// The router's splice (§15.4, D-MAIL-2, X6; MAIL-M7-19): from the ClientHello on, the sender's bytes to
// the receiver's stream and back, untouched. Nothing here parses a byte past the hello, holds a key or
// answers SMTP, so TLS ends on the receiver alone. A sender's FIN maps to StreamClose (CloseWrite) and a
// receiver's StreamClose to a FIN, so each half closes by itself; a sender's reset maps to StreamReset
// and a receiver's StreamReset to a reset of the sender's connection. §22.7 holds tlsedge's and this
// splice byte-identical, and the two share no code: each copies the bytes as they come, reframing
// nothing.
//
// A splice ends, once, when both halves have closed, when either side resets, and at §15.4's bounds:
// SpliceIdleTimeout with no byte either way, SpliceSlowTimeout having passed fewer than
// SpliceSlowByteCount, SpliceSessionTimeout whatever it carries, and SpliceMessageMultiple times its
// network's message cap plus SpliceExtraByteCount, both ways. It ends too at its ticket's grant expiry,
// when its network's lease runs out (RST_QUOTA), and at a drain's or a close's reset (RST_DRAINING).
// Whatever ends it closes both sides, which is what stops the two copies.
//
// Every chunk is spent from the listening network's lease on meter mx before it moves (§20.6), and the
// hello's bytes before the splice starts: one lease serves every session of a network in this process,
// the first asking Quota.Lease and the last to end closing it. A lease refused or run out marks the
// network spent: a new session closes in the handshake as spent, and every open splice of it resets.
// The next session after the last one ended asks again, so a network that bought more comes back by
// itself.
//
// The message cap is the network's mail_inbound_message_bytes (§20.4), loaded off every session's path
// and cached per network (mxMessageLimits); a network not loaded yet gets ColdMessageByteCount.
//
// Every wait is on the engine's clock. Nothing here logs a byte, an address or a name (I-13). Safe for
// concurrent use.

package mxedgeservice

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// How a splice ended, a metric's result and, prefixed with splice_, its session record's.
const (
	// Both halves closed by themselves.
	mxSpliceEndClosed = "closed"
	// The sender reset, or a write to it failed.
	mxSpliceEndSenderReset = "sender_reset"
	// The receiver reset, or a write to it failed.
	mxSpliceEndReceiverReset = "receiver_reset"
	// §15.4's bounds.
	mxSpliceEndIdle    = "idle"
	mxSpliceEndSlow    = "slow"
	mxSpliceEndSession = "session_timeout"
	mxSpliceEndBytes   = "byte_cap"
	// The network's lease ran out.
	mxSpliceEndQuota = "quota"
	// The ticket's grant expired.
	mxSpliceEndExpired = "expired"
	// A drain's or a close's reset.
	mxSpliceEndDrain = "drain"
)

// Which way a chunk went, a metric's label.
const (
	mxByteDirectionToReceiver = "to_receiver"
	mxByteDirectionToSender   = "to_sender"
)

var (
	// The host gave no Quota, so no byte can be accounted and none moves.
	errMxLeaseNoQuota = errors.New("mxedge has no quota to lease from")
	// The network has no balance left for meter mx (§20.6).
	errMxLeaseSpent = errors.New("the network is spent")
)

// One network's lease in this process and the sessions sharing it.
type mxLease struct {
	networkId sidecar.Id
	// closed once the Lease call has answered
	ready chan struct{}
	// set before ready closes, and not changed after
	lease sidecar.QuotaLease
	err   error
	// a Spend refused: every holder resets
	spent atomic.Bool

	// under mxLeases.stateLock
	holderCount int
}

// Every network's lease. See the file header.
type mxLeases struct {
	ctx      context.Context
	quota    sidecar.Quota
	usage    *sidecar.QuotaUsageBatcher
	settings *MxEdgeSettings
	clock    sidecar.Clock
	// called once, off every lock, when a network's lease runs out
	spent func(networkId sidecar.Id)

	stateLock       sync.Mutex
	networkIdLeases map[sidecar.Id]*mxLease
}

func newMxLeases(ctx context.Context, quota sidecar.Quota, usage *sidecar.QuotaUsageBatcher, settings *MxEdgeSettings, clock sidecar.Clock, spent func(networkId sidecar.Id)) *mxLeases {
	return &mxLeases{
		ctx:             ctx,
		quota:           quota,
		usage:           usage,
		settings:        settings,
		clock:           clock,
		spent:           spent,
		networkIdLeases: map[sidecar.Id]*mxLease{},
	}
}

// The network's lease for one more session, asking Quota for it when no session holds one. A refusal,
// an error or a lease that already ran out holds nothing. The caller gives it back with Release.
func (self *mxLeases) Acquire(networkId sidecar.Id) (*mxLease, error) {
	if self.quota == nil || self.usage == nil {
		return nil, errMxLeaseNoQuota
	}
	lease, first := func() (*mxLease, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if lease, ok := self.networkIdLeases[networkId]; ok {
			lease.holderCount += 1
			return lease, false
		}
		lease := &mxLease{networkId: networkId, ready: make(chan struct{}), holderCount: 1}
		self.networkIdLeases[networkId] = lease
		return lease, true
	}()
	if first {
		func() {
			defer close(lease.ready)
			callCtx, cancel := context.WithCancel(self.ctx)
			stop := self.clock.AfterFunc(self.settings.LeaseTimeout, cancel)
			defer func() {
				stop()
				cancel()
			}()
			quotaLease, refusal, err := self.quota.Lease(callCtx, connect.Id(networkId), sidecar.QuotaMeterMx)
			switch {
			case err != nil:
				lease.err = err
			case refusal != nil || quotaLease == nil:
				lease.err = errMxLeaseSpent
			default:
				lease.lease = quotaLease
			}
		}()
	} else {
		select {
		case <-lease.ready:
		case <-self.ctx.Done():
			self.Release(lease)
			return nil, self.ctx.Err()
		}
	}
	if lease.err != nil {
		self.Release(lease)
		return nil, lease.err
	}
	if lease.spent.Load() {
		self.Release(lease)
		return nil, errMxLeaseSpent
	}
	return lease, nil
}

// Gives one session's hold back. The last holder closes the lease, settling its unused rest, and the
// next session of the network asks afresh.
func (self *mxLeases) Release(lease *mxLease) {
	last := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		lease.holderCount -= 1
		if 0 < lease.holderCount {
			return false
		}
		if self.networkIdLeases[lease.networkId] == lease {
			delete(self.networkIdLeases, lease.networkId)
		}
		return true
	}()
	if !last {
		return
	}
	// the first holder's call has answered by now: every holder waited on ready before it released
	<-lease.ready
	if lease.lease != nil {
		lease.lease.Close()
	}
}

// Spends a chunk's bytes before they move. False when the lease has run out: the chunk is not sent, and
// every splice of the network resets with RST_QUOTA. No I/O.
func (self *mxLeases) Spend(lease *mxLease, byteCount int) bool {
	if lease.spent.Load() {
		return false
	}
	if !lease.lease.Spend(int64(byteCount)) {
		if !lease.spent.Swap(true) {
			self.spent(lease.networkId)
		}
		return false
	}
	// only a closed batcher refuses, and then the engine is ending and nothing more is billed
	self.usage.AddTransfer(connect.Id(lease.networkId), sidecar.QuotaMeterMx, int64(byteCount))
	return true
}

// The QuotaLimits key of the message cap (§20.4).
const mxLimitKeyInboundMessageBytes = "mail_inbound_message_bytes"

// One network's cached cap.
type mxCachedLimit struct {
	// 0 until a load answered
	messageByteCount int64
	loadTime         time.Time
	usedTime         time.Time
}

// Each network's message cap, loaded off every session's path by run: a session reads the cache and
// never waits on Quota (I-12).
type mxMessageLimits struct {
	settings *MxEdgeSettings
	quota    sidecar.Quota
	clock    sidecar.Clock
	// wakes run for a network asked for and not yet loaded
	wake chan struct{}
	// rises at each finished pass, so a wait can see one land
	passCount *sidecar.MonitorValue[uint64]

	stateLock       sync.Mutex
	networkIdLimits map[sidecar.Id]*mxCachedLimit
	networkIdQueue  []sidecar.Id
}

func newMxMessageLimits(settings *MxEdgeSettings, quota sidecar.Quota, clock sidecar.Clock) *mxMessageLimits {
	return &mxMessageLimits{
		settings:        settings,
		quota:           quota,
		clock:           clock,
		wake:            make(chan struct{}, 1),
		passCount:       sidecar.NewMonitorValue(uint64(0)),
		networkIdLimits: map[sidecar.Id]*mxCachedLimit{},
	}
}

// The network's message cap as last loaded, or ColdMessageByteCount until a load answers. Marks the
// network in use, so the next pass loads or refreshes it. No I/O and no wait.
func (self *mxMessageLimits) MessageByteCount(networkId sidecar.Id) int64 {
	now := self.clock.Now()
	messageByteCount, wake := func() (int64, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cached, ok := self.networkIdLimits[networkId]
		if !ok {
			// bounded: past the bound the oldest network goes, which only makes it cold again
			for self.settings.LimitsNetworkCount <= len(self.networkIdLimits) && 0 < len(self.networkIdQueue) {
				delete(self.networkIdLimits, self.networkIdQueue[0])
				self.networkIdQueue = self.networkIdQueue[1:]
			}
			cached = &mxCachedLimit{}
			self.networkIdLimits[networkId] = cached
			self.networkIdQueue = append(self.networkIdQueue, networkId)
		}
		cached.usedTime = now
		if cached.messageByteCount <= 0 {
			return int64(self.settings.ColdMessageByteCount), !ok
		}
		return cached.messageByteCount, false
	}()
	if wake {
		select {
		case self.wake <- struct{}{}:
		default:
		}
	}
	return messageByteCount
}

// Loads every network in use that is cold or older than LimitsRefreshInterval, and forgets those unused
// for LimitsActiveWindow, until ctx ends. A load that fails, or answers no positive cap, keeps what the
// network had, cold included. No lock is held across a Quota call.
func (self *mxMessageLimits) run(ctx context.Context) {
	for {
		if self.quota != nil {
			self.refresh(ctx)
		}
		// armed before the pass is counted, so a wait that sees the count can move the clock past it
		next := self.clock.After(self.settings.LimitsRefreshInterval)
		self.passCount.Update(func(count uint64) uint64 { return count + 1 })
		select {
		case <-ctx.Done():
			return
		case <-self.wake:
		case <-next:
		}
	}
}

// One pass.
func (self *mxMessageLimits) refresh(ctx context.Context) {
	now := self.clock.Now()
	networkIds := func() []sidecar.Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		networkIds := []sidecar.Id{}
		keptQueue := []sidecar.Id{}
		for _, networkId := range self.networkIdQueue {
			cached, ok := self.networkIdLimits[networkId]
			if !ok {
				continue
			}
			if self.settings.LimitsActiveWindow < now.Sub(cached.usedTime) {
				delete(self.networkIdLimits, networkId)
				continue
			}
			keptQueue = append(keptQueue, networkId)
			if cached.messageByteCount <= 0 || self.settings.LimitsRefreshInterval <= now.Sub(cached.loadTime) {
				networkIds = append(networkIds, networkId)
			}
		}
		self.networkIdQueue = keptQueue
		return networkIds
	}()
	for _, networkId := range networkIds {
		quotaLimits, err := func() (*sidecar.QuotaLimits, error) {
			callCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			stop := self.clock.AfterFunc(self.settings.StoreTimeout, cancel)
			defer stop()
			return self.quota.Limits(callCtx, connect.Id(networkId))
		}()
		if err != nil || quotaLimits == nil {
			continue
		}
		messageByteCount := quotaLimits.Limits[mxLimitKeyInboundMessageBytes]
		if messageByteCount <= 0 {
			// none (-1) or not included (0) has no cap to bound a splice by: the cold cap stands, and the
			// receiver holds the message to its own SIZE
			continue
		}
		loadTime := self.clock.Now()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if cached, ok := self.networkIdLimits[networkId]; ok {
				cached.messageByteCount = messageByteCount
				cached.loadTime = loadTime
			}
		}()
	}
}

// One spliced session, from the receiver's accept to its end.
type mxSplice struct {
	router    *mxRouter
	conn      net.Conn
	stream    MxEdgeStream
	lease     *mxLease
	networkId sidecar.Id
	startTime time.Time
	// the most bytes both ways: SpliceMessageMultiple times the network's cap plus SpliceExtraByteCount
	byteCap int64

	// bytes admitted both ways, the hello's included: each chunk counts once its lease paid for it, before
	// it moves, so this is what the network paid for and what its record names
	byteCount atomic.Int64
	// the clock's time of the last byte moved, in Unix nanoseconds
	lastActiveNanos atomic.Int64

	endOnce sync.Once
	// closed by end
	ended chan struct{}
	// set by end before ended closes
	endReason string
}

// Ends the splice, once: the first reason stands. A clean end closes both sides; a receiver's reset
// resets the sender; a sender's reset resets the stream with code; anything else resets both.
func (self *mxSplice) end(reason string, code protocol.StreamResetCode) {
	self.endOnce.Do(func() {
		self.endReason = reason
		close(self.ended)
		switch reason {
		case mxSpliceEndClosed:
			self.stream.Close()
			self.conn.Close()
		case mxSpliceEndReceiverReset:
			self.stream.Close()
			mxResetConnection(self.conn)
		case mxSpliceEndSenderReset:
			self.stream.Reset(code)
			self.conn.Close()
		default:
			self.stream.Reset(code)
			mxResetConnection(self.conn)
		}
	})
}

// Accounts one chunk before it moves: the byte cap, then the lease. False when the splice ended
// instead.
func (self *mxSplice) admitChunk(byteCount int) bool {
	select {
	case <-self.ended:
		return false
	default:
	}
	router := self.router
	// a byte that arrived is activity, whether or not its write has finished
	self.lastActiveNanos.Store(router.service.clock.Now().UnixNano())
	if self.byteCap < self.byteCount.Load()+int64(byteCount) {
		self.end(mxSpliceEndBytes, protocol.StreamResetCode_RST_CANCELLED)
		return false
	}
	if !router.leases.Spend(self.lease, byteCount) {
		self.end(mxSpliceEndQuota, protocol.StreamResetCode_RST_QUOTA)
		return false
	}
	self.byteCount.Add(int64(byteCount))
	return true
}

// Counts one chunk that moved.
func (self *mxSplice) movedChunk(byteCount int, direction string) {
	self.router.service.metrics.spliceBytes.Add(float64(byteCount), direction)
}

// Sender to receiver, until the sender's FIN, which half-closes the stream, or an end.
func (self *mxSplice) copyToReceiver() {
	buffer := make([]byte, self.router.service.settings.SpliceBufferByteCount)
	for {
		n, err := self.conn.Read(buffer)
		if 0 < n {
			if !self.admitChunk(n) {
				return
			}
			if _, writeErr := self.stream.Write(buffer[:n]); writeErr != nil {
				self.end(mxSpliceEndReceiverReset, protocol.StreamResetCode_RST_UNSPECIFIED)
				return
			}
			self.movedChunk(n, mxByteDirectionToReceiver)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// FIN maps to StreamClose
				if self.stream.CloseWrite() != nil {
					self.end(mxSpliceEndReceiverReset, protocol.StreamResetCode_RST_UNSPECIFIED)
				}
				return
			}
			// RST maps to StreamReset
			self.end(mxSpliceEndSenderReset, protocol.StreamResetCode_RST_CANCELLED)
			return
		}
	}
}

// Receiver to sender, until the receiver's StreamClose, which half-closes the sender's connection, or an
// end.
func (self *mxSplice) copyToSender() {
	buffer := make([]byte, self.router.service.settings.SpliceBufferByteCount)
	for {
		n, err := self.stream.Read(buffer)
		if 0 < n {
			if !self.admitChunk(n) {
				return
			}
			if _, writeErr := self.conn.Write(buffer[:n]); writeErr != nil {
				self.end(mxSpliceEndSenderReset, protocol.StreamResetCode_RST_CANCELLED)
				return
			}
			self.movedChunk(n, mxByteDirectionToSender)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// StreamClose maps to FIN
				writeCloser, ok := self.conn.(interface{ CloseWrite() error })
				if !ok || writeCloser.CloseWrite() != nil {
					// a connection that cannot half-close ends whole
					self.end(mxSpliceEndClosed, protocol.StreamResetCode_RST_UNSPECIFIED)
				}
				return
			}
			// StreamReset maps to RST
			self.end(mxSpliceEndReceiverReset, protocol.StreamResetCode_RST_UNSPECIFIED)
			return
		}
	}
}

// Runs both copies until both have returned, ending the splice at §15.4's bounds and at
// grantExpireTime, when it is not zero. Returns with the splice ended and both sides closed.
func (self *mxSplice) run(grantExpireTime time.Time) {
	service := self.router.service
	settings := service.settings
	clock := service.clock
	// armed before a byte can move, so a byte that moved says the waits are set
	idleTimeout := settings.SpliceIdleTimeout
	idle := clock.After(idleTimeout)
	slow := clock.After(max(settings.SpliceSlowTimeout-clock.Now().Sub(self.startTime), 0))
	session := clock.After(max(settings.SpliceSessionTimeout-clock.Now().Sub(self.startTime), 0))
	var expired <-chan time.Time
	if !grantExpireTime.IsZero() {
		expired = clock.After(max(grantExpireTime.Sub(clock.Now()), 0))
	}
	testHookBarrier("mxedge.splice.start", "")
	done := make(chan struct{}, 2)
	go func() {
		self.copyToReceiver()
		done <- struct{}{}
	}()
	go func() {
		self.copyToSender()
		done <- struct{}{}
	}()
	for doneCount := 0; doneCount < 2; {
		select {
		case <-done:
			doneCount += 1
		case <-idle:
			idleFor := clock.Now().UnixNano() - self.lastActiveNanos.Load()
			if int64(idleTimeout) <= idleFor {
				self.end(mxSpliceEndIdle, protocol.StreamResetCode_RST_PEER_TIMEOUT)
				// a nil channel never fires: the copies return now that both sides are closed
				idle = nil
			} else {
				idle = clock.After(idleTimeout - time.Duration(idleFor))
			}
		case <-slow:
			slow = nil
			if self.byteCount.Load() < int64(settings.SpliceSlowByteCount) {
				self.end(mxSpliceEndSlow, protocol.StreamResetCode_RST_PEER_TIMEOUT)
			}
		case <-session:
			session = nil
			self.end(mxSpliceEndSession, protocol.StreamResetCode_RST_PEER_TIMEOUT)
		case <-expired:
			expired = nil
			self.end(mxSpliceEndExpired, protocol.StreamResetCode_RST_REVOKED)
		}
	}
	// both halves closed by themselves, unless something ended it first
	self.end(mxSpliceEndClosed, protocol.StreamResetCode_RST_UNSPECIFIED)
	testHookBarrier("mxedge.splice.end", "")
}
