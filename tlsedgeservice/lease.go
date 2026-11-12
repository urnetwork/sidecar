// §13.6's accounting (X11, owner decision 10): tlsedge spends §20.6 leases on meter tls for the listening
// network. One lease serves every connection of a network in this process: the first connection asks
// Quota.Lease, the rest share its answer, and the last to end closes it, which settles what was not
// spent. A chunk's Spend is the lease's own atomic count, with no I/O, so it runs inline in the splice,
// and each spent byte is added to the process's usage window, which leaves every 60 s under producer
// tlsedge and once more on drain.
//
// A network whose lease is refused or runs out is spent: a new connection gets internal_error, and every
// open one is reset with RST_QUOTA (spent). The next connection after the last one ended asks again, so
// a network that bought more comes back by itself.
//
// With no Quota the host gave nothing to spend from, so every connection is refused, the closed
// direction. Safe for concurrent use.

package tlsedgeservice

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

var (
	// The host gave no Quota, so no byte can be accounted and none moves.
	errTlsLeaseNoQuota = errors.New("tlsedge has no quota to lease from")
	// The network has no balance left for meter tls (§20.6).
	errTlsLeaseSpent = errors.New("the network is spent")
)

// One network's lease in this process and the connections sharing it.
type tlsEdgeLease struct {
	networkId sidecar.Id
	// closed once the Lease call has answered
	ready chan struct{}
	// set before ready closes, and not changed after
	lease sidecar.QuotaLease
	err   error
	// a Spend refused: every holder resets
	spent atomic.Bool

	// under tlsEdgeLeases.stateLock
	holderCount int
}

// Every network's lease. See the file header.
type tlsEdgeLeases struct {
	ctx      context.Context
	quota    sidecar.Quota
	usage    *sidecar.QuotaUsageBatcher
	settings *TlsEdgeSettings
	clock    sidecar.Clock
	// called once, off every lock, when a network's lease runs out
	spent func(networkId sidecar.Id)

	stateLock       sync.Mutex
	networkIdLeases map[sidecar.Id]*tlsEdgeLease
}

func newTlsEdgeLeases(
	ctx context.Context,
	quota sidecar.Quota,
	usage *sidecar.QuotaUsageBatcher,
	settings *TlsEdgeSettings,
	clock sidecar.Clock,
	spent func(networkId sidecar.Id),
) *tlsEdgeLeases {
	return &tlsEdgeLeases{
		ctx:             ctx,
		quota:           quota,
		usage:           usage,
		settings:        settings,
		clock:           clock,
		spent:           spent,
		networkIdLeases: map[sidecar.Id]*tlsEdgeLease{},
	}
}

// The network's lease for one more connection, asking Quota for it when no connection holds one. A
// refusal, an error or a lease that already ran out holds nothing. The caller gives it back with Release.
func (self *tlsEdgeLeases) Acquire(networkId sidecar.Id) (*tlsEdgeLease, error) {
	if self.quota == nil || self.usage == nil {
		return nil, errTlsLeaseNoQuota
	}
	lease, first := func() (*tlsEdgeLease, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if lease, ok := self.networkIdLeases[networkId]; ok {
			lease.holderCount += 1
			return lease, false
		}
		lease := &tlsEdgeLease{networkId: networkId, ready: make(chan struct{}), holderCount: 1}
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
			quotaLease, refusal, err := self.quota.Lease(callCtx, connect.Id(networkId), sidecar.QuotaMeterTls)
			switch {
			case err != nil:
				lease.err = err
			case refusal != nil || quotaLease == nil:
				lease.err = errTlsLeaseSpent
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
		return nil, errTlsLeaseSpent
	}
	return lease, nil
}

// Gives one connection's hold back. The last holder closes the lease, settling its unused rest, and the
// next connection of the network asks afresh.
func (self *tlsEdgeLeases) Release(lease *tlsEdgeLease) {
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
// every connection of the network resets with RST_QUOTA. No I/O.
func (self *tlsEdgeLeases) Spend(lease *tlsEdgeLease, byteCount int) bool {
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
	self.usage.AddTransfer(connect.Id(lease.networkId), sidecar.QuotaMeterTls, int64(byteCount))
	return true
}
