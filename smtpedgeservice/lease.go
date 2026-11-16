// §14's accounting (R-SMTP-8, owner decision 10; SMTP-M9-13): smtpedge spends §20.6 leases on meter smtp for
// the sending network, the stream's dialer's. One lease serves every connection of a network in this process:
// the first asks Quota.Lease, the rest share its answer, and the last to end closes it, which settles what was
// not spent. A record's Spend is the lease's own atomic count, with no I/O, so it runs inline on the splice, and
// each spent byte joins the process's usage window, which leaves every 60 s under producer smtpedge and once
// more on drain.
//
// A network whose lease is refused or runs out is spent: its connections end, and the next one asks again, so a
// network that bought more comes back by itself. With no Quota there is nothing to spend from, so no
// connection splices, the closed direction. Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The usage producer smtpedge reports as (§20.6).
const smtpUsageProducer = "smtpedge"

var (
	// The host gave no Quota, so no byte can be accounted and none moves.
	errSmtpLeaseNoQuota = errors.New("smtpedge has no quota to lease from")
	// The network has no balance left for meter smtp (§20.6).
	errSmtpLeaseSpent = errors.New("the network is spent")
)

// One network's lease in this process and the connections sharing it.
type smtpEdgeLease struct {
	networkId sidecar.Id
	// closed once the Lease call has answered
	ready chan struct{}
	// set before ready closes, and not changed after
	lease sidecar.QuotaLease
	err   error
	// a Spend refused: every holder ends
	spent atomic.Bool

	// under smtpEdgeLeases.stateLock
	holderCount int
}

// Every network's lease. See the file header.
type smtpEdgeLeases struct {
	ctx      context.Context
	quota    sidecar.Quota
	usage    *sidecar.QuotaUsageBatcher
	settings *SmtpEdgeSettings
	clock    sidecar.Clock

	stateLock       sync.Mutex
	networkIdLeases map[sidecar.Id]*smtpEdgeLease
}

func newSmtpEdgeLeases(ctx context.Context, quota sidecar.Quota, usage *sidecar.QuotaUsageBatcher, settings *SmtpEdgeSettings, clock sidecar.Clock) *smtpEdgeLeases {
	return &smtpEdgeLeases{
		ctx:             ctx,
		quota:           quota,
		usage:           usage,
		settings:        settings,
		clock:           clock,
		networkIdLeases: map[sidecar.Id]*smtpEdgeLease{},
	}
}

// The network's lease for one more connection, asking Quota for it when no connection holds one. A refusal,
// an error or a lease that already ran out holds nothing. The caller gives it back with release.
func (self *smtpEdgeLeases) acquire(networkId sidecar.Id) (*smtpEdgeLease, error) {
	if self.quota == nil || self.usage == nil {
		return nil, errSmtpLeaseNoQuota
	}
	lease, first := func() (*smtpEdgeLease, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if lease, ok := self.networkIdLeases[networkId]; ok {
			lease.holderCount += 1
			return lease, false
		}
		lease := &smtpEdgeLease{networkId: networkId, ready: make(chan struct{}), holderCount: 1}
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
			quotaLease, refusal, err := self.quota.Lease(callCtx, connect.Id(networkId), sidecar.QuotaMeterSmtp)
			switch {
			case err != nil:
				lease.err = err
			case refusal != nil || quotaLease == nil:
				lease.err = errSmtpLeaseSpent
			default:
				lease.lease = quotaLease
			}
		}()
	} else {
		select {
		case <-lease.ready:
		case <-self.ctx.Done():
			self.release(lease)
			return nil, self.ctx.Err()
		}
	}
	if lease.err != nil || lease.spent.Load() {
		err := lease.err
		if err == nil {
			err = errSmtpLeaseSpent
		}
		self.release(lease)
		return nil, err
	}
	return lease, nil
}

// Gives one connection's hold back. The last holder closes the lease, settling its unused rest.
func (self *smtpEdgeLeases) release(lease *smtpEdgeLease) {
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

// Spends a record's octets before they move. False when the lease has run out: the record is not relayed and
// the connection ends. No I/O.
func (self *smtpEdgeLeases) spend(lease *smtpEdgeLease, byteCount int) bool {
	if lease.spent.Load() {
		return false
	}
	if !lease.lease.Spend(int64(byteCount)) {
		lease.spent.Store(true)
		return false
	}
	// only a closed batcher refuses, and then the engine is ending and nothing more is billed
	self.usage.AddTransfer(connect.Id(lease.networkId), sidecar.QuotaMeterSmtp, int64(byteCount))
	return true
}
