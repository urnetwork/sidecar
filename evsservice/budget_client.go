// §11.13's write budget for one process (EVSB-M2-06): one instance shared by every engine the process
// hosts, evs, gkm, api or taskworker, as ServiceHost.Budget. Budgets belong to the instance, never to a
// package global. For each metadata cluster it holds an account with this interval's shares of the
// governor's allowance, and spends them inline with no Redis op and no lock across I/O (I-12, §22.5's
// hot-path gate):
//
//   - IssueP0 adds to a counter and returns: no queue, no wait, no refusal (owner decision 186);
//   - AdmitP1 waits in the network's fair queue within the P1 share, or is refused past the shed delay
//     (budget_queue.go). Admission debits the whole price and moves the deferred part into the credit
//     the process reports, which the wallet gains; an abort lets that credit lapse through W's clamp, and
//     a retry is priced only for the writes it repeats, by its caller;
//   - AcquireP2 and TryAcquireP2 serve by rank within the funded and unfunded shares (budget_p2.go).
//
// Its own goroutine, every Interval, reads each cluster's allowance, takes the next interval's shares
// (budget_fallback.go when none came fresh), and writes the process's report (budget_redis.go), with the
// shares of the last interval lapsing; another keeps the store_weight of the networks it admitted fresh.
// Segment clusters spend no NVMe budget and have no account.
//
// Safe for concurrent use.

package evsservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

var (
	// A P1 or P2 admission on a cluster this process holds no account for. Nothing was spent.
	ErrWriteBudgetCluster = errors.New("no write budget for this cluster")
	// The budget closed while the work waited. Nothing was spent.
	ErrWriteBudgetClosed = errors.New("write budget closed")
	// A P1 admission with no network to queue it under: the caller's bug.
	ErrWriteBudgetNetwork = errors.New("a P1 admission names no network")
)

// §19.8's issued bytes, by cluster, class and, for P0, kind: no network or repo label.
const writeBudgetIssuedMetricName = "urnetwork_evs_budget_issued_bytes_total"

// The metric's class values.
const (
	writeBudgetMetricClassP0         = "p0"
	writeBudgetMetricClassP1         = "p1"
	writeBudgetMetricClassP2Funded   = "p2_funded"
	writeBudgetMetricClassP2Unfunded = "p2_unfunded"
)

// See the file header.
type WriteBudgetClient struct {
	ctx           context.Context
	cancel        context.CancelFunc
	settings      *WriteBudgetSettings
	clock         sidecar.Clock
	redis         sidecar.Redis
	issuedCounter sidecar.MetricsCounter
	// 16 random bytes as hex, drawn at construction: names this process's reports and no host
	processId string
	startTime time.Time
	weights   *writeBudgetWeights
	// fixed at construction
	clusterIdAccounts map[string]*writeBudgetAccount
	// a test's: called as an AdmitP1 or AcquireP2 starts to wait, so a test knows a waiter is queued
	// without a sleep. Set before the first call, nil otherwise.
	waitHook func()
}

// The process's budget over clusterIds, host.Blobs's metadata clusters when nil, started at once.
// host.Redis carries its reports and allowances, host.Quota its networks' weights (each weighs
// DefaultStoreWeight without one), host.Metrics its issued bytes, host.Clock its intervals. settings
// may be nil for the defaults. Close ends it.
func NewWriteBudget(ctx context.Context, host *sidecar.ServiceHost, clusterIds []string, settings *WriteBudgetSettings) (*WriteBudgetClient, error) {
	client, err := newWriteBudgetClient(ctx, host, clusterIds, settings)
	if err != nil {
		return nil, err
	}
	go client.runAccounts()
	go client.runWeights()
	return client, nil
}

// NewWriteBudget without its goroutines, which a test drives through tick and refreshWeights.
func newWriteBudgetClient(ctx context.Context, host *sidecar.ServiceHost, clusterIds []string, settings *WriteBudgetSettings) (*WriteBudgetClient, error) {
	if settings == nil {
		settings = DefaultWriteBudgetSettings()
	}
	if host == nil || host.Redis == nil {
		return nil, errors.New("the write budget needs ServiceHost.Redis")
	}
	if clusterIds == nil && host.Blobs != nil {
		clusterIds = host.Blobs.MetadataClusterIds()
	}
	if len(clusterIds) == 0 {
		return nil, errors.New("the write budget needs a metadata cluster")
	}
	processIdBytes := make([]byte, 16)
	if _, err := rand.Read(processIdBytes); err != nil {
		return nil, err
	}
	clock := host.ClockOrReal()
	cancelCtx, cancel := context.WithCancel(ctx)
	client := &WriteBudgetClient{
		ctx:               cancelCtx,
		cancel:            cancel,
		settings:          settings,
		clock:             clock,
		redis:             host.Redis,
		processId:         hex.EncodeToString(processIdBytes),
		startTime:         clock.Now(),
		weights:           newWriteBudgetWeights(settings, host.Quota),
		clusterIdAccounts: map[string]*writeBudgetAccount{},
	}
	if host.Metrics != nil {
		client.issuedCounter = host.Metrics.Counter(
			writeBudgetIssuedMetricName,
			"Priced bytes issued against each metadata cluster's write budget, by class, and by kind for P0.",
			"cluster", "class", "kind",
		)
	}
	for _, clusterId := range clusterIds {
		if _, exists := client.clusterIdAccounts[clusterId]; exists {
			cancel()
			return nil, fmt.Errorf("cluster %s twice", clusterId)
		}
		client.clusterIdAccounts[clusterId] = newWriteBudgetAccount(client, clusterId)
	}
	return client, nil
}

// Ends the goroutines, refuses every P1 waiting and fails every P2 waiting. Safe more than once.
func (self *WriteBudgetClient) Close() {
	self.cancel()
	for _, account := range self.clusterIdAccounts {
		account.close()
	}
}

// Ticks each account at once, then every Interval.
func (self *WriteBudgetClient) runAccounts() {
	clusterIds := slices.Sorted(maps.Keys(self.clusterIdAccounts))
	for {
		for _, clusterId := range clusterIds {
			self.clusterIdAccounts[clusterId].tick(self.ctx)
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.Interval):
		}
	}
}

// Rereads the active networks' weights every WeightRefreshInterval.
func (self *WriteBudgetClient) runWeights() {
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.WeightRefreshInterval):
		}
		self.weights.refresh(self.ctx, self.clock)
	}
}

// The account for clusterId, ErrWriteBudgetCluster when the process holds none.
func (self *WriteBudgetClient) account(clusterId string) (*writeBudgetAccount, error) {
	account, ok := self.clusterIdAccounts[clusterId]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrWriteBudgetCluster, clusterId)
	}
	return account, nil
}

// Counts the bytes and returns: see sidecar.WriteBudget. A kind outside the vocabulary counts as
// lifecycle's, so no P0 byte goes unmeasured, and a cluster with no account counts nowhere, since its
// write has no cluster to go to.
func (self *WriteBudgetClient) IssueP0(ctx context.Context, clusterId string, kind sidecar.WriteP0Kind, byteCount int64) context.Context {
	if account, ok := self.clusterIdAccounts[clusterId]; ok && 0 < byteCount {
		if !kind.Valid() {
			kind = sidecar.WriteP0KindLifecycle
		}
		account.p0KindByteCounts[kind].Add(byteCount)
	}
	return sidecar.WithWriteClass(ctx, sidecar.WriteClassP0)
}

// See sidecar.WriteBudget.
func (self *WriteBudgetClient) AdmitP1(ctx context.Context, clusterId string, networkId connect.Id, cost sidecar.WriteCost) (sidecar.WriteGrant, error) {
	if err := cost.Validate(); err != nil {
		return nil, err
	}
	if networkId == (connect.Id{}) {
		return nil, ErrWriteBudgetNetwork
	}
	account, err := self.account(clusterId)
	if err != nil {
		return nil, err
	}
	now := self.clock.Now()
	waiter := &writeBudgetP1Waiter{
		networkId:   networkId,
		cost:        cost,
		weight:      self.weights.weight(networkId, now),
		enqueueTime: now,
		decided:     make(chan struct{}),
	}
	state := account.offerP1(waiter)
	if state == writeBudgetWaiting {
		if self.waitHook != nil {
			self.waitHook()
		}
		select {
		case <-waiter.decided:
			state = account.p1State(waiter)
		case <-ctx.Done():
			if state = account.abandonP1(waiter); state == writeBudgetAbandoned {
				return nil, ctx.Err()
			}
		}
	}
	switch state {
	case writeBudgetAdmitted:
		return account.newGrant(ctx, sidecar.WriteClassP1, cost.ImmediateByteCount), nil
	case writeBudgetRefused:
		return nil, &sidecar.WriteRefusal{ClusterId: clusterId, RetryAfter: self.settings.RefusalRetryAfter}
	}
	return nil, ErrWriteBudgetClosed
}

// A work AcquireP2 can take: a rank, and no negative size.
func validateWriteP2Work(work *sidecar.WriteP2Work) error {
	if work == nil || !work.Rank.Valid() || work.ByteCount < 0 {
		return fmt.Errorf("%w: a P2 work", sidecar.ErrWriteCost)
	}
	return nil
}

// See sidecar.WriteBudget.
func (self *WriteBudgetClient) AcquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, error) {
	if err := validateWriteP2Work(work); err != nil {
		return nil, err
	}
	account, err := self.account(clusterId)
	if err != nil {
		return nil, err
	}
	waiter := account.offerP2(work)
	if self.waitHook != nil && account.p2State(waiter) == writeBudgetWaiting {
		self.waitHook()
	}
	select {
	case <-waiter.decided:
	case <-ctx.Done():
		account.abandonP2(waiter)
		return nil, ctx.Err()
	}
	if account.p2State(waiter) != writeBudgetAdmitted {
		return nil, ErrWriteBudgetClosed
	}
	return account.issueP2(ctx, waiter)
}

// See sidecar.WriteBudget.
func (self *WriteBudgetClient) TryAcquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, bool, error) {
	if err := validateWriteP2Work(work); err != nil {
		return nil, false, err
	}
	account, err := self.account(clusterId)
	if err != nil {
		return nil, false, err
	}
	waiter, ok := account.tryReserveP2(work)
	if !ok {
		return nil, false, nil
	}
	grant, err := account.issueP2(ctx, waiter)
	if err != nil {
		return nil, false, err
	}
	return grant, true, nil
}

// See sidecar.WriteBudget. A cluster with no account, a rank outside §11.13's or a size below zero
// declares nothing.
func (self *WriteBudgetClient) DeclareP2Backlog(clusterId string, owner string, rank sidecar.WriteP2Rank, funded bool, byteCount int64) {
	account, ok := self.clusterIdAccounts[clusterId]
	if !ok || !rank.Valid() || byteCount < 0 || owner == "" {
		return
	}
	account.stateLock.Lock()
	defer account.stateLock.Unlock()
	backlogs, ok := account.ownerBacklogs[owner]
	if !ok {
		backlogs = &[2][sidecar.WriteP2RankCount]int64{}
		account.ownerBacklogs[owner] = backlogs
	}
	backlogs[writeBudgetFundedIndex(funded)][rank] = byteCount
}

// The index of an owner's backlogs for funded or unfunded work.
func writeBudgetFundedIndex(funded bool) int {
	if funded {
		return 1
	}
	return 0
}

// This process's part of the cluster's copy rate: the rate the governor published over the processes
// copying, this one counted, or the base rate while there is no allowance.
func (self *WriteBudgetClient) CopyOpsPerSecond(clusterId string) int {
	account, ok := self.clusterIdAccounts[clusterId]
	if !ok {
		return 0
	}
	account.stateLock.Lock()
	defer account.stateLock.Unlock()
	allowance := account.allowance
	if allowance == nil {
		return self.settings.CopyOpsPerSecond
	}
	copyProcessCount := allowance.CopyProcessCount
	if !account.copyingWithLock() {
		copyProcessCount += 1
	}
	return allowance.CopyOpsPerSecond / max(1, copyProcessCount)
}

// §19.9's line from the cluster's last allowance, kept while the key is absent (plan-EVSB-nvb-fields).
func (self *WriteBudgetClient) AtLimit(clusterId string) bool {
	account, ok := self.clusterIdAccounts[clusterId]
	if !ok {
		return false
	}
	account.stateLock.Lock()
	defer account.stateLock.Unlock()
	return account.allowance != nil && account.allowance.AtLimit
}

// The id this process reports under.
func (self *WriteBudgetClient) ProcessId() string {
	return self.processId
}

// The issued totals the metric last carried, so each tick adds what is new.
type writeBudgetExported struct {
	p0KindByteCounts  map[sidecar.WriteP0Kind]int64
	p1ByteCount       int64
	fundedByteCount   int64
	unfundedByteCount int64
}

// One metadata cluster's part of the process's budget.
type writeBudgetAccount struct {
	client    *WriteBudgetClient
	clusterId string
	// every kind's counter, made at construction, so IssueP0 adds without a lock
	p0KindByteCounts map[sidecar.WriteP0Kind]*atomic.Int64

	stateLock sync.Mutex
	closed    bool
	// the interval the pools below are of, which a P2 reservation gives its bytes back to
	epoch         uint64
	p1Left        int64
	unfundedLeft  int64
	uncoveredLeft int64
	fundedLeft    int64
	// the last allowance read
	allowance *WriteBudgetAllowance
	fallback  writeBudgetFallback
	// totals since the process started, priced bytes
	p1ByteCount       int64
	creditByteCount   int64
	unfundedByteCount int64
	fundedByteCount   int64
	inFlightByteCount int64
	// funded P2 issued this interval, for the fallback's rate
	fundedIssuedByteCount int64
	// what each owner declared, unfunded then funded, by rank
	ownerBacklogs map[string]*[2][sidecar.WriteP2RankCount]int64
	p1            *writeBudgetP1Queue
	p2            *writeBudgetP2Queue
	// the pending shed check, and when it fires
	shedStop func() bool
	shedAt   time.Time
	exported writeBudgetExported
}

// An account with no share until its first tick.
func newWriteBudgetAccount(client *WriteBudgetClient, clusterId string) *writeBudgetAccount {
	account := &writeBudgetAccount{
		client:           client,
		clusterId:        clusterId,
		p0KindByteCounts: map[sidecar.WriteP0Kind]*atomic.Int64{},
		ownerBacklogs:    map[string]*[2][sidecar.WriteP2RankCount]int64{},
		p1:               newWriteBudgetP1Queue(),
		p2:               &writeBudgetP2Queue{},
		exported:         writeBudgetExported{p0KindByteCounts: map[sidecar.WriteP0Kind]int64{}},
	}
	for _, kind := range sidecar.WriteP0Kinds {
		account.p0KindByteCounts[kind] = &atomic.Int64{}
	}
	return account
}

// Counts an admitted P1's price: its immediate part issued and in flight, its deferred part credit.
func (self *writeBudgetAccount) admitP1WithLock(cost sidecar.WriteCost) {
	self.p1ByteCount += cost.ImmediateByteCount
	self.creditByteCount += cost.DeferredByteCount
	self.inFlightByteCount += cost.ImmediateByteCount
}

// Admits waiter at once when nothing waits ahead and the share covers it, else queues it and runs the
// shed rule. Returns where it stands.
func (self *writeBudgetAccount) offerP1(waiter *writeBudgetP1Waiter) writeBudgetWaiterState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return writeBudgetAbandoned
	}
	price := waiter.cost.ByteCount()
	if price == 0 || (self.p1.emptyWithLock() && price <= self.p1Left) {
		self.p1Left -= price
		self.admitP1WithLock(waiter.cost)
		waiter.state = writeBudgetAdmitted
		return waiter.state
	}
	self.p1.enqueueWithLock(waiter)
	now := self.client.clock.Now()
	self.shedWithLock(now)
	self.armShedWithLock(now)
	return waiter.state
}

// Where a decided waiter stands.
func (self *writeBudgetAccount) p1State(waiter *writeBudgetP1Waiter) writeBudgetWaiterState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return waiter.state
}

// Takes a waiter whose ctx ended out of its queue, unless it was decided first, and returns where it
// stands.
func (self *writeBudgetAccount) abandonP1(waiter *writeBudgetP1Waiter) writeBudgetWaiterState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if waiter.state == writeBudgetWaiting {
		waiter.state = writeBudgetAbandoned
		self.p1.removeWithLock(waiter)
		close(waiter.decided)
		self.armShedWithLock(self.client.clock.Now())
	}
	return waiter.state
}

// Admits waiters in fair order while the P1 share covers the next.
func (self *writeBudgetAccount) dispatchP1WithLock() {
	for {
		waiter := self.p1.nextWithLock()
		if waiter == nil {
			return
		}
		price := waiter.cost.ByteCount()
		if self.p1Left < price {
			return
		}
		self.p1Left -= price
		waiter.state = writeBudgetAdmitted
		self.p1.removeWithLock(waiter)
		self.admitP1WithLock(waiter.cost)
		close(waiter.decided)
	}
}

// §11.13's shed row: while the oldest waiter has waited ShedDelay, refuses every waiter of the
// heaviest network, never the last network waiting.
func (self *writeBudgetAccount) shedWithLock(now time.Time) {
	for {
		oldest, ok := self.p1.oldestEnqueueTimeWithLock()
		if !ok || now.Sub(oldest) < self.client.settings.ShedDelay {
			return
		}
		networkId, ok := self.p1.heaviestNetworkWithLock()
		if !ok {
			return
		}
		for _, waiter := range self.p1.networkWaitersWithLock(networkId) {
			waiter.state = writeBudgetRefused
			self.p1.removeWithLock(waiter)
			close(waiter.decided)
		}
	}
}

// Arms the shed check for when the oldest waiter reaches ShedDelay, once: a waiter already past it is
// checked again when another network queues.
func (self *writeBudgetAccount) armShedWithLock(now time.Time) {
	oldest, ok := self.p1.oldestEnqueueTimeWithLock()
	if !ok {
		if self.shedStop != nil {
			self.shedStop()
			self.shedStop = nil
		}
		return
	}
	at := oldest.Add(self.client.settings.ShedDelay)
	if !now.Before(at) || (self.shedStop != nil && self.shedAt.Equal(at)) {
		return
	}
	if self.shedStop != nil {
		self.shedStop()
	}
	self.shedAt = at
	self.shedStop = self.client.clock.AfterFunc(at.Sub(now), func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.shedAt.Equal(at) {
			return
		}
		self.shedStop = nil
		now := self.client.clock.Now()
		self.shedWithLock(now)
		self.armShedWithLock(now)
	})
}

// Queues work and serves the queue.
func (self *writeBudgetAccount) offerP2(work *sidecar.WriteP2Work) *writeBudgetP2Waiter {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	waiter := self.p2.enqueueWithLock(work)
	if self.closed {
		waiter.state = writeBudgetAbandoned
		self.p2.removeWithLock(waiter)
		close(waiter.decided)
		return waiter
	}
	self.dispatchP2WithLock()
	return waiter
}

// Where a decided waiter stands.
func (self *writeBudgetAccount) p2State(waiter *writeBudgetP2Waiter) writeBudgetWaiterState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return waiter.state
}

// Takes a waiter whose ctx ended out of the queue, or gives back the bytes it was reserved.
func (self *writeBudgetAccount) abandonP2(waiter *writeBudgetP2Waiter) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch waiter.state {
	case writeBudgetWaiting:
		waiter.state = writeBudgetAbandoned
		self.p2.removeWithLock(waiter)
		close(waiter.decided)
	case writeBudgetAdmitted:
		self.releaseWithLock(waiter)
	}
}

// Reserves work's bytes from its pools, false when they do not cover it: funded work from the funded
// share, then the uncovered part of the unfunded share; unfunded work from the rest of that share.
func (self *writeBudgetAccount) reserveWithLock(work *sidecar.WriteP2Work) (writeBudgetPool, bool) {
	size := work.ByteCount
	if work.Funded {
		switch {
		case size <= self.fundedLeft:
			self.fundedLeft -= size
			return writeBudgetPoolFunded, true
		case size <= self.uncoveredLeft:
			self.uncoveredLeft -= size
			return writeBudgetPoolUncovered, true
		}
		return 0, false
	}
	if size <= self.unfundedLeft {
		self.unfundedLeft -= size
		return writeBudgetPoolUnfunded, true
	}
	return 0, false
}

// Gives a reservation's bytes back to its interval's pool, and serves the queue again. Bytes of an
// interval that has passed lapse with it.
func (self *writeBudgetAccount) releaseWithLock(waiter *writeBudgetP2Waiter) {
	waiter.state = writeBudgetAbandoned
	if waiter.epoch == self.epoch {
		size := waiter.work.ByteCount
		switch waiter.pool {
		case writeBudgetPoolFunded:
			self.fundedLeft += size
		case writeBudgetPoolUncovered:
			self.uncoveredLeft += size
		case writeBudgetPoolUnfunded:
			self.unfundedLeft += size
		}
	}
	self.dispatchP2WithLock()
}

// Reserves waiters in §11.13's order while their pools cover them, each account holding back what
// comes after a waiter that does not fit.
func (self *writeBudgetAccount) dispatchP2WithLock() {
	fundedBlocked := false
	unfundedBlocked := false
	for _, waiter := range slices.Clone(self.p2.waiters) {
		if (waiter.work.Funded && fundedBlocked) || (!waiter.work.Funded && unfundedBlocked) {
			continue
		}
		pool, ok := self.reserveWithLock(waiter.work)
		if !ok {
			if waiter.work.Funded {
				fundedBlocked = true
			} else {
				unfundedBlocked = true
			}
			continue
		}
		waiter.pool = pool
		waiter.epoch = self.epoch
		waiter.state = writeBudgetAdmitted
		self.p2.removeWithLock(waiter)
		close(waiter.decided)
	}
}

// TryAcquireP2's reservation: nothing of the work's rank or before waits in its account, and its pools
// cover it now.
func (self *writeBudgetAccount) tryReserveP2(work *sidecar.WriteP2Work) (*writeBudgetP2Waiter, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed || self.p2.blocksWithLock(work) {
		return nil, false
	}
	pool, ok := self.reserveWithLock(work)
	if !ok {
		return nil, false
	}
	return &writeBudgetP2Waiter{work: work, state: writeBudgetAdmitted, pool: pool, epoch: self.epoch}, true
}

// Runs a reserved work's Recheck, outside the lock, then issues it, or gives its bytes back.
func (self *writeBudgetAccount) issueP2(ctx context.Context, waiter *writeBudgetP2Waiter) (sidecar.WriteGrant, error) {
	testHookBarrier("evs.budget.p2.recheck", self.clusterId)
	if waiter.work.Recheck != nil {
		if err := waiter.work.Recheck(ctx); err != nil {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.releaseWithLock(waiter)
			}()
			return nil, err
		}
	}
	size := waiter.work.ByteCount
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch waiter.pool {
		case writeBudgetPoolFunded:
			self.fundedByteCount += size
			self.fundedIssuedByteCount += size
		default:
			self.unfundedByteCount += size
		}
		self.inFlightByteCount += size
	}()
	testHookBarrier("evs.budget.p2.issued", self.clusterId)
	return self.newGrant(ctx, sidecar.WriteClassP2, size), nil
}

// Whether this process has copies waiting or declared.
func (self *writeBudgetAccount) copyingWithLock() bool {
	for _, waiter := range self.p2.waiters {
		if waiter.work.Rank == sidecar.WriteP2RankCopy {
			return true
		}
	}
	for _, backlogs := range self.ownerBacklogs {
		if 0 < backlogs[0][sidecar.WriteP2RankCopy] || 0 < backlogs[1][sidecar.WriteP2RankCopy] {
			return true
		}
	}
	return false
}

// The process's report on this cluster as of now.
func (self *writeBudgetAccount) reportWithLock(now time.Time) *WriteBudgetReport {
	fundedDemand, unfundedDemand := self.p2.demandWithLock()
	fundedBacklog := slices.Clone(fundedDemand)
	unfundedBacklog := slices.Clone(unfundedDemand)
	var declared [2][sidecar.WriteP2RankCount]int64
	for _, backlogs := range self.ownerBacklogs {
		for fundedIndex := range 2 {
			for rank := range sidecar.WriteP2RankCount {
				declared[fundedIndex][rank] += backlogs[fundedIndex][rank]
			}
		}
	}
	// an owner's declaration holds the work it has waiting, so the larger of the two is the backlog
	for rank := range sidecar.WriteP2RankCount {
		unfundedBacklog[rank] = max(unfundedBacklog[rank], declared[0][rank])
		fundedBacklog[rank] = max(fundedBacklog[rank], declared[1][rank])
	}
	p0ByteCounts := map[sidecar.WriteP0Kind]int64{}
	for kind, byteCount := range self.p0KindByteCounts {
		if total := byteCount.Load(); 0 < total {
			p0ByteCounts[kind] = total
		}
	}
	return &WriteBudgetReport{
		ProcessId:                 self.client.processId,
		StartMs:                   self.client.startTime.UnixMilli(),
		TimeMs:                    now.UnixMilli(),
		P0ByteCounts:              p0ByteCounts,
		P1ByteCount:               self.p1ByteCount,
		CreditByteCount:           self.creditByteCount,
		UnfundedByteCount:         self.unfundedByteCount,
		FundedByteCount:           self.fundedByteCount,
		P1QueuedByteCount:         self.p1.queuedByteCount,
		InFlightByteCount:         self.inFlightByteCount,
		UnfundedDemandByteCounts:  unfundedDemand,
		UnfundedBacklogByteCounts: unfundedBacklog,
		FundedDemandByteCounts:    fundedDemand,
		FundedBacklogByteCounts:   fundedBacklog,
	}
}

// One interval: reads the cluster's allowance, and the loop's saved state while the process has never
// had one, takes the next shares, serves the queues and writes the report. A Redis error leaves the
// interval as if nothing was read or written; the fallback covers it.
func (self *writeBudgetAccount) tick(ctx context.Context) {
	client := self.client
	input := &writeBudgetIntervalInput{now: client.clock.Now()}
	if allowance, err := readWriteBudgetAllowance(ctx, client.redis, self.clusterId); err == nil {
		input.allowance = allowance
	}
	hadAllowance := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.fallback.hadAllowance
	}()
	if !hadAllowance {
		if state, err := LoadGovernorState(ctx, client.redis, self.clusterId); err == nil && state != nil {
			input.stateRead = true
			input.stateBucketByteCount = state.BucketByteCount
			input.stateCalibration = state.Calibration
			input.processCount = len(state.Processes)
		}
		if input.processCount == 0 {
			if count, err := readWriteBudgetReportCount(ctx, client.redis, self.clusterId); err == nil {
				input.processCount = count
			}
		}
		// this process, which a count read before its first report does not hold
		input.processCount += 1
	}
	report := func() *WriteBudgetReport {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil
		}
		share, _ := self.fallback.takeShares(client.settings, client.processId, input, self.fundedIssuedByteCount)
		self.fundedIssuedByteCount = 0
		if input.allowance != nil {
			self.allowance = input.allowance
		}
		// last interval's shares lapse
		self.epoch += 1
		self.p1Left = share.P1ByteCount
		self.uncoveredLeft = min(max(0, share.UncoveredByteCount), share.UnfundedByteCount)
		self.unfundedLeft = share.UnfundedByteCount - self.uncoveredLeft
		self.fundedLeft = share.FundedByteCount
		self.dispatchP1WithLock()
		self.dispatchP2WithLock()
		self.armShedWithLock(input.now)
		return self.reportWithLock(input.now)
	}()
	if report == nil {
		return
	}
	writeWriteBudgetReport(ctx, client.redis, client.settings, self.clusterId, report)
	self.export(report)
}

// Adds what the report's totals gained since the last export to the issued metric.
func (self *writeBudgetAccount) export(report *WriteBudgetReport) {
	counter := self.client.issuedCounter
	if counter == nil {
		return
	}
	exported := &self.exported
	for _, kind := range sidecar.WriteP0Kinds {
		if delta := report.P0ByteCounts[kind] - exported.p0KindByteCounts[kind]; 0 < delta {
			counter.Add(float64(delta), self.clusterId, writeBudgetMetricClassP0, string(kind))
			exported.p0KindByteCounts[kind] = report.P0ByteCounts[kind]
		}
	}
	if delta := report.P1ByteCount - exported.p1ByteCount; 0 < delta {
		counter.Add(float64(delta), self.clusterId, writeBudgetMetricClassP1, "")
		exported.p1ByteCount = report.P1ByteCount
	}
	if delta := report.FundedByteCount - exported.fundedByteCount; 0 < delta {
		counter.Add(float64(delta), self.clusterId, writeBudgetMetricClassP2Funded, "")
		exported.fundedByteCount = report.FundedByteCount
	}
	if delta := report.UnfundedByteCount - exported.unfundedByteCount; 0 < delta {
		counter.Add(float64(delta), self.clusterId, writeBudgetMetricClassP2Unfunded, "")
		exported.unfundedByteCount = report.UnfundedByteCount
	}
}

// Refuses every P1 waiting and fails every P2 waiting, and takes nothing more.
func (self *writeBudgetAccount) close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	self.closed = true
	for !self.p1.emptyWithLock() {
		waiter := self.p1.nextWithLock()
		waiter.state = writeBudgetAbandoned
		self.p1.removeWithLock(waiter)
		close(waiter.decided)
	}
	for _, waiter := range slices.Clone(self.p2.waiters) {
		waiter.state = writeBudgetAbandoned
		self.p2.removeWithLock(waiter)
		close(waiter.decided)
	}
	if self.shedStop != nil {
		self.shedStop()
		self.shedStop = nil
	}
}

// A grant whose bytes are in flight until closed.
func (self *writeBudgetAccount) newGrant(ctx context.Context, class sidecar.WriteClass, inFlightByteCount int64) *writeBudgetGrant {
	return &writeBudgetGrant{
		account:           self,
		ctx:               sidecar.WithWriteClass(ctx, class),
		inFlightByteCount: inFlightByteCount,
	}
}

// Safe for concurrent use.
type writeBudgetGrant struct {
	account           *writeBudgetAccount
	ctx               context.Context
	inFlightByteCount int64
	closeOnce         sync.Once
}

// The admission's ctx with its class.
func (self *writeBudgetGrant) Context() context.Context {
	return self.ctx
}

// Takes its bytes out of flight, once.
func (self *writeBudgetGrant) Close() {
	self.closeOnce.Do(func() {
		self.account.stateLock.Lock()
		defer self.account.stateLock.Unlock()
		self.account.inFlightByteCount -= self.inFlightByteCount
	})
}

var _ sidecar.WriteBudget = (*WriteBudgetClient)(nil)
