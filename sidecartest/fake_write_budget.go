// ServiceHost.Budget in memory (host_budget.go), for engines whose tests are not about the budget: it
// admits every write unless a test refuses a network's P1 on a cluster, counts what each class spent,
// and runs a P2 work's Recheck where the real one does, at issue. It keeps the promises a caller can
// break: a P0 kind or a P2 rank outside the vocabulary, or a cost below zero, is a violation, and the
// write is still counted, as the real budget never loses a P0 byte. The accounts themselves, the
// governor and the fair queues are evsservice's, which FS-116 and its own tests run.

package sidecartest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

type FakeWriteBudgetSettings struct {
	// What CopyOpsPerSecond answers until a test sets another: §11.6's 250 a cluster.
	CopyOpsPerSecond int
	// A refusal's retry_after_ms.
	RefusalRetryAfter time.Duration
}

// §11.6's copy rate and one interval's retry.
func DefaultFakeWriteBudgetSettings() *FakeWriteBudgetSettings {
	return &FakeWriteBudgetSettings{
		CopyOpsPerSecond:  250,
		RefusalRetryAfter: 5 * time.Second,
	}
}

// One cluster's counts.
type fakeWriteBudgetCluster struct {
	p0KindByteCounts map[sidecar.WriteP0Kind]int64
	// at full price
	p1ByteCount     int64
	creditByteCount int64
	p2FundedCount   int64
	p2UnfundedCount int64
	// what DeclareP2Backlog was told, by owner, funded or not, and rank
	ownerBacklogs     map[string]*[2][sidecar.WriteP2RankCount]int64
	refusedNetworkIds map[connect.Id]bool
	copyOpsPerSecond  int
}

// Safe for concurrent use.
type FakeWriteBudget struct {
	settings *FakeWriteBudgetSettings

	stateLock         sync.Mutex
	clusterIdClusters map[string]*fakeWriteBudgetCluster
	inFlightByteCount int64
	violations        []string
}

// A budget that admits everything. settings may be nil for the defaults.
func NewFakeWriteBudget(settings *FakeWriteBudgetSettings) *FakeWriteBudget {
	if settings == nil {
		settings = DefaultFakeWriteBudgetSettings()
	}
	return &FakeWriteBudget{
		settings:          settings,
		clusterIdClusters: map[string]*fakeWriteBudgetCluster{},
	}
}

// The cluster's counts, made on first use.
func (self *FakeWriteBudget) clusterWithLock(clusterId string) *fakeWriteBudgetCluster {
	cluster, ok := self.clusterIdClusters[clusterId]
	if !ok {
		cluster = &fakeWriteBudgetCluster{
			p0KindByteCounts:  map[sidecar.WriteP0Kind]int64{},
			ownerBacklogs:     map[string]*[2][sidecar.WriteP2RankCount]int64{},
			refusedNetworkIds: map[connect.Id]bool{},
			copyOpsPerSecond:  self.settings.CopyOpsPerSecond,
		}
		self.clusterIdClusters[clusterId] = cluster
	}
	return cluster
}

// Records a broken promise.
func (self *FakeWriteBudget) violateWithLock(format string, args ...any) {
	self.violations = append(self.violations, fmt.Sprintf(format, args...))
}

// What callers did that the interface forbids.
func (self *FakeWriteBudget) Violations() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.violations...)
}

// Counts the bytes by kind, as the real one does, and never refuses.
func (self *FakeWriteBudget) IssueP0(ctx context.Context, clusterId string, kind sidecar.WriteP0Kind, byteCount int64) context.Context {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !kind.Valid() {
			self.violateWithLock("P0 of kind %q", kind)
		}
		if byteCount < 0 {
			self.violateWithLock("P0 of %d bytes", byteCount)
		}
		self.clusterWithLock(clusterId).p0KindByteCounts[kind] += byteCount
	}()
	return sidecar.WithWriteClass(ctx, sidecar.WriteClassP0)
}

// Admits at once unless the network is refused on the cluster.
func (self *FakeWriteBudget) AdmitP1(ctx context.Context, clusterId string, networkId connect.Id, cost sidecar.WriteCost) (sidecar.WriteGrant, error) {
	if err := cost.Validate(); err != nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.violateWithLock("P1 %v", err)
		}()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	refused := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cluster := self.clusterWithLock(clusterId)
		if cluster.refusedNetworkIds[networkId] {
			refused = true
			return
		}
		cluster.p1ByteCount += cost.ByteCount()
		cluster.creditByteCount += cost.DeferredByteCount
		self.inFlightByteCount += cost.ImmediateByteCount
	}()
	if refused {
		return nil, &sidecar.WriteRefusal{ClusterId: clusterId, RetryAfter: self.settings.RefusalRetryAfter}
	}
	return self.newGrant(ctx, sidecar.WriteClassP1, cost.ImmediateByteCount), nil
}

// Runs the work's Recheck and admits it at once.
func (self *FakeWriteBudget) acquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, error) {
	ok := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if work == nil || !work.Rank.Valid() || work.ByteCount < 0 {
			self.violateWithLock("P2 work %+v", work)
			return false
		}
		return true
	}()
	if !ok {
		return nil, fmt.Errorf("%w: a P2 work", sidecar.ErrWriteCost)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if work.Recheck != nil {
		if err := work.Recheck(ctx); err != nil {
			return nil, err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cluster := self.clusterWithLock(clusterId)
		if work.Funded {
			cluster.p2FundedCount += work.ByteCount
		} else {
			cluster.p2UnfundedCount += work.ByteCount
		}
		self.inFlightByteCount += work.ByteCount
	}()
	return self.newGrant(ctx, sidecar.WriteClassP2, work.ByteCount), nil
}

// Never waits.
func (self *FakeWriteBudget) AcquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, error) {
	return self.acquireP2(ctx, clusterId, work)
}

// Always succeeds unless the work is invalid or its Recheck refuses.
func (self *FakeWriteBudget) TryAcquireP2(ctx context.Context, clusterId string, work *sidecar.WriteP2Work) (sidecar.WriteGrant, bool, error) {
	grant, err := self.acquireP2(ctx, clusterId, work)
	if err != nil {
		return nil, false, err
	}
	return grant, true, nil
}

// Keeps what owner declared, for P2Backlog.
func (self *FakeWriteBudget) DeclareP2Backlog(clusterId string, owner string, rank sidecar.WriteP2Rank, funded bool, byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !rank.Valid() || byteCount < 0 || owner == "" {
		self.violateWithLock("backlog of %d at rank %d by %q", byteCount, rank, owner)
		return
	}
	cluster := self.clusterWithLock(clusterId)
	backlogs, ok := cluster.ownerBacklogs[owner]
	if !ok {
		backlogs = &[2][sidecar.WriteP2RankCount]int64{}
		cluster.ownerBacklogs[owner] = backlogs
	}
	fundedIndex := 0
	if funded {
		fundedIndex = 1
	}
	backlogs[fundedIndex][rank] = byteCount
}

// What SetCopyOpsPerSecond last set, else the settings' rate.
func (self *FakeWriteBudget) CopyOpsPerSecond(clusterId string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clusterWithLock(clusterId).copyOpsPerSecond
}

// Refuses, or admits again, the network's P1 on the cluster.
func (self *FakeWriteBudget) RefuseP1(clusterId string, networkId connect.Id, refused bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clusterWithLock(clusterId).refusedNetworkIds[networkId] = refused
}

// What CopyOpsPerSecond answers for the cluster.
func (self *FakeWriteBudget) SetCopyOpsPerSecond(clusterId string, opsPerSecond int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clusterWithLock(clusterId).copyOpsPerSecond = opsPerSecond
}

// P0's priced bytes of kind on the cluster.
func (self *FakeWriteBudget) P0ByteCount(clusterId string, kind sidecar.WriteP0Kind) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clusterWithLock(clusterId).p0KindByteCounts[kind]
}

// P1's admitted priced bytes on the cluster at full price, and the deferred part among them.
func (self *FakeWriteBudget) P1ByteCount(clusterId string) (byteCount int64, creditByteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	cluster := self.clusterWithLock(clusterId)
	return cluster.p1ByteCount, cluster.creditByteCount
}

// P2's acquired priced bytes on the cluster, funded or not.
func (self *FakeWriteBudget) P2ByteCount(clusterId string, funded bool) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	cluster := self.clusterWithLock(clusterId)
	if funded {
		return cluster.p2FundedCount
	}
	return cluster.p2UnfundedCount
}

// What owner last declared at rank on the cluster.
func (self *FakeWriteBudget) P2Backlog(clusterId string, owner string, rank sidecar.WriteP2Rank, funded bool) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	backlogs, ok := self.clusterWithLock(clusterId).ownerBacklogs[owner]
	if !ok || !rank.Valid() {
		return 0
	}
	fundedIndex := 0
	if funded {
		fundedIndex = 1
	}
	return backlogs[fundedIndex][rank]
}

// Priced bytes of grants not yet closed.
func (self *FakeWriteBudget) InFlightByteCount() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.inFlightByteCount
}

// A grant holding inFlightByteCount in flight until closed.
func (self *FakeWriteBudget) newGrant(ctx context.Context, class sidecar.WriteClass, inFlightByteCount int64) *fakeWriteGrant {
	return &fakeWriteGrant{
		budget:            self,
		ctx:               sidecar.WithWriteClass(ctx, class),
		inFlightByteCount: inFlightByteCount,
	}
}

// Safe for concurrent use.
type fakeWriteGrant struct {
	budget            *FakeWriteBudget
	ctx               context.Context
	inFlightByteCount int64
	closeOnce         sync.Once
}

// The admission's ctx with its class.
func (self *fakeWriteGrant) Context() context.Context {
	return self.ctx
}

// Takes its bytes out of flight, once.
func (self *fakeWriteGrant) Close() {
	self.closeOnce.Do(func() {
		self.budget.stateLock.Lock()
		defer self.budget.stateLock.Unlock()
		self.budget.inFlightByteCount -= self.inFlightByteCount
	})
}

var _ sidecar.WriteBudget = (*FakeWriteBudget)(nil)
