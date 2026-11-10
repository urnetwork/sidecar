// The storage-limit gate on evs (EVSB-M2-15): §11.13's limit, wait and transfer rows and §20.7's limit, closure
// and allow rows. QuotaGate keeps the over-limit list Quota.OverLimit gives, reread every OverLimitInterval on
// its own goroutine, and classifies a push or an upload against it with no I/O, so a network past its storage
// limit, or spent, is refused new payload within one interval of api's list, itself a minute behind the usage
// batches (overshooting by up to a minute), and nothing else is:
//
//   - CheckUpload, a segment upload (EVSB-M2-09): refused while the network is over its limit or spent, a
//     re-seed upload excepted. A ?closure=1 upload goes to ChargeClosure instead.
//   - CheckPush, step 5c (EVS1-M2-11): a push naming a new segment or inline record is refused; maintenance,
//     which adds no payload (CONSUME, BASE, ERASE, PATH_EPOCH and its maps, DELETE, a repo's deletion and
//     restore, EvsReseed), a CUT, an erasure's CLOSURE, a DROP that uploads no segment, a cancel, and config and
//     mailcfg pushes, which §7.9's own limits bound, are accepted.
//   - ChargeClosure, a ?closure=1 upload at the limit or while spent: at most 1,088 KiB, the eraser's own 60 a
//     minute and its turn of the network's pacing (evs_closure_uploads_per_s in equal turns), and its own daily
//     allowance, never under evs_closure_bytes_floor, all counted by Quota.CountRate on {sq_<network_id>}, a
//     refusal 429 with retry_after_ms. The eraser is the token's sidecar, so no eraser spends another's.
//   - ChargeClosureRecords, a CLOSURE push's inline records at the limit or while spent: the eraser's daily
//     allowance alone.
//   - CheckRead, a read by a spent network (quota_read_gate.go): its own repos at evs_unpaid_read_rate, another
//     network's not at all. A storage limit never touches a read.
//
// A metadata cluster at §19.9's cohort limit holds every repo placed on it to what the limit accepts
// (cluster_limit.go): QuotaRefusesAtLimit classifies a push alone, and ChargeClosureAtClusterLimit and
// ChargeClosureRecordsOn hold its closure uploads and records to the closure bounds as at the limit.
//
// Below the limit and not spent, closure uploads and records are ordinary payload, counted nowhere here.
// Storage quotas are soft (owner decisions 2, 10): until the first list is read, and while reads fail, the
// last list stands, none at first, so a gate that cannot read errs toward accepting, as CountRate fails open
// for a window when Redis is lost (§20.7). Safe for concurrent use.

package evsservice

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The push flags of §11.13's maintenance pushes, which add no payload.
const quotaMaintenanceFlags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE |
	protocol.EvsPushFlag_EVS_PUSH_BASE |
	protocol.EvsPushFlag_EVS_PUSH_CONSUME |
	protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH |
	protocol.EvsPushFlag_EVS_PUSH_ERASE)

type QuotaGateSettings struct {
	// How often Quota.OverLimit is reread: 5 s (§20.6).
	OverLimitInterval time.Duration
	// Bounds one read. Non-positive leaves it to the gate's context: 4 s, inside the interval.
	OverLimitTimeout time.Duration
	// A spent network's reads (quota_read_gate.go). nil takes the defaults.
	Read *QuotaReadSettings
}

func DefaultQuotaGateSettings() *QuotaGateSettings {
	return &QuotaGateSettings{
		OverLimitInterval: 5 * time.Second,
		OverLimitTimeout:  4 * time.Second,
		Read:              DefaultQuotaReadSettings(),
	}
}

// What step 5c knows of a push when it asks the gate. EVS1-M2-11 fills it from the push, its payload and its
// repo.
type QuotaPush struct {
	// The repo's network: its storage and spent state count, as its stored bytes do.
	NetworkId connect.Id
	// EvsPush.flags.
	Flags uint32
	// The repo is a config or mailcfg repo: authorization, which §7.9's limits bound.
	Authorization bool
	// The push deletes or restores the repo (repo/ lifecycle), or is an EvsReseed's.
	Lifecycle bool
	// The segments the push introduces and the inline records it adds.
	NewSegmentCount   int
	InlineRecordCount int
}

// See the file header.
type QuotaGate struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *QuotaGateSettings
	clock    sidecar.Clock
	quota    sidecar.Quota
	// spent networks' reads, paced here (quota_read_gate.go)
	reads *quotaReadGate

	stateLock sync.Mutex
	overLimit *sidecar.QuotaOverLimit
	readTime  time.Time
}

// The gate over host.Quota, its first read started at once. settings may be nil for the defaults. Close ends
// it.
func NewQuotaGate(ctx context.Context, host *sidecar.ServiceHost, settings *QuotaGateSettings) (*QuotaGate, error) {
	self, err := newQuotaGate(ctx, host, settings)
	if err != nil {
		return nil, err
	}
	go self.run()
	return self, nil
}

// NewQuotaGate without its goroutine, which a test drives through refresh.
func newQuotaGate(ctx context.Context, host *sidecar.ServiceHost, settings *QuotaGateSettings) (*QuotaGate, error) {
	if settings == nil {
		settings = DefaultQuotaGateSettings()
	}
	if host == nil || host.Quota == nil {
		return nil, errors.New("the quota gate needs ServiceHost.Quota")
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := host.ClockOrReal()
	return &QuotaGate{
		ctx:      cancelCtx,
		cancel:   cancel,
		settings: settings,
		clock:    clock,
		quota:    host.Quota,
		reads:    newQuotaReadGate(clock, host.Quota, settings.Read),
	}, nil
}

// Ends the rereads. The last list stands.
func (self *QuotaGate) Close() {
	self.cancel()
}

// Reads at once, then every interval, until Close.
func (self *QuotaGate) run() {
	for {
		self.refresh(self.ctx)
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.OverLimitInterval):
		}
	}
}

// One read, then the spent readers' rates. A failed read keeps the last list and every rate.
func (self *QuotaGate) refresh(ctx context.Context) {
	readCtx := ctx
	if 0 < self.settings.OverLimitTimeout {
		var cancel context.CancelFunc
		readCtx, cancel = context.WithTimeout(ctx, self.settings.OverLimitTimeout)
		defer cancel()
	}
	overLimit, err := self.quota.OverLimit(readCtx)
	if err != nil || overLimit == nil {
		return
	}
	readTime := self.clock.Now()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.overLimit = overLimit
		self.readTime = readTime
	}()
	// the limits of the spent networks reading here, under the same bound and off every read's path
	self.reads.refresh(readCtx, overLimit)
}

// The refusal the list holds for the network, its storage limit's first, nil while it is under the limit and
// not spent.
func (self *QuotaGate) refusal(networkId connect.Id) *sidecar.QuotaRefusal {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.overLimit == nil {
		return nil
	}
	if refusal, ok := self.overLimit.StorageNetworkIdRefusals[networkId]; ok && refusal != nil {
		copied := *refusal
		return &copied
	}
	if refusal, ok := self.overLimit.SpentNetworkIdRefusals[networkId]; ok && refusal != nil {
		copied := *refusal
		return &copied
	}
	return nil
}

// Whether the network is over its storage limit or spent.
func (self *QuotaGate) Over(networkId connect.Id) bool {
	return self.refusal(networkId) != nil
}

// A segment upload to a repo of the network: nil admits it. A re-seed upload passes at the limit. No I/O.
func (self *QuotaGate) CheckUpload(networkId connect.Id, reseed bool) *sidecar.QuotaRefusal {
	if reseed {
		return nil
	}
	return self.refusal(networkId)
}

// Step 5c's check: nil accepts the push. See the file header. No I/O.
func (self *QuotaGate) CheckPush(push *QuotaPush) *sidecar.QuotaRefusal {
	refusal := self.refusal(push.NetworkId)
	if refusal == nil || !QuotaRefusesAtLimit(push) {
		return nil
	}
	return refusal
}

// Whether §20.7's storage limit refuses the push, as it does for a network at its limit or spent and, through the
// cohort limit, for every repo of a full cluster (cluster_limit.go): it names a new segment or inline record and is
// none of what the limit accepts. Pure.
func QuotaRefusesAtLimit(push *QuotaPush) bool {
	switch {
	case push.Authorization || push.Lifecycle:
		return false
	case push.Flags&uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) != 0:
		// its inline records spend the eraser's allowance through ChargeClosureRecords, and its uploads
		// were charged through ChargeClosure
		return false
	case push.Flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP|protocol.EvsPushFlag_EVS_PUSH_CUT) != 0:
		// a drop or its cancel, or a CUT whose one staged record replaces its ref's erasure set: accepted
		// while it uploads no segment
		return push.NewSegmentCount != 0
	case push.Flags&quotaMaintenanceFlags != 0 && push.NewSegmentCount == 0 && push.InlineRecordCount == 0:
		return false
	}
	// a push that adds no payload passes whatever its flags
	return push.NewSegmentCount != 0 || push.InlineRecordCount != 0
}

// A ?closure=1 upload of byteCount by eraserId, the token's sidecar, to a repo of the network. Below the limit
// and not spent it is ordinary payload and nil comes back with no host call. At the limit or while spent: one
// over QuotaClosureUploadMaxByteCount is refused as any upload is, and the rest count on the eraser's rate,
// pacing and allowance under debitId, which a retry of the same upload repeats. An error means the count's
// outcome is unknown.
func (self *QuotaGate) ChargeClosure(ctx context.Context, networkId connect.Id, eraserId connect.Id, byteCount int64, debitId connect.Id) (*sidecar.QuotaRefusal, error) {
	refusal := self.refusal(networkId)
	if refusal == nil {
		return nil, nil
	}
	if byteCount < 0 || sidecar.QuotaClosureUploadMaxByteCount < byteCount {
		return refusal, nil
	}
	return self.quota.CountRate(ctx, networkId, map[string]int64{
		sidecar.QuotaRateKeyClosureUpload(eraserId): 1,
		sidecar.QuotaRateKeyClosureBytes(eraserId):  byteCount,
	}, debitId)
}

// A CLOSURE push's inline records of byteCount by eraserId at the limit or while spent: the eraser's daily
// allowance alone (§20.7's allow row). Below the limit and not spent, nil with no host call.
func (self *QuotaGate) ChargeClosureRecords(ctx context.Context, networkId connect.Id, eraserId connect.Id, byteCount int64, debitId connect.Id) (*sidecar.QuotaRefusal, error) {
	return self.ChargeClosureRecordsOn(ctx, networkId, eraserId, byteCount, debitId, false)
}

// ChargeClosureRecords for a repo whose cluster stands at its cohort limit when clusterFull, which holds the
// records to the eraser's allowance as the storage limit does, whatever the network's own state (cluster_limit.go).
func (self *QuotaGate) ChargeClosureRecordsOn(ctx context.Context, networkId connect.Id, eraserId connect.Id, byteCount int64, debitId connect.Id, clusterFull bool) (*sidecar.QuotaRefusal, error) {
	if (self.refusal(networkId) == nil && !clusterFull) || byteCount <= 0 {
		return nil, nil
	}
	return self.quota.CountRate(ctx, networkId, map[string]int64{
		sidecar.QuotaRateKeyClosureBytes(eraserId): byteCount,
	}, debitId)
}

// ChargeClosure for a repo on a cluster at its cohort limit, which holds a closure upload to the storage limit's
// closure bounds whatever the network's own state (cluster_limit.go). A network at its own limit or spent is answered
// as ChargeClosure answers it. Otherwise oversize is true for an upload past QuotaClosureUploadMaxByteCount, which
// the cohort limit refuses 507, and refusal is the eraser's rate, pacing or allowance, a 429.
func (self *QuotaGate) ChargeClosureAtClusterLimit(ctx context.Context, networkId connect.Id, eraserId connect.Id, byteCount int64, debitId connect.Id) (refusal *sidecar.QuotaRefusal, oversize bool, err error) {
	if self.refusal(networkId) != nil {
		refusal, err := self.ChargeClosure(ctx, networkId, eraserId, byteCount, debitId)
		return refusal, false, err
	}
	if byteCount < 0 || sidecar.QuotaClosureUploadMaxByteCount < byteCount {
		return nil, true, nil
	}
	refusal, err = self.quota.CountRate(ctx, networkId, map[string]int64{
		sidecar.QuotaRateKeyClosureUpload(eraserId): 1,
		sidecar.QuotaRateKeyClosureBytes(eraserId):  byteCount,
	}, debitId)
	return refusal, false, err
}
