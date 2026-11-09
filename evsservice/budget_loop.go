// §19.6's budget row (EVSB-M2-07): taskworker runs one BudgetLoop per metadata cluster. The loop holds the
// cluster's lease in {nvb_<set>}, and every interval reads the drives' counters, takes the processes' reports,
// steps its Governor (budget_governor.go), saves the state and publishes the allowance. A loop that takes the
// lease resumes B, W and the counter readings they were taken at exactly; with no saved state, B and W start at
// zero, which is conservative.
//
// What it measures (§19.6's counters row, plan-EVSB-counter-transport):
//
//   - B drains by the busiest drive not under heal's bytes written since the last step. Heal, MRF and scanner
//     writes stay in the counters, so a drive admin info shows under heal is skipped whole, never corrected for.
//   - A counter below its last reading is a reboot, and a drive the state has no reading of is new: each is a
//     fresh baseline, never a credit.
//   - A drive admin info lists, not under heal, with no reading, publishes nothing, so the processes take
//     §11.13's fallback row rather than a guess. Its readings stay as they were, so the step that reads it again
//     drains B by everything written meanwhile against one interval's refill, which errs toward a lower bucket.
//   - Writes completed feed §22.8 and monitor, never B.
//
// The trap (§11.13's wallet row): evacuation's funded work runs 25 h after the admissions that paid for it, so a
// wallet clamped to what the processes report queued would lose that credit every interval. The loop lists pb/
// (budgetBatchBacklog, below) and gives the governor the priced evacuation of every batch still on the cluster
// as funded backlog standing beside what the processes report (Governor.SetStandingFundedBacklog).
//
// §19.8's series, each with no network or repo label: the bucket B, P0's forgiven excess by kind, P0's measured
// bytes over the last hour against that hour's refill, the liabilities by class with their drain times at the
// last hour's rate, and the busiest drive's DWPD over 24 h, 7 d and 30 d. Only the lease holder sets them.
//
// Not safe for concurrent use: Run steps it, or a T2 schedule steps it on its own clock.

package evsservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// §19.8's series the loop sets.
const (
	budgetBucketMetricName         = "urnetwork_evs_budget_bucket_bytes"
	budgetP0ForgivenMetricName     = "urnetwork_evs_budget_p0_forgiven_bytes_total"
	budgetP0RefillRatioMetricName  = "urnetwork_evs_budget_p0_refill_ratio"
	budgetLiabilityMetricName      = "urnetwork_evs_budget_liability_bytes"
	budgetDrainMetricName          = "urnetwork_evs_budget_drain_seconds"
	fileClusterDriveDwpdMetricName = "urnetwork_filecluster_drive_dwpd"
)

// The liabilities' class values: P1 waiting in the processes' queues, the wallet, and the funded and unfunded
// P2 backlogs, the last two as urnetwork_evs_budget_issued_bytes_total spells them.
const (
	budgetLiabilityClassP1Queued   = "p1_queued"
	budgetLiabilityClassWallet     = "wallet"
	budgetLiabilityClassP2Funded   = "p2_funded"
	budgetLiabilityClassP2Unfunded = "p2_unfunded"
)

// The lease's field in a cluster's {nvb_} key, the budget loop's on a metadata cluster and the hdd loop's on a
// segment cluster.
const budgetLeaseField = "lease"

var (
	// Takes or renews a lease field: set to the holder while it is absent or already the holder's, with its ttl.
	// KEYS[1] the cluster's key; ARGV the field, the holder, the ttl in ms. 1 when held.
	budgetLeaseTakeScript = &sidecar.RedisScript{
		Name: "evs_budget_lease_take",
		Source: `
local holder = redis.call('HGET', KEYS[1], ARGV[1])
if holder and holder ~= ARGV[2] then return 0 end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('HPEXPIRE', KEYS[1], ARGV[3], 'FIELDS', 1, ARGV[1])
return 1`,
	}
	// Releases a lease field only while the holder holds it. KEYS[1] the cluster's key; ARGV the field, the
	// holder. 1 when released.
	budgetLeaseReleaseScript = &sidecar.RedisScript{
		Name: "evs_budget_lease_release",
		Source: `
if redis.call('HGET', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
redis.call('HDEL', KEYS[1], ARGV[1])
return 1`,
	}
)

// Takes or renews the lease field of the cluster's key for holder. held is false while another holds it.
func takeBudgetLease(ctx context.Context, redis sidecar.Redis, clusterId string, holder string, ttl time.Duration) (held bool, err error) {
	ttlMs := max(1, ttl.Milliseconds())
	reply, err := redis.RunScript(ctx, budgetLeaseTakeScript, []string{writeBudgetKey(clusterId)}, []string{
		budgetLeaseField, holder, strconv.FormatInt(ttlMs, 10),
	})
	if err != nil {
		return false, err
	}
	return reply.Kind == sidecar.RedisReplyInteger && reply.Integer == 1, nil
}

// Releases the lease field while holder holds it, so the next loop need not wait out its ttl.
func releaseBudgetLease(ctx context.Context, redis sidecar.Redis, clusterId string, holder string) error {
	_, err := redis.RunScript(ctx, budgetLeaseReleaseScript, []string{writeBudgetKey(clusterId)}, []string{budgetLeaseField, holder})
	return err
}

// 16 random bytes as hex: names a lease holder and no host.
func newBudgetHolderId() (string, error) {
	holderIdBytes := make([]byte, 16)
	if _, err := rand.Read(holderIdBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(holderIdBytes), nil
}

// One drive's kernel counters, /sys/block/<dev>/stat's fields as plan-EVSB-counter-transport's exporter serves
// them, beside what admin info says of the drive.
type DriveCounter struct {
	// Stable while the cluster's drives are, such as its pool, set and disk index: never a network or repo.
	DriveId string
	// Field 7 in bytes (512 B sectors), field 5 and field 1.
	WrittenByteCount uint64
	WritesCompleted  uint64
	ReadsCompleted   uint64
	// Admin info shows it under heal: its writes are the heal's, and B skips it (§19.6).
	Healing bool
	// Admin info lists it and no reading came: its host's exporter did not answer or did not list it.
	Missing bool
}

// One read of a cluster's drives.
type DriveCounterReading struct {
	// Every drive admin info lists.
	Drives []*DriveCounter
	// Admin info's summed raw use and inodes, for §19.9's at_limit line. UsageKnown is false while admin info
	// is unread or stale, and the loop then keeps the last value it published.
	UsageKnown           bool
	RawUsageByteCount    uint64
	RawCapacityByteCount uint64
	UsedInodeCount       uint64
	FreeInodeCount       uint64
}

// What a loop reads its cluster's drives through: server's FileClusterCounters, or a T2 fake. Safe for
// concurrent use.
type DriveCounterSource interface {
	// Reads every drive of the cluster now, within ctx. An error reads as every drive missing.
	ReadDriveCounters(ctx context.Context, clusterId string) (*DriveCounterReading, error)
}

// The loop's tunables beside the accounts' own. Every process and the loop of a cluster run on one Budget.
type BudgetLoopSettings struct {
	// The accounts', the governor's and the processes'.
	Budget *WriteBudgetSettings
	// How long the lease holds without a renewal: 15 s, three intervals, so a cluster whose loop died is taken
	// over within that, as its allowance lapses.
	LeaseTtl time.Duration
	// How long one read of the drive counters may take: 2 s (plan-EVSB-counter-transport).
	CounterTimeout time.Duration
	// How long releasing the lease may take as Run ends: 2 s.
	ReleaseTimeout time.Duration
	// §19.9's at_limit lines on summed raw use and on inodes, in percent (plan-EVSB-nvb-fields): 80 and 70.
	AtLimitRawPercent   int
	AtLimitInodePercent int
	// The span the P0 refill ratio and the drain rates are taken over: 1 h (§19.8).
	RateWindow time.Duration
	// §19.8's DWPD windows, by their label: 24h, 7d and 30d.
	DwpdWindows map[string]time.Duration
	// Each drive's written total is snapshotted once this often, for the DWPD windows: 1 h.
	DriveSnapshotInterval time.Duration
	// Snapshots older than this are thinned to one a DriveSnapshotDayInterval, so a 30-day window costs at
	// most a few dozen of them: 25 h and 24 h.
	DriveSnapshotHourlySpan  time.Duration
	DriveSnapshotDayInterval time.Duration
	// pb/'s LIST: keys a page and pages a step at most, so a step's work stays bounded however long the
	// backlog: 1,000 and 16.
	BatchListLimit     int
	BatchListPageCount int
	// A minute's batches are listed once this long after the minute ends, when no batch opened in it is still
	// being written: 2 min.
	BatchMinuteSettle time.Duration
	// A listed minute this old is listed again every BatchRelistInterval, since evacuation deletes it whole
	// once it is past 25 h: 25 h and 5 min.
	BatchRelistAge      time.Duration
	BatchRelistInterval time.Duration
}

// §19.6's and §19.8's figures.
func DefaultBudgetLoopSettings() *BudgetLoopSettings {
	return &BudgetLoopSettings{
		Budget:              DefaultWriteBudgetSettings(),
		LeaseTtl:            15 * time.Second,
		CounterTimeout:      2 * time.Second,
		ReleaseTimeout:      2 * time.Second,
		AtLimitRawPercent:   80,
		AtLimitInodePercent: 70,
		RateWindow:          1 * time.Hour,
		DwpdWindows: map[string]time.Duration{
			"24h": 24 * time.Hour,
			"7d":  7 * 24 * time.Hour,
			"30d": 30 * 24 * time.Hour,
		},
		DriveSnapshotInterval:    1 * time.Hour,
		DriveSnapshotHourlySpan:  25 * time.Hour,
		DriveSnapshotDayInterval: 24 * time.Hour,
		BatchListLimit:           1000,
		BatchListPageCount:       16,
		BatchMinuteSettle:        2 * time.Minute,
		BatchRelistAge:           25 * time.Hour,
		BatchRelistInterval:      5 * time.Minute,
	}
}

// One step's figures, kept for RateWindow.
type budgetLoopSample struct {
	time time.Time
	// drive bytes
	p0MeasuredByteCount int64
	refillByteCount     int64
	// priced bytes issued
	p1IssuedByteCount       int64
	fundedIssuedByteCount   int64
	unfundedIssuedByteCount int64
}

// See the file header.
type BudgetLoop struct {
	clusterId string
	settings  *BudgetLoopSettings
	clock     sidecar.Clock
	redis     sidecar.Redis
	counters  DriveCounterSource
	log       sidecar.Logger
	// where pb/ is listed; nil leaves evacuation's backlog to the processes' reports
	cluster  sidecar.BlobCluster
	holderId string

	bucketGauge      sidecar.MetricsGauge
	forgivenCounter  sidecar.MetricsCounter
	refillRatioGauge sidecar.MetricsGauge
	liabilityGauge   sidecar.MetricsGauge
	drainGauge       sidecar.MetricsGauge
	dwpdGauge        sidecar.MetricsGauge

	// nil while the lease is not held: a loop that takes it loads the saved state again
	governor *Governor
	// the counter readings B was last drained to, the written totals and their snapshots, as saved
	counterReadings map[string]uint64
	driveTotals     map[string]uint64
	driveSnapshots  []*GovernorDriveSnapshot
	atLimit         bool
	// P0's forgiven excess the counter carries, so a holder adds only what it saw forgiven
	exportedExcess map[sidecar.WriteP0Kind]int64
	samples        []*budgetLoopSample
	batches        *budgetBatchBacklog
}

// A loop for one metadata cluster, which steps nothing until Run or Step. host.Redis carries {nvb_<set>},
// host.Blobs the cluster whose pb/ it lists, host.Metrics §19.8's series and host.Clock its intervals. log
// takes what fails, and nil discards it. settings may be nil for the defaults.
func NewBudgetLoop(host *sidecar.ServiceHost, clusterId string, counters DriveCounterSource, log sidecar.Logger, settings *BudgetLoopSettings) (*BudgetLoop, error) {
	if settings == nil {
		settings = DefaultBudgetLoopSettings()
	}
	if host == nil || host.Redis == nil {
		return nil, errors.New("the budget loop needs ServiceHost.Redis")
	}
	if counters == nil {
		return nil, errors.New("the budget loop needs a drive counter source")
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	holderId, err := newBudgetHolderId()
	if err != nil {
		return nil, err
	}
	self := &BudgetLoop{
		log:       log,
		clusterId: clusterId,
		settings:  settings,
		clock:     host.ClockOrReal(),
		redis:     host.Redis,
		counters:  counters,
		holderId:  holderId,
		batches:   newBudgetBatchBacklog(),
	}
	if host.Blobs != nil {
		cluster, err := host.Blobs.Cluster(clusterId)
		if err != nil {
			return nil, err
		}
		self.cluster = cluster
	}
	if metrics := host.Metrics; metrics != nil {
		self.bucketGauge = metrics.Gauge(budgetBucketMetricName, "The write budget's bucket B, drive bytes, never below zero.", "cluster")
		self.forgivenCounter = metrics.Counter(budgetP0ForgivenMetricName, "P0's forgiven excess, its drive bytes past what B held, by kind (owner decision 190).", "cluster", "kind")
		self.refillRatioGauge = metrics.Gauge(budgetP0RefillRatioMetricName, "P0's measured bytes over the last hour against that hour's refill.", "cluster")
		self.liabilityGauge = metrics.Gauge(budgetLiabilityMetricName, "Outstanding write work by class, priced bytes.", "cluster", "class")
		self.drainGauge = metrics.Gauge(budgetDrainMetricName, "How long each class's outstanding work takes at the last hour's rate.", "cluster", "class")
		self.dwpdGauge = metrics.Gauge(fileClusterDriveDwpdMetricName, "The busiest drive's writes in drive writes a day over the window.", "cluster", "window")
	}
	return self, nil
}

// Steps at once, then every interval, until ctx ends, and then releases the lease. taskworker joins it on its
// runtime's lifetime.
func (self *BudgetLoop) Run(ctx context.Context) {
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), self.settings.ReleaseTimeout)
		defer cancel()
		if err := releaseBudgetLease(releaseCtx, self.redis, self.clusterId, self.holderId); err != nil {
			self.log.Infof("[evsbudget]%s: lease not released: %v\n", self.clusterId, err)
		}
	}()
	for {
		self.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.Budget.Interval):
		}
	}
}

// Whether this loop held the lease at its last step.
func (self *BudgetLoop) Holding() bool {
	return self.governor != nil
}

// One interval: see the file header. Returns what was published, nil when nothing was: the lease held
// elsewhere, Redis or the counters not answering, or a drive not under heal with no reading.
func (self *BudgetLoop) Step(ctx context.Context) *WriteBudgetAllowance {
	budget := self.settings.Budget
	now := self.clock.Now()
	held, err := takeBudgetLease(ctx, self.redis, self.clusterId, self.holderId, self.settings.LeaseTtl)
	if err != nil || !held {
		// a loop that loses the lease forgets its state, and the holder's saved state is what counts
		self.governor = nil
		return nil
	}
	if self.governor == nil {
		state, err := LoadGovernorState(ctx, self.redis, self.clusterId)
		if err != nil {
			// whether a state exists is unknown, and starting from none would forget B and W
			return nil
		}
		self.resume(state)
	}

	reading, ok := self.readCounters(ctx)
	if !ok {
		return nil
	}
	measuredByteCount, counterReadings, ok := self.measure(reading)
	if !ok {
		return nil
	}
	if reading.UsageKnown {
		self.atLimit = budgetAtLimit(self.settings, reading)
	}

	reports, err := ReadWriteBudgetReports(ctx, self.redis, self.clusterId)
	if err != nil {
		return nil
	}
	if self.cluster != nil {
		self.batches.advance(ctx, self.cluster, self.settings, now)
	}
	self.governor.SetStandingFundedBacklog(self.batches.costByteCount())
	allowance := self.governor.Step(now, measuredByteCount, reports)
	allowance.AtLimit = self.atLimit

	self.counterReadings = counterReadings
	self.snapshotDrives(now)
	state := self.governor.State()
	state.CounterReadings = maps.Clone(self.counterReadings)
	state.DriveTotals = maps.Clone(self.driveTotals)
	state.DriveSnapshots = cloneGovernorDriveSnapshots(self.driveSnapshots)
	// a state saved before its allowance is published, so a published allowance always has its state; a save
	// that fails leaves the older state, whose readings match its B
	if err := SaveGovernorState(ctx, self.redis, budget, self.clusterId, state); err != nil {
		self.log.Infof("[evsbudget]%s: state not saved: %v\n", self.clusterId, err)
	}
	if err := PublishWriteBudgetAllowance(ctx, self.redis, budget, allowance); err != nil {
		self.log.Infof("[evsbudget]%s: allowance not published: %v\n", self.clusterId, err)
		return nil
	}
	self.export(now, allowance)
	return allowance
}

// Takes up the saved state, or none, as a new lease holder.
func (self *BudgetLoop) resume(state *GovernorState) {
	self.governor = NewGovernor(self.clusterId, self.settings.Budget, state)
	self.counterReadings = map[string]uint64{}
	self.driveTotals = map[string]uint64{}
	self.driveSnapshots = []*GovernorDriveSnapshot{}
	self.exportedExcess = map[sidecar.WriteP0Kind]int64{}
	if state != nil {
		self.counterReadings = maps.Clone(state.CounterReadings)
		self.driveTotals = maps.Clone(state.DriveTotals)
		self.driveSnapshots = cloneGovernorDriveSnapshots(state.DriveSnapshots)
		self.exportedExcess = maps.Clone(state.P0ExcessByteCounts)
		if self.counterReadings == nil {
			self.counterReadings = map[string]uint64{}
		}
		if self.driveTotals == nil {
			self.driveTotals = map[string]uint64{}
		}
		if self.exportedExcess == nil {
			self.exportedExcess = map[sidecar.WriteP0Kind]int64{}
		}
	}
	self.samples = nil
	self.batches = newBudgetBatchBacklog()
}

// One read of the counters within CounterTimeout. ok is false when the source failed.
func (self *BudgetLoop) readCounters(ctx context.Context) (*DriveCounterReading, bool) {
	readCtx, cancel := context.WithTimeout(ctx, self.settings.CounterTimeout)
	defer cancel()
	reading, err := self.counters.ReadDriveCounters(readCtx, self.clusterId)
	if err != nil || reading == nil {
		if err != nil {
			self.log.Infof("[evsbudget]%s: counters not read: %v\n", self.clusterId, err)
		}
		return nil, false
	}
	return reading, true
}

// The busiest drive not under heal's bytes written since the last readings, and the readings to keep. ok is
// false when a drive not under heal has no reading, or no drive is outside a heal, so nothing is published.
func (self *BudgetLoop) measure(reading *DriveCounterReading) (measuredByteCount int64, counterReadings map[string]uint64, ok bool) {
	counterReadings = maps.Clone(self.counterReadings)
	totals := maps.Clone(self.driveTotals)
	measuredCount := 0
	for _, drive := range reading.Drives {
		if drive.Missing {
			if !drive.Healing {
				return 0, nil, false
			}
			// a healing drive's reading waits, and its next delta counts toward its total alone
			continue
		}
		previous, seen := counterReadings[drive.DriveId]
		counterReadings[drive.DriveId] = drive.WrittenByteCount
		var deltaByteCount uint64
		if seen && previous <= drive.WrittenByteCount {
			deltaByteCount = drive.WrittenByteCount - previous
		}
		// a fall or a new drive is a fresh baseline, never a credit
		totals[drive.DriveId] += deltaByteCount
		if drive.Healing {
			continue
		}
		measuredCount += 1
		measuredByteCount = max(measuredByteCount, int64(min(deltaByteCount, math.MaxInt64)))
	}
	if measuredCount == 0 {
		return 0, nil, false
	}
	self.driveTotals = totals
	return measuredByteCount, counterReadings, true
}

// §19.9's line: summed raw use at or past AtLimitRawPercent of raw capacity, or inodes at or past
// AtLimitInodePercent.
func budgetAtLimit(settings *BudgetLoopSettings, reading *DriveCounterReading) bool {
	if 0 < reading.RawCapacityByteCount && uint64(settings.AtLimitRawPercent)*reading.RawCapacityByteCount <= 100*reading.RawUsageByteCount {
		return true
	}
	inodeCount := reading.UsedInodeCount + reading.FreeInodeCount
	return 0 < inodeCount && uint64(settings.AtLimitInodePercent)*inodeCount <= 100*reading.UsedInodeCount
}

// One snapshot of every drive's written total.
type GovernorDriveSnapshot struct {
	TimeMs int64             `json:"time_ms"`
	Totals map[string]uint64 `json:"totals"`
}

// A deep copy.
func cloneGovernorDriveSnapshots(snapshots []*GovernorDriveSnapshot) []*GovernorDriveSnapshot {
	copied := make([]*GovernorDriveSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		copied = append(copied, &GovernorDriveSnapshot{TimeMs: snapshot.TimeMs, Totals: maps.Clone(snapshot.Totals)})
	}
	return copied
}

// Takes a snapshot once a DriveSnapshotInterval, and thins those past the hourly span to one a day.
func (self *BudgetLoop) snapshotDrives(now time.Time) {
	settings := self.settings
	nowMs := now.UnixMilli()
	if n := len(self.driveSnapshots); n == 0 || settings.DriveSnapshotInterval.Milliseconds() <= nowMs-self.driveSnapshots[n-1].TimeMs {
		self.driveSnapshots = append(self.driveSnapshots, &GovernorDriveSnapshot{TimeMs: nowMs, Totals: maps.Clone(self.driveTotals)})
	}
	var longest time.Duration
	for _, window := range settings.DwpdWindows {
		longest = max(longest, window)
	}
	kept := []*GovernorDriveSnapshot{}
	var lastDailyMs int64
	for _, snapshot := range self.driveSnapshots {
		age := time.Duration(nowMs-snapshot.TimeMs) * time.Millisecond
		switch {
		case longest+settings.DriveSnapshotDayInterval < age:
			continue
		case age <= settings.DriveSnapshotHourlySpan:
			kept = append(kept, snapshot)
		case lastDailyMs == 0 || settings.DriveSnapshotDayInterval.Milliseconds() <= snapshot.TimeMs-lastDailyMs:
			kept = append(kept, snapshot)
			lastDailyMs = snapshot.TimeMs
		}
	}
	self.driveSnapshots = kept
}

// The busiest drive's drive writes a day over window, from the oldest snapshot inside it. ok is false while no
// snapshot an interval old lies inside it.
func (self *BudgetLoop) busiestDwpd(now time.Time, window time.Duration) (float64, bool) {
	nowMs := now.UnixMilli()
	var base *GovernorDriveSnapshot
	for _, snapshot := range self.driveSnapshots {
		if window.Milliseconds() < nowMs-snapshot.TimeMs {
			continue
		}
		base = snapshot
		break
	}
	if base == nil {
		return 0, false
	}
	span := time.Duration(nowMs-base.TimeMs) * time.Millisecond
	if span < self.settings.Budget.Interval {
		return 0, false
	}
	var busiest uint64
	for driveId, total := range self.driveTotals {
		if previous, ok := base.Totals[driveId]; ok && previous <= total {
			busiest = max(busiest, total-previous)
		}
	}
	days := span.Hours() / 24
	return float64(busiest) / float64(self.settings.Budget.DriveByteCount) / days, true
}

// Sets §19.8's series from a published step.
func (self *BudgetLoop) export(now time.Time, allowance *WriteBudgetAllowance) {
	budget := self.settings.Budget
	self.samples = append(self.samples, &budgetLoopSample{
		time:                    now,
		p0MeasuredByteCount:     allowance.P0MeasuredByteCount,
		refillByteCount:         int64(math.Round(budget.intervalRefillByteCount())),
		p1IssuedByteCount:       allowance.P1IssuedByteCount,
		fundedIssuedByteCount:   allowance.FundedIssuedByteCount,
		unfundedIssuedByteCount: allowance.UnfundedIssuedByteCount,
	})
	for 0 < len(self.samples) && self.settings.RateWindow <= now.Sub(self.samples[0].time) {
		self.samples = self.samples[1:]
	}
	if self.bucketGauge == nil {
		return
	}
	clusterId := self.clusterId
	self.bucketGauge.Set(float64(allowance.BucketByteCount), clusterId)
	for _, kind := range sidecar.WriteP0Kinds {
		if delta := allowance.P0ExcessByteCounts[kind] - self.exportedExcess[kind]; 0 < delta {
			self.forgivenCounter.Add(float64(delta), clusterId, string(kind))
			self.exportedExcess[kind] = allowance.P0ExcessByteCounts[kind]
		}
	}

	var p0ByteCount, refillByteCount, p1Issued, fundedIssued, unfundedIssued int64
	for _, sample := range self.samples {
		p0ByteCount += sample.p0MeasuredByteCount
		refillByteCount += sample.refillByteCount
		p1Issued += sample.p1IssuedByteCount
		fundedIssued += sample.fundedIssuedByteCount
		unfundedIssued += sample.unfundedIssuedByteCount
	}
	if 0 < refillByteCount {
		self.refillRatioGauge.Set(float64(p0ByteCount)/float64(refillByteCount), clusterId)
	}
	spanSeconds := float64(len(self.samples)) * budget.Interval.Seconds()
	liabilities := []struct {
		class     string
		byteCount int64
		issued    int64
	}{
		{class: budgetLiabilityClassP1Queued, byteCount: allowance.P1QueuedByteCount, issued: p1Issued},
		{class: budgetLiabilityClassWallet, byteCount: allowance.WalletByteCount, issued: fundedIssued},
		{class: budgetLiabilityClassP2Funded, byteCount: allowance.FundedBacklogByteCount, issued: fundedIssued},
		{class: budgetLiabilityClassP2Unfunded, byteCount: allowance.UnfundedBacklogByteCount, issued: unfundedIssued},
	}
	for _, liability := range liabilities {
		self.liabilityGauge.Set(float64(liability.byteCount), clusterId, liability.class)
		drainSeconds := 0.0
		switch {
		case liability.byteCount <= 0:
		case liability.issued <= 0:
			// nothing of the class issued in the window: it does not drain at this rate
			drainSeconds = math.Inf(1)
		default:
			drainSeconds = float64(liability.byteCount) / (float64(liability.issued) / spanSeconds)
		}
		self.drainGauge.Set(drainSeconds, clusterId, liability.class)
	}
	for _, label := range slices.Sorted(maps.Keys(self.settings.DwpdWindows)) {
		if dwpd, ok := self.busiestDwpd(now, self.settings.DwpdWindows[label]); ok {
			self.dwpdGauge.Set(dwpd, clusterId, label)
		}
	}
}

// The priced cost of evacuating one batch of byteCount bytes (§11.13's push row's evacuation line): its DELETE,
// its records written into a parcel, and a pidx/ entry. A pack goes to the segment cluster and costs this one
// less, so this errs toward a larger backlog, which only loosens W's clamp.
func evacuationBatchCost(table *PriceTable, byteCount int64) int64 {
	cost, err := table.PriceOperations([]WriteOperation{
		{Kind: WriteOperationDelete, Count: 1},
		{Kind: WriteOperationCreate, ObjectByteCount: byteCount, Count: 1},
		{Kind: WriteOperationCreate, Count: 1},
	})
	if err != nil {
		return 0
	}
	return cost
}

// The batches still on a cluster, by minute directory, from LISTs of pb/ bounded per step. A settled minute is
// listed once, through one cursor over pb/ in key order, which minutes follow; a minute past BatchRelistAge is
// listed again every BatchRelistInterval until evacuation has deleted it.
type budgetBatchBacklog struct {
	// priced evacuation cost by minute
	minuteCosts map[uint32]int64
	// when each listed minute was last listed
	minuteListTimes map[uint32]time.Time
	// the key pb/'s cursor has passed: every settled minute at or before it is in minuteCosts
	cursor string
	// a relist in progress: its minute, where it stands and what it found so far
	relistMinute     uint32
	relistStartAfter string
	relistCost       int64
	relisting        bool
}

func newBudgetBatchBacklog() *budgetBatchBacklog {
	return &budgetBatchBacklog{
		minuteCosts:     map[uint32]int64{},
		minuteListTimes: map[uint32]time.Time{},
	}
}

// The priced evacuation of every listed batch.
func (self *budgetBatchBacklog) costByteCount() int64 {
	var byteCount int64
	for _, cost := range self.minuteCosts {
		byteCount += cost
	}
	return byteCount
}

// The minute a pb/<yyyymmddhh>/<mm>/<instance>-<seq> key names. ok is false for a key of no such shape.
func batchKeyMinute(key string) (uint32, bool) {
	rest, ok := strings.CutPrefix(key, batchKeyPrefix)
	if !ok {
		return 0, false
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || len(parts[0]) != 10 || len(parts[1]) != 2 {
		return 0, false
	}
	at, err := time.Parse("200601021504", parts[0]+parts[1])
	if err != nil {
		return 0, false
	}
	return BatchMinute(at), true
}

// Spends at most BatchListPageCount LISTs: the cursor first, through every minute that has settled, then a
// relist of the oldest minute due one. A LIST that fails ends the step's listing, to resume at the next.
func (self *budgetBatchBacklog) advance(ctx context.Context, cluster sidecar.BlobCluster, settings *BudgetLoopSettings, now time.Time) {
	table := settings.Budget.PriceTable
	settledMinute := BatchMinute(now.Add(-settings.BatchMinuteSettle)) - 1
	pageCount := 0
	for pageCount < settings.BatchListPageCount {
		objects, more, err := cluster.List(ctx, batchKeyPrefix, self.cursor, settings.BatchListLimit)
		pageCount += 1
		if err != nil {
			return
		}
		stopped := false
		for _, object := range objects {
			minute, ok := batchKeyMinute(object.Key)
			if !ok {
				self.cursor = object.Key
				continue
			}
			if settledMinute < minute {
				stopped = true
				break
			}
			self.minuteCosts[minute] += evacuationBatchCost(table, object.ByteCount)
			self.minuteListTimes[minute] = now
			self.cursor = object.Key
		}
		if stopped || !more {
			break
		}
	}
	for pageCount < settings.BatchListPageCount {
		if !self.relisting {
			minute, ok := self.relistDue(settings, now)
			if !ok {
				return
			}
			self.relistMinute = minute
			self.relistStartAfter = ""
			self.relistCost = 0
			self.relisting = true
		}
		objects, more, err := cluster.List(ctx, BatchMinutePrefix(self.relistMinute), self.relistStartAfter, settings.BatchListLimit)
		pageCount += 1
		if err != nil {
			return
		}
		for _, object := range objects {
			self.relistCost += evacuationBatchCost(table, object.ByteCount)
			self.relistStartAfter = object.Key
		}
		if more {
			continue
		}
		self.relisting = false
		if self.relistCost == 0 {
			delete(self.minuteCosts, self.relistMinute)
			delete(self.minuteListTimes, self.relistMinute)
		} else {
			self.minuteCosts[self.relistMinute] = self.relistCost
			self.minuteListTimes[self.relistMinute] = now
		}
	}
}

// The oldest listed minute past BatchRelistAge not listed within BatchRelistInterval.
func (self *budgetBatchBacklog) relistDue(settings *BudgetLoopSettings, now time.Time) (uint32, bool) {
	for _, minute := range slices.Sorted(maps.Keys(self.minuteCosts)) {
		if now.Sub(batchMinuteTime(minute)) < settings.BatchRelistAge {
			return 0, false
		}
		if settings.BatchRelistInterval <= now.Sub(self.minuteListTimes[minute]) {
			return minute, true
		}
	}
	return 0, false
}
