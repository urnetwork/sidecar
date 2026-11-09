// §19.6's hdd row (EVSB-M2-08): taskworker runs one HddLoop per segment cluster. The loop holds the cluster's
// lease in {nvb_<cluster>} and every interval publishes there, with a 15 s ttl, the cluster's drive operations a
// second, its HDDs' reads and writes completed since the last reading, heals and the scanner included, and its
// capacity: what §22.8's M3 hdd run measured, which sidecar.yml's file_clusters entry carries
// (plan-EVSB-settle-gate). Until that run sets it, no capacity is published, so evs refuses no upload on HDD
// grounds (hdd_admission.go) and a drop job stays paused.
//
// A drive with no reading publishes nothing, and the next reading's rate is taken over the time since the last
// one it was taken against, so a gap never inflates a rate. A counter that falls is a fresh baseline. The figures
// name no network or repo (evs-10), and §19.8's urnetwork_filecluster_hdd_drive_ops{cluster} and
// urnetwork_filecluster_hdd_capacity{cluster} carry them (g0-recheck-0-hdd-trigger #1).
//
// Not safe for concurrent use: Run steps it, or a T2 schedule does.

package evsservice

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
)

// The figures' field in a segment cluster's {nvb_} key.
const hddFiguresField = "hdd"

// §19.8's gauges the loop sets (g0-recheck-0-hdd-trigger #1).
const (
	hddDriveOpsMetricName = "urnetwork_filecluster_hdd_drive_ops"
	hddCapacityMetricName = "urnetwork_filecluster_hdd_capacity"
)

// What an hdd loop publishes in {nvb_<cluster>}.
type HddFigures struct {
	ClusterId string `json:"cluster"`
	TimeMs    int64  `json:"time_ms"`
	// The HDDs' reads and writes completed a second over the last interval.
	DriveOpsPerSecond float64 `json:"drive_ops"`
	// The measured capacity in drive operations a second, zero while none is set.
	CapacityOps int64 `json:"capacity_ops,omitempty"`
}

// Writes figures with ttl.
func publishHddFigures(ctx context.Context, redis sidecar.Redis, figures *HddFigures, ttl time.Duration) error {
	return setWriteBudgetField(ctx, redis, figures.ClusterId, hddFiguresField, figures, ttl)
}

// The cluster's live figures, nil when none are. Figures naming another cluster are an error.
func readHddFigures(ctx context.Context, redis sidecar.Redis, clusterId string) (*HddFigures, error) {
	figures := &HddFigures{}
	found, err := getWriteBudgetField(ctx, redis, clusterId, hddFiguresField, figures)
	if err != nil || !found {
		return nil, err
	}
	if figures.ClusterId != clusterId {
		return nil, errors.New("hdd figures for another cluster")
	}
	return figures, nil
}

type HddLoopSettings struct {
	// How often it publishes: 5 s (§19.6).
	Interval time.Duration
	// The figures' ttl: 15 s (§19.6).
	FiguresTtl time.Duration
	// The lease's: 15 s, three intervals.
	LeaseTtl time.Duration
	// One read of the counters: 2 s (plan-EVSB-counter-transport).
	CounterTimeout time.Duration
	// Releasing the lease as Run ends: 2 s.
	ReleaseTimeout time.Duration
}

func DefaultHddLoopSettings() *HddLoopSettings {
	return &HddLoopSettings{
		Interval:       5 * time.Second,
		FiguresTtl:     15 * time.Second,
		LeaseTtl:       15 * time.Second,
		CounterTimeout: 2 * time.Second,
		ReleaseTimeout: 2 * time.Second,
	}
}

// See the file header.
type HddLoop struct {
	clusterId string
	settings  *HddLoopSettings
	clock     sidecar.Clock
	redis     sidecar.Redis
	gates     sidecar.ServiceGates
	counters  DriveCounterSource
	log       sidecar.Logger
	holderId  string

	driveOpsGauge sidecar.MetricsGauge
	capacityGauge sidecar.MetricsGauge

	holding bool
	// each drive's reads and writes completed at the last reading, and when it was taken
	readings    map[string]uint64
	readingTime time.Time
}

// A loop for one segment cluster, stepping nothing until Run or Step. host.Redis carries {nvb_<cluster>},
// host.Gates the cluster's capacity, host.Metrics the gauges and host.Clock its intervals. log takes what
// fails, and nil discards it. settings may be nil for the defaults.
func NewHddLoop(host *sidecar.ServiceHost, clusterId string, counters DriveCounterSource, log sidecar.Logger, settings *HddLoopSettings) (*HddLoop, error) {
	if settings == nil {
		settings = DefaultHddLoopSettings()
	}
	if host == nil || host.Redis == nil {
		return nil, errors.New("the hdd loop needs ServiceHost.Redis")
	}
	if counters == nil {
		return nil, errors.New("the hdd loop needs a drive counter source")
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	holderId, err := newBudgetHolderId()
	if err != nil {
		return nil, err
	}
	self := &HddLoop{
		clusterId: clusterId,
		settings:  settings,
		clock:     host.ClockOrReal(),
		redis:     host.Redis,
		gates:     host.GatesOrClosed(),
		counters:  counters,
		log:       log,
		holderId:  holderId,
	}
	if metrics := host.Metrics; metrics != nil {
		self.driveOpsGauge = metrics.Gauge(hddDriveOpsMetricName, "A segment cluster's HDD reads and writes completed a second.", "cluster")
		self.capacityGauge = metrics.Gauge(hddCapacityMetricName, "A segment cluster's measured capacity, drive operations a second.", "cluster")
	}
	return self, nil
}

// Steps at once, then every interval, until ctx ends, and then releases the lease.
func (self *HddLoop) Run(ctx context.Context) {
	defer func() {
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), self.settings.ReleaseTimeout)
		defer cancel()
		if err := releaseBudgetLease(releaseCtx, self.redis, self.clusterId, self.holderId); err != nil {
			self.log.Infof("[evshdd]%s: lease not released: %v\n", self.clusterId, err)
		}
	}()
	for {
		self.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.Interval):
		}
	}
}

// Whether this loop held the lease at its last step.
func (self *HddLoop) Holding() bool {
	return self.holding
}

// One interval: see the file header. Returns what was published, nil when nothing was.
func (self *HddLoop) Step(ctx context.Context) *HddFigures {
	now := self.clock.Now()
	held, err := takeBudgetLease(ctx, self.redis, self.clusterId, self.holderId, self.settings.LeaseTtl)
	if err != nil || !held {
		self.holding = false
		self.readings = nil
		return nil
	}
	if !self.holding {
		// a new holder takes its own baseline
		self.holding = true
		self.readings = nil
	}

	readCtx, cancel := context.WithTimeout(ctx, self.settings.CounterTimeout)
	reading, err := self.counters.ReadDriveCounters(readCtx, self.clusterId)
	cancel()
	if err != nil || reading == nil || len(reading.Drives) == 0 {
		return nil
	}
	readings := map[string]uint64{}
	for _, drive := range reading.Drives {
		if drive.Missing {
			return nil
		}
		readings[drive.DriveId] = drive.ReadsCompleted + drive.WritesCompleted
	}
	previous := self.readings
	previousTime := self.readingTime
	self.readings = readings
	self.readingTime = now
	elapsed := now.Sub(previousTime)
	if previous == nil || elapsed <= 0 {
		return nil
	}
	var operationCount uint64
	for driveId, count := range readings {
		if before, ok := previous[driveId]; ok && before <= count {
			operationCount += count - before
		}
	}
	figures := &HddFigures{
		ClusterId:         self.clusterId,
		TimeMs:            now.UnixMilli(),
		DriveOpsPerSecond: float64(operationCount) / elapsed.Seconds(),
		CapacityOps:       max(0, self.gates.FileCluster(self.clusterId).HddCapacityOps),
	}
	if err := publishHddFigures(ctx, self.redis, figures, self.settings.FiguresTtl); err != nil {
		self.log.Infof("[evshdd]%s: figures not published: %v\n", self.clusterId, err)
		return nil
	}
	if self.driveOpsGauge != nil {
		self.driveOpsGauge.Set(figures.DriveOpsPerSecond, self.clusterId)
		self.capacityGauge.Set(float64(figures.CapacityOps), self.clusterId)
	}
	return figures
}
