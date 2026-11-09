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
// The loop also sets §19.8's urnetwork_filecluster_hdd_puts{cluster}, the cluster's segment PUTs a second, which
// §19.9's hdd trigger trends against §22.8's admitted throughput. No drive counter tells a PUT from a GET, so it
// sums the evs processes' totals: each process's HddAdmission writes, every interval, the segments the cluster
// stored for it since it started, as its own field puts:<process id> with a 15 s ttl (HddPutReport). The loop
// takes each process's rate over the span between that process's own last two reports, so no two clocks are
// compared there, and sets the gauge only while every live process has a rate: on a lease just taken each process
// is a baseline, and so is one whose count fell, and the gauge then stays as it was. A process that started since
// the loop's last step counts from its start. A report past its ttl by the loop's clock is a process gone, and the
// loop deletes its field, since a field whose ttl never landed would otherwise stand. Nothing names a network or
// repo.
//
// Not safe for concurrent use: Run steps it, or a T2 schedule does.

package evsservice

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The figures' field in a segment cluster's {nvb_} key.
const hddFiguresField = "hdd"

// The prefix of each evs process's PUT report field in a segment cluster's {nvb_} key.
const hddPutReportFieldPrefix = "puts:"

// §19.8's gauges the loop sets (g0-recheck-0-hdd-trigger #1).
const (
	hddDriveOpsMetricName = "urnetwork_filecluster_hdd_drive_ops"
	hddCapacityMetricName = "urnetwork_filecluster_hdd_capacity"
	hddPutsMetricName     = "urnetwork_filecluster_hdd_puts"
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

// One evs process's segment PUTs on one segment cluster, which its HddAdmission writes every interval. The count
// runs from the process's start, so a report the loop missed loses nothing but timing. It names no host, network
// or repo (evs-10).
type HddPutReport struct {
	// 16 random bytes drawn when the admission started, as hex.
	ProcessId string `json:"process"`
	// When the admission started and when it wrote this, Unix ms by its clock.
	StartMs int64 `json:"start_ms"`
	TimeMs  int64 `json:"time_ms"`
	// The segments the cluster stored for the process since StartMs.
	PutCount int64 `json:"puts"`
}

// Writes report as the process's own field, expiring with ttl.
func writeHddPutReport(ctx context.Context, redis sidecar.Redis, clusterId string, report *HddPutReport, ttl time.Duration) error {
	return setWriteBudgetField(ctx, redis, clusterId, hddPutReportFieldPrefix+report.ProcessId, report, ttl)
}

// The reports on the cluster, in process id order. A field that does not parse, names another process, or holds
// a count below zero or a time before its start is skipped, its process read as absent.
func readHddPutReports(ctx context.Context, redis sidecar.Redis, clusterId string) ([]*HddPutReport, error) {
	fieldValues, err := redis.HashGetAll(ctx, writeBudgetKey(clusterId))
	if err != nil {
		return nil, err
	}
	reports := []*HddPutReport{}
	for _, field := range slices.Sorted(maps.Keys(fieldValues)) {
		processId, ok := strings.CutPrefix(field, hddPutReportFieldPrefix)
		if !ok {
			continue
		}
		report := &HddPutReport{}
		if err := json.Unmarshal(fieldValues[field], report); err != nil {
			continue
		}
		if report.ProcessId != processId || report.PutCount < 0 || report.TimeMs < report.StartMs {
			continue
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// What the loop keeps of one process's reports between steps.
type hddPutProcess struct {
	report *HddPutReport
	// PUTs a second over the span between its last two reports, once rated
	putsPerSecond float64
	rated         bool
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
	// A process's PUT report older than this by the loop's clock is a process gone, its field deleted: 15 s, the
	// ttl HddAdmissionSettings.PutReportTtl writes it with, so no live process is dropped.
	PutReportTtl time.Duration
}

func DefaultHddLoopSettings() *HddLoopSettings {
	return &HddLoopSettings{
		Interval:       5 * time.Second,
		FiguresTtl:     15 * time.Second,
		LeaseTtl:       15 * time.Second,
		CounterTimeout: 2 * time.Second,
		ReleaseTimeout: 2 * time.Second,
		PutReportTtl:   15 * time.Second,
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
	putsGauge     sidecar.MetricsGauge

	holding bool
	// each drive's reads and writes completed at the last reading, and when it was taken
	readings    map[string]uint64
	readingTime time.Time
	// each live process's last report and rate, and when the step that read them ran, zero before the first
	putProcesses map[string]*hddPutProcess
	putsTimeMs   int64
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
		self.putsGauge = metrics.Gauge(hddPutsMetricName, "A segment cluster's segment PUTs a second, the segments it stored for the evs processes.", "cluster")
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
		self.putProcesses = nil
		self.putsTimeMs = 0
		return nil
	}
	if !self.holding {
		// a new holder takes its own baselines
		self.holding = true
		self.readings = nil
		self.putProcesses = nil
		self.putsTimeMs = 0
	}

	// the PUT rate needs no drive counter, so a missing drive does not hold it back
	if putsPerSecond, complete := self.stepPuts(ctx, now); complete && self.putsGauge != nil {
		self.putsGauge.Set(putsPerSecond, self.clusterId)
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

// Reads the processes' PUT reports and sums their rates, as the file header says. complete is false while the
// reports are unread or a live process is a baseline, and then the sum is not the cluster's.
func (self *HddLoop) stepPuts(ctx context.Context, now time.Time) (putsPerSecond float64, complete bool) {
	reports, err := readHddPutReports(ctx, self.redis, self.clusterId)
	if err != nil {
		self.log.Infof("[evshdd]%s: put reports not read: %v\n", self.clusterId, err)
		return 0, false
	}
	nowMs := now.UnixMilli()
	complete = true
	processes := map[string]*hddPutProcess{}
	staleFields := []string{}
	for _, report := range reports {
		if self.settings.PutReportTtl.Milliseconds() < nowMs-report.TimeMs {
			staleFields = append(staleFields, hddPutReportFieldPrefix+report.ProcessId)
			continue
		}
		process := &hddPutProcess{report: report}
		previous, seen := self.putProcesses[report.ProcessId]
		switch {
		case seen && previous.report.StartMs == report.StartMs && previous.report.TimeMs == report.TimeMs:
			// no report since the last step: the rate it had stands
			process.putsPerSecond = previous.putsPerSecond
			process.rated = previous.rated
		case seen && previous.report.StartMs == report.StartMs && previous.report.TimeMs < report.TimeMs && previous.report.PutCount <= report.PutCount:
			process.putsPerSecond = float64(report.PutCount-previous.report.PutCount) * 1000 / float64(report.TimeMs-previous.report.TimeMs)
			process.rated = true
		case !seen && 0 < self.putsTimeMs && self.putsTimeMs <= report.StartMs && report.StartMs < report.TimeMs:
			// it started since the last step, so the step before saw none of its count
			process.putsPerSecond = float64(report.PutCount) * 1000 / float64(report.TimeMs-report.StartMs)
			process.rated = true
		}
		// anything else is a baseline: a process this holder has not seen run, or one whose count fell or whose
		// clock went back
		processes[report.ProcessId] = process
		if process.rated {
			putsPerSecond += process.putsPerSecond
		} else {
			complete = false
		}
	}
	self.putProcesses = processes
	self.putsTimeMs = nowMs
	if 0 < len(staleFields) {
		if err := self.redis.HashDelete(ctx, writeBudgetKey(self.clusterId), staleFields); err != nil {
			self.log.Infof("[evshdd]%s: stale put reports not deleted: %v\n", self.clusterId, err)
		}
	}
	return putsPerSecond, complete
}
