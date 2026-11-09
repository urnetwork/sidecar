// §11.13's hdd row on evs (EVSB-M2-08): each evs process keeps, per segment cluster, every network's upload bytes
// over a window, weighed by its store_weight (1, 4 and 16), and refuses segment uploads only past
// AdmissionLine of the cluster's measured capacity, heaviest network first: 503 with Retry-After, which refuses
// nothing durable. The figures come from §19.6's hdd loop through {nvb_<cluster>} (hdd_loop.go), read by this
// admission's own goroutine every interval, so the inline path reads memory alone (I-12).
//
// Who is refused, set once an interval from the figures and the window:
//
//   - no capacity published (§22.8's M3 run has not set one), no live figures, or drive operations at or under
//     the line: no one;
//   - past the line: the heaviest networks by bytes per weight, until their share of the window's bytes covers
//     the share of the operations past the line, at least one network;
//   - never authorization (config and mailcfg repos), deletion, shredding, erasure or closure uploads, which
//     their own bounds hold (§11.13; QuotaGate's closure pacing for closures).
//
// Every refusal counts in §19.8's urnetwork_evs_hdd_admission_refused_total{cluster}, with no network label.
//
// The admission also counts the segments the cluster stored for this process (CountPut, which the upload route
// calls), and on the same interval writes that count, from the admission's start, to {nvb_<cluster>} as the
// process's HddPutReport with a 15 s ttl, from which the hdd loop sets §19.8's
// urnetwork_filecluster_hdd_puts{cluster}. A report that does not land loses nothing but timing, since the next
// carries the count from the start. The report names no network or repo, and the count is one atomic add.
// Safe for concurrent use.

package evsservice

import (
	"context"
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

// §19.8's refusal count.
const hddAdmissionRefusedMetricName = "urnetwork_evs_hdd_admission_refused_total"

// What an upload is for, as its route and repo say. Every class but ordinary is exempt (§11.13's hdd row).
type HddUploadClass int

const (
	// A segment upload with no exemption.
	HddUploadOrdinary HddUploadClass = 0
	// To a config or mailcfg repo: authorization.
	HddUploadAuthorization HddUploadClass = 1
	// Part of a repo's deletion.
	HddUploadDeletion HddUploadClass = 2
	// Part of a shred.
	HddUploadShredding HddUploadClass = 3
	// Part of an erasure.
	HddUploadErasure HddUploadClass = 4
	// A ?closure=1 upload, which QuotaGate.ChargeClosure paces.
	HddUploadClosure HddUploadClass = 5
)

// Whether the class passes at the line.
func (self HddUploadClass) Exempt() bool {
	return self != HddUploadOrdinary
}

// An upload refused at the HDD line: 503 with Retry-After. Nothing was written.
type HddRefusal struct {
	ClusterId  string
	RetryAfter time.Duration
}

// Says which cluster refused, and when to try again.
func (self *HddRefusal) Error() string {
	return fmt.Sprintf("segment cluster %s past its HDD line, retry after %s", self.ClusterId, self.RetryAfter)
}

type HddAdmissionSettings struct {
	// How often the figures are read and the refused networks set: 5 s, the loop's interval.
	Interval time.Duration
	// The share of the measured capacity past which uploads are refused: 0.5 (§11.13).
	AdmissionLine float64
	// The span a network's upload bytes are weighed over: 1 min, long enough that one large upload does not
	// swing the order and short enough that a flood is seen within it.
	WindowSpan time.Duration
	// A refusal's Retry-After: one interval, when the next figures arrive.
	RetryAfter time.Duration
	// Where the store_weight cache reads its tunables: the write budget's (budget_queue.go).
	Weights *WriteBudgetSettings
	// The ttl of the process's PUT report: 15 s, three intervals, as {nvb_}'s other 5 s figures (§19.6).
	PutReportTtl time.Duration
}

func DefaultHddAdmissionSettings() *HddAdmissionSettings {
	return &HddAdmissionSettings{
		Interval:      5 * time.Second,
		AdmissionLine: 0.5,
		WindowSpan:    1 * time.Minute,
		RetryAfter:    5 * time.Second,
		Weights:       DefaultWriteBudgetSettings(),
		PutReportTtl:  15 * time.Second,
	}
}

// See the file header.
type HddAdmission struct {
	ctx            context.Context
	cancel         context.CancelFunc
	clusterId      string
	settings       *HddAdmissionSettings
	clock          sidecar.Clock
	redis          sidecar.Redis
	weights        *writeBudgetWeights
	refusedCounter sidecar.MetricsCounter
	// names the process's PUT report, with when the admission started
	processId string
	startMs   int64
	// segments the cluster stored for the process since startMs
	putCount atomic.Int64

	stateLock sync.Mutex
	// upload bytes by network, the open interval's last
	windows [][]hddNetworkBytes
	open    map[connect.Id]int64
	refused map[connect.Id]bool
	figures *HddFigures
}

// One interval's bytes of one network.
type hddNetworkBytes struct {
	networkId connect.Id
	byteCount int64
}

// The admission for one segment cluster, its goroutine started. host.Redis carries {nvb_<cluster>}, host.Quota
// the weights, host.Metrics the refusals, host.Clock its intervals. settings may be nil for the defaults. Close
// ends it.
func NewHddAdmission(ctx context.Context, host *sidecar.ServiceHost, clusterId string, settings *HddAdmissionSettings) (*HddAdmission, error) {
	self, err := newHddAdmission(ctx, host, clusterId, settings)
	if err != nil {
		return nil, err
	}
	go self.run()
	return self, nil
}

// NewHddAdmission without its goroutine, which a test drives through tick.
func newHddAdmission(ctx context.Context, host *sidecar.ServiceHost, clusterId string, settings *HddAdmissionSettings) (*HddAdmission, error) {
	if settings == nil {
		settings = DefaultHddAdmissionSettings()
	}
	if host == nil || host.Redis == nil {
		return nil, errors.New("the hdd admission needs ServiceHost.Redis")
	}
	processId, err := newBudgetHolderId()
	if err != nil {
		return nil, err
	}
	clock := host.ClockOrReal()
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &HddAdmission{
		ctx:       cancelCtx,
		cancel:    cancel,
		clusterId: clusterId,
		settings:  settings,
		clock:     clock,
		redis:     host.Redis,
		weights:   newWriteBudgetWeights(settings.Weights, host.Quota),
		processId: processId,
		startMs:   clock.Now().UnixMilli(),
		open:      map[connect.Id]int64{},
		refused:   map[connect.Id]bool{},
	}
	if host.Metrics != nil {
		self.refusedCounter = host.Metrics.Counter(hddAdmissionRefusedMetricName, "Segment uploads refused past a segment cluster's HDD line.", "cluster")
	}
	return self, nil
}

// Ends the goroutine. Admit goes on answering from the last figures.
func (self *HddAdmission) Close() {
	self.cancel()
}

// Every interval until Close, rereads the weights of the networks seen, then ticks on them, so no weight a tick
// reads is older than the reread.
func (self *HddAdmission) run() {
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.Interval):
		}
		self.weights.refresh(self.ctx, self.clock)
		self.tick(self.ctx)
	}
}

// Admits or refuses one upload of byteCount bytes from networkId, counting what it admits toward the network's
// share. No I/O: see the file header.
func (self *HddAdmission) Admit(networkId connect.Id, byteCount int64, class HddUploadClass) error {
	refused := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !class.Exempt() && self.refused[networkId] {
			return true
		}
		self.open[networkId] += max(0, byteCount)
		return false
	}()
	// the weight is read so the next refresh keeps it fresh
	self.weights.weight(networkId, self.clock.Now())
	if refused {
		if self.refusedCounter != nil {
			self.refusedCounter.Add(1, self.clusterId)
		}
		return &HddRefusal{ClusterId: self.clusterId, RetryAfter: self.settings.RetryAfter}
	}
	return nil
}

// Counts one segment the cluster stored for this process, toward §19.8's urnetwork_filecluster_hdd_puts{cluster}.
// The upload route calls it once the segment cluster has stored the body, so a refusal, a re-upload's 412 or a
// failed write counts nothing. No I/O.
func (self *HddAdmission) CountPut() {
	self.putCount.Add(1)
}

// One interval: writes the process's PUT report, reads the figures, closes the open interval into the window,
// and sets who is refused. A read that fails keeps the last figures, which the key's own ttl ends: once it finds
// none, no one is refused.
func (self *HddAdmission) tick(ctx context.Context) {
	report := &HddPutReport{
		ProcessId: self.processId,
		StartMs:   self.startMs,
		TimeMs:    self.clock.Now().UnixMilli(),
		PutCount:  self.putCount.Load(),
	}
	// one that does not land costs the loop only timing: the next carries the count from the start
	writeHddPutReport(ctx, self.redis, self.clusterId, report, self.settings.PutReportTtl)

	figures, err := readHddFigures(ctx, self.redis, self.clusterId)
	readOk := err == nil
	now := self.clock.Now()
	weights := map[connect.Id]int64{}
	networkIds := func() []connect.Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		closed := []hddNetworkBytes{}
		for _, networkId := range slices.SortedFunc(maps.Keys(self.open), func(a connect.Id, b connect.Id) int { return a.Cmp(b) }) {
			closed = append(closed, hddNetworkBytes{networkId: networkId, byteCount: self.open[networkId]})
		}
		self.open = map[connect.Id]int64{}
		self.windows = append(self.windows, closed)
		if windowCount := max(1, int(self.settings.WindowSpan/self.settings.Interval)); windowCount < len(self.windows) {
			self.windows = self.windows[len(self.windows)-windowCount:]
		}
		if readOk {
			self.figures = figures
		}
		networkIds := []connect.Id{}
		for _, window := range self.windows {
			for _, entry := range window {
				if !slices.Contains(networkIds, entry.networkId) {
					networkIds = append(networkIds, entry.networkId)
				}
			}
		}
		return networkIds
	}()
	for _, networkId := range networkIds {
		weights[networkId] = max(1, self.weights.weight(networkId, now))
	}

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refused = map[connect.Id]bool{}
	figures = self.figures
	if figures == nil || figures.CapacityOps <= 0 {
		return
	}
	line := self.settings.AdmissionLine * float64(figures.CapacityOps)
	if figures.DriveOpsPerSecond <= line {
		return
	}
	excessShare := (figures.DriveOpsPerSecond - line) / figures.DriveOpsPerSecond
	networkBytes := map[connect.Id]int64{}
	var totalByteCount int64
	for _, window := range self.windows {
		for _, entry := range window {
			networkBytes[entry.networkId] += entry.byteCount
			totalByteCount += entry.byteCount
		}
	}
	if totalByteCount <= 0 {
		return
	}
	order := slices.Collect(maps.Keys(networkBytes))
	slices.SortFunc(order, func(a connect.Id, b connect.Id) int {
		// heaviest by bytes per weight first, compared as a cross product so no division rounds a tie
		left := networkBytes[a] * weights[b]
		right := networkBytes[b] * weights[a]
		switch {
		case right < left:
			return -1
		case left < right:
			return 1
		}
		return a.Cmp(b)
	})
	var shedByteCount int64
	for _, networkId := range order {
		self.refused[networkId] = true
		shedByteCount += networkBytes[networkId]
		if excessShare*float64(totalByteCount) <= float64(shedByteCount) {
			break
		}
	}
}
