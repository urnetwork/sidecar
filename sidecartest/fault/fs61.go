// FS-61 (§22.8, FI-14; EVSB-M2-07) on a Net, its first clauses: the budget loop over fake drive counters beside real
// process budgets, on the Net's host and clock: its Redis, with evs's twins on T2's fake, and its metrics. The drives
// are the PM9A3 set's, so the refill is 0.768 DWPD of 1.92 TB. The loop steps from a schedule's step, and each process
// ticks on its own goroutine at the interval's end, which a step waits out by its next timer, so every step sees what
// each side has done and nothing races; no barrier is passed, so the explorer's seeds each take the one order there is.
//
// The registered case, Fs61AllowancesFallWithinTenSecondsAtNinetyPercentDwpd: a process spends all of T at exact prices
// while the drives write what it priced, then the drives write at 0.9 DWPD's rate for the same priced bytes, and within
// 10 s the allowance in priced bytes has fallen, and B with it. The clauses beside it (clauses.go): P0 issues at once
// while B is empty and T is zero, its bytes reported by kind; the governor killed, processes hold their share 60 s,
// then half, and a new process starts at the refill over twice the process count; and the {nvb_<set>} keys every
// process and the loop write pass the schema guard's family check. FI-14's oracle is EVSB-M2-16's and unbound
// (fault.FI(14) fails closed), so each schedule checks FI-14 (b) as its world reads it after every step (FI-14/fs61):
// every allowance the loop published splits T into A1 and A_U, A_U within its share of T, and holds no figure below
// zero; each step's own clauses read the allowances beside it.
//
// Outside the registry: the Pro flood against a Community network's p99, in evsservice's budget_loop_test.go, which
// holds a process's queue between ticks; and the 26 h tail at twice year one's mix, EVSB-M2-16's fs61_long_test.go, on
// FS-117's world. T3 has no FS-61 run yet.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs61 = Register("FS-61", "", []Tier{TierT2}, Fs61AllowancesFallWithinTenSecondsAtNinetyPercentDwpd)

// The metadata set the world's loop and processes budget.
const fs61ClusterId = "meta-1"

// What FS-61's world is built with.
type Fs61WorldSettings struct {
	// The loop's and every process's settings: the defaults, the weights reread once an hour, so the only timers a
	// step waits for are the processes' ticks.
	Loop *evsservice.BudgetLoopSettings
	// Real time a step waits for the processes to arm the timers it counts before it fails: a guard against a process
	// that never arms one, never a wait a schedule orders: 10 s.
	TimerTimeout time.Duration
}

func DefaultFs61WorldSettings() *Fs61WorldSettings {
	loop := evsservice.DefaultBudgetLoopSettings()
	loop.Budget.WeightRefreshInterval = time.Hour
	return &Fs61WorldSettings{
		Loop:         loop,
		TimerTimeout: 10 * time.Second,
	}
}

// The busiest drive and one beside it, moved by hand.
type fs61Counters struct {
	stateLock sync.Mutex
	written   [2]uint64
}

func (self *fs61Counters) ReadDriveCounters(ctx context.Context, clusterId string) (*evsservice.DriveCounterReading, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &evsservice.DriveCounterReading{
		Drives: []*evsservice.DriveCounter{
			{DriveId: "0-0-0", WrittenByteCount: self.written[0]},
			{DriveId: "0-0-1", WrittenByteCount: self.written[1]},
		},
	}, nil
}

// The busiest drive writes byteCount, the other a little less.
func (self *fs61Counters) write(byteCount uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.written[0] += byteCount
	self.written[1] += byteCount * 9 / 10
}

// The loop over the Net's host and the processes a schedule starts.
type fs61NetWorld struct {
	net      *Net
	settings *Fs61WorldSettings
	counters *fs61Counters

	stateLock sync.Mutex
	loop      *evsservice.BudgetLoop
	clients   []*evsservice.WriteBudgetClient
	// every allowance the loop published, in order
	allowances []*evsservice.WriteBudgetAllowance
}

func newFs61NetWorld(net *Net, settings *Fs61WorldSettings) *fs61NetWorld {
	if settings == nil {
		settings = DefaultFs61WorldSettings()
	}
	return &fs61NetWorld{net: net, settings: settings, counters: &fs61Counters{}}
}

func (self *fs61NetWorld) budget() *evsservice.WriteBudgetSettings {
	return self.settings.Loop.Budget
}

// The bucket's depth at the refill: a day's refill over 24.
func (self *fs61NetWorld) depth() int64 {
	return int64(self.budget().RefillDwpd * float64(self.budget().DriveByteCount) / 24)
}

// The drive writes of an interval at dwpd: at the refill, the refill r.
func (self *fs61NetWorld) intervalBytes(dwpd float64) uint64 {
	return uint64(dwpd * float64(self.budget().DriveByteCount) / (24 * time.Hour).Seconds() * self.budget().Interval.Seconds())
}

// A step action: the loop, over a saved state of bucket B and calibration 1, or none when bucketByteCount is negative,
// stepped once so it publishes.
func (self *fs61NetWorld) setup(bucketByteCount int64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		sidecartest.RegisterEvsTwins(net.Fakes().Redis)
		host := net.Host()
		if 0 <= bucketByteCount {
			state := &evsservice.GovernorState{
				Seq:             1,
				TimeMs:          net.Clock().Now().Add(-self.budget().Interval).UnixMilli(),
				BucketByteCount: bucketByteCount,
				Calibration:     1,
			}
			if err := evsservice.SaveGovernorState(ctx, host.Redis, self.budget(), fs61ClusterId, state); err != nil {
				return err
			}
		}
		loop, err := evsservice.NewBudgetLoop(host, fs61ClusterId, self.counters, nil, self.settings.Loop)
		if err != nil {
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.loop = loop
		}()
		allowance := loop.Step(ctx)
		if allowance == nil {
			if 0 <= bucketByteCount {
				return errors.New("the loop did not publish")
			}
			return nil
		}
		self.published(allowance)
		return nil
	}
}

func (self *fs61NetWorld) theLoop() *evsservice.BudgetLoop {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.loop
}

func (self *fs61NetWorld) client(index int) *evsservice.WriteBudgetClient {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clients[index]
}

// The timers pending at exactly at.
func (self *fs61NetWorld) timerCount(at time.Time) int {
	pending, _ := self.net.Clock().WatchTimers()
	count := 0
	for _, pendingAt := range pending {
		if pendingAt.Equal(at) {
			count += 1
		}
	}
	return count
}

// Returns once count timers are pending at exactly at. A process re-arms its interval's timer only after its tick, so
// this is how a step knows every tick is done. Field ttls in the fake Redis set timers too, on the interval's grid, so
// a caller counts the ones there before it moves the clock.
func (self *fs61NetWorld) awaitTimers(ctx context.Context, at time.Time, count int) error {
	for {
		pending, added := self.net.Clock().WatchTimers()
		found := 0
		for _, pendingAt := range pending {
			if pendingAt.Equal(at) {
				found += 1
			}
		}
		if count <= found {
			return nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(self.settings.TimerTimeout):
			return fmt.Errorf("%d timers at %s, want %d", found, at, count)
		}
	}
}

// A process budget, started on the Net's host under the step's actor, its first tick waited out.
func (self *fs61NetWorld) addClient(ctx context.Context) (*evsservice.WriteBudgetClient, error) {
	next := self.net.Clock().Now().Add(self.budget().Interval)
	before := self.timerCount(next)
	client, err := evsservice.NewWriteBudget(ctx, self.net.Host(), []string{fs61ClusterId}, self.budget())
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	self.clients = append(self.clients, client)
	self.stateLock.Unlock()
	return client, self.awaitTimers(ctx, next, before+1)
}

// One interval: the drives write byteCount, the processes tick at its end, and the loop steps when stepping, its
// allowance then given.
func (self *fs61NetWorld) interval(ctx context.Context, byteCount uint64, stepping bool) (*evsservice.WriteBudgetAllowance, error) {
	self.counters.write(byteCount)
	self.stateLock.Lock()
	clientCount := len(self.clients)
	self.stateLock.Unlock()
	next := self.net.Clock().Now().Add(2 * self.budget().Interval)
	before := self.timerCount(next)
	self.net.Clock().Advance(self.budget().Interval)
	if err := self.awaitTimers(ctx, next, before+clientCount); err != nil {
		return nil, err
	}
	if !stepping {
		return nil, nil
	}
	allowance := self.theLoop().Step(ctx)
	if allowance == nil {
		return nil, errors.New("the loop published no allowance")
	}
	self.published(allowance)
	return allowance, nil
}

// Keeps an allowance the loop published, for FI-14's check.
func (self *fs61NetWorld) published(allowance *evsservice.WriteBudgetAllowance) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.allowances = append(self.allowances, allowance)
}

// FI-14 (b) as the world reads it, after every step: each allowance the loop published splits T into A1 and A_U, keeps
// A_U within its share of T, and holds no figure below zero.
func (self *fs61NetWorld) check() Invariant {
	return NewInvariant("FI-14/fs61", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		allowances := slices.Clone(self.allowances)
		self.stateLock.Unlock()
		for index, allowance := range allowances {
			figures := []int64{allowance.BucketByteCount, allowance.WalletByteCount, allowance.TotalByteCount, allowance.P1ByteCount, allowance.UnfundedByteCount, allowance.FundedByteCount}
			if slices.ContainsFunc(figures, func(figure int64) bool { return figure < 0 }) {
				return fmt.Errorf("allowance %d holds a figure below zero: B %d, W %d, T %d, A1 %d, A_U %d, A2 %d", index, figures[0], figures[1], figures[2], figures[3], figures[4], figures[5])
			}
			if allowance.P1ByteCount+allowance.UnfundedByteCount != allowance.TotalByteCount {
				return fmt.Errorf("allowance %d: A1 %d and A_U %d are not T %d", index, allowance.P1ByteCount, allowance.UnfundedByteCount, allowance.TotalByteCount)
			}
			if self.budget().UnfundedShare*float64(allowance.TotalByteCount) < float64(allowance.UnfundedByteCount) {
				return fmt.Errorf("allowance %d: A_U %d past its share of T %d", index, allowance.UnfundedByteCount, allowance.TotalByteCount)
			}
		}
		return nil
	})
}

// Whether a P1 of price priced bytes is admitted now, out of the process's share: a ctx already ended leaves the
// queue at once when the share does not cover it.
func fs61AdmitNow(client *evsservice.WriteBudgetClient, networkId connect.Id, price int64) bool {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	grant, err := client.AdmitP1(ctx, fs61ClusterId, networkId, sidecar.WriteCost{ImmediateByteCount: price})
	if err != nil {
		return false
	}
	grant.Close()
	return true
}

// Spends the process's P1 share in units, returning the priced bytes admitted.
func fs61SpendShare(client *evsservice.WriteBudgetClient, networkId connect.Id, unit int64) int64 {
	var spent int64
	for fs61AdmitNow(client, networkId, unit) {
		spent += unit
	}
	return spent
}

// See the file header.
func Fs61AllowancesFallWithinTenSecondsAtNinetyPercentDwpd(net *Net) *Schedule {
	world := newFs61NetWorld(net, nil)
	networkId := connect.NewId()
	unit := int64(64 * 1024)
	var steady *evsservice.WriteBudgetAllowance
	steps := []*Step{
		{Actor: "governor", Action: world.setup(world.depth())},
		{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
			_, err := world.addClient(ctx)
			return err
		}},
		// the process takes its share once the loop has seen its report
		{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			_, err := world.interval(ctx, 0, true)
			return err
		}},
		{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			for range 6 {
				spent := fs61SpendShare(world.client(0), networkId, unit)
				allowance, err := world.interval(ctx, uint64(spent), true)
				if err != nil {
					return err
				}
				steady = allowance
			}
			if refill := world.intervalBytes(world.budget().RefillDwpd); steady.TotalByteCount < int64(refill)*9/10 {
				return fmt.Errorf("steady T %d against a refill of %d", steady.TotalByteCount, refill)
			}
			return nil
		}},
		{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			busy := world.intervalBytes(0.9)
			for range 2 {
				fs61SpendShare(world.client(0), networkId, unit)
				allowance, err := world.interval(ctx, busy, true)
				if err != nil {
					return err
				}
				if allowance.TotalByteCount < steady.TotalByteCount && allowance.BucketByteCount < steady.BucketByteCount {
					if allowance.Calibration <= 1 {
						return fmt.Errorf("k %v after the drives wrote past the priced bytes", allowance.Calibration)
					}
					return nil
				}
			}
			return errors.New("the allowance did not fall within 10 s")
		}},
	}
	return &Schedule{Id: "FS-61", Steps: steps, Check: []Invariant{world.check()}}
}

// P0 issues at once while B is empty and T is zero, P1 waits, and P0's bytes come back by kind: in the process's
// issued metric, in the allowance's measured P0 and in its forgiven excess.
func Fs61P0ProceedsAtOnceWithItsBytesByKind(net *Net) *Schedule {
	world := newFs61NetWorld(net, nil)
	networkId := connect.NewId()
	kinds := []sidecar.WriteP0Kind{sidecar.WriteP0KindRevocation, sidecar.WriteP0KindShred, sidecar.WriteP0KindErasure, sidecar.WriteP0KindRotation}
	var last *evsservice.WriteBudgetAllowance
	steps := []*Step{
		{Actor: "governor", Action: world.setup(0)},
		{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
			_, err := world.addClient(ctx)
			return err
		}},
		{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			_, err := world.interval(ctx, 0, true)
			return err
		}},
		// a storm of twice the refill, split over four kinds, every write issued on arrival
		{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
			refill := world.intervalBytes(world.budget().RefillDwpd)
			for range 4 {
				for _, kind := range kinds {
					issued := world.client(0).IssueP0(ctx, fs61ClusterId, kind, int64(refill)/2)
					if class, ok := sidecar.WriteClassOf(issued); !ok || class != sidecar.WriteClassP0 {
						return fmt.Errorf("P0 of kind %s carries class %v", kind, class)
					}
				}
				allowance, err := world.interval(ctx, 2*refill, true)
				if err != nil {
					return err
				}
				last = allowance
			}
			return nil
		}},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			refill := world.intervalBytes(world.budget().RefillDwpd)
			if last.TotalByteCount != 0 || last.BucketByteCount != 0 {
				return fmt.Errorf("T %d and B %d while P0 takes twice the refill", last.TotalByteCount, last.BucketByteCount)
			}
			if fs61AdmitNow(world.client(0), networkId, 1) {
				return errors.New("P1 issued while P0 holds the bucket empty")
			}
			metrics := net.Fakes().Metrics
			for _, kind := range kinds {
				if issued := metrics.Value("urnetwork_evs_budget_issued_bytes_total", fs61ClusterId, "p0", string(kind)); issued != float64(4*(int64(refill)/2)) {
					return fmt.Errorf("issued P0 of kind %s: %v", kind, issued)
				}
				if last.P0ExcessByteCounts[kind] <= 0 {
					return fmt.Errorf("no forgiven excess counted for kind %s", kind)
				}
				if forgiven := metrics.Value("urnetwork_evs_budget_p0_forgiven_bytes_total", fs61ClusterId, string(kind)); forgiven <= 0 {
					return fmt.Errorf("forgiven series for kind %s: %v", kind, forgiven)
				}
			}
			if last.P0MeasuredByteCount < int64(2*refill)*9/10 {
				return fmt.Errorf("P0 measured %d of twice the refill", last.P0MeasuredByteCount)
			}
			return nil
		}},
	}
	return &Schedule{Id: "FS-61 p0 proceeds at once with its bytes by kind", Steps: steps, Check: []Invariant{world.check()}}
}

// The governor killed, a process runs its last share for 60 s, then half of it; a process started after the kill,
// which never had an allowance, runs within the refill over twice the process count.
func Fs61GovernorKilledProcessesFallBack(net *Net) *Schedule {
	world := newFs61NetWorld(net, nil)
	networkId := connect.NewId()
	unit := int64(1024 * 1024)
	var share int64
	steps := []*Step{
		{Actor: "governor", Action: world.setup(world.depth())},
		{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
			_, err := world.addClient(ctx)
			return err
		}},
		{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			for range 2 {
				if _, err := world.interval(ctx, 0, true); err != nil {
					return err
				}
			}
			spent := fs61SpendShare(world.client(0), networkId, unit)
			if _, err := world.interval(ctx, uint64(spent), true); err != nil {
				return err
			}
			share = fs61SpendShare(world.client(0), networkId, unit)
			if share <= 0 {
				return errors.New("no share before the kill")
			}
			return nil
		}},
		// killed: no step from here on. The process's next tick takes the last allowance the loop published, and from
		// that read it holds the share for FallbackAfter, through the allowance's lapse
		{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
			if _, err := world.interval(ctx, 0, false); err != nil {
				return err
			}
			if spent := fs61SpendShare(world.client(0), networkId, unit); spent != share {
				return fmt.Errorf("the last allowance gave %d, want %d", spent, share)
			}
			elapsed := time.Duration(0)
			for elapsed+world.budget().Interval < world.budget().FallbackAfter {
				if _, err := world.interval(ctx, 0, false); err != nil {
					return err
				}
				elapsed += world.budget().Interval
				if spent := fs61SpendShare(world.client(0), networkId, unit); spent != share {
					return fmt.Errorf("%s after the last fresh allowance the share was %d, want the last %d", elapsed, spent, share)
				}
			}
			if _, err := world.interval(ctx, 0, false); err != nil {
				return err
			}
			elapsed += world.budget().Interval
			if half := fs61SpendShare(world.client(0), networkId, unit); half < share/2-unit || share/2 < half {
				return fmt.Errorf("%s after the last fresh allowance the share was %d, want half of %d", elapsed, half, share)
			}
			return nil
		}},
		// a process that never had an allowance: the refill over twice the two processes reporting, as the saved state
		// counts them, P1 taking all but unfunded P2's part
		{Actor: "evs2", Action: func(ctx context.Context, net *Net) error {
			late, err := world.addClient(ctx)
			if err != nil {
				return err
			}
			total := int64(world.intervalBytes(world.budget().RefillDwpd)) / (2 * 2)
			want := total - int64(float64(total)*world.budget().UnfundedShare)
			if spent := fs61SpendShare(late, networkId, 1024); spent < want-1024 || want < spent {
				return fmt.Errorf("a new process spent %d, want about %d", spent, want)
			}
			return nil
		}},
	}
	return &Schedule{Id: "FS-61 governor killed processes fall back", Steps: steps, Check: []Invariant{world.check()}}
}

// The keys the loop and every process write to {nvb_<set>} are one family §2.8's evs-10 names, so the schema guard's
// store check passes them: the reports of four processes alike, which differ only in their process ids.
func Fs61BudgetKeysPassTheSchemaGuard(net *Net) *Schedule {
	world := newFs61NetWorld(net, nil)
	steps := []*Step{
		{Actor: "governor", Action: world.setup(-1)},
	}
	for _, actor := range []string{"evs1", "gkm1", "api1", "taskworker1"} {
		steps = append(steps, &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
			_, err := world.addClient(ctx)
			return err
		}})
	}
	steps = append(steps, []*Step{
		{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			_, err := world.interval(ctx, 1000, true)
			return err
		}},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			keys := slices.Sorted(func(yield func(string) bool) {
				for key := range net.Fakes().Redis.Dump() {
					if !yield(key) {
						return
					}
				}
			})
			if !slices.Contains(keys, "{nvb_"+fs61ClusterId+"}") {
				return fmt.Errorf("no {nvb_%s} among %v", fs61ClusterId, keys)
			}
			reports, err := evsservice.ReadWriteBudgetReports(sidecartest.InspectContext(ctx), net.Host().Redis, fs61ClusterId)
			if err != nil {
				return err
			}
			if len(reports) != 4 {
				return fmt.Errorf("%d reports from four processes", len(reports))
			}
			guard, err := sidecartest.LoadSchemaGuard()
			if err != nil {
				return err
			}
			findings, err := guard.CheckStores(ctx, &sidecartest.SchemaGuardStores{RedisKeys: keys})
			if err != nil {
				return err
			}
			if len(findings) != 0 {
				return fmt.Errorf("the guard refuses the budget's keys: %v", findings)
			}
			return nil
		}},
	}...)
	return &Schedule{Id: "FS-61 budget keys pass the schema guard", Steps: steps, Check: []Invariant{world.check()}}
}
