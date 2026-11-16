// T4's surrogate cells (§22.4's T4, §22.9's Memory, size row; SDK-M8-15; owner decision 100): a cell runs a step of an
// app host under one surrogate profile and measures what §18.4 budgets, so the budgets are assertions rather than
// estimates.
//
//	profile   ios32: the iOS app's 32 MiB Go soft limit and sidecar budget, forwarding's 4 MiB steady heap and 10 MiB
//	          compile cap (§18.4, §18.10's memory row, QD-620); android: the app's 64 MiB limit, the sidecar role's
//	          16 MiB added and forwarding's 16 MiB compile cap. A cell runs on this host under the profile's limit; the
//	          surrogate devices' own runs (a phone holding the profile, tests/runner/perf's ios32 and android) are the
//	          same harness there, and external
//	measure   a step runs under the profile's Go memory limit; the heap's live objects are sampled every
//	          HeapSampleInterval while it runs and at each Sample the step calls where it holds the most, the peak
//	          taken over the heap at the step's start, then after the step and runtime/debug.FreeOSMemory the steady
//	          heap over the cell's baseline: a sampled peak, not an allocation total, and it counts garbage the
//	          collector had not yet freed. Under a limit below the process's heap the collector runs at once, so a
//	          transient the timed samples happen to miss is caught only by a Sample at its high-water mark
//	budgets   each row names its budget, and CheckWithin fails a row past it, so a step that keeps more than the budget
//	          fails, as a deliberate over-allocation shows
//
// The figures are this host's on this leg: no surrogate figure is evidence for a device (owner decision 100), and
// jetsam on a physical iPhone stays unmeasured.
//
// It imports only the standard library, so sdk's tests use it without taking on sidecartest's modules, and the sidecar
// module's own cells (SEARCH-M10-38's phone cells among them) import it beside sidecartest.

package t4cell

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The heap's live objects, as runtime/metrics names them.
const heapMetric = "/memory/classes/heap/objects:bytes"

// The surrogate profiles, as cells and reports name them.
const (
	ProfileIos32   = "ios32"
	ProfileAndroid = "android"
)

// What one surrogate profile holds a cell to.
type Profile struct {
	Name string
	// The Go memory limit a cell's steps run under: the app's soft limit on the device.
	GoMemoryLimitByteCount int64
	// §18.4's budget for the sidecar role in the app: iOS 32 MiB; Android 16 MiB added.
	SidecarBudgetByteCount int64
	// §18.10's memory row: forwarding's Go heap steady.
	ForwardingSteadyByteCount int64
	// The forwarding compile's cap on this class (QD-620's 10 MiB in the Apple extensions; 16 MiB on Android).
	CompileMemoryMaxByteCount int64
	// How often a running step's heap is sampled.
	HeapSampleInterval time.Duration
}

// The ios32 surrogate (§22.9): the iOS app's and network extension's figures.
func Ios32Profile() *Profile {
	return &Profile{
		Name:                      ProfileIos32,
		GoMemoryLimitByteCount:    32 * 1024 * 1024,
		SidecarBudgetByteCount:    32 * 1024 * 1024,
		ForwardingSteadyByteCount: 4 * 1024 * 1024,
		CompileMemoryMaxByteCount: 10 * 1024 * 1024,
		HeapSampleInterval:        200 * time.Microsecond,
	}
}

// The Android surrogate (§22.9): the app's limit, with the sidecar role's 16 MiB added.
func AndroidProfile() *Profile {
	return &Profile{
		Name:                      ProfileAndroid,
		GoMemoryLimitByteCount:    64 * 1024 * 1024,
		SidecarBudgetByteCount:    16 * 1024 * 1024,
		ForwardingSteadyByteCount: 4 * 1024 * 1024,
		CompileMemoryMaxByteCount: 16 * 1024 * 1024,
		HeapSampleInterval:        200 * time.Microsecond,
	}
}

// One measured step.
type Row struct {
	Profile string
	Step    string
	// The sampled peak over the heap at the step's start.
	PeakByteCount int64
	// After the step and FreeOSMemory, over the cell's baseline.
	SteadyByteCount int64
	// The budget the row is held to, 0 for a row that is only reported.
	BudgetByteCount int64
	// Which figure the budget holds: peak or steady.
	Holds    string
	Duration time.Duration
}

// The figure a row's budget holds.
const (
	HoldsPeak   = "peak"
	HoldsSteady = "steady"
)

// Whether the row is within its budget; a row with none is.
func (self *Row) Within() bool {
	if self.BudgetByteCount <= 0 {
		return true
	}
	if self.Holds == HoldsSteady {
		return self.SteadyByteCount <= self.BudgetByteCount
	}
	return self.PeakByteCount <= self.BudgetByteCount
}

// One cell: a profile's steps and their rows. Not safe for concurrent steps; Sample is safe from any goroutine.
type Cell struct {
	profile *Profile
	// the heap when the cell began, after FreeOSMemory: what steady figures are over
	baselineByteCount int64
	rows              []*Row
	// the step Measure runs now, which Sample notes into; nil between steps
	measuring atomic.Pointer[cellStep]
}

// The peak of the step running, which the sampler and Sample raise.
type cellStep struct {
	stateLock     sync.Mutex
	peakByteCount int64
}

// Raises the step's peak to the heap now.
func (self *cellStep) note() {
	heap := heap()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.peakByteCount = max(self.peakByteCount, heap)
}

// The step's peak so far.
func (self *cellStep) peak() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.peakByteCount
}

// A cell under profile, its baseline read now.
func NewCell(profile *Profile) *Cell {
	return &Cell{profile: profile, baselineByteCount: settledHeap()}
}

// The profile.
func (self *Cell) Profile() *Profile {
	return self.profile
}

// The heap's live objects now.
func heap() int64 {
	samples := []metrics.Sample{{Name: heapMetric}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return int64(samples[0].Value.Uint64())
}

// The heap's live objects once the collector ran and returned what it could.
func settledHeap() int64 {
	runtime.GC()
	debug.FreeOSMemory()
	return heap()
}

// Runs step under the profile's Go memory limit, and records its sampled peak over the heap at its start and its steady
// heap over the baseline, held to budget by holds (HoldsPeak or HoldsSteady; a budget of 0 only reports).
// keep, when step returns one, is held until the steady figure is read, so what a step keeps counts. Answers step's
// error, the row recorded either way.
func (self *Cell) Measure(step string, budgetByteCount int64, holds string, run func() (keep any, err error)) (*Row, error) {
	previousLimit := debug.SetMemoryLimit(self.profile.GoMemoryLimitByteCount)
	defer debug.SetMemoryLimit(previousLimit)
	startByteCount := settledHeap()

	measuring := &cellStep{peakByteCount: startByteCount}
	self.measuring.Store(measuring)
	defer self.measuring.Store(nil)
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(self.profile.HeapSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				measuring.note()
			}
		}
	}()
	started := time.Now()
	keep, err := run()
	duration := time.Since(started)
	measuring.note()
	close(stop)
	<-sampled
	steady := settledHeap() - self.baselineByteCount
	runtime.KeepAlive(keep)

	row := &Row{
		Profile:         self.profile.Name,
		Step:            step,
		PeakByteCount:   max(0, measuring.peak()-startByteCount),
		SteadyByteCount: max(0, steady),
		BudgetByteCount: budgetByteCount,
		Holds:           holds,
		Duration:        duration,
	}
	self.rows = append(self.rows, row)
	return row, err
}

// Samples the heap into the step Measure runs now: a step calls it where it holds the most, so a transient's peak is
// measured whatever the timed samples' luck. Between steps it does nothing.
func (self *Cell) Sample() {
	if measuring := self.measuring.Load(); measuring != nil {
		measuring.note()
	}
}

// Every row so far.
func (self *Cell) Rows() []*Row {
	return append([]*Row{}, self.rows...)
}

// An error naming each row past its budget, nil when every row is within.
func (self *Cell) CheckWithin() error {
	findings := []string{}
	for _, row := range self.rows {
		if !row.Within() {
			figure := row.PeakByteCount
			if row.Holds == HoldsSteady {
				figure = row.SteadyByteCount
			}
			findings = append(findings, fmt.Sprintf("%s %s: %s %d B past its budget of %d B", row.Profile, row.Step, row.Holds, figure, row.BudgetByteCount))
		}
	}
	if len(findings) == 0 {
		return nil
	}
	return errors.New(strings.Join(findings, "; "))
}

// The rows as a table, for a report.
func (self *Cell) Table() string {
	var table strings.Builder
	fmt.Fprintf(&table, "%-8s %-40s %12s %12s %12s %-6s %s\n", "profile", "step", "peak B", "steady B", "budget B", "holds", "within")
	for _, row := range self.rows {
		fmt.Fprintf(&table, "%-8s %-40s %12d %12d %12d %-6s %v\n", row.Profile, row.Step, row.PeakByteCount, row.SteadyByteCount, row.BudgetByteCount, row.Holds, row.Within())
	}
	return table.String()
}
