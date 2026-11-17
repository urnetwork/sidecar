// The heap a search is held to (SEARCH-M10-38; §18.4's targets, §5.9's bounds row, D-SDK-25, FI-18; FS-77, FS-109,
// FS-110): the live heap as runtime/metrics' /memory/classes/heap/objects:bytes reads it right after a forced
// collection, at every point a search passes that a schedule samples (each record it opens and each page it answers),
// less its value when the sampler began. The forced collection is the point: without it, a search that collected a
// partition's keys and dropped them before the sample hides in what the collector had not yet freed, which is the bug
// FS-109 exists to catch.
//
// A sampler keeps its peak and count, never every sample, so sampling adds nothing to what it measures. Safe for
// concurrent use: concurrent searches sample from their own goroutines.

package sidecartest

import (
	"fmt"
	"runtime"
	"runtime/metrics"
	"sync"
)

// The heap's live and not yet swept objects, as runtime/metrics names it; after a forced collection, the live heap.
const searchHeapMetric = "/memory/classes/heap/objects:bytes"

// The live heap now: a forced collection, then the metric.
func SearchHeapByteCount() int64 {
	runtime.GC()
	samples := []metrics.Sample{{Name: searchHeapMetric}}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return int64(samples[0].Value.Uint64())
}

// One sample: where, and the heap then less the sampler's start.
type SearchHeapSample struct {
	Label           string
	GrowthByteCount int64
}

// A search's heap from its start.
type SearchHeapSampler struct {
	// bytes in the heap that stand for storage, which a sample leaves out: a cache kept in memory for its disk
	stored func() int64

	stateLock        sync.Mutex
	startByteCount   int64
	startStoredCount int64
	peak             SearchHeapSample
	sampleCount      int
}

// A sampler whose start is the live heap now.
func NewSearchHeapSampler() *SearchHeapSampler {
	return NewSearchHeapSamplerLeavingOut(nil)
}

// A sampler whose start is the live heap now, leaving out what stored reports at each sample over its value at the
// start: the bytes a cache kept in memory holds for what a device keeps on disk. nil leaves out nothing.
func NewSearchHeapSamplerLeavingOut(stored func() int64) *SearchHeapSampler {
	sampler := &SearchHeapSampler{stored: stored}
	if stored != nil {
		sampler.startStoredCount = stored()
	}
	sampler.startByteCount = SearchHeapByteCount()
	return sampler
}

// Samples the live heap now, at label, and answers its growth over the start, less what storage took.
func (self *SearchHeapSampler) Sample(label string) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	growth := SearchHeapByteCount() - self.startByteCount
	if self.stored != nil {
		growth -= self.stored() - self.startStoredCount
	}
	self.sampleCount += 1
	if self.sampleCount == 1 || self.peak.GrowthByteCount < growth {
		self.peak = SearchHeapSample{Label: label, GrowthByteCount: growth}
	}
	return growth
}

// The largest growth sampled, and where.
func (self *SearchHeapSampler) Peak() SearchHeapSample {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.peak
}

// How many samples were taken: a check that took none measured nothing.
func (self *SearchHeapSampler) SampleCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sampleCount
}

// nil when every sample stayed within budgetByteCount of the start and at least one was taken; else what passed it.
func (self *SearchHeapSampler) CheckWithin(what string, budgetByteCount int64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.sampleCount == 0 {
		return fmt.Errorf("%s: no heap sample was taken, so nothing was measured", what)
	}
	if budgetByteCount < self.peak.GrowthByteCount {
		return fmt.Errorf("%s: the heap grew %d B at %s, past %d B", what, self.peak.GrowthByteCount, self.peak.Label, budgetByteCount)
	}
	return nil
}
