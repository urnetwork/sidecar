// The heap a search is held to (SEARCH-M10-38; §18.4's targets, §5.9's bounds row, D-SDK-25, FI-18; FS-77, FS-109,
// FS-110): the live heap as runtime/metrics' /memory/classes/heap/objects:bytes reads it right after a forced
// collection, at every point a search passes that a schedule samples (each record it opens and each page it answers),
// less its value when the sampler began. The forced collection is the point: without it, a search that collected a
// partition's keys and dropped them before the sample hides in what the collector had not yet freed, which is the bug
// FS-109 exists to catch.
//
// The metric is the process's, so a sample is the searches' heap only while nothing else allocates through the
// collection, and two things can:
//
//	other tests       a goroutine or world an earlier test of the binary left running counts as the search's, and one
//	                  freed during the step hides the search's growth. So CheckWithin answers only for a sampler begun
//	                  in a search heap process (search_heap_process.go), the test binary run again for the one test,
//	                  and refuses any other.
//	searches at once  a search still at work while another's sample collects allocates through the collection, and what
//	                  it allocates then counts as live, frame buffers it drops a moment later included, by as much as
//	                  the collection takes: FS-109's desktop at 80,000 measured from 8 MB to 58 MB this way with nothing
//	                  else in the process, the sibling's io.ReadAll and seal reader buffers at the peak, and went past
//	                  its 64 MiB under load (111 MB in tip-check's run at abd1bdee). So a sampler of searches at once
//	                  (NewSearchHeapSamplerOfSearches) collects only once every search holding one of the engine's slots
//	                  is parked at a sample of its own, and holds the free slots through the collection so none starts
//	                  meanwhile: each search counts what it holds where it samples, as one alone does, and none what it
//	                  allocates on the way. Parked together they take one sample, 2 MB to 3 MB at that step.
//
// A sampler keeps its peak and count, never every sample, so sampling adds nothing to what it measures. Safe for
// concurrent use: concurrent searches sample from their own goroutines.

package sidecartest

import (
	"errors"
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

// The admission of the engine searches at once run on, which their sampler holds through each collection
// (sidecar.SearchTestDevice's).
type SearchHeapSlots interface {
	// Holds every free slot, so no search is admitted to an open or a page until release gives them back, and answers
	// how many searches hold one meanwhile.
	HoldSearchSlots() (holderCount int, release func())
}

// A search's heap from its start, or the heap of searches at once on one engine from theirs.
type SearchHeapSampler struct {
	// bytes in the heap that stand for storage, which a sample leaves out: a cache kept in memory for its disk
	stored func() int64
	// for searches at once, the engine's slots; nil for one search, which samples on its own goroutine
	slots SearchHeapSlots
	// why CheckWithin cannot answer for this sampler, whatever it sampled: empty when it can
	refusal string

	stateLock        sync.Mutex
	startByteCount   int64
	startStoredCount int64
	peak             SearchHeapSample
	sampleCount      int
	// searches at once: those parked at a sample, those of them inside a page holding a slot, where the latest parked,
	// and the collection the parked wait for
	parkedCount       int
	parkedHolderCount int
	parkedLabel       string
	collection        *searchHeapCollection
}

// One collection searches at once wait for: closed once taken, with its growth.
type searchHeapCollection struct {
	done            chan struct{}
	growthByteCount int64
}

func newSearchHeapCollection() *searchHeapCollection {
	return &searchHeapCollection{done: make(chan struct{})}
}

// A sampler of one search, which samples on its own goroutine, whose start is the live heap now.
func NewSearchHeapSampler() *SearchHeapSampler {
	return NewSearchHeapSamplerLeavingOut(nil)
}

// A sampler of one search whose start is the live heap now, leaving out what stored reports at each sample over its
// value at the start: the bytes a cache kept in memory holds for what a device keeps on disk. nil leaves out nothing.
func NewSearchHeapSamplerLeavingOut(stored func() int64) *SearchHeapSampler {
	return newSearchHeapSampler(stored, nil, "")
}

// A sampler of searches at once on the engine slots admits to, each sampling on its own goroutine and calling
// SearchEnded when it ends, whose start is the live heap now: begin it before any of them starts. stored as
// NewSearchHeapSamplerLeavingOut takes it. A sampler given no slots refuses its check.
func NewSearchHeapSamplerOfSearches(stored func() int64, slots SearchHeapSlots) *SearchHeapSampler {
	if slots == nil {
		return newSearchHeapSampler(stored, nil, "a sampler of searches at once was given no engine slots to hold")
	}
	return newSearchHeapSampler(stored, slots, "")
}

func newSearchHeapSampler(stored func() int64, slots SearchHeapSlots, refusal string) *SearchHeapSampler {
	if refusal == "" && !InSearchHeapProcess() {
		refusal = "the heap was sampled in a process the test binary's other tests share, where whatever they left " +
			"running counts as the search's: run the test through RunSearchHeapProcess"
	}
	sampler := &SearchHeapSampler{stored: stored, slots: slots, refusal: refusal, collection: newSearchHeapCollection()}
	if stored != nil {
		sampler.startStoredCount = stored()
	}
	sampler.startByteCount = SearchHeapByteCount()
	return sampler
}

// Samples the live heap at label, from a search holding no slot of the engine's there (between its pages, or before its
// first), and answers its growth over the start, less what storage took. Of searches at once, the caller waits for a
// collection with every search that holds a slot parked at a sample of its own, and answers that collection's growth.
func (self *SearchHeapSampler) Sample(label string) int64 {
	return self.sample(label, false)
}

// Sample from a search inside a page, holding one of the engine's slots there: at a record it opens.
func (self *SearchHeapSampler) SampleHoldingSlot(label string) int64 {
	return self.sample(label, true)
}

func (self *SearchHeapSampler) sample(label string, holdingSlot bool) int64 {
	if self.slots == nil {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.collectWithLock(label)
	}
	collection := func() *searchHeapCollection {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.parkedCount += 1
		if holdingSlot {
			self.parkedHolderCount += 1
		}
		self.parkedLabel = label
		collection := self.collection
		self.collectIfStillWithLock()
		return collection
	}()
	<-collection.done
	// a search the collection let go comes back through the lock, which the next collection holds, so it starts no work
	// through one before it counts itself unparked
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.parkedCount -= 1
	if holdingSlot {
		self.parkedHolderCount -= 1
	}
	return collection.growthByteCount
}

// Tells a sampler of searches at once that one of its searches ended, holding no slot and sampling no more, so the
// searches parked may be collected for. A search that ends between samples, as one whose page fails does, would
// otherwise leave them waiting.
func (self *SearchHeapSampler) SearchEnded() {
	if self.slots == nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.collectIfStillWithLock()
}

// Of searches at once: collects for every search parked once no search holding a slot is at work, the free slots held
// through the collection so none is admitted meanwhile. A search parked inside a page holds its slot, so the slots'
// holders are all parked exactly when no more of them are than parked holders. A search the last collection let go
// still counts as parked until it comes back through the lock, which this holds, so it is still.
func (self *SearchHeapSampler) collectIfStillWithLock() {
	if self.parkedCount == 0 {
		return
	}
	holderCount, release := self.slots.HoldSearchSlots()
	defer release()
	if self.parkedHolderCount < holderCount {
		return
	}
	collection := self.collection
	collection.growthByteCount = self.collectWithLock(self.parkedLabel)
	self.collection = newSearchHeapCollection()
	close(collection.done)
}

// A forced collection now, kept as a sample at label: its growth over the start, less what storage took.
func (self *SearchHeapSampler) collectWithLock(label string) int64 {
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

// How many samples were taken: a check that took none measured nothing. Searches at once parked together share one.
func (self *SearchHeapSampler) SampleCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sampleCount
}

// What CheckWithin answers for a sampler that cannot answer for the searches' heap alone, as one begun outside a
// search heap process.
var ErrSearchHeapRefused = errors.New("search heap check refused")

// nil when every sample stayed within budgetByteCount of the start and at least one was taken; else what passed it, or
// ErrSearchHeapRefused where the sampler cannot answer.
func (self *SearchHeapSampler) CheckWithin(what string, budgetByteCount int64) error {
	if self.refusal != "" {
		return fmt.Errorf("%s: %w: %s", what, ErrSearchHeapRefused, self.refusal)
	}
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
