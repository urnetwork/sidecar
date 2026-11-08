// mx-2's session records (§15.4, §15.15; MAIL-M7-21): one for each router session whose SNI named a
// network, holding that network, the session's start, its bytes and its result, and nothing of the
// sender. A session that named no network leaves none (plan-MAIL-small-readings #3), so a scan or an
// unknown name costs no row and counts only in urnetwork_mxedge_*.
//
// A session hands its record over without waiting (Add), and a goroutine of the engine's writes what
// waits each RecordFlushInterval, one batch per write, so no session ever waits on Postgres (I-12).
// The queue is bounded: past RecordQueueCount a new record is dropped and counted, so a store that lags
// costs memory up to that bound and records past it, never a session. A failed write leaves its batch
// at the front for the next flush. A write that failed only on its answer may then store its rows twice,
// so a count read off the table is an upper bound. The engine writes once more after its last session
// ends, so a close loses only what its store will not take.

package mxedgeservice

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// How a session record went.
const (
	// The store took it.
	mxRecordResultWritten = "written"
	// The queue was full, so it never waited.
	mxRecordResultDropped = "dropped"
)

// How a flush went.
const (
	mxRecordFlushResultWritten = "written"
	mxRecordFlushResultFailed  = "failed"
)

// No store was given, so nothing can be written and records stay queued.
var errMxRecordsNoStore = errors.New("mxedge has no store for its session records")

// The queue and its writer. Safe for concurrent use: Add from any session's goroutine, run from the
// engine's, and flush from one goroutine at a time, which the engine keeps.
type mxConnectionRecords struct {
	store    MxEdgeStore
	settings *MxEdgeSettings
	clock    sidecar.Clock
	metrics  *mxMetrics
	log      sidecar.Logger
	// Waits armed: one before the first flush, then one after each, each counted once armed, so a test
	// can see a flush land and move a fake clock past the next wait.
	flushCount *sidecar.MonitorValue[int]
	// Closed once run has returned.
	done chan struct{}

	stateLock sync.Mutex
	pending   []*MxConnectionRecord
}

func newMxConnectionRecords(store MxEdgeStore, settings *MxEdgeSettings, clock sidecar.Clock, metrics *mxMetrics, log sidecar.Logger) *mxConnectionRecords {
	return &mxConnectionRecords{
		store:      store,
		settings:   settings,
		clock:      clock,
		metrics:    metrics,
		log:        log,
		flushCount: sidecar.NewMonitorValue(0),
		done:       make(chan struct{}),
	}
}

// Queues a session's record and returns at once, whether it was kept. A record naming no network is
// none (reading 3), and one past RecordQueueCount is dropped and counted.
func (self *mxConnectionRecords) Add(record *MxConnectionRecord) bool {
	if record == nil || record.NetworkId == (sidecar.Id{}) {
		return false
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.settings.RecordQueueCount <= len(self.pending) {
			return false
		}
		copied := *record
		self.pending = append(self.pending, &copied)
		return true
	}()
	if !kept {
		self.metrics.records.Add(1, mxRecordResultDropped)
	}
	return kept
}

// How many records wait.
func (self *mxConnectionRecords) PendingCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.pending)
}

// Writes what waits, a batch at a time, until nothing waits or a write fails, which leaves its batch at
// the front. Each write is bounded by RecordWriteTimeout on the engine's clock. Only one flush runs at a
// time, so the front a write took is still the front when it lands.
func (self *mxConnectionRecords) flush(ctx context.Context) error {
	for {
		batch := func() []*MxConnectionRecord {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return slices.Clone(self.pending[:min(len(self.pending), self.settings.RecordBatchCount)])
		}()
		if len(batch) == 0 {
			return nil
		}
		if self.store == nil {
			return errMxRecordsNoStore
		}
		err := func() error {
			writeCtx, cancel := context.WithCancel(ctx)
			stop := self.clock.AfterFunc(self.settings.RecordWriteTimeout, cancel)
			defer func() {
				stop()
				cancel()
			}()
			return self.store.InsertConnectionRecords(writeCtx, batch)
		}()
		if err != nil {
			self.metrics.recordFlushes.Add(1, mxRecordFlushResultFailed)
			// the error may carry a statement, so only the fact is logged
			self.log.Info("[mxedge]a session record batch was not written; it waits for the next flush")
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.pending = slices.Delete(self.pending, 0, len(batch))
		}()
		self.metrics.records.Add(float64(len(batch)), mxRecordResultWritten)
		self.metrics.recordFlushes.Add(1, mxRecordFlushResultWritten)
	}
}

// Arms the first wait, then flushes after each on a goroutine of its own until ctx ends, closing done.
// The first wait is armed before this returns, so an engine's timers stand still once it is built. The
// engine flushes once more after its sessions have ended (Close).
func (self *mxConnectionRecords) start(ctx context.Context) {
	flushTimer := self.clock.After(self.settings.RecordFlushInterval)
	self.flushCount.Update(func(count int) int { return count + 1 })
	go self.run(ctx, flushTimer)
}

func (self *mxConnectionRecords) run(ctx context.Context, flushTimer <-chan time.Time) {
	defer close(self.done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-flushTimer:
		}
		self.flush(ctx)
		flushTimer = self.clock.After(self.settings.RecordFlushInterval)
		self.flushCount.Update(func(count int) int { return count + 1 })
	}
}
