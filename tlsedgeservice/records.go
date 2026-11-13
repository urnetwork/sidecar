// tls-3's connection records (§13.9, §2.8): one for each connection that reached a listener, holding the
// network, the published host, the connection id its TlsEdgeOpen carried, its start and end, its bytes
// and the keyed hash of the visitor's /24 or /48. No address, name or port of the visitor is in one
// (I-13), and a connection that reached no listener leaves none, so a scan costs no row.
//
// A connection hands its record over as it ends, without waiting (Add), and a goroutine of the engine's
// writes what waits each RecordFlushInterval, a batch per write, so no connection ever waits on Postgres
// (I-12). The queue is bounded: past RecordQueueCount a new record is dropped and counted, so a store
// that lags costs records and never a connection. A failed write leaves its batch at the front for the
// next flush, which the table's primary key makes safe to repeat. Drain and Close write once more after
// the last connection ended.

package tlsedgeservice

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// No store was given, so nothing can be written and records stay queued.
var errTlsRecordsNoStore = errors.New("tlsedge has no store for its connection records")

// The queue and its writer. Safe for concurrent use: Add from any connection's goroutine, run from the
// engine's, and flush from one goroutine at a time.
type tlsConnectionRecords struct {
	store    TlsEdgeStore
	settings *TlsEdgeSettings
	clock    sidecar.Clock
	metrics  *tlsEdgeMetrics
	// Waits armed: one before the first flush, then one after each, each counted once armed, so a test
	// can see a flush land and move a fake clock past the next wait.
	flushCount *sidecar.MonitorValue[uint64]

	// one flush at a time, so the front a write took is still the front when it lands
	flushLock sync.Mutex

	stateLock sync.Mutex
	pending   []*TlsConnectionRecord
}

func newTlsConnectionRecords(store TlsEdgeStore, settings *TlsEdgeSettings, clock sidecar.Clock, metrics *tlsEdgeMetrics) *tlsConnectionRecords {
	return &tlsConnectionRecords{
		store:      store,
		settings:   settings,
		clock:      clock,
		metrics:    metrics,
		flushCount: sidecar.NewMonitorValue(uint64(0)),
	}
}

// Queues a connection's record and returns at once, whether it was kept: one past RecordQueueCount is
// dropped and counted.
func (self *tlsConnectionRecords) Add(record *TlsConnectionRecord) bool {
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.settings.RecordQueueCount <= len(self.pending) {
			return false
		}
		self.pending = append(self.pending, record)
		return true
	}()
	if !kept {
		self.metrics.records.Add(1, tlsRecordResultDropped)
	}
	return kept
}

// How many records wait.
func (self *tlsConnectionRecords) PendingCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.pending)
}

// Writes what waits, a batch at a time, until nothing waits or a write fails, which leaves its batch at
// the front. Each write is bounded by RecordWriteTimeout on the engine's clock.
func (self *tlsConnectionRecords) flush(ctx context.Context) error {
	self.flushLock.Lock()
	defer self.flushLock.Unlock()
	for {
		batch := func() []*TlsConnectionRecord {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return slices.Clone(self.pending[:min(len(self.pending), self.settings.RecordBatchCount)])
		}()
		if len(batch) == 0 {
			return nil
		}
		if self.store == nil {
			return errTlsRecordsNoStore
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
			self.metrics.recordFlushes.Add(1, tlsRecordFlushResultFailed)
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.pending = slices.Delete(self.pending, 0, len(batch))
		}()
		self.metrics.records.Add(float64(len(batch)), tlsRecordResultWritten)
		self.metrics.recordFlushes.Add(1, tlsRecordFlushResultWritten)
	}
}

// Flushes after each RecordFlushInterval until ctx ends.
func (self *tlsConnectionRecords) run(ctx context.Context) {
	for {
		// armed before the pass is counted, so a wait that sees the count can move the clock past it
		next := self.clock.After(self.settings.RecordFlushInterval)
		self.flushCount.Update(func(count uint64) uint64 { return count + 1 })
		select {
		case <-ctx.Done():
			return
		case <-next:
		}
		self.flush(ctx)
	}
}

// A record's times, whole to the microsecond a timestamp column keeps.
func tlsRecordTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}
