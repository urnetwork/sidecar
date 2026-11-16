// smtpSendLog (D-SMTP-10, §2.8 smtp-3; SMTP-M9-13): each ended connection's send record, written through
// InsertSends in batches off the connection path. A connection adds its record and goes on, never waiting on
// Postgres (I-12): a goroutine flushes SendBatchCount records at a time, at once when a batch is full and else
// each SendBatchInterval. A batch that fails stays at the front and is sent again, which InsertSends' key makes
// safe; past SendLogMaxCount waiting records the oldest is dropped and counted, so a store that stays down
// costs records, never memory. Close flushes once more, bounded by StoreTimeout.
//
// A record holds smtp-3's fields and no more (records.go): the MX's name and never its IP, no recipient, no
// session ciphertext, no record length, no SHTS. Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"sync"

	"github.com/urnetwork/sidecar"
)

// How a batch went, a metric's result.
const (
	smtpSendLogWritten = "written"
	smtpSendLogFailed  = "failed"
	smtpSendLogDropped = "dropped"
)

type smtpSendLog struct {
	ctx      context.Context
	cancel   context.CancelFunc
	store    SmtpEdgeStore
	settings *SmtpEdgeSettings
	clock    sidecar.Clock
	// records by how their batch went
	records sidecar.MetricsCounter
	// closed once run has returned
	released chan struct{}
	// a batch is full
	wake chan struct{}

	stateLock sync.Mutex
	pending   []*SmtpSendRecord
}

// A log writing to store until Close. metrics names its family.
func newSmtpSendLog(ctx context.Context, store SmtpEdgeStore, settings *SmtpEdgeSettings, clock sidecar.Clock, metrics sidecar.Metrics) *smtpSendLog {
	logCtx, cancel := context.WithCancel(ctx)
	self := &smtpSendLog{
		ctx:      logCtx,
		cancel:   cancel,
		store:    store,
		settings: settings,
		clock:    clock,
		records:  metrics.Counter("urnetwork_smtpedge_send_records_total", "Send records, by how their batch went.", "result"),
		released: make(chan struct{}),
		wake:     make(chan struct{}, 1),
	}
	go self.run()
	return self
}

// Adds a record, with no wait.
func (self *smtpSendLog) add(record *SmtpSendRecord) {
	full := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.settings.SendLogMaxCount <= len(self.pending) {
			self.pending = self.pending[1:]
			self.records.Add(1, smtpSendLogDropped)
		}
		self.pending = append(self.pending, record)
		return self.settings.SendBatchCount <= len(self.pending)
	}()
	if full {
		select {
		case self.wake <- struct{}{}:
		default:
		}
	}
}

// Flushes each SendBatchInterval, or at once on a full batch, until Close.
func (self *smtpSendLog) run() {
	defer close(self.released)
	for {
		timer := self.clock.After(self.settings.SendBatchInterval)
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-timer:
		}
		for self.flushBatch(self.ctx) {
		}
	}
}

// Writes one batch from the front. Whether a full batch was written, so another may follow at once.
func (self *smtpSendLog) flushBatch(ctx context.Context) bool {
	batch := func() []*SmtpSendRecord {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		count := min(len(self.pending), self.settings.SendBatchCount)
		return append([]*SmtpSendRecord(nil), self.pending[:count]...)
	}()
	if len(batch) == 0 {
		return false
	}
	err := func() error {
		callCtx, cancel := context.WithCancel(ctx)
		stop := self.clock.AfterFunc(self.settings.StoreTimeout, cancel)
		defer func() {
			stop()
			cancel()
		}()
		testHookBarrier("smtpedge.send_log.before", "")
		defer testHookBarrier("smtpedge.send_log.after", "")
		return self.store.InsertSends(callCtx, batch)
	}()
	if err != nil {
		// the batch stays at the front, for the next tick
		self.records.Add(float64(len(batch)), smtpSendLogFailed)
		return false
	}
	self.records.Add(float64(len(batch)), smtpSendLogWritten)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// what add dropped meanwhile came off the front, so the batch is whatever of it is still there
		written := 0
		for written < len(batch) && written < len(self.pending) && self.pending[written] == batch[written] {
			written += 1
		}
		self.pending = self.pending[written:]
	}()
	return len(batch) == self.settings.SendBatchCount
}

// How many records wait.
func (self *smtpSendLog) pendingCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.pending)
}

// Ends the loop and flushes what waits, each batch bounded by StoreTimeout. What a store that does not answer
// leaves is dropped and counted.
func (self *smtpSendLog) close() {
	self.cancel()
	<-self.released
	ctx := context.WithoutCancel(self.ctx)
	for self.flushBatch(ctx) {
	}
	// a partial batch is the last one; one that did not answer leaves its records here
	self.flushBatch(ctx)
	if 0 < self.pendingCount() {
		dropped := func() int {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			dropped := len(self.pending)
			self.pending = nil
			return dropped
		}()
		if 0 < dropped {
			self.records.Add(float64(dropped), smtpSendLogDropped)
		}
	}
}
