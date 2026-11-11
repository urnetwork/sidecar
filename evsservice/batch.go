// Group commit (§11.8's batches, D-EVS-30): each evs process holds one open batch per metadata cluster, for repos
// placed there, and a request's record joins it at step 6 (a part or seal at its own step) and waits for that
// batch's write. The batch is pb/<yyyymmddhh>/<mm>/<instance>-<seq>, the root's EvsBatchWriter's bytes.
//
//   - flush: a batch is written when it reaches 256 KiB, when its oldest record has waited BatchFlushDelay (20 ms),
//     or at once when nothing is in flight on its cluster and the process took fewer than
//     BatchLightLoadRecordCount (50) records there in the last BatchLightLoadWindow (1 s); at most
//     BatchWriteInFlightCount (2) writes are in flight per cluster, a due batch staying open, still taking
//     records, until a slot frees; a record over 256 KiB is a batch alone, up to 1 MiB;
//   - write: PUT If-None-Match with its SHA-256 as x-amz-checksum-sha256, through sidecar.PutImmutable: a 412 reads
//     the key back, equal bytes success and other bytes a fault that alarms; an unknown outcome GETs the key, equal
//     bytes written and a 404 written again with the same bytes; with the store unreachable every waiter gets the
//     error, which it answers 503, since nothing it carried reached a head;
//   - bind: a record counts only at the place its version's window entry names, so a second copy of a push (a retry
//     on another process, a part posted twice) is dead weight evacuation drops (§11.13). Nothing here deletes.
//
// The key's minute is the UTC minute the batch opened, never below one this process already used, so a clock that
// steps back cannot make a key repeat; seq counts within that minute across the process's clusters. instance is
// the process's random 32-bit id.
//
// A batch opens only while this process's clock is sure (§19.6's clocks row, DESIGN-DETAILS 2.2.3's minute rule), and
// Append answers ErrEvsClockUnsure otherwise, which its caller answers 503 as it does any unwritten batch. So a
// batch's key names a minute that began no later than 50 ms past the time each of its records joined it, which is
// what lets evacuation's oldest batch stand as a horizon for segment GC (§11.13): every record that could adopt a
// segment is in a batch whose minute began before the segment's LastModified + 24 h + 2 min. A record may join a
// batch that opened while the clock was sure, since its minute was fixed then.
//
// A batch's write is paid for: each record's admission (AdmitP1, or a P0 issue) counted its batch share (§11.13's
// push row), so the write runs under the class the opening record's ctx carries, past that request's own end and
// within the engine's. Safe for concurrent use; no lock is held across a write or a barrier.

package evsservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The batch holding a record was not written: the store did not take it or answered nothing that says it did.
	// The waiter answers 503, retryable, since nothing its request carried reached a head.
	ErrEvsBatchUnwritten = errors.New("evs batch not written")
	// The engine closed before the batch was written.
	ErrEvsBatchClosed = errors.New("evs batch writer closed")
)

// One batch, open or on its way to the store.
type pendingBatch struct {
	clusterId string
	minute    uint32
	seq       uint32
	writer    *sidecar.EvsBatchWriter
	// the ctx of the record that opened it, whose class pays the write
	openerCtx context.Context
	places    []*protocol.EvsPlace
	due       bool
	stopTimer func() bool
	// closed once written or failed, with err set first
	done chan struct{}
	err  error
}

// One cluster's batches.
type batchClusterState struct {
	open *pendingBatch
	// closed batches waiting for a write slot, oldest first
	ready         []*pendingBatch
	inFlightCount int
	// the times of the last BatchLightLoadRecordCount records taken, oldest first
	appendTimes []time.Time
}

// See the file header.
type BatchWriter struct {
	ctx   context.Context
	clock sidecar.Clock
	// nil reads as unsure, so no batch opens
	clockCheck sidecar.ClockCheck
	blobs      sidecar.BlobStore
	records    *RecordCache
	settings   *EvsSettings
	log        sidecar.Logger
	instance   uint32

	stateLock     sync.Mutex
	minute        uint32
	nextSeq       uint32
	clusterStates map[string]*batchClusterState
	writeCount    int
	// records that have joined a batch, for a test to wait on before it moves a clock
	appendedCount *sidecar.MonitorValue[int]
}

// A writer for one process, until ctx ends. clockCheck says whether clock is sure: a batch opens only while it is,
// and a nil one opens none. blobs is the engine's, metadata writes held to the budget. records may be nil, keeping
// nothing.
func NewBatchWriter(ctx context.Context, clock sidecar.Clock, clockCheck sidecar.ClockCheck, blobs sidecar.BlobStore, records *RecordCache, settings *EvsSettings, log sidecar.Logger) *BatchWriter {
	instanceBytes := make([]byte, 4)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	rand.Read(instanceBytes)
	return &BatchWriter{
		ctx:           ctx,
		clock:         clock,
		clockCheck:    clockCheck,
		blobs:         blobs,
		records:       records,
		settings:      settings,
		log:           log,
		instance:      binary.BigEndian.Uint32(instanceBytes),
		clusterStates: map[string]*batchClusterState{},
		appendedCount: sidecar.NewMonitorValue(0),
	}
}

// How many records have joined a batch, and a channel that closes at the next.
func (self *BatchWriter) Appended() (int, chan struct{}) {
	return self.appendedCount.Get()
}

// The process's random 32-bit id, every one of its batch keys carrying it.
func (self *BatchWriter) Instance() uint32 {
	return self.instance
}

// How many batch writes have started, for tests.
func (self *BatchWriter) WriteCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.writeCount
}

// Adds record to clusterId's open batch and waits for that batch's write: its place, or the write's error, which
// the caller answers 503. ctx must carry the class the budget passed the record's request under; a ctx that never
// spent is ErrWriteUnbudgeted. A record no batch can hold, past 1 MiB with its framing, is sidecar.ErrEvsPushInvalid.
// A record that would open a batch while this process's clock is unsure is ErrEvsClockUnsure, and joins nothing.
func (self *BatchWriter) Append(ctx context.Context, clusterId string, record *sidecar.EvsBatchRecord) (*protocol.EvsPlace, error) {
	if _, ok := sidecar.WriteClassOf(ctx); !ok {
		return nil, ErrWriteUnbudgeted
	}
	if !sidecar.NewEvsBatchWriter(0, 0, 0, 0).Fits(len(record.Body)) {
		return nil, fmt.Errorf("%w: a record of %d body bytes", sidecar.ErrEvsPushInvalid, len(record.Body))
	}
	if record.Type < protocol.EvsBatchRecordType_EVS_BATCH_PUSH || protocol.EvsBatchRecordType_EVS_BATCH_RESEED < record.Type {
		return nil, fmt.Errorf("%w: record type %d", sidecar.ErrEvsPushInvalid, record.Type)
	}
	var batch *pendingBatch
	var place *protocol.EvsPlace
	var started []*pendingBatch
	var addErr error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.clusterStateWithLock(clusterId)
		now := self.clock.Now()
		light := self.noteAppendWithLock(state, now)
		if state.open != nil && !state.open.writer.Fits(len(record.Body)) {
			self.closeOpenWithLock(state)
		}
		if state.open == nil {
			if self.clockCheck == nil || !self.clockCheck.Sure() {
				// the batch just closed, if one was, still goes to the store
				addErr = ErrEvsClockUnsure
				started = self.startWritesWithLock(state)
				return
			}
			state.open = self.openWithLock(ctx, state, clusterId, now)
		}
		batch = state.open
		place, addErr = batch.writer.Add(record)
		if addErr != nil {
			return
		}
		batch.places = append(batch.places, place)
		switch {
		case sidecar.EvsBatchMaxByteCount <= batch.writer.ByteCount():
			// full: a record over 256 KiB alone, or one more record would not fit
			self.closeOpenWithLock(state)
		case state.inFlightCount == 0 && light:
			batch.due = true
		}
		started = self.startWritesWithLock(state)
	}()
	for _, startedBatch := range started {
		go self.write(startedBatch)
	}
	if addErr != nil {
		return nil, addErr
	}
	self.appendedCount.Update(func(count int) int { return count + 1 })
	select {
	case <-batch.done:
		if batch.err != nil {
			return nil, batch.err
		}
		return place, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-self.ctx.Done():
		return nil, ErrEvsBatchClosed
	}
}

// The cluster's state, made on first use.
func (self *BatchWriter) clusterStateWithLock(clusterId string) *batchClusterState {
	state, ok := self.clusterStates[clusterId]
	if !ok {
		state = &batchClusterState{}
		self.clusterStates[clusterId] = state
	}
	return state
}

// Counts one record taken at now, and whether the cluster is lightly loaded: fewer than BatchLightLoadRecordCount
// records, this one included, in the last BatchLightLoadWindow.
func (self *BatchWriter) noteAppendWithLock(state *batchClusterState, now time.Time) bool {
	limit := self.settings.BatchLightLoadRecordCount
	if limit <= 0 {
		return false
	}
	state.appendTimes = append(state.appendTimes, now)
	if limit < len(state.appendTimes) {
		state.appendTimes = state.appendTimes[len(state.appendTimes)-limit:]
	}
	return len(state.appendTimes) < limit || !state.appendTimes[0].After(now.Add(-self.settings.BatchLightLoadWindow))
}

// A new open batch for the cluster, its key's minute and seq drawn, its flush timer armed.
func (self *BatchWriter) openWithLock(ctx context.Context, state *batchClusterState, clusterId string, now time.Time) *pendingBatch {
	minute := max(BatchMinute(now), self.minute)
	if minute != self.minute {
		self.minute = minute
		self.nextSeq = 0
	}
	seq := self.nextSeq
	self.nextSeq += 1
	batch := &pendingBatch{
		clusterId: clusterId,
		minute:    minute,
		seq:       seq,
		writer:    sidecar.NewEvsBatchWriter(self.instance, minute, seq, now.UnixMilli()),
		openerCtx: ctx,
		done:      make(chan struct{}),
		stopTimer: func() bool { return false },
	}
	if self.settings.BatchFlushDelay <= 0 {
		batch.due = true
		return batch
	}
	batch.stopTimer = self.clock.AfterFunc(self.settings.BatchFlushDelay, func() {
		var started []*pendingBatch
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			batch.due = true
			started = self.startWritesWithLock(state)
		}()
		for _, startedBatch := range started {
			go self.write(startedBatch)
		}
	})
	return batch
}

// Closes the open batch: it takes no more records and waits for a write slot.
func (self *BatchWriter) closeOpenWithLock(state *batchClusterState) {
	if state.open == nil {
		return
	}
	state.open.stopTimer()
	state.open.due = true
	state.ready = append(state.ready, state.open)
	state.open = nil
}

// The batches to write now, each counted in flight: closed ones first, then the open one if it is due.
func (self *BatchWriter) startWritesWithLock(state *batchClusterState) []*pendingBatch {
	started := []*pendingBatch{}
	for state.inFlightCount < self.settings.BatchWriteInFlightCount {
		switch {
		case 0 < len(state.ready):
			started = append(started, state.ready[0])
			state.ready = state.ready[1:]
		case state.open != nil && state.open.due:
			state.open.stopTimer()
			started = append(started, state.open)
			state.open = nil
		default:
			return started
		}
		state.inFlightCount += 1
		self.writeCount += 1
	}
	return started
}

// Writes one batch and answers its waiters, then starts what its slot lets go.
func (self *BatchWriter) write(batch *pendingBatch) {
	err := self.put(batch)
	if err != nil {
		batch.err = fmt.Errorf("%w: %w", ErrEvsBatchUnwritten, err)
	}
	// The slot is freed before the waiters hear: a waiter that appends again at once must see no write in flight,
	// or its batch, not marked due, waits a window for a slot that is already free.
	var started []*pendingBatch
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.clusterStateWithLock(batch.clusterId)
		state.inFlightCount -= 1
		started = self.startWritesWithLock(state)
	}()
	close(batch.done)
	for _, startedBatch := range started {
		go self.write(startedBatch)
	}
}

// The batch's PUT, and on success its records into the process's cache.
func (self *BatchWriter) put(batch *pendingBatch) error {
	batchBytes, err := batch.writer.Bytes()
	if err != nil {
		return err
	}
	cluster, err := self.blobs.Cluster(batch.clusterId)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(batchBytes)
	// the opening record's class, past its request's end and within the engine's
	writeCtx, cancel := context.WithCancel(context.WithoutCancel(batch.openerCtx))
	defer cancel()
	stop := context.AfterFunc(self.ctx, cancel)
	defer stop()
	barrierKey := barrierBatchKey(batch.minute, self.instance, batch.seq)
	testHookBarrier(BarrierBatchPutBefore, barrierKey)
	_, err = sidecar.PutImmutable(writeCtx, cluster, BatchKey(batch.minute, self.instance, batch.seq), batchBytes,
		&sidecar.BlobPutOptions{Sha256: digest[:]})
	testHookBarrier(BarrierBatchPutAfter, barrierKey)
	if errors.Is(err, sidecar.ErrBlobImmutableMismatch) {
		self.log.Errorf("[evs] alarm batch_mismatch: batch %s on cluster %s holds other bytes", barrierKey, batch.clusterId)
	}
	if err != nil {
		return err
	}
	if self.records != nil {
		for _, place := range batch.places {
			// a copy, so a cached record pins its own bytes and not its whole batch's, which the cache's bound
			// would not count
			self.records.Put(batch.clusterId, place, bytes.Clone(batchBytes[place.GetOffset():place.GetOffset()+place.GetLength()]))
		}
	}
	return nil
}
