// The writer's push loop, on every leg: each log's journaled entries wait in a queue until a batch is due, then go to
// evs as one planned push to this sidecar's own stream, or one deposit, retried until it commits (§16.8's storage row,
// RECORD.md sections 5.3 and 5.4).
//
//	stream push   up to PushEntryCount entries, at most 64, or PushCoalesce of them, in one part with one slot object
//	              of their keys, 64 to a slot object, so a full object of 104 B rows stays inside 8 KiB; entries ordered
//	              by (writer, seq), each at its stream path, the stream's counter from 1 (record_route.go)
//	deposit       up to 64 entries or DepositByteCount, or DepositInterval of them, an entry past the bytes alone in a
//	              batch of its own (record_deposit.go); an approval-family entry or a run's coverage sends at once
//
// One plan is outstanding a log, so a writer's chain reaches evs in seq order, which a reader of its stream relies on
// and AdoptStream reads back. A plan is journaled (record_slot.go) before it first goes, so a retry after a kill is the
// same statement: the same push id, slot id, paths, rows and entry bytes, and evs answers it with the commit it made or
// the refusal it recorded (I-EVS-3). An outcome evs could not give, or a code that refuses nothing (128 and up), sends
// the same plan again after a backoff. A refusal that spends the push id (1 to 127) drops the plan and its entries wait
// for a new one, with a new push id, slot id and key indexes, and the same signed bytes: key_slot_id and key_index lie
// outside the signed header, so nothing is signed again (D-MCP-10, §16.8). A refusal of the paths (REF_MODE,
// PATH_CONFLICT) re-reads the stream's counter first. A commit acknowledges the chain's journal records, writes the
// stream's counter and drops the plan, in that order, so a kill between leaves a plan whose retry answers the commit
// again, or one naming a seq already acknowledged, which reads as committed.
//
// Before signing a fresh direct entry on a binding, the writer reconciles the verified stream with its local head
// and replays pending work. Captures spool during startup. A deposit-only writer never reads the stream (§5.3).
//
// DESIGN-COMPUTE §24.5's session entries (CTXH-M11-02): a riding entry starts no batch of its own: it waits until an
// ordinary entry's batch is due, a turn's end releases it, or the ride interval passes, and goes in seq order with
// what it waits beside, so a header never waits behind a later entry. A body-apart entry's body rides in the push
// that carries its header, at s/<n>, the n of its e/<n>, unless its log's bodies are held: then the header goes alone,
// the plan says so, and once the push commits the body waits in bodies/<log_id>/<n>, before the journal record that
// held it is acknowledged; a later push of the log the hold no longer stops carries waiting bodies beside its entries,
// and the files go once that push is settled. A deposit carries every entry whole, so a depositor holds no body.
//
// Barriers: record.push.before and record.push.after around each send, keyed by the log, with no lock held.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One log's entries on their way to evs. Fields are the writer's stateLock's.
type recordLogQueue struct {
	logId Id
	// this writer's sealed entries waiting for a plan, by seq
	waitingSeqEntries map[uint64]*RecordSealedEntry
	// ingested entries waiting for a plan (RECORD-M3-04), in the order ingested
	waitingIngested []*recordIngestedEntry
	// when the oldest waiting entry was queued, Unix milliseconds
	firstWaitingMillis int64
	// the waiting seqs that ride (DESIGN-COMPUTE §24.5), and when the oldest of them was queued
	ridingSeqs        map[uint64]bool
	firstRidingMillis int64
	// the newest seq of an entry that sends at once: a batch is due while a seq at or below it waits
	flushThroughSeq uint64
	// the plan outstanding, nil for none
	plan *recordPushPlan
	// the plan's own entries by seq, with their keys
	planSeqEntries map[uint64]*RecordSealedEntry
	attemptCount   int
	// no attempt before this, Unix milliseconds
	nextAttemptMillis int64
	// the stream's newest counter, once read
	counter       uint64
	counterLoaded bool
}

// The queue of logId, made on first use.
func (self *recordWriter) queueWithLock(logId Id) *recordLogQueue {
	queue, ok := self.logQueues[logId]
	if !ok {
		queue = &recordLogQueue{
			logId:             logId,
			waitingSeqEntries: map[uint64]*RecordSealedEntry{},
			planSeqEntries:    map[uint64]*RecordSealedEntry{},
			ridingSeqs:        map[uint64]bool{},
		}
		self.logQueues[logId] = queue
	}
	return queue
}

// Whether the queue holds anything a plan has not taken.
func (self *recordLogQueue) waitingWithLock() bool {
	return 0 < len(self.waitingSeqEntries) || 0 < len(self.waitingIngested)
}

// How many waiting entries do not ride: the ones that make a batch due by count or time.
func (self *recordLogQueue) ordinaryWaitingWithLock() int {
	riding := 0
	for seq := range self.ridingSeqs {
		if _, ok := self.waitingSeqEntries[seq]; ok {
			riding += 1
		}
	}
	return len(self.waitingSeqEntries) - riding + len(self.waitingIngested)
}

// Forgets the riding seqs no longer waiting, and the riding wait once none is.
func (self *recordLogQueue) pruneRidingWithLock() {
	for seq := range self.ridingSeqs {
		if _, ok := self.waitingSeqEntries[seq]; !ok {
			delete(self.ridingSeqs, seq)
		}
	}
	if len(self.ridingSeqs) == 0 {
		self.firstRidingMillis = 0
	}
}

// Whether an entry that sends at once is waiting.
func (self *recordLogQueue) flushWaitingWithLock() bool {
	for seq := range self.waitingSeqEntries {
		if seq <= self.flushThroughSeq {
			return true
		}
	}
	return false
}

// The bytes the waiting entries take, as a deposit batch would carry them.
func (self *recordLogQueue) waitingByteCountWithLock() int {
	byteCount := 0
	for _, entry := range self.waitingSeqEntries {
		byteCount += len(entry.Signed) + len(entry.SealedBody) + RecordSlotRowByteCount
	}
	return byteCount
}

// Takes a journaled plan back after a restart: its own entries leave the waiting set for the plan. False when a seq
// it names is journaled no longer, which only a commit acknowledges: then its other seqs leave the waiting set too,
// for the caller to acknowledge.
func (self *recordLogQueue) adoptPlanWithLock(plan *recordPushPlan) bool {
	seqs := plan.ownSeqs()
	committed := slices.ContainsFunc(seqs, func(seq uint64) bool {
		_, ok := self.waitingSeqEntries[seq]
		return !ok
	})
	if committed {
		for _, seq := range seqs {
			delete(self.waitingSeqEntries, seq)
		}
		return false
	}
	for _, seq := range seqs {
		self.planSeqEntries[seq] = self.waitingSeqEntries[seq]
		delete(self.waitingSeqEntries, seq)
	}
	self.plan = plan
	return true
}

// Puts a sealed entry on its log's queue and wakes the loop, which sends a due batch or arms the queue's timer: a
// body-apart kind's rides (DESIGN-COMPUTE §24.5).
func (self *recordWriter) enqueue(route *recordRoute, sealed *RecordSealedEntry, kind RecordKind) {
	self.enqueueRiding(route, sealed, kind, kind.BodyApart())
}

// enqueue, a riding entry waiting for a batch an ordinary one makes due, ReleaseRides, or the ride interval.
func (self *recordWriter) enqueueRiding(route *recordRoute, sealed *RecordSealedEntry, kind RecordKind, rides bool) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(route.logId)
		nowMillis := self.clock.Now().UnixMilli()
		queue.pruneRidingWithLock()
		if rides {
			if len(queue.ridingSeqs) == 0 {
				queue.firstRidingMillis = nowMillis
			}
			queue.ridingSeqs[sealed.Seq] = true
		} else if queue.ordinaryWaitingWithLock() == 0 {
			queue.firstWaitingMillis = nowMillis
		}
		queue.waitingSeqEntries[sealed.Seq] = sealed
		if recordKindSendsAtOnce(kind) {
			queue.flushThroughSeq = max(queue.flushThroughSeq, sealed.Seq)
		}
	}()
	self.signal()
}

// Section 5.3's deposits row: the approval family goes at once, and so does a run's end, which its coverage marks.
func recordKindSendsAtOnce(kind RecordKind) bool {
	switch kind {
	case RecordKindApproval, RecordKindApprovalDecision, RecordKindApprovalCancel, RecordKindApprovalUse, RecordKindCoverage:
		return true
	}
	return false
}

// The entries a stream push carries at most.
func recordPushEntryCount(settings *SidecarRecordSettings) int {
	return min(settings.PushEntryCount, DefaultEvsFormatSettings().SlotMaxKeyCount)
}

// How this sidecar reaches logId now, by the state's rights: its own stream as a consented writer of a vault, or as a
// writer of a team log, which has no owner to consent; else deposits. False when it may do neither, and its entries
// wait.
func recordLogMode(auth RecordAuthView, sidecarId Id, logId Id) (bool, bool) {
	if recordIsTeamLog(auth, logId) {
		if auth.Writes(logId, sidecarId) {
			return false, true
		}
		if auth.Deposits(logId, sidecarId) && !auth.ReceiptOnly(logId, sidecarId) {
			return true, true
		}
		return false, false
	}
	if auth.Consented(logId, sidecarId) && auth.Writes(logId, sidecarId) {
		return false, true
	}
	if auth.Deposits(logId, sidecarId) && !auth.ReceiptOnly(logId, sidecarId) {
		return true, true
	}
	return false, false
}

// Whether a batch is due: full, past its interval, or holding an entry that sends at once; a riding entry by the ride
// interval alone, or as any where none is set.
func (self *recordWriter) dueWithLock(queue *recordLogQueue, deposit bool, nowMillis int64, force bool) bool {
	if !queue.waitingWithLock() {
		return false
	}
	if force || queue.flushWaitingWithLock() {
		return true
	}
	queue.pruneRidingWithLock()
	if 0 < len(queue.ridingSeqs) {
		ridden := time.Duration(nowMillis-queue.firstRidingMillis) * time.Millisecond
		if 0 < self.rideInterval && self.rideInterval <= ridden {
			return true
		}
		if self.rideInterval <= 0 && queue.ordinaryWaitingWithLock() == 0 {
			// no ride interval: a riding entry goes as any
			return self.ordinaryDueWithLock(queue, deposit, len(queue.waitingSeqEntries), ridden)
		}
	}
	ordinary := queue.ordinaryWaitingWithLock()
	if ordinary == 0 {
		return false
	}
	waited := time.Duration(nowMillis-queue.firstWaitingMillis) * time.Millisecond
	return self.ordinaryDueWithLock(queue, deposit, ordinary, waited)
}

// Whether count ordinary entries, the oldest waiting waited, make a batch due.
func (self *recordWriter) ordinaryDueWithLock(queue *recordLogQueue, deposit bool, count int, waited time.Duration) bool {
	if deposit {
		return recordDepositEntryCount <= count || self.settings.DepositByteCount <= queue.waitingByteCountWithLock() ||
			self.settings.DepositInterval <= waited
	}
	return recordPushEntryCount(self.settings) <= count || self.settings.PushCoalesce <= waited
}

// The logs with a queue, in id order, so a pump visits them alike every time.
func (self *recordWriter) queueLogIds() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	logIds := make([]Id, 0, len(self.logQueues))
	for logId := range self.logQueues {
		logIds = append(logIds, logId)
	}
	slices.SortFunc(logIds, func(a Id, b Id) int { return a.Cmp(b) })
	return logIds
}

// Carries journaled entries to evs until ctx ends, calling tend, when given, at each pass before it pumps. See the
// file's header. No pass starts once ctx has ended, a wake taken as it ended included, so nothing is tended, drained
// from the spool or planned past the end, and an ended ctx asks the clock for nothing.
func (self *recordWriter) run(ctx context.Context, tend func(ctx context.Context)) {
	self.runLock.Lock()
	defer self.runLock.Unlock()
	// select takes either of its ready cases at random: a wake taken as ctx ended reads as the end
	for ctx.Err() == nil {
		if tend != nil {
			tend(ctx)
		}
		if self.backlogged() && self.drainDue() {
			if err := self.drainSpool(ctx); err != nil && self.log.V(1).Enabled() {
				self.log.Infof("[record]the spool is not drained: %s", err)
			}
		}
		if err := self.pump(ctx, false); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[record]a push did not commit: %s", err)
		}
		if ctx.Err() != nil {
			// a writer that ended as the pass ran asks the clock for nothing
			return
		}
		stop := func() bool { return false }
		if wakeAt, ok := self.nextWake(); ok {
			// for that time itself (QD-1425); signal never blocks, so a time already reached may signal here
			stop = ClockAfterFuncAt(self.clock, wakeAt, self.signal)
		}
		select {
		case <-ctx.Done():
		case <-self.wake:
		}
		stop()
	}
}

// When a queue is due or a retry may go, false when nothing waits.
func (self *recordWriter) nextWake() (time.Time, bool) {
	auth := self.auth()
	nowMillis := self.clock.Now().UnixMilli()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var next int64
	found := false
	consider := func(atMillis int64) {
		if !found || atMillis < next {
			next = atMillis
			found = true
		}
	}
	for _, queue := range self.logQueues {
		switch {
		case queue.plan != nil:
			consider(queue.nextAttemptMillis)
		case queue.waitingWithLock():
			deposit, ok := recordLogMode(auth, self.sidecarId, queue.logId)
			interval := self.settings.PushCoalesce
			if deposit || !ok {
				interval = self.settings.DepositInterval
			}
			queue.pruneRidingWithLock()
			at := int64(-1)
			if 0 < queue.ordinaryWaitingWithLock() {
				at = queue.firstWaitingMillis + interval.Milliseconds()
			}
			if 0 < len(queue.ridingSeqs) {
				rideAt := queue.firstRidingMillis + interval.Milliseconds()
				if 0 < self.rideInterval {
					rideAt = queue.firstRidingMillis + self.rideInterval.Milliseconds()
				}
				if at < 0 || rideAt < at {
					at = rideAt
				}
			}
			if queue.flushWaitingWithLock() {
				at = nowMillis
			}
			consider(max(at, queue.nextAttemptMillis))
		}
	}
	if self.spoolBacklog && 0 < self.drainRetryMillis {
		consider(self.drainRetryMillis)
	}
	if !found {
		return time.Time{}, false
	}
	return time.UnixMilli(next), true
}

// Pushes and deposits everything due, or everything queued when force, ignoring backoff then; the first failure.
func (self *recordWriter) Flush(ctx context.Context) error {
	if err := self.pump(ctx, true); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, queue := range self.logQueues {
		if queue.plan != nil || queue.waitingWithLock() {
			return fmt.Errorf("record: log %s still has entries to send", queue.logId)
		}
	}
	return nil
}

// One pass over every queue: each due log sends plans until one fails or nothing is due.
func (self *recordWriter) pump(ctx context.Context, force bool) error {
	self.pumpLock.Lock()
	defer self.pumpLock.Unlock()
	if err := self.load(); err != nil {
		return err
	}
	errs := []error{}
	for _, logId := range self.queueLogIds() {
		if deposit, ok := recordLogMode(self.auth(), self.sidecarId, logId); ok && !deposit {
			if err := self.adopt(ctx, logId); err != nil {
				self.backoff(logId)
				errs = append(errs, err)
				continue
			}
		}
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			progressed, err := self.pumpLog(ctx, logId, force)
			if err != nil {
				errs = append(errs, err)
				break
			}
			if !progressed {
				break
			}
		}
	}
	return errors.Join(errs...)
}

// Sends logId's plan, building one when a batch is due: true once a plan committed.
func (self *recordWriter) pumpLog(ctx context.Context, logId Id, force bool) (bool, error) {
	auth := self.auth()
	deposit, ok := recordLogMode(auth, self.sidecarId, logId)
	nowMillis := self.clock.Now().UnixMilli()
	plan, waiting := func() (*recordPushPlan, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(logId)
		if !force && nowMillis < queue.nextAttemptMillis {
			return nil, false
		}
		if queue.plan != nil {
			return queue.plan, false
		}
		return nil, self.dueWithLock(queue, deposit, nowMillis, force)
	}()
	if plan == nil {
		if !waiting {
			return false, nil
		}
		if !ok {
			// waits, backing off, so the loop does not wake for it at once again
			self.backoff(logId)
			return false, fmt.Errorf("record: log %s takes neither this sidecar's stream nor its deposits now", logId)
		}

		built, err := self.buildPlan(ctx, auth, logId, deposit)
		if err != nil {
			self.backoff(logId)
			return false, err
		}
		if built == nil {
			// what waits cannot go this way now, such as ingested entries once this device only deposits
			self.backoff(logId)
			return false, nil
		}
		plan = built
	}
	commit, err := self.send(ctx, plan)
	if err != nil {
		self.refused(plan, err)
		return false, err
	}
	if err := self.committed(plan, commit); err != nil {
		return false, err
	}
	return true, nil
}

// Reconciles the verified stream head and resends all already signed work before enabling fresh signatures. The
// caller holds pumpLock. Read the stream before replay so a restored older batch cannot obscure its higher head.
func (self *recordWriter) adopt(ctx context.Context, logId Id) error {
	if func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.adoptedLogs[logId]
	}() {
		return nil
	}
	read, err := self.chain.readWriterStream(ctx, self.boundStreams(), logId, self.identityPublicKey)
	raised := false
	if err == nil && read.head != nil {
		raised, err = func() (bool, error) {
			self.sealLock.Lock()
			defer self.sealLock.Unlock()
			if err := self.finishCaptureWithLock(); err != nil {
				return false, err
			}
			return self.chain.Adopt(logId, *read.head)
		}()
		if err == nil {
			err = self.settleRestoredEntries(ctx, logId, read.head.Seq)
		}
	}
	if errors.Is(err, ErrRecordChainForked) {
		// A conflicting head stops fresh signatures and replay on this binding.
		self.log.Warningf("[record]this writer's chain in log %s forks its stream's", logId)
		self.raise(SidecarRecordAlarmChainFork, logId, &self.sidecarId)
	}
	if err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(logId)
		queue.counter = max(queue.counter, read.counter)
		queue.counterLoaded = true
	}()
	if raised {
		self.log.Warningf("[record]log %s's stream is ahead of this writer's journal; the chain continues from it", logId)
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		progress, err := self.pumpLog(ctx, logId, true)
		if err != nil {
			return err
		}
		if !progress {
			break
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.adoptedLogs[logId] = true
	return nil
}

// Schedules the next attempt at logId: PushCoalesce, doubling to DepositInterval (their comments).
func (self *recordWriter) backoff(logId Id) {
	nowMillis := self.clock.Now().UnixMilli()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	queue := self.queueWithLock(logId)
	queue.attemptCount += 1
	delay := self.settings.PushCoalesce
	for i := 1; i < queue.attemptCount && delay < self.settings.DepositInterval; i += 1 {
		delay *= 2
	}
	delay = min(delay, self.settings.DepositInterval)
	queue.nextAttemptMillis = nowMillis + delay.Milliseconds()
}

// Sends a plan as its push or deposit, between record.push's barriers.
func (self *recordWriter) send(ctx context.Context, plan *recordPushPlan) (*RecordStreamCommit, error) {
	streams := self.boundStreams()
	hookKey := recordChainIdText(plan.LogId)
	if plan.Deposit {
		deposit, err := self.depositOf(plan)
		if err != nil {
			return nil, err
		}
		testHookBarrier("record.push.before", hookKey)
		commit, err := streams.Deposit(ctx, plan.LogId, deposit)
		testHookBarrier("record.push.after", hookKey)
		return commit, err
	}
	push, err := self.pushOf(plan)
	if err != nil {
		return nil, err
	}
	testHookBarrier("record.push.before", hookKey)
	commit, err := streams.Append(ctx, plan.LogId, push)
	testHookBarrier("record.push.after", hookKey)
	return commit, err
}

// The push a stream plan sends: the same bytes on every attempt.
func (self *recordWriter) pushOf(plan *recordPushPlan) (*RecordStreamPush, error) {
	entries := func() map[uint64]*RecordSealedEntry {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.queueWithLock(plan.LogId).planSeqEntries
	}()
	push := &RecordStreamPush{
		PushId:          plan.PushId,
		WriterSidecarId: self.sidecarId,
		SlotId:          plan.SlotId,
		AuthPin:         plan.authPin(),
	}
	for _, planEntry := range plan.Entries {
		var row []byte
		var entryBytes []byte
		if planEntry.Ingested != nil && planEntry.BodyPath != "" {
			// DESIGN-COMPUTE §24.5: a deposited session entry, whole in its deposit, filed apart here as its
			// writer would have
			apart, body, err := recordEntrySplitApart(planEntry.Ingested.Entry, &plan.SlotId, planEntry.KeyIndex)
			if err != nil {
				return nil, err
			}
			joined, err := RecordSlotRowJoin(planEntry.Ingested.Key, planEntry.Ingested.Salt)
			if err != nil {
				return nil, err
			}
			entryBytes = apart
			row = joined
			push.Bodies = append(push.Bodies, &RecordStreamBody{Path: planEntry.BodyPath, Body: body})
		} else if planEntry.Ingested != nil {
			reslotted, err := recordEntryReslot(planEntry.Ingested.Entry, &plan.SlotId, planEntry.KeyIndex)
			if err != nil {
				return nil, err
			}
			joined, err := RecordSlotRowJoin(planEntry.Ingested.Key, planEntry.Ingested.Salt)
			if err != nil {
				return nil, err
			}
			entryBytes = reslotted
			row = joined
		} else {
			sealed := entries[planEntry.Seq]
			if sealed == nil {
				return nil, fmt.Errorf("%w: plan of log %s names seq %d, which it does not hold", ErrRecordChainCorrupt, plan.LogId, planEntry.Seq)
			}
			entryBytes = sealed.EntryBytes(&plan.SlotId, planEntry.KeyIndex)
			row = sealed.SlotRow(planEntry.KeyIndex).Row
			if planEntry.BodyPath != "" {
				push.Bodies = append(push.Bodies, &RecordStreamBody{Path: planEntry.BodyPath, Body: sealed.BodyBytes()})
			}
		}
		push.SlotRows = append(push.SlotRows, &RecordSlotRow{KeyIndex: planEntry.KeyIndex, Row: row})
		push.Entries = append(push.Entries, &RecordStreamEntry{Path: planEntry.Path, Entry: entryBytes})
	}
	for _, planBody := range plan.Bodies {
		held, err := self.readHeldBody(plan.LogId, planBody.Counter)
		if err != nil {
			return nil, err
		}
		push.Bodies = append(push.Bodies, &RecordStreamBody{Path: planBody.Path, Body: held.SealedBody})
	}
	slices.SortFunc(push.SlotRows, func(a *RecordSlotRow, b *RecordSlotRow) int {
		return cmp.Compare(a.KeyIndex, b.KeyIndex)
	})
	return push, nil
}

// What evs answered instead of a commit: the same plan again later, or, for a refusal that spends the push id, its
// entries back to wait for a new plan.
func (self *recordWriter) refused(plan *recordPushPlan, err error) {
	code, refusal := RecordStreamRefusalCode(err)
	if !refusal || EvsRefusalRefusesNothing(code) {
		self.backoff(plan.LogId)
		return
	}
	self.log.Warningf("[record]log %s refused a push: %s", plan.LogId, err)
	if removeErr := self.store.Remove(recordPlanName(plan.LogId)); removeErr != nil {
		// the plan stays journaled and goes again, to the same refusal, until its file goes
		self.backoff(plan.LogId)
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(plan.LogId)
		for seq, entry := range queue.planSeqEntries {
			queue.waitingSeqEntries[seq] = entry
		}
		queue.planSeqEntries = map[uint64]*RecordSealedEntry{}
		ingested := []*recordIngestedEntry{}
		for _, planEntry := range plan.Entries {
			if planEntry.Ingested == nil {
				continue
			}
			if waiting, ok := planEntry.Ingested.entry(); ok {
				ingested = append(ingested, waiting)
			}
		}
		queue.waitingIngested = append(ingested, queue.waitingIngested...)
		queue.plan = nil
		if code == protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE || code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT {
			queue.counterLoaded = false
		}
	}()
	self.backoff(plan.LogId)
}

// A plan committed: the chain's records acknowledged, the counter written, the plan dropped, then the hooks.
func (self *recordWriter) committed(plan *recordPushPlan, commit *RecordStreamCommit) error {
	if plan.Deposit {
		// kept before the plan is acknowledged, so a failure sends the plan again, to the same commit (D-MCP-10)
		if err := self.keepDeposit(plan, commit); err != nil {
			self.backoff(plan.LogId)
			return err
		}
	}
	if err := self.finishCommittedPlan(plan); err != nil {
		return err
	}
	if self.log.V(2).Enabled() {
		self.log.Infof("[record]log %s took %d entries at version %d", plan.LogId, len(plan.Entries), commit.Version)
	}
	return nil
}

// Hands a committed deposit to the depositor's keeper (record_mirror.go): the batch as it went, kept until an
// ingester's mark passes it. No keeper keeps nothing.
func (self *recordWriter) keepDeposit(plan *recordPushPlan, commit *RecordStreamCommit) error {
	keeper := func() func(logId Id, commit *RecordStreamCommit, batch []byte) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.depositKeeper
	}()
	if keeper == nil {
		return nil
	}
	deposit, err := self.depositOf(plan)
	if err != nil {
		return err
	}
	// the batch holds its entries' keys and salts
	defer clear(deposit.Batch)
	return keeper(plan.LogId, commit, deposit.Batch)
}

// Settles a committed plan: the journal acknowledged, the counter raised, the plan file removed, the queue cleared and
// the hooks called. A kill anywhere here leaves a plan that reads committed or retries to the same commit.
func (self *recordWriter) finishCommittedPlan(plan *recordPushPlan) error {
	if !plan.Deposit {
		if err := self.writeCounter(plan.LogId, plan.lastCounter()); err != nil {
			return err
		}
	}
	// a held body waits in the body store before the journal record holding it goes
	if err := self.storeHeldBodies(plan); err != nil {
		return err
	}
	if err := self.chain.Acknowledge(plan.LogId, plan.ownSeqs()); err != nil {
		return err
	}
	for _, planBody := range plan.Bodies {
		if err := self.store.Remove(recordHeldBodyName(plan.LogId, planBody.Counter)); err != nil {
			return fmt.Errorf("record: a held body: %w", err)
		}
	}
	if err := self.store.Remove(recordPlanName(plan.LogId)); err != nil {
		return fmt.Errorf("record: plan: %w", err)
	}
	hooks := func() []func(logId Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(plan.LogId)
		if !plan.Deposit {
			queue.counter = max(queue.counter, plan.lastCounter())
		}
		if queue.plan == plan {
			for _, entry := range queue.planSeqEntries {
				entry.Clear()
			}
			queue.planSeqEntries = map[uint64]*RecordSealedEntry{}
			queue.plan = nil
		}
		queue.attemptCount = 0
		queue.nextAttemptMillis = 0
		return slices.Clone(self.commitHooks)
	}()
	for _, hook := range hooks {
		hook(plan.LogId)
	}
	return nil
}

// The pin a plan declares.
func (self *recordPushPlan) authPin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: self.PinVersion, Chain: bytes.Clone(self.PinChain)}
}

// The writer's held bodies (DESIGN-COMPUTE §24.5, §24.10): bodies/<log_id>/<counter>, one a session entry's sealed body
// whose header went ahead while its log's bodies were held, in the record component's sealed directory. A body is
// written before the journal record that held it is acknowledged, and removed once a push that carried it is settled,
// so a kill anywhere loses none and sends one at most once more, as the same statement.
const (
	recordHeldBodyDirectory = "bodies"
	recordHeldBodyVersion   = 1
)

// One held body's document.
type recordHeldBody struct {
	Version int `json:"version"`
	LogId   Id  `json:"log_id"`
	// its entry's seq in this writer's chain, and its stream counter, the n of its header's e/<n> and its s/<n>
	Seq        uint64 `json:"seq"`
	Counter    uint64 `json:"counter"`
	SealedBody []byte `json:"sealed_body"`
	// its entry's run, which a drop past the spool's budget names in that run's coverage (DESIGN-COMPUTE §24.10); empty
	// from a body held before it was kept
	RunId []byte `json:"run_id,omitempty"`
}

// A held body's file name: its counter in 20 decimal digits, so a listing sorts by counter.
func recordHeldBodyName(logId Id, counter uint64) string {
	return fmt.Sprintf("%s/%s/%0*d", recordHeldBodyDirectory, recordChainIdText(logId), recordChainSeqDigitCount, counter)
}

// The held body at counter, refusing one that does not decode or is not where its name says.
func (self *recordWriter) readHeldBody(logId Id, counter uint64) (*recordHeldBody, error) {
	content, err := self.chain.readFile(recordHeldBodyName(logId, counter))
	if err != nil {
		return nil, err
	}
	if content == nil {
		return nil, fmt.Errorf("%w: held body %d of log %s is gone", ErrRecordChainCorrupt, counter, logId)
	}
	held := &recordHeldBody{}
	if err := recordChainDecode(content, held); err != nil || held.Version != recordHeldBodyVersion || held.LogId != logId || held.Counter != counter {
		return nil, fmt.Errorf("%w: held body %d of log %s", ErrRecordChainCorrupt, counter, logId)
	}
	return held, nil
}

// Every body of logId the writer holds, by counter.
func (self *recordWriter) heldBodies(logId Id) ([]*recordHeldBody, error) {
	entries, err := self.store.List(recordHeldBodyDirectory + "/" + recordChainIdText(logId) + "/")
	if err != nil {
		return nil, err
	}
	held := []*recordHeldBody{}
	for _, entry := range entries {
		name := entry.Name[strings.LastIndexByte(entry.Name, '/')+1:]
		counter, err := strconv.ParseUint(name, 10, 64)
		if err != nil || recordHeldBodyName(logId, counter) != entry.Name {
			return nil, fmt.Errorf("%w: a held body named %q", ErrRecordChainCorrupt, entry.Name)
		}
		body, err := self.readHeldBody(logId, counter)
		if err != nil {
			return nil, err
		}
		held = append(held, body)
	}
	slices.SortFunc(held, func(a *recordHeldBody, b *recordHeldBody) int { return cmp.Compare(a.Counter, b.Counter) })
	return held, nil
}

// Writes the bodies plan held back, from the journal records that still hold them: what a commit does before it
// acknowledges them. A record already acknowledged wrote its body before.
func (self *recordWriter) storeHeldBodies(plan *recordPushPlan) error {
	if plan.Deposit {
		return nil
	}
	entries := func() map[uint64]*RecordSealedEntry {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return maps.Clone(self.queueWithLock(plan.LogId).planSeqEntries)
	}()
	for _, planEntry := range plan.Entries {
		if !planEntry.BodyHeld || planEntry.Ingested != nil {
			continue
		}
		sealed := entries[planEntry.Seq]
		if sealed == nil {
			continue
		}
		held := &recordHeldBody{
			Version: recordHeldBodyVersion, LogId: plan.LogId, Seq: planEntry.Seq, Counter: planEntry.Counter, SealedBody: sealed.BodyBytes(),
		}
		if header, err := sealed.Header(); err == nil {
			held.RunId = header.Header.GetRunId()
		}
		content, err := json.Marshal(held)
		if err != nil {
			return err
		}
		if err := self.chain.writeFile(recordHeldBodyName(plan.LogId, planEntry.Counter), content); err != nil {
			return fmt.Errorf("record: a held body: %w", err)
		}
	}
	return nil
}

// Drops the held bodies of logId at seqs, answering the seqs dropped, ascending. A body a plan carries now stays.
func (self *recordWriter) dropHeldBodies(logId Id, seqs []uint64) ([]uint64, error) {
	self.pumpLock.Lock()
	defer self.pumpLock.Unlock()
	held, err := self.heldBodies(logId)
	if err != nil {
		return nil, err
	}
	carried := func() map[uint64]bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		carried := map[uint64]bool{}
		if plan := self.queueWithLock(logId).plan; plan != nil {
			for _, planBody := range plan.Bodies {
				carried[planBody.Counter] = true
			}
		}
		return carried
	}()
	dropped := []uint64{}
	for _, body := range held {
		if !slices.Contains(seqs, body.Seq) || carried[body.Counter] {
			continue
		}
		if err := self.store.Remove(recordHeldBodyName(logId, body.Counter)); err != nil {
			return dropped, fmt.Errorf("record: a held body: %w", err)
		}
		dropped = append(dropped, body.Seq)
	}
	slices.Sort(dropped)
	return dropped, nil
}
