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
// Before a log's first stream push in this process the writer adopts the newest entry of its chain in its own stream
// (RecordChainStore.AdoptStream). Sealing does not wait for that: an entry sealed before it, on a device restored from
// an old backup, forks the chain, which readers alarm on (section 5.3's restart row).
//
// Barriers: record.push.before and record.push.after around each send, keyed by the log, with no lock held.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §11.8's slot bound: the rows one slot object holds, which a push of one part carries at most.
const recordSlotRowCount = 64

// One log's entries on their way to evs. Fields are the writer's stateLock's.
type recordLogQueue struct {
	logId Id
	// this writer's sealed entries waiting for a plan, by seq
	waitingSeqEntries map[uint64]*RecordSealedEntry
	// ingested entries waiting for a plan (RECORD-M3-04), in the order ingested
	waitingIngested []*recordIngestedEntry
	// when the oldest waiting entry was queued, Unix milliseconds
	firstWaitingMillis int64
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
		}
		self.logQueues[logId] = queue
	}
	return queue
}

// Whether the queue holds anything a plan has not taken.
func (self *recordLogQueue) waitingWithLock() bool {
	return 0 < len(self.waitingSeqEntries) || 0 < len(self.waitingIngested)
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

// Puts a sealed entry on its log's queue and wakes the loop, which sends a due batch or arms the queue's timer.
func (self *recordWriter) enqueue(route *recordRoute, sealed *RecordSealedEntry, kind RecordKind) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(route.logId)
		if !queue.waitingWithLock() {
			queue.firstWaitingMillis = self.clock.Now().UnixMilli()
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
	return min(settings.PushEntryCount, recordSlotRowCount)
}

// How this sidecar reaches logId now, by the state's rights: its own stream as a consented writer, else deposits.
// False when it may do neither, and its entries wait.
func recordLogMode(auth RecordAuthView, sidecarId Id, logId Id) (bool, bool) {
	if auth.Consented(logId, sidecarId) && auth.Writes(logId, sidecarId) {
		return false, true
	}
	if auth.Deposits(logId, sidecarId) && !auth.ReceiptOnly(logId, sidecarId) {
		return true, true
	}
	return false, false
}

// Whether a batch is due: full, past its interval, or holding an entry that sends at once.
func (self *recordWriter) dueWithLock(queue *recordLogQueue, deposit bool, nowMillis int64, force bool) bool {
	if !queue.waitingWithLock() {
		return false
	}
	if force || queue.flushWaitingWithLock() {
		return true
	}
	count := len(queue.waitingSeqEntries) + len(queue.waitingIngested)
	waited := time.Duration(nowMillis-queue.firstWaitingMillis) * time.Millisecond
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
// file's header.
func (self *recordWriter) run(ctx context.Context, tend func(ctx context.Context)) {
	self.runLock.Lock()
	defer self.runLock.Unlock()
	for {
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
		stop := func() bool { return false }
		if timeout, ok := self.nextWake(); ok {
			stop = self.clock.AfterFunc(timeout, self.signal)
		}
		select {
		case <-ctx.Done():
			stop()
			return
		case <-self.wake:
		}
		stop()
	}
}

// How long until a queue is due or a retry may go, false when nothing waits.
func (self *recordWriter) nextWake() (time.Duration, bool) {
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
			at := queue.firstWaitingMillis + interval.Milliseconds()
			if queue.flushWaitingWithLock() {
				at = nowMillis
			}
			consider(max(at, queue.nextAttemptMillis))
		}
	}
	if !found {
		return 0, false
	}
	return max(0, time.Duration(next-nowMillis)*time.Millisecond), true
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
		if !deposit {
			if err := self.adopt(ctx, logId); err != nil {
				self.backoff(logId)
				return false, err
			}
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

// Adopts the newest entry of this writer's chain in its own stream, once a process, before its first push there.
func (self *recordWriter) adopt(ctx context.Context, logId Id) error {
	if func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.adoptedLogs[logId]
	}() {
		return nil
	}
	raised, err := self.chain.AdoptStream(ctx, self.boundStreams(), logId, self.identityPublicKey)
	if errors.Is(err, ErrRecordChainForked) {
		// a pending entry at the stream's head seq with another leaf: readers alarm on what goes out
		self.log.Warningf("[record]this writer's chain in log %s forks its stream's", logId)
		self.raise(SidecarRecordAlarmChainFork, logId, &self.sidecarId)
		err = nil
	}
	if err != nil {
		return err
	}
	if raised {
		self.log.Warningf("[record]log %s's stream is ahead of this writer's journal; the chain continues from it", logId)
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
		if planEntry.Ingested != nil {
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
		}
		push.SlotRows = append(push.SlotRows, &RecordSlotRow{KeyIndex: planEntry.KeyIndex, Row: row})
		push.Entries = append(push.Entries, &RecordStreamEntry{Path: planEntry.Path, Entry: entryBytes})
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
	if err := self.finishCommittedPlan(plan); err != nil {
		return err
	}
	if self.log.V(2).Enabled() {
		self.log.Infof("[record]log %s took %d entries at version %d", plan.LogId, len(plan.Entries), commit.Version)
	}
	return nil
}

// Settles a committed plan: the journal acknowledged, the counter raised, the plan file removed, the queue cleared and
// the hooks called. A kill anywhere here leaves a plan that reads committed or retries to the same commit.
func (self *recordWriter) finishCommittedPlan(plan *recordPushPlan) error {
	if !plan.Deposit {
		if err := self.writeCounter(plan.LogId, plan.lastCounter()); err != nil {
			return err
		}
	}
	if err := self.chain.Acknowledge(plan.LogId, plan.ownSeqs()); err != nil {
		return err
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
