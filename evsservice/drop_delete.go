// The drop job's deletes (§11.13's delete, young, holds and clock rows; D-EVS-63, D-EVS-65, D-OPS-21, I-EVS-15, FI-5,
// FI-13, FI-27, FS-90, FS-92, FS-96; DESIGN-DETAILS 10.2.8's F7 to F9; owner decision 184; EVSB-M10-06): D, the round's
// unmarked candidates not yet answered for good, in cand order from the job's cursor, each judged and deleted.
//
//	F0     before each DELETE: ClockCheck.Sure(); SettlePassed on the repo's metadata cluster and on the segment
//	       cluster; format2.drop on (observe deletes nothing, and the job never asks then); repo/ active (cached at
//	       most 5 s); the lease more than LeaseMargin away, renewed by a checkpoint when it is not. Any false: nothing
//	       more is issued, and the ids left are unanswered
//	F8     per id, hold/ and repo/ reread, each cached at most 5 s: a covering hold, or one whose terms no reader
//	       can tell, moves the rest of D to held, each still stored counted at its stored size; nothing a hold keeps
//	       is deleted, and a DELETE already issued completes
//	HEAD   seg/<repo>/<id> on the segment cluster, slot/<repo>/<id> on the metadata cluster: a segment's 404 with a
//	       page in spidx/ is packed (withheld until a compaction, unscheduled), any other 404 absent
//	F7     LastModified + AdoptionBound past the round's horizon: young, for a later round whose scans read only
//	       versions after this one's (owner decision 203's rule, QD-703)
//	F9     else DELETE naming that LastModified (x-ur-if-unmodified-ms) and carrying the lease's deadline less
//	       DeadlineMargin, cancelled the moment the clock turns unsure: 204 deleted; 412 replaced, the id stored
//	       again since the HEAD and no longer this drop's, never retried, but for a slot, which an ERASE rewrites
//	       in place, read again once; a held key or an unknown outcome leaves the id unanswered
//	pace   at most DeletesPerSecond DELETEs, and HEADs of held ids, in each second of the clock
//
// The cursor passes only answered ids: it stops before the first unanswered one, and ids answered after it carry
// their del rows, so a run that resumes skips those answered for good. Each checkpoint, at most once a
// CheckpointInterval and at the end, writes the del rows and held ids since the last, then the job's cursor by CAS,
// then the stored-byte delta as a usage batch whose id is the job's and the cursor range's (§20.6, producer
// taskworker): each seg/ object's stored size once, when it is deleted or moves to held, a held object's later
// DELETE reporting nothing, and slots, outside the stored count, nothing. A batch whose report fails is not retried:
// under-billing, never double-billing.
//
// Safe for concurrent use: each call holds its own state.

package evsservice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §19.8's drop deletion series, none with a network or repo label.
const (
	dropDeletesMetricName    = "urnetwork_evs_drop_deletes_total"
	dropFreedBytesMetricName = "urnetwork_evs_drop_freed_bytes_total"
)

// What the deletes run on beyond their host.
type DropDeleteDeps struct {
	// §19.11's drop mode. nil reads observe, under which nothing is deleted.
	Format2 Format2Gate
	// The holds each id rereads. nil reads hold/ through a HoldCache of its own.
	Holds *HoldCache
	// nil: the defaults.
	Settings    *DropSettings
	EvsSettings *EvsSettings
	// What a run did. nil discards.
	Log sidecar.Logger
}

// See the file header.
type DropDelete struct {
	host     *sidecar.ServiceHost
	settings *DropSettings
	clock    sidecar.Clock
	repos    *RepoCache
	holds    *HoldCache
	format2  Format2Gate
	log      sidecar.Logger

	deletes sidecar.MetricsCounter
	freed   sidecar.MetricsCounter
}

// The deletes on host, which needs Blobs.
func NewDropDelete(host *sidecar.ServiceHost, deps *DropDeleteDeps) (*DropDelete, error) {
	if host == nil || host.Blobs == nil {
		return nil, errors.New("evs's drop deletes need a host with Blobs")
	}
	if deps == nil {
		deps = &DropDeleteDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultDropSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	evsSettings := deps.EvsSettings
	if evsSettings == nil {
		evsSettings = DefaultEvsSettings()
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	clock := host.ClockOrReal()
	holds := deps.Holds
	if holds == nil {
		holds = NewHoldCache(host.Blobs, clock, nil)
	}
	format2 := deps.Format2
	if format2 == nil {
		format2 = ClosedFormat2Gate{}
	}
	self := &DropDelete{
		host: host, settings: settings, clock: clock, repos: NewRepoCache(clock, evsSettings), holds: holds, format2: format2, log: log,
	}
	if host.Metrics != nil {
		self.deletes = host.Metrics.Counter(dropDeletesMetricName, "Drop candidates the jobs answered, by result.", "result")
		self.freed = host.Metrics.Counter(dropFreedBytesMetricName, "Stored bytes the drop jobs' DELETEs freed.")
	}
	return self, nil
}

// The label a result counts under.
func dropDeleteResultLabel(outcome DropOutcome) string {
	switch outcome {
	case DropOutcomeDeleted:
		return "deleted"
	case DropOutcomeAbsent:
		return "absent"
	case DropOutcomePacked:
		return "packed"
	case DropOutcomeYoung:
		return "young"
	case DropOutcomeReplaced:
		return "replaced"
	case DropOutcomeHeld:
		return "held"
	}
	return "unknown"
}

// The cursor's bytes in a usage batch id: sequence u32 | row u32.
func dropCursorBytes(cursor DropCursor) []byte {
	encoded := binary.BigEndian.AppendUint32(nil, cursor.Sequence)
	return binary.BigEndian.AppendUint32(encoded, cursor.Row)
}

// One run's state.
type dropDeleteRun struct {
	deleter *DropDelete
	ctx     context.Context
	request *DropDeleteRequest
	files   *DropFiles
	result  *DropDeleteResult
	// the newest outcome of each id answered before this run, which tells a held id's later DELETE
	answered map[DropScanId]DropOutcome
	// since the last checkpoint
	answers  []*DropAnswer
	heldIds  []DropScanId
	freed    uint64
	held     uint64
	cursor   DropCursor
	reported DropCursor
	// the cursor stopped before an unanswered id
	stopped        bool
	delSequence    uint32
	heldSequence   uint32
	leaseUntil     time.Time
	lastCheckpoint time.Time
	// the pace's second and how many it spent
	paceStart time.Time
	paceCount int
	// whether spidx/ holds a page, read once a run
	spidxRead bool
	packed    bool
}

// The deletes (EVSB-M10-06): see the file header.
func (self *DropDelete) Delete(ctx context.Context, request *DropDeleteRequest) (*DropDeleteResult, error) {
	if request.Cluster == nil || request.SegmentCluster == nil || request.Checkpoint == nil {
		return nil, fmt.Errorf("%w: deletes with no clusters or checkpoint", ErrDropJobState)
	}
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.JobId, self.settings)
	answered, err := files.Answers(ctx)
	if err != nil {
		return nil, err
	}
	delSequence, err := files.NextSequence(ctx, DropFileDel)
	if err != nil {
		return nil, err
	}
	heldSequence, err := files.NextSequence(ctx, DropFileHeld)
	if err != nil {
		return nil, err
	}
	run := &dropDeleteRun{
		deleter: self, ctx: ctx, request: request, files: files, answered: answered,
		result:      &DropDeleteResult{Progress: &DropDeleteProgress{}},
		delSequence: delSequence, heldSequence: heldSequence, leaseUntil: request.LeaseUntil,
		lastCheckpoint: self.clock.Now(),
	}
	if 0 < len(request.Candidates) {
		run.cursor = request.Candidates[0].Cursor
		run.reported = run.cursor
	}
	runErr := run.run()
	if err := run.checkpoint(false); err != nil && runErr == nil {
		runErr = err
	}
	if runErr != nil {
		return nil, runErr
	}
	return run.result, nil
}

// Why nothing more may be issued now (F0), "" when the DELETE may go: the lease is renewed by a checkpoint first when
// it is under LeaseMargin away.
func (self *dropDeleteRun) gate() (string, error) {
	deleter := self.deleter
	if deleter.host.ClockCheck == nil || !deleter.host.ClockCheck.Sure() {
		return DropWaitClock, nil
	}
	if !self.request.Cluster.SettlePassed() || !self.request.SegmentCluster.SettlePassed() {
		return DropWaitSettle, nil
	}
	if deleter.format2.DropMode() != sidecar.Format2On {
		return "observe", nil
	}
	if !deleter.clock.Now().Add(self.request.LeaseMargin).Before(self.leaseUntil) {
		if err := self.checkpoint(true); err != nil {
			return "", err
		}
		if !deleter.clock.Now().Add(self.request.LeaseMargin).Before(self.leaseUntil) {
			return DropWaitLease, nil
		}
	}
	return "", nil
}

// The repo's repo/ and the holds covering it, each read at most 5 s ago (F8): the repo's object, and whether it is
// active and whether a hold covers it, one whose terms no reader can tell among them.
func (self *dropDeleteRun) cover() (active bool, held bool, err error) {
	read, err := self.deleter.repos.Read(self.ctx, self.request.Cluster, self.request.RepoId)
	if errors.Is(err, sidecar.ErrEvsRepoNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if read.Object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		return false, false, nil
	}
	cover, err := self.deleter.holds.CoveringRepo(self.ctx, self.request.RepoId, read.Object)
	if err != nil {
		return false, false, err
	}
	return true, cover.Covered(), nil
}

// Waits so at most DeletesPerSecond requests go in each second of the clock.
func (self *dropDeleteRun) pace() error {
	perSecond := max(1, self.request.DeletesPerSecond)
	now := self.deleter.clock.Now()
	if self.paceStart.IsZero() || !now.Before(self.paceStart.Add(time.Second)) {
		self.paceStart, self.paceCount = now, 0
	}
	if perSecond <= self.paceCount {
		select {
		case <-self.ctx.Done():
			return self.ctx.Err()
		case <-self.deleter.clock.After(self.paceStart.Add(time.Second).Sub(now)):
		}
		self.paceStart, self.paceCount = self.deleter.clock.Now(), 0
	}
	self.paceCount += 1
	return nil
}

// Records an answer for candidate: its del row, the cursor past it while every id before it is answered, and the
// result's count.
func (self *dropDeleteRun) answer(candidate *DropCandidate, outcome DropOutcome) {
	self.answers = append(self.answers, &DropAnswer{DropScanId: candidate.DropScanId, Outcome: outcome})
	if !self.stopped {
		self.cursor = DropCursor{Sequence: candidate.Cursor.Sequence, Row: candidate.Cursor.Row + 1}
	}
	if self.deleter.deletes != nil {
		self.deleter.deletes.Add(1, dropDeleteResultLabel(outcome))
	}
}

// Leaves candidate unanswered: the cursor stops before the first such id.
func (self *dropDeleteRun) unanswered(candidate *DropCandidate) {
	self.result.Unanswered += 1
	if !self.stopped {
		self.stopped = true
		self.cursor = candidate.Cursor
	}
}

// The key and cluster of a candidate's object.
func (self *dropDeleteRun) objectOf(candidate *DropCandidate) (sidecar.BlobCluster, string) {
	if candidate.Kind == DropIdSlot {
		return self.request.Cluster, SlotKey(self.request.RepoId, candidate.SlotId())
	}
	return self.request.SegmentCluster, SegmentKey(self.request.RepoId, candidate.Id)
}

// Whether a segment's 404 is a packed one: spidx/<repo>/ holds a page, read once a run. spidx/ stays empty in this
// build (locate_segment.go), and a page there, which this build cannot read, may hold the id, so it reads as packed.
func (self *dropDeleteRun) packedAbsent() (bool, error) {
	if !self.spidxRead {
		pages, _, err := self.request.Cluster.List(self.ctx, spidxKeyPrefix+sidecar.EvsKeyId(self.request.RepoId)+"/", "", 1)
		if err != nil {
			return false, err
		}
		self.spidxRead, self.packed = true, 0 < len(pages)
	}
	return self.packed, nil
}

// Whether err leaves an id unanswered: a held key, or an outcome the caller cannot tell.
func dropUnknownOutcome(err error) bool {
	var unknown *sidecar.BlobUnknownError
	return errors.Is(err, sidecar.ErrBlobHeld) || errors.As(err, &unknown)
}

// Every candidate of D in turn, until the gate or a hold stops it.
func (self *dropDeleteRun) run() error {
	candidates := self.request.Candidates
	for i, candidate := range candidates {
		why, err := self.gate()
		if err != nil {
			return err
		}
		if why != "" {
			for _, left := range candidates[i:] {
				self.unanswered(left)
			}
			return nil
		}
		active, held, err := self.cover()
		if err != nil {
			return err
		}
		if !active {
			for _, left := range candidates[i:] {
				self.unanswered(left)
			}
			return nil
		}
		if held {
			return self.moveToHeld(candidates[i:])
		}
		if err := self.judge(candidate); err != nil {
			return err
		}
		if self.deleter.settings.CheckpointInterval <= self.deleter.clock.Now().Sub(self.lastCheckpoint) {
			if err := self.checkpoint(true); err != nil {
				return err
			}
		}
	}
	return nil
}

// One candidate's HEAD, F7 and F9.
func (self *dropDeleteRun) judge(candidate *DropCandidate) error {
	cluster, key := self.objectOf(candidate)
	for attempt := 0; ; attempt += 1 {
		if err := self.pace(); err != nil {
			return err
		}
		info, err := cluster.Head(self.ctx, key)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
			outcome := DropOutcomeAbsent
			if candidate.Kind == DropIdSegment {
				packed, err := self.packedAbsent()
				if err != nil {
					return err
				}
				if packed {
					outcome = DropOutcomePacked
				}
			}
			self.answer(candidate, outcome)
			return nil
		case dropUnknownOutcome(err):
			self.unanswered(candidate)
			return nil
		case err != nil:
			return err
		}
		// F7: young until the round's horizon passes LastModified + the adoption bound
		bound := info.LastModified.Add(self.request.AdoptionBound)
		if self.request.Horizon.Before(bound) {
			if self.result.YoungBound.IsZero() || bound.Before(self.result.YoungBound) {
				self.result.YoungBound = bound
			}
			self.answer(candidate, DropOutcomeYoung)
			return nil
		}
		// F0 again at the DELETE: the gate held before the HEAD, and the lease may have run down since
		why, err := self.gate()
		if err != nil {
			return err
		}
		if why != "" {
			self.unanswered(candidate)
			return nil
		}
		err = self.delete(candidate, cluster, key, info.LastModified)
		switch {
		case err == nil:
			if candidate.Kind == DropIdSegment {
				size := uint64(max(0, info.ByteCount))
				if self.answered[candidate.DropScanId] != DropOutcomeHeld {
					self.freed += size
				}
				if self.deleter.freed != nil {
					self.deleter.freed.Add(float64(size))
				}
			}
			self.answer(candidate, DropOutcomeDeleted)
			return nil
		case errors.Is(err, sidecar.ErrBlobPrecondition):
			if candidate.Kind == DropIdSlot && attempt == 0 {
				// an ERASE rewrote the slot in place since the HEAD: read it again
				continue
			}
			if candidate.Kind == DropIdSlot {
				self.unanswered(candidate)
				return nil
			}
			self.answer(candidate, DropOutcomeReplaced)
			return nil
		case dropUnknownOutcome(err), errors.Is(err, context.Canceled) && self.ctx.Err() == nil:
			// a held key, an unknown outcome, or a DELETE cancelled as the clock turned unsure
			self.unanswered(candidate)
			return nil
		default:
			return err
		}
	}
}

// One DELETE naming lastModified, with the lease's deadline less DeadlineMargin, cancelled the moment the clock
// turns unsure.
func (self *dropDeleteRun) delete(candidate *DropCandidate, cluster sidecar.BlobCluster, key string, lastModified time.Time) error {
	deadline := self.leaseUntil.Add(-self.request.DeadlineMargin)
	deleteCtx, cancel := context.WithCancel(sidecar.WithBlobUnmodified(sidecar.WithBlobDeadline(self.ctx, deadline), lastModified))
	defer cancel()
	if clockCheck := self.deleter.host.ClockCheck; clockCheck != nil {
		unsure := clockCheck.UnsureChannel()
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-unsure:
				cancel()
			case <-done:
			}
		}()
	}
	barrierKey := barrierSegmentKey(self.request.RepoId, candidate.Id[:])
	if candidate.Kind == DropIdSlot {
		barrierKey = barrierSlotKey(self.request.RepoId, candidate.SlotId())
	}
	testHookBarrier(BarrierDropDeleteBefore, barrierKey)
	err := cluster.Delete(deleteCtx, key)
	testHookBarrier(BarrierDropDeleteAfter, barrierKey)
	return err
}

// The rest of D to held (owner decision 184): each id still stored is held, counted at its stored size unless an
// earlier round held it; one gone is absent.
func (self *dropDeleteRun) moveToHeld(candidates []*DropCandidate) error {
	self.result.Held = true
	for _, candidate := range candidates {
		if err := self.pace(); err != nil {
			return err
		}
		cluster, key := self.objectOf(candidate)
		info, err := cluster.Head(self.ctx, key)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
			self.answer(candidate, DropOutcomeAbsent)
			continue
		case dropUnknownOutcome(err):
			// still stored, or not: held keeps it either way, and the size goes uncounted
			self.answer(candidate, DropOutcomeHeld)
			self.heldIds = append(self.heldIds, candidate.DropScanId)
			continue
		case err != nil:
			return err
		}
		if candidate.Kind == DropIdSegment && self.answered[candidate.DropScanId] != DropOutcomeHeld {
			self.held += uint64(max(0, info.ByteCount))
		}
		self.answer(candidate, DropOutcomeHeld)
		self.heldIds = append(self.heldIds, candidate.DropScanId)
		if self.deleter.settings.CheckpointInterval <= self.deleter.clock.Now().Sub(self.lastCheckpoint) {
			if err := self.checkpoint(true); err != nil {
				return err
			}
		}
	}
	return nil
}

// Writes the del rows and held ids since the last checkpoint, then the cursor by the job's CAS, which renews the lease,
// then the stored-byte delta as one usage batch. With nothing new, renew alone writes the cursor as it stands to renew
// the lease, and else nothing is written.
func (self *dropDeleteRun) checkpoint(renew bool) error {
	self.lastCheckpoint = self.deleter.clock.Now()
	if len(self.answers) == 0 && len(self.heldIds) == 0 && self.cursor == self.reported && self.freed == 0 && self.held == 0 {
		if !renew {
			return nil
		}
		leaseUntil, err := self.request.Checkpoint(self.ctx, &DropDeleteProgress{Cursor: self.cursor})
		if err != nil {
			return err
		}
		self.leaseUntil = leaseUntil
		return nil
	}
	settings := self.deleter.settings
	for 0 < len(self.answers) {
		chunk := self.answers[:min(len(self.answers), settings.FileRowCount)]
		if err := self.files.Put(self.ctx, DropFileDel, self.delSequence, EncodeDropDelFile(self.request.RepoId, self.request.JobId, self.delSequence, chunk)); err != nil {
			return err
		}
		self.delSequence += 1
		self.answers = self.answers[len(chunk):]
	}
	for 0 < len(self.heldIds) {
		chunk := self.heldIds[:min(len(self.heldIds), settings.FileRowCount)]
		encoded, err := EncodeDropIdFile(DropFileHeld, self.request.RepoId, self.request.JobId, self.heldSequence, chunk)
		if err != nil {
			return err
		}
		if err := self.files.Put(self.ctx, DropFileHeld, self.heldSequence, encoded); err != nil {
			return err
		}
		self.heldSequence += 1
		self.heldIds = self.heldIds[len(chunk):]
	}
	progress := &DropDeleteProgress{Cursor: self.cursor, FreedByteCount: self.freed, HeldByteCount: self.held}
	leaseUntil, err := self.request.Checkpoint(self.ctx, progress)
	if err != nil {
		return err
	}
	self.leaseUntil = leaseUntil
	self.result.Progress = progress
	from := self.reported
	self.reported = self.cursor
	stored := progress.FreedByteCount + progress.HeldByteCount
	self.freed, self.held = 0, 0
	if 0 < stored {
		self.report(from, progress.Cursor, stored)
	}
	return nil
}

// The stored-byte delta of one checkpoint, as a usage batch keyed by the job and its cursor range (§20.6): a failed
// report is logged and dropped, under-billing and never double-billing.
func (self *dropDeleteRun) report(from DropCursor, to DropCursor, storedByteCount uint64) {
	quota := self.deleter.host.Quota
	networkId := self.request.NetworkId
	if quota == nil || networkId == (sidecar.Id{}) {
		self.deleter.log.Warningf("[evs] drop usage not reported: repo %s job %s: no quota or network for %d freed bytes",
			sidecar.EvsKeyId(self.request.RepoId), sidecar.EvsKeyId(self.request.JobId), storedByteCount)
		return
	}
	now := self.deleter.clock.Now()
	batch := &sidecar.UsageBatch{
		BatchId:     sidecar.NewDropUsageBatchId(connect.Id(self.request.JobId), dropCursorBytes(from), dropCursorBytes(to)),
		Producer:    sidecar.QuotaProducerTaskworker,
		WindowStart: now.Truncate(sidecar.DefaultQuotaUsageBatcherSettings().WindowTimeout),
		Events:      []*sidecar.UsageEvent{{NetworkId: connect.Id(networkId), StoredByteDelta: -int64(storedByteCount)}},
	}
	if err := quota.ReportUsage(self.ctx, batch); err != nil {
		self.deleter.log.Warningf("[evs] drop usage batch dropped: repo %s job %s: %d freed bytes: %v",
			sidecar.EvsKeyId(self.request.RepoId), sidecar.EvsKeyId(self.request.JobId), storedByteCount, err)
	}
}
