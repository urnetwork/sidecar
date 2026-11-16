// The drop table, drops/<repo>/_ (§11.13's who row, §11.8's drops/ row; QD-179, DESIGN-DETAILS 10.2.2; EVSB-M10-03):
// one object per repo on its metadata cluster, at most 64 KiB, changed only by If-Match (created If-None-Match), which
// holds the repo's drops, the void records of the cancelled and refused ones, its dry runs and its one running drop
// job. Fixed-size records only (QD-179), integers big-endian:
//
//	header, 16 B   "URdt" | format u8 (1) | 3 zero bytes | drop count u16 | void count u16 | dry run count u16 |
//	               job count u8 (0 or 1) | 1 zero byte
//	job, 128 B     job_id 16 | owner 16 | until_ms i64 | phase u8 | flags u8 | 2 zero bytes | round u32 | fence_ms i64 |
//	               horizon_ms i64 | cursor (file sequence u32, row u32) | retry_ms i64 | covered u16 | 6 zero bytes |
//	               freed u64 | held u64 | started_ms i64 | 16 zero bytes
//	drop, 128 B    drop_id 16 | ref_id 16 | push_id 16 | version u64 | place 20 | not_before_ms i64 | seen_ms i64 |
//	               state u8 | phase u8 | freed u64 | held u64 | preview_id 16 | ended_day u16
//	void, 17 B     drop_id 16 | state u8
//	dry run, 64 B  preview_id 16 | ref_id 16 | state u8 | 7 zero bytes | created_ms i64 | until_ms i64 | snapshot u64
//	trailer, 32 B  SHA-256 of every byte before it
//
// The drop entry is 10.2.2's 126 B with one u16 added, the UTC day it ended, which QD-179's "an entry leaves 30 d after
// it ends" needs and 10.2.2's fields do not hold; it keeps QD-179's 128 B. A dry run's until_ms is the lease of the run
// holding it while it runs and the time it ended once it has. Each record's meaning:
//
//	drop     a committed DROP: pending, cancelled, executing in its phase, done, refused {locked, mismatch, verify},
//	         held or observed. seen_ms is its appender's checked clock read after the answer that showed it the DROP
//	         committed (step 7's 200, or a cluster read for evacuation's and a reader's append), never earlier
//	void     a cancelled or refused drop, for the repo's life: an entry absent with no void record means executed
//	         (QD-179's rule 4), which is the safe default for §11.9's serve row and the job's liveness
//	dry run  queued, running, done or failed; its request and results live in dropscan/<repo>/<preview_id>/
//	job      the repo's one running drop job (one job a repo), its owner instance and lease (until_ms), its phase,
//	         round, fence and the round's horizon, its delete cursor and when a waiting job wakes (retry_ms)
//
// Bounds (QD-179): an ended entry leaves 30 d after it ends, or sooner when a write would pass 64 KiB, ended entries
// oldest first and never one whose DROP evs saw committed under 27 h ago, since evacuation appends a committed DROP the
// table lacks; pending, executing and observed entries never leave. A held entry occupies, lists and leaves the table
// exactly as its done twin would (owner decision 184). A DROP is refused 429 while pending, executing and observed
// entries and void records would pass 48 KiB (AdmitsDrop, which EVS2-M10-09's 5c reads); a cancel is never refused and
// dry runs only evict.
//
// evs writes the table at each DROP and cancel, through DropSink (CONTRACTS.md C-14: EVS2-M10-09's step 8 calls it,
// this file implements it), and at each dry run's request; the job writes it at each phase and at most once a minute
// besides. Each write also sets the repo's {evsd_<repo_id>} hint, which taskworker takes (server/taskworker/evs_drop.go),
// and whose loss the daily LIST of drops/ bounds to a day.
//
// Safe for concurrent use: a DropTable holds no state but its settings, and every change is one If-Match.

package evsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The table's layout. Format values, not tunables.
const (
	dropTableMagic                 = "URdt"
	dropTableFormat1          byte = 1
	dropTableHeaderByteCount       = 16
	dropTableJobByteCount          = 128
	dropTableEntryByteCount        = 128
	dropTableVoidByteCount         = 17
	dropTablePreviewByteCount      = 64
	dropTableTrailerByteCount      = sha256.Size
	// the job record's flag: the rest of D waits on a hold (owner decision 184)
	dropJobFlagHeld uint8 = 1
)

// A drop's state as the table holds it: §11.13's who row's states, a refusal's reason folded in.
type DropState uint8

const (
	DropStatePending         DropState = 1
	DropStateCancelled       DropState = 2
	DropStateExecuting       DropState = 3
	DropStateDone            DropState = 4
	DropStateRefusedLocked   DropState = 5
	DropStateRefusedMismatch DropState = 6
	DropStateRefusedVerify   DropState = 7
	DropStateHeld            DropState = 8
	DropStateObserved        DropState = 9
)

// Whether the value is one of the states.
func (self DropState) Valid() bool {
	return DropStatePending <= self && self <= DropStateObserved
}

// Whether the drop has ended: cancelled, done, refused or held. An ended entry leaves the table 30 d after it ends.
func (self DropState) Ended() bool {
	switch self {
	case DropStateCancelled, DropStateDone, DropStateRefusedLocked, DropStateRefusedMismatch, DropStateRefusedVerify, DropStateHeld:
		return true
	}
	return false
}

// Whether the drop ended deleting nothing, so it leaves a void record for the repo's life: cancelled or refused.
func (self DropState) Void() bool {
	switch self {
	case DropStateCancelled, DropStateRefusedLocked, DropStateRefusedMismatch, DropStateRefusedVerify:
		return true
	}
	return false
}

// Whether the drop's listed versions are not live (DESIGN-DETAILS 10.2.8's live row): done or held. A covered drop
// that its job did not refuse is not live either, which the job adds.
func (self DropState) Executed() bool {
	return self == DropStateDone || self == DropStateHeld
}

// The state and reason GET .../drops reports: held reads done, so no field, value or count shows a hold.
func (self DropState) Status() (protocol.EvsDropState, protocol.EvsDropRefusal) {
	switch self {
	case DropStatePending:
		return protocol.EvsDropState_EVS_DROP_PENDING, 0
	case DropStateCancelled:
		return protocol.EvsDropState_EVS_DROP_CANCELLED, 0
	case DropStateExecuting:
		return protocol.EvsDropState_EVS_DROP_EXECUTING, 0
	case DropStateDone, DropStateHeld:
		return protocol.EvsDropState_EVS_DROP_DONE, 0
	case DropStateRefusedLocked:
		return protocol.EvsDropState_EVS_DROP_REFUSED, protocol.EvsDropRefusal_EVS_DROP_REFUSAL_LOCKED
	case DropStateRefusedMismatch:
		return protocol.EvsDropState_EVS_DROP_REFUSED, protocol.EvsDropRefusal_EVS_DROP_REFUSAL_MISMATCH
	case DropStateRefusedVerify:
		return protocol.EvsDropState_EVS_DROP_REFUSED, protocol.EvsDropRefusal_EVS_DROP_REFUSAL_VERIFY
	case DropStateObserved:
		return protocol.EvsDropState_EVS_DROP_OBSERVED, 0
	}
	return protocol.EvsDropState_EVS_DROP_STATE_UNSPECIFIED, 0
}

// The label urnetwork_evs_drop_jobs counts a drop's move into the state under.
func (self DropState) metricLabel() string {
	switch self {
	case DropStatePending:
		return "pending"
	case DropStateCancelled:
		return "cancelled"
	case DropStateExecuting:
		return "executing"
	case DropStateDone:
		return "done"
	case DropStateRefusedLocked:
		return "refused_locked"
	case DropStateRefusedMismatch:
		return "refused_mismatch"
	case DropStateRefusedVerify:
		return "refused_verify"
	case DropStateHeld:
		return "held"
	case DropStateObserved:
		return "observed"
	}
	return "unknown"
}

var (
	// The table's bytes break its layout: a bad magic, format, count, state or trailer. Nothing is deleted on it.
	ErrDropTableInvalid = errors.New("evs drop table invalid")
	// A write would pass the table's bound even with every ended entry it may evict gone.
	ErrDropTableFull = errors.New("evs drop table full")
	// The table moved under every CAS a change tried.
	ErrDropTableBusy = errors.New("evs drop table busy")
	// The clock was unsure, so nothing was appended (DESIGN-DETAILS 10.6's drop_table_test.go row).
	ErrDropClockUnsure = errors.New("evs drop clock unsure")
	// Settings a table or job cannot work with.
	ErrDropSettings = errors.New("evs drop settings invalid")
)

// Tunables of the drop table, the drop job and the dry runs (§11.13's drop history rows; DESIGN-DETAILS 10.2.2's
// settings). Each floor is the design's value, and a value under its floor is refused.
type DropSettings struct {
	// Owner decision 183's fence after not_before_ms: a drop starts once not_before_ms plus this has passed. 25 min.
	StartDelay      time.Duration
	StartDelayFloor time.Duration
	// The job's margin past fence_ms (10.2.8's F4): 12 min, a floor no setting passes.
	CiteBound      time.Duration
	CiteBoundFloor time.Duration
	// Section 2.2.4's adoption bound, which F7's young rule reads: 24 h 2 min, the same value and floor.
	AdoptionBound      time.Duration
	AdoptionBoundFloor time.Duration
	// A job's owner holds it until now plus this, renewed at each checkpoint: 2 min.
	LeaseTime time.Duration
	// Another instance takes a job once its owner's lease lapsed this long ago by its checked clock: 30 s.
	LeaseLapse time.Duration
	// An instance whose lease is under this away issues nothing: 1 s.
	LeaseMargin time.Duration
	// The job writes the table at most once a minute besides its phase changes.
	CheckpointInterval time.Duration
	// A waiting job is woken at retry_ms and then each this long: 10 min.
	HorizonRetryInterval time.Duration
	// How long after a bound the horizon is taken to pass it: the next round's wake for a drop whose cite bound, or a
	// young candidate whose adoption bound, the horizon has not passed is that bound plus this. 25 h, evacuation's.
	HorizonRetryLag time.Duration
	// The table's bound: 64 KiB (§11.8's drops/ row).
	TableByteCount int
	// 5c's line: a DROP is refused 429 while pending, executing and observed entries and void records would pass
	// this. 48 KiB (QD-179's rule 5).
	TableAdmitByteCount int
	// An ended entry or dry run leaves the table this long after it ends: 30 d.
	EndedRetention time.Duration
	// No ended entry whose DROP evs saw committed under this long ago leaves the table early, since evacuation appends
	// a committed DROP the table lacks within 26 h: 27 h.
	EvictGuard time.Duration
	// Changes a write retries on a 412 before ErrDropTableBusy.
	TableCasRetryCount int
	// At most this much a second a job reads of the clusters: 32 MB/s.
	ReadBytesPerSecond int64
	// At most this many DELETEs a second a job issues: 10.
	DeletesPerSecond int
	// Each DELETE is cancelled this long before the lease's until_ms by the job's clock: 50 ms (§11.13's clock row).
	DeleteDeadlineMargin time.Duration
	// A job pauses while the segment cluster's drive operations a second pass this share of its measured capacity,
	// and while no capacity is known: 0.5 (§11.13's bound row; QD-056).
	HddPauseShare float64
	// How long a paused or blocked job waits before it is asked again: 1 min.
	PauseRetryInterval time.Duration
	// Rows a dropscan/ file holds at most: 131,072 (DESIGN-DETAILS 10.2.9's list file).
	FileRowCount int
	// LIST pages ask for this many keys.
	ListLimit int
	// A dry run's request body: at most this many bytes, and at most PreviewPathCount paths.
	PreviewRequestByteCount int64
	PreviewPathCount        int
	// The counts of a dry run's paths sum to at most this: 1,048,576 (EvsFormatSettings' EvsDropMaxListedCount).
	PreviewListedCount uint64
	// How long a GET .../drops answer is served from this process's cache: 5 s, as repo/ is.
	TableCacheTtl time.Duration
	// The usage window a job's stored-byte batch starts in, its start the checkpoint's time truncated to it: §20.6's
	// 60 s, the usage batcher's WindowTimeout.
	UsageWindowTimeout time.Duration
}

// §11.13's and DESIGN-DETAILS 10.2.2's values. A fresh value each call.
func DefaultDropSettings() *DropSettings {
	return &DropSettings{
		StartDelay:              25 * time.Minute,
		StartDelayFloor:         25 * time.Minute,
		CiteBound:               12 * time.Minute,
		CiteBoundFloor:          12 * time.Minute,
		AdoptionBound:           24*time.Hour + 2*time.Minute,
		AdoptionBoundFloor:      24*time.Hour + 2*time.Minute,
		LeaseTime:               2 * time.Minute,
		LeaseLapse:              30 * time.Second,
		LeaseMargin:             1 * time.Second,
		CheckpointInterval:      1 * time.Minute,
		HorizonRetryInterval:    10 * time.Minute,
		HorizonRetryLag:         25 * time.Hour,
		TableByteCount:          64 * 1024,
		TableAdmitByteCount:     48 * 1024,
		EndedRetention:          30 * 24 * time.Hour,
		EvictGuard:              27 * time.Hour,
		TableCasRetryCount:      8,
		ReadBytesPerSecond:      32 * 1000 * 1000,
		DeletesPerSecond:        10,
		DeleteDeadlineMargin:    50 * time.Millisecond,
		HddPauseShare:           0.5,
		PauseRetryInterval:      1 * time.Minute,
		FileRowCount:            131072,
		ListLimit:               1000,
		PreviewRequestByteCount: 4 * 1024 * 1024,
		PreviewPathCount:        1024,
		PreviewListedCount:      1048576,
		TableCacheTtl:           5 * time.Second,
		UsageWindowTimeout:      sidecar.DefaultQuotaUsageBatcherSettings().WindowTimeout,
	}
}

// ErrDropSettings for a value under its floor or one the job cannot work with.
func (self *DropSettings) Validate() error {
	switch {
	case self.StartDelayFloor <= 0 || self.StartDelay < self.StartDelayFloor:
		return fmt.Errorf("%w: a start delay of %s, under %s", ErrDropSettings, self.StartDelay, self.StartDelayFloor)
	case self.CiteBoundFloor <= 0 || self.CiteBound < self.CiteBoundFloor:
		return fmt.Errorf("%w: a cite bound of %s, under %s", ErrDropSettings, self.CiteBound, self.CiteBoundFloor)
	case self.AdoptionBoundFloor <= 0 || self.AdoptionBound < self.AdoptionBoundFloor:
		return fmt.Errorf("%w: an adoption bound of %s, under %s", ErrDropSettings, self.AdoptionBound, self.AdoptionBoundFloor)
	case self.LeaseTime <= self.LeaseMargin || self.LeaseLapse <= 0 || self.LeaseMargin <= 0 || self.DeleteDeadlineMargin <= 0 ||
		self.LeaseMargin <= self.DeleteDeadlineMargin:
		return fmt.Errorf("%w: a lease of %s with a margin of %s", ErrDropSettings, self.LeaseTime, self.LeaseMargin)
	case self.CheckpointInterval <= 0 || self.HorizonRetryInterval <= 0 || self.HorizonRetryLag <= 0 || self.PauseRetryInterval <= 0 ||
		self.UsageWindowTimeout <= 0:
		return fmt.Errorf("%w: an interval that is not positive", ErrDropSettings)
	case self.TableByteCount < dropTableHeaderByteCount+dropTableJobByteCount+dropTableTrailerByteCount ||
		self.TableAdmitByteCount <= 0 || self.TableByteCount < self.TableAdmitByteCount:
		return fmt.Errorf("%w: a table of %d bytes admitting %d", ErrDropSettings, self.TableByteCount, self.TableAdmitByteCount)
	case self.EndedRetention <= 0 || self.EvictGuard <= 0 || self.TableCacheTtl < 0:
		return fmt.Errorf("%w: a retention that is not positive", ErrDropSettings)
	case self.TableCasRetryCount <= 0 || self.ReadBytesPerSecond <= 0 || self.DeletesPerSecond <= 0 || self.FileRowCount <= 0 || self.ListLimit <= 0:
		return fmt.Errorf("%w: a bound that is not positive", ErrDropSettings)
	case self.HddPauseShare <= 0 || 1 < self.HddPauseShare:
		return fmt.Errorf("%w: an hdd pause share of %g", ErrDropSettings, self.HddPauseShare)
	case self.PreviewRequestByteCount <= 0 || self.PreviewPathCount <= 0 || self.PreviewListedCount == 0:
		return fmt.Errorf("%w: a dry run bound that is not positive", ErrDropSettings)
	}
	return nil
}

// A delete cursor: the cand file sequence and row before which every candidate of the round is answered.
type DropCursor struct {
	Sequence uint32
	Row      uint32
}

// The repo's running drop job.
type DropJobRecord struct {
	JobId sidecar.Id
	// The instance holding it, and its lease's end by that instance's checked clock. A zero owner holds nothing: a
	// job waiting for the horizon or a hold holds no lease.
	Owner   sidecar.Id
	UntilMs int64
	// Its phase: resolve, horizon, mark, verify or delete.
	Phase protocol.EvsDropPhase
	// The rest of D waits on a hold (owner decision 184).
	Held bool
	// The round whose horizon it took last, 0 before its first.
	Round uint32
	// The largest seen_ms of its covered drops, and the round's H (DESIGN-DETAILS 10.2.8's F3 and F4).
	FenceMs   int64
	HorizonMs int64
	// Where the round's deletes resume.
	Cursor DropCursor
	// When a job that waits is woken, 0 for one that does not wait.
	RetryMs int64
	// How many drops it covers: snap-0 names them.
	CoveredCount uint16
	// What its deletes freed and moved to held, stored bytes.
	FreedByteCount uint64
	HeldByteCount  uint64
	StartedMs      int64
}

// One drop.
type DropTableEntry struct {
	DropId sidecar.Id
	RefId  sidecar.Id
	PushId sidecar.Id
	// u_d, the ref version its DROP committed at, and the place of its record.
	Version     uint64
	Place       *protocol.EvsPlace
	NotBeforeMs int64
	SeenMs      int64
	State       DropState
	// While executing: resolve, horizon, mark, verify or delete.
	Phase          protocol.EvsDropPhase
	FreedByteCount uint64
	HeldByteCount  uint64
	// The dry run its DROP names, or zero.
	PreviewId sidecar.Id
	// The UTC day, since the Unix epoch, it ended: 0 while it has not.
	EndedDay uint16
}

// A cancelled or refused drop, for the repo's life.
type DropVoidRecord struct {
	DropId sidecar.Id
	State  DropState
}

// One dry run.
type DropPreviewRecord struct {
	PreviewId sidecar.Id
	RefId     sidecar.Id
	State     protocol.EvsDropPreviewState
	CreatedMs int64
	// While running, the lease of the run holding it; once done or failed, when it ended.
	UntilMs int64
	// The request ref's version at its snapshot, once done.
	SnapshotVersion uint64
}

// The table as one read found it.
type DropTableState struct {
	Job      *DropJobRecord
	Drops    []*DropTableEntry
	Voids    []*DropVoidRecord
	Previews []*DropPreviewRecord
}

// The entry of dropId, or nil.
func (self *DropTableState) Drop(dropId sidecar.Id) *DropTableEntry {
	for _, entry := range self.Drops {
		if entry.DropId == dropId {
			return entry
		}
	}
	return nil
}

// The void record of dropId, or nil.
func (self *DropTableState) Void(dropId sidecar.Id) *DropVoidRecord {
	for _, void := range self.Voids {
		if void.DropId == dropId {
			return void
		}
	}
	return nil
}

// The dry run of previewId, or nil.
func (self *DropTableState) Preview(previewId sidecar.Id) *DropPreviewRecord {
	for _, preview := range self.Previews {
		if preview.PreviewId == previewId {
			return preview
		}
	}
	return nil
}

// Sets entry's state, ending it on day when the state ends it and adding its void record when it voids it.
func (self *DropTableState) setState(entry *DropTableEntry, state DropState, day uint16) {
	entry.State = state
	if state != DropStateExecuting {
		entry.Phase = 0
	}
	if state.Ended() && entry.EndedDay == 0 {
		entry.EndedDay = max(1, day)
	}
	if state.Void() && self.Void(entry.DropId) == nil {
		self.Voids = append(self.Voids, &DropVoidRecord{DropId: entry.DropId, State: state})
	}
}

// Whether a DROP may be appended (5c's 429 row; QD-179's rule 5): pending, executing and observed entries and void
// records within TableAdmitByteCount, a new entry included. Held entries never count, and a cancel never asks.
func (self *DropTableState) AdmitsDrop(settings *DropSettings) bool {
	byteCount := dropTableEntryByteCount
	for _, entry := range self.Drops {
		switch entry.State {
		case DropStatePending, DropStateExecuting, DropStateObserved:
			byteCount += dropTableEntryByteCount
		}
	}
	byteCount += dropTableVoidByteCount * len(self.Voids)
	return byteCount <= settings.TableAdmitByteCount
}

// The table's encoded size.
func (self *DropTableState) byteCount() int {
	byteCount := dropTableHeaderByteCount + dropTableTrailerByteCount
	if self.Job != nil {
		byteCount += dropTableJobByteCount
	}
	return byteCount + dropTableEntryByteCount*len(self.Drops) + dropTableVoidByteCount*len(self.Voids) +
		dropTablePreviewByteCount*len(self.Previews)
}

// A UTC day number, as an entry's ended_day holds it.
func dropDay(at time.Time) uint16 {
	return uint16(min(int64(0xffff), max(int64(1), at.Unix()/int64(24*time.Hour/time.Second))))
}

// The start of a UTC day number.
func dropDayStart(day uint16) time.Time {
	return time.Unix(int64(day)*int64(24*time.Hour/time.Second), 0).UTC()
}

// Whether an entry has ended and says when.
func (self *DropTableEntry) ended() bool {
	return self.State.Ended() && self.EndedDay != 0
}

// Whether a dry run has ended.
func (self *DropPreviewRecord) ended() bool {
	return self.State == protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE || self.State == protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_FAILED
}

// Whether an ended entry's retention has passed at now: a full EndedRetention after the end of the day it ended.
func (self *DropTableEntry) expired(now time.Time, settings *DropSettings) bool {
	return self.ended() && !now.Before(dropDayStart(self.EndedDay).Add(settings.EndedRetention+24*time.Hour))
}

// Whether an ended dry run's retention has passed at now.
func (self *DropPreviewRecord) expired(now time.Time, settings *DropSettings) bool {
	return self.ended() && !now.Before(time.UnixMilli(self.UntilMs).Add(settings.EndedRetention))
}

// Whether any ended entry or dry run's retention has passed at now.
func (self *DropTableState) expiring(now time.Time, settings *DropSettings) bool {
	for _, entry := range self.Drops {
		if entry.expired(now, settings) {
			return true
		}
	}
	for _, preview := range self.Previews {
		if preview.expired(now, settings) {
			return true
		}
	}
	return false
}

// Drops what the bounds let go before a write at now: every ended entry and dry run past EndedRetention, then, while
// the table would pass TableByteCount, ended entries oldest first that evs saw committed EvictGuard ago or more, then
// ended dry runs oldest first. ErrDropTableFull when it still passes.
func (self *DropTableState) evict(now time.Time, settings *DropSettings) error {
	self.Drops = slices.DeleteFunc(self.Drops, func(entry *DropTableEntry) bool {
		return entry.expired(now, settings)
	})
	self.Previews = slices.DeleteFunc(self.Previews, func(preview *DropPreviewRecord) bool {
		return preview.expired(now, settings)
	})
	ended := func(entry *DropTableEntry) bool {
		return entry.ended()
	}
	previewEnded := func(preview *DropPreviewRecord) bool {
		return preview.ended()
	}
	for settings.TableByteCount < self.byteCount() {
		oldest := -1
		for i, entry := range self.Drops {
			if !ended(entry) || now.Sub(time.UnixMilli(entry.SeenMs)) < settings.EvictGuard {
				continue
			}
			if oldest < 0 || entry.EndedDay < self.Drops[oldest].EndedDay {
				oldest = i
			}
		}
		if 0 <= oldest {
			self.Drops = append(self.Drops[:oldest], self.Drops[oldest+1:]...)
			continue
		}
		oldestPreview := -1
		for i, preview := range self.Previews {
			if !previewEnded(preview) {
				continue
			}
			if oldestPreview < 0 || preview.UntilMs < self.Previews[oldestPreview].UntilMs {
				oldestPreview = i
			}
		}
		if oldestPreview < 0 {
			return fmt.Errorf("%w: %d bytes", ErrDropTableFull, self.byteCount())
		}
		self.Previews = append(self.Previews[:oldestPreview], self.Previews[oldestPreview+1:]...)
	}
	return nil
}

// The table's bytes. A state that breaks the layout's rules is ErrDropTableInvalid; one past TableByteCount is the
// caller's to evict first.
func EncodeDropTable(state *DropTableState) ([]byte, error) {
	if 0xffff < len(state.Drops) || 0xffff < len(state.Voids) || 0xffff < len(state.Previews) {
		return nil, fmt.Errorf("%w: too many records", ErrDropTableInvalid)
	}
	encoded := make([]byte, 0, state.byteCount())
	encoded = append(encoded, dropTableMagic...)
	encoded = append(encoded, dropTableFormat1, 0, 0, 0)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(state.Drops)))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(state.Voids)))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(state.Previews)))
	if state.Job != nil {
		encoded = append(encoded, 1, 0)
	} else {
		encoded = append(encoded, 0, 0)
	}
	if job := state.Job; job != nil {
		if !dropPhaseValid(job.Phase) {
			return nil, fmt.Errorf("%w: a job in phase %d", ErrDropTableInvalid, job.Phase)
		}
		flags := uint8(0)
		if job.Held {
			flags |= dropJobFlagHeld
		}
		encoded = append(encoded, job.JobId[:]...)
		encoded = append(encoded, job.Owner[:]...)
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(job.UntilMs))
		encoded = append(encoded, byte(job.Phase), flags, 0, 0)
		encoded = binary.BigEndian.AppendUint32(encoded, job.Round)
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(job.FenceMs))
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(job.HorizonMs))
		encoded = binary.BigEndian.AppendUint32(encoded, job.Cursor.Sequence)
		encoded = binary.BigEndian.AppendUint32(encoded, job.Cursor.Row)
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(job.RetryMs))
		encoded = binary.BigEndian.AppendUint16(encoded, job.CoveredCount)
		encoded = append(encoded, make([]byte, 6)...)
		encoded = binary.BigEndian.AppendUint64(encoded, job.FreedByteCount)
		encoded = binary.BigEndian.AppendUint64(encoded, job.HeldByteCount)
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(job.StartedMs))
		encoded = append(encoded, make([]byte, 16)...)
	}
	seen := map[sidecar.Id]bool{}
	for _, entry := range state.Drops {
		if !entry.State.Valid() || seen[entry.DropId] || entry.Place == nil {
			return nil, fmt.Errorf("%w: a drop in state %d", ErrDropTableInvalid, entry.State)
		}
		if entry.Phase != 0 && (entry.State != DropStateExecuting || !dropPhaseValid(entry.Phase)) {
			return nil, fmt.Errorf("%w: a drop in phase %d", ErrDropTableInvalid, entry.Phase)
		}
		seen[entry.DropId] = true
		encoded = append(encoded, entry.DropId[:]...)
		encoded = append(encoded, entry.RefId[:]...)
		encoded = append(encoded, entry.PushId[:]...)
		encoded = binary.BigEndian.AppendUint64(encoded, entry.Version)
		encoded = append(encoded, sidecar.EvsPackPlace(entry.Place)...)
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(entry.NotBeforeMs))
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(entry.SeenMs))
		encoded = append(encoded, byte(entry.State), byte(entry.Phase))
		encoded = binary.BigEndian.AppendUint64(encoded, entry.FreedByteCount)
		encoded = binary.BigEndian.AppendUint64(encoded, entry.HeldByteCount)
		encoded = append(encoded, entry.PreviewId[:]...)
		encoded = binary.BigEndian.AppendUint16(encoded, entry.EndedDay)
	}
	seenVoids := map[sidecar.Id]bool{}
	for _, void := range state.Voids {
		if !void.State.Void() || seenVoids[void.DropId] {
			return nil, fmt.Errorf("%w: a void record in state %d", ErrDropTableInvalid, void.State)
		}
		seenVoids[void.DropId] = true
		encoded = append(encoded, void.DropId[:]...)
		encoded = append(encoded, byte(void.State))
	}
	seenPreviews := map[sidecar.Id]bool{}
	for _, preview := range state.Previews {
		if preview.State < protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED || protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_FAILED < preview.State ||
			seenPreviews[preview.PreviewId] {
			return nil, fmt.Errorf("%w: a dry run in state %d", ErrDropTableInvalid, preview.State)
		}
		seenPreviews[preview.PreviewId] = true
		encoded = append(encoded, preview.PreviewId[:]...)
		encoded = append(encoded, preview.RefId[:]...)
		encoded = append(encoded, byte(preview.State), 0, 0, 0, 0, 0, 0, 0)
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(preview.CreatedMs))
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(preview.UntilMs))
		encoded = binary.BigEndian.AppendUint64(encoded, preview.SnapshotVersion)
	}
	trailer := sha256.Sum256(encoded)
	return append(encoded, trailer[:]...), nil
}

// Whether phase is one a job or an executing drop can be in.
func dropPhaseValid(phase protocol.EvsDropPhase) bool {
	return protocol.EvsDropPhase_EVS_DROP_RESOLVE <= phase && phase <= protocol.EvsDropPhase_EVS_DROP_HORIZON
}

// The table from its bytes, or ErrDropTableInvalid.
func DecodeDropTable(encoded []byte) (*DropTableState, error) {
	invalid := func(why string) error {
		return fmt.Errorf("%w: %s", ErrDropTableInvalid, why)
	}
	if len(encoded) < dropTableHeaderByteCount+dropTableTrailerByteCount {
		return nil, invalid("short")
	}
	body := encoded[:len(encoded)-dropTableTrailerByteCount]
	if trailer := sha256.Sum256(body); !bytes.Equal(trailer[:], encoded[len(body):]) {
		return nil, invalid("trailer")
	}
	if string(body[0:4]) != dropTableMagic || body[4] != dropTableFormat1 || body[5] != 0 || body[6] != 0 || body[7] != 0 || body[15] != 0 {
		return nil, invalid("header")
	}
	dropCount := int(binary.BigEndian.Uint16(body[8:10]))
	voidCount := int(binary.BigEndian.Uint16(body[10:12]))
	previewCount := int(binary.BigEndian.Uint16(body[12:14]))
	jobCount := int(body[14])
	if 1 < jobCount {
		return nil, invalid("two jobs")
	}
	if len(body) != dropTableHeaderByteCount+jobCount*dropTableJobByteCount+dropCount*dropTableEntryByteCount+
		voidCount*dropTableVoidByteCount+previewCount*dropTablePreviewByteCount {
		return nil, invalid("length")
	}
	state := &DropTableState{}
	offset := dropTableHeaderByteCount
	readId := func() sidecar.Id {
		id := sidecar.Id(body[offset : offset+16])
		offset += 16
		return id
	}
	readUint64 := func() uint64 {
		value := binary.BigEndian.Uint64(body[offset : offset+8])
		offset += 8
		return value
	}
	readUint32 := func() uint32 {
		value := binary.BigEndian.Uint32(body[offset : offset+4])
		offset += 4
		return value
	}
	zero := func(byteCount int) bool {
		for _, b := range body[offset : offset+byteCount] {
			if b != 0 {
				return false
			}
		}
		offset += byteCount
		return true
	}
	if jobCount == 1 {
		job := &DropJobRecord{}
		job.JobId = readId()
		job.Owner = readId()
		job.UntilMs = int64(readUint64())
		job.Phase = protocol.EvsDropPhase(body[offset])
		flags := body[offset+1]
		offset += 2
		if !dropPhaseValid(job.Phase) || flags&^dropJobFlagHeld != 0 || !zero(2) {
			return nil, invalid("job")
		}
		job.Held = flags&dropJobFlagHeld != 0
		job.Round = readUint32()
		job.FenceMs = int64(readUint64())
		job.HorizonMs = int64(readUint64())
		job.Cursor.Sequence = readUint32()
		job.Cursor.Row = readUint32()
		job.RetryMs = int64(readUint64())
		job.CoveredCount = binary.BigEndian.Uint16(body[offset : offset+2])
		offset += 2
		if !zero(6) {
			return nil, invalid("job")
		}
		job.FreedByteCount = readUint64()
		job.HeldByteCount = readUint64()
		job.StartedMs = int64(readUint64())
		if !zero(16) {
			return nil, invalid("job")
		}
		state.Job = job
	}
	seen := map[sidecar.Id]bool{}
	for range dropCount {
		entry := &DropTableEntry{}
		entry.DropId = readId()
		entry.RefId = readId()
		entry.PushId = readId()
		entry.Version = readUint64()
		place, err := sidecar.EvsUnpackPlace(body[offset : offset+sidecar.EvsPlaceByteCount])
		if err != nil {
			return nil, invalid("place")
		}
		offset += sidecar.EvsPlaceByteCount
		entry.Place = place
		entry.NotBeforeMs = int64(readUint64())
		entry.SeenMs = int64(readUint64())
		entry.State = DropState(body[offset])
		entry.Phase = protocol.EvsDropPhase(body[offset+1])
		offset += 2
		entry.FreedByteCount = readUint64()
		entry.HeldByteCount = readUint64()
		entry.PreviewId = readId()
		entry.EndedDay = binary.BigEndian.Uint16(body[offset : offset+2])
		offset += 2
		if !entry.State.Valid() || seen[entry.DropId] || (entry.Phase != 0 && (entry.State != DropStateExecuting || !dropPhaseValid(entry.Phase))) {
			return nil, invalid("drop")
		}
		seen[entry.DropId] = true
		state.Drops = append(state.Drops, entry)
	}
	seenVoids := map[sidecar.Id]bool{}
	for range voidCount {
		void := &DropVoidRecord{DropId: readId(), State: DropState(body[offset])}
		offset += 1
		if !void.State.Void() || seenVoids[void.DropId] {
			return nil, invalid("void record")
		}
		seenVoids[void.DropId] = true
		state.Voids = append(state.Voids, void)
	}
	seenPreviews := map[sidecar.Id]bool{}
	for range previewCount {
		preview := &DropPreviewRecord{PreviewId: readId(), RefId: readId(), State: protocol.EvsDropPreviewState(body[offset])}
		offset += 1
		if !zero(7) || preview.State < protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_QUEUED ||
			protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_FAILED < preview.State || seenPreviews[preview.PreviewId] {
			return nil, invalid("dry run")
		}
		seenPreviews[preview.PreviewId] = true
		preview.CreatedMs = int64(readUint64())
		preview.UntilMs = int64(readUint64())
		preview.SnapshotVersion = readUint64()
		state.Previews = append(state.Previews, preview)
	}
	return state, nil
}

// The repo's {evsd_<repo_id>} hint (§11.13's who row; §2.8's evs-28): set at each write that leaves drop work, taken
// by taskworker once it has queued the repo's run.
func DropHintKey(repoId sidecar.Id) string {
	return "{evsd_" + sidecar.EvsKeyId(repoId) + "}"
}

// The repo whose hint key is key, and whether key is one.
func DropHintRepoId(key string) (sidecar.Id, bool) {
	text, ok := bytes.CutPrefix([]byte(key), []byte("{evsd_"))
	if !ok || len(text) != 33 || text[32] != '}' {
		return sidecar.Id{}, false
	}
	repoId, err := parseEvsHexId(string(text[:32]))
	if err != nil {
		return sidecar.Id{}, false
	}
	return repoId, true
}

// One segment cluster's job lease, holding only the instance id (§11.13's bound row: one job a segment cluster): evs-28's
// {evsd_} family, whose "per job: its owner instance and lease" it is, keyed by the cluster's id, which no hint key takes
// since a cluster id is no repo id's 32 hex characters.
func dropClusterLeaseKey(clusterId string) string {
	return "{evsd_" + clusterId + "}"
}

// The table as one read of the cluster found it.
type DropTableRead struct {
	State *DropTableState
	// "" for a table that does not exist yet: the next write creates it.
	Etag   string
	ReadAt time.Time
}

// A committed DROP or cancel, as its appender hands it to DropSink.
type DropCommit struct {
	// The repo's metadata cluster, which holds drops/<repo>/_.
	ClusterId string
	RepoId    sidecar.Id
	RefId     sidecar.Id
	PushId    sidecar.Id
	// u_d, and the place of its record.
	Version uint64
	Place   *protocol.EvsPlace
	// Its checked body (EvsCheckDropPayload): a drop's id, window and dry run, or a cancel's target.
	Body *protocol.EvsDropHistory
}

// The seam step 8 appends each committed DROP and cancel to (CONTRACTS.md C-14: EVS2-M10-09 calls it, the DropTable
// meets it), and evacuation and a reader that meets a bit-5 window entry the table lacks call again. A nil sink appends
// nothing: evacuation's append within 26 h and the daily LIST cover a lost one.
type DropSink interface {
	// Appends commit. seenMs is the appender's checked clock read after the answer that showed it the commit (step 7's
	// 200, or a cluster read), never earlier. ctx carries the write class its caller paid: step 8's push grant,
	// evacuation's P2 grant. ErrDropClockUnsure on an unsure clock, which appends nothing.
	Append(ctx context.Context, commit *DropCommit, seenMs int64) error
}

// The drop table of every repo on host's clusters. See the file header.
type DropTable struct {
	host     *sidecar.ServiceHost
	blobs    sidecar.BlobStore
	clock    sidecar.Clock
	settings *DropSettings
	log      sidecar.Logger
	jobs     sidecar.MetricsCounter
}

var _ DropSink = (*DropTable)(nil)

// A table over blobs, which holds every metadata write to the budget (BudgetedBlobs), on host's clock, clock check and
// Redis. settings nil takes the defaults.
func NewDropTable(host *sidecar.ServiceHost, blobs sidecar.BlobStore, settings *DropSettings, log sidecar.Logger) (*DropTable, error) {
	if host == nil || blobs == nil {
		return nil, errors.New("evs's drop table needs a host and its Blobs")
	}
	if settings == nil {
		settings = DefaultDropSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	self := &DropTable{host: host, blobs: blobs, clock: host.ClockOrReal(), settings: settings, log: log}
	if host.Metrics != nil {
		self.jobs = host.Metrics.Counter(dropJobsMetricName, "Drops moved into a state, by the state (§19.8's drop history row).", "state")
	}
	return self, nil
}

// The settings in force.
func (self *DropTable) Settings() *DropSettings {
	return self.settings
}

// Counts a drop's move into state.
func (self *DropTable) countState(state DropState) {
	if self.jobs != nil {
		self.jobs.Add(1, state.metricLabel())
	}
}

// The table from the cluster: an empty state with no ETag when it does not exist.
func (self *DropTable) Read(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (*DropTableRead, error) {
	readAt := self.clock.Now()
	object, err := cluster.Get(ctx, DropsKey(repoId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return &DropTableRead{State: &DropTableState{}, ReadAt: readAt}, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(object.Body, int64(self.settings.TableByteCount)+1))
	if err != nil {
		return nil, err
	}
	if self.settings.TableByteCount < len(encoded) {
		return nil, fmt.Errorf("%w: %d bytes", ErrDropTableInvalid, len(encoded))
	}
	state, err := DecodeDropTable(encoded)
	if err != nil {
		self.log.Errorf("[evs] alarm drop_table_invalid: repo %s: %v", sidecar.EvsKeyId(repoId), err)
		return nil, err
	}
	return &DropTableRead{State: state, Etag: object.Etag, ReadAt: readAt}, nil
}

// Changes the table by one If-Match, or If-None-Match to create it: read, decide on the read's state at the clock's
// now, write, and read again on a 412, at most TableCasRetryCount times. decide returns false to write nothing, and
// its error is Update's. ctx carries the write's class. A write that answers with an unknown outcome is read again,
// as §11.8's unknown row has it, and decided again on what that read shows.
func (self *DropTable) Update(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, decide func(state *DropTableState, now time.Time) (bool, error)) (*DropTableRead, error) {
	for range self.settings.TableCasRetryCount {
		read, err := self.Read(ctx, cluster, repoId)
		if err != nil {
			return nil, err
		}
		now := self.clock.Now()
		changed, err := decide(read.State, now)
		if err != nil {
			return read, err
		}
		if !changed {
			return read, nil
		}
		if err := read.State.evict(now, self.settings); err != nil {
			return read, err
		}
		encoded, err := EncodeDropTable(read.State)
		if err != nil {
			return read, err
		}
		var etag string
		if read.Etag == "" {
			etag, err = cluster.PutIfNoneMatch(ctx, DropsKey(repoId), encoded, nil)
		} else {
			etag, err = cluster.PutIfMatch(ctx, DropsKey(repoId), read.Etag, encoded, nil)
		}
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			read.Etag = etag
			return read, nil
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
			// moved under us, or may have landed: the next read tells
			continue
		default:
			return read, err
		}
	}
	return nil, fmt.Errorf("%w: repo %s", ErrDropTableBusy, sidecar.EvsKeyId(repoId))
}

// Sets the repo's hint, its value the repo's metadata cluster: what evs does after a write that leaves drop work, a
// DROP's, a cancel's or a dry run's, so taskworker runs the repo. The job's own writes set none. Soft state: a hint that
// does not land is covered by the daily LIST of drops/.
func (self *DropTable) Hint(ctx context.Context, repoId sidecar.Id, clusterId string) {
	if self.host.Redis == nil {
		return
	}
	if err := self.host.Redis.Set(ctx, DropHintKey(repoId), []byte(clusterId), 0); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[evs] drop hint for repo %s not set: %v", sidecar.EvsKeyId(repoId), err)
	}
}

// See DropSink. A drop is appended pending unless the table holds it or its void record already, or it committed more
// than EvictGuard ago and the table holds neither, which is an executed drop whose entry has left (QD-179's rule 4) and
// never one whose append was lost, since evacuation appends within 26 h. A cancel moves its pending drop to cancelled
// with its void record, and leaves the void record alone when the table lacks the drop, so a later append of that drop
// finds it cancelled.
func (self *DropTable) Append(ctx context.Context, commit *DropCommit, seenMs int64) error {
	clockCheck := self.host.ClockCheck
	if clockCheck == nil || !clockCheck.Sure() {
		return ErrDropClockUnsure
	}
	if commit == nil || commit.Body == nil || commit.Place == nil {
		return fmt.Errorf("%w: an append with no body or place", ErrDropTableInvalid)
	}
	cluster, err := self.blobs.Cluster(commit.ClusterId)
	if err != nil {
		return err
	}
	body := commit.Body
	var moved DropState
	changed := false
	switch body.GetAction() {
	case 1:
		dropId, err := sidecar.IdFromBytes(body.GetDropId())
		if err != nil {
			return fmt.Errorf("%w: a drop id of %d bytes", ErrDropTableInvalid, len(body.GetDropId()))
		}
		previewId := sidecar.Id{}
		if 0 < len(body.GetPreviewId()) {
			if previewId, err = sidecar.IdFromBytes(body.GetPreviewId()); err != nil {
				return fmt.Errorf("%w: a preview id of %d bytes", ErrDropTableInvalid, len(body.GetPreviewId()))
			}
		}
		_, err = self.Update(ctx, cluster, commit.RepoId, func(state *DropTableState, now time.Time) (bool, error) {
			moved, changed = 0, false
			if state.Drop(dropId) != nil || state.Void(dropId) != nil {
				return false, nil
			}
			if self.settings.EvictGuard < now.Sub(batchMinuteTime(commit.Place.GetMinute())) {
				return false, nil
			}
			state.Drops = append(state.Drops, &DropTableEntry{
				DropId: dropId, RefId: commit.RefId, PushId: commit.PushId, Version: commit.Version, Place: commit.Place,
				NotBeforeMs: body.GetNotBeforeMs(), SeenMs: seenMs, State: DropStatePending, PreviewId: previewId,
			})
			moved, changed = DropStatePending, true
			return true, nil
		})
		if err != nil {
			return err
		}
	case 2:
		dropId, err := sidecar.IdFromBytes(body.GetCancelsDropId())
		if err != nil {
			return fmt.Errorf("%w: a cancelled drop id of %d bytes", ErrDropTableInvalid, len(body.GetCancelsDropId()))
		}
		_, err = self.Update(ctx, cluster, commit.RepoId, func(state *DropTableState, now time.Time) (bool, error) {
			moved, changed = 0, false
			entry := state.Drop(dropId)
			switch {
			case entry == nil && state.Void(dropId) == nil:
				state.Voids = append(state.Voids, &DropVoidRecord{DropId: dropId, State: DropStateCancelled})
				changed = true
				return true, nil
			case entry != nil && entry.State == DropStatePending:
				state.setState(entry, DropStateCancelled, dropDay(now))
				moved, changed = DropStateCancelled, true
				return true, nil
			}
			// any other state stands: the job's start reads the ref's history for a cancel itself (F1)
			return false, nil
		})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: action %d", ErrDropTableInvalid, body.GetAction())
	}
	if moved != 0 {
		self.countState(moved)
	}
	if changed {
		self.Hint(ctx, commit.RepoId, commit.ClusterId)
	}
	return nil
}
