// Evacuation's resolve step (§11.13's resolve and skip rows; §11.8's Resolve row; I-EVS-2, I-EVS-4): what one batch
// record becomes.
//
//	repo/      read first, cached at most 5 s, with the holds covering it: an unheld repo in shredding or shredded
//	           loses its records here with nothing else read; a repo this run cannot judge (no repo/, a keying
//	           repo, a format past this instance's, a place/ naming another cluster, a shredded repo under a hold)
//	           keeps its records in their batch
//	committed  at this record's place: kept, to be moved. A part follows its seal: it is kept when the committed
//	           seal's record names its place. At another place, a second copy of its push: dropped, nothing else
//	           deleted
//	dead       dropped, and the new slots its record lists are deleted before its batch, the only cleanup
//	pending    the ref's fence is raised, one head CAS with fence_ms, and the record resolved again on the fenced
//	           head. While this process's clock is unsure no fence is raised and the record stays. A ref with no
//	           head has nothing to fence and its record stays too: how a fence reaches such a ref is
//	           DESIGN-DETAILS.md's problem 2, which this file does not answer
//	           (questions/evsb-m2-11-pending-record-no-head)
//	reseed     counts as committed, and is kept at the version its ref's history names its push at
//
// A kept record's bytes go to the run's spool, a local file, so a run holds no batch in memory past its parse, and
// its segments and a dead record's slots are read from the new-objects list of its payload or part.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A write for a repo whose repo/ no longer lets it issue (§11.13's skip row): nothing was written, and the
	// repo's records wait for the next run.
	errEvacuateRepoWaits = errors.New("evs evacuation: the repo's state lets no write issue")
	// A delete a hold covering the repo keeps from issuing: nothing was deleted.
	errEvacuateHeld = errors.New("evs evacuation: a hold keeps the object")
)

// What a run does with a repo's records.
type evacuateRepoAction int

const (
	// Resolve each record, and move the kept ones.
	evacuateRepoMove evacuateRepoAction = iota + 1
	// An unheld repo in shredding or shredded: its records are dropped.
	evacuateRepoDrop
	// The run cannot judge it: its records stay in their batches.
	evacuateRepoWait
)

// A repo as one read of repo/ and hold/ found it, each at most 5 s old.
type evacuateRepoState struct {
	action evacuateRepoAction
	// a hold covers the repo, or may: nothing of it is deleted
	held bool
	// for evacuateRepoWait: why
	why string
}

// A repo's part of one run.
type evacuateRepo struct {
	repoId sidecar.Id
	// the oldest minute holding one of its records, which its move is due by
	firstMinute uint32
	kept        []*evacuateKept
	// the kept records' bytes in the spool
	keptByteCount int64
	moved         bool
	moveErr       error
}

// One kept record: where it committed, where it sat and where the spool holds its bytes.
type evacuateKept struct {
	refId       sidecar.Id
	version     uint64
	place       *protocol.EvsPlace
	spoolOffset int64
	segmentIds  [][32]byte
}

// A place as a map key.
func placeKey(place *protocol.EvsPlace) string {
	return fmt.Sprintf("%08x-%08x-%08x-%08x-%08x", place.GetMinute(), place.GetInstance(), place.GetSeq(), place.GetOffset(), place.GetLength())
}

// Whether two places name the same bytes.
func placesEqual(a *protocol.EvsPlace, b *protocol.EvsPlace) bool {
	return a != nil && b != nil && comparePlaces(a, b) == 0 && a.GetLength() == b.GetLength()
}

// The run's spool: kept records' bytes in a local file, appended and read back by offset.
type evacuateSpool struct {
	file      *os.File
	byteCount int64
}

// A new spool file in directory, the system's temporary directory when empty.
func newEvacuateSpool(directory string) (*evacuateSpool, error) {
	file, err := os.CreateTemp(directory, "evs-evacuate-*.spool")
	if err != nil {
		return nil, err
	}
	return &evacuateSpool{file: file}, nil
}

// Appends recordBytes and gives where they start.
func (self *evacuateSpool) append(recordBytes []byte) (int64, error) {
	offset := self.byteCount
	if _, err := self.file.WriteAt(recordBytes, offset); err != nil {
		return 0, err
	}
	self.byteCount += int64(len(recordBytes))
	return offset, nil
}

// The byteCount bytes at offset.
func (self *evacuateSpool) read(offset int64, byteCount int) ([]byte, error) {
	recordBytes := make([]byte, byteCount)
	if _, err := self.file.ReadAt(recordBytes, offset); err != nil {
		return nil, err
	}
	return recordBytes, nil
}

// Closes and removes the file.
func (self *evacuateSpool) close() {
	self.file.Close()
	os.Remove(self.file.Name())
}

// The repo as repo/ and hold/ show it now, each cached at most 5 s (§11.13's skip row). An error comes with a
// waiting state, so a caller that reads only the state still deletes nothing.
func (self *evacuateRun) repoState(repoId sidecar.Id) (*evacuateRepoState, error) {
	evacuator := self.evacuator
	read, err := evacuator.repos.Read(self.ctx, self.cluster, repoId)
	switch {
	case errors.Is(err, sidecar.ErrEvsRepoNotFound):
		return &evacuateRepoState{action: evacuateRepoWait, held: true, why: "no repo/"}, nil
	case err != nil:
		return &evacuateRepoState{action: evacuateRepoWait, held: true, why: "repo/ unread"}, err
	}
	cover, err := evacuator.holds.CoveringRepo(self.ctx, repoId, read.Object)
	// a hold/ that cannot be read covers, with the error (hold_cache.go)
	held := cover.Covered()
	if err != nil {
		return &evacuateRepoState{action: evacuateRepoWait, held: true, why: "hold/ unread"}, err
	}
	if !read.FormatWithin(evacuator.evsSettings.InstanceFormat) {
		return &evacuateRepoState{action: evacuateRepoWait, held: held, why: "repo/ format"}, nil
	}
	switch state := read.Object.GetState(); {
	case evacuateStateMoves(state, held):
		return &evacuateRepoState{action: evacuateRepoMove, held: held}, nil
	case state == protocol.EvsRepoState_EVS_REPO_SHREDDING, state == protocol.EvsRepoState_EVS_REPO_SHREDDED:
		if held {
			// a shredded repo under a hold: no write may issue for it, and the hold keeps what stands
			return &evacuateRepoState{action: evacuateRepoWait, held: true, why: "shredded repo held"}, nil
		}
		return &evacuateRepoState{action: evacuateRepoDrop}, nil
	}
	return &evacuateRepoState{action: evacuateRepoWait, held: held, why: "repo/ state"}, nil
}

// The skip row for a write that creates or fences: the repo's state must still move.
func (self *evacuateRun) recheckMove(ctx context.Context, repoId sidecar.Id) error {
	state, err := self.repoState(repoId)
	if err != nil {
		return err
	}
	if state.action != evacuateRepoMove {
		return fmt.Errorf("%w: %s", errEvacuateRepoWaits, state.why)
	}
	return nil
}

// The skip row for a delete of something a repo no longer needs: nothing a hold covers goes (§21.9), and nothing
// of a repo the run cannot judge.
func (self *evacuateRun) recheckDelete(ctx context.Context, repoId sidecar.Id) error {
	state, err := self.repoState(repoId)
	switch {
	case err != nil:
		return err
	case state.held:
		return errEvacuateHeld
	case state.action == evacuateRepoWait:
		return fmt.Errorf("%w: %s", errEvacuateRepoWaits, state.why)
	}
	return nil
}

// The repo's part of the run, made at its first record: place/ must name this cluster, since a batch holds only
// records of repos placed where it is. nil when it does not, which leaves the record waiting.
func (self *evacuateRun) repoOf(repoId sidecar.Id, minute uint32) (*evacuateRepo, error) {
	if repo, ok := self.repos[repoId]; ok {
		return repo, nil
	}
	place, err := self.evacuator.places.Resolve(self.ctx, repoId)
	if err != nil {
		return nil, err
	}
	if place.ClusterId != self.clusterId {
		return nil, nil
	}
	repo := &evacuateRepo{repoId: repoId, firstMinute: minute}
	self.repos[repoId] = repo
	return repo, nil
}

// Settles one record of a batch: see the file header. A record it cannot settle leaves its minute waiting. tail is a
// format-2 record's, nil for format 1's form.
func (self *evacuateRun) resolveRecord(minute *evacuateMinute, place *protocol.EvsPlace, record *sidecar.EvsBatchRecord, tail *sidecar.EvsBatchRecordTail, recordBytes []byte) {
	wait := func(why string, err error) {
		self.result.WaitingCount += 1
		minute.wait(why)
		if err != nil && !errors.Is(err, errEvacuateRepoWaits) {
			self.fail(err)
		}
	}
	state, err := self.repoState(record.RepoId)
	if err != nil {
		wait(state.why, err)
		return
	}
	switch state.action {
	case evacuateRepoWait:
		self.alarm("evacuate_repo_waits", sidecar.EvsKeyId(record.RepoId), "a record of batch minute %d on cluster %s stays: %s", minute.minute, self.clusterId, state.why)
		wait(state.why, nil)
		return
	case evacuateRepoDrop:
		self.result.ShreddedCount += 1
		minute.shredRepoIds[record.RepoId] = true
		return
	}
	repo, err := self.repoOf(record.RepoId, minute.minute)
	if err != nil || repo == nil {
		self.alarm("evacuate_repo_place", sidecar.EvsKeyId(record.RepoId), "a record of batch minute %d on cluster %s is of a repo place/ does not name here: it stays", minute.minute, self.clusterId)
		wait("place/", err)
		return
	}

	resolution, why, err := self.resolve(minute, record)
	if err != nil || resolution == nil {
		wait(why, err)
		return
	}
	switch resolution.State {
	case EvsResolveDead:
		_, slotIds, err := evacuateRecordObjects(record)
		if err != nil {
			// its slots cannot be read from it, so none is deleted: the record goes, as a dead one does
			self.alarm("evacuate_dead_record", placeKey(place), "a dead record of batch minute %d on cluster %s lists objects that do not parse: its slots stay", minute.minute, self.clusterId)
		}
		for _, slotId := range slotIds {
			minute.deadSlots = append(minute.deadSlots, &evacuateSlot{repoId: record.RepoId, slotId: slotId})
		}
		self.result.DeadCount += 1
	case EvsResolveCommitted:
		keep, version, err := self.committedHere(record, place, resolution)
		if err != nil {
			wait("committed record unread", err)
			return
		}
		if !keep {
			// committed at another place: this copy is dead weight, and nothing else goes with it (I-EVS-2)
			self.result.DuplicateCount += 1
			return
		}
		segmentIds, _, err := evacuateRecordObjects(record)
		if err != nil {
			// GC reads what a committed push introduced from its pidx/ entry, so a list that does not parse
			// must not be indexed as empty
			self.alarm("evacuate_kept_record", placeKey(place), "a committed record of batch minute %d on cluster %s lists objects that do not parse: it stays", minute.minute, self.clusterId)
			wait("record objects", nil)
			return
		}
		if !tail.Empty() {
			// format 2: each staged segment written or dropped, the record's own list swept, both before its batch
			// goes, and the record kept without its staged bytes
			if why, err := self.settleFormat2(minute, place, record, tail); why != "" {
				wait(why, err)
				return
			}
			recordBytes = sidecar.EvsBatchRecordBytesWithoutStaged(record, tail)
		}
		spoolOffset, err := self.spool.append(recordBytes)
		if err != nil {
			wait("spool", err)
			return
		}
		repo.kept = append(repo.kept, &evacuateKept{
			refId: record.RefId, version: version, place: place, spoolOffset: spoolOffset, segmentIds: segmentIds,
		})
		repo.keptByteCount += int64(len(recordBytes))
		minute.moveRepoIds[record.RepoId] = true
		self.result.KeptCount += 1
	default:
		wait(why, nil)
	}
}

// The ref's head as the run holds it: read from the cluster once a run, and replaced by a fence's write. A cached
// head settles a record for good when it shows the push committed or dead, and a pending one is fenced and read
// again, so a head read earlier in the run decides nothing a later read would not.
func (self *evacuateRun) refHead(repoId sidecar.Id, refId sidecar.Id) (*EvsStoredHead, error) {
	refKey := barrierRefKey(repoId, refId)
	if head, ok := self.refHeads[refKey]; ok {
		return head, nil
	}
	head, err := self.evacuator.heads.ReadCluster(self.ctx, self.cluster, repoId, refId)
	if err != nil {
		return nil, err
	}
	self.refHeads[refKey] = head
	return head, nil
}

// One log page of a ref for Resolve: this process's cache, log/, or, once packed, its pack through pidx/.
func (self *evacuateRun) readLogPage(ctx context.Context, repoId sidecar.Id, refId sidecar.Id, page uint64) (*LogPage, error) {
	evacuator := self.evacuator
	logPage, err := ReadLogPage(ctx, evacuator.logPages, self.cluster, repoId, refId, page)
	if !errors.Is(err, ErrEvsRecordEvacuated) {
		return logPage, err
	}
	pageBytes, err := evacuator.locator.ReadLogPage(ctx, self.cluster, repoId, refId, page)
	if err != nil {
		return nil, err
	}
	logPage, err = ParseLogPage(repoId, refId, page, pageBytes)
	if err != nil {
		return nil, err
	}
	evacuator.logPages.Put(self.cluster.ClusterId(), repoId, refId, logPage)
	return logPage, nil
}

// Resolve's answer for record, a pending one fenced and resolved again. A nil resolution, or one still pending,
// leaves the record where it is, for why.
func (self *evacuateRun) resolve(minute *evacuateMinute, record *sidecar.EvsBatchRecord) (*EvsResolution, string, error) {
	readPage := func(ctx context.Context, page uint64) (*LogPage, error) {
		return self.readLogPage(ctx, record.RepoId, record.RefId, page)
	}
	head, err := self.refHead(record.RepoId, record.RefId)
	if err != nil {
		return nil, "head unread", err
	}
	resolution, err := ResolveBatchRecord(self.ctx, record, head.Head, readPage)
	if err != nil {
		return nil, "resolve", err
	}
	if resolution.State != EvsResolvePending {
		return resolution, "", nil
	}

	// A ref with no head is fenced like any other: RaiseFence creates the placeholder head with its fence raised
	// (DESIGN-DETAILS 2.2.3), so a pending record always has a head to be resolved again on.
	refKey := barrierRefKey(record.RepoId, record.RefId)
	if clockCheck := self.evacuator.host.ClockCheck; clockCheck == nil || !clockCheck.Sure() {
		return resolution, "pending while the clock is unsure", nil
	}
	fenced, err := self.fence(minute, record.RepoId, record.RefId, head)
	switch {
	case errors.Is(err, ErrEvsClockUnsure):
		return resolution, "pending while the clock is unsure", nil
	case errors.Is(err, ErrEvsHeadBusy), errors.Is(err, errEvacuateRepoWaits):
		return resolution, "pending, its fence not raised", nil
	case err != nil:
		return nil, "fence", err
	}
	self.refHeads[refKey] = fenced
	self.result.FenceCount += 1
	resolution, err = ResolveBatchRecord(self.ctx, record, fenced.Head, readPage)
	if err != nil {
		return nil, "resolve", err
	}
	return resolution, "pending past its ref's fence", nil
}

// Raises the ref's fence for a pending record: one head CAS that sets fence_ms, paid as the minute's work (§11.13's
// order row: a fence goes with the work that raises it). A ref with no head pays for a create, of the placeholder
// head the fence makes (DESIGN-DETAILS 2.4), and any other for an overwrite of the head it has.
func (self *evacuateRun) fence(minute *evacuateMinute, repoId sidecar.Id, refId sidecar.Id, head *EvsStoredHead) (*EvsStoredHead, error) {
	operation := WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(len(head.Bytes)), Count: 1}
	if head.Absent() {
		operation = WriteOperation{Kind: WriteOperationCreate, ObjectByteCount: evsFencePlaceholderByteCount, Count: 1}
	}
	grant, err := self.acquire(minute.minute, operation,
		func(ctx context.Context) error { return self.recheckMove(ctx, repoId) })
	if err != nil {
		return nil, err
	}
	defer grant.Close()
	refKey := barrierRefKey(repoId, refId)
	testHookBarrier(BarrierEvacuateFenceBefore, refKey)
	if err := self.stop(BarrierEvacuateFenceBefore, refKey); err != nil {
		return nil, err
	}
	fenced, err := self.evacuator.heads.RaiseFence(grant.Context(), self.cluster, repoId, refId)
	if err != nil {
		return nil, err
	}
	testHookBarrier(BarrierEvacuateFenceAfter, refKey)
	if err := self.stop(BarrierEvacuateFenceAfter, refKey); err != nil {
		return nil, err
	}
	return fenced, nil
}

// Whether a committed record is the copy its ref's history names, and the version it committed at: a push or seal
// at the place its version's entry names; a part when its committed seal's record names its place; a reseed at the
// version its ref's history names its push at.
func (self *evacuateRun) committedHere(record *sidecar.EvsBatchRecord, place *protocol.EvsPlace, resolution *EvsResolution) (bool, uint64, error) {
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PART:
		named, err := self.sealNamesPart(record, place, resolution.Place)
		return named, resolution.Version, err
	case protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		statement, err := EvsBatchRecordStatement(record)
		if err != nil {
			return false, 0, err
		}
		head, err := self.refHead(record.RepoId, record.RefId)
		if err != nil {
			return false, 0, err
		}
		push := statement.Push
		gitMode := protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT
		standing, err := EvsPushStandingIn(self.ctx, head.Head, record.PushId, statement.Sha256, push.GetBaseVersion(), gitMode,
			func(ctx context.Context, page uint64) (*LogPage, error) {
				return self.readLogPage(ctx, record.RepoId, record.RefId, page)
			})
		if err != nil {
			return false, 0, err
		}
		if !standing.Committed {
			// committed by rule, at a version nothing here can name: it stays until EVSB-M2-20's re-seed says
			// how its ref's history names it
			return false, 0, fmt.Errorf("%w: a reseed record its ref's history does not name", errEvacuateRepoWaits)
		}
		return true, standing.Version, nil
	}
	return placesEqual(resolution.Place, place), resolution.Version, nil
}

// Whether the committed seal at sealPlace names the part at place: parts follow their seal, and a part posted
// twice leaves one copy the seal does not name.
func (self *evacuateRun) sealNamesPart(record *sidecar.EvsBatchRecord, place *protocol.EvsPlace, sealPlace *protocol.EvsPlace) (bool, error) {
	if sealPlace == nil {
		return false, fmt.Errorf("%w: a committed part with no seal place", sidecar.ErrEvsPushInvalid)
	}
	sealKey := placeKey(sealPlace)
	partKeys, ok := self.sealParts[sealKey]
	if !ok {
		sealBytes, err := self.evacuator.locator.ReadRecord(self.ctx, self.cluster, record.RepoId, record.RefId, sealPlace)
		if err != nil {
			return false, err
		}
		seal, err := sidecar.ParseEvsBatchRecord(sealBytes)
		if err != nil {
			return false, err
		}
		if seal.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL || seal.PushId != record.PushId {
			return false, fmt.Errorf("%w: a part whose push committed by a record that is not its seal", sidecar.ErrEvsPushInvalid)
		}
		_, parts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
		if err != nil {
			return false, err
		}
		partKeys = map[string]bool{}
		for _, part := range parts {
			partKeys[placeKey(part.Place)] = true
		}
		self.sealParts[sealKey] = partKeys
	}
	return partKeys[placeKey(place)], nil
}

// The segments a record introduces and the slots it lists as new, from its payload's or part's new-objects list
// and, for a part, its receipts (§11.8's record row). A seal lists none: its parts do.
func evacuateRecordObjects(record *sidecar.EvsBatchRecord) (segmentIds [][32]byte, slotIds []sidecar.Id, err error) {
	addNewObjects := func(payloadBytes []byte) error {
		if len(payloadBytes) == 0 {
			return nil
		}
		payload, err := sidecar.ParseEvsPayload(payloadBytes)
		if err != nil {
			return err
		}
		objects, err := sidecar.EvsDecodeNewObjects(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_NEW_OBJECTS))
		if err != nil {
			return err
		}
		for _, object := range objects {
			switch object.Kind {
			case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT:
				// a staged segment the record introduced is listed as introduced too, written to seg/ or not, so
				// orphan GC never takes one evacuation wrote (DESIGN-DETAILS 2.2.4)
				segmentIds = append(segmentIds, [32]byte(object.Id))
			case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT:
				slotIds = append(slotIds, sidecar.Id(object.Id))
			}
		}
		return nil
	}
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		_, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, nil, err
		}
		if err := addNewObjects(payloadBytes); err != nil {
			return nil, nil, err
		}
	case protocol.EvsBatchRecordType_EVS_BATCH_PART:
		_, partBytes, receipts, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
		if err != nil {
			return nil, nil, err
		}
		part := &protocol.EvsPushPart{}
		if err := proto.Unmarshal(partBytes, part); err != nil {
			return nil, nil, fmt.Errorf("%w: a part that does not parse", sidecar.ErrEvsPushInvalid)
		}
		if err := addNewObjects(part.GetSections()); err != nil {
			return nil, nil, err
		}
		for _, receiptBytes := range receipts {
			receipt := &protocol.EvsUploadReceipt{}
			if err := proto.Unmarshal(receiptBytes, receipt); err != nil || len(receipt.GetSegmentId()) != 32 {
				return nil, nil, fmt.Errorf("%w: a part's receipt that does not parse", sidecar.ErrEvsPushInvalid)
			}
			segmentId := [32]byte(receipt.GetSegmentId())
			known := false
			for _, id := range segmentIds {
				known = known || id == segmentId
			}
			if !known {
				segmentIds = append(segmentIds, segmentId)
			}
		}
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
	default:
		return nil, nil, sidecar.ErrEvsPushInvalid
	}
	return segmentIds, slotIds, nil
}
