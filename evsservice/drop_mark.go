// The drop job's mark (§11.13's mark row; D-EVS-64, I-EVS-15, FI-27, FS-91; DESIGN-DETAILS 10.2.8's round and Names,
// 8.3's G11; EVSB-M10-04): at a round's snapshot M_r, taken after the round's horizon (F5), every live version of every
// ref of the repo marks the candidates it names, so the deletes never take what a committed version still needs.
//
//	refs     one LIST of head/<repo>/ once the job has read the round's horizon: file and git mode, shared and
//	         owned, creates-only, deposit and erasure refs, overlays and DELETE tombstones alike (owner decision 173);
//	         each ref's head read from the cluster, its version M_r[ref]; a held key is the store's 503, which stops
//	         the phase to wait and retry, so a ref is never skipped; a placeholder head has no version to scan
//	scan     each ref's pushes after M_{r-1}[ref] (from version 1 in round 1, and for a ref created since), each from
//	         its record as stored, a sealed push's from every part
//	Names    for each live entry version of the push, every segment id of a kind-1 or kind-5 locator and every slot
//	         id; on a git-mode ref also every segment id of the push's new-objects list, which names its history
//	         segments as nothing else does (G11)
//	live     an entry version is not live when a list file of the repo, any job's, holds its entry hash under a drop
//	         the job's liveness takes as executed (covered and not refused, done or held, or gone from the table with
//	         no void record), or, for a dry run, when its paths list it; every other version is live
//	marks    only grow: the marks so far are every mark file's ids, and each checkpoint, at most once a
//	         CheckpointInterval and at the end, writes the next sequence with the ids marked since the last and the
//	         scan's cursor, the ref and version it reached
//
// Ids are compared, never decrypted. A round run again after a kill scans every ref from M_{r-1} again with its marks
// kept: a resume past refs read before the round's new horizon would break F4 before F5, so the cursor records where a
// scan reached and no run starts from it. Reads are paced to the job's 32 MB/s and renew its lease.
//
// Safe for concurrent use: each call holds its own state; the caches beneath are.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What a mark runs on beyond its host.
type DropMarkDeps struct {
	// nil: the defaults.
	Settings    *DropSettings
	EvsSettings *EvsSettings
	// What a run did. nil discards.
	Log sidecar.Logger
}

// See the file header.
type DropMark struct {
	host     *sidecar.ServiceHost
	settings *DropSettings
	log      sidecar.Logger
	clock    sidecar.Clock
	records  *RecordCache
	locator  *RecordLocator
	logPages *LogPageCache
}

// A mark on host, which needs Blobs.
func NewDropMark(host *sidecar.ServiceHost, deps *DropMarkDeps) (*DropMark, error) {
	if host == nil || host.Blobs == nil {
		return nil, errors.New("evs's drop mark needs a host with Blobs")
	}
	if deps == nil {
		deps = &DropMarkDeps{}
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
	return &DropMark{
		host:     host,
		settings: settings,
		log:      log,
		clock:    host.ClockOrReal(),
		records:  NewRecordCache(evsSettings),
		locator:  NewRecordLocator(host.Blobs, nil),
		logPages: NewLogPageCache(evsSettings),
	}, nil
}

// One mark's checkpoints: the ids marked since the last, the cursor, and the next mark file's sequence.
type dropMarkCheckpoints struct {
	ctx      context.Context
	files    *DropFiles
	settings *DropSettings
	repoId   sidecar.Id
	jobId    sidecar.Id
	sequence uint32
	pending  []DropScanId
	refId    sidecar.Id
	version  uint64
	last     time.Time
}

// Writes the pending marks with the cursor as the next mark files, FileRowCount ids a file, each carrying the cursor.
func (self *dropMarkCheckpoints) write(now time.Time) error {
	self.last = now
	for 0 < len(self.pending) {
		chunk := self.pending[:min(len(self.pending), self.settings.FileRowCount)]
		encoded := EncodeDropMarkFile(self.repoId, self.jobId, self.sequence, self.refId, self.version, chunk)
		if err := self.files.Put(self.ctx, DropFileMark, self.sequence, encoded); err != nil {
			return err
		}
		self.sequence += 1
		self.pending = self.pending[len(chunk):]
	}
	return nil
}

// Mark (EVSB-M10-04): see the file header.
func (self *DropMark) Mark(ctx context.Context, request *DropMarkRequest) (*DropMarkResult, error) {
	result := &DropMarkResult{Snapshot: map[sidecar.Id]uint64{}}
	if request.Cluster == nil || request.SegmentCluster == nil {
		return result, fmt.Errorf("%w: a mark with no clusters", ErrDropJobState)
	}
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.JobId, self.settings)
	candidates, err := files.Candidates(ctx)
	if err != nil {
		return result, err
	}
	marks, _, _, err := files.Marks(ctx)
	if err != nil {
		return result, err
	}
	unmarked := map[DropScanId]bool{}
	for _, candidate := range candidates {
		if !marks[candidate.DropScanId] {
			unmarked[candidate.DropScanId] = true
		}
	}
	notLive, byteCount, err := self.notLive(ctx, request)
	result.ScanByteCount += byteCount
	if err != nil {
		return result, err
	}
	sequence, err := files.NextSequence(ctx, DropFileMark)
	if err != nil {
		return result, err
	}
	checkpoints := &dropMarkCheckpoints{
		ctx: ctx, files: files, settings: self.settings, repoId: request.RepoId, jobId: request.JobId, sequence: sequence,
		last: self.clock.Now(),
	}
	repoKey := barrierRepoKey(request.RepoId)
	testHookBarrier(BarrierDropRefsBefore, repoKey)
	refIds, err := dropListRefs(ctx, request.Cluster, request.RepoId, self.settings)
	testHookBarrier(BarrierDropRefsAfter, repoKey)
	if err != nil {
		return result, err
	}
	for _, refId := range refIds {
		refKey := barrierRefKey(request.RepoId, refId)
		testHookBarrier(BarrierDropHeadBefore, refKey)
		head, err := dropReadHead(ctx, request.Cluster, request.RepoId, refId)
		testHookBarrier(BarrierDropHeadAfter, refKey)
		if err != nil {
			return result, err
		}
		if head == nil {
			continue
		}
		result.Snapshot[refId] = head.GetVersion()
		if len(unmarked) == 0 || head.GetVersion() <= request.Since[refId] {
			continue
		}
		byteCount, err := self.markRef(ctx, request, refId, head, unmarked, notLive, checkpoints)
		result.ScanByteCount += byteCount
		if err != nil {
			return result, err
		}
	}
	if err := checkpoints.write(self.clock.Now()); err != nil {
		return result, err
	}
	return result, nil
}

// The entry hashes that mark nothing: a dry run's listed versions, and each row a list file of the repo holds under a
// drop the request's liveness takes as executed. nil liveness takes none as executed, so every version marks.
func (self *DropMark) notLive(ctx context.Context, request *DropMarkRequest) (map[[32]byte]bool, int64, error) {
	notLive := map[[32]byte]bool{}
	for entrySha256 := range request.Listed {
		notLive[entrySha256] = true
	}
	listFiles, byteCount, err := ReadDropListFiles(ctx, request.SegmentCluster, request.RepoId, self.settings)
	if err != nil {
		return nil, byteCount, err
	}
	if request.Liveness == nil {
		return notLive, byteCount, nil
	}
	for _, file := range listFiles {
		executed := make([]bool, len(file.Drops))
		for i, drop := range file.Drops {
			executed[i] = request.Liveness.Executed(drop.DropId)
		}
		for _, row := range file.Rows {
			if executed[row.Drop] {
				notLive[row.EntrySha256] = true
			}
		}
	}
	return notLive, byteCount, nil
}

// One ref's pushes after M_{r-1} to head's version, marking each unmarked candidate its live versions name.
func (self *DropMark) markRef(ctx context.Context, request *DropMarkRequest, refId sidecar.Id, head *protocol.EvsHead, unmarked map[DropScanId]bool, notLive map[[32]byte]bool, checkpoints *dropMarkCheckpoints) (int64, error) {
	reader, err := newDropRefReader(ctx, request.Cluster, request.RepoId, refId, head, self.records, self.locator, self.logPages, request.Pace)
	if err != nil {
		return 0, err
	}
	gitMode := protocol.EvsRefMode(head.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT
	for version := request.Since[refId] + 1; version <= head.GetVersion() && 0 < len(unmarked); version += 1 {
		entry, _, err := reader.entryAt(version)
		if err != nil {
			return reader.byteCount, err
		}
		_, payload, err := reader.pushAt(version, entry)
		if err != nil {
			return reader.byteCount, fmt.Errorf("version %d of ref %s: %w", version, sidecar.EvsKeyId(refId), err)
		}
		names, err := DropNames(payload, gitMode, notLive)
		if err != nil {
			return reader.byteCount, fmt.Errorf("version %d of ref %s: %w", version, sidecar.EvsKeyId(refId), err)
		}
		for _, name := range names {
			if unmarked[name] {
				delete(unmarked, name)
				checkpoints.pending = append(checkpoints.pending, name)
			}
		}
		checkpoints.refId, checkpoints.version = refId, version
		if request.Renew != nil {
			if err := request.Renew(ctx); err != nil {
				return reader.byteCount, err
			}
		}
		if now := self.clock.Now(); self.settings.CheckpointInterval <= now.Sub(checkpoints.last) {
			if err := checkpoints.write(now); err != nil {
				return reader.byteCount, err
			}
		}
	}
	return reader.byteCount, nil
}

// What a committed push names (DESIGN-DETAILS 10.2.8's Names): for each entry version it writes whose entry hash
// notLive does not hold, every segment id of a kind-1 or kind-5 locator and every slot id; and on a git-mode ref,
// every segment id of its new-objects list, a git push's history segments, which no entry version names (G11). In the
// order met, repeats kept.
func DropNames(payload *sidecar.EvsCheckedPayload, gitMode bool, notLive map[[32]byte]bool) ([]DropScanId, error) {
	names := []DropScanId{}
	for _, change := range payload.Changes {
		if len(change.EntryVersion) == 0 {
			continue
		}
		if entryHash := change.Change.GetEntrySha256(); len(entryHash) == 32 && notLive[[32]byte(entryHash)] {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			return nil, fmt.Errorf("%w: an entry version that does not parse", ErrEvsStatementMismatch)
		}
		for _, locator := range entry.GetChain() {
			switch locator.GetKind() {
			case uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT):
				if len(locator.GetId()) == 32 {
					names = append(names, DropSegmentId([32]byte(locator.GetId())))
				}
			}
		}
		for _, slotId := range entry.GetSlotIds() {
			if len(slotId) == 16 {
				names = append(names, DropSlotId(sidecar.Id(slotId)))
			}
		}
	}
	if gitMode {
		for _, object := range payload.NewObjects {
			switch object.Kind {
			case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT:
				if len(object.Id) == 32 {
					names = append(names, DropSegmentId([32]byte(object.Id)))
				}
			}
		}
	}
	return names, nil
}

// The repo's refs, by one LIST of head/<repo>/, in id order.
func dropListRefs(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, settings *DropSettings) ([]sidecar.Id, error) {
	prefix := HeadRepoPrefix(repoId)
	refIds := []sidecar.Id{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, prefix, startAfter, settings.ListLimit)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			rest := strings.TrimPrefix(object.Key, prefix)
			refId, err := parseEvsHexId(rest)
			if err != nil || HeadKey(repoId, refId) != object.Key {
				continue
			}
			refIds = append(refIds, refId)
		}
		if !more || len(objects) == 0 {
			break
		}
		startAfter = objects[len(objects)-1].Key
	}
	slices.SortFunc(refIds, func(a sidecar.Id, b sidecar.Id) int { return strings.Compare(sidecar.EvsKeyId(a), sidecar.EvsKeyId(b)) })
	return refIds, nil
}
