// §11.6's copy row (D-EVS-12, FI-1, FI-6, FS-4; EVS1-M2-17): taskworker's job evs.epoch_copy, one per ref and epoch,
// which moves the entries a PATH_EPOCH left in its sources into the new current epoch, so the sources drain, then
// drops them by a fence write. It is P2 work of rank copy, unfunded (§11.13): each write is paid before it is issued
// and rereads repo/ as it issues.
//
//	moves    the newest map's moves, from the parts at pmap/<repo>/<ref>/<p>/<map>/ that the head's newest source
//	         names, and the PATH_EPOCH push's tail, in descending token-path order, so a directory moves after its
//	         children: each reads the entry from the newest source holding it, keeps its folded versions, marker and
//	         drop mark, rewrites a directory's rows from its children's moves, each row matched in its own epoch, PUTs
//	         it If-None-Match, carried from that source, and deletes every source copy, only once the new one exists
//	412      a current entry already there: a file's, a removed or a fresh one is done, its source copies deleted
//	         unmoved; a carried directory's carried rows are translated and the entry PUT If-Match, read again on 412
//	prefixes after each PUT the path's prefixes' current entries are HEADed, and under a removed or fresh one what it
//	         put becomes a marker, If-Match on that PUT's ETag; on 412 the newer entry stands
//	pace     at most CopyRepoOpsPerSecond operations a second on the repo, CopyRepoSourcesOpsPerSecond while two or
//	         more sources stand, and the process's share of its cluster's copy rate (WriteBudget.CopyOpsPerSecond)
//	head     reread at least every CopyHeadRereadInterval; every write carries §11.7's stale deadline, FoldStaleDeadline
//	         after the head read it relies on, and relies only on a head still listing the sources it moves from; a
//	         head whose current epoch passed the job's is a newer map's, which supersedes this job
//	end      LIST idx/<repo>/<ref>/<p_i>/ for each source: a marker there is deleted unmoved; any other entry, or a
//	         carried row no move translated, is one the map missed, alarmed, its source kept listed; once every source
//	         is empty, one head CAS raising only the fence drops them (§11.8's fence row)
//	report   each run answers the moves it left, §19.8's copy liability (urnetwork_evs_path_epoch_moves_left)
//
// Every step is idempotent and resumes after a kill: a move whose current entry stands reads it and goes on, a
// source copy is deleted only once the new copy exists, and the drop rereads the head. A run makes at most
// CopyRunMoveCount moves that write and queues its successor, which reads its way past the moves already made. Not
// built: a cursor between runs, so a successor reads every move made before it again; and the queue's order by sources
// held, then the oldest source (§11.6), since the task queue keeps no priority: copies run in queue order. Readings, named in the report: a child moved under a fresh prefix is marked with that prefix's newest
// version as its removal, since a re-creation keeps no marker (a fresh directory names none, and its child stays
// carried, which reads absent under it all the same); a PATH_EPOCH paged out of the window is looked for in at most
// CopyLogPageCount log pages, and without it the copy moves the map alone, the end's LIST keeping what the tail would
// have moved.

package evsservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The job's name in taskworker's registry.
const EvsEpochCopyTaskName = "evs.epoch_copy"

// A move read again past CopyMoveRetryCount times, or a fence write that lost FenceRetryCount races: the run ends, and
// its retry resumes.
var ErrEvsCopyBusy = errors.New("evs copy busy")

// An args body: repo id, ref id, then the epoch the copy moves into, 8 bytes big-endian.
const evsEpochCopyArgsByteCount = 16 + 16 + 8

// A copy job's args.
func EvsEpochCopyArgs(repoId sidecar.Id, refId sidecar.Id, epoch uint64) []byte {
	args := make([]byte, 0, evsEpochCopyArgsByteCount)
	args = append(args, repoId[:]...)
	args = append(args, refId[:]...)
	return binary.BigEndian.AppendUint64(args, epoch)
}

// What args name, or an error for args that name no copy.
func ParseEvsEpochCopyArgs(args []byte) (repoId sidecar.Id, refId sidecar.Id, epoch uint64, err error) {
	if len(args) != evsEpochCopyArgsByteCount {
		return sidecar.Id{}, sidecar.Id{}, 0, fmt.Errorf("evs copy args of %d bytes", len(args))
	}
	copy(repoId[:], args[:16])
	copy(refId[:], args[16:32])
	epoch = binary.BigEndian.Uint64(args[32:])
	if epoch < 2 {
		return sidecar.Id{}, sidecar.Id{}, 0, fmt.Errorf("evs copy into epoch %d", epoch)
	}
	return repoId, refId, epoch, nil
}

// The copy's queue entry: once-keyed by repo, ref and epoch, opaque ids only (I-13).
func EvsEpochCopyTaskRequest(repoId sidecar.Id, refId sidecar.Id, epoch uint64, runAt time.Time) *sidecar.TaskRequest {
	return &sidecar.TaskRequest{
		Name:    EvsEpochCopyTaskName,
		OnceKey: fmt.Sprintf("%s.%s.%s.%d", EvsEpochCopyTaskName, sidecar.EvsKeyId(repoId), sidecar.EvsKeyId(refId), epoch),
		Args:    EvsEpochCopyArgs(repoId, refId, epoch),
		RunAt:   runAt,
	}
}

// What a copy runs on beyond its host.
type EvsEpochCopyDeps struct {
	// nil: the defaults.
	Settings *EvsSettings
	// Alarms and the run's line. nil discards.
	Log sidecar.Logger
	// Called with each entry write's key before it is issued, for a test to land a fold's write first.
	beforeWrite func(key string)
}

// What one run did.
type EvsEpochCopyResult struct {
	// The repo's metadata cluster, which §19.8's moves-left series is labeled by.
	ClusterId string
	// Moves made: a new current entry PUT, or a carried directory's rows translated.
	MovedCount int
	// Moves found done: the current entry stood (412's rule), or no source held the path.
	DoneCount int
	// Entries turned into markers under a removed or fresh prefix.
	MarkedCount int
	// Source copies deleted.
	DeletedCount int
	// Entries or carried rows the map missed, alarmed, each keeping its source listed.
	MissedCount int
	// §19.8's copy liability: the moves this run left, 0 once every move is made.
	MovesLeft int64
	// A newer epoch's map superseded this job's, which ended doing nothing more.
	Superseded bool
	// The fence write dropped the drained sources.
	SourcesDropped bool
}

// One run of evs.epoch_copy: see the file header.
func RunPathEpochCopy(ctx context.Context, host *sidecar.ServiceHost, deps *EvsEpochCopyDeps, args []byte) (*EvsEpochCopyResult, error) {
	repoId, refId, epoch, err := ParseEvsEpochCopyArgs(args)
	if err != nil {
		return nil, err
	}
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's copy needs a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &EvsEpochCopyDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultEvsSettings()
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	priceTable, err := DefaultPriceTable(settings.PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	clock := host.ClockOrReal()
	blobs := NewBudgetedBlobs(host.Blobs)
	firstCluster, err := blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	place, err := sidecar.ReadEvsRepoPlace(ctx, firstCluster, repoId)
	if err != nil {
		return nil, err
	}
	cluster, err := blobs.Cluster(place.ClusterId)
	if err != nil {
		return nil, err
	}
	run := &copyRun{
		ctx:        ctx,
		host:       host,
		deps:       deps,
		settings:   settings,
		log:        log,
		clock:      clock,
		cluster:    cluster,
		priceTable: priceTable,
		heads:      NewHeadStore(clock, host.ClockCheck, nil, settings, log),
		repos:      NewRepoCache(clock, settings),
		records:    NewRecordCache(settings),
		logPages:   NewLogPageCache(settings),
		repoId:     repoId,
		refId:      refId,
		epoch:      epoch,
		startedAt:  clock.Now(),
		result:     &EvsEpochCopyResult{ClusterId: cluster.ClusterId()},
		barrierKey: barrierRefKey(repoId, refId),
	}
	if err := run.run(); err != nil {
		return run.result, err
	}
	return run.result, nil
}

// One move as the copy makes it: the path in the current epoch, in each listed source, and its re-sealed name.
type copyMove struct {
	newPath     sidecar.EvsTokenPath
	sourcePaths map[uint64]sidecar.EvsTokenPath
	sealedName  []byte
}

// One run's state. Not safe for concurrent use: it lives on its job's goroutine.
type copyRun struct {
	ctx        context.Context
	host       *sidecar.ServiceHost
	deps       *EvsEpochCopyDeps
	settings   *EvsSettings
	log        sidecar.Logger
	clock      sidecar.Clock
	cluster    sidecar.BlobCluster
	priceTable *PriceTable
	heads      *HeadStore
	repos      *RepoCache
	records    *RecordCache
	logPages   *LogPageCache
	repoId     sidecar.Id
	refId      sidecar.Id
	epoch      uint64
	startedAt  time.Time
	result     *EvsEpochCopyResult
	barrierKey string

	// the head the writes rely on, and when its cluster read was issued
	head       *EvsStoredHead
	headReadAt time.Time
	// the sources the head lists, newest first
	sourceEpochs []uint64
	moves        []*copyMove
	// each source epoch's moves by the path's token path there
	epochMoves map[uint64]map[string]*copyMove
	// the operations spent in the pacing window and when it opened
	windowStart time.Time
	windowCount int
}

// See the file header.
func (self *copyRun) run() error {
	if err := self.readHead(); err != nil {
		return err
	}
	if self.result.Superseded || len(self.sourceEpochs) == 0 {
		return nil
	}
	if err := self.loadMoves(); err != nil {
		return err
	}
	// descending token-path order: children before their directory
	slices.SortFunc(self.moves, func(a *copyMove, b *copyMove) int { return b.newPath.Compare(a.newPath) })
	// moves that wrote or deleted, which the run's bound counts, so each successor gets further: a move found done
	// costs only its reads
	workedCount := 0
	for i, move := range self.moves {
		if 0 < self.settings.CopyRunMoveCount && self.settings.CopyRunMoveCount <= workedCount {
			self.result.MovesLeft = int64(len(self.moves) - i)
			return self.queueSuccessor()
		}
		if err := self.ready(); err != nil {
			return err
		}
		if self.result.Superseded {
			self.result.MovesLeft = int64(len(self.moves) - i)
			return nil
		}
		writes := self.result.MovedCount + self.result.MarkedCount + self.result.DeletedCount
		if err := self.copyOne(move); err != nil {
			self.result.MovesLeft = int64(len(self.moves) - i)
			return err
		}
		if writes != self.result.MovedCount+self.result.MarkedCount+self.result.DeletedCount {
			workedCount += 1
		}
	}
	return self.finish()
}

// The head from the cluster, its sources and whether a newer map superseded this job's.
func (self *copyRun) readHead() error {
	readAt := self.clock.Now()
	head, err := self.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		return err
	}
	self.head = head
	self.headReadAt = readAt
	pathEpoch := head.Head.GetPathEpoch()
	if head.Absent() || EvsHeadCurrentEpoch(head.Head) != self.epoch {
		// another epoch is current: a newer map's job copies, or this epoch never committed
		self.result.Superseded = EvsHeadCurrentEpoch(head.Head) != self.epoch
		self.sourceEpochs = nil
		return nil
	}
	self.sourceEpochs = self.sourceEpochs[:0]
	for _, source := range pathEpoch.GetSources() {
		self.sourceEpochs = append(self.sourceEpochs, source.GetEpoch())
	}
	return nil
}

// Before each move: the head read again once CopyHeadRereadInterval passed, and the job ends superseded when a newer
// epoch is current. A head that no longer lists a source the moves read from ends the run too: its sources dropped.
func (self *copyRun) ready() error {
	if self.clock.Now().Sub(self.headReadAt) < self.settings.CopyHeadRereadInterval {
		return nil
	}
	listed := slices.Clone(self.sourceEpochs)
	if err := self.readHead(); err != nil {
		return err
	}
	if !self.result.Superseded && !slices.Equal(listed, self.sourceEpochs) {
		// another process dropped them, or a newer map's job took over: nothing here relies on a stale list
		self.result.Superseded = true
	}
	return nil
}

// The newest map's moves and the PATH_EPOCH push's tail.
func (self *copyRun) loadMoves() error {
	mapSha256 := self.head.Head.GetPathEpoch().GetSources()[0].GetMapSha256()
	moveItems := [][]byte{}
	parts := uint32(1)
	for part := uint32(1); part <= parts; part += 1 {
		if err := self.pace(); err != nil {
			return err
		}
		object, err := self.cluster.Get(self.ctx, PathMapKey(self.repoId, self.refId, self.epoch, mapSha256, part))
		if err != nil {
			return fmt.Errorf("the map's part %d: %w", part, err)
		}
		partBytes, err := readAllLimited(object, sidecar.EvsPathMapMaxByteCount)
		object.Body.Close()
		if err != nil {
			return err
		}
		_, pathMap, err := sidecar.ParseEvsPathMap(partBytes)
		if err != nil || sidecar.Id(pathMap.GetRepoId()) != self.repoId || sidecar.Id(pathMap.GetRefId()) != self.refId ||
			pathMap.GetPathEpoch() != self.epoch || pathMap.GetPart() != part {
			return fmt.Errorf("%w: a map part that is not this ref's", ErrEvsIndexEntryInvalid)
		}
		if part == 1 {
			parts = max(1, pathMap.GetParts())
		}
		for _, move := range pathMap.GetMoves() {
			moveBytes, err := proto.Marshal(move)
			if err != nil {
				return err
			}
			moveItems = append(moveItems, moveBytes)
		}
	}
	tail, found, err := self.tailMoves(mapSha256)
	if err != nil {
		return err
	}
	if !found {
		self.log.Errorf("[evs] alarm copy_tail: repo %s: no PATH_EPOCH to read the tail from; the map's moves alone", sidecar.EvsKeyId(self.repoId))
	}
	moveItems = append(moveItems, tail...)
	self.epochMoves = map[uint64]map[string]*copyMove{}
	seen := map[string]bool{}
	for _, item := range moveItems {
		pathMove := &protocol.EvsPathMove{}
		if err := proto.Unmarshal(item, pathMove); err != nil {
			return fmt.Errorf("%w: a move that does not parse", ErrEvsIndexEntryInvalid)
		}
		newPath, err := sidecar.ParseEvsChangedTokenPath(pathMove.GetNewTokenPath())
		if err != nil {
			return err
		}
		if seen[newPath.KeyString()] {
			continue
		}
		seen[newPath.KeyString()] = true
		move := &copyMove{newPath: newPath, sourcePaths: map[uint64]sidecar.EvsTokenPath{}, sealedName: pathMove.GetSealedName()}
		for _, source := range pathMove.GetSources() {
			if !slices.Contains(self.sourceEpochs, source.GetEpoch()) {
				continue
			}
			sourcePath, err := sidecar.ParseEvsChangedTokenPath(source.GetTokenPath())
			if err != nil {
				return err
			}
			move.sourcePaths[source.GetEpoch()] = sourcePath
			byPath := self.epochMoves[source.GetEpoch()]
			if byPath == nil {
				byPath = map[string]*copyMove{}
				self.epochMoves[source.GetEpoch()] = byPath
			}
			byPath[sourcePath.KeyString()] = move
		}
		self.moves = append(self.moves, move)
	}
	return nil
}

// The tail moves of the PATH_EPOCH that made this job's epoch current under mapSha256: from the window, else from at
// most evsCopyLogPageCount log pages before it. false when neither holds it.
func (self *copyRun) tailMoves(mapSha256 []byte) ([][]byte, bool, error) {
	matches := func(entry *sidecar.EvsWindowEntry) ([][]byte, bool, error) {
		if !entry.PathEpoch() {
			return nil, false, nil
		}
		record, err := ReadRecord(self.ctx, self.records, self.cluster, entry.Place)
		if err != nil {
			return nil, false, err
		}
		statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, false, err
		}
		statement, err := sidecar.ParseEvsStatement(statementBytes)
		if err != nil {
			return nil, false, err
		}
		push := statement.Push
		if push.GetPathEpoch() != self.epoch || !bytes.Equal(push.GetPathMapSha256(), mapSha256) {
			return nil, false, nil
		}
		payload, err := sidecar.EvsCheckPayload(statement, payloadBytes)
		if err != nil {
			return nil, false, err
		}
		return payload.TailMoves, true, nil
	}
	window, err := EvsHeadWindow(self.head.Head)
	if err != nil {
		return nil, false, err
	}
	for i := len(window) - 1; 0 <= i; i -= 1 {
		if tail, ok, err := matches(window[i]); err != nil || ok {
			return tail, ok, err
		}
	}
	first := EvsHeadWindowFirstVersion(self.head.Head)
	if first <= 1 {
		return nil, false, nil
	}
	page := EvsLogPageOf(first - 1)
	for count := 0; count < self.settings.CopyLogPageCount; count += 1 {
		logPage, err := ReadLogPage(self.ctx, self.logPages, self.cluster, self.repoId, self.refId, page)
		if err != nil {
			return nil, false, err
		}
		low, high := EvsLogPageVersions(page)
		for version := high; low <= version && 0 < version; version -= 1 {
			entry, _, ok := logPage.At(version)
			if !ok {
				continue
			}
			if tail, ok, err := matches(entry); err != nil || ok {
				return tail, ok, err
			}
		}
		if page == 0 {
			break
		}
		page -= 1
	}
	return nil, false, nil
}

// Waits out the pacing window when this run spent its rate there: the repo's, faster while two or more sources stand,
// and never past the process's share of the cluster's copy rate.
func (self *copyRun) pace() error {
	rate := self.settings.CopyRepoOpsPerSecond
	if 2 <= len(self.sourceEpochs) {
		rate = self.settings.CopyRepoSourcesOpsPerSecond
	}
	if share := self.host.Budget.CopyOpsPerSecond(self.cluster.ClusterId()); 0 < share {
		rate = min(rate, share)
	}
	rate = max(1, rate)
	now := self.clock.Now()
	if self.windowStart.IsZero() || time.Second <= now.Sub(self.windowStart) {
		self.windowStart = now
		self.windowCount = 0
	}
	if rate <= self.windowCount {
		wait := self.windowStart.Add(time.Second).Sub(now)
		select {
		case <-self.ctx.Done():
			return self.ctx.Err()
		case <-self.clock.After(wait):
		}
		self.windowStart = self.clock.Now()
		self.windowCount = 0
	}
	self.windowCount += 1
	return nil
}

// One move: see the file header's moves, 412 and prefixes rows.
func (self *copyRun) copyOne(move *copyMove) error {
	for attempt := 0; attempt < self.settings.CopyMoveRetryCount; attempt += 1 {
		if err := self.pace(); err != nil {
			return err
		}
		current, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, self.epoch, move.newPath, self.head.Head.GetFoldedThrough())
		if err != nil {
			return err
		}
		source, sourceEpoch, err := self.newestSource(move)
		if err != nil {
			return err
		}
		switch {
		case source == nil && !current.Absent():
			// moved before, its sources deleted
			self.result.DoneCount += 1
			return nil
		case source == nil:
			// no epoch holds it: removed and collected, or never folded
			self.result.DoneCount += 1
			return nil
		case !current.Absent():
			done, err := self.settleCurrent(move, current)
			if err != nil {
				return err
			}
			if !done {
				continue
			}
			return self.deleteSources(move)
		}
		entry := self.translated(move, source.Entry, sourceEpoch, carryEvsIndexEntry)
		etag, err := self.put(move.newPath, current, entry, EvsEntryStateValue{State: EvsEntryStateCarried, Epoch: sourceEpoch})
		if retryEntryWrite(err) {
			continue
		}
		if err != nil {
			return err
		}
		self.result.MovedCount += 1
		if err := self.markUnderPrefixes(move, etag, entry, sourceEpoch); err != nil {
			return err
		}
		return self.deleteSources(move)
	}
	return fmt.Errorf("%w: %d tries on one move", ErrEvsCopyBusy, self.settings.CopyMoveRetryCount)
}

// The entry of the newest source holding the move's path, its epoch, or nil when none does.
func (self *copyRun) newestSource(move *copyMove) (*EvsEntryRead, uint64, error) {
	for _, epoch := range self.sourceEpochs {
		sourcePath, ok := move.sourcePaths[epoch]
		if !ok {
			continue
		}
		if err := self.pace(); err != nil {
			return nil, 0, err
		}
		read, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, epoch, sourcePath, self.head.Head.GetFoldedThrough())
		if err != nil {
			return nil, 0, err
		}
		if !read.Absent() {
			return read, epoch, nil
		}
	}
	return nil, 0, nil
}

// 412's rule for a current entry that stands: true when the move is done, false to read again after a 412 of its own.
// A carried directory's carried rows are translated by an If-Match PUT; anything else is done as it is.
func (self *copyRun) settleCurrent(move *copyMove, current *EvsEntryRead) (bool, error) {
	if current.State.State != EvsEntryStateCarried || current.Entry.GetNames() == nil || current.Entry.GetMarker() != nil {
		self.result.DoneCount += 1
		return true, nil
	}
	translated := self.translated(move, current.Entry, 0, nil)
	if proto.Equal(translated, current.Entry) {
		self.result.DoneCount += 1
		return true, nil
	}
	_, err := self.put(move.newPath, current, translated, current.State)
	if retryEntryWrite(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	self.result.MovedCount += 1
	return true, nil
}

// An entry of directory's move as the current epoch holds it: carry, when given, first tags a source entry's untagged
// rows with sourceEpoch; then each carried row a move names in its row's epoch becomes that move's row in the current
// epoch, untagged, with its re-sealed name. A carried row no move names stays carried, and counts as one the map
// missed.
func (self *copyRun) translated(directory *copyMove, entry *protocol.EvsIndexEntry, sourceEpoch uint64, carry func(*protocol.EvsIndexEntry, uint64) *protocol.EvsIndexEntry) *protocol.EvsIndexEntry {
	var next *protocol.EvsIndexEntry
	if carry != nil {
		next = carry(entry, sourceEpoch)
	} else {
		next = proto.Clone(entry).(*protocol.EvsIndexEntry)
	}
	table := next.GetNames()
	if table == nil {
		return next
	}
	rows := []*protocol.EvsName{}
	for _, row := range table.GetNames() {
		if row.GetEpoch() == 0 {
			rows = append(rows, row)
			continue
		}
		child := self.childMove(directory, row)
		if child == nil {
			self.result.MissedCount += 1
			rows = append(rows, row)
			continue
		}
		rows = append(rows, &protocol.EvsName{
			Token:      child.newPath.Last().Bytes(),
			Kind:       row.GetKind(),
			SealedName: bytes.Clone(child.sealedName),
		})
	}
	slices.SortFunc(rows, func(a *protocol.EvsName, b *protocol.EvsName) int { return bytes.Compare(a.GetToken(), b.GetToken()) })
	table.Names = rows
	return next
}

// The move of the child a carried row names: the directory's own path in the row's epoch, which the directory's move
// gives, joined with the row's token, among that epoch's moves. nil when none is.
func (self *copyRun) childMove(directory *copyMove, row *protocol.EvsName) *copyMove {
	token, err := sidecar.EvsTokenFromBytes(row.GetToken())
	if err != nil {
		return nil
	}
	directoryPath, ok := directory.sourcePaths[row.GetEpoch()]
	if !ok {
		return nil
	}
	childPath := append(slices.Clone(directoryPath), token)
	return self.epochMoves[row.GetEpoch()][childPath.KeyString()]
}

// One entry write, paid for as P2 copy work, rereading repo/ as it issues, with §11.7's stale deadline: If-None-Match
// where prior is absent, else If-Match its ETag. The written ETag.
func (self *copyRun) put(tokenPath sidecar.EvsTokenPath, prior *EvsEntryRead, entry *protocol.EvsIndexEntry, state EvsEntryStateValue) (string, error) {
	if err := self.pace(); err != nil {
		return "", err
	}
	operation := WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(proto.Size(entry)), Count: 1}
	if prior.Absent() {
		operation.Kind = WriteOperationCreate
	}
	price, err := self.priceTable.Price(operation)
	if err != nil {
		return "", err
	}
	grant, err := self.acquire(price)
	if err != nil {
		return "", err
	}
	defer grant.Close()
	writeCtx := sidecar.WithBlobDeadline(grant.Context(), self.headReadAt.Add(self.settings.FoldStaleDeadline))
	if self.deps.beforeWrite != nil {
		self.deps.beforeWrite(IndexEntryKey(self.repoId, self.refId, self.epoch, tokenPath))
	}
	testHookBarrier(BarrierCopyMoveBefore, self.barrierKey)
	etag, err := PutEntry(writeCtx, self.cluster, self.repoId, self.refId, self.epoch, tokenPath, prior, entry, state)
	testHookBarrier(BarrierCopyMoveAfter, self.barrierKey)
	return etag, err
}

// The P2 grant one write spends, rereading repo/ as it issues (§11.13's skip row): active or deleted.
func (self *copyRun) acquire(byteCount int64) (sidecar.WriteGrant, error) {
	return self.host.Budget.AcquireP2(self.ctx, self.cluster.ClusterId(), &sidecar.WriteP2Work{
		Rank:      sidecar.WriteP2RankCopy,
		Due:       self.startedAt,
		ByteCount: byteCount,
		Recheck: func(ctx context.Context) error {
			read, err := self.repos.Read(ctx, self.cluster, self.repoId)
			if err != nil {
				return err
			}
			switch read.Object.GetState() {
			case protocol.EvsRepoState_EVS_REPO_ACTIVE, protocol.EvsRepoState_EVS_REPO_DELETED:
				return nil
			}
			return fmt.Errorf("%w: state %s", ErrEvsFoldRepoState, read.Object.GetState())
		},
	})
}

// The prefixes row: under a removed or fresh prefix in the current epoch, what the move put becomes a marker by
// If-Match on its ETag, a 412 leaving the newer entry standing.
func (self *copyRun) markUnderPrefixes(move *copyMove, etag string, entry *protocol.EvsIndexEntry, sourceEpoch uint64) error {
	for length := 1; length < len(move.newPath); length += 1 {
		if err := self.pace(); err != nil {
			return err
		}
		state, found, err := HeadEntryState(self.ctx, self.cluster, self.repoId, self.refId, self.epoch, move.newPath[:length])
		if err != nil {
			return err
		}
		if !found || (state.State != EvsEntryStateRemoved && state.State != EvsEntryStateFresh) {
			continue
		}
		prefix, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, self.epoch, move.newPath[:length], self.head.Head.GetFoldedThrough())
		if err != nil || prefix.Absent() {
			return err
		}
		pushId, removalVersion := prefixRemoval(prefix.Entry)
		if removalVersion == 0 || removalVersion <= evsIndexEntryNewestCommit(entry) {
			return nil
		}
		standing, ok := evsIndexEntryStanding(entry, 0)
		if !ok {
			return nil
		}
		marked := proto.Clone(entry).(*protocol.EvsIndexEntry)
		marked.Marker = &protocol.EvsRemovalMarker{PushId: pushId, RemovalVersion: removalVersion, PathVersion: standing + 1}
		written := &EvsEntryRead{Entry: entry, Etag: etag}
		_, err = self.put(move.newPath, written, marked, EvsEntryStateValue{State: EvsEntryStateRemoved})
		if errors.Is(err, sidecar.ErrBlobPrecondition) {
			// a newer entry stands
			return nil
		}
		if err != nil {
			return err
		}
		self.result.MarkedCount += 1
		return nil
	}
	return nil
}

// The removal a prefix stands for: a removed one's marker, or a fresh one's newest version, which its re-creation
// committed after the removal (a reading: a re-creation keeps no marker). 0 for none.
func prefixRemoval(prefix *protocol.EvsIndexEntry) ([]byte, uint64) {
	if marker := prefix.GetMarker(); marker != nil {
		return marker.GetPushId(), marker.GetRemovalVersion()
	}
	if versions := prefix.GetVersions(); 0 < len(versions) {
		return versions[0].GetPushId(), versions[0].GetCommitVersion()
	}
	return nil, 0
}

// Deletes every source copy of the move's path, once its current copy stands.
func (self *copyRun) deleteSources(move *copyMove) error {
	for _, epoch := range self.sourceEpochs {
		sourcePath, ok := move.sourcePaths[epoch]
		if !ok {
			continue
		}
		if err := self.deleteKey(IndexEntryKey(self.repoId, self.refId, epoch, sourcePath)); err != nil {
			return err
		}
	}
	return nil
}

// One delete, paid for as P2 copy work.
func (self *copyRun) deleteKey(key string) error {
	if err := self.pace(); err != nil {
		return err
	}
	price, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationDelete, Count: 1})
	if err != nil {
		return err
	}
	grant, err := self.acquire(price)
	if err != nil {
		return err
	}
	defer grant.Close()
	if err := self.cluster.Delete(sidecar.WithBlobDeadline(grant.Context(), self.headReadAt.Add(self.settings.FoldStaleDeadline)), key); err != nil {
		return err
	}
	self.result.DeletedCount += 1
	return nil
}

// The end row: each source's entries LISTed, markers deleted unmoved, anything else alarmed as missed; then, every
// source empty and nothing missed, the fence write that drops them.
func (self *copyRun) finish() error {
	drained := true
	for _, epoch := range self.sourceEpochs {
		epochPrefix := IndexEpochPrefix(self.repoId, self.refId, epoch)
		startAfter := ""
		for {
			if err := self.pace(); err != nil {
				return err
			}
			objects, more, err := self.cluster.List(self.ctx, epochPrefix, startAfter, self.settings.CopyListPageCount)
			if err != nil {
				return err
			}
			for _, object := range objects {
				startAfter = object.Key
				tokenPath, err := IndexEntryTokenPath(epochPrefix, object.Key)
				if err != nil {
					continue
				}
				read, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, epoch, tokenPath, self.head.Head.GetFoldedThrough())
				if err != nil {
					return err
				}
				if read.Absent() {
					continue
				}
				if read.Entry.GetMarker() != nil {
					if err := self.deleteKey(object.Key); err != nil {
						return err
					}
					continue
				}
				self.result.MissedCount += 1
				drained = false
				self.log.Errorf("[evs] alarm copy_missed: repo %s ref %s: an entry of source %d no move took", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(self.refId), epoch)
			}
			if !more || len(objects) == 0 {
				break
			}
		}
	}
	if !drained || 0 < self.result.MissedCount {
		return nil
	}
	return self.dropSources()
}

// One head CAS raising only the fence, dropping the sources this run drained, on a head that still lists exactly
// them; a 412 rereads, at most FenceRetryCount times; an unknown outcome rereads and finds whether it landed.
func (self *copyRun) dropSources() error {
	drained := slices.Clone(self.sourceEpochs)
	for attempt := 0; attempt <= self.settings.FenceRetryCount; attempt += 1 {
		if err := self.readHead(); err != nil {
			return err
		}
		if self.result.Superseded || len(self.sourceEpochs) == 0 {
			return nil
		}
		if !slices.Equal(self.sourceEpochs, drained) {
			// the head lists other sources now: a newer epoch's copy drops its own
			return nil
		}
		price, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(len(self.head.Bytes)), Count: 1})
		if err != nil {
			return err
		}
		grant, err := self.acquire(price)
		if err != nil {
			return err
		}
		next := CloneEvsHead(self.head.Head)
		next.Fence = self.head.Head.GetFence() + 1
		next.PathEpoch = CloneEvsPathEpoch(self.head.Head.GetPathEpoch())
		next.PathEpoch.Sources = nil
		_, err = self.heads.Commit(sidecar.WithBlobDeadline(grant.Context(), self.headReadAt.Add(self.settings.FoldStaleDeadline)), self.cluster, self.repoId, self.refId, self.head, next)
		grant.Close()
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			self.result.SourcesDropped = true
			return nil
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
		default:
			return err
		}
	}
	return ErrEvsCopyBusy
}

// Queues this copy again, its next run resuming where the store shows it.
func (self *copyRun) queueSuccessor() error {
	if self.host.Tasks == nil {
		return errors.New("evs's copy needs a task queue to go on")
	}
	return self.host.Tasks.Schedule(self.ctx, EvsEpochCopyTaskRequest(self.repoId, self.refId, self.epoch, self.clock.Now()))
}
