//go:build !ios_extension

// The path-epoch mapper (DESIGN-DETAILS 9.2.7, 9.2.2's map and tail rows; D-EVS-12, FS-4; owner decision 114;
// EVS1-M2-47): a writer that holds every name of a ref builds a signed map of every live path's tokens in the new
// epoch, uploads its parts, and commits them by a PATH_EPOCH push, after which evs's copy job moves each entry.
//
//	eligible  a device that writes the repo, on a shared or owned ref, with an index of every name: one registered
//	          for the ref (a mirror's, RegisterNameIndex), else the listed index; on a phone only while the index
//	          holds at most MobileMapNameCount names. Wrapped agents are eligible on the same terms
//	tick      on a new generation, a verified head, a PATH_EPOCH hint and a timer: r is the newest REMOVE generation
//	          held above the head's current epoch, or the head's due generation; none deletes any job. g*, the newest
//	          generation held, below r waits for gkm's delivery. A job on disk resumes at its state. A batched due
//	          builds nothing while two sources stand, any due while three do. Otherwise the job starts now for a
//	          device whose own EnsureWritable call returned r, else at an immediate due's first sight plus
//	          U[0, MapperSpread), a batched one's due_by_ms less MapperBatchedLead plus U[0, MapperSpread), U seeded
//	          by (sidecar_id, ref_id, r)
//	build     on the index's head S, whose epoch state is the head's: per path ascending by new token path, its
//	          token path in p_new = g*, its sources the current epoch's then each listed source at or above its born,
//	          newest first, its name sealed in p_new; the root first, its paths empty and no sealed name. The moves
//	          sort on disk: runs of MapPartFillByteCount sorted in memory and written to run/<n>, then merged, so the
//	          mapper holds a run and a part, never the map (QD-641). Parts close at MapPartFillByteCount, each signed
//	          (evs-path-epoch) and written to part/<k>, hashed into path_map_sha256; then the job record, durable
//	          before the first upload
//	upload    POST .../path-epoch per part not yet marked, MapUploadCount at once, a 200 marking it; MAP_SOURCE,
//	          other bytes under the key, abandons
//	commit    on the head b, read fresh, whose current epoch must still be the job's source epoch: the tail, a move
//	          per path index.CreatedAfter(S) gives, removed ones included, its source the current epoch alone; the
//	          PATH_EPOCH push at g*'s pin naming the map's source and hash, a git-mode ref's on its tip, under the
//	          index's publish lock P_r when it holds one (DESIGN-DETAILS 8.2.9), taking the seal lease first once an
//	          attempt lost the tip (409 NON_FAST_FORWARD). Answers: 200 done; 409 naming paths, a new head and tail,
//	          and after MapTailRefusalCount of them and 10 min past due_by_ms the block, then the push; 409
//	          MAP_SOURCE abandons and builds again; 409 MAP_PARTS uploads the parts again, a second abandoning; 409
//	          REF_MODE (an IMMUTABLE tag, which takes no map) abandons and maps nothing more on the ref for that
//	          generation; 412 EPOCH_SOURCES_FULL waits with the job kept; 412 PATH_EPOCH is done (an epoch at or above
//	          p_new stands); 412 GATE_CLOSED takes EnsureWritable and pushes the same map under the newer pin
//	abandon   deletes the job and its parts: on MAP_SOURCE, the head's current epoch reaching p_new, the oldest part
//	          past MapMaxAge, a REMOVE generation above p_new delivered before the commit, and lost eligibility
//	wake      a verified head showing a due or a removal this device holds, a new generation (NoteGeneration) and
//	          this device's own rotation ask the component's loop for a tick of the ref, once per head version, beside
//	          hints and the MapperSpread timer
//
// A restart resumes from the job record: the parts on disk are the bytes the map's hash names, so an upload continues
// where it stopped and never draws a nonce twice. Parts evs holds of an abandoned map are §2.2.5's to delete. Two
// mappers need no agreement: of two at one generation the second's PATH_EPOCH answers 412 PATH_EPOCH, and of two at
// two generations the second meets the between fence (409 MAP_SOURCE) and maps again.
//
// Not built here: FS-4's mapper schedules on barriers.
//
// On desktop and mobile legs. Safe for concurrent use: one job per ref at a time.

package sidecar

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The states a job record names.
const (
	evsMapJobUploading  = "uploading"
	evsMapJobCommitting = "committing"
)

var (
	// The mapper has nothing to do yet: a start time ahead, a source slot, a generation gkm has not delivered.
	errEvsMapperWait = errors.New("evs: the mapper waits")
	// The ref is not this device's to map: no index, or not a writer of a shared or owned ref.
	ErrEvsMapperNotEligible = errors.New("evs: not eligible to map the ref")
	// The job was abandoned and deleted: the next tick builds again.
	errEvsMapAbandoned = errors.New("evs: the map was abandoned")
)

// A registered index whose mount publishes the ref's pushes under one lock, P_r (DESIGN-DETAILS 8.2.9): the mapper's
// PATH_EPOCH takes it, so one device's pushes to the ref take turns. The local tier's replayed index implements it.
type EvsNameIndexPublisher interface {
	// Takes P_r, waiting for its holder. The answer releases it, once.
	LockPublish(ctx context.Context) (func(), error)
}

// How many ticks the component's loop holds asked and not yet run before a further ask is dropped, which the timer
// then covers.
const evsMapperWakeCount = 64

// A map job on disk: evs/epoch/<repo>/<ref>/job, its parts at part/<k> beside it (DESIGN-DETAILS 9.2.2).
type EvsMapJob struct {
	PNew          uint64   `json:"p_new"`
	SourceVersion uint64   `json:"source_version"`
	SourceChain   string   `json:"source_chain"`
	SourceEpoch   uint64   `json:"source_epoch"`
	Sources       []uint64 `json:"sources"`
	PathMapSha256 string   `json:"path_map_sha256"`
	PartCount     int      `json:"part_count"`
	Uploaded      []bool   `json:"uploaded"`
	BuiltMs       int64    `json:"built_ms"`
	State         string   `json:"state"`
	TailRefusals  int      `json:"tail_refusals"`
	PartsRetried  bool     `json:"parts_retried,omitempty"`
}

// The mapper of one client: the indexes registered per ref, and its jobs' bookkeeping. Under its own lock.
type evsMapper struct {
	client *EvsClient
	// the refs asked a tick of (see the file header's wake row), which the component's loop takes
	wakeups chan evsRefKey

	stateLock sync.Mutex
	indexes   map[evsRefKey]EvsNameIndex
	running   map[evsRefKey]bool
	// when this device first saw an immediate due per ref and generation, which its start counts from
	firstSeen map[evsRefKey]time.Time
	// the job states it last reached per ref, which PathEpochStatus shows
	states map[evsRefKey]*EvsMapJob
	// per ref, the head version that last asked a tick, so the mapper's own head reads ask none again
	wokenAt map[evsRefKey]uint64
	// per ref, the generation whose PATH_EPOCH evs refused 409 REF_MODE: nothing is mapped there up to it
	refusedThrough map[evsRefKey]uint64
}

// The client's mapper, made on first use and registered as PathEpochStatus's source and the epochs' waker.
func (self *EvsClient) mapper() *evsMapper {
	self.epochs.stateLock.Lock()
	defer self.epochs.stateLock.Unlock()
	if mapper, ok := self.epochs.mapper.(*evsMapper); ok {
		return mapper
	}
	mapper := &evsMapper{
		client: self, wakeups: make(chan evsRefKey, evsMapperWakeCount), indexes: map[evsRefKey]EvsNameIndex{},
		running: map[evsRefKey]bool{}, firstSeen: map[evsRefKey]time.Time{}, states: map[evsRefKey]*EvsMapJob{},
		wokenAt: map[evsRefKey]uint64{}, refusedThrough: map[evsRefKey]uint64{},
	}
	self.epochs.mapper = mapper
	self.epochs.mapperStatus = mapper.status
	self.epochs.mapperWake = mapper.wake
	return mapper
}

// Asks a tick of the ref at headVersion, once per version and never while the ref's tick runs: see the file header's
// wake row. A full queue drops the ask, which the timer covers.
func (self *evsMapper) wake(repoId Id, refId Id, headVersion uint64) {
	key := evsRefKey{repoId: repoId, refId: refId}
	asked := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.running[key] || (headVersion != 0 && headVersion <= self.wokenAt[key]) {
			return false
		}
		if headVersion != 0 {
			self.wokenAt[key] = headVersion
		}
		return true
	}()
	if !asked {
		return
	}
	select {
	case self.wakeups <- key:
	default:
	}
}

// A new generation of a repo reached this device (gkm's delivery, a rotation): every ref this client pins in the repo
// is asked a tick, since a REMOVE generation is what a mapper maps to. The host's gkm wiring calls it as each
// generation arrives; this client's own rotation calls it too.
func (self *EvsClient) NoteGeneration(repoId Id) {
	mapper := self.mapper()
	for _, pin := range self.pins.loadedPins() {
		if pin.RepoId == repoId {
			mapper.wake(repoId, pin.RefId, 0)
		}
	}
}

// Registers a replayed index of every name of a ref: the seam EVS1-M2-33's and EVS1-M2-35's mirrors map through.
// The returned function removes it.
func (self *EvsClient) RegisterNameIndex(repoId Id, refId Id, index EvsNameIndex) func() {
	mapper := self.mapper()
	key := evsRefKey{repoId: repoId, refId: refId}
	mapper.stateLock.Lock()
	defer mapper.stateLock.Unlock()
	mapper.indexes[key] = index
	return func() {
		mapper.stateLock.Lock()
		defer mapper.stateLock.Unlock()
		if mapper.indexes[key] == index {
			delete(mapper.indexes, key)
		}
	}
}

// What PathEpochStatus shows of a ref's job.
func (self *evsMapper) status(repoId Id, refId Id) (string, int, int, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	job := self.states[evsRefKey{repoId: repoId, refId: refId}]
	if job == nil {
		return "", 0, 0, false
	}
	uploaded := 0
	for _, done := range job.Uploaded {
		if done {
			uploaded += 1
		}
	}
	state := EvsPathEpochStateUploading
	switch job.State {
	case evsMapJobCommitting:
		state = EvsPathEpochStateCommitting
	case "":
		state = EvsPathEpochStateBuilding
	}
	return state, uploaded, job.PartCount, true
}

// The job's directory in the component's sealed store.
func evsMapJobDirectory(repoId Id, refId Id) string {
	return "epoch/" + repoId.String() + "/" + refId.String() + "/"
}

// The job on disk, nil for none.
func (self *EvsRepo) loadMapJob(refId Id) (*EvsMapJob, error) {
	reader, err := self.client.args.Store.Open(evsMapJobDirectory(self.repoId, refId) + "job")
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	job := &EvsMapJob{}
	if err := json.Unmarshal(data, job); err != nil {
		return nil, fmt.Errorf("%w: a map job that does not parse", ErrSidecarStoreFailed)
	}
	return job, nil
}

// Writes the job durably.
func (self *EvsRepo) saveMapJob(refId Id, job *EvsMapJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	if err := self.writeStoreFile(evsMapJobDirectory(self.repoId, refId)+"job", data); err != nil {
		return err
	}
	mapper := self.client.mapper()
	mapper.stateLock.Lock()
	defer mapper.stateLock.Unlock()
	copied := *job
	mapper.states[evsRefKey{repoId: self.repoId, refId: refId}] = &copied
	return nil
}

// Deletes the job and its parts.
func (self *EvsRepo) deleteMapJob(refId Id) error {
	directory := evsMapJobDirectory(self.repoId, refId)
	entries, err := self.client.args.Store.List(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := self.client.args.Store.Remove(entry.Name); err != nil {
			return err
		}
	}
	mapper := self.client.mapper()
	mapper.stateLock.Lock()
	defer mapper.stateLock.Unlock()
	delete(mapper.states, evsRefKey{repoId: self.repoId, refId: refId})
	return nil
}

// A file of the sealed store, replaced durably.
func (self *EvsRepo) writeStoreFile(name string, data []byte) error {
	writer, err := self.client.args.Store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// A part's bytes as written to disk.
func (self *EvsRepo) readMapPart(refId Id, k int) ([]byte, error) {
	reader, err := self.client.args.Store.Open(evsMapJobDirectory(self.repoId, refId) + "part/" + strconv.Itoa(k))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// One tick of the ref's mapper (see the file header's tick row): what the component runs on each verified head, hint
// and new generation and on its timer. nil when there is nothing to do or the job committed; errEvsMapperWait when
// it waits; another error when a step failed, which the next tick tries again.
func (self *EvsRepo) TickMapper(ctx context.Context, refId Id) error {
	mapper := self.client.mapper()
	key := evsRefKey{repoId: self.repoId, refId: refId}
	if !func() bool {
		mapper.stateLock.Lock()
		defer mapper.stateLock.Unlock()
		if mapper.running[key] {
			return false
		}
		mapper.running[key] = true
		return true
	}() {
		return errEvsMapperWait
	}
	defer func() {
		mapper.stateLock.Lock()
		defer mapper.stateLock.Unlock()
		delete(mapper.running, key)
	}()
	head, err := self.readHeadAlone(ctx, refId, true)
	if err != nil {
		return err
	}
	epoch := head.Head.GetPathEpoch()
	current := evsCurrentEpoch(epoch)
	state := self.client.refEpochState(self.repoId, refId)
	_, removal, err := self.pressure(ctx, state)
	if err != nil {
		return err
	}
	job, err := self.loadMapJob(refId)
	if err != nil {
		return err
	}
	if removal == 0 || removal <= current {
		if job != nil {
			return self.deleteMapJob(refId)
		}
		return nil
	}
	if func() bool {
		mapper.stateLock.Lock()
		defer mapper.stateLock.Unlock()
		return removal <= mapper.refusedThrough[key]
	}() {
		// evs refused this ref a map at that generation (409 REF_MODE): an IMMUTABLE tag takes none
		return ErrEvsMapperNotEligible
	}
	index, err := self.eligibleIndex(ctx, head)
	if errors.Is(err, ErrEvsMapperNotEligible) && job != nil {
		// eligibility lost: the job goes, its parts on evs left for §2.2.5's collection
		if deleteErr := self.deleteMapJob(refId); deleteErr != nil {
			return deleteErr
		}
	}
	if err != nil {
		return err
	}
	newest, err := self.client.args.Gkm.CurrentRepoKey(ctx, self.repoId)
	if err != nil {
		return err
	}
	if newest.Generation() < removal {
		return errEvsMapperWait
	}
	if job != nil {
		if abandon := self.abandonReason(job, head, newest.Generation()); abandon != "" {
			if err := self.deleteMapJob(refId); err != nil {
				return err
			}
			job = nil
		}
	}
	batched := !epoch.GetDueBlocksCreation() && current < epoch.GetDueGeneration()
	sourceCount := len(epoch.GetSources())
	if job == nil {
		switch {
		case batched && evsPathEpochBatchedMaxSourceCount <= sourceCount, evsPathEpochMaxSourceCount <= sourceCount:
			return errEvsMapperWait
		}
		if start := self.mapperStart(refId, epoch, removal, batched); self.client.clock.Now().Before(start) {
			return errEvsMapperWait
		}
		if job, err = self.buildMap(ctx, refId, head, index, newest.Generation()); err != nil {
			return err
		}
	}
	if err := self.uploadMap(ctx, refId, job); err != nil {
		if errors.Is(err, errEvsMapAbandoned) {
			return fmt.Errorf("%w: %w", errEvsMapperWait, err)
		}
		return err
	}
	return self.commitMap(ctx, refId, job, index)
}

// Why a job on disk is abandoned on head with g* newest, empty when it stands: the head's current epoch reached its
// p_new, its oldest part passed MapMaxAge, or a REMOVE generation above p_new was delivered.
func (self *EvsRepo) abandonReason(job *EvsMapJob, head *EvsVerifiedHead, newest uint64) string {
	switch {
	case job.PNew <= evsCurrentEpoch(head.Head.GetPathEpoch()):
		return "the epoch landed"
	case self.client.settings.MapMaxAge < self.client.clock.Now().Sub(time.UnixMilli(job.BuiltMs)):
		return "past MapMaxAge"
	}
	for generation := job.PNew + 1; generation <= newest; generation += 1 {
		if key, err := self.client.args.Gkm.RepoKey(context.Background(), self.repoId, generation); err == nil && key.Cause() == GkmCauseRemove {
			return "a newer REMOVE generation"
		}
	}
	return ""
}

// The index the ref maps from, or ErrEvsMapperNotEligible: see the file header's eligible row.
func (self *EvsRepo) eligibleIndex(ctx context.Context, head *EvsVerifiedHead) (EvsNameIndex, error) {
	refKind := head.Head.GetRefKind()
	if refKind != protocol.EvsRefKind_EVS_REF_SHARED && refKind != protocol.EvsRefKind_EVS_REF_OWNED {
		return nil, ErrEvsMapperNotEligible
	}
	// a git-mode ref maps as a file-mode one, its entries being its tip's tree (DESIGN-DETAILS 8.2.10), and commits
	// on its tip (commitMap)
	config, err := self.client.verifier.config()
	if err != nil {
		return nil, err
	}
	if !slices.Contains(config.RepoWriters(self.repoId), self.client.args.Identity().SidecarId) {
		return nil, ErrEvsMapperNotEligible
	}
	mapper := self.client.mapper()
	mapper.stateLock.Lock()
	index := mapper.indexes[evsRefKey{repoId: self.repoId, refId: head.RefId}]
	mapper.stateLock.Unlock()
	if index == nil {
		listed, err := newEvsListedNameIndex(ctx, self, head.RefId, self.client.settings.ListedIndexRoundCount)
		if err != nil {
			return nil, err
		}
		index = listed
	}
	if self.client.settings.MapperMobile && self.client.settings.MobileMapNameCount < evsIndexCount(ctx, index) {
		return nil, ErrEvsMapperNotEligible
	}
	return index, nil
}

// How many paths an index holds.
func evsIndexCount(ctx context.Context, index EvsNameIndex) int {
	count := 0
	index.Walk(ctx, func(path *EvsIndexedPath) error {
		count += 1
		return nil
	})
	return count
}

// When the ref's job may start (see the file header's tick row), U seeded by (sidecar_id, ref_id, r).
func (self *EvsRepo) mapperStart(refId Id, epoch *protocol.EvsPathEpoch, removal uint64, batched bool) time.Time {
	seed := sha256.New()
	seed.Write(self.client.args.Identity().SidecarId.Bytes())
	seed.Write(refId.Bytes())
	seed.Write(binary.BigEndian.AppendUint64(nil, removal))
	// U[0, MapperSpread) from the seed's digest, the same on every tick of this device for this removal
	spread := time.Duration(binary.BigEndian.Uint64(seed.Sum(nil)) % uint64(max(1, int64(self.client.settings.MapperSpread))))
	mapper := self.client.mapper()
	key := evsRefKey{repoId: self.repoId, refId: refId}
	firstSeen := func() time.Time {
		mapper.stateLock.Lock()
		defer mapper.stateLock.Unlock()
		if seen, ok := mapper.firstSeen[key]; ok {
			return seen
		}
		mapper.firstSeen[key] = self.client.clock.Now()
		return mapper.firstSeen[key]
	}()
	if self.client.epochs.rotatedTo(self.repoId, removal) {
		return time.Time{}
	}
	if batched {
		dueBy := self.client.epochs.dueBy(self.repoId, epoch, removal, true)
		return dueBy.Add(-self.client.settings.MapperBatchedLead).Add(spread)
	}
	return firstSeen.Add(spread)
}

// A move of path in pNew: its new token path, its sources in the current epoch then each listed source at or above
// its born (0: every one), newest first, and its name sealed in pNew; the root's paths empty, with no sealed name.
func (self *EvsRepo) mapMove(ctx context.Context, keys *evsReadKeys, path *EvsIndexedPath, pNew uint64, current uint64, sources []uint64, tailOnly bool) (*protocol.EvsPathMove, error) {
	newPath, err := keys.tokenPathIn(ctx, path.Names, pNew)
	if err != nil {
		return nil, err
	}
	move := &protocol.EvsPathMove{NewTokenPath: newPath.Components()}
	epochs := []uint64{current}
	if !tailOnly {
		for _, source := range sources {
			if path.Born == 0 || path.Born <= source {
				epochs = append(epochs, source)
			}
		}
	}
	for _, epoch := range epochs {
		sourcePath, err := keys.tokenPathIn(ctx, path.Names, epoch)
		if err != nil {
			return nil, err
		}
		move.Sources = append(move.Sources, &protocol.EvsSourcePath{Epoch: epoch, TokenPath: sourcePath.Components()})
	}
	if len(path.Names) == 0 {
		return move, nil
	}
	manifest, err := keys.manifest(ctx, pNew)
	if err != nil {
		return nil, err
	}
	if move.SealedName, err = EvsNameSeal(manifest, newPath.Parent(), newPath.Last(), path.Names[len(path.Names)-1]); err != nil {
		return nil, err
	}
	return move, nil
}

// Builds the map on the index's head (see the file header's build row), its parts and job record on disk.
func (self *EvsRepo) buildMap(ctx context.Context, refId Id, head *EvsVerifiedHead, index EvsNameIndex, pNew uint64) (*EvsMapJob, error) {
	source, err := index.Head(ctx)
	if err != nil {
		return nil, err
	}
	if !evsSamePathEpoch(source.PathEpoch, head.Head.GetPathEpoch()) {
		return nil, fmt.Errorf("%w: an index on another epoch state", errEvsMapperWait)
	}
	keys := newEvsReadKeys(self)
	current := evsCurrentEpoch(source.PathEpoch)
	sources := evsSourceEpochs(source.PathEpoch)
	directory := evsMapJobDirectory(self.repoId, refId)
	sorter := &evsMapSorter{repo: self, directory: directory, fillByteCount: self.client.settings.MapPartFillByteCount}
	defer sorter.removeRuns()
	if err := index.Walk(ctx, func(path *EvsIndexedPath) error {
		move, err := self.mapMove(ctx, keys, path, pNew, current, sources, false)
		if err != nil {
			return err
		}
		return sorter.add(move)
	}); err != nil {
		return nil, err
	}
	if err := sorter.flush(); err != nil {
		return nil, err
	}
	// the parts, a run of moves each closed at MapPartFillByteCount, signed and written in order as the merge yields
	// them, so one part is held at a time
	hasher := NewEvsPathMapHasher()
	partCount := 0
	partMoves := []*protocol.EvsPathMove{}
	partBytes := 0
	writePart := func(parts uint32) error {
		partCount += 1
		if EvsPathMapMaxPartCount < partCount {
			return fmt.Errorf("%w: a map past %d parts", ErrEvsWriteInvalid, EvsPathMapMaxPartCount)
		}
		pathMap := &protocol.EvsPathMap{
			RepoId: self.repoId.Bytes(), RefId: refId.Bytes(), PathEpoch: pNew, Part: uint32(partCount), Parts: parts,
			Moves: partMoves, SourceVersion: source.Version, SourceChain: source.Chain[:],
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(pathMap)
		if err != nil {
			return err
		}
		signed, err := self.client.args.Sign("evs-path-epoch", bridge.SignedType_SIGNED_EVS_PATH_MAP, body, nil)
		if err != nil {
			return err
		}
		signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			return err
		}
		if err := self.writeStoreFile(directory+"part/"+strconv.Itoa(partCount), signedBytes); err != nil {
			return err
		}
		hasher.Add(signedBytes)
		partMoves, partBytes = []*protocol.EvsPathMove{}, 0
		return nil
	}
	// a part names how many parts the map has, so the merge runs twice: once counting the parts, once writing them
	countParts := func() (int, error) {
		count, bytesInPart, movesInPart := 0, 0, 0
		err := sorter.merge(ctx, func(move *protocol.EvsPathMove, size int) error {
			if 0 < movesInPart && self.client.settings.MapPartFillByteCount < bytesInPart+size {
				count, bytesInPart, movesInPart = count+1, 0, 0
			}
			bytesInPart += size
			movesInPart += 1
			return nil
		})
		if 0 < movesInPart {
			count += 1
		}
		return count, err
	}
	parts, err := countParts()
	if err != nil {
		return nil, err
	}
	if EvsPathMapMaxPartCount < parts {
		return nil, fmt.Errorf("%w: a map of %d parts", ErrEvsWriteInvalid, parts)
	}
	if err := sorter.merge(ctx, func(move *protocol.EvsPathMove, size int) error {
		if 0 < len(partMoves) && self.client.settings.MapPartFillByteCount < partBytes+size {
			if err := writePart(uint32(parts)); err != nil {
				return err
			}
		}
		partMoves = append(partMoves, move)
		partBytes += size
		return nil
	}); err != nil {
		return nil, err
	}
	if 0 < len(partMoves) {
		if err := writePart(uint32(parts)); err != nil {
			return nil, err
		}
	}
	if partCount != parts {
		return nil, fmt.Errorf("%w: the map's runs changed between merges", ErrSidecarStoreFailed)
	}
	job := &EvsMapJob{
		PNew: pNew, SourceVersion: source.Version, SourceChain: hex.EncodeToString(source.Chain[:]), SourceEpoch: current,
		Sources: sources, PathMapSha256: hex.EncodeToString(hasher.Sum()), PartCount: partCount,
		Uploaded: make([]bool, partCount), BuiltMs: self.client.clock.Now().UnixMilli(), State: evsMapJobUploading,
	}
	if err := self.saveMapJob(refId, job); err != nil {
		return nil, err
	}
	return job, nil
}

// A map's moves sorted by new token path on disk (see the file header's build row): moves gather in memory until
// they pass fillByteCount, then sort and go to run/<n> beside the job as u32 key length | key | u32 move length |
// move, each key the move's new token path's bytes; a merge reads the runs in step, a buffered reader each. Not safe
// for concurrent use.
type evsMapSorter struct {
	repo          *EvsRepo
	directory     string
	fillByteCount int

	buffered      []*evsMapSortedMove
	bufferedBytes int
	runCount      int
}

// One move as a run holds it: its key and its bytes.
type evsMapSortedMove struct {
	key  []byte
	move []byte
}

// The bytes a move adds to a part beside its own: the field's tag and length.
const evsMapMoveFramingByteCount = 8

// Takes one move, writing a run once the moves held pass fillByteCount.
func (self *evsMapSorter) add(move *protocol.EvsPathMove) error {
	moveBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(move)
	if err != nil {
		return err
	}
	key := EvsTokenPath(evsTokensOf(move.GetNewTokenPath())).Bytes()
	self.buffered = append(self.buffered, &evsMapSortedMove{key: key, move: moveBytes})
	self.bufferedBytes += len(key) + len(moveBytes) + evsMapMoveFramingByteCount
	if self.fillByteCount <= self.bufferedBytes {
		return self.flush()
	}
	return nil
}

// Sorts the moves held and writes them as the next run.
func (self *evsMapSorter) flush() error {
	if len(self.buffered) == 0 {
		return nil
	}
	slices.SortFunc(self.buffered, func(a *evsMapSortedMove, b *evsMapSortedMove) int {
		return bytes.Compare(a.key, b.key)
	})
	writer, err := self.repo.client.args.Store.Create(self.runName(self.runCount))
	if err != nil {
		return err
	}
	defer writer.Close()
	buffered := bufio.NewWriter(writer)
	for _, sorted := range self.buffered {
		for _, field := range [][]byte{sorted.key, sorted.move} {
			if err := binary.Write(buffered, binary.BigEndian, uint32(len(field))); err != nil {
				return err
			}
			if _, err := buffered.Write(field); err != nil {
				return err
			}
		}
	}
	if err := buffered.Flush(); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.runCount += 1
	self.buffered, self.bufferedBytes = nil, 0
	return nil
}

// Run n's file.
func (self *evsMapSorter) runName(n int) string {
	return self.directory + "run/" + strconv.Itoa(n)
}

// Removes every run, which the parts replace.
func (self *evsMapSorter) removeRuns() {
	for n := range self.runCount {
		self.repo.client.args.Store.Remove(self.runName(n))
	}
}

// One run being merged: its reader and its next move.
type evsMapRunReader struct {
	reader *bufio.Reader
	closer io.Closer
	next   *evsMapSortedMove
}

// Reads the run's next move into next, nil at its end.
func (self *evsMapRunReader) advance() error {
	fields := [2][]byte{}
	for i := range fields {
		var length uint32
		if err := binary.Read(self.reader, binary.BigEndian, &length); err != nil {
			if i == 0 && errors.Is(err, io.EOF) {
				self.next = nil
				return nil
			}
			return fmt.Errorf("%w: a map run cut short", ErrSidecarStoreFailed)
		}
		if EvsPathMapMaxByteCount < length {
			return fmt.Errorf("%w: a map run's field of %d bytes", ErrSidecarStoreFailed, length)
		}
		fields[i] = make([]byte, length)
		if _, err := io.ReadFull(self.reader, fields[i]); err != nil {
			return fmt.Errorf("%w: a map run cut short", ErrSidecarStoreFailed)
		}
	}
	self.next = &evsMapSortedMove{key: fields[0], move: fields[1]}
	return nil
}

// The runs a merge reads, smallest next key first.
type evsMapRunHeap []*evsMapRunReader

// How many runs have a move left.
func (self evsMapRunHeap) Len() int {
	return len(self)
}

// Whether run i's next key sorts before run j's.
func (self evsMapRunHeap) Less(i int, j int) bool {
	return bytes.Compare(self[i].next.key, self[j].next.key) < 0
}

// Swaps runs i and j.
func (self evsMapRunHeap) Swap(i int, j int) {
	self[i], self[j] = self[j], self[i]
}

// Adds a run, as container/heap asks.
func (self *evsMapRunHeap) Push(item any) {
	*self = append(*self, item.(*evsMapRunReader))
}

// Takes the last run, as container/heap asks.
func (self *evsMapRunHeap) Pop() any {
	old := *self
	item := old[len(old)-1]
	*self = old[:len(old)-1]
	return item
}

// Visits every move of every run in ascending key order, with the bytes it adds to a part.
func (self *evsMapSorter) merge(ctx context.Context, visit func(move *protocol.EvsPathMove, size int) error) error {
	runs := evsMapRunHeap{}
	defer func() {
		for _, run := range runs {
			run.closer.Close()
		}
	}()
	for n := range self.runCount {
		file, err := self.repo.client.args.Store.Open(self.runName(n))
		if err != nil {
			return err
		}
		run := &evsMapRunReader{reader: bufio.NewReader(file), closer: file}
		if err := run.advance(); err != nil {
			file.Close()
			return err
		}
		if run.next == nil {
			file.Close()
			continue
		}
		runs = append(runs, run)
	}
	heap.Init(&runs)
	for 0 < len(runs) {
		if err := ctx.Err(); err != nil {
			return err
		}
		run := runs[0]
		move := &protocol.EvsPathMove{}
		if err := proto.Unmarshal(run.next.move, move); err != nil {
			return fmt.Errorf("%w: a map run's move does not parse", ErrSidecarStoreFailed)
		}
		if err := visit(move, len(run.next.move)+evsMapMoveFramingByteCount); err != nil {
			return err
		}
		if err := run.advance(); err != nil {
			return err
		}
		if run.next == nil {
			heap.Pop(&runs)
			run.closer.Close()
			continue
		}
		heap.Fix(&runs, 0)
	}
	return nil
}

// The token paths of components that parse, as moves hold them.
func evsTokensOf(components [][]byte) []EvsToken {
	tokens := make([]EvsToken, 0, len(components))
	for _, component := range components {
		tokens = append(tokens, EvsToken(component))
	}
	return tokens
}

// Uploads every part not yet marked, from disk, MapUploadCount at once, marking each as it answers (see the file
// header's upload row). MAP_SOURCE, other bytes under a part's key, abandons the job, ends the rest and answers
// errEvsMapAbandoned; any other failure ends the rest and answers it, the parts marked so far kept.
func (self *EvsRepo) uploadMap(ctx context.Context, refId Id, job *EvsMapJob) error {
	mapSha256, err := hex.DecodeString(job.PathMapSha256)
	if err != nil {
		return err
	}
	pending := []int{}
	for k := 1; k <= job.PartCount; k += 1 {
		if !job.Uploaded[k-1] {
			pending = append(pending, k)
		}
	}
	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// marks a part, and writes the job, one at a time
	var markLock sync.Mutex
	var firstErr error
	abandoned := false
	fail := func(err error, abandon bool) {
		markLock.Lock()
		defer markLock.Unlock()
		if firstErr == nil {
			firstErr = err
		}
		abandoned = abandoned || abandon
		cancel()
	}
	work := make(chan int)
	wait := sync.WaitGroup{}
	for range max(1, min(self.client.settings.MapUploadCount, len(pending))) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for k := range work {
				err := self.uploadMapPart(uploadCtx, refId, mapSha256, k)
				switch {
				case IsEvsMapSource(err):
					fail(err, true)
				case err != nil:
					fail(err, false)
				default:
					markLock.Lock()
					job.Uploaded[k-1] = true
					err := self.saveMapJob(refId, job)
					markLock.Unlock()
					if err != nil {
						fail(err, false)
					}
				}
			}
		}()
	}
	func() {
		defer close(work)
		for _, k := range pending {
			select {
			case work <- k:
			case <-uploadCtx.Done():
				return
			}
		}
	}()
	wait.Wait()
	if abandoned {
		if err := self.deleteMapJob(refId); err != nil {
			return err
		}
		return errEvsMapAbandoned
	}
	if firstErr != nil {
		return firstErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	job.State = evsMapJobCommitting
	return self.saveMapJob(refId, job)
}

// POST .../path-epoch {path_map_sha256, part}: part k as written to disk, retried as a push is.
func (self *EvsRepo) uploadMapPart(ctx context.Context, refId Id, mapSha256 []byte, k int) error {
	part, err := self.readMapPart(refId, k)
	if err != nil {
		return err
	}
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/path-epoch",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/path-epoch",
		repoId: self.repoId,
		role:   evsScopeWrite,
		body:   &protocol.EvsPathMapRequest{PathMapSha256: mapSha256, Part: part},
	}
	return self.client.retryRefusingNothing(ctx, func() error { return self.client.http.callMessage(ctx, call, nil) })
}

// Commits the job by a PATH_EPOCH push on the head (see the file header's commit row).
func (self *EvsRepo) commitMap(ctx context.Context, refId Id, job *EvsMapJob, index EvsNameIndex) error {
	sourceChain, err := hex.DecodeString(job.SourceChain)
	if err != nil {
		return err
	}
	mapSha256, err := hex.DecodeString(job.PathMapSha256)
	if err != nil {
		return err
	}
	// a git-mode attempt that lost its tip takes the seal lease before the next one is sent
	leaseFirst := false
	for attempt := 0; ; attempt += 1 {
		answer, head, err := self.commitMapOnce(ctx, refId, job, index, mapSha256, sourceChain, leaseFirst)
		evsError, refused := EvsErrorOf(err)
		switch {
		case answer == evsMapCommitDone:
			return self.deleteMapJob(refId)
		case answer == evsMapCommitAbandon:
			return self.deleteMapJob(refId)
		case err == nil:
			return nil
		case !refused:
			return err
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH:
			// an epoch at or above p_new stands
			return self.deleteMapJob(refId)
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE:
			return self.deleteMapJob(refId)
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE:
			// a ref evs maps nothing on, an IMMUTABLE tag's: nothing more is mapped there through this generation
			mapper := self.client.mapper()
			func() {
				mapper.stateLock.Lock()
				defer mapper.stateLock.Unlock()
				key := evsRefKey{repoId: self.repoId, refId: refId}
				mapper.refusedThrough[key] = max(mapper.refusedThrough[key], job.PNew)
			}()
			if deleteErr := self.deleteMapJob(refId); deleteErr != nil {
				return deleteErr
			}
			return ErrEvsMapperNotEligible
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_MAP_PARTS:
			if job.PartsRetried {
				return self.deleteMapJob(refId)
			}
			job.PartsRetried = true
			job.Uploaded = make([]bool, job.PartCount)
			if err := self.uploadMap(ctx, refId, job); err != nil {
				return err
			}
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_EPOCH_SOURCES_FULL:
			return errEvsMapperWait
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD:
			// git mode: another push took the tip between the head read and the post
			leaseFirst = true
			if self.client.settings.PushRebuildCount <= attempt {
				return err
			}
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED:
			// EnsureWritable gives the newer generation's pin for the same map next time
			if self.client.settings.PushRebuildCount <= attempt {
				return err
			}
		case evsError.Status == http.StatusConflict && 0 < len(evsError.Paths):
			// creations after the map's base: a new head and tail; past MapTailRefusalCount and 10 min past due, the block
			job.TailRefusals += 1
			if err := self.saveMapJob(refId, job); err != nil {
				return err
			}
			var headEpoch *protocol.EvsPathEpoch
			if head != nil {
				headEpoch = head.Head.GetPathEpoch()
			}
			dueBy := self.client.epochs.dueBy(self.repoId, headEpoch, job.PNew, false)
			if self.client.settings.MapTailRefusalCount <= job.TailRefusals && !dueBy.IsZero() &&
				dueBy.Add(10*time.Minute).Before(self.client.clock.Now()) {
				if err := self.blockCreation(ctx, refId); err != nil {
					return err
				}
			}
			if self.client.settings.PushRebuildCount <= attempt {
				return err
			}
		default:
			return err
		}
	}
}

// What one PATH_EPOCH attempt settled beside evs's answer.
type evsMapCommitAnswer int

const (
	// evs answered, or failed to: the error says
	evsMapCommitAnswered evsMapCommitAnswer = iota
	// it committed
	evsMapCommitDone
	// the head's epoch moved past the job's source: abandoned
	evsMapCommitAbandon
)

// One PATH_EPOCH attempt on a freshly read head, under the index's publish lock when it holds one: the tail, the
// statement, the seal lease first on a git-mode ref when leaseFirst, and the post. The head it read goes back with
// the answer, nil only when reading it failed.
func (self *EvsRepo) commitMapOnce(ctx context.Context, refId Id, job *EvsMapJob, index EvsNameIndex, mapSha256 []byte, sourceChain []byte, leaseFirst bool) (evsMapCommitAnswer, *EvsVerifiedHead, error) {
	if publisher, ok := index.(EvsNameIndexPublisher); ok {
		release, err := publisher.LockPublish(ctx)
		if err != nil {
			return evsMapCommitAnswered, nil, err
		}
		defer release()
	}
	head, err := self.readHeadAlone(ctx, refId, true)
	if err != nil {
		return evsMapCommitAnswered, nil, err
	}
	answer, err := self.postMapCommit(ctx, refId, job, index, mapSha256, sourceChain, leaseFirst, head)
	return answer, head, err
}

// The attempt of commitMapOnce on head.
func (self *EvsRepo) postMapCommit(ctx context.Context, refId Id, job *EvsMapJob, index EvsNameIndex, mapSha256 []byte, sourceChain []byte, leaseFirst bool, head *EvsVerifiedHead) (evsMapCommitAnswer, error) {
	if evsCurrentEpoch(head.Head.GetPathEpoch()) != job.SourceEpoch {
		return evsMapCommitAbandon, nil
	}
	var err error
	var created []*EvsIndexedPath
	if listed, ok := index.(*evsListedNameIndex); ok && len(sourceChain) == sha256.Size {
		// the listed index walks from the map's source, whose chain the job holds
		created, err = listed.createdAfterFrom(ctx, job.SourceVersion, [sha256.Size]byte(sourceChain))
	} else {
		created, err = index.CreatedAfter(ctx, job.SourceVersion)
	}
	if err != nil {
		return evsMapCommitAnswered, err
	}
	keys := newEvsReadKeys(self)
	tail := [][]byte{}
	for _, path := range created {
		move, err := self.mapMove(ctx, keys, path, job.PNew, job.SourceEpoch, nil, true)
		if err != nil {
			return evsMapCommitAnswered, err
		}
		moveBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(move)
		if err != nil {
			return evsMapCommitAnswered, err
		}
		tail = append(tail, moveBytes)
	}
	repoKey, err := self.client.args.Gkm.RepoKey(ctx, self.repoId, job.PNew)
	if err != nil {
		return evsMapCommitAnswered, err
	}
	if newest, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId); err == nil && job.PNew < newest.Generation() {
		repoKey = newest
	}
	manifest, err := NewEvsManifestKey(repoKey)
	if err != nil {
		return evsMapCommitAnswered, err
	}
	metadata, err := EvsSealMetadata(manifest, &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{}})
	if err != nil {
		return evsMapCommitAnswered, err
	}
	config, err := self.client.verifier.config()
	if err != nil {
		return evsMapCommitAnswered, err
	}
	identity := self.client.args.Identity()
	pushId := NewEvsPushId()
	plan := &EvsPushPlan{
		RepoId: self.repoId, RefId: refId, RefKind: head.Head.GetRefKind(), RefMode: head.Head.GetRefMode(),
		PushId: pushId, BaseVersion: head.Version, BaseChain: head.Chain, Generation: repoKey.Generation(),
		GroupId: repoKey.GroupId(), GenerationCommitment: repoKey.Commitment(), PathEpoch: job.PNew, Auth: config.Pin(),
		SignerSidecarId: identity.SidecarId, ClientId: identity.ClientId, TimeMs: self.client.clock.Now().UnixMilli(),
		Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH), PathMapSha256: mapSha256,
		MapSourceVersion: job.SourceVersion, MapSourceChain: sourceChain, SealedMetadata: metadata, TailMoves: tail,
	}
	if owner := head.Head.GetOwnerSidecarId(); 0 < len(owner) {
		ownerId, err := IdFromBytes(owner)
		if err != nil {
			return evsMapCommitAnswered, err
		}
		plan.OwnerSidecarId = &ownerId
	}
	built, err := NewEvsStatementBuilder(self.client.args.Sign).Build(plan)
	if err != nil {
		return evsMapCommitAnswered, err
	}
	if leaseFirst && head.Head.GetRefMode() == protocol.EvsRefMode_EVS_REF_GIT {
		// the tip is this push's until it seals or the lease ends: a commit landing first answers the lease 409
		// NON_FAST_FORWARD, and the next attempt reads the head again
		lease := &evsPushAttempt{pushId: pushId, refId: refId, baseVersion: head.Version}
		if err := self.takeLease(ctx, lease); err != nil {
			return evsMapCommitAnswered, err
		}
	}
	if _, err := self.postPush(ctx, pushId, &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}); err != nil {
		return evsMapCommitAnswered, err
	}
	return evsMapCommitDone, nil
}

// POST .../path-epoch/block {ref_id, ms: 120,000}: creation stops on the ref while the mapper commits.
func (self *EvsRepo) blockCreation(ctx context.Context, refId Id) error {
	call := &evsCall{
		route:  "POST /evs/v1/repos/{repo_id}/path-epoch/block",
		method: http.MethodPost,
		path:   "/evs/v1/repos/" + evsUrlId(self.repoId) + "/path-epoch/block",
		repoId: self.repoId,
		role:   evsScopeWrite,
		body:   &protocol.EvsPathEpochBlockRequest{RefId: refId.Bytes(), Ms: uint32(evsPathEpochBlockMs)},
	}
	return self.client.retryRefusingNothing(ctx, func() error { return self.client.http.callMessage(ctx, call, nil) })
}

// §11.6's block row: a block holds creation 120 s at most.
const evsPathEpochBlockMs = 120 * 1000
