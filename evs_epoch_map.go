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
//	          newest first, its name sealed in p_new; the root first, its paths empty and no sealed name. Parts close
//	          at MapPartFillByteCount, each signed (evs-path-epoch) and written to part/<k>, hashed into
//	          path_map_sha256; then the job record, durable before the first upload
//	upload    POST .../path-epoch per part not yet marked, a 200 marking it; MAP_SOURCE, other bytes under the key,
//	          abandons
//	commit    on the head b, read fresh, whose current epoch must still be the job's source epoch: the tail, a move
//	          per path index.CreatedAfter(S) gives, removed ones included, its source the current epoch alone; the
//	          PATH_EPOCH push at g*'s pin naming the map's source and hash. Answers: 200 done; 409 naming paths, a new
//	          head and tail, and after MapTailRefusalCount of them and 10 min past due_by_ms the block, then the push;
//	          409 MAP_SOURCE abandons and builds again; 409 MAP_PARTS uploads the parts again, a second abandoning;
//	          412 EPOCH_SOURCES_FULL waits with the job kept; 412 PATH_EPOCH is done (an epoch at or above p_new
//	          stands); 412 GATE_CLOSED takes EnsureWritable and pushes the same map under the newer pin
//	abandon   deletes the job and its parts: on MAP_SOURCE, the head's current epoch reaching p_new, the oldest part
//	          past MapMaxAge, a REMOVE generation above p_new delivered before the commit, and lost eligibility
//
// A restart resumes from the job record: the parts on disk are the bytes the map's hash names, so an upload continues
// where it stopped and never draws a nonce twice. Parts evs holds of an abandoned map are §2.2.5's to delete. Two
// mappers need no agreement: of two at one generation the second's PATH_EPOCH answers 412 PATH_EPOCH, and of two at
// two generations the second meets the between fence (409 MAP_SOURCE) and maps again.
//
// Not built here: git-mode refs, whose PATH_EPOCH goes on the tip under the seal lease (the mapper refuses them, as
// ErrEvsGitRef); MapUploadCount parts at once (they go one at a time); a 1M-path map within one part's memory (a map
// is built whole in memory, its parts written to disk); FS-4's mapper schedules on barriers.
//
// On desktop and mobile legs. Safe for concurrent use: one job per ref at a time.

package sidecar

import (
	"bytes"
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
)

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

	stateLock sync.Mutex
	indexes   map[evsRefKey]EvsNameIndex
	running   map[evsRefKey]bool
	// when this device first saw an immediate due per ref and generation, which its start counts from
	firstSeen map[evsRefKey]time.Time
	// the job states it last reached per ref, which PathEpochStatus shows
	states map[evsRefKey]*EvsMapJob
}

// The client's mapper, made on first use and registered as PathEpochStatus's source.
func (self *EvsClient) mapper() *evsMapper {
	self.epochs.stateLock.Lock()
	defer self.epochs.stateLock.Unlock()
	if mapper, ok := self.epochs.mapper.(*evsMapper); ok {
		return mapper
	}
	mapper := &evsMapper{
		client: self, indexes: map[evsRefKey]EvsNameIndex{}, running: map[evsRefKey]bool{},
		firstSeen: map[evsRefKey]time.Time{}, states: map[evsRefKey]*EvsMapJob{},
	}
	self.epochs.mapper = mapper
	self.epochs.mapperStatus = mapper.status
	return mapper
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
	if head.Head.GetRefMode() == protocol.EvsRefMode_EVS_REF_GIT {
		return nil, ErrEvsGitRef
	}
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
	moves := []*protocol.EvsPathMove{}
	if err := index.Walk(ctx, func(path *EvsIndexedPath) error {
		move, err := self.mapMove(ctx, keys, path, pNew, current, sources, false)
		if err != nil {
			return err
		}
		moves = append(moves, move)
		return nil
	}); err != nil {
		return nil, err
	}
	slices.SortFunc(moves, func(a *protocol.EvsPathMove, b *protocol.EvsPathMove) int {
		return bytes.Compare(EvsTokenPath(evsTokensOf(a.GetNewTokenPath())).Bytes(), EvsTokenPath(evsTokensOf(b.GetNewTokenPath())).Bytes())
	})
	// parts by size, then signed in order
	partMoves := [][]*protocol.EvsPathMove{{}}
	partBytes := 0
	for _, move := range moves {
		size := proto.Size(move) + 8
		if 0 < len(partMoves[len(partMoves)-1]) && self.client.settings.MapPartFillByteCount < partBytes+size {
			partMoves = append(partMoves, []*protocol.EvsPathMove{})
			partBytes = 0
		}
		partMoves[len(partMoves)-1] = append(partMoves[len(partMoves)-1], move)
		partBytes += size
	}
	if EvsPathMapMaxPartCount < len(partMoves) {
		return nil, fmt.Errorf("%w: a map of %d parts", ErrEvsWriteInvalid, len(partMoves))
	}
	hasher := NewEvsPathMapHasher()
	directory := evsMapJobDirectory(self.repoId, refId)
	for k, moves := range partMoves {
		pathMap := &protocol.EvsPathMap{
			RepoId: self.repoId.Bytes(), RefId: refId.Bytes(), PathEpoch: pNew, Part: uint32(k + 1), Parts: uint32(len(partMoves)),
			Moves: moves, SourceVersion: source.Version, SourceChain: source.Chain[:],
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(pathMap)
		if err != nil {
			return nil, err
		}
		signed, err := self.client.args.Sign("evs-path-epoch", bridge.SignedType_SIGNED_EVS_PATH_MAP, body, nil)
		if err != nil {
			return nil, err
		}
		signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			return nil, err
		}
		if err := self.writeStoreFile(directory+"part/"+strconv.Itoa(k+1), signedBytes); err != nil {
			return nil, err
		}
		hasher.Add(signedBytes)
	}
	job := &EvsMapJob{
		PNew: pNew, SourceVersion: source.Version, SourceChain: hex.EncodeToString(source.Chain[:]), SourceEpoch: current,
		Sources: sources, PathMapSha256: hex.EncodeToString(hasher.Sum()), PartCount: len(partMoves),
		Uploaded: make([]bool, len(partMoves)), BuiltMs: self.client.clock.Now().UnixMilli(), State: evsMapJobUploading,
	}
	if err := self.saveMapJob(refId, job); err != nil {
		return nil, err
	}
	return job, nil
}

// The token paths of components that parse, as moves hold them.
func evsTokensOf(components [][]byte) []EvsToken {
	tokens := make([]EvsToken, 0, len(components))
	for _, component := range components {
		tokens = append(tokens, EvsToken(component))
	}
	return tokens
}

// Uploads every part not yet marked, from disk, marking each as it answers (see the file header's upload row).
func (self *EvsRepo) uploadMap(ctx context.Context, refId Id, job *EvsMapJob) error {
	mapSha256, err := hex.DecodeString(job.PathMapSha256)
	if err != nil {
		return err
	}
	for k := 1; k <= job.PartCount; k += 1 {
		if job.Uploaded[k-1] {
			continue
		}
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
		err = self.client.retryRefusingNothing(ctx, func() error { return self.client.http.callMessage(ctx, call, nil) })
		switch {
		case IsEvsMapSource(err):
			return self.deleteMapJob(refId)
		case err != nil:
			return err
		}
		job.Uploaded[k-1] = true
		if err := self.saveMapJob(refId, job); err != nil {
			return err
		}
	}
	job.State = evsMapJobCommitting
	return self.saveMapJob(refId, job)
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
	for attempt := 0; ; attempt += 1 {
		head, err := self.readHeadAlone(ctx, refId, true)
		if err != nil {
			return err
		}
		if evsCurrentEpoch(head.Head.GetPathEpoch()) != job.SourceEpoch {
			return self.deleteMapJob(refId)
		}
		created, err := index.CreatedAfter(ctx, job.SourceVersion)
		if err != nil {
			return err
		}
		keys := newEvsReadKeys(self)
		tail := [][]byte{}
		for _, path := range created {
			move, err := self.mapMove(ctx, keys, path, job.PNew, job.SourceEpoch, nil, true)
			if err != nil {
				return err
			}
			moveBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(move)
			if err != nil {
				return err
			}
			tail = append(tail, moveBytes)
		}
		repoKey, err := self.client.args.Gkm.RepoKey(ctx, self.repoId, job.PNew)
		if err != nil {
			return err
		}
		if newest, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId); err == nil && job.PNew < newest.Generation() {
			repoKey = newest
		}
		manifest, err := NewEvsManifestKey(repoKey)
		if err != nil {
			return err
		}
		metadata, err := EvsSealMetadata(manifest, &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{}})
		if err != nil {
			return err
		}
		config, err := self.client.verifier.config()
		if err != nil {
			return err
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
				return err
			}
			plan.OwnerSidecarId = &ownerId
		}
		built, err := NewEvsStatementBuilder(self.client.args.Sign).Build(plan)
		if err != nil {
			return err
		}
		_, err = self.postPush(ctx, pushId, &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload})
		evsError, refused := EvsErrorOf(err)
		switch {
		case err == nil:
			return self.deleteMapJob(refId)
		case !refused:
			return err
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH:
			// an epoch at or above p_new stands
			return self.deleteMapJob(refId)
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE:
			return self.deleteMapJob(refId)
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
		case evsError.Code == protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED:
			// EnsureWritable above gives the newer generation's pin for the same map next time
			if self.client.settings.PushRebuildCount <= attempt {
				return err
			}
		case evsError.Status == http.StatusConflict && 0 < len(evsError.Paths):
			// creations after the map's base: a new head and tail; past MapTailRefusalCount and 10 min past due, the block
			job.TailRefusals += 1
			if err := self.saveMapJob(refId, job); err != nil {
				return err
			}
			dueBy := self.client.epochs.dueBy(self.repoId, head.Head.GetPathEpoch(), job.PNew, false)
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
