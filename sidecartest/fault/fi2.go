// FI-2, outcomes (§22.8; I-EVS-2, I-EVS-3; D-TEST-10): every operation ends committed, aborted or unknown; unknown
// never triggers destructive cleanup; a retry of a committed operation returns its original result; a refusal a
// client received stays true, so once any attempt of a push id is answered a refusal, no attempt of it commits,
// whenever it reaches evs, save one validated before its repo's shred began, which the shred destroys; and a
// reclaimed preparation never commits later. The oracle reads what clients were answered from the ledger
// (ledger.go) and what committed from the store walk FI-1 makes (fi1.go), and holds each to the other:
//
//   - every operation the ledger holds is one a check can read (Operation.Validate): a push committed at a version,
//     aborted with its refusal, or unknown with an open end;
//   - the head history never changes what it committed: each version of each ref names one push id for good, and a
//     push id commits at most once, across every ref and check;
//   - every 200 a push id was answered names one version, the one the head history commits it at;
//   - a push id answered a refusal that binds (every code but PUSH_ID_REUSED, ledger.go) is in no head history and
//     answered no 200. The one exception is §11.12's: every refusal it got was SHREDDING, some attempt of it that
//     did not end refused arrived before the repo/ write that began its repo's shred (Operation.StoreArrival against
//     that write's blob history index), and repo/ is shredding or shredded, so the shred destroys what it committed;
//   - once a reclaimer deletes a push's preparation, its batch, a slot or a segment it introduced, while the head
//     history does not commit it, that push never commits after;
//   - no answer deletes anything (§11.8's cleanup row): no evs instance that answered an operation deletes an object
//     between two checks, but for the index entries of an epoch below its ref's current one, the source copies a
//     PATH_EPOCH's fold deletes inside its request (DESIGN-DETAILS 9.2.6).
//
// Durable state's own unknown, a record whose push Resolve finds pending, is FI-6's to protect from reclaimers; a
// pending push's objects are reclaimed only once it is dead, which FI-6 checks, so FI-2 holds what only the ledger
// knows. Readings and gaps: "validated before the shred began" is read as arrived before the repo/ CAS that began
// it, the arrival bounding the validation from below, so an attempt that arrived before the CAS and validated after
// it is excused here (the residual is narrow, and evs's 5c reads repo/ within its own 5 s; TEST-M2-04's report); a
// shred whose repo/ write no check saw starts before every attempt, excusing none; §16's operations (approval uses,
// FI-7's) and a client's own local cleanup are not in the ledger yet, so FI-2 holds evs's pushes alone.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(2, func(ctx context.Context, oracle *Oracle) error {
	return checkFi2(ctx, oracle)
})

// What FI-2 keeps from one check to the next on one Net.
type fi2Memory struct {
	stateLock sync.Mutex
	// each ref's committed versions as any check read them, and each push id's commit
	refVersions map[HistoryRef]map[uint64]sidecar.Id
	pushCommits map[sidecar.Id]*fi2Commit
	// the objects of every push the head history did not commit at the last check, by cluster and key: a batch, a
	// slot or a segment
	preparedObjects map[string][]sidecar.Id
	// pushes whose preparation a reclaimer deleted while uncommitted, with what it deleted
	reclaimed map[sidecar.Id]string
	// each repo's repo/ as the last check read it, and the blob history index of the write that began its shred
	repoObjects map[sidecar.Id]*fi2RepoObject
	shredStarts map[sidecar.Id]int
}

type fi2Commit struct {
	ref     HistoryRef
	version uint64
}

type fi2RepoObject struct {
	etag  string
	state protocol.EvsRepoState
}

var fi2Memories sync.Map

func newFi2Memory() *fi2Memory {
	return &fi2Memory{
		refVersions:     map[HistoryRef]map[uint64]sidecar.Id{},
		pushCommits:     map[sidecar.Id]*fi2Commit{},
		preparedObjects: map[string][]sidecar.Id{},
		reclaimed:       map[sidecar.Id]string{},
		repoObjects:     map[sidecar.Id]*fi2RepoObject{},
		shredStarts:     map[sidecar.Id]int{},
	}
}

func checkFi2(ctx context.Context, oracle *Oracle) error {
	memory := netMemoryOf(&fi2Memories, oracle.Net, newFi2Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()

	operations := LedgerOf(oracle.Net).Operations()
	errs := []error{}
	for _, operation := range operations {
		if err := operation.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("the ledger holds an operation that ends no way a check can read: %w", err))
		}
	}
	repos, walkErrs := evsStoreWalkOf(ctx, oracle)
	if 0 < len(walkErrs) {
		// what the walk could not read is FI-1's to name; FI-2 cannot hold an answer to a history it could not read
		errs = append(errs, fmt.Errorf("the store walk could not read every repo, so FI-2 holds no answer to it whole: %w", walkErrs[0]))
	}
	errs = append(errs, memory.noteHistory(repos)...)
	errs = append(errs, memory.noteRepoStates(ctx, oracle, repos)...)
	errs = append(errs, memory.checkAnswers(ledgerPushesOf(operations))...)
	records, _, batchErrs := fi6Batches(ctx, oracle, evsOracleMemoryOf(oracle.Net))
	if 0 < len(batchErrs) {
		errs = append(errs, fmt.Errorf("the batches could not be read whole, so FI-2 cannot follow every preparation: %w", batchErrs[0]))
	}
	errs = append(errs, memory.checkReclaimed(oracle, repos, records)...)
	errs = append(errs, fi2CheckAnswerDeletes(oracle, operations, repos)...)
	return errors.Join(errs...)
}

// The head history as this check's walk read it: each version names the push it named at every earlier check, and
// each push id commits once.
func (self *fi2Memory) noteHistory(repos []*evsStoreRepo) []error {
	errs := []error{}
	for _, repo := range repos {
		for _, ref := range repo.refs {
			historyRef := HistoryRef{RepoId: repo.repoId, RefId: ref.refId}
			versions := self.refVersions[historyRef]
			if versions == nil {
				versions = map[uint64]sidecar.Id{}
				self.refVersions[historyRef] = versions
			}
			for _, version := range ref.versions {
				if version == nil {
					continue
				}
				pushId := version.entry.PushId
				if seen, ok := versions[version.version]; ok && seen != pushId {
					errs = append(errs, fmt.Errorf("%s's version %d named push %s and now names %s: a committed result changed", historyRef, version.version, seen, pushId))
					continue
				}
				versions[version.version] = pushId
				commit := self.pushCommits[pushId]
				switch {
				case commit == nil:
					self.pushCommits[pushId] = &fi2Commit{ref: historyRef, version: version.version}
				case commit.ref != historyRef || commit.version != version.version:
					errs = append(errs, fmt.Errorf("push %s committed at %s v%d and at %s v%d: a push id commits at most once (I-EVS-3)", pushId, commit.ref, commit.version, historyRef, version.version))
				}
			}
		}
	}
	return errs
}

// Each walked repo's repo/, and the blob history index of the write that began its shred, the first check that finds
// it shredding or shredded: the write of this step that made the shredding object read now, else this step's
// earliest repo/ write, else 0, before every attempt.
func (self *fi2Memory) noteRepoStates(ctx context.Context, oracle *Oracle, repos []*evsStoreRepo) []error {
	errs := []error{}
	for _, repo := range repos {
		if repo.clusterId == "" {
			continue
		}
		key := sidecar.EvsRepoObjectKey(repo.repoId)
		object, err := oracle.View.Object(ctx, repo.clusterId, key)
		if err != nil {
			errs = append(errs, fmt.Errorf("repo %s's repo/: %w", repo.repoId, err))
			continue
		}
		if object == nil {
			continue
		}
		decoded := &protocol.EvsRepoObject{}
		if err := proto.Unmarshal(object.Body, decoded); err != nil {
			errs = append(errs, fmt.Errorf("repo %s's repo/: %w", repo.repoId, err))
			continue
		}
		state := decoded.GetState()
		shredding := state == protocol.EvsRepoState_EVS_REPO_SHREDDING || state == protocol.EvsRepoState_EVS_REPO_SHREDDED
		if _, started := self.shredStarts[repo.repoId]; shredding && !started {
			start := 0
			earliest := -1
			for i, entry := range oracle.Changed() {
				if entry.ClusterId != repo.clusterId || entry.Key != key || !fi2IsWrite(entry.Op) {
					continue
				}
				index := oracle.previousHistoryCount + i
				if earliest < 0 {
					earliest = index
				}
				if state == protocol.EvsRepoState_EVS_REPO_SHREDDING && entry.WriteEtag == object.Etag {
					start = index
				}
			}
			if start == 0 && 0 <= earliest {
				start = earliest
			}
			self.shredStarts[repo.repoId] = start
		}
		self.repoObjects[repo.repoId] = &fi2RepoObject{etag: object.Etag, state: state}
	}
	return errs
}

func fi2IsWrite(op sidecartest.BlobHistoryOp) bool {
	switch op {
	case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream:
		return true
	}
	return false
}

// What each push id was answered, held to the head history and to its other answers.
func (self *fi2Memory) checkAnswers(pushes []*LedgerPush) []error {
	errs := []error{}
	for _, push := range pushes {
		versions := push.Versions()
		if 1 < len(versions) {
			errs = append(errs, fmt.Errorf("push %s was answered committed at versions %v: a retry of a committed push returns its original result", push.PushId, versions))
		}
		commit := self.pushCommits[push.PushId]
		for _, attempt := range push.Attempts {
			if attempt.Outcome != OutcomeCommitted || commit == nil {
				continue
			}
			if commit.ref != attempt.Ref || commit.version != attempt.Version {
				errs = append(errs, fmt.Errorf("%s, and the head history commits push %s at %s v%d: an answer that is not its original result", attempt, push.PushId, commit.ref, commit.version))
			}
		}
		if commit == nil && 0 < len(versions) {
			// a 200 at a version the history names another push at
			for _, attempt := range push.Attempts {
				if attempt.Outcome != OutcomeCommitted {
					continue
				}
				if named, ok := self.refVersions[attempt.Ref][attempt.Version]; ok && named != push.PushId {
					errs = append(errs, fmt.Errorf("%s, and the head history names push %s at v%d", attempt, named, attempt.Version))
				}
			}
		}
		refusals := push.Refusals()
		if len(refusals) == 0 || (commit == nil && len(versions) == 0) {
			continue
		}
		if self.shredExcuses(push, refusals) {
			continue
		}
		committedAt := ""
		switch {
		case commit != nil:
			committedAt = fmt.Sprintf("the head history commits it at %s v%d", commit.ref, commit.version)
		default:
			committedAt = fmt.Sprintf("it was answered committed at %v", versions)
		}
		errs = append(errs, fmt.Errorf("push %s was answered a refusal (%s) and %s: a refusal a client received stays true (I-EVS-3)", push.PushId, refusals[0], committedAt))
	}
	return errs
}

// §11.12's exception (see the file header): every refusal SHREDDING, an attempt that did not end refused arriving
// before the repo/ write that began the shred, and repo/ shredding or shredded.
func (self *fi2Memory) shredExcuses(push *LedgerPush, refusals []*Operation) bool {
	for _, refusal := range refusals {
		if refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING {
			return false
		}
	}
	start, started := self.shredStarts[push.Ref.RepoId]
	repoObject := self.repoObjects[push.Ref.RepoId]
	if !started || repoObject == nil {
		return false
	}
	if repoObject.state != protocol.EvsRepoState_EVS_REPO_SHREDDING && repoObject.state != protocol.EvsRepoState_EVS_REPO_SHREDDED {
		return false
	}
	for _, attempt := range push.Attempts {
		if attempt.Outcome != OutcomeAborted && 0 < attempt.StoreArrival && attempt.StoreArrival <= start {
			return true
		}
	}
	return false
}

// Reclaimed preparations: a delete this step of an object of a push the last check found uncommitted marks the push
// reclaimed, while the history still does not commit it; a reclaimed push the history commits afterward is a
// violation. Then each uncommitted record's objects are kept for the next check.
func (self *fi2Memory) checkReclaimed(oracle *Oracle, repos []*evsStoreRepo, records []*fi6BatchRecord) []error {
	errs := []error{}
	for _, entry := range oracle.Changed() {
		if entry.Op != sidecartest.BlobHistoryDelete || entry.Outcome != sidecartest.BlobOutcomeOk {
			continue
		}
		for _, pushId := range self.preparedObjects[fi6ObjectKey(entry.ClusterId, entry.Key)] {
			if _, committed := self.pushCommits[pushId]; committed {
				// it committed in this step too, before or after the delete: a committed object's loss is FI-1's
				continue
			}
			if _, ok := self.reclaimed[pushId]; !ok {
				self.reclaimed[pushId] = fmt.Sprintf("%s deleted %s on %s", entry.Actor, entry.Key, entry.ClusterId)
			}
		}
	}
	for pushId, how := range self.reclaimed {
		if commit := self.pushCommits[pushId]; commit != nil {
			errs = append(errs, fmt.Errorf("push %s's preparation was reclaimed (%s) and it committed after, at %s v%d: a reclaimed preparation never commits later", pushId, how, commit.ref, commit.version))
		}
	}

	segmentClusterId := ""
	if segmentCluster, err := oracle.Net.Host().Blobs.SegmentCluster(); err == nil {
		segmentClusterId = segmentCluster.ClusterId()
	}
	repoById := map[sidecar.Id]*evsStoreRepo{}
	for _, repo := range repos {
		repoById[repo.repoId] = repo
	}
	prepared := map[string][]sidecar.Id{}
	add := func(objectKey string, pushId sidecar.Id) {
		if !slices.Contains(prepared[objectKey], pushId) {
			prepared[objectKey] = append(prepared[objectKey], pushId)
		}
	}
	for _, read := range records {
		if _, committed := self.pushCommits[read.record.PushId]; committed {
			continue
		}
		switch fi6Resolve(repoById[read.record.RepoId], read) {
		case fi6CommittedHere, fi6CommittedElsewhere:
			continue
		}
		pushId := read.record.PushId
		add(fi6ObjectKey(read.clusterId, read.batchKey), pushId)
		clusterId := read.clusterId
		if repo := repoById[read.record.RepoId]; repo != nil && repo.clusterId != "" {
			clusterId = repo.clusterId
		}
		for _, slotId := range read.slotIds {
			add(fi6ObjectKey(clusterId, evsOracleSlotKey(read.record.RepoId, slotId)), pushId)
		}
		if segmentClusterId != "" {
			for _, segmentId := range read.segmentIds {
				add(fi6ObjectKey(segmentClusterId, evsOracleSegmentKey(read.record.RepoId, segmentId)), pushId)
			}
		}
	}
	self.preparedObjects = prepared
	return errs
}

// No answer deletes anything: see the file header.
func fi2CheckAnswerDeletes(oracle *Oracle, operations []*Operation, repos []*evsStoreRepo) []error {
	instances := map[string]bool{}
	for _, operation := range operations {
		if operation.Instance != "" && operation.Instance != "lb" {
			instances[operation.Instance] = true
		}
	}
	if len(instances) == 0 {
		return nil
	}
	currentEpochs := map[string]uint64{}
	for _, repo := range repos {
		for _, ref := range repo.refs {
			currentEpochs[evsOracleRefPrefix("idx/", repo.repoId, ref.refId)] = max(1, ref.head.Head.GetPathEpoch().GetCurrent())
		}
	}
	errs := []error{}
	for _, entry := range oracle.Changed() {
		if entry.Op != sidecartest.BlobHistoryDelete || !instances[entry.Actor] {
			continue
		}
		if fi2SourceCopy(entry.Key, currentEpochs) {
			continue
		}
		errs = append(errs, fmt.Errorf("evs instance %s, which answered operations, deleted %s on %s: no answer deletes anything (I-EVS-2)", entry.Actor, entry.Key, entry.ClusterId))
	}
	return errs
}

// Whether key is an index entry of an epoch below its ref's current one: a source copy a fold deletes.
func fi2SourceCopy(key string, currentEpochs map[string]uint64) bool {
	for refPrefix, current := range currentEpochs {
		if !strings.HasPrefix(key, refPrefix) {
			continue
		}
		epoch, _, err := fi6ParseIndexKey(refPrefix, key)
		return err == nil && epoch < current
	}
	return false
}
