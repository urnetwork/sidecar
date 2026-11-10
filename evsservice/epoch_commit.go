// Path epochs on evs at the push route's steps (§11.6's due, tail and commit rows; D-EVS-12, FI-3; EVS1-M2-16):
//
//	due     the first commit whose generation pin crosses a REMOVE generation records it in head.path_epoch: each
//	        generation k in (max(the head's generation, its current epoch), the push's] is read from gen/<k>, and the
//	        newest whose GenRotate cause is REMOVE becomes due_generation. evs classifies the crossing immediate when
//	        the newest state shows a shrink after the pin of the generation it crosses from, and batched when only
//	        expiries passed: a compromise retirement shows as a shrink with no holder leaving (§7.9), so evs cannot
//	        tell an agent's shrink, which is batched, from one, and reads every shrink as immediate. Immediate takes
//	        due_by_ms that commit's time and, on shared and owned refs of general, config and mailcfg repos,
//	        due_blocks_creation (plan-EVS1-epoch-kinds#1); batched takes due_by_ms 24 h after the first and no block.
//	        Deposit and erasure refs record no due and stay at epoch 1 for life (plan-EVS1-epoch-kinds#2). A due
//	        already recorded keeps its earlier due_by_ms and its block, an immediate crossing pulling both forward,
//	        and takes the newer generation
//	commit  a PATH_EPOCH push names p_new, a generation above the head's current epoch and at most its own pin's; it
//	        commits only if its map's parts exist under the key path_map_sha256 names, each under 24 h old and part 1
//	        naming this repo, ref, epoch and source head; its source version is in the window with a matching chain;
//	        its tail covers every token path a window version after that source creates (base_entry_version 0), else
//	        409 naming the paths; the head lists fewer than three sources, and fewer than two unless the due blocks
//	        creation, else 412 EPOCH_SOURCES_FULL; and its own process's fold leaves nothing unfolded before step 7,
//	        whose head then carries folded_through = v (§11.7's when row (4)), a fold that cannot finish answering
//	        503, refusing nothing. The head makes p_new current, lists the old current epoch first among its sources
//	        with the committed map's hash, clears the block, and clears the due once p_new reaches its generation.
//
// 5e's epoch and tail refusals are final, and EPOCH_SOURCES_FULL and the map parts' are recorded (§11.8's refuse
// row). Readings, each named in the report: a source outside the window or under another chain is final, answered
// MAP_PARTS, since the window only moves on and the mapper must map again; "path_map_sha256 matches" is the parts'
// presence under the key that hash names, readers checking the parts' bytes against it (§11.9); a batched epoch is
// one whose due does not block creation, so in a repo whose kind never blocks every epoch waits while two sources
// stand.

package evsservice

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §11.6's due row: a batched epoch is due 24 h after the first commit crossing it.
const evsPathEpochBatchedDelay = 24 * time.Hour

// §11.6's map row: a PATH_EPOCH commits on parts each under 24 h old.
const evsPathMapMaxAge = 24 * time.Hour

// §11.6's commit row: at most 3 sources stand, and a batched epoch waits while 2 do.
const (
	evsPathEpochMaxSourceCount         = 3
	evsPathEpochBatchedMaxSourceCount = 2
)

// The most generations one commit's crossing reads, gen/<k> by gen/<k>: past it, 503, refusing nothing.
const evsPathEpochMaxCrossing = 1024

// What a commit crossing REMOVE generations records: the newest one, and whether the crossing is immediate.
type pathEpochDue struct {
	generation uint64
	immediate  bool
	// on a shared or owned ref of a general, config or mailcfg repo: an immediate due blocks creation
	blocks bool
}

// What step 4 read for a PATH_EPOCH push: whether its map's parts stand, and the token paths window versions after
// its source create that its tail does not move.
type pathEpochReads struct {
	partsPresent bool
	uncovered    []sidecar.EvsTokenPath
}

// The due a commit over head records, nil for none. See the file header.
func (self *pushAttempt) pathEpochDueOver(head *protocol.EvsHead) (*pathEpochDue, error) {
	push := self.statement.Push
	refKind := protocol.EvsRefKind(push.GetRefKind())
	if refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || refKind == protocol.EvsRefKind_EVS_REF_ERASURE ||
		push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		return nil, nil
	}
	from := max(head.GetGeneration(), EvsHeadCurrentEpoch(head))
	to := push.GetGeneration()
	if to <= from {
		return nil, nil
	}
	if evsPathEpochMaxCrossing < to-from {
		return nil, fmt.Errorf("a crossing of %d generations", to-from)
	}
	groupId, err := sidecar.IdFromBytes(push.GetGroupId())
	if err != nil {
		return nil, err
	}
	due := &pathEpochDue{}
	for generation := from + 1; generation <= to; generation += 1 {
		record, err := self.engine.generations.Read(self.ctx, self.cluster, groupId, generation, self.gateView)
		if err != nil {
			return nil, err
		}
		if record == nil {
			return nil, fmt.Errorf("no gen/%d to judge the crossing by", generation)
		}
		if sidecar.GkmCause(record.GetCause()) == sidecar.GkmCauseRemove {
			due.generation = generation
		}
	}
	if due.generation == 0 {
		return nil, nil
	}
	due.immediate = true
	if fromRecord, err := self.engine.generations.Read(self.ctx, self.cluster, groupId, from, self.gateView); err == nil && fromRecord != nil {
		if repo := self.gateView.Repo(self.repoId); repo != nil && repo.GetHoldersShrunkAt() <= fromRecord.GetAuth().GetVersion() {
			// only expiries passed since the crossing's start: batched
			due.immediate = false
		}
	}
	switch self.reads.repo.Object.GetKind() {
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG:
		due.blocks = due.immediate && (refKind == protocol.EvsRefKind_EVS_REF_SHARED || refKind == protocol.EvsRefKind_EVS_REF_OWNED)
	}
	return due, nil
}

// prior's path epoch with due recorded at now. See the file header.
func applyPathEpochDue(prior *protocol.EvsPathEpoch, due *pathEpochDue, now time.Time) *protocol.EvsPathEpoch {
	next := &protocol.EvsPathEpoch{Current: max(1, prior.GetCurrent()), Sources: prior.GetSources(),
		DueGeneration: prior.GetDueGeneration(), DueBlocksCreation: prior.GetDueBlocksCreation(), DueByMs: prior.GetDueByMs(),
		BlockUntilMs: prior.GetBlockUntilMs()}
	dueByMs := now.Add(evsPathEpochBatchedDelay).UnixMilli()
	if due.immediate {
		dueByMs = now.UnixMilli()
	}
	if next.GetDueGeneration() == 0 {
		next.DueByMs = dueByMs
		next.DueBlocksCreation = due.blocks
	} else {
		next.DueByMs = min(next.GetDueByMs(), dueByMs)
		next.DueBlocksCreation = next.GetDueBlocksCreation() || due.blocks
	}
	next.DueGeneration = max(next.GetDueGeneration(), due.generation)
	return next
}

// prior's path epoch once a PATH_EPOCH to pNew under mapSha256 commits.
func committedPathEpoch(prior *protocol.EvsHead, pNew uint64, mapSha256 []byte) *protocol.EvsPathEpoch {
	pathEpoch := prior.GetPathEpoch()
	sources := []*protocol.EvsEpochSource{{Epoch: EvsHeadCurrentEpoch(prior), MapSha256: bytes.Clone(mapSha256)}}
	sources = append(sources, pathEpoch.GetSources()...)
	next := &protocol.EvsPathEpoch{Current: pNew, Sources: sources}
	if pNew < pathEpoch.GetDueGeneration() {
		// an epoch below the due generation leaves it due
		next.DueGeneration = pathEpoch.GetDueGeneration()
		next.DueBlocksCreation = pathEpoch.GetDueBlocksCreation()
		next.DueByMs = pathEpoch.GetDueByMs()
	}
	return next
}

// Step 4's reads for a PATH_EPOCH push over head: its map's parts and the creations its tail must move.
func (self *pushAttempt) readPathEpoch(head *protocol.EvsHead) (*pathEpochReads, error) {
	push := self.statement.Push
	reads := &pathEpochReads{}
	present, err := self.pathMapPartsPresent(push)
	if err != nil {
		return nil, err
	}
	reads.partsPresent = present
	covered := map[string]bool{}
	current := EvsHeadCurrentEpoch(head)
	for _, item := range self.payload.TailMoves {
		move := &protocol.EvsPathMove{}
		if err := proto.Unmarshal(item, move); err != nil {
			return nil, err
		}
		for _, source := range move.GetSources() {
			if source.GetEpoch() != current {
				continue
			}
			tokenPath, err := sidecar.ParseEvsChangedTokenPath(source.GetTokenPath())
			if err != nil {
				return nil, err
			}
			covered[tokenPath.KeyString()] = true
		}
	}
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	first := EvsHeadWindowFirstVersion(head)
	for i, entry := range window {
		version := first + uint64(i)
		if version <= push.GetMapSourceVersion() || !entry.CreatesPath() {
			continue
		}
		_, changes, err := self.pushes.allChangesAt(self.ctx, version, entry)
		if err != nil {
			return nil, err
		}
		for _, change := range changes {
			if change.BaseEntryVersion == 0 && !change.Removes() && !covered[change.TokenPath.KeyString()] {
				reads.uncovered = append(reads.uncovered, change.TokenPath)
				covered[change.TokenPath.KeyString()] = true
			}
		}
	}
	return reads, nil
}

// Whether the push's map stands: part 1 names this repo, ref, epoch and the push's source head, and every part it
// counts is listed under the map's key, each under 24 h old.
func (self *pushAttempt) pathMapPartsPresent(push *protocol.EvsPush) (bool, error) {
	pNew := push.GetPathEpoch()
	mapSha256 := push.GetPathMapSha256()
	object, err := self.cluster.Get(self.ctx, PathMapKey(self.repoId, self.refId, pNew, mapSha256, 1))
	if err != nil {
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			return false, nil
		}
		return false, err
	}
	partBytes, err := readAllLimited(object, sidecar.EvsPathMapMaxByteCount)
	object.Body.Close()
	if err != nil {
		return false, err
	}
	_, pathMap, err := sidecar.ParseEvsPathMap(partBytes)
	if err != nil {
		return false, nil
	}
	if sidecar.Id(pathMap.GetRepoId()) != self.repoId || sidecar.Id(pathMap.GetRefId()) != self.refId || pathMap.GetPathEpoch() != pNew ||
		pathMap.GetSourceVersion() != push.GetMapSourceVersion() || !bytes.Equal(pathMap.GetSourceChain(), push.GetMapSourceChain()) {
		return false, nil
	}
	listed := map[string]time.Time{}
	prefix := PathMapPrefix(self.repoId, self.refId, pNew, mapSha256)
	startAfter := ""
	for {
		objects, more, err := self.cluster.List(self.ctx, prefix, startAfter, 1000)
		if err != nil {
			return false, err
		}
		for _, info := range objects {
			listed[info.Key] = info.LastModified
			startAfter = info.Key
		}
		if !more || len(objects) == 0 {
			break
		}
	}
	now := self.engine.clock.Now()
	for part := uint32(1); part <= pathMap.GetParts(); part += 1 {
		uploaded, ok := listed[PathMapKey(self.repoId, self.refId, pNew, mapSha256, part)]
		if !ok || evsPathMapMaxAge <= now.Sub(uploaded) {
			return false, nil
		}
	}
	return true, nil
}

// 5e for a PATH_EPOCH push: see the file header. Set as the view's PathEpochRules.
func (self *pushAttempt) pathEpochRules(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	head := view.Head
	current := uint64(1)
	if view.headExists() {
		current = EvsHeadCurrentEpoch(head)
	}
	pNew := push.GetPathEpoch()
	if pNew <= current || push.GetGeneration() < pNew {
		return newEvsCheckRefusal(EvsCheckReasonPathEpoch, fmt.Sprintf("a PATH_EPOCH to %d at epoch %d and generation %d", pNew, current, push.GetGeneration()))
	}
	pathEpoch := head.GetPathEpoch()
	sourceCount := len(pathEpoch.GetSources())
	if evsPathEpochMaxSourceCount <= sourceCount || (evsPathEpochBatchedMaxSourceCount <= sourceCount && !pathEpoch.GetDueBlocksCreation()) {
		return newEvsCheckRefusal(EvsCheckReasonEpochSourcesFull, fmt.Sprintf("%d sources standing", sourceCount))
	}
	reads := self.pathEpoch
	if reads == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no map read")
	}
	if !reads.partsPresent {
		return newEvsCheckRefusal(EvsCheckReasonMapParts, "a map whose parts do not all stand under 24 h old")
	}
	sourceChain, err := self.baseChainAt(head, push.GetMapSourceVersion())
	if err != nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "the map source's chain")
	}
	if sourceChain == nil || !view.headExists() || head.GetVersion() < push.GetMapSourceVersion() || !bytes.Equal(sourceChain[:], push.GetMapSourceChain()) {
		return newEvsCheckRefusal(EvsCheckReasonMapSource, "a map source outside the window or under another chain")
	}
	if 0 < len(reads.uncovered) {
		refusal := newEvsCheckRefusal(EvsCheckReasonTailMissing, "creations after the map's source its tail does not move")
		refusal.Paths = reads.uncovered
		return refusal
	}
	return nil
}

// The signed path map part's signature: an identity key's statement of type SIGNED_EVS_PATH_MAP under the
// purpose evs-path-epoch.
func verifyEvsPathMapPart(signed *bridge.Signed, identityKey []byte) error {
	return bridge.VerifySigned(signed, evsPathMapPurpose, bridge.SignedType_SIGNED_EVS_PATH_MAP, bridge.SignedKeyAlgEd25519, identityKey)
}

// §6.11's purpose for a path map part.
const evsPathMapPurpose = "evs-path-epoch"
