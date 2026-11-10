// Path epochs on evs at the push route's steps (§11.6's due, tail and commit rows; D-EVS-12, FI-3; EVS1-M2-16, with
// DESIGN-DETAILS 9.2.6's source rule, between fence and crossing creation, EVS1-M2-44):
//
//	due     the first push whose generation pin crosses a REMOVE generation records it in head.path_epoch: each
//	        generation k in (max(the head's generation, its current epoch), the push's] is read from gen/<k>, and the
//	        newest whose GenRotate cause is REMOVE becomes due_generation. sidecar.EvsClassifyPathEpochDue, which
//	        clients call too, classes the crossing immediate when the newest state shows a shrink after the pin of
//	        the generation it crosses from, and batched when only expiries passed (question
//	        evs1-m2-16-due-classification, option 1). Immediate takes due_by_ms that push's time and, on the refs
//	        sidecar.EvsRefBlocksCreation names, due_blocks_creation (plan-EVS1-epoch-kinds#1); batched takes due_by_ms
//	        24 h after the first and no block. Deposit and erasure refs record no due and stay at epoch 1 for life
//	        (plan-EVS1-epoch-kinds#2). A due already recorded keeps its earlier due_by_ms and its block, an immediate
//	        crossing pulling both forward, and takes the newer generation. The push records it at its commit, or,
//	        when it creates a path the due blocks, at its refusal: 412 PATH_EPOCH_DUE, recorded, whose fence write
//	        sets the due as the commit would have (check_cas.go, refuse.go; question details-9-crossing-creation)
//	commit  a PATH_EPOCH push names p_new, a generation above the head's current epoch and at most its own pin's; it
//	        commits only if the head lists fewer than three sources, and fewer than two unless the due blocks
//	        creation, else 412 EPOCH_SOURCES_FULL; its map's parts exist under the key path_map_sha256 names, each
//	        under 24 h old and part 1 naming this repo, ref, epoch and source head, else 409 MAP_PARTS; its source S
//	        is at or below the head's version with C_S its map_source_chain, the statement at S and C_S read from the
//	        window when it holds S, else from log page S/64, one cached GET, C_S carried from the page's first_chain
//	        (question details-9-map-source-window); the epoch the statement at S declares, a PATH_EPOCH's being its
//	        p_new, is the head's current one, so no PATH_EPOCH committed after S (the between fence); else 409
//	        MAP_SOURCE, final; its tail covers every token path a window version after S creates (base_entry_version
//	        0), else 409 naming the paths, a creation between S and the window being the mapper's to cover; and its
//	        own process's fold leaves nothing unfolded before step 7, whose head then carries folded_through = v
//	        (§11.7's when row (4)), a fold that cannot finish answering 503, refusing nothing. The head makes p_new
//	        current, lists the old current epoch first among its sources with the committed map's hash, clears the
//	        block, and clears the due once p_new reaches its generation.
//
// 5e's epoch, source and tail refusals are final, and EPOCH_SOURCES_FULL and the map parts' are recorded (§11.8's
// refuse row). Readings, each named in the report: "path_map_sha256 matches" is the parts' presence under the key that
// hash names, the copy checking the parts' bytes against it as it reads them (epoch_copy.go; question
// details-9-map-verifiers); a batched epoch is one whose due does not block creation, so in a repo whose kind never
// blocks every epoch waits while two sources stand; the log page holding S is read only when it is among
// MapSourcePageCount pages just below the window, a source further down answering MAP_SOURCE (9.6's "a source below
// the window by one page commits; by more, 409"); S of 0, a map of a ref before its first commit, is C_0 in epoch 1.

package evsservice

import (
	"bytes"
	"crypto/sha256"
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
	evsPathEpochMaxSourceCount        = 3
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
	// immediate unless both the state's shrink and the starting generation's pin are known and say batched
	due.immediate = true
	if fromRecord, err := self.engine.generations.Read(self.ctx, self.cluster, groupId, from, self.gateView); err == nil && fromRecord != nil {
		if repo := self.gateView.Repo(self.repoId); repo != nil {
			due.immediate = sidecar.EvsClassifyPathEpochDue(repo.GetHoldersShrunkAt(), fromRecord.GetAuth().GetVersion())
		}
	}
	due.blocks = due.immediate && sidecar.EvsRefBlocksCreation(self.reads.repo.Object.GetKind(), refKind)
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
	if !view.headExists() {
		return newEvsCheckRefusal(EvsCheckReasonMapSource, "a map of a ref with no head")
	}
	source, err := self.mapSourceAt(head, push.GetMapSourceVersion())
	if err != nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "the map source's statement and chain")
	}
	if source == nil || !bytes.Equal(source.chain[:], push.GetMapSourceChain()) {
		return newEvsCheckRefusal(EvsCheckReasonMapSource, "a map source evs does not hold, or under another chain")
	}
	if source.epoch != current {
		// the between fence: a PATH_EPOCH committed after the map's source, so the mapper maps again
		return newEvsCheckRefusal(EvsCheckReasonMapSource, fmt.Sprintf("a map source in epoch %d, the head's %d", source.epoch, current))
	}
	if 0 < len(reads.uncovered) {
		refusal := newEvsCheckRefusal(EvsCheckReasonTailMissing, "creations after the map's source its tail does not move")
		refusal.Paths = reads.uncovered
		return refusal
	}
	return nil
}

// What a PATH_EPOCH binds at its map's source version S: C_S, and the path epoch S's statement declares.
type pathMapSource struct {
	chain [32]byte
	epoch uint64
}

// The map source at sourceVersion over head: from the window when it holds the version, else from the log page that
// does, when that page is among MapSourcePageCount just below the window. nil when evs holds it in neither: a
// version past the head, or further below the window. See the file header.
func (self *pushAttempt) mapSourceAt(head *protocol.EvsHead, sourceVersion uint64) (*pathMapSource, error) {
	if head.GetVersion() < sourceVersion {
		return nil, nil
	}
	if sourceVersion == 0 {
		// a map of the ref before its first commit: C_0, in the epoch every ref starts in
		return &pathMapSource{chain: sidecar.EvsChainStart(self.repoId, self.refId), epoch: 1}, nil
	}
	entry := windowEntryAt(head, sourceVersion)
	if entry == nil {
		return self.mapSourceBelowWindow(head, sourceVersion)
	}
	chain, err := self.baseChainAt(head, sourceVersion)
	if err != nil || chain == nil {
		return nil, err
	}
	statement, err := self.pushes.statementAt(self.ctx, sourceVersion, entry)
	if err != nil {
		return nil, err
	}
	return &pathMapSource{chain: *chain, epoch: statement.Push.GetPathEpoch()}, nil
}

// The map source at a version below head's window, from its log page: C carried from the page's first_chain
// through each statement to the version's own, and that statement's epoch. nil when the page lies more than
// MapSourcePageCount pages below the window.
func (self *pushAttempt) mapSourceBelowWindow(head *protocol.EvsHead, sourceVersion uint64) (*pathMapSource, error) {
	first := EvsHeadWindowFirstVersion(head)
	if first <= 1 || first <= sourceVersion {
		return nil, nil
	}
	page := EvsLogPageOf(sourceVersion)
	// the page just below the window is the window's last page-out
	if pageCount := self.settings.MapSourcePageCount; pageCount <= 0 || uint64(pageCount) <= EvsLogPageOf(first-1)-page {
		return nil, nil
	}
	logPage, err := self.engine.readLogPage(self.ctx, self.cluster, self.repoId, self.refId, page)
	if err != nil {
		return nil, err
	}
	pageFirst, _ := EvsLogPageVersions(page)
	chain := logPage.FirstChain
	for version := pageFirst; version <= sourceVersion; version += 1 {
		entry, statementBytes, ok := logPage.At(version)
		if !ok {
			return nil, fmt.Errorf("%w: log page %d lacks version %d", ErrEvsLogPageInvalid, page, version)
		}
		// ParseLogPage held each statement to the entry naming it
		chain = sidecar.EvsChainNext(chain, entry.PushId, sha256.Sum256(statementBytes))
		if version < sourceVersion {
			continue
		}
		statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: version %d: %v", ErrEvsLogPageInvalid, version, err)
		}
		return &pathMapSource{chain: chain, epoch: statement.Push.GetPathEpoch()}, nil
	}
	return nil, nil
}

// The signed path map part's signature: an identity key's statement of type SIGNED_EVS_PATH_MAP under the
// purpose evs-path-epoch.
func verifyEvsPathMapPart(signed *bridge.Signed, identityKey []byte) error {
	return bridge.VerifySigned(signed, evsPathMapPurpose, bridge.SignedType_SIGNED_EVS_PATH_MAP, bridge.SignedKeyAlgEd25519, identityKey)
}

// §6.11's purpose for a path map part.
const evsPathMapPurpose = "evs-path-epoch"
