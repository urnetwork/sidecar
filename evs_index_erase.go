//go:build !ios_extension

// An erasure's rewrites on one index ref (§11.14's erase, bound, holds, writers and limit rows; §11.12's closure, rekey,
// versionless, after and reconcile rows; §11.13's wait row; R-EVS-23, D-EVS-26, D-EVS-48, D-EVS-67, I-EVS-13, FI-19,
// FS-78, FS-112; DESIGN-DETAILS 15.2.3 to 15.2.7, 15.2.10 and 15.7's note as owner decision 584 leaves them with full
// entries only, QD-1036; SEARCH-M10-17): after its CUT an eraser takes each listed document out of the index's files by
// CLOSURE pushes, destroys the old keys by ERASEs and folds each run card it listed again.
//
//	list     at a head at or after its CUT, every live index file holding an entry, row or tombstone of one of the
//	         erasure's documents at or below L(k): each writer's slots and large entries in each bucket, absorbed or
//	         not, each bucket shard and each all shard, read from its doc table (I-EVS-11), under every root, i2 beside
//	         i1 during a rebuild. After the CUT every index push but a CLOSURE names its epoch and writes nothing the set
//	         lists, so no later push lengthens the list; a writer's push that writes such a file again makes the
//	         CLOSURE's 409, on which the pass lists again
//	history  the ERASEs also name the key of every index path whose retained version still holds a listed document,
//	         found from the ref's history (the store's Retained): a version a hold kept, a writer slot reused after a
//	         merge, a shard the document left, a bucket a roll-up removed. A live one is rewritten under a fresh key by a
//	         CLOSURE first, with its live bytes where they hold nothing listed. A version committed at or after the
//	         set's newest CUT holds nothing it lists, nor does one this erasure's CLOSURE wrote or replaced. One evs no
//	         longer serves cannot be read, so one replaced within StagedRetention, whose staged bytes may still sit in
//	         a batch under the path's key, counts as holding. A history the store could not walk whole, or a file that
//	         may hold a listed document and does not read, leaves the erasure without complete (fail closed)
//	pairs    CLOSURE pushes (flag 128, admin, no epoch) rewrite each listed file in place by clean (evs_index_closure.go),
//	         under a fresh key in a new slot, in path order and in pairs of whole files sized to the eraser's allowance
//	         (evs_index_wait.go); each CLOSURE's payload lists, and the ERASE after it destroys, the key of every slot any
//	         version of its files named (EvsRepo.SlotKeysOf), so every stored version, staged bytes in a batch included,
//	         goes with it. A general repo's versions name no slot, their keys riding segments the purge deletes, so its
//	         CLOSUREs are followed by no ERASE
//	complete the last ERASE a rewrite sends says complete only where the caller says the erasure ends with this ref's
//	         rewrite and nothing here was left unproven. Where none is left to say it, the list finding nothing to
//	         rewrite or an orphaned CLOSURE's ERASE finding its keys gone, a caller that asks for it (Completion) gets a
//	         completion ERASE (evs_erase_completion.go; QD-1132); any other leaves complete to its own ERASEs. An
//	         erasure counts complete after an ERASE that could have found its keys gone only once evs's state read back
//	         says so
//	relisted an erasure the store reads complete is done, with nothing listed, unless the caller's CUT listed documents
//	         again (IndexRewriteArgs.Relisted; QD-1158): a CUT that adds documents to an erasure already complete, as the
//	         directory's 30-day sweep does for a later-signed card, can reach files no rewrite has listed, so the pass
//	         lists first and rewrites what holds a listed version, the first ERASE opening the erasure again under a
//	         store that reads it by its newest ERASE (recordEraseNewestStore), until the last says complete. A list that
//	         finds nothing, or a set that dropped the erasure since, leaves it complete with nothing sent
//	resume   from evs's state, never one device's memory: an ERASE first for the keys of each CLOSURE of the erasure no
//	         ERASE of it named, saying complete where the list at the head finds nothing else to rewrite, so an erasure
//	         killed between its last CLOSURE and that CLOSURE's ERASE ends with it (QD-1132), then the pairs at the head;
//	         the list is taken before that ERASE goes and its keys go whatever the list did. A duplicate CLOSURE's 409
//	         lists again and finds the file clean, and a duplicate ERASE's NOTHING_TO_ERASE counts done. The eraser's
//	         device resumes at its start,
//	         another device of its member ResumeAfter (25 h) after its CUT or last ERASE, any device that may erase once
//	         its eraser is gone, each committing the CUT itself where a crash or a full set left it missing
//	re-entry each run card the CUT lists through its epoch is folded again at its stream's head and entered full in the
//	         eraser's own head, in a push built in a companion push's order that carries no other document and names
//	         the epoch; a quota refusal waits, holding back no file of the erasure, whose listed card versions the
//	         pairs remove whether or not it was folded again (§11.14's erase and limit rows)
//	limit    on a metadata cluster at §19.9's cohort limit evs's 507 CLUSTER_FULL is the storage limit's refusal to
//	         the index (QD-1118): the pairs and the re-entry wait on it as at the storage limit, the pairs until its
//	         Retry-After, and go on once there is room; the erasure event shows waiting, never a failure
//
// Hints only speed this: every step reads evs's state at the head, so a lost hint publishes nothing, and no indexer
// takes part. No watch follows an ERASE, since the CUT fences. A hold never pauses an ERASE. Not built here: ?closure=1
// uploads, which EvsRepo.Closure does not send yet (evs_closure.go), so at the storage limit or on a full cluster a
// CLOSURE's upload is refused as any upload is and its pair waits on that refusal. Barriers evs.index.erase.listed,
// .closed, .erased and .completed, and evs.index.reenter.built and .pushed, keyed <repo>:<ref>. Paths and documents
// stay on the device (I-13). Not safe for concurrent use: one rewrite or re-entry of an erasure at a time.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The erasure set at the head does not list the erasure: its CUT is committed first (§11.12's reconcile row).
	ErrIndexEraseNotCut = errors.New("index erasure not cut on this ref: its CUT comes first")
	// An erasure that committed nothing, no CUT and no ERASE, never began, and only its own device resumes it (§11.12's
	// reconcile row).
	ErrIndexErasureNotBegun = errors.New("index erasure never began: only its own device's journal retries it")
	// A rewrite or re-entry of no erasure, or a resume asked of no role.
	errIndexEraseArgs = errors.New("index erasure rewrite of no erasure")
	// A rewrite listed again RewriteAttemptCount times, each refused for a change under it: the caller tries again.
	errIndexEraseAttempts = errors.New("index erasure rewrite refused at each attempt")
	// A run card's stream fetched past CardFetchByteCount for an eraser that does not mirror the log: nothing is
	// entered for that card, which its stream's writer or a mirror folds again.
	errIndexCardFetchBound = errors.New("index run card past its fetch bound")
)

// What an eraser asks of evs beyond the index's reads (§11.12's push, closure, rekey and reconcile rows): its CLOSURE and
// ERASE pushes, the keys they name, the versions the ref's history retains and the erasure's progress. indexEvsStore
// implements it on EvsRepo; tests give a fake. Safe for concurrent use.
type indexEraseStore interface {
	// Commits a CLOSURE on the index's ref: each file replacing the version it names, at that version's exact length,
	// its sealed note the erasure's id, its payload erased, which the ERASE after it destroys. Refused as a push is,
	// with an *indexRefusal: 409 for a path another push changed, 429 or a quota at the eraser's allowance, a quota too
	// for a full cluster's 507, with its Retry-After (QD-1118).
	Closure(ctx context.Context, closure *indexClosurePush) (*indexCommitted, error)
	// Commits an ERASE of keys on the repo's erasure ref; one naming only keys already gone answers done.
	Erase(ctx context.Context, erase *indexErasePush) error
	// The key of every slot a version of each path names, across its history and every life, each once; none in a
	// general repo, whose versions name no slot. Fails closed where a path's history does not walk whole.
	KeysOf(ctx context.Context, paths []string) ([]*EvsErasedKey, error)
	// Every version of an index file the ref still stores beside each live path's newest, a removed path's included.
	Retained(ctx context.Context) (*indexRetained, error)
	// The erasure's committed CLOSUREs on the index's ref and its ERASEs on the repo's erasure ref, oldest first.
	Progress(ctx context.Context, erasureId Id) (*indexEraseProgress, error)
}

// One CLOSURE push.
type indexClosurePush struct {
	// A retry of an unknown outcome sends the same id.
	pushId       Id
	erasureId    Id
	baseVersion  uint64
	signedTimeMs int64
	// Each file and the version it replaces.
	files []*indexPushFile
	// The keys the ERASE after it destroys.
	erased []*EvsErasedKey
}

// One ERASE push.
type indexErasePush struct {
	erasureId Id
	keys      []*EvsErasedKey
	complete  bool
	// The caller's bytes of what the keys covered (§11.12's push row), carried by a complete ERASE.
	note []byte
	// A completion ERASE (evs_erase_completion.go; QD-1132): it says complete and names only a key an earlier ERASE
	// of the erasure destroyed, so it destroys nothing. A store answers one evs did not take as done, as any ERASE
	// whose keys are gone, and the eraser reads evs's state back to see whether it ended the erasure.
	completion bool
}

// What the ref's history retains.
type indexRetained struct {
	versions []*indexRetainedVersion
	// The verified head the store walked, when supplied.
	headVersion uint64
	// Every retained version is here: false where the store could not walk the whole history, so no erasure it serves
	// completes.
	complete bool
}

// One retained version of an index path.
type indexRetainedVersion struct {
	file *indexFileVersion
	// Its content is still served (a hold kept it), so the eraser reads it.
	readable bool
	// The ref version and signed time_ms of the push that replaced or removed it, 0 where it still stands.
	replacedVersion uint64
	replacedMs      int64
}

// An erasure's progress on evs.
type indexEraseProgress struct {
	closures []*indexEraseClosed
	erases   []*indexEraseErased
	// A key this erasure named first and no ERASE of the whole ref named again (QD-1137).
	completionKey *EvsErasedKey
}

// One committed CLOSURE of the erasure on the index's ref.
type indexEraseClosed struct {
	// The ref version it committed at.
	version uint64
	keys    []*EvsErasedKey
}

// One committed ERASE of the erasure.
type indexEraseErased struct {
	keys     []*EvsErasedKey
	complete bool
	timeMs   int64
}

// The time_ms of the erasure's last ERASE, 0 for none.
func (self *indexEraseProgress) lastEraseMs() int64 {
	lastMs := int64(0)
	for _, erased := range self.erases {
		lastMs = max(lastMs, erased.timeMs)
	}
	return lastMs
}

// Whether an ERASE of the erasure said complete.
func (self *indexEraseProgress) complete() bool {
	for _, erased := range self.erases {
		if erased.complete {
			return true
		}
	}
	return false
}

// The keys of the erasure's CLOSUREs that no ERASE of it named, in the CLOSUREs' order, each once.
func (self *indexEraseProgress) orphanKeys() []*EvsErasedKey {
	named := map[EvsErasedKey]bool{}
	for _, erased := range self.erases {
		for _, key := range erased.keys {
			named[*key] = true
		}
	}
	orphans := []*EvsErasedKey{}
	for _, closed := range self.closures {
		for _, key := range closed.keys {
			if !named[*key] {
				named[*key] = true
				orphans = append(orphans, &EvsErasedKey{SlotId: key.SlotId, KeyIndex: key.KeyIndex})
			}
		}
	}
	return orphans
}

// Whether the erasure's CLOSURE committed at refVersion.
func (self *indexEraseProgress) closedAt(refVersion uint64) bool {
	for _, closed := range self.closures {
		if closed.version == refVersion {
			return true
		}
	}
	return false
}

// What a rewrite of an erasure's index files is asked.
type IndexRewriteArgs struct {
	ErasureId Id
	// Whether the erasure ends with this ref's rewrite: its last ERASE here then says complete, carrying Note, the
	// caller's bytes of what the keys covered (§11.12's push row), where nothing here was left unproven.
	Complete bool
	Note     []byte
	// With Complete, where the rewrite ends with no ERASE of its own left to say complete and nothing unproven, end
	// the erasure with a completion ERASE (evs_erase_completion.go; QD-1132). False leaves that to the caller, as
	// record_erase.go sends its own, journaled with the record's ERASEs: the result then reads rewriting.
	Completion bool
	// A CUT of the caller's call listed documents again, which may have reached an erasure an ERASE had ended, as the
	// directory's 30-day sweep cuts a later-signed card (QD-1158): the rewrite lists before it trusts a complete it
	// reads, and rewrites each file that holds a listed version, its first ERASE opening the erasure again until one
	// says complete. Where nothing is left to rewrite here the erasure stays complete, as its newest ERASE says, and
	// nothing is sent. False trusts a complete it reads and lists nothing.
	Relisted bool
}

// What a rewrite did.
type IndexRewriteResult struct {
	// The erasure's state after the call: rewriting with nothing left once its pairs ran, waiting on a refusal of the
	// eraser's allowance, done where its complete ERASE committed or one had.
	Erasure *SidecarErasure
	// Pairs and files this call rewrote, and the keys its ERASEs named, orphaned CLOSUREs' included.
	PairCount int
	FileCount int
	KeyCount  int
	// This call's last ERASE said complete, a completion ERASE among them. Where an ERASE could have found its keys
	// gone (an orphaned CLOSURE's, a completion), only once evs's state read back shows the erasure complete.
	Completed bool
	// The history was not walked whole, or a file that may hold a listed document did not read: nothing here said
	// complete, and the erasure stays rewriting until it can.
	Unproven bool
	// Passes made, the last included.
	Attempts int
}

// One file a pass takes: a live version a CLOSURE replaces.
type indexEraseFile struct {
	path indexPath
	file *indexFileVersion
}

// What one pass rewrites and destroys.
type indexEraseWork struct {
	// Live files a CLOSURE rewrites, by path.
	rewrites map[string]*indexEraseFile
	// Removed paths whose keys an ERASE destroys with no CLOSURE.
	keyOnly map[string]bool
	// Something here could not be proven clean: the history did not walk whole, or a file did not read.
	unproven bool
}

// Raises the erasure's event where the eraser has a sink.
func (self *IndexEraser) raise(erasure *SidecarErasure) {
	if self.args.events != nil && erasure != nil {
		copied := *erasure
		self.args.events(&copied)
	}
}

// The erasure the set lists by id, nil for none.
func indexErasureOf(erasureSet *protocol.IndexErasureSet, erasureId Id) *protocol.IndexErasure {
	for _, erasure := range erasureSet.GetErasures() {
		if listedId, err := IdFromBytes(erasure.GetErasureId()); err == nil && listedId == erasureId {
			return erasure
		}
	}
	return nil
}

// L(k) of an erasure's own documents, from the whole set's listing: what its list looks for.
func indexEraseOwnListed(listed indexEraseListed, erasure *protocol.IndexErasure) indexEraseListed {
	own := indexEraseListed{}
	for _, erased := range erasure.GetDocs() {
		if len(erased.GetDocKey()) != indexIdByteCount {
			continue
		}
		key := [indexIdByteCount]byte(erased.GetDocKey())
		if version, ok := listed[key]; ok {
			own[key] = version
		}
	}
	return own
}

// Rewrites the erasure's index files on this ref and destroys their old keys: see the file header. Called again after
// a wait, or at a resume, it carries on from evs's state.
func (self *IndexEraser) Rewrite(ctx context.Context, args *IndexRewriteArgs) (*IndexRewriteResult, error) {
	if self.args.eraseStore == nil {
		return nil, errIndexEraserArgs
	}
	if args == nil || args.ErasureId == (Id{}) {
		return nil, errIndexEraseArgs
	}
	result := &IndexRewriteResult{}
	for result.Attempts < self.settings.RewriteAttemptCount {
		result.Attempts += 1
		done, err := self.rewritePass(ctx, args, result)
		if err != nil || done {
			return result, err
		}
	}
	return result, errIndexEraseAttempts
}

// One pass: the list taken at the head, orphans erased, the pairs sent. True when done, or waiting; false with no
// error to list again.
func (self *IndexEraser) rewritePass(ctx context.Context, args *IndexRewriteArgs, result *IndexRewriteResult) (bool, error) {
	store := self.args.eraseStore
	progress, err := store.Progress(ctx, args.ErasureId)
	if err != nil {
		return false, err
	}
	complete := progress.complete()
	if complete && !args.Relisted {
		result.Erasure = &SidecarErasure{ErasureId: args.ErasureId, State: SidecarErasureDone}
		return true, nil
	}
	orphans := progress.orphanKeys()
	view, listed, work, err := self.listPass(ctx, args.ErasureId, progress)
	if complete && errors.Is(err, ErrIndexEraseNotCut) {
		// relisted, and a later CUT dropped the erasure from the set since it completed: nothing is listed here to
		// rewrite. A CLOSURE no ERASE followed still has its keys erased, saying complete again where the erasure ends
		// here; where it does not, that ERASE opens the erasure again, and the caller's last ERASE ends it
		if 0 < len(orphans) {
			if done, eraseErr := self.eraseOrphans(ctx, args, orphans, args.Complete, result); eraseErr != nil || done {
				return done, eraseErr
			}
			result.Erasure = &SidecarErasure{ErasureId: args.ErasureId, State: SidecarErasureRewriting}
			return true, nil
		}
		result.Erasure = &SidecarErasure{ErasureId: args.ErasureId, State: SidecarErasureDone}
		return true, nil
	}
	if err != nil || work == nil {
		// resume: the keys of each CLOSURE no ERASE followed go whatever the list did (§11.12's reconcile row)
		if 0 < len(orphans) {
			if done, eraseErr := self.eraseOrphans(ctx, args, orphans, false, result); eraseErr != nil || done {
				return done, eraseErr
			}
		}
		return false, err
	}
	if complete && len(orphans) == 0 && len(work.rewrites) == 0 && len(work.keyOnly) == 0 && !work.unproven {
		// relisted, and no file holds a listed version: the erasure stays complete, as its newest ERASE says
		result.Erasure = &SidecarErasure{ErasureId: args.ErasureId, State: SidecarErasureDone}
		return true, nil
	}
	if 0 < len(orphans) {
		// resume: an ERASE first for each CLOSURE no ERASE followed (§11.12's reconcile row), saying complete where
		// nothing else of the erasure is left here (QD-1132), so one killed between its last CLOSURE and that
		// CLOSURE's ERASE ends with it
		last := len(work.rewrites) == 0 && len(work.keyOnly) == 0
		done, err := self.eraseOrphans(ctx, args, orphans, last && args.Complete && !work.unproven, result)
		if err != nil || done {
			return done, err
		}
	}
	return self.sendPairs(ctx, args, view, listed, work, result)
}

// The pass's list at the head (§11.14's erase row; DESIGN-DETAILS 15.2.3): the view, the whole set's listing, and the
// files to rewrite for the erasure's own documents. Reads only. A nil work with no error lists again: a file moved
// under the read.
func (self *IndexEraser) listPass(ctx context.Context, erasureId Id, progress *indexEraseProgress) (*indexView, indexEraseListed, *indexEraseWork, error) {
	view, err := self.loadView(ctx)
	if errors.Is(err, errIndexCollected) {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		return nil, nil, nil, err
	}
	if view.newerFormat {
		// a file this build cannot rewrite may hold the document: nothing is claimed complete
		return nil, nil, nil, errIndexMergeNewerFormat
	}
	erasure := indexErasureOf(view.erasureSet, erasureId)
	if erasure == nil {
		return nil, nil, nil, ErrIndexEraseNotCut
	}
	listed := indexEraseListed(guard.listed)
	own := indexEraseOwnListed(listed, erasure)
	work, err := self.list(ctx, view, own)
	if err != nil {
		return nil, nil, nil, indexRerunCollected(err)
	}
	if err := self.history(ctx, view, own, progress, work); err != nil {
		return nil, nil, nil, indexRerunCollected(err)
	}
	testHookBarrier("evs.index.erase.listed", self.barrierKey())
	return view, listed, work, nil
}

// One ERASE of the keys of each CLOSURE of the erasure no ERASE followed, saying complete with the caller's note where
// asked. True where the call ends here: waiting on a refusal of the eraser's allowance, or done by evs's state read
// back after it said complete, since an ERASE whose keys a racing resumer took first commits nothing.
func (self *IndexEraser) eraseOrphans(ctx context.Context, args *IndexRewriteArgs, orphans []*EvsErasedKey, complete bool, result *IndexRewriteResult) (bool, error) {
	erase := &indexErasePush{erasureId: args.ErasureId, keys: orphans, complete: complete}
	if complete {
		erase.note = args.Note
	}
	if err := self.args.eraseStore.Erase(ctx, erase); err != nil {
		if waiting, ok := self.waitingOf(args.ErasureId, err, nil); ok {
			result.Erasure = waiting
			self.raise(waiting)
			return true, nil
		}
		return false, err
	}
	result.KeyCount += len(orphans)
	testHookBarrier("evs.index.erase.erased", self.barrierKey())
	if !complete {
		return false, nil
	}
	completed, err := self.completeByState(ctx, args.ErasureId, result)
	if err != nil || !completed {
		return false, err
	}
	result.Erasure = &SidecarErasure{ErasureId: args.ErasureId, State: SidecarErasureDone}
	self.raise(result.Erasure)
	return true, nil
}

// Whether evs's state shows the erasure complete, read back after an ERASE of this call that said so: one whose keys
// were gone commits nothing, so it carried no complete. Marks result where it does.
func (self *IndexEraser) completeByState(ctx context.Context, erasureId Id, result *IndexRewriteResult) (bool, error) {
	progress, err := self.args.eraseStore.Progress(ctx, erasureId)
	if err != nil {
		return false, err
	}
	if !progress.complete() {
		return false, nil
	}
	result.Completed = true
	return true, nil
}

// Ends an erasure whose rewrite here is over with no ERASE of it saying complete by a completion ERASE
// (evs_erase_completion.go; QD-1132): one key an earlier ERASE of the erasure destroyed, the caller's note, then evs's
// state read back. An erasure with no such key, or whose completion evs did not take, stays rewriting. True where a
// refusal of the eraser's allowance makes it wait.
func (self *IndexEraser) sendCompletion(ctx context.Context, args *IndexRewriteArgs, result *IndexRewriteResult) (bool, error) {
	store := self.args.eraseStore
	progress, err := store.Progress(ctx, args.ErasureId)
	if err != nil {
		return false, err
	}
	if progress.complete() {
		// another device's ERASE ended it meanwhile
		result.Completed = true
		return false, nil
	}
	key := progress.completionKey
	if key == nil {
		// no ERASE of it destroyed a key that stands unnamed since: nothing here can say complete
		return false, nil
	}
	err = store.Erase(ctx, &indexErasePush{erasureId: args.ErasureId, keys: []*EvsErasedKey{key}, complete: true, note: args.Note, completion: true})
	if err != nil {
		if waiting, ok := self.waitingOf(args.ErasureId, err, nil); ok {
			result.Erasure = waiting
			self.raise(waiting)
			return true, nil
		}
		return false, err
	}
	testHookBarrier("evs.index.erase.completed", self.barrierKey())
	_, err = self.completeByState(ctx, args.ErasureId, result)
	return false, err
}

// The live files holding one of the erasure's documents at or below its listed version (§11.14's erase row).
func (self *IndexEraser) list(ctx context.Context, view *indexView, own indexEraseListed) (*indexEraseWork, error) {
	work := &indexEraseWork{rewrites: map[string]*indexEraseFile{}, keyOnly: map[string]bool{}}
	add := func(path indexPath, file *indexFileVersion) {
		work.rewrites[file.path] = &indexEraseFile{path: path, file: file}
	}
	shards := func(viewShards []*indexViewShard) error {
		for _, shard := range viewShards {
			decoded, err := view.shard(ctx, shard)
			if err != nil {
				return err
			}
			if decoded == nil {
				// a shard this build cannot read may hold the document: nothing here is claimed complete
				work.unproven = true
				continue
			}
			if indexShardHolds(decoded, own) {
				add(shard.path, shard.file)
			}
		}
		return nil
	}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			for _, writer := range bucket.writers {
				for _, file := range slices.Concat(writer.slots, writer.large) {
					if indexSlotHolds(file.slot, own) {
						add(file.path, file.file)
					}
				}
			}
			if err := shards(bucket.shards); err != nil {
				return nil, err
			}
		}
		if err := shards(root.allShards); err != nil {
			return nil, err
		}
	}
	// a slot, large entry or shard the view dropped as malformed may hold the document
	for _, alarm := range view.alarms {
		if alarm.reason != indexViewAlarmMalformed {
			continue
		}
		if parsed, ok := indexParsePath(alarm.path, view.companion); ok && indexPathHoldsDocuments(parsed.kind) {
			work.unproven = true
		}
	}
	return work, nil
}

// Whether a path of kind holds documents: a slot, a large entry or a shard.
func indexPathHoldsDocuments(kind indexPathKind) bool {
	switch kind {
	case indexPathSlot, indexPathLargeEntry, indexPathBucketShard, indexPathAllShard:
		return true
	}
	return false
}

// Every live slot, large entry and shard of the view, by path: what a retained version of a live path is rewritten
// through.
func indexEraseLiveFiles(view *indexView) map[string]*indexEraseFile {
	live := map[string]*indexEraseFile{}
	addShards := func(shards []*indexViewShard) {
		for _, shard := range shards {
			live[shard.file.path] = &indexEraseFile{path: shard.path, file: shard.file}
		}
	}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			for _, writer := range bucket.writers {
				for _, file := range slices.Concat(writer.slots, writer.large) {
					live[file.file.path] = &indexEraseFile{path: file.path, file: file.file}
				}
			}
			addShards(bucket.shards)
		}
		addShards(root.allShards)
	}
	return live
}

// Adds the paths whose retained versions hold, or may hold, one of the erasure's documents (§11.14's erase row's
// history): a live one to rewrite, a removed one for its keys alone.
func (self *IndexEraser) history(ctx context.Context, view *indexView, own indexEraseListed, progress *indexEraseProgress, work *indexEraseWork) error {
	retained, err := self.args.eraseStore.Retained(ctx)
	if err != nil {
		return err
	}
	if retained.headVersion != 0 && retained.headVersion != view.head.version {
		return indexEvsMoved(view.head.version, retained.headVersion)
	}
	if !retained.complete {
		work.unproven = true
	}
	// a version committed at or after the set's newest CUT holds nothing the set lists (the epoch row)
	cutVersion := uint64(0)
	if view.erasureSetFile != nil {
		cutVersion = view.erasureSetFile.commitVersion
	}
	live := indexEraseLiveFiles(view)
	// a live path the view dropped as malformed is no removed path: the list left the erasure unproven for it
	dropped := map[string]bool{}
	for _, alarm := range view.alarms {
		dropped[alarm.path] = true
	}
	now := self.clock.Now()
	for _, version := range retained.versions {
		parsed, ok := indexParsePath(version.file.path, view.companion)
		if !ok || !indexPathHoldsDocuments(parsed.kind) || work.rewrites[version.file.path] != nil ||
			work.keyOnly[version.file.path] || dropped[version.file.path] {
			continue
		}
		if cutVersion <= version.file.commitVersion || progress.closedAt(version.file.commitVersion) ||
			version.replacedVersion != 0 && progress.closedAt(version.replacedVersion) {
			// written after the CUT, or this erasure's CLOSURE wrote it or replaced it and its ERASE took its key
			continue
		}
		holds := false
		readable := version.readable
		if readable {
			plaintext, err := view.store.Read(ctx, version.file)
			switch {
			case errors.Is(err, ErrEvsErased):
				// One missing key can stop reconstruction. The history walk
				// could still identify other slots retaining some of this file.
				holds = true
			case errors.Is(err, errIndexCollected):
				readable = false
			case err != nil:
				return err
			default:
				holds, err = indexHolds(parsed, plaintext, own, view.settings)
				if isIndexMalformed(err) {
					// a retained version that does not read may hold anything
					holds, err = true, nil
				}
				if err != nil {
					return err
				}
			}
		}
		if !readable {
			// its staged bytes may still sit in a batch under the path's key
			holds = version.replacedMs == 0 || now.Sub(time.UnixMilli(version.replacedMs)) < self.settings.StagedRetention
		}
		if !holds {
			continue
		}
		if file := live[version.file.path]; file != nil {
			work.rewrites[version.file.path] = file
		} else {
			work.keyOnly[version.file.path] = true
		}
	}
	return nil
}

// The erasure's state while a refusal of its allowance, or a full cluster's 507 (QD-1118), holds its pairs, and true
// where err is one. A refusal naming the allowance is remembered, so the next pairs stay within it; a 507 names none.
func (self *IndexEraser) waitingOf(erasureId Id, err error, objects []*indexRekeyObject) (*SidecarErasure, bool) {
	allowance, ok := indexEraseAllowanceOf(err)
	if !ok {
		return nil, false
	}
	now := self.clock.Now()
	if 0 < allowance.limit {
		self.allowance, self.allowanceUsed, self.allowanceDay = allowance.limit, allowance.used, indexUtcDay(now)
	}
	return indexEraseWaiting(erasureId, now, objects, allowance, self.settings), true
}

// The days since the epoch of now's UTC date.
func indexUtcDay(now time.Time) int64 {
	return now.UTC().Unix() / (24 * 60 * 60)
}

// The most closure bytes the next pair takes: PairByteCount, and once a 429 named the allowance, what is left of it
// this UTC day, so a pair never spends past it (§11.13's wait row).
func (self *IndexEraser) pairByteCount() int64 {
	byteCount := self.settings.PairByteCount
	if self.allowance <= 0 {
		return byteCount
	}
	if day := indexUtcDay(self.clock.Now()); day != self.allowanceDay {
		self.allowanceUsed, self.allowanceDay = 0, day
	}
	return max(1, min(byteCount, self.allowance-self.allowanceUsed))
}

// Counts a committed pair's closure bytes against the remembered allowance.
func (self *IndexEraser) spend(byteCount int64) {
	if 0 < self.allowance {
		self.allowanceUsed += byteCount
	}
}

// Sends the pass's pairs in path order, then the ERASE of the paths whose keys alone go. True when done or waiting;
// false with no error to list again.
func (self *IndexEraser) sendPairs(ctx context.Context, args *IndexRewriteArgs, view *indexView, listed indexEraseListed, work *indexEraseWork, result *IndexRewriteResult) (bool, error) {
	store := self.args.eraseStore
	paths := []string{}
	for path := range work.rewrites {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	objects := make([]*indexRekeyObject, 0, len(paths))
	for _, path := range paths {
		objects = append(objects, indexNewRekeyObject(path, work.rewrites[path].file.byteCount, self.settings))
	}
	keyOnlyPaths := []string{}
	for path := range work.keyOnly {
		keyOnlyPaths = append(keyOnlyPaths, path)
	}
	slices.Sort(keyOnlyPaths)
	keyOnlyKeys := []*EvsErasedKey{}
	if 0 < len(keyOnlyPaths) {
		var err error
		if keyOnlyKeys, err = store.KeysOf(ctx, keyOnlyPaths); err != nil {
			return false, err
		}
	}
	if work.unproven {
		result.Unproven = true
	}
	mayComplete := args.Complete && !work.unproven
	sentComplete := false
	if 0 < len(objects) {
		self.raise(&SidecarErasure{
			ErasureId: args.ErasureId, State: SidecarErasureRewriting, ObjectsLeft: int64(len(objects)),
			BytesLeft: indexRekeyByteCount(objects),
		})
	}
	for 0 < len(objects) {
		count := indexPairObjectCount(objects, self.pairByteCount())
		pairPaths := paths[:count]
		erased, err := store.KeysOf(ctx, pairPaths)
		if err != nil {
			return false, err
		}
		signedTime := self.clock.Now()
		files := make([]*indexPushFile, 0, count)
		for _, path := range pairPaths {
			taken := work.rewrites[path]
			plaintext, err := view.store.Read(ctx, taken.file)
			if errors.Is(err, errIndexCollected) {
				// the file moved under the list: list again
				return false, nil
			}
			if err != nil {
				return false, err
			}
			cleaned, _, err := indexClean(taken.path, plaintext, listed, view.settings)
			if err != nil {
				return false, err
			}
			files = append(files, &indexPushFile{path: path, plaintext: cleaned, replaces: taken.file.version})
		}
		closure := &indexClosurePush{
			pushId: NewId(), erasureId: args.ErasureId, baseVersion: view.head.version,
			signedTimeMs: signedTime.UnixMilli(), files: files, erased: erased,
		}
		_, err = self.sendClosure(ctx, closure, signedTime)
		switch {
		case isIndexRefusal(err, indexRefusalConflict), errors.Is(err, errIndexPushLifePassed):
			// another push changed a file, or a duplicate CLOSURE: list again at the new head
			return false, nil
		case err != nil:
			if waiting, ok := self.waitingOf(args.ErasureId, err, objects); ok {
				result.Erasure = waiting
				self.raise(waiting)
				return true, nil
			}
			return false, err
		}
		testHookBarrier("evs.index.erase.closed", self.barrierKey())
		self.spend(indexRekeyByteCount(objects[:count]))
		result.PairCount += 1
		result.FileCount += count
		paths, objects = paths[count:], objects[count:]
		last := len(objects) == 0 && len(keyOnlyKeys) == 0
		if 0 < len(erased) {
			complete := last && mayComplete
			erase := &indexErasePush{erasureId: args.ErasureId, keys: erased, complete: complete}
			if complete {
				erase.note = args.Note
			}
			if err := store.Erase(ctx, erase); err != nil {
				// the CLOSURE stands: the next pass's orphan step erases its keys
				if waiting, ok := self.waitingOf(args.ErasureId, err, objects); ok {
					result.Erasure = waiting
					self.raise(waiting)
					return true, nil
				}
				return false, err
			}
			result.KeyCount += len(erased)
			sentComplete = complete
			testHookBarrier("evs.index.erase.erased", self.barrierKey())
		}
		if 0 < len(objects) {
			self.raise(&SidecarErasure{
				ErasureId: args.ErasureId, State: SidecarErasureRewriting, ObjectsLeft: int64(len(objects)),
				BytesLeft: indexRekeyByteCount(objects),
			})
		}
	}
	if 0 < len(keyOnlyKeys) {
		erase := &indexErasePush{erasureId: args.ErasureId, keys: keyOnlyKeys, complete: mayComplete}
		if mayComplete {
			erase.note = args.Note
		}
		if err := store.Erase(ctx, erase); err != nil {
			if waiting, ok := self.waitingOf(args.ErasureId, err, nil); ok {
				result.Erasure = waiting
				self.raise(waiting)
				return true, nil
			}
			return false, err
		}
		result.KeyCount += len(keyOnlyKeys)
		sentComplete = mayComplete
		testHookBarrier("evs.index.erase.erased", self.barrierKey())
	}
	if sentComplete {
		// An independent erasure may have destroyed the same keys first. NOTHING_TO_ERASE carries no note.
		if _, err := self.completeByState(ctx, args.ErasureId, result); err != nil {
			return false, err
		}
	}
	if mayComplete && args.Completion && !result.Completed {
		// no ERASE of this pass said complete: nothing was left to rewrite here, an orphaned CLOSURE's ERASE found its
		// keys gone, or the last pair named no key (QD-1132)
		if waiting, err := self.sendCompletion(ctx, args, result); err != nil || waiting {
			return waiting, err
		}
	}
	state := SidecarErasureRewriting
	if result.Completed {
		state = SidecarErasureDone
	}
	result.Erasure = &SidecarErasure{ErasureId: args.ErasureId, State: state}
	self.raise(result.Erasure)
	return true, nil
}

// Sends one CLOSURE within its life, again under its push id where its outcome is unknown.
func (self *IndexEraser) sendClosure(ctx context.Context, closure *indexClosurePush, signedTime time.Time) (*indexCommitted, error) {
	life := self.args.format.PushLife
	if !indexPushAlive(signedTime, self.clock.Now(), life) {
		return nil, errIndexPushLifePassed
	}
	committed, err := self.args.eraseStore.Closure(ctx, closure)
	if !isIndexRefusal(err, indexRefusalOutcomeUnknown) {
		return committed, err
	}
	if !indexPushAlive(signedTime, self.clock.Now(), life) {
		return nil, err
	}
	return self.args.eraseStore.Closure(ctx, closure)
}

// Who resumes an erasure (§11.12's reconcile row).
type IndexResumeRole int

const (
	// The eraser's own device, at its next start.
	IndexResumeEraser IndexResumeRole = iota + 1
	// Another device of the eraser's member that may erase it, ResumeAfter past its CUT or its last ERASE.
	IndexResumeMember
	// Any device that may erase it, once its eraser is revoked, reaped, suspended or parked.
	IndexResumeAny
)

// What a resume is asked.
type IndexResumeArgs struct {
	ErasureId Id
	Role      IndexResumeRole
	// The erasure's documents as its caller reads them from its ERASEs' notes, which the CUT lists where a crash or a
	// full set left it missing; nil where the caller cannot, and then a missing CUT is ErrIndexEraseNotCut.
	Documents []*IndexCutDocument
	// As IndexRewriteArgs'.
	Complete   bool
	Note       []byte
	Completion bool
}

// What a resume did.
type IndexResumeResult struct {
	// Not yet this device's: another device of the member resumes only from then.
	NotBefore time.Time
	// The CUT it committed, nil where the set listed the erasure.
	Cut     *IndexCutResult
	Rewrite *IndexRewriteResult
}

// Resumes an erasure on this ref from evs's state (§11.12's reconcile row): the CUT where it is missing, then the
// rewrite, whose first step erases each CLOSURE's keys no ERASE named.
func (self *IndexEraser) Resume(ctx context.Context, args *IndexResumeArgs) (*IndexResumeResult, error) {
	if self.args.eraseStore == nil {
		return nil, errIndexEraserArgs
	}
	if args == nil || args.ErasureId == (Id{}) || args.Role < IndexResumeEraser || IndexResumeAny < args.Role {
		return nil, errIndexEraseArgs
	}
	progress, err := self.args.eraseStore.Progress(ctx, args.ErasureId)
	if err != nil {
		return nil, err
	}
	view, err := self.loadView(ctx)
	if err != nil {
		return nil, err
	}
	result := &IndexResumeResult{}
	erasure := indexErasureOf(view.erasureSet, args.ErasureId)
	if erasure == nil && len(progress.erases) == 0 && len(progress.closures) == 0 && args.Role != IndexResumeEraser {
		// an erasure that committed nothing never began: only its own device's journal retries it
		return result, ErrIndexErasureNotBegun
	}
	if args.Role == IndexResumeMember {
		lastMs := progress.lastEraseMs()
		if erasure != nil {
			lastMs = max(lastMs, erasure.GetCutMs())
		}
		notBefore := time.UnixMilli(lastMs).Add(self.settings.ResumeAfter)
		if self.clock.Now().Before(notBefore) {
			result.NotBefore = notBefore
			return result, nil
		}
	}
	if erasure == nil && !progress.complete() {
		if len(args.Documents) == 0 {
			return result, ErrIndexEraseNotCut
		}
		cut, err := self.Cut(ctx, &IndexCutArgs{ErasureId: args.ErasureId, Documents: args.Documents})
		result.Cut = cut
		if err != nil {
			return result, err
		}
	}
	result.Rewrite, err = self.Rewrite(ctx, &IndexRewriteArgs{
		ErasureId: args.ErasureId, Complete: args.Complete, Note: args.Note, Completion: args.Completion,
	})
	return result, err
}

// One run card a re-entry folds again.
type IndexReenterCard struct {
	// Its doc_key, as the CUT listed it through its epoch.
	Key [indexIdByteCount]byte
	// Its stream, which this device holds, and the run.
	Stream indexRecordStream
	RunId  Id
	// The stream's head from evs, never a cache, read after the index's (a companion push's order): the fold's pin.
	Head func(ctx context.Context) (uint64, error)
}

// What a re-entry is asked.
type IndexReenterArgs struct {
	ErasureId Id
	Cards     []*IndexReenterCard
	// The log's ERASEs this device holds, which with the set at the push's base say what each fold leaves out
	// (DESIGN-DETAILS 15.2.2's erased at E).
	Erasures []*RecordStreamErasure
}

// What a re-entry did.
type IndexReenterResult struct {
	// Cards entered, in how many pushes.
	EnteredCount int
	PushCount    int
	// Cards with nothing to enter: an empty fold, blocked, past the version's bits or the fetch bound, one D6 skips,
	// or one already standing above the list.
	SkippedCount int
	// A quota refused the push, the storage limit's or a full cluster's 507 (QD-1118): the cards wait, tried again
	// from NextTry.
	Waiting bool
	NextTry time.Time
	// Builds made, the committed one included.
	Attempts int
}

// Folds each listed run card again at its stream's head and enters it full in this eraser's own head (§11.14's erase
// row; DESIGN-DETAILS 15.2.4's re-entry and 15.2.10's step 5), in key order, in pushes whose entries stay within
// PushDirectByteCount, so that none merges, each built in a companion push's order. A card the index already holds
// above the list, as this eraser's earlier push or a writer's again unit left it, is not entered twice. Built again
// after each refusal that says the index moved, at most RewriteAttemptCount refused builds.
func (self *IndexEraser) Reenter(ctx context.Context, args *IndexReenterArgs) (*IndexReenterResult, error) {
	if self.args.eraseStore == nil || len(self.args.refKey) == 0 {
		return nil, errIndexEraserArgs
	}
	if args == nil || args.ErasureId == (Id{}) {
		return nil, errIndexEraseArgs
	}
	for _, card := range args.Cards {
		if card == nil || card.Stream == nil || card.Head == nil {
			return nil, errIndexEraseArgs
		}
	}
	result := &IndexReenterResult{}
	if len(args.Cards) == 0 {
		return result, nil
	}
	entered := map[[indexIdByteCount]byte]bool{}
	refused := 0
	for pushes := 0; pushes <= len(args.Cards); {
		result.Attempts += 1
		outcome, err := self.reenterAttempt(ctx, args, entered, result)
		switch {
		case err != nil:
			return result, err
		case outcome == indexReenterDone:
			return result, nil
		case outcome == indexReenterPushed:
			pushes += 1
		default:
			refused += 1
			if self.settings.RewriteAttemptCount <= refused {
				return result, errIndexEraseAttempts
			}
		}
	}
	return result, errIndexEraseAttempts
}

// What one build of a re-entry came to.
type indexReenterOutcome int

const (
	// Every card stands, is skipped, or waits on a quota.
	indexReenterDone indexReenterOutcome = iota + 1
	// A push of some of the cards committed; the rest build again at the new head.
	indexReenterPushed
	// Refused for a change under it, or its life passed: built again from step 1.
	indexReenterRefused
)

// One build of the re-entry and its push, in a companion push's order (DESIGN-DETAILS 1.2.6).
func (self *IndexEraser) reenterAttempt(ctx context.Context, args *IndexReenterArgs, entered map[[indexIdByteCount]byte]bool, result *IndexReenterResult) (indexReenterOutcome, error) {
	// 1: the push's signed time, before any read
	signedTime := self.clock.Now()
	// 2: the index at its head
	view, err := self.loadView(ctx)
	if errors.Is(err, errIndexCollected) {
		return indexReenterRefused, nil
	}
	if err != nil {
		return 0, err
	}
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		return 0, err
	}
	if view.newerFormat {
		return 0, errIndexMergeNewerFormat
	}
	if indexErasureOf(view.erasureSet, args.ErasureId) == nil {
		return 0, ErrIndexEraseNotCut
	}
	root := view.writeRoot()
	result.SkippedCount = 0
	if root.off() {
		// an index turned off holds no card: the build that turns it on folds them from the streams
		result.SkippedCount = len(args.Cards) - len(entered)
		return indexReenterDone, nil
	}
	epoch := guard.epoch()
	erasedAtEpoch := newIndexRecordErasures(args.Erasures, view.erasureSet).erasedAtEpoch
	recordSettings := self.args.recordSettings
	if recordSettings == nil {
		recordSettings = DefaultIndexRecordSettings()
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return 0, err
	}
	var held *indexHeldKeys
	// 3 and 4: each card folded at its stream's head, read after the index's
	pending := []*indexPendingDocument{}
	for _, card := range args.Cards {
		if entered[card.Key] {
			continue
		}
		if held == nil {
			if held, err = indexLoadHeldKeys(ctx, view, root); err != nil {
				return 0, indexRerunCollected(err)
			}
		}
		if newest, ok := held.keyNewests[card.Key]; ok && guard.listed[card.Key] < newest.version {
			// standing above the list already: an earlier re-entry, or a writer's again unit
			result.SkippedCount += 1
			continue
		}
		head, err := card.Head(ctx)
		if err != nil {
			return 0, err
		}
		document, _, err := searchRunCard(ctx, card.Stream, card.RunId, head, epoch, erasedAtEpoch, recordSettings, self.args.format)
		switch {
		case errors.Is(err, errIndexCardBlocked), errors.Is(err, errIndexCardVersionSpace), errors.Is(err, errIndexCardFetchBound):
			// entered later by an again unit of the stream's writer or a mirror
			result.SkippedCount += 1
			continue
		case err != nil:
			return 0, err
		case document == nil:
			// a fold with no entry is no document, and the card is gone from search
			result.SkippedCount += 1
			continue
		}
		key, err := indexDocKey(self.args.refKey, card.Stream.RefId(), document.Name, document.Chunk)
		if err != nil {
			return 0, err
		}
		if key != card.Key {
			return 0, fmt.Errorf("%w: a card whose fold is another document", errIndexEraseArgs)
		}
		if guard.erased(key, document.Version) {
			// a fold at the head's epoch is above every version a CUT before it listed: never sent
			return 0, errIndexEpochListed
		}
		prepared, err := document.prepare(normalizer, view.companion, card.Stream.RefId(), view.settings)
		if err != nil {
			return 0, err
		}
		if prepared.skipped {
			result.SkippedCount += 1
			continue
		}
		pending = append(pending, &indexPendingDocument{kind: indexEntryFull, key: key, version: document.Version, keys: prepared.keys, row: prepared.row})
	}
	if len(pending) == 0 {
		return indexReenterDone, nil
	}
	slices.SortFunc(pending, func(a *indexPendingDocument, b *indexPendingDocument) int {
		return compareIndexKeys(a.key, b.key)
	})
	// 5: the eraser's own head, coverage its newest head's rows, none moved; halved until none merges
	batch := pending
	var plan *indexHeadPlan
	for {
		plan, err = indexPlanHead(ctx, &indexHeadPlanArgs{
			view: view, root: root, writer: self.args.eraser, signedTimeMs: signedTime.UnixMilli(), tables: self.args.tables,
			pending: batch, mayMerge: self.args.mayMerge != nil && self.args.mayMerge(),
			coverage: indexWriterNewestRows(root, self.args.eraser),
		})
		if err != nil {
			return 0, err
		}
		if !plan.mergeInPush || len(batch) == 1 {
			break
		}
		batch = batch[:len(batch)/2]
	}
	if plan.mergeFirst {
		return 0, errIndexNoFreeSlot
	}
	files, removals := plan.files(), plan.removals()
	if plan.mergeInPush {
		if self.args.padKey == nil {
			return 0, errIndexCompanionPadKey
		}
		padKey, err := self.args.padKey(ctx)
		if err != nil {
			return 0, err
		}
		if files, removals, err = indexMergeHeadPlan(ctx, view, root, plan, padKey, self.args.tables); err != nil {
			return 0, indexRerunCollected(err)
		}
	}
	testHookBarrier("evs.index.reenter.built", self.barrierKey())
	// 6: sent within the push's life
	push, err := guard.push(indexPushIndex, signedTime.UnixMilli(), files, removals)
	if err != nil {
		return 0, err
	}
	_, err = indexSendPush(ctx, self.args.store, push, signedTime, self.clock, self.args.format.PushLife)
	switch {
	case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch),
		isIndexRefusal(err, indexRefusalRetry), errors.Is(err, errIndexPushLifePassed):
		// built again from step 1, never resent as built
		return indexReenterRefused, nil
	case isIndexRefusal(err, indexRefusalQuota):
		// the re-entry adds payload and waits as builds do, at the storage limit and on a full cluster alike, holding
		// back no file of the erasure
		waiting := indexReenterWaiting(args.ErasureId, self.clock.Now(), len(pending), self.settings)
		result.Waiting, result.NextTry = true, waiting.NextTry
		self.raise(waiting)
		return indexReenterDone, nil
	case err != nil:
		return 0, err
	}
	testHookBarrier("evs.index.reenter.pushed", self.barrierKey())
	for _, document := range batch {
		entered[document.key] = true
	}
	result.EnteredCount += len(batch)
	result.PushCount += 1
	result.Waiting, result.NextTry = false, time.Time{}
	if len(batch) < len(pending) {
		return indexReenterPushed, nil
	}
	return indexReenterDone, nil
}
