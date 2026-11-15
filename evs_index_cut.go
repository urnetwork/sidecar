//go:build !ios_extension

// The erasure's CUT on the client (§11.12's cut row; §11.14's cut and epoch rows; R-EVS-23, D-EVS-26, D-EVS-66, I-EVS-13,
// I-EVS-16, I-EVS-17, FI-19, FS-111; DESIGN-DETAILS 15.2.10 and 15.7's note; SEARCH-M10-16): an erasure's first push on
// each index ref of its documents, the file-mode ref's .ur-index/ or the repo's ur/index, which fences every index push
// built before it.
//
//	set      the push changes one file, the ref's erasure set x (.ur-index/x, or x on ur/index), versionless, staged,
//	         at most SlotMaxByteCount (16,208 B): it keeps every erasure still pending, adds this one, {erasure_id,
//	         eraser, the epoch this CUT names, its signed time_ms, its documents sorted by doc_key}, and drops each
//	         complete erasure only by raising listed_since past the epoch that erasure's CUT named, so the set keeps
//	         every erasure whose epoch is at or above listed_since; complete is read from evs's state (the ERASE notes
//	         of the erasure ref), and an erasure no note completes is pending
//	again    called for an erasure_id the set lists, it adds the documents to that entry, each doc_key at the higher of
//	         its two versions, the entry's epoch and cut_ms kept; called for one the set has dropped, it adds the entry
//	         again (15.7's note: a copy that arrives late)
//	card     a document {Key, ThroughEpoch} is listed through the epoch the CUT names: epoch * 2^b + 2^b - 1, b the
//	         format's CardVersionBitCount, computed at each build, a rebuild after 409 INDEX_EPOCH included, so every
//	         projection made before the CUT is listed whatever landed after its eraser read (QD-779); an epoch past
//	         2^(64-b) lists every version, since no card is written there (QD-783)
//	epoch    the CUT names the head's index_epoch, and evs moves the epoch to the CUT's own version (11.8's 5d), so no
//	         index push but a CLOSURE built before it commits after it (the epoch guard); 409 INDEX_EPOCH, or a 409 on
//	         x, means another CUT landed first: the set is read again and the CUT built again under a new push id
//	full     a set that cannot hold this erasure once every complete one is dropped makes the CUT wait while pending
//	         erasures finish: ErrIndexErasureSetFull, and the caller tries again; its first ERASE does not wait
//	after    the CUT's own device masks what it lists at once through applyCut (CORE-M10-04's SearchCache.ApplyCut);
//	         every other reader masks each listed document at or below its version from the CUT on, as its next round
//	         syncs the set (search_retained.go's erased run)
//
// The CUT runs with the index on or off, and creates ur/index where it is absent (the store's, EVS2-M10-11's). Which
// order a caller takes its CUT and first ERASE in is the caller's: mail CUTs first; a record erasure ERASEs the bodies,
// reads the stream heads again, then CUTs (QD-781). evs takes a CUT only from an admin, in the directory too (§11.12's
// directory row), and readers ignore and alarm a set version from a signer who may not erase (evs_index_view.go,
// search_fetch.go). No indexer takes part. Barriers evs.index.cut.built and .pushed, keyed <repo>/<ref>. Not safe for
// concurrent use: one CUT at a time an eraser.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The erasure set cannot hold this erasure beside the pending ones: the CUT waits while they finish, and the caller
	// tries again (§11.12's cut row).
	ErrIndexErasureSetFull = errors.New("index erasure set full: the CUT waits while pending erasures finish")
	// A CUT built CutAttemptCount times, each refused for a change under it: the caller tries again later.
	errIndexCutAttempts = errors.New("index CUT refused at each attempt")
	// An eraser built without what every CUT needs, or a CUT asked of nothing.
	errIndexEraserArgs = errors.New("index eraser without its store, settings, eraser or clock")
	errIndexCutArgs    = errors.New("index CUT of no erasure or no document")
)

// What erasing the index holds to (QD-702). SEARCH-M10-17's rewrites add their own fields here.
type IndexEraseSettings struct {
	// Builds of one CUT, the first included, before it gives up on the refusals it builds again after: 409
	// INDEX_EPOCH, a 409 on the erasure set, a read answering collected, its life passing unsent: 8, a reading, as the
	// merge's. Each build reads the new set, so this bounds the work a busy ref costs. Positive.
	CutAttemptCount int
}

// The defaults, a fresh value each call.
func DefaultIndexEraseSettings() *IndexEraseSettings {
	return &IndexEraseSettings{CutAttemptCount: 8}
}

// One document a CUT lists.
type IndexCutDocument struct {
	// Its doc_key (a run card's, for ThroughEpoch).
	Key [indexIdByteCount]byte
	// The newest version erased; unread for ThroughEpoch.
	Version uint64
	// A run card, listed through the epoch the CUT names (DESIGN-DETAILS 15.2.10's step 4).
	ThroughEpoch bool
}

// What one CUT lists.
type IndexCutArgs struct {
	// The erasure's 16 random bytes, which its CLOSUREs' and ERASEs' notes name.
	ErasureId Id
	Documents []*IndexCutDocument
}

// What a CUT did.
type IndexCutResult struct {
	// False where the set already listed every document at or above what this CUT would write, so nothing was pushed.
	Pushed bool
	// The ref version the CUT committed at, the ref's index_epoch from then; 0 where nothing was pushed.
	Version uint64
	// The epoch the CUT named, which each ThroughEpoch document is listed through.
	Epoch uint64
	// The set as committed, or as found where nothing was pushed.
	Set *protocol.IndexErasureSet
	// Complete erasures dropped by raising listed_since.
	DroppedCount int
	// Builds made, the committed one included.
	Attempts int
}

// What an eraser reads and writes one index ref with.
type indexEraserArgs struct {
	store     indexRefStore
	repoId    Id
	refId     Id
	repoKind  protocol.RepoKind
	companion bool
	// Which settings and erasure set versions count, as indexViewArgs.isAdmin.
	isAdmin func(file *indexFileVersion) bool
	format  *IndexFormatSettings
	// Nil takes DefaultIndexEraseSettings.
	settings *IndexEraseSettings
	// This device's sidecar_id, the eraser an erasure it adds names.
	eraser Id
	// Which of erasureIds are complete by evs's state: an ERASE of theirs whose note says complete (EvsRepo.Erasures).
	// Nil takes none as complete, so the CUT drops nothing.
	complete func(ctx context.Context, erasureIds []Id) (map[Id]bool, error)
	// This device's own masks of what its CUT lists, at once: CORE-M10-04's SearchCache.ApplyCut over the cache, the
	// journal and the local layer. Nil until that lands; the next sync round's set masks them then.
	applyCut func(ctx context.Context, repoId Id, refId Id, erasureSet *protocol.IndexErasureSet) error
	// Nil is real time.
	clock Clock
	log   Logger
}

// An erasure's pushes on one index ref: the CUT here; the file list, CLOSURE and ERASE pairs, the re-entry and resume
// are SEARCH-M10-17's.
type IndexEraser struct {
	args     indexEraserArgs
	settings *IndexEraseSettings
	clock    Clock
	log      Logger
}

// An eraser of one index ref.
func indexNewEraser(args *indexEraserArgs) (*IndexEraser, error) {
	if args == nil || args.store == nil || args.format == nil || args.eraser == (Id{}) {
		return nil, errIndexEraserArgs
	}
	settings := args.settings
	if settings == nil {
		settings = DefaultIndexEraseSettings()
	}
	if settings.CutAttemptCount <= 0 {
		return nil, fmt.Errorf("%w: a CUT is built at least once", errInvalidSettings)
	}
	if bits := args.format.CardVersionBitCount; bits <= 0 || 64 <= bits {
		return nil, fmt.Errorf("%w: a card's version bits within 1 and 63", errInvalidSettings)
	}
	return &IndexEraser{args: *args, settings: settings, clock: clockOrReal(args.clock), log: loggerOrDefault(args.log)}, nil
}

// The barrier key of this ref: <repo>/<ref>.
func (self *IndexEraser) barrierKey() string {
	return self.args.repoId.String() + "/" + self.args.refId.String()
}

// The ref's index at its head.
func (self *IndexEraser) loadView(ctx context.Context) (*indexView, error) {
	return indexLoadView(ctx, &indexViewArgs{
		store:     self.args.store,
		repoId:    self.args.repoId,
		refId:     self.args.refId,
		repoKind:  self.args.repoKind,
		companion: self.args.companion,
		isAdmin:   self.args.isAdmin,
		settings:  self.args.format,
	})
}

// The version a card is listed through at epoch: epoch * 2^bits + 2^bits - 1, every version where that passes 64 bits.
func indexCardVersionThrough(epoch uint64, bits int) uint64 {
	if uint64(1)<<(64-bits) <= epoch {
		return math.MaxUint64
	}
	return epoch<<bits | (uint64(1)<<bits - 1)
}

// Commits the CUT of args on the ref, built again after each refusal that says another push changed what it read, at
// most CutAttemptCount builds. ErrIndexErasureSetFull where the set cannot hold it; a 429, a quota refusal and an
// unknown outcome a second try did not settle come back as the store's *indexRefusal, unsent again.
func (self *IndexEraser) Cut(ctx context.Context, args *IndexCutArgs) (*IndexCutResult, error) {
	if args == nil || args.ErasureId == (Id{}) || len(args.Documents) == 0 {
		return nil, errIndexCutArgs
	}
	for _, document := range args.Documents {
		if document == nil || document.Key == ([indexIdByteCount]byte{}) || (!document.ThroughEpoch && document.Version == 0) {
			return nil, fmt.Errorf("%w: a document with no doc_key or version", errIndexCutArgs)
		}
	}
	result := &IndexCutResult{}
	for result.Attempts < self.settings.CutAttemptCount {
		result.Attempts += 1
		done, err := self.attempt(ctx, args, result)
		if err != nil || done {
			return result, err
		}
	}
	return result, errIndexCutAttempts
}

// One build of the CUT and its push: true when done, committed or with nothing to push; false with no error builds
// again.
func (self *IndexEraser) attempt(ctx context.Context, args *IndexCutArgs, result *IndexCutResult) (bool, error) {
	signedTime := self.clock.Now()
	view, err := self.loadView(ctx)
	if errors.Is(err, errIndexCollected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		return false, err
	}
	epoch := guard.epoch()
	docs := make([]*protocol.IndexErased, 0, len(args.Documents))
	for _, document := range args.Documents {
		version := document.Version
		if document.ThroughEpoch {
			version = indexCardVersionThrough(epoch, self.args.format.CardVersionBitCount)
		}
		docs = append(docs, &protocol.IndexErased{DocKey: bytes.Clone(document.Key[:]), Version: version})
	}
	added := &protocol.IndexErasure{
		ErasureId:       args.ErasureId.Bytes(),
		EraserSidecarId: self.args.eraser.Bytes(),
		Epoch:           epoch,
		CutMs:           signedTime.UnixMilli(),
		Docs:            docs,
	}
	if indexCutListed(view.erasureSet, added) {
		result.Pushed, result.Version, result.Epoch, result.Set = false, 0, epoch, view.erasureSet
		return true, nil
	}
	complete := map[Id]bool{}
	if self.args.complete != nil && view.erasureSet != nil {
		erasureIds := []Id{}
		for _, erasure := range view.erasureSet.Erasures {
			erasureId, err := IdFromBytes(erasure.ErasureId)
			if err != nil {
				return false, err
			}
			if erasureId != args.ErasureId {
				erasureIds = append(erasureIds, erasureId)
			}
		}
		if 0 < len(erasureIds) {
			if complete, err = self.args.complete(ctx, erasureIds); err != nil {
				return false, err
			}
		}
	}
	next, file, droppedCount, err := indexCutSet(view.erasureSet, added, complete, self.args.format)
	if err != nil {
		return false, err
	}
	replaces := uint64(0)
	if view.erasureSetFile != nil {
		replaces = view.erasureSetFile.version
	}
	push, err := guard.push(indexPushCut, signedTime.UnixMilli(), []*indexPushFile{{
		path: indexErasureSetPath(self.args.companion), plaintext: file, replaces: replaces,
	}}, nil)
	if err != nil {
		return false, err
	}
	testHookBarrier("evs.index.cut.built", self.barrierKey())
	committed, err := indexSendPush(ctx, self.args.store, push, signedTime, self.clock, self.args.format.PushLife)
	switch {
	case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch), errors.Is(err, errIndexPushLifePassed):
		// another CUT landed first, or the life passed: read the set again and build again
		return false, nil
	case err != nil:
		return false, err
	}
	result.Pushed, result.Version, result.Epoch, result.Set, result.DroppedCount = true, committed.version, epoch, next, droppedCount
	testHookBarrier("evs.index.cut.pushed", self.barrierKey())
	if self.args.applyCut != nil {
		if err := self.args.applyCut(ctx, self.args.repoId, self.args.refId, next); err != nil {
			// the CUT stands; the next sync round's set masks what it lists
			self.log.Warningf("[index]a CUT committed and its own masks were not applied: %s", err)
		}
	}
	return true, nil
}

// Whether current already lists every document of added, in added's erasure, at or above its version: a CUT asked
// again with nothing new pushes nothing.
func indexCutListed(current *protocol.IndexErasureSet, added *protocol.IndexErasure) bool {
	if current == nil {
		return false
	}
	for _, erasure := range current.Erasures {
		if !bytes.Equal(erasure.ErasureId, added.ErasureId) {
			continue
		}
		listed := map[[indexIdByteCount]byte]uint64{}
		for _, erased := range erasure.Docs {
			listed[[indexIdByteCount]byte(erased.DocKey)] = erased.Version
		}
		for _, erased := range added.Docs {
			version, ok := listed[[indexIdByteCount]byte(erased.DocKey)]
			if !ok || version < erased.Version {
				return false
			}
		}
		return true
	}
	return false
}

// The set a CUT writes over current: added joined to its entry, or appended; every complete erasure but added's own
// dropped by raising listed_since past its epoch; encoded within SlotMaxByteCount, else ErrIndexErasureSetFull. Answers
// the set, its file and how many erasures it dropped. A pure function of its inputs.
func indexCutSet(current *protocol.IndexErasureSet, added *protocol.IndexErasure, complete map[Id]bool, settings *IndexFormatSettings) (*protocol.IndexErasureSet, []byte, int, error) {
	next := &protocol.IndexErasureSet{}
	if current != nil {
		next = proto.CloneOf(current)
	}
	joined := false
	for _, erasure := range next.Erasures {
		if !bytes.Equal(erasure.ErasureId, added.ErasureId) {
			continue
		}
		// listed again: the documents join, the entry's epoch and cut_ms stay
		versions := map[[indexIdByteCount]byte]uint64{}
		for _, erased := range slices.Concat(erasure.Docs, added.Docs) {
			key := [indexIdByteCount]byte(erased.DocKey)
			versions[key] = max(versions[key], erased.Version)
		}
		erasure.Docs = indexErasedOf(versions)
		joined = true
	}
	if !joined {
		versions := map[[indexIdByteCount]byte]uint64{}
		for _, erased := range added.Docs {
			key := [indexIdByteCount]byte(erased.DocKey)
			versions[key] = max(versions[key], erased.Version)
		}
		entry := proto.CloneOf(added)
		entry.Docs = indexErasedOf(versions)
		next.Erasures = append(next.Erasures, entry)
	}
	// complete erasures go only by raising listed_since past their epochs; every one at or above it stays
	listedSince := next.ListedSince
	for _, erasure := range next.Erasures {
		erasureId, err := IdFromBytes(erasure.ErasureId)
		if err != nil {
			return nil, nil, 0, indexMalformed("an erasure without its id")
		}
		if complete[erasureId] && !bytes.Equal(erasure.ErasureId, added.ErasureId) && listedSince <= erasure.Epoch {
			listedSince = erasure.Epoch + 1
		}
	}
	droppedCount := 0
	next.ListedSince = listedSince
	next.Erasures = slices.DeleteFunc(next.Erasures, func(erasure *protocol.IndexErasure) bool {
		erasureId, _ := IdFromBytes(erasure.ErasureId)
		drop := complete[erasureId] && !bytes.Equal(erasure.ErasureId, added.ErasureId) && erasure.Epoch < listedSince
		if drop {
			droppedCount += 1
		}
		return drop
	})
	file, err := indexEncodeErasureSet(next, settings)
	if isIndexMalformed(err) && settings.SlotMaxByteCount < indexErasureSetByteCount(next) {
		return nil, nil, 0, ErrIndexErasureSetFull
	}
	if err != nil {
		return nil, nil, 0, err
	}
	return next, file, droppedCount, nil
}

// Documents by doc_key, as the set sorts them.
func indexErasedOf(versions map[[indexIdByteCount]byte]uint64) []*protocol.IndexErased {
	docs := make([]*protocol.IndexErased, 0, len(versions))
	for key, version := range versions {
		docs = append(docs, &protocol.IndexErased{DocKey: bytes.Clone(key[:]), Version: version})
	}
	slices.SortFunc(docs, func(a *protocol.IndexErased, b *protocol.IndexErased) int {
		return cmp.Compare(string(a.DocKey), string(b.DocKey))
	})
	return docs
}

// A set's encoded length, its order aside.
func indexErasureSetByteCount(erasureSet *protocol.IndexErasureSet) int {
	return proto.Size(erasureSet)
}
