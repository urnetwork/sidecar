//go:build sidecar_testhooks && !ios_extension && !js

// Index upkeep on a search world, for FS-74's and FS-75's schedules (SEARCH-M10-35): a writer's push planned at the head
// and committed later, so two of one writer's pushes race on its head as §11.14's conflict row has them; a merge of a
// bucket and a roll-up of an expired one, by the index's own merger and roller on the world's store and clock; the
// world's index files as plaintext digests, which two runs of one roll-up compare; and a CUT by the index's eraser,
// which outdates a roll-up built before it.
//
// Every push goes through the world's store, which models path CAS and index_epoch as evs does (search_schedule_
// testhooks.go). Only the sidecar_testhooks build has it, which no release leg is (§22.4). Safe for concurrent use as
// the world is.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"
)

var (
	// A planned push refused for a file another push changed since its base (409).
	ErrSearchTestConflict = errors.New("search test world: a push refused for a change under it")
	// A planned push refused for a CUT since its base (409 INDEX_EPOCH).
	ErrSearchTestIndexEpoch = errors.New("search test world: a push refused for its index epoch")
	// A push refused at the storage limit (a quota refusal), as evs refuses one adding payload while the network is
	// over its limit or spent.
	ErrSearchTestQuota = errors.New("search test world: a push refused at the storage limit")
	// A push the store committed whose answer was lost: its sender cannot tell that it landed.
	ErrSearchTestReplyLost = errors.New("search test world: a push's answer was lost")
)

// The world's repo admin, whose settings and erasure set versions count: the eraser its CUT signs as.
func (self *SearchTestWorld) AdminId() Id {
	digest := sha256.Sum256(append([]byte("search test world admin "), self.repoId.Bytes()...))
	return Id(digest[:16])
}

// Whether a version's signer is the world's admin, or another device of an admin (AddAdmin).
func (self *SearchTestWorld) isAdmin(file *indexFileVersion) bool {
	return self.mayErase(file.signerSidecarId, file.signedTimeMs)
}

// Whether signer may erase the repo's documents, as a device's sync judges an erasure set's signer: the world's admin,
// and each device AddAdmin named.
func (self *SearchTestWorld) mayErase(signer Id, signedTimeMs int64) bool {
	if signer == self.AdminId() {
		return true
	}
	self.adminLock.Lock()
	defer self.adminLock.Unlock()
	return self.adminIds[signer]
}

// Names signer an admin of the repo beside the world's own: another device of the admin's member, whose CUT and
// settings versions count (§11.12's reconcile row).
func (self *SearchTestWorld) AddAdmin(signer Id) {
	self.adminLock.Lock()
	defer self.adminLock.Unlock()
	if self.adminIds == nil {
		self.adminIds = map[Id]bool{}
	}
	self.adminIds[signer] = true
}

// A writer's push planned at a head and not yet committed.
type SearchTestPlannedPush struct {
	store *searchTestStore
	push  *indexPush
}

// The index's view at the head, as signer reads it.
func (self *SearchTestWorld) view(ctx context.Context, signer Id) (*indexView, error) {
	return indexLoadView(ctx, &indexViewArgs{
		store: self.ref.store(signer), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, settings: self.format,
	})
}

// writer's push of documents planned at the head now, as PushDocuments plans it, and not committed.
func (self *SearchTestWorld) PlanPush(ctx context.Context, writer Id, at time.Time, documents []*SearchTestDocument) (*SearchTestPlannedPush, error) {
	pending := []*indexPendingDocument{}
	for _, document := range documents {
		prepared, err := self.prepare(document)
		if err != nil {
			return nil, err
		}
		pending = append(pending, &indexPendingDocument{
			kind: indexEntryFull, key: prepared.key, version: document.Version, keys: prepared.keys, row: prepared.row,
		})
	}
	view, err := self.view(ctx, writer)
	if err != nil {
		return nil, err
	}
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: writer, signedTimeMs: at.UnixMilli(), tables: indexLinkedTables(),
		pending: pending, mayMerge: true,
	})
	if err != nil {
		return nil, err
	}
	if plan.mergeFirst || plan.mergeInPush {
		return nil, errors.New("search test world: a push that merges, which a schedule writes as shards")
	}
	return &SearchTestPlannedPush{store: self.ref.store(writer), push: &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: at.UnixMilli(),
		files: plan.files(), removals: plan.removals(),
	}}, nil
}

// Commits the planned push at the base it was planned at: ErrSearchTestConflict where another push changed a file it
// writes, ErrSearchTestIndexEpoch where a CUT moved the epoch; the ref version it committed at otherwise.
func (self *SearchTestPlannedPush) Commit(ctx context.Context) (uint64, error) {
	committed, err := self.store.Commit(ctx, self.push)
	switch {
	case isIndexRefusal(err, indexRefusalConflict):
		return 0, ErrSearchTestConflict
	case isIndexRefusal(err, indexRefusalIndexEpoch):
		return 0, ErrSearchTestIndexEpoch
	case err != nil:
		return 0, err
	}
	return committed.version, nil
}

// The world's head version.
func (self *SearchTestWorld) HeadVersion(ctx context.Context) (uint64, error) {
	head, err := self.ref.store(Id{}).Head(ctx)
	if err != nil {
		return 0, err
	}
	return head.version, nil
}

// Merges the bucket starting on startDay, 0 for the newest, as a merger signing as signer, on the world's clock: the
// ref version its push committed at, 0 where it committed nothing.
func (self *SearchTestWorld) Merge(ctx context.Context, signer Id, startDay uint32) (uint64, error) {
	result, err := self.MergeResult(ctx, signer, startDay)
	if err != nil {
		return 0, err
	}
	return result.Version, nil
}

// Rolls the oldest expired bucket up into all, as runner, on the world's clock: the ref version its push committed
// at, 0 where none was due or another runner's lock held it.
func (self *SearchTestWorld) RollUp(ctx context.Context, runner Id) (uint64, error) {
	result, err := self.RollUpResult(ctx, runner)
	if err != nil {
		return 0, err
	}
	return result.Version, nil
}

// The start days of the head's buckets, ascending.
func (self *SearchTestWorld) BucketStartDays(ctx context.Context) ([]uint32, error) {
	view, err := self.view(ctx, Id{})
	if err != nil {
		return nil, err
	}
	days := []uint32{}
	for _, bucket := range view.writeRoot().buckets {
		days = append(days, bucket.window.startDay)
	}
	return days, nil
}

// Each index file's plaintext SHA-256 at the head, by path: what two runs of one roll-up compare.
func (self *SearchTestWorld) FileDigests() map[string][sha256.Size]byte {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	digests := map[string][sha256.Size]byte{}
	for path, stored := range self.ref.states[len(self.ref.states)-1].files {
		digests[path] = stored.version.contentSha256
	}
	return digests
}

// The documents of the paths, at their versions, that the head's index files hold live, a bucket's or all's: what a
// reader's merged view could find, before masks.
func (self *SearchTestWorld) LiveDocKeys(ctx context.Context) (map[[indexIdByteCount]byte]uint64, error) {
	view, err := self.view(ctx, Id{})
	if err != nil {
		return nil, err
	}
	root := view.writeRoot()
	held, err := indexLoadHeldKeys(ctx, view, root)
	if err != nil {
		return nil, err
	}
	live := map[[indexIdByteCount]byte]uint64{}
	for key, newest := range held.keyNewests {
		if newest.live {
			live[key] = newest.version
		}
	}
	return live, nil
}

// Commits a CUT listing paths' documents at their versions, as the world's admin, the eraser: the ref version it
// committed at.
func (self *SearchTestWorld) Cut(ctx context.Context, erasureId Id, documents []*SearchTestDocument) (uint64, error) {
	cut := []*IndexCutDocument{}
	for _, document := range documents {
		key, err := self.DocKey(document.Path)
		if err != nil {
			return 0, err
		}
		cut = append(cut, &IndexCutDocument{Key: key, Version: document.Version})
	}
	eraser, err := indexNewEraser(&indexEraserArgs{
		store: self.ref.store(self.AdminId()), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format,
		eraser: self.AdminId(), clock: self.clock,
	})
	if err != nil {
		return 0, err
	}
	result, err := eraser.Cut(ctx, &IndexCutArgs{ErasureId: erasureId, Documents: cut})
	if err != nil {
		return 0, err
	}
	return result.Version, nil
}

// --- what a merge and a roll-up wrote, and the store's faults ---

// What one merge did.
type SearchTestMerge struct {
	// The ref version it committed at; 0 where it committed nothing.
	Version uint64
	// Builds made, the committed one included: more than one where a push of its was refused and it built again.
	Attempts int
}

// Merges the bucket starting on startDay, 0 for the newest, as a merger signing as signer, on the world's clock.
func (self *SearchTestWorld) MergeResult(ctx context.Context, signer Id, startDay uint32) (*SearchTestMerge, error) {
	merger, err := indexNewMerger(&indexMergerArgs{
		store: self.ref.store(signer), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format,
		padKey: func(ctx context.Context) (*indexPadKey, error) { return self.padKey, nil }, tables: indexLinkedTables(),
		clock: self.clock,
	})
	if err != nil {
		return nil, err
	}
	if startDay == 0 {
		view, err := self.view(ctx, signer)
		if err != nil {
			return nil, err
		}
		bucket := view.writeRoot().newestBucket()
		if bucket == nil {
			return &SearchTestMerge{}, nil
		}
		startDay = bucket.window.startDay
	}
	outcome, err := merger.Merge(ctx, indexRootNumber, startDay)
	result := &SearchTestMerge{}
	if outcome != nil {
		result.Attempts = outcome.attempts
		if outcome.committed != nil {
			result.Version = outcome.committed.version
		}
	}
	return result, searchTestErr(err)
}

// What one roll-up did.
type SearchTestRollUp struct {
	// The ref version it committed at; 0 where it committed nothing.
	Version uint64
	// Why it committed nothing without failing: "none", "off", "locked" or "rolled"; "" otherwise.
	Skipped string
	// The bucket it rolled, or was rolling.
	StartDay uint32
	// Builds after its lock, the committed one included.
	Attempts int
	// The plaintext SHA-256 of each file its last build wrote but the runner's own head, by path, and the paths it
	// removed: what two runners of one bucket write alike, whether or not the build committed.
	Content  map[string][sha256.Size]byte
	Removals []string
	// The buckets its promotions went to, by start day.
	PromotedTo []uint32
}

// Rolls the oldest expired bucket up into all, as runner, on the world's clock; ErrSearchTestLockLost where another
// runner took its lapsed lock, ErrSearchTestQuota at the storage limit.
func (self *SearchTestWorld) RollUpResult(ctx context.Context, runner Id) (*SearchTestRollUp, error) {
	roller, err := indexNewRoller(&indexRollerArgs{
		store: self.ref.store(runner), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format,
		padKey: func(ctx context.Context) (*indexPadKey, error) { return self.padKey, nil }, tables: indexLinkedTables(),
		clock: self.clock, runner: runner,
	})
	if err != nil {
		return nil, err
	}
	outcome, err := roller.Roll(ctx, indexRootNumber)
	return searchTestRollUpOf(outcome, runner), searchTestErr(err)
}

// What a roll-up's outcome says, the runner's own head left out of its content.
func searchTestRollUpOf(outcome *indexRollupOutcome, runner Id) *SearchTestRollUp {
	result := &SearchTestRollUp{Content: map[string][sha256.Size]byte{}}
	if outcome != nil {
		result.StartDay, result.Attempts = outcome.startDay, outcome.attempts
		if outcome.committed != nil {
			result.Version = outcome.committed.version
		}
		switch outcome.skipped {
		case indexRollupSkipNone:
			result.Skipped = "none"
		case indexRollupSkipOff:
			result.Skipped = "off"
		case indexRollupSkipLocked:
			result.Skipped = "locked"
		case indexRollupSkipRolled:
			result.Skipped = "rolled"
		}
		if outcome.result != nil {
			for _, file := range outcome.result.files {
				parsed, ok := indexParsePath(file.path, false)
				if ok && (parsed.kind == indexPathSlot || parsed.kind == indexPathLargeEntry) && parsed.writerSidecarId == [indexIdByteCount]byte(runner.Bytes()) {
					continue
				}
				result.Content[file.path] = sha256.Sum256(file.plaintext)
			}
			for _, removal := range outcome.result.removals {
				result.Removals = append(result.Removals, removal.path)
			}
			for startDay := range outcome.result.promoted {
				result.PromotedTo = append(result.PromotedTo, startDay)
			}
			slices.Sort(result.PromotedTo)
		}
	}
	return result
}

// The world's errors for a builder's: a lost lock, the storage limit, a lost reply; any other as it came.
func searchTestErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errIndexLockLost):
		return ErrSearchTestLockLost
	case isIndexRefusal(err, indexRefusalQuota):
		return ErrSearchTestQuota
	}
	return err
}

// One bucket's window.
type SearchTestWindow struct {
	StartDay uint32
	Days     uint32
}

// The head's buckets' windows, ascending.
func (self *SearchTestWorld) BucketWindows(ctx context.Context) ([]SearchTestWindow, error) {
	view, err := self.view(ctx, Id{})
	if err != nil {
		return nil, err
	}
	windows := []SearchTestWindow{}
	for _, bucket := range view.writeRoot().buckets {
		windows = append(windows, SearchTestWindow{StartDay: bucket.window.startDay, Days: bucket.window.days})
	}
	return windows, nil
}

// One writer's files in a bucket.
type SearchTestWriterFiles struct {
	StartDay uint32
	// Its head's path and plaintext length; "" where it holds no slot there.
	Head          string
	HeadByteCount int
	// Its slots and large entries, each at its version.
	Slots []SearchTestFile
	Large []SearchTestFile
}

// writer's files in the bucket starting on startDay, 0 for the newest bucket it holds a file in.
func (self *SearchTestWorld) WriterFiles(ctx context.Context, writer Id, startDay uint32) (*SearchTestWriterFiles, error) {
	view, err := self.view(ctx, writer)
	if err != nil {
		return nil, err
	}
	files := &SearchTestWriterFiles{}
	for _, bucket := range slices.Backward(view.writeRoot().buckets) {
		if startDay != 0 && bucket.window.startDay != startDay {
			continue
		}
		held := bucket.writer(writer)
		if held == nil {
			continue
		}
		files.StartDay = bucket.window.startDay
		if head := held.head(); head != nil {
			files.Head, files.HeadByteCount = head.file.path, head.file.byteCount
		}
		for _, slot := range held.slots {
			files.Slots = append(files.Slots, SearchTestFile{Path: slot.file.path, Version: slot.file.version, ByteCount: slot.file.byteCount})
		}
		for _, large := range held.large {
			files.Large = append(files.Large, SearchTestFile{Path: large.file.path, Version: large.file.version, ByteCount: large.file.byteCount})
		}
		break
	}
	return files, nil
}

// What a push the world's store is about to commit writes, as its faults judge it.
type SearchTestPushShape struct {
	// Index files written and removed, and whether content rides it.
	FileCount    int
	RemovalCount int
	Content      bool
	// An erasure's CUT, which is maintenance at the limit (§11.12's cut row).
	Cut bool
}

// Refuses every push refuse names as evs refuses at the storage limit, until refuse is nil: what a push adding payload
// gets while the network is over its limit or spent (§11.14's limit row).
func (self *SearchTestWorld) SetStorageLimit(refuse func(shape SearchTestPushShape) bool) {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	self.ref.refuse = refuse
}

// The next push the store commits loses its answer: it lands, and its sender gets ErrSearchTestReplyLost, as a head
// CAS whose response the network dropped.
func (self *SearchTestWorld) LoseNextReply() {
	self.ref.stateLock.Lock()
	defer self.ref.stateLock.Unlock()
	self.ref.loseReply = true
}

// What a reproducer made of one push (SEARCH-M10-21).
type SearchTestReproduced struct {
	// "merge", "rollup", "closure", "head" or "none".
	Kind string
	// Outputs it rebuilt and held to their content_sha256, which a device keeps as its own and does not fetch; and
	// outputs it would fetch.
	Matched []string
	Fetch   []string
	// index_mismatch raised, one an output that differed.
	Mismatches int
	// An input it lacked, so it fetched everything and raised nothing.
	Lacking bool
}

// The push that committed refVersion, as a device holding every file at its base reproduces it, signed at signedTime,
// zero taking the time it was signed at: a merge's or a roll-up's outputs rebuilt from its inputs and held to their
// content_sha256 (SEARCH-M10-21; FS-75's reproducer clauses).
func (self *SearchTestWorld) ReproducePush(ctx context.Context, refVersion uint64, signedTime time.Time) (*SearchTestReproduced, error) {
	ref := self.ref
	ref.stateLock.Lock()
	if refVersion == 0 || uint64(len(ref.states)) <= refVersion {
		ref.stateLock.Unlock()
		return nil, errors.New("search test world: no push at that version")
	}
	base, after := ref.states[refVersion-1], ref.states[refVersion]
	ref.stateLock.Unlock()
	head := *base.head
	listing := &indexListing{head: &head}
	for _, stored := range base.files {
		file := *stored.version
		listing.files = append(listing.files, &file)
	}
	slices.SortFunc(listing.files, func(a *indexFileVersion, b *indexFileVersion) int { return strings.Compare(a.path, b.path) })
	push := &indexReproducePush{
		version: refVersion, baseVersion: refVersion - 1, signer: after.signer, signedTimeMs: after.head.signedTimeMs,
		generation: self.padKey.generation,
	}
	if !signedTime.IsZero() {
		push.signedTimeMs = signedTime.UnixMilli()
	}
	for path, stored := range after.files {
		replaced := base.files[path]
		if replaced != nil && replaced.version.version == stored.version.version {
			continue
		}
		file := *stored.version
		written := &indexReproduceFile{file: &file}
		if replaced != nil {
			written.replaces = replaced.version.version
		}
		push.files = append(push.files, written)
	}
	slices.SortFunc(push.files, func(a *indexReproduceFile, b *indexReproduceFile) int {
		return strings.Compare(a.file.path, b.file.path)
	})
	for path, stored := range base.files {
		if after.files[path] == nil {
			push.removals = append(push.removals, &indexPushRemoval{path: path, version: stored.version.version})
		}
	}
	slices.SortFunc(push.removals, func(a *indexPushRemoval, b *indexPushRemoval) int { return strings.Compare(a.path, b.path) })
	reproducer, err := indexNewReproducer(&indexReproducerArgs{
		repoId: self.repoId, refId: self.refId, repoKind: self.kind, isAdmin: self.isAdmin, format: self.format,
		tables: indexLinkedTables(),
		padKeyOf: func(ctx context.Context, generation uint64) (*indexPadKey, error) {
			if generation != self.padKey.generation {
				return nil, errIndexReproduceLacking
			}
			return self.padKey, nil
		},
	})
	if err != nil {
		return nil, err
	}
	outcome, err := reproducer.Reproduce(ctx, push, &indexReproduceBase{
		listing: listing,
		held: func(ctx context.Context, file *indexFileVersion) ([]byte, bool, error) {
			stored := base.files[file.path]
			if stored == nil || stored.version.version != file.version {
				return nil, false, nil
			}
			return bytes.Clone(stored.plaintext), true, nil
		},
	})
	if err != nil {
		return nil, err
	}
	reproduced := &SearchTestReproduced{
		Kind: map[indexReproduceKind]string{
			indexReproduceNone: "none", indexReproduceMerge: "merge", indexReproduceRollup: "rollup",
			indexReproduceClosure: "closure", indexReproduceHead: "head",
		}[outcome.kind],
		Mismatches: len(outcome.events), Lacking: outcome.lacking,
	}
	for _, matched := range outcome.matched {
		reproduced.Matched = append(reproduced.Matched, matched.file.path)
	}
	for _, fetch := range outcome.fetch {
		reproduced.Fetch = append(reproduced.Fetch, fetch.path)
	}
	return reproduced, nil
}
