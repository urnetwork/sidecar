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
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

var (
	// A planned push refused for a file another push changed since its base (409).
	ErrSearchTestConflict = errors.New("search test world: a push refused for a change under it")
	// A planned push refused for a CUT since its base (409 INDEX_EPOCH).
	ErrSearchTestIndexEpoch = errors.New("search test world: a push refused for its index epoch")
)

// The world's repo admin, whose settings and erasure set versions count: the eraser its CUT signs as.
func (self *SearchTestWorld) AdminId() Id {
	digest := sha256.Sum256(append([]byte("search test world admin "), self.repoId.Bytes()...))
	return Id(digest[:16])
}

// Whether a version's signer is the world's admin.
func (self *SearchTestWorld) isAdmin(file *indexFileVersion) bool {
	return file.signerSidecarId == self.AdminId()
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
	merger, err := indexNewMerger(&indexMergerArgs{
		store: self.ref.store(signer), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format,
		padKey: func(ctx context.Context) (*indexPadKey, error) { return self.padKey, nil }, tables: indexLinkedTables(),
		clock: self.clock,
	})
	if err != nil {
		return 0, err
	}
	if startDay == 0 {
		view, err := self.view(ctx, signer)
		if err != nil {
			return 0, err
		}
		bucket := view.writeRoot().newestBucket()
		if bucket == nil {
			return 0, nil
		}
		startDay = bucket.window.startDay
	}
	outcome, err := merger.Merge(ctx, indexRootNumber, startDay)
	if err != nil || outcome.committed == nil {
		return 0, err
	}
	return outcome.committed.version, nil
}

// Rolls the oldest expired bucket up into all, as runner, on the world's clock: the ref version its push committed
// at, 0 where none was due or another runner's lock held it.
func (self *SearchTestWorld) RollUp(ctx context.Context, runner Id) (uint64, error) {
	roller, err := indexNewRoller(&indexRollerArgs{
		store: self.ref.store(runner), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format,
		padKey: func(ctx context.Context) (*indexPadKey, error) { return self.padKey, nil }, tables: indexLinkedTables(),
		clock: self.clock, runner: runner,
	})
	if err != nil {
		return 0, err
	}
	outcome, err := roller.Roll(ctx, indexRootNumber)
	if err != nil || outcome.committed == nil {
		return 0, err
	}
	return outcome.committed.version, nil
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
