//go:build sidecar_testhooks && !ios_extension && !js

// Content on a search world, for FS-74's, FS-75's and FS-79's schedules (SEARCH-M10-35): the world's ref as a file-mode
// ref holding text beside its .ur-index/, read through SEARCH-M10-12's indexContentRef as a device holding the text
// reads its content ref, so the index's own builder, backfiller, settings writes and schedule run on the world's store
// and clock.
//
//	commits   CommitContent is a push that writes no index entry: an old client's, a phone's or a format-1 client's.
//	          CommitIndexed is an in-ref writer's (SEARCH-M10-13's IndexWriter on the push builder): the content and
//	          the writer's head planned at the push's base and committed at one ref version under one CAS, each
//	          change extracted in one pass, a chunk a document; a removal, a turn to binary, a chunk D6 skips and a
//	          chunk the new version lost are tombstones where the replaced version held them; a config, mailcfg or
//	          secret repo, a path the never row keeps out, and an index that is off take no entry
//	versions  a path's entry version is one past the version it replaces, a removal's included, and a creation's one
//	          past the push's base (11.7's versions), as the store gives index files theirs
//	reads     the world's content ref answers its head, every push of the ref with the paths it changed (index files
//	          among them, which the never row keeps out), a path's state at a version and the paths standing there; an
//	          in-ref push is one that wrote index files beside its content
//	upkeep    Build and FirstBuild (SEARCH-M10-15's IndexBuilder), Backfill (SEARCH-M10-12's IndexBackfiller), SetIndex
//	          (an admin's settings version, evs_index_admin.go) and NewUpkeep (SEARCH-M10-11's schedule: one device's
//	          merges, roll-ups and backfills a tick), each signing as the device it names
//	coverage  a device made with SearchTestDeviceArgs.Coverage reads indexed_through as SEARCH-M10-12's reader does,
//	          over the world's content at the world's head, which a schedule syncs to before it searches
//
// Only the sidecar_testhooks build has it, which no release leg is (§22.4). Safe for concurrent use as the world is.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	// A build or roll-up whose lapsed lock another runner took: its push fails at the lock's CAS (errIndexLockLost).
	ErrSearchTestLockLost = errors.New("search test world: the runner's lock was lost")
	// A build in a repo that holds no index (errIndexBuildExcluded).
	ErrSearchTestExcluded = errors.New("search test world: a repo that holds no index")
)

// One change of a content push: Content at Path, nil removing the path.
type SearchTestChange struct {
	Path    string
	Content []byte
}

// What a content push committed.
type SearchTestCommit struct {
	// The ref version it committed at, and its signed time.
	RefVersion uint64
	Time       time.Time
	// Each change's entry version, by path.
	Versions map[string]uint64
	// The index files and removals it carried beside its content: 0 for a push that wrote no index entry.
	IndexWriteCount int
}

// One version of a content path: its bytes, nil for a removal.
type searchTestContentVersion struct {
	commitVersion uint64
	version       uint64
	content       []byte
}

// One change as a push commits it: the entry version it writes and the standing version it replaces, 0 for a
// creation.
type searchTestContentChange struct {
	path     string
	version  uint64
	replaces uint64
	content  []byte
}

// The path's standing entry version at refVersion, 0 for a path absent or removed there. The lock held.
func (self *searchTestRef) contentStandingWithLock(path string, refVersion uint64) uint64 {
	if version := self.contentAtWithLock(path, refVersion); version != nil && version.content != nil {
		return version.version
	}
	return 0
}

// The path's newest version committed at or below refVersion, nil for none. The lock held.
func (self *searchTestRef) contentAtWithLock(path string, refVersion uint64) *searchTestContentVersion {
	var newest *searchTestContentVersion
	for _, version := range self.contentVersions[path] {
		if version.commitVersion <= refVersion {
			newest = version
		}
	}
	return newest
}

// Records content's changes at next's version. The lock held.
func (self *searchTestRef) applyContentWithLock(next *searchTestState, content []*searchTestContentChange) {
	for _, change := range content {
		self.contentVersions[change.path] = append(self.contentVersions[change.path], &searchTestContentVersion{
			commitVersion: next.head.version, version: change.version, content: bytes.Clone(change.content),
		})
		next.contentPaths = append(next.contentPaths, change.path)
	}
	slices.Sort(next.contentPaths)
}

// changes as a push at base commits them: each one's entry version and the standing version it replaces. A removal of
// a path that does not stand, or a path twice, is refused. The lock held.
func (self *searchTestRef) planContentWithLock(base uint64, changes []*SearchTestChange) ([]*searchTestContentChange, error) {
	planned := []*searchTestContentChange{}
	seen := map[string]bool{}
	for _, change := range changes {
		if change == nil || change.Path == "" || seen[change.Path] {
			return nil, errors.New("search test world: a content change without a path, or one path twice")
		}
		seen[change.Path] = true
		replaces := self.contentStandingWithLock(change.Path, base)
		next := &searchTestContentChange{path: change.Path, replaces: replaces, content: change.Content}
		switch {
		case change.Content == nil && replaces == 0:
			return nil, fmt.Errorf("search test world: a removal of a path that does not stand")
		case replaces == 0:
			next.version = base + 1
		default:
			next.version = replaces + 1
		}
		planned = append(planned, next)
	}
	return planned, nil
}

// The SearchTestCommit of a committed push.
func searchTestCommitOf(version uint64, at time.Time, content []*searchTestContentChange, indexWriteCount int) *SearchTestCommit {
	commit := &SearchTestCommit{RefVersion: version, Time: at, Versions: map[string]uint64{}, IndexWriteCount: indexWriteCount}
	for _, change := range content {
		commit.Versions[change.path] = change.version
	}
	return commit
}

// signer's push of changes at at, writing no index entry: an old client's, a phone's or a format-1 client's, which
// reads not yet searchable until a build or a backfill covers it. It names no index_epoch, being no index push.
func (self *SearchTestWorld) CommitContent(ctx context.Context, signer Id, at time.Time, changes []*SearchTestChange) (*SearchTestCommit, error) {
	ref := self.ref
	ref.stateLock.Lock()
	defer ref.stateLock.Unlock()
	base := ref.states[len(ref.states)-1].head.version
	content, err := ref.planContentWithLock(base, changes)
	if err != nil {
		return nil, err
	}
	committed, err := ref.commitWithLock(signer, &indexPush{pushId: NewId(), baseVersion: base, signedTimeMs: at.UnixMilli()}, content)
	if err != nil {
		return nil, err
	}
	return searchTestCommitOf(committed.version, at, content, 0), nil
}

// One extraction of a content version: its documents, the chunks D6 skipped, its chunk count, and whether it was text.
type searchTestExtraction struct {
	full    []*indexStreamDocument
	skipped []uint32
	count   uint32
	text    bool
}

// Extracts content as the in-ref writer does, in one pass, a chunk a document: mail for a mailbox's m/ messages, files
// for the rest (indexExtractorKind); nil content extracts nothing.
func (self *SearchTestWorld) extract(path string, version uint64, content []byte) (*searchTestExtraction, error) {
	extraction := &searchTestExtraction{}
	if content == nil {
		return extraction, nil
	}
	self.normalizerLock.Lock()
	defer self.normalizerLock.Unlock()
	kind := indexExtractorKind(indexPlace{repoKind: self.kind, path: path})
	streamArgs := &indexStreamArgs{
		template:   &IndexDocument{Kind: kind, Name: []byte(path), Version: version},
		byteCount:  uint64(len(content)),
		normalizer: self.normalizer,
		refId:      self.refId,
		settings:   self.format,
		emit: func(document *indexStreamDocument) error {
			extraction.count = max(extraction.count, document.chunk+1)
			if document.skipped {
				extraction.skipped = append(extraction.skipped, document.chunk)
				return nil
			}
			extraction.full = append(extraction.full, document)
			return nil
		},
	}
	if kind == IndexDocMail {
		// a message is always text, written to the extractor in one piece
		stream := indexExtractMailStream(streamArgs)
		if _, err := stream.Write(content); err != nil {
			return nil, err
		}
		if err := stream.Close(); err != nil {
			return nil, err
		}
		extraction.text = true
		return extraction, nil
	}
	text, err := indexExtractFileStream(streamArgs, bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	extraction.text = text
	if !text {
		extraction.count = 0
		extraction.full, extraction.skipped = nil, nil
	}
	return extraction, nil
}

// The entries an in-ref writer's push carries for change, the version it replaces read at base: see the file header.
func (self *SearchTestWorld) pendingOf(change *searchTestContentChange, replaced []byte) ([]*indexPendingDocument, error) {
	keyOf := func(chunk uint32) ([indexIdByteCount]byte, error) {
		return indexDocKey(self.refKey, self.refId, []byte(change.path), chunk)
	}
	pending := []*indexPendingDocument{}
	tombstones := func(from uint32, to uint32) error {
		for chunk := from; chunk < to; chunk += 1 {
			key, err := keyOf(chunk)
			if err != nil {
				return err
			}
			pending = append(pending, &indexPendingDocument{kind: indexEntryTombstone, key: key, version: change.version})
		}
		return nil
	}
	previous, err := self.extract(change.path, change.replaces, replaced)
	if err != nil {
		return nil, err
	}
	if change.content == nil {
		return pending, tombstones(0, previous.count)
	}
	current, err := self.extract(change.path, change.version, change.content)
	if err != nil {
		return nil, err
	}
	if !current.text {
		return pending, tombstones(0, previous.count)
	}
	for _, document := range current.full {
		key, err := keyOf(document.chunk)
		if err != nil {
			return nil, err
		}
		pending = append(pending, &indexPendingDocument{kind: indexEntryFull, key: key, version: change.version, keys: document.keys, row: document.row})
	}
	for _, chunk := range current.skipped {
		if chunk < previous.count {
			if err := tombstones(chunk, chunk+1); err != nil {
				return nil, err
			}
		}
	}
	return pending, tombstones(current.count, previous.count)
}

// writer's in-ref push of changes at at: the content and writer's head planned at the head as it reads now and
// committed together, under one CAS, at the next ref version; ErrSearchTestConflict where a push changed a path it
// writes since, ErrSearchTestIndexEpoch where a CUT did. A push the planner would merge first or inside is refused, as
// PushDocuments refuses one.
func (self *SearchTestWorld) CommitIndexed(ctx context.Context, writer Id, at time.Time, changes []*SearchTestChange) (*SearchTestCommit, error) {
	return self.commitIndexed(ctx, writer, at, changes, false)
}

// As CommitIndexed, but a push whose entries pass DirectBytes merges them into the buckets' shards in the same push,
// as the in-ref writer does (indexMergeHeadPlan): a large message's chunks land in its bucket's shards (FS-112).
func (self *SearchTestWorld) CommitIndexedMerging(ctx context.Context, writer Id, at time.Time, changes []*SearchTestChange) (*SearchTestCommit, error) {
	return self.commitIndexed(ctx, writer, at, changes, true)
}

// See CommitIndexed; mergeInPush merges a push past DirectBytes in the push rather than refusing it.
func (self *SearchTestWorld) commitIndexed(ctx context.Context, writer Id, at time.Time, changes []*SearchTestChange, mergeInPush bool) (*SearchTestCommit, error) {
	planned, err := self.planIndexed(ctx, writer, at, changes, mergeInPush)
	if err != nil {
		return nil, err
	}
	return planned.Commit(ctx)
}

// A writer's in-ref push planned at a head and not yet committed: its content and the writer's head, as CommitIndexed
// builds them.
type SearchTestPlannedContentPush struct {
	world   *SearchTestWorld
	writer  Id
	at      time.Time
	push    *indexPush
	content []*searchTestContentChange
}

// writer's in-ref push of changes planned at the head now, as CommitIndexed plans it, and not committed: what a schedule
// lands a merge or another push of the writer's before.
func (self *SearchTestWorld) PlanIndexed(ctx context.Context, writer Id, at time.Time, changes []*SearchTestChange) (*SearchTestPlannedContentPush, error) {
	return self.planIndexed(ctx, writer, at, changes, false)
}

// Commits the planned push at the base it was planned at, content and head under one CAS: ErrSearchTestConflict where
// a push changed a path it writes since, ErrSearchTestIndexEpoch where a CUT did.
func (self *SearchTestPlannedContentPush) Commit(ctx context.Context) (*SearchTestCommit, error) {
	ref := self.world.ref
	committed, err := func() (*indexCommitted, error) {
		ref.stateLock.Lock()
		defer ref.stateLock.Unlock()
		return ref.commitWithLock(self.writer, self.push, self.content)
	}()
	switch {
	case isIndexRefusal(err, indexRefusalConflict):
		return nil, ErrSearchTestConflict
	case isIndexRefusal(err, indexRefusalIndexEpoch):
		return nil, ErrSearchTestIndexEpoch
	case err != nil:
		return nil, err
	}
	return searchTestCommitOf(committed.version, self.at, self.content, len(self.push.files)+len(self.push.removals)), nil
}

// See PlanIndexed; mergeInPush merges a push past DirectBytes in the push rather than refusing it.
func (self *SearchTestWorld) planIndexed(ctx context.Context, writer Id, at time.Time, changes []*SearchTestChange, mergeInPush bool) (*SearchTestPlannedContentPush, error) {
	return self.planIndexedClaiming(ctx, writer, at, changes, mergeInPush, nil)
}

// See planIndexed; a path claimed names takes its entries from the claim in place of the bytes the push commits
// (SearchTestClaim): a writer lying in its own head.
func (self *SearchTestWorld) planIndexedClaiming(ctx context.Context, writer Id, at time.Time, changes []*SearchTestChange, mergeInPush bool, claimed map[string]*SearchTestClaim) (*SearchTestPlannedContentPush, error) {
	view, err := self.view(ctx, writer)
	if err != nil {
		return nil, err
	}
	base := view.head.version
	ref := self.ref
	content, replaced, err := func() ([]*searchTestContentChange, [][]byte, error) {
		ref.stateLock.Lock()
		defer ref.stateLock.Unlock()
		content, err := ref.planContentWithLock(base, changes)
		if err != nil {
			return nil, nil, err
		}
		replaced := [][]byte{}
		for _, change := range content {
			var previous []byte
			if version := ref.contentAtWithLock(change.path, base); version != nil {
				previous = version.content
			}
			replaced = append(replaced, previous)
		}
		return content, replaced, nil
	}()
	if err != nil {
		return nil, err
	}
	push := &indexPush{pushId: NewId(), baseVersion: base, indexEpoch: view.head.indexEpoch, signedTimeMs: at.UnixMilli()}
	if !indexRepoExcluded(self.kind) {
		pending := []*indexPendingDocument{}
		for index, change := range content {
			if indexExcluded(indexPlace{repoKind: self.kind, path: change.path}) {
				continue
			}
			entered := change
			if claim := claimed[change.path]; claim != nil {
				forged := *change
				forged.content = claim.Content
				entered = &forged
			}
			documents, err := self.pendingOf(entered, replaced[index])
			if err != nil {
				return nil, err
			}
			pending = append(pending, documents...)
		}
		if 0 < len(pending) {
			plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
				view: view, root: view.writeRoot(), writer: writer, signedTimeMs: at.UnixMilli(), tables: indexLinkedTables(),
				pending: pending, mayMerge: true,
			})
			if err != nil {
				return nil, err
			}
			if plan.mergeFirst || plan.mergeInPush && !mergeInPush {
				return nil, errors.New("search test world: a push that merges, which a schedule writes as shards")
			}
			push.files, push.removals = plan.files(), plan.removals()
			if plan.mergeInPush {
				push.files, push.removals, err = indexMergeHeadPlan(ctx, view, view.writeRoot(), plan, self.padKey, indexLinkedTables())
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return &SearchTestPlannedContentPush{world: self, writer: writer, at: at, push: push, content: content}, nil
}

// --- the content ref, as SEARCH-M10-12 reads one ---

// The world's ref as its own content ref.
type searchTestContentRef struct {
	world *SearchTestWorld
}

var _ indexContentRef = (*searchTestContentRef)(nil)

// The world's content ref.
func (self *SearchTestWorld) contentRef() *searchTestContentRef {
	return &searchTestContentRef{world: self}
}

// See indexContentRef.
func (self *searchTestContentRef) RefId() Id {
	return self.world.refId
}

// See indexContentRef: the ref's head.
func (self *searchTestContentRef) Head(ctx context.Context) (*indexContentHead, error) {
	ref := self.world.ref
	ref.stateLock.Lock()
	defer ref.stateLock.Unlock()
	head := ref.states[len(ref.states)-1].head
	return &indexContentHead{version: head.version, signedTimeMs: head.signedTimeMs}, nil
}

// See indexContentRef: every push of the ref in the range, with each path it changed.
func (self *searchTestContentRef) Pushes(ctx context.Context, afterVersion uint64, throughVersion uint64) ([]*indexContentPush, error) {
	ref := self.world.ref
	ref.stateLock.Lock()
	defer ref.stateLock.Unlock()
	pushes := []*indexContentPush{}
	for version := afterVersion + 1; version <= throughVersion && version < uint64(len(ref.states)); version += 1 {
		previous, state := ref.states[version-1], ref.states[version]
		push := &indexContentPush{
			version: version, signedTimeMs: state.head.signedTimeMs, signer: state.signer, changesHead: state.inRef,
		}
		paths := slices.Clone(state.contentPaths)
		for path, stored := range state.files {
			if old := previous.files[path]; old == nil || old.version.version != stored.version.version {
				paths = append(paths, path)
			}
		}
		for path := range previous.files {
			if state.files[path] == nil {
				paths = append(paths, path)
			}
		}
		slices.Sort(paths)
		for _, path := range slices.Compact(paths) {
			push.changes = append(push.changes, &indexContentChange{path: path})
		}
		pushes = append(pushes, push)
	}
	return pushes, nil
}

// See indexContentRef: the path's newest version at the ref version.
func (self *searchTestContentRef) State(ctx context.Context, path string, refVersion uint64) (*indexContentState, error) {
	ref := self.world.ref
	ref.stateLock.Lock()
	defer ref.stateLock.Unlock()
	version := ref.contentAtWithLock(path, refVersion)
	if version == nil {
		return &indexContentState{}, nil
	}
	state := &indexContentState{version: version.version, commitVersion: version.commitVersion, removed: version.content == nil}
	if version.content != nil {
		state.content = bytes.NewReader(version.content)
		state.byteCount = uint64(len(version.content))
	}
	return state, nil
}

// See indexContentRef: every path standing at the ref version, in order.
func (self *searchTestContentRef) Paths(ctx context.Context, refVersion uint64, visit func(path string, byteCount uint64) error) error {
	standing := func() map[string]uint64 {
		ref := self.world.ref
		ref.stateLock.Lock()
		defer ref.stateLock.Unlock()
		standing := map[string]uint64{}
		for path := range ref.contentVersions {
			if version := ref.contentAtWithLock(path, refVersion); version != nil && version.content != nil {
				standing[path] = uint64(len(version.content))
			}
		}
		return standing
	}()
	paths := []string{}
	for path := range standing {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		if err := visit(path, standing[path]); err != nil {
			return err
		}
	}
	return nil
}

// SEARCH-M10-12's indexed_through for the world's ref, read over its content at the world's head (the file header).
func (self *SearchTestWorld) contentCoverage(ctx context.Context, repoId Id, contentRefId Id, rows []*SearchManifestCoverage) (uint64, error) {
	if repoId != self.repoId || contentRefId != self.refId {
		return 0, nil
	}
	view, err := self.view(ctx, Id{})
	if err != nil {
		return 0, err
	}
	coverage, err := indexCoverageOf(ctx, &indexCoverageArgs{view: view, root: view.writeRoot(), content: self.contentRef()})
	if err != nil {
		return 0, err
	}
	return coverage.indexedThrough, nil
}

// The world's coverage at its head as SEARCH-M10-12's reader gives it: indexed_through, and the pushes above it no
// rule counts.
func (self *SearchTestWorld) Coverage(ctx context.Context) (uint64, int, error) {
	view, err := self.view(ctx, Id{})
	if err != nil {
		return 0, 0, err
	}
	coverage, err := indexCoverageOf(ctx, &indexCoverageArgs{view: view, root: view.writeRoot(), content: self.contentRef()})
	if err != nil {
		return 0, 0, err
	}
	return coverage.indexedThrough, coverage.unindexedCount, nil
}

// --- builds, backfills, settings and the schedule ---

// What one build did.
type SearchTestBuild struct {
	// The ref version it committed at; 0 where it wrote nothing.
	Version uint64
	// Why it wrote nothing without failing: "off" or "locked"; "" otherwise.
	Skipped string
	// The pin it read the content at and the documents it wrote, as its last attempt built them.
	Pin        uint64
	EntryCount int
	// The plaintext SHA-256 of each file its last plan wrote but its own head and the lock, by path: what two builders
	// of one pin write alike, whether or not the plan committed.
	Content map[string][sha256.Size]byte
}

// One build of the world's index by builder, a device holding the text, on the world's clock: the build an admin's
// "on" asks for, a rebuild, or a migration's first build (first). ErrSearchTestExcluded in a repo that holds no index;
// ErrSearchTestLockLost where another builder took its lapsed lock.
func (self *SearchTestWorld) build(ctx context.Context, builder Id, first bool) (*SearchTestBuild, error) {
	indexBuilder, err := indexNewBuilder(&indexBuilderArgs{
		store: self.ref.store(builder), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format, tables: indexLinkedTables(), clock: self.clock, builder: builder,
		refKey: self.refKey, contents: []indexContentRef{self.contentRef()},
		padKey: func(ctx context.Context) (*indexPadKey, error) { return self.padKey, nil },
	})
	if err != nil {
		return nil, err
	}
	run := indexBuilder.Build
	if first {
		run = indexBuilder.FirstBuild
	}
	outcome, err := run(ctx)
	result := &SearchTestBuild{Content: map[string][sha256.Size]byte{}}
	if outcome != nil {
		if outcome.committed != nil {
			result.Version = outcome.committed.version
		}
		switch outcome.skipped {
		case indexBuildSkipOff:
			result.Skipped = "off"
		case indexBuildSkipLocked:
			result.Skipped = "locked"
		}
		for _, ref := range outcome.refs {
			result.Pin, result.EntryCount = ref.pin, result.EntryCount+ref.entryCount
		}
		if outcome.plan != nil {
			for _, file := range outcome.plan.contentFiles(builder, false) {
				result.Content[file.path] = sha256.Sum256(file.plaintext)
			}
		}
	}
	switch {
	case errors.Is(err, errIndexLockLost):
		return result, ErrSearchTestLockLost
	case errors.Is(err, errIndexBuildExcluded):
		return result, ErrSearchTestExcluded
	}
	return result, err
}

// See build: an admin's "on", or a rebuild.
func (self *SearchTestWorld) Build(ctx context.Context, builder Id) (*SearchTestBuild, error) {
	return self.build(ctx, builder, false)
}

// See build: the build that ends a migration to format 2, on a ref a format-1 client wrote.
func (self *SearchTestWorld) FirstBuild(ctx context.Context, builder Id) (*SearchTestBuild, error) {
	return self.build(ctx, builder, true)
}

// What one backfill did.
type SearchTestBackfill struct {
	// The ref version it committed at; 0 where it wrote nothing.
	Version uint64
	// "none" where no push was due, "off" with the index off; "" otherwise.
	Skipped string
	// The horizon it raised the ref to, and the documents it wrote.
	Horizon    uint64
	EntryCount int
}

// One backfill by writer, a device holding the text that may merge: every push still unindexed BackfillAge after its
// commit, indexed into writer's own head on the world's clock.
func (self *SearchTestWorld) Backfill(ctx context.Context, writer Id) (*SearchTestBackfill, error) {
	backfiller, err := indexNewBackfiller(&indexBackfillArgs{
		store: self.ref.store(writer), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format, tables: indexLinkedTables(), clock: self.clock, writer: writer,
		refKey: self.refKey, contents: []indexContentRef{self.contentRef()}, mayMerge: true,
		padKey: func(ctx context.Context) (*indexPadKey, error) { return self.padKey, nil },
	})
	if err != nil {
		return nil, err
	}
	outcome, err := backfiller.backfill(ctx)
	if err != nil {
		return nil, err
	}
	result := &SearchTestBackfill{}
	if outcome.committed != nil {
		result.Version = outcome.committed.version
	}
	switch outcome.skipped {
	case indexBackfillSkipNone:
		result.Skipped = "none"
	case indexBackfillSkipOff:
		result.Skipped = "off"
	}
	for _, ref := range outcome.refs {
		result.Horizon, result.EntryCount = max(result.Horizon, ref.h), result.EntryCount+ref.entryCount
	}
	return result, nil
}

// What a settings write did.
type SearchTestSettings struct {
	// The settings path's new version, 0 where it held these settings already or the off version waits.
	Version uint64
	// The files an off removed.
	RemovedCount int
	// The off version waits at the storage limit, its files gone.
	Waiting bool
}

// signer's settings version, as `ur evs index on|off|window` writes it (EvsIndexOn, EvsIndexOff, EvsIndexWindow): a
// version counts only where the world's admin signed it.
func (self *SearchTestWorld) SetIndex(ctx context.Context, signer Id, action string, windowDays uint32) (*SearchTestSettings, error) {
	change, err := indexSettingsChangeOf(action, windowDays)
	if err != nil {
		return nil, err
	}
	outcomes, err := indexApplySettings(ctx, &indexSettingsArgs{
		store: self.ref.store(signer), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format, attemptCount: DefaultIndexBuilderSettings().AttemptCount, clock: self.clock,
	}, change)
	if err != nil {
		return nil, err
	}
	result := &SearchTestSettings{}
	for _, outcome := range outcomes {
		result.Version = max(result.Version, outcome.version)
		result.RemovedCount += outcome.removedCount
		result.Waiting = result.Waiting || outcome.waiting
	}
	return result, nil
}

// Whether the world's index is off at its head.
func (self *SearchTestWorld) IndexOff(ctx context.Context) (bool, error) {
	view, err := self.view(ctx, Id{})
	if err != nil {
		return false, err
	}
	return view.writeRoot().off(), nil
}

// The paths the head lists under the world's index root.
func (self *SearchTestWorld) IndexPaths() []string {
	prefix := self.paths().root + "/"
	paths := []string{}
	for _, file := range self.Files() {
		if strings.HasPrefix(file.Path, prefix) {
			paths = append(paths, file.Path)
		}
	}
	return paths
}

// What a device is to the index's upkeep (§11.14's devices row).
type SearchTestUpkeepDevice int

const (
	// An indexer serving the repo for search.
	SearchTestUpkeepIndexer SearchTestUpkeepDevice = iota + 1
	// A desktop or the daemon.
	SearchTestUpkeepDesktop
	// A phone or the browser's wasm.
	SearchTestUpkeepPhone
)

// What one device's upkeep is made of.
type SearchTestUpkeepArgs struct {
	Device SearchTestUpkeepDevice
	// The device's sidecar_id, which its merges, roll-ups and backfills sign as.
	Self Id
	// Whether an indexer other than this device serves the repo for search; nil is none.
	IndexerServes func() bool
	// A phone's leave to merge and roll up, on Wi-Fi while charging; nil never.
	MayRun func() bool
	// The device backfills where the schedule lets it (SEARCH-M10-12's backfill given).
	Backfill bool
}

// One device's index upkeep on the world: SEARCH-M10-11's schedule over the world's ref alone.
type SearchTestUpkeep struct {
	schedule *indexSchedule
	ref      *indexScheduleRef
}

// A device's upkeep on the world's store and clock.
func (self *SearchTestWorld) NewUpkeep(args *SearchTestUpkeepArgs) (*SearchTestUpkeep, error) {
	if args == nil || args.Self == (Id{}) || args.Device < SearchTestUpkeepIndexer || SearchTestUpkeepPhone < args.Device {
		return nil, errors.New("search test upkeep: a device and its sidecar_id")
	}
	padKey := func(ctx context.Context) (*indexPadKey, error) { return self.padKey, nil }
	merger, err := indexNewMerger(&indexMergerArgs{
		store: self.ref.store(args.Self), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format, padKey: padKey, tables: indexLinkedTables(), clock: self.clock,
	})
	if err != nil {
		return nil, err
	}
	roller, err := indexNewRoller(&indexRollerArgs{
		store: self.ref.store(args.Self), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
		isAdmin: self.isAdmin, format: self.format, padKey: padKey, tables: indexLinkedTables(), clock: self.clock,
		runner: args.Self,
	})
	if err != nil {
		return nil, err
	}
	device := map[SearchTestUpkeepDevice]indexSearchDevice{
		SearchTestUpkeepIndexer: indexSearchDeviceIndexer, SearchTestUpkeepDesktop: indexSearchDeviceDesktop,
		SearchTestUpkeepPhone: indexSearchDevicePhone,
	}[args.Device]
	refArgs := &indexScheduleRefArgs{
		merger: merger, roller: roller, device: device, self: args.Self, indexerServes: args.IndexerServes, mayRun: args.MayRun,
	}
	if args.Backfill {
		backfiller, err := indexNewBackfiller(&indexBackfillArgs{
			store: self.ref.store(args.Self), repoId: self.repoId, refId: self.refId, repoKind: self.kind,
			isAdmin: self.isAdmin, format: self.format, tables: indexLinkedTables(), clock: self.clock, writer: args.Self,
			refKey: self.refKey, contents: []indexContentRef{self.contentRef()}, mayMerge: args.Device != SearchTestUpkeepPhone,
			padKey: padKey,
		})
		if err != nil {
			return nil, err
		}
		refArgs.backfill = backfiller
	}
	schedule := indexNewSchedule(nil, self.clock)
	return &SearchTestUpkeep{schedule: schedule, ref: schedule.add(refArgs)}, nil
}

// Records that the device committed an index push signed at at, as its writer tells the schedule.
func (self *SearchTestUpkeep) Committed(at time.Time) {
	self.ref.Committed(at.UnixMilli())
}

// What one tick did.
type SearchTestTick struct {
	// The ref versions its merges committed at.
	Merged []uint64
	// The ref version its roll-up committed at; 0 where none ran or it committed nothing.
	RolledUp uint64
	// Whether a roll-up ran at all, and why it committed nothing: "none", "off", "locked" or "rolled".
	RollUpRan     bool
	RollUpSkipped string
	Errs          []error
}

// One tick of the device's schedule: its due merges, its roll-up and its backfill, on the world's clock.
func (self *SearchTestUpkeep) Tick(ctx context.Context) *SearchTestTick {
	tick := self.schedule.tickRef(ctx, self.ref)
	result := &SearchTestTick{Errs: tick.errs}
	for _, merge := range tick.merges {
		if merge != nil && merge.committed != nil {
			result.Merged = append(result.Merged, merge.committed.version)
		}
	}
	if tick.rollup != nil {
		result.RollUpRan = true
		if tick.rollup.committed != nil {
			result.RolledUp = tick.rollup.committed.version
		}
		switch tick.rollup.skipped {
		case indexRollupSkipNone:
			result.RollUpSkipped = "none"
		case indexRollupSkipOff:
			result.RollUpSkipped = "off"
		case indexRollupSkipLocked:
			result.RollUpSkipped = "locked"
		case indexRollupSkipRolled:
			result.RollUpSkipped = "rolled"
		}
	}
	return result
}

// The documents of a content path the head's index files hold live, by chunk, at their versions: what a reader's
// merged view could find of it, before masks.
func (self *SearchTestWorld) LiveChunks(ctx context.Context, path string, chunkCount uint32) (map[uint32]uint64, error) {
	live, err := self.LiveDocKeys(ctx)
	if err != nil {
		return nil, err
	}
	chunks := map[uint32]uint64{}
	for chunk := uint32(0); chunk < chunkCount; chunk += 1 {
		key, err := indexDocKey(self.refKey, self.refId, []byte(path), chunk)
		if err != nil {
			return nil, err
		}
		if version, ok := live[key]; ok {
			chunks[chunk] = version
		}
	}
	return chunks, nil
}
