//go:build !ios_extension

// The in-ref writer on the real push builder (§11.14's in-ref, devices and limit rows; R-EVS-21, R-EVS-24, D-EVS-43,
// D-EVS-46, D-EVS-66, I-2, I-EVS-17, FS-74; DESIGN-DETAILS 1.2.3 and 1.7's note for SEARCH-M10-13; SEARCH-M10-13): on
// a file-mode ref the index rides the content push. IndexWriter.Prepare is the client's EvsWritePlanHook: it sees each
// write's plan once the content is planned, extracts every document the plan changes, plans this writer's head against
// the push's base (indexPlanHead, 1.2.3), and adds every file and removal that returns to the same push, each the
// index's reserved writer's write held to the version the plan read, naming the head's index_epoch, so one head CAS
// commits content and index. An in-ref push needs no pin and no life of its own: its content CAS is its fence.
//
// Documents (§11.14's dependency row): a put is extracted in one pass (SEARCH-M10-44's form), one document a chunk, each a full
// entry at the version the plan writes, replacing the version it read; a removal, a version turned binary and a chunk
// D6 skips are tombstones at the version, and a version with fewer chunks than the one it replaces writes tombstones
// for the chunk numbers from its count up to the replaced version's less one, the replaced count taken from the
// replaced version's text, which the writer reads. A writer that cannot read that text writes no index entry for the
// push, which then reads unindexed and is backfilled (§11.14's coverage row). The push's signed time is taken here and
// set on the plan, so its entries, its buckets and its statement name one time.
//
// Writes nothing, leaving content to go as it would: outside §19.11's format2 gate (EvsClient.Format2Admitted); on a
// git-mode ref or a creates-only one (a record stream, a deposit, the erasure ref), whose index is the companion's;
// in a config, mailcfg or secret repo; with the index off; for a CLOSURE, ERASE, CUT or DROP push, which their own
// builders index; for a plan that writes nothing the never row leaves in; where the erasure set does not read (fail
// closed); where the build's tables are not normalizer 1's; and where the writer holds no free slot or must merge
// first, which SEARCH-M10-10's runner does and not the push builder: such a push goes unindexed and is backfilled. A
// push whose entries pass DirectBytes merges them into the buckets' shards in the same push (indexMergeHeadPlan).
//
// Who indexes: every device indexes the pushes it makes, desktops, the daemon, indexers, phones and the page Worker
// alike, since a push's entries ride it; who may merge is mayMerge's. Index files take versioning 2 through
// EvsWriteOptions.Reserved, staged under 16 KiB; at the storage limit they ride content pushes and stop with them.
// The tainted bit rides the push's provenance as the plan has it; outside's comes from mail or an EvsImport (QD-042),
// whose writers mark the writes they make (EvsPathWrite.Outside), and a document takes its write's mark.
//
// Paths are this device's plaintext and go into no log or error (I-13). Safe for concurrent use: each Prepare is one
// plan's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// What an in-ref writer writes with.
type indexWriterArgs struct {
	client *EvsClient
	// The store a ref's own index reads through: the EvsRepo adapter, one a ref.
	store func(repo *EvsRepo, refName []byte) indexRefStore
	// Whether a settings version's signer was a repo admin when it signed (indexAclAdmins). Required: a writer that
	// cannot judge the settings writes nothing, so an index an admin turned off is never written to.
	isAdmin func(repoId Id) func(file *indexFileVersion) bool
	// Whether this device may merge now: desktops, the daemon and indexers; phones on Wi-Fi while charging (§11.14's
	// devices row). Nil merges never.
	mayMerge func() bool
	// The team directory's copy of a card or repo file at the version a write replaces (DirectoryClient.IndexReplaced):
	// its d/ and r/ files are versionless, so evs holds a replaced version about a minute. False, and nil, read the
	// version from evs, and a version neither gives leaves the push unindexed.
	directoryReplaced func(repoId Id, path string, version uint64) ([]byte, bool)
	settings          *IndexFormatSettings
	clock             Clock
	log               Logger
}

// The in-ref writer of one client's pushes. Construct with newIndexWriter; Install sets Prepare as the client's
// EvsWritePlanHook.
type IndexWriter struct {
	args *indexWriterArgs
}

// A writer over args.
func newIndexWriter(args *indexWriterArgs) (*IndexWriter, error) {
	if args == nil || args.client == nil || args.store == nil || args.isAdmin == nil || args.settings == nil {
		return nil, fmt.Errorf("%w: an index writer needs its client, store, admins and settings", ErrEvsWriteInvalid)
	}
	copied := *args
	copied.clock = clockOrReal(args.clock)
	copied.log = loggerOrDefault(args.log)
	return &IndexWriter{args: &copied}, nil
}

// Sets Prepare as the client's write plan hook; the function returned removes it.
func (self *IndexWriter) Install() func() {
	self.args.client.SetWritePlanHook(self.Prepare)
	return func() { self.args.client.SetWritePlanHook(nil) }
}

// One content path of a plan the index may hold, and the write that made it.
type indexWriterChange struct {
	planned *EvsPlannedPath
	write   *EvsPathWrite
}

// Adds this writer's index files and removals to a write's plan: see the file header. An error fails the write; a
// push the index cannot take goes unindexed, with no error.
func (self *IndexWriter) Prepare(ctx context.Context, plan *EvsWritePlan) error {
	client := self.args.client
	if !client.Format2Admitted() || plan.RefMode != protocol.EvsRefMode_EVS_REF_FILE || plan.Flags != 0 || plan.argsFlags != 0 {
		return nil
	}
	if evsEpochExempt(plan.RefKind) || (plan.RefKind == protocol.EvsRefKind_EVS_REF_OWNED && EvsRepoKindRecordClass(plan.repoKind)) {
		return nil
	}
	switch plan.repoKind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_SECRET,
		protocol.RepoKind_REPO_KIND_UNSPECIFIED:
		return nil
	}
	groupInbox := plan.groupInbox
	changes := []*indexWriterChange{}
	for _, planned := range plan.Paths {
		write := plan.writeOf(planned.Path)
		// the git-lfs store's objects on ur/lfs are no documents (§11.11's store row)
		if write == nil || evsIsIndexWrite(write) || evsIsLfsWrite(write) || planned.Kind != protocol.EvsEntryKind_EVS_ENTRY_FILE {
			continue
		}
		if indexExcluded(indexPlace{repoKind: plan.repoKind, groupInbox: groupInbox, path: planned.Path}) {
			continue
		}
		if plan.repoKind == protocol.RepoKind_REPO_KIND_DIRECTORY && !directoryIndexPath(planned.Path) {
			// a notice, or anything else of the team directory that is no card and no repo file, is no document
			continue
		}
		changes = append(changes, &indexWriterChange{planned: planned, write: write})
	}
	if len(changes) == 0 {
		return nil
	}
	tables := indexLinkedTables()
	normalizer, err := indexNewNormalizer(tables)
	if errors.Is(err, errIndexOtherNormalizer) {
		// a build that cannot write normalizer 1 writes no index (§11.14's tables row)
		return nil
	}
	if err != nil {
		return err
	}
	repoKey, err := client.args.Gkm.EnsureWritable(ctx, plan.RepoId)
	if err != nil {
		return err
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return err
	}
	repo := client.Repo(plan.RepoId)
	documents := &indexWriterDocuments{
		writer: self, repo: repo, plan: plan, refKey: refKey, normalizer: normalizer, groupInbox: groupInbox,
	}
	for _, change := range changes {
		enter := documents.enter
		if plan.repoKind == protocol.RepoKind_REPO_KIND_DIRECTORY {
			// the team directory's documents are its class's: a card's or a repo file's announcements (§16.11)
			enter = documents.enterDirectory
		}
		complete, err := enter(ctx, change)
		if err != nil {
			return err
		}
		if !complete {
			// a replaced version this device cannot read: no entry of the push, which a backfill covers
			return nil
		}
	}
	view, err := indexLoadView(ctx, &indexViewArgs{
		store: self.args.store(repo, plan.refName), repoId: plan.RepoId, refId: plan.RefId, repoKind: plan.repoKind,
		refVersion: plan.BaseVersion, isAdmin: self.args.isAdmin(plan.RepoId), settings: self.args.settings,
	})
	if err != nil {
		return err
	}
	signedTimeMs := self.args.clock.Now().UnixMilli()
	headPlan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: client.args.Identity().SidecarId, signedTimeMs: signedTimeMs,
		tables: tables, pending: documents.pending, mayMerge: self.args.mayMerge != nil && self.args.mayMerge(),
	})
	switch {
	case errors.Is(err, errIndexErasureSetUnreadable), errors.Is(err, errIndexNoFreeSlot):
		return nil
	case err != nil:
		return err
	case headPlan.mergeFirst:
		// the writer must merge before it can write: SEARCH-M10-10's runner, not the push builder's; unindexed,
		// backfilled
		self.args.log.Infof("[index]a writer holding every slot left its push unindexed, to be backfilled")
		return nil
	}
	if headPlan.pastRing {
		self.args.log.Warningf("[index]a writer took a slot past its ring, unable to merge")
	}
	files, removals := headPlan.files(), headPlan.removals()
	if headPlan.mergeInPush {
		// the push's entries pass DirectBytes: it merges them into the buckets' shards itself and commits the
		// shards, the manifest and its head together (1.2.3)
		padKey, err := indexNewPadKey(repoKey)
		if err != nil {
			return err
		}
		files, removals, err = indexMergeHeadPlan(ctx, view, view.writeRoot(), headPlan, padKey, tables)
		if errors.Is(err, errIndexCollected) {
			return errEvsIndexMoved
		}
		if err != nil {
			return err
		}
	}
	// the push names the view's epoch and carries nothing the erasure set lists (the epoch guard)
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		return nil
	}
	if err := guard.checkFiles(files, false); err != nil {
		return err
	}
	writes := []*EvsPathWrite{}
	for _, file := range files {
		replaces := file.replaces
		writes = append(writes, &EvsPathWrite{
			Path: file.path, Content: bytes.NewReader(file.plaintext), IfVersion: &replaces,
			Options: &EvsWriteOptions{Reserved: EvsReservedIndex},
		})
	}
	for _, removal := range removals {
		version := removal.version
		writes = append(writes, &EvsPathWrite{Path: removal.path, Remove: true, IfVersion: &version, Options: &EvsWriteOptions{Reserved: EvsReservedIndex}})
	}
	if len(writes) == 0 {
		return nil
	}
	plan.addIndexWrites(writes...)
	plan.IndexEpoch = guard.epoch()
	plan.SignedTimeMs = signedTimeMs
	return nil
}

// The documents one plan's changes give.
type indexWriterDocuments struct {
	writer     *IndexWriter
	repo       *EvsRepo
	plan       *EvsWritePlan
	refKey     []byte
	normalizer *indexNormalizer
	groupInbox bool
	pending    []*indexPendingDocument
}

// What one extraction gave: the documents' chunks, the skipped ones, and whether the text was a text.
type indexWriterExtraction struct {
	full    []*indexStreamDocument
	skipped []uint32
	count   uint32
	text    bool
}

// Enters one change's documents; false where the replaced version's text is needed and cannot be
// read, so the push writes no entry.
func (self *indexWriterDocuments) enter(ctx context.Context, change *indexWriterChange) (bool, error) {
	planned := change.planned
	name := []byte(planned.Path)
	keyOf := func(chunk uint32) ([indexIdByteCount]byte, error) {
		return indexDocKey(self.refKey, self.plan.RefId, name, chunk)
	}
	tombstones := func(from uint32, to uint32, version uint64) error {
		for chunk := from; chunk < to; chunk += 1 {
			key, err := keyOf(chunk)
			if err != nil {
				return err
			}
			self.pending = append(self.pending, &indexPendingDocument{kind: indexEntryTombstone, key: key, version: version})
		}
		return nil
	}
	replacedCount := func() (uint32, bool, error) {
		if planned.BaseEntryVersion == 0 {
			return 0, true, nil
		}
		previous, err := self.readReplaced(ctx, planned)
		if err != nil {
			self.writer.args.log.Infof("[index]a replaced version did not read: the push goes unindexed")
			return 0, false, nil
		}
		defer previous.close()
		extraction, err := self.extract(planned.Path, planned.BaseEntryVersion, previous, false)
		if err != nil {
			return 0, false, err
		}
		return extraction.count, true, nil
	}
	if planned.Remove {
		count, ok, err := replacedCount()
		if err != nil || !ok {
			return ok, err
		}
		// a removal's version is the one past what it removes
		return true, tombstones(0, count, planned.BaseEntryVersion+1)
	}
	extraction, err := self.extract(planned.Path, planned.Version, change.write.Content, change.write.Outside)
	if err != nil {
		return false, err
	}
	count, ok, err := replacedCount()
	if err != nil || !ok {
		return ok, err
	}
	if !extraction.text {
		// a version turned binary: tombstones for what the replaced text held
		return true, tombstones(0, count, planned.Version)
	}
	for _, document := range extraction.full {
		key, err := keyOf(document.chunk)
		if err != nil {
			return false, err
		}
		self.pending = append(self.pending, &indexPendingDocument{
			kind: indexEntryFull, key: key, version: planned.Version, keys: document.keys, row: document.row,
		})
	}
	for _, chunk := range extraction.skipped {
		if chunk < count {
			// a chunk D6 skips where the replaced version held one: a tombstone
			if err := tombstones(chunk, chunk+1, planned.Version); err != nil {
				return false, err
			}
		}
	}
	// dropped chunks: from this version's count up to the replaced version's
	return true, tombstones(extraction.count, count, planned.Version)
}

// One pass over a version's content: its documents as key sets and rows, by the mail extractor for a mailbox's m/ and
// the file extractor for the rest. outside is the write's mark, which each document's row carries.
func (self *indexWriterDocuments) extract(path string, version uint64, content EvsGitDeltaSource, outside bool) (*indexWriterExtraction, error) {
	settings := self.writer.args.settings
	extraction := &indexWriterExtraction{text: true}
	kind := indexExtractorKind(indexPlace{repoKind: self.plan.repoKind, groupInbox: self.groupInbox, path: path})
	streamArgs := &indexStreamArgs{
		template:   &IndexDocument{Kind: kind, Name: []byte(path), Version: version, Tainted: self.plan.Tainted, Outside: outside},
		byteCount:  uint64(content.Size()),
		normalizer: self.normalizer,
		refId:      self.plan.RefId,
		settings:   settings,
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
		stream := indexExtractMailStream(streamArgs)
		block := make([]byte, settings.ExtractReadByteCount)
		size := content.Size()
		for offset := int64(0); offset < size; {
			byteCount, err := content.ReadAt(block[:min(int64(len(block)), size-offset)], offset)
			if 0 < byteCount {
				if _, err := stream.Write(block[:byteCount]); err != nil {
					return nil, err
				}
				offset += int64(byteCount)
			}
			if err != nil && !(errors.Is(err, io.EOF) && offset == size) {
				return nil, err
			}
		}
		if err := stream.Close(); err != nil {
			return nil, err
		}
		return extraction, nil
	}
	text, err := indexExtractFileStream(streamArgs, content)
	if err != nil {
		return nil, err
	}
	extraction.text = text
	if !text {
		extraction.count = 0
	}
	return extraction, nil
}

// The version a change replaces or removes, read in full into a spill the caller closes: evs's reader verifies it.
func (self *indexWriterDocuments) readReplaced(ctx context.Context, planned *EvsPlannedPath) (*evsSpill, error) {
	client := self.writer.args.client
	spill := newEvsSpill(client.args.Store, client.settings.DeltaBaseMemoryByteCount)
	refId := self.plan.RefId
	if _, err := self.repo.ReadVersion(ctx, &EvsReadArgs{RefId: &refId, Path: planned.Path, Version: planned.BaseEntryVersion}, spill); err != nil {
		spill.close()
		return nil, err
	}
	return spill, nil
}
