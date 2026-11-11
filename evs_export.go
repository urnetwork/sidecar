//go:build !ios_extension

// Export (§11.12's export row, R-EVS-10, FI-9): plain git rebuilt from evs, into a new bare repository, with git's
// own oids. Each ref's whole history is read from version 1 and verified as a replaying reader does (the walk from C_0
// to the head, every statement's signer and rules), then rebuilt push by push from each push's record, one part or
// many:
//
//   - a git-mode ref replays as the local tier's sync engine does (DESIGN-DETAILS 8.2.7, EVS1-M2-49): each version
//     held to EvsGitCheckUpdate, its sources replayed first to the versions it names, its blobs taken from its own
//     entries and its history blobs, its tags written, and each commit it carries rebuilt through EvsGitTreeBuilder
//     from its first parent's tree, its changes and its raw trees, the tree held to the one the commit names before
//     the commit's exact bytes are written; the ref's tip is the sealed update's new tip. Nothing is kept per commit:
//     memory is the builder's tree cache and one push's metadata;
//   - a file-mode ref gets one deterministic commit per version (evs_export_file.go), each push's changes replayed
//     onto the version before, every path's names opened from the rows its directories' deltas added, the root's for
//     the top level (question evs1-m2-24-root-directory-names, option 1).
//
// A git-mode version that fails its check stops its ref at the version before, never skipped in silence: export
// alarms version_rule, reports the version and why in EvsExportedRef.Refused, and goes on from the ref's next DELETE,
// which carries nothing to check (8.5). Provenance goes in refs/notes/ur (evs_export_notes.go). ur/index and ur/lfs are
// derived or stores, never exported, and .ur-index/ files are left out of every file-mode tree. A format-2 repo's
// collected or dropped versions (M10's) refuse.
//
// Refs are named by the names the caller holds: nil exports main. A source a push names is replayed for its objects
// whether or not the caller named it, and a cycle of sources refuses the version that closes it.
//
// On every leg but the forwarding role's; only a desktop host runs it. Safe for concurrent use with other calls; one
// export at a time per target.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The refs export leaves out (§11.11, §11.14).
var evsExportSkippedRefNames = [][]byte{[]byte("ur/index"), []byte("ur/lfs")}

// The top-level directory of the search index's files, which export leaves out of every tree.
const evsExportSkippedDirectory = ".ur-index"

// The parts one read asks for at once.
const evsExportPartReadCount = 64

// Rebuilds plain git from the repo's refs into args.Dir.
func (self *EvsRepo) Export(ctx context.Context, args *EvsExportArgs) (*EvsExportResult, error) {
	writer, err := newEvsGitObjectWriter(args.Dir)
	if err != nil {
		return nil, err
	}
	refNames := args.RefNames
	if refNames == nil {
		refNames = [][]byte{EvsMainRefName}
	}
	export := newEvsGitExport(self, writer)
	result := &EvsExportResult{}
	notes := []*evsExportNote{}
	for _, refName := range refNames {
		skipped := false
		for _, skip := range evsExportSkippedRefNames {
			skipped = skipped || bytes.Equal(refName, skip)
		}
		if skipped {
			continue
		}
		refId, err := self.resolveRefId(ctx, refName, nil)
		if err != nil {
			return nil, err
		}
		gitRef := EvsGitRefOfName(refName)
		exported, refNotes, err := self.exportRef(ctx, export, refId, refName, gitRef)
		if err != nil {
			return nil, err
		}
		if exported != nil {
			result.Refs = append(result.Refs, exported)
		}
		notes = append(notes, refNotes...)
	}
	if err := export.finishSources(ctx); err != nil {
		return nil, err
	}
	if err := writer.writeNotes(notes); err != nil {
		return nil, err
	}
	return result, nil
}

// One ref's whole history, verified from C_0 and pinned, then rebuilt into the export's repository under gitRef.
func (self *EvsRepo) exportRef(ctx context.Context, export *evsGitExport, refId Id, refName []byte, gitRef string) (*EvsExportedRef, []*evsExportNote, error) {
	head, err := self.pinnedHead(ctx, refId)
	if err != nil || head.Version == 0 {
		return nil, nil, err
	}
	switch protocol.EvsRefMode(head.Head.GetRefMode()) {
	case protocol.EvsRefMode_EVS_REF_GIT:
		return export.exportGitRef(ctx, head, refName, gitRef)
	case protocol.EvsRefMode_EVS_REF_FILE:
		verified, err := self.verifiedHistory(ctx, head)
		if err != nil || verified == nil {
			return nil, nil, err
		}
		return self.exportFileRef(ctx, export.writer, verified, gitRef)
	default:
		return nil, nil, fmt.Errorf("%w: ref mode %d", ErrEvsExport, head.Head.GetRefMode())
	}
}

// A ref's head, read fresh and held to this device's pin: its statements not read yet.
func (self *EvsRepo) pinnedHead(ctx context.Context, refId Id) (*EvsVerifiedHead, error) {
	reply, objects, err := self.client.postRead(ctx, self.repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), Fresh: true})
	if err != nil {
		return nil, err
	}
	objects.close()
	head := reply.head
	headChain, err := EvsChainFromBytes(head.GetChain())
	if err != nil {
		return nil, fmt.Errorf("%w: the head's chain", ErrEvsReplyInvalid)
	}
	if err := self.client.verifier.checkPin(self.repoId, refId, head.GetVersion(), headChain); err != nil {
		return nil, err
	}
	return &EvsVerifiedHead{RepoId: self.repoId, RefId: refId, Head: head, Version: head.GetVersion(), Chain: headChain}, nil
}

// A ref's whole history, verified from C_0 to the pinned head and pinned again: nil for a ref with no version. A
// file-mode export reads it whole; a git-mode one pages it (evsGitExportRef).
func (self *EvsRepo) verifiedHistory(ctx context.Context, head *EvsVerifiedHead) (*EvsVerifiedHead, error) {
	statements, err := self.client.readLog(ctx, self.repoId, head.RefId, 1, head.Version)
	if err != nil {
		return nil, err
	}
	start := EvsChainStart(self.repoId, head.RefId)
	walked, err := self.client.verifier.walk(self.repoId, head.RefId, 0, start, statements, head.Version)
	if err != nil {
		return nil, err
	}
	reached := start
	if 0 < len(walked) {
		reached = walked[len(walked)-1].Chain
	}
	if reached != head.Chain {
		return nil, fmt.Errorf("%w: the history does not chain to the head", ErrEvsChainBroken)
	}
	verified := &EvsVerifiedHead{RepoId: self.repoId, RefId: head.RefId, Head: head.Head, Version: head.Version, Chain: head.Chain, Statements: walked}
	if err := self.client.verifier.Pin(verified); err != nil {
		return nil, err
	}
	if len(walked) == 0 {
		return nil, nil
	}
	return verified, nil
}

// One export's git-mode replays: its repository, the tree builder over it, and each ref replayed so far, sources
// included. Not safe for concurrent use.
type evsGitExport struct {
	repo    *EvsRepo
	writer  *evsGitObjectWriter
	builder *EvsGitTreeBuilder
	keys    *evsReadKeys
	// a committer check for when the client gives none: the push's own client, with no lookup
	ownClient *SidecarCommitter
	refs      map[Id]*evsGitExportRef
	// the refs mid-replay, so a source that names one back is a cycle
	replaying map[Id]bool
}

// One git-mode ref as export has replayed it. Its history is read a page at a time from the log, each page walked
// from the chain the last one reached and dropped once applied, so memory holds one page, not the history; the chain
// is held to the pinned head once the last page is walked.
type evsGitExportRef struct {
	refId Id
	// its name bytes: the caller's, else its creating push's sealed copy; nil when neither gave one
	name []byte
	// the head read when the export first reached the ref, pinned; its statements nil
	head *EvsVerifiedHead
	// the last version passed, applied or stopped, and the chain there; the page of verified statements after it
	passed uint64
	chain  [sha256.Size]byte
	page   []*EvsVerifiedStatement
	// the chain was held to the head and pinned
	pinned bool
	// its tip, nil before its creation and after a DELETE
	tip    *EvsGitOid
	exists bool
	// a version that failed its check, 0 for none: nothing applies past it until a DELETE
	stoppedAt uint64
	refused   []*EvsExportRefusal
	notes     []*evsExportNote
	// each applied version that moved the tip, in order, and each span of versions a refusal stopped, from the
	// refused version to the DELETE that ended it (0 while it stands): what a source naming a version reads
	tips    []evsGitExportTip
	stopped [][2]uint64
}

// The tip a ref's version left, nil for none.
type evsGitExportTip struct {
	version uint64
	tip     *EvsGitOid
}

// The tip the ref had at version, and whether this export applied the ref there: false inside a stopped span or
// past what it has replayed.
func (self *evsGitExportRef) tipAt(version uint64) (*EvsGitOid, bool) {
	if self.passed < version {
		return nil, false
	}
	for _, span := range self.stopped {
		if span[0] <= version && (span[1] == 0 || version < span[1]) {
			return nil, false
		}
	}
	var tip *EvsGitOid
	for _, moved := range self.tips {
		if version < moved.version {
			break
		}
		tip = moved.tip
	}
	return tip, true
}

// The ref's next statement past what it passed, nil at its head: the next page read and walked when the last is
// spent.
func (self *evsGitExport) next(ctx context.Context, ref *evsGitExportRef) (*EvsVerifiedStatement, error) {
	if len(ref.page) == 0 {
		if ref.head.Version <= ref.passed {
			return nil, nil
		}
		through := min(ref.head.Version, ref.passed+uint64(max(1, self.repo.client.settings.HistoryVersionCount)))
		client := self.repo.client
		statements, err := client.readLog(ctx, self.repo.repoId, ref.refId, ref.passed+1, through)
		if err != nil {
			return nil, err
		}
		walked, err := client.verifier.walk(self.repo.repoId, ref.refId, ref.passed, ref.chain, statements, through)
		if err != nil {
			return nil, err
		}
		if len(walked) == 0 {
			return nil, fmt.Errorf("%w: the log ends short of the head", ErrEvsChainBroken)
		}
		ref.page = walked
	}
	return ref.page[0], nil
}

// Marks a statement passed.
func (self *evsGitExportRef) pass(statement *EvsVerifiedStatement) {
	self.passed, self.chain = statement.Version, statement.Chain
	self.page = self.page[1:]
}

// Walks what is left of the ref's history without applying it, holds the chain to the head and pins it: a source
// replayed part way is still read to its head, so no fork below a head goes unseen.
func (self *evsGitExport) finish(ctx context.Context, ref *evsGitExportRef) error {
	if ref.pinned {
		return nil
	}
	for {
		statement, err := self.next(ctx, ref)
		if err != nil {
			return err
		}
		if statement == nil {
			break
		}
		ref.pass(statement)
	}
	if ref.chain != ref.head.Chain {
		return fmt.Errorf("%w: the history does not chain to the head", ErrEvsChainBroken)
	}
	if err := self.repo.client.verifier.Pin(ref.head); err != nil {
		return err
	}
	ref.pinned = true
	return nil
}

// An export's replays into writer's repository, its tree cache bounded by the client's TreeCacheByteCount.
func newEvsGitExport(repo *EvsRepo, writer *evsGitObjectWriter) *evsGitExport {
	return &evsGitExport{
		repo:      repo,
		writer:    writer,
		builder:   NewEvsGitTreeBuilder(writer, writer, repo.client.settings.TreeCacheByteCount),
		keys:      newEvsReadKeys(repo),
		ownClient: NewSidecarCommitter(&SidecarCommitterArgs{NetworkId: repo.client.args.NetworkId}),
		refs:      map[Id]*evsGitExportRef{},
		replaying: map[Id]bool{},
	}
}

// The ref's export state, made on first use from its pinned head.
func (self *evsGitExport) ref(head *EvsVerifiedHead) *evsGitExportRef {
	ref := self.refs[head.RefId]
	if ref == nil {
		ref = &evsGitExportRef{refId: head.RefId, head: head, chain: EvsChainStart(self.repo.repoId, head.RefId)}
		self.refs[head.RefId] = ref
	}
	return ref
}

// A git-mode ref's whole history replayed, its tip set as gitRef.
func (self *evsGitExport) exportGitRef(ctx context.Context, head *EvsVerifiedHead, refName []byte, gitRef string) (*EvsExportedRef, []*evsExportNote, error) {
	ref := self.ref(head)
	if refName != nil {
		ref.name = refName
	}
	if err := self.replay(ctx, ref, ref.head.Version); err != nil {
		return nil, nil, err
	}
	if err := self.finish(ctx, ref); err != nil {
		return nil, nil, err
	}
	if ref.tip == nil && len(ref.refused) == 0 {
		return nil, ref.notes, nil
	}
	exported := &EvsExportedRef{GitRef: gitRef, Versions: ref.head.Version, Refused: ref.refused}
	if ref.tip != nil {
		if err := self.writer.setRef(gitRef, *ref.tip); err != nil {
			return nil, nil, err
		}
		exported.Tip = *ref.tip
	}
	return exported, ref.notes, nil
}

// Every ref the export reached for a source and did not export, read to its head and pinned.
func (self *evsGitExport) finishSources(ctx context.Context) error {
	for _, ref := range self.refs {
		if err := self.finish(ctx, ref); err != nil {
			return err
		}
	}
	return nil
}

// Applies ref's versions through upTo, those not passed yet.
func (self *evsGitExport) replay(ctx context.Context, ref *evsGitExportRef, upTo uint64) error {
	self.replaying[ref.refId] = true
	defer delete(self.replaying, ref.refId)
	for ref.passed < upTo {
		statement, err := self.next(ctx, ref)
		if err != nil {
			return err
		}
		if statement == nil {
			break
		}
		if err := self.apply(ctx, ref, statement); err != nil {
			return err
		}
		ref.pass(statement)
	}
	return nil
}

// A refused version: alarmed, reported, and the ref stopped at the version before it until a DELETE.
func (self *evsGitExport) refuse(ref *evsGitExportRef, statement *EvsVerifiedStatement, reason error) error {
	self.repo.client.alarm(self.repo.repoId, ref.refId, SidecarEvsAlarmVersionRule, "", nil)
	ref.stoppedAt = statement.Version
	ref.stopped = append(ref.stopped, [2]uint64{statement.Version, 0})
	ref.refused = append(ref.refused, &EvsExportRefusal{Version: statement.Version, Reason: reason.Error()})
	return nil
}

// Whether err is a version's own fault, which stops its ref, rather than export's, which ends the export.
func evsExportRefusesVersion(err error) bool {
	return errors.Is(err, ErrEvsGitUpdateRefused) || errors.Is(err, ErrEvsGitObjectInvalid) || errors.Is(err, ErrEvsSealInvalid) ||
		errors.Is(err, ErrEvsEntryRefused)
}

// One version of a git-mode ref: see the file header.
func (self *evsGitExport) apply(ctx context.Context, ref *evsGitExportRef, statement *EvsVerifiedStatement) error {
	push := statement.Statement.Push
	flags := push.GetFlags()
	if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		// the epoch state's alone: no object, and no tip moves
		return nil
	}
	if ref.stoppedAt != 0 && flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) == 0 {
		return nil
	}
	payload, err := self.repo.pushContent(ctx, ref.head, statement)
	if err != nil {
		return err
	}
	manifest, err := self.keys.manifest(ctx, push.GetGeneration())
	if err != nil {
		return err
	}
	metadata, err := EvsOpenMetadata(manifest, payload.SealedMetadata)
	if err != nil {
		self.repo.client.alarm(self.repo.repoId, ref.refId, SidecarEvsAlarmTamper, "", nil)
		return self.refuse(ref, statement, err)
	}
	// a creating push's section 15, opened as the head's copy of it is, and the ref id its sealed name gives
	creating := !ref.exists
	var sectionRefName []byte
	if creating && len(payload.RefName) != 0 {
		sectionRefName, err = EvsOpenRefName(manifest, ref.refId, payload.RefName)
		if err != nil {
			self.repo.client.alarm(self.repo.repoId, ref.refId, SidecarEvsAlarmTamper, "", nil)
			return self.refuse(ref, statement, err)
		}
	}
	refIdOf := func(refName []byte) (Id, error) {
		repoKey, err := self.keys.repoKey(ctx, push.GetGeneration())
		if err != nil {
			return Id{}, err
		}
		refKey, err := NewEvsRefKey(repoKey)
		if err != nil {
			return Id{}, err
		}
		return EvsRefId(refKey, refName)
	}
	checked, err := EvsGitCheckUpdate(ctx, &EvsGitUpdateArgs{
		RepoId: self.repo.repoId, RefId: ref.refId, RefName: ref.name, Statement: statement.Statement, Payload: payload,
		Metadata: metadata, PriorTip: ref.tip, Creating: creating, SectionRefName: sectionRefName, RefIdOf: refIdOf,
		HeadBase: ref.head.Head.GetBase(),
		ReplaySources: func(ctx context.Context, sources []*protocol.EvsOverlay) error {
			for _, source := range sources {
				if err := self.replaySource(ctx, source); err != nil {
					return err
				}
			}
			return nil
		},
		Held:      self.writer.has,
		Committer: self.committer,
		Import: func(ctx context.Context, signed []byte, push *protocol.EvsPush) (*protocol.EvsImport, error) {
			return self.repo.client.verifier.verifyImport(signed, self.repo.repoId, push)
		},
		Parents: self.parents,
	})
	if err != nil {
		if evsExportRefusesVersion(err) {
			return self.refuse(ref, statement, err)
		}
		return err
	}
	switch checked.Shape {
	case protocol.EvsGitShape_EVS_GIT_DELETE:
		if ref.stoppedAt != 0 {
			ref.stopped[len(ref.stopped)-1][1] = statement.Version
		}
		ref.tip, ref.exists, ref.stoppedAt = nil, false, 0
		ref.tips = append(ref.tips, evsGitExportTip{version: statement.Version})
		return nil
	case protocol.EvsGitShape_EVS_GIT_REKEY:
		return nil
	}
	if err := self.applyUpdate(ctx, ref, statement, payload, metadata, checked); err != nil {
		if evsExportRefusesVersion(err) {
			return self.refuse(ref, statement, err)
		}
		return err
	}
	ref.tip, ref.exists = checked.NewTip, true
	ref.tips = append(ref.tips, evsGitExportTip{version: statement.Version, tip: checked.NewTip})
	if creating && ref.name == nil {
		// the name its creating push sealed, which the check held to the ref's id
		ref.name = metadata.GetRefName()
	}
	ref.notes = append(ref.notes, &evsExportNote{commit: *checked.Peeled, statement: statement})
	return nil
}

// An UPDATE's objects, its sources replayed by the check: its blobs, its tags, then each commit's tree rebuilt and the
// commit written.
func (self *evsGitExport) applyUpdate(ctx context.Context, ref *evsGitExportRef, statement *EvsVerifiedStatement, payload *EvsCheckedPayload, metadata *protocol.EvsSealedMetadata, checked *EvsGitCheckedUpdate) error {
	git := metadata.GetGit()
	for _, change := range payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		if _, err := self.repo.exportBlob(ctx, self.writer, ref.head, self.keys, statement, change); err != nil {
			return err
		}
	}
	if err := self.historyBlobs(ctx, ref.head, statement, git); err != nil {
		return err
	}
	for i, tag := range checked.Tags {
		if oid, err := self.writer.write(evsGitTagKind, tag); err != nil || oid != checked.TagOids[i] {
			return errors.Join(err, fmt.Errorf("%w: a tag that is not its oid", ErrEvsGitUpdateRefused))
		}
	}
	for _, commit := range checked.Commits {
		if commit.Held {
			continue
		}
		var parentTree *EvsGitOid
		if 0 < len(commit.ParentOids) {
			kind, parentObject, err := self.writer.ReadGitObject(ctx, commit.ParentOids[0])
			if err != nil || kind != evsGitCommitKind {
				return errors.Join(err, fmt.Errorf("%w: a commit whose first parent is not held", ErrEvsGitUpdateRefused))
			}
			treeOid, _, err := EvsGitCommitGraph(parentObject)
			if err != nil {
				return err
			}
			parentTree = &treeOid
		}
		for _, change := range commit.Sealed.GetChanges() {
			if len(change.GetGitOid()) != 0 && change.GetMode() != EvsGitModeGitlink && !self.writer.has(EvsGitOid(change.GetGitOid())) {
				return fmt.Errorf("%w: a commit naming a blob neither held nor carried", ErrEvsGitUpdateRefused)
			}
		}
		treeOid, err := self.builder.Build(ctx, parentTree, commit.Sealed.GetChanges(), commit.Sealed.GetTrees())
		if err != nil {
			return err
		}
		if treeOid != commit.TreeOid {
			self.repo.client.alarm(self.repo.repoId, ref.refId, SidecarEvsAlarmTamper, "", nil)
			return fmt.Errorf("%w: a commit's tree does not rebuild from its changes", ErrEvsGitUpdateRefused)
		}
		if _, err := self.writer.write(evsGitCommitKind, commit.Sealed.GetObject()); err != nil {
			return err
		}
	}
	return nil
}

// A source a push names, replayed to the version it names, whose tip there must exist: a source with no such version,
// one whose ref this export stopped there, one with no tip there, and a cycle of sources each refuse the version that
// names it. A source at a version its ref has passed already, as a ref mid-replay named back, is held already.
func (self *evsGitExport) replaySource(ctx context.Context, source *protocol.EvsOverlay) error {
	refId, err := IdFromBytes(source.GetRefId())
	if err != nil {
		return fmt.Errorf("%w: a source that is no ref", ErrEvsGitUpdateRefused)
	}
	ref := self.refs[refId]
	if ref == nil {
		head, err := self.repo.pinnedHead(ctx, refId)
		if err != nil {
			return err
		}
		if head.Version == 0 {
			return fmt.Errorf("%w: a source with no version", ErrEvsGitUpdateRefused)
		}
		if protocol.EvsRefMode(head.Head.GetRefMode()) != protocol.EvsRefMode_EVS_REF_GIT {
			return fmt.Errorf("%w: a source that is no git-mode ref", ErrEvsGitUpdateRefused)
		}
		ref = self.ref(head)
	}
	if ref.head.Version < source.GetVersion() {
		return fmt.Errorf("%w: a source past its ref's head", ErrEvsGitUpdateRefused)
	}
	if ref.passed < source.GetVersion() {
		if self.replaying[refId] {
			return fmt.Errorf("%w: a cycle of sources", ErrEvsGitUpdateRefused)
		}
		if err := self.replay(ctx, ref, source.GetVersion()); err != nil {
			return err
		}
	}
	tip, applied := ref.tipAt(source.GetVersion())
	if !applied || tip == nil {
		return fmt.Errorf("%w: a source with no tip at its version", ErrEvsGitUpdateRefused)
	}
	return nil
}

// owner decision 81's rule for a new commit's committer: the client's check, else the push's own client alone.
func (self *evsGitExport) committer(ctx context.Context, committer *EvsGitIdent, push *protocol.EvsPush) error {
	identityKey, err := self.repo.client.verifier.signerIdentityKey(push)
	if err != nil {
		return err
	}
	clientId, err := IdFromBytes(push.GetClientId())
	if err != nil {
		return err
	}
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return err
	}
	claim := &SidecarCommitterClaim{
		CommitterEmail: string(committer.Email), PushClientId: clientId, SignerSidecarId: signerId,
		SignerIdentityPublicKey: identityKey,
	}
	if check := self.repo.client.args.Committer; check != nil {
		return check(ctx, claim)
	}
	return self.ownClient.Check(ctx, claim)
}

// A held commit's parents, read back from the repository.
func (self *evsGitExport) parents(ctx context.Context, oid EvsGitOid) ([]EvsGitOid, error) {
	kind, object, err := self.writer.ReadGitObject(ctx, oid)
	if err != nil {
		return nil, err
	}
	if kind != evsGitCommitKind {
		return nil, ErrEvsGitObjectMissing
	}
	_, parentOids, err := EvsGitCommitGraph(object)
	return parentOids, err
}

// A push's history blobs (DESIGN-DETAILS 8.2.3), in their order, each after the blob it is a diff of: the records of
// the blobs that begin in one history segment fetched in one read, as one range of each segment they touch, so a push's
// blobs cost about a read a segment and memory holds about a segment. A blob held already is neither fetched nor
// opened.
func (self *evsGitExport) historyBlobs(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement, git *protocol.EvsGitUpdate) error {
	blobs := git.GetBlobs()
	for start := 0; start < len(blobs); {
		segment := blobs[start].GetRecords()[0].GetSegment()
		end := start
		for end < len(blobs) && blobs[end].GetRecords()[0].GetSegment() == segment {
			end += 1
		}
		// each segment's span over the records the group's unheld blobs name
		spans := map[uint32][2]uint64{}
		order := []uint32{}
		for _, blob := range blobs[start:end] {
			if self.writer.has(EvsGitOid(blob.GetGitOid())) {
				continue
			}
			for _, record := range blob.GetRecords() {
				low, high := uint64(record.GetOffset()), uint64(record.GetOffset())+uint64(record.GetLength())
				span, ok := spans[record.GetSegment()]
				if !ok {
					order = append(order, record.GetSegment())
					span = [2]uint64{low, high}
				}
				spans[record.GetSegment()] = [2]uint64{min(span[0], low), max(span[1], high)}
			}
		}
		entry := &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE)}
		for _, index := range order {
			span := spans[index]
			if EvsReadMaxRangeByteCount < span[1]-span[0] {
				return fmt.Errorf("%w: history records spread over more of a segment than a read takes", ErrEvsGitUpdateRefused)
			}
			entry.Chain = append(entry.Chain, &protocol.EvsLocator{
				Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: git.GetSegmentIds()[index],
				Offset: uint32(span[0]), Length: uint32(span[1] - span[0]),
			})
		}
		if err := func() error {
			result := &evsReadResult{refId: head.RefId, head: head, keys: self.keys, objects: newEvsReadObjects(self.repo.client)}
			defer result.objects.close()
			if err := self.repo.fetchMissing(ctx, result, entry); err != nil {
				return err
			}
			for _, blob := range blobs[start:end] {
				if err := self.historyBlob(ctx, result, statement, git, blob); err != nil {
					return err
				}
			}
			return nil
		}(); err != nil {
			return err
		}
		start = end
	}
	return nil
}

// One history blob (DESIGN-DETAILS 8.2.3): its records, fetched into result, opened under its file_id, a checkpoint
// whole, chunks joined, or one diff applied to the base blob the readers hold, then its size and oid checked and the
// blob written. One held already is skipped.
func (self *evsGitExport) historyBlob(ctx context.Context, result *evsReadResult, statement *EvsVerifiedStatement, git *protocol.EvsGitUpdate, blob *protocol.EvsSealedBlob) error {
	oid := EvsGitOid(blob.GetGitOid())
	if self.writer.has(oid) {
		return nil
	}
	fileId, err := IdFromBytes(blob.GetFileId())
	if err != nil {
		return fmt.Errorf("%w: a history blob's file_id", ErrEvsGitUpdateRefused)
	}
	chain := []*protocol.EvsLocator{}
	for _, record := range blob.GetRecords() {
		chain = append(chain, &protocol.EvsLocator{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: git.GetSegmentIds()[record.GetSegment()],
			Offset: record.GetOffset(), Length: record.GetLength(),
		})
	}
	// the records as an entry's chain, which the reader's open takes as they are
	entry := &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), Chain: chain}
	repo := self.repo
	store, memoryLimit := repo.client.args.Store, repo.client.settings.DeltaBaseMemoryByteCount
	content := newEvsSpill(store, memoryLimit)
	defer content.close()
	push := statement.Statement.Push
	for index, locator := range chain {
		header, body, _, err := repo.openRecord(ctx, result, push, entry, fileId, locator, index == 0, nil)
		if err != nil {
			return err
		}
		// a record's oid field is 32 B, a SHA-1 left-aligned and zero-filled (EVS-FORMAT.md)
		if !bytes.Equal(header.Oid[:len(oid)], oid[:]) || header.OidKind != protocol.EvsOidKind_EVS_OID_SHA1 {
			return fmt.Errorf("%w: a history record of another blob", ErrEvsSealInvalid)
		}
		switch {
		case len(blob.GetBaseOid()) != 0 && header.Kind == protocol.EvsRecordKind_EVS_RECORD_DIFF && header.BaseRecordId == (Id{}):
			kind, baseObject, err := self.writer.ReadGitObject(ctx, EvsGitOid(blob.GetBaseOid()))
			if err != nil || kind != evsGitBlobKind {
				return errors.Join(err, fmt.Errorf("%w: a history diff whose base blob is not held", ErrEvsGitUpdateRefused))
			}
			if _, err := EvsGitDeltaApply(bytes.NewReader(baseObject), body, EvsFileMaxByteCount, content, DefaultEvsGitDeltaSettings()); err != nil {
				return err
			}
		case len(blob.GetBaseOid()) == 0 && header.Kind == protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT && len(chain) == 1,
			len(blob.GetBaseOid()) == 0 && header.Kind == protocol.EvsRecordKind_EVS_RECORD_CHUNK:
			if _, err := io.Copy(content, body); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: a history blob's records of another shape", ErrEvsSealInvalid)
		}
	}
	if uint64(content.Size()) != blob.GetSize() {
		return fmt.Errorf("%w: a history blob of another size", ErrEvsSealInvalid)
	}
	written, err := self.writer.writeFrom(evsGitBlobKind, content.reader(), content.Size())
	if err != nil {
		return err
	}
	if written != oid {
		return fmt.Errorf("%w: a history blob that is not its oid", ErrEvsSealInvalid)
	}
	return nil
}

// The push record of one verified statement, read by its push id and version, its statement equal to the one
// verified and its payload checked against it (§11.6's checks row): a one-part push's payload, or a sealed push's
// parts, read in rounds and checked whole as its stored seal is.
func (self *EvsRepo) pushContent(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsCheckedPayload, error) {
	push := statement.Statement.Push
	if push.GetPartCount() == 0 {
		return self.pushPayload(ctx, head, statement)
	}
	parts := make([][]byte, push.GetPartCount())
	for start := uint32(1); start <= push.GetPartCount(); start += evsExportPartReadCount {
		request := &protocol.EvsReadRequest{RefId: head.RefId.Bytes(), PinVersion: head.Version}
		for part := start; part <= min(push.GetPartCount(), start+evsExportPartReadCount-1); part += 1 {
			request.Pushes = append(request.Pushes, &protocol.EvsReadPush{PushId: push.GetPushId(), Version: statement.Version, Part: part})
		}
		if err := func() error {
			_, objects, err := self.client.postRead(ctx, self.repoId, request)
			if err != nil {
				return err
			}
			defer objects.close()
			for key, spill := range objects.objects {
				if key.kind != protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD || key.number == 0 || uint64(push.GetPartCount()) < key.number {
					continue
				}
				recordBytes, err := io.ReadAll(spill.reader())
				if err != nil {
					return err
				}
				record, err := ParseEvsBatchRecord(recordBytes)
				if err != nil || record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART {
					return fmt.Errorf("%w: a part record that is not one part's", ErrEvsEntryRefused)
				}
				statementBytes, partBytes, _, _, err := ParseEvsPartRecordBody(record.Body)
				if err != nil || !bytes.Equal(statementBytes, statement.Statement.Bytes) {
					return fmt.Errorf("%w: a part record of another statement", ErrEvsEntryRefused)
				}
				parts[key.number-1] = partBytes
			}
			return nil
		}(); err != nil {
			return nil, err
		}
	}
	for part, partBytes := range parts {
		if partBytes == nil {
			return nil, fmt.Errorf("%w: part %d evs did not serve", ErrEvsObjectMissing, part+1)
		}
	}
	checked, _, err := EvsCheckStoredSeal(statement.Statement, parts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsEntryRefused, err)
	}
	return checked, nil
}

// A one-part push's record, read by its push id and version, its statement equal to the one verified and its payload
// checked against it.
func (self *EvsRepo) pushPayload(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (*EvsCheckedPayload, error) {
	request := &protocol.EvsReadRequest{
		RefId:      head.RefId.Bytes(),
		PinVersion: head.Version,
		Pushes:     []*protocol.EvsReadPush{{PushId: statement.Statement.Push.GetPushId(), Version: statement.Version}},
	}
	_, objects, err := self.client.postRead(ctx, self.repoId, request)
	if err != nil {
		return nil, err
	}
	defer objects.close()
	var record []byte
	for key, spill := range objects.objects {
		if key.kind == protocol.EvsReadObjectKind_EVS_READ_OBJECT_BATCH_RECORD && key.number == 0 {
			record, err = io.ReadAll(spill.reader())
			if err != nil {
				return nil, err
			}
		}
	}
	if record == nil {
		return nil, fmt.Errorf("%w: a push record evs did not serve", ErrEvsObjectMissing)
	}
	// the batch record as its place holds it: its header, then the push's statement and payload
	batchRecord, err := ParseEvsBatchRecord(record)
	if err != nil || batchRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_PUSH {
		return nil, fmt.Errorf("%w: a push record that is not one push's", ErrEvsEntryRefused)
	}
	statementBytes, payload, err := ParseEvsPushRecordBody(batchRecord.Body)
	if err != nil || !bytes.Equal(statementBytes, statement.Statement.Bytes) {
		return nil, fmt.Errorf("%w: a push record of another statement", ErrEvsEntryRefused)
	}
	return EvsCheckPayload(statement.Statement, payload)
}

// One entry of a push reconstructed into a blob, its oid checked by reconstruction, and the blob's oid; nil for an
// entry that is no file's, and for a gitlink, whose oid names a commit and which has no content.
func (self *EvsRepo) exportBlob(ctx context.Context, writer *evsGitObjectWriter, head *EvsVerifiedHead, keys *evsReadKeys, statement *EvsVerifiedStatement, change *EvsCheckedChange) (*EvsGitOid, error) {
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
		return nil, fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
	}
	if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
		return nil, nil
	}
	result := &evsReadResult{refId: head.RefId, head: head, keys: keys, objects: newEvsReadObjects(self.client)}
	defer result.objects.close()
	verified := &EvsVerifiedPath{TokenPath: change.TokenPath, EntryBytes: change.EntryVersion, Entry: entry, Statement: statement.Statement, CommitVersion: statement.Version}
	spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
	defer spill.close()
	info, err := self.reconstruct(ctx, result, verified, spill)
	if err != nil {
		return nil, err
	}
	if info.Mode == EvsGitModeGitlink {
		return nil, nil
	}
	oid, err := writer.writeFrom(evsGitBlobKind, spill.reader(), spill.Size())
	if err != nil {
		return nil, err
	}
	return &oid, nil
}
