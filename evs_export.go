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
// which carries nothing to check (8.5). Under a general repo's prefix write rules the check's prefix line runs as the
// sync engine runs it, through EvsGitCheckUpdate with the same arguments and EvsGitCheckPrefixTrees once the
// version's objects stand (DESIGN-DETAILS 8.2.7, 16.2.6): a breach stops the ref, alarmed prefix_rule and reported with
// that reason; a set export cannot read, pending or a later release's, ends the export with EVS_PREFIX_RULE, since
// export cannot wait. Export keeps no tainted token paths, so a re-creating push's are not judged here. Provenance goes in refs/notes/ur (evs_export_notes.go). ur/index and ur/lfs are
// derived or stores, never exported, and .ur-index/ files are left out of every file-mode tree. A format-2 repo's
// collected or dropped versions (M10's) refuse.
//
// A file-mode version whose key a committed ERASE destroyed exports as its stub and the export goes on (§11.12's
// retention row; evs_export_file.go, evs_export_format2.go). A git-mode version's blob so erased exports as that stub
// too, and the trees, commits and tags holding it, and every commit of the ref after them, are rewritten under new
// oids, each rewritten commit's note naming its original (QD-1156, question
// erased-version-readers-git-mode-erased-blob, option 1; evs_export_erased.go): the oids D-EVS-22 keeps hold up to the
// first erased commit. The local tier's sync, which shares applyUpdate, still meets such a blob as ErrEvsErased.
//
// Refs are named by the names the caller holds: nil exports main. A source a push names is replayed for its objects
// whether or not the caller named it, and a cycle of sources refuses the version that closes it.
//
// The bundled git's store asks the replayer for what export never does (GIT-M13-02, evsGitReplayOptions): resuming a
// ref from the state its worktree kept (.git/ur/refs: the version passed, its chain, tip, last tip, kind, stopped spans
// and each tip move), so a fetch replays only from its last pin; deferring a blob, its locator (the version that carries
// it, the chains around that version, whether it is an entry or a history record) recorded in the promisor table in
// place of its bytes, so trees and commits are built from the changes' modes and oids while content waits; and seeing
// each version's push's provenance before any of its objects is written, so the run is tainted first (§13.6). Export
// and the local tier set none of them, so their output does not change by a byte.
//
// On every leg but the forwarding role's; only a desktop host runs it. Safe for concurrent use with other calls; one
// export at a time per target.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// the originals a rewrite over an erased blob kept beside the repository go with the export, whatever its end
	defer export.store.close()
	defer export.release()
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

// One ref's whole history, verified from C_0 and pinned, then rebuilt into the export's repository under gitRef. The
// read of the ref stays in flight until its head is pinned: at the export's end for a git-mode ref, whose sources the
// export pins last (evsGitExport.release), and before a file-mode ref's tree is rebuilt, a stale read of which is read
// again, fresh, at most EvsSettings.ReadStaleRetryCount times.
func (self *EvsRepo) exportRef(ctx context.Context, export *evsGitExport, refId Id, refName []byte, gitRef string) (*EvsExportedRef, []*evsExportNote, error) {
	for staleCount := 0; ; staleCount += 1 {
		done := self.client.pins.beginRead(self.repoId, refId)
		head, err := self.pinnedHead(ctx, refId)
		if err != nil || head.Version == 0 {
			done()
			return nil, nil, err
		}
		switch protocol.EvsRefMode(head.Head.GetRefMode()) {
		case protocol.EvsRefMode_EVS_REF_GIT:
			export.reading(done)
			return export.exportGitRef(ctx, head, refName, gitRef)
		case protocol.EvsRefMode_EVS_REF_FILE:
			verified, err := self.verifiedHistory(ctx, head)
			done()
			if errors.Is(err, ErrEvsReadStale) && staleCount < self.client.settings.ReadStaleRetryCount {
				continue
			}
			if err != nil || verified == nil {
				return nil, nil, err
			}
			return self.exportFileRef(ctx, export.writer, verified, gitRef)
		default:
			done()
			return nil, nil, fmt.Errorf("%w: ref mode %d", ErrEvsExport, head.Head.GetRefMode())
		}
	}
}

// A ref's head, read fresh and held to the pin its read asked at (EvsPinStore.ask, evs_pin_walk.go): its statements
// not read yet, so the walk that reads them, from C_0 or from its reader's own state, gives Pin what it walked
// (verifiedHistory, evsWalkTrail), and Pin judges the head against the pin as it then stands, which another call of
// the client may have raised past it meanwhile. A head below the pin asked at is taken only under the ref's Signed
// EvsReseed, as a read takes it (evs_read.go's acceptReseedBelowPin), and is otherwise a fork, alarmed. A caller that
// walks before it pins notes its read in flight first (EvsPinStore.beginRead), so a raise meanwhile keeps the chains
// that place this head.
func (self *EvsRepo) pinnedHead(ctx context.Context, refId Id) (*EvsVerifiedHead, error) {
	return self.pinnedHeadFromPin(ctx, refId, true)
}

// pinnedHead, taking a head below the pin under the ref's EvsReseed at most once (reseed).
func (self *EvsRepo) pinnedHeadFromPin(ctx context.Context, refId Id, reseed bool) (*EvsVerifiedHead, error) {
	ask, err := self.client.pins.ask(self.repoId, refId)
	if err != nil {
		return nil, err
	}
	reply, objects, err := self.client.postRead(ctx, self.repoId, &protocol.EvsReadRequest{RefId: refId.Bytes(), Fresh: true})
	if err != nil {
		return nil, err
	}
	objects.close()
	head := reply.head
	if reseed && ask.pin != nil && head.GetVersion() < ask.pin.Version {
		// this read named no pin, so the statement comes with a second one that does
		again, err := self.acceptReseedBelowPin(ctx, refId, ask.pin, reply, 0)
		if err != nil {
			return nil, err
		}
		if again {
			return self.pinnedHeadFromPin(ctx, refId, false)
		}
	}
	headChain, err := EvsChainFromBytes(head.GetChain())
	if err != nil {
		return nil, fmt.Errorf("%w: the head's chain", ErrEvsReplyInvalid)
	}
	if err := self.client.verifier.checkAsked(self.repoId, refId, ask, head.GetVersion(), headChain); err != nil {
		return nil, err
	}
	return &EvsVerifiedHead{
		RepoId: self.repoId, RefId: refId, Head: head, Version: head.GetVersion(), Chain: headChain,
		ask: ask, fromChain: EvsChainStart(self.repoId, refId),
	}, nil
}

// A ref's whole history, verified from C_0 to the pinned head and pinned with its walk: nil for a ref with no version.
// A head its read pinned already is not judged again, its whole history reaching its chain. A file-mode export reads
// it whole; a git-mode one pages it (evsGitExportRef).
func (self *EvsRepo) verifiedHistory(ctx context.Context, head *EvsVerifiedHead) (*EvsVerifiedHead, error) {
	walked, err := self.client.verifier.walkToHead(ctx, head)
	if err != nil {
		return nil, err
	}
	verified := &EvsVerifiedHead{
		RepoId: self.repoId, RefId: head.RefId, Head: head.Head, Version: head.Version, Chain: head.Chain, Statements: walked,
		ask: head.ask, fromChain: EvsChainStart(self.repoId, head.RefId), pinned: head.pinned,
	}
	if !verified.pinned {
		if err := self.client.verifier.Pin(verified); err != nil {
			return nil, err
		}
	}
	if len(walked) == 0 {
		return nil, nil
	}
	return verified, nil
}

// Where a git-mode replay holds and writes its objects: export's loose objects (evsGitObjectWriter), or a mount's bare
// repository through cat-file and packs (the local tier's sync engine, evs_local_apply.go).
type evsGitReplayStore interface {
	EvsGitObjectSource
	EvsGitObjectSink
}

// One file a version's entry rebuilt: its sealed mode and blob oid, which the local tier holds to the tree (G4), and,
// where its fields were opened without a read (GIT-M13-02's deferral), its size.
type evsGitWrittenFile struct {
	mode uint32
	oid  EvsGitOid
	size uint64
}

// One export's git-mode replays: its repository, the tree builder over it, and each ref replayed so far, sources
// included. The local tier's sync engine runs applyUpdate on one over its own store, with no writer. Not safe for
// concurrent use.
type evsGitExport struct {
	repo *EvsRepo
	// export's repository, for its refs and notes; nil in the local tier
	writer *evsGitObjectWriter
	// export's store over it, objects too, which stubs an erased blob and rewrites what holds it (evs_export_erased.go,
	// QD-1156); nil in the local tier, whose replay meets an erased blob as ErrEvsErased
	store *evsGitExportStore
	// where objects are read and written
	objects evsGitReplayStore
	builder *EvsGitTreeBuilder
	keys    *evsReadKeys
	// a committer check for when the client gives none: the push's own client, with no lookup
	ownClient *SidecarCommitter
	refs      map[Id]*evsGitExportRef
	// the refs mid-replay, so a source that names one back is a cycle
	replaying map[Id]bool
	// each ref's read in flight from its head's ask to its pin, ended with the export (EvsPinStore.beginRead)
	dones []func()
	// what the bundled git's store asks beyond export (GIT-M13-02); nil for export and the local tier
	options *evsGitReplayOptions
	// the ref and the chains around the version applyUpdate writes, for a deferred blob's locator; nil between them
	applying *evsGitApplying
}

// What a replay's store may ask beyond export's (GIT-M13-02; see the file header): export and the local tier ask
// none, so neither's output changes.
type evsGitReplayOptions struct {
	// The states a store kept of the refs it replayed before, by ref id: a ref found here resumes from its version
	// passed, its walk from its chain.
	resume map[Id]*EvsGitReplayState
	// Records a blob's locator in place of reading it; nil reads every blob, as export does.
	deferBlob func(locator *EvsGitBlobLocator) error
	// Sees each version's push, its sealed metadata opened, before any of its objects is written; an error ends the
	// replay there.
	provenance func(ctx context.Context, refId Id, statement *EvsVerifiedStatement, metadata *protocol.EvsSealedMetadata) error
}

// A version applyUpdate writes: its ref, its number and the chains before and at it.
type evsGitApplying struct {
	refId       Id
	version     uint64
	chainBefore [sha256.Size]byte
	chain       [sha256.Size]byte
}

// A git-mode ref's replay as a store keeps it between replays, so the next resumes where it stopped (GIT-M13-02's
// .git/ur/refs): the version passed and its chain, the tip, whether the ref stands, the tip at its last DELETE, the kind
// its pushes carry, the version a refusal stopped it at and every stopped span, and each version that moved its tip, which
// a source naming one of its versions is read against.
type EvsGitReplayState struct {
	RefId     Id
	Name      []byte
	Passed    uint64
	Chain     [sha256.Size]byte
	Tip       *EvsGitOid
	Exists    bool
	LastTip   *EvsGitOid
	Kind      protocol.EvsRefKind
	StoppedAt uint64
	Stopped   [][2]uint64
	Tips      []EvsGitReplayTip
}

// A version that moved a ref's tip, and the tip it left, nil for none.
type EvsGitReplayTip struct {
	Version uint64
	Tip     *EvsGitOid
}

// Where a deferred blob's bytes are: the ref and version whose push carries it, the chains before and at that
// version, which a lazy fetch walks the statement from and holds it to, and whether it is one of the push's history
// records or one of its entries (GIT-M13-02's promisor table).
type EvsGitBlobLocator struct {
	Oid         EvsGitOid
	Size        uint64
	RefId       Id
	Version     uint64
	ChainBefore [sha256.Size]byte
	Chain       [sha256.Size]byte
	History     bool
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
	// the last version applied and the chain there, which finish's walk to the head passes without applying: where a
	// kept state resumes (GIT-M13-02), so a source replayed part way is applied from there, never skipped
	applied      uint64
	appliedChain [sha256.Size]byte
	// the chain was held to the head and pinned; the walk's chains from the pin its head's read asked at, which the
	// pin's raise judges
	pinned bool
	trail  *evsWalkTrail
	// its tip, nil before its creation and after a DELETE; the tip it had at its last DELETE, nil for none; and the
	// kind its pushes carry, which with its name says whether it is a shared branch (DESIGN-DETAILS 8.2.7)
	tip     *EvsGitOid
	exists  bool
	lastTip *EvsGitOid
	kind    protocol.EvsRefKind
	// a version that failed its check, 0 for none: nothing applies past it until a DELETE
	stoppedAt uint64
	refused   []*EvsExportRefusal
	notes     []*evsExportNote
	// the commits its pushes carried that export rewrote over an erased blob (evs_export_erased.go)
	rewritten uint64
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
		walked, err := client.verifier.walk(ctx, self.repo.repoId, ref.refId, ref.passed, ref.chain, statements, through)
		if err != nil {
			return nil, err
		}
		if len(walked) == 0 {
			return nil, fmt.Errorf("%w: the log ends short of the head", ErrEvsChainBroken)
		}
		ref.page = walked
		ref.trail.add(walked)
	}
	return ref.page[0], nil
}

// Marks a statement passed.
func (self *evsGitExportRef) pass(statement *EvsVerifiedStatement) {
	self.passed, self.chain = statement.Version, statement.Chain
	self.page = self.page[1:]
}

// Walks what is left of the ref's history without applying it, holds the chain to the head and pins it with the walk's
// chains from the pin its read asked at: a source replayed part way is still read to its head, so no fork below a head
// goes unseen, and a head another call of the client raised the pin past meanwhile stands where the store places it,
// else answers ErrEvsReadStale.
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
	if err := self.repo.client.verifier.Pin(ref.trail.head(ref.head)); err != nil {
		return err
	}
	ref.pinned = true
	return nil
}

// Keeps a ref's read in flight until the export ends.
func (self *evsGitExport) reading(done func()) {
	self.dones = append(self.dones, done)
}

// Ends every ref's read the export kept in flight.
func (self *evsGitExport) release() {
	for _, done := range self.dones {
		done()
	}
	self.dones = nil
}

// An export's replays into writer's repository through its store (evs_export_erased.go), its tree cache bounded by
// the client's TreeCacheByteCount.
func newEvsGitExport(repo *EvsRepo, writer *evsGitObjectWriter) *evsGitExport {
	store := newEvsGitExportStore(writer)
	export := newEvsGitReplayer(repo, store)
	export.writer, export.store = writer, store
	return export
}

// A replay's object work over objects, its tree cache bounded by the client's TreeCacheByteCount: export's, or the
// local tier's over a mount's bare repository.
func newEvsGitReplayer(repo *EvsRepo, objects evsGitReplayStore) *evsGitExport {
	return &evsGitExport{
		repo:      repo,
		objects:   objects,
		builder:   NewEvsGitTreeBuilder(objects, objects, repo.client.settings.TreeCacheByteCount),
		keys:      newEvsReadKeys(repo),
		ownClient: NewSidecarCommitter(&SidecarCommitterArgs{NetworkId: repo.client.args.NetworkId}),
		refs:      map[Id]*evsGitExportRef{},
		replaying: map[Id]bool{},
	}
}

// A replay over objects with what the bundled git's store asks (GIT-M13-02).
func newEvsGitReplayerWith(repo *EvsRepo, objects evsGitReplayStore, options *evsGitReplayOptions) *evsGitExport {
	replayer := newEvsGitReplayer(repo, objects)
	replayer.options = options
	return replayer
}

// The ref's export state, made on first use from its pinned head, or resumed from the state the store kept of it.
func (self *evsGitExport) ref(head *EvsVerifiedHead) *evsGitExportRef {
	ref := self.refs[head.RefId]
	if ref == nil {
		ref = &evsGitExportRef{refId: head.RefId, head: head, chain: EvsChainStart(self.repo.repoId, head.RefId), trail: newEvsWalkTrail(head.ask)}
		if self.options != nil {
			if kept := self.options.resume[head.RefId]; kept != nil && kept.RefId == head.RefId {
				ref.name, ref.passed, ref.chain = kept.Name, kept.Passed, kept.Chain
				ref.tip, ref.exists, ref.lastTip, ref.kind = kept.Tip, kept.Exists, kept.LastTip, kept.Kind
				ref.stoppedAt, ref.stopped = kept.StoppedAt, kept.Stopped
				for _, moved := range kept.Tips {
					ref.tips = append(ref.tips, evsGitExportTip{version: moved.Version, tip: moved.Tip})
				}
			}
		}
		ref.applied, ref.appliedChain = ref.passed, ref.chain
		ref.trail.start(ref.passed, ref.chain)
		self.refs[head.RefId] = ref
	}
	return ref
}

// A ref's state as a store keeps it for the next replay to resume from: at the last version applied, which every
// other field holds to.
func (self *evsGitExportRef) kept() *EvsGitReplayState {
	state := &EvsGitReplayState{
		RefId: self.refId, Name: self.name, Passed: self.applied, Chain: self.appliedChain, Tip: self.tip, Exists: self.exists,
		LastTip: self.lastTip, Kind: self.kind, StoppedAt: self.stoppedAt, Stopped: self.stopped,
	}
	for _, moved := range self.tips {
		state.Tips = append(state.Tips, EvsGitReplayTip{Version: moved.version, Tip: moved.tip})
	}
	return state
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
	exported := &EvsExportedRef{GitRef: gitRef, Versions: ref.head.Version, Refused: ref.refused, Rewritten: ref.rewritten}
	if ref.tip != nil {
		// the repository's oid for the tip: its rewrite's, where a blob under it was erased
		tip := self.store.exported(*ref.tip)
		if err := self.writer.setRef(gitRef, tip); err != nil {
			return nil, nil, err
		}
		exported.Tip = tip
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
		ref.applied, ref.appliedChain = ref.passed, ref.chain
	}
	return nil
}

// A refused version: alarmed, reported, and the ref stopped at the version before it until a DELETE. The prefix line's
// refusal alarms prefix_rule with detail refused, and its reason says prefix_rule (16.2.6).
func (self *evsGitExport) refuse(ref *evsGitExportRef, statement *EvsVerifiedStatement, reason error) error {
	var prefixRefusal *EvsGitPrefixRefusal
	if errors.As(reason, &prefixRefusal) {
		signerId := evsSignerOf(statement.Statement.Bytes)
		pushId, _ := IdFromBytes(statement.Statement.Push.GetPushId())
		if judge := self.repo.client.prefixJudge(); judge != nil && signerId != nil {
			judge.alarm(self.repo.repoId, ref.refId, *signerId, prefixRefusal.Path, statement.Version, &pushId, SidecarEvsAlarmDetailRefused, 1)
		}
	} else {
		self.repo.client.alarm(self.repo.repoId, ref.refId, SidecarEvsAlarmVersionRule, "", nil)
	}
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
	ref.kind = protocol.EvsRefKind(push.GetRefKind())
	// the prefix line's set at u's pin, before the record is read: export cannot wait, so a set it cannot read ends it
	var line *EvsGitPrefixLine
	if ref.stoppedAt == 0 {
		var err error
		if line, err = self.repo.gitPrefixLine(ctx, ref.refId, statement.Statement); err != nil {
			return err
		}
		if line.waits() {
			if line.Verdict.Outcome == AclPrefixUpdate {
				return &EvsPrefixRuleError{Detail: EvsPrefixDetailUpdate}
			}
			return &EvsPrefixRuleError{Detail: EvsPrefixDetailPending}
		}
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
	if self.options != nil && self.options.provenance != nil {
		// the push is seen before any of its objects is written (GIT-M13-02's taint)
		if err := self.options.provenance(ctx, ref.refId, statement, metadata); err != nil {
			return err
		}
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
	if base := ref.head.Head.GetBase(); creating && base != nil {
		// an overlay's readers hold what its base tip reaches (DESIGN-DETAILS 8.3's G2): the base ref is replayed to
		// the version it names before the overlay's first push is judged, as a source is
		if err := self.replaySource(ctx, base); err != nil {
			if evsExportRefusesVersion(err) {
				return self.refuse(ref, statement, err)
			}
			return err
		}
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
		Held:      self.objects.HasGitObject,
		Committer: self.committer,
		Import: func(ctx context.Context, signed []byte, push *protocol.EvsPush) (*protocol.EvsImport, error) {
			return self.repo.client.verifier.verifyImport(signed, self.repo.repoId, push)
		},
		Parents: self.parents,
		// the prefix line, with the arguments the sync engine passes, so export judges alike
		Prefix: line, HeldTip: ref.tip != nil || ref.lastTip != nil, SharedBranch: self.sharedBranch, SourceTip: self.sourceTip,
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
		if ref.tip != nil {
			ref.lastTip = ref.tip
		}
		ref.tip, ref.exists, ref.stoppedAt = nil, false, 0
		ref.tips = append(ref.tips, evsGitExportTip{version: statement.Version})
		return nil
	case protocol.EvsGitShape_EVS_GIT_REKEY:
		return nil
	}
	self.applying = &evsGitApplying{refId: ref.refId, version: statement.Version, chainBefore: ref.chain, chain: statement.Chain}
	_, err = self.applyUpdate(ctx, ref.head, statement, payload, metadata, checked)
	self.applying = nil
	if err != nil {
		if evsExportRefusesVersion(err) {
			return self.refuse(ref, statement, err)
		}
		return err
	}
	if err := self.checkPrefixTrees(ctx, ref, metadata, checked, line, payload); err != nil {
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
	note := &evsExportNote{commit: *checked.Peeled, statement: statement}
	if self.store != nil {
		// a rewrite over an erased blob (evs_export_erased.go): the note goes on the commit the repository holds, with
		// this push's stubs, and each commit it rewrote names its original, one before the tip in a note of its own
		lines, rewritten := self.store.takePush()
		note.commit, note.lines = self.store.exported(*checked.Peeled), lines
		for _, commit := range rewritten {
			line := "rewritten " + hex.EncodeToString(commit.original[:])
			if commit.original == *checked.Peeled {
				note.lines = append([]string{line}, note.lines...)
				continue
			}
			ref.notes = append(ref.notes, &evsExportNote{commit: commit.rewritten, statement: statement, lines: []string{line}})
		}
		ref.rewritten += uint64(len(rewritten))
	}
	ref.notes = append(ref.notes, note)
	return nil
}

// The prefix line's late test on export's objects (DESIGN-DETAILS 8.2.7), as the sync engine runs it: J is the tree of
// the tip before, the last tip's on a re-creation, the shared base's tip at its version on a branch's first tip, or
// the empty tree. Export keeps no tainted token paths, so a re-creation's are not judged here.
func (self *evsGitExport) checkPrefixTrees(ctx context.Context, ref *evsGitExportRef, metadata *protocol.EvsSealedMetadata, checked *EvsGitCheckedUpdate, line *EvsGitPrefixLine, payload *EvsCheckedPayload) error {
	if checked.PrefixMeasure == EvsGitPrefixMeasureNone {
		return nil
	}
	next, err := evsGitPeeledTree(ctx, self.objects, *checked.Peeled)
	if err != nil {
		return err
	}
	var stood *EvsGitOid
	if checked.PrefixMeasure == EvsGitPrefixMeasureFromJ {
		var from *EvsGitOid
		switch {
		case ref.tip != nil:
			from = ref.tip
		case ref.lastTip != nil:
			from = ref.lastTip
		case metadata.GetBase() != nil:
			baseRefId, err := IdFromBytes(metadata.GetBase().GetRefId())
			if err != nil {
				return fmt.Errorf("%w: an overlay base that is no ref", ErrEvsGitUpdateRefused)
			}
			if base := self.refs[baseRefId]; base != nil {
				if tip, applied := base.tipAt(metadata.GetBase().GetVersion()); applied {
					from = tip
				}
			}
			if from == nil {
				return fmt.Errorf("%w: an overlay whose base version has no tip", ErrEvsGitUpdateRefused)
			}
		}
		if from != nil {
			tree, err := evsGitPeeledTree(ctx, self.objects, *from)
			if err != nil {
				return err
			}
			stood = &tree
		}
	}
	return EvsGitCheckPrefixTrees(ctx, &EvsGitPrefixTreesArgs{
		Line: line, Measure: checked.PrefixMeasure, Source: self.objects, J: stood, N: next, Changes: payload.Changes,
	})
}

// Whether a ref export replayed is a shared branch by its own history: kind shared, a name that is no tag's.
func (self *evsGitExport) sharedBranch(ctx context.Context, refId Id) (bool, error) {
	ref := self.refs[refId]
	if ref == nil {
		return false, nil
	}
	return ref.kind == protocol.EvsRefKind_EVS_REF_SHARED && len(ref.name) != 0 && !bytes.HasPrefix(ref.name, []byte(evsGitTagRefPrefix)), nil
}

// The tip a source held at the version it names, as export applied it: nil where none stands.
func (self *evsGitExport) sourceTip(ctx context.Context, source *protocol.EvsOverlay) (*EvsGitOid, error) {
	refId, err := IdFromBytes(source.GetRefId())
	if err != nil {
		return nil, nil
	}
	ref := self.refs[refId]
	if ref == nil {
		return nil, nil
	}
	tip, applied := ref.tipAt(source.GetVersion())
	if !applied {
		return nil, nil
	}
	return tip, nil
}

// An UPDATE's objects, its sources replayed by the check: its blobs, its tags, then each commit's tree rebuilt and the
// commit written. It answers each file entry's sealed mode and oid by its change's token path key. Under export's
// store a blob a committed ERASE destroyed is its stub, and what holds it is rewritten, the tags after the commits
// they may name (evs_export_erased.go); the local tier's replay, with no store, meets it as ErrEvsErased.
func (self *evsGitExport) applyUpdate(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement, payload *EvsCheckedPayload, metadata *protocol.EvsSealedMetadata, checked *EvsGitCheckedUpdate) (map[string]*evsGitWrittenFile, error) {
	git := metadata.GetGit()
	if self.store != nil {
		self.store.beginPush()
	}
	written := map[string]*evsGitWrittenFile{}
	deferring := self.options != nil && self.options.deferBlob != nil && self.applying != nil
	for _, change := range payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		if deferring {
			file, err := self.deferEntry(ctx, statement, change)
			if err != nil {
				return nil, err
			}
			if file != nil {
				written[change.TokenPath.KeyString()] = file
			}
			continue
		}
		file, err := self.repo.exportBlob(ctx, self.objects, head, self.keys, statement, change, "")
		if errors.Is(err, ErrEvsErased) && self.store != nil {
			file, err = self.erasedBlob(ctx, head, statement, change)
		}
		if err != nil {
			return nil, err
		}
		if file != nil {
			written[change.TokenPath.KeyString()] = file
		}
	}
	if deferring {
		for _, blob := range git.GetBlobs() {
			oid := EvsGitOid(blob.GetGitOid())
			if self.objects.HasGitObject(oid) {
				continue
			}
			if err := self.options.deferBlob(self.locator(oid, blob.GetSize(), true)); err != nil {
				return nil, err
			}
		}
	} else if err := self.historyBlobs(ctx, head, statement, git); err != nil {
		return nil, err
	}
	if self.store == nil {
		for i, tag := range checked.Tags {
			if oid, err := self.objects.WriteGitObject(evsGitTagKind, tag); err != nil || oid != checked.TagOids[i] {
				return nil, errors.Join(err, fmt.Errorf("%w: a tag that is not its oid", ErrEvsGitUpdateRefused))
			}
		}
	}
	for _, commit := range checked.Commits {
		if commit.Held {
			continue
		}
		var parentTree *EvsGitOid
		if 0 < len(commit.ParentOids) {
			kind, parentObject, err := self.objects.ReadGitObject(ctx, commit.ParentOids[0])
			if err != nil || kind != evsGitCommitKind {
				return nil, errors.Join(err, fmt.Errorf("%w: a commit whose first parent is not held", ErrEvsGitUpdateRefused))
			}
			treeOid, _, err := EvsGitCommitGraph(parentObject)
			if err != nil {
				return nil, err
			}
			parentTree = &treeOid
		}
		for _, change := range commit.Sealed.GetChanges() {
			if len(change.GetGitOid()) != 0 && change.GetMode() != EvsGitModeGitlink && !self.objects.HasGitObject(EvsGitOid(change.GetGitOid())) {
				return nil, fmt.Errorf("%w: a commit naming a blob neither held nor carried", ErrEvsGitUpdateRefused)
			}
		}
		treeOid, err := self.builder.Build(ctx, parentTree, commit.Sealed.GetChanges(), commit.Sealed.GetTrees())
		if err != nil {
			return nil, err
		}
		if treeOid != commit.TreeOid {
			self.repo.client.alarm(self.repo.repoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
			return nil, fmt.Errorf("%w: a commit's tree does not rebuild from its changes", ErrEvsGitUpdateRefused)
		}
		if self.store != nil {
			if err := self.store.commit(commit); err != nil {
				return nil, err
			}
			continue
		}
		if _, err := self.objects.WriteGitObject(evsGitCommitKind, commit.Sealed.GetObject()); err != nil {
			return nil, err
		}
	}
	if self.store != nil {
		// innermost first, so a tag of a rewritten tag is rewritten too
		for i := len(checked.Tags) - 1; 0 <= i; i -= 1 {
			if oid, err := self.store.tag(checked.Tags[i]); err != nil || oid != checked.TagOids[i] {
				return nil, errors.Join(err, fmt.Errorf("%w: a tag that is not its oid", ErrEvsGitUpdateRefused))
			}
		}
	}
	return written, nil
}

// A deferred blob's locator at the version applyUpdate writes.
func (self *evsGitExport) locator(oid EvsGitOid, size uint64, history bool) *EvsGitBlobLocator {
	return &EvsGitBlobLocator{
		Oid: oid, Size: size, RefId: self.applying.refId, Version: self.applying.version, ChainBefore: self.applying.chainBefore,
		Chain: self.applying.chain, History: history,
	}
}

// One entry of a version deferred (GIT-M13-02): its file as its sealed fields state it, its locator recorded where the
// store holds no blob of that oid; nil for an entry that is no file's. A gitlink holds no blob and records nothing.
func (self *evsGitExport) deferEntry(ctx context.Context, statement *EvsVerifiedStatement, change *EvsCheckedChange) (*evsGitWrittenFile, error) {
	file, err := self.entryFields(ctx, self.applying.refId, statement, change)
	if err != nil || file == nil {
		return nil, err
	}
	if file.mode == EvsGitModeGitlink || self.objects.HasGitObject(file.oid) {
		return file, nil
	}
	if err := self.options.deferBlob(self.locator(file.oid, file.size, false)); err != nil {
		return nil, err
	}
	return file, nil
}

// An entry's file as its sealed fields state it, opened under manifest_g with no record read: its mode, SHA-1 oid and
// size; nil for an entry that is no file's. Fields that do not open alarm tamper on the ref, as reconstruction's do.
func (self *evsGitExport) entryFields(ctx context.Context, refId Id, statement *EvsVerifiedStatement, change *EvsCheckedChange) (*evsGitWrittenFile, error) {
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
		return nil, fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
	}
	if entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
		return nil, nil
	}
	manifest, err := self.keys.manifest(ctx, statement.Statement.Push.GetGeneration())
	if err != nil {
		return nil, err
	}
	var fields *protocol.EvsSealedFields
	if entry.GetVersioning() == 0 {
		fields, err = EvsOpenFields(manifest, entry.GetSealedFields())
	} else {
		fields, err = EvsOpenFieldsFormat2(manifest, entry.GetSealedFields(), entry.GetVersioning())
	}
	if err != nil {
		self.repo.client.alarm(self.repo.repoId, refId, SidecarEvsAlarmTamper, "", nil)
		return nil, err
	}
	if len(fields.GetGitOid()) != len(EvsGitOid{}) || fields.GetOidKind() != protocol.EvsOidKind_EVS_OID_SHA1 {
		return nil, fmt.Errorf("%w: a git-mode file of no SHA-1 blob", ErrEvsSealInvalid)
	}
	return &evsGitWrittenFile{mode: fields.GetMode(), oid: EvsGitOid(fields.GetGitOid()), size: fields.GetSize()}, nil
}

// Export's reading of a git-mode version's blob a committed ERASE destroyed (evs_export_erased.go): its stub in the
// repository, and the file as its sealed fields state it, so the replay goes on in the original oids. A gitlink holds
// no key to erase, and sealed fields that do not open alarm tamper, as reconstruction's do.
func (self *evsGitExport) erasedBlob(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement, change *EvsCheckedChange) (*evsGitWrittenFile, error) {
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
		return nil, fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
	}
	manifest, err := self.keys.manifest(ctx, statement.Statement.Push.GetGeneration())
	if err != nil {
		return nil, err
	}
	var fields *protocol.EvsSealedFields
	if entry.GetVersioning() == 0 {
		fields, err = EvsOpenFields(manifest, entry.GetSealedFields())
	} else {
		fields, err = EvsOpenFieldsFormat2(manifest, entry.GetSealedFields(), entry.GetVersioning())
	}
	if err != nil {
		self.repo.client.alarm(self.repo.repoId, head.RefId, SidecarEvsAlarmTamper, "", nil)
		return nil, err
	}
	if len(fields.GetGitOid()) != len(EvsGitOid{}) || fields.GetMode() == EvsGitModeGitlink {
		return nil, fmt.Errorf("%w: an erased git-mode file of no blob", ErrEvsErased)
	}
	oid := EvsGitOid(fields.GetGitOid())
	if _, err := self.store.erase(change, oid); err != nil {
		return nil, err
	}
	return &evsGitWrittenFile{mode: fields.GetMode(), oid: oid}, nil
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
		done := self.repo.client.pins.beginRead(self.repo.repoId, refId)
		head, err := self.repo.pinnedHead(ctx, refId)
		if err != nil {
			done()
			return err
		}
		self.reading(done)
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
	kind, object, err := self.objects.ReadGitObject(ctx, oid)
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
			if self.objects.HasGitObject(EvsGitOid(blob.GetGitOid())) {
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
	if self.objects.HasGitObject(oid) {
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
			kind, baseObject, err := self.objects.ReadGitObject(ctx, EvsGitOid(blob.GetBaseOid()))
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
	written, err := self.objects.WriteGitObjectFrom(evsGitBlobKind, content.reader(), content.Size())
	if err != nil {
		return err
	}
	if written != oid {
		return fmt.Errorf("%w: a history blob that is not its oid", ErrEvsSealInvalid)
	}
	return nil
}

// One entry of a push reconstructed into a blob written to sink, its oid checked by reconstruction, and the file's
// sealed mode and oid; nil for an entry that is no file's. A gitlink, whose oid names a commit and which has no
// content, writes nothing and answers its mode and oid.
func (self *EvsRepo) exportBlob(ctx context.Context, sink EvsGitObjectSink, head *EvsVerifiedHead, keys *evsReadKeys, statement *EvsVerifiedStatement, change *EvsCheckedChange, path string) (*evsGitWrittenFile, error) {
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
	result.exportPath = path
	spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
	defer spill.close()
	info, err := self.reconstruct(ctx, result, verified, spill)
	if err != nil {
		return nil, err
	}
	if info.Mode == EvsGitModeGitlink {
		return &evsGitWrittenFile{mode: info.Mode, oid: info.GitOid}, nil
	}
	oid, err := sink.WriteGitObjectFrom(evsGitBlobKind, spill.reader(), spill.Size())
	if err != nil {
		return nil, err
	}
	return &evsGitWrittenFile{mode: info.Mode, oid: oid}, nil
}
