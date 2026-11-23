//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// One git ref update published as one evs push (DESIGN-DETAILS 8.2.5): EvsLocalPublish, which the receive path, an
// owned ref's queue and an import call, each holding the ref's publish lock and having read old and the base version
// b under its apply lock (8.2.9).
//
//	1 shape    a DELETE for no new tip, else an UPDATE: FORCE when new does not descend from old, IMMUTABLE on a
//	           tag ref's creation; a tag ref takes no update past its creation, and a tag of a tree or blob none
//	2 carried  C, S and B over excl, old's, a deleted ref's last tip, and an overlay's base tip (evs_local_commits.go),
//	           each one its readers hold; each commit of C sealed
//	           with its changes against its first parent by the tree reader, a new one held to 8.2.3's rule and an
//	           import's to git's graph alone
//	3 changes  the net change from the tree the path state stands at (old's, a deleted ref's last tip's) to new's
//	           (evs_local_tree.go), none on a tag ref; PlanGitUpdate plans it, and its entries are sealed. A branch's
//	           re-creating push writes or removes each tainted token path beside it (8.5; 8.2.4's chain row), named
//	           in the new tree, which PlanGitUpdate walks, save one last removed that the new tree lacks, where it
//	           states nothing (QD-826): a taint below the epoch this client last saw the ref in, or below another
//	           taint's, matches no push's epoch, and is refused before any request
//	4 history  every blob a carried commit's change names that B holds and no entry carries, one record each in
//	           order: a diff against the same path's blob in the commit's first parent where it is smaller, else a
//	           checkpoint, or chunks past 8 MiB; each in a history segment of 8 MiB, Padmé-padded, uploaded with the
//	           push's own segments under ?push=P and named by the sealed update's segment_ids
//	5 metadata commits, git {shape, old_tip, new_tip, tags, sources, segment_ids, blobs}, an import's EvsImport over
//	           this push's own commits signed by this admin (QD-603), none when it carries none, and on a creating
//	           push the ref name and base,
//	           with payload sections 15 and 16 beside them
//	6 send     the landed sender: one part, or parts under the seal lease taken again as it lapses, and the seal
//	7 answers  200 is the caller's to apply and settle (EVS1-M2-35's replay). A head past b, found by the plan or
//	           by a 409 NON_FAST_FORWARD, is judged by the versions between: this push's id among them is its commit;
//	           PATH_EPOCH and REKEY versions and pin pushes alone, which move no tip, build the update again on the new
//	           head under a new push id; anything else moved the tip, ErrEvsGitTipMoved, the caller's `ng
//	           non-fast-forward`. A pin push is the UPDATE of one tip, old_tip = new_tip, carrying nothing (8.2.10), so a
//	           push that loses its turn to one is never non-fast-forward (8.2.10's losing row)
//	           412 PATH_EPOCH is the sender's retoken, a first push planned again; SEGMENT_STALE, SEGMENT_GONE,
//	           SLOT_STALE, TIME_STALE and GATE_CLOSED build again under a new push id, at most PushRebuildCount
//	           times; 412 PATH_EPOCH_DUE, a mapper's block, waits as WritePaths does, ErrEvsPathEpochDue past its
//	           bound; any other refusal is the caller's
//
// Under a general repo's prefix write rules a shared ref's update passes this device's own check before anything is
// planned (DESIGN-DETAILS 8.2.5's prefix check, 16.2.7; QD-801), so its push passes 8.2.7's prefix line at every reader:
//
//	held      at step 1, for an update that creates a shared branch or is a tag's, one AllowPrefixWrite call for the
//	          path of no component at the installed state: a device the set names in no rule of no path is held. A
//	          held device takes its new branch's base from the shared branches alone, on every parent line
//	          (evs_local_overlay.go), and names its tag's proof first among the sources (evs_local_commits.go); a set
//	          pending or newer ends the update there
//	check     at the top of every attempt, so again before each statement signed on another state's pin (the landed
//	          rebuild after 412 GATE_CLOSED or a stale segment, a build again from step 3 after a REKEY or a pin push,
//	          a retoken): AllowPrefixWrite over the files measured from J, every path that is a file in J or in N and
//	          not the same mode and oid in both, drawn from the net change, or from nothing, every file of N drawn in
//	          the tree reader's order, the engine stopping at the first it refuses and drawing none for a device
//	          named for every path; then each tainted token path the re-creating push writes or removes, on its token
//	          path against this sidecar's prefixes in the push's epoch. J is S but on a branch's first tip over a base
//	          that is no shared branch, or none, and on a tag with no proof, where it is the empty tree. A DELETE skips
//	          it, a FORCE is outside the rules, and an owned ref asks nothing. A refusal is EVS_PREFIX_RULE with the
//	          path and detail refused, pending or update, or base for a new branch measured from nothing and tag for a
//	          tag with no proof; a tainted token path names none
//
// A refusal before any evs write names the commit, tree or path, never its bytes (I-13). The history segments and the
// write's spills are dropped on every exit. Memory holds one push's sealed commits and its history blobs' records as
// they are sealed: the spool to disk 8.2.5 asks for is not built (incomplete).
//
// Desktop legs only. Safe for concurrent use as its arguments are; the caller's publish lock makes one device's
// pushes to one ref take turns.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A git push whose ref's tip moved under it, by a version that is not its own and not commitless: the caller's
// `ng <ref> non-fast-forward` (DESIGN-DETAILS 8.2.8), said only when no attempt of the update is in the history.
var ErrEvsGitTipMoved = errors.New("evs: the ref's tip moved under the update")

// What EvsLocalPublish publishes.
type EvsLocalPublishArgs struct {
	// The mount whose bare repository holds the update's objects, and the evs repo it serves.
	Mount *EvsLocalRepo
	Repo  *EvsRepo
	// The ref's name bytes as evs names it: a branch's short name, a tag's refs/tags/<name>.
	RefName []byte
	// The ref's value before, as replay applied it, nil for none (never created, or deleted), and after, nil for a
	// DELETE: a commit, or an annotated tag's oid.
	Old *EvsGitOid
	New *EvsGitOid
	// The version replay applied, whose tip is Old, and its chain C_b: the push's base, which a moved head's versions
	// are walked from.
	BaseVersion uint64
	BaseChain   [sha256.Size]byte
	// The ref was deleted at BaseVersion, so the push re-creates it; LastTip is its last tip, whose tree the
	// re-creating push states its net change against (8.2.4's branch row), nil for one deleted with no tip.
	Deleted bool
	LastTip *EvsGitOid
	// The ref's tainted token paths (EvsGitRef.Tainted), read under the apply lock with Old and BaseVersion: the
	// token paths a version stopped at, and those after it until the DELETE, changed (8.5), each with whether the last
	// of those changes removed it. A branch's re-creating push writes or removes each beside its net change, save one
	// last removed that the new tree lacks, where it states nothing (PlanGitUpdate's tainted row; QD-826); a DELETE
	// and a tag ref, which hold no change, take none, and any other update of a ref holding them is refused. Nil for
	// none.
	Tainted []EvsTaintedPath
	// An overlay's base as replay holds it from the head (EvsGitRef.base), for a push that does not create its ref or
	// re-creates it after a DELETE; a new branch's is chosen here by the base search (evs_local_overlay.go), nil for
	// none.
	Base *protocol.EvsOverlay
	// The writing run's tainted bit and the agent the push is made for, which its sealed provenance carries
	// (EvsGitPlanArgs.RunTainted, AgentId): WriteAtTip's, false and nil for a git client's push, which no run binds.
	RunTainted bool
	AgentId    *Id
	// An import's push: every carried commit is listed by an EvsImport this sidecar signs, as a repo admin, over the
	// push's own commits (8.2.6), held to git's graph alone.
	Import bool
	// Replay's state: the refs whose tips a push may name as sources (EVS1-M2-35's EvsGitRef and tips log).
	State EvsGitSourceState
	// Whether a client is this sidecar's, whose commits a push may carry as new (owner decision 81): nil takes this
	// client alone.
	OwnClient func(clientId Id) bool
	// Called with each attempt before its statement's first POST, its segments uploaded: what the receive path, the
	// queue and the import journal SENT (DESIGN-DETAILS 8.2.8). An error stops the publish with nothing posted. Nil
	// for none.
	OnAttempt func(attempt *EvsGitPublishAttempt) error
}

// One attempt of a publish, as the journal records it before its first POST.
type EvsGitPublishAttempt struct {
	PushId          Id
	StatementSha256 [sha256.Size]byte
	// The version and chain it is built on, and the update's tips.
	BaseVersion uint64
	BaseChain   [sha256.Size]byte
	Old         *EvsGitOid
	New         *EvsGitOid
	// The statement's time_ms, and whether it seals in parts.
	TimeMs int64
	Parts  bool
}

// What a committed publish did.
type EvsLocalPublishResult struct {
	PushId  Id
	Version uint64
	Shape   protocol.EvsGitShape
	Flags   uint32
	// The carried commits, parents first, and the sources the push named.
	Commits []EvsGitOid
	Sources []*protocol.EvsOverlay
	// The overlay's base the push named, or the ref holds, nil for none: what replay keeps in EvsGitRef.
	Base *protocol.EvsOverlay
	// How many history blobs it carried.
	HistoryBlobCount int
}

// Publishes one git ref update as one evs push: see the file header.
func EvsLocalPublish(ctx context.Context, args *EvsLocalPublishArgs) (*EvsLocalPublishResult, error) {
	repo, mount := args.Repo, args.Mount
	if repo == nil || mount == nil || repo.repoId != mount.RepoId {
		return nil, fmt.Errorf("%w: a publish with no mount, or another repo's", ErrEvsWriteInvalid)
	}
	refId, err := repo.resolveRefId(ctx, args.RefName, nil)
	if err != nil {
		return nil, err
	}
	switch {
	case args.Old == nil && args.New != nil && args.BaseVersion != 0 && !args.Deleted:
		return nil, fmt.Errorf("%w: an update with no old tip of a ref that has one", ErrEvsGitUpdateInvalid)
	case args.New == nil && (args.BaseVersion == 0 || args.Deleted):
		return nil, fmt.Errorf("%w: a deletion of a ref that does not stand", ErrEvsGitUpdateInvalid)
	}
	if err := evsGitCheckTaints(repo, refId, args); err != nil {
		return nil, err
	}
	objects, err := mount.Objects(ctx)
	if err != nil {
		return nil, err
	}
	defer objects.Close()
	update, err := newEvsGitPublishUpdate(ctx, args, refId, objects)
	if err != nil {
		return nil, err
	}
	baseVersion, baseChain := args.BaseVersion, args.BaseChain
	if baseVersion == 0 {
		baseChain = EvsChainStart(repo.repoId, refId)
	}
	rebuilds, dueWaits := 0, 0
	for {
		result, err := update.publishOnce(ctx, baseVersion, &rebuilds)
		moved := (*EvsGitHeadMovedError)(nil)
		if err != nil && !errors.As(err, &moved) && IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD) {
			head, headErr := repo.readHeadAlone(ctx, refId, true)
			if headErr != nil {
				return nil, headErr
			}
			moved = &EvsGitHeadMovedError{Head: head, BaseVersion: baseVersion}
		}
		switch {
		case err == nil:
			return result, nil
		case moved != nil:
			committed, commitless, judgeErr := update.judgeMoved(ctx, moved, baseChain)
			switch {
			case judgeErr != nil:
				return nil, judgeErr
			case committed != nil:
				return committed, nil
			case !commitless || repo.client.settings.PushRebuildCount <= rebuilds:
				return nil, fmt.Errorf("%w: the head is at %d, past %d", ErrEvsGitTipMoved, moved.Head.Version, baseVersion)
			}
			// PATH_EPOCH and REKEY versions alone: the update built again on the new head (8.2.5's 409 row)
			rebuilds += 1
			baseVersion, baseChain = moved.Head.Version, moved.Head.Chain
		case IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE):
			if repo.client.settings.PushRetryCount <= dueWaits {
				return nil, fmt.Errorf("%w: %w", ErrEvsPathEpochDue, err)
			}
			dueWaits += 1
			if err := repo.waitPathEpoch(ctx, refId, err); err != nil {
				return nil, err
			}
		case (evsNeedsRebuild(err) || errors.Is(err, errEvsPlanEpochMoved) || errors.Is(err, errEvsRetokenSealsAgain)) &&
			rebuilds < repo.client.settings.PushRebuildCount:
			rebuilds += 1
		default:
			return nil, err
		}
	}
}

// The tainted token paths a publish plans: a branch's, on an update with a new tip, none for a DELETE, which carries
// nothing to check, or a tag ref, which holds no path state (8.2.4, 8.5).
func evsGitPublishTaints(args *EvsLocalPublishArgs) []EvsTaintedPath {
	if args.New == nil || bytes.HasPrefix(args.RefName, []byte(evsGitTagRefPrefix)) {
		return nil
	}
	return args.Tainted
}

// What a publish refuses of the ref's taints before any request (8.5): an update other than the push that re-creates
// the ref after its DELETE, since a stopped ref takes its deletion and nothing else; and a taint below the epoch this
// client last verified the ref's head in, or below another taint's, since a ref's epoch never falls, so no push of it
// can be in that taint's epoch, on which every replaying reader fails closed. PlanGitUpdate holds each taint to the
// push's own epoch once it has read the head.
func evsGitCheckTaints(repo *EvsRepo, refId Id, args *EvsLocalPublishArgs) error {
	tainted := evsGitPublishTaints(args)
	if len(tainted) == 0 {
		return nil
	}
	if !args.Deleted {
		return fmt.Errorf("%w: a ref stopped at a refused version takes only its deletion", ErrEvsGitUpdateInvalid)
	}
	least, most := tainted[0].Epoch, tainted[0].Epoch
	for _, path := range tainted[1:] {
		least, most = min(least, path.Epoch), max(most, path.Epoch)
	}
	if state := repo.client.refEpochState(repo.repoId, refId); state != nil {
		most = max(most, evsCurrentEpoch(state.epoch))
	}
	if least < most {
		return fmt.Errorf("%w: %w: a taint of path epoch %d, where the ref has reached %d", ErrEvsGitUpdateInvalid, ErrEvsGitTaintedPath, least, most)
	}
	return nil
}

// One update as publish builds it: what steps 1 and 2 fixed, which every attempt seals again.
type evsGitPublishUpdate struct {
	args    *EvsLocalPublishArgs
	repo    *EvsRepo
	refId   Id
	objects *EvsLocalObjects
	// the update the push seals, with no history yet, its flags, and whether it creates its ref
	git      *protocol.EvsGitUpdate
	flags    uint32
	creating bool
	tagRef   bool
	// the carried commits, sealed, and their oids; the blobs no reader holds; the net change
	commits    []*protocol.EvsSealedCommit
	commitOids []EvsGitOid
	carried    *evsGitCarried
	changes    []*EvsGitPathChange
	// the push ids this update sent, which the history may hold
	pushIds map[Id]bool
	// an overlay's base, the head's or the one the base search chose
	base *protocol.EvsOverlay
	// a branch update's new tree, and the tainted token paths its re-creating push writes or removes (8.5)
	nextTree EvsGitOid
	tainted  []EvsTaintedPath
	// the prefix check's measure (8.2.5): from J, which is S here, or from nothing over N, the commit the update peels
	// to, and the detail a refusal from nothing takes; a tag's proof, nil for none
	measure      EvsGitPrefixMeasure
	peeled       EvsGitOid
	measureEmpty EvsPrefixDetail
	proof        *EvsGitSourceRef
}

// A test's hook that skips the prefix check, as a device that does not run this code would, to build a push every
// reader refuses; nil outside tests.
var evsLocalPublishSkipPrefixHook func(update *evsGitPublishUpdate) bool

// Steps 1 and 2 of the file header, and the net change, which no attempt changes.
func newEvsGitPublishUpdate(ctx context.Context, args *EvsLocalPublishArgs, refId Id, objects *EvsLocalObjects) (*evsGitPublishUpdate, error) {
	self := &evsGitPublishUpdate{
		args: args, repo: args.Repo, refId: refId, objects: objects, creating: args.Old == nil,
		tagRef: bytes.HasPrefix(args.RefName, []byte(evsGitTagRefPrefix)), pushIds: map[Id]bool{},
	}
	self.git = &protocol.EvsGitUpdate{Shape: protocol.EvsGitShape_EVS_GIT_UPDATE}
	if args.Old != nil {
		self.git.OldTip = bytes.Clone(args.Old[:])
	}
	if args.New == nil {
		// a DELETE carries nothing and states no new tip (8.2.3's shapes)
		self.git.Shape = protocol.EvsGitShape_EVS_GIT_DELETE
		self.flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
		self.creating = false
		return self, nil
	}
	if self.tagRef && !self.creating {
		return nil, fmt.Errorf("%w: a tag ref's update past its creation", ErrEvsGitUpdateInvalid)
	}
	self.git.NewTip = bytes.Clone(args.New[:])
	peeled, tags, err := evsGitPeel(ctx, objects, *args.New)
	if err != nil {
		return nil, err
	}
	self.git.Tags = tags
	excl := []EvsGitOid{}
	var stood *EvsGitOid
	if args.Old != nil {
		peeledOld, _, err := evsGitPeel(ctx, objects, *args.Old)
		if err != nil {
			return nil, err
		}
		excl = append(excl, peeledOld)
		// FORCE when new does not descend from old (8.2.3's shapes row)
		descends, err := args.Mount.reachedBy(ctx, peeledOld, []EvsGitOid{peeled})
		if err != nil {
			return nil, err
		}
		if !descends {
			self.flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
		}
		stood = &peeledOld
	} else if args.Deleted && args.LastTip != nil {
		// a re-creation states its net change against the tree the deleted ref's entries stand at, and its readers
		// hold what that tip reaches, the ref's own refs/ur/evs/ tip, which is excl and never a source
		peeledLast, _, err := evsGitPeel(ctx, objects, *args.LastTip)
		if err != nil {
			return nil, err
		}
		excl = append(excl, peeledLast)
		stood = &peeledLast
	}
	if self.tagRef {
		self.flags |= uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)
	}
	if args.State == nil {
		return nil, fmt.Errorf("%w: a publish with no replay state", ErrEvsWriteInvalid)
	}
	// step 1 under the repo's prefix rules: whether this device is held, for an update that creates a shared branch or
	// is a tag's (8.2.4, 8.2.5; QD-801)
	held, err := self.askHeld(ctx)
	if err != nil {
		return nil, err
	}
	// an overlay's base: a new branch's from the base search, else the head's; its tip is held by every reader, and a
	// new overlay states its first net change against the base tip's tree (8.2.4)
	self.base = args.Base
	var baseTip *EvsGitOid
	baseShared := false
	switch {
	case self.tagRef:
		if self.base != nil {
			return nil, fmt.Errorf("%w: a tag ref with a base", ErrEvsGitUpdateInvalid)
		}
	case self.base == nil && self.creating && !args.Deleted:
		search := args.Mount.overlayBase
		if held {
			search = args.Mount.overlayBaseShared
		}
		found, err := search(ctx, refId, peeled, args.State, args.Repo.client.settings.OverlayBaseSearchCount)
		if err != nil {
			return nil, err
		}
		if found != nil {
			self.base = &protocol.EvsOverlay{RefId: found.RefId.Bytes(), Version: found.Version}
			tip := found.Tip
			baseTip = &tip
			baseShared = evsGitSourceSharedBranch(found)
		}
	case self.base != nil:
		baseRefId, err := IdFromBytes(self.base.GetRefId())
		if err != nil {
			return nil, fmt.Errorf("%w: an overlay base's ref id", ErrEvsWriteInvalid)
		}
		tip, ok, err := args.State.TipAt(ctx, baseRefId, self.base.GetVersion())
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: an overlay whose base version replay has not applied", ErrEvsGitUpdateInvalid)
		}
		baseTip = &tip
		if baseShared, err = evsGitStateSharedBranch(ctx, args.State, baseRefId); err != nil {
			return nil, err
		}
	}
	if baseTip != nil {
		peeledBase, _, err := evsGitPeel(ctx, objects, *baseTip)
		if err != nil {
			return nil, err
		}
		excl = append(excl, peeledBase)
		if self.creating && (!args.Deleted || args.LastTip == nil) {
			// an overlay's first push, or the push re-creating one whose every earlier push was refused, which never
			// held a tip, states its net change against its base tip's tree, as its readers hold it (8.2.4)
			stood = &peeledBase
		}
	}
	if self.tagRef && held {
		// a held device names its tag's proof first among the sources, or none, and is then measured from nothing
		if self.proof, err = evsGitTagProof(ctx, args.State, peeled); err != nil {
			return nil, err
		}
	}
	carried, err := args.Mount.carried(ctx, refId, peeled, excl, args.State, self.proof)
	if err != nil {
		return nil, err
	}
	self.carried = carried
	for _, source := range carried.sources {
		self.git.Sources = append(self.git.Sources, &protocol.EvsOverlay{RefId: source.RefId.Bytes(), Version: source.Version})
	}
	own := args.OwnClient
	if own == nil {
		clientId := args.Repo.client.args.Identity().ClientId
		own = func(candidate Id) bool { return candidate == clientId }
	}
	for _, oid := range carried.commits {
		sealed, _, err := evsGitSealCommit(ctx, objects, oid)
		if err != nil {
			return nil, err
		}
		if !args.Import {
			if err := evsGitCheckNewCommit(oid, sealed, own); err != nil {
				return nil, err
			}
		}
		self.commits = append(self.commits, sealed)
		self.commitOids = append(self.commitOids, oid)
	}
	if !self.tagRef {
		nextTree, err := evsGitTreeOf(ctx, objects, peeled)
		if err != nil {
			return nil, err
		}
		var stoodTree *EvsGitOid
		if stood != nil {
			tree, err := evsGitTreeOf(ctx, objects, *stood)
			if err != nil {
				return nil, err
			}
			stoodTree = &tree
		}
		if self.changes, err = evsGitNetChange(ctx, objects, stoodTree, nextTree); err != nil {
			return nil, err
		}
		if err := self.markReuses(ctx); err != nil {
			return nil, err
		}
		self.nextTree, self.tainted = nextTree, evsGitPublishTaints(args)
	}
	// step 3's measure (8.2.5's new ref row): J is S but on a branch's first tip over a base that is no shared branch,
	// or none, and on a tag with no proof, where every file of N is asked about from nothing
	self.peeled = peeled
	switch {
	case self.tagRef:
		if self.proof == nil {
			self.measure, self.measureEmpty = EvsGitPrefixMeasureFromNothing, EvsPrefixDetailTag
		}
	case args.Old != nil || args.LastTip != nil || baseShared:
		self.measure = EvsGitPrefixMeasureFromJ
	default:
		self.measure, self.measureEmpty = EvsGitPrefixMeasureFromNothing, EvsPrefixDetailBase
	}
	if evsLocalPublishUpdateHook != nil {
		evsLocalPublishUpdateHook(self)
	}
	return self, nil
}

// Step 1's question under the repo's prefix rules (8.2.4, 8.2.5's new shared name): for an update that creates a
// shared branch, or is a tag's, whether this device is held, by one AllowPrefixWrite call for the path of no component
// at the installed state. A set pending or newer ends the update with EVS_PREFIX_RULE; an owned ref, a branch's
// re-creation, whose base is the head's, and a repo with no set ask nothing.
func (self *evsGitPublishUpdate) askHeld(ctx context.Context) (bool, error) {
	if _, owned := EvsOwnedRefOwner(self.args.RefName); owned || !self.creating || (!self.tagRef && self.args.Deleted) {
		return false, nil
	}
	ruled, err := self.repo.prefixRuled()
	if err != nil || ruled == nil {
		return false, err
	}
	err = ruled.allowWrite(ctx, self.repo, &evsPrefixWriteAsk{
		refName: self.args.RefName, refKind: protocol.EvsRefKind_EVS_REF_SHARED, refMode: protocol.EvsRefMode_EVS_REF_GIT,
		flags: self.flags, paths: []string{""},
	})
	var ruleErr *EvsPrefixRuleError
	switch {
	case err == nil:
		return false, nil
	case errors.As(err, &ruleErr) && ruleErr.Detail == EvsPrefixDetailRefused && ruleErr.Path == "":
		return true, nil
	}
	return false, err
}

// Whether the state holds a ref as a shared branch: by the ref's own history where the state answers it (the sync
// engine's SharedBranch), else by its row with a tip; a ref it holds neither of is none, which measures from nothing.
func evsGitStateSharedBranch(ctx context.Context, state EvsGitSourceState, refId Id) (bool, error) {
	if history, ok := state.(interface {
		SharedBranch(ctx context.Context, refId Id) (bool, error)
	}); ok {
		return history.SharedBranch(ctx, refId)
	}
	source, held, err := state.SourceRef(ctx, refId)
	if err != nil || !held {
		return false, err
	}
	return evsGitSourceSharedBranch(source), nil
}

// Step 3's prefix check (see the file header's check row): nil where the update passes, else EVS_PREFIX_RULE.
func (self *evsGitPublishUpdate) checkPrefix(ctx context.Context) error {
	if self.git.GetShape() == protocol.EvsGitShape_EVS_GIT_DELETE {
		return nil
	}
	if _, owned := EvsOwnedRefOwner(self.args.RefName); owned {
		return nil
	}
	if evsLocalPublishSkipPrefixHook != nil && evsLocalPublishSkipPrefixHook(self) {
		return nil
	}
	ruled, err := self.repo.prefixRuled()
	if err != nil || ruled == nil {
		return err
	}
	ask := &evsPrefixWriteAsk{
		refName: self.args.RefName, refKind: protocol.EvsRefKind_EVS_REF_SHARED, refMode: protocol.EvsRefMode_EVS_REF_GIT,
		flags: self.flags,
	}
	var walkErr error
	switch self.measure {
	case EvsGitPrefixMeasureFromJ:
		ask.drawn = self.changedFiles()
	case EvsGitPrefixMeasureFromNothing:
		// a tag's tree is read only once the engine draws a path, so a device named for every path reads nothing
		files := func(yield func(string) bool) {
			tree := self.nextTree
			if self.tagRef {
				if tree, walkErr = evsGitTreeOf(ctx, self.objects, self.peeled); walkErr != nil {
					return
				}
			}
			evsGitTreeFiles(ctx, newEvsGitCachedTrees(self.objects, self.repo.client.settings.TreeCacheByteCount), tree, &walkErr)(yield)
		}
		ask.drawn = files
	}
	err = ruled.allowWrite(ctx, self.repo, ask)
	if walkErr != nil {
		// a tree the walk could not read refuses: a check that drew short of it decided nothing
		return walkErr
	}
	var ruleErr *EvsPrefixRuleError
	if errors.As(err, &ruleErr) && ruleErr.Detail == EvsPrefixDetailRefused && ruleErr.Path != "" && self.measureEmpty != "" {
		// what the ref lacked, since the path alone would mislead (8.2.8): no shared base, or no proof
		ruleErr.Detail = self.measureEmpty
	}
	if err != nil {
		return err
	}
	return self.checkTaints(ctx)
}

// The files measured from J where J is S (8.2.5's files row): from the net change in its order, the tree reader's,
// each path that is a file in S or in N and not the same mode and oid in both, a write, a removal, an inherited file a
// held directory's table drops and a file a directory is created over among them.
func (self *evsGitPublishUpdate) changedFiles() iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, change := range self.changes {
			if change.Kind == protocol.EvsEntryKind_EVS_ENTRY_FILE || change.Stood == protocol.EvsEntryKind_EVS_ENTRY_FILE {
				if !yield(change.Path) {
					return
				}
			}
		}
	}
}

// Every file of the tree at root, each path its raw names joined by /, drawn in the tree reader's order: names sorted
// by their bytes, depth first, a tree read only as the drawing reaches it. A read that fails ends the sequence and is
// set in walkErr, which the caller must take as a refusal.
func evsGitTreeFiles(ctx context.Context, source EvsGitObjectSource, root EvsGitOid, walkErr *error) iter.Seq[string] {
	return func(yield func(string) bool) {
		var walk func(prefix string, tree EvsGitOid) bool
		walk = func(prefix string, tree EvsGitOid) bool {
			entries, err := evsGitSortedEntries(ctx, source, &tree)
			if err != nil {
				*walkErr = err
				return false
			}
			for _, entry := range entries {
				path := string(entry.Name)
				if prefix != "" {
					path = prefix + "/" + path
				}
				if entry.CanonMode == EvsGitModeDirectory {
					if !walk(path, entry.Oid) {
						return false
					}
					continue
				}
				if !yield(path) {
					return false
				}
			}
			return true
		}
		walk("", root)
	}
}

// The re-creating push's tainted token paths (8.5) against this sidecar's prefixes in the push's epoch at the
// installed state, on the token paths themselves, since this device may hold no name for one: EVS_PREFIX_RULE with
// no path to name where one lies outside. Every taint is asked, a last-removed one the new tree lacks included, which
// the push states nothing at: a held device refuses some re-creations every reader would take, and never sends one
// they refuse.
func (self *evsGitPublishUpdate) checkTaints(ctx context.Context) error {
	if len(self.tainted) == 0 {
		return nil
	}
	state, err := self.repo.client.verifier.config()
	if err != nil {
		return err
	}
	identity := self.repo.client.args.Identity()
	line, err := self.repo.gitPrefixLine(ctx, self.refId, &EvsStatement{Push: &protocol.EvsPush{
		SignerSidecarId: identity.SidecarId.Bytes(), Auth: state.Pin(), RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED),
		RefMode: uint32(protocol.EvsRefMode_EVS_REF_GIT), Flags: self.flags, PathEpoch: self.tainted[0].Epoch,
	}})
	switch {
	case err != nil:
		return err
	case line.waits() && line.Verdict.Outcome == AclPrefixUpdate:
		return &EvsPrefixRuleError{Detail: EvsPrefixDetailUpdate}
	case line.waits():
		return &EvsPrefixRuleError{Detail: EvsPrefixDetailPending}
	case !line.judges():
		return nil
	}
	for _, taint := range self.tainted {
		tokenPath, err := parseEvsTokenPathKey(taint.Key)
		if err != nil {
			return fmt.Errorf("%w: a tainted token path that does not parse", ErrEvsGitUpdateInvalid)
		}
		if !line.under(tokenPath) {
			return &EvsPrefixRuleError{Detail: EvsPrefixDetailRefused}
		}
	}
	return nil
}

// A test's hook on an update once its carried set and net change are fixed, before any attempt: what a test breaks a
// rule of 8.2.7's check with, to see replaying readers refuse it. Nil outside tests.
var evsLocalPublishUpdateHook func(update *evsGitPublishUpdate)

// Marks each file write whose chain another ref's standing entry may serve (8.2.4's reuse row): a source whose tip's
// tree holds the new blob at the path, cited whole; else, on an overlay, the base, whose entry of the blob that stood
// the write's diff applies to where the overlay holds no version of the path. The plan reads each entry and plans a
// checkpoint where it holds another blob.
func (self *evsGitPublishUpdate) markReuses(ctx context.Context) error {
	type sourceTree struct {
		refId Id
		tree  EvsGitOid
	}
	trees := []*sourceTree{}
	for _, source := range self.carried.sources {
		peeled, _, err := evsGitPeel(ctx, self.objects, source.Tip)
		if err != nil {
			return err
		}
		tree, err := evsGitTreeOf(ctx, self.objects, peeled)
		if err != nil {
			return err
		}
		trees = append(trees, &sourceTree{refId: source.RefId, tree: tree})
	}
	var baseRefId *Id
	if self.base != nil {
		refId, err := IdFromBytes(self.base.GetRefId())
		if err != nil {
			return fmt.Errorf("%w: an overlay base's ref id", ErrEvsWriteInvalid)
		}
		baseRefId = &refId
	}
	cached := newEvsGitCachedTrees(self.objects, self.repo.client.settings.TreeCacheByteCount)
	for _, change := range self.changes {
		if change.Kind != protocol.EvsEntryKind_EVS_ENTRY_FILE || change.Mode == EvsGitModeGitlink {
			continue
		}
		names, err := evsPathNames(change.Path)
		if err != nil {
			return err
		}
		for _, source := range trees {
			entry, found, err := evsGitFileAt(ctx, cached, source.tree, names)
			if err != nil {
				return err
			}
			if found && entry.Oid == change.Oid {
				refId := source.refId
				change.ReuseRefId, change.ReuseWhole = &refId, true
				break
			}
		}
		if change.ReuseRefId == nil && baseRefId != nil && change.Stood == protocol.EvsEntryKind_EVS_ENTRY_FILE {
			change.ReuseRefId = baseRefId
		}
	}
	return nil
}

// A branch update's new tree, read by the tree reader through source: what its plan names a tainted token path in
// (EvsGitTreeEntries).
type evsGitPublishTree struct {
	source EvsGitObjectSource
	root   EvsGitOid
}

// See EvsGitTreeEntries.
func (self *evsGitPublishTree) EntriesAt(ctx context.Context, path string) ([]EvsGitRawEntry, bool, error) {
	at := self.root
	if path != "" {
		names, err := evsPathNames(path)
		if err != nil {
			return nil, false, err
		}
		for _, name := range names {
			entries, err := evsGitSortedEntries(ctx, self.source, &at)
			if err != nil {
				return nil, false, err
			}
			index, found := slices.BinarySearchFunc(entries, name, func(entry EvsGitRawEntry, name []byte) int { return bytes.Compare(entry.Name, name) })
			if !found || entries[index].CanonMode != EvsGitModeDirectory {
				return nil, false, nil
			}
			at = entries[index].Oid
		}
	}
	entries, err := evsGitSortedEntries(ctx, self.source, &at)
	if err != nil {
		return nil, false, err
	}
	return entries, true, nil
}

// One attempt on base version baseVersion: steps 3 to 6 of the file header, under a fresh generation and push ids.
func (self *evsGitPublishUpdate) publishOnce(ctx context.Context, baseVersion uint64, rebuilds *int) (*EvsLocalPublishResult, error) {
	repo := self.repo
	// step 3's prefix check, at the state whose pin this attempt's statement carries, before anything is planned
	if err := self.checkPrefix(ctx); err != nil {
		return nil, err
	}
	repoKey, err := repo.client.args.Gkm.EnsureWritable(ctx, repo.repoId)
	if err != nil {
		return nil, err
	}
	if repo.client.epochs.noteWritable(repo.repoId, repoKey.Generation()) {
		repo.client.NoteGeneration(repo.repoId)
	}
	git := proto.Clone(self.git).(*protocol.EvsGitUpdate)
	planArgs := &EvsGitPlanArgs{
		RefName: self.args.RefName, RefId: self.refId, Update: git, Changes: self.changes, BaseVersion: baseVersion,
		Base: self.base, Blobs: self.objects, Generation: repoKey.Generation(),
		RunTainted: self.args.RunTainted, AgentId: self.args.AgentId,
	}
	if 0 < len(self.tainted) {
		planArgs.Tainted = self.tainted
		planArgs.NextTree = &evsGitPublishTree{
			source: newEvsGitCachedTrees(self.objects, repo.client.settings.TreeCacheByteCount), root: self.nextTree,
		}
	}
	plan, err := repo.PlanGitUpdate(ctx, planArgs)
	if err != nil {
		return nil, err
	}
	defer plan.closeContents()
	plan.Flags = self.flags
	if self.flags&(uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)|uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)) != 0 &&
		plan.RefKind == protocol.EvsRefKind_EVS_REF_SHARED {
		// FORCE and DELETE on a shared ref take admin (§11.8's refs table), which the push's token must carry; evs
		// answers SCOPE to an admin's push at rw (found by EVS1-M2-43's conformance run against evsservice)
		plan.scope = evsScopeAdmin
	}
	plan.gitExtras = &evsGitPushExtras{commits: self.commits, creating: self.creating}
	if self.creating {
		// payload sections 15 and 16, the first after a DELETE's as a new ref's, repeating the head's base (8.2.2's
		// sections row)
		plan.gitExtras.refName, plan.gitExtras.base = self.args.RefName, self.base
	}
	sealed, err := repo.client.sealWrite(ctx, plan, repoKey)
	if err != nil {
		return nil, err
	}
	defer sealed.Close()
	historyCount, err := self.sealHistory(ctx, plan, sealed, repoKey)
	if err != nil {
		return nil, err
	}
	if self.args.Import && 0 < len(self.commits) {
		// an import push that carries no commit, its tip held through its sources, signs nothing: an EvsImport
		// covers a push's own commits and none
		signedImport, err := self.signImport(git)
		if err != nil {
			return nil, err
		}
		plan.gitExtras.signedImport = signedImport
	}
	var beforePost func(attempt *evsPushAttempt) error
	if onAttempt := self.args.OnAttempt; onAttempt != nil {
		beforePost = func(attempt *evsPushAttempt) error {
			push := attempt.built.Statement.Push
			baseChain, _ := EvsChainFromBytes(push.GetBaseChain())
			if push.GetBaseVersion() == 0 {
				baseChain = EvsChainStart(repo.repoId, self.refId)
			}
			return onAttempt(&EvsGitPublishAttempt{
				PushId: attempt.pushId, StatementSha256: attempt.built.Statement.Sha256, BaseVersion: push.GetBaseVersion(),
				BaseChain: baseChain, Old: self.args.Old, New: self.args.New, TimeMs: push.GetTimeMs(),
				Parts: 0 < push.GetPartCount(),
			})
		}
	}
	pushId, reply, err := repo.sendSealedNoting(ctx, sealed, rebuilds, func(pushId Id) { self.pushIds[pushId] = true }, beforePost)
	if err != nil {
		return nil, err
	}
	return &EvsLocalPublishResult{
		PushId: pushId, Version: reply.GetVersion(), Shape: git.GetShape(), Flags: self.flags, Commits: self.commitOids,
		Sources: git.GetSources(), Base: self.base, HistoryBlobCount: historyCount,
	}, nil
}

// An import push's EvsImport (DESIGN-DETAILS 8.2.6, QD-603): the push's new tip, the SHA-256 over its carried commit
// oids in carried order and their count, for this ref, signed by this sidecar's identity key under evs-import.
func (self *evsGitPublishUpdate) signImport(git *protocol.EvsGitUpdate) ([]byte, error) {
	oidList := []byte{}
	for _, oid := range self.commitOids {
		oidList = append(oidList, oid[:]...)
	}
	listDigest := sha256.Sum256(oidList)
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.EvsImport{
		RepoId: self.repo.repoId.Bytes(), RefId: self.refId.Bytes(), TipOid: git.GetNewTip(), OidListSha256: listDigest[:],
		Count: uint32(len(self.commitOids)),
	})
	if err != nil {
		return nil, err
	}
	signed, err := self.repo.client.args.Sign(evsImportPurpose, bridge.SignedType_SIGNED_EVS_IMPORT, body, nil)
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// Judges a head past the update's base by the versions between, walked from the base's chain (8.2.5's 409 row):
// committed when one is a push this update sent, commitless when each is a PATH_EPOCH, a REKEY or a pin push, which
// move no tip.
func (self *evsGitPublishUpdate) judgeMoved(ctx context.Context, moved *EvsGitHeadMovedError, chain [sha256.Size]byte) (*EvsLocalPublishResult, bool, error) {
	repo := self.repo
	head := moved.Head
	if head.Version <= moved.BaseVersion {
		return nil, false, nil
	}
	statements, err := repo.client.readLog(ctx, repo.repoId, self.refId, moved.BaseVersion+1, head.Version)
	if err != nil {
		return nil, false, err
	}
	walked, err := repo.client.verifier.walk(ctx, repo.repoId, self.refId, moved.BaseVersion, chain, statements, head.Version)
	if err != nil {
		return nil, false, err
	}
	keys := newEvsReadKeys(repo)
	commitless := true
	for _, statement := range walked {
		push := statement.Statement.Push
		if self.pushIds[Id(push.GetPushId())] {
			return &EvsLocalPublishResult{
				PushId: Id(push.GetPushId()), Version: statement.Version, Shape: self.git.GetShape(), Flags: self.flags,
				Commits: self.commitOids, Sources: self.git.GetSources(), Base: self.base,
			}, false, nil
		}
		switch {
		case push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0:
		case push.GetFlags() == 0:
			// an UPDATE or a REKEY, which its sealed update tells apart
			moves, err := self.movesTip(ctx, keys, head, statement)
			if err != nil {
				return nil, false, err
			}
			commitless = commitless && !moves
		default:
			commitless = false
		}
	}
	return nil, commitless, nil
}

// Whether a version moves its ref's tip, by its push record's sealed update: a REKEY moves none, and neither does a pin
// push, the UPDATE of one tip whose old and new tips are one oid and which carries no commit, tag, source or blob
// (8.2.10); every other update does.
func (self *evsGitPublishUpdate) movesTip(ctx context.Context, keys *evsReadKeys, head *EvsVerifiedHead, statement *EvsVerifiedStatement) (bool, error) {
	payload, err := self.repo.pushContent(ctx, head, statement)
	if err != nil {
		return false, err
	}
	manifest, err := keys.manifest(ctx, statement.Statement.Push.GetGeneration())
	if err != nil {
		return false, err
	}
	metadata, err := EvsOpenMetadata(manifest, payload.SealedMetadata)
	if err != nil {
		return false, err
	}
	git := metadata.GetGit()
	switch git.GetShape() {
	case protocol.EvsGitShape_EVS_GIT_REKEY:
		return false, nil
	case protocol.EvsGitShape_EVS_GIT_UPDATE:
		pinPush := len(git.GetOldTip()) != 0 && bytes.Equal(git.GetOldTip(), git.GetNewTip()) && len(metadata.GetCommits()) == 0 &&
			len(git.GetTags()) == 0 && len(git.GetSources()) == 0 && len(git.GetBlobs()) == 0
		return !pinPush, nil
	}
	return true, nil
}

// Step 4 of the file header: the history blobs sealed into history segments of the push, appended to the sealed
// write's segments so they upload with its own, and the update's segment_ids and blobs set. Answers how many it
// sealed.
func (self *evsGitPublishUpdate) sealHistory(ctx context.Context, plan *EvsWritePlan, sealed *EvsSealedWrite, repoKey *EvsRepoKey) (int, error) {
	git := plan.gitUpdate
	if len(self.commits) == 0 {
		return 0, nil
	}
	// the blobs the push's entries carry: the new blobs of its net-changed files
	entryBlobs := map[EvsGitOid]bool{}
	for _, change := range self.changes {
		if change.Kind == protocol.EvsEntryKind_EVS_ENTRY_FILE && change.Mode != EvsGitModeGitlink {
			entryBlobs[change.Oid] = true
		}
	}
	manifest, err := NewEvsManifestKey(repoKey)
	if err != nil {
		return 0, err
	}
	fek, err := NewEvsFekKey(repoKey)
	if err != nil {
		return 0, err
	}
	client := self.repo.client
	writer := &evsHistoryWriter{store: client.args.Store, memoryLimit: client.settings.DeltaBaseMemoryByteCount, manifest: manifest, fek: fek, generation: repoKey.Generation()}
	defer writer.close()
	placed := map[EvsGitOid]bool{}
	for i, sealedCommit := range self.commits {
		var parentTree *EvsGitOid
		_, parentOids, err := EvsGitCommitGraph(sealedCommit.GetObject())
		if err != nil {
			return 0, fmt.Errorf("commit %x: %w", self.commitOids[i][:], err)
		}
		if 0 < len(parentOids) {
			tree, err := evsGitTreeOf(ctx, self.objects, parentOids[0])
			if err != nil {
				return 0, err
			}
			parentTree = &tree
		}
		for _, change := range sealedCommit.GetChanges() {
			if len(change.GetGitOid()) == 0 || change.GetMode() == EvsGitModeGitlink {
				continue
			}
			oid := EvsGitOid(change.GetGitOid())
			if placed[oid] || !self.carried.blobs[oid] {
				continue
			}
			placed[oid] = true
			if entryBlobs[oid] {
				// its entry carries it
				continue
			}
			var base *EvsGitRawEntry
			if parentTree != nil {
				entry, found, err := evsGitFileAt(ctx, self.objects, *parentTree, change.GetPath())
				if err != nil {
					return 0, err
				}
				if found && entry.CanonMode != EvsGitModeGitlink {
					base = &entry
				}
			}
			blob, err := writer.add(ctx, self.objects, oid, base, client.settings.DiffMaxByteCount)
			if err != nil {
				return 0, err
			}
			git.Blobs = append(git.Blobs, blob)
		}
	}
	segments, err := writer.finish()
	if err != nil {
		return 0, err
	}
	for _, segment := range segments {
		git.SegmentIds = append(git.SegmentIds, bytes.Clone(segment.Id[:]))
		sealed.Segments = append(sealed.Segments, segment)
	}
	writer.segments = nil
	return len(git.Blobs), nil
}

// History records (DESIGN-DETAILS 8.2.3) sealed into segments as they come: each blob one record, a diff on a base,
// a checkpoint, or chunks past 8 MiB, each record under the blob's own fresh file_id, a segment finished when the next
// record would pass 8 MiB.
type evsHistoryWriter struct {
	store       SidecarStore
	memoryLimit int64
	manifest    *EvsManifestKey
	fek         *EvsFekKey
	generation  uint64

	segments []*EvsSealedSegment
	builder  *EvsSegmentBuilder
	length   uint64
	// the open segment's records, in order, each a locator to fill at its finish
	open []*protocol.EvsHistoryLocator
}

// Seals oid's blob as one history blob: a diff on base's blob where both are at most diffMax and the delta is
// smaller, else a checkpoint, or chunks past 8 MiB.
func (self *evsHistoryWriter) add(ctx context.Context, source EvsGitBlobSource, oid EvsGitOid, base *EvsGitRawEntry, diffMax int64) (*protocol.EvsSealedBlob, error) {
	content := newEvsSpill(self.store, self.memoryLimit)
	defer content.close()
	size, err := source.CopyBlob(ctx, oid, content)
	if err != nil {
		return nil, err
	}
	fileId := NewEvsSlotId()
	blob := &protocol.EvsSealedBlob{GitOid: bytes.Clone(oid[:]), Size: uint64(size), FileId: fileId.Bytes()}
	if base != nil && size <= diffMax {
		baseContent := newEvsSpill(self.store, self.memoryLimit)
		defer baseContent.close()
		baseSize, err := source.CopyBlob(ctx, base.Oid, baseContent)
		if err != nil {
			return nil, err
		}
		if baseSize <= diffMax {
			delta := &evsBoundedBuffer{limit: int(size)}
			err := EvsGitDeltaEncode(baseContent, content, delta, DefaultEvsGitDeltaSettings())
			switch {
			case errors.Is(err, errEvsBoundedBufferFull):
			case err != nil:
				return nil, err
			case delta.Len() < int(size):
				locator, err := self.record(fileId, oid, protocol.EvsRecordKind_EVS_RECORD_DIFF, bytes.NewReader(delta.Bytes()), int64(delta.Len()))
				if err != nil {
					return nil, err
				}
				blob.BaseOid = bytes.Clone(base.Oid[:])
				blob.Records = []*protocol.EvsHistoryLocator{locator}
				return blob, nil
			}
		}
	}
	if !EvsChunked(uint64(size)) {
		locator, err := self.record(fileId, oid, protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, io.NewSectionReader(content, 0, size), size)
		if err != nil {
			return nil, err
		}
		blob.Records = []*protocol.EvsHistoryLocator{locator}
		return blob, nil
	}
	chunks, err := EvsPlanChunks(content, nil, nil, true)
	if err != nil {
		return nil, err
	}
	for _, chunk := range chunks {
		locator, err := self.record(fileId, oid, protocol.EvsRecordKind_EVS_RECORD_CHUNK, io.NewSectionReader(content, chunk.Offset, chunk.Length), chunk.Length)
		if err != nil {
			return nil, err
		}
		blob.Records = append(blob.Records, locator)
	}
	return blob, nil
}

// Appends one record of body's length bytes to the open history segment, a new one begun when it would pass 8 MiB.
func (self *evsHistoryWriter) record(fileId Id, oid EvsGitOid, kind protocol.EvsRecordKind, body io.Reader, length int64) (*protocol.EvsHistoryLocator, error) {
	recordLength := EvsRecordByteCount(uint64(length))
	if self.builder != nil && EvsSegmentMaxByteCount < self.length+recordLength {
		if err := self.finishOpen(); err != nil {
			return nil, err
		}
	}
	if self.builder == nil {
		spill := newEvsSpill(self.store, self.memoryLimit)
		self.segments = append(self.segments, &EvsSealedSegment{content: spill})
		builder, err := NewEvsSegmentBuilder(spill, self.manifest, self.fek)
		if err != nil {
			return nil, err
		}
		self.builder, self.length, self.open = builder, evsSegmentKeyedRecordsOffset, nil
	}
	header := &EvsRecordHeader{
		RecordId: NewEvsSlotId(), Generation: self.generation, BodyLength: uint64(length), Kind: kind,
		KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER, OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
	}
	copy(header.Oid[:], oid[:])
	writer, err := self.builder.BeginRecord(fileId, header)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(writer, body); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	self.length += recordLength
	locator := &protocol.EvsHistoryLocator{Segment: uint32(len(self.segments) - 1)}
	self.open = append(self.open, locator)
	return locator, nil
}

// Finishes the open segment: its id and padded size, and each of its records' offset and length.
func (self *evsHistoryWriter) finishOpen() error {
	summary, err := self.builder.Finish()
	if err != nil {
		return err
	}
	segment := self.segments[len(self.segments)-1]
	segment.Id, segment.PaddedSize = summary.Id, summary.PaddedSize
	for i, locator := range self.open {
		locator.Offset, locator.Length = summary.Places[i].Offset, summary.Places[i].Length
	}
	self.builder, self.open = nil, nil
	return nil
}

// Finishes the open segment and answers every segment, in order.
func (self *evsHistoryWriter) finish() ([]*EvsSealedSegment, error) {
	if self.builder != nil {
		if err := self.finishOpen(); err != nil {
			return nil, err
		}
	}
	return self.segments, nil
}

// Drops the segments' spills that no sealed write took.
func (self *evsHistoryWriter) close() {
	for _, segment := range self.segments {
		if segment.content != nil {
			segment.content.close()
		}
	}
}
