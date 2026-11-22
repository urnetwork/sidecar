//go:build !ios_extension

// One git-mode version's check (DESIGN-DETAILS 8.2.7's check(u)), which export and the local tier's sync engine both
// run on every version they apply: the part that needs no repository. The shape against the push's flags and the
// ref's kind; a creating push's sealed ref name against its section 15 and the ref's id, and its base against section
// 16 and the head's, and neither on any other push; old_tip; the sources' shape; each carried commit's oid, its
// parents held or carried before it, and either the push's own EvsImport over exactly its commits or the rule a new
// commit is held to (canonical bytes, a strict committer whom the resolver takes, canonical trees); the tags chaining
// down to a commit; the new tip peeling to a commit held or carried that every carried commit is an ancestor of;
// descent unless FORCE; the history blobs' shape.
//
// Each source is replayed through the caller's ReplaySources once the sources' shape passes, before the commits are
// judged. What needs the objects or the path state is the caller's, after this passes: each commit's tree through
// EvsGitTreeBuilder held to the tree its commit names, each blob opened and its oid checked, a REKEY's entries held to
// the modes and oids of the tree they re-checkpoint, and on a branch the push's changes held to the net change between
// the trees with its tainted token paths (G4).
// A refusal is ErrEvsGitUpdateRefused naming the line, never the bytes; a replaying reader alarms version_rule and
// stops the ref at the version before (8.5).
//
// The prefix line (DESIGN-DETAILS 8.2.7's every-shape row, 16.2.6; QD-793, QD-801), under a general repo's prefix
// write rules, is judged in three places, in one order on every reader:
//
//	the set    16.2.4's lines 1 to 3 at u's pin and signer (EvsGitPrefixLine, gitPrefixLine through the client's
//	           judge), found from the pin and the device's own state before u's record is read: a set pending or
//	           newer is a wait, which the caller takes as the replay's end before u, with no alarm
//	early      after the shape checks and before a commit is read: every change of u that writes a file entry, by
//	           its token path, so the plain breach costs no object work
//	proof      a tag ref's UPDATE, with the tags row once its sources are replayed: one of u's sources (r', v') whose
//	           ref is a shared branch, by that ref's own history, and whose tip at v' is the commit new_tip peels to,
//	           by the tips log, is its proof, and no file is judged; never a lookup in the reader's own tip index
//	late       EvsGitCheckPrefixTrees, the caller's once J and N stand (with the changes row on a branch, after the
//	           tags row on a tag ref): every path that is a file in J or in N and not the same mode and oid in both,
//	           or, measured from nothing, every file of N in the tree reader's order, a directory under a prefix
//	           passed whole; then every tainted token path u writes or removes, on the token path itself
//
// J is S on every push but the one that gives a branch its first tip, which no version this reader applied had: there
// it is S where the branch's base is a shared branch, else the empty tree. A tag with no proof is measured from
// nothing too. A signer the set names for every path is passed before any tree is read, and directory changes are not
// judged: a ref's directories follow from its files. A refusal is an *EvsGitPrefixRefusal, which wraps both
// ErrEvsGitUpdateRefused and ErrEvsGitPrefixRule, so the reader alarms prefix_rule in place of version_rule; its
// error never names the path, which goes only to the event (I-13).
//
// On every leg but the forwarding role's. Package-level functions are safe for concurrent use as the arguments'
// functions are.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A git-mode version that breaks check(u): what a replaying reader alarms on and stops the ref before.
var ErrEvsGitUpdateRefused = errors.New("evs: a git-mode version that does not check")

var (
	// A git-mode version the repo's prefix rules refuse (DESIGN-DETAILS 8.2.7's prefix line, 16.2.6; QD-793): check(u)
	// fails with reason prefix_rule. Always an *EvsGitPrefixRefusal, which wraps ErrEvsGitUpdateRefused too.
	ErrEvsGitPrefixRule = errors.New("evs: a git-mode version the repo's prefix rules refuse")
	// A git-mode version whose rule set at its pin this reader holds pending, or of a later release: the replay waits
	// before it with no alarm (8.2.7's waiting u), and goes on once the config state or the release moves.
	ErrEvsGitPrefixWait = errors.New("evs: a git-mode version the reader cannot judge under the repo's prefix rules yet")
)

// Which test of the prefix line found a file outside the signer's prefixes: what a refusal says, never the path.
type EvsGitPrefixRow string

const (
	// The early test: a file entry the push writes, by its token path, before a commit is read.
	EvsGitPrefixRowWritten EvsGitPrefixRow = "written"
	// The late test: a file that differs between J and N.
	EvsGitPrefixRowChanged EvsGitPrefixRow = "changed"
	// The late test from nothing: a file of N where J is the empty tree, a new branch's with no shared base or a
	// tag's with no proof (QD-801).
	EvsGitPrefixRowFromNothing EvsGitPrefixRow = "from_nothing"
	// A tainted token path the push writes or removes (8.5), judged as a file's on the token path itself.
	EvsGitPrefixRowTainted EvsGitPrefixRow = "tainted"
)

// The prefix line's refusal of a version: the first file found outside its signer's prefixes, which the reader's
// alarm carries where it holds the file's name. Its error names the row and never the path (I-13).
type EvsGitPrefixRefusal struct {
	Row EvsGitPrefixRow
	// The file's raw names joined by /, empty where this reader holds no name for it: a written entry the early test
	// refused before any tree was read, or a tainted token path.
	Path string
}

// The refusal's row, never its path.
func (self *EvsGitPrefixRefusal) Error() string {
	return fmt.Sprintf("%s: prefix_rule (%s)", ErrEvsGitUpdateRefused, self.Row)
}

// ErrEvsGitUpdateRefused, so a replaying reader stops the ref, and ErrEvsGitPrefixRule, so it alarms prefix_rule.
func (self *EvsGitPrefixRefusal) Unwrap() []error {
	return []error{ErrEvsGitUpdateRefused, ErrEvsGitPrefixRule}
}

// The prefix line of one push (DESIGN-DETAILS 8.2.7, 16.2.4's lines 1 to 3 at u's pin and signer), as a reader's judge
// gives it, so export and the sync engine judge alike. Immutable once made.
type EvsGitPrefixLine struct {
	// Lines 1 and 2: allowed with reason scope or no_set where nothing is judged, wait or update where a set at u's
	// pin is pending or newer, else allowed with reason no_change and the set in force's position.
	Verdict AclPrefixVerdict
	// Line 3's A in u's path epoch: the token paths of the set's rules that name the signer.
	Prefixes []EvsTokenPath
	// K_path of u's path epoch, which the late test names a tree's paths in; nil where nothing is judged.
	PathKey *EvsPathKey
}

// Whether the line waits: a set at u's pin pending, or of a later release.
func (self *EvsGitPrefixLine) waits() bool {
	return self != nil && (self.Verdict.Outcome == AclPrefixWait || self.Verdict.Outcome == AclPrefixUpdate)
}

// Whether the line judges files: a set in force at u's pin that does not name the signer for every path.
func (self *EvsGitPrefixLine) judges() bool {
	return self != nil && self.Verdict.Outcome == AclPrefixAllowed && self.Verdict.Reason == AclPrefixReasonNoChange && !self.whole()
}

// Whether the set names the signer for every path: a rule of no path, whose token path is empty in every epoch.
func (self *EvsGitPrefixLine) whole() bool {
	for _, prefix := range self.Prefixes {
		if len(prefix) == 0 {
			return true
		}
	}
	return false
}

// 16.2.4's under(T): a file at the token path lies under a prefix the set gives the signer.
func (self *EvsGitPrefixLine) under(tokenPath EvsTokenPath) bool {
	return AclPrefixUnder(self.Prefixes, tokenPath)
}

// What the late test of the prefix line measures (DESIGN-DETAILS 8.2.7; QD-801).
type EvsGitPrefixMeasure int

const (
	// Nothing: no set in force, the push outside the rules, a signer named for every path, a REKEY or a DELETE, or a
	// tag whose push names its proof.
	EvsGitPrefixMeasureNone EvsGitPrefixMeasure = iota
	// Every file that differs between J, which is S, and N.
	EvsGitPrefixMeasureFromJ
	// Every file of N, J the empty tree: a branch's first tip over no shared branch, or a tag with no proof.
	EvsGitPrefixMeasureFromNothing
)

// The sources a push may name (DESIGN-DETAILS 8.2.3): a format bound.
const EvsGitMaxSourceCount = 16

// The ref name prefix of a tag ref, which holds no path state (8.2.4).
const evsGitTagRefPrefix = "refs/tags/"

// What one git-mode version is checked against.
type EvsGitUpdateArgs struct {
	RepoId Id
	RefId  Id
	// The ref's name bytes: a tag ref's begin refs/tags/.
	RefName []byte
	// The statement, its payload as the checks row took it, and its sealed metadata opened.
	Statement *EvsStatement
	Payload   *EvsCheckedPayload
	Metadata  *protocol.EvsSealedMetadata
	// The ref's tip before this version: nil for none, never created or deleted.
	PriorTip *EvsGitOid
	// Whether this version creates the ref: no tip before it, the ref never created or deleted. Only an UPDATE creates.
	Creating bool
	// A creating version's payload section 15 opened under manifest_g, the name evs copies into the head; nil when
	// the push carries none.
	SectionRefName []byte
	// The ref id a name gives, EvsRefId under K_ref: a creating push's sealed name must give the ref's own. Nil
	// refuses every creating push.
	RefIdOf func(refName []byte) (Id, error)
	// The head's base, which every creating push of the ref repeats (8.2.2's sections row): nil for none.
	HeadBase *protocol.EvsOverlay
	// Replays each source to the version it names, so what its tip reaches is held before the commits are judged
	// (8.2.7's "replay(r', v') first"): asked once the sources' shape passes. An error refusing the version wraps
	// ErrEvsGitUpdateRefused; nil asks nothing, for a caller that holds every source already.
	ReplaySources func(ctx context.Context, sources []*protocol.EvsOverlay) error
	// Whether the reader holds the object already, from earlier versions of any ref.
	Held func(oid EvsGitOid) bool
	// owner decision 81's rule for a new commit's committer, the push its carrier: SidecarCommitter's check. Nil
	// refuses every new commit.
	Committer func(ctx context.Context, committer *EvsGitIdent, push *protocol.EvsPush) error
	// A signed_import's check: its signature, and its signer a repo admin at the push's authorization pin; the
	// EvsImport it signs. Nil refuses every import.
	Import func(ctx context.Context, signed []byte, push *protocol.EvsPush) (*protocol.EvsImport, error)
	// A held commit's parents, ErrEvsGitObjectMissing for a commit not held: what descent walks past the carried
	// commits. Asked only of a version that moves a tip without FORCE.
	Parents func(ctx context.Context, oid EvsGitOid) ([]EvsGitOid, error)
	// The prefix line (see the file header): nil where the repo's rows hold no rule set, which judges nothing. A
	// waiting line is answered ErrEvsGitPrefixWait, which a caller acts on before it reads u's record.
	Prefix *EvsGitPrefixLine
	// Whether the ref held a tip in a version this reader applied: E, or the tip before its DELETE. A push that gives a
	// branch its first tip is measured from J (QD-801).
	HeldTip bool
	// Whether a ref is a shared branch by its own history: a git-mode ref whose pushes carry the kind shared and whose
	// name, from its creating push's sealed copy, is no tag's. Nil takes none for one.
	SharedBranch func(ctx context.Context, refId Id) (bool, error)
	// The tip a source held at the version it names, by this reader's tips log once ReplaySources replayed it: nil
	// where none stands (a version its replay skipped, before it had a tip, after its DELETE). Nil holds none.
	SourceTip func(ctx context.Context, source *protocol.EvsOverlay) (*EvsGitOid, error)
	// A test's stand-in for the proof test, which looks the tagged commit up some other way than by the sources u
	// names; nil outside tests (evsLocalSyncProofHook).
	ProofOf func(ctx context.Context, peeled EvsGitOid) (bool, error)
}

// One commit a version carries, as the check read it.
type EvsGitCarriedCommit struct {
	Oid        EvsGitOid
	TreeOid    EvsGitOid
	ParentOids []EvsGitOid
	Sealed     *protocol.EvsSealedCommit
	// The reader held it already, two refs having pushed it at once: judged the same, written once.
	Held bool
}

// What a version that checks does to its ref.
type EvsGitCheckedUpdate struct {
	Shape protocol.EvsGitShape
	// The tip after: the commit or outermost tag, nil for a DELETE, the tip before for a REKEY.
	NewTip *EvsGitOid
	// The commit the tip peels to, nil for none.
	Peeled *EvsGitOid
	// The tag objects, outermost first, each with its oid.
	Tags    [][]byte
	TagOids []EvsGitOid
	Commits []*EvsGitCarriedCommit
	// Every carried commit is an EvsImport's, held to no committer rule and with raw trees allowed.
	Imported bool
	// What the prefix line's late test measures, which the caller runs through EvsGitCheckPrefixTrees once J and N
	// stand, and a tag's proof, nil for none.
	PrefixMeasure EvsGitPrefixMeasure
	PrefixProof   *protocol.EvsOverlay
}

// See the file header.
func EvsGitCheckUpdate(ctx context.Context, args *EvsGitUpdateArgs) (*EvsGitCheckedUpdate, error) {
	refused := func(format string, values ...any) error {
		return fmt.Errorf("%w: %s", ErrEvsGitUpdateRefused, fmt.Sprintf(format, values...))
	}
	push := args.Statement.Push
	flags := push.GetFlags()
	git := args.Metadata.GetGit()
	if flags&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		if git != nil || len(args.Metadata.GetCommits()) != 0 {
			return nil, refused("a PATH_EPOCH with an update")
		}
		return &EvsGitCheckedUpdate{Shape: protocol.EvsGitShape_EVS_GIT_SHAPE_UNSPECIFIED, NewTip: args.PriorTip}, nil
	}
	if git == nil {
		return nil, refused("no update")
	}
	if args.Prefix.waits() {
		// the set at u's pin is found before anything else is judged: a wait is no refusal
		return nil, ErrEvsGitPrefixWait
	}
	// the prefix line's early test: every file entry u writes, by its token path, before a commit is read
	early := func() error {
		if !args.Prefix.judges() {
			return nil
		}
		for _, change := range args.Payload.Changes {
			if change.WritesEntry() && !evsEntryVersionIsDirectory(change.EntryVersion) && !args.Prefix.under(change.TokenPath) {
				return &EvsGitPrefixRefusal{Row: EvsGitPrefixRowWritten}
			}
		}
		return nil
	}
	tagRef := bytes.HasPrefix(args.RefName, []byte(evsGitTagRefPrefix))
	// a creating push's sections, which only it carries: its sealed name its section 15's and the ref's own, its base
	// its section 16's and the head's
	creating := args.Creating && git.GetShape() == protocol.EvsGitShape_EVS_GIT_UPDATE
	if creating {
		refName := args.Metadata.GetRefName()
		if len(refName) == 0 || !bytes.Equal(refName, args.SectionRefName) {
			return nil, refused("a creating push whose sealed ref name is not its section 15's")
		}
		if args.RefIdOf == nil {
			return nil, refused("a creating push no ref id check takes")
		}
		if refId, err := args.RefIdOf(refName); err != nil || refId != args.RefId {
			return nil, refused("a creating push whose ref name is another ref's")
		}
		if !evsOverlayEqual(args.Metadata.GetBase(), args.Payload.Base) || !evsOverlayEqual(args.Metadata.GetBase(), args.HeadBase) {
			return nil, refused("a creating push whose base is not its section 16's and the head's")
		}
		tagRef = bytes.HasPrefix(refName, []byte(evsGitTagRefPrefix))
	} else if len(args.Metadata.GetRefName()) != 0 || args.Metadata.GetBase() != nil {
		return nil, refused("a ref name or base on a push that does not create its ref")
	}
	if tagRef && args.Metadata.GetBase() != nil {
		return nil, refused("a tag ref with a base")
	}
	for _, blob := range git.GetBlobs() {
		if err := checkEvsSealedBlob(blob, git, args.Payload); err != nil {
			return nil, err
		}
	}
	const (
		forceFlag     = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
		deleteFlag    = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
		immutableFlag = uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)
	)
	commits := args.Metadata.GetCommits()
	nothingCarried := len(commits) == 0 && len(git.GetTags()) == 0 && len(git.GetSources()) == 0 && len(git.GetBlobs()) == 0 &&
		len(args.Metadata.GetSignedImport()) == 0
	switch git.GetShape() {
	case protocol.EvsGitShape_EVS_GIT_DELETE:
		// old_tip is not held to the tip: a stopped ref's deleter does not hold it (8.5)
		if flags != deleteFlag || !nothingCarried || len(args.Payload.Changes) != 0 || len(git.GetNewTip()) != 0 {
			return nil, refused("a DELETE that is not flag DELETE alone with nothing carried")
		}
		return &EvsGitCheckedUpdate{Shape: protocol.EvsGitShape_EVS_GIT_DELETE}, nil
	case protocol.EvsGitShape_EVS_GIT_REKEY:
		if flags != 0 || !nothingCarried || len(git.GetOldTip()) != 0 || len(git.GetNewTip()) != 0 || tagRef || args.PriorTip == nil {
			return nil, refused("a REKEY with a flag, a tip or anything carried, or on a tag or a ref with no tip")
		}
		for _, change := range args.Payload.Changes {
			if !change.WritesEntry() || change.Change.GetBaseEntryVersion() == 0 || evsEntryVersionIsDirectory(change.EntryVersion) {
				return nil, refused("a REKEY change that is no file's re-checkpoint")
			}
		}
		// a writer re-checkpoints only under its prefixes (16.2.4): every entry is a file's, judged early
		if err := early(); err != nil {
			return nil, err
		}
		return &EvsGitCheckedUpdate{Shape: protocol.EvsGitShape_EVS_GIT_REKEY, NewTip: args.PriorTip, Peeled: args.PriorTip}, nil
	case protocol.EvsGitShape_EVS_GIT_UPDATE:
	default:
		return nil, refused("shape %d", git.GetShape())
	}

	// an UPDATE
	if flags&^(forceFlag|immutableFlag) != 0 {
		return nil, refused("an UPDATE with flags %#x", flags)
	}
	if (flags&immutableFlag != 0) != (tagRef && creating) {
		return nil, refused("IMMUTABLE other than on a tag ref's creation")
	}
	if tagRef && (!creating || len(args.Payload.Changes) != 0) {
		return nil, refused("a tag ref's update past its creation, or with a change")
	}
	if err := early(); err != nil {
		return nil, err
	}
	switch {
	case args.PriorTip == nil && len(git.GetOldTip()) != 0:
		return nil, refused("an old tip on a ref with none")
	case args.PriorTip != nil && !bytes.Equal(git.GetOldTip(), args.PriorTip[:]):
		return nil, refused("an old tip that is not the ref's")
	}
	if len(git.GetNewTip()) != len(EvsGitOid{}) {
		return nil, refused("an UPDATE with no new tip")
	}
	newTip := EvsGitOid(git.GetNewTip())
	if EvsGitMaxSourceCount < len(git.GetSources()) {
		return nil, refused("%d sources", len(git.GetSources()))
	}
	for _, source := range git.GetSources() {
		if len(source.GetRefId()) != 16 || bytes.Equal(source.GetRefId(), args.RefId.Bytes()) || source.GetVersion() == 0 {
			return nil, refused("a source that is no other ref's committed version")
		}
	}
	if args.ReplaySources != nil && 0 < len(git.GetSources()) {
		if err := args.ReplaySources(ctx, git.GetSources()); err != nil {
			return nil, err
		}
	}
	held := func(oid EvsGitOid) bool {
		return args.Held != nil && args.Held(oid)
	}

	// the commits: each its oid, its parents held or before it, and the import over exactly them or the new rule
	checked := &EvsGitCheckedUpdate{Shape: protocol.EvsGitShape_EVS_GIT_UPDATE, NewTip: &newTip}
	carried := map[EvsGitOid]*EvsGitCarriedCommit{}
	oidList := []byte{}
	for _, sealed := range commits {
		object := sealed.GetObject()
		oid := evsGitObjectOid(evsGitCommitKind, object)
		treeOid, parentOids, err := EvsGitCommitGraph(object)
		if err != nil {
			return nil, refused("a commit git cannot walk")
		}
		for _, parentOid := range parentOids {
			if carried[parentOid] == nil && !held(parentOid) {
				return nil, refused("a commit whose parent is neither held nor carried before it")
			}
		}
		if carried[oid] != nil {
			return nil, refused("a commit carried twice")
		}
		commit := &EvsGitCarriedCommit{Oid: oid, TreeOid: treeOid, ParentOids: parentOids, Sealed: sealed, Held: held(oid)}
		carried[oid] = commit
		checked.Commits = append(checked.Commits, commit)
		oidList = append(oidList, oid[:]...)
	}
	if signedImport := args.Metadata.GetSignedImport(); len(signedImport) != 0 {
		if args.Import == nil {
			return nil, refused("an import no check takes")
		}
		evsImport, err := args.Import(ctx, signedImport, push)
		if err != nil {
			return nil, fmt.Errorf("%w: the import: %w", ErrEvsGitUpdateRefused, err)
		}
		listDigest := sha256.Sum256(oidList)
		if !bytes.Equal(evsImport.GetRepoId(), args.RepoId.Bytes()) || !bytes.Equal(evsImport.GetRefId(), args.RefId.Bytes()) ||
			!bytes.Equal(evsImport.GetTipOid(), newTip[:]) || evsImport.GetCount() != uint32(len(commits)) ||
			!bytes.Equal(evsImport.GetOidListSha256(), listDigest[:]) || len(commits) == 0 {
			// an EvsImport covers exactly the commits of the push that carries it (8.2.6, QD-603)
			return nil, refused("an import that is not over this push's own commits")
		}
		checked.Imported = true
	} else {
		for _, commit := range checked.Commits {
			if commit.Held {
				continue
			}
			decoded, err := EvsGitCommitDecode(commit.Sealed.GetObject())
			if err != nil {
				return nil, refused("a new commit that is not canonical")
			}
			committer, err := EvsGitIdentDecode(decoded.Committer)
			if err != nil {
				return nil, refused("a new commit whose committer is not a strict ident")
			}
			if args.Committer == nil {
				return nil, refused("a new commit no committer rule takes")
			}
			if err := args.Committer(ctx, committer, push); err != nil {
				return nil, fmt.Errorf("%w: a new commit's committer: %w", ErrEvsGitUpdateRefused, err)
			}
			if len(commit.Sealed.GetTrees()) != 0 {
				return nil, refused("a new commit carrying a raw tree")
			}
		}
	}

	// the tags, down to a commit
	peeled := newTip
	for i, tagBytes := range git.GetTags() {
		tagOid := evsGitObjectOid(evsGitTagKind, tagBytes)
		if (i == 0 && tagOid != newTip) || (0 < i && tagOid != peeled) {
			return nil, refused("a tag that is not the one before it names")
		}
		tag, err := EvsGitTagDecode(tagBytes)
		if err != nil {
			return nil, refused("a tag git cannot read")
		}
		last := i == len(git.GetTags())-1
		switch {
		case !last && tag.ObjectKind != evsGitTagKind:
			return nil, refused("a tag of a %s before the last", tag.ObjectKind)
		case last && tag.ObjectKind != evsGitCommitKind:
			return nil, refused("a tag of a %s", tag.ObjectKind)
		}
		checked.Tags = append(checked.Tags, tagBytes)
		checked.TagOids = append(checked.TagOids, tagOid)
		peeled = tag.ObjectOid
	}
	// the prefix line: a tag's proof, with the tags row and its sources replayed; and what the late test measures
	if args.Prefix.judges() {
		measure, proof, err := evsGitPrefixMeasureOf(ctx, args, tagRef, peeled)
		if err != nil {
			return nil, err
		}
		checked.PrefixMeasure, checked.PrefixProof = measure, proof
	}
	if carried[peeled] == nil && !held(peeled) {
		return nil, refused("a tip that peels to a commit neither held nor carried")
	}
	checked.Peeled = &peeled
	// every carried commit an ancestor of the peeled tip, walking only the carried ones
	reached := map[EvsGitOid]bool{}
	for walk := []EvsGitOid{peeled}; 0 < len(walk); {
		oid := walk[len(walk)-1]
		walk = walk[:len(walk)-1]
		commit := carried[oid]
		if commit == nil || reached[oid] {
			continue
		}
		reached[oid] = true
		walk = append(walk, commit.ParentOids...)
	}
	if len(reached) != len(carried) {
		return nil, refused("a carried commit the tip does not reach")
	}
	// descent, unless FORCE: the tip before is an ancestor of the new one, or it
	if args.PriorTip != nil && flags&forceFlag == 0 {
		descends, err := evsGitDescends(ctx, *args.PriorTip, peeled, carried, args.Parents)
		if err != nil {
			return nil, err
		}
		if !descends {
			return nil, refused("an update that does not descend, without FORCE")
		}
	}
	return checked, nil
}

// Whether ancestor is descendant or one of its ancestors: a walk over the carried commits' parents and, past them,
// the held ones' through parents. A commit neither carried nor held ends its line of the walk.
func evsGitDescends(ctx context.Context, ancestor EvsGitOid, descendant EvsGitOid, carried map[EvsGitOid]*EvsGitCarriedCommit, parents func(ctx context.Context, oid EvsGitOid) ([]EvsGitOid, error)) (bool, error) {
	visited := map[EvsGitOid]bool{}
	for walk := []EvsGitOid{descendant}; 0 < len(walk); {
		oid := walk[0]
		walk = walk[1:]
		if oid == ancestor {
			return true, nil
		}
		if visited[oid] {
			continue
		}
		visited[oid] = true
		if commit := carried[oid]; commit != nil {
			walk = append(walk, commit.ParentOids...)
			continue
		}
		if parents == nil {
			return false, fmt.Errorf("%w: a descent no parents walk takes", ErrEvsGitUpdateRefused)
		}
		heldParents, err := parents(ctx, oid)
		switch {
		case errors.Is(err, ErrEvsGitObjectMissing):
		case err != nil:
			return false, err
		default:
			walk = append(walk, heldParents...)
		}
	}
	return false, nil
}

// The identity key a statement's signer had at its authorization pin: what SidecarCommitterClaim names. A pin before
// what the reader retains gives the key the oldest retained rows that admit the signer give it (QD-1178), the key that
// signed the statement itself.
func (self *EvsVerifier) signerIdentityKey(push *protocol.EvsPush) ([]byte, error) {
	newest, err := self.config()
	if err != nil {
		return nil, err
	}
	state, err := newest.At(push.GetAuth())
	unjudged := errors.Is(err, ErrGkmAuthNotRetained)
	if err != nil && !unjudged {
		return nil, fmt.Errorf("%w: its authorization pin: %w", ErrEvsStatementRefused, err)
	}
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: its signer", ErrEvsStatementRefused)
	}
	if unjudged {
		return evsUnjudgedSignerKey(newest, signerId, push.GetAuth())
	}
	return state.IdentityKey(signerId), nil
}

// The purpose an EvsImport is signed under (§6.11).
const evsImportPurpose = "evs-import"

// A push's signed_import as a replaying reader checks it (DESIGN-DETAILS 8.2.6): a Signed EvsImport, purpose
// evs-import, by the identity key of a sidecar that is a repo admin at the push's authorization pin. What it signs is
// held to the push's own commits by EvsGitCheckUpdate. A push pinned before what the reader retains is not judged
// (QD-1178): its import is taken on its signature, under the key the oldest retained rows that admit its signer give
// it.
func (self *EvsVerifier) verifyImport(signedBytes []byte, repoId Id, push *protocol.EvsPush) (*protocol.EvsImport, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: an import that does not parse", ErrEvsStatementRefused)
	}
	evsImport := &protocol.EvsImport{}
	if err := proto.Unmarshal(signed.GetBody(), evsImport); err != nil {
		return nil, fmt.Errorf("%w: an import body that does not parse", ErrEvsStatementRefused)
	}
	newest, err := self.config()
	if err != nil {
		return nil, err
	}
	state, err := newest.At(push.GetAuth())
	unjudged := errors.Is(err, ErrGkmAuthNotRetained)
	if err != nil && !unjudged {
		return nil, fmt.Errorf("%w: the push's authorization pin: %w", ErrEvsStatementRefused, err)
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, fmt.Errorf("%w: an import's signer", ErrEvsStatementRefused)
	}
	var identityKey []byte
	if unjudged {
		if identityKey, err = evsUnjudgedSignerKey(newest, signerId, push.GetAuth()); err != nil {
			return nil, err
		}
	} else {
		repo := state.Repo(repoId)
		if repo == nil || !evsRepoAdmin(state, repo, signerId) {
			return nil, fmt.Errorf("%w: an import by a sidecar no repo admin at the push's pin", ErrEvsStatementRefused)
		}
		identityKey = state.IdentityKey(signerId)
	}
	if err := bridge.VerifySigned(signed, evsImportPurpose, bridge.SignedType_SIGNED_EVS_IMPORT, bridge.SignedKeyAlgEd25519, identityKey); err != nil {
		return nil, fmt.Errorf("%w: an import's signature: %w", ErrEvsStatementRefused, err)
	}
	return evsImport, nil
}

// Whether two optional overlays name one ref and version.
func evsOverlayEqual(a *protocol.EvsOverlay, b *protocol.EvsOverlay) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return proto.Equal(a, b)
}

// A history blob's shape: a 20 B oid, a 16 B file_id, records in the push's history segments, one diff record on a
// base or a checkpoint's or chunks' records; each history segment among the push's new objects.
func checkEvsSealedBlob(blob *protocol.EvsSealedBlob, git *protocol.EvsGitUpdate, payload *EvsCheckedPayload) error {
	refused := func(what string) error {
		return fmt.Errorf("%w: a history blob %s", ErrEvsGitUpdateRefused, what)
	}
	if len(blob.GetGitOid()) != len(EvsGitOid{}) || len(blob.GetFileId()) != 16 || len(blob.GetRecords()) == 0 {
		return refused("of another shape")
	}
	if len(blob.GetBaseOid()) != 0 && (len(blob.GetBaseOid()) != len(EvsGitOid{}) || len(blob.GetRecords()) != 1) {
		return refused("on a base with other than one record")
	}
	for _, record := range blob.GetRecords() {
		if int(record.GetSegment()) >= len(git.GetSegmentIds()) {
			return refused("in no segment of the push")
		}
	}
	for _, segmentId := range git.GetSegmentIds() {
		introduced := false
		for _, object := range payload.NewObjects {
			introduced = introduced || (object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT && bytes.Equal(object.Id, segmentId))
		}
		if !introduced {
			return refused("segment the push does not introduce")
		}
	}
	return nil
}

// What the late test of the prefix line measures, and a tag's proof (DESIGN-DETAILS 8.2.7, QD-801): a tag ref's
// UPDATE judges no file when one of u's sources is its proof, else every file of the tagged tree from nothing; a
// branch is measured from J, which is S unless the push gives the branch its first tip over a base that is no shared
// branch, or over none, where J is the empty tree.
func evsGitPrefixMeasureOf(ctx context.Context, args *EvsGitUpdateArgs, tagRef bool, peeled EvsGitOid) (EvsGitPrefixMeasure, *protocol.EvsOverlay, error) {
	if tagRef {
		proof, err := evsGitPrefixProof(ctx, args, peeled)
		if err != nil || proof != nil {
			return EvsGitPrefixMeasureNone, proof, err
		}
		return EvsGitPrefixMeasureFromNothing, nil, nil
	}
	if args.HeldTip || args.PriorTip != nil {
		// a push on a tip has held one
		return EvsGitPrefixMeasureFromJ, nil, nil
	}
	base := args.Metadata.GetBase()
	if base == nil || args.SharedBranch == nil {
		return EvsGitPrefixMeasureFromNothing, nil, nil
	}
	baseRefId, err := IdFromBytes(base.GetRefId())
	if err != nil {
		return 0, nil, fmt.Errorf("%w: an overlay base that is no ref", ErrEvsGitUpdateRefused)
	}
	shared, err := args.SharedBranch(ctx, baseRefId)
	if err != nil {
		return 0, nil, err
	}
	if shared {
		return EvsGitPrefixMeasureFromJ, nil, nil
	}
	return EvsGitPrefixMeasureFromNothing, nil, nil
}

// A tag's proof among u's sources: the first (r', v') whose ref is a shared branch and whose tip at v', by this
// reader's tips log, is the commit the tag peels to; nil for none. The version the push names is the proof, never a
// lookup in this reader's own tip index, which differs between mounts.
func evsGitPrefixProof(ctx context.Context, args *EvsGitUpdateArgs, peeled EvsGitOid) (*protocol.EvsOverlay, error) {
	if args.ProofOf != nil {
		found, err := args.ProofOf(ctx, peeled)
		if err != nil || !found {
			return nil, err
		}
		return &protocol.EvsOverlay{}, nil
	}
	if args.SharedBranch == nil || args.SourceTip == nil {
		return nil, nil
	}
	for _, source := range args.Metadata.GetGit().GetSources() {
		refId, err := IdFromBytes(source.GetRefId())
		if err != nil {
			continue
		}
		shared, err := args.SharedBranch(ctx, refId)
		if err != nil {
			return nil, err
		}
		if !shared {
			continue
		}
		tip, err := args.SourceTip(ctx, source)
		if err != nil {
			return nil, err
		}
		if tip != nil && *tip == peeled {
			return source, nil
		}
	}
	return nil, nil
}

// What the prefix line's late test reads (DESIGN-DETAILS 8.2.7): the measure the check chose, J and N and where their
// objects are read, and the push's changes with the keys of the ref's tainted token paths.
type EvsGitPrefixTreesArgs struct {
	Line    *EvsGitPrefixLine
	Measure EvsGitPrefixMeasure
	Source  EvsGitObjectSource
	// J, nil for the empty tree, which a measure from nothing takes whatever this says; and N, tree(peel(new_tip)).
	J *EvsGitOid
	N EvsGitOid
	// u's changes, and the key forms (EvsTokenPath.KeyString) of the ref's tainted token paths in u's path epoch: each
	// change at one is judged as a file's on its token path (8.5), since this reader may hold no name for it.
	Changes []*EvsCheckedChange
	Tainted map[string]bool
}

// The prefix line's late test (see the file header): nil where every file it measures, and every tainted token path u
// writes or removes, lies under a prefix the set gives u's signer; else the first found, an *EvsGitPrefixRefusal. It
// reads no tree for a signer the set names for every path.
func EvsGitCheckPrefixTrees(ctx context.Context, args *EvsGitPrefixTreesArgs) error {
	line := args.Line
	if !line.judges() {
		return nil
	}
	walk := &evsGitPrefixWalk{ctx: ctx, source: args.Source, line: line}
	switch args.Measure {
	case EvsGitPrefixMeasureFromJ:
		if args.J == nil || *args.J != args.N {
			if err := walk.trees(nil, EvsTokenPath{}, args.J, &args.N, EvsGitPrefixRowChanged); err != nil {
				return err
			}
		}
	case EvsGitPrefixMeasureFromNothing:
		if err := walk.trees(nil, EvsTokenPath{}, nil, &args.N, EvsGitPrefixRowFromNothing); err != nil {
			return err
		}
	}
	if walk.refused != nil {
		return walk.refused
	}
	for _, change := range args.Changes {
		if args.Tainted[change.TokenPath.KeyString()] && !line.under(change.TokenPath) {
			return &EvsGitPrefixRefusal{Row: EvsGitPrefixRowTainted}
		}
	}
	return nil
}

// One walk of the late test over two trees in the tree reader's order: names sorted by their bytes, a directory's
// files after its own name's, depth first, descending only where the trees differ and never into a directory under a
// prefix, every file of which is allowed. It stops at the first file outside.
type evsGitPrefixWalk struct {
	ctx     context.Context
	source  EvsGitObjectSource
	line    *EvsGitPrefixLine
	refused *EvsGitPrefixRefusal
}

// The files of a and b, directories at names whose token path is tokenPath, either nil for none there.
func (self *evsGitPrefixWalk) trees(names [][]byte, tokenPath EvsTokenPath, a *EvsGitOid, b *EvsGitOid, row EvsGitPrefixRow) error {
	if err := self.ctx.Err(); err != nil {
		return err
	}
	aEntries, err := evsGitPrefixEntries(self.ctx, self.source, a)
	if err != nil {
		return err
	}
	bEntries, err := evsGitPrefixEntries(self.ctx, self.source, b)
	if err != nil {
		return err
	}
	for i, j := 0, 0; (i < len(aEntries) || j < len(bEntries)) && self.refused == nil; {
		var aEntry, bEntry *EvsGitRawEntry
		switch {
		case j == len(bEntries) || (i < len(aEntries) && bytes.Compare(aEntries[i].Name, bEntries[j].Name) < 0):
			aEntry = &aEntries[i]
			i += 1
		case i == len(aEntries) || bytes.Compare(bEntries[j].Name, aEntries[i].Name) < 0:
			bEntry = &bEntries[j]
			j += 1
		default:
			aEntry, bEntry = &aEntries[i], &bEntries[j]
			i += 1
			j += 1
		}
		if aEntry != nil && bEntry != nil && aEntry.CanonMode == bEntry.CanonMode && aEntry.Oid == bEntry.Oid {
			continue
		}
		name := aEntry
		if name == nil {
			name = bEntry
		}
		token, err := EvsPathToken(self.line.PathKey, tokenPath.Last(), name.Name)
		if err != nil {
			return err
		}
		childNames := evsGitPathWith(names, name.Name)
		childTokens := append(slices.Clone(tokenPath), token)
		aFile, bFile := aEntry != nil && aEntry.CanonMode != EvsGitModeDirectory, bEntry != nil && bEntry.CanonMode != EvsGitModeDirectory
		under := self.line.under(childTokens)
		if (aFile || bFile) && !under {
			self.refused = &EvsGitPrefixRefusal{Row: row, Path: string(bytes.Join(childNames, []byte{'/'}))}
			return nil
		}
		if under {
			// every path below a prefix is the writer's, so the directory is passed whole
			continue
		}
		var aDirectory, bDirectory *EvsGitOid
		if aEntry != nil && !aFile {
			aDirectory = &aEntry.Oid
		}
		if bEntry != nil && !bFile {
			bDirectory = &bEntry.Oid
		}
		if aDirectory != nil || bDirectory != nil {
			if err := self.trees(childNames, childTokens, aDirectory, bDirectory, row); err != nil {
				return err
			}
		}
	}
	return nil
}

// A tree's entries as git reads them, sorted by their names' bytes: the tree reader's order. Nil reads nothing.
func evsGitPrefixEntries(ctx context.Context, source EvsGitObjectSource, oid *EvsGitOid) ([]EvsGitRawEntry, error) {
	if oid == nil || *oid == EvsGitEmptyTreeOid {
		return nil, nil
	}
	kind, encoded, err := source.ReadGitObject(ctx, *oid)
	if err != nil {
		return nil, fmt.Errorf("tree %x: %w", oid[:], err)
	}
	if kind != evsGitTreeKind {
		return nil, fmt.Errorf("%w: object %x is a %s, not a tree", ErrEvsGitObjectInvalid, oid[:], kind)
	}
	entries, err := EvsGitTreeRead(encoded)
	if err != nil {
		return nil, fmt.Errorf("tree %x: %w", oid[:], err)
	}
	slices.SortFunc(entries, func(a EvsGitRawEntry, b EvsGitRawEntry) int { return bytes.Compare(a.Name, b.Name) })
	return entries, nil
}

// The prefix line of one verified push of a git-mode ref of this repo (see the file header), through the client's
// judge, at the push's pin and signer and in its path epoch, from this device's own state alone: nil where the
// repo's rows hold no rule set; a waiting line where the client holds no judge, which cannot read the rules in force,
// or no key of the push's epoch.
func (self *EvsRepo) gitPrefixLine(ctx context.Context, refId Id, statement *EvsStatement) (*EvsGitPrefixLine, error) {
	waiting := &EvsGitPrefixLine{Verdict: AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonPending}}
	ruled, err := self.prefixRuled()
	var ruleErr *EvsPrefixRuleError
	switch {
	case errors.As(err, &ruleErr):
		return waiting, nil
	case err != nil:
		return nil, err
	case ruled == nil:
		return nil, nil
	}
	judge, ok := ruled.(*evsPrefixJudge)
	if !ok {
		return waiting, nil
	}
	state, err := self.client.verifier.config()
	if err != nil {
		return nil, err
	}
	repoRow := state.Repo(self.repoId)
	if repoRow == nil || len(repoRow.GetPrefixRules()) == 0 {
		return nil, nil
	}
	refName, err := judge.refName(ctx, self, refId)
	if err != nil {
		return nil, err
	}
	sets, err := judge.setsOf(ctx, self.repoId, state)
	if err != nil {
		return nil, err
	}
	push := statement.Push
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: a push with no signer", ErrEvsGitUpdateRefused)
	}
	row := state.SidecarRow(signerId)
	epoch := max(1, push.GetPathEpoch())
	tables := judge.tokenTable(ctx, self, epoch)
	line := &EvsGitPrefixLine{Verdict: PrefixVerdict(&AclPrefixVerdictArgs{
		RepoKind: repoRow.GetKind(), RefKind: protocol.EvsRefKind(push.GetRefKind()), RefMode: protocol.EvsRefMode(push.GetRefMode()),
		RefName: refName, Flags: push.GetFlags(), PinVersion: push.GetAuth().GetVersion(), Signer: row,
		Rows: repoRow.GetPrefixRules(), Sets: sets, TokenTable: tables,
	})}
	if line.Verdict.Outcome != AclPrefixAllowed || line.Verdict.Reason != AclPrefixReasonNoChange {
		return line, nil
	}
	set := aclPrefixSetAt(sets, line.Verdict.SetAt)
	table, err := tables(set)
	if err != nil || table == nil {
		return &EvsGitPrefixLine{Verdict: AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonTokens, SetAt: line.Verdict.SetAt}}, nil
	}
	line.Prefixes = table.Prefixes(set, row)
	repoKey, err := self.client.args.Gkm.RepoKey(ctx, self.repoId, epoch)
	if err != nil {
		return &EvsGitPrefixLine{Verdict: AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonTokens, SetAt: line.Verdict.SetAt}}, nil
	}
	if line.PathKey, err = NewEvsPathKey(repoKey); err != nil {
		return nil, err
	}
	return line, nil
}

// The tree of the commit oid peels to, an annotated tag followed to its commit, read from source on any leg: what a
// late test reads J and N from where the local tier's tree reader is not built.
func evsGitPeeledTree(ctx context.Context, source EvsGitObjectSource, oid EvsGitOid) (EvsGitOid, error) {
	for {
		kind, object, err := source.ReadGitObject(ctx, oid)
		if err != nil {
			return EvsGitOid{}, err
		}
		switch kind {
		case evsGitCommitKind:
			tree, _, err := EvsGitCommitGraph(object)
			return tree, err
		case evsGitTagKind:
			tag, err := EvsGitTagDecode(object)
			if err != nil {
				return EvsGitOid{}, err
			}
			oid = tag.ObjectOid
		default:
			return EvsGitOid{}, fmt.Errorf("%w: object %x is a %s, which no tip peels through", ErrEvsGitObjectInvalid, oid[:], kind)
		}
	}
}
