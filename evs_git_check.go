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
// On every leg but the forwarding role's. Package-level functions are safe for concurrent use as the arguments'
// functions are.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A git-mode version that breaks check(u): what a replaying reader alarms on and stops the ref before.
var ErrEvsGitUpdateRefused = errors.New("evs: a git-mode version that does not check")

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

// The identity key a statement's signer had at its authorization pin: what SidecarCommitterClaim names.
func (self *EvsVerifier) signerIdentityKey(push *protocol.EvsPush) ([]byte, error) {
	newest, err := self.config()
	if err != nil {
		return nil, err
	}
	state, err := newest.At(push.GetAuth())
	if err != nil {
		return nil, fmt.Errorf("%w: its authorization pin: %w", ErrEvsStatementRefused, err)
	}
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: its signer", ErrEvsStatementRefused)
	}
	return state.IdentityKey(signerId), nil
}

// The purpose an EvsImport is signed under (§6.11).
const evsImportPurpose = "evs-import"

// A push's signed_import as a replaying reader checks it (DESIGN-DETAILS 8.2.6): a Signed EvsImport, purpose
// evs-import, by the identity key of a sidecar that is a repo admin at the push's authorization pin. What it signs is
// held to the push's own commits by EvsGitCheckUpdate.
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
	if err != nil {
		return nil, fmt.Errorf("%w: the push's authorization pin: %w", ErrEvsStatementRefused, err)
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, fmt.Errorf("%w: an import's signer", ErrEvsStatementRefused)
	}
	repo := state.Repo(repoId)
	if repo == nil || !evsRepoAdmin(state, repo, signerId) {
		return nil, fmt.Errorf("%w: an import by a sidecar no repo admin at the push's pin", ErrEvsStatementRefused)
	}
	identityKey := state.IdentityKey(signerId)
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
