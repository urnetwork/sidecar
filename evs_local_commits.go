//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// What a git ref update carries (DESIGN-DETAILS 8.2.3), read from a mount's bare repository:
//
//	excl      old, when the ref has a tip, and an overlay's base tip at its base version
//	carried   C: what peel(new) reaches that excl and every refs/ur/evs/ tip do not, parents first, by
//	          git rev-list --topo-order --reverse --boundary peel(new) --not excl --glob=refs/ur/evs/*
//	sources   for each boundary commit excl does not reach, in C's order, and for peel(new) when C is empty and excl
//	          does not reach it: the ref whose refs/ur/evs/ tip reaches it, a shared ref before an owned one, then the
//	          most recently applied, the update's own ref never; each with the version replay's tips log gives its
//	          tip. At most 16: past that C is taken again against excl and the sixteen's tips alone, and what it
//	          gains is carried, and must then be this sidecar's own
//	blobs     B: every blob git rev-list --objects peel(new) --not excl tips(S) lists, which the readers do not hold
//
// Every commit of C that no EvsImport covers is new, and held to 8.2.3's rule before anything is sent: its object
// canonical (EvsGitCommitDecode), its committer a strict ident whose email is a client of this sidecar
// (<client_id>@ur.invalid), and every tree it brings canonical, so it carries no raw tree. A refusal names the commit
// and never its bytes (I-13).
//
// Replay's state, which the sync engine keeps (EVS1-M2-35's EvsGitRef and tips log), comes through EvsGitSourceState.
//
// Desktop legs only. Safe for concurrent use as the mount and the state are.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// An update whose carried history breaks 8.2.3's rule, or more than a push can name: refused before any evs write.
var ErrEvsGitUpdateInvalid = errors.New("evs: a git update its push cannot carry")

// The ref prefix in a mount's bare repository at which the daemon keeps each ref's tip as evs holds it (8.2.2).
const evsLocalEvsRefPrefix = evsLocalDaemonRefPrefix + "/evs/"

// One ref a push may name as a source, or an overlay take as its base, as replay holds it.
type EvsGitSourceRef struct {
	RefId Id
	Kind  protocol.EvsRefKind
	// The version replay's tips log gives the ref's refs/ur/evs/ tip, and that tip.
	Version uint64
	Tip     EvsGitOid
	// When replay applied that version, in the order it applied versions: the higher, the more recent.
	AppliedOrder uint64
	// A tag ref, which is never a base (DESIGN-DETAILS 8.2.4).
	Tag bool
}

// What publish reads of replay's state (EVS1-M2-35's EvsGitRef, tips log and tip index).
type EvsGitSourceState interface {
	// The ref whose refs/ur/evs/ tip it is, at the version its tips log gives: ok false for a ref replay holds no tip
	// of, which is no source.
	SourceRef(ctx context.Context, refId Id) (*EvsGitSourceRef, bool, error)
	// Every git-mode ref replay holds a tip of, at the version it applied: the base search's other branches.
	Refs(ctx context.Context) ([]*EvsGitSourceRef, error)
	// Every ref version whose tip was oid, from the tip index: none for a commit no applied version had as its tip.
	TipsOf(ctx context.Context, oid EvsGitOid) ([]*EvsGitSourceRef, error)
	// The ref's tip at version, from its tips log: false for a version replay has not applied or that left no tip.
	TipAt(ctx context.Context, refId Id, version uint64) (EvsGitOid, bool, error)
}

// What an update carries.
type evsGitCarried struct {
	// C, parents first.
	commits []EvsGitOid
	// S, at most EvsGitMaxSourceCount.
	sources []*EvsGitSourceRef
	// B.
	blobs map[EvsGitOid]bool
}

// The hex of oids, for git's arguments.
func evsGitOidHexes(oids []EvsGitOid) []string {
	hexes := make([]string, len(oids))
	for i, oid := range oids {
		hexes[i] = hex.EncodeToString(oid[:])
	}
	return hexes
}

// What the update of refId to peeled carries over excl (see the file header).
func (self *EvsLocalRepo) carried(ctx context.Context, refId Id, peeled EvsGitOid, excl []EvsGitOid, state EvsGitSourceState) (*evsGitCarried, error) {
	commits, boundaries, err := self.revList(ctx, peeled, excl, true)
	if err != nil {
		return nil, err
	}
	candidates := boundaries
	if len(commits) == 0 {
		candidates = []EvsGitOid{peeled}
	}
	carried := &evsGitCarried{commits: commits}
	named := map[Id]bool{}
	for _, candidate := range candidates {
		reached, err := self.reachedBy(ctx, candidate, excl)
		if err != nil {
			return nil, err
		}
		if reached {
			continue
		}
		source, err := self.sourceOf(ctx, refId, candidate, state)
		if err != nil {
			return nil, err
		}
		if source == nil {
			return nil, fmt.Errorf("%w: commit %x is held by no ref replay holds", ErrEvsGitUpdateInvalid, candidate[:])
		}
		if !named[source.RefId] {
			named[source.RefId] = true
			carried.sources = append(carried.sources, source)
		}
	}
	tips := []EvsGitOid{}
	if EvsGitMaxSourceCount < len(carried.sources) {
		// C taken again against excl and the first sixteen's tips alone: what it gains is carried
		carried.sources = carried.sources[:EvsGitMaxSourceCount]
		for _, source := range carried.sources {
			tips = append(tips, source.Tip)
		}
		carried.commits, _, err = self.revList(ctx, peeled, append(slices.Clone(excl), tips...), false)
		if err != nil {
			return nil, err
		}
	} else {
		for _, source := range carried.sources {
			tips = append(tips, source.Tip)
		}
	}
	blobs, err := self.revListBlobs(ctx, peeled, append(slices.Clone(excl), tips...))
	if err != nil {
		return nil, err
	}
	carried.blobs = blobs
	return carried, nil
}

// rev-list --topo-order --reverse of peeled --not excl, and every refs/ur/evs/ tip when glob: the commits, and the
// boundary ones when boundary.
func (self *EvsLocalRepo) revList(ctx context.Context, peeled EvsGitOid, excl []EvsGitOid, glob bool) ([]EvsGitOid, []EvsGitOid, error) {
	args := []string{"rev-list", "--topo-order", "--reverse"}
	if glob {
		args = append(args, "--boundary")
	}
	args = append(args, hex.EncodeToString(peeled[:]), "--not")
	args = append(args, evsGitOidHexes(excl)...)
	if glob {
		args = append(args, "--glob="+evsLocalEvsRefPrefix+"*")
	}
	out, err := self.Git(ctx, args...)
	if err != nil {
		return nil, nil, err
	}
	commits, boundaries := []EvsGitOid{}, []EvsGitOid{}
	for _, line := range strings.Fields(string(out)) {
		boundary := strings.HasPrefix(line, "-")
		oid, err := evsGitOidDecodeHex([]byte(strings.TrimPrefix(line, "-")))
		if err != nil {
			return nil, nil, fmt.Errorf("%w: rev-list answered no oid", ErrEvsGitFailed)
		}
		if boundary {
			boundaries = append(boundaries, oid)
		} else {
			commits = append(commits, oid)
		}
	}
	return commits, boundaries, nil
}

// Whether commit is excl or an ancestor of one of them.
func (self *EvsLocalRepo) reachedBy(ctx context.Context, commit EvsGitOid, excl []EvsGitOid) (bool, error) {
	if len(excl) == 0 {
		return false, nil
	}
	args := append([]string{"rev-list", "-n", "1", hex.EncodeToString(commit[:]), "--not"}, evsGitOidHexes(excl)...)
	out, err := self.Git(ctx, args...)
	if err != nil {
		return false, err
	}
	return len(bytes.TrimSpace(out)) == 0, nil
}

// The source a commit is held through: of the refs whose refs/ur/evs/ tip reaches it, other than refId, a shared ref
// before an owned one, then the most recently applied; nil when none does.
func (self *EvsLocalRepo) sourceOf(ctx context.Context, refId Id, commit EvsGitOid, state EvsGitSourceState) (*EvsGitSourceRef, error) {
	out, err := self.Git(ctx, "for-each-ref", "--format=%(refname)", "--contains", hex.EncodeToString(commit[:]), evsLocalEvsRefPrefix)
	if err != nil {
		return nil, err
	}
	var chosen *EvsGitSourceRef
	for _, line := range strings.Fields(string(out)) {
		idText, ok := strings.CutPrefix(line, evsLocalEvsRefPrefix)
		if !ok {
			continue
		}
		decoded, err := hex.DecodeString(idText)
		if err != nil || len(decoded) != 16 || Id(decoded) == refId {
			continue
		}
		source, held, err := state.SourceRef(ctx, Id(decoded))
		if err != nil {
			return nil, err
		}
		if !held || source.Version == 0 {
			continue
		}
		shared := source.Kind == protocol.EvsRefKind_EVS_REF_SHARED
		switch {
		case chosen == nil:
			chosen = source
		case shared != (chosen.Kind == protocol.EvsRefKind_EVS_REF_SHARED):
			if shared {
				chosen = source
			}
		case chosen.AppliedOrder < source.AppliedOrder:
			chosen = source
		}
	}
	return chosen, nil
}

// The blobs peeled reaches that excl does not: git rev-list --objects with git's blob filter, which still prints the
// walk's commits, less those commits.
func (self *EvsLocalRepo) revListBlobs(ctx context.Context, peeled EvsGitOid, excl []EvsGitOid) (map[EvsGitOid]bool, error) {
	walk := append([]string{hex.EncodeToString(peeled[:]), "--not"}, evsGitOidHexes(excl)...)
	commitsOut, err := self.Git(ctx, append([]string{"rev-list"}, walk...)...)
	if err != nil {
		return nil, err
	}
	commits := map[string]bool{}
	for _, line := range strings.Fields(string(commitsOut)) {
		commits[line] = true
	}
	out, err := self.Git(ctx, append([]string{"rev-list", "--objects", "--no-object-names", "--filter=object:type=blob"}, walk...)...)
	if err != nil {
		return nil, err
	}
	blobs := map[EvsGitOid]bool{}
	for _, line := range strings.Fields(string(out)) {
		if commits[line] {
			continue
		}
		oid, err := evsGitOidDecodeHex([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("%w: rev-list answered no oid", ErrEvsGitFailed)
		}
		blobs[oid] = true
	}
	return blobs, nil
}

// A carried commit sealed (8.2.2's commits, changes and trees rows): its object, its changes against its first
// parent's tree by the tree reader, and the trees of it that do not rebuild from names, modes and oids.
func evsGitSealCommit(ctx context.Context, objects EvsGitObjectSource, oid EvsGitOid) (*protocol.EvsSealedCommit, []EvsGitOid, error) {
	kind, object, err := objects.ReadGitObject(ctx, oid)
	if err != nil {
		return nil, nil, err
	}
	if kind != evsGitCommitKind {
		return nil, nil, fmt.Errorf("%w: object %x is a %s, not a commit", ErrEvsGitUpdateInvalid, oid[:], kind)
	}
	treeOid, parentOids, err := EvsGitCommitGraph(object)
	if err != nil {
		return nil, nil, fmt.Errorf("commit %x: %w", oid[:], err)
	}
	var parentTree *EvsGitOid
	if 0 < len(parentOids) {
		_, parentObject, err := objects.ReadGitObject(ctx, parentOids[0])
		if err != nil {
			return nil, nil, err
		}
		parentTreeOid, _, err := EvsGitCommitGraph(parentObject)
		if err != nil {
			return nil, nil, fmt.Errorf("commit %x: %w", parentOids[0][:], err)
		}
		parentTree = &parentTreeOid
	}
	changes, raw, err := EvsGitCommitChanges(ctx, objects, parentTree, treeOid)
	if err != nil {
		return nil, nil, err
	}
	return &protocol.EvsSealedCommit{Object: object, Changes: changes, Trees: raw}, parentOids, nil
}

// 8.2.3's rule for a new commit, one no EvsImport covers: its object canonical, its committer a strict ident whose
// email is <client_id>@ur.invalid for a client own takes, a client of this sidecar, and every tree it brings canonical,
// so it carries no raw tree.
func evsGitCheckNewCommit(oid EvsGitOid, sealed *protocol.EvsSealedCommit, own func(clientId Id) bool) error {
	decoded, err := EvsGitCommitDecode(sealed.GetObject())
	if err != nil {
		return fmt.Errorf("%w: new commit %x is not canonical", ErrEvsGitUpdateInvalid, oid[:])
	}
	committer, err := EvsGitIdentDecode(decoded.Committer)
	if err != nil {
		return fmt.Errorf("%w: new commit %x's committer is not a strict ident", ErrEvsGitUpdateInvalid, oid[:])
	}
	clientId, err := ParseSidecarCommitterEmail(string(committer.Email))
	if err != nil || !own(clientId) {
		return fmt.Errorf("%w: new commit %x's committer is no client of this sidecar", ErrEvsGitUpdateInvalid, oid[:])
	}
	if 0 < len(sealed.GetTrees()) {
		return fmt.Errorf("%w: new commit %x brings a tree that is not canonical", ErrEvsGitUpdateInvalid, oid[:])
	}
	return nil
}
