//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Overlays (DESIGN-DETAILS 8.2.4; FS-5): the base a new branch is created over, chosen by the device that creates it,
// and what an overlay's pushes hold.
//
//	candidates  the first ancestor of the new tip on its first-parent line, the tip included, within
//	            OverlayBaseSearchCount, that the tip index holds as a branch's tip: each (ref, version) it was; and
//	            each other branch's applied (ref, version) whose tip is the new tip or an ancestor of it
//	choose      the candidate whose tip leaves the fewest commits (git rev-list --count tip --not base); ties: a
//	            shared ref before an owned one, then the lower ref id, then the lower version
//	none        no candidate: the ref has no base and holds its whole tree
//
// Under a general repo's prefix rules a held device, one the set in force names in no rule of no path, chooses among
// shared branches alone (DESIGN-DETAILS 8.2.4's new shared name, QD-801), so its new branch is measured from a shared
// branch's tree rather than from nothing:
//
//	candidates  the new tip's ancestry walked on every parent line, the tip included, a line ending at the first commit
//	            the tip index holds as a shared branch's tip and the walk at OverlayBaseSearchCount commits in all:
//	            each such commit's (ref, version) rows; and each shared branch's applied (ref, version) whose tip is
//	            the new tip or an ancestor of it
//	choose      the fewest commits left, then the lower ref id, then the lower version
//
// A device that merged main into its work holds main's merged tip on a second-parent line, which the first-parent
// walk would miss. Any other device, and every owned ref, chooses as above.
//
// A base is a branch, never a tag ref, and never changes: the overlay's first push names it in payload section 16 and
// takes its ref's current path epoch (8.2.10, QD-632); its unheld paths read from it, and its first push states its
// net change against the base tip's tree. What the overlay holds is what its pushes wrote: a file once it wrote it, a
// directory whole or not at all (QD-605), so a removal of an inherited name is its parent's table written whole
// without it, and a file changed in a directory it never holds needs no directory (evs_plan.go's overlay rows). A
// tag ref holds no path state and takes no base (QD-606).
//
// Desktop legs only. Safe for concurrent use as the mount and the state are.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// The base a new branch whose tip is tip is created over, for refId, nil for none: see the file header.
func (self *EvsLocalRepo) overlayBase(ctx context.Context, refId Id, tip EvsGitOid, state EvsGitSourceState, searchCount int) (*EvsGitSourceRef, error) {
	type refVersion struct {
		refId   Id
		version uint64
	}
	candidates := []*EvsGitSourceRef{}
	seen := map[refVersion]bool{}
	add := func(candidate *EvsGitSourceRef) {
		if candidate.Tag || candidate.RefId == refId || candidate.Version == 0 {
			return
		}
		key := refVersion{refId: candidate.RefId, version: candidate.Version}
		if seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, candidate)
	}
	if 0 < searchCount {
		out, err := self.Git(ctx, "rev-list", "--first-parent", "--max-count="+strconv.Itoa(searchCount), hex.EncodeToString(tip[:]))
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Fields(string(out)) {
			oid, err := evsGitOidDecodeHex([]byte(line))
			if err != nil {
				return nil, err
			}
			found, err := state.TipsOf(ctx, oid)
			if err != nil {
				return nil, err
			}
			branches := 0
			for _, candidate := range found {
				if !candidate.Tag && candidate.RefId != refId {
					add(candidate)
					branches += 1
				}
			}
			if 0 < branches {
				break
			}
		}
	}
	refs, err := state.Refs(ctx)
	if err != nil {
		return nil, err
	}
	for _, candidate := range refs {
		if candidate.Tag || candidate.RefId == refId || candidate.Version == 0 {
			continue
		}
		reached, err := self.reachedBy(ctx, candidate.Tip, []EvsGitOid{tip})
		if err != nil {
			return nil, err
		}
		if reached {
			add(candidate)
		}
	}
	return self.fewestLeft(ctx, tip, candidates)
}

// Whether a source row is a shared branch: a ref of kind shared that is no tag ref (8.2.4).
func evsGitSourceSharedBranch(source *EvsGitSourceRef) bool {
	return source.Kind == protocol.EvsRefKind_EVS_REF_SHARED && !source.Tag
}

// The base a held device's new branch whose tip is tip is created over, for refId, nil for none: shared branches only,
// found on every parent line (see the file header).
func (self *EvsLocalRepo) overlayBaseShared(ctx context.Context, refId Id, tip EvsGitOid, state EvsGitSourceState, searchCount int) (*EvsGitSourceRef, error) {
	type refVersion struct {
		refId   Id
		version uint64
	}
	candidates := []*EvsGitSourceRef{}
	seen := map[refVersion]bool{}
	add := func(candidate *EvsGitSourceRef) {
		if !evsGitSourceSharedBranch(candidate) || candidate.RefId == refId || candidate.Version == 0 {
			return
		}
		key := refVersion{refId: candidate.RefId, version: candidate.Version}
		if seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, candidate)
	}
	if 0 < searchCount {
		// children before parents, so a commit is reached on a line before it is read; a line ends at a shared tip
		out, err := self.Git(ctx, "rev-list", "--topo-order", "--parents", "--max-count="+strconv.Itoa(searchCount), hex.EncodeToString(tip[:]))
		if err != nil {
			return nil, err
		}
		live := map[EvsGitOid]bool{tip: true}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			oids := make([]EvsGitOid, 0, len(fields))
			for _, field := range fields {
				oid, err := evsGitOidDecodeHex([]byte(field))
				if err != nil {
					return nil, err
				}
				oids = append(oids, oid)
			}
			if !live[oids[0]] {
				continue
			}
			found, err := state.TipsOf(ctx, oids[0])
			if err != nil {
				return nil, err
			}
			ended := false
			for _, candidate := range found {
				if evsGitSourceSharedBranch(candidate) && candidate.RefId != refId {
					add(candidate)
					ended = true
				}
			}
			if ended {
				continue
			}
			for _, parent := range oids[1:] {
				live[parent] = true
			}
		}
	}
	refs, err := state.Refs(ctx)
	if err != nil {
		return nil, err
	}
	for _, candidate := range refs {
		if !evsGitSourceSharedBranch(candidate) || candidate.RefId == refId || candidate.Version == 0 {
			continue
		}
		reached, err := self.reachedBy(ctx, candidate.Tip, []EvsGitOid{tip})
		if err != nil {
			return nil, err
		}
		if reached {
			add(candidate)
		}
	}
	return self.fewestLeft(ctx, tip, candidates)
}

// The candidate whose tip leaves the fewest commits of tip (git rev-list --count tip --not candidate), ties broken by
// evsOverlayBaseBefore; nil for none.
func (self *EvsLocalRepo) fewestLeft(ctx context.Context, tip EvsGitOid, candidates []*EvsGitSourceRef) (*EvsGitSourceRef, error) {
	var chosen *EvsGitSourceRef
	chosenCount := 0
	for _, candidate := range candidates {
		out, err := self.Git(ctx, "rev-list", "--count", hex.EncodeToString(tip[:]), "--not", hex.EncodeToString(candidate.Tip[:]))
		if err != nil {
			return nil, err
		}
		count, err := strconv.Atoi(strings.TrimSpace(string(out)))
		if err != nil {
			return nil, err
		}
		if chosen == nil || count < chosenCount || (count == chosenCount && evsOverlayBaseBefore(candidate, chosen)) {
			chosen, chosenCount = candidate, count
		}
	}
	return chosen, nil
}

// The tie order of two candidates leaving as many commits: a shared ref before an owned one, then the lower ref id,
// then the lower version.
func evsOverlayBaseBefore(a *EvsGitSourceRef, b *EvsGitSourceRef) bool {
	aShared, bShared := a.Kind == protocol.EvsRefKind_EVS_REF_SHARED, b.Kind == protocol.EvsRefKind_EVS_REF_SHARED
	if aShared != bShared {
		return aShared
	}
	if order := bytes.Compare(a.RefId[:], b.RefId[:]); order != 0 {
		return order < 0
	}
	return a.Version < b.Version
}
