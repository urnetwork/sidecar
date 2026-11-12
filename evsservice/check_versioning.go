// Format 2's 5c on evs (§11.7's refused row, §11.8's 5c; R-EVS-20, D-EVS-35, FI-17, FS-68; EVS2-M10-06), for a push
// that carries format 2 once §19.11's gate admitted it (check_refs.go's checkFormat2Gate):
//
//	kind     409 VERSIONING for an entry version of versioning 1 or 2 in a config or mailcfg repo, whose replaying
//	         readers verify authority from every version, on a git-mode ref, and on a creates-only ref (a record-class
//	         stream, a deposit ref, the erasure ref): final, since a repo's kind and a ref's mode and kind never
//	         change (plan-EVS2-small-readings#3)
//	lock     409 VERSIONING for versioning 1, never 2 (owner decision 168), in a repo whose lock stands in the
//	         authorization state evs validates the push against (5d's newest state), so a write validated before
//	         the lock serializes before it: recorded, since a lock can change
//	others   a DROP's and a cancel's rules are EVS2-M10-09's and a CUT's EVS2-M10-11's: until they land, such a push
//	         answers 503, refusing nothing, so none commits on a check this file did not run
//
// A value past 2 never reaches here: the payload checks refuse it as malformed. evs reads no rule: only each version's
// own setting (§11.7's choose row). The citation rule, 5h's kind-5 rows, is check_citation.go's.
//
// Package-level functions are safe for concurrent use.

package evsservice

import (
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Format 2's 5c for a push carrying format 2: a seam's rules when the view carries one (a test's), else the DROP and
// CUT waits and CheckVersioning. A format-1 push passes.
func checkFormat2Refs(view *PushView) *EvsCheckRefusal {
	if !view.NeedsFormat2 {
		return nil
	}
	if view.Format2Rules != nil {
		return view.Format2Rules(view)
	}
	if view.InstanceFormat != sidecar.EvsRepoFormat2 {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a format-2 push at an instance of another format")
	}
	push := view.Statement.Push
	switch {
	case push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) != 0 || len(push.GetDropSha256()) != 0:
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a DROP's rules are EVS2-M10-09's")
	case push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CUT) != 0 || push.GetIndexEpoch() != 0:
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a CUT's and an index_epoch's rules are EVS2-M10-11's")
	}
	return CheckVersioning(view)
}

// 5c's versioning refusals: see the file header.
func CheckVersioning(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	versionlessPaths := []sidecar.EvsTokenPath{}
	lockedPaths := []sidecar.EvsTokenPath{}
	for _, change := range view.Payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
		}
		switch entry.GetVersioning() {
		case uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT):
			continue
		case uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS):
			lockedPaths = append(lockedPaths, change.TokenPath)
		}
		versionlessPaths = append(versionlessPaths, change.TokenPath)
	}
	if len(versionlessPaths) == 0 {
		return nil
	}
	refusal := func(reason EvsCheckReason, detail string, paths []sidecar.EvsTokenPath) *EvsCheckRefusal {
		refused := newEvsCheckRefusal(reason, detail)
		refused.Paths = paths
		return refused
	}
	repoKind := view.Repo.GetKind()
	refKind := protocol.EvsRefKind(push.GetRefKind())
	switch {
	case repoKind == protocol.RepoKind_REPO_KIND_CONFIG || repoKind == protocol.RepoKind_REPO_KIND_MAILCFG:
		return refusal(EvsCheckReasonVersioningRef, "a versionless version in a config or mailcfg repo", versionlessPaths)
	case protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT:
		return refusal(EvsCheckReasonVersioningRef, "a versionless version on a git-mode ref", versionlessPaths)
	case refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT, refKind == protocol.EvsRefKind_EVS_REF_ERASURE,
		refKind == protocol.EvsRefKind_EVS_REF_OWNED && sidecar.EvsRepoKindRecordClass(repoKind):
		return refusal(EvsCheckReasonVersioningRef, "a versionless version on a creates-only ref", versionlessPaths)
	}
	if 0 < len(lockedPaths) {
		if view.Auth == nil {
			return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "no authorization state to read the lock in")
		}
		if row := view.Auth.Repo(view.RepoId); row != nil && row.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED {
			return refusal(EvsCheckReasonVersioningLocked, "versioning 1 in a locked repo", lockedPaths)
		}
	}
	return nil
}
