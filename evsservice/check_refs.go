// 5c (§11.8): repo/ active, §11.8's refs table, and the storage limit.
//
// The refs table, as evs holds it from the token's honored rights and its sidecar (readers hold the same table from
// the access log, evs_verify.go's evsCheckRefRules):
//
//	ref kind                     mode         writer                          FORCE, DELETE           other flags
//	shared (main, ...)           git or file  rw                              admin                   IMMUTABLE ref: DELETE only
//	owned, general and config    git or file  its sidecar, rw                 its sidecar             CLOSURE (admin)
//	owned, record-class stream   file         its sidecar, rw, creates only   refused                 BASE, CLOSURE (admin)
//	deposit                      file         its depositor, creates only     refused                 CONSUME (rw)
//	erasure (per repo)           file         admin, creates only             refused                 ERASE (admin)
//
// and with it: the erasure ref's public id carries the erasure kind and no other id does, a deposit ref's id is its
// depositor's public one (plan-EVS1-ref-name-bytes#3); a ref's first push sets its kind, mode and owner, which every
// later push repeats (409 REF_MODE), as replaying readers require; only git-mode refs take overlays; IMMUTABLE, which
// tags carry, goes only on git-mode refs, and a ref whose head push carried it takes only a DELETE; PATH_EPOCH never
// goes on deposit or erasure refs, which stay at path epoch 1 (plan-EVS1-epoch-kinds#2); and BASE, ERASE and CLOSURE
// take admin wherever they go. A BASE's changes are only removals and it introduces nothing, a CONSUME's are only
// removals (plan-EVS1-v1-unspecified#6, §11.12); a CLOSURE's and an ERASE's own rules are EVS1-M2-20's, behind
// PushView.ErasureRules.
//
// What settles for good is final: shredding, every ref rule and every change-shape rule, since each is a property of
// the statement or of a head that never changes it. Keying, deletion, scope and the storage limit can change, so they
// are recorded.

package evsservice

import (
	"bytes"
	"fmt"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// 5c: repo/'s state and format, §19.11's format2 gate for a push carrying format 2, the refs table, then the storage
// limit.
func CheckRefs(view *PushView) *EvsCheckRefusal {
	if refusal := checkRepoState(view.Repo, view.InstanceFormat); refusal != nil {
		return refusal
	}
	if refusal := checkFormat2Gate(view); refusal != nil {
		return refusal
	}
	if refusal := checkRefTable(view); refusal != nil {
		return refusal
	}
	return checkStorageLimit(view)
}

// §11.6's format row at 5c: a push carrying a format-2 value from a network outside the format2 gate is 409
// VERSIONING, recorded, since a gate can change (plan-EVS2-small-readings#3). A format-1 instance never reaches
// here with one, having refused it as needing format 2 (push.go).
func checkFormat2Gate(view *PushView) *EvsCheckRefusal {
	if !view.NeedsFormat2 || view.Format2Admitted {
		return nil
	}
	return newEvsCheckRefusal(EvsCheckReasonFormat2Gate, "a format-2 push from a network outside the format2 gate")
}

// repo/ active and of a format the instance writes: a repo/ past instanceFormat, a format-2 repo on a format-1
// instance, answers 503 and writes nothing (plan-EVS1-format-unsupported#4). A repo/ step 4 did not read, or an
// instance format the view does not give, refuses 503.
func checkRepoState(repo *protocol.EvsRepoObject, instanceFormat uint32) *EvsCheckRefusal {
	if repo == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no repo/ read")
	}
	if instanceFormat != sidecar.EvsRepoFormat1 && instanceFormat != sidecar.EvsRepoFormat2 {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, fmt.Sprintf("an instance format of %d", instanceFormat))
	}
	switch repo.GetState() {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE:
	case protocol.EvsRepoState_EVS_REPO_KEYING:
		return newEvsCheckRefusal(EvsCheckReasonRepoKeying, "repo/ keying")
	case protocol.EvsRepoState_EVS_REPO_DELETED:
		return newEvsCheckRefusal(EvsCheckReasonRepoDeleted, "repo/ deleted")
	case protocol.EvsRepoState_EVS_REPO_SHREDDING, protocol.EvsRepoState_EVS_REPO_SHREDDED:
		return newEvsCheckRefusal(EvsCheckReasonRepoShredding, "repo/ shredding or shredded")
	default:
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, fmt.Sprintf("repo/ state %d", repo.GetState()))
	}
	if instanceFormat < repo.GetFormat() {
		return newEvsCheckRefusal(EvsCheckReasonRepoFormat, fmt.Sprintf("a repo of format %d at an instance of format %d", repo.GetFormat(), instanceFormat))
	}
	return nil
}

// The refs table: see the file header.
func checkRefTable(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	refId := sidecar.Id(push.GetRefId())
	refKind := protocol.EvsRefKind(push.GetRefKind())
	refMode := protocol.EvsRefMode(push.GetRefMode())
	recordClass := sidecar.EvsRepoKindRecordClass(view.Repo.GetKind())
	refRule := func(format string, args ...any) *EvsCheckRefusal {
		return newEvsCheckRefusal(EvsCheckReasonRefRule, fmt.Sprintf(format, args...))
	}
	scope := func(format string, args ...any) *EvsCheckRefusal {
		return newEvsCheckRefusal(EvsCheckReasonScope, fmt.Sprintf(format, args...))
	}
	admin := view.Rights.Has(sidecar.AclEvsAdmin)
	write := view.Rights.Has(sidecar.AclEvsWrite)

	// ids and owners
	if (refId == sidecar.EvsErasureRefId(view.RepoId)) != (refKind == protocol.EvsRefKind_EVS_REF_ERASURE) {
		return refRule("the erasure ref's id and the erasure kind go together")
	}
	ownerId, ownerErr := sidecar.IdFromBytes(push.GetOwnerSidecarId())
	switch refKind {
	case protocol.EvsRefKind_EVS_REF_SHARED, protocol.EvsRefKind_EVS_REF_ERASURE:
		if len(push.GetOwnerSidecarId()) != 0 {
			return refRule("a %s ref with an owner", refKind)
		}
	case protocol.EvsRefKind_EVS_REF_OWNED:
		if ownerErr != nil {
			return refRule("an owned ref with no owner")
		}
	case protocol.EvsRefKind_EVS_REF_DEPOSIT:
		if ownerErr != nil || sidecar.EvsDepositRefId(view.RepoId, ownerId) != refId {
			return refRule("a deposit ref not at its depositor's id")
		}
	default:
		return refRule("ref kind %d", refKind)
	}

	// modes, and what the head fixed
	fileOnly := refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || refKind == protocol.EvsRefKind_EVS_REF_ERASURE ||
		(refKind == protocol.EvsRefKind_EVS_REF_OWNED && recordClass)
	if fileOnly && refMode != protocol.EvsRefMode_EVS_REF_FILE {
		return refRule("a %s ref of mode %s", refKind, refMode)
	}
	if view.headExists() {
		head := view.Head
		if head.GetRefKind() != push.GetRefKind() || head.GetRefMode() != push.GetRefMode() ||
			!bytes.Equal(head.GetOwnerSidecarId(), push.GetOwnerSidecarId()) {
			return refRule("a kind, mode or owner other than the head's")
		}
		if head.GetBase() != nil && refMode != protocol.EvsRefMode_EVS_REF_GIT {
			return refRule("an overlay of a file-mode ref")
		}
		if !head.GetDeleted() && view.HeadFlags&uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE) != 0 && !view.has(protocol.EvsPushFlag_EVS_PUSH_DELETE) {
			return refRule("an IMMUTABLE ref takes only a DELETE")
		}
	}

	// the flags each ref kind takes
	switch {
	case view.has(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE) && refMode != protocol.EvsRefMode_EVS_REF_GIT:
		return refRule("IMMUTABLE on a file-mode ref")
	case (view.has(protocol.EvsPushFlag_EVS_PUSH_FORCE) || view.has(protocol.EvsPushFlag_EVS_PUSH_DELETE)) && fileOnly:
		return refRule("FORCE or DELETE on a %s ref", refKind)
	case view.has(protocol.EvsPushFlag_EVS_PUSH_BASE) && !(refKind == protocol.EvsRefKind_EVS_REF_OWNED && recordClass):
		return refRule("BASE outside a record-class stream")
	case view.has(protocol.EvsPushFlag_EVS_PUSH_CONSUME) && refKind != protocol.EvsRefKind_EVS_REF_DEPOSIT:
		return refRule("CONSUME outside a deposit ref")
	case view.has(protocol.EvsPushFlag_EVS_PUSH_ERASE) && refKind != protocol.EvsRefKind_EVS_REF_ERASURE:
		return refRule("ERASE outside the erasure ref")
	case view.has(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) &&
		(refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || refKind == protocol.EvsRefKind_EVS_REF_ERASURE):
		return refRule("CLOSURE on a %s ref", refKind)
	case view.has(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) &&
		(refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || refKind == protocol.EvsRefKind_EVS_REF_ERASURE):
		return refRule("PATH_EPOCH on a %s ref", refKind)
	}

	// admin wherever these go
	if !admin && (view.has(protocol.EvsPushFlag_EVS_PUSH_BASE) || view.has(protocol.EvsPushFlag_EVS_PUSH_ERASE) ||
		view.has(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)) {
		return scope("BASE, ERASE or CLOSURE below admin")
	}

	// the writer each ref kind takes
	signerOwns := ownerErr == nil && ownerId == view.TokenSidecarId
	switch refKind {
	case protocol.EvsRefKind_EVS_REF_SHARED:
		if !write {
			return scope("a shared ref below rw")
		}
		if (view.has(protocol.EvsPushFlag_EVS_PUSH_FORCE) || view.has(protocol.EvsPushFlag_EVS_PUSH_DELETE)) && !admin {
			return scope("FORCE or DELETE on a shared ref below admin")
		}
	case protocol.EvsRefKind_EVS_REF_OWNED:
		adminPush := view.has(protocol.EvsPushFlag_EVS_PUSH_BASE) || view.has(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
		if !signerOwns && !(recordClass && adminPush) {
			return refRule("an owned ref written by another sidecar")
		}
		if !write {
			return scope("an owned ref below rw")
		}
		if recordClass && !adminPush {
			if refusal := checkCreatesOnly(view); refusal != nil {
				return refusal
			}
		}
	case protocol.EvsRefKind_EVS_REF_DEPOSIT:
		if view.has(protocol.EvsPushFlag_EVS_PUSH_CONSUME) {
			if !write {
				return scope("a CONSUME below rw")
			}
			return checkRemovalsOnly(view, "a CONSUME's changes are removals")
		}
		if !signerOwns {
			return refRule("a deposit by another sidecar than its depositor")
		}
		if !view.Rights.Has(sidecar.AclEvsDeposit) && !write {
			return scope("a deposit below deposit")
		}
		if refusal := checkCreatesOnly(view); refusal != nil {
			return refusal
		}
	case protocol.EvsRefKind_EVS_REF_ERASURE:
		if !admin {
			return scope("the erasure ref below admin")
		}
		if refusal := checkCreatesOnly(view); refusal != nil {
			return refusal
		}
	}
	if view.has(protocol.EvsPushFlag_EVS_PUSH_BASE) {
		if refusal := checkRemovalsOnly(view, "a BASE's changes are removals"); refusal != nil {
			return refusal
		}
		if 0 < len(view.Payload.NewObjects) || 0 < len(view.Payload.SlotBodies) {
			return newEvsCheckRefusal(EvsCheckReasonChangeShape, "a BASE that introduces an object")
		}
	}
	return nil
}

// A creates-only ref's changes: each creates its path, writing a version on base 0. 409 naming the others.
func checkCreatesOnly(view *PushView) *EvsCheckRefusal {
	conflicts := []*sidecar.EvsCheckedChange{}
	for _, change := range view.Payload.Changes {
		if change.Change.GetBaseEntryVersion() != 0 || !change.WritesEntry() {
			conflicts = append(conflicts, change)
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	refusal := newEvsCheckRefusal(EvsCheckReasonChangeShape, "a creates-only ref changed or removed a path")
	refusal.Paths = evsChangePaths(conflicts)
	return refusal
}

// Every change a removal. 409 naming the others.
func checkRemovalsOnly(view *PushView, detail string) *EvsCheckRefusal {
	conflicts := []*sidecar.EvsCheckedChange{}
	for _, change := range view.Payload.Changes {
		if change.WritesEntry() {
			conflicts = append(conflicts, change)
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	refusal := newEvsCheckRefusal(EvsCheckReasonChangeShape, detail)
	refusal.Paths = evsChangePaths(conflicts)
	return refusal
}

// §11.13's storage limit through the quota gate, which classifies the push as payload or maintenance (QuotaPush):
// a refusal is recorded, and a quota's rate refuses nothing. The network's own QuotaRefusal comes first, as for an
// upload; then, while the repo's cluster stands at its cohort limit, what the storage limit refuses answers 507
// CLUSTER_FULL with Retry-After, recorded too (§19.9's cohorts row, §11.20).
func checkStorageLimit(view *PushView) *EvsCheckRefusal {
	if view.Quota == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no storage limit to classify against")
	}
	quotaPush := &QuotaPush{
		NetworkId:     connect.Id(view.NetworkId),
		Flags:         view.Statement.Push.GetFlags(),
		Authorization: view.Repo.GetKind() == protocol.RepoKind_REPO_KIND_CONFIG || view.Repo.GetKind() == protocol.RepoKind_REPO_KIND_MAILCFG,
	}
	for _, object := range view.Payload.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT {
			quotaPush.NewSegmentCount += 1
		}
	}
	for _, change := range view.Payload.Changes {
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil || change.EntryVersion == nil {
			continue
		}
		for _, locator := range entry.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
				quotaPush.InlineRecordCount += 1
			}
		}
	}
	quotaRefusal := view.Quota.CheckPush(quotaPush)
	if quotaRefusal == nil {
		if view.ClusterFull && QuotaRefusesAtLimit(quotaPush) {
			refusal := newEvsCheckRefusal(EvsCheckReasonClusterFull, "the storage limit at the cluster's cohort limit")
			refusal.RetryAfter = view.ClusterFullRetryAfter
			return refusal
		}
		return nil
	}
	var refusal *EvsCheckRefusal
	switch {
	case 0 < quotaRefusal.RetryAfterMs:
		refusal = newEvsCheckRefusal(EvsCheckReasonQuotaRate, "a quota's rate")
		refusal.RetryAfter = time.Duration(quotaRefusal.RetryAfterMs) * time.Millisecond
	default:
		refusal = newEvsCheckRefusal(EvsCheckReasonQuota, "the storage limit")
		if quotaRefusal.Upgrade {
			refusal.Code = protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT
		}
	}
	refusal.Quota = quotaRefusal
	return refusal
}
