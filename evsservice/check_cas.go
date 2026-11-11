// 5e, 5f and 5g (§11.8): the path epoch, the base and the path-level CAS.
//
//	5e  a push planned on no head (base version 0) on a ref that has one is final 409 before its epoch is compared,
//	    BASE_STALE in file mode and non-fast-forward in git mode: it commits only as the push that creates the ref,
//	    and its sender plans again on the head (DESIGN-DETAILS 9.2.6's once line). A push names the head's current
//	    path epoch, an older or other one getting final 412 PATH_EPOCH, on which the client re-tokenizes. A ref with
//	    no head starts in the epoch its first push names (9.2.6's first push, QD-632): 1 on a deposit or erasure
//	    ref, an overlay's base ref's current epoch as step 4 read its head, and otherwise any epoch from 1 to the
//	    push's generation, else 412 PATH_EPOCH. A push creating a path (a change on base 0, or a directory add)
//	    while the head's due_blocks_creation holds, or before its block_until_ms, or whose own commit would record a
//	    due that blocks creation (9.2.6's crossing creation, PushView.CrossingDue, counted on a ref with no head from
//	    the epoch its push names), gets 412 PATH_EPOCH_DUE, recorded, the refusal's fence write recording that due as
//	    the commit would have (refuse.go), where there is a head to carry one; an overlay's first push creating a
//	    path while its base ref's head blocks creation is refused the same way. A PATH_EPOCH push's own rules (map
//	    parts, source binding, tail, fold) are EVS1-M2-16's, through PushView.PathEpochRules.
//	5f  git mode: b = v (TIP), else final 409 non-fast-forward, and no other push's live seal lease, else 429 with
//	    the lease's remaining time, refusing nothing; file mode: v - 63 <= b <= v, so the push lands within
//	    (b, b+64], else final 409 BASE_STALE, which on the caller's own deposit ref carries its head
//	    (plan-EVS1-deposit-head); either mode: base_chain is C_b as the history holds it.
//	5g  each changed file's newest committed version (§11.7's newest rule, which step 4 ran) equals its
//	    base_entry_version, 0 naming it absent, and each new version follows the versions rule: base + 1, or for a
//	    creation max(b, m) + 1 with b the effective base version (I-EVS-8); a file over a standing directory, or a
//	    directory over a standing file, conflicts on a file-mode ref, and on a git-mode ref is a creation of the new
//	    kind, base 0 and the creation's version, the push removing what stood below a replaced directory by its own
//	    changes, which only a replaying reader can check (DESIGN-DETAILS 8.2.2's kinds row). A part of a push on a ref
//	    with no head defers a creation's version to the seal, which runs 5g again over the joined payload: only the
//	    seal holds the overlay base section 16 names, which the effective base version counts. Directory deltas merge
//	    without a CAS, but for §11.7's two-way
//	    check: a push removing D conflicts if a delta to D committed after its base, and a push changing D conflicts
//	    if D's removal, its own or a prefix's, committed after its base. A directory's creation is a CAS like a file's,
//	    since it starts its table again. Every conflict is final, 409 naming every conflicting path; then each
//	    directory the push writes is held to 4,096 children and 448 KiB of name table over its listing at the head
//	    plus the push's delta (409 DIRECTORY_FULL, recorded). Git mode runs the same over the paths it changes, TIP
//	    already implying them for a ref with no overlay.

package evsservice

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.8's 5f: a file-mode push's base lies within 63 versions of the head, so it lands within (b, b+64].
const evsFileModeBaseWindow = 63

// 5e: see the file header.
func CheckPathEpoch(view *PushView) *EvsCheckRefusal {
	if view.has(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) {
		if view.PathEpochRules == nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a PATH_EPOCH push's rules are EVS1-M2-16's")
		}
		return view.PathEpochRules(view)
	}
	push := view.Statement.Push
	if view.headVersion() == 0 {
		return checkFirstPushEpoch(view)
	}
	if push.GetBaseVersion() == 0 && !evsFirstPushOnceSkipped {
		// planned on no head, it commits only as the push that creates the ref (DESIGN-DETAILS 9.2.6's once line)
		detail := fmt.Sprintf("a push planned on no head, on a ref at version %d", view.Head.GetVersion())
		if protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT {
			return newEvsCheckRefusal(EvsCheckReasonNonFastForward, detail)
		}
		return baseStale(view, detail)
	}
	current := EvsHeadCurrentEpoch(view.Head)
	if epoch := push.GetPathEpoch(); epoch != current {
		return newEvsCheckRefusal(EvsCheckReasonPathEpoch, fmt.Sprintf("path epoch %d, the head's %d", epoch, current))
	}
	if !view.Payload.CreatesPath {
		return nil
	}
	pathEpoch := view.Head.GetPathEpoch()
	crossing := view.CrossingDue != nil && view.CrossingDue.blocks
	if crossing || pathEpoch.GetDueBlocksCreation() || view.Now.UnixMilli() < pathEpoch.GetBlockUntilMs() {
		return creationRefusal(view, "a creation while the path epoch is due or blocked, or crossing a due that blocks it")
	}
	return nil
}

// A test's hook that lets a push planned on no head through on a ref that has one, as 5e did before the once line:
// what DESIGN-DETAILS 9.6's PathEpochTwin-StaleFirstPush schedule needs to show the creation over a standing file the
// line prevents. false outside tests.
var evsFirstPushOnceSkipped bool

// 5e on a ref with no head, absent or a placeholder a refusal or evacuation left (DESIGN-DETAILS 9.2.6's first push,
// QD-632): the epoch its first push names, 1 on a deposit or erasure ref, its base ref's current epoch on an overlay,
// and within 1 to its generation on any other ref, else 412 PATH_EPOCH; then a creation crossing a due that blocks
// it, counted from that epoch, or an overlay's while its base ref's head blocks creation, 412 PATH_EPOCH_DUE,
// recorded in the placeholder head with no due, there being no head to carry one.
func checkFirstPushEpoch(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	epoch, generation := push.GetPathEpoch(), push.GetGeneration()
	refKind := protocol.EvsRefKind(push.GetRefKind())
	var base *protocol.EvsHead
	switch {
	case refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || refKind == protocol.EvsRefKind_EVS_REF_ERASURE:
		if epoch != 1 {
			return newEvsCheckRefusal(EvsCheckReasonPathEpoch, fmt.Sprintf("path epoch %d on a deposit or erasure ref, which stays at 1", epoch))
		}
	case view.Payload.Base != nil:
		base = view.OverlayBase
		if base == nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "an overlay base step 4 did not read")
		}
		if baseEpoch := EvsHeadCurrentEpoch(base); epoch != baseEpoch || generation < epoch {
			return newEvsCheckRefusal(EvsCheckReasonPathEpoch, fmt.Sprintf("path epoch %d on an overlay whose base ref's is %d", epoch, baseEpoch))
		}
	default:
		if epoch == 0 || generation < epoch {
			return newEvsCheckRefusal(EvsCheckReasonPathEpoch, fmt.Sprintf("path epoch %d on a ref with no head, at generation %d", epoch, generation))
		}
	}
	if !view.Payload.CreatesPath {
		return nil
	}
	if view.CrossingDue != nil && view.CrossingDue.blocks {
		return creationRefusal(view, "a ref's first push creating across a due that blocks creation, counted from the epoch it names")
	}
	if base != nil {
		basePathEpoch := base.GetPathEpoch()
		if basePathEpoch.GetDueBlocksCreation() || view.Now.UnixMilli() < basePathEpoch.GetBlockUntilMs() {
			return creationRefusal(view, "an overlay's first push creating while its base ref blocks creation")
		}
	}
	return nil
}

// 412 PATH_EPOCH_DUE, recorded, naming every path the push creates.
func creationRefusal(view *PushView, detail string) *EvsCheckRefusal {
	refusal := newEvsCheckRefusal(EvsCheckReasonPathEpochDue, detail)
	for _, change := range view.Payload.Changes {
		if change.Change.GetBaseEntryVersion() == 0 && change.WritesEntry() {
			refusal.Paths = append(refusal.Paths, change.TokenPath)
		}
	}
	return refusal
}

// 5f: see the file header.
func CheckBase(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	baseVersion := push.GetBaseVersion()
	version := view.headVersion()
	switch protocol.EvsRefMode(push.GetRefMode()) {
	case protocol.EvsRefMode_EVS_REF_GIT:
		if baseVersion != version {
			return newEvsCheckRefusal(EvsCheckReasonNonFastForward, fmt.Sprintf("base %d at version %d", baseVersion, version))
		}
		if lease := view.Head.GetLease(); lease != nil && len(lease.GetPushId()) != 0 &&
			!bytes.Equal(lease.GetPushId(), push.GetPushId()) && view.Now.UnixMilli() < lease.GetUntilMs() {
			refusal := newEvsCheckRefusal(EvsCheckReasonLeaseHeld, "another push's live seal lease")
			refusal.RetryAfter = timeUntilMs(view, lease.GetUntilMs())
			return refusal
		}
	case protocol.EvsRefMode_EVS_REF_FILE:
		if version < baseVersion || (evsFileModeBaseWindow < version && baseVersion < version-evsFileModeBaseWindow) {
			return baseStale(view, fmt.Sprintf("base %d at version %d", baseVersion, version))
		}
	default:
		return newEvsCheckRefusal(EvsCheckReasonRefRule, fmt.Sprintf("ref mode %d", push.GetRefMode()))
	}
	if view.BaseChain == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no chain at the base version")
	}
	if !bytes.Equal(push.GetBaseChain(), view.BaseChain[:]) {
		if protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT {
			return newEvsCheckRefusal(EvsCheckReasonNonFastForward, "a base chain the history does not hold")
		}
		return baseStale(view, "a base chain the history does not hold")
	}
	return nil
}

// 5f's file-mode refusal, carrying the head on the caller's own deposit ref.
func baseStale(view *PushView, detail string) *EvsCheckRefusal {
	refusal := newEvsCheckRefusal(EvsCheckReasonBaseStale, detail)
	push := view.Statement.Push
	if protocol.EvsRefKind(push.GetRefKind()) == protocol.EvsRefKind_EVS_REF_DEPOSIT &&
		bytes.Equal(push.GetOwnerSidecarId(), view.TokenSidecarId.Bytes()) {
		depositHead := &protocol.EvsDepositHead{}
		if view.headExists() {
			depositHead.Version = view.Head.GetVersion()
			depositHead.Chain = bytes.Clone(view.Head.GetChain())
			depositHead.ConsumedThrough = view.Head.GetConsumedThrough()
		} else {
			chain := sidecar.EvsChainStart(view.RepoId, sidecar.Id(push.GetRefId()))
			depositHead.Chain = chain[:]
		}
		refusal.DepositHead = depositHead
	}
	return refusal
}

// 5g: see the file header.
func CheckPaths(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	effectiveBaseVersion := EffectiveBaseVersion(push.GetBaseVersion(), view.OverlayBaseVersions)
	gitMode := protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT
	// a part on a ref with no head cannot know the overlay base its seal's section 16 names
	deferVersions := view.Stage == PushStagePart && !view.headExists()
	var conflict *EvsCheckRefusal
	conflicted := func(reason EvsCheckReason, change *sidecar.EvsCheckedChange, detail string) {
		if conflict == nil {
			conflict = newEvsCheckRefusal(reason, detail)
		}
		conflict.Paths = append(conflict.Paths, change.TokenPath)
	}
	directories := []*directoryWrite{}
	for _, change := range view.Payload.Changes {
		read := view.Paths[change.TokenPath.KeyString()]
		if read == nil || read.Newest == nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a changed path step 4 did not read")
		}
		newest := read.Newest
		baseEntryVersion := change.Change.GetBaseEntryVersion()
		// a removal or a delta after this push's base was committed by a push it could not have read
		changedAfterBase := push.GetBaseVersion() < newest.CommitVersion
		if !change.WritesEntry() {
			if newest.Exists && newest.Directory {
				if changedAfterBase {
					conflicted(EvsCheckReasonDirectoryRemoved, change, "a directory removed after a delta past its base")
				}
				continue
			}
			if err := CheckPathVersion(newest, baseEntryVersion, 0, true, effectiveBaseVersion); err != nil {
				conflicted(EvsCheckReasonPathConflict, change, err.Error())
			}
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
		}
		if protocol.EvsEntryKind(entry.GetKind()) == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			switch {
			case baseEntryVersion == 0 && newest.Exists && !(gitMode && !newest.Directory):
				conflicted(EvsCheckReasonPathConflict, change, "a directory created over a standing path")
				continue
			case baseEntryVersion == 0:
				// absent, or on a git-mode ref a standing file the directory replaces
				expected := ExpectedEntryVersion(0, effectiveBaseVersion, newest.RemovalVersion)
				if entry.GetVersion() != expected && !deferVersions {
					conflicted(EvsCheckReasonVersionRule, change, fmt.Sprintf("version %d, the rule's %d", entry.GetVersion(), expected))
					continue
				}
			case !newest.Exists && changedAfterBase:
				conflicted(EvsCheckReasonDirectoryRemoved, change, "a delta to a directory removed after its base")
				continue
			case !newest.Exists || !newest.Directory:
				conflicted(EvsCheckReasonPathConflict, change, "a delta to a path that is no directory")
				continue
			}
			directories = append(directories, &directoryWrite{change: change, read: read, delta: entry.GetNames(), creation: baseEntryVersion == 0})
			continue
		}
		if newest.Exists && newest.Directory {
			if !gitMode || baseEntryVersion != 0 {
				conflicted(EvsCheckReasonPathConflict, change, "a file written over a standing directory")
				continue
			}
			// git mode: a creation of a file where the directory stood
			expected := ExpectedEntryVersion(0, effectiveBaseVersion, newest.RemovalVersion)
			if entry.GetVersion() != expected && !deferVersions {
				conflicted(EvsCheckReasonVersionRule, change, fmt.Sprintf("version %d, the rule's %d", entry.GetVersion(), expected))
			}
			continue
		}
		err = CheckPathVersion(newest, baseEntryVersion, entry.GetVersion(), false, effectiveBaseVersion)
		if deferVersions && baseEntryVersion == 0 && errors.Is(err, ErrEvsVersionRule) {
			err = nil
		}
		switch {
		case errors.Is(err, ErrEvsVersionRule):
			conflicted(EvsCheckReasonVersionRule, change, err.Error())
		case err != nil:
			conflicted(EvsCheckReasonPathConflict, change, err.Error())
		}
	}
	if conflict != nil {
		return conflict
	}
	for _, directory := range directories {
		if refusal := directory.checkBound(); refusal != nil {
			return refusal
		}
	}
	return nil
}

// A directory a push writes: its change, its read and its delta.
type directoryWrite struct {
	change   *sidecar.EvsCheckedChange
	read     *PathRead
	delta    *protocol.EvsNameTable
	creation bool
}

// §11.7's bound over the directory's listing at the head and the push's delta: a creation's table is its delta's
// rows alone, a delta's the listing less the tokens it removes and with the rows it adds.
func (self *directoryWrite) checkBound() *EvsCheckRefusal {
	rows := map[sidecar.EvsToken]*protocol.EvsName{}
	if !self.creation {
		if self.read.Listing == nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a directory delta with no listing read")
		}
		for _, row := range self.read.Listing.Names {
			if token, err := sidecar.EvsTokenFromBytes(row.GetToken()); err == nil {
				rows[token] = row
			}
		}
		for _, removed := range self.delta.GetRemovedTokens() {
			if token, err := sidecar.EvsTokenFromBytes(removed); err == nil {
				delete(rows, token)
			}
		}
	}
	for _, row := range self.delta.GetNames() {
		if token, err := sidecar.EvsTokenFromBytes(row.GetToken()); err == nil {
			rows[token] = row
		}
	}
	table := &protocol.EvsNameTable{Names: sortedEvsNameRows(rows)}
	childCount := len(table.GetNames())
	boundByteCount := sidecar.EvsNameTableBoundByteCount(table)
	if sidecar.EvsDirectoryMaxChildCount < childCount || sidecar.EvsNameTableMaxBoundByteCount < boundByteCount {
		refusal := newEvsCheckRefusal(EvsCheckReasonDirectoryFull, fmt.Sprintf("%d children and %d bytes of name table", childCount, boundByteCount))
		refusal.Paths = []sidecar.EvsTokenPath{self.change.TokenPath}
		return refusal
	}
	return nil
}
