// A DROP push's own rules on evs (§11.7's action, boundary and refused rows, §11.8's 5c and 5h; D-ACL-25, D-EVS-62,
// D-QUOTA-12, FS-95; DESIGN-DETAILS 10.2.5 and 10.7's note; EVS2-M10-09), as pure functions over the view step 4 built:
//
//	refs      first, at every stage: a config or mailcfg repo 409 DROP_KIND; a git-mode ref, an overlay or a
//	          creates-only ref (a record-class stream, a deposit ref, the erasure ref) 409 REF_MODE; both final. Below
//	          the admin scope 403 SCOPE, recorded (CheckDropRefs)
//	part      a part runs those and §19.11's gate (check_refs.go), and its entries' 5g and 5h as any part's: no body,
//	          list, consent or boundary rule and no evs_drops_per_day count, since only the seal reads every part
//	          (10.2.5's part row)
//	consent   in an owner-bound repo, a signer that is not a consented, not-read-only device of its owner 409
//	          DROP_CONSENT, for a cancel as for a drop (AclState.MayDrop at the validated state)
//	lock      a drop, never a cancel, under a lock standing at the validated state 409 VERSIONING
//	cancel    409 DROP_STATE unless its drop committed on this ref at cancels_version (a bit-5 version whose body is a
//	          drop of that id), neither the table nor the window after it shows it ended, and evs's clock is before
//	          its not_before_ms less DropSettings.CancelMargin (owner decision 183)
//	path      each written lineage's head, the path's newest version, which 5g holds the change's base to: a directory
//	          or versioning 2 409 DROP_PATH, versioning 1 409 VERSIONING (plan-EVS2-drop-path-visibility); a removed
//	          lineage's evs cannot judge by name, so the reserved names stay the client's and readers' to refuse
//	boundary  (CheckDropBoundary, after 5h's own checks) a written lineage has exactly one change, at its newest token
//	          path in the push's epoch, writing through_version on base through_version - 1, a file of versioning 0,
//	          self-contained: one locator naming this push's upload or an inline record, or chunk locators each this
//	          push's upload or a kind-1 locator its base names, all but the last a whole 4 MiB chunk; a removed one has
//	          none, and where its newest entry's epoch is current or a listed source, that entry's newest is the
//	          standing removal at through_version, else resolve judges it; every change is a written lineage's: else
//	          409 DROP_BOUNDARY
//	list      a written lineage's list holds its base's entry hash, found by a search over section 10's slices as
//	          received: else 409 DROP_LIST. The lists' own counts, order, repeats and hashes, and the body's shape and
//	          drop_sha256, are EvsCheckDropPayload's, where the bytes are first whole (the one-part payload, the seal)
//
// Every refusal but DROP_KIND and REF_MODE is recorded (§11.8's refuse row). evs reads no rule and decrypts nothing,
// and reads no hold/: a hold never refuses a DROP and no answer shows one (owner decision 184). One repo admin signs, no
// k of n. 5h's fence, DROPPED, for every push, is check_dropped.go's; what step 4 reads for these, and the counts
// after step 5 (the table's bound and evs_drops_per_day, a drop at the one-part push or the seal only), are
// push_drop.go's.
//
// Package-level functions are safe for concurrent use; a PushView is read only.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What step 4 read for a DROP's own rules beside the view's paths (push_drop.go).
type PushDropReads struct {
	// The DROP's lists as received: section 10's slices in part order, never joined.
	ListSlices [][]byte
	// Per removed lineage, by its index in the body, whose newest entry is in the head's current epoch or a listed
	// source: that entry's newest. A lineage the map lacks is left to the job's resolve.
	Removed map[int]*DropRemovedRead
	// A cancel's target as step 4 read it; nil for a drop.
	Cancel *DropCancelRead
	// DropSettings.CancelMargin.
	CancelMargin time.Duration
}

// A removed lineage's newest entry as step 4 read it.
type DropRemovedRead struct {
	// Whether step 4 could judge it: false for an entry absent at its epoch, copied or collected since, which resolve
	// judges against history.
	Known bool
	// Whether the path stands there; else its newest is a removal of path version RemovalVersion.
	Exists         bool
	RemovalVersion uint64
}

// A cancel's target as step 4 read it.
type DropCancelRead struct {
	// The ref's version cancels_version holds a DROP of action 1 whose drop id is cancels_drop_id, and its window.
	Found       bool
	NotBeforeMs int64
	// A cancel of it is in the head's window after it, or the table holds it ended or void.
	Ended bool
}

// D-ACL-25 as evs asks it of the validated state: sidecar.AclState's, or a test's.
type EvsDropConsent interface {
	MayDrop(subjectId sidecar.Id, repoId sidecar.Id, now time.Time) sidecar.AclDecision
}

// A state that holds its acl part: sidecar.ConfigState.
type evsAclStateHolder interface {
	Acl() (*sidecar.AclState, error)
}

// The consent auth answers through, nil when it offers none.
func evsDropConsentOf(auth sidecar.GkmAuthView) EvsDropConsent {
	switch view := auth.(type) {
	case EvsDropConsent:
		return view
	case evsAclStateHolder:
		acl, err := view.Acl()
		if err != nil || acl == nil {
			return nil
		}
		return acl
	}
	return nil
}

// Whether the view's push is a DROP or its cancel.
func (self *PushView) drop() bool {
	return self.has(protocol.EvsPushFlag_EVS_PUSH_DROP)
}

// 5c's DROP rules that need no body, at every stage, before the refs table: see the file header. A push that is no
// DROP passes, and so does a view with no repo/, which CheckRefs refuses 503, and one whose test stands in for format
// 2's rules (PushView.Format2Rules), a DROP's among them.
func CheckDropRefs(view *PushView) *EvsCheckRefusal {
	if !view.drop() || view.Repo == nil || view.Format2Rules != nil {
		return nil
	}
	push := view.Statement.Push
	switch view.Repo.GetKind() {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG:
		return newEvsCheckRefusal(EvsCheckReasonDropKind, "a DROP in a config or mailcfg repo")
	}
	refKind := protocol.EvsRefKind(push.GetRefKind())
	switch {
	case protocol.EvsRefMode(push.GetRefMode()) != protocol.EvsRefMode_EVS_REF_FILE:
		return newEvsCheckRefusal(EvsCheckReasonDropRefMode, "a DROP on a git-mode ref")
	case refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT, refKind == protocol.EvsRefKind_EVS_REF_ERASURE,
		refKind == protocol.EvsRefKind_EVS_REF_OWNED && sidecar.EvsRepoKindRecordClass(view.Repo.GetKind()):
		return newEvsCheckRefusal(EvsCheckReasonDropRefMode, "a DROP on a creates-only ref")
	case view.headExists() && view.Head.GetBase() != nil:
		return newEvsCheckRefusal(EvsCheckReasonDropRefMode, "a DROP on an overlay")
	}
	if !view.Rights.Has(sidecar.AclEvsAdmin) {
		return newEvsCheckRefusal(EvsCheckReasonScope, "a DROP below admin")
	}
	return nil
}

// 5c's DROP rules that read the body, the state and the head, at a one-part push or a seal: consent, the lock for a
// drop, a cancel's target and window, and each written lineage's head. A part passes, its body rules being its seal's;
// a view with no checked body or no reads of its own refuses 503.
func CheckDrop(view *PushView) *EvsCheckRefusal {
	if !view.drop() || view.Stage == PushStagePart {
		return nil
	}
	checked := view.Payload.Drop
	if checked == nil || view.Drop == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a DROP whose body or reads step 4 did not give")
	}
	if refusal := checkDropConsent(view); refusal != nil {
		return refusal
	}
	if checked.Cancel() {
		return checkDropCancel(view, checked.History)
	}
	if view.Auth == nil {
		return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "no authorization state to read the lock in")
	}
	if row := view.Auth.Repo(view.RepoId); row != nil && row.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED {
		return newEvsCheckRefusal(EvsCheckReasonDropVersioning, "a drop under a standing lock")
	}
	for _, path := range checked.History.GetPaths() {
		if path.GetBoundary() != evsDropBoundaryWritten {
			continue
		}
		tokenPath, err := evsDropNewestTokenPath(path)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "a lineage entry that does not parse")
		}
		read := view.Paths[tokenPath.KeyString()]
		if read == nil || read.Newest == nil || !read.Newest.Exists {
			// a written boundary over no standing path is the boundary rule's
			continue
		}
		refused := func(reason EvsCheckReason, detail string) *EvsCheckRefusal {
			refusal := newEvsCheckRefusal(reason, detail)
			refusal.Paths = []sidecar.EvsTokenPath{tokenPath}
			return refusal
		}
		if read.Newest.Directory {
			return refused(EvsCheckReasonDropPath, "a DROP of a directory")
		}
		head, refusal := evsPathNewestEntry(view, tokenPath)
		if refusal != nil {
			return refusal
		}
		if head == nil {
			continue
		}
		switch protocol.EvsVersioning(head.GetVersioning()) {
		case protocol.EvsVersioning_EVS_VERSIONING_INDEX:
			return refused(EvsCheckReasonDropPath, "a DROP of a versioning-2 file")
		case protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS:
			return refused(EvsCheckReasonDropVersioning, "a DROP of a versionless file")
		}
	}
	return nil
}

// D-ACL-25 in an owner-bound repo: only a consented, not-read-only device of its owner drops or cancels there.
func checkDropConsent(view *PushView) *EvsCheckRefusal {
	if view.Repo == nil || !sidecar.EvsRepoKindOwnerBound(view.Repo.GetKind()) {
		return nil
	}
	consent := evsDropConsentOf(view.Auth)
	if consent == nil {
		// no state that answers consent: nothing here may pass on a check it did not run
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no state that answers a drop's consent")
	}
	if decision := consent.MayDrop(view.TokenSidecarId, view.RepoId, view.Now); !decision.Allowed {
		return newEvsCheckRefusal(EvsCheckReasonDropConsent, fmt.Sprintf("a DROP in an owner-bound repo, refused for %s", decision.Reason))
	}
	return nil
}

// A cancel's target and window: see the file header.
func checkDropCancel(view *PushView, history *protocol.EvsDropHistory) *EvsCheckRefusal {
	cancel := view.Drop.Cancel
	switch {
	case cancel == nil:
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a cancel whose target step 4 did not read")
	case !cancel.Found:
		return newEvsCheckRefusal(EvsCheckReasonDropState, fmt.Sprintf("no drop committed at version %d", history.GetCancelsVersion()))
	case cancel.Ended:
		return newEvsCheckRefusal(EvsCheckReasonDropState, "a cancel of a drop no longer pending")
	case !view.Now.Before(time.UnixMilli(cancel.NotBeforeMs).Add(-view.Drop.CancelMargin)):
		return newEvsCheckRefusal(EvsCheckReasonDropState, "a cancel after its drop's window less the margin")
	}
	return nil
}

// A lineage's newest entry's token path.
func evsDropNewestTokenPath(path *protocol.EvsDropPath) (sidecar.EvsTokenPath, error) {
	lineage := path.GetLineage()
	if len(lineage) == 0 {
		return nil, fmt.Errorf("%w: a lineage with no entry", sidecar.ErrEvsPushInvalid)
	}
	return sidecar.ParseEvsChangedTokenPath(lineage[0].GetTokenPath())
}

// 5h's DROP rules at a one-part push or a seal: each lineage's boundary against the push's changes, and each written
// lineage's list holding its base. See the file header. Any other push, a part, and a view whose test stands in for
// format 2's rules pass.
func CheckDropBoundary(view *PushView) *EvsCheckRefusal {
	if !view.drop() || view.Stage == PushStagePart || view.Format2Rules != nil {
		return nil
	}
	checked := view.Payload.Drop
	if checked == nil || view.Drop == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a DROP whose body or reads step 4 did not give")
	}
	boundary := func(tokenPath sidecar.EvsTokenPath, detail string) *EvsCheckRefusal {
		refusal := newEvsCheckRefusal(EvsCheckReasonDropBoundary, detail)
		if tokenPath != nil {
			refusal.Paths = []sidecar.EvsTokenPath{tokenPath}
		}
		return refusal
	}
	push := view.Statement.Push
	changes := map[string]*sidecar.EvsCheckedChange{}
	for _, change := range view.Payload.Changes {
		changes[change.TokenPath.KeyString()] = change
	}
	if checked.Cancel() {
		if len(changes) != 0 {
			return boundary(nil, "a cancel that changes a path")
		}
		return nil
	}
	lists := newEvsDropListSlices(view.Drop.ListSlices)
	written := map[string]bool{}
	listStart := uint64(0)
	for i, path := range checked.History.GetPaths() {
		start := listStart
		listStart += uint64(path.GetCount())
		tokenPath, err := evsDropNewestTokenPath(path)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "a lineage entry that does not parse")
		}
		newestEpoch := path.GetLineage()[0].GetEpoch()
		key := tokenPath.KeyString()
		switch path.GetBoundary() {
		case evsDropBoundaryWritten:
			if newestEpoch != push.GetPathEpoch() {
				return boundary(tokenPath, "a written boundary outside the push's path epoch")
			}
			change := changes[key]
			if change == nil {
				return boundary(tokenPath, "a written boundary with no change")
			}
			written[key] = true
			if refusal := checkDropWrittenBoundary(view, path, change); refusal != nil {
				return refusal
			}
			baseHash, refusal := evsPathNewestEntryHash(view, tokenPath)
			if refusal != nil {
				return refusal
			}
			if !lists.contains(start, uint64(path.GetCount()), baseHash) {
				refusal := newEvsCheckRefusal(EvsCheckReasonDropList, "a written list without the base step 4 read")
				refusal.Paths = []sidecar.EvsTokenPath{tokenPath}
				return refusal
			}
		case evsDropBoundaryRemoved:
			if newestEpoch == push.GetPathEpoch() && changes[key] != nil {
				return boundary(tokenPath, "a removed boundary the push changes")
			}
			removed := view.Drop.Removed[i]
			if removed == nil || !removed.Known {
				continue
			}
			if removed.Exists || removed.RemovalVersion != path.GetThroughVersion() {
				return boundary(tokenPath, "a removed boundary that is not the standing removal")
			}
		default:
			return boundary(tokenPath, fmt.Sprintf("boundary %d", path.GetBoundary()))
		}
	}
	for key, change := range changes {
		if !written[key] {
			return boundary(change.TokenPath, "a change no written lineage names")
		}
	}
	return nil
}

// One written boundary's change: the path's next version, a file of versioning 0, self-contained.
func checkDropWrittenBoundary(view *PushView, path *protocol.EvsDropPath, change *sidecar.EvsCheckedChange) *EvsCheckRefusal {
	boundary := func(detail string) *EvsCheckRefusal {
		refusal := newEvsCheckRefusal(EvsCheckReasonDropBoundary, detail)
		refusal.Paths = []sidecar.EvsTokenPath{change.TokenPath}
		return refusal
	}
	throughVersion := path.GetThroughVersion()
	if !change.WritesEntry() {
		return boundary("a written boundary that removes its path")
	}
	if change.Change.GetBaseEntryVersion()+1 != throughVersion {
		return boundary("a written boundary that is not the path's next version")
	}
	read := view.Paths[change.TokenPath.KeyString()]
	if read == nil || read.Newest == nil || !read.Newest.Exists || read.Newest.Directory || read.Newest.Version+1 != throughVersion {
		return boundary("a written boundary over no standing file at its base")
	}
	entry, err := parseEvsEntryVersion(change.EntryVersion)
	if err != nil {
		return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
	}
	if entry.GetVersion() != throughVersion || protocol.EvsEntryKind(entry.GetKind()) != protocol.EvsEntryKind_EVS_ENTRY_FILE ||
		entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		return boundary("a written boundary that is not a kept file at through_version")
	}
	uploads := map[[sha256.Size]byte]bool{}
	for _, object := range view.Payload.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT && len(object.Id) == sha256.Size {
			uploads[[sha256.Size]byte(object.Id)] = true
		}
	}
	chain := entry.GetChain()
	if len(chain) == 0 {
		return boundary("a written boundary with no record")
	}
	if len(chain) == 1 {
		locator := chain[0]
		switch protocol.EvsLocatorKind(locator.GetKind()) {
		case protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
			return nil
		case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
			if len(locator.GetId()) == sha256.Size && uploads[[sha256.Size]byte(locator.GetId())] {
				return nil
			}
		}
		return boundary("a written boundary's one record is not this push's upload or an inline record")
	}
	base, refusal := evsPathNewestEntry(view, change.TokenPath)
	if refusal != nil {
		return refusal
	}
	baseLocators := map[string]bool{}
	if base != nil {
		for _, locator := range base.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT {
				baseLocators[evsLocatorKey(locator)] = true
			}
		}
	}
	chunkRecordByteCount := uint32(sidecar.EvsRecordByteCount(sidecar.EvsChunkByteCount))
	for i, locator := range chain {
		if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT || len(locator.GetId()) != sha256.Size {
			return boundary("a written boundary's chunk that is no segment")
		}
		if !uploads[[sha256.Size]byte(locator.GetId())] && !baseLocators[evsLocatorKey(locator)] {
			return boundary("a written boundary's chunk neither this push's upload nor its base's")
		}
		if i < len(chain)-1 && locator.GetLength() != chunkRecordByteCount {
			return boundary("a written boundary's chunk short of a whole chunk")
		}
	}
	return nil
}

// A kind-1 locator's identity: its segment, offset and length.
func evsLocatorKey(locator *protocol.EvsLocator) string {
	return fmt.Sprintf("%x:%d:%d", locator.GetId(), locator.GetOffset(), locator.GetLength())
}

// The entry hash of a path's newest version as step 4 read it: its window change's entry_sha256, or SHA-256 of its
// folded entry version, which, being the newest, is never elided. A path step 4 read no file version of refuses as
// the boundary rule does; an elided newest version, which no fold writes, refuses 503.
func evsPathNewestEntryHash(view *PushView, tokenPath sidecar.EvsTokenPath) ([]byte, *EvsCheckRefusal) {
	read := view.Paths[tokenPath.KeyString()]
	if read == nil || read.Newest == nil || !read.Newest.Exists {
		refusal := newEvsCheckRefusal(EvsCheckReasonDropBoundary, "a written boundary over no standing file")
		refusal.Paths = []sidecar.EvsTokenPath{tokenPath}
		return nil, refusal
	}
	switch {
	case read.Newest.Change != nil && len(read.Newest.Change.EntrySha256) == sha256.Size:
		return read.Newest.Change.EntrySha256, nil
	case read.Newest.IndexVersion != nil && !read.Newest.IndexVersion.GetElided() && len(read.Newest.IndexVersion.GetEntryVersion()) != 0:
		digest := sha256.Sum256(read.Newest.IndexVersion.GetEntryVersion())
		return digest[:], nil
	}
	return nil, newEvsCheckRefusal(EvsCheckReasonUnchecked, "a newest version with no entry hash step 4 could read")
}

// A DROP's lists as received, section 10's slices in part order, read by value index without being joined: path i's
// values are its count values from the counts before it, ascending.
type evsDropListSlices struct {
	slices [][]byte
	// each slice's first byte's offset in the whole
	starts    []uint64
	byteCount uint64
}

// The lists of slices.
func newEvsDropListSlices(slices [][]byte) *evsDropListSlices {
	lists := &evsDropListSlices{slices: slices}
	for _, slice := range slices {
		lists.starts = append(lists.starts, lists.byteCount)
		lists.byteCount += uint64(len(slice))
	}
	return lists
}

// The value at index of the whole, false past the end.
func (self *evsDropListSlices) value(index uint64) ([sha256.Size]byte, bool) {
	value := [sha256.Size]byte{}
	at := index * sha256.Size
	if self.byteCount < at+sha256.Size {
		return value, false
	}
	filled := 0
	for i, slice := range self.slices {
		start := self.starts[i]
		end := start + uint64(len(slice))
		if end <= at+uint64(filled) || at+sha256.Size <= start {
			continue
		}
		from := at + uint64(filled) - start
		filled += copy(value[filled:], slice[from:])
		if filled == sha256.Size {
			break
		}
	}
	return value, filled == sha256.Size
}

// Whether the count values from start hold value, by a binary search over values the payload checks held ascending.
func (self *evsDropListSlices) contains(start uint64, count uint64, value []byte) bool {
	low, high := uint64(0), count
	for low < high {
		middle := low + (high-low)/2
		at, ok := self.value(start + middle)
		if !ok {
			return false
		}
		switch bytes.Compare(at[:], value) {
		case 0:
			return true
		case -1:
			low = middle + 1
		default:
			high = middle
		}
	}
	return false
}
