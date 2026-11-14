// The CUT and index_epoch on evs (§11.12's cut row, §11.8's 5c and 5d; D-EVS-26, D-EVS-66, I-EVS-16, I-EVS-17, FI-19,
// FS-111; EVS2-M10-11). evs enforces an opaque counter and never sees a document: the erasure set's contents, the
// client's CUT and every index rule are SEARCH's.
//
//	5c   a CUT (flag 512) needs admin, in the team directory too, whose admin §7.8 mints only to its admins, so one
//	     below it is refused before any commit (I-EVS-16); it carries no other push kind's flag; and it changes one
//	     file only, created or replaced as one staged record of versioning 2, which staging bounds at 16 KiB (a set
//	     of 16,208 B under its record's header and tag), beside the directory deltas a creation's names need, with no
//	     removal: else 409 naming the paths, final
//	5d   a CUT, and a push other than a CLOSURE that creates or replaces an entry version with versioning 2 (an index
//	     file), names index_epoch equal to the head's, 0 on a ref with none, else 409 INDEX_EPOCH: final when below
//	     the head's, which never falls, and recorded when above it (§11.8's refuse row). A CLOSURE stays outside the
//	     epoch, so no eraser's CUT voids another's paid uploads (owner decision 146), and so does a push writing no
//	     index file, a settings version among them, whatever index_epoch it carries: evs reads theirs nowhere
//	7    a CUT's head carries index_epoch = its own version (push_commit.go), which head.go keeps from falling
//
// The check rides step 7's If-Match on the head it compared against, so it needs no extra read: a CUT that commits
// in between fails the CAS, and the rerun compares against the moved epoch. A CUT may create its ref's head, `ur/index`'s
// by its first push: it then names 0 and commits index_epoch 1. At the storage limit a CUT is maintenance
// (quota_gate.go), and within its network's rate it is P0 (erase.go's erasureP0).
//
// A re-seed's index_epoch, from the newest CUT it replays, is EVS2-M10-13's: reseed.go refuses format 2 until then.
//
// Package-level functions are safe for concurrent use.

package evsservice

import (
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The flags a CUT may not carry beside its own: each names another push kind, whose rules would then have to hold
// for the erasure set's one file.
const evsCutExcludedFlags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE) | uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) |
	uint32(protocol.EvsPushFlag_EVS_PUSH_BASE) | uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE) |
	uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME) | uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) |
	uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) | uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) |
	uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)

// 5c's CUT rules: see the file header. A push that is no CUT passes.
func CheckCut(view *PushView) *EvsCheckRefusal {
	if !view.has(protocol.EvsPushFlag_EVS_PUSH_CUT) {
		return nil
	}
	if !view.Rights.Has(sidecar.AclEvsAdmin) {
		return newEvsCheckRefusal(EvsCheckReasonScope, "a CUT below admin")
	}
	if view.Stage != PushStageOnePart {
		// one staged record of at most 16 KiB never needs parts, and a part's check sees only its own entries
		return newEvsCheckRefusal(EvsCheckReasonCutShape, "a CUT in parts")
	}
	shape := newEvsCheckRefusal(EvsCheckReasonCutShape, "")
	refuse := func(change *sidecar.EvsCheckedChange, detail string) {
		if shape.Detail == "" {
			shape.Detail = detail
		}
		shape.Paths = append(shape.Paths, change.TokenPath)
	}
	if view.Statement.Push.GetFlags()&evsCutExcludedFlags != 0 {
		shape.Detail = "a CUT carrying another push kind's flag"
		for _, change := range view.Payload.Changes {
			shape.Paths = append(shape.Paths, change.TokenPath)
		}
		return shape
	}
	fileCount := 0
	for _, change := range view.Payload.Changes {
		if !change.WritesEntry() {
			refuse(change, "a CUT that removes a path")
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
		}
		if protocol.EvsEntryKind(entry.GetKind()) == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			if len(entry.GetNames().GetRemovedTokens()) != 0 {
				refuse(change, "a CUT whose directory delta removes a name")
			}
			continue
		}
		fileCount += 1
		chain := entry.GetChain()
		switch {
		case 1 < fileCount:
			refuse(change, "a CUT that changes a second file")
		case protocol.EvsVersioning(entry.GetVersioning()) != protocol.EvsVersioning_EVS_VERSIONING_INDEX:
			refuse(change, fmt.Sprintf("a CUT's file of versioning %d", entry.GetVersioning()))
		case len(chain) != 1 || protocol.EvsLocatorKind(chain[0].GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT || !chain[0].GetStaged():
			refuse(change, "a CUT's file that is not one staged record")
		}
	}
	if fileCount == 0 {
		shape.Detail = "a CUT that changes no file"
		for _, change := range view.Payload.Changes {
			shape.Paths = append(shape.Paths, change.TokenPath)
		}
		return shape
	}
	if shape.Detail != "" {
		return shape
	}
	return nil
}

// Whether 5d holds the push to the head's index_epoch: a CUT, or a push other than a CLOSURE that creates or replaces
// an entry version with versioning 2. An entry version that does not parse answers an error, which refuses nothing.
func evsNamesIndexEpoch(view *PushView) (bool, error) {
	if view.has(protocol.EvsPushFlag_EVS_PUSH_CUT) {
		return true, nil
	}
	if view.has(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) {
		return false, nil
	}
	for _, change := range view.Payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return false, err
		}
		if protocol.EvsVersioning(entry.GetVersioning()) == protocol.EvsVersioning_EVS_VERSIONING_INDEX {
			return true, nil
		}
	}
	return false, nil
}

// 5d's index epoch: see the file header. A format-1 push, which carries neither a CUT nor an index file, passes, as
// does a push under a test's stand-in for format 2's rules.
func CheckIndexEpoch(view *PushView) *EvsCheckRefusal {
	if !view.NeedsFormat2 || view.Format2Rules != nil {
		return nil
	}
	names, err := evsNamesIndexEpoch(view)
	if err != nil {
		return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
	}
	if !names {
		return nil
	}
	headEpoch := uint64(0)
	if view.headExists() {
		headEpoch = view.Head.GetIndexEpoch()
	}
	pushEpoch := view.Statement.Push.GetIndexEpoch()
	var refusal *EvsCheckRefusal
	switch {
	case pushEpoch < headEpoch:
		refusal = newEvsCheckRefusal(EvsCheckReasonIndexEpochBelow, fmt.Sprintf("index_epoch %d below the head's %d", pushEpoch, headEpoch))
	case headEpoch < pushEpoch:
		refusal = newEvsCheckRefusal(EvsCheckReasonIndexEpochAbove, fmt.Sprintf("index_epoch %d above the head's %d", pushEpoch, headEpoch))
	default:
		return nil
	}
	return refusal
}

// The index_epoch the commit of push over prior carries: a CUT's own version, else prior's (§11.8's step 7).
func committedIndexEpoch(prior *protocol.EvsHead, push *protocol.EvsPush) uint64 {
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CUT) != 0 {
		return prior.GetVersion() + 1
	}
	return prior.GetIndexEpoch()
}
