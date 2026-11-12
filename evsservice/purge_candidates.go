// The purge's candidates (§11.13's purge row, D-EVS-37, I-EVS-9, FI-16), as the one pure function evs's step 5 and
// evacuation's sweep share: a versionless version V of path X is replaced at the first committed version u of X's
// ref that writes X or removes it (directly, as a listed file below a removed directory, or by the ref's DELETE), and
// u's candidates are V's kind-5 segments less every segment a version of u's push names, and V's slots when no
// version of u's push names them, which only slot-keyed repos have. A version names an id through any locator, staged
// or not and of any kind, or its slot ids, so a kind-5 segment adopted as kind 1 (§11.7's on row) or cited by a
// rename's target is never a candidate. Past 2,048 ids, or when the list would not fit the record's room, the list
// is marked and lists nothing, and the sweep recomputes it (plan-EVS2-small-readings#13).
//
// It decides nothing about time: the committing process deletes candidates only once u's commit is certain and 60 s
// have passed, rereading X's newest version and the holds first (EVSB-M10-01's Purger), and a refused or unknown push
// hands nothing on (I-EVS-2). For a push in parts the caller must pass every part's versions: a part's alone would
// leave a rename across parts listing what its target still names (questions/evs2-m10-04-purge-across-parts.md).
//
// Safe for concurrent use.

package evsservice

import (
	"crypto/sha256"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One version a push replaces or removes, as its step 4 read it: its path, in the push's path epoch, and its entry
// version. A versioned one leaves no candidate.
type PurgeReplaced struct {
	TokenPath sidecar.EvsTokenPath
	Version   *protocol.EvsEntryVersion
}

// The purge list of a push that replaces the versions replaced, whose new versions are pushVersions, for a record with
// roomByteCount left for it: its candidates in replaced's order, each without what the push names; marked when the ids
// would pass 2,048 or the list roomByteCount; empty, unmarked, when nothing is left to purge, which the record then
// carries no list for.
func PurgeCandidates(replaced []*PurgeReplaced, pushVersions []*protocol.EvsEntryVersion, roomByteCount int) *protocol.EvsPurgeList {
	list, idCount := purgeCandidateList(replaced, pushVersions)
	if sidecar.DefaultEvsFormatSettings().PurgeListMaxIdCount < idCount || roomByteCount < proto.Size(list) {
		return &protocol.EvsPurgeList{Marked: true}
	}
	return list
}

// The candidates PurgeCandidates lists, with no bound, and how many ids they name: what the sweep recomputes a marked
// list as (sweep_recompute.go).
func purgeCandidateList(replaced []*PurgeReplaced, pushVersions []*protocol.EvsEntryVersion) (*protocol.EvsPurgeList, int) {
	named := map[string]bool{}
	for _, version := range pushVersions {
		for _, locator := range version.GetChain() {
			if len(locator.GetId()) != 0 {
				named[string(locator.GetId())] = true
			}
		}
		for _, slotId := range version.GetSlotIds() {
			named[string(slotId)] = true
		}
	}
	list := &protocol.EvsPurgeList{}
	idCount := 0
	for _, entry := range replaced {
		version := entry.Version
		if version.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
			continue
		}
		candidate := &protocol.EvsPurgeCandidate{TokenPath: entry.TokenPath.Components(), ReplacedVersion: version.GetVersion()}
		listed := map[string]bool{}
		for _, locator := range version.GetChain() {
			id := locator.GetId()
			if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT ||
				len(id) != sha256.Size || named[string(id)] || listed[string(id)] {
				continue
			}
			listed[string(id)] = true
			if locator.GetStaged() {
				candidate.StagedSegmentIds = append(candidate.StagedSegmentIds, id)
			} else {
				candidate.SegmentIds = append(candidate.SegmentIds, id)
			}
		}
		for _, slotId := range version.GetSlotIds() {
			if len(slotId) != 16 || named[string(slotId)] || listed[string(slotId)] {
				continue
			}
			listed[string(slotId)] = true
			candidate.SlotIds = append(candidate.SlotIds, slotId)
		}
		if len(listed) == 0 {
			continue
		}
		idCount += len(listed)
		list.Candidates = append(list.Candidates, candidate)
	}
	return list, idCount
}
