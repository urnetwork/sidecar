// What an instance does with data of a format past its own (§11.6's format row, D-PHASE-9, FS-72; EVS2-M2-01): a
// rolled-back format-1 binary meeting a format-2 repo/ refuses its pushes 503 before step 4 (push_step4.go), serves
// its stored bytes (read.go checks no format) and writes nothing: no fold, page-out, path-epoch copy or marker
// collection, since no commit of its own can need them and a format-2 evacuator may be moving what they would touch.
// A format-1 instance meeting a format-2 construct in a push refuses it 409 FORMAT_UNSUPPORTED {needs_format: 2},
// recorded (push.go), never as a fork, tampering or a missing segment.
//
// Serving stored bytes means reading a committed push back as it was stored, of either format: the read route, the
// newest rule and a log page parse a stored statement by format 2's shape and a stored payload or part by
// sidecar.EvsCheckStoredPayload and EvsCheckStoredPart, which take format 1's too, so a format-2 statement or entry
// version in a format-1 batch record is served as it is and its reader decides what it can open. A batch or record
// of format 2's layout, which this code does not parse, answers the read 409 FORMAT_UNSUPPORTED, with no alarm
// (read.go; EVS1-M2-39).
//
// What format-1 writers keep (testdata/evs/reserved_numbers.yml's kept): an entry's drop mark and a marker's carried
// segment and slot ids, which a format-2 collection deletes by and format 1 never wrote. A format-1 fold or copy
// carries them unchanged, a newer marker over an older one inheriting its ids, and where a write would drop them it
// alarms and keeps the content, until the orphan marker plan-EVS2-marker-carried-ids decided lands with its
// collection case and evs-11's store row (its interim; fold_format2.go).
//
// The instance's format is EvsSettings.InstanceFormat: 2 for this code, 1 for a test standing in for the rolled-back
// binary, which is how FS-72's format-1 cases run on one tree.

package evsservice

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A repo/ of a format past the instance's, which no fold, page-out, copy or collection writes to.
var ErrEvsFoldRepoFormat = errors.New("evs repo of a format past this instance's: writing nothing")

// §11.13's skip row with FS-72's format rule: repo/ read for a P2 write must be active or deleted, and of a format
// this instance writes.
func checkRepoWritable(read *EvsRepoRead, instanceFormat uint32) error {
	switch read.Object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE, protocol.EvsRepoState_EVS_REPO_DELETED:
	default:
		return fmt.Errorf("%w: state %s", ErrEvsFoldRepoState, read.Object.GetState())
	}
	if !read.FormatWithin(instanceFormat) {
		return fmt.Errorf("%w: repo/ format %d at an instance of format %d", ErrEvsFoldRepoFormat, read.Object.GetFormat(), instanceFormat)
	}
	return nil
}

// Whether the repo's format is one this instance writes: at most instanceFormat. A format-2 repo/ at a format-1
// instance answers a push 503 before anything is written and takes no fold, copy or collection write
// (plan-EVS1-format-unsupported#4).
func (self *EvsRepoRead) FormatWithin(instanceFormat uint32) bool {
	return self.Object.GetFormat() <= instanceFormat
}

// Whether a marker carries format 2's ids.
func markerCarriesIds(marker *protocol.EvsRemovalMarker) bool {
	return 0 < len(marker.GetSegmentIds()) || 0 < len(marker.GetSlotIds())
}

// next with prior's carried ids added, each once: a newer marker over an older one keeps what the older carried, so
// a collection still finds every id the removed versionless file left.
func inheritCarriedIds(prior *protocol.EvsRemovalMarker, next *protocol.EvsRemovalMarker) *protocol.EvsRemovalMarker {
	if !markerCarriesIds(prior) {
		return next
	}
	add := func(held [][]byte, carried [][]byte) [][]byte {
		for _, id := range carried {
			if !slices.ContainsFunc(held, func(heldId []byte) bool { return bytes.Equal(heldId, id) }) {
				held = append(held, bytes.Clone(id))
			}
		}
		return held
	}
	next.SegmentIds = add(next.SegmentIds, prior.GetSegmentIds())
	next.SlotIds = add(next.SlotIds, prior.GetSlotIds())
	return next
}

// A write or delete that would drop a marker's carried ids: alarmed, and the content kept, since nothing this
// instance writes names the ids for a collection to delete (plan-EVS2-marker-carried-ids's interim, until its orphan
// marker lands).
func alarmCarriedIdsDropped(log sidecar.Logger, marker *protocol.EvsRemovalMarker, what string) {
	if !markerCarriesIds(marker) {
		return
	}
	log.Errorf("[evs] alarm fold_carried_ids: %s over a marker carrying %d segment ids and %d slot ids, whose content stays", what, len(marker.GetSegmentIds()), len(marker.GetSlotIds()))
}
