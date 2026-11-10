// 5h (§11.8): the objects a push's new versions name. evs never HEADs a segment: it adopts an upload only on its
// receipt (EVSB-M2-09's CheckUploadReceipt), and a cited object only where a committed version step 4 read names it,
// so a locator to an upload that never completed fails only that file's reads, which readers alarm on.
//
//	receipts  each valid, for this repo and this signer, under 24 h old: one that does not verify refuses nothing
//	          (400), one past its age is 409 SEGMENT_GONE, recorded, and the client re-uploads
//	new       each new segment of the new-objects list carries a receipt of its id, padded size and upload day
//	segments  every segment a new version names is one of this push's uploads or appears in a version step 4 read:
//	          a changed path's base, a path the push removes (a rename), or a reuse source; else SEGMENT_GONE
//	slots     every slot a new version names is one this push introduces or one a version step 4 read names (from
//	          M2, §11.22); else 409 SLOT_UNKNOWN, recorded
//
// By stage: a one-part push runs every row. A part runs receipts and segments over its own entries, its receipts
// being its uploads, since a part's new-objects slice need not hold whole items; its slots are left to the seal. A
// seal runs the age check over every part's receipts (§11.8's seal row), each new segment's receipt, and the slot
// rule over every part's versions, the slots step 4's reads name being what the seal's view carries (EVS1-M2-13's).
// Format 2's kind-5, staged and DROPPED rows are refused before this, by the codecs; its versionless receipt, which no
// codec of a push's bytes sees, is refused here once it verifies, 409 FORMAT_UNSUPPORTED {needs_format: 2}, at an
// instance that is not format 2.
//
// An ERASE's and a CLOSURE's own rules, which read the named slots and the replaced chains, are EVS1-M2-20's, through
// PushView.ErasureRules, run last.

package evsservice

import (
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A day in milliseconds: new-objects items carry their upload's day since the Unix epoch.
const evsUploadDayMs = 24 * 60 * 60 * 1000

// 5h: see the file header.
func CheckObjects(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	signerId := sidecar.Id(push.GetSignerSidecarId())
	receiptSegments := map[[32]byte]*protocol.EvsUploadReceipt{}
	for _, receipt := range view.Receipts {
		if view.ReceiptKeys == nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no receipt keys")
		}
		err := CheckUploadReceipt(view.ReceiptKeys, receipt, view.RepoId, signerId, view.Now)
		switch {
		case errors.Is(err, ErrUploadReceiptStale):
			return newEvsCheckRefusal(EvsCheckReasonSegmentGone, "a receipt past its age")
		case err != nil:
			return newEvsCheckRefusal(EvsCheckReasonReceiptInvalid, "a receipt that does not verify")
		}
		if receipt.GetVersionless() && view.InstanceFormat != sidecar.EvsRepoFormat2 {
			// a format-2 instance's receipt for a kind-5 segment, which verifies under the keys both share: no
			// format-1 commit adopts one (§11.6's kinds row, FS-72)
			refusal := newEvsCheckRefusal(EvsCheckReasonFormatUnsupported, "a versionless receipt")
			refusal.NeedsFormat = sidecar.EvsRepoFormat2
			return refusal
		}
		receiptSegments[[32]byte(receipt.GetSegmentId())] = receipt
	}

	newSegments := map[[32]byte]bool{}
	newSlots := map[sidecar.Id]bool{}
	if view.Stage == PushStagePart {
		// a part's uploads are its receipts
		for segmentId := range receiptSegments {
			newSegments[segmentId] = true
		}
	} else {
		for _, object := range view.Payload.NewObjects {
			switch object.Kind {
			case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT:
				receipt := receiptSegments[[32]byte(object.Id)]
				if receipt == nil {
					return newEvsCheckRefusal(EvsCheckReasonReceiptInvalid, "a new segment with no receipt")
				}
				if receipt.GetPaddedSize() != object.PaddedSize || uint64(receipt.GetUploadMs())/evsUploadDayMs != uint64(object.UploadDay) {
					return newEvsCheckRefusal(EvsCheckReasonReceiptInvalid, "a new segment unlike its receipt")
				}
				newSegments[[32]byte(object.Id)] = true
			case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT:
				newSlots[sidecar.Id(object.Id)] = true
			default:
				return newEvsCheckRefusal(EvsCheckReasonFormatUnsupported, fmt.Sprintf("a new object of kind %d", object.Kind))
			}
		}
	}

	citedSegments, citedSlots, refusal := evsCitable(view)
	if refusal != nil {
		return refusal
	}
	for _, change := range view.Payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
		}
		if view.Stage != PushStageSeal {
			for _, locator := range entry.GetChain() {
				if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT {
					continue
				}
				segmentId := [32]byte(locator.GetId())
				if !newSegments[segmentId] && !citedSegments[segmentId] {
					refusal := newEvsCheckRefusal(EvsCheckReasonSegmentUnknown, "a segment neither uploaded nor named by a version read")
					refusal.Paths = []sidecar.EvsTokenPath{change.TokenPath}
					return refusal
				}
			}
		}
		if view.Stage != PushStagePart {
			for _, slotId := range entry.GetSlotIds() {
				if !newSlots[sidecar.Id(slotId)] && !citedSlots[sidecar.Id(slotId)] {
					refusal := newEvsCheckRefusal(EvsCheckReasonSlotUnknown, "a slot neither introduced nor named by a version read")
					refusal.Paths = []sidecar.EvsTokenPath{change.TokenPath}
					return refusal
				}
			}
		}
	}

	if view.has(protocol.EvsPushFlag_EVS_PUSH_ERASE) || view.has(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) {
		if view.ErasureRules == nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "an ERASE's or CLOSURE's rules are EVS1-M2-20's")
		}
		return view.ErasureRules(view)
	}
	return nil
}

// The segments and slots the versions step 4 read name: each changed path's newest version, a removed path's
// included, and each reuse source. A reuse source step 4 found no version of cites nothing, and refuses.
func evsCitable(view *PushView) (map[[32]byte]bool, map[sidecar.Id]bool, *EvsCheckRefusal) {
	segments := map[[32]byte]bool{}
	slots := map[sidecar.Id]bool{}
	cite := func(entry *protocol.EvsEntryVersion) {
		for _, locator := range entry.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT && len(locator.GetId()) == 32 {
				segments[[32]byte(locator.GetId())] = true
			}
		}
		for _, slotId := range entry.GetSlotIds() {
			if len(slotId) == 16 {
				slots[sidecar.Id(slotId)] = true
			}
		}
	}
	for _, read := range view.Paths {
		if read == nil || read.Newest == nil || !read.Newest.Exists {
			continue
		}
		var entryBytes []byte
		switch {
		case read.Newest.IndexVersion != nil:
			entryBytes = read.Newest.IndexVersion.GetEntryVersion()
		case read.Newest.Change != nil:
			entryBytes = read.Newest.Change.EntryVersion
		}
		if len(entryBytes) == 0 {
			continue
		}
		entry, err := parseEvsEntryVersion(entryBytes)
		if err != nil {
			return nil, nil, newEvsCheckRefusal(EvsCheckReasonUnchecked, "a read version that does not parse")
		}
		cite(entry)
	}
	for _, reuse := range view.Reuses {
		if reuse == nil || reuse.Reuse == nil || reuse.EntryVersion == nil || reuse.EntryVersion.GetVersion() != reuse.Reuse.EntryVersion {
			return nil, nil, newEvsCheckRefusal(EvsCheckReasonSegmentUnknown, "a reuse source with no committed version of its number")
		}
		cite(reuse.EntryVersion)
	}
	return segments, slots, nil
}
