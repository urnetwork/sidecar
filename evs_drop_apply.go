//go:build !ios_extension

// Applying an executed drop on a device (§11.7's rule and states rows, §11.11's Drops; D-CORE-19, FI-27, FS-89, FS-96;
// DESIGN-DETAILS 10.7's note; EVS2-M10-22): what a drop whose window passed with no cancel takes of what this device
// holds, decided by Covers over each version it holds, handed to Sidecar.ApplyExecutedDrop (CORE-M10-04).
//
//	covers   a held version is listed when the DROP's body covers it: its token path in its statement's epoch in a
//	         lineage, its version below that lineage's through_version, on the DROP's ref, and not a removal
//	names    what only listed versions name goes: their kind-1 segments and slots, and decrypted copies of their
//	         content. Every id or content a held version no listed one names also names stays (Live): the kept head's
//	         re-cited chunk set, a rename, a copy on another ref, a revert. Kind-5 segments stay the purge's
//	         (I-EVS-9), and statements and served entry versions are never among what a drop names
//	when     the caller hands the drop once its window passed by this device's clock, with no committed cancel and
//	         evs not reporting it refused (SidecarExecutedDrop.Executed); a device offline at the drop applies it when
//	         it syncs, and a second apply deletes nothing more
//	seam     the client holds no Sidecar: SetDropApplier names the Sidecar's ApplyExecutedDrop, which a composition
//	         sets; with none set nothing is deleted (ErrEvsDropApplierMissing), failing safe
//
// On every leg but ios_extension. Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// An executed drop on a client no composition gave Sidecar.ApplyExecutedDrop: nothing was deleted.
var ErrEvsDropApplierMissing = errors.New("evs: no drop applier on this client, so nothing was deleted")

// One version this device holds anything of, as its reader or mirror replayed it.
type EvsDropHeldVersion struct {
	// The path as this device names it. Never logged (I-13).
	Path  string
	RefId Id
	// The epoch its statement declares, and its token path there.
	Epoch     uint64
	TokenPath EvsTokenPath
	Version   uint64
	// Its entry version, nil for a removal: the segments its chain names and the slots it names.
	Entry *protocol.EvsEntryVersion
	// Its content's SHA-256, zero where this device does not know it: a decrypted copy holding these bytes is its.
	ContentSha256 [sha256.Size]byte
}

// Sets what an executed drop is handed to: the Sidecar's ApplyExecutedDrop, nil for none.
func (self *EvsClient) SetDropApplier(apply func(ctx context.Context, drop *SidecarExecutedDrop) error) {
	drops := self.dropClient()
	drops.stateLock.Lock()
	defer drops.stateLock.Unlock()
	drops.applier = apply
}

// Hands an executed drop to the applier the composition set, ErrEvsDropApplierMissing with none.
func (self *EvsClient) ApplyExecutedDrop(ctx context.Context, drop *SidecarExecutedDrop) error {
	drops := self.dropClient()
	apply := func() func(ctx context.Context, drop *SidecarExecutedDrop) error {
		drops.stateLock.Lock()
		defer drops.stateLock.Unlock()
		return drops.applier
	}()
	if apply == nil {
		return ErrEvsDropApplierMissing
	}
	return apply(ctx, drop)
}

// The executed drop the DROP statement and its checked body make over held, every version this device holds anything
// of on any ref of the repo: see the file header. mirror is the repo's sealed mirror, nil where it mirrors none.
func EvsExecutedDropOf(repoId Id, refId Id, statement *EvsStatement, body []byte, held []*EvsDropHeldVersion, mirror *EvsMirrorStore) (*SidecarExecutedDrop, error) {
	lists, err := NewEvsDropLists(statement.Push, body)
	if err != nil {
		return nil, err
	}
	history := lists.History()
	if history.GetAction() != evsDropActionDrop {
		return nil, fmt.Errorf("%w: a cancel takes nothing", ErrEvsDropInvalid)
	}
	dropId, err := IdFromBytes(history.GetDropId())
	if err != nil {
		return nil, fmt.Errorf("%w: a drop id", ErrEvsDropInvalid)
	}
	drop := &SidecarExecutedDrop{RepoId: repoId, RefId: refId, DropId: dropId, NotBefore: evsTime(history.GetNotBeforeMs()), Mirror: mirror}
	liveIds := map[string]bool{}
	liveContents := map[[sha256.Size]byte]bool{}
	for _, version := range held {
		if version == nil || version.Entry == nil {
			continue
		}
		_, covered := lists.Lists(version.Epoch, version.TokenPath, version.Version, false)
		covered = covered && version.RefId == refId
		segmentIds := [][]byte{}
		for _, locator := range version.Entry.GetChain() {
			kind := protocol.EvsLocatorKind(locator.GetKind())
			if len(locator.GetId()) == 0 || kind == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
				continue
			}
			if !covered || kind == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT {
				// what a live version names stays, and a kind-5 segment is the purge's
				liveIds[string(locator.GetId())] = true
				continue
			}
			segmentIds = append(segmentIds, locator.GetId())
		}
		slotIds := []Id{}
		for _, slotIdBytes := range version.Entry.GetSlotIds() {
			if !covered {
				liveIds[string(slotIdBytes)] = true
				continue
			}
			if slotId, err := IdFromBytes(slotIdBytes); err == nil {
				slotIds = append(slotIds, slotId)
			}
		}
		if !covered {
			if version.ContentSha256 != ([sha256.Size]byte{}) {
				liveContents[version.ContentSha256] = true
			}
			continue
		}
		drop.Versions = append(drop.Versions, &SidecarDroppedVersion{
			Path: version.Path, Version: version.Version, ContentSha256: version.ContentSha256, SegmentIds: segmentIds, SlotIds: slotIds,
		})
	}
	drop.Live = func(ctx context.Context, object SidecarDropObject) (bool, error) {
		switch object.Kind {
		case SidecarDropSegment, SidecarDropSlot:
			return liveIds[string(object.Id)], nil
		case SidecarDropContent:
			var sum [sha256.Size]byte
			copy(sum[:], object.Id)
			return liveContents[sum], nil
		}
		// a kind this build does not know keeps the object
		return true, nil
	}
	return drop, nil
}
