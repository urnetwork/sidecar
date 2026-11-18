// What a drop job's listed versions show of its repo's history (owner decision 513; QD-987, question
// evs2-m10-33-observe-report-command): the two booleans the job records in its snap-0 file (drop_files.go's
// DropListedShape), which `sidecarctl evs observe-report` counts toward D-TEST-18's "half of them on repos with renames
// and cross-ref copies". Resolve reads them once it has judged its drops, over the versions it listed, S of each
// resolved drop, from each listed version's own push as its record holds it:
//
//	renames    a listed version's push removed one path and created another citing its kind-5 content: the push
//	           holds a removal, and a change creating a path (base_entry_version 0) whose version names an unstaged
//	           kind-5 segment the push's new-objects list does not hold. The citation rule (§11.8's 5h) lets a
//	           created path take such a segment only from a path the same push removes, so the record alone shows
//	           the rename and the removed path's version is not read
//	cross-ref  a listed version's chain named a reuse source of another ref: the push's reuse list (its payload's
//	           section 13) names a committed version of another ref, and the listed version's chain names a kind-1
//	           segment that neither the push's new-objects list nor the path's version before it holds, which 5h
//	           lets it take only from a reuse source. A kind-5 segment is never a reuse source's
//
// Both read only committed, immutable records of the ref the drop is on, so a resolve run again reads the same shape
// and writes an equal snap-0. What that costs in exactness: a push whose reuse list names versions of this ref and of
// another shows a cross-ref copy for a listed version that took its segment from the one of this ref, since the
// record does not say which source a segment came from and the other ref's history is not read; and a path's version
// before a listed one counts as its base only while the drop lists it, which it does for every version of a dropped
// path but one a removal stands before.
//
// Each listed version's push is read whole, once a ref version, a push in parts with every part, paced and counted
// as resolve's other reads and stopped once both booleans hold. The scan before it has read each such version's
// record, so a store error here is resolve's error, as there. A push whose stored payload does not check is logged
// and shows neither: the shape is evidence for a soak, and never a reason to stop a job that deletes nothing on it.

package evsservice

import (
	"context"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A listed version and its path's version before it, nil for a creation or one the drop does not list.
type dropListedVersion struct {
	hit  *dropHit
	base *protocol.EvsEntryVersion
}

// The 32 B ids an entry version's chain names, of any locator kind.
func dropChainIds(entry *protocol.EvsEntryVersion) map[[32]byte]bool {
	ids := map[[32]byte]bool{}
	for _, locator := range entry.GetChain() {
		if len(locator.GetId()) == 32 {
			ids[[32]byte(locator.GetId())] = true
		}
	}
	return ids
}

// Whether a push's payload removes one path and creates another citing kind-5 content it did not introduce: see the
// file header's renames row.
func dropPushRenames(payload *sidecar.EvsCheckedPayload, introduced map[[32]byte]bool) bool {
	removes := false
	for _, change := range payload.Changes {
		removes = removes || !change.WritesEntry()
	}
	if !removes {
		return false
	}
	for _, change := range payload.Changes {
		if !change.WritesEntry() || change.Change.GetBaseEntryVersion() != 0 {
			continue
		}
		created := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, created); err != nil {
			continue
		}
		for _, locator := range created.GetChain() {
			if locator.GetKind() == uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT) && !locator.GetStaged() &&
				len(locator.GetId()) == 32 && !introduced[[32]byte(locator.GetId())] {
				return true
			}
		}
	}
	return false
}

// Whether a listed version's chain names a kind-1 segment its push did not introduce and its path's version before it
// does not name: with a reuse source of another ref in its push, the file header's cross-ref row.
func dropListedCopies(listed *dropListedVersion, introduced map[[32]byte]bool) bool {
	baseIds := dropChainIds(listed.base)
	for _, locator := range listed.hit.entry.GetChain() {
		if locator.GetKind() != uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT) || len(locator.GetId()) != 32 {
			continue
		}
		if id := [32]byte(locator.GetId()); !introduced[id] && !baseIds[id] {
			return true
		}
	}
	return false
}

// Reads into shape what the listed versions of resolved's drops that resolved show, over the ref reader holds: see
// the file header. renew is called after each push read.
func (self *DropResolve) listedShape(reader *dropRefReader, resolved []*dropResolved, shape *DropListedShape, renew func(ctx context.Context) error) error {
	// the listed versions each push of the ref wrote, by its ref version
	versionListed := map[uint64][]*dropListedVersion{}
	for _, one := range resolved {
		if one.mismatch != "" {
			continue
		}
		for _, pathListed := range one.pathListed {
			pathVersionHits := map[uint64]*dropHit{}
			for _, hit := range pathListed {
				pathVersionHits[hit.entry.GetVersion()] = hit
			}
			for _, hit := range pathListed {
				listed := &dropListedVersion{hit: hit}
				if base := pathVersionHits[hit.baseEntryVersion]; base != nil && hit.baseEntryVersion != 0 {
					listed.base = base.entry
				}
				versionListed[hit.version] = append(versionListed[hit.version], listed)
			}
		}
	}
	versions := make([]uint64, 0, len(versionListed))
	for version := range versionListed {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	for _, version := range versions {
		if shape.Renames && shape.CrossRefCopies {
			return nil
		}
		entry, _, err := reader.entryAt(version)
		if err != nil {
			return err
		}
		_, payload, err := reader.pushAt(version, entry)
		if errors.Is(err, ErrEvsStatementMismatch) {
			self.log.Errorf("[evs] drop_shape_unread: repo %s ref %s version %d: its stored push does not check, so it shows no rename and no copy: %v",
				sidecar.EvsKeyId(reader.repoId), sidecar.EvsKeyId(reader.refId), version, err)
			continue
		}
		if err != nil {
			return err
		}
		introduced := map[[32]byte]bool{}
		for _, object := range payload.NewObjects {
			if len(object.Id) == 32 {
				introduced[[32]byte(object.Id)] = true
			}
		}
		if !shape.Renames {
			shape.Renames = dropPushRenames(payload, introduced)
		}
		otherRef := false
		for _, reuse := range payload.ReuseList {
			otherRef = otherRef || reuse.RefId != reader.refId
		}
		if otherRef && !shape.CrossRefCopies {
			for _, listed := range versionListed[version] {
				if dropListedCopies(listed, introduced) {
					shape.CrossRefCopies = true
					break
				}
			}
		}
		if renew != nil {
			if err := renew(reader.ctx); err != nil {
				return err
			}
		}
	}
	return nil
}
