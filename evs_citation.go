//go:build !ios_extension

// The citation rule (§11.7's content, kind 5, staged and cite rows; §11.8's 5h; I-EVS-10; FI-17), as one pure function
// that 5h and replaying readers both run, and that the client's planner can run before it signs. It answers only what
// format 2 adds, each breach ErrEvsVersioning, 409 VERSIONING:
//
//   - kind-5 locators only in versionless versions (versioning 1 or 2);
//   - each naming a staged segment of this push, an upload of this push whose receipt is marked versionless, or an
//     unstaged kind-5 locator of its path's base version or of a path this push removes, never a reuse source's;
//   - a staged segment named only by its introducing version: a later version, or a kind-1 locator, re-stages or
//     re-uploads its bytes;
//   - a versionless version's kind-1 locators only from its path's base version, or from a path this push removes
//     (plan-EVS2-slot-rename, decided), and no kind-2 locator;
//   - a versioned version's kind-1 locator naming what its sources name only as kind 5 (§11.7's on row, adopting it
//     for good) only from its path's base or a removed path, never through a reuse source;
//   - no slot a versionless version names named by another path's version, but the rename target of the push
//     removing that path (plan-EVS2-slot-rename);
//   - each kind-5 segment, and each slot of a removed versionless path, named by at most one new version of the push.
//
// What it cannot see it is told: the push's staged ids and versionless uploads (a replaying reader passes the push's
// new-objects segments as uploads, and checks each one's kind-5 header as it reads it), each new version's path base as
// step 4 read it, and the versions of the paths it removes and of its reuse sources. Format 1's own 5h rules, a kind-1
// segment's source and a slot's, stay EVS1's. A push in parts runs it per part as each arrives and once more over every
// part's versions at the seal, so the at-most-one rules hold across parts.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// A committed version a citation reads: its ref, its path in the push's path epoch, and its entry version.
type EvsCitedVersion struct {
	RefId     Id
	TokenPath EvsTokenPath
	Entry     *protocol.EvsEntryVersion
}

// One new version of a push, on the push's ref, with its path's base version as step 4 read it: nil for a creation.
type EvsCitation struct {
	TokenPath EvsTokenPath
	Version   *protocol.EvsEntryVersion
	Base      *protocol.EvsEntryVersion
}

// What a push's new versions may cite besides their bases.
type EvsCitationSources struct {
	// the push's ref, the one its new versions, bases and removed paths are on
	RefId Id
	// the push's staged segments, by id
	Staged map[[sha256.Size]byte]bool
	// the push's uploads whose receipts are marked versionless; a replaying reader's, every segment its new-objects
	// list names
	VersionlessUploads map[[sha256.Size]byte]bool
	// the newest committed version of each path the push removes
	Removed []*EvsCitedVersion
	// the committed versions its reuse list names (§11.8's 5h)
	Reuse []*EvsCitedVersion
}

// Whether a version is versionless: versioning 1 or 2.
func evsVersionless(entry *protocol.EvsEntryVersion) bool {
	return entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
}

// A path's identity across refs: its ref and token path.
type evsCitationPath struct {
	refId     Id
	tokenPath string
}

// What the sources name, by id: kind-5 locators staged or not, and kind-1 ones.
type evsCitationNames struct {
	kind5Unstaged map[[sha256.Size]byte]bool
	kind5Staged   map[[sha256.Size]byte]bool
	kind1         map[[sha256.Size]byte]bool
}

// The ids entries name, by locator kind.
func evsCitationNamesOf(entries ...*protocol.EvsEntryVersion) *evsCitationNames {
	names := &evsCitationNames{
		kind5Unstaged: map[[sha256.Size]byte]bool{},
		kind5Staged:   map[[sha256.Size]byte]bool{},
		kind1:         map[[sha256.Size]byte]bool{},
	}
	for _, entry := range entries {
		if entry == nil {
			continue
		}
		for _, locator := range entry.GetChain() {
			if len(locator.GetId()) != sha256.Size {
				continue
			}
			id := [sha256.Size]byte(locator.GetId())
			switch protocol.EvsLocatorKind(locator.GetKind()) {
			case protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
				if locator.GetStaged() {
					names.kind5Staged[id] = true
				} else {
					names.kind5Unstaged[id] = true
				}
			case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
				names.kind1[id] = true
			}
		}
	}
	return names
}

// A slot a source version names: whose path, whether versionless, and whether the push removes that path.
type evsCitationSlotSource struct {
	path        evsCitationPath
	versionless bool
	removed     bool
}

// §11.7's citation rule over a push's new versions, or a part's, with what they may cite: nil, or ErrEvsVersioning
// naming the first breach.
func EvsCheckCitation(citations []*EvsCitation, sources *EvsCitationSources) error {
	removedEntries := make([]*protocol.EvsEntryVersion, 0, len(sources.Removed))
	for _, removed := range sources.Removed {
		removedEntries = append(removedEntries, removed.Entry)
	}
	reuseEntries := make([]*protocol.EvsEntryVersion, 0, len(sources.Reuse))
	for _, reuse := range sources.Reuse {
		reuseEntries = append(reuseEntries, reuse.Entry)
	}
	removedNames := evsCitationNamesOf(removedEntries...)
	reuseNames := evsCitationNamesOf(reuseEntries...)

	// every slot a version step 4 read names, with its path: the bases, the removed paths' versions, the reuse sources
	slotSources := map[string][]*evsCitationSlotSource{}
	addSlots := func(path evsCitationPath, entry *protocol.EvsEntryVersion, removed bool) {
		if entry == nil {
			return
		}
		for _, slotId := range entry.GetSlotIds() {
			slotSources[string(slotId)] = append(slotSources[string(slotId)], &evsCitationSlotSource{
				path: path, versionless: evsVersionless(entry), removed: removed,
			})
		}
	}
	for _, citation := range citations {
		addSlots(evsCitationPath{refId: sources.RefId, tokenPath: string(citation.TokenPath.Bytes())}, citation.Base, false)
	}
	for _, removed := range sources.Removed {
		addSlots(evsCitationPath{refId: sources.RefId, tokenPath: string(removed.TokenPath.Bytes())}, removed.Entry, true)
	}
	for _, reuse := range sources.Reuse {
		addSlots(evsCitationPath{refId: reuse.RefId, tokenPath: string(reuse.TokenPath.Bytes())}, reuse.Entry, false)
	}

	// what the new versions name, for the at-most-one rules
	kind5Namers := map[[sha256.Size]byte]int{}
	slotNamers := map[string][]*EvsCitation{}
	for _, citation := range citations {
		version := citation.Version
		versionless := evsVersionless(version)
		path := evsCitationPath{refId: sources.RefId, tokenPath: string(citation.TokenPath.Bytes())}
		baseNames := evsCitationNamesOf(citation.Base)
		for _, locator := range version.GetChain() {
			kind := protocol.EvsLocatorKind(locator.GetKind())
			if kind == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
				if versionless {
					return fmt.Errorf("%w: an inline record in a versionless version", ErrEvsVersioning)
				}
				continue
			}
			if len(locator.GetId()) != sha256.Size {
				// the payload checks refuse it first; the rule judges no locator it cannot read
				return fmt.Errorf("%w: a segment locator of a %d-byte id", ErrEvsPushInvalid, len(locator.GetId()))
			}
			id := [sha256.Size]byte(locator.GetId())
			switch kind {
			case protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
				if !versionless {
					return fmt.Errorf("%w: a kind-5 locator in a versioned version", ErrEvsVersioning)
				}
				if locator.GetStaged() {
					if !sources.Staged[id] {
						return fmt.Errorf("%w: a staged locator naming no staged segment of this push", ErrEvsVersioning)
					}
				} else if !sources.VersionlessUploads[id] && !baseNames.kind5Unstaged[id] && !removedNames.kind5Unstaged[id] {
					return fmt.Errorf("%w: a kind-5 locator naming neither this push's versionless upload nor its base's or a removed path's segment", ErrEvsVersioning)
				}
				kind5Namers[id] += 1
			case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
				if sources.Staged[id] || baseNames.kind5Staged[id] || removedNames.kind5Staged[id] || reuseNames.kind5Staged[id] {
					return fmt.Errorf("%w: a staged segment cited past its introducing version", ErrEvsVersioning)
				}
				if versionless {
					if !baseNames.kind1[id] && !removedNames.kind1[id] {
						return fmt.Errorf("%w: a versionless version's kind-1 locator not from its base or a removed path", ErrEvsVersioning)
					}
					continue
				}
				// the on row: adopting kind-5 content as kind 1, only from the path's base or a removed path
				if baseNames.kind5Unstaged[id] || removedNames.kind5Unstaged[id] {
					kind5Namers[id] += 1
					continue
				}
				if reuseNames.kind5Unstaged[id] && !baseNames.kind1[id] && !removedNames.kind1[id] && !reuseNames.kind1[id] {
					return fmt.Errorf("%w: a kind-5 segment cited through a reuse source", ErrEvsVersioning)
				}
			}
		}
		for _, slotId := range version.GetSlotIds() {
			slotNamers[string(slotId)] = append(slotNamers[string(slotId)], citation)
			for _, source := range slotSources[string(slotId)] {
				if source.path == path || source.removed {
					continue
				}
				if versionless || source.versionless {
					return fmt.Errorf("%w: a slot a versionless version names, named by another path's version", ErrEvsVersioning)
				}
			}
		}
	}
	for _, count := range kind5Namers {
		if 1 < count {
			return fmt.Errorf("%w: a kind-5 segment named by %d new versions", ErrEvsVersioning, count)
		}
	}
	for slotKey, namers := range slotNamers {
		if len(namers) < 2 {
			continue
		}
		removedVersionless := false
		for _, source := range slotSources[slotKey] {
			removedVersionless = removedVersionless || (source.removed && source.versionless)
		}
		for _, namer := range namers {
			if removedVersionless || evsVersionless(namer.Version) {
				return fmt.Errorf("%w: a versionless path's slot named by %d new versions", ErrEvsVersioning, len(namers))
			}
		}
	}
	return nil
}
