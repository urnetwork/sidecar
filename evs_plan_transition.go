// A format-2 version's links (§11.7's content, kind 5, staged, off and on rows; FS-68; EVS2-M10-15), as one pure
// function over what the plan read of the path's previous version, so its rules hold whoever calls it:
//
//	versionless  one checkpoint, or 4 MiB chunks above 8 MiB: a written record kind 5, staged where its segment pads
//	             to at most 16 KiB; an unchanged chunk keeps its previous locator and that locator's kind, kind 5 or
//	             kind 1, never a staged one; rule (4) or a forced checkpoint writes every chunk anew
//	off          k+1 versionless over a versioned k: with its content unchanged and k's chain holding no diff or inline
//	             record, it cites k's records as kind 1, uploading nothing; else it writes one checkpoint, or chunks,
//	             as kind 5, keeping k's unchanged kind-1 chunks as kind 1
//	setting      k+1 versionless over a versionless k with its content unchanged rewrites nothing stored: k's
//	             unstaged locators stay as they are, and staged content stages again
//	on           k+1 versioned over a versionless k starts history: with its content unchanged it adopts k's unstaged
//	             kind-5 segments as kind 1, no re-upload, then kept for good; staged content becomes inline again, a
//	             record written anew, which the format-1 planner's inline rule then places; a changed one writes a
//	             checkpoint, or chunks keeping unchanged ones relabeled kind 1, never a diff on content the purge takes
//
// On every leg but ios_extension. Package-level functions are safe for concurrent use.

package sidecar

import (
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// What a format-2 version's links are made from.
type EvsPlanFormat2Args struct {
	// The new version's setting, EvsVersioningFor's.
	Versioning uint32
	Size       uint64
	Oid        EvsGitOid
	Content    EvsGitDeltaSource
	SlotKeyed  bool
	// Every record anew: a forced checkpoint, or rule (4).
	RewriteAll bool
	// The path's previous version, nil for a new path: its chain state, setting, locators and content, and whether
	// the new content is the same blob.
	Previous           *EvsChainState
	PreviousVersioning uint32
	PreviousChain      []*protocol.EvsLocator
	PreviousContent    EvsGitDeltaSource
	Unchanged          bool
}

// The links of a format-2 version and why it checkpoints (see the file header).
func EvsPlanFormat2Links(args *EvsPlanFormat2Args) ([]*EvsPlannedLink, EvsCheckpointReason, error) {
	if EvsFileMaxByteCount < args.Size {
		return nil, EvsCheckpointNone, fmt.Errorf("%w: %d bytes", ErrEvsFileTooLarge, args.Size)
	}
	versionless := args.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
	previousVersionless := args.Previous != nil && args.PreviousVersioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
	kept := func(locator *protocol.EvsLocator) (*EvsPlannedLink, bool) {
		kind := protocol.EvsLocatorKind(locator.GetKind())
		switch {
		case locator.GetStaged() || kind == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
			// a staged segment or an inline record is cited only by its own version
			return nil, false
		case !versionless && kind == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
			// the on row: adopted as kind 1, kept for good
			return &EvsPlannedLink{Kept: locator, Kind: protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT}, true
		}
		return &EvsPlannedLink{Kept: locator, Kind: kind}, true
	}
	writtenKind := protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT
	if versionless {
		writtenKind = protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT
	}

	// an unchanged version cites what it may of its previous chain: the off row, a setting change, the on row
	if args.Unchanged && args.Previous != nil && !args.RewriteAll {
		citable := args.Previous.DiffCount == 0 && !args.Previous.Inline
		links := []*EvsPlannedLink{}
		for _, locator := range args.PreviousChain {
			link, ok := kept(locator)
			if !ok {
				citable = false
				break
			}
			if versionless && !previousVersionless {
				// the off row: k's records cited as kind 1, never purged
				link.Kind = protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT
			}
			links = append(links, link)
		}
		if citable && 0 < len(links) {
			return links, EvsCheckpointNone, nil
		}
	}

	if EvsChunked(args.Size) {
		var previousSource EvsGitDeltaSource
		var previousChain []*protocol.EvsLocator
		if args.Previous != nil && args.Previous.Chunked {
			previousSource, previousChain = args.PreviousContent, args.PreviousChain
		}
		chunks, err := EvsPlanChunks(args.Content, previousSource, previousChain, args.RewriteAll)
		if err != nil {
			return nil, EvsCheckpointNone, err
		}
		links := []*EvsPlannedLink{}
		for _, chunk := range chunks {
			if chunk.Kept != nil {
				if link, ok := kept(chunk.Kept); ok {
					links = append(links, link)
					continue
				}
			}
			links = append(links, &EvsPlannedLink{Kind: writtenKind, Record: &EvsPlannedRecord{
				Kind: protocol.EvsRecordKind_EVS_RECORD_CHUNK, RecordId: NewEvsSlotId(), Oid: args.Oid,
				Body: io.NewSectionReader(args.Content, chunk.Offset, chunk.Length),
			}})
		}
		return links, EvsCheckpointChunked, nil
	}
	link := &EvsPlannedLink{Kind: writtenKind, Record: &EvsPlannedRecord{
		Kind: protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, RecordId: NewEvsSlotId(), Oid: args.Oid, Body: args.Content,
	}}
	if versionless {
		link.Staged = evsPlanStages(args.Size, args.SlotKeyed)
	}
	reason := EvsCheckpointNewFile
	switch {
	case args.Previous == nil:
	case args.RewriteAll:
		reason = EvsCheckpointRemoveGeneration
	default:
		reason = EvsCheckpointVersionless
	}
	return []*EvsPlannedLink{link}, reason, nil
}
