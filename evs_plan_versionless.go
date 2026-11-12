// The versionless write planner (§11.7's Versionless rows; R-EVS-7, R-EVS-14, R-EVS-20, D-EVS-35, D-EVS-36, D-EVS-38,
// D-EVS-40, I-EVS-10, FI-17, FS-64, FS-67, FS-68; EVS2-M10-15): the chain of a file version whose versioning, as
// EvsVersioningFor chose it (evs_versioning.go), is 1 or 2, or whose path's previous version's was, so the planner
// never picks a setting of its own.
//
//	content   one checkpoint record, or 4 MiB chunk records above 8 MiB, never a diff or an inline record, so
//	          checkpoint rules (1) to (3) do not apply; rule (4), a REMOVE generation newer than the key, makes the
//	          next write re-encrypt every chunk; content_sha256, the whole plaintext's SHA-256, joins its sealed fields
//	kinds     kind 5 for what this push writes and for unchanged chunks its path's previous version named as kind 5;
//	          kind 1 for chunks that version named as kind 1 (versioning just turned off; never purged); a staged
//	          locator is never kept, a later version re-staging its bytes
//	staged    a record whose kind-5 segment pads to at most 16 KiB stages in the push (EvsPlannedLink.Staged); a
//	          larger one uploads under a header naming the push, which the sender seals (EVS2-M10-16)
//	keys      a general repo's kind-5 segment carries its key in its sealed header; a slot-keyed repo keeps a
//	          versionless path's one key in a slot only that path's versions name, reused by each next version
//	          (EvsPlannedPath.ReuseSlotKey) until rule (4), a CLOSURE or a rekey draws a fresh one in a new slot, so an
//	          overwrite writes no slot
//	off, on   the transitions are evs_plan_transition.go's
//
// Not built, failing closed: a rename, as the format-1 planner builds none (evs_plan.go's header), so a versionless
// rename's citation of the removed path's unstaged kind-5 chain waits for it; a copy re-uploads, which a write does
// anyway. ur/lfs objects never stage (plan-EVS2-small-readings#8), and the git-lfs store is EVS2-M10-24's, which this
// planner refuses as a reserved ref until it lands.
//
// On every leg but ios_extension. Not safe for concurrent use: one plan at a time per write.

package sidecar

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether a version's chain is format 2's: it is versionless, or its path's previous version was.
func evsPlanIsFormat2(write *EvsPathWrite, verified *EvsVerifiedPath) bool {
	if write.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		return true
	}
	return verified != nil && verified.Entry != nil && verified.Entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
}

// The SHA-256 of content's whole plaintext, read a piece at a time (R-EVS-14).
func evsContentSha256(content EvsGitDeltaSource) ([]byte, error) {
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(content, 0, content.Size())); err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

// Whether a checkpoint of size bytes, its record in a kind-5 segment, pads to at most 16 KiB and so stages: in a
// general repo past the header and the key block, in a slot-keyed one past the header alone.
func evsPlanStages(size uint64, slotKeyed bool) bool {
	offset := uint64(evsKind5KeyedRecordOffset)
	if slotKeyed {
		offset = EvsKind5SegmentHeaderByteCount
	}
	return EvsPadme(offset+EvsRecordByteCount(size)) <= EvsStagedSegmentMaxByteCount
}

// A format-2 version's chain (see the file header): its setting, content_sha256, and its records and kept locators
// by evsPlanFormat2Links' rules, with what the path's previous version and the chain's key give.
func (self *EvsRepo) planFormat2Chain(ctx context.Context, plan *EvsWritePlan, planned *EvsPlannedPath, write *EvsPathWrite, verified *EvsVerifiedPath, previous *EvsChainState, previousContent *evsSpill, previousKeys *evsChainKeys, previousFields *protocol.EvsSealedFields, oid EvsGitOid) error {
	content := write.Content
	size := uint64(content.Size())
	planned.Versioning = write.Versioning
	removeSince := false
	if previous != nil {
		var err error
		removeSince, err = evsRemoveGenerationSince(ctx, self.client.args.Gkm, self.repoId, previous.KeyGeneration, plan.Generation)
		if err != nil {
			return err
		}
	}
	if planned.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		contentSha256, err := evsContentSha256(content)
		if err != nil {
			return err
		}
		planned.Fields.ContentSha256 = contentSha256
	}
	args := &EvsPlanFormat2Args{
		Versioning: planned.Versioning, Size: size, Oid: oid, Content: content, SlotKeyed: plan.slotKeyed,
		RewriteAll: write.ForceCheckpoint || removeSince,
	}
	if previous != nil && verified != nil && verified.Entry != nil {
		args.Previous = previous
		args.PreviousVersioning = verified.Entry.GetVersioning()
		args.PreviousChain = verified.Entry.GetChain()
		args.PreviousContent = previousContent
		args.Unchanged = previous.Size == size && previousFields != nil && string(previousFields.GetGitOid()) == string(oid[:])
	}
	links, reason, err := EvsPlanFormat2Links(args)
	if err != nil {
		return err
	}
	planned.Checkpoint = reason
	planned.Chain = links
	// a versionless version never rides inline; a versioned one over versionless content takes the inline rule, so
	// staged content becomes inline again (§11.7's on row)
	planned.Inline = false
	if planned.Versioning == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) && len(links) == 1 && links[0].Record != nil &&
		links[0].Record.Kind == protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT {
		planned.Inline = !plan.slotKeyed && EvsPadme(EvsWrappedKeyByteCount+EvsRecordByteCount(size)) <= EvsInlineMaxByteCount
	}
	if plan.slotKeyed {
		for _, link := range links {
			if link.Kept == nil {
				continue
			}
			if previousKeys == nil {
				return fmt.Errorf("%w: a kept locator of a chain whose keys the plan did not open", ErrEvsWriteInvalid)
			}
			slotId, ok := previousKeys.slotOf(link.Kept)
			if !ok {
				return fmt.Errorf("%w: a kept locator under no slot key", ErrEvsWriteInvalid)
			}
			planned.keptSlotIds = append(planned.keptSlotIds, slotId)
		}
		// a versionless path's one key, reused by each next version until rule (4), a CLOSURE or a rekey
		if planned.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) && args.PreviousVersioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) &&
			!args.RewriteAll && previousKeys != nil && previousKeys.chain != nil {
			planned.chainKey = previousKeys.chain
			planned.ReuseSlotKey = true
		}
	}
	return nil
}
