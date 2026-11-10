//go:build !ios_extension

// EvsRepo.Write and WritePaths (§11.20, §18.5; EVS1-M2-25, EVS1-M2-26): files written or removed on a file-mode ref
// in one push. Head mode cannot build a git tree, which needs every sibling's oid, so a git-mode ref answers
// EVS_GIT_REF and is written through the local tier (§11.7). Format 1 writes versioning on only.
//
// Each attempt: GkmClient.EnsureWritable first, so nothing is sealed to a generation a non-reader holds (§8.12); a
// plan on a verified read (evs_plan.go); its records sealed (evs_upload.go); a new push id; its segments uploaded with
// ?push=P; the statement built on the head the plan read and sent, retried under that one push id until evs answers
// (evs_push.go), and re-tokenized on 412 PATH_EPOCH with what it sealed kept (DESIGN-DETAILS 9.2.5). A refusal asking
// for a rebuild runs the attempt again under a new push id from a fresh read; rebuilds and retokens together at most
// PushRebuildCount times; a creation refused 409 is planned once more, since the removal a fresh read shows sets its
// version (§11.7's versions row), unless the path now stands, whose 409 then goes back; a creation the ref's coming
// path epoch holds, 412 PATH_EPOCH_DUE or the planner's ErrEvsPathEpochDue, is planned again after its wait or at
// the ref's next verified head, at most PushRetryCount times, then ErrEvsPathEpochDue (DESIGN-DETAILS 9.2.5); every
// other refusal, a file-mode 409 with paths among them, goes back to the caller.
//
// On every leg. Safe for concurrent use, each call its own push.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// What WritePaths writes.
type EvsWritePathsArgs struct {
	// The ref's name bytes: nil writes main.
	RefName []byte
	Writes  []*EvsPathWrite
}

// What a committed WritePaths did.
type EvsWritePathsResult struct {
	PushId Id
	// The ref version it committed at.
	Version uint64
	// Each write's path version, in the args' order: a removal's is the one it removed past.
	PathVersions []uint64
}

// Writes or removes one file on a file-mode ref: see the file header.
func (self *EvsRepo) Write(ctx context.Context, args *EvsWriteArgs) (*EvsWriteResult, error) {
	switch args.Versioning {
	case "", "on":
	case "off":
		return nil, fmt.Errorf("%w: versioning off is format 2's", ErrEvsFormatUnsupported)
	default:
		return nil, fmt.Errorf("%w: versioning %q", ErrEvsWriteInvalid, args.Versioning)
	}
	write := &EvsPathWrite{Path: args.Path, Mode: args.Mode, Remove: args.Remove, ForceCheckpoint: args.ForceCheckpoint}
	if !args.Remove {
		if args.Content == nil || args.Size < 0 || EvsFileMaxByteCount < args.Size {
			return nil, fmt.Errorf("%w: content of %d bytes", ErrEvsWriteInvalid, args.Size)
		}
		spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
		defer spill.close()
		copied, err := io.Copy(spill, io.LimitReader(args.Content, args.Size+1))
		if err != nil {
			return nil, err
		}
		if copied != args.Size {
			return nil, fmt.Errorf("%w: content of %d bytes, not %d", ErrEvsWriteInvalid, copied, args.Size)
		}
		write.Content = spill
	}
	result, err := self.WritePaths(ctx, &EvsWritePathsArgs{RefName: args.RefName, Writes: []*EvsPathWrite{write}})
	if err != nil {
		return nil, err
	}
	return &EvsWriteResult{PushId: result.PushId, Version: result.Version, PathVersion: result.PathVersions[0]}, nil
}

// Writes and removes paths on a file-mode ref in one push: see the file header. What KEYS-M2-26's ur evs rekey
// writes through, each path's ForceCheckpoint set.
func (self *EvsRepo) WritePaths(ctx context.Context, args *EvsWritePathsArgs) (*EvsWritePathsResult, error) {
	return self.writePaths(ctx, args, nil)
}

// WritePaths with what the push carries beside its changes, nil for none: a CLOSURE's flag, erased list and scope.
func (self *EvsRepo) writePaths(ctx context.Context, args *EvsWritePathsArgs, extras *evsPushExtras) (*EvsWritePathsResult, error) {
	refName := args.RefName
	if refName == nil {
		refName = EvsMainRefName
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	var creations map[string]bool
	rebuilds := 0
	dueWaits := 0
	for attempt := 0; ; attempt += 1 {
		result, plan, err := self.writeOnce(ctx, args.Writes, refName, refId, 0 < attempt, &rebuilds, extras)
		switch {
		case err == nil:
			return result, nil
		case errors.Is(err, ErrEvsPathEpochDue) || IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE):
			if self.client.settings.PushRetryCount <= dueWaits {
				if errors.Is(err, ErrEvsPathEpochDue) {
					return nil, err
				}
				return nil, fmt.Errorf("%w: %w", ErrEvsPathEpochDue, err)
			}
			dueWaits += 1
			if err := self.waitPathEpoch(ctx, refId, err); err != nil {
				return nil, err
			}
		case (evsNeedsRebuild(err) || errors.Is(err, errEvsPlanEpochMoved) || errors.Is(err, errEvsRetokenSealsAgain)) &&
			rebuilds < self.client.settings.PushRebuildCount:
			rebuilds += 1
			continue
		case evsCreationConflict(err) && creations == nil && plan != nil:
			creations = map[string]bool{}
			for _, planned := range plan.Paths {
				if planned.BaseEntryVersion == 0 && !planned.Remove {
					creations[planned.Path] = true
				}
			}
			if len(creations) == 0 {
				return nil, err
			}
			// read the removal the first read did not show, and plan once more, unless a creation now stands
			retried, _, retryErr := self.writeOnce(ctx, args.Writes, refName, refId, true, &rebuilds, extras, creations)
			if retryErr == nil {
				return retried, nil
			}
			if errors.Is(retryErr, errEvsCreationStands) {
				return nil, err
			}
			return nil, retryErr
		default:
			return nil, err
		}
	}
}

// A creation refused 409 now stands: the refusal goes back to the caller.
var errEvsCreationStands = errors.New("evs: a path created concurrently")

// One attempt: see the file header. creations, when given, are paths the last plan created, refused with
// errEvsCreationStands if this plan finds one standing. rebuilds counts the write's rebuilds and retokens.
func (self *EvsRepo) writeOnce(ctx context.Context, writes []*EvsPathWrite, refName []byte, refId Id, fresh bool, rebuilds *int, extras *evsPushExtras, creations ...map[string]bool) (*EvsWritePathsResult, *EvsWritePlan, error) {
	repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
	if err != nil {
		return nil, nil, err
	}
	self.client.epochs.noteWritable(self.repoId, repoKey.Generation())
	plan, err := self.PlanWrite(ctx, &EvsPlanArgs{RefName: refName, RefId: refId, Writes: writes, Generation: repoKey.Generation(), Fresh: fresh})
	if err != nil {
		return nil, nil, err
	}
	for _, created := range creations {
		for _, planned := range plan.Paths {
			if created[planned.Path] && planned.BaseEntryVersion != 0 {
				return nil, plan, errEvsCreationStands
			}
		}
	}
	if extras != nil {
		if extras.flags&uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) != 0 {
			for _, planned := range plan.Paths {
				if planned.creates() || planned.Remove || planned.Kind != protocol.EvsEntryKind_EVS_ENTRY_FILE {
					// a CLOSURE replaces committed file versions alone, which a directory's delta is not
					return nil, plan, fmt.Errorf("%w: a CLOSURE creating, removing or listing a path", ErrEvsWriteInvalid)
				}
			}
		}
		plan.Flags, plan.Erased, plan.scope = extras.flags, extras.erased, extras.scope
	}
	sealed, err := self.client.sealWrite(ctx, plan, repoKey)
	if err != nil {
		return nil, plan, err
	}
	sealed.scope = plan.scope
	defer sealed.Close()
	pushId, reply, err := self.sendSealed(ctx, sealed, rebuilds)
	if err != nil {
		return nil, plan, err
	}
	result := &EvsWritePathsResult{PushId: pushId, Version: reply.GetVersion()}
	pathVersions := map[string]uint64{}
	for _, planned := range plan.Paths {
		version := planned.Version
		if planned.Remove {
			version = planned.BaseEntryVersion + 1
		}
		pathVersions[planned.Path] = version
	}
	for _, write := range writes {
		result.PathVersions = append(result.PathVersions, pathVersions[write.Path])
	}
	return result, plan, nil
}

// Waits out a creation the ref's coming path epoch holds: its retry_after_ms, else PathEpochDueWait, at most
// PushRetryMaxWait, or the ref's next verified head, whichever comes first (DESIGN-DETAILS 9.2.5's 412
// PATH_EPOCH_DUE row). A mapper on this device maps meanwhile on its own ticks (evs_epoch_map.go).
func (self *EvsRepo) waitPathEpoch(ctx context.Context, refId Id, refusal error) error {
	wait := self.client.settings.PathEpochDueWait
	if evsError, ok := EvsErrorOf(refusal); ok && 0 < evsError.RetryAfter {
		wait = evsError.RetryAfter
	}
	moved := self.client.epochs.moved(self.repoId, refId)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-moved:
	case <-self.client.clock.After(min(wait, self.client.settings.PushRetryMaxWait)):
	}
	return nil
}
