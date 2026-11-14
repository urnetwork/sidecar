//go:build !ios_extension

// EvsRepo.Base (§16.8's retention, §16.11's erasure runner; R-EVS-11, D-EVS-10; plan-EVS1-v1-unspecified#6;
// EVS1-M6-03): an admin's BASE re-lists a record-class stream's live set once its expired entries are erased.
//
//	what     a push at admin scope, flag BASE, on a writer's owned stream in a record-class repo, the directory's
//	         included: its changes are removals alone, each naming its path's newest version (base_entry_version),
//	         and it carries nothing else, no entry version, segment, slot or inline record and no directory delta, so
//	         a removed file's row stays in its table; changes_root and parts past 1 KiB as any push's. It commits at
//	         the stream's next version with window bit 3, and its statement stays in history: what stands after it is
//	         the live set
//	order    §16.8's expiry runs ERASE first (EvsRepo.Erase), which destroys the expired entries' keys, then BASE,
//	         which deletes nothing itself; §11.13's GC would later free what no retained push names, which EVSB-M6-01
//	         holds closed until plan-EVSB-fs94-compaction-clause#2 is answered, so nothing is freed yet
//	plan     the files read fresh at the stream's verified head, 64 to a read, every batch on one head, each a
//	         standing file, else refused before anything is sent (ErrEvsPathAbsent, ErrEvsPathKind); sent under one
//	         push id until evs answers; a refusal asking for a rebuild reads again under a new one, at most
//	         PushRebuildCount times; any other refusal, 409 with the paths among them, goes back
//	readers  a removal on a creates-only stream stands only from a BASE a repo admin signed at its auth pin
//	         (evs_verify.go's ref rules), and §16.8's readers take the gap it leaves in its writer's seq chain as
//	         expired, not withheld
//
// A stream whose head lists source epochs is refused (ErrEvsWriteNotBuilt): its removals would name their source token
// paths (DESIGN-DETAILS 9.2.5), which this draft does not build. On every leg but the ios_extension legs. Safe for
// concurrent use, each call its own push.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// What Base removes.
type EvsBaseArgs struct {
	// The stream's ref: a writer's owned stream by its name's bytes (RecordStreamRefName), or by id, which overrides.
	RefName []byte
	RefId   *Id
	// The expired entries' files, raw names joined by /, each once.
	Paths []string
}

// A committed BASE.
type EvsBaseResult struct {
	PushId Id
	// The stream's version it committed at.
	Version uint64
}

// A plan read over more than one head: read again.
var errEvsBaseHeadMoved = errors.New("evs: a BASE's reads met two heads")

// Commits a BASE removing args.Paths from a stream: see the file header.
func (self *EvsRepo) Base(ctx context.Context, args *EvsBaseArgs) (*EvsBaseResult, error) {
	if args == nil || len(args.Paths) == 0 {
		return nil, fmt.Errorf("%w: a BASE of nothing", ErrEvsWriteInvalid)
	}
	seen := map[string]bool{}
	for _, path := range args.Paths {
		if _, err := evsPathNames(path); err != nil {
			return nil, err
		}
		if seen[path] {
			return nil, fmt.Errorf("%w: a path named twice", ErrEvsWriteInvalid)
		}
		seen[path] = true
	}
	kind, err := self.repoKind()
	if err != nil {
		return nil, err
	}
	if !EvsRepoKindRecordClass(kind) {
		return nil, fmt.Errorf("%w: BASE outside a record-class repo", ErrEvsWriteInvalid)
	}
	refId, err := self.resolveRefId(ctx, args.RefName, args.RefId)
	if err != nil {
		return nil, err
	}
	rebuilds := 0
	for {
		repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
		if err != nil {
			return nil, err
		}
		plan, err := self.planBase(ctx, refId, args.Paths, repoKey.Generation())
		if errors.Is(err, errEvsBaseHeadMoved) && rebuilds < self.client.settings.PushRebuildCount {
			rebuilds += 1
			continue
		}
		if err != nil {
			return nil, err
		}
		sealed := &EvsSealedWrite{Plan: plan, RepoKey: repoKey, scope: evsScopeAdmin}
		for _, planned := range plan.Paths {
			sealed.Paths = append(sealed.Paths, &EvsSealedPath{Planned: planned})
		}
		pushId, reply, err := self.sendSealed(ctx, sealed, &rebuilds)
		sealed.Close()
		switch {
		case err == nil:
			return &EvsBaseResult{PushId: pushId, Version: reply.GetVersion()}, nil
		case (evsNeedsRebuild(err) || errors.Is(err, errEvsPlanEpochMoved) || errors.Is(err, errEvsRetokenSealsAgain)) &&
			rebuilds < self.client.settings.PushRebuildCount:
			rebuilds += 1
			continue
		default:
			return nil, err
		}
	}
}

// The BASE's plan: each path's newest version as a removal, on the stream's head read fresh.
func (self *EvsRepo) planBase(ctx context.Context, refId Id, paths []string, generation uint64) (*EvsWritePlan, error) {
	var plan *EvsWritePlan
	batchCount := DefaultEvsFormatSettings().ReadMaxPathCount
	for start := 0; start < len(paths); start += batchCount {
		batch := paths[start:min(start+batchCount, len(paths))]
		err := func() error {
			result, err := self.read(ctx, refId, batch, 0, true)
			if err != nil {
				return err
			}
			defer result.objects.close()
			head := result.head.Head
			if plan == nil {
				if head.GetRefKind() != protocol.EvsRefKind_EVS_REF_OWNED || head.GetRefMode() != protocol.EvsRefMode_EVS_REF_FILE {
					return fmt.Errorf("%w: BASE outside an owned stream", ErrEvsWriteInvalid)
				}
				if 0 < len(evsSourceEpochs(head.GetPathEpoch())) {
					return fmt.Errorf("%w: a BASE while the stream's head lists source epochs", ErrEvsWriteNotBuilt)
				}
				ownerId, err := IdFromBytes(head.GetOwnerSidecarId())
				if err != nil {
					return fmt.Errorf("%w: the head's owner", ErrEvsReplyInvalid)
				}
				plan = &EvsWritePlan{
					RepoId: self.repoId, RefId: refId, RefKind: head.GetRefKind(), RefMode: head.GetRefMode(),
					OwnerSidecarId: &ownerId, BaseVersion: result.head.Version, BaseChain: result.head.Chain, Head: head,
					PathEpoch: evsCurrentEpoch(head.GetPathEpoch()), Generation: generation, keys: result.keys,
					floors: map[string]uint64{}, slotKeyed: true, Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_BASE),
					scope: evsScopeAdmin,
				}
			} else if result.head.Version != plan.BaseVersion {
				return errEvsBaseHeadMoved
			}
			for i, verified := range result.replies {
				switch {
				case verified.Base != nil, verified.Entry == nil:
					return fmt.Errorf("%w: a BASE names a file that does not stand", ErrEvsPathAbsent)
				case verified.Entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE):
					return fmt.Errorf("%w: a BASE names a directory", ErrEvsPathKind)
				}
				plan.Paths = append(plan.Paths, &EvsPlannedPath{
					Path: batch[i], TokenPath: result.paths[i].current, Kind: protocol.EvsEntryKind_EVS_ENTRY_FILE,
					Remove: true, BaseEntryVersion: verified.Entry.GetVersion(),
				})
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return plan, nil
}
