//go:build !ios_extension

// CLOSURE, an erasure's re-checkpoint (§11.12's closure and rekey rows; EVS1-M2-30): before the keys of a derived chain
// go, the erasing device writes each file holding the entry again without it, as a whole checkpoint under a fresh
// object key, by a CLOSURE push (flag 128, admin) on the file's own ref, whose payload lists the old chains' keys,
// which erased_sha256 binds, for the ERASE that follows (evs_erase.go), and whose sealed metadata carries its
// erasure's id as its erasure note, the id's 16 bytes and nothing more (§11.12's rekey row; QD-682; EVS-FORMAT.md's
// erasure notes), so a device resuming the erasure finds the CLOSUREs of it that no ERASE followed (ReadClosures).
//
// It goes through Write's planner with every path forced to a checkpoint, so it follows DESIGN-DETAILS 9.2.5: its paths
// stand and have floors, and one refused 412 PATH_EPOCH is re-tokenized with its segments, receipts and slot ids kept,
// so the closure upload is charged once and needs no second wait for its allowance. evs takes one only if each
// change replaces a committed file version and each new chain's record lengths sum to at most Padmé of the replaced
// chain's; else 409 with the paths, which goes back to the caller, as a duplicate CLOSURE's 409 does, which the
// caller's reconcile counts done.
//
// In a record-class repo the new chain's key goes in a new slot, which the CLOSURE introduces, and the old chain's
// slot key is what its erased list names (evs_plan.go's slot-keyed chains).
//
// Not built here, and failing closed: ?closure=1 uploads at the storage limit; and reading a CLOSURE that went in
// parts, whose note ReadClosures does not reach.
//
// On desktop and mobile legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What Closure re-checkpoints.
type EvsClosureArgs struct {
	// The erasure it belongs to (§11.12's rekey row), which its sealed note names. Required.
	ErasureId Id
	// The ref's name bytes: nil for main.
	RefName []byte
	// Each file written again without the entry: its new content, the entry gone.
	Writes []*EvsPathWrite
	// The replaced chains' keys, which the ERASE after it lists.
	Erased []*EvsErasedKey
}

// One committed CLOSURE as ReadClosures reads it.
type EvsClosure struct {
	Version         uint64
	PushId          Id
	Time            time.Time
	EraserSidecarId Id
	ErasureId       Id
	// The replaced chains' keys, which the ERASE that follows it lists.
	Keys []*EvsErasedKey
}

// What a push carries beyond its plan's changes: its flags, its erased list, the scope it goes under, and its
// erasure note.
type evsPushExtras struct {
	flags       uint32
	erased      []*EvsErasedKey
	scope       string
	erasureNote []byte
}

// Commits a CLOSURE: see the file header.
func (self *EvsRepo) Closure(ctx context.Context, args *EvsClosureArgs) (*EvsWritePathsResult, error) {
	if args == nil || len(args.Writes) == 0 {
		return nil, fmt.Errorf("%w: a CLOSURE of nothing", ErrEvsWriteInvalid)
	}
	if args.ErasureId == (Id{}) {
		// its sealed note names its erasure, which a resume finds it by (§11.12's reconcile row)
		return nil, fmt.Errorf("%w: a CLOSURE of no erasure", ErrEvsWriteInvalid)
	}
	writes := []*EvsPathWrite{}
	for _, write := range args.Writes {
		if write.Remove || write.Content == nil {
			return nil, fmt.Errorf("%w: a CLOSURE replaces a file version, never removes one", ErrEvsWriteInvalid)
		}
		forced := *write
		forced.ForceCheckpoint = true
		writes = append(writes, &forced)
	}
	return self.writePaths(ctx, &EvsWritePathsArgs{RefName: args.RefName, Writes: writes}, &evsPushExtras{
		flags: uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE), erased: args.Erased, scope: evsScopeAdmin,
		erasureNote: EvsClosureNote(args.ErasureId),
	})
}

// The committed CLOSUREs of a ref after afterVersion, oldest first, each with its erasure's id from its sealed note
// and the keys its payload lists: what a device resuming an erasure reads to find a CLOSURE no ERASE followed
// (§11.12's reconcile row). refName nil is main. A CLOSURE whose note does not open to an erasure id refuses the read.
func (self *EvsRepo) ReadClosures(ctx context.Context, refName []byte, afterVersion uint64) ([]*EvsClosure, error) {
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	head, err := self.readHeadAlone(ctx, refId, true)
	if err != nil || head.Version == 0 {
		return nil, err
	}
	walked, err := self.client.verifier.Walk(ctx, self.repoId, refId, 0, EvsChainStart(self.repoId, refId), head.Version)
	if err != nil {
		return nil, err
	}
	closures := []*EvsClosure{}
	for _, statement := range walked {
		push := statement.Statement.Push
		if statement.Version <= afterVersion || push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) == 0 {
			continue
		}
		checked, note, err := self.erasureNoteOf(ctx, head, statement)
		if err != nil {
			return nil, err
		}
		erasureId, err := ParseEvsClosureNote(note)
		if err != nil {
			return nil, err
		}
		pushId, _ := IdFromBytes(push.GetPushId())
		signerId, _ := IdFromBytes(push.GetSignerSidecarId())
		closures = append(closures, &EvsClosure{
			Version: statement.Version, PushId: pushId, Time: evsTime(push.GetTimeMs()), EraserSidecarId: signerId,
			ErasureId: erasureId, Keys: checked.Erased,
		})
	}
	return closures, nil
}
