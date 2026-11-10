//go:build !ios_extension

// CLOSURE, an erasure's re-checkpoint (§11.12's closure and rekey rows; EVS1-M2-30): before the keys of a derived chain
// go, the erasing device writes each file holding the entry again without it, as a whole checkpoint under a fresh
// object key, by a CLOSURE push (flag 128, admin) on the file's own ref, whose payload lists the old chains' keys,
// which erased_sha256 binds, for the ERASE that follows (evs_erase.go).
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
// Not built here, and failing closed: the sealed erasure id a CLOSURE carries, which no format field holds yet
// (question evs1-m2-30-erasure-note-format); and ?closure=1 uploads at the storage limit.
//
// On desktop and mobile legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// What Closure re-checkpoints.
type EvsClosureArgs struct {
	// The ref's name bytes: nil for main.
	RefName []byte
	// Each file written again without the entry: its new content, the entry gone.
	Writes []*EvsPathWrite
	// The replaced chains' keys, which the ERASE after it lists.
	Erased []*EvsErasedKey
}

// What a push carries beyond its plan's changes: its flags, its erased list, and the scope it goes under.
type evsPushExtras struct {
	flags  uint32
	erased []*EvsErasedKey
	scope  string
}

// Commits a CLOSURE: see the file header.
func (self *EvsRepo) Closure(ctx context.Context, args *EvsClosureArgs) (*EvsWritePathsResult, error) {
	if args == nil || len(args.Writes) == 0 {
		return nil, fmt.Errorf("%w: a CLOSURE of nothing", ErrEvsWriteInvalid)
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
	})
}
