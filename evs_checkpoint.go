// Checkpoints (§11.7's checkpoint rule, PLAN.md:63): whether a file's next version is a whole checkpoint or a git
// pack delta against its previous version. A checkpoint draws a fresh object key, so it also ends the chain's reach
// back to keys older generations held.
//
//	(1) the chain has N = 16 diffs, so a chain never passes N + 1 records
//	(2) its diffs, the new one with them, exceed 50% of the file's size (Mercurial's revlog rule)
//	(3) the file is new, or the delta outgrows it
//	(4) a REMOVE generation is newer than the chain's key (owner decision 64), which takes in a moved entry's first
//	    write after one, since its chain's key is still its old generation's
//
// and beside them: a forced checkpoint (KEYS-M2-26's ur evs rekey); a file over 8 MiB, or one whose whole record
// would not fit one 8 MiB segment beside the segment's header and key block, which is chunks (evs_chunk.go), as is a
// previous version that was; a file or base past EvsSettings.DiffMaxByteCount, 1 MiB on a phone, which never diffs
// one (§11.7); an inline chain sealed under another generation than the one this push seals to, since an inline
// record is bound to its push's generation and cannot ride in another's (EVS-FORMAT.md's record header row); and a
// diff that would take an inline chain past 16 KiB, since a chain is inline or in segments and never both. Each of
// the last two starts the chain again.
//
// Rules (1), (4) and the others needing no delta are EvsCheckpointBefore's; (2) and (3), which need the delta's
// size, EvsCheckpointAfter's. A REMOVE generation is the real GkmClient's signal: gen/<g>'s cause, which
// EvsRepoKey.Cause gives for every generation the ladder reaches (evsRemoveGenerationSince).
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
)

// §11.7's chain bound: N diffs after a checkpoint.
const EvsChainMaxDiffCount = EvsChainMaxRecordCount - 1

// Why a file's next version is a checkpoint, or none for a diff.
type EvsCheckpointReason int

const (
	// A diff against the previous version.
	EvsCheckpointNone EvsCheckpointReason = iota
	// (3): the file is new, or its previous version stands for nothing this push can diff against.
	EvsCheckpointNewFile
	// (1): the chain holds N diffs.
	EvsCheckpointChainFull
	// (2): the diffs would pass half the file.
	EvsCheckpointDiffsHeavy
	// (3): the delta is no smaller than the file.
	EvsCheckpointDeltaOutgrows
	// (4): a REMOVE generation is newer than the chain's key.
	EvsCheckpointRemoveGeneration
	// ur evs rekey's rewrite.
	EvsCheckpointForced
	// The file, or its previous version, is chunks: past 8 MiB.
	EvsCheckpointChunked
	// The file or its base is past the client's DiffMaxByteCount.
	EvsCheckpointNoDiff
	// An inline chain sealed under another generation.
	EvsCheckpointInlineGeneration
	// A diff that would take an inline chain past 16 KiB, which a chain in segments cannot carry on from.
	EvsCheckpointInlineFull
	// A versionless version, or the first versioned one over versionless content: never a diff (§11.7's content and
	// on rows; EVS2-M10-15).
	EvsCheckpointVersionless
)

// What the previous version's chain holds, as reconstructing it found it.
type EvsChainState struct {
	// Records, the checkpoint or chunks first.
	RecordCount int
	// Diffs after its checkpoint, and their bodies' plaintext bytes.
	DiffCount     int
	DiffByteCount uint64
	// The oldest generation its records' keys were wrapped under: the chain's key (rule 4).
	KeyGeneration uint64
	// Whether its records ride inline, and the generation of the push that carried them, which an inline chain is
	// bound to.
	Inline           bool
	InlineGeneration uint64
	// The inline locators' bytes in all.
	InlineByteCount int
	// Whether it is chunks.
	Chunked bool
	// The previous version's plaintext size.
	Size uint64
	// Its last record's id, a new diff's base record.
	LastRecordId Id
}

// What decides a checkpoint before any delta is computed.
type EvsCheckpointArgs struct {
	// The previous version's chain; nil for a new file.
	Previous *EvsChainState
	// The new content's size.
	Size uint64
	// ur evs rekey.
	Force bool
	// Whether a REMOVE generation lies past the chain's key, up to the generation this push seals to.
	RemoveSince bool
	// The generation this push seals to.
	Generation uint64
	// EvsSettings.DiffMaxByteCount.
	DiffMaxByteCount uint64
}

// The rules a checkpoint needs no delta for, in order: none answers EvsCheckpointNone, and the caller computes the
// delta and asks EvsCheckpointAfter.
func EvsCheckpointBefore(args *EvsCheckpointArgs) EvsCheckpointReason {
	previous := args.Previous
	switch {
	case EvsChunked(args.Size):
		return EvsCheckpointChunked
	case previous == nil || previous.RecordCount == 0:
		return EvsCheckpointNewFile
	case previous.Chunked:
		return EvsCheckpointChunked
	case args.Force:
		return EvsCheckpointForced
	case args.RemoveSince:
		return EvsCheckpointRemoveGeneration
	case EvsChainMaxDiffCount <= previous.DiffCount:
		return EvsCheckpointChainFull
	case args.DiffMaxByteCount < args.Size || args.DiffMaxByteCount < previous.Size:
		return EvsCheckpointNoDiff
	case previous.Inline && previous.InlineGeneration != args.Generation:
		return EvsCheckpointInlineGeneration
	}
	return EvsCheckpointNone
}

// Rules (2) and (3) once the delta's size is known: the delta outgrows the file, or the chain's diffs with it pass
// half the file's size.
func EvsCheckpointAfter(previous *EvsChainState, deltaByteCount uint64, size uint64) EvsCheckpointReason {
	switch {
	case size <= deltaByteCount:
		return EvsCheckpointDeltaOutgrows
	case size < 2*(previous.DiffByteCount+deltaByteCount):
		return EvsCheckpointDiffsHeavy
	}
	return EvsCheckpointNone
}

// Whether a generation past keyGeneration, up to generation, is a REMOVE generation (§10.5's GenRotate cause): each
// is asked of gkm once, through the ladder.
func evsRemoveGenerationSince(ctx context.Context, gkm GkmClient, repoId Id, keyGeneration uint64, generation uint64) (bool, error) {
	for g := keyGeneration + 1; g <= generation; g += 1 {
		repoKey, err := gkm.RepoKey(ctx, repoId, g)
		if err != nil {
			return false, fmt.Errorf("evs: generation %d's cause: %w", g, err)
		}
		if repoKey.Cause() == GkmCauseRemove {
			return true, nil
		}
	}
	return false, nil
}
