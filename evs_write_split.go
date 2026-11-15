//go:build !ios_extension

// A write too large for one push's slot bodies (QD-819; question push-record-no-slot-bodies-part-slot-bodies): a push
// in parts carries its new slots' bodies, payload section 7, whole in its seal request and in none of its parts, within
// the format's SealSlotBodiesMaxByteCount, so a slot-keyed write introducing more slots than that holds, past some
// 12,000 new chains of a record-class repo, cannot go as one push. As an import past 1,024 parts splits at commits
// (§11.8's seal row), WritePaths splits such a write into pushes each within the bound:
//
//	check  once a plan is sealed and before anything is uploaded, its bodies framed as section 7 are held to
//	       EvsSettings.PushSlotBodiesByteCount, at most the format's bound
//	split  past it, a plain write of two paths or more sends nothing and goes as its halves in order, the first half's
//	       paths first, each half its own write: planned on a fresh read, sealed, held to the bound and split again in
//	       turn, so each push holds as many of the write's paths as fit
//	result the last push's id and version, and each write's path version in the args' order, as one push's
//	closed a CLOSURE, whose erased list must equal the ERASE after it, and a single path past the bound split no
//	       further: they fail with ErrEvsSlotBodiesTooLarge, nothing sent, as the statement builder refuses a push in
//	       parts past the bound before signing it
//
// A write so split lands as several versions, not one: a reader may see the first half's paths before the second's,
// and an error from a later half leaves the earlier halves committed, as the paths' new versions show; a caller that
// writes again reads them there, and a write held to versions (EvsPathWrite.IfVersion) finds the committed paths moved.
// Each half keeps its own rebuild budget.
//
// On every leg but the extension's, as evs_write.go.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

// What writeOnce answers for a write whose sealed slot bodies pass one push's and that may split: nothing was sent.
var errEvsWriteSplits = errors.New("evs: a write past one push's slot bodies, to split")

// The bytes slots' bodies take framed as payload section 7: each u32 length | bytes.
func evsSlotBodiesByteCount(slots []*EvsSealedSlot) int {
	byteCount := 0
	for _, slot := range slots {
		byteCount += 4 + len(slot.Body)
	}
	return byteCount
}

// Holds a sealed write's new slots' bodies to what one push carries: nil within it; errEvsWriteSplits past it for a
// plain write of two paths or more; else ErrEvsSlotBodiesTooLarge. See the file header.
func (self *EvsRepo) checkSlotBodies(sealed *EvsSealedWrite, writes []*EvsPathWrite, extras *evsPushExtras) error {
	byteCount := evsSlotBodiesByteCount(sealed.Slots)
	if byteCount <= self.client.settings.PushSlotBodiesByteCount {
		return nil
	}
	if extras != nil || len(writes) < 2 {
		return fmt.Errorf("%w: %d bytes of slot bodies in one push, past %d", ErrEvsSlotBodiesTooLarge, byteCount, self.client.settings.PushSlotBodiesByteCount)
	}
	return errEvsWriteSplits
}

// writePathsPlanned for a plain write whose slot bodies pass one push's: its first half, then its second, each its own
// write. See the file header.
func (self *EvsRepo) writeSplit(ctx context.Context, args *EvsWritePathsArgs) (*EvsWritePathsResult, *EvsWritePlan, error) {
	half := len(args.Writes) / 2
	result := &EvsWritePathsResult{PathVersions: []uint64{}}
	var plan *EvsWritePlan
	for _, writes := range [][]*EvsPathWrite{args.Writes[:half], args.Writes[half:]} {
		halfResult, halfPlan, err := self.writePathsPlanned(ctx, &EvsWritePathsArgs{RefName: args.RefName, Writes: writes, AgentId: args.AgentId}, nil)
		if err != nil {
			return nil, halfPlan, err
		}
		result.PushId, result.Version = halfResult.PushId, halfResult.Version
		result.PathVersions = append(result.PathVersions, halfResult.PathVersions...)
		plan = halfPlan
	}
	return result, plan, nil
}
