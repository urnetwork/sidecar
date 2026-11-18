//go:build !ios_extension

// A drop's cancel (§11.7's action row, §18.5's CancelDrop; owner decision 183; FS-89; EVS2-M10-21): a DROP push of
// action 2 with cancels_drop_id and cancels_version, by any repo admin, in an owner-bound repo a consented device of its
// owner, committed before not_before_ms less 60 s by evs's clock.
//
//	target   the drop the repo's table lists on the ref, pending, at its version and window; where this device's verified
//	         walk holds the statement at that version it must be a DROP of the table's push. Below the walk the table
//	         is evs's word, which evs's 5c holds to (a cancel whose target is not that drop is 409 DROP_STATE) and every
//	         reader checks against its own history, so a wrong one cancels nothing
//	time     refused here within DropCancelMargin, 60 s, of the drop's not_before_ms by this device's clock, as evs
//	         refuses one by its own (409 DROP_STATE); a lock never refuses a cancel
//	push     a push of no change carrying the cancel's body, a fresh drop_id of its own and not_before_ms 0, no lists
//	         (evs_drop_push.go's changeless push); a cancel lifts no fence and never counts in evs_drops_per_day
//
// On every leg but ios_extension. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A cancel of a drop the ref does not hold pending.
var ErrEvsDropNotPending = errors.New("evs: no pending drop of that id on the ref")

// What CancelDrop is asked.
type EvsCancelDropArgs struct {
	// The ref the drop is on; nil is main.
	RefName []byte
	DropId  Id
}

// What a committed cancel did.
type EvsCancelDropResult struct {
	PushId Id
	// The ref version the cancel committed at.
	Version uint64
	// The drop it cancels, and that drop's ref version.
	DropId      Id
	DropVersion uint64
}

// Cancels a pending drop: see the file header.
func (self *EvsRepo) CancelDrop(ctx context.Context, args *EvsCancelDropArgs) (*EvsCancelDropResult, error) {
	if args == nil || args.DropId == (Id{}) {
		return nil, fmt.Errorf("%w: a cancel of no drop", ErrEvsDropNotPending)
	}
	refName := args.RefName
	if refName == nil {
		refName = EvsMainRefName
	}
	if err := self.dropSigner(true); err != nil {
		return nil, err
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	drops, err := self.Drops(ctx, &EvsDropsArgs{RefName: refName})
	if err != nil {
		return nil, err
	}
	var status *protocol.EvsDropStatus
	for _, drop := range drops {
		if bytes.Equal(drop.Status.GetDropId(), args.DropId.Bytes()) && bytes.Equal(drop.Status.GetRefId(), refId.Bytes()) {
			status = drop.Status
		}
	}
	if status == nil || status.GetState() != protocol.EvsDropState_EVS_DROP_PENDING {
		return nil, ErrEvsDropNotPending
	}
	head, err := self.pinnedHead(ctx, refId)
	if err != nil {
		return nil, err
	}
	if statement, ok := head.StatementAt(status.GetVersion()); ok {
		// the walk holds the drop's statement: a DROP of the table's push at that version
		push := statement.Statement.Push
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 || !bytes.Equal(push.GetPushId(), status.GetPushId()) {
			return nil, fmt.Errorf("%w: the statement at the drop's version is no DROP of its push", ErrEvsDropNotPending)
		}
	}
	// else the version is below what this device walked: evs's 5c refuses a cancel whose target is not that drop
	// (409 DROP_STATE), and every reader checks a cancel against its own history (§11.7's states row)
	notBefore := evsTime(status.GetNotBeforeMs())
	if !self.client.clock.Now().Add(self.client.settings.DropCancelMargin).Before(notBefore) {
		return nil, fmt.Errorf("%w: within %s of the drop's window end", ErrEvsDropState, self.client.settings.DropCancelMargin.Round(time.Second))
	}
	pushId, version, err := self.dropChangeless(ctx, refName, newEvsDropCancelSpec(args.DropId, status.GetVersion()))
	if err != nil {
		return nil, err
	}
	return &EvsCancelDropResult{PushId: pushId, Version: version, DropId: args.DropId, DropVersion: status.GetVersion()}, nil
}
