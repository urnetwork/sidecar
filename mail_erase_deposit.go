//go:build !ios_extension

// The signed deposit entries an eraser needs before destroying a mailbox message (§15.7, FS-13).

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// The keys named by the requested standing deposits of one repo.
type mailEraseDeposits interface {
	Depositors(ctx context.Context) ([]Id, error)
	depositSlots(ctx context.Context, depositorId Id, messageIds []Id) ([]mailDepositSlot, error)
}

// A deposit entry's authenticated slot and its signed, padded plaintext size.
type mailDepositSlot struct {
	messageId  Id
	slotId     Id
	paddedSize uint64
}

// Finds every slot that held these deposits, including the original behind a signed CONSUME whose slot delete may
// still be outstanding on another device. The signed ref walk independently names the entries that must stand.
func (self *mailIngestEvsRepo) depositSlots(ctx context.Context, depositorId Id, messageIds []Id) ([]mailDepositSlot, error) {
	refId := EvsDepositRefId(self.repo.repoId, depositorId)
	standing, err := self.repo.standingDeposits(ctx, depositorId)
	if err != nil {
		return nil, err
	}
	creations := make(map[Id][]byte, len(standing))
	for _, deposit := range standing {
		id, err := IdFromBytes(deposit.EntryId)
		if err != nil {
			return nil, fmt.Errorf("%w: a deposit cursor's entry", ErrSidecarStoreFailed)
		}
		creations[id] = deposit.PushId
	}
	var slots []mailDepositSlot
	for _, messageId := range messageIds {
		creatingPush, stands := creations[messageId]
		history, err := self.repo.historyAt(ctx, refId, &EvsReadArgs{Fresh: true}, EvsTokenPath{EvsToken(messageId)}, nil)
		if errors.Is(err, ErrEvsPathAbsent) && !stands {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !history.Whole || len(history.Versions) == 0 {
			return nil, fmt.Errorf("%w: incomplete deposit history", ErrEvsReplyInvalid)
		}
		newest := history.Versions[0]
		if newest.Removed == stands || (stands && !bytes.Equal(newest.PushId[:], creatingPush)) {
			return nil, fmt.Errorf("%w: the deposit history disagrees with its signed ref", ErrEvsReplyInvalid)
		}
		for _, version := range history.Versions {
			if version.Removed {
				continue
			}
			if version.kind != protocol.EvsEntryKind_EVS_ENTRY_FILE || len(version.SlotIds) != 1 || version.SlotIds[0] == (Id{}) {
				return nil, fmt.Errorf("%w: a deposit needs one file slot", ErrMailNotShreddable)
			}
			slots = append(slots, mailDepositSlot{messageId: messageId, slotId: version.SlotIds[0], paddedSize: version.paddedSize})
		}
	}
	return slots, nil
}
