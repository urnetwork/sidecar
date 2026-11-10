// §10.5's depositor rule (KEYS-M2-22; D-KEYS-8, D-KEYS-17, R7; DESIGN-DETAILS 6.2.5): the drop key a depositor
// seals to and cannot read back. A depositor holds no key of the repo, so everything it knows of a generation is
// its Signed GenRotate, and it seals nothing it cannot verify, with evs's gate off too:
//
//	verifies    the newest GenRotate gkm serves for the repo (GET repos/<id>/drop-key?since=), under its signer's
//	            admitted key, chained by parent_commitment from the generation this depositor pinned, and judged by
//	            the rotation checks at its own pin (CheckRotation), so its signer is a holder that writes, its
//	            holders hash is this state's and its drop key's life is in bounds
//	newest      it is the last of what gkm serves, read to the end of its pages
//	covers      it covers the repo's holders_shrunk_at and every expiry up to now at this depositor's state (§7.9's
//	            coverage, GkmGateCheck): an older, unexpired GenRotate after a removal is refused
//	unexpired   now is before drop_not_after_ms
//	pin         its generation is not below this depositor's pin, which then rises; gkm serving nothing at the pin,
//	            or another commitment there, is a fork. After a re-form the route serves the new group, whose
//	            ladder holds the pinned statement as the old group did, and the pin's group follows the chain from
//	            it (KEYS-M2-25; gkm_reform.go)
//
// A pin of the repo this depositor saw fork stops its deposits as it stops a writer's seals (ErrGkmForked), until
// the chain extends the pin.
//
// Anything else waits, ErrGkmWait, for a writer's rotation, which the gate or the renewal below makes writers
// write. With gkm unreachable the newest GenRotate this depositor holds answers if it still passes covers and
// unexpired at its state (KF7).
//
// Renewal (plan-KEYS-drop-key-lifetime's rule 2): a lapse closes no gate, so a writer of a kind that takes deposits
// rotates with cause SCHEDULE, with no write of its own, when the newest drop key has under 7 days left, at its
// hourly resync and at gkm's renewal hint, which arrives as pending.
//
// A depositor keeps what it verified as gen/<g> records without keys and the same pins a reader keeps, so one
// device that both reads and deposits holds one pin.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The newest generation's drop key, under §10.5's depositor rule. See the file header.
func (self *GkmGroupClient) DropKey(ctx context.Context, repoId Id) (*GkmDropKey, error) {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	if state.Repo(repoId) == nil {
		return nil, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, repoId)
	}
	held, err := manager.newestDropGenerationInFlow(ctx, state)
	if gkmUnreachable(ctx, err) {
		// KF7: the newest GenRotate held, if it still covers at this state
		if self.log.V(1).Enabled() {
			self.log.Infof("[gkm]unreachable, depositing on what the keychain holds: %v", err)
		}
		held, err = self.newestHeldGeneration(repoId)
		if errors.Is(err, ErrGkmKeyMissing) {
			return nil, fmt.Errorf("%w: no GenRotate of the repo is held", ErrGkmUnavailable)
		}
	}
	if err != nil {
		return nil, err
	}
	rotate := held.generation.Rotate
	if held.poisoned {
		return nil, fmt.Errorf("%w: generation %d failed its checks", ErrGkmWait, rotate.GetGeneration())
	}
	if len(rotate.GetDropPublicKey()) == 0 {
		return nil, fmt.Errorf("%w: generation %d publishes no drop key", ErrGkmKeyMissing, rotate.GetGeneration())
	}
	now := self.clock.Now()
	generationTime := time.UnixMilli(rotate.GetTimeMs())
	if gate := GkmGateCheck(state, repoId, rotate.GetAuth(), generationTime, now); gate != nil {
		if errors.Is(gate, ErrGkmAuthAhead) {
			return nil, gate
		}
		return nil, fmt.Errorf("%w: %w", ErrGkmWait, gate)
	}
	notAfter := time.UnixMilli(rotate.GetDropNotAfterMs())
	latest := generationTime.Add(self.settings.DropKeyLifetime + GkmClockSkew)
	if !now.Before(notAfter) || latest.Before(notAfter) {
		return nil, fmt.Errorf("%w: generation %d's drop key has lapsed", ErrGkmWait, rotate.GetGeneration())
	}
	// a deposit is a seal: none at a forked pin
	if err := self.sealStopped(repoId); err != nil {
		return nil, err
	}
	return &GkmDropKey{
		RepoId:     repoId,
		GroupId:    Id(rotate.GetGroupId()),
		Generation: rotate.GetGeneration(),
		Commitment: bytes.Clone(rotate.GetCommitment()),
		PublicKey:  bytes.Clone(rotate.GetDropPublicKey()),
		NotAfter:   notAfter,
	}, nil
}

// The verifies, newest and pin rows: reads the repo's GenRotates from this depositor's pin to gkm's newest, holds
// each to its signer's key and to its parent's commitment, judges the newest, keeps it and moves the pin. A device
// that already holds the repo's generations as a reader takes them as a reader does.
func (self *gkmGroupManager) newestDropGenerationInFlow(ctx context.Context, state GkmAuthView) (*gkmHeldGeneration, error) {
	client := self.client
	pins, err := client.repoPins(self.repoId)
	switch {
	case err == nil && 0 < pins.generation:
		if _, openedErr := client.newestOpenedGeneration(self.repoId); openedErr == nil {
			// a reader's own refresh also opens what it can
			if err := self.refreshGenerationsInFlow(ctx, state); err != nil {
				return nil, err
			}
			return client.newestHeldGeneration(self.repoId)
		}
	case err == nil || errors.Is(err, ErrGkmKeyMissing):
		pins = &gkmRepoPins{}
	default:
		return nil, err
	}
	var parent *GkmGeneration
	parentPoisoned := false
	since := uint64(0)
	if 0 < pins.generation {
		pinned, err := client.heldGeneration(self.repoId, pins.generation)
		if err != nil {
			return nil, err
		}
		// from the pinned generation itself, so a store that no longer serves it shows
		since = pins.generation - 1
		parent, parentPoisoned = pinned.generation, pinned.poisoned
	}
	var newest *GkmGeneration
	first := true
	for pageCount := 0; pageCount < gkmGenerationPageMaxCount; pageCount += 1 {
		reply, err := client.args.Api.DropKeys(ctx, self.repoId, since)
		if err != nil {
			return nil, err
		}
		page := reply.GetGenerations()
		if len(page) == 0 {
			break
		}
		for _, signed := range page {
			body := &protocol.GenRotate{}
			if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
				return nil, fmt.Errorf("%w: a GenRotate", ErrGkmReplyInvalid)
			}
			groupId, err := IdFromBytes(body.GetGroupId())
			if err != nil || !bytes.Equal(body.GetRepoId(), self.repoId.Bytes()) {
				return nil, fmt.Errorf("%w: a GenRotate of another repo", ErrGkmReplyInvalid)
			}
			signedBytes, err := gkmSignedBytes(signed)
			if err != nil {
				return nil, err
			}
			generation, err := ParseGenRotate(signedBytes, groupId, since+1, GkmIdentityKeys(state))
			if err != nil {
				return nil, err
			}
			since += 1
			if first && 0 < pins.generation {
				// the pinned generation, as gkm serves it now
				first = false
				if groupId != pins.groupId || !bytes.Equal(generation.Rotate.GetCommitment(), pins.commitment) {
					local, remote := pins.genHead(), &protocol.GenHead{GroupId: groupId.Bytes(), Generation: since, Commitment: generation.Rotate.GetCommitment()}
					return nil, client.pinForked(self.repoId, pins, HeadForkGen, local, remote, nil, true, "gkm serves another commitment at this depositor's pin")
				}
				continue
			}
			first = false
			if newest != nil {
				parent, parentPoisoned = newest, false
			}
			if parent != nil && !bytes.Equal(generation.Rotate.GetParentCommitment(), parent.Rotate.GetCommitment()) {
				return nil, client.pinForked(self.repoId, pins, HeadForkGen, pins.genHead(), nil, nil, true, "gen/ does not chain from this depositor's pin")
			}
			newest = generation
		}
	}
	if first && 0 < pins.generation {
		return nil, client.pinForked(self.repoId, pins, HeadForkGen, pins.genHead(), nil, nil, true, "gkm serves nothing at this depositor's pin")
	}
	if newest == nil {
		if 0 < pins.generation {
			// nothing past the pin
			return client.heldGeneration(self.repoId, pins.generation)
		}
		return nil, fmt.Errorf("%w: gkm holds no generation of the repo", ErrGkmWait)
	}
	if newest.Rotate.GetGeneration() == 1 {
		parent = nil
	}
	verdict, err := CheckRotation(state, &GkmRotationCheckArgs{
		RepoId: self.repoId, Generation: newest, Parent: parent, ParentPoisoned: parentPoisoned,
		DropKeyLifetime: client.settings.DropKeyLifetime, Now: client.clock.Now(),
	})
	if err != nil {
		return nil, err
	}
	held := &gkmHeldGeneration{generation: newest, poisoned: verdict.Refused}
	if err := client.putHeldGeneration(self.repoId, held); err != nil {
		return nil, err
	}
	if verdict.Refused {
		client.alarm(&GkmAlarm{
			Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: Id(newest.Rotate.GetGroupId()), Generation: newest.Rotate.GetGeneration(),
			SidecarId: newest.SignerId, Reason: verdict.Reason, Detail: verdict.Detail,
		})
		return held, nil
	}
	if 0 < pins.generation && Id(newest.Rotate.GetGroupId()) != pins.groupId {
		// a re-formed group's, which a depositor follows along the chain just verified from its pin (gkm_reform.go)
		err = client.movePinsAlongChain(self.repoId, newest)
	} else {
		err = client.advancePins(self.repoId, func(pins *gkmRepoPins) {
			pins.groupId = Id(newest.Rotate.GetGroupId())
			pins.generation = newest.Rotate.GetGeneration()
			pins.commitment = bytes.Clone(newest.Rotate.GetCommitment())
		})
	}
	if err != nil {
		return nil, err
	}
	return held, nil
}

// The renewal: a SCHEDULE rotation when this device writes a repo whose kind takes deposits and the newest
// generation's drop key has under 7 days left, or carries none. Nothing for any other repo or device.
func (self *GkmGroupClient) RenewDropKey(ctx context.Context, repoId Id) error {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return err
	}
	repo := state.Repo(repoId)
	row := state.SidecarRow(self.args.SidecarId)
	if repo == nil || !GkmRepoKindTakesDeposits(repo.GetKind()) || !gkmRowStanding(row) || gkmRowReadOnly(row) || !gkmWrites(state, repoId, self.args.SidecarId) {
		return nil
	}
	top, err := self.newestHeldGeneration(repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	rotate := top.generation.Rotate
	renewAt := time.UnixMilli(rotate.GetDropNotAfterMs()).Add(-gkmDropKeyRenewBefore)
	if 0 < len(rotate.GetDropPublicKey()) && self.clock.Now().Before(renewAt) {
		return nil
	}
	_, err = manager.rotateInFlow(ctx, GkmCauseSchedule)
	return err
}
