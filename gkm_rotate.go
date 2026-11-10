// §10.5's Rotate (KEYS-M2-20; D-KEYS-6, D-KEYS-9, D-KEYS-15; DESIGN-DETAILS 6.2.4), one code path for every cause
// and every rotator, a leaf, a wrapped member device and an agent alike:
//
//	pre      a writer, or in the config and directory groups any standing holder that is not read_only; a holder or
//	         covered at this state; RK_g* held and this state at or past gen/<g*>'s pin (R1, R2)
//	1 draft  H = KeyHolders at (this state, now); RK' random; cause REMOVE iff the state requires it or the parent
//	         is poisoned, else the cause asked for; a leaf_wrap only on a clean tree (R5); a drop key for a kind that
//	         takes deposits; the delivery set counted into wrap_count; RK' and the Signed GenRotate persisted in the
//	         keychain's draft before anything is staged
//	2 stage  every delivery STAGED before the claim (gkm_deliver.go)
//	3 claim  POST gen/<g*+1>, the linearization point, between barriers gkm.rotate.claim.before and .after
//	         201  the generation is this device's: keychain, pin, the draft deleted
//	         412  the winner is judged by CheckRotation; one that passes is held, and adopted as the answer only if
//	              it covers every shrink and expiry this state shows, else the rotation starts over at g*+2; one
//	              that fails is held as poisoned, alarmed and never sealed to, and the rotation starts over at g*+2
//	              with cause REMOVE
//	         403  gkm's state is ahead of this one: ErrGkmWait, to try again once the log advances
//	         unknown  GET gen/<g*+1>: this device's commitment is 201, another's is 412, none repeats the same bytes
//
// MLS commits never raise the generation: a Remove is a commit plus this separate claim (D-KEYS-15). A read_only
// device signs no rotation. A restart resumes from the draft: the same RK' and the same Signed bytes go to the claim,
// and the deliveries are staged again; a draft whose delivery set no longer has the count it signed, a ReaderKey
// having lapsed or appeared since, is dropped and drawn afresh, since nothing of it stands at gen/.
//
// Calls testHookSecret through the ladder's own functions at every key made or opened.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The barriers around the claim, keyed <group_id>:<g> as gkmservice keys its own.
const (
	gkmBarrierRotateClaimBefore = "gkm.rotate.claim.before"
	gkmBarrierRotateClaimAfter  = "gkm.rotate.claim.after"
)

// Whether a kind's GenRotates carry a drop key (D-KEYS-17): §8.5's deposit column, the vault, the mailbox, the
// secret store and the team record. A group inbox's marker (plan-MAIL-group-inbox) is not in §8.8's rows yet, so
// a general repo's inbox gets none until ACL-M2-06 carries it.
func GkmRepoKindTakesDeposits(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET, protocol.RepoKind_REPO_KIND_TEAM_RECORD:
		return true
	}
	return false
}

// A rotation's draft as the keychain holds it: RK' and the Signed GenRotate it will claim with.
type gkmRotateDraft struct {
	generation *GkmGeneration
	key        *EvsRepoKey
}

// version | u32 length | Signed GenRotate | RK'.
func (self *gkmRotateDraft) encode() ([]byte, error) {
	signedBytes, err := gkmSignedBytes(self.generation.Signed)
	if err != nil {
		return nil, err
	}
	encoded := []byte{gkmRecordVersion}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(signedBytes)))
	encoded = append(encoded, signedBytes...)
	return append(encoded, self.key.repoKey...), nil
}

// A draft record's fields, RK' held to the statement's commitment.
func decodeGkmRotateDraft(encoded []byte) (*gkmRotateDraft, error) {
	malformed := fmt.Errorf("%w: a rotation draft", ErrGkmMalformed)
	if len(encoded) < 5 || encoded[0] != gkmRecordVersion {
		return nil, malformed
	}
	signedByteCount := int(binary.BigEndian.Uint32(encoded[1:5]))
	rest := encoded[5:]
	if len(rest) != signedByteCount+gkmRepoKeyByteCount {
		return nil, malformed
	}
	generation, err := gkmStoredGeneration(rest[:signedByteCount])
	if err != nil {
		return nil, err
	}
	key, err := OpenEvsRepoKey(generation, rest[signedByteCount:])
	if err != nil {
		return nil, err
	}
	return &gkmRotateDraft{generation: generation, key: key}, nil
}

// `ur keys rotate`: a new generation now, REMOVE if one is due, else REQUEST. ErrGkmNotWriter for a device that may
// not rotate, ErrGkmAuthAhead while its state is below the newest generation's pin, ErrGkmKeyMissing while it holds
// no key of it, ErrGkmWait while gkm's state is ahead of this one.
func (self *GkmGroupClient) RotateRepo(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return self.Rotate(ctx, repoId, GkmCauseRequest)
}

// A rotation for cause, REQUEST or SCHEDULE; REMOVE is taken whenever the state requires it, whatever is asked.
func (self *GkmGroupClient) Rotate(ctx context.Context, repoId Id, cause GkmCause) (*EvsRepoKey, error) {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	return manager.rotateInFlow(ctx, cause)
}

// Whether this sidecar may rotate at a state and time (§10.9's Rotation alone row).
func (self *gkmGroupManager) mayRotate(state GkmAuthView, holders GkmHolders, at time.Time) error {
	sidecarId := self.client.args.SidecarId
	row := state.SidecarRow(sidecarId)
	if !gkmRowStanding(row) || gkmRowReadOnly(row) {
		return fmt.Errorf("%w: a revoked, parked or read_only device signs no rotation", ErrGkmNotWriter)
	}
	if !gkmHolderOrCovered(state, holders, self.repoId, sidecarId, at) {
		return fmt.Errorf("%w: no key holder at this state", ErrGkmNotWriter)
	}
	if !gkmWrites(state, self.repoId, sidecarId) && !gkmGroupLeafRanked(state.Repo(self.repoId)) {
		return ErrGkmNotWriter
	}
	return nil
}

// Rotate with the group's flow held. Each pass rotates from the newest generation held, so a lost claim's winner
// becomes the parent of the next.
func (self *gkmGroupManager) rotateInFlow(ctx context.Context, cause GkmCause) (*EvsRepoKey, error) {
	client := self.client
	if cause != GkmCauseRequest && cause != GkmCauseSchedule && cause != GkmCauseRemove {
		return nil, fmt.Errorf("%w: cause %d", ErrGkmMalformed, cause)
	}
	for passCount := 0; passCount < max(1, client.settings.RotatePassCount); passCount += 1 {
		state, err := client.currentState()
		if err != nil {
			return nil, err
		}
		pins, err := client.repoPins(self.repoId)
		if err != nil {
			return nil, err
		}
		top, err := client.newestHeldGeneration(self.repoId)
		if err != nil {
			return nil, err
		}
		if top.key == nil {
			// a poisoned generation this device could not open: nothing to link a new one to until a late
			// delivery brings its key
			return nil, fmt.Errorf("%w: generation %d is held without its key", ErrGkmKeyMissing, top.generation.Rotate.GetGeneration())
		}
		parent := top.generation.Rotate
		// R1, R2: this state is at or past the generation it rotates from
		if state.Pin().GetVersion() < parent.GetAuth().GetVersion() {
			return nil, fmt.Errorf("%w: this state is below gen/%d's pin", ErrGkmAuthAhead, parent.GetGeneration())
		}
		if standing := gkmPinStanding(state, parent.GetAuth()); errors.Is(standing, ErrGkmAuthOffChain) {
			return nil, standing
		}
		now := client.clock.Now()
		at := now
		if parentTime := time.UnixMilli(parent.GetTimeMs()); at.Before(parentTime) {
			// a claim's time is never below its parent's
			at = parentTime
		}

		// a generation gkm already holds past this one is a winner, as a 412's is
		newer, err := client.args.Api.Generations(ctx, self.repoId, pins.groupId, parent.GetGeneration())
		if err != nil {
			return nil, err
		}
		if 0 < len(newer.GetGenerations()) {
			// this device's own claim, landed before a kill took the answer: the draft's commitment stands there
			if draft := self.storedDraft(); draft != nil && draft.generation.Rotate.GetGeneration() == parent.GetGeneration()+1 {
				standing := &protocol.GenRotate{}
				if err := proto.Unmarshal(newer.GetGenerations()[0].GetBody(), standing); err == nil && bytes.Equal(standing.GetCommitment(), draft.generation.Rotate.GetCommitment()) {
					return self.claimed(draft)
				}
			}
			key, err := self.takeWinner(ctx, state, pins, top, newer.GetGenerations()[0], now)
			if err != nil || key != nil {
				return key, err
			}
			continue
		}

		draft, targets, err := self.rotateDraft(ctx, state, pins, top, cause, at)
		if err != nil {
			return nil, err
		}
		if err := self.stageDeliveries(ctx, state, pins.groupId, draft.key, targets); err != nil {
			return nil, err
		}
		key, winner, err := self.claim(ctx, pins.groupId, draft)
		if err != nil {
			return nil, err
		}
		if key != nil {
			return key, nil
		}
		key, err = self.takeWinner(ctx, state, pins, top, winner, now)
		if err != nil || key != nil {
			return key, err
		}
	}
	return nil, fmt.Errorf("%w: the claim was lost %d times", ErrGkmWait, max(1, client.settings.RotatePassCount))
}

// The keychain's rotation draft, or nil for none or one that does not decode.
func (self *gkmGroupManager) storedDraft() *gkmRotateDraft {
	encoded, err := self.client.getRecord(gkmRepoRecordName(self.repoId, "draft"))
	if err != nil {
		return nil
	}
	defer clear(encoded)
	draft, err := decodeGkmRotateDraft(encoded)
	if err != nil {
		return nil
	}
	return draft
}

// Step 1, or its resumption: the draft for generation g*+1 on top, and the delivery set it counts. A stored draft
// is reused when it chains on top, is this device's at a pin its state holds, and still counts its delivery set;
// else a new one is drawn and persisted before it returns.
func (self *gkmGroupManager) rotateDraft(ctx context.Context, state GkmAuthView, pins *gkmRepoPins, top *gkmHeldGeneration, cause GkmCause, at time.Time) (*gkmRotateDraft, []*gkmDeliveryTarget, error) {
	client := self.client
	parent := top.generation.Rotate
	draftName := gkmRepoRecordName(self.repoId, "draft")
	// the rotator's own epoch, when it is a leaf
	var group MlsGroup
	var roster []MlsMember
	if loaded, err := client.loadGroup(pins.groupId); err == nil {
		group = loaded
		roster = loaded.Roster()
	} else if !errors.Is(err, ErrMlsGroupUnknown) && !errors.Is(err, ErrMlsNotMember) {
		return nil, nil, err
	}

	if encoded, err := client.getRecord(draftName); err == nil {
		stored, decodeErr := decodeGkmRotateDraft(encoded)
		clear(encoded)
		if decodeErr == nil {
			rotate := stored.generation.Rotate
			chains := rotate.GetGeneration() == parent.GetGeneration()+1 && bytes.Equal(rotate.GetParentCommitment(), parent.GetCommitment()) &&
				stored.generation.SignerId == client.args.SidecarId
			if draftState, stateErr := state.At(rotate.GetAuth()); chains && stateErr == nil {
				draftAt := time.UnixMilli(rotate.GetTimeMs())
				holders, err := KeyHolders(draftState, self.repoId, draftAt)
				if err != nil {
					return nil, nil, err
				}
				leafWrapped := rotate.GetLeafWrap() != nil
				if !leafWrapped || group != nil && group.Epoch() == rotate.GetLeafWrap().GetEpoch() {
					targets, err := self.deliverySet(ctx, draftState, holders, draftAt, roster, leafWrapped)
					if err != nil {
						return nil, nil, err
					}
					if uint32(len(targets)) == rotate.GetWrapCount() && bytes.Equal(holders.Sha256(), rotate.GetHoldersSha256()) {
						return stored, targets, nil
					}
				}
			}
		}
		// nothing of this draft stands at gen/: its staged objects are collected after 24 h (§10.6)
		if err := client.args.Secrets.Delete(draftName); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, ErrGkmKeyMissing) {
		return nil, nil, err
	}

	holders, err := KeyHolders(state, self.repoId, at)
	if err != nil {
		return nil, nil, err
	}
	if err := self.mayRotate(state, holders, at); err != nil {
		return nil, nil, err
	}
	removeDue, err := GkmRemoveDue(state, self.repoId, parent.GetAuth(), time.UnixMilli(parent.GetTimeMs()), at)
	if err != nil {
		return nil, nil, err
	}
	if removeDue || top.poisoned {
		cause = GkmCauseRemove
	} else if cause == GkmCauseRemove {
		// REMOVE only when one is due (6.2.5's RotateRepo)
		cause = GkmCauseRequest
	}
	args := &GkmGenerationArgs{Cause: cause, Auth: state.Pin(), Time: at, HoldersSha256: holders.Sha256()}
	if repo := state.Repo(self.repoId); repo != nil && GkmRepoKindTakesDeposits(repo.GetKind()) {
		args.DropNotAfter = at.Add(client.settings.DropKeyLifetime)
	}
	// R5: a leaf_wrap only if this device is a leaf of its epoch and that tree holds holders alone
	leafWrapped := group != nil
	for _, member := range roster {
		if !holders.Contains(GkmHolderLeaf, member.SidecarId.Bytes()) {
			leafWrapped = false
		}
	}
	if leafWrapped {
		kek, err := MlsKek(group, self.repoId)
		if err != nil {
			return nil, nil, err
		}
		defer clear(kek)
		args.LeafWrapKek = kek
		args.LeafWrapEpoch = group.Epoch()
	}
	targets, err := self.deliverySet(ctx, state, holders, at, roster, leafWrapped)
	if err != nil {
		return nil, nil, err
	}
	args.WrapCount = uint32(len(targets))
	// in the pinned group, which after a re-form is not the one the parent's statement names (gkm_reform.go)
	key, rotate, err := top.key.NextGenerationIn(pins.groupId, args)
	if err != nil {
		return nil, nil, err
	}
	signed, err := SignGenRotate(rotate, client.args.Sign)
	if err != nil {
		return nil, nil, err
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil || signerId != client.args.SidecarId {
		return nil, nil, fmt.Errorf("%w: the signer returned another sidecar's statement", ErrGkmMalformed)
	}
	draft := &gkmRotateDraft{generation: &GkmGeneration{Signed: signed, SignerId: signerId, Rotate: rotate}, key: key}
	encoded, err := draft.encode()
	if err != nil {
		return nil, nil, err
	}
	defer clear(encoded)
	// persisted before anything is staged, so a kill resumes with the same RK' and the same bytes
	if err := client.args.Secrets.Put(draftName, encoded); err != nil {
		return nil, nil, err
	}
	return draft, targets, nil
}

// Step 3: the claim of the draft's generation. Returns the key on 201, or the winner on 412; an outcome it cannot
// learn is read back from gen/.
func (self *gkmGroupManager) claim(ctx context.Context, groupId Id, draft *gkmRotateDraft) (*EvsRepoKey, *bridge.Signed, error) {
	client := self.client
	rotate := draft.generation.Rotate
	generation := rotate.GetGeneration()
	barrierKey := gkmPathId(groupId) + ":" + strconv.FormatUint(generation, 10)
	for sendCount := 0; sendCount < max(1, client.settings.RotateClaimSendCount); sendCount += 1 {
		testHookBarrier(gkmBarrierRotateClaimBefore, barrierKey)
		err := client.args.Api.ClaimGeneration(ctx, self.repoId, groupId, generation, draft.generation.Signed)
		testHookBarrier(gkmBarrierRotateClaimAfter, barrierKey)
		gkmError, refused := GkmErrorOf(err)
		switch {
		case err == nil:
			key, err := self.claimed(draft)
			return key, nil, err
		case refused && gkmError.Status == http.StatusPreconditionFailed:
			winner := &bridge.Signed{}
			if err := proto.Unmarshal(gkmError.Winner, winner); err != nil {
				return nil, nil, fmt.Errorf("%w: a claim's winner", ErrGkmReplyInvalid)
			}
			return nil, winner, nil
		case refused && gkmError.Status == http.StatusForbidden:
			// its signer, auth or time check: gkm's state is ahead of this one, or this clock is off
			return nil, nil, fmt.Errorf("%w: gkm refused the claim of generation %d", ErrGkmWait, generation)
		case refused:
			return nil, nil, err
		case ctx.Err() != nil:
			return nil, nil, err
		}
		// unknown: what stands at gen/<g+1> says what happened
		standing, readErr := client.args.Api.Generations(ctx, self.repoId, groupId, generation-1)
		if readErr != nil {
			return nil, nil, readErr
		}
		if 0 < len(standing.GetGenerations()) {
			winner := standing.GetGenerations()[0]
			body := &protocol.GenRotate{}
			if err := proto.Unmarshal(winner.GetBody(), body); err == nil && bytes.Equal(body.GetCommitment(), rotate.GetCommitment()) {
				key, err := self.claimed(draft)
				return key, nil, err
			}
			return nil, winner, nil
		}
		// nothing there: the same bytes go again
	}
	return nil, nil, fmt.Errorf("%w: the claim of generation %d got no answer", ErrGkmUnavailable, generation)
}

// 201: generation g*+1 is this device's. Its key and Signed bytes go to the keychain, the pin moves forward and the
// draft goes.
func (self *gkmGroupManager) claimed(draft *gkmRotateDraft) (*EvsRepoKey, error) {
	client := self.client
	if err := client.putHeldGeneration(self.repoId, &gkmHeldGeneration{generation: draft.generation, key: draft.key}); err != nil {
		return nil, err
	}
	rotate := draft.generation.Rotate
	err := client.advancePins(self.repoId, func(pins *gkmRepoPins) {
		pins.generation = rotate.GetGeneration()
		pins.commitment = bytes.Clone(rotate.GetCommitment())
	})
	if err != nil {
		return nil, err
	}
	if err := client.args.Secrets.Delete(gkmRepoRecordName(self.repoId, "draft")); err != nil {
		return nil, err
	}
	return draft.key, nil
}

// The 412 branch: judges the generation that holds g*+1, holds it, and answers its key only if it passed and covers
// every shrink and expiry this state shows. A nil key with no error means rotate again on top of it: it does not
// cover what this rotation is for, or it is poisoned.
func (self *gkmGroupManager) takeWinner(ctx context.Context, state GkmAuthView, pins *gkmRepoPins, top *gkmHeldGeneration, winner *bridge.Signed, now time.Time) (*EvsRepoKey, error) {
	client := self.client
	generationNumber := top.generation.Rotate.GetGeneration() + 1
	winnerBytes, err := gkmSignedBytes(winner)
	if err != nil {
		return nil, err
	}
	generation, err := client.parseServedGeneration(ctx, state, self.repoId, pins.groupId, generationNumber, winnerBytes)
	if err != nil {
		if errors.Is(err, ErrGkmAuthentication) || errors.Is(err, ErrGkmMalformed) {
			// nothing verifiable stands at gen/<g*+1>, so nothing can be held or linked past it: the admins
			// re-form the group (§10.9)
			verdict := gkmRefuse(GkmRefusalSigner, "gen/%d does not verify", generationNumber)
			client.alarm(&GkmAlarm{
				Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: pins.groupId, Generation: generationNumber,
				Reason: verdict.Reason, Detail: verdict.Detail,
			})
			return nil, fmt.Errorf("%w: gen/%d does not verify", ErrGkmWait, generationNumber)
		}
		return nil, err
	}
	held, err := self.holdGenerationInFlow(ctx, state, pins.groupId, generation, top.generation, top.poisoned, now)
	if err != nil {
		return nil, err
	}
	// whatever this device drafted for g*+1 lost
	if err := client.args.Secrets.Delete(gkmRepoRecordName(self.repoId, "draft")); err != nil {
		return nil, err
	}
	if held.poisoned {
		// §10.9's poisoned row: never seal to it, rotate at once on top of it with cause REMOVE
		if held.key == nil {
			return nil, fmt.Errorf("%w: generation %d is poisoned and this device holds no key of it to rotate past it", ErrGkmKeyMissing, generationNumber)
		}
		return nil, nil
	}
	if held.key == nil {
		// it passed, and nothing this device holds opens it yet: a holder's late delivery brings it
		return nil, fmt.Errorf("%w: generation %d is claimed and no delivery of it reached this device yet", ErrGkmKeyMissing, generationNumber)
	}
	// adopt it only if it covers what this rotation is for
	rotate := generation.Rotate
	if GkmGatePasses(state, self.repoId, rotate.GetAuth(), time.UnixMilli(rotate.GetTimeMs()), now) {
		return held.key, nil
	}
	return nil, nil
}

// Judges gen/<g> as gkm serves it, on parent, gen/<g-1> as this device holds it and nil at generation 1, opens its
// key where this device can, and keeps it (§10.9's rotation checks, R1 and R6): the STAGED deliveries to this device
// are judged with it; its key comes by its leaf_wrap where this device adopted that epoch, else by a delivery to a
// ReaderKey it holds; one that fails its checks is kept as poisoned and alarmed naming its signer; one that passes
// moves the generation pin; and one this device cannot open is asked for late. The error is a wait, ErrGkmAuthAhead
// while its pin is above this state, or a store's failure, never a refusal.
func (self *gkmGroupManager) holdGenerationInFlow(ctx context.Context, state GkmAuthView, groupId Id, generation *GkmGeneration, parent *GkmGeneration, parentPoisoned bool, now time.Time) (*gkmHeldGeneration, error) {
	client := self.client
	rotate := generation.Rotate
	generationNumber := rotate.GetGeneration()

	// what this device can read of it: its own deliveries, and the leaf_wrap's tree where it holds that epoch
	deliveries, err := self.ownDeliveries(ctx, state, groupId, generationNumber)
	if err != nil {
		return nil, err
	}
	staged := []*GkmDelivery{}
	for _, delivery := range deliveries {
		if GkmDeliveryKind(delivery.Body.GetDeliveryKind()) == GkmDeliveryStaged {
			staged = append(staged, delivery)
		}
	}
	var group MlsGroup
	if leafWrap := rotate.GetLeafWrap(); leafWrap != nil {
		if loaded, err := client.loadGroup(groupId); err == nil && loaded.Epoch() == leafWrap.GetEpoch() {
			group = loaded
		}
	}
	checkArgs := &GkmRotationCheckArgs{
		RepoId: self.repoId, Generation: generation, Parent: parent, ParentPoisoned: parentPoisoned,
		StagedDeliveries: staged, DropKeyLifetime: client.settings.DropKeyLifetime, Now: now,
	}
	if group != nil {
		checkArgs.LeafWrapRoster = group.Roster()
	}
	verdict, err := CheckRotation(state, checkArgs)
	if err != nil {
		return nil, err
	}

	key, err := self.openGenerationKey(state, groupId, generation, deliveries, now)
	if err != nil {
		return nil, err
	}

	held := &gkmHeldGeneration{generation: generation, key: key, poisoned: verdict.Refused}
	if err := client.putHeldGeneration(self.repoId, held); err != nil {
		return nil, err
	}
	if verdict.Refused {
		client.alarm(&GkmAlarm{
			Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: groupId, Generation: generationNumber,
			SidecarId: generation.SignerId, Reason: verdict.Reason, Detail: verdict.Detail,
		})
	} else {
		err = client.advancePins(self.repoId, func(pins *gkmRepoPins) {
			pins.groupId = groupId
			if pins.generation < generationNumber {
				pins.generation = generationNumber
				pins.commitment = bytes.Clone(rotate.GetCommitment())
			}
		})
		if err != nil {
			return nil, err
		}
	}
	if key == nil {
		self.askLate(ctx, groupId, generationNumber, now)
	}
	return held, nil
}

// RK_g of a generation this device parsed, by its leaf_wrap where this device's engine holds that epoch, else by a
// delivery to a ReaderKey it holds, each delivery judged at its own pin before its key is used (GkmUseDelivery). Nil
// when nothing this device holds opens it.
func (self *gkmGroupManager) openGenerationKey(state GkmAuthView, groupId Id, generation *GkmGeneration, deliveries []*GkmDelivery, now time.Time) (*EvsRepoKey, error) {
	client := self.client
	if leafWrap := generation.Rotate.GetLeafWrap(); leafWrap != nil {
		if group, err := client.loadGroup(groupId); err == nil && group.Epoch() == leafWrap.GetEpoch() {
			kek, err := MlsKek(group, self.repoId)
			if err != nil {
				return nil, err
			}
			opened, err := OpenGkmLeafWrap(generation, kek)
			clear(kek)
			if err == nil {
				return opened, nil
			}
		}
	}
	if client.args.ReaderPrivateKey == nil {
		return nil, nil
	}
	yield := client.newYield()
	for _, delivery := range deliveries {
		yield.step()
		privateKey, err := client.args.ReaderPrivateKey(delivery.Body.GetRecipientKeySha256())
		if err != nil {
			continue
		}
		// read from groupId's wrap paths, which a re-formed group's deliveries of its ladder's generations name
		deliveryArgs := &GkmDeliveryCheckArgs{RepoId: self.repoId, Delivery: delivery, Generation: generation, GroupId: groupId, Now: now}
		opened, deliveryVerdict, err := GkmUseDelivery(state, deliveryArgs, client.args.SidecarId.Bytes(), privateKey)
		if err == nil && deliveryVerdict.Passed() && opened != nil {
			return opened, nil
		}
	}
	return nil, nil
}

// A generation this device holds without its key, tried again: a late delivery, or its leaf_wrap's epoch, may have
// come since. One it still cannot open is asked for late.
func (self *gkmGroupManager) openHeldGenerationInFlow(ctx context.Context, state GkmAuthView, groupId Id, held *gkmHeldGeneration) error {
	client := self.client
	generationNumber := held.generation.Rotate.GetGeneration()
	now := client.clock.Now()
	deliveries, err := self.ownDeliveries(ctx, state, groupId, generationNumber)
	if err != nil {
		return err
	}
	key, err := self.openGenerationKey(state, groupId, held.generation, deliveries, now)
	if err != nil {
		return err
	}
	if key == nil {
		self.askLate(ctx, groupId, generationNumber, now)
		return nil
	}
	recipient := "s:" + hex.EncodeToString(client.args.SidecarId.Bytes())
	client.lateAsks.Done(groupId, generationNumber, recipient)
	return client.putHeldGeneration(self.repoId, &gkmHeldGeneration{generation: held.generation, key: key})
}

// This sidecar's deliveries of one generation, as gkm serves them, each verified under its signer's admitted key. One
// that does not verify is passed over.
func (self *gkmGroupManager) ownDeliveries(ctx context.Context, state GkmAuthView, groupId Id, generation uint64) ([]*GkmDelivery, error) {
	client := self.client
	recipient := "s:" + hex.EncodeToString(client.args.SidecarId.Bytes())
	reply, err := client.args.Api.Wraps(ctx, self.repoId, groupId, generation, &GkmWrapsQuery{Recipient: recipient})
	if err != nil {
		return nil, err
	}
	deliveries := []*GkmDelivery{}
	for _, signed := range reply.GetWraps() {
		delivery, err := ParseGkmDelivery(signed, GkmWrapTypeReader, GkmIdentityKeys(state))
		if err != nil || !bytes.Equal(delivery.Body.GetRecipient(), client.args.SidecarId.Bytes()) {
			continue
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, nil
}

// §10.6's late ask of one generation, to this sidecar's current ReaderKey, at most once a LateAskInterval. A lost
// ask costs latency alone, so its error is dropped.
func (self *gkmGroupManager) askLate(ctx context.Context, groupId Id, generation uint64, now time.Time) {
	client := self.client
	if client.args.ReaderKeySha256 == nil {
		return
	}
	keySha256 := client.args.ReaderKeySha256()
	if len(keySha256) != gkmDigestByteCount {
		return
	}
	recipient := "s:" + hex.EncodeToString(client.args.SidecarId.Bytes())
	since, ok := client.lateAsks.Ask(groupId, generation, recipient, now)
	if !ok {
		return
	}
	query := &GkmWrapsQuery{Recipient: recipient, Want: keySha256[:gkmDigestPrefixByteCount], Since: since}
	if _, err := client.args.Api.Wraps(ctx, self.repoId, groupId, generation, query); err != nil && client.log.V(1).Enabled() {
		client.log.Infof("[gkm]late ask of generation %d failed: %v", generation, err)
	}
}
