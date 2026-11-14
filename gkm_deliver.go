// A generation's deliveries (KEYS-M2-20; §10.5's Rotate, DESIGN-DETAILS 6.2.4): the set a rotation stages before
// its claim, how it is staged, and the LATE deliveries a holder writes after it.
//
//	leaves       a leaf_wrap under KEK_e in the GenRotate only if the rotator is a leaf of its epoch e and tree(e)
//	             lies within the holders (R5); else a ReaderWrap to each leaf of e among the holders; a rotator that
//	             is no leaf wraps to every member device among the holders, since it sees no tree
//	wrapped      config and directory groups: a ReaderWrap to each member device among the holders that tree(e) lacks
//	agents       a ReaderWrap to each agent among the holders, which no live Delegation there covers
//	delegations  a DelegationWrap to each live Delegation among the holders, at its reader key
//	forwarding   in the config, a DelegationWrap to each sidecar's live forwarding Delegation among the holders, at
//	             the reader key its statement names where this device keeps the entry, else gkm's object, read for
//	             every such holder at once through POST /gkm/delegation-keys (QD-637) and each held to its own row's
//	             digest (GkmForwardingReaderKey); one with neither is skipped and counted, and delivered late once its
//	             object stands: its sidecar uploads the object, then writes that wrap (§10.5's dwraps)
//	recovery     a RecoveryWrap to each member with a recovery identity among the holders, at its binding
//
// A ReaderWrap seals only to a ReaderKey gkm serves that the state's admitted identity key signed and that passes
// §10.5's readerkey check at the rotation's time, so a holder whose key lapsed, or was forged, gets none and waits
// for a late delivery. The rotator wraps nothing to itself: it keeps RK' in its keychain.
//
// Every delivery is STAGED before the claim, in batches of RotateBatchSize, RotateBatchConcurrency at once
// (QD-066). A path is created If-None-Match, so a restart stages again: a 412 whose winner is this rotator's own
// earlier delivery of the same generation and commitment to the same recipient and key is success, a RecoveryWrap's
// 412 under this rotation's own commitment likewise, and any other winner an alarm, since no other rotator holds
// this C'. A result of 0 is sent again.
//
// A LATE delivery (the deliver row) answers wrap-pending: after a random wait of up to LateDeliverJitter, a holder
// that is not read_only, holds RK_g* and judged gen/<g*>, at a tip at or past its pin (R2), delivers to a recipient
// among the holders at its own state and time (R6), to the key gkm serves for it, signed at that state.
//
// A reading: in a data repo a rotator that is no leaf wraps to every member device among the holders, a device
// waiting for a seat included, since only a leaf sees which devices are seated; each is a key holder, so nothing
// reaches a non-reader.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The most deliveries one wraps or recovery-wraps request carries (QD-066), gkm's bound.
const gkmWrapBatchMaxCount = 256

// What one delivery of a rotation is.
type gkmDeliveryTargetKind int

const (
	gkmDeliveryTargetReader gkmDeliveryTargetKind = iota + 1
	gkmDeliveryTargetDelegation
	gkmDeliveryTargetRecovery
)

// One recipient of a generation, with the key it is sealed to.
type gkmDeliveryTarget struct {
	kind gkmDeliveryTargetKind
	// a sidecar_id, a delegation_id or a member_id
	recipient []byte
	// the X-Wing public key sealed to
	publicKey []byte
	// a RecoveryWrap's binding
	bindingKeySha256 []byte
}

// §10.5's delivery set of a rotation at a state and time: holders is KeyHolders there, roster the rotator's epoch's
// leaves when it is a leaf and nil otherwise, and leafWrapped whether the GenRotate carries a leaf_wrap for that
// epoch. ErrGkmKeyMissing when a member's recovery key cannot be read, which refuses the rotation.
func (self *gkmGroupManager) deliverySet(ctx context.Context, state GkmAuthView, holders GkmHolders, at time.Time, roster []MlsMember, leafWrapped bool) ([]*gkmDeliveryTarget, error) {
	client := self.client
	repo := state.Repo(self.repoId)
	if repo == nil {
		return nil, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, self.repoId)
	}
	inTree := map[Id]bool{}
	for _, member := range roster {
		inTree[member.SidecarId] = true
	}
	readerIds := []Id{}
	targets := []*gkmDeliveryTarget{}
	// every forwarding holder's key the log does not give, read from gkm in batches before the loop (QD-637)
	forwardingKeyFetch, err := GkmForwardingReaderKeysFetched(ctx, state, holders, self.delegationKeysFetch())
	if err != nil {
		return nil, err
	}
	for _, holder := range holders {
		switch holder.Kind {
		case GkmHolderLeaf, GkmHolderAgent:
			sidecarId, err := IdFromBytes(holder.Id)
			if err != nil {
				return nil, fmt.Errorf("%w: a holder's id", ErrGkmMalformed)
			}
			if sidecarId == client.args.SidecarId {
				continue
			}
			if holder.Kind == GkmHolderLeaf && roster != nil {
				switch {
				case inTree[sidecarId] && leafWrapped:
					// the leaf_wrap serves it
					continue
				case !inTree[sidecarId] && !gkmGroupLeafRanked(repo):
					// a data repo's reader with no seat waits keyless (§8.12)
					continue
				}
			}
			readerIds = append(readerIds, sidecarId)
		case GkmHolderDelegation:
			var publicKey []byte
			for _, delegation := range state.Delegations() {
				if bytes.Equal(delegation.GetDelegationId(), holder.Id) {
					publicKey = delegation.GetReaderXwingPublicKey()
				}
			}
			if len(publicKey) != gkmXWingPublicKeyByteCount {
				return nil, fmt.Errorf("%w: a live Delegation with no reader key", ErrGkmMalformed)
			}
			targets = append(targets, &gkmDeliveryTarget{kind: gkmDeliveryTargetDelegation, recipient: bytes.Clone(holder.Id), publicKey: bytes.Clone(publicKey)})
		case GkmHolderForwarding:
			publicKey, err := GkmForwardingReaderKey(ctx, state, holder, forwardingKeyFetch)
			if errors.Is(err, ErrGkmKeyMissing) {
				// skipped and counted: a late delivery gives it this generation once its object stands
				client.delegationWrapsSkipped.Add(1)
				if client.log.V(1).Enabled() {
					client.log.Infof("[gkm]a rotation skipped a forwarding Delegation's wrap: %v", err)
				}
				continue
			}
			if err != nil {
				return nil, err
			}
			targets = append(targets, &gkmDeliveryTarget{kind: gkmDeliveryTargetDelegation, recipient: bytes.Clone(holder.ForwardDelegationId), publicKey: publicKey})
		case GkmHolderRecovery:
			memberId, err := IdFromBytes(holder.Id)
			if err != nil {
				return nil, fmt.Errorf("%w: a holder's id", ErrGkmMalformed)
			}
			if client.args.RecoveryKey == nil {
				return nil, fmt.Errorf("%w: no source of recovery keys, and a member holds a recovery identity", ErrGkmKeyMissing)
			}
			recoveryKey, err := client.args.RecoveryKey(memberId)
			if err != nil {
				return nil, err
			}
			if recoveryKey == nil || len(recoveryKey.XwingPublicKey) != gkmXWingPublicKeyByteCount || len(recoveryKey.BindingKeySha256) != gkmDigestByteCount {
				return nil, fmt.Errorf("%w: a member's recovery key", ErrGkmKeyMissing)
			}
			targets = append(targets, &gkmDeliveryTarget{
				kind: gkmDeliveryTargetRecovery, recipient: memberId.Bytes(),
				publicKey: bytes.Clone(recoveryKey.XwingPublicKey), bindingKeySha256: bytes.Clone(recoveryKey.BindingKeySha256),
			})
		}
	}
	// the ReaderKeys gkm serves, each held to its sidecar's admitted identity key and to the readerkey check
	readerKeysBatchCount := max(1, client.settings.ReaderKeysBatchCount)
	for first := 0; first < len(readerIds); first += readerKeysBatchCount {
		batch := readerIds[first:min(first+readerKeysBatchCount, len(readerIds))]
		readerKeys, err := client.args.Api.ReaderKeys(ctx, batch)
		if err != nil {
			return nil, err
		}
		for index, sidecarId := range batch {
			if len(readerKeys) <= index || readerKeys[index] == nil || len(readerKeys[index].GetBody()) == 0 {
				continue
			}
			readerKey, err := GkmAdmittedReaderKey(state, readerKeys[index], sidecarId, at.UnixMilli())
			if err != nil {
				// lapsed, forged or of no admitted sidecar: it waits for a late delivery
				continue
			}
			targets = append(targets, &gkmDeliveryTarget{kind: gkmDeliveryTargetReader, recipient: sidecarId.Bytes(), publicKey: readerKey.Body.GetXwingPublicKey()})
		}
	}
	return targets, nil
}

// gkm's objects of forwarding Delegations' reader keys, read in batches under this repo's scopes, which in the
// config's group are the config's, whose readers alone may read them (QD-637).
func (self *gkmGroupManager) delegationKeysFetch() GkmDelegationKeysFetch {
	return func(ctx context.Context, delegationIds [][]byte) ([][]byte, error) {
		return self.client.args.Api.DelegationKeys(ctx, self.repoId, delegationIds)
	}
}

// How many DelegationWraps this client's rotations have skipped for a forwarding Delegation whose reader key neither
// its log nor gkm gave it (DESIGN-DETAILS 4.2.2): each goes late once the key's object stands. Safe for concurrent
// use.
func (self *GkmGroupClient) DelegationWrapsSkipped() uint64 {
	return self.delegationWrapsSkipped.Load()
}

// One delivery sealed and signed for a route.
type gkmStagedItem struct {
	target *gkmDeliveryTarget
	// a Signed delivery's bytes, or a RecoveryWrap's item
	delivery []byte
	recovery *protocol.GkmRecoveryWrapItem
}

// Seals key to one target as a STAGED delivery of groupId.
func (self *gkmGroupManager) sealStaged(key *EvsRepoKey, groupId Id, target *gkmDeliveryTarget) (*gkmStagedItem, error) {
	item := &gkmStagedItem{target: target}
	if target.kind == gkmDeliveryTargetRecovery {
		memberId, err := IdFromBytes(target.recipient)
		if err != nil {
			return nil, fmt.Errorf("%w: a recovery wrap's member", ErrGkmMalformed)
		}
		ciphertext, err := SealGkmRecoveryWrap(key, &GkmRecoveryArgs{
			MemberId: memberId, GroupId: groupId, RecoveryPublicKey: target.publicKey, BindingKeySha256: target.bindingKeySha256,
		})
		if err != nil {
			return nil, err
		}
		item.recovery = &protocol.GkmRecoveryWrapItem{
			MemberId:      memberId.Bytes(),
			BindingPrefix: bytes.Clone(target.bindingKeySha256[:gkmDigestPrefixByteCount]),
			Ciphertext:    ciphertext,
		}
		return item, nil
	}
	wrapType := GkmWrapTypeReader
	if target.kind == gkmDeliveryTargetDelegation {
		wrapType = GkmWrapTypeDelegation
	}
	body, err := SealGkmDelivery(key, &GkmDeliveryArgs{
		GroupId: groupId, Type: wrapType, Recipient: target.recipient, RecipientPublicKey: target.publicKey, Kind: GkmDeliveryStaged,
	})
	if err != nil {
		return nil, err
	}
	signed, err := SignGkmDelivery(body, wrapType, self.client.args.Sign)
	if err != nil {
		return nil, err
	}
	item.delivery, err = gkmSignedBytes(signed)
	if err != nil {
		return nil, err
	}
	return item, nil
}

// Whether a 412's winner at a delivery's path is this rotator's own earlier delivery of the same generation and
// commitment to the same recipient and key: what a restart's second staging meets.
func (self *gkmGroupManager) ownStagedWinner(state GkmAuthView, winner []byte, sent []byte) bool {
	if bytes.Equal(winner, sent) {
		return true
	}
	parse := func(encoded []byte) *GkmDelivery {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(encoded, signed); err != nil {
			return nil
		}
		wrapType := GkmWrapTypeReader
		if signed.GetType() == uint32(bridge.SignedType_SIGNED_DELEGATION_WRAP) {
			wrapType = GkmWrapTypeDelegation
		}
		delivery, err := ParseGkmDelivery(signed, wrapType, GkmIdentityKeys(state))
		if err != nil {
			return nil
		}
		return delivery
	}
	held, mine := parse(winner), parse(sent)
	if held == nil || mine == nil || held.SignerId != self.client.args.SidecarId || held.Type != mine.Type {
		return false
	}
	return bytes.Equal(held.Body.GetGroupId(), mine.Body.GetGroupId()) && held.Body.GetGeneration() == mine.Body.GetGeneration() &&
		bytes.Equal(held.Body.GetCommitment(), mine.Body.GetCommitment()) && bytes.Equal(held.Body.GetRecipient(), mine.Body.GetRecipient()) &&
		bytes.Equal(held.Body.GetRecipientKeySha256(), mine.Body.GetRecipientKeySha256()) &&
		held.Body.GetDeliveryKind() == uint32(GkmDeliveryStaged)
}

// Stages every delivery of key, generation g+1's RK', to the targets: step 2 of Rotate, and KF1's step 4 for
// generation 1. Returns once every one stands at gkm, this call's or an earlier try's.
func (self *gkmGroupManager) stageDeliveries(ctx context.Context, state GkmAuthView, groupId Id, key *EvsRepoKey, targets []*gkmDeliveryTarget) error {
	client := self.client
	wrapItems := []*gkmStagedItem{}
	recoveryItems := []*gkmStagedItem{}
	yield := client.newYield()
	for _, target := range targets {
		yield.step()
		item, err := self.sealStaged(key, groupId, target)
		if err != nil {
			return err
		}
		if item.recovery != nil {
			recoveryItems = append(recoveryItems, item)
		} else {
			wrapItems = append(wrapItems, item)
		}
	}
	batchSize := max(1, min(client.settings.RotateBatchSize, gkmWrapBatchMaxCount))
	type batch struct {
		items    []*gkmStagedItem
		recovery bool
	}
	batches := []*batch{}
	for first := 0; first < len(wrapItems); first += batchSize {
		batches = append(batches, &batch{items: wrapItems[first:min(first+batchSize, len(wrapItems))]})
	}
	for first := 0; first < len(recoveryItems); first += batchSize {
		batches = append(batches, &batch{items: recoveryItems[first:min(first+batchSize, len(recoveryItems))], recovery: true})
	}
	// one batch, sent until every item has a definite answer
	upload := func(staged *batch) error {
		pending := staged.items
		for sendCount := 0; 0 < len(pending); sendCount += 1 {
			if client.settings.RotateStageSendCount <= sendCount {
				return fmt.Errorf("%w: gkm gave no answer for %d deliveries", ErrGkmUnavailable, len(pending))
			}
			var reply *protocol.GkmWrapBatchReply
			var err error
			if staged.recovery {
				request := &protocol.GkmRecoveryWrapBatch{}
				for _, item := range pending {
					request.Items = append(request.Items, item.recovery)
				}
				reply, err = client.args.Api.UploadRecoveryWraps(ctx, self.repoId, groupId, key.Generation(), key.Commitment(), request)
			} else {
				request := &protocol.GkmWrapBatch{}
				for _, item := range pending {
					request.Deliveries = append(request.Deliveries, item.delivery)
				}
				reply, err = client.args.Api.UploadWraps(ctx, self.repoId, groupId, key.Generation(), key.Commitment(), request)
			}
			if err != nil {
				return err
			}
			if len(reply.GetResults()) != len(pending) {
				return fmt.Errorf("%w: %d results for %d deliveries", ErrGkmReplyInvalid, len(reply.GetResults()), len(pending))
			}
			again := []*gkmStagedItem{}
			for index, result := range reply.GetResults() {
				item := pending[index]
				switch result.GetStatus() {
				case http.StatusCreated, http.StatusOK:
				case http.StatusPreconditionFailed:
					// under this rotation's own commitment: a RecoveryWrap's path holds an earlier try's bytes, and a
					// delivery's must be this rotator's own
					if !staged.recovery && !self.ownStagedWinner(state, result.GetWinner(), item.delivery) {
						client.alarm(&GkmAlarm{Kind: GkmAlarmWrapConflict, RepoId: self.repoId, GroupId: groupId, Generation: key.Generation(), Detail: "a staged delivery's path holds another's bytes"})
						return fmt.Errorf("%w: a staged delivery's path holds another's bytes", ErrGkmAuthentication)
					}
				case 0:
					again = append(again, item)
				case http.StatusForbidden:
					return fmt.Errorf("%w: gkm refused a staged delivery", ErrGkmWait)
				default:
					return &GkmError{Status: int(result.GetStatus())}
				}
			}
			pending = again
		}
		return nil
	}
	concurrency := max(1, client.settings.RotateBatchConcurrency)
	slots := make(chan struct{}, concurrency)
	errs := make([]error, len(batches))
	var wait sync.WaitGroup
	for index, staged := range batches {
		slots <- struct{}{}
		wait.Add(1)
		go func() {
			defer wait.Done()
			defer func() { <-slots }()
			errs[index] = upload(staged)
		}()
	}
	wait.Wait()
	return errors.Join(errs...)
}

// The recipient a wrap-pending hint names: s:<sidecar_id> or d:<delegation_id>, as a wrap path writes it.
func gkmParseHintRecipient(recipient string) (wrapType GkmWrapType, id []byte, err error) {
	prefix, hexId, found := strings.Cut(recipient, ":")
	if !found {
		return 0, nil, fmt.Errorf("%w: a hint's recipient", ErrGkmMalformed)
	}
	id, err = hex.DecodeString(hexId)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: a hint's recipient", ErrGkmMalformed)
	}
	switch {
	case prefix == "s" && len(id) == gkmIdByteCount:
		return GkmWrapTypeReader, id, nil
	case prefix == "d" && len(id) == gkmDelegationIdByteCount:
		return GkmWrapTypeDelegation, id, nil
	}
	return 0, nil, fmt.Errorf("%w: a hint's recipient", ErrGkmMalformed)
}

// §10.6's late delivery, the deliver row: answers a wrap-pending hint naming recipient with one LATE delivery of
// the newest generation this device holds and judged, after a random wait of up to LateDeliverJitter. It returns
// nil with nothing written when this device may not deliver or the recipient is no holder at its state: another
// holder, or a later state, serves it. A 412 means another holder delivered first, whose delivery is judged as any.
func (self *GkmGroupClient) DeliverLate(ctx context.Context, repoId Id, recipient string) error {
	if err := self.wait(ctx, self.jitter(self.settings.LateDeliverJitter)); err != nil {
		return err
	}
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	return manager.deliverLateInFlow(ctx, recipient)
}

// DeliverLate, with the group's flow held.
func (self *gkmGroupManager) deliverLateInFlow(ctx context.Context, recipient string) error {
	client := self.client
	wrapType, recipientId, err := gkmParseHintRecipient(recipient)
	if err != nil {
		return err
	}
	state, err := client.currentState()
	if err != nil {
		return err
	}
	pins, err := client.repoPins(self.repoId)
	if err != nil {
		return err
	}
	top, err := client.newestHeldGeneration(self.repoId)
	if err != nil {
		return err
	}
	if top.key == nil || top.poisoned {
		// nothing this device may hand on
		return nil
	}
	rotate := top.generation.Rotate
	// R2: signed at or past the claim's pin
	if state.Pin().GetVersion() < rotate.GetAuth().GetVersion() {
		return fmt.Errorf("%w: this state is below gen/%d's pin", ErrGkmAuthAhead, rotate.GetGeneration())
	}
	now := client.clock.Now()
	at := now
	if generationTime := time.UnixMilli(rotate.GetTimeMs()); at.Before(generationTime) {
		at = generationTime
	}
	holders, err := KeyHolders(state, self.repoId, at)
	if err != nil {
		return err
	}
	// the deliverer: a holder, or covered, standing and not read_only
	selfRow := state.SidecarRow(client.args.SidecarId)
	if !gkmRowStanding(selfRow) || gkmRowReadOnly(selfRow) || !gkmHolderOrCovered(state, holders, self.repoId, client.args.SidecarId, at) {
		return nil
	}
	// R6: the recipient a holder at this state and time, at a key it published and gkm serves
	var publicKey []byte
	switch wrapType {
	case GkmWrapTypeReader:
		if !holders.Contains(GkmHolderLeaf, recipientId) && !holders.Contains(GkmHolderAgent, recipientId) {
			return nil
		}
		sidecarId, _ := IdFromBytes(recipientId)
		signedKey, err := client.args.Api.ReaderKey(ctx, sidecarId)
		if err != nil {
			return err
		}
		readerKey, err := GkmAdmittedReaderKey(state, signedKey, sidecarId, at.UnixMilli())
		if err != nil {
			// no key that passes the readerkey check: the recipient publishes one and asks again
			return nil
		}
		publicKey = readerKey.Body.GetXwingPublicKey()
	case GkmWrapTypeDelegation:
		holder, held := holders.DelegationRecipient(recipientId)
		if !held {
			return nil
		}
		if holder.Kind == GkmHolderForwarding {
			fetch, err := GkmForwardingReaderKeysFetched(ctx, state, GkmHolders{holder}, self.delegationKeysFetch())
			if err != nil {
				return err
			}
			key, err := GkmForwardingReaderKey(ctx, state, holder, fetch)
			if errors.Is(err, ErrGkmKeyMissing) {
				// no key to seal to yet: its sidecar uploads the object, then writes this delivery itself
				return nil
			}
			if err != nil {
				return err
			}
			publicKey = key
			break
		}
		for _, delegation := range state.Delegations() {
			if bytes.Equal(delegation.GetDelegationId(), recipientId) {
				publicKey = delegation.GetReaderXwingPublicKey()
			}
		}
		if len(publicKey) != gkmXWingPublicKeyByteCount {
			return nil
		}
	}
	body, err := SealGkmDelivery(top.key, &GkmDeliveryArgs{
		GroupId: pins.groupId, Type: wrapType, Recipient: recipientId, RecipientPublicKey: publicKey,
		Kind: GkmDeliveryLate, Auth: state.Pin(), Time: at,
	})
	if err != nil {
		return err
	}
	signed, err := SignGkmDelivery(body, wrapType, client.args.Sign)
	if err != nil {
		return err
	}
	signedBytes, err := gkmSignedBytes(signed)
	if err != nil {
		return err
	}
	for sendCount := 0; sendCount < max(1, client.settings.RotateStageSendCount); sendCount += 1 {
		reply, err := client.args.Api.UploadWraps(ctx, self.repoId, pins.groupId, rotate.GetGeneration(), rotate.GetCommitment(), &protocol.GkmWrapBatch{Deliveries: [][]byte{signedBytes}})
		if err != nil {
			return err
		}
		if len(reply.GetResults()) != 1 {
			return fmt.Errorf("%w: %d results for one delivery", ErrGkmReplyInvalid, len(reply.GetResults()))
		}
		result := reply.GetResults()[0]
		switch result.GetStatus() {
		case http.StatusCreated, http.StatusOK:
			return nil
		case 0:
			// not tried: the same bytes go again
			continue
		case http.StatusPreconditionFailed:
			return self.judgeLateWinner(state, pins.groupId, top, wrapType, result.GetWinner())
		case http.StatusConflict:
			// not the newest generation any more, or a key gkm no longer serves: the next hint asks again
			return nil
		case http.StatusForbidden:
			return fmt.Errorf("%w: gkm refused a late delivery", ErrGkmWait)
		default:
			return &GkmError{Status: int(result.GetStatus())}
		}
	}
	return fmt.Errorf("%w: gkm gave no answer for a late delivery", ErrGkmUnavailable)
}

// Judges the delivery that holds a late delivery's path in groupId, as any member judges one it reads when it
// answers wrap-pending (§10.9): a refused one is alarmed, and poisons nothing later.
func (self *gkmGroupManager) judgeLateWinner(state GkmAuthView, groupId Id, top *gkmHeldGeneration, wrapType GkmWrapType, winner []byte) error {
	client := self.client
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(winner, signed); err != nil {
		return fmt.Errorf("%w: a late delivery's winner", ErrGkmReplyInvalid)
	}
	delivery, err := ParseGkmDelivery(signed, wrapType, GkmIdentityKeys(state))
	if err != nil {
		client.alarm(&GkmAlarm{Kind: GkmAlarmRefused, RepoId: self.repoId, Generation: top.generation.Rotate.GetGeneration(), Reason: GkmRefusalDelivery, Detail: "a delivery that does not verify"})
		return nil
	}
	verdict, err := CheckDelivery(state, &GkmDeliveryCheckArgs{RepoId: self.repoId, Delivery: delivery, Generation: top.generation, GroupId: groupId, Now: client.clock.Now()})
	if err != nil {
		return err
	}
	if verdict.Refused {
		client.alarm(&GkmAlarm{
			Kind: GkmAlarmRefused, RepoId: self.repoId, Generation: top.generation.Rotate.GetGeneration(),
			SidecarId: delivery.SignerId, Reason: verdict.Reason, Detail: verdict.Detail,
		})
	}
	return nil
}

// The repos this device holds a group of: those with a pins record.
func (self *GkmGroupClient) heldRepoIds() ([]Id, error) {
	names, err := self.args.Secrets.List("")
	if err != nil {
		return nil, err
	}
	repoIds := []Id{}
	for _, name := range names {
		repoHex, found := strings.CutSuffix(name, "/pins")
		if !found {
			continue
		}
		idBytes, err := hex.DecodeString(repoHex)
		if err != nil {
			continue
		}
		if repoId, err := IdFromBytes(idBytes); err == nil {
			repoIds = append(repoIds, repoId)
		}
	}
	return repoIds, nil
}

// A Delegation's dwraps (§10.5): the device that signed a Delegation writes, for each repo it holds whose key the
// Delegation's reach holds, one LATE DelegationWrap of the newest generation to the Delegation's reader key, so its
// agents read at once. Each is a late delivery under its checks, and a repo this device may not deliver for is
// passed over: another holder answers its wrap-pending. For a forwarding Delegation the reach is the config alone,
// and its sidecar calls this once GkmApi.UploadDelegationKey has stored the key's object (DESIGN-DETAILS 4.2.6's S3
// and S4), at a newer one's supersession as at its first.
func (self *GkmGroupClient) DeliverDelegationWraps(ctx context.Context, delegationId []byte) error {
	if len(delegationId) != gkmDelegationIdByteCount {
		return fmt.Errorf("%w: a delegation id of %d bytes", ErrGkmMalformed, len(delegationId))
	}
	repoIds, err := self.heldRepoIds()
	if err != nil {
		return err
	}
	recipient := "d:" + hex.EncodeToString(delegationId)
	errs := []error{}
	for _, repoId := range repoIds {
		manager := self.manager(repoId)
		err := func() error {
			manager.flowLock.Lock()
			defer manager.flowLock.Unlock()
			return manager.deliverLateInFlow(ctx, recipient)
		}()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
