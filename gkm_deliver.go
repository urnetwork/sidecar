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
// this C'. A result of 0 is sent again. A 409 or 403 ends the staging with ErrGkmWait, which the rotation first holds
// against gen/: gkm takes a STAGED delivery only while its generation is unclaimed, so where a claim stands now the
// race was lost at the claim, and the rotation takes the winner as a 412 has it (gkm_rotate.go).
//
// A LATE delivery (the deliver row) answers wrap-pending: after a random wait of up to LateDeliverJitter, a holder
// that is not read_only, holds RK_g* and judged gen/<g*>, at a tip at or past its pin (R2), delivers to a recipient
// among the holders at its own state and time (R6), to the key gkm serves for it, signed at that state; gkm's 409,
// a newer generation or a key it no longer serves, refetches both and tries once more. KF2 and KF3's granting
// device waits none: the holder that signed the recipient's admission, a grant or share in the repo's access log
// naming it, or the Delegation it names (gkmGrantingSigner). Hints are lossy, so in KeyDelivery mode each sync
// answers too (answerLateInFlow): a writer, or the signer of a holder's admission in the config and directory
// groups, writes a LATE delivery to each holder the newest generation's own state did not hold, once a generation,
// so a holder offline at a hint delivers at its next resync. At a pending hint, gkm's wake after a holder change,
// the granting device answers at once and every other holder after PendingCommitWait (KeyDeliveryPending), whose
// PUT then meets the granting device's delivery.
//
// A reading: in a data repo a rotator that is no leaf wraps to every member device among the holders, a device
// waiting for a seat included, since only a leaf sees which devices are seated; each is a key holder, so nothing
// reaches a non-reader.

package sidecar

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// gkm's 409 or 403 to a STAGED delivery, under ErrGkmWait. gkm takes one only while gen/<g> is absent (§10.6), so a
// rotation that meets it reads gen/ before it waits (rotateInFlow): another rotator's claim may have landed meanwhile.
var errGkmStagedRefused = errors.New("gkm refused a staged delivery")

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
			if err := self.auditWrapAllowed(state, sidecarId, at); err != nil {
				// never ahead of the reader list (gkm_audit.go): it gets this generation by a late delivery
				// once the list at a signer's state shows it
				if client.log.V(1).Enabled() {
					client.log.Infof("[gkm]a rotation skipped a wrap: %v", err)
				}
				continue
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
			var recoveryKey *GkmRecoveryKey
			switch {
			case client.args.RecoveryKeyAt != nil:
				recoveryKey, err = client.args.RecoveryKeyAt(state, memberId)
			case client.args.RecoveryKey != nil:
				recoveryKey, err = client.args.RecoveryKey(memberId)
			}
			if err != nil {
				return nil, err
			}
			if recoveryKey == nil || len(recoveryKey.XwingPublicKey) != gkmXWingPublicKeyByteCount ||
				len(recoveryKey.BindingKeySha256) != gkmDigestByteCount || !bytes.Equal(recoveryKey.BindingKeySha256, state.Member(memberId).GetRecoveryKeySha256()) {
				return nil, fmt.Errorf("%w: no recovery key for the member's binding at this pin", ErrGkmKeyMissing)
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
	batchSize := max(1, min(client.settings.RotateBatchSize, client.settings.WrapBatchMaxCount))
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
				case http.StatusConflict, http.StatusForbidden:
					return fmt.Errorf("%w: %w", ErrGkmWait, errGkmStagedRefused)
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
// KF2 and KF3's granting device waits none (gkmGrantingSigner): the signer of the recipient's admission, of a grant
// or share in the repo's access log naming it, or of the Delegation it names delivers at once, and the other holders
// after their wait, whose PUT then meets its delivery.
func (self *GkmGroupClient) DeliverLate(ctx context.Context, repoId Id, recipient string) error {
	if !self.grantingFor(repoId, recipient) {
		if err := self.wait(ctx, self.jitter(self.settings.LateDeliverJitter)); err != nil {
			return err
		}
	}
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	return manager.deliverLateInFlow(ctx, recipient)
}

// Whether this device is the granting device of a delivery of repoId to recipient at its newest verified state
// (gkmGrantingSigner). False for a malformed recipient, for this device itself, or with no state.
func (self *GkmGroupClient) grantingFor(repoId Id, recipient string) bool {
	state, err := self.currentState()
	if err != nil {
		return false
	}
	return gkmGrantingSigner(state, repoId, recipient, self.args.SidecarId)
}

// Whether signerId is KF2 and KF3's granting device of a delivery of repoId to recipient at view, which delivers at
// once while the other holders wait (DESIGN-DETAILS 6.2.4's may(c), §10.7's KF3, §5.6's reads row): for a sidecar,
// the signer of its admission, or of a grant or an EvsShare in the repo's access log whose subject is the sidecar, its
// member or one of its tags; for a Delegation, the signer of its row (§10.5's dwraps). Who signed is read from the rows,
// never trusted from a hint; a grant naming the recipient through another atom finds no granting device, and the
// holders then answer after their waits.
func gkmGrantingSigner(view GkmAuthView, repoId Id, recipient string, signerId Id) bool {
	wrapType, recipientId, err := gkmParseHintRecipient(recipient)
	if err != nil {
		return false
	}
	if wrapType == GkmWrapTypeDelegation {
		for _, delegation := range view.Delegations() {
			if bytes.Equal(delegation.GetDelegationId(), recipientId) {
				return bytes.Equal(delegation.GetSigner(), signerId.Bytes())
			}
		}
		return false
	}
	sidecarId, err := IdFromBytes(recipientId)
	if err != nil || sidecarId == signerId {
		return false
	}
	if gkmAdmissionSignedBy(view, sidecarId, signerId) {
		return true
	}
	row := view.SidecarRow(sidecarId)
	repo := view.Repo(repoId)
	if row == nil || repo == nil {
		return false
	}
	// the subjects a grant may name the recipient by: itself, its member, or a tag it carries
	subjects := [][]byte{recipientId}
	if 0 < len(row.GetMemberId()) {
		subjects = append(subjects, row.GetMemberId())
	}
	subjects = append(subjects, row.GetTagIds()...)
	names := func(subject []byte) bool {
		return slices.ContainsFunc(subjects, func(candidate []byte) bool { return bytes.Equal(candidate, subject) })
	}
	for _, grant := range repo.GetGrants() {
		if bytes.Equal(grant.GetSigner(), signerId.Bytes()) && names(grant.GetSubject()) {
			return true
		}
	}
	for _, share := range repo.GetShares() {
		if bytes.Equal(share.GetSigner(), signerId.Bytes()) && names(share.GetSubject()) {
			return true
		}
	}
	return false
}

// Whether signerId signed sidecarId's admission at view: one of its row's admission signers.
func gkmAdmissionSignedBy(view GkmAuthView, sidecarId Id, signerId Id) bool {
	row := view.SidecarRow(sidecarId)
	return row != nil && slices.ContainsFunc(row.GetAdmissionSigners(), func(signer []byte) bool { return bytes.Equal(signer, signerId.Bytes()) })
}

// What this device's LATE deliveries of a repo's newest generation are made at: its newest verified state, the
// repo's pins, the generation it holds and judged with its key, the delivery's time, max(now, gen/<g>'s time), and
// KeyHolders there.
type gkmLateDelivery struct {
	state   GkmAuthView
	pins    *gkmRepoPins
	top     *gkmHeldGeneration
	at      time.Time
	holders GkmHolders
}

// How one LATE delivery ended.
type gkmLateOutcome int

const (
	// gkm took it: 201, or 200 for the same bytes again
	gkmLateDelivered gkmLateOutcome = iota + 1
	// another holder's delivery stood at its path, 412, and was judged
	gkmLateStood
	// nothing written: the recipient is no holder here, has no key to seal to that passes its check, or gkm answered
	// 409 (not the newest generation any more, or a key it no longer serves) again after the refetch, which a later ask
	// or sync tries again
	gkmLatePassed
	// gkm answered 409 to one try: the deliver row's refetch and second try follow (deliverLateToInFlow), so no caller
	// of that sees it
	gkmLateConflict
)

// The deliverer's row of the late delivery: nil, with no error, when this device may not hand the newest generation
// on: it holds none with its key, or it poisoned it, or it is not standing, is read_only, or is neither a holder nor
// covered at its state. ErrGkmAuthAhead while its state is below gen/<g>'s pin (R2).
func (self *gkmGroupManager) lateDeliveryInFlow() (*gkmLateDelivery, error) {
	client := self.client
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
	if top.key == nil || top.poisoned {
		// nothing this device may hand on
		return nil, nil
	}
	rotate := top.generation.Rotate
	// R2: signed at or past the claim's pin
	if state.Pin().GetVersion() < rotate.GetAuth().GetVersion() {
		return nil, fmt.Errorf("%w: this state is below gen/%d's pin", ErrGkmAuthAhead, rotate.GetGeneration())
	}
	at := client.clock.Now()
	if generationTime := time.UnixMilli(rotate.GetTimeMs()); at.Before(generationTime) {
		at = generationTime
	}
	holders, err := KeyHolders(state, self.repoId, at)
	if err != nil {
		return nil, err
	}
	// the deliverer: a holder, or covered, standing and not read_only
	selfRow := state.SidecarRow(client.args.SidecarId)
	if !gkmRowStanding(selfRow) || gkmRowReadOnly(selfRow) || !gkmHolderOrCovered(state, holders, self.repoId, client.args.SidecarId, at) {
		return nil, nil
	}
	return &gkmLateDelivery{state: state, pins: pins, top: top, at: at, holders: holders}, nil
}

// DeliverLate, with the group's flow held.
func (self *gkmGroupManager) deliverLateInFlow(ctx context.Context, recipient string) error {
	if _, _, err := gkmParseHintRecipient(recipient); err != nil {
		return err
	}
	late, err := self.lateDeliveryInFlow()
	if err != nil || late == nil {
		return err
	}
	_, err = self.deliverLateToInFlow(ctx, late, recipient)
	return err
}

// One LATE delivery to recipient at late (deliverLateOnceInFlow), and on gkm's 409, which says gkm holds a newer
// generation than late's or no longer serves the key the delivery was sealed to, the deliver row's refetch and one
// more try (DESIGN-DETAILS 6.2.4): gkm's newest generations are taken at the newest verified state, late is made again
// in place from what this device then holds, and the second try reads the recipient's key afresh. A second 409 passes
// the recipient to its next ask or this device's next sync, as a refetch that leaves this device nothing to hand on
// does.
func (self *gkmGroupManager) deliverLateToInFlow(ctx context.Context, late *gkmLateDelivery, recipient string) (gkmLateOutcome, error) {
	outcome, err := self.deliverLateOnceInFlow(ctx, late, recipient)
	if err != nil || outcome != gkmLateConflict {
		return outcome, err
	}
	state, err := self.client.currentState()
	if err != nil {
		return 0, err
	}
	if err := self.refreshGenerationsInFlow(ctx, state); err != nil {
		return 0, err
	}
	again, err := self.lateDeliveryInFlow()
	if err != nil {
		return 0, err
	}
	if again == nil {
		return gkmLatePassed, nil
	}
	*late = *again
	outcome, err = self.deliverLateOnceInFlow(ctx, late, recipient)
	if outcome == gkmLateConflict {
		return gkmLatePassed, err
	}
	return outcome, err
}

// One try of a LATE delivery to recipient at late, the deliver row's checks from R6 on: the recipient a holder at
// late's state and time, at a key it published and gkm serves; sealed, signed at that state and PUT, a lost answer
// sending the same bytes again (If-None-Match), and a 412's winner judged. gkm's 409 answers gkmLateConflict.
func (self *gkmGroupManager) deliverLateOnceInFlow(ctx context.Context, late *gkmLateDelivery, recipient string) (gkmLateOutcome, error) {
	client := self.client
	wrapType, recipientId, err := gkmParseHintRecipient(recipient)
	if err != nil {
		return 0, err
	}
	state, holders, at, top := late.state, late.holders, late.at, late.top
	rotate := top.generation.Rotate
	// R6: the recipient a holder at this state and time, at a key it published and gkm serves
	var publicKey []byte
	switch wrapType {
	case GkmWrapTypeReader:
		if !holders.Contains(GkmHolderLeaf, recipientId) && !holders.Contains(GkmHolderAgent, recipientId) {
			return gkmLatePassed, nil
		}
		sidecarId, _ := IdFromBytes(recipientId)
		if err := self.auditWrapAllowed(state, sidecarId, at); err != nil {
			// the reader list at this state does not show the audit reader (gkm_audit.go)
			return gkmLatePassed, nil
		}
		signedKey, err := client.args.Api.ReaderKey(ctx, sidecarId)
		if err != nil {
			return 0, err
		}
		readerKey, err := GkmAdmittedReaderKey(state, signedKey, sidecarId, at.UnixMilli())
		if err != nil {
			// no key that passes the readerkey check: the recipient publishes one and asks again
			return gkmLatePassed, nil
		}
		publicKey = readerKey.Body.GetXwingPublicKey()
	case GkmWrapTypeDelegation:
		holder, held := holders.DelegationRecipient(recipientId)
		if !held {
			return gkmLatePassed, nil
		}
		if holder.Kind == GkmHolderForwarding {
			fetch, err := GkmForwardingReaderKeysFetched(ctx, state, GkmHolders{holder}, self.delegationKeysFetch())
			if err != nil {
				return 0, err
			}
			key, err := GkmForwardingReaderKey(ctx, state, holder, fetch)
			if errors.Is(err, ErrGkmKeyMissing) {
				// no key to seal to yet: its sidecar uploads the object, then writes this delivery itself
				return gkmLatePassed, nil
			}
			if err != nil {
				return 0, err
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
			return gkmLatePassed, nil
		}
	}
	body, err := SealGkmDelivery(top.key, &GkmDeliveryArgs{
		GroupId: late.pins.groupId, Type: wrapType, Recipient: recipientId, RecipientPublicKey: publicKey,
		Kind: GkmDeliveryLate, Auth: state.Pin(), Time: at,
	})
	if err != nil {
		return 0, err
	}
	signed, err := SignGkmDelivery(body, wrapType, client.args.Sign)
	if err != nil {
		return 0, err
	}
	signedBytes, err := gkmSignedBytes(signed)
	if err != nil {
		return 0, err
	}
	for sendCount := 0; sendCount < max(1, client.settings.RotateStageSendCount); sendCount += 1 {
		reply, err := client.args.Api.UploadWraps(ctx, self.repoId, late.pins.groupId, rotate.GetGeneration(), rotate.GetCommitment(), &protocol.GkmWrapBatch{Deliveries: [][]byte{signedBytes}})
		if err != nil {
			return 0, err
		}
		if len(reply.GetResults()) != 1 {
			return 0, fmt.Errorf("%w: %d results for one delivery", ErrGkmReplyInvalid, len(reply.GetResults()))
		}
		result := reply.GetResults()[0]
		switch result.GetStatus() {
		case http.StatusCreated, http.StatusOK:
			return gkmLateDelivered, nil
		case 0:
			// not tried: the same bytes go again
			continue
		case http.StatusPreconditionFailed:
			return gkmLateStood, self.judgeLateWinner(state, late.pins.groupId, top, wrapType, result.GetWinner())
		case http.StatusConflict:
			// not the newest generation any more, or a key gkm no longer serves: refetched and tried once more
			return gkmLateConflict, nil
		case http.StatusForbidden:
			return 0, fmt.Errorf("%w: gkm refused a late delivery", ErrGkmWait)
		default:
			return 0, &GkmError{Status: int(result.GetStatus())}
		}
	}
	return 0, fmt.Errorf("%w: gkm gave no answer for a late delivery", ErrGkmUnavailable)
}

// §10.6's late wraps at a sync, the KeyDelivery resync's answer (KEYS-M2-20): what the asks this device's lost
// wrap-pending hints named would have brought, since hints are lossy and correctness rests on the hourly resync
// (§6.8). A writer of the repo, the hinted holders' first row, or in the config and directory groups the device that
// signed a holder's admission (§5.6's reads row), writes one LATE delivery of the newest generation, by the deliver
// row's checks, to each holder at its state that gen/<g>'s own state, KeyHolders at the claim's pin and time, did not
// hold, so no STAGED delivery reached it:
//
//	joined       a member device or agent reading the repo since the claim, an agent its Delegation no longer
//	             covers among them: a ReaderWrap at its current ReaderKey
//	delegation   a Delegation live since the claim, whose signer's dwraps a kill may have cut short: a DelegationWrap
//	forwarding   a sidecar's forwarding Delegation newer than the claim's: a DelegationWrap to its key, where its
//	             object stands
//
// at most ResyncLateDeliverMaxCount a sync, each recipient once a generation: the keychain's late-answered record
// keeps those gkm took or found answered, so a later sync PUTs nothing for them again. A claim older than this
// device's previous base, whose state it no longer retains, is told by position instead: a sidecar whose row was
// admitted or went live past the claim's position, a Delegation filed past it, which misses a holder whose read
// began later by a grant alone. A holder whose ReaderKey lapsed before the claim, which the claim's state holds and
// its rotator skipped, is not seen here either: its ask's hint answers both. Nothing is answered where this device may
// not deliver.
func (self *gkmGroupManager) answerLateInFlow(ctx context.Context) error {
	client := self.client
	if client.settings.ResyncLateDeliverMaxCount <= 0 {
		return nil
	}
	// a device that answers nothing here, no writer of a data repo, computes no holders at every sync
	if state, err := client.currentState(); err != nil {
		return nil
	} else if !gkmWrites(state, self.repoId, client.args.SidecarId) && !gkmGroupLeafRanked(state.Repo(self.repoId)) {
		return nil
	}
	late, err := self.lateDeliveryInFlow()
	switch {
	case errors.Is(err, ErrGkmUnavailable), errors.Is(err, ErrGkmKeyMissing), errors.Is(err, ErrGkmAuthAhead):
		// no verified state, no generation held, or a state below the claim: nothing to hand on yet
		return nil
	case err != nil:
		return err
	case late == nil:
		return nil
	}
	generation := late.top.generation.Rotate.GetGeneration()
	recipients, err := self.lateRecipientsInFlow(late)
	if err != nil {
		return err
	}
	newlyAnswered := []string{}
	errs := []error{}
	yield := client.newYield()
	for _, recipient := range recipients {
		yield.step()
		outcome, err := self.deliverLateToInFlow(ctx, late, recipient)
		if moved := late.top.generation.Rotate.GetGeneration(); moved != generation {
			// a 409's refetch took a newer generation: what this pass answered of the older one is moot, and the next
			// sync answers the newer one's holders, its claim's STAGED deliveries told afresh
			if err == nil && (outcome == gkmLateDelivered || outcome == gkmLateStood) {
				errs = append(errs, client.noteLateAnswered(self.repoId, moved, []string{recipient}))
			}
			errs = append(errs, err)
			return errors.Join(errs...)
		}
		if err != nil {
			errs = append(errs, err)
			if gkmUnreachable(ctx, err) {
				// the rest wait for the next sync
				break
			}
			continue
		}
		if outcome == gkmLateDelivered || outcome == gkmLateStood {
			newlyAnswered = append(newlyAnswered, recipient)
		}
	}
	if 0 < len(newlyAnswered) {
		errs = append(errs, client.noteLateAnswered(self.repoId, generation, newlyAnswered))
	}
	return errors.Join(errs...)
}

// The recipients a sync's late answer writes to at late (answerLateInFlow's rows), as their wrap paths name them, at
// most ResyncLateDeliverMaxCount, none the keychain records as answered for late's generation: none where this device
// answers nothing for the repo, or where it cannot place the claim, which the generation's own checks alarm.
func (self *gkmGroupManager) lateRecipientsInFlow(late *gkmLateDelivery) ([]string, error) {
	client := self.client
	if client.settings.ResyncLateDeliverMaxCount <= 0 {
		return nil, nil
	}
	rotate := late.top.generation.Rotate
	repo := late.state.Repo(self.repoId)
	writer := gkmWrites(late.state, self.repoId, client.args.SidecarId)
	if !writer && !gkmGroupLeafRanked(repo) {
		return nil, nil
	}
	staged, err := self.stagedHoldersInFlow(late)
	if err != nil {
		if client.log.V(1).Enabled() {
			client.log.Infof("[gkm]%s no late delivery at this sync: %v", self.repoId, err)
		}
		return nil, nil
	}
	answered, err := client.lateAnswered(self.repoId, rotate.GetGeneration())
	if err != nil {
		return nil, err
	}
	recipients := []string{}
	for _, holder := range late.holders {
		if client.settings.ResyncLateDeliverMaxCount <= len(recipients) {
			break
		}
		recipient := ""
		switch holder.Kind {
		case GkmHolderLeaf, GkmHolderAgent:
			if bytes.Equal(holder.Id, client.args.SidecarId.Bytes()) || staged(holder) {
				continue
			}
			if !writer {
				// a config or directory group's non-writer answers the devices whose admission it signed alone
				sidecarId, err := IdFromBytes(holder.Id)
				if err != nil || !gkmAdmissionSignedBy(late.state, sidecarId, client.args.SidecarId) {
					continue
				}
			}
			recipient = "s:" + hex.EncodeToString(holder.Id)
		case GkmHolderDelegation:
			if !writer || staged(holder) {
				continue
			}
			recipient = "d:" + hex.EncodeToString(holder.Id)
		case GkmHolderForwarding:
			if !writer {
				continue
			}
			if staged(holder) {
				continue
			}
			recipient = "d:" + hex.EncodeToString(holder.ForwardDelegationId)
		default:
			// a RecoveryWrap is no late delivery: the recovery flows write their own
			continue
		}
		if !answered[recipient] {
			recipients = append(recipients, recipient)
		}
	}
	return recipients, nil
}

// What a KeyDelivery device's pending hint has it do for a repo it holds (§10.6's pending changes row, §10.7's KF2 and
// KF3; DESIGN-DETAILS 6.2.4's may(c)), and whether it is the granting device, which acts at once while every other
// holder first waits PendingCommitWait: pending when it would write a LATE delivery to a holder the newest generation's
// claim did not reach (answerLateInFlow's recipients), or may rotate and a rotation is due, a drop key's renewal
// among them; granting when it is gkmGrantingSigner of a recipient it would deliver to. It first takes what gkm holds
// past this device's generations, so gkm's wake of a recipient, a delivery to this device, is taken at once whatever
// else is pending. An error leaves nothing to wait for.
func (self *GkmGroupClient) KeyDeliveryPending(ctx context.Context, repoId Id) (pending bool, granting bool, err error) {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return false, false, err
	}
	if err := manager.takeGenerationsInFlow(ctx, state); err != nil && !errors.Is(err, ErrGkmKeyMissing) {
		return false, false, err
	}
	late, err := manager.lateDeliveryInFlow()
	switch {
	case errors.Is(err, ErrGkmKeyMissing), errors.Is(err, ErrGkmAuthAhead):
		// no generation held, or a state below the claim: nothing to hand on yet
	case err != nil:
		return false, false, err
	case late != nil:
		recipients, err := manager.lateRecipientsInFlow(late)
		if err != nil {
			return false, false, err
		}
		for _, recipient := range recipients {
			if gkmGrantingSigner(late.state, repoId, recipient, self.args.SidecarId) {
				granting = true
				break
			}
		}
		if 0 < len(recipients) {
			return true, granting, nil
		}
	}
	due, err := manager.rotationPendingInFlow(state)
	return due, false, err
}

// Whether this device may rotate the repo at state now and a rotation is due there (rotationDueInFlow), its drop key's
// renewal included (RenewDropKey's rule): what a pending hint's run would rotate for.
func (self *gkmGroupManager) rotationPendingInFlow(state GkmAuthView) (bool, error) {
	client := self.client
	top, err := client.newestHeldGeneration(self.repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := client.clock.Now()
	holders, err := KeyHolders(state, self.repoId, now)
	if err != nil {
		return false, err
	}
	if self.mayRotate(state, holders, now) != nil {
		return false, nil
	}
	if _, due, err := self.rotationDueInFlow(state); err != nil || due {
		return due, err
	}
	rotate := top.generation.Rotate
	if !gkmRepoTakesDeposits(state.Repo(self.repoId)) || !gkmWrites(state, self.repoId, client.args.SidecarId) || top.key == nil {
		return false, nil
	}
	renewAt := time.UnixMilli(rotate.GetDropNotAfterMs()).Add(-client.settings.DropKeyRenewBefore)
	return len(rotate.GetDropPublicKey()) == 0 || !now.Before(renewAt), nil
}

// Whether a holder at late's state was among the holders gen/<g>'s STAGED deliveries went to: KeyHolders at the
// claim's pin and time where this device retains that state; else, the claim being before its previous base, whether
// the holder's row stood at the claim's position, a sidecar admitted and live by then and a Delegation filed by then,
// a forwarding holder's by its live Delegation's row. An error for a claim this state cannot place: ahead of it, or
// off its chain, which the generation's own checks alarm.
func (self *gkmGroupManager) stagedHoldersInFlow(late *gkmLateDelivery) (func(holder GkmHolder) bool, error) {
	rotate := late.top.generation.Rotate
	claimState, err := late.state.At(rotate.GetAuth())
	if err == nil {
		staged, err := KeyHolders(claimState, self.repoId, time.UnixMilli(rotate.GetTimeMs()))
		if err != nil {
			return nil, err
		}
		return func(holder GkmHolder) bool {
			switch holder.Kind {
			case GkmHolderLeaf, GkmHolderAgent:
				return staged.Contains(GkmHolderLeaf, holder.Id) || staged.Contains(GkmHolderAgent, holder.Id)
			case GkmHolderForwarding:
				stagedHolder, held := staged.DelegationRecipient(holder.ForwardDelegationId)
				return held && stagedHolder.Kind == GkmHolderForwarding
			}
			return staged.Contains(holder.Kind, holder.Id)
		}, nil
	}
	if !errors.Is(err, ErrGkmAuthNotRetained) {
		return nil, fmt.Errorf("gen/%d's state: %w", rotate.GetGeneration(), err)
	}
	claimVersion := rotate.GetAuth().GetVersion()
	delegationAt := func(delegationId []byte) uint64 {
		for _, delegation := range late.state.Delegations() {
			if bytes.Equal(delegation.GetDelegationId(), delegationId) {
				return delegation.GetAt()
			}
		}
		// a row this state does not show is taken as staged: nothing is sent to it
		return claimVersion
	}
	return func(holder GkmHolder) bool {
		switch holder.Kind {
		case GkmHolderLeaf, GkmHolderAgent:
			sidecarId, err := IdFromBytes(holder.Id)
			if err != nil {
				return true
			}
			row := late.state.SidecarRow(sidecarId)
			return row == nil || max(row.GetAdmittedAt(), row.GetLiveSince()) <= claimVersion
		case GkmHolderDelegation:
			return delegationAt(holder.Id) <= claimVersion
		case GkmHolderForwarding:
			return delegationAt(holder.ForwardDelegationId) <= claimVersion
		}
		return true
	}, nil
}

// The keychain's record of the recipients a sync answered for one generation of a repo (answerLateInFlow): version |
// u64 generation | each recipient as its wrap path writes it, a u16 length before each. A record of an older
// generation answers nothing, and the next note replaces it.
func gkmLateAnsweredRecordName(repoId Id) string {
	return gkmRepoRecordName(repoId, "late-answered")
}

// The recipients the keychain records as answered for generation of the repo.
func (self *GkmGroupClient) lateAnswered(repoId Id, generation uint64) (map[string]bool, error) {
	answered := map[string]bool{}
	encoded, err := self.getRecord(gkmLateAnsweredRecordName(repoId))
	if errors.Is(err, ErrGkmKeyMissing) {
		return answered, nil
	}
	if err != nil {
		return nil, err
	}
	if len(encoded) < 9 || encoded[0] != gkmRecordVersion {
		// unreadable: answered again, which If-None-Match makes safe
		return answered, nil
	}
	if binary.BigEndian.Uint64(encoded[1:9]) != generation {
		return answered, nil
	}
	rest := encoded[9:]
	for 2 <= len(rest) {
		length := int(binary.BigEndian.Uint16(rest[:2]))
		if len(rest) < 2+length {
			break
		}
		answered[string(rest[2:2+length])] = true
		rest = rest[2+length:]
	}
	return answered, nil
}

// Adds recipients to the record of generation's answered recipients, replacing a record of another generation.
func (self *GkmGroupClient) noteLateAnswered(repoId Id, generation uint64, recipients []string) error {
	answered, err := self.lateAnswered(repoId, generation)
	if err != nil {
		return err
	}
	for _, recipient := range recipients {
		answered[recipient] = true
	}
	sorted := make([]string, 0, len(answered))
	for recipient := range answered {
		sorted = append(sorted, recipient)
	}
	slices.Sort(sorted)
	encoded := []byte{gkmRecordVersion}
	encoded = binary.BigEndian.AppendUint64(encoded, generation)
	for _, recipient := range sorted {
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(recipient)))
		encoded = append(encoded, recipient...)
	}
	return self.args.Secrets.Put(gkmLateAnsweredRecordName(repoId), encoded)
}

// Judges the delivery that holds a late delivery's path in groupId, as any member judges one it reads when it
// answers wrap-pending (§10.9): a refused one poisons the generation and is alarmed naming its signer (the poisoned
// row; FS-104), and one valid at its own state poisons nothing, whatever came later.
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
		return self.poisonForDeliveries(groupId, top.generation, []*gkmRefusedDelivery{{delivery: delivery, verdict: verdict}})
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
