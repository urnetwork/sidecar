//go:build !ios_extension

// Ingest and CONSUME (§11.12's deposits rows; EVS1-M2-29): a reader with rw reads a depositor's ref in version order,
// each deposit opened by the drop private key of its slot key's generation, which every reader derives from RK_g, and
// commits a CONSUME deleting the entries it ingested and, at evs, their slots.
//
//	read     the deposit ref's verified statements from version 0, each deposit push's creations standing until a
//	         CONSUME removes them; each standing entry read by its id in epoch 1 (a deposit ref's entries take random
//	         ids in tokens' place and stay at epoch 1, evsEpochExempt), its slot taken from the entry's cleartext
//	         slot_ids, opened with the drop private key, K_dep derived from the object key, then the body
//	         reconstructed and checked against its sealed fields' oid and size, as any file's
//	consume  one CONSUME on the depositor's ref: a removal of each entry at its version, rw, path epoch 1, the
//	         consumer's generation pin from EnsureWritable, and consumed_through the caller's, the highest version at
//	         or below which its read left nothing unconsumed (EvsHead.consumed_through, never falling). A deposit
//	         already gone answers PATH_CONFLICT, which an ingester takes as consumed. One deposit's entries share a
//	         slot, so an ingester consumes a deposit's entries together
//
// The walk reads the ref from version 0 each time, within the catch-up budget; a cursor kept between ingests is the
// review phase's. A CONSUME whose answer was lost goes again under its push id, which evs answers with the commit it
// made and its slot deletes finished; one cut short by a crash is a new push, whose entries are gone, and whose slots
// evs's own retry of the first attempt finished or left (EVS1-M2-20's note).
//
// On desktop and mobile legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One deposit as an ingester reads it, in version order.
type EvsDeposit struct {
	// Its random id, the message id.
	EntryId EvsToken
	// The deposit ref's version its push committed at, the push, its signer and time, and the auth pin it declared,
	// at which the ingester judges the depositor.
	Version         uint64
	PushId          Id
	SignerSidecarId Id
	Time            time.Time
	AuthPin         *bridge.AuthPin
	// The entry's own version, which a CONSUME removes, its size, and the slot holding its key, which an erasure of an
	// unconsumed deposit names (§11.12's closure row).
	EntryVersion uint64
	Size         uint64
	SlotId       Id
}

// A deposit ref's standing deposits after afterVersion, oldest first, each opened and given to visit with its body,
// which visit reads before it returns. visit's error ends the read.
func (self *EvsRepo) ReadDeposits(ctx context.Context, depositorId Id, afterVersion uint64, visit func(deposit *EvsDeposit, body io.Reader) error) error {
	refId := EvsDepositRefId(self.repoId, depositorId)
	head, err := self.readHeadAlone(ctx, refId, true)
	if err != nil {
		return err
	}
	if head.Version == 0 {
		return nil
	}
	walked, err := self.client.verifier.Walk(ctx, self.repoId, refId, 0, EvsChainStart(self.repoId, refId), head.Version)
	if err != nil {
		return err
	}
	type standing struct {
		deposit *EvsDeposit
	}
	standings := map[EvsToken]*standing{}
	order := []EvsToken{}
	for _, statement := range walked {
		push := statement.Statement.Push
		consume := push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME) != 0
		for _, change := range statement.Statement.Changes {
			if len(change.TokenPath) != 1 {
				return fmt.Errorf("%w: a deposit ref's change of %d components", ErrEvsEntryRefused, len(change.TokenPath))
			}
			entryId := change.TokenPath[0]
			if consume || !change.WritesEntry() {
				delete(standings, entryId)
				continue
			}
			pushId, _ := IdFromBytes(push.GetPushId())
			signerId, _ := IdFromBytes(push.GetSignerSidecarId())
			standings[entryId] = &standing{deposit: &EvsDeposit{
				EntryId: entryId, Version: statement.Version, PushId: pushId, SignerSidecarId: signerId,
				Time: evsTime(push.GetTimeMs()), AuthPin: push.GetAuth(),
			}}
			order = append(order, entryId)
		}
		if 0 < push.GetChangeCount() {
			// a deposit push's list rides inline: one entry a deposit, far within 1 KiB
			return fmt.Errorf("%w: a deposit push with its changes under a root", ErrEvsFormatUnsupported)
		}
	}
	for _, entryId := range order {
		held := standings[entryId]
		if held == nil || held.deposit.Version <= afterVersion {
			continue
		}
		delete(standings, entryId)
		if err := self.openDeposit(ctx, refId, held.deposit, visit); err != nil {
			return err
		}
	}
	return nil
}

// Reads one deposit by its id and opens it for visit: see the file header's read row.
func (self *EvsRepo) openDeposit(ctx context.Context, refId Id, deposit *EvsDeposit, visit func(deposit *EvsDeposit, body io.Reader) error) error {
	result, err := self.readPaths(ctx, refId, []*evsReadPath{{token: EvsTokenPath{deposit.EntryId}}}, false)
	if err != nil {
		return err
	}
	defer result.objects.close()
	verified := result.replies[0]
	if verified.Entry == nil {
		// consumed since the walk
		return nil
	}
	entry := verified.Entry
	if len(entry.GetSlotIds()) != 1 || entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
		return fmt.Errorf("%w: a deposit that is not one file of one slot", ErrEvsEntryRefused)
	}
	if err := self.fetchMissing(ctx, result, entry); err != nil {
		return err
	}
	slotBytes, ok := result.objects.slot(entry.GetSlotIds()[0])
	if !ok {
		return ErrEvsObjectMissing
	}
	slot, err := EvsDecodeSlotObject(slotBytes)
	if err != nil {
		return err
	}
	slotKey, ok := EvsSlotKeyAt(slot, 0)
	if !ok || slotKey.GetGeneration() != verified.Statement.Push.GetGeneration() {
		return fmt.Errorf("%w: a deposit slot without its key", ErrEvsSealInvalid)
	}
	repoKey, err := result.keys.repoKey(ctx, slotKey.GetGeneration())
	if err != nil {
		return err
	}
	dropPrivateKey, err := repoKey.DropKeyPair()
	if err != nil {
		return err
	}
	objectKey, err := EvsOpenDepositSlotKey(dropPrivateKey, self.repoId, slotKey)
	if err != nil {
		self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, "", nil)
		return err
	}
	depositKey, err := NewEvsDepositManifestKey(self.repoId, slotKey.GetGeneration(), objectKey)
	if err != nil {
		return err
	}
	slotId, err := IdFromBytes(entry.GetSlotIds()[0])
	if err != nil {
		return err
	}
	result.keys.deposit = &evsDepositKeys{slotId: slotId, generation: slotKey.GetGeneration(), objectKey: objectKey, manifest: depositKey}
	content, fields, _, err := self.reconstructContent(ctx, result, verified, nil)
	if err != nil {
		return err
	}
	defer content.close()
	deposit.EntryVersion = entry.GetVersion()
	deposit.Size = fields.GetSize()
	deposit.SlotId = slotId
	return visit(deposit, content.reader())
}

// A deposit's keys for one read: its slot's object key and the K_dep it derives, which take the slot's and
// manifest's place for that slot and generation (EVS-FORMAT.md's deposits).
type evsDepositKeys struct {
	slotId     Id
	generation uint64
	objectKey  *EvsObjectKey
	manifest   *EvsManifestKey
}

// Commits a CONSUME of args.EntryIds on the deposit ref args.DepositRefId: see the file header's consume row. Each
// entry is read first, by its id, for the version its removal names; one already gone is left out, and a CONSUME of
// none commits nothing.
func (self *EvsRepo) Consume(ctx context.Context, args *EvsConsumeArgs) (*EvsConsumeResult, error) {
	if args == nil || len(args.EntryIds) == 0 {
		return nil, fmt.Errorf("%w: a CONSUME of nothing", ErrEvsWriteInvalid)
	}
	refId := args.DepositRefId
	for rebuild := 0; ; rebuild += 1 {
		repoKey, err := self.client.args.Gkm.EnsureWritable(ctx, self.repoId)
		if err != nil {
			return nil, err
		}
		paths := []*evsReadPath{}
		for _, entryId := range args.EntryIds {
			paths = append(paths, &evsReadPath{token: EvsTokenPath{entryId}})
		}
		result, err := self.readPaths(ctx, refId, paths, 0 < rebuild)
		if err != nil {
			return nil, err
		}
		result.objects.close()
		head := result.head
		if head.Head.GetRefKind() != protocol.EvsRefKind_EVS_REF_DEPOSIT {
			return nil, fmt.Errorf("%w: a CONSUME outside a deposit ref", ErrEvsWriteInvalid)
		}
		ownerId, err := IdFromBytes(head.Head.GetOwnerSidecarId())
		if err != nil {
			return nil, fmt.Errorf("%w: the deposit ref's owner", ErrEvsReplyInvalid)
		}
		changes := []*EvsPlannedChange{}
		for i, verified := range result.replies {
			if verified.Entry == nil {
				continue
			}
			changes = append(changes, &EvsPlannedChange{TokenPath: result.paths[i].token, BaseEntryVersion: evsVerifiedNewestVersion(verified)})
		}
		if len(changes) == 0 {
			return &EvsConsumeResult{Version: head.Version}, nil
		}
		state, err := self.client.verifier.config()
		if err != nil {
			return nil, err
		}
		identity := self.client.args.Identity()
		pushId := NewEvsPushId()
		manifest, err := NewEvsManifestKey(repoKey)
		if err != nil {
			return nil, err
		}
		metadata, err := EvsSealMetadata(manifest, &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{}})
		if err != nil {
			return nil, err
		}
		built, err := NewEvsStatementBuilder(self.client.args.Sign).Build(&EvsPushPlan{
			RepoId: self.repoId, RefId: refId, RefKind: protocol.EvsRefKind_EVS_REF_DEPOSIT, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
			OwnerSidecarId: &ownerId, PushId: pushId, BaseVersion: head.Version, BaseChain: head.Chain,
			Generation: repoKey.Generation(), GroupId: repoKey.GroupId(), GenerationCommitment: repoKey.Commitment(), PathEpoch: 1,
			Auth: state.Pin(), SignerSidecarId: identity.SidecarId, ClientId: identity.ClientId, TimeMs: self.client.clock.Now().UnixMilli(),
			Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME), ConsumedThrough: args.ConsumedThrough,
			SealedMetadata: metadata, Changes: changes,
		})
		if err != nil {
			return nil, err
		}
		request := &protocol.EvsPushRequest{Statement: built.Statement.Bytes, Payload: built.Payload}
		var reply *protocol.EvsPushReply
		if 0 < len(built.Parts) {
			return nil, fmt.Errorf("%w: a CONSUME past one part", ErrEvsWriteInvalid)
		}
		reply, err = self.postPushAs(ctx, pushId, request, evsScopeWrite)
		switch {
		case err == nil:
			return &EvsConsumeResult{PushId: pushId, Version: reply.GetVersion()}, nil
		case rebuild < self.client.settings.PushRebuildCount && (evsNeedsRebuild(err) || evsCreationConflict(err)):
			// a deposit consumed meanwhile, or what a rebuild answers: read again and consume what stands
		default:
			return nil, err
		}
	}
}

// Whether an error is a deposit already gone, which an ingester takes as consumed.
func IsEvsDepositConsumed(err error) bool {
	return evsCreationConflict(err) || errors.Is(err, ErrEvsPathAbsent)
}
