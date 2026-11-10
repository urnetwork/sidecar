//go:build !ios_extension

// Ingest and CONSUME (§11.12's deposits rows; EVS1-M2-29): a reader with rw reads a depositor's ref in version order,
// each deposit opened by the drop private key of its slot key's generation, which every reader derives from RK_g, and
// commits a CONSUME deleting the entries it ingested and, at evs, their slots.
//
//	read     the deposit ref's verified statements, each deposit push's creations standing until a CONSUME removes
//	         them, walked from where this device's last read reached: its cursor, the version, chain and standing
//	         deposits it keeps per ref in the sealed store, from version 0 for a ref it never read or one whose head
//	         fell below it; each standing entry read by its id in epoch 1 (a deposit ref's entries take random ids in
//	         tokens' place and stay at epoch 1, evsEpochExempt), its slot taken from the entry's cleartext slot_ids,
//	         opened with the drop private key, K_dep derived from the object key, then the body reconstructed and
//	         checked against its sealed fields' oid and size, as any file's
//	consume  one CONSUME on the depositor's ref: a removal of each entry at its version, rw, path epoch 1, the
//	         consumer's generation pin from EnsureWritable, and consumed_through the caller's, the highest version at
//	         or below which its read left nothing unconsumed (EvsHead.consumed_through, never falling). A deposit
//	         already gone answers PATH_CONFLICT, which an ingester takes as consumed. One deposit's entries share a
//	         slot, so an ingester consumes a deposit's entries together
//
// A CONSUME whose answer was lost goes again under its push id, which evs answers with the commit it made. Its
// statement and payload are journaled in the sealed store before it is sent, so one cut short by a crash goes again
// unchanged, under the same push id, at the device's next ReadDeposits or Consume of that ref, and is forgotten once
// evs answers it. That evs's answer to a committed CONSUME's retry finishes its slot deletes is EVS1-M2-20's (its
// note: such a retry no longer reads the removed versions).
//
// On desktop and mobile legs. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

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

// Where an ingester keeps each deposit ref's cursor, and a CONSUME it sent and has not seen answered: one file a ref.
const (
	evsDepositCursorDirectory  = "deposits/cursor/"
	evsDepositConsumeDirectory = "deposits/consume/"
)

// What an ingester keeps of a deposit ref between reads: the version and chain its walk reached, and the deposits
// standing there, oldest first.
type evsDepositCursor struct {
	Version  uint64                `json:"version"`
	Chain    []byte                `json:"chain,omitempty"`
	Standing []*evsDepositStanding `json:"standing"`
}

// One deposit standing at a cursor.
type evsDepositStanding struct {
	EntryId         []byte `json:"entry_id"`
	Version         uint64 `json:"version"`
	PushId          []byte `json:"push_id"`
	SignerSidecarId []byte `json:"signer_sidecar_id"`
	TimeMs          int64  `json:"time_ms"`
	AuthPin         []byte `json:"auth_pin,omitempty"`
}

// A CONSUME sent and not yet answered: its push id and bytes, which a restart sends again unchanged.
type evsConsumeJournal struct {
	PushId    []byte `json:"push_id"`
	Statement []byte `json:"statement"`
	Payload   []byte `json:"payload"`
}

// A deposit ref's file in directory.
func (self *EvsRepo) depositFile(directory string, refId Id) string {
	return directory + self.repoId.String() + "/" + refId.String()
}

// Reads a JSON file of the sealed store into value; false when there is none.
func (self *EvsRepo) readStoreJson(name string, value any) (bool, error) {
	reader, err := self.client.args.Store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return false, fmt.Errorf("%w: %s does not parse", ErrSidecarStoreFailed, name)
	}
	return true, nil
}

// Writes value durably as a JSON file of the sealed store.
func (self *EvsRepo) writeStoreJson(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return self.writeStoreFile(name, data)
}

// The ref's cursor, an empty one for a ref this device never read.
func (self *EvsRepo) depositCursor(refId Id) (*evsDepositCursor, error) {
	cursor := &evsDepositCursor{}
	if _, err := self.readStoreJson(self.depositFile(evsDepositCursorDirectory, refId), cursor); err != nil {
		return nil, err
	}
	return cursor, nil
}

// Takes the walked statements after the cursor into its standing deposits: a deposit push's creations stand, and a
// CONSUME's removals, or any removal, end them.
func (self *evsDepositCursor) apply(walked []*EvsVerifiedStatement) error {
	for _, statement := range walked {
		push := statement.Statement.Push
		if 0 < push.GetChangeCount() {
			// a deposit push's list rides inline: one entry a deposit, far within 1 KiB
			return fmt.Errorf("%w: a deposit push with its changes under a root", ErrEvsFormatUnsupported)
		}
		consume := push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME) != 0
		for _, change := range statement.Statement.Changes {
			if len(change.TokenPath) != 1 {
				return fmt.Errorf("%w: a deposit ref's change of %d components", ErrEvsEntryRefused, len(change.TokenPath))
			}
			entryId := change.TokenPath[0].Bytes()
			self.Standing = slices.DeleteFunc(self.Standing, func(standing *evsDepositStanding) bool {
				return bytes.Equal(standing.EntryId, entryId)
			})
			if consume || !change.WritesEntry() {
				continue
			}
			authPin, err := proto.Marshal(push.GetAuth())
			if err != nil {
				return err
			}
			self.Standing = append(self.Standing, &evsDepositStanding{
				EntryId: entryId, Version: statement.Version, PushId: push.GetPushId(), SignerSidecarId: push.GetSignerSidecarId(),
				TimeMs: push.GetTimeMs(), AuthPin: authPin,
			})
		}
	}
	return nil
}

// The deposit a standing one names.
func (self *evsDepositStanding) deposit() (*EvsDeposit, error) {
	entryId, err := EvsTokenFromBytes(self.EntryId)
	if err != nil {
		return nil, fmt.Errorf("%w: a deposit cursor's entry", ErrSidecarStoreFailed)
	}
	pushId, _ := IdFromBytes(self.PushId)
	signerId, _ := IdFromBytes(self.SignerSidecarId)
	authPin := &bridge.AuthPin{}
	if err := proto.Unmarshal(self.AuthPin, authPin); err != nil {
		return nil, fmt.Errorf("%w: a deposit cursor's auth pin", ErrSidecarStoreFailed)
	}
	return &EvsDeposit{
		EntryId: entryId, Version: self.Version, PushId: pushId, SignerSidecarId: signerId, Time: evsTime(self.TimeMs), AuthPin: authPin,
	}, nil
}

// A deposit ref's standing deposits after afterVersion, oldest first, each opened and given to visit with its body,
// which visit reads before it returns. visit's error ends the read. A CONSUME of the ref this device sent and saw no
// answer to goes again first.
func (self *EvsRepo) ReadDeposits(ctx context.Context, depositorId Id, afterVersion uint64, visit func(deposit *EvsDeposit, body io.Reader) error) error {
	refId := EvsDepositRefId(self.repoId, depositorId)
	if err := self.resumeConsume(ctx, refId); err != nil {
		return err
	}
	head, err := self.readHeadAlone(ctx, refId, true)
	if err != nil {
		return err
	}
	cursor, err := self.depositCursor(refId)
	if err != nil {
		return err
	}
	if head.Version < cursor.Version {
		// a history below what this device read, as after a re-seed: read the ref again from its first version
		cursor = &evsDepositCursor{}
	}
	if cursor.Version < head.Version {
		chain := EvsChainStart(self.repoId, refId)
		if cursor.Version != 0 {
			if chain, err = EvsChainFromBytes(cursor.Chain); err != nil {
				return fmt.Errorf("%w: a deposit cursor's chain", ErrSidecarStoreFailed)
			}
		}
		walked, err := self.client.verifier.Walk(ctx, self.repoId, refId, cursor.Version, chain, head.Version)
		if err != nil {
			return err
		}
		if len(walked) == 0 || walked[len(walked)-1].Chain != head.Chain {
			return fmt.Errorf("%w: a deposit ref's walk that does not reach its head", ErrEvsChainBroken)
		}
		if err := cursor.apply(walked); err != nil {
			return err
		}
		cursor.Version, cursor.Chain = head.Version, head.Chain[:]
		if err := self.writeStoreJson(self.depositFile(evsDepositCursorDirectory, refId), cursor); err != nil {
			return err
		}
	}
	for _, standing := range slices.Clone(cursor.Standing) {
		if standing.Version <= afterVersion {
			continue
		}
		deposit, err := standing.deposit()
		if err != nil {
			return err
		}
		if err := self.openDeposit(ctx, refId, deposit, visit); err != nil {
			return err
		}
	}
	return nil
}

// Sends again the CONSUME of refId this device journaled and saw no answer to: the same push id and bytes, which evs
// answers as it answered or would have answered the first attempt. Forgotten once evs answers, whatever it says; kept
// while nothing answers.
func (self *EvsRepo) resumeConsume(ctx context.Context, refId Id) error {
	journal := &evsConsumeJournal{}
	name := self.depositFile(evsDepositConsumeDirectory, refId)
	found, err := self.readStoreJson(name, journal)
	if err != nil || !found {
		return err
	}
	pushId, err := IdFromBytes(journal.PushId)
	if err != nil {
		return fmt.Errorf("%w: a CONSUME journal's push id", ErrSidecarStoreFailed)
	}
	_, err = self.postPushAs(ctx, pushId, &protocol.EvsPushRequest{Statement: journal.Statement, Payload: journal.Payload}, evsScopeWrite)
	if !evsAnswered(err) {
		return err
	}
	return self.client.args.Store.Remove(name)
}

// Whether err is evs's answer to a push, a 200 or a refusal that ends the attempt, as opposed to nothing answering.
func evsAnswered(err error) bool {
	if err == nil {
		return true
	}
	evsError, refused := EvsErrorOf(err)
	return refused && !evsError.RefusesNothing() && !evsError.OutcomeUnknown
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

// Commits a CONSUME of args.EntryIds on the deposit ref args.DepositRefId: see the file header's consume row. Each
// entry is read first, by its id, for the version its removal names; one already gone is left out, and a CONSUME of
// none commits nothing.
func (self *EvsRepo) Consume(ctx context.Context, args *EvsConsumeArgs) (*EvsConsumeResult, error) {
	if args == nil || len(args.EntryIds) == 0 {
		return nil, fmt.Errorf("%w: a CONSUME of nothing", ErrEvsWriteInvalid)
	}
	refId := args.DepositRefId
	if err := self.resumeConsume(ctx, refId); err != nil {
		return nil, err
	}
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
		// journaled before it is sent, so a crash before evs answers sends it again unchanged
		journalName := self.depositFile(evsDepositConsumeDirectory, refId)
		if err := self.writeStoreJson(journalName, &evsConsumeJournal{PushId: pushId.Bytes(), Statement: request.Statement, Payload: request.Payload}); err != nil {
			return nil, err
		}
		reply, err = self.postPushAs(ctx, pushId, request, evsScopeWrite)
		if evsAnswered(err) {
			if removeErr := self.client.args.Store.Remove(journalName); removeErr != nil {
				return nil, removeErr
			}
		}
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
