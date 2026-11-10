//go:build !ios_extension

// Deposits (§11.12's deposits rows; D-EVS-10; plan-EVS1-deposit-head; FS-23; EVS1-M2-29): a depositor appends sealed
// entries to its own deposit ref, which only readers of the repo open, and a reader with rw ingests them in version
// order and commits a CONSUME deleting them and their slots (evs_consume.go).
//
//	drop key  GkmClient.DropKey gives the newest generation's drop key under §10.5's depositor rule: its GenRotate
//	          verifies, it covers holders_shrunk_at and every holder expiry the depositor knows, now is before its
//	          drop_not_after_ms, and it is not below the depositor's pin for the repo, which it raises; else ErrGkmWait,
//	          and the depositor waits for a newer rotation. A depositor holds no path, manifest or fek key
//	seal      one random object key per deposit, which a slot the deposit push introduces holds HPKE-XWing to the drop
//	          key (EvsWrapDepositKey); K_dep from it seals the record headers, the entry's sealed fields and the push's
//	          metadata in manifest's place (EVS-FORMAT.md's deposits); the body goes under the object key, one
//	          checkpoint record, or 4 MiB chunk records past 8 MiB, in slot-keyed segments of at most 8 MiB, so a
//	          50 MiB message reaches evs in segments under the lb's bound. Slot ids are random, drawn per sealing,
//	          never derived from a deposit, message or entry id, and a deposit sealed again for a newer drop key or a
//	          new base draws new ones, its segments sealed again since every record header names its slot
//	entry    one change creating a random 16 B id in the ref's epoch 1, the deposit id, which is the message id: a file
//	          of the body's padded size with the slot in its cleartext slot_ids
//	push      on the depositor's own deposit ref (EvsDepositRefId), file mode, path epoch 1 for life, at the drop key's
//	          generation pin, uploads and push under the token's deposit scope. Its base is the newest EvsDepositHead
//	          this device keeps of the ref, from each 200 and each BASE_STALE, or version 0 and C_0 for a first deposit,
//	          which a restart with no state reaches through BASE_STALE. A depositor learns nothing else of the head
//
// Deposit refs stay at epoch 1 and take no floors, lookups or retoken (evsEpochExempt); the only waits are a
// deposit's own, ErrGkmWait and BASE_STALE's rebuild. Every read route refuses a deposit-only principal (FS-23), so a
// depositor never reads.
//
// On desktop and mobile legs. Safe for concurrent use, one deposit at a time per ref.

package sidecar

import (
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Where a depositor keeps its deposit heads, one file a repo.
const evsDepositHeadDirectory = "deposits/"

// The deposit head a depositor keeps of its own deposit ref, stored form.
type evsDepositHeadRecord struct {
	RefId           string `json:"ref_id"`
	Version         uint64 `json:"version"`
	Chain           string `json:"chain"`
	ConsumedThrough uint64 `json:"consumed_through,omitempty"`
}

// What a deposit push built: its statement and payload, and the segments it uploads.
type evsDepositPush struct {
	pushId   Id
	built    *EvsBuiltPush
	sealed   *EvsSealedWrite
	receipts []*protocol.EvsUploadReceipt
	version  uint64
}

// The newest deposit head this device keeps of refId, {0, C_0} when none.
func (self *EvsRepo) depositHead(refId Id) (*protocol.EvsDepositHead, error) {
	chain := EvsChainStart(self.repoId, refId)
	head := &protocol.EvsDepositHead{Chain: chain[:]}
	reader, err := self.client.args.Store.Open(evsDepositHeadDirectory + self.repoId.String())
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return head, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	records := []*evsDepositHeadRecord{}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("%w: evs deposit heads do not parse", ErrSidecarStoreFailed)
	}
	for _, record := range records {
		if record.RefId != refId.String() {
			continue
		}
		chainBytes, err := hex.DecodeString(record.Chain)
		if err != nil || len(chainBytes) != sha256.Size {
			return nil, fmt.Errorf("%w: an evs deposit head's chain", ErrSidecarStoreFailed)
		}
		return &protocol.EvsDepositHead{Version: record.Version, Chain: chainBytes, ConsumedThrough: record.ConsumedThrough}, nil
	}
	return head, nil
}

// Keeps head as refId's newest, unless the one kept is newer; durably, before the deposit it answers is shown.
func (self *EvsRepo) keepDepositHead(refId Id, head *protocol.EvsDepositHead) error {
	if head == nil || len(head.GetChain()) != sha256.Size {
		return fmt.Errorf("%w: a deposit head of no chain", ErrEvsReplyInvalid)
	}
	held, err := self.depositHead(refId)
	if err != nil {
		return err
	}
	if head.GetVersion() < held.GetVersion() {
		return nil
	}
	writer, err := self.client.args.Store.Create(evsDepositHeadDirectory + self.repoId.String())
	if err != nil {
		return err
	}
	defer writer.Close()
	data, err := json.Marshal([]*evsDepositHeadRecord{{
		RefId: refId.String(), Version: head.GetVersion(), Chain: hex.EncodeToString(head.GetChain()), ConsumedThrough: head.GetConsumedThrough(),
	}})
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Deposits one entry, args.Body of args.Size bytes, to this sidecar's deposit ref of the repo: see the file header.
// The result names the entry's random id, the deposit and message id, and the version it committed at.
func (self *EvsRepo) Deposit(ctx context.Context, args *EvsDepositArgs) (*EvsDepositResult, error) {
	if args == nil || args.Body == nil || args.Size < 0 || EvsFileMaxByteCount < args.Size {
		return nil, fmt.Errorf("%w: a deposit of no body or past 2 GiB", ErrEvsWriteInvalid)
	}
	body := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
	defer body.close()
	copied, err := io.Copy(body, io.LimitReader(args.Body, args.Size+1))
	if err != nil {
		return nil, err
	}
	if copied != args.Size {
		return nil, fmt.Errorf("%w: a body of %d bytes, not %d", ErrEvsWriteInvalid, copied, args.Size)
	}
	oid, err := EvsGitBlobOid(body.reader(), body.Size())
	if err != nil {
		return nil, err
	}
	identity := self.client.args.Identity()
	refId := EvsDepositRefId(self.repoId, identity.SidecarId)
	entryId := NewEvsRandomToken()
	for rebuild := 0; ; rebuild += 1 {
		dropKey, err := self.client.args.Gkm.DropKey(ctx, self.repoId)
		if err != nil {
			return nil, err
		}
		if !self.client.clock.Now().Before(dropKey.NotAfter) {
			return nil, fmt.Errorf("%w: the drop key lapsed", ErrGkmWait)
		}
		head, err := self.depositHead(refId)
		if err != nil {
			return nil, err
		}
		push, err := self.sealDeposit(ctx, dropKey, refId, entryId, body, oid, head)
		if err != nil {
			return nil, err
		}
		reply, err := self.sendDeposit(ctx, push)
		push.sealed.Close()
		switch {
		case err == nil:
			if err := self.keepDepositHead(refId, reply.GetDepositHead()); err != nil {
				return nil, err
			}
			return &EvsDepositResult{EntryId: entryId, Version: reply.GetVersion()}, nil
		case rebuild < self.client.settings.PushRebuildCount && IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE):
			// the head this device kept is behind: the refusal carries the ref's, on which it seals again
			evsError, _ := EvsErrorOf(err)
			if evsError.DepositHead == nil {
				return nil, err
			}
			if err := self.keepDepositHead(refId, evsError.DepositHead); err != nil {
				return nil, err
			}
		case rebuild < self.client.settings.PushRebuildCount && (evsNeedsRebuild(err) || IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)):
			// a newer drop key, or what a rebuild answers: sealed again, new slot ids
		default:
			return nil, err
		}
	}
}

// Seals one deposit on head: a fresh object key and slot, the body's records in slot-keyed segments, the entry and
// the push's metadata under K_dep (see the file header).
func (self *EvsRepo) sealDeposit(ctx context.Context, dropKey *GkmDropKey, refId Id, entryId EvsToken, body *evsSpill, oid EvsGitOid, head *protocol.EvsDepositHead) (*evsDepositPush, error) {
	generation := dropKey.Generation
	publicKey, err := hpke.MLKEM768X25519().NewPublicKey(dropKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: the drop key does not parse", ErrGkmMalformed)
	}
	objectKey := NewEvsObjectKey()
	depositKey, err := NewEvsDepositManifestKey(self.repoId, generation, objectKey)
	if err != nil {
		return nil, err
	}
	slotId := NewEvsSlotId()
	wrapped, err := EvsWrapDepositKey(publicKey, self.repoId, generation, objectKey)
	if err != nil {
		return nil, err
	}
	slotBytes, err := EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: generation, Wrapped: wrapped}}})
	if err != nil {
		return nil, err
	}
	fileId := NewEvsSlotId()
	size := uint64(body.Size())
	sealed := &EvsSealedWrite{scope: evsScopeDeposit}
	keep := false
	defer func() {
		if !keep {
			sealed.Close()
		}
	}()
	// one checkpoint, or 4 MiB chunks past 8 MiB
	kind := protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT
	pieces := []*EvsChunkPlan{{Offset: 0, Length: int64(size)}}
	if EvsChunked(size) {
		kind = protocol.EvsRecordKind_EVS_RECORD_CHUNK
		pieces = evsChunkBounds(int64(size))
	}
	var builder *EvsSegmentBuilder
	var builderLength uint64
	places := []*evsSegmentPlace{}
	recordCount := 0
	finish := func() error {
		if builder == nil {
			return nil
		}
		summary, err := builder.Finish()
		if err != nil {
			return err
		}
		segmentIndex := len(sealed.Segments) - 1
		segment := sealed.Segments[segmentIndex]
		segment.Id, segment.PaddedSize = summary.Id, summary.PaddedSize
		for _, place := range places {
			if place.segment == segmentIndex {
				place.locator.Id = summary.Id[:]
				place.locator.Offset = summary.Places[place.record].Offset
				place.locator.Length = summary.Places[place.record].Length
			}
		}
		builder = nil
		return nil
	}
	chain := []*protocol.EvsLocator{}
	for _, piece := range pieces {
		recordLength := EvsRecordByteCount(uint64(piece.Length))
		if builder != nil && EvsSegmentMaxByteCount < builderLength+recordLength {
			if err := finish(); err != nil {
				return nil, err
			}
		}
		if builder == nil {
			spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
			sealed.Segments = append(sealed.Segments, &EvsSealedSegment{content: spill})
			if builder, err = NewEvsSlotKeyedSegmentBuilder(spill, depositKey); err != nil {
				return nil, err
			}
			builderLength = EvsSegmentHeaderByteCount
			recordCount = 0
		}
		header := &EvsRecordHeader{
			RecordId: NewEvsSlotId(), Generation: generation, BodyLength: uint64(piece.Length), Kind: kind,
			KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT, SlotId: slotId, KeyIndex: 0, OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
		}
		copy(header.Oid[:], oid[:])
		writer, err := builder.BeginSlotRecord(depositKey, objectKey, fileId, header)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(writer, io.NewSectionReader(body, piece.Offset, piece.Length)); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		builderLength += recordLength
		locator := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT)}
		places = append(places, &evsSegmentPlace{locator: locator, segment: len(sealed.Segments) - 1, record: recordCount})
		recordCount += 1
		chain = append(chain, locator)
	}
	if err := finish(); err != nil {
		return nil, err
	}
	sealedFields, err := EvsSealFields(depositKey, &protocol.EvsSealedFields{
		FileId: fileId.Bytes(), Mode: EvsGitModeFile, GitOid: oid[:], OidKind: protocol.EvsOidKind_EVS_OID_SHA1, Size: size,
	})
	if err != nil {
		return nil, err
	}
	sealedMetadata, err := EvsSealMetadata(depositKey, &protocol.EvsSealedMetadata{Provenance: &protocol.EvsProvenance{}})
	if err != nil {
		return nil, err
	}
	pushId := NewEvsPushId()
	if err := self.uploadSegments(ctx, sealed, pushId); err != nil {
		return nil, err
	}
	state, err := self.client.verifier.config()
	if err != nil {
		return nil, err
	}
	identity := self.client.args.Identity()
	timeMs := self.client.clock.Now().UnixMilli()
	baseChain, err := EvsChainFromBytes(head.GetChain())
	if err != nil {
		return nil, fmt.Errorf("%w: the deposit head's chain", ErrEvsReplyInvalid)
	}
	entry := &protocol.EvsEntryVersion{
		Version: head.GetVersion() + 1, PushId: pushId.Bytes(), BaseVersion: head.GetVersion(), TimeMs: timeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: EvsPadme(size), SealedFields: sealedFields,
		Chain: chain, SlotIds: [][]byte{slotId.Bytes()},
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		return nil, err
	}
	ownerId := identity.SidecarId
	pushPlan := &EvsPushPlan{
		RepoId: self.repoId, RefId: refId, RefKind: protocol.EvsRefKind_EVS_REF_DEPOSIT, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		OwnerSidecarId: &ownerId, PushId: pushId, BaseVersion: head.GetVersion(), BaseChain: baseChain,
		Generation: generation, GroupId: dropKey.GroupId, GenerationCommitment: dropKey.Commitment, PathEpoch: 1,
		Auth: state.Pin(), SignerSidecarId: identity.SidecarId, ClientId: identity.ClientId, TimeMs: timeMs,
		SealedMetadata: sealedMetadata, SlotBodies: [][]byte{slotBytes},
		Changes: []*EvsPlannedChange{{TokenPath: EvsTokenPath{entryId}, EntryVersion: entryBytes}},
	}
	push := &evsDepositPush{pushId: pushId, sealed: sealed}
	for _, segment := range sealed.Segments {
		pushPlan.NewObjects = append(pushPlan.NewObjects, &EvsNewObject{
			Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segment.Id[:], PaddedSize: segment.PaddedSize, UploadDay: evsUploadDay(segment.Receipt),
		})
		push.receipts = append(push.receipts, segment.Receipt)
	}
	pushPlan.NewObjects = append(pushPlan.NewObjects, &EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()})
	if push.built, err = NewEvsStatementBuilder(self.client.args.Sign).Build(pushPlan); err != nil {
		return nil, err
	}
	if 0 < len(push.built.Parts) {
		return nil, fmt.Errorf("%w: a deposit past one part", ErrEvsWriteInvalid)
	}
	keep = true
	return push, nil
}

// Posts a deposit push under the deposit scope, retried with the same bytes until evs answers it.
func (self *EvsRepo) sendDeposit(ctx context.Context, push *evsDepositPush) (*protocol.EvsPushReply, error) {
	request := &protocol.EvsPushRequest{Statement: push.built.Statement.Bytes, Payload: push.built.Payload, Receipts: push.receipts}
	return self.postPushAs(ctx, push.pushId, request, evsScopeDeposit)
}
