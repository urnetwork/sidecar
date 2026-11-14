//go:build !ios_extension

// Sealing a plan and uploading its segments (§11.8's client steps 1 and 2, EVS1-M2-26): an EvsWritePlan's records
// sealed under the generation GkmClient.EnsureWritable returned, which precedes every seal so no writer seals to a
// generation a non-reader holds (§8.12), then each new segment PUT with ?push=P before the push is posted, at most
// UploadConcurrency at once (4; a phone's 2), the post waiting for every 200.
//
// A chain that rides inline is sealed into its locators: a checkpoint with its own key's block under fek_g, a diff
// under the chain's key, which its first record's block gives (plan-EVS1-format-bytes#2). Every other record goes
// into a segment, packed in plan order until the next would pass 8 MiB, each segment drawing its own object key and
// padding to Padmé, so a checkpoint draws a fresh key wherever it lands (§11.7). Segments are held in the sealed local
// store's spills, not in memory, until they upload (R-EVS-14); one upload's body is read into memory, at most 8 MiB.
//
// A record-class repo's plan is slot-keyed (evs_plan.go): its segments carry no key block, a new chain draws a fresh
// object key in a new slot/ object as it is sealed, its one key at index 0 wrapped under fek_g, which the push
// introduces, and a diff appended to a chain seals under that chain's slot key; each version names the slots its
// chain's records name. The slots are sealed bytes like any other: a retoken sends the same ones again, and a rebuild,
// which seals again, draws new ones (§11.6's object key row, DESIGN-DETAILS 9.2.5).
//
// A segment's receipt is evs's MAC over its id, size, time and uploader (§11.13), which the push carries back; its
// upload day is the statement's, so the statement is built after the uploads answer. A 429 or 503 is retried after
// its wait, at most PushRetryCount times, and so is no answer at all, the lb's 502 or 504 among them: a drain cuts a
// streamed segment PUT the lb cannot pass to another block, and the client sends the same bytes again (QD-758;
// §22.8's lb drain row). SEGMENT_STALE, and any other refusal, goes back to the push sender, whose rebuild seals
// afresh.
//
// On every leg. An EvsSealedWrite is not safe for concurrent use but by its own uploads.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A plan sealed under one generation's keys: each path's sealed fields and chain, and the segments to upload.
type EvsSealedWrite struct {
	Plan *EvsWritePlan
	// The generation it seals to.
	RepoKey  *EvsRepoKey
	Paths    []*EvsSealedPath
	Segments []*EvsSealedSegment
	// A slot-keyed plan's new slot/ objects, in the order the push introduces them.
	Slots []*EvsSealedSlot
	// the token scope its uploads take: rw, or a deposit's deposit (evs_deposit.go)
	scope string
}

// One path sealed.
type EvsSealedPath struct {
	Planned      *EvsPlannedPath
	SealedFields []byte
	Chain        []*protocol.EvsLocator
	PaddedSize   uint64
	// The slots the chain's records name, in chain order, each once: a slot-keyed repo's.
	SlotIds []Id
}

// A slot/ object a push introduces: its id and its EvsSlotObject bytes.
type EvsSealedSlot struct {
	Id   Id
	Body []byte
}

// One segment to upload: its id, padded size and bytes, and its receipt once evs answered.
type EvsSealedSegment struct {
	Id         [32]byte
	PaddedSize uint64
	content    *evsSpill
	Receipt    *protocol.EvsUploadReceipt
}

// Drops the segments' spills.
func (self *EvsSealedWrite) Close() {
	for _, segment := range self.Segments {
		if segment.content != nil {
			segment.content.close()
		}
	}
}

// Where a record went in a segment being built: the segment's index and the record's within it.
type evsSegmentPlace struct {
	locator *protocol.EvsLocator
	segment int
	record  int
}

// Seals plan's records under repoKey's generation, which must be the plan's.
func (self *EvsClient) sealWrite(ctx context.Context, plan *EvsWritePlan, repoKey *EvsRepoKey) (*EvsSealedWrite, error) {
	if repoKey.Generation() != plan.Generation || repoKey.RepoId() != plan.RepoId {
		return nil, fmt.Errorf("%w: a plan of another generation or repo", ErrEvsWriteInvalid)
	}
	manifest, err := NewEvsManifestKey(repoKey)
	if err != nil {
		return nil, err
	}
	fek, err := NewEvsFekKey(repoKey)
	if err != nil {
		return nil, err
	}
	sealed := &EvsSealedWrite{Plan: plan, RepoKey: repoKey}
	// a slot-keyed chain's key: a new slot's, drawn here, which the push introduces
	newChainKey := func() (*evsChainKey, error) {
		objectKey := NewEvsObjectKey()
		wrapped, err := EvsWrapObjectKey(fek, objectKey)
		if err != nil {
			return nil, err
		}
		chainKey := &evsChainKey{slotId: NewEvsSlotId(), keyIndex: 0, generation: repoKey.Generation(), objectKey: objectKey}
		body, err := EvsEncodeSlotObject(&protocol.EvsSlotObject{Keys: []*protocol.EvsSlotKey{{KeyIndex: 0, Generation: chainKey.generation, Wrapped: wrapped}}})
		if err != nil {
			return nil, err
		}
		sealed.Slots = append(sealed.Slots, &EvsSealedSlot{Id: chainKey.slotId, Body: body})
		return chainKey, nil
	}
	keep := false
	defer func() {
		if !keep {
			sealed.Close()
		}
	}()
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
		segment.Id = summary.Id
		segment.PaddedSize = summary.PaddedSize
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
	for _, planned := range plan.Paths {
		if planned.Kind != protocol.EvsEntryKind_EVS_ENTRY_FILE || planned.Remove {
			sealed.Paths = append(sealed.Paths, &EvsSealedPath{Planned: planned})
			continue
		}
		sealedFields, err := EvsSealFields(manifest, planned.Fields)
		if err != nil {
			return nil, err
		}
		fileId, err := IdFromBytes(planned.Fields.GetFileId())
		if err != nil {
			return nil, err
		}
		path := &EvsSealedPath{Planned: planned, SealedFields: sealedFields, PaddedSize: EvsPadme(planned.Fields.GetSize())}
		if plan.slotKeyed && planned.Inline {
			return nil, fmt.Errorf("%w: an inline chain in a slot-keyed repo", ErrEvsWriteInvalid)
		}
		// the chain's slot key, which its new records seal under: the previous chain's for a diff, else a new slot's
		chainKey := planned.chainKey
		keptSlots := planned.keptSlotIds
		nameSlot := func(slotId Id) {
			if !slices.Contains(path.SlotIds, slotId) {
				path.SlotIds = append(path.SlotIds, slotId)
			}
		}
		var inlineKey *EvsObjectKey
		for index, link := range planned.Chain {
			if link.Kept != nil {
				path.Chain = append(path.Chain, link.Kept)
				if plan.slotKeyed {
					if len(keptSlots) == 0 {
						return nil, fmt.Errorf("%w: a kept locator under no slot", ErrEvsWriteInvalid)
					}
					nameSlot(keptSlots[0])
					keptSlots = keptSlots[1:]
				}
				continue
			}
			record := link.Record
			body, err := io.ReadAll(io.NewSectionReader(record.Body, 0, record.Body.Size()))
			if err != nil {
				return nil, err
			}
			header := &EvsRecordHeader{
				RecordId: record.RecordId, BaseRecordId: record.BaseRecordId, Generation: repoKey.Generation(),
				BodyLength: uint64(len(body)), Kind: record.Kind, KeyRefKind: protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER,
				OidKind: protocol.EvsOidKind_EVS_OID_SHA1,
			}
			copy(header.Oid[:], record.Oid[:])
			if planned.Inline {
				var fekKey *EvsFekKey
				if index == 0 {
					fekKey = fek
				} else if inlineKey == nil {
					// the chain's key, from its first record's block
					_, _, chainKey, err := EvsOpenInlineRecord(manifest, fek, nil, fileId, path.Chain[0].GetInline())
					if err != nil {
						return nil, fmt.Errorf("evs: the inline chain's key: %w", err)
					}
					inlineKey = chainKey
				}
				inline, chainKey, err := EvsSealInlineRecord(manifest, fekKey, inlineKey, fileId, header, body)
				if err != nil {
					return nil, err
				}
				inlineKey = chainKey
				path.Chain = append(path.Chain, &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: inline})
				continue
			}
			recordLength := EvsRecordByteCount(uint64(len(body)))
			if builder != nil && EvsSegmentMaxByteCount < builderLength+recordLength {
				if err := finish(); err != nil {
					return nil, err
				}
			}
			if builder == nil {
				spill := newEvsSpill(self.args.Store, self.settings.DeltaBaseMemoryByteCount)
				sealed.Segments = append(sealed.Segments, &EvsSealedSegment{content: spill})
				if plan.slotKeyed {
					builder, err = NewEvsSlotKeyedSegmentBuilder(spill, manifest)
					builderLength = EvsSegmentHeaderByteCount
				} else {
					builder, err = NewEvsSegmentBuilder(spill, manifest, fek)
					builderLength = evsSegmentKeyedRecordsOffset
				}
				if err != nil {
					return nil, err
				}
				recordCount = 0
			}
			var writer io.WriteCloser
			if plan.slotKeyed {
				if chainKey == nil {
					if chainKey, err = newChainKey(); err != nil {
						return nil, err
					}
				}
				header.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT
				header.SlotId, header.KeyIndex, header.Generation = chainKey.slotId, chainKey.keyIndex, chainKey.generation
				nameSlot(chainKey.slotId)
				writer, err = builder.BeginSlotRecord(manifest, chainKey.objectKey, fileId, header)
			} else {
				writer, err = builder.BeginRecord(fileId, header)
			}
			if err != nil {
				return nil, err
			}
			if _, err := writer.Write(body); err != nil {
				return nil, err
			}
			if err := writer.Close(); err != nil {
				return nil, err
			}
			builderLength += recordLength
			locator := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT)}
			places = append(places, &evsSegmentPlace{locator: locator, segment: len(sealed.Segments) - 1, record: recordCount})
			recordCount += 1
			path.Chain = append(path.Chain, locator)
		}
		sealed.Paths = append(sealed.Paths, path)
	}
	if err := finish(); err != nil {
		return nil, err
	}
	keep = true
	return sealed, nil
}

// Uploads every segment not yet holding a receipt, at most UploadConcurrency at once, each with ?push=pushId. The
// first refusal ends the rest and is answered.
func (self *EvsRepo) uploadSegments(ctx context.Context, sealed *EvsSealedWrite, pushId Id) error {
	pending := []*EvsSealedSegment{}
	for _, segment := range sealed.Segments {
		if segment.Receipt == nil {
			pending = append(pending, segment)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	uploadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	work := make(chan *EvsSealedSegment)
	errs := make(chan error, len(pending))
	wait := sync.WaitGroup{}
	for range max(1, min(self.client.settings.UploadConcurrency, len(pending))) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for segment := range work {
				if err := self.uploadSegment(uploadCtx, segment, pushId, sealed.scope); err != nil {
					errs <- err
					cancel()
				}
			}
		}()
	}
	func() {
		defer close(work)
		for _, segment := range pending {
			select {
			case work <- segment:
			case <-uploadCtx.Done():
				return
			}
		}
	}()
	wait.Wait()
	close(errs)
	for err := range errs {
		return err
	}
	return ctx.Err()
}

// One segment's PUT under scope (rw when empty), retried with its same bytes after a 429 or 503 that refuses nothing
// or no answer at all, the lb's 502 or 504 among them (retryRefusingNothing), and its receipt held to the segment.
func (self *EvsRepo) uploadSegment(ctx context.Context, segment *EvsSealedSegment, pushId Id, scope string) error {
	if scope == "" {
		scope = evsScopeWrite
	}
	body, err := io.ReadAll(segment.content.reader())
	if err != nil {
		return err
	}
	call := &evsCall{
		route:   "PUT /evs/v1/repos/{repo_id}/segments/{segment_id}",
		method:  http.MethodPut,
		path:    "/evs/v1/repos/" + evsUrlId(self.repoId) + "/segments/" + hex.EncodeToString(segment.Id[:]) + "?push=" + evsUrlId(pushId),
		repoId:  self.repoId,
		role:    scope,
		rawBody: body,
	}
	receipt := &protocol.EvsUploadReceipt{}
	if err := self.client.retryRefusingNothing(ctx, func() error { return self.client.http.callMessage(ctx, call, receipt) }); err != nil {
		return err
	}
	receiptBytes, err := proto.Marshal(receipt)
	if err != nil {
		return err
	}
	if _, err := DecodeEvsUploadReceipt(receiptBytes); err != nil {
		return fmt.Errorf("%w: %w", ErrEvsReplyInvalid, err)
	}
	if string(receipt.GetSegmentId()) != string(segment.Id[:]) || receipt.GetPaddedSize() != segment.PaddedSize ||
		string(receipt.GetRepoId()) != string(self.repoId[:]) {
		return fmt.Errorf("%w: a receipt for another segment", ErrEvsReplyInvalid)
	}
	segment.Receipt = receipt
	return nil
}

// Runs call, one attempt at a time with the same bytes, until it answers anything but a 429, a 503 or no answer at
// all, each one's retry_after waited (the read wait when it names none), at most PushRetryCount times: §11.8's retry
// id row, where a 503 whose outcome is unknown is resolved by the same request again. The lb's 502 or 504 is no
// answer at all (evsErrorOfAnswer, QD-758).
func (self *EvsClient) retryRefusingNothing(ctx context.Context, call func() error) error {
	var err error
	for attempt := 0; attempt <= self.settings.PushRetryCount; attempt += 1 {
		err = call()
		if err == nil || ctx.Err() != nil || errors.Is(err, ErrEvsUnauthorized) || errors.Is(err, ErrEvsReplyInvalid) {
			return err
		}
		wait := self.settings.ReadRetryWait
		if evsError, ok := EvsErrorOf(err); ok {
			if !evsError.RefusesNothing() && !evsError.OutcomeUnknown {
				return err
			}
			if 0 < evsError.RetryAfter {
				wait = evsError.RetryAfter
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.clock.After(min(wait, self.settings.PushRetryMaxWait)):
		}
	}
	return err
}

// The day since the Unix epoch a receipt's upload falls on, as a new-objects item carries it.
func evsUploadDay(receipt *protocol.EvsUploadReceipt) uint32 {
	return uint32(receipt.GetUploadMs() / (24 * time.Hour).Milliseconds())
}
