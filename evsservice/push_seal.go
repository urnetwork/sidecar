// The seal form of POST /evs/v1/repos/<id>/push (§11.8's seal row; EVS1-M2-13): {Signed EvsPush, the parts' places,
// the slot bodies} within 30 min of time_ms. Before step 4, one round reads the parts at their places and the head
// from the cluster, since a git-mode push's own lease left the cached ETag stale:
//
//	5a       on that head first, so a retry of a sealed push answers its version whatever became of its parts
//	missing  a place that holds no record, or a record that is not this push's part, answers 409 PARTS_MISSING,
//	         which records and refuses nothing: the client posts that part again and seals P again
//	parts    each part's record is checked to be this statement's, and the parts together to parts_sha256,
//	         changes_root and change_count, their slices joined into the one-part payload step 5 checks, the
//	         request's slot bodies its section 7 (sidecar.EvsCheckSeal); every part's receipts join the view's, for
//	         5h's age check
//	5        b to f and h over the joined payload against that head (check.go's seal stage), then 5g again for
//	         every part against the same head (push.go's check): a changed path's newest version at the seal's head
//	         is its base, or a statement after the version the part was checked at changed it, which refuses the seal
//	         naming the paths; directory deltas merge but for §11.7's two-way check, and each directory's bound is
//	         checked over the parts' joined delta
//	6, 7     the slots from the request's bodies, then the seal record {statement, each part's place, changes_root and
//	         first token path}, which keeps no body (push_commit.go's step 6), and the head If-Match, which clears the
//	         lease: a git seal fails 412 only on a write after its read, and commits only by TIP, so an expired lease
//	         is ignored and a stalled holder cannot commit over a newer tip
//
// The slot bodies (QD-819; question push-record-no-slot-bodies-part-slot-bodies). A push in parts carries its new
// slots' bodies, payload section 7, whole in its seal request, outside every hash, and in none of its parts, as a
// one-part push carries them in its payload (QD-806): the part route refuses a part holding one as INVALID, so no part
// record evs stores, evacuates, packs or serves, and no mirror's copy, holds a key an ERASE may destroy. The seal's
// checks hold the bodies to the statement's new slots, one each, within the format's SealSlotBodiesMaxByteCount, and
// refuse a seal whose bodies do not match as INVALID, as a one-part push's are refused. A retry of the seal carries
// them again: after a commit 5a answers its version, and before one, an attempt whose slots stand finds them its own
// and goes on (push_commit.go's slot round).
//
// A failed seal leaves its parts to evacuation, which finds them dead through their statement (resolve.go); nothing
// here deletes. A format-2 seal reads no part: only 5a and its FORMAT_UNSUPPORTED refusal run.
//
// A re-seeded push in parts (reseed.go; QD-818, QD-836) runs the same round over the places its seal call names, which
// its part calls answered: each an EVS_BATCH_RESEED record holding a part's body, the type the round takes in that
// mode alone, as the push route's takes EVS_BATCH_PART alone, so neither mode seals the other's parts. Its parts carry
// no slot body and its seal call none, since its slots come last by their own calls: the round checks it as its
// records keep it (sidecar.EvsCheckRecordSeal), format 1 alone, as a re-seeded one-part push's payload is checked.

package evsservice

import (
	"bytes"
	"errors"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A seal's parts: the places its request names and what their records gave, read once per attempt.
type sealReads struct {
	// In part order, one per part the statement counts.
	places []*protocol.EvsPlace
	// The request's slot bodies, the push's payload section 7 whole, which step 6 writes to their slots and no record
	// keeps (QD-819); nil for a push with no new slot and for a re-seed, whose slots come last.
	slotBodies []byte
	// Set once the parts have been read and checked.
	read bool
	// The cluster's head read in the parts' round, which step 4 takes once in place of its own read.
	head *EvsStoredHead
	// What the seal record names per part.
	parts []*sidecar.EvsSealPart
	// The seal record's body.
	body []byte
	// Format 2: each part's purge list from its record's tail, nil for none, in part order: what the seal's list is
	// made of (push_purge.go).
	partLists []*protocol.EvsPurgeList
	// A DROP's lists as its parts carry them, section 10's slices in part order, which 5h searches for each written
	// lineage's base (check_drop.go).
	dropListSlices [][]byte
}

// The parts' round, once per attempt: the head from the cluster and every part at its place together, then 5a on
// the head, PARTS_MISSING, and the seal's checks of the parts. A nil outcome leaves self.payload, self.receipts and
// self.seal filled for step 4.
func (self *pushAttempt) readSealParts() *pushOutcome {
	if self.seal.read {
		return nil
	}
	if self.formatRefusal != nil {
		// a format-2 seal: the parts are left unread, since only 5a and the format refusal run
		self.seal.read = true
		return nil
	}
	engine := self.engine
	format2 := engine.format2Instance()
	places := self.seal.places
	records := make([]*sidecar.EvsBatchRecord, len(places))
	tails := make([]*sidecar.EvsBatchRecordTail, len(places))
	readErrs := make([]error, len(places))
	var head *EvsStoredHead
	var headErr error
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		head, headErr = engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	}()
	for i, place := range places {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if !format2 {
				records[i], readErrs[i] = engine.readRecordAt(self.ctx, self.cluster, self.repoId, self.refId, place)
				return
			}
			// a format-2 part's record keeps its staged bytes and its replaced list in its tail
			recordBytes, err := engine.readRecordBytesAt(self.ctx, self.cluster, self.repoId, self.refId, place)
			if err != nil {
				readErrs[i] = err
				return
			}
			records[i], tails[i], readErrs[i] = sidecar.ParseEvsBatchRecordFormat2(recordBytes)
		}()
	}
	waitGroup.Wait()
	if headErr != nil {
		return self.unavailableOn(headErr)
	}
	if outcome := self.settle(head); outcome != nil {
		return outcome
	}
	partBytes := make([][]byte, len(places))
	partStaged := make([][]byte, len(places))
	partLists := make([]*protocol.EvsPurgeList, len(places))
	receipts := []*protocol.EvsUploadReceipt{}
	for i, record := range records {
		err := readErrs[i]
		switch {
		case errors.Is(err, ErrEvsRecordEvacuated), errors.Is(err, sidecar.ErrBlobNotFound), errors.Is(err, sidecar.ErrEvsPushInvalid):
			return self.partsMissing()
		case err != nil:
			return self.unavailableOn(err)
		}
		if record.Type != self.sealPartType() || record.PushId != self.pushId ||
			record.RepoId != self.repoId || record.RefId != self.refId {
			return self.partsMissing()
		}
		statementBytes, part, receiptItems, _, err := sidecar.ParseEvsSealPartRecord(record)
		if err != nil || !bytes.Equal(statementBytes, self.statement.Bytes) {
			return self.partsMissing()
		}
		for _, item := range receiptItems {
			decode := sidecar.DecodeEvsUploadReceipt
			if format2 {
				decode = sidecar.DecodeEvsUploadReceiptFormat2
			}
			receipt, err := decode(item)
			if err != nil {
				return refusedOutcome(EvsCheckRefusalOfCodec(err).Reply(self.pushId))
			}
			receipts = append(receipts, receipt)
		}
		partBytes[i] = part
		if tail := tails[i]; !tail.Empty() {
			partStaged[i] = tail.Staged
			list, err := tail.PurgeListValue()
			if err != nil || (list != nil && !list.GetReplaced()) {
				// a part's record lists its replaced versions whole, or nothing (DESIGN-DETAILS 10.2.6)
				return self.partsMissing()
			}
			partLists[i] = list
		}
	}
	var payload *sidecar.EvsCheckedPayload
	var checkedParts []*sidecar.EvsCheckedPart
	var err error
	switch {
	case self.reseed != nil:
		// a re-seeded push in parts: no part carries a slot body, nor its call, its slots coming last (QD-819); held to
		// format 1, as a re-seeded one-part push's payload is
		payload, checkedParts, err = sidecar.EvsCheckRecordSeal(self.statement, partBytes)
	case format2:
		payload, checkedParts, err = sidecar.EvsCheckSealFormat2(self.statement, partBytes, partStaged, self.seal.slotBodies)
		if err == nil {
			self.needsFormat2 = self.needsFormat2 || sidecar.EvsPushNeedsFormat2(self.statement, payload)
		}
	default:
		payload, checkedParts, err = sidecar.EvsCheckSeal(self.statement, partBytes, self.seal.slotBodies)
	}
	if err != nil {
		refusal := EvsCheckRefusalOfCodec(err)
		switch {
		case format2 && refusal.recordedCodec():
			// a DROP's lists or window, which the statement's own bytes settle: recorded after 5a (push.go's check)
			self.payloadRefusal = refusal
			self.needsFormat2 = true
			self.seal.read = true
			self.seal.head = head
			return nil
		case refusal.Reason != EvsCheckReasonFormatUnsupported:
			return refusedOutcome(refusal.Reply(self.pushId))
		}
		self.formatRefusal = refusal
		self.seal.read = true
		self.seal.head = head
		return nil
	}
	if format2 && payload.Drop != nil {
		// the lists' slices as the parts carry them, never joined (DESIGN-DETAILS 10.2.5)
		for _, part := range partBytes {
			sections, err := evsPartSections(part)
			if err != nil {
				return refusedOutcome(EvsCheckRefusalOfCodec(err).Reply(self.pushId))
			}
			self.seal.dropListSlices = append(self.seal.dropListSlices, sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS))
		}
	}
	parts := make([]*sidecar.EvsSealPart, len(checkedParts))
	for i, checkedPart := range checkedParts {
		if !checkedPart.HoldsChanges() {
			// a changeless part, which the record names by its place alone (DESIGN-DETAILS 8.2.2's parts row)
			parts[i] = &sidecar.EvsSealPart{Place: places[i], Changeless: true}
			continue
		}
		parts[i] = &sidecar.EvsSealPart{Place: places[i], ChangesRoot: checkedPart.Root, FirstTokenPath: checkedPart.FirstTokenPath()}
	}
	self.payload = payload
	self.receipts = receipts
	self.seal.parts = parts
	self.seal.body = sidecar.EvsSealRecordBody(self.statement.Bytes, parts)
	self.seal.partLists = partLists
	self.seal.head = head
	self.seal.read = true
	return nil
}

// The type of the records a seal's parts are: EVS_BATCH_PART records the part route wrote, or for a re-seeded push in
// parts EVS_BATCH_RESEED records holding a part's body (QD-818), so neither mode seals the other's parts.
func (self *pushAttempt) sealPartType() protocol.EvsBatchRecordType {
	if self.reseed != nil {
		return protocol.EvsBatchRecordType_EVS_BATCH_RESEED
	}
	return protocol.EvsBatchRecordType_EVS_BATCH_PART
}

// 409 PARTS_MISSING, which records and refuses nothing.
func (self *pushAttempt) partsMissing() *pushOutcome {
	return refusedOutcome(&protocol.EvsRefusalReply{PushId: self.pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING})
}
