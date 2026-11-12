// The seal form of POST /evs/v1/repos/<id>/push (§11.8's seal row; EVS1-M2-13): {Signed EvsPush, the parts' places}
// within 30 min of time_ms. Before step 4, one round reads the parts at their places and the head from the cluster,
// since a git-mode push's own lease left the cached ETag stale:
//
//	5a       on that head first, so a retry of a sealed push answers its version whatever became of its parts
//	missing  a place that holds no record, or a record that is not this push's part, answers 409 PARTS_MISSING,
//	         which records and refuses nothing: the client posts that part again and seals P again
//	parts    each part's record is checked to be this statement's, and the parts together to parts_sha256,
//	         changes_root and change_count, their slices joined into the one-part payload step 5 checks
//	         (sidecar.EvsCheckSeal); every part's receipts join the view's, for 5h's age check
//	5        b to f and h over the joined payload against that head (check.go's seal stage), then 5g again for
//	         every part against the same head (push.go's check): a changed path's newest version at the seal's head
//	         is its base, or a statement after the version the part was checked at changed it, which refuses the seal
//	         naming the paths; directory deltas merge but for §11.7's two-way check, and each directory's bound is
//	         checked over the parts' joined delta
//	6, 7     the seal record {statement, each part's place, changes_root and first token path} and the head If-Match,
//	         which clears the lease: a git seal fails 412 only on a write after its read, and commits only by TIP,
//	         so an expired lease is ignored and a stalled holder cannot commit over a newer tip
//
// A failed seal leaves its parts to evacuation, which finds them dead through their statement (resolve.go); nothing
// here deletes. A format-2 seal reads no part: only 5a and its FORMAT_UNSUPPORTED refusal run.

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
		if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART || record.PushId != self.pushId ||
			record.RepoId != self.repoId || record.RefId != self.refId {
			return self.partsMissing()
		}
		statementBytes, part, receiptItems, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
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
	if format2 {
		payload, checkedParts, err = sidecar.EvsCheckSealFormat2(self.statement, partBytes, partStaged)
		if err == nil {
			self.needsFormat2 = self.needsFormat2 || sidecar.EvsPushNeedsFormat2(self.statement, payload)
		}
	} else {
		payload, checkedParts, err = sidecar.EvsCheckSeal(self.statement, partBytes)
	}
	if err != nil {
		refusal := EvsCheckRefusalOfCodec(err)
		if refusal.Reason != EvsCheckReasonFormatUnsupported {
			return refusedOutcome(refusal.Reply(self.pushId))
		}
		self.formatRefusal = refusal
		self.seal.read = true
		self.seal.head = head
		return nil
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

// 409 PARTS_MISSING, which records and refuses nothing.
func (self *pushAttempt) partsMissing() *pushOutcome {
	return refusedOutcome(&protocol.EvsRefusalReply{PushId: self.pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING})
}
