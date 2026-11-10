// CLOSURE, CONSUME, BASE and deposits on evs (§11.12's rekey, deposits and retention rows, §11.8's refs table,
// §16.8; EVS1-M2-20), beside 5c's refs table (check_refs.go), which already holds a CLOSURE, BASE and ERASE to admin,
// a BASE and a CONSUME to removals, a deposit to its depositor's own creates-only ref, and FORCE and DELETE off
// record-class streams, deposit and erasure refs.
//
//	closure   a CLOSURE (flag 128, admin) commits only if every change replaces a committed file version, with no
//	          creation, removal or directory delta; its erased list names every slot the versions it replaces name;
//	          and each new chain's record lengths sum to at most Padmé of the replaced chain's, so a re-checkpoint
//	          that drops an entry passes when its merged record crosses a padding step; else 409 naming the paths,
//	          final. At the storage limit or while spent its inline records count against its eraser's own allowance
//	          (QuotaGate.ChargeClosureRecords), 429 past it, refusing nothing
//	consume   a CONSUME (rw) commits its removals, then deletes the slots the versions it removes name, before its
//	          200, as an ERASE rewrites them; a crash between leaves its retry, which finds it committed and deletes
//	          again. The head keeps the highest consumed_through any CONSUME carried, never falling
//	          (plan-RECORD-depositor-spool)
//	receipts  a reader of an owner-bound repo (vault, mailbox, secret) that does not write it deposits only read
//	          receipts: each entry at most 4 KiB padded, else 403 QUOTA_LIMIT naming evs_read_receipt_bytes, and 256 a
//	          UTC day per repo, counted once a push id through Quota.CountRate's evs_read_receipts, else 429 with
//	          retry_after_ms to the next 00:00 UTC (plan-EVS1-subscription-caps#3); evs sees only sealed bytes, so the
//	          owner's ingest enforces the receipt's kind
//	base      BASE is 5c's whole rule at M2 (plan-EVS1-v1-unspecified#6): removals only, each naming the path's newest
//	          version, which 5g holds, no new object, admin on an owned record-class stream; it commits with window
//	          bit 3
//
// A CONSUME deletes every slot its removed versions name: one deposit's entries may share a slot, so an ingester
// consumes a deposit's entries together, as §11.12's ingest-in-version-order does.

package evsservice

import (
	"errors"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.12's receipt bound: a read receipt's entry pads to at most 4 KiB.
const evsReadReceiptMaxByteCount = 4 * 1024

// §20.4's key a too-large receipt names (plan-EVS1-subscription-caps#3).
const evsReadReceiptBytesLimitKey = "evs_read_receipt_bytes"

// 5h's CLOSURE rules: see the file header.
func closureRules(view *PushView) *EvsCheckRefusal {
	erasedSlots := map[sidecar.Id]bool{}
	for _, erased := range view.Payload.Erased {
		erasedSlots[erased.SlotId] = true
	}
	var refusal *EvsCheckRefusal
	refuse := func(change *sidecar.EvsCheckedChange, detail string) {
		if refusal == nil {
			refusal = newEvsCheckRefusal(EvsCheckReasonClosureShape, detail)
		}
		refusal.Paths = append(refusal.Paths, change.TokenPath)
	}
	for _, change := range view.Payload.Changes {
		if change.Change.GetBaseEntryVersion() == 0 || !change.WritesEntry() {
			refuse(change, "a CLOSURE that creates or removes a path")
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
		}
		if protocol.EvsEntryKind(entry.GetKind()) != protocol.EvsEntryKind_EVS_ENTRY_FILE {
			refuse(change, "a CLOSURE that writes a directory")
			continue
		}
		read := view.Paths[change.TokenPath.KeyString()]
		replaced, err := replacedEntryVersion(read)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a replaced version that does not parse")
		}
		if replaced == nil || protocol.EvsEntryKind(replaced.GetKind()) != protocol.EvsEntryKind_EVS_ENTRY_FILE {
			refuse(change, "a CLOSURE that replaces no committed file version")
			continue
		}
		for _, slotId := range replaced.GetSlotIds() {
			if !erasedSlots[sidecar.Id(slotId)] {
				refuse(change, "a CLOSURE whose list omits a slot the replaced version names")
				break
			}
		}
		if sidecar.EvsPadme(evsChainRecordByteCount(replaced)) < evsChainRecordByteCount(entry) {
			refuse(change, "a CLOSURE chain past Padmé of the chain it replaces")
		}
	}
	return refusal
}

// The committed version step 4 found a change replacing: the newest's entry version, nil when the path stands not.
func replacedEntryVersion(read *PathRead) (*protocol.EvsEntryVersion, error) {
	if read == nil || read.Newest == nil || !read.Newest.Exists {
		return nil, nil
	}
	switch {
	case read.Newest.IndexVersion != nil:
		return parseEvsEntryVersion(read.Newest.IndexVersion.GetEntryVersion())
	case read.Newest.Change != nil:
		return parseEvsEntryVersion(read.Newest.Change.EntryVersion)
	}
	return nil, nil
}

// A chain's records' summed lengths: a segment locator's length, an inline record's bytes.
func evsChainRecordByteCount(entry *protocol.EvsEntryVersion) uint64 {
	byteCount := uint64(0)
	for _, locator := range entry.GetChain() {
		switch protocol.EvsLocatorKind(locator.GetKind()) {
		case protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
			byteCount += uint64(len(locator.GetInline()))
		default:
			byteCount += uint64(locator.GetLength())
		}
	}
	return byteCount
}

// The checks after step 5 that count against a quota, so do I/O: a CLOSURE's inline records against its eraser's
// allowance, and a receipt-only depositor's receipts. nil to go on.
func (self *pushAttempt) countedRules() *pushOutcome {
	push := self.statement.Push
	if self.payload == nil {
		return nil
	}
	switch {
	case push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) != 0:
		return self.chargeClosureRecords()
	case protocol.EvsRefKind(push.GetRefKind()) == protocol.EvsRefKind_EVS_REF_DEPOSIT &&
		push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME) == 0:
		return self.countReadReceipts()
	}
	return nil
}

// A CLOSURE's inline records at the storage limit or while spent: its eraser's own allowance.
func (self *pushAttempt) chargeClosureRecords() *pushOutcome {
	uploads := self.engine.deps.Uploads
	if uploads == nil || uploads.Quota == nil {
		return self.unavailable()
	}
	inline := int64(0)
	for _, change := range self.payload.Changes {
		if entry, err := parseEvsEntryVersion(change.EntryVersion); err == nil {
			for _, locator := range entry.GetChain() {
				if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
					inline += int64(len(locator.GetInline()))
				}
			}
		}
	}
	refusal, err := uploads.Quota.ChargeClosureRecords(self.ctx, connect.Id(self.networkId), connect.Id(self.request.SidecarId), inline, connect.Id(self.pushId))
	switch {
	case err != nil:
		return self.unavailable()
	case refusal != nil:
		reply := evsQuotaRefusalReply(refusal)
		reply.PushId = self.pushId.Bytes()
		return refusedOutcome(reply)
	}
	return nil
}

// Whether the push's signer reads the owner-bound repo and does not write it: a receipt-only depositor.
func (self *pushAttempt) receiptOnly() bool {
	switch self.reads.repo.Object.GetKind() {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
	default:
		return false
	}
	signer := self.request.SidecarId
	reads, writes := false, false
	for _, reader := range self.gateView.RepoReaders(self.repoId) {
		reads = reads || reader == signer
	}
	for _, writer := range self.gateView.RepoWriters(self.repoId) {
		writes = writes || writer == signer
	}
	return reads && !writes
}

// A receipt-only depositor's receipts: each at most 4 KiB, 256 a UTC day per repo.
func (self *pushAttempt) countReadReceipts() *pushOutcome {
	if !self.receiptOnly() {
		return nil
	}
	for _, change := range self.payload.Changes {
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return refusedOutcome(newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse").Reply(self.pushId))
		}
		if evsReadReceiptMaxByteCount < entry.GetPaddedSize() {
			reply := evsQuotaRefusalReply(&sidecar.QuotaRefusal{LimitKey: evsReadReceiptBytesLimitKey, Limit: evsReadReceiptMaxByteCount, Used: int64(entry.GetPaddedSize())})
			reply.PushId = self.pushId.Bytes()
			reply.Paths = []*protocol.EvsTokenPath{change.TokenPath.Proto()}
			return refusedOutcome(reply)
		}
	}
	if self.engine.host.Quota == nil {
		return self.unavailable()
	}
	refusal, err := self.engine.host.Quota.CountRate(self.ctx, connect.Id(self.networkId),
		map[string]int64{sidecar.QuotaRateKeyReadReceipt(connect.Id(self.repoId)): int64(len(self.payload.Changes))}, connect.Id(self.pushId))
	switch {
	case err != nil:
		return self.unavailable()
	case refusal != nil:
		reply := evsQuotaRefusalReply(refusal)
		reply.PushId = self.pushId.Bytes()
		return refusedOutcome(reply)
	}
	return nil
}

// After a CONSUME commits, or an attempt of it finds it committed: the slots the versions it removes name, deleted,
// P0 as an ERASE's rewrites are. A delete that does not answer answers 503 unknown, which the retry finishes.
func (self *pushAttempt) finishConsume() *pushOutcome {
	slotIds := map[sidecar.Id]bool{}
	for _, read := range self.reads.view.Paths {
		replaced, err := replacedEntryVersion(read)
		if err != nil || replaced == nil {
			continue
		}
		for _, slotId := range replaced.GetSlotIds() {
			slotIds[sidecar.Id(slotId)] = true
		}
	}
	for slotId := range slotIds {
		writeCtx := self.engine.budget.IssueP0(self.ctx, self.cluster.ClusterId(), sidecar.WriteP0KindErasure, self.engine.priceTable.DeleteByteCount)
		if err := self.cluster.Delete(writeCtx, SlotKey(self.repoId, slotId)); err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
			self.engine.log.Warningf("[evs] repo %s: a CONSUME's slot not deleted: %v", sidecar.EvsKeyId(self.repoId), err)
			return self.unknown()
		}
	}
	return nil
}

// The consumed_through a CONSUME's head carries over prior: the higher of the two, never past prior's version.
func consumedThroughOf(prior *protocol.EvsHead, push *protocol.EvsPush) uint64 {
	return max(prior.GetConsumedThrough(), min(push.GetConsumedThrough(), prior.GetVersion()))
}

