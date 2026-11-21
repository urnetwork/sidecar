// A direct writer reconciles its verified stream before it gives a new capture a sequence. Its capture entry point
// never waits for the network. Until startup finishes, drafts stay in capture order in the local spool.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
)

// The log's direct writer has yet to reconcile its stream in this binding.
var errRecordHeadPending = errors.New("record writer awaits verified stream head")

// Opens the record and reconciles its writable streams, for hosts that need immediate signed references. An offline
// host can construct the record with NewSidecarRecord and let Run prepare it while captures accumulate in its spool.
func OpenSidecarRecord(ctx context.Context, args *SidecarRecordArgs) (*SidecarRecord, error) {
	record, err := NewSidecarRecord(args)
	if err != nil {
		return nil, err
	}
	if err := record.PrepareDirectWrites(ctx); err != nil {
		return nil, err
	}
	return record, nil
}

// Replays pending direct writes and reconciles verified heads before fresh signatures. A depositor reads no log.
func (self *SidecarRecord) PrepareDirectWrites(ctx context.Context) error {
	writer := self.writer
	auth := writer.auth()
	logIds := []Id{}
	if vault, err := recordVaultRoute(auth, writer.sidecarId); err == nil && !vault.deposit {
		logIds = append(logIds, vault.logId)
	}
	if logs := auth.Logs(); logs != nil {
		for _, id := range []*Id{logs.TeamRecordId, logs.DirectoryId} {
			if id != nil {
				logIds = append(logIds, *id)
			}
		}
		logIds = append(logIds, logs.LedgerIds...)
	}
	func() {
		writer.stateLock.Lock()
		defer writer.stateLock.Unlock()
		for id, ready := range writer.adoptedLogs {
			if !ready {
				logIds = append(logIds, id)
			}
		}
	}()
	slices.SortFunc(logIds, Id.Cmp)
	var errs []error
	for _, logId := range slices.Compact(logIds) {
		if err := writer.prepareLog(ctx, logId); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Prepares one log while serialized with its push loop. Only a sidecar with a direct write right may read the stream.
func (self *recordWriter) prepareLog(ctx context.Context, logId Id) error {
	if deposit, ok := recordLogMode(self.auth(), self.sidecarId, logId); deposit || !ok {
		return nil
	}
	self.pumpLock.Lock()
	defer self.pumpLock.Unlock()
	if deposit, ok := recordLogMode(self.auth(), self.sidecarId, logId); deposit || !ok {
		return nil
	}
	if err := self.load(); err != nil {
		return err
	}
	return self.adopt(ctx, logId)
}

// Refuses a fresh seal until every direct destination has passed startup. The caller holds sealLock, so a rebind
// cannot reset the heads between this check and signing.
func (self *recordWriter) readyToSeal(routes *recordRoutes) error {
	all := []*recordRoute{routes.vault, routes.team, routes.directory}
	all = append(all, routes.ledgers...)
	auth := self.auth()
	for _, route := range all {
		if route == nil {
			continue
		}
		if route.deposit {
			if deposit, ok := recordLogMode(auth, self.sidecarId, route.logId); deposit || !ok {
				continue
			}
		}
		if err := self.readyLog(route.logId); err != nil {
			return err
		}
	}
	return nil
}

// Records a cold direct log for the startup loop. Only the pump can mark it ready.
func (self *recordWriter) readyLog(logId Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ready, known := self.adoptedLogs[logId]
	if ready {
		return nil
	}
	if !known {
		self.adoptedLogs[logId] = false
		self.signal()
	}
	return fmt.Errorf("%w: %s", errRecordHeadPending, logId)
}

// A restored journal may predate a push plan that another life of this device already committed. Rebuilding a plan
// for those entries would append them after newer entries on different paths. Settle each only on its original
// signed header and sealed body in the verified stream. Existing plans keep their original push ids for their retry.
func (self *recordWriter) settleRestoredEntries(ctx context.Context, logId Id, through uint64) error {
	waiting := map[uint64]*RecordSealedEntry{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for seq, entry := range self.queueWithLock(logId).waitingSeqEntries {
			if seq <= through {
				waiting[seq] = entry
			}
		}
	}()
	if len(waiting) == 0 {
		return nil
	}
	versions, err := self.boundStreams().ReadStream(ctx, logId, self.sidecarId, 0)
	if err != nil {
		return err
	}
	found := map[uint64]bool{}
	for _, version := range versions {
		for _, stored := range version.Entries {
			seq, leaf, verified := recordStreamEntryOf(stored.Entry, logId, self.sidecarId, self.identityPublicKey)
			entry := waiting[seq]
			if !verified || entry == nil {
				continue
			}
			if leaf != entry.Leaf {
				return fmt.Errorf("%w: restored sequence %d", ErrRecordChainForked, seq)
			}
			signed, body, err := recordEntrySplit(stored.Entry)
			if err == nil && bytes.Equal(signed, entry.Signed) && bytes.Equal(body, entry.SealedBody) {
				found[seq] = true
			}
		}
	}
	// The surviving stream may not hold every journaled entry. An unknown outcome still replays its original bytes.
	seqs := make([]uint64, 0, len(found))
	for seq := range found {
		seqs = append(seqs, seq)
	}
	if len(seqs) == 0 {
		return nil
	}
	slices.Sort(seqs)
	if err := self.chain.Acknowledge(logId, seqs); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	queue := self.queueWithLock(logId)
	for _, seq := range seqs {
		waiting[seq].Clear()
		delete(queue.waitingSeqEntries, seq)
	}
	return nil
}
