//go:build !ios_extension

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
			if !verified {
				continue
			}
			if through < seq {
				// This read already saw a newer signed entry. Repeat the complete writer read before any
				// acknowledgement or fresh signature uses its earlier head and counter.
				return fmt.Errorf("%w: record stream advanced from sequence %d to %d during journal recovery", ErrRecordStreamsUnavailable, through, seq)
			}
			entry := waiting[seq]
			if entry == nil {
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

// A record over args. Nothing is read until the first Append or Run.
func NewSidecarRecord(args *SidecarRecordArgs) (*SidecarRecord, error) {
	if args == nil || args.Store == nil || args.Sign == nil || args.Settings == nil {
		return nil, fmt.Errorf("%w: a record needs a store, a signer and settings", ErrRecordDraftInvalid)
	}
	writer := newRecordWriter(args)
	reader := NewRecordReader(&RecordReaderArgs{
		SidecarId:    args.SidecarId,
		Store:        args.Store,
		Streams:      writer.boundStreams,
		Auth:         writer.auth,
		Alarm:        args.Alarm,
		Clock:        args.Clock,
		Settings:     args.Settings,
		Log:          args.Log,
		AgentSubkeys: args.AgentSubkeys,
	})
	self := &SidecarRecord{
		writer:     writer,
		reader:     reader,
		ingester:   newRecordIngester(writer, reader),
		receipts:   newRecordReceipts(writer),
		approvals:  &RecordApprovals{writer: writer, reader: reader},
		accounting: &RecordAccounting{writer: writer, reader: reader},
		ingestDue:  true,
	}
	writer.addCommitHook(func(logId Id) { self.markIngestDue() })
	self.log = newRecordLog(self, args.Witness)
	reader.addSyncHook(self.log.monitor)
	self.export = newRecordExport(self)
	return self, nil
}

// The network's record, one per Sidecar, built once its network and identity are known. Its streams stay unavailable
// until RECORD-M3-12 binds evs, and its authorization state until TEAM's and ACL's states bind (SidecarRecord.Bind), so
// until then every draft spools, as an unrouted one does. ErrSidecarStoreLocked before enrollment, and
// ErrSidecarNoIdentity before an identity. The record component (record_component.go) runs its push loop.
func (self *Sidecar) Record() (*SidecarRecord, error) {
	networkId := self.knownNetworkId()
	if self.instance == nil || networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	identity := self.Identity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	store, err := self.LocalStore().Directory(recordComponentName, recordComponentName)
	if err != nil {
		return nil, err
	}
	// each takes the records' lock itself, so before it is taken here
	var spool RecordSpool
	var kept *Spool
	if built, err := self.Spool(); err == nil {
		spool = built
		kept = built
	}
	runs, runsErr := self.Runs()
	self.records.stateLock.Lock()
	defer self.records.stateLock.Unlock()
	self.records.forNetworkWithLock(*networkId)
	if self.records.record != nil {
		return self.records.record, nil
	}
	args := &SidecarRecordArgs{
		SidecarId:         identity.SidecarId,
		IdentityPublicKey: identity.IdentityPublicKey,
		Store:             store,
		Sign:              self.Sign,
		Spool:             spool,
		// taint read at sealing, true whenever the run store cannot answer (D-MCP-16)
		Runs: self,
		Alarm: func(alarm *RecordAlarm) {
			logId := alarm.LogId
			self.emitEvent(SidecarEvent{Kind: SidecarEventRecordAlarm, RepoId: &logId, SidecarId: alarm.SidecarId, RecordAlarm: alarm.Reason})
		},
		Clock:    self.settings.ClockOrReal(),
		Settings: self.settings.Record,
		Log:      self.log,
	}
	args.AgentSubkeys = self.settings.AgentSubkeys
	if recordSidecarAgentSigner != nil && self.settings.AgentSubkeys != nil && self.settings.AgentSubkeys.SignRecordEntries {
		args.SignProvenance = recordSidecarAgentSigner(self)
	}
	if runsErr == nil {
		args.Gap = func(runId Id, code string) {
			if err := runs.AddGap(context.Background(), runId, code); err != nil {
				self.log.Warningf("[record]a coverage gap was not counted: %s", err)
			}
		}
	}
	record, err := NewSidecarRecord(args)
	if err != nil {
		return nil, err
	}
	// where a follow job's lines go: a file on this device, on a leg that has files
	record.SetExportSink(recordExportFileSink())
	if kept != nil {
		record.kept = kept
	}
	// §5's membership and key events, mirrored into the member's vault (RECORD-M3-08); Queue never blocks. A Sidecar
	// NewSidecar did not build raises no events to mirror.
	if self.eventCallbacks != nil {
		self.AddEventCallback(func(event SidecarEvent) {
			if mirrored, ok := RecordAccountingEventOf(event); ok {
				record.Accounting().Queue(mirrored)
			}
		})
	}
	self.records.record = record
	return record, nil
}
