//go:build !ios_extension

// RecordMirrors (proposed; RECORD-M3-10): the record's part of D-MCP-10 (R-MCP-11, R-EVS-17, D-EVS-17), on every leg
// but ios_extension, whose VPN component forwards and writes no record (owner decision 197). Two halves, neither of which keeps a mirror itself: EvsMirror keeps one (evs_mirror.go,
// slot copies included, each ERASE applied before its next sync), and §16.7's spool holds what a depositor keeps.
//
//	mirrors     which indexer mirrors each log, by §16.8's table, among the sidecars the config's IndexerSet designates
//	            for mirror: the author's consented indexer for a vault, a directory admin's for the directory, an
//	            admin's or auditor's for the team record, an admin's for an other ledger. A network has none by
//	            default (owner decision 177), so nothing here designates one: `ur status` names each unmirrored log,
//	            and each log this device mirrors whose mirror is partial, past HeadLag behind among the reasons
//	deposits    a depositor keeps each deposit it committed, its RecordDepositBatch as deposited, until an ingester's
//	            consumed_through mark passes its push version (QD-176): the mark comes back beside each later
//	            deposit's 200, and everything else stays within the spool's cap, oldest dropped first and counted
//	site loss   once the network's log resumes, the depositor deposits every kept batch again, verbatim: the same
//	            signed entries, never re-signed, under a new push id and deposit id, wrapped by the binding to the
//	            current drop key (§19.10), so chains and pins verify. Re-seed mode mints tokens only to Owners and
//	            Admins, so until then each deposit is refused and the kept batches wait
//
// A deposit ref placed afresh starts again from version 1, so a kept deposit's key is its ref's life and its push
// version together: the life is raised when a commit answers a version at or below one this depositor already
// committed at, or when the composition says the log resumed (Resumed). While kept deposits of an earlier life wait
// no mark prunes, since a mark of the new life says nothing of them; once each is deposited again and kept under the
// new life, the earlier lives' copies go. A kill anywhere deposits a batch again at most, which an ingester reads as
// the leaf it already wrote (RECORD.md section 5.4), and never loses one.
//
// What a depositor keeps is a deposit's plaintext, entry keys and salts among it, so it goes only to the spool's
// sealed store and never to a log line or an error.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Where a depositor's state of one log's deposit ref lives in the record's directory, and its document's version.
const (
	recordMirrorDepositPrefix  = "mirror/deposit/"
	recordMirrorDepositVersion = 1
	// a kept deposit's key holds its ref's life above its push version's 48 bits, a layout of the spool's names
	recordMirrorLifeShift = 48
)

// A deposit ref's version past what a kept deposit's key holds beside its life.
var ErrRecordMirrorVersion = errors.New("record deposit version past a kept deposit's key")

// What the record's mirror reporting and resume are tuned by.
type RecordMirrorSettings struct {
	// A mirror whose oldest missing version is at least this old is partial: 1 h (§11.13's status row, D-MCP-10).
	HeadLag time.Duration
}

// A fresh value each call.
func DefaultRecordMirrorSettings() *RecordMirrorSettings {
	return &RecordMirrorSettings{
		HeadLag: 1 * time.Hour,
	}
}

// What this device's own mirror of one log covers, as §11.13's status row reads it.
type RecordMirrorCoverage struct {
	// The time of the oldest version of any ref the mirror lacks; zero when it holds every head.
	BehindSince time.Time
	// Every other reason the mirror is partial, as a person reads it: ids and counts only (I-13).
	Reasons []string
}

// What the record reads of the config's indexers and of this device's mirrors, so it builds with neither:
// record_mirror_evs.go binds ConfigState and EvsMirror, and RecordMirrorViewUnavailable answers until then.
type RecordMirrorView interface {
	// The sidecars the newest verified config designates for mirror: IndexerSet subjects that serve and whose
	// services name it (§3.6). False while no verified state answers, and then nothing is said of any log.
	Indexers() ([]Id, bool)
	// The network's other ledgers at that state, its live `record` repos (§16.8's table).
	Ledgers() []Id
	// This device's mirror of logId; nil with no error when it keeps none.
	Coverage(ctx context.Context, logId Id) (*RecordMirrorCoverage, error)
}

// The view until one is bound: no state answers, so status says the mirrors are unknown rather than absent.
type RecordMirrorViewUnavailable struct{}

// Unknown.
func (self RecordMirrorViewUnavailable) Indexers() ([]Id, bool) {
	return nil, false
}

// None.
func (self RecordMirrorViewUnavailable) Ledgers() []Id {
	return nil
}

// None kept.
func (self RecordMirrorViewUnavailable) Coverage(ctx context.Context, logId Id) (*RecordMirrorCoverage, error) {
	return nil, nil
}

// What the depositor's half needs of §16.7's spool: *Spool, or a test's. Keep, Kept and PruneKept as Spool documents
// them, pushVersion being whatever key the caller orders its deposits by.
type RecordDepositSpool interface {
	Keep(logId Id, pushVersion uint64, deposit []byte) error
	Kept(logId Id, visit func(pushVersion uint64, deposit []byte) error) error
	PruneKept(logId Id, consumedThrough uint64) (int, error)
}

// Which of §16.8's table's rows a log is.
type RecordMirrorLogKind string

const (
	RecordMirrorLogVault      RecordMirrorLogKind = "vault"
	RecordMirrorLogTeamRecord RecordMirrorLogKind = "team_record"
	RecordMirrorLogDirectory  RecordMirrorLogKind = "directory"
	RecordMirrorLogLedger     RecordMirrorLogKind = "record"
)

// One log this device reports on, with the indexers the table makes its mirrors.
type RecordMirrorLog struct {
	LogId Id
	Kind  RecordMirrorLogKind
	// The designated indexers §16.8's table names for the log, ascending; empty for an unmirrored log.
	MirrorSidecarIds []Id
}

// A depositor's state of one log's deposit ref, stored form.
type recordMirrorDepositDocument struct {
	Version int `json:"version"`
	// The ref's life this depositor is on, raised each time the ref is found placed afresh.
	Life uint32 `json:"life"`
	// The highest version a deposit of this life committed at.
	LastVersion uint64 `json:"last_version"`
	// Kept deposits of earlier lives wait to be deposited again.
	Resuming bool `json:"resuming,omitempty"`
	// Deposits the spool did not keep at its cap, which a site loss before their ingest loses.
	DropCount uint64 `json:"drop_count,omitempty"`
}

// The record's mirrors and kept deposits on one sidecar.
type RecordMirrors struct {
	writer *recordWriter

	// one resume pass at a time
	tendLock sync.Mutex

	stateLock sync.Mutex
	settings  *RecordMirrorSettings
	view      RecordMirrorView
	spool     RecordDepositSpool
	// each log's deposit state as last read or written
	logDeposits map[Id]*recordMirrorDepositDocument
	// the earlier lives' deposits each log deposited again in this process, by their kept key
	logRedeposited map[Id]map[uint64]bool
}

// Which indexer mirrors each log, and the deposits this device keeps until consumed (RECORD-M3-10), made at the first
// call: from then the writer hands them each committed deposit, the loop tends them, and Sidecar.Record's spool keeps
// their deposits. The record's component makes them when it is built, so a daemon's depositor always keeps; a record
// run with no component keeps nothing before its first call here.
func (self *SidecarRecord) Mirrors() *RecordMirrors {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	mirrors, _ := self.mirrors.(*RecordMirrors)
	if mirrors == nil {
		mirrors = newRecordMirrors(self.writer)
		if spool, ok := self.kept.(RecordDepositSpool); ok {
			mirrors.spool = spool
		}
		self.mirrors = mirrors
		self.writer.setDepositKeeper(mirrors.depositCommitted)
		self.tendHooks = append(self.tendHooks, func(ctx context.Context) {
			if err := mirrors.Tend(ctx); err != nil && self.writer.log.V(1).Enabled() {
				self.writer.log.Infof("[record]%s", err)
			}
		})
	}
	return mirrors
}

// The mirrors over writer's bindings, with the default settings: no view, so status says the mirrors are unknown,
// and no spool, so nothing is kept, which status names, until Bind.
func newRecordMirrors(writer *recordWriter) *RecordMirrors {
	return &RecordMirrors{
		writer:         writer,
		settings:       DefaultRecordMirrorSettings(),
		view:           RecordMirrorViewUnavailable{},
		logDeposits:    map[Id]*recordMirrorDepositDocument{},
		logRedeposited: map[Id]map[uint64]bool{},
	}
}

// Replaces the settings, DefaultRecordMirrorSettings until then.
func (self *RecordMirrors) SetSettings(settings *RecordMirrorSettings) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if settings != nil {
		self.settings = settings
	}
}

// Binds the config's indexers and this device's mirrors, and the spool that keeps deposits, as they land. A nil
// argument keeps the current binding.
func (self *RecordMirrors) Bind(view RecordMirrorView, spool RecordDepositSpool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if view != nil {
		self.view = view
	}
	if spool != nil {
		self.spool = spool
	}
}

// The bound view and spool.
func (self *RecordMirrors) bound() (RecordMirrorView, RecordDepositSpool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.view, self.spool
}

// A kept deposit's key: its ref's life, then its push version.
func recordMirrorKeptKey(life uint32, version uint64) (uint64, error) {
	if 1<<recordMirrorLifeShift <= version || 1<<(64-recordMirrorLifeShift) <= uint64(life) {
		return 0, fmt.Errorf("%w: life %d, version %d", ErrRecordMirrorVersion, life, version)
	}
	return uint64(life)<<recordMirrorLifeShift | version, nil
}

// The life a kept deposit's key holds.
func recordMirrorKeptLife(key uint64) uint32 {
	return uint32(key >> recordMirrorLifeShift)
}

// The name of logId's deposit state.
func recordMirrorDepositName(logId Id) string {
	return recordMirrorDepositPrefix + recordChainIdText(logId)
}

// logId's deposit state, a fresh one where none is stored. The caller holds no lock; the answer is a copy.
func (self *RecordMirrors) loadDeposit(logId Id) (*recordMirrorDepositDocument, error) {
	held := func() *recordMirrorDepositDocument {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if document, ok := self.logDeposits[logId]; ok {
			copied := *document
			return &copied
		}
		return nil
	}()
	if held != nil {
		return held, nil
	}
	content, err := self.writer.chain.readFile(recordMirrorDepositName(logId))
	if err != nil {
		return nil, err
	}
	document := &recordMirrorDepositDocument{Version: recordMirrorDepositVersion}
	if content != nil {
		if err := recordChainDecode(content, document); err != nil || document.Version != recordMirrorDepositVersion {
			return nil, fmt.Errorf("%w: deposit state of log %s", ErrRecordChainCorrupt, logId)
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *document
	self.logDeposits[logId] = &copied
	return document, nil
}

// Writes logId's deposit state durably, then keeps it.
func (self *RecordMirrors) storeDeposit(logId Id, document *recordMirrorDepositDocument) error {
	content, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if err := self.writer.chain.writeFile(recordMirrorDepositName(logId), content); err != nil {
		return fmt.Errorf("record: deposit state: %w", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *document
	self.logDeposits[logId] = &copied
	return nil
}

// Whether the spool keeps batch under key for logId already: a commit answered again after a kill.
func recordMirrorHolds(spool RecordDepositSpool, logId Id, key uint64, batch []byte) (bool, error) {
	want := sha256.Sum256(batch)
	held := false
	err := spool.Kept(logId, func(keptKey uint64, deposit []byte) error {
		if keptKey == key && sha256.Sum256(deposit) == want {
			held = true
		}
		clear(deposit)
		return nil
	})
	return held, err
}

// A deposit of this sidecar to logId committed at commit: kept under its ref's life and version until the mark
// passes it, and what the mark already passed pruned. The writer calls it before it acknowledges the plan, so a
// failure here sends the plan again, to the same commit, and keeps then. A spool at its cap that cannot take the
// batch drops it, counted, and the commit stands.
func (self *RecordMirrors) depositCommitted(logId Id, commit *RecordStreamCommit, batch []byte) error {
	_, spool := self.bound()
	if spool == nil || commit == nil {
		return nil
	}
	document, err := self.loadDeposit(logId)
	if err != nil {
		return err
	}
	if document.LastVersion != 0 && commit.Version <= document.LastVersion {
		key, err := recordMirrorKeptKey(document.Life, commit.Version)
		if err != nil {
			return err
		}
		held, err := recordMirrorHolds(spool, logId, key, batch)
		if err != nil {
			return err
		}
		if held {
			// the same commit answered again: kept already
			return nil
		}
		// a version this depositor already passed: the ref was placed afresh, so what is kept of its earlier life
		// goes again (the file header's site loss row)
		document.Life += 1
		document.LastVersion = 0
		document.Resuming = true
		if err := self.storeDeposit(logId, document); err != nil {
			return err
		}
		self.writer.log.Warningf("[record]log %s's deposit ref started again; its kept deposits go again", logId)
	}
	key, err := recordMirrorKeptKey(document.Life, commit.Version)
	if err != nil {
		return err
	}
	testHookBarrier("record.mirror.keep.before", recordChainIdText(logId))
	err = spool.Keep(logId, key, batch)
	testHookBarrier("record.mirror.keep.after", recordChainIdText(logId))
	switch {
	case errors.Is(err, ErrSpoolFull):
		document.DropCount += 1
	case err != nil:
		return err
	}
	document.LastVersion = commit.Version
	if err := self.storeDeposit(logId, document); err != nil {
		return err
	}
	if document.Resuming || commit.ConsumedThrough == 0 {
		return nil
	}
	// never past what this depositor committed: a mark above it is not of this ref's life
	mark, err := recordMirrorKeptKey(document.Life, min(commit.ConsumedThrough, document.LastVersion))
	if err != nil {
		return err
	}
	if _, err := spool.PruneKept(logId, mark); err != nil {
		return err
	}
	return nil
}

// The composition's word that logId's network resumed after a site loss, so its deposit ref was placed afresh
// (§19.10): what this depositor keeps of it goes again at the next Tend. Calling it for a log that lost nothing
// deposits its kept batches once more, which an ingester reads as entries it already wrote.
func (self *RecordMirrors) Resumed(logId Id) error {
	self.tendLock.Lock()
	defer self.tendLock.Unlock()
	// with the writer's commits, which raise the life too
	self.writer.pumpLock.Lock()
	defer self.writer.pumpLock.Unlock()
	document, err := self.loadDeposit(logId)
	if err != nil {
		return err
	}
	document.Life += 1
	document.LastVersion = 0
	document.Resuming = true
	if err := self.storeDeposit(logId, document); err != nil {
		return err
	}
	self.writer.signal()
	return nil
}

// The logs whose deposit state this device holds, ascending.
func (self *RecordMirrors) depositLogs() ([]Id, error) {
	entries, err := self.writer.store.List(recordMirrorDepositPrefix)
	if err != nil {
		return nil, err
	}
	logIds := []Id{}
	for _, entry := range entries {
		logIdBytes, err := hex.DecodeString(strings.TrimPrefix(entry.Name, recordMirrorDepositPrefix))
		if err != nil {
			continue
		}
		logId, err := IdFromBytes(logIdBytes)
		if err != nil {
			continue
		}
		logIds = append(logIds, logId)
	}
	slices.SortFunc(logIds, func(a Id, b Id) int { return a.Cmp(b) })
	return logIds, nil
}

// One pass of the depositor's upkeep: each log whose kept deposits wait on a resumed ref deposits them again. The
// first failure of a log leaves it resuming, for the next pass, and the pass goes on to the next log.
func (self *RecordMirrors) Tend(ctx context.Context) error {
	self.tendLock.Lock()
	defer self.tendLock.Unlock()
	_, spool := self.bound()
	if spool == nil {
		return nil
	}
	logIds, err := self.depositLogs()
	if err != nil {
		return err
	}
	errs := []error{}
	for _, logId := range logIds {
		document, err := self.loadDeposit(logId)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !document.Resuming {
			continue
		}
		if err := self.redeposit(ctx, spool, logId); err != nil {
			errs = append(errs, fmt.Errorf("record: log %s's kept deposits wait: %w", logId, err))
		}
	}
	return errors.Join(errs...)
}

// Deposits again every batch kept of logId's earlier lives, in the order kept, each kept anew under the current
// life, then drops the earlier lives' copies. Serialized with the writer's own deposits on the ref.
func (self *RecordMirrors) redeposit(ctx context.Context, spool RecordDepositSpool, logId Id) error {
	writer := self.writer
	writer.pumpLock.Lock()
	defer writer.pumpLock.Unlock()
	auth := writer.auth()
	if deposit, ok := recordLogMode(auth, writer.sidecarId, logId); !ok || !deposit {
		return fmt.Errorf("%w: this sidecar does not deposit to log %s now", ErrRecordRouteNoLog, logId)
	}
	pin := auth.Pin()
	if pin == nil {
		return ErrRecordAuthAhead
	}
	document, err := self.loadDeposit(logId)
	if err != nil {
		return err
	}
	done := func() map[uint64]bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.logRedeposited[logId] == nil {
			self.logRedeposited[logId] = map[uint64]bool{}
		}
		return self.logRedeposited[logId]
	}()
	streams := writer.boundStreams()
	hookKey := recordChainIdText(logId)
	err = spool.Kept(logId, func(key uint64, batch []byte) error {
		defer clear(batch)
		if document.Life <= recordMirrorKeptLife(key) || done[key] {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		pushId, err := writer.drawId()
		if err != nil {
			return err
		}
		depositId, err := writer.drawId()
		if err != nil {
			return err
		}
		testHookBarrier("record.mirror.redeposit.before", hookKey)
		commit, err := streams.Deposit(ctx, logId, &RecordStreamDeposit{
			PushId:             pushId,
			DepositorSidecarId: writer.sidecarId,
			DepositId:          depositId,
			Batch:              batch,
			AuthPin:            pin,
		})
		testHookBarrier("record.mirror.redeposit.after", hookKey)
		if err != nil {
			return err
		}
		newKey, err := recordMirrorKeptKey(document.Life, commit.Version)
		if err != nil {
			return err
		}
		switch err := spool.Keep(logId, newKey, batch); {
		case errors.Is(err, ErrSpoolFull):
			document.DropCount += 1
		case err != nil:
			return err
		}
		document.LastVersion = max(document.LastVersion, commit.Version)
		if err := self.storeDeposit(logId, document); err != nil {
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			done[key] = true
		}()
		return nil
	})
	if err != nil {
		return err
	}
	// every earlier life's copy went again and is kept under this life: below this life's first key, all go
	floor, err := recordMirrorKeptKey(document.Life, 0)
	if err != nil {
		return err
	}
	if 0 < floor {
		if _, err := spool.PruneKept(logId, floor-1); err != nil {
			return err
		}
	}
	document.Resuming = false
	if err := self.storeDeposit(logId, document); err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.logRedeposited, logId)
	}()
	return nil
}

// The logs this device reports on at the bound state, each with its mirrors by §16.8's table: its author's vault,
// the team record, the directory and the network's other ledgers. False while no verified state names the indexers.
func (self *RecordMirrors) Logs() ([]*RecordMirrorLog, bool) {
	view, _ := self.bound()
	indexerIds, ok := view.Indexers()
	if !ok {
		return nil, false
	}
	auth := self.writer.auth()
	sidecarId := self.writer.sidecarId
	logs := []*RecordMirrorLog{}
	add := func(logId Id, kind RecordMirrorLogKind, mirrors func(indexerId Id) bool) {
		log := &RecordMirrorLog{LogId: logId, Kind: kind}
		for _, indexerId := range indexerIds {
			if mirrors(indexerId) && !slices.Contains(log.MirrorSidecarIds, indexerId) {
				log.MirrorSidecarIds = append(log.MirrorSidecarIds, indexerId)
			}
		}
		slices.SortFunc(log.MirrorSidecarIds, func(a Id, b Id) int { return a.Cmp(b) })
		logs = append(logs, log)
	}
	authorId, hasAuthor := auth.Member(sidecarId)
	if !hasAuthor {
		authorId, hasAuthor = auth.Sponsor(sidecarId)
	}
	if hasAuthor {
		if vaultId, ok := auth.Vault(authorId); ok {
			// the author's consented indexer
			add(vaultId, RecordMirrorLogVault, func(indexerId Id) bool { return auth.Consented(vaultId, indexerId) })
		}
	}
	teamRecordId, directoryId := recordTeamLogs(auth)
	if teamRecordId != nil {
		// an admin's or auditor's indexer: the team record's readers are admins' and auditors' devices
		add(*teamRecordId, RecordMirrorLogTeamRecord, func(indexerId Id) bool {
			return auth.Admins(*teamRecordId, indexerId) || auth.Reads(*teamRecordId, indexerId)
		})
	}
	if directoryId != nil {
		add(*directoryId, RecordMirrorLogDirectory, func(indexerId Id) bool { return auth.Admins(*directoryId, indexerId) })
	}
	ledgerIds := slices.Clone(view.Ledgers())
	slices.SortFunc(ledgerIds, func(a Id, b Id) int { return a.Cmp(b) })
	for _, ledgerId := range slices.Compact(ledgerIds) {
		add(ledgerId, RecordMirrorLogLedger, func(indexerId Id) bool { return auth.Admins(ledgerId, indexerId) })
	}
	return logs, true
}

// The logs this device is a mirror of by the table, which its composition keeps EvsMirrors of; empty for a device
// no designation names, which mirrors nothing unasked.
func (self *RecordMirrors) Plan() []Id {
	logs, ok := self.Logs()
	if !ok {
		return nil
	}
	logIds := []Id{}
	for _, log := range logs {
		if slices.Contains(log.MirrorSidecarIds, self.writer.sidecarId) {
			logIds = append(logIds, log.LogId)
		}
	}
	return logIds
}

// `ur status`'s record lines (QD-550), in a fixed order: each unmirrored log, each log this device mirrors whose
// mirror is partial or missing, then what this depositor's kept deposits wait on. Ids and counts only (I-13). A
// coverage that cannot be read is named as such, never left out.
func (self *RecordMirrors) StatusLines(ctx context.Context) []string {
	view, spool := self.bound()
	settings := func() *RecordMirrorSettings {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.settings
	}()
	lines := []string{}
	logs, ok := self.Logs()
	if !ok {
		lines = append(lines, "record:     mirrors unknown: no verified config state names the network's indexers yet")
	}
	now := self.writer.clock.Now()
	for _, log := range logs {
		if len(log.MirrorSidecarIds) == 0 {
			lines = append(lines, fmt.Sprintf("unmirrored: log %s (%s): no indexer its readers' table names is designated for mirror, so a site loss loses it", log.LogId, log.Kind))
			continue
		}
		if !slices.Contains(log.MirrorSidecarIds, self.writer.sidecarId) {
			continue
		}
		coverage, err := view.Coverage(ctx, log.LogId)
		switch {
		case err != nil:
			lines = append(lines, fmt.Sprintf("record:     log %s (%s) mirror unknown: %s", log.LogId, log.Kind, err))
		case coverage == nil:
			lines = append(lines, fmt.Sprintf("record:     log %s (%s) mirror none: this device is designated to mirror it and holds no mirror", log.LogId, log.Kind))
		default:
			reasons := slices.Clone(coverage.Reasons)
			if !coverage.BehindSince.IsZero() && settings.HeadLag <= now.Sub(coverage.BehindSince) {
				reasons = append([]string{"behind its head since " + coverage.BehindSince.UTC().Format(time.RFC3339)}, reasons...)
			}
			if 0 < len(reasons) {
				lines = append(lines, fmt.Sprintf("record:     log %s (%s) mirror partial: %s", log.LogId, log.Kind, strings.Join(reasons, "; ")))
			}
		}
	}
	logIds, err := self.depositLogs()
	if err != nil {
		return append(lines, fmt.Sprintf("record:     kept deposits unknown: %s", err))
	}
	for _, logId := range logIds {
		document, err := self.loadDeposit(logId)
		if err != nil {
			lines = append(lines, fmt.Sprintf("record:     log %s kept deposits unknown: %s", logId, err))
			continue
		}
		if document.Resuming {
			lines = append(lines, fmt.Sprintf("record:     log %s: kept deposits wait to go again once the log takes deposits after a site loss", logId))
		}
		if 0 < document.DropCount {
			lines = append(lines, fmt.Sprintf("record:     log %s: %d deposits not kept at the spool's cap, which a site loss before their ingest loses", logId, document.DropCount))
		}
	}
	if spool == nil {
		auth := self.writer.auth()
		if route, err := recordVaultRoute(auth, self.writer.sidecarId); err == nil && route.deposit {
			lines = append(lines, fmt.Sprintf("record:     log %s: this device keeps no deposit until its ingest, so a site loss loses what is not ingested", route.logId))
		}
	}
	return lines
}
