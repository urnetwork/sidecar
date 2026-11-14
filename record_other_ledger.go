//go:build !ios_extension

// Other ledgers (RECORD-M6-09; RECORD.md section 6.5; R-CTX-18; owner decision on QD-138): a `record` repo, an R log,
// is a per-client partition of the team record under its own keys. A log admin writes a `ledger_scope` entry there
// naming the repos and projects the ledger covers; a sidecar with write on that log adds, from its next run, a copy
// of each in-scope run entry bound for the team record.
//
//	governs   the newest ledger_scope by section 5.5's newest row, among those a repo admin of the log pushed, judged
//	          at each push's own pin: each admin's newest by seq, then the latest push time, then the higher
//	          writer_sidecar_id. One from a writer that was no admin at its push's pin is ignored
//	next run  a run's ledgers are decided once, at its first context entry, from the scopes governing then; a run
//	          already under way keeps what was decided for it, and a run whose context came before a scope is not
//	          copied. The decisions live in memory, so a daemon restart mid-run stops that run's copies: a copy is
//	          never made on a guess
//	copies    T's projection of the entry, never a vault body, sealed as an ordinary entry of the R log: its own
//	          entry_id, chain position, key and commitment. So an R log's erasure or shred leaves T's entry, and T's
//	          erasure leaves the R log's
//	kinds     context, change, the approval family, restore and coverage, narrowed by the scope's kinds. Claims and
//	          the other coordination kinds never go here; cost joins only once it goes past the vault
//	agents    write here only through this path: no tool names a log
//
// `ur status` names each ledger this daemon copies to (StatusLines). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The ledgers' own bounds.
type RecordLedgerSettings struct {
	// Runs whose ledgers are kept decided at once: 4,096. Past it the run decided first is forgotten, and its later
	// entries are not copied.
	RunCount int
}

// The defaults, a fresh value each call.
func DefaultRecordLedgerSettings() *RecordLedgerSettings {
	return &RecordLedgerSettings{RunCount: 4096}
}

// A ledger's governing scope.
type RecordLedgerScope struct {
	LogId Id
	// The entry that governs, and who wrote it.
	EntryId         Id
	WriterSidecarId Id
	RepoIds         []Id
	Projects        []string
	// The kinds copied; empty for every kind a ledger takes.
	Kinds []RecordKind
}

// Whether the scope covers a run in repo, or of project.
func (self *RecordLedgerScope) covers(repoId []byte, project string) bool {
	if len(repoId) != 0 && slices.ContainsFunc(self.RepoIds, func(held Id) bool { return bytes.Equal(held[:], repoId) }) {
		return true
	}
	return project != "" && slices.Contains(self.Projects, project)
}

// Whether the scope copies kind.
func (self *RecordLedgerScope) copies(kind RecordKind) bool {
	if !RecordKindLedgerCopied(kind) {
		return false
	}
	return len(self.Kinds) == 0 || slices.Contains(self.Kinds, kind)
}

// The scope that governs logId among entries, a reader's of that log: section 5.5's newest row over the ledger_scope
// entries whose writer administered the log at the pin of the push that first held them. Nil when none stands.
func RecordLedgerGoverning(auth RecordAuthView, logId Id, entries []*RecordReadEntry) *RecordLedgerScope {
	// each admin's newest by seq
	writerNewest := map[Id]*RecordReadEntry{}
	for _, entry := range entries {
		if entry == nil || entry.Kind() != RecordKindLedgerScope || entry.State == RecordEntryForked {
			continue
		}
		writerId, err := IdFromBytes(entry.Header.Header.GetWriterSidecarId())
		if err != nil || len(entry.Copies) == 0 || entry.Copies[0].AuthPin == nil {
			continue
		}
		judged, err := auth.At(entry.Copies[0].AuthPin)
		if err != nil || !judged.Admins(logId, writerId) {
			continue
		}
		if held, ok := writerNewest[writerId]; !ok || held.Header.Header.GetSeq() < entry.Header.Header.GetSeq() {
			writerNewest[writerId] = entry
		}
	}
	var newest *RecordReadEntry
	for _, entry := range writerNewest {
		switch {
		case newest == nil, newest.PushTimeMillis < entry.PushTimeMillis:
			newest = entry
		case newest.PushTimeMillis == entry.PushTimeMillis &&
			bytes.Compare(newest.Header.Header.GetWriterSidecarId(), entry.Header.Header.GetWriterSidecarId()) < 0:
			newest = entry
		}
	}
	if newest == nil || newest.Body == nil || newest.BodyInvalid {
		// the newest scope erased or unreadable governs nothing, and no older one stands in for it
		return nil
	}
	body := &protocol.LedgerScopeBody{}
	if err := proto.Unmarshal(newest.Body, body); err != nil || RecordBodyValidate(RecordKindLedgerScope, body) != nil {
		return nil
	}
	scope := &RecordLedgerScope{LogId: logId, EntryId: newest.EntryId, Projects: slices.Clone(body.GetProjects())}
	scope.WriterSidecarId, _ = IdFromBytes(newest.Header.Header.GetWriterSidecarId())
	for _, repoIdBytes := range body.GetRepoIds() {
		if repoId, err := IdFromBytes(repoIdBytes); err == nil {
			scope.RepoIds = append(scope.RepoIds, repoId)
		}
	}
	for _, kind := range body.GetKinds() {
		scope.Kinds = append(scope.Kinds, RecordKind(kind))
	}
	return scope
}

// What `ur record ledger set` asks.
type RecordLedgerScopeArgs struct {
	LogId    Id
	RepoIds  []Id
	Projects []string
	Kinds    []RecordKind
	// The caller runs under a harness process: refused, since a log admin sets a scope.
	HarnessAncestor bool
	// A person confirmed on /dev/tty or in an app.
	Confirmed bool
}

// A daemon's ledgers: the scopes that govern, and each run's.
type RecordLedgers struct {
	record   *SidecarRecord
	settings *RecordLedgerSettings

	stateLock sync.Mutex
	// each ledger's governing scope at the last Refresh
	logScopes map[Id]*RecordLedgerScope
	// each run's ledgers, decided at its first context entry, and the runs in the order decided
	runLedgers map[Id][]Id
	runOrder   []Id
	// the ledgers a copy was sealed for since the process began
	copiedLogs map[Id]bool
}

// The record's ledgers, made at the first call: from then the writer copies in-scope run entries, and the loop
// refreshes the scopes.
func (self *SidecarRecord) Ledgers() *RecordLedgers {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ledgers, _ := self.ledgers.(*RecordLedgers)
	if ledgers == nil {
		ledgers = &RecordLedgers{
			record:     self,
			settings:   DefaultRecordLedgerSettings(),
			logScopes:  map[Id]*RecordLedgerScope{},
			runLedgers: map[Id][]Id{},
			copiedLogs: map[Id]bool{},
		}
		self.ledgers = ledgers
		self.writer.setLedgerCopies(ledgers.copiesOf)
		self.tendHooks = append(self.tendHooks, func(ctx context.Context) {
			if err := ledgers.Refresh(ctx); err != nil && self.writer.log.V(1).Enabled() {
				self.writer.log.Infof("[record]%s", err)
			}
		})
	}
	return ledgers
}

// Writes a ledger_scope entry to a ledger this sidecar administers and writes. It governs once pushed, for runs that
// start after each copying sidecar next reads the ledger.
func (self *RecordLedgers) SetScope(args *RecordLedgerScopeArgs) (*RecordEntryRef, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: no scope", ErrRecordDraftInvalid)
	}
	if args.HarnessAncestor {
		return nil, fmt.Errorf("%w: a ledger's scope is set by a person, not under a harness", ErrRecordDraftInvalid)
	}
	if !args.Confirmed {
		return nil, fmt.Errorf("%w: a ledger's scope takes a person's confirmation", ErrRecordDraftInvalid)
	}
	body := &protocol.LedgerScopeBody{Projects: slices.Clone(args.Projects)}
	for _, repoId := range args.RepoIds {
		body.RepoIds = append(body.RepoIds, repoId.Bytes())
	}
	for _, kind := range args.Kinds {
		body.Kinds = append(body.Kinds, uint32(kind))
	}
	logId := args.LogId
	refs, err := self.record.writer.Append(&RecordDraft{
		Kind:      RecordKindLedgerScope,
		Source:    RecordSourceObserved,
		NoSession: true,
		Body:      body,
		LogId:     &logId,
	})
	if err != nil {
		return nil, err
	}
	if len(refs) != 1 {
		return nil, fmt.Errorf("record: a ledger scope sealed %d entries", len(refs))
	}
	return refs[0], nil
}

// The ledgers of the state this sidecar writes its own stream of.
func (self *RecordLedgers) written() []Id {
	auth := self.record.writer.auth()
	logs := auth.Logs()
	if logs == nil {
		return nil
	}
	written := []Id{}
	for _, logId := range logs.LedgerIds {
		if auth.Writes(logId, self.record.writer.sidecarId) {
			written = append(written, logId)
		}
	}
	return written
}

// Reads each ledger this sidecar writes and takes its governing scope. A ledger that does not read keeps no scope:
// nothing is copied on a scope this sidecar cannot see. The first failure is returned after every ledger was tried.
func (self *RecordLedgers) Refresh(ctx context.Context) error {
	var first error
	scopes := map[Id]*RecordLedgerScope{}
	reader := self.record.Reader()
	for _, logId := range self.written() {
		if err := reader.Sync(ctx, logId); err != nil {
			if first == nil {
				first = fmt.Errorf("record: ledger %s: %w", logId, err)
			}
			continue
		}
		if scope := RecordLedgerGoverning(self.record.writer.auth(), logId, reader.Entries(logId)); scope != nil {
			scopes[logId] = scope
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.logScopes = scopes
	return first
}

// A ledger's governing scope as last read, and false for none.
func (self *RecordLedgers) Scope(logId Id) (*RecordLedgerScope, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	scope, ok := self.logScopes[logId]
	return scope, ok
}

// The ledgers a draft's team entry is copied to: the writer's question as it seals a draft bound for the team record.
// A run's first context entry decides the run's ledgers.
func (self *RecordLedgers) copiesOf(kind RecordKind, runId *Id, body []byte) []Id {
	if runId == nil || !RecordKindLedgerCopied(kind) {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ledgerIds, decided := self.runLedgers[*runId]
	if !decided {
		if kind != RecordKindContext {
			return nil
		}
		contextBody := &protocol.ContextBody{}
		if err := proto.Unmarshal(body, contextBody); err != nil {
			return nil
		}
		ledgerIds = []Id{}
		for logId, scope := range self.logScopes {
			if scope.covers(contextBody.GetRepoId(), contextBody.GetProject()) {
				ledgerIds = append(ledgerIds, logId)
			}
		}
		slices.SortFunc(ledgerIds, func(a Id, b Id) int { return a.Cmp(b) })
		if 0 < self.settings.RunCount && self.settings.RunCount <= len(self.runOrder) {
			delete(self.runLedgers, self.runOrder[0])
			self.runOrder = self.runOrder[1:]
		}
		self.runLedgers[*runId] = ledgerIds
		self.runOrder = append(self.runOrder, *runId)
	}
	copied := []Id{}
	for _, logId := range ledgerIds {
		// the scope's kinds as they stand now narrow a run already decided; its repos and projects do not widen it
		if scope, ok := self.logScopes[logId]; ok && scope.copies(kind) {
			copied = append(copied, logId)
			self.copiedLogs[logId] = true
		}
	}
	return copied
}

// What `ur status` shows of the ledgers: each `record` log this daemon copies run entries to.
func (self *RecordLedgers) StatusLines() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	logIds := []Id{}
	for logId := range self.logScopes {
		logIds = append(logIds, logId)
	}
	slices.SortFunc(logIds, func(a Id, b Id) int { return a.Cmp(b) })
	lines := []string{}
	for _, logId := range logIds {
		scope := self.logScopes[logId]
		line := fmt.Sprintf("record:     copies run entries to ledger %s: %d repos and %d projects in scope", logId, len(scope.RepoIds), len(scope.Projects))
		if !self.copiedLogs[logId] {
			line += ", none copied yet"
		}
		lines = append(lines, line)
	}
	return lines
}
