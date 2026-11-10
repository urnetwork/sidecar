// RECORD.md section 18's RecordWriter, on every leg: Append seals each draft as the next entry of its author's vault
// (record_route.go), in section 5.3's order, and returns once the entry is durable in the chain's journal or in §16.7's
// spool, never waiting on evs. The push loop (record_batch.go) carries journaled entries to evs in batches, and
// record_component.go runs it on each client generation.
//
// What Append does with a draft:
//
//	routed, unlocked   seal (record_seal.go), journal (record_chain.go), queue for the log's next push or deposit
//	locked             spool the draft unsealed, to the spool's public key; it is sealed at unlock, in capture order
//	unrouted           spool it: no author, no vault yet, or no right there (section 4.2's no author row); the run's
//	                   coverage names no_vault, and it is sealed once a log takes it
//	team mode          record_team.go's routes: the vault's entry sealed first, then T's, a projection or the same
//	                   bytes, then its copy in the vault when T takes it by deposit; or the directory's (RECORD-M6-01)
//	refused            a kind no log of this network takes, a claim or handoff that is state of a run's announcement,
//	                   and read receipts, which are deposited before their reads (RECORD-M3-05)
//
// A spooled draft holds its body as marshaled once at capture and its capture time, so sealing later changes neither,
// and the run's taint at capture, which sealing ORs with the run's bit then: taint never clears, so a later seal can
// only read more tainted (D-MCP-16). While the spool holds drafts, Append spools too, after trying to drain it, so
// entries are sealed in capture order: seq order never runs against capture order on one writer. A draft of several
// entries carries its capture id on its last, so a kill between them seals the whole draft again at the next drain:
// the earlier entries then stand twice, never missing.
//
// The spool's drain (MCP-M3-18) hands over taint records first and delivers at least once. This writer owns the drain:
// a taint record goes to the handler SetSpoolHandlers installs (MCP-M3-15's ingest, which applies it to the run file
// before any capture is sealed), and so does a capture record that is no record draft. With no handler installed
// either stops the drain, failing closed: nothing after a taint record is sealed until it applies. A record draft
// drained again after a kill is told by its capture id, which the entry's journal record keeps (RecordSealArgs.
// CaptureId), and by the mark file, written after each seal and before the entry can be pushed: a capture is sealed
// once.
//
// Safe for concurrent use. Locks are taken in this order: runLock, pumpLock, drainLock, sealLock, stateLock; the chain
// store's own locks sit inside sealLock. stateLock is never held across I/O, a barrier or a call out.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The spooled draft's tag and the writer's local files, which are format values of its own state.
const (
	recordSpoolDraftPrefix  = "urnetwork-sidecar-v1/record-draft\x00"
	recordSpoolDraftVersion = 1
	recordSpoolMarkName     = "spool-mark"
	recordSpoolMarkVersion  = 1
	recordComponentName     = "record"
)

var (
	// A draft breaks a rule its header or body holds: nothing was sealed or spooled.
	ErrRecordDraftInvalid = errors.New("record draft invalid")
	// An entry a write-ahead act waits on did not commit in evs now: the act is refused.
	ErrRecordNotLanded = errors.New("record entry not landed")
	// The drain met a record no handler takes, or a draft no log takes yet: it stopped there, leaving that record and
	// every later one spooled, in order.
	errRecordSpoolUnhandled = errors.New("record spool record unhandled")
)

// Seals and appends entries to one network's logs, section 5.3's order. Safe for concurrent use. Append routes by
// section 4.2 and returns once each entry is durable in the journal or spool, never waiting on evs. A kind bound for V
// and T takes both messages.
type RecordWriter interface {
	Append(draft *RecordDraft) ([]*RecordEntryRef, error)
}

// One entry to write. Its zero value seals tainted, section 5.3's closed reading.
type RecordDraft struct {
	Kind   RecordKind
	Source RecordSource
	// nil where no run binds the entry
	RunId *Id
	// No session or harness ancestor filed it; a nil RunId without this seals tainted.
	NoSession bool
	AgentId   *Id
	// Who vouches for AgentId (§5.5): none exactly when AgentId is nil, and agent_asserted when it is set and this is
	// left none.
	AgentSource RecordAgentSource
	// 32 bytes: §16.6's action_id, or a tool's (section 4.4); empty for an entry about no action.
	ActionId []byte
	// The grant the action ran under: ACL's AclGrantId, 32 bytes, or empty. RECORD.md section 18 writes *Id, which
	// the header's 32 bytes cannot hold.
	GrantId []byte
	// The capture time on this writer's clock, Unix milliseconds; 0 takes the clock's time at Append.
	TimeMillis int64
	// The vault's body, or the only one. Exactly one of Body and StoredBody.
	Body proto.Message
	// The body as stored, never re-encoded: the approval family's (RECORD-M3-07).
	StoredBody []byte
	// T's projection, nil to take RecordProjectForTeam's of the body (record_team.go), which leaves the project empty
	// for a run in an evs repo. Held to its kind, and refused holding any field record.proto marks V:.
	Projection proto.Message
	// The approval family's entry whose approver reads only the team record, an admin's (§16.8): T alone, refused in a
	// network with none.
	TeamOnly bool
	// The one log the entry goes to, for a kind whose row in RECORD.md section 6.3 is the log it is about: a
	// disclosure, written to the log disclosed or exported. Nil routes by kind. One entry, no projection and no copy.
	LogId *Id
}

// Where one entry of a draft went.
type RecordEntryRef struct {
	LogId   Id
	EntryId Id
	// The writer's chain position in LogId, from 1.
	Seq  uint64
	Leaf [sha256.Size]byte
	// body_commitment, which a ContentRef to this entry names.
	Commitment [sha256.Size]byte
	// The draft waits unsealed in the spool: the daemon is locked, or no log takes it yet. Nothing else is set.
	Spooled bool
}

// What the writer needs of §16.7's spool: *Spool, or a test's. Append and Drain as Spool documents them.
type RecordSpool interface {
	Append(record *SpoolRecord) error
	Drain(ctx context.Context, consume func(id SpoolRecordId, record *SpoolRecord) error) error
}

// What a SidecarRecord needs of its sidecar, which Sidecar.Record fills and a test fakes.
type SidecarRecordArgs struct {
	SidecarId Id
	// This sidecar's identity key, which every entry it adopts from its own stream must verify under.
	IdentityPublicKey []byte
	// The record component's sealed directory, <state>/net/<network_id>/record/ (§5.9).
	Store SidecarStore
	// Sidecar.Sign.
	Sign func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)
	// §16.7's spool; nil refuses every draft that would spool.
	Spool RecordSpool
	// Sidecar.RunTainted; nil reads every run tainted.
	Runs RecordRunView
	// Counts a coverage gap against a run (RunStore.AddGap); nil drops it.
	Gap func(runId Id, code string)
	// RecordStreamsUnavailable until RECORD-M3-12 binds evs; nil is that.
	Streams RecordStreams
	// The authorization state now; nil, and a nil answer, read as RecordAuthUnavailable.
	Auth func() RecordAuthView
	// record_alarm's one sink (RecordAlarm); nil drops alarms.
	Alarm    func(alarm *RecordAlarm)
	Clock    Clock
	Settings *SidecarRecordSettings
	// crypto/rand's reader when nil. Push, slot and deposit ids draw from it too.
	Random io.Reader
	Log    Logger
	// Reaches the verifiable log's witnesses (record_log_witness.go); the HTTPS client when nil.
	Witness RecordLogWitness
}

// One network's record on this sidecar: its writer, its reader, its ingester, its read receipts, the approval family's
// log and the accounting mirror, sharing one binding of evs and of the authorization state, and the loop that carries
// what the writer holds, ingests deposits and mirrors queued events. Safe for concurrent use.
type SidecarRecord struct {
	writer     *recordWriter
	reader     *RecordReader
	ingester   *RecordIngester
	receipts   *RecordReceipts
	approvals  *RecordApprovals
	accounting *RecordAccounting
	log        *RecordLog

	stateLock sync.Mutex
	// a deposit may wait in this device's vault: set at each loop's start, at a commit there and at a hint
	ingestDue bool
}

// A record over args. Nothing is read until the first Append or Run.
func NewSidecarRecord(args *SidecarRecordArgs) (*SidecarRecord, error) {
	if args == nil || args.Store == nil || args.Sign == nil || args.Settings == nil {
		return nil, fmt.Errorf("%w: a record needs a store, a signer and settings", ErrRecordDraftInvalid)
	}
	writer := newRecordWriter(args)
	reader := NewRecordReader(&RecordReaderArgs{
		SidecarId: args.SidecarId,
		Store:     args.Store,
		Streams:   writer.boundStreams,
		Auth:      writer.auth,
		Alarm:     args.Alarm,
		Clock:     args.Clock,
		Settings:  args.Settings,
		Log:       args.Log,
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
	return self, nil
}

// The verifiable log (RECORD-M6-05): its monitor runs at each of the reader's syncs.
func (self *SidecarRecord) Log() *RecordLog {
	return self.log
}

// The record's writer.
func (self *SidecarRecord) Writer() RecordWriter {
	return self.writer
}

// The record's reader (RECORD-M3-03).
func (self *SidecarRecord) Reader() *RecordReader {
	return self.reader
}

// The record's ingester (RECORD-M3-04).
func (self *SidecarRecord) Ingester() *RecordIngester {
	return self.ingester
}

// The record's read receipts (RECORD-M3-05), which a reader deposits before it decrypts.
func (self *SidecarRecord) Receipts() *RecordReceipts {
	return self.receipts
}

// The approval family's log (RECORD-M3-07).
func (self *SidecarRecord) Approvals() *RecordApprovals {
	return self.approvals
}

// The membership and key mirror (RECORD-M3-08).
func (self *SidecarRecord) Accounting() *RecordAccounting {
	return self.accounting
}

// Notes that a deposit may wait, and wakes the loop.
func (self *SidecarRecord) markIngestDue() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.ingestDue = true
	}()
	self.writer.signal()
}

// Takes the ingest flag.
func (self *SidecarRecord) takeIngestDue() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	due := self.ingestDue
	self.ingestDue = false
	return due
}

// The logs this device ingests now: its vault where it writes there as a consented device, and the team record where
// it writes its stream, as a log admin's device or a designated indexer (RECORD.md section 5.4's ingester row).
func (self *SidecarRecord) ingestedLogs() []Id {
	auth := self.writer.auth()
	logIds := []Id{}
	if route, err := recordVaultRoute(auth, self.writer.sidecarId); err == nil && !route.deposit {
		logIds = append(logIds, route.logId)
	}
	if teamRecordId, _ := recordTeamLogs(auth); teamRecordId != nil && recordIngests(auth, self.writer.sidecarId, *teamRecordId) {
		logIds = append(logIds, *teamRecordId)
	}
	return logIds
}

// One pass of the loop's own work before the writer pumps: queued events mirrored, and each log this device ingests
// ingested when a deposit may wait.
func (self *SidecarRecord) tend(ctx context.Context) {
	self.accounting.mirrorQueued(ctx)
	self.log.Tick(ctx)
	logIds := self.ingestedLogs()
	if len(logIds) == 0 || !self.takeIngestDue() {
		return
	}
	for _, logId := range logIds {
		if err := self.ingester.Ingest(ctx, logId); err != nil && self.writer.log.V(1).Enabled() {
			self.writer.log.Infof("[record]an ingest pass of %s stopped: %s", logId, err)
		}
	}
}

// Carries journaled entries to evs, ingests this device's vault's deposits and mirrors queued events until ctx ends:
// one client generation's loop. A second Run waits for the first to return.
func (self *SidecarRecord) Run(ctx context.Context) {
	self.markIngestDue()
	unsubscribes := []func(){}
	for _, logId := range self.ingestedLogs() {
		unsubscribes = append(unsubscribes, self.writer.boundStreams().Subscribe(logId, func(repoId Id) { self.markIngestDue() }))
	}
	defer func() {
		for _, unsubscribe := range unsubscribes {
			unsubscribe()
		}
	}()
	self.writer.run(ctx, self.tend)
}

// Pushes and deposits everything queued now, retrying nothing that fails, and answers the first failure: what sleep
// and exit call, and what a test steps the loop with.
func (self *SidecarRecord) Flush(ctx context.Context) error {
	return self.writer.Flush(ctx)
}

// Sends what refs' logs hold now and answers nil only once every ref's entry committed in evs: a stream push, or a
// deposit holding evs's 200. What a write-ahead act waits on before its effect, a disclosure's file or an export's
// first line (RECORD.md sections 9 and 11's record rows). A ref that spooled, or that evs did not take now, is an
// error, and the entry still goes later, since a journaled entry is never withdrawn.
func (self *SidecarRecord) Land(ctx context.Context, refs []*RecordEntryRef) error {
	for _, ref := range refs {
		if ref == nil || ref.Spooled {
			return fmt.Errorf("%w: an entry waits unsealed in the spool", ErrRecordNotLanded)
		}
	}
	// another log's failure is not this act's: only these refs are judged
	flushErr := self.writer.Flush(ctx)
	for _, ref := range refs {
		if !self.writer.landed(ref.LogId, ref.Seq) {
			if flushErr != nil {
				return fmt.Errorf("%w: %v", ErrRecordNotLanded, flushErr)
			}
			return fmt.Errorf("%w: entry %s of log %s", ErrRecordNotLanded, ref.EntryId, ref.LogId)
		}
	}
	return nil
}

// Whether this writer's entry at seq of logId committed: sealed here, and neither waiting nor in a plan.
func (self *recordWriter) landed(logId Id, seq uint64) bool {
	head, err := self.chain.Head(logId)
	if err != nil || head.Seq < seq {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	queue, ok := self.logQueues[logId]
	if !ok {
		// nothing of this log was queued in this process, so nothing of it waits unless the journal says so, which
		// load puts on a queue
		return self.loaded
	}
	_, waiting := queue.waitingSeqEntries[seq]
	_, planned := queue.planSeqEntries[seq]
	return !waiting && !planned
}

// Binds evs and the authorization state as they land: RECORD-M3-12's streams, TEAM's and ACL's states. A nil
// argument keeps the current binding.
func (self *SidecarRecord) Bind(streams RecordStreams, auth func() RecordAuthView) {
	self.writer.bind(streams, auth)
}

// Installs the drain's handlers for what is not a record draft: taint records, and capture records of another
// producer (MCP-M3-15). Until one is installed a record it would take stops the drain.
func (self *SidecarRecord) SetSpoolHandlers(taint func(id SpoolRecordId, record *SpoolRecord) error, other func(id SpoolRecordId, record *SpoolRecord) error) {
	self.writer.setSpoolHandlers(taint, other)
}

// Seals what the spool holds now, in capture order, as far as it can: what an unlock calls.
func (self *SidecarRecord) DrainSpool(ctx context.Context) error {
	return self.writer.drainSpool(ctx)
}

// The writer: routing, sealing, spooling, and the queues the push loop empties.
type recordWriter struct {
	sidecarId         Id
	identityPublicKey []byte
	store             SidecarStore
	chain             *RecordChainStore
	sign              func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)
	spool             RecordSpool
	runs              RecordRunView
	gap               func(runId Id, code string)
	alarm             func(alarm *RecordAlarm)
	clock             Clock
	settings          *SidecarRecordSettings
	random            io.Reader
	log               Logger
	wake              chan struct{}

	runLock   sync.Mutex
	pumpLock  sync.Mutex
	drainLock sync.Mutex
	// held shared from a seal through its entry's enqueue, and alone while a plan takes entries, so a plan never takes
	// seq n+1 while n is between its journal and its queue
	sealLock sync.RWMutex
	loadLock sync.Mutex

	stateLock sync.Mutex
	streams   RecordStreams
	authFunc  func() RecordAuthView
	loaded    bool
	logQueues map[Id]*recordLogQueue
	// whether the spool may hold drafts: true until a drain finds none
	spoolBacklog bool
	// no drain is tried before this, Unix milliseconds: a drain that failed waits PushCoalesce, so a run of Appends
	// does not read the whole spool once each
	drainRetryMillis int64
	// the newest spooled capture sealed, nil before any
	captureMark *SpoolRecordId
	spoolTaint  func(id SpoolRecordId, record *SpoolRecord) error
	spoolOther  func(id SpoolRecordId, record *SpoolRecord) error
	commitHooks []func(logId Id)
	adoptedLogs map[Id]bool
}

// A writer over args, reading nothing until its first Append or pump.
func newRecordWriter(args *SidecarRecordArgs) *recordWriter {
	streams := args.Streams
	if streams == nil {
		streams = RecordStreamsUnavailable{}
	}
	runs := args.Runs
	if runs == nil {
		runs = RecordRunViewMissing{}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &recordWriter{
		sidecarId:         args.SidecarId,
		identityPublicKey: bytes.Clone(args.IdentityPublicKey),
		store:             args.Store,
		chain:             NewRecordChainStore(args.Store, args.SidecarId),
		sign:              args.Sign,
		spool:             args.Spool,
		runs:              runs,
		gap:               args.Gap,
		alarm:             args.Alarm,
		clock:             clockOrReal(args.Clock),
		settings:          args.Settings,
		random:            args.Random,
		log:               log,
		wake:              make(chan struct{}, 1),
		streams:           streams,
		authFunc:          args.Auth,
		logQueues:         map[Id]*recordLogQueue{},
		spoolBacklog:      true,
		adoptedLogs:       map[Id]bool{},
	}
}

// The authorization state now, failing closed to RecordAuthUnavailable.
func (self *recordWriter) auth() RecordAuthView {
	authFunc := func() func() RecordAuthView {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.authFunc
	}()
	if authFunc != nil {
		if auth := authFunc(); auth != nil {
			return auth
		}
	}
	return RecordAuthUnavailable{}
}

// The streams bound now.
func (self *recordWriter) boundStreams() RecordStreams {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.streams
}

// SidecarRecord.Bind's: a new binding lets every log adopt again, and wakes the loop.
func (self *recordWriter) bind(streams RecordStreams, auth func() RecordAuthView) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if streams != nil {
			self.streams = streams
		}
		if auth != nil {
			self.authFunc = auth
		}
		// a new binding may let a log take what waited
		self.adoptedLogs = map[Id]bool{}
	}()
	self.signal()
}

// SidecarRecord.SetSpoolHandlers'.
func (self *recordWriter) setSpoolHandlers(taint func(id SpoolRecordId, record *SpoolRecord) error, other func(id SpoolRecordId, record *SpoolRecord) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.spoolTaint = taint
	self.spoolOther = other
}

// Called after each commit of a push or deposit to logId, with no lock held: the ingester's cue (RECORD-M3-04).
func (self *recordWriter) addCommitHook(hook func(logId Id)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.commitHooks = append(self.commitHooks, hook)
}

// Wakes the push loop without waiting.
func (self *recordWriter) signal() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Raises one alarm through the record's one sink.
func (self *recordWriter) raise(reason SidecarRecordAlarm, logId Id, sidecarId *Id) {
	if self.alarm != nil {
		self.alarm(&RecordAlarm{Reason: reason, LogId: logId, SidecarId: sidecarId})
	}
}

// The draft's own rules, before anything is routed or drawn.
func (self *RecordDraft) check() error {
	if !self.Kind.Writable() {
		return fmt.Errorf("%w: kind %d is not one a v1 writer writes", ErrRecordDraftInvalid, uint32(self.Kind))
	}
	if !self.Source.Known() || self.Source == RecordSourceUnknown {
		return fmt.Errorf("%w: source %d", ErrRecordDraftInvalid, uint32(self.Source))
	}
	if !self.AgentSource.Known() || (self.AgentId == nil && self.AgentSource != RecordAgentSourceNone) {
		return fmt.Errorf("%w: agent source %s", ErrRecordDraftInvalid, self.AgentSource)
	}
	if len(self.ActionId) != 0 && len(self.ActionId) != recordHashByteCount {
		return fmt.Errorf("%w: action_id of %d bytes", ErrRecordDraftInvalid, len(self.ActionId))
	}
	if len(self.GrantId) != 0 && len(self.GrantId) != recordHashByteCount {
		return fmt.Errorf("%w: grant_id of %d bytes", ErrRecordDraftInvalid, len(self.GrantId))
	}
	if self.TimeMillis < 0 {
		return fmt.Errorf("%w: a capture time before 1970", ErrRecordDraftInvalid)
	}
	if (self.Body == nil) == (self.StoredBody == nil) {
		return fmt.Errorf("%w: a body, either as a message or as stored", ErrRecordDraftInvalid)
	}
	if self.Projection != nil {
		if err := RecordBodyValidate(self.Kind, self.Projection); err != nil {
			return fmt.Errorf("%w: projection: %v", ErrRecordDraftInvalid, err)
		}
	}
	if self.TeamOnly && !recordKindApprovalFamily(self.Kind) {
		return fmt.Errorf("%w: only the approval family goes to the team record alone", ErrRecordDraftInvalid)
	}
	if self.LogId != nil && (!recordKindNamesItsLog(self.Kind) || self.TeamOnly || self.Projection != nil) {
		return fmt.Errorf("%w: %s names no log of its own", ErrRecordDraftInvalid, self.Kind)
	}
	return nil
}

// The body as it will be sealed: the stored bytes, or the message marshaled once, deterministically. Held to section
// 6.4's caps either way, and a directory kind's to §16.11's redaction row, so no field it covers is sealed holding a
// secret.
func (self *RecordDraft) bodyBytes() ([]byte, error) {
	if self.StoredBody != nil {
		if err := RecordBodyValidateStored(self.Kind, self.StoredBody); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecordDraftInvalid, err)
		}
		if err := directoryRefuseUnredacted(self.Kind, nil, self.StoredBody); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecordDraftInvalid, err)
		}
		return bytes.Clone(self.StoredBody), nil
	}
	if err := RecordBodyValidate(self.Kind, self.Body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordDraftInvalid, err)
	}
	if err := directoryRefuseUnredacted(self.Kind, self.Body, nil); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordDraftInvalid, err)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(self.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrRecordDraftInvalid, err)
	}
	return body, nil
}

// A draft as the spool keeps it until it can be sealed: its body as marshaled at capture, its capture time and the
// run's taint then.
type recordSpoolDraft struct {
	Version     int    `json:"version"`
	Kind        uint32 `json:"kind"`
	Source      uint32 `json:"source"`
	RunId       *Id    `json:"run_id,omitempty"`
	NoSession   bool   `json:"no_session"`
	AgentId     *Id    `json:"agent_id,omitempty"`
	AgentSource uint32 `json:"agent_source"`
	ActionId    []byte `json:"action_id,omitempty"`
	GrantId     []byte `json:"grant_id,omitempty"`
	TimeMillis  int64  `json:"time_millis"`
	Tainted     bool   `json:"tainted"`
	Body        []byte `json:"body"`
	// T's projection as the caller gave it, marshaled once; empty to project the body at sealing.
	Projection []byte `json:"projection,omitempty"`
	TeamOnly   bool   `json:"team_only,omitempty"`
	// RecordDraft.LogId
	LogId *Id `json:"log_id,omitempty"`
}

// The routes of a spooled draft now: its named log's, or its kind's (record_team.go).
func (self *recordWriter) routesOf(draft *recordSpoolDraft) (*recordRoutes, error) {
	if draft.LogId != nil {
		return recordRoutesToLog(self.auth(), self.sidecarId, RecordKind(draft.Kind), *draft.LogId)
	}
	return recordRoutesFor(self.auth(), self.sidecarId, RecordKind(draft.Kind), draft.TeamOnly)
}

// The draft's spooled form, tagged so the drain tells it from another producer's capture.
func encodeRecordSpoolDraft(draft *recordSpoolDraft) ([]byte, error) {
	encoded, err := json.Marshal(draft)
	if err != nil {
		return nil, err
	}
	return append([]byte(recordSpoolDraftPrefix), encoded...), nil
}

// A spooled draft, and false for a record that is none.
func decodeRecordSpoolDraft(encoded []byte) (*recordSpoolDraft, bool) {
	rest, ok := bytes.CutPrefix(encoded, []byte(recordSpoolDraftPrefix))
	if !ok {
		return nil, false
	}
	draft := &recordSpoolDraft{}
	if err := recordChainDecode(rest, draft); err != nil || draft.Version != recordSpoolDraftVersion {
		return nil, false
	}
	return draft, true
}

// The seal's args for one entry of a spooled draft at logId: kind and body its own, with content refs, and the run's
// taint now ORed in.
func (self *recordWriter) sealArgs(draft *recordSpoolDraft, logId Id, kind RecordKind, body []byte, content []*protocol.ContentRef, captureId []byte) *RecordSealArgs {
	tainted := draft.Tainted
	switch {
	case draft.RunId != nil:
		tainted = tainted || self.runs.RunTainted(*draft.RunId)
	case !draft.NoSession:
		// an entry a session filed while no run binds it (section 5.3's unbound row)
		tainted = true
	}
	args := &RecordSealArgs{
		LogId:         logId,
		Kind:          kind,
		Source:        RecordSource(draft.Source),
		AgentSource:   RecordAgentSource(draft.AgentSource),
		AgentId:       draft.AgentId,
		RunId:         draft.RunId,
		ActionId:      bytes.Clone(draft.ActionId),
		TimeMillis:    draft.TimeMillis,
		Tainted:       tainted,
		PolicyVersion: self.auth().Pin().GetVersion(),
		GrantId:       bytes.Clone(draft.GrantId),
		Content:       content,
		StoredBody:    body,
		CaptureId:     captureId,
	}
	return args
}

// Appends draft: section 4.2's route, then section 5.3's seal and journal, or the spool. See the file's header.
func (self *recordWriter) Append(draft *RecordDraft) ([]*RecordEntryRef, error) {
	if draft == nil {
		return nil, fmt.Errorf("%w: no draft", ErrRecordDraftInvalid)
	}
	if err := draft.check(); err != nil {
		return nil, err
	}
	body, err := draft.bodyBytes()
	if err != nil {
		return nil, err
	}
	agentSource := draft.AgentSource
	if draft.AgentId != nil && agentSource == RecordAgentSourceNone {
		agentSource = RecordAgentSourceAsserted
	}
	timeMillis := draft.TimeMillis
	if timeMillis == 0 {
		timeMillis = self.clock.Now().UnixMilli()
	}
	spoolDraft := &recordSpoolDraft{
		Version:     recordSpoolDraftVersion,
		Kind:        uint32(draft.Kind),
		Source:      uint32(draft.Source),
		RunId:       draft.RunId,
		NoSession:   draft.NoSession,
		AgentId:     draft.AgentId,
		AgentSource: uint32(agentSource),
		ActionId:    bytes.Clone(draft.ActionId),
		GrantId:     bytes.Clone(draft.GrantId),
		TimeMillis:  timeMillis,
		Body:        body,
	}
	if draft.RunId != nil {
		spoolDraft.Tainted = self.runs.RunTainted(*draft.RunId)
	}
	projection, err := recordCheckedProjection(draft.Kind, draft.Projection)
	if err != nil {
		return nil, err
	}
	spoolDraft.Projection = projection
	spoolDraft.TeamOnly = draft.TeamOnly
	spoolDraft.LogId = draft.LogId
	routes, err := self.routesOf(spoolDraft)
	if errors.Is(err, errRecordUnrouted) {
		return self.spoolDraft(spoolDraft, RecordCoverageGapNoVault)
	}
	if err != nil {
		return nil, err
	}
	if err := self.load(); err != nil {
		// locked, or state this process cannot read: the capture keeps in the spool either way
		if !errors.Is(err, ErrSidecarStoreLocked) {
			self.log.Warningf("[record]the writer's state did not load: %s", err)
		}
		return self.spoolDraft(spoolDraft, "")
	}
	if self.backlogged() {
		// anything still spooled is older, so it seals first, or this draft waits behind it
		if !self.drainDue() {
			return self.spoolDraft(spoolDraft, "")
		}
		if err := self.drainSpool(context.Background()); err != nil {
			return self.spoolDraft(spoolDraft, "")
		}
	}
	refs, err := self.sealRoutes(spoolDraft, routes, nil)
	if err != nil && recordDraftNeverSeals(err) {
		return nil, err
	}
	if err != nil {
		// locked, or a journal that did not take it: the spool keeps the draft, and a draft cut after its first entry
		// seals whole again at the drain
		return self.spoolDraft(spoolDraft, "")
	}
	return refs, nil
}

// Whether a seal's failure is the draft's own, which no later attempt mends.
func recordDraftNeverSeals(err error) bool {
	return errors.Is(err, ErrRecordSealInvalid) || errors.Is(err, ErrRecordDraftInvalid) ||
		errors.Is(err, ErrRecordRouteTeamOnly) || errors.Is(err, ErrRecordRouteReceipt) ||
		errors.Is(err, ErrRecordRouteAnnouncement) || errors.Is(err, ErrRecordRouteNoTeamRecord) || errors.Is(err, ErrRecordRouteNoLog) ||
		errors.Is(err, ErrRecordProjectionNone) || errors.Is(err, ErrRecordBodyOverCap) || errors.Is(err, ErrRecordBodyInvalid)
}

// One entry sealed and queued, with what a copy of it opens it by, taken before the pump may clear its salt.
type recordSealedOpening struct {
	ref    *RecordEntryRef
	signed []byte
	salt   []byte
}

// Seals one entry of draft into route's log, kind and body its own, and queues it for the log's next push or
// deposit. captureId names a spooled capture.
func (self *recordWriter) sealOne(draft *recordSpoolDraft, route *recordRoute, kind RecordKind, body []byte, content []*protocol.ContentRef, captureId []byte) (*recordSealedOpening, error) {
	self.sealLock.RLock()
	defer self.sealLock.RUnlock()
	sealed, err := RecordSeal(&RecordSealEnv{Chain: self.chain, Sign: self.sign, Random: self.random}, self.sealArgs(draft, route.logId, kind, body, content, captureId))
	if err != nil {
		return nil, err
	}
	header, err := sealed.Header()
	if err != nil {
		return nil, err
	}
	opening := &recordSealedOpening{
		ref: &RecordEntryRef{
			LogId:      sealed.LogId,
			EntryId:    sealed.EntryId,
			Seq:        sealed.Seq,
			Leaf:       sealed.Leaf,
			Commitment: [sha256.Size]byte(header.Header.GetBodyCommitment()),
		},
		signed: bytes.Clone(sealed.Signed),
		salt:   bytes.Clone(sealed.Salt),
	}
	self.enqueue(route, sealed, kind)
	return opening, nil
}

// Seals a draft's entries by its routes (record_team.go), in order: the vault's, T's, T's copy in the vault, the
// directory's. Only the last carries captureId, so a kill between them leaves the capture to seal again whole.
func (self *recordWriter) sealRoutes(draft *recordSpoolDraft, routes *recordRoutes, captureId []byte) ([]*RecordEntryRef, error) {
	kind := RecordKind(draft.Kind)
	remaining := 0
	if routes.vault != nil && routes.vaultEntry {
		remaining += 1
	}
	if routes.team != nil {
		remaining += 1
		if routes.copy && routes.vault != nil {
			remaining += 1
		}
	}
	if routes.directory != nil {
		remaining += 1
	}
	if remaining == 0 {
		return nil, fmt.Errorf("%w: %s routes nowhere", ErrRecordRouteTeamOnly, kind)
	}
	capture := func() []byte {
		remaining -= 1
		if remaining == 0 {
			return captureId
		}
		return nil
	}
	// T's body first, so a draft that cannot project seals nothing at all
	var teamBody []byte
	if routes.team != nil {
		projected, err := recordTeamBodyBytes(kind, routes.teamBody, draft.Body, draft.Projection)
		if err != nil {
			return nil, err
		}
		teamBody = projected
	}
	refs := []*RecordEntryRef{}
	var vaultRef *RecordEntryRef
	if routes.vault != nil && routes.vaultEntry {
		sealed, err := self.sealOne(draft, routes.vault, kind, draft.Body, nil, capture())
		if err != nil {
			return refs, err
		}
		vaultRef = sealed.ref
		refs = append(refs, sealed.ref)
	}
	if routes.team != nil {
		var content []*protocol.ContentRef
		if routes.teamBody == recordTeamBodyProjection && vaultRef != nil {
			// one ContentRef to the vault entry, whose salt stays in its slot row (RECORD.md section 5.1)
			content = []*protocol.ContentRef{{RepoId: vaultRef.LogId.Bytes(), ObjectId: vaultRef.EntryId.Bytes(), Commitment: bytes.Clone(vaultRef.Commitment[:])}}
		}
		sealed, err := self.sealOne(draft, routes.team, kind, teamBody, content, capture())
		if err != nil {
			return refs, err
		}
		refs = append(refs, sealed.ref)
		if routes.copy && routes.vault != nil {
			copyBody, err := NewRecordCopyBody([]*RecordOpened{{SignedBytes: sealed.signed, Salt: sealed.salt, Body: teamBody}})
			clear(sealed.salt)
			if err != nil {
				return refs, err
			}
			copyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(copyBody)
			if err != nil {
				return refs, err
			}
			// an accounting entry of the run that filed T's, about no action of its own
			copyDraft := *draft
			copyDraft.Kind = uint32(RecordKindCopy)
			copyDraft.Source = uint32(RecordSourceObserved)
			copyDraft.ActionId = nil
			copyDraft.GrantId = nil
			copied, err := self.sealOne(&copyDraft, routes.vault, RecordKindCopy, copyBytes, nil, capture())
			clear(copyBytes)
			if err != nil {
				return refs, err
			}
			refs = append(refs, copied.ref)
		}
		clear(sealed.salt)
	}
	if routes.directory != nil {
		sealed, err := self.sealOne(draft, routes.directory, kind, draft.Body, nil, capture())
		if err != nil {
			return refs, err
		}
		refs = append(refs, sealed.ref)
	}
	return refs, nil
}

// Whether a drain may be tried now: none failed within PushCoalesce.
func (self *recordWriter) drainDue() bool {
	nowMillis := self.clock.Now().UnixMilli()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.drainRetryMillis <= nowMillis
}

// Whether the spool may hold drafts that must seal before a new one.
func (self *recordWriter) backlogged() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.spoolBacklog
}

// Spools draft unsealed, durable when this returns nil, counting gapCode against its run when one is given. A spool
// that refuses it, full or with no key, drops it, and the run's coverage names spool_drop.
func (self *recordWriter) spoolDraft(draft *recordSpoolDraft, gapCode string) ([]*RecordEntryRef, error) {
	if self.spool == nil {
		self.countGap(draft.RunId, RecordCoverageGapSpoolDrop)
		return nil, fmt.Errorf("record: no spool takes a draft that cannot seal now")
	}
	encoded, err := encodeRecordSpoolDraft(draft)
	if err != nil {
		return nil, err
	}
	record := &SpoolRecord{Kind: SpoolRecordCapture, Bytes: encoded}
	if draft.RunId != nil {
		record.RunId = *draft.RunId
	}
	if err := self.spool.Append(record); err != nil {
		self.countGap(draft.RunId, RecordCoverageGapSpoolDrop)
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.spoolBacklog = true
	}()
	if gapCode != "" {
		self.countGap(draft.RunId, gapCode)
	}
	return []*RecordEntryRef{{Spooled: true}}, nil
}

// Counts one gap against a run, when the entry has one.
func (self *recordWriter) countGap(runId *Id, code string) {
	if runId != nil && self.gap != nil {
		self.gap(*runId, code)
	}
}

// Seals what the spool holds, in capture order, until it is empty or a record cannot be taken now. Taint records and
// other producers' captures go to their handlers. See the file's header for the capture ids and the mark.
func (self *recordWriter) drainSpool(ctx context.Context) error {
	if self.spool == nil {
		return nil
	}
	if err := self.load(); err != nil {
		return err
	}
	self.drainLock.Lock()
	defer self.drainLock.Unlock()
	taint, other, mark := func() (func(SpoolRecordId, *SpoolRecord) error, func(SpoolRecordId, *SpoolRecord) error, *SpoolRecordId) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.spoolTaint, self.spoolOther, self.captureMark
	}()
	err := self.spool.Drain(ctx, func(id SpoolRecordId, record *SpoolRecord) error {
		if record.Kind == SpoolRecordTaint {
			if taint == nil {
				return fmt.Errorf("%w: a taint record with no handler", errRecordSpoolUnhandled)
			}
			return taint(id, record)
		}
		draft, ok := decodeRecordSpoolDraft(record.Bytes)
		if !ok {
			if other == nil {
				return fmt.Errorf("%w: a capture record with no handler", errRecordSpoolUnhandled)
			}
			return other(id, record)
		}
		if mark != nil && id.Compare(*mark) <= 0 {
			// sealed before a kill cut the drain short
			return nil
		}
		routes, err := self.routesOf(draft)
		if errors.Is(err, errRecordUnrouted) {
			return fmt.Errorf("%w: %v", errRecordSpoolUnhandled, err)
		}
		if err == nil {
			_, err = self.sealRoutes(draft, routes, encodeSpoolRecordId(id))
		}
		if err != nil && !recordDraftNeverSeals(err) {
			// locked again, or a write that failed: the drain stops here and takes this record again later
			return err
		}
		if err != nil {
			// a draft that can never seal: say so, and go on past it
			self.log.Warningf("[record]a spooled draft of kind %d did not seal: %s", draft.Kind, err)
			self.countGap(draft.RunId, RecordCoverageGapSpoolDrop)
		}
		if err := self.writeMark(id); err != nil {
			return err
		}
		mark = &id
		return nil
	})
	if err != nil {
		retryMillis := self.clock.Now().Add(self.settings.PushCoalesce).UnixMilli()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.drainRetryMillis = retryMillis
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.spoolBacklog = false
		self.drainRetryMillis = 0
	}()
	self.signal()
	return nil
}

// A spool record id as a capture id: its segment id, then its index, big-endian.
func encodeSpoolRecordId(id SpoolRecordId) []byte {
	encoded := make([]byte, 0, len(id.SegmentId)+8)
	encoded = append(encoded, id.SegmentId[:]...)
	for shift := 56; 0 <= shift; shift -= 8 {
		encoded = append(encoded, byte(id.Index>>shift))
	}
	return encoded
}

// The spool record id a capture id holds, false for bytes encodeSpoolRecordId did not make.
func decodeSpoolRecordId(encoded []byte) (SpoolRecordId, bool) {
	if len(encoded) != len(Id{})+8 {
		return SpoolRecordId{}, false
	}
	id := SpoolRecordId{SegmentId: Id(encoded[:len(Id{})])}
	for _, b := range encoded[len(Id{}):] {
		id.Index = id.Index<<8 | uint64(b)
	}
	return id, true
}

// The mark file's document.
type recordSpoolMarkDocument struct {
	Version   int    `json:"version"`
	SegmentId Id     `json:"segment_id"`
	Index     uint64 `json:"index"`
}

// Writes the mark durably, and keeps it.
func (self *recordWriter) writeMark(id SpoolRecordId) error {
	content, err := json.Marshal(&recordSpoolMarkDocument{Version: recordSpoolMarkVersion, SegmentId: id.SegmentId, Index: id.Index})
	if err != nil {
		return err
	}
	if err := self.chain.writeFile(recordSpoolMarkName, content); err != nil {
		return fmt.Errorf("record: spool mark: %w", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.captureMark = &id
	return nil
}

// Reads the writer's state once: each log's journaled entries and planned push, and the spool mark, the higher of the
// mark file's and the newest capture id a journal record keeps. ErrSidecarStoreLocked while locked, read again later.
func (self *recordWriter) load() error {
	self.loadLock.Lock()
	defer self.loadLock.Unlock()
	if func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}() {
		return nil
	}
	var mark *SpoolRecordId
	content, err := self.chain.readFile(recordSpoolMarkName)
	if err != nil {
		return err
	}
	if content != nil {
		document := &recordSpoolMarkDocument{}
		if err := recordChainDecode(content, document); err != nil || document.Version != recordSpoolMarkVersion {
			return fmt.Errorf("%w: the spool mark", ErrRecordChainCorrupt)
		}
		mark = &SpoolRecordId{SegmentId: document.SegmentId, Index: document.Index}
	}
	plans, err := self.readPlans()
	if err != nil {
		return err
	}
	logIds, err := self.chain.PendingLogIds()
	if err != nil {
		return err
	}
	pendingLogEntries := map[Id][]*RecordSealedEntry{}
	for _, logId := range logIds {
		pending, err := self.chain.Pending(logId)
		if err != nil {
			return err
		}
		// a read receipt goes out through its own path, which awaits evs before its read (record_receipt.go)
		entries := []*RecordSealedEntry{}
		for _, entry := range pending {
			if header, err := entry.Header(); err == nil && header.Kind() == RecordKindRead {
				entry.Clear()
				continue
			}
			entries = append(entries, entry)
		}
		if len(entries) == 0 {
			continue
		}
		pendingLogEntries[logId] = entries
		for _, entry := range entries {
			if id, ok := decodeSpoolRecordId(entry.CaptureId); ok && (mark == nil || mark.Compare(id) < 0) {
				mark = &id
			}
		}
	}
	committedPlans := []*recordPushPlan{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for logId, entries := range pendingLogEntries {
			queue := self.queueWithLock(logId)
			for _, entry := range entries {
				queue.waitingSeqEntries[entry.Seq] = entry
				if header, err := entry.Header(); err == nil && recordKindSendsAtOnce(header.Kind()) {
					queue.flushThroughSeq = max(queue.flushThroughSeq, entry.Seq)
				}
			}
			if 0 < len(entries) && queue.firstWaitingMillis == 0 {
				queue.firstWaitingMillis = self.clock.Now().UnixMilli()
			}
		}
		for _, plan := range plans {
			queue := self.queueWithLock(plan.LogId)
			if !queue.adoptPlanWithLock(plan) {
				// a plan naming a seq no longer journaled committed before the kill
				committedPlans = append(committedPlans, plan)
			}
		}
		self.captureMark = mark
		self.loaded = true
	}()
	for _, plan := range committedPlans {
		if err := self.finishCommittedPlan(plan); err != nil {
			return err
		}
	}
	return nil
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
	if built, err := self.Spool(); err == nil {
		spool = built
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
