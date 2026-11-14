//go:build !ios_extension

// RECORD-M3-09's projections (RECORD.md sections 5.6 and 6.4; §16.5's record tools; R-MCP-6, D-MCP-16, D-MCP-17, I-7,
// I-9): RecordProjection answers record_query, run_coverage and approval_status with rows over what this sidecar's
// record reads, and files record_append's coordination entries, so the MCP tools (mcp/tools_record.go), and any later
// `ur record` command, hold none of these rules.
//
//	logs        a query reads one log: vault, the author's and the default; team, the team record; directory, the
//	            team directory's copy; or an R log by its id; each only where RecordAuthView says this sidecar reads it.
//	            §8's evaluation is of the sidecar, every in-daemon agent sharing its grants (§5.5): per-agent
//	            narrowing (owner decision 4) has no agent policy to read yet, so none narrows here
//	rows        RECORD.md section 5.6's: the header's fields, the run's agent label from its context entries, trust,
//	            state, and the body by proto field name, or stub true with what withheld it
//	trust       own, a device of this sidecar's member (or of its sponsor) in an untainted run; member, another
//	            member's sidecar or a member-sponsored one in an untainted run; untrusted, a flagged entry (the
//	            header's tainted, RECORD.md reading 1), a writer the state does not admit, and the directory's
//	            announcements, requests and decisions whoever wrote them (D-MCP-29)
//	stubs       an untrusted row is a stub unless untrusted: include, which calls Taint once before any untrusted
//	            text is put in a row and fails the query when Taint fails (D-MCP-16), so a stub leaves the run as it
//	            was; a raw kind (48-53) carries its body only when entry names it; copy entries are always stubs; an
//	            erased or invalid entry has no body to show
//	pages       PageRowCount rows a call, in the log's read order; the cursor names the log and the next index
//	append      record_append's kinds only (claim, handoff, ask, answer, check, note), held to section 6.4's targets
//	            grammar, their text and targets normalized and redacted whole by §16.11's rule before the writer seals;
//	            a personal network's vault takes them; in team mode the writer sends ask, answer, check and note to
//	            the directory, and claim and handoff, state of the run's announcement (§16.11), go to the directory's
//	            runs (RECORD-M6-16) once a directory client is bound, else are refused as the writer refuses them
//	approvals   approval_status: this daemon's ledger, a named approval's log polled first while it waits
//	            (Sidecar.ApprovalStatus), then the approval family in the vault and team record for approvals the
//	            ledger does not hold; rows carry no hash or signature
//
// Safe for concurrent use: every call reads what the record, its reader and the ledger hold.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The names a query gives its log (RECORD.md section 5.6's log row); any other is an R log's id.
const (
	RecordProjectionLogVault     = "vault"
	RecordProjectionLogTeam      = "team"
	RecordProjectionLogDirectory = "directory"
)

// Section 6.4's targets forms: a keyword, its separator, and its value.
const (
	RecordTargetClaim   = "claim:"
	RecordTargetMember  = "member:"
	RecordTargetAgent   = "agent:"
	RecordTargetProject = "project:"
	RecordTargetEntry   = "entry:"
	RecordTargetAction  = "action:"
	RecordTargetResult  = "result:"
)

// check's results, CoordinationBody.result.
const (
	RecordCheckResultPass      = 1
	RecordCheckResultFail      = 2
	RecordCheckResultObjection = 3
)

// CoordinationBody.claim_state.
const (
	recordClaimStateActive   = 1
	recordClaimStateReleased = 2
)

// The cursor's text: the log's id and the index to read from, base64url.
const recordProjectionCursorSeparator = ":"

var (
	// The log a query names is none of section 5.6's forms, or one this sidecar does not read.
	ErrRecordProjectionLog = errors.New("record projection log not read")
	// A cursor this projection did not give for this log.
	ErrRecordProjectionCursor = errors.New("record projection cursor invalid")
	// untrusted: include with no way to taint the run first (D-MCP-16): nothing untrusted is returned.
	ErrRecordProjectionNoTaint = errors.New("record projection cannot taint the run first")
	// record_append of a kind other than claim, handoff, ask, answer, check and note (§16.6's refusal).
	ErrRecordAppendKind = errors.New("record_append takes claim, handoff, ask, answer, check and note only")
	// targets that section 6.4's grammar does not take for the kind, or text past its cap.
	ErrRecordTargetsInvalid = errors.New("record targets invalid")
)

// How far a row is trusted (§16.10's trust row).
type RecordTrust string

const (
	RecordTrustOwn       RecordTrust = "own"
	RecordTrustMember    RecordTrust = "member"
	RecordTrustUntrusted RecordTrust = "untrusted"
)

// Why a row holds no body.
type RecordStubReason string

const (
	// An untrusted row, or the directory's announcement, request or decision, without untrusted: include.
	RecordStubUntrusted RecordStubReason = "untrusted"
	// A raw capture kind, whose body returns only when entry names it.
	RecordStubRaw RecordStubReason = "raw"
	// A copy entry, always a stub.
	RecordStubCopy RecordStubReason = "copy"
	// No body is held: erased, invalid, or not opened; the row's state says which.
	RecordStubNoBody RecordStubReason = "no_body"
)

// A projection's bounds.
type RecordProjectionSettings struct {
	// Rows one record_query, run_coverage or approval_status call answers: 64, a reading, since RECORD.md section 5.6
	// names none; past it the page carries a cursor. Non-positive is one.
	PageRowCount int
}

// The defaults, a fresh value each call.
func DefaultRecordProjectionSettings() *RecordProjectionSettings {
	return &RecordProjectionSettings{PageRowCount: 64}
}

// What a projection reads and files through.
type RecordProjectionArgs struct {
	Record *SidecarRecord
	// The team directory's client now, nil outside a team network with a directory; nil reads none.
	Directory func() *DirectoryClient
	// The requester's inbox, whose ledger approval_status reads first; nil answers from the logs alone.
	Inbox *ApprovalInbox
	// Sidecar.ApprovalStatus, which asks a waiting approval's log first; nil reads the inbox's ledger alone.
	ApprovalStatus func(ctx context.Context, approvalId Id) (*ApprovalStatus, error)
	// §16.7's redactor, which record_append's text and targets pass; nil makes one of the projection's own.
	Redactor *Redactor
	Settings *RecordProjectionSettings
}

// The record tools' rules over one network's record.
type RecordProjection struct {
	record         *SidecarRecord
	directory      func() *DirectoryClient
	inbox          *ApprovalInbox
	approvalStatus func(ctx context.Context, approvalId Id) (*ApprovalStatus, error)
	redactor       *Redactor
	settings       *RecordProjectionSettings
}

// A projection over args.
func NewRecordProjection(args *RecordProjectionArgs) (*RecordProjection, error) {
	if args == nil || args.Record == nil {
		return nil, fmt.Errorf("%w: a projection needs a record", ErrRecordProjectionLog)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultRecordProjectionSettings()
	}
	redactor := args.Redactor
	if redactor == nil {
		var err error
		if redactor, err = NewRedactor(args.Record.writer.randomOrDefault()); err != nil {
			return nil, err
		}
	}
	directory := args.Directory
	if directory == nil {
		directory = func() *DirectoryClient { return nil }
	}
	return &RecordProjection{
		record:         args.Record,
		directory:      directory,
		inbox:          args.Inbox,
		approvalStatus: args.ApprovalStatus,
		redactor:       redactor,
		settings:       settings,
	}, nil
}

// The network's projection over its record, its directory, its approval gate's inbox and the spool's redactor, each
// read as it stands: a gate not installed answers approval_status from the logs alone. ErrSidecarStoreLocked before
// enrollment, as Record.
func (self *Sidecar) RecordProjection() (*RecordProjection, error) {
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	args := &RecordProjectionArgs{
		Record:         record,
		Directory:      self.Directory,
		ApprovalStatus: self.ApprovalStatus,
	}
	if gate, err := self.ApprovalGate(); err == nil {
		args.Inbox = gate.Inbox()
	}
	if spool, err := self.Spool(); err == nil {
		args.Redactor = spool.Redactor()
	}
	return NewRecordProjection(args)
}

// The writer's reader of randomness, crypto/rand's when none was given.
func (self *recordWriter) randomOrDefault() io.Reader {
	if self.random != nil {
		return self.random
	}
	return cryptorand.Reader
}

// One log a query reads.
type RecordProjectionLog struct {
	LogId Id
	// vault, team or directory, or the R log's id as 32 lowercase hex
	Name string
	// The directory, whose copy its client reads.
	Directory bool
}

// The log name names for this sidecar, "" taking the vault: refused with ErrRecordProjectionLog for a form section 5.6
// does not hold, a log the network has none of, and one this sidecar does not read.
func (self *RecordProjection) ResolveLog(name string) (*RecordProjectionLog, error) {
	auth := self.record.writer.auth()
	sidecarId := self.record.writer.sidecarId
	teamRecordId, directoryId := recordTeamLogs(auth)
	log := &RecordProjectionLog{Name: name}
	switch name {
	case "", RecordProjectionLogVault:
		log.Name = RecordProjectionLogVault
		authorId, ok := auth.Member(sidecarId)
		if !ok {
			authorId, ok = auth.Sponsor(sidecarId)
		}
		if !ok {
			return nil, fmt.Errorf("%w: this sidecar has no author, so no vault", ErrRecordProjectionLog)
		}
		vaultId, ok := auth.Vault(authorId)
		if !ok {
			return nil, fmt.Errorf("%w: the author has no vault yet", ErrRecordProjectionLog)
		}
		log.LogId = vaultId
	case RecordProjectionLogTeam:
		if teamRecordId == nil {
			return nil, fmt.Errorf("%w: the network has no team record", ErrRecordProjectionLog)
		}
		log.LogId = *teamRecordId
	case RecordProjectionLogDirectory:
		if directoryId == nil {
			return nil, fmt.Errorf("%w: the network has no team directory", ErrRecordProjectionLog)
		}
		log.LogId = *directoryId
		log.Directory = true
	default:
		if len(name) != 2*recordIdByteCount {
			return nil, fmt.Errorf("%w: a log is vault, team, directory or an id in 32 lowercase hex", ErrRecordProjectionLog)
		}
		logId, err := ParseId(name)
		if err != nil || recordChainIdText(logId) != name {
			return nil, fmt.Errorf("%w: a log is vault, team, directory or an id in 32 lowercase hex", ErrRecordProjectionLog)
		}
		log.LogId = logId
		switch {
		case teamRecordId != nil && *teamRecordId == logId:
			log.Name = RecordProjectionLogTeam
		case directoryId != nil && *directoryId == logId:
			log.Name = RecordProjectionLogDirectory
			log.Directory = true
		}
	}
	if !auth.Reads(log.LogId, sidecarId) {
		return nil, fmt.Errorf("%w: this sidecar does not read that log", ErrRecordProjectionLog)
	}
	return log, nil
}

// The entries log holds now, in read order, after asking for a sync: the record's reader's for a vault, team record or
// R log, the directory client's copy for the directory. stale says the sync did not complete, so these are what this
// device held before it.
func (self *RecordProjection) entries(ctx context.Context, log *RecordProjectionLog) ([]*RecordReadEntry, bool, error) {
	if log.Directory {
		directory := self.directory()
		if directory == nil {
			return nil, false, fmt.Errorf("%w: no directory client is bound", ErrRecordProjectionLog)
		}
		directory.ViewSync()
		return directory.Entries(), false, nil
	}
	reader := self.record.reader
	stale := reader.Sync(ctx, log.LogId) != nil
	return reader.Entries(log.LogId), stale, nil
}

// An entry's writer's member, or a tagged sidecar's sponsor.
func recordProjectionAuthor(auth RecordAuthView, sidecarId Id) (Id, bool) {
	if memberId, ok := auth.Member(sidecarId); ok {
		return memberId, true
	}
	return auth.Sponsor(sidecarId)
}

// §16.10's trust of an entry to this sidecar (see the file header).
func recordProjectionTrust(auth RecordAuthView, sidecarId Id, entry *RecordReadEntry, log *RecordProjectionLog) RecordTrust {
	kind := entry.Kind()
	if entry.Flagged || (log.Directory && (kind == RecordKindAnnounce || kind == RecordKindRequest || kind == RecordKindDecision)) {
		return RecordTrustUntrusted
	}
	writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
	if writerId == sidecarId {
		return RecordTrustOwn
	}
	writerAuthor, writerAdmitted := recordProjectionAuthor(auth, writerId)
	if !writerAdmitted {
		return RecordTrustUntrusted
	}
	if author, ok := recordProjectionAuthor(auth, sidecarId); ok && author == writerAuthor {
		return RecordTrustOwn
	}
	return RecordTrustMember
}

// Whether a kind is raw capture, whose body returns only when entry names it (RECORD.md section 5.6's stubs row).
func recordKindRaw(kind RecordKind) bool {
	return RecordKindTranscript <= kind && kind <= RecordKindModelCall
}

// What record_query asks (RECORD.md section 5.6).
type RecordQueryArgs struct {
	// vault (the default), team, directory, or an R log's id.
	Log   string
	RunId *Id
	// An agent's id in 32 lowercase hex, or its label.
	Agent string
	// None for every kind.
	Kinds    []RecordKind
	ActionId []byte
	EntryId  *Id
	// Zero for no bound; until is exclusive.
	Since time.Time
	Until time.Time
	// untrusted: include: an untrusted row's text, the run tainted first.
	Untrusted bool
	// Archived entries too (section 8).
	Archived bool
	Cursor   string
	// Taints the calling run, write-ahead, before any untrusted text is put in a row (D-MCP-16); nil refuses include.
	Taint func() error
}

// One row of record_query, ur://record/{log} streaming the same.
type RecordQueryRow struct {
	EntryId Id
	LogId   Id
	// vault, team, directory, or the R log's id.
	Log             string
	Kind            RecordKind
	TimeMillis      int64
	WriterSidecarId Id
	AgentId         *Id
	// The run's agent label, from its context entries this log holds; "" for none.
	AgentLabel string
	RunId      *Id
	ActionId   []byte
	Source     RecordSource
	Tainted    bool
	Trust      RecordTrust
	State      RecordEntryState
	// The body by proto field name; nil for a stub, and for a body this build cannot parse.
	Fields map[string]any
	Stub   bool
	// Why the row is a stub, "" when it is none.
	StubReason RecordStubReason
	// The stored body's size, which a caller links to past its result limit.
	BodyByteCount int
	// The cursor that continues after this row: a caller that cuts a page short ends it here.
	Cursor string
}

// One page of record_query.
type RecordQueryPage struct {
	Log  *RecordProjectionLog
	Rows []*RecordQueryRow
	// "" once the log is read to its end.
	NextCursor string
	// The log's sync did not complete: these are what this device held before it.
	Stale bool
	// Untrusted rows returned as stubs.
	WithheldCount int
	// Taint was called: an untrusted row's text is in the page.
	Tainted bool
}

// The cursor of index in log.
func recordProjectionCursor(logId Id, index int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(recordChainIdText(logId) + recordProjectionCursorSeparator + strconv.Itoa(index)))
}

// The index a cursor names in logId, 0 for none.
func recordProjectionCursorIndex(logId Id, cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, ErrRecordProjectionCursor
	}
	logText, indexText, ok := strings.Cut(string(decoded), recordProjectionCursorSeparator)
	if !ok || logText != recordChainIdText(logId) {
		return 0, ErrRecordProjectionCursor
	}
	index, err := strconv.Atoi(indexText)
	if err != nil || index < 0 {
		return 0, ErrRecordProjectionCursor
	}
	return index, nil
}

// Each run's agent label, from the context entries entries holds.
func recordProjectionAgentLabels(entries []*RecordReadEntry) map[Id]string {
	labels := map[Id]string{}
	for _, entry := range entries {
		runId := entry.Header.Header.GetRunId()
		if entry.Kind() != RecordKindContext || entry.Body == nil || len(runId) == 0 {
			continue
		}
		context := &protocol.ContextBody{}
		if err := proto.Unmarshal(entry.Body, context); err == nil && context.GetAgentLabel() != "" {
			labels[recordIdOf(runId)] = context.GetAgentLabel()
		}
	}
	return labels
}

// Whether an entry is one args keep, before paging.
func (self *RecordProjection) queryKeeps(args *RecordQueryArgs, entry *RecordReadEntry, labels map[Id]string) bool {
	header := entry.Header.Header
	switch {
	case args.EntryId != nil && entry.EntryId != *args.EntryId:
		return false
	case entry.State == RecordEntryArchived && !args.Archived && args.EntryId == nil:
		return false
	case args.RunId != nil && !bytes.Equal(header.GetRunId(), args.RunId.Bytes()):
		return false
	case 0 < len(args.Kinds) && !slices.Contains(args.Kinds, entry.Kind()):
		return false
	case len(args.ActionId) != 0 && !bytes.Equal(header.GetActionId(), args.ActionId):
		return false
	case !args.Since.IsZero() && header.GetTimeMillis() < args.Since.UnixMilli():
		return false
	case !args.Until.IsZero() && args.Until.UnixMilli() <= header.GetTimeMillis():
		return false
	}
	if args.Agent != "" {
		agentId := header.GetAgentId()
		label := ""
		if len(header.GetRunId()) != 0 {
			label = labels[recordIdOf(header.GetRunId())]
		}
		if hex.EncodeToString(agentId) != args.Agent && (label == "" || label != args.Agent) {
			return false
		}
	}
	return true
}

// record_query: one page of the rows args keep (see the file header's rows, trust and stubs rows).
func (self *RecordProjection) Query(ctx context.Context, args *RecordQueryArgs) (*RecordQueryPage, error) {
	if args == nil {
		args = &RecordQueryArgs{}
	}
	log, err := self.ResolveLog(args.Log)
	if err != nil {
		return nil, err
	}
	start, err := recordProjectionCursorIndex(log.LogId, args.Cursor)
	if err != nil {
		return nil, err
	}
	entries, stale, err := self.entries(ctx, log)
	if err != nil {
		return nil, err
	}
	auth := self.record.writer.auth()
	sidecarId := self.record.writer.sidecarId
	labels := recordProjectionAgentLabels(entries)
	pageRowCount := max(self.settings.PageRowCount, 1)
	page := &RecordQueryPage{Log: log, Stale: stale}
	type picked struct {
		entry *RecordReadEntry
		row   *RecordQueryRow
	}
	picks := []picked{}
	index := min(start, len(entries))
	for ; index < len(entries) && len(picks) < pageRowCount; index += 1 {
		entry := entries[index]
		if !self.queryKeeps(args, entry, labels) {
			continue
		}
		header := entry.Header.Header
		row := &RecordQueryRow{
			EntryId:         entry.EntryId,
			LogId:           log.LogId,
			Log:             log.Name,
			Kind:            entry.Kind(),
			TimeMillis:      header.GetTimeMillis(),
			WriterSidecarId: recordIdOf(header.GetWriterSidecarId()),
			ActionId:        bytes.Clone(header.GetActionId()),
			Source:          RecordSource(header.GetSource()),
			Tainted:         header.GetTainted(),
			Trust:           recordProjectionTrust(auth, sidecarId, entry, log),
			State:           entry.State,
			BodyByteCount:   len(entry.Body),
		}
		if agentId := header.GetAgentId(); len(agentId) != 0 {
			id := recordIdOf(agentId)
			row.AgentId = &id
		}
		if runId := header.GetRunId(); len(runId) != 0 {
			id := recordIdOf(runId)
			row.RunId = &id
			row.AgentLabel = labels[id]
		}
		switch {
		case entry.Body == nil || entry.BodyInvalid || entry.State == RecordEntryErased:
			row.Stub, row.StubReason = true, RecordStubNoBody
		case row.Kind == RecordKindCopy:
			row.Stub, row.StubReason = true, RecordStubCopy
		case recordKindRaw(row.Kind) && args.EntryId == nil:
			row.Stub, row.StubReason = true, RecordStubRaw
		case row.Trust == RecordTrustUntrusted && !args.Untrusted:
			row.Stub, row.StubReason = true, RecordStubUntrusted
			page.WithheldCount += 1
		}
		row.Cursor = recordProjectionCursor(log.LogId, index+1)
		picks = append(picks, picked{entry: entry, row: row})
	}
	if index < len(entries) {
		page.NextCursor = recordProjectionCursor(log.LogId, index)
	}
	for _, pick := range picks {
		if pick.row.Stub || pick.row.Trust != RecordTrustUntrusted || page.Tainted {
			continue
		}
		// an untrusted row's text is about to be read into the page: the run's taint first, or nothing
		if args.Taint == nil {
			return nil, ErrRecordProjectionNoTaint
		}
		if err := args.Taint(); err != nil {
			return nil, err
		}
		page.Tainted = true
	}
	for _, pick := range picks {
		if !pick.row.Stub {
			pick.row.Fields = recordExportBodyFields(pick.row.Kind, pick.entry.Body)
		}
		page.Rows = append(page.Rows, pick.row)
	}
	return page, nil
}

// What run_coverage asks (RECORD.md section 5.6).
type RecordCoverageArgs struct {
	// The logs to read by name, vault and team, each read only where this sidecar reads it; none reads both.
	Logs  []string
	RunId *Id
	// Zero for no bound: a row whose coverage, or for an open run whose last event, is older is left out.
	Since time.Time
	// Only rows whose coverage names a gap.
	GapsOnly  bool
	Cursor    string
	Untrusted bool
	// As RecordQueryArgs.Taint.
	Taint func() error
}

// One run's newest coverage in one log.
type RecordCoverageRow struct {
	RunId Id
	LogId Id
	Log   string
	// The harness and its version, as the coverage entry names them; withheld from an untrusted row without include.
	Harness  string
	Version  string
	Sources  []string
	Gaps     []string
	FirstSeq uint64
	LastSeq  uint64
	// The newest coverage entry is no older than the run's last event (RECORD.md section 4.3's re-open row).
	Ended bool
	// No coverage entry yet: the run is open.
	Open bool
	// The coverage entry's time, or an open run's last event's.
	TimeMillis int64
	Trust      RecordTrust
	// The harness and version are withheld.
	Stub bool
}

// One page of run_coverage.
type RecordCoveragePage struct {
	Rows       []*RecordCoverageRow
	NextCursor string
	Stale      bool
	Tainted    bool
}

// The logs run_coverage and approval_status read: the vault and the team record, those of names when any are named,
// each where this sidecar reads it.
func (self *RecordProjection) coverageLogs(names []string) []*RecordProjectionLog {
	logs := []*RecordProjectionLog{}
	for _, name := range []string{RecordProjectionLogVault, RecordProjectionLogTeam} {
		if 0 < len(names) && !slices.Contains(names, name) {
			continue
		}
		if log, err := self.ResolveLog(name); err == nil {
			logs = append(logs, log)
		}
	}
	return logs
}

// run_coverage: the newest coverage entry of each run in the logs this sidecar reads, with its log; a run with none
// shows open. Rows sort by log, then by run id; the cursor is the index past the last row of the page.
func (self *RecordProjection) Coverage(ctx context.Context, args *RecordCoverageArgs) (*RecordCoveragePage, error) {
	if args == nil {
		args = &RecordCoverageArgs{}
	}
	auth := self.record.writer.auth()
	sidecarId := self.record.writer.sidecarId
	page := &RecordCoveragePage{}
	rows := []*RecordCoverageRow{}
	type runState struct {
		coverage      *RecordReadEntry
		lastEvent     int64
		lastEventSeen bool
	}
	for _, log := range self.coverageLogs(args.Logs) {
		entries, stale, err := self.entries(ctx, log)
		if err != nil {
			return nil, err
		}
		page.Stale = page.Stale || stale
		runStates := map[Id]*runState{}
		runIds := []Id{}
		for _, entry := range entries {
			runIdBytes := entry.Header.Header.GetRunId()
			if len(runIdBytes) == 0 {
				continue
			}
			runId := recordIdOf(runIdBytes)
			state, ok := runStates[runId]
			if !ok {
				state = &runState{}
				runStates[runId] = state
				runIds = append(runIds, runId)
			}
			timeMillis := entry.Header.Header.GetTimeMillis()
			if entry.Kind() == RecordKindCoverage {
				if state.coverage == nil || state.coverage.Header.Header.GetTimeMillis() <= timeMillis {
					state.coverage = entry
				}
				continue
			}
			if !state.lastEventSeen || state.lastEvent < timeMillis {
				state.lastEvent, state.lastEventSeen = timeMillis, true
			}
		}
		slices.SortFunc(runIds, func(a Id, b Id) int { return a.Cmp(b) })
		for _, runId := range runIds {
			if args.RunId != nil && *args.RunId != runId {
				continue
			}
			state := runStates[runId]
			row := &RecordCoverageRow{RunId: runId, LogId: log.LogId, Log: log.Name}
			if state.coverage == nil {
				row.Open = true
				row.TimeMillis = state.lastEvent
				row.Trust = RecordTrustOwn
			} else {
				entry := state.coverage
				row.TimeMillis = entry.Header.Header.GetTimeMillis()
				row.Trust = recordProjectionTrust(auth, sidecarId, entry, log)
				row.Ended = !state.lastEventSeen || state.lastEvent <= row.TimeMillis
				coverage := &protocol.Coverage{}
				if entry.Body != nil && entry.State != RecordEntryErased && proto.Unmarshal(entry.Body, coverage) == nil {
					row.Harness = coverage.GetHarness()
					row.Version = coverage.GetVersion()
					row.Sources = slices.Clone(coverage.GetSources())
					row.Gaps = slices.Clone(coverage.GetGaps())
					row.FirstSeq = coverage.GetFirstSeq()
					row.LastSeq = coverage.GetLastSeq()
				}
				if row.Trust == RecordTrustUntrusted && !args.Untrusted {
					// the harness's own words: withheld from an untrusted row, its codes and numbers kept
					row.Harness, row.Version, row.Stub = "", "", true
				}
			}
			switch {
			case !args.Since.IsZero() && row.TimeMillis < args.Since.UnixMilli():
				continue
			case args.GapsOnly && len(row.Gaps) == 0:
				continue
			}
			rows = append(rows, row)
		}
	}
	start := 0
	if args.Cursor != "" {
		index, err := strconv.Atoi(args.Cursor)
		if err != nil || index < 0 {
			return nil, ErrRecordProjectionCursor
		}
		start = index
	}
	end := min(len(rows), min(start, len(rows))+max(self.settings.PageRowCount, 1))
	pageRows := rows[min(start, len(rows)):end]
	if end < len(rows) {
		page.NextCursor = strconv.Itoa(end)
	}
	for _, row := range pageRows {
		if row.Trust == RecordTrustUntrusted && args.Untrusted && !page.Tainted {
			if args.Taint == nil {
				return nil, ErrRecordProjectionNoTaint
			}
			if err := args.Taint(); err != nil {
				return nil, err
			}
			page.Tainted = true
		}
	}
	page.Rows = pageRows
	return page, nil
}

// What approval_status asks (RECORD.md section 5.6).
type RecordApprovalArgs struct {
	// The logs whose approval family to read beside the ledger, by name, as RecordCoverageArgs.Logs.
	Logs []string
	// The ledger alone, no log: what a caller asks that may read none.
	LedgerOnly bool
	ApprovalId *Id
	RunId      *Id
	// "" for every state.
	State  ApprovalStatusState
	Cursor string
}

// One approval's row: no hash and no signature.
type RecordApprovalRow struct {
	ApprovalId Id
	ActionId   []byte
	RunId      *Id
	State      ApprovalStatusState
	// Uses reserved, of the uses the kept approving decisions grant.
	UsedCount int
	Uses      uint32
	// Each kept approving decision's channel and approver, in the order kept.
	Channels          []protocol.ApprovalChannel
	ApproverMemberIds []Id
	NotAfter          time.Time
	// Read from this daemon's ledger, else only from a log it reads.
	Ledger bool
}

// One page of approval_status.
type RecordApprovalPage struct {
	Rows       []*RecordApprovalRow
	NextCursor string
}

// The row of a ledger approval: its status, with its request's run and its kept decisions' approvers.
func (self *RecordProjection) ledgerApprovalRow(ctx context.Context, approvalId Id, poll bool) (*RecordApprovalRow, error) {
	var status *ApprovalStatus
	var err error
	if poll && self.approvalStatus != nil {
		status, err = self.approvalStatus(ctx, approvalId)
	} else {
		status, err = self.inbox.Status(approvalId)
	}
	if err != nil {
		return nil, err
	}
	row := &RecordApprovalRow{
		ApprovalId: approvalId,
		ActionId:   bytes.Clone(status.ActionId),
		State:      status.State,
		UsedCount:  status.UsedCount,
		Uses:       status.Uses,
		Channels:   slices.Clone(status.Channels),
		NotAfter:   status.NotAfter,
		Ledger:     true,
	}
	state, err := self.inbox.args.Ledger.State(approvalId)
	if err == nil && state.Request != nil {
		if request, err := ParseStoredApprovalRequest(state.Request); err == nil && len(request.Request.GetRunId()) != 0 {
			runId := recordIdOf(request.Request.GetRunId())
			row.RunId = &runId
		}
		approves, _ := approvalKeptDecisions(state)
		for _, kept := range approves {
			row.ApproverMemberIds = append(row.ApproverMemberIds, recordIdOf(kept.decision.Decision.GetApproverMemberId()))
		}
	}
	return row, nil
}

// One approval as the approval family in the logs shows it.
type recordProjectionLogApproval struct {
	request     *protocol.ApprovalRequest
	approves    []*protocol.ApprovalDecision
	denied      bool
	cancelled   bool
	usedIndexes map[uint32]bool
}

// Each approval the vault and the team record hold the family of, by its id, for the ones no ledger here holds.
func (self *RecordProjection) logApprovals(ctx context.Context, names []string) map[Id]*recordProjectionLogApproval {
	approvals := map[Id]*recordProjectionLogApproval{}
	of := func(approvalId Id) *recordProjectionLogApproval {
		approval, ok := approvals[approvalId]
		if !ok {
			approval = &recordProjectionLogApproval{usedIndexes: map[uint32]bool{}}
			approvals[approvalId] = approval
		}
		return approval
	}
	for _, log := range self.coverageLogs(names) {
		entries, _, err := self.entries(ctx, log)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.Body == nil || entry.State == RecordEntryErased {
				continue
			}
			switch entry.Kind() {
			case RecordKindApproval:
				request := &protocol.ApprovalRequest{}
				if proto.Unmarshal(entry.Body, request) == nil && len(request.GetApprovalId()) == recordIdByteCount {
					approval := of(recordIdOf(request.GetApprovalId()))
					if approval.request == nil {
						approval.request = request
					}
				}
			case RecordKindApprovalDecision:
				decision, err := ParseStoredApprovalDecision(entry.Body)
				if err != nil || len(decision.Decision.GetApprovalId()) != recordIdByteCount {
					continue
				}
				approval := of(recordIdOf(decision.Decision.GetApprovalId()))
				if protocol.ApprovalVerdict(decision.Decision.GetDecision()) == protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY {
					approval.denied = true
				} else {
					approval.approves = append(approval.approves, decision.Decision)
				}
			case RecordKindApprovalCancel:
				signed := &bridge.Signed{}
				cancel := &protocol.ApprovalCancel{}
				if proto.Unmarshal(entry.Body, signed) == nil && proto.Unmarshal(signed.GetBody(), cancel) == nil &&
					len(cancel.GetApprovalId()) == recordIdByteCount {
					of(recordIdOf(cancel.GetApprovalId())).cancelled = true
				}
			case RecordKindApprovalUse:
				use := &protocol.ApprovalUseBody{}
				if proto.Unmarshal(entry.Body, use) == nil && len(use.GetApprovalId()) == recordIdByteCount {
					of(recordIdOf(use.GetApprovalId())).usedIndexes[use.GetUseIndex()] = true
				}
			}
		}
	}
	return approvals
}

// The row the logs give an approval, at now: approval_status's states by the ledger's rule (approvalStatusOf), over
// what the entries show.
func recordProjectionLogApprovalRow(approvalId Id, approval *recordProjectionLogApproval, now time.Time) *RecordApprovalRow {
	row := &RecordApprovalRow{ApprovalId: approvalId, UsedCount: len(approval.usedIndexes)}
	if request := approval.request; request != nil {
		row.ActionId = bytes.Clone(request.GetActionId())
		row.NotAfter = time.UnixMilli(request.GetNotAfterMillis())
		if len(request.GetRunId()) == recordIdByteCount {
			runId := recordIdOf(request.GetRunId())
			row.RunId = &runId
		}
	}
	approverIds := []Id{}
	for i, decision := range approval.approves {
		approverId := recordIdOf(decision.GetApproverMemberId())
		if slices.Contains(approverIds, approverId) {
			continue
		}
		approverIds = append(approverIds, approverId)
		if i == 0 || decision.GetUses() < row.Uses {
			row.Uses = decision.GetUses()
		}
		if notAfter := time.UnixMilli(decision.GetNotAfterMillis()); i == 0 || notAfter.Before(row.NotAfter) {
			row.NotAfter = notAfter
		}
		row.Channels = append(row.Channels, protocol.ApprovalChannel(decision.GetChannel()))
	}
	row.ApproverMemberIds = approverIds
	switch {
	case 0 < len(approverIds) && row.Uses <= uint32(row.UsedCount):
		row.State = ApprovalStatusSpent
	case approval.cancelled:
		row.State = ApprovalStatusCancelled
	case approval.denied:
		row.State = ApprovalStatusDenied
	case !row.NotAfter.IsZero() && now.After(row.NotAfter):
		row.State = ApprovalStatusExpired
	case 0 < len(approverIds):
		row.State = ApprovalStatusApproved
	default:
		row.State = ApprovalStatusPending
	}
	return row
}

// approval_status: the rows args keep, by approval id, from this daemon's ledger and then the logs.
func (self *RecordProjection) Approvals(ctx context.Context, args *RecordApprovalArgs) (*RecordApprovalPage, error) {
	if args == nil {
		args = &RecordApprovalArgs{}
	}
	var after *Id
	if args.Cursor != "" {
		cursorId, err := ParseId(args.Cursor)
		if err != nil {
			return nil, ErrRecordProjectionCursor
		}
		after = &cursorId
	}
	rows := []*RecordApprovalRow{}
	ledgerIds := map[Id]bool{}
	if self.inbox != nil {
		approvalIds, err := self.inbox.args.Ledger.approvalIds()
		if err != nil {
			return nil, err
		}
		for _, approvalId := range approvalIds {
			if args.ApprovalId != nil && *args.ApprovalId != approvalId {
				continue
			}
			row, err := self.ledgerApprovalRow(ctx, approvalId, args.ApprovalId != nil)
			if err != nil {
				// a file that does not read keeps nothing: the logs may still show it
				continue
			}
			ledgerIds[approvalId] = true
			rows = append(rows, row)
		}
	}
	now := self.record.writer.clock.Now()
	logApprovals := map[Id]*recordProjectionLogApproval{}
	if !args.LedgerOnly {
		logApprovals = self.logApprovals(ctx, args.Logs)
	}
	for approvalId, approval := range logApprovals {
		if ledgerIds[approvalId] || (args.ApprovalId != nil && *args.ApprovalId != approvalId) {
			continue
		}
		rows = append(rows, recordProjectionLogApprovalRow(approvalId, approval, now))
	}
	kept := []*RecordApprovalRow{}
	for _, row := range rows {
		switch {
		case args.RunId != nil && (row.RunId == nil || *row.RunId != *args.RunId):
			continue
		case args.State != "" && row.State != args.State:
			continue
		case after != nil && row.ApprovalId.Cmp(*after) <= 0:
			continue
		}
		kept = append(kept, row)
	}
	slices.SortFunc(kept, func(a *RecordApprovalRow, b *RecordApprovalRow) int { return a.ApprovalId.Cmp(b.ApprovalId) })
	page := &RecordApprovalPage{}
	pageRowCount := max(self.settings.PageRowCount, 1)
	if pageRowCount < len(kept) {
		page.NextCursor = recordChainIdText(kept[pageRowCount-1].ApprovalId)
		kept = kept[:pageRowCount]
	}
	page.Rows = kept
	return page, nil
}

// record_append's targets, parsed by section 6.4's grammar for one kind.
type RecordTargets struct {
	// claim:<id hex>, each a claim's opening entry_id, or in team mode §16.11's claim_id.
	ClaimIds  []Id
	MemberIds []Id
	// agent:<label>
	AgentLabels []string
	// project:<label>
	Projects []string
	// entry:<id hex>
	EntryIds []Id
	// action:<id hex>, 32 bytes each
	ActionIds [][]byte
	// path prefixes
	Paths []string
	// check's result:<pass|fail|objection>, 0 for none
	Result uint32
	// A claim with exactly one claim: target and an expiry at or before now: a release (RECORD.md reading 11).
	Release bool
}

// A target's keyword form and value, or "" for a path prefix.
func recordTargetForm(target string) (string, string) {
	for _, form := range []string{RecordTargetClaim, RecordTargetMember, RecordTargetAgent, RecordTargetProject, RecordTargetEntry, RecordTargetAction, RecordTargetResult} {
		if value, ok := strings.CutPrefix(target, form); ok {
			return form, value
		}
	}
	return "", target
}

// An id in 32 lowercase hex, or false.
func recordTargetId(text string) (Id, bool) {
	if len(text) != 2*recordIdByteCount {
		return Id{}, false
	}
	id, err := ParseId(text)
	if err != nil || recordChainIdText(id) != text {
		return Id{}, false
	}
	return id, true
}

// Parses targets for kind by section 6.4's grammar: claim, path prefixes, or to release, exactly one claim:<id> with
// expires at or before now; handoff, claim:<id> for each claim it hands off and at most one member:<id> and one
// agent:<label>; ask, any of member:, agent: and project:; answer, entry:<id> first, then as ask; check,
// result:pass|fail|objection first, then entry:<id>, action:<id> or path prefixes; note, any of these. Every refusal
// is ErrRecordTargetsInvalid and names no target's text.
func ParseRecordTargets(kind RecordKind, targets []string, expiresMillis int64, now time.Time) (*RecordTargets, error) {
	refuse := func(reason string) (*RecordTargets, error) {
		return nil, fmt.Errorf("%w: %s %s", ErrRecordTargetsInvalid, kind, reason)
	}
	switch kind {
	case RecordKindClaim, RecordKindHandoff, RecordKindAsk, RecordKindAnswer, RecordKindCheck, RecordKindNote:
	default:
		return nil, ErrRecordAppendKind
	}
	if recordTargetCount < len(targets) {
		return refuse(fmt.Sprintf("takes at most %d targets", recordTargetCount))
	}
	parsed := &RecordTargets{}
	for index, target := range targets {
		form, value := recordTargetForm(target)
		allowed := map[RecordKind][]string{
			RecordKindClaim:   {RecordTargetClaim, ""},
			RecordKindHandoff: {RecordTargetClaim, RecordTargetMember, RecordTargetAgent},
			RecordKindAsk:     {RecordTargetMember, RecordTargetAgent, RecordTargetProject},
			RecordKindAnswer:  {RecordTargetEntry, RecordTargetMember, RecordTargetAgent, RecordTargetProject},
			RecordKindCheck:   {RecordTargetResult, RecordTargetEntry, RecordTargetAction, ""},
			RecordKindNote: {RecordTargetClaim, RecordTargetMember, RecordTargetAgent, RecordTargetProject, RecordTargetEntry,
				RecordTargetAction, RecordTargetResult, ""},
		}[kind]
		if !slices.Contains(allowed, form) {
			return refuse(fmt.Sprintf("does not take target %d's form", index))
		}
		switch form {
		case RecordTargetClaim:
			id, ok := recordTargetId(value)
			if !ok {
				return refuse(fmt.Sprintf("target %d names no claim id", index))
			}
			parsed.ClaimIds = append(parsed.ClaimIds, id)
		case RecordTargetMember:
			id, ok := recordTargetId(value)
			if !ok {
				return refuse(fmt.Sprintf("target %d names no member id", index))
			}
			if kind == RecordKindHandoff && 0 < len(parsed.MemberIds) {
				return refuse("names more than one member")
			}
			parsed.MemberIds = append(parsed.MemberIds, id)
		case RecordTargetAgent:
			if !directoryLabelValid(value, DirectoryLabelByteCount) {
				return refuse(fmt.Sprintf("target %d is no agent label", index))
			}
			if kind == RecordKindHandoff && 0 < len(parsed.AgentLabels) {
				return refuse("names more than one agent")
			}
			parsed.AgentLabels = append(parsed.AgentLabels, value)
		case RecordTargetProject:
			if value == "" || !directoryIdentifierValid(directoryIdentifierText, value, DirectoryProjectByteCount) {
				return refuse(fmt.Sprintf("target %d is no project label", index))
			}
			parsed.Projects = append(parsed.Projects, value)
		case RecordTargetEntry:
			id, ok := recordTargetId(value)
			if !ok {
				return refuse(fmt.Sprintf("target %d names no entry id", index))
			}
			if kind == RecordKindAnswer && index != 0 {
				return refuse("names the entry it answers first")
			}
			parsed.EntryIds = append(parsed.EntryIds, id)
		case RecordTargetAction:
			actionId, err := hex.DecodeString(value)
			if err != nil || len(actionId) != recordHashByteCount || hex.EncodeToString(actionId) != value {
				return refuse(fmt.Sprintf("target %d names no action id", index))
			}
			parsed.ActionIds = append(parsed.ActionIds, actionId)
		case RecordTargetResult:
			result := map[string]uint32{"pass": RecordCheckResultPass, "fail": RecordCheckResultFail, "objection": RecordCheckResultObjection}[value]
			if result == 0 {
				return refuse(fmt.Sprintf("target %d is no result", index))
			}
			if kind == RecordKindCheck {
				if index != 0 {
					return refuse("names its result first")
				}
				parsed.Result = result
			}
		default:
			if value == "" || !directoryIdentifierValid(directoryIdentifierText, value, DirectoryClaimTargetByteCount) {
				return refuse(fmt.Sprintf("target %d is no path prefix", index))
			}
			parsed.Paths = append(parsed.Paths, value)
		}
	}
	switch kind {
	case RecordKindClaim:
		if 0 < len(parsed.ClaimIds) {
			if len(targets) != 1 || expiresMillis == 0 || now.UnixMilli() < expiresMillis {
				return refuse("releases one claim, alone, with expires at or before now")
			}
			parsed.Release = true
		} else if expiresMillis != 0 && expiresMillis <= now.UnixMilli() {
			return refuse("opens with expires after now; a past expiry only releases")
		}
	case RecordKindAnswer:
		if len(parsed.EntryIds) == 0 {
			return refuse("names the entry it answers first")
		}
	case RecordKindCheck:
		if parsed.Result == 0 {
			return refuse("names its result first")
		}
	}
	if expiresMillis != 0 && kind != RecordKindClaim && kind != RecordKindAsk {
		return refuse("takes no expires")
	}
	if expiresMillis < 0 {
		return refuse("expires before 1970")
	}
	return parsed, nil
}

// What record_append asks (§16.5).
type RecordAppendArgs struct {
	Kind RecordKind
	// The calling run: the session's, whose placeholder reads tainted until a hook binds it.
	RunId   *Id
	AgentId *Id
	// 32 bytes, or empty.
	ActionId []byte
	Targets  []string
	Text     string
	// Unix milliseconds; claim and ask only.
	ExpiresMillis int64
}

// What record_append filed.
type RecordAppendResult struct {
	EntryId Id
	LogId   Id
	// The entry waits unsealed in the spool, so it has no id yet: no log takes it now.
	Spooled bool
	// In team mode, the run's announcement a claim or handoff changed (RECORD-M6-16), and its version.
	AnnouncementId *Id
	Version        uint64
}

// text normalized as prose, then whole as §16.11's redaction row does it: a field the redactor finds a secret or PII
// in, or that holds a marker, becomes [REDACTED:<rule>].
func (self *RecordProjection) redactProse(text string) string {
	return self.redactWhole(DirectoryNormalizeProse(text))
}

// text, normalized already, whole as §16.11's redaction row does it.
func (self *RecordProjection) redactWhole(text string) string {
	if text == "" || directorySharedMarker(text) {
		return text
	}
	rule := ""
	start := len(text)
	if location := directoryAnyMarkerPattern.FindStringSubmatchIndex(text); location != nil {
		rule, start = text[location[2]:location[3]], location[0]
	}
	if _, matches := self.redactor.RedactShared([]byte(text)); len(matches) != 0 && matches[0].Start < start {
		rule = matches[0].Rule
	}
	if rule == "" {
		return text
	}
	return "[REDACTED:" + rule + "]"
}

// The coordination body of a record_append, its targets parsed and its text and targets redacted: a refusal before
// anything is written.
func (self *RecordProjection) coordinationBody(args *RecordAppendArgs, now time.Time) (*protocol.CoordinationBody, *RecordTargets, error) {
	targets, err := ParseRecordTargets(args.Kind, args.Targets, args.ExpiresMillis, now)
	if err != nil {
		return nil, nil, err
	}
	text := self.redactProse(args.Text)
	textCap := recordCoordinationTextByteCount
	if args.Kind == RecordKindClaim || args.Kind == RecordKindHandoff {
		textCap = recordClaimTextByteCount
	}
	if textCap < len(text) {
		return nil, nil, fmt.Errorf("%w: %s text of %d bytes, past %d", ErrRecordTargetsInvalid, args.Kind, len(text), textCap)
	}
	body := &protocol.CoordinationBody{Text: text, ExpiresMillis: args.ExpiresMillis, Result: targets.Result}
	for _, target := range args.Targets {
		form, value := recordTargetForm(target)
		if form == "" {
			// a path prefix is the agent's text: redacted whole, as a claim target is (§16.11's redaction row)
			target = self.redactWhole(value)
		}
		body.Targets = append(body.Targets, target)
	}
	if args.Kind == RecordKindClaim {
		body.ClaimState = recordClaimStateActive
		if targets.Release {
			body.ClaimId = targets.ClaimIds[0].Bytes()
			body.ClaimState = recordClaimStateReleased
		}
	}
	return body, targets, nil
}

// The log a record_append of kind lands in, and whether this sidecar deposits there rather than writing its own
// stream: the directory in team mode for every coordination kind (claim and handoff as the run's announcement), else
// the vault. What the tool's allow is judged on.
func (self *RecordProjection) AppendLog(kind RecordKind) (*RecordProjectionLog, bool, error) {
	auth := self.record.writer.auth()
	sidecarId := self.record.writer.sidecarId
	if _, directoryId := recordTeamLogs(auth); directoryId != nil {
		return &RecordProjectionLog{LogId: *directoryId, Name: RecordProjectionLogDirectory, Directory: true}, false, nil
	}
	route, err := recordVaultRoute(auth, sidecarId)
	if err != nil {
		return nil, false, fmt.Errorf("%w: no vault takes this sidecar's entries now", ErrRecordProjectionLog)
	}
	return &RecordProjectionLog{LogId: route.logId, Name: RecordProjectionLogVault}, route.deposit, nil
}

// The names a query may give logId now: its id as 32 lowercase hex, and vault, team or directory where it is that log.
func (self *RecordProjection) LogNames(logId Id) []string {
	names := []string{recordChainIdText(logId)}
	for _, name := range []string{RecordProjectionLogVault, RecordProjectionLogTeam, RecordProjectionLogDirectory} {
		if log, err := self.ResolveLog(name); err == nil && log.LogId == logId {
			names = append(names, name)
		}
	}
	return names
}

// Calls hook with each log's id after each sync of it by this record's reader, until the returned function stops it:
// what a resource's updates hang on. The reader keeps the hook, which does nothing once stopped.
func (self *SidecarRecord) WatchSyncs(hook func(logId Id)) func() {
	stopped := &atomic.Bool{}
	self.reader.addSyncHook(func(ctx context.Context, logId Id) {
		if !stopped.Load() {
			hook(logId)
		}
	})
	return func() { stopped.Store(true) }
}

// The projection's record.
func (self *RecordProjection) Record() *SidecarRecord {
	return self.record
}

// record_append: the coordination entry args describe, through the writer (see the file header's append row).
func (self *RecordProjection) Append(ctx context.Context, args *RecordAppendArgs) (*RecordAppendResult, error) {
	if args == nil {
		return nil, ErrRecordAppendKind
	}
	if len(args.ActionId) != 0 && len(args.ActionId) != recordHashByteCount {
		return nil, fmt.Errorf("%w: an action_id of %d bytes", ErrRecordTargetsInvalid, len(args.ActionId))
	}
	now := self.record.writer.clock.Now()
	body, targets, err := self.coordinationBody(args, now)
	if err != nil {
		return nil, err
	}
	if args.Kind == RecordKindClaim || args.Kind == RecordKindHandoff {
		if _, directoryId := recordTeamLogs(self.record.writer.auth()); directoryId != nil {
			return self.appendTeamClaim(ctx, args, body, targets)
		}
	}
	draft := &RecordDraft{
		Kind:     args.Kind,
		Source:   RecordSourceAgent,
		RunId:    args.RunId,
		AgentId:  args.AgentId,
		ActionId: bytes.Clone(args.ActionId),
		Body:     body,
	}
	if args.RunId == nil {
		draft.NoSession = true
	}
	refs, err := self.record.writer.Append(draft)
	if err != nil {
		return nil, err
	}
	result := &RecordAppendResult{}
	if len(refs) == 0 || refs[0].Spooled {
		result.Spooled = true
		return result, nil
	}
	result.EntryId, result.LogId = refs[0].EntryId, refs[0].LogId
	return result, nil
}

// A team-mode claim or handoff, state of the run's announcement (§16.11): the directory's runs take it once
// RECORD-M6-16 binds them; until then refused as the writer refuses it.
func (self *RecordProjection) appendTeamClaim(ctx context.Context, args *RecordAppendArgs, body *protocol.CoordinationBody, targets *RecordTargets) (*RecordAppendResult, error) {
	return nil, fmt.Errorf("%w: %s", ErrRecordRouteAnnouncement, args.Kind)
}
