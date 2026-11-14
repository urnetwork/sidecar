//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's record tools (RECORD-M3-09; RECORD.md section 5.6; D-MCP-13, D-MCP-16, D-MCP-17, I-7, I-9): record_query,
// run_coverage and approval_status at R, record_append at W, and ur://record/{log}, each over the call's network's
// sidecar.RecordProjection, which holds the rules (record_projection.go's header). What this file adds:
//
//	allow      §8's local allow of read on the log a query reads, and of write, or deposit where this sidecar deposits,
//	           on the log record_append lands in; record_append's kind goes to McpGuard, whose record row refuses
//	           every kind but claim, handoff, ask, answer, check and note (§16.6)
//	taint      untrusted: include taints the run, write-ahead, before any untrusted text is read into a row
//	           (McpResult.Untrusted, D-MCP-16); a failed write fails the call, and a stub leaves the run as it was;
//	           untrusted text then sits between §16.6's markers (McpResult.Fence), every string of the row's body
//	trust      the result is own until a row is another member's or a stub of an untrusted one, member then, and
//	           untrusted once an untrusted row's text is in it
//	size       a page stops before the row that would take it past ResultByteCount; a single row past it, a raw
//	           kind's body named by entry, returns as a link to ur://record/{log}/{entry}, which reads that one row
//	           (D-MCP-13's resource_link from 2025-06-18, else text naming it)
//	resources  ur://record/{log} reads the log's first page as record_query does; a read never taints, so it
//	           returns an untrusted row's text only where the call's run is tainted already; ur://record/{log}/{entry}
//	           reads one entry's row, a raw body included; a subscription is judged at once (the log resolves for
//	           this sidecar and §8 allows read), and WatchRecord sends the record reader's syncs as updates
//	secrets    every result passes the framework's matcher (I-7): a body holding a credential is refused whole
//
// Errors are constant text and never name a target, a path or any other argument.

package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A row's time, as every record tool writes one: RFC 3339 in UTC with milliseconds.
const mcpRecordTimeLayout = "2006-01-02T15:04:05.000Z"

// untrusted's values, as §16.10 names them.
const (
	mcpRecordUntrustedWithhold = "withhold"
	mcpRecordUntrustedInclude  = "include"
)

// What the record tools read of a network: *sidecar.RecordProjection, or a test's. Safe for concurrent use.
type McpRecord interface {
	ResolveLog(name string) (*sidecar.RecordProjectionLog, error)
	AppendLog(kind sidecar.RecordKind) (*sidecar.RecordProjectionLog, bool, error)
	Query(ctx context.Context, args *sidecar.RecordQueryArgs) (*sidecar.RecordQueryPage, error)
	Coverage(ctx context.Context, args *sidecar.RecordCoverageArgs) (*sidecar.RecordCoveragePage, error)
	Approvals(ctx context.Context, args *sidecar.RecordApprovalArgs) (*sidecar.RecordApprovalPage, error)
	Append(ctx context.Context, args *sidecar.RecordAppendArgs) (*sidecar.RecordAppendResult, error)
}

// How a tool reaches a call's record.
type mcpRecordOfFunction func(call *McpCall) (McpRecord, error)

// The production record of a call: its network's RecordProjection, *sidecar.Sidecar's.
func mcpRecordOfNetwork(call *McpCall) (McpRecord, error) {
	holder, ok := call.Network.(interface {
		RecordProjection() (*sidecar.RecordProjection, error)
	})
	if !ok {
		return nil, errMcpRecordUnavailable
	}
	projection, err := holder.RecordProjection()
	if err != nil {
		return nil, mcpRecordError(err)
	}
	return projection, nil
}

// The tools' refusals, each constant.
var (
	errMcpRecordUnavailable = NewMcpError(McpCodeUnavailable, "this daemon holds no record for the network yet: run ur status in your own terminal", true)
	errMcpRecordLog         = NewMcpError(McpCodeFailedPrecondition,
		"this sidecar does not read that log: name vault, team, directory or the id of a log it reads", false)
	errMcpRecordCursor   = NewMcpError(McpCodeInvalidArguments, "the cursor is not one this tool gave for that log", false)
	errMcpRecordArgument = NewMcpError(McpCodeInvalidArguments,
		"an id is 32 lowercase hex (64 for an action), a time RFC 3339, kind a record kind's name and untrusted withhold or include", false)
	errMcpRecordTargets = NewMcpError(McpCodeInvalidArguments,
		"the targets do not fit the kind's grammar (RECORD.md section 6.4), or the text or expires does not fit the kind", false)
	errMcpRecordAnnouncement = NewMcpError(McpCodeFailedPrecondition,
		"in a team network a claim or a handoff changes the calling run's announcement, which this daemon cannot file for the run now", false)
	errMcpRecordState = NewMcpError(McpCodeInvalidArguments,
		"state is pending, approved, denied, cancelled, expired, spent or uncertain", false)
	errMcpRecordClaimsOff = NewMcpError(McpCodeFailedPrecondition,
		"claims is off for this run's project, so it announces nothing and takes no claim or handoff: a person sets it with ur directory runs", false)
	errMcpRecordClaimsFull = NewMcpError(McpCodeFailedPrecondition,
		"the run's announcement holds its four claims: release one with a claim:<id> target and a past expires first", false)
	// the guard's record row answers first; this is the projection's own refusal behind it
	errMcpRecordKind = NewMcpError(McpCodeRefused, "record_append takes claim, handoff, ask, answer, check and note only", false)
)

// A sidecar error as the tools answer it, by constant text.
func mcpRecordError(err error) error {
	var mcpError *McpError
	switch {
	case errors.As(err, &mcpError):
		return err
	case errors.Is(err, sidecar.ErrSidecarStoreLocked):
		return errMcpLocked
	case errors.Is(err, sidecar.ErrRecordProjectionLog):
		return errMcpRecordLog
	case errors.Is(err, sidecar.ErrRecordProjectionCursor):
		return errMcpRecordCursor
	case errors.Is(err, sidecar.ErrRecordAppendKind):
		return errMcpRecordKind
	case errors.Is(err, sidecar.ErrRecordTargetsInvalid), errors.Is(err, sidecar.ErrRecordDraftInvalid):
		return errMcpRecordTargets
	case errors.Is(err, sidecar.ErrRecordRouteAnnouncement), errors.Is(err, sidecar.ErrDirectoryRunUnknown):
		return errMcpRecordAnnouncement
	case errors.Is(err, sidecar.ErrDirectoryRunsClaimsOff):
		return errMcpRecordClaimsOff
	case errors.Is(err, sidecar.ErrDirectoryRunClaimsFull):
		return errMcpRecordClaimsFull
	case errors.Is(err, sidecar.ErrRecordProjectionNoTaint):
		return errMcpTaintFailed
	case errors.Is(err, sidecar.ErrApprovalNoState):
		return errMcpApprovalUnavailable
	}
	return err
}

// A time argument, zero for "".
func mcpRecordTime(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, errMcpRecordArgument
	}
	return parsed, nil
}

// An id argument in 32 lowercase hex, nil for "".
func mcpRecordId(text string) (*sidecar.Id, error) {
	if text == "" {
		return nil, nil
	}
	id, err := sidecar.ParseId(text)
	if err != nil || len(text) != 32 || hex.EncodeToString(id.Bytes()) != text {
		return nil, errMcpRecordArgument
	}
	return &id, nil
}

// An action id argument in 64 lowercase hex, nil for "".
func mcpRecordActionId(text string) ([]byte, error) {
	if text == "" {
		return nil, nil
	}
	actionId, err := hex.DecodeString(text)
	if err != nil || len(actionId) != 32 || hex.EncodeToString(actionId) != text {
		return nil, errMcpRecordArgument
	}
	return actionId, nil
}

// Whether untrusted asks for untrusted text: include, or withhold and "" for not.
func mcpRecordInclude(untrusted string) (bool, error) {
	switch untrusted {
	case "", mcpRecordUntrustedWithhold:
		return false, nil
	case mcpRecordUntrustedInclude:
		return true, nil
	}
	return false, errMcpRecordArgument
}

// hex, "" for none.
func mcpRecordHex(value []byte) string {
	return hex.EncodeToString(value)
}

// An id as hex, "" for nil.
func mcpRecordIdHex(id *sidecar.Id) string {
	if id == nil {
		return ""
	}
	return hex.EncodeToString(id.Bytes())
}

// A time in milliseconds as a row writes it.
func mcpRecordTimeText(millis int64) string {
	return time.UnixMilli(millis).UTC().Format(mcpRecordTimeLayout)
}

// Each string of value fenced, through maps and lists, for an untrusted row's body.
func mcpRecordFence(result *McpResult, value any) any {
	switch typed := value.(type) {
	case string:
		return result.Fence(typed)
	case map[string]any:
		fenced := map[string]any{}
		for key, item := range typed {
			fenced[key] = mcpRecordFence(result, item)
		}
		return fenced
	case []any:
		fenced := make([]any, 0, len(typed))
		for _, item := range typed {
			fenced = append(fenced, mcpRecordFence(result, item))
		}
		return fenced
	}
	return value
}

// The names of the vault and the team record where each resolves for this sidecar and §8 allows read on it, at clock's
// now; errMcpNotAllowed when none is, errMcpRecordLog when none resolves.
func mcpRecordAllowedLogs(record McpRecord, clock sidecar.Clock, call *McpCall) ([]string, error) {
	network, ok := mcpToolNetworkOf(call)
	if !ok {
		return nil, errMcpNoToolNetwork
	}
	names := []string{}
	resolved := false
	for _, name := range []string{sidecar.RecordProjectionLogVault, sidecar.RecordProjectionLogTeam} {
		log, err := record.ResolveLog(name)
		if err != nil {
			continue
		}
		resolved = true
		allowed := true
		for _, access := range mcpRecordReadAccess(log) {
			check, installed := network.Allow(access.Action, access.Resource, clock.Now())
			if !installed {
				return nil, errMcpNoPolicy
			}
			allowed = allowed && check.Allowed
		}
		if allowed {
			names = append(names, name)
		}
	}
	switch {
	case !resolved:
		return nil, errMcpRecordLog
	case len(names) == 0:
		return nil, errMcpNotAllowed
	}
	return names, nil
}

// The access a query of log needs: read on it.
func mcpRecordReadAccess(log *sidecar.RecordProjectionLog) []McpAccess {
	return []McpAccess{{Action: protocol.AclAction_ACL_ACTION_READ, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: log.LogId}}}
}

// record_query's arguments (RECORD.md section 5.6).
type mcpRecordQueryIn struct {
	// vault (the default), team, directory, or a log's id
	Log string `json:"log,omitempty"`
	Run string `json:"run,omitempty"`
	// an agent's id or label
	Agent string `json:"agent,omitempty"`
	// a record kind's name
	Kind   string `json:"kind,omitempty"`
	Action string `json:"action,omitempty"`
	Entry  string `json:"entry,omitempty"`
	// RFC 3339
	Since string `json:"since,omitempty"`
	Until string `json:"until,omitempty"`
	// withhold (the default) or include
	Untrusted string `json:"untrusted,omitempty"`
	Archived  bool   `json:"archived,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

// One row, as record_query and ur://record write it.
type mcpRecordRowOut struct {
	EntryId    string `json:"entry_id"`
	Log        string `json:"log"`
	Kind       string `json:"kind"`
	Time       string `json:"time"`
	Writer     string `json:"writer"`
	AgentId    string `json:"agent_id,omitempty"`
	AgentLabel string `json:"agent_label,omitempty"`
	RunId      string `json:"run_id,omitempty"`
	ActionId   string `json:"action_id,omitempty"`
	Source     string `json:"source"`
	Tainted    bool   `json:"tainted"`
	Trust      string `json:"trust"`
	State      string `json:"state"`
	// the body by proto field name
	Body map[string]any `json:"body,omitempty"`
	Stub bool           `json:"stub,omitempty"`
	// why a stub holds no body: untrusted, raw, copy or no_body
	Withheld string `json:"withheld,omitempty"`
}

// record_query's data, and ur://record's.
type mcpRecordQueryOut struct {
	Rows       []*mcpRecordRowOut `json:"rows"`
	NextCursor string             `json:"next_cursor,omitempty"`
	// the log's sync did not finish: these are what this device held before it
	Stale bool `json:"stale,omitempty"`
	// untrusted rows returned as stubs
	UntrustedWithheld int `json:"untrusted_withheld"`
}

// The out of row, its body fenced where its text is untrusted; whether it lowers the result's trust to member.
func mcpRecordRow(result *McpResult, row *sidecar.RecordQueryRow) (*mcpRecordRowOut, bool) {
	out := &mcpRecordRowOut{
		EntryId:    mcpRecordHex(row.EntryId.Bytes()),
		Log:        row.Log,
		Kind:       row.Kind.String(),
		Time:       mcpRecordTimeText(row.TimeMillis),
		Writer:     mcpRecordHex(row.WriterSidecarId.Bytes()),
		AgentId:    mcpRecordIdHex(row.AgentId),
		AgentLabel: row.AgentLabel,
		RunId:      mcpRecordIdHex(row.RunId),
		ActionId:   mcpRecordHex(row.ActionId),
		Source:     row.Source.String(),
		Tainted:    row.Tainted,
		Trust:      string(row.Trust),
		State:      string(row.State),
		Stub:       row.Stub,
		Withheld:   string(row.StubReason),
	}
	if !row.Stub && row.Fields != nil {
		out.Body = row.Fields
		if row.Trust == sidecar.RecordTrustUntrusted {
			out.Body, _ = mcpRecordFence(result, row.Fields).(map[string]any)
		}
	}
	return out, row.Trust != sidecar.RecordTrustOwn
}

// A page as its out, cut before the row that would take it past byteLimit; a first row past it alone is the page, and
// the result links to its entry's resource.
func mcpRecordPageOut(result *McpResult, page *sidecar.RecordQueryPage, byteLimit int) *mcpRecordQueryOut {
	out := &mcpRecordQueryOut{Rows: []*mcpRecordRowOut{}, NextCursor: page.NextCursor, Stale: page.Stale, UntrustedWithheld: page.WithheldCount}
	byteCount := mcpRecordPageOverhead(page)
	member := false
	for i, row := range page.Rows {
		rowOut, lowers := mcpRecordRow(result, row)
		encoded, err := json.Marshal(rowOut)
		if err != nil {
			continue
		}
		if 0 < len(out.Rows) && byteLimit < byteCount+len(encoded) {
			out.NextCursor = page.Rows[i-1].Cursor
			break
		}
		if len(out.Rows) == 0 && byteLimit < byteCount+len(encoded) {
			// one row past the limit: the result links to the resource that reads it
			result.SetResource(McpRecordEntryUri(page.Log.Name, row.EntryId))
			if i+1 < len(page.Rows) {
				out.NextCursor = row.Cursor
			}
			out.Rows = append(out.Rows, rowOut)
			member = member || lowers
			break
		}
		byteCount += len(encoded)
		out.Rows = append(out.Rows, rowOut)
		member = member || lowers
	}
	if member {
		result.Member()
	}
	return out
}

// The bytes a page's result holds besides its rows, measured rather than guessed: the envelope at its longest tags,
// and the page's own keys with a cursor as long as any a row gives.
func mcpRecordPageOverhead(page *sidecar.RecordQueryPage) int {
	cursor := page.NextCursor
	for _, row := range page.Rows {
		if len(cursor) < len(row.Cursor) {
			cursor = row.Cursor
		}
	}
	data, err := json.Marshal(&mcpRecordQueryOut{Rows: []*mcpRecordRowOut{}, NextCursor: cursor, Stale: true, UntrustedWithheld: len(page.Rows)})
	if err != nil {
		return 0
	}
	envelope, err := json.Marshal(&mcpResultEnvelope{
		Trust:        McpTrustUntrusted,
		Source:       "record:" + page.Log.Name,
		MeteredBytes: math.MaxInt64,
		MarkerBroken: true,
		Data:         json.RawMessage(data),
	})
	if err != nil {
		return 0
	}
	// each row after the first adds its separating comma
	return len(envelope) + len(page.Rows)
}

// The URI of a log's resource.
func McpRecordUri(logName string) string {
	return "ur://record/" + logName
}

// The URI of one entry's row.
func McpRecordEntryUri(logName string, entryId sidecar.Id) string {
	return "ur://record/" + logName + "/" + hex.EncodeToString(entryId.Bytes())
}

// run_coverage's arguments.
type mcpRunCoverageIn struct {
	Run       string `json:"run,omitempty"`
	Since     string `json:"since,omitempty"`
	GapsOnly  bool   `json:"gaps_only,omitempty"`
	Untrusted string `json:"untrusted,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

// One run's coverage row.
type mcpRunCoverageRowOut struct {
	RunId    string   `json:"run_id"`
	Log      string   `json:"log"`
	Harness  string   `json:"harness,omitempty"`
	Version  string   `json:"version,omitempty"`
	Sources  []string `json:"sources"`
	Gaps     []string `json:"gaps"`
	FirstSeq uint64   `json:"first_seq"`
	LastSeq  uint64   `json:"last_seq"`
	Ended    bool     `json:"ended"`
	Open     bool     `json:"open,omitempty"`
	Time     string   `json:"time"`
	Trust    string   `json:"trust"`
	Stub     bool     `json:"stub,omitempty"`
}

// run_coverage's data.
type mcpRunCoverageOut struct {
	Rows       []*mcpRunCoverageRowOut `json:"rows"`
	NextCursor string                  `json:"next_cursor,omitempty"`
	Stale      bool                    `json:"stale,omitempty"`
}

// approval_status's arguments.
type mcpApprovalStatusIn struct {
	Approval string `json:"approval,omitempty"`
	Run      string `json:"run,omitempty"`
	State    string `json:"state,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
}

// One approval's row: ids, states and counts, no hash and no signature.
type mcpApprovalRowOut struct {
	ApprovalId string   `json:"approval_id"`
	ActionId   string   `json:"action_id,omitempty"`
	RunId      string   `json:"run_id,omitempty"`
	State      string   `json:"state"`
	UsedCount  int      `json:"used_count"`
	Uses       uint32   `json:"uses"`
	Channels   []string `json:"channels"`
	Approvers  []string `json:"approver_member_ids"`
	NotAfter   string   `json:"not_after,omitempty"`
	// from this daemon's ledger, else from a log it reads
	Ledger bool `json:"ledger"`
}

// approval_status's data.
type mcpApprovalStatusOut struct {
	Rows       []*mcpApprovalRowOut `json:"rows"`
	NextCursor string               `json:"next_cursor,omitempty"`
}

// record_append's arguments (§16.5).
type mcpRecordAppendIn struct {
	// claim, handoff, ask, answer, check or note
	Kind     string   `json:"kind"`
	ActionId string   `json:"action_id,omitempty"`
	Targets  []string `json:"targets,omitempty"`
	Text     string   `json:"text,omitempty"`
	// RFC 3339; claim and ask only
	Expires string `json:"expires,omitempty"`
}

// record_append's data.
type mcpRecordAppendOut struct {
	EntryId string `json:"entry_id,omitempty"`
	Log     string `json:"log,omitempty"`
	// no log takes the entry now, so it waits in the spool and has no id yet
	Spooled bool `json:"spooled,omitempty"`
	// in a team network, the run's announcement a claim or handoff changed, and its version
	AnnouncementId string `json:"announcement_id,omitempty"`
	Version        uint64 `json:"version,omitempty"`
}

// The kind record_append names, 0 for a name that is none, which the guard refuses.
func mcpRecordAppendKind(name string) sidecar.RecordKind {
	kind, ok := sidecar.RecordKindNamed(name)
	if !ok {
		return sidecar.RecordKindUnspecified
	}
	return kind
}

// The record of a call, refusing a call that has none.
func mcpRecordFor(recordOf mcpRecordOfFunction, call *McpCall) (McpRecord, error) {
	if call == nil {
		return nil, errMcpNoCall
	}
	record, err := recordOf(call)
	if err != nil {
		return nil, mcpRecordError(err)
	}
	if record == nil {
		return nil, errMcpRecordUnavailable
	}
	return record, nil
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addRecordTools(catalog, mcpRecordOfNetwork)
	})
	registerMcpResources(func(resources *McpResources, server *McpServer) {
		addRecordResources(resources, mcpRecordOfNetwork)
	})
}

// Registers the four record tools on catalog, each reaching a call's record through recordOf.
func addRecordTools(catalog *McpCatalog, recordOf mcpRecordOfFunction) {
	byteLimit := catalog.settings.ResultByteCount

	AddTool(catalog, &McpToolSpec[mcpRecordQueryIn]{
		Name: "record_query",
		Tier: McpTierRead,
		Description: "Reads the record's entries as rows: log vault (the default), team, directory or a log's id, filtered by run, agent, " +
			"kind, action, entry and time. Rows another writer's tainted run wrote, and the directory's announcements, requests and " +
			"decisions, come back as stubs unless untrusted is include, which taints this run first. Raw capture returns its body " +
			"only when entry names it.",
		Access: func(call *McpCall, in *mcpRecordQueryIn) ([]McpAccess, error) {
			record, err := mcpRecordFor(recordOf, call)
			if err != nil {
				return nil, err
			}
			log, err := record.ResolveLog(in.Log)
			if err != nil {
				return nil, mcpRecordError(err)
			}
			return mcpRecordReadAccess(log), nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpRecordQueryIn, result *McpResult) (*mcpRecordQueryOut, error) {
		record, err := mcpRecordFor(recordOf, call)
		if err != nil {
			return nil, err
		}
		args := &sidecar.RecordQueryArgs{Log: in.Log, Agent: in.Agent, Archived: in.Archived, Cursor: in.Cursor}
		if args.RunId, err = mcpRecordId(in.Run); err != nil {
			return nil, err
		}
		if args.EntryId, err = mcpRecordId(in.Entry); err != nil {
			return nil, err
		}
		if args.ActionId, err = mcpRecordActionId(in.Action); err != nil {
			return nil, err
		}
		if args.Since, err = mcpRecordTime(in.Since); err != nil {
			return nil, err
		}
		if args.Until, err = mcpRecordTime(in.Until); err != nil {
			return nil, err
		}
		if args.Untrusted, err = mcpRecordInclude(in.Untrusted); err != nil {
			return nil, err
		}
		if in.Kind != "" {
			kind, ok := sidecar.RecordKindNamed(in.Kind)
			if !ok {
				return nil, errMcpRecordArgument
			}
			args.Kinds = []sidecar.RecordKind{kind}
		}
		args.Taint = func() error { return result.Untrusted(ctx) }
		page, err := record.Query(ctx, args)
		if err != nil {
			return nil, mcpRecordError(err)
		}
		result.SetSource("record:" + page.Log.Name)
		result.SetResource(McpRecordUri(page.Log.Name))
		return mcpRecordPageOut(result, page, byteLimit), nil
	})

	AddTool(catalog, &McpToolSpec[mcpRunCoverageIn]{
		Name: "run_coverage",
		Tier: McpTierRead,
		Description: "Reads each run's newest coverage in the logs this sidecar reads: its sources, its gaps, its first and last " +
			"entries and whether it ended; a run with no coverage entry shows open.",
		// the logs it reads are judged in the handler: each one §8 allows read on, and refused when none is
		Access: func(call *McpCall, in *mcpRunCoverageIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpRunCoverageIn, result *McpResult) (*mcpRunCoverageOut, error) {
		record, err := mcpRecordFor(recordOf, call)
		if err != nil {
			return nil, err
		}
		logs, err := mcpRecordAllowedLogs(record, catalog.clock, call)
		if err != nil {
			return nil, err
		}
		args := &sidecar.RecordCoverageArgs{Logs: logs, GapsOnly: in.GapsOnly, Cursor: in.Cursor}
		if args.RunId, err = mcpRecordId(in.Run); err != nil {
			return nil, err
		}
		if args.Since, err = mcpRecordTime(in.Since); err != nil {
			return nil, err
		}
		if args.Untrusted, err = mcpRecordInclude(in.Untrusted); err != nil {
			return nil, err
		}
		args.Taint = func() error { return result.Untrusted(ctx) }
		page, err := record.Coverage(ctx, args)
		if err != nil {
			return nil, mcpRecordError(err)
		}
		result.SetSource("record:coverage")
		out := &mcpRunCoverageOut{Rows: []*mcpRunCoverageRowOut{}, NextCursor: page.NextCursor, Stale: page.Stale}
		for _, row := range page.Rows {
			rowOut := &mcpRunCoverageRowOut{
				RunId:    mcpRecordHex(row.RunId.Bytes()),
				Log:      row.Log,
				Harness:  row.Harness,
				Version:  row.Version,
				Sources:  append([]string{}, row.Sources...),
				Gaps:     append([]string{}, row.Gaps...),
				FirstSeq: row.FirstSeq,
				LastSeq:  row.LastSeq,
				Ended:    row.Ended,
				Open:     row.Open,
				Time:     mcpRecordTimeText(row.TimeMillis),
				Trust:    string(row.Trust),
				Stub:     row.Stub,
			}
			if row.Trust != sidecar.RecordTrustOwn {
				result.Member()
			}
			if row.Trust == sidecar.RecordTrustUntrusted && !row.Stub {
				if rowOut.Harness != "" {
					rowOut.Harness = result.Fence(rowOut.Harness)
				}
				if rowOut.Version != "" {
					rowOut.Version = result.Fence(rowOut.Version)
				}
			}
			out.Rows = append(out.Rows, rowOut)
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpApprovalStatusIn]{
		Name: "approval_status",
		Tier: McpTierRead,
		Description: "Reads where this sidecar's approvals stand, and those in the logs it reads: pending, approved, denied, " +
			"cancelled, expired, spent or uncertain, with uses reserved of uses, each decision's channel and approver, and " +
			"not_after. Filter by approval, run or state.",
		Access: func(call *McpCall, in *mcpApprovalStatusIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpApprovalStatusIn, result *McpResult) (*mcpApprovalStatusOut, error) {
		record, err := mcpRecordFor(recordOf, call)
		if err != nil {
			return nil, err
		}
		// a log §8 does not let this sidecar read, or none at all yet, gives no approval rows; the ledger is this
		// daemon's own
		logs, err := mcpRecordAllowedLogs(record, catalog.clock, call)
		if err != nil && !errors.Is(err, errMcpNotAllowed) && !errors.Is(err, errMcpRecordLog) {
			return nil, err
		}
		args := &sidecar.RecordApprovalArgs{Logs: logs, LedgerOnly: len(logs) == 0, Cursor: in.Cursor}
		if args.ApprovalId, err = mcpRecordId(in.Approval); err != nil {
			return nil, err
		}
		if args.RunId, err = mcpRecordId(in.Run); err != nil {
			return nil, err
		}
		if in.Cursor != "" {
			if _, err := mcpRecordId(in.Cursor); err != nil {
				return nil, errMcpRecordCursor
			}
		}
		if in.State != "" {
			states := []sidecar.ApprovalStatusState{sidecar.ApprovalStatusPending, sidecar.ApprovalStatusApproved, sidecar.ApprovalStatusDenied,
				sidecar.ApprovalStatusCancelled, sidecar.ApprovalStatusExpired, sidecar.ApprovalStatusSpent, sidecar.ApprovalStatusUncertain}
			if !slices.Contains(states, sidecar.ApprovalStatusState(in.State)) {
				return nil, errMcpRecordState
			}
			args.State = sidecar.ApprovalStatusState(in.State)
		}
		page, err := record.Approvals(ctx, args)
		if err != nil {
			return nil, mcpRecordError(err)
		}
		result.SetSource("record:approvals")
		out := &mcpApprovalStatusOut{Rows: []*mcpApprovalRowOut{}, NextCursor: page.NextCursor}
		for _, row := range page.Rows {
			rowOut := &mcpApprovalRowOut{
				ApprovalId: mcpRecordHex(row.ApprovalId.Bytes()),
				ActionId:   mcpRecordHex(row.ActionId),
				RunId:      mcpRecordIdHex(row.RunId),
				State:      string(row.State),
				UsedCount:  row.UsedCount,
				Uses:       row.Uses,
				Channels:   []string{},
				Approvers:  []string{},
				Ledger:     row.Ledger,
			}
			if !row.NotAfter.IsZero() {
				rowOut.NotAfter = row.NotAfter.UTC().Format(mcpRecordTimeLayout)
			}
			for _, channel := range row.Channels {
				rowOut.Channels = append(rowOut.Channels, mcpChannelName(channel))
			}
			for _, approverId := range row.ApproverMemberIds {
				rowOut.Approvers = append(rowOut.Approvers, mcpRecordHex(approverId.Bytes()))
			}
			if !row.Ledger {
				result.Member()
			}
			out.Rows = append(out.Rows, rowOut)
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpRecordAppendIn]{
		Name: "record_append",
		Tier: McpTierWrite,
		Description: "Writes a coordination entry for this run: kind claim, handoff, ask, answer, check or note, with targets by " +
			"the record's grammar (paths, claim:<id>, member:<id>, agent:<label>, project:<label>, entry:<id>, action:<id>, " +
			"result:pass|fail|objection). A claim with one claim:<id> target and a past expires releases it. In a team " +
			"network a claim or handoff updates this run's announcement, and the others are directory entries.",
		Targets: func(call *McpCall, in *mcpRecordAppendIn) ([]McpTarget, error) {
			return []McpTarget{{Kind: McpTargetRecordAppend, RecordKind: mcpRecordAppendKind(in.Kind)}}, nil
		},
		Access: func(call *McpCall, in *mcpRecordAppendIn) ([]McpAccess, error) {
			record, err := mcpRecordFor(recordOf, call)
			if err != nil {
				return nil, err
			}
			log, deposit, err := record.AppendLog(mcpRecordAppendKind(in.Kind))
			if err != nil {
				return nil, mcpRecordError(err)
			}
			action := protocol.AclAction_ACL_ACTION_WRITE
			if deposit {
				action = protocol.AclAction_ACL_ACTION_DEPOSIT
			}
			return []McpAccess{{Action: action, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: log.LogId}}}, nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpRecordAppendIn, result *McpResult) (*mcpRecordAppendOut, error) {
		record, err := mcpRecordFor(recordOf, call)
		if err != nil {
			return nil, err
		}
		args := &sidecar.RecordAppendArgs{Kind: mcpRecordAppendKind(in.Kind), Targets: in.Targets, Text: in.Text}
		runId := call.RunId
		args.RunId = &runId
		if args.ActionId, err = mcpRecordActionId(in.ActionId); err != nil {
			return nil, err
		}
		expires, err := mcpRecordTime(in.Expires)
		if err != nil {
			return nil, err
		}
		if !expires.IsZero() {
			args.ExpiresMillis = expires.UnixMilli()
		}
		appended, err := record.Append(ctx, args)
		if err != nil {
			return nil, mcpRecordError(err)
		}
		result.SetSource("record:append")
		out := &mcpRecordAppendOut{Spooled: appended.Spooled, Version: appended.Version, AnnouncementId: mcpRecordIdHex(appended.AnnouncementId)}
		if !appended.Spooled {
			out.EntryId = mcpRecordHex(appended.EntryId.Bytes())
			out.Log = mcpRecordHex(appended.LogId.Bytes())
		}
		return out, nil
	})
}

// A resource read's record and log, with §8's allow of read on it for this sidecar at clock's now.
func mcpRecordResourceLog(recordOf mcpRecordOfFunction, clock sidecar.Clock, call *McpCall, name string) (McpRecord, *sidecar.RecordProjectionLog, error) {
	record, err := mcpRecordFor(recordOf, call)
	if err != nil {
		return nil, nil, err
	}
	log, err := record.ResolveLog(name)
	if err != nil {
		return nil, nil, mcpRecordError(err)
	}
	network, ok := mcpToolNetworkOf(call)
	if !ok {
		return nil, nil, errMcpNoToolNetwork
	}
	for _, access := range mcpRecordReadAccess(log) {
		check, installed := network.Allow(access.Action, access.Resource, clock.Now())
		if !installed {
			return nil, nil, errMcpNoPolicy
		}
		if !check.Allowed {
			return nil, nil, errMcpNotAllowed
		}
	}
	return record, log, nil
}

// One read of a log's rows for a resource: untrusted text only where the call's run is tainted already, so a read
// never taints.
func mcpRecordResourceRead(ctx context.Context, recordOf mcpRecordOfFunction, clock sidecar.Clock, call *McpCall, name string, entryId *sidecar.Id, result *McpResult) (any, error) {
	record, log, err := mcpRecordResourceLog(recordOf, clock, call, name)
	if err != nil {
		return nil, err
	}
	args := &sidecar.RecordQueryArgs{Log: name, EntryId: entryId, Untrusted: call.Tainted()}
	args.Taint = func() error { return result.Untrusted(ctx) }
	page, err := record.Query(ctx, args)
	if err != nil {
		return nil, mcpRecordError(err)
	}
	result.SetSource("record:" + log.Name)
	out := &mcpRecordQueryOut{Rows: []*mcpRecordRowOut{}, NextCursor: page.NextCursor, Stale: page.Stale, UntrustedWithheld: page.WithheldCount}
	member := false
	for _, row := range page.Rows {
		rowOut, lowers := mcpRecordRow(result, row)
		out.Rows = append(out.Rows, rowOut)
		member = member || lowers
	}
	if member {
		result.Member()
	}
	return out, nil
}

// Registers ur://record/{log} and ur://record/{log}/{entry} on resources.
func addRecordResources(resources *McpResources, recordOf mcpRecordOfFunction) {
	resources.Add(&McpResourceSpec{
		UriTemplate: "ur://record/{log}",
		Name:        "record",
		Description: "The first page of a log's rows, as record_query reads them: vault, team, directory or a log's id; an untrusted row is a stub unless this run is tainted already.",
		Read: func(ctx context.Context, call *McpCall, uri string, variables map[string]string, result *McpResult) (any, error) {
			return mcpRecordResourceRead(ctx, recordOf, resources.server.clock, call, variables["log"], nil, result)
		},
		Subscribe: func(ctx context.Context, session *McpSession, uri string, variables map[string]string) error {
			return mcpRecordSubscribe(resources, recordOf, session, variables["log"])
		},
	})
	resources.Add(&McpResourceSpec{
		UriTemplate: "ur://record/{log}/{entry}",
		Name:        "record_entry",
		Description: "One entry's row, its body included as record_query with entry reads it: where a result too large to return links.",
		Read: func(ctx context.Context, call *McpCall, uri string, variables map[string]string, result *McpResult) (any, error) {
			entryId, err := mcpRecordId(variables["entry"])
			if err != nil || entryId == nil {
				return nil, errMcpResourceNotFound()
			}
			return mcpRecordResourceRead(ctx, recordOf, resources.server.clock, call, variables["log"], entryId, result)
		},
	})
}

// A subscription of a log's resource, judged at once: the log resolves for this sidecar and §8 allows read on it.
func mcpRecordSubscribe(resources *McpResources, recordOf mcpRecordOfFunction, session *McpSession, name string) error {
	networkId, network, err := resources.server.sessionNetwork(session)
	if err != nil {
		return err
	}
	call := &McpCall{Session: session, NetworkId: networkId, Network: network}
	_, _, err = mcpRecordResourceLog(recordOf, resources.server.clock, call, name)
	return err
}

// Sends each sync of a log the projection's record reads as its resources' update, under every name it goes by,
// until the returned function stops it. The directory's copy syncs apart, and sends nothing here.
func (self *McpResources) WatchRecord(projection *sidecar.RecordProjection) func() {
	return projection.Record().WatchSyncs(func(logId sidecar.Id) {
		for _, name := range projection.LogNames(logId) {
			self.Notify(McpRecordUri(name))
		}
	})
}
