//go:build !ios_extension && !sidecar_http

// The record tools in process (DESIGN-COMPUTE §7.5's record_query and record_append row, CO-19; DESIGN §16.5; RECORD.md
// section 5.6; R-HARN-8, IC-12, D-MCP-16, D-MCP-17, I-7, I-9; HARN-M11-06): record_query at R and record_append at W,
// as MCP's tools of the names (mcp/tools_record.go), over the same RecordProjection, which holds the rules
// (record_projection.go's header), on every leg the Harness runs. record_query lets an agent review other agents' runs
// within its reach (CO-19):
//
//	allow      §8's local read on the log a query reads, and write, or deposit where this sidecar deposits, on the log
//	           record_append lands in; record_append's kind goes to harnessGuard, whose record row refuses every kind
//	           but claim, handoff, ask, answer, check and note (§16.6)
//	stubs      a row another writer's tainted run wrote, a record entry a tagged sidecar other than the member's own
//	           enclave wrote (IC-12), and the directory's announcements come back as stubs unless untrusted is include,
//	           which taints the run, write-ahead, before any untrusted text is read into a row (D-MCP-16); a failed
//	           taint fails the call, and a stub leaves the run as it was; a raw kind's body comes back only when its
//	           entry is named
//	fence      an untrusted row's body is fenced string by string between §16.6's markers, as MCP's is
//	trust      own until a row is another member's or a stub of an untrusted one, member then, and untrusted once an
//	           untrusted row's text is in it
//	size       a page stops before the row that would take it past ResultByteCount; a first row past it alone is refused,
//	           since the ur://record resource MCP links it to is not the Harness's to read
//	hits       a search hit's id opens the entry, or the run card's run, its run's search named (harness_tool_search.go)
//
// run_coverage and approval_status are MCP's; an agent waits on its own approvals through approval_pending.
// Errors are constant text and never name a target, a path or any other argument.

package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The tools' names, MCP's.
const (
	HarnessToolRecordQuery  = "record_query"
	HarnessToolRecordAppend = "record_append"
)

// The tools' descriptions, MCP's text.
const (
	harnessRecordQueryDescription = "Reads the record's entries as rows: log vault (the default), team, directory or a log's id, filtered by run, agent, " +
		"kind, action, entry and time, or the entry or run a search hit names by its hit id. Rows another writer's tainted run " +
		"wrote, and the directory's announcements, requests and decisions, come back as stubs unless untrusted is include, which " +
		"taints this run first. Raw capture returns its body only when entry names it."
	harnessRecordAppendDescription = "Writes a coordination entry for this run: kind claim, handoff, ask, answer, check or note, with targets by " +
		"the record's grammar (paths, claim:<id>, member:<id>, agent:<label>, project:<label>, entry:<id>, action:<id>, " +
		"result:pass|fail|objection). A claim with one claim:<id> target and a past expires releases it. In a team " +
		"network a claim or handoff updates this run's announcement, and the others are directory entries."
)

// The tools' argument schemas, MCP's arguments but network.
var (
	harnessRecordQuerySchema = []byte(`{"type":"object","properties":{` +
		`"log":{"type":"string","description":"vault (the default), team, directory, or a log's id."},` +
		`"run":{"type":"string"},"agent":{"type":"string","description":"An agent's id or label."},` +
		`"kind":{"type":"string","description":"A record kind's name."},"action":{"type":"string"},"entry":{"type":"string"},` +
		`"since":{"type":"string","description":"RFC 3339."},"until":{"type":"string","description":"RFC 3339."},` +
		`"untrusted":{"type":"string","enum":["withhold","include"]},"archived":{"type":"boolean"},` +
		`"cursor":{"type":"string"},"hit":{"type":"string","description":"A search hit's id, in place of log, run, entry and the filters."}},` +
		`"additionalProperties":false}`)
	harnessRecordAppendSchema = []byte(`{"type":"object","properties":{` +
		`"kind":{"type":"string","enum":["claim","handoff","ask","answer","check","note"]},` +
		`"action_id":{"type":"string"},"targets":{"type":"array","items":{"type":"string"}},` +
		`"text":{"type":"string"},"expires":{"type":"string","description":"RFC 3339; claim and ask only."}},` +
		`"required":["kind"],"additionalProperties":false}`)
)

// A row's time, as every record tool writes one: RFC 3339 in UTC with milliseconds.
const harnessRecordTimeLayout = "2006-01-02T15:04:05.000Z"

// untrusted's values, as §16.10 names them.
const (
	harnessRecordUntrustedWithhold = "withhold"
	harnessRecordUntrustedInclude  = "include"
)

// The prefix of a run card's registered name, run/ || run_id in lowercase hex (§11.14's key row).
const harnessRecordRunCardPrefix = "run/"

// The tools' refusals, each constant, MCP's meaning.
var (
	errHarnessRecordUnavailable = errors.New("this sidecar holds no record for the network yet")
	errHarnessRecordLog         = errors.New("this sidecar does not read that log: name vault, team, directory or the id of a log it reads")
	errHarnessRecordCursor      = errors.New("the cursor is not one this tool gave for that log")
	errHarnessRecordArgument    = errors.New("an id is 32 lowercase hex (64 for an action), a time RFC 3339, kind a record kind's name and untrusted withhold or include")
	errHarnessRecordTargets     = errors.New("the targets do not fit the kind's grammar (RECORD.md section 6.4), or the text or expires does not fit the kind")
	errHarnessRecordRoute       = errors.New("in a team network a claim or a handoff changes the calling run's announcement, which this device cannot file for the run now")
	errHarnessRecordClaimsOff   = errors.New("claims is off for this run's project, so it announces nothing and takes no claim or handoff")
	errHarnessRecordClaimsFull  = errors.New("the run's announcement holds its four claims: release one with a claim:<id> target and a past expires first")
	errHarnessRecordKind        = errors.New("record_append takes claim, handoff, ask, answer, check and note only")
	errHarnessRecordLocked      = errors.New("the sidecar's store is locked")
)

// Registers the two tools.
func init() {
	registerHarnessDesignTool(HarnessToolRecordQuery, func(harness *Harness) *harnessDesignTool {
		return &harnessDesignTool{harness: harness, name: HarnessToolRecordQuery, description: harnessRecordQueryDescription,
			schema: harnessRecordQuerySchema, tier: HarnessToolTierRead, execute: harnessRecordQueryCall}
	})
	registerHarnessDesignTool(HarnessToolRecordAppend, func(harness *Harness) *harnessDesignTool {
		return &harnessDesignTool{harness: harness, name: HarnessToolRecordAppend, description: harnessRecordAppendDescription,
			schema: harnessRecordAppendSchema, tier: HarnessToolTierWrite, execute: harnessRecordAppendCall}
	})
}

// A record error as the tools answer it, by constant text.
func harnessRecordError(err error) error {
	switch {
	case errors.Is(err, ErrSidecarStoreLocked):
		return errHarnessRecordLocked
	case errors.Is(err, ErrRecordProjectionLog):
		return errHarnessRecordLog
	case errors.Is(err, ErrRecordProjectionCursor):
		return errHarnessRecordCursor
	case errors.Is(err, ErrRecordAppendKind):
		return errHarnessRecordKind
	case errors.Is(err, ErrRecordTargetsInvalid), errors.Is(err, ErrRecordDraftInvalid):
		return errHarnessRecordTargets
	case errors.Is(err, ErrRecordRouteAnnouncement), errors.Is(err, ErrDirectoryRunUnknown):
		return errHarnessRecordRoute
	case errors.Is(err, ErrDirectoryRunsClaimsOff):
		return errHarnessRecordClaimsOff
	case errors.Is(err, ErrDirectoryRunClaimsFull):
		return errHarnessRecordClaimsFull
	case errors.Is(err, ErrRecordProjectionNoTaint), errors.Is(err, errHarnessDesignTaint):
		return errHarnessDesignTaint
	case errors.Is(err, errHarnessDesignNoRun):
		return err
	}
	return errHarnessRecordUnavailable
}

// The network's record, refused with constant text where it holds none.
func harnessRecordOf(network harnessDesignNetwork) (harnessRecord, error) {
	record, err := network.Record()
	if err != nil {
		return nil, harnessRecordError(err)
	}
	if record == nil {
		return nil, errHarnessRecordUnavailable
	}
	return record, nil
}

// A time argument, zero for "".
func harnessRecordTime(text string) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, errHarnessRecordArgument
	}
	return parsed, nil
}

// An id argument in 32 lowercase hex, nil for "".
func harnessRecordId(text string) (*Id, error) {
	if text == "" {
		return nil, nil
	}
	id, err := ParseId(text)
	if err != nil || len(text) != 32 || hex.EncodeToString(id.Bytes()) != text {
		return nil, errHarnessRecordArgument
	}
	return &id, nil
}

// An action id argument in 64 lowercase hex, nil for "".
func harnessRecordActionId(text string) ([]byte, error) {
	if text == "" {
		return nil, nil
	}
	actionId, err := hex.DecodeString(text)
	if err != nil || len(actionId) != 32 || hex.EncodeToString(actionId) != text {
		return nil, errHarnessRecordArgument
	}
	return actionId, nil
}

// Whether untrusted asks for untrusted text: include, or withhold and "" for not.
func harnessRecordInclude(untrusted string) (bool, error) {
	switch untrusted {
	case "", harnessRecordUntrustedWithhold:
		return false, nil
	case harnessRecordUntrustedInclude:
		return true, nil
	}
	return false, errHarnessRecordArgument
}

// An id as hex, "" for nil.
func harnessRecordIdHex(id *Id) string {
	if id == nil {
		return ""
	}
	return hex.EncodeToString(id.Bytes())
}

// A time in milliseconds as a row writes it.
func harnessRecordTimeText(millis int64) string {
	return time.UnixMilli(millis).UTC().Format(harnessRecordTimeLayout)
}

// Each string of value fenced, through maps and lists, for an untrusted row's body.
func harnessRecordFence(result *harnessDesignResult, value any) any {
	switch typed := value.(type) {
	case string:
		return result.Fence(typed)
	case map[string]any:
		fenced := map[string]any{}
		for key, item := range typed {
			fenced[key] = harnessRecordFence(result, item)
		}
		return fenced
	case []any:
		fenced := make([]any, 0, len(typed))
		for _, item := range typed {
			fenced = append(fenced, harnessRecordFence(result, item))
		}
		return fenced
	}
	return value
}

// record_query's arguments, MCP's.
type harnessRecordQueryIn struct {
	Log       string `json:"log,omitempty"`
	Run       string `json:"run,omitempty"`
	Agent     string `json:"agent,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Action    string `json:"action,omitempty"`
	Entry     string `json:"entry,omitempty"`
	Since     string `json:"since,omitempty"`
	Until     string `json:"until,omitempty"`
	Untrusted string `json:"untrusted,omitempty"`
	Archived  bool   `json:"archived,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
	Hit       string `json:"hit,omitempty"`
}

// One row, MCP's.
type harnessRecordRowOut struct {
	EntryId    string         `json:"entry_id"`
	Log        string         `json:"log"`
	Kind       string         `json:"kind"`
	Time       string         `json:"time"`
	Writer     string         `json:"writer"`
	AgentId    string         `json:"agent_id,omitempty"`
	AgentLabel string         `json:"agent_label,omitempty"`
	RunId      string         `json:"run_id,omitempty"`
	ActionId   string         `json:"action_id,omitempty"`
	Source     string         `json:"source"`
	Tainted    bool           `json:"tainted"`
	Trust      string         `json:"trust"`
	State      string         `json:"state"`
	Body       map[string]any `json:"body,omitempty"`
	Stub       bool           `json:"stub,omitempty"`
	Withheld   string         `json:"withheld,omitempty"`
}

// record_query's data, MCP's.
type harnessRecordQueryOut struct {
	Rows              []*harnessRecordRowOut `json:"rows"`
	NextCursor        string                 `json:"next_cursor,omitempty"`
	Stale             bool                   `json:"stale,omitempty"`
	UntrustedWithheld int                    `json:"untrusted_withheld"`
}

// The out of row, its body fenced where its text is untrusted; whether it lowers the result's trust to member.
func harnessRecordRow(result *harnessDesignResult, row *RecordQueryRow) (*harnessRecordRowOut, bool) {
	out := &harnessRecordRowOut{
		EntryId:    hex.EncodeToString(row.EntryId.Bytes()),
		Log:        row.Log,
		Kind:       row.Kind.String(),
		Time:       harnessRecordTimeText(row.TimeMillis),
		Writer:     hex.EncodeToString(row.WriterSidecarId.Bytes()),
		AgentId:    harnessRecordIdHex(row.AgentId),
		AgentLabel: row.AgentLabel,
		RunId:      harnessRecordIdHex(row.RunId),
		ActionId:   hex.EncodeToString(row.ActionId),
		Source:     row.Source.String(),
		Tainted:    row.Tainted,
		Trust:      string(row.Trust),
		State:      string(row.State),
		Stub:       row.Stub,
		Withheld:   string(row.StubReason),
	}
	if !row.Stub && row.Fields != nil {
		out.Body = row.Fields
		if row.Trust == RecordTrustUntrusted {
			out.Body, _ = harnessRecordFence(result, row.Fields).(map[string]any)
		}
	}
	return out, row.Trust != RecordTrustOwn
}

// A page as its out, cut before the row that would take it past byteLimit; a first row past it alone is refused.
func harnessRecordPageOut(result *harnessDesignResult, page *RecordQueryPage, byteLimit int) (*harnessRecordQueryOut, error) {
	out := &harnessRecordQueryOut{Rows: []*harnessRecordRowOut{}, NextCursor: page.NextCursor, Stale: page.Stale,
		UntrustedWithheld: page.WithheldCount}
	// the envelope and the page's own keys, a cursor as long as any a row gives
	cursor := page.NextCursor
	for _, row := range page.Rows {
		if len(cursor) < len(row.Cursor) {
			cursor = row.Cursor
		}
	}
	overhead, _ := json.Marshal(&harnessDesignEnvelope{Trust: harnessDesignTrustUntrusted, Source: "record:" + page.Log.Name,
		MeteredBytes: 1 << 62, MarkerBroken: true, Data: json.RawMessage(`{"rows":[],"next_cursor":"` + cursor +
			`","stale":true,"untrusted_withheld":0}`)})
	byteCount := len(overhead) + len(page.Rows)
	member := false
	for i, row := range page.Rows {
		rowOut, lowers := harnessRecordRow(result, row)
		encoded, err := json.Marshal(rowOut)
		if err != nil {
			continue
		}
		if byteLimit < byteCount+len(encoded) {
			if len(out.Rows) == 0 {
				return nil, errHarnessDesignTooLarge
			}
			out.NextCursor = page.Rows[i-1].Cursor
			break
		}
		byteCount += len(encoded)
		out.Rows = append(out.Rows, rowOut)
		member = member || lowers
	}
	if member {
		result.Member()
	}
	return out, nil
}

// What record_query reads for a hit: the hit's log by its id, and the run of a run card's hit or the copy of an entry's.
type harnessRecordHit struct {
	log   string
	runId *Id
	copy  *RecordQueryCopy
}

// record_query's by-hit lookup (§16.10's open row): a record entry's hit reads the entry with that copy in its stream,
// a run card's the card's run, each in the log the hit is in. A hit stands alone but for untrusted and cursor.
func harnessRecordQueryHit(network harnessDesignNetwork, call *HarnessCall, in *harnessRecordQueryIn) (*harnessRecordHit, error) {
	if in.Log != "" || in.Run != "" || in.Agent != "" || in.Kind != "" || in.Action != "" || in.Entry != "" || in.Since != "" ||
		in.Until != "" || in.Archived {
		return nil, errHarnessHitAlone
	}
	ref, err := harnessHitOfKind(network, call, in.Hit, IndexDocRecord, IndexDocDerived)
	if err != nil {
		return nil, err
	}
	hit := &harnessRecordHit{log: hex.EncodeToString(ref.RepoId.Bytes())}
	if ref.DocKind == int(IndexDocRecord) {
		hit.copy = &RecordQueryCopy{RefId: ref.RefId, Path: ref.Path}
		return hit, nil
	}
	name, ok := strings.CutPrefix(ref.Path, harnessRecordRunCardPrefix)
	if !ok {
		// the directory's announcements open by directory_list
		return nil, errHarnessHitKind
	}
	runId, err := harnessRecordId(name)
	if err != nil || runId == nil {
		return nil, errHarnessHitKind
	}
	hit.runId = runId
	return hit, nil
}

// record_query: one page of the rows the arguments keep, untrusted rows as stubs unless include, which taints first.
func harnessRecordQueryCall(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessToolResult, error) {
	in := &harnessRecordQueryIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, err
	}
	record, err := harnessRecordOf(network)
	if err != nil {
		return nil, err
	}
	query := &RecordQueryArgs{Log: in.Log, Agent: in.Agent, Archived: in.Archived, Cursor: in.Cursor}
	var hit *harnessRecordHit
	if in.Hit != "" {
		if hit, err = harnessRecordQueryHit(network, call, in); err != nil {
			return nil, err
		}
		query.Log, query.Copy = hit.log, hit.copy
	}
	log, err := record.ResolveLog(query.Log)
	if err != nil {
		return nil, harnessRecordError(err)
	}
	if err := harnessDesignAllow(network, tool.now(), harnessDesignRepoAccess(log.LogId, protocol.AclAction_ACL_ACTION_READ)); err != nil {
		return nil, err
	}
	if query.RunId, err = harnessRecordId(in.Run); err != nil {
		return nil, err
	}
	if query.EntryId, err = harnessRecordId(in.Entry); err != nil {
		return nil, err
	}
	if query.ActionId, err = harnessRecordActionId(in.Action); err != nil {
		return nil, err
	}
	if query.Since, err = harnessRecordTime(in.Since); err != nil {
		return nil, err
	}
	if query.Until, err = harnessRecordTime(in.Until); err != nil {
		return nil, err
	}
	if query.Untrusted, err = harnessRecordInclude(in.Untrusted); err != nil {
		return nil, err
	}
	if in.Kind != "" {
		kind, ok := RecordKindNamed(in.Kind)
		if !ok {
			return nil, errHarnessRecordArgument
		}
		query.Kinds = []RecordKind{kind}
	}
	if hit != nil && hit.runId != nil {
		// a run card's hit opens its run's entries in the card's log
		query.RunId = hit.runId
	}
	result := newHarnessDesignResult(call)
	query.Taint = func() error { return result.Untrusted(ctx) }
	page, err := record.Query(ctx, query)
	if err != nil {
		return nil, harnessRecordError(err)
	}
	result.SetSource("record:" + page.Log.Name)
	out, err := harnessRecordPageOut(result, page, network.Mcp().ResultByteCount)
	if err != nil {
		return nil, err
	}
	return result.toolResult(network, out, nil)
}

// record_append's arguments and data, MCP's.
type harnessRecordAppendIn struct {
	Kind     string   `json:"kind"`
	ActionId string   `json:"action_id,omitempty"`
	Targets  []string `json:"targets,omitempty"`
	Text     string   `json:"text,omitempty"`
	Expires  string   `json:"expires,omitempty"`
}

type harnessRecordAppendOut struct {
	EntryId        string `json:"entry_id,omitempty"`
	Log            string `json:"log,omitempty"`
	Spooled        bool   `json:"spooled,omitempty"`
	AnnouncementId string `json:"announcement_id,omitempty"`
	Version        uint64 `json:"version,omitempty"`
}

// The kind record_append names, unspecified for a name that is none, which the guard refuses.
func harnessRecordAppendKind(name string) RecordKind {
	kind, ok := RecordKindNamed(name)
	if !ok {
		return RecordKindUnspecified
	}
	return kind
}

// record_append: a coordination entry for the call's run, its kind held to the guard's record row.
func harnessRecordAppendCall(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessToolResult, error) {
	in := &harnessRecordAppendIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, err
	}
	kind := harnessRecordAppendKind(in.Kind)
	if err := harnessGuard([]harnessGuardTarget{{Kind: harnessTargetRecordAppend, RecordKind: kind}}); err != nil {
		return nil, err
	}
	record, err := harnessRecordOf(network)
	if err != nil {
		return nil, err
	}
	log, deposit, err := record.AppendLog(kind)
	if err != nil {
		return nil, harnessRecordError(err)
	}
	action := protocol.AclAction_ACL_ACTION_WRITE
	if deposit {
		action = protocol.AclAction_ACL_ACTION_DEPOSIT
	}
	if err := harnessDesignAllow(network, tool.now(), harnessDesignRepoAccess(log.LogId, action)); err != nil {
		return nil, err
	}
	appendArgs := &RecordAppendArgs{Kind: kind, Targets: in.Targets, Text: in.Text}
	runId := call.Run().Id()
	appendArgs.RunId = &runId
	if appendArgs.ActionId, err = harnessRecordActionId(in.ActionId); err != nil {
		return nil, err
	}
	expires, err := harnessRecordTime(in.Expires)
	if err != nil {
		return nil, err
	}
	if !expires.IsZero() {
		appendArgs.ExpiresMillis = expires.UnixMilli()
	}
	appended, err := record.Append(ctx, appendArgs)
	if err != nil {
		return nil, harnessRecordError(err)
	}
	result := newHarnessDesignResult(call)
	result.SetSource("record:append")
	out := &harnessRecordAppendOut{Spooled: appended.Spooled, Version: appended.Version, AnnouncementId: harnessRecordIdHex(appended.AnnouncementId)}
	if !appended.Spooled {
		out.EntryId = hex.EncodeToString(appended.EntryId.Bytes())
		out.Log = hex.EncodeToString(appended.LogId.Bytes())
	}
	return result.toolResult(network, out, nil)
}
