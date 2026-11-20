//go:build !ios_extension

// Run cost (RECORD-M6-08; RECORD.md section 13.1; R-MCP-7, I-20): what a run's model calls came to, as its harness
// reported them. A `cost` entry holds a run's whole totals by model, written with each coverage entry and superseded
// as that is; `ur record cost` reads one log's and sums them.
//
//	sources   model_call entries alone, tokens and the amounts a harness reported; no price table ships, since a
//	          price this sidecar computed would be a claim it cannot back, so a self-hosted model's amount stays 0
//	complete  false for every model of a run whose coverage holds a gap that may hide calls
//	report    per run only the newest cost entry by seq in its writer's chain, since a re-opened run writes a newer
//	          entry of whole-run totals; grouped by project, client, model or month: a --map file of project,client
//	          lines turns a project into its client under project, as RECORD.md section 13.1's synopsis has it, and
//	          client, §7.9's grouping, needs one, a run whose project it names no client for showing as
//	          `(no client)`; no grouping by member and no order by amount, so the report ranks no one (owner
//	          decision 302); on a team log a group fewer than GroupMemberCount members wrote shows as `other`, which
//	          shapes the tool and is no privacy control, admins holding the entries regardless
//
// Not a bill: §20 owns billing.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var ErrRecordCostInvalid = errors.New("record: cost query invalid")

// A report by client with no --map, or one naming no project: there is no client to group by.
var ErrRecordCostNoClientMap = fmt.Errorf("%w: --by client needs --map, a file of project,client lines", ErrRecordCostInvalid)

// The group a report folds small groups and uncapped models into, the one a run with no project falls in, and the
// one a run whose project the map names no client for falls in by client.
const (
	RecordCostGroupOther     = "other"
	RecordCostGroupNoProject = "(no project)"
	RecordCostGroupNoClient  = "(no client)"
)

// How `ur record cost` groups.
type RecordCostBy string

const (
	// One row, the log's total.
	RecordCostByNone    RecordCostBy = ""
	RecordCostByProject RecordCostBy = "project"
	// The client --map names for each run's project; refused without a map (ErrRecordCostNoClientMap).
	RecordCostByClient RecordCostBy = "client"
	RecordCostByModel  RecordCostBy = "model"
	RecordCostByMonth  RecordCostBy = "month"
)

// A report's output format.
type RecordCostFormat string

const (
	RecordCostFormatText  RecordCostFormat = "text"
	RecordCostFormatCsv   RecordCostFormat = "csv"
	RecordCostFormatJsonl RecordCostFormat = "jsonl"
)

// The cost body's cap and the report's bounds.
type RecordCostSettings struct {
	// RunCostBody.usage's entries, by model: 16 (RECORD.md section 13.1). Models past it fold into one unnamed entry.
	UsageModelCount int
	// A model name's bytes, ModelCallBody's 128 B.
	ModelByteCount int
	// On a team log, a group fewer members than this wrote shows as `other`: 5 (QD-019).
	GroupMemberCount int
	// A --map file's bytes and lines.
	MapByteCount int
	MapLineCount int
}

// RECORD.md section 13.1's cap and QD-019's group size.
func DefaultRecordCostSettings() *RecordCostSettings {
	return &RecordCostSettings{
		UsageModelCount:  16,
		ModelByteCount:   128,
		GroupMemberCount: 5,
		MapByteCount:     1024 * 1024,
		MapLineCount:     16384,
	}
}

// The gaps that may hide a model call: capture was off, failed or lost for a stretch. A cut field, an oversize body,
// a redaction and a missing tool id lose part of an entry and no call.
var recordCostHidingGaps = []string{
	RecordCoverageGapHookFailure,
	RecordCoverageGapMissedEvent,
	RecordCoverageGapConfigChanged,
	RecordCoverageGapDowntime,
	RecordCoverageGapNoVault,
	RecordCoverageGapRunFileMissing,
	RecordCoverageGapSpoolDrop,
}

// One model's totals in a run.
type RecordRunCostUsage struct {
	Model            string `json:"model"`
	InputTokens      uint64 `json:"input_tokens"`
	OutputTokens     uint64 `json:"output_tokens"`
	CacheReadTokens  uint64 `json:"cache_read_tokens"`
	CacheWriteTokens uint64 `json:"cache_write_tokens"`
	Calls            uint64 `json:"calls"`
	ReportedMicroUsd uint64 `json:"reported_micro_usd"`
}

// A run's totals as its model calls arrive, in a form a run file keeps across a restart. Its zero value holds
// nothing. Not safe for concurrent use: the run's lock orders its calls.
type RecordRunCost struct {
	// By model, in first-call order.
	Usage []*RecordRunCostUsage `json:"usage,omitempty"`
	// The sum of the run's tool results' metered_bytes (§16.6).
	MeteredBytes uint64 `json:"metered_bytes,omitempty"`
}

// A sum that stops at the type's top, never wrapping.
func recordCostAdd(a uint64, b uint64) uint64 {
	if sum := a + b; a <= sum {
		return sum
	}
	return ^uint64(0)
}

// Adds one model_call's tokens and reported amount under its model. A model past UsageModelCount's last named one
// goes to the unnamed entry, so the body holds its cap and no call is left out of the totals.
func (self *RecordRunCost) AddCall(call *protocol.ModelCallBody, settings *RecordCostSettings) {
	if call == nil {
		return
	}
	if settings == nil {
		settings = DefaultRecordCostSettings()
	}
	model := call.GetModel()
	if settings.ModelByteCount < len(model) {
		model = recordCostCut(model, settings.ModelByteCount)
	}
	index := slices.IndexFunc(self.Usage, func(usage *RecordRunCostUsage) bool { return usage.Model == model })
	if index < 0 && model != "" && max(settings.UsageModelCount, 1)-1 <= self.named() {
		// the cap's last entry is the unnamed one's
		model = ""
		index = slices.IndexFunc(self.Usage, func(usage *RecordRunCostUsage) bool { return usage.Model == "" })
	}
	if index < 0 {
		self.Usage = append(self.Usage, &RecordRunCostUsage{Model: model})
		index = len(self.Usage) - 1
	}
	usage := self.Usage[index]
	usage.InputTokens = recordCostAdd(usage.InputTokens, call.GetInputTokens())
	usage.OutputTokens = recordCostAdd(usage.OutputTokens, call.GetOutputTokens())
	usage.CacheReadTokens = recordCostAdd(usage.CacheReadTokens, call.GetCacheReadTokens())
	usage.CacheWriteTokens = recordCostAdd(usage.CacheWriteTokens, call.GetCacheWriteTokens())
	usage.Calls = recordCostAdd(usage.Calls, 1)
	usage.ReportedMicroUsd = recordCostAdd(usage.ReportedMicroUsd, call.GetReportedMicroUsd())
}

// How many named models the run holds.
func (self *RecordRunCost) named() int {
	count := 0
	for _, usage := range self.Usage {
		if usage.Model != "" {
			count += 1
		}
	}
	return count
}

// Adds a tool result's metered bytes.
func (self *RecordRunCost) AddMeteredBytes(byteCount uint64) {
	self.MeteredBytes = recordCostAdd(self.MeteredBytes, byteCount)
}

// value cut to at most byteCount bytes on a rune boundary.
func recordCostCut(value string, byteCount int) string {
	if len(value) <= byteCount {
		return value
	}
	cut := max(byteCount, 0)
	for 0 < cut && !utf8.RuneStart(value[cut]) {
		cut -= 1
	}
	return value[:cut]
}

// Whether a coverage's gaps may hide a model call. A gap string this build cannot parse may.
func RecordCostGapsHideCalls(gaps []string) bool {
	for _, gap := range gaps {
		code, _, ok := RecordCoverageGapParse(gap)
		if !ok || slices.Contains(recordCostHidingGaps, code) {
			return true
		}
	}
	return false
}

// The run's cost entry body beside a coverage of gaps, models ascending with the unnamed entry last, and false for
// a run that reported no model call, which has no cost entry (its coverage says so by naming no telemetry source).
func (self *RecordRunCost) Body(gaps []string) (*protocol.RunCostBody, bool) {
	if len(self.Usage) == 0 {
		return nil, false
	}
	complete := !RecordCostGapsHideCalls(gaps)
	usages := slices.Clone(self.Usage)
	slices.SortStableFunc(usages, func(a *RecordRunCostUsage, b *RecordRunCostUsage) int {
		if (a.Model == "") != (b.Model == "") {
			if a.Model == "" {
				return 1
			}
			return -1
		}
		return strings.Compare(a.Model, b.Model)
	})
	body := &protocol.RunCostBody{MeteredBytes: self.MeteredBytes}
	for _, usage := range usages {
		body.Usage = append(body.Usage, &protocol.ModelUsage{
			Model:            usage.Model,
			InputTokens:      usage.InputTokens,
			OutputTokens:     usage.OutputTokens,
			CacheReadTokens:  usage.CacheReadTokens,
			CacheWriteTokens: usage.CacheWriteTokens,
			Calls:            usage.Calls,
			ReportedMicroUsd: usage.ReportedMicroUsd,
			Complete:         complete,
		})
	}
	return body, true
}

// The draft of a run's cost entry: source hook, as its model calls are (RECORD.md section 13.1).
func RecordRunCostDraft(runId Id, body *protocol.RunCostBody) *RecordDraft {
	return &RecordDraft{
		Kind:   RecordKindCost,
		Source: RecordSourceHook,
		RunId:  &runId,
		Body:   body,
	}
}

// One cost entry as a reader opened it.
type RecordCostEntry struct {
	RunId           Id
	WriterSidecarId Id
	// The entry's place in its writer's chain in the log read.
	Seq        uint64
	TimeMillis int64
	// The writer's member, or a tagged sidecar's sponsor; nil where the state names none.
	MemberId *Id
	// The run's project, from its context entry in the same log; empty for none.
	Project string
	Body    *protocol.RunCostBody
}

// What `ur record cost` asks.
type RecordCostQuery struct {
	// Entries at or after, and before; 0 for no bound.
	SinceMillis int64
	UntilMillis int64
	By          RecordCostBy
	// --map's project to client; nil for none. With it, by project groups a mapped project by its client; by client
	// needs it.
	Clients map[string]string
	// The log read is a team record: small groups fold into `other`.
	Team bool
}

// One group's totals.
type RecordCostRow struct {
	Group            string `json:"group"`
	Runs             uint64 `json:"runs"`
	Calls            uint64 `json:"calls"`
	InputTokens      uint64 `json:"input_tokens"`
	OutputTokens     uint64 `json:"output_tokens"`
	CacheReadTokens  uint64 `json:"cache_read_tokens"`
	CacheWriteTokens uint64 `json:"cache_write_tokens"`
	ReportedMicroUsd uint64 `json:"reported_micro_usd"`
	MeteredBytes     uint64 `json:"metered_bytes"`
	// False where any run folded in had a coverage gap that may hide calls.
	Complete bool `json:"complete"`

	runs    map[Id]bool
	members map[Id]bool
	// a writer with no member known: counted as no member, so its group never passes the size on it
	unknownMember bool
}

// Adds a model's usage of run by member to the row.
func (self *RecordCostRow) add(runId Id, memberId *Id, usage *protocol.ModelUsage) {
	if !self.runs[runId] {
		self.runs[runId] = true
		self.Runs += 1
	}
	if memberId != nil {
		self.members[*memberId] = true
	} else {
		self.unknownMember = true
	}
	self.Calls = recordCostAdd(self.Calls, usage.GetCalls())
	self.InputTokens = recordCostAdd(self.InputTokens, usage.GetInputTokens())
	self.OutputTokens = recordCostAdd(self.OutputTokens, usage.GetOutputTokens())
	self.CacheReadTokens = recordCostAdd(self.CacheReadTokens, usage.GetCacheReadTokens())
	self.CacheWriteTokens = recordCostAdd(self.CacheWriteTokens, usage.GetCacheWriteTokens())
	self.ReportedMicroUsd = recordCostAdd(self.ReportedMicroUsd, usage.GetReportedMicroUsd())
	self.Complete = self.Complete && usage.GetComplete()
}

// other's totals folded into the row.
func (self *RecordCostRow) fold(other *RecordCostRow) {
	for runId := range other.runs {
		if !self.runs[runId] {
			self.runs[runId] = true
			self.Runs += 1
		}
	}
	for memberId := range other.members {
		self.members[memberId] = true
	}
	self.unknownMember = self.unknownMember || other.unknownMember
	self.Calls = recordCostAdd(self.Calls, other.Calls)
	self.InputTokens = recordCostAdd(self.InputTokens, other.InputTokens)
	self.OutputTokens = recordCostAdd(self.OutputTokens, other.OutputTokens)
	self.CacheReadTokens = recordCostAdd(self.CacheReadTokens, other.CacheReadTokens)
	self.CacheWriteTokens = recordCostAdd(self.CacheWriteTokens, other.CacheWriteTokens)
	self.ReportedMicroUsd = recordCostAdd(self.ReportedMicroUsd, other.ReportedMicroUsd)
	self.MeteredBytes = recordCostAdd(self.MeteredBytes, other.MeteredBytes)
	self.Complete = self.Complete && other.Complete
}

// An empty row for group.
func newRecordCostRow(group string) *RecordCostRow {
	return &RecordCostRow{Group: group, Complete: true, runs: map[Id]bool{}, members: map[Id]bool{}}
}

// Parses --by: empty, project, client, model or month. `member` and anything else is refused: the report groups no one
// by person.
func ParseRecordCostBy(by string) (RecordCostBy, error) {
	switch typed := RecordCostBy(by); typed {
	case RecordCostByNone, RecordCostByProject, RecordCostByClient, RecordCostByModel, RecordCostByMonth:
		return typed, nil
	}
	return RecordCostByNone, fmt.Errorf("%w: --by takes project, client, model or month, not %q", ErrRecordCostInvalid, by)
}

// Checks what a report asks before anything is read: a grouping ParseRecordCostBy takes, and a map naming a project
// for a report by client.
func CheckRecordCostQuery(by RecordCostBy, clients map[string]string) error {
	if _, err := ParseRecordCostBy(string(by)); err != nil {
		return err
	}
	if by == RecordCostByClient && len(clients) == 0 {
		return ErrRecordCostNoClientMap
	}
	return nil
}

// Parses --format, text when empty.
func ParseRecordCostFormat(format string) (RecordCostFormat, error) {
	switch typed := RecordCostFormat(format); typed {
	case "":
		return RecordCostFormatText, nil
	case RecordCostFormatText, RecordCostFormatCsv, RecordCostFormatJsonl:
		return typed, nil
	}
	return "", fmt.Errorf("%w: --format takes text, csv or jsonl, not %q", ErrRecordCostInvalid, format)
}

// Parses a --map file: `project,client` lines, the project up to the last comma, blank lines and lines starting #
// skipped. A project named twice is refused.
func ParseRecordCostMap(content []byte, settings *RecordCostSettings) (map[string]string, error) {
	if settings == nil {
		settings = DefaultRecordCostSettings()
	}
	if settings.MapByteCount < len(content) {
		return nil, fmt.Errorf("%w: a map of %d bytes, past %d", ErrRecordCostInvalid, len(content), settings.MapByteCount)
	}
	if !utf8.Valid(content) {
		return nil, fmt.Errorf("%w: a map that is not UTF-8", ErrRecordCostInvalid)
	}
	clients := map[string]string{}
	lines := bytes.Split(content, []byte("\n"))
	if settings.MapLineCount < len(lines) {
		return nil, fmt.Errorf("%w: a map of %d lines, past %d", ErrRecordCostInvalid, len(lines), settings.MapLineCount)
	}
	for number, line := range lines {
		text := strings.TrimSpace(string(line))
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		at := strings.LastIndex(text, ",")
		if at < 0 {
			return nil, fmt.Errorf("%w: map line %d is not project,client", ErrRecordCostInvalid, number+1)
		}
		project, client := strings.TrimSpace(text[:at]), strings.TrimSpace(text[at+1:])
		if project == "" || client == "" {
			return nil, fmt.Errorf("%w: map line %d names no project or no client", ErrRecordCostInvalid, number+1)
		}
		if _, ok := clients[project]; ok {
			return nil, fmt.Errorf("%w: map line %d names a project again", ErrRecordCostInvalid, number+1)
		}
		clients[project] = client
	}
	return clients, nil
}

// One log's cost entries summed: per run and writer only the newest entry by seq, inside the query's times, grouped
// as it asks. Rows ascend by group, `other` last: no order by amount.
func RecordCostReport(entries []*RecordCostEntry, query *RecordCostQuery, settings *RecordCostSettings) ([]*RecordCostRow, error) {
	if settings == nil {
		settings = DefaultRecordCostSettings()
	}
	if query == nil {
		query = &RecordCostQuery{}
	}
	if err := CheckRecordCostQuery(query.By, query.Clients); err != nil {
		return nil, err
	}
	type chain struct {
		runId    Id
		writerId Id
	}
	newest := map[chain]*RecordCostEntry{}
	for _, entry := range entries {
		if entry == nil || entry.Body == nil {
			continue
		}
		key := chain{runId: entry.RunId, writerId: entry.WriterSidecarId}
		if held, ok := newest[key]; !ok || held.Seq < entry.Seq {
			newest[key] = entry
		}
	}
	rows := map[string]*RecordCostRow{}
	row := func(group string) *RecordCostRow {
		held, ok := rows[group]
		if !ok {
			held = newRecordCostRow(group)
			rows[group] = held
		}
		return held
	}
	for _, entry := range newest {
		// the newest entry's own time places the run: an older entry of a run re-opened later counts nowhere
		if entry.TimeMillis < query.SinceMillis || (query.UntilMillis != 0 && query.UntilMillis <= entry.TimeMillis) {
			continue
		}
		group := ""
		switch query.By {
		case RecordCostByProject:
			group = entry.Project
			if group == "" {
				group = RecordCostGroupNoProject
			} else if client, ok := query.Clients[group]; ok {
				group = client
			}
		case RecordCostByClient:
			group = RecordCostGroupNoClient
			if client, ok := query.Clients[entry.Project]; ok && entry.Project != "" {
				group = client
			}
		case RecordCostByMonth:
			group = time.UnixMilli(entry.TimeMillis).UTC().Format("2006-01")
		case RecordCostByNone:
			group = "total"
		}
		metered := false
		for _, usage := range entry.Body.GetUsage() {
			target := group
			if query.By == RecordCostByModel {
				target = usage.GetModel()
				if target == "" {
					target = RecordCostGroupOther
				}
			}
			held := row(target)
			held.add(entry.RunId, entry.MemberId, usage)
			if !metered && query.By != RecordCostByModel {
				// a run's metered bytes are its own, not a model's: counted once, and left out by model
				held.MeteredBytes = recordCostAdd(held.MeteredBytes, entry.Body.GetMeteredBytes())
				metered = true
			}
		}
	}
	if query.Team && query.By != RecordCostByNone {
		other := rows[RecordCostGroupOther]
		for group, held := range rows {
			if group == RecordCostGroupOther || settings.GroupMemberCount <= len(held.members) {
				continue
			}
			if other == nil {
				other = newRecordCostRow(RecordCostGroupOther)
				rows[RecordCostGroupOther] = other
			}
			other.fold(held)
			delete(rows, group)
		}
	}
	listed := make([]*RecordCostRow, 0, len(rows))
	for _, held := range rows {
		listed = append(listed, held)
	}
	slices.SortFunc(listed, func(a *RecordCostRow, b *RecordCostRow) int {
		if (a.Group == RecordCostGroupOther) != (b.Group == RecordCostGroupOther) {
			if a.Group == RecordCostGroupOther {
				return 1
			}
			return -1
		}
		return strings.Compare(a.Group, b.Group)
	})
	return listed, nil
}

// A report's columns, in order.
var recordCostColumns = []string{
	"group", "runs", "calls", "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens",
	"reported_micro_usd", "metered_bytes", "complete",
}

// A row's values in recordCostColumns' order.
func (self *RecordCostRow) values() []string {
	return []string{
		self.Group,
		strconv.FormatUint(self.Runs, 10),
		strconv.FormatUint(self.Calls, 10),
		strconv.FormatUint(self.InputTokens, 10),
		strconv.FormatUint(self.OutputTokens, 10),
		strconv.FormatUint(self.CacheReadTokens, 10),
		strconv.FormatUint(self.CacheWriteTokens, 10),
		strconv.FormatUint(self.ReportedMicroUsd, 10),
		strconv.FormatUint(self.MeteredBytes, 10),
		strconv.FormatBool(self.Complete),
	}
}

// A csv field, quoted where it holds a comma, a quote or a line break.
func recordCostCsvField(value string) string {
	if !strings.ContainsAny(value, ",\"\r\n") {
		return value
	}
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

// The report as `ur record cost` prints it. Amounts are what harnesses reported, in millionths of a US dollar, and
// tokens: no price is computed.
func FormatRecordCost(rows []*RecordCostRow, format RecordCostFormat) ([]byte, error) {
	out := &bytes.Buffer{}
	switch format {
	case RecordCostFormatJsonl:
		for _, row := range rows {
			line, err := json.Marshal(row)
			if err != nil {
				return nil, err
			}
			out.Write(line)
			out.WriteByte('\n')
		}
	case RecordCostFormatCsv:
		out.WriteString(strings.Join(recordCostColumns, ",") + "\n")
		for _, row := range rows {
			fields := row.values()
			for i, field := range fields {
				fields[i] = recordCostCsvField(field)
			}
			out.WriteString(strings.Join(fields, ",") + "\n")
		}
	case RecordCostFormatText, "":
		widths := make([]int, len(recordCostColumns))
		lines := [][]string{recordCostColumns}
		for _, row := range rows {
			lines = append(lines, row.values())
		}
		for _, line := range lines {
			for i, field := range line {
				widths[i] = max(widths[i], utf8.RuneCountInString(field))
			}
		}
		for _, line := range lines {
			for i, field := range line {
				if i != 0 {
					out.WriteString("  ")
				}
				out.WriteString(field)
				if i != len(line)-1 {
					out.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(field)))
				}
			}
			out.WriteByte('\n')
		}
	default:
		return nil, fmt.Errorf("%w: format %q", ErrRecordCostInvalid, format)
	}
	return out.Bytes(), nil
}

// logId's cost entries as this sidecar reads them, each with its run's project from the run's first context entry in
// the same log, and its writer's member or sponsor. An entry whose body does not open, erased or without its key, is
// left out: the report sums what this reader holds.
func (self *SidecarRecord) CostEntries(ctx context.Context, logId Id) ([]*RecordCostEntry, error) {
	reader := self.Reader()
	if err := reader.Sync(ctx, logId); err != nil {
		return nil, err
	}
	auth := self.writer.auth()
	entries := reader.Entries(logId)
	runProjects := map[Id]string{}
	for _, entry := range entries {
		if entry.Kind() != RecordKindContext || entry.Body == nil || entry.State == RecordEntryForked {
			continue
		}
		runId, err := IdFromBytes(entry.Header.Header.GetRunId())
		if err != nil {
			continue
		}
		if _, ok := runProjects[runId]; ok {
			continue
		}
		body := &protocol.ContextBody{}
		if proto.Unmarshal(entry.Body, body) == nil {
			runProjects[runId] = body.GetProject()
		}
	}
	costs := []*RecordCostEntry{}
	for _, entry := range entries {
		if entry.Kind() != RecordKindCost || entry.Body == nil || entry.BodyInvalid || entry.State == RecordEntryForked {
			continue
		}
		runId, err := IdFromBytes(entry.Header.Header.GetRunId())
		if err != nil {
			continue
		}
		writerId, err := IdFromBytes(entry.Header.Header.GetWriterSidecarId())
		if err != nil {
			continue
		}
		body := &protocol.RunCostBody{}
		if proto.Unmarshal(entry.Body, body) != nil {
			continue
		}
		cost := &RecordCostEntry{
			RunId:           runId,
			WriterSidecarId: writerId,
			Seq:             entry.Header.Header.GetSeq(),
			TimeMillis:      entry.Header.Header.GetTimeMillis(),
			Project:         runProjects[runId],
			Body:            body,
		}
		if memberId, ok := auth.Member(writerId); ok {
			cost.MemberId = &memberId
		} else if sponsorId, ok := auth.Sponsor(writerId); ok {
			cost.MemberId = &sponsorId
		}
		costs = append(costs, cost)
	}
	return costs, nil
}

// `ur record cost` over logId: its cost entries read and summed as query asks, a team log's small groups folded.
func (self *SidecarRecord) CostReport(ctx context.Context, logId Id, query *RecordCostQuery, settings *RecordCostSettings) ([]*RecordCostRow, error) {
	if query == nil {
		query = &RecordCostQuery{}
	}
	if err := CheckRecordCostQuery(query.By, query.Clients); err != nil {
		return nil, err
	}
	entries, err := self.CostEntries(ctx, logId)
	if err != nil {
		return nil, err
	}
	asked := *query
	asked.Team = recordIsTeamLog(self.writer.auth(), logId)
	return RecordCostReport(entries, &asked, settings)
}
