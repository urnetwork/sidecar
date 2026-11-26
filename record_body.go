// RECORD.md section 6.4's body rules, written once, on every leg: each body's caps, which a writer holds a body to
// before it seals (RecordBodyValidate refuses an overrun) and a reader holds a stored body to after it opens (an
// overrun is shown as no body, with record_alarm over_cap); Coverage's source and gap codes, which carry no path or
// text; and T's projection, RecordProjectForTeam, which leaves empty every field record.proto marks V:, so what reaches
// the team record is a function of the body rather than a habit of its callers (R-RECORD-2, I-20). The caps are the
// format's, as record.proto's comments write them, not tunables: §16.7's capture settings may cut lower, never higher.
//
// Hook payloads and agent text reach these bodies redacted already (§16.7, D-MCP-5): this layer checks what it is
// given and redacts nothing itself, so a credential is kept out by the redactor before sealing (I-7). Bodies of the
// kinds M6 adds (model, cost, attestation, disclosure, the log upkeep, file_event) have their caps in RECORD.md
// sections 10 to 13 and their own tasks; until those land they pass here unchecked, and nothing writes one. model_call
// is checked here: its identifiers within their bytes, and DESIGN-COMPUTE §6.8's evidence rule (recordModelCallValidate).
// The directory's kinds, announce, request, decision and erasure_request, take §16.11's classes and caps from
// directory_fields.go, a stored one through directory_decode.go's bounded decoders.
//
// DESIGN-COMPUTE §24.5's kinds 54 session_entry and 55 session_blob, and a model_call's CallContext, are checked here
// for their shape and caps, which both ends share: the node's ids and hashes at their lengths, its item within
// SessionItemByteCount, its parts within SessionPartCount, each part kept whole in at most SessionBlobPieceCount blobs
// up to SessionPartWholeByteCount or by hash and size alone past it, and a blob's piece within BlobByteCount. Whether an
// item's hash and a node's chain hold is session_format.go's, which a session reader runs over a run's nodes.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// A body breaks one of section 6.4's rules: a cap, a length, or a value its field does not take. A writer refuses
// it; a reader shows the entry with no body and raises over_cap.
var ErrRecordBodyOverCap = errors.New("record body over its caps")

// Section 6.4's caps, as record.proto's comments write them, as settings (QD-702): format values, which a writer holds
// a body to before it seals and every reader holds a stored body to after it opens, so no device sets one on its own;
// this object holds them and its defaults stay here. §16.7's capture settings may cut lower, never higher. A count is
// entries, a byte count bytes.
type RecordBodySettings struct {
	// ContextBody.prompts in one entry, the prompts' bytes together: 2,048 B, §16.10's "first 2 KiB of user prompts",
	// all a run card reads of them (QD-900). Each prompt is non-empty.
	ContextPromptByteCount int
	// A claim's or handoff's text, in bytes: 512.
	ClaimTextByteCount int
	// An ask's, answer's, check's or note's text, in bytes: 1,024.
	CoordinationTextByteCount int
	// A coordination entry's targets: 16.
	TargetCount int
	// An agent label's bytes: 64, which ContextBody's label pattern holds.
	AgentLabelByteCount int
	// ContextBody's session ids: 4.
	SessionIdCount int
	// One session id's bytes: 64.
	SessionIdByteCount int
	// ContextBody's model, in bytes: 64.
	ModelByteCount int
	// A permission mode's bytes: 32.
	PermissionModeByteCount int
	// A project key's bytes, §16.11's rule: 128.
	ProjectByteCount int
	// A branch's bytes, a git ref name: 128.
	BranchByteCount int
	// A run title's bytes after redaction, §16.10's: 120.
	TitleByteCount int
	// ContextBody's instruction files: 64.
	InstructionFileCount int
	// An instruction file name's bytes: 128.
	FileNameByteCount int
	// ContextBody's truncation warnings: 16.
	TruncationCount int
	// One truncation warning's bytes: 128.
	TruncationByteCount int
	// A change's commits: 64.
	CommitCount int
	// A change's paths: 4,096.
	ChangedPathCount int
	// A permission's tool name, in bytes: 64.
	ToolNameByteCount int
	// A restore's paths: 4,096.
	RestoredPathCount int
	// A restored path's copies: 2.
	RestoredCopyCount int
	// A read receipt's object ids: 64.
	ReadObjectCount int
	// An erasure's entries: 1,024.
	ErasureEntryCount int
	// An inventory's agents: 64.
	InventoryAgentCount int
	// An inventory agent's harnesses: 8.
	InventoryHarnessCount int
	// An inventory agent's models: 16.
	InventoryModelCount int
	// An inventory agent's repo ids, and its projects: 64 each.
	InventoryRepoCount int
	// A model manifest field's bytes, an identifier: 128.
	ModelFieldByteCount int
	// A model_call's model, provider and request id, each in bytes: 128, as record.proto writes them.
	ModelCallFieldByteCount int
	// A cost entry's usages, by model: 16 (section 13.1).
	CostUsageCount int
	// A ledger_scope's repo ids: 256.
	LedgerRepoCount int
	// A ledger_scope's projects: 256.
	LedgerProjectCount int
	// A copy entry's openings: 64.
	CopyEntryCount int
	// A transcript chunk's lines, a tool call's input and output together, and a hook payload, in bytes after
	// redaction: 1 MiB (§16.7).
	CaptureByteCount int
	// A blob's content after redaction, in bytes: 8 MiB (§16.7).
	BlobByteCount int
	// The paths a tool call names: 256.
	ToolPathCount int
	// DESIGN-COMPUTE §28.12's support_message: a message's or a reply's text, in bytes: 64 KiB, the most of one event
	// the support client reads (SupportSettings.EventMaxByteCount), past a message's 16 KiB and room for a reply support
	// wrote.
	SupportTextByteCount int
	// A support_message's agent label, the agent's registered name and where it ran, in bytes: 192, a 64-byte name and
	// its place.
	SupportAgentLabelByteCount int
	// A support_message's files: 3 (§28.7), CanonicalActionSettings' SupportFileMaxCount, which field 80 holds to.
	SupportFileCount int
	// One file's base name, in bytes: 255, a file system's.
	SupportFileNameByteCount int
	// One file's bytes: 10 MiB (§28.7, FB section 9).
	SupportFileByteCount uint64
	// A bundle's compressed bytes: 4 MiB (§28.7).
	SupportBundleByteCount uint64
	// A bundle manifest's codes by component: 256, past every code the support log's registry declares.
	SupportBundleCodeCount int
	// A component's or a code's name in a bundle manifest, in bytes: 64.
	SupportCodeNameByteCount int
	// A status event's fixed_in, a version or next, in bytes: 32 (SupportSettings.VersionMaxByteCount's).
	SupportFixedInByteCount int
	// A message's body as sent or received, in bytes: 64 KiB, the bound a body's text and fields sit within.
	SupportBodyByteCount uint64

	// DESIGN-COMPUTE §24.5's session_entry: a node's item as recorded, RFC 8785 JSON after redaction and stubs, in
	// bytes: 16 KiB, what rides in a push's payload beside its header (DESIGN §11.7); a part that would carry it past
	// this moves to session_blob entries.
	SessionItemByteCount int
	// A node's parts: 64.
	SessionPartCount int
	// The session_blob pieces one part is kept whole in: 8, so a part of SessionPartWholeByteCount is eight pieces of
	// BlobByteCount.
	SessionBlobPieceCount int
	// The largest part kept whole, in bytes: 64 MiB (Q-CTXH-8); past it, by hash and size alone, omitted.
	SessionPartWholeByteCount uint64
	// A part's media type, in bytes: 255, RFC 6838's 127 bytes of type and of subtype and the slash between.
	SessionMediaTypeByteCount int
}

// RECORD.md's values, the only source of their defaults. A fresh value each call.
func DefaultRecordBodySettings() *RecordBodySettings {
	return &RecordBodySettings{
		ContextPromptByteCount:    2 * 1024,
		ClaimTextByteCount:        512,
		CoordinationTextByteCount: 1024,
		TargetCount:               16,
		AgentLabelByteCount:       64,
		SessionIdCount:            4,
		SessionIdByteCount:        64,
		ModelByteCount:            64,
		PermissionModeByteCount:   32,
		ProjectByteCount:          128,
		BranchByteCount:           128,
		TitleByteCount:            120,
		InstructionFileCount:      64,
		FileNameByteCount:         128,
		TruncationCount:           16,
		TruncationByteCount:       128,
		CommitCount:               64,
		ChangedPathCount:          4096,
		ToolNameByteCount:         64,
		RestoredPathCount:         4096,
		RestoredCopyCount:         2,
		ReadObjectCount:           64,
		ErasureEntryCount:         1024,
		InventoryAgentCount:       64,
		InventoryHarnessCount:     8,
		InventoryModelCount:       16,
		InventoryRepoCount:        64,
		ModelFieldByteCount:       128,
		ModelCallFieldByteCount:   128,
		CostUsageCount:            16,
		LedgerRepoCount:           256,
		LedgerProjectCount:        256,
		CopyEntryCount:            64,
		CaptureByteCount:          1024 * 1024,
		BlobByteCount:             8 * 1024 * 1024,
		ToolPathCount:             256,

		SupportTextByteCount:       64 * 1024,
		SupportAgentLabelByteCount: 192,
		SupportFileCount:           DefaultCanonicalActionSettings().SupportFileMaxCount,
		SupportFileNameByteCount:   255,
		SupportFileByteCount:       10 * 1024 * 1024,
		SupportBundleByteCount:     4 * 1024 * 1024,
		SupportBundleCodeCount:     256,
		SupportCodeNameByteCount:   64,
		SupportFixedInByteCount:    32,
		SupportBodyByteCount:       64 * 1024,

		SessionItemByteCount:      16 * 1024,
		SessionPartCount:          64,
		SessionBlobPieceCount:     8,
		SessionPartWholeByteCount: 64 * 1024 * 1024,
		SessionMediaTypeByteCount: 255,
	}
}

// Coverage.sources' codes (RECORD.md section 6.4).
const (
	RecordCoverageSourceMcp        = "mcp"
	RecordCoverageSourceHooks      = "hooks"
	RecordCoverageSourceTranscript = "transcript"
	RecordCoverageSourceScan       = "scan"
	RecordCoverageSourceTelemetry  = "telemetry"
	RecordCoverageSourceFileEvents = "file_events"
	// DESIGN-COMPUTE §24.5, §24.8: the Harness recorded the run natively, and the gateway recorded its model calls
	RecordCoverageSourceHarness = "harness"
	RecordCoverageSourceGateway = "gateway"
)

// Coverage.gaps' codes (RECORD.md section 6.4), each written "code" once or "code:count".
const (
	RecordCoverageGapHookFailure    = "hook_failure"
	RecordCoverageGapMissedEvent    = "missed_event"
	RecordCoverageGapConfigChanged  = "config_changed"
	RecordCoverageGapDowntime       = "downtime"
	RecordCoverageGapTruncation     = "truncation"
	RecordCoverageGapOversize       = "oversize"
	RecordCoverageGapBypassMode     = "bypass_mode"
	RecordCoverageGapRedaction      = "redaction"
	RecordCoverageGapNoToolId       = "no_tool_id"
	RecordCoverageGapNoVault        = "no_vault"
	RecordCoverageGapRunFileMissing = "run_file_missing"
	RecordCoverageGapSpoolDrop      = "spool_drop"
	// DESIGN-COMPUTE §24.8: a model_call a hook or telemetry reported whose request the gateway never saw, so its
	// context is only what the transcript shows (Q-CTXH-14)
	RecordCoverageGapContextPartial = "context_partial"
)

var recordCoverageSources = []string{
	RecordCoverageSourceMcp,
	RecordCoverageSourceHooks,
	RecordCoverageSourceTranscript,
	RecordCoverageSourceScan,
	RecordCoverageSourceTelemetry,
	RecordCoverageSourceFileEvents,
	RecordCoverageSourceHarness,
	RecordCoverageSourceGateway,
}

var recordCoverageGaps = []string{
	RecordCoverageGapHookFailure,
	RecordCoverageGapMissedEvent,
	RecordCoverageGapConfigChanged,
	RecordCoverageGapDowntime,
	RecordCoverageGapTruncation,
	RecordCoverageGapOversize,
	RecordCoverageGapBypassMode,
	RecordCoverageGapRedaction,
	RecordCoverageGapNoToolId,
	RecordCoverageGapNoVault,
	RecordCoverageGapRunFileMissing,
	RecordCoverageGapSpoolDrop,
	RecordCoverageGapContextPartial,
}

// Whether section 6.4 names code as a Coverage source.
func RecordCoverageSourceKnown(code string) bool {
	return slices.Contains(recordCoverageSources, code)
}

// A gap as Coverage.gaps holds it: "code" for one, "code:count" for more, as RunStore.AddGap counts them. Refuses a
// code section 6.4 does not name and a count below 1.
func RecordCoverageGap(code string, count int) (string, error) {
	if !slices.Contains(recordCoverageGaps, code) {
		return "", fmt.Errorf("%w: gap code %q", ErrRecordBodyOverCap, code)
	}
	if count < 1 {
		return "", fmt.Errorf("%w: gap count %d", ErrRecordBodyOverCap, count)
	}
	if count == 1 {
		return code, nil
	}
	return code + ":" + strconv.Itoa(count), nil
}

// The code and count of a gap string, and false for any form RecordCoverageGap would not make, which carries a path
// or text where only a code may stand.
func RecordCoverageGapParse(gap string) (string, int, bool) {
	code, countText, counted := strings.Cut(gap, ":")
	if !slices.Contains(recordCoverageGaps, code) {
		return "", 0, false
	}
	if !counted {
		return code, 1, true
	}
	count, err := strconv.Atoi(countText)
	if err != nil || count < 2 || strconv.Itoa(count) != countText {
		return "", 0, false
	}
	return code, count, true
}

// ContextBody.agent_label and §16.11's AnnounceWho.
var recordAgentLabelPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// One rule check: a refusal naming the field, nil when it holds.
func recordBodyRule(holds bool, format string, args ...any) error {
	if holds {
		return nil
	}
	return fmt.Errorf("%w: "+format, append([]any{ErrRecordBodyOverCap}, args...)...)
}

// Whether value is length bytes long, or empty where optional.
func recordBodyLength(value []byte, length int, optional bool) bool {
	return len(value) == length || (optional && len(value) == 0)
}

// Holds a body of kind to section 6.4's caps and values: the writer's refusal of an overrun, and the reader's check
// of what it opened. body must be kind's one message (record_kind.go); a Signed kind's body is checked by its own
// parser (record_hash.go), and a kind without rules here passes.
func RecordBodyValidate(kind RecordKind, body proto.Message) error {
	settings := DefaultRecordBodySettings()
	if body == nil {
		return recordBodyRule(false, "no body")
	}
	if want, ok := kind.NewBody(); ok && proto.MessageName(want) != proto.MessageName(body) {
		return recordBodyRule(false, "kind %s takes %s, not %s", kind, proto.MessageName(want), proto.MessageName(body))
	}
	// the directory's kinds take §16.11's classes and caps (directory_fields.go)
	if directory, err := directoryValidateBody(kind, body); directory {
		return err
	}
	switch typed := body.(type) {
	case *protocol.CoordinationBody:
		return recordCoordinationValidate(kind, typed)
	case *protocol.ContextBody:
		return recordContextValidate(typed)
	case *protocol.ChangeBody:
		return recordChangeValidate(typed)
	case *protocol.PermissionBody:
		return errors.Join(
			recordBodyRule(typed.GetDecision() <= 3, "permission decision %d", typed.GetDecision()),
			recordBodyRule(typed.GetDecidedBy() <= 4, "permission decided_by %d", typed.GetDecidedBy()),
			recordBodyRule(len(typed.GetPermissionMode()) <= settings.PermissionModeByteCount, "permission_mode of %d bytes", len(typed.GetPermissionMode())),
			recordBodyRule(typed.GetToolClass() <= 5, "tool_class %d", typed.GetToolClass()),
			recordBodyRule(len(typed.GetToolName()) <= settings.ToolNameByteCount, "tool_name of %d bytes", len(typed.GetToolName())),
			recordBodyRule(recordBodyLength(typed.GetArgumentsSha256(), recordHashByteCount, true), "arguments_sha256 of %d bytes", len(typed.GetArgumentsSha256())),
		)
	case *protocol.ApprovalUseBody:
		return errors.Join(
			recordBodyRule(recordBodyLength(typed.GetApprovalId(), recordIdByteCount, false), "approval_id of %d bytes", len(typed.GetApprovalId())),
			recordBodyRule(recordBodyLength(typed.GetPayloadSha256(), recordHashByteCount, false), "payload_sha256 of %d bytes", len(typed.GetPayloadSha256())),
			recordBodyRule(recordBodyLength(typed.GetEffectKey(), recordHashByteCount, false), "effect_key of %d bytes", len(typed.GetEffectKey())),
			recordBodyRule(1 <= typed.GetState() && typed.GetState() <= 3, "use state %d", typed.GetState()),
		)
	case *protocol.RouteBody:
		return recordRouteBodyValidate(typed)
	case *protocol.PublishBody:
		return recordPublishBodyValidate(typed)
	case *protocol.RestoreBody:
		checks := []error{
			recordBodyRule(recordBodyLength(typed.GetRestoredRunId(), recordIdByteCount, false), "restored_run_id of %d bytes", len(typed.GetRestoredRunId())),
			recordBodyRule(recordBodyLength(typed.GetPreviewId(), recordIdByteCount, true), "preview_id of %d bytes", len(typed.GetPreviewId())),
			recordBodyRule(recordBodyLength(typed.GetApprovalId(), recordIdByteCount, true), "approval_id of %d bytes", len(typed.GetApprovalId())),
			recordBodyRule(len(typed.GetPaths()) <= settings.RestoredPathCount, "%d restored paths", len(typed.GetPaths())),
		}
		for _, path := range typed.GetPaths() {
			checks = append(checks, recordBodyRule(len(path.GetCopies()) <= settings.RestoredCopyCount, "%d copies of a restored path", len(path.GetCopies())))
		}
		return errors.Join(checks...)
	case *protocol.MembershipBody:
		return recordMembershipValidate(typed)
	case *protocol.KeyBody:
		return errors.Join(
			recordBodyRule(typed.GetEvent() == 1, "key event %d", typed.GetEvent()),
			recordBodyRule(recordBodyLength(typed.GetGroupId(), recordIdByteCount, true), "group_id of %d bytes", len(typed.GetGroupId())),
			recordBodyRule(recordBodyLength(typed.GetStatementSha256(), recordHashByteCount, true), "statement_sha256 of %d bytes", len(typed.GetStatementSha256())),
		)
	case *protocol.ReadBody:
		checks := []error{
			recordBodyRule(1 <= len(typed.GetObjectIds()) && len(typed.GetObjectIds()) <= settings.ReadObjectCount, "%d object ids", len(typed.GetObjectIds())),
			recordBodyRule(1 <= typed.GetPurpose() && typed.GetPurpose() <= 4, "read purpose %d", typed.GetPurpose()),
			recordBodyRule(recordBodyLength(typed.GetReadLogId(), recordIdByteCount, true), "read_log_id of %d bytes", len(typed.GetReadLogId())),
		}
		for _, objectId := range typed.GetObjectIds() {
			checks = append(checks, recordBodyRule(len(objectId) == recordIdByteCount || len(objectId) == recordHashByteCount, "an object id of %d bytes", len(objectId)))
		}
		return errors.Join(checks...)
	case *protocol.ErasureBody:
		checks := []error{
			recordBodyRule(recordBodyLength(typed.GetErasureId(), recordIdByteCount, false), "erasure_id of %d bytes", len(typed.GetErasureId())),
			recordBodyRule(1 <= len(typed.GetEntryIds()) && len(typed.GetEntryIds()) <= settings.ErasureEntryCount, "%d erased entries", len(typed.GetEntryIds())),
			recordBodyRule(1 <= typed.GetReason() && typed.GetReason() <= 4, "erasure reason %d", typed.GetReason()),
			recordBodyRule((typed.GetReason() == 4) == (len(typed.GetRequestId()) == recordIdByteCount), "request_id of %d bytes for reason %d", len(typed.GetRequestId()), typed.GetReason()),
		}
		for _, entryId := range typed.GetEntryIds() {
			checks = append(checks, recordBodyRule(len(entryId) == recordIdByteCount, "an erased entry id of %d bytes", len(entryId)))
		}
		return errors.Join(checks...)
	case *protocol.InventoryBody:
		checks := []error{recordBodyRule(len(typed.GetAgents()) <= settings.InventoryAgentCount, "%d inventory agents", len(typed.GetAgents()))}
		for _, agent := range typed.GetAgents() {
			checks = append(checks,
				recordBodyRule(len(agent.GetHarnesses()) <= settings.InventoryHarnessCount, "%d harnesses", len(agent.GetHarnesses())),
				recordBodyRule(len(agent.GetModels()) <= settings.InventoryModelCount, "%d models", len(agent.GetModels())),
				recordBodyRule(len(agent.GetRepoIds()) <= settings.InventoryRepoCount, "%d repo ids", len(agent.GetRepoIds())),
				recordBodyRule(len(agent.GetProjects()) <= settings.InventoryRepoCount, "%d projects", len(agent.GetProjects())),
			)
		}
		return errors.Join(checks...)
	case *protocol.ModelManifest:
		return recordModelManifestValidate(typed, false)
	case *protocol.ModelCallBody:
		return recordModelCallValidate(typed)
	case *protocol.RunCostBody:
		return recordBodyRule(len(typed.GetUsage()) <= settings.CostUsageCount, "%d model usages", len(typed.GetUsage()))
	case *protocol.LedgerScopeBody:
		return recordLedgerScopeValidate(typed)
	case *protocol.CopyBody:
		return recordBodyRule(len(typed.GetEntries()) <= settings.CopyEntryCount, "%d copied entries", len(typed.GetEntries()))
	case *protocol.TranscriptBody:
		return recordBodyRule(len(typed.GetLines()) <= settings.CaptureByteCount, "transcript lines of %d bytes", len(typed.GetLines()))
	case *protocol.ToolCallBody:
		return errors.Join(
			recordBodyRule(len(typed.GetInput())+len(typed.GetOutput()) <= settings.CaptureByteCount, "tool input and output of %d bytes", len(typed.GetInput())+len(typed.GetOutput())),
			recordBodyRule(len(typed.GetPaths()) <= settings.ToolPathCount, "%d tool paths", len(typed.GetPaths())),
			recordBodyRule(typed.GetToolClass() <= 5, "tool_class %d", typed.GetToolClass()),
		)
	case *protocol.HookEventBody:
		return errors.Join(
			recordBodyRule(len(typed.GetPayload()) <= settings.CaptureByteCount, "hook payload of %d bytes", len(typed.GetPayload())),
			recordBodyRule(recordBodyLength(typed.GetArgumentsSha256(), recordHashByteCount, true), "arguments_sha256 of %d bytes", len(typed.GetArgumentsSha256())),
		)
	case *protocol.BlobBody:
		return errors.Join(
			recordBodyRule(len(typed.GetContent()) <= settings.BlobByteCount, "blob content of %d bytes", len(typed.GetContent())),
			recordBodyRule(recordBodyLength(typed.GetSha256(), recordHashByteCount, true), "blob sha256 of %d bytes", len(typed.GetSha256())),
		)
	case *protocol.Coverage:
		return recordCoverageValidate(typed)
	case *protocol.LogSettingsBody:
		return recordLogSettingsValidate(typed)
	case *protocol.LogCheckpointBody:
		return recordLogCheckpointValidate(typed)
	case *protocol.DisclosureBody:
		return recordDisclosureValidate(typed)
	case *protocol.SupportMessageBody:
		return recordSupportMessageValidate(typed)
	case *protocol.SessionEntryBody:
		return recordSessionEntryValidate(typed)
	case *protocol.SessionBlobBody:
		return recordSessionBlobValidate(typed)
	}
	return nil
}

// SessionEntryBody.type's last value, 9 link: 1 message to 9 link, as §24.5's fence numbers them (session_node.go
// names each).
const recordSessionNodeTypeLast uint32 = 9

// SessionEntryBody.marks' bits: 0 limited_use (§25.10), 1 private (§7.8). Any other bit is no mark.
const recordSessionMarkBits uint32 = 1<<0 | 1<<1

// session_entry (DESIGN-COMPUTE §24.5): a random 16-byte node id; a parent node of 16 bytes or none, and a parent run
// only beside a parent node; a type section §24.5 numbers; the item within SessionItemByteCount and the parts within
// SessionPartCount; the item and chain hashes of 32 bytes; a same_as node of 16 bytes standing for an item and parts
// it leaves empty; and only the two marks. Each part holds an RFC 6901 pointer into the item, a 32-byte hash, a media
// type within its bytes, and either its pieces, 1 to SessionBlobPieceCount blob entry ids of 16 bytes for a part of up
// to SessionPartWholeByteCount, or, omitted, none at all: a part past it, past the run-hour budget or at a cap.
func recordSessionEntryValidate(body *protocol.SessionEntryBody) error {
	settings := DefaultRecordBodySettings()
	sameAs := len(body.GetSameAs()) != 0
	checks := []error{
		recordBodyRule(recordBodyLength(body.GetNodeId(), recordIdByteCount, false), "node_id of %d bytes", len(body.GetNodeId())),
		recordBodyRule(recordBodyLength(body.GetParentNodeId(), recordIdByteCount, true), "parent_node_id of %d bytes", len(body.GetParentNodeId())),
		recordBodyRule(recordBodyLength(body.GetParentRunId(), recordIdByteCount, true), "parent_run_id of %d bytes", len(body.GetParentRunId())),
		recordBodyRule(len(body.GetParentRunId()) == 0 || len(body.GetParentNodeId()) != 0, "a parent run with no parent node"),
		recordBodyRule(1 <= body.GetType() && body.GetType() <= recordSessionNodeTypeLast, "session node type %d", body.GetType()),
		recordBodyRule(len(body.GetItem()) <= settings.SessionItemByteCount, "a session item of %d bytes", len(body.GetItem())),
		recordBodyRule(len(body.GetParts()) <= settings.SessionPartCount, "%d session parts", len(body.GetParts())),
		recordBodyRule(recordBodyLength(body.GetItemSha256(), recordHashByteCount, false), "item_sha256 of %d bytes", len(body.GetItemSha256())),
		recordBodyRule(recordBodyLength(body.GetChainSha256(), recordHashByteCount, false), "chain_sha256 of %d bytes", len(body.GetChainSha256())),
		recordBodyRule(recordBodyLength(body.GetSameAs(), recordIdByteCount, true), "same_as of %d bytes", len(body.GetSameAs())),
		recordBodyRule(!sameAs || (len(body.GetItem()) == 0 && len(body.GetParts()) == 0), "a same_as node holding an item or parts"),
		recordBodyRule(sameAs || len(body.GetItem()) != 0, "a session node with no item and no same_as"),
		recordBodyRule(body.GetMarks()&^recordSessionMarkBits == 0, "session marks %#x", body.GetMarks()),
	}
	for _, part := range body.GetParts() {
		checks = append(checks, recordSessionPartValidate(settings, part))
	}
	return errors.Join(checks...)
}

// One part of a session node: see recordSessionEntryValidate.
func recordSessionPartValidate(settings *RecordBodySettings, part *protocol.SessionPart) error {
	pieceCount := len(part.GetBlobEntryIds())
	checks := []error{
		recordBodyRule(RecordSessionPointerValid(part.GetPointer()) && len(part.GetPointer()) <= settings.SessionItemByteCount,
			"a session part pointer of %d bytes that is no RFC 6901 pointer into the item", len(part.GetPointer())),
		recordBodyRule(recordBodyLength(part.GetSha256(), recordHashByteCount, false), "a session part sha256 of %d bytes", len(part.GetSha256())),
		recordBodyRule(len(part.GetMediaType()) <= settings.SessionMediaTypeByteCount, "a session part media type of %d bytes", len(part.GetMediaType())),
	}
	if part.GetOmitted() {
		// past SessionPartWholeByteCount, past the run-hour budget, or at a history cap (§24.10): by hash and size alone
		checks = append(checks, recordBodyRule(pieceCount == 0, "an omitted session part naming %d blobs", pieceCount))
	} else {
		checks = append(checks,
			recordBodyRule(1 <= pieceCount && pieceCount <= settings.SessionBlobPieceCount, "a session part in %d blobs", pieceCount),
			recordBodyRule(part.GetSize() <= settings.SessionPartWholeByteCount, "a session part of %d bytes kept whole", part.GetSize()),
			recordBodyRule(part.GetSize() <= uint64(pieceCount)*uint64(settings.BlobByteCount), "a session part of %d bytes in %d blobs", part.GetSize(), pieceCount),
		)
	}
	for _, entryId := range part.GetBlobEntryIds() {
		checks = append(checks, recordBodyRule(len(entryId) == recordIdByteCount, "a session blob entry id of %d bytes", len(entryId)))
	}
	return errors.Join(checks...)
}

// Whether pointer is an RFC 6901 JSON pointer to a value inside an item: not the whole item, "", but "/" and its
// reference tokens, where a "~" escapes only "0" and "1".
func RecordSessionPointerValid(pointer string) bool {
	if !strings.HasPrefix(pointer, "/") || !utf8.ValidString(pointer) {
		return false
	}
	for i := 0; i < len(pointer); i += 1 {
		if pointer[i] != '~' {
			continue
		}
		if i+1 == len(pointer) || (pointer[i+1] != '0' && pointer[i+1] != '1') {
			return false
		}
	}
	return true
}

// session_blob (DESIGN-COMPUTE §24.5): one piece, index below count, of a part's 1 to SessionBlobPieceCount, the part's
// 32-byte hash, and content within BlobByteCount.
func recordSessionBlobValidate(body *protocol.SessionBlobBody) error {
	settings := DefaultRecordBodySettings()
	return errors.Join(
		recordBodyRule(recordBodyLength(body.GetPartSha256(), recordHashByteCount, false), "a blob's part_sha256 of %d bytes", len(body.GetPartSha256())),
		recordBodyRule(1 <= body.GetCount() && int(body.GetCount()) <= settings.SessionBlobPieceCount, "a part in %d pieces", body.GetCount()),
		recordBodyRule(body.GetIndex() < body.GetCount(), "piece %d of %d", body.GetIndex(), body.GetCount()),
		recordBodyRule(len(body.GetContent()) <= settings.BlobByteCount, "a session blob of %d bytes", len(body.GetContent())),
	)
}

// A model call's CallContext (ModelCallBody field 15, DESIGN-COMPUTE §24.5): its input, output and system nodes by
// 16-byte ids, the input always, the request's hash of 32 bytes, and a renderer within the body's identifier bytes.
func recordCallContextValidate(settings *RecordBodySettings, context *protocol.CallContext) error {
	checks := []error{
		recordBodyRule(recordBodyLength(context.GetInputNodeId(), recordIdByteCount, false), "a call context's input_node_id of %d bytes", len(context.GetInputNodeId())),
		recordBodyRule(recordBodyLength(context.GetSystemNodeId(), recordIdByteCount, true), "a call context's system_node_id of %d bytes", len(context.GetSystemNodeId())),
		recordBodyRule(recordBodyLength(context.GetRequestSha256(), recordHashByteCount, false), "a call context's request_sha256 of %d bytes", len(context.GetRequestSha256())),
		recordBodyRule(context.GetRenderer() != "" && len(context.GetRenderer()) <= settings.ModelCallFieldByteCount, "a call context's renderer of %d bytes", len(context.GetRenderer())),
	}
	for _, nodeId := range context.GetOutputNodeIds() {
		checks = append(checks, recordBodyRule(len(nodeId) == recordIdByteCount, "a call context's output node id of %d bytes", len(nodeId)))
	}
	return errors.Join(checks...)
}

// support_message (DESIGN-COMPUTE §28.12): a direction, one of FB's products, an entry in FB's form or none and a seq
// only with an entry, an event type, a tier and a status among those numbered, a 16-byte client_ref or none, the text,
// the label, the bundle's manifest and the files within their caps, the hashes and ids at their lengths, a sent
// message's support:urnetwork version and no approval on an event received.
func recordSupportMessageValidate(body *protocol.SupportMessageBody) error {
	settings := DefaultRecordBodySettings()
	direction := body.GetDirection()
	checks := []error{
		recordBodyRule(direction == supportDirectionSent || direction == supportDirectionReceived, "support direction %d", direction),
		recordBodyRule(body.GetProduct() == SupportProductUrnetwork || body.GetProduct() == supportProductRecurd, "a support product of %d bytes", len(body.GetProduct())),
		recordBodyRule(body.GetEntry() == "" || supportEntryPattern.MatchString(body.GetEntry()), "a support entry outside FB's form"),
		recordBodyRule(body.GetEntry() != "" || body.GetSeq() == 0, "a support seq with no entry"),
		recordBodyRule(body.GetType() <= supportEventTypeLast, "support event type %d", body.GetType()),
		recordBodyRule(body.GetTier() <= supportTierNumberLast, "support tier %d", body.GetTier()),
		recordBodyRule(recordBodyLength(body.GetClientRef(), supportClientRefByteCount, true), "a client_ref of %d bytes", len(body.GetClientRef())),
		recordBodyRule(len(body.GetText()) <= settings.SupportTextByteCount && utf8.ValidString(body.GetText()), "support text of %d bytes", len(body.GetText())),
		recordBodyRule(len(body.GetAgentLabel()) <= settings.SupportAgentLabelByteCount, "a support agent label of %d bytes", len(body.GetAgentLabel())),
		recordBodyRule(len(body.GetFiles()) <= settings.SupportFileCount, "%d support files", len(body.GetFiles())),
		recordBodyRule(recordBodyLength(body.GetBodySha256(), recordHashByteCount, true), "a support body_sha256 of %d bytes", len(body.GetBodySha256())),
		recordBodyRule(body.GetBodyBytes() <= settings.SupportBodyByteCount, "a support body of %d bytes", body.GetBodyBytes()),
		recordBodyRule(body.GetStatus() <= supportStatusLast, "support status %d", body.GetStatus()),
		recordBodyRule(len(body.GetFixedIn()) <= settings.SupportFixedInByteCount, "a fixed_in of %d bytes", len(body.GetFixedIn())),
		recordBodyRule(recordBodyLength(body.GetApprovalId(), recordIdByteCount, true), "a support approval_id of %d bytes", len(body.GetApprovalId())),
		recordBodyRule(direction != supportDirectionSent || 0 < body.GetDisclosureVersion(), "a sent support message with no disclosure version"),
		recordBodyRule(direction != supportDirectionReceived || len(body.GetApprovalId()) == 0, "a received support event naming an approval"),
	}
	if bundle := body.GetBundle(); bundle != nil {
		checks = append(checks,
			recordBodyRule(bundle.GetFirst() <= bundle.GetLast(), "a support bundle whose window ends before it starts"),
			recordBodyRule(bundle.GetBytes() <= settings.SupportBundleByteCount, "a support bundle of %d bytes", bundle.GetBytes()),
			recordBodyRule(recordBodyLength(bundle.GetSha256(), recordHashByteCount, true), "a support bundle sha256 of %d bytes", len(bundle.GetSha256())),
			recordBodyRule(len(bundle.GetCodes()) <= settings.SupportBundleCodeCount, "%d support bundle codes", len(bundle.GetCodes())),
		)
		for _, code := range bundle.GetCodes() {
			component, name := code.GetComponent(), code.GetCode()
			checks = append(checks, recordBodyRule(
				0 < len(component) && len(component) <= settings.SupportCodeNameByteCount && 0 < len(name) && len(name) <= settings.SupportCodeNameByteCount,
				"a support bundle code's names of %d and %d bytes", len(component), len(name)))
		}
	}
	for _, file := range body.GetFiles() {
		checks = append(checks,
			recordBodyRule(0 < len(file.GetName()) && len(file.GetName()) <= settings.SupportFileNameByteCount, "a support file name of %d bytes", len(file.GetName())),
			recordBodyRule(supportFileTypeText <= file.GetType() && file.GetType() <= supportFileTypeJpeg, "support file type %d", file.GetType()),
			recordBodyRule(file.GetSize() <= settings.SupportFileByteCount, "a support file of %d bytes", file.GetSize()),
			recordBodyRule(recordBodyLength(file.GetSha256(), recordHashByteCount, false), "a support file sha256 of %d bytes", len(file.GetSha256())),
		)
	}
	return errors.Join(checks...)
}

// ModelField.evidence (RECORD.md section 12): how a manifest's field is known.
const (
	// A person typed it, confirmed on /dev/tty or in an app.
	RecordModelEvidenceDeclared uint32 = 1
	// The engine said so over loopback on the host.
	RecordModelEvidenceReported uint32 = 2
	// The host's daemon hashed the files a person named.
	RecordModelEvidenceMeasured uint32 = 3
	// Reserved for hardware attestation; a v1 writer never sets it, and software evidence is never presented as it.
	RecordModelEvidenceAttested uint32 = 4
)

// model: a port, and each field an identifier within its bytes with an evidence section 12 names. A reader keeps a
// field marked attested, which a later writer with hardware evidence may set; writer holds a v1 writer's own, which
// refuses attested, an empty value, and measured on anything but the weights digest (D-RECORD-11).
func recordModelManifestValidate(body *protocol.ModelManifest, writer bool) error {
	settings := DefaultRecordBodySettings()
	checks := []error{recordBodyRule(1 <= body.GetPort() && body.GetPort() <= 0xffff, "model port %d", body.GetPort())}
	fields := []struct {
		name     string
		field    *protocol.ModelField
		measured bool
	}{
		{name: "served_name", field: body.GetServedName()},
		{name: "engine", field: body.GetEngine()},
		{name: "engine_version", field: body.GetEngineVersion()},
		{name: "quantization", field: body.GetQuantization()},
		{name: "weights_digest", field: body.GetWeightsDigest(), measured: true},
	}
	for _, item := range fields {
		if item.field == nil {
			continue
		}
		evidence := item.field.GetEvidence()
		checks = append(checks,
			recordBodyRule(len(item.field.GetValue()) <= settings.ModelFieldByteCount, "%s of %d bytes", item.name, len(item.field.GetValue())),
			recordBodyRule(RecordModelEvidenceDeclared <= evidence && evidence <= RecordModelEvidenceAttested, "%s evidence %d", item.name, evidence),
		)
		if writer {
			checks = append(checks,
				recordBodyRule(evidence != RecordModelEvidenceAttested, "%s claims attested evidence, which is reserved", item.name),
				recordBodyRule(item.field.GetValue() != "", "%s with no value", item.name),
				recordBodyRule((evidence == RecordModelEvidenceMeasured) == item.measured || evidence == RecordModelEvidenceAttested,
					"%s evidence %d: the weights digest alone is measured", item.name, evidence),
			)
		}
	}
	return errors.Join(checks...)
}

// ModelCallBody.route (DESIGN-COMPUTE §6.8): where a call ran. A hook's or a harness's own model_call has none.
const (
	RecordModelCallRouteLocal  = "local"
	RecordModelCallRouteTee    = "tee"
	RecordModelCallRouteDirect = "direct"
)

// model_call (RECORD.md section 12, DESIGN-COMPUTE §6.8, D-INFER-4): model, provider and request id within their bytes;
// a route, where there is one, of local, tee or direct; an attestation only on the TEE route; and the platform field at
// evidence 4, attested, only on the TEE route with the attestation set and naming the profile it verified, else at
// declared or reported. No other field of the body carries evidence, so nothing claims more than what is behind it:
// weaker evidence is never presented as attested (D-RECORD-11). A writer holds a body to it before it seals, and a
// reader after it opens one, so a stored body that claims an attestation it does not carry shows no body.
func recordModelCallValidate(body *protocol.ModelCallBody) error {
	settings := DefaultRecordBodySettings()
	route := body.GetRoute()
	checks := []error{
		recordBodyRule(len(body.GetModel()) <= settings.ModelCallFieldByteCount, "model of %d bytes", len(body.GetModel())),
		recordBodyRule(len(body.GetProvider()) <= settings.ModelCallFieldByteCount, "provider of %d bytes", len(body.GetProvider())),
		recordBodyRule(len(body.GetRequestId()) <= settings.ModelCallFieldByteCount, "request_id of %d bytes", len(body.GetRequestId())),
		recordBodyRule(route == "" || route == RecordModelCallRouteLocal || route == RecordModelCallRouteTee || route == RecordModelCallRouteDirect,
			"a route of %d bytes that is not local, tee or direct", len(route)),
		recordBodyRule(body.GetAttestation() == nil || route == RecordModelCallRouteTee, "an attestation off the tee route"),
	}
	if context := body.GetContext(); context != nil {
		checks = append(checks, recordCallContextValidate(settings, context))
	}
	if platform := body.GetPlatform(); platform != nil {
		evidence := platform.GetEvidence()
		attested := evidence == RecordModelEvidenceAttested
		verified := route == RecordModelCallRouteTee && body.GetAttestation() != nil && platform.GetValue() != "" &&
			platform.GetValue() == body.GetAttestation().GetProfileId()
		checks = append(checks,
			recordBodyRule(len(platform.GetValue()) <= settings.ModelFieldByteCount, "platform of %d bytes", len(platform.GetValue())),
			recordBodyRule(RecordModelEvidenceDeclared <= evidence && (evidence <= RecordModelEvidenceReported || attested), "platform evidence %d", evidence),
			recordBodyRule(!attested || verified, "a platform attested without a verified TEE attestation naming its profile"),
		)
	}
	return errors.Join(checks...)
}

// The kinds another ledger takes a copy of (RECORD.md section 6.5): context, change, the approval family, restore,
// coverage and cost, cost only while the Team's record_cost sends it to T, since a ledger copies T's entries alone.
var recordKindsLedgerCopied = []RecordKind{
	RecordKindContext,
	RecordKindChange,
	RecordKindApproval,
	RecordKindApprovalDecision,
	RecordKindApprovalCancel,
	RecordKindApprovalUse,
	RecordKindRestore,
	RecordKindCoverage,
	RecordKindCost,
}

// Whether another ledger takes a copy of kind's team entry.
func RecordKindLedgerCopied(kind RecordKind) bool {
	return slices.Contains(recordKindsLedgerCopied, kind)
}

// ledger_scope: repos by id and projects by key within their counts, and kinds only among those a ledger copies.
func recordLedgerScopeValidate(body *protocol.LedgerScopeBody) error {
	settings := DefaultRecordBodySettings()
	checks := []error{
		recordBodyRule(len(body.GetRepoIds()) <= settings.LedgerRepoCount, "%d ledger repos", len(body.GetRepoIds())),
		recordBodyRule(len(body.GetProjects()) <= settings.LedgerProjectCount, "%d ledger projects", len(body.GetProjects())),
		recordBodyRule(len(body.GetKinds()) <= len(recordKindsLedgerCopied), "%d ledger kinds", len(body.GetKinds())),
	}
	for _, repoId := range body.GetRepoIds() {
		checks = append(checks, recordBodyRule(len(repoId) == recordIdByteCount, "a ledger repo id of %d bytes", len(repoId)))
	}
	for _, project := range body.GetProjects() {
		checks = append(checks, recordBodyRule(1 <= len(project) && len(project) <= settings.ProjectByteCount, "a ledger project of %d bytes", len(project)))
	}
	seen := map[uint32]bool{}
	for _, kind := range body.GetKinds() {
		checks = append(checks, recordBodyRule(RecordKindLedgerCopied(RecordKind(kind)) && !seen[kind], "ledger kind %d twice, or one a ledger does not copy", kind))
		seen[kind] = true
	}
	return errors.Join(checks...)
}

// Parses stored as kind's body and holds it to RecordBodyValidate: the reader's check of an opened body. A Signed kind
// is parsed and checked by its own parser instead, and passes here.
func RecordBodyValidateStored(kind RecordKind, stored []byte) error {
	if _, _, signed := kind.NewSignedBody(); signed {
		return nil
	}
	// the directory's kinds through their bounded decoders (directory_decode.go)
	if directory, err := directoryValidateStoredBody(kind, stored); directory {
		return err
	}
	body, ok := kind.NewBody()
	if !ok {
		return nil
	}
	if err := proto.Unmarshal(stored, body); err != nil {
		return fmt.Errorf("%w: a body that does not parse as %s: %v", ErrRecordBodyOverCap, proto.MessageName(body), err)
	}
	return RecordBodyValidate(kind, body)
}

// claim, handoff, ask, answer, check and note. The targets' grammar is the record_append handler's (RECORD-M3-09).
func recordCoordinationValidate(kind RecordKind, body *protocol.CoordinationBody) error {
	settings := DefaultRecordBodySettings()
	textCap := settings.CoordinationTextByteCount
	if kind == RecordKindClaim || kind == RecordKindHandoff {
		textCap = settings.ClaimTextByteCount
	}
	return errors.Join(
		recordBodyRule(len(body.GetText()) <= textCap, "%s text of %d bytes", kind, len(body.GetText())),
		recordBodyRule(len(body.GetTargets()) <= settings.TargetCount, "%d targets", len(body.GetTargets())),
		recordBodyRule(body.GetExpiresMillis() == 0 || kind == RecordKindClaim || kind == RecordKindAsk, "expires on a %s", kind),
		recordBodyRule(recordBodyLength(body.GetClaimId(), recordIdByteCount, true) && (len(body.GetClaimId()) == 0 || kind == RecordKindClaim), "claim_id of %d bytes on a %s", len(body.GetClaimId()), kind),
		recordBodyRule(body.GetClaimState() == 0 || (kind == RecordKindClaim && body.GetClaimState() <= 2), "claim_state %d on a %s", body.GetClaimState(), kind),
		recordBodyRule(body.GetResult() == 0 || (kind == RecordKindCheck && body.GetResult() <= 3), "result %d on a %s", body.GetResult(), kind),
	)
}

// context.
func recordContextValidate(body *protocol.ContextBody) error {
	settings := DefaultRecordBodySettings()
	checks := []error{
		recordBodyRule(body.GetStage() == 1 || body.GetStage() == 2, "context stage %d", body.GetStage()),
		recordBodyRule(body.GetAgentLabel() == "" || recordAgentLabelPattern.MatchString(body.GetAgentLabel()), "an agent label outside [a-z0-9-]{1,64}"),
		recordBodyRule(len(body.GetSessionIds()) <= settings.SessionIdCount, "%d session ids", len(body.GetSessionIds())),
		recordBodyRule(len(body.GetModel()) <= settings.ModelByteCount, "model of %d bytes", len(body.GetModel())),
		recordBodyRule(len(body.GetPermissionMode()) <= settings.PermissionModeByteCount, "permission_mode of %d bytes", len(body.GetPermissionMode())),
		recordBodyRule(recordBodyLength(body.GetRepoId(), recordIdByteCount, true), "repo_id of %d bytes", len(body.GetRepoId())),
		recordBodyRule(len(body.GetProject()) <= settings.ProjectByteCount, "project of %d bytes", len(body.GetProject())),
		recordBodyRule(len(body.GetBranch()) <= settings.BranchByteCount, "branch of %d bytes", len(body.GetBranch())),
		recordBodyRule(len(body.GetTitle()) <= settings.TitleByteCount, "title of %d bytes", len(body.GetTitle())),
		recordBodyRule(len(body.GetInstructionFiles()) <= settings.InstructionFileCount, "%d instruction files", len(body.GetInstructionFiles())),
		recordBodyRule(len(body.GetTruncations()) <= settings.TruncationCount, "%d truncations", len(body.GetTruncations())),
		recordBodyRule(recordBodyLength(body.GetConfigSha256(), recordHashByteCount, true), "config_sha256 of %d bytes", len(body.GetConfigSha256())),
		recordBodyRule(recordBodyLength(body.GetContinuesRunId(), recordIdByteCount, true), "continues_run_id of %d bytes", len(body.GetContinuesRunId())),
		recordBodyRule(recordBodyLength(body.GetContinuesEntryId(), recordIdByteCount, true), "continues_entry_id of %d bytes", len(body.GetContinuesEntryId())),
	}
	for _, sessionId := range body.GetSessionIds() {
		checks = append(checks, recordBodyRule(len(sessionId) <= settings.SessionIdByteCount, "a session id of %d bytes", len(sessionId)))
	}
	for _, file := range body.GetInstructionFiles() {
		checks = append(checks,
			recordBodyRule(1 <= file.GetScope() && file.GetScope() <= 3, "instruction file scope %d", file.GetScope()),
			recordBodyRule(len(file.GetName()) <= settings.FileNameByteCount, "an instruction file name of %d bytes", len(file.GetName())),
			recordBodyRule(recordBodyLength(file.GetSha256(), recordHashByteCount, true), "an instruction file sha256 of %d bytes", len(file.GetSha256())),
		)
	}
	for _, truncation := range body.GetTruncations() {
		checks = append(checks, recordBodyRule(len(truncation) <= settings.TruncationByteCount, "a truncation of %d bytes", len(truncation)))
	}
	// QD-900's prompts: none empty, and together within the cap
	promptByteCount := 0
	for _, prompt := range body.GetPrompts() {
		promptByteCount += len(prompt)
		checks = append(checks, recordBodyRule(prompt != "", "an empty prompt"))
	}
	checks = append(checks, recordBodyRule(promptByteCount <= settings.ContextPromptByteCount, "prompts of %d bytes", promptByteCount))
	return errors.Join(checks...)
}

// change.
func recordChangeValidate(body *protocol.ChangeBody) error {
	settings := DefaultRecordBodySettings()
	checks := []error{
		recordBodyRule(recordBodyLength(body.GetRepoId(), recordIdByteCount, true), "repo_id of %d bytes", len(body.GetRepoId())),
		recordBodyRule(len(body.GetProject()) <= settings.ProjectByteCount, "project of %d bytes", len(body.GetProject())),
		recordBodyRule(len(body.GetCommits()) <= settings.CommitCount, "%d commits", len(body.GetCommits())),
		recordBodyRule(len(body.GetPaths()) <= settings.ChangedPathCount, "%d changed paths", len(body.GetPaths())),
		recordBodyRule(body.GetCapture()&^7 == 0, "capture bits %#x", body.GetCapture()),
	}
	for _, path := range body.GetPaths() {
		checks = append(checks,
			recordBodyRule(recordBodyLength(path.GetBeforeSha256(), recordHashByteCount, true), "before_sha256 of %d bytes", len(path.GetBeforeSha256())),
			recordBodyRule(recordBodyLength(path.GetAfterSha256(), recordHashByteCount, true), "after_sha256 of %d bytes", len(path.GetAfterSha256())),
			recordBodyRule(path.GetAttribution() <= 3, "attribution %d", path.GetAttribution()),
			recordBodyRule(recordBodyLength(path.GetBlobEntryId(), recordIdByteCount, true), "blob_entry_id of %d bytes", len(path.GetBlobEntryId())),
		)
	}
	return errors.Join(checks...)
}

// membership: §5.4's events by their numbers, and the evidence a member's own device revocation names (§5.6).
func recordMembershipValidate(body *protocol.MembershipBody) error {
	return errors.Join(
		recordBodyRule(1 <= body.GetEvent() && body.GetEvent() <= 6, "membership event %d", body.GetEvent()),
		recordBodyRule(recordBodyLength(body.GetMemberId(), recordIdByteCount, true), "member_id of %d bytes", len(body.GetMemberId())),
		recordBodyRule(recordBodyLength(body.GetSidecarId(), recordIdByteCount, true), "sidecar_id of %d bytes", len(body.GetSidecarId())),
		recordBodyRule(recordBodyLength(body.GetGroupId(), recordIdByteCount, true), "group_id of %d bytes", len(body.GetGroupId())),
		recordBodyRule(recordBodyLength(body.GetStatementSha256(), recordHashByteCount, true), "statement_sha256 of %d bytes", len(body.GetStatementSha256())),
		recordBodyRule(body.GetEvidence() <= 2, "evidence %d", body.GetEvidence()),
		recordBodyRule((body.GetEvidence() == 1) == (len(body.GetAssertion()) != 0), "an assertion with evidence %d", body.GetEvidence()),
	)
}

// route (M4): opened or closed, a reason only once closed.
func recordRouteBodyValidate(body *protocol.RouteBody) error {
	return errors.Join(
		recordBodyRule(body.GetEvent() == 1 || body.GetEvent() == 2, "route event %d", body.GetEvent()),
		recordBodyRule(1 <= body.GetKind() && body.GetKind() <= 4, "route kind %d", body.GetKind()),
		recordBodyRule(recordBodyLength(body.GetTargetSidecarId(), recordIdByteCount, true), "target_sidecar_id of %d bytes", len(body.GetTargetSidecarId())),
		recordBodyRule(recordBodyLength(body.GetApprovalId(), recordIdByteCount, true), "approval_id of %d bytes", len(body.GetApprovalId())),
		recordBodyRule(recordClosedReason(body.GetEvent(), body.GetReason()), "route reason %d at event %d", body.GetReason(), body.GetEvent()),
		recordBodyRule(body.GetTargetPort() <= 65535, "target_port %d", body.GetTargetPort()),
	)
}

// publish (M5): as route.
func recordPublishBodyValidate(body *protocol.PublishBody) error {
	return errors.Join(
		recordBodyRule(body.GetEvent() == 1 || body.GetEvent() == 2, "publish event %d", body.GetEvent()),
		recordBodyRule(body.GetHost() != "", "publish with no host"),
		recordBodyRule(body.GetPort() <= 65535, "port %d", body.GetPort()),
		recordBodyRule(recordBodyLength(body.GetApprovalId(), recordIdByteCount, true), "approval_id of %d bytes", len(body.GetApprovalId())),
		recordBodyRule(recordClosedReason(body.GetEvent(), body.GetReason()), "publish reason %d at event %d", body.GetReason(), body.GetEvent()),
	)
}

// A closed route's or publish's reason is 1 to 4 (RouteBody's comment); an opened one has none.
func recordClosedReason(event uint32, reason uint32) bool {
	if event == 2 {
		return 1 <= reason && reason <= 4
	}
	return reason == 0
}

// coverage: codes only, so V's and T's entries of a run hold the same lists.
func recordCoverageValidate(body *protocol.Coverage) error {
	checks := []error{
		recordBodyRule(recordBodyLength(body.GetRunId(), recordIdByteCount, true), "run_id of %d bytes", len(body.GetRunId())),
		recordBodyRule(body.GetFirstSeq() <= body.GetLastSeq(), "first_seq %d past last_seq %d", body.GetFirstSeq(), body.GetLastSeq()),
	}
	for _, source := range body.GetSources() {
		checks = append(checks, recordBodyRule(RecordCoverageSourceKnown(source), "a coverage source section 6.4 does not name"))
	}
	for _, gap := range body.GetGaps() {
		_, _, ok := RecordCoverageGapParse(gap)
		checks = append(checks, recordBodyRule(ok, "a coverage gap that is no code or code:count"))
	}
	// DESIGN-COMPUTE §24.10's bodies_dropped: ranges of seqs from 1, each first <= last, ascending and apart
	var previousLast uint64
	for index, dropped := range body.GetBodiesDropped() {
		checks = append(checks, recordBodyRule(1 <= dropped.GetFirst() && dropped.GetFirst() <= dropped.GetLast() && (index == 0 || previousLast < dropped.GetFirst()),
			"a bodies_dropped range %d to %d that is empty, from 0, or not after the one before", dropped.GetFirst(), dropped.GetLast()))
		previousLast = dropped.GetLast()
	}
	return errors.Join(checks...)
}

// What a builder of §17's route entry fills (M4): RouteBody's fields, checked.
type RecordRouteArgs struct {
	// 1 opened, 2 closed
	Event uint32
	// 1 forward, 2 expose, 3 route, 4 map (§17.8)
	Kind            uint32
	RuleId          []byte
	TargetSidecarId *Id
	TargetPort      uint32
	Cidrs           []string
	ExpiresMillis   int64
	ApprovalId      *Id
	// closed: 1 expired, 2 revoked, 3 withdrawn, 4 suspended
	Reason uint32
}

// A route body for the sidecar that files the grant or rule (RECORD.md section 6.3's route row), held to its rules.
func NewRecordRouteBody(args *RecordRouteArgs) (*protocol.RouteBody, error) {
	body := &protocol.RouteBody{
		Event:         args.Event,
		Kind:          args.Kind,
		RuleId:        slices.Clone(args.RuleId),
		TargetPort:    args.TargetPort,
		Cidrs:         slices.Clone(args.Cidrs),
		ExpiresMillis: args.ExpiresMillis,
		Reason:        args.Reason,
	}
	if args.TargetSidecarId != nil {
		body.TargetSidecarId = args.TargetSidecarId.Bytes()
	}
	if args.ApprovalId != nil {
		body.ApprovalId = args.ApprovalId.Bytes()
	}
	if err := recordRouteBodyValidate(body); err != nil {
		return nil, err
	}
	return body, nil
}

// What a builder of §13's publish entry fills (M5): PublishBody's fields, checked.
type RecordPublishArgs struct {
	// 1 opened, 2 closed
	Event uint32
	Host  string
	Port  uint32
	// acl.proto's AclAudience and AclAppMode, resolved non-zero as the action writes them
	Audience      uint32
	AppMode       uint32
	ExpiresMillis int64
	ApprovalId    *Id
	// closed: as RouteBody's
	Reason uint32
}

// A publish body for the publishing sidecar (RECORD.md section 6.3's publish row), held to its rules.
func NewRecordPublishBody(args *RecordPublishArgs) (*protocol.PublishBody, error) {
	body := &protocol.PublishBody{
		Event:         args.Event,
		Host:          args.Host,
		Port:          args.Port,
		Audience:      args.Audience,
		AppMode:       args.AppMode,
		ExpiresMillis: args.ExpiresMillis,
		Reason:        args.Reason,
	}
	if args.ApprovalId != nil {
		body.ApprovalId = args.ApprovalId.Bytes()
	}
	if err := recordPublishBodyValidate(body); err != nil {
		return nil, err
	}
	return body, nil
}

// A kind whose T entry this does not make: its body never reaches T (raw capture and the vault's own kinds), or
// T's entry of it is no projection, as the approval family's, which §16.8 copies whole.
var ErrRecordProjectionNone = errors.New("record kind has no team projection")

// Section 6.3's kinds that go to V and T as two entries, the T one a projection (section 4.2's twice row): cost only
// while the Team's record_cost is on (row 28), which routing reads (record_team.go), and RunCostBody marks no field V:.
var recordKindsProjected = []RecordKind{
	RecordKindContext,
	RecordKindChange,
	RecordKindPermission,
	RecordKindRestore,
	RecordKindCoverage,
	RecordKindCost,
	// DESIGN-COMPUTE.md §28.12: V and T, T's copy holding no text
	RecordKindSupportMessage,
}

// record.proto's V: marks, by message and field name: what T's projection leaves empty. record_body_test.go holds this
// table to record.proto's comments.
var recordTeamStrippedFields = map[protoreflect.FullName][]protoreflect.Name{
	"urnetwork.sidecar.ContextBody":        {"branch", "title", "truncations", "prompts"},
	"urnetwork.sidecar.InstructionFile":    {"name"},
	"urnetwork.sidecar.ChangedPath":        {"path", "blob_entry_id"},
	"urnetwork.sidecar.PermissionBody":     {"tool_name", "arguments_sha256"},
	"urnetwork.sidecar.RestoreBody":        {"paths"},
	"urnetwork.sidecar.SupportMessageBody": {"text", "agent_label", "bundle", "files"},
}

// ContextBody.project, which T leaves empty when the run's repo is private (its comment).
const recordContextProjectField protoreflect.Name = "project"

// T's projection of a vault body of kind (RECORD.md section 4.2's twice row): a copy with every V: field empty, and
// ContextBody's and ChangeBody's project too where repoPrivate says the run's repo is private. ErrRecordProjectionNone
// for a kind section 6.3 does not send to V and T as two entries. The caller writes the projection under its own
// chain position, key and commitment, with one ContentRef to the vault entry, which is sealed first (RECORD-M6-01).
func RecordProjectForTeam(kind RecordKind, body proto.Message, repoPrivate bool) (proto.Message, error) {
	if !slices.Contains(recordKindsProjected, kind) {
		return nil, fmt.Errorf("%w: %s", ErrRecordProjectionNone, kind)
	}
	if err := RecordBodyValidate(kind, body); err != nil {
		return nil, err
	}
	projection := proto.Clone(body)
	recordStripTeamFields(projection.ProtoReflect(), repoPrivate)
	return projection, nil
}

// Clears the V: fields of message and of every message it holds.
func recordStripTeamFields(message protoreflect.Message, repoPrivate bool) {
	fullName := message.Descriptor().FullName()
	fields := message.Descriptor().Fields()
	for _, name := range recordTeamStrippedFields[fullName] {
		if field := fields.ByName(name); field != nil {
			message.Clear(field)
		}
	}
	if repoPrivate && (fullName == "urnetwork.sidecar.ContextBody" || fullName == "urnetwork.sidecar.ChangeBody") {
		message.Clear(fields.ByName(recordContextProjectField))
	}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Message() == nil || field.IsMap() {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i += 1 {
				recordStripTeamFields(list.Get(i).Message(), repoPrivate)
			}
			return true
		}
		recordStripTeamFields(value.Message(), repoPrivate)
		return true
	})
}
