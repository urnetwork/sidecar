// RECORD.md section 6.4's body rules, written once, on every leg: each body's caps, which a writer holds a body to
// before it seals (RecordBodyValidate refuses an overrun) and a reader holds a stored body to after it opens (an
// overrun is shown as no body, with record_alarm over_cap); Coverage's source and gap codes, which carry no path or
// text; and T's projection, RecordProjectForTeam, which leaves empty every field record.proto marks V:, so what reaches
// the team record is a function of the body rather than a habit of its callers (R-RECORD-2, I-20). The caps are the
// format's, as record.proto's comments write them, not tunables: §16.7's capture settings may cut lower, never higher.
//
// Hook payloads and agent text reach these bodies redacted already (§16.7, D-MCP-5): this layer checks what it is
// given and redacts nothing itself, so a credential is kept out by the redactor before sealing (I-7). Bodies of the
// kinds M6 adds (model, cost, attestation, disclosure, the log upkeep, file_event, model_call) have their caps in
// RECORD.md sections 10 to 13 and their own tasks; until those land they pass here unchecked, and nothing writes one.
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

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// Section 6.4's caps, as record.proto's comments write them.
const (
	recordClaimTextByteCount        = 512
	recordCoordinationTextByteCount = 1024
	recordTargetCount               = 16
	recordAgentLabelByteCount       = 64
	recordSessionIdCount            = 4
	recordSessionIdByteCount        = 64
	recordModelByteCount            = 64
	recordPermissionModeByteCount   = 32
	recordProjectByteCount          = 128
	recordBranchByteCount           = 128
	recordTitleByteCount            = 120
	recordInstructionFileCount      = 64
	recordFileNameByteCount         = 128
	recordTruncationCount           = 16
	recordTruncationByteCount       = 128
	recordCommitCount               = 64
	recordChangedPathCount          = 4096
	recordToolNameByteCount         = 64
	recordRestoredPathCount         = 4096
	recordRestoredCopyCount         = 2
	recordReadObjectCount           = 64
	recordErasureEntryCount         = 1024
	recordInventoryAgentCount       = 64
	recordInventoryHarnessCount     = 8
	recordInventoryModelCount       = 16
	recordInventoryRepoCount        = 64
	recordCopyEntryCount            = 64
	recordCaptureByteCount          = 1024 * 1024
	recordBlobByteCount             = 8 * 1024 * 1024
	recordToolPathCount             = 256
)

// A body breaks one of section 6.4's rules: a cap, a length, or a value its field does not take. A writer refuses
// it; a reader shows the entry with no body and raises over_cap.
var ErrRecordBodyOverCap = errors.New("record body over its caps")

// Coverage.sources' codes (RECORD.md section 6.4).
const (
	RecordCoverageSourceMcp        = "mcp"
	RecordCoverageSourceHooks      = "hooks"
	RecordCoverageSourceTranscript = "transcript"
	RecordCoverageSourceScan       = "scan"
	RecordCoverageSourceTelemetry  = "telemetry"
	RecordCoverageSourceFileEvents = "file_events"
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
)

var recordCoverageSources = []string{
	RecordCoverageSourceMcp,
	RecordCoverageSourceHooks,
	RecordCoverageSourceTranscript,
	RecordCoverageSourceScan,
	RecordCoverageSourceTelemetry,
	RecordCoverageSourceFileEvents,
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
	if body == nil {
		return recordBodyRule(false, "no body")
	}
	if want, ok := kind.NewBody(); ok && proto.MessageName(want) != proto.MessageName(body) {
		return recordBodyRule(false, "kind %s takes %s, not %s", kind, proto.MessageName(want), proto.MessageName(body))
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
			recordBodyRule(len(typed.GetPermissionMode()) <= recordPermissionModeByteCount, "permission_mode of %d bytes", len(typed.GetPermissionMode())),
			recordBodyRule(typed.GetToolClass() <= 5, "tool_class %d", typed.GetToolClass()),
			recordBodyRule(len(typed.GetToolName()) <= recordToolNameByteCount, "tool_name of %d bytes", len(typed.GetToolName())),
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
			recordBodyRule(len(typed.GetPaths()) <= recordRestoredPathCount, "%d restored paths", len(typed.GetPaths())),
		}
		for _, path := range typed.GetPaths() {
			checks = append(checks, recordBodyRule(len(path.GetCopies()) <= recordRestoredCopyCount, "%d copies of a restored path", len(path.GetCopies())))
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
			recordBodyRule(1 <= len(typed.GetObjectIds()) && len(typed.GetObjectIds()) <= recordReadObjectCount, "%d object ids", len(typed.GetObjectIds())),
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
			recordBodyRule(1 <= len(typed.GetEntryIds()) && len(typed.GetEntryIds()) <= recordErasureEntryCount, "%d erased entries", len(typed.GetEntryIds())),
			recordBodyRule(1 <= typed.GetReason() && typed.GetReason() <= 4, "erasure reason %d", typed.GetReason()),
			recordBodyRule((typed.GetReason() == 4) == (len(typed.GetRequestId()) == recordIdByteCount), "request_id of %d bytes for reason %d", len(typed.GetRequestId()), typed.GetReason()),
		}
		for _, entryId := range typed.GetEntryIds() {
			checks = append(checks, recordBodyRule(len(entryId) == recordIdByteCount, "an erased entry id of %d bytes", len(entryId)))
		}
		return errors.Join(checks...)
	case *protocol.InventoryBody:
		checks := []error{recordBodyRule(len(typed.GetAgents()) <= recordInventoryAgentCount, "%d inventory agents", len(typed.GetAgents()))}
		for _, agent := range typed.GetAgents() {
			checks = append(checks,
				recordBodyRule(len(agent.GetHarnesses()) <= recordInventoryHarnessCount, "%d harnesses", len(agent.GetHarnesses())),
				recordBodyRule(len(agent.GetModels()) <= recordInventoryModelCount, "%d models", len(agent.GetModels())),
				recordBodyRule(len(agent.GetRepoIds()) <= recordInventoryRepoCount, "%d repo ids", len(agent.GetRepoIds())),
				recordBodyRule(len(agent.GetProjects()) <= recordInventoryRepoCount, "%d projects", len(agent.GetProjects())),
			)
		}
		return errors.Join(checks...)
	case *protocol.CopyBody:
		return recordBodyRule(len(typed.GetEntries()) <= recordCopyEntryCount, "%d copied entries", len(typed.GetEntries()))
	case *protocol.TranscriptBody:
		return recordBodyRule(len(typed.GetLines()) <= recordCaptureByteCount, "transcript lines of %d bytes", len(typed.GetLines()))
	case *protocol.ToolCallBody:
		return errors.Join(
			recordBodyRule(len(typed.GetInput())+len(typed.GetOutput()) <= recordCaptureByteCount, "tool input and output of %d bytes", len(typed.GetInput())+len(typed.GetOutput())),
			recordBodyRule(len(typed.GetPaths()) <= recordToolPathCount, "%d tool paths", len(typed.GetPaths())),
			recordBodyRule(typed.GetToolClass() <= 5, "tool_class %d", typed.GetToolClass()),
		)
	case *protocol.HookEventBody:
		return errors.Join(
			recordBodyRule(len(typed.GetPayload()) <= recordCaptureByteCount, "hook payload of %d bytes", len(typed.GetPayload())),
			recordBodyRule(recordBodyLength(typed.GetArgumentsSha256(), recordHashByteCount, true), "arguments_sha256 of %d bytes", len(typed.GetArgumentsSha256())),
		)
	case *protocol.BlobBody:
		return errors.Join(
			recordBodyRule(len(typed.GetContent()) <= recordBlobByteCount, "blob content of %d bytes", len(typed.GetContent())),
			recordBodyRule(recordBodyLength(typed.GetSha256(), recordHashByteCount, true), "blob sha256 of %d bytes", len(typed.GetSha256())),
		)
	case *protocol.Coverage:
		return recordCoverageValidate(typed)
	}
	return nil
}

// Parses stored as kind's body and holds it to RecordBodyValidate: the reader's check of an opened body. A Signed kind
// is parsed and checked by its own parser instead, and passes here.
func RecordBodyValidateStored(kind RecordKind, stored []byte) error {
	if _, _, signed := kind.NewSignedBody(); signed {
		return nil
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
	textCap := recordCoordinationTextByteCount
	if kind == RecordKindClaim || kind == RecordKindHandoff {
		textCap = recordClaimTextByteCount
	}
	return errors.Join(
		recordBodyRule(len(body.GetText()) <= textCap, "%s text of %d bytes", kind, len(body.GetText())),
		recordBodyRule(len(body.GetTargets()) <= recordTargetCount, "%d targets", len(body.GetTargets())),
		recordBodyRule(body.GetExpiresMillis() == 0 || kind == RecordKindClaim || kind == RecordKindAsk, "expires on a %s", kind),
		recordBodyRule(recordBodyLength(body.GetClaimId(), recordIdByteCount, true) && (len(body.GetClaimId()) == 0 || kind == RecordKindClaim), "claim_id of %d bytes on a %s", len(body.GetClaimId()), kind),
		recordBodyRule(body.GetClaimState() == 0 || (kind == RecordKindClaim && body.GetClaimState() <= 2), "claim_state %d on a %s", body.GetClaimState(), kind),
		recordBodyRule(body.GetResult() == 0 || (kind == RecordKindCheck && body.GetResult() <= 3), "result %d on a %s", body.GetResult(), kind),
	)
}

// context.
func recordContextValidate(body *protocol.ContextBody) error {
	checks := []error{
		recordBodyRule(body.GetStage() == 1 || body.GetStage() == 2, "context stage %d", body.GetStage()),
		recordBodyRule(body.GetAgentLabel() == "" || recordAgentLabelPattern.MatchString(body.GetAgentLabel()), "an agent label outside [a-z0-9-]{1,64}"),
		recordBodyRule(len(body.GetSessionIds()) <= recordSessionIdCount, "%d session ids", len(body.GetSessionIds())),
		recordBodyRule(len(body.GetModel()) <= recordModelByteCount, "model of %d bytes", len(body.GetModel())),
		recordBodyRule(len(body.GetPermissionMode()) <= recordPermissionModeByteCount, "permission_mode of %d bytes", len(body.GetPermissionMode())),
		recordBodyRule(recordBodyLength(body.GetRepoId(), recordIdByteCount, true), "repo_id of %d bytes", len(body.GetRepoId())),
		recordBodyRule(len(body.GetProject()) <= recordProjectByteCount, "project of %d bytes", len(body.GetProject())),
		recordBodyRule(len(body.GetBranch()) <= recordBranchByteCount, "branch of %d bytes", len(body.GetBranch())),
		recordBodyRule(len(body.GetTitle()) <= recordTitleByteCount, "title of %d bytes", len(body.GetTitle())),
		recordBodyRule(len(body.GetInstructionFiles()) <= recordInstructionFileCount, "%d instruction files", len(body.GetInstructionFiles())),
		recordBodyRule(len(body.GetTruncations()) <= recordTruncationCount, "%d truncations", len(body.GetTruncations())),
		recordBodyRule(recordBodyLength(body.GetConfigSha256(), recordHashByteCount, true), "config_sha256 of %d bytes", len(body.GetConfigSha256())),
		recordBodyRule(recordBodyLength(body.GetContinuesRunId(), recordIdByteCount, true), "continues_run_id of %d bytes", len(body.GetContinuesRunId())),
		recordBodyRule(recordBodyLength(body.GetContinuesEntryId(), recordIdByteCount, true), "continues_entry_id of %d bytes", len(body.GetContinuesEntryId())),
	}
	for _, sessionId := range body.GetSessionIds() {
		checks = append(checks, recordBodyRule(len(sessionId) <= recordSessionIdByteCount, "a session id of %d bytes", len(sessionId)))
	}
	for _, file := range body.GetInstructionFiles() {
		checks = append(checks,
			recordBodyRule(1 <= file.GetScope() && file.GetScope() <= 3, "instruction file scope %d", file.GetScope()),
			recordBodyRule(len(file.GetName()) <= recordFileNameByteCount, "an instruction file name of %d bytes", len(file.GetName())),
			recordBodyRule(recordBodyLength(file.GetSha256(), recordHashByteCount, true), "an instruction file sha256 of %d bytes", len(file.GetSha256())),
		)
	}
	for _, truncation := range body.GetTruncations() {
		checks = append(checks, recordBodyRule(len(truncation) <= recordTruncationByteCount, "a truncation of %d bytes", len(truncation)))
	}
	return errors.Join(checks...)
}

// change.
func recordChangeValidate(body *protocol.ChangeBody) error {
	checks := []error{
		recordBodyRule(recordBodyLength(body.GetRepoId(), recordIdByteCount, true), "repo_id of %d bytes", len(body.GetRepoId())),
		recordBodyRule(len(body.GetProject()) <= recordProjectByteCount, "project of %d bytes", len(body.GetProject())),
		recordBodyRule(len(body.GetCommits()) <= recordCommitCount, "%d commits", len(body.GetCommits())),
		recordBodyRule(len(body.GetPaths()) <= recordChangedPathCount, "%d changed paths", len(body.GetPaths())),
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

// Section 6.3's kinds that go to V and T as two entries, the T one a projection (section 4.2's twice row).
var recordKindsProjected = []RecordKind{
	RecordKindContext,
	RecordKindChange,
	RecordKindPermission,
	RecordKindRestore,
	RecordKindCoverage,
}

// record.proto's V: marks, by message and field name: what T's projection leaves empty. record_body_test.go holds this
// table to record.proto's comments.
var recordTeamStrippedFields = map[protoreflect.FullName][]protoreflect.Name{
	"urnetwork.sidecar.ContextBody":     {"branch", "title", "truncations"},
	"urnetwork.sidecar.InstructionFile": {"name"},
	"urnetwork.sidecar.ChangedPath":     {"path", "blob_entry_id"},
	"urnetwork.sidecar.PermissionBody":  {"tool_name", "arguments_sha256"},
	"urnetwork.sidecar.RestoreBody":     {"paths"},
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
