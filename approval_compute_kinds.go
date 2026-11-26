// DESIGN-COMPUTE.md §16.3's outward actions, kinds 19 to 26 appended to §5.4's list, and 27, support_send, beside them
// (approval_compute_support.go) (D-CACL-2, D-CACL-5;
// CACL-M11-04), each through Sidecar.Authorize, each at CanonicalAction version 5 alone, which an approver, spender or
// gate that does not know the version refuses whole. record.proto's SidecarActionKind holds the same values, which
// record_kind_test.go checks, and sidecarGateKinds lists each, so every kind reaches the gate.
//
// Version 5's rules (CACL-M12-01), which every builder, approver, spender and gate holds through
// canonicalActionCheck: each kind's row, appended to canonicalActionKindRows, at version 5 alone; and what a row
// cannot say:
//
//	fields     a version-5 action sets only kind, version and its kind's fields, never 37, 40 or 41, and no field
//	           past 41 is set at any other version; field 49, took_tainted, only on kind 5 (egress_change), whose
//	           version 5 it is; field 70 only on kinds 23 to 27
//	scope      no template: every use of a version-5 action is its own approval
//	auto       field 70's basis 1 (taint) or 2 (always), its rules nonzero, ascending and among §27.7's rules that
//	           follow from the action alone, numbered in its table's order (QD-1371): other_member 1, reaches_people 2,
//	           unclassified 3, own_definition 4, interactive 5, continue_run 6, private_container 7, amount 8, secret 9,
//	           hidden_text 10; 11 to 14 are checked at the decision and never ride the action
//	limits     a send's stdin and a call's body at most 32 KiB, the call's body_sha256 over exactly that body, and 1
//	           to 20 events on kind 25 (CanonicalActionSettings)
//	shapes     ids at 16 bytes, hashes at 32, every enumerated value one §16.3 names, hosts in their one form
//	           (lowercase punycode, as canonicalActionDomainForm holds a domain), no empty entry in a list, and no field
//	           this build cannot name at any depth; field 39 auto, exits or none, BridgeEgressMode's, and on kind 24
//	           also 4, direct, the receiving enclave's default egress off (QD-1391), which §11.8 allows a create
//	           never, an enclave's egress turning direct only by kind 20
//	binding    a kind-24 send that continues or crosses nothing hashes field 46 exactly as stored in field 3, so its
//	           approval binds what leaves (approvalComputeStoredCheck); a continuation's or crossing's field 3 hashes
//	           the node list it names, which its builder holds
//
// Field 38 at version 5 is a sealed CanonicalActionDetail5, kinds 19's and 21's alone (approval_compute_detail.go). A
// server path takes kind 19's and 21's version-5 actions alone, the broker's create and raise
// (CheckCanonicalActionForServer). Each kind's effect lookup is its filing area's (ENC 19, 20, 22; BAL 21; FETCH 23;
// HARN, SKILL and SSH 24; MAILCAL 25; CONN 26), so the gate refuses each kind's spend until its area registers one
// (record_effect.go).
//
// On every leg: the gate's kind list and the parsers read them. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	// Creating an enclave, a start that changes its shape or provider, or any start a tool or MCP asks for (§11.7).
	SidecarActionEnclaveCreate SidecarActionKind = 19
	// Turning an enclave's default egress off, so its traffic leaves through the provider and the miner sees its
	// metadata (§11.8).
	SidecarActionEnclaveEgressDirect SidecarActionKind = 20
	// An agent or a person passing a compute budget, or a gateway grant made or raised above the server's default
	// (§7.4, §8.6, §16.4).
	SidecarActionComputeBudgetRaise SidecarActionKind = 21
	// Removing an enclave, and what that erases (§11.11).
	SidecarActionEnclaveDelete SidecarActionKind = 22
	// An agent in a tainted run fetching a URL it composed (§22.5).
	SidecarActionFetchUnlistedUrl SidecarActionKind = 23
	// A tainted run sending into an enclave whose egress is not none, or to another member's agent or enclave, at
	// every entry point §16.3 lists (§7.8).
	SidecarActionTaintedSend SidecarActionKind = 24
	// An agent's addition, change or removal of calendar events from a tainted run, or of any event with attendees
	// (§23.9).
	SidecarActionCalendarWrite SidecarActionKind = 25
	// An agent's write or send to a connected service from a tainted run (§25.10).
	SidecarActionServiceWrite SidecarActionKind = 26
)

// Whether kind is one of §16.3's, which CanonicalAction version 5 alone holds.
func approvalComputeKind(kind SidecarActionKind) bool {
	return SidecarActionEnclaveCreate <= kind && kind <= SidecarActionSupportSend
}

// CanonicalAction's field numbers version 5 names (§16.3), beside the rules file's.
const (
	canonicalActionFieldBodySha256       = 3
	canonicalActionFieldHost             = 5
	canonicalActionFieldSubject          = 29
	canonicalActionFieldEnclave          = 42
	canonicalActionFieldBudget           = 43
	canonicalActionFieldUrl              = 44
	canonicalActionFieldTool             = 45
	canonicalActionFieldSend             = 46
	canonicalActionFieldContext          = 47
	canonicalActionFieldTaintReasons     = 48
	canonicalActionFieldTookTainted      = 49
	canonicalActionFieldCalendarLabel    = 50
	canonicalActionFieldCalendarHost     = 51
	canonicalActionFieldCalendarAudience = 52
	canonicalActionFieldCalendarEvents   = 53
	canonicalActionFieldCalendarLink     = 54
	canonicalActionFieldCalendarTarget   = 55
	canonicalActionFieldCalendarName     = 56
	canonicalActionFieldServiceCall      = 60
	canonicalActionFieldAuto             = 70
)

// The values version 5's uint32 fields carry, as §16.3, §23.9, §25.10 and §27.9 name them, 0 meaning none where a
// field allows it.
const (
	// BudgetFields.period
	approvalComputeBudgetPeriodDay   uint32 = 1
	approvalComputeBudgetPeriodMonth uint32 = 2
	approvalComputeBudgetPeriodRun   uint32 = 3
	// SendFields.mode: 0 a message, then §7.10's prompt, steer and follow_up
	approvalComputeSendModeMessage  uint32 = 0
	approvalComputeSendModeFollowUp uint32 = 3
	// ContextFields.act
	approvalComputeContextActContinue uint32 = 1
	approvalComputeContextActCross    uint32 = 2
	// CalendarEventAction.operation
	approvalComputeEventOperationAdd    uint32 = 1
	approvalComputeEventOperationChange uint32 = 2
	approvalComputeEventOperationRemove uint32 = 3
	// ServiceCallFields.class
	approvalComputeServiceClassWrite uint32 = 1
	approvalComputeServiceClassSend  uint32 = 2
	// AutoFields.basis: outward only because the run is tainted, or outward in any run
	approvalComputeAutoBasisTaint  uint32 = 1
	approvalComputeAutoBasisAlways uint32 = 2
	// CanonicalActionDetail5.role
	approvalComputeDetailRoleAgents  uint32 = 1
	approvalComputeDetailRoleIndexer uint32 = 2
	// Field 39's value at version 5 alone for §11.8's direct, an enclave's default egress off, beside BridgeEgressMode's
	// auto, exits and none, 1 to 3, which it leaves as they are (QD-1391)
	approvalComputeEgressModeDirect uint32 = 4
)

// §27.7's rules that follow from the action alone, the ones field 70 may name, in its table's order from 1 (QD-1371):
// other_member to hidden_text. new_destination 11, audience 12, flagged_url 13 and inputs_unknown 14 are checked at the
// decision, never in the action, which a retried call rebuilds byte for byte.
const (
	approvalComputeAutoRuleFirst uint32 = 1
	approvalComputeAutoRuleLast  uint32 = 10
)

// The rows, version 5's alone, which canonicalActionKindRows appends: §16.3's field list read per kind (D-CACL-5).
// Kinds 19 and 21 are the broker's gates' (POST compute/v1/enclaves, POST compute/v1/budget/raise), which see their
// Server fields; what those gates do not see rides sealed in field 38. Every other kind reaches no server.
var approvalComputeKindRows = []*CanonicalActionKindFields{
	{
		// enclave_create: field 42's shape, provider, label and price per hour, field 39's mode at create, and its name
		// and role sealed in field 38
		Kind: SidecarActionEnclaveCreate,
		Required: []protoreflect.FieldNumber{
			canonicalActionFieldSealedDetail, canonicalActionFieldEgressMode, canonicalActionFieldEnclave,
		},
		Versions: []uint32{canonicalActionVersionCompute},
		Server: []protoreflect.FieldNumber{
			canonicalActionFieldSealedDetail, canonicalActionFieldEgressMode, canonicalActionFieldEnclave,
		},
	},
	{
		// enclave_egress_direct: the running incarnation and its enclave
		Kind:     SidecarActionEnclaveEgressDirect,
		Required: []protoreflect.FieldNumber{canonicalActionFieldSubject, canonicalActionFieldEnclave},
		Versions: []uint32{canonicalActionVersionCompute},
	},
	{
		// compute_budget_raise: the budget it passes, and a gateway grant sealed in field 38
		Kind:     SidecarActionComputeBudgetRaise,
		Required: []protoreflect.FieldNumber{canonicalActionFieldSealedDetail, canonicalActionFieldBudget},
		Versions: []uint32{canonicalActionVersionCompute},
		Server:   []protoreflect.FieldNumber{canonicalActionFieldSealedDetail, canonicalActionFieldBudget},
	},
	{
		// enclave_delete: the running incarnation and its enclave
		Kind:     SidecarActionEnclaveDelete,
		Required: []protoreflect.FieldNumber{canonicalActionFieldSubject, canonicalActionFieldEnclave},
		Versions: []uint32{canonicalActionVersionCompute},
	},
	{
		// fetch_unlisted_url: the host in punycode, the whole URL, the run's taint reasons and field 70
		Kind: SidecarActionFetchUnlistedUrl,
		Required: []protoreflect.FieldNumber{
			canonicalActionFieldHost, canonicalActionFieldUrl, canonicalActionFieldTaintReasons, canonicalActionFieldAuto,
		},
		Versions: []uint32{canonicalActionVersionCompute},
		Domains:  []protoreflect.FieldNumber{canonicalActionFieldHost},
	},
	{
		// tainted_send: what is sent and its hash, the receiver, the tool, the run's taint reasons and field 70; the
		// receiving enclave and its mode, and a continuation's or crossing's context, where they apply
		Kind: SidecarActionTaintedSend,
		Required: []protoreflect.FieldNumber{
			canonicalActionFieldBodySha256, canonicalActionFieldSubject, canonicalActionFieldTool, canonicalActionFieldSend,
			canonicalActionFieldTaintReasons, canonicalActionFieldAuto,
		},
		Optional: []protoreflect.FieldNumber{
			canonicalActionFieldEgressMode, canonicalActionFieldEnclave, canonicalActionFieldContext,
		},
		Versions: []uint32{canonicalActionVersionCompute},
	},
	{
		// calendar_write (§23.9): the link's label, host, link and target, the calendar's name, the events and field 70;
		// the calendar's reported audience where the provider reports one
		Kind: SidecarActionCalendarWrite,
		Required: []protoreflect.FieldNumber{
			canonicalActionFieldCalendarLabel, canonicalActionFieldCalendarHost, canonicalActionFieldCalendarEvents,
			canonicalActionFieldCalendarLink, canonicalActionFieldCalendarTarget, canonicalActionFieldCalendarName,
			canonicalActionFieldAuto,
		},
		Optional: []protoreflect.FieldNumber{canonicalActionFieldCalendarAudience},
		Versions: []uint32{canonicalActionVersionCompute},
		Domains:  []protoreflect.FieldNumber{canonicalActionFieldCalendarHost},
	},
	{
		// service_write (§25.10): the body's hash, the API host in punycode, the run's taint reasons, the call and
		// field 70
		Kind: SidecarActionServiceWrite,
		Required: []protoreflect.FieldNumber{
			canonicalActionFieldBodySha256, canonicalActionFieldHost, canonicalActionFieldTaintReasons,
			canonicalActionFieldServiceCall, canonicalActionFieldAuto,
		},
		Versions: []uint32{canonicalActionVersionCompute},
		Domains:  []protoreflect.FieldNumber{canonicalActionFieldHost},
	},
	// support_send (DESIGN-COMPUTE §28.8), approval_compute_support.go's
	supportSendActionKindRow,
}

// Fields no version-5 action sets, whatever its kind's row says at another version: format 2's versioning, a
// share's network and an egress_change's requirement of default egress.
var approvalComputeVersion5Refused = []protoreflect.FieldNumber{
	canonicalActionFieldVersioning, canonicalActionFieldShareNetworkId, canonicalActionFieldRequireDefaultEgress,
}

// Holds a version-5 action to its version's rules, the file header's, given the fields it sets: its kind takes
// version 5, it sets its kind's fields and no other, it is no template, and each field holds what §16.3 lets it.
// The values stay out of every error, which a log may carry (I-13).
func approvalComputeActionCheck(action *protocol.CanonicalAction, setFields []protoreflect.FieldNumber, settings *CanonicalActionSettings) error {
	kind := SidecarActionKind(action.GetKind())
	row, ok := CanonicalActionFields(kind)
	if !ok || !slices.Contains(row.Versions, canonicalActionVersionCompute) {
		return fmt.Errorf("%w: kind %d at version 5", ErrCanonicalActionInvalid, kind)
	}
	if action.GetScope() {
		// every use is its own approval
		return fmt.Errorf("%w: a template at version 5", ErrCanonicalActionInvalid)
	}
	for _, number := range setFields {
		if slices.Contains(approvalComputeVersion5Refused, number) || !row.allows(number, canonicalActionVersionCompute) {
			return fmt.Errorf("%w: field %d on kind %d at version 5", ErrCanonicalActionInvalid, number, kind)
		}
	}
	message := action.ProtoReflect()
	fields := message.Descriptor().Fields()
	for _, number := range row.Required {
		if !message.Has(fields.ByNumber(number)) {
			return fmt.Errorf("%w: kind %d at version 5 without field %d", ErrCanonicalActionInvalid, kind, number)
		}
	}
	if kind == SidecarActionEgressChange && !action.GetTookTainted() {
		// field 49 is what makes an egress_change version 5's
		return fmt.Errorf("%w: an egress_change at version 5 that took nothing tainted", ErrCanonicalActionInvalid)
	}
	if protoMessageHoldsUnknown(message) {
		return fmt.Errorf("%w: a field this build cannot name in a version-5 action", ErrCanonicalActionInvalid)
	}
	for _, number := range row.Domains {
		if field := fields.ByNumber(number); message.Has(field) && !canonicalActionDomainForm(message.Get(field).String()) {
			return fmt.Errorf("%w: field %d on kind %d is not a host in its one form", ErrCanonicalActionInvalid, number, kind)
		}
	}
	if sha := action.GetBodySha256(); len(sha) != 0 && len(sha) != recordHashByteCount {
		return fmt.Errorf("%w: a body_sha256 of %d bytes", ErrCanonicalActionInvalid, len(sha))
	}
	if subject := action.GetSubject(); len(subject) != 0 && len(subject) != recordIdByteCount {
		return fmt.Errorf("%w: a subject of %d bytes", ErrCanonicalActionInvalid, len(subject))
	}
	if mode := action.GetEgressMode(); mode != 0 && kind != SidecarActionEgressChange {
		// an enclave's mode at create, or a receiving enclave's: auto, exits or none (§11.8), and for the receiver also
		// direct, its default egress off, which a create never takes (QD-1391)
		_, named := bridge.BridgeEgressMode_name[int32(mode)]
		direct := kind == SidecarActionTaintedSend && mode == approvalComputeEgressModeDirect
		if !named && !direct {
			return fmt.Errorf("%w: egress_mode %d on kind %d at version 5", ErrCanonicalActionInvalid, mode, kind)
		}
	}
	if slices.Contains(action.GetTaintReasons(), "") {
		return fmt.Errorf("%w: an empty taint reason", ErrCanonicalActionInvalid)
	}
	checks := []error{}
	if enclave := action.GetEnclave(); enclave != nil {
		checks = append(checks, approvalComputeEnclaveCheck(kind, enclave))
	}
	if budget := action.GetBudget(); budget != nil {
		checks = append(checks, approvalComputeBudgetCheck(budget))
	}
	if send := action.GetSend(); send != nil {
		checks = append(checks, approvalComputeSendCheck(send, settings))
	}
	if context := action.GetContext(); context != nil {
		checks = append(checks, approvalComputeContextCheck(context))
	}
	if kind == SidecarActionCalendarWrite {
		checks = append(checks, approvalComputeCalendarCheck(action, settings))
	}
	if call := action.GetServiceCall(); call != nil {
		checks = append(checks, approvalComputeServiceCheck(action, call, settings))
	}
	if support := action.GetSupport(); support != nil {
		checks = append(checks, approvalComputeSupportCheck(action, support, settings))
	}
	if auto := action.GetAuto(); auto != nil {
		checks = append(checks, approvalComputeAutoCheck(kind, auto))
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	return nil
}

// Holds a version-5 action's stored bytes to what its parsed fields cannot say (D-CACL-5): a kind-24 send that
// continues or crosses nothing names in field 3 the SHA-256 of field 46 exactly as stored, its value's bytes, which is
// what its effect sends, and stores field 46 once, so no reader takes two sends for one. A continuation's or a
// crossing's field 3 hashes the node list it names (§16.3), which no action holds and its builder checks.
func approvalComputeStoredCheck(action *protocol.CanonicalAction, stored []byte) error {
	if SidecarActionKind(action.GetKind()) != SidecarActionTaintedSend || action.GetContext() != nil {
		return nil
	}
	sends := [][]byte{}
	for rest := stored; 0 < len(rest); {
		number, wireType, tagByteCount := protowire.ConsumeTag(rest)
		if tagByteCount < 0 {
			return fmt.Errorf("%w: canonical action: %v", ErrCanonicalActionInvalid, protowire.ParseError(tagByteCount))
		}
		valueByteCount := protowire.ConsumeFieldValue(number, wireType, rest[tagByteCount:])
		if valueByteCount < 0 {
			return fmt.Errorf("%w: canonical action: %v", ErrCanonicalActionInvalid, protowire.ParseError(valueByteCount))
		}
		if number == canonicalActionFieldSend {
			if wireType != protowire.BytesType {
				return fmt.Errorf("%w: field 46 stored as no message", ErrCanonicalActionInvalid)
			}
			value, _ := protowire.ConsumeBytes(rest[tagByteCount:])
			sends = append(sends, value)
		}
		rest = rest[tagByteCount+valueByteCount:]
	}
	if len(sends) != 1 {
		// protobuf would merge them, and no builder writes two
		return fmt.Errorf("%w: field 46 stored %d times", ErrCanonicalActionInvalid, len(sends))
	}
	sendSha256 := sha256.Sum256(sends[0])
	if !bytes.Equal(action.GetBodySha256(), sendSha256[:]) {
		return fmt.Errorf("%w: a body_sha256 that is not the send's as stored", ErrCanonicalActionInvalid)
	}
	return nil
}

// Whether message, or any message it holds at any depth, carries a field this build cannot name.
func protoMessageHoldsUnknown(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	holds := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() != protoreflect.MessageKind && field.Kind() != protoreflect.GroupKind {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len() && !holds; i += 1 {
				holds = protoMessageHoldsUnknown(list.Get(i).Message())
			}
		} else if !field.IsMap() {
			holds = protoMessageHoldsUnknown(value.Message())
		}
		return !holds
	})
	return holds
}

// Refuses an id that is neither 16 bytes nor, where optional, empty.
func approvalComputeIdCheck(name string, id []byte, optional bool) error {
	if len(id) == recordIdByteCount || (optional && len(id) == 0) {
		return nil
	}
	return fmt.Errorf("%w: %s of %d bytes", ErrCanonicalActionInvalid, name, len(id))
}

// Field 42: an enclave id of 16 bytes, required where the action names an enclave that stands (20, 22, 24); on kind 19
// its shape, provider and label, and no name, which rides sealed in field 38.
func approvalComputeEnclaveCheck(kind SidecarActionKind, enclave *protocol.EnclaveFields) error {
	if err := approvalComputeIdCheck("enclave_id", enclave.GetEnclaveId(), kind == SidecarActionEnclaveCreate); err != nil {
		return err
	}
	if kind != SidecarActionEnclaveCreate {
		return nil
	}
	if enclave.GetName() != "" {
		return fmt.Errorf("%w: an enclave_create naming its enclave in the clear", ErrCanonicalActionInvalid)
	}
	if enclave.GetShape() == "" || enclave.GetProvider() == "" || enclave.GetLabel() == "" {
		return fmt.Errorf("%w: an enclave_create without its shape, provider or label", ErrCanonicalActionInvalid)
	}
	return nil
}

// Field 43, or a launch's budget: an agent id of 16 bytes or none, a period §16.3 names and an amount.
func approvalComputeBudgetCheck(budget *protocol.BudgetFields) error {
	if err := approvalComputeIdCheck("agent_id", budget.GetAgentId(), true); err != nil {
		return err
	}
	if period := budget.GetPeriod(); period < approvalComputeBudgetPeriodDay || approvalComputeBudgetPeriodRun < period {
		return fmt.Errorf("%w: a budget period %d", ErrCanonicalActionInvalid, period)
	}
	if budget.GetAmount() == 0 {
		return fmt.Errorf("%w: a budget of no amount", ErrCanonicalActionInvalid)
	}
	return nil
}

// Field 46: the receiving agent's and member's ids at 16 bytes or none, a mode §7.10 names, stdin within its cap, each
// ref naming a repo and a path, no empty tool, and a launch's budget held as field 43's.
func approvalComputeSendCheck(send *protocol.SendFields, settings *CanonicalActionSettings) error {
	checks := []error{
		approvalComputeIdCheck("target_agent_id", send.GetTargetAgentId(), true),
		approvalComputeIdCheck("target_member_id", send.GetTargetMemberId(), true),
	}
	for _, ref := range send.GetRefs() {
		checks = append(checks, approvalComputeIdCheck("a ref's repo_id", ref.GetRepoId(), false))
		if ref.GetPath() == "" {
			checks = append(checks, fmt.Errorf("%w: a ref with no path", ErrCanonicalActionInvalid))
		}
	}
	if budget := send.GetBudget(); budget != nil {
		checks = append(checks, approvalComputeBudgetCheck(budget))
	}
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	if mode := send.GetMode(); approvalComputeSendModeFollowUp < mode {
		return fmt.Errorf("%w: a send of mode %d", ErrCanonicalActionInvalid, mode)
	}
	if settings.SendStdinMaxByteCount < len(send.GetStdin()) {
		return fmt.Errorf("%w: a send's stdin of %d bytes", ErrCanonicalActionInvalid, len(send.GetStdin()))
	}
	if slices.Contains(send.GetTools(), "") {
		return fmt.Errorf("%w: an empty tool", ErrCanonicalActionInvalid)
	}
	return nil
}

// Field 47: the run continued or crossing at 16 bytes, its node's entry at 16 bytes or none, and an act §16.3 names.
func approvalComputeContextCheck(context *protocol.ContextFields) error {
	if err := approvalComputeIdCheck("run_id", context.GetRunId(), false); err != nil {
		return err
	}
	if err := approvalComputeIdCheck("entry_id", context.GetEntryId(), true); err != nil {
		return err
	}
	if act := context.GetAct(); act != approvalComputeContextActContinue && act != approvalComputeContextActCross {
		return fmt.Errorf("%w: a context of act %d", ErrCanonicalActionInvalid, act)
	}
	return nil
}

// Kind 25's fields (§23.9): its link's repo id and its target's SHA-256 at their sizes, 1 to the cap's events, each an
// operation §23.9 names on a uid, a change's or removal's expected revision and an addition's none, prior values on a
// change alone, and no empty entry in a list.
func approvalComputeCalendarCheck(action *protocol.CanonicalAction, settings *CanonicalActionSettings) error {
	if err := approvalComputeIdCheck("calendar_link", action.GetCalendarLink(), false); err != nil {
		return err
	}
	if target := action.GetCalendarTarget(); len(target) != recordHashByteCount {
		return fmt.Errorf("%w: a calendar_target of %d bytes", ErrCanonicalActionInvalid, len(target))
	}
	events := action.GetCalendarEvents()
	if len(events) == 0 || settings.CalendarEventMaxCount < len(events) {
		return fmt.Errorf("%w: %d calendar events", ErrCanonicalActionInvalid, len(events))
	}
	for i, event := range events {
		operation := event.GetOperation()
		switch {
		case operation < approvalComputeEventOperationAdd || approvalComputeEventOperationRemove < operation:
			return fmt.Errorf("%w: event %d's operation %d", ErrCanonicalActionInvalid, i, operation)
		case event.GetUid() == "":
			return fmt.Errorf("%w: event %d names no uid", ErrCanonicalActionInvalid, i)
		case (operation == approvalComputeEventOperationAdd) != (event.GetExpected() == ""):
			return fmt.Errorf("%w: event %d's expected revision on operation %d", ErrCanonicalActionInvalid, i, operation)
		case (operation == approvalComputeEventOperationChange) != (event.GetBefore() != nil):
			return fmt.Errorf("%w: event %d's prior values on operation %d", ErrCanonicalActionInvalid, i, operation)
		}
		lists := [][]string{event.GetReminders(), event.GetAttendees(), event.GetMails()}
		if before := event.GetBefore(); before != nil {
			lists = append(lists, before.GetReminders(), before.GetAttendees())
		}
		for _, list := range lists {
			if slices.Contains(list, "") {
				return fmt.Errorf("%w: event %d holds an empty entry", ErrCanonicalActionInvalid, i)
			}
		}
	}
	return nil
}

// Field 60 (§25.10): the connection's repo id, a method, a class §25.10 names, and the body within its cap, which
// field 3 hashes exactly.
func approvalComputeServiceCheck(action *protocol.CanonicalAction, call *protocol.ServiceCallFields, settings *CanonicalActionSettings) error {
	if err := approvalComputeIdCheck("connection", call.GetConnection(), false); err != nil {
		return err
	}
	if call.GetMethod() == "" {
		return fmt.Errorf("%w: a service call with no method", ErrCanonicalActionInvalid)
	}
	if class := call.GetClass(); class != approvalComputeServiceClassWrite && class != approvalComputeServiceClassSend {
		return fmt.Errorf("%w: a service call of class %d", ErrCanonicalActionInvalid, class)
	}
	body := []byte(call.GetBody())
	if settings.ServiceBodyMaxByteCount < len(body) {
		return fmt.Errorf("%w: a service call's body of %d bytes", ErrCanonicalActionInvalid, len(body))
	}
	bodySha256 := sha256.Sum256(body)
	if !bytes.Equal(action.GetBodySha256(), bodySha256[:]) {
		return fmt.Errorf("%w: a body_sha256 that is not the service call's body's", ErrCanonicalActionInvalid)
	}
	return nil
}

// Field 70 (§27.9): basis taint or always, and its rules ascending, each one of §27.7's that follow from the action
// alone (QD-1371).
func approvalComputeAutoCheck(kind SidecarActionKind, auto *protocol.AutoFields) error {
	if basis := auto.GetBasis(); basis != approvalComputeAutoBasisTaint && basis != approvalComputeAutoBasisAlways {
		return fmt.Errorf("%w: field 70's basis %d", ErrCanonicalActionInvalid, basis)
	}
	rules := auto.GetRules()
	for i, rule := range rules {
		if !approvalComputeAutoRuleAllowed(kind, rule) {
			return fmt.Errorf("%w: field 70 names rule %d", ErrCanonicalActionInvalid, rule)
		}
		if 0 < i && rule <= rules[i-1] {
			return fmt.Errorf("%w: field 70's rules out of order or repeated", ErrCanonicalActionInvalid)
		}
	}
	return nil
}
