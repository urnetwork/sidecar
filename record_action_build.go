// The daemon's CanonicalAction builder (D-MCP-17, R-MCP-6): every O tool's owner fills a CanonicalAction from the
// call and the daemon's own state, never the agent's words, and NewCanonicalAction holds it to its kind's row
// (record_action_kinds.go), fixes its version and marshals it once, deterministically. From then on the bytes are the
// action: payload_sha256 and action_id cover them, approvers render only their fields, and nothing re-marshals a
// parsed action, since a reader keeps what it cannot name by keeping the bytes. For uses = 1, ApprovalActionId over
// these bytes at proposal is the one action_id from proposal to execution.
//
// A multi-use decision binds a template, an action with scope = true whose non-empty fields every use equals, its
// recipients a superset of each use's (§16.6's multi-use row): ActionMatchesTemplate. A server path admits only its
// kind's column of the table (QD-064): CheckCanonicalActionForServer.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// Fixed sizes of the CanonicalAction fields that hold a hash or an id, which a builder holds an action to.
var canonicalActionFieldByteCounts = map[protoreflect.FieldNumber]int{
	// body_sha256, content_sha256 and link_spki_sha256
	3:  recordHashByteCount,
	16: recordHashByteCount,
	35: recordHashByteCount,
	// repo_id, target_sidecar_id and restore_run_id
	14: recordIdByteCount,
	26: recordIdByteCount,
	30: recordIdByteCount,
}

// The field numbers set on message, in number order.
func setFieldNumbers(message protoreflect.Message) []protoreflect.FieldNumber {
	numbers := []protoreflect.FieldNumber{}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		numbers = append(numbers, field.Number())
		return true
	})
	slices.Sort(numbers)
	return numbers
}

// The stored action for what action holds, held to its kind's row: no field outside the row, every required field
// filled unless the action is a template (scope = true), hashes and ids at their sizes, the preview within 2 KiB, a
// version the kind takes (0 picks its default) and this build knows, and nothing the verifiers would refuse, since the
// bytes go through ParseStoredCanonicalAction before they are answered. The caller's message is not changed. A kind
// with no row, or one a question holds, is refused.
func NewCanonicalAction(action *protocol.CanonicalAction) (*StoredCanonicalAction, error) {
	if action == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	kind := SidecarActionKind(action.GetKind())
	row, ok := CanonicalActionFields(kind)
	if !ok {
		return nil, fmt.Errorf("%w: kind %d has no fields", ErrCanonicalActionInvalid, action.GetKind())
	}
	if row.Held != "" {
		return nil, fmt.Errorf("%w: kind %d waits on question %s", ErrCanonicalActionInvalid, action.GetKind(), row.Held)
	}
	built := proto.Clone(action).(*protocol.CanonicalAction)
	if len(built.ProtoReflect().GetUnknown()) != 0 {
		return nil, fmt.Errorf("%w: a field this build cannot name", ErrCanonicalActionInvalid)
	}
	version := built.GetVersion()
	if version == 0 {
		version = row.Versions[0]
	}
	if !slices.Contains(row.Versions, version) {
		return nil, fmt.Errorf("%w: kind %d at version %d", ErrCanonicalActionInvalid, action.GetKind(), version)
	}
	if !CanonicalActionVersionKnown(version) {
		return nil, fmt.Errorf("%w: version %d", ErrCanonicalActionVersionUnknown, version)
	}
	built.Version = version

	message := built.ProtoReflect()
	fields := message.Descriptor().Fields()
	for _, number := range setFieldNumbers(message) {
		if !row.allows(number, version) {
			return nil, fmt.Errorf("%w: field %d on kind %d", ErrCanonicalActionInvalid, number, action.GetKind())
		}
		if byteCount, ok := canonicalActionFieldByteCounts[number]; ok {
			if value := message.Get(fields.ByNumber(number)).Bytes(); len(value) != byteCount {
				return nil, fmt.Errorf("%w: field %d of %d bytes", ErrCanonicalActionInvalid, number, len(value))
			}
		}
	}
	if !built.GetScope() {
		for _, number := range row.Required {
			if !message.Has(fields.ByNumber(number)) {
				return nil, fmt.Errorf("%w: kind %d without field %d", ErrCanonicalActionInvalid, action.GetKind(), number)
			}
		}
	}
	if slices.Contains(built.GetRecipients(), "") || slices.Contains(built.GetRestorePaths(), "") {
		return nil, fmt.Errorf("%w: an empty recipient or path", ErrCanonicalActionInvalid)
	}
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(built)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCanonicalActionInvalid, err)
	}
	return ParseStoredCanonicalAction(stored)
}

// Whether use falls inside template (§16.6's multi-use row): template is a scope = true action, use a full one of
// the same kind and version, and every field template fills, scope aside, equals use's, but recipients, where use's
// must each be among template's. A field template leaves empty matches anything.
func ActionMatchesTemplate(template *StoredCanonicalAction, use *StoredCanonicalAction) bool {
	if template == nil || use == nil || !template.Action.GetScope() || use.Action.GetScope() {
		return false
	}
	if template.Action.GetKind() != use.Action.GetKind() || template.Action.GetVersion() != use.Action.GetVersion() {
		return false
	}
	templateMessage := template.Action.ProtoReflect()
	useMessage := use.Action.ProtoReflect()
	matches := true
	templateMessage.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch field.Number() {
		case canonicalActionFieldScope:
			return true
		case 2:
			allowed := template.Action.GetRecipients()
			for _, recipient := range use.Action.GetRecipients() {
				if !slices.Contains(allowed, recipient) {
					matches = false
					return false
				}
			}
			return true
		}
		if !useMessage.Has(field) || !protoValueEqual(field, value, useMessage.Get(field)) {
			matches = false
			return false
		}
		return true
	})
	return matches
}

// Whether two values of field are equal: lists element by element, bytes by content.
func protoValueEqual(field protoreflect.FieldDescriptor, a protoreflect.Value, b protoreflect.Value) bool {
	if field.IsList() {
		aList, bList := a.List(), b.List()
		if aList.Len() != bList.Len() {
			return false
		}
		for i := 0; i < aList.Len(); i += 1 {
			if !protoScalarEqual(field.Kind(), aList.Get(i), bList.Get(i)) {
				return false
			}
		}
		return true
	}
	return protoScalarEqual(field.Kind(), a, b)
}

// Whether two scalar values of kind are equal. CanonicalAction holds no message or map field.
func protoScalarEqual(kind protoreflect.Kind, a protoreflect.Value, b protoreflect.Value) bool {
	if kind == protoreflect.BytesKind {
		return bytes.Equal(a.Bytes(), b.Bytes())
	}
	return a.Interface() == b.Interface()
}

// risk(a, P) (§5.4, §16.8's ApprovalRequest.risk): the largest of policy's, the daemon classifier's and what the agent
// asked, so an agent can only raise it. The classifier answers normal for every action: the owner dropped SSHSIGs
// from every milestone and every action stays normal (plan-MCP-risk-classifier#1), so a high risk comes only from a
// policy or an agent's own ask, and spends as a normal one. A value SidecarRisk does not name counts for nothing, and
// the answer is at least normal.
func CanonicalActionRisk(action *StoredCanonicalAction, policy SidecarRisk, agentAsked SidecarRisk) SidecarRisk {
	risk := SidecarRiskNormal
	for _, candidate := range []SidecarRisk{policy, agentAsked} {
		if (candidate == SidecarRiskNormal || candidate == SidecarRiskHigh) && risk < candidate {
			risk = candidate
		}
	}
	return risk
}

// Holds an action a GrantActivate or a gate carries to its kind's server column (QD-064): kind, version, scope and
// the column's fields, nothing more, so recipients, previews and paths never reach a server even from a builder that
// filled them. A kind no server path takes is refused. api, every reader's GrantActivate check and each gate run this
// on the stored bytes, after ParseStoredCanonicalAction.
func CheckCanonicalActionForServer(action *StoredCanonicalAction) error {
	if action == nil {
		return fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	row, ok := CanonicalActionFields(SidecarActionKind(action.Action.GetKind()))
	if !ok || len(row.Server) == 0 {
		return fmt.Errorf("%w: kind %d takes no server path", ErrCanonicalActionInvalid, action.Action.GetKind())
	}
	for _, number := range setFieldNumbers(action.Action.ProtoReflect()) {
		if !row.serverAllows(number) {
			return fmt.Errorf("%w: field %d on a server path", ErrCanonicalActionInvalid, number)
		}
	}
	return nil
}
