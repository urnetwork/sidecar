// The daemon's CanonicalAction builder (D-MCP-17, R-MCP-6): every O tool's owner fills a CanonicalAction from the
// call and the daemon's own state, never the agent's words, and NewCanonicalAction holds it to its kind's row
// (record_action_kinds.go), fixes its version and marshals it once, deterministically. From then on the bytes are the
// action: payload_sha256 and action_id cover them, approvers render only their fields, and nothing re-marshals a
// parsed action, since a reader keeps what it cannot name by keeping the bytes. For uses = 1, ApprovalActionId over
// these bytes at proposal is the one action_id from proposal to execution.
//
// A multi-use decision binds a template, an action with scope = true whose non-empty fields every use equals, its
// recipients a superset of each use's (§16.6's multi-use row), and the empty ones its kind's row binds (TemplateBound:
// an egress_change's require_default_egress, QD-1060): ActionMatchesTemplate. An agent asks for one only through
// mail_send's uses (owner decision 613), whose template NewMailTemplateAction builds. A server path admits only its
// kind's column of the table (QD-064): CheckCanonicalActionForServer.
//
// The builder takes both of QD-740's forms. A kind that binds a local port, a weight or ALPNs builds its action
// without them: they are the request's, which the caller hands the gate as SidecarAction.Detail, and so is a listen's
// socket name (QD-772), its action naming the socket by grant_dst alone (SocketListenGrantDst). A dial or route
// grant, bridge_forward's at version 4, and an access request to a worker's port carry sealed_detail, which
// NewSealedCanonicalAction (record_action_detail.go) seals once the clear fields are final, bound to them (QD-771;
// canonicalActionClearBytes here): the builder holds it to the sealed-body layout and holds every clear grant_dst to a
// subject alone, so no action it answers shows a server a prefix or a port.
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
	// a share's other network
	canonicalActionFieldShareNetworkId: recordIdByteCount,
	// version 5's subject, a calendar link's repo id and its target's SHA-256 (DESIGN-COMPUTE §16.3, §23.9); the ids
	// inside version 5's messages are its rules' (approval_compute_kinds.go)
	canonicalActionFieldCalendarLink:   recordIdByteCount,
	canonicalActionFieldCalendarTarget: recordHashByteCount,
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
// filled unless the action is a template (scope = true), which fills only the row's TemplateRequired and leaves its
// TemplateEmpty empty, a domain field in its one form, lowercase with no trailing dot, hashes and ids at their sizes,
// the preview within 2 KiB, a
// version the kind takes (0 picks its default) and this build knows, a grant_dst naming subjects alone, with no ip:
// prefix or port, and nothing the verifiers would refuse, since the bytes go through ParseStoredCanonicalAction before
// they are answered. The caller's message is not changed. A kind with no row is refused.
func NewCanonicalAction(action *protocol.CanonicalAction) (*StoredCanonicalAction, error) {
	return newCanonicalAction(action, CanonicalActionVersionKnown)
}

// NewCanonicalAction, given which versions are known: CanonicalActionVersionKnown outside tests.
func newCanonicalAction(action *protocol.CanonicalAction, known func(version uint32) bool) (*StoredCanonicalAction, error) {
	if action == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	kind := SidecarActionKind(action.GetKind())
	row, ok := CanonicalActionFields(kind)
	if !ok {
		return nil, fmt.Errorf("%w: kind %d has no fields", ErrCanonicalActionInvalid, action.GetKind())
	}
	built := proto.Clone(action).(*protocol.CanonicalAction)
	if len(built.ProtoReflect().GetUnknown()) != 0 {
		return nil, fmt.Errorf("%w: a field this build cannot name", ErrCanonicalActionInvalid)
	}
	version := canonicalActionBuildVersion(built, row)
	if !slices.Contains(row.Versions, version) {
		return nil, fmt.Errorf("%w: kind %d at version %d", ErrCanonicalActionInvalid, action.GetKind(), version)
	}
	if !known(version) {
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
	required := row.Required
	if built.GetScope() {
		required = row.TemplateRequired
		for _, number := range row.TemplateEmpty {
			if message.Has(fields.ByNumber(number)) {
				return nil, fmt.Errorf("%w: a template of kind %d with field %d", ErrCanonicalActionInvalid, action.GetKind(), number)
			}
		}
	}
	for _, number := range required {
		if !message.Has(fields.ByNumber(number)) {
			return nil, fmt.Errorf("%w: kind %d without field %d", ErrCanonicalActionInvalid, action.GetKind(), number)
		}
	}
	for _, number := range row.Domains {
		if field := fields.ByNumber(number); message.Has(field) && !canonicalActionDomainForm(message.Get(field).String()) {
			// the name itself stays out of the error, which a log may carry (I-13)
			return nil, fmt.Errorf("%w: field %d on kind %d is not a domain in lowercase with no trailing dot", ErrCanonicalActionInvalid, number, action.GetKind())
		}
	}
	if slices.Contains(built.GetRecipients(), "") || slices.Contains(built.GetRestorePaths(), "") {
		return nil, fmt.Errorf("%w: an empty recipient or path", ErrCanonicalActionInvalid)
	}
	for _, dst := range built.GetGrantDst() {
		// at every version: a prefix or a port rides sealed_detail, never the clear fields (owner decision 220)
		if !canonicalActionGrantDstClear(dst) {
			return nil, fmt.Errorf("%w: a grant_dst naming a prefix or a port, which rides sealed_detail", ErrCanonicalActionInvalid)
		}
	}
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(built)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCanonicalActionInvalid, err)
	}
	return parseStoredCanonicalAction(stored, known)
}

// The version an action of row's kind is built at: its own, or the kind's default, the row's first, where it sets
// none (0).
func canonicalActionBuildVersion(action *protocol.CanonicalAction, row *CanonicalActionKindFields) uint32 {
	if version := action.GetVersion(); version != 0 || len(row.Versions) == 0 {
		return version
	}
	return row.Versions[0]
}

// clear's bytes as the builder stores them, before its detail is sealed: sealed_detail left out and the version fixed
// as NewCanonicalAction fixes it, deterministically encoded, field by field in number order. The stored action is
// these bytes with its sealed_detail's record, field 38's, among them in number order: after every other field (39,
// egress_mode, and 41, require_default_egress, are a version-1 egress_change's alone) but a share's
// share_network_id, 40 (QD-820), which follows it.
// The context cuts field 38's record out wherever it stands, so the one a detail is sealed to here is the one its
// stored bytes derive (CanonicalActionDetailSealContext), a share's network bound into it as every clear field is.
// The caller's message is not changed.
func canonicalActionClearBytes(clear *protocol.CanonicalAction) ([]byte, error) {
	final := proto.Clone(clear).(*protocol.CanonicalAction)
	final.SealedDetail = nil
	if row, ok := CanonicalActionFields(SidecarActionKind(final.GetKind())); ok {
		final.Version = canonicalActionBuildVersion(final, row)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(final)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCanonicalActionInvalid, err)
	}
	return encoded, nil
}

// The template mail_send's uses asks for (owner decision 613; §16.6's multi-use row): scope set, from_alias fromAlias,
// and recipients the allowed set, distinct and in byte order, so the same set asked again in another order is the same
// action, with no body hash or preview, so each mail from fromAlias to a subset of them falls inside it
// (ActionMatchesTemplate) whatever its text. A use matches it byte for byte, so the caller gives the alias and the
// addresses from MailClient's plan, which canonicalizes domains and preserves external local parts.
// NewCanonicalAction requires an alias and at least one recipient, with no empty address.
func NewMailTemplateAction(fromAlias string, recipients []string) (*StoredCanonicalAction, error) {
	allowed := slices.Clone(recipients)
	slices.Sort(allowed)
	return NewCanonicalAction(&protocol.CanonicalAction{
		Kind:       uint32(SidecarActionMail),
		Scope:      true,
		Recipients: slices.Compact(allowed),
		Alias:      fromAlias,
	})
}

// Whether use falls inside template (§16.6's multi-use row): template is a scope = true action, use a full one of
// the same kind and version, and every field template fills, scope aside, equals use's, but recipients, where use's
// must each be among template's. A field template leaves empty matches anything, but one its kind's row binds
// (TemplateBound), which use leaves empty too: an egress_change's require_default_egress (QD-1060), so a template for
// exits without the requirement, whose approver never saw it, covers no use that sets it.
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
	if !matches {
		return false
	}
	if row, ok := CanonicalActionFields(SidecarActionKind(template.Action.GetKind())); ok {
		fields := templateMessage.Descriptor().Fields()
		for _, number := range row.TemplateBound {
			// one template fills is equal in use by the range above; one it leaves empty, use leaves empty too
			if field := fields.ByNumber(number); templateMessage.Has(field) != useMessage.Has(field) {
				return false
			}
		}
	}
	return true
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

// Whether two scalar values of kind are equal. CanonicalAction holds no map field, and its message fields are version
// 5's, which takes no template, so a template's never reach here.
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
// filled them, nor a field this build cannot name, such as a listen's name at its old 23 (QD-772), whose listen
// passes on the grant's fields alone. A kind no server path takes is refused. api, every reader's GrantActivate check
// and each gate run this on the stored bytes, after ParseStoredCanonicalAction. Version 5 reaches a server only as
// kind 19's create and kind 21's raise, the broker's (DESIGN-COMPUTE §16.3), every other version-5 action refused whole.
func CheckCanonicalActionForServer(action *StoredCanonicalAction) error {
	if action == nil || action.Action == nil {
		return fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	kind := SidecarActionKind(action.Action.GetKind())
	if action.Action.GetVersion() == canonicalActionVersionCompute && kind != SidecarActionEnclaveCreate && kind != SidecarActionComputeBudgetRaise {
		return fmt.Errorf("%w: kind %d at version 5 takes no server path", ErrCanonicalActionInvalid, kind)
	}
	row, ok := CanonicalActionFields(kind)
	if !ok || len(row.Server) == 0 {
		return fmt.Errorf("%w: kind %d takes no server path", ErrCanonicalActionInvalid, action.Action.GetKind())
	}
	if len(action.Action.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("%w: a field this build cannot name on a server path", ErrCanonicalActionInvalid)
	}
	for _, number := range setFieldNumbers(action.Action.ProtoReflect()) {
		if !row.serverAllows(number) {
			return fmt.Errorf("%w: field %d on a server path", ErrCanonicalActionInvalid, number)
		}
	}
	return nil
}
