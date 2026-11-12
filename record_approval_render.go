//go:build !ios_extension

// What an approver's device shows of one request (MCP-M3-07; D-MCP-17, R-MCP-7): only the daemon-built CanonicalAction
// fields, each by its record.proto name, as the action the person approves, and the agent's summary and the action's
// preview apart, labeled untrusted, so an agent cannot carry trusted rdata, an alias or a path in prose. The request
// it renders came through ParseStoredApprovalRequest, which recomputed payload_sha256 and action_id over the stored
// bytes and refused a version this build does not know (RecordApprovals.Pending), so nothing is shown that was not
// checked.
//
// A kind whose fields alone do not say what approving it gives up also shows a sentence built around those fields,
// never from an agent's text: mail_tls_unauthenticated's names its domain and that an active URnetwork edge could read
// the mail (QD-729, §2.8 EX4).
//
// Every string shown passes ApprovalPrintable, which drops C0 and C1 controls and the bidi controls, so a value cannot
// move the terminal's cursor, end a line early or reorder what follows it (§16.6's ur approve row). Bytes show as
// lowercase hex, numbers in decimal, and an audience or app mode by its record.proto name beside its number.
//
// Package-level functions are safe for concurrent use; a render is a value nothing changes. On every leg but the
// ios_extension legs.

package sidecar

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// CanonicalAction's field numbers a render sets apart: what every action carries, and the preview it shows untrusted.
const (
	approvalRenderPreviewField  protoreflect.FieldNumber = 4
	approvalRenderAudienceField protoreflect.FieldNumber = 7
	approvalRenderAppModeField  protoreflect.FieldNumber = 33
)

// One daemon-built field of a request's action.
type ApprovalRenderField struct {
	// record.proto's name for it, such as dns_value.
	Name string
	// Printable: a string as written, a list joined by ", ", bytes in lowercase hex, a number in decimal.
	Value string
}

// What an approver's device shows of one request.
type ApprovalRender struct {
	ApprovalId Id
	Kind       SidecarActionKind
	// record.proto's name for the kind, lowercased past its prefix: dns_set, mail_send.
	KindName string
	Version  uint32
	// A multi-use template: each use's action equals its non-empty fields, its recipients among those listed.
	Template bool
	// What approving the action allows, in words around its daemon-built fields, for a kind whose fields alone do
	// not say it; empty for the rest. Printable.
	Meaning string
	// Each field the action sets, in field order, kind, version, scope and preview aside: the action the person
	// approves.
	Fields []*ApprovalRenderField
	// The agent's own words and the daemon's preview, untrusted, printable.
	Summary string
	Preview string
	// Who asks, from which run and agent, the zero Id for none.
	RequesterSidecarId Id
	RunId              Id
	AgentId            Id
	Risk               SidecarRisk
	// Filed in a tainted run (TS1).
	Tainted bool
	// The entry carrying it is flagged.
	Flagged   bool
	NotAfter  time.Time
	Approvers []Id
}

// Whether r is one ApprovalPrintable drops: C0 and DEL, C1, and the bidi controls (Unicode's
// Bidi_Control property: ALM, LRM, RLM, LRE to RLO, LRI to PDI).
func approvalRenderDropped(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, 0x80 <= r && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, 0x202a <= r && r <= 0x202e, 0x2066 <= r && r <= 0x2069:
		return true
	}
	return false
}

// text with every C0, C1 and bidi control dropped, and each byte that is not UTF-8 shown as U+FFFD: what an approver's
// terminal or screen may print of an untrusted string.
func ApprovalPrintable(text string) string {
	builder := strings.Builder{}
	for len(text) != 0 {
		r, size := utf8.DecodeRuneInString(text)
		text = text[size:]
		if r == utf8.RuneError && size == 1 {
			builder.WriteRune(utf8.RuneError)
			continue
		}
		if !approvalRenderDropped(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// record.proto's name for a kind, lowercased past its prefix, or its number for one record.proto does not name.
func approvalKindName(kind SidecarActionKind) string {
	name, ok := protocol.SidecarActionKind_name[int32(kind)]
	if !ok {
		return strconv.FormatUint(uint64(kind), 10)
	}
	return strings.ToLower(strings.TrimPrefix(name, "SIDECAR_ACTION_KIND_"))
}

// What approving action allows, in words around its daemon-built fields: mail_tls_unauthenticated's sentence
// (QD-729), and empty for a kind whose fields say it themselves.
func approvalRenderMeaning(action *protocol.CanonicalAction) string {
	switch SidecarActionKind(action.GetKind()) {
	case SidecarActionMailTlsUnauthenticated:
		return fmt.Sprintf("Send mail to %s through a mail server that cannot be authenticated: an active URnetwork edge could read it",
			ApprovalPrintable(action.GetHost()))
	}
	return ""
}

// One field's value, printable.
func approvalRenderValue(field protoreflect.FieldDescriptor, value protoreflect.Value) string {
	scalar := func(value protoreflect.Value) string {
		switch field.Kind() {
		case protoreflect.StringKind:
			return ApprovalPrintable(value.String())
		case protoreflect.BytesKind:
			return hex.EncodeToString(value.Bytes())
		case protoreflect.BoolKind:
			return strconv.FormatBool(value.Bool())
		case protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind,
			protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
			return strconv.FormatInt(value.Int(), 10)
		}
		return strconv.FormatUint(value.Uint(), 10)
	}
	if field.IsList() {
		list := value.List()
		values := make([]string, 0, list.Len())
		for i := 0; i < list.Len(); i += 1 {
			values = append(values, scalar(list.Get(i)))
		}
		return strings.Join(values, ", ")
	}
	text := scalar(value)
	switch field.Number() {
	case approvalRenderAudienceField:
		if name, ok := protocol.AclAudience_name[int32(value.Uint())]; ok {
			text += " (" + strings.ToLower(strings.TrimPrefix(name, "ACL_AUDIENCE_")) + ")"
		}
	case approvalRenderAppModeField:
		if name, ok := protocol.AclAppMode_name[int32(value.Uint())]; ok {
			text += " (" + strings.ToLower(strings.TrimPrefix(name, "ACL_APP_MODE_")) + ")"
		}
	}
	return text
}

// The render of a request as Pending parsed it.
func RenderApprovalRequest(request *StoredApprovalRequest) *ApprovalRender {
	action := request.Action.Action
	render := &ApprovalRender{
		ApprovalId:         request.ApprovalId(),
		Kind:               SidecarActionKind(action.GetKind()),
		KindName:           approvalKindName(SidecarActionKind(action.GetKind())),
		Version:            action.GetVersion(),
		Template:           action.GetScope(),
		Meaning:            approvalRenderMeaning(action),
		Summary:            ApprovalPrintable(request.Request.GetSummary()),
		Preview:            ApprovalPrintable(action.GetPreview()),
		RequesterSidecarId: recordIdOf(request.Request.GetRequesterSidecarId()),
		RunId:              recordIdOf(request.Request.GetRunId()),
		AgentId:            recordIdOf(request.Request.GetAgentId()),
		Risk:               SidecarRisk(request.Request.GetRisk()),
		Tainted:            request.Request.GetTainted(),
		NotAfter:           time.UnixMilli(request.Request.GetNotAfterMillis()),
	}
	for _, approver := range request.Request.GetApprovers() {
		render.Approvers = append(render.Approvers, recordIdOf(approver))
	}
	message := action.ProtoReflect()
	for _, number := range setFieldNumbers(message) {
		switch number {
		case canonicalActionFieldKind, canonicalActionFieldVersion, canonicalActionFieldScope, approvalRenderPreviewField:
			continue
		}
		field := message.Descriptor().Fields().ByNumber(number)
		render.Fields = append(render.Fields, &ApprovalRenderField{
			Name:  string(field.Name()),
			Value: approvalRenderValue(field, message.Get(field)),
		})
	}
	return render
}

// What ur approve prints: the kind and what approving it allows where the render says, the action's fields, then who
// asks, then the untrusted text under its own heading. Every line is printable.
func (self *ApprovalRender) Text() string {
	lines := []string{}
	heading := fmt.Sprintf("request %s: %s", self.ApprovalId, self.KindName)
	if self.Template {
		heading += ", a template each use must match"
	}
	if self.Meaning != "" {
		heading += ". " + self.Meaning
	}
	lines = append(lines, heading+". The action, as this daemon built it:")
	for _, field := range self.Fields {
		lines = append(lines, fmt.Sprintf("  %s: %s", field.Name, field.Value))
	}
	asked := fmt.Sprintf("asked by sidecar %s", self.RequesterSidecarId)
	if self.RunId != (Id{}) {
		asked += fmt.Sprintf(", run %s", self.RunId)
	}
	if self.AgentId != (Id{}) {
		asked += fmt.Sprintf(", agent %s", self.AgentId)
	}
	lines = append(lines, asked)
	state := fmt.Sprintf("expires %s", self.NotAfter.UTC().Format(time.RFC3339))
	if self.Risk == SidecarRiskHigh {
		state += "; high risk"
	}
	if self.Tainted {
		state += "; the run read untrusted data"
	}
	if self.Flagged {
		state += "; its entry is flagged"
	}
	lines = append(lines, state)
	if self.Summary != "" || self.Preview != "" {
		lines = append(lines, "untrusted text the agent wrote, which is not the action:")
		if self.Summary != "" {
			lines = append(lines, "  summary: "+self.Summary)
		}
		if self.Preview != "" {
			lines = append(lines, "  preview: "+self.Preview)
		}
	}
	return strings.Join(lines, "\n")
}
