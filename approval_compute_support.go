// Outward action 27, support_send (DESIGN-COMPUTE §16.3, §28.8, D-SUP-5): an agent's message to URnetwork's support
// that needs a decision, built at CanonicalAction version 5 with fields 3, 48, 70 and 80. A Harness run's message that
// has read nothing untrusted, carries no private mark and names no file is no action at all, W (CO-45); every other
// agent's message is this kind:
//
//	a tainted run's message, with the support log's bundle or none     the classifier first (§27.4), the person when
//	                                                                    it asks or a rule holds: field 70's basis taint
//	a run carrying the private mark, tainted or not                    the person, rule private_data (15)
//	a message naming a file                                            the person, rule attachment (16)
//	an MCP session's, `ur support send` from a harness's process, a     the person: the classifier asks,
//	call through an enclave's container socket                         inputs_unknown, which no action carries
//
// Field 80 is the whole message, rendered on the card as untrusted text; field 3 hashes the SupportBody the effect
// posts, exactly as the outbox stores it (support_body.go), so the approval binds what leaves; field 48 is the run's
// taint reasons; field 70 is built here and says basis taint for a tainted run's plain message, always where the mark
// or a file makes it outward, with the rule that says why (§27.9). §27.7 numbers private_data and attachment after
// inputs_unknown (14), so the rules before them keep QD-1371's numbers; they follow from the action alone, so they ride
// it, the one pair of field 70's rules past 10.
//
// On every leg, as approval_compute_kinds.go is, whose rows and checks read this file's. Package-level functions are safe
// for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"slices"
	"unicode/utf8"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// An agent's message to URnetwork's support that needs a decision (§28.8).
const SidecarActionSupportSend SidecarActionKind = 27

// CanonicalAction's field 80, kind 27's (§16.3); 81 to 89 are reserved for it.
const canonicalActionFieldSupport = 80

// A client_ref's size, 128 bits (§28.6, FB section 3): an identifier's, as recordIdByteCount is.
const supportClientRefByteCount = 16

// §27.7's rules for kind 27, numbered after inputs_unknown (14), which ride field 70 as the rules before 11 do.
const (
	approvalComputeAutoRulePrivateData uint32 = 15
	approvalComputeAutoRuleAttachment  uint32 = 16
)

// SupportFields.kind: FB section 4's hints in its order, 0 for none.
const (
	supportKindNone     uint32 = 0
	supportKindBug      uint32 = 1
	supportKindFeature  uint32 = 2
	supportKindQuestion uint32 = 3
	supportKindPraise   uint32 = 4
	supportKindSecurity uint32 = 5
	supportKindOther    uint32 = 6
)

// FileFields.type: what §28.7 lets a message carry.
const (
	supportFileTypeText uint32 = 1
	supportFileTypePng  uint32 = 2
	supportFileTypeJpeg uint32 = 3
)

// The product every agent's message goes to (§28.5, Q-SUP-1).
const SupportProductUrnetwork = "urnetwork"

// FB section 3's entry id on the wire: six digits from 100001, room left for the counter to grow.
var supportEntryPattern = regexp.MustCompile(`^[1-9][0-9]{5,11}$`)

// support_send's row, version 5's alone: the body's hash, field 70 and field 80, and the run's taint reasons where it
// is tainted. No server path takes it: the message goes to FB's service, which reads no CanonicalAction.
var supportSendActionKindRow = &CanonicalActionKindFields{
	Kind: SidecarActionSupportSend,
	Required: []protoreflect.FieldNumber{
		canonicalActionFieldBodySha256, canonicalActionFieldAuto, canonicalActionFieldSupport,
	},
	Optional: []protoreflect.FieldNumber{canonicalActionFieldTaintReasons},
	Versions: []uint32{canonicalActionVersionCompute},
}

// Whether field 70 may name rule on kind's action: §27.7's rules that follow from the action alone, 1 to 10, and for
// kind 27 private_data and attachment too.
func approvalComputeAutoRuleAllowed(kind SidecarActionKind, rule uint32) bool {
	if approvalComputeAutoRuleFirst <= rule && rule <= approvalComputeAutoRuleLast {
		return true
	}
	return kind == SidecarActionSupportSend && (rule == approvalComputeAutoRulePrivateData || rule == approvalComputeAutoRuleAttachment)
}

// Field 80 (§16.3, §28.8): product urnetwork, an entry in FB's form or none, a kind FB names, the text whole within its
// bound and valid UTF-8, the bundle's manifest whole where it is named, at most SupportFileMaxCount files, each named,
// typed and hashed, and a 16-byte client_ref; and field 70's rules as the message says them: attachment exactly when
// it names a file, its basis always where a rule holds.
func approvalComputeSupportCheck(action *protocol.CanonicalAction, support *protocol.SupportFields, settings *CanonicalActionSettings) error {
	if support.GetProduct() != SupportProductUrnetwork {
		return fmt.Errorf("%w: field 80's product", ErrCanonicalActionInvalid)
	}
	if entry := support.GetEntry(); entry != "" && !supportEntryPattern.MatchString(entry) {
		return fmt.Errorf("%w: field 80's entry", ErrCanonicalActionInvalid)
	}
	if supportKindOther < support.GetKind() {
		return fmt.Errorf("%w: field 80's kind %d", ErrCanonicalActionInvalid, support.GetKind())
	}
	text := support.GetText()
	if text == "" || settings.SupportTextMaxByteCount < len(text) || !utf8.ValidString(text) {
		return fmt.Errorf("%w: field 80's text of %d bytes", ErrCanonicalActionInvalid, len(text))
	}
	if len(support.GetClientRef()) != supportClientRefByteCount {
		return fmt.Errorf("%w: a client_ref of %d bytes", ErrCanonicalActionInvalid, len(support.GetClientRef()))
	}
	if bundle := support.GetBundle(); bundle != nil {
		if len(bundle.GetSha256()) != recordHashByteCount || bundle.GetBytes() == 0 || bundle.GetLast() < bundle.GetFirst() {
			return fmt.Errorf("%w: field 80's bundle", ErrCanonicalActionInvalid)
		}
		for _, code := range bundle.GetCodes() {
			if code.GetComponent() == "" || code.GetCode() == "" || code.GetCount() == 0 {
				return fmt.Errorf("%w: field 80's bundle names an empty code", ErrCanonicalActionInvalid)
			}
		}
	}
	files := support.GetFiles()
	if settings.SupportFileMaxCount < len(files) {
		return fmt.Errorf("%w: %d files", ErrCanonicalActionInvalid, len(files))
	}
	for i, file := range files {
		if file.GetName() == "" || len(file.GetSha256()) != recordHashByteCount ||
			file.GetType() < supportFileTypeText || supportFileTypeJpeg < file.GetType() {
			return fmt.Errorf("%w: field 80's file %d", ErrCanonicalActionInvalid, i)
		}
	}
	auto := action.GetAuto()
	if (0 < len(files)) != slices.Contains(auto.GetRules(), approvalComputeAutoRuleAttachment) {
		return fmt.Errorf("%w: field 70's attachment rule on a message with %d files", ErrCanonicalActionInvalid, len(files))
	}
	if 0 < len(auto.GetRules()) && auto.GetBasis() != approvalComputeAutoBasisAlways {
		return fmt.Errorf("%w: field 70's basis taint beside a rule", ErrCanonicalActionInvalid)
	}
	return nil
}

// What kind 27's action is built from: the message as the outbox will post it, and why it is outward.
type SupportSendActionArgs struct {
	// The SupportBody as the outbox stores and posts it, which field 3 hashes.
	Body []byte
	// Field 80.
	Support *protocol.SupportFields
	// The run's taint reasons, field 48; empty for a run that read nothing untrusted.
	TaintReasons []string
	// The run counts as tainted whatever its reasons: an MCP session's, a harness process's or a container socket's
	// message, whose inputs the daemon never saw (Q-SUP-8, §11.10).
	CountsTainted bool
	// The run carries the private mark (§7.8): rule private_data.
	Private bool
}

// Kind 27's action at version 5, its field 70 built from args: basis taint for a tainted run's plain message, always
// with private_data or attachment where the mark or a file makes it outward. Refused where nothing makes it outward:
// a clean run's message with no mark and no file is W, and files no action.
func NewSupportSendAction(args *SupportSendActionArgs) (*StoredCanonicalAction, error) {
	if args == nil || args.Support == nil || len(args.Body) == 0 {
		return nil, fmt.Errorf("%w: a support_send without its message", ErrCanonicalActionInvalid)
	}
	rules := []uint32{}
	if args.Private {
		rules = append(rules, approvalComputeAutoRulePrivateData)
	}
	if 0 < len(args.Support.GetFiles()) {
		rules = append(rules, approvalComputeAutoRuleAttachment)
	}
	auto := &protocol.AutoFields{Basis: approvalComputeAutoBasisTaint}
	switch {
	case 0 < len(rules):
		auto = &protocol.AutoFields{Basis: approvalComputeAutoBasisAlways, Rules: rules}
	case len(args.TaintReasons) == 0 && !args.CountsTainted:
		return nil, fmt.Errorf("%w: a clean run's plain message is no action (W)", ErrCanonicalActionInvalid)
	}
	bodySha256 := sha256.Sum256(args.Body)
	return NewCanonicalAction(&protocol.CanonicalAction{
		Kind:         uint32(SidecarActionSupportSend),
		Version:      canonicalActionVersionCompute,
		BodySha256:   bodySha256[:],
		TaintReasons: slices.Clone(args.TaintReasons),
		Auto:         auto,
		Support:      args.Support,
	})
}

// Whether a stored kind-27 action's field 3 hashes body: what the effect checks before it posts, so a decision spends
// only on the message its approver saw.
func supportSendActionBinds(action *protocol.CanonicalAction, body []byte) bool {
	bodySha256 := sha256.Sum256(body)
	return SidecarActionKind(action.GetKind()) == SidecarActionSupportSend && bytes.Equal(action.GetBodySha256(), bodySha256[:])
}
