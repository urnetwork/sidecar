// MCP-M3-02's kind table: for each SidecarActionKind, the CanonicalAction fields an action of that kind must and may
// fill, the versions it takes, and the fields an action bound for a GrantActivate or a gate may carry there. One table,
// so the builder, the template match and every server path read the same rows, and the rule set is data: a kind's
// fields change in a row, never in code.
//
// The rows follow MCP.md's MCP-M3-02 and the owner's answer to protos-services-canonical-action (QD-064): a grant
// carries 8, 10, 11, 28 and 29, a publish's also 5, 6, 7, 33 and 35, a version-3 access_request 8, 10, 11, 14, 26, 27
// and 29, and a dns_* action 8 and 18 to 21, each with kind, version and scope; local_port, weight and alpn (24, 25,
// 34) leave CanonicalAction, so no row fills them. How the kinds that bound a local port bind it now, and where a
// dial or route grant's prefixes and ports go (QD-003's sealed_detail), is question
// record-m2-01-canonical-action-detail, open: publish, listen, forward and expose are held, and NewCanonicalAction
// refuses them until it is answered, rather than build an action whose approver renders no local port. Kinds 5, 6, 7
// and 16 have no O tool and no row, so they are refused until their owners name their fields
// (plan-MCP-wire-enum-numbers).
//
// Kind 18, mail_tls_unauthenticated, is the owner's answer to smtp-m9-06-tl4-allowance-action (QD-729): §14.4's TL4
// allowance for one recipient domain, host, in the one form a domain has here, lowercase with no trailing dot, so a
// domain has one action; and expires_millis for an allowance that ends. Its host is filled even by a template, since
// D-SMTP-2's consent is per recipient domain and an empty host would match them all.
//
// Package-level functions are safe for concurrent use: the table never changes.

package sidecar

import (
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// The question that holds every kind binding a local port or a grant's ports.
const canonicalActionDetailQuestion = "record-m2-01-canonical-action-detail"

// Fields every action sets, whatever its kind: kind, version and scope (§16.8).
var canonicalActionCommonFields = []protoreflect.FieldNumber{
	canonicalActionFieldKind, canonicalActionFieldVersion, canonicalActionFieldScope,
}

// Fields QD-064 takes out of CanonicalAction, local_port, weight and alpn, which no row fills while record.proto
// still declares them.
var canonicalActionLeavingFields = []protoreflect.FieldNumber{24, 25, 34}

// What a grant's action carries to a GrantActivate (QD-064): expires_millis, grant_dst, grant_allow, rule_id and
// subject.
var canonicalActionGrantFields = []protoreflect.FieldNumber{8, 10, 11, 28, 29}

// One kind's row.
type CanonicalActionKindFields struct {
	Kind SidecarActionKind
	// Filled by every action of the kind but a template (scope = true), whose empty fields match anything. Only fields
	// whose zero value is no answer are here: a base_version or a ttl of 0 is one.
	Required []protoreflect.FieldNumber
	// May be filled.
	Optional []protoreflect.FieldNumber
	// The versions an action of the kind takes, the first its default.
	Versions []uint32
	// Fields the kind may fill only at version 2: field 37, format 2's versioning.
	Version2 []protoreflect.FieldNumber
	// The fields an action bound for a GrantActivate or a gate may carry beside kind, version and scope, which api,
	// every reader's GrantActivate check and each gate admit and nothing more (QD-064). Empty for a kind no server
	// path takes, which every server refuses.
	Server []protoreflect.FieldNumber
	// The open question that keeps the builder refusing the kind, empty when none does.
	Held string
	// String fields that hold a domain name, which the builder holds to its one form where filled
	// (canonicalActionDomainForm).
	Domains []protoreflect.FieldNumber
	// Required fields a template fills too, so no template of the kind matches every value of them.
	TemplateRequired []protoreflect.FieldNumber
}

// The rows, one a kind with an O tool, in SidecarActionKind's order.
var canonicalActionKindRows = []*CanonicalActionKindFields{
	{
		// tls_publish: host, port, audience and app_mode, which a publish always writes resolved and non-zero, then the
		// grant's fields and a raw link's SPKI pin (§13.7, §13.10)
		Kind:     SidecarActionPublish,
		Required: []protoreflect.FieldNumber{5, 6, 7, 33},
		Optional: []protoreflect.FieldNumber{8, 10, 11, 28, 29, 35},
		Versions: []uint32{1},
		Server:   []protoreflect.FieldNumber{5, 6, 7, 8, 10, 11, 28, 29, 33, 35},
		Held:     canonicalActionDetailQuestion,
	},
	{
		// socket_listen: the name and the grant's fields (§9.9)
		Kind:     SidecarActionListen,
		Required: []protoreflect.FieldNumber{23},
		Optional: canonicalActionGrantFields,
		Versions: []uint32{1},
		Server:   canonicalActionGrantFields,
		Held:     canonicalActionDetailQuestion,
	},
	{
		// bridge_forward: the target sidecar, its port and the expiry (§17), a dial grant
		Kind:     SidecarActionForward,
		Required: []protoreflect.FieldNumber{26, 27},
		Optional: []protoreflect.FieldNumber{8},
		Versions: []uint32{1},
		Server:   canonicalActionGrantFields,
		Held:     canonicalActionDetailQuestion,
	},
	{
		// bridge_expose: the target, its prefixes or port and the expiry, filed as BridgeRoute or BridgeMap rules
		// sealed in their bodies, which no server reads (§17.8)
		Kind:     SidecarActionExpose,
		Required: []protoreflect.FieldNumber{26},
		Optional: []protoreflect.FieldNumber{8, 9, 27},
		Versions: []uint32{1},
		Held:     canonicalActionDetailQuestion,
	},
	{
		// mail_alias_create(alias, group?) (§15.8)
		Kind:     SidecarActionAliasCreate,
		Required: []protoreflect.FieldNumber{22},
		Optional: []protoreflect.FieldNumber{36},
		Versions: []uint32{1},
	},
	{
		// mail_alias_delete(alias): the alias and its mailcfg record's repo, path and base version (§16.6's evs row)
		Kind:     SidecarActionAliasDelete,
		Required: []protoreflect.FieldNumber{14, 15, 22},
		Optional: []protoreflect.FieldNumber{17},
		Versions: []uint32{1},
	},
	{
		// O-tier evs_write of an agent-config file: repo, path, content hash and base version, and versioning at
		// format 2's version (§11.7)
		Kind:     SidecarActionAgentConfigWrite,
		Required: []protoreflect.FieldNumber{14, 15, 16},
		Optional: []protoreflect.FieldNumber{17},
		Versions: []uint32{1, 2},
		Version2: []protoreflect.FieldNumber{canonicalActionFieldVersioning},
	},
	{
		// O-tier evs_delete of one: repo, path and base version
		Kind:     SidecarActionAgentConfigDelete,
		Required: []protoreflect.FieldNumber{14, 15},
		Optional: []protoreflect.FieldNumber{16, 17},
		Versions: []uint32{1, 2},
		Version2: []protoreflect.FieldNumber{canonicalActionFieldVersioning},
	},
	{
		// dns_set(name, type, value), and §12.8's gate's expiry
		Kind:     SidecarActionDnsSet,
		Required: []protoreflect.FieldNumber{18, 19, 20},
		Optional: []protoreflect.FieldNumber{8, 21},
		Versions: []uint32{1},
		Server:   []protoreflect.FieldNumber{8, 18, 19, 20, 21},
	},
	{
		// dns_delete(name, type)
		Kind:     SidecarActionDnsDelete,
		Required: []protoreflect.FieldNumber{18, 19},
		Optional: []protoreflect.FieldNumber{8, 20, 21},
		Versions: []uint32{1},
		Server:   []protoreflect.FieldNumber{8, 18, 19, 20, 21},
	},
	{
		// mail_send: every recipient, the body's hash, the daemon's preview and from_alias (§15)
		Kind:     SidecarActionMail,
		Required: []protoreflect.FieldNumber{2, 3, 22},
		Optional: []protoreflect.FieldNumber{4},
		Versions: []uint32{1},
	},
	{
		// directory_request's access request at version 3 (16.11), which approvers refuse until MCP-M6-01 adds it
		Kind:     SidecarActionAccessRequest,
		Required: []protoreflect.FieldNumber{10, 11},
		Optional: []protoreflect.FieldNumber{8, 14, 26, 27, 29},
		Versions: []uint32{3},
		Server:   []protoreflect.FieldNumber{8, 10, 11, 14, 26, 27, 29},
	},
	{
		// run_restore: the run, its preview and, for shell paths, the paths named (16.7)
		Kind:     SidecarActionRestore,
		Required: []protoreflect.FieldNumber{30, 32},
		Optional: []protoreflect.FieldNumber{31},
		Versions: []uint32{1},
	},
	{
		// §14.4's TL4 allowance (QD-729): the recipient domain as host, and when the allowance ends, 0 for never. No
		// server path takes it: the allowance lives in the desktop's store
		Kind:             SidecarActionMailTlsUnauthenticated,
		Required:         []protoreflect.FieldNumber{5},
		Optional:         []protoreflect.FieldNumber{8},
		Versions:         []uint32{1},
		Domains:          []protoreflect.FieldNumber{5},
		TemplateRequired: []protoreflect.FieldNumber{5},
	},
}

// A kind's row: what it must and may fill. False for a kind with no row, which no builder or server takes.
func CanonicalActionFields(kind SidecarActionKind) (*CanonicalActionKindFields, bool) {
	for _, row := range canonicalActionKindRows {
		if row.Kind == kind {
			return row, true
		}
	}
	return nil, false
}

// Whether an action of this row at version may fill field.
func (self *CanonicalActionKindFields) allows(field protoreflect.FieldNumber, version uint32) bool {
	return slices.Contains(canonicalActionCommonFields, field) || slices.Contains(self.Required, field) ||
		slices.Contains(self.Optional, field) || (version == 2 && slices.Contains(self.Version2, field))
}

// Whether name is a domain in the one form a row's Domains fields take: dot-separated labels of 1 to 63 lowercase
// letters, digits and inner hyphens, with no trailing dot. Capitals and a trailing dot are refused rather than
// folded, so the bytes an approver hashes name one domain one way. The whole name's length is its component's to
// bound, under its own settings: the sender's holds a recipient domain to RFC 5321's Domain before it builds one.
func canonicalActionDomainForm(name string) bool {
	for label := range strings.SplitSeq(name, ".") {
		if !isDnsLowerLdhLabel(label) {
			return false
		}
	}
	return true
}

// Whether a server path takes this kind, and may see field on it.
func (self *CanonicalActionKindFields) serverAllows(field protoreflect.FieldNumber) bool {
	return 0 < len(self.Server) &&
		(slices.Contains(canonicalActionCommonFields, field) || slices.Contains(self.Server, field))
}
