// MCP-M3-02's kind table: for each SidecarActionKind, the CanonicalAction fields an action of that kind must and may
// fill, the versions it takes, the fields an action bound for a GrantActivate or a gate may carry there, and the
// daemon-built ApprovalRequest fields its request may carry beside it. One table, so the builder, the template match,
// every server path and the request's parser read the same rows, and the rule set is data: a kind's fields change in
// a row, never in code.
//
// The rows follow MCP.md's MCP-M3-02 and the owner's answers to protos-services-canonical-action (QD-064),
// record-m2-01-canonical-action-detail (QD-740) and canonical-action-detail-listen-socket-name (QD-772), which
// combine by field:
//
//	server   a grant carries 8, 10, 11, 28 and 29, a publish's also 5, 6, 7, 33 and 35, a version-3 access_request 8,
//	         10, 11, 14, 26, 29 and 38, and a dns_* action 8 and 18 to 21, each with kind, version and scope
//	request  local_port, weight and alpn left CanonicalAction (24, 25 and 34 reserved) for ApprovalRequest's 14, 15
//	         and 16, sealed with the request in its entry, for every kind that has them: publish its local port and
//	         ALPNs, listen its local port and weight, forward and expose their local port. A listen's socket_name
//	         left too (23 reserved) for ApprovalRequest's 17, which every listen's request carries
//	sealed   bridge_forward's grant is a dial or route grant, so it takes version 4: its target's port, and its
//	         grant_dst's port and prefix text, ride sealed_detail, 38, and its clear grant_dst names subjects alone;
//	         access_request's port rides there too, 27 leaving version 3's clear set. bridge_expose's action rides a
//	         rule body no server reads (§17.8), so it keeps 9 and 27 in the clear at version 1
//
// socket_listen's row is QD-772's: the action carries the grant's fields alone, its grant_dst naming the socket by one
// sock: entry in the form a server may already see (D-SOCK-13), sock:<name> for a tls/ or smtp/ name and sock:<its
// token path in hex> for an application name (SocketListenGrantDst), so a listen's action passes every server path as
// QD-064's grant column stands and a listen's grant activates there. Its request carries the name as socket_name,
// which agrees with that entry: a parse holds what needs no key (approvalRequestDetailCheck), and an approver's
// device the token path under its K_sock (ApprovalApprover). A template names its socket too, so no multi-use
// decision covers every listen. Kinds 6, 7 and 16 have no O tool and no row, so they are refused until their owners
// name their fields (plan-MCP-wire-enum-numbers).
//
// Kind 5, egress_change, is the owner's answer to bridge-m4-19-egress-change-action (QD-799): §17.9's egress spec, an
// outward act that only a person's confirmed command asks for. It names its subject and egress_mode, 39, a
// BridgeEgressMode, and under exits its exits in grant_dst, sidecar:<id> entries or one tag:<id>, each id in
// lowercase hex; auto and none name none, a shape every parser holds (checkEgressChangeAction). A template names its
// subject and mode too, so no
// multi-use decision sets every subject's route. No server path takes it: its BridgeEgress rides the log as its own
// statement, which no GrantActivate or gate carries.
//
// Kind 18, mail_tls_unauthenticated, is the owner's answer to smtp-m9-06-tl4-allowance-action (QD-729): §14.4's TL4
// allowance for one recipient domain, host, in the one form a domain has here, lowercase with no trailing dot, so a
// domain has one action; and expires_millis for an allowance that ends. Its host is filled even by a template, since
// D-SMTP-2's consent is per recipient domain and an empty host would match them all.
//
// Package-level functions are safe for concurrent use: the table never changes.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// A listen's socket_name that does not agree with its action's grant_dst (QD-772): a name not in its one form or in a
// namespace no listen action names, an action naming no one socket, or a sock: entry naming another socket than the
// name, or one a device holding no K_sock could not derive.
var ErrSocketListenName = errors.New("a listen's socket name does not agree with its action's grant_dst")

// Fields every action sets, whatever its kind: kind, version and scope (§16.8).
var canonicalActionCommonFields = []protoreflect.FieldNumber{
	canonicalActionFieldKind, canonicalActionFieldVersion, canonicalActionFieldScope,
}

// What a grant's action carries to a GrantActivate (QD-064): expires_millis, grant_dst, grant_allow, rule_id and
// subject.
var canonicalActionGrantFields = []protoreflect.FieldNumber{8, canonicalActionFieldGrantDst, 11, 28, 29}

// ApprovalRequest's daemon-built fields beside its action: local_port, weight and alpn (QD-740), and socket_name
// (QD-772).
const (
	approvalRequestFieldLocalPort  protoreflect.FieldNumber = 14
	approvalRequestFieldWeight     protoreflect.FieldNumber = 15
	approvalRequestFieldAlpn       protoreflect.FieldNumber = 16
	approvalRequestFieldSocketName protoreflect.FieldNumber = 17
)

// Every one of them, which a request of a kind whose row names none may not set, in the order an approver's render
// shows them: the name first, as what a listen is.
var approvalRequestDetailFields = []protoreflect.FieldNumber{
	approvalRequestFieldSocketName, approvalRequestFieldLocalPort, approvalRequestFieldWeight, approvalRequestFieldAlpn,
}

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
	// ApprovalRequest's daemon-built fields a request for the kind may carry beside its action: 14 local_port, 15
	// weight, 16 alpn (QD-740), 17 socket_name (QD-772). Empty for a kind that binds none, whose request setting one is
	// refused.
	Request []protoreflect.FieldNumber
	// Of Request, those every request for the kind carries, a template's included: a listen's socket_name, which says
	// what the listen is (QD-772). A request without one is refused.
	RequestRequired []protoreflect.FieldNumber
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
		// grant's fields and a raw link's SPKI pin (§13.7, §13.10); its request binds the local port and the ALPNs
		Kind:     SidecarActionPublish,
		Required: []protoreflect.FieldNumber{5, 6, 7, 33},
		Optional: []protoreflect.FieldNumber{8, 10, 11, 28, 29, 35},
		Versions: []uint32{1},
		Server:   []protoreflect.FieldNumber{5, 6, 7, 8, 10, 11, 28, 29, 33, 35},
		Request:  []protoreflect.FieldNumber{approvalRequestFieldLocalPort, approvalRequestFieldAlpn},
	},
	{
		// socket_listen: the grant's fields (§9.9), grant_dst naming the socket as a server may see it, which a template
		// fills too (QD-772); its request binds the name, the local port and the weight
		Kind:     SidecarActionListen,
		Required: []protoreflect.FieldNumber{canonicalActionFieldGrantDst},
		Optional: []protoreflect.FieldNumber{8, 11, 28, 29},
		Versions: []uint32{1},
		Server:   canonicalActionGrantFields,
		Request: []protoreflect.FieldNumber{
			approvalRequestFieldSocketName, approvalRequestFieldLocalPort, approvalRequestFieldWeight,
		},
		RequestRequired:  []protoreflect.FieldNumber{approvalRequestFieldSocketName},
		TemplateRequired: []protoreflect.FieldNumber{canonicalActionFieldGrantDst},
	},
	{
		// bridge_forward: a dial or route grant (§17), so version 4: the grant's fields, its destination a subject
		// alone, and the target's port sealed in sealed_detail; its request binds the local port. A template fills
		// its sealed_detail too, so no multi-use decision leaves a grant's ports and prefixes open
		Kind:             SidecarActionForward,
		Required:         []protoreflect.FieldNumber{canonicalActionFieldGrantDst, 11, 28, 29, canonicalActionFieldSealedDetail},
		Optional:         []protoreflect.FieldNumber{8},
		Versions:         []uint32{canonicalActionVersionSealedGrant},
		Server:           []protoreflect.FieldNumber{8, canonicalActionFieldGrantDst, 11, 28, 29, canonicalActionFieldSealedDetail},
		Request:          []protoreflect.FieldNumber{approvalRequestFieldLocalPort},
		TemplateRequired: []protoreflect.FieldNumber{canonicalActionFieldSealedDetail},
	},
	{
		// bridge_expose: the target, its prefixes or port and the expiry, filed as BridgeRoute or BridgeMap rules
		// sealed in their bodies, which no server reads (§17.8); its request binds the local port
		Kind:     SidecarActionExpose,
		Required: []protoreflect.FieldNumber{26},
		Optional: []protoreflect.FieldNumber{8, 9, 27},
		Versions: []uint32{1},
		Request:  []protoreflect.FieldNumber{approvalRequestFieldLocalPort},
	},
	{
		// egress_change (QD-799): the subject and its mode, and under exits the exits in grant_dst; a template names
		// the subject and the mode too. No server path takes it
		Kind:             SidecarActionEgressChange,
		Required:         []protoreflect.FieldNumber{29, canonicalActionFieldEgressMode},
		Optional:         []protoreflect.FieldNumber{canonicalActionFieldGrantDst},
		Versions:         []uint32{1},
		TemplateRequired: []protoreflect.FieldNumber{29, canonicalActionFieldEgressMode},
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
		// directory_request's access request at version 3 (16.11), which approvers know since MCP-M6-01; a
		// worker's port rides sealed_detail, so its clear fields name no port (QD-740)
		Kind:     SidecarActionAccessRequest,
		Required: []protoreflect.FieldNumber{canonicalActionFieldGrantDst, 11},
		Optional: []protoreflect.FieldNumber{8, 14, 26, 29, canonicalActionFieldSealedDetail},
		Versions: []uint32{canonicalActionVersionAccessRequest},
		Server:   []protoreflect.FieldNumber{8, canonicalActionFieldGrantDst, 11, 14, 26, 29, canonicalActionFieldSealedDetail},
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

// Whether a request for an action of this row may set ApprovalRequest's field.
func (self *CanonicalActionKindFields) requestAllows(field protoreflect.FieldNumber) bool {
	return slices.Contains(self.Request, field)
}

// Whether a server path takes this kind, and may see field on it.
func (self *CanonicalActionKindFields) serverAllows(field protoreflect.FieldNumber) bool {
	return 0 < len(self.Server) &&
		(slices.Contains(canonicalActionCommonFields, field) || slices.Contains(self.Server, field))
}

// §8.4's grant_dst kind of a socket, as ParseAclGrantDst reads it.
const socketListenGrantDstPrefix = "sock:"

// The namespace of a listen's name, held to the forms a listen's action names (QD-772): its one form, as
// ParseSocketName gives it, so a person approves one spelling, and an application name, which tools listen on, or a
// tls/ or smtp/ name, which Sidecar.Listen takes. share/ listens through ur share, which no approval covers, ur/ is the
// platform's, and a reserved name has no owner. The name stays out of every error, which a log may carry (I-13).
func socketListenNamespace(name string) (SocketNamespace, error) {
	canonical, namespace, err := ParseSocketName(name)
	if err != nil || canonical != name {
		return 0, fmt.Errorf("%w: no socket name in its one form", ErrSocketListenName)
	}
	switch namespace {
	case SocketNamespaceApplication, SocketNamespaceTls, SocketNamespaceSmtp:
		return namespace, nil
	}
	return 0, fmt.Errorf("%w: a namespace no listen's action names", ErrSocketListenName)
}

// The grant_dst entry a listen on name carries (QD-772), what a server may already see of the socket (D-SOCK-13):
// sock:<name> for a tls/ or smtp/ name, and for an application name sock:<its token path in lowercase hex> under keys,
// the network's current K_sock's, which may be nil for a tls/ or smtp/ name. name is in its one form, in a namespace
// a listen's action names (socketListenNamespace).
func SocketListenGrantDst(name string, keys *SocketKeys) (string, error) {
	namespace, err := socketListenNamespace(name)
	if err != nil {
		return "", err
	}
	if !namespace.blinded() {
		return socketListenGrantDstPrefix + name, nil
	}
	if keys == nil {
		return "", fmt.Errorf("%w: no K_sock to derive an application name's token path under", ErrSocketListenName)
	}
	tokenPath, err := keys.TokenPath(name)
	if err != nil {
		return "", fmt.Errorf("%w: no token path", ErrSocketListenName)
	}
	return socketListenGrantDstPrefix + hex.EncodeToString(tokenPath), nil
}

// Whether a listen's socket_name agrees with its action's grant_dst (QD-772): the action names one destination, the
// sock: entry SocketListenGrantDst gives the name. A tls/ or smtp/ name's is the name itself. An application name's is
// its token path, which K_sock alone decides: under ring's keys, the current and, while the file holds one, the
// previous (CompileKeys), so a request built under either through a rotation's overlap agrees. ring nil checks what
// holds without a key, an entry that reads as a token path in lowercase hex, 16 B a segment of the name, which is what
// a parse can hold; an approver passes its ring. The name stays out of every error, which a log may carry (I-13).
func checkSocketListenName(action *protocol.CanonicalAction, name string, ring *SocketKeyRing) error {
	namespace, err := socketListenNamespace(name)
	if err != nil {
		return err
	}
	grantDsts := action.GetGrantDst()
	if len(grantDsts) != 1 {
		return fmt.Errorf("%w: an action naming %d destinations", ErrSocketListenName, len(grantDsts))
	}
	value, isSocket := strings.CutPrefix(grantDsts[0], socketListenGrantDstPrefix)
	if !isSocket {
		return fmt.Errorf("%w: a grant_dst naming no socket", ErrSocketListenName)
	}
	if !namespace.blinded() {
		if value != name {
			return fmt.Errorf("%w: a grant_dst naming another socket", ErrSocketListenName)
		}
		return nil
	}
	tokenPath, err := hex.DecodeString(value)
	segmentCount := strings.Count(name, "/") + 1
	if err != nil || strings.ToLower(value) != value || len(tokenPath) != segmentCount*socketTokenByteCount {
		return fmt.Errorf("%w: a grant_dst that is no token path of the name's segments", ErrSocketListenName)
	}
	if ring == nil {
		return nil
	}
	tokenPaths, err := ring.CompileTokenPaths(name)
	if err != nil {
		return fmt.Errorf("%w: no token path", ErrSocketListenName)
	}
	if !slices.ContainsFunc(tokenPaths, func(candidate []byte) bool { return bytes.Equal(candidate, tokenPath) }) {
		return fmt.Errorf("%w: a grant_dst naming another socket", ErrSocketListenName)
	}
	return nil
}
