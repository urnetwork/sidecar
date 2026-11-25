// The record's primitives (§16.8), then RECORD.md's entry bodies. An entry is a sealed file, so evs parses none of it,
// and that is all the fence's "every field is sealed" below speaks of. Three of §16.8's messages also travel outside
// an entry, and servers parse them: api and the gates read ApprovalDecision and ApprovalCancel (§2.8's api-10), and
// whatever a CanonicalAction holds shows wherever a GrantActivate carries it into the log (api-7, §8.8) or a gate takes
// it beside a decision (api-10, §16.6's spend check). testdata/metadata/fields.yml maps those fields to their rows, and
// says which have none. RECORD.md's messages travel only sealed, in an entry or a deposit, an erasure's ErasureBody
// also as each of its ERASEs' sealed note (DESIGN-DETAILS 15.2.10, §16.11's moderation row), or in a packet a
// person hands to someone outside the log, so none of them needs a row (RECORD.md section 18; I-18).
//
// The four enums after §16.8's messages name the values CanonicalAction.kind, ApprovalRequest.risk and
// ApprovalDecision.decision and .channel carry, and those fields stay uint32 on the wire, as §16.8 writes them
// (plan-MCP-wire-enum-numbers). RECORD.md's kind numbers and classes are record_kind.go's rather than enums here: a
// header carries a kind as a number, and a reader keeps a kind it does not know (§16.8). A bare section number, as in
// 16.6, is DESIGN.md's, and "section n" is RECORD.md's.
//
// CanonicalAction's field 37 is reserved in D-PHASE-9's sense: declared here, and set only in version 2, for
// format 2's evs_write, so an approver that does not know that version refuses it (§16.8).
//
// The owners' answers the fences now write: local_port, weight and alpn left CanonicalAction, 24, 25 and 34 reserved,
// for ApprovalRequest's 14, 15 and 16, which ride sealed in the approval entry and never reach a server, and a dial or
// route grant's prefixes and ports ride sealed_detail = 38, a CanonicalActionDetail under §7.9's sealed-body format
// (owner decision 220), at version 4, as a version-3 access_request's port does (QD-740); socket_name left the same
// way, 23 reserved, for ApprovalRequest's 17, a listen's action naming its socket by its one grant_dst entry alone, in
// the form a server may see (QD-772); CanonicalAction gained require_default_egress = 41, an egress_change's
// requirement of default egress under exits (QD-1053, QD-1060), which approvers render and the gate binds; and
// ApprovalRequest gained uses = 18 at its version 2, the uses its agent asks a template's approval for, 1 for any other
// action, which approvers render and sign as ApprovalDecision.uses (QD-1010, owner decision 574). §16.8's fence writes
// those, and RECORD.md section 6.4's writes ContextBody's prompts = 17, the run's redacted user prompts in stage 2
// entries as they arrive, which a vault's run card reads (RECORD.md 7.4) and T's projection leaves empty (QD-900,
// owner decision 467), and ErasureBody's announcement_ids = 5, at reason 3: the announcements a directory admin's
// moderation took off the cards holding them, which the sealed note of every ERASE of its erasure names, its ERASE
// of a card's keys among them, while a person's erasure and a revocation's name none, and which the writer's sync
// journals so that every card it writes after leaves them out; a field of its own, never an entry's id, since every
// reader of a note takes entry_ids as entries erased (§16.11's moderation row; QD-1148, owner decision 664).
// design_unfenced_test.go writes CanonicalActionDetail, which no fence does.
//
// DESIGN-COMPUTE.md's version 5 (§16.3, §23.9, §25.10, §27.9; owner decisions 737, 749, 756, 757, 768, 772), this
// file's one change for it (CACL-M11-04; CONTRACTS C-26): CanonicalAction's fields 42 to 56, 60 and 70, with 57 to 59,
// 61 to 69 and 71 to 79 reserved, each message they hold numbered in the order the design writes its fields, the
// sealed CanonicalActionDetail5 that field 38 carries at version 5, kinds 19 to 26, ApprovalDecision's selected at its
// version 2 and auto and auto_verdict at its version 3, AutoVerdict, and channel 4, auto. §16.3's list is a text
// fence, so design_unfenced_test.go writes these fields and messages, as testFenceAdditions and testUnfencedFence,
// until a design-records fold writes them into §16.8's; §27.9's proto fence writes auto, auto_verdict, AutoVerdict and
// channel 4. No field holds a oneof: version tells field 38 which message it holds, and every text an approver's card
// shows is a string, every amount a uint64 of nano-USD, every enumerated value a uint32, as §16.8's are.
//
// DESIGN-COMPUTE.md §6.8's ModelCallBody fields 11 to 14 (INFER-M11-07; CONTRACTS C-26): the attestation of a TEE call
// §5 verified, the route, the catalog version and the platform field, attested only with that attestation, and the
// import of protocol/attest.proto, whose AttestationResult field 11 holds. Field 15, CallContext, is CTXH-M11-01's.
//
// DESIGN-COMPUTE.md §24.5's session wire (CTXH-M11-01; CONTRACTS C-26): kinds 54 session_entry's and 55 session_blob's
// bodies, SessionEntryBody, SessionPart and SessionBlobBody, as §24.5's fence writes them; CallContext, ModelCallBody
// field 15; RecordEntry.body_apart = 6, a session entry's sealed body filed apart from its header, at s/<n> beside its
// e/<n> (Appendix D's RECORD.md 5.2 to 5.7 rows), which every reader learns at format 1; Coverage.bodies_dropped = 8
// with SeqRange (Appendix D's Coverage row); and ApprovalNotice, owner decision 573's per-request notice at
// a/<approval_id>, shaped as §16.11's DirectoryNotice (compute-plan-approval-notice-bytes, QD-1234). Each travels only
// sealed, inside an entry or a vault file, so none adds a server-visible field (§24.11), and design_unfenced_test.go
// writes what no fence does yet: body_apart, bodies_dropped, SeqRange and ApprovalNotice.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.11
// 	protoc        v7.36.2
// source: protocol/record.proto

package protocol

import (
	bridge "github.com/urnetwork/sidecar/protocol/bridge"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// plan-MCP-wire-enum-numbers: names for what §16.8's uint32 fields carry, 0 unspecified and written by no one. An
// approver, spender or gate refuses 0 or a value it does not know in any of them; §16.8's "unknown kinds are kept"
// speaks of RecordHeader.kind alone.
// CanonicalAction.kind: §5.4's SidecarActionKind in its order, one verb a value, 16.7's restore appended, and new
// kinds append. publish and listen cover tls/ and smtp/ alike, since host, and a listen's request's socket_name, say
// which.
// mail_tls_unauthenticated is §14.4's TL4 allowance for one recipient domain, host (QD-729).
type SidecarActionKind int32

const (
	SidecarActionKind_SIDECAR_ACTION_KIND_UNSPECIFIED              SidecarActionKind = 0
	SidecarActionKind_SIDECAR_ACTION_KIND_PUBLISH                  SidecarActionKind = 1
	SidecarActionKind_SIDECAR_ACTION_KIND_LISTEN                   SidecarActionKind = 2
	SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD                  SidecarActionKind = 3
	SidecarActionKind_SIDECAR_ACTION_KIND_EXPOSE                   SidecarActionKind = 4
	SidecarActionKind_SIDECAR_ACTION_KIND_EGRESS_CHANGE            SidecarActionKind = 5
	SidecarActionKind_SIDECAR_ACTION_KIND_INVITE                   SidecarActionKind = 6
	SidecarActionKind_SIDECAR_ACTION_KIND_SHARE                    SidecarActionKind = 7
	SidecarActionKind_SIDECAR_ACTION_KIND_ALIAS_CREATE             SidecarActionKind = 8
	SidecarActionKind_SIDECAR_ACTION_KIND_ALIAS_DELETE             SidecarActionKind = 9
	SidecarActionKind_SIDECAR_ACTION_KIND_AGENT_CONFIG_WRITE       SidecarActionKind = 10
	SidecarActionKind_SIDECAR_ACTION_KIND_AGENT_CONFIG_DELETE      SidecarActionKind = 11
	SidecarActionKind_SIDECAR_ACTION_KIND_DNS_SET                  SidecarActionKind = 12
	SidecarActionKind_SIDECAR_ACTION_KIND_DNS_DELETE               SidecarActionKind = 13
	SidecarActionKind_SIDECAR_ACTION_KIND_MAIL_SEND                SidecarActionKind = 14
	SidecarActionKind_SIDECAR_ACTION_KIND_ACCESS_REQUEST           SidecarActionKind = 15
	SidecarActionKind_SIDECAR_ACTION_KIND_PAYMENT                  SidecarActionKind = 16
	SidecarActionKind_SIDECAR_ACTION_KIND_RESTORE                  SidecarActionKind = 17
	SidecarActionKind_SIDECAR_ACTION_KIND_MAIL_TLS_UNAUTHENTICATED SidecarActionKind = 18
	// DESIGN-COMPUTE.md §16.3's, each at version 5 alone
	SidecarActionKind_SIDECAR_ACTION_KIND_ENCLAVE_CREATE        SidecarActionKind = 19
	SidecarActionKind_SIDECAR_ACTION_KIND_ENCLAVE_EGRESS_DIRECT SidecarActionKind = 20
	SidecarActionKind_SIDECAR_ACTION_KIND_COMPUTE_BUDGET_RAISE  SidecarActionKind = 21
	SidecarActionKind_SIDECAR_ACTION_KIND_ENCLAVE_DELETE        SidecarActionKind = 22
	SidecarActionKind_SIDECAR_ACTION_KIND_FETCH_UNLISTED_URL    SidecarActionKind = 23
	SidecarActionKind_SIDECAR_ACTION_KIND_TAINTED_SEND          SidecarActionKind = 24
	SidecarActionKind_SIDECAR_ACTION_KIND_CALENDAR_WRITE        SidecarActionKind = 25
	SidecarActionKind_SIDECAR_ACTION_KIND_SERVICE_WRITE         SidecarActionKind = 26
	SidecarActionKind_SIDECAR_ACTION_KIND_SUPPORT_SEND          SidecarActionKind = 27 // DESIGN-COMPUTE.md §28.8's
)

// Enum value maps for SidecarActionKind.
var (
	SidecarActionKind_name = map[int32]string{
		0:  "SIDECAR_ACTION_KIND_UNSPECIFIED",
		1:  "SIDECAR_ACTION_KIND_PUBLISH",
		2:  "SIDECAR_ACTION_KIND_LISTEN",
		3:  "SIDECAR_ACTION_KIND_FORWARD",
		4:  "SIDECAR_ACTION_KIND_EXPOSE",
		5:  "SIDECAR_ACTION_KIND_EGRESS_CHANGE",
		6:  "SIDECAR_ACTION_KIND_INVITE",
		7:  "SIDECAR_ACTION_KIND_SHARE",
		8:  "SIDECAR_ACTION_KIND_ALIAS_CREATE",
		9:  "SIDECAR_ACTION_KIND_ALIAS_DELETE",
		10: "SIDECAR_ACTION_KIND_AGENT_CONFIG_WRITE",
		11: "SIDECAR_ACTION_KIND_AGENT_CONFIG_DELETE",
		12: "SIDECAR_ACTION_KIND_DNS_SET",
		13: "SIDECAR_ACTION_KIND_DNS_DELETE",
		14: "SIDECAR_ACTION_KIND_MAIL_SEND",
		15: "SIDECAR_ACTION_KIND_ACCESS_REQUEST",
		16: "SIDECAR_ACTION_KIND_PAYMENT",
		17: "SIDECAR_ACTION_KIND_RESTORE",
		18: "SIDECAR_ACTION_KIND_MAIL_TLS_UNAUTHENTICATED",
		19: "SIDECAR_ACTION_KIND_ENCLAVE_CREATE",
		20: "SIDECAR_ACTION_KIND_ENCLAVE_EGRESS_DIRECT",
		21: "SIDECAR_ACTION_KIND_COMPUTE_BUDGET_RAISE",
		22: "SIDECAR_ACTION_KIND_ENCLAVE_DELETE",
		23: "SIDECAR_ACTION_KIND_FETCH_UNLISTED_URL",
		24: "SIDECAR_ACTION_KIND_TAINTED_SEND",
		25: "SIDECAR_ACTION_KIND_CALENDAR_WRITE",
		26: "SIDECAR_ACTION_KIND_SERVICE_WRITE",
		27: "SIDECAR_ACTION_KIND_SUPPORT_SEND",
	}
	SidecarActionKind_value = map[string]int32{
		"SIDECAR_ACTION_KIND_UNSPECIFIED":              0,
		"SIDECAR_ACTION_KIND_PUBLISH":                  1,
		"SIDECAR_ACTION_KIND_LISTEN":                   2,
		"SIDECAR_ACTION_KIND_FORWARD":                  3,
		"SIDECAR_ACTION_KIND_EXPOSE":                   4,
		"SIDECAR_ACTION_KIND_EGRESS_CHANGE":            5,
		"SIDECAR_ACTION_KIND_INVITE":                   6,
		"SIDECAR_ACTION_KIND_SHARE":                    7,
		"SIDECAR_ACTION_KIND_ALIAS_CREATE":             8,
		"SIDECAR_ACTION_KIND_ALIAS_DELETE":             9,
		"SIDECAR_ACTION_KIND_AGENT_CONFIG_WRITE":       10,
		"SIDECAR_ACTION_KIND_AGENT_CONFIG_DELETE":      11,
		"SIDECAR_ACTION_KIND_DNS_SET":                  12,
		"SIDECAR_ACTION_KIND_DNS_DELETE":               13,
		"SIDECAR_ACTION_KIND_MAIL_SEND":                14,
		"SIDECAR_ACTION_KIND_ACCESS_REQUEST":           15,
		"SIDECAR_ACTION_KIND_PAYMENT":                  16,
		"SIDECAR_ACTION_KIND_RESTORE":                  17,
		"SIDECAR_ACTION_KIND_MAIL_TLS_UNAUTHENTICATED": 18,
		"SIDECAR_ACTION_KIND_ENCLAVE_CREATE":           19,
		"SIDECAR_ACTION_KIND_ENCLAVE_EGRESS_DIRECT":    20,
		"SIDECAR_ACTION_KIND_COMPUTE_BUDGET_RAISE":     21,
		"SIDECAR_ACTION_KIND_ENCLAVE_DELETE":           22,
		"SIDECAR_ACTION_KIND_FETCH_UNLISTED_URL":       23,
		"SIDECAR_ACTION_KIND_TAINTED_SEND":             24,
		"SIDECAR_ACTION_KIND_CALENDAR_WRITE":           25,
		"SIDECAR_ACTION_KIND_SERVICE_WRITE":            26,
		"SIDECAR_ACTION_KIND_SUPPORT_SEND":             27,
	}
)

func (x SidecarActionKind) Enum() *SidecarActionKind {
	p := new(SidecarActionKind)
	*p = x
	return p
}

func (x SidecarActionKind) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SidecarActionKind) Descriptor() protoreflect.EnumDescriptor {
	return file_protocol_record_proto_enumTypes[0].Descriptor()
}

func (SidecarActionKind) Type() protoreflect.EnumType {
	return &file_protocol_record_proto_enumTypes[0]
}

func (x SidecarActionKind) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SidecarActionKind.Descriptor instead.
func (SidecarActionKind) EnumDescriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{0}
}

// ApprovalRequest.risk: numeric order is the max §5.4 takes, and an agent may only raise it.
type SidecarRisk int32

const (
	SidecarRisk_SIDECAR_RISK_UNSPECIFIED SidecarRisk = 0
	SidecarRisk_SIDECAR_RISK_NORMAL      SidecarRisk = 1
	SidecarRisk_SIDECAR_RISK_HIGH        SidecarRisk = 2
)

// Enum value maps for SidecarRisk.
var (
	SidecarRisk_name = map[int32]string{
		0: "SIDECAR_RISK_UNSPECIFIED",
		1: "SIDECAR_RISK_NORMAL",
		2: "SIDECAR_RISK_HIGH",
	}
	SidecarRisk_value = map[string]int32{
		"SIDECAR_RISK_UNSPECIFIED": 0,
		"SIDECAR_RISK_NORMAL":      1,
		"SIDECAR_RISK_HIGH":        2,
	}
)

func (x SidecarRisk) Enum() *SidecarRisk {
	p := new(SidecarRisk)
	*p = x
	return p
}

func (x SidecarRisk) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SidecarRisk) Descriptor() protoreflect.EnumDescriptor {
	return file_protocol_record_proto_enumTypes[1].Descriptor()
}

func (SidecarRisk) Type() protoreflect.EnumType {
	return &file_protocol_record_proto_enumTypes[1]
}

func (x SidecarRisk) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SidecarRisk.Descriptor instead.
func (SidecarRisk) EnumDescriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{1}
}

// ApprovalDecision.decision.
type ApprovalVerdict int32

const (
	ApprovalVerdict_APPROVAL_VERDICT_UNSPECIFIED ApprovalVerdict = 0
	ApprovalVerdict_APPROVAL_VERDICT_APPROVE     ApprovalVerdict = 1
	ApprovalVerdict_APPROVAL_VERDICT_DENY        ApprovalVerdict = 2
)

// Enum value maps for ApprovalVerdict.
var (
	ApprovalVerdict_name = map[int32]string{
		0: "APPROVAL_VERDICT_UNSPECIFIED",
		1: "APPROVAL_VERDICT_APPROVE",
		2: "APPROVAL_VERDICT_DENY",
	}
	ApprovalVerdict_value = map[string]int32{
		"APPROVAL_VERDICT_UNSPECIFIED": 0,
		"APPROVAL_VERDICT_APPROVE":     1,
		"APPROVAL_VERDICT_DENY":        2,
	}
)

func (x ApprovalVerdict) Enum() *ApprovalVerdict {
	p := new(ApprovalVerdict)
	*p = x
	return p
}

func (x ApprovalVerdict) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ApprovalVerdict) Descriptor() protoreflect.EnumDescriptor {
	return file_protocol_record_proto_enumTypes[2].Descriptor()
}

func (ApprovalVerdict) Type() protoreflect.EnumType {
	return &file_protocol_record_proto_enumTypes[2]
}

func (x ApprovalVerdict) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ApprovalVerdict.Descriptor instead.
func (ApprovalVerdict) EnumDescriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{2}
}

// ApprovalDecision.channel and AclRequestRule.evidence, as RECORD.md section 6.2 numbers them.
type ApprovalChannel int32

const (
	ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED ApprovalChannel = 0
	ApprovalChannel_APPROVAL_CHANNEL_DEVICE      ApprovalChannel = 1
	ApprovalChannel_APPROVAL_CHANNEL_PRESENCE    ApprovalChannel = 2
	ApprovalChannel_APPROVAL_CHANNEL_HARNESS     ApprovalChannel = 3
	ApprovalChannel_APPROVAL_CHANNEL_AUTO        ApprovalChannel = 4 // DESIGN-COMPUTE.md §27.9: decision version 3 alone
)

// Enum value maps for ApprovalChannel.
var (
	ApprovalChannel_name = map[int32]string{
		0: "APPROVAL_CHANNEL_UNSPECIFIED",
		1: "APPROVAL_CHANNEL_DEVICE",
		2: "APPROVAL_CHANNEL_PRESENCE",
		3: "APPROVAL_CHANNEL_HARNESS",
		4: "APPROVAL_CHANNEL_AUTO",
	}
	ApprovalChannel_value = map[string]int32{
		"APPROVAL_CHANNEL_UNSPECIFIED": 0,
		"APPROVAL_CHANNEL_DEVICE":      1,
		"APPROVAL_CHANNEL_PRESENCE":    2,
		"APPROVAL_CHANNEL_HARNESS":     3,
		"APPROVAL_CHANNEL_AUTO":        4,
	}
)

func (x ApprovalChannel) Enum() *ApprovalChannel {
	p := new(ApprovalChannel)
	*p = x
	return p
}

func (x ApprovalChannel) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ApprovalChannel) Descriptor() protoreflect.EnumDescriptor {
	return file_protocol_record_proto_enumTypes[3].Descriptor()
}

func (ApprovalChannel) Type() protoreflect.EnumType {
	return &file_protocol_record_proto_enumTypes[3]
}

func (x ApprovalChannel) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ApprovalChannel.Descriptor instead.
func (ApprovalChannel) EnumDescriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{3}
}

// sidecar/protocol/record.proto; frozen at M3's entry review (D-MCP-6). Frozen means wire-stable: numbers and
// meanings never change, versions add fields; every hash and signature covers stored bytes. Every field is
// sealed: each RecordEntry is a file in its writer's stream (§11.8), and evs sees only §2.8's evs rows. The leaf
// hash SHA-256(0x00 || Signed.body) (RFC 9162) admits M6's verifiable log (16.18). §6.11 SignedType: 0x1801
// SIGNED_RECORD_HEADER, 0x1802 SIGNED_APPROVAL_DECISION, 0x1803 SIGNED_APPROVAL_CANCEL, 0x1804
// SIGNED_RETENTION_POLICY.
type RecordHeader struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	EntryId         []byte                 `protobuf:"bytes,1,opt,name=entry_id,json=entryId,proto3" json:"entry_id,omitempty"`
	LogId           []byte                 `protobuf:"bytes,2,opt,name=log_id,json=logId,proto3" json:"log_id,omitempty"` // random; repo id
	WriterSidecarId []byte                 `protobuf:"bytes,3,opt,name=writer_sidecar_id,json=writerSidecarId,proto3" json:"writer_sidecar_id,omitempty"`
	Seq             uint64                 `protobuf:"varint,4,opt,name=seq,proto3" json:"seq,omitempty"`
	PrevSha256      []byte                 `protobuf:"bytes,5,opt,name=prev_sha256,json=prevSha256,proto3" json:"prev_sha256,omitempty"` // per-writer chain
	AgentId         []byte                 `protobuf:"bytes,6,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
	RunId           []byte                 `protobuf:"bytes,7,opt,name=run_id,json=runId,proto3" json:"run_id,omitempty"`
	ActionId        []byte                 `protobuf:"bytes,8,opt,name=action_id,json=actionId,proto3" json:"action_id,omitempty"`
	Kind            uint32                 `protobuf:"varint,9,opt,name=kind,proto3" json:"kind,omitempty"` // RECORD.md's v1 registry; unknown kinds are kept and shown generically: coordination
	// log: claim, handoff, ask, answer, check, note, and, in the team directory, announce,
	// request, decision and erasure_request (claims and handoffs there are state of a run's
	// announcement, 16.11). Team record: context, change, approval, route, publish, reach,
	// membership, key, coverage, read, erasure, restore, inventory. Vault: raw content and read
	// receipts, plus every kind in a personal network.
	// membership and key entries mirror §5's SidecarEvents, admission alarms included,
	// into each affected log; a member's own device revocation's names its approval
	// evidence, presence with its assertion or a confirmation (§5.6).
	TimeMillis int64  `protobuf:"varint,10,opt,name=time_millis,json=timeMillis,proto3" json:"time_millis,omitempty"`
	Source     uint32 `protobuf:"varint,11,opt,name=source,proto3" json:"source,omitempty"` // observed (the daemon did or saw it), hook (any same-user process can fake it),
	// agent, approver
	Tainted        bool          `protobuf:"varint,12,opt,name=tainted,proto3" json:"tainted,omitempty"`
	BodyCommitment []byte        `protobuf:"bytes,13,opt,name=body_commitment,json=bodyCommitment,proto3" json:"body_commitment,omitempty"` // SHA-256("urnetwork-sidecar-v1/record-body" || salt || body)
	Content        []*ContentRef `protobuf:"bytes,14,rep,name=content,proto3" json:"content,omitempty"`
	PolicyVersion  uint64        `protobuf:"varint,15,opt,name=policy_version,json=policyVersion,proto3" json:"policy_version,omitempty"`
	GrantId        []byte        `protobuf:"bytes,16,opt,name=grant_id,json=grantId,proto3" json:"grant_id,omitempty"`
	AgentSource    uint32        `protobuf:"varint,17,opt,name=agent_source,json=agentSource,proto3" json:"agent_source,omitempty"` // agent_asserted, or isolated (own OS user, container or VM; §5.5)
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *RecordHeader) Reset() {
	*x = RecordHeader{}
	mi := &file_protocol_record_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RecordHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RecordHeader) ProtoMessage() {}

func (x *RecordHeader) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RecordHeader.ProtoReflect.Descriptor instead.
func (*RecordHeader) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{0}
}

func (x *RecordHeader) GetEntryId() []byte {
	if x != nil {
		return x.EntryId
	}
	return nil
}

func (x *RecordHeader) GetLogId() []byte {
	if x != nil {
		return x.LogId
	}
	return nil
}

func (x *RecordHeader) GetWriterSidecarId() []byte {
	if x != nil {
		return x.WriterSidecarId
	}
	return nil
}

func (x *RecordHeader) GetSeq() uint64 {
	if x != nil {
		return x.Seq
	}
	return 0
}

func (x *RecordHeader) GetPrevSha256() []byte {
	if x != nil {
		return x.PrevSha256
	}
	return nil
}

func (x *RecordHeader) GetAgentId() []byte {
	if x != nil {
		return x.AgentId
	}
	return nil
}

func (x *RecordHeader) GetRunId() []byte {
	if x != nil {
		return x.RunId
	}
	return nil
}

func (x *RecordHeader) GetActionId() []byte {
	if x != nil {
		return x.ActionId
	}
	return nil
}

func (x *RecordHeader) GetKind() uint32 {
	if x != nil {
		return x.Kind
	}
	return 0
}

func (x *RecordHeader) GetTimeMillis() int64 {
	if x != nil {
		return x.TimeMillis
	}
	return 0
}

func (x *RecordHeader) GetSource() uint32 {
	if x != nil {
		return x.Source
	}
	return 0
}

func (x *RecordHeader) GetTainted() bool {
	if x != nil {
		return x.Tainted
	}
	return false
}

func (x *RecordHeader) GetBodyCommitment() []byte {
	if x != nil {
		return x.BodyCommitment
	}
	return nil
}

func (x *RecordHeader) GetContent() []*ContentRef {
	if x != nil {
		return x.Content
	}
	return nil
}

func (x *RecordHeader) GetPolicyVersion() uint64 {
	if x != nil {
		return x.PolicyVersion
	}
	return 0
}

func (x *RecordHeader) GetGrantId() []byte {
	if x != nil {
		return x.GrantId
	}
	return nil
}

func (x *RecordHeader) GetAgentSource() uint32 {
	if x != nil {
		return x.AgentSource
	}
	return 0
}

type ContentRef struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RepoId        []byte                 `protobuf:"bytes,1,opt,name=repo_id,json=repoId,proto3" json:"repo_id,omitempty"`
	ObjectId      []byte                 `protobuf:"bytes,2,opt,name=object_id,json=objectId,proto3" json:"object_id,omitempty"`
	Commitment    []byte                 `protobuf:"bytes,3,opt,name=commitment,proto3" json:"commitment,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ContentRef) Reset() {
	*x = ContentRef{}
	mi := &file_protocol_record_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContentRef) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContentRef) ProtoMessage() {}

func (x *ContentRef) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContentRef.ProtoReflect.Descriptor instead.
func (*ContentRef) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{1}
}

func (x *ContentRef) GetRepoId() []byte {
	if x != nil {
		return x.RepoId
	}
	return nil
}

func (x *ContentRef) GetObjectId() []byte {
	if x != nil {
		return x.ObjectId
	}
	return nil
}

func (x *ContentRef) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

type RecordEntry struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Header        *bridge.Signed         `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	SealedBody    []byte                 `protobuf:"bytes,2,opt,name=sealed_body,json=sealedBody,proto3" json:"sealed_body,omitempty"`
	KeySlotId     []byte                 `protobuf:"bytes,3,opt,name=key_slot_id,json=keySlotId,proto3" json:"key_slot_id,omitempty"` // with key_index, the body key's slot object and index (Erasure)
	Version       uint32                 `protobuf:"varint,4,opt,name=version,proto3" json:"version,omitempty"`                       // 1
	KeyIndex      uint32                 `protobuf:"varint,5,opt,name=key_index,json=keyIndex,proto3" json:"key_index,omitempty"`
	BodyApart     bool                   `protobuf:"varint,6,opt,name=body_apart,json=bodyApart,proto3" json:"body_apart,omitempty"` // a session entry's (kinds 54, 55; DESIGN-COMPUTE §24.5): sealed_body
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RecordEntry) Reset() {
	*x = RecordEntry{}
	mi := &file_protocol_record_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RecordEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RecordEntry) ProtoMessage() {}

func (x *RecordEntry) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RecordEntry.ProtoReflect.Descriptor instead.
func (*RecordEntry) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{2}
}

func (x *RecordEntry) GetHeader() *bridge.Signed {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *RecordEntry) GetSealedBody() []byte {
	if x != nil {
		return x.SealedBody
	}
	return nil
}

func (x *RecordEntry) GetKeySlotId() []byte {
	if x != nil {
		return x.KeySlotId
	}
	return nil
}

func (x *RecordEntry) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *RecordEntry) GetKeyIndex() uint32 {
	if x != nil {
		return x.KeyIndex
	}
	return 0
}

func (x *RecordEntry) GetBodyApart() bool {
	if x != nil {
		return x.BodyApart
	}
	return false
}

type CanonicalAction struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Kind          uint32                 `protobuf:"varint,1,opt,name=kind,proto3" json:"kind,omitempty"`            // §5.4 SidecarActionKind, or restore (16.7)
	Recipients    []string               `protobuf:"bytes,2,rep,name=recipients,proto3" json:"recipients,omitempty"` // to, cc and bcc
	BodySha256    []byte                 `protobuf:"bytes,3,opt,name=body_sha256,json=bodySha256,proto3" json:"body_sha256,omitempty"`
	Preview       string                 `protobuf:"bytes,4,opt,name=preview,proto3" json:"preview,omitempty"` // preview <= 2 KiB, rendered as untrusted text
	Host          string                 `protobuf:"bytes,5,opt,name=host,proto3" json:"host,omitempty"`
	Port          uint32                 `protobuf:"varint,6,opt,name=port,proto3" json:"port,omitempty"`
	Audience      uint32                 `protobuf:"varint,7,opt,name=audience,proto3" json:"audience,omitempty"`
	ExpiresMillis int64                  `protobuf:"varint,8,opt,name=expires_millis,json=expiresMillis,proto3" json:"expires_millis,omitempty"`
	Cidrs         []string               `protobuf:"bytes,9,rep,name=cidrs,proto3" json:"cidrs,omitempty"`
	GrantDst      []string               `protobuf:"bytes,10,rep,name=grant_dst,json=grantDst,proto3" json:"grant_dst,omitempty"`
	GrantAllow    []string               `protobuf:"bytes,11,rep,name=grant_allow,json=grantAllow,proto3" json:"grant_allow,omitempty"`
	Version       uint32                 `protobuf:"varint,12,opt,name=version,proto3" json:"version,omitempty"` // 1; 2 with field 37; 3 for kind access_request (16.11), in fields 8,
	// 10, 11, 14, 26, 29 and 38; 4 for a dial or route grant, in fields 8,
	// 10, 11, 28, 29 and 38, a share's also 40; 5 for DESIGN-COMPUTE.md's
	// kinds 19 to 26, in fields 3, 5, 29, 38, 39 and 42 to 70, and for kind
	// 5 with field 49 (§16.3); approvers that do not know a version refuse it
	Scope         bool   `protobuf:"varint,13,opt,name=scope,proto3" json:"scope,omitempty"` // a multi-use template (16.6)
	RepoId        []byte `protobuf:"bytes,14,opt,name=repo_id,json=repoId,proto3" json:"repo_id,omitempty"`
	Path          string `protobuf:"bytes,15,opt,name=path,proto3" json:"path,omitempty"`
	ContentSha256 []byte `protobuf:"bytes,16,opt,name=content_sha256,json=contentSha256,proto3" json:"content_sha256,omitempty"`
	BaseVersion   uint64 `protobuf:"varint,17,opt,name=base_version,json=baseVersion,proto3" json:"base_version,omitempty"` // O-tier evs_write,
	// evs_delete; mail_alias_delete's mailcfg record (16.6)
	DnsName          string   `protobuf:"bytes,18,opt,name=dns_name,json=dnsName,proto3" json:"dns_name,omitempty"`
	DnsType          string   `protobuf:"bytes,19,opt,name=dns_type,json=dnsType,proto3" json:"dns_type,omitempty"`
	DnsValue         string   `protobuf:"bytes,20,opt,name=dns_value,json=dnsValue,proto3" json:"dns_value,omitempty"`
	DnsTtl           uint32   `protobuf:"varint,21,opt,name=dns_ttl,json=dnsTtl,proto3" json:"dns_ttl,omitempty"` // dns_set, dns_delete
	Alias            string   `protobuf:"bytes,22,opt,name=alias,proto3" json:"alias,omitempty"`                  // mail_alias_*; mail_send's from_alias
	TargetSidecarId  []byte   `protobuf:"bytes,26,opt,name=target_sidecar_id,json=targetSidecarId,proto3" json:"target_sidecar_id,omitempty"`
	TargetPort       uint32   `protobuf:"varint,27,opt,name=target_port,json=targetPort,proto3" json:"target_port,omitempty"` // bridge_expose
	RuleId           []byte   `protobuf:"bytes,28,opt,name=rule_id,json=ruleId,proto3" json:"rule_id,omitempty"`
	Subject          []byte   `protobuf:"bytes,29,opt,name=subject,proto3" json:"subject,omitempty"` // a grant (§8.8), with 8, 10 and 11; a publish's also 33, 35
	RestoreRunId     []byte   `protobuf:"bytes,30,opt,name=restore_run_id,json=restoreRunId,proto3" json:"restore_run_id,omitempty"`
	RestorePaths     []string `protobuf:"bytes,31,rep,name=restore_paths,json=restorePaths,proto3" json:"restore_paths,omitempty"`
	RestorePreviewId []byte   `protobuf:"bytes,32,opt,name=restore_preview_id,json=restorePreviewId,proto3" json:"restore_preview_id,omitempty"` // run_restore
	AppMode          uint32   `protobuf:"varint,33,opt,name=app_mode,json=appMode,proto3" json:"app_mode,omitempty"`
	LinkSpkiSha256   []byte   `protobuf:"bytes,35,opt,name=link_spki_sha256,json=linkSpkiSha256,proto3" json:"link_spki_sha256,omitempty"` // tls_publish (§13.7)
	AliasGroup       string   `protobuf:"bytes,36,opt,name=alias_group,json=aliasGroup,proto3" json:"alias_group,omitempty"`               // mail_alias_create's group (§15.8)
	Versioning       uint32   `protobuf:"varint,37,opt,name=versioning,proto3" json:"versioning,omitempty"`                                // O-tier evs_write: its version's setting, 0 on, 1 off (§11.7); set
	// only in version 2, which approvers that do not know it refuse
	SealedDetail []byte `protobuf:"bytes,38,opt,name=sealed_detail,json=sealedDetail,proto3" json:"sealed_detail,omitempty"` // a dial or route grant's prefixes and ports, and a version-3 access
	// request's: a CanonicalActionDetail in §7.9's sealed-body format, which
	// approvers and readers open and no server does (owner decision 220);
	// set only in versions 3 and 4. Its aad takes the action's own clear
	// identity for a header's (QD-771): SignedType SIGNED_GRANT_ACTIVATE,
	// the network's id, and as the nonce the first 16 bytes of SHA-256 over
	// this action as stored with its field-38 record cut out, every other
	// tag and value in its stored order and encoding: for a builder's bytes,
	// written once in field order, the clear fields' deterministic encoding.
	// Sealed once those fields are final, it opens beside them alone
	EgressMode uint32 `protobuf:"varint,39,opt,name=egress_mode,json=egressMode,proto3" json:"egress_mode,omitempty"` // egress_change: the subject's BridgeEgressMode, auto, exits or none,
	// beside its subject (29) and, under exits, its exits in grant_dst (10),
	// sidecar:<id> entries or one tag:<id>; version 1 alone, so no action
	// that seals a detail sets it, and no server path takes it (QD-799)
	ShareNetworkId []byte `protobuf:"bytes,40,opt,name=share_network_id,json=shareNetworkId,proto3" json:"share_network_id,omitempty"` // a share's grant (§8.11): the other network, 16 bytes, on a dial or
	// route grant alone, version 4's. Either the grant gives that network
	// reach to what grant_dst names here, or grant_dst names that network
	// alone and the grant gives its subject (29) reach to it. The subject
	// stays the requesting sidecar, and an admin's approval covers the
	// network as it covers every field (QD-820). Empty on every other
	// grant, so an action stored before the field reads as before
	RequireDefaultEgress bool `protobuf:"varint,41,opt,name=require_default_egress,json=requireDefaultEgress,proto3" json:"require_default_egress,omitempty"` // egress_change under exits alone: the spec requires the subject's
	// devices to keep default egress on, sealed in its BridgeEgressBody, so
	// an approval shows and binds it (QD-1053, QD-1060); version 1, on no
	// server path, and unset reads as before
	// Version 5's fields (DESIGN-COMPUTE.md §16.3), each set only at version 5. At version 5 field 3 is SHA-256 of
	// exactly what the effect sends: field 46 as stored, the node list a continuation or crossing names, or kind 26's
	// request body; field 5 the composed URL's host (23) or the API host (26), in punycode; field 29 the enclave's
	// running incarnation or the receiving sidecar (20, 22, 24); field 38 a sealed CanonicalActionDetail5 (19, 21),
	// whose aad's SignedType is SIGNED_APPROVAL_DECISION; field 39 the mode at create (19), or the receiving
	// enclave's (24): BridgeEgressMode's auto, exits or none, and on kind 24 also 4, direct, the enclave's default
	// egress off (§11.8; QD-1391), a value no other version's field 39 takes.
	Enclave      *EnclaveFields `protobuf:"bytes,42,opt,name=enclave,proto3" json:"enclave,omitempty"`                               // 19, 20, 22, 24; on 19 its name rides in field 38
	Budget       *BudgetFields  `protobuf:"bytes,43,opt,name=budget,proto3" json:"budget,omitempty"`                                 // 21
	Url          string         `protobuf:"bytes,44,opt,name=url,proto3" json:"url,omitempty"`                                       // 23: the whole URL as the agent composed it
	Tool         string         `protobuf:"bytes,45,opt,name=tool,proto3" json:"tool,omitempty"`                                     // 24: the tool or ur command that sends
	Send         *SendFields    `protobuf:"bytes,46,opt,name=send,proto3" json:"send,omitempty"`                                     // 24: the whole of what is sent, rendered as untrusted text
	Context      *ContextFields `protobuf:"bytes,47,opt,name=context,proto3" json:"context,omitempty"`                               // 24: harness_continue's, or a run's crossing (§7.8)
	TaintReasons []string       `protobuf:"bytes,48,rep,name=taint_reasons,json=taintReasons,proto3" json:"taint_reasons,omitempty"` // 23, 24, 26: the requesting run's taint reasons (DESIGN §16.6)
	TookTainted  bool           `protobuf:"varint,49,opt,name=took_tainted,json=tookTainted,proto3" json:"took_tainted,omitempty"`   // kind 5 alone, of an enclave leaving none: it took tainted input there
	// (§7.10); an action that sets it is version 5
	CalendarLabel    string                 `protobuf:"bytes,50,opt,name=calendar_label,json=calendarLabel,proto3" json:"calendar_label,omitempty"`          // 25 (§23.9): the link's label, daemon-built
	CalendarHost     string                 `protobuf:"bytes,51,opt,name=calendar_host,json=calendarHost,proto3" json:"calendar_host,omitempty"`             // 25: the provider's host, daemon-built
	CalendarAudience string                 `protobuf:"bytes,52,opt,name=calendar_audience,json=calendarAudience,proto3" json:"calendar_audience,omitempty"` // 25: the sharing or publishing the provider reports, else empty
	CalendarEvents   []*CalendarEventAction `protobuf:"bytes,53,rep,name=calendar_events,json=calendarEvents,proto3" json:"calendar_events,omitempty"`       // 25: 1 to 20 events, each with its switch on the card
	CalendarLink     []byte                 `protobuf:"bytes,54,opt,name=calendar_link,json=calendarLink,proto3" json:"calendar_link,omitempty"`             // 25: the link's repo id
	CalendarTarget   []byte                 `protobuf:"bytes,55,opt,name=calendar_target,json=calendarTarget,proto3" json:"calendar_target,omitempty"`       // 25: the SHA-256 that names the link's account and calendar (§23.6)
	CalendarName     string                 `protobuf:"bytes,56,opt,name=calendar_name,json=calendarName,proto3" json:"calendar_name,omitempty"`             // 25: the calendar's display name as the provider reports it
	ServiceCall      *ServiceCallFields     `protobuf:"bytes,60,opt,name=service_call,json=serviceCall,proto3" json:"service_call,omitempty"`                // 26 (§25.10)
	Auto             *AutoFields            `protobuf:"bytes,70,opt,name=auto,proto3" json:"auto,omitempty"`                                                 // 23 to 27 (§27.9): daemon-built, rendered on the card
	Support          *SupportFields         `protobuf:"bytes,80,opt,name=support,proto3" json:"support,omitempty"`                                           // 27 (DESIGN-COMPUTE §28.8): the whole message, rendered as untrusted text
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *CanonicalAction) Reset() {
	*x = CanonicalAction{}
	mi := &file_protocol_record_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CanonicalAction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CanonicalAction) ProtoMessage() {}

func (x *CanonicalAction) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CanonicalAction.ProtoReflect.Descriptor instead.
func (*CanonicalAction) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{3}
}

func (x *CanonicalAction) GetKind() uint32 {
	if x != nil {
		return x.Kind
	}
	return 0
}

func (x *CanonicalAction) GetRecipients() []string {
	if x != nil {
		return x.Recipients
	}
	return nil
}

func (x *CanonicalAction) GetBodySha256() []byte {
	if x != nil {
		return x.BodySha256
	}
	return nil
}

func (x *CanonicalAction) GetPreview() string {
	if x != nil {
		return x.Preview
	}
	return ""
}

func (x *CanonicalAction) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *CanonicalAction) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *CanonicalAction) GetAudience() uint32 {
	if x != nil {
		return x.Audience
	}
	return 0
}

func (x *CanonicalAction) GetExpiresMillis() int64 {
	if x != nil {
		return x.ExpiresMillis
	}
	return 0
}

func (x *CanonicalAction) GetCidrs() []string {
	if x != nil {
		return x.Cidrs
	}
	return nil
}

func (x *CanonicalAction) GetGrantDst() []string {
	if x != nil {
		return x.GrantDst
	}
	return nil
}

func (x *CanonicalAction) GetGrantAllow() []string {
	if x != nil {
		return x.GrantAllow
	}
	return nil
}

func (x *CanonicalAction) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *CanonicalAction) GetScope() bool {
	if x != nil {
		return x.Scope
	}
	return false
}

func (x *CanonicalAction) GetRepoId() []byte {
	if x != nil {
		return x.RepoId
	}
	return nil
}

func (x *CanonicalAction) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *CanonicalAction) GetContentSha256() []byte {
	if x != nil {
		return x.ContentSha256
	}
	return nil
}

func (x *CanonicalAction) GetBaseVersion() uint64 {
	if x != nil {
		return x.BaseVersion
	}
	return 0
}

func (x *CanonicalAction) GetDnsName() string {
	if x != nil {
		return x.DnsName
	}
	return ""
}

func (x *CanonicalAction) GetDnsType() string {
	if x != nil {
		return x.DnsType
	}
	return ""
}

func (x *CanonicalAction) GetDnsValue() string {
	if x != nil {
		return x.DnsValue
	}
	return ""
}

func (x *CanonicalAction) GetDnsTtl() uint32 {
	if x != nil {
		return x.DnsTtl
	}
	return 0
}

func (x *CanonicalAction) GetAlias() string {
	if x != nil {
		return x.Alias
	}
	return ""
}

func (x *CanonicalAction) GetTargetSidecarId() []byte {
	if x != nil {
		return x.TargetSidecarId
	}
	return nil
}

func (x *CanonicalAction) GetTargetPort() uint32 {
	if x != nil {
		return x.TargetPort
	}
	return 0
}

func (x *CanonicalAction) GetRuleId() []byte {
	if x != nil {
		return x.RuleId
	}
	return nil
}

func (x *CanonicalAction) GetSubject() []byte {
	if x != nil {
		return x.Subject
	}
	return nil
}

func (x *CanonicalAction) GetRestoreRunId() []byte {
	if x != nil {
		return x.RestoreRunId
	}
	return nil
}

func (x *CanonicalAction) GetRestorePaths() []string {
	if x != nil {
		return x.RestorePaths
	}
	return nil
}

func (x *CanonicalAction) GetRestorePreviewId() []byte {
	if x != nil {
		return x.RestorePreviewId
	}
	return nil
}

func (x *CanonicalAction) GetAppMode() uint32 {
	if x != nil {
		return x.AppMode
	}
	return 0
}

func (x *CanonicalAction) GetLinkSpkiSha256() []byte {
	if x != nil {
		return x.LinkSpkiSha256
	}
	return nil
}

func (x *CanonicalAction) GetAliasGroup() string {
	if x != nil {
		return x.AliasGroup
	}
	return ""
}

func (x *CanonicalAction) GetVersioning() uint32 {
	if x != nil {
		return x.Versioning
	}
	return 0
}

func (x *CanonicalAction) GetSealedDetail() []byte {
	if x != nil {
		return x.SealedDetail
	}
	return nil
}

func (x *CanonicalAction) GetEgressMode() uint32 {
	if x != nil {
		return x.EgressMode
	}
	return 0
}

func (x *CanonicalAction) GetShareNetworkId() []byte {
	if x != nil {
		return x.ShareNetworkId
	}
	return nil
}

func (x *CanonicalAction) GetRequireDefaultEgress() bool {
	if x != nil {
		return x.RequireDefaultEgress
	}
	return false
}

func (x *CanonicalAction) GetEnclave() *EnclaveFields {
	if x != nil {
		return x.Enclave
	}
	return nil
}

func (x *CanonicalAction) GetBudget() *BudgetFields {
	if x != nil {
		return x.Budget
	}
	return nil
}

func (x *CanonicalAction) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *CanonicalAction) GetTool() string {
	if x != nil {
		return x.Tool
	}
	return ""
}

func (x *CanonicalAction) GetSend() *SendFields {
	if x != nil {
		return x.Send
	}
	return nil
}

func (x *CanonicalAction) GetContext() *ContextFields {
	if x != nil {
		return x.Context
	}
	return nil
}

func (x *CanonicalAction) GetTaintReasons() []string {
	if x != nil {
		return x.TaintReasons
	}
	return nil
}

func (x *CanonicalAction) GetTookTainted() bool {
	if x != nil {
		return x.TookTainted
	}
	return false
}

func (x *CanonicalAction) GetCalendarLabel() string {
	if x != nil {
		return x.CalendarLabel
	}
	return ""
}

func (x *CanonicalAction) GetCalendarHost() string {
	if x != nil {
		return x.CalendarHost
	}
	return ""
}

func (x *CanonicalAction) GetCalendarAudience() string {
	if x != nil {
		return x.CalendarAudience
	}
	return ""
}

func (x *CanonicalAction) GetCalendarEvents() []*CalendarEventAction {
	if x != nil {
		return x.CalendarEvents
	}
	return nil
}

func (x *CanonicalAction) GetCalendarLink() []byte {
	if x != nil {
		return x.CalendarLink
	}
	return nil
}

func (x *CanonicalAction) GetCalendarTarget() []byte {
	if x != nil {
		return x.CalendarTarget
	}
	return nil
}

func (x *CanonicalAction) GetCalendarName() string {
	if x != nil {
		return x.CalendarName
	}
	return ""
}

func (x *CanonicalAction) GetServiceCall() *ServiceCallFields {
	if x != nil {
		return x.ServiceCall
	}
	return nil
}

func (x *CanonicalAction) GetAuto() *AutoFields {
	if x != nil {
		return x.Auto
	}
	return nil
}

func (x *CanonicalAction) GetSupport() *SupportFields {
	if x != nil {
		return x.Support
	}
	return nil
}

// What field 42 holds: the enclave an action creates, removes, sends into or turns default egress off for.
type EnclaveFields struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	EnclaveId     []byte                 `protobuf:"bytes,1,opt,name=enclave_id,json=enclaveId,proto3" json:"enclave_id,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"` // empty on kind 19, whose name rides in field 38
	Shape         string                 `protobuf:"bytes,3,opt,name=shape,proto3" json:"shape,omitempty"`
	Provider      string                 `protobuf:"bytes,4,opt,name=provider,proto3" json:"provider,omitempty"`
	Label         string                 `protobuf:"bytes,5,opt,name=label,proto3" json:"label,omitempty"`                                      // §4.3's label, as the catalog writes it
	PricePerHour  uint64                 `protobuf:"varint,6,opt,name=price_per_hour,json=pricePerHour,proto3" json:"price_per_hour,omitempty"` // nano-USD
	Incarnation   uint64                 `protobuf:"varint,7,opt,name=incarnation,proto3" json:"incarnation,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EnclaveFields) Reset() {
	*x = EnclaveFields{}
	mi := &file_protocol_record_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EnclaveFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnclaveFields) ProtoMessage() {}

func (x *EnclaveFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnclaveFields.ProtoReflect.Descriptor instead.
func (*EnclaveFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{4}
}

func (x *EnclaveFields) GetEnclaveId() []byte {
	if x != nil {
		return x.EnclaveId
	}
	return nil
}

func (x *EnclaveFields) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *EnclaveFields) GetShape() string {
	if x != nil {
		return x.Shape
	}
	return ""
}

func (x *EnclaveFields) GetProvider() string {
	if x != nil {
		return x.Provider
	}
	return ""
}

func (x *EnclaveFields) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

func (x *EnclaveFields) GetPricePerHour() uint64 {
	if x != nil {
		return x.PricePerHour
	}
	return 0
}

func (x *EnclaveFields) GetIncarnation() uint64 {
	if x != nil {
		return x.Incarnation
	}
	return 0
}

// What field 43 holds, and a launch's budget in field 46: an amount over a period.
type BudgetFields struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	AgentId       []byte                 `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
	Period        uint32                 `protobuf:"varint,2,opt,name=period,proto3" json:"period,omitempty"`   // 1 day, 2 month, 3 run
	Amount        uint64                 `protobuf:"varint,3,opt,name=amount,proto3" json:"amount,omitempty"`   // nano-USD
	Current       uint64                 `protobuf:"varint,4,opt,name=current,proto3" json:"current,omitempty"` // nano-USD
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BudgetFields) Reset() {
	*x = BudgetFields{}
	mi := &file_protocol_record_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BudgetFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BudgetFields) ProtoMessage() {}

func (x *BudgetFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BudgetFields.ProtoReflect.Descriptor instead.
func (*BudgetFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{5}
}

func (x *BudgetFields) GetAgentId() []byte {
	if x != nil {
		return x.AgentId
	}
	return nil
}

func (x *BudgetFields) GetPeriod() uint32 {
	if x != nil {
		return x.Period
	}
	return 0
}

func (x *BudgetFields) GetAmount() uint64 {
	if x != nil {
		return x.Amount
	}
	return 0
}

func (x *BudgetFields) GetCurrent() uint64 {
	if x != nil {
		return x.Current
	}
	return 0
}

// What field 46 holds: the whole of what a kind-24 action sends.
type SendFields struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	TargetAgent    string                 `protobuf:"bytes,1,opt,name=target_agent,json=targetAgent,proto3" json:"target_agent,omitempty"`
	TargetAgentId  []byte                 `protobuf:"bytes,2,opt,name=target_agent_id,json=targetAgentId,proto3" json:"target_agent_id,omitempty"`
	TargetMemberId []byte                 `protobuf:"bytes,3,opt,name=target_member_id,json=targetMemberId,proto3" json:"target_member_id,omitempty"`
	Mode           uint32                 `protobuf:"varint,4,opt,name=mode,proto3" json:"mode,omitempty"` // §7.10's prompt 1, steer 2 and follow_up 3; 0 a message
	Text           string                 `protobuf:"bytes,5,opt,name=text,proto3" json:"text,omitempty"`
	Stdin          string                 `protobuf:"bytes,6,opt,name=stdin,proto3" json:"stdin,omitempty"` // at most 32 KiB
	Cwd            string                 `protobuf:"bytes,7,opt,name=cwd,proto3" json:"cwd,omitempty"`
	Refs           []*RefFields           `protobuf:"bytes,8,rep,name=refs,proto3" json:"refs,omitempty"`
	Model          string                 `protobuf:"bytes,9,opt,name=model,proto3" json:"model,omitempty"`
	Tools          []string               `protobuf:"bytes,10,rep,name=tools,proto3" json:"tools,omitempty"`
	Budget         *BudgetFields          `protobuf:"bytes,11,opt,name=budget,proto3" json:"budget,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *SendFields) Reset() {
	*x = SendFields{}
	mi := &file_protocol_record_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SendFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SendFields) ProtoMessage() {}

func (x *SendFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SendFields.ProtoReflect.Descriptor instead.
func (*SendFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{6}
}

func (x *SendFields) GetTargetAgent() string {
	if x != nil {
		return x.TargetAgent
	}
	return ""
}

func (x *SendFields) GetTargetAgentId() []byte {
	if x != nil {
		return x.TargetAgentId
	}
	return nil
}

func (x *SendFields) GetTargetMemberId() []byte {
	if x != nil {
		return x.TargetMemberId
	}
	return nil
}

func (x *SendFields) GetMode() uint32 {
	if x != nil {
		return x.Mode
	}
	return 0
}

func (x *SendFields) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

func (x *SendFields) GetStdin() string {
	if x != nil {
		return x.Stdin
	}
	return ""
}

func (x *SendFields) GetCwd() string {
	if x != nil {
		return x.Cwd
	}
	return ""
}

func (x *SendFields) GetRefs() []*RefFields {
	if x != nil {
		return x.Refs
	}
	return nil
}

func (x *SendFields) GetModel() string {
	if x != nil {
		return x.Model
	}
	return ""
}

func (x *SendFields) GetTools() []string {
	if x != nil {
		return x.Tools
	}
	return nil
}

func (x *SendFields) GetBudget() *BudgetFields {
	if x != nil {
		return x.Budget
	}
	return nil
}

// One version a send names, or a release carries.
type RefFields struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RepoId        []byte                 `protobuf:"bytes,1,opt,name=repo_id,json=repoId,proto3" json:"repo_id,omitempty"`
	Path          string                 `protobuf:"bytes,2,opt,name=path,proto3" json:"path,omitempty"`
	Version       uint64                 `protobuf:"varint,3,opt,name=version,proto3" json:"version,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RefFields) Reset() {
	*x = RefFields{}
	mi := &file_protocol_record_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RefFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RefFields) ProtoMessage() {}

func (x *RefFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RefFields.ProtoReflect.Descriptor instead.
func (*RefFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{7}
}

func (x *RefFields) GetRepoId() []byte {
	if x != nil {
		return x.RepoId
	}
	return nil
}

func (x *RefFields) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *RefFields) GetVersion() uint64 {
	if x != nil {
		return x.Version
	}
	return 0
}

// What field 47 holds: a continuation's or a crossing's run and node, and counts of what its context holds.
type ContextFields struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	RunId          []byte                 `protobuf:"bytes,1,opt,name=run_id,json=runId,proto3" json:"run_id,omitempty"`
	EntryId        []byte                 `protobuf:"bytes,2,opt,name=entry_id,json=entryId,proto3" json:"entry_id,omitempty"`
	Nodes          uint32                 `protobuf:"varint,3,opt,name=nodes,proto3" json:"nodes,omitempty"`
	Flagged        uint32                 `protobuf:"varint,4,opt,name=flagged,proto3" json:"flagged,omitempty"`
	Untrusted      uint32                 `protobuf:"varint,5,opt,name=untrusted,proto3" json:"untrusted,omitempty"`
	MailMessages   uint32                 `protobuf:"varint,6,opt,name=mail_messages,json=mailMessages,proto3" json:"mail_messages,omitempty"`
	CalendarEvents uint32                 `protobuf:"varint,7,opt,name=calendar_events,json=calendarEvents,proto3" json:"calendar_events,omitempty"`
	FetchedPages   uint32                 `protobuf:"varint,8,opt,name=fetched_pages,json=fetchedPages,proto3" json:"fetched_pages,omitempty"`
	ServiceResults uint32                 `protobuf:"varint,9,opt,name=service_results,json=serviceResults,proto3" json:"service_results,omitempty"`
	Act            uint32                 `protobuf:"varint,10,opt,name=act,proto3" json:"act,omitempty"` // 1 continue, 2 cross
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *ContextFields) Reset() {
	*x = ContextFields{}
	mi := &file_protocol_record_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContextFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContextFields) ProtoMessage() {}

func (x *ContextFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContextFields.ProtoReflect.Descriptor instead.
func (*ContextFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{8}
}

func (x *ContextFields) GetRunId() []byte {
	if x != nil {
		return x.RunId
	}
	return nil
}

func (x *ContextFields) GetEntryId() []byte {
	if x != nil {
		return x.EntryId
	}
	return nil
}

func (x *ContextFields) GetNodes() uint32 {
	if x != nil {
		return x.Nodes
	}
	return 0
}

func (x *ContextFields) GetFlagged() uint32 {
	if x != nil {
		return x.Flagged
	}
	return 0
}

func (x *ContextFields) GetUntrusted() uint32 {
	if x != nil {
		return x.Untrusted
	}
	return 0
}

func (x *ContextFields) GetMailMessages() uint32 {
	if x != nil {
		return x.MailMessages
	}
	return 0
}

func (x *ContextFields) GetCalendarEvents() uint32 {
	if x != nil {
		return x.CalendarEvents
	}
	return 0
}

func (x *ContextFields) GetFetchedPages() uint32 {
	if x != nil {
		return x.FetchedPages
	}
	return 0
}

func (x *ContextFields) GetServiceResults() uint32 {
	if x != nil {
		return x.ServiceResults
	}
	return 0
}

func (x *ContextFields) GetAct() uint32 {
	if x != nil {
		return x.Act
	}
	return 0
}

// One event of field 53 (§23.9), every string rendered as untrusted text.
type CalendarEventAction struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Operation     uint32                 `protobuf:"varint,1,opt,name=operation,proto3" json:"operation,omitempty"` // 1 add, 2 change, 3 remove
	Uid           string                 `protobuf:"bytes,2,opt,name=uid,proto3" json:"uid,omitempty"`
	Occurrence    string                 `protobuf:"bytes,3,opt,name=occurrence,proto3" json:"occurrence,omitempty"`
	Expected      string                 `protobuf:"bytes,4,opt,name=expected,proto3" json:"expected,omitempty"` // the revision a change or removal expects
	Title         string                 `protobuf:"bytes,5,opt,name=title,proto3" json:"title,omitempty"`
	Start         string                 `protobuf:"bytes,6,opt,name=start,proto3" json:"start,omitempty"`
	End           string                 `protobuf:"bytes,7,opt,name=end,proto3" json:"end,omitempty"`
	Zone          string                 `protobuf:"bytes,8,opt,name=zone,proto3" json:"zone,omitempty"`
	AllDay        bool                   `protobuf:"varint,9,opt,name=all_day,json=allDay,proto3" json:"all_day,omitempty"`
	Recurrence    string                 `protobuf:"bytes,10,opt,name=recurrence,proto3" json:"recurrence,omitempty"`
	Location      string                 `protobuf:"bytes,11,opt,name=location,proto3" json:"location,omitempty"`
	Reminders     []string               `protobuf:"bytes,12,rep,name=reminders,proto3" json:"reminders,omitempty"`
	Attendees     []string               `protobuf:"bytes,13,rep,name=attendees,proto3" json:"attendees,omitempty"`
	Mails         []string               `protobuf:"bytes,14,rep,name=mails,proto3" json:"mails,omitempty"`             // what the provider will mail, and to whom
	Description   string                 `protobuf:"bytes,15,opt,name=description,proto3" json:"description,omitempty"` // whole
	Before        *CalendarEventFields   `protobuf:"bytes,16,opt,name=before,proto3" json:"before,omitempty"`           // a change's prior values
	Source        string                 `protobuf:"bytes,17,opt,name=source,proto3" json:"source,omitempty"`           // the message the agent cites, as its claim
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CalendarEventAction) Reset() {
	*x = CalendarEventAction{}
	mi := &file_protocol_record_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CalendarEventAction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CalendarEventAction) ProtoMessage() {}

func (x *CalendarEventAction) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CalendarEventAction.ProtoReflect.Descriptor instead.
func (*CalendarEventAction) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{9}
}

func (x *CalendarEventAction) GetOperation() uint32 {
	if x != nil {
		return x.Operation
	}
	return 0
}

func (x *CalendarEventAction) GetUid() string {
	if x != nil {
		return x.Uid
	}
	return ""
}

func (x *CalendarEventAction) GetOccurrence() string {
	if x != nil {
		return x.Occurrence
	}
	return ""
}

func (x *CalendarEventAction) GetExpected() string {
	if x != nil {
		return x.Expected
	}
	return ""
}

func (x *CalendarEventAction) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

func (x *CalendarEventAction) GetStart() string {
	if x != nil {
		return x.Start
	}
	return ""
}

func (x *CalendarEventAction) GetEnd() string {
	if x != nil {
		return x.End
	}
	return ""
}

func (x *CalendarEventAction) GetZone() string {
	if x != nil {
		return x.Zone
	}
	return ""
}

func (x *CalendarEventAction) GetAllDay() bool {
	if x != nil {
		return x.AllDay
	}
	return false
}

func (x *CalendarEventAction) GetRecurrence() string {
	if x != nil {
		return x.Recurrence
	}
	return ""
}

func (x *CalendarEventAction) GetLocation() string {
	if x != nil {
		return x.Location
	}
	return ""
}

func (x *CalendarEventAction) GetReminders() []string {
	if x != nil {
		return x.Reminders
	}
	return nil
}

func (x *CalendarEventAction) GetAttendees() []string {
	if x != nil {
		return x.Attendees
	}
	return nil
}

func (x *CalendarEventAction) GetMails() []string {
	if x != nil {
		return x.Mails
	}
	return nil
}

func (x *CalendarEventAction) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *CalendarEventAction) GetBefore() *CalendarEventFields {
	if x != nil {
		return x.Before
	}
	return nil
}

func (x *CalendarEventAction) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

// A changed event's values before the change, the event's own fields in CalendarEventAction's order, so no message
// holds itself.
type CalendarEventFields struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Title         string                 `protobuf:"bytes,1,opt,name=title,proto3" json:"title,omitempty"`
	Start         string                 `protobuf:"bytes,2,opt,name=start,proto3" json:"start,omitempty"`
	End           string                 `protobuf:"bytes,3,opt,name=end,proto3" json:"end,omitempty"`
	Zone          string                 `protobuf:"bytes,4,opt,name=zone,proto3" json:"zone,omitempty"`
	AllDay        bool                   `protobuf:"varint,5,opt,name=all_day,json=allDay,proto3" json:"all_day,omitempty"`
	Recurrence    string                 `protobuf:"bytes,6,opt,name=recurrence,proto3" json:"recurrence,omitempty"`
	Location      string                 `protobuf:"bytes,7,opt,name=location,proto3" json:"location,omitempty"`
	Reminders     []string               `protobuf:"bytes,8,rep,name=reminders,proto3" json:"reminders,omitempty"`
	Attendees     []string               `protobuf:"bytes,9,rep,name=attendees,proto3" json:"attendees,omitempty"`
	Description   string                 `protobuf:"bytes,10,opt,name=description,proto3" json:"description,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CalendarEventFields) Reset() {
	*x = CalendarEventFields{}
	mi := &file_protocol_record_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CalendarEventFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CalendarEventFields) ProtoMessage() {}

func (x *CalendarEventFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CalendarEventFields.ProtoReflect.Descriptor instead.
func (*CalendarEventFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{10}
}

func (x *CalendarEventFields) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

func (x *CalendarEventFields) GetStart() string {
	if x != nil {
		return x.Start
	}
	return ""
}

func (x *CalendarEventFields) GetEnd() string {
	if x != nil {
		return x.End
	}
	return ""
}

func (x *CalendarEventFields) GetZone() string {
	if x != nil {
		return x.Zone
	}
	return ""
}

func (x *CalendarEventFields) GetAllDay() bool {
	if x != nil {
		return x.AllDay
	}
	return false
}

func (x *CalendarEventFields) GetRecurrence() string {
	if x != nil {
		return x.Recurrence
	}
	return ""
}

func (x *CalendarEventFields) GetLocation() string {
	if x != nil {
		return x.Location
	}
	return ""
}

func (x *CalendarEventFields) GetReminders() []string {
	if x != nil {
		return x.Reminders
	}
	return nil
}

func (x *CalendarEventFields) GetAttendees() []string {
	if x != nil {
		return x.Attendees
	}
	return nil
}

func (x *CalendarEventFields) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

// What field 60 holds: the one request a kind-26 action sends (§25.10).
type ServiceCallFields struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Connection    []byte                 `protobuf:"bytes,1,opt,name=connection,proto3" json:"connection,omitempty"` // the connection's repo id
	Label         string                 `protobuf:"bytes,2,opt,name=label,proto3" json:"label,omitempty"`
	Service       string                 `protobuf:"bytes,3,opt,name=service,proto3" json:"service,omitempty"`
	Account       string                 `protobuf:"bytes,4,opt,name=account,proto3" json:"account,omitempty"`
	Method        string                 `protobuf:"bytes,5,opt,name=method,proto3" json:"method,omitempty"`
	Path          string                 `protobuf:"bytes,6,opt,name=path,proto3" json:"path,omitempty"`
	Query         string                 `protobuf:"bytes,7,opt,name=query,proto3" json:"query,omitempty"`
	ContentType   string                 `protobuf:"bytes,8,opt,name=content_type,json=contentType,proto3" json:"content_type,omitempty"`
	Body          string                 `protobuf:"bytes,9,opt,name=body,proto3" json:"body,omitempty"`     // whole, at most 32 KiB; field 3 is its SHA-256
	Class         uint32                 `protobuf:"varint,10,opt,name=class,proto3" json:"class,omitempty"` // 1 write, 2 send
	Feature       string                 `protobuf:"bytes,11,opt,name=feature,proto3" json:"feature,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ServiceCallFields) Reset() {
	*x = ServiceCallFields{}
	mi := &file_protocol_record_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ServiceCallFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServiceCallFields) ProtoMessage() {}

func (x *ServiceCallFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServiceCallFields.ProtoReflect.Descriptor instead.
func (*ServiceCallFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{11}
}

func (x *ServiceCallFields) GetConnection() []byte {
	if x != nil {
		return x.Connection
	}
	return nil
}

func (x *ServiceCallFields) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

func (x *ServiceCallFields) GetService() string {
	if x != nil {
		return x.Service
	}
	return ""
}

func (x *ServiceCallFields) GetAccount() string {
	if x != nil {
		return x.Account
	}
	return ""
}

func (x *ServiceCallFields) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *ServiceCallFields) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *ServiceCallFields) GetQuery() string {
	if x != nil {
		return x.Query
	}
	return ""
}

func (x *ServiceCallFields) GetContentType() string {
	if x != nil {
		return x.ContentType
	}
	return ""
}

func (x *ServiceCallFields) GetBody() string {
	if x != nil {
		return x.Body
	}
	return ""
}

func (x *ServiceCallFields) GetClass() uint32 {
	if x != nil {
		return x.Class
	}
	return 0
}

func (x *ServiceCallFields) GetFeature() string {
	if x != nil {
		return x.Feature
	}
	return ""
}

// What field 70 holds (§27.9).
type AutoFields struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Basis         uint32                 `protobuf:"varint,1,opt,name=basis,proto3" json:"basis,omitempty"`        // 1 taint: outward only because its run is tainted; 2 always
	Rules         []uint32               `protobuf:"varint,2,rep,packed,name=rules,proto3" json:"rules,omitempty"` // §27.7's rules that follow from the action alone, by their numbers
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AutoFields) Reset() {
	*x = AutoFields{}
	mi := &file_protocol_record_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AutoFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AutoFields) ProtoMessage() {}

func (x *AutoFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AutoFields.ProtoReflect.Descriptor instead.
func (*AutoFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{12}
}

func (x *AutoFields) GetBasis() uint32 {
	if x != nil {
		return x.Basis
	}
	return 0
}

func (x *AutoFields) GetRules() []uint32 {
	if x != nil {
		return x.Rules
	}
	return nil
}

// What field 80 holds (DESIGN-COMPUTE §16.3, §28.8): the whole of a kind-27 message, rendered on the card as
// untrusted text, which field 3's SHA-256 of the SupportBody posted binds.
type SupportFields struct {
	state   protoimpl.MessageState `protogen:"open.v1"`
	Product string                 `protobuf:"bytes,1,opt,name=product,proto3" json:"product,omitempty"` // urnetwork
	Entry   string                 `protobuf:"bytes,2,opt,name=entry,proto3" json:"entry,omitempty"`     // the item it continues; empty opens one
	Kind    uint32                 `protobuf:"varint,3,opt,name=kind,proto3" json:"kind,omitempty"`      // FB section 4's hint: 1 bug, 2 feature, 3 question, 4 praise, 5 security,
	// 6 other; 0 none
	Text          string          `protobuf:"bytes,4,opt,name=text,proto3" json:"text,omitempty"`                            // whole, at most 16 KiB of UTF-8
	Bundle        *BundleManifest `protobuf:"bytes,5,opt,name=bundle,proto3" json:"bundle,omitempty"`                        // the support log's bundle's, where the message carries one
	Files         []*FileFields   `protobuf:"bytes,6,rep,name=files,proto3" json:"files,omitempty"`                          // at most 3, each shown whole on the card
	ClientRef     []byte          `protobuf:"bytes,7,opt,name=client_ref,json=clientRef,proto3" json:"client_ref,omitempty"` // 16 bytes (§28.6)
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SupportFields) Reset() {
	*x = SupportFields{}
	mi := &file_protocol_record_proto_msgTypes[13]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SupportFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SupportFields) ProtoMessage() {}

func (x *SupportFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[13]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SupportFields.ProtoReflect.Descriptor instead.
func (*SupportFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{13}
}

func (x *SupportFields) GetProduct() string {
	if x != nil {
		return x.Product
	}
	return ""
}

func (x *SupportFields) GetEntry() string {
	if x != nil {
		return x.Entry
	}
	return ""
}

func (x *SupportFields) GetKind() uint32 {
	if x != nil {
		return x.Kind
	}
	return 0
}

func (x *SupportFields) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

func (x *SupportFields) GetBundle() *BundleManifest {
	if x != nil {
		return x.Bundle
	}
	return nil
}

func (x *SupportFields) GetFiles() []*FileFields {
	if x != nil {
		return x.Files
	}
	return nil
}

func (x *SupportFields) GetClientRef() []byte {
	if x != nil {
		return x.ClientRef
	}
	return nil
}

// A support log bundle's manifest (§28.7): what an agent and a card learn of it, never an event's fields.
type BundleManifest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Events        uint32                 `protobuf:"varint,1,opt,name=events,proto3" json:"events,omitempty"`
	First         int64                  `protobuf:"varint,2,opt,name=first,proto3" json:"first,omitempty"`
	Last          int64                  `protobuf:"varint,3,opt,name=last,proto3" json:"last,omitempty"`   // the window's first and last events, unix seconds
	Bytes         uint64                 `protobuf:"varint,4,opt,name=bytes,proto3" json:"bytes,omitempty"` // compressed
	Sha256        []byte                 `protobuf:"bytes,5,opt,name=sha256,proto3" json:"sha256,omitempty"`
	Codes         []*BundleCodeCount     `protobuf:"bytes,6,rep,name=codes,proto3" json:"codes,omitempty"` // by component and code
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BundleManifest) Reset() {
	*x = BundleManifest{}
	mi := &file_protocol_record_proto_msgTypes[14]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BundleManifest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BundleManifest) ProtoMessage() {}

func (x *BundleManifest) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[14]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BundleManifest.ProtoReflect.Descriptor instead.
func (*BundleManifest) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{14}
}

func (x *BundleManifest) GetEvents() uint32 {
	if x != nil {
		return x.Events
	}
	return 0
}

func (x *BundleManifest) GetFirst() int64 {
	if x != nil {
		return x.First
	}
	return 0
}

func (x *BundleManifest) GetLast() int64 {
	if x != nil {
		return x.Last
	}
	return 0
}

func (x *BundleManifest) GetBytes() uint64 {
	if x != nil {
		return x.Bytes
	}
	return 0
}

func (x *BundleManifest) GetSha256() []byte {
	if x != nil {
		return x.Sha256
	}
	return nil
}

func (x *BundleManifest) GetCodes() []*BundleCodeCount {
	if x != nil {
		return x.Codes
	}
	return nil
}

type BundleCodeCount struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Component     string                 `protobuf:"bytes,1,opt,name=component,proto3" json:"component,omitempty"`
	Code          string                 `protobuf:"bytes,2,opt,name=code,proto3" json:"code,omitempty"`
	Count         uint32                 `protobuf:"varint,3,opt,name=count,proto3" json:"count,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BundleCodeCount) Reset() {
	*x = BundleCodeCount{}
	mi := &file_protocol_record_proto_msgTypes[15]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BundleCodeCount) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BundleCodeCount) ProtoMessage() {}

func (x *BundleCodeCount) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[15]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BundleCodeCount.ProtoReflect.Descriptor instead.
func (*BundleCodeCount) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{15}
}

func (x *BundleCodeCount) GetComponent() string {
	if x != nil {
		return x.Component
	}
	return ""
}

func (x *BundleCodeCount) GetCode() string {
	if x != nil {
		return x.Code
	}
	return ""
}

func (x *BundleCodeCount) GetCount() uint32 {
	if x != nil {
		return x.Count
	}
	return 0
}

// One file a support message names (§28.7).
type FileFields struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`  // its base name
	Type          uint32                 `protobuf:"varint,2,opt,name=type,proto3" json:"type,omitempty"` // 1 UTF-8 text, 2 PNG, 3 JPEG
	Size          uint64                 `protobuf:"varint,3,opt,name=size,proto3" json:"size,omitempty"`
	Sha256        []byte                 `protobuf:"bytes,4,opt,name=sha256,proto3" json:"sha256,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FileFields) Reset() {
	*x = FileFields{}
	mi := &file_protocol_record_proto_msgTypes[16]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FileFields) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FileFields) ProtoMessage() {}

func (x *FileFields) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[16]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FileFields.ProtoReflect.Descriptor instead.
func (*FileFields) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{16}
}

func (x *FileFields) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *FileFields) GetType() uint32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *FileFields) GetSize() uint64 {
	if x != nil {
		return x.Size
	}
	return 0
}

func (x *FileFields) GetSha256() []byte {
	if x != nil {
		return x.Sha256
	}
	return nil
}

// What sealed_detail opens to at version 5 (§16.3): what the broker's gates, kinds 19 and 21, do not see.
type CanonicalActionDetail5 struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`  // kind 19's enclave name
	Role          uint32                 `protobuf:"varint,2,opt,name=role,proto3" json:"role,omitempty"` // kind 19's: 1 agents, 2 indexer
	Harness       string                 `protobuf:"bytes,3,opt,name=harness,proto3" json:"harness,omitempty"`
	GrantId       []byte                 `protobuf:"bytes,4,opt,name=grant_id,json=grantId,proto3" json:"grant_id,omitempty"` // kind 21's gateway grant
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CanonicalActionDetail5) Reset() {
	*x = CanonicalActionDetail5{}
	mi := &file_protocol_record_proto_msgTypes[17]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CanonicalActionDetail5) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CanonicalActionDetail5) ProtoMessage() {}

func (x *CanonicalActionDetail5) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[17]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CanonicalActionDetail5.ProtoReflect.Descriptor instead.
func (*CanonicalActionDetail5) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{17}
}

func (x *CanonicalActionDetail5) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *CanonicalActionDetail5) GetRole() uint32 {
	if x != nil {
		return x.Role
	}
	return 0
}

func (x *CanonicalActionDetail5) GetHarness() string {
	if x != nil {
		return x.Harness
	}
	return ""
}

func (x *CanonicalActionDetail5) GetGrantId() []byte {
	if x != nil {
		return x.GrantId
	}
	return nil
}

// What sealed_detail opens to: what a dial or route grant's clear fields may not hold (QD-740).
type CanonicalActionDetail struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Cidrs         []string               `protobuf:"bytes,1,rep,name=cidrs,proto3" json:"cidrs,omitempty"`                              // a route's prefixes
	TargetPort    uint32                 `protobuf:"varint,2,opt,name=target_port,json=targetPort,proto3" json:"target_port,omitempty"` // a forward's or an access request's port on its target
	GrantDst      []string               `protobuf:"bytes,3,rep,name=grant_dst,json=grantDst,proto3" json:"grant_dst,omitempty"`        // the grant's destinations that name a port or a prefix, in §8.4's
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CanonicalActionDetail) Reset() {
	*x = CanonicalActionDetail{}
	mi := &file_protocol_record_proto_msgTypes[18]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CanonicalActionDetail) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CanonicalActionDetail) ProtoMessage() {}

func (x *CanonicalActionDetail) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[18]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CanonicalActionDetail.ProtoReflect.Descriptor instead.
func (*CanonicalActionDetail) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{18}
}

func (x *CanonicalActionDetail) GetCidrs() []string {
	if x != nil {
		return x.Cidrs
	}
	return nil
}

func (x *CanonicalActionDetail) GetTargetPort() uint32 {
	if x != nil {
		return x.TargetPort
	}
	return 0
}

func (x *CanonicalActionDetail) GetGrantDst() []string {
	if x != nil {
		return x.GrantDst
	}
	return nil
}

// Rendering (D-MCP-17): approver devices render only these daemon-built fields as the action, and
// ApprovalRequest.summary and preview as untrusted text, so an agent cannot carry trusted rdata, an alias or a
// path in prose.
type ApprovalRequest struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	ApprovalId         []byte                 `protobuf:"bytes,1,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"`
	ActionId           []byte                 `protobuf:"bytes,2,opt,name=action_id,json=actionId,proto3" json:"action_id,omitempty"`
	RunId              []byte                 `protobuf:"bytes,3,opt,name=run_id,json=runId,proto3" json:"run_id,omitempty"`
	AgentId            []byte                 `protobuf:"bytes,4,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
	CanonicalAction    []byte                 `protobuf:"bytes,5,opt,name=canonical_action,json=canonicalAction,proto3" json:"canonical_action,omitempty"`
	PayloadSha256      []byte                 `protobuf:"bytes,6,opt,name=payload_sha256,json=payloadSha256,proto3" json:"payload_sha256,omitempty"` // SHA-256(canonical_action as stored)
	Summary            string                 `protobuf:"bytes,7,opt,name=summary,proto3" json:"summary,omitempty"`                                  // agent text, shown as untrusted
	Risk               uint32                 `protobuf:"varint,8,opt,name=risk,proto3" json:"risk,omitempty"`                                       // max(policy, classifier); agents may only raise it
	RequesterSidecarId []byte                 `protobuf:"bytes,9,opt,name=requester_sidecar_id,json=requesterSidecarId,proto3" json:"requester_sidecar_id,omitempty"`
	Tainted            bool                   `protobuf:"varint,10,opt,name=tainted,proto3" json:"tainted,omitempty"`
	Approvers          [][]byte               `protobuf:"bytes,11,rep,name=approvers,proto3" json:"approvers,omitempty"`
	NotAfterMillis     int64                  `protobuf:"varint,12,opt,name=not_after_millis,json=notAfterMillis,proto3" json:"not_after_millis,omitempty"`
	Version            uint32                 `protobuf:"varint,13,opt,name=version,proto3" json:"version,omitempty"` // 1, or 2, which adds uses (18) and always sets it; an approver that
	// does not know a version refuses it
	// Daemon-built, as the action's fields are, and rendered by approvers; request_sha256 covers them: the local port a
	// socket_listen, tls_publish, bridge_forward or bridge_expose binds, a listen's weight and a publish's ALPNs
	// (QD-740), and a socket_listen's name in its one form, which every listen's request carries (QD-772). The name
	// agrees with the action's one grant_dst entry: sock:<the name> for a tls/ or smtp/ name, sock:<its token path in
	// hex> for an application name, which an approver derives under K_sock before it approves.
	LocalPort     uint32   `protobuf:"varint,14,opt,name=local_port,json=localPort,proto3" json:"local_port,omitempty"`
	Weight        int32    `protobuf:"varint,15,opt,name=weight,proto3" json:"weight,omitempty"`
	Alpn          []string `protobuf:"bytes,16,rep,name=alpn,proto3" json:"alpn,omitempty"`
	SocketName    string   `protobuf:"bytes,17,opt,name=socket_name,json=socketName,proto3" json:"socket_name,omitempty"`
	Uses          uint32   `protobuf:"varint,18,opt,name=uses,proto3" json:"uses,omitempty"` // version 2's (QD-1010; 16.6's multi-use row): how many distinct actions
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ApprovalRequest) Reset() {
	*x = ApprovalRequest{}
	mi := &file_protocol_record_proto_msgTypes[19]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ApprovalRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApprovalRequest) ProtoMessage() {}

func (x *ApprovalRequest) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[19]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApprovalRequest.ProtoReflect.Descriptor instead.
func (*ApprovalRequest) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{19}
}

func (x *ApprovalRequest) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

func (x *ApprovalRequest) GetActionId() []byte {
	if x != nil {
		return x.ActionId
	}
	return nil
}

func (x *ApprovalRequest) GetRunId() []byte {
	if x != nil {
		return x.RunId
	}
	return nil
}

func (x *ApprovalRequest) GetAgentId() []byte {
	if x != nil {
		return x.AgentId
	}
	return nil
}

func (x *ApprovalRequest) GetCanonicalAction() []byte {
	if x != nil {
		return x.CanonicalAction
	}
	return nil
}

func (x *ApprovalRequest) GetPayloadSha256() []byte {
	if x != nil {
		return x.PayloadSha256
	}
	return nil
}

func (x *ApprovalRequest) GetSummary() string {
	if x != nil {
		return x.Summary
	}
	return ""
}

func (x *ApprovalRequest) GetRisk() uint32 {
	if x != nil {
		return x.Risk
	}
	return 0
}

func (x *ApprovalRequest) GetRequesterSidecarId() []byte {
	if x != nil {
		return x.RequesterSidecarId
	}
	return nil
}

func (x *ApprovalRequest) GetTainted() bool {
	if x != nil {
		return x.Tainted
	}
	return false
}

func (x *ApprovalRequest) GetApprovers() [][]byte {
	if x != nil {
		return x.Approvers
	}
	return nil
}

func (x *ApprovalRequest) GetNotAfterMillis() int64 {
	if x != nil {
		return x.NotAfterMillis
	}
	return 0
}

func (x *ApprovalRequest) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *ApprovalRequest) GetLocalPort() uint32 {
	if x != nil {
		return x.LocalPort
	}
	return 0
}

func (x *ApprovalRequest) GetWeight() int32 {
	if x != nil {
		return x.Weight
	}
	return 0
}

func (x *ApprovalRequest) GetAlpn() []string {
	if x != nil {
		return x.Alpn
	}
	return nil
}

func (x *ApprovalRequest) GetSocketName() string {
	if x != nil {
		return x.SocketName
	}
	return ""
}

func (x *ApprovalRequest) GetUses() uint32 {
	if x != nil {
		return x.Uses
	}
	return 0
}

type ApprovalDecision struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ApprovalId    []byte                 `protobuf:"bytes,1,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"`
	RequestSha256 []byte                 `protobuf:"bytes,2,opt,name=request_sha256,json=requestSha256,proto3" json:"request_sha256,omitempty"` // SHA-256(ApprovalRequest as stored): binds run_id, agent_id,
	// approvers, expiry
	PayloadSha256  []byte `protobuf:"bytes,3,opt,name=payload_sha256,json=payloadSha256,proto3" json:"payload_sha256,omitempty"` // SHA-256(CanonicalAction as stored), never a re-encoding
	Decision       uint32 `protobuf:"varint,4,opt,name=decision,proto3" json:"decision,omitempty"`
	Uses           uint32 `protobuf:"varint,5,opt,name=uses,proto3" json:"uses,omitempty"`
	NotAfterMillis int64  `protobuf:"varint,6,opt,name=not_after_millis,json=notAfterMillis,proto3" json:"not_after_millis,omitempty"` // at most uses distinct actions, each
	// once (D-MCP-11); uses > 1 only with a
	// scope = true template (16.6)
	ApproverMemberId []byte `protobuf:"bytes,7,opt,name=approver_member_id,json=approverMemberId,proto3" json:"approver_member_id,omitempty"`
	Channel          uint32 `protobuf:"varint,8,opt,name=channel,proto3" json:"channel,omitempty"` // evidence: device, presence or harness (owner decision 75)
	Sshsig           []byte `protobuf:"bytes,9,opt,name=sshsig,proto3" json:"sshsig,omitempty"`
	EvidenceSha256   []byte `protobuf:"bytes,10,opt,name=evidence_sha256,json=evidenceSha256,proto3" json:"evidence_sha256,omitempty"` // harness: the matched hook event, which stays in the record;
	// device and presence: empty, a presence decision's assertion riding
	// in Signed.webauthn (record-md-presence-evidence-sha256)
	RequesterSidecarId []byte          `protobuf:"bytes,11,opt,name=requester_sidecar_id,json=requesterSidecarId,proto3" json:"requester_sidecar_id,omitempty"` // the only sidecar that may spend it (16.6)
	AuthPin            *bridge.AuthPin `protobuf:"bytes,12,opt,name=auth_pin,json=authPin,proto3" json:"auth_pin,omitempty"`                                    // §7.9's pin the approver evaluated the request under
	Version            uint32          `protobuf:"varint,13,opt,name=version,proto3" json:"version,omitempty"`                                                  // 1; 2 adds selected; 3, channel 4's alone, adds auto and auto_verdict
	// and may carry selected; a reader that does not know a version refuses
	// it whole (DESIGN-COMPUTE.md §23.9, §27.9)
	Selected []uint32 `protobuf:"varint,14,rep,packed,name=selected,proto3" json:"selected,omitempty"` // version 2's: the indexes of the events a kind-25 decision approves,
	// ascending, an empty list approving none (§23.9)
	Auto          bool         `protobuf:"varint,15,opt,name=auto,proto3" json:"auto,omitempty"`                                 // version 3's: the requesting sidecar's classifier decided, not a person
	AutoVerdict   *AutoVerdict `protobuf:"bytes,16,opt,name=auto_verdict,json=autoVerdict,proto3" json:"auto_verdict,omitempty"` // version 3's (§27.9)
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ApprovalDecision) Reset() {
	*x = ApprovalDecision{}
	mi := &file_protocol_record_proto_msgTypes[20]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ApprovalDecision) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApprovalDecision) ProtoMessage() {}

func (x *ApprovalDecision) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[20]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApprovalDecision.ProtoReflect.Descriptor instead.
func (*ApprovalDecision) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{20}
}

func (x *ApprovalDecision) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

func (x *ApprovalDecision) GetRequestSha256() []byte {
	if x != nil {
		return x.RequestSha256
	}
	return nil
}

func (x *ApprovalDecision) GetPayloadSha256() []byte {
	if x != nil {
		return x.PayloadSha256
	}
	return nil
}

func (x *ApprovalDecision) GetDecision() uint32 {
	if x != nil {
		return x.Decision
	}
	return 0
}

func (x *ApprovalDecision) GetUses() uint32 {
	if x != nil {
		return x.Uses
	}
	return 0
}

func (x *ApprovalDecision) GetNotAfterMillis() int64 {
	if x != nil {
		return x.NotAfterMillis
	}
	return 0
}

func (x *ApprovalDecision) GetApproverMemberId() []byte {
	if x != nil {
		return x.ApproverMemberId
	}
	return nil
}

func (x *ApprovalDecision) GetChannel() uint32 {
	if x != nil {
		return x.Channel
	}
	return 0
}

func (x *ApprovalDecision) GetSshsig() []byte {
	if x != nil {
		return x.Sshsig
	}
	return nil
}

func (x *ApprovalDecision) GetEvidenceSha256() []byte {
	if x != nil {
		return x.EvidenceSha256
	}
	return nil
}

func (x *ApprovalDecision) GetRequesterSidecarId() []byte {
	if x != nil {
		return x.RequesterSidecarId
	}
	return nil
}

func (x *ApprovalDecision) GetAuthPin() *bridge.AuthPin {
	if x != nil {
		return x.AuthPin
	}
	return nil
}

func (x *ApprovalDecision) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *ApprovalDecision) GetSelected() []uint32 {
	if x != nil {
		return x.Selected
	}
	return nil
}

func (x *ApprovalDecision) GetAuto() bool {
	if x != nil {
		return x.Auto
	}
	return false
}

func (x *ApprovalDecision) GetAutoVerdict() *AutoVerdict {
	if x != nil {
		return x.AutoVerdict
	}
	return nil
}

// ApprovalDecision.auto_verdict (DESIGN-COMPUTE.md §27.9): the verdict a channel-4 decision rests on, whose entry,
// RECORD.md's kind 56, holds the rest.
type AutoVerdict struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Verdict       uint32                 `protobuf:"varint,1,opt,name=verdict,proto3" json:"verdict,omitempty"` // 1 allow; an ask files no decision
	Reason        uint32                 `protobuf:"varint,2,opt,name=reason,proto3" json:"reason,omitempty"`   // 1 clean
	Score         uint32                 `protobuf:"varint,3,opt,name=score,proto3" json:"score,omitempty"`
	Threshold     uint32                 `protobuf:"varint,4,opt,name=threshold,proto3" json:"threshold,omitempty"` // basis points
	Model         string                 `protobuf:"bytes,5,opt,name=model,proto3" json:"model,omitempty"`
	ModelSha256   []byte                 `protobuf:"bytes,6,opt,name=model_sha256,json=modelSha256,proto3" json:"model_sha256,omitempty"`    // as the release's manifest pins them
	InputsSha256  []byte                 `protobuf:"bytes,7,opt,name=inputs_sha256,json=inputsSha256,proto3" json:"inputs_sha256,omitempty"` // SHA-256 over the auto_verdict entry's inputs and payload, as stored
	Windows       uint32                 `protobuf:"varint,8,opt,name=windows,proto3" json:"windows,omitempty"`                              // how many windows it scored
	RunCount      uint32                 `protobuf:"varint,9,opt,name=run_count,json=runCount,proto3" json:"run_count,omitempty"`
	DayCount      uint32                 `protobuf:"varint,10,opt,name=day_count,json=dayCount,proto3" json:"day_count,omitempty"` // this run's and this device's, this one included
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AutoVerdict) Reset() {
	*x = AutoVerdict{}
	mi := &file_protocol_record_proto_msgTypes[21]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AutoVerdict) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AutoVerdict) ProtoMessage() {}

func (x *AutoVerdict) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[21]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AutoVerdict.ProtoReflect.Descriptor instead.
func (*AutoVerdict) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{21}
}

func (x *AutoVerdict) GetVerdict() uint32 {
	if x != nil {
		return x.Verdict
	}
	return 0
}

func (x *AutoVerdict) GetReason() uint32 {
	if x != nil {
		return x.Reason
	}
	return 0
}

func (x *AutoVerdict) GetScore() uint32 {
	if x != nil {
		return x.Score
	}
	return 0
}

func (x *AutoVerdict) GetThreshold() uint32 {
	if x != nil {
		return x.Threshold
	}
	return 0
}

func (x *AutoVerdict) GetModel() string {
	if x != nil {
		return x.Model
	}
	return ""
}

func (x *AutoVerdict) GetModelSha256() []byte {
	if x != nil {
		return x.ModelSha256
	}
	return nil
}

func (x *AutoVerdict) GetInputsSha256() []byte {
	if x != nil {
		return x.InputsSha256
	}
	return nil
}

func (x *AutoVerdict) GetWindows() uint32 {
	if x != nil {
		return x.Windows
	}
	return 0
}

func (x *AutoVerdict) GetRunCount() uint32 {
	if x != nil {
		return x.RunCount
	}
	return 0
}

func (x *AutoVerdict) GetDayCount() uint32 {
	if x != nil {
		return x.DayCount
	}
	return 0
}

type ApprovalCancel struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ApprovalId    []byte                 `protobuf:"bytes,1,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ApprovalCancel) Reset() {
	*x = ApprovalCancel{}
	mi := &file_protocol_record_proto_msgTypes[22]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ApprovalCancel) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApprovalCancel) ProtoMessage() {}

func (x *ApprovalCancel) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[22]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApprovalCancel.ProtoReflect.Descriptor instead.
func (*ApprovalCancel) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{22}
}

func (x *ApprovalCancel) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

type ReachReceipt struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// receipts per server name too
	GrantId           []byte   `protobuf:"bytes,1,opt,name=grant_id,json=grantId,proto3" json:"grant_id,omitempty"`
	PolicyVersion     uint64   `protobuf:"varint,2,opt,name=policy_version,json=policyVersion,proto3" json:"policy_version,omitempty"`
	Kind              uint32   `protobuf:"varint,3,opt,name=kind,proto3" json:"kind,omitempty"`
	Owner             []byte   `protobuf:"bytes,4,opt,name=owner,proto3" json:"owner,omitempty"`
	Approver          []byte   `protobuf:"bytes,5,opt,name=approver,proto3" json:"approver,omitempty"`
	WindowStartMillis int64    `protobuf:"varint,6,opt,name=window_start_millis,json=windowStartMillis,proto3" json:"window_start_millis,omitempty"`
	Peers             [][]byte `protobuf:"bytes,7,rep,name=peers,proto3" json:"peers,omitempty"`
	StreamCount       uint64   `protobuf:"varint,8,opt,name=stream_count,json=streamCount,proto3" json:"stream_count,omitempty"`
	ByteCount         uint64   `protobuf:"varint,9,opt,name=byte_count,json=byteCount,proto3" json:"byte_count,omitempty"`
	Relays            []string `protobuf:"bytes,10,rep,name=relays,proto3" json:"relays,omitempty"`                           // host, IP and operator of each relay or edge in the path
	ServerName        string   `protobuf:"bytes,11,opt,name=server_name,json=serverName,proto3" json:"server_name,omitempty"` // the name the visitor asked for, the TLS SNI, which only the TLS
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *ReachReceipt) Reset() {
	*x = ReachReceipt{}
	mi := &file_protocol_record_proto_msgTypes[23]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ReachReceipt) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReachReceipt) ProtoMessage() {}

func (x *ReachReceipt) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[23]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReachReceipt.ProtoReflect.Descriptor instead.
func (*ReachReceipt) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{23}
}

func (x *ReachReceipt) GetGrantId() []byte {
	if x != nil {
		return x.GrantId
	}
	return nil
}

func (x *ReachReceipt) GetPolicyVersion() uint64 {
	if x != nil {
		return x.PolicyVersion
	}
	return 0
}

func (x *ReachReceipt) GetKind() uint32 {
	if x != nil {
		return x.Kind
	}
	return 0
}

func (x *ReachReceipt) GetOwner() []byte {
	if x != nil {
		return x.Owner
	}
	return nil
}

func (x *ReachReceipt) GetApprover() []byte {
	if x != nil {
		return x.Approver
	}
	return nil
}

func (x *ReachReceipt) GetWindowStartMillis() int64 {
	if x != nil {
		return x.WindowStartMillis
	}
	return 0
}

func (x *ReachReceipt) GetPeers() [][]byte {
	if x != nil {
		return x.Peers
	}
	return nil
}

func (x *ReachReceipt) GetStreamCount() uint64 {
	if x != nil {
		return x.StreamCount
	}
	return 0
}

func (x *ReachReceipt) GetByteCount() uint64 {
	if x != nil {
		return x.ByteCount
	}
	return 0
}

func (x *ReachReceipt) GetRelays() []string {
	if x != nil {
		return x.Relays
	}
	return nil
}

func (x *ReachReceipt) GetServerName() string {
	if x != nil {
		return x.ServerName
	}
	return ""
}

type Coverage struct {
	state   protoimpl.MessageState `protogen:"open.v1"`
	RunId   []byte                 `protobuf:"bytes,1,opt,name=run_id,json=runId,proto3" json:"run_id,omitempty"`
	Harness string                 `protobuf:"bytes,2,opt,name=harness,proto3" json:"harness,omitempty"`
	Version string                 `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	Sources []string               `protobuf:"bytes,4,rep,name=sources,proto3" json:"sources,omitempty"`
	Gaps    []string               `protobuf:"bytes,5,rep,name=gaps,proto3" json:"gaps,omitempty"` // hook failures, missed events, changed configs, downtime, truncation,
	// oversize, bypass modes, redactions
	FirstSeq      uint64      `protobuf:"varint,6,opt,name=first_seq,json=firstSeq,proto3" json:"first_seq,omitempty"`
	LastSeq       uint64      `protobuf:"varint,7,opt,name=last_seq,json=lastSeq,proto3" json:"last_seq,omitempty"`
	BodiesDropped []*SeqRange `protobuf:"bytes,8,rep,name=bodies_dropped,json=bodiesDropped,proto3" json:"bodies_dropped,omitempty"` // DESIGN-COMPUTE §24.5, §24.10: the writer's seqs in this log whose
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Coverage) Reset() {
	*x = Coverage{}
	mi := &file_protocol_record_proto_msgTypes[24]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Coverage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Coverage) ProtoMessage() {}

func (x *Coverage) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[24]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Coverage.ProtoReflect.Descriptor instead.
func (*Coverage) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{24}
}

func (x *Coverage) GetRunId() []byte {
	if x != nil {
		return x.RunId
	}
	return nil
}

func (x *Coverage) GetHarness() string {
	if x != nil {
		return x.Harness
	}
	return ""
}

func (x *Coverage) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *Coverage) GetSources() []string {
	if x != nil {
		return x.Sources
	}
	return nil
}

func (x *Coverage) GetGaps() []string {
	if x != nil {
		return x.Gaps
	}
	return nil
}

func (x *Coverage) GetFirstSeq() uint64 {
	if x != nil {
		return x.FirstSeq
	}
	return 0
}

func (x *Coverage) GetLastSeq() uint64 {
	if x != nil {
		return x.LastSeq
	}
	return 0
}

func (x *Coverage) GetBodiesDropped() []*SeqRange {
	if x != nil {
		return x.BodiesDropped
	}
	return nil
}

type SeqRange struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	First         uint64                 `protobuf:"varint,1,opt,name=first,proto3" json:"first,omitempty"`
	Last          uint64                 `protobuf:"varint,2,opt,name=last,proto3" json:"last,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SeqRange) Reset() {
	*x = SeqRange{}
	mi := &file_protocol_record_proto_msgTypes[25]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SeqRange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SeqRange) ProtoMessage() {}

func (x *SeqRange) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[25]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SeqRange.ProtoReflect.Descriptor instead.
func (*SeqRange) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{25}
}

func (x *SeqRange) GetFirst() uint64 {
	if x != nil {
		return x.First
	}
	return 0
}

func (x *SeqRange) GetLast() uint64 {
	if x != nil {
		return x.Last
	}
	return 0
}

type RetentionPolicy struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	LogId          []byte                 `protobuf:"bytes,1,opt,name=log_id,json=logId,proto3" json:"log_id,omitempty"`
	Class          uint32                 `protobuf:"varint,2,opt,name=class,proto3" json:"class,omitempty"` // a kind class, announce among them (keep_days 30, 16.11)
	KeepDays       uint32                 `protobuf:"varint,3,opt,name=keep_days,json=keepDays,proto3" json:"keep_days,omitempty"`
	SearchableDays uint32                 `protobuf:"varint,4,opt,name=searchable_days,json=searchableDays,proto3" json:"searchable_days,omitempty"`
	Archive        bool                   `protobuf:"varint,5,opt,name=archive,proto3" json:"archive,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *RetentionPolicy) Reset() {
	*x = RetentionPolicy{}
	mi := &file_protocol_record_proto_msgTypes[26]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RetentionPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RetentionPolicy) ProtoMessage() {}

func (x *RetentionPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[26]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RetentionPolicy.ProtoReflect.Descriptor instead.
func (*RetentionPolicy) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{26}
}

func (x *RetentionPolicy) GetLogId() []byte {
	if x != nil {
		return x.LogId
	}
	return nil
}

func (x *RetentionPolicy) GetClass() uint32 {
	if x != nil {
		return x.Class
	}
	return 0
}

func (x *RetentionPolicy) GetKeepDays() uint32 {
	if x != nil {
		return x.KeepDays
	}
	return 0
}

func (x *RetentionPolicy) GetSearchableDays() uint32 {
	if x != nil {
		return x.SearchableDays
	}
	return 0
}

func (x *RetentionPolicy) GetArchive() bool {
	if x != nil {
		return x.Archive
	}
	return false
}

// RECORD.md section 5.4: a deposit file's one message, sealed under its object key (§11.12).
type RecordDepositBatch struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Entries       []*RecordDeposit       `protobuf:"bytes,1,rep,name=entries,proto3" json:"entries,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RecordDepositBatch) Reset() {
	*x = RecordDepositBatch{}
	mi := &file_protocol_record_proto_msgTypes[27]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RecordDepositBatch) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RecordDepositBatch) ProtoMessage() {}

func (x *RecordDepositBatch) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[27]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RecordDepositBatch.ProtoReflect.Descriptor instead.
func (*RecordDepositBatch) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{27}
}

func (x *RecordDepositBatch) GetEntries() []*RecordDeposit {
	if x != nil {
		return x.Entries
	}
	return nil
}

type RecordDeposit struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Entry         []byte                 `protobuf:"bytes,1,opt,name=entry,proto3" json:"entry,omitempty"` // RecordEntry bytes; key_slot_id empty, key_index 0
	Key           []byte                 `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	Salt          []byte                 `protobuf:"bytes,3,opt,name=salt,proto3" json:"salt,omitempty"` // the body key and salt, which the ingester re-slots
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RecordDeposit) Reset() {
	*x = RecordDeposit{}
	mi := &file_protocol_record_proto_msgTypes[28]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RecordDeposit) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RecordDeposit) ProtoMessage() {}

func (x *RecordDeposit) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[28]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RecordDeposit.ProtoReflect.Descriptor instead.
func (*RecordDeposit) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{28}
}

func (x *RecordDeposit) GetEntry() []byte {
	if x != nil {
		return x.Entry
	}
	return nil
}

func (x *RecordDeposit) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *RecordDeposit) GetSalt() []byte {
	if x != nil {
		return x.Salt
	}
	return nil
}

// RECORD.md section 6.4: the new kinds' bodies, beside §16.8's messages (M3 unless a comment says otherwise).
type CoordinationBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Text          string                 `protobuf:"bytes,1,opt,name=text,proto3" json:"text,omitempty"`                                         // prose: claim and handoff <= 512 B, the others <= 1,024 B
	Targets       []string               `protobuf:"bytes,2,rep,name=targets,proto3" json:"targets,omitempty"`                                   // <= 16; section 6.4's targets grammar
	ExpiresMillis int64                  `protobuf:"varint,3,opt,name=expires_millis,json=expiresMillis,proto3" json:"expires_millis,omitempty"` // claim, ask; else 0
	ClaimId       []byte                 `protobuf:"bytes,4,opt,name=claim_id,json=claimId,proto3" json:"claim_id,omitempty"`                    // a claim restated: the opening entry's entry_id; empty when opening
	ClaimState    uint32                 `protobuf:"varint,5,opt,name=claim_state,json=claimState,proto3" json:"claim_state,omitempty"`          // claim: 1 active, 2 released (§16.11's Claim.state)
	Result        uint32                 `protobuf:"varint,6,opt,name=result,proto3" json:"result,omitempty"`                                    // check: 1 pass, 2 fail, 3 objection (a person's "no")
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CoordinationBody) Reset() {
	*x = CoordinationBody{}
	mi := &file_protocol_record_proto_msgTypes[29]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CoordinationBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CoordinationBody) ProtoMessage() {}

func (x *CoordinationBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[29]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CoordinationBody.ProtoReflect.Descriptor instead.
func (*CoordinationBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{29}
}

func (x *CoordinationBody) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

func (x *CoordinationBody) GetTargets() []string {
	if x != nil {
		return x.Targets
	}
	return nil
}

func (x *CoordinationBody) GetExpiresMillis() int64 {
	if x != nil {
		return x.ExpiresMillis
	}
	return 0
}

func (x *CoordinationBody) GetClaimId() []byte {
	if x != nil {
		return x.ClaimId
	}
	return nil
}

func (x *CoordinationBody) GetClaimState() uint32 {
	if x != nil {
		return x.ClaimState
	}
	return 0
}

func (x *CoordinationBody) GetResult() uint32 {
	if x != nil {
		return x.Result
	}
	return 0
}

type ContextBody struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	Stage            uint32                 `protobuf:"varint,1,opt,name=stage,proto3" json:"stage,omitempty"` // 1 start, 2 restatement (section 4.3)
	Harness          string                 `protobuf:"bytes,2,opt,name=harness,proto3" json:"harness,omitempty"`
	HarnessVersion   string                 `protobuf:"bytes,3,opt,name=harness_version,json=harnessVersion,proto3" json:"harness_version,omitempty"`
	AgentLabel       string                 `protobuf:"bytes,4,opt,name=agent_label,json=agentLabel,proto3" json:"agent_label,omitempty"`                    // [a-z0-9-]{1,64}, as §16.11's AnnounceWho
	SessionIds       []string               `protobuf:"bytes,5,rep,name=session_ids,json=sessionIds,proto3" json:"session_ids,omitempty"`                    // <= 4, each <= 64 B
	Model            string                 `protobuf:"bytes,6,opt,name=model,proto3" json:"model,omitempty"`                                                // an identifier <= 64 B, or empty
	PermissionMode   string                 `protobuf:"bytes,7,opt,name=permission_mode,json=permissionMode,proto3" json:"permission_mode,omitempty"`        // the harness's own string, <= 32 B
	RepoId           []byte                 `protobuf:"bytes,8,opt,name=repo_id,json=repoId,proto3" json:"repo_id,omitempty"`                                // the run's evs repo, else empty
	Project          string                 `protobuf:"bytes,9,opt,name=project,proto3" json:"project,omitempty"`                                            // §16.11's project key rule, <= 128 B; T: empty when the repo is private
	Branch           string                 `protobuf:"bytes,10,opt,name=branch,proto3" json:"branch,omitempty"`                                             // V: a git ref name <= 128 B
	Title            string                 `protobuf:"bytes,11,opt,name=title,proto3" json:"title,omitempty"`                                               // V: §16.10's run title, <= 120 B after redaction
	InstructionFiles []*InstructionFile     `protobuf:"bytes,12,rep,name=instruction_files,json=instructionFiles,proto3" json:"instruction_files,omitempty"` // <= 64
	Truncations      []string               `protobuf:"bytes,13,rep,name=truncations,proto3" json:"truncations,omitempty"`                                   // V: <= 16 warnings, each <= 128 B: a base name and its cut
	ConfigSha256     []byte                 `protobuf:"bytes,14,opt,name=config_sha256,json=configSha256,proto3" json:"config_sha256,omitempty"`             // the harness config hash §16.6 checks
	ContinuesRunId   []byte                 `protobuf:"bytes,15,opt,name=continues_run_id,json=continuesRunId,proto3" json:"continues_run_id,omitempty"`
	ContinuesEntryId []byte                 `protobuf:"bytes,16,opt,name=continues_entry_id,json=continuesEntryId,proto3" json:"continues_entry_id,omitempty"`
	Prompts          []string               `protobuf:"bytes,17,rep,name=prompts,proto3" json:"prompts,omitempty"` // V: the run's user prompts as they arrive (§16.7), each redacted and
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *ContextBody) Reset() {
	*x = ContextBody{}
	mi := &file_protocol_record_proto_msgTypes[30]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ContextBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContextBody) ProtoMessage() {}

func (x *ContextBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[30]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContextBody.ProtoReflect.Descriptor instead.
func (*ContextBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{30}
}

func (x *ContextBody) GetStage() uint32 {
	if x != nil {
		return x.Stage
	}
	return 0
}

func (x *ContextBody) GetHarness() string {
	if x != nil {
		return x.Harness
	}
	return ""
}

func (x *ContextBody) GetHarnessVersion() string {
	if x != nil {
		return x.HarnessVersion
	}
	return ""
}

func (x *ContextBody) GetAgentLabel() string {
	if x != nil {
		return x.AgentLabel
	}
	return ""
}

func (x *ContextBody) GetSessionIds() []string {
	if x != nil {
		return x.SessionIds
	}
	return nil
}

func (x *ContextBody) GetModel() string {
	if x != nil {
		return x.Model
	}
	return ""
}

func (x *ContextBody) GetPermissionMode() string {
	if x != nil {
		return x.PermissionMode
	}
	return ""
}

func (x *ContextBody) GetRepoId() []byte {
	if x != nil {
		return x.RepoId
	}
	return nil
}

func (x *ContextBody) GetProject() string {
	if x != nil {
		return x.Project
	}
	return ""
}

func (x *ContextBody) GetBranch() string {
	if x != nil {
		return x.Branch
	}
	return ""
}

func (x *ContextBody) GetTitle() string {
	if x != nil {
		return x.Title
	}
	return ""
}

func (x *ContextBody) GetInstructionFiles() []*InstructionFile {
	if x != nil {
		return x.InstructionFiles
	}
	return nil
}

func (x *ContextBody) GetTruncations() []string {
	if x != nil {
		return x.Truncations
	}
	return nil
}

func (x *ContextBody) GetConfigSha256() []byte {
	if x != nil {
		return x.ConfigSha256
	}
	return nil
}

func (x *ContextBody) GetContinuesRunId() []byte {
	if x != nil {
		return x.ContinuesRunId
	}
	return nil
}

func (x *ContextBody) GetContinuesEntryId() []byte {
	if x != nil {
		return x.ContinuesEntryId
	}
	return nil
}

func (x *ContextBody) GetPrompts() []string {
	if x != nil {
		return x.Prompts
	}
	return nil
}

type InstructionFile struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Scope         uint32                 `protobuf:"varint,1,opt,name=scope,proto3" json:"scope,omitempty"` // 1 managed, 2 user, 3 project
	Name          string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`    // V: the file's base name, <= 128 B; T keeps the hash (§16.7)
	Sha256        []byte                 `protobuf:"bytes,3,opt,name=sha256,proto3" json:"sha256,omitempty"`
	Size          uint64                 `protobuf:"varint,4,opt,name=size,proto3" json:"size,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *InstructionFile) Reset() {
	*x = InstructionFile{}
	mi := &file_protocol_record_proto_msgTypes[31]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InstructionFile) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InstructionFile) ProtoMessage() {}

func (x *InstructionFile) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[31]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InstructionFile.ProtoReflect.Descriptor instead.
func (*InstructionFile) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{31}
}

func (x *InstructionFile) GetScope() uint32 {
	if x != nil {
		return x.Scope
	}
	return 0
}

func (x *InstructionFile) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *InstructionFile) GetSha256() []byte {
	if x != nil {
		return x.Sha256
	}
	return nil
}

func (x *InstructionFile) GetSize() uint64 {
	if x != nil {
		return x.Size
	}
	return 0
}

type ChangeBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RepoId        []byte                 `protobuf:"bytes,1,opt,name=repo_id,json=repoId,proto3" json:"repo_id,omitempty"`
	Project       string                 `protobuf:"bytes,2,opt,name=project,proto3" json:"project,omitempty"`                         // as ContextBody
	BaseCommit    string                 `protobuf:"bytes,3,opt,name=base_commit,json=baseCommit,proto3" json:"base_commit,omitempty"` // the git oid the interval started from
	Commits       []string               `protobuf:"bytes,4,rep,name=commits,proto3" json:"commits,omitempty"`                         // <= 64 commits the run made in the interval: commit-to-run links
	PathCount     uint32                 `protobuf:"varint,5,opt,name=path_count,json=pathCount,proto3" json:"path_count,omitempty"`   // changed paths in all
	EditCount     uint32                 `protobuf:"varint,6,opt,name=edit_count,json=editCount,proto3" json:"edit_count,omitempty"`
	ShellCount    uint32                 `protobuf:"varint,7,opt,name=shell_count,json=shellCount,proto3" json:"shell_count,omitempty"`
	ForeignCount  uint32                 `protobuf:"varint,8,opt,name=foreign_count,json=foreignCount,proto3" json:"foreign_count,omitempty"` // by §16.7's attribution
	Capture       uint32                 `protobuf:"varint,9,opt,name=capture,proto3" json:"capture,omitempty"`                               // bits: 1 hooks, 2 scan, 4 file events
	Paths         []*ChangedPath         `protobuf:"bytes,10,rep,name=paths,proto3" json:"paths,omitempty"`                                   // <= 4,096; past it path_count stands, and coverage has truncation
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ChangeBody) Reset() {
	*x = ChangeBody{}
	mi := &file_protocol_record_proto_msgTypes[32]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ChangeBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChangeBody) ProtoMessage() {}

func (x *ChangeBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[32]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChangeBody.ProtoReflect.Descriptor instead.
func (*ChangeBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{32}
}

func (x *ChangeBody) GetRepoId() []byte {
	if x != nil {
		return x.RepoId
	}
	return nil
}

func (x *ChangeBody) GetProject() string {
	if x != nil {
		return x.Project
	}
	return ""
}

func (x *ChangeBody) GetBaseCommit() string {
	if x != nil {
		return x.BaseCommit
	}
	return ""
}

func (x *ChangeBody) GetCommits() []string {
	if x != nil {
		return x.Commits
	}
	return nil
}

func (x *ChangeBody) GetPathCount() uint32 {
	if x != nil {
		return x.PathCount
	}
	return 0
}

func (x *ChangeBody) GetEditCount() uint32 {
	if x != nil {
		return x.EditCount
	}
	return 0
}

func (x *ChangeBody) GetShellCount() uint32 {
	if x != nil {
		return x.ShellCount
	}
	return 0
}

func (x *ChangeBody) GetForeignCount() uint32 {
	if x != nil {
		return x.ForeignCount
	}
	return 0
}

func (x *ChangeBody) GetCapture() uint32 {
	if x != nil {
		return x.Capture
	}
	return 0
}

func (x *ChangeBody) GetPaths() []*ChangedPath {
	if x != nil {
		return x.Paths
	}
	return nil
}

type ChangedPath struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Path          string                 `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"` // V: relative to the worktree
	BeforeSha256  []byte                 `protobuf:"bytes,2,opt,name=before_sha256,json=beforeSha256,proto3" json:"before_sha256,omitempty"`
	AfterSha256   []byte                 `protobuf:"bytes,3,opt,name=after_sha256,json=afterSha256,proto3" json:"after_sha256,omitempty"`   // §16.7's ledger; empty when absent or unknown
	Mode          uint32                 `protobuf:"varint,4,opt,name=mode,proto3" json:"mode,omitempty"`                                   // git's file mode
	Attribution   uint32                 `protobuf:"varint,5,opt,name=attribution,proto3" json:"attribution,omitempty"`                     // 1 edit, 2 shell, 3 foreign (§16.7)
	BlobEntryId   []byte                 `protobuf:"bytes,6,opt,name=blob_entry_id,json=blobEntryId,proto3" json:"blob_entry_id,omitempty"` // V: the blob with the after bytes; empty past §16.7's 8 MiB
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ChangedPath) Reset() {
	*x = ChangedPath{}
	mi := &file_protocol_record_proto_msgTypes[33]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ChangedPath) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChangedPath) ProtoMessage() {}

func (x *ChangedPath) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[33]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChangedPath.ProtoReflect.Descriptor instead.
func (*ChangedPath) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{33}
}

func (x *ChangedPath) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *ChangedPath) GetBeforeSha256() []byte {
	if x != nil {
		return x.BeforeSha256
	}
	return nil
}

func (x *ChangedPath) GetAfterSha256() []byte {
	if x != nil {
		return x.AfterSha256
	}
	return nil
}

func (x *ChangedPath) GetMode() uint32 {
	if x != nil {
		return x.Mode
	}
	return 0
}

func (x *ChangedPath) GetAttribution() uint32 {
	if x != nil {
		return x.Attribution
	}
	return 0
}

func (x *ChangedPath) GetBlobEntryId() []byte {
	if x != nil {
		return x.BlobEntryId
	}
	return nil
}

type PermissionBody struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	Decision        uint32                 `protobuf:"varint,1,opt,name=decision,proto3" json:"decision,omitempty"`                    // 0 unknown, 1 asked, 2 allowed, 3 denied
	DecidedBy       uint32                 `protobuf:"varint,2,opt,name=decided_by,json=decidedBy,proto3" json:"decided_by,omitempty"` // 0 unknown, 1 user, 2 config, 3 hook, 4 classifier
	PermissionMode  string                 `protobuf:"bytes,3,opt,name=permission_mode,json=permissionMode,proto3" json:"permission_mode,omitempty"`
	ToolClass       uint32                 `protobuf:"varint,4,opt,name=tool_class,json=toolClass,proto3" json:"tool_class,omitempty"`                  // 1 shell, 2 edit, 3 mcp, 4 web, 5 other
	ToolName        string                 `protobuf:"bytes,5,opt,name=tool_name,json=toolName,proto3" json:"tool_name,omitempty"`                      // V: <= 64 B
	ArgumentsSha256 []byte                 `protobuf:"bytes,6,opt,name=arguments_sha256,json=argumentsSha256,proto3" json:"arguments_sha256,omitempty"` // V: §16.6's hash of the arguments
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *PermissionBody) Reset() {
	*x = PermissionBody{}
	mi := &file_protocol_record_proto_msgTypes[34]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PermissionBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PermissionBody) ProtoMessage() {}

func (x *PermissionBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[34]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PermissionBody.ProtoReflect.Descriptor instead.
func (*PermissionBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{34}
}

func (x *PermissionBody) GetDecision() uint32 {
	if x != nil {
		return x.Decision
	}
	return 0
}

func (x *PermissionBody) GetDecidedBy() uint32 {
	if x != nil {
		return x.DecidedBy
	}
	return 0
}

func (x *PermissionBody) GetPermissionMode() string {
	if x != nil {
		return x.PermissionMode
	}
	return ""
}

func (x *PermissionBody) GetToolClass() uint32 {
	if x != nil {
		return x.ToolClass
	}
	return 0
}

func (x *PermissionBody) GetToolName() string {
	if x != nil {
		return x.ToolName
	}
	return ""
}

func (x *PermissionBody) GetArgumentsSha256() []byte {
	if x != nil {
		return x.ArgumentsSha256
	}
	return nil
}

type ApprovalUseBody struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	ApprovalId     []byte                 `protobuf:"bytes,1,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"`
	UseIndex       uint32                 `protobuf:"varint,2,opt,name=use_index,json=useIndex,proto3" json:"use_index,omitempty"`
	PayloadSha256  []byte                 `protobuf:"bytes,3,opt,name=payload_sha256,json=payloadSha256,proto3" json:"payload_sha256,omitempty"`
	EffectKey      []byte                 `protobuf:"bytes,4,opt,name=effect_key,json=effectKey,proto3" json:"effect_key,omitempty"`
	State          uint32                 `protobuf:"varint,5,opt,name=state,proto3" json:"state,omitempty"` // §16.6's Outcome: 1 done, 2 not_done, 3 uncertain
	EffectRef      []byte                 `protobuf:"bytes,6,opt,name=effect_ref,json=effectRef,proto3" json:"effect_ref,omitempty"`
	ReservedMillis int64                  `protobuf:"varint,7,opt,name=reserved_millis,json=reservedMillis,proto3" json:"reserved_millis,omitempty"`
	OutcomeMillis  int64                  `protobuf:"varint,8,opt,name=outcome_millis,json=outcomeMillis,proto3" json:"outcome_millis,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *ApprovalUseBody) Reset() {
	*x = ApprovalUseBody{}
	mi := &file_protocol_record_proto_msgTypes[35]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ApprovalUseBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApprovalUseBody) ProtoMessage() {}

func (x *ApprovalUseBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[35]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApprovalUseBody.ProtoReflect.Descriptor instead.
func (*ApprovalUseBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{35}
}

func (x *ApprovalUseBody) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

func (x *ApprovalUseBody) GetUseIndex() uint32 {
	if x != nil {
		return x.UseIndex
	}
	return 0
}

func (x *ApprovalUseBody) GetPayloadSha256() []byte {
	if x != nil {
		return x.PayloadSha256
	}
	return nil
}

func (x *ApprovalUseBody) GetEffectKey() []byte {
	if x != nil {
		return x.EffectKey
	}
	return nil
}

func (x *ApprovalUseBody) GetState() uint32 {
	if x != nil {
		return x.State
	}
	return 0
}

func (x *ApprovalUseBody) GetEffectRef() []byte {
	if x != nil {
		return x.EffectRef
	}
	return nil
}

func (x *ApprovalUseBody) GetReservedMillis() int64 {
	if x != nil {
		return x.ReservedMillis
	}
	return 0
}

func (x *ApprovalUseBody) GetOutcomeMillis() int64 {
	if x != nil {
		return x.OutcomeMillis
	}
	return 0
}

type RouteBody struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	Event           uint32                 `protobuf:"varint,1,opt,name=event,proto3" json:"event,omitempty"`                // 1 opened, 2 closed
	Kind            uint32                 `protobuf:"varint,2,opt,name=kind,proto3" json:"kind,omitempty"`                  // 1 forward, 2 expose, 3 route, 4 map (§17.8)
	RuleId          []byte                 `protobuf:"bytes,3,opt,name=rule_id,json=ruleId,proto3" json:"rule_id,omitempty"` // bridge rules; a forward's grant is the header's grant_id
	TargetSidecarId []byte                 `protobuf:"bytes,4,opt,name=target_sidecar_id,json=targetSidecarId,proto3" json:"target_sidecar_id,omitempty"`
	TargetPort      uint32                 `protobuf:"varint,5,opt,name=target_port,json=targetPort,proto3" json:"target_port,omitempty"`
	Cidrs           []string               `protobuf:"bytes,6,rep,name=cidrs,proto3" json:"cidrs,omitempty"`
	ExpiresMillis   int64                  `protobuf:"varint,7,opt,name=expires_millis,json=expiresMillis,proto3" json:"expires_millis,omitempty"`
	ApprovalId      []byte                 `protobuf:"bytes,8,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"`
	Reason          uint32                 `protobuf:"varint,9,opt,name=reason,proto3" json:"reason,omitempty"` // closed: 1 expired, 2 revoked, 3 withdrawn, 4 suspended
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *RouteBody) Reset() {
	*x = RouteBody{}
	mi := &file_protocol_record_proto_msgTypes[36]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RouteBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RouteBody) ProtoMessage() {}

func (x *RouteBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[36]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RouteBody.ProtoReflect.Descriptor instead.
func (*RouteBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{36}
}

func (x *RouteBody) GetEvent() uint32 {
	if x != nil {
		return x.Event
	}
	return 0
}

func (x *RouteBody) GetKind() uint32 {
	if x != nil {
		return x.Kind
	}
	return 0
}

func (x *RouteBody) GetRuleId() []byte {
	if x != nil {
		return x.RuleId
	}
	return nil
}

func (x *RouteBody) GetTargetSidecarId() []byte {
	if x != nil {
		return x.TargetSidecarId
	}
	return nil
}

func (x *RouteBody) GetTargetPort() uint32 {
	if x != nil {
		return x.TargetPort
	}
	return 0
}

func (x *RouteBody) GetCidrs() []string {
	if x != nil {
		return x.Cidrs
	}
	return nil
}

func (x *RouteBody) GetExpiresMillis() int64 {
	if x != nil {
		return x.ExpiresMillis
	}
	return 0
}

func (x *RouteBody) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

func (x *RouteBody) GetReason() uint32 {
	if x != nil {
		return x.Reason
	}
	return 0
}

type PublishBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Event         uint32                 `protobuf:"varint,1,opt,name=event,proto3" json:"event,omitempty"` // 1 opened, 2 closed
	Host          string                 `protobuf:"bytes,2,opt,name=host,proto3" json:"host,omitempty"`
	Port          uint32                 `protobuf:"varint,3,opt,name=port,proto3" json:"port,omitempty"`
	Audience      uint32                 `protobuf:"varint,4,opt,name=audience,proto3" json:"audience,omitempty"`
	AppMode       uint32                 `protobuf:"varint,5,opt,name=app_mode,json=appMode,proto3" json:"app_mode,omitempty"`
	ExpiresMillis int64                  `protobuf:"varint,6,opt,name=expires_millis,json=expiresMillis,proto3" json:"expires_millis,omitempty"`
	ApprovalId    []byte                 `protobuf:"bytes,7,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"`
	Reason        uint32                 `protobuf:"varint,8,opt,name=reason,proto3" json:"reason,omitempty"` // reason as RouteBody
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PublishBody) Reset() {
	*x = PublishBody{}
	mi := &file_protocol_record_proto_msgTypes[37]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublishBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublishBody) ProtoMessage() {}

func (x *PublishBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[37]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublishBody.ProtoReflect.Descriptor instead.
func (*PublishBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{37}
}

func (x *PublishBody) GetEvent() uint32 {
	if x != nil {
		return x.Event
	}
	return 0
}

func (x *PublishBody) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *PublishBody) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *PublishBody) GetAudience() uint32 {
	if x != nil {
		return x.Audience
	}
	return 0
}

func (x *PublishBody) GetAppMode() uint32 {
	if x != nil {
		return x.AppMode
	}
	return 0
}

func (x *PublishBody) GetExpiresMillis() int64 {
	if x != nil {
		return x.ExpiresMillis
	}
	return 0
}

func (x *PublishBody) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

func (x *PublishBody) GetReason() uint32 {
	if x != nil {
		return x.Reason
	}
	return 0
}

type RestoreBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RestoredRunId []byte                 `protobuf:"bytes,1,opt,name=restored_run_id,json=restoredRunId,proto3" json:"restored_run_id,omitempty"`
	PreviewId     []byte                 `protobuf:"bytes,2,opt,name=preview_id,json=previewId,proto3" json:"preview_id,omitempty"`
	ApprovalId    []byte                 `protobuf:"bytes,3,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"` // a tainted run's, or shell paths', else empty
	RestoredCount uint32                 `protobuf:"varint,4,opt,name=restored_count,json=restoredCount,proto3" json:"restored_count,omitempty"`
	ConflictCount uint32                 `protobuf:"varint,5,opt,name=conflict_count,json=conflictCount,proto3" json:"conflict_count,omitempty"`
	Paths         []*RestoredPath        `protobuf:"bytes,6,rep,name=paths,proto3" json:"paths,omitempty"` // V: <= 4,096
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RestoreBody) Reset() {
	*x = RestoreBody{}
	mi := &file_protocol_record_proto_msgTypes[38]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RestoreBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RestoreBody) ProtoMessage() {}

func (x *RestoreBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[38]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RestoreBody.ProtoReflect.Descriptor instead.
func (*RestoreBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{38}
}

func (x *RestoreBody) GetRestoredRunId() []byte {
	if x != nil {
		return x.RestoredRunId
	}
	return nil
}

func (x *RestoreBody) GetPreviewId() []byte {
	if x != nil {
		return x.PreviewId
	}
	return nil
}

func (x *RestoreBody) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

func (x *RestoreBody) GetRestoredCount() uint32 {
	if x != nil {
		return x.RestoredCount
	}
	return 0
}

func (x *RestoreBody) GetConflictCount() uint32 {
	if x != nil {
		return x.ConflictCount
	}
	return 0
}

func (x *RestoreBody) GetPaths() []*RestoredPath {
	if x != nil {
		return x.Paths
	}
	return nil
}

type RestoredPath struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Path          string                 `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	Result        string                 `protobuf:"bytes,2,opt,name=result,proto3" json:"result,omitempty"` // restored, or §16.7's conflict name
	Copies        []string               `protobuf:"bytes,3,rep,name=copies,proto3" json:"copies,omitempty"` // <= 2: §16.7's copies beside the path
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RestoredPath) Reset() {
	*x = RestoredPath{}
	mi := &file_protocol_record_proto_msgTypes[39]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RestoredPath) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RestoredPath) ProtoMessage() {}

func (x *RestoredPath) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[39]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RestoredPath.ProtoReflect.Descriptor instead.
func (*RestoredPath) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{39}
}

func (x *RestoredPath) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *RestoredPath) GetResult() string {
	if x != nil {
		return x.Result
	}
	return ""
}

func (x *RestoredPath) GetCopies() []string {
	if x != nil {
		return x.Copies
	}
	return nil
}

type MembershipBody struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	Event uint32                 `protobuf:"varint,1,opt,name=event,proto3" json:"event,omitempty"` // 1 member_added, 2 member_removed, 3 admission_alarm, 4 recovery_rebind,
	// 5 recovery_window, 6 recovery_unseen
	MemberId        []byte `protobuf:"bytes,2,opt,name=member_id,json=memberId,proto3" json:"member_id,omitempty"`
	SidecarId       []byte `protobuf:"bytes,3,opt,name=sidecar_id,json=sidecarId,proto3" json:"sidecar_id,omitempty"`
	GroupId         []byte `protobuf:"bytes,4,opt,name=group_id,json=groupId,proto3" json:"group_id,omitempty"`
	AuthPosition    uint64 `protobuf:"varint,5,opt,name=auth_position,json=authPosition,proto3" json:"auth_position,omitempty"`         // the statement's log position; 0 for an alarm
	StatementSha256 []byte `protobuf:"bytes,6,opt,name=statement_sha256,json=statementSha256,proto3" json:"statement_sha256,omitempty"` // the statement's Signed as stored
	Evidence        uint32 `protobuf:"varint,7,opt,name=evidence,proto3" json:"evidence,omitempty"`                                     // a member's own device revocation (§5.6): 1 presence, 2 confirmation
	Assertion       []byte `protobuf:"bytes,8,opt,name=assertion,proto3" json:"assertion,omitempty"`                                    // evidence 1: the WebAuthnEvidence as stored (§6.9)
	Reason          uint32 `protobuf:"varint,9,opt,name=reason,proto3" json:"reason,omitempty"`                                         // the revocation's reason, as its statement gives it
	SignedType      uint32 `protobuf:"varint,10,opt,name=signed_type,json=signedType,proto3" json:"signed_type,omitempty"`              // §6.11's SignedType of the statement that raised it, such as SidecarAdmit
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *MembershipBody) Reset() {
	*x = MembershipBody{}
	mi := &file_protocol_record_proto_msgTypes[40]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *MembershipBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MembershipBody) ProtoMessage() {}

func (x *MembershipBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[40]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MembershipBody.ProtoReflect.Descriptor instead.
func (*MembershipBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{40}
}

func (x *MembershipBody) GetEvent() uint32 {
	if x != nil {
		return x.Event
	}
	return 0
}

func (x *MembershipBody) GetMemberId() []byte {
	if x != nil {
		return x.MemberId
	}
	return nil
}

func (x *MembershipBody) GetSidecarId() []byte {
	if x != nil {
		return x.SidecarId
	}
	return nil
}

func (x *MembershipBody) GetGroupId() []byte {
	if x != nil {
		return x.GroupId
	}
	return nil
}

func (x *MembershipBody) GetAuthPosition() uint64 {
	if x != nil {
		return x.AuthPosition
	}
	return 0
}

func (x *MembershipBody) GetStatementSha256() []byte {
	if x != nil {
		return x.StatementSha256
	}
	return nil
}

func (x *MembershipBody) GetEvidence() uint32 {
	if x != nil {
		return x.Evidence
	}
	return 0
}

func (x *MembershipBody) GetAssertion() []byte {
	if x != nil {
		return x.Assertion
	}
	return nil
}

func (x *MembershipBody) GetReason() uint32 {
	if x != nil {
		return x.Reason
	}
	return 0
}

func (x *MembershipBody) GetSignedType() uint32 {
	if x != nil {
		return x.SignedType
	}
	return 0
}

type KeyBody struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	Event           uint32                 `protobuf:"varint,1,opt,name=event,proto3" json:"event,omitempty"` // 1 key_changed
	GroupId         []byte                 `protobuf:"bytes,2,opt,name=group_id,json=groupId,proto3" json:"group_id,omitempty"`
	Generation      uint64                 `protobuf:"varint,3,opt,name=generation,proto3" json:"generation,omitempty"`
	Cause           uint32                 `protobuf:"varint,4,opt,name=cause,proto3" json:"cause,omitempty"` // a rotation: §10.5's GenRotate cause
	KeyId           []byte                 `protobuf:"bytes,5,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	AuthPosition    uint64                 `protobuf:"varint,6,opt,name=auth_position,json=authPosition,proto3" json:"auth_position,omitempty"`
	StatementSha256 []byte                 `protobuf:"bytes,7,opt,name=statement_sha256,json=statementSha256,proto3" json:"statement_sha256,omitempty"`
	SignedType      uint32                 `protobuf:"varint,8,opt,name=signed_type,json=signedType,proto3" json:"signed_type,omitempty"` // §6.11's SignedType: KeyRegister, KeyRevoke, RecoveryBind or
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *KeyBody) Reset() {
	*x = KeyBody{}
	mi := &file_protocol_record_proto_msgTypes[41]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *KeyBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KeyBody) ProtoMessage() {}

func (x *KeyBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[41]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KeyBody.ProtoReflect.Descriptor instead.
func (*KeyBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{41}
}

func (x *KeyBody) GetEvent() uint32 {
	if x != nil {
		return x.Event
	}
	return 0
}

func (x *KeyBody) GetGroupId() []byte {
	if x != nil {
		return x.GroupId
	}
	return nil
}

func (x *KeyBody) GetGeneration() uint64 {
	if x != nil {
		return x.Generation
	}
	return 0
}

func (x *KeyBody) GetCause() uint32 {
	if x != nil {
		return x.Cause
	}
	return 0
}

func (x *KeyBody) GetKeyId() []byte {
	if x != nil {
		return x.KeyId
	}
	return nil
}

func (x *KeyBody) GetAuthPosition() uint64 {
	if x != nil {
		return x.AuthPosition
	}
	return 0
}

func (x *KeyBody) GetStatementSha256() []byte {
	if x != nil {
		return x.StatementSha256
	}
	return nil
}

func (x *KeyBody) GetSignedType() uint32 {
	if x != nil {
		return x.SignedType
	}
	return 0
}

type ReadBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ObjectIds     [][]byte               `protobuf:"bytes,1,rep,name=object_ids,json=objectIds,proto3" json:"object_ids,omitempty"`   // <= 64: a 16 B entry_id, or a 32 B index file's content_sha256 (§11.14)
	Purpose       uint32                 `protobuf:"varint,2,opt,name=purpose,proto3" json:"purpose,omitempty"`                       // 1 read, 2 search, 3 export, 4 disclosure
	ReadLogId     []byte                 `protobuf:"bytes,3,opt,name=read_log_id,json=readLogId,proto3" json:"read_log_id,omitempty"` // in T: the log read; else empty
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ReadBody) Reset() {
	*x = ReadBody{}
	mi := &file_protocol_record_proto_msgTypes[42]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ReadBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReadBody) ProtoMessage() {}

func (x *ReadBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[42]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReadBody.ProtoReflect.Descriptor instead.
func (*ReadBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{42}
}

func (x *ReadBody) GetObjectIds() [][]byte {
	if x != nil {
		return x.ObjectIds
	}
	return nil
}

func (x *ReadBody) GetPurpose() uint32 {
	if x != nil {
		return x.Purpose
	}
	return 0
}

func (x *ReadBody) GetReadLogId() []byte {
	if x != nil {
		return x.ReadLogId
	}
	return nil
}

type ErasureBody struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	ErasureId       []byte                 `protobuf:"bytes,1,opt,name=erasure_id,json=erasureId,proto3" json:"erasure_id,omitempty"`                   // §11.12's id; its ERASE and CLOSURE notes name it
	EntryIds        [][]byte               `protobuf:"bytes,2,rep,name=entry_ids,json=entryIds,proto3" json:"entry_ids,omitempty"`                      // <= 1,024; a larger erasure writes several
	Reason          uint32                 `protobuf:"varint,3,opt,name=reason,proto3" json:"reason,omitempty"`                                         // 1 person, 2 retention, 3 moderation, 4 revocation
	RequestId       []byte                 `protobuf:"bytes,4,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`                   // reason 4: the DirectoryErasureRequest
	AnnouncementIds [][]byte               `protobuf:"bytes,5,rep,name=announcement_ids,json=announcementIds,proto3" json:"announcement_ids,omitempty"` // reason 3 (QD-1148): the 16 B announcement ids a moderation took off a
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *ErasureBody) Reset() {
	*x = ErasureBody{}
	mi := &file_protocol_record_proto_msgTypes[43]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ErasureBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ErasureBody) ProtoMessage() {}

func (x *ErasureBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[43]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ErasureBody.ProtoReflect.Descriptor instead.
func (*ErasureBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{43}
}

func (x *ErasureBody) GetErasureId() []byte {
	if x != nil {
		return x.ErasureId
	}
	return nil
}

func (x *ErasureBody) GetEntryIds() [][]byte {
	if x != nil {
		return x.EntryIds
	}
	return nil
}

func (x *ErasureBody) GetReason() uint32 {
	if x != nil {
		return x.Reason
	}
	return 0
}

func (x *ErasureBody) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *ErasureBody) GetAnnouncementIds() [][]byte {
	if x != nil {
		return x.AnnouncementIds
	}
	return nil
}

type InventoryBody struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	SponsorMemberId []byte                 `protobuf:"bytes,1,opt,name=sponsor_member_id,json=sponsorMemberId,proto3" json:"sponsor_member_id,omitempty"` // the member, or a tagged sidecar's sponsor
	Day             uint32                 `protobuf:"varint,2,opt,name=day,proto3" json:"day,omitempty"`                                                 // days since 1970-01-01, UTC
	CredentialRef   []byte                 `protobuf:"bytes,3,opt,name=credential_ref,json=credentialRef,proto3" json:"credential_ref,omitempty"`         // a delegation_id or auth key id; never a value (I-7)
	Agents          []*InventoryAgent      `protobuf:"bytes,4,rep,name=agents,proto3" json:"agents,omitempty"`                                            // <= 64
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *InventoryBody) Reset() {
	*x = InventoryBody{}
	mi := &file_protocol_record_proto_msgTypes[44]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InventoryBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InventoryBody) ProtoMessage() {}

func (x *InventoryBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[44]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InventoryBody.ProtoReflect.Descriptor instead.
func (*InventoryBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{44}
}

func (x *InventoryBody) GetSponsorMemberId() []byte {
	if x != nil {
		return x.SponsorMemberId
	}
	return nil
}

func (x *InventoryBody) GetDay() uint32 {
	if x != nil {
		return x.Day
	}
	return 0
}

func (x *InventoryBody) GetCredentialRef() []byte {
	if x != nil {
		return x.CredentialRef
	}
	return nil
}

func (x *InventoryBody) GetAgents() []*InventoryAgent {
	if x != nil {
		return x.Agents
	}
	return nil
}

type InventoryAgent struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	AgentId         []byte                 `protobuf:"bytes,1,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
	AgentLabel      string                 `protobuf:"bytes,2,opt,name=agent_label,json=agentLabel,proto3" json:"agent_label,omitempty"`
	AgentSource     uint32                 `protobuf:"varint,3,opt,name=agent_source,json=agentSource,proto3" json:"agent_source,omitempty"`
	Harnesses       []string               `protobuf:"bytes,4,rep,name=harnesses,proto3" json:"harnesses,omitempty"` // <= 8, each name/version
	Models          []string               `protobuf:"bytes,5,rep,name=models,proto3" json:"models,omitempty"`       // <= 16
	RepoIds         [][]byte               `protobuf:"bytes,6,rep,name=repo_ids,json=repoIds,proto3" json:"repo_ids,omitempty"`
	Projects        []string               `protobuf:"bytes,7,rep,name=projects,proto3" json:"projects,omitempty"` // <= 64 each; a private repo's id, with no project
	Runs            uint32                 `protobuf:"varint,8,opt,name=runs,proto3" json:"runs,omitempty"`
	FirstSeenMillis int64                  `protobuf:"varint,9,opt,name=first_seen_millis,json=firstSeenMillis,proto3" json:"first_seen_millis,omitempty"`
	LastSeenMillis  int64                  `protobuf:"varint,10,opt,name=last_seen_millis,json=lastSeenMillis,proto3" json:"last_seen_millis,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *InventoryAgent) Reset() {
	*x = InventoryAgent{}
	mi := &file_protocol_record_proto_msgTypes[45]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InventoryAgent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InventoryAgent) ProtoMessage() {}

func (x *InventoryAgent) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[45]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InventoryAgent.ProtoReflect.Descriptor instead.
func (*InventoryAgent) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{45}
}

func (x *InventoryAgent) GetAgentId() []byte {
	if x != nil {
		return x.AgentId
	}
	return nil
}

func (x *InventoryAgent) GetAgentLabel() string {
	if x != nil {
		return x.AgentLabel
	}
	return ""
}

func (x *InventoryAgent) GetAgentSource() uint32 {
	if x != nil {
		return x.AgentSource
	}
	return 0
}

func (x *InventoryAgent) GetHarnesses() []string {
	if x != nil {
		return x.Harnesses
	}
	return nil
}

func (x *InventoryAgent) GetModels() []string {
	if x != nil {
		return x.Models
	}
	return nil
}

func (x *InventoryAgent) GetRepoIds() [][]byte {
	if x != nil {
		return x.RepoIds
	}
	return nil
}

func (x *InventoryAgent) GetProjects() []string {
	if x != nil {
		return x.Projects
	}
	return nil
}

func (x *InventoryAgent) GetRuns() uint32 {
	if x != nil {
		return x.Runs
	}
	return 0
}

func (x *InventoryAgent) GetFirstSeenMillis() int64 {
	if x != nil {
		return x.FirstSeenMillis
	}
	return 0
}

func (x *InventoryAgent) GetLastSeenMillis() int64 {
	if x != nil {
		return x.LastSeenMillis
	}
	return 0
}

type AgentSignedBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Body          []byte                 `protobuf:"bytes,1,opt,name=body,proto3" json:"body,omitempty"`
	AgentId       []byte                 `protobuf:"bytes,2,opt,name=agent_id,json=agentId,proto3" json:"agent_id,omitempty"`
	KeyId         []byte                 `protobuf:"bytes,3,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Signature     []byte                 `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
	AgentCert     []byte                 `protobuf:"bytes,5,opt,name=agent_cert,json=agentCert,proto3" json:"agent_cert,omitempty"` // QD-159: the Signed AgentCert the subkey's signature checks under, by
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AgentSignedBody) Reset() {
	*x = AgentSignedBody{}
	mi := &file_protocol_record_proto_msgTypes[46]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AgentSignedBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AgentSignedBody) ProtoMessage() {}

func (x *AgentSignedBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[46]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AgentSignedBody.ProtoReflect.Descriptor instead.
func (*AgentSignedBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{46}
}

func (x *AgentSignedBody) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

func (x *AgentSignedBody) GetAgentId() []byte {
	if x != nil {
		return x.AgentId
	}
	return nil
}

func (x *AgentSignedBody) GetKeyId() []byte {
	if x != nil {
		return x.KeyId
	}
	return nil
}

func (x *AgentSignedBody) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *AgentSignedBody) GetAgentCert() []byte {
	if x != nil {
		return x.AgentCert
	}
	return nil
}

type Opening struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Header        []byte                 `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"` // RecordEntry.header, the whole Signed, as stored
	Salt          []byte                 `protobuf:"bytes,2,opt,name=salt,proto3" json:"salt,omitempty"`
	Body          []byte                 `protobuf:"bytes,3,opt,name=body,proto3" json:"body,omitempty"`        // both empty: the header alone
	Version       uint32                 `protobuf:"varint,4,opt,name=version,proto3" json:"version,omitempty"` // QD-864: RecordEntry.version of the entry this was made from, absent
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Opening) Reset() {
	*x = Opening{}
	mi := &file_protocol_record_proto_msgTypes[47]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Opening) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Opening) ProtoMessage() {}

func (x *Opening) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[47]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Opening.ProtoReflect.Descriptor instead.
func (*Opening) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{47}
}

func (x *Opening) GetHeader() []byte {
	if x != nil {
		return x.Header
	}
	return nil
}

func (x *Opening) GetSalt() []byte {
	if x != nil {
		return x.Salt
	}
	return nil
}

func (x *Opening) GetBody() []byte {
	if x != nil {
		return x.Body
	}
	return nil
}

func (x *Opening) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

type CopyBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Entries       []*Opening             `protobuf:"bytes,1,rep,name=entries,proto3" json:"entries,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CopyBody) Reset() {
	*x = CopyBody{}
	mi := &file_protocol_record_proto_msgTypes[48]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CopyBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CopyBody) ProtoMessage() {}

func (x *CopyBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[48]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CopyBody.ProtoReflect.Descriptor instead.
func (*CopyBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{48}
}

func (x *CopyBody) GetEntries() []*Opening {
	if x != nil {
		return x.Entries
	}
	return nil
}

// the decisions a directory requester's notice names (§16.11)
type TranscriptBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	FirstLine     uint64                 `protobuf:"varint,1,opt,name=first_line,json=firstLine,proto3" json:"first_line,omitempty"`
	LineCount     uint32                 `protobuf:"varint,2,opt,name=line_count,json=lineCount,proto3" json:"line_count,omitempty"`
	Lines         []byte                 `protobuf:"bytes,3,opt,name=lines,proto3" json:"lines,omitempty"` // the harness's JSONL lines after redaction, <= 1 MiB
	Truncated     bool                   `protobuf:"varint,4,opt,name=truncated,proto3" json:"truncated,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TranscriptBody) Reset() {
	*x = TranscriptBody{}
	mi := &file_protocol_record_proto_msgTypes[49]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TranscriptBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TranscriptBody) ProtoMessage() {}

func (x *TranscriptBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[49]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TranscriptBody.ProtoReflect.Descriptor instead.
func (*TranscriptBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{49}
}

func (x *TranscriptBody) GetFirstLine() uint64 {
	if x != nil {
		return x.FirstLine
	}
	return 0
}

func (x *TranscriptBody) GetLineCount() uint32 {
	if x != nil {
		return x.LineCount
	}
	return 0
}

func (x *TranscriptBody) GetLines() []byte {
	if x != nil {
		return x.Lines
	}
	return nil
}

func (x *TranscriptBody) GetTruncated() bool {
	if x != nil {
		return x.Truncated
	}
	return false
}

type ToolCallBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	ToolName      string                 `protobuf:"bytes,1,opt,name=tool_name,json=toolName,proto3" json:"tool_name,omitempty"`
	ToolUseId     string                 `protobuf:"bytes,2,opt,name=tool_use_id,json=toolUseId,proto3" json:"tool_use_id,omitempty"`
	ToolClass     uint32                 `protobuf:"varint,3,opt,name=tool_class,json=toolClass,proto3" json:"tool_class,omitempty"` // tool_class as PermissionBody
	Input         []byte                 `protobuf:"bytes,4,opt,name=input,proto3" json:"input,omitempty"`
	Output        []byte                 `protobuf:"bytes,5,opt,name=output,proto3" json:"output,omitempty"` // after redaction, <= 1 MiB together (§16.7)
	StartedMillis int64                  `protobuf:"varint,6,opt,name=started_millis,json=startedMillis,proto3" json:"started_millis,omitempty"`
	EndedMillis   int64                  `protobuf:"varint,7,opt,name=ended_millis,json=endedMillis,proto3" json:"ended_millis,omitempty"`
	ExitCode      int32                  `protobuf:"varint,8,opt,name=exit_code,json=exitCode,proto3" json:"exit_code,omitempty"`
	Paths         []string               `protobuf:"bytes,9,rep,name=paths,proto3" json:"paths,omitempty"` // <= 256: the paths the call names
	Truncated     bool                   `protobuf:"varint,10,opt,name=truncated,proto3" json:"truncated,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ToolCallBody) Reset() {
	*x = ToolCallBody{}
	mi := &file_protocol_record_proto_msgTypes[50]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ToolCallBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ToolCallBody) ProtoMessage() {}

func (x *ToolCallBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[50]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ToolCallBody.ProtoReflect.Descriptor instead.
func (*ToolCallBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{50}
}

func (x *ToolCallBody) GetToolName() string {
	if x != nil {
		return x.ToolName
	}
	return ""
}

func (x *ToolCallBody) GetToolUseId() string {
	if x != nil {
		return x.ToolUseId
	}
	return ""
}

func (x *ToolCallBody) GetToolClass() uint32 {
	if x != nil {
		return x.ToolClass
	}
	return 0
}

func (x *ToolCallBody) GetInput() []byte {
	if x != nil {
		return x.Input
	}
	return nil
}

func (x *ToolCallBody) GetOutput() []byte {
	if x != nil {
		return x.Output
	}
	return nil
}

func (x *ToolCallBody) GetStartedMillis() int64 {
	if x != nil {
		return x.StartedMillis
	}
	return 0
}

func (x *ToolCallBody) GetEndedMillis() int64 {
	if x != nil {
		return x.EndedMillis
	}
	return 0
}

func (x *ToolCallBody) GetExitCode() int32 {
	if x != nil {
		return x.ExitCode
	}
	return 0
}

func (x *ToolCallBody) GetPaths() []string {
	if x != nil {
		return x.Paths
	}
	return nil
}

func (x *ToolCallBody) GetTruncated() bool {
	if x != nil {
		return x.Truncated
	}
	return false
}

type HookEventBody struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	Event           string                 `protobuf:"bytes,1,opt,name=event,proto3" json:"event,omitempty"` // the harness's event name
	Payload         []byte                 `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	ArgumentsSha256 []byte                 `protobuf:"bytes,3,opt,name=arguments_sha256,json=argumentsSha256,proto3" json:"arguments_sha256,omitempty"` // §16.6's hash, for harness_ok's match
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *HookEventBody) Reset() {
	*x = HookEventBody{}
	mi := &file_protocol_record_proto_msgTypes[51]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HookEventBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HookEventBody) ProtoMessage() {}

func (x *HookEventBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[51]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HookEventBody.ProtoReflect.Descriptor instead.
func (*HookEventBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{51}
}

func (x *HookEventBody) GetEvent() string {
	if x != nil {
		return x.Event
	}
	return ""
}

func (x *HookEventBody) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *HookEventBody) GetArgumentsSha256() []byte {
	if x != nil {
		return x.ArgumentsSha256
	}
	return nil
}

type FileEventBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Path          string                 `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	Op            uint32                 `protobuf:"varint,2,opt,name=op,proto3" json:"op,omitempty"` // 1 create, 2 write, 3 delete, 4 rename
	AfterSha256   []byte                 `protobuf:"bytes,3,opt,name=after_sha256,json=afterSha256,proto3" json:"after_sha256,omitempty"`
	Millis        int64                  `protobuf:"varint,4,opt,name=millis,proto3" json:"millis,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FileEventBody) Reset() {
	*x = FileEventBody{}
	mi := &file_protocol_record_proto_msgTypes[52]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FileEventBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FileEventBody) ProtoMessage() {}

func (x *FileEventBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[52]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FileEventBody.ProtoReflect.Descriptor instead.
func (*FileEventBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{52}
}

func (x *FileEventBody) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *FileEventBody) GetOp() uint32 {
	if x != nil {
		return x.Op
	}
	return 0
}

func (x *FileEventBody) GetAfterSha256() []byte {
	if x != nil {
		return x.AfterSha256
	}
	return nil
}

func (x *FileEventBody) GetMillis() int64 {
	if x != nil {
		return x.Millis
	}
	return 0
}

type BlobBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Path          string                 `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	Content       []byte                 `protobuf:"bytes,2,opt,name=content,proto3" json:"content,omitempty"` // after redaction, <= 8 MiB (§16.7)
	Sha256        []byte                 `protobuf:"bytes,3,opt,name=sha256,proto3" json:"sha256,omitempty"`   // the bytes as captured, before redaction: the ledger's after_sha256
	Redacted      bool                   `protobuf:"varint,4,opt,name=redacted,proto3" json:"redacted,omitempty"`
	Size          uint64                 `protobuf:"varint,5,opt,name=size,proto3" json:"size,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BlobBody) Reset() {
	*x = BlobBody{}
	mi := &file_protocol_record_proto_msgTypes[53]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BlobBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlobBody) ProtoMessage() {}

func (x *BlobBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[53]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlobBody.ProtoReflect.Descriptor instead.
func (*BlobBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{53}
}

func (x *BlobBody) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *BlobBody) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

func (x *BlobBody) GetSha256() []byte {
	if x != nil {
		return x.Sha256
	}
	return nil
}

func (x *BlobBody) GetRedacted() bool {
	if x != nil {
		return x.Redacted
	}
	return false
}

func (x *BlobBody) GetSize() uint64 {
	if x != nil {
		return x.Size
	}
	return 0
}

// RECORD.md section 6.5: an R log's scope (M6).
type LedgerScopeBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RepoIds       [][]byte               `protobuf:"bytes,1,rep,name=repo_ids,json=repoIds,proto3" json:"repo_ids,omitempty"` // <= 256
	Projects      []string               `protobuf:"bytes,2,rep,name=projects,proto3" json:"projects,omitempty"`              // <= 256, §16.11's project keys
	Kinds         []uint32               `protobuf:"varint,3,rep,packed,name=kinds,proto3" json:"kinds,omitempty"`            // the kinds copied here, from context, change, the approval family,
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LedgerScopeBody) Reset() {
	*x = LedgerScopeBody{}
	mi := &file_protocol_record_proto_msgTypes[54]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LedgerScopeBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LedgerScopeBody) ProtoMessage() {}

func (x *LedgerScopeBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[54]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LedgerScopeBody.ProtoReflect.Descriptor instead.
func (*LedgerScopeBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{54}
}

func (x *LedgerScopeBody) GetRepoIds() [][]byte {
	if x != nil {
		return x.RepoIds
	}
	return nil
}

func (x *LedgerScopeBody) GetProjects() []string {
	if x != nil {
		return x.Projects
	}
	return nil
}

func (x *LedgerScopeBody) GetKinds() []uint32 {
	if x != nil {
		return x.Kinds
	}
	return nil
}

// RECORD.md section 10.1: the verifiable log's settings and checkpoints (M6).
type LogSettingsBody struct {
	state                 protoimpl.MessageState `protogen:"open.v1"`
	Origin                string                 `protobuf:"bytes,1,opt,name=origin,proto3" json:"origin,omitempty"`                                                              // ur.io/recurd/log/<log_id hex>: a name, never dialed
	CheckpointerSidecarId []byte                 `protobuf:"bytes,2,opt,name=checkpointer_sidecar_id,json=checkpointerSidecarId,proto3" json:"checkpointer_sidecar_id,omitempty"` // a device with rw on the log: an admin's device or indexer
	NotePublicKey         []byte                 `protobuf:"bytes,3,opt,name=note_public_key,json=notePublicKey,proto3" json:"note_public_key,omitempty"`                         // its Ed25519 log key, 32 B
	IntervalSeconds       uint32                 `protobuf:"varint,4,opt,name=interval_seconds,json=intervalSeconds,proto3" json:"interval_seconds,omitempty"`                    // 3,600 by default; 300 to 86,400; 0 turns the log off
	Witnesses             []*LogWitness          `protobuf:"bytes,5,rep,name=witnesses,proto3" json:"witnesses,omitempty"`                                                        // <= 8, each called by section 10.2's witness step
	FromBatch             uint64                 `protobuf:"varint,6,opt,name=from_batch,json=fromBatch,proto3" json:"from_batch,omitempty"`                                      // the first batch this entry governs
	unknownFields         protoimpl.UnknownFields
	sizeCache             protoimpl.SizeCache
}

func (x *LogSettingsBody) Reset() {
	*x = LogSettingsBody{}
	mi := &file_protocol_record_proto_msgTypes[55]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogSettingsBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogSettingsBody) ProtoMessage() {}

func (x *LogSettingsBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[55]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogSettingsBody.ProtoReflect.Descriptor instead.
func (*LogSettingsBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{55}
}

func (x *LogSettingsBody) GetOrigin() string {
	if x != nil {
		return x.Origin
	}
	return ""
}

func (x *LogSettingsBody) GetCheckpointerSidecarId() []byte {
	if x != nil {
		return x.CheckpointerSidecarId
	}
	return nil
}

func (x *LogSettingsBody) GetNotePublicKey() []byte {
	if x != nil {
		return x.NotePublicKey
	}
	return nil
}

func (x *LogSettingsBody) GetIntervalSeconds() uint32 {
	if x != nil {
		return x.IntervalSeconds
	}
	return 0
}

func (x *LogSettingsBody) GetWitnesses() []*LogWitness {
	if x != nil {
		return x.Witnesses
	}
	return nil
}

func (x *LogSettingsBody) GetFromBatch() uint64 {
	if x != nil {
		return x.FromBatch
	}
	return 0
}

type LogWitness struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"` // its cosigner name
	Url           string                 `protobuf:"bytes,2,opt,name=url,proto3" json:"url,omitempty"`   // its submission prefix, https only (c2sp.org/tlog-witness)
	Vkey          string                 `protobuf:"bytes,3,opt,name=vkey,proto3" json:"vkey,omitempty"` // its verifier key
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogWitness) Reset() {
	*x = LogWitness{}
	mi := &file_protocol_record_proto_msgTypes[56]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogWitness) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogWitness) ProtoMessage() {}

func (x *LogWitness) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[56]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogWitness.ProtoReflect.Descriptor instead.
func (*LogWitness) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{56}
}

func (x *LogWitness) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *LogWitness) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

func (x *LogWitness) GetVkey() string {
	if x != nil {
		return x.Vkey
	}
	return ""
}

type LogCheckpointBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Batch         uint64                 `protobuf:"varint,1,opt,name=batch,proto3" json:"batch,omitempty"`                             // from 1, +1 each
	FirstIndex    uint64                 `protobuf:"varint,2,opt,name=first_index,json=firstIndex,proto3" json:"first_index,omitempty"` // the tree index of this batch's first leaf
	Frontier      []*LogFrontier         `protobuf:"bytes,3,rep,name=frontier,proto3" json:"frontier,omitempty"`                        // sorted by ref_id
	Leaves        []byte                 `protobuf:"bytes,4,opt,name=leaves,proto3" json:"leaves,omitempty"`                            // this batch's leaves, 32 B each, in order
	Note          []byte                 `protobuf:"bytes,5,opt,name=note,proto3" json:"note,omitempty"`                                // the signed checkpoint, by the log key alone (section 10.2's steps)
	Cosigned      []*LogCosigned         `protobuf:"bytes,6,rep,name=cosigned,proto3" json:"cosigned,omitempty"`                        // the cosignature lines got since the last entry
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogCheckpointBody) Reset() {
	*x = LogCheckpointBody{}
	mi := &file_protocol_record_proto_msgTypes[57]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogCheckpointBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogCheckpointBody) ProtoMessage() {}

func (x *LogCheckpointBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[57]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogCheckpointBody.ProtoReflect.Descriptor instead.
func (*LogCheckpointBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{57}
}

func (x *LogCheckpointBody) GetBatch() uint64 {
	if x != nil {
		return x.Batch
	}
	return 0
}

func (x *LogCheckpointBody) GetFirstIndex() uint64 {
	if x != nil {
		return x.FirstIndex
	}
	return 0
}

func (x *LogCheckpointBody) GetFrontier() []*LogFrontier {
	if x != nil {
		return x.Frontier
	}
	return nil
}

func (x *LogCheckpointBody) GetLeaves() []byte {
	if x != nil {
		return x.Leaves
	}
	return nil
}

func (x *LogCheckpointBody) GetNote() []byte {
	if x != nil {
		return x.Note
	}
	return nil
}

func (x *LogCheckpointBody) GetCosigned() []*LogCosigned {
	if x != nil {
		return x.Cosigned
	}
	return nil
}

type LogFrontier struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RefId         []byte                 `protobuf:"bytes,1,opt,name=ref_id,json=refId,proto3" json:"ref_id,omitempty"`
	Version       uint64                 `protobuf:"varint,2,opt,name=version,proto3" json:"version,omitempty"`
	Chain         []byte                 `protobuf:"bytes,3,opt,name=chain,proto3" json:"chain,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogFrontier) Reset() {
	*x = LogFrontier{}
	mi := &file_protocol_record_proto_msgTypes[58]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogFrontier) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogFrontier) ProtoMessage() {}

func (x *LogFrontier) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[58]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogFrontier.ProtoReflect.Descriptor instead.
func (*LogFrontier) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{58}
}

func (x *LogFrontier) GetRefId() []byte {
	if x != nil {
		return x.RefId
	}
	return nil
}

func (x *LogFrontier) GetVersion() uint64 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *LogFrontier) GetChain() []byte {
	if x != nil {
		return x.Chain
	}
	return nil
}

type LogCosigned struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Batch         uint64                 `protobuf:"varint,1,opt,name=batch,proto3" json:"batch,omitempty"` // the batch whose note these lines cosign
	Lines         []byte                 `protobuf:"bytes,2,opt,name=lines,proto3" json:"lines,omitempty"`  // each witness's signature lines, as it returned them
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *LogCosigned) Reset() {
	*x = LogCosigned{}
	mi := &file_protocol_record_proto_msgTypes[59]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogCosigned) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogCosigned) ProtoMessage() {}

func (x *LogCosigned) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[59]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LogCosigned.ProtoReflect.Descriptor instead.
func (*LogCosigned) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{59}
}

func (x *LogCosigned) GetBatch() uint64 {
	if x != nil {
		return x.Batch
	}
	return 0
}

func (x *LogCosigned) GetLines() []byte {
	if x != nil {
		return x.Lines
	}
	return nil
}

// RECORD.md section 11: disclosure packets and the log's record of them (M6).
type DisclosurePacket struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Version       uint32                 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"` // 1
	LogId         []byte                 `protobuf:"bytes,2,opt,name=log_id,json=logId,proto3" json:"log_id,omitempty"`
	Origin        string                 `protobuf:"bytes,3,opt,name=origin,proto3" json:"origin,omitempty"`
	CreatedMillis int64                  `protobuf:"varint,4,opt,name=created_millis,json=createdMillis,proto3" json:"created_millis,omitempty"`
	Entries       []*DisclosedEntry      `protobuf:"bytes,5,rep,name=entries,proto3" json:"entries,omitempty"`         // <= 1,024
	Checkpoints   [][]byte               `protobuf:"bytes,6,rep,name=checkpoints,proto3" json:"checkpoints,omitempty"` // signed notes, each with the lines of its cosigned rows appended
	Keys          []*DisclosedKey        `protobuf:"bytes,7,rep,name=keys,proto3" json:"keys,omitempty"`
	Purpose       string                 `protobuf:"bytes,8,opt,name=purpose,proto3" json:"purpose,omitempty"` // <= 512 B, as the person typed it
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DisclosurePacket) Reset() {
	*x = DisclosurePacket{}
	mi := &file_protocol_record_proto_msgTypes[60]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DisclosurePacket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisclosurePacket) ProtoMessage() {}

func (x *DisclosurePacket) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[60]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisclosurePacket.ProtoReflect.Descriptor instead.
func (*DisclosurePacket) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{60}
}

func (x *DisclosurePacket) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *DisclosurePacket) GetLogId() []byte {
	if x != nil {
		return x.LogId
	}
	return nil
}

func (x *DisclosurePacket) GetOrigin() string {
	if x != nil {
		return x.Origin
	}
	return ""
}

func (x *DisclosurePacket) GetCreatedMillis() int64 {
	if x != nil {
		return x.CreatedMillis
	}
	return 0
}

func (x *DisclosurePacket) GetEntries() []*DisclosedEntry {
	if x != nil {
		return x.Entries
	}
	return nil
}

func (x *DisclosurePacket) GetCheckpoints() [][]byte {
	if x != nil {
		return x.Checkpoints
	}
	return nil
}

func (x *DisclosurePacket) GetKeys() []*DisclosedKey {
	if x != nil {
		return x.Keys
	}
	return nil
}

func (x *DisclosurePacket) GetPurpose() string {
	if x != nil {
		return x.Purpose
	}
	return ""
}

type DisclosedEntry struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Opening       *Opening               `protobuf:"bytes,1,opt,name=opening,proto3" json:"opening,omitempty"` // section 6.4; salt and body empty for a header alone
	LeafIndex     uint64                 `protobuf:"varint,2,opt,name=leaf_index,json=leafIndex,proto3" json:"leaf_index,omitempty"`
	Checkpoint    uint32                 `protobuf:"varint,3,opt,name=checkpoint,proto3" json:"checkpoint,omitempty"`                           // checkpoint: an index into checkpoints
	InclusionPath [][]byte               `protobuf:"bytes,4,rep,name=inclusion_path,json=inclusionPath,proto3" json:"inclusion_path,omitempty"` // RFC 9162 §2.1.3, <= 63 hashes
	Content       []*Opening             `protobuf:"bytes,5,rep,name=content,proto3" json:"content,omitempty"`                                  // the author's openings of its ContentRefs, if given
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DisclosedEntry) Reset() {
	*x = DisclosedEntry{}
	mi := &file_protocol_record_proto_msgTypes[61]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DisclosedEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisclosedEntry) ProtoMessage() {}

func (x *DisclosedEntry) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[61]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisclosedEntry.ProtoReflect.Descriptor instead.
func (*DisclosedEntry) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{61}
}

func (x *DisclosedEntry) GetOpening() *Opening {
	if x != nil {
		return x.Opening
	}
	return nil
}

func (x *DisclosedEntry) GetLeafIndex() uint64 {
	if x != nil {
		return x.LeafIndex
	}
	return 0
}

func (x *DisclosedEntry) GetCheckpoint() uint32 {
	if x != nil {
		return x.Checkpoint
	}
	return 0
}

func (x *DisclosedEntry) GetInclusionPath() [][]byte {
	if x != nil {
		return x.InclusionPath
	}
	return nil
}

func (x *DisclosedEntry) GetContent() []*Opening {
	if x != nil {
		return x.Content
	}
	return nil
}

type DisclosedKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	KeyId         []byte                 `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	SidecarId     []byte                 `protobuf:"bytes,2,opt,name=sidecar_id,json=sidecarId,proto3" json:"sidecar_id,omitempty"`
	Alg           uint32                 `protobuf:"varint,3,opt,name=alg,proto3" json:"alg,omitempty"`
	PublicKey     []byte                 `protobuf:"bytes,4,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	Label         string                 `protobuf:"bytes,5,opt,name=label,proto3" json:"label,omitempty"` // the person or device, as the team states it
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DisclosedKey) Reset() {
	*x = DisclosedKey{}
	mi := &file_protocol_record_proto_msgTypes[62]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DisclosedKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisclosedKey) ProtoMessage() {}

func (x *DisclosedKey) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[62]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisclosedKey.ProtoReflect.Descriptor instead.
func (*DisclosedKey) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{62}
}

func (x *DisclosedKey) GetKeyId() []byte {
	if x != nil {
		return x.KeyId
	}
	return nil
}

func (x *DisclosedKey) GetSidecarId() []byte {
	if x != nil {
		return x.SidecarId
	}
	return nil
}

func (x *DisclosedKey) GetAlg() uint32 {
	if x != nil {
		return x.Alg
	}
	return 0
}

func (x *DisclosedKey) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *DisclosedKey) GetLabel() string {
	if x != nil {
		return x.Label
	}
	return ""
}

type DisclosureBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Act           uint32                 `protobuf:"varint,1,opt,name=act,proto3" json:"act,omitempty"`                                      // 1 packet, 2 opening, 3 export
	PacketSha256  []byte                 `protobuf:"bytes,2,opt,name=packet_sha256,json=packetSha256,proto3" json:"packet_sha256,omitempty"` // acts 1, 2: the file's SHA-256
	EntryIds      [][]byte               `protobuf:"bytes,3,rep,name=entry_ids,json=entryIds,proto3" json:"entry_ids,omitempty"`             // acts 1, 2: <= 1,024
	Recipient     string                 `protobuf:"bytes,4,opt,name=recipient,proto3" json:"recipient,omitempty"`                           // <= 128 B (prose), as typed
	Purpose       string                 `protobuf:"bytes,5,opt,name=purpose,proto3" json:"purpose,omitempty"`                               // <= 512 B (prose)
	SinceMillis   int64                  `protobuf:"varint,6,opt,name=since_millis,json=sinceMillis,proto3" json:"since_millis,omitempty"`
	UntilMillis   int64                  `protobuf:"varint,7,opt,name=until_millis,json=untilMillis,proto3" json:"until_millis,omitempty"` // act 3: the range, 0 where none was given
	Format        uint32                 `protobuf:"varint,8,opt,name=format,proto3" json:"format,omitempty"`                              // act 3: 1 jsonl, 2 ocsf, 3 otel, 4 git (ur evs export)
	Bodies        bool                   `protobuf:"varint,9,opt,name=bodies,proto3" json:"bodies,omitempty"`                              // act 3: bodies left the log
	Kinds         []uint32               `protobuf:"varint,10,rep,packed,name=kinds,proto3" json:"kinds,omitempty"`                        // act 3: --kind's list, empty for all
	RunId         []byte                 `protobuf:"bytes,11,opt,name=run_id,json=runId,proto3" json:"run_id,omitempty"`                   // act 3: --run, else empty
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DisclosureBody) Reset() {
	*x = DisclosureBody{}
	mi := &file_protocol_record_proto_msgTypes[63]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DisclosureBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisclosureBody) ProtoMessage() {}

func (x *DisclosureBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[63]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisclosureBody.ProtoReflect.Descriptor instead.
func (*DisclosureBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{63}
}

func (x *DisclosureBody) GetAct() uint32 {
	if x != nil {
		return x.Act
	}
	return 0
}

func (x *DisclosureBody) GetPacketSha256() []byte {
	if x != nil {
		return x.PacketSha256
	}
	return nil
}

func (x *DisclosureBody) GetEntryIds() [][]byte {
	if x != nil {
		return x.EntryIds
	}
	return nil
}

func (x *DisclosureBody) GetRecipient() string {
	if x != nil {
		return x.Recipient
	}
	return ""
}

func (x *DisclosureBody) GetPurpose() string {
	if x != nil {
		return x.Purpose
	}
	return ""
}

func (x *DisclosureBody) GetSinceMillis() int64 {
	if x != nil {
		return x.SinceMillis
	}
	return 0
}

func (x *DisclosureBody) GetUntilMillis() int64 {
	if x != nil {
		return x.UntilMillis
	}
	return 0
}

func (x *DisclosureBody) GetFormat() uint32 {
	if x != nil {
		return x.Format
	}
	return 0
}

func (x *DisclosureBody) GetBodies() bool {
	if x != nil {
		return x.Bodies
	}
	return false
}

func (x *DisclosureBody) GetKinds() []uint32 {
	if x != nil {
		return x.Kinds
	}
	return nil
}

func (x *DisclosureBody) GetRunId() []byte {
	if x != nil {
		return x.RunId
	}
	return nil
}

// RECORD.md section 11: a person's statement about commits (M6).
type AttestationBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Statement     uint32                 `protobuf:"varint,1,opt,name=statement,proto3" json:"statement,omitempty"` // 1 reviewed, 2 tested, 3 approved
	Commits       []string               `protobuf:"bytes,2,rep,name=commits,proto3" json:"commits,omitempty"`      // <= 64 git oids
	RepoId        []byte                 `protobuf:"bytes,3,opt,name=repo_id,json=repoId,proto3" json:"repo_id,omitempty"`
	Note          string                 `protobuf:"bytes,4,opt,name=note,proto3" json:"note,omitempty"`     // note <= 512 B (prose)
	Sshsig        []byte                 `protobuf:"bytes,5,opt,name=sshsig,proto3" json:"sshsig,omitempty"` // section 5.1's attestation sshsig
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AttestationBody) Reset() {
	*x = AttestationBody{}
	mi := &file_protocol_record_proto_msgTypes[64]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AttestationBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttestationBody) ProtoMessage() {}

func (x *AttestationBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[64]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttestationBody.ProtoReflect.Descriptor instead.
func (*AttestationBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{64}
}

func (x *AttestationBody) GetStatement() uint32 {
	if x != nil {
		return x.Statement
	}
	return 0
}

func (x *AttestationBody) GetCommits() []string {
	if x != nil {
		return x.Commits
	}
	return nil
}

func (x *AttestationBody) GetRepoId() []byte {
	if x != nil {
		return x.RepoId
	}
	return nil
}

func (x *AttestationBody) GetNote() string {
	if x != nil {
		return x.Note
	}
	return ""
}

func (x *AttestationBody) GetSshsig() []byte {
	if x != nil {
		return x.Sshsig
	}
	return nil
}

// RECORD.md section 12: model receipts (M6).
type ModelManifest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Port          uint32                 `protobuf:"varint,1,opt,name=port,proto3" json:"port,omitempty"`                              // the local port: a forward's target_port
	ServedName    *ModelField            `protobuf:"bytes,2,opt,name=served_name,json=servedName,proto3" json:"served_name,omitempty"` // the name clients ask for
	Engine        *ModelField            `protobuf:"bytes,3,opt,name=engine,proto3" json:"engine,omitempty"`                           // vllm, sglang, ollama, llama.cpp or other
	EngineVersion *ModelField            `protobuf:"bytes,4,opt,name=engine_version,json=engineVersion,proto3" json:"engine_version,omitempty"`
	Quantization  *ModelField            `protobuf:"bytes,5,opt,name=quantization,proto3" json:"quantization,omitempty"`
	WeightsDigest *ModelField            `protobuf:"bytes,6,opt,name=weights_digest,json=weightsDigest,proto3" json:"weights_digest,omitempty"` // section 5.1's weights_digest, in lowercase hex
	WeightsBytes  uint64                 `protobuf:"varint,7,opt,name=weights_bytes,json=weightsBytes,proto3" json:"weights_bytes,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ModelManifest) Reset() {
	*x = ModelManifest{}
	mi := &file_protocol_record_proto_msgTypes[65]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ModelManifest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ModelManifest) ProtoMessage() {}

func (x *ModelManifest) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[65]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ModelManifest.ProtoReflect.Descriptor instead.
func (*ModelManifest) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{65}
}

func (x *ModelManifest) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *ModelManifest) GetServedName() *ModelField {
	if x != nil {
		return x.ServedName
	}
	return nil
}

func (x *ModelManifest) GetEngine() *ModelField {
	if x != nil {
		return x.Engine
	}
	return nil
}

func (x *ModelManifest) GetEngineVersion() *ModelField {
	if x != nil {
		return x.EngineVersion
	}
	return nil
}

func (x *ModelManifest) GetQuantization() *ModelField {
	if x != nil {
		return x.Quantization
	}
	return nil
}

func (x *ModelManifest) GetWeightsDigest() *ModelField {
	if x != nil {
		return x.WeightsDigest
	}
	return nil
}

func (x *ModelManifest) GetWeightsBytes() uint64 {
	if x != nil {
		return x.WeightsBytes
	}
	return 0
}

type ModelField struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Value         string                 `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`        // an identifier <= 128 B
	Evidence      uint32                 `protobuf:"varint,2,opt,name=evidence,proto3" json:"evidence,omitempty"` // section 12's evidence: 1 declared, 2 reported, 3 measured, 4 attested
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ModelField) Reset() {
	*x = ModelField{}
	mi := &file_protocol_record_proto_msgTypes[66]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ModelField) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ModelField) ProtoMessage() {}

func (x *ModelField) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[66]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ModelField.ProtoReflect.Descriptor instead.
func (*ModelField) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{66}
}

func (x *ModelField) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *ModelField) GetEvidence() uint32 {
	if x != nil {
		return x.Evidence
	}
	return 0
}

type ModelCallBody struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	Model            string                 `protobuf:"bytes,1,opt,name=model,proto3" json:"model,omitempty"`
	Provider         string                 `protobuf:"bytes,2,opt,name=provider,proto3" json:"provider,omitempty"`
	RequestId        string                 `protobuf:"bytes,3,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"` // each <= 128 B, as the harness reports them
	InputTokens      uint64                 `protobuf:"varint,4,opt,name=input_tokens,json=inputTokens,proto3" json:"input_tokens,omitempty"`
	OutputTokens     uint64                 `protobuf:"varint,5,opt,name=output_tokens,json=outputTokens,proto3" json:"output_tokens,omitempty"`
	CacheReadTokens  uint64                 `protobuf:"varint,6,opt,name=cache_read_tokens,json=cacheReadTokens,proto3" json:"cache_read_tokens,omitempty"`
	CacheWriteTokens uint64                 `protobuf:"varint,7,opt,name=cache_write_tokens,json=cacheWriteTokens,proto3" json:"cache_write_tokens,omitempty"`
	ReportedMicroUsd uint64                 `protobuf:"varint,8,opt,name=reported_micro_usd,json=reportedMicroUsd,proto3" json:"reported_micro_usd,omitempty"` // the harness's own amount, else 0
	StartedMillis    int64                  `protobuf:"varint,9,opt,name=started_millis,json=startedMillis,proto3" json:"started_millis,omitempty"`
	DurationMillis   uint32                 `protobuf:"varint,10,opt,name=duration_millis,json=durationMillis,proto3" json:"duration_millis,omitempty"`
	Attestation      *AttestationResult     `protobuf:"bytes,11,opt,name=attestation,proto3" json:"attestation,omitempty"`                              // remote TEE calls only (DESIGN-COMPUTE §6.8)
	Route            string                 `protobuf:"bytes,12,opt,name=route,proto3" json:"route,omitempty"`                                          // "local" | "tee" | "direct"; empty on a hook's or a harness's own call
	CatalogVersion   uint64                 `protobuf:"varint,13,opt,name=catalog_version,json=catalogVersion,proto3" json:"catalog_version,omitempty"` // the broker's catalog version a remote call named
	Platform         *ModelField            `protobuf:"bytes,14,opt,name=platform,proto3" json:"platform,omitempty"`                                    // evidence 4: the policy profile verified; the model stays evidence 2
	Context          *CallContext           `protobuf:"bytes,15,opt,name=context,proto3" json:"context,omitempty"`                                      // the call's place in the run's session tree (DESIGN-COMPUTE §24.5)
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *ModelCallBody) Reset() {
	*x = ModelCallBody{}
	mi := &file_protocol_record_proto_msgTypes[67]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ModelCallBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ModelCallBody) ProtoMessage() {}

func (x *ModelCallBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[67]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ModelCallBody.ProtoReflect.Descriptor instead.
func (*ModelCallBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{67}
}

func (x *ModelCallBody) GetModel() string {
	if x != nil {
		return x.Model
	}
	return ""
}

func (x *ModelCallBody) GetProvider() string {
	if x != nil {
		return x.Provider
	}
	return ""
}

func (x *ModelCallBody) GetRequestId() string {
	if x != nil {
		return x.RequestId
	}
	return ""
}

func (x *ModelCallBody) GetInputTokens() uint64 {
	if x != nil {
		return x.InputTokens
	}
	return 0
}

func (x *ModelCallBody) GetOutputTokens() uint64 {
	if x != nil {
		return x.OutputTokens
	}
	return 0
}

func (x *ModelCallBody) GetCacheReadTokens() uint64 {
	if x != nil {
		return x.CacheReadTokens
	}
	return 0
}

func (x *ModelCallBody) GetCacheWriteTokens() uint64 {
	if x != nil {
		return x.CacheWriteTokens
	}
	return 0
}

func (x *ModelCallBody) GetReportedMicroUsd() uint64 {
	if x != nil {
		return x.ReportedMicroUsd
	}
	return 0
}

func (x *ModelCallBody) GetStartedMillis() int64 {
	if x != nil {
		return x.StartedMillis
	}
	return 0
}

func (x *ModelCallBody) GetDurationMillis() uint32 {
	if x != nil {
		return x.DurationMillis
	}
	return 0
}

func (x *ModelCallBody) GetAttestation() *AttestationResult {
	if x != nil {
		return x.Attestation
	}
	return nil
}

func (x *ModelCallBody) GetRoute() string {
	if x != nil {
		return x.Route
	}
	return ""
}

func (x *ModelCallBody) GetCatalogVersion() uint64 {
	if x != nil {
		return x.CatalogVersion
	}
	return 0
}

func (x *ModelCallBody) GetPlatform() *ModelField {
	if x != nil {
		return x.Platform
	}
	return nil
}

func (x *ModelCallBody) GetContext() *CallContext {
	if x != nil {
		return x.Context
	}
	return nil
}

// DESIGN-COMPUTE.md §24.5: a run's session tree, one node an entry, its large parts as blobs, and a model call's place
// in it (M11). Kinds 54 and 55 are V's alone, raw and never indexed (I-20), and file their bodies apart (body_apart).
type SessionEntryBody struct {
	state        protoimpl.MessageState `protogen:"open.v1"`
	NodeId       []byte                 `protobuf:"bytes,1,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`                     // 16 random bytes
	ParentNodeId []byte                 `protobuf:"bytes,2,opt,name=parent_node_id,json=parentNodeId,proto3" json:"parent_node_id,omitempty"` // empty at a root; may name another run's node (24.7)
	ParentRunId  []byte                 `protobuf:"bytes,3,opt,name=parent_run_id,json=parentRunId,proto3" json:"parent_run_id,omitempty"`    // set when the parent is another run's
	Type         uint32                 `protobuf:"varint,4,opt,name=type,proto3" json:"type,omitempty"`                                      // 1 message, 2 model_change, 3 thinking_level_change, 4 usage,
	// 5 compaction, 6 branch_summary, 7 custom, 8 custom_message, 9 link
	Item []byte `protobuf:"bytes,5,opt,name=item,proto3" json:"item,omitempty"` // the Harness's Pi v3 entry, or the gateway's API item, RFC 8785 JSON,
	// after redaction and stubs (24.9); <= 16 KiB, larger parts in blobs
	Parts       []*SessionPart `protobuf:"bytes,6,rep,name=parts,proto3" json:"parts,omitempty"`                                // <= 64
	ItemSha256  []byte         `protobuf:"bytes,7,opt,name=item_sha256,json=itemSha256,proto3" json:"item_sha256,omitempty"`    // of the item as recorded, its parts by their hashes
	ChainSha256 []byte         `protobuf:"bytes,8,opt,name=chain_sha256,json=chainSha256,proto3" json:"chain_sha256,omitempty"` // SHA-256(the parent's chain_sha256 || item_sha256), a root's parent
	// counting as 32 zero bytes
	SameAs        []byte `protobuf:"bytes,9,opt,name=same_as,json=sameAs,proto3" json:"same_as,omitempty"` // an earlier entry of this run holding the same item; item, parts empty
	Redactions    uint32 `protobuf:"varint,10,opt,name=redactions,proto3" json:"redactions,omitempty"`
	Stubs         uint32 `protobuf:"varint,11,opt,name=stubs,proto3" json:"stubs,omitempty"` // markers in the item (24.9)
	Marks         uint32 `protobuf:"varint,12,opt,name=marks,proto3" json:"marks,omitempty"` // from this node on the run carries: bit 0 limited_use, §25.10's
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SessionEntryBody) Reset() {
	*x = SessionEntryBody{}
	mi := &file_protocol_record_proto_msgTypes[68]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SessionEntryBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionEntryBody) ProtoMessage() {}

func (x *SessionEntryBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[68]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionEntryBody.ProtoReflect.Descriptor instead.
func (*SessionEntryBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{68}
}

func (x *SessionEntryBody) GetNodeId() []byte {
	if x != nil {
		return x.NodeId
	}
	return nil
}

func (x *SessionEntryBody) GetParentNodeId() []byte {
	if x != nil {
		return x.ParentNodeId
	}
	return nil
}

func (x *SessionEntryBody) GetParentRunId() []byte {
	if x != nil {
		return x.ParentRunId
	}
	return nil
}

func (x *SessionEntryBody) GetType() uint32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *SessionEntryBody) GetItem() []byte {
	if x != nil {
		return x.Item
	}
	return nil
}

func (x *SessionEntryBody) GetParts() []*SessionPart {
	if x != nil {
		return x.Parts
	}
	return nil
}

func (x *SessionEntryBody) GetItemSha256() []byte {
	if x != nil {
		return x.ItemSha256
	}
	return nil
}

func (x *SessionEntryBody) GetChainSha256() []byte {
	if x != nil {
		return x.ChainSha256
	}
	return nil
}

func (x *SessionEntryBody) GetSameAs() []byte {
	if x != nil {
		return x.SameAs
	}
	return nil
}

func (x *SessionEntryBody) GetRedactions() uint32 {
	if x != nil {
		return x.Redactions
	}
	return 0
}

func (x *SessionEntryBody) GetStubs() uint32 {
	if x != nil {
		return x.Stubs
	}
	return 0
}

func (x *SessionEntryBody) GetMarks() uint32 {
	if x != nil {
		return x.Marks
	}
	return 0
}

type SessionPart struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Pointer       string                 `protobuf:"bytes,1,opt,name=pointer,proto3" json:"pointer,omitempty"` // RFC 6901 pointer to the part within the item
	Sha256        []byte                 `protobuf:"bytes,2,opt,name=sha256,proto3" json:"sha256,omitempty"`
	Size          uint64                 `protobuf:"varint,3,opt,name=size,proto3" json:"size,omitempty"`
	MediaType     string                 `protobuf:"bytes,4,opt,name=media_type,json=mediaType,proto3" json:"media_type,omitempty"`
	BlobEntryIds  [][]byte               `protobuf:"bytes,5,rep,name=blob_entry_ids,json=blobEntryIds,proto3" json:"blob_entry_ids,omitempty"` // <= 8 session_blob entries, in order; empty when omitted
	Omitted       bool                   `protobuf:"varint,6,opt,name=omitted,proto3" json:"omitted,omitempty"`                                // past 64 MiB: kept by hash and size only
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SessionPart) Reset() {
	*x = SessionPart{}
	mi := &file_protocol_record_proto_msgTypes[69]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SessionPart) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionPart) ProtoMessage() {}

func (x *SessionPart) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[69]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionPart.ProtoReflect.Descriptor instead.
func (*SessionPart) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{69}
}

func (x *SessionPart) GetPointer() string {
	if x != nil {
		return x.Pointer
	}
	return ""
}

func (x *SessionPart) GetSha256() []byte {
	if x != nil {
		return x.Sha256
	}
	return nil
}

func (x *SessionPart) GetSize() uint64 {
	if x != nil {
		return x.Size
	}
	return 0
}

func (x *SessionPart) GetMediaType() string {
	if x != nil {
		return x.MediaType
	}
	return ""
}

func (x *SessionPart) GetBlobEntryIds() [][]byte {
	if x != nil {
		return x.BlobEntryIds
	}
	return nil
}

func (x *SessionPart) GetOmitted() bool {
	if x != nil {
		return x.Omitted
	}
	return false
}

type SessionBlobBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	PartSha256    []byte                 `protobuf:"bytes,1,opt,name=part_sha256,json=partSha256,proto3" json:"part_sha256,omitempty"`
	Index         uint32                 `protobuf:"varint,2,opt,name=index,proto3" json:"index,omitempty"`
	Count         uint32                 `protobuf:"varint,3,opt,name=count,proto3" json:"count,omitempty"`
	Content       []byte                 `protobuf:"bytes,4,opt,name=content,proto3" json:"content,omitempty"` // <= 8 MiB, after redaction
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SessionBlobBody) Reset() {
	*x = SessionBlobBody{}
	mi := &file_protocol_record_proto_msgTypes[70]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SessionBlobBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionBlobBody) ProtoMessage() {}

func (x *SessionBlobBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[70]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionBlobBody.ProtoReflect.Descriptor instead.
func (*SessionBlobBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{70}
}

func (x *SessionBlobBody) GetPartSha256() []byte {
	if x != nil {
		return x.PartSha256
	}
	return nil
}

func (x *SessionBlobBody) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *SessionBlobBody) GetCount() uint32 {
	if x != nil {
		return x.Count
	}
	return 0
}

func (x *SessionBlobBody) GetContent() []byte {
	if x != nil {
		return x.Content
	}
	return nil
}

type CallContext struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	InputNodeId   []byte                 `protobuf:"bytes,1,opt,name=input_node_id,json=inputNodeId,proto3" json:"input_node_id,omitempty"`       // the context's last message; the path from it to its root is the rest
	OutputNodeIds [][]byte               `protobuf:"bytes,2,rep,name=output_node_ids,json=outputNodeIds,proto3" json:"output_node_ids,omitempty"` // what the response wrote
	SystemNodeId  []byte                 `protobuf:"bytes,3,opt,name=system_node_id,json=systemNodeId,proto3" json:"system_node_id,omitempty"`    // the system message in force
	RequestSha256 []byte                 `protobuf:"bytes,4,opt,name=request_sha256,json=requestSha256,proto3" json:"request_sha256,omitempty"`   // SHA-256 of the InferRequest (§6.4) as recorded, RFC 8785, each
	// part's bytes replaced by {pointer, sha256, size}, so pruning a
	// blob leaves the call checkable (24.6)
	Exact          bool   `protobuf:"varint,5,opt,name=exact,proto3" json:"exact,omitempty"`                                           // the recorded request is the one sent: no marker, stub or omission
	Renderer       string `protobuf:"bytes,6,opt,name=renderer,proto3" json:"renderer,omitempty"`                                      // harness-<version> or gateway-<api>-<version> (24.6)
	Params         []byte `protobuf:"bytes,7,opt,name=params,proto3" json:"params,omitempty"`                                          // the request's fields beside system, tools and messages, RFC 8785
	SignInWithheld bool   `protobuf:"varint,8,opt,name=sign_in_withheld,json=signInWithheld,proto3" json:"sign_in_withheld,omitempty"` // sign-in mail withheld from this call's rendering (§23.4)
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *CallContext) Reset() {
	*x = CallContext{}
	mi := &file_protocol_record_proto_msgTypes[71]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CallContext) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CallContext) ProtoMessage() {}

func (x *CallContext) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[71]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CallContext.ProtoReflect.Descriptor instead.
func (*CallContext) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{71}
}

func (x *CallContext) GetInputNodeId() []byte {
	if x != nil {
		return x.InputNodeId
	}
	return nil
}

func (x *CallContext) GetOutputNodeIds() [][]byte {
	if x != nil {
		return x.OutputNodeIds
	}
	return nil
}

func (x *CallContext) GetSystemNodeId() []byte {
	if x != nil {
		return x.SystemNodeId
	}
	return nil
}

func (x *CallContext) GetRequestSha256() []byte {
	if x != nil {
		return x.RequestSha256
	}
	return nil
}

func (x *CallContext) GetExact() bool {
	if x != nil {
		return x.Exact
	}
	return false
}

func (x *CallContext) GetRenderer() string {
	if x != nil {
		return x.Renderer
	}
	return ""
}

func (x *CallContext) GetParams() []byte {
	if x != nil {
		return x.Params
	}
	return nil
}

func (x *CallContext) GetSignInWithheld() bool {
	if x != nil {
		return x.SignInWithheld
	}
	return false
}

// a/<approval_id> in the requester's vault (owner decision 573's remedy; DESIGN-COMPUTE §24.7): one approval request's
// hint, versionless and sealed as any vault file, which an approver's phone leases in place of the whole approval log.
// Shaped as §16.11's DirectoryNotice (compute-plan-approval-notice-bytes, QD-1234). It names no approver and no action
// text, and nothing about a request is trusted from it: the phone reads the request entry from its log.
type ApprovalNotice struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	ApprovalId         []byte                 `protobuf:"bytes,1,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"`
	RequesterSidecarId []byte                 `protobuf:"bytes,2,opt,name=requester_sidecar_id,json=requesterSidecarId,proto3" json:"requester_sidecar_id,omitempty"`
	EntrySeq           uint64                 `protobuf:"varint,3,opt,name=entry_seq,json=entrySeq,proto3" json:"entry_seq,omitempty"`                     // the approval entry's seq in the requester's stream
	NotAfterMillis     int64                  `protobuf:"varint,4,opt,name=not_after_millis,json=notAfterMillis,proto3" json:"not_after_millis,omitempty"` // the request's own not_after_millis
	State              uint32                 `protobuf:"varint,5,opt,name=state,proto3" json:"state,omitempty"`                                           // 1 pending, 2 decided; a cancel removes the notice
	Kind               uint32                 `protobuf:"varint,6,opt,name=kind,proto3" json:"kind,omitempty"`                                             // the request's CanonicalAction.kind, a SidecarActionKind
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *ApprovalNotice) Reset() {
	*x = ApprovalNotice{}
	mi := &file_protocol_record_proto_msgTypes[72]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ApprovalNotice) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApprovalNotice) ProtoMessage() {}

func (x *ApprovalNotice) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[72]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApprovalNotice.ProtoReflect.Descriptor instead.
func (*ApprovalNotice) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{72}
}

func (x *ApprovalNotice) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

func (x *ApprovalNotice) GetRequesterSidecarId() []byte {
	if x != nil {
		return x.RequesterSidecarId
	}
	return nil
}

func (x *ApprovalNotice) GetEntrySeq() uint64 {
	if x != nil {
		return x.EntrySeq
	}
	return 0
}

func (x *ApprovalNotice) GetNotAfterMillis() int64 {
	if x != nil {
		return x.NotAfterMillis
	}
	return 0
}

func (x *ApprovalNotice) GetState() uint32 {
	if x != nil {
		return x.State
	}
	return 0
}

func (x *ApprovalNotice) GetKind() uint32 {
	if x != nil {
		return x.Kind
	}
	return 0
}

// RECORD.md section 13.1: run cost (M6).
type RunCostBody struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Usage         []*ModelUsage          `protobuf:"bytes,1,rep,name=usage,proto3" json:"usage,omitempty"`                                    // <= 16, by model
	MeteredBytes  uint64                 `protobuf:"varint,2,opt,name=metered_bytes,json=meteredBytes,proto3" json:"metered_bytes,omitempty"` // the sum of the run's tool results' metered_bytes (§16.6)
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RunCostBody) Reset() {
	*x = RunCostBody{}
	mi := &file_protocol_record_proto_msgTypes[73]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RunCostBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RunCostBody) ProtoMessage() {}

func (x *RunCostBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[73]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RunCostBody.ProtoReflect.Descriptor instead.
func (*RunCostBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{73}
}

func (x *RunCostBody) GetUsage() []*ModelUsage {
	if x != nil {
		return x.Usage
	}
	return nil
}

func (x *RunCostBody) GetMeteredBytes() uint64 {
	if x != nil {
		return x.MeteredBytes
	}
	return 0
}

type ModelUsage struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	Model            string                 `protobuf:"bytes,1,opt,name=model,proto3" json:"model,omitempty"`
	InputTokens      uint64                 `protobuf:"varint,2,opt,name=input_tokens,json=inputTokens,proto3" json:"input_tokens,omitempty"`
	OutputTokens     uint64                 `protobuf:"varint,3,opt,name=output_tokens,json=outputTokens,proto3" json:"output_tokens,omitempty"`
	CacheReadTokens  uint64                 `protobuf:"varint,4,opt,name=cache_read_tokens,json=cacheReadTokens,proto3" json:"cache_read_tokens,omitempty"`
	CacheWriteTokens uint64                 `protobuf:"varint,5,opt,name=cache_write_tokens,json=cacheWriteTokens,proto3" json:"cache_write_tokens,omitempty"`
	Calls            uint64                 `protobuf:"varint,6,opt,name=calls,proto3" json:"calls,omitempty"`
	ReportedMicroUsd uint64                 `protobuf:"varint,7,opt,name=reported_micro_usd,json=reportedMicroUsd,proto3" json:"reported_micro_usd,omitempty"` // the sum of what the harness reported, else 0
	Complete         bool                   `protobuf:"varint,8,opt,name=complete,proto3" json:"complete,omitempty"`                                           // false where coverage has a gap that may hide calls
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *ModelUsage) Reset() {
	*x = ModelUsage{}
	mi := &file_protocol_record_proto_msgTypes[74]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ModelUsage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ModelUsage) ProtoMessage() {}

func (x *ModelUsage) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[74]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ModelUsage.ProtoReflect.Descriptor instead.
func (*ModelUsage) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{74}
}

func (x *ModelUsage) GetModel() string {
	if x != nil {
		return x.Model
	}
	return ""
}

func (x *ModelUsage) GetInputTokens() uint64 {
	if x != nil {
		return x.InputTokens
	}
	return 0
}

func (x *ModelUsage) GetOutputTokens() uint64 {
	if x != nil {
		return x.OutputTokens
	}
	return 0
}

func (x *ModelUsage) GetCacheReadTokens() uint64 {
	if x != nil {
		return x.CacheReadTokens
	}
	return 0
}

func (x *ModelUsage) GetCacheWriteTokens() uint64 {
	if x != nil {
		return x.CacheWriteTokens
	}
	return 0
}

func (x *ModelUsage) GetCalls() uint64 {
	if x != nil {
		return x.Calls
	}
	return 0
}

func (x *ModelUsage) GetReportedMicroUsd() uint64 {
	if x != nil {
		return x.ReportedMicroUsd
	}
	return 0
}

func (x *ModelUsage) GetComplete() bool {
	if x != nil {
		return x.Complete
	}
	return false
}

// DESIGN-COMPUTE.md §28.12: the support conversation's messages in the vault, the team record's projection holding
// no V: field.
type SupportMessageBody struct {
	state             protoimpl.MessageState `protogen:"open.v1"`
	Direction         uint32                 `protobuf:"varint,1,opt,name=direction,proto3" json:"direction,omitempty"`                     // 1 sent, 2 received
	Product           string                 `protobuf:"bytes,2,opt,name=product,proto3" json:"product,omitempty"`                          // urnetwork
	Entry             string                 `protobuf:"bytes,3,opt,name=entry,proto3" json:"entry,omitempty"`                              // FB's id; empty until the service acknowledges it
	Seq               uint32                 `protobuf:"varint,4,opt,name=seq,proto3" json:"seq,omitempty"`                                 // FB's event seq; 0 for a message not yet acknowledged
	Type              uint32                 `protobuf:"varint,5,opt,name=type,proto3" json:"type,omitempty"`                               // FB section 4's event types, in its order; 0 UNSPECIFIED
	Tier              uint32                 `protobuf:"varint,6,opt,name=tier,proto3" json:"tier,omitempty"`                               // 1 human, 2 released, 3 agent
	ClientRef         []byte                 `protobuf:"bytes,7,opt,name=client_ref,json=clientRef,proto3" json:"client_ref,omitempty"`     // joins a sent message to its acknowledgment
	Text              string                 `protobuf:"bytes,8,opt,name=text,proto3" json:"text,omitempty"`                                // V: exactly the text sent, or the reply received
	AgentLabel        string                 `protobuf:"bytes,9,opt,name=agent_label,json=agentLabel,proto3" json:"agent_label,omitempty"`  // V: the sending agent's name and where it ran
	Bundle            *BundleManifest        `protobuf:"bytes,10,opt,name=bundle,proto3" json:"bundle,omitempty"`                           // V: events, window, size, SHA-256, codes by component
	Files             []*FileFields          `protobuf:"bytes,11,rep,name=files,proto3" json:"files,omitempty"`                             // V: name, type, size, SHA-256
	BodySha256        []byte                 `protobuf:"bytes,12,opt,name=body_sha256,json=bodySha256,proto3" json:"body_sha256,omitempty"` // of the body sent or received
	BodyBytes         uint64                 `protobuf:"varint,13,opt,name=body_bytes,json=bodyBytes,proto3" json:"body_bytes,omitempty"`
	Status            uint32                 `protobuf:"varint,14,opt,name=status,proto3" json:"status,omitempty"`
	FixedIn           string                 `protobuf:"bytes,15,opt,name=fixed_in,json=fixedIn,proto3" json:"fixed_in,omitempty"`                                // a status event's
	ApprovalId        []byte                 `protobuf:"bytes,16,opt,name=approval_id,json=approvalId,proto3" json:"approval_id,omitempty"`                       // a kind-27 use's
	DisclosureVersion uint32                 `protobuf:"varint,17,opt,name=disclosure_version,json=disclosureVersion,proto3" json:"disclosure_version,omitempty"` // a sent message's support:urnetwork version
	unknownFields     protoimpl.UnknownFields
	sizeCache         protoimpl.SizeCache
}

func (x *SupportMessageBody) Reset() {
	*x = SupportMessageBody{}
	mi := &file_protocol_record_proto_msgTypes[75]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SupportMessageBody) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SupportMessageBody) ProtoMessage() {}

func (x *SupportMessageBody) ProtoReflect() protoreflect.Message {
	mi := &file_protocol_record_proto_msgTypes[75]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SupportMessageBody.ProtoReflect.Descriptor instead.
func (*SupportMessageBody) Descriptor() ([]byte, []int) {
	return file_protocol_record_proto_rawDescGZIP(), []int{75}
}

func (x *SupportMessageBody) GetDirection() uint32 {
	if x != nil {
		return x.Direction
	}
	return 0
}

func (x *SupportMessageBody) GetProduct() string {
	if x != nil {
		return x.Product
	}
	return ""
}

func (x *SupportMessageBody) GetEntry() string {
	if x != nil {
		return x.Entry
	}
	return ""
}

func (x *SupportMessageBody) GetSeq() uint32 {
	if x != nil {
		return x.Seq
	}
	return 0
}

func (x *SupportMessageBody) GetType() uint32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *SupportMessageBody) GetTier() uint32 {
	if x != nil {
		return x.Tier
	}
	return 0
}

func (x *SupportMessageBody) GetClientRef() []byte {
	if x != nil {
		return x.ClientRef
	}
	return nil
}

func (x *SupportMessageBody) GetText() string {
	if x != nil {
		return x.Text
	}
	return ""
}

func (x *SupportMessageBody) GetAgentLabel() string {
	if x != nil {
		return x.AgentLabel
	}
	return ""
}

func (x *SupportMessageBody) GetBundle() *BundleManifest {
	if x != nil {
		return x.Bundle
	}
	return nil
}

func (x *SupportMessageBody) GetFiles() []*FileFields {
	if x != nil {
		return x.Files
	}
	return nil
}

func (x *SupportMessageBody) GetBodySha256() []byte {
	if x != nil {
		return x.BodySha256
	}
	return nil
}

func (x *SupportMessageBody) GetBodyBytes() uint64 {
	if x != nil {
		return x.BodyBytes
	}
	return 0
}

func (x *SupportMessageBody) GetStatus() uint32 {
	if x != nil {
		return x.Status
	}
	return 0
}

func (x *SupportMessageBody) GetFixedIn() string {
	if x != nil {
		return x.FixedIn
	}
	return ""
}

func (x *SupportMessageBody) GetApprovalId() []byte {
	if x != nil {
		return x.ApprovalId
	}
	return nil
}

func (x *SupportMessageBody) GetDisclosureVersion() uint32 {
	if x != nil {
		return x.DisclosureVersion
	}
	return 0
}

var File_protocol_record_proto protoreflect.FileDescriptor

const file_protocol_record_proto_rawDesc = "" +
	"\n" +
	"\x15protocol/record.proto\x12\x11urnetwork.sidecar\x1a\x15protocol/attest.proto\x1a\x1aprotocol/bridge/auth.proto\x1a\x1cprotocol/bridge/signed.proto\"\x9c\x04\n" +
	"\fRecordHeader\x12\x19\n" +
	"\bentry_id\x18\x01 \x01(\fR\aentryId\x12\x15\n" +
	"\x06log_id\x18\x02 \x01(\fR\x05logId\x12*\n" +
	"\x11writer_sidecar_id\x18\x03 \x01(\fR\x0fwriterSidecarId\x12\x10\n" +
	"\x03seq\x18\x04 \x01(\x04R\x03seq\x12\x1f\n" +
	"\vprev_sha256\x18\x05 \x01(\fR\n" +
	"prevSha256\x12\x19\n" +
	"\bagent_id\x18\x06 \x01(\fR\aagentId\x12\x15\n" +
	"\x06run_id\x18\a \x01(\fR\x05runId\x12\x1b\n" +
	"\taction_id\x18\b \x01(\fR\bactionId\x12\x12\n" +
	"\x04kind\x18\t \x01(\rR\x04kind\x12\x1f\n" +
	"\vtime_millis\x18\n" +
	" \x01(\x03R\n" +
	"timeMillis\x12\x16\n" +
	"\x06source\x18\v \x01(\rR\x06source\x12\x18\n" +
	"\atainted\x18\f \x01(\bR\atainted\x12'\n" +
	"\x0fbody_commitment\x18\r \x01(\fR\x0ebodyCommitment\x127\n" +
	"\acontent\x18\x0e \x03(\v2\x1d.urnetwork.sidecar.ContentRefR\acontent\x12%\n" +
	"\x0epolicy_version\x18\x0f \x01(\x04R\rpolicyVersion\x12\x19\n" +
	"\bgrant_id\x18\x10 \x01(\fR\agrantId\x12!\n" +
	"\fagent_source\x18\x11 \x01(\rR\vagentSource\"b\n" +
	"\n" +
	"ContentRef\x12\x17\n" +
	"\arepo_id\x18\x01 \x01(\fR\x06repoId\x12\x1b\n" +
	"\tobject_id\x18\x02 \x01(\fR\bobjectId\x12\x1e\n" +
	"\n" +
	"commitment\x18\x03 \x01(\fR\n" +
	"commitment\"\xd7\x01\n" +
	"\vRecordEntry\x121\n" +
	"\x06header\x18\x01 \x01(\v2\x19.urnetwork.sidecar.SignedR\x06header\x12\x1f\n" +
	"\vsealed_body\x18\x02 \x01(\fR\n" +
	"sealedBody\x12\x1e\n" +
	"\vkey_slot_id\x18\x03 \x01(\fR\tkeySlotId\x12\x18\n" +
	"\aversion\x18\x04 \x01(\rR\aversion\x12\x1b\n" +
	"\tkey_index\x18\x05 \x01(\rR\bkeyIndex\x12\x1d\n" +
	"\n" +
	"body_apart\x18\x06 \x01(\bR\tbodyApart\"\x84\x10\n" +
	"\x0fCanonicalAction\x12\x12\n" +
	"\x04kind\x18\x01 \x01(\rR\x04kind\x12\x1e\n" +
	"\n" +
	"recipients\x18\x02 \x03(\tR\n" +
	"recipients\x12\x1f\n" +
	"\vbody_sha256\x18\x03 \x01(\fR\n" +
	"bodySha256\x12\x18\n" +
	"\apreview\x18\x04 \x01(\tR\apreview\x12\x12\n" +
	"\x04host\x18\x05 \x01(\tR\x04host\x12\x12\n" +
	"\x04port\x18\x06 \x01(\rR\x04port\x12\x1a\n" +
	"\baudience\x18\a \x01(\rR\baudience\x12%\n" +
	"\x0eexpires_millis\x18\b \x01(\x03R\rexpiresMillis\x12\x14\n" +
	"\x05cidrs\x18\t \x03(\tR\x05cidrs\x12\x1b\n" +
	"\tgrant_dst\x18\n" +
	" \x03(\tR\bgrantDst\x12\x1f\n" +
	"\vgrant_allow\x18\v \x03(\tR\n" +
	"grantAllow\x12\x18\n" +
	"\aversion\x18\f \x01(\rR\aversion\x12\x14\n" +
	"\x05scope\x18\r \x01(\bR\x05scope\x12\x17\n" +
	"\arepo_id\x18\x0e \x01(\fR\x06repoId\x12\x12\n" +
	"\x04path\x18\x0f \x01(\tR\x04path\x12%\n" +
	"\x0econtent_sha256\x18\x10 \x01(\fR\rcontentSha256\x12!\n" +
	"\fbase_version\x18\x11 \x01(\x04R\vbaseVersion\x12\x19\n" +
	"\bdns_name\x18\x12 \x01(\tR\adnsName\x12\x19\n" +
	"\bdns_type\x18\x13 \x01(\tR\adnsType\x12\x1b\n" +
	"\tdns_value\x18\x14 \x01(\tR\bdnsValue\x12\x17\n" +
	"\adns_ttl\x18\x15 \x01(\rR\x06dnsTtl\x12\x14\n" +
	"\x05alias\x18\x16 \x01(\tR\x05alias\x12*\n" +
	"\x11target_sidecar_id\x18\x1a \x01(\fR\x0ftargetSidecarId\x12\x1f\n" +
	"\vtarget_port\x18\x1b \x01(\rR\n" +
	"targetPort\x12\x17\n" +
	"\arule_id\x18\x1c \x01(\fR\x06ruleId\x12\x18\n" +
	"\asubject\x18\x1d \x01(\fR\asubject\x12$\n" +
	"\x0erestore_run_id\x18\x1e \x01(\fR\frestoreRunId\x12#\n" +
	"\rrestore_paths\x18\x1f \x03(\tR\frestorePaths\x12,\n" +
	"\x12restore_preview_id\x18  \x01(\fR\x10restorePreviewId\x12\x19\n" +
	"\bapp_mode\x18! \x01(\rR\aappMode\x12(\n" +
	"\x10link_spki_sha256\x18# \x01(\fR\x0elinkSpkiSha256\x12\x1f\n" +
	"\valias_group\x18$ \x01(\tR\n" +
	"aliasGroup\x12\x1e\n" +
	"\n" +
	"versioning\x18% \x01(\rR\n" +
	"versioning\x12#\n" +
	"\rsealed_detail\x18& \x01(\fR\fsealedDetail\x12\x1f\n" +
	"\vegress_mode\x18' \x01(\rR\n" +
	"egressMode\x12(\n" +
	"\x10share_network_id\x18( \x01(\fR\x0eshareNetworkId\x124\n" +
	"\x16require_default_egress\x18) \x01(\bR\x14requireDefaultEgress\x12:\n" +
	"\aenclave\x18* \x01(\v2 .urnetwork.sidecar.EnclaveFieldsR\aenclave\x127\n" +
	"\x06budget\x18+ \x01(\v2\x1f.urnetwork.sidecar.BudgetFieldsR\x06budget\x12\x10\n" +
	"\x03url\x18, \x01(\tR\x03url\x12\x12\n" +
	"\x04tool\x18- \x01(\tR\x04tool\x121\n" +
	"\x04send\x18. \x01(\v2\x1d.urnetwork.sidecar.SendFieldsR\x04send\x12:\n" +
	"\acontext\x18/ \x01(\v2 .urnetwork.sidecar.ContextFieldsR\acontext\x12#\n" +
	"\rtaint_reasons\x180 \x03(\tR\ftaintReasons\x12!\n" +
	"\ftook_tainted\x181 \x01(\bR\vtookTainted\x12%\n" +
	"\x0ecalendar_label\x182 \x01(\tR\rcalendarLabel\x12#\n" +
	"\rcalendar_host\x183 \x01(\tR\fcalendarHost\x12+\n" +
	"\x11calendar_audience\x184 \x01(\tR\x10calendarAudience\x12O\n" +
	"\x0fcalendar_events\x185 \x03(\v2&.urnetwork.sidecar.CalendarEventActionR\x0ecalendarEvents\x12#\n" +
	"\rcalendar_link\x186 \x01(\fR\fcalendarLink\x12'\n" +
	"\x0fcalendar_target\x187 \x01(\fR\x0ecalendarTarget\x12#\n" +
	"\rcalendar_name\x188 \x01(\tR\fcalendarName\x12G\n" +
	"\fservice_call\x18< \x01(\v2$.urnetwork.sidecar.ServiceCallFieldsR\vserviceCall\x121\n" +
	"\x04auto\x18F \x01(\v2\x1d.urnetwork.sidecar.AutoFieldsR\x04auto\x12:\n" +
	"\asupport\x18P \x01(\v2 .urnetwork.sidecar.SupportFieldsR\asupportJ\x04\b\x17\x10\x18J\x04\b\x18\x10\x19J\x04\b\x19\x10\x1aJ\x04\b\"\x10#J\x04\b9\x10<J\x04\b=\x10FJ\x04\bG\x10PJ\x04\bQ\x10Z\"\xd2\x01\n" +
	"\rEnclaveFields\x12\x1d\n" +
	"\n" +
	"enclave_id\x18\x01 \x01(\fR\tenclaveId\x12\x12\n" +
	"\x04name\x18\x02 \x01(\tR\x04name\x12\x14\n" +
	"\x05shape\x18\x03 \x01(\tR\x05shape\x12\x1a\n" +
	"\bprovider\x18\x04 \x01(\tR\bprovider\x12\x14\n" +
	"\x05label\x18\x05 \x01(\tR\x05label\x12$\n" +
	"\x0eprice_per_hour\x18\x06 \x01(\x04R\fpricePerHour\x12 \n" +
	"\vincarnation\x18\a \x01(\x04R\vincarnation\"s\n" +
	"\fBudgetFields\x12\x19\n" +
	"\bagent_id\x18\x01 \x01(\fR\aagentId\x12\x16\n" +
	"\x06period\x18\x02 \x01(\rR\x06period\x12\x16\n" +
	"\x06amount\x18\x03 \x01(\x04R\x06amount\x12\x18\n" +
	"\acurrent\x18\x04 \x01(\x04R\acurrent\"\xe8\x02\n" +
	"\n" +
	"SendFields\x12!\n" +
	"\ftarget_agent\x18\x01 \x01(\tR\vtargetAgent\x12&\n" +
	"\x0ftarget_agent_id\x18\x02 \x01(\fR\rtargetAgentId\x12(\n" +
	"\x10target_member_id\x18\x03 \x01(\fR\x0etargetMemberId\x12\x12\n" +
	"\x04mode\x18\x04 \x01(\rR\x04mode\x12\x12\n" +
	"\x04text\x18\x05 \x01(\tR\x04text\x12\x14\n" +
	"\x05stdin\x18\x06 \x01(\tR\x05stdin\x12\x10\n" +
	"\x03cwd\x18\a \x01(\tR\x03cwd\x120\n" +
	"\x04refs\x18\b \x03(\v2\x1c.urnetwork.sidecar.RefFieldsR\x04refs\x12\x14\n" +
	"\x05model\x18\t \x01(\tR\x05model\x12\x14\n" +
	"\x05tools\x18\n" +
	" \x03(\tR\x05tools\x127\n" +
	"\x06budget\x18\v \x01(\v2\x1f.urnetwork.sidecar.BudgetFieldsR\x06budget\"R\n" +
	"\tRefFields\x12\x17\n" +
	"\arepo_id\x18\x01 \x01(\fR\x06repoId\x12\x12\n" +
	"\x04path\x18\x02 \x01(\tR\x04path\x12\x18\n" +
	"\aversion\x18\x03 \x01(\x04R\aversion\"\xbd\x02\n" +
	"\rContextFields\x12\x15\n" +
	"\x06run_id\x18\x01 \x01(\fR\x05runId\x12\x19\n" +
	"\bentry_id\x18\x02 \x01(\fR\aentryId\x12\x14\n" +
	"\x05nodes\x18\x03 \x01(\rR\x05nodes\x12\x18\n" +
	"\aflagged\x18\x04 \x01(\rR\aflagged\x12\x1c\n" +
	"\tuntrusted\x18\x05 \x01(\rR\tuntrusted\x12#\n" +
	"\rmail_messages\x18\x06 \x01(\rR\fmailMessages\x12'\n" +
	"\x0fcalendar_events\x18\a \x01(\rR\x0ecalendarEvents\x12#\n" +
	"\rfetched_pages\x18\b \x01(\rR\ffetchedPages\x12'\n" +
	"\x0fservice_results\x18\t \x01(\rR\x0eserviceResults\x12\x10\n" +
	"\x03act\x18\n" +
	" \x01(\rR\x03act\"\xf4\x03\n" +
	"\x13CalendarEventAction\x12\x1c\n" +
	"\toperation\x18\x01 \x01(\rR\toperation\x12\x10\n" +
	"\x03uid\x18\x02 \x01(\tR\x03uid\x12\x1e\n" +
	"\n" +
	"occurrence\x18\x03 \x01(\tR\n" +
	"occurrence\x12\x1a\n" +
	"\bexpected\x18\x04 \x01(\tR\bexpected\x12\x14\n" +
	"\x05title\x18\x05 \x01(\tR\x05title\x12\x14\n" +
	"\x05start\x18\x06 \x01(\tR\x05start\x12\x10\n" +
	"\x03end\x18\a \x01(\tR\x03end\x12\x12\n" +
	"\x04zone\x18\b \x01(\tR\x04zone\x12\x17\n" +
	"\aall_day\x18\t \x01(\bR\x06allDay\x12\x1e\n" +
	"\n" +
	"recurrence\x18\n" +
	" \x01(\tR\n" +
	"recurrence\x12\x1a\n" +
	"\blocation\x18\v \x01(\tR\blocation\x12\x1c\n" +
	"\treminders\x18\f \x03(\tR\treminders\x12\x1c\n" +
	"\tattendees\x18\r \x03(\tR\tattendees\x12\x14\n" +
	"\x05mails\x18\x0e \x03(\tR\x05mails\x12 \n" +
	"\vdescription\x18\x0f \x01(\tR\vdescription\x12>\n" +
	"\x06before\x18\x10 \x01(\v2&.urnetwork.sidecar.CalendarEventFieldsR\x06before\x12\x16\n" +
	"\x06source\x18\x11 \x01(\tR\x06source\"\x9a\x02\n" +
	"\x13CalendarEventFields\x12\x14\n" +
	"\x05title\x18\x01 \x01(\tR\x05title\x12\x14\n" +
	"\x05start\x18\x02 \x01(\tR\x05start\x12\x10\n" +
	"\x03end\x18\x03 \x01(\tR\x03end\x12\x12\n" +
	"\x04zone\x18\x04 \x01(\tR\x04zone\x12\x17\n" +
	"\aall_day\x18\x05 \x01(\bR\x06allDay\x12\x1e\n" +
	"\n" +
	"recurrence\x18\x06 \x01(\tR\n" +
	"recurrence\x12\x1a\n" +
	"\blocation\x18\a \x01(\tR\blocation\x12\x1c\n" +
	"\treminders\x18\b \x03(\tR\treminders\x12\x1c\n" +
	"\tattendees\x18\t \x03(\tR\tattendees\x12 \n" +
	"\vdescription\x18\n" +
	" \x01(\tR\vdescription\"\xa6\x02\n" +
	"\x11ServiceCallFields\x12\x1e\n" +
	"\n" +
	"connection\x18\x01 \x01(\fR\n" +
	"connection\x12\x14\n" +
	"\x05label\x18\x02 \x01(\tR\x05label\x12\x18\n" +
	"\aservice\x18\x03 \x01(\tR\aservice\x12\x18\n" +
	"\aaccount\x18\x04 \x01(\tR\aaccount\x12\x16\n" +
	"\x06method\x18\x05 \x01(\tR\x06method\x12\x12\n" +
	"\x04path\x18\x06 \x01(\tR\x04path\x12\x14\n" +
	"\x05query\x18\a \x01(\tR\x05query\x12!\n" +
	"\fcontent_type\x18\b \x01(\tR\vcontentType\x12\x12\n" +
	"\x04body\x18\t \x01(\tR\x04body\x12\x14\n" +
	"\x05class\x18\n" +
	" \x01(\rR\x05class\x12\x18\n" +
	"\afeature\x18\v \x01(\tR\afeature\"8\n" +
	"\n" +
	"AutoFields\x12\x14\n" +
	"\x05basis\x18\x01 \x01(\rR\x05basis\x12\x14\n" +
	"\x05rules\x18\x02 \x03(\rR\x05rules\"\xf6\x01\n" +
	"\rSupportFields\x12\x18\n" +
	"\aproduct\x18\x01 \x01(\tR\aproduct\x12\x14\n" +
	"\x05entry\x18\x02 \x01(\tR\x05entry\x12\x12\n" +
	"\x04kind\x18\x03 \x01(\rR\x04kind\x12\x12\n" +
	"\x04text\x18\x04 \x01(\tR\x04text\x129\n" +
	"\x06bundle\x18\x05 \x01(\v2!.urnetwork.sidecar.BundleManifestR\x06bundle\x123\n" +
	"\x05files\x18\x06 \x03(\v2\x1d.urnetwork.sidecar.FileFieldsR\x05files\x12\x1d\n" +
	"\n" +
	"client_ref\x18\a \x01(\fR\tclientRef\"\xba\x01\n" +
	"\x0eBundleManifest\x12\x16\n" +
	"\x06events\x18\x01 \x01(\rR\x06events\x12\x14\n" +
	"\x05first\x18\x02 \x01(\x03R\x05first\x12\x12\n" +
	"\x04last\x18\x03 \x01(\x03R\x04last\x12\x14\n" +
	"\x05bytes\x18\x04 \x01(\x04R\x05bytes\x12\x16\n" +
	"\x06sha256\x18\x05 \x01(\fR\x06sha256\x128\n" +
	"\x05codes\x18\x06 \x03(\v2\".urnetwork.sidecar.BundleCodeCountR\x05codes\"Y\n" +
	"\x0fBundleCodeCount\x12\x1c\n" +
	"\tcomponent\x18\x01 \x01(\tR\tcomponent\x12\x12\n" +
	"\x04code\x18\x02 \x01(\tR\x04code\x12\x14\n" +
	"\x05count\x18\x03 \x01(\rR\x05count\"`\n" +
	"\n" +
	"FileFields\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x12\n" +
	"\x04type\x18\x02 \x01(\rR\x04type\x12\x12\n" +
	"\x04size\x18\x03 \x01(\x04R\x04size\x12\x16\n" +
	"\x06sha256\x18\x04 \x01(\fR\x06sha256\"u\n" +
	"\x16CanonicalActionDetail5\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x12\n" +
	"\x04role\x18\x02 \x01(\rR\x04role\x12\x18\n" +
	"\aharness\x18\x03 \x01(\tR\aharness\x12\x19\n" +
	"\bgrant_id\x18\x04 \x01(\fR\agrantId\"k\n" +
	"\x15CanonicalActionDetail\x12\x14\n" +
	"\x05cidrs\x18\x01 \x03(\tR\x05cidrs\x12\x1f\n" +
	"\vtarget_port\x18\x02 \x01(\rR\n" +
	"targetPort\x12\x1b\n" +
	"\tgrant_dst\x18\x03 \x03(\tR\bgrantDst\"\xaf\x04\n" +
	"\x0fApprovalRequest\x12\x1f\n" +
	"\vapproval_id\x18\x01 \x01(\fR\n" +
	"approvalId\x12\x1b\n" +
	"\taction_id\x18\x02 \x01(\fR\bactionId\x12\x15\n" +
	"\x06run_id\x18\x03 \x01(\fR\x05runId\x12\x19\n" +
	"\bagent_id\x18\x04 \x01(\fR\aagentId\x12)\n" +
	"\x10canonical_action\x18\x05 \x01(\fR\x0fcanonicalAction\x12%\n" +
	"\x0epayload_sha256\x18\x06 \x01(\fR\rpayloadSha256\x12\x18\n" +
	"\asummary\x18\a \x01(\tR\asummary\x12\x12\n" +
	"\x04risk\x18\b \x01(\rR\x04risk\x120\n" +
	"\x14requester_sidecar_id\x18\t \x01(\fR\x12requesterSidecarId\x12\x18\n" +
	"\atainted\x18\n" +
	" \x01(\bR\atainted\x12\x1c\n" +
	"\tapprovers\x18\v \x03(\fR\tapprovers\x12(\n" +
	"\x10not_after_millis\x18\f \x01(\x03R\x0enotAfterMillis\x12\x18\n" +
	"\aversion\x18\r \x01(\rR\aversion\x12\x1d\n" +
	"\n" +
	"local_port\x18\x0e \x01(\rR\tlocalPort\x12\x16\n" +
	"\x06weight\x18\x0f \x01(\x05R\x06weight\x12\x12\n" +
	"\x04alpn\x18\x10 \x03(\tR\x04alpn\x12\x1f\n" +
	"\vsocket_name\x18\x11 \x01(\tR\n" +
	"socketName\x12\x12\n" +
	"\x04uses\x18\x12 \x01(\rR\x04uses\"\xda\x04\n" +
	"\x10ApprovalDecision\x12\x1f\n" +
	"\vapproval_id\x18\x01 \x01(\fR\n" +
	"approvalId\x12%\n" +
	"\x0erequest_sha256\x18\x02 \x01(\fR\rrequestSha256\x12%\n" +
	"\x0epayload_sha256\x18\x03 \x01(\fR\rpayloadSha256\x12\x1a\n" +
	"\bdecision\x18\x04 \x01(\rR\bdecision\x12\x12\n" +
	"\x04uses\x18\x05 \x01(\rR\x04uses\x12(\n" +
	"\x10not_after_millis\x18\x06 \x01(\x03R\x0enotAfterMillis\x12,\n" +
	"\x12approver_member_id\x18\a \x01(\fR\x10approverMemberId\x12\x18\n" +
	"\achannel\x18\b \x01(\rR\achannel\x12\x16\n" +
	"\x06sshsig\x18\t \x01(\fR\x06sshsig\x12'\n" +
	"\x0fevidence_sha256\x18\n" +
	" \x01(\fR\x0eevidenceSha256\x120\n" +
	"\x14requester_sidecar_id\x18\v \x01(\fR\x12requesterSidecarId\x125\n" +
	"\bauth_pin\x18\f \x01(\v2\x1a.urnetwork.sidecar.AuthPinR\aauthPin\x12\x18\n" +
	"\aversion\x18\r \x01(\rR\aversion\x12\x1a\n" +
	"\bselected\x18\x0e \x03(\rR\bselected\x12\x12\n" +
	"\x04auto\x18\x0f \x01(\bR\x04auto\x12A\n" +
	"\fauto_verdict\x18\x10 \x01(\v2\x1e.urnetwork.sidecar.AutoVerdictR\vautoVerdict\"\xa5\x02\n" +
	"\vAutoVerdict\x12\x18\n" +
	"\averdict\x18\x01 \x01(\rR\averdict\x12\x16\n" +
	"\x06reason\x18\x02 \x01(\rR\x06reason\x12\x14\n" +
	"\x05score\x18\x03 \x01(\rR\x05score\x12\x1c\n" +
	"\tthreshold\x18\x04 \x01(\rR\tthreshold\x12\x14\n" +
	"\x05model\x18\x05 \x01(\tR\x05model\x12!\n" +
	"\fmodel_sha256\x18\x06 \x01(\fR\vmodelSha256\x12#\n" +
	"\rinputs_sha256\x18\a \x01(\fR\finputsSha256\x12\x18\n" +
	"\awindows\x18\b \x01(\rR\awindows\x12\x1b\n" +
	"\trun_count\x18\t \x01(\rR\brunCount\x12\x1b\n" +
	"\tday_count\x18\n" +
	" \x01(\rR\bdayCount\"1\n" +
	"\x0eApprovalCancel\x12\x1f\n" +
	"\vapproval_id\x18\x01 \x01(\fR\n" +
	"approvalId\"\xd7\x02\n" +
	"\fReachReceipt\x12\x19\n" +
	"\bgrant_id\x18\x01 \x01(\fR\agrantId\x12%\n" +
	"\x0epolicy_version\x18\x02 \x01(\x04R\rpolicyVersion\x12\x12\n" +
	"\x04kind\x18\x03 \x01(\rR\x04kind\x12\x14\n" +
	"\x05owner\x18\x04 \x01(\fR\x05owner\x12\x1a\n" +
	"\bapprover\x18\x05 \x01(\fR\bapprover\x12.\n" +
	"\x13window_start_millis\x18\x06 \x01(\x03R\x11windowStartMillis\x12\x14\n" +
	"\x05peers\x18\a \x03(\fR\x05peers\x12!\n" +
	"\fstream_count\x18\b \x01(\x04R\vstreamCount\x12\x1d\n" +
	"\n" +
	"byte_count\x18\t \x01(\x04R\tbyteCount\x12\x16\n" +
	"\x06relays\x18\n" +
	" \x03(\tR\x06relays\x12\x1f\n" +
	"\vserver_name\x18\v \x01(\tR\n" +
	"serverName\"\xff\x01\n" +
	"\bCoverage\x12\x15\n" +
	"\x06run_id\x18\x01 \x01(\fR\x05runId\x12\x18\n" +
	"\aharness\x18\x02 \x01(\tR\aharness\x12\x18\n" +
	"\aversion\x18\x03 \x01(\tR\aversion\x12\x18\n" +
	"\asources\x18\x04 \x03(\tR\asources\x12\x12\n" +
	"\x04gaps\x18\x05 \x03(\tR\x04gaps\x12\x1b\n" +
	"\tfirst_seq\x18\x06 \x01(\x04R\bfirstSeq\x12\x19\n" +
	"\blast_seq\x18\a \x01(\x04R\alastSeq\x12B\n" +
	"\x0ebodies_dropped\x18\b \x03(\v2\x1b.urnetwork.sidecar.SeqRangeR\rbodiesDropped\"4\n" +
	"\bSeqRange\x12\x14\n" +
	"\x05first\x18\x01 \x01(\x04R\x05first\x12\x12\n" +
	"\x04last\x18\x02 \x01(\x04R\x04last\"\x9e\x01\n" +
	"\x0fRetentionPolicy\x12\x15\n" +
	"\x06log_id\x18\x01 \x01(\fR\x05logId\x12\x14\n" +
	"\x05class\x18\x02 \x01(\rR\x05class\x12\x1b\n" +
	"\tkeep_days\x18\x03 \x01(\rR\bkeepDays\x12'\n" +
	"\x0fsearchable_days\x18\x04 \x01(\rR\x0esearchableDays\x12\x18\n" +
	"\aarchive\x18\x05 \x01(\bR\aarchive\"P\n" +
	"\x12RecordDepositBatch\x12:\n" +
	"\aentries\x18\x01 \x03(\v2 .urnetwork.sidecar.RecordDepositR\aentries\"K\n" +
	"\rRecordDeposit\x12\x14\n" +
	"\x05entry\x18\x01 \x01(\fR\x05entry\x12\x10\n" +
	"\x03key\x18\x02 \x01(\fR\x03key\x12\x12\n" +
	"\x04salt\x18\x03 \x01(\fR\x04salt\"\xbb\x01\n" +
	"\x10CoordinationBody\x12\x12\n" +
	"\x04text\x18\x01 \x01(\tR\x04text\x12\x18\n" +
	"\atargets\x18\x02 \x03(\tR\atargets\x12%\n" +
	"\x0eexpires_millis\x18\x03 \x01(\x03R\rexpiresMillis\x12\x19\n" +
	"\bclaim_id\x18\x04 \x01(\fR\aclaimId\x12\x1f\n" +
	"\vclaim_state\x18\x05 \x01(\rR\n" +
	"claimState\x12\x16\n" +
	"\x06result\x18\x06 \x01(\rR\x06result\"\xd2\x04\n" +
	"\vContextBody\x12\x14\n" +
	"\x05stage\x18\x01 \x01(\rR\x05stage\x12\x18\n" +
	"\aharness\x18\x02 \x01(\tR\aharness\x12'\n" +
	"\x0fharness_version\x18\x03 \x01(\tR\x0eharnessVersion\x12\x1f\n" +
	"\vagent_label\x18\x04 \x01(\tR\n" +
	"agentLabel\x12\x1f\n" +
	"\vsession_ids\x18\x05 \x03(\tR\n" +
	"sessionIds\x12\x14\n" +
	"\x05model\x18\x06 \x01(\tR\x05model\x12'\n" +
	"\x0fpermission_mode\x18\a \x01(\tR\x0epermissionMode\x12\x17\n" +
	"\arepo_id\x18\b \x01(\fR\x06repoId\x12\x18\n" +
	"\aproject\x18\t \x01(\tR\aproject\x12\x16\n" +
	"\x06branch\x18\n" +
	" \x01(\tR\x06branch\x12\x14\n" +
	"\x05title\x18\v \x01(\tR\x05title\x12O\n" +
	"\x11instruction_files\x18\f \x03(\v2\".urnetwork.sidecar.InstructionFileR\x10instructionFiles\x12 \n" +
	"\vtruncations\x18\r \x03(\tR\vtruncations\x12#\n" +
	"\rconfig_sha256\x18\x0e \x01(\fR\fconfigSha256\x12(\n" +
	"\x10continues_run_id\x18\x0f \x01(\fR\x0econtinuesRunId\x12,\n" +
	"\x12continues_entry_id\x18\x10 \x01(\fR\x10continuesEntryId\x12\x18\n" +
	"\aprompts\x18\x11 \x03(\tR\aprompts\"g\n" +
	"\x0fInstructionFile\x12\x14\n" +
	"\x05scope\x18\x01 \x01(\rR\x05scope\x12\x12\n" +
	"\x04name\x18\x02 \x01(\tR\x04name\x12\x16\n" +
	"\x06sha256\x18\x03 \x01(\fR\x06sha256\x12\x12\n" +
	"\x04size\x18\x04 \x01(\x04R\x04size\"\xce\x02\n" +
	"\n" +
	"ChangeBody\x12\x17\n" +
	"\arepo_id\x18\x01 \x01(\fR\x06repoId\x12\x18\n" +
	"\aproject\x18\x02 \x01(\tR\aproject\x12\x1f\n" +
	"\vbase_commit\x18\x03 \x01(\tR\n" +
	"baseCommit\x12\x18\n" +
	"\acommits\x18\x04 \x03(\tR\acommits\x12\x1d\n" +
	"\n" +
	"path_count\x18\x05 \x01(\rR\tpathCount\x12\x1d\n" +
	"\n" +
	"edit_count\x18\x06 \x01(\rR\teditCount\x12\x1f\n" +
	"\vshell_count\x18\a \x01(\rR\n" +
	"shellCount\x12#\n" +
	"\rforeign_count\x18\b \x01(\rR\fforeignCount\x12\x18\n" +
	"\acapture\x18\t \x01(\rR\acapture\x124\n" +
	"\x05paths\x18\n" +
	" \x03(\v2\x1e.urnetwork.sidecar.ChangedPathR\x05paths\"\xc3\x01\n" +
	"\vChangedPath\x12\x12\n" +
	"\x04path\x18\x01 \x01(\tR\x04path\x12#\n" +
	"\rbefore_sha256\x18\x02 \x01(\fR\fbeforeSha256\x12!\n" +
	"\fafter_sha256\x18\x03 \x01(\fR\vafterSha256\x12\x12\n" +
	"\x04mode\x18\x04 \x01(\rR\x04mode\x12 \n" +
	"\vattribution\x18\x05 \x01(\rR\vattribution\x12\"\n" +
	"\rblob_entry_id\x18\x06 \x01(\fR\vblobEntryId\"\xdb\x01\n" +
	"\x0ePermissionBody\x12\x1a\n" +
	"\bdecision\x18\x01 \x01(\rR\bdecision\x12\x1d\n" +
	"\n" +
	"decided_by\x18\x02 \x01(\rR\tdecidedBy\x12'\n" +
	"\x0fpermission_mode\x18\x03 \x01(\tR\x0epermissionMode\x12\x1d\n" +
	"\n" +
	"tool_class\x18\x04 \x01(\rR\ttoolClass\x12\x1b\n" +
	"\ttool_name\x18\x05 \x01(\tR\btoolName\x12)\n" +
	"\x10arguments_sha256\x18\x06 \x01(\fR\x0fargumentsSha256\"\x9a\x02\n" +
	"\x0fApprovalUseBody\x12\x1f\n" +
	"\vapproval_id\x18\x01 \x01(\fR\n" +
	"approvalId\x12\x1b\n" +
	"\tuse_index\x18\x02 \x01(\rR\buseIndex\x12%\n" +
	"\x0epayload_sha256\x18\x03 \x01(\fR\rpayloadSha256\x12\x1d\n" +
	"\n" +
	"effect_key\x18\x04 \x01(\fR\teffectKey\x12\x14\n" +
	"\x05state\x18\x05 \x01(\rR\x05state\x12\x1d\n" +
	"\n" +
	"effect_ref\x18\x06 \x01(\fR\teffectRef\x12'\n" +
	"\x0freserved_millis\x18\a \x01(\x03R\x0ereservedMillis\x12%\n" +
	"\x0eoutcome_millis\x18\b \x01(\x03R\routcomeMillis\"\x91\x02\n" +
	"\tRouteBody\x12\x14\n" +
	"\x05event\x18\x01 \x01(\rR\x05event\x12\x12\n" +
	"\x04kind\x18\x02 \x01(\rR\x04kind\x12\x17\n" +
	"\arule_id\x18\x03 \x01(\fR\x06ruleId\x12*\n" +
	"\x11target_sidecar_id\x18\x04 \x01(\fR\x0ftargetSidecarId\x12\x1f\n" +
	"\vtarget_port\x18\x05 \x01(\rR\n" +
	"targetPort\x12\x14\n" +
	"\x05cidrs\x18\x06 \x03(\tR\x05cidrs\x12%\n" +
	"\x0eexpires_millis\x18\a \x01(\x03R\rexpiresMillis\x12\x1f\n" +
	"\vapproval_id\x18\b \x01(\fR\n" +
	"approvalId\x12\x16\n" +
	"\x06reason\x18\t \x01(\rR\x06reason\"\xe2\x01\n" +
	"\vPublishBody\x12\x14\n" +
	"\x05event\x18\x01 \x01(\rR\x05event\x12\x12\n" +
	"\x04host\x18\x02 \x01(\tR\x04host\x12\x12\n" +
	"\x04port\x18\x03 \x01(\rR\x04port\x12\x1a\n" +
	"\baudience\x18\x04 \x01(\rR\baudience\x12\x19\n" +
	"\bapp_mode\x18\x05 \x01(\rR\aappMode\x12%\n" +
	"\x0eexpires_millis\x18\x06 \x01(\x03R\rexpiresMillis\x12\x1f\n" +
	"\vapproval_id\x18\a \x01(\fR\n" +
	"approvalId\x12\x16\n" +
	"\x06reason\x18\b \x01(\rR\x06reason\"\xfa\x01\n" +
	"\vRestoreBody\x12&\n" +
	"\x0frestored_run_id\x18\x01 \x01(\fR\rrestoredRunId\x12\x1d\n" +
	"\n" +
	"preview_id\x18\x02 \x01(\fR\tpreviewId\x12\x1f\n" +
	"\vapproval_id\x18\x03 \x01(\fR\n" +
	"approvalId\x12%\n" +
	"\x0erestored_count\x18\x04 \x01(\rR\rrestoredCount\x12%\n" +
	"\x0econflict_count\x18\x05 \x01(\rR\rconflictCount\x125\n" +
	"\x05paths\x18\x06 \x03(\v2\x1f.urnetwork.sidecar.RestoredPathR\x05paths\"R\n" +
	"\fRestoredPath\x12\x12\n" +
	"\x04path\x18\x01 \x01(\tR\x04path\x12\x16\n" +
	"\x06result\x18\x02 \x01(\tR\x06result\x12\x16\n" +
	"\x06copies\x18\x03 \x03(\tR\x06copies\"\xc0\x02\n" +
	"\x0eMembershipBody\x12\x14\n" +
	"\x05event\x18\x01 \x01(\rR\x05event\x12\x1b\n" +
	"\tmember_id\x18\x02 \x01(\fR\bmemberId\x12\x1d\n" +
	"\n" +
	"sidecar_id\x18\x03 \x01(\fR\tsidecarId\x12\x19\n" +
	"\bgroup_id\x18\x04 \x01(\fR\agroupId\x12#\n" +
	"\rauth_position\x18\x05 \x01(\x04R\fauthPosition\x12)\n" +
	"\x10statement_sha256\x18\x06 \x01(\fR\x0fstatementSha256\x12\x1a\n" +
	"\bevidence\x18\a \x01(\rR\bevidence\x12\x1c\n" +
	"\tassertion\x18\b \x01(\fR\tassertion\x12\x16\n" +
	"\x06reason\x18\t \x01(\rR\x06reason\x12\x1f\n" +
	"\vsigned_type\x18\n" +
	" \x01(\rR\n" +
	"signedType\"\xf8\x01\n" +
	"\aKeyBody\x12\x14\n" +
	"\x05event\x18\x01 \x01(\rR\x05event\x12\x19\n" +
	"\bgroup_id\x18\x02 \x01(\fR\agroupId\x12\x1e\n" +
	"\n" +
	"generation\x18\x03 \x01(\x04R\n" +
	"generation\x12\x14\n" +
	"\x05cause\x18\x04 \x01(\rR\x05cause\x12\x15\n" +
	"\x06key_id\x18\x05 \x01(\fR\x05keyId\x12#\n" +
	"\rauth_position\x18\x06 \x01(\x04R\fauthPosition\x12)\n" +
	"\x10statement_sha256\x18\a \x01(\fR\x0fstatementSha256\x12\x1f\n" +
	"\vsigned_type\x18\b \x01(\rR\n" +
	"signedType\"c\n" +
	"\bReadBody\x12\x1d\n" +
	"\n" +
	"object_ids\x18\x01 \x03(\fR\tobjectIds\x12\x18\n" +
	"\apurpose\x18\x02 \x01(\rR\apurpose\x12\x1e\n" +
	"\vread_log_id\x18\x03 \x01(\fR\treadLogId\"\xab\x01\n" +
	"\vErasureBody\x12\x1d\n" +
	"\n" +
	"erasure_id\x18\x01 \x01(\fR\terasureId\x12\x1b\n" +
	"\tentry_ids\x18\x02 \x03(\fR\bentryIds\x12\x16\n" +
	"\x06reason\x18\x03 \x01(\rR\x06reason\x12\x1d\n" +
	"\n" +
	"request_id\x18\x04 \x01(\fR\trequestId\x12)\n" +
	"\x10announcement_ids\x18\x05 \x03(\fR\x0fannouncementIds\"\xaf\x01\n" +
	"\rInventoryBody\x12*\n" +
	"\x11sponsor_member_id\x18\x01 \x01(\fR\x0fsponsorMemberId\x12\x10\n" +
	"\x03day\x18\x02 \x01(\rR\x03day\x12%\n" +
	"\x0ecredential_ref\x18\x03 \x01(\fR\rcredentialRef\x129\n" +
	"\x06agents\x18\x04 \x03(\v2!.urnetwork.sidecar.InventoryAgentR\x06agents\"\xc6\x02\n" +
	"\x0eInventoryAgent\x12\x19\n" +
	"\bagent_id\x18\x01 \x01(\fR\aagentId\x12\x1f\n" +
	"\vagent_label\x18\x02 \x01(\tR\n" +
	"agentLabel\x12!\n" +
	"\fagent_source\x18\x03 \x01(\rR\vagentSource\x12\x1c\n" +
	"\tharnesses\x18\x04 \x03(\tR\tharnesses\x12\x16\n" +
	"\x06models\x18\x05 \x03(\tR\x06models\x12\x19\n" +
	"\brepo_ids\x18\x06 \x03(\fR\arepoIds\x12\x1a\n" +
	"\bprojects\x18\a \x03(\tR\bprojects\x12\x12\n" +
	"\x04runs\x18\b \x01(\rR\x04runs\x12*\n" +
	"\x11first_seen_millis\x18\t \x01(\x03R\x0ffirstSeenMillis\x12(\n" +
	"\x10last_seen_millis\x18\n" +
	" \x01(\x03R\x0elastSeenMillis\"\x94\x01\n" +
	"\x0fAgentSignedBody\x12\x12\n" +
	"\x04body\x18\x01 \x01(\fR\x04body\x12\x19\n" +
	"\bagent_id\x18\x02 \x01(\fR\aagentId\x12\x15\n" +
	"\x06key_id\x18\x03 \x01(\fR\x05keyId\x12\x1c\n" +
	"\tsignature\x18\x04 \x01(\fR\tsignature\x12\x1d\n" +
	"\n" +
	"agent_cert\x18\x05 \x01(\fR\tagentCert\"c\n" +
	"\aOpening\x12\x16\n" +
	"\x06header\x18\x01 \x01(\fR\x06header\x12\x12\n" +
	"\x04salt\x18\x02 \x01(\fR\x04salt\x12\x12\n" +
	"\x04body\x18\x03 \x01(\fR\x04body\x12\x18\n" +
	"\aversion\x18\x04 \x01(\rR\aversion\"@\n" +
	"\bCopyBody\x124\n" +
	"\aentries\x18\x01 \x03(\v2\x1a.urnetwork.sidecar.OpeningR\aentries\"\x82\x01\n" +
	"\x0eTranscriptBody\x12\x1d\n" +
	"\n" +
	"first_line\x18\x01 \x01(\x04R\tfirstLine\x12\x1d\n" +
	"\n" +
	"line_count\x18\x02 \x01(\rR\tlineCount\x12\x14\n" +
	"\x05lines\x18\x03 \x01(\fR\x05lines\x12\x1c\n" +
	"\ttruncated\x18\x04 \x01(\bR\ttruncated\"\xb3\x02\n" +
	"\fToolCallBody\x12\x1b\n" +
	"\ttool_name\x18\x01 \x01(\tR\btoolName\x12\x1e\n" +
	"\vtool_use_id\x18\x02 \x01(\tR\ttoolUseId\x12\x1d\n" +
	"\n" +
	"tool_class\x18\x03 \x01(\rR\ttoolClass\x12\x14\n" +
	"\x05input\x18\x04 \x01(\fR\x05input\x12\x16\n" +
	"\x06output\x18\x05 \x01(\fR\x06output\x12%\n" +
	"\x0estarted_millis\x18\x06 \x01(\x03R\rstartedMillis\x12!\n" +
	"\fended_millis\x18\a \x01(\x03R\vendedMillis\x12\x1b\n" +
	"\texit_code\x18\b \x01(\x05R\bexitCode\x12\x14\n" +
	"\x05paths\x18\t \x03(\tR\x05paths\x12\x1c\n" +
	"\ttruncated\x18\n" +
	" \x01(\bR\ttruncated\"j\n" +
	"\rHookEventBody\x12\x14\n" +
	"\x05event\x18\x01 \x01(\tR\x05event\x12\x18\n" +
	"\apayload\x18\x02 \x01(\fR\apayload\x12)\n" +
	"\x10arguments_sha256\x18\x03 \x01(\fR\x0fargumentsSha256\"n\n" +
	"\rFileEventBody\x12\x12\n" +
	"\x04path\x18\x01 \x01(\tR\x04path\x12\x0e\n" +
	"\x02op\x18\x02 \x01(\rR\x02op\x12!\n" +
	"\fafter_sha256\x18\x03 \x01(\fR\vafterSha256\x12\x16\n" +
	"\x06millis\x18\x04 \x01(\x03R\x06millis\"\x80\x01\n" +
	"\bBlobBody\x12\x12\n" +
	"\x04path\x18\x01 \x01(\tR\x04path\x12\x18\n" +
	"\acontent\x18\x02 \x01(\fR\acontent\x12\x16\n" +
	"\x06sha256\x18\x03 \x01(\fR\x06sha256\x12\x1a\n" +
	"\bredacted\x18\x04 \x01(\bR\bredacted\x12\x12\n" +
	"\x04size\x18\x05 \x01(\x04R\x04size\"^\n" +
	"\x0fLedgerScopeBody\x12\x19\n" +
	"\brepo_ids\x18\x01 \x03(\fR\arepoIds\x12\x1a\n" +
	"\bprojects\x18\x02 \x03(\tR\bprojects\x12\x14\n" +
	"\x05kinds\x18\x03 \x03(\rR\x05kinds\"\x90\x02\n" +
	"\x0fLogSettingsBody\x12\x16\n" +
	"\x06origin\x18\x01 \x01(\tR\x06origin\x126\n" +
	"\x17checkpointer_sidecar_id\x18\x02 \x01(\fR\x15checkpointerSidecarId\x12&\n" +
	"\x0fnote_public_key\x18\x03 \x01(\fR\rnotePublicKey\x12)\n" +
	"\x10interval_seconds\x18\x04 \x01(\rR\x0fintervalSeconds\x12;\n" +
	"\twitnesses\x18\x05 \x03(\v2\x1d.urnetwork.sidecar.LogWitnessR\twitnesses\x12\x1d\n" +
	"\n" +
	"from_batch\x18\x06 \x01(\x04R\tfromBatch\"F\n" +
	"\n" +
	"LogWitness\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x10\n" +
	"\x03url\x18\x02 \x01(\tR\x03url\x12\x12\n" +
	"\x04vkey\x18\x03 \x01(\tR\x04vkey\"\xee\x01\n" +
	"\x11LogCheckpointBody\x12\x14\n" +
	"\x05batch\x18\x01 \x01(\x04R\x05batch\x12\x1f\n" +
	"\vfirst_index\x18\x02 \x01(\x04R\n" +
	"firstIndex\x12:\n" +
	"\bfrontier\x18\x03 \x03(\v2\x1e.urnetwork.sidecar.LogFrontierR\bfrontier\x12\x16\n" +
	"\x06leaves\x18\x04 \x01(\fR\x06leaves\x12\x12\n" +
	"\x04note\x18\x05 \x01(\fR\x04note\x12:\n" +
	"\bcosigned\x18\x06 \x03(\v2\x1e.urnetwork.sidecar.LogCosignedR\bcosigned\"T\n" +
	"\vLogFrontier\x12\x15\n" +
	"\x06ref_id\x18\x01 \x01(\fR\x05refId\x12\x18\n" +
	"\aversion\x18\x02 \x01(\x04R\aversion\x12\x14\n" +
	"\x05chain\x18\x03 \x01(\fR\x05chain\"9\n" +
	"\vLogCosigned\x12\x14\n" +
	"\x05batch\x18\x01 \x01(\x04R\x05batch\x12\x14\n" +
	"\x05lines\x18\x02 \x01(\fR\x05lines\"\xb0\x02\n" +
	"\x10DisclosurePacket\x12\x18\n" +
	"\aversion\x18\x01 \x01(\rR\aversion\x12\x15\n" +
	"\x06log_id\x18\x02 \x01(\fR\x05logId\x12\x16\n" +
	"\x06origin\x18\x03 \x01(\tR\x06origin\x12%\n" +
	"\x0ecreated_millis\x18\x04 \x01(\x03R\rcreatedMillis\x12;\n" +
	"\aentries\x18\x05 \x03(\v2!.urnetwork.sidecar.DisclosedEntryR\aentries\x12 \n" +
	"\vcheckpoints\x18\x06 \x03(\fR\vcheckpoints\x123\n" +
	"\x04keys\x18\a \x03(\v2\x1f.urnetwork.sidecar.DisclosedKeyR\x04keys\x12\x18\n" +
	"\apurpose\x18\b \x01(\tR\apurpose\"\xe2\x01\n" +
	"\x0eDisclosedEntry\x124\n" +
	"\aopening\x18\x01 \x01(\v2\x1a.urnetwork.sidecar.OpeningR\aopening\x12\x1d\n" +
	"\n" +
	"leaf_index\x18\x02 \x01(\x04R\tleafIndex\x12\x1e\n" +
	"\n" +
	"checkpoint\x18\x03 \x01(\rR\n" +
	"checkpoint\x12%\n" +
	"\x0einclusion_path\x18\x04 \x03(\fR\rinclusionPath\x124\n" +
	"\acontent\x18\x05 \x03(\v2\x1a.urnetwork.sidecar.OpeningR\acontent\"\x8b\x01\n" +
	"\fDisclosedKey\x12\x15\n" +
	"\x06key_id\x18\x01 \x01(\fR\x05keyId\x12\x1d\n" +
	"\n" +
	"sidecar_id\x18\x02 \x01(\fR\tsidecarId\x12\x10\n" +
	"\x03alg\x18\x03 \x01(\rR\x03alg\x12\x1d\n" +
	"\n" +
	"public_key\x18\x04 \x01(\fR\tpublicKey\x12\x14\n" +
	"\x05label\x18\x05 \x01(\tR\x05label\"\xbf\x02\n" +
	"\x0eDisclosureBody\x12\x10\n" +
	"\x03act\x18\x01 \x01(\rR\x03act\x12#\n" +
	"\rpacket_sha256\x18\x02 \x01(\fR\fpacketSha256\x12\x1b\n" +
	"\tentry_ids\x18\x03 \x03(\fR\bentryIds\x12\x1c\n" +
	"\trecipient\x18\x04 \x01(\tR\trecipient\x12\x18\n" +
	"\apurpose\x18\x05 \x01(\tR\apurpose\x12!\n" +
	"\fsince_millis\x18\x06 \x01(\x03R\vsinceMillis\x12!\n" +
	"\funtil_millis\x18\a \x01(\x03R\vuntilMillis\x12\x16\n" +
	"\x06format\x18\b \x01(\rR\x06format\x12\x16\n" +
	"\x06bodies\x18\t \x01(\bR\x06bodies\x12\x14\n" +
	"\x05kinds\x18\n" +
	" \x03(\rR\x05kinds\x12\x15\n" +
	"\x06run_id\x18\v \x01(\fR\x05runId\"\x8e\x01\n" +
	"\x0fAttestationBody\x12\x1c\n" +
	"\tstatement\x18\x01 \x01(\rR\tstatement\x12\x18\n" +
	"\acommits\x18\x02 \x03(\tR\acommits\x12\x17\n" +
	"\arepo_id\x18\x03 \x01(\fR\x06repoId\x12\x12\n" +
	"\x04note\x18\x04 \x01(\tR\x04note\x12\x16\n" +
	"\x06sshsig\x18\x05 \x01(\fR\x06sshsig\"\x8e\x03\n" +
	"\rModelManifest\x12\x12\n" +
	"\x04port\x18\x01 \x01(\rR\x04port\x12>\n" +
	"\vserved_name\x18\x02 \x01(\v2\x1d.urnetwork.sidecar.ModelFieldR\n" +
	"servedName\x125\n" +
	"\x06engine\x18\x03 \x01(\v2\x1d.urnetwork.sidecar.ModelFieldR\x06engine\x12D\n" +
	"\x0eengine_version\x18\x04 \x01(\v2\x1d.urnetwork.sidecar.ModelFieldR\rengineVersion\x12A\n" +
	"\fquantization\x18\x05 \x01(\v2\x1d.urnetwork.sidecar.ModelFieldR\fquantization\x12D\n" +
	"\x0eweights_digest\x18\x06 \x01(\v2\x1d.urnetwork.sidecar.ModelFieldR\rweightsDigest\x12#\n" +
	"\rweights_bytes\x18\a \x01(\x04R\fweightsBytes\">\n" +
	"\n" +
	"ModelField\x12\x14\n" +
	"\x05value\x18\x01 \x01(\tR\x05value\x12\x1a\n" +
	"\bevidence\x18\x02 \x01(\rR\bevidence\"\xfc\x04\n" +
	"\rModelCallBody\x12\x14\n" +
	"\x05model\x18\x01 \x01(\tR\x05model\x12\x1a\n" +
	"\bprovider\x18\x02 \x01(\tR\bprovider\x12\x1d\n" +
	"\n" +
	"request_id\x18\x03 \x01(\tR\trequestId\x12!\n" +
	"\finput_tokens\x18\x04 \x01(\x04R\vinputTokens\x12#\n" +
	"\routput_tokens\x18\x05 \x01(\x04R\foutputTokens\x12*\n" +
	"\x11cache_read_tokens\x18\x06 \x01(\x04R\x0fcacheReadTokens\x12,\n" +
	"\x12cache_write_tokens\x18\a \x01(\x04R\x10cacheWriteTokens\x12,\n" +
	"\x12reported_micro_usd\x18\b \x01(\x04R\x10reportedMicroUsd\x12%\n" +
	"\x0estarted_millis\x18\t \x01(\x03R\rstartedMillis\x12'\n" +
	"\x0fduration_millis\x18\n" +
	" \x01(\rR\x0edurationMillis\x12F\n" +
	"\vattestation\x18\v \x01(\v2$.urnetwork.sidecar.AttestationResultR\vattestation\x12\x14\n" +
	"\x05route\x18\f \x01(\tR\x05route\x12'\n" +
	"\x0fcatalog_version\x18\r \x01(\x04R\x0ecatalogVersion\x129\n" +
	"\bplatform\x18\x0e \x01(\v2\x1d.urnetwork.sidecar.ModelFieldR\bplatform\x128\n" +
	"\acontext\x18\x0f \x01(\v2\x1e.urnetwork.sidecar.CallContextR\acontext\"\xfc\x02\n" +
	"\x10SessionEntryBody\x12\x17\n" +
	"\anode_id\x18\x01 \x01(\fR\x06nodeId\x12$\n" +
	"\x0eparent_node_id\x18\x02 \x01(\fR\fparentNodeId\x12\"\n" +
	"\rparent_run_id\x18\x03 \x01(\fR\vparentRunId\x12\x12\n" +
	"\x04type\x18\x04 \x01(\rR\x04type\x12\x12\n" +
	"\x04item\x18\x05 \x01(\fR\x04item\x124\n" +
	"\x05parts\x18\x06 \x03(\v2\x1e.urnetwork.sidecar.SessionPartR\x05parts\x12\x1f\n" +
	"\vitem_sha256\x18\a \x01(\fR\n" +
	"itemSha256\x12!\n" +
	"\fchain_sha256\x18\b \x01(\fR\vchainSha256\x12\x17\n" +
	"\asame_as\x18\t \x01(\fR\x06sameAs\x12\x1e\n" +
	"\n" +
	"redactions\x18\n" +
	" \x01(\rR\n" +
	"redactions\x12\x14\n" +
	"\x05stubs\x18\v \x01(\rR\x05stubs\x12\x14\n" +
	"\x05marks\x18\f \x01(\rR\x05marks\"\xb2\x01\n" +
	"\vSessionPart\x12\x18\n" +
	"\apointer\x18\x01 \x01(\tR\apointer\x12\x16\n" +
	"\x06sha256\x18\x02 \x01(\fR\x06sha256\x12\x12\n" +
	"\x04size\x18\x03 \x01(\x04R\x04size\x12\x1d\n" +
	"\n" +
	"media_type\x18\x04 \x01(\tR\tmediaType\x12$\n" +
	"\x0eblob_entry_ids\x18\x05 \x03(\fR\fblobEntryIds\x12\x18\n" +
	"\aomitted\x18\x06 \x01(\bR\aomitted\"x\n" +
	"\x0fSessionBlobBody\x12\x1f\n" +
	"\vpart_sha256\x18\x01 \x01(\fR\n" +
	"partSha256\x12\x14\n" +
	"\x05index\x18\x02 \x01(\rR\x05index\x12\x14\n" +
	"\x05count\x18\x03 \x01(\rR\x05count\x12\x18\n" +
	"\acontent\x18\x04 \x01(\fR\acontent\"\x9a\x02\n" +
	"\vCallContext\x12\"\n" +
	"\rinput_node_id\x18\x01 \x01(\fR\vinputNodeId\x12&\n" +
	"\x0foutput_node_ids\x18\x02 \x03(\fR\routputNodeIds\x12$\n" +
	"\x0esystem_node_id\x18\x03 \x01(\fR\fsystemNodeId\x12%\n" +
	"\x0erequest_sha256\x18\x04 \x01(\fR\rrequestSha256\x12\x14\n" +
	"\x05exact\x18\x05 \x01(\bR\x05exact\x12\x1a\n" +
	"\brenderer\x18\x06 \x01(\tR\brenderer\x12\x16\n" +
	"\x06params\x18\a \x01(\fR\x06params\x12(\n" +
	"\x10sign_in_withheld\x18\b \x01(\bR\x0esignInWithheld\"\xd4\x01\n" +
	"\x0eApprovalNotice\x12\x1f\n" +
	"\vapproval_id\x18\x01 \x01(\fR\n" +
	"approvalId\x120\n" +
	"\x14requester_sidecar_id\x18\x02 \x01(\fR\x12requesterSidecarId\x12\x1b\n" +
	"\tentry_seq\x18\x03 \x01(\x04R\bentrySeq\x12(\n" +
	"\x10not_after_millis\x18\x04 \x01(\x03R\x0enotAfterMillis\x12\x14\n" +
	"\x05state\x18\x05 \x01(\rR\x05state\x12\x12\n" +
	"\x04kind\x18\x06 \x01(\rR\x04kind\"g\n" +
	"\vRunCostBody\x123\n" +
	"\x05usage\x18\x01 \x03(\v2\x1d.urnetwork.sidecar.ModelUsageR\x05usage\x12#\n" +
	"\rmetered_bytes\x18\x02 \x01(\x04R\fmeteredBytes\"\xa4\x02\n" +
	"\n" +
	"ModelUsage\x12\x14\n" +
	"\x05model\x18\x01 \x01(\tR\x05model\x12!\n" +
	"\finput_tokens\x18\x02 \x01(\x04R\vinputTokens\x12#\n" +
	"\routput_tokens\x18\x03 \x01(\x04R\foutputTokens\x12*\n" +
	"\x11cache_read_tokens\x18\x04 \x01(\x04R\x0fcacheReadTokens\x12,\n" +
	"\x12cache_write_tokens\x18\x05 \x01(\x04R\x10cacheWriteTokens\x12\x14\n" +
	"\x05calls\x18\x06 \x01(\x04R\x05calls\x12,\n" +
	"\x12reported_micro_usd\x18\a \x01(\x04R\x10reportedMicroUsd\x12\x1a\n" +
	"\bcomplete\x18\b \x01(\bR\bcomplete\"\xa3\x04\n" +
	"\x12SupportMessageBody\x12\x1c\n" +
	"\tdirection\x18\x01 \x01(\rR\tdirection\x12\x18\n" +
	"\aproduct\x18\x02 \x01(\tR\aproduct\x12\x14\n" +
	"\x05entry\x18\x03 \x01(\tR\x05entry\x12\x10\n" +
	"\x03seq\x18\x04 \x01(\rR\x03seq\x12\x12\n" +
	"\x04type\x18\x05 \x01(\rR\x04type\x12\x12\n" +
	"\x04tier\x18\x06 \x01(\rR\x04tier\x12\x1d\n" +
	"\n" +
	"client_ref\x18\a \x01(\fR\tclientRef\x12\x12\n" +
	"\x04text\x18\b \x01(\tR\x04text\x12\x1f\n" +
	"\vagent_label\x18\t \x01(\tR\n" +
	"agentLabel\x129\n" +
	"\x06bundle\x18\n" +
	" \x01(\v2!.urnetwork.sidecar.BundleManifestR\x06bundle\x123\n" +
	"\x05files\x18\v \x03(\v2\x1d.urnetwork.sidecar.FileFieldsR\x05files\x12\x1f\n" +
	"\vbody_sha256\x18\f \x01(\fR\n" +
	"bodySha256\x12\x1d\n" +
	"\n" +
	"body_bytes\x18\r \x01(\x04R\tbodyBytes\x12\x16\n" +
	"\x06status\x18\x0e \x01(\rR\x06status\x12\x19\n" +
	"\bfixed_in\x18\x0f \x01(\tR\afixedIn\x12\x1f\n" +
	"\vapproval_id\x18\x10 \x01(\fR\n" +
	"approvalId\x12-\n" +
	"\x12disclosure_version\x18\x11 \x01(\rR\x11disclosureVersion*\xbd\b\n" +
	"\x11SidecarActionKind\x12#\n" +
	"\x1fSIDECAR_ACTION_KIND_UNSPECIFIED\x10\x00\x12\x1f\n" +
	"\x1bSIDECAR_ACTION_KIND_PUBLISH\x10\x01\x12\x1e\n" +
	"\x1aSIDECAR_ACTION_KIND_LISTEN\x10\x02\x12\x1f\n" +
	"\x1bSIDECAR_ACTION_KIND_FORWARD\x10\x03\x12\x1e\n" +
	"\x1aSIDECAR_ACTION_KIND_EXPOSE\x10\x04\x12%\n" +
	"!SIDECAR_ACTION_KIND_EGRESS_CHANGE\x10\x05\x12\x1e\n" +
	"\x1aSIDECAR_ACTION_KIND_INVITE\x10\x06\x12\x1d\n" +
	"\x19SIDECAR_ACTION_KIND_SHARE\x10\a\x12$\n" +
	" SIDECAR_ACTION_KIND_ALIAS_CREATE\x10\b\x12$\n" +
	" SIDECAR_ACTION_KIND_ALIAS_DELETE\x10\t\x12*\n" +
	"&SIDECAR_ACTION_KIND_AGENT_CONFIG_WRITE\x10\n" +
	"\x12+\n" +
	"'SIDECAR_ACTION_KIND_AGENT_CONFIG_DELETE\x10\v\x12\x1f\n" +
	"\x1bSIDECAR_ACTION_KIND_DNS_SET\x10\f\x12\"\n" +
	"\x1eSIDECAR_ACTION_KIND_DNS_DELETE\x10\r\x12!\n" +
	"\x1dSIDECAR_ACTION_KIND_MAIL_SEND\x10\x0e\x12&\n" +
	"\"SIDECAR_ACTION_KIND_ACCESS_REQUEST\x10\x0f\x12\x1f\n" +
	"\x1bSIDECAR_ACTION_KIND_PAYMENT\x10\x10\x12\x1f\n" +
	"\x1bSIDECAR_ACTION_KIND_RESTORE\x10\x11\x120\n" +
	",SIDECAR_ACTION_KIND_MAIL_TLS_UNAUTHENTICATED\x10\x12\x12&\n" +
	"\"SIDECAR_ACTION_KIND_ENCLAVE_CREATE\x10\x13\x12-\n" +
	")SIDECAR_ACTION_KIND_ENCLAVE_EGRESS_DIRECT\x10\x14\x12,\n" +
	"(SIDECAR_ACTION_KIND_COMPUTE_BUDGET_RAISE\x10\x15\x12&\n" +
	"\"SIDECAR_ACTION_KIND_ENCLAVE_DELETE\x10\x16\x12*\n" +
	"&SIDECAR_ACTION_KIND_FETCH_UNLISTED_URL\x10\x17\x12$\n" +
	" SIDECAR_ACTION_KIND_TAINTED_SEND\x10\x18\x12&\n" +
	"\"SIDECAR_ACTION_KIND_CALENDAR_WRITE\x10\x19\x12%\n" +
	"!SIDECAR_ACTION_KIND_SERVICE_WRITE\x10\x1a\x12$\n" +
	" SIDECAR_ACTION_KIND_SUPPORT_SEND\x10\x1b*[\n" +
	"\vSidecarRisk\x12\x1c\n" +
	"\x18SIDECAR_RISK_UNSPECIFIED\x10\x00\x12\x17\n" +
	"\x13SIDECAR_RISK_NORMAL\x10\x01\x12\x15\n" +
	"\x11SIDECAR_RISK_HIGH\x10\x02*l\n" +
	"\x0fApprovalVerdict\x12 \n" +
	"\x1cAPPROVAL_VERDICT_UNSPECIFIED\x10\x00\x12\x1c\n" +
	"\x18APPROVAL_VERDICT_APPROVE\x10\x01\x12\x19\n" +
	"\x15APPROVAL_VERDICT_DENY\x10\x02*\xa8\x01\n" +
	"\x0fApprovalChannel\x12 \n" +
	"\x1cAPPROVAL_CHANNEL_UNSPECIFIED\x10\x00\x12\x1b\n" +
	"\x17APPROVAL_CHANNEL_DEVICE\x10\x01\x12\x1d\n" +
	"\x19APPROVAL_CHANNEL_PRESENCE\x10\x02\x12\x1c\n" +
	"\x18APPROVAL_CHANNEL_HARNESS\x10\x03\x12\x19\n" +
	"\x15APPROVAL_CHANNEL_AUTO\x10\x04B'Z%github.com/urnetwork/sidecar/protocolb\x06proto3"

var (
	file_protocol_record_proto_rawDescOnce sync.Once
	file_protocol_record_proto_rawDescData []byte
)

func file_protocol_record_proto_rawDescGZIP() []byte {
	file_protocol_record_proto_rawDescOnce.Do(func() {
		file_protocol_record_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_protocol_record_proto_rawDesc), len(file_protocol_record_proto_rawDesc)))
	})
	return file_protocol_record_proto_rawDescData
}

var file_protocol_record_proto_enumTypes = make([]protoimpl.EnumInfo, 4)
var file_protocol_record_proto_msgTypes = make([]protoimpl.MessageInfo, 76)
var file_protocol_record_proto_goTypes = []any{
	(SidecarActionKind)(0),         // 0: urnetwork.sidecar.SidecarActionKind
	(SidecarRisk)(0),               // 1: urnetwork.sidecar.SidecarRisk
	(ApprovalVerdict)(0),           // 2: urnetwork.sidecar.ApprovalVerdict
	(ApprovalChannel)(0),           // 3: urnetwork.sidecar.ApprovalChannel
	(*RecordHeader)(nil),           // 4: urnetwork.sidecar.RecordHeader
	(*ContentRef)(nil),             // 5: urnetwork.sidecar.ContentRef
	(*RecordEntry)(nil),            // 6: urnetwork.sidecar.RecordEntry
	(*CanonicalAction)(nil),        // 7: urnetwork.sidecar.CanonicalAction
	(*EnclaveFields)(nil),          // 8: urnetwork.sidecar.EnclaveFields
	(*BudgetFields)(nil),           // 9: urnetwork.sidecar.BudgetFields
	(*SendFields)(nil),             // 10: urnetwork.sidecar.SendFields
	(*RefFields)(nil),              // 11: urnetwork.sidecar.RefFields
	(*ContextFields)(nil),          // 12: urnetwork.sidecar.ContextFields
	(*CalendarEventAction)(nil),    // 13: urnetwork.sidecar.CalendarEventAction
	(*CalendarEventFields)(nil),    // 14: urnetwork.sidecar.CalendarEventFields
	(*ServiceCallFields)(nil),      // 15: urnetwork.sidecar.ServiceCallFields
	(*AutoFields)(nil),             // 16: urnetwork.sidecar.AutoFields
	(*SupportFields)(nil),          // 17: urnetwork.sidecar.SupportFields
	(*BundleManifest)(nil),         // 18: urnetwork.sidecar.BundleManifest
	(*BundleCodeCount)(nil),        // 19: urnetwork.sidecar.BundleCodeCount
	(*FileFields)(nil),             // 20: urnetwork.sidecar.FileFields
	(*CanonicalActionDetail5)(nil), // 21: urnetwork.sidecar.CanonicalActionDetail5
	(*CanonicalActionDetail)(nil),  // 22: urnetwork.sidecar.CanonicalActionDetail
	(*ApprovalRequest)(nil),        // 23: urnetwork.sidecar.ApprovalRequest
	(*ApprovalDecision)(nil),       // 24: urnetwork.sidecar.ApprovalDecision
	(*AutoVerdict)(nil),            // 25: urnetwork.sidecar.AutoVerdict
	(*ApprovalCancel)(nil),         // 26: urnetwork.sidecar.ApprovalCancel
	(*ReachReceipt)(nil),           // 27: urnetwork.sidecar.ReachReceipt
	(*Coverage)(nil),               // 28: urnetwork.sidecar.Coverage
	(*SeqRange)(nil),               // 29: urnetwork.sidecar.SeqRange
	(*RetentionPolicy)(nil),        // 30: urnetwork.sidecar.RetentionPolicy
	(*RecordDepositBatch)(nil),     // 31: urnetwork.sidecar.RecordDepositBatch
	(*RecordDeposit)(nil),          // 32: urnetwork.sidecar.RecordDeposit
	(*CoordinationBody)(nil),       // 33: urnetwork.sidecar.CoordinationBody
	(*ContextBody)(nil),            // 34: urnetwork.sidecar.ContextBody
	(*InstructionFile)(nil),        // 35: urnetwork.sidecar.InstructionFile
	(*ChangeBody)(nil),             // 36: urnetwork.sidecar.ChangeBody
	(*ChangedPath)(nil),            // 37: urnetwork.sidecar.ChangedPath
	(*PermissionBody)(nil),         // 38: urnetwork.sidecar.PermissionBody
	(*ApprovalUseBody)(nil),        // 39: urnetwork.sidecar.ApprovalUseBody
	(*RouteBody)(nil),              // 40: urnetwork.sidecar.RouteBody
	(*PublishBody)(nil),            // 41: urnetwork.sidecar.PublishBody
	(*RestoreBody)(nil),            // 42: urnetwork.sidecar.RestoreBody
	(*RestoredPath)(nil),           // 43: urnetwork.sidecar.RestoredPath
	(*MembershipBody)(nil),         // 44: urnetwork.sidecar.MembershipBody
	(*KeyBody)(nil),                // 45: urnetwork.sidecar.KeyBody
	(*ReadBody)(nil),               // 46: urnetwork.sidecar.ReadBody
	(*ErasureBody)(nil),            // 47: urnetwork.sidecar.ErasureBody
	(*InventoryBody)(nil),          // 48: urnetwork.sidecar.InventoryBody
	(*InventoryAgent)(nil),         // 49: urnetwork.sidecar.InventoryAgent
	(*AgentSignedBody)(nil),        // 50: urnetwork.sidecar.AgentSignedBody
	(*Opening)(nil),                // 51: urnetwork.sidecar.Opening
	(*CopyBody)(nil),               // 52: urnetwork.sidecar.CopyBody
	(*TranscriptBody)(nil),         // 53: urnetwork.sidecar.TranscriptBody
	(*ToolCallBody)(nil),           // 54: urnetwork.sidecar.ToolCallBody
	(*HookEventBody)(nil),          // 55: urnetwork.sidecar.HookEventBody
	(*FileEventBody)(nil),          // 56: urnetwork.sidecar.FileEventBody
	(*BlobBody)(nil),               // 57: urnetwork.sidecar.BlobBody
	(*LedgerScopeBody)(nil),        // 58: urnetwork.sidecar.LedgerScopeBody
	(*LogSettingsBody)(nil),        // 59: urnetwork.sidecar.LogSettingsBody
	(*LogWitness)(nil),             // 60: urnetwork.sidecar.LogWitness
	(*LogCheckpointBody)(nil),      // 61: urnetwork.sidecar.LogCheckpointBody
	(*LogFrontier)(nil),            // 62: urnetwork.sidecar.LogFrontier
	(*LogCosigned)(nil),            // 63: urnetwork.sidecar.LogCosigned
	(*DisclosurePacket)(nil),       // 64: urnetwork.sidecar.DisclosurePacket
	(*DisclosedEntry)(nil),         // 65: urnetwork.sidecar.DisclosedEntry
	(*DisclosedKey)(nil),           // 66: urnetwork.sidecar.DisclosedKey
	(*DisclosureBody)(nil),         // 67: urnetwork.sidecar.DisclosureBody
	(*AttestationBody)(nil),        // 68: urnetwork.sidecar.AttestationBody
	(*ModelManifest)(nil),          // 69: urnetwork.sidecar.ModelManifest
	(*ModelField)(nil),             // 70: urnetwork.sidecar.ModelField
	(*ModelCallBody)(nil),          // 71: urnetwork.sidecar.ModelCallBody
	(*SessionEntryBody)(nil),       // 72: urnetwork.sidecar.SessionEntryBody
	(*SessionPart)(nil),            // 73: urnetwork.sidecar.SessionPart
	(*SessionBlobBody)(nil),        // 74: urnetwork.sidecar.SessionBlobBody
	(*CallContext)(nil),            // 75: urnetwork.sidecar.CallContext
	(*ApprovalNotice)(nil),         // 76: urnetwork.sidecar.ApprovalNotice
	(*RunCostBody)(nil),            // 77: urnetwork.sidecar.RunCostBody
	(*ModelUsage)(nil),             // 78: urnetwork.sidecar.ModelUsage
	(*SupportMessageBody)(nil),     // 79: urnetwork.sidecar.SupportMessageBody
	(*bridge.Signed)(nil),          // 80: urnetwork.sidecar.Signed
	(*bridge.AuthPin)(nil),         // 81: urnetwork.sidecar.AuthPin
	(*AttestationResult)(nil),      // 82: urnetwork.sidecar.AttestationResult
}
var file_protocol_record_proto_depIdxs = []int32{
	5,  // 0: urnetwork.sidecar.RecordHeader.content:type_name -> urnetwork.sidecar.ContentRef
	80, // 1: urnetwork.sidecar.RecordEntry.header:type_name -> urnetwork.sidecar.Signed
	8,  // 2: urnetwork.sidecar.CanonicalAction.enclave:type_name -> urnetwork.sidecar.EnclaveFields
	9,  // 3: urnetwork.sidecar.CanonicalAction.budget:type_name -> urnetwork.sidecar.BudgetFields
	10, // 4: urnetwork.sidecar.CanonicalAction.send:type_name -> urnetwork.sidecar.SendFields
	12, // 5: urnetwork.sidecar.CanonicalAction.context:type_name -> urnetwork.sidecar.ContextFields
	13, // 6: urnetwork.sidecar.CanonicalAction.calendar_events:type_name -> urnetwork.sidecar.CalendarEventAction
	15, // 7: urnetwork.sidecar.CanonicalAction.service_call:type_name -> urnetwork.sidecar.ServiceCallFields
	16, // 8: urnetwork.sidecar.CanonicalAction.auto:type_name -> urnetwork.sidecar.AutoFields
	17, // 9: urnetwork.sidecar.CanonicalAction.support:type_name -> urnetwork.sidecar.SupportFields
	11, // 10: urnetwork.sidecar.SendFields.refs:type_name -> urnetwork.sidecar.RefFields
	9,  // 11: urnetwork.sidecar.SendFields.budget:type_name -> urnetwork.sidecar.BudgetFields
	14, // 12: urnetwork.sidecar.CalendarEventAction.before:type_name -> urnetwork.sidecar.CalendarEventFields
	18, // 13: urnetwork.sidecar.SupportFields.bundle:type_name -> urnetwork.sidecar.BundleManifest
	20, // 14: urnetwork.sidecar.SupportFields.files:type_name -> urnetwork.sidecar.FileFields
	19, // 15: urnetwork.sidecar.BundleManifest.codes:type_name -> urnetwork.sidecar.BundleCodeCount
	81, // 16: urnetwork.sidecar.ApprovalDecision.auth_pin:type_name -> urnetwork.sidecar.AuthPin
	25, // 17: urnetwork.sidecar.ApprovalDecision.auto_verdict:type_name -> urnetwork.sidecar.AutoVerdict
	29, // 18: urnetwork.sidecar.Coverage.bodies_dropped:type_name -> urnetwork.sidecar.SeqRange
	32, // 19: urnetwork.sidecar.RecordDepositBatch.entries:type_name -> urnetwork.sidecar.RecordDeposit
	35, // 20: urnetwork.sidecar.ContextBody.instruction_files:type_name -> urnetwork.sidecar.InstructionFile
	37, // 21: urnetwork.sidecar.ChangeBody.paths:type_name -> urnetwork.sidecar.ChangedPath
	43, // 22: urnetwork.sidecar.RestoreBody.paths:type_name -> urnetwork.sidecar.RestoredPath
	49, // 23: urnetwork.sidecar.InventoryBody.agents:type_name -> urnetwork.sidecar.InventoryAgent
	51, // 24: urnetwork.sidecar.CopyBody.entries:type_name -> urnetwork.sidecar.Opening
	60, // 25: urnetwork.sidecar.LogSettingsBody.witnesses:type_name -> urnetwork.sidecar.LogWitness
	62, // 26: urnetwork.sidecar.LogCheckpointBody.frontier:type_name -> urnetwork.sidecar.LogFrontier
	63, // 27: urnetwork.sidecar.LogCheckpointBody.cosigned:type_name -> urnetwork.sidecar.LogCosigned
	65, // 28: urnetwork.sidecar.DisclosurePacket.entries:type_name -> urnetwork.sidecar.DisclosedEntry
	66, // 29: urnetwork.sidecar.DisclosurePacket.keys:type_name -> urnetwork.sidecar.DisclosedKey
	51, // 30: urnetwork.sidecar.DisclosedEntry.opening:type_name -> urnetwork.sidecar.Opening
	51, // 31: urnetwork.sidecar.DisclosedEntry.content:type_name -> urnetwork.sidecar.Opening
	70, // 32: urnetwork.sidecar.ModelManifest.served_name:type_name -> urnetwork.sidecar.ModelField
	70, // 33: urnetwork.sidecar.ModelManifest.engine:type_name -> urnetwork.sidecar.ModelField
	70, // 34: urnetwork.sidecar.ModelManifest.engine_version:type_name -> urnetwork.sidecar.ModelField
	70, // 35: urnetwork.sidecar.ModelManifest.quantization:type_name -> urnetwork.sidecar.ModelField
	70, // 36: urnetwork.sidecar.ModelManifest.weights_digest:type_name -> urnetwork.sidecar.ModelField
	82, // 37: urnetwork.sidecar.ModelCallBody.attestation:type_name -> urnetwork.sidecar.AttestationResult
	70, // 38: urnetwork.sidecar.ModelCallBody.platform:type_name -> urnetwork.sidecar.ModelField
	75, // 39: urnetwork.sidecar.ModelCallBody.context:type_name -> urnetwork.sidecar.CallContext
	73, // 40: urnetwork.sidecar.SessionEntryBody.parts:type_name -> urnetwork.sidecar.SessionPart
	78, // 41: urnetwork.sidecar.RunCostBody.usage:type_name -> urnetwork.sidecar.ModelUsage
	18, // 42: urnetwork.sidecar.SupportMessageBody.bundle:type_name -> urnetwork.sidecar.BundleManifest
	20, // 43: urnetwork.sidecar.SupportMessageBody.files:type_name -> urnetwork.sidecar.FileFields
	44, // [44:44] is the sub-list for method output_type
	44, // [44:44] is the sub-list for method input_type
	44, // [44:44] is the sub-list for extension type_name
	44, // [44:44] is the sub-list for extension extendee
	0,  // [0:44] is the sub-list for field type_name
}

func init() { file_protocol_record_proto_init() }
func file_protocol_record_proto_init() {
	if File_protocol_record_proto != nil {
		return
	}
	file_protocol_attest_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_protocol_record_proto_rawDesc), len(file_protocol_record_proto_rawDesc)),
			NumEnums:      4,
			NumMessages:   76,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protocol_record_proto_goTypes,
		DependencyIndexes: file_protocol_record_proto_depIdxs,
		EnumInfos:         file_protocol_record_proto_enumTypes,
		MessageInfos:      file_protocol_record_proto_msgTypes,
	}.Build()
	File_protocol_record_proto = out.File
	file_protocol_record_proto_goTypes = nil
	file_protocol_record_proto_depIdxs = nil
}
