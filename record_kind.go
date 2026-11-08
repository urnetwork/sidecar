// RECORD.md section 6's v1 kind registry, on every leg: each kind's number and name (section 6.3), its retention
// class (section 8) and the one body message it parses as (section 6.4), with section 6.2's enumerations of what a
// RecordHeader and a ReachReceipt label. RECORD.md is the source, and record_kind_test.go holds this file to it.
//
// A kind's number and name are permanent once released and never reused, and 0 is never written. 1 to 1,023 are the
// registry's, in blocks by class (section 6.1); 1,024 and up are private use, shown generically, like any kind this
// build does not know, and never refused (§16.8). 64 to 79 are derived names, which appear in search alone
// (SearchFilters.kinds) and never as a header's kind. Every value here is a format value, not a tunable.
//
// Package-level functions and the methods on these types are safe for concurrent use: nothing here changes.

package sidecar

import (
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A RecordHeader's kind, as RECORD.md section 6.3 numbers it. A header carries it as a uint32 (§16.8's kind field),
// so a value this build does not name is still a kind, kept and shown generically.
type RecordKind uint32

const (
	// Never written; a reader shows it as a kind it does not know.
	RecordKindUnspecified RecordKind = 0

	// 1 to 15: coordination and directory entries.
	RecordKindClaim          RecordKind = 1
	RecordKindHandoff        RecordKind = 2
	RecordKindAsk            RecordKind = 3
	RecordKindAnswer         RecordKind = 4
	RecordKindCheck          RecordKind = 5
	RecordKindNote           RecordKind = 6
	RecordKindAnnounce       RecordKind = 7
	RecordKindRequest        RecordKind = 8
	RecordKindDecision       RecordKind = 9
	RecordKindErasureRequest RecordKind = 10

	// 16 to 47: actions, accounting and log upkeep.
	RecordKindContext          RecordKind = 16
	RecordKindChange           RecordKind = 17
	RecordKindPermission       RecordKind = 18
	RecordKindApproval         RecordKind = 19
	RecordKindApprovalDecision RecordKind = 20
	RecordKindApprovalCancel   RecordKind = 21
	RecordKindApprovalUse      RecordKind = 22
	RecordKindRoute            RecordKind = 23
	RecordKindPublish          RecordKind = 24
	RecordKindReach            RecordKind = 25
	RecordKindRestore          RecordKind = 26
	RecordKindModel            RecordKind = 27
	RecordKindCost             RecordKind = 28
	RecordKindAttestation      RecordKind = 29
	RecordKindMembership       RecordKind = 32
	RecordKindKey              RecordKind = 33
	RecordKindCoverage         RecordKind = 34
	RecordKindRead             RecordKind = 35
	RecordKindErasure          RecordKind = 36
	RecordKindInventory        RecordKind = 37
	RecordKindDisclosure       RecordKind = 38
	RecordKindCopy             RecordKind = 39
	RecordKindRetention        RecordKind = 40
	RecordKindLogSettings      RecordKind = 41
	RecordKindCheckpoint       RecordKind = 42
	RecordKindLedgerScope      RecordKind = 43

	// 48 to 63: raw capture.
	RecordKindTranscript RecordKind = 48
	RecordKindToolCall   RecordKind = 49
	RecordKindHookEvent  RecordKind = 50
	RecordKindFileEvent  RecordKind = 51
	RecordKindBlob       RecordKind = 52
	RecordKindModelCall  RecordKind = 53

	// 64 to 79: derived names, from M10, in search alone: a run card or D's run announcement, and D's worker and
	// repo announcements.
	RecordKindRun    RecordKind = 64
	RecordKindWorker RecordKind = 65
	RecordKindRepo   RecordKind = 66
)

// Section 6.1's blocks.
const (
	recordKindDerivedFirst = 64
	recordKindDerivedLast  = 79
	// the first number for private use, which v1 readers show generically
	recordKindPrivateFirst = 1024
)

// A RetentionPolicy's class (§16.8's class field), section 8's table. Class 7 takes no policy: its entries last as
// long as the log, or a tree could no longer be rebuilt (section 10).
type RecordClass uint32

const (
	// Never written.
	RecordClassUnspecified  RecordClass = 0
	RecordClassCapture      RecordClass = 1
	RecordClassAction       RecordClass = 2
	RecordClassCoordination RecordClass = 3
	// keep_days 30 in the team directory (§16.11)
	RecordClassAnnounce   RecordClass = 4
	RecordClassRequest    RecordClass = 5
	RecordClassAccounting RecordClass = 6
	RecordClassLog        RecordClass = 7
)

// How far an entry goes (§16.8's source field; section 6.2's numbers, §16.8's meanings). No writer sets 0, and a
// reader takes it as unknown.
type RecordSource uint32

const (
	RecordSourceUnknown RecordSource = 0
	// The daemon did or saw it.
	RecordSourceObserved RecordSource = 1
	// Any same-user process can fake it.
	RecordSourceHook  RecordSource = 2
	RecordSourceAgent RecordSource = 3
	// A person's act at a device: a decision, or a command confirmed on /dev/tty or in an app's UI (§5.8).
	RecordSourceApprover RecordSource = 4
)

// Who vouches for an entry's agent (§16.8's agent_source field; section 6.2; §5.5). Here 0 is a value: no agent.
type RecordAgentSource uint32

const (
	RecordAgentSourceNone RecordAgentSource = 0
	// The agent says who it is, and nothing checks it.
	RecordAgentSourceAsserted RecordAgentSource = 1
	// The agent runs as its own OS user, container or VM (§5.5).
	RecordAgentSourceIsolated RecordAgentSource = 2
)

// What a ReachReceipt counts (its kind field; section 6.2): §16.8's four enforcing endpoints, six acts. No writer
// sets 0.
type RecordReachKind uint32

const (
	RecordReachKindUnspecified RecordReachKind = 0
	RecordReachKindListen      RecordReachKind = 1
	RecordReachKindPublish     RecordReachKind = 2
	RecordReachKindForward     RecordReachKind = 3
	RecordReachKindRoute       RecordReachKind = 4
	RecordReachKindSend        RecordReachKind = 5
	RecordReachKindReceive     RecordReachKind = 6
)

// One row of section 6.3, the columns this file holds, with section 6.4's body.
type recordKindRow struct {
	name  string
	class RecordClass
	// A new, empty body message: for a kind whose stored body is a Signed, the Signed. Nil for a derived name,
	// which no entry carries.
	body func() proto.Message
	// For a kind whose stored body is a Signed (section 6.4): the message the Signed's body holds, and its type.
	signedBody func() proto.Message
	signedType bridge.SignedType
}

// Section 6.3's registry and section 6.4's bodies. Rows are added, never changed or removed.
var recordKindRows = map[RecordKind]recordKindRow{
	RecordKindClaim:          {name: "claim", class: RecordClassCoordination, body: newRecordCoordinationBody},
	RecordKindHandoff:        {name: "handoff", class: RecordClassCoordination, body: newRecordCoordinationBody},
	RecordKindAsk:            {name: "ask", class: RecordClassCoordination, body: newRecordCoordinationBody},
	RecordKindAnswer:         {name: "answer", class: RecordClassCoordination, body: newRecordCoordinationBody},
	RecordKindCheck:          {name: "check", class: RecordClassCoordination, body: newRecordCoordinationBody},
	RecordKindNote:           {name: "note", class: RecordClassCoordination, body: newRecordCoordinationBody},
	RecordKindAnnounce:       {name: "announce", class: RecordClassAnnounce, body: func() proto.Message { return &protocol.Announcement{} }},
	RecordKindRequest:        {name: "request", class: RecordClassRequest, body: func() proto.Message { return &protocol.DirectoryRequest{} }},
	RecordKindDecision:       {name: "decision", class: RecordClassRequest, body: func() proto.Message { return &protocol.DirectoryDecision{} }},
	RecordKindErasureRequest: {name: "erasure_request", class: RecordClassRequest, body: func() proto.Message { return &protocol.DirectoryErasureRequest{} }},

	RecordKindContext:    {name: "context", class: RecordClassAction, body: func() proto.Message { return &protocol.ContextBody{} }},
	RecordKindChange:     {name: "change", class: RecordClassAction, body: func() proto.Message { return &protocol.ChangeBody{} }},
	RecordKindPermission: {name: "permission", class: RecordClassAction, body: func() proto.Message { return &protocol.PermissionBody{} }},
	RecordKindApproval:   {name: "approval", class: RecordClassAction, body: func() proto.Message { return &protocol.ApprovalRequest{} }},
	RecordKindApprovalDecision: {
		name:       "approval_decision",
		class:      RecordClassAction,
		body:       newRecordSignedBody,
		signedBody: func() proto.Message { return &protocol.ApprovalDecision{} },
		signedType: bridge.SignedType_SIGNED_APPROVAL_DECISION,
	},
	RecordKindApprovalCancel: {
		name:       "approval_cancel",
		class:      RecordClassAction,
		body:       newRecordSignedBody,
		signedBody: func() proto.Message { return &protocol.ApprovalCancel{} },
		signedType: bridge.SignedType_SIGNED_APPROVAL_CANCEL,
	},
	RecordKindApprovalUse: {name: "approval_use", class: RecordClassAction, body: func() proto.Message { return &protocol.ApprovalUseBody{} }},
	RecordKindRoute:       {name: "route", class: RecordClassAction, body: func() proto.Message { return &protocol.RouteBody{} }},
	RecordKindPublish:     {name: "publish", class: RecordClassAction, body: func() proto.Message { return &protocol.PublishBody{} }},
	RecordKindReach:       {name: "reach", class: RecordClassAction, body: func() proto.Message { return &protocol.ReachReceipt{} }},
	RecordKindRestore:     {name: "restore", class: RecordClassAction, body: func() proto.Message { return &protocol.RestoreBody{} }},
	RecordKindModel:       {name: "model", class: RecordClassAction, body: func() proto.Message { return &protocol.ModelManifest{} }},
	RecordKindCost:        {name: "cost", class: RecordClassAction, body: func() proto.Message { return &protocol.RunCostBody{} }},
	RecordKindAttestation: {name: "attestation", class: RecordClassAction, body: func() proto.Message { return &protocol.AttestationBody{} }},
	RecordKindMembership:  {name: "membership", class: RecordClassAccounting, body: func() proto.Message { return &protocol.MembershipBody{} }},
	RecordKindKey:         {name: "key", class: RecordClassAccounting, body: func() proto.Message { return &protocol.KeyBody{} }},
	RecordKindCoverage:    {name: "coverage", class: RecordClassAccounting, body: func() proto.Message { return &protocol.Coverage{} }},
	RecordKindRead:        {name: "read", class: RecordClassAccounting, body: func() proto.Message { return &protocol.ReadBody{} }},
	RecordKindErasure:     {name: "erasure", class: RecordClassAccounting, body: func() proto.Message { return &protocol.ErasureBody{} }},
	RecordKindInventory:   {name: "inventory", class: RecordClassAccounting, body: func() proto.Message { return &protocol.InventoryBody{} }},
	RecordKindDisclosure:  {name: "disclosure", class: RecordClassAccounting, body: func() proto.Message { return &protocol.DisclosureBody{} }},
	RecordKindCopy:        {name: "copy", class: RecordClassAccounting, body: func() proto.Message { return &protocol.CopyBody{} }},
	RecordKindRetention: {
		name:       "retention",
		class:      RecordClassLog,
		body:       newRecordSignedBody,
		signedBody: func() proto.Message { return &protocol.RetentionPolicy{} },
		signedType: bridge.SignedType_SIGNED_RETENTION_POLICY,
	},
	RecordKindLogSettings: {name: "log_settings", class: RecordClassLog, body: func() proto.Message { return &protocol.LogSettingsBody{} }},
	RecordKindCheckpoint:  {name: "checkpoint", class: RecordClassLog, body: func() proto.Message { return &protocol.LogCheckpointBody{} }},
	RecordKindLedgerScope: {name: "ledger_scope", class: RecordClassLog, body: func() proto.Message { return &protocol.LedgerScopeBody{} }},

	RecordKindTranscript: {name: "transcript", class: RecordClassCapture, body: func() proto.Message { return &protocol.TranscriptBody{} }},
	RecordKindToolCall:   {name: "tool_call", class: RecordClassCapture, body: func() proto.Message { return &protocol.ToolCallBody{} }},
	RecordKindHookEvent:  {name: "hook_event", class: RecordClassCapture, body: func() proto.Message { return &protocol.HookEventBody{} }},
	RecordKindFileEvent:  {name: "file_event", class: RecordClassCapture, body: func() proto.Message { return &protocol.FileEventBody{} }},
	RecordKindBlob:       {name: "blob", class: RecordClassCapture, body: func() proto.Message { return &protocol.BlobBody{} }},
	RecordKindModelCall:  {name: "model_call", class: RecordClassCapture, body: func() proto.Message { return &protocol.ModelCallBody{} }},

	// Derived names hold no class: no header carries one.
	RecordKindRun:    {name: "run"},
	RecordKindWorker: {name: "worker"},
	RecordKindRepo:   {name: "repo"},
}

func newRecordCoordinationBody() proto.Message {
	return &protocol.CoordinationBody{}
}

func newRecordSignedBody() proto.Message {
	return &bridge.Signed{}
}

// Every kind the registry names, derived names included, in number order.
func RecordKinds() []RecordKind {
	kinds := make([]RecordKind, 0, len(recordKindRows))
	for kind := range recordKindRows {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	return kinds
}

// The kind section 6.3 names so, and false for a name it does not hold.
func RecordKindNamed(name string) (RecordKind, bool) {
	for kind, row := range recordKindRows {
		if row.name == name {
			return kind, true
		}
	}
	return RecordKindUnspecified, false
}

// Section 6.3's name, or for a kind the registry does not hold, private use among them, the generic form a v1 reader
// shows (section 6.1's unknown row).
func (self RecordKind) String() string {
	if row, ok := recordKindRows[self]; ok {
		return row.name
	}
	return fmt.Sprintf("kind %d", uint32(self))
}

// Whether section 6.3 names the kind, derived names included.
func (self RecordKind) Known() bool {
	_, ok := recordKindRows[self]
	return ok
}

// Whether the kind is in 64 to 79, the derived names, which search alone takes and no header carries.
func (self RecordKind) Derived() bool {
	return recordKindDerivedFirst <= self && self <= recordKindDerivedLast
}

// Whether the kind is in the private-use range, which v1 readers show generically.
func (self RecordKind) PrivateUse() bool {
	return recordKindPrivateFirst <= self
}

// Whether a v1 writer may put the kind in a header: a kind section 6.3 names that is no derived name. 0 never is.
func (self RecordKind) Writable() bool {
	return self.Known() && !self.Derived()
}

// Section 8's class. A kind the registry does not hold takes class 2, action, and so do 0 and the derived names, since
// a header carrying one is no kind this build knows.
func (self RecordKind) Class() RecordClass {
	if row, ok := recordKindRows[self]; ok && row.class != RecordClassUnspecified {
		return row.class
	}
	return RecordClassAction
}

// A new, empty message of the kind's one body (section 6.1's one-body row), to parse its stored bytes into: the
// Signed for approval_decision, approval_cancel and retention, whose message NewSignedBody gives. False for a kind
// that is not Writable, which a reader keeps and shows generically instead.
func (self RecordKind) NewBody() (proto.Message, bool) {
	row, ok := recordKindRows[self]
	if !ok || row.body == nil {
		return nil, false
	}
	return row.body(), true
}

// For a kind whose stored body is a Signed: a new, empty message of what the Signed's body holds, and the SignedType
// that Signed must carry. False for every other kind.
func (self RecordKind) NewSignedBody() (proto.Message, bridge.SignedType, bool) {
	row, ok := recordKindRows[self]
	if !ok || row.signedBody == nil {
		return nil, bridge.SignedType_SIGNED_TYPE_NONE, false
	}
	return row.signedBody(), row.signedType, true
}

// Section 8's class names.
var recordClassNames = map[RecordClass]string{
	RecordClassCapture:      "capture",
	RecordClassAction:       "action",
	RecordClassCoordination: "coordination",
	RecordClassAnnounce:     "announce",
	RecordClassRequest:      "request",
	RecordClassAccounting:   "accounting",
	RecordClassLog:          "log",
}

// Section 8's name, or "class n" for a number it does not hold.
func (self RecordClass) String() string {
	if name, ok := recordClassNames[self]; ok {
		return name
	}
	return fmt.Sprintf("class %d", uint32(self))
}

// Whether section 8 holds the class. A RetentionPolicy naming another is no policy this build applies.
func (self RecordClass) Known() bool {
	_, ok := recordClassNames[self]
	return ok
}

// Section 6.2's source names.
var recordSourceNames = map[RecordSource]string{
	RecordSourceObserved: "observed",
	RecordSourceHook:     "hook",
	RecordSourceAgent:    "agent",
	RecordSourceApprover: "approver",
}

// Section 6.2's name, or "source n" for a value it does not hold, 0 among them.
func (self RecordSource) String() string {
	if name, ok := recordSourceNames[self]; ok {
		return name
	}
	return fmt.Sprintf("source %d", uint32(self))
}

// Whether section 6.2 holds the value. A reader shows any other as unknown, and keeps the entry.
func (self RecordSource) Known() bool {
	_, ok := recordSourceNames[self]
	return ok
}

// Section 6.2's agent_source names.
var recordAgentSourceNames = map[RecordAgentSource]string{
	RecordAgentSourceNone:     "none",
	RecordAgentSourceAsserted: "agent_asserted",
	RecordAgentSourceIsolated: "isolated",
}

// Section 6.2's name, or "agent source n" for a value it does not hold.
func (self RecordAgentSource) String() string {
	if name, ok := recordAgentSourceNames[self]; ok {
		return name
	}
	return fmt.Sprintf("agent source %d", uint32(self))
}

// Whether section 6.2 holds the value.
func (self RecordAgentSource) Known() bool {
	_, ok := recordAgentSourceNames[self]
	return ok
}

// Section 6.2's ReachReceipt.kind names.
var recordReachKindNames = map[RecordReachKind]string{
	RecordReachKindListen:  "listen",
	RecordReachKindPublish: "publish",
	RecordReachKindForward: "forward",
	RecordReachKindRoute:   "route",
	RecordReachKindSend:    "send",
	RecordReachKindReceive: "receive",
}

// Section 6.2's name, or "reach kind n" for a value it does not hold, 0 among them.
func (self RecordReachKind) String() string {
	if name, ok := recordReachKindNames[self]; ok {
		return name
	}
	return fmt.Sprintf("reach kind %d", uint32(self))
}

// Whether section 6.2 holds the value.
func (self RecordReachKind) Known() bool {
	_, ok := recordReachKindNames[self]
	return ok
}
