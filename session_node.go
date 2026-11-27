//go:build !ios_extension && !sidecar_http

// What the session journal takes (CTXH-M11-03; DESIGN-COMPUTE §24.4, §24.5): a run's node, one message of its session
// tree as the Harness's loop or the gateway hands it, with the tool result it holds, if any, and the form the record
// keeps that result in (§24.9). The journal draws each node's id, 16 random bytes, never derived from content, and
// names a node's parent by the key the caller gave it within its run: the Harness's Pi entry id, the gateway's item
// key.
//
// Safe for concurrent use: these are values.

package sidecar

import (
	"errors"
	"fmt"
)

// A node's type, SessionEntryBody.type (§24.5's fence numbers them).
type SessionNodeType uint32

const (
	SessionNodeMessage             SessionNodeType = 1
	SessionNodeModelChange         SessionNodeType = 2
	SessionNodeThinkingLevelChange SessionNodeType = 3
	SessionNodeUsage               SessionNodeType = 4
	SessionNodeCompaction          SessionNodeType = 5
	SessionNodeBranchSummary       SessionNodeType = 6
	SessionNodeCustom              SessionNodeType = 7
	SessionNodeCustomMessage       SessionNodeType = 8
	SessionNodeLink                SessionNodeType = 9
)

// The node type of a Pi v3 entry type (§7.7, §24.4): Pi's types by their own, the Harness's link, and every other entry
// Pi keeps, a label or a session_info, as custom.
func SessionNodeTypeOfPi(entryType HarnessPiEntryType) SessionNodeType {
	switch entryType {
	case HarnessPiEntryMessage:
		return SessionNodeMessage
	case HarnessPiEntryModelChange:
		return SessionNodeModelChange
	case HarnessPiEntryThinkingLevelChange:
		return SessionNodeThinkingLevelChange
	case HarnessPiEntryUsage:
		return SessionNodeUsage
	case HarnessPiEntryCompaction:
		return SessionNodeCompaction
	case HarnessPiEntryBranchSummary:
		return SessionNodeBranchSummary
	case HarnessPiEntryCustomMessage:
		return SessionNodeCustomMessage
	case HarnessPiEntryLink:
		return SessionNodeLink
	}
	return SessionNodeCustom
}

// The form the record keeps a tool result in (§24.9's exceptions).
type SessionItemForm uint32

const (
	// Kept whole, up to the part caps: every tool's result but those below, a calendar's and a fetched page's among them.
	SessionItemWhole SessionItemForm = 1
	// A built-in's keep: false result, today web search's alone: §21.6's stub, the call and what SRCH's stub gives, never
	// the result's text or details.
	SessionItemStub SessionItemForm = 2
	// mail_list's and mail_read's result: §23.11's reference, the mailbox, the messages, the window read and the hash of
	// the text read, never the text.
	SessionItemMailReference SessionItemForm = 3
)

// The tool result a node's item holds, as the caller knows it: which tool, and what it said of its details.
type SessionToolResult struct {
	// The tool's name, as its call named it.
	Name string
	// Built into sidecar: the only kind whose keep: false is honored (§24.9). A harness's own or an MCP server's is not.
	BuiltIn bool
	// The result's details marked keep: false. Honored only from a built-in, whose result then keeps its stub.
	KeepFalse bool
	// SRCH's stub of a web search (§21.6): the call, the number of results, a hash of the answer, the payment and the
	// charge, as JSON. Nil until SRCH gives one, and then the stub holds the call alone.
	SearchStub []byte
	// MAILCAL's reference to what a mail tool read (§23.11); a mail tool's result without one is refused, never kept
	// as text.
	MailReference *SessionMailReference
}

// The run a node belongs to and what it carries at capture (§24.5): the run's taint and its marks.
type SessionRun struct {
	RunId   Id
	AgentId *Id
	// The run's taint at capture, failing closed: the header's tainted bit.
	Tainted bool
	// The run's marks at capture: bit 0 limited_use, bit 1 private (HarnessMark's bits).
	Marks uint32
}

// One node to journal.
type SessionNode struct {
	// The node's key within its run, by which later nodes name it as their parent: the Harness's Pi entry id. Unique in
	// the run; a key journaled already is refused.
	Key string
	// The parent's key within the run, empty at a root.
	ParentKey string
	// A continuation's root (§24.7): the other run's node it continues and that node's chain hash, ParentKey empty.
	ParentRunId       *Id
	ParentNodeId      *Id
	ParentChainSha256 []byte
	Type              SessionNodeType
	// The Harness's Pi v3 entry, or the gateway's API item, as JSON; canonicalized (RFC 8785) after the exceptions.
	Item []byte
	// The tool result the item holds, nil for any other item.
	Tool *SessionToolResult
	// An item the gateway records from a harness's request, which is that harness's word: source hook.
	FromHarness bool
	// The stubs the caller put in Item already, a harness's copies of web search results the gateway's recorder
	// replaced (§24.9, CTXH-M13-01), counted in the node's stubs beside the journal's own.
	Stubs int
}

var (
	// A node that breaks the journal's rules: no key, a key journaled already, a parent the run has not journaled, an item
	// that is no JSON object, or a type out of range. Nothing of it was written.
	ErrSessionNodeRefused = errors.New("session node refused")
	// A mail tool's result with no reference form: the journal never keeps a mail message's text (§24.9, D-MAILCAL-8).
	ErrSessionMailAsText = errors.New("session journal refuses a mail tool's result as text")
)

// The node's own rules, before anything is drawn.
func (self *SessionNode) check() error {
	switch {
	case self.Key == "":
		return fmt.Errorf("%w: no key", ErrSessionNodeRefused)
	case self.Type < SessionNodeMessage || SessionNodeLink < self.Type:
		return fmt.Errorf("%w: node type %d", ErrSessionNodeRefused, self.Type)
	case len(self.Item) == 0:
		return fmt.Errorf("%w: no item", ErrSessionNodeRefused)
	case self.Stubs < 0:
		return fmt.Errorf("%w: %d stubs", ErrSessionNodeRefused, self.Stubs)
	case self.ParentKey != "" && (self.ParentRunId != nil || self.ParentNodeId != nil):
		return fmt.Errorf("%w: a parent in its run and in another", ErrSessionNodeRefused)
	case (self.ParentRunId == nil) != (self.ParentNodeId == nil) || (self.ParentNodeId != nil && len(self.ParentChainSha256) != 32):
		return fmt.Errorf("%w: another run's parent without its node or chain hash", ErrSessionNodeRefused)
	}
	return nil
}

// The run and node a Harness journal node is (HARN-M11-08 wires the Harness's journal through it): the Pi entry's id
// its key and its parentId its parent's, its type the node's, the run's taint and marks, and a continuation's root
// naming the other run; an untrusted node's entry carries its trust and sender, which harness-1 reads to place the
// untrusted-data markers (CTXH-M11-04). The tool result's form is the caller's to give, from the tool's spec.
func SessionNodeOfHarness(node *HarnessJournalNode, tool *SessionToolResult) (*SessionRun, *SessionNode, error) {
	if node == nil || node.Entry == nil {
		return nil, nil, fmt.Errorf("%w: no entry", ErrSessionNodeRefused)
	}
	item, err := SessionHarnessEntryWithTrust(node.Entry, node.Untrusted, node.Sender).Json()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSessionNodeRefused, err)
	}
	agentId := node.AgentId
	run := &SessionRun{RunId: node.RunId, AgentId: &agentId, Tainted: node.Tainted || node.Untrusted, Marks: uint32(node.Marks)}
	sessionNode := &SessionNode{Key: node.Entry.Id(), Type: SessionNodeTypeOfPi(node.Entry.Type()), Item: item, Tool: tool}
	if parentId, ok := node.Entry.ParentId(); ok && node.ParentRunId == nil {
		sessionNode.ParentKey = parentId
	}
	if node.ParentRunId != nil {
		// a continuation's root names its parent by the other run's node, which the caller resolves (CTXH-M11-05)
		return nil, nil, fmt.Errorf("%w: a continuation's root needs the node it continues", ErrSessionNodeRefused)
	}
	return run, sessionNode, nil
}
