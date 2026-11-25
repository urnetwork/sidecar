//go:build !ios_extension && !sidecar_http

// Pi's session entries, JSONL version 3 (session-format.md, DESIGN-COMPUTE §7.3, §7.7), with Pi's JSON names, and
// §24.4's link: the tree CTXH's journal records, one entry a node (§24.5's SessionEntryBody.item), and
// `ur harness export` writes, which Pi and PiG open.
//
// An entry has a type, an 8-hex-character id, its parent's id (null at a root), and an ISO 8601 timestamp; then its
// type's members in Pi's order. The types are Pi's message, model_change, thinking_level_change, usage, compaction,
// branch_summary, custom and custom_message, and the Harness's link, which names a sub-agent's run in its parent's
// tree and its parent's run and node at the sub-agent's root, so neither context takes in the other's (§24.4). Pi's
// other entries (label, session_info, context_edit) and any type this build does not know read and write back as they
// came, every member kept.
//
// model_change keeps Pi's provider and modelId and adds §24.4's previous name and who changed it, after them, which a
// Pi reader ignores.
//
// An entry is a value: a change goes to a copy where another holds it.

package sidecar

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// An entry's type (session-format.md), with §24.4's link and the file's header.
type HarnessPiEntryType string

const (
	HarnessPiEntrySession             HarnessPiEntryType = "session"
	HarnessPiEntryMessage             HarnessPiEntryType = "message"
	HarnessPiEntryModelChange         HarnessPiEntryType = "model_change"
	HarnessPiEntryThinkingLevelChange HarnessPiEntryType = "thinking_level_change"
	HarnessPiEntryUsage               HarnessPiEntryType = "usage"
	HarnessPiEntryCompaction          HarnessPiEntryType = "compaction"
	HarnessPiEntryBranchSummary       HarnessPiEntryType = "branch_summary"
	HarnessPiEntryCustom              HarnessPiEntryType = "custom"
	HarnessPiEntryCustomMessage       HarnessPiEntryType = "custom_message"
	HarnessPiEntryLink                HarnessPiEntryType = "link"
)

// Pi's session file version.
const HarnessPiSessionVersion = 3

// Who changed a run's model (§24.4): the person, the agent, or §7.4's failure choice.
const (
	HarnessModelChangedByPerson        = "person"
	HarnessModelChangedByAgent         = "agent"
	HarnessModelChangedByFailureChoice = "failure_choice"
)

// Which way a link points (§24.4): in a parent's tree to the child it launched, or at a child's root to its parent.
const (
	HarnessPiLinkChild  = "child"
	HarnessPiLinkParent = "parent"
)

// The ISO 8601 form Pi writes an entry's timestamp in, JavaScript's toISOString.
const harnessPiTimestampLayout = "2006-01-02T15:04:05.000Z"

// A fresh entry id: 8 hex characters, as Pi makes them.
func NewHarnessPiEntryId() string {
	random := make([]byte, 4)
	rand.Read(random)
	return hex.EncodeToString(random)
}

// t as an entry's timestamp.
func harnessPiTimestamp(t time.Time) string {
	return t.UTC().Format(harnessPiTimestampLayout)
}

// One session entry, its members in Pi's order.
type HarnessPiEntry struct {
	object harnessPiObject
}

// An entry of entryType with the base members: id, parentId (null for a root, "" parentId) and timestamp.
func newHarnessPiEntry(entryType HarnessPiEntryType, id string, parentId string, timestamp time.Time) *HarnessPiEntry {
	entry := &HarnessPiEntry{}
	entry.object.set("type", entryType)
	entry.object.set("id", id)
	if parentId == "" {
		entry.object.setRaw("parentId", json.RawMessage("null"))
	} else {
		entry.object.set("parentId", parentId)
	}
	entry.object.set("timestamp", harnessPiTimestamp(timestamp))
	return entry
}

// The file's first line: metadata, no id in the tree.
func NewHarnessPiSessionHeader(sessionId string, timestamp time.Time, cwd string, parentSession string) *HarnessPiEntry {
	entry := &HarnessPiEntry{}
	entry.object.set("type", HarnessPiEntrySession)
	entry.object.set("version", HarnessPiSessionVersion)
	entry.object.set("id", sessionId)
	entry.object.set("timestamp", harnessPiTimestamp(timestamp))
	entry.object.set("cwd", cwd)
	if parentSession != "" {
		entry.object.set("parentSession", parentSession)
	}
	return entry
}

// A message entry holding one AgentMessage.
func NewHarnessPiMessageEntry(id string, parentId string, timestamp time.Time, message *HarnessPiMessage) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryMessage, id, parentId, timestamp)
	entry.object.set("message", message)
	return entry
}

// A run's model change (§24.4): Pi's provider and model id, the canonical name, then the name it replaced and who
// changed it, where known.
type HarnessPiModelChange struct {
	Provider string
	ModelId  string
	// The canonical name before; empty at a run's first model.
	PreviousModelId string
	// person, agent or failure_choice; empty where unknown.
	ChangedBy string
}

// A model_change entry.
func NewHarnessPiModelChangeEntry(id string, parentId string, timestamp time.Time, change *HarnessPiModelChange) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryModelChange, id, parentId, timestamp)
	entry.object.set("provider", change.Provider)
	entry.object.set("modelId", change.ModelId)
	if change.PreviousModelId != "" {
		entry.object.set("previousModelId", change.PreviousModelId)
	}
	if change.ChangedBy != "" {
		entry.object.set("changedBy", change.ChangedBy)
	}
	return entry
}

// A thinking_level_change entry: the effort the run asks for (§6.3's words).
func NewHarnessPiThinkingLevelChangeEntry(id string, parentId string, timestamp time.Time, thinkingLevel string) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryThinkingLevelChange, id, parentId, timestamp)
	entry.object.set("thinkingLevel", thinkingLevel)
	return entry
}

// A usage entry: model-attributed usage that is no assistant message, such as a compaction's call.
func NewHarnessPiUsageEntry(id string, parentId string, timestamp time.Time, kind string, provider string, model string, usage *HarnessPiUsage) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryUsage, id, parentId, timestamp)
	entry.object.set("kind", kind)
	entry.object.set("provider", provider)
	entry.object.set("model", model)
	entry.object.set("usage", usage)
	return entry
}

// A compaction entry: the summary, the first entry kept from before it, and the tokens it replaced.
func NewHarnessPiCompactionEntry(id string, parentId string, timestamp time.Time, summary string, firstKeptEntryId string, tokensBefore int64) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryCompaction, id, parentId, timestamp)
	entry.object.set("summary", summary)
	entry.object.set("firstKeptEntryId", firstKeptEntryId)
	entry.object.set("tokensBefore", tokensBefore)
	return entry
}

// A branch_summary entry: the abandoned leaf and its summary.
func NewHarnessPiBranchSummaryEntry(id string, parentId string, timestamp time.Time, fromId string, summary string) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryBranchSummary, id, parentId, timestamp)
	entry.object.set("fromId", fromId)
	entry.object.set("summary", summary)
	return entry
}

// A custom entry: state outside the model's context.
func NewHarnessPiCustomEntry(id string, parentId string, timestamp time.Time, customType string, data json.RawMessage) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryCustom, id, parentId, timestamp)
	entry.object.set("customType", customType)
	if compacted, err := harnessPiCompact(data); err == nil {
		entry.object.setRaw("data", compacted)
	} else {
		entry.object.setRaw("data", json.RawMessage("null"))
	}
	return entry
}

// A custom_message entry: context the model reads as user text.
func NewHarnessPiCustomMessageEntry(id string, parentId string, timestamp time.Time, customType string, content string, display bool) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryCustomMessage, id, parentId, timestamp)
	entry.object.set("customType", customType)
	entry.object.set("content", content)
	entry.object.set("display", display)
	return entry
}

// What a link names (§24.4): in a parent's tree the child's agent, run and place; at a child's root the parent's
// agent, run and the node it launched from.
type HarnessPiLink struct {
	// child or parent
	To      string
	AgentId Id
	RunId   Id
	// local or enclave:<name>
	Place string
	// The node the link names in the other run: the parent's node at a child's root; empty in a parent's tree.
	NodeId string
}

// A link entry. A child's first node is a link back, a root (empty parentId) whose item names its parent's run and
// node, so the child's context never takes in the parent's.
func NewHarnessPiLinkEntry(id string, parentId string, timestamp time.Time, link *HarnessPiLink) *HarnessPiEntry {
	entry := newHarnessPiEntry(HarnessPiEntryLink, id, parentId, timestamp)
	entry.object.set("to", link.To)
	entry.object.set("agentId", link.AgentId.String())
	entry.object.set("runId", link.RunId.String())
	entry.object.set("place", link.Place)
	if link.NodeId != "" {
		entry.object.set("nodeId", link.NodeId)
	}
	return entry
}

// The entry's type.
func (self *HarnessPiEntry) Type() HarnessPiEntryType {
	return HarnessPiEntryType(self.object.str("type"))
}

// The entry's id.
func (self *HarnessPiEntry) Id() string {
	return self.object.str("id")
}

// Its parent's id, and false at a root.
func (self *HarnessPiEntry) ParentId() (string, bool) {
	parentId := ""
	if !self.object.decode("parentId", &parentId) || parentId == "" {
		return "", false
	}
	return parentId, true
}

// Its timestamp, the zero time where it does not read.
func (self *HarnessPiEntry) Timestamp() time.Time {
	timestamp, err := time.Parse(time.RFC3339Nano, self.object.str("timestamp"))
	if err != nil {
		return time.Time{}
	}
	return timestamp
}

// A message entry's message, or nil.
func (self *HarnessPiEntry) Message() *HarnessPiMessage {
	if self.Type() != HarnessPiEntryMessage {
		return nil
	}
	message := &HarnessPiMessage{}
	if !self.object.decode("message", message) {
		return nil
	}
	return message
}

// A link entry's link, or nil.
func (self *HarnessPiEntry) Link() *HarnessPiLink {
	if self.Type() != HarnessPiEntryLink {
		return nil
	}
	link := &HarnessPiLink{
		To:     self.object.str("to"),
		Place:  self.object.str("place"),
		NodeId: self.object.str("nodeId"),
	}
	agentId, err := ParseId(self.object.str("agentId"))
	if err != nil {
		return nil
	}
	runId, err := ParseId(self.object.str("runId"))
	if err != nil {
		return nil
	}
	link.AgentId = agentId
	link.RunId = runId
	return link
}

// A compaction entry's summary, first kept entry and tokens before.
func (self *HarnessPiEntry) Compaction() (summary string, firstKeptEntryId string, tokensBefore int64, ok bool) {
	if self.Type() != HarnessPiEntryCompaction {
		return "", "", 0, false
	}
	self.object.decode("tokensBefore", &tokensBefore)
	return self.object.str("summary"), self.object.str("firstKeptEntryId"), tokensBefore, true
}

// The member named name, as written, or nil.
func (self *HarnessPiEntry) Field(name string) json.RawMessage {
	return self.object.get(name)
}

// A copy.
func (self *HarnessPiEntry) Clone() *HarnessPiEntry {
	return &HarnessPiEntry{object: self.object.clone()}
}

// The entry as Pi writes its line: JSON.stringify's bytes, which `ur harness export` writes. json.Marshal of an entry
// gives the same value with Go's HTML escapes.
func (self *HarnessPiEntry) Json() ([]byte, error) {
	return self.MarshalJSON()
}

func (self *HarnessPiEntry) MarshalJSON() ([]byte, error) {
	return self.object.MarshalJSON()
}

// Reads an entry, keeping every member as written, refusing one with no type.
func (self *HarnessPiEntry) UnmarshalJSON(data []byte) error {
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(data); err != nil {
		return err
	}
	if object.str("type") == "" {
		return fmt.Errorf("a session entry with no type")
	}
	self.object = object
	return nil
}
