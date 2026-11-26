//go:build !ios_extension && !sidecar_http

// harness-1, the Harness's first renderer (CTXH-M11-04; DESIGN-COMPUTE §24.6, D-CTXH-4): the request a Harness call sends,
// a pure function of the Pi v3 entries of its context (harness_pi_entry.go), each entry's trust and the call's params.
// HARN's loop renders each request with it from its journaled nodes (HARN-M11-08), so a rebuild from the record equals
// what was sent by construction. Its goldens (testdata/session/renderers/harness-1/) are frozen once shipped: a change
// to what it renders is harness-2.
//
//	context   the path from the input node to its root; the newest compaction on it, its summary first, then the
//	          messages from its firstKeptEntryId on, the rest staying in the tree; system messages on the path up to
//	          the call's system node, the first whole and each later one a patch
//	system    one system message: the sections' texts joined by a blank line, skill first, instructions last and any
//	          other between in name order, since a recorded item's members are in RFC 8785's order and the Harness's
//	          are in its own; then the tools, each later system message replacing a tool of its name or adding it
//	messages  user text and images; assistant text, its thinking as the reasoning sent back, and its tool calls, their
//	          arguments in RFC 8785 form; a tool result's text and images, naming its call; a custom message, a bash
//	          execution, a compaction's and a branch's summary as user text; a model or effort change, usage, a custom
//	          entry and a link render nothing, a link keeping a sub-agent's context apart from its parent's (§24.4)
//	trust     an untrusted node's text goes between the untrusted-data markers naming its sender (harness_untrusted.go)
//	params    the call's model, effort, maxima, sampling, schema, run, agent and budget: CallContext.params, InferRequest's
//	          JSON with no messages and no tools; a field harness-1 does not know refuses, since a field INFER adds is
//	          a new renderer
//
// A node's trust is the Pi entry's own member untrusted, {"sender": ...}, which SessionNodeOfHarness writes from the
// Harness's journal node, so a rebuild places the markers where the call did.
//
// Safe for concurrent use: a value.

package sidecar

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// harness-1's id.
const SessionRendererHarness1 = "harness-1"

// The Pi entry member a node's trust rides in, and its sender's.
const (
	sessionHarnessUntrustedMember = "untrusted"
	sessionHarnessSenderMember    = "sender"
)

// The system sections harness-1 places first and last.
const (
	sessionHarnessSectionFirst = "skill"
	sessionHarnessSectionLast  = "instructions"
)

// The words a compaction's and a branch's summary open with, which harness-1's goldens freeze.
const (
	sessionHarnessCompactionLead = "The conversation before this point was compacted into this summary:\n\n"
	sessionHarnessBranchLead     = "This conversation came back from a branch, summarized:\n\n"
)

// InferRequest's JSON names when harness-1 shipped, which its id stands for: a name INFER adds or takes away is a new
// renderer (TestSessionRendererGoldens holds InferRequest to these).
var sessionHarness1RequestFields = []string{
	"model", "messages", "tools", "tool_choice", "schema", "reasoning", "max_output", "sampling", "run_id", "agent_id",
	"binding", "budget",
}

// Registers harness-1, which every build holds.
func init() {
	RegisterSessionRenderer(sessionHarness1Renderer{})
}

// harness-1.
type sessionHarness1Renderer struct{}

// harness-1.
func (sessionHarness1Renderer) Id() string {
	return SessionRendererHarness1
}

// Stamps a Harness journal node's trust on its entry (the file header's trust row): an untrusted node's entry gains
// the member untrusted, {"sender": sender}, which harness-1 reads to place the markers. A trusted node's entry is
// returned as it is.
func SessionHarnessEntryWithTrust(entry *HarnessPiEntry, untrusted bool, sender string) *HarnessPiEntry {
	if !untrusted {
		return entry
	}
	stamped := entry.Clone()
	stamped.object.set(sessionHarnessUntrustedMember, map[string]string{sessionHarnessSenderMember: sender})
	return stamped
}

// A Pi entry's trust: whether it carries the member untrusted, and the sender it names.
func sessionHarnessEntryTrust(entry *HarnessPiEntry) (bool, string) {
	raw := entry.Field(sessionHarnessUntrustedMember)
	if raw == nil {
		return false, ""
	}
	trust := map[string]string{}
	if json.Unmarshal(raw, &trust) != nil {
		// a member that does not read: untrusted, its sender unknown
		return true, ""
	}
	return true, trust[sessionHarnessSenderMember]
}

// An item as a Pi entry, refused where it is none.
func sessionHarnessEntryOf(item []byte) (*HarnessPiEntry, error) {
	entry := &HarnessPiEntry{}
	if err := json.Unmarshal(item, entry); err != nil {
		return nil, fmt.Errorf("%w: an item that is no Pi entry: %v", ErrSessionRenderRefused, err)
	}
	return entry, nil
}

// Whether entry is a system message.
func sessionHarnessIsSystem(entry *HarnessPiEntry) bool {
	message := entry.Message()
	return message != nil && message.Role() == HarnessPiRoleSystem
}

// The context of a Harness call (the file header's context row): path is the input node's path, its root first.
func (sessionHarness1Renderer) Context(path []*SessionRenderNode, systemNodeId *Id, nodeOf func(nodeId Id) (*SessionRenderNode, bool)) (*SessionRenderInput, error) {
	entries := make([]*HarnessPiEntry, 0, len(path))
	for _, node := range path {
		entry, err := sessionHarnessEntryOf(node.Item)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	systemAt := len(path) - 1
	if systemNodeId != nil {
		systemAt = slices.IndexFunc(path, func(node *SessionRenderNode) bool { return node.NodeId == *systemNodeId })
		if systemAt < 0 || !sessionHarnessIsSystem(entries[systemAt]) {
			return nil, fmt.Errorf("%w: the call's system node is no system message on its path", ErrSessionRenderRefused)
		}
	}
	compactionAt := -1
	for i, entry := range entries {
		if entry.Type() == HarnessPiEntryCompaction {
			compactionAt = i
		}
	}
	keepFrom := 0
	input := &SessionRenderInput{}
	if 0 <= compactionAt {
		_, firstKept, _, _ := entries[compactionAt].Compaction()
		keepFrom = compactionAt
		for i := range compactionAt {
			if entries[i].Id() == firstKept {
				keepFrom = i
				break
			}
		}
		input.Nodes = append(input.Nodes, path[compactionAt])
	}
	for i, entry := range entries {
		if sessionHarnessIsSystem(entry) {
			if i <= systemAt {
				input.System = append(input.System, path[i])
			}
			continue
		}
		if 0 <= compactionAt && (i < keepFrom || i == compactionAt) {
			continue
		}
		input.Nodes = append(input.Nodes, path[i])
	}
	return input, nil
}

// The request (the file header's rows).
func (sessionHarness1Renderer) Render(context *SessionRenderContext) (*InferRequest, error) {
	request := &InferRequest{}
	if len(context.Params) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(context.Params))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(request); err != nil {
			return nil, fmt.Errorf("%w: params harness-1 does not take: %v", ErrSessionRenderRefused, err)
		}
		if request.Messages != nil || request.Tools != nil {
			return nil, fmt.Errorf("%w: params that hold messages or tools", ErrSessionRenderRefused)
		}
	}
	system, tools, err := sessionHarness1System(context.System)
	if err != nil {
		return nil, err
	}
	if system != "" {
		request.Messages = append(request.Messages, &InferMessage{Role: InferRoleSystem, Parts: []*InferPart{{Kind: InferPartText, Text: system}}})
	}
	request.Tools = tools
	for _, node := range context.Nodes {
		message, err := sessionHarness1Message(node)
		if err != nil {
			return nil, err
		}
		if message != nil {
			request.Messages = append(request.Messages, message)
		}
	}
	return request, nil
}

// The system text and the tools of the system messages in force: the first whole, each later one a patch.
func sessionHarness1System(items []*SessionRenderItem) (string, []*InferTool, error) {
	sectionTexts := map[string]string{}
	toolNames := []string{}
	toolsByName := map[string]*InferTool{}
	for _, item := range items {
		entry, err := sessionHarnessEntryOf(item.Item)
		if err != nil {
			return "", nil, err
		}
		message := entry.Message()
		if message == nil || message.Role() != HarnessPiRoleSystem {
			return "", nil, fmt.Errorf("%w: a system node that is no system message", ErrSessionRenderRefused)
		}
		if raw := message.Field("sections"); raw != nil {
			sections := map[string]string{}
			if err := json.Unmarshal(raw, &sections); err != nil {
				return "", nil, fmt.Errorf("%w: a system message's sections: %v", ErrSessionRenderRefused, err)
			}
			for name, text := range sections {
				sectionTexts[name] = text
			}
		}
		if raw := message.Field("toolsAdded"); raw != nil {
			added := []*HarnessPiTool{}
			if err := json.Unmarshal(raw, &added); err != nil {
				return "", nil, fmt.Errorf("%w: a system message's tools: %v", ErrSessionRenderRefused, err)
			}
			for _, tool := range added {
				schema, err := sessionHarness1Json(tool.Parameters)
				if err != nil {
					return "", nil, err
				}
				if _, held := toolsByName[tool.Name]; !held {
					toolNames = append(toolNames, tool.Name)
				}
				toolsByName[tool.Name] = &InferTool{Name: tool.Name, Description: tool.Description, Schema: schema}
			}
		}
	}
	names := []string{}
	for name := range sectionTexts {
		if name != sessionHarnessSectionFirst && name != sessionHarnessSectionLast {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	if _, ok := sectionTexts[sessionHarnessSectionFirst]; ok {
		names = append([]string{sessionHarnessSectionFirst}, names...)
	}
	if _, ok := sectionTexts[sessionHarnessSectionLast]; ok {
		names = append(names, sessionHarnessSectionLast)
	}
	texts := []string{}
	for _, name := range names {
		if text := sectionTexts[name]; text != "" {
			texts = append(texts, text)
		}
	}
	var tools []*InferTool
	for _, name := range toolNames {
		tools = append(tools, toolsByName[name])
	}
	return strings.Join(texts, "\n\n"), tools, nil
}

// JSON in RFC 8785 form, nil for none; a value that is no JSON kept as written, as a string, as Pi keeps a model's.
func sessionHarness1Json(value json.RawMessage) (json.RawMessage, error) {
	if len(value) == 0 {
		return nil, nil
	}
	canonical, err := CanonicalJson(value)
	if err != nil {
		quoted, err := json.Marshal(string(value))
		if err != nil {
			return nil, err
		}
		return quoted, nil
	}
	return canonical, nil
}

// A content block list's parts: its text blocks joined as one text part, then its images, in order. The text is
// fenced where the node is untrusted.
func sessionHarness1Parts(blocks []*HarnessPiBlock, item *SessionRenderItem) []*InferPart {
	texts := []string{}
	images := []*InferPart{}
	for _, block := range blocks {
		switch block.Type() {
		case HarnessPiBlockText:
			texts = append(texts, block.Text())
		case HarnessPiBlockImage:
			mediaType := block.object.str("mimeType")
			data := block.object.str("data")
			decoded, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				// a request hash's form, a part's reference in place of its bytes: kept as written
				decoded = []byte(data)
			}
			images = append(images, &InferPart{Kind: InferPartImage, MediaType: mediaType, Data: decoded})
		}
	}
	parts := []*InferPart{}
	if text := strings.Join(texts, ""); text != "" || len(images) == 0 {
		parts = append(parts, &InferPart{Kind: InferPartText, Text: sessionHarness1Fence(item, text)})
	}
	return append(parts, images...)
}

// text as the model reads it from item: between the markers where item is untrusted.
func sessionHarness1Fence(item *SessionRenderItem, text string) string {
	if !item.Untrusted {
		return text
	}
	return HarnessUntrustedText(item.Sender, text)
}

// The message a context node renders to, nil for none. A node is untrusted where its entry says so, or its caller does.
func sessionHarness1Message(item *SessionRenderItem) (*InferMessage, error) {
	entry, err := sessionHarnessEntryOf(item.Item)
	if err != nil {
		return nil, err
	}
	if untrusted, sender := sessionHarnessEntryTrust(entry); untrusted && !item.Untrusted {
		marked := *item
		marked.Untrusted, marked.Sender = true, sender
		item = &marked
	}
	userText := func(text string) *InferMessage {
		return &InferMessage{Role: InferRoleUser, Parts: []*InferPart{{Kind: InferPartText, Text: sessionHarness1Fence(item, text)}}}
	}
	switch entry.Type() {
	case HarnessPiEntryCompaction:
		summary, _, _, _ := entry.Compaction()
		return userText(sessionHarnessCompactionLead + summary), nil
	case HarnessPiEntryBranchSummary:
		summary := ""
		json.Unmarshal(entry.Field("summary"), &summary)
		return userText(sessionHarnessBranchLead + summary), nil
	case HarnessPiEntryCustomMessage:
		content := ""
		json.Unmarshal(entry.Field("content"), &content)
		return userText(content), nil
	case HarnessPiEntryMessage:
	default:
		// model and effort changes, usage, custom state and links render nothing
		return nil, nil
	}
	message := entry.Message()
	if message == nil {
		return nil, fmt.Errorf("%w: a message entry with no message", ErrSessionRenderRefused)
	}
	switch message.Role() {
	case HarnessPiRoleUser:
		return &InferMessage{Role: InferRoleUser, Parts: sessionHarness1Parts(message.Blocks(), item)}, nil
	case HarnessPiRoleAssistant:
		rendered := &InferMessage{Role: InferRoleAssistant}
		texts, thinking := []string{}, []string{}
		for _, block := range message.Blocks() {
			switch block.Type() {
			case HarnessPiBlockText:
				texts = append(texts, block.Text())
			case HarnessPiBlockThinking:
				thinking = append(thinking, block.Text())
			case HarnessPiBlockToolCall:
				toolCall := block.ToolCall()
				arguments, err := sessionHarness1Json(toolCall.Arguments)
				if err != nil {
					return nil, err
				}
				rendered.ToolCalls = append(rendered.ToolCalls, &InferToolCall{Id: toolCall.Id, Name: toolCall.Name, Arguments: string(arguments)})
			}
		}
		if text := strings.Join(texts, ""); text != "" {
			rendered.Parts = []*InferPart{{Kind: InferPartText, Text: text}}
		}
		rendered.Reasoning = strings.Join(thinking, "")
		if len(rendered.Parts) == 0 && rendered.Reasoning == "" && len(rendered.ToolCalls) == 0 {
			return nil, nil
		}
		return rendered, nil
	case HarnessPiRoleToolResult:
		return &InferMessage{Role: InferRoleTool, ToolCallId: message.ToolCallId(), Parts: sessionHarness1Parts(message.Blocks(), item)}, nil
	case HarnessPiRoleCustom:
		content := ""
		json.Unmarshal(message.Field("content"), &content)
		return userText(content), nil
	case HarnessPiRoleBashExecution:
		command := ""
		json.Unmarshal(message.Field("command"), &command)
		return userText("$ " + command + "\n" + message.Text()), nil
	case HarnessPiRoleCompactionSummary:
		return userText(sessionHarnessCompactionLead + message.Text()), nil
	case HarnessPiRoleBranchSummary:
		return userText(sessionHarnessBranchLead + message.Text()), nil
	}
	// a system message in the context's nodes, or a role this build does not know: nothing
	return nil, nil
}
