//go:build !js && !ios && !android && !sdk_mobile_bind

// Claude Code's install (§16.7's table; https://code.claude.com/docs/en/hooks and /mcp, read for §16.7 on 2026-11-03
// and 2026-11-05):
//
//	MCP entry  mcpServers.ur in ~/.claude.json, the file `claude mcp add --scope user ur` writes, or .mcp.json with
//	           --project: {"type": "stdio", "command": <ur>, "args": ["mcp", ...]}. A reading: ur writes the entry
//	           itself, by an exact edit, rather than running `claude mcp add`, so the diff shows it before anything is
//	           written and no claude binary is needed
//	ask rule   permissions.ask in ~/.claude/settings.json, or .claude/settings.json with --project: mcp__ur__<tool>
//	           for each outward tool, so the harness prompts before every one and its PermissionRequest is harness
//	           evidence (D-MCP-9)
//	hooks      hooks in the same file: SessionStart to SessionEnd, the tool events matching every tool, and
//	           PermissionRequest with Ingest.PermissionHookTimeout, which may wait on a presence prompt
//	           (plan-MCP-presence-hook-timing); each runs `<ur> hook claude-code`. SessionEnd's 1.5 s is the harness's
//	           own bound, which ur hook's 300 ms meets, so nothing is written for it
//
// The same hooks shape serves Codex's hooks.json (harness_install_codex.go), its events its own and no ask rule.
//
// What the seal hashes of a settings file: the ask rules naming ur's server, sorted, and per event each of this ur's
// hook entries with its group's matcher, sorted by their canonical bytes; another ur's entries, an older path's among
// them, are not this ur's and count as competing where they can answer for a tool.

package mcp

import (
	"bytes"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar"
)

// Claude Code's install.
type claudeInstallAdapter struct{}

// The events ur hooks in Claude Code, in the order they are written.
var claudeHookEvents = []harnessHookEvent{
	{name: "SessionStart"},
	{name: "InstructionsLoaded"},
	{name: "UserPromptSubmit"},
	{name: "PreToolUse", matcher: "*"},
	{name: "PermissionRequest", matcher: "*", permission: true},
	{name: "PostToolUse", matcher: "*"},
	{name: "Notification"},
	{name: "Stop"},
	{name: "SubagentStop"},
	{name: "PreCompact"},
	{name: "SessionEnd"},
}

func (self *claudeInstallAdapter) files(home string, projectDirectory string) []*harnessFile {
	mode := harnessFileMode(projectDirectory)
	settings := &harnessHooksFile{askRules: true, events: claudeHookEvents}
	if projectDirectory != "" {
		return []*harnessFile{
			{path: filepath.Join(projectDirectory, ".mcp.json"), mode: mode, kind: &harnessMcpEntryFile{stdioType: true}},
			{path: filepath.Join(projectDirectory, ".claude", "settings.json"), mode: mode, kind: settings},
		}
	}
	return []*harnessFile{
		{path: filepath.Join(home, ".claude.json"), mode: mode, kind: &harnessMcpEntryFile{stdioType: true}},
		{path: filepath.Join(home, ".claude", "settings.json"), mode: mode, kind: settings},
	}
}

func (self *claudeInstallAdapter) projectSettingsFiles(cwd string) []*harnessFile {
	settings := &harnessHooksFile{askRules: true, events: claudeHookEvents}
	return []*harnessFile{
		{path: filepath.Join(cwd, ".claude", "settings.json"), kind: settings},
		{path: filepath.Join(cwd, ".claude", "settings.local.json"), kind: settings},
	}
}

// One event ur hooks: its name, the matcher its group carries ("" for none), and whether its entry may wait on a
// presence prompt and so carries Ingest.PermissionHookTimeout.
type harnessHookEvent struct {
	name       string
	matcher    string
	permission bool
}

// The events whose hooks can answer for a tool call before it runs, where another's hook counts as competing
// (QD-103).
var harnessAnsweringEvents = []string{"PermissionRequest", "PreToolUse", "beforeMCPExecution"}

// An MCP entry file: mcpServers.ur.
type harnessMcpEntryFile struct {
	// Claude Code's entries name their transport; Cursor's do not.
	stdioType bool
}

// The MCP entry, as written.
type harnessMcpEntry struct {
	Type    string   `json:"type,omitempty"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// mcpServers holding ur's entry.
type harnessMcpServers struct {
	McpServers map[string]*harnessMcpEntry `json:"mcpServers"`
}

func (self *harnessMcpEntryFile) entry(template *harnessTemplate) *harnessMcpEntry {
	entry := &harnessMcpEntry{Command: template.urPath, Args: template.mcpArgs()}
	if self.stdioType {
		entry.Type = "stdio"
	}
	return entry
}

func (self *harnessMcpEntryFile) template(template *harnessTemplate) (any, error) {
	return self.entry(template), nil
}

func (self *harnessMcpEntryFile) nextEdit(content []byte, template *harnessTemplate, maxDepth int) (*harnessEdit, error) {
	root, err := harnessParseJson(content, maxDepth)
	if err != nil {
		return nil, err
	}
	entry := self.entry(template)
	if root == nil {
		return harnessNewDocument(content, &harnessMcpServers{McpServers: map[string]*harnessMcpEntry{urMcpServerName: entry}})
	}
	if root.kind != harnessJsonObject {
		return nil, harnessConfigError("the document is no object")
	}
	servers, err := root.member("mcpServers")
	if err != nil {
		return nil, err
	}
	if servers == nil {
		return harnessJsonAddMember(content, root, "mcpServers", map[string]*harnessMcpEntry{urMcpServerName: entry})
	}
	if servers.value.kind != harnessJsonObject {
		return nil, harnessConfigError("mcpServers is no object")
	}
	ur, err := servers.value.member(urMcpServerName)
	if err != nil {
		return nil, err
	}
	if ur == nil {
		return harnessJsonAddMember(content, servers.value, urMcpServerName, entry)
	}
	same, err := harnessJsonSame(content, ur.value, entry)
	if err != nil || same {
		return nil, err
	}
	return harnessJsonReplace(content, ur.value, entry)
}

func (self *harnessMcpEntryFile) extract(content []byte, template *harnessTemplate, maxDepth int) (any, error) {
	root, err := harnessParseJson(content, maxDepth)
	if err != nil {
		return nil, err
	}
	return harnessJsonValue(content, root.get("mcpServers").get(urMcpServerName))
}

// An MCP entry file names no hook or rule.
func (self *harnessMcpEntryFile) competing(content []byte, template *harnessTemplate, maxDepth int) (int, error) {
	return 0, nil
}

// A new document of value at content's end, after any comments it holds.
func harnessNewDocument(content []byte, value any) (*harnessEdit, error) {
	text, err := harnessJsonEncode(value, "", "  ")
	if err != nil {
		return nil, err
	}
	prefix := ""
	if 0 < len(content) && !bytes.HasSuffix(content, []byte("\n")) {
		prefix = "\n"
	}
	return &harnessEdit{start: len(content), end: len(content), text: prefix + text + "\n"}, nil
}

// Whether node holds value, both read as JSON's values.
func harnessJsonSame(content []byte, node *harnessJsonNode, value any) (bool, error) {
	found, err := harnessJsonValue(content, node)
	if err != nil {
		return false, err
	}
	want, err := harnessJsonNormal(value)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(found, want), nil
}

// A hooks file of Claude Code's shape: hooks.<event> is a list of groups, each an optional matcher and a list of
// hook entries; with askRules, permissions.ask too.
type harnessHooksFile struct {
	askRules bool
	events   []harnessHookEvent
}

// One hook group, as written.
type harnessHookGroup struct {
	Matcher string              `json:"matcher,omitempty"`
	Hooks   []*harnessHookEntry `json:"hooks"`
}

// One hook entry, as written.
type harnessHookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

// One of ur's entries as the seal reads it: the entry and its group's matcher.
type harnessSealedHook struct {
	Matcher string `json:"matcher"`
	Hook    any    `json:"hook"`
}

// The ask rule of one outward tool.
func claudeAskRule(tool string) string {
	return "mcp__" + urMcpServerName + "__" + tool
}

// Whether a permission rule names ur's server: mcp__ur itself, or anything under mcp__ur__.
func claudeRuleNamesUr(rule string) bool {
	server := "mcp__" + urMcpServerName
	return rule == server || strings.HasPrefix(rule, server+"__") || strings.HasPrefix(rule, server+"(")
}

// The template's ask rules, sorted.
func (self *harnessHooksFile) askRulesOf(template *harnessTemplate) []string {
	rules := []string{}
	for _, tool := range template.outwardTools {
		rules = append(rules, claudeAskRule(tool))
	}
	return rules
}

// The template's group for event.
func (self *harnessHooksFile) group(event harnessHookEvent, template *harnessTemplate) *harnessHookGroup {
	entry := &harnessHookEntry{Type: "command", Command: template.hookCommand()}
	if event.permission {
		entry.Timeout = template.permissionTimeoutSeconds
	}
	return &harnessHookGroup{Matcher: event.matcher, Hooks: []*harnessHookEntry{entry}}
}

// The template's hooks object.
func (self *harnessHooksFile) hooks(template *harnessTemplate) map[string][]*harnessHookGroup {
	hooks := map[string][]*harnessHookGroup{}
	for _, event := range self.events {
		hooks[event.name] = []*harnessHookGroup{self.group(event, template)}
	}
	return hooks
}

// The template's document, for a file with none.
func (self *harnessHooksFile) document(template *harnessTemplate) any {
	document := map[string]any{"hooks": self.hooks(template)}
	if self.askRules {
		document["permissions"] = map[string]any{"ask": self.askRulesOf(template)}
	}
	return document
}

// The event of a name, false for one ur does not hook.
func (self *harnessHooksFile) event(name string) (harnessHookEvent, bool) {
	for _, event := range self.events {
		if event.name == name {
			return event, true
		}
	}
	return harnessHookEvent{}, false
}

// The sealed shape: {"ask": [...], "hooks": {event: [{matcher, hook}, ...]}}, ask only where the file has rules.
func (self *harnessHooksFile) template(template *harnessTemplate) (any, error) {
	sealed := map[string]any{}
	if self.askRules {
		sealed["ask"] = self.askRulesOf(template)
	}
	hooks := map[string]any{}
	for _, event := range self.events {
		group := self.group(event, template)
		hook, err := harnessJsonNormal(group.Hooks[0])
		if err != nil {
			return nil, err
		}
		hooks[event.name] = []any{&harnessSealedHook{Matcher: event.matcher, Hook: hook}}
	}
	sealed["hooks"] = hooks
	return sealed, nil
}

// How a group's hook entries split: indexes of ur's, any ur's among them, and the count of others'.
func harnessGroupEntries(group *harnessJsonNode) (entries *harnessJsonNode, urIndexes []int, others int) {
	entries = group.get("hooks")
	if entries == nil || entries.kind != harnessJsonArray {
		return nil, nil, 0
	}
	for index, entry := range entries.elements {
		command := entry.get("command")
		if command != nil && command.kind == harnessJsonString && harnessUrishCommand(command.text) {
			urIndexes = append(urIndexes, index)
		} else {
			others += 1
		}
	}
	return entries, urIndexes, others
}

func (self *harnessHooksFile) nextEdit(content []byte, template *harnessTemplate, maxDepth int) (*harnessEdit, error) {
	root, err := harnessParseJson(content, maxDepth)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return harnessNewDocument(content, self.document(template))
	}
	if root.kind != harnessJsonObject {
		return nil, harnessConfigError("the document is no object")
	}
	if self.askRules {
		if edit, err := self.nextAskEdit(content, root, template); edit != nil || err != nil {
			return edit, err
		}
	}
	hooks, err := root.member("hooks")
	if err != nil {
		return nil, err
	}
	if hooks == nil {
		return harnessJsonAddMember(content, root, "hooks", self.hooks(template))
	}
	if hooks.value.kind != harnessJsonObject {
		return nil, harnessConfigError("hooks is no object")
	}
	// ur's entries where they no longer belong: beside another's in one group, or on an event ur does not hook
	for _, member := range hooks.value.members {
		if member.value.kind != harnessJsonArray {
			if _, ours := self.event(member.key); ours {
				return nil, harnessConfigError("hooks.%s is no list", member.key)
			}
			continue
		}
		_, ours := self.event(member.key)
		for index, group := range member.value.elements {
			entries, urIndexes, others := harnessGroupEntries(group)
			switch {
			case 0 < len(urIndexes) && 0 < others:
				return harnessJsonRemoveElement(content, entries, urIndexes[0]), nil
			case 0 < len(urIndexes) && !ours:
				return harnessJsonRemoveElement(content, member.value, index), nil
			}
		}
	}
	for _, event := range self.events {
		member, err := hooks.value.member(event.name)
		if err != nil {
			return nil, err
		}
		group := self.group(event, template)
		if member == nil {
			return harnessJsonAddMember(content, hooks.value, event.name, []*harnessHookGroup{group})
		}
		urGroups := []int{}
		for index, found := range member.value.elements {
			if _, urIndexes, others := harnessGroupEntries(found); 0 < len(urIndexes) && others == 0 {
				urGroups = append(urGroups, index)
			}
		}
		if len(urGroups) == 0 {
			return harnessJsonAddElements(content, member.value, []any{group})
		}
		if same, err := harnessJsonSame(content, member.value.elements[urGroups[0]], group); err != nil || !same {
			if err != nil {
				return nil, err
			}
			return harnessJsonReplace(content, member.value.elements[urGroups[0]], group)
		}
		if 1 < len(urGroups) {
			return harnessJsonRemoveElement(content, member.value, urGroups[1]), nil
		}
	}
	return nil, nil
}

// The next edit of permissions.ask: a rule naming ur that the template has not, or has once already, removed; then
// the template's missing rules added.
func (self *harnessHooksFile) nextAskEdit(content []byte, root *harnessJsonNode, template *harnessTemplate) (*harnessEdit, error) {
	rules := self.askRulesOf(template)
	permissions, err := root.member("permissions")
	if err != nil {
		return nil, err
	}
	if permissions == nil {
		return harnessJsonAddMember(content, root, "permissions", map[string]any{"ask": rules})
	}
	if permissions.value.kind != harnessJsonObject {
		return nil, harnessConfigError("permissions is no object")
	}
	ask, err := permissions.value.member("ask")
	if err != nil {
		return nil, err
	}
	if ask == nil {
		return harnessJsonAddMember(content, permissions.value, "ask", rules)
	}
	if ask.value.kind != harnessJsonArray {
		return nil, harnessConfigError("permissions.ask is no list")
	}
	seen := map[string]bool{}
	for index, element := range ask.value.elements {
		if element.kind != harnessJsonString || !claudeRuleNamesUr(element.text) {
			continue
		}
		if !slices.Contains(rules, element.text) || seen[element.text] {
			return harnessJsonRemoveElement(content, ask.value, index), nil
		}
		seen[element.text] = true
	}
	missing := []any{}
	for _, rule := range rules {
		if !seen[rule] {
			missing = append(missing, rule)
		}
	}
	if 0 < len(missing) {
		return harnessJsonAddElements(content, ask.value, missing)
	}
	return nil, nil
}

func (self *harnessHooksFile) extract(content []byte, template *harnessTemplate, maxDepth int) (any, error) {
	root, err := harnessParseJson(content, maxDepth)
	if err != nil {
		return nil, err
	}
	sealed := map[string]any{}
	if self.askRules {
		rules := []any{}
		found := []string{}
		if ask := root.get("permissions").get("ask"); ask != nil && ask.kind == harnessJsonArray {
			for _, element := range ask.elements {
				if element.kind == harnessJsonString && claudeRuleNamesUr(element.text) {
					found = append(found, element.text)
				}
			}
		}
		slices.Sort(found)
		for _, rule := range found {
			rules = append(rules, rule)
		}
		sealed["ask"] = rules
	}
	hooks := map[string]any{}
	if events := root.get("hooks"); events != nil && events.kind == harnessJsonObject {
		for _, member := range events.members {
			if member.value.kind != harnessJsonArray {
				continue
			}
			found := []any{}
			for _, group := range member.value.elements {
				matcher := ""
				if node := group.get("matcher"); node != nil && node.kind == harnessJsonString {
					matcher = node.text
				}
				entries, _, _ := harnessGroupEntries(group)
				if entries == nil {
					continue
				}
				for _, entry := range entries.elements {
					command := entry.get("command")
					if command == nil || command.kind != harnessJsonString || !template.ownsCommand(command.text) {
						continue
					}
					hook, err := harnessJsonValue(content, entry)
					if err != nil {
						return nil, err
					}
					found = append(found, &harnessSealedHook{Matcher: matcher, Hook: hook})
				}
			}
			if 0 < len(found) {
				sorted, err := harnessSortedByCanonical(found)
				if err != nil {
					return nil, err
				}
				hooks[member.key] = sorted
			}
		}
	}
	sealed["hooks"] = hooks
	return sealed, nil
}

// values sorted by their RFC 8785 bytes, so an order the person or the harness changed does not change the seal.
func harnessSortedByCanonical(values []any) ([]any, error) {
	type keyed struct {
		key   []byte
		value any
	}
	keyedValues := []keyed{}
	for _, value := range values {
		encoded, err := harnessJsonEncode(value, "", "")
		if err != nil {
			return nil, err
		}
		key, err := sidecar.CanonicalJson([]byte(encoded))
		if err != nil {
			return nil, err
		}
		keyedValues = append(keyedValues, keyed{key: key, value: value})
	}
	slices.SortStableFunc(keyedValues, func(a keyed, b keyed) int { return bytes.Compare(a.key, b.key) })
	sorted := []any{}
	for _, value := range keyedValues {
		sorted = append(sorted, value.value)
	}
	return sorted, nil
}

// Hooks on an answering event whose group's matcher covers one of ur's outward tools and whose command is not this
// ur's, and allow rules naming ur's server (QD-103).
func (self *harnessHooksFile) competing(content []byte, template *harnessTemplate, maxDepth int) (int, error) {
	root, err := harnessParseJson(content, maxDepth)
	if err != nil {
		return 0, err
	}
	count := 0
	if allow := root.get("permissions").get("allow"); allow != nil && allow.kind == harnessJsonArray {
		for _, element := range allow.elements {
			if element.kind == harnessJsonString && claudeRuleCovers(element.text) {
				count += 1
			}
		}
	}
	events := root.get("hooks")
	if events == nil || events.kind != harnessJsonObject {
		return count, nil
	}
	for _, member := range events.members {
		if !slices.Contains(harnessAnsweringEvents, member.key) || member.value.kind != harnessJsonArray {
			continue
		}
		for _, group := range member.value.elements {
			matcher := ""
			if node := group.get("matcher"); node != nil && node.kind == harnessJsonString {
				matcher = node.text
			}
			if !harnessMatcherCoversUr(matcher, template.outwardTools) {
				continue
			}
			entries := group.get("hooks")
			if entries == nil || entries.kind != harnessJsonArray {
				continue
			}
			for _, entry := range entries.elements {
				command := entry.get("command")
				if command == nil || command.kind != harnessJsonString || !template.ownsCommand(command.text) {
					count += 1
				}
			}
		}
	}
	return count, nil
}

// Whether an allow rule can allow one of ur's tools: one naming ur's server, or a wildcard over MCP servers.
func claudeRuleCovers(rule string) bool {
	if claudeRuleNamesUr(rule) {
		return true
	}
	return rule == "*" || rule == "mcp__*" || strings.HasPrefix(rule, "mcp__*")
}

// Whether a group's matcher covers a call of one of ur's outward tools: none or * matches every tool, and any other
// is a regular expression a tool's name is tested against. One that does not compile covers, the closed reading.
func harnessMatcherCoversUr(matcher string, outwardTools []string) bool {
	if matcher == "" || matcher == "*" {
		return true
	}
	pattern, err := regexp.Compile(matcher)
	if err != nil {
		return true
	}
	for _, tool := range outwardTools {
		if pattern.MatchString(claudeAskRule(tool)) {
			return true
		}
	}
	return false
}
