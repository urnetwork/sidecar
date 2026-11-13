//go:build !js && !ios && !android && !sdk_mobile_bind

// Cursor's install (§16.7's table; https://cursor.com/docs/agent/hooks and /docs/context/mcp, read for §16.7 on
// 2026-11-03 and 2026-11-05):
//
//	MCP entry  mcpServers.ur in ~/.cursor/mcp.json, or .cursor/mcp.json with --project: {"command": <ur>, "args":
//	           ["mcp", ...]}
//	ask        no rule in a file: beforeMCPExecution answers ask for ur's outward tools, from the catalog built into
//	           the ur binary (CursorHookAnswer), so the hook entry is the ask
//	hooks      ~/.cursor/hooks.json, version 1: beforeMCPExecution, with Ingest.PermissionHookTimeout since it may
//	           wait on a presence prompt (plan-MCP-presence-hook-timing), afterShellExecution, afterMCPExecution and
//	           afterFileEdit, each a list of {command} entries, no matcher
//
// What the seal hashes of hooks.json: its version, and per event each of this ur's entries, sorted by their canonical
// bytes. Another's beforeMCPExecution entry can answer before ur's does, so it counts as competing.

package mcp

import (
	"path/filepath"
)

// Cursor's install.
type cursorInstallAdapter struct{}

// The events ur hooks in Cursor, in the order they are written.
var cursorHookEvents = []harnessHookEvent{
	{name: "beforeMCPExecution", permission: true},
	{name: "afterShellExecution"},
	{name: "afterMCPExecution"},
	{name: "afterFileEdit"},
}

// The hooks.json version ur writes and reads.
const cursorHooksVersion = 1

func (self *cursorInstallAdapter) directory(home string, projectDirectory string) string {
	if projectDirectory != "" {
		return filepath.Join(projectDirectory, ".cursor")
	}
	return filepath.Join(home, ".cursor")
}

func (self *cursorInstallAdapter) files(home string, projectDirectory string) []*harnessFile {
	directory := self.directory(home, projectDirectory)
	mode := harnessFileMode(projectDirectory)
	return []*harnessFile{
		{path: filepath.Join(directory, "mcp.json"), mode: mode, kind: &harnessMcpEntryFile{}},
		{path: filepath.Join(directory, "hooks.json"), mode: mode, kind: &cursorHooksFile{}},
	}
}

func (self *cursorInstallAdapter) projectSettingsFiles(cwd string) []*harnessFile {
	return []*harnessFile{
		{path: filepath.Join(cwd, ".cursor", "hooks.json"), kind: &cursorHooksFile{}},
	}
}

// Cursor's hooks.json.
type cursorHooksFile struct{}

// One entry, as written.
type cursorHookEntry struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

// The template's entry for event.
func (self *cursorHooksFile) entry(event harnessHookEvent, template *harnessTemplate) *cursorHookEntry {
	entry := &cursorHookEntry{Command: template.hookCommand()}
	if event.permission {
		entry.Timeout = template.permissionTimeoutSeconds
	}
	return entry
}

// The template's hooks object.
func (self *cursorHooksFile) hooks(template *harnessTemplate) map[string][]*cursorHookEntry {
	hooks := map[string][]*cursorHookEntry{}
	for _, event := range cursorHookEvents {
		hooks[event.name] = []*cursorHookEntry{self.entry(event, template)}
	}
	return hooks
}

// The event of a name, false for one ur does not hook.
func (self *cursorHooksFile) event(name string) (harnessHookEvent, bool) {
	for _, event := range cursorHookEvents {
		if event.name == name {
			return event, true
		}
	}
	return harnessHookEvent{}, false
}

// The sealed shape: {"version": 1, "hooks": {event: [entry, ...]}}.
func (self *cursorHooksFile) template(template *harnessTemplate) (any, error) {
	hooks := map[string]any{}
	for _, event := range cursorHookEvents {
		hooks[event.name] = []any{self.entry(event, template)}
	}
	return map[string]any{"version": cursorHooksVersion, "hooks": hooks}, nil
}

// Whether an entry runs any ur's `ur hook`.
func cursorUrishEntry(entry *harnessJsonNode) bool {
	command := entry.get("command")
	return command != nil && command.kind == harnessJsonString && harnessUrishCommand(command.text)
}

func (self *cursorHooksFile) nextEdit(content []byte, template *harnessTemplate, maxDepth int) (*harnessEdit, error) {
	root, err := harnessParseJson(content, maxDepth)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return harnessNewDocument(content, map[string]any{"version": cursorHooksVersion, "hooks": self.hooks(template)})
	}
	if root.kind != harnessJsonObject {
		return nil, harnessConfigError("the document is no object")
	}
	version, err := root.member("version")
	if err != nil {
		return nil, err
	}
	if version == nil {
		return harnessJsonAddMember(content, root, "version", cursorHooksVersion)
	}
	if same, err := harnessJsonSame(content, version.value, cursorHooksVersion); err != nil || !same {
		return nil, harnessConfigError("a hooks.json version ur does not write")
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
	// ur's entries on an event ur does not hook
	for _, member := range hooks.value.members {
		if _, ours := self.event(member.key); ours || member.value.kind != harnessJsonArray {
			continue
		}
		for index, entry := range member.value.elements {
			if cursorUrishEntry(entry) {
				return harnessJsonRemoveElement(content, member.value, index), nil
			}
		}
	}
	for _, event := range cursorHookEvents {
		member, err := hooks.value.member(event.name)
		if err != nil {
			return nil, err
		}
		entry := self.entry(event, template)
		if member == nil {
			return harnessJsonAddMember(content, hooks.value, event.name, []*cursorHookEntry{entry})
		}
		if member.value.kind != harnessJsonArray {
			return nil, harnessConfigError("hooks.%s is no list", event.name)
		}
		urEntries := []int{}
		for index, found := range member.value.elements {
			if cursorUrishEntry(found) {
				urEntries = append(urEntries, index)
			}
		}
		if len(urEntries) == 0 {
			return harnessJsonAddElements(content, member.value, []any{entry})
		}
		if same, err := harnessJsonSame(content, member.value.elements[urEntries[0]], entry); err != nil || !same {
			if err != nil {
				return nil, err
			}
			return harnessJsonReplace(content, member.value.elements[urEntries[0]], entry)
		}
		if 1 < len(urEntries) {
			return harnessJsonRemoveElement(content, member.value, urEntries[1]), nil
		}
	}
	return nil, nil
}

func (self *cursorHooksFile) extract(content []byte, template *harnessTemplate, maxDepth int) (any, error) {
	root, err := harnessParseJson(content, maxDepth)
	if err != nil {
		return nil, err
	}
	version, err := harnessJsonValue(content, root.get("version"))
	if err != nil {
		return nil, err
	}
	hooks := map[string]any{}
	if events := root.get("hooks"); events != nil && events.kind == harnessJsonObject {
		for _, member := range events.members {
			if member.value.kind != harnessJsonArray {
				continue
			}
			found := []any{}
			for _, entry := range member.value.elements {
				command := entry.get("command")
				if command == nil || command.kind != harnessJsonString || !template.ownsCommand(command.text) {
					continue
				}
				value, err := harnessJsonValue(content, entry)
				if err != nil {
					return nil, err
				}
				found = append(found, value)
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
	return map[string]any{"version": version, "hooks": hooks}, nil
}

// Every beforeMCPExecution entry that is not this ur's: Cursor's hooks name no matcher, so each one covers ur's tools.
func (self *cursorHooksFile) competing(content []byte, template *harnessTemplate, maxDepth int) (int, error) {
	root, err := harnessParseJson(content, maxDepth)
	if err != nil {
		return 0, err
	}
	count := 0
	events := root.get("hooks")
	if events == nil || events.kind != harnessJsonObject {
		return 0, nil
	}
	for _, member := range events.members {
		if member.key != "beforeMCPExecution" || member.value.kind != harnessJsonArray {
			continue
		}
		for _, entry := range member.value.elements {
			command := entry.get("command")
			if command == nil || command.kind != harnessJsonString || !template.ownsCommand(command.text) {
				count += 1
			}
		}
	}
	return count, nil
}
