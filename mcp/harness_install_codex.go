//go:build !js && !ios && !android && !sdk_mobile_bind

// Codex's install (§16.7's table; https://learn.chatgpt.com/docs/hooks.md and /docs/extend/mcp?surface=cli, read for
// §16.7 on 2026-11-03 and 2026-11-05):
//
//	MCP entry  [mcp_servers.ur] in ~/.codex/config.toml, command and args, and each outward tool's own table under
//	           it, [mcp_servers.ur.tools.<tool>], with approval_mode "prompt", Codex's per-tool approval, so it asks
//	           before every one. The table's spelling is a reading MCP-M3-28's conformance run pins
//	hooks      ~/.codex/hooks.json, Claude Code's shape: PermissionRequest with Ingest.PermissionHookTimeout,
//	           PreToolUse and PostToolUse matching every tool (shell, apply_patch and MCP among them), and the session
//	           events. Codex trusts the file by its hash, so it asks the person to trust it again after an install.
//	           SessionEnd's 1 s is the harness's own bound, which ur hook's 300 ms meets
//	--project  .codex/config.toml and .codex/hooks.json in the project, a reading, since §16.7 names only the user's
//
// config.toml is edited by whole tables: every table under mcp_servers.ur is ur's, replaced together by the
// template's block where the first one stood, and a config defining mcp_servers.ur any other way is refused
// (harness_config.go). What the seal hashes of it: mcp_servers.ur's tables as one JSON object.

package mcp

import (
	"path/filepath"
	"reflect"
	"strings"
)

// Codex's install.
type codexInstallAdapter struct{}

// The events ur hooks in Codex, in the order they are written.
var codexHookEvents = []harnessHookEvent{
	{name: "SessionStart", start: true},
	{name: "UserPromptSubmit"},
	{name: "PreToolUse", matcher: "*"},
	{name: "PermissionRequest", matcher: "*", permission: true},
	{name: "PostToolUse", matcher: "*"},
	{name: "Stop"},
	{name: "SessionEnd"},
}

func (self *codexInstallAdapter) directory(home string, projectDirectory string) string {
	if projectDirectory != "" {
		return filepath.Join(projectDirectory, ".codex")
	}
	return filepath.Join(home, ".codex")
}

func (self *codexInstallAdapter) files(home string, projectDirectory string) []*harnessFile {
	directory := self.directory(home, projectDirectory)
	mode := harnessFileMode(projectDirectory)
	return []*harnessFile{
		{path: filepath.Join(directory, "config.toml"), mode: mode, kind: &codexConfigFile{}},
		{path: filepath.Join(directory, "hooks.json"), mode: mode, kind: &harnessHooksFile{events: codexHookEvents}},
	}
}

func (self *codexInstallAdapter) projectSettingsFiles(cwd string) []*harnessFile {
	return []*harnessFile{
		{path: filepath.Join(cwd, ".codex", "hooks.json"), kind: &harnessHooksFile{events: codexHookEvents}},
	}
}

// Codex's config.toml: mcp_servers.ur's tables.
type codexConfigFile struct{}

// The table path of ur's MCP server.
var codexServerKeys = []string{"mcp_servers", urMcpServerName}

// The approval mode each outward tool's table sets: Codex asks before the call.
const codexApprovalModePrompt = "prompt"

// ur's server as one object: command, args, and tools.<tool>.approval_mode.
func (self *codexConfigFile) template(template *harnessTemplate) (any, error) {
	tools := map[string]any{}
	for _, tool := range template.outwardTools {
		tools[tool] = map[string]any{"approval_mode": codexApprovalModePrompt}
	}
	server := map[string]any{"command": template.urPath, "args": template.mcpArgs()}
	if 0 < len(tools) {
		server["tools"] = tools
	}
	return server, nil
}

// The template's block of tables, each line ending in a newline, a blank line between tables.
func (self *codexConfigFile) block(template *harnessTemplate) string {
	text := strings.Builder{}
	text.WriteString("[mcp_servers." + urMcpServerName + "]\n")
	text.WriteString("command = " + harnessTomlString(template.urPath) + "\n")
	args := []string{}
	for _, arg := range template.mcpArgs() {
		args = append(args, harnessTomlString(arg))
	}
	text.WriteString("args = [" + strings.Join(args, ", ") + "]\n")
	for _, tool := range template.outwardTools {
		text.WriteString("\n[mcp_servers." + urMcpServerName + ".tools." + tool + "]\n")
		text.WriteString("approval_mode = " + harnessTomlString(codexApprovalModePrompt) + "\n")
	}
	return text.String()
}

// ur's tables, in order, refused where mcp_servers.ur is defined any other way: a dotted key or an inline table
// outside them, or an array of tables.
func (self *codexConfigFile) urTables(document *harnessTomlDocument) ([]*harnessTomlTable, error) {
	tables := []*harnessTomlTable{}
	for _, table := range document.tables {
		if table.keys != nil && table.keys.hasPrefix(codexServerKeys...) {
			if table.arrayOfThem {
				return nil, harnessConfigError("mcp_servers.%s as an array of tables", urMcpServerName)
			}
			tables = append(tables, table)
			continue
		}
		for _, value := range table.values {
			full := append(append(harnessTomlKey{}, table.keys...), value.keys...)
			if full.hasPrefix(codexServerKeys...) {
				return nil, harnessConfigError("mcp_servers.%s set by a dotted key", urMcpServerName)
			}
			if codexServerKeysHavePrefix(full) {
				if object, ok := value.value.(map[string]any); ok && codexInlineHoldsServer(object, codexServerKeys[len(full):]) {
					return nil, harnessConfigError("mcp_servers.%s set by an inline table", urMcpServerName)
				}
			}
		}
	}
	return tables, nil
}

// Whether keys is a proper prefix of mcp_servers.ur.
func codexServerKeysHavePrefix(keys harnessTomlKey) bool {
	return len(keys) < len(codexServerKeys) && harnessTomlKey(codexServerKeys).hasPrefix(keys...)
}

// Whether an inline table holds the rest of mcp_servers.ur's path.
func codexInlineHoldsServer(object map[string]any, rest []string) bool {
	for _, key := range rest {
		next, ok := object[key]
		if !ok {
			return false
		}
		if nested, isObject := next.(map[string]any); isObject {
			object = nested
			continue
		}
		return true
	}
	return true
}

// ur's tables as one object, nil for none.
func (self *codexConfigFile) entries(document *harnessTomlDocument, tables []*harnessTomlTable) (any, error) {
	if len(tables) == 0 {
		return nil, nil
	}
	server := map[string]any{}
	for _, table := range tables {
		relative := table.keys[len(codexServerKeys):]
		// the header alone makes its table, empty or not
		object := server
		for _, key := range relative {
			next, ok := object[key]
			if !ok {
				made := map[string]any{}
				object[key] = made
				object = made
				continue
			}
			nested, isObject := next.(map[string]any)
			if !isObject {
				return nil, harnessConfigError("mcp_servers.%s.%s is a value and a table", urMcpServerName, key)
			}
			object = nested
		}
		for _, value := range table.values {
			if err := harnessTomlSet(object, value.keys, value.value); err != nil {
				return nil, err
			}
		}
	}
	return server, nil
}

func (self *codexConfigFile) nextEdit(content []byte, template *harnessTemplate, maxDepth int) (*harnessEdit, error) {
	document, err := harnessParseToml(content, maxDepth)
	if err != nil {
		return nil, err
	}
	tables, err := self.urTables(document)
	if err != nil {
		return nil, err
	}
	block := self.block(template)
	if len(tables) == 0 {
		prefix := ""
		switch {
		case len(content) == 0:
		case !strings.HasSuffix(string(content), "\n"):
			prefix = "\n\n"
		case !strings.HasSuffix(string(content), "\n\n"):
			prefix = "\n"
		}
		return &harnessEdit{start: len(content), end: len(content), text: prefix + block}, nil
	}
	found, err := self.entries(document, tables)
	if err != nil {
		return nil, err
	}
	templateValue, err := self.template(template)
	if err != nil {
		return nil, err
	}
	want, err := harnessJsonNormal(templateValue)
	if err != nil {
		return nil, err
	}
	if reflect.DeepEqual(found, want) {
		return nil, nil
	}
	if 1 < len(tables) {
		last := tables[len(tables)-1]
		return &harnessEdit{start: last.start, end: last.end}, nil
	}
	table := tables[0]
	text := block
	if table.end < len(content) && strings.HasSuffix(string(content[table.start:table.end]), "\n\n") {
		// the blank line before the next table stays
		text += "\n"
	}
	return &harnessEdit{start: table.start, end: table.end, text: text}, nil
}

func (self *codexConfigFile) extract(content []byte, template *harnessTemplate, maxDepth int) (any, error) {
	document, err := harnessParseToml(content, maxDepth)
	if err != nil {
		return nil, err
	}
	tables, err := self.urTables(document)
	if err != nil {
		return nil, err
	}
	return self.entries(document, tables)
}

// Codex's config names no hook: an outward tool's approval mode is ur's own table, which the seal covers.
func (self *codexConfigFile) competing(content []byte, template *harnessTemplate, maxDepth int) (int, error) {
	return 0, nil
}
