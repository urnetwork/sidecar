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
//	exporter   with a telemetry pair (a user install's alone; QD-822), the [otel] table of config.toml: exporter
//	           otlp-http to the daemon's listener's logs endpoint, protocol json, its bearer in headers'
//	           Authorization, and log_user_prompt false, since the listener takes model calls alone. The listener
//	           takes no Codex record as a call until question harness-telemetry-token-codex-double-count settles
//	           where Codex's calls come from, since §16.18's PostModelRequest hook reports the same calls with their
//	           request ids and tokens (ingest_model.go)
//
// config.toml is edited by whole tables: every table under mcp_servers.ur is ur's, and with a telemetry pair every
// table under otel too, each group replaced together by the template's block where its first table stood, and a config
// defining either any other way is refused (harness_config.go). What the seal hashes of it: mcp_servers.ur's tables as
// one JSON object, and with a telemetry pair that object and otel's, as {"server": ..., "otel": ...}.

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

// Codex's config.toml: mcp_servers.ur's tables, and with a telemetry pair otel's.
type codexConfigFile struct{}

// The table path of ur's MCP server.
var codexServerKeys = []string{"mcp_servers", urMcpServerName}

// The table path of the exporter's settings (QD-822), every table under which is ur's while the template has a
// telemetry pair.
var codexOtelKeys = []string{"otel"}

// The approval mode each outward tool's table sets: Codex asks before the call.
const codexApprovalModePrompt = "prompt"

// Codex's OTLP/HTTP exporter, as its [otel] table names it, and the payload encoding the listener reads.
const (
	codexOtelExporterOtlpHttp = "otlp-http"
	codexOtelProtocolJson     = "json"
)

// ur's server as one object: command, args, and tools.<tool>.approval_mode.
func (self *codexConfigFile) serverTemplate(template *harnessTemplate) map[string]any {
	tools := map[string]any{}
	for _, tool := range template.outwardTools {
		tools[tool] = map[string]any{"approval_mode": codexApprovalModePrompt}
	}
	server := map[string]any{"command": template.urPath, "args": template.mcpArgs()}
	if 0 < len(tools) {
		server["tools"] = tools
	}
	return server
}

// The exporter's settings as one object: otel's exporter, naming the listener and its bearer, and log_user_prompt.
func (self *codexConfigFile) otelTemplate(telemetry *HarnessTelemetry) map[string]any {
	return map[string]any{
		"log_user_prompt": false,
		"exporter": map[string]any{
			codexOtelExporterOtlpHttp: map[string]any{
				"endpoint": telemetry.LogsEndpoint(),
				"protocol": codexOtelProtocolJson,
				"headers":  map[string]any{"Authorization": telemetry.Authorization()},
			},
		},
	}
}

// ur's server's object, and with a telemetry pair that object and otel's: see the file header.
func (self *codexConfigFile) template(template *harnessTemplate) (any, error) {
	server := self.serverTemplate(template)
	if template.telemetry == nil {
		return server, nil
	}
	return map[string]any{"server": server, "otel": self.otelTemplate(template.telemetry)}, nil
}

// The template's block of server tables, each line ending in a newline, a blank line between tables.
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

// The exporter's block: one [otel] table, the exporter an inline table on one line, as TOML 1.0 has them.
func (self *codexConfigFile) otelBlock(telemetry *HarnessTelemetry) string {
	text := strings.Builder{}
	text.WriteString("[otel]\n")
	text.WriteString("log_user_prompt = false\n")
	text.WriteString("exporter = { " + codexOtelExporterOtlpHttp + " = { endpoint = " + harnessTomlString(telemetry.LogsEndpoint()) +
		", protocol = " + harnessTomlString(codexOtelProtocolJson) +
		", headers = { Authorization = " + harnessTomlString(telemetry.Authorization()) + " } } }\n")
	return text.String()
}

// The tables under keys, in order, refused where keys' table is defined any other way: a dotted key or an inline
// table outside them, or an array of tables.
func codexOwnedTables(document *harnessTomlDocument, keys []string) ([]*harnessTomlTable, error) {
	name := strings.Join(keys, ".")
	tables := []*harnessTomlTable{}
	for _, table := range document.tables {
		if table.keys != nil && table.keys.hasPrefix(keys...) {
			if table.arrayOfThem {
				return nil, harnessConfigError("%s as an array of tables", name)
			}
			tables = append(tables, table)
			continue
		}
		for _, value := range table.values {
			full := append(append(harnessTomlKey{}, table.keys...), value.keys...)
			if full.hasPrefix(keys...) {
				return nil, harnessConfigError("%s set by a dotted key", name)
			}
			if codexKeysHavePrefix(keys, full) {
				if object, ok := value.value.(map[string]any); ok && codexInlineHolds(object, keys[len(full):]) {
					return nil, harnessConfigError("%s set by an inline table", name)
				}
			}
		}
	}
	return tables, nil
}

// Whether prefix is a proper prefix of keys.
func codexKeysHavePrefix(keys []string, prefix harnessTomlKey) bool {
	return len(prefix) < len(keys) && harnessTomlKey(keys).hasPrefix(prefix...)
}

// Whether an inline table holds the rest of a table's path.
func codexInlineHolds(object map[string]any, rest []string) bool {
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

// The tables under keys as one object, nil for none.
func codexOwnedEntries(tables []*harnessTomlTable, keys []string) (any, error) {
	if len(tables) == 0 {
		return nil, nil
	}
	owned := map[string]any{}
	for _, table := range tables {
		relative := table.keys[len(keys):]
		// the header alone makes its table, empty or not
		object := owned
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
				return nil, harnessConfigError("%s.%s is a value and a table", strings.Join(keys, "."), key)
			}
			object = nested
		}
		for _, value := range table.values {
			if err := harnessTomlSet(object, value.keys, value.value); err != nil {
				return nil, err
			}
		}
	}
	return owned, nil
}

// The next edit that brings one group of owned tables to the template's block: the block at the end where the group
// has no table, nothing where its tables hold want, else its last table removed while it has more than one, then its
// one table replaced by the block.
func codexTablesEdit(content []byte, tables []*harnessTomlTable, keys []string, block string, want any) (*harnessEdit, error) {
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
	found, err := codexOwnedEntries(tables, keys)
	if err != nil {
		return nil, err
	}
	normal, err := harnessJsonNormal(want)
	if err != nil {
		return nil, err
	}
	if reflect.DeepEqual(found, normal) {
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

func (self *codexConfigFile) nextEdit(content []byte, template *harnessTemplate, maxDepth int) (*harnessEdit, error) {
	document, err := harnessParseToml(content, maxDepth)
	if err != nil {
		return nil, err
	}
	tables, err := codexOwnedTables(document, codexServerKeys)
	if err != nil {
		return nil, err
	}
	edit, err := codexTablesEdit(content, tables, codexServerKeys, self.block(template), self.serverTemplate(template))
	if edit != nil || err != nil || template.telemetry == nil {
		return edit, err
	}
	otelTables, err := codexOwnedTables(document, codexOtelKeys)
	if err != nil {
		return nil, err
	}
	return codexTablesEdit(content, otelTables, codexOtelKeys, self.otelBlock(template.telemetry), self.otelTemplate(template.telemetry))
}

// ur's tables as the template's shape has them; a nil template reads the server's alone.
func (self *codexConfigFile) extract(content []byte, template *harnessTemplate, maxDepth int) (any, error) {
	document, err := harnessParseToml(content, maxDepth)
	if err != nil {
		return nil, err
	}
	tables, err := codexOwnedTables(document, codexServerKeys)
	if err != nil {
		return nil, err
	}
	server, err := codexOwnedEntries(tables, codexServerKeys)
	if err != nil || template == nil || template.telemetry == nil {
		return server, err
	}
	otelTables, err := codexOwnedTables(document, codexOtelKeys)
	if err != nil {
		return nil, err
	}
	otel, err := codexOwnedEntries(otelTables, codexOtelKeys)
	if err != nil {
		return nil, err
	}
	return map[string]any{"server": server, "otel": otel}, nil
}

// Codex's config names no hook: an outward tool's approval mode is ur's own table, which the seal covers.
func (self *codexConfigFile) competing(content []byte, template *harnessTemplate, maxDepth int) (int, error) {
	return 0, nil
}
