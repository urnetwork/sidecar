//go:build !js && !ios && !android && !sdk_mobile_bind

// Codex's install (§16.7's table; https://learn.chatgpt.com/docs/hooks.md and /docs/extend/mcp?surface=cli, read for
// §16.7 on 2026-11-03 and 2026-11-05):
//
//	MCP entry  [mcp_servers.ur] in ~/.codex/config.toml, command and args, and each outward tool's own table under
//	           it, [mcp_servers.ur.tools.<tool>], with approval_mode "prompt", Codex's per-tool approval, so it asks
//	           before every one. The table's spelling is a reading MCP-M3-28's conformance run pins
//	hooks      ~/.codex/hooks.json, Claude Code's shape: PermissionRequest with Ingest.PermissionHookTimeout,
//	           PreToolUse and PostToolUse matching every tool (shell, apply_patch and MCP among them), the session
//	           events, and PostModelRequest, §16.18's model calls, each of which the hook path records as one
//	           model_call entry while Ingest.ModelCalls is on (hook_codex.go, ingest_model.go; QD-835). Codex trusts
//	           the file by its hash, so it asks the person to trust it again after an install. SessionEnd's 1 s is the
//	           harness's own bound, which ur hook's 300 ms meets
//	--project  .codex/config.toml and .codex/hooks.json in the project, a reading, since §16.7 names only the user's
//	exporter   none: Codex's model calls come from its PostModelRequest hook alone, with each call's request id and
//	           tokens (QD-835), so the install takes no telemetry pair, and it removes the [otel] table, bearer and
//	           all, that an earlier install wrote for QD-822 (below)
//
// config.toml is edited by whole tables: every table under mcp_servers.ur is ur's, replaced together by the template's
// block where the first one stood, and a config defining mcp_servers.ur any other way is refused (harness_config.go).
// What the seal hashes of it: mcp_servers.ur's tables as one JSON object.
//
// An earlier install's exporter table is otel's one table holding exactly what that install wrote for some telemetry
// pair: log_user_prompt false and an otlp-http exporter to 127.0.0.1's logs endpoint at a port, protocol json,
// headers' Authorization a bearer of lowercase hex. The install removes its lines, and where it ends the file the blank
// lines before it, which that install put there, so the rest of the file stays as it was; the diff shows its bearer
// as the token's stand-in (harness_telemetry.go). Anything else under otel, a person's own exporter or ur's table
// edited since, is the person's: it stays byte for byte, refuses nothing, and no seal holds it.

package mcp

import (
	"bytes"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
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
	// §16.18's model calls, Codex's one source of them (QD-835)
	{name: "PostModelRequest"},
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

// ~/.codex, or a project's .codex: Codex's skills are under its skills/.
func (self *codexInstallAdapter) skillDirectory(home string, projectDirectory string) string {
	return self.directory(home, projectDirectory)
}

func (self *codexInstallAdapter) projectSettingsFiles(cwd string) []*harnessFile {
	return []*harnessFile{
		{path: filepath.Join(cwd, ".codex", "hooks.json"), kind: &harnessHooksFile{events: codexHookEvents}},
	}
}

// Codex's config.toml: mcp_servers.ur's tables, and an earlier install's exporter table, which the install removes.
type codexConfigFile struct{}

// The table path of ur's MCP server.
var codexServerKeys = []string{"mcp_servers", urMcpServerName}

// The table path of the exporter's settings an earlier install wrote (QD-822), which this one removes (QD-835).
var codexOtelKeys = []string{"otel"}

// The approval mode each outward tool's table sets: Codex asks before the call.
const codexApprovalModePrompt = "prompt"

// Codex's OTLP/HTTP exporter, as an earlier install's [otel] table named it, and the payload encoding that table set.
const (
	codexOtelExporterOtlpHttp = "otlp-http"
	codexOtelProtocolJson     = "json"
)

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

// The exporter's settings an earlier install wrote for pair, as one object (QD-822): otel's otlp-http exporter naming
// the listener's logs endpoint and the bearer, and log_user_prompt false.
func codexEarlierOtel(pair *HarnessTelemetry) map[string]any {
	return map[string]any{
		"log_user_prompt": false,
		"exporter": map[string]any{
			codexOtelExporterOtlpHttp: map[string]any{
				"endpoint": pair.LogsEndpoint(),
				"protocol": codexOtelProtocolJson,
				"headers":  map[string]any{"Authorization": pair.Authorization()},
			},
		},
	}
}

// An earlier install's exporter table in document and the pair it names (see the file header): false for none, for
// otel defined any other way, and for otel's tables holding anything but exactly what that install wrote.
func codexEarlierOtelTable(document *harnessTomlDocument) (*harnessTomlTable, *HarnessTelemetry, bool) {
	tables, err := codexOwnedTables(document, codexOtelKeys)
	if err != nil || len(tables) != 1 {
		// a dotted key, an inline table, an array of tables or more tables than one: never what an install wrote
		return nil, nil, false
	}
	found, err := codexOwnedEntries(tables, codexOtelKeys)
	if err != nil {
		return nil, nil, false
	}
	// the pair the table would name, then the table that pair renders, which must be the one found
	object, _ := found.(map[string]any)
	exporters, _ := object["exporter"].(map[string]any)
	exporter, _ := exporters[codexOtelExporterOtlpHttp].(map[string]any)
	headers, _ := exporter["headers"].(map[string]any)
	endpoint, _ := exporter["endpoint"].(string)
	authorization, _ := headers["Authorization"].(string)
	address := strings.TrimSuffix(strings.TrimPrefix(endpoint, "http://"), ingestTelemetryLogsPath)
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, false
	}
	port, err := strconv.Atoi(portText)
	token, bearer := strings.CutPrefix(authorization, harnessTelemetryBearerScheme)
	if err != nil || !bearer {
		return nil, nil, false
	}
	pair := &HarnessTelemetry{Version: harnessTelemetryVersion, Port: port, Token: token}
	if pair.validate() != nil {
		return nil, nil, false
	}
	want, err := harnessJsonNormal(codexEarlierOtel(pair))
	if err != nil || !reflect.DeepEqual(found, want) {
		return nil, nil, false
	}
	return tables[0], pair, true
}

// The edit removing an earlier install's exporter table, nil where content holds none: its lines, and where it ends
// the file the blank lines before it, the line before keeping its own ending.
func codexEarlierOtelEdit(content []byte, document *harnessTomlDocument) *harnessEdit {
	table, _, ok := codexEarlierOtelTable(document)
	if !ok {
		return nil
	}
	start := table.start
	if table.end == len(content) {
		kept := len(bytes.TrimRight(content[:table.start], " \t\r\n"))
		start = 0
		if 0 < kept {
			start = kept + bytes.IndexByte(content[kept:table.start], '\n') + 1
		}
	}
	return &harnessEdit{start: start, end: table.end}
}

// The bearer of an earlier install's exporter table content holds, which a plan's diff never prints
// (harnessTelemetryTokenFile).
func (self *codexConfigFile) telemetryTokens(content []byte, maxDepth int) []string {
	document, err := harnessParseToml(content, maxDepth)
	if err != nil {
		return nil
	}
	if _, pair, ok := codexEarlierOtelTable(document); ok {
		return []string{pair.Token}
	}
	return nil
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

// ur's server tables brought to the template's, then an earlier install's exporter table removed.
func (self *codexConfigFile) nextEdit(content []byte, template *harnessTemplate, maxDepth int) (*harnessEdit, error) {
	document, err := harnessParseToml(content, maxDepth)
	if err != nil {
		return nil, err
	}
	tables, err := codexOwnedTables(document, codexServerKeys)
	if err != nil {
		return nil, err
	}
	server, err := self.template(template)
	if err != nil {
		return nil, err
	}
	edit, err := codexTablesEdit(content, tables, codexServerKeys, self.block(template), server)
	if edit != nil || err != nil {
		return edit, err
	}
	return codexEarlierOtelEdit(content, document), nil
}

// ur's server tables as one object, the template's shape: otel's tables are no part of what ur installs.
func (self *codexConfigFile) extract(content []byte, template *harnessTemplate, maxDepth int) (any, error) {
	document, err := harnessParseToml(content, maxDepth)
	if err != nil {
		return nil, err
	}
	tables, err := codexOwnedTables(document, codexServerKeys)
	if err != nil {
		return nil, err
	}
	return codexOwnedEntries(tables, codexServerKeys)
}

// Codex's config names no hook: an outward tool's approval mode is ur's own table, which the seal covers.
func (self *codexConfigFile) competing(content []byte, template *harnessTemplate, maxDepth int) (int, error) {
	return 0, nil
}
