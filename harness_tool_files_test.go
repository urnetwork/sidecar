//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The local file tools, each built for a Harness with the default settings.
func harnessTestFileTools(t *testing.T) map[string]HarnessTool {
	t.Helper()
	harness := &Harness{settings: DefaultHarnessSettings()}
	tools := map[string]HarnessTool{}
	for _, name := range []string{"read", "write", "edit", "ls", "grep", "find"} {
		spec, ok := harnessToolSpecs[name]
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if !spec.BuiltIn || !slices.Equal(spec.Profiles, []HarnessProfile{HarnessProfileLocal}) {
			t.Fatalf("%s: built in %v, profiles %v", name, spec.BuiltIn, spec.Profiles)
		}
		tool, err := spec.New(harness)
		if err != nil {
			t.Fatal(err)
		}
		tools[name] = tool
	}
	return tools
}

// Runs tool in a call carrying workspace, failing the test on an error unless wantError.
func harnessRunFileTool(t *testing.T, tool HarnessTool, workspace *harnessWorkspace, args string) (string, error) {
	t.Helper()
	call := NewHarnessCall(&HarnessCallArgs{Profile: HarnessProfileLocal, ToolCallId: "c", ToolName: tool.Name(), Workspace: workspace})
	result, err := tool.Execute(harnessCallContext(context.Background(), call), "c", []byte(args), func(*HarnessToolUpdate) {})
	if err != nil {
		return "", err
	}
	if result.Trust != HarnessToolTrusted {
		t.Fatalf("%s's result in its own workspace reads %q", tool.Name(), result.Trust)
	}
	return result.Text, nil
}

// The properties and required members of a JSON schema, with each property's type.
func harnessSchemaShape(t *testing.T, schema []byte) (map[string]string, []string) {
	t.Helper()
	parsed := struct {
		Properties map[string]struct {
			Type string `json:"type"`
		} `json:"properties"`
		Required []string `json:"required"`
	}{}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		t.Fatal(err)
	}
	properties := map[string]string{}
	for name, property := range parsed.Properties {
		properties[name] = property.Type
	}
	sort.Strings(parsed.Required)
	return properties, parsed.Required
}

// Each file tool takes Pi 1.5.0's arguments, by name, type and requirement (read.js, write.js, edit.js, ls.js,
// grep.js, find.js), and does what Pi's does in the workspace.
func TestHarnessFileToolsMatchPiArguments(t *testing.T) {
	tools := harnessTestFileTools(t)
	want := map[string]struct {
		properties map[string]string
		required   []string
	}{
		"read":  {properties: map[string]string{"path": "string", "offset": "number", "limit": "number"}, required: []string{"path"}},
		"write": {properties: map[string]string{"path": "string", "content": "string"}, required: []string{"content", "path"}},
		"edit":  {properties: map[string]string{"path": "string", "edits": "array"}, required: []string{"edits", "path"}},
		"ls":    {properties: map[string]string{"path": "string", "limit": "number"}, required: nil},
		"grep": {properties: map[string]string{"pattern": "string", "path": "string", "glob": "string", "ignoreCase": "boolean",
			"literal": "boolean", "context": "number", "limit": "number"}, required: []string{"pattern"}},
		"find": {properties: map[string]string{"pattern": "string", "path": "string", "limit": "number"}, required: []string{"pattern"}},
	}
	for name, shape := range want {
		properties, required := harnessSchemaShape(t, tools[name].Schema())
		if fmt.Sprint(properties) != fmt.Sprint(shape.properties) || !slices.Equal(required, shape.required) {
			t.Errorf("%s takes %v required %v", name, properties, required)
		}
		if tools[name].Name() != name || tools[name].Description() == "" {
			t.Errorf("%s names itself %q", name, tools[name].Name())
		}
	}

	workspace := newHarnessTestWorkspace(t, 1024*1024)
	run := func(name string, args string) string {
		t.Helper()
		text, err := harnessRunFileTool(t, tools[name], workspace, args)
		if err != nil {
			t.Fatalf("%s %s: %v", name, args, err)
		}
		return text
	}
	if got := run("write", `{"path":"src/app.txt","content":"alpha\nbeta\ngamma\n"}`); got != "Successfully wrote to src/app.txt" {
		t.Fatalf("write: %q", got)
	}
	if got := run("read", `{"path":"src/app.txt"}`); got != "alpha\nbeta\ngamma\n" {
		t.Fatalf("read: %q", got)
	}
	if got := run("read", `{"path":"src/app.txt","offset":2,"limit":1}`); got != "beta\n\n[2 more lines in file. Use offset=3 to continue.]" {
		t.Fatalf("read with offset and limit: %q", got)
	}
	if _, err := harnessRunFileTool(t, tools["read"], workspace, `{"path":"src/app.txt","offset":9}`); err == nil ||
		!strings.Contains(err.Error(), "beyond end of file (4 lines total)") {
		t.Fatalf("read past the end: %v", err)
	}
	if got := run("edit", `{"path":"src/app.txt","edits":[{"oldText":"beta","newText":"BETA"}]}`); got != "Successfully replaced 1 block(s) in src/app.txt." {
		t.Fatalf("edit: %q", got)
	}
	// the legacy form, and an edits array sent as a string
	run("edit", `{"path":"src/app.txt","oldText":"alpha","newText":"ALPHA"}`)
	run("edit", `{"path":"src/app.txt","edits":"[{\"oldText\":\"gamma\",\"newText\":\"GAMMA\"}]"}`)
	if got := run("read", `{"path":"src/app.txt"}`); got != "ALPHA\nBETA\nGAMMA\n" {
		t.Fatalf("after the edits: %q", got)
	}
	// an edit's match is exact and unique or refused, nothing written
	for _, args := range []string{
		`{"path":"src/app.txt","edits":[{"oldText":"alpha","newText":"x"}]}`,
		`{"path":"src/app.txt","edits":[{"oldText":"A","newText":"x"}]}`,
		`{"path":"src/app.txt","edits":[{"oldText":"ALPHA\nBETA","newText":"x"},{"oldText":"BETA","newText":"y"}]}`,
		`{"path":"src/app.txt","edits":[{"oldText":"","newText":"x"}]}`,
		`{"path":"src/app.txt","edits":[]}`,
	} {
		if _, err := harnessRunFileTool(t, tools["edit"], workspace, args); err == nil {
			t.Errorf("edit %s passed", args)
		}
	}
	if got := run("read", `{"path":"src/app.txt"}`); got != "ALPHA\nBETA\nGAMMA\n" {
		t.Fatalf("a refused edit wrote: %q", got)
	}
	run("write", `{"path":"src/.hidden","content":"x"}`)
	run("write", `{"path":"Docs/readme.md","content":"beta notes\n"}`)
	if got := run("ls", `{}`); got != "Docs/\nsrc/" {
		t.Fatalf("ls: %q", got)
	}
	if got := run("ls", `{"path":"src"}`); got != ".hidden\napp.txt" {
		t.Fatalf("ls src: %q", got)
	}
	if got := run("grep", `{"pattern":"beta","ignoreCase":true}`); got != "Docs/readme.md:1: beta notes\nsrc/app.txt:2: BETA" {
		t.Fatalf("grep: %q", got)
	}
	if got := run("grep", `{"pattern":"BETA","context":1,"glob":"*.txt"}`); got != "src/app.txt-1- ALPHA\nsrc/app.txt:2: BETA\nsrc/app.txt-3- GAMMA" {
		t.Fatalf("grep with context: %q", got)
	}
	if got := run("grep", `{"pattern":"A.P","literal":true}`); got != "No matches found" {
		t.Fatalf("a literal grep: %q", got)
	}
	if got := run("find", `{"pattern":"*.txt"}`); got != "src/app.txt" {
		t.Fatalf("find: %q", got)
	}
	if got := run("find", `{"pattern":"src/**"}`); got != "src/.hidden\nsrc/app.txt" {
		t.Fatalf("find with a slash: %q", got)
	}
	// a .git directory a worktree holds is never written, listed, searched or found
	if _, err := workspace.WriteFile("repo/.git/config", []byte("x")); err == nil {
		t.Fatal("a file tool wrote under .git")
	}
	gitDirectory := filepath.Join(workspace.HostPath(), "repo", ".git")
	if err := os.MkdirAll(gitDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDirectory, "config"), []byte("[core]\n\tfsmonitor = beta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("write", `{"path":"repo/main.go","content":"package main\n"}`)
	if got := run("find", `{"pattern":"*config*"}`); got != "No files found matching pattern" {
		t.Fatalf("find under .git: %q", got)
	}
	if got := run("ls", `{"path":"repo"}`); got != "main.go" {
		t.Fatalf("ls of a worktree: %q", got)
	}
	if got := run("grep", `{"pattern":"fsmonitor"}`); got != "No matches found" {
		t.Fatalf("grep under .git: %q", got)
	}
	for _, args := range []string{`{"path":"repo/.git/config"}`, `{"path":"repo/.GIT/config"}`} {
		if _, err := harnessRunFileTool(t, tools["read"], workspace, args); err == nil {
			t.Fatalf("read %s", args)
		}
	}
	if _, err := harnessRunFileTool(t, tools["edit"], workspace, `{"path":"repo/.git/config","edits":[{"oldText":"beta","newText":"x"}]}`); err == nil {
		t.Fatal("an edit under .git")
	}
}

// read holds Pi's limits: at most ReadLineCount lines and OutputByteCount bytes, never a partial line, with Pi's
// notices; a line alone past the byte limit is not shown.
func TestHarnessReadTruncatesAsPi(t *testing.T) {
	settings := DefaultHarnessSettings()
	settings.ReadLineCount = 3
	settings.OutputByteCount = 20
	tool := &harnessReadTool{settings: settings}
	workspace := newHarnessTestWorkspace(t, 1024*1024)
	workspace.WriteFile("lines.txt", []byte("one\ntwo\nthree\nfour\nfive"))
	text, err := harnessRunFileTool(t, tool, workspace, `{"path":"lines.txt"}`)
	if err != nil || text != "one\ntwo\nthree\n\n[Showing lines 1-3 of 5. Use offset=4 to continue.]" {
		t.Fatalf("by lines: %q, %v", text, err)
	}
	workspace.WriteFile("wide.txt", []byte("0123456789\nabcdefghij\nklm"))
	text, err = harnessRunFileTool(t, tool, workspace, `{"path":"wide.txt"}`)
	if err != nil || text != "0123456789\n\n[Showing lines 1-1 of 3 (20B limit). Use offset=2 to continue.]" {
		t.Fatalf("by bytes: %q, %v", text, err)
	}
	workspace.WriteFile("long.txt", []byte(strings.Repeat("x", 100)+"\nshort"))
	text, err = harnessRunFileTool(t, tool, workspace, `{"path":"long.txt"}`)
	if err != nil || text != "[Line 1 is longer than 20B. It is not shown.]" {
		t.Fatalf("a long first line: %q, %v", text, err)
	}
}
