//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M3-16: ur install-harness's exact edits and the config hashes. Golden diffs against fixture files holding a
// person's settings (testdata/harness/install/), then the seal's rules: an unrelated edit keeps the hash, and a removed
// hook, a changed ask rule, a competing hook or allow rule, a forged seal or another ur changes it.

package mcp

import (
	"context"
	"encoding/hex"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

var updateHarnessInstall = flag.Bool("update-harness-install", false, "rewrite testdata/harness/install/*.diff")

// The synthetic absolute path every test install names as ur's.
const testHarnessUrPath = "/opt/ur/bin/ur"

// A copy of a harness's fixture home, in a fresh directory.
func testHarnessHome(t *testing.T, harness string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures name POSIX paths")
	}
	home := t.TempDir()
	source := filepath.Join("..", "testdata", "harness", "install", harness, "home")
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(home, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return home
}

// An install of harness into home, its seal under state.
func testHarnessArgs(harness string, home string, state string) *HarnessInstallArgs {
	return &HarnessInstallArgs{
		Harness:        harness,
		Instance:       "default",
		Home:           home,
		UrPath:         testHarnessUrPath,
		StateDirectory: state,
		Ingest:         sidecar.DefaultSidecarSettings().Ingest,
	}
}

// Plans and writes an install.
func testInstallHarness(t *testing.T, args *HarnessInstallArgs) *HarnessInstallPlan {
	t.Helper()
	plan, err := PlanHarnessInstall(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(); err != nil {
		t.Fatal(err)
	}
	return plan
}

// The daemon's check over state, ur's path the test install's.
func testHarnessCheck(state string) *HarnessConfigHashes {
	return NewHarnessConfigHashes(&HarnessConfigHashesArgs{
		StateDirectory: state,
		Executable:     func() (string, error) { return testHarnessUrPath, nil },
		Ingest:         sidecar.DefaultSidecarSettings().Ingest,
	})
}

// Whether the check reads harness changed for cwd, failing on an error where it reads unchanged.
func testHarnessChanged(t *testing.T, check *HarnessConfigHashes, harness string, cwd string) bool {
	t.Helper()
	changed, err := check.Check(context.Background(), harness, cwd)
	if err != nil && !changed {
		t.Fatalf("an error read unchanged: %v", err)
	}
	return changed
}

// Rewrites part of a file: old, which must be there once, becomes replacement.
func testHarnessEdit(t *testing.T, path string, old string, replacement string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(content), old) != 1 {
		t.Fatalf("%q is not in %s once:\n%s", old, path, content)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(content), old, replacement, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Each harness's diff against its fixtures is the golden one, every change an insertion: the person's lines all
// stay, comments and spacing included.
func TestInstallDiffsAreGolden(t *testing.T) {
	for _, harness := range HarnessNames() {
		home := testHarnessHome(t, harness)
		plan, err := PlanHarnessInstall(testHarnessArgs(harness, home, t.TempDir()))
		if err != nil {
			t.Fatalf("%s: %v", harness, err)
		}
		diff := strings.ReplaceAll(plan.Diff(), filepath.ToSlash(home), "/$HOME")
		golden := filepath.Join("..", "testdata", "harness", "install", harness+".diff")
		if *updateHarnessInstall {
			if err := os.WriteFile(golden, []byte(diff), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if diff != string(want) {
			t.Errorf("%s's diff:\n%s\nwant:\n%s", harness, diff, want)
		}
		// a line of the person's goes only where an entry is added after it, and comes back with its comma
		lines := strings.Split(diff, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") && !slices.Contains(lines, "+"+line[1:]+",") {
				t.Errorf("%s's install removes a line of the person's: %q", harness, line)
			}
		}
	}
}

// Running the install again changes nothing, and its config reads unchanged.
func TestReinstallIsIdempotent(t *testing.T) {
	for _, harness := range HarnessNames() {
		home := testHarnessHome(t, harness)
		state := t.TempDir()
		first := testInstallHarness(t, testHarnessArgs(harness, home, state))
		again, err := PlanHarnessInstall(testHarnessArgs(harness, home, state))
		if err != nil {
			t.Fatal(err)
		}
		if changed, err := again.Changed(); err != nil || changed {
			t.Errorf("%s: a second install changes something: %v\n%s", harness, err, again.Diff())
		}
		for i, file := range again.Files {
			if string(file.Before) != string(first.Files[i].After) {
				t.Errorf("%s: %s moved between installs", harness, file.Path)
			}
		}
		if testHarnessChanged(t, testHarnessCheck(state), harness, home) {
			t.Errorf("%s: a fresh install reads changed", harness)
		}
	}
}

// An edit elsewhere in a file, by the person or the harness, changes nothing (QD-103).
func TestUnrelatedEditKeepsHash(t *testing.T) {
	edits := map[string][]struct{ file, old, replacement string }{
		"claude-code": {
			{file: ".claude.json", old: `"numStartups": 42`, replacement: `"numStartups": 43`},
			{file: ".claude/settings.json", old: `"model": "sonnet"`, replacement: `"model": "opus"`},
			{file: ".claude/settings.json", old: `"Bash(rm:*)"`, replacement: `"Bash(rm:*)", "Bash(git push:*)"`},
		},
		"codex": {
			{file: ".codex/config.toml", old: `model = "review-example"`, replacement: "model = \"review-example\"\n\n[profiles.fast]\nmodel = \"fast-example\""},
		},
		"cursor": {
			{file: ".cursor/mcp.json", old: `"args": [] }`, replacement: `"args": ["--fast"] }`},
		},
	}
	for _, harness := range HarnessNames() {
		home := testHarnessHome(t, harness)
		state := t.TempDir()
		testInstallHarness(t, testHarnessArgs(harness, home, state))
		for _, edit := range edits[harness] {
			testHarnessEdit(t, filepath.Join(home, edit.file), edit.old, edit.replacement)
		}
		if testHarnessChanged(t, testHarnessCheck(state), harness, home) {
			t.Errorf("%s: an unrelated edit reads changed", harness)
		}
	}
}

// Removing one of ur's hooks reads changed, and the install puts it back.
func TestRemovedHookChangesHash(t *testing.T) {
	removals := map[string]struct{ file, old, replacement string }{
		"claude-code": {file: ".claude/settings.json", old: `"SessionEnd": [`, replacement: `"SessionEndRemoved": [`},
		"codex":       {file: ".codex/hooks.json", old: `"PostToolUse": [`, replacement: `"PostToolUseRemoved": [`},
		"cursor":      {file: ".cursor/hooks.json", old: `"afterShellExecution": [`, replacement: `"afterShellExecutionRemoved": [`},
	}
	for _, harness := range HarnessNames() {
		home := testHarnessHome(t, harness)
		state := t.TempDir()
		testInstallHarness(t, testHarnessArgs(harness, home, state))
		removal := removals[harness]
		testHarnessEdit(t, filepath.Join(home, removal.file), removal.old, removal.replacement)
		check := testHarnessCheck(state)
		if !testHarnessChanged(t, check, harness, home) {
			t.Errorf("%s: a removed hook reads unchanged", harness)
		}
		testInstallHarness(t, testHarnessArgs(harness, home, state))
		if testHarnessChanged(t, check, harness, home) {
			t.Errorf("%s: the install did not restore its hook", harness)
		}
	}
}

// A changed ask rule or approval mode reads changed, and the install restores ur's, never blessing the change.
func TestWidenedAskRuleChangesHash(t *testing.T) {
	widenings := map[string]struct{ file, old, replacement string }{
		"claude-code": {file: ".claude/settings.json", old: `"mcp__ur__dns_set",`, replacement: `"mcp__ur__dns_set(example)",`},
		"codex":       {file: ".codex/config.toml", old: "[mcp_servers.ur.tools.dns_set]\napproval_mode = \"prompt\"", replacement: "[mcp_servers.ur.tools.dns_set]\napproval_mode = \"approve\""},
		"cursor":      {file: ".cursor/hooks.json", old: `"timeout": 75`, replacement: `"timeout": 1`},
	}
	for _, harness := range HarnessNames() {
		home := testHarnessHome(t, harness)
		state := t.TempDir()
		testInstallHarness(t, testHarnessArgs(harness, home, state))
		widening := widenings[harness]
		testHarnessEdit(t, filepath.Join(home, widening.file), widening.old, widening.replacement)
		check := testHarnessCheck(state)
		if !testHarnessChanged(t, check, harness, home) {
			t.Errorf("%s: a changed rule reads unchanged", harness)
		}
		testInstallHarness(t, testHarnessArgs(harness, home, state))
		if testHarnessChanged(t, check, harness, home) {
			t.Errorf("%s: the install did not restore its rule", harness)
		}
		content, err := os.ReadFile(filepath.Join(home, widening.file))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), widening.replacement) {
			t.Errorf("%s: the changed rule survived the install", harness)
		}
	}
}

// Another's hook that can answer for a ur tool, or an allow rule naming ur, reads changed, in the installed files and
// in the session's working directory's settings; one that cannot answer does not.
func TestCompetingHookChangesHash(t *testing.T) {
	home := testHarnessHome(t, "claude-code")
	state := t.TempDir()
	testInstallHarness(t, testHarnessArgs("claude-code", home, state))
	check := testHarnessCheck(state)
	settings := filepath.Join(home, ".claude", "settings.json")
	original, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		old         string
		replacement string
		changed     bool
	}{
		{name: "a PermissionRequest hook covering ur", old: `"PermissionRequest": [`,
			replacement: `"PermissionRequest": [{"matcher": "mcp__ur__.*", "hooks": [{"type": "command", "command": "/opt/auto/approve"}]}, `, changed: true},
		{name: "a PreToolUse hook on every tool", old: `"PreToolUse": [`,
			replacement: `"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/gate/check"}]}, `, changed: true},
		{name: "a PreToolUse hook on Bash alone", old: `"PreToolUse": [`,
			replacement: `"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/gate/check"}]}, `, changed: false},
		{name: "a PostToolUse hook", old: `"PostToolUse": [`,
			replacement: `"PostToolUse": [{"matcher": "mcp__ur__.*", "hooks": [{"type": "command", "command": "/opt/log/tool"}]}, `, changed: false},
		{name: "an allow rule naming ur", old: `"allow": ["Bash(git status)", "Read"]`,
			replacement: `"allow": ["Bash(git status)", "Read", "mcp__ur__dns_set"]`, changed: true},
		{name: "an older ur's PermissionRequest hook", old: `"PermissionRequest": [`,
			replacement: `"PermissionRequest": [{"matcher": "*", "hooks": [{"type": "command", "command": "/opt/old/bin/ur hook claude-code"}]}, `, changed: true},
	}
	for _, c := range cases {
		if err := os.WriteFile(settings, original, 0o600); err != nil {
			t.Fatal(err)
		}
		testHarnessEdit(t, settings, c.old, c.replacement)
		if changed := testHarnessChanged(t, check, "claude-code", home); changed != c.changed {
			t.Errorf("%s: changed %t, want %t", c.name, changed, c.changed)
		}
	}

	// the session's working directory's own settings, at SessionStart
	if err := os.WriteFile(settings, original, 0o600); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	local := `{"hooks": {"PermissionRequest": [{"matcher": "*", "hooks": [{"type": "command", "command": "/opt/auto/approve"}]}]}}`
	if err := os.WriteFile(filepath.Join(project, ".claude", "settings.local.json"), []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	if !testHarnessChanged(t, check, "claude-code", project) {
		t.Error("a competing hook in the project's settings reads unchanged")
	}
	if testHarnessChanged(t, check, "claude-code", home) {
		t.Error("another directory's settings read changed")
	}

	// Cursor's hooks name no matcher: another's beforeMCPExecution covers ur's tools
	cursorHome := testHarnessHome(t, "cursor")
	cursorState := t.TempDir()
	testInstallHarness(t, testHarnessArgs("cursor", cursorHome, cursorState))
	testHarnessEdit(t, filepath.Join(cursorHome, ".cursor", "hooks.json"), `"beforeMCPExecution": [`,
		`"beforeMCPExecution": [{"command": "/opt/auto/approve"}, `)
	if !testHarnessChanged(t, testHarnessCheck(cursorState), "cursor", cursorHome) {
		t.Error("a competing beforeMCPExecution reads unchanged")
	}
}

// --project writes the committed files a cloud session loads and §5.8's `.ur`, touches none of the person's own, and
// its seal holds for a session in the project alone.
func TestProjectWritesCommittedFiles(t *testing.T) {
	home := testHarnessHome(t, "claude-code")
	userBefore, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	state := t.TempDir()
	args := testHarnessArgs("claude-code", home, state)
	args.ProjectDirectory = project
	args.Agent = "builder"
	testInstallHarness(t, args)
	for _, name := range []string{".mcp.json", ".claude/settings.json", ".ur"} {
		info, err := os.Stat(filepath.Join(project, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Errorf("%s: mode %v, want a committed file's 0644", name, info.Mode().Perm())
		}
	}
	urFile, err := os.ReadFile(filepath.Join(project, ".ur"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := sidecar.ParseSidecarProject(urFile)
	if err != nil || parsed.Agent != "builder" {
		t.Errorf("the project's .ur: %+v %v", parsed, err)
	}
	mcpEntry, err := os.ReadFile(filepath.Join(project, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mcpEntry), `"--agent",`) || !strings.Contains(string(mcpEntry), `"builder"`) {
		t.Errorf("the project's MCP entry names no agent:\n%s", mcpEntry)
	}
	userAfter, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(userBefore) != string(userAfter) {
		t.Error("a project install touched the person's own files")
	}
	check := testHarnessCheck(state)
	inside := filepath.Join(project, "src")
	if testHarnessChanged(t, check, "claude-code", inside) {
		t.Error("a session inside the project reads changed")
	}
	if !testHarnessChanged(t, check, "claude-code", t.TempDir()) {
		t.Error("a session outside the project, with no user install, reads unchanged")
	}

	// an existing `.ur` is the project's, and stays as it is
	if err := os.WriteFile(filepath.Join(project, ".ur"), []byte("agent = \"other\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanHarnessInstall(args)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range plan.Files {
		if filepath.Base(file.Path) == ".ur" {
			t.Error("an existing .ur is planned over")
		}
	}
}

// Every command an install writes names ur by its absolute path (§4.10), and a relative path is refused.
func TestAbsolutePathUsed(t *testing.T) {
	for _, harness := range HarnessNames() {
		home := testHarnessHome(t, harness)
		plan := testInstallHarness(t, testHarnessArgs(harness, home, t.TempDir()))
		for _, file := range plan.Files {
			text := string(file.After)
			for _, line := range strings.Split(text, "\n") {
				if strings.Contains(line, " hook "+harness) && !strings.Contains(line, testHarnessUrPath+" hook "+harness) {
					t.Errorf("%s: a hook not by ur's absolute path: %s", harness, line)
				}
			}
		}
		template := newHarnessTemplate(harness, testHarnessUrPath, "", "default", McpOutwardToolNames(), sidecar.DefaultSidecarSettings().Ingest)
		if !strings.HasPrefix(template.hookCommand(), testHarnessUrPath+" ") || slices.Contains(template.mcpArgs(), "--instance") {
			t.Errorf("%s: the default instance's commands: %q %q", harness, template.hookCommand(), template.mcpArgs())
		}
		args := testHarnessArgs(harness, home, t.TempDir())
		args.UrPath = "ur"
		if _, err := PlanHarnessInstall(args); err == nil {
			t.Errorf("%s: a relative ur path is taken", harness)
		}
	}
	// a path with a space is quoted for the harness's shell, and read back as one word
	quoted := harnessShellQuote("/opt/ur tools/bin/ur")
	if words := harnessShellWords(quoted + " hook codex"); len(words) != 3 || words[0] != "/opt/ur tools/bin/ur" {
		t.Errorf("a quoted path reads as %q", words)
	}
}

// The ask rules and approval modes name every outward tool of §16.5's catalog, and nothing else.
func TestEveryOToolAsked(t *testing.T) {
	outward := McpOutwardToolNames()
	designOutward := []string{}
	for _, design := range mcpCatalogDesign {
		if design.tier == McpTierOutward {
			designOutward = append(designOutward, design.name)
		}
	}
	slices.Sort(designOutward)
	if !slices.Equal(outward, designOutward) || len(outward) == 0 {
		t.Fatalf("outward tools %q, the catalog's %q", outward, designOutward)
	}
	home := testHarnessHome(t, "claude-code")
	testInstallHarness(t, testHarnessArgs("claude-code", home, t.TempDir()))
	settings, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := harnessParseJson(settings, 64)
	if err != nil {
		t.Fatal(err)
	}
	rules := []string{}
	for _, element := range root.get("permissions").get("ask").elements {
		if claudeRuleNamesUr(element.text) {
			rules = append(rules, strings.TrimPrefix(element.text, "mcp__ur__"))
		}
	}
	if !slices.Equal(rules, outward) {
		t.Errorf("Claude Code's ask rules %q, want %q", rules, outward)
	}

	codexHome := testHarnessHome(t, "codex")
	testInstallHarness(t, testHarnessArgs("codex", codexHome, t.TempDir()))
	config, err := os.ReadFile(filepath.Join(codexHome, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range outward {
		if !strings.Contains(string(config), "[mcp_servers.ur.tools."+tool+"]\napproval_mode = \"prompt\"") {
			t.Errorf("Codex does not ask before %s", tool)
		}
	}
}

// A seal whose hashes were edited to bless a changed file, or that names another ur, reads changed: the check holds a
// seal to the template its inputs render. No seal at all reads changed.
func TestForgedSealChangesHash(t *testing.T) {
	home := testHarnessHome(t, "claude-code")
	state := t.TempDir()
	plan := testInstallHarness(t, testHarnessArgs("claude-code", home, state))
	check := testHarnessCheck(state)
	if testHarnessChanged(t, check, "codex", home) == false {
		t.Error("a harness with no seal reads unchanged")
	}

	// the person's hooks file widened, and the seal's hash rewritten to the widened file's
	settings := filepath.Join(home, ".claude", "settings.json")
	testHarnessEdit(t, settings, `"mcp__ur__dns_set",`, ``)
	content, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	template := newHarnessTemplate("claude-code", testHarnessUrPath, "", "default", McpOutwardToolNames(), sidecar.DefaultSidecarSettings().Ingest)
	found, err := (&harnessHooksFile{askRules: true, events: claudeHookEvents}).extract(content, template, 64)
	if err != nil {
		t.Fatal(err)
	}
	forgedHash, err := harnessEntriesSha256(found)
	if err != nil {
		t.Fatal(err)
	}
	seal := plan.Seal
	seal.Files[1].Sha256 = hex.EncodeToString(forgedHash[:])
	if err := writeHarnessSeal(state, seal); err != nil {
		t.Fatal(err)
	}
	if !testHarnessChanged(t, check, "claude-code", home) {
		t.Error("a forged seal blessed a widened file")
	}

	// a seal naming another ur's path
	other := testHarnessCheck(state)
	other.args.Executable = func() (string, error) { return "/opt/other/bin/ur", nil }
	testInstallHarness(t, testHarnessArgs("claude-code", home, state))
	if !testHarnessChanged(t, other, "claude-code", home) {
		t.Error("a seal of another ur reads unchanged")
	}
	if testHarnessChanged(t, check, "claude-code", home) {
		t.Error("the restored install reads changed")
	}
}

// A config.toml that defines mcp_servers.ur by a dotted key has no exact edit: the install refuses it, and the check
// reads it changed.
func TestUneditableConfigRefused(t *testing.T) {
	home := testHarnessHome(t, "codex")
	state := t.TempDir()
	testInstallHarness(t, testHarnessArgs("codex", home, state))
	config := filepath.Join(home, ".codex", "config.toml")
	testHarnessEdit(t, config, `model = "gpt-example"`, "model = \"gpt-example\"\nmcp_servers.ur.env = { MODE = \"x\" }")
	if _, err := PlanHarnessInstall(testHarnessArgs("codex", home, state)); err == nil {
		t.Error("an install planned over a dotted mcp_servers.ur")
	}
	changed, err := testHarnessCheck(state).Check(context.Background(), "codex", home)
	if !changed || err == nil {
		t.Errorf("the check: changed %t, err %v", changed, err)
	}
}

// The hooks fail open (D-MCP-5): no entry carries a fail-closed setting until M6's record_required.
func TestHooksFailOpen(t *testing.T) {
	for _, harness := range HarnessNames() {
		plan, err := PlanHarnessInstall(testHarnessArgs(harness, testHarnessHome(t, harness), t.TempDir()))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range plan.Files {
			for _, closed := range []string{"onFailure", "failClosed", "--required"} {
				if strings.Contains(string(file.After), closed) {
					t.Errorf("%s: %s carries %s", harness, file.Path, closed)
				}
			}
		}
	}
}

// The JSON reader keeps comments and a trailing comma, adds where the container's entries sit, and refuses a duplicate
// key where it edits and text that is no JSON.
func TestHarnessJsonEdits(t *testing.T) {
	content := []byte("{\n  // a comment\n  \"a\": [1, 2,],\n  \"b\": {\n    \"c\": true, /* kept */\n  },\n}\n")
	root, err := harnessParseJson(content, 64)
	if err != nil {
		t.Fatal(err)
	}
	edit, err := harnessJsonAddElements(content, root.get("a"), []any{3})
	if err != nil {
		t.Fatal(err)
	}
	content = harnessApplyEdit(content, edit)
	root, err = harnessParseJson(content, 64)
	if err != nil {
		t.Fatal(err)
	}
	edit, err = harnessJsonAddMember(content, root.get("b"), "d", map[string]any{"e": "f"})
	if err != nil {
		t.Fatal(err)
	}
	content = harnessApplyEdit(content, edit)
	want := "{\n  // a comment\n  \"a\": [1, 2, 3,],\n  \"b\": {\n    \"c\": true, /* kept */\n    \"d\": {\n      \"e\": \"f\"\n    },\n  },\n}\n"
	if string(content) != want {
		t.Errorf("edited:\n%s\nwant:\n%s", content, want)
	}
	if _, err := harnessParseJson([]byte(`{"a": 1, "a": 2}`), 64); err != nil {
		t.Fatal(err)
	}
	duplicate, _ := harnessParseJson([]byte(`{"a": 1, "a": 2}`), 64)
	if _, err := duplicate.member("a"); err == nil {
		t.Error("a duplicate key is edited")
	}
	for _, bad := range []string{`{"a": }`, `{"a": 1`, `[1 2]`, `{"a": 1} x`, `{"a": nope}`, "{\"a\": \"\x01\"}"} {
		if _, err := harnessParseJson([]byte(bad), 64); err == nil {
			t.Errorf("%q reads", bad)
		}
	}
	if _, err := harnessParseJson([]byte(strings.Repeat("[", 70)+strings.Repeat("]", 70)), 64); err == nil {
		t.Error("nesting past the bound reads")
	}
}

// The TOML reader finds every table and reads values of every kind, so a table's lines are its own.
func TestHarnessTomlTables(t *testing.T) {
	content := []byte(`# top
title = "x" # trailing
multi = """
[not.a.table]
"""
literal = '''
[nor.this]'''
array = [
  1, # one
  [2, 3],
  { a = 1 },
]
when = 1979-05-27 07:32:00

[mcp_servers.ur]
command = "/opt/ur/bin/ur"
args = ["mcp"]

[mcp_servers.ur.tools.dns_set]
approval_mode = "prompt"

[[products]]
name = "y"
`)
	document, err := harnessParseToml(content, 64)
	if err != nil {
		t.Fatal(err)
	}
	headers := []string{}
	for _, table := range document.tables[1:] {
		headers = append(headers, strings.Join(table.keys, "."))
	}
	if !slices.Equal(headers, []string{"mcp_servers.ur", "mcp_servers.ur.tools.dns_set", "products"}) {
		t.Errorf("tables %q", headers)
	}
	found, err := (&codexConfigFile{}).extract(content, nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := harnessJsonEncode(found, "", "")
	if encoded != `{"args":["mcp"],"command":"/opt/ur/bin/ur","tools":{"dns_set":{"approval_mode":"prompt"}}}` {
		t.Errorf("ur's tables read as %s", encoded)
	}
	for _, bad := range []string{"a = \"open\n", "[open\n", "a = [1 2]\n", "a = 1 b\n", "a = { b = 1, b = 2 }\n"} {
		if _, err := harnessParseToml([]byte(bad), 64); err == nil {
			t.Errorf("%q reads", bad)
		}
	}
}

// Agent-config paths match by last name or by tail.
func TestAgentConfigPaths(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	for _, path := range []string{"CLAUDE.md", "docs/CLAUDE.md", "AGENTS.md", ".mcp.json", ".claude/settings.json", "sub/.cursor/hooks.json", ".ur"} {
		if !McpAgentConfigPath(ingest, path) {
			t.Errorf("%s is not an agent-config path", path)
		}
	}
	for _, path := range []string{"README.md", "claude.md", "settings.json", "x.claude/settings.json", "CLAUDE.md.bak"} {
		if McpAgentConfigPath(ingest, path) {
			t.Errorf("%s is an agent-config path", path)
		}
	}
}
