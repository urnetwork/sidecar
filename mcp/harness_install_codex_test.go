//go:build !js && !ios && !android && !sdk_mobile_bind

// Codex's install after QD-835: its model calls come from its PostModelRequest hook alone. A user or project install
// writes PostModelRequest into Codex's hooks.json and no [otel] table; the [otel] table an earlier install wrote for
// QD-822 is removed with its bearer, the rest of config.toml left as it was and the bearer never printed; a person's
// own otel settings, ur's table edited since among them, stay byte for byte; and ur's PostModelRequest hook goes where
// a template no longer names it, as any of ur's stale hooks does.

package mcp

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The [otel] table an earlier install wrote for pair (QD-822): one table, the exporter an inline table on one line.
func testCodexEarlierOtelBlock(pair *HarnessTelemetry) string {
	return "[otel]\n" +
		"log_user_prompt = false\n" +
		"exporter = { otlp-http = { endpoint = " + harnessTomlString(pair.LogsEndpoint()) +
		", protocol = \"json\", headers = { Authorization = " + harnessTomlString(pair.Authorization()) + " } } }\n"
}

// The bytes of a file.
func testCodexRead(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// Writes content to a file.
func testCodexWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The hook groups under one event of a hooks file.
func testCodexHookGroups(t *testing.T, path string, event string) []any {
	t.Helper()
	content := []byte(testCodexRead(t, path))
	root, err := harnessParseJson(content, 64)
	if err != nil {
		t.Fatal(err)
	}
	value, err := harnessJsonValue(content, root.get("hooks").get(event))
	if err != nil {
		t.Fatal(err)
	}
	groups, _ := value.([]any)
	return groups
}

// A user install and a project install each write PostModelRequest into Codex's hooks.json as ur's one hook, with no
// matcher; the check holds, a PostModelRequest hook removed reads changed, and the install puts it back.
func TestCodexInstallHooksPostModelRequest(t *testing.T) {
	if !slices.ContainsFunc(codexHookEvents, func(event harnessHookEvent) bool { return event.name == "PostModelRequest" }) {
		t.Fatal("codex's events name no PostModelRequest")
	}
	home := testHarnessHome(t, "codex")
	state := t.TempDir()
	testInstallHarness(t, testHarnessArgs("codex", home, state))
	project := testHarnessArgs("codex", testHarnessHome(t, "codex"), state)
	project.ProjectDirectory = t.TempDir()
	testInstallHarness(t, project)
	for _, path := range []string{filepath.Join(home, ".codex", "hooks.json"), filepath.Join(project.ProjectDirectory, ".codex", "hooks.json")} {
		groups := testCodexHookGroups(t, path, "PostModelRequest")
		encoded, _ := harnessJsonEncode(groups, "", "")
		if encoded != `[{"hooks":[{"command":"/opt/ur/bin/ur hook codex","type":"command"}]}]` {
			t.Errorf("%s's PostModelRequest: %s", path, encoded)
		}
	}
	check := testHarnessCheck(state)
	if testHarnessChanged(t, check, "codex", "") || testHarnessChanged(t, check, "codex", project.ProjectDirectory) {
		t.Fatal("a fresh install reads changed")
	}
	testHarnessEdit(t, filepath.Join(home, ".codex", "hooks.json"), `"PostModelRequest": [`, `"PostModelRequestRemoved": [`)
	if !testHarnessChanged(t, check, "codex", "") {
		t.Error("a removed PostModelRequest hook reads unchanged")
	}
	testInstallHarness(t, testHarnessArgs("codex", home, state))
	if testHarnessChanged(t, check, "codex", "") {
		t.Error("the install did not restore its PostModelRequest hook")
	}
}

// Codex's install writes no [otel] table and no bearer into config.toml, and its seal names no telemetry port.
func TestCodexInstallWritesNoOtel(t *testing.T) {
	home := testHarnessHome(t, "codex")
	plan := testInstallHarness(t, testHarnessArgs("codex", home, t.TempDir()))
	config := testCodexRead(t, filepath.Join(home, ".codex", "config.toml"))
	if strings.Contains(config, "[otel") || strings.Contains(config, "Bearer") || strings.Contains(config, "otlp") {
		t.Errorf("codex's config holds exporter settings:\n%s", config)
	}
	if plan.Seal.TelemetryPort != 0 || plan.Telemetry() != nil {
		t.Errorf("codex's install names a telemetry pair: port %d", plan.Seal.TelemetryPort)
	}
}

// An earlier install's [otel] table, at the file's end where that install appended it or in the middle where it
// replaced a person's, is removed with its bearer, and config.toml becomes byte for byte what a fresh install writes:
// nothing else changes. The diff shows the removal with the token's stand-in, never the token, the check holds after,
// and a re-install changes nothing.
func TestCodexInstallRemovesEarlierOtel(t *testing.T) {
	pair := testTelemetryPair(testTelemetryPort, "synthetic earlier codex token")
	freshHome := testHarnessHome(t, "codex")
	testInstallHarness(t, testHarnessArgs("codex", freshHome, t.TempDir()))
	fresh := testCodexRead(t, filepath.Join(freshHome, ".codex", "config.toml"))
	if !strings.HasSuffix(fresh, "approval_mode = \"prompt\"\n") || !strings.Contains(fresh, "\n[profiles.review]\n") {
		t.Fatalf("the fresh config is not as this test reads it:\n%s", fresh)
	}
	earlierConfigs := map[string]string{
		// as the earlier install appended it, after ur's server tables, one blank line before it
		"at the end": fresh + "\n" + testCodexEarlierOtelBlock(pair),
		// where a person's [otel] table stood, which the earlier install replaced in place
		"in the middle": strings.Replace(fresh, "[profiles.review]\n", testCodexEarlierOtelBlock(pair)+"\n[profiles.review]\n", 1),
	}
	for name, earlier := range earlierConfigs {
		home := testHarnessHome(t, "codex")
		state := t.TempDir()
		path := filepath.Join(home, ".codex", "config.toml")
		testInstallHarness(t, testHarnessArgs("codex", home, state))
		testCodexWrite(t, path, earlier)
		plan, err := PlanHarnessInstall(testHarnessArgs("codex", home, state))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		diff := plan.Diff()
		if strings.Contains(diff, pair.Token) || !strings.Contains(diff, "-[otel]\n") || !strings.Contains(diff, harnessTelemetryTokenShown) {
			t.Errorf("%s: the diff shows the token, or not the removal:\n%s", name, diff)
		}
		if err := plan.Write(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if after := testCodexRead(t, path); after != fresh {
			t.Errorf("%s: the removal left\n%s\nwant\n%s", name, after, fresh)
		}
		if testHarnessChanged(t, testHarnessCheck(state), "codex", "") {
			t.Errorf("%s: the config reads changed after the removal", name)
		}
		again, err := PlanHarnessInstall(testHarnessArgs("codex", home, state))
		if err != nil {
			t.Fatal(err)
		}
		if changed, err := again.Changed(); err != nil || changed {
			t.Errorf("%s: a re-install changes something: %v %v\n%s", name, changed, err, again.Diff())
		}
	}
}

// otel settings that are not exactly what an earlier install wrote are the person's: a collector of their own, ur's
// table edited or added to, split over two tables, set by a dotted key, naming another host or a bearer that is no
// token. Each stays byte for byte, refuses nothing, and is no part of the seal, so the check holds over it.
func TestCodexInstallKeepsPersonsOtel(t *testing.T) {
	pair := testTelemetryPair(testTelemetryPort, "synthetic earlier codex token")
	earlier := testCodexEarlierOtelBlock(pair)
	tables := map[string]string{
		"a collector of the person's": "[otel]\nexporter = { otlp-http = { endpoint = \"https://collector.example/v1/logs\", protocol = \"binary\" } }\n",
		"ur's table edited":           strings.Replace(earlier, "log_user_prompt = false", "log_user_prompt = true", 1),
		"ur's table added to":         earlier + "environment = \"dev\"\n",
		"split over two tables": "[otel]\nlog_user_prompt = false\n\n[otel.exporter.otlp-http]\nendpoint = " + harnessTomlString(pair.LogsEndpoint()) +
			"\nprotocol = \"json\"\nheaders = { Authorization = " + harnessTomlString(pair.Authorization()) + " }\n",
		"another host":            strings.Replace(earlier, "127.0.0.1", "192.0.2.1", 1),
		"a bearer that is no hex": strings.Replace(earlier, pair.Token, "not-a-drawn-token", 1),
	}
	for name, table := range tables {
		home := testHarnessHome(t, "codex")
		state := t.TempDir()
		path := filepath.Join(home, ".codex", "config.toml")
		testInstallHarness(t, testHarnessArgs("codex", home, state))
		before := testCodexRead(t, path) + "\n" + table
		testCodexWrite(t, path, before)
		plan, err := PlanHarnessInstall(testHarnessArgs("codex", home, state))
		if err != nil {
			t.Fatalf("%s: refused: %v", name, err)
		}
		if changed, err := plan.Changed(); err != nil || changed {
			t.Errorf("%s: the install changes something: %v %v\n%s", name, changed, err, plan.Diff())
		}
		if testHarnessChanged(t, testHarnessCheck(state), "codex", "") {
			t.Errorf("%s: the person's otel settings read changed", name)
		}
	}

	// otel by a dotted key in the root table, before any header, which a whole-table edit could never have written
	home := testHarnessHome(t, "codex")
	path := filepath.Join(home, ".codex", "config.toml")
	dotted := "otel.log_user_prompt = false\n" + testCodexRead(t, path)
	testCodexWrite(t, path, dotted)
	testInstallHarness(t, testHarnessArgs("codex", home, t.TempDir()))
	if after := testCodexRead(t, path); !strings.HasPrefix(after, dotted) {
		t.Errorf("a dotted otel key went:\n%s", after)
	}
}

// ur's PostModelRequest hook goes where a template no longer names the event, as any of ur's stale hooks does, while
// another's hook on the event stays: the removal an install makes of what it no longer installs.
func TestStalePostModelRequestHookRemoved(t *testing.T) {
	home := testHarnessHome(t, "codex")
	args := testHarnessArgs("codex", home, t.TempDir())
	testInstallHarness(t, args)
	path := filepath.Join(home, ".codex", "hooks.json")
	testHarnessEdit(t, path, `"PostModelRequest": [`, `"PostModelRequest": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/meter/bin/meter codex"
          }
        ]
      },`)
	without := []harnessHookEvent{}
	for _, event := range codexHookEvents {
		if event.name != "PostModelRequest" {
			without = append(without, event)
		}
	}
	template := newHarnessTemplate("codex", testHarnessUrPath, "", "", McpOutwardToolNames(), args.Ingest)
	file := &harnessFile{path: path, kind: &harnessHooksFile{events: without}}
	after, err := harnessApplyTemplate(file, []byte(testCodexRead(t, path)), template, args.Ingest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, after, 0o600); err != nil {
		t.Fatal(err)
	}
	groups := testCodexHookGroups(t, path, "PostModelRequest")
	encoded, _ := harnessJsonEncode(groups, "", "")
	if encoded != `[{"hooks":[{"command":"/opt/meter/bin/meter codex","type":"command"}]}]` {
		t.Errorf("PostModelRequest after a template without it: %s", encoded)
	}
	if !strings.Contains(string(after), `"SessionEnd": [`) {
		t.Errorf("the other hooks went:\n%s", after)
	}
}
