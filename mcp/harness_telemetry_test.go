//go:build !js && !ios && !android && !sdk_mobile_bind

// The telemetry pair in ur install-harness (QD-822): a user install of Claude Code or Codex writes the exporter's
// settings naming the sealed loopback port and bearer token, seals the pair beside the seals, and a re-install changes
// nothing; a pair drawn again or an edited exporter setting reads as changed; a project install, or Cursor's, takes no
// token; the diff never prints the token; and the pair is no seal.

package mcp

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A synthetic port every test pair names: the listener is never started on it.
const testTelemetryPort = 41234

// A visibly synthetic pair: the token is the SHA-256 of a fixed phrase, never a drawn one.
func testTelemetryPair(port int, phrase string) *HarnessTelemetry {
	token := sha256.Sum256([]byte(phrase))
	return NewHarnessTelemetry(port, token[:])
}

// A user install of harness into a copy of its fixture home, naming pair, its seal under a fresh state.
func testTelemetryArgs(t *testing.T, harness string, pair *HarnessTelemetry) *HarnessInstallArgs {
	t.Helper()
	args := testHarnessArgs(harness, testHarnessHome(t, harness), t.TempDir())
	args.Telemetry = pair
	return args
}

// Claude Code's env block as settings.json holds it.
func testClaudeEnv(t *testing.T, home string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := harnessParseJson(content, 64)
	if err != nil {
		t.Fatal(err)
	}
	value, err := harnessJsonValue(content, root.get("env"))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := value.(map[string]any)
	return env
}

// Claude Code's install writes the exporter's variables into its settings' env block, keeping the person's own, and
// Codex's its [otel] table; both name the pair's loopback port and its bearer, the pair is sealed 0600 beside the
// seals, the seal names the port, and the check holds.
func TestInstallWritesExporterSettings(t *testing.T) {
	pair := testTelemetryPair(testTelemetryPort, "synthetic telemetry token")
	args := testTelemetryArgs(t, "claude-code", pair)
	testHarnessEdit(t, filepath.Join(args.Home, ".claude", "settings.json"), `"model": "sonnet"`, `"model": "sonnet",
  "env": { "PERSON_OWN": "kept" }`)
	plan := testInstallHarness(t, args)
	env := testClaudeEnv(t, args.Home)
	want := map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
		"OTEL_LOGS_EXPORTER":           "otlp",
		"OTEL_EXPORTER_OTLP_PROTOCOL":  "http/json",
		"OTEL_EXPORTER_OTLP_ENDPOINT":  "http://127.0.0.1:41234",
		"OTEL_EXPORTER_OTLP_HEADERS":   "Authorization=Bearer " + pair.Token,
		"PERSON_OWN":                   "kept",
	}
	for name, value := range want {
		if env[name] != value {
			t.Errorf("env %s = %v, not %q", name, env[name], value)
		}
	}
	if plan.Seal.TelemetryPort != testTelemetryPort {
		t.Errorf("the seal names port %d", plan.Seal.TelemetryPort)
	}
	sealed, err := ReadHarnessTelemetry(args.StateDirectory, args.Ingest.HarnessConfigByteCount)
	if err != nil || !sealed.equal(pair) {
		t.Fatalf("the sealed pair %+v: %v", sealed, err)
	}
	info, err := os.Stat(HarnessTelemetryPath(args.StateDirectory))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the pair file: %v %v", info, err)
	}
	if testHarnessChanged(t, testHarnessCheck(args.StateDirectory), "claude-code", "") {
		t.Error("a fresh install with exporter settings reads changed")
	}

	// Codex, into the same state: the same pair, its [otel] table naming the logs endpoint
	codex := testHarnessArgs("codex", testHarnessHome(t, "codex"), args.StateDirectory)
	codex.Telemetry = sealed
	testInstallHarness(t, codex)
	config, err := os.ReadFile(filepath.Join(codex.Home, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := harnessParseToml(config, 64)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := codexOwnedTables(document, codexOtelKeys)
	if err != nil {
		t.Fatal(err)
	}
	otel, err := codexOwnedEntries(tables, codexOtelKeys)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := harnessJsonEncode(otel, "", "")
	wantOtel := `{"exporter":{"otlp-http":{"endpoint":"http://127.0.0.1:41234/v1/logs","headers":{"Authorization":"Bearer ` +
		pair.Token + `"},"protocol":"json"}},"log_user_prompt":false}`
	if encoded != wantOtel {
		t.Errorf("codex's otel %s", encoded)
	}
	if !strings.Contains(string(config), "[profiles.review]") || !strings.Contains(string(config), "[mcp_servers.docs]") {
		t.Errorf("the person's tables went:\n%s", config)
	}
	if testHarnessChanged(t, testHarnessCheck(args.StateDirectory), "codex", "") {
		t.Error("codex's fresh install with exporter settings reads changed")
	}
}

// Each harness's diff with a pair against its fixtures is the golden one, the token shown by a stand-in.
func TestTelemetryInstallDiffsAreGolden(t *testing.T) {
	for _, harness := range []string{"claude-code", "codex"} {
		args := testTelemetryArgs(t, harness, testTelemetryPair(testTelemetryPort, "synthetic telemetry token"))
		plan, err := PlanHarnessInstall(args)
		if err != nil {
			t.Fatalf("%s: %v", harness, err)
		}
		diff := strings.ReplaceAll(plan.Diff(), filepath.ToSlash(args.Home), "/$HOME")
		golden := filepath.Join("..", "testdata", "harness", "install", harness+"-telemetry.diff")
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
	}
}

// The diff names the stand-in, never the token, and the files written hold the token itself.
func TestTelemetryDiffHidesToken(t *testing.T) {
	pair := testTelemetryPair(testTelemetryPort, "synthetic telemetry token")
	for _, harness := range []string{"claude-code", "codex"} {
		plan, err := PlanHarnessInstall(testTelemetryArgs(t, harness, pair))
		if err != nil {
			t.Fatal(err)
		}
		diff := plan.Diff()
		if strings.Contains(diff, pair.Token) || !strings.Contains(diff, harnessTelemetryTokenShown) {
			t.Errorf("%s's diff shows the token or no stand-in:\n%s", harness, diff)
		}
		written := false
		for _, file := range plan.Files {
			written = written || strings.Contains(string(file.After), pair.Token)
		}
		if !written {
			t.Errorf("%s's planned files hold no token", harness)
		}
	}
}

// A re-install with the sealed pair changes nothing: the same files, the same seal, the same pair.
func TestReinstallKeepsTelemetryPair(t *testing.T) {
	for _, harness := range []string{"claude-code", "codex"} {
		args := testTelemetryArgs(t, harness, testTelemetryPair(testTelemetryPort, "synthetic telemetry token"))
		testInstallHarness(t, args)
		sealed, err := ReadHarnessTelemetry(args.StateDirectory, args.Ingest.HarnessConfigByteCount)
		if err != nil {
			t.Fatal(err)
		}
		again := testHarnessArgs(harness, args.Home, args.StateDirectory)
		again.Telemetry = sealed
		plan, err := PlanHarnessInstall(again)
		if err != nil {
			t.Fatal(err)
		}
		if changed, err := plan.Changed(); err != nil || changed {
			t.Errorf("%s: a re-install changes something: %v %v\n%s", harness, changed, err, plan.Diff())
		}
	}
}

// A pair drawn again since the install, a pair gone, and an exporter setting edited in the file each read as changed,
// and a re-install with the new pair restores a config that holds.
func TestChangedTelemetryPairReadsChanged(t *testing.T) {
	args := testTelemetryArgs(t, "claude-code", testTelemetryPair(testTelemetryPort, "synthetic telemetry token"))
	testInstallHarness(t, args)
	check := testHarnessCheck(args.StateDirectory)

	// another token on the same port
	drawn := testTelemetryPair(testTelemetryPort, "another synthetic token")
	if err := writeHarnessTelemetry(args.StateDirectory, drawn); err != nil {
		t.Fatal(err)
	}
	if !testHarnessChanged(t, check, "claude-code", "") {
		t.Error("a token drawn again reads unchanged")
	}
	// another port
	if err := writeHarnessTelemetry(args.StateDirectory, testTelemetryPair(testTelemetryPort+1, "synthetic telemetry token")); err != nil {
		t.Fatal(err)
	}
	if !testHarnessChanged(t, check, "claude-code", "") {
		t.Error("a port drawn again reads unchanged")
	}
	// gone
	if err := os.Remove(HarnessTelemetryPath(args.StateDirectory)); err != nil {
		t.Fatal(err)
	}
	if !testHarnessChanged(t, check, "claude-code", "") {
		t.Error("a pair gone reads unchanged")
	}
	// the re-install with the pair now sealed restores ur's entries
	again := testHarnessArgs("claude-code", args.Home, args.StateDirectory)
	again.Telemetry = drawn
	testInstallHarness(t, again)
	if testHarnessChanged(t, check, "claude-code", "") {
		t.Error("the re-install with the new pair reads changed")
	}
	// the endpoint edited in the file
	testHarnessEdit(t, filepath.Join(args.Home, ".claude", "settings.json"), `"http://127.0.0.1:41234"`, `"http://192.0.2.1:41234"`)
	if !testHarnessChanged(t, check, "claude-code", "") {
		t.Error("an edited endpoint reads unchanged")
	}
}

// A project install takes no token, since its files are committed, and Cursor documents no exporter: each is refused
// with a pair named, and nothing is written.
func TestTelemetryRefusedOutsideUserInstalls(t *testing.T) {
	pair := testTelemetryPair(testTelemetryPort, "synthetic telemetry token")
	project := testHarnessArgs("claude-code", testHarnessHome(t, "claude-code"), t.TempDir())
	project.ProjectDirectory = t.TempDir()
	project.Telemetry = pair
	if _, err := PlanHarnessInstall(project); err == nil {
		t.Error("a project install took a token")
	}
	cursor := testTelemetryArgs(t, "cursor", pair)
	if _, err := PlanHarnessInstall(cursor); err == nil {
		t.Error("cursor's install took a token")
	}
	if HarnessExportsTelemetry("cursor") || !HarnessExportsTelemetry("claude-code") || !HarnessExportsTelemetry("codex") {
		t.Error("the harnesses with exporters are not Claude Code and Codex alone")
	}
	for _, args := range []*HarnessInstallArgs{project, cursor} {
		if _, err := os.Stat(HarnessTelemetryPath(args.StateDirectory)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a refused install sealed a pair: %v", err)
		}
	}
	bad := testTelemetryArgs(t, "claude-code", &HarnessTelemetry{Version: harnessTelemetryVersion, Port: 0, Token: pair.Token})
	if _, err := PlanHarnessInstall(bad); err == nil {
		t.Error("a pair with no port was taken")
	}
	odd := testTelemetryArgs(t, "claude-code", &HarnessTelemetry{Version: harnessTelemetryVersion, Port: testTelemetryPort, Token: "Bearer x"})
	if _, err := PlanHarnessInstall(odd); err == nil {
		t.Error("a token that is no hex was taken")
	}
}

// The pair is written before any harness file, and a pair another install sealed since the plan stops the write
// before any file changes.
func TestTelemetryPairSealedFirst(t *testing.T) {
	args := testTelemetryArgs(t, "claude-code", testTelemetryPair(testTelemetryPort, "synthetic telemetry token"))
	plan, err := PlanHarnessInstall(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeHarnessTelemetry(args.StateDirectory, testTelemetryPair(testTelemetryPort, "another synthetic token")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(args.Home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(); err == nil {
		t.Fatal("a plan over a pair sealed since wrote")
	}
	after, _ := os.ReadFile(filepath.Join(args.Home, ".claude", "settings.json"))
	if string(before) != string(after) {
		t.Error("the refused write changed a harness file")
	}
}

// The pair beside the seals is none of them: `ur status`'s read of the seals neither lists nor counts it.
func TestTelemetryPairIsNoSeal(t *testing.T) {
	args := testTelemetryArgs(t, "claude-code", testTelemetryPair(testTelemetryPort, "synthetic telemetry token"))
	testInstallHarness(t, args)
	seals, unreadable, err := ReadHarnessSeals(args.StateDirectory, args.Ingest.HarnessConfigByteCount)
	if err != nil || len(seals) != 1 || unreadable != 0 {
		t.Errorf("%d seals, %d unreadable: %v", len(seals), unreadable, err)
	}
	// the pair file holds the token and the port, and the seal names the port alone
	sealContent, err := os.ReadFile(seals[0].path(args.StateDirectory))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealContent), args.Telemetry.Token) {
		t.Error("the seal holds the token")
	}
	pairContent, _ := os.ReadFile(HarnessTelemetryPath(args.StateDirectory))
	read := map[string]any{}
	if err := json.Unmarshal(pairContent, &read); err != nil || read["token"] != args.Telemetry.Token {
		t.Errorf("the pair file %s: %v", pairContent, err)
	}
}

// With no pair named, an install writes no exporter setting: the default, while model calls are off.
func TestNoTelemetryWritesNoExporter(t *testing.T) {
	for _, harness := range []string{"claude-code", "codex"} {
		args := testHarnessArgs(harness, testHarnessHome(t, harness), t.TempDir())
		plan := testInstallHarness(t, args)
		for _, file := range plan.Files {
			if strings.Contains(string(file.After), "OTEL_") || strings.Contains(string(file.After), "[otel]") {
				t.Errorf("%s's %s holds exporter settings:\n%s", harness, file.Path, file.After)
			}
		}
		if plan.Seal.TelemetryPort != 0 {
			t.Errorf("%s's seal names a port", harness)
		}
		if _, err := os.Stat(HarnessTelemetryPath(args.StateDirectory)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s sealed a pair: %v", harness, err)
		}
	}
}
