// ur install-harness (MCP-M3-16): the diff is shown before anything is written, nothing is written unless the person
// confirms on the terminal, and a second run with nothing to change asks nothing.

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

// A ur whose install-harness writes under home and state, as /opt/ur/bin/ur, its output and the terminal's one log.
func newTestInstallHarnessCli(t *testing.T, home string, state string, answers ...string) (*urCli, *testTty) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the install names POSIX paths")
	}
	executable, homeDirectory := urHarnessExecutable, urHarnessHome
	t.Cleanup(func() {
		urHarnessExecutable, urHarnessHome = executable, homeDirectory
	})
	urHarnessExecutable = func() (string, error) { return "/opt/ur/bin/ur", nil }
	urHarnessHome = func() (string, error) { return home, nil }
	cli, _, _ := newTestUrCli(filepath.Join(shortTestDirectory(t), "none"))
	tty := &testTty{lines: answers}
	cli.openTty = func() (urTty, error) { return tty, nil }
	// the output and the question in one log, so their order shows
	cli.stdout = tty
	cli.stateDirectory = func(instance string) (string, error) { return state, nil }
	return cli, tty
}

// The diff is on the terminal before the question, a no writes nothing, and a yes writes the files and the seal.
func TestDiffShownBeforeWrite(t *testing.T) {
	home := t.TempDir()
	state := t.TempDir()
	cli, tty := newTestInstallHarnessCli(t, home, state, "n")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "cursor"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	log := tty.written.String()
	diffAt := strings.Index(log, "+++ b"+filepath.ToSlash(filepath.Join(home, ".cursor", "hooks.json")))
	questionAt := strings.Index(log, "write these changes")
	if diffAt < 0 || questionAt < 0 || questionAt < diffAt {
		t.Fatalf("the diff does not come before the question:\n%s", log)
	}
	if _, err := os.Stat(filepath.Join(home, ".cursor", "hooks.json")); !os.IsNotExist(err) {
		t.Errorf("a declined install wrote: %v", err)
	}
	if entries, _ := os.ReadDir(state); 0 < len(entries) {
		t.Error("a declined install sealed")
	}

	cli, _ = newTestInstallHarnessCli(t, home, state, "y")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "cursor"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	hooks, err := os.ReadFile(filepath.Join(home, ".cursor", "hooks.json"))
	if err != nil || !strings.Contains(string(hooks), "/opt/ur/bin/ur hook cursor") {
		t.Fatalf("the hooks were not written: %v\n%s", err, hooks)
	}
	if _, err := os.Stat(filepath.Join(state, "harness", "cursor.json")); err != nil {
		t.Errorf("no seal: %v", err)
	}

	// nothing left to change: nothing asked
	cli, tty = newTestInstallHarnessCli(t, home, state)
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "cursor"}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(tty.written.String(), "nothing to change") || strings.Contains(tty.written.String(), "write these changes") {
		t.Errorf("a second install:\n%s", tty.written.String())
	}
}

// A harness ur does not install into is refused, and nothing is asked or written.
func TestInstallHarnessRefusesUnknown(t *testing.T) {
	home := t.TempDir()
	cli, tty := newTestInstallHarnessCli(t, home, t.TempDir())
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "notepad"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if tty.written.Len() != 0 {
		t.Errorf("asked or wrote: %s", tty.written.String())
	}
}

// The cloud profile (MCP-M4-02; QD-041): --project with --cloud-key-file commits a session-start step that takes the
// key file before ur hook runs, shown in the diff before it is written, and the flag without --project is refused
// with nothing asked.
func TestInstallHarnessCloudKeyFile(t *testing.T) {
	home := t.TempDir()
	state := t.TempDir()
	project := t.TempDir()
	cli, tty := newTestInstallHarnessCli(t, home, state, "y")
	cli.cwd = func() (string, error) { return project, nil }
	args := []string{"ur", "install-harness", "claude-code", "--project", "--cloud-key-file=/run/ur/authkey"}
	if code := cli.main(context.Background(), args); code != urExitOk {
		t.Fatalf("exit %d:\n%s", code, tty.written.String())
	}
	step := "/opt/ur/bin/ur connect --token-file /run/ur/authkey --ephemeral </dev/null >/dev/null 2>&1; /opt/ur/bin/ur hook claude-code"
	log := tty.written.String()
	if diffAt, questionAt := strings.Index(log, "connect --token-file /run/ur/authkey"), strings.Index(log, "write these changes"); diffAt < 0 || questionAt < diffAt {
		t.Errorf("the connect step is not in the diff before the question:\n%s", log)
	}
	settings, err := os.ReadFile(filepath.Join(project, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	// JSON writes < and > escaped or plain; the command's words either way
	if !strings.Contains(string(settings), "connect --token-file /run/ur/authkey --ephemeral") || !strings.Contains(string(settings), "; /opt/ur/bin/ur hook claude-code") {
		t.Errorf("the committed settings hold no session-start step %q:\n%s", step, settings)
	}
	if strings.Contains(string(settings), "ur-authkey-") {
		t.Error("a committed file holds an auth key's prefix")
	}

	cli, tty = newTestInstallHarnessCli(t, home, state, "y")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "claude-code", "--cloud-key-file=/run/ur/authkey"}); code != urExitFailed {
		t.Fatalf("a key file with no project: exit %d", code)
	}
	if strings.Contains(tty.written.String(), "write these changes") {
		t.Errorf("a refused install asked:\n%s", tty.written.String())
	}
}

// A ur on newTestInstallHarnessCli's terms with model calls captured, its daemon at socketPath, each telemetry pair it
// draws on port.
func newTestTelemetryInstallCli(t *testing.T, home string, state string, socketPath string, port int, answers ...string) (*urCli, *testTty) {
	t.Helper()
	cli, tty := newTestInstallHarnessCli(t, home, state, answers...)
	cli.socketPath = func(instance string) (string, error) { return socketPath, nil }
	ingest := *cli.ingest
	ingest.ModelCalls = true
	cli.ingest = &ingest
	telemetryPort := urHarnessTelemetryPort
	t.Cleanup(func() { urHarnessTelemetryPort = telemetryPort })
	urHarnessTelemetryPort = func() (int, error) { return port, nil }
	return cli, tty
}

// While model calls are captured, a user install of Claude Code draws a telemetry pair, seals it under <state>/harness/
// and writes the exporter's settings naming it, the diff never printing the token; Codex's install then names the same
// pair, and a re-install changes nothing.
func TestInstallHarnessWritesTelemetry(t *testing.T) {
	home := t.TempDir()
	state := t.TempDir()
	none := filepath.Join(shortTestDirectory(t), "none")
	cli, tty := newTestTelemetryInstallCli(t, home, state, none, 41235, "y")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "claude-code"}); code != urExitOk {
		t.Fatalf("exit %d:\n%s", code, tty.written.String())
	}
	pair, err := mcp.ReadHarnessTelemetry(state, cli.ingest.HarnessConfigByteCount)
	if err != nil {
		t.Fatalf("no pair sealed: %v", err)
	}
	if pair.Port != 41235 || len(pair.Token) != 2*cli.ingest.TelemetryTokenByteCount {
		t.Errorf("the pair: port %d, a token of %d hex digits", pair.Port, len(pair.Token))
	}
	log := tty.written.String()
	if strings.Contains(log, pair.Token) {
		t.Error("the install printed the token")
	}
	if !strings.Contains(log, "OTEL_EXPORTER_OTLP_ENDPOINT") || !strings.Contains(log, "which the daemon serves from its next start") {
		t.Errorf("the diff or the note:\n%s", log)
	}
	settings, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(settings), `"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:41235"`) ||
		!strings.Contains(string(settings), `"OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer `+pair.Token+`"`) {
		t.Errorf("the exporter's settings:\n%s", settings)
	}

	// Codex names the pair already sealed, whatever port is free now
	cli, tty = newTestTelemetryInstallCli(t, home, state, none, 41299, "y")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "codex"}); code != urExitOk {
		t.Fatalf("codex: exit %d:\n%s", code, tty.written.String())
	}
	config, err := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), `endpoint = "http://127.0.0.1:41235/v1/logs"`) || !strings.Contains(string(config), "Bearer "+pair.Token) {
		t.Errorf("codex's [otel] table:\n%s", config)
	}

	// a re-install changes nothing and asks nothing
	cli, tty = newTestTelemetryInstallCli(t, home, state, none, 41299)
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "claude-code"}); code != urExitOk {
		t.Fatalf("the re-install: exit %d", code)
	}
	if !strings.Contains(tty.written.String(), "nothing to change") || strings.Contains(tty.written.String(), "write these changes") {
		t.Errorf("the re-install:\n%s", tty.written.String())
	}
	again, err := mcp.ReadHarnessTelemetry(state, cli.ingest.HarnessConfigByteCount)
	if err != nil || *again != *pair {
		t.Errorf("the re-install changed the pair: %v", err)
	}
}

// Cursor documents no exporter, so its install says so and draws no pair; a project install takes no token, since its
// files are committed; and with model calls off no install writes exporter settings.
func TestInstallHarnessTelemetryOnlyWhereItCan(t *testing.T) {
	none := filepath.Join(shortTestDirectory(t), "none")

	home, state := t.TempDir(), t.TempDir()
	cli, tty := newTestTelemetryInstallCli(t, home, state, none, 41235, "y")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "cursor"}); code != urExitOk {
		t.Fatalf("cursor: exit %d", code)
	}
	if !strings.Contains(tty.written.String(), "cursor documents no OpenTelemetry exporter setting") {
		t.Errorf("cursor's install says nothing of it:\n%s", tty.written.String())
	}
	if _, err := os.Stat(mcp.HarnessTelemetryPath(state)); !os.IsNotExist(err) {
		t.Errorf("cursor's install drew a pair: %v", err)
	}

	home, state = t.TempDir(), t.TempDir()
	project := t.TempDir()
	cli, tty = newTestTelemetryInstallCli(t, home, state, none, 41235, "y")
	cli.cwd = func() (string, error) { return project, nil }
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "claude-code", "--project"}); code != urExitOk {
		t.Fatalf("the project install: exit %d:\n%s", code, tty.written.String())
	}
	committed, err := os.ReadFile(filepath.Join(project, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(committed), "Bearer") || strings.Contains(string(committed), "OTEL_") {
		t.Errorf("a committed file holds exporter settings:\n%s", committed)
	}
	if _, err := os.Stat(mcp.HarnessTelemetryPath(state)); !os.IsNotExist(err) {
		t.Errorf("a project install drew a pair: %v", err)
	}

	home, state = t.TempDir(), t.TempDir()
	cli, _ = newTestInstallHarnessCli(t, home, state, "y")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "claude-code"}); code != urExitOk {
		t.Fatalf("with model calls off: exit %d", code)
	}
	settings, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(settings), "OTEL_") {
		t.Errorf("model calls off, yet exporter settings:\n%s", settings)
	}
	if _, err := os.Stat(mcp.HarnessTelemetryPath(state)); !os.IsNotExist(err) {
		t.Errorf("model calls off, yet a pair: %v", err)
	}
}

// A pair under <state> that does not read is refused, naming the file, and nothing is asked or written.
func TestInstallHarnessRefusesUnreadablePair(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(state, "harness"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mcp.HarnessTelemetryPath(state), []byte("not a pair"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli, tty := newTestTelemetryInstallCli(t, home, state, filepath.Join(shortTestDirectory(t), "none"), 41235, "y")
	stderr := &bytes.Buffer{}
	cli.stderr = stderr
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "claude-code"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(tty.written.String(), "write these changes") || !strings.Contains(stderr.String(), "telemetry.json") {
		t.Errorf("the refusal: %q, asked: %q", stderr.String(), tty.written.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("a refused install wrote: %v", err)
	}
}

// Once the install seals a pair, a daemon already running is asked to serve it, and serves it at once.
func TestInstallHarnessReloadsRunningDaemon(t *testing.T) {
	home, state := t.TempDir(), t.TempDir()
	settings := sidecar.DefaultSidecarSettings()
	settings.Ingest.ModelCalls = true
	var listener *mcp.IngestTelemetryListener
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		server := mcp.NewMcpServer(mcp.DaemonOf(daemon), mcp.NewMcpServerSettings(settings, sidecar.Version))
		ingest := mcp.NewIngest(&mcp.IngestArgs{Server: server})
		listener = mcp.NewIngestTelemetryListener(&mcp.IngestTelemetryListenerArgs{Ingest: ingest, StateDirectory: state})
		t.Cleanup(listener.Close)
		for _, method := range urTelemetryMethods(listener) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	if listener.Status().Serving {
		t.Fatal("serving before any install")
	}
	port, err := urHarnessTelemetryPort()
	if err != nil {
		t.Fatal(err)
	}
	cli, tty := newTestTelemetryInstallCli(t, home, state, daemon.socketPath, port, "y")
	if code := cli.main(context.Background(), []string{"ur", "install-harness", "claude-code"}); code != urExitOk {
		t.Fatalf("exit %d:\n%s", code, tty.written.String())
	}
	status := listener.Status()
	if !status.Serving || status.Port != port {
		t.Fatalf("the daemon after the install: %+v", status)
	}
	if !strings.Contains(tty.written.String(), "its telemetry goes to 127.0.0.1:"+strconv.Itoa(port)+", which the daemon serves") {
		t.Errorf("the install's note:\n%s", tty.written.String())
	}
}
