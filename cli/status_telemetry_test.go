package main

// `ur status`'s telemetry line (QD-822): the listener's port and whether it serves, why not where it does not, and
// nothing while model calls are off with no pair sealed; through a daemon, the line its listener answers.

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

// Each status prints its line, and capture off with no pair prints none.
func TestStatusTelemetryLines(t *testing.T) {
	cases := []struct {
		status *mcp.IngestTelemetryStatus
		line   string
	}{
		{
			status: &mcp.IngestTelemetryStatus{ModelCalls: true, Port: 41234, Address: "127.0.0.1:41234", Serving: true},
			line:   "telemetry:  serving on 127.0.0.1:41234, model calls alone\n",
		},
		{
			status: &mcp.IngestTelemetryStatus{ModelCalls: true, Port: 41234, Address: "127.0.0.1:41234", Serving: true,
				Counts: mcp.IngestTelemetryCounts{Refused: 2, Limited: 1}},
			line: "telemetry:  serving on 127.0.0.1:41234, model calls alone (2 refused, 1 past the rate)\n",
		},
		{
			status: &mcp.IngestTelemetryStatus{ModelCalls: true, Port: 41234, Reason: "port 41234 did not bind on loopback: in use"},
			line:   "telemetry:  port 41234 not serving: port 41234 did not bind on loopback: in use\n",
		},
		{
			status: &mcp.IngestTelemetryStatus{Port: 41234, Reason: "model calls are off: M6's capture, off by default"},
			line:   "telemetry:  port 41234 not serving: model calls are off: M6's capture, off by default\n",
		},
		{
			status: &mcp.IngestTelemetryStatus{ModelCalls: true, Reason: "no harness's exporter settings are installed"},
			line:   "telemetry:  not serving: no harness's exporter settings are installed\n",
		},
		{
			status: &mcp.IngestTelemetryStatus{Reason: "no harness's exporter settings are installed"},
			line:   "",
		},
	}
	for i, c := range cases {
		cli, stdout, _ := newTestUrCli(filepath.Join(shortTestDirectory(t), "none"))
		printUrTelemetryStatus(cli, c.status)
		if stdout.String() != c.line {
			t.Errorf("case %d: %q, not %q", i, stdout.String(), c.line)
		}
	}
}

// Through a daemon whose listener serves a sealed pair, `ur status`'s section names its loopback port and that it
// serves; the reply carries no token.
func TestStatusNamesTelemetryListener(t *testing.T) {
	state := t.TempDir()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	settings := sidecar.DefaultSidecarSettings()
	settings.Ingest.ModelCalls = true
	plan, err := mcp.PlanHarnessInstall(&mcp.HarnessInstallArgs{
		Harness:        "claude-code",
		Home:           t.TempDir(),
		UrPath:         "/opt/ur/bin/ur",
		StateDirectory: state,
		Telemetry:      mcp.NewHarnessTelemetry(port, []byte("synthetic status token 32 bytes!")),
		Ingest:         settings.Ingest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(); err != nil {
		t.Fatal(err)
	}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		server := mcp.NewMcpServer(mcp.DaemonOf(daemon), mcp.NewMcpServerSettings(settings, sidecar.Version))
		ingest := mcp.NewIngest(&mcp.IngestArgs{Server: server})
		listener := mcp.NewIngestTelemetryListener(&mcp.IngestTelemetryListenerArgs{Ingest: ingest, StateDirectory: state})
		t.Cleanup(listener.Close)
		for _, method := range urTelemetryMethods(listener) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	printUrStatusTelemetry(context.Background(), cli)
	want := "telemetry:  serving on 127.0.0.1:" + strconv.Itoa(port) + ", model calls alone\n"
	if stdout.String() != want {
		t.Errorf("status %q, not %q", stdout.String(), want)
	}
	if strings.Contains(stdout.String(), plan.Telemetry().Token) {
		t.Error("the status line holds the token")
	}
}
