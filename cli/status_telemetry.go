// The daemon's telemetry listener (§16.18's harness OpenTelemetry; I-17; QD-822; mcp's ingest_telemetry.go) as ur
// reaches it: status.telemetry, which `ur status` prints as the listener's port and whether it serves, and
// telemetry.reload, which `ur install-harness` calls once it seals a telemetry pair, so a daemon already running serves
// it at once. Neither carries the token: a reply names the port, the address, why it serves nothing and the receiver's
// counts. Reload only reads the instance's own pair again, so it asks no confirmation.

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

// The control methods over the telemetry listener. Each name is a reading: QD-822 names none.
const (
	urMethodStatusTelemetry = "status.telemetry"
	urMethodTelemetryReload = "telemetry.reload"
)

func init() {
	urStatusSections = append(urStatusSections, printUrStatusTelemetry)
}

// status.telemetry and telemetry.reload over listener, the one ur daemon starts.
func urTelemetryMethods(listener *mcp.IngestTelemetryListener) []*sidecar.DaemonMethod {
	return []*sidecar.DaemonMethod{
		{
			Name: urMethodStatusTelemetry,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return listener.Status(), nil
			},
		},
		{
			Name: urMethodTelemetryReload,
			Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
				return listener.Reload(), nil
			},
		},
	}
}

// Asks the instance's daemon, if one is running, to serve the sealed pair: the status after. An error where none
// answers, since none is started for this.
func urTelemetryReloadRunning(ctx context.Context, cli *urCli) (*mcp.IngestTelemetryStatus, error) {
	callCtx, cancel := context.WithTimeout(ctx, cli.settings.CallTimeout)
	defer cancel()
	socketPath, err := cli.socketPath(cli.instance)
	if err != nil {
		return nil, err
	}
	client, err := cli.dialDaemon(callCtx, socketPath, cli.hello(sidecar.DaemonModeControl))
	if err != nil {
		return nil, err
	}
	defer client.Close()
	status := &mcp.IngestTelemetryStatus{}
	if err := client.Call(callCtx, urMethodTelemetryReload, struct{}{}, false, status); err != nil {
		return nil, err
	}
	return status, nil
}

// The listener's line, after status's own: nothing for a daemon that does not answer the method, or while model calls
// are off with no pair sealed, when there is nothing to say.
func printUrStatusTelemetry(ctx context.Context, cli *urCli) {
	status := &mcp.IngestTelemetryStatus{}
	if err := cli.callDaemon(ctx, urMethodStatusTelemetry, struct{}{}, false, status); err != nil {
		return
	}
	printUrTelemetryStatus(cli, status)
}

// One status as a person reads it.
func printUrTelemetryStatus(cli *urCli, status *mcp.IngestTelemetryStatus) {
	switch {
	case !status.ModelCalls && status.Port == 0:
		return
	case status.Serving:
		fmt.Fprintf(cli.stdout, "telemetry:  serving on %s, model calls alone%s\n", status.Address, urTelemetryCountsText(status.Counts))
	case status.Port != 0:
		fmt.Fprintf(cli.stdout, "telemetry:  port %d not serving: %s\n", status.Port, status.Reason)
	default:
		fmt.Fprintf(cli.stdout, "telemetry:  not serving: %s\n", status.Reason)
	}
}

// The receiver's counts, where any is not zero.
func urTelemetryCountsText(counts mcp.IngestTelemetryCounts) string {
	parts := []string{}
	if 0 < counts.Refused {
		parts = append(parts, fmt.Sprintf("%d refused", counts.Refused))
	}
	if 0 < counts.Dropped {
		parts = append(parts, fmt.Sprintf("%d dropped", counts.Dropped))
	}
	if 0 < counts.Limited {
		parts = append(parts, fmt.Sprintf("%d past the rate", counts.Limited))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}
