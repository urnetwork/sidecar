// ur install-harness (§16.7, R-MCP-2, D-MCP-5, D-MCP-9; MCP-M3-16): ur's MCP entry, the ask rule naming each
// outward tool and the hooks, written into a harness's own files after their diff is shown and the person confirms on
// /dev/tty, and the seal of what ur installed, which the daemon's config check holds each run to (mcp's
// harness_hash.go). It needs no daemon: the files are the person's, and the seal is the instance's local state.
//
//	ur install-harness <claude-code|codex|cursor> [--agent=<name>] [--project]
//
// Every command it writes names ur by this binary's absolute path (§4.10), and --instance, which ur takes anywhere,
// the daemon it reaches. --project writes the files a cloud session loads into the working directory, to be committed,
// and §5.8's `.ur` where the project has none. A file already holding ur's entries is left as it is, so running it
// again changes nothing, and running it after an edit restores ur's entries. --cloud-key-file, with --project, is the
// cloud profile (§16.9; QD-041; MCP-M4-02): the committed SessionStart step then first runs ur connect --token-file
// <path> --ephemeral on the owner-only file a cloud environment's setup step leaves the auth key in, the path as the
// session's VM reads it. The path is committed; no key ever is.
//
// The fail-closed form, ur hook --required on every command, Claude Code's onFailure block and Cursor's failClosed
// (D-MCP-5; MCP-M6-04), is written while a network the instance's running daemon hosts sets
// ServiceSettings.record_required (§7.9's Settings fields; owner decision 305), read from that daemon's config head
// without starting one (status.settings, status_settings.go), or where --record-required asks, the local flag a
// personal network keeps. A daemon that does not answer, or a head it cannot open, reads no Team's, and the install
// says so; while a Team requires the form, the daemon's config check reads a fail-open install as changed, so its runs
// taint until the install runs again. `ur status` names each harness installed fail-closed, and each installed
// fail-open while a Team requires otherwise. Nothing here or in MCP sets record_required: an Owner or Admin does, with
// ur admin settings.
//
// While Ingest.ModelCalls is on (§16.18; M6's, off by default), a user install of Claude Code also writes the
// exporter's settings for the daemon's telemetry listener (QD-822; mcp's harness_telemetry.go): the instance's
// telemetry pair, Ingest.TelemetryTokenByteCount random bytes and a port the loopback interface has free, drawn here
// at the first such install and sealed under <state>/harness/ by the write, then read back by every later one, so a
// re-install changes nothing and every harness names one pair. Once written, a daemon already running is asked to
// serve it (telemetry.reload, status_telemetry.go), and none is started for it. A project install takes no token,
// since its files are committed. Codex reports its model calls by its PostModelRequest hook, which every Codex install
// writes, so it takes no exporter settings and loses the [otel] table an earlier install wrote (QD-835), and Cursor
// documents no exporter setting; the install says which.

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "install-harness",
		usage:   "  ur install-harness <harness> [--agent=<name>] [--project] [--cloud-key-file=<path>] [--record-required]",
		summary: "install ur's MCP entry, outward-tool ask rule and hooks in a harness: " + strings.Join(mcp.HarnessNames(), ", "),
		run:     runUrInstallHarness,
	})
}

// ur's own absolute path, which every command the install writes names. A test replaces it.
var urHarnessExecutable = func() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(executable)
}

// The person's home, under which a user install's files go. A test replaces it.
var urHarnessHome = os.UserHomeDir

// A port the loopback interface has free now, for a telemetry pair drawn here. A test replaces it.
var urHarnessTelemetryPort = func() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// The instance's telemetry pair for an install: the one sealed under stateDirectory, else a fresh one, which the
// install's write seals. A pair that does not read is refused, naming the file, rather than drawn again over, since
// every harness installed with it would then read as changed.
func urHarnessTelemetry(ingest *sidecar.SidecarIngestSettings, stateDirectory string) (*mcp.HarnessTelemetry, error) {
	sealed, err := mcp.ReadHarnessTelemetry(stateDirectory, ingest.HarnessConfigByteCount)
	if err == nil {
		return sealed, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("the telemetry pair %s does not read: remove it, then run ur install-harness for each harness again (%w)",
			mcp.HarnessTelemetryPath(stateDirectory), err)
	}
	token := make([]byte, ingest.TelemetryTokenByteCount)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	port, err := urHarnessTelemetryPort()
	if err != nil {
		return nil, fmt.Errorf("no loopback port is free for the telemetry listener: %w", err)
	}
	return mcp.NewHarnessTelemetry(port, token), nil
}

func runUrInstallHarness(ctx context.Context, cli *urCli, options docopt.Opts) error {
	harness, _ := options.String("<harness>")
	agent, _ := options.String("--agent")
	project, _ := options.Bool("--project")
	cloudKeyFile, _ := options.String("--cloud-key-file")
	// the fail-closed form's local flag, which a personal network keeps (plan-MCP-record-required)
	recordRequired, _ := options.Bool("--record-required")
	urPath, err := urHarnessExecutable()
	if err != nil {
		return fmt.Errorf("ur's own path: %w", err)
	}
	home, err := urHarnessHome()
	if err != nil {
		return fmt.Errorf("the home directory: %w", err)
	}
	stateDirectory, err := cli.stateDirectory(cli.instance)
	if err != nil {
		return err
	}
	args := &mcp.HarnessInstallArgs{
		Harness:        harness,
		Agent:          agent,
		Instance:       cli.instance,
		Home:           home,
		UrPath:         urPath,
		StateDirectory: stateDirectory,
		CloudKeyFile:   cloudKeyFile,
		RecordRequired: recordRequired,
		Ingest:         cli.ingest,
	}
	// a Team's record_required, from a running daemon's config head (owner decision 305): asked only for a harness ur
	// installs into, and said once the plan stands
	requiredNote := ""
	if slices.Contains(mcp.HarnessNames(), harness) {
		teamRequired, note := urInstallHarnessTeamRequired(ctx, cli)
		args.RecordRequired = args.RecordRequired || teamRequired
		requiredNote = note
	}
	if project {
		cwd, err := cli.cwd()
		if err != nil {
			return err
		}
		args.ProjectDirectory, err = filepath.Abs(cwd)
		if err != nil {
			return err
		}
	}
	// the exporter's settings (QD-822): a user install's, of a harness that exports, while model calls are captured
	exporterNote := ""
	if cli.ingest.ModelCalls && !project && slices.Contains(mcp.HarnessNames(), harness) {
		if mcp.HarnessExportsTelemetry(harness) {
			args.Telemetry, err = urHarnessTelemetry(cli.ingest, stateDirectory)
			if err != nil {
				return err
			}
		} else if reason := mcp.HarnessTelemetryNone(harness); reason != "" {
			exporterNote = reason + "\n"
		}
	}
	plan, err := mcp.PlanHarnessInstall(args)
	if err != nil {
		return err
	}
	cli.printf("%s", requiredNote)
	changed, err := plan.Changed()
	if err != nil {
		return err
	}
	if !changed {
		cli.printf("ur's entries are installed in %s as they are: nothing to change\n", harness)
		cli.printf("%s", exporterNote)
		urInstallHarnessReload(ctx, cli, plan.Telemetry())
		return nil
	}
	if diff := plan.Diff(); diff != "" {
		fmt.Fprint(cli.stdout, diff)
	}
	confirmed, err := confirmOnTty(cli, fmt.Sprintf("write these changes to %s's files and seal them?", harness))
	if err != nil {
		return err
	}
	if !confirmed {
		cli.printf("nothing written\n")
		return nil
	}
	if err := plan.Write(); err != nil {
		return err
	}
	cli.printf("installed in %s; its config is sealed as %s\n", harness, plan.Seal.ConfigSha256)
	cli.printf("%s", exporterNote)
	urInstallHarnessReload(ctx, cli, plan.Telemetry())
	return nil
}

// Whether a network the instance's running daemon hosts sets record_required, read without starting a daemon, and the
// lines that say so, or what was not read.
func urInstallHarnessTeamRequired(ctx context.Context, cli *urCli) (bool, string) {
	reply, err := urRunningDaemonSettings(ctx, cli)
	if err != nil {
		return false, "no running daemon gave this instance's networks' settings, so no Team's record_required was read: " +
			"these hooks are fail-closed only with --record-required, and while a Team this instance hosts requires them the " +
			"daemon reads a fail-open install as changed until ur install-harness runs again with it up\n"
	}
	required, unknown := reply.required()
	ids := func(networkIds []sidecar.Id) string {
		texts := []string{}
		for _, networkId := range networkIds {
			texts = append(texts, networkId.String())
		}
		return strings.Join(texts, ", ")
	}
	note := ""
	if 0 < len(required) {
		note += fmt.Sprintf("network %s requires fail-closed hooks (record_required), so they are written fail-closed\n", ids(required))
	}
	if 0 < len(unknown) {
		note += fmt.Sprintf("network %s: record_required is not known here, since this device opens no config head yet; "+
			"run ur install-harness again once it does\n", ids(unknown))
	}
	return 0 < len(required), note
}

// Asks a daemon already running to serve the sealed telemetry pair, and says what it serves; nothing for an install
// with no pair. No daemon is started for it: the next one serves the pair from its start.
func urInstallHarnessReload(ctx context.Context, cli *urCli, telemetry *mcp.HarnessTelemetry) {
	if telemetry == nil {
		return
	}
	status, err := urTelemetryReloadRunning(ctx, cli)
	switch {
	case err != nil:
		cli.printf("its telemetry goes to 127.0.0.1:%d, which the daemon serves from its next start\n", telemetry.Port)
	case status.Serving:
		cli.printf("its telemetry goes to %s, which the daemon serves\n", status.Address)
	default:
		cli.printf("its telemetry goes to 127.0.0.1:%d, which the daemon does not serve: %s\n", telemetry.Port, status.Reason)
	}
}
