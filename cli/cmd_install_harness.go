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
// again changes nothing, and running it after an edit restores ur's entries.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar/mcp"
)

func init() {
	registerUrCommand(&urCommand{
		name:    "install-harness",
		usage:   "  ur install-harness <harness> [--agent=<name>] [--project]",
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

func runUrInstallHarness(ctx context.Context, cli *urCli, options docopt.Opts) error {
	harness, _ := options.String("<harness>")
	agent, _ := options.String("--agent")
	project, _ := options.Bool("--project")
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
		Ingest:         cli.ingest,
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
	plan, err := mcp.PlanHarnessInstall(args)
	if err != nil {
		return err
	}
	changed, err := plan.Changed()
	if err != nil {
		return err
	}
	if !changed {
		cli.printf("ur's entries are installed in %s as they are: nothing to change\n", harness)
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
	return nil
}
