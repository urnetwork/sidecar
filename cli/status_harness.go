// `ur status`'s harness lines (D-MCP-5; MCP-M6-04; plan-MCP-record-required): each harness ur installed the
// fail-closed form into, read from the instance's seals (mcp.ReadHarnessSeals), since a fail-closed hook stops a
// person's work while the daemon is down, and what the form does there: Claude Code and Cursor stop, Codex only while
// each hook runs. A harness installed fail-open prints nothing. The lines name the harness and the project's
// directory, which are the person's own, and no key.

package main

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/mcp"
)

func init() {
	urStatusSections = append(urStatusSections, printUrStatusHarnesses)
}

// The fail-closed harnesses of the instance, one line each.
func printUrStatusHarnesses(ctx context.Context, cli *urCli) {
	stateDirectory, err := cli.stateDirectory(cli.instance)
	if err != nil {
		return
	}
	seals, unreadable, err := mcp.ReadHarnessSeals(stateDirectory, cli.ingest.HarnessConfigByteCount)
	if err != nil {
		fmt.Fprintf(cli.stdout, "harnesses:  not read: %s\n", err)
		return
	}
	for _, seal := range seals {
		note := mcp.HarnessFailClosedNote(seal)
		if note == "" {
			continue
		}
		where := "your own files"
		if seal.ProjectDirectory != "" {
			where = seal.ProjectDirectory
		}
		fmt.Fprintf(cli.stdout, "harness:    %s in %s: %s\n", seal.Harness, where, note)
	}
	if 0 < unreadable {
		fmt.Fprintf(cli.stdout, "harnesses:  %d seals do not read: run ur install-harness again\n", unreadable)
	}
}
