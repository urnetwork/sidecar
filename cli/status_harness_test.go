package main

// `ur status`'s harness lines (MCP-M6-04): a harness installed fail-closed is named with what the form does there,
// one installed fail-open is not.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

func TestStatusNamesFailClosedHarnesses(t *testing.T) {
	directory := shortTestDirectory(t)
	cli, stdout, _ := newTestUrCli(filepath.Join(directory, "s"))
	cli.instance = sidecar.DefaultSidecarSettings().Instance
	state, err := cli.stateDirectory(cli.instance)
	if err != nil {
		t.Fatal(err)
	}
	install := func(harness string, required bool) {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
			t.Fatal(err)
		}
		plan, err := mcp.PlanHarnessInstall(&mcp.HarnessInstallArgs{
			Harness:        harness,
			Home:           home,
			UrPath:         "/opt/ur/bin/ur",
			StateDirectory: state,
			RecordRequired: required,
			Ingest:         sidecar.DefaultSidecarSettings().Ingest,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := plan.Write(); err != nil {
			t.Fatal(err)
		}
	}
	install("claude-code", true)
	install("codex", true)
	install("cursor", false)
	printUrStatusHarnesses(context.Background(), cli)
	out := stdout.String()
	if !strings.Contains(out, "claude-code in your own files: fail-closed") || !strings.Contains(out, "codex in your own files: fail-closed only while each hook runs") {
		t.Errorf("the fail-closed harnesses are not named: %q", out)
	}
	if strings.Contains(out, "cursor") {
		t.Errorf("a fail-open harness is named: %q", out)
	}
}
