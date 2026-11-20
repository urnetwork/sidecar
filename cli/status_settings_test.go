package main

// `ur status`'s settings lines (status_settings.go; owner decisions 302, 305): every Team network names record_cost as
// its Sidecar honors it, on, off or not known, and record_required when set, a personal network nothing; and while a
// hosted network requires fail-closed hooks each harness installed fail-open is named, one installed fail-closed not.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

func TestUrStatusNamesRecordCostForEveryTeamNetwork(t *testing.T) {
	on, off, unknown, personal, unhosted := sidecar.NewId(), sidecar.NewId(), sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	hosted := []sidecar.DaemonNetwork{
		{NetworkId: on, Sidecar: &sidecar.Sidecar{}},
		{NetworkId: off, Sidecar: &sidecar.Sidecar{}},
		{NetworkId: unknown, Sidecar: &sidecar.Sidecar{}},
		{NetworkId: personal, Sidecar: &sidecar.Sidecar{}},
		{NetworkId: unhosted},
	}
	honored := []*sidecar.ConfigTeamSettings{
		{Team: true, Known: true, RecordCost: true, RecordRequired: true},
		{Team: true, Known: true},
		{Team: true},
		{Known: true, RecordCost: true},
	}
	calls := 0
	reply := urStatusSettingsOf(hosted, func(running *sidecar.Sidecar) (*sidecar.ConfigTeamSettings, error) {
		calls += 1
		return honored[calls-1], nil
	})
	if len(reply.Networks) != 5 || !reply.Networks[4].Unknown || calls != 4 {
		t.Fatalf("the reply: %+v, %d calls", reply.Networks, calls)
	}
	required, notKnown := reply.required()
	if len(required) != 1 || required[0] != on || len(notKnown) != 2 || notKnown[0] != unknown || notKnown[1] != unhosted {
		t.Fatalf("required %v, not known %v", required, notKnown)
	}
	cli, stdout, _ := newTestUrCli("")
	printUrSettingsReply(cli, reply)
	text := stdout.String()
	for _, want := range []string{
		"network " + on.String() + ": record_cost on, the Team's default: per-run cost totals go to the team record as well as your vault",
		"network " + on.String() + ": record_required on: ur install-harness writes fail-closed hooks",
		"network " + off.String() + ": record_cost off: per-run cost totals stay in your vault",
		"network " + unknown.String() + ": record_cost and record_required are not known here",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no line %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, personal.String()) || strings.Contains(text, unhosted.String()) || strings.Count(text, "\n") != 4 {
		t.Errorf("a network that is no Team's printed, or a line too many:\n%s", text)
	}
	// a Sidecar that cannot answer reads as not known
	failing := urStatusSettingsOf(hosted[:1], func(running *sidecar.Sidecar) (*sidecar.ConfigTeamSettings, error) {
		return nil, errors.New("no verified state")
	})
	if len(failing.Networks) != 1 || !failing.Networks[0].Unknown {
		t.Errorf("a Sidecar with no state: %+v", failing.Networks)
	}
}

// While a hosted network requires fail-closed hooks, the harnesses installed fail-open are named, with the command
// that fixes them; with none requiring, nothing prints.
func TestUrStatusNamesFailOpenHarnessesWhileATeamRequires(t *testing.T) {
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
	install("cursor", false)
	team := sidecar.NewId()
	printUrRequiredHarnesses(cli, &urStatusSettingsReply{Networks: []*urNetworkSettings{{NetworkId: team, Team: true, RecordRequired: false}}})
	if stdout.Len() != 0 {
		t.Fatalf("with no Team requiring: %q", stdout.String())
	}
	printUrRequiredHarnesses(cli, &urStatusSettingsReply{Networks: []*urNetworkSettings{{NetworkId: team, Team: true, RecordRequired: true}}})
	text := stdout.String()
	if !strings.Contains(text, "cursor in your own files: fail-open while network "+team.String()+" requires fail-closed hooks") ||
		!strings.Contains(text, "until ur install-harness cursor runs again") || strings.Contains(text, "claude-code") {
		t.Errorf("the lines:\n%s", text)
	}
}
