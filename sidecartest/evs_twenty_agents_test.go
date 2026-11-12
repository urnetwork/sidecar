//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// §22.8's twenty-agent test (EVS1-M2-43; DESIGN-DETAILS 8.6's twenty agents) through load.RunEvsAgents on T2's
// EvsGitWorld: agents pushing their owned refs and merging into main, then no acknowledged commit lost, no conflict
// branch, git fsck --strict on a device that pushed nothing, and export's main equal to its replay. The unit form is
// a smoke, four agents for a few seconds, which proves the harness and the checks and is never a gate's evidence;
// SIDECAR_EVS_AGENTS=ci runs §22.8's CI form, twenty agents for five minutes, and twenty-agents.sh runs the full hour
// with its report (SIDECAR_EVS_AGENTS=hour, SIDECAR_EVS_AGENTS_REPORT=<file>), apart from any test campaign.

package sidecartest_test

import (
	"os"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest/evsgit"
	"github.com/urnetwork/sidecar/sidecartest/load"
)

// The run's form: smoke by default, ci or hour by the environment.
func evsTwentyAgentsSettings(t *testing.T) (*load.EvsAgentsSettings, bool) {
	t.Helper()
	settings := load.DefaultEvsAgentsSettings()
	switch os.Getenv("SIDECAR_EVS_AGENTS") {
	case "hour":
		return settings, false
	case "ci":
		settings.Duration = 5 * time.Minute
		settings.Warmup = 30 * time.Second
		return settings, false
	}
	settings.Agents = 4
	settings.OwnedPushRate = 2
	settings.MergeInterval = 4 * time.Second
	settings.Duration = 8 * time.Second
	settings.Warmup = 0
	return settings, true
}

func TestEvsTwentyAgents(t *testing.T) {
	settings, smoke := evsTwentyAgentsSettings(t)
	world := evsgit.NewWorld(t, &evsgit.WorldSettings{HookCommand: evsGitHookCommand(t)})
	result, err := load.RunEvsAgents(t.Context(), world, settings)
	if err != nil {
		t.Fatal(err)
	}
	result.Owned.Smoke = smoke
	if err := result.Err(); err != nil {
		t.Fatal(err)
	}
	if result.Owned.Succeeded == 0 || result.Merges.Succeeded == 0 {
		t.Fatalf("%d owned pushes and %d merges succeeded", result.Owned.Succeeded, result.Merges.Succeeded)
	}
	if path := os.Getenv("SIDECAR_EVS_AGENTS_REPORT"); path != "" {
		data, err := result.Owned.Json()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("owned pushes: %d ok, %d failed, p50 %.0f ms, p99 %.0f ms, failures %v; merges: %d ok, %d failed, failures %v",
		result.Owned.Succeeded, result.Owned.Failed, result.Owned.LatencyMillis.P50, result.Owned.LatencyMillis.P99,
		result.Owned.FailureKinds, result.Merges.Succeeded, result.Merges.Failed, result.Merges.FailureKinds)
}
