//go:build sidecar_legs

// test.sh --legs and the nightly cadence: every leg of this repository, on whatever runner this host has
// for it. A failing leg fails the run; a leg that compiled only, or could not run, is reported with its
// reason and is no pass, which a gate reads as open.

package legs

import (
	"context"
	"os"
	"testing"
)

func TestEveryLegRuns(t *testing.T) {
	settings := DefaultRunSettings(repositoryTop(t))
	settings.Go = goCommand()
	if image := os.Getenv("SIDECAR_LEGS_IMAGE"); image != "" {
		settings.ContainerImage = image
	}
	passed := 0
	for _, result := range Run(context.Background(), settings, DefaultLegs()) {
		switch result.Outcome {
		case OutcomePass:
			passed += 1
			t.Logf("%s", result)
		case OutcomeFail:
			t.Errorf("%s", result)
			for _, packageResult := range result.Packages {
				if packageResult.Outcome == OutcomeFail {
					t.Logf("%s on %s:\n%s", packageResult.ImportPath, result.Leg.Name, packageResult.Output)
				}
			}
		default:
			t.Logf("%s: no pass", result)
		}
	}
	t.Logf("%d of %d legs passed", passed, len(DefaultLegs()))
}
