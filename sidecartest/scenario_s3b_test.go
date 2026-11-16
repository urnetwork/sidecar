package sidecartest_test

// S3b on T2 (§22.7; TEAM-M6-12): scenarios.S3b's one builder, which server's sidecart3 runs on T3, under the harness
// and the guard on T2's fakes. sidecartest/scenarios says what it composes.

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/scenarios"
)

func TestScenarioS3b(t *testing.T) {
	sidecartest.RunScenario(t, scenarios.S3b(t), nil)
}
