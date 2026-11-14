package sidecartest_test

// S3a on T2 (§22.7; TEST-M2-11): scenarios.S3a's one builder, which server's sidecart3 runs on T3, under the harness
// and the guard on T2's fakes, whole on both legs: under sidecar_testhooks every key the MLS subset hooks is searched
// for. sidecartest/scenarios says what it composes and what it does not yet.

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/scenarios"
)

func TestScenarioS3a(t *testing.T) {
	sidecartest.RunScenario(t, scenarios.S3a(t), nil)
}
