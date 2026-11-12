package sidecartest_test

// S3a on T2 (§22.7; TEST-M2-11): scenarios.S3a's one builder, which server's sidecart3 runs on T3, under the harness
// and the guard on T2's fakes. sidecartest/scenarios says what it composes and what it does not yet.

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest/scenarios"
)

func TestScenarioS3a(t *testing.T) {
	if open := scenarios.RunOnTheMlsSubset(t, scenarios.S3a(t), nil); open != "" {
		t.Skip(open)
	}
}
