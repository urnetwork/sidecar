//go:build !js && !ios && !android && !sdk_mobile_bind

// A run's coverage names source gateway where the network's gateway recorded its model calls as session entries
// (DESIGN-COMPUTE §24.8's coverage row; CTXH-M12-01), and not otherwise.

package mcp

import (
	"bytes"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Two sessions of a harness: the one whose calls the gateway recorded names source gateway in its coverage, beside
// hooks; the other names hooks alone.
func TestIngestCoverageNamesGatewaySource(t *testing.T) {
	env := newIngestTestEnv(t)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	for _, sessionId := range []string{"s1", "s2"} {
		if err := harness.SessionStart(sessionId, "startup"); err != nil {
			t.Fatal(err)
		}
	}
	recorded := env.runOf(sidecartest.FakeHarnessClaudeCode, "s1")
	other := env.runOf(sidecartest.FakeHarnessClaudeCode, "s2")
	env.network.setGatewayRecorded(recorded)
	for _, sessionId := range []string{"s1", "s2"} {
		if err := harness.SessionEnd(sessionId, "exit"); err != nil {
			t.Fatal(err)
		}
	}
	runIdSources := map[sidecar.Id][]string{}
	for _, draft := range env.writer.of(sidecar.RecordKindCoverage) {
		coverage := draft.Body.(*protocol.Coverage)
		for _, runId := range []sidecar.Id{recorded, other} {
			if bytes.Equal(coverage.RunId, runId[:]) {
				runIdSources[runId] = coverage.Sources
			}
		}
	}
	if sources := runIdSources[recorded]; !slices.Contains(sources, sidecar.RecordCoverageSourceGateway) || !slices.Contains(sources, sidecar.RecordCoverageSourceHooks) || !slices.IsSorted(sources) {
		t.Errorf("the gateway's run names %v", sources)
	}
	if sources := runIdSources[other]; len(sources) == 0 || slices.Contains(sources, sidecar.RecordCoverageSourceGateway) {
		t.Errorf("the other run names %v", sources)
	}
}
