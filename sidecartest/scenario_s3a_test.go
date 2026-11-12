package sidecartest_test

// S3a (§22.7; F3's device form, KF2, D-KEYS-3): a device added to a repo's readers, run as one scenario under the
// harness and the guard (scenario.go), on gkm's group client and the real MLS subset against gkmservice's engine on
// the scenario Net's stores, gkm's writes recorded through the host StoredWriters gave it. Its own KF2 flow, whose
// devices' names are canaries, adds a reader to the config group and the repo's, and KEYS's schedules (gkmschedule)
// run beside it on the same Net as its clauses: composition adds no mechanism, and a failure goes back to KEYS. At the
// end the runner scans every store for the canaries and for every key testHookSecret saw, classifies every key, and
// holds every stored commit to a PrivateMessage whose GkmCommitHeader carries the generation and the auth pin alone.
//
// Composed: readerkey-valid-over-7-days-refused (FS-105's long advertisement, refused at its upload and by a rotator
// a server serves it to) and adds-and-wraps-only-for-readers (KF2's Adds and Welcomes to readers alone, and FS-15's
// delivery to a non-holder, which members poison and rotate past). Not composed yet, and so missing at M2-out on
// TEST-M2-10's and this registry: a server-forged admission, KeyPackage or ReaderKey refused, an authentic ReaderKey
// past its not_after refused, and each late wrap judged at its own pin.

import (
	"context"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

// A gkm world on the scenario's Net, its engine's stores those of the host the run gives gkm.
func scenarioGkmWorlds(t *testing.T, run *sidecartest.ScenarioRun) gkmschedule.FsKeysNewWorld {
	return func(kind protocol.RepoKind) *gkmschedule.FsKeysWorld {
		return gkmschedule.NewFsKeysWorldOn(t, kind, run.Net.Clock(), run.Net.Fakes(), func(host *sidecar.ServiceHost) {
			gkmHost := run.Host("gkm")
			host.Blobs = gkmHost.Blobs
			host.Redis = gkmHost.Redis
		})
	}
}

func TestScenarioS3a(t *testing.T) {
	scenario := &sidecartest.Scenario{Id: "S3a", Run: func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		newWorld := scenarioGkmWorlds(t, run)

		// KF2: a writer and a reader whose names are canaries; the writer's pending runs add the reader to the config
		// group and the repo's by its KeyPackage, and the reader joins both from their Welcomes
		world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
		writer := world.AddMember(run.CanaryText("a device name"), false)
		reader := world.AddMember(run.CanaryText("a device name"), false)
		world.Grant(true, writer)
		world.Grant(false, reader)
		world.Admin(writer)
		world.ConfigWriters(writer)
		world.Advance()
		world.Publish()
		world.CreateConfig(writer)
		world.Create(writer)
		world.Again("the writer's pending run in the config group", func() error { return writer.Client.RunPending(world.Ctx, world.ConfigRepoId) })
		world.Again("the writer's pending run in the repo's group", func() error { return writer.Client.RunPending(world.Ctx, world.RepoId) })
		joined, err := reader.Client.JoinWelcomes(world.Ctx)
		if err != nil {
			t.Fatalf("the reader's joins: %v", err)
		}
		if len(joined) != 2 {
			t.Errorf("the reader joined %d groups", len(joined))
		}
		world.AgreeOnEpoch(writer, reader)

		// adds-and-wraps-only-for-readers
		gkmschedule.FsKeysScheduleDeliveryToANonHolder(t, newWorld)
		// readerkey-valid-over-7-days-refused
		gkmschedule.FsKeysScheduleLongAdvertisement(t, newWorld)
		return nil
	}}
	runScenarioOnTheMlsSubset(t, scenario)
}

// The 12-byte AEAD nonces the MLS subset hooks, which the capture refuses to search for
// (questions/test-m2-11-mls-nonce-hooks.md).
var scenarioMlsNonceKinds = []string{"ratchet_nonce", "sender_data_nonce", "welcome_nonce"}

// Runs a scenario whose worlds run the real MLS subset: it passes whole without the hooks, and with them it fails on
// any finding but the refused MLS nonces, and on those alone reads open, naming the question that waits on them,
// never passing.
func runScenarioOnTheMlsSubset(t *testing.T, scenario *sidecartest.Scenario) {
	t.Helper()
	if !sidecartest.HooksLinked {
		sidecartest.RunScenario(t, scenario, nil)
		return
	}
	report := sidecartest.RunScenarioReport(t, scenario, nil)
	if report.FlowErr != nil || 0 < len(report.GuardFindings) || 0 < len(report.StoredFindings) || 0 < len(report.Problems) {
		t.Fatalf("%s: flow %v, guard %q, stored %q, problems %q", scenario.Id, report.FlowErr, report.GuardFindings, report.StoredFindings, report.Problems)
	}
	if len(report.Findings) == 0 {
		return
	}
	if !report.OnlyRefusedSecrets(scenarioMlsNonceKinds...) {
		for _, finding := range report.Findings {
			t.Errorf("%s: %s", scenario.Id, finding)
		}
		return
	}
	t.Skipf("%s: every hooked key and canary was searched for and found in no store, but the capture refused %d of the MLS subset's 12-byte nonces, which waits on questions/test-m2-11-mls-nonce-hooks.md", scenario.Id, len(report.Findings))
}
