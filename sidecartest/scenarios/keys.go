// S3a and S4a (§22.7; TEST-M2-11): F3's and F9's device forms, KF2 and KF4, each one builder that sidecartest's T2
// test and server's sidecart3 T3 test both run, as an FS row's one builder runs on both tiers, never two hand copies
// (plan-TEST-small-readings reading 1). It sits apart from sidecartest because it composes gkmschedule's worlds, which
// import sidecartest.
//
// Each runs gkm's group client and the real MLS subset against gkmservice's engine on the scenario Net's stores (T2's
// fakes, or T3's real stores), gkm's writes recorded through the host StoredWriters gave it, beside KEYS's exported
// schedules as clauses, so composition adds no mechanism and a failure goes back to KEYS:
//
//   - S3a: its own KF2 flow, whose devices' names are canaries, adds a reader to the config group and the repo's by its
//     KeyPackage and the reader joins both from their Welcomes; FS-15's delivery to a non-holder, which members poison
//     and rotate past (adds-and-wraps-only-for-readers); FS-105's long advertisement, refused at its upload and by a
//     rotator a server serves it to (readerkey-valid-over-7-days-refused). Not composed yet: a server-forged
//     admission, KeyPackage or ReaderKey, an authentic ReaderKey past its not_after, and each late wrap judged at its
//     own pin.
//   - S4a: its own KF4 flow, whose devices' names are canaries: x revoked, the writer's next EnsureWritable claims a
//     REMOVE generation wrapped to no device of x's (writers-seal-nothing-to-x), and x, keeping its MLS state and every
//     ReaderKey it signed as a malicious server lets it, opens nothing of the new generation however much of the store
//     it reads (next-generation-fails-under-xs-keys); FS-15's wrapped rotation and its kills between writes beside it.
//     Not composed yet: the gates' 412 until a covering generation, members refusing a bad commit, tokens failing in
//     their windows, the path epoch and the first-write checkpoint, which TEST-M2-12's revocation suite holds whole.
//
// RunOnTheMlsSubset judges a run under sidecar_testhooks, where the MLS subset hooks its 12-byte AEAD nonces and the
// capture refuses them (questions/test-m2-11-mls-nonce-hooks.md): any other finding fails, and those alone read open.

package scenarios

import (
	"context"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

// The 12-byte AEAD nonces the MLS subset hooks, which the capture refuses to search for.
var mlsNonceKinds = []string{"ratchet_nonce", "sender_data_nonce", "welcome_nonce"}

// gkm worlds on the scenario's Net, their engine's stores those of the host the run gives gkm.
func gkmWorlds(t testing.TB, run *sidecartest.ScenarioRun) gkmschedule.FsKeysNewWorld {
	return func(kind protocol.RepoKind) *gkmschedule.FsKeysWorld {
		return gkmschedule.NewFsKeysWorldOn(t, kind, run.Net.Clock(), run.Net.Fakes(), func(host *sidecar.ServiceHost) {
			gkmHost := run.Host("gkm")
			host.Blobs = gkmHost.Blobs
			host.Redis = gkmHost.Redis
		})
	}
}

// S3a, failing t through KEYS's schedules where they fail.
func S3a(t testing.TB) *sidecartest.Scenario {
	return &sidecartest.Scenario{Id: "S3a", Run: func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		newWorld := gkmWorlds(t, run)

		// KF2: a writer and a reader whose names are canaries
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
}

// S4a, failing t through KEYS's schedules where they fail.
func S4a(t testing.TB) *sidecartest.Scenario {
	return &sidecartest.Scenario{Id: "S4a", Run: func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		newWorld := gkmWorlds(t, run)

		world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
		writer := world.AddMember(run.CanaryText("a device name"), false)
		x := world.AddMember(run.CanaryText("a device name"), false)
		world.Grant(true, writer)
		world.Grant(false, x)
		world.Admin(writer)
		world.Advance()
		world.Publish()
		world.Create(writer)
		world.AddPending(writer)
		before, err := writer.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		if err != nil {
			t.Fatalf("the writer's first key: %v", err)
		}
		if reach := world.RemovedReach(x); reach < before.Generation() {
			t.Fatalf("x reaches generation %d before its revocation, not %d", reach, before.Generation())
		}

		// KF4: x's revocation drops it from the repo's holders; the writer's next write key is a REMOVE generation
		world.Revoke(x)
		world.Advance()
		after, err := writer.Client.EnsureWritable(world.Ctx, world.RepoId)
		if err != nil {
			t.Fatalf("the writer's rotation past x: %v", err)
		}
		if after.Generation() <= before.Generation() {
			t.Fatalf("the writer kept generation %d past x's revocation", after.Generation())
		}
		// writers-seal-nothing-to-x
		if world.WrapRecipients(after.Generation())[x.SidecarId()] {
			t.Errorf("a ReaderWrap of generation %d to the revoked device", after.Generation())
		}
		// next-generation-fails-under-xs-keys: every ReaderKey x signed, and its MLS state's every epoch
		if world.OpensWrapOf(x, after.Generation(), x.CopyReaderKeys()) {
			t.Errorf("x's ReaderKeys open generation %d", after.Generation())
		}
		if reach := world.RemovedReach(x); after.Generation() <= reach {
			t.Errorf("x's MLS state reaches generation %d of %d", reach, after.Generation())
		}

		gkmschedule.FsKeysScheduleWrappedRotation(t, newWorld)
		gkmschedule.FsKeysScheduleKillsBetweenWrites(t, newWorld)
		return nil
	}}
}

// Runs a scenario whose worlds run the real MLS subset, on settings' tier (nil: T2): without the hooks it passes
// whole or fails t; with them it fails t on any finding but the refused MLS nonces, and on those alone returns why
// the test reads open, naming the question that waits on them, which the caller skips with, never passing. It
// returns "" otherwise. The caller skips, since a skip inside server's TestEnv reads as an attempt that never
// returned.
func RunOnTheMlsSubset(t testing.TB, scenario *sidecartest.Scenario, settings *sidecartest.ScenarioSettings) string {
	t.Helper()
	if !sidecartest.HooksLinked {
		sidecartest.RunScenario(t, scenario, settings)
		return ""
	}
	report := sidecartest.RunScenarioReport(t, scenario, settings)
	if report.FlowErr != nil || 0 < len(report.GuardFindings) || 0 < len(report.StoredFindings) || 0 < len(report.Problems) {
		t.Errorf("%s: flow %v, guard %q, stored %q, problems %q", scenario.Id, report.FlowErr, report.GuardFindings, report.StoredFindings, report.Problems)
		return ""
	}
	if len(report.Findings) == 0 {
		return ""
	}
	if !report.OnlyRefusedSecrets(mlsNonceKinds...) {
		for _, finding := range report.Findings {
			t.Errorf("%s: %s", scenario.Id, finding)
		}
		return ""
	}
	return fmt.Sprintf("%s: every hooked key and canary was searched for and found in no store, but the capture refused %d of the MLS subset's 12-byte nonces, which waits on questions/test-m2-11-mls-nonce-hooks.md", scenario.Id, len(report.Findings))
}
