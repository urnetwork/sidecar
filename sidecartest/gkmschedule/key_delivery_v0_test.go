package gkmschedule

import (
	"bytes"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
)

// The production routes and KeyDelivery clients form, join and remove a reader, replace the code, and recover the
// winning generation on a fresh device after both the writer and the service restart.
func TestKeyDeliveryLifecycleAfterRestartAndDeviceLoss(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.DraftMls = false })
	writer := world.AddMember("writer", false)
	member := world.AddMember("reader", false)
	agent := world.AddAgent("creator")
	world.Grant(true, writer, agent)
	world.Creator(agent)
	world.Admin(writer)
	world.ConfigWriters(writer)
	old := world.BindRecovery("initial", writer)
	world.Advance()
	world.Publish()
	world.CreateConfig(writer)
	first := world.Create(agent)
	if first.Generation() != 1 || world.EpochObject(0) != nil || world.Generation(1).Rotate.GetLeafWrap() != nil {
		t.Fatal("generation 1 must stand without an epoch")
	}
	world.Grant(false, member)
	world.Advance()
	member.PublishReaderKey()
	if err := writer.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if err := writer.Client.DeliverFirstWrap(world.Ctx, world.RepoId, member.SidecarId()); err != nil {
		t.Fatal(err)
	}
	got, err := member.Client.CurrentRepoKey(world.Ctx, world.RepoId)
	if err != nil || !bytes.Equal(got.Commitment(), first.Commitment()) {
		t.Fatalf("late delivery: %v", err)
	}
	world.Drop(member)
	world.Advance()
	removed, err := writer.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil || removed.Cause() != sidecar.GkmCauseRemove || world.WrapRecipients(removed.Generation())[member.SidecarId()] {
		t.Fatalf("removal rotation: %v", err)
	}
	replacement := world.RebindRecovery("replacement", writer, false)
	world.Advance()
	if err := writer.Client.CompleteRecoveryBinding(world.Ctx, replacement.KeySha256); err != nil {
		t.Fatal(err)
	}
	world.RestartEngine()
	writer.Restart()
	newDevice := world.AddRecovered("replacement-device", replacement)
	world.AdmitRecovered(newDevice)
	world.Grant(true, newDevice)
	world.Advance()
	// The code's wrap, fetched over the same engine the writer restarted against, must open under the new code.
	recovery := world.RecoverArgs(replacement)
	if err := newDevice.Client.AnchorRecovery(world.Ctx, recovery); err != nil {
		t.Fatal(err)
	}
	repos, err := newDevice.Client.RunRecovery(world.Ctx, recovery)
	if err != nil || len(repos) < 2 {
		t.Fatalf("recovery: %v", err)
	}
	read, err := newDevice.Client.CurrentRepoKey(world.Ctx, world.RepoId)
	latest, heldErr := writer.Client.CurrentRepoKey(world.Ctx, world.RepoId)
	if err != nil || heldErr != nil || !bytes.Equal(read.Commitment(), latest.Commitment()) || world.RecoveryReach(old, world.GroupId) != 0 {
		t.Fatalf("replacement read: %v, writer: %v", err, heldErr)
	}
}

// A readable repo can have its projection row before its group forms. It contributes no generation to retirement.
func TestRecoveryRotationCompletesAcrossAnUnformedRepo(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.DraftMls = false })
	writer := world.AddMember("writer", false)
	world.Grant(true, writer)
	world.Admin(writer)
	world.ConfigWriters(writer)
	old := world.BindRecovery("initial", writer)
	world.Advance()
	world.Publish()
	world.CreateConfig(writer)
	replacement := world.RebindRecovery("replacement", writer, false)
	world.Advance()
	if err := writer.Client.CompleteRecoveryBinding(world.Ctx, replacement.KeySha256); err != nil {
		t.Fatal(err)
	}
	if world.RecoveryReach(old, world.ConfigGroupId) != 0 || world.RecoveryReach(replacement, world.ConfigGroupId) == 0 {
		t.Fatal("the formed config group's replacement was not completed")
	}
}
