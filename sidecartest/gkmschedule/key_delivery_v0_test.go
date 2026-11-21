package gkmschedule

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
)

// A newly granted reader asks for its first key when the grant reaches its follower. Relay the two real
// service notices to the stock clients and wait on the keychain, without an application read or timer tick.
func TestReaderGrantDeliversExistingGenerationThroughHints(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	ctx, cancel := context.WithTimeout(world.Ctx, 15*time.Second)
	defer cancel()
	world.Ctx = ctx
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.DraftMls = false })
	writer := world.AddMember("writer", false)
	reader := world.AddMember("reader", true)
	world.Grant(true, writer)
	world.Creator(writer)
	world.Advance()
	world.Publish()
	first := world.Create(writer)

	reader.Offline = true
	world.Grant(false, reader)
	grant := world.Advance()
	reader.PublishReaderKey()
	attach := func(device *FsKeysDevice) *sidecar.GkmHints {
		t.Helper()
		hints, err := sidecar.NewGkmHints(ctx, &sidecar.GkmHintsArgs{Clock: world.Clock})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(hints.Close)
		device.Client.AttachHints(ctx, hints)
		return hints
	}
	writerHints, readerHints := attach(writer), attach(reader)
	reader.Take(grant)
	relay := func(hints *sidecar.GkmHints, notice *FsKeysHint) {
		t.Helper()
		body, err := proto.Marshal(notice.Hint)
		if err != nil {
			t.Fatal(err)
		}
		hints.Receive(sidecar.PushNotice{Topic: notice.Topic, Version: notice.Version, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: body})
	}
	relay(writerHints, world.AwaitHint(writer, func(hint *FsKeysHint) bool {
		return hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING && bytes.Equal(hint.Hint.GetGroupId(), world.GroupId.Bytes()) && string(hint.Hint.GetRecipient()) == fsKeysRecipient(reader.SidecarId())
	}))
	relay(readerHints, world.AwaitHint(reader, world.pendingHint))
	for {
		held, changed := reader.Client.RepoKeyHeld(world.RepoId)
		if held {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("the delivered key never reached the reader")
		}
	}
	key, err := reader.Client.CurrentRepoKey(ctx, world.RepoId)
	if err != nil || !bytes.Equal(key.Commitment(), first.Commitment()) {
		t.Fatalf("reading the signer's generation after the wake: %v", err)
	}
}

// The production routes and KeyDelivery clients form, join and remove a reader, replace the code, and recover the
// winning generation on a fresh device after both the writer and the service restart.
func TestKeyDeliveryLifecycleAfterRestartAndDeviceLoss(t *testing.T) {
	world := NewFsKeysWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.Reconfigure(func(settings *gkmservice.GkmServiceSettings) { settings.DraftMls = false })
	writer := world.AddMember("writer", false)
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
	member := world.AddMember("reader", true)
	world.Grant(false, member)
	world.Advance()
	member.PublishReaderKey()
	if _, err := member.Client.CurrentRepoKey(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Fatalf("reading before the first wrap: %v", err)
	}
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	recipient := fsKeysRecipient(member.SidecarId())
	if !slices.ContainsFunc(world.Hints(writer), func(hint *FsKeysHint) bool {
		return hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING && bytes.Equal(hint.Hint.GetGroupId(), world.GroupId.Bytes()) && string(hint.Hint.GetRecipient()) == recipient
	}) {
		t.Fatal("the reader's first key request did not wake the writer")
	}
	if err := writer.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if err := writer.Client.DeliverLate(world.Ctx, world.RepoId, recipient); err != nil {
		t.Fatal(err)
	}
	if err := world.Engine.AwaitHints(world.Ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(world.Hints(member), world.pendingHint) {
		t.Fatal("the written wrap did not wake the reader of the existing generation")
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
