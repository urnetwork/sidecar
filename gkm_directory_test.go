//go:build !sidecar_http

// The team directory's group on the fake gkm (KEYS-M6-01; §22.7's seats row, §10.9's Directory group rows): the
// unhinted writers' random wait before a rotation, which a covering generation ends, the committers' order, and what
// waits for nothing.

package sidecar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// How long a test waits, in real time, for a push to reach its wait before it fails.
const gkmDirectoryTestTimeout = 30 * time.Second

// What one EnsureWritable answered.
type gkmDirectoryPush struct {
	key *sidecar.EvsRepoKey
	err error
}

// A writer's push the gate refused: its EnsureWritable on a goroutine, with wait the random time its client draws.
// Returns once the client waits on its timer, the timerCount-th the clock holds.
func (self *gkmFlowWorld) refusedPush(device *gkmFlowDevice, wait time.Duration, timerCount int) chan *gkmDirectoryPush {
	self.t.Helper()
	self.jitter = wait
	done := make(chan *gkmDirectoryPush, 1)
	go func() {
		key, err := device.client.EnsureWritable(self.ctx, self.repoId)
		done <- &gkmDirectoryPush{key: key, err: err}
	}()
	// a push that does not wait fails the test here rather than hang it
	ctx, cancel := context.WithTimeout(self.ctx, gkmDirectoryTestTimeout)
	defer cancel()
	if err := self.clock.AwaitTimers(ctx, timerCount); err != nil {
		self.t.Fatalf("%s's push set no timer: %v", device.label, err)
	}
	return done
}

// Fails if a push has answered.
func (self *gkmFlowWorld) stillWaits(label string, done chan *gkmDirectoryPush) {
	self.t.Helper()
	select {
	case push := <-done:
		self.t.Fatalf("%s answered before its wait ended: %v", label, push.err)
	default:
	}
}

// TestUnhintedDirectoryWritersWaitAndOneRotates: §22.7's seats row. x is revoked, and the revocation's signer and
// the config writers are offline, so no hint reaches anyone. Three writers push and the gate refuses each: b, a
// leaf, c, a leaf, and d, a wrapped member device, each wait their own random time and stage nothing meanwhile. b's
// wait ends first: it rotates alone with cause REMOVE, by wraps, since the tree still holds x, and the gate reopens
// within DirectoryRotateWait of the first refused push. c is told of the rotation on the group's topic: its sync
// takes the covering generation, which ends its wait, and it adopts it and stages nothing. d's hint is lost: it
// waits its whole time, then finds the covering generation at gkm and stages nothing either. Nobody committed.
func TestUnhintedDirectoryWritersWaitAndOneRotates(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_DIRECTORY)
	world.grant(true, world.c)
	wrapped := world.admit("d")
	world.grant(true, wrapped)
	d := world.hold(wrapped, world.gen1)
	world.revoke(world.x)
	second := world.stateFor()
	b, c := world.flows[world.b], world.flows[world.c]
	settings := sidecar.DefaultGkmSettings()
	if settings.DirectoryRotateWait != 15*time.Second {
		t.Fatalf("the unhinted writers' wait is up to %s", settings.DirectoryRotateWait)
	}
	timers := len(world.clock.PendingTimers())

	firstRefusedAt := world.clock.Now()
	bDone := world.refusedPush(b, 4*time.Second, timers+1)
	cDone := world.refusedPush(c, 9*time.Second, timers+2)
	dDone := world.refusedPush(d, 14*time.Second, timers+3)
	world.stillWaits("b", bDone)
	if world.store.callCount("ClaimGeneration") != 0 || world.store.callCount("UploadWraps") != 0 {
		t.Fatalf("a refused writer staged or claimed while it waited")
	}

	// b's wait ends: one rotation
	world.advance(4 * time.Second)
	push := <-bDone
	if push.err != nil {
		t.Fatalf("b's rotation: %v", push.err)
	}
	if push.key.Generation() != 2 || push.key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("b seals to generation %d, cause %d", push.key.Generation(), push.key.Cause())
	}
	generation2 := world.storedGeneration(second, 2)
	if generation2.SignerId != world.b.id || generation2.Rotate.GetLeafWrap() != nil {
		t.Errorf("generation 2 is not b's rotation by wraps over the tree that holds x")
	}
	if !sidecar.GkmGatePasses(second, world.repoId, generation2.Rotate.GetAuth(), time.UnixMilli(generation2.Rotate.GetTimeMs()), world.clock.Now()) {
		t.Errorf("the gate stays closed at b's generation")
	}
	if reopened := world.clock.Now().Sub(firstRefusedAt); settings.DirectoryRotateWait < reopened {
		t.Errorf("the gate reopened %s after the first refused push", reopened)
	}
	recipients := world.deliveryRecipients(2)
	if _, wrapped := recipients["s:x"]; wrapped {
		t.Errorf("b's rotation wrapped to the revoked device")
	}
	for _, label := range []string{"s:a", "s:c", "s:d"} {
		if _, wrapped := recipients[label]; !wrapped {
			t.Errorf("b's rotation holds no wrap to %s: %v", label, recipients)
		}
	}
	claims, uploads, wraps := world.store.callCount("ClaimGeneration"), world.store.callCount("UploadWraps"), len(world.store.wrapPaths(world.groupId, 2))
	if claims != 1 {
		t.Fatalf("%d claims for one rotation", claims)
	}

	// c's hint: the covering generation ends its wait, with 5 s of it left
	world.stillWaits("c", cDone)
	if err := c.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("c's sync at the group's hint: %v", err)
	}
	push = <-cDone
	if push.err != nil || push.key.Generation() != 2 {
		t.Fatalf("c after the covering generation: %v", push.err)
	}
	// d's hint is lost: it waits its whole time, then finds the covering generation
	world.stillWaits("d", dDone)
	world.advance(10 * time.Second)
	push = <-dDone
	if push.err != nil || push.key.Generation() != 2 {
		t.Fatalf("d after its whole wait: %v", push.err)
	}
	if world.store.callCount("ClaimGeneration") != claims || world.store.callCount("UploadWraps") != uploads || len(world.store.wrapPaths(world.groupId, 2)) != wraps {
		t.Errorf("a writer whose wait a covering generation ended staged or claimed")
	}
	if world.store.newestGeneration(world.groupId) != 2 {
		t.Errorf("gkm holds generation %d", world.store.newestGeneration(world.groupId))
	}
	if world.store.callCount("CommitEpoch") != 0 {
		t.Errorf("an unhinted writer committed from its write")
	}
}

// TestTheDirectoryGroupsSignersCommitAtOnce: the committers' order. The device that signed an admission is the
// granting device and waits nothing before it seats its subject, where any other writer leaf waits PendingCommitDelay
// plus jitter; the revocation's signer, run by its hint, commits the leaf target's Remove and then rotates, on the
// clean tree by its leaf_wrap.
func TestTheDirectoryGroupsSignersCommitAtOnce(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_DIRECTORY)
	a, b := world.flows[world.a], world.flows[world.b]
	joiner := world.admitReader("d", 1)
	joiner.row.AdmissionSigners = [][]byte{world.a.id.Bytes()}
	world.revoke(world.x)
	second := world.stateFor()
	settings := sidecar.DefaultGkmSettings()

	if _, granting, err := a.client.Pending(world.ctx, world.repoId); err != nil || !granting || a.client.PendingCommitWait(granting) != 0 {
		t.Errorf("the admission's signer does not act at once: %v", err)
	}
	if _, granting, err := b.client.Pending(world.ctx, world.repoId); err != nil || granting || b.client.PendingCommitWait(granting) != settings.PendingCommitDelay {
		t.Errorf("another writer leaf does not wait PendingCommitDelay: %v", err)
	}
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatalf("the signer's pending run: %v", err)
	}
	if world.store.callCount("CommitEpoch") != 1 || world.store.callCount("ClaimGeneration") != 1 {
		t.Fatalf("%d commits and %d claims for one Remove with its Add", world.store.callCount("CommitEpoch"), world.store.callCount("ClaimGeneration"))
	}
	firstCommit, _ := world.store.callSpan("CommitEpoch")
	firstClaim, _ := world.store.callSpan("ClaimGeneration")
	if firstClaim < firstCommit {
		t.Errorf("the rotation was claimed before the Remove was committed")
	}
	generation2 := world.storedGeneration(second, 2)
	if sidecar.GkmCause(generation2.Rotate.GetCause()) != sidecar.GkmCauseRemove || generation2.Rotate.GetLeafWrap() == nil {
		t.Errorf("the signer's rotation past its Remove: cause %d, leaf_wrap %v", generation2.Rotate.GetCause(), generation2.Rotate.GetLeafWrap() != nil)
	}
}

// TestOnlyDirectoryWritersWaitBeforeARotation: a read_only device and a reader of the directory are refused at
// once, a writer with nothing to rotate for is answered at once, and a general repo's writer rotates at its write
// with no wait, whatever its client would draw.
func TestOnlyDirectoryWritersWaitBeforeARotation(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_DIRECTORY)
	world.jitter = 10 * time.Second
	timers := len(world.clock.PendingTimers())
	if key, err := world.flows[world.b].client.EnsureWritable(world.ctx, world.repoId); err != nil || key.Generation() != 1 {
		t.Fatalf("a writer with nothing to rotate for: %v", err)
	}
	world.revoke(world.x)
	world.stateFor()
	if _, err := world.flows[world.p].client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a read_only device's EnsureWritable: %v", err)
	}
	if _, err := world.flows[world.c].client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a reader's EnsureWritable: %v", err)
	}
	if len(world.clock.PendingTimers()) != timers {
		t.Errorf("a device that rotates nothing waited")
	}

	general := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	general.jitter = 10 * time.Second
	general.revoke(general.x)
	general.stateFor()
	key, err := general.flows[general.b].client.EnsureWritable(general.ctx, general.repoId)
	if err != nil || key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Errorf("a general repo's writer at its write: %v", err)
	}
}

// TestADirectoryRepoHasNoOwner: the team directory is no member's, so a directory row that names an owner is
// refused before this device rotates for it.
func TestADirectoryRepoHasNoOwner(t *testing.T) {
	directory := &protocol.AclRepo{RepoId: sidecar.NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY}
	if !sidecar.GkmDirectoryGroup(directory) || sidecar.GkmDirectoryRepoCheck(directory) != nil {
		t.Errorf("a directory repo with no owner is refused")
	}
	owned := &protocol.AclRepo{RepoId: sidecar.NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, OwnerMemberId: sidecar.NewId().Bytes()}
	if err := sidecar.GkmDirectoryRepoCheck(owned); !errors.Is(err, sidecar.ErrGkmDirectoryOwned) {
		t.Errorf("a directory repo with an owner: %v", err)
	}
	vault := &protocol.AclRepo{RepoId: sidecar.NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: sidecar.NewId().Bytes()}
	if sidecar.GkmDirectoryGroup(vault) || sidecar.GkmDirectoryRepoCheck(vault) != nil {
		t.Errorf("a vault is held to the directory's rule")
	}

	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_DIRECTORY)
	world.repo.OwnerMemberId = world.memberId.Bytes()
	world.revoke(world.x)
	world.stateFor()
	if _, err := world.flows[world.b].client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmDirectoryOwned) {
		t.Errorf("a write to a directory repo that names an owner: %v", err)
	}
	if world.store.callCount("ClaimGeneration") != 0 {
		t.Errorf("a rotation was claimed for a directory repo that names an owner")
	}
}
