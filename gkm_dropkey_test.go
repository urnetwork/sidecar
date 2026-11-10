//go:build !sidecar_http

// §10.5's depositor rule on the fake gkm (KEYS-M2-22; DESIGN-DETAILS 6.6's TestDropKeyFollowsTheDepositorRule,
// FS-23's M2 half as a unit): a depositor that reads nothing of the repo seals only to the newest GenRotate it can
// verify and that covers its state, its pin never falls, a lapsed key waits, gkm's absence costs it nothing while
// what it holds still covers, and a writer renews a drop key with under 7 days left.

package sidecar_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A mailbox's world with generation 2 claimed, so the newest GenRotate carries a drop key, and a depositor that is
// no reader of the repo.
func newGkmDropWorld(t *testing.T) (*gkmFlowWorld, *gkmFlowDevice) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_MAILBOX)
	depositor := world.flow(world.admit("depositor", sidecar.NewId()))
	world.stateFor()
	world.advance(time.Minute)
	if _, err := world.flows[world.a].client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	return world, depositor
}

// TestDropKeyFollowsTheDepositorRule: the newest GenRotate's drop key, verified and pinned; after a removal the
// older, unexpired GenRotate is refused though no gate of evs's is in the way, and the REMOVE generation's key is
// answered once a writer has rotated; a lapsed drop key waits.
func TestDropKeyFollowsTheDepositorRule(t *testing.T) {
	world, depositor := newGkmDropWorld(t)
	a := world.flows[world.a]
	second := world.log.Tip()

	dropKey, err := depositor.client.DropKey(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	gen2 := world.storedGeneration(second, 2).Rotate
	if dropKey.Generation != 2 || dropKey.GroupId != world.groupId || dropKey.RepoId != world.repoId || !bytes.Equal(dropKey.Commitment, gen2.GetCommitment()) ||
		!bytes.Equal(dropKey.PublicKey, gen2.GetDropPublicKey()) || dropKey.NotAfter.UnixMilli() != gen2.GetDropNotAfterMs() {
		t.Fatalf("the drop key answered: generation %d", dropKey.Generation)
	}
	if _, _, pinned, err := depositor.client.TestPins(world.repoId); err != nil || pinned != 2 {
		t.Errorf("the depositor's pin: %d %v", pinned, err)
	}
	if held, _, found, err := depositor.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || held != nil {
		t.Errorf("a depositor holds the GenRotate and no key: found %v", found)
	}

	// a removal: the unexpired generation 2 no longer covers this depositor's state
	world.revoke(world.x)
	world.stateFor()
	if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a stale, unexpired drop key after a removal: %v", err)
	}
	if _, err := a.client.EnsureWritable(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	dropKey, err = depositor.client.DropKey(world.ctx, world.repoId)
	if err != nil || dropKey.Generation != 3 {
		t.Fatalf("the drop key after the writer's rotation: %v", err)
	}
	if _, _, pinned, err := depositor.client.TestPins(world.repoId); err != nil || pinned != 3 {
		t.Errorf("the pin did not rise: %d %v", pinned, err)
	}

	// lapsed: it waits for a writer's rotation
	world.advance(sidecar.DefaultGkmSettings().DropKeyLifetime)
	if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("a lapsed drop key: %v", err)
	}
	if len(depositor.alarms) != 0 {
		t.Errorf("the depositor alarmed: %+v", depositor.alarms[0])
	}
}

// A pin that never falls: gkm serving nothing at the depositor's pin, a generation chain rolled back, is a fork,
// alarmed and reported, and no drop key is answered; a second commitment at the pin likewise.
func TestADepositorsPinNeverFalls(t *testing.T) {
	world, depositor := newGkmDropWorld(t)
	second := world.log.Tip()
	if _, err := depositor.client.DropKey(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	generations := world.store.groupGenerations[world.groupId]

	world.store.groupGenerations[world.groupId] = generations[:1]
	if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
		t.Fatalf("a rolled back generation chain: %v", err)
	}
	if _, _, pinned, err := depositor.client.TestPins(world.repoId); err != nil || pinned != 2 {
		t.Errorf("the pin fell: %d %v", pinned, err)
	}
	if len(depositor.alarms) != 1 || depositor.alarms[0].Kind != sidecar.GkmAlarmHead || len(depositor.forks) != 1 || depositor.forks[0].Kind != sidecar.HeadForkGen ||
		depositor.forks[0].GroupId != world.groupId {
		t.Errorf("the fork's alarm and report: %+v %+v", depositor.alarms, depositor.forks)
	}

	// another generation 2 at the pin
	other := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	world.store.groupGenerations[world.groupId] = append(generations[:1:1], other.signed)
	if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
		t.Errorf("a second commitment at the pin: %v", err)
	}
	if len(depositor.forks) != 2 || len(depositor.forks[1].Remote) == 0 {
		t.Errorf("the second fork's report: %+v", depositor.forks)
	}
	// the fork stops its deposits even once gkm serves the chain it pinned again
	world.store.groupGenerations[world.groupId] = generations
	if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmForked) {
		t.Errorf("a deposit at a forked pin: %v", err)
	}
}

// A GenRotate the depositor cannot verify is never sealed to: one signed by a device that is no writer is held as
// poisoned and alarmed, and a general repo's GenRotate carries no drop key at all.
func TestADepositorSealsToNothingItCannotVerify(t *testing.T) {
	world, depositor := newGkmDropWorld(t)
	second := world.log.Tip()
	gen2 := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	// generation 3 by a reader that does not write, with a drop key of its own
	hostile := world.generation(second, world.c, gen2, sidecar.GkmCauseRequest, func(args *sidecar.GkmGenerationArgs) {
		args.Time = world.now.Add(time.Minute)
		args.DropNotAfter = args.Time.Add(24 * time.Hour)
	})
	world.store.groupGenerations[world.groupId] = append(world.store.groupGenerations[world.groupId][:1:1], gen2.signed, hostile.signed)
	world.advance(2 * time.Minute)

	if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a GenRotate signed by no writer: %v", err)
	}
	if len(depositor.alarms) != 1 || depositor.alarms[0].Kind != sidecar.GkmAlarmRefused || depositor.alarms[0].SidecarId != world.c.id || depositor.alarms[0].Generation != 3 {
		t.Errorf("the alarm: %+v", depositor.alarms)
	}
	if _, _, pinned, _ := depositor.client.TestPins(world.repoId); pinned != 0 {
		t.Errorf("a refused generation moved the pin to %d", pinned)
	}

	general := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	generalDepositor := general.flow(general.admit("depositor", sidecar.NewId()))
	general.stateFor()
	if _, err := generalDepositor.client.DropKey(general.ctx, general.repoId); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a repo whose kind takes no deposits: %v", err)
	}
}

// KF7's deposits: with gkm stopped the newest GenRotate the depositor holds answers while it covers its state, and
// stops answering at the first removal its state shows.
func TestADepositorSealsOnWhatItHoldsWhileGkmIsStopped(t *testing.T) {
	world, depositor := newGkmDropWorld(t)
	if _, err := depositor.client.DropKey(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	world.store.setDown(true)
	dropKey, err := depositor.client.DropKey(world.ctx, world.repoId)
	if err != nil || dropKey.Generation != 2 {
		t.Fatalf("a deposit with gkm stopped: %v", err)
	}
	world.revoke(world.x)
	world.stateFor()
	if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("a deposit past a removal with gkm stopped: %v", err)
	}
	// a depositor that holds nothing has nothing to answer with
	fresh := world.flow(world.admit("fresh", sidecar.NewId()))
	world.stateFor()
	if _, err := fresh.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("a first deposit with gkm stopped: %v", err)
	}
}

// The renewal (plan-KEYS-drop-key-lifetime's rule 2): a writer rotates with cause SCHEDULE once the newest drop key
// has under 7 days left, and not a day earlier; a reader and a general repo's writer renew nothing.
func TestAWriterRenewsADropKeyWithUnderSevenDaysLeft(t *testing.T) {
	world, depositor := newGkmDropWorld(t)
	a := world.flows[world.a]
	lifetime := sidecar.DefaultGkmSettings().DropKeyLifetime
	// 8 days before it lapses nothing is renewed
	world.advance(lifetime - 8*24*time.Hour)
	if err := a.client.RenewDropKey(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.store.newestGeneration(world.groupId) != 2 {
		t.Fatalf("a drop key with over 7 days left was renewed: generation %d", world.store.newestGeneration(world.groupId))
	}
	if err := world.flows[world.c].client.RenewDropKey(world.ctx, world.repoId); err != nil || world.store.newestGeneration(world.groupId) != 2 {
		t.Errorf("a reader renewed a drop key: %v", err)
	}
	world.advance(2 * 24 * time.Hour)
	if err := a.client.RenewDropKey(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	gen3 := world.storedGeneration(world.log.Tip(), 3).Rotate
	if sidecar.GkmCause(gen3.GetCause()) != sidecar.GkmCauseSchedule || gen3.GetDropNotAfterMs() != gen3.GetTimeMs()+lifetime.Milliseconds() {
		t.Errorf("the renewal: cause %d", gen3.GetCause())
	}
	if dropKey, err := depositor.client.DropKey(world.ctx, world.repoId); err != nil || dropKey.Generation != 3 {
		t.Errorf("the renewed drop key: %v", err)
	}

	general := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	if err := general.flows[general.a].client.RenewDropKey(general.ctx, general.repoId); err != nil || general.store.newestGeneration(general.groupId) != 1 {
		t.Errorf("a general repo's writer renewed a drop key: %v", err)
	}
}
