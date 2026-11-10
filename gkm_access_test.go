//go:build !sidecar_http

// Key access on the fake gkm (KEYS-M2-22, §22.5's ladder walk, DESIGN-DETAILS 6.6's key-access rows): the ladder
// walked from a first wrap and from a leaf's own generation, a wrong parent refused, a removed reader opening
// nothing of the next generation, EnsureWritable's steps in order with its refusals, the witness stop holding no
// Remove or rotation, and a shred's ForgetRepo.

package sidecar_test

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// An agent that reads the repo, with its flows and a ReaderKey at gkm.
func (self *gkmFlowWorld) admitAgent(label string, write bool) *gkmFlowDevice {
	self.t.Helper()
	agent := self.admit(label, sidecar.NewId())
	self.grant(write, agent)
	return self.flow(agent)
}

// TestKeyAccessWalksTheLadderFromAnyHeldGeneration: an agent that holds nothing takes its first wrap of the newest
// generation and walks the ladder down to generation 1 through the GenRotates gkm serves; every generation then
// answers from the keychain with RK_1, so `ref` derives; a leaf that holds only generation 1 reaches the newer ones
// by their leaf_wraps; a generation gkm does not hold is refused, never defaulted.
func TestKeyAccessWalksTheLadderFromAnyHeldGeneration(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	agent := world.admitAgent("agent", false)
	view := world.stateFor()
	a := world.flows[world.a]
	for generation := uint64(2); generation <= 4; generation += 1 {
		world.advance(time.Minute)
		if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
	}

	key, err := agent.client.CurrentRepoKey(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation() != 4 || !key.HoldsFirst() || key.GroupId() != world.groupId {
		t.Fatalf("the agent's first key: generation %d, RK_1 %v", key.Generation(), key.HoldsFirst())
	}
	if _, err := key.DeriveKey(sidecar.EvsKeyPurposeRef, nil); err != nil {
		t.Errorf("ref does not derive after the walk: %v", err)
	}
	calls := world.store.callCount("Generations")
	for generation := uint64(1); generation <= 4; generation += 1 {
		held, err := agent.client.RepoKey(world.ctx, world.repoId, generation)
		if err != nil {
			t.Fatalf("generation %d: %v", generation, err)
		}
		want := world.storedGeneration(view, generation).Rotate.GetCommitment()
		if held.Generation() != generation || !bytes.Equal(held.Commitment(), want) || !held.HoldsFirst() {
			t.Errorf("generation %d from the keychain: generation %d", generation, held.Generation())
		}
	}
	if world.store.callCount("Generations") != calls {
		t.Errorf("a generation the keychain holds was read from gkm again")
	}
	if current, err := agent.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || current.Generation() != 4 || world.store.callCount("Generations") != calls {
		t.Errorf("CurrentRepoKey from the keychain: %v", err)
	}
	if _, _, pinned, err := agent.client.TestPins(world.repoId); err != nil || pinned != 4 {
		t.Errorf("the agent's generation pin: %d %v", pinned, err)
	}
	for _, generation := range []uint64{0, 5} {
		if _, err := agent.client.RepoKey(world.ctx, world.repoId, generation); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
			t.Errorf("generation %d, which gkm does not hold: %v", generation, err)
		}
	}
	// a leaf that holds generation 1 alone reaches generation 3 by the generations' leaf_wraps
	b := world.flows[world.b]
	if held, err := b.client.RepoKey(world.ctx, world.repoId, 3); err != nil || held.Generation() != 3 {
		t.Fatalf("a leaf's generation 3: %v", err)
	}
	if current, err := b.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || current.Generation() != 4 {
		t.Errorf("a leaf's newest key after its refresh: %v", err)
	}
	for _, device := range []*gkmFlowDevice{agent, b} {
		if len(device.alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, device.alarms[0])
		}
	}
}

// A wrong C_g in the ladder: gkm serves, at gen/2, a validly signed statement that is not generation 3's parent.
// The generation the delivery opened is held, alarmed as one that does not chain, and never sealed to; the walk
// opens nothing through the wrong parent and keeps nothing of it.
func TestKeyAccessRefusesAParentThatIsNotItsChilds(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	agent := world.admitAgent("agent", true)
	view := world.stateFor()
	a := world.flows[world.a]
	for generation := uint64(2); generation <= 3; generation += 1 {
		world.advance(time.Minute)
		if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
	}
	// another generation 2 by the same rotator, with another RK
	other := world.generation(view, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	world.store.groupGenerations[world.groupId][1] = other.signed

	key, err := agent.client.CurrentRepoKey(world.ctx, world.repoId)
	if err != nil || key.Generation() != 3 || key.HoldsFirst() {
		t.Fatalf("the generation the delivery opened, with no RK_1 reached: %v", err)
	}
	if _, poisoned, found, err := agent.client.TestHeldGeneration(world.repoId, 3); err != nil || !found || !poisoned {
		t.Errorf("a generation that does not chain on what gkm serves below it is not held as poisoned")
	}
	if len(agent.alarms) != 1 || agent.alarms[0].Kind != sidecar.GkmAlarmRefused || agent.alarms[0].Reason != sidecar.GkmRefusalChain || agent.alarms[0].Generation != 3 {
		t.Errorf("the alarm: %+v", agent.alarms)
	}
	for count := 0; count < 2; count += 1 {
		if _, err := agent.client.RepoKey(world.ctx, world.repoId, 2); !errors.Is(err, sidecar.ErrGkmAuthentication) {
			t.Errorf("generation 2 behind a wrong parent: %v", err)
		}
	}
	if _, _, found, _ := agent.client.TestHeldGeneration(world.repoId, 2); found {
		t.Errorf("a parent that does not chain was kept")
	}
	if _, err := key.DeriveKey(sidecar.EvsKeyPurposeRef, nil); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("ref derived with no RK_1: %v", err)
	}
	// nothing is sealed to it: the writer's rotation past it is refused its claim here, so it waits
	world.store.refuseTimes("ClaimGeneration", http.StatusForbidden, 2)
	if _, err := agent.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("EnsureWritable on a poisoned generation: %v", err)
	}
}

// A removed reader opens nothing of the next generation: it adopts its own Remove, keeps what it held, judges gen/2
// as any member does, and finds neither a leaf_wrap of an epoch it holds nor a delivery to its key.
func TestARemovedReaderOpensNothingOfTheNextGeneration(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	x := world.flows[world.x]
	world.revoke(world.x)
	world.stateFor()

	key, err := a.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the generation after the Remove: %d, cause %d", key.Generation(), key.Cause())
	}
	if err := x.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("the removed leaf's sync: %v", err)
	}
	if world.engineGroup(world.x) != nil {
		t.Errorf("the removed leaf still holds a leaf")
	}
	if _, err := x.client.RepoKey(world.ctx, world.repoId, 2); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("the removed reader's generation 2: %v", err)
	}
	if held, _, found, err := x.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || held != nil {
		t.Errorf("the removed reader holds a key of generation 2")
	}
	if current, err := x.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || current.Generation() != 1 {
		t.Errorf("what it held before its removal: %v", err)
	}
	if recipients := world.deliveryRecipients(2); len(recipients) != 0 {
		t.Errorf("deliveries of generation 2: %v", recipients)
	}
}

// TestEnsureWritableCommitsThenRotatesThenRefuses: the steps in order on a fake clock. A writer leaf commits the
// pending Remove and Add in one commit, then rotates with cause REMOVE; 30 days on it rotates with cause SCHEDULE;
// while gkm refuses its claim it refuses to answer a key any non-reader holds, with no gate of evs's in the way; a
// reader and a read_only device are no writers.
func TestEnsureWritableCommitsThenRotatesThenRefuses(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	world.revoke(world.x)
	d := world.admitReader("d", 1)
	second := world.stateFor()

	key, err := a.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	gen2 := world.storedGeneration(second, 2)
	if key.Generation() != 2 || !bytes.Equal(key.Commitment(), gen2.Rotate.GetCommitment()) || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the key after a Remove: generation %d, cause %d", key.Generation(), key.Cause())
	}
	if world.store.callCount("CommitEpoch") != 1 || world.store.callCount("ClaimGeneration") != 1 {
		t.Errorf("%d commits and %d claims for one Remove with its Add", world.store.callCount("CommitEpoch"), world.store.callCount("ClaimGeneration"))
	}
	firstCommit, _ := world.store.callSpan("CommitEpoch")
	firstClaim, _ := world.store.callSpan("ClaimGeneration")
	if firstClaim < firstCommit {
		t.Errorf("the rotation was claimed before the pending changes were committed")
	}
	if labels := world.rosterLabels(world.engineGroup(world.a)); strings.Join(labels, "") != "abcdp" {
		t.Errorf("the tree after the commit: %v", labels)
	}
	// nothing more is due: the same generation, and nothing written
	if again, err := a.client.EnsureWritable(world.ctx, world.repoId); err != nil || again.Generation() != 2 || world.store.callCount("ClaimGeneration") != 1 {
		t.Errorf("a second call with nothing pending: %v", err)
	}

	// 30 days on: SCHEDULE
	world.advance(30*24*time.Hour + time.Second)
	key, err = a.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation() != 3 || key.Cause() != sidecar.GkmCauseSchedule {
		t.Errorf("the key 30 days on: generation %d, cause %d", key.Generation(), key.Cause())
	}

	// a shrink gkm will not let this device rotate past: the key a non-reader holds is refused
	world.revoke(world.c)
	world.stateFor()
	world.store.refuseTimes("ClaimGeneration", http.StatusForbidden, 2)
	if _, err := a.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a key a non-reader holds: %v", err)
	}
	if world.store.newestGeneration(world.groupId) != 3 {
		t.Fatalf("a refused claim stands")
	}
	key, err = a.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil || key.Generation() != 4 || key.Cause() != sidecar.GkmCauseRemove {
		t.Errorf("the key once the claim is taken: %v", err)
	}

	// no writer: a reader, and a read_only device whatever its grant
	if _, err := world.flows[d].client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a reader's EnsureWritable: %v", err)
	}
	world.grant(true, world.p)
	world.stateFor()
	if _, err := world.flows[world.p].client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a read_only device's EnsureWritable: %v", err)
	}
}

// EnsureWritable acts only on the newest generation: a writer behind another's rotation takes the winner by its
// leaf_wrap and rotates nothing; an agent writer with no delivery of the newest is refused, never answered the
// older key it holds, and asks for a late one.
func TestEnsureWritableAnswersOnlyTheNewestGeneration(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	agent := world.admit("agent", sidecar.NewId())
	world.grant(true, agent)
	world.stateFor()
	wrapped := world.hold(agent, world.gen1)
	// its ReaderKey is not at gkm when the rotation stages its deliveries
	delete(world.store.readerKeys, agent.id)
	a := world.flows[world.a]
	b := world.flows[world.b]
	world.advance(time.Minute)
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}

	key, err := b.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation() != 2 || world.store.newestGeneration(world.groupId) != 2 {
		t.Errorf("a writer behind a rotation: generation %d, gkm at %d", key.Generation(), world.store.newestGeneration(world.groupId))
	}
	if _, err := wrapped.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Fatalf("a writer with no delivery of the newest generation: %v", err)
	}
	if len(world.store.lateAsks) != 1 || world.store.newestGeneration(world.groupId) != 2 {
		t.Errorf("late asks %v, gkm at generation %d", world.store.lateAsks, world.store.newestGeneration(world.groupId))
	}
	if current, err := wrapped.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || current.Generation() != 1 {
		t.Errorf("reads go on with what it holds: %v", err)
	}
}

// The witness stop never holds a Remove or a rotation (owner decision 129): with sealing stopped, EnsureWritable
// still commits the Remove and claims the REMOVE generation, and only then refuses the key.
func TestTheWitnessStopHoldsNoRemoveOrRotation(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	asked := []sidecar.Id{}
	a.sealAllowed = func(groupId sidecar.Id) error {
		asked = append(asked, groupId)
		return sidecar.ErrHeadStop
	}
	world.revoke(world.x)
	world.stateFor()

	if _, err := a.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrHeadStop) {
		t.Fatalf("a stopped seal: %v", err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.newestGeneration(world.groupId) != 2 {
		t.Errorf("the stop held the Remove or the rotation: epoch %d, generation %d", newest, world.store.newestGeneration(world.groupId))
	}
	if len(asked) != 1 || asked[0] != world.groupId {
		t.Errorf("SealAllowed asked %v", asked)
	}
	a.sealAllowed = nil
	if key, err := a.client.EnsureWritable(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("the key once the stop lifts: %v", err)
	}
}

// §11.12's shred: ForgetRepo drops the repo's keys, GenRotates, pins and MLS state, and nothing of the repo answers
// from the keychain after.
func TestForgetRepoDropsEveryRecordAndTheGroupsState(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	b := world.flows[world.b]
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if _, err := b.client.RepoKey(world.ctx, world.repoId, 2); err != nil {
		t.Fatal(err)
	}
	if err := b.client.LoadHeads(); err != nil {
		t.Fatal(err)
	}
	if _, held := b.client.GenHead(world.groupId); !held {
		t.Fatal("no generation pin before the shred")
	}

	if err := b.client.ForgetRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if names, err := b.secrets.List(""); err != nil || len(names) != 0 {
		t.Errorf("records left after the shred: %v %v", names, err)
	}
	if world.engineGroup(world.b) != nil {
		t.Errorf("the group's MLS state is still held")
	}
	if _, held := b.client.GenHead(world.groupId); held {
		t.Errorf("a generation pin answers after the shred")
	}
	world.store.setDown(true)
	if _, err := b.client.RepoKey(world.ctx, world.repoId, 1); err == nil {
		t.Errorf("a key answered after the shred")
	}
	if _, err := b.client.CurrentRepoKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("CurrentRepoKey after the shred: %v", err)
	}
}

// A process that does not hold the network's state, a page Worker without the Web Lock, runs no flow and loads no
// MLS state: every call refuses.
func TestAProcessWithoutTheStateRunsNoFlow(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	b := world.flows[world.b]
	b.stateless = true
	if _, err := b.client.CurrentRepoKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("CurrentRepoKey: %v", err)
	}
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("EnsureWritable: %v", err)
	}
	if err := b.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("SyncRepo: %v", err)
	}
	if err := b.client.ForgetRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("ForgetRepo: %v", err)
	}
	if world.store.callCount("Generations")+world.store.callCount("Epochs") != 0 {
		t.Errorf("a stateless process called gkm")
	}
	b.stateless = false
	if key, err := b.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 1 {
		t.Errorf("the holder's CurrentRepoKey: %v", err)
	}
}
