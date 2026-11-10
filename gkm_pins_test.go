//go:build !sidecar_http

// Pins on the fake gkm (KEYS-M2-23; R8, I-16, DESIGN-DETAILS 6.6's TestPinsNeverFall): a conflicting generation or
// epoch pin from a head, a push, a GenRotate, a store that rolled back or a HeadCheck peer raises head_alarm with
// both values, is reported as a fork and stops sealing until the chain extends the pin; and HeadCheck's heads and
// the acks answer from memory, GroupHeads only for groups both peers are leaves of and GenHeads for repos both read.

package sidecar_test

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// TestPinsNeverFall, the generation pin: a second commitment at this device's generation, shown by a head or a
// push, forks; sealing stops while its own rotation, which only shrinks exposure, still runs, and the pin's move to
// the next generation lifts the stop. A lower generation it holds is compared too, one it agrees with and a higher
// one raise nothing.
func TestAConflictingGenerationPinForksAndStopsSealing(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	b := world.flows[world.b]
	peerId := world.c.id
	agreed := world.gen1.key.GenHead()
	if standing, err := b.client.ObserveGenHead(world.repoId, agreed, &peerId); err != nil || standing != sidecar.GkmPinAgrees {
		t.Fatalf("the same pin: %d %v", standing, err)
	}
	ahead := &protocol.GenHead{GroupId: world.groupId.Bytes(), Generation: 2, Commitment: bytes.Repeat([]byte{2}, 32)}
	if standing, err := b.client.ObserveGenHead(world.repoId, ahead, &peerId); err != nil || standing != sidecar.GkmPinAhead {
		t.Fatalf("a higher pin: %d %v", standing, err)
	}
	if standing, err := b.client.ObserveGenHead(sidecar.NewId(), agreed, &peerId); err != nil || standing != sidecar.GkmPinUnheld {
		t.Fatalf("a repo this device holds nothing of: %d %v", standing, err)
	}
	if len(b.alarms) != 0 || len(b.forks) != 0 {
		t.Fatalf("an agreeing or higher pin alarmed")
	}

	forked := &protocol.GenHead{GroupId: world.groupId.Bytes(), Generation: 1, Commitment: bytes.Repeat([]byte{9}, 32)}
	if standing, err := b.client.ObserveGenHead(world.repoId, forked, &peerId); err != nil || standing != sidecar.GkmPinForked {
		t.Fatalf("a second commitment at this device's generation: %d %v", standing, err)
	}
	if len(b.alarms) != 1 || b.alarms[0].Kind != sidecar.GkmAlarmHead || b.alarms[0].SidecarId != peerId || b.alarms[0].Reason != sidecar.GkmRefusalFork {
		t.Fatalf("the alarm: %+v", b.alarms)
	}
	local := &protocol.GenHead{}
	if len(b.forks) != 1 || b.forks[0].Kind != sidecar.HeadForkGen || b.forks[0].GroupId != world.groupId || b.forks[0].PeerId == nil || *b.forks[0].PeerId != peerId ||
		proto.Unmarshal(b.forks[0].Local, local) != nil || !proto.Equal(local, agreed) {
		t.Fatalf("the fork's report: %+v", b.forks)
	}
	remote := &protocol.GenHead{}
	if err := proto.Unmarshal(b.forks[0].Remote, remote); err != nil || !proto.Equal(remote, forked) {
		t.Errorf("the fork's remote value: %v", err)
	}
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmForked) {
		t.Fatalf("a seal at a forked pin: %v", err)
	}
	if key, err := b.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 1 {
		t.Errorf("a read at a forked pin: %v", err)
	}
	// the stop survives a restart
	b.restart()
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmForked) {
		t.Fatalf("a seal at a forked pin after a restart: %v", err)
	}
	// a rotation never stops, and the chain it extends the pin by resumes sealing
	if _, err := b.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	key, err := b.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil || key.Generation() != 2 {
		t.Fatalf("a seal once the chain extended the pin: %v", err)
	}
	// a lower generation this device holds: the same commitment agrees, another forks
	if standing, err := b.client.ObserveGenHead(world.repoId, agreed, nil); err != nil || standing != sidecar.GkmPinAgrees {
		t.Errorf("a lower pin it holds: %d %v", standing, err)
	}
	if standing, err := b.client.ObserveGenHead(world.repoId, forked, nil); err != nil || standing != sidecar.GkmPinForked || len(b.forks) != 2 {
		t.Errorf("a second commitment at a lower generation it holds: %d %v", standing, err)
	}
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmForked) {
		t.Errorf("a seal after a fork below the pin: %v", err)
	}
}

// TestPinsNeverFall, the epoch pin: a second epoch_authenticator at this device's epoch, as a push seals it, forks
// and stops sealing; a commit adopted past it resumes it. A lower epoch says nothing, a higher one is to catch up
// to, and a device that is no leaf compares no epoch.
func TestAConflictingEpochPinForksAndStopsSealing(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	b := world.flows[world.b]
	group := world.engineGroup(world.b)
	agreed := &protocol.GroupHead{GroupId: world.groupId.Bytes(), Epoch: 1, EpochAuthenticator: group.EpochAuthenticator()}
	if standing, err := b.client.ObserveGroupHead(world.repoId, agreed, nil); err != nil || standing != sidecar.GkmPinAgrees {
		t.Fatalf("the same epoch pin: %d %v", standing, err)
	}
	higher := &protocol.GroupHead{GroupId: world.groupId.Bytes(), Epoch: 2, EpochAuthenticator: bytes.Repeat([]byte{2}, 32)}
	if standing, err := b.client.ObserveGroupHead(world.repoId, higher, nil); err != nil || standing != sidecar.GkmPinAhead {
		t.Fatalf("a higher epoch pin: %d %v", standing, err)
	}
	agent := world.admitAgent("agent", false)
	world.stateFor()
	world.hold(agent.gkmWorldDevice, world.gen1)
	if standing, err := agent.client.ObserveGroupHead(world.repoId, agreed, nil); err != nil || standing != sidecar.GkmPinUnheld {
		t.Fatalf("an epoch pin at a device that is no leaf: %d %v", standing, err)
	}

	forked := &protocol.GroupHead{GroupId: world.groupId.Bytes(), Epoch: 1, EpochAuthenticator: bytes.Repeat([]byte{9}, 32)}
	if standing, err := b.client.ObserveGroupHead(world.repoId, forked, nil); err != nil || standing != sidecar.GkmPinForked {
		t.Fatalf("a second epoch_authenticator at this device's epoch: %d %v", standing, err)
	}
	if len(b.alarms) != 1 || b.alarms[0].Kind != sidecar.GkmAlarmHead || len(b.forks) != 1 || b.forks[0].Kind != sidecar.HeadForkGroup || b.forks[0].PeerId != nil {
		t.Fatalf("the fork's alarm and report: %+v %+v", b.alarms, b.forks)
	}
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmForked) {
		t.Fatalf("a seal at a forked epoch: %v", err)
	}
	world.selfUpdates(world.a, 1)
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if key, err := b.client.EnsureWritable(world.ctx, world.repoId); err != nil || key.Generation() != 1 {
		t.Fatalf("a seal once a commit extended the epoch pin: %v", err)
	}
	if standing, err := b.client.ObserveGroupHead(world.repoId, forked, nil); err != nil || standing != sidecar.GkmPinBehind || len(b.forks) != 1 {
		t.Errorf("a lower epoch pin: %d %v", standing, err)
	}
}

// TestPinsNeverFall, the store: gkm serving another GenRotate at this device's generation, nothing at it, or no
// epoch at or past the one it adopted is a fork; nothing it holds changes.
func TestAStoreThatRollsBackForks(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	b := world.flows[world.b]
	world.selfUpdates(world.a, 2)
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	epochs := world.store.groupEpochs[world.groupId]
	generations := world.store.groupGenerations[world.groupId]

	// another generation 1
	other := world.generation(world.first, world.a, nil, sidecar.GkmCauseRequest, nil)
	world.store.groupGenerations[world.groupId] = append(generations[:0:0], other.signed)
	if err := b.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
		t.Fatalf("another GenRotate at the pinned generation: %v", err)
	}
	if len(b.forks) != 1 || b.forks[0].Kind != sidecar.HeadForkGen || len(b.forks[0].Remote) == 0 {
		t.Fatalf("the fork's report: %+v", b.forks)
	}
	if key, _, found, err := b.client.TestHeldGeneration(world.repoId, 1); err != nil || !found || !bytes.Equal(key.Commitment(), world.gen1.key.Commitment()) {
		t.Errorf("the held generation changed")
	}
	// no generation at all
	world.store.groupGenerations[world.groupId] = nil
	if err := b.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmAuthOffChain) || len(b.forks) != 2 {
		t.Fatalf("no GenRotate at the pinned generation: %v", err)
	}
	// epochs rolled back below the one it adopted
	world.store.groupGenerations[world.groupId] = generations
	world.store.groupEpochs[world.groupId] = epochs[:2]
	if err := b.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
		t.Fatalf("no epoch at or past the adopted one: %v", err)
	}
	if len(b.forks) != 3 || b.forks[2].Kind != sidecar.HeadForkGroup || world.pinnedEpoch(world.b) != 3 {
		t.Errorf("the epoch fork's report: %+v", b.forks)
	}
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); err == nil {
		t.Errorf("a seal after the store rolled back")
	}
	for _, alarm := range b.alarms {
		if alarm.Kind != sidecar.GkmAlarmHead {
			t.Errorf("an alarm that is no head_alarm: %+v", alarm)
		}
	}
}

// §6.4's forward read for a HeadCheck peer's generation pin: caught up when the chain gkm serves reaches it, forked
// when the chain holds another commitment there, unserved when gkm holds too little to say.
func TestCatchUpGenReadsTheChainToAPeersPin(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	b := world.flows[world.b]
	key, err := a.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := b.client.CatchUpGen(world.ctx, key.GenHead()); err != nil || outcome != sidecar.HeadCheckCaughtUp {
		t.Fatalf("a peer's pin the chain reaches: %d %v", outcome, err)
	}
	if _, _, pinned, err := b.client.TestPins(world.repoId); err != nil || pinned != 2 {
		t.Errorf("the pin after the forward read: %d %v", pinned, err)
	}
	beyond := &protocol.GenHead{GroupId: world.groupId.Bytes(), Generation: 5, Commitment: bytes.Repeat([]byte{5}, 32)}
	if outcome, err := b.client.CatchUpGen(world.ctx, beyond); err != nil || outcome != sidecar.HeadCheckCatchUpUnserved {
		t.Errorf("a peer's pin gkm serves nothing of: %d %v", outcome, err)
	}
	unknown := &protocol.GenHead{GroupId: sidecar.NewId().Bytes(), Generation: 1, Commitment: bytes.Repeat([]byte{5}, 32)}
	if outcome, err := b.client.CatchUpGen(world.ctx, unknown); err != nil || outcome != sidecar.HeadCheckCatchUpUnserved {
		t.Errorf("a group this device holds nothing of: %d %v", outcome, err)
	}
	if len(b.alarms) != 0 {
		t.Fatalf("a forward read alarmed: %+v", b.alarms[0])
	}
	forked := &protocol.GenHead{GroupId: world.groupId.Bytes(), Generation: 2, Commitment: bytes.Repeat([]byte{9}, 32)}
	if outcome, err := b.client.CatchUpGen(world.ctx, forked); err != nil || outcome != sidecar.HeadCheckCatchUpForked {
		t.Fatalf("a peer's pin the chain does not reach: %d %v", outcome, err)
	}
	// alarmed and stopped here; the engine that asked reports the fork with its peer
	if len(b.alarms) != 1 || b.alarms[0].Kind != sidecar.GkmAlarmHead || len(b.forks) != 0 {
		t.Errorf("the forked read's alarm: %+v %+v", b.alarms, b.forks)
	}
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmForked) {
		t.Errorf("a seal after a forked read: %v", err)
	}
}

// HeadCheck's heads and the acks, from memory: a generation pin for each repo the peer also reads, an epoch pin only
// for a group both are leaves of, and the groups this device is a leaf of with their newest epochs; a device with no
// leaf offers generation pins alone.
func TestHeadsNameOnlyWhatBothPeersHold(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	agent := world.admitAgent("agent", false)
	outsider := world.admit("outsider", sidecar.NewId())
	world.stateFor()
	world.hold(agent.gkmWorldDevice, world.gen1)
	world.selfUpdates(world.a, 1)
	b := world.flows[world.b]
	// a fresh process knows nothing until it loads its heads
	b.restart()
	if len(b.client.GenHeads(world.c.id)) != 0 || len(b.client.AckGroups()) != 0 {
		t.Fatalf("heads before they were loaded")
	}
	if err := b.client.LoadHeads(); err != nil {
		t.Fatal(err)
	}
	calls := len(world.store.calls)
	genHeads := b.client.GenHeads(world.c.id)
	if len(genHeads) != 1 || !proto.Equal(genHeads[0], world.gen1.key.GenHead()) {
		t.Fatalf("the generation pins for a peer that reads the repo: %v", genHeads)
	}
	groupHeads := b.client.GroupHeads(world.c.id)
	if len(groupHeads) != 1 || groupHeads[0].GetEpoch() != 1 || !bytes.Equal(groupHeads[0].GetEpochAuthenticator(), world.engineGroup(world.b).EpochAuthenticator()) {
		t.Fatalf("the epoch pins for a peer that is a leaf: %v", groupHeads)
	}
	if len(b.client.GenHeads(agent.id)) != 1 || len(b.client.GroupHeads(agent.id)) != 0 {
		t.Errorf("an agent peer reads the repo and is no leaf")
	}
	if len(b.client.GenHeads(outsider.id)) != 0 || len(b.client.GroupHeads(outsider.id)) != 0 {
		t.Errorf("a pin offered to a peer that reads nothing")
	}
	if head, held := b.client.GenHead(world.groupId); !held || head.GetGeneration() != 1 {
		t.Errorf("this device's generation pin by group")
	}
	if head, held := b.client.GroupHead(world.groupId); !held || head.GetEpoch() != 1 {
		t.Errorf("this device's epoch pin by group")
	}
	if _, held := b.client.GroupHead(sidecar.NewId()); held {
		t.Errorf("an epoch pin for a group it holds nothing of")
	}
	if acks := b.client.AckGroups(); len(acks) != 1 || acks[0].RepoId != world.repoId || acks[0].GroupId != world.groupId || acks[0].Epoch != 1 {
		t.Errorf("the groups to ack: %+v", acks)
	}
	// a catch-up moves memory with the pin, with no reload
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	calls = len(world.store.calls)
	if acks := b.client.AckGroups(); len(acks) != 1 || acks[0].Epoch != 2 {
		t.Errorf("the groups to ack after a catch-up: %+v", acks)
	}
	if heads := b.client.GroupHeads(world.a.id); len(heads) != 1 || heads[0].GetEpoch() != 2 {
		t.Errorf("the epoch pins after a catch-up: %v", heads)
	}
	if len(world.store.calls) != calls {
		t.Errorf("a head's read called gkm")
	}
	// an agent holds no leaf: generation pins alone, and no group to ack
	if err := agent.client.LoadHeads(); err != nil {
		t.Fatal(err)
	}
	if len(agent.client.GenHeads(world.b.id)) != 1 || len(agent.client.GroupHeads(world.b.id)) != 0 || len(agent.client.AckGroups()) != 0 {
		t.Errorf("an agent's heads")
	}
	if _, held := agent.client.GroupHead(world.groupId); held {
		t.Errorf("an agent's epoch pin")
	}
}
