package gkmschedule

// FS-18's Delegation cases on T2 and FS-102's key legs on T2 and T3 (KEYS-M2-28; D-KEYS-16, I-15, FI-3, FI-4; §10.5's
// covered row and its table, owner decision 114), on the real subset against gkmservice's engine, with evs's gate off
// (D-TEST-6), so what holds is the writers' own rule and gkm's: a Delegation D admits agents, which read the repo
// through D's DelegationWrap while D covers them, and
//
//   - a covered agent's Suspend drops D's key: the next generation is cause REMOVE and wrapped neither to D nor to
//     the agent, the other agent reading it by its own ReaderWrap; with every staged and late wrap gkm holds given to
//     the suspended agent, nothing claimed after the Suspend opens under any key it kept, D's reader seed included;
//     unsuspended, it reads the current generation only by a late ReaderWrap of its own;
//   - a DelegationRevoke ends D: the next generation is cause REMOVE, D's seed opens nothing of it, and its agents
//     read on uncovered by their own ReaderWraps;
//   - a covered agent's reap, and an ephemeral covered agent's own not_after passing, drop no holder: no rotation is
//     due, and the agent, holding D's seed, reads D's generations until D's key drops, and nothing after;
//   - FS-102: a thief keeps a copy of D's whole bundle; A revoked for compromise from a since_n after C's admission
//     ends D there, the next REMOVE generations exclude D's key, B, whom the thief admits with D's signing seed, is
//     refused by every reader, so it stands in no state and no honest writer wraps to it, and C reads on by its own
//     ReaderWrap; a thief holding only D's reader seed opens nothing claimed after the drop; and with A revoked as
//     removed instead, D's key retires while D still admits: B's admission lands, B reads only by its own late
//     ReaderWrap, and a later DelegationRevoke whose since_n precedes B's admission parks B, whom the next REMOVE
//     generation excludes.
//
// What a covered agent reads it reads at gkm's read route under its own token, which serves it its covering
// Delegation's d: deliveries (§10.6's read row), opened with D's seed (CoveredRead): the group client opens only s:
// deliveries, so a covered agent's own key access is not exercised here (see KEYS-M2-28's record). A SidecarAdmit by
// D's key refused by api and every reader, D's max_admits, the checkpoint a path epoch makes and the AdmissionConfirm
// that lifts a park are TEAM's and evs's.

import (
	"crypto/hpke"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The newest generation of the repo any of keys opens from every delivery gkm holds, whatever recipient its path
// names: what a party gkm hands every staged and late wrap to reaches with those keys.
func (self *FsKeysWorld) KeysOpenAny(keys []hpke.PrivateKey) uint64 {
	self.t.Helper()
	reach := uint64(0)
	for generation := uint64(1); generation <= uint64(self.GenerationCount()); generation += 1 {
		parsed := self.Generation(generation)
		for key, body := range self.objects(gkmservice.GkmWrapGenerationPrefix(self.GroupId, generation)) {
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(body, signed); err != nil {
				continue
			}
			wrapType := sidecar.GkmWrapTypeReader
			if strings.Contains(key, "/d:") {
				wrapType = sidecar.GkmWrapTypeDelegation
			}
			delivery, err := sidecar.ParseGkmDelivery(signed, wrapType, sidecar.GkmIdentityKeys(self.Log.Tip()))
			if err != nil {
				continue
			}
			for _, privateKey := range keys {
				if _, err := sidecar.OpenGkmDelivery(delivery, parsed, delivery.Body.GetRecipient(), privateKey); err == nil && reach < generation {
					reach = generation
				}
			}
		}
	}
	return reach
}

// An agent a thief admits with a Delegation's copied signing seed, which api and every reader refuse: it stands in
// no state, so gkm refuses its token's every route and no honest writer counts it.
func (self *FsKeysWorld) AddRefused(label string, delegation *FsKeysDelegation) *FsKeysDevice {
	self.t.Helper()
	device := self.admit(label)
	device.row.TagIds = [][]byte{delegation.atom.Bytes()}
	device.row.DelegationId = append([]byte(nil), delegation.Id...)
	device.unadmitted = true
	device.Restart()
	return device
}

// The Delegation world: a, the repo's admin and D's signer, and b, writer leaves; Delegation D, valid 30 days,
// admitting agents first and second, which read the repo through D's tag grant and so through D's wrap.
func newFsKeysDelegationWorld(t FsKeysT, newWorld FsKeysNewWorld, first string, second string, ephemeral bool) (*FsKeysWorld, *FsKeysDevice, *FsKeysDevice, *FsKeysDelegation, *FsKeysDevice, *FsKeysDevice) {
	t.Helper()
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	world.Grant(true, a, b)
	world.Admin(a)
	delegation := world.AddDelegation("D", a, world.Clock.Now().Add(30*24*time.Hour))
	agentFirst := world.AddCoveredAgent(first, delegation, ephemeral)
	agentSecond := world.AddCoveredAgent(second, delegation, false)
	world.Grant(false, agentFirst, agentSecond)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	// generation 1 reaches the agents through D's wrap alone
	if !world.DelegationOpens(delegation, 1) {
		t.Fatalf("generation 1 holds no DelegationWrap to D")
	}
	for _, agent := range []*FsKeysDevice{agentFirst, agentSecond} {
		if world.WrapRecipients(1)[agent.SidecarId()] {
			t.Errorf("generation 1 holds a ReaderWrap to covered agent %s", agent.Label)
		}
		if !world.CoveredRead(agent, delegation, 1) {
			t.Errorf("covered agent %s does not read generation 1 through D's wrap", agent.Label)
		}
	}
	return world, a, b, delegation, agentFirst, agentSecond
}

// The keys a party holds: a device's own ReaderKeys, and a Delegation's reader seed.
func fsKeysHeldKeys(device *FsKeysDevice, delegation *FsKeysDelegation) []hpke.PrivateKey {
	keys := []hpke.PrivateKey{}
	if device != nil {
		keys = append(keys, device.CopyReaderKeys()...)
	}
	if delegation != nil {
		keys = append(keys, delegation.ReaderPrivateKey)
	}
	return keys
}

// FS-18: covered agent A's Suspend drops D's key; nothing claimed after it opens under any key A kept, D's seed
// included, while B reads each generation by its own ReaderWrap; unsuspended, A reads the current generation by a
// late ReaderWrap of its own and no earlier one.
func FsKeysScheduleCoveredAgentSuspended(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, _, delegation, agentA, agentB := newFsKeysDelegationWorld(t, newWorld, "A", "B", false)
	world.Suspend(agentA)
	world.Advance()
	key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil {
		t.Fatalf("the writer's EnsureWritable after the Suspend: %v", err)
	}
	if key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the writer seals to generation %d, cause %d", key.Generation(), key.Cause())
	}
	if world.DelegationRecipients(2)[delegation.Hex()] {
		t.Errorf("generation 2 is wrapped to D, whose key dropped")
	}
	recipients := world.WrapRecipients(2)
	if recipients[agentA.SidecarId()] || !recipients[agentB.SidecarId()] {
		t.Errorf("generation 2's ReaderWraps: to A %v, to B %v", recipients[agentA.SidecarId()], recipients[agentB.SidecarId()])
	}
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("a later rotation: %v", err)
	}
	// every wrap gkm holds, handed to A: nothing claimed after the Suspend opens under A's keys or D's seed
	if reached := world.KeysOpenAny(fsKeysHeldKeys(agentA, delegation)); reached != 1 {
		t.Errorf("the suspended agent's keys open generation %d", reached)
	}
	for generation := uint64(2); generation <= 3; generation += 1 {
		if err := agentB.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
			t.Fatal(err)
		}
		if _, err := agentB.Client.RepoKey(world.Ctx, world.RepoId, generation); err != nil {
			t.Errorf("B does not read generation %d by its own ReaderWrap: %v", generation, err)
		}
	}

	// unsuspended, A reads the current generation by a late ReaderWrap of its own
	world.Unsuspend(agentA)
	world.Advance()
	if err := a.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(agentA.SidecarId())); err != nil {
		t.Fatalf("the late delivery to the unsuspended agent: %v", err)
	}
	if err := agentA.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if held, err := agentA.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != 3 {
		t.Errorf("the unsuspended agent's current generation: %v", err)
	}
	if world.OpensWrapOf(agentA, 2, agentA.CopyReaderKeys()) {
		t.Errorf("the unsuspended agent holds a ReaderWrap of generation 2, claimed while it was suspended")
	}
}

// FS-18: a DelegationRevoke ends D: the next generation is cause REMOVE, D's seed opens nothing of it, and both agents
// read on, uncovered, by their own ReaderWraps.
func FsKeysScheduleDelegationRevoked(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, _, delegation, agentA, agentB := newFsKeysDelegationWorld(t, newWorld, "A", "B", false)
	world.RevokeDelegation(delegation)
	world.Advance()
	key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil || key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the writer's EnsureWritable after the DelegationRevoke: %v", err)
	}
	if world.DelegationRecipients(2)[delegation.Hex()] {
		t.Errorf("generation 2 is wrapped to the revoked Delegation")
	}
	if reached := world.KeysOpenAny(fsKeysHeldKeys(nil, delegation)); reached != 1 {
		t.Errorf("D's reader seed opens generation %d", reached)
	}
	for _, agent := range []*FsKeysDevice{agentA, agentB} {
		if err := agent.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
			t.Fatal(err)
		}
		if held, err := agent.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != 2 {
			t.Errorf("agent %s does not read generation 2 uncovered: %v", agent.Label, err)
		}
	}
}

// FS-18: covered agent A's reap drops no holder, so no rotation is due and the gate stays open; A, holding D's seed,
// reads D's generations, a later REQUEST one included, until D's key drops at B's Suspend, and nothing after.
func FsKeysScheduleCoveredAgentReaped(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, _, delegation, agentA, agentB := newFsKeysDelegationWorld(t, newWorld, "A", "B", false)
	world.Reap(agentA)
	view := world.Advance()
	generation1 := world.Generation(1)
	if !sidecar.GkmGatePasses(view, world.RepoId, generation1.Rotate.GetAuth(), world.GenerationTime(generation1), world.Clock.Now()) {
		t.Errorf("a covered agent's reap closed the gate")
	}
	if key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil || key.Generation() != 1 {
		t.Fatalf("a rotation started at a covered agent's reap: %v", err)
	}
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if !world.DelegationOpens(delegation, 2) {
		t.Errorf("the reaped agent's D seed does not open generation 2, claimed while D's key stands")
	}
	world.Suspend(agentB)
	world.Advance()
	key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil || key.Generation() != 3 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the rotation past D's key drop: %v", err)
	}
	if reached := world.KeysOpenAny(fsKeysHeldKeys(agentA, delegation)); reached != 2 {
		t.Errorf("the reaped agent's keys reach generation %d, not 2", reached)
	}
}

// FS-18: ephemeral covered agent E's own not_after passing drops no holder, as its reap would not: no rotation is
// due, and E reads D's generations until D's key drops.
func FsKeysScheduleEphemeralCoveredAgentPastItsNotAfter(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, _, delegation, agentE, agentB := newFsKeysDelegationWorld(t, newWorld, "E", "B", true)
	world.ExpireAt(agentE, world.Clock.Now().Add(time.Minute))
	world.Advance()
	world.Clock.Advance(2 * time.Minute)
	if key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil || key.Generation() != 1 {
		t.Fatalf("a rotation started at a covered ephemeral agent's not_after: %v", err)
	}
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if !world.DelegationOpens(delegation, 2) {
		t.Errorf("the ephemeral agent's D seed does not open generation 2")
	}
	world.Suspend(agentB)
	world.Advance()
	if key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the rotation past D's key drop: %v", err)
	}
	if reached := world.KeysOpenAny(fsKeysHeldKeys(agentE, delegation)); reached != 2 {
		t.Errorf("the ephemeral agent's keys reach generation %d, not 2", reached)
	}
}

// FS-102 (1) and (3): A's compromise revocation from a since_n after C's admission ends D there; the REMOVE generations
// after it exclude D's key; B, whom the thief admits with D's copied signing seed, stands in no state and gets no wrap,
// its keys and the copy's seed opening nothing after the drop; C reads on by its own ReaderWrap.
func FsKeysScheduleCopiedBundleCompromise(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, _, delegation, agentA, agentC := newFsKeysDelegationWorld(t, newWorld, "A", "C", false)
	// the thief's copy of D's whole bundle: the reader seed, and the signing seed it admits B with
	copied := delegation.ReaderPrivateKey
	world.RevokeForCompromise(agentA)
	world.Advance()
	thiefAgent := world.AddRefused("B", delegation)
	key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil || key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the REMOVE generation past D's end: %v", err)
	}
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	for generation := uint64(2); generation <= 3; generation += 1 {
		if world.DelegationRecipients(generation)[delegation.Hex()] {
			t.Errorf("generation %d is wrapped to the ended Delegation", generation)
		}
		if world.WrapRecipients(generation)[thiefAgent.SidecarId()] {
			t.Errorf("generation %d is wrapped to the thief's agent", generation)
		}
		if !world.WrapRecipients(generation)[agentC.SidecarId()] {
			t.Errorf("generation %d holds no ReaderWrap to C", generation)
		}
	}
	// the thief's agent cannot even upload a ReaderKey: gkm holds no row of it
	thiefAgent.published = true
	now := world.Clock.Now()
	readerKey, _, err := sidecar.NewGkmReaderKey(thiefAgent.SidecarId(), now, now.Add(6*24*time.Hour), thiefAgent.signer.Sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := thiefAgent.Api.UploadReaderKey(world.Ctx, readerKey); err == nil {
		t.Errorf("gkm took a ReaderKey from an agent no state admits")
	}
	if reached := world.KeysOpenAny([]hpke.PrivateKey{copied}); reached != 1 {
		t.Errorf("the copied reader seed opens generation %d, claimed after D's end", reached)
	}
	if reached := world.KeysOpenAny(fsKeysHeldKeys(thiefAgent, delegation)); reached != 1 {
		t.Errorf("the thief's agent reaches generation %d", reached)
	}
	if err := agentC.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if held, err := agentC.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != 3 {
		t.Errorf("C does not read on by its own ReaderWrap: %v", err)
	}
	if reached := world.KeysOpenAny(fsKeysHeldKeys(agentA, delegation)); reached != 1 {
		t.Errorf("the revoked agent reaches generation %d", reached)
	}
}

// FS-102 (2): A revoked as removed: D's key retires at that position while D still admits, so B's admission lands and
// B, uncovered, reads only by its own late ReaderWrap; a later DelegationRevoke whose since_n precedes B's admission
// parks B, and the next REMOVE generation excludes it.
func FsKeysScheduleCopiedBundleRemoved(t FsKeysT, newWorld FsKeysNewWorld) {
	world, a, _, delegation, agentA, _ := newFsKeysDelegationWorld(t, newWorld, "A", "C", false)
	at := world.nextPosition()
	world.Revoke(agentA)
	delegation.row.KeyDroppedAt = at
	world.Advance()
	if key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil || key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the REMOVE generation past D's key drop: %v", err)
	}
	// B's admission by D's key lands: D still admits, its key retired
	agentB := world.AddCoveredAgent("B", delegation, false)
	world.Grant(false, agentB)
	world.Advance()
	world.Publish()
	if world.DelegationOpens(delegation, 2) {
		t.Errorf("generation 2 is wrapped to D, whose key dropped")
	}
	if err := a.Client.DeliverLate(world.Ctx, world.RepoId, fsKeysRecipient(agentB.SidecarId())); err != nil {
		t.Fatalf("the late delivery to B: %v", err)
	}
	if err := agentB.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	if held, err := agentB.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != 2 {
		t.Errorf("B does not read generation 2 by its own ReaderWrap: %v", err)
	}
	// D's DelegationRevoke with a since_n before B's admission parks B
	agentB.row.ParkedAt = world.nextPosition()
	world.RevokeDelegation(delegation)
	world.Advance()
	key, err := a.Client.EnsureWritable(world.Ctx, world.RepoId)
	if err != nil || key.Generation() != 3 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the REMOVE generation past B's park: %v", err)
	}
	if world.WrapRecipients(3)[agentB.SidecarId()] {
		t.Errorf("generation 3 is wrapped to the parked agent")
	}
	if reached := world.KeysOpenAny(fsKeysHeldKeys(agentB, delegation)); reached != 2 {
		t.Errorf("the parked agent's keys reach generation %d, not 2", reached)
	}
}
