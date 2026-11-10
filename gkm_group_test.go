//go:build !sidecar_http

// KF1 on the fake gkm (KEYS-M2-21, §22.5): a repo's group, epoch 0 and generation 1, then generation 1's deliveries
// before anything activates the repo; a kill at each step resumed from the keychain; a group id another repo owns
// drawn again; then the engine's first Add commit and its joiners' Welcome joins.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A bare world whose member holds a recovery identity and which an uncovered agent reads, so generation 1 owes a
// RecoveryWrap and a ReaderWrap.
func newGkmCreateWorld(t *testing.T, kind protocol.RepoKind) (*gkmFlowWorld, *gkmWorldDevice) {
	world := newGkmBareFlowWorld(t, kind)
	recoveryKeySha256 := sha256.Sum256([]byte("the member's recovery key"))
	recoveryKey, err := sidecar.LoadGkmDelegationKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	world.members[0].RecoveryKeySha256 = recoveryKeySha256[:]
	world.members[0].Bindings = []*bridge.RecoveryBindingRow{{KeySha256: recoveryKeySha256[:], Signer: world.a.id.Bytes(), At: 1}}
	world.recoveryKeys[world.memberId] = &sidecar.GkmRecoveryKey{XwingPublicKey: recoveryKey.PublicKey().Bytes(), BindingKeySha256: recoveryKeySha256[:]}
	agent := world.admit("agent", sidecar.NewId())
	world.grant(false, agent)
	world.stateFor()
	world.flow(agent)
	return world, agent
}

// The args KF1 takes for the world's repo.
func (self *gkmFlowWorld) createArgs() *sidecar.GkmCreateGroupArgs {
	return &sidecar.GkmCreateGroupArgs{RepoId: self.repoId, Kind: self.repo.GetKind()}
}

// CreateGroup as EvsClient.CreateRepo sequences it: the repo is activated only once CreateGroup has returned, and by
// then generation 1's recovery wrap and reader wrap stand at gkm (D-KEYS-18). Returns whether it activated.
func (self *gkmFlowWorld) createThenActivate(creator *gkmFlowDevice) (bool, error) {
	self.t.Helper()
	key, err := creator.client.CreateGroup(self.ctx, self.createArgs())
	if err != nil {
		return false, err
	}
	self.groupId = key.GroupId()
	if len(self.store.recoveryWrapPaths(self.groupId, 1)) != 1 || self.deliveryRecipients(1)["s:agent"] != sidecar.GkmDeliveryStaged {
		self.t.Errorf("the repo would activate before generation 1's wraps exist: %v", self.deliveryRecipients(1))
	}
	return true, nil
}

// KF1: the owner marker, the form, epoch 0 and gen/1 at gkm, generation 1's deliveries staged before the repo could
// activate, and the keychain holding the group's pins and RK_1 with no draft left; then the engine's first run adds
// every pending member device in one Add commit, and each joins by its Welcome.
func TestCreateGroupThenTheFirstAddCommit(t *testing.T) {
	world, _ := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	if activated, err := world.createThenActivate(a); err != nil || !activated {
		t.Fatal(err)
	}
	tip := world.log.Tip()
	groupId, epoch, generation, err := a.client.TestPins(world.repoId)
	if err != nil || groupId != world.groupId || epoch != 0 || generation != 1 {
		t.Fatalf("the creator's pins: epoch %d, generation %d, %v", epoch, generation, err)
	}
	if world.store.groupOwnerRepoIds[world.groupId] != world.repoId || len(world.store.repoForms[world.repoId]) != 1 {
		t.Errorf("no owner marker or form at gkm")
	}
	first := world.storedGeneration(tip, 1)
	if sidecar.GkmCause(first.Rotate.GetCause()) != sidecar.GkmCauseRequest || first.Rotate.GetWrapCount() != 2 || first.SignerId != world.a.id ||
		first.Rotate.GetAuth().GetVersion() != tip.Pin().GetVersion() || !bytes.Equal(first.Rotate.GetHoldersSha256(), world.holdersSha256(tip, world.clock.Now())) {
		t.Errorf("gen/1: cause %d, wrap_count %d", first.Rotate.GetCause(), first.Rotate.GetWrapCount())
	}
	if verdict := world.memberAccepts(tip, 1, nil); !verdict.Passed() {
		t.Errorf("a member's check of gen/1: %+v", verdict)
	}
	// a second call finds the group standing and answers the same key
	again, err := a.client.CreateGroup(world.ctx, world.createArgs())
	if err != nil || again.GroupId() != world.groupId || world.store.callCount("CreateGroup") != 1 {
		t.Errorf("a second CreateGroup of the repo: %v", err)
	}

	// KF2: every pending member device in one Add commit
	for _, device := range []*gkmWorldDevice{world.b, world.c, world.p, world.x} {
		world.store.publishKeyPackages(device, 1, true)
	}
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 1 || world.store.callCount("CommitEpoch") != 1 {
		t.Fatalf("the first Add commit: gkm at epoch %d after %d commits", newest, world.store.callCount("CommitEpoch"))
	}
	if labels := world.rosterLabels(world.engineGroup(world.a)); !slices.Equal(labels, []string{"a", "b", "c", "p", "x"}) {
		t.Errorf("the tree after the first Add commit: %v", labels)
	}
	if world.store.newestGeneration(world.groupId) != 1 {
		t.Errorf("a commit raised the generation")
	}
	for _, device := range []*gkmWorldDevice{world.b, world.c, world.p, world.x} {
		flow := world.flows[device]
		joined, err := flow.client.JoinWelcomes(world.ctx)
		if err != nil || !slices.Equal(joined, []sidecar.Id{world.repoId}) {
			t.Fatalf("%s joins: %v %v", device.label, joined, err)
		}
		_, epoch, generation, err := flow.client.TestPins(world.repoId)
		if err != nil || epoch != 1 || generation != 1 {
			t.Errorf("%s's pins after its join: epoch %d, generation %d, %v", device.label, epoch, generation, err)
		}
		if key, poisoned, found, err := flow.client.TestHeldGeneration(world.repoId, 1); err != nil || !found || key == nil || poisoned || !bytes.Equal(key.Commitment(), first.Rotate.GetCommitment()) {
			t.Errorf("%s's generation 1 after its join: %v %v", device.label, found, err)
		}
		// a second look takes nothing: the pointer is at the epoch it reached
		if joined, err := flow.client.JoinWelcomes(world.ctx); err != nil || len(joined) != 0 {
			t.Errorf("%s joins again: %v %v", device.label, joined, err)
		}
	}
	// nothing is pending now
	if pending, _, err := a.client.Pending(world.ctx, world.repoId); err != nil || !pending.Empty() {
		t.Errorf("pending after the first Add commit: %+v %v", pending, err)
	}
}

// A kill at each KF1 step resumes from the keychain, and at no step is the repo activated before generation 1's
// recovery wraps exist: before the POST lands, after it lands with every answer lost, and after the group stands
// but before its deliveries.
func TestCreateGroupResumesAfterAKillAtEachStep(t *testing.T) {
	cases := []struct {
		name  string
		plant func(world *gkmFlowWorld)
		// whether the group stands at gkm when the process dies
		formed bool
	}{
		{name: "before the POST", plant: func(world *gkmFlowWorld) { world.store.plantCount("CreateGroup", true, 3) }},
		{name: "after the POST, its answers lost", plant: func(world *gkmFlowWorld) { world.store.plantCount("CreateGroup", false, 3) }, formed: true},
		{name: "before generation 1's reader wraps", plant: func(world *gkmFlowWorld) { world.store.plant("UploadWraps", true) }, formed: true},
		{name: "before generation 1's recovery wraps", plant: func(world *gkmFlowWorld) { world.store.plant("UploadRecoveryWraps", true) }, formed: true},
	}
	for _, c := range cases {
		world, _ := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
		a := world.flows[world.a]
		c.plant(world)
		activated, err := world.createThenActivate(a)
		if activated || err == nil {
			t.Fatalf("%s: the killed creation activated the repo: %v", c.name, err)
		}
		if formed := len(world.store.groupOwnerRepoIds) == 1; formed != c.formed {
			t.Fatalf("%s: the group stands at gkm: %t", c.name, formed)
		}
		a.restart()
		activated, err = world.createThenActivate(a)
		if err != nil || !activated {
			t.Fatalf("%s: the resumed creation: %v", c.name, err)
		}
		// one group, the one the draft drew
		if len(world.store.groupOwnerRepoIds) != 1 || len(world.store.repoForms[world.repoId]) != 1 || world.store.newestGeneration(world.groupId) != 1 {
			t.Errorf("%s: a second group or generation after the resumed creation", c.name)
		}
		if groupId, _, generation, err := a.client.TestPins(world.repoId); err != nil || groupId != world.groupId || generation != 1 {
			t.Errorf("%s: the creator's pins after the resumed creation: %v", c.name, err)
		}
		if verdict := world.memberAccepts(world.log.Tip(), 1, nil); !verdict.Passed() {
			t.Errorf("%s: a member's check of gen/1: %+v", c.name, verdict)
		}
	}
}

// A group id another repo owns answers 409 at the owner marker: the creator draws another and forms the group
// there. A state that does not hold the repo yet, and a sidecar with no leaf, create nothing.
func TestCreateGroupDrawsAnotherIdWhenTheMarkerIsTaken(t *testing.T) {
	world, agent := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	world.store.refuseOnce("CreateGroup", http.StatusConflict)
	if activated, err := world.createThenActivate(a); err != nil || !activated {
		t.Fatal(err)
	}
	if world.store.callCount("CreateGroup") != 2 || len(world.store.groupOwnerRepoIds) != 1 {
		t.Errorf("%d creations sent, %d groups formed", world.store.callCount("CreateGroup"), len(world.store.groupOwnerRepoIds))
	}
	if groupId, _, _, err := a.client.TestPins(world.repoId); err != nil || world.store.groupOwnerRepoIds[groupId] != world.repoId {
		t.Errorf("the creator's group is not the one gkm formed")
	}

	other := newGkmBareFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	unknown := &sidecar.GkmCreateGroupArgs{RepoId: sidecar.NewId(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}
	if _, err := other.flows[other.a].client.CreateGroup(other.ctx, unknown); !errors.Is(err, sidecar.ErrGkmNoRepo) {
		t.Errorf("a creation before its RepoCreate reached the state: %v", err)
	}
	if _, err := world.flows[agent].client.CreateGroup(world.ctx, world.createArgs()); !errors.Is(err, sidecar.ErrGkmUnavailable) {
		t.Errorf("a creation by a sidecar with no leaf: %v", err)
	}
	if other.store.callCount("CreateGroup") != 0 {
		t.Errorf("a refused creation reached gkm")
	}
}

// A depositor kind's gen/1 carries its drop key from the start, and the config group's creation wraps to each
// member device among the holders, which the tree does not hold yet.
func TestCreateGroupWrapsToWrappedMembersAndCarriesADropKey(t *testing.T) {
	world, _ := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	a := world.flows[world.a]
	key, err := a.client.CreateGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	world.groupId = key.GroupId()
	recipients := world.deliveryRecipients(1)
	for _, label := range []string{"s:agent", "s:b", "s:c", "s:p", "s:x"} {
		if recipients[label] != sidecar.GkmDeliveryStaged {
			t.Errorf("the config group's generation 1 has no wrap for %s: %v", label, recipients)
		}
	}
	if rotate := world.storedGeneration(world.log.Tip(), 1).Rotate; 0 < len(rotate.GetDropPublicKey()) {
		t.Errorf("the config's gen/1 carries a drop key")
	}

	mailbox, _ := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_MAILBOX)
	mailboxKey, err := mailbox.flows[mailbox.a].client.CreateGroup(mailbox.ctx, mailbox.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	mailbox.groupId = mailboxKey.GroupId()
	rotate := mailbox.storedGeneration(mailbox.log.Tip(), 1).Rotate
	if len(rotate.GetDropPublicKey()) == 0 || rotate.GetDropNotAfterMs() != rotate.GetTimeMs()+sidecar.DefaultGkmSettings().DropKeyLifetime.Milliseconds() {
		t.Errorf("a mailbox's gen/1 carries no drop key")
	}
	// only the agent reads a data repo by a wrap at creation: its member devices wait for their Add
	if recipients := mailbox.deliveryRecipients(1); len(recipients) != 1 || recipients["s:agent"] != sidecar.GkmDeliveryStaged {
		t.Errorf("a data repo's generation 1 deliveries: %v", recipients)
	}
	encoded, _ := proto.Marshal(mailbox.store.repoForms[mailbox.repoId][0])
	if len(encoded) == 0 {
		t.Errorf("no form filed")
	}
}
