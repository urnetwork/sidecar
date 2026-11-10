//go:build !sidecar_http

// §10.5's Rotate on the fake gkm (KEYS-M2-20, DESIGN-DETAILS 6.6): each delivery kind exactly when §10.5 says, a
// leaf_wrap only on a clean tree, a wrapped writer's rotation with no leaf online, a kill before and after each step
// resumed from the keychain's draft, a 412 with a covering, a non-covering and a poisoned winner, and a depositor
// kind's drop key.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Whether gen/<g> passes a member's rotation checks at view, with the leaf_wrap's tree as reader holds it.
func (self *gkmFlowWorld) memberAccepts(view sidecar.GkmAuthView, generation uint64, reader *gkmWorldDevice) sidecar.GkmVerdict {
	self.t.Helper()
	args := &sidecar.GkmRotationCheckArgs{
		RepoId:          self.repoId,
		Generation:      self.storedGeneration(view, generation),
		DropKeyLifetime: sidecar.DefaultGkmSettings().DropKeyLifetime,
		Now:             self.clock.Now(),
	}
	if 1 < generation {
		args.Parent = self.storedGeneration(view, generation-1)
	}
	if reader != nil && reader.group != nil {
		args.LeafWrapRoster = reader.group.Roster()
	}
	verdict, err := sidecar.CheckRotation(view, args)
	if err != nil {
		self.t.Fatalf("a member's check of gen/%d: %v", generation, err)
	}
	return verdict
}

// The index of the first and the last call of a route among the store's calls, -1 for none.
func (self *gkmFakeStore) callSpan(route string) (first int, last int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	first, last = -1, -1
	for index, call := range self.calls {
		if strings.HasSuffix(call, ":"+route) {
			if first < 0 {
				first = index
			}
			last = index
		}
	}
	return first, last
}

// Each delivery kind appears exactly when §10.5 says: on a clean tree one leaf_wrap and no ReaderWrap to a leaf, a
// ReaderWrap to each uncovered agent whose ReaderKey passes, a DelegationWrap to each live Delegation and none to
// the agent it covers, and a RecoveryWrap to each member with a recovery identity; every one staged before the
// claim, and a rotation that cannot read a recovery key refused before anything is written.
func TestGkmRotateStagesEachDeliveryKindThenClaims(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	tag := sidecar.NewId()
	delegationId := sha256.Sum256([]byte("a delegation"))
	delegationKey, err := sidecar.LoadGkmDelegationKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	world.delegations = []*bridge.DelegationRow{{
		DelegationId: delegationId[:], Signer: world.a.id.Bytes(), At: 1, TagAtoms: [][]byte{tag.Bytes()},
		NotAfter:             world.now.Add(30 * 24 * time.Hour).UnixMilli(),
		ReaderXwingPublicKey: delegationKey.PublicKey().Bytes(),
	}}
	world.atomRepos[tag] = []sidecar.Id{world.repoId}
	covered := world.admit("covered", tag)
	covered.row.DelegationId = delegationId[:]
	agent := world.admit("agent", sidecar.NewId())
	lapsed := world.admit("lapsed", sidecar.NewId())
	world.grant(false, covered, agent, lapsed)
	recoveryKeySha256 := sha256.Sum256([]byte("the member's recovery key"))
	recoveryKey, err := sidecar.LoadGkmDelegationKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	world.members[0].RecoveryKeySha256 = recoveryKeySha256[:]
	world.members[0].Bindings = []*bridge.RecoveryBindingRow{{KeySha256: recoveryKeySha256[:], Signer: world.a.id.Bytes(), At: 1}}
	second := world.stateFor()
	world.holdAll()
	for _, device := range []*gkmWorldDevice{covered, agent, lapsed} {
		world.flow(device)
	}
	// its ReaderKey is not at gkm: it waits for a late delivery
	delete(world.store.readerKeys, lapsed.id)
	a := world.flows[world.a]

	if _, err := a.client.RotateRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Fatalf("a rotation with no readable recovery key: %v", err)
	}
	if world.store.newestGeneration(world.groupId) != 1 || world.store.callCount("UploadWraps") != 0 || a.client.TestHasRotateDraft(world.repoId) {
		t.Fatalf("the refused rotation wrote something")
	}

	world.recoveryKeys[world.memberId] = &sidecar.GkmRecoveryKey{XwingPublicKey: recoveryKey.PublicKey().Bytes(), BindingKeySha256: recoveryKeySha256[:]}
	key, err := a.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation() != 2 || world.store.newestGeneration(world.groupId) != 2 {
		t.Fatalf("generation %d claimed, gkm at %d", key.Generation(), world.store.newestGeneration(world.groupId))
	}
	generation := world.storedGeneration(second, 2)
	rotate := generation.Rotate
	if sidecar.GkmCause(rotate.GetCause()) != sidecar.GkmCauseRequest || rotate.GetLeafWrap() == nil || rotate.GetLeafWrap().GetEpoch() != 1 ||
		rotate.GetWrapCount() != 3 || 0 < len(rotate.GetDropPublicKey()) || !bytes.Equal(rotate.GetCommitment(), key.Commitment()) {
		t.Errorf("gen/2 as claimed: cause %d, leaf_wrap %v, wrap_count %d", rotate.GetCause(), rotate.GetLeafWrap(), rotate.GetWrapCount())
	}
	recipients := world.deliveryRecipients(2)
	want := map[string]sidecar.GkmDeliveryKind{"s:agent": sidecar.GkmDeliveryStaged, "d:delegation": sidecar.GkmDeliveryStaged}
	if len(recipients) != len(want) || recipients["s:agent"] != sidecar.GkmDeliveryStaged || recipients["d:delegation"] != sidecar.GkmDeliveryStaged {
		t.Errorf("deliveries of generation 2: %v", recipients)
	}
	if paths := world.store.recoveryWrapPaths(world.groupId, 2); len(paths) != 1 {
		t.Errorf("recovery wraps of generation 2: %v", paths)
	}
	_, lastWrap := world.store.callSpan("UploadWraps")
	_, lastRecovery := world.store.callSpan("UploadRecoveryWraps")
	firstClaim, lastClaim := world.store.callSpan("ClaimGeneration")
	if lastWrap < 0 || lastRecovery < 0 || firstClaim != lastClaim || firstClaim < lastWrap || firstClaim < lastRecovery {
		t.Errorf("a delivery staged after the claim, or a second claim")
	}
	// what the rotator keeps
	if held, poisoned, found, err := a.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || held == nil || poisoned || a.client.TestHasRotateDraft(world.repoId) {
		t.Errorf("the rotator's keychain after the claim: %v %v %v", found, poisoned, err)
	}
	if _, _, pinned, err := a.client.TestPins(world.repoId); err != nil || pinned != 2 {
		t.Errorf("the rotator's generation pin: %d %v", pinned, err)
	}
	// every member accepts it, and a leaf opens the leaf_wrap
	if verdict := world.memberAccepts(second, 2, world.b); !verdict.Passed() {
		t.Errorf("a member's check of the claim: %+v", verdict)
	}
	kek, err := sidecar.MlsKek(world.b.group, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := sidecar.OpenGkmLeafWrap(generation, kek); err != nil || !bytes.Equal(opened.Commitment(), key.Commitment()) {
		t.Errorf("a leaf opens the leaf_wrap: %v", err)
	}
}

// R5 (TestALeafWrapNeedsACleanTree): a leaf whose tree holds a dropped leaf rotates with cause REMOVE by ReaderWraps
// to every remaining leaf and no leaf_wrap; once the Remove is adopted, the next rotation is one leaf_wrap; the
// removed leaf opens neither.
func TestALeafWrapNeedsACleanTree(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a, b := world.flows[world.a], world.flows[world.b]
	world.revoke(world.x)
	second := world.stateFor()
	// what the dropped leaf can still derive: its last epoch's KEK
	staleKek, err := sidecar.MlsKek(world.x.group, world.repoId)
	if err != nil {
		t.Fatal(err)
	}

	key, err := a.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	gen2 := world.storedGeneration(second, 2)
	if key.Generation() != 2 || sidecar.GkmCause(gen2.Rotate.GetCause()) != sidecar.GkmCauseRemove || gen2.Rotate.GetLeafWrap() != nil {
		t.Fatalf("gen/2 over a dirty tree: cause %d, leaf_wrap %v", gen2.Rotate.GetCause(), gen2.Rotate.GetLeafWrap())
	}
	recipients := world.deliveryRecipients(2)
	if len(recipients) != 3 || recipients["s:b"] != sidecar.GkmDeliveryStaged || recipients["s:c"] != sidecar.GkmDeliveryStaged || recipients["s:p"] != sidecar.GkmDeliveryStaged {
		t.Errorf("deliveries of generation 2: %v", recipients)
	}
	if verdict := world.memberAccepts(second, 2, world.b); !verdict.Passed() {
		t.Errorf("a member's check of the wrapped rotation: %+v", verdict)
	}

	// a writer leaf's Remove lands, and every remaining leaf adopts it
	world.adopt(world.a, world.stage(world.a, 2, second.Pin(), nil, []*gkmWorldDevice{world.x}))
	header := gkmWorldHeader(t, 2, second.Pin())
	for _, device := range []*gkmWorldDevice{world.a, world.b, world.c, world.p} {
		if err := world.flows[device].client.TestHoldEpoch(world.repoId, device.group, header); err != nil {
			t.Fatal(err)
		}
	}
	// b takes generation 2 by its ReaderWrap, then rotates on the clean tree
	if adopted, err := b.client.RotateRepo(world.ctx, world.repoId); err != nil || adopted.Generation() != 2 || !bytes.Equal(adopted.Commitment(), key.Commitment()) {
		t.Fatalf("b takes generation 2 by its wrap: %v %v", adopted, err)
	}
	if world.store.newestGeneration(world.groupId) != 2 {
		t.Fatalf("b claimed a generation while taking the winner")
	}
	next, err := b.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	gen3 := world.storedGeneration(second, 3)
	if next.Generation() != 3 || gen3.Rotate.GetLeafWrap() == nil || gen3.Rotate.GetLeafWrap().GetEpoch() != 2 || gen3.Rotate.GetWrapCount() != 0 || len(world.deliveryRecipients(3)) != 0 {
		t.Errorf("gen/3 over the clean tree: leaf_wrap %v, wrap_count %d, deliveries %v", gen3.Rotate.GetLeafWrap(), gen3.Rotate.GetWrapCount(), world.deliveryRecipients(3))
	}
	if verdict := world.memberAccepts(second, 3, world.c); !verdict.Passed() {
		t.Errorf("a member's check of the leaf-wrapped rotation: %+v", verdict)
	}
	// the removed leaf: no wrap of generation 2, and epoch 1's KEK does not open generation 3's leaf_wrap
	if _, toRemoved := recipients["s:x"]; toRemoved {
		t.Errorf("a delivery of generation 2 to the removed leaf")
	}
	if _, err := sidecar.OpenGkmLeafWrap(gen3, staleKek); err == nil {
		t.Errorf("the removed leaf opened generation 3's leaf_wrap")
	}
}

// A wrapped writer rotates with no leaf online (owner decision 114): an agent that writes the repo, holding no leaf,
// rotates for a revocation by ReaderWraps to every remaining member device, with no leaf_wrap, and members accept it.
func TestAWrappedWriterRotatesWithNoLeafOnline(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	agent := world.admit("agent", sidecar.NewId())
	world.grant(true, agent)
	world.stateFor()
	world.holdAll()
	wrapped := world.hold(agent, world.gen1)
	world.revoke(world.x)
	third := world.stateFor()

	key, err := wrapped.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	gen2 := world.storedGeneration(third, 2)
	if key.Generation() != 2 || sidecar.GkmCause(gen2.Rotate.GetCause()) != sidecar.GkmCauseRemove || gen2.Rotate.GetLeafWrap() != nil || gen2.SignerId != agent.id {
		t.Fatalf("the wrapped writer's gen/2: cause %d, leaf_wrap %v", gen2.Rotate.GetCause(), gen2.Rotate.GetLeafWrap())
	}
	recipients := world.deliveryRecipients(2)
	if len(recipients) != 4 || recipients["s:a"] == 0 || recipients["s:b"] == 0 || recipients["s:c"] == 0 || recipients["s:p"] == 0 {
		t.Errorf("deliveries of generation 2: %v", recipients)
	}
	if verdict := world.memberAccepts(third, 2, world.a); !verdict.Passed() {
		t.Errorf("a member's check of the wrapped writer's rotation: %+v", verdict)
	}
}

// read_only signs no rotation, and neither does a reader that does not write: nothing is drafted, staged or claimed.
func TestAReadOnlyDeviceAndAReaderSignNoRotation(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.grant(true, world.p)
	world.stateFor()
	world.holdAll()
	for _, device := range []*gkmWorldDevice{world.p, world.c} {
		flow := world.flows[device]
		if _, err := flow.client.RotateRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmNotWriter) {
			t.Errorf("%s rotates: %v", device.label, err)
		}
		if flow.client.TestHasRotateDraft(world.repoId) {
			t.Errorf("%s kept a draft", device.label)
		}
	}
	if world.store.newestGeneration(world.groupId) != 1 || world.store.callCount("UploadWraps") != 0 || world.store.callCount("ClaimGeneration") != 0 {
		t.Errorf("a refused rotation reached gkm")
	}
}

// R2 (TestARotationsClaimNeverFallsBelowItsParent's client half): a rotator whose state is below the pin of the
// generation it holds refuses to claim, and claims once the log reaches it.
func TestARotatorAtAStaleTipRefusesToClaim(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a, b := world.flows[world.a], world.flows[world.b]
	second := world.stateFor(world.b)
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	// b holds generation 2, claimed at a pin its own log has not reached
	gen2 := world.storedGeneration(second, 2)
	kek, err := sidecar.MlsKek(world.b.group, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := sidecar.OpenGkmLeafWrap(gen2, kek)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.client.TestHoldGeneration(world.repoId, world.groupId, gen2, key2); err != nil {
		t.Fatal(err)
	}
	claimCount := world.store.callCount("ClaimGeneration")
	if _, err := b.client.RotateRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a rotation from a generation above this state: %v", err)
	}
	if world.store.callCount("ClaimGeneration") != claimCount || b.client.TestHasRotateDraft(world.repoId) {
		t.Errorf("the stale rotator drafted or claimed")
	}
	b.client.AuthAdvanced(second)
	if key, err := b.client.RotateRepo(world.ctx, world.repoId); err != nil || key.Generation() != 3 {
		t.Errorf("the same rotation once the log reaches the pin: %v %v", key, err)
	}
	if auth := world.storedGeneration(second, 3).Rotate.GetAuth(); auth.GetVersion() < gen2.Rotate.GetAuth().GetVersion() {
		t.Errorf("gen/3's pin %d below gen/2's %d", auth.GetVersion(), gen2.Rotate.GetAuth().GetVersion())
	}
}

// A kill before and after each step resumes from the keychain's draft: before any delivery is staged, after staging
// and before the claim, and after the claim landed with its answer lost. Each resumed rotation claims with the same
// RK', so every delivery sits under one commitment and no second generation is claimed.
func TestGkmRotateResumesFromItsDraftAfterAKill(t *testing.T) {
	cases := []struct {
		name string
		// plants the kill
		plant func(world *gkmFlowWorld)
		// what gkm holds when the process dies
		generation uint64
		wrapCount  int
	}{
		{
			name:       "before staging",
			plant:      func(world *gkmFlowWorld) { world.store.plant("UploadWraps", true) },
			generation: 1,
			wrapCount:  0,
		},
		{
			name: "after staging, before the claim",
			plant: func(world *gkmFlowWorld) {
				world.store.plantHook("a", "ClaimGeneration", func() { world.store.plant("Generations", true) })
				world.store.plant("ClaimGeneration", true)
			},
			generation: 1,
			wrapCount:  3,
		},
		{
			name: "after the claim, its answer lost",
			plant: func(world *gkmFlowWorld) {
				world.store.plantHook("a", "ClaimGeneration", func() { world.store.plant("Generations", true) })
				world.store.plant("ClaimGeneration", false)
			},
			generation: 2,
			wrapCount:  3,
		},
	}
	for _, c := range cases {
		world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
		world.holdAll()
		a := world.flows[world.a]
		world.revoke(world.x)
		second := world.stateFor()
		c.plant(world)
		if _, err := a.client.RotateRepo(world.ctx, world.repoId); !errors.Is(err, errGkmFakeFault) {
			t.Fatalf("%s: the killed rotation: %v", c.name, err)
		}
		if !a.client.TestHasRotateDraft(world.repoId) {
			t.Fatalf("%s: no draft in the keychain at the kill", c.name)
		}
		if _, _, found, _ := a.client.TestHeldGeneration(world.repoId, 2); found {
			t.Fatalf("%s: generation 2 held before its claim was known", c.name)
		}
		if world.store.newestGeneration(world.groupId) != c.generation || len(world.store.wrapPaths(world.groupId, 2)) != c.wrapCount {
			t.Fatalf("%s: gkm at the kill: generation %d, %d wraps", c.name, world.store.newestGeneration(world.groupId), len(world.store.wrapPaths(world.groupId, 2)))
		}
		// a new process over the same keychain
		a.restart()
		key, err := a.client.RotateRepo(world.ctx, world.repoId)
		if err != nil {
			t.Fatalf("%s: the resumed rotation: %v", c.name, err)
		}
		gen2 := world.storedGeneration(second, 2)
		if key.Generation() != 2 || !bytes.Equal(gen2.Rotate.GetCommitment(), key.Commitment()) || world.store.newestGeneration(world.groupId) != 2 {
			t.Errorf("%s: the resumed rotation ended at generation %d, gkm at %d", c.name, key.Generation(), world.store.newestGeneration(world.groupId))
		}
		// one RK': every delivery under one commitment, each recipient once
		if paths := world.store.wrapPaths(world.groupId, 2); len(paths) != 3 || len(world.deliveryRecipients(2)) != 3 {
			t.Errorf("%s: deliveries after the resumed rotation: %v", c.name, paths)
		}
		if a.client.TestHasRotateDraft(world.repoId) {
			t.Errorf("%s: the draft outlived its claim", c.name)
		}
		if held, _, found, err := a.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || held == nil {
			t.Errorf("%s: the rotator's keychain after the resumed rotation: %v %v", c.name, found, err)
		}
		if verdict := world.memberAccepts(second, 2, world.b); !verdict.Passed() {
			t.Errorf("%s: a member's check of the resumed claim: %+v", c.name, verdict)
		}
	}
}

// A lost answer with the process alive: the claim's outcome is read back from gen/, this device's commitment there
// being a 201, and nothing there meaning the same bytes go again.
func TestGkmRotateResolvesAnUnknownClaimFromGen(t *testing.T) {
	for _, landed := range []bool{true, false} {
		world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
		world.holdAll()
		a := world.flows[world.a]
		world.store.plant("ClaimGeneration", !landed)
		key, err := a.client.RotateRepo(world.ctx, world.repoId)
		if err != nil || key.Generation() != 2 || world.store.newestGeneration(world.groupId) != 2 {
			t.Fatalf("landed %t: %v %v", landed, key, err)
		}
		wantClaims := 1
		if !landed {
			wantClaims = 2
		}
		if world.store.callCount("ClaimGeneration") != wantClaims || a.client.TestHasRotateDraft(world.repoId) {
			t.Errorf("landed %t: %d claims", landed, world.store.callCount("ClaimGeneration"))
		}
	}
}

// 412 with a covering winner: two writers rotate for one revocation, the loser judges the winner, opens it by its
// ReaderWrap and adopts it, claiming nothing more.
func TestGkmRotateAdoptsAWinnerThatCoversItsShrink(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a, b := world.flows[world.a], world.flows[world.b]
	world.revoke(world.x)
	second := world.stateFor()
	var winnerKey *sidecar.EvsRepoKey
	world.store.plantHook("b", "ClaimGeneration", func() {
		key, err := a.client.RotateRepo(world.ctx, world.repoId)
		if err != nil {
			t.Errorf("the winner's rotation: %v", err)
		}
		winnerKey = key
	})
	key, err := b.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if winnerKey == nil || key.Generation() != 2 || !bytes.Equal(key.Commitment(), winnerKey.Commitment()) {
		t.Fatalf("the loser's key: generation %d", key.Generation())
	}
	if world.store.newestGeneration(world.groupId) != 2 || b.client.TestHasRotateDraft(world.repoId) || len(b.alarms) != 0 {
		t.Errorf("the loser claimed again, kept its draft or alarmed: gkm at %d, alarms %v", world.store.newestGeneration(world.groupId), b.alarms)
	}
	if gen2 := world.storedGeneration(second, 2); gen2.SignerId != world.a.id {
		t.Errorf("gen/2 is not the winner's")
	}
	if held, poisoned, found, err := b.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || held == nil || poisoned {
		t.Errorf("the loser's keychain: %v %v %v", found, poisoned, err)
	}
}

// 412 with a winner that does not cover (D-KEYS-15): the loser rotates for a revocation its state shows, the winner
// claimed at a state before it. The loser judges and holds the winner, never returns it as the generation to seal
// to, and claims g+2 with cause REMOVE.
func TestGkmRotateStartsOverPastAWinnerThatDoesNotCover(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a, b := world.flows[world.a], world.flows[world.b]
	world.revoke(world.x)
	// a's log has not reached the revocation
	second := world.stateFor(world.a)
	world.store.plantHook("b", "ClaimGeneration", func() {
		if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
			t.Errorf("the winner's rotation: %v", err)
		}
	})
	key, err := b.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	gen2, gen3 := world.storedGeneration(second, 2), world.storedGeneration(second, 3)
	if gen2.SignerId != world.a.id || gen2.Rotate.GetAuth().GetVersion() != 1 || sidecar.GkmCause(gen2.Rotate.GetCause()) != sidecar.GkmCauseRequest {
		t.Fatalf("gen/2 is not the stale winner's")
	}
	if key.Generation() != 3 || gen3.SignerId != world.b.id || sidecar.GkmCause(gen3.Rotate.GetCause()) != sidecar.GkmCauseRemove ||
		!bytes.Equal(gen3.Rotate.GetParentCommitment(), gen2.Rotate.GetCommitment()) || gen3.Rotate.GetAuth().GetVersion() != 2 {
		t.Errorf("the loser's second claim: generation %d, cause %d, pin %d", key.Generation(), gen3.Rotate.GetCause(), gen3.Rotate.GetAuth().GetVersion())
	}
	// the winner is held, for the ladder, and is no poison
	if held, poisoned, found, err := b.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || held == nil || poisoned {
		t.Errorf("the loser's record of the winner: %v %v %v", found, poisoned, err)
	}
	if len(b.alarms) != 0 {
		t.Errorf("a valid winner alarmed: %v", b.alarms)
	}
	// generation 3 excludes the revoked leaf: ReaderWraps to the remaining leaves, none to x
	recipients := world.deliveryRecipients(3)
	if _, toRevoked := recipients["s:x"]; toRevoked || len(recipients) != 3 || gen3.Rotate.GetLeafWrap() != nil {
		t.Errorf("deliveries of generation 3: %v", recipients)
	}
	for _, generation := range []uint64{2, 3} {
		if verdict := world.memberAccepts(second, generation, world.c); !verdict.Passed() {
			t.Errorf("a member's check of gen/%d: %+v", generation, verdict)
		}
	}
}

// 412 with a winner that fails the rotation checks: the loser alarms refused naming its signer, holds the generation
// as poisoned and never returns it, and rotates at once on top of it with cause REMOVE.
func TestGkmRotatePoisonsAWinnerThatFailsItsChecks(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	b := world.flows[world.b]
	second := world.stateFor()
	// c reads and does not write: its claim is no writer's
	bad := world.generation(second, world.c, world.gen1, sidecar.GkmCauseRequest, nil)
	world.store.plantHook("b", "ClaimGeneration", func() {
		world.store.groupGenerations[world.groupId] = append(world.store.groupGenerations[world.groupId], bad.signed)
		// its staged delivery to b, at b's current ReaderKey
		checked, err := sidecar.GkmAdmittedReaderKey(second, world.store.readerKeys[world.b.id], world.b.id, world.now.UnixMilli())
		if err != nil {
			t.Fatal(err)
		}
		delivery := world.deliveryTo(second, world.c, bad, sidecar.GkmWrapTypeReader, world.b.id.Bytes(), checked.Body.GetXwingPublicKey(), sidecar.GkmDeliveryStaged, nil, time.Time{})
		path, err := sidecar.GkmDeliveryPath(world.groupId, delivery)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(delivery.Signed)
		world.store.pathWraps[path] = encoded
	})
	key, err := b.client.RotateRepo(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	gen3 := world.storedGeneration(second, 3)
	if key.Generation() != 3 || sidecar.GkmCause(gen3.Rotate.GetCause()) != sidecar.GkmCauseRemove || !bytes.Equal(gen3.Rotate.GetParentCommitment(), bad.rotate.GetCommitment()) {
		t.Errorf("the rotation past the poisoned generation: generation %d, cause %d", key.Generation(), gen3.Rotate.GetCause())
	}
	if _, poisoned, found, err := b.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || !poisoned {
		t.Errorf("the poisoned generation as held: %v %v %v", found, poisoned, err)
	}
	if len(b.alarms) != 1 || b.alarms[0].Kind != sidecar.GkmAlarmRefused || b.alarms[0].Generation != 2 || b.alarms[0].SidecarId != world.c.id || b.alarms[0].Reason != sidecar.GkmRefusalSigner {
		t.Errorf("the alarm: %+v", b.alarms)
	}
	// a member that judges gen/3 with its parent known as poisoned accepts the REMOVE
	verdict, err := sidecar.CheckRotation(second, &sidecar.GkmRotationCheckArgs{
		RepoId: world.repoId, Generation: gen3, Parent: bad.generation, ParentPoisoned: true,
		DropKeyLifetime: sidecar.DefaultGkmSettings().DropKeyLifetime, Now: world.clock.Now(),
	})
	if err != nil || !verdict.Passed() {
		t.Errorf("a member's check of the rotation past the poison: %+v %v", verdict, err)
	}
}

// A depositor kind's GenRotate carries a drop key that lives DropKeyLifetime, and a general repo's none.
func TestGkmRotateCarriesADropKeyOnlyForAKindThatTakesDeposits(t *testing.T) {
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_GENERAL} {
		world := newGkmFlowWorld(t, kind)
		world.holdAll()
		a := world.flows[world.a]
		if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		rotate := world.storedGeneration(world.first, 2).Rotate
		lifetime := sidecar.DefaultGkmSettings().DropKeyLifetime
		if sidecar.GkmRepoKindTakesDeposits(kind) {
			if len(rotate.GetDropPublicKey()) == 0 || rotate.GetDropNotAfterMs() != rotate.GetTimeMs()+lifetime.Milliseconds() {
				t.Errorf("%s: drop key of %d bytes until %d", kind, len(rotate.GetDropPublicKey()), rotate.GetDropNotAfterMs())
			}
		} else if 0 < len(rotate.GetDropPublicKey()) || rotate.GetDropNotAfterMs() != 0 {
			t.Errorf("%s: a drop key on a kind that takes no deposits", kind)
		}
		if verdict := world.memberAccepts(world.first, 2, world.b); !verdict.Passed() {
			t.Errorf("%s: a member's check: %+v", kind, verdict)
		}
	}
	if slices.ContainsFunc([]protocol.RepoKind{protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_DIRECTORY, protocol.RepoKind_REPO_KIND_RECORD}, sidecar.GkmRepoKindTakesDeposits) {
		t.Errorf("a kind that takes no deposits carries a drop key")
	}
}
