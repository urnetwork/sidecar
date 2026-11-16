//go:build !sidecar_http

// The group flows when the lb answers in gkm's place (QD-876): a 502 or a 504 is no answer of gkm's, so KF7's
// fallback is taken as with gkm stopped, and a write the lb answered so is resolved as after a lost answer, never
// judged refused, whether or not a block applied it before it died. On the fake gkm, whose planted lb answers go
// through GkmApi's own answer mapping (gkm_fake_service_test.go's gkmFakeLbAnswer).

package sidecar_test

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The lb's two answers of its own.
var gkmLbStatuses = []int{http.StatusBadGateway, http.StatusGatewayTimeout}

// KF7 with the lb answering every call 502 or 504, gkm's blocks gone behind it: cached keys serve reads, a writer
// goes on sealing while its newest generation covers its state, and a removal still blocks writes; catch-up waits,
// nothing alarms, and everything resumes when gkm answers again.
func TestWithTheLbAnsweringForGkmReadsGoOnAndARemovalStillBlocksWrites(t *testing.T) {
	for _, status := range gkmLbStatuses {
		world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
		a := world.flows[world.a]
		b := world.flows[world.b]
		if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
		if _, err := b.client.EnsureWritable(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
		world.store.setLb(status)

		if key, err := b.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
			t.Errorf("%d: a read's newest key: %v", status, err)
		}
		if key, err := b.client.RepoKey(world.ctx, world.repoId, 1); err != nil || key.Generation() != 1 {
			t.Errorf("%d: an older generation: %v", status, err)
		}
		asked := world.store.callCount("Generations")
		if key, err := b.client.EnsureWritable(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
			t.Errorf("%d: a write with every shrink covered: %v", status, err)
		}
		if world.store.callCount("Generations") == asked {
			t.Errorf("%d: the write never asked gkm", status)
		}
		if err := b.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmNoAnswer) {
			t.Errorf("%d: catch-up did not wait for gkm: %v", status, err)
		}
		world.revoke(world.x)
		world.stateFor()
		if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
			t.Fatalf("%d: a write past a removal: %v", status, err)
		}
		if key, err := b.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
			t.Errorf("%d: a read past a removal: %v", status, err)
		}

		world.store.setLb(0)
		key, err := b.client.EnsureWritable(world.ctx, world.repoId)
		if err != nil || key.Generation() != 3 || key.Cause() != sidecar.GkmCauseRemove {
			t.Errorf("%d: the write once gkm answers: %v", status, err)
		}
		if len(b.alarms) != 0 {
			t.Errorf("%d: the lb's answer alarmed: %+v", status, b.alarms[0])
		}
	}
}

// The contrast KF7 rests on: gkm's own refusal of the same read is no fallback. A 403 at gen/ fails the write, where
// the lb's 502 at the same call lets it go on with what the keychain holds.
func TestAGkmRefusalIsNoFallbackWhereTheLbsAnswerIs(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	b := world.flows[world.b]
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	world.store.refuseOnce("Generations", http.StatusForbidden)
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !sidecar.IsGkmStatus(err, http.StatusForbidden) {
		t.Fatalf("a write gkm refused at gen/: %v", err)
	}
	world.store.plantLb("Generations", http.StatusBadGateway, true)
	if key, err := b.client.EnsureWritable(world.ctx, world.repoId); err != nil || key.Generation() != 1 {
		t.Errorf("a write the lb answered at gen/: %v", err)
	}
}

// KF7's deposits with the lb answering for gkm: the newest GenRotate the depositor holds answers while it covers its
// state, stops at the first removal its state shows, and a depositor that holds nothing has nothing to answer with.
func TestADepositorSealsOnWhatItHoldsWhileTheLbAnswersForGkm(t *testing.T) {
	for _, status := range gkmLbStatuses {
		world, depositor := newGkmDropWorld(t)
		if _, err := depositor.client.DropKey(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
		world.store.setLb(status)
		dropKey, err := depositor.client.DropKey(world.ctx, world.repoId)
		if err != nil || dropKey.Generation != 2 {
			t.Fatalf("%d: a deposit: %v", status, err)
		}
		world.revoke(world.x)
		world.stateFor()
		if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
			t.Errorf("%d: a deposit past a removal: %v", status, err)
		}
		fresh := world.flow(world.admit("fresh", sidecar.NewId()))
		world.stateFor()
		if _, err := fresh.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmUnavailable) {
			t.Errorf("%d: a first deposit: %v", status, err)
		}
	}
}

// A claim the lb answered 502 or 504: its outcome is read back from gen/, as after a lost answer. Where a block
// applied it before it died, this device's commitment stands there and the claim resolves as applied, with no second
// claim; where neither of the lb's tries reached a block, nothing stands there and the same bytes go again. Never
// judged refused: the rotation ends at generation 2 either way, its draft gone.
func TestAClaimTheLbAnsweredResolvesFromGen(t *testing.T) {
	for _, status := range gkmLbStatuses {
		for _, applied := range []bool{true, false} {
			world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
			world.holdAll()
			a := world.flows[world.a]
			world.store.plantLb("ClaimGeneration", status, !applied)
			key, err := a.client.RotateRepo(world.ctx, world.repoId)
			if err != nil || key.Generation() != 2 || world.store.newestGeneration(world.groupId) != 2 {
				t.Fatalf("%d, applied %t: %v %v", status, applied, key, err)
			}
			wantClaims := 1
			if !applied {
				wantClaims = 2
			}
			if world.store.callCount("ClaimGeneration") != wantClaims || a.client.TestHasRotateDraft(world.repoId) {
				t.Errorf("%d, applied %t: %d claims", status, applied, world.store.callCount("ClaimGeneration"))
			}
			if held, _, found, err := a.client.TestHeldGeneration(world.repoId, 2); err != nil || !found || held == nil {
				t.Errorf("%d, applied %t: the rotator's keychain: %v %v", status, applied, found, err)
			}
			if len(a.alarms) != 0 {
				t.Errorf("%d, applied %t: the lb's answer alarmed: %+v", status, applied, a.alarms[0])
			}
		}
	}
}

// A commit the lb answered 502 or 504: what stands at epoch/<n> says what happened. Where a block applied it, this
// device's own commit stands there and it adopts it, writes its Welcome and sends no second commit; where no block
// took it, the same bytes go again. The joiner joins by the one Welcome either way.
func TestACommitTheLbAnsweredResolvesFromEpochs(t *testing.T) {
	for _, status := range gkmLbStatuses {
		for _, applied := range []bool{true, false} {
			world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
			b := world.flows[world.b]
			d := world.admitReader("d", 2)
			world.stateFor()
			world.store.plantLb("CommitEpoch", status, !applied)
			if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
				t.Fatalf("%d, applied %t: the run: %v", status, applied, err)
			}
			wantCommits := 1
			if !applied {
				wantCommits = 2
			}
			if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.callCount("CommitEpoch") != wantCommits {
				t.Fatalf("%d, applied %t: gkm at epoch %d after %d commits", status, applied, newest, world.store.callCount("CommitEpoch"))
			}
			if _, epoch, _, err := b.client.TestPins(world.repoId); err != nil || epoch != 2 {
				t.Errorf("%d, applied %t: the committer's epoch pin %d: %v", status, applied, epoch, err)
			}
			if labels := world.rosterLabels(world.engineGroup(world.b)); !slices.Contains(labels, "d") {
				t.Errorf("%d, applied %t: the committer's tree: %v", status, applied, labels)
			}
			if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{2}) {
				t.Errorf("%d, applied %t: d's Welcome pointers: %v", status, applied, epochs)
			}
			if joined, err := world.flows[d].client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
				t.Errorf("%d, applied %t: d joins: %v %v", status, applied, joined, err)
			}
			if len(b.alarms) != 0 {
				t.Errorf("%d, applied %t: the lb's answer alarmed: %+v", status, applied, b.alarms[0])
			}
		}
	}
}

// A group's creation the lb answered 502 or 504 after a block wrote it: every write of the request is an
// If-None-Match create that equal bytes resume, so it goes again and the one group stands, activated, where gkm's own
// refusal would have ended the creation.
func TestACreationTheLbAnsweredGoesAgainWithItsBytes(t *testing.T) {
	for _, status := range gkmLbStatuses {
		for _, applied := range []bool{true, false} {
			world, _ := newGkmCreateWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
			a := world.flows[world.a]
			world.store.plantLb("CreateGroup", status, !applied)
			activated, err := world.createThenActivate(a)
			if err != nil || !activated {
				t.Fatalf("%d, applied %t: the creation: %v", status, applied, err)
			}
			if world.store.callCount("CreateGroup") != 2 || len(world.store.groupOwnerRepoIds) != 1 || len(world.store.repoForms[world.repoId]) != 1 || world.store.newestGeneration(world.groupId) != 1 {
				t.Errorf("%d, applied %t: %d creations sent, %d groups formed", status, applied, world.store.callCount("CreateGroup"), len(world.store.groupOwnerRepoIds))
			}
		}
	}
}
