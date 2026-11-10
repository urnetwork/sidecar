// §10.9's rotation checks on fixtures (KEYS-M2-19, DESIGN-DETAILS 6.6): one success and one refusal per row,
// covered and read_only signers, the claim chain's floors, and a future time that waits rather than poisons.

package sidecar_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// CheckRotation of generation after parent, as a member judges it at view.
func (self *gkmCommitWorld) checkRotation(view sidecar.GkmAuthView, generation *gkmWorldGeneration, parent *gkmWorldGeneration, edit func(args *sidecar.GkmRotationCheckArgs)) (sidecar.GkmVerdict, error) {
	args := &sidecar.GkmRotationCheckArgs{
		RepoId:          self.repoId,
		Generation:      generation.generation,
		DropKeyLifetime: sidecar.DefaultGkmSettings().DropKeyLifetime,
		Now:             self.now,
	}
	if parent != nil {
		args.Parent = parent.generation
	}
	if edit != nil {
		edit(args)
	}
	return sidecar.CheckRotation(view, args)
}

// Fails unless the rotation passes.
func (self *gkmCommitWorld) expectRotation(label string, view sidecar.GkmAuthView, generation *gkmWorldGeneration, parent *gkmWorldGeneration) {
	self.t.Helper()
	verdict, err := self.checkRotation(view, generation, parent, nil)
	if err != nil || !verdict.Passed() {
		self.t.Errorf("%s: %+v %v", label, verdict, err)
	}
}

// Fails unless the rotation is refused for reason, poisoning its own generation.
func (self *gkmCommitWorld) expectPoisoned(label string, view sidecar.GkmAuthView, generation *gkmWorldGeneration, parent *gkmWorldGeneration, reason sidecar.GkmRefusalReason) {
	self.t.Helper()
	verdict, err := self.checkRotation(view, generation, parent, nil)
	if err != nil || !verdict.Refused || verdict.Reason != reason || verdict.Poisoned != generation.rotate.GetGeneration() {
		self.t.Errorf("%s: %+v %v, want refused for %s", label, verdict, err, reason)
	}
}

// The signer row: a writer that holds the key rotates; a reader that does not write, a read_only device, a revoked
// one and an agent that no longer reads do not; an agent a live Delegation covers does.
func TestCheckRotationSignerRow(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.expectRotation("gen/1 by the creator", world.first, world.gen1, nil)

	tag := sidecar.NewId()
	delegationId := sha256.Sum256([]byte("a delegation"))
	world.delegations = []*bridge.DelegationRow{{
		DelegationId: delegationId[:], Signer: world.a.id.Bytes(), At: 1, TagAtoms: [][]byte{tag.Bytes()},
		NotAfter: world.now.Add(30 * 24 * time.Hour).UnixMilli(),
	}}
	world.atomRepos[tag] = []sidecar.Id{world.repoId}
	covered := world.admit("covered agent", tag)
	covered.row.DelegationId = delegationId[:]
	gone := world.admit("agent that stopped reading", tag)
	gone.row.DelegationId = delegationId[:]
	world.grant(true, covered, world.p)
	second := world.state()

	world.expectRotation("a writer leaf", second, world.generation(second, world.b, world.gen1, sidecar.GkmCauseRequest, nil), world.gen1)
	world.expectRotation("a covered agent that writes", second, world.generation(second, covered, world.gen1, sidecar.GkmCauseRequest, nil), world.gen1)
	world.expectPoisoned("a reader that does not write", second, world.generation(second, world.c, world.gen1, sidecar.GkmCauseRequest, nil), world.gen1, sidecar.GkmRefusalSigner)
	world.expectPoisoned("a read_only writer", second, world.generation(second, world.p, world.gen1, sidecar.GkmCauseRequest, nil), world.gen1, sidecar.GkmRefusalSigner)
	world.expectPoisoned("an agent that reads nothing", second, world.generation(second, gone, world.gen1, sidecar.GkmCauseRequest, nil), world.gen1, sidecar.GkmRefusalSigner)

	world.revoke(world.b)
	third := world.state()
	world.expectPoisoned("a revoked signer", third, world.generation(third, world.b, world.gen1, sidecar.GkmCauseRemove, nil), world.gen1, sidecar.GkmRefusalSigner)
	// judged at its own pin: b's rotation before its revocation still stands at the later tip
	world.expectRotation("a rotation signed before its signer's revocation", third, world.generation(second, world.b, world.gen1, sidecar.GkmCauseRequest, nil), world.gen1)
}

// The chain, holders and cause rows: a parent that does not chain, a holders hash this state does not recompute, a
// REQUEST over a shrink and a REMOVE at gen/1 are refused; a REMOVE over the shrink, and one the state does not
// require, pass.
func TestCheckRotationChainHoldersAndCauseRows(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	otherFirst := world.generation(world.first, world.a, nil, sidecar.GkmCauseRequest, nil)
	second := world.state()
	gen2 := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	world.expectPoisoned("a parent it does not chain on", second, gen2, otherFirst, sidecar.GkmRefusalChain)
	world.expectPoisoned("another holders hash", second, world.generation(second, world.a, world.gen1, sidecar.GkmCauseRequest, func(args *sidecar.GkmGenerationArgs) {
		args.HoldersSha256 = make([]byte, 32)
	}), world.gen1, sidecar.GkmRefusalHolders)
	world.expectRotation("a REMOVE the state does not require", second, world.generation(second, world.a, world.gen1, sidecar.GkmCauseRemove, nil), world.gen1)
	world.expectPoisoned("gen/1 with cause REMOVE", second, world.generation(second, world.a, nil, sidecar.GkmCauseRemove, nil), nil, sidecar.GkmRefusalCause)

	world.revoke(world.x)
	third := world.state()
	world.expectPoisoned("a REQUEST over a shrink", third, world.generation(third, world.a, world.gen1, sidecar.GkmCauseRequest, nil), world.gen1, sidecar.GkmRefusalCause)
	world.expectPoisoned("a SCHEDULE over a shrink", third, world.generation(third, world.a, world.gen1, sidecar.GkmCauseSchedule, nil), world.gen1, sidecar.GkmRefusalCause)
	world.expectRotation("a REMOVE over the shrink", third, world.generation(third, world.a, world.gen1, sidecar.GkmCauseRemove, nil), world.gen1)
	verdict, err := world.checkRotation(third, world.generation(third, world.a, world.gen1, sidecar.GkmCauseRequest, nil), world.gen1, func(args *sidecar.GkmRotationCheckArgs) {
		args.RepoId = sidecar.NewId()
	})
	if err != nil || verdict.Reason != sidecar.GkmRefusalChain {
		t.Errorf("gen/<g> of another repo: %+v %v", verdict, err)
	}
	// a poisoned parent requires REMOVE whatever the state shows
	poisonedParent, err := world.checkRotation(second, gen2, world.gen1, func(args *sidecar.GkmRotationCheckArgs) {
		args.ParentPoisoned = true
	})
	if err != nil || poisonedParent.Reason != sidecar.GkmRefusalCause {
		t.Errorf("a REQUEST after a poisoned parent: %+v %v", poisonedParent, err)
	}
}

// R2 and the time row (TestARotationsClaimNeverFallsBelowItsParent's member half): a claim whose auth pin or time
// is below its parent's is refused; a time past this clock and its 60 s waits and poisons nothing; a pin above the
// tip waits, one off the chain is a fork, one before what is retained is not judged.
func TestCheckRotationFloorsTimeAndPins(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	second := world.state()
	third := world.state()
	gen2 := world.generation(third, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	world.expectRotation("gen/2 at the tip", third, gen2, world.gen1)
	world.expectPoisoned("a claim whose pin is below its parent's", third, world.generation(second, world.a, gen2, sidecar.GkmCauseRequest, nil), gen2, sidecar.GkmRefusalPinFloor)
	world.expectPoisoned("a claim whose time is before its parent's", third, world.generation(third, world.a, gen2, sidecar.GkmCauseRequest, func(args *sidecar.GkmGenerationArgs) {
		args.Time = world.now.Add(-time.Second)
	}), gen2, sidecar.GkmRefusalTime)

	ahead := world.generation(third, world.a, gen2, sidecar.GkmCauseRequest, func(args *sidecar.GkmGenerationArgs) {
		args.Time = world.now.Add(sidecar.GkmMemberClockSkew + time.Millisecond)
		args.HoldersSha256 = world.holdersSha256(third, args.Time)
	})
	if verdict, err := world.checkRotation(third, ahead, gen2, nil); !errors.Is(err, sidecar.ErrGkmTimeAhead) || verdict.Refused || verdict.Poisoned != 0 {
		t.Errorf("a time past this clock's skew: %+v %v", verdict, err)
	}
	world.now = world.now.Add(time.Millisecond)
	world.expectRotation("the same claim once the clock reaches it", third, ahead, gen2)

	if _, err := world.checkRotation(second, gen2, world.gen1, nil); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a pin above the tip: %v", err)
	}
	forked := world.generation(third, world.a, world.gen1, sidecar.GkmCauseRequest, func(args *sidecar.GkmGenerationArgs) {
		args.Auth = sidecartest.FakeGkmForkPin(2)
	})
	if verdict, err := world.checkRotation(third, forked, world.gen1, nil); err != nil || !verdict.Fork || verdict.Poisoned != 2 {
		t.Errorf("a pin off the chain: %+v %v", verdict, err)
	}
	world.log.Retain(2)
	if verdict, err := world.checkRotation(third, world.gen1, nil, nil); err != nil || !verdict.NotJudged || verdict.Refused {
		t.Errorf("a pin before what is retained: %+v %v", verdict, err)
	}
}

// The drop key's life (plan-KEYS-drop-key-lifetime), R5's leaf_wrap condition, and the poisoned row: a drop key past
// DropKeyLifetime plus 10 minutes, a leaf_wrap under an epoch whose tree holds a non-holder, and a staged delivery
// to a non-holder each poison the generation.
func TestCheckRotationDropKeyLeafWrapAndStagedDeliveries(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_MAILBOX)
	lifetime := sidecar.DefaultGkmSettings().DropKeyLifetime
	world.revoke(world.x)
	second := world.state()
	withDrop := func(notAfter time.Time) *gkmWorldGeneration {
		return world.generation(second, world.a, world.gen1, sidecar.GkmCauseRemove, func(args *sidecar.GkmGenerationArgs) {
			args.DropNotAfter = notAfter
		})
	}
	world.expectRotation("a drop key of the settled life", second, withDrop(world.now.Add(lifetime)), world.gen1)
	world.expectRotation("a drop key at the bound", second, withDrop(world.now.Add(lifetime+sidecar.GkmClockSkew)), world.gen1)
	world.expectPoisoned("a drop key past the bound", second, withDrop(world.now.Add(lifetime+sidecar.GkmClockSkew+time.Millisecond)), world.gen1, sidecar.GkmRefusalTime)

	kek, err := sidecar.MlsKek(world.a.group, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	leafWrapped := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRemove, func(args *sidecar.GkmGenerationArgs) {
		args.LeafWrapKek = kek
		args.LeafWrapEpoch = world.a.group.Epoch()
	})
	dirty, err := world.checkRotation(second, leafWrapped, world.gen1, func(args *sidecar.GkmRotationCheckArgs) {
		args.LeafWrapRoster = world.a.group.Roster()
	})
	if err != nil || dirty.Reason != sidecar.GkmRefusalHolders || dirty.Poisoned != 2 {
		t.Errorf("a leaf_wrap under a tree that holds a dropped leaf: %+v %v", dirty, err)
	}
	world.adopt(world.a, world.stage(world.a, 1, second.Pin(), nil, []*gkmWorldDevice{world.x}))
	clean, err := world.checkRotation(second, leafWrapped, world.gen1, func(args *sidecar.GkmRotationCheckArgs) {
		args.LeafWrapRoster = world.a.group.Roster()
	})
	if err != nil || !clean.Passed() {
		t.Errorf("a leaf_wrap under a clean tree: %+v %v", clean, err)
	}

	gen2 := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRemove, nil)
	toHolder := world.delivery(second, world.a, gen2, world.c, sidecar.GkmDeliveryStaged, nil, time.Time{})
	toDropped := world.delivery(second, world.a, gen2, world.x, sidecar.GkmDeliveryStaged, nil, time.Time{})
	passed, err := world.checkRotation(second, gen2, world.gen1, func(args *sidecar.GkmRotationCheckArgs) {
		args.StagedDeliveries = []*sidecar.GkmDelivery{toHolder}
	})
	if err != nil || !passed.Passed() {
		t.Errorf("a rotation whose staged delivery reaches a holder: %+v %v", passed, err)
	}
	poisoned, err := world.checkRotation(second, gen2, world.gen1, func(args *sidecar.GkmRotationCheckArgs) {
		args.StagedDeliveries = []*sidecar.GkmDelivery{toHolder, toDropped}
	})
	if err != nil || !poisoned.Refused || poisoned.Reason != sidecar.GkmRefusalDelivery || poisoned.Poisoned != 2 {
		t.Errorf("a rotation that staged a delivery to a dropped holder: %+v %v", poisoned, err)
	}
}
