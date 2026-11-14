package fault

// FI-2's oracle (fi2.go) on T2, in fi1_test.go's hand world: pushes built with the format's own builders and
// committed through evsservice.HeadStore, so a step can commit what evs would refuse, and the ledger recorded as a
// client was answered. Each mutant is caught at its step beside the twin that reads clean; the shred exception is
// held on both sides of "validated before its repo's shred began". fi2_world_test.go runs the exception on the evs
// world's instances and lb, under the hooks.

import (
	"context"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One push of the hand world's main, a file creation that introduces one slot, its record in a batch and its slot
// written; committed by fi2Commit.
type fi2Push struct {
	push   *fiHandPush
	pushId sidecar.Id
	slotId sidecar.Id
}

type fi2World struct {
	*fiHandWorld
	main sidecar.Id
}

func newFi2World(t *testing.T) *fi2World {
	return &fi2World{fiHandWorld: newFiHandWorld(t), main: sidecar.NewId()}
}

func (self *fi2World) ref() HistoryRef {
	return HistoryRef{RepoId: self.repoId, RefId: self.main}
}

// A step's action preparing a push pending on main into push.
func (self *fi2World) prepare(push *fi2Push) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		slotId, built, err := self.slotPush(ctx, self.main, true)
		if err != nil {
			return err
		}
		push.push, push.pushId, push.slotId = built, sidecar.Id(built.statement.Push.GetPushId()), slotId
		return nil
	}
}

// A step's action committing a prepared push at main's next version, as a step 7 that skipped every check would.
func (self *fi2World) commit(push *fi2Push) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		return self.fiHandWorld.commit(ctx, push.push)
	}
}

// A step's action recording into the Net's ledger that an attempt of push was answered as operation says, its push
// id, ref, times and store arrival filled in now.
func (self *fi2World) answer(push *fi2Push, operation Operation) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		ledger := LedgerOf(net)
		operation.Kind = OperationPush
		operation.Ref = self.ref()
		operation.PushId = push.pushId
		if operation.Actor == "" {
			operation.Actor = "writerA"
		}
		if operation.StoreArrival == 0 {
			operation.StoreArrival = ledger.StoreArrival()
		}
		operation.Call = ledger.Now()
		if operation.Outcome != OutcomeUnknown {
			operation.Return = ledger.Now()
		}
		ledger.Record(&operation)
		return nil
	}
}

// A step's action moving repo/ to state by its If-Match, as a lifecycle route's CAS does.
func (self *fi2World) repoState(state protocol.EvsRepoState) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		key := sidecar.EvsRepoObjectKey(self.repoId)
		object, err := self.cluster.Get(ctx, key)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(object.Body)
		object.Body.Close()
		if err != nil {
			return err
		}
		repo := &protocol.EvsRepoObject{}
		if err := proto.Unmarshal(body, repo); err != nil {
			return err
		}
		repo.State = state
		repo.DeletionId = sidecar.NewId().Bytes()
		repoBytes, err := proto.Marshal(repo)
		if err != nil {
			return err
		}
		_, err = self.cluster.PutIfMatch(ctx, key, object.Etag, repoBytes, nil)
		return err
	}
}

// A step's action deleting the push's slot, as a reclaimer would.
func (self *fi2World) deleteSlot(push *fi2Push) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		return self.cluster.Delete(ctx, evsOracleSlotKey(self.repoId, push.slotId.Bytes()))
	}
}

func fi2Checks() []Invariant {
	return []Invariant{FI(2)}
}

// A committed push answered 200 at its version, twice, as a client's retry is: clean at every step.
func TestFi2ReadsARetryOfACommittedPushClean(t *testing.T) {
	world := newFi2World(t)
	push := &fi2Push{}
	steps := []*Step{
		{Actor: "writerA", Action: world.prepare(push)},
		{Actor: "evs1", Action: world.commit(push)},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs1", Outcome: OutcomeCommitted, Version: 1})},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs2", Outcome: OutcomeCommitted, Version: 1})},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs1", Outcome: OutcomeUnknown})},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi2-retry", Steps: steps, Check: fi2Checks()}, world.net))
	if pushes := LedgerOf(world.net).Pushes(); len(pushes) != 1 || len(pushes[0].Attempts) != 3 || pushes[0].Outcome() != OutcomeCommitted {
		t.Fatalf("the ledger holds %d pushes, not the one push of three attempts, committed", len(pushes))
	}
}

// A retry answered with a new version: caught at the answer.
func TestFi2CatchesARetryReturningANewVersion(t *testing.T) {
	world := newFi2World(t)
	push := &fi2Push{}
	other := &fi2Push{}
	steps := []*Step{
		{Actor: "writerA", Action: world.prepare(push)},
		{Actor: "evs1", Action: world.commit(push)},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs1", Outcome: OutcomeCommitted, Version: 1})},
		{Actor: "writerB", Action: world.prepare(other)},
		{Actor: "evs3", Action: world.commit(other)},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs2", Outcome: OutcomeCommitted, Version: 2})},
	}
	result := Run(t.Context(), &Schedule{Id: "fi2-new-version", Steps: steps, Check: fi2Checks()}, world.net)
	fiRequireViolation(t, result, 5, "FI-2", "answered committed at versions [1 2]", "returns its original result")
	fiRequireViolation(t, result, 5, "FI-2", "committed v2, and the head history commits push", "v1: an answer that is not its original result")
}

// A push answered a refusal commits after: caught at the commit. Its twin, the refusal and no commit, reads clean
// up to it.
func TestFi2CatchesARefusedPushCommittingLate(t *testing.T) {
	world := newFi2World(t)
	push := &fi2Push{}
	steps := []*Step{
		{Actor: "writerA", Action: world.prepare(push)},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs1", Outcome: OutcomeAborted, Code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, Answer: "evs1 409 PATH_CONFLICT"})},
		{Actor: "evs2", Action: world.commit(push)},
	}
	result := Run(t.Context(), &Schedule{Id: "fi2-refused-commits", Steps: steps, Check: fi2Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-2", "was answered a refusal", "the head history commits it at", "a refusal a client received stays true")
}

// PUSH_ID_REUSED answers another statement under a push id that committed, so it binds nothing: clean.
func TestFi2TakesPushIdReusedBesideTheCommit(t *testing.T) {
	world := newFi2World(t)
	push := &fi2Push{}
	steps := []*Step{
		{Actor: "writerA", Action: world.prepare(push)},
		{Actor: "evs1", Action: world.commit(push)},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs1", Outcome: OutcomeCommitted, Version: 1})},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs2", Outcome: OutcomeAborted, Code: protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED})},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi2-push-id-reused", Steps: steps, Check: fi2Checks()}, world.net))
}

// An instance that answered a push unknown deletes its slot: caught at the delete, since no answer deletes anything.
func TestFi2CatchesCleanupOnAnUnknownOutcome(t *testing.T) {
	world := newFi2World(t)
	push := &fi2Push{}
	steps := []*Step{
		{Actor: "writerA", Action: world.prepare(push)},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs1", Outcome: OutcomeUnknown, Answer: "evs1 503 unknown"})},
		{Actor: "evs1", Action: world.deleteSlot(push)},
	}
	result := Run(t.Context(), &Schedule{Id: "fi2-unknown-cleanup", Steps: steps, Check: fi2Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-2", "evs instance evs1, which answered operations, deleted", "no answer deletes anything")
	if unknown := LedgerOf(world.net).Unknown(); len(unknown) != 1 || unknown[0].PushId != push.pushId {
		t.Fatalf("the ledger's unknown set is %d pushes, not the one answered unknown", len(unknown))
	}
}

// A reclaimer deletes an uncommitted push's slot, and the push commits after: caught at the commit.
func TestFi2CatchesAReclaimedPreparationCommittingLater(t *testing.T) {
	world := newFi2World(t)
	push := &fi2Push{}
	steps := []*Step{
		{Actor: "writerA", Action: world.prepare(push)},
		{Actor: "evacuator", Action: world.deleteSlot(push)},
		{Actor: "evs1", Action: world.commit(push)},
	}
	result := Run(t.Context(), &Schedule{Id: "fi2-reclaimed-commits", Steps: steps, Check: fi2Checks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-2", "preparation was reclaimed (evacuator deleted slot/", "a reclaimed preparation never commits later")
}

// §11.12's exception, its excused side: an attempt that arrived before the repo/ CAS that began the shred, held, then
// committing after a sibling's SHREDDING refusal, on a repo now shredding. Clean.
func TestFi2TakesACommitThatArrivedBeforeTheShred(t *testing.T) {
	result, _ := fi2ShredRun(t, true, protocol.EvsRepoState_EVS_REPO_SHREDDING)
	fiRequirePass(t, result)
}

// The other side: every attempt that did not end refused arrived after the CAS, so none was validated before the
// shred began: caught at the commit.
func TestFi2CatchesACommitThatArrivedAfterTheShred(t *testing.T) {
	result, _ := fi2ShredRun(t, false, protocol.EvsRepoState_EVS_REPO_SHREDDING)
	fiRequireViolation(t, result, 4, "FI-2", "SHREDDING", "a refusal a client received stays true")
}

// A SHREDDING refusal on a repo no shred began, deleted only: the exception does not apply, caught at the commit.
func TestFi2CatchesAShreddingRefusalWithNoShred(t *testing.T) {
	result, _ := fi2ShredRun(t, true, protocol.EvsRepoState_EVS_REPO_DELETED)
	fiRequireViolation(t, result, 4, "FI-2", "SHREDDING", "a refusal a client received stays true")
}

// The shred race on the hand world: push P prepared; its attempt A1 answered unknown, recorded before repo/'s CAS to
// state when before is true and after it otherwise; the CAS; a sibling A2 answered 409 SHREDDING; P committed.
func fi2ShredRun(t *testing.T, before bool, state protocol.EvsRepoState) (*Result, *fi2Push) {
	world := newFi2World(t)
	push := &fi2Push{}
	first := &Step{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs1", Outcome: OutcomeUnknown, Answer: "evs1 never answered"})}
	cas := &Step{Actor: "evs3", Action: world.repoState(state)}
	steps := []*Step{{Actor: "writerA", Action: world.prepare(push)}}
	if before {
		steps = append(steps, first, cas)
	} else {
		steps = append(steps, cas, first)
	}
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs2", Outcome: OutcomeAborted, Code: protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING, Answer: "evs2 409 SHREDDING"})},
		{Actor: "evs1", Action: world.commit(push)},
	}...)
	return Run(t.Context(), &Schedule{Id: "fi2-shred-race", Steps: steps, Check: fi2Checks()}, world.net), push
}

// An operation that ends no way a check can read, a commit at version 0: caught.
func TestFi2CatchesAnOperationEndingNoWay(t *testing.T) {
	world := newFi2World(t)
	push := &fi2Push{}
	steps := []*Step{
		{Actor: "writerA", Action: world.prepare(push)},
		{Actor: "writerA", Action: world.answer(push, Operation{Instance: "evs1", Outcome: OutcomeCommitted})},
	}
	result := Run(t.Context(), &Schedule{Id: "fi2-malformed", Steps: steps, Check: fi2Checks()}, world.net)
	fiRequireViolation(t, result, 1, "FI-2", "ends no way a check can read", "a commit at version 0")
}
