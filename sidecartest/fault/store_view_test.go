package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Every family the oracle reads decodes through one view on T2's fakes: a head, a log page, a slot, a batch record
// and a gen/ object, at the cluster place/ names. Server's sidecart3 runs the same fixture on T3.
func TestStoreViewDecodesEachFamilyThroughOneView(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	fixture := NewStoreViewFixture()
	if err := fixture.Write(t.Context(), net); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Check(t.Context(), NewStoreView(net, nil)); err != nil {
		t.Fatal(err)
	}
}

// A look fires no plan, counts toward none, and adds nothing to the blob history FI-30 reads; the same read by an
// engine takes the plan.
func TestStoreViewLookFiresNoPlan(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	fixture := NewStoreViewFixture()
	if err := fixture.Write(t.Context(), net); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{sidecartest.FaultOpGet, sidecartest.FaultOpList} {
		if _, err := net.Faults().Add(&FaultPlan{Op: op, KeyPrefix: "head/", Result: sidecartest.FailBeforeApply}); err != nil {
			t.Fatal(err)
		}
	}
	historyCount := len(net.BlobHistory())
	view := NewStoreView(net, nil)
	if heads, err := view.Heads(t.Context(), fixture.RepoId); err != nil || len(heads) != 1 {
		t.Fatalf("the look under armed plans: %v, %v", heads, err)
	}
	if object, err := view.Object(t.Context(), fixture.ClusterId, fixture.HeadKey); err != nil || object == nil {
		t.Fatalf("a head by its key: %v, %v", object, err)
	}
	if unfired := net.Faults().Unfired(); len(unfired) != 2 {
		t.Fatalf("a look fired a plan: %d left unfired", len(unfired))
	}
	if got := len(net.BlobHistory()); got != historyCount {
		t.Fatalf("a look added %d requests to the history", got-historyCount)
	}
	first, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Get(t.Context(), fixture.HeadKey); err == nil {
		t.Fatal("an engine's read under the armed plan succeeded, so the plan was never live")
	}
	if unfired := net.Faults().Unfired(); len(unfired) != 1 {
		t.Fatalf("the engine's read left %d plans unfired", len(unfired))
	}
}

// A planted failure names its step: every invariant failing at that check is collected with the step, the run
// stops there, and Changed gives each check only the writes its step made.
func TestOracleNamesEachViolationsStep(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	changedAt := map[int][]string{}
	steps := []*Step{}
	for index := range 4 {
		steps = append(steps, &Step{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			if index == 3 {
				return nil
			}
			first, err := net.Host().Blobs.FirstCluster()
			if err != nil {
				return err
			}
			_, err = first.PutIfNoneMatch(ctx, fmt.Sprintf("planted/%d", index), []byte("written"), nil)
			return err
		}})
	}
	planted := errors.New("the planted failure")
	schedule := &Schedule{
		Id:    "planted",
		Steps: steps,
		Check: []Invariant{
			NewInvariant("changes", func(ctx context.Context, oracle *Oracle) error {
				for _, keys := range oracle.ChangedKeys() {
					changedAt[oracle.Step] = append(changedAt[oracle.Step], keys...)
				}
				if oracle.View == nil {
					return errors.New("the oracle has no store view")
				}
				return nil
			}),
			NewInvariant("planted", func(ctx context.Context, oracle *Oracle) error {
				if oracle.Step == 2 {
					return planted
				}
				return nil
			}),
			NewInvariant("also", func(ctx context.Context, oracle *Oracle) error {
				if oracle.Step == 2 {
					return errors.New("a second failure at the same step")
				}
				return nil
			}),
		},
	}
	result := Run(t.Context(), schedule, net)
	if result.Err == nil || result.FailedStep != 2 || !errors.Is(result.Err, planted) {
		t.Fatalf("the run: %s", result)
	}
	if !strings.Contains(result.Err.Error(), "planted after step 2") || !strings.Contains(result.Err.Error(), "also after step 2") {
		t.Fatalf("the error names %v", result.Err)
	}
	if len(result.Violations) != 2 || result.Violations[0].Step != 2 || result.Violations[1].Invariant != "also" {
		t.Fatalf("violations %v", result.Violations)
	}
	for step, want := range map[int][]string{0: {"planted/0"}, 1: {"planted/1"}, 2: {"planted/2"}} {
		if !slices.Equal(changedAt[step], want) {
			t.Errorf("step %d changed %v, want %v", step, changedAt[step], want)
		}
	}
	if _, ran := changedAt[3]; ran {
		t.Error("a step after the failing check ran")
	}
}

// Without the hooks no reader held anything, so Open fails closed for every reader; a ladder missing the asked
// generation opens nothing either; and T2 has no Postgres to read.
func TestStoreViewOpenFailsClosedForAKeyNeverHeld(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	fixture := NewStoreViewFixture()
	if err := fixture.Write(t.Context(), net); err != nil {
		t.Fatal(err)
	}
	view := NewStoreView(net, nil)
	ladder, err := view.Generations(t.Context(), fixture.GroupId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.Open("readerNever", ladder, 1); !errors.Is(err, ErrStoreViewNotHeld) {
		t.Fatalf("a reader that held nothing opened gen/1: %v", err)
	}
	if _, err := view.Open("readerNever", ladder, 2); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Fatalf("a generation the ladder lacks: %v", err)
	}
	if _, err := view.Postgres(t.Context(), "SELECT 1"); !errors.Is(err, ErrStoreViewNoStore) {
		t.Fatalf("T2's Postgres: %v", err)
	}
}
