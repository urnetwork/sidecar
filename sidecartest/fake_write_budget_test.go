package sidecartest

import (
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// Each class's ctx carries its class, and what each spent is counted where a test can read it.
func TestFakeWriteBudgetCountsWhatEachClassSpent(t *testing.T) {
	budget := NewFakeWriteBudget(nil)
	ctx := t.Context()
	if class, ok := sidecar.WriteClassOf(budget.IssueP0(ctx, "meta-1", sidecar.WriteP0KindRemove, 300)); !ok || class != sidecar.WriteClassP0 {
		t.Errorf("P0 class %v", class)
	}
	grant, err := budget.AdmitP1(ctx, "meta-1", connect.NewId(), sidecar.WriteCost{ImmediateByteCount: 63, DeferredByteCount: 37})
	if err != nil {
		t.Fatal(err)
	}
	if class, _ := sidecar.WriteClassOf(grant.Context()); class != sidecar.WriteClassP1 {
		t.Errorf("P1 class %v", class)
	}
	rechecked := false
	p2, err := budget.AcquireP2(ctx, "meta-1", &sidecar.WriteP2Work{
		Rank:      sidecar.WriteP2RankFold,
		ByteCount: 50,
		Funded:    true,
		Recheck: func(ctx context.Context) error {
			rechecked = true
			return nil
		},
	})
	if err != nil || !rechecked {
		t.Fatalf("P2: %v, rechecked %v", err, rechecked)
	}
	if budget.InFlightByteCount() != 113 {
		t.Errorf("in flight %d", budget.InFlightByteCount())
	}
	grant.Close()
	p2.Close()
	p2.Close()
	if budget.InFlightByteCount() != 0 {
		t.Errorf("in flight %d after close", budget.InFlightByteCount())
	}
	if byteCount, credit := budget.P1ByteCount("meta-1"); byteCount != 100 || credit != 37 {
		t.Errorf("P1 %d, credit %d", byteCount, credit)
	}
	if budget.P0ByteCount("meta-1", sidecar.WriteP0KindRemove) != 300 || budget.P2ByteCount("meta-1", true) != 50 {
		t.Error("P0 or P2 miscounted")
	}
	budget.DeclareP2Backlog("meta-1", "evacuation", sidecar.WriteP2RankEvacuation, true, 900)
	if budget.P2Backlog("meta-1", "evacuation", sidecar.WriteP2RankEvacuation, true) != 900 {
		t.Error("backlog not kept")
	}
	if violations := budget.Violations(); len(violations) != 0 {
		t.Errorf("violations %v", violations)
	}
}

// A refused network gets the real one's 429, and a recheck that refuses spends nothing.
func TestFakeWriteBudgetRefusesWhatATestRefuses(t *testing.T) {
	budget := NewFakeWriteBudget(nil)
	networkId := connect.NewId()
	budget.RefuseP1("meta-1", networkId, true)
	_, err := budget.AdmitP1(t.Context(), "meta-1", networkId, sidecar.WriteCost{ImmediateByteCount: 1})
	refusal := &sidecar.WriteRefusal{}
	if !errors.As(err, &refusal) || refusal.RetryAfterMs() != 5000 {
		t.Errorf("refusal %v", err)
	}
	errSkip := errors.New("gone")
	if _, ok, err := budget.TryAcquireP2(t.Context(), "meta-1", &sidecar.WriteP2Work{
		Rank:      sidecar.WriteP2RankGc,
		ByteCount: 10,
		Recheck:   func(ctx context.Context) error { return errSkip },
	}); ok || !errors.Is(err, errSkip) {
		t.Errorf("recheck: %v %v", ok, err)
	}
	if budget.P2ByteCount("meta-1", false) != 0 || budget.InFlightByteCount() != 0 {
		t.Error("a refused recheck spent")
	}
}

// What the real budget refuses or would mislabel, the fake records as a violation.
func TestFakeWriteBudgetRecordsBrokenPromises(t *testing.T) {
	budget := NewFakeWriteBudget(nil)
	ctx := t.Context()
	budget.IssueP0(ctx, "meta-1", "not-a-kind", 10)
	if _, err := budget.AdmitP1(ctx, "meta-1", connect.Id{}, sidecar.WriteCost{}); !errors.Is(err, sidecar.ErrWriteCost) {
		t.Errorf("no network: %v", err)
	}
	if _, err := budget.AdmitP1(ctx, "meta-1", connect.NewId(), sidecar.WriteCost{DeferredByteCount: -1}); !errors.Is(err, sidecar.ErrWriteCost) {
		t.Errorf("negative cost: %v", err)
	}
	if _, err := budget.AcquireP2(ctx, "meta-1", &sidecar.WriteP2Work{Rank: 42}); err == nil {
		t.Error("a rank outside §11.13's")
	}
	budget.DeclareP2Backlog("meta-1", "", sidecar.WriteP2RankGc, false, 1)
	if violations := budget.Violations(); len(violations) != 5 {
		t.Errorf("violations %v", violations)
	}
}
