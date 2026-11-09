//go:build sidecar_testhooks

// The record's barriers, under the tag: record.reserve.before sits outside the approval's mutex, so a schedule parks
// every racer there, as FS-25 does, and record.taint.before comes after the run's memory flag, so a reader racing a
// taint parked there reads tainted.

package sidecar

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// Installs a barrier hook that parks every caller at name until release closes, telling arrived of each.
func parkAtBarrier(t *testing.T, name string) (arrived chan struct{}, release chan struct{}) {
	t.Helper()
	arrived = make(chan struct{}, 16)
	release = make(chan struct{})
	t.Cleanup(func() { SetTestHooks(nil) })
	SetTestHooks(&TestHooks{
		Barrier: func(barrierName string, key string) {
			if barrierName != name {
				return
			}
			arrived <- struct{}{}
			<-release
		},
	})
	return arrived, release
}

// Two racers for an approval's one use both reach record.reserve.before, which they could not if it sat inside the
// mutex; released, exactly one reserves.
func TestReserveBarrierParksEveryRacer(t *testing.T) {
	_, _, ledger, _ := newTestLedger(t)
	approvalId := NewId()
	arrived, release := parkAtBarrier(t, "record.reserve.before")
	var group sync.WaitGroup
	results := make(chan error, 2)
	for _, action := range []string{"first", "second"} {
		group.Add(1)
		go func() {
			defer group.Done()
			_, _, err := reserveTestUse(t, ledger, approvalId, action, 1)
			results <- err
		}()
	}
	<-arrived
	<-arrived
	close(release)
	group.Wait()
	close(results)
	spentCount := 0
	for err := range results {
		if errors.Is(err, ErrApprovalSpent) {
			spentCount += 1
		} else if err != nil {
			t.Error(err)
		}
	}
	if spentCount != 1 {
		t.Errorf("%d racers found the use spent", spentCount)
	}
	if uses, err := ledger.Uses(approvalId); err != nil || uses != 1 {
		t.Errorf("uses %d, err %v", uses, err)
	}
}

// A taint parked before its fsync has already set the run's flag: a racing reader errs tainted (D-MCP-16).
func TestTaintBarrierFollowsTheMemoryFlag(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	runId := createTestRun(t, runs)
	arrived, release := parkAtBarrier(t, "record.taint.before")
	returned := make(chan error, 1)
	go func() {
		returned <- runs.Taint(context.Background(), runId, RunTaintUntrustedData)
	}()
	<-arrived
	if !runs.Tainted(runId) {
		t.Error("a reader racing a parked taint read untainted")
	}
	close(release)
	if err := <-returned; err != nil {
		t.Fatal(err)
	}
}
