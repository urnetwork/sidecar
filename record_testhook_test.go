//go:build sidecar_testhooks

// The record's hooks, under the tag: record.reserve.before sits outside the approval's mutex, so a schedule parks
// every racer there, as FS-25 does; record.taint.before comes after the run's memory flag, so a reader racing a taint
// parked there reads tainted; and the spool's keys reach the secret hook and never the medium.

package sidecar

import (
	"bytes"
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

// Both halves of an epoch's key pair and the redaction key reach the privacy harness's hook, and the medium holds the
// public half alone: no private seed and no redaction key, sealed or not, in any file.
func TestSpoolKeysReachTheHook(t *testing.T) {
	var stateLock sync.Mutex
	kindSecrets := map[string][][]byte{}
	t.Cleanup(func() { SetTestHooks(nil) })
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			stateLock.Lock()
			defer stateLock.Unlock()
			kindSecrets[kind] = append(kindSecrets[kind], secret)
		},
	})
	instance, backend, spool := newTestSpool(t, testSpoolSettings())
	spoolTestTexts(t, spool, "unlocked")
	lockTestInstance(t, instance)
	spoolTestTexts(t, spool, "locked")
	unlockTestInstance(t, instance)
	drainTestSpool(t, spool)
	stateLock.Lock()
	defer stateLock.Unlock()
	for _, kind := range []string{"spool_private_key", "spool_public_key", "K_redact"} {
		if len(kindSecrets[kind]) == 0 {
			t.Errorf("no %s reached the hook", kind)
		}
	}
	snapshot := backendSnapshot(t, backend)
	for _, kind := range []string{"spool_private_key", "K_redact"} {
		for _, secret := range kindSecrets[kind] {
			for path, content := range snapshot {
				if bytes.Contains(content, secret) {
					t.Errorf("%s holds a %s", path, kind)
				}
			}
		}
	}
}
