//go:build sidecar_testhooks

package evsservice

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

func TestNightlyFinishesAnArchivedEraseAfterTheWriterStopsAtCommit(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	repoId := fixture.check.repoId
	refId := sidecar.EvsErasureRefId(repoId)
	target := fixture.commitWithSlot("interrupted", 2, "target")
	others := []sidecar.Id{
		fixture.commitWithSlot("first group", 64, "first"),
		fixture.commitWithSlot("second group", 64, "second"),
	}
	stopped := new(int)
	atBarrierOnce(t, BarrierHeadCasAfter, barrierRefKey(repoId, refId), func() { panic(stopped) })
	func() {
		defer func() {
			if result := recover(); result != stopped {
				t.Fatalf("writer did not stop just after the head write: %v", result)
			}
		}()
		fixture.slotsDelete(fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: target, KeyIndex: 1}), "admin")
	}()
	for v := 2; v <= 128; v++ {
		fixture.clock.Advance(time.Second)
		key := &sidecar.EvsErasedKey{SlotId: others[(v-2)/64], KeyIndex: uint16((v - 2) % 64)}
		fixture.requireCommitted(fixture.slotsDelete(fixture.erasePlan(key), "admin"), uint64(v))
	}
	head, err := fixture.engine.heads.ReadCluster(fixture.ctx, fixture.cluster, repoId, refId)
	if err != nil || EvsHeadWindowFirstVersion(head.Head) <= 1 || len(fixture.slotIndexes(target)) != 2 {
		t.Fatalf("interrupted ERASE did not leave its slot and an archived version: %v", err)
	}
	for _, task := range fixture.host.Tasks.AllRequests() {
		if task.Name == EvsErasureFinishTaskName {
			t.Fatal("the stopped writer queued a reconciler")
		}
	}
	fixture.clock.Advance(32 * 24 * time.Hour)
	host := fixture.host.ServiceHost()
	nightly, err := NewNightlyPass(host, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nightly.Run(fixture.ctx, fixture.cluster.ClusterId(), "", ""); err != nil {
		t.Fatal(err)
	}
	fixture.host.Tasks.Register(EvsErasureFinishTaskName, func(ctx context.Context, args []byte) error {
		id, through, ok := ParseErasureFinishArgs(args)
		if !ok || id != repoId {
			t.Fatalf("invalid continuation: %x", args)
		}
		return RunErasureFinish(ctx, host, id, through)
	})
	if ran, err := fixture.host.Tasks.RunDue(fixture.ctx); err != nil || ran != 3 {
		t.Fatalf("reconciled %d tasks: %v", ran, err)
	}
	if indexes := fixture.slotIndexes(target); len(indexes) != 1 || indexes[0] != 0 {
		t.Fatalf("keys after recovery: %v", indexes)
	}
}
