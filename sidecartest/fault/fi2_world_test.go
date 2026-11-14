//go:build sidecar_testhooks

package fault

// FI-2's shred exception on the evs world's instances and lb (§11.12's phase 1, I-EVS-3; TEST-M2-04): writerA's push
// P is held at evs1's head CAS once its checks pass; writerB deletes the repo now through evs3, whose CAS takes repo/
// to shredding; the lb's read timeout sends P on to evs2, which answers 409 SHREDDING, so writerA was refused; released,
// evs1's attempt lands the PUT whose If-Match the CAS left standing and answers 200. FI-2 excuses that commit, since
// the attempt arrived before the CAS and the shred destroys it, which the shred's passes then do. The schedule holds
// evs1 at a barrier, so it needs the sidecar_testhooks tag.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFi2TakesTheShredRaceOnTheEvsWorld(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fi2 a", 200))},
		{Actor: "writerA", Action: world.WriteAny("writerA", "b.txt", EvsWorldContent("fi2 b", 200)), Background: true},
		// a.txt's commit passes evs1's site once
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: 1},
		{Actor: "writerB", Action: world.DeleteRepo("writerB", true)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_SHREDDING)},
		// the lb's read timeout: P goes on to evs2
		{Advance: 30 * time.Second},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectRefused("writerA", "b.txt", protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)},
		{Release: []string{evsservice.BarrierHeadCasBefore}},
		{Actor: "evs1", Join: true},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			pushes := world.DevicePushes("writerA")
			push := pushes[len(pushes)-1]
			committed, refused := false, false
			for _, answer := range push.InstanceAnswers() {
				committed = committed || (answer.Instance == "evs1" && answer.Status == http.StatusOK)
				refused = refused || (answer.Instance == "evs2" && answer.Code == protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
			}
			if !committed || !refused {
				return errors.New("the race did not happen: evs1 did not commit P after evs2 refused it SHREDDING")
			}
			return nil
		}},
		// the shred destroys it: step 1's 20 s, then every family, then the tombstone
		{Actor: "shred", Action: world.Shred(false)},
		{Advance: 20 * time.Second},
		{Actor: "shred", Action: world.Shred(false)},
		{Advance: 10 * time.Minute},
		{Actor: "shred", Action: world.Shred(true)},
		{Actor: "check", Action: world.ExpectShredded()},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi2-shred-race-world", Steps: steps, Check: []Invariant{FI(2)}}, net))
	// FI-2 judged the exception: the ledger holds P refused and the head history it read committed P
	pushes := world.DevicePushes("writerA")
	pushId := pushes[len(pushes)-1].PushId
	memory := netMemoryOf(&fi2Memories, net, newFi2Memory)
	memory.stateLock.Lock()
	commit := memory.pushCommits[pushId]
	_, started := memory.shredStarts[world.RepoId]
	memory.stateLock.Unlock()
	if commit == nil || !started {
		t.Fatalf("FI-2 never read P's commit (%v) or the shred's start (%t), so the exception was not judged", commit, started)
	}
	for _, push := range LedgerOf(net).Pushes() {
		if push.PushId == pushId && (len(push.Refusals()) == 0 || len(push.Versions()) == 0) {
			t.Fatalf("the ledger holds P with %d refusals and versions %v, not refused and committed", len(push.Refusals()), push.Versions())
		}
	}
}
