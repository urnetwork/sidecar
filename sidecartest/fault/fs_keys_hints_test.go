// The gkm schedules' last step and gkm's free hint senders (QD-1155): a hint queued before the step is sent before the
// worlds close, so every run of a schedule makes the same Push writes for §22.8's unknown rule to lose one at a time.

package fault

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/gkmschedule"
)

// A hint send held at the fault queue until the last step begins its wait: the step waits for it and closes the world
// with nothing pending. Closing at once, as the step did before, leaves the held hint pending, whenever its sender
// would have been scheduled.
func TestFsKeysLastStepSendsEveryQueuedHintBeforeTheWorldsClose(t *testing.T) {
	ctx := t.Context()
	net := sidecartest.NewNet(ctx, nil)
	defer net.Close()
	run := newFsKeysRun(net)
	release := make(chan struct{})
	released := false
	releaseOnce := func() {
		if !released {
			released = true
			close(release)
		}
	}
	defer releaseOnce()
	run.awaitingHints = releaseOnce
	hold, err := net.Faults().Add(&FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "push.HintSidecars", Result: ApplyThenDrop})
	if err != nil {
		t.Fatal(err)
	}
	// the plan fires once, on the first HintSidecars after it is armed, whose sender then waits here
	taken := make(chan struct{})
	net.Faults().SetOnFire(func(plan *FaultPlan) {
		close(taken)
		<-release
	})
	var world *gkmschedule.FsKeysWorld
	if err := fsKeysCatch(func() {
		world = run.world(protocol.RepoKind_REPO_KIND_GENERAL)
		a := world.AddMember("a", false)
		b := world.AddMember("b", false)
		world.Grant(true, a, b)
		world.Admin(a)
		world.Advance()
		world.Publish()
		world.Create(a)
		world.AddPending(a)
	}); err != nil {
		t.Fatal(err)
	}
	// a guard against a world that queues no hint, never a wait the test orders
	select {
	case <-taken:
	case <-time.After(10 * time.Second):
		t.Fatal("no hint send reached the plan")
	}
	// the plan's channel closes once onFire has returned, so it stays open while the send is held
	select {
	case <-hold:
		t.Fatal("the held send went on before the last step")
	default:
	}
	if err := run.cleanup().Action(ctx, net); err != nil {
		t.Fatal(err)
	}
	if pending, _ := world.Engine.HintsPending(); pending != 0 {
		t.Errorf("the worlds closed with %d hints pending", pending)
	}
	select {
	case <-hold:
	default:
		t.Error("the held send had not gone on when the worlds closed")
	}
}
