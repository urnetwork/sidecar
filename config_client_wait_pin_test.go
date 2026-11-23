// ConfigClient.WaitForPin (QD-1202): the wait an evs reader asks of its log for a statement's pin above its state.
// It asks a follow at once and answers once the log applies the position, as WaitFor does, but records no hint, since
// the pin is evs's word: a position api never serves counts nothing against api, where WaitFor's does.

package sidecar

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// WaitForPin follows at once to a position api serves, with no hint naming it, and answers the state there; for a
// position api never serves it waits until its ctx ends and records no hint, so the follow after it raises no withheld
// alarm, while the same position through WaitFor, which takes it as proof api holds it, raises one.
func TestConfigClientWaitForPinFollowsAndRecordsNoHint(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	world.publish()
	client := world.client(nil)
	world.caughtUp(client)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// published, and no hint names it: the wait's own follow reaches it
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("another"))
	world.publish()
	readsBefore := world.projection.readCount()
	state, err := client.WaitForPin(ctx, net.n)
	if err != nil || state.Pin().GetVersion() != net.n {
		t.Fatalf("waiting for a published position: %v %v", state.Pin(), err)
	}
	if world.projection.readCount() == readsBefore {
		t.Error("the wait asked no follow")
	}

	// past anything api serves: the wait ends with its ctx, and the follows after it count nothing against api
	beyond := net.n + 5
	ended, end := context.WithCancel(ctx)
	end()
	if _, err := client.WaitForPin(ended, beyond); !errors.Is(err, context.Canceled) {
		t.Fatalf("a wait whose ctx ended: %v", err)
	}
	if err := client.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if alarms := world.headAlarms(SidecarHeadAlarmWithheld); alarms != 0 {
		t.Fatalf("a pin only evs named raised %d withheld alarms", alarms)
	}
	if !client.WithheldSince().IsZero() {
		t.Fatal("a pin only evs named counts api as withholding it")
	}
	if _, err := client.WaitFor(ended, beyond); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitFor whose ctx ended: %v", err)
	}
	if err := client.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if alarms := world.headAlarms(SidecarHeadAlarmWithheld); alarms != 1 {
		t.Errorf("the same position through WaitFor raised %d withheld alarms, not 1", alarms)
	}
}
