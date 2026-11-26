//go:build sidecar_testhooks && !ios_extension && !sidecar_http && !js

package sidecar

// Wake's one ordering (support_client.go): a wake that comes while a pass is reading answers only after a pass that
// began after it, so a pass whose read predates the event the wake announces never answers it. The barrier after
// Wake's target holds the order: the wake takes its target while the first pass's read is held, and only then does
// that read finish, without the reply.

import (
	"testing"
)

func TestSupportWakeWaitsForAPassThatBeganAfterIt(t *testing.T) {
	world := newTestSupportLoopWorld(t, true)
	testAwait(t, world.transport.held, "the first pass's read, the service's events taken")
	targeted := make(chan struct{}, 1)
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		if name == "support_client.wake.after" {
			targeted <- struct{}{}
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })

	world.service.addEvent(&SupportServiceEvent{Entry: "100171", Seq: 2, Type: "note", Note: "Reproduced.", By: "support"})
	woke := make(chan error, 1)
	go func() { woke <- world.client.Wake(t.Context()) }()
	testAwait(t, targeted, "Wake's target, taken while the first pass reads")
	world.transport.release <- struct{}{}
	if err := testAwait(t, woke, "Wake's answer"); err != nil {
		t.Fatal(err)
	}
	select {
	case update := <-world.updates:
		if update.Seq != 2 || update.Type != "note" {
			t.Fatalf("update %+v", update)
		}
	default:
		t.Fatal("Wake answered on the first pass's end, whose read predated the reply")
	}
	if reads := world.transport.reads.Load(); reads != 2 {
		t.Errorf("%d reads, want the first pass's and the woken one's", reads)
	}
}
