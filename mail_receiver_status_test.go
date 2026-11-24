//go:build !sidecar_http && !ios_extension && !js

// The receiver's part of MailClient.Status across generations (mail_client.go's runReportsWithLock), as the sender's
// is in mail_sender_status_test.go: a generation another has replaced says nothing over the one that runs. The
// receiver here is mail_receiver_test.go's stand-in on its test listener, and nothing dials.

package sidecar

import (
	"context"
	"testing"
)

// The new generation's first pass starts its receiver, and the old generation's stop, which closes its own receiver's
// parts and so can end after that pass, leaves the new generation's status standing, where it once cleared it while
// the new receiver ran.
func TestMailReceiverStatusOfAReplacedGenerationDoesNotStand(t *testing.T) {
	world := newMailClientTestWorld(t)
	receivers := newMailReceiverTestWorld(t, nil)
	world.client.componentSeams = &mailComponentSeams{
		mayReceive: func() bool { return true },
		factory: func(args *mailReceiverFactoryArgs) (*MailReceiver, func(), error) {
			return receivers.newReceiver(nil), func() {}, nil
		},
	}
	world.enable()
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	previousCtx, previousCancel := context.WithCancel(t.Context())
	previous := &mailComponentRun{ctx: previousCtx, cancel: previousCancel}
	// the next generation, installed as Attach installs it before it cancels the one it replaces, and its first pass
	ctx, cancel := context.WithCancel(t.Context())
	next := &mailComponentRun{ctx: ctx, cancel: cancel}
	func() {
		world.client.stateLock.Lock()
		defer world.client.stateLock.Unlock()
		world.client.componentRun = next
	}()
	t.Cleanup(func() {
		cancel()
		world.client.stopRun(next)
	})
	previousCancel()
	world.client.passReceive(next, binding)
	receivers.publisher.awaitCount(1)
	world.client.stopRun(previous)
	status := func() MailClientReceiverStatus {
		world.client.stateLock.Lock()
		defer world.client.stateLock.Unlock()
		return world.client.receiverStatus
	}()
	if next.receiver == nil || !status.Running {
		t.Fatalf("after the replaced generation's stop, a receiver %t and the status %+v", next.receiver != nil, status)
	}
}
