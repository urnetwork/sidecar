//go:build sidecar_testhooks && !sidecar_http && !js

// Fault schedules on the dispatcher's barriers (§22.8). A worker that has emptied its queue is held just
// before it looks again, the inline handler queues behind it, and the envelope must still be run: the
// worker retires and the handler starts another only under one lock, so nothing lands in a queue whose
// worker has gone.

package sidecar

import (
	"sync"
	"testing"

	"github.com/urnetwork/connect"
)

// Holds the arrival at name with key that is the nth, counting from 1, until release runs, and closes
// held once it is there. Every other arrival passes. Removed with the test.
func testHoldNthBarrier(t *testing.T, name string, key string, n int) (held chan struct{}, release func()) {
	t.Helper()
	held = make(chan struct{})
	released := make(chan struct{})
	var stateLock sync.Mutex
	count := 0
	SetTestHooks(&TestHooks{
		Barrier: func(barrierName string, barrierKey string) {
			if barrierName != name || barrierKey != key {
				return
			}
			hold := false
			func() {
				stateLock.Lock()
				defer stateLock.Unlock()
				count += 1
				hold = count == n
			}()
			if hold {
				close(held)
				<-released
			}
		},
	})
	t.Cleanup(func() { SetTestHooks(nil) })
	return held, func() { close(released) }
}

func TestEnqueueBehindARetiringWorkerIsRun(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")
	fixture.verify(sourceId, "a")
	messages := fixture.collect(t, testFreeMessageType)

	// the worker's first look finds the first envelope; its second, held, would find the queue empty
	held, release := testHoldNthBarrier(t, "rpc.peer_take.before", sourceId.String(), 2)
	first := testRequest(testFreeMessageType, []byte{1})
	fixture.receive(sourceId, first, peer)
	if message := testAwait(t, messages, "first"); message.envelope.RequestId != first.RequestId {
		t.Fatalf("first %d", message.envelope.RequestId)
	}
	testAwait(t, held, "worker at its second look")

	second := testRequest(testFreeMessageType, []byte{2})
	fixture.receive(sourceId, second, peer)
	release()
	if message := testAwait(t, messages, "second"); message.envelope.RequestId != second.RequestId {
		t.Fatalf("second %d", message.envelope.RequestId)
	}
	fixture.closeBalanced(t)
}
