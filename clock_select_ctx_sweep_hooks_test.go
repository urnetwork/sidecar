//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// The certificate manager's Close waits for its loop (clock-select-ctx-sweep): a pass of the loop's that was in
// flight when Close was called has ended before Close returns, so no pass of the loop's writes the store or reads the
// api once Close has. The barrier tls.cert_close marks where Close begins its wait, which is how the test knows Close
// is waiting rather than gone, with no sleep.

package sidecar

import (
	"sync"
	"testing"
	"time"
)

// Close returns only once its loop has: with the loop's pass held in its GET /tls/certs, Close reaches its wait and
// stays there, its loop still running, until the pass is let go; then the loop ends and Close returns. A Close that
// only cancelled returned while the pass was held, its loop still in flight.
func TestTlsCertManagerCloseWaitsForItsLoop(t *testing.T) {
	t.Cleanup(func() { SetTestHooks(nil) })
	guard := 30 * time.Second
	fixture := newTlsCertFixture(t)
	fixture.manager.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	func() {
		fixture.api.stateLock.Lock()
		defer fixture.api.stateLock.Unlock()
		fixture.api.certsEntered = entered
		fixture.api.certsRelease = release
	}()
	manager := fixture.newManager()
	// the attachment asks for a pass, whose read of the rows the api holds
	manager.SetApi(fixture.api)
	select {
	case <-entered:
	case <-time.After(guard):
		t.Fatalf("the loop's pass did not read the rows within %v", guard)
	}

	closeWaiting := make(chan struct{})
	var closeWaitingOnce sync.Once
	SetTestHooks(&TestHooks{
		Barrier: func(name string, key string) {
			if name == "tls.cert_close" {
				closeWaitingOnce.Do(func() { close(closeWaiting) })
			}
		},
	})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		manager.Close()
	}()
	select {
	case <-closed:
		t.Fatal("Close returned with its loop's pass still in flight")
	case <-closeWaiting:
	case <-time.After(guard):
		t.Fatalf("Close did not reach its wait within %v", guard)
	}
	select {
	case <-manager.done:
		t.Fatal("the loop ended with its pass still held")
	case <-closed:
		t.Fatal("Close returned with its loop's pass still in flight")
	default:
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(guard):
		t.Fatalf("Close did not return within %v of its loop's pass ending", guard)
	}
	select {
	case <-manager.done:
	default:
		t.Fatal("Close returned before its loop did")
	}
}
