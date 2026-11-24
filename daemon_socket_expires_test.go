//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// ur socket listen's --expires through a real daemon's socket.listen (owner decision 687): the daemon hands
// expires_ms to its listen as SocketListenSettings.Expires, asks none where the call names none, as Listen, the
// socket_listen tool's entry, asks none, and refuses an expires_ms past what a duration holds as params that do not
// decode, listening on nothing.

package sidecar

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

// A backend whose every listen waits on approvalId, keeping the settings each was asked with.
type testExpiresSocketBackend struct {
	*testSocketBackend
	approvalId Id

	stateLock sync.Mutex
	asked     []SocketListenSettings
}

func (self *testExpiresSocketBackend) listen(ctx context.Context, address *SocketAddress, settings *SocketListenSettings, share bool) (daemonSocketListener, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, *settings)
	return nil, &ApprovalPendingError{ApprovalId: self.approvalId}
}

// The settings each listen was asked with, in order.
func (self *testExpiresSocketBackend) askedSettings() []SocketListenSettings {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]SocketListenSettings{}, self.asked...)
}

// socket.listen's expires_ms reaches the listen as Expires; none named asks none, as Listen asks none; one past what
// a duration holds is refused before any listen.
func TestDaemonSocketListenAsksItsExpires(t *testing.T) {
	clock := newTestArmedClock()
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.Clock = clock
	})
	backend := &testExpiresSocketBackend{testSocketBackend: newTestSocketBackend(newTestSocketNet()), approvalId: NewId()}
	if err := started.daemon.AddSidecar(testRegistrarNetworkId, &Sidecar{}); err != nil {
		t.Fatal(err)
	}
	sockets := started.daemon.Sockets()
	sockets.backends = func(networkId Id) (daemonSocketBackend, error) {
		return backend, nil
	}
	for _, method := range sockets.Methods() {
		if err := started.daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	control := dialTestDaemon(t, started, DaemonModeControl)

	for _, params := range []*DaemonSocketListenParams{
		{Address: "tls/443/blog", Target: "8443", ExpiresMs: (3 * 24 * time.Hour).Milliseconds()},
		{Address: "tls/443/blog", Target: "8443"},
	} {
		reply := &DaemonSocketListenReply{}
		if err := control.Call(context.Background(), DaemonMethodSocketListen, params, false, reply); err != nil {
			t.Fatal(err)
		}
		if reply.ApprovalId == nil || *reply.ApprovalId != backend.approvalId {
			t.Errorf("expires_ms %d: reply %+v", params.ExpiresMs, reply)
		}
	}
	if _, err := sockets.Listen(context.Background(), testRegistrarNetworkId, "tls/443/blog", "8443"); err != nil {
		t.Fatal(err)
	}
	asked := backend.askedSettings()
	if len(asked) != 3 || asked[0].Expires != 3*24*time.Hour || asked[1].Expires != 0 || asked[2].Expires != 0 {
		t.Fatalf("the listens asked %+v", asked)
	}

	err := control.Call(context.Background(), DaemonMethodSocketListen, &DaemonSocketListenParams{
		Address: "tls/443/blog", Target: "8443", ExpiresMs: math.MaxInt64,
	}, false, &DaemonSocketListenReply{})
	if err == nil {
		t.Error("an expires_ms past what a duration holds was taken")
	}
	if asked := backend.askedSettings(); len(asked) != 3 {
		t.Errorf("a refused call listened: %+v", asked)
	}
}
