//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// The grant end a listen forward's status carries (owner decision 687) through a real daemon's socket.listen and
// socket.local: the reply names the end the listener came to, ur socket's listing repeats it, and a listener with none
// leaves the field out of the reply altogether.

package sidecar

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The in-memory network's backend whose listens each come to the grant end set for their name, none for another.
type testGrantEndSocketBackend struct {
	*testSocketBackend
	nameGrantEnds map[string]time.Time
}

func (self *testGrantEndSocketBackend) listen(ctx context.Context, address *SocketAddress, settings *SocketListenSettings, share bool) (daemonSocketListener, error) {
	listened, err := self.testSocketBackend.listen(ctx, address, settings, share)
	if err != nil {
		return nil, err
	}
	listener := listened.(*testSocketListener)
	listener.grantExpireTime = self.nameGrantEnds[address.Name]
	return listener, nil
}

// socket.listen's reply carries the end of the grant its listener registered under, socket.local's listing the same,
// and a listen with none, an application name's, names none, its reply leaving grant_expires_ms out.
func TestDaemonSocketListenReplyCarriesItsGrantEnd(t *testing.T) {
	fixture := newTestDaemonSockets(t)
	end := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	backend := &testGrantEndSocketBackend{testSocketBackend: fixture.backend, nameGrantEnds: map[string]time.Time{"tls/443/blog": end}}
	fixture.started.daemon.Sockets().backends = func(networkId Id) (daemonSocketBackend, error) {
		return backend, nil
	}
	_, port := startTestEchoTarget(t)

	reply := &DaemonSocketListenReply{}
	fixture.call(t, DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "tls/443/blog", Target: strconv.Itoa(port)}, reply)
	if reply.Status == nil || reply.Status.Name != "tls/443/blog" || reply.Status.GrantExpiresMs != end.UnixMilli() || reply.ApprovalId != nil {
		t.Fatalf("the outward listen's reply: %+v", reply.Status)
	}

	var raw json.RawMessage
	fixture.call(t, DaemonMethodSocketListen, &DaemonSocketListenParams{Address: "db/primary", Target: strconv.Itoa(port)}, &raw)
	if strings.Contains(string(raw), "grant_expires_ms") {
		t.Errorf("an application listen's reply names a grant end: %s", raw)
	}

	local := &DaemonSocketLocalReply{}
	fixture.call(t, DaemonMethodSocketLocal, nil, local)
	ends := map[string]int64{}
	for _, socket := range local.Sockets {
		ends[socket.Name] = socket.GrantExpiresMs
	}
	if len(ends) != 2 || ends["tls/443/blog"] != end.UnixMilli() || ends["db/primary"] != 0 {
		t.Errorf("the listing's grant ends: %v", ends)
	}
}
