// §22.7's revocation suite for sockets (SOCK-M5-16; X10, I-15; DESIGN-DETAILS 13.2.3's bounds), on the suite's world
// (socket_suite_test.go): X's sockets end and X's tokens fail at sockets at once. A sidecar revoked in the log loses
// its leases to the sweep the revocation's load queues, with a SOCKET_HINT_REVOKED for each, gets no ticket and
// has its next page refused; a client removed through {X}c_removed is answered 401 from memory at once, before any
// store work, and its leases and pairs end with no hint.

package sidecartest_test

import (
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The SOCKET_HINT_REVOKED hints the Net's push gave clientId.
func socketSuiteRevokedHints(t *testing.T, world *socketSuiteWorld, clientId connect.Id) int {
	t.Helper()
	count := 0
	for _, hint := range world.net.Fakes().Push.Hints(clientId) {
		message := &protocol.SocketHint{}
		if hint.Topic == sidecar.PushTopicSock && proto.Unmarshal(hint.Body, message) == nil && message.GetKind() == protocol.SocketHintKind_SOCKET_HINT_REVOKED {
			count += 1
		}
	}
	return count
}

// X revoked in the log: the revocation's event loads it, its load queues the network's sweep, which removes X's
// leases for cause and hints X once for each; a Find gets no ticket for X, and X's next page is refused.
func TestSocketRevocationEndsTheRevokedSidecarsSockets(t *testing.T) {
	world := newSocketSuiteWorld(t, nil)
	names := []string{"app/db", "app/cache"}
	registrations := []*sidecar.SocketRegistration{}
	for _, name := range names {
		registrations = append(registrations, world.registration(world.listener, name, 256))
	}
	world.registerOk(world.listener, 1, registrations...)
	if code, _ := world.find(world.dialer, "app/db"); code != "" {
		t.Fatalf("before the revocation the Find answered %s", code)
	}

	// the network's owner revokes the member's lost device
	world.admission.MustLand(world.admission.Sign(world.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		world.admission.Revocation(world.listener.device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	sweeps, _ := world.engine.Sweeps()
	count, _ := world.gate.Loads()
	world.engine.ProjectionChanged(world.networkId)
	world.awaitLoadsPast(count)
	world.awaitSweepsPast(sweeps)

	for _, name := range names {
		nameToken, err := world.keys.TokenPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if listeners, err := world.store.ListListeners(world.ctx, world.networkId, nameToken); err != nil || len(listeners) != 0 {
			t.Fatalf("a revoked sidecar's lease of %s stands: %d, %v", name, len(listeners), err)
		}
	}
	if hints := socketSuiteRevokedHints(t, world, world.listener.clientId); hints != len(names) {
		t.Fatalf("%d revocation hints for %d leases", hints, len(names))
	}
	signed := world.signedFinds()
	if code, _ := world.find(world.dialer, "app/db"); code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a Find of the revoked sidecar's name answered %s", code)
	}
	if world.signedFinds() != signed {
		t.Fatal("a ticket was signed for a revoked sidecar")
	}
	code, result := world.register(world.listener, 2, nil, nil, registrations)
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("the revoked sidecar's page answered %d, %+v", code, result.Error)
	}
	for index, status := range result.Statuses {
		if status == sidecar.SocketRegistrationStatusOk {
			t.Fatalf("entry %d of a revoked sidecar's page answered ok", index)
		}
	}
}

// {X}c_removed: X's next call answers 401 at once, before the store work runs, and once it has run X's leases are gone
// with no hint, while another client of the network is untouched.
func TestSocketRevocationFailsARemovedClientsTokenAtOnce(t *testing.T) {
	world := newSocketSuiteWorld(t, nil)
	registration := world.registration(world.listener, "app/db", 256)
	world.registerOk(world.listener, 1, registration)
	world.engine.ClientRemoved(world.listener.clientId)
	if code, _ := world.register(world.listener, 2, nil, nil, []*sidecar.SocketRegistration{registration}); code != http.StatusUnauthorized {
		t.Fatalf("a removed client's page answered %d", code)
	}
	result := &sidecar.SocketFindResult{}
	nameToken, _ := world.keys.TokenPath("app/db")
	networkId := world.networkId
	if code := world.call(http.MethodPost, "/socket/find", world.listener.token, &sidecar.SocketFindArgs{NameToken: nameToken, NetworkId: &networkId}, result); code != http.StatusUnauthorized {
		t.Fatalf("a removed client's Find answered %d", code)
	}
	world.awaitRemovals(1)
	if listeners, err := world.store.ListListeners(world.ctx, world.networkId, nameToken); err != nil || len(listeners) != 0 {
		t.Fatalf("a removed client's lease stands: %d, %v", len(listeners), err)
	}
	if hints := world.net.Fakes().Push.Hints(world.listener.clientId); len(hints) != 0 {
		t.Fatalf("a removed client was hinted %d times", len(hints))
	}
	if code, _ := world.find(world.dialer, "app/db"); code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("the other client's Find answered %s", code)
	}
}
