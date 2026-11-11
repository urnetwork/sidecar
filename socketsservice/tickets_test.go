// Ticket issuance at T2 (SOCK-M5-06): a ticket through the real path keeps within §9.6's bounds at the
// longest name a Find can carry, verifies under the key GET /socket/keys publishes, and is never signed by an
// engine with no key that signs.

package socketsservice_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An 8-segment token path, the longest a Find carries, takes a ticket of at most 370 B and a signed ticket of at
// most 512 B through the real path (§9.6), which verifies under the published key.
func TestSocketTicketKeepsWithinItsBoundAtTheLongestName(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	networkId := testSocketId()
	nameToken := testSocketTokenPath(t, 8)
	dialer := world.newSidecar(networkId)
	listener := world.newSidecar(networkId)
	process.gate.SetIdentityKey(networkId, listener.sidecarId, listener.publicKey())
	process.gate.AllowListen(networkId, listener.sidecarId, nameToken, testSocketGrant("listen"))
	process.gate.AllowDial(networkId, dialer.clientId, nameToken, sidecartest.FakeSocketGrant{GrantId: make([]byte, 16), ExpireMillis: 1 << 62})
	process.gate.LoadAt(networkId, 1<<60)
	process.registerOk(listener, 1, listener.blindedRegistration(t, nameToken))

	code, result := process.find(dialer.token, &sidecar.SocketFindArgs{NameToken: nameToken, NetworkId: &networkId})
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if 512 < len(result.Primary.Ticket) {
		t.Fatalf("a signed ticket of %d bytes", len(result.Primary.Ticket))
	}
	signedTicket := &protocol.SignedSocketTicket{}
	if err := proto.Unmarshal(result.Primary.Ticket, signedTicket); err != nil || 370 < len(signedTicket.GetTicket()) {
		t.Fatalf("a ticket of %d bytes, %v", len(signedTicket.GetTicket()), err)
	}

	recorder := process.call(http.MethodGet, "/socket/keys", "", nil)
	keys := &sidecar.SocketKeysResult{}
	if err := json.Unmarshal(recorder.Body.Bytes(), keys); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.VerifySocketTicket(result.Primary.Ticket, keys.Keys, uint64(world.clock.Now().UnixMilli())); err != nil {
		t.Fatalf("the ticket does not verify under the published key: %v", err)
	}
}

// With no key that signs, a Find that passes every check answers unavailable and signs nothing.
func TestSocketFindSignsNothingWithNoKey(t *testing.T) {
	scene := newTestSocketFindScene(t, 1)
	scene.process.service.SetTicketKeys(&testSocketTicketKeys{})
	code, result := scene.process.find(scene.dialer.token, scene.findArgs())
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Primary != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if count := scene.process.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
}
