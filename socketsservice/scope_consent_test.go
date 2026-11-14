// SOCK-M6-01's Team scope hosts at the production gate (§9.4, §8.5; owner decisions 40, 126) on a network's real log: a
// scope host stands only for a scope the verified state holds and, in a member scope, only for one of that member's
// consented devices. The state's Team scopes come through the gate's SocketScopeSource, which a host sets once §7.9's
// rows carry TeamScopeRow; with none set, every scope host is refused, the closed direction.

package socketsservice_test

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A scope host refused for a scope absent from the state and from an unconsented device, and served for a consented
// one; a tag scope takes any device; and with no source every scope host is refused.
func TestScopeHostNeedsTheScopeAndTheMembersConsent(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	process.awaitLoaded(network.networkId)
	gate := process.projection
	consented := connect.Id(network.listener.SidecarId)
	unconsented := connect.Id(network.dialer.SidecarId)

	if err := gate.ConsentListen(network.networkId, "eng", &consented); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("with no scope source a scope host answered %v", err)
	}

	gate.SetScopeSource(func(snapshot *sidecar.AclGateSnapshot, label string) (sidecar.AclScope, bool) {
		switch label {
		case "eng":
			return sidecar.AclScope{Label: label, MemberId: network.memberId}, true
		case "ops":
			return sidecar.AclScope{Label: label}, true
		}
		return sidecar.AclScope{}, false
	})
	if err := gate.ConsentListen(network.networkId, "eng", &consented); err != nil {
		t.Fatalf("the member's consented device was refused its scope: %v", err)
	}
	if err := gate.ConsentListen(network.networkId, "eng", &unconsented); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("an unconsented device answered %v", err)
	}
	if err := gate.ConsentListen(network.networkId, "eng", nil); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("no sidecar answered %v", err)
	}
	if err := gate.ConsentListen(network.networkId, "ops", &unconsented); err != nil {
		t.Fatalf("a tag scope refused a device: %v", err)
	}
	if err := gate.ConsentListen(network.networkId, "absent", &consented); !errors.Is(err, socketsservice.ErrSocketListenRefused) {
		t.Fatalf("a scope the state does not hold answered %v", err)
	}
	if err := gate.ConsentListen(connect.NewId(), "eng", &consented); !errors.Is(err, socketsservice.ErrSocketListenUnavailable) {
		t.Fatalf("a network not loaded answered %v", err)
	}

	// the view judges a scope host the same way: a scope the state does not hold is no listen or publish, whatever the
	// grants, and a member scope's host is its consented devices' alone
	view := process.awaitLoaded(network.networkId)
	now := world.clock.Now()
	for _, name := range []string{"tls/443/blog.absent", "smtp/25/mx.absent"} {
		request := &socketsservice.SocketGateRequest{NetworkId: network.networkId, CallerNetworkId: network.networkId, SidecarId: &consented, Name: name}
		if verdict := view.MayListen(request, now); verdict.Allowed {
			t.Fatalf("%s: a scope the state does not hold was listened on", name)
		}
	}
	request := &socketsservice.SocketGateRequest{NetworkId: network.networkId, CallerNetworkId: network.networkId, SidecarId: &unconsented, Name: "tls/443/blog.eng"}
	if verdict := view.MayListen(request, now); verdict.Allowed {
		t.Fatal("an unconsented device listened on its member scope's host")
	}
	if verdict := view.MayPublish(request, now.Add(time.Second)); verdict.Allowed {
		t.Fatal("an unconsented device published its member scope's host")
	}
}
