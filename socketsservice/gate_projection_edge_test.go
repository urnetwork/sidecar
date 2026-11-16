// The production gate's edge path (SOCK-M5-07 on ACL-M5-01; §9.10, §13.5 step 4, §8.10; QD-852) on a network's real
// authorization log: an urnetwork-edge caller's tls/ dial and publish is a visitor's Find as autogroup:public, made
// before any listener is picked. It goes on under any audience's publish of the name, members, members-device, link
// or public, since only the listener's front judges the audience, and is refused where no publish grant names the
// host. The world is gate_projection_test.go's.

package socketsservice_test

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// One host a policy publishes, with what its grant says.
type testGatePublish struct {
	host     string
	audience string
	// publish with no listen on the host's tls/443 name: no grant a registration could take
	publishOnly bool
}

// Saves a policy with the members' grant on app/db and, for each publish, the members' publish and listen on its
// host's tls/443 name under its audience for a day. The base's position.
func (self *testGateNetwork) savePublishes(now time.Time, publishes ...*testGatePublish) uint64 {
	self.t.Helper()
	grants := []string{`{ "src": ["autogroup:member"], "dst": ["sock:app/db"], "allow": ["listen", "dial"] }`}
	expires := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for _, publish := range publishes {
		dst, allow := fmt.Sprintf(`"dns:%s", "sock:tls/443/%s"`, publish.host, publish.host), `"publish", "listen"`
		if publish.publishOnly {
			dst, allow = fmt.Sprintf(`"dns:%s"`, publish.host), `"publish"`
		}
		grants = append(grants, fmt.Sprintf(`{ "src": ["autogroup:member"], "dst": [%s], "allow": [%s], "audience": %q, "expires": %q }`,
			dst, allow, publish.audience, expires))
	}
	_, pin := self.admission.SaveAclPolicy([]byte(`{"grants": [`+strings.Join(grants, ",\n")+`]}`), sidecartest.AclSaveMembers{})
	return pin.GetVersion()
}

// An edge client's request about name in the network, as Find's dial check builds it: no sidecar, the caller's
// network urnetwork-edge.
func (self *testSocketEdge) gateRequest(world *testSocketWorld, networkId connect.Id, name string) *socketsservice.SocketGateRequest {
	return &socketsservice.SocketGateRequest{
		NetworkId:       networkId,
		CallerClientId:  self.clientId,
		CallerNetworkId: world.edgeNetworkId,
		SubjectClientId: self.clientId,
		Name:            name,
	}
}

// An edge's tls/ dial and publish pass under each §13.7 audience's publish, at the view's position and carrying the
// grant the name stands on, the same one the listener's own registration reads; the gate judges no audience.
func TestGateEdgeFindPassesUnderEachAudiencesPublish(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	edge := world.newEdge(4)
	publishes := []*testGatePublish{
		{host: "members-site", audience: "members"},
		{host: "device-site", audience: "members-device"},
		{host: "link-site", audience: "link"},
		{host: "public-site", audience: "public"},
	}
	position := network.savePublishes(world.clock.Now(), publishes...)
	view := process.awaitLoaded(network.networkId)
	if view.Position() != position {
		t.Fatalf("the view stands at %d, the policy's base at %d", view.Position(), position)
	}
	now := world.clock.Now()
	listenerSidecarId := connect.Id(network.listener.SidecarId)
	for _, publish := range publishes {
		name := "tls/443/" + publish.host
		request := edge.gateRequest(world, network.networkId, name)
		dial, published := view.MayDial(request, now), view.MayPublish(request, now)
		if !dial.Allowed || !published.Allowed {
			t.Errorf("%s: an edge's dial allowed %t, its publish %t", publish.audience, dial.Allowed, published.Allowed)
			continue
		}
		grant := view.PublishGrant(&socketsservice.SocketGateRequest{
			NetworkId:       network.networkId,
			CallerNetworkId: network.networkId,
			SidecarId:       &listenerSidecarId,
			Name:            name,
		}, "http", now)
		if grant == nil || len(grant.GrantIds) != 1 {
			t.Errorf("%s: the listener's own grant %+v", publish.audience, grant)
			continue
		}
		for _, verdict := range []*socketsservice.SocketGateVerdict{dial, published} {
			if verdict.PolicyVersion != position || !bytes.Equal(verdict.GrantId, grant.GrantIds[0]) ||
				verdict.GrantExpireMillis != uint64(grant.ExpiresMs) || verdict.GrantExpireMillis == 0 {
				t.Errorf("%s: the edge's verdict %+v, the listener's grant %+v", publish.audience, verdict, grant)
			}
		}
	}
}

// An edge's tls/ dial and publish are refused where no publish grant names the host, where the only grant is one no
// registration could take, and on every name that is no tls/ name; and a caller that is no edge gets none of it.
func TestGateEdgeFindNeedsAPublishGrant(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	edge := world.newEdge(4)
	network.savePublishes(world.clock.Now(),
		&testGatePublish{host: "members-site", audience: "members"},
		&testGatePublish{host: "no-listen", audience: "public", publishOnly: true},
	)
	view := process.awaitLoaded(network.networkId)
	now := world.clock.Now()
	refused := []struct {
		name    string
		request *socketsservice.SocketGateRequest
	}{
		{name: "a host no grant names", request: edge.gateRequest(world, network.networkId, "tls/443/absent")},
		{name: "another port of a granted host", request: edge.gateRequest(world, network.networkId, "tls/8443/members-site")},
		{name: "a publish without listen", request: edge.gateRequest(world, network.networkId, "tls/443/no-listen")},
		{name: "an smtp/ name", request: edge.gateRequest(world, network.networkId, "smtp/25/mx")},
		{name: "a ur/ name", request: edge.gateRequest(world, network.networkId, "ur/smtpedge")},
		{name: "no name", request: edge.gateRequest(world, network.networkId, "")},
		{name: "a blinded name", request: func() *socketsservice.SocketGateRequest {
			request := edge.gateRequest(world, network.networkId, "")
			request.NameToken = network.tokenPath
			return request
		}()},
		{name: "a caller with no sidecar that is no edge", request: &socketsservice.SocketGateRequest{
			NetworkId:       network.networkId,
			CallerClientId:  edge.clientId,
			CallerNetworkId: network.networkId,
			Name:            "tls/443/members-site",
		}},
		{name: "another network's caller with no sidecar", request: &socketsservice.SocketGateRequest{
			NetworkId:       network.networkId,
			CallerClientId:  edge.clientId,
			CallerNetworkId: connect.NewId(),
			Name:            "tls/443/members-site",
		}},
	}
	for _, c := range refused {
		if dial, published := view.MayDial(c.request, now), view.MayPublish(c.request, now); dial.Allowed || published.Allowed {
			t.Errorf("%s: dial allowed %t, publish allowed %t", c.name, dial.Allowed, published.Allowed)
		}
	}
	// the grant stands, so the refusals above are each its own
	request := edge.gateRequest(world, network.networkId, "tls/443/members-site")
	if !view.MayDial(request, now).Allowed {
		t.Fatal("the granted name was refused")
	}
	// and it ends with the grant: past its expiry the same view refuses
	if view.MayDial(request, now.Add(25*time.Hour)).Allowed || view.MayPublish(request, now.Add(25*time.Hour)).Allowed {
		t.Fatal("an edge's Find outlived the publish grant")
	}

	// a sidecar's dial of a tls/ name stays no sidecar's to make
	dialerSidecarId := connect.Id(network.dialer.SidecarId)
	if verdict := view.MayDial(&socketsservice.SocketGateRequest{
		NetworkId:       network.networkId,
		CallerNetworkId: network.networkId,
		SidecarId:       &dialerSidecarId,
		Name:            "tls/443/members-site",
	}, now); verdict.Allowed {
		t.Fatal("a sidecar dialed a tls/ name")
	}
}

// Through the engine's route: an edge's Find of a name a members publish grants passes the dial check and reaches the
// pick, which finds no listener, while a name no grant names is denied before any group is read; once the policy
// drops the grant and the gate has loaded it, the same Find is denied.
func TestGateEdgeFindReachesThePickOnlyUnderAGrant(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	edge := world.newEdge(4)
	network.savePublishes(world.clock.Now(), &testGatePublish{host: "members-site", audience: "members"})
	process.awaitLoaded(network.networkId)
	networkId := network.networkId
	find := func(name string) sidecar.SocketErrorCode {
		t.Helper()
		code, result := process.find(edge.token, &sidecar.SocketFindArgs{Name: name, NetworkId: &networkId, ClientIds: edge.clientIdArgs()})
		if code != http.StatusOK || result.Error == nil {
			t.Fatalf("an edge's Find of %s answered %d, %+v", name, code, result)
		}
		return result.Error.Code
	}
	if code := find("tls/443/members-site"); code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("an edge's Find under a members publish answered %s", code)
	}
	if code := find("tls/443/absent"); code != sidecar.SocketErrorCodeDenied {
		t.Fatalf("an edge's Find with no publish answered %s", code)
	}
	if process.service.SignedTicketCount() != 0 {
		t.Fatal("a Find with no listener got a ticket")
	}

	network.savePublishes(world.clock.Now())
	process.changed(networkId)
	if code := find("tls/443/members-site"); code != sidecar.SocketErrorCodeDenied {
		t.Fatalf("an edge's Find after the grant left the policy answered %s", code)
	}
}

// A scope host's edge Find stands only for a scope the state holds, and a member scope's only on a grant of its
// member's consented devices, as a registration is held (§9.4, §8.5); with no scope source every scope host is refused.
func TestGateEdgeFindHoldsAScopeHostToItsScope(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	edge := world.newEdge(4)
	// a policy names no scope host until the network's scopes resolve (Q-TLS-3), so the grant takes every host
	network.savePublishes(world.clock.Now(), &testGatePublish{host: "*", audience: "members"})
	view := process.awaitLoaded(network.networkId)
	now := world.clock.Now()
	allowed := func(name string) bool {
		request := edge.gateRequest(world, network.networkId, name)
		dial, published := view.MayDial(request, now), view.MayPublish(request, now)
		if dial.Allowed != published.Allowed {
			t.Fatalf("%s: dial allowed %t, publish allowed %t", name, dial.Allowed, published.Allowed)
		}
		return dial.Allowed
	}
	for _, name := range []string{"tls/443/blog.eng", "tls/443/blog.ops", "tls/443/blog.solo"} {
		if allowed(name) {
			t.Fatalf("%s: with no scope source a scope host's edge Find passed", name)
		}
	}
	process.projection.SetScopeSource(func(snapshot *sidecar.AclGateSnapshot, label string) (sidecar.AclScope, bool) {
		switch label {
		case "eng":
			// the listener is this member's consented device
			return sidecar.AclScope{Label: label, MemberId: network.memberId}, true
		case "ops":
			return sidecar.AclScope{Label: label}, true
		case "solo":
			// a member none of whose devices holds the grant
			return sidecar.AclScope{Label: label, MemberId: sidecar.NewId()}, true
		}
		return sidecar.AclScope{}, false
	})
	if !allowed("tls/443/blog.eng") {
		t.Fatal("a member scope's host was refused under its member's consented device's grant")
	}
	if !allowed("tls/443/blog.ops") {
		t.Fatal("a tag scope's host was refused under a member's grant")
	}
	if allowed("tls/443/blog.solo") {
		t.Fatal("a member scope's host passed on another member's device's grant")
	}
	if allowed("tls/443/blog.absent") {
		t.Fatal("a scope the state does not hold passed")
	}
}
