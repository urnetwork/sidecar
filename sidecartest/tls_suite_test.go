// §22.5's §13 row across components (TLS-M5-25, S5's registration half) on T2's fakes: the socket suite's world, the
// sockets engine on the production gate over a network's real authorization log (socket_suite_test.go), with tls/'s
// ValidateListen registered over a fake listen facts source. What only the composition shows: the publish grant §8's
// evaluator gives a member device for tls/443/blog, under each §13.7 audience, admits the registration; at Community
// a grant of 8 days is refused and one of 7 passes, the 8-day grant ending a lease it held at the next heartbeat once
// the log moves; an unverified network publishes nothing; and a device with no certificate row, or the system publish
// without a receiver's grant, registers nothing. Each component's own rows stay in its task (namespace_tls_test.go's
// refusal table, the gate's and the engine's). Nothing sleeps: loads are awaited by the gate's own count and time is
// the Net's FakeClock.

package sidecartest_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// The socket suite's world with tls/ open over facts the test sets.
type tlsSuiteWorld struct {
	*socketSuiteWorld
	facts *socketsservice.TlsListenFacts
	hooks *socketsservice.TlsNamespaceHooks
}

// A world whose network is verified, at Community, and whose listener holds the network's pair until a day from now.
func newTlsSuiteWorld(t *testing.T) *tlsSuiteWorld {
	t.Helper()
	world := &tlsSuiteWorld{socketSuiteWorld: newSocketSuiteWorld(t, nil)}
	world.facts = &socketsservice.TlsListenFacts{
		Verified: true,
		Standing: sidecar.AbuseStandingStandard,
		Tier:     "free",
		Certs: []*socketsservice.TlsListenCert{
			{SidecarId: connect.Id(world.listener.device.SidecarId), NotAfter: world.net.Clock().Now().Add(24 * time.Hour), NetworkPair: true},
		},
	}
	source := socketsservice.TlsListenFactsFunc(func(ctx context.Context, networkId connect.Id) (*socketsservice.TlsListenFacts, error) {
		if networkId != world.networkId {
			return nil, fmt.Errorf("no such network")
		}
		return world.facts, nil
	})
	hooks, err := socketsservice.NewTlsNamespaceHooks(world.ctx, source, world.net.Clock(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hooks.Close)
	world.hooks = hooks
	if err := world.engine.RegisterNamespace(sidecar.SocketNamespaceTls, hooks); err != nil {
		t.Fatal(err)
	}
	world.loadFacts()
	return world
}

// Has the hooks read the facts as they now stand.
func (self *tlsSuiteWorld) loadFacts() {
	self.t.Helper()
	if err := self.hooks.LoadFacts(self.ctx, self.networkId); err != nil {
		self.t.Fatal(err)
	}
}

// Saves a policy giving members publish and listen on tls/443/blog's host under audience, expiring at expires, and
// has the gate load it.
func (self *tlsSuiteWorld) savePublish(audience string, expires time.Time) {
	self.t.Helper()
	self.admission.SaveAclPolicy([]byte(fmt.Sprintf(`{"grants": [
		{ "src": ["autogroup:member"], "dst": ["sock:app/*"], "allow": ["listen", "dial"] },
		{ "src": ["autogroup:member"], "dst": ["dns:blog", "sock:tls/443/blog"], "allow": ["publish", "listen"], "audience": %q, "expires": %q }
	]}`, audience, expires.UTC().Format(time.RFC3339))), sidecartest.AclSaveMembers{})
	count, _ := self.gate.Loads()
	self.engine.ProjectionChanged(self.networkId)
	self.awaitLoadsPast(count)
}

// caller's registration of an edge name, http, with a claim its identity key signs.
func (self *tlsSuiteWorld) edgeRegistration(caller *socketSuiteSidecar, name string) *sidecar.SocketRegistration {
	self.t.Helper()
	listenId := connect.NewId()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.SocketRegistrationClaim{
		NetworkId: self.networkId.Bytes(),
		Name:      name,
		ListenId:  listenId.Bytes(),
		Protocol:  "tls",
		AppMode:   "http",
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed := &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(caller.device.Key, bridge.SignedBytes(sidecar.SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION, body)),
		Type:      uint32(bridge.SignedType_SIGNED_SOCKET_REGISTRATION),
	}
	claim, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	return &sidecar.SocketRegistration{
		Name:       name,
		ListenId:   &listenId,
		Protocol:   "tls",
		AppMode:    "http",
		Alpn:       []string{"h2", "http/1.1"},
		Weight:     100,
		MaxStreams: 256,
		Serving:    true,
		Claim:      claim,
	}
}

// The one entry's status on a whole-set page.
func (self *tlsSuiteWorld) status(caller *socketSuiteSidecar, setVersion uint64, registration *sidecar.SocketRegistration) sidecar.SocketRegistrationStatus {
	self.t.Helper()
	code, result := self.register(caller, setVersion, nil, nil, []*sidecar.SocketRegistration{registration})
	if code != http.StatusOK || result.Error != nil {
		self.t.Fatalf("the page answered %d, %+v", code, result.Error)
	}
	return result.Statuses[0]
}

// S5 on the log: each §13.7 audience's grant admits a member device's tls/443/blog; at Community a 7-day grant passes
// and an 8-day one is refused, ending the lease at the next heartbeat once the log carries it.
func TestTlsSuiteAdmitsEachAudienceAndHoldsCommunityToSevenDays(t *testing.T) {
	world := newTlsSuiteWorld(t)
	now := world.net.Clock().Now()
	setVersion := uint64(0)
	for _, audience := range []string{"members", "members-device", "link", "public"} {
		world.savePublish(audience, now.Add(7*24*time.Hour))
		setVersion += 1
		if status := world.status(world.listener, setVersion, world.edgeRegistration(world.listener, "tls/443/blog")); status != sidecar.SocketRegistrationStatusOk {
			t.Fatalf("a %s grant of 7 days answered %s", audience, status)
		}
	}
	registration := world.edgeRegistration(world.listener, "tls/443/blog")
	setVersion += 1
	if status := world.status(world.listener, setVersion, registration); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the lease answered %s", status)
	}
	world.savePublish("public", now.Add(8*24*time.Hour))
	setVersion += 1
	if status := world.status(world.listener, setVersion, registration); status != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("an 8-day grant at Community answered %s", status)
	}
	// at Pro the same grant passes
	world.facts = &socketsservice.TlsListenFacts{Verified: true, Standing: sidecar.AbuseStandingStandard, Tier: "pro", Certs: world.facts.Certs}
	world.loadFacts()
	setVersion += 1
	if status := world.status(world.listener, setVersion, world.edgeRegistration(world.listener, "tls/443/blog")); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("an 8-day grant at Pro answered %s", status)
	}
}

// An unverified network publishes nothing, a device holding no certificate row registers nothing, and a host the policy
// gives no publish grant is refused, all on the log's own grants.
func TestTlsSuiteRefusesWhatTheGrantsOrFactsDoNotAllow(t *testing.T) {
	world := newTlsSuiteWorld(t)
	world.savePublish("public", world.net.Clock().Now().Add(24*time.Hour))
	if status := world.status(world.dialer, 1, world.edgeRegistration(world.dialer, "tls/443/blog")); status != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a device with no certificate row answered %s", status)
	}
	if status := world.status(world.listener, 1, world.edgeRegistration(world.listener, "tls/443/shop")); status != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a host with no publish grant answered %s", status)
	}
	if status := world.status(world.listener, 2, world.edgeRegistration(world.listener, "tls/443/blog")); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the granted host answered %s", status)
	}
	world.facts = &socketsservice.TlsListenFacts{Verified: false, Standing: sidecar.AbuseStandingStandard, Tier: "free", Certs: world.facts.Certs}
	world.loadFacts()
	if status := world.status(world.listener, 3, world.edgeRegistration(world.listener, "tls/443/blog")); status == sidecar.SocketRegistrationStatusOk {
		t.Fatal("an unverified network's publish was admitted")
	}
	// the system publish needs a receiver's smtp/25/mx grant, which no member holds here
	world.facts = &socketsservice.TlsListenFacts{Verified: true, Standing: sidecar.AbuseStandingStandard, Tier: "free", MailNetwork: true, Certs: world.facts.Certs}
	world.loadFacts()
	if status := world.status(world.listener, 4, world.edgeRegistration(world.listener, sidecar.SocketSystemPublishName)); status != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("the system publish with no receiver's grant answered %s", status)
	}
}
