// The ur/ namespace on the engine (SOCK-M9-01, T2 on the route fixture): only an urnetwork-edge client lists
// ur/<service>, for a named service and with no claim; any enrolled sidecar Finds it with no §8 grant, across networks,
// paying from its own network; its tickets run the service's grant, and its pair is field <edge> of {svc_<sidecar>}
// (QD-728), living the grant's life and ending with the sidecar's removal.

package socketsservice_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A ur/ registration as a platform client sends it: in the clear, with no claim.
func testPlatformRegistration(name string) *sidecar.SocketRegistration {
	listenId := testSocketId()
	return &sidecar.SocketRegistration{
		Name:       name,
		ListenId:   &listenId,
		Protocol:   "tcp",
		Weight:     100,
		MaxStreams: 256,
		Serving:    true,
	}
}

// A process with ur/ open, the edge network loaded, and the edges' and a sidecar's networks loaded.
func newTestPlatformProcess(t *testing.T, world *testSocketWorld) *testSocketProcess {
	t.Helper()
	process := world.newProcess(nil)
	if err := process.service.RegisterPlatformNamespace(); err != nil {
		t.Fatal(err)
	}
	process.gate.Load(world.edgeNetworkId)
	return process
}

// One page as an edge's platform client.
func (self *testSocketProcess) registerAsEdge(edge *testSocketEdge, setVersion uint64, registrations ...*sidecar.SocketRegistration) *sidecar.SocketRegistrationsResult {
	self.world.t.Helper()
	code, result := self.register(edge.token, &sidecar.SocketRegistrationsArgs{
		SetVersion:    setVersion,
		Registrations: testSocketSortRegistrations(registrations),
	})
	if code != http.StatusOK {
		self.world.t.Fatalf("an edge's page answered %d", code)
	}
	return result
}

// A Find of name in urnetwork-edge by a sidecar.
func (self *testSocketProcess) findPlatform(dialer *testSocketSidecar, name string) *sidecar.SocketFindResult {
	self.world.t.Helper()
	edgeNetworkId := self.world.edgeNetworkId
	code, result := self.find(dialer.token, &sidecar.SocketFindArgs{Name: name, NetworkId: &edgeNetworkId})
	if code != http.StatusOK {
		self.world.t.Fatalf("a Find answered %d", code)
	}
	return result
}

// Only an edge lists ur/smtpedge; a sidecar's entry is denied, as is an edge's for a service no setting names or with a
// claim.
func TestPlatformListenIsAnEdgesAlone(t *testing.T) {
	world := newTestSocketWorld(t)
	process := newTestPlatformProcess(t, world)
	edge := world.newEdge(1)
	result := process.registerAsEdge(edge, 1, testPlatformRegistration("ur/smtpedge"))
	if result.Error != nil || len(result.Statuses) != 1 || result.Statuses[0] != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("an edge's ur/smtpedge answered %+v", result)
	}

	networkId := testSocketId()
	process.gate.Load(networkId)
	listener := world.newSidecar(networkId)
	code, sidecarResult := process.register(listener.token, &sidecar.SocketRegistrationsArgs{
		SetVersion:    1,
		Registrations: []*sidecar.SocketRegistration{testPlatformRegistration("ur/smtpedge")},
	})
	if code != http.StatusOK || sidecarResult.Error != nil || sidecarResult.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a sidecar's ur/ entry answered %d, %+v", code, sidecarResult)
	}

	unknown := process.registerAsEdge(world.newEdge(1), 1, testPlatformRegistration("ur/nosuchservice"))
	if unknown.Error != nil || unknown.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("an unnamed service answered %+v", unknown)
	}
	claimed := testPlatformRegistration("ur/smtpedge")
	claimed.Claim = []byte("a platform client signs no claim")
	withClaim := process.registerAsEdge(world.newEdge(1), 1, claimed)
	if withClaim.Error != nil || withClaim.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("an entry with a claim answered %+v", withClaim)
	}
}

// Any enrolled sidecar, in any network, Finds ur/smtpedge with no §8 grant: a ticket in the clear in urnetwork-edge,
// naming it as the dialer, carrying smtpedge's 125 min grant and no grant id, and a backup when two edges listen.
func TestPlatformFindNeedsNoGrant(t *testing.T) {
	world := newTestSocketWorld(t)
	process := newTestPlatformProcess(t, world)
	edges := []*testSocketEdge{world.newEdge(1), world.newEdge(1)}
	for _, edge := range edges {
		process.registerAsEdge(edge, 1, testPlatformRegistration("ur/smtpedge"))
	}
	for range 2 {
		networkId := testSocketId()
		process.gate.Load(networkId)
		dialer := world.newSidecar(networkId)
		result := process.findPlatform(dialer, "ur/smtpedge")
		if result.Error != nil || result.Primary == nil || result.Backup == nil {
			t.Fatalf("a sidecar's Find answered %+v", result.Error)
		}
		for _, findTicket := range []*sidecar.SocketFindTicket{result.Primary, result.Backup} {
			ticket := world.verifyTicket(findTicket)
			switch {
			case ticket.GetName() != "ur/smtpedge" || len(ticket.GetNameToken()) != 0:
				t.Fatal("a ur/ ticket names no service in the clear")
			case !bytes.Equal(ticket.GetNetworkId(), world.edgeNetworkId.Bytes()):
				t.Fatal("a ur/ ticket is not urnetwork-edge's")
			case !bytes.Equal(ticket.GetDialerClientId(), dialer.clientId.Bytes()) || !bytes.Equal(ticket.GetDialerNetworkId(), networkId.Bytes()):
				t.Fatal("a ur/ ticket names another dialer")
			case ticket.GetGrantExpireTimeMillis() != ticket.GetIssueTimeMillis()+uint64((125*time.Minute).Milliseconds()):
				t.Fatalf("a ur/smtpedge grant ends %d ms after its issue", ticket.GetGrantExpireTimeMillis()-ticket.GetIssueTimeMillis())
			case len(ticket.GetGrantId()) != 0 || ticket.GetPolicyVersion() != 0:
				t.Fatal("a ur/ ticket carries a §8 grant")
			case len(findTicket.Claim) != 0:
				t.Fatal("a ur/ ticket carries a claim")
			}
		}
	}
	// an edge Finds no ur/ name: a pair has one edge end
	edgeNetworkId := world.edgeNetworkId
	if _, result := process.find(edges[0].token, &sidecar.SocketFindArgs{Name: "ur/smtpedge", NetworkId: &edgeNetworkId, ClientIds: edges[0].clientIdArgs()}); result == nil || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeDenied {
		t.Fatal("an edge's ur/ Find was not denied")
	}
}

// The paying network is the caller's: a spent caller answers quota, whatever urnetwork-edge's standing.
func TestPlatformFindPaysFromTheCallersNetwork(t *testing.T) {
	world := newTestSocketWorld(t)
	process := newTestPlatformProcess(t, world)
	process.registerAsEdge(world.newEdge(1), 1, testPlatformRegistration("ur/smtpedge"))
	networkId := testSocketId()
	process.gate.Load(networkId)
	dialer := world.newSidecar(networkId)
	process.gate.SetSpent(networkId, true)
	signed := process.service.SignedTicketCount()
	if result := process.findPlatform(dialer, "ur/smtpedge"); result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeQuota {
		t.Fatalf("a spent caller's ur/ Find answered %+v", result.Error)
	}
	if process.service.SignedTicketCount() != signed {
		t.Fatal("a spent caller's ur/ Find signed")
	}
	process.gate.SetSpent(networkId, false)
	process.gate.SetSpent(world.edgeNetworkId, true)
	if result := process.findPlatform(dialer, "ur/smtpedge"); result.Error != nil {
		t.Fatalf("urnetwork-edge's standing stopped a caller's Find: %+v", result.Error)
	}
}

// QD-728: a ur/ Find's pair is field <edge listener> of {svc_<sidecar dialer>} with the grant's expiry, nothing under the
// edge's key; it lives the grant's 125 min, and the sidecar's removal takes it.
func TestPlatformPairIsKeyedByTheSidecarDialer(t *testing.T) {
	world := newTestSocketWorld(t)
	process := newTestPlatformProcess(t, world)
	edge := world.newEdge(1)
	process.registerAsEdge(edge, 1, testPlatformRegistration("ur/smtpedge"))
	networkId := testSocketId()
	process.gate.Load(networkId)
	dialer := world.newSidecar(networkId)
	result := process.findPlatform(dialer, "ur/smtpedge")
	if result.Error != nil {
		t.Fatalf("the Find answered %+v", result.Error)
	}
	ticket := world.verifyTicket(result.Primary)
	ctx := world.ctx
	grantExpireMillis, found, err := world.fakeStore.GetServicePair(ctx, dialer.clientId, edge.clientId)
	if err != nil || !found || grantExpireMillis != ticket.GetGrantExpireTimeMillis() {
		t.Fatalf("the pair under the dialer: %d, %v, %v", grantExpireMillis, found, err)
	}
	if _, found, _ := world.fakeStore.GetServicePair(ctx, edge.clientId, dialer.clientId); found {
		t.Fatal("a pair stands under the edge's key")
	}
	// a registration of the dialer's never shortens it (QD-656's touch is the edge pairs')
	world.clock.Advance(124 * time.Minute)
	if _, found, _ := world.fakeStore.GetServicePair(ctx, dialer.clientId, edge.clientId); !found {
		t.Fatal("the pair ended before its grant")
	}
	world.clock.Advance(2 * time.Minute)
	if _, found, _ := world.fakeStore.GetServicePair(ctx, dialer.clientId, edge.clientId); found {
		t.Fatal("the pair outlived its grant")
	}

	// a new Find, the edge's lease renewed, writes it again; the dialer's removal takes it
	process.registerAsEdge(edge, 2, testPlatformRegistration("ur/smtpedge"))
	if result := process.findPlatform(dialer, "ur/smtpedge"); result.Error != nil {
		t.Fatalf("the second Find answered %+v", result.Error)
	}
	removals, _ := process.service.Removals()
	process.service.ClientRemoved(dialer.clientId)
	for {
		count, changed := process.service.Removals()
		if removals < count {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal("the removal never ran")
		}
	}
	if _, found, _ := world.fakeStore.GetServicePair(ctx, dialer.clientId, edge.clientId); found {
		t.Fatal("a removed sidecar's ur/ pair stands")
	}
}

// A touch of the dialer's own edge pairs never shortens its ur/ pair, and the pair's write is refused only below a floor
// of the dialer's own network's position.
func TestPlatformPairOutlivesTheDialersEdgeTouch(t *testing.T) {
	world := newTestSocketWorld(t)
	process := newTestPlatformProcess(t, world)
	edge := world.newEdge(1)
	process.registerAsEdge(edge, 1, testPlatformRegistration("ur/smtpedge"))
	networkId := testSocketId()
	process.gate.Load(networkId)
	dialer := world.newSidecar(networkId)
	if result := process.findPlatform(dialer, "ur/smtpedge"); result.Error != nil {
		t.Fatalf("the Find answered %+v", result.Error)
	}
	if err := world.fakeStore.TouchServicePairs(world.ctx, dialer.clientId); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(socketsservice.DefaultSocketStoreSettings().EdgePairTtl + time.Minute)
	if _, found, _ := world.fakeStore.GetServicePair(world.ctx, dialer.clientId, edge.clientId); !found {
		t.Fatal("a touch cut the ur/ pair to an edge pair's life")
	}
	// a removal of the dialer's edge pairs at a position its network's state has not reached refuses the next pair
	process.registerAsEdge(edge, 2, testPlatformRegistration("ur/smtpedge"))
	position := process.gate.Load(networkId)
	if err := world.fakeStore.RemoveServicePairs(world.ctx, dialer.clientId, position+5); err != nil {
		t.Fatal(err)
	}
	if result := process.findPlatform(dialer, "ur/smtpedge"); result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("a pair below the floor answered %+v", result.Error)
	}
	observed := process.gate.Observed(networkId)
	if len(observed) == 0 || observed[len(observed)-1] != position+5 {
		t.Fatalf("the floor reached the dialer's network as evidence: %v", observed)
	}
	process.gate.LoadAt(networkId, position+5)
	if result := process.findPlatform(dialer, "ur/smtpedge"); result.Error != nil {
		t.Fatalf("at the floor's position the Find answered %+v", result.Error)
	}
}
