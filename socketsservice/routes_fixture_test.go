// The fixture the route tests share (T2): engines on fake hosts over one FakeSocketStore and one fake clock,
// each with a FakeSocketGate of its own, so two engines are two sockets processes at two positions; sidecars
// that hold client tokens and identity keys and sign their claims; and edges with K platform clients. A store
// call may be held at a hook, which is how a test puts a revocation between a call's judgment and its write
// on every leg, with no sleep.

package socketsservice_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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

// A store whose calls a test may hold or follow: each hook, when set, runs on the call's goroutine before or
// after the call it names, and a hook that blocks holds the call there.
type testSocketHookStore struct {
	socketsservice.SocketStore
	beforeApplyPage func(page *socketsservice.SocketStorePage)
	afterPick       func(result *socketsservice.SocketStorePickResult)
}

// See socketsservice.SocketStore.
func (self *testSocketHookStore) ApplyPage(ctx context.Context, page *socketsservice.SocketStorePage) (*socketsservice.SocketStorePageResult, error) {
	if hook := self.beforeApplyPage; hook != nil {
		hook(page)
	}
	return self.SocketStore.ApplyPage(ctx, page)
}

// See socketsservice.SocketStore.
func (self *testSocketHookStore) Pick(ctx context.Context, request *socketsservice.SocketStorePickRequest) (*socketsservice.SocketStorePickResult, error) {
	result, err := self.SocketStore.Pick(ctx, request)
	if hook := self.afterPick; hook != nil && err == nil {
		hook(result)
	}
	return result, err
}

// What every process of one test shares: the clock, the store, the tokens' issuer and the ticket key.
type testSocketWorld struct {
	t             *testing.T
	ctx           context.Context
	clock         *sidecartest.FakeClock
	fakeStore     *sidecartest.FakeSocketStore
	store         *testSocketHookStore
	authenticator *sidecartest.FakeAuthenticator
	authFaults    *sidecartest.FaultQueue
	edgeNetworkId connect.Id
	ticketKeys    *testSocketTicketKeys
}

// A world at the default clock start, with no process yet.
func newTestSocketWorld(t *testing.T) *testSocketWorld {
	t.Helper()
	return newTestSocketWorldOn(t, sidecartest.NewFakeClock(sidecartest.DefaultClockStart()))
}

// A world on clock, which another fixture shares, with no process yet.
func newTestSocketWorldOn(t *testing.T, clock *sidecartest.FakeClock) *testSocketWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	fakeStore := sidecartest.NewFakeSocketStore(clock, nil, nil)
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authFaults := sidecartest.NewFaultQueue()
	return &testSocketWorld{
		t:             t,
		ctx:           ctx,
		clock:         clock,
		fakeStore:     fakeStore,
		store:         &testSocketHookStore{SocketStore: fakeStore},
		authenticator: sidecartest.NewFakeAuthenticator(clock, authFaults),
		authFaults:    authFaults,
		edgeNetworkId: testSocketId(),
		ticketKeys:    &testSocketTicketKeys{privateKey: privateKey},
	}
}

// One sockets process: an engine, its host and its gate, a fake one or, for gate_projection_test.go's processes,
// the production gate.
type testSocketProcess struct {
	world      *testSocketWorld
	host       *sidecartest.FakeHost
	gate       *sidecartest.FakeSocketGate
	projection *socketsservice.SocketProjectionGate
	service    *socketsservice.SocketsService
}

// A process with the defaults, or settings changed by mutate, with §19.11's sockets gate open to every
// network and urnetwork_edge set.
func (self *testSocketWorld) newProcess(mutate func(settings *socketsservice.SocketsSettings)) *testSocketProcess {
	self.t.Helper()
	host := sidecartest.NewFakeHost(self.ctx, self.clock, nil, nil, nil)
	gates := "sidecar:\n  sockets: {enabled: true, percent: 100}\n  urnetwork_edge: " + self.edgeNetworkId.String() + "\n"
	if err := host.Gates.Set(gates); err != nil {
		self.t.Fatal(err)
	}
	serviceHost := host.ServiceHost()
	serviceHost.Authenticator = self.authenticator
	settings := socketsservice.DefaultSocketsSettings()
	if mutate != nil {
		mutate(settings)
	}
	edgeNetworkId := self.edgeNetworkId
	gate := sidecartest.NewFakeSocketGate(self.clock, &edgeNetworkId)
	service, err := socketsservice.NewSocketsService(self.ctx, serviceHost, self.store, gate, settings)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(service.Close)
	service.SetTicketKeys(self.ticketKeys)
	return &testSocketProcess{world: self, host: host, gate: gate, service: service}
}

// A sidecar of one network: its client, its sidecar id and identity key, and its token.
type testSocketSidecar struct {
	networkId   connect.Id
	clientId    connect.Id
	sidecarId   connect.Id
	identityKey ed25519.PrivateKey
	token       string
}

// A sidecar of networkId with a token for SocketsAudience.
func (self *testSocketWorld) newSidecar(networkId connect.Id) *testSocketSidecar {
	self.t.Helper()
	_, identityKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		self.t.Fatal(err)
	}
	sidecarId := testSocketId()
	listener := &testSocketSidecar{
		networkId:   networkId,
		clientId:    testSocketId(),
		sidecarId:   sidecarId,
		identityKey: identityKey,
	}
	listener.token = self.authenticator.Issue(&sidecar.Principal{
		NetworkId: networkId,
		ClientId:  listener.clientId,
		SidecarId: &sidecarId,
		Audience:  socketsservice.SocketsAudience,
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(24 * time.Hour),
	})
	return listener
}

// The sidecar's public identity key.
func (self *testSocketSidecar) publicKey() []byte {
	return self.identityKey.Public().(ed25519.PublicKey)
}

// A marshaled §6 Signed by key over the claim (§9.5).
func testSocketSignClaim(t *testing.T, key ed25519.PrivateKey, claim *protocol.SocketRegistrationClaim) []byte {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	signed := &bridge.Signed{
		Body:      body,
		Signature: ed25519.Sign(key, bridge.SignedBytes(sidecar.SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION, body)),
		Type:      uint32(bridge.SignedType_SIGNED_SOCKET_REGISTRATION),
	}
	claimBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return claimBytes
}

// An edge name's registration with a fresh listen id, protocol as given, and a claim this sidecar signs.
func (self *testSocketSidecar) edgeRegistration(t *testing.T, name string, protocolName string, appMode string) *sidecar.SocketRegistration {
	t.Helper()
	listenId := testSocketId()
	registration := &sidecar.SocketRegistration{
		Name:       name,
		ListenId:   &listenId,
		Protocol:   protocolName,
		AppMode:    appMode,
		Weight:     100,
		MaxStreams: 256,
		Serving:    true,
	}
	registration.Claim = testSocketSignClaim(t, self.identityKey, &protocol.SocketRegistrationClaim{
		NetworkId: self.networkId.Bytes(),
		Name:      name,
		ListenId:  listenId.Bytes(),
		Protocol:  protocolName,
		AppMode:   appMode,
	})
	return registration
}

// A blinded name's registration: the token path, a seal the service never opens, and this sidecar's claim.
func (self *testSocketSidecar) blindedRegistration(t *testing.T, nameToken []byte) *sidecar.SocketRegistration {
	t.Helper()
	listenId := testSocketId()
	sealedName := make([]byte, 152)
	if _, err := rand.Read(sealedName); err != nil {
		t.Fatal(err)
	}
	registration := &sidecar.SocketRegistration{
		NameToken:  bytes.Clone(nameToken),
		SealedName: sealedName,
		ListenId:   &listenId,
		Protocol:   "tcp",
		Weight:     100,
		MaxStreams: 256,
		Serving:    true,
	}
	registration.Claim = testSocketSignClaim(t, self.identityKey, &protocol.SocketRegistrationClaim{
		NetworkId: self.networkId.Bytes(),
		NameToken: nameToken,
		ListenId:  listenId.Bytes(),
		Protocol:  "tcp",
	})
	return registration
}

// A random token path of segmentCount segments.
func testSocketTokenPath(t *testing.T, segmentCount int) []byte {
	t.Helper()
	nameToken := make([]byte, 16*segmentCount)
	if _, err := rand.Read(nameToken); err != nil {
		t.Fatal(err)
	}
	return nameToken
}

// registrations sorted by name key, as a page sends them.
func testSocketSortRegistrations(registrations []*sidecar.SocketRegistration) []*sidecar.SocketRegistration {
	sorted := slices.Clone(registrations)
	slices.SortFunc(sorted, func(a *sidecar.SocketRegistration, b *sidecar.SocketRegistration) int {
		return bytes.Compare(a.NameKey(), b.NameKey())
	})
	return sorted
}

// An edge process: its own platform client's token, in urnetwork-edge, and its K clients.
type testSocketEdge struct {
	clientId  connect.Id
	clientIds []connect.Id
	token     string
}

// An edge with k clients.
func (self *testSocketWorld) newEdge(k int) *testSocketEdge {
	edge := &testSocketEdge{clientId: testSocketId()}
	for range k {
		edge.clientIds = append(edge.clientIds, testSocketId())
	}
	edge.token = self.authenticator.Issue(&sidecar.Principal{
		NetworkId: self.edgeNetworkId,
		ClientId:  edge.clientId,
		Audience:  socketsservice.SocketsAudience,
		IssuedAt:  self.clock.Now(),
		ExpiresAt: self.clock.Now().Add(24 * time.Hour),
	})
	return edge
}

// The edge's K ids as a Find sends them.
func (self *testSocketEdge) clientIdArgs() []*connect.Id {
	clientIds := []*connect.Id{}
	for _, clientId := range self.clientIds {
		copied := clientId
		clientIds = append(clientIds, &copied)
	}
	return clientIds
}

// One call to the engine's handler with token, nil body for a GET.
func (self *testSocketProcess) call(method string, path string, token string, body any) *httptest.ResponseRecorder {
	self.world.t.Helper()
	var request *http.Request
	if body == nil {
		request = httptest.NewRequest(method, path, nil)
	} else {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			self.world.t.Fatal(err)
		}
		request = httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	self.service.Handler().ServeHTTP(recorder, request)
	return recorder
}

// POST /socket/registrations as token's holder: the status, and the body when it is 200.
func (self *testSocketProcess) register(token string, args *sidecar.SocketRegistrationsArgs) (int, *sidecar.SocketRegistrationsResult) {
	self.world.t.Helper()
	recorder := self.call(http.MethodPost, "/socket/registrations", token, args)
	if recorder.Code != http.StatusOK {
		return recorder.Code, nil
	}
	result := &sidecar.SocketRegistrationsResult{}
	if err := json.Unmarshal(recorder.Body.Bytes(), result); err != nil {
		self.world.t.Fatal(err)
	}
	return recorder.Code, result
}

// One whole-set page of registrations as listener, under setVersion, every status required ok.
func (self *testSocketProcess) registerOk(listener *testSocketSidecar, setVersion uint64, registrations ...*sidecar.SocketRegistration) {
	self.world.t.Helper()
	code, result := self.register(listener.token, &sidecar.SocketRegistrationsArgs{
		SetVersion:    setVersion,
		Registrations: testSocketSortRegistrations(registrations),
	})
	if code != http.StatusOK || result.Error != nil {
		self.world.t.Fatalf("registration answered %d, %+v", code, result)
	}
	for index, status := range result.Statuses {
		if status != sidecar.SocketRegistrationStatusOk {
			self.world.t.Fatalf("entry %d answered %s", index, status)
		}
	}
}

// POST /socket/find as token's holder: the status, and the body when it is 200.
func (self *testSocketProcess) find(token string, args *sidecar.SocketFindArgs) (int, *sidecar.SocketFindResult) {
	self.world.t.Helper()
	recorder := self.call(http.MethodPost, "/socket/find", token, args)
	if recorder.Code != http.StatusOK {
		return recorder.Code, nil
	}
	result := &sidecar.SocketFindResult{}
	if err := json.Unmarshal(recorder.Body.Bytes(), result); err != nil {
		self.world.t.Fatal(err)
	}
	return recorder.Code, result
}

// GET /socket/list with cursor.
func (self *testSocketProcess) list(token string, cursor string) (int, *sidecar.SocketListResult) {
	self.world.t.Helper()
	path := "/socket/list"
	if cursor != "" {
		path += "?cursor=" + url.QueryEscape(cursor)
	}
	recorder := self.call(http.MethodGet, path, token, nil)
	if recorder.Code != http.StatusOK {
		return recorder.Code, nil
	}
	result := &sidecar.SocketListResult{}
	if err := json.Unmarshal(recorder.Body.Bytes(), result); err != nil {
		self.world.t.Fatal(err)
	}
	return recorder.Code, result
}

// The ticket a Find returned, verified under the world's key at the clock's now.
func (self *testSocketWorld) verifyTicket(findTicket *sidecar.SocketFindTicket) *protocol.SocketTicket {
	self.t.Helper()
	if findTicket == nil {
		self.t.Fatal("no ticket")
	}
	ticket, err := sidecar.VerifySocketTicket(findTicket.Ticket, self.ticketKeys.VerifyKeys(), uint64(self.clock.Now().UnixMilli()))
	if err != nil {
		self.t.Fatalf("ticket: %v", err)
	}
	return ticket
}

// A grant that never expires, with an id.
func testSocketGrant(label string) sidecartest.FakeSocketGrant {
	return sidecartest.FakeSocketGrant{GrantId: []byte("grant-" + label)}
}
