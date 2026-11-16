// §22.5's §9 row across components (SOCK-M5-16) on T2's fakes: a sidecartest.Net with the sockets engine added as a
// process of its own (Net.AddEngine) and reached through Net.EngineClient, so the privacy harness captures every
// call as CC1; over FakeSocketStore; on the production gate (SocketProjectionGate) reading the Net's admission world
// through the direct source, so every verdict is §8's on a network's real log, with K_sock in its head and a policy
// giving its members listen and dial on app/*; and on the Net's fake host for Quota, Push and the gates. Each
// component's own rows stay in its task (socketsservice's, the registrar's, the listener's and the dialer's); what
// is here is what only the composition shows: a set of 3,000 names in three pages and the listing that follows it,
// Redis's loss healed by one heartbeat, a looping client shed before anything is signed while another client's
// calls go on, a spent network's quota from the over-limit list, and the one-dialer clamp on a fake clock.
//
// DESIGN-DETAILS 17.2.10's custom names (17.6, 17.7's SOCK-M5-16 line, after TLS-M6-08) run on the same world with
// tls/ open over facts the test sets (tls_suite_test.go's newTlsSuiteWorld) and urnetwork-edge's platform client
// Finding as tlsedge does: the pick's table of acme by custom by an acme-only listener by a visitor with no ALPN, the
// highest claim, the tie and no backup; and ValidateListen's narrowing of a listener's certified and ACME names on the
// production gate's view, the fake store keeping each entry as the hook left it and the pick reading that. The pick's
// own table on the pure function is scheduler_test.go's, the narrowing's own cases namespace_tls_test.go's.
//
// Nothing sleeps: the engine's first probe, the gate's first over-limit read and its worker's first pass are awaited
// by count, loads by the gate's own count against the loads its cache has started, and time moves on the Net's
// FakeClock.

package sidecartest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
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

// The engine's process name on the Net.
const socketSuiteEngine = "sockets"

// A service key for the suite's tickets, which never expires inside a test.
type socketSuiteTicketKeys struct {
	privateKey ed25519.PrivateKey
}

func (self *socketSuiteTicketKeys) SigningKey() (string, ed25519.PrivateKey, bool) {
	return "suite", self.privateKey, true
}

func (self *socketSuiteTicketKeys) VerifyKeys() []*sidecar.SocketTicketKey {
	return []*sidecar.SocketTicketKey{{KeyId: "suite", PublicKey: self.privateKey.Public().(ed25519.PublicKey), ExpireTimeMillis: 1 << 62}}
}

// A device of the network as a sockets caller: its token, its own client and the keys it signs claims with.
type socketSuiteSidecar struct {
	device   *sidecartest.AdmissionDevice
	clientId connect.Id
	token    string
}

// One sockets world: the Net, its admission world, the engine on the production gate, and the network's K_sock.
type socketSuiteWorld struct {
	t             *testing.T
	ctx           context.Context
	net           *sidecartest.Net
	admission     *sidecartest.AdmissionNet
	store         *sidecartest.FakeSocketStore
	gate          *socketsservice.SocketProjectionGate
	engine        *socketsservice.SocketsService
	client        *http.Client
	ticketKeys    *socketSuiteTicketKeys
	networkId     connect.Id
	edgeNetworkId connect.Id
	socketKey     []byte
	keys          *sidecar.SocketKeys
	listener      *socketSuiteSidecar
	dialer        *socketSuiteSidecar
}

// A world whose network has a member with two devices, the listener and the dialer, K_sock in its head and a policy
// giving members listen and dial on app/*, with the engine running and the network loaded. mutate changes the
// engine's settings.
func newSocketSuiteWorld(t *testing.T, mutate func(settings *socketsservice.SocketsSettings)) *socketSuiteWorld {
	t.Helper()
	ctx := t.Context()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	admission := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(admission.Close)
	memberId, listenerDevice := admission.ConsentedMember("m")
	dialerDevice := admission.Device("m second device", memberId)
	admission.AdmitDevice(admission.Owner(), dialerDevice, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	socketKey := bytes.Repeat([]byte{0x3c}, 32)
	net.Capture().AddSecret("sockets K_sock", socketKey)
	keyFileBytes, err := proto.Marshal(&protocol.SocketKeyFile{CurrentKey: socketKey})
	if err != nil {
		t.Fatal(err)
	}
	admission.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadSocketKeyPath, keyFileBytes)
	})
	admission.SaveAclPolicy([]byte(`{"grants": [{ "src": ["autogroup:member"], "dst": ["sock:app/*"], "allow": ["listen", "dial"] }]}`), sidecartest.AclSaveMembers{})
	networkId := connect.Id(admission.NetworkId())
	keys, err := sidecar.NewSocketKeys(admission.NetworkId(), socketKey)
	if err != nil {
		t.Fatal(err)
	}
	edgeNetworkId := connect.NewId()
	if err := net.Fakes().Gates.Set("sidecar:\n  sockets: {enabled: true, percent: 100}\n  urnetwork_edge: " + edgeNetworkId.String() + "\n"); err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	world := &socketSuiteWorld{
		t:             t,
		ctx:           ctx,
		net:           net,
		admission:     admission,
		store:         sidecartest.NewFakeSocketStore(net.Clock(), nil, nil),
		ticketKeys:    &socketSuiteTicketKeys{privateKey: privateKey},
		networkId:     networkId,
		edgeNetworkId: edgeNetworkId,
		socketKey:     socketKey,
		keys:          keys,
	}
	settings := socketsservice.DefaultSocketsSettings()
	settings.Gate.Cache.PollJitter = 0
	settings.Gate.Cache.FailureBackoff = 0
	settings.Gate.BehindReloadInterval = time.Hour
	if mutate != nil {
		mutate(settings)
	}
	engine, err := net.AddEngine(socketSuiteEngine, func(engineCtx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error) {
		production, err := socketsservice.NewSocketProjectionGate(engineCtx, host, sidecar.NewAclGateDirectSource(nil, host.Blobs, nil), settings.Gate)
		if err != nil {
			return nil, err
		}
		world.gate = production
		service, err := socketsservice.NewSocketsService(engineCtx, host, world.store, production, settings)
		if err != nil {
			production.Close()
			return nil, err
		}
		service.SetTicketKeys(world.ticketKeys)
		return service, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	world.engine = engine.(*socketsservice.SocketsService)
	t.Cleanup(world.gate.Close)
	world.client = net.EngineClient(socketSuiteEngine)
	world.listener = world.sidecarOf(listenerDevice)
	world.dialer = world.sidecarOf(dialerDevice)
	world.awaitStarted()
	world.awaitLoaded()
	return world
}

// A device's sockets token, as plan-SOCK-client-auth's Client-class token names its sidecar.
func (self *socketSuiteWorld) sidecarOf(device *sidecartest.AdmissionDevice) *socketSuiteSidecar {
	sidecarId := connect.Id(device.SidecarId)
	clientId := connect.NewId()
	now := self.net.Clock().Now()
	return &socketSuiteSidecar{
		device:   device,
		clientId: clientId,
		token: self.net.Fakes().Authenticator.Issue(&sidecar.Principal{
			NetworkId: self.networkId,
			ClientId:  clientId,
			SidecarId: &sidecarId,
			Audience:  socketsservice.SocketsAudience,
			IssuedAt:  now,
			ExpiresAt: now.Add(48 * time.Hour),
		}),
	}
}

// Waits until counts rises past past.
func socketSuiteAwait[T int | uint64](t *testing.T, ctx context.Context, what string, counts func() (T, chan struct{}), past T) {
	t.Helper()
	for {
		count, changed := counts()
		if past < count {
			return
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("%s never came", what)
		}
	}
}

// Waits for the engine's first probe, the gate's first over-limit read and the gate worker's first pass. The pass
// runs on a goroutine of its own and asks for a load of every network it finds behind, so it ends before a test
// gives the gate any evidence: one that came late would add a load to those the test triggers.
func (self *socketSuiteWorld) awaitStarted() {
	self.t.Helper()
	socketSuiteAwait(self.t, self.ctx, "the engine's first probe", self.engine.Probes, 0)
	socketSuiteAwait(self.t, self.ctx, "the gate's first over-limit read", self.gate.OverLimitReads, 0)
	socketSuiteAwait(self.t, self.ctx, "the gate worker's first pass", self.gate.Passes, 0)
}

// Asks the gate for the network, awaiting the load each refused ask starts, until it serves, and returns with every
// load the cache has started taken in by the gate: the cache installs a state before it tells the gate of the load,
// so a view served is not yet a load counted, and a test that read the gate's count then and awaited one more would
// be answered by this load, not the one it triggered. An ask comes only with no load running, since an ask of a
// network still loading can mark another load due behind the running one.
func (self *socketSuiteWorld) awaitLoaded() {
	self.t.Helper()
	for {
		started := self.gate.Stats().LoadCount
		if _, err := self.gate.View(self.networkId); err == nil {
			break
		}
		self.awaitLoadsPast(started)
	}
	if started := self.gate.Stats().LoadCount; 0 < started {
		self.awaitLoadsPast(started - 1)
	}
}

// Waits until the gate has taken in a load past count.
func (self *socketSuiteWorld) awaitLoadsPast(count uint64) {
	self.t.Helper()
	socketSuiteAwait(self.t, self.ctx, "a load", self.gate.Loads, count)
}

// Waits until a sweep past count has ended.
func (self *socketSuiteWorld) awaitSweepsPast(count int) {
	self.t.Helper()
	socketSuiteAwait(self.t, self.ctx, "a sweep", self.engine.Sweeps, count)
}

// Waits until count removed clients' store work has ended.
func (self *socketSuiteWorld) awaitRemovals(count int) {
	self.t.Helper()
	socketSuiteAwait(self.t, self.ctx, "a removal", self.engine.Removals, count-1)
}

// One call through the engine client, the answer decoded into answer when it is 200.
func (self *socketSuiteWorld) call(method string, path string, token string, body any, answer any) int {
	self.t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			self.t.Fatal(err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	request, err := http.NewRequestWithContext(self.ctx, method, "https://sockets.sidecartest.example"+path, bodyReader)
	if err != nil {
		self.t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := self.client.Do(request)
	if err != nil {
		self.t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK && answer != nil {
		if err := json.NewDecoder(response.Body).Decode(answer); err != nil {
			self.t.Fatal(err)
		}
	}
	return response.StatusCode
}

// A blinded registration of name by caller: its token path and seal under the network's K_sock, as the client
// side makes them (D-SOCK-13), and a claim its identity key signs.
func (self *socketSuiteWorld) registration(caller *socketSuiteSidecar, name string, maxStreams int) *sidecar.SocketRegistration {
	self.t.Helper()
	nameToken, err := self.keys.TokenPath(name)
	if err != nil {
		self.t.Fatal(err)
	}
	sealedName, err := self.keys.Seal(name)
	if err != nil {
		self.t.Fatal(err)
	}
	listenId := connect.NewId()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.SocketRegistrationClaim{
		NetworkId: self.networkId.Bytes(),
		NameToken: nameToken,
		ListenId:  listenId.Bytes(),
		Protocol:  "tcp",
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
		NameToken:  nameToken,
		SealedName: sealedName,
		ListenId:   &listenId,
		Protocol:   "tcp",
		Weight:     100,
		MaxStreams: maxStreams,
		Serving:    true,
		Claim:      claim,
	}
}

// One page of caller's set: registrations sorted by name key, within [keyStart, keyEnd).
func (self *socketSuiteWorld) register(caller *socketSuiteSidecar, setVersion uint64, keyStart []byte, keyEnd []byte, registrations []*sidecar.SocketRegistration) (int, *sidecar.SocketRegistrationsResult) {
	self.t.Helper()
	sort.Slice(registrations, func(i int, j int) bool {
		return bytes.Compare(registrations[i].NameKey(), registrations[j].NameKey()) < 0
	})
	result := &sidecar.SocketRegistrationsResult{}
	code := self.call(http.MethodPost, "/socket/registrations", caller.token, &sidecar.SocketRegistrationsArgs{
		SetVersion: setVersion, KeyStart: keyStart, KeyEnd: keyEnd, Registrations: registrations,
	}, result)
	return code, result
}

// A whole-set page every status of which must be ok.
func (self *socketSuiteWorld) registerOk(caller *socketSuiteSidecar, setVersion uint64, registrations ...*sidecar.SocketRegistration) {
	self.t.Helper()
	code, result := self.register(caller, setVersion, nil, nil, registrations)
	if code != http.StatusOK || result.Error != nil {
		self.t.Fatalf("a page answered %d, %+v", code, result.Error)
	}
	for index, status := range result.Statuses {
		if status != sidecar.SocketRegistrationStatusOk {
			self.t.Fatalf("entry %d answered %s", index, status)
		}
	}
}

// The store's calls so far by method, but its probe, which the engine makes on its own clock.
func (self *socketSuiteWorld) storeCalls() map[string]int {
	calls := map[string]int{}
	for _, method := range []string{"ApplyPage", "Pick", "ListListeners", "ListNames", "SetServicePair", "GetServicePair",
		"RemoveServicePairs", "TouchServicePairs", "RemoveClient", "RemoveEntries", "ClaimSweep"} {
		calls[method] = self.store.OpCount(method)
	}
	return calls
}

// All of them.
func (self *socketSuiteWorld) storeCallCount(calls map[string]int) int {
	count := 0
	for _, methodCount := range calls {
		count += methodCount
	}
	return count
}

// Finds answered with tickets, from the engine's own find_total: what a test of the composition counts signatures by.
func (self *socketSuiteWorld) signedFinds() float64 {
	return self.net.Fakes().Metrics.Value("urnetwork_sockets_find_total", "ok")
}

// One Find of name by caller: the refusal's code, or "" with the primary ticket verified.
func (self *socketSuiteWorld) find(caller *socketSuiteSidecar, name string) (sidecar.SocketErrorCode, *protocol.SocketTicket) {
	self.t.Helper()
	nameToken, err := self.keys.TokenPath(name)
	if err != nil {
		self.t.Fatal(err)
	}
	networkId := self.networkId
	result := &sidecar.SocketFindResult{}
	if code := self.call(http.MethodPost, "/socket/find", caller.token, &sidecar.SocketFindArgs{NameToken: nameToken, NetworkId: &networkId}, result); code != http.StatusOK {
		self.t.Fatalf("a Find answered %d", code)
	}
	if result.Error != nil {
		return result.Error.Code, nil
	}
	ticket, err := sidecar.VerifySocketTicket(result.Primary.Ticket, self.ticketKeys.VerifyKeys(), uint64(self.net.Clock().Now().UnixMilli()))
	if err != nil {
		self.t.Fatalf("a Find's ticket: %v", err)
	}
	return "", ticket
}

// D-SOCK-3: a set of 3,000 names goes as three pages of one set_version, none refused for size, each its range of
// name keys, and the listing then holds all 3,000; a page that lacks a name of its range unlistens it, and nothing
// outside its range moves; an entry outside its page's range, or a page of an older set_version, refuses the page.
func TestSocketSuiteThreeThousandNamesInThreePages(t *testing.T) {
	world := newSocketSuiteWorld(t, nil)
	registrations := []*sidecar.SocketRegistration{}
	for index := range 3000 {
		registrations = append(registrations, world.registration(world.listener, fmt.Sprintf("app/n%04d", index), 256))
	}
	sort.Slice(registrations, func(i int, j int) bool {
		return bytes.Compare(registrations[i].NameKey(), registrations[j].NameKey()) < 0
	})
	pages := [][]*sidecar.SocketRegistration{registrations[:1024], registrations[1024:2048], registrations[2048:]}
	bounds := [][]byte{nil, registrations[1024].NameKey(), registrations[2048].NameKey(), nil}
	for index, page := range pages {
		code, result := world.register(world.listener, 1, bounds[index], bounds[index+1], page)
		if code != http.StatusOK || result.Error != nil || len(result.Statuses) != len(page) {
			t.Fatalf("page %d answered %d, %+v", index, code, result.Error)
		}
	}
	listed := map[string]bool{}
	cursor := ""
	for range 16 {
		result := &sidecar.SocketListResult{}
		path := "/socket/list"
		if cursor != "" {
			path += "?cursor=" + url.QueryEscape(cursor)
		}
		if code := world.call(http.MethodGet, path, world.listener.token, nil, result); code != http.StatusOK || result.Error != nil {
			t.Fatalf("a listing page answered %d, %+v", code, result.Error)
		}
		for _, name := range result.Names {
			if opened, ok := sidecar.OpenSocketName(world.keys, nil, name.NameToken, name.SealedName); ok {
				listed[opened] = true
			}
		}
		if cursor = result.NextCursor; cursor == "" {
			break
		}
	}
	if len(listed) != 3000 {
		t.Fatalf("the listing opens %d names", len(listed))
	}

	// the middle page again without its first name: that name alone leaves
	dropped := pages[1][0]
	code, result := world.register(world.listener, 2, bounds[1], bounds[2], pages[1][1:])
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("the shorter page answered %d, %+v", code, result.Error)
	}
	if listeners, err := world.store.ListListeners(world.ctx, world.networkId, dropped.NameToken); err != nil || len(listeners) != 0 {
		t.Fatalf("a name the page lacked stands: %d, %v", len(listeners), err)
	}
	if listeners, err := world.store.ListListeners(world.ctx, world.networkId, pages[0][0].NameToken); err != nil || len(listeners) != 1 {
		t.Fatalf("a name outside the page's range moved: %d, %v", len(listeners), err)
	}

	// an entry outside its page's range, and a page of an older set_version, refuse the page whole
	code, result = world.register(world.listener, 3, bounds[1], bounds[2], []*sidecar.SocketRegistration{pages[0][0]})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeInvalid {
		t.Fatalf("an entry outside its page's range answered %d, %+v", code, result.Error)
	}
	code, result = world.register(world.listener, 1, bounds[1], bounds[2], pages[1])
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeStale {
		t.Fatalf("a page of an older set answered %d, %+v", code, result.Error)
	}
	if listeners, err := world.store.ListListeners(world.ctx, world.networkId, dropped.NameToken); err != nil || len(listeners) != 0 {
		t.Fatalf("the older set's page wrote a lease: %d, %v", len(listeners), err)
	}
}

// One script per Find, and D-SOCK-3's heal: a Find whose listener passes is the group's one script; then Redis is
// lost, a Find finds no listener, and the listener's next heartbeat, its whole set again, rebuilds the lease, so the
// next Find signs.
func TestSocketSuiteRedisLossHealsInOneHeartbeat(t *testing.T) {
	world := newSocketSuiteWorld(t, nil)
	registration := world.registration(world.listener, "app/db", 256)
	world.registerOk(world.listener, 1, registration)
	if code, _ := world.find(world.dialer, "app/db"); code != "" {
		t.Fatalf("before the loss the Find answered %s", code)
	}
	// a Find whose listener passes is one store call, the group's script (§22.5's one script per Find)
	calls := world.storeCalls()
	if code, _ := world.find(world.dialer, "app/db"); code != "" {
		t.Fatalf("the counted Find answered %s", code)
	}
	if after := world.storeCalls(); after["Pick"] != calls["Pick"]+1 || world.storeCallCount(after) != world.storeCallCount(calls)+1 {
		t.Fatalf("one Find made the store calls %v after %v", after, calls)
	}
	world.store.Wipe()
	if code, _ := world.find(world.dialer, "app/db"); code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("after the loss the Find answered %s", code)
	}
	world.net.Clock().Advance(15 * time.Second)
	world.registerOk(world.listener, 2, registration)
	if code, _ := world.find(world.dialer, "app/db"); code != "" {
		t.Fatalf("after one heartbeat the Find answered %s", code)
	}
}

// D-SOCK-15: a client calling past its bucket is answered unavailable with retry_after_ms before anything is sampled
// or signed, while another client's calls, the listener's heartbeat among them, go on.
func TestSocketSuiteLoopingClientIsShedBeforeSigning(t *testing.T) {
	world := newSocketSuiteWorld(t, nil)
	registration := world.registration(world.listener, "app/db", 256)
	world.registerOk(world.listener, 1, registration)
	burst := socketsservice.DefaultSocketControlBoundSettings().Burst
	for index := range burst {
		if code, _ := world.find(world.dialer, "app/db"); code != "" {
			t.Fatalf("Find %d inside the burst answered %s", index, code)
		}
	}
	signed := world.signedFinds()
	nameToken, err := world.keys.TokenPath("app/db")
	if err != nil {
		t.Fatal(err)
	}
	networkId := world.networkId
	result := &sidecar.SocketFindResult{}
	if code := world.call(http.MethodPost, "/socket/find", world.dialer.token, &sidecar.SocketFindArgs{NameToken: nameToken, NetworkId: &networkId}, result); code != http.StatusOK ||
		result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Error.RetryAfterMs == 0 {
		t.Fatalf("a Find past the burst answered %d, %+v", code, result.Error)
	}
	if world.signedFinds() != signed {
		t.Fatal("a shed Find was signed")
	}
	world.registerOk(world.listener, 2, registration)
}

// §20.7's spent mark: once the over-limit list marks the network spent, a Find answers quota and signs nothing, and a
// page says new streams are stopped; once it clears, Find signs again. A network over its storage limit alone is not
// stopped.
func TestSocketSuiteSpentNetworkAnswersQuota(t *testing.T) {
	world := newSocketSuiteWorld(t, nil)
	registration := world.registration(world.listener, "app/db", 256)
	world.registerOk(world.listener, 1, registration)
	quota := world.net.Fakes().Quota
	interval := socketsservice.DefaultSocketGateSettings().OverLimitInterval
	advance := func() {
		t.Helper()
		count, _ := world.gate.OverLimitReads()
		world.net.Clock().Advance(interval)
		for {
			next, changed := world.gate.OverLimitReads()
			if count < next {
				return
			}
			select {
			case <-changed:
			case <-world.ctx.Done():
				t.Fatal("the over-limit list was not read again")
			}
		}
	}
	quota.SetStorageRefusal(world.networkId, &sidecar.QuotaRefusal{LimitKey: "storage"})
	advance()
	if code, _ := world.find(world.dialer, "app/db"); code != "" {
		t.Fatalf("over its storage limit alone the Find answered %s", code)
	}
	quota.SetSpentRefusal(world.networkId, &sidecar.QuotaRefusal{LimitKey: "transfer_balance"})
	advance()
	signed := world.signedFinds()
	if code, _ := world.find(world.dialer, "app/db"); code != sidecar.SocketErrorCodeQuota {
		t.Fatalf("a spent network's Find answered %s", code)
	}
	if world.signedFinds() != signed {
		t.Fatal("a spent network's Find was signed")
	}
	code, result := world.register(world.listener, 2, nil, nil, []*sidecar.SocketRegistration{registration})
	if code != http.StatusOK || !result.StreamsStopped {
		t.Fatalf("a spent network's page answered %d, streams stopped %v", code, result.StreamsStopped)
	}
	quota.SetSpentRefusal(world.networkId, nil)
	advance()
	if code, _ := world.find(world.dialer, "app/db"); code != "" {
		t.Fatalf("once it recovered the Find answered %s", code)
	}
}

// D-SOCK-5's one-dialer case (meta review CC-06) on a fake clock: a dialer of short connections to a 256-stream
// listener takes 50 tickets a second after a burst of 500, none refused or delayed by the clamp, and adds at most
// c = 25 to the listener's est however many it takes; a second dialer moves est at most another 25.
func TestSocketSuiteOneDialerIsClampedButNeverRefused(t *testing.T) {
	world := newSocketSuiteWorld(t, nil)
	world.registerOk(world.listener, 1, world.registration(world.listener, "app/db", 256))
	scheduler := socketsservice.DefaultSocketSchedulerSettings()
	clamp := socketsservice.SocketClampCount(256, scheduler)
	estimate := func() int {
		t.Helper()
		nameToken, _ := world.keys.TokenPath("app/db")
		listeners, err := world.store.ListListeners(world.ctx, world.networkId, nameToken)
		if err != nil || len(listeners) != 1 {
			t.Fatalf("the listener: %d, %v", len(listeners), err)
		}
		return socketsservice.SocketEstimate(listeners[0].Candidate, world.net.Clock().Now().UnixMilli(), scheduler)
	}
	burst := socketsservice.DefaultSocketControlBoundSettings().Burst
	for index := range burst {
		if code, _ := world.find(world.dialer, "app/db"); code != "" {
			t.Fatalf("Find %d of the burst answered %s", index, code)
		}
	}
	for second := range 3 {
		world.net.Clock().Advance(time.Second)
		for index := range socketsservice.DefaultSocketControlBoundSettings().CallsPerSecond {
			if code, _ := world.find(world.dialer, "app/db"); code != "" {
				t.Fatalf("Find %d of second %d answered %s", index, second, code)
			}
		}
		if est := estimate(); clamp < est {
			t.Fatalf("one dialer moved est to %d past c = %d", est, clamp)
		}
	}
	second := world.sidecarOf(world.dialer.device)
	for range clamp + 10 {
		if code, _ := world.find(second, "app/db"); code != "" {
			t.Fatalf("the second dialer's Find answered %s", code)
		}
	}
	if est := estimate(); 2*clamp < est {
		t.Fatalf("two dialers moved est to %d past 2c = %d", est, 2*clamp)
	}
	if clamp != 25 {
		t.Fatalf("c at 256 streams is %d", clamp)
	}
}

// urnetwork-edge's platform client as tlsedge Finds through it: its K client ids, the first of which its token names.
type socketSuiteEdge struct {
	clientIds []*connect.Id
	token     string
}

// The world with a custom domain's names (DESIGN-DETAILS 17.2.10): tls/ open over facts the test sets, tls/443/blog
// and tls/443/shop published to the public for a day, both of the member's devices holding the network's pair, and an
// edge that Finds as tlsedge does, with the hello's ALPN ids and, for a custom host, its server name. Listeners are
// clients of either device, so two of one device share the facts its sidecar has.
type socketSuiteCustomWorld struct {
	*tlsSuiteWorld
	edge *socketSuiteEdge
	// every listener client the test made, and each one's newest set_version
	clientIdListeners   map[connect.Id]*socketSuiteSidecar
	clientIdSetVersions map[connect.Id]uint64
}

func newSocketSuiteCustomWorld(t *testing.T) *socketSuiteCustomWorld {
	t.Helper()
	world := &socketSuiteCustomWorld{
		tlsSuiteWorld:       newTlsSuiteWorld(t),
		edge:                &socketSuiteEdge{},
		clientIdListeners:   map[connect.Id]*socketSuiteSidecar{},
		clientIdSetVersions: map[connect.Id]uint64{},
	}
	now := world.net.Clock().Now()
	world.setFacts(func(facts *socketsservice.TlsListenFacts) {
		facts.Certs = append(slices.Clone(facts.Certs), &socketsservice.TlsListenCert{
			SidecarId:   connect.Id(world.dialer.device.SidecarId),
			NotAfter:    now.Add(24 * time.Hour),
			NetworkPair: true,
		})
	})
	world.savePublish("public", now.Add(24*time.Hour), "blog", "shop")
	for range 2 {
		clientId := connect.NewId()
		world.edge.clientIds = append(world.edge.clientIds, &clientId)
	}
	world.edge.token = world.net.Fakes().Authenticator.Issue(&sidecar.Principal{
		NetworkId: world.edgeNetworkId,
		ClientId:  *world.edge.clientIds[0],
		Audience:  socketsservice.SocketsAudience,
		IssuedAt:  now,
		ExpiresAt: now.Add(48 * time.Hour),
	})
	return world
}

// Has the source answer change's copy of the facts from now on, the hooks keeping what they last read.
func (self *socketSuiteCustomWorld) sourceFacts(change func(facts *socketsservice.TlsListenFacts)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	facts := *self.facts
	change(&facts)
	self.facts = &facts
}

// A new listener client of device, which the world's Finds know.
func (self *socketSuiteCustomWorld) listenerOf(device *sidecartest.AdmissionDevice) *socketSuiteSidecar {
	listener := self.sidecarOf(device)
	self.clientIdListeners[listener.clientId] = listener
	return listener
}

// listener's heartbeat of tls/443/<owner>, its http registration as edgeRegistration makes it changed by mutate: the
// status of the whole-set page's one entry.
func (self *socketSuiteCustomWorld) heartbeatWith(listener *socketSuiteSidecar, owner string, mutate func(registration *sidecar.SocketRegistration)) sidecar.SocketRegistrationStatus {
	self.t.Helper()
	registration := self.edgeRegistration(listener, "tls/443/"+owner)
	mutate(registration)
	self.clientIdSetVersions[listener.clientId] += 1
	return self.status(listener, self.clientIdSetVersions[listener.clientId], registration)
}

// listener's heartbeat of tls/443/<owner> offering alpns and listing certified and acme.
func (self *socketSuiteCustomWorld) heartbeat(listener *socketSuiteSidecar, owner string, alpns []string, certified []string, acme []*sidecar.SocketAcmeName) sidecar.SocketRegistrationStatus {
	self.t.Helper()
	return self.heartbeatWith(listener, owner, func(registration *sidecar.SocketRegistration) {
		registration.Alpn = alpns
		registration.CertifiedNames = certified
		registration.AcmeNames = acme
	})
}

// listener's lease of tls/443/<owner> as the store keeps it, nil for none.
func (self *socketSuiteCustomWorld) stored(listener *socketSuiteSidecar, owner string) *sidecar.SocketRegistration {
	self.t.Helper()
	listeners, err := self.store.ListListeners(self.ctx, self.networkId, []byte("tls/443/"+owner))
	if err != nil {
		self.t.Fatal(err)
	}
	for _, stored := range listeners {
		if stored.Candidate.ListenerClientId == listener.clientId {
			return stored.Registration
		}
	}
	return nil
}

// The edge's Find of tls/443/<owner> offering alpns for serverName, "" for a name under the network's own zone: the
// listeners its primary and backup tickets name, each verified, nil for none, or the refusal's code.
func (self *socketSuiteCustomWorld) edgeFind(owner string, alpns []string, serverName string) (*socketSuiteSidecar, *socketSuiteSidecar, sidecar.SocketErrorCode) {
	self.t.Helper()
	name := "tls/443/" + owner
	networkId := self.networkId
	result := &sidecar.SocketFindResult{}
	code := self.call(http.MethodPost, "/socket/find", self.edge.token, &sidecar.SocketFindArgs{
		Name:       name,
		NetworkId:  &networkId,
		ClientIds:  self.edge.clientIds,
		Protocol:   "tls",
		Alpn:       alpns,
		ServerName: serverName,
	}, result)
	if code != http.StatusOK {
		self.t.Fatalf("an edge Find answered %d", code)
	}
	if result.Error != nil {
		return nil, nil, result.Error.Code
	}
	listenerOf := func(findTicket *sidecar.SocketFindTicket) *socketSuiteSidecar {
		if findTicket == nil {
			return nil
		}
		ticket, err := sidecar.VerifySocketTicket(findTicket.Ticket, self.ticketKeys.VerifyKeys(), uint64(self.net.Clock().Now().UnixMilli()))
		if err != nil {
			self.t.Fatalf("an edge Find's ticket: %v", err)
		}
		listenerClientId, err := connect.IdFromBytes(ticket.GetListenerClientId())
		if err != nil || self.clientIdListeners[listenerClientId] == nil || ticket.GetName() != name {
			self.t.Fatalf("a ticket names %q and no listener of the world (%v)", ticket.GetName(), err)
		}
		return self.clientIdListeners[listenerClientId]
	}
	return listenerOf(result.Primary), listenerOf(result.Backup), ""
}

// A listener as a failure names it.
func socketSuiteListenerName(listener *socketSuiteSidecar) string {
	if listener == nil {
		return "none"
	}
	return listener.clientId.String()
}

// The ALPN ids the rows below offer and serve.
var (
	socketSuiteVisitorAlpns = []string{"h2", "http/1.1"}
	socketSuiteAcmeAlpns    = []string{sidecar.SocketAlpnAcme}
	socketSuiteBothAlpns    = []string{"h2", "http/1.1", sidecar.SocketAlpnAcme}
)

// DESIGN-DETAILS 17.6's pick through the engine, the production gate's view and the fake store, every list as
// ValidateListen left it: its table of acme by custom by an acme-only listener by a visitor with no ALPN. An
// acme-tls/1 Find for a custom host reaches the claim holder alone, though it neither serves nor stays out of a drain,
// and never with a backup; one for a host nobody claims, or for a name under the network's own zone, finds no
// listener; of two equal claims the lower client id answers, and after a takeover the higher claim, while the old
// holder's lease still lists its own, until its next heartbeat ends it. A visitor's Find for a custom host reaches
// only a listener certified for it and never an acme-only one; one with neither ALPN nor server name reaches every
// listener but an acme-only one, and finds no listener where only acme-only ones listen.
func TestSocketSuitePicksByCertifiedNamesAndClaims(t *testing.T) {
	world := newSocketSuiteCustomWorld(t)
	now := world.net.Clock().Now()
	firstSidecarId := connect.Id(world.listener.device.SidecarId)
	secondSidecarId := connect.Id(world.dialer.device.SidecarId)
	world.setFacts(func(facts *socketsservice.TlsListenFacts) {
		facts.CustomCertified = []*socketsservice.TlsListenCustomName{
			{SidecarId: secondSidecarId, Owner: "blog", Name: "app.customer.example", NotAfter: now.Add(30 * 24 * time.Hour)},
			{SidecarId: firstSidecarId, Owner: "blog", Name: "solo.customer.example", NotAfter: now.Add(30 * 24 * time.Hour)},
		}
		facts.AcmeClaims = []*socketsservice.TlsListenAcmeClaim{
			{SidecarId: firstSidecarId, Owner: "blog", Name: "acme.customer.example", ClaimSeq: 9},
			{SidecarId: firstSidecarId, Owner: "blog", Name: "solo.customer.example", ClaimSeq: 3},
			{SidecarId: secondSidecarId, Owner: "blog", Name: "tie.customer.example", ClaimSeq: 4},
			{SidecarId: firstSidecarId, Owner: "shop", Name: "shop.customer.example", ClaimSeq: 2},
		}
	})
	plain := world.listenerOf(world.listener.device)
	certified := world.listenerOf(world.dialer.device)
	holder := world.listenerOf(world.listener.device)
	// acme-only, serving, out of any drain, and certified for the host it answers challenges for
	responder := world.listenerOf(world.listener.device)
	tieOne := world.listenerOf(world.dialer.device)
	tieTwo := world.listenerOf(world.dialer.device)
	shopHolder := world.listenerOf(world.listener.device)
	holderEntry := func(registration *sidecar.SocketRegistration) {
		registration.Alpn = socketSuiteAcmeAlpns
		registration.AcmeNames = []*sidecar.SocketAcmeName{{Name: "acme.customer.example", ClaimSeq: 9}}
		registration.Serving = false
		registration.Draining = true
	}
	for index, status := range []sidecar.SocketRegistrationStatus{
		world.heartbeat(plain, "blog", socketSuiteVisitorAlpns, nil, nil),
		world.heartbeat(certified, "blog", socketSuiteVisitorAlpns, []string{"app.customer.example"}, nil),
		world.heartbeatWith(holder, "blog", holderEntry),
		world.heartbeat(responder, "blog", socketSuiteAcmeAlpns, []string{"solo.customer.example"}, []*sidecar.SocketAcmeName{{Name: "solo.customer.example", ClaimSeq: 3}}),
		world.heartbeat(tieOne, "blog", socketSuiteBothAlpns, nil, []*sidecar.SocketAcmeName{{Name: "tie.customer.example", ClaimSeq: 4}}),
		world.heartbeat(tieTwo, "blog", socketSuiteBothAlpns, nil, []*sidecar.SocketAcmeName{{Name: "tie.customer.example", ClaimSeq: 4}}),
		world.heartbeat(shopHolder, "shop", socketSuiteAcmeAlpns, nil, []*sidecar.SocketAcmeName{{Name: "shop.customer.example", ClaimSeq: 2}}),
	} {
		if status != sidecar.SocketRegistrationStatusOk {
			t.Fatalf("listener %d's heartbeat answered %s", index, status)
		}
	}
	if stored := world.stored(holder, "blog"); stored == nil || stored.Serving || !stored.Draining || len(stored.AcmeNames) != 1 || stored.AcmeNames[0].ClaimSeq != 9 {
		t.Fatalf("the store keeps the holder's lease as %+v", stored)
	}
	if stored := world.stored(responder, "blog"); stored == nil || !slices.Equal(stored.CertifiedNames, []string{"solo.customer.example"}) ||
		len(stored.AcmeNames) != 1 || stored.AcmeNames[0].ClaimSeq != 3 {
		t.Fatalf("the store keeps the responder's lease as %+v", stored)
	}
	lowerTie := tieOne
	if tieTwo.clientId.Cmp(tieOne.clientId) < 0 {
		lowerTie = tieTwo
	}
	cases := []struct {
		name       string
		owner      string
		alpns      []string
		serverName string
		code       sidecar.SocketErrorCode
		// the listeners an answer may name, and whether it comes with a backup
		reached []*socketSuiteSidecar
		backup  bool
	}{
		{name: "acme, custom: the claim holder alone", owner: "blog", alpns: socketSuiteAcmeAlpns, serverName: "acme.customer.example", reached: []*socketSuiteSidecar{holder}},
		{name: "acme, custom: an acme-only claim holder certified too", owner: "blog", alpns: socketSuiteAcmeAlpns, serverName: "solo.customer.example", reached: []*socketSuiteSidecar{responder}},
		{name: "acme among other ids, custom: still the claim holder alone", owner: "blog", alpns: []string{"h2", sidecar.SocketAlpnAcme}, serverName: "acme.customer.example", reached: []*socketSuiteSidecar{holder}},
		{name: "acme, custom, a host nobody claims", owner: "blog", alpns: socketSuiteAcmeAlpns, serverName: "app.customer.example", code: sidecar.SocketErrorCodeNoListener},
		{name: "acme, a name under the network's own zone", owner: "blog", alpns: socketSuiteAcmeAlpns, code: sidecar.SocketErrorCodeNoListener},
		{name: "acme, custom, two equal claims: the lower client id alone", owner: "blog", alpns: socketSuiteAcmeAlpns, serverName: "tie.customer.example", reached: []*socketSuiteSidecar{lowerTie}},
		{name: "visitor, custom: the certified listener alone", owner: "blog", alpns: []string{"h2"}, serverName: "app.customer.example", reached: []*socketSuiteSidecar{certified}},
		{name: "visitor with no ALPN, custom: the certified listener alone", owner: "blog", serverName: "app.customer.example", reached: []*socketSuiteSidecar{certified}},
		{name: "visitor, custom, none certified", owner: "blog", alpns: []string{"h2"}, serverName: "none.customer.example", code: sidecar.SocketErrorCodeNoListener},
		{name: "visitor with no ALPN, custom, an acme-only listener certified alone", owner: "blog", serverName: "solo.customer.example", code: sidecar.SocketErrorCodeNoListener},
		{name: "visitor with no ALPN, a name under the network's own zone: every listener but the acme-only ones", owner: "blog", reached: []*socketSuiteSidecar{plain, certified, tieOne, tieTwo}, backup: true},
		{name: "visitor with no ALPN, acme-only listeners alone", owner: "shop", code: sidecar.SocketErrorCodeNoListener},
	}
	for _, c := range cases {
		for range 20 {
			primary, backup, code := world.edgeFind(c.owner, c.alpns, c.serverName)
			if code != c.code {
				t.Fatalf("%s: answered %q", c.name, code)
			}
			if code != "" {
				continue
			}
			if !slices.Contains(c.reached, primary) || (backup == nil) == c.backup ||
				(backup != nil && (backup == primary || !slices.Contains(c.reached, backup))) {
				t.Fatalf("%s: reached %s and %s", c.name, socketSuiteListenerName(primary), socketSuiteListenerName(backup))
			}
		}
	}

	// a takeover: the lock's claim for the host moves to the second device at 10, whose new listener lists it at once;
	// the holder's lease still lists 9, and the higher claim answers
	world.setFacts(func(facts *socketsservice.TlsListenFacts) {
		facts.AcmeClaims = []*socketsservice.TlsListenAcmeClaim{
			{SidecarId: secondSidecarId, Owner: "blog", Name: "acme.customer.example", ClaimSeq: 10},
			{SidecarId: firstSidecarId, Owner: "blog", Name: "solo.customer.example", ClaimSeq: 3},
			{SidecarId: secondSidecarId, Owner: "blog", Name: "tie.customer.example", ClaimSeq: 4},
			{SidecarId: firstSidecarId, Owner: "shop", Name: "shop.customer.example", ClaimSeq: 2},
		}
	})
	taker := world.listenerOf(world.dialer.device)
	if status := world.heartbeat(taker, "blog", socketSuiteAcmeAlpns, nil, []*sidecar.SocketAcmeName{{Name: "acme.customer.example", ClaimSeq: 10}}); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("the taker's heartbeat answered %s", status)
	}
	if stored := world.stored(holder, "blog"); stored == nil || len(stored.AcmeNames) != 1 || stored.AcmeNames[0].ClaimSeq != 9 {
		t.Fatalf("the old holder's lease reads %+v before its next heartbeat", stored)
	}
	for range 20 {
		if primary, backup, code := world.edgeFind("blog", socketSuiteAcmeAlpns, "acme.customer.example"); code != "" || primary != taker || backup != nil {
			t.Fatalf("after the takeover a challenge reached %s and %s (%q)", socketSuiteListenerName(primary), socketSuiteListenerName(backup), code)
		}
	}
	// the old holder's next heartbeat: its claim is the lock's no longer, and an acme-only entry left with none ends
	if status := world.heartbeatWith(holder, "blog", holderEntry); status != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("the old holder's heartbeat answered %s", status)
	}
	if stored := world.stored(holder, "blog"); stored != nil {
		t.Fatalf("the old holder's lease stands: %+v", stored)
	}
	if primary, backup, code := world.edgeFind("blog", socketSuiteAcmeAlpns, "acme.customer.example"); code != "" || primary != taker || backup != nil {
		t.Fatalf("a challenge reached %s and %s (%q)", socketSuiteListenerName(primary), socketSuiteListenerName(backup), code)
	}
}

// DESIGN-DETAILS 17.2.10's narrowing through the engine, the production gate's view and the fake store. A heartbeat
// keeps the certified names its sidecar's rows certify past CertifiedMargin on the name's owner, and the ACME names
// whose claim the account's lock holds at that sequence; a name with no row, a row on another owner, a row inside the
// margin and a claim below the row's are dropped, the entry answering ok and its network name still served. A list
// past its count is malformed. An acme-only entry left with no claim is refused, and one holding its claim admitted.
// A claim above the facts' reads them again on the heartbeat, so a new claim is not held up by the cache. The store
// keeps each entry as the hook left it, and the pick reads that.
func TestSocketSuiteNarrowsCertifiedAndAcmeNames(t *testing.T) {
	world := newSocketSuiteCustomWorld(t)
	now := world.net.Clock().Now()
	tlsSettings := socketsservice.DefaultTlsNamespaceSettings()
	firstSidecarId := connect.Id(world.listener.device.SidecarId)
	secondSidecarId := connect.Id(world.dialer.device.SidecarId)
	world.setFacts(func(facts *socketsservice.TlsListenFacts) {
		facts.CustomCertified = []*socketsservice.TlsListenCustomName{
			{SidecarId: firstSidecarId, Owner: "blog", Name: "app.customer.example", NotAfter: now.Add(30 * 24 * time.Hour)},
			{SidecarId: firstSidecarId, Owner: "shop", Name: "other.customer.example", NotAfter: now.Add(30 * 24 * time.Hour)},
			{SidecarId: secondSidecarId, Owner: "blog", Name: "app.customer.example", NotAfter: now.Add(tlsSettings.CertifiedMargin / 2)},
		}
		facts.AcmeClaims = []*socketsservice.TlsListenAcmeClaim{
			{SidecarId: firstSidecarId, Owner: "blog", Name: "acme.customer.example", ClaimSeq: 5},
		}
	})
	listed := world.listenerOf(world.listener.device)
	marginal := world.listenerOf(world.dialer.device)
	if status := world.heartbeat(listed, "blog", socketSuiteBothAlpns,
		[]string{"app.customer.example", "unrowed.customer.example", "other.customer.example"},
		[]*sidecar.SocketAcmeName{{Name: "acme.customer.example", ClaimSeq: 4}}); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("a heartbeat with names to drop answered %s", status)
	}
	if status := world.heartbeat(marginal, "blog", socketSuiteVisitorAlpns, []string{"app.customer.example"}, nil); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("a heartbeat whose one certificate is inside the margin answered %s", status)
	}
	if stored := world.stored(listed, "blog"); stored == nil || !slices.Equal(stored.CertifiedNames, []string{"app.customer.example"}) || stored.AcmeNames != nil {
		t.Fatalf("the store keeps the listed lease as %+v", stored)
	}
	if stored := world.stored(marginal, "blog"); stored == nil || stored.CertifiedNames != nil || stored.AcmeNames != nil {
		t.Fatalf("the store keeps the marginal lease as %+v", stored)
	}
	// the pick reads what the store keeps
	for range 20 {
		if primary, backup, code := world.edgeFind("blog", []string{"h2"}, "app.customer.example"); code != "" || primary != listed || backup != nil {
			t.Fatalf("the custom host reached %s and %s (%q)", socketSuiteListenerName(primary), socketSuiteListenerName(backup), code)
		}
	}
	for _, serverName := range []string{"unrowed.customer.example", "other.customer.example"} {
		if _, _, code := world.edgeFind("blog", []string{"h2"}, serverName); code != sidecar.SocketErrorCodeNoListener {
			t.Fatalf("the dropped %s answered %q", serverName, code)
		}
	}
	if _, _, code := world.edgeFind("blog", socketSuiteAcmeAlpns, "acme.customer.example"); code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a dropped claim's challenge answered %q", code)
	}
	reached := map[*socketSuiteSidecar]bool{}
	for range 20 {
		primary, backup, code := world.edgeFind("blog", []string{"h2"}, "")
		if code != "" {
			t.Fatalf("the network name answered %q", code)
		}
		reached[primary] = true
		reached[backup] = true
	}
	if !reached[listed] || !reached[marginal] {
		t.Fatal("a listener that lost a custom name lost its network name too")
	}

	// a list past its count is malformed, whichever list it is
	tooManyCertified := []string{}
	for index := range socketsservice.DefaultSocketsSettings().CertifiedNameMaxCount + 1 {
		tooManyCertified = append(tooManyCertified, fmt.Sprintf("h%d.customer.example", index))
	}
	tooManyAcme := []*sidecar.SocketAcmeName{}
	for index := range socketsservice.DefaultSocketsSettings().AcmeNameMaxCount + 1 {
		tooManyAcme = append(tooManyAcme, &sidecar.SocketAcmeName{Name: fmt.Sprintf("a%d.customer.example", index), ClaimSeq: 5})
	}
	crowded := world.listenerOf(world.listener.device)
	if status := world.heartbeat(crowded, "blog", socketSuiteBothAlpns, tooManyCertified, nil); status != sidecar.SocketRegistrationStatusInvalid {
		t.Fatalf("certified names past their count answered %s", status)
	}
	if status := world.heartbeat(crowded, "blog", socketSuiteBothAlpns, nil, tooManyAcme); status != sidecar.SocketRegistrationStatusInvalid {
		t.Fatalf("ACME names past their count answered %s", status)
	}
	if stored := world.stored(crowded, "blog"); stored != nil {
		t.Fatalf("a malformed entry was stored: %+v", stored)
	}

	// an acme-only entry left with no claim is refused, and one holding the lock's claim admitted
	responder := world.listenerOf(world.listener.device)
	if status := world.heartbeat(responder, "blog", socketSuiteAcmeAlpns, nil, []*sidecar.SocketAcmeName{{Name: "acme.customer.example", ClaimSeq: 4}}); status != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("an acme-only entry left with no claim answered %s", status)
	}
	if status := world.heartbeat(responder, "blog", socketSuiteAcmeAlpns, nil, []*sidecar.SocketAcmeName{{Name: "acme.customer.example", ClaimSeq: 5}}); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("an acme-only entry holding the claim answered %s", status)
	}
	if primary, backup, code := world.edgeFind("blog", socketSuiteAcmeAlpns, "acme.customer.example"); code != "" || primary != responder || backup != nil {
		t.Fatalf("the challenge reached %s and %s (%q)", socketSuiteListenerName(primary), socketSuiteListenerName(backup), code)
	}

	// the lock's next claim, 6, is the first device's in the rows but not yet in the hooks' facts: the heartbeat
	// listing it reads them once more and keeps it, and it answers the next challenge over the responder's 5
	world.net.Clock().Advance(tlsSettings.FactsRereadInterval)
	world.sourceFacts(func(facts *socketsservice.TlsListenFacts) {
		facts.AcmeClaims = []*socketsservice.TlsListenAcmeClaim{
			{SidecarId: firstSidecarId, Owner: "blog", Name: "acme.customer.example", ClaimSeq: 6},
		}
	})
	loads, _ := world.hooks.Loads()
	if status := world.heartbeat(listed, "blog", socketSuiteBothAlpns, []string{"app.customer.example"},
		[]*sidecar.SocketAcmeName{{Name: "acme.customer.example", ClaimSeq: 6}}); status != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("a heartbeat listing a newer claim answered %s", status)
	}
	if count, _ := world.hooks.Loads(); count != loads+1 {
		t.Fatalf("a claim above the facts' read them %d times", count-loads)
	}
	if stored := world.stored(listed, "blog"); stored == nil || len(stored.AcmeNames) != 1 || stored.AcmeNames[0].ClaimSeq != 6 {
		t.Fatalf("the store keeps the newer claim's lease as %+v", stored)
	}
	for range 20 {
		if primary, backup, code := world.edgeFind("blog", socketSuiteAcmeAlpns, "acme.customer.example"); code != "" || primary != listed || backup != nil {
			t.Fatalf("the newer claim's challenge reached %s and %s (%q)", socketSuiteListenerName(primary), socketSuiteListenerName(backup), code)
		}
	}
}
