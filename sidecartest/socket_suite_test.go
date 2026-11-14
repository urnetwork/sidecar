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
		gate, err := socketsservice.NewSocketProjectionGate(engineCtx, host, sidecar.NewAclGateDirectSource(nil, host.Blobs, nil), settings.Gate)
		if err != nil {
			return nil, err
		}
		world.gate = gate
		service, err := socketsservice.NewSocketsService(engineCtx, host, world.store, gate, settings)
		if err != nil {
			gate.Close()
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
