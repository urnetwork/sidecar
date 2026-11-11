// POST /socket/find at T2, on FakeSocketStore and FakeSocketGate (SOCK-M5-06): each refusal in step order,
// signing nothing; tickets for the primary and the backup; edge Finds' K mapping and pairs; failed-ticket
// reports; and DESIGN-DETAILS 13.6's listener check, with a revocation landing between a Find's pick and its
// signing through the store's hook.

package socketsservice_test

import (
	"bytes"
	"net/http"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// One network with a dialer and two listeners of one blinded name, each allowed, at the gate's position.
type testSocketFindScene struct {
	world     *testSocketWorld
	process   *testSocketProcess
	networkId connect.Id
	nameToken []byte
	dialer    *testSocketSidecar
	listeners []*testSocketSidecar
	position  uint64
}

// The scene with listenerCount listeners registered.
func newTestSocketFindScene(t *testing.T, listenerCount int) *testSocketFindScene {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	scene := &testSocketFindScene{world: world, process: process, networkId: testSocketId(), nameToken: testSocketTokenPath(t, 2)}
	scene.dialer = world.newSidecar(scene.networkId)
	process.gate.AllowDial(scene.networkId, scene.dialer.clientId, scene.nameToken, sidecartest.FakeSocketGrant{GrantId: []byte("dial"), ExpireMillis: 1 << 50})
	for range listenerCount {
		listener := world.newSidecar(scene.networkId)
		process.gate.SetIdentityKey(scene.networkId, listener.sidecarId, listener.publicKey())
		process.gate.AllowListen(scene.networkId, listener.sidecarId, scene.nameToken, testSocketGrant("listen"))
		scene.listeners = append(scene.listeners, listener)
	}
	scene.position = process.gate.Load(scene.networkId)
	for _, listener := range scene.listeners {
		process.registerOk(listener, 1, listener.blindedRegistration(t, scene.nameToken))
	}
	return scene
}

// A Find of the scene's name by its dialer.
func (self *testSocketFindScene) findArgs() *sidecar.SocketFindArgs {
	networkId := self.networkId
	return &sidecar.SocketFindArgs{NameToken: self.nameToken, NetworkId: &networkId}
}

// The scene's listener whose client id is clientId's bytes.
func (self *testSocketFindScene) listenerOf(t *testing.T, clientIdBytes []byte) *testSocketSidecar {
	t.Helper()
	for _, listener := range self.listeners {
		if bytes.Equal(listener.clientId.Bytes(), clientIdBytes) {
			return listener
		}
	}
	t.Fatal("a ticket names no listener of the scene")
	return nil
}

// A Find whose listeners pass answers a primary and a backup ticket, each verifying under the published key,
// naming the dialer, the listener and its listen, the gate's position and the dial grant, with the listener's
// claim beside it; and it is one store call, the pick (§22.5).
func TestSocketFindSignsAPrimaryAndABackup(t *testing.T) {
	scene := newTestSocketFindScene(t, 2)
	world := scene.world
	before := map[string]int{}
	for _, method := range []string{"Pick", "ApplyPage", "SetServicePair", "RemoveEntries", "ListListeners"} {
		before[method] = world.fakeStore.OpCount(method)
	}
	code, result := scene.process.find(scene.dialer.token, scene.findArgs())
	if code != http.StatusOK || result.Error != nil || result.Primary == nil || result.Backup == nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	primary := world.verifyTicket(result.Primary)
	backup := world.verifyTicket(result.Backup)
	if bytes.Equal(primary.GetListenerClientId(), backup.GetListenerClientId()) {
		t.Fatal("both tickets name one listener")
	}
	for index, ticket := range []*protocol.SocketTicket{primary, backup} {
		listener := scene.listenerOf(t, ticket.GetListenerClientId())
		switch {
		case !bytes.Equal(ticket.GetDialerClientId(), scene.dialer.clientId.Bytes()),
			!bytes.Equal(ticket.GetDialerNetworkId(), scene.networkId.Bytes()),
			!bytes.Equal(ticket.GetNetworkId(), scene.networkId.Bytes()),
			!bytes.Equal(ticket.GetNameToken(), scene.nameToken), ticket.GetName() != "":
			t.Errorf("ticket %d names %v", index, ticket)
		case ticket.GetPolicyVersion() != scene.position, !bytes.Equal(ticket.GetGrantId(), []byte("dial")),
			ticket.GetGrantExpireTimeMillis() != 1<<50, ticket.GetBackup() != (index == 1):
			t.Errorf("ticket %d carries %v", index, ticket)
		case ticket.GetExpireTimeMillis()-ticket.GetIssueTimeMillis() != 30000:
			t.Errorf("ticket %d lives %d ms", index, ticket.GetExpireTimeMillis()-ticket.GetIssueTimeMillis())
		}
		findTicket := result.Primary
		if index == 1 {
			findTicket = result.Backup
		}
		listeners, err := world.fakeStore.ListListeners(world.ctx, scene.networkId, scene.nameToken)
		if err != nil {
			t.Fatal(err)
		}
		for _, stored := range listeners {
			if stored.Candidate.ListenerClientId == listener.clientId && !bytes.Equal(stored.Registration.Claim, findTicket.Claim) {
				t.Errorf("ticket %d's claim is not its listener's", index)
			}
		}
	}
	if count := world.fakeStore.OpCount("Pick") - before["Pick"]; count != 1 {
		t.Errorf("%d picks", count)
	}
	for _, method := range []string{"ApplyPage", "SetServicePair", "RemoveEntries"} {
		if count := world.fakeStore.OpCount(method) - before[method]; count != 0 {
			t.Errorf("a passing Find made %d %s calls", count, method)
		}
	}
	if count := scene.process.service.SignedTicketCount(); count != 2 {
		t.Errorf("%d tickets signed", count)
	}
}

// Each refusal in §9.6's step order signs nothing, and step 3's dial refusal comes before any group is read.
func TestSocketFindRefusesInStepOrderSigningNothing(t *testing.T) {
	scene := newTestSocketFindScene(t, 1)
	world := scene.world
	process := scene.process
	expect := func(label string, code sidecar.SocketErrorCode) {
		t.Helper()
		status, result := process.find(scene.dialer.token, scene.findArgs())
		if status != http.StatusOK || result.Error == nil || result.Error.Code != code || result.Primary != nil {
			t.Fatalf("%s answered %d, %+v", label, status, result)
		}
		if count := process.service.SignedTicketCount(); count != 0 {
			t.Fatalf("%s signed %d tickets", label, count)
		}
	}

	// the dial check, before the group is read
	process.gate.RevokeDial(scene.networkId, scene.dialer.clientId, scene.nameToken)
	process.gate.Load(scene.networkId)
	picks := world.fakeStore.OpCount("Pick")
	expect("a refused dial", sidecar.SocketErrorCodeDenied)
	if world.fakeStore.OpCount("Pick") != picks {
		t.Fatal("a refused dial read the group")
	}
	process.gate.AllowDial(scene.networkId, scene.dialer.clientId, scene.nameToken, testSocketGrant("dial"))
	process.gate.Load(scene.networkId)

	// the network unloaded, or behind past the grace
	process.gate.Unload(scene.networkId)
	expect("an unloaded network", sidecar.SocketErrorCodeUnavailable)
	process.gate.Load(scene.networkId)
	process.gate.NoteEvidence(scene.networkId, 1000)
	world.clock.Advance(process.gate.BehindGrace)
	expect("a network behind", sidecar.SocketErrorCodeUnavailable)
	process.gate.LoadAt(scene.networkId, 1000)
	for _, listener := range scene.listeners {
		// the leases lapsed while the clock moved
		process.registerOk(listener, 2, listener.blindedRegistration(t, scene.nameToken))
	}

	// spent
	process.gate.SetSpent(scene.networkId, true)
	expect("a spent network", sidecar.SocketErrorCodeQuota)
	process.gate.SetSpent(scene.networkId, false)

	// no listener, then busy
	busyToken := testSocketTokenPath(t, 2)
	process.gate.AllowDial(scene.networkId, scene.dialer.clientId, busyToken, testSocketGrant("dial"))
	process.gate.Load(scene.networkId)
	networkId := scene.networkId
	status, result := process.find(scene.dialer.token, &sidecar.SocketFindArgs{NameToken: busyToken, NetworkId: &networkId})
	if status != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("an empty group answered %d, %+v", status, result)
	}
	full := scene.listeners[0].blindedRegistration(t, scene.nameToken)
	full.Inflight = full.MaxStreams
	process.registerOk(scene.listeners[0], 3, full)
	expect("a full listener", sidecar.SocketErrorCodeBusy)

	// the bucket, first of all
	busyArgs := scene.findArgs()
	for range 600 {
		status, result = process.find(scene.dialer.token, busyArgs)
		if result != nil && result.Error != nil && result.Error.Code == sidecar.SocketErrorCodeUnavailable {
			break
		}
	}
	if result == nil || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Error.RetryAfterMs == 0 {
		t.Fatalf("the bucket never refused: %+v", result)
	}
	if count := process.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
}

// §9.10's bucket: a dialer's burst of 500 Finds, then 50 a second on the fake clock.
func TestSocketFindBucketKeepsFiftyASecondAfterItsBurst(t *testing.T) {
	scene := newTestSocketFindScene(t, 1)
	allowed := func(count int) int {
		allowedCount := 0
		for range count {
			if _, result := scene.process.find(scene.dialer.token, scene.findArgs()); result != nil && result.Error == nil {
				allowedCount += 1
			}
		}
		return allowedCount
	}
	if count := allowed(600); count != 500 {
		t.Fatalf("the burst allowed %d", count)
	}
	scene.world.clock.Advance(time.Second)
	for _, listener := range scene.listeners {
		scene.process.registerOk(listener, 2, listener.blindedRegistration(t, scene.nameToken))
	}
	// the listener's page charged its own bucket, never the dialer's
	if count := allowed(100); count != 50 {
		t.Fatalf("a second later %d Finds passed", count)
	}
}

// A spent network answers quota with retry_after_ms and no ticket (§9.6's step 3).
func TestSocketFindAnswersQuotaForASpentNetwork(t *testing.T) {
	scene := newTestSocketFindScene(t, 1)
	scene.process.gate.SetSpent(scene.networkId, true)
	code, result := scene.process.find(scene.dialer.token, scene.findArgs())
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeQuota || result.Error.RetryAfterMs != 5000 || result.Primary != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if count := scene.process.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
}

// DESIGN-DETAILS 13.6 (TestFindJudgesTheListener): a lease a stale process wrote, whose grant this process's
// state no longer holds, gets no ticket; it is removed for cause, its tombstone refusing the stale process's
// next put, and its client is hinted.
func TestFindJudgesTheListener(t *testing.T) {
	world := newTestSocketWorld(t)
	stale := world.newProcess(nil)
	fresh := world.newProcess(nil)
	networkId := testSocketId()
	nameToken := testSocketTokenPath(t, 2)
	dialer := world.newSidecar(networkId)
	listener := world.newSidecar(networkId)
	for _, process := range []*testSocketProcess{stale, fresh} {
		process.gate.SetIdentityKey(networkId, listener.sidecarId, listener.publicKey())
		process.gate.AllowDial(networkId, dialer.clientId, nameToken, testSocketGrant("dial"))
	}
	stale.gate.AllowListen(networkId, listener.sidecarId, nameToken, testSocketGrant("listen"))
	stale.gate.LoadAt(networkId, 1)
	fresh.gate.LoadAt(networkId, 2)
	registration := listener.blindedRegistration(t, nameToken)
	stale.registerOk(listener, 1, registration)

	code, result := fresh.find(dialer.token, &sidecar.SocketFindArgs{NameToken: nameToken, NetworkId: &networkId})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if count := fresh.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
	if listeners, _ := world.fakeStore.ListListeners(world.ctx, networkId, nameToken); len(listeners) != 0 {
		t.Fatal("the refused lease stands")
	}
	hints := fresh.host.Push.Hints(listener.clientId)
	if len(hints) != 1 || hints[0].Topic != sidecar.PushTopicSock || hints[0].Kind != uint32(protocol.MessageType_SOCKET_HINT) {
		t.Fatalf("hints %+v", hints)
	}
	socketHint := &protocol.SocketHint{}
	if err := proto.Unmarshal(hints[0].Body, socketHint); err != nil || socketHint.GetKind() != protocol.SocketHintKind_SOCKET_HINT_REVOKED ||
		!bytes.Equal(socketHint.GetListenId(), registration.ListenId.Bytes()) {
		t.Fatalf("hint %v, %v", socketHint, err)
	}
	code, page := stale.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || page.Error == nil || page.Error.Code != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("the stale process's put past the tombstone answered %d, %+v", code, page)
	}
}

// DESIGN-DETAILS 13.6: a Find that picked before a revocation and its sweep, and signs after, takes every
// verdict again on the newer state: it signs nothing and writes no pair.
func TestSocketFindPickedBeforeASweepSignsNothing(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, &testSocketRecordingHooks{}); err != nil {
		t.Fatal(err)
	}
	networkId := testSocketId()
	name := "tls/443/blog"
	listener := world.newSidecar(networkId)
	process.gate.SetIdentityKey(networkId, listener.sidecarId, listener.publicKey())
	process.gate.AllowListen(networkId, listener.sidecarId, []byte(name), testSocketGrant("listen"))
	process.gate.AllowPublicDial(networkId, []byte(name), testSocketGrant("public"))
	process.gate.AllowPublish(networkId, []byte(name), testSocketGrant("publish"))
	position := process.gate.Load(networkId)
	process.registerOk(listener, 1, listener.edgeRegistration(t, name, "tls", "http"))
	edge := world.newEdge(4)

	world.store.afterPick = func(result *socketsservice.SocketStorePickResult) {
		world.store.afterPick = nil
		process.gate.RevokeListen(networkId, listener.sidecarId, []byte(name))
		process.gate.Load(networkId)
		if _, err := world.fakeStore.RemoveEntries(world.ctx, networkId, socketsservice.SocketRemoveRefused, position+1,
			[]*socketsservice.SocketStoreEntryRef{{ListenerClientId: listener.clientId, NameKey: []byte(name)}}); err != nil {
			t.Error(err)
		}
		if err := world.fakeStore.RemoveServicePairs(world.ctx, listener.clientId, position+1); err != nil {
			t.Error(err)
		}
	}
	code, result := process.find(edge.token, &sidecar.SocketFindArgs{Name: name, NetworkId: &networkId, ClientIds: edge.clientIdArgs()})
	if code != http.StatusOK || result.Error == nil || result.Primary != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if count := process.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
	if count := world.fakeStore.OpCount("SetServicePair"); count != 0 {
		t.Fatalf("%d pair writes", count)
	}
	for _, clientId := range edge.clientIds {
		if _, found, _ := world.fakeStore.GetServicePair(world.ctx, listener.clientId, clientId); found {
			t.Fatal("a pair stands for the revoked listener")
		}
	}
}

// DESIGN-DETAILS 13.6: a lease a fresher process admitted above this Find's position gets no ticket here: the
// Find answers unavailable for BehindRetryAfter, and the lease's position is handed to the gate.
func TestSocketFindLeaseAboveItsPositionIsUnavailable(t *testing.T) {
	world := newTestSocketWorld(t)
	behind := world.newProcess(nil)
	ahead := world.newProcess(nil)
	networkId := testSocketId()
	nameToken := testSocketTokenPath(t, 1)
	dialer := world.newSidecar(networkId)
	listener := world.newSidecar(networkId)
	for _, process := range []*testSocketProcess{behind, ahead} {
		process.gate.SetIdentityKey(networkId, listener.sidecarId, listener.publicKey())
		process.gate.AllowDial(networkId, dialer.clientId, nameToken, testSocketGrant("dial"))
	}
	ahead.gate.AllowListen(networkId, listener.sidecarId, nameToken, testSocketGrant("listen"))
	behind.gate.LoadAt(networkId, 2)
	ahead.gate.LoadAt(networkId, 3)
	ahead.registerOk(listener, 1, listener.blindedRegistration(t, nameToken))

	code, result := behind.find(dialer.token, &sidecar.SocketFindArgs{NameToken: nameToken, NetworkId: &networkId})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Error.RetryAfterMs != 250 {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if observed := behind.gate.Observed(networkId); !slices.Contains(observed, 3) {
		t.Fatalf("observed %v", observed)
	}
	if listeners, _ := world.fakeStore.ListListeners(world.ctx, networkId, nameToken); len(listeners) != 1 {
		t.Fatal("a lease this process could not judge was removed")
	}
	if count := behind.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
}

// DESIGN-DETAILS 13.6: a grant that ran out by time since the listener's last heartbeat is refused at the check,
// and the other listener takes the ticket; a removed client's lease is refused alike.
func TestSocketFindRefusesAGrantThatRanOutByTime(t *testing.T) {
	scene := newTestSocketFindScene(t, 2)
	world := scene.world
	process := scene.process
	expiring := scene.listeners[0]
	process.gate.AllowListen(scene.networkId, expiring.sidecarId, scene.nameToken, sidecartest.FakeSocketGrant{
		GrantId: []byte("short"), ExpireMillis: uint64(world.clock.Now().Add(10 * time.Second).UnixMilli()),
	})
	process.gate.Load(scene.networkId)
	world.clock.Advance(11 * time.Second)
	code, result := process.find(scene.dialer.token, scene.findArgs())
	if code != http.StatusOK || result.Error != nil || result.Backup != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if ticket := world.verifyTicket(result.Primary); !bytes.Equal(ticket.GetListenerClientId(), scene.listeners[1].clientId.Bytes()) {
		t.Fatal("the expired listener took the ticket")
	}
	listeners, _ := world.fakeStore.ListListeners(world.ctx, scene.networkId, scene.nameToken)
	if len(listeners) != 1 || listeners[0].Candidate.ListenerClientId != scene.listeners[1].clientId {
		t.Fatal("the expired listener's lease stands")
	}

	process.service.NoteClientRemovedForTest(scene.listeners[1].clientId)
	code, result = process.find(scene.dialer.token, scene.findArgs())
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a removed client's lease answered %d, %+v", code, result)
	}
}

// A refused primary hands the ticket to the backup; with both refused, one more pick finds what is left.
func TestSocketFindPicksAgainWhenEveryPickedListenerIsRefused(t *testing.T) {
	scene := newTestSocketFindScene(t, 3)
	world := scene.world
	process := scene.process
	keep := scene.listeners[2]
	for _, listener := range scene.listeners[:2] {
		process.gate.RevokeListen(scene.networkId, listener.sidecarId, scene.nameToken)
	}
	process.gate.Load(scene.networkId)
	// draws that take the two refused listeners in the first pick: weights are 100 each, candidates are in client
	// id order, and the second draw skips the first's
	sorted := slices.Clone(scene.listeners)
	slices.SortFunc(sorted, func(a *testSocketSidecar, b *testSocketSidecar) int { return a.clientId.Cmp(b.clientId) })
	refusedIndexes := []int{}
	for index, listener := range sorted {
		if listener != keep {
			refusedIndexes = append(refusedIndexes, index)
		}
	}
	firstIndex := refusedIndexes[0]
	remaining := []int{}
	for index := range sorted {
		if index != firstIndex {
			remaining = append(remaining, index)
		}
	}
	secondDraw := uint32(100 * slices.Index(remaining, refusedIndexes[1]))
	process.service.SetDrawsForTest(uint32(100*firstIndex), secondDraw, 0)
	before := map[string]int{}
	for _, method := range []string{"Pick", "RemoveEntries", "RemoveServicePairs"} {
		before[method] = world.fakeStore.OpCount(method)
	}
	code, result := process.find(scene.dialer.token, scene.findArgs())
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if ticket := world.verifyTicket(result.Primary); !bytes.Equal(ticket.GetListenerClientId(), keep.clientId.Bytes()) {
		t.Fatal("a refused listener took the ticket")
	}
	// the refused path's calls: one removal for both, and no pair call, a blinded name standing for no pair
	for method, count := range map[string]int{"Pick": 2, "RemoveEntries": 1, "RemoveServicePairs": 0} {
		if made := world.fakeStore.OpCount(method) - before[method]; made != count {
			t.Errorf("the refused path made %d %s calls, not %d", made, method, count)
		}
	}
	listeners, _ := world.fakeStore.ListListeners(world.ctx, scene.networkId, scene.nameToken)
	if len(listeners) != 1 {
		t.Fatalf("%d leases stand after both refused were removed", len(listeners))
	}
}

// Who may Find what (§9.4's table): a sidecar may not Find tls/ or smtp/, an edge may not Find a blinded name,
// a sidecar may not Find another network's blinded name, ur/ waits on SOCK-M9-01, and only an edge sends
// client_ids. Each answers before any group is read.
func TestSocketFindDeniesWhatItsCallerCannotReach(t *testing.T) {
	scene := newTestSocketFindScene(t, 1)
	world := scene.world
	process := scene.process
	edge := world.newEdge(2)
	networkId := scene.networkId
	otherNetworkId := testSocketId()
	picks := world.fakeStore.OpCount("Pick")
	for index, call := range []struct {
		token string
		args  *sidecar.SocketFindArgs
		code  sidecar.SocketErrorCode
	}{
		{token: scene.dialer.token, args: &sidecar.SocketFindArgs{Name: "tls/443/blog", NetworkId: &networkId}, code: sidecar.SocketErrorCodeDenied},
		{token: scene.dialer.token, args: &sidecar.SocketFindArgs{Name: "smtp/25/mx", NetworkId: &networkId}, code: sidecar.SocketErrorCodeDenied},
		{token: scene.dialer.token, args: &sidecar.SocketFindArgs{Name: "ur/smtpedge", NetworkId: &world.edgeNetworkId}, code: sidecar.SocketErrorCodeDenied},
		{token: scene.dialer.token, args: &sidecar.SocketFindArgs{NameToken: scene.nameToken, NetworkId: &otherNetworkId}, code: sidecar.SocketErrorCodeDenied},
		{token: edge.token, args: &sidecar.SocketFindArgs{NameToken: scene.nameToken, NetworkId: &networkId, ClientIds: edge.clientIdArgs()}, code: sidecar.SocketErrorCodeDenied},
		{token: scene.dialer.token, args: &sidecar.SocketFindArgs{NameToken: scene.nameToken, NetworkId: &networkId, ClientIds: edge.clientIdArgs()}, code: sidecar.SocketErrorCodeInvalid},
		{token: edge.token, args: &sidecar.SocketFindArgs{Name: "tls/443/blog", NetworkId: &networkId}, code: sidecar.SocketErrorCodeInvalid},
		{token: scene.dialer.token, args: &sidecar.SocketFindArgs{Name: "db/primary", NetworkId: &networkId}, code: sidecar.SocketErrorCodeInvalid},
		{token: scene.dialer.token, args: &sidecar.SocketFindArgs{Name: "tls/443/blog", NameToken: scene.nameToken, NetworkId: &networkId}, code: sidecar.SocketErrorCodeInvalid},
		{token: scene.dialer.token, args: &sidecar.SocketFindArgs{NameToken: scene.nameToken}, code: sidecar.SocketErrorCodeInvalid},
	} {
		code, result := process.find(call.token, call.args)
		if code != http.StatusOK || result.Error == nil || result.Error.Code != call.code {
			t.Errorf("call %d answered %d, %+v", index, code, result)
		}
	}
	if world.fakeStore.OpCount("Pick") != picks {
		t.Fatal("a Find its caller cannot reach read a group")
	}
}

// The kill set refuses a tls/ name before anything is read (§13.9).
func TestSocketFindRefusesAKilledName(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	edge := world.newEdge(1)
	networkId := testSocketId()
	process.gate.AllowPublicDial(networkId, []byte("tls/443/blog"), testSocketGrant("public"))
	process.gate.AllowPublish(networkId, []byte("tls/443/blog"), testSocketGrant("publish"))
	process.gate.Load(networkId)
	process.service.SetKillsForTest(networkId, []*sidecar.TlsKillEntry{{Host: "blog", Reason: "phishing"}})
	views := process.gate.ViewCount(networkId)
	code, result := process.find(edge.token, &sidecar.SocketFindArgs{Name: "tls/443/blog", NetworkId: &networkId, ClientIds: edge.clientIdArgs()})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeDenied {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if process.gate.ViewCount(networkId) != views {
		t.Fatal("a killed name read the gate")
	}
}

// An edge Find of tls/: tickets name the edge's K clients by a mapping stable per listener, the {svc_} pair is
// written for that client with the publish grant's expiry, at most once a PairWriteInterval, and a pair below
// its floor makes the Find unavailable with the floor handed to the gate.
func TestSocketEdgeFindMapsItsClientsAndWritesThePair(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, &testSocketRecordingHooks{}); err != nil {
		t.Fatal(err)
	}
	networkId := testSocketId()
	name := "tls/443/blog"
	grantExpireMillis := uint64(world.clock.Now().Add(2 * time.Hour).UnixMilli())
	listeners := []*testSocketSidecar{world.newSidecar(networkId), world.newSidecar(networkId)}
	for _, listener := range listeners {
		process.gate.SetIdentityKey(networkId, listener.sidecarId, listener.publicKey())
		process.gate.AllowListen(networkId, listener.sidecarId, []byte(name), testSocketGrant("listen"))
	}
	process.gate.AllowPublicDial(networkId, []byte(name), testSocketGrant("public"))
	process.gate.AllowPublish(networkId, []byte(name), sidecartest.FakeSocketGrant{GrantId: []byte("publish"), ExpireMillis: grantExpireMillis})
	position := process.gate.Load(networkId)
	for _, listener := range listeners {
		process.registerOk(listener, 1, listener.edgeRegistration(t, name, "tls", "http"))
	}
	edge := world.newEdge(4)
	args := &sidecar.SocketFindArgs{Name: name, NetworkId: &networkId, ClientIds: edge.clientIdArgs()}

	listenerDialers := map[connect.Id][]byte{}
	for round := range 3 {
		code, result := process.find(edge.token, args)
		if code != http.StatusOK || result.Error != nil || result.Backup == nil {
			t.Fatalf("round %d answered %d, %+v", round, code, result)
		}
		for _, findTicket := range []*sidecar.SocketFindTicket{result.Primary, result.Backup} {
			ticket := world.verifyTicket(findTicket)
			listenerClientId, _ := connect.IdFromBytes(ticket.GetListenerClientId())
			if !slices.ContainsFunc(edge.clientIds, func(clientId connect.Id) bool { return bytes.Equal(clientId.Bytes(), ticket.GetDialerClientId()) }) {
				t.Fatal("a ticket names a client the edge does not hold")
			}
			if previous, found := listenerDialers[listenerClientId]; found && !bytes.Equal(previous, ticket.GetDialerClientId()) {
				t.Fatal("a listener's edge client moved between Finds")
			}
			listenerDialers[listenerClientId] = ticket.GetDialerClientId()
			if ticket.GetName() != name || !bytes.Equal(ticket.GetGrantId(), []byte("publish")) || ticket.GetGrantExpireTimeMillis() != grantExpireMillis ||
				!bytes.Equal(ticket.GetDialerNetworkId(), world.edgeNetworkId.Bytes()) || ticket.GetPolicyVersion() != position {
				t.Fatalf("an edge ticket carries %v", ticket)
			}
			dialerClientId, _ := connect.IdFromBytes(ticket.GetDialerClientId())
			pairExpireMillis, found, err := world.fakeStore.GetServicePair(world.ctx, listenerClientId, dialerClientId)
			if err != nil || !found || pairExpireMillis != grantExpireMillis {
				t.Fatalf("the pair: %d, %v, %v", pairExpireMillis, found, err)
			}
		}
	}
	if count := world.fakeStore.OpCount("SetServicePair"); count != 2 {
		t.Fatalf("%d pair writes in three Finds within a minute", count)
	}
	world.clock.Advance(61 * time.Second)
	for _, listener := range listeners {
		process.registerOk(listener, 2, listener.edgeRegistration(t, name, "tls", "http"))
	}
	if code, result := process.find(edge.token, args); code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if count := world.fakeStore.OpCount("SetServicePair"); count != 4 {
		t.Fatalf("%d pair writes once the interval passed", count)
	}

	// a removal at a newer position floors the pairs
	for _, listener := range listeners {
		if err := world.fakeStore.RemoveServicePairs(world.ctx, listener.clientId, position+5); err != nil {
			t.Fatal(err)
		}
	}
	world.clock.Advance(61 * time.Second)
	for _, listener := range listeners {
		process.registerOk(listener, 3, listener.edgeRegistration(t, name, "tls", "http"))
	}
	code, result := process.find(edge.token, args)
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Primary != nil {
		t.Fatalf("a pair below its floor answered %d, %+v", code, result)
	}
	if observed := process.gate.Observed(networkId); !slices.Contains(observed, position+5) {
		t.Fatalf("observed %v", observed)
	}
}

// DESIGN-DETAILS 13.2.3's find step 7: a refused listener whose last edge name the removal took loses its {svc_}
// pairs at the Find's position, leaving a floor that refuses a pair written below it, while a refused listener
// that still holds another edge name keeps its pairs. The refused path's calls beyond the pick are the one
// RemoveEntries, a RemoveServicePairs for the listener left with no edge name, and one more Pick. Once granted
// again, the listener's next registration renews its pairs and the next Find writes its pair afresh, this
// process's memos of the removed pairs forgotten.
func TestSocketFindRemovesARefusedListenersLastPairs(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, &testSocketRecordingHooks{}); err != nil {
		t.Fatal(err)
	}
	networkId := testSocketId()
	blog := "tls/443/blog"
	shop := "tls/443/shop"
	grantExpireMillis := uint64(world.clock.Now().Add(2 * time.Hour).UnixMilli())
	only := world.newSidecar(networkId)
	both := world.newSidecar(networkId)
	for _, listener := range []*testSocketSidecar{only, both} {
		process.gate.SetIdentityKey(networkId, listener.sidecarId, listener.publicKey())
		process.gate.AllowListen(networkId, listener.sidecarId, []byte(blog), testSocketGrant("listen"))
	}
	process.gate.AllowListen(networkId, both.sidecarId, []byte(shop), testSocketGrant("listen"))
	process.gate.AllowPublicDial(networkId, []byte(blog), testSocketGrant("public"))
	process.gate.AllowPublish(networkId, []byte(blog), sidecartest.FakeSocketGrant{GrantId: []byte("publish"), ExpireMillis: grantExpireMillis})
	process.gate.Load(networkId)
	onlyRegistration := only.edgeRegistration(t, blog, "tls", "http")
	process.registerOk(only, 1, onlyRegistration)
	process.registerOk(both, 1, both.edgeRegistration(t, blog, "tls", "http"), both.edgeRegistration(t, shop, "tls", "http"))
	edge := world.newEdge(4)
	args := &sidecar.SocketFindArgs{Name: blog, NetworkId: &networkId, ClientIds: edge.clientIdArgs()}

	code, result := process.find(edge.token, args)
	if code != http.StatusOK || result.Error != nil || result.Backup == nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	listenerDialerClientIds := map[connect.Id]connect.Id{}
	for _, findTicket := range []*sidecar.SocketFindTicket{result.Primary, result.Backup} {
		ticket := world.verifyTicket(findTicket)
		listenerClientId, _ := connect.IdFromBytes(ticket.GetListenerClientId())
		dialerClientId, _ := connect.IdFromBytes(ticket.GetDialerClientId())
		listenerDialerClientIds[listenerClientId] = dialerClientId
	}
	pairFound := func(listener *testSocketSidecar) bool {
		t.Helper()
		_, found, err := world.fakeStore.GetServicePair(world.ctx, listener.clientId, listenerDialerClientIds[listener.clientId])
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	if !pairFound(only) || !pairFound(both) {
		t.Fatal("the first Find wrote no pair")
	}

	for _, listener := range []*testSocketSidecar{only, both} {
		process.gate.RevokeListen(networkId, listener.sidecarId, []byte(blog))
	}
	revokedPosition := process.gate.Load(networkId)
	before := map[string]int{}
	for _, method := range []string{"Pick", "RemoveEntries", "RemoveServicePairs", "SetServicePair"} {
		before[method] = world.fakeStore.OpCount(method)
	}
	signed := process.service.SignedTicketCount()
	code, result = process.find(edge.token, args)
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener || result.Primary != nil {
		t.Fatalf("a Find of two refused listeners answered %d, %+v", code, result)
	}
	if count := process.service.SignedTicketCount() - signed; count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
	for method, count := range map[string]int{"Pick": 2, "RemoveEntries": 1, "RemoveServicePairs": 1, "SetServicePair": 0} {
		if made := world.fakeStore.OpCount(method) - before[method]; made != count {
			t.Errorf("the refused path made %d %s calls, not %d", made, method, count)
		}
	}
	if pairFound(only) {
		t.Fatal("the pair of a listener with no edge name left stands")
	}
	if !pairFound(both) {
		t.Fatal("the pair of a listener that still holds an edge name went")
	}
	for _, listener := range []*testSocketSidecar{only, both} {
		if hints := process.host.Push.Hints(listener.clientId); len(hints) != 1 {
			t.Fatalf("%d hints for a removed listener", len(hints))
		}
	}

	// granted again: the page renews the pairs at once, and the Find writes the pair afresh
	process.gate.AllowListen(networkId, only.sidecarId, []byte(blog), testSocketGrant("listen"))
	process.gate.Load(networkId)
	touches := world.fakeStore.OpCount("TouchServicePairs")
	process.registerOk(only, 2, onlyRegistration)
	if count := world.fakeStore.OpCount("TouchServicePairs") - touches; count != 1 {
		t.Fatalf("the registration after the removal made %d pair touches", count)
	}
	code, result = process.find(edge.token, args)
	if code != http.StatusOK || result.Error != nil || result.Backup != nil {
		t.Fatalf("a Find after the grant answered %d, %+v", code, result)
	}
	if !pairFound(only) {
		t.Fatal("the Find after the removal wrote no pair")
	}

	// the floor stands at the removal's position
	wrote, floor, err := world.fakeStore.SetServicePair(world.ctx, only.clientId, listenerDialerClientIds[only.clientId], grantExpireMillis, time.Minute, revokedPosition-1)
	if err != nil || wrote || floor != revokedPosition {
		t.Fatalf("a pair below the removal's position: %v, %d, %v", wrote, floor, err)
	}
}

// Failed-ticket reports (§9.6): a forged ticket and a stranger's are dropped; a holder's report excludes the
// listener for that dialer, so the next pick names the other as primary.
func TestSocketFindCountsOnlyItsHoldersReports(t *testing.T) {
	scene := newTestSocketFindScene(t, 2)
	world := scene.world
	process := scene.process
	stranger := world.newSidecar(scene.networkId)
	process.gate.AllowDial(scene.networkId, stranger.clientId, scene.nameToken, testSocketGrant("dial"))
	process.gate.Load(scene.networkId)

	code, result := process.find(scene.dialer.token, scene.findArgs())
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	failedListener := world.verifyTicket(result.Primary).GetListenerClientId()

	forged := bytes.Clone(result.Primary.Ticket)
	forged[len(forged)-1] ^= 0x01
	args := scene.findArgs()
	args.FailedTickets = []*sidecar.SocketFailedTicket{{Ticket: forged, Reason: sidecar.SocketFailedReasonTimeout}}
	if code, result := process.find(scene.dialer.token, args); code != http.StatusOK || result.Error != nil {
		t.Fatalf("a forged report answered %d, %+v", code, result)
	}
	args.FailedTickets = []*sidecar.SocketFailedTicket{{Ticket: result.Primary.Ticket, Reason: sidecar.SocketFailedReasonTimeout}}
	if code, result := process.find(stranger.token, args); code != http.StatusOK || result.Error != nil {
		t.Fatalf("a stranger's report answered %d, %+v", code, result)
	}
	dropped := process.host.Metrics.Value("urnetwork_sockets_failure_reports_total", "dropped")
	if dropped != 2 {
		t.Fatalf("%v reports dropped", dropped)
	}
	if excluded := process.host.Metrics.Value("urnetwork_sockets_exclusions_total"); excluded != 0 {
		t.Fatalf("%v exclusions from refused reports", excluded)
	}

	// the holder's own report, while its ticket lives, excludes that listener for it
	args.FailedTickets = []*sidecar.SocketFailedTicket{{Ticket: result.Primary.Ticket, Reason: sidecar.SocketFailedReasonTimeout}}
	for round := range 5 {
		code, answer := process.find(scene.dialer.token, args)
		if code != http.StatusOK || answer.Error != nil {
			t.Fatalf("round %d answered %d, %+v", round, code, answer)
		}
		if bytes.Equal(world.verifyTicket(answer.Primary).GetListenerClientId(), failedListener) {
			t.Fatalf("round %d's primary is the excluded listener", round)
		}
		args.FailedTickets = nil
	}
	if counted := process.host.Metrics.Value("urnetwork_sockets_failure_reports_total", "timeout"); counted != 1 {
		t.Fatalf("%v holder reports counted", counted)
	}
}
