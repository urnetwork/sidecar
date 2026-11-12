// The engine's removals (SOCK-M5-07; DESIGN-DETAILS 13.2.3, 13.6) on the route fixture: FakeSocketGate, one
// FakeSocketStore and a fake clock. The revocation sweep removes for cause, with tombstones, pairs and hints, what
// the newest state refuses, once per network and period and by one process a position, and a sweep that dies is
// healed by the next heartbeat; a removed client's leases and pairs end with no hint; a network's kills follow its
// {tes_} hash. The gate's own triggers for the sweep are gate_projection_test.go's.

package socketsservice_test

import (
	"bytes"
	"encoding/json"
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

// The SOCKET_HINT_REVOKED hints host's push gave clientId, by listen id.
func testSocketRevokedHints(t *testing.T, host *sidecartest.FakeHost, clientId connect.Id) [][]byte {
	t.Helper()
	listenIds := [][]byte{}
	for _, hint := range host.Push.Hints(clientId) {
		message := &protocol.SocketHint{}
		if hint.Topic != sidecar.PushTopicSock || proto.Unmarshal(hint.Body, message) != nil {
			t.Fatalf("a hint that is no socket hint: %+v", hint)
		}
		if message.GetKind() == protocol.SocketHintKind_SOCKET_HINT_REVOKED {
			listenIds = append(listenIds, message.GetListenId())
		}
	}
	return listenIds
}

// A sweep removes for cause every lease the newest state refuses, leaving the rest: each removal leaves its
// tombstone, which refuses a put admitted below it, and hints its client for its listen; a listener left with no
// edge name loses its pairs at the sweep's position; LastUnlisten fires for an edge name's last listener.
func TestSweepRemovesTheRefusedAndHintsThem(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	hooks := &testSocketRecordingHooks{}
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, hooks); err != nil {
		t.Fatal(err)
	}
	kept := testSocketEnrolledListener(world, process)
	networkId := kept.networkId
	revoked := world.newSidecar(networkId)
	process.gate.SetIdentityKey(networkId, revoked.sidecarId, revoked.publicKey())
	process.gate.AllowListenPrefix(networkId, revoked.sidecarId, nil, testSocketGrant("listen"))
	process.gate.Load(networkId)
	nameToken := testSocketTokenPath(t, 2)
	keptRegistration := kept.blindedRegistration(t, nameToken)
	process.registerOk(kept, 1, keptRegistration)
	revokedBlinded := revoked.blindedRegistration(t, nameToken)
	revokedEdge := revoked.edgeRegistration(t, "tls/443/blog", "tls", "http")
	process.registerOk(revoked, 1, revokedBlinded, revokedEdge)
	dialerClientId := testSocketId()
	if wrote, _, err := world.fakeStore.SetServicePair(world.ctx, revoked.clientId, dialerClientId, 0, 15*time.Minute, 1); err != nil || !wrote {
		t.Fatalf("pair: %v, %v", wrote, err)
	}

	process.gate.RevokeListen(networkId, revoked.sidecarId, nil)
	position := process.gate.Load(networkId)
	process.service.QueueSweepForTest(networkId, position)
	if err := process.service.AwaitSweeps(world.ctx, 1); err != nil {
		t.Fatal(err)
	}

	listeners, err := world.fakeStore.ListListeners(world.ctx, networkId, nameToken)
	if err != nil || len(listeners) != 1 || listeners[0].Candidate.ListenerClientId != kept.clientId {
		t.Fatalf("the name's listeners after the sweep: %d, %v", len(listeners), err)
	}
	if edgeListeners, err := world.fakeStore.ListListeners(world.ctx, networkId, []byte("tls/443/blog")); err != nil || len(edgeListeners) != 0 {
		t.Fatalf("the edge name's listeners after the sweep: %d, %v", len(edgeListeners), err)
	}
	if !slices.Equal(hooks.lastUnlistens, []string{"tls/443/blog"}) {
		t.Fatalf("LastUnlisten %v", hooks.lastUnlistens)
	}
	if _, found, _ := world.fakeStore.GetServicePair(world.ctx, revoked.clientId, dialerClientId); found {
		t.Fatal("the revoked listener's pair outlived its last edge name")
	}
	if wrote, floor, err := world.fakeStore.SetServicePair(world.ctx, revoked.clientId, dialerClientId, 0, time.Minute, position-1); err != nil || wrote || floor != position {
		t.Fatalf("a pair below the sweep's floor: %v, %d, %v", wrote, floor, err)
	}
	listenIds := testSocketRevokedHints(t, process.host, revoked.clientId)
	if len(listenIds) != 2 || !slices.ContainsFunc(listenIds, func(listenId []byte) bool { return bytes.Equal(listenId, revokedBlinded.ListenId.Bytes()) }) ||
		!slices.ContainsFunc(listenIds, func(listenId []byte) bool { return bytes.Equal(listenId, revokedEdge.ListenId.Bytes()) }) {
		t.Fatalf("the revoked client's hints name %x", listenIds)
	}
	if hints := testSocketRevokedHints(t, process.host, kept.clientId); len(hints) != 0 {
		t.Fatal("the kept listener was hinted")
	}

	// a put admitted below the sweep's position, a stale process's, is fenced by the tombstone
	result, err := world.fakeStore.ApplyPage(world.ctx, &socketsservice.SocketStorePage{
		NetworkId:        networkId,
		ListenerClientId: revoked.clientId,
		SetVersion:       2,
		PolicyVersion:    position - 1,
		SidecarId:        &revoked.sidecarId,
		Registrations:    []*sidecar.SocketRegistration{revokedBlinded},
		RefusedNameKeys:  [][]byte{},
	})
	if err != nil || len(result.Outcomes) != 1 || !result.Outcomes[0].Fenced || result.Outcomes[0].FencePolicyVersion != position {
		t.Fatalf("a put below the tombstone: %+v, %v", result, err)
	}
}

// Queued twice before it runs, a network is swept once, at its newest position; queued again within
// SweepMinInterval, it waits out the interval, always at the newest position.
func TestSweepRunsOnceForACoalescedQueueAndOncePerInterval(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	networkId := listener.networkId
	process.registerOk(listener, 1, listener.blindedRegistration(t, testSocketTokenPath(t, 1)))
	first := process.gate.Load(networkId)
	second := process.gate.Load(networkId)
	process.service.QueueSweepForTest(networkId, first)
	process.service.QueueSweepForTest(networkId, second)
	if err := process.service.AwaitSweeps(world.ctx, 1); err != nil {
		t.Fatal(err)
	}
	if count := world.fakeStore.OpCount("ClaimSweep"); count != 1 {
		t.Fatalf("a coalesced queue claimed %d times", count)
	}

	third := process.gate.Load(networkId)
	process.service.QueueSweepForTest(networkId, third)
	interval := socketsservice.DefaultSocketsSettings().SweepMinInterval
	world.clock.Advance(interval - time.Millisecond)
	if count := process.service.SweepCount(); count != 1 {
		t.Fatalf("%d sweeps inside the interval", count)
	}
	world.clock.Advance(time.Millisecond)
	if err := process.service.AwaitSweeps(world.ctx, 2); err != nil {
		t.Fatal(err)
	}
	if count := world.fakeStore.OpCount("ClaimSweep"); count != 2 {
		t.Fatalf("%d claims after the interval", count)
	}
}

// Of two processes at one position, one claims the network's sweep: the revoked lease is removed once and its
// client hinted once.
func TestSweepClaimIsWonByOneOfTwoProcesses(t *testing.T) {
	world := newTestSocketWorld(t)
	processes := []*testSocketProcess{world.newProcess(nil), world.newProcess(nil)}
	networkId := testSocketId()
	listener := world.newSidecar(networkId)
	for _, process := range processes {
		process.gate.SetIdentityKey(networkId, listener.sidecarId, listener.publicKey())
		process.gate.AllowListenPrefix(networkId, listener.sidecarId, nil, testSocketGrant("listen"))
		process.gate.LoadAt(networkId, 7)
	}
	processes[0].registerOk(listener, 1, listener.blindedRegistration(t, testSocketTokenPath(t, 1)))
	for _, process := range processes {
		process.gate.RevokeListen(networkId, listener.sidecarId, nil)
		process.gate.LoadAt(networkId, 8)
	}
	for _, process := range processes {
		process.service.QueueSweepForTest(networkId, 8)
	}
	for _, process := range processes {
		if err := process.service.AwaitSweeps(world.ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	if count := world.fakeStore.OpCount("RemoveEntries"); count != 1 {
		t.Fatalf("%d removals of one position", count)
	}
	hints := 0
	for _, process := range processes {
		hints += len(testSocketRevokedHints(t, process.host, listener.clientId))
	}
	if hints != 1 {
		t.Fatalf("%d revocation hints", hints)
	}
}

// A sweep whose removal the store does not answer leaves nothing wrong: the refused lease's next heartbeat, judged on
// the newest state, ends it as revoked.
func TestSweepKilledMidwayIsHealedByTheNextHeartbeat(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	listener := testSocketEnrolledListener(world, process)
	networkId := listener.networkId
	registration := listener.blindedRegistration(t, testSocketTokenPath(t, 1))
	process.registerOk(listener, 1, registration)
	process.gate.RevokeListen(networkId, listener.sidecarId, nil)
	position := process.gate.Load(networkId)
	if _, err := world.fakeStore.Faults().Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "sockets.RemoveEntries", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	process.service.QueueSweepForTest(networkId, position)
	if err := process.service.AwaitSweeps(world.ctx, 1); err != nil {
		t.Fatal(err)
	}
	if listeners, err := world.fakeStore.ListListeners(world.ctx, networkId, registration.NameToken); err != nil || len(listeners) != 1 {
		t.Fatalf("the failed sweep removed %v, %v", listeners, err)
	}
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error != nil || result.Statuses[0] != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("the next heartbeat answered %d, %+v", code, result)
	}
	if listeners, err := world.fakeStore.ListListeners(world.ctx, networkId, registration.NameToken); err != nil || len(listeners) != 0 {
		t.Fatalf("after the heartbeat the lease stands: %v, %v", listeners, err)
	}
}

// {X}c_removed (§9.8, D-SOCK-9, X10): the client is refused from memory at once, its leases end with cause-2
// tombstones and its pairs with a floor no position passes, and it is not hinted; a child is removed by its own
// event, beside its parent's.
func TestClientRemovedEndsItsLeasesAndPairsWithNoHint(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	parent := testSocketEnrolledListener(world, process)
	networkId := parent.networkId
	child := world.newSidecar(networkId)
	process.gate.SetIdentityKey(networkId, child.sidecarId, child.publicKey())
	process.gate.AllowListenPrefix(networkId, child.sidecarId, nil, testSocketGrant("listen"))
	process.gate.Load(networkId)
	nameToken := testSocketTokenPath(t, 1)
	parentRegistration := parent.blindedRegistration(t, nameToken)
	process.registerOk(parent, 1, parentRegistration)
	process.registerOk(child, 1, child.blindedRegistration(t, nameToken))
	dialerClientId := testSocketId()
	if wrote, _, err := world.fakeStore.SetServicePair(world.ctx, parent.clientId, dialerClientId, 0, 15*time.Minute, 1); err != nil || !wrote {
		t.Fatalf("pair: %v, %v", wrote, err)
	}

	process.service.ClientRemoved(parent.clientId)
	process.service.ClientRemoved(child.clientId)
	if code, _ := process.register(parent.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{parentRegistration}}); code != http.StatusUnauthorized {
		t.Fatalf("a removed client's page answered %d", code)
	}
	if err := process.service.AwaitRemovals(world.ctx, 2); err != nil {
		t.Fatal(err)
	}
	if listeners, err := world.fakeStore.ListListeners(world.ctx, networkId, nameToken); err != nil || len(listeners) != 0 {
		t.Fatalf("a removed client's lease stands: %d, %v", len(listeners), err)
	}
	if _, found, _ := world.fakeStore.GetServicePair(world.ctx, parent.clientId, dialerClientId); found {
		t.Fatal("a removed client's pair stands")
	}
	if wrote, _, err := world.fakeStore.SetServicePair(world.ctx, parent.clientId, dialerClientId, 0, time.Minute, 1<<40); err != nil || wrote {
		t.Fatalf("a pair after the removal: %v, %v", wrote, err)
	}
	// a page that slipped past the removed-client set, a stale process's, is fenced by the client's tombstone
	result, err := world.fakeStore.ApplyPage(world.ctx, &socketsservice.SocketStorePage{
		NetworkId:        networkId,
		ListenerClientId: parent.clientId,
		SetVersion:       3,
		PolicyVersion:    1 << 40,
		SidecarId:        &parent.sidecarId,
		Registrations:    []*sidecar.SocketRegistration{parentRegistration},
		RefusedNameKeys:  [][]byte{},
	})
	if err != nil || len(result.Outcomes) != 1 || !result.Outcomes[0].Fenced || result.Outcomes[0].FenceCause != socketsservice.SocketRemoveClientRemoved {
		t.Fatalf("a put after the removal: %+v, %v", result, err)
	}
	for _, clientId := range []connect.Id{parent.clientId, child.clientId} {
		if hints := process.host.Push.Hints(clientId); len(hints) != 0 {
			t.Fatalf("a removed client was hinted %d times", len(hints))
		}
	}
}

// A network's kills follow its {tes_} hash (§13.9): read when a tls/ name of it is first judged, read again on its
// event, and on a resubscription for every network already read.
func TestKillChangedReadsTheNetworksHash(t *testing.T) {
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
	process.gate.Load(networkId)
	// the reader's first round, with nothing asked of it yet
	if err := process.service.AwaitKillReads(world.ctx, 1); err != nil {
		t.Fatal(err)
	}
	reads := process.service.KillReadCount()
	process.registerOk(listener, 1, listener.edgeRegistration(t, name, "tls", "http"))
	if err := process.service.AwaitKillReads(world.ctx, reads+1); err != nil {
		t.Fatal(err)
	}
	edge := world.newEdge(1)
	find := func() *sidecar.SocketError {
		t.Helper()
		code, result := process.find(edge.token, &sidecar.SocketFindArgs{Name: name, NetworkId: &networkId, ClientIds: edge.clientIdArgs()})
		if code != http.StatusOK {
			t.Fatalf("a Find answered %d", code)
		}
		return result.Error
	}
	if refusal := find(); refusal != nil {
		t.Fatalf("with no kill the Find answered %+v", refusal)
	}

	kill, err := json.Marshal(&sidecar.TlsKillEntry{Host: "blog", Reason: "phishing"})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.host.Redis.HashSet(world.ctx, sidecar.TlsKillKey(sidecar.Id(networkId)), map[string][]byte{"blog": kill}); err != nil {
		t.Fatal(err)
	}
	if refusal := find(); refusal != nil {
		t.Fatalf("before its event the kill refused the Find: %+v", refusal)
	}
	reads = process.service.KillReadCount()
	process.service.KillChanged(networkId)
	if err := process.service.AwaitKillReads(world.ctx, reads+1); err != nil {
		t.Fatal(err)
	}
	if refusal := find(); refusal == nil || refusal.Code != sidecar.SocketErrorCodeDenied {
		t.Fatalf("after its event the Find answered %+v", refusal)
	}

	if err := process.host.Redis.HashDelete(world.ctx, sidecar.TlsKillKey(sidecar.Id(networkId)), []string{"blog"}); err != nil {
		t.Fatal(err)
	}
	reads = process.service.KillReadCount()
	process.service.KillsResync()
	if err := process.service.AwaitKillReads(world.ctx, reads+1); err != nil {
		t.Fatal(err)
	}
	if refusal := find(); refusal != nil {
		t.Fatalf("after the resubscription the lifted kill answered %+v", refusal)
	}
}
