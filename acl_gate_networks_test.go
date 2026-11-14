//go:build !sidecar_http && !ios_extension

// What a follower reads of the gate cache (QD-718), on the fake source and fake clock of acl_gate_test.go: the list
// holds loaded networks alone; the index names a sidecar's network from its row, a revoked one's too, drops an evicted
// network's sidecars, and answers none for an id two logs admit; and an install callback runs after the install, never
// during a load and never for a load that installed nothing, with the snapshot and the index already the new ones.
// No sleeps: a held source keeps a load open, and loads report as they finish.

package sidecar

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The list is the loaded networks, sorted, and the index is their sidecars' rows: a tracked network with nothing
// loaded is in neither, a device admitted later is found at the next install, and a revoked one stays found, since
// its tombstone is what tells a reader it is revoked.
func TestAclGateListsLoadedNetworksAndIndexesTheirSidecars(t *testing.T) {
	source := newAclGateTestSource()
	x, y := newTestConfigNetNamed(t, "list x"), newTestConfigNetNamed(t, "list y")
	source.publish(x)
	source.publish(y)
	unpublished := NewId()
	settings := DefaultAclGateSettings()
	settings.FailureBackoff = 0
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), settings)
	if networkIds := cache.Networks(); len(networkIds) != 0 {
		t.Fatalf("an empty cache lists %v", networkIds)
	}
	if _, found := cache.SidecarNetwork(x.owner.sidecarId); found {
		t.Fatal("a sidecar found before any load")
	}
	for _, networkId := range []Id{x.networkId, y.networkId} {
		cache.Changed(networkId)
		if load := aclGateTestNextLoad(t, loads); load.err != nil {
			t.Fatal(load.err)
		}
	}
	cache.Changed(unpublished)
	if load := aclGateTestNextLoad(t, loads); load.err == nil {
		t.Fatal("an unpublished network loaded")
	}
	want := []Id{x.networkId, y.networkId}
	slices.SortFunc(want, Id.Cmp)
	if networkIds := cache.Networks(); !slices.Equal(networkIds, want) {
		t.Fatalf("the list %v, want %v", networkIds, want)
	}
	for _, net := range []*testConfigNet{x, y} {
		if networkId, found := cache.SidecarNetwork(net.owner.sidecarId); !found || networkId != net.networkId {
			t.Errorf("the owner's network: %s, %t", networkId, found)
		}
	}
	if _, found := cache.SidecarNetwork(NewId()); found {
		t.Error("a sidecar no log admits was found")
	}

	device := x.admitMemberDevice("list later")
	if _, found := cache.SidecarNetwork(device.sidecarId); found {
		t.Fatal("a device found before its admission loaded")
	}
	source.publish(x)
	cache.Changed(x.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	if networkId, found := cache.SidecarNetwork(device.sidecarId); !found || networkId != x.networkId {
		t.Fatalf("the admitted device's network: %s, %t", networkId, found)
	}
	x.mustPost(x.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, x.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	source.publish(x)
	cache.Changed(x.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	networkId, found := cache.SidecarNetwork(device.sidecarId)
	if !found || networkId != x.networkId {
		t.Fatalf("the revoked device's network: %s, %t", networkId, found)
	}
	snapshot, _ := cache.State(networkId)
	if snapshot.Config.SidecarRow(device.sidecarId).GetRevokedAt() == 0 {
		t.Error("the revoked device's row is no tombstone")
	}
}

// A callback runs once for each install and only after it: while a load is held open nothing is called, and when it
// runs the cache already answers the new snapshot and the index the new device, so what it wakes cannot read the state
// before. A load that reads nothing new calls nothing, and a removed callback is called no more.
func TestAclGateInstallCallbackRunsAfterEachInstall(t *testing.T) {
	net := newTestConfigNet(t)
	source := newAclGateTestSource()
	source.publish(net)
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	type install struct {
		networkId Id
		snapshot  *AclGateSnapshot
		// what the cache answered from inside the callback
		state      *AclGateSnapshot
		status     AclGateStatus
		deviceId   Id
		deviceSeen bool
	}
	installs := make(chan install, 16)
	var watched Id
	remove := cache.AddInstallCallback(func(networkId Id, snapshot *AclGateSnapshot) {
		state, status := cache.State(networkId)
		_, seen := cache.SidecarNetwork(watched)
		installs <- install{networkId: networkId, snapshot: snapshot, state: state, status: status, deviceId: watched, deviceSeen: seen}
	})
	others := make(chan Id, 16)
	removeOther := cache.AddInstallCallback(func(networkId Id, snapshot *AclGateSnapshot) {
		others <- networkId
	})

	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	first := <-installs
	if first.networkId != net.networkId || first.status != AclGateLoaded || first.state != first.snapshot || !proto.Equal(first.snapshot.Pin, net.log.Pin()) {
		t.Fatalf("the cold start's install: %+v", first)
	}
	<-others

	// a load that reads nothing new installs nothing
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	select {
	case again := <-installs:
		t.Fatalf("a callback for a load that installed nothing: %+v", again)
	default:
	}

	// the log moves, and its load is held open: the hint has come, and no callback has
	device := net.admitMemberDevice("install later")
	watched = device.sidecarId
	source.publish(net)
	func() {
		source.stateLock.Lock()
		defer source.stateLock.Unlock()
		source.hold = make(chan struct{})
	}()
	for len(source.started) != 0 {
		<-source.started
	}
	cache.Changed(net.networkId)
	<-source.started
	select {
	case early := <-installs:
		t.Fatalf("a callback before the load finished: %+v", early)
	default:
	}
	if held, _ := cache.State(net.networkId); held != first.snapshot {
		t.Fatal("the state moved while its load was held")
	}
	removeOther()
	close(source.hold)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	second := <-installs
	if second.state != second.snapshot || !proto.Equal(second.snapshot.Pin, net.log.Pin()) || second.snapshot == first.snapshot {
		t.Fatalf("the install after the hint: %+v", second)
	}
	if !second.deviceSeen {
		t.Error("the index had not moved when the callback ran")
	}
	select {
	case networkId := <-others:
		t.Errorf("a removed callback was called for %s", networkId)
	default:
	}

	// the entry the install carried: its time and the sidecar that signed it
	entry := second.snapshot.Entry(second.snapshot.Pin.GetVersion())
	if entry == nil || entry.SignerSidecarId == nil || *entry.SignerSidecarId != net.owner.sidecarId || entry.TimeMs != second.snapshot.Config.TimeMs() {
		t.Errorf("the newest entry: %+v", entry)
	}
	if entry := second.snapshot.Entry(second.snapshot.Pin.GetVersion() + 1); entry != nil {
		t.Errorf("an entry above the snapshot: %+v", entry)
	}
	if entry := second.snapshot.Entry(0); entry != nil {
		t.Errorf("an entry at position 0: %+v", entry)
	}

	remove()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("after removal"))
	func() {
		source.stateLock.Lock()
		defer source.stateLock.Unlock()
		source.hold = nil
	}()
	source.publish(net)
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !proto.Equal(load.pin, net.log.Pin()) {
		t.Fatalf("the load after the removal: %v", load.err)
	}
	select {
	case late := <-installs:
		t.Errorf("a removed callback was called: %+v", late)
	default:
	}
}

// A sidecar two loaded logs admit is of no one network the cache can name, and is found again once one of them is
// evicted; an evicted network leaves the list and the index, and returns to both with its reload.
func TestAclGateIndexRefusesASharedSidecarAndDropsAnEvictedNetwork(t *testing.T) {
	source := newAclGateTestSource()
	nets := []*testConfigNet{}
	shared := []testConfigDevice{}
	for i, label := range []string{"index x", "index y", "index z"} {
		net := newTestConfigNetNamed(t, label)
		if i < 2 {
			// the same device label in two networks gives the same sidecar id in each log
			shared = append(shared, net.admitMemberDevice("index shared"))
		} else {
			net.admitMemberDevice("index z alone")
		}
		source.publish(net)
		nets = append(nets, net)
	}
	sharedId := shared[0].sidecarId
	if shared[1].sidecarId != sharedId {
		t.Fatal("the networks admitted different ids")
	}
	probe, probeLoads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	probe.Changed(nets[0].networkId)
	aclGateTestNextLoad(t, probeLoads)
	oneNetwork := probe.byteTotal.Load()

	settings := DefaultAclGateSettings()
	settings.ByteBudget = 2*oneNetwork + oneNetwork/2
	settings.FailureBackoff = 0
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), settings)
	cache.Changed(nets[0].networkId)
	aclGateTestNextLoad(t, loads)
	if networkId, found := cache.SidecarNetwork(sharedId); !found || networkId != nets[0].networkId {
		t.Fatalf("one log's sidecar: %s, %t", networkId, found)
	}
	cache.Changed(nets[1].networkId)
	aclGateTestNextLoad(t, loads)
	if networkId, found := cache.SidecarNetwork(sharedId); found {
		t.Fatalf("a sidecar two logs admit was given to %s", networkId)
	}
	for _, net := range nets[:2] {
		if networkId, found := cache.SidecarNetwork(net.owner.sidecarId); !found || networkId != net.networkId {
			t.Errorf("an owner beside the shared sidecar: %s, %t", networkId, found)
		}
	}

	// the third load evicts the network read longest ago, the second
	cache.epoch.Add(1)
	cache.State(nets[0].networkId)
	cache.Changed(nets[2].networkId)
	aclGateTestNextLoad(t, loads)
	if cache.Stats().EvictionCount != 1 {
		t.Fatalf("%+v", cache.Stats())
	}
	want := []Id{nets[0].networkId, nets[2].networkId}
	slices.SortFunc(want, Id.Cmp)
	if networkIds := cache.Networks(); !slices.Equal(networkIds, want) {
		t.Fatalf("the list after the eviction %v, want %v", networkIds, want)
	}
	if _, found := cache.SidecarNetwork(nets[1].owner.sidecarId); found {
		t.Error("an evicted network's sidecar is still indexed")
	}
	if networkId, found := cache.SidecarNetwork(sharedId); !found || networkId != nets[0].networkId {
		t.Errorf("the shared sidecar once one log holds it: %s, %t", networkId, found)
	}
	if networkId, found := cache.SidecarNetwork(nets[2].owner.sidecarId); !found || networkId != nets[2].networkId {
		t.Errorf("the loaded network's owner: %s, %t", networkId, found)
	}
}
