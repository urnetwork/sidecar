//go:build !sidecar_http

// The gate cache on a fake source and a fake clock (T2's shape, no sleeps): a miss touches no store; an unloaded
// network is never allowed; a revocation is seen by its event and, with the event lost, by the poll; triggers during a
// load coalesce to one more; a run with a gap or a second A_n at a held position is refused with an alarm while the old
// state serves; a cold start never lands below the pin the cache last held; and the byte budget evicts the network read
// longest ago, keeping its pin. FS-62's {acl_}e case runs on the direct source in acl_gate_source_test.go.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clock whose one timer the test fires: After reports what was armed and answers a channel the test sends on.
type aclGateTestClock struct {
	stateLock sync.Mutex
	current   time.Time
	armed     chan time.Duration
	fire      chan time.Time
}

func newAclGateTestClock() *aclGateTestClock {
	return &aclGateTestClock{current: aclTestNow, armed: make(chan time.Duration, 64), fire: make(chan time.Time)}
}

func (self *aclGateTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

func (self *aclGateTestClock) After(timeout time.Duration) <-chan time.Time {
	self.armed <- timeout
	return self.fire
}

func (self *aclGateTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return false }
}

// A source over test networks' published entries: what a test publishes, a load reads. Entries may be held, counted
// and rewritten.
type aclGateTestSource struct {
	stateLock sync.Mutex
	// by network: its genesis, its entries from position 1, its rows by hash
	genesis map[Id][]byte
	entries map[Id][][]byte
	rows    map[Id]ConfigRowsSource
	// each Entries call, counted, and while hold is set, waiting on it after reporting on started
	entriesCalls int
	hold         chan struct{}
	started      chan struct{}
	// rewrites what Entries answers
	rewrite func(networkId Id, after *bridge.AuthPin, entries [][]byte) [][]byte
}

func newAclGateTestSource() *aclGateTestSource {
	return &aclGateTestSource{genesis: map[Id][]byte{}, entries: map[Id][][]byte{}, rows: map[Id]ConfigRowsSource{}, started: make(chan struct{}, 64)}
}

// Publishes a test network's log as it stands.
func (self *aclGateTestSource) publish(net *testConfigNet) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.genesis[net.networkId] = net.signedGenesis
	self.entries[net.networkId] = slices.Clone(net.entries)
	self.rows[net.networkId] = net.rowsOnlySource()
}

func (self *aclGateTestSource) Genesis(ctx context.Context, networkId Id) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	genesis, found := self.genesis[networkId]
	if !found {
		return nil, ErrBlobNotFound
	}
	return genesis, nil
}

func (self *aclGateTestSource) Entries(ctx context.Context, networkId Id, after *bridge.AuthPin) ([][]byte, error) {
	hold, entries, rewrite := func() (chan struct{}, [][]byte, func(Id, *bridge.AuthPin, [][]byte) [][]byte) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.entriesCalls += 1
		entries := self.entries[networkId]
		from := uint64(0)
		if after != nil {
			from = after.GetVersion()
		}
		if uint64(len(entries)) < from {
			from = uint64(len(entries))
		}
		return self.hold, slices.Clone(entries[from:]), self.rewrite
	}()
	self.started <- struct{}{}
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if rewrite != nil {
		entries = rewrite(networkId, after, entries)
	}
	return entries, nil
}

func (self *aclGateTestSource) Rows(ctx context.Context, networkId Id, rowsSha256 []byte) ([]byte, error) {
	self.stateLock.Lock()
	rows := self.rows[networkId]
	self.stateLock.Unlock()
	if rows == nil {
		return nil, ErrBlobNotFound
	}
	return rows.Rows(networkId, rowsSha256)
}

// How many Entries calls ran.
func (self *aclGateTestSource) calls() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.entriesCalls
}

// One finished load, as the cache's hook reports it.
type aclGateTestLoad struct {
	networkId Id
	pin       *bridge.AuthPin
	err       error
}

// A cache over source on clock, whose loads report on the returned channel, closed at the test's end.
func newAclGateTestCache(t *testing.T, source AclGateSource, clock Clock, settings *AclGateSettings) (*AclGateCache, chan aclGateTestLoad) {
	if settings == nil {
		settings = DefaultAclGateSettings()
	}
	settings.Log = NewNoopLogger()
	loads := make(chan aclGateTestLoad, 64)
	settings.OnLoad = func(networkId Id, pin *bridge.AuthPin, err error) {
		loads <- aclGateTestLoad{networkId: networkId, pin: pin, err: err}
	}
	cache := NewAclGateCache(context.Background(), source, clock, settings)
	t.Cleanup(cache.Close)
	return cache, loads
}

// Waits for the next load to finish, failing the test after a real-time bound that only a broken cache reaches.
func aclGateTestNextLoad(t *testing.T, loads chan aclGateTestLoad) aclGateTestLoad {
	t.Helper()
	select {
	case load := <-loads:
		return load
	case <-time.After(30 * time.Second):
		t.Fatal("no load finished")
	}
	return aclGateTestLoad{}
}

// A network the cache holds nothing of costs one map read: no source call, no load, no store touched (R-ACL-8).
func TestAclGateMissTouchesNoStore(t *testing.T) {
	source := newAclGateTestSource()
	clock := newAclGateTestClock()
	cache, _ := newAclGateTestCache(t, source, clock, nil)
	<-clock.armed
	missing := NewId()
	for range 100 {
		if snapshot, status := cache.State(missing); snapshot != nil || status != AclGateUnknown {
			t.Fatalf("%v, %d", snapshot, status)
		}
	}
	if source.calls() != 0 || cache.Stats() != (AclGateStats{}) {
		t.Errorf("a miss read: %d calls, %+v", source.calls(), cache.Stats())
	}
	if allocations := testing.AllocsPerRun(100, func() { cache.State(missing) }); 0 < allocations {
		t.Errorf("a miss allocates %v", allocations)
	}
}

// Cold state is no pass: a network the cache tracks reads not loaded, with no snapshot to allow from, until its first
// verified state installs.
func TestAclGateUnloadedNetworkIsNeverAllowed(t *testing.T) {
	net := newTestConfigNet(t)
	source := newAclGateTestSource()
	source.publish(net)
	source.hold = make(chan struct{})
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	cache.Changed(net.networkId)
	<-source.started
	if snapshot, status := cache.State(net.networkId); snapshot != nil || status != AclGateNotLoaded {
		t.Fatalf("while loading: %v, %d", snapshot, status)
	}
	close(source.hold)
	load := aclGateTestNextLoad(t, loads)
	snapshot, status := cache.State(net.networkId)
	if load.err != nil || status != AclGateLoaded || !proto.Equal(snapshot.Pin, net.log.Pin()) || !proto.Equal(load.pin, snapshot.Pin) {
		t.Fatalf("after the load: %v, %d", load.err, status)
	}
}

// A revocation reaches the gate by its {acl_}v event, and with the event lost by the poll, which fires at
// PollInterval plus at most PollJitter.
func TestAclGateSeesARevocationByEventAndByPoll(t *testing.T) {
	net := newTestConfigNet(t)
	first, second := net.admitMemberDevice("event revoked"), net.admitMemberDevice("poll revoked")
	source := newAclGateTestSource()
	source.publish(net)
	clock := newAclGateTestClock()
	settings := DefaultAclGateSettings()
	cache, loads := newAclGateTestCache(t, source, clock, settings)
	armed := <-clock.armed
	if armed < settings.PollInterval || settings.PollInterval+settings.PollJitter < armed {
		t.Fatalf("the poll armed %v", armed)
	}
	cache.Changed(net.networkId)
	aclGateTestNextLoad(t, loads)
	revoked := func(sidecarId Id) bool {
		snapshot, status := cache.State(net.networkId)
		if status != AclGateLoaded {
			t.Fatalf("status %d", status)
		}
		return snapshot.Config.SidecarRow(sidecarId).GetRevokedAt() != 0
	}

	// by event: api's INCR reaches Changed
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(first, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	source.publish(net)
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !revoked(first.sidecarId) {
		t.Fatalf("the event's revocation: %v", load.err)
	}

	// by poll: no event, and the next poll loads it
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	source.publish(net)
	if revoked(second.sidecarId) {
		t.Fatal("seen before any trigger")
	}
	clock.fire <- clock.Now().Add(armed)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !revoked(second.sidecarId) || !proto.Equal(load.pin, net.log.Pin()) {
		t.Fatalf("the poll's revocation: %v", load.err)
	}
	<-clock.armed
}

// Triggers while a load runs coalesce: however many arrive, one more load follows it, and no two load at once.
func TestAclGateLoadsCoalesce(t *testing.T) {
	net := newTestConfigNet(t)
	source := newAclGateTestSource()
	source.publish(net)
	source.hold = make(chan struct{})
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	cache.Changed(net.networkId)
	<-source.started
	for range 20 {
		cache.Changed(net.networkId)
	}
	close(source.hold)
	aclGateTestNextLoad(t, loads)
	aclGateTestNextLoad(t, loads)
	select {
	case load := <-loads:
		t.Fatalf("a third load: %+v", load)
	default:
	}
	if calls := source.calls(); calls != 2 || cache.Stats().LoadCount != 2 {
		t.Errorf("%d reads, %+v", calls, cache.Stats())
	}
}

// A run with a gap, or carrying a second A_n at a position the gate holds, is refused with an alarm, and the old state
// keeps serving; proj/'s true run then moves it on.
func TestAclGateRefusesAGapAndAForkWithAnAlarm(t *testing.T) {
	net := newTestConfigNet(t)
	source := newAclGateTestSource()
	source.publish(net)
	settings := DefaultAclGateSettings()
	settings.FailureBackoff = 0
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), settings)
	cache.Changed(net.networkId)
	aclGateTestNextLoad(t, loads)
	held, _ := cache.State(net.networkId)
	for i := range 3 {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(string(rune('a'+i))))
	}
	source.publish(net)

	cases := []struct {
		name    string
		rewrite func(networkId Id, after *bridge.AuthPin, entries [][]byte) [][]byte
	}{
		{name: "a gap", rewrite: func(networkId Id, after *bridge.AuthPin, entries [][]byte) [][]byte {
			return append(slices.Clone(entries[:1]), entries[2:]...)
		}},
		{name: "a second A_n at a held position", rewrite: func(networkId Id, after *bridge.AuthPin, entries [][]byte) [][]byte {
			forged := &bridge.AuthEntry{}
			if err := proto.Unmarshal(net.entries[after.GetVersion()-1], forged); err != nil {
				t.Fatal(err)
			}
			forged.TimeMs += 1
			return append([][]byte{testConfigMarshal(t, forged)}, entries...)
		}},
	}
	for i, c := range cases {
		source.stateLock.Lock()
		source.rewrite = c.rewrite
		source.stateLock.Unlock()
		cache.Changed(net.networkId)
		load := aclGateTestNextLoad(t, loads)
		snapshot, _ := cache.State(net.networkId)
		if !errors.Is(load.err, ErrConfigRunRefused) || snapshot != held || cache.Stats().AlarmCount != uint64(i+1) {
			t.Errorf("%s: %v, alarms %d, pin %d", c.name, load.err, cache.Stats().AlarmCount, snapshot.Pin.GetVersion())
		}
	}
	source.stateLock.Lock()
	source.rewrite = nil
	source.stateLock.Unlock()
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !proto.Equal(load.pin, net.log.Pin()) {
		t.Errorf("the true run: %v", load.err)
	}
}

// Past its byte budget the cache drops the loaded state of the network read longest ago, never the one it just
// loaded; that network reads not loaded, keeps its pin, reloads when next changed, and a cold start below its pin is
// refused with an alarm.
func TestAclGateEvictsUnderItsByteBudgetAndKeepsPins(t *testing.T) {
	source := newAclGateTestSource()
	nets := []*testConfigNet{}
	for _, label := range []string{"x", "y", "z"} {
		net := newTestConfigNetNamed(t, label)
		for i := range 2 {
			net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(label+string(rune('0'+i))))
		}
		source.publish(net)
		nets = append(nets, net)
	}
	probe, probeLoads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	probe.Changed(nets[0].networkId)
	aclGateTestNextLoad(t, probeLoads)
	oneNetwork := probe.byteTotal.Load()

	settings := DefaultAclGateSettings()
	settings.ByteBudget = 2*oneNetwork + oneNetwork/2
	settings.FailureBackoff = 0
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), settings)
	for _, net := range nets[:2] {
		cache.Changed(net.networkId)
		aclGateTestNextLoad(t, loads)
	}
	cache.epoch.Add(1)
	cache.State(nets[0].networkId)
	cache.Changed(nets[2].networkId)
	aclGateTestNextLoad(t, loads)
	statuses := []AclGateStatus{}
	for _, net := range nets {
		_, status := cache.State(net.networkId)
		statuses = append(statuses, status)
	}
	if !slices.Equal(statuses, []AclGateStatus{AclGateLoaded, AclGateNotLoaded, AclGateLoaded}) || cache.Stats().EvictionCount != 1 {
		t.Fatalf("statuses %v, %+v", statuses, cache.Stats())
	}

	// the evicted network keeps its pin: a stale store's cold start below it is refused with an alarm, the true one
	// reloads
	evicted := nets[1]
	evicted.mustPost(evicted.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, evicted.memberAdmitStatement("after eviction"))
	source.stateLock.Lock()
	source.entries[evicted.networkId] = slices.Clone(evicted.entries[:len(evicted.entries)-2])
	source.stateLock.Unlock()
	cache.Changed(evicted.networkId)
	if load := aclGateTestNextLoad(t, loads); !errors.Is(load.err, ErrConfigBelowPin) || cache.Stats().AlarmCount != 1 {
		t.Fatalf("a cold start below the pin: %v", load.err)
	}
	if _, status := cache.State(evicted.networkId); status != AclGateNotLoaded {
		t.Errorf("after the refused cold start: %d", status)
	}
	source.publish(evicted)
	cache.Changed(evicted.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !proto.Equal(load.pin, evicted.log.Pin()) {
		t.Fatalf("the reload: %v", load.err)
	}
}

// newTestConfigNet's network under ids of its own, so several share one cache.
func newTestConfigNetNamed(t *testing.T, label string) *testConfigNet {
	self := &testConfigNet{
		t:             t,
		networkId:     testConfigId(label + " network"),
		ownerMemberId: testConfigId(label + " owner member"),
		source:        newTestConfigRowsSource(),
		timeMs:        testConfigStartMs,
		statesAt:      map[uint64]*ConfigState{},
		verdicts:      map[uint64]ConfigVerdict{},
	}
	self.owner = testConfigDevice{sidecarId: testConfigId(label + " owner device"), memberId: self.ownerMemberId, key: testConfigDeviceKey(label + " owner device")}
	genesis := &bridge.Genesis{
		NetworkId:              self.networkId.Bytes(),
		ConfigRepoId:           testConfigId(label + " config repo").Bytes(),
		OwnerMemberId:          self.ownerMemberId.Bytes(),
		OwnerSidecarId:         self.owner.sidecarId.Bytes(),
		OwnerIdentityPublicKey: self.owner.publicKey(),
		TimeMs:                 testConfigStartMs,
	}
	self.signedGenesis = self.sign(self.owner, bridge.SignedType_SIGNED_GENESIS, genesis)
	self.chain = bridge.GenesisChain(self.signedGenesis)
	log, err := NewConfigLog(testConfigLogSettings(), self.signedGenesis)
	if err != nil {
		t.Fatal(err)
	}
	self.log = log
	self.statesAt[0] = log.State()
	rows := &bridge.ProjectionRows{
		Members: []*bridge.MemberRow{{MemberId: self.ownerMemberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_OWNER}},
		Sidecars: []*bridge.SidecarRow{{
			SidecarId:         self.owner.sidecarId.Bytes(),
			AdmissionSigners:  [][]byte{self.owner.sidecarId.Bytes()},
			IdentityPublicKey: self.owner.publicKey(),
			IdentityAlg:       configIdentityAlgEd25519,
			MemberId:          self.ownerMemberId.Bytes(),
		}},
	}
	if verdict := self.pushBase(self.owner, rows, 0, 1, 0); !verdict.Accepted() {
		t.Fatalf("base 1: %v", verdict.Refusal)
	}
	return self
}

// A load that fails holds the network's next load back by FailureBackoff, every trigger meanwhile coalescing into it,
// so a gate asking on each request while the source fails costs one read a wait.
func TestAclGateBacksOffAfterAFailedLoad(t *testing.T) {
	net := newTestConfigNet(t)
	source := newAclGateTestSource()
	clock := newAclGateTestClock()
	settings := DefaultAclGateSettings()
	settings.PollInterval = 0
	cache, loads := newAclGateTestCache(t, source, clock, settings)
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err == nil {
		t.Fatal("a load of an unpublished network read")
	}
	if armed := <-clock.armed; armed != settings.FailureBackoff {
		t.Fatalf("the back-off armed %v", armed)
	}
	source.publish(net)
	for range 20 {
		cache.Changed(net.networkId)
	}
	if calls := source.calls(); calls != 0 {
		t.Fatalf("%d reads during the back-off", calls)
	}
	clock.fire <- clock.Now().Add(settings.FailureBackoff)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !proto.Equal(load.pin, net.log.Pin()) {
		t.Fatalf("the load after the back-off: %v", load.err)
	}
	select {
	case load := <-loads:
		t.Fatalf("another load: %+v", load)
	default:
	}
}
