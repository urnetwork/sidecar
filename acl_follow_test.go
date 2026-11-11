//go:build !ios_extension

// AclFollower on T2's shape: each applied entry installs the newest state in the engine and acks it, a burst
// coalescing to one ack of the newest n an interval; a failed ack is dropped and never retried; a base whose rows do not
// compile from its head forks TEAM's ConfigClient, which alarms, and the engine keeps its state; the grants view moves
// with each install; and propagation on the fake clock meets §8.9's p50 1 s and p99 5 s from each entry's time to the
// ack covering it. The clock moves only when the test moves it; loads and acks report on channels.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A source over a test network's reader, whose callbacks the test fires.
type aclTestFollowSource struct {
	stateLock sync.Mutex
	state     *ConfigState
	callbacks []SidecarAuthorityEntryFunction
}

func (self *aclTestFollowSource) State() *ConfigState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state
}

func (self *aclTestFollowSource) AddEntryCallback(callback SidecarAuthorityEntryFunction) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.callbacks = append(self.callbacks, callback)
	return func() {}
}

// Makes state the newest and calls back once, as the client does after applying the entry that reached it.
func (self *aclTestFollowSource) applied(state *ConfigState) {
	callbacks := func() []SidecarAuthorityEntryFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.state = state
		return slices.Clone(self.callbacks)
	}()
	for _, callback := range callbacks {
		callback(&SidecarAuthorityEntry{Pin: state.Pin(), TimeMs: state.TimeMs()})
	}
}

// One ack as api received it, with the follower's clock when it was sent.
type aclTestAck struct {
	version uint64
	timeMs  int64
	sentAt  time.Time
}

// An api that records each ack, failing those fail says.
type aclTestAckSender struct {
	clock *testConfigClock
	acks  chan aclTestAck
	fail  func(version uint64) bool
}

func newAclTestAckSender(clock *testConfigClock) *aclTestAckSender {
	return &aclTestAckSender{clock: clock, acks: make(chan aclTestAck, 1024)}
}

func (self *aclTestAckSender) PostAclAck(ctx context.Context, version uint64, timeMs int64) (bool, error) {
	self.acks <- aclTestAck{version: version, timeMs: timeMs, sentAt: self.clock.Now()}
	if self.fail != nil && self.fail(version) {
		return false, errors.New("api answered 503")
	}
	return true, nil
}

// The next ack, failing the test after a real-time bound that only a broken loop reaches.
func (self *aclTestAckSender) next(t *testing.T) aclTestAck {
	t.Helper()
	select {
	case ack := <-self.acks:
		return ack
	case <-time.After(30 * time.Second):
		t.Fatal("no ack")
	}
	return aclTestAck{}
}

// Fails the test when an ack is waiting.
func (self *aclTestAckSender) none(t *testing.T) {
	t.Helper()
	select {
	case ack := <-self.acks:
		t.Fatalf("an unexpected ack of %d", ack.version)
	default:
	}
}

// The duration the clock was next armed with, failing the test after a real-time bound.
func aclTestArmed(t *testing.T, clock *testConfigClock) time.Duration {
	t.Helper()
	select {
	case timeout := <-clock.armed:
		return timeout
	case <-time.After(30 * time.Second):
		t.Fatal("nothing armed the clock")
	}
	return 0
}

// A follower over a fake source on the test network, the owner's device its sidecar.
type aclFollowWorld struct {
	net      *testConfigNet
	source   *aclTestFollowSource
	clock    *testConfigClock
	acks     *aclTestAckSender
	engine   *AclEngine
	follower *AclFollower
	settings *AclSettings
}

func newAclFollowWorld(t *testing.T) *aclFollowWorld {
	net := newTestConfigNet(t)
	clock := newTestConfigClock()
	world := &aclFollowWorld{
		net:      net,
		source:   &aclTestFollowSource{state: net.log.State()},
		clock:    clock,
		acks:     newAclTestAckSender(clock),
		engine:   NewAclEngine(net.owner.sidecarId, nil, nil, nil),
		settings: DefaultAclSettings(),
	}
	world.settings.Clock = clock
	world.settings.Log = NewNoopLogger()
	follower, err := NewAclFollower(context.Background(), &AclFollowerArgs{Source: world.source, Engine: world.engine, Acks: world.acks, Settings: world.settings})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(follower.Close)
	world.follower = follower
	return world
}

// Posts a statement on the network and has the source apply it.
func (self *aclFollowWorld) post(label string) *ConfigState {
	self.net.mustPost(self.net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, self.net.memberAdmitStatement(label))
	state := self.net.log.State()
	self.source.applied(state)
	return state
}

// A state installs at its callback and acks at once; a burst during the ack interval coalesces to one ack of the
// newest n at its end; an interval with no install sends nothing.
func TestAclFollowerInstallsAndCoalescesAcks(t *testing.T) {
	world := newAclFollowWorld(t)
	first := world.acks.next(t)
	if first.version != world.net.n || first.timeMs != world.net.log.State().TimeMs() || !proto.Equal(world.engine.Pin(), world.net.log.Pin()) {
		t.Fatalf("the first ack %+v, engine at %v", first, world.engine.Pin())
	}
	if interval := aclTestArmed(t, world.clock); interval != world.settings.AckInterval {
		t.Fatalf("the interval armed %v", interval)
	}
	for _, label := range []string{"a", "b", "c", "d", "e"} {
		state := world.post(label)
		if !proto.Equal(world.engine.Pin(), state.Pin()) {
			t.Fatalf("%s not installed at its callback", label)
		}
	}
	world.acks.none(t)
	world.clock.Advance(world.settings.AckInterval)
	coalesced := world.acks.next(t)
	if coalesced.version != world.net.n {
		t.Fatalf("the coalesced ack is of %d, not %d", coalesced.version, world.net.n)
	}
	aclTestArmed(t, world.clock)
	world.clock.Advance(world.settings.AckInterval)
	world.acks.none(t)
	if stats := world.follower.Stats(); stats.AckCount != 2 || stats.InstallCount != 6 || stats.RefusalCount != 0 {
		t.Errorf("stats %+v", stats)
	}

	// a quiet interval past, the next install acks at once
	world.post("f")
	if ack := world.acks.next(t); ack.version != world.net.n {
		t.Errorf("after a quiet interval: %+v", ack)
	}
}

// A failed ack is dropped: the loop does not send its n again, and the next state's ack carries the newer n.
func TestAclFollowerDropsAFailedAck(t *testing.T) {
	net := newTestConfigNet(t)
	clock := newTestConfigClock()
	acks := newAclTestAckSender(clock)
	failing := net.n
	acks.fail = func(version uint64) bool { return version == failing }
	settings := DefaultAclSettings()
	settings.Clock, settings.Log = clock, NewNoopLogger()
	source := &aclTestFollowSource{state: net.log.State()}
	follower, err := NewAclFollower(context.Background(), &AclFollowerArgs{Source: source, Engine: NewAclEngine(net.owner.sidecarId, nil, nil, nil), Acks: acks, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()
	if ack := acks.next(t); ack.version != failing {
		t.Fatalf("the first ack %+v", ack)
	}
	aclTestArmed(t, clock)
	clock.Advance(settings.AckInterval)
	acks.none(t)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("next"))
	source.applied(net.log.State())
	if ack := acks.next(t); ack.version != net.n {
		t.Fatalf("the next ack %+v", ack)
	}
	// the sender holds the ack before ack() counts it; the loop arms its interval only after, so the counts are final
	aclTestArmed(t, clock)
	if stats := follower.Stats(); stats.AckFailureCount != 1 || stats.AckCount != 1 {
		t.Errorf("stats %+v", stats)
	}
}

// §7's BASE row owns the rows check: a base whose rows do not compile from its head forks the real ConfigClient, which
// raises head_alarm fork, and the follower installs nothing, the engine keeping its state.
func TestAclFollowerKeepsTheEngineOnARowsMismatch(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	net.fold(net.owner, net.n, 2)
	world.publish()
	client := world.client(nil)
	world.caughtUp(client)
	engine := NewAclEngine(net.owner.sidecarId, nil, nil, nil)
	clock := newTestConfigClock()
	settings := DefaultAclSettings()
	settings.Clock, settings.Log = clock, NewNoopLogger()
	follower, err := NewAclFollower(context.Background(), &AclFollowerArgs{Source: client, Engine: engine, Settings: settings, Emit: func(event SidecarEvent) {}})
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()
	held := engine.Pin()
	if !proto.Equal(held, net.log.Pin()) {
		t.Fatalf("the engine holds %v, not %v", held, net.log.Pin())
	}

	// a statement applies and installs
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("applies"))
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	world.caughtUp(client)
	if !proto.Equal(engine.Pin(), net.log.Pin()) {
		t.Fatalf("the statement's state is not installed: %v", engine.Pin())
	}
	held = engine.Pin()
	installs := follower.Stats().InstallCount

	// a base whose rows are not its head's compile
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.HasDocument = true
	})
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.CatchUp(ctx); !errors.Is(err, ErrConfigFork) && !errors.Is(err, ErrConfigRunRefused) {
		t.Fatalf("the mismatched base: %v", err)
	}
	if world.headAlarms(SidecarHeadAlarmFork) == 0 {
		t.Error("no head_alarm fork")
	}
	if !proto.Equal(engine.Pin(), held) || follower.Stats().InstallCount != installs {
		t.Errorf("the engine moved to %v", engine.Pin())
	}
}

// The grants view is the installed state as ids, and GrantsChanged moves at each install.
func TestAclFollowerServesTheGrantsView(t *testing.T) {
	world := newAclFollowWorld(t)
	world.acks.next(t)
	version, changed := world.follower.GrantsChanged()
	grants := world.follower.Grants()
	if version != world.net.n || grants == nil || !proto.Equal(grants.Pin, world.net.log.Pin()) {
		t.Fatalf("version %d, grants %+v", version, grants)
	}
	if len(grants.Sidecars) != 1 || grants.Sidecars[0].SidecarId != world.net.owner.sidecarId ||
		len(grants.Members) != 1 || grants.Members[0].Role != bridge.MemberRole_MEMBER_ROLE_OWNER {
		t.Errorf("admissions %+v, members %+v", grants.Sidecars, grants.Members)
	}
	world.net.withAclRows(func(rows *protocol.AclRows) {
		rows.HasDocument = true
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:   testConfigId("grants rule").Bytes(),
			SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{RepoId: make([]byte, 16)}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_READ)},
		})
	})
	world.source.applied(world.net.log.State())
	select {
	case <-changed:
	default:
		t.Fatal("GrantsChanged did not move")
	}
	grants = world.follower.Grants()
	if len(grants.Rules) != 1 || !slices.Equal(grants.Rules[0].Targets, []string{"repo:*"}) ||
		!slices.Equal(grants.Rules[0].Actions, []protocol.AclAction{protocol.AclAction_ACL_ACTION_READ}) || !grants.HasDocument {
		t.Errorf("rules %+v", grants.Rules)
	}
}

// §8.9's applied-time targets on the harness: entries every 250 ms of the fake clock, each applied 100 ms after its
// time, and the ack covering each sent within p50 1 s and p99 5 s of the entry's time, with no ack sooner than an
// interval after the one before.
func TestAclFollowerPropagationMeetsTheTargets(t *testing.T) {
	world := newAclFollowWorld(t)
	interval := world.settings.AckInterval
	ack := world.acks.next(t)
	acks := []aclTestAck{ack}
	intervalEnd := world.clock.Now().Add(aclTestArmed(t, world.clock))
	pending := false
	type entry struct {
		version uint64
		timeMs  int64
	}
	entries := []entry{}
	for i := range 200 {
		world.net.mustPost(world.net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, world.net.memberAdmitStatement(string(rune('A'+i%26))+string(rune('a'+i/26))))
		state := world.net.log.State()
		// entries every 250 ms on the clock, each applied 100 ms after it, the clock never behind
		appliedAt := time.UnixMilli(world.clock.Now().UnixMilli() + 250)
		if !intervalEnd.IsZero() && !appliedAt.Before(intervalEnd) {
			// the interval ends first: an ack of what is pending goes then, or the loop goes idle
			world.clock.Advance(intervalEnd.Sub(world.clock.Now()))
			if pending {
				acks = append(acks, world.acks.next(t))
				intervalEnd = world.clock.Now().Add(aclTestArmed(t, world.clock))
			} else {
				intervalEnd = time.Time{}
			}
			pending = false
		}
		if delta := appliedAt.Sub(world.clock.Now()); 0 < delta {
			world.clock.Advance(delta)
		}
		entries = append(entries, entry{version: state.Pin().GetVersion(), timeMs: world.clock.Now().UnixMilli() - 100})
		world.source.applied(state)
		if intervalEnd.IsZero() {
			acks = append(acks, world.acks.next(t))
			intervalEnd = world.clock.Now().Add(aclTestArmed(t, world.clock))
		} else {
			pending = true
		}
	}
	world.clock.Advance(intervalEnd.Sub(world.clock.Now()))
	if pending {
		acks = append(acks, world.acks.next(t))
	}
	for i := 1; i < len(acks); i += 1 {
		if acks[i].sentAt.Sub(acks[i-1].sentAt) < interval {
			t.Fatalf("acks %d and %d are %v apart", i-1, i, acks[i].sentAt.Sub(acks[i-1].sentAt))
		}
	}
	delays := []time.Duration{}
	for _, entry := range entries {
		covering := slices.IndexFunc(acks, func(ack aclTestAck) bool { return entry.version <= ack.version })
		if covering < 0 {
			t.Fatalf("entry %d was never acked", entry.version)
		}
		delays = append(delays, acks[covering].sentAt.Sub(time.UnixMilli(entry.timeMs)))
	}
	slices.Sort(delays)
	p50, p99 := delays[len(delays)/2], delays[len(delays)*99/100]
	if time.Second < p50 || 5*time.Second < p99 {
		t.Errorf("p50 %v, p99 %v", p50, p99)
	}
	if len(acks) <= 1 || len(entries) <= len(acks) {
		t.Errorf("%d acks for %d entries", len(acks), len(entries))
	}
}
