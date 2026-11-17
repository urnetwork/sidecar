// §11.6's due row classed from the log (question evs1-m2-16-due-classification, option 3; QD-949) on a real network: an
// agent's ordinary revocation, its other removals and an expiry alone are batched; a compromise revocation of the same
// agent, a member device's removal, a member's removal and a base's own shrink are immediate, and so is any span holding
// one of them; a view that cannot reach the earlier pin, or holds it on another chain, reads immediate. Every reader of
// one log classes alike: the network's own long-running reader and one walked from the genesis, as a client holds the
// log, and a new device and a rows-only gate restored at the newest base, as evs's gate cache holds it. The client's
// pressure and status on that log follow the same class, and the fail-closed branches of a shrink's class read
// immediate.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network for the due's class: its owner owns tag ci; member m's device reads a general repo, and so do two agents
// of ci, admitted by the owner's device under no Delegation and reading by their own grants, and a third whose
// not_after passes an hour on; then a base folding everything, so a new device and a rows-only gate start at the pin
// every span starts from.
type evsDueClassWorld struct {
	t        *testing.T
	net      *testConfigNet
	tagId    Id
	repoId   Id
	device   testConfigDevice
	agent    testConfigDevice
	second   testConfigDevice
	expiring testConfigDevice
	// the base's pin, where every span starts
	from *bridge.AuthPin
}

func newEvsDueClassWorld(t *testing.T) *evsDueClassWorld {
	t.Helper()
	net, ci, _ := newTestConfigTagNet(t)
	_, device := net.consentedMember("m")
	day := int64(24 * 60 * 60 * 1000)
	world := &evsDueClassWorld{
		t:        t,
		net:      net,
		tagId:    ci,
		device:   device,
		agent:    net.device("ci agent", Id{}),
		second:   net.device("ci agent two", Id{}),
		expiring: net.device("ci agent expiring", Id{}),
	}
	for _, agent := range []testConfigDevice{world.agent, world.second} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{ci}, false, net.timeMs+day, 0))
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(world.expiring, []Id{ci}, false, net.timeMs+60*60*1000, 0))
	world.repoId = net.createRepo("due class")
	for _, reader := range []testConfigDevice{world.device, world.agent, world.second, world.expiring} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: net.header(), RepoId: world.repoId.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		})
	}
	holders, err := KeyHolders(net.log.State(), world.repoId, time.UnixMilli(net.timeMs))
	if err != nil || !holders.Contains(GkmHolderLeaf, world.device.sidecarId.Bytes()) ||
		!holders.Contains(GkmHolderAgent, world.agent.sidecarId.Bytes()) || !holders.Contains(GkmHolderAgent, world.second.sidecarId.Bytes()) ||
		!holders.Contains(GkmHolderAgent, world.expiring.sidecarId.Bytes()) {
		t.Fatalf("the repo's holders %v: %v", holders, err)
	}
	if verdict := net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()); !verdict.Accepted() {
		t.Fatalf("the base: %v", verdict.Refusal)
	}
	world.from = net.log.Pin()
	return world
}

// A SidecarRevoke of device by the owner's device for reason.
func (self *evsDueClassWorld) revoke(device testConfigDevice, reason bridge.SidecarRevokeReason) {
	self.t.Helper()
	self.net.mustPost(self.net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, self.net.revocation(device, reason))
}

// A compromise revocation of device by the owner's device, from the base on.
func (self *evsDueClassWorld) compromise(device testConfigDevice) {
	self.t.Helper()
	self.net.mustPost(self.net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, self.net.compromise(device, self.from.GetVersion()))
}

// A RepoRevoke of device's grant on the repo.
func (self *evsDueClassWorld) revokeGrant(device testConfigDevice) {
	self.t.Helper()
	self.net.mustPost(self.net.owner, bridge.SignedType_SIGNED_REPO_REVOKE, &protocol.RepoRevoke{
		Header: self.net.header(), RepoId: self.repoId.Bytes(), Subject: device.sidecarId.Bytes(),
	})
}

// The expiring agent's not_after passes, and an entry that touches no row lands after it: an empty tick, as api's
// ticks go on whether or not anything is due.
func (self *evsDueClassWorld) expire() {
	self.t.Helper()
	fromTime := time.UnixMilli(self.net.timeMs)
	self.lapse()
	if verdict := self.net.tick(&bridge.ApiTick{}); !verdict.Accepted() {
		self.t.Fatalf("an empty tick: %v", verdict.Refusal)
	}
	if expired, err := GkmHolderExpired(self.net.log.State(), self.repoId, fromTime, time.UnixMilli(self.net.timeMs)); err != nil || !expired {
		self.t.Fatalf("no holder expired: %v", err)
	}
}

// Time passes the expiring agent's not_after, and no entry lands.
func (self *evsDueClassWorld) lapse() {
	self.net.wait(2 * 60 * 60 * 1000)
}

// One reader of the world's log as it stands now, and what it is.
type evsDueClassReader struct {
	name  string
	state *ConfigState
}

// Every reader of the world's log: the network's own long-running reader and one walked from the genesis, as clients
// follow the log, and a new device and a rows-only gate restored at the newest base, the gate as evs holds it.
func (self *evsDueClassWorld) readers() []evsDueClassReader {
	self.t.Helper()
	readers := []evsDueClassReader{{name: "the long-running reader", state: self.net.log.State()}}
	names := []string{"a reader from the genesis", "a new device", "a rows-only gate"}
	for i, log := range self.net.everyReader() {
		readers = append(readers, evsDueClassReader{name: names[i], state: log.State()})
	}
	return readers
}

// Fails unless every reader classes the crossing from from to the tip as immediate says.
func (self *evsDueClassWorld) expectClass(label string, from *bridge.AuthPin, immediate bool) {
	self.t.Helper()
	to := self.net.log.Pin()
	for _, reader := range self.readers() {
		if got := EvsClassifyPathEpochDue(reader.state, self.repoId, from, to); got != immediate {
			self.t.Errorf("%s at %s: immediate %t", label, reader.name, got)
		}
	}
}

// Each span after the base, classed alike by every reader: an agent's ordinary removals and an expiry alone batched;
// a compromise of the same agent, a member device's removal and a member's removal immediate; one of each immediate;
// and, while a base's rows carry no t_s (QD-1015), an expiry and then an entry that touches the rows immediate.
func TestEvsDueClassFromTheLog(t *testing.T) {
	cases := []struct {
		name string
		span func(world *evsDueClassWorld)
		// whether some entry in the span shrank the repo's holders
		shrinks   bool
		immediate bool
	}{
		{name: "an agent's ordinary revocation", shrinks: true, span: func(world *evsDueClassWorld) {
			world.revoke(world.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
		}},
		{name: "two agents' revocations with an entry between", shrinks: true, span: func(world *evsDueClassWorld) {
			world.revoke(world.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
			world.net.admitMemberDevice("between")
			world.revoke(world.second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
		}},
		{name: "an agent's grant revoked", shrinks: true, span: func(world *evsDueClassWorld) {
			world.revokeGrant(world.agent)
		}},
		{name: "an agent suspended", shrinks: true, span: func(world *evsDueClassWorld) {
			world.net.mustPost(world.net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{
				Header: world.net.header(), Subject: world.agent.sidecarId.Bytes(), SuspendId: aclTestSuspendId("due class"),
			})
		}},
		{name: "an expiry alone", span: func(world *evsDueClassWorld) {
			world.expire()
		}},
		{name: "an expiry and then an entry that touches the rows", shrinks: true, immediate: true, span: func(world *evsDueClassWorld) {
			// the shrink row's interim closed reading (QD-883), the base having folded the repo's t_s: the first entry
			// after the lapse that touches the rows shrinks the repo, here a member's admission, which no statement the
			// class names explains, so every reader fails closed; QD-1015's exact comparison at t_s restores
			// shrinks: false here, and the batched class of an expiry alone
			world.expire()
			world.net.admitMemberDevice("bystander")
		}},
		{name: "an agent's revocation and an expiry", shrinks: true, span: func(world *evsDueClassWorld) {
			world.revoke(world.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
			world.expire()
		}},
		{name: "a lapsed agent's revocation after a shrink kept t_s", shrinks: true, span: func(world *evsDueClassWorld) {
			// QD-883's second comparison: dropped at t_s, the time of the second agent's revocation, not at its own
			world.revoke(world.second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
			world.lapse()
			world.revoke(world.expiring, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
		}},
		{name: "a lapsed agent's grant revoked where the base folded t_s", shrinks: true, immediate: true, span: func(world *evsDueClassWorld) {
			// the closed reading's shrink, which names no holder it dropped
			world.lapse()
			world.revokeGrant(world.expiring)
		}},
		{name: "an expiry and then a base", shrinks: true, immediate: true, span: func(world *evsDueClassWorld) {
			// the base's closed reading flags the lapsed holder (QD-883), and a base's shrink says no statement
			world.expire()
			if verdict := world.net.fold(world.net.owner, world.net.n, world.net.log.State().Base().GetConfigVersion()); !verdict.Accepted() {
				world.t.Fatalf("the later base: %v", verdict.Refusal)
			}
		}},
		{name: "the agent revoked for compromise", shrinks: true, immediate: true, span: func(world *evsDueClassWorld) {
			world.compromise(world.agent)
		}},
		{name: "a member device's removal", shrinks: true, immediate: true, span: func(world *evsDueClassWorld) {
			world.revoke(world.device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
		}},
		{name: "a member device's grant revoked", shrinks: true, immediate: true, span: func(world *evsDueClassWorld) {
			world.revokeGrant(world.device)
		}},
		{name: "a member's removal", shrinks: true, immediate: true, span: func(world *evsDueClassWorld) {
			world.net.mustPost(world.net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{
				Header: world.net.header(), MemberId: world.device.memberId.Bytes(),
			})
		}},
		{name: "one of each", shrinks: true, immediate: true, span: func(world *evsDueClassWorld) {
			world.revoke(world.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
			world.compromise(world.second)
			world.revoke(world.device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
			world.expire()
		}},
	}
	for _, c := range cases {
		world := newEvsDueClassWorld(t)
		c.span(world)
		if shrunk := world.net.log.State().ShrunkAt(world.repoId); (world.from.GetVersion() < shrunk) != c.shrinks {
			t.Fatalf("%s: holders_shrunk_at %d after the base at %d", c.name, shrunk, world.from.GetVersion())
		}
		world.expectClass(c.name, world.from, c.immediate)
	}
}

// A base's own change that drops a member device from a repo's readers shrinks it with no statement saying why: every
// reader classes the crossing immediate.
func TestEvsDueClassOfABasesOwnShrinkIsImmediate(t *testing.T) {
	net, repoA, repoB, a, b := testConfigTwoGroupNet(t)
	from := net.log.Pin()
	edited := net.withGroupReads(
		testConfigGroupRead{repoId: repoA, memberIds: []Id{a.memberId}},
		testConfigGroupRead{repoId: repoB, memberIds: []Id{b.memberId}},
	)
	if shrunk := net.log.State().ShrunkAt(repoA); shrunk != edited.Pin.GetVersion() {
		t.Fatalf("repo a's holders_shrunk_at %d, the base at %d", shrunk, edited.Pin.GetVersion())
	}
	world := &evsDueClassWorld{t: t, net: net, repoId: repoA}
	world.expectClass("a base's own shrink", from, true)
	// repo b lost no holder there: batched, as only expiries could have passed
	world.repoId = repoB
	world.expectClass("the base's other repo", from, false)
}

// A view that cannot reach the earlier pin reads immediate: after a later base, a new device and a rows-only gate
// start past it and read the agent's ordinary revocation immediate, where the long-running readers, which still reach
// it, read it batched; from that base on, every reader classes a later span alike. An earlier pin on another chain reads
// immediate at every reader.
func TestEvsDueClassOfAPinTheViewCannotReachIsImmediate(t *testing.T) {
	world := newEvsDueClassWorld(t)
	world.revoke(world.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
	if verdict := world.net.fold(world.net.owner, world.net.n, world.net.log.State().Base().GetConfigVersion()); !verdict.Accepted() {
		t.Fatalf("the later base: %v", verdict.Refusal)
	}
	later := world.net.log.Pin()
	to := later
	for _, reader := range world.readers() {
		reaches := reader.name == "the long-running reader" || reader.name == "a reader from the genesis"
		if _, err := reader.state.StateAt(world.from); (err == nil) != reaches || (!reaches && !errors.Is(err, ErrConfigPinNotRetained)) {
			t.Fatalf("%s reaches the earlier pin: %v", reader.name, err)
		}
		if immediate := EvsClassifyPathEpochDue(reader.state, world.repoId, world.from, to); immediate == reaches {
			t.Errorf("%s: immediate %t, reaching the earlier pin %t", reader.name, immediate, reaches)
		}
	}
	world.revoke(world.second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
	world.expectClass("a revocation after the later base", later, false)

	forked := &bridge.AuthPin{Version: later.GetVersion(), Chain: bytes.Repeat([]byte{0x5a}, sha256.Size)}
	world.expectClass("an earlier pin on another chain", forked, true)
}

// Two later bases move every reader's window past both pins of a crossing: with nothing shrunk since the earlier pin,
// every reader still classes it batched, by the pins' numbers as option 1 did; after an agent's ordinary revocation in
// between, every reader reads it immediate, reaching neither pin's state. (An expiry before those bases would read
// immediate too: each base's closed reading flags the lapsed holder, QD-883, which TestEvsDueClassFromTheLog shows.)
func TestEvsDueClassOfPinsBeforeTheWindow(t *testing.T) {
	cases := []struct {
		name      string
		span      func(world *evsDueClassWorld)
		immediate bool
	}{
		{name: "an entry that shrinks nothing", span: func(world *evsDueClassWorld) {
			world.net.admitMemberDevice("bystander")
		}},
		{name: "an agent's ordinary revocation", immediate: true, span: func(world *evsDueClassWorld) {
			world.revoke(world.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
		}},
	}
	for _, c := range cases {
		world := newEvsDueClassWorld(t)
		c.span(world)
		to := world.net.log.Pin()
		for range 2 {
			if verdict := world.net.fold(world.net.owner, world.net.n, world.net.log.State().Base().GetConfigVersion()); !verdict.Accepted() {
				t.Fatalf("%s: a later base: %v", c.name, verdict.Refusal)
			}
		}
		for _, reader := range world.readers() {
			if _, err := reader.state.StateAt(to); !errors.Is(err, ErrConfigPinNotRetained) {
				t.Fatalf("%s: %s still reaches the later pin: %v", c.name, reader.name, err)
			}
			if immediate := EvsClassifyPathEpochDue(reader.state, world.repoId, world.from, to); immediate != c.immediate {
				t.Errorf("%s at %s: immediate %t", c.name, reader.name, immediate)
			}
		}
	}
}

// Each fail-closed branch of a shrink's class: no entry, a refused one, a base, a statement or a tick with nothing
// kept, a type the class does not know, and an untagged sidecar's reap.
func TestEvsShrinkClassFailsClosed(t *testing.T) {
	world := newEvsDueClassWorld(t)
	world.revoke(world.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
	shrinks, err := world.net.log.State().shrinksBetween(world.repoId, world.from, world.net.log.Pin())
	if err != nil || len(shrinks) != 1 || evsShrinkImmediate(world.repoId, shrinks[0]) {
		t.Fatalf("the agent's revocation: %d shrinks, %v", len(shrinks), err)
	}
	shrink := shrinks[0]
	kept := *shrink.kept
	statement := *kept.statement
	cases := []struct {
		name string
		kept *configKeptEntry
	}{
		{name: "no entry", kept: nil},
		{name: "a refused entry", kept: &configKeptEntry{entry: kept.entry, statement: kept.statement, verdict: ConfigVerdict{Refusal: ErrConfigRule}}},
		{name: "a base", kept: &configKeptEntry{entry: &bridge.AuthEntry{Kind: bridge.AuthEntryKindBase}}},
		{name: "a statement not kept", kept: &configKeptEntry{entry: kept.entry}},
		{name: "a tick not kept", kept: &configKeptEntry{entry: &bridge.AuthEntry{Kind: bridge.AuthEntryKindTick}}},
		{name: "a type the class does not know", kept: &configKeptEntry{entry: kept.entry, statement: &configStatement{
			signedType: bridge.SignedType_SIGNED_ADMIN_SET, body: &protocol.AdminSet{},
		}}},
		{name: "a member device's reap", kept: &configKeptEntry{entry: &bridge.AuthEntry{Kind: bridge.AuthEntryKindTick},
			tick: &bridge.ApiTick{ReapedSidecarIds: [][]byte{world.device.sidecarId.Bytes()}}}},
		{name: "a compromise reason", kept: &configKeptEntry{entry: kept.entry, statement: func() *configStatement {
			compromised := statement
			compromised.body = &bridge.SidecarRevoke{SidecarId: world.agent.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE}
			return &compromised
		}()}},
	}
	for _, c := range cases {
		if !evsShrinkImmediate(world.repoId, &configShrink{n: shrink.n, kept: c.kept, before: shrink.before, after: shrink.after}) {
			t.Errorf("%s: batched", c.name)
		}
	}
	// a tagged sidecar's reap that drops it is an agent's ordinary removal
	reap := &configKeptEntry{entry: &bridge.AuthEntry{Kind: bridge.AuthEntryKindTick}, tick: &bridge.ApiTick{ReapedSidecarIds: [][]byte{world.agent.sidecarId.Bytes()}}}
	if evsShrinkImmediate(world.repoId, &configShrink{n: shrink.n, kept: reap, before: shrink.before, after: shrink.after}) {
		t.Error("an agent's reap: immediate")
	}
}

// A gkm client holding generations 1 and 2 of the world's repo, 2 a REMOVE, pinned where the test says.
type evsDueClassGkm struct {
	gkmRefusingClient
	pins map[uint64]*bridge.AuthPin
}

func (self *evsDueClassGkm) key(repoId Id, generation uint64) *EvsRepoKey {
	key := evsTestRepoKey(repoId, generation)
	key.auth = self.pins[generation]
	if generation == 2 {
		key.cause = GkmCauseRemove
	}
	return key
}

func (self *evsDueClassGkm) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return self.key(repoId, 2), nil
}

func (self *evsDueClassGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	return self.key(repoId, generation), nil
}

// A client of the world's network whose verified state is the world's long-running reader's, holding gen/1 pinned at
// the base and a REMOVE gen/2 pinned at the tip, sending nothing.
func (self *evsDueClassWorld) client() (*EvsClient, *evsTestClock) {
	self.t.Helper()
	clock := newEvsTestClock()
	identity := &SidecarIdentity{NetworkId: self.net.networkId, SidecarId: self.net.owner.sidecarId, ClientId: testConfigId("due class client")}
	refuse := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
	})
	client, err := NewEvsClient(&EvsClientArgs{
		NetworkId:    self.net.networkId,
		EvsUrl:       "https://evs.example",
		Transport:    &evsTestTransport{handler: refuse},
		ServiceToken: (&evsTestTokens{}).token,
		Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
			return nil, errors.New("no signer in this test")
		},
		Identity: func() *SidecarIdentity { return identity },
		Config:   func() GkmAuthView { return self.net.log.State() },
		Gkm:      &evsDueClassGkm{pins: map[uint64]*bridge.AuthPin{1: self.from, 2: self.net.log.Pin()}},
		Store:    newEvsTestStore(self.t),
		Clock:    clock,
		Log:      NewNoopLogger(),
		Settings: DefaultEvsSettings(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client, clock
}

// A client classes the crossing it would make on its verified state as evs does: an agent's ordinary revocation is
// batched pressure, which holds no new name, and ur status shows it batched, due 24 h after the device first held the
// REMOVE generation; the same agent revoked for compromise, and a member device's removal, are immediate, holding new
// names and due at once.
func TestEvsPressureClassesTheCrossingFromTheLog(t *testing.T) {
	cases := []struct {
		name      string
		span      func(world *evsDueClassWorld)
		immediate bool
	}{
		{name: "an agent's ordinary revocation", span: func(world *evsDueClassWorld) {
			world.revoke(world.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
		}},
		{name: "the agent revoked for compromise", immediate: true, span: func(world *evsDueClassWorld) {
			world.compromise(world.agent)
		}},
		{name: "a member device's removal", immediate: true, span: func(world *evsDueClassWorld) {
			world.revoke(world.device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
		}},
	}
	ctx := context.Background()
	for _, c := range cases {
		world := newEvsDueClassWorld(t)
		c.span(world)
		client, clock := world.client()
		repo := client.Repo(world.repoId)
		refId := testConfigId("due class ref")
		client.noteVerifiedHead(world.repoId, refId, &protocol.EvsHeadSummary{
			Version: 4, Generation: 1, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, PathEpoch: &protocol.EvsPathEpoch{Current: 1},
		})
		state := client.refEpochState(world.repoId, refId)
		heldAt := clock.Now()
		pressure, generation, err := repo.pressure(ctx, state)
		want := evsPressureBatched
		if c.immediate {
			want = evsPressureImmediate
		}
		if err != nil || pressure != want || generation != 2 {
			t.Errorf("%s: pressure %d at %d: %v", c.name, pressure, generation, err)
		}
		if quiet, err := repo.quiet(ctx, state); err != nil || quiet == c.immediate {
			t.Errorf("%s: quiet %t: %v", c.name, quiet, err)
		}
		status, err := repo.pathEpochStatusOf(ctx, refId)
		wantClass, wantDueBy := "batched", heldAt.Add(24*time.Hour)
		if c.immediate {
			wantClass, wantDueBy = "immediate", heldAt
		}
		if err != nil || status.Class != wantClass || !status.DueBy.Equal(wantDueBy) || status.DueGeneration != 2 {
			t.Errorf("%s: status %+v: %v", c.name, status, err)
		}
		// evs, on a rows-only gate of the same log, classes the same crossing alike
		gate := world.net.everyReader()[2].State()
		if immediate := EvsClassifyPathEpochDue(gate, world.repoId, world.from, world.net.log.Pin()); immediate != c.immediate {
			t.Errorf("%s: the gate classes it immediate %t", c.name, immediate)
		}
	}
}
