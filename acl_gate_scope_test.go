//go:build !sidecar_http && !ios_extension

// §7.9's tokens row at the gate, on T2's shape: the rights a state gives decide each scope, a group edit and a Suspend
// close a live token's scope at the next state, deposit is no read, the config splits by audience (FS-19), cold state
// is never a pass, and FS-14's closing case through the real cache over TEAM's log: a subject a group edit drops loses
// its scope at the gate the moment the edit's {acl_}v event loads, and with the event lost, at the poll. No sleeps: the
// fake clock fires the poll and loads report as they finish.

package sidecar

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network for scope checks: an Owner with a laptop, a member in group:eng with a phone, a read_only and an ephemeral
// device of the member, an agent the Owner sponsors, a general repo the group reads, and the config.
type aclScopeWorld struct {
	world     *aclCompileWorld
	owner     Id
	laptop    Id
	member    Id
	phone     Id
	readOnly  Id
	ephemeral Id
	agent     Id
	notes     Id
	config    Id
}

func newAclScopeWorld(t testing.TB, policy string) *aclScopeWorld {
	world := newAclCompileWorld("scope")
	self := &aclScopeWorld{world: world}
	self.owner = world.member("owner@scope.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.member = world.member("dana@scope.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.laptop = world.device("laptop", self.owner)
	self.phone = world.device("phone", self.member)
	self.readOnly = world.device("read only", self.member)
	self.ephemeral = world.device("ephemeral", self.member)
	world.ephemeral[self.ephemeral] = true
	for _, row := range world.sidecars {
		if Id(row.SidecarId) == self.readOnly {
			row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
		}
	}
	self.agent = world.agent("agent", self.owner, "ci")
	world.group("eng")
	self.notes = world.repo("notes", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	// the config's row is the state's own, from the Genesis (QD-719)
	self.config = world.configRepo()
	world.setPolicy(t, policy)
	return self
}

// The policy the scope tests run: the group reads notes, the agent deposits there, and the member device writes it.
const aclScopePolicy = `{
  "groups": { "group:eng": ["dana@scope.example"] },
  "tagOwners": { "tag:ci": ["autogroup:admin"] },
  "grants": [
    { "src": ["group:eng"], "dst": ["evs:notes"], "allow": ["read"] },
    { "src": ["tag:ci"], "dst": ["evs:notes"], "allow": ["deposit"] },
  ],
}`

// The same policy with the member out of the group: a group edit.
const aclScopePolicyAfterEdit = `{
  "groups": { "group:eng": [] },
  "tagOwners": { "tag:ci": ["autogroup:admin"] },
  "grants": [
    { "src": ["group:eng"], "dst": ["evs:notes"], "allow": ["read"] },
    { "src": ["tag:ci"], "dst": ["evs:notes"], "allow": ["deposit"] },
  ],
}`

// Each scope answers as the state's rights say, and a scope naming no right is refused.
func TestAclHonorScopeHoldsTheRightsTheStateGives(t *testing.T) {
	scope := newAclScopeWorld(t, aclScopePolicy)
	state := scope.world.state(t)
	cases := []struct {
		name     string
		subject  Id
		repoId   Id
		scope    AclEvsRights
		audience AclTokenAudience
		want     AclScopeAnswer
	}{
		{name: "a group member reads", subject: scope.phone, repoId: scope.notes, scope: AclEvsRead, audience: AclTokenAudienceEvs, want: AclScopeHonored},
		{name: "and does not write", subject: scope.phone, repoId: scope.notes, scope: AclEvsWrite, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "or administer", subject: scope.phone, repoId: scope.notes, scope: AclEvsAdmin, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "the Owner's laptop is in no group", subject: scope.laptop, repoId: scope.notes, scope: AclEvsRead, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "a read_only device reads", subject: scope.readOnly, repoId: scope.notes, scope: AclEvsRead, audience: AclTokenAudienceEvs, want: AclScopeHonored},
		{name: "an ephemeral device is held to its ceiling", subject: scope.ephemeral, repoId: scope.notes, scope: AclEvsRead, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "an unknown repo", subject: scope.phone, repoId: scope.world.id("no such repo"), scope: AclEvsRead, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "an unadmitted sidecar", subject: scope.world.id("stranger"), repoId: scope.notes, scope: AclEvsRead, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "no right", subject: scope.phone, repoId: scope.notes, scope: 0, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "a right no role carries", subject: scope.phone, repoId: scope.notes, scope: AclEvsRead | 64, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "an audience that takes no repo scope", subject: scope.phone, repoId: scope.notes, scope: AclEvsRead, audience: 0, want: AclScopeRefused},
	}
	for _, c := range cases {
		if answer := AclHonorScope(state, c.subject, c.repoId, c.scope, c.audience, aclTestNow); answer != c.want {
			t.Errorf("%s: %d, want %d", c.name, answer, c.want)
		}
	}
	if answer := AclHonorScope(nil, scope.phone, scope.notes, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeUnknown {
		t.Errorf("no state: %d", answer)
	}
}

// Deposit implies no read: a depositor's deposit is honored and its read refused, so it is never counted a reader.
func TestAclHonorScopeDepositIsNoRead(t *testing.T) {
	scope := newAclScopeWorld(t, aclScopePolicy)
	state := scope.world.state(t)
	if answer := AclHonorScope(state, scope.agent, scope.notes, AclEvsDeposit, AclTokenAudienceEvs, aclTestNow); answer != AclScopeHonored {
		t.Errorf("the agent's deposit: %d", answer)
	}
	if answer := AclHonorScope(state, scope.agent, scope.notes, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeRefused {
		t.Errorf("the depositor's read: %d", answer)
	}
	if answer := AclHonorScope(state, scope.agent, scope.notes, AclEvsDeposit|AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeRefused {
		t.Errorf("deposit and read together: %d", answer)
	}
}

// The config splits by audience (§10.6, FS-19): config writers write its heads at evs, member devices but read_only ones
// commit its group at gkm, and an ephemeral sidecar reads it and writes it at neither.
func TestAclHonorScopeSplitsTheConfigByAudience(t *testing.T) {
	scope := newAclScopeWorld(t, aclScopePolicy)
	view := scope.world.view()
	view.configWriters[scope.laptop] = true
	state, err := NewAclState(scope.world.compile(t), view)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		subject  Id
		scope    AclEvsRights
		audience AclTokenAudience
		want     AclScopeAnswer
	}{
		{name: "a config writer writes heads at evs", subject: scope.laptop, scope: AclEvsWrite, audience: AclTokenAudienceEvs, want: AclScopeHonored},
		{name: "a member device writes no head at evs", subject: scope.phone, scope: AclEvsWrite, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "and commits the group at gkm", subject: scope.phone, scope: AclEvsWrite, audience: AclTokenAudienceGkm, want: AclScopeHonored},
		{name: "a read_only device commits nothing", subject: scope.readOnly, scope: AclEvsWrite, audience: AclTokenAudienceGkm, want: AclScopeRefused},
		{name: "and reads", subject: scope.readOnly, scope: AclEvsRead, audience: AclTokenAudienceEvs, want: AclScopeHonored},
		{name: "an ephemeral device reads the config", subject: scope.ephemeral, scope: AclEvsRead, audience: AclTokenAudienceEvs, want: AclScopeHonored},
		{name: "and writes it at no evs", subject: scope.ephemeral, scope: AclEvsWrite, audience: AclTokenAudienceEvs, want: AclScopeRefused},
		{name: "and at no gkm", subject: scope.ephemeral, scope: AclEvsWrite, audience: AclTokenAudienceGkm, want: AclScopeRefused},
		{name: "a tagged agent reads it", subject: scope.agent, scope: AclEvsRead, audience: AclTokenAudienceGkm, want: AclScopeHonored},
		{name: "and commits nothing", subject: scope.agent, scope: AclEvsWrite, audience: AclTokenAudienceGkm, want: AclScopeRefused},
	}
	for _, c := range cases {
		if answer := AclHonorScope(state, c.subject, scope.config, c.scope, c.audience, aclTestNow); answer != c.want {
			t.Errorf("%s: %d, want %d", c.name, answer, c.want)
		}
	}
}

// A group edit and a Suspend each close a live token's scope at the next state, whatever the token says (D-ACL-21).
func TestAclHonorScopeClosesAtTheNextState(t *testing.T) {
	scope := newAclScopeWorld(t, aclScopePolicy)
	before := scope.world.state(t)
	if answer := AclHonorScope(before, scope.phone, scope.notes, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeHonored {
		t.Fatalf("before: %d", answer)
	}

	edited := newAclScopeWorld(t, aclScopePolicyAfterEdit)
	if answer := AclHonorScope(edited.world.state(t), scope.phone, scope.notes, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeRefused {
		t.Errorf("after the group edit: %d", answer)
	}

	scope.world.statements.Suspensions = []*protocol.AclSuspension{{
		Subject: scope.phone.Bytes(), SuspendId: scope.world.id("suspend phone").Bytes(), SignerClass: AclSuspendClassAdmin,
		Signer: scope.laptop.Bytes(), At: 2,
	}}
	suspended := scope.world.state(t)
	if answer := AclHonorScope(suspended, scope.phone, scope.notes, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeRefused {
		t.Errorf("after the Suspend: %d", answer)
	}
	if answer := AclHonorScope(suspended, scope.readOnly, scope.notes, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeHonored {
		t.Errorf("another device of the member after the Suspend: %d", answer)
	}
}

// A check on a loaded state allocates nothing (§22.5's 0 allocs).
func TestAclHonorScopeDoesNotAllocate(t *testing.T) {
	scope := newAclScopeWorld(t, aclScopePolicy)
	state := scope.world.state(t)
	allocations := testing.AllocsPerRun(100, func() {
		AclHonorScope(state, scope.phone, scope.notes, AclEvsRead, AclTokenAudienceEvs, aclTestNow)
	})
	if 0 < allocations {
		t.Errorf("a check allocates %v", allocations)
	}
}

func BenchmarkAclHonorScope(b *testing.B) {
	scope := newAclScopeWorld(b, aclScopePolicy)
	state := scope.world.state(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		AclHonorScope(state, scope.phone, scope.notes, AclEvsRead, AclTokenAudienceEvs, aclTestNow)
	}
}

// The acl rows a test network's base carries for FS-14's closing case: group:eng, holding members, reads one repo.
func aclScopeGroupRows(groupAtom Id, repoId Id, members ...Id) *protocol.AclRows {
	atom := &protocol.AclAtom{Atom: groupAtom.Bytes()}
	for _, member := range members {
		atom.MemberIds = append(atom.MemberIds, member.Bytes())
	}
	return &protocol.AclRows{
		HasDocument: true,
		Atoms:       []*protocol.AclAtom{atom},
		Rules: []*protocol.AclRule{{
			RuleId:   testConfigId("scope group rule").Bytes(),
			SrcAtoms: [][]byte{groupAtom.Bytes()},
			Targets:  []*protocol.AclTarget{{RepoId: repoId.Bytes()}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_READ)},
		}},
		Repos: []*protocol.AclRepo{{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}},
	}
}

// A cold gate is no pass: a network the cache has not heard of is unknown and starts its load, and one loading is
// unknown until its state installs.
func TestAclGateHonorScopeIsUnknownUntilLoaded(t *testing.T) {
	net := newTestConfigNet(t)
	device := net.admitMemberDevice("cold")
	repoId := testConfigId("cold repo")
	groupAtom := testConfigId("cold group")
	net.withAclRows(func(rows *protocol.AclRows) {
		proto.Merge(rows, aclScopeGroupRows(groupAtom, repoId, device.memberId))
	})
	source := newAclGateTestSource()
	source.publish(net)
	source.hold = make(chan struct{})
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	if answer := cache.HonorScope(net.networkId, device.sidecarId, repoId, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeUnknown {
		t.Fatalf("an unheard-of network: %d", answer)
	}
	<-source.started
	if answer := cache.HonorScope(net.networkId, device.sidecarId, repoId, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeUnknown {
		t.Fatalf("while loading: %d", answer)
	}
	close(source.hold)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	if answer := cache.HonorScope(net.networkId, device.sidecarId, repoId, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeHonored {
		t.Fatalf("loaded: %d", answer)
	}
}

// FS-14's closing case on the real cache over TEAM's log: a group edit's base drops the member, and its scope closes at
// the gate when the edit's event loads, with no clock moving; a second edit whose event is lost closes at the poll.
func TestAclGateHonorScopeClosesByEventAndByPoll(t *testing.T) {
	net := newTestConfigNet(t)
	first := net.admitMemberDevice("event")
	second := net.admitMemberDevice("poll")
	repoId := testConfigId("scope repo")
	groupAtom := testConfigId("scope group")
	setGroup := func(members ...Id) {
		net.withAclRows(func(rows *protocol.AclRows) {
			edited := aclScopeGroupRows(groupAtom, repoId, members...)
			rows.HasDocument, rows.Atoms, rows.Rules, rows.Repos = edited.HasDocument, edited.Atoms, edited.Rules, edited.Repos
		})
	}
	setGroup(first.memberId, second.memberId)
	source := newAclGateTestSource()
	source.publish(net)
	clock := newAclGateTestClock()
	cache, loads := newAclGateTestCache(t, source, clock, nil)
	armed := <-clock.armed
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	honored := func(device testConfigDevice) AclScopeAnswer {
		return cache.HonorScope(net.networkId, device.sidecarId, repoId, AclEvsRead, AclTokenAudienceEvs, aclTestNow)
	}
	if honored(first) != AclScopeHonored || honored(second) != AclScopeHonored {
		t.Fatalf("before any edit: %d, %d", honored(first), honored(second))
	}

	// by event: the edit's INCR reaches Changed, and the load is the only step
	setGroup(second.memberId)
	source.publish(net)
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !proto.Equal(load.pin, net.log.Pin()) {
		t.Fatalf("the event's load: %v", load.err)
	}
	if honored(first) != AclScopeRefused || honored(second) != AclScopeHonored {
		t.Fatalf("after the first edit: %d, %d", honored(first), honored(second))
	}

	// by poll: the second edit's event is lost, and the next poll closes it
	setGroup()
	source.publish(net)
	if honored(second) != AclScopeHonored {
		t.Fatal("closed before any trigger")
	}
	clock.fire <- clock.Now().Add(armed)
	if load := aclGateTestNextLoad(t, loads); load.err != nil || !proto.Equal(load.pin, net.log.Pin()) {
		t.Fatalf("the poll's load: %v", load.err)
	}
	if honored(second) != AclScopeRefused {
		t.Fatalf("after the poll: %d", honored(second))
	}
	<-clock.armed
}

// QD-719 at the real gate, over TEAM's log: no rows hold the config repo's AclRepo, and the cache's state, built from
// those rows and the Genesis, honors the config's scopes for evs and for gkm as §8.5's kind default gives them: every
// admitted sidecar's r, a config writer's rw at evs, a member device's rw at gkm, §7.9's bootstrap admin for the
// Genesis's owner sidecar alone; and a revocation closes a live config scope at the next load.
func TestAclGateHonorScopeHonorsTheConfigRepo(t *testing.T) {
	net := newTestConfigNet(t)
	phone := net.admitMemberDevice("config scope")
	readOnly := net.device("config scope read only", phone.memberId)
	net.admitDevice(net.owner, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	ephemeral := net.device("config scope ephemeral", phone.memberId)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(ephemeral, nil, true, net.timeMs+24*60*60*1000, 0))
	ownerPhone := net.device("config scope owner phone", net.ownerMemberId)
	net.admitDevice(net.owner, ownerPhone, 0)
	configId := Id(net.log.State().Genesis().GetConfigRepoId())
	if acl, err := net.log.State().Acl(); err != nil || len(acl.Rows().GetRepos()) != 0 {
		t.Fatalf("the rows hold repos: %v", err)
	}

	source := newAclGateTestSource()
	source.publish(net)
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	now := time.UnixMilli(net.timeMs)
	if answer := cache.HonorScope(net.networkId, phone.sidecarId, configId, AclEvsRead, AclTokenAudienceEvs, now); answer != AclScopeUnknown {
		t.Fatalf("before the load: %d", answer)
	}
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	evs, gkm := AclTokenAudienceEvs, AclTokenAudienceGkm
	cases := []struct {
		name     string
		device   testConfigDevice
		scope    AclEvsRights
		audience AclTokenAudience
		want     AclScopeAnswer
	}{
		{name: "the bootstrap sidecar reads at evs", device: net.owner, scope: AclEvsRead, audience: evs, want: AclScopeHonored},
		{name: "writes heads at evs", device: net.owner, scope: AclEvsWrite, audience: evs, want: AclScopeHonored},
		{name: "places the repo at evs", device: net.owner, scope: AclEvsAdmin, audience: evs, want: AclScopeHonored},
		{name: "and forms its group at gkm", device: net.owner, scope: AclEvsAdmin, audience: gkm, want: AclScopeHonored},
		{name: "another config writer writes heads at evs", device: ownerPhone, scope: AclEvsWrite, audience: evs, want: AclScopeHonored},
		{name: "and administers nothing at evs", device: ownerPhone, scope: AclEvsAdmin, audience: evs, want: AclScopeRefused},
		{name: "or at gkm", device: ownerPhone, scope: AclEvsAdmin, audience: gkm, want: AclScopeRefused},
		{name: "a member device reads at evs", device: phone, scope: AclEvsRead, audience: evs, want: AclScopeHonored},
		{name: "reads at gkm", device: phone, scope: AclEvsRead, audience: gkm, want: AclScopeHonored},
		{name: "writes no head at evs", device: phone, scope: AclEvsWrite, audience: evs, want: AclScopeRefused},
		{name: "commits the group at gkm", device: phone, scope: AclEvsWrite, audience: gkm, want: AclScopeHonored},
		{name: "and administers nothing", device: phone, scope: AclEvsAdmin, audience: gkm, want: AclScopeRefused},
		{name: "a read_only device reads at evs", device: readOnly, scope: AclEvsRead, audience: evs, want: AclScopeHonored},
		{name: "and commits nothing at gkm", device: readOnly, scope: AclEvsWrite, audience: gkm, want: AclScopeRefused},
		{name: "an ephemeral device reads at evs", device: ephemeral, scope: AclEvsRead, audience: evs, want: AclScopeHonored},
		{name: "reads at gkm", device: ephemeral, scope: AclEvsRead, audience: gkm, want: AclScopeHonored},
		{name: "and writes at neither", device: ephemeral, scope: AclEvsWrite, audience: gkm, want: AclScopeRefused},
	}
	for _, c := range cases {
		if answer := cache.HonorScope(net.networkId, c.device.sidecarId, configId, c.scope, c.audience, now); answer != c.want {
			t.Errorf("%s: %d, want %d", c.name, answer, c.want)
		}
	}
	if answer := cache.HonorScope(net.networkId, testConfigId("config scope stranger"), configId, AclEvsRead, evs, now); answer != AclScopeRefused {
		t.Errorf("an unadmitted sidecar: %d", answer)
	}

	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	source.publish(net)
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	for _, audience := range []AclTokenAudience{evs, gkm} {
		if answer := cache.HonorScope(net.networkId, phone.sidecarId, configId, AclEvsRead, audience, now); answer != AclScopeRefused {
			t.Errorf("a revoked device's config r at %d: %d", audience, answer)
		}
		if answer := cache.HonorScope(net.networkId, readOnly.sidecarId, configId, AclEvsRead, audience, now); answer != AclScopeHonored {
			t.Errorf("another device's config r at %d after the revocation: %d", audience, answer)
		}
	}
}

// A Suspend in the log's tail closes the subject's live scope at the gate's next load, before any base folds it.
func TestAclGateHonorScopeClosesAtASuspend(t *testing.T) {
	net := newTestConfigNet(t)
	device := net.admitMemberDevice("suspended")
	repoId := testConfigId("suspend repo")
	groupAtom := testConfigId("suspend group")
	net.withAclRows(func(rows *protocol.AclRows) {
		proto.Merge(rows, aclScopeGroupRows(groupAtom, repoId, device.memberId))
	})
	source := newAclGateTestSource()
	source.publish(net)
	cache, loads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	cache.Changed(net.networkId)
	aclGateTestNextLoad(t, loads)
	if answer := cache.HonorScope(net.networkId, device.sidecarId, repoId, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeHonored {
		t.Fatalf("before the Suspend: %d", answer)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: device.sidecarId.Bytes(), SuspendId: aclTestSuspendId("scope")})
	source.publish(net)
	cache.Changed(net.networkId)
	if load := aclGateTestNextLoad(t, loads); load.err != nil {
		t.Fatal(load.err)
	}
	if answer := cache.HonorScope(net.networkId, device.sidecarId, repoId, AclEvsRead, AclTokenAudienceEvs, aclTestNow); answer != AclScopeRefused {
		t.Errorf("after the Suspend: %d", answer)
	}
}

// A RepoDelete is dated by its row's time, the entry's (QD-743), and while the gate's log keeps its entry the gate also
// knows its signer; with no log it is dated all the same and unsigned.
func TestAclGateSnapshotDatesARepoDeleteItKeeps(t *testing.T) {
	net := newTestConfigNet(t)
	repoId := testConfigId("deleted repo")
	deletionId := testConfigId("deletion")
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Repos = append(rows.Repos, &protocol.AclRepo{
			RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Admins: []*protocol.AclRepoAdminRow{{SidecarId: net.owner.sidecarId.Bytes(), Signer: net.owner.sidecarId.Bytes(), At: 1}},
		})
	})
	verdict := net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{Header: net.header(), RepoId: repoId.Bytes(), DeletionId: deletionId.Bytes()})
	state := net.log.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &AclGateSnapshot{Pin: state.Pin(), Config: state, Acl: acl}
	deletion := snapshot.RepoDeletion(repoId)
	if deletion == nil || deletion.DeletionId != deletionId || deletion.DeletedAt != verdict.Pin.GetVersion() || !deletion.Dated ||
		!deletion.Signed || deletion.SignerSidecarId != net.owner.sidecarId || deletion.TimeMs != state.TimeMs() || deletion.Now || deletion.Restored {
		t.Fatalf("the kept deletion: %+v", deletion)
	}
	rowsOnly := &AclGateSnapshot{Pin: state.Pin(), Acl: acl}
	if deletion := rowsOnly.RepoDeletion(repoId); deletion == nil || !deletion.Dated || deletion.TimeMs != state.TimeMs() || deletion.Signed ||
		deletion.SignerSidecarId != (Id{}) {
		t.Errorf("with no log: %+v", deletion)
	}
	if deletion := snapshot.RepoDeletion(testConfigId("no such repo")); deletion != nil {
		t.Errorf("an unknown repo: %+v", deletion)
	}
}
