//go:build !sidecar_http && !ios_extension

// §7.9's tokens row at the gate, on T2's shape: the rights a state gives decide each scope, a group edit and a Suspend
// close a live token's scope at the next state, deposit is no read, the config splits by audience (FS-19), cold state
// is never a pass, and FS-14's closing case through the real cache over TEAM's log: a subject a group edit drops loses
// its scope at the gate the moment the edit's {acl_}v event loads, and with the event lost, at the poll. No sleeps: the
// fake clock fires the poll and loads report as they finish.

package sidecar

import (
	"testing"

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
	self.config = world.repo("config", protocol.RepoKind_REPO_KIND_CONFIG, Id{})
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

// A RepoDelete the gate's log keeps is dated by its entry's time and signer; one past the log's window is undated.
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
		deletion.SignerSidecarId != net.owner.sidecarId || deletion.TimeMs != state.TimeMs() || deletion.Now || deletion.Restored {
		t.Fatalf("the kept deletion: %+v", deletion)
	}
	undated := &AclGateSnapshot{Pin: state.Pin(), Acl: acl}
	if deletion := undated.RepoDeletion(repoId); deletion == nil || deletion.Dated {
		t.Errorf("with no log: %+v", deletion)
	}
	if deletion := snapshot.RepoDeletion(testConfigId("no such repo")); deletion != nil {
		t.Errorf("an unknown repo: %+v", deletion)
	}
}
