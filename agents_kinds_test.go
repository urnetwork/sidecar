// SKILL-M11-01: the agent_repos feature's kinds agents and agent and the inbox marker team (DESIGN-COMPUTE §20.4,
// §16.5, §16.6; D-SKILL-1, D-SKILL-5): what EvsAccess gives each subject on them, deposits included, with a document
// and without; their RepoCreates refused before the feature's base alike by a reader that implements it and one that
// predates it, and taken after; a reader of a release without the feature holding at the base and, updated, agreeing on
// the repos' kinds and readers; a member's first agents repo in log order; the Team inbox a config writer's, once; and
// the implicit document's rows unchanged by the feature. Pure, on every leg.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A member's agents and agent repos and every kind of subject around them: the member's devices, a read_only one, a
// cloud agent the member sponsors with an EvsShare of both repos, another member's device and tagged sidecar, an
// admin's device, and an ephemeral sidecar of another member.
type testAgentsKindsCast struct {
	fixture *aclTestFixture
	owner   Id
	other   Id
	admin   Id

	laptop      Id
	phone       Id
	readOnly    Id
	cloud       Id
	otherDevice Id
	otherAgent  Id
	otherTag    Id
	adminDevice Id
	burner      Id

	agentsId Id
	agentId  Id
}

func newTestAgentsKindsCast(hasDocument bool) *testAgentsKindsCast {
	fixture := newAclTestFixture()
	fixture.rows.HasDocument = hasDocument
	cast := &testAgentsKindsCast{fixture: fixture}
	cast.owner = fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	cast.other = fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	cast.admin = fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	ownerTag := fixture.tag(cast.owner)
	cast.otherTag = fixture.tag(cast.other)
	cast.laptop = fixture.invitedDevice(cast.owner)
	cast.phone = fixture.device(cast.owner, cast.laptop.Bytes())
	cast.readOnly = fixture.device(cast.owner, cast.laptop.Bytes())
	fixture.admission(cast.readOnly).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	cast.cloud = fixture.agent(cast.owner, ownerTag)
	cast.otherDevice = fixture.invitedDevice(cast.other)
	cast.otherAgent = fixture.agent(cast.other, cast.otherTag)
	cast.adminDevice = fixture.invitedDevice(cast.admin)
	fixture.view.configWriters[cast.adminDevice] = true
	cast.burner = fixture.device(cast.other, cast.otherDevice.Bytes())
	fixture.admission(cast.burner).Ephemeral = true
	consented := [][]byte{cast.laptop.Bytes(), cast.phone.Bytes(), cast.readOnly.Bytes()}
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_AGENTS, protocol.RepoKind_REPO_KIND_AGENT} {
		repoId, row := fixture.repo(kind, cast.owner)
		row.ConsentedSidecarIds = consented
		row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: cast.laptop.Bytes(), Signer: cast.laptop.Bytes(), At: fixture.next()}}
		row.Shares = []*protocol.AclRepoShareRow{{Subject: cast.cloud.Bytes(), Signer: cast.laptop.Bytes(), At: fixture.next()}}
		if kind == protocol.RepoKind_REPO_KIND_AGENTS {
			cast.agentsId = repoId
		} else {
			cast.agentId = repoId
		}
	}
	return cast
}

// §20.4's table as EvsAccess gives it: the member's consented devices read and write both kinds, the admin among them
// administers, a read_only one reads with the receipt deposit, the cloud agent the member shares them with reads and
// writes; nobody outside the member reaches the agents repo, an admin included; every member device deposits into the
// agent repo, and with a document no tagged or ephemeral sidecar of another member does, without one every admitted
// sidecar does (§16.5's deposit row); a rule naming the agent repo adds a deposit alone, and one naming the agents repo
// nothing.
func TestAgentsKindDefaultsTable(t *testing.T) {
	owned := AclEvsRead | AclEvsWrite | AclEvsDeposit
	for _, hasDocument := range []bool{true, false} {
		cast := newTestAgentsKindsCast(hasDocument)
		state := cast.fixture.state(t)
		// with no document every admitted sidecar deposits into an agent repo; with one only member devices do
		openDeposit := AclEvsRights(0)
		if !hasDocument {
			openDeposit = AclEvsDeposit
		}
		cases := []struct {
			name      string
			sidecarId Id
			agents    AclEvsRights
			agent     AclEvsRights
		}{
			{name: "the member's admin device", sidecarId: cast.laptop, agents: owned | AclEvsAdmin, agent: owned | AclEvsAdmin},
			{name: "the member's other device", sidecarId: cast.phone, agents: owned, agent: owned},
			{name: "the member's read_only device", sidecarId: cast.readOnly, agents: AclEvsRead | AclEvsDeposit, agent: AclEvsRead | AclEvsDeposit},
			{name: "the member's cloud agent by EvsShare", sidecarId: cast.cloud, agents: owned, agent: owned},
			{name: "another member's device", sidecarId: cast.otherDevice, agents: 0, agent: AclEvsDeposit},
			{name: "an admin's device", sidecarId: cast.adminDevice, agents: 0, agent: AclEvsDeposit},
			{name: "another member's tagged sidecar", sidecarId: cast.otherAgent, agents: 0, agent: openDeposit},
			{name: "another member's ephemeral sidecar", sidecarId: cast.burner, agents: 0, agent: openDeposit},
		}
		for _, c := range cases {
			if rights := aclTestRights(state, c.sidecarId, cast.agentsId, AclTokenAudienceEvs); rights != c.agents {
				t.Errorf("document %t, %s, agents repo: %b, want %b", hasDocument, c.name, rights, c.agents)
			}
			if rights := aclTestRights(state, c.sidecarId, cast.agentId, AclTokenAudienceEvs); rights != c.agent {
				t.Errorf("document %t, %s, agent repo: %b, want %b", hasDocument, c.name, rights, c.agent)
			}
		}
		// the member's devices and the agent it shares with are the readers, so only they hold the groups' keys
		wantReaders := []Id{cast.laptop, cast.phone, cast.readOnly, cast.cloud}
		slices.SortFunc(wantReaders, Id.Cmp)
		for _, repoId := range []Id{cast.agentsId, cast.agentId} {
			if readers := state.RepoReaders(repoId, aclTestNow); !slices.Equal(readers, wantReaders) {
				t.Errorf("document %t: readers %v, want %v", hasDocument, readers, wantReaders)
			}
		}
	}

	// another tagged subject deposits into an agent repo only by a rule naming it, which adds no read; a rule naming the
	// agents repo adds nothing
	cast := newTestAgentsKindsCast(true)
	everything := []protocol.AclAction{protocol.AclAction_ACL_ACTION_DEPOSIT, protocol.AclAction_ACL_ACTION_READ,
		protocol.AclAction_ACL_ACTION_WRITE, protocol.AclAction_ACL_ACTION_ADMIN}
	cast.fixture.rule([]Id{cast.otherTag}, []*protocol.AclTarget{aclRepoTarget(cast.agentId), aclRepoTarget(cast.agentsId)}, everything...)
	cast.fixture.rule([]Id{cast.otherTag}, []*protocol.AclTarget{aclWildcardRepoTarget()}, everything...)
	state := cast.fixture.state(t)
	if rights := aclTestRights(state, cast.otherAgent, cast.agentId, AclTokenAudienceEvs); rights != AclEvsDeposit {
		t.Errorf("a rule naming the agent repo: %b", rights)
	}
	if rights := aclTestRights(state, cast.otherAgent, cast.agentsId, AclTokenAudienceEvs); rights != 0 {
		t.Errorf("a rule naming the agents repo: %b", rights)
	}
	// the kinds take a drop key, an agent repo for its inbox's deposits and an agents repo for its readers' receipts
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_AGENTS, protocol.RepoKind_REPO_KIND_AGENT} {
		if !GkmRepoKindTakesDeposits(kind) || !aclRepoKindOwnerBound(kind) || !EvsRepoKindOwnerBound(kind) || !aclRepoKindKnown(kind) {
			t.Errorf("%s: deposits %t, owner-bound %t, known %t", kind, GkmRepoKindTakesDeposits(kind), aclRepoKindOwnerBound(kind), aclRepoKindKnown(kind))
		}
		if !AclRepoKindOwnerFits(kind, true) || AclRepoKindOwnerFits(kind, false) {
			t.Errorf("%s stands without an owner", kind)
		}
	}
}

// No admin reaches a member's agents by its own act (owner decision 126): a RepoGrant on either kind, by a config
// writer or anyone, is refused, a RepoAdmin add by an admin's device is refused, and so is an EvsShare an admin signs.
func TestAgentsKindsNoAdminGrantsItselfIn(t *testing.T) {
	cast := newTestAgentsKindsCast(true)
	state := cast.fixture.state(t)
	for _, repoId := range []Id{cast.agentsId, cast.agentId} {
		grant := &protocol.RepoGrant{RepoId: repoId.Bytes(), Subject: cast.adminDevice.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}
		if _, err := state.CheckStatement(cast.fixture.statement(bridge.SignedType_SIGNED_REPO_GRANT, grant, cast.adminDevice), nil); aclTestRefusal(err) != ErrConfigRule {
			t.Errorf("a RepoGrant: %v", err)
		}
		admin := &protocol.RepoAdmin{RepoId: repoId.Bytes(), SidecarId: cast.adminDevice.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD}
		if _, err := state.CheckStatement(cast.fixture.statement(bridge.SignedType_SIGNED_REPO_ADMIN, admin, cast.adminDevice), nil); err == nil {
			t.Error("an admin's RepoAdmin add of itself was taken")
		}
		share := &protocol.EvsShare{RepoId: repoId.Bytes(), Subject: cast.adminDevice.Bytes()}
		if _, err := state.CheckStatement(cast.fixture.statement(bridge.SignedType_SIGNED_EVS_SHARE, share, cast.adminDevice), nil); err == nil {
			t.Error("an admin's EvsShare to itself was taken")
		}
		// the member's own consented device shares and adds alike
		share = &protocol.EvsShare{RepoId: repoId.Bytes(), Subject: cast.otherAgent.Bytes()}
		if _, err := state.CheckStatement(cast.fixture.statement(bridge.SignedType_SIGNED_EVS_SHARE, share, cast.laptop), nil); err != nil {
			t.Errorf("the member's EvsShare: %v", err)
		}
	}
}

// The Team inbox (§20.4): read and written by every admitted sidecar of the network, a tagged one included, within
// §8.6's ceiling, so an ephemeral sidecar takes neither and a read_only one reads alone; it is no mail inbox and takes
// no deposit or drop key.
func TestTeamInboxReadersAndWriters(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(other)
	laptop := fixture.invitedDevice(owner)
	otherDevice := fixture.invitedDevice(other)
	tagged := fixture.agent(other, tagId)
	burner := fixture.device(other, otherDevice.Bytes())
	fixture.admission(burner).Ephemeral = true
	readOnly := fixture.device(other, otherDevice.Bytes())
	fixture.admission(readOnly).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	inboxId, inbox := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	inbox.Inbox = protocol.RepoInbox_REPO_INBOX_TEAM
	inbox.Admins = []*protocol.AclRepoAdminRow{{SidecarId: laptop.Bytes(), Signer: laptop.Bytes(), At: fixture.next()}}
	plainId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	state := fixture.state(t)
	if !AclRepoIsTeamInbox(inbox) || AclRepoIsInbox(inbox) || gkmRepoTakesDeposits(inbox) {
		t.Fatal("the Team inbox reads as a mail inbox")
	}
	cases := []struct {
		name      string
		sidecarId Id
		rights    AclEvsRights
	}{
		{name: "its creator", sidecarId: laptop, rights: AclEvsRead | AclEvsWrite | AclEvsAdmin},
		{name: "another member's device", sidecarId: otherDevice, rights: AclEvsRead | AclEvsWrite},
		{name: "a tagged sidecar", sidecarId: tagged, rights: AclEvsRead | AclEvsWrite},
		{name: "an ephemeral sidecar", sidecarId: burner, rights: 0},
		{name: "a read_only device", sidecarId: readOnly, rights: AclEvsRead},
	}
	for _, c := range cases {
		if rights := aclTestRights(state, c.sidecarId, inboxId, AclTokenAudienceEvs); rights != c.rights {
			t.Errorf("%s: %b, want %b", c.name, rights, c.rights)
		}
		if rights := aclTestRights(state, c.sidecarId, plainId, AclTokenAudienceEvs); rights != 0 {
			t.Errorf("%s reaches an unmarked general repo: %b", c.name, rights)
		}
	}
	if teamInbox, found := state.TeamInbox(); !found || teamInbox != inboxId {
		t.Fatalf("the Team inbox reads as %s, %t", teamInbox, found)
	}
	// rows holding a second standing Team inbox build no state
	second, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	fixture.rows.Repos[len(fixture.rows.Repos)-1].Inbox = protocol.RepoInbox_REPO_INBOX_TEAM
	if _, err := NewAclState(fixture.rows, fixture.view); err == nil {
		t.Fatalf("rows with a second Team inbox %s built a state", second)
	}
}

// The creations the agent_repos feature turns on, at the tip of net: an agents and an agent repo by the member's
// consented device, and the Team inbox by the network's owner device, a config writer.
func testAgentReposCreations(net *testConfigNet, device testConfigDevice, label string) [][]byte {
	statement := func(signer testConfigDevice, create *protocol.RepoCreate) []byte {
		create.Header = net.header()
		return net.sign(signer, bridge.SignedType_SIGNED_REPO_CREATE, create)
	}
	return [][]byte{
		statement(device, &protocol.RepoCreate{RepoId: testConfigId(label + " agents").Bytes(), Kind: protocol.RepoKind_REPO_KIND_AGENTS}),
		statement(device, &protocol.RepoCreate{RepoId: testConfigId(label + " agent").Bytes(), Kind: protocol.RepoKind_REPO_KIND_AGENT}),
		statement(net.owner, &protocol.RepoCreate{RepoId: testConfigId(label + " team inbox").Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
			Inbox: protocol.RepoInbox_REPO_INBOX_TEAM}),
	}
}

// §16.6's before row on the feature's own entries: each creation is refused before the base that turns agent_repos
// on, by a reader that implements the feature and one that predates it alike, with the same verdicts and rows, and
// taken past the base, the repos folded with their kinds, the marker and the member as their owner.
func TestAgentReposRefusedBeforeFeature(t *testing.T) {
	net := newTestConfigNet(t)
	member, device := net.consentedMember("agents member")
	implements := net.log
	implements.authFeatures = AuthFeatureAgentRepos
	predates := net.newReader()
	predates.authFeatures = 0
	for i, statement := range testAgentReposCreations(net, device, "before") {
		entry := net.makeEntry(bridge.AuthEntryKindStatement, statement)
		testFeatureSequence(t, net, entry)
		verdicts := []ConfigVerdict{}
		for _, reader := range []*ConfigLog{implements, predates} {
			verdict, err := reader.Apply(entry, net.source)
			if err != nil {
				t.Fatal(err)
			}
			verdicts = append(verdicts, verdict)
		}
		if verdicts[0].Accepted() || verdicts[1].Accepted() || verdicts[0].tailBits() != verdicts[1].tailBits() ||
			!errors.Is(verdicts[0].Refusal, ErrAuthFeatureOff) {
			t.Fatalf("creation %d before the base: %v, %v", i, verdicts[0].Refusal, verdicts[1].Refusal)
		}
		if !bytes.Equal(testConfigRowsBytes(t, implements.State()), testConfigRowsBytes(t, predates.State())) {
			t.Fatalf("creation %d: the readers' rows differ", i)
		}
		net.statesAt[net.n] = implements.State()
		net.verdicts[net.n] = verdicts[0]
	}

	// the base: the reader that implements it turns it on, and takes each creation past it
	base := testFeatureBase(t, net, AuthFeatureAgentRepos)
	if _, err := implements.Apply(base, net.source); err != nil {
		t.Fatal(err)
	}
	net.statesAt[net.n] = implements.State()
	net.verdicts[net.n] = ConfigVerdict{Kind: bridge.AuthEntryKindBase}
	if _, err := predates.Apply(base, net.source); !errors.Is(err, ErrConfigUpgradeRequired) {
		t.Fatalf("the predating reader at the base: %v", err)
	}
	for i, statement := range testAgentReposCreations(net, device, "after") {
		if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, statement)); !verdict.Accepted() {
			t.Fatalf("creation %d past the base: %v", i, verdict.Refusal)
		}
	}
	state := implements.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	agentsId, found := acl.AgentsRepo(member)
	if !found || agentsId != testConfigId("after agents") || !bytes.Equal(state.Repo(agentsId).GetOwnerMemberId(), member.Bytes()) {
		t.Fatalf("the member's agents repo: %s, %t", agentsId, found)
	}
	agentRepo := state.Repo(testConfigId("after agent"))
	if agentRepo.GetKind() != protocol.RepoKind_REPO_KIND_AGENT || !bytes.Equal(agentRepo.GetOwnerMemberId(), member.Bytes()) ||
		!acl.MemberAgentRepo(member, testConfigId("after agent")) {
		t.Fatalf("the agent repo's row: %v", agentRepo)
	}
	if teamInbox, found := acl.TeamInbox(); !found || teamInbox != testConfigId("after team inbox") {
		t.Fatalf("the Team inbox: %s, %t", teamInbox, found)
	}
	if !slices.Equal(acl.RepoReaders(agentsId, aclTestNow), []Id{device.sidecarId}) {
		t.Fatalf("the agents repo's readers: %v", acl.RepoReaders(agentsId, aclTestNow))
	}
}

// R2-02's acceptance on the real kinds, M11's exit (§16.6's hold and update rows): a device on a release without
// agent_repos, offline while the network turns it on and its member's devices create the agents and agent repos,
// holds at the base with upgrade_required and writes nothing; updated, it resumes there and agrees with the network
// on the repos' kinds, owners and readers before it writes anything.
func TestAgentReposHoldOnOldReader(t *testing.T) {
	WithAuthFeaturesImplementedForTest(t, 0, nil)
	world := newTestConfigClientWorld(t)
	net := world.net
	net.log.authFeatures = AuthFeatureAgentRepos
	member, first := net.consentedMember("agents member")
	net.fold(net.owner, net.n, 2)
	world.publish()
	settings := DefaultConfigClientSettings()
	settings.RetainFullTail = true
	client := world.client(settings)
	world.caughtUp(client)

	state := net.log.State()
	configVersion := state.Base().GetConfigVersion() + 1
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{AuthFeatures: uint32(AuthFeatureAgentRepos)}
	net.fold(net.owner, net.n, configVersion)
	baseAt := net.n
	second := net.device("agents member second", member)
	net.admitDevice(first, second, 0)
	for _, statement := range testAgentReposCreations(net, first, "network") {
		if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, statement)); !verdict.Accepted() {
			t.Fatalf("the network's creation: %v", verdict.Refusal)
		}
	}
	world.publish()
	client.ReceiveNotice(PushNotice{Topic: PushTopicTeam, Version: net.n})
	hold := testFeatureStopped(t, client)
	if !hold.Held() || hold.N != baseAt || hold.UpgradeRequired != AuthFeatureAgentRepos || client.State().Repo(testConfigId("network agents")) != nil {
		t.Fatalf("the old release stopped at %v", hold)
	}
	if upgrades, headAlarms := world.upgradeEvents(); len(upgrades) != 1 || headAlarms != 0 {
		t.Fatalf("%d upgrade_required, %d head alarms", len(upgrades), headAlarms)
	}
	client.Close()

	WithAuthFeaturesImplementedForTest(t, AuthFeatureAgentRepos, nil)
	updated := world.client(settings)
	resumed := world.caughtUp(updated)
	testConfigStatesEqual(t, resumed, net.log.State())
	if fork := updated.Fork(); fork != nil {
		t.Fatalf("the updated release stops at %v", fork)
	}
	resumedAcl, err := resumed.Acl()
	if err != nil {
		t.Fatal(err)
	}
	networkAcl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"network agents", "network agent", "network team inbox"} {
		repoId := testConfigId(label)
		ours, theirs := resumed.Repo(repoId), net.log.State().Repo(repoId)
		if ours == nil || ours.GetKind() != theirs.GetKind() || ours.GetInbox() != theirs.GetInbox() ||
			!bytes.Equal(ours.GetOwnerMemberId(), theirs.GetOwnerMemberId()) {
			t.Fatalf("%s: the updated release's row %v, the network's %v", label, ours, theirs)
		}
		if !slices.Equal(resumedAcl.RepoReaders(repoId, aclTestNow), networkAcl.RepoReaders(repoId, aclTestNow)) {
			t.Fatalf("%s: readers %v, the network's %v", label, resumedAcl.RepoReaders(repoId, aclTestNow), networkAcl.RepoReaders(repoId, aclTestNow))
		}
	}
	// the member's second device, admitted past the base, reads the agents repo at both
	if !slices.Contains(resumedAcl.RepoReaders(testConfigId("network agents"), aclTestNow), second.sidecarId) {
		t.Fatal("the second device does not read the agents repo")
	}
}

// One agents repo a member (§20.4): where two of the member's devices raced, every reader takes the first in log order,
// a later one with a lower id included, the other standing and never taken; a deleted first gives way to the next; and
// another member's is its own.
func TestAgentsRepoFoldFirstPerMember(t *testing.T) {
	net := newTestConfigNet(t)
	net.log.authFeatures = AuthFeatureAgentRepos
	member, first := net.consentedMember("racing member")
	second := net.device("racing member second", member)
	net.admitDevice(first, second, 0)
	other, otherDevice := net.consentedMember("other member")
	net.statesAt[net.n] = net.log.State()
	base := testFeatureBase(t, net, AuthFeatureAgentRepos)
	if _, err := net.log.Apply(base, net.source); err != nil {
		t.Fatal(err)
	}
	net.statesAt[net.n] = net.log.State()
	net.verdicts[net.n] = ConfigVerdict{Kind: bridge.AuthEntryKindBase}
	// the first in log order has the higher id
	firstId, laterId := Id{0xf0}, Id{0x01}
	for _, create := range []struct {
		signer testConfigDevice
		repoId Id
	}{
		{signer: first, repoId: firstId},
		{signer: second, repoId: laterId},
		{signer: otherDevice, repoId: Id{0x02}},
	} {
		net.mustPost(create.signer, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
			Header: net.header(), RepoId: create.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_AGENTS,
		})
	}
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if agentsId, found := acl.AgentsRepo(member); !found || agentsId != firstId {
		t.Fatalf("the member's agents repo %s, %t", agentsId, found)
	}
	if agentsId, found := acl.AgentsRepo(other); !found || agentsId != (Id{0x02}) {
		t.Fatalf("the other member's agents repo %s, %t", agentsId, found)
	}
	for _, repoId := range []Id{firstId, laterId} {
		if !bytes.Equal(net.log.State().Repo(repoId).GetOwnerMemberId(), member.Bytes()) {
			t.Fatalf("%s is not bound to its signer's member", repoId)
		}
	}
	net.mustPost(first, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{
		Header: net.header(), RepoId: firstId.Bytes(), DeletionId: testConfigId("first agents deletion").Bytes(),
	})
	acl, err = net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if agentsId, found := acl.AgentsRepo(member); !found || agentsId != laterId {
		t.Fatalf("past the first's deletion the member's agents repo is %s, %t", agentsId, found)
	}
	if _, found := acl.AgentsRepo(Id{}); found {
		t.Fatal("no member's agents repo")
	}
}

// The team marker (§20.4, D-SKILL-5): only a config writer creates the Team inbox, only on a general repo, and only one
// while one stands; a refused marker is never folded as something else.
func TestTeamInboxMarkerOnlyConfigWriterOnce(t *testing.T) {
	net := newTestConfigNet(t)
	net.log.authFeatures = AuthFeatureAgentRepos
	_, device := net.consentedMember("inbox member")
	net.statesAt[net.n] = net.log.State()
	base := testFeatureBase(t, net, AuthFeatureAgentRepos)
	if _, err := net.log.Apply(base, net.source); err != nil {
		t.Fatal(err)
	}
	net.statesAt[net.n] = net.log.State()
	net.verdicts[net.n] = ConfigVerdict{Kind: bridge.AuthEntryKindBase}
	create := func(repoLabel string, kind protocol.RepoKind) *protocol.RepoCreate {
		return &protocol.RepoCreate{Header: net.header(), RepoId: testConfigId(repoLabel).Bytes(), Kind: kind, Inbox: protocol.RepoInbox_REPO_INBOX_TEAM}
	}
	net.mustRefuse(device, bridge.SignedType_SIGNED_REPO_CREATE, create("a member's", protocol.RepoKind_REPO_KIND_GENERAL), ErrConfigAuthority)
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_AGENTS, protocol.RepoKind_REPO_KIND_AGENT} {
		net.mustRefuse(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, create("marked "+kind.String(), kind), ErrConfigRule)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, create("the team inbox", protocol.RepoKind_REPO_KIND_GENERAL))
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, create("a second", protocol.RepoKind_REPO_KIND_GENERAL), ErrConfigRule)
	for _, label := range []string{"a member's", "a second"} {
		if net.log.State().Repo(testConfigId(label)) != nil {
			t.Fatalf("%s folded", label)
		}
	}
	// a deleted Team inbox gives way: the next config writer's creation stands
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{
		Header: net.header(), RepoId: testConfigId("the team inbox").Bytes(), DeletionId: testConfigId("team inbox deletion").Bytes(),
	})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, create("the next team inbox", protocol.RepoKind_REPO_KIND_GENERAL))
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if teamInbox, found := acl.TeamInbox(); !found || teamInbox != testConfigId("the next team inbox") {
		t.Fatalf("the Team inbox %s, %t", teamInbox, found)
	}
}

// §16.6's implicit row: agent_repos adds no implicit rule, its deposits being the agent kind's default, so the implicit
// document's rows are the same bytes with the feature on as off, the frozen golden's, and EvsAccess gives the deposits
// from the rows' has_document alone.
func TestAgentReposImplicitRowsUnchanged(t *testing.T) {
	world := newAclCompileWorld("implicit")
	off := world.input()
	off.AuthFeatures = 0
	on := world.input()
	on.AuthFeatures = AuthFeatureAgentRepos
	offRows, err := CompileAcl(off)
	if err != nil {
		t.Fatal(err)
	}
	onRows, err := CompileAcl(on)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aclEncodeRows(t, offRows), aclEncodeRows(t, onRows)) {
		t.Fatal("agent_repos changes the implicit document's rows")
	}
	if onRows.GetHasDocument() {
		t.Fatal("the implicit document's rows say has_document")
	}
	if AuthFeaturesImplemented()&AuthFeatureAgentRepos == 0 {
		t.Fatal("this build does not implement agent_repos")
	}
}
