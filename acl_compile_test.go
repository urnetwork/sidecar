// CompileAcl on hand-built heads: one function for documents and the implicit document alike, deterministic bytes, a
// frozen implicit document, §8.5's worked example, no name in the rows, and the refusals a reader shares with the
// writer. Pure, on every leg.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// testdata/acl/vectors, embedded, since the sidecar_http leg's Worker reads no file (§22.6's every-leg vectors).
//
//go:embed testdata/acl/vectors
var testAclVectorFiles embed.FS

// A network as a compile test writes it: the log's rows at the head's fold and the head's tables, every id fixed by a
// label, so a world built twice is the same world.
type aclCompileWorld struct {
	networkId  Id
	policy     []byte
	members    []*bridge.MemberRow
	sidecars   []*bridge.SidecarRow
	ephemeral  map[Id]bool
	tags       *protocol.ConfigAtomTable
	groups     *protocol.ConfigAtomTable
	rules      *protocol.ConfigRuleTable
	labels     *protocol.ConfigLabelTable
	resolve    *protocol.ConfigResolution
	socketKey  *protocol.SocketKeyFile
	statements *protocol.AclRows
	headTimeMs int64
	position   uint64
	// The config repo a test names in the view's Genesis, zero for none: no rows hold its row (QD-719).
	configRepoId Id
}

func newAclCompileWorld(label string) *aclCompileWorld {
	world := &aclCompileWorld{
		ephemeral:  map[Id]bool{},
		tags:       &protocol.ConfigAtomTable{},
		groups:     &protocol.ConfigAtomTable{},
		rules:      &protocol.ConfigRuleTable{},
		labels:     &protocol.ConfigLabelTable{},
		resolve:    &protocol.ConfigResolution{},
		statements: &protocol.AclRows{},
		headTimeMs: aclTestNow.UnixMilli(),
	}
	world.networkId = world.id("network " + label)
	world.socketKey = &protocol.SocketKeyFile{CurrentKey: world.key("k_sock " + label)}
	return world
}

// An id fixed by its label.
func (self *aclCompileWorld) id(label string) Id {
	digest := sha256.Sum256([]byte("acl compile test " + label))
	return Id(digest[:aclAtomByteCount])
}

// 32 bytes fixed by a label.
func (self *aclCompileWorld) key(label string) []byte {
	digest := sha256.Sum256([]byte("acl compile test key " + label))
	return digest[:]
}

// A member with an email resolve names.
func (self *aclCompileWorld) member(email string, role bridge.MemberRole) Id {
	memberId := self.id("member " + email)
	self.members = append(self.members, &bridge.MemberRow{MemberId: memberId.Bytes(), Role: role})
	self.resolve.Members = append(self.resolve.Members, &protocol.ConfigMemberResolution{Email: email, MemberId: memberId.Bytes()})
	return memberId
}

// An untagged sidecar of a member.
func (self *aclCompileWorld) device(label string, memberId Id) Id {
	sidecarId := self.id("sidecar " + label)
	self.position += 1
	self.sidecars = append(self.sidecars, &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), MemberId: memberId.Bytes(), AdmittedAt: self.position})
	return sidecarId
}

// A tagged sidecar a member sponsors.
func (self *aclCompileWorld) agent(label string, sponsorId Id, tagNames ...string) Id {
	sidecarId := self.id("sidecar " + label)
	self.position += 1
	row := &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), Sponsor: sponsorId.Bytes(), AdmittedAt: self.position}
	for _, tagName := range tagNames {
		row.TagIds = append(row.TagIds, self.tag(tagName).Bytes())
	}
	self.sidecars = append(self.sidecars, row)
	return sidecarId
}

// A tag's atom id, its tags row added once.
func (self *aclCompileWorld) tag(name string) Id {
	atomId := self.id("tag " + name)
	if !slices.ContainsFunc(self.tags.Atoms, func(row *protocol.ConfigAtomName) bool { return row.Name == name }) {
		self.tags.Atoms = append(self.tags.Atoms, &protocol.ConfigAtomName{Name: name, AtomId: atomId.Bytes()})
	}
	return atomId
}

// A group's atom id, its groups row added once.
func (self *aclCompileWorld) group(name string) Id {
	atomId := self.id("group " + name)
	if !slices.ContainsFunc(self.groups.Atoms, func(row *protocol.ConfigAtomName) bool { return row.Name == name }) {
		self.groups.Atoms = append(self.groups.Atoms, &protocol.ConfigAtomName{Name: name, AtomId: atomId.Bytes()})
	}
	return atomId
}

// A repo of a kind in the log's rows, with an owner for an owner-bound one, and a label when given.
func (self *aclCompileWorld) repo(label string, kind protocol.RepoKind, ownerId Id) Id {
	repoId := self.id("repo " + label)
	row := &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: kind}
	if ownerId != (Id{}) {
		row.OwnerMemberId = ownerId.Bytes()
	}
	self.statements.Repos = append(self.statements.Repos, row)
	self.labels.Labels = append(self.labels.Labels, &protocol.ConfigRepoLabel{Label: label, RepoId: repoId.Bytes()})
	return repoId
}

// Another network resolve names.
func (self *aclCompileWorld) network(text string) Id {
	networkId := self.id("other network " + text)
	self.resolve.Networks = append(self.resolve.Networks, &protocol.ConfigNetworkResolution{Text: text, NetworkId: networkId.Bytes()})
	return networkId
}

// The document, with a rules row for every rule, each id fixed by its canonical form.
func (self *aclCompileWorld) setPolicy(t testing.TB, source string) {
	t.Helper()
	self.policy = []byte(source)
	policy, err := ParseAclPolicy(self.policy)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	keys, err := AclPolicyRuleKeys(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if slices.ContainsFunc(self.rules.Rules, func(row *protocol.ConfigRuleId) bool { return bytes.Equal(row.CanonicalSha256, key.CanonicalSha256[:]) }) {
			continue
		}
		ruleId := self.id("rule " + hex.EncodeToString(key.CanonicalSha256[:]))
		self.rules.Rules = append(self.rules.Rules, &protocol.ConfigRuleId{CanonicalSha256: bytes.Clone(key.CanonicalSha256[:]), RuleId: ruleId.Bytes()})
	}
}

// The rule id a document rule's rules row gives it.
func (self *aclCompileWorld) documentRuleId(t testing.TB, kind string, index int) Id {
	t.Helper()
	policy, err := ParseAclPolicy(self.policy)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := AclPolicyRuleKeys(policy)
	for _, key := range keys {
		if key.Kind == kind && key.Index == index {
			return self.id("rule " + hex.EncodeToString(key.CanonicalSha256[:]))
		}
	}
	t.Fatalf("no %s %d", kind, index)
	return Id{}
}

func (self *aclCompileWorld) input() *AclCompileInput {
	return &AclCompileInput{
		NetworkId:  self.networkId,
		Policy:     self.policy,
		Tags:       self.tags,
		Groups:     self.groups,
		Rules:      self.rules,
		Labels:     self.labels,
		Resolve:    self.resolve,
		SocketKey:  self.socketKey,
		HeadTimeMs: self.headTimeMs,
		Members:    self.members,
		Sidecars:   self.sidecars,
		Statements: self.statements,
	}
}

func (self *aclCompileWorld) compile(t testing.TB) *protocol.AclRows {
	t.Helper()
	rows, err := CompileAcl(self.input())
	if err != nil {
		t.Fatalf("CompileAcl: %v", err)
	}
	return rows
}

// Names the network's config repo, which the view's Genesis then carries with strangers as its signer and its member,
// so the state adds its row (QD-719).
func (self *aclCompileWorld) configRepo() Id {
	self.configRepoId = self.id("repo config")
	return self.configRepoId
}

// The state's view over the world's members and sidecars, for AclState on the compiled rows.
func (self *aclCompileWorld) view() *aclTestView {
	view := newAclTestFixture().view
	if self.configRepoId != (Id{}) {
		view.genesis = &bridge.Genesis{
			ConfigRepoId:   self.configRepoId.Bytes(),
			OwnerSidecarId: self.id("genesis owner sidecar").Bytes(),
			OwnerMemberId:  self.id("genesis owner member").Bytes(),
		}
	}
	for _, member := range self.members {
		view.members[Id(member.MemberId)] = member
	}
	for _, row := range self.sidecars {
		sidecarId := Id(row.SidecarId)
		facts := &AclSidecar{Row: row, Ephemeral: self.ephemeral[sidecarId]}
		if len(row.MemberId) != 0 {
			facts.MemberId = Id(row.MemberId)
		}
		for _, tagId := range row.TagIds {
			facts.TagIds = append(facts.TagIds, Id(tagId))
		}
		if len(row.Sponsor) != 0 {
			view.sponsors[sidecarId] = Id(row.Sponsor)
		}
		view.sidecars[sidecarId] = facts
	}
	return view
}

func (self *aclCompileWorld) state(t testing.TB) *AclState {
	t.Helper()
	state, err := NewAclState(self.compile(t), self.view())
	if err != nil {
		t.Fatalf("NewAclState: %v", err)
	}
	return state
}

func aclEncodeRows(t testing.TB, rows *protocol.AclRows) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// §8.5's worked example, its audit block left out: it names a reader only under a k-of-n AuditOptIn, which
// acl_audit_test.go's tests stand.
const aclWorkedExampleSource = `{
  "groups":    { "group:eng": ["dana@acme.example", "amir@acme.example"] },
  "tagOwners": { "tag:recurd": ["group:eng"], "tag:db": ["autogroup:admin"],
                 "tag:api": ["autogroup:admin"], "tag:audit": ["autogroup:admin"] },
  "grants": [
    { "src": ["autogroup:untagged"], "dst": ["autogroup:self"], "allow": ["dial", "route"] },
    { "src": ["tag:recurd"], "dst": ["evs:repo-x"], "allow": ["write"] },
    { "src": ["group:eng"], "dst": ["sock:db"], "allow": ["dial"] },
    { "src": ["tag:db"],    "dst": ["sock:db"], "allow": ["listen"] },
    { "src": ["network:partner-y"], "dst": ["tag:api"], "allow": ["dial"], "ip": ["tcp:443"],
      "expires": "2026-12-31T00:00:00Z" },
    { "src": ["tag:recurd"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:443"] },
  ],
  "requests": [
    { "src": ["tag:recurd"], "dst": ["dns:*-preview", "sock:tls/443/*-preview"], "allow": ["publish", "listen"],
      "approver": ["autogroup:sponsor"], "maxExpiry": "24h", "evidence": ["device", "presence"] },
  ],
  "tests": [ { "src": "dana@acme.example", "accept": ["sock:db#dial"], "deny": ["evs:secrets#read"] } ],
}`

// The worked example's world: an owner, dana and amir in group:eng, their devices, a tag:db and a tag:recurd agent.
type aclWorkedExample struct {
	world        *aclCompileWorld
	owner        Id
	dana, amir   Id
	ownerDevice  Id
	danaLaptop   Id
	danaPhone    Id
	amirLaptop   Id
	dbAgent      Id
	recurdAgent  Id
	repoX        Id
	partnerY     Id
	secretsRepo  Id
	dbSocketName string
}

func newAclWorkedExample(t testing.TB) *aclWorkedExample {
	world := newAclCompileWorld("worked example")
	example := &aclWorkedExample{world: world, dbSocketName: "db"}
	example.owner = world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	example.dana = world.member("dana@acme.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	example.amir = world.member("amir@acme.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	example.ownerDevice = world.device("owner laptop", example.owner)
	example.danaLaptop = world.device("dana laptop", example.dana)
	example.danaPhone = world.device("dana phone", example.dana)
	example.amirLaptop = world.device("amir laptop", example.amir)
	for _, name := range []string{"recurd", "db", "api", "audit"} {
		world.tag(name)
	}
	world.group("eng")
	example.dbAgent = world.agent("db agent", example.owner, "db")
	example.recurdAgent = world.agent("recurd agent", example.dana, "recurd")
	example.repoX = world.repo("repo-x", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	example.secretsRepo = world.repo("secrets", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	example.partnerY = world.network("partner-y")
	world.setPolicy(t, aclWorkedExampleSource)
	return example
}

// The token path of an application socket under the world's K_sock.
func (self *aclCompileWorld) tokenPath(t testing.TB, name string) []byte {
	t.Helper()
	keys, err := NewSocketKeys(self.networkId, self.socketKey.CurrentKey)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath, err := keys.TokenPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return tokenPath
}

// Equal input in any order gives equal bytes: every list of the head's tables and the log's rows shuffled, over many
// seeds (§7.9's BASE row hashes the rows on every reader).
func TestCompileAclIsDeterministic(t *testing.T) {
	example := newAclWorkedExample(t)
	world := example.world
	world.statements.Suspensions = []*protocol.AclSuspension{
		{Subject: example.amirLaptop.Bytes(), SuspendId: world.id("suspend a").Bytes(), SignerClass: AclSuspendClassAdmin, Signer: example.ownerDevice.Bytes(), At: 3},
		{Subject: example.dbAgent.Bytes(), SuspendId: world.id("suspend b").Bytes(), SignerClass: AclSuspendClassOwner, Signer: example.ownerDevice.Bytes(), At: 4},
	}
	world.statements.SpentGrants = []*protocol.AclSpentGrant{
		{GrantId: world.key("grant a"), RetainUntilMs: 0},
		{GrantId: world.key("grant b"), RetainUntilMs: world.headTimeMs + 1},
	}
	want := aclEncodeRows(t, world.compile(t))
	random := rand.New(rand.NewPCG(7, 11))
	shuffle := func(n int, swap func(i int, j int)) {
		random.Shuffle(n, swap)
	}
	for seed := range 64 {
		shuffled := *world
		shuffled.members = slices.Clone(world.members)
		shuffled.sidecars = slices.Clone(world.sidecars)
		shuffled.tags = &protocol.ConfigAtomTable{Atoms: slices.Clone(world.tags.Atoms)}
		shuffled.groups = &protocol.ConfigAtomTable{Atoms: slices.Clone(world.groups.Atoms)}
		shuffled.rules = &protocol.ConfigRuleTable{Rules: slices.Clone(world.rules.Rules)}
		shuffled.labels = &protocol.ConfigLabelTable{Labels: slices.Clone(world.labels.Labels)}
		shuffled.resolve = proto.Clone(world.resolve).(*protocol.ConfigResolution)
		shuffled.statements = proto.Clone(world.statements).(*protocol.AclRows)
		shuffle(len(shuffled.members), func(i int, j int) {
			shuffled.members[i], shuffled.members[j] = shuffled.members[j], shuffled.members[i]
		})
		shuffle(len(shuffled.sidecars), func(i int, j int) {
			shuffled.sidecars[i], shuffled.sidecars[j] = shuffled.sidecars[j], shuffled.sidecars[i]
		})
		for _, list := range [][]*protocol.ConfigAtomName{shuffled.tags.Atoms, shuffled.groups.Atoms} {
			shuffle(len(list), func(i int, j int) { list[i], list[j] = list[j], list[i] })
		}
		shuffle(len(shuffled.rules.Rules), func(i int, j int) {
			shuffled.rules.Rules[i], shuffled.rules.Rules[j] = shuffled.rules.Rules[j], shuffled.rules.Rules[i]
		})
		shuffle(len(shuffled.labels.Labels), func(i int, j int) {
			shuffled.labels.Labels[i], shuffled.labels.Labels[j] = shuffled.labels.Labels[j], shuffled.labels.Labels[i]
		})
		members := shuffled.resolve.Members
		shuffle(len(members), func(i int, j int) { members[i], members[j] = members[j], members[i] })
		repos := shuffled.statements.Repos
		shuffle(len(repos), func(i int, j int) { repos[i], repos[j] = repos[j], repos[i] })
		suspensions := shuffled.statements.Suspensions
		shuffle(len(suspensions), func(i int, j int) { suspensions[i], suspensions[j] = suspensions[j], suspensions[i] })
		spent := shuffled.statements.SpentGrants
		shuffle(len(spent), func(i int, j int) { spent[i], spent[j] = spent[j], spent[i] })
		if got := aclEncodeRows(t, shuffled.compile(t)); !bytes.Equal(got, want) {
			t.Fatalf("seed %d compiles to other bytes", seed)
		}
	}
}

// The implicit document is the binary's, frozen: its source is testdata's, and its compiled rows are the golden's,
// byte for byte, so a change to either fails here before any reader compiles other rows (D-ACL-20, D-PHASE-9).
func TestCompileAclImplicitDocumentIsFrozen(t *testing.T) {
	if !bytes.Equal(AclImplicitPolicySource(), testAclPolicyFixture(t, "implicit_document.hujson")) {
		t.Fatal("acl_implicit.hujson is not §8.5's implicit document as testdata holds it")
	}
	rows := newAclCompileWorld("implicit").compile(t)
	if rows.GetHasDocument() {
		t.Fatal("the implicit document's rows say has_document")
	}
	golden, err := testAclVectorFiles.ReadFile("testdata/acl/vectors/implicit_rows.hex")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(aclEncodeRows(t, rows)); got != strings.TrimSpace(string(golden)) {
		t.Fatalf("the implicit document compiles to other rows:\n%s", got)
	}
	// its rules take the fixed ids, grants first, then requests
	for i, rule := range rows.GetRules() {
		if !slices.ContainsFunc([]uint32{0, 1, 2, 3}, func(index uint32) bool { return bytes.Equal(rule.GetRuleId(), aclImplicitRuleId(index).Bytes()) }) {
			t.Errorf("rules[%d] takes no implicit grant's id", i)
		}
	}
	for i, request := range rows.GetRequests() {
		if !slices.ContainsFunc([]uint32{4, 5, 6, 7}, func(index uint32) bool { return bytes.Equal(request.GetRuleId(), aclImplicitRuleId(index).Bytes()) }) {
			t.Errorf("requests[%d] takes no implicit request's id", i)
		}
	}
}

// Without a document every sidecar keeps today's reach, tagged ones the implicit tagged rules, and the first rule's *
// reaches share/ as an application socket does (SOCK-M5-15).
func TestCompileAclImplicitDocumentEvaluates(t *testing.T) {
	world := newAclCompileWorld("implicit evaluates")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := world.device("laptop", owner)
	phone := world.device("phone", owner)
	agent := world.agent("agent", owner, "worker")
	general := world.repo("notes", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	state := world.state(t)
	if decision := state.Reach(AclSidecarSubject(laptop), AclSidecarSubject(phone), aclTestNow); !decision.Allowed {
		t.Errorf("member reach: %s", decision.Reason)
	}
	if decision := state.MayDialSocket(AclSidecarSubject(laptop), world.tokenPath(t, "share/"+strings.Repeat("a", socketShareTokenByteCount)), aclTestNow); !decision.Allowed {
		t.Errorf("share/: %s", decision.Reason)
	}
	if decision := state.Reach(AclSidecarSubject(agent), AclSidecarSubject(laptop), aclTestNow); !decision.Allowed {
		t.Errorf("tagged dial to its sponsor's devices: %s", decision.Reason)
	}
	if access := state.EvsAccess(AclSidecarSubject(laptop), general, AclTokenAudienceEvs, aclTestNow); !access.Rights.Has(AclEvsAdmin) {
		t.Errorf("member rights on a general repo: %b", access.Rights)
	}
	if access := state.EvsAccess(AclSidecarSubject(agent), general, AclTokenAudienceEvs, aclTestNow); access.Rights != AclEvsDeposit {
		t.Errorf("tagged rights on a general repo: %b", access.Rights)
	}
	if decision := state.MayListen(AclSidecarSubject(laptop), AclSocketName{PublicName: "tls/443/blog"}, aclTestNow); decision.Allowed {
		t.Error("a standing tls/ listen without a document")
	}
}

// §8.5's worked example, compiled: its atoms, rules and request, read back through AclState.
func TestCompileAclWorkedExample(t *testing.T) {
	example := newAclWorkedExample(t)
	world := example.world
	rows := world.compile(t)
	if !rows.GetHasDocument() || len(rows.GetRules()) != 6 || len(rows.GetRequests()) != 1 {
		t.Fatalf("%d rules, %d requests", len(rows.GetRules()), len(rows.GetRequests()))
	}
	atoms := map[Id]*protocol.AclAtom{}
	for _, atom := range rows.GetAtoms() {
		atoms[Id(atom.GetAtom())] = atom
	}
	eng := atoms[world.group("eng")]
	if eng == nil || len(eng.GetMemberIds()) != 2 {
		t.Fatalf("group:eng: %v", eng)
	}
	recurd := atoms[world.tag("recurd")]
	if recurd == nil || len(recurd.GetMemberIds()) != 0 || len(recurd.GetTagOwnerMemberIds()) != 2 ||
		!slices.ContainsFunc(recurd.GetSidecarIds(), func(id []byte) bool { return Id(id) == example.recurdAgent }) {
		t.Fatalf("tag:recurd: %v", recurd)
	}
	if db := atoms[world.tag("db")]; db == nil || len(db.GetTagOwnerMemberIds()) != 1 || Id(db.GetTagOwnerMemberIds()[0]) != example.owner {
		t.Fatalf("tag:db's owners: %v", db)
	}
	partner := atoms[AclDerivedAtom(AclDerivedAtomNetwork, example.partnerY.Bytes())]
	if partner == nil || len(partner.GetNetworkIds()) != 1 {
		t.Fatalf("network:partner-y: %v", partner)
	}
	request := rows.GetRequests()[0]
	wantEvidence := []uint32{uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE), uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)}
	if request.GetMaxExpirySeconds() != 24*60*60 || request.GetDefaultExpirySeconds() != 60*60 || request.GetApprovers() != 1 ||
		!slices.Equal(request.GetEvidence(), wantEvidence) ||
		!bytes.Equal(request.GetApproverAtoms()[0], AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SPONSOR).Bytes()) {
		t.Fatalf("the request: %v", request)
	}
	if len(request.GetTargets()) != 2 || request.GetTargets()[0].GetPublicName() == "" || request.GetTargets()[1].GetPublicName() == "" {
		t.Fatalf("the request's targets: %v", request.GetTargets())
	}
	for _, rule := range rows.GetRules() {
		if Id(rule.GetRuleId()) == world.documentRuleId(t, "grant", 4) && (!rule.GetPortsLimited() || rule.GetExpires() == 0) {
			t.Errorf("the share's rule: %v", rule)
		}
	}

	state := world.state(t)
	dbToken := world.tokenPath(t, example.dbSocketName)
	cases := []struct {
		name     string
		decision AclDecision
		allowed  bool
	}{
		{name: "dana dials sock:db", decision: state.MayDialSocket(AclSidecarSubject(example.danaLaptop), dbToken, aclTestNow), allowed: true},
		{name: "the owner dials sock:db", decision: state.MayDialSocket(AclSidecarSubject(example.ownerDevice), dbToken, aclTestNow), allowed: false},
		{name: "tag:db listens on sock:db", decision: state.MayListen(AclSidecarSubject(example.dbAgent), AclSocketName{NameToken: dbToken}, aclTestNow), allowed: true},
		{name: "dana reaches the db listener", decision: state.Reach(AclSidecarSubject(example.danaLaptop), AclSidecarSubject(example.dbAgent), aclTestNow), allowed: true},
		{name: "dana's laptop reaches her phone", decision: state.Reach(AclSidecarSubject(example.danaLaptop), AclSidecarSubject(example.danaPhone), aclTestNow), allowed: false},
		{name: "partner-y dials tag:api", decision: state.Reach(AclRemoteSubject(example.partnerY), AclSidecarSubject(example.dbAgent), aclTestNow), allowed: false},
		{name: "the recurd agent reaches its sponsor", decision: state.Reach(AclSidecarSubject(example.recurdAgent), AclSidecarSubject(example.danaPhone), aclTestNow), allowed: true},
	}
	for _, c := range cases {
		if c.decision.Allowed != c.allowed {
			t.Errorf("%s: allowed %t (%s)", c.name, c.decision.Allowed, c.decision.Reason)
		}
	}
	// grant 1 names autogroup:untagged, app devices, which a member's sidecars are not (D-ACL-20)
	if access := state.EvsAccess(AclSidecarSubject(example.recurdAgent), example.repoX, AclTokenAudienceEvs, aclTestNow); !access.Rights.Has(AclEvsWrite) {
		t.Errorf("tag:recurd's write on repo-x: %b", access.Rights)
	}
	if access := state.EvsAccess(AclSidecarSubject(example.danaLaptop), example.secretsRepo, AclTokenAudienceEvs, aclTestNow); access.Allowed {
		t.Errorf("dana reads secrets: %b", access.Rights)
	}
}

// No name a member chose reaches the rows a server stores (R-ACL-12, owner decision 72): a canary in every name field
// of a document, its tables and its labels is absent from the encoded rows. tls/ names and dns hosts are in clear by
// design (§8.4), so none carries one.
func TestCompileAclRowsHoldNoNames(t *testing.T) {
	world := newAclCompileWorld("canaries")
	owner := world.member("canary-email@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.device("canary device", owner)
	world.agent("canary agent", owner, "canary-tag")
	world.group("canary-group")
	world.repo("canary-label", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	world.network("canary-network")
	world.setPolicy(t, `{
  "groups": { "group:canary-group": ["canary-email@acme.example"] },
  "tagOwners": { "tag:canary-tag": ["group:canary-group"] },
  "hosts": { "canary-host": "192.0.2.0/24" },
  "grants": [
    { "id": "canary-rule-id", "note": "canary-note", "src": ["group:canary-group"], "dst": ["sock:canary-socket"], "allow": ["dial"] },
    { "src": ["tag:canary-tag"], "dst": ["evs:canary-label", "mail:canary-alias"], "allow": ["read", "send"] },
    { "src": ["network:canary-network"], "dst": ["ip:canary-host"], "via": ["tag:canary-tag"], "allow": ["route"] },
  ],
}`)
	encoded := aclEncodeRows(t, world.compile(t))
	for _, canary := range []string{"canary-email", "acme.example", "canary-tag", "canary-group", "canary-label", "canary-network",
		"canary-rule-id", "canary-note", "canary-socket", "canary-alias", "canary-host", "192.0.2"} {
		if bytes.Contains(encoded, []byte(canary)) {
			t.Errorf("the rows hold %q", canary)
		}
	}
	if bytes.Contains(encoded, []byte{192, 0, 2}) {
		t.Error("the rows hold the host's prefix")
	}
}

// With no document the directory's readers are the kind default's, every admitted sidecar of the team, which M6 code
// computes alike (D-ACL-24, D-PHASE-9); writers are the ones not read_only.
func TestCompileAclDirectoryReadersFromTheKindDefault(t *testing.T) {
	world := newAclCompileWorld("directory")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	member := world.member("member@acme.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	laptop := world.device("laptop", owner)
	phone := world.device("phone", member)
	burner := world.device("burner", member)
	world.ephemeral[burner] = true
	agent := world.agent("agent", member, "worker")
	viewer := world.device("viewer", member)
	world.sidecars[len(world.sidecars)-1].Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	directory := world.repo("directory", protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	state := world.state(t)
	all := []Id{laptop, phone, burner, agent, viewer}
	slices.SortFunc(all, Id.Cmp)
	if readers := state.RepoReaders(directory, aclTestNow); !slices.Equal(readers, all) {
		t.Errorf("readers %v, want %v", readers, all)
	}
	writers := slices.DeleteFunc(slices.Clone(all), func(id Id) bool { return id == viewer })
	if got := state.RepoWriters(directory, aclTestNow); !slices.Equal(got, writers) {
		t.Errorf("writers %v, want %v", got, writers)
	}
}

// What the head does not hold refuses, at the writer and every reader alike, so no base compiles from a guess.
func TestCompileAclRefusesWhatTheHeadDoesNotHold(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		edit   func(world *aclCompileWorld)
	}{
		{name: "a tag with no row", policy: `{"grants": [{"src": ["tag:missing"], "dst": ["*"], "allow": ["dial"]}]}`},
		{name: "a group with no row", policy: `{"grants": [{"src": ["group:missing"], "dst": ["*"], "allow": ["dial"]}]}`},
		{name: "an email with no row", policy: `{"grants": [{"src": ["user:nobody@acme.example"], "dst": ["*"], "allow": ["dial"]}]}`},
		{name: "a network with no row", policy: `{"grants": [{"src": ["network:nowhere"], "dst": ["*"], "allow": ["dial"]}]}`},
		{name: "a client with no row", policy: `{"grants": [{"src": ["*"], "dst": ["client:01234567-89ab-cdef-0123-456789abcdef"], "allow": ["dial"]}]}`},
		{name: "a label with no row", policy: `{"grants": [{"src": ["autogroup:member"], "dst": ["evs:nowhere"], "allow": ["read"]}]}`},
		{name: "a ur/ socket", policy: `{"grants": [{"src": ["autogroup:member"], "dst": ["sock:ur/dns"], "allow": ["dial"]}]}`},
		{name: "a reserved socket", policy: `{"grants": [{"src": ["autogroup:member"], "dst": ["sock:sys/x"], "allow": ["dial"]}]}`},
		{name: "an application socket with no K_sock", policy: `{"grants": [{"src": ["autogroup:member"], "dst": ["sock:db"], "allow": ["dial"]}]}`, edit: func(world *aclCompileWorld) {
			world.socketKey = nil
		}},
		{name: "a rule with no rules row", policy: `{"grants": [{"src": ["autogroup:member"], "dst": ["*"], "allow": ["dial"]}]}`, edit: func(world *aclCompileWorld) {
			world.rules.Rules = nil
		}},
		{name: "an AuditOptIn record that does not parse", policy: `{"tagOwners": {"tag:audit": ["autogroup:admin"]}, "audit": {"reader": "tag:audit", "repos": ["kind:vault"]}}`,
			edit: func(world *aclCompileWorld) {
				world.statements.Audit = &protocol.AclAudit{AuditOptIn: []byte{0xff}}
			}},
		{name: "a policy that does not parse", policy: `{"grants": [{"src": ["autogroup:member"]}]}`},
	}
	for _, c := range cases {
		world := newAclCompileWorld("refusals")
		world.tag("audit")
		world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
		world.policy = []byte(c.policy)
		if policy, err := ParseAclPolicy(world.policy); err == nil {
			keys, _ := AclPolicyRuleKeys(policy)
			for _, key := range keys {
				world.rules.Rules = append(world.rules.Rules, &protocol.ConfigRuleId{CanonicalSha256: bytes.Clone(key.CanonicalSha256[:]), RuleId: world.id("rule").Bytes()})
			}
		}
		if c.edit != nil {
			c.edit(world)
		}
		if _, err := CompileAcl(world.input()); !errors.Is(err, ErrAclCompile) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// During a K_sock rotation's overlap each sock: target compiles a second time under the previous key, so listeners on
// either path pass (plan-SOCK-ksock-rotation); a glob's token prefix does too.
func TestCompileAclSocketTargetsDuringARotation(t *testing.T) {
	world := newAclCompileWorld("rotation")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.device("laptop", owner)
	world.setPolicy(t, `{"grants": [{"src": ["autogroup:member"], "dst": ["sock:db", "sock:app/*"], "allow": ["dial"]}]}`)
	current := world.compile(t)
	if targets := current.GetRules()[0].GetTargets(); len(targets) != 2 {
		t.Fatalf("%d targets with one key", len(targets))
	}
	previousKey := world.socketKey.CurrentKey
	world.socketKey = &protocol.SocketKeyFile{CurrentKey: world.key("k_sock next"), PreviousKey: previousKey, RotatedAtMs: world.headTimeMs}
	rotating := world.compile(t)
	targets := rotating.GetRules()[0].GetTargets()
	if len(targets) != 4 {
		t.Fatalf("%d targets during the overlap", len(targets))
	}
	oldKeys, _ := NewSocketKeys(world.networkId, previousKey)
	oldPath, _ := oldKeys.TokenPath("db")
	oldPrefix, _ := oldKeys.TokenPrefix("app")
	newKeys, _ := NewSocketKeys(world.networkId, world.socketKey.CurrentKey)
	newPath, _ := newKeys.TokenPath("db")
	for _, want := range []*protocol.AclTarget{
		{SocketTokens: [][]byte{oldPath}}, {SocketTokens: [][]byte{newPath}}, {SocketTokens: [][]byte{oldPrefix}, SocketPrefix: true},
	} {
		if !slices.ContainsFunc(targets, func(target *protocol.AclTarget) bool { return proto.Equal(target, want) }) {
			t.Errorf("no target %v", want)
		}
	}
}

// The log's activated grants ride the rows while their requests rule stands and they have not expired; a head that
// deletes the rule ends them at that base for every reader (FS-14), and a spent grant id leaves once its retention is
// below the head's newest record time (plan-ACL-folded-grant-state #2, #3).
func TestCompileAclCarriesTheLogsGrants(t *testing.T) {
	world := newAclCompileWorld("grants")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := world.device("laptop", owner)
	agent := world.agent("agent", owner, "worker")
	agentAtom := AclDerivedAtom(AclDerivedAtomSidecar, agent.Bytes())
	taggedRequest := aclImplicitRuleId(5)
	grant := func(label string, sourceRuleId Id, expires int64) *protocol.AclRule {
		return &protocol.AclRule{
			RuleId:       world.key(label),
			SrcAtoms:     [][]byte{agentAtom.Bytes()},
			Targets:      []*protocol.AclTarget{{SidecarId: laptop.Bytes()}},
			Actions:      []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
			Expires:      expires,
			SourceRuleId: sourceRuleId.Bytes(),
		}
	}
	world.statements.Atoms = []*protocol.AclAtom{{Atom: agentAtom.Bytes(), SidecarIds: [][]byte{agent.Bytes()}}}
	world.statements.Rules = []*protocol.AclRule{
		grant("live", taggedRequest, world.headTimeMs+60_000),
		grant("orphaned", world.id("a deleted rule"), world.headTimeMs+60_000),
		grant("expired", taggedRequest, world.headTimeMs),
		// a previous base's own compile, which this one replaces
		{RuleId: aclImplicitRuleId(0).Bytes(), Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_ADMIN)}},
	}
	world.statements.SpentGrants = []*protocol.AclSpentGrant{
		{GrantId: world.key("kept for life"), RetainUntilMs: 0},
		{GrantId: world.key("kept"), RetainUntilMs: world.headTimeMs},
		{GrantId: world.key("dropped"), RetainUntilMs: world.headTimeMs - 1},
	}
	rows := world.compile(t)
	activated := slices.DeleteFunc(slices.Clone(rows.GetRules()), func(rule *protocol.AclRule) bool { return len(rule.GetSourceRuleId()) == 0 })
	if len(activated) != 1 || !bytes.Equal(activated[0].GetRuleId(), world.key("live")) {
		t.Fatalf("activated grants %v", activated)
	}
	if !slices.ContainsFunc(rows.GetAtoms(), func(atom *protocol.AclAtom) bool { return bytes.Equal(atom.GetAtom(), agentAtom.Bytes()) }) {
		t.Error("the grant's subject atom did not ride")
	}
	if len(rows.GetSpentGrants()) != 2 {
		t.Errorf("spent grants %v", rows.GetSpentGrants())
	}
	for _, rule := range rows.GetRules() {
		if bytes.Equal(rule.GetRuleId(), aclImplicitRuleId(0).Bytes()) && slices.Equal(rule.GetActions(), []uint32{uint32(protocol.AclAction_ACL_ACTION_ADMIN)}) {
			t.Error("a previous base's rule rode")
		}
	}
	state := world.state(t)
	if decision := state.Reach(AclSidecarSubject(agent), AclSidecarSubject(laptop), aclTestNow); !decision.Allowed {
		t.Errorf("the live grant: %s", decision.Reason)
	}
}

// CompileAclLocal keeps what rows drop on purpose: ports, prefixes, exact socket globs, aliases, a rule's own naming of
// harness, and names for previews.
func TestCompileAclLocalKeepsWhatRowsDrop(t *testing.T) {
	world := newAclCompileWorld("local")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.device("laptop", owner)
	world.agent("router", owner, "router")
	world.setPolicy(t, `{
  "hosts": { "lan": "192.0.2.0/24" },
  "grants": [
    { "id": "lan route", "src": ["autogroup:member"], "dst": ["ip:lan"], "via": ["tag:router"], "allow": ["route"], "ip": ["tcp:22", "udp:53"] },
    { "src": ["autogroup:member"], "dst": ["sock:app/db*", "mail:ops-*"], "allow": ["dial", "send"] },
  ],
  "requests": [
    { "src": ["tag:router"], "dst": ["sock:tls/443/*"], "allow": ["listen"], "evidence": ["harness"] },
  ],
}`)
	local, err := CompileAclLocal(world.input())
	if err != nil {
		t.Fatal(err)
	}
	route := local.Rule(world.documentRuleId(t, "grant", 0).Bytes())
	if route == nil || route.DocumentId != "lan route" || len(route.Cidrs) != 1 || route.Cidrs[0].String() != "192.0.2.0/24" ||
		len(route.Ports) != 2 || route.Ports[0] != (AclPortRange{Protocol: aclIpProtocolTcp, First: 22, Last: 22}) {
		t.Fatalf("the route's detail: %+v", route)
	}
	dial := local.Rule(world.documentRuleId(t, "grant", 1).Bytes())
	if dial == nil || !slices.Equal(dial.Sockets, []string{"app/db*"}) || !slices.Equal(dial.Aliases, []string{"ops-*"}) || dial.Ports != nil {
		t.Fatalf("the dial's detail: %+v", dial)
	}
	request := local.Request(world.documentRuleId(t, "request", 0).Bytes())
	if request == nil || !request.NamesHarness {
		t.Fatalf("the request's detail: %+v", request)
	}
	if !slices.ContainsFunc(local.Names, func(name AclLocalName) bool { return name.Text == "tag:router" && name.Id == world.tag("router") }) {
		t.Errorf("names %v", local.Names)
	}
	rows := world.compile(t)
	for _, rule := range rows.GetRules() {
		if Id(rule.GetRuleId()) == world.documentRuleId(t, "grant", 0) {
			if !rule.GetPortsLimited() || len(rule.GetTargets()) != 1 || !bytes.Equal(rule.GetTargets()[0].GetAtom(), world.tag("router").Bytes()) {
				t.Errorf("the route's row: %v", rule)
			}
		}
	}
}

// The tag:mail mail indexers' kind defaults compile as two fixed rules over the log's repos, reading mailcfg and
// depositing to vault and mailbox, and only while the tags file holds mail (owner decision 150).
func TestCompileAclMailIndexerKindRules(t *testing.T) {
	world := newAclCompileWorld("mail")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.device("laptop", owner)
	mailcfg := world.repo("mailcfg", protocol.RepoKind_REPO_KIND_MAILCFG, Id{})
	mailbox := world.repo("mailbox", protocol.RepoKind_REPO_KIND_MAILBOX, owner)
	vault := world.repo("vault", protocol.RepoKind_REPO_KIND_VAULT, owner)
	if rows := world.compile(t); slices.ContainsFunc(rows.GetRules(), func(rule *protocol.AclRule) bool {
		return bytes.Equal(rule.GetRuleId(), aclKindRuleId(0).Bytes())
	}) {
		t.Fatal("kind rules with no tag:mail")
	}
	indexer := world.agent("indexer", owner, aclMailIndexerTag)
	state := world.state(t)
	if access := state.EvsAccess(AclSidecarSubject(indexer), mailcfg, AclTokenAudienceEvs, aclTestNow); access.Rights != AclEvsRead {
		t.Errorf("mailcfg %b", access.Rights)
	}
	for _, repoId := range []Id{mailbox, vault} {
		if access := state.EvsAccess(AclSidecarSubject(indexer), repoId, AclTokenAudienceEvs, aclTestNow); access.Rights != AclEvsDeposit {
			t.Errorf("owner-bound repo %b", access.Rights)
		}
	}
}

// A head compiles through §7.9's compile with CompileAcl registered (C-05), to the same rows CompileAcl gives.
func TestCompileProjectionRowsRunsCompileAcl(t *testing.T) {
	net := newTestConfigNet(t)
	head := testConfigHead(t, net)
	var err error
	head, err = head.WithFile(ConfigHeadPolicyPath, []byte(`{"grants": [{"src": ["autogroup:member"], "dst": ["*"], "allow": ["dial"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := ParseAclPolicy(head.File(ConfigHeadPolicyPath))
	keys, _ := AclPolicyRuleKeys(policy)
	rules := &protocol.ConfigRuleTable{Rules: []*protocol.ConfigRuleId{{CanonicalSha256: keys[0].CanonicalSha256[:], RuleId: NewId().Bytes()}}}
	rulesBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(rules)
	if head, err = head.WithFile(ConfigHeadRulesPath, rulesBytes); err != nil {
		t.Fatal(err)
	}
	compileRows := ConfigCompileRowsOf(net.log.State())
	compiled, err := CompileProjectionRows(head, compileRows)
	if err != nil {
		t.Fatal(err)
	}
	projection := &bridge.ProjectionRows{}
	if err := proto.Unmarshal(compiled, projection); err != nil {
		t.Fatal(err)
	}
	input, err := NewAclCompileInput(head, compileRows)
	if err != nil {
		t.Fatal(err)
	}
	want, err := CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(projection.GetAcl(), aclEncodeRows(t, want)) || !want.GetHasDocument() {
		t.Fatal("the base's acl part is not CompileAcl's")
	}
}
